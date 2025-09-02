import os
import time
import hashlib
import sqlite3
import json
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

SUSPICIOUS_EXTENSIONS = {
    '.exe': 'T1204.002',    
    '.bat': 'T1059.003',    
    '.scr': 'T1204.002',   
    '.cmd': 'T1059.003',   
    '.pif': 'T1204.002',    
    '.com': 'T1204.002',    
    '.vbs': 'T1059.005',   
    '.js': 'T1059.007',    
    '.ps1': 'T1059.001',   
    '.dll': 'T1055.001'     
}

WATCHED_DIRECTORIES = [
    r"C:\Windows",
    r"C:\Windows\System32",
    r"C:\Users\Public",    
    r"C:\ProgramData",
    r"C:\Temp",
    r"C:\Windows\Temp"
]

SENSITIVE_DIRECTORIES = [
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Program Files",
    r"C:\Program Files (x86)"
]

MAX_FILE_SIZE = 100 * 1024 * 1024 
MIN_SUSPICIOUS_SIZE = 1024          

class ThreatDatabase:
    def __init__(self, db_path='threat_detection.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database for threat events"""
        conn = sqlite3.connect(self.db_path)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                datetime_str TEXT,
                event_type TEXT,
                file_path TEXT,
                mitre_technique TEXT,
                severity TEXT,
                file_hash TEXT,
                file_size INTEGER,
                details TEXT,
                hostname TEXT
            )
        ''')
        
        conn.execute('''
            CREATE TABLE IF NOT EXISTS correlations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                event_count INTEGER,
                techniques TEXT,
                severity TEXT,
                description TEXT,
                countermeasures TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        print("Database initialized successfully")
    
    def log_event(self, event_type, file_path, technique, severity, file_hash, file_size, details):
        """Log security event to database"""
        conn = sqlite3.connect(self.db_path)
        timestamp = time.time()
        datetime_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        hostname = os.environ.get('COMPUTERNAME', 'Unknown')
        
        conn.execute('''
            INSERT INTO events (timestamp, datetime_str, event_type, file_path, 
                              mitre_technique, severity, file_hash, file_size, details, hostname)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, datetime_str, event_type, file_path, technique, 
              severity, file_hash, file_size, json.dumps(details), hostname))
        
        conn.commit()
        conn.close()
        
        self.check_correlations()
    
    def check_correlations(self):
        """Simple correlation: multiple events in short time window"""
        conn = sqlite3.connect(self.db_path)
        
        cutoff_time = time.time() - 300  
        cursor = conn.execute('''
            SELECT COUNT(*) as event_count, 
                   GROUP_CONCAT(DISTINCT mitre_technique) as techniques,
                   GROUP_CONCAT(file_path) as files
            FROM events 
            WHERE timestamp > ?
        ''', (cutoff_time,))
        
        result = cursor.fetchone()
        event_count = result[0]
        techniques = result[1] if result[1] else ""
        files = result[2] if result[2] else ""
        
        if event_count >= 3:
            self.generate_correlation_alert(event_count, techniques, files)
        
        conn.close()
    
    def generate_correlation_alert(self, event_count, techniques, files):
        """Generate correlation alert for multiple suspicious events"""
        conn = sqlite3.connect(self.db_path)
        
        recent_cutoff = time.time() - 300  
        cursor = conn.execute('''
            SELECT COUNT(*) FROM correlations WHERE timestamp > ?
        ''', (recent_cutoff,))
        
        if cursor.fetchone()[0] == 0:  
            severity = "CRITICAL" if event_count >= 5 else "HIGH"
            description = f"Multiple suspicious activities detected: {event_count} events involving techniques: {techniques}"
            
            conn.execute('''
                INSERT INTO correlations (timestamp, event_count, techniques, severity, description)
                VALUES (?, ?, ?, ?, ?)
            ''', (time.time(), event_count, techniques, severity, description))
            
            conn.commit()
            
            print("\n" + "="*80)
            print("CORRELATION ALERT")
            print(f"Severity: {severity}")
            print(f"Event Count: {event_count}")
            print(f"MITRE Techniques: {techniques}")
            print(f"Description: {description}")
            print("="*80 + "\n")
        
        conn.close()

class SecurityAnalyzer:
    @staticmethod
    def get_file_hash(file_path):
        """Calculate SHA256 hash of file"""
        try:
            with open(file_path, "rb") as f:
                file_bytes = f.read()
                return hashlib.sha256(file_bytes).hexdigest()
        except Exception as e:
            return f"HashError: {e}"
    
    @staticmethod
    def analyze_file_threat(file_path, file_size):
        """Comprehensive file threat analysis"""
        ext = os.path.splitext(file_path)[1].lower()
        threat_indicators = []
        mitre_techniques = []
        severity = "LOW"
        
        if ext in SUSPICIOUS_EXTENSIONS:
            threat_indicators.append(f"Suspicious extension: {ext}")
            mitre_techniques.append(SUSPICIOUS_EXTENSIONS[ext])
            severity = "MEDIUM"
        
        if any(sensitive_dir.lower() in file_path.lower() for sensitive_dir in SENSITIVE_DIRECTORIES):
            threat_indicators.append("File in sensitive system directory")
            mitre_techniques.append("T1543.003")  
            severity = "HIGH"
        
        if file_size > MAX_FILE_SIZE:
            threat_indicators.append(f"Unusually large file: {file_size} bytes")
            severity = "MEDIUM"
        elif file_size < MIN_SUSPICIOUS_SIZE and ext in ['.exe', '.dll', '.com']:
            threat_indicators.append(f"Suspiciously small executable: {file_size} bytes")
            severity = "MEDIUM"
        
        temp_indicators = ['temp', 'tmp', 'public', 'downloads']
        if any(temp_dir in file_path.lower() for temp_dir in temp_indicators):
            threat_indicators.append("File in common malware drop location")
            mitre_techniques.append("T1105")  
            if severity == "LOW":
                severity = "MEDIUM"
        
        primary_technique = mitre_techniques[0] if mitre_techniques else "T1105"
        
        return {
            'is_suspicious': len(threat_indicators) > 0,
            'threat_indicators': threat_indicators,
            'mitre_technique': primary_technique,
            'all_techniques': mitre_techniques,
            'severity': severity
        }

class EnhancedSecurityMonitor(FileSystemEventHandler):
    def __init__(self):
        self.db = ThreatDatabase()
        self.analyzer = SecurityAnalyzer()
        print("Enhanced Security Monitor initialized")
    
    def on_created(self, event):
        if event.is_directory:
            return
        
        self.analyze_file_event("FILE_CREATED", event.src_path)
    
    def on_modified(self, event):
        if not event.is_directory:
            ext = os.path.splitext(event.src_path)[1].lower()
            if ext in SUSPICIOUS_EXTENSIONS:
                self.analyze_file_event("FILE_MODIFIED", event.src_path)
    
    def on_moved(self, event):
        if not event.is_directory:
            dest_analysis = self.analyzer.analyze_file_threat(event.dest_path, 0)
            if dest_analysis['is_suspicious']:
                print(f"Suspicious Move: {event.src_path} ➡️ {event.dest_path}")
                self.analyze_file_event("FILE_MOVED", event.dest_path)
    
    def analyze_file_event(self, event_type, file_path):
        """Comprehensive file event analysis"""
        try:
            file_size = os.path.getsize(file_path)
            file_hash = self.analyzer.get_file_hash(file_path)

            analysis = self.analyzer.analyze_file_threat(file_path, file_size)
            
            print(f"\n{event_type}: {file_path}")
            print(f"Size: {file_size:,} bytes")
            print(f"SHA-256: {file_hash[:16]}...")
            
            if analysis['is_suspicious']:
                print(f"THREAT DETECTED!")
                print(f"MITRE Technique: {analysis['mitre_technique']}")
                print(f"Severity: {analysis['severity']}")
                print(f"Indicators:")
                for indicator in analysis['threat_indicators']:
                    print(f"   • {indicator}")
                
                details = {
                    'indicators': analysis['threat_indicators'],
                    'all_techniques': analysis['all_techniques'],
                    'extension': os.path.splitext(file_path)[1].lower()
                }
                
                self.db.log_event(
                    event_type=event_type,
                    file_path=file_path,
                    technique=analysis['mitre_technique'],
                    severity=analysis['severity'],
                    file_hash=file_hash,
                    file_size=file_size,
                    details=details
                )
            else:
                print("File appears benign")
            
            print("-" * 60)
            
        except Exception as e:
            print(f"Error analyzing file {file_path}: {e}")

def print_startup_banner():
    """Print startup information"""
    print("="*80)
    print("   ENHANCED FILE SECURITY MONITOR")
    print("   MITRE ATT&CK Framework Integration")
    print("   Real-time Threat Detection & Correlation")
    print("="*80)
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Hostname: {os.environ.get('COMPUTERNAME', 'Unknown')}")
    print("Database: threat_detection.db")
    print()

def main():
    print_startup_banner()
    
    event_handler = EnhancedSecurityMonitor()
    observer = Observer()
    
    monitored_count = 0
    for path in WATCHED_DIRECTORIES:
        if os.path.exists(path):
            print(f"Monitoring: {path}")
            observer.schedule(event_handler, path, recursive=True)
            monitored_count += 1
        else:
            print(f"Directory not found: {path}")
    
    if monitored_count == 0:
        print("No directories to monitor! Exiting...")
        return
    
    print(f"\n Monitoring directories")
    print("Watching for suspicious file activities...")
    print("Press Ctrl+C to stop monitoring\n")
    
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping monitor...")
        observer.stop()
        print("Monitor stopped safely")
    
    observer.join()

if __name__ == "__main__":
    main()