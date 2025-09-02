import time
import psutil
from filesystemmonitor import ThreatDatabase  

SUSPICIOUS_PROCESSES = {
    "powershell.exe": "T1059.001", 
    "cmd.exe": "T1059.003",         
    "wscript.exe": "T1059.005",    
    "cscript.exe": "T1059.005",     
    "mshta.exe": "T1218.005",      
    "rundll32.exe": "T1218.011"     
}

SUSPICIOUS_DIRS = [
    r"\appdata\local\temp",
    r"\windows\temp",
    r"\users\public",
    r"\appdata\roaming"
]

class ProcessWatcher:
    """Watches system processes for suspicious activity and logs to ThreatDatabase."""

    def __init__(self):
        self.db = ThreatDatabase("threat_detection.db")  
        self.seen_pids = set()
        print("Process Watcher initialized and linked to threat_detection.db")

    def _severity_rank(self, sev):
        """Ranking helper for severity levels."""
        return {"LOW": 1, "MEDIUM": 2, "HIGH": 3}.get(sev, 0)

    def analyze_process(self, proc):
        """Check process for suspicious indicators."""
        indicators = []
        mitre_techniques = []
        severity = "LOW"

        try:
            name = (proc.info.get('name') or "").lower()
            exe_path = (proc.info.get('exe') or "").lower()
            cmdline = " ".join(proc.info.get('cmdline') or []).lower()

            if name in SUSPICIOUS_PROCESSES:
                indicators.append(f"Suspicious process: {name}")
                mitre_techniques.append(SUSPICIOUS_PROCESSES[name])
                severity = max(severity, "MEDIUM", key=self._severity_rank)

            if exe_path and any(sdir in exe_path for sdir in SUSPICIOUS_DIRS):
                indicators.append("Process running from suspicious directory")
                mitre_techniques.append("T1105") 
                severity = max(severity, "HIGH", key=self._severity_rank)

            if "encodedcommand" in cmdline or "downloadstring" in cmdline:
                indicators.append("Suspicious command-line flags")
                mitre_techniques.append("T1059.001") 
                severity = max(severity, "HIGH", key=self._severity_rank)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None  

        return {
            'is_suspicious': bool(indicators),
            'indicators': indicators,
            'mitre_technique': mitre_techniques[0] if mitre_techniques else "T1057",  
            'all_techniques': mitre_techniques,
            'severity': severity
        }

    def _report_suspicious(self, proc, analysis):
        """Log and print suspicious process details."""
        pid = proc.info['pid']
        print(f"\nSuspicious Process Detected: {proc.info.get('name')} (PID {pid})")
        print(f"Path: {proc.info.get('exe')}")
        print(f"Command: {' '.join(proc.info.get('cmdline') or [])}")
        print(f"MITRE Technique: {analysis['mitre_technique']}")
        print(f"Severity: {analysis['severity']}")
        for ind in analysis['indicators']:
            print(f"   • {ind}")

        details = {
            'pid': pid,
            'name': proc.info.get('name'),
            'exe': proc.info.get('exe'),
            'cmdline': proc.info.get('cmdline'),
            'indicators': analysis['indicators'],
            'all_techniques': analysis['all_techniques']
        }

        self.db.log_event(
            event_type="PROCESS_STARTED",
            file_path=proc.info.get('exe') or proc.info.get('name'),
            technique=analysis['mitre_technique'],
            severity=analysis['severity'],
            file_hash="N/A",  
            file_size=0,
            details=details
        )

    def watch_processes(self):
        """Continuously watch for suspicious processes."""
        print("Watching for suspicious processes... (Press Ctrl+C to stop)")
        try:
            while True:
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                    pid = proc.info['pid']

                    if pid not in self.seen_pids:
                        self.seen_pids.add(pid)
                        analysis = self.analyze_process(proc)
                        if analysis and analysis['is_suspicious']:
                            self._report_suspicious(proc, analysis)

                self.seen_pids.intersection_update(
                    p.pid for p in psutil.process_iter(['pid'])
                )

                time.sleep(2)  

        except KeyboardInterrupt:
            print("\nProcess watcher stopped.")

        except Exception as e:
            print(f"Unexpected error: {e}")


if __name__ == "__main__":
    watcher = ProcessWatcher()
    watcher.watch_processes()