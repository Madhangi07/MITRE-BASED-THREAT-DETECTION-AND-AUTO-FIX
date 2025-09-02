import sqlite3
import time
import json
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class EventCorrelator:
    def __init__(self, db_path="threat_detection.db", d3fend_file="compact_d3fend.json"):
        self.db_path = db_path
        self.d3fend_map = self.load_d3fend(d3fend_file)
        self.init_db()
        print(f"[INFO] Event Correlator initialized with DB: {db_path} and D3FEND mapping.")

    def load_d3fend(self, mapping_file):
        try:
            with open(mapping_file, "r") as f:
                return json.load(f)
        except Exception as e:
            print(f"[ERROR] Failed to load D3FEND mapping: {e}")
            return {}

    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            event_type TEXT,
            file_path TEXT,
            mitre_technique TEXT,
            severity TEXT,
            datetime_str TEXT,
            details TEXT
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS correlations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            event_count INTEGER,
            techniques TEXT,
            severity TEXT,
            description TEXT,
            countermeasures TEXT
        )''')
        conn.commit()
        conn.close()

    def fetch_recent_events(self, seconds=300):
        cutoff_time = time.time() - seconds
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute('''
            SELECT event_type, file_path, mitre_technique, severity, datetime_str, details 
            FROM events 
            WHERE timestamp > ?
        ''', (cutoff_time,))
        events = cursor.fetchall()
        conn.close()
        return events

    def generate_countermeasure(self, severity, techniques):
        """Generate countermeasures dynamically based on severity and MITRE techniques."""
        measures = []

        if "T1055.001" in techniques:
            measures.append("Terminate injected process")
        if "T1049" in techniques:
            measures.append("Check network connections / Alert admin")
        if "T1204.002" in techniques:
            measures.append("Quarantine malicious file / Notify user")
        if "T1105" in techniques:
            measures.append("Block download / Scan file")
        if "T1059.001" in techniques:
            measures.append("Restrict PowerShell / Log commands")

        if severity == "CRITICAL":
            measures.append("Immediate investigation required")
        elif severity == "HIGH":
            measures.append("Monitor activity closely")
        else:
            measures.append("Log for review")

        return " | ".join(measures)

    def apply_countermeasures(self, technique_id):
        """Apply or simulate countermeasures based on MITRE technique from D3FEND mapping."""
        if technique_id not in self.d3fend_map:
            print(f"[INFO] No countermeasures found for {technique_id}")
            return

        cms = self.d3fend_map[technique_id].get("countermeasures", [])
        if not cms:
            print(f"[INFO] Empty countermeasure list for {technique_id}")
            return

        print(f"[ACTION] Countermeasures for {technique_id}:")
        for cm in cms:
            print(f"   - {cm}")
            self.simulate_action(cm)

    def simulate_action(self, countermeasure):
        """Stub to simulate actual response actions."""
        if "Terminate Process" in countermeasure:
            print("[SYSTEM] Would terminate malicious process here")
        elif "Network Isolation" in countermeasure:
            print("[SYSTEM] Would isolate network here")
        elif "File Quarantine" in countermeasure:
            print("[SYSTEM] Would move file to quarantine folder")
        else:
            print(f"[SYSTEM] Simulated countermeasure: {countermeasure}")

    def send_alert(self, subject, body):
        sender = "madhangir2005@gmail.com"
        receiver = "divyax1385@gmail.com"
        password = "kacf kepe wula dlev" 

        try:
            msg = MIMEMultipart()
            msg["From"] = sender
            msg["To"] = receiver
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain"))

            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.starttls()
            server.login(sender, password)
            server.send_message(msg)
            server.quit()

            print(f"[ALERT] Email sent to {receiver}: {subject}")
        except Exception as e:
            print(f"[ERROR] Failed to send email alert: {e}")

    def correlate(self):
        events = self.fetch_recent_events()
        if not events:
            print("[INFO] No events in DB, skipping...")
            return

        alerts = [{
            "severity": "HIGH",
            "rule": "Event Correlation Detected",
            "description": f"{len(events)} recent event(s) found."
        }]

        conn = sqlite3.connect(self.db_path)
        for alert in alerts:
            techniques_list = list(set(e[2] for e in events if e[2]))
            countermeasure = self.generate_countermeasure(alert["severity"], techniques_list)

            conn.execute('''
                INSERT INTO correlations (timestamp, event_count, techniques, severity, description, countermeasures)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                time.time(),
                len(events),
                ",".join(techniques_list),
                alert["severity"],
                alert["description"],
                countermeasure
            ))
            conn.commit()

            print("\n" + "="*60)
            print(f"ALERT: {alert['rule']} | Severity: {alert['severity']}")
            print(f"Description: {alert['description']}")
            print(f"Countermeasures: {countermeasure}")
            print("="*60 + "\n")

            self.send_alert(
                subject=f"[SECURITY ALERT] {alert['rule']} - {alert['severity']}",
                body=f"{alert['description']}\nCountermeasures: {countermeasure}"
            )

            for event in events:
                tech_id = event[2]
                self.apply_countermeasures(tech_id)
        conn.close()

    def run(self, interval=60):
        print(f"[INFO] Event correlator running every {interval} seconds...")
        try:
            while True:
                self.correlate()
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[INFO] Event correlator stopped.")

def insert_fake_events(db_path="threat_detection.db"):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    now = time.time()
    dt_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute('''
        INSERT INTO events (timestamp, event_type, file_path, mitre_technique, severity, datetime_str, details)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (now, "FILE", "/tmp/suspicious.exe", "T1105", "HIGH", dt_str, "Suspicious file created"))

    cursor.execute('''
        INSERT INTO events (timestamp, event_type, file_path, mitre_technique, severity, datetime_str, details)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (now, "PROCESS", "malware.exe", "T1059.001", "CRITICAL", dt_str, "Suspicious process started"))

    cursor.execute('''
        INSERT INTO events (timestamp, event_type, file_path, mitre_technique, severity, datetime_str, details)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (now, "NETWORK", "192.168.1.50", "T1049", "MEDIUM", dt_str, "Suspicious connection opened"))

    conn.commit()
    conn.close()
    print("[TEST] Fake events inserted into DB")


if __name__ == "__main__":
    correlator = EventCorrelator()

    correlator.send_alert(
        "Test Alert - Email Check",
        "This is a forced test alert to confirm the email system works."
    )

    insert_fake_events()

    correlator.run(5)