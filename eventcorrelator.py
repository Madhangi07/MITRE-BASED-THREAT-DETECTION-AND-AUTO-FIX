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
            countermeasures TEXT,
            status TEXT
        )''')
        conn.commit()
        conn.close()

    def fetch_recent_events(self, seconds=300):
        cutoff_time = time.time() - seconds
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute('''
            SELECT id, event_type, file_path, mitre_technique, severity, datetime_str, details
            FROM events
            WHERE timestamp > ?
        ''', (cutoff_time,))
        events = cursor.fetchall()
        conn.close()
        return events

    def generate_countermeasure(self, severity, techniques):
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

    def execute_action(self, countermeasure):
        try:
            if "Terminate" in countermeasure:
                print("[SYSTEM] Terminating malicious process (simulated).")
            elif "Network Isolation" in countermeasure:
                print("[SYSTEM] Applying network isolation (simulated).")
            elif "Quarantine" in countermeasure:
                print("[SYSTEM] Quarantining file (simulated).")
            else:
                print(f"[SYSTEM] Executed generic action: {countermeasure}")
        except Exception as e:
            print(f"[ERROR] Failed to execute countermeasure {countermeasure}: {e}")

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

    def is_already_handled(self, techniques):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, status FROM correlations
            WHERE techniques = ?
            ORDER BY id DESC
            LIMIT 1
        ''', (",".join(techniques),))
        row = cursor.fetchone()
        conn.close()
        return row is not None and row[1] == "HANDLED"

    def apply_countermeasures_batch(self, events, correlation_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT status FROM correlations WHERE id = ?", (correlation_id,))
        status = cursor.fetchone()[0]

        if status == "HANDLED":
            for event in events:
                tech_id = event[3]
                if tech_id in self.d3fend_map:
                    cms = self.d3fend_map[tech_id].get("countermeasures", [])
                    for cm in cms:
                        self.execute_action(cm)
            conn.close()
            return True

        unique_techniques = list(set(e[3] for e in events if e[3]))
        print(f"\n[ACTION] Batch countermeasures for {len(events)} events (techniques: {', '.join(unique_techniques)}):")

        choice = input("   Apply countermeasures for this batch? (y/n): ").strip().lower()
        if choice != "y":
            print("[INFO] Batch skipped. Correlation remains PENDING.\n")
            conn.close()
            return False

        for tech_id in unique_techniques:
            if tech_id in self.d3fend_map:
                cms = self.d3fend_map[tech_id].get("countermeasures", [])
                for cm in cms:
                    self.execute_action(cm)

        conn.execute("UPDATE correlations SET status='HANDLED' WHERE id=?", (correlation_id,))
        conn.commit()
        conn.close()
        print(f"[INFO] Batch of {len(events)} events marked as HANDLED\n")
        return True

    def correlate(self):
        events = self.fetch_recent_events()
        if not events:
            print("[INFO] No events in DB, skipping...")
            return

        techniques_list = list(set(e[3] for e in events if e[3]))
        if self.is_already_handled(techniques_list):
            print("[INFO] These techniques were already handled. Skipping correlation.")
            return

        countermeasure = self.generate_countermeasure("HIGH", techniques_list)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO correlations (timestamp, event_count, techniques, severity, description, countermeasures, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            time.time(),
            len(events),
            ",".join(techniques_list),
            "HIGH",
            f"{len(events)} recent event(s) found.",
            countermeasure,
            "PENDING"
        ))
        conn.commit()
        correlation_id = cursor.lastrowid
        conn.close()

        print("\n" + "="*60)
        print(f"ALERT: Event Correlation Detected | Severity: HIGH")
        print(f"Description: {len(events)} recent event(s) found.")
        print(f"Countermeasures: {countermeasure}")
        print(f"Correlation ID: {correlation_id} | Status: PENDING")
        print("="*60 + "\n")

        self.send_alert(
            subject=f"[SECURITY ALERT] Event Correlation Detected - HIGH",
            body=f"{len(events)} recent event(s) found.\nCountermeasures: {countermeasure}"
        )

        BATCH_SIZE = 10
        for i in range(0, len(events), BATCH_SIZE):
            batch = events[i:i+BATCH_SIZE]
            self.apply_countermeasures_batch(batch, correlation_id)

    def run(self, interval=60):
        print(f"[INFO] Event correlator running every {interval} seconds...")
        try:
            while True:
                self.correlate()
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[INFO] Event correlator stopped.")


def insert_small_fake_events(db_path="threat_detection.db"):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    now = time.time()
    dt_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for i in range(10):
        cursor.execute('''
            INSERT INTO events (timestamp, event_type, file_path, mitre_technique, severity, datetime_str, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            now,
            "FILE",
            f"/tmp/fake{i}.exe",
            "T1105" if i % 2 == 0 else "T1059.001",
            "HIGH" if i % 3 == 0 else "MEDIUM",
            dt_str,
            f"Fake suspicious file {i}"
        ))

    conn.commit()
    conn.close()
    print("[TEST] 10 fake events inserted into DB")


if __name__ == "__main__":
    insert_small_fake_events()  
    correlator = EventCorrelator()
    correlator.run(5)