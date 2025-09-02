import sqlite3
from flask import Flask, render_template
import threading
import time

DB_PATH = "threat_detection.db"
app = Flask(__name__)

def get_events(limit=20):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute('''
        SELECT datetime_str, event_type, file_path, mitre_technique, severity, hostname 
        FROM events ORDER BY timestamp DESC LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_correlations(limit=10):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute('''
        SELECT timestamp, event_count, techniques, severity, description
        FROM correlations ORDER BY timestamp DESC LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows

@app.route("/")
def dashboard():
    events = get_events()
    correlations = get_correlations()
    return render_template("dashboard.html", events=events, correlations=correlations)

def run_dashboard():
    app.run(host="0.0.0.0", port=5000, debug=False)

if __name__ == "__main__":
    run_dashboard()
