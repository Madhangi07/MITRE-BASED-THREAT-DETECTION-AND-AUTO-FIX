from flask import Flask, jsonify, render_template
import sqlite3

app = Flask(__name__)
DB_PATH = "threat_detection.db"


def fetch_events():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT timestamp, event_type, file_path, mitre_technique, severity, hostname, countermeasures FROM events ORDER BY timestamp DESC')
    rows = cursor.fetchall()
    conn.close()
    return [
        {
            "timestamp": r[0],
            "event_type": r[1],
            "file_path": r[2],
            "mitre_technique": r[3],
            "severity": r[4],
            "hostname": r[5],
            "countermeasures": r[6]
        }
        for r in rows
    ]

def fetch_correlations():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT timestamp, event_count, techniques, severity, description, countermeasures FROM correlations ORDER BY timestamp DESC')
    rows = cursor.fetchall()
    conn.close()
    return [
        {
            "timestamp": r[0],
            "event_count": r[1],
            "techniques": r[2],
            "severity": r[3],
            "description": r[4],
            "countermeasures": r[5]
        }
        for r in rows
    ]
def init_database():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # Make sure countermeasures column exists
    try:
        cursor.execute('ALTER TABLE events ADD COLUMN countermeasures TEXT')
        conn.commit()
    except sqlite3.OperationalError:
        pass  # Column already exists
    conn.close()


@app.route("/api/events")
def api_events():
    return jsonify(fetch_events())

@app.route("/api/correlations")
def api_correlations():
    return jsonify(fetch_correlations())


@app.route("/")
def dashboard():
    return render_template("dashboard.html")

if __name__ == "__main__":
    init_database()
    app.run(debug=True)