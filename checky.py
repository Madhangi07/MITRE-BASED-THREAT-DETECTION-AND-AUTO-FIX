import sqlite3

conn = sqlite3.connect("threat_detection.db")
cursor = conn.cursor()

cursor.execute("SELECT timestamp, event_type, countermeasures FROM events ORDER BY timestamp DESC LIMIT 5")
rows = cursor.fetchall()
for r in rows:
    print(r)

conn.close()