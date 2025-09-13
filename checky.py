import sqlite3

db_path = "threat_detection.db"

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Get all tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()

# Wipe each table
for table in tables:
    table_name = table[0]
    cursor.execute(f"DELETE FROM {table_name};")
    print(f"[INFO] Cleared table: {table_name}")

conn.commit()
conn.close()
print("[INFO] Database cleared but schema intact.")
