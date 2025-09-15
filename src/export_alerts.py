import sqlite3
import json
import csv
from pathlib import Path

DB_PATH = "data/ids.db"
JSON_PATH = "exported_alerts.json"
CSV_PATH = "exported_alerts.csv"

def fetch_alerts():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts")
    columns = [desc[0] for desc in cursor.description]
    rows = cursor.fetchall()
    conn.close()
    return columns, rows

def export_to_json(columns, rows):
    alerts = [dict(zip(columns, row)) for row in rows]
    with open(JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=4)
    print(f"[JSON] Exported {len(alerts)} alerts to {JSON_PATH}")

def export_to_csv(columns, rows):
    with open(CSV_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(columns)
        writer.writerows(rows)
    print(f"[CSV] Exported {len(rows)} alerts to {CSV_PATH}")

def main():
    Path("exported_alerts.json").unlink(missing_ok=True)
    Path("exported_alerts.csv").unlink(missing_ok=True)

    columns, rows = fetch_alerts()
    export_to_json(columns, rows)
    export_to_csv(columns, rows)

if __name__ == "__main__":
    main()
