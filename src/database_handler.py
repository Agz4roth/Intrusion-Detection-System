import sqlite3
from pathlib import Path
from typing import Dict

class Database:
    def __init__(self, path="data/ids.db"):
        self.path = path
        self.conn = None

    def init(self):
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        cur = self.conn.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT (datetime('now')),
            threat_id TEXT,
            severity TEXT,
            description TEXT
        );
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT,
            description TEXT,
            severity TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            proto TEXT,
            timestamp REAL,
            rep_score INTEGER
        );
        """)

        self.conn.commit()

    def insert_threat(self, threat_id: str, severity: str, description: str):
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO threats (threat_id, severity, description) VALUES (?, ?, ?)",
            (threat_id, severity, str(description))
        )
        self.conn.commit()

    def insert_alert(self, alert: Dict):
        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO alerts (id, description, severity, src_ip, dst_ip, proto, timestamp, rep_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert["id"],
            alert["description"],
            alert["severity"],
            alert["src_ip"],
            alert["dst_ip"],
            alert["proto"],
            alert["timestamp"],
            alert["rep_score"]
        ))
        self.conn.commit()

    def close(self):
        try:
            if self.conn:
                self.conn.close()
        except Exception:
            pass
