import sqlite3
import time
import os

DB_PATH = "storage/packets.db"

def init_db():
    os.makedirs("storage", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            size INTEGER
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            src_ip TEXT,
            severity TEXT,
            description TEXT,
            rule_id TEXT
        )
    """)

    conn.commit()
    conn.close()

def store_packet(parsed):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, size)
        VALUES (?, ?, ?, ?, ?)
    """, (time.time(), parsed.get("src_ip"), parsed.get("dst_ip"),
          parsed.get("protocol"), parsed.get("size")))
    conn.commit()
    conn.close()

def store_alert(src_ip, severity, description, rule_id):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO alerts (timestamp, src_ip, severity, description, rule_id)
        VALUES (?, ?, ?, ?, ?)
    """, (time.time(), src_ip, severity, description, rule_id))
    conn.commit()
    conn.close()
