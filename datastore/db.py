# datastore/db.py
import sqlite3


def get_connection():
    return sqlite3.connect("events.db")


def initialize_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source TEXT,
            event_type TEXT,
            entity TEXT,
            severity INTEGER,
            metadata TEXT
        )
    """)

    conn.commit()
    conn.close()
