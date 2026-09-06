import sqlite3
import os
from typing import Dict, Any

# Name changed to reflect the database's actual function
DB_PATH = "forensics.db"

def init_db():
    """Initializes the SQLite database and creates necessary tables if they don't exist."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # 1. Cases Table: Stores all parsed email investigations
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            file_name TEXT,
            sha256 TEXT UNIQUE,
            sender TEXT,
            subject TEXT,
            origin_ip TEXT,
            risk_score INTEGER,
            status TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 2. Employees Table: For cross-referencing internal spoofing
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT,
            email TEXT UNIQUE,
            designation TEXT
        )
    """)

    # 3. Blocklist Table: For custom flagged URLs/IPs
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator_type TEXT, -- e.g., 'IP', 'URL', 'EMAIL'
            indicator_value TEXT UNIQUE,
            reason TEXT
        )
    """)

    # 4. Users Table: For dashboard login credentials
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            role TEXT
        )
    """)

    conn.commit()
    conn.close()

def get_db_connection():
    """Returns a connection to the database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Allows accessing columns by name
    return conn

if __name__ == "__main__":
    init_db()
    print(f"Database initialized successfully at {DB_PATH}")