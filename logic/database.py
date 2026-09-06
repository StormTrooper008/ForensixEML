import sqlite3
import os
from typing import Dict, Any

DB_PATH = "forensics.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # 1. Cases Table (Now includes telemetry column)
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
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            telemetry TEXT
        )
    """)

    # Safe Migration: Add telemetry column to older DBs if it doesn't exist
    try:
        cursor.execute("ALTER TABLE cases ADD COLUMN telemetry TEXT")
    except sqlite3.OperationalError:
        pass # Column already exists, safe to ignore

    # 2. Employees Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT,
            email TEXT UNIQUE,
            designation TEXT
        )
    """)

    # 3. Blocklist Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator_type TEXT,
            indicator_value TEXT UNIQUE,
            reason TEXT
        )
    """)

    # 4. Users Table
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
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Automatically run migration when imported
init_db()