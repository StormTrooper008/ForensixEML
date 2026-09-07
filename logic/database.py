import sqlite3

DB_PATH = "forensics.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # 1. Cases Table
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
            last_analyzed DATETIME DEFAULT CURRENT_TIMESTAMP,
            telemetry TEXT,
            notes TEXT
        )
    """)
    try: cursor.execute("ALTER TABLE cases ADD COLUMN telemetry TEXT")
    except sqlite3.OperationalError: pass
    try: 
        cursor.execute("ALTER TABLE cases ADD COLUMN last_analyzed DATETIME")
        cursor.execute("UPDATE cases SET last_analyzed = timestamp WHERE last_analyzed IS NULL")
    except sqlite3.OperationalError: pass
    try: cursor.execute("ALTER TABLE cases ADD COLUMN notes TEXT")
    except sqlite3.OperationalError: pass

    # 2. Personnel Table (Replaces Employees)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS personnel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id TEXT UNIQUE,
            full_name TEXT,
            email TEXT UNIQUE,
            designation TEXT,
            notes TEXT,
            timestamp_added DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_modified DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 3. Blocklist Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator_type TEXT,
            indicator_value TEXT UNIQUE,
            reason TEXT,
            notes TEXT,
            timestamp_added DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_modified DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    try: cursor.execute("ALTER TABLE blocklist ADD COLUMN notes TEXT")
    except sqlite3.OperationalError: pass
    try:
        cursor.execute("ALTER TABLE blocklist ADD COLUMN timestamp_added DATETIME")
        cursor.execute("ALTER TABLE blocklist ADD COLUMN last_modified DATETIME")
        cursor.execute("UPDATE blocklist SET timestamp_added = CURRENT_TIMESTAMP WHERE timestamp_added IS NULL")
        cursor.execute("UPDATE blocklist SET last_modified = CURRENT_TIMESTAMP WHERE last_modified IS NULL")
    except sqlite3.OperationalError: pass

    # 4. Users Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            role TEXT
        )
    """)

    # 5. Crash Logs Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS crash_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            error_message TEXT,
            traceback TEXT,
            user TEXT
        )
    """)

    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

init_db()