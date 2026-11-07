
import sqlite3
import os
from pathlib import Path
from werkzeug.security import generate_password_hash

# Database location
DB_PATH = Path("database/file_records.db")


# ----------------------------------
# DATABASE CONNECTION
# ----------------------------------

def connect_db():

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    return conn


# ----------------------------------
# CREATE FILE TABLE
# ----------------------------------

def create_table():

    conn = connect_db()

    try:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT UNIQUE NOT NULL,
                file_hash TEXT NOT NULL,
                status TEXT DEFAULT 'SAFE'
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                event_type TEXT NOT NULL,
                event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.commit()

    finally:
        conn.close()


# ----------------------------------
# CREATE ADMIN TABLE
# ----------------------------------

def create_admin_table():

    username = os.getenv("ADMIN_USERNAME")
    password = os.getenv("ADMIN_PASSWORD")

    if not username or not password:
        raise ValueError(
            "ADMIN_USERNAME or ADMIN_PASSWORD missing in .env"
        )

    conn = connect_db()

    try:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)

        existing_admin = conn.execute(
            "SELECT id FROM admins WHERE username = ?",
            (username,)
        ).fetchone()

        if existing_admin is None:

            password_hash = generate_password_hash(password)

            conn.execute("""
                INSERT INTO admins (username, password_hash)
                VALUES (?, ?)
            """, (username, password_hash))

        conn.commit()

    finally:
        conn.close()


# ----------------------------------
# REGISTER FILE
# ----------------------------------

def register_file(file_path, file_hash):

    conn = connect_db()

    try:

        conn.execute("""
            INSERT INTO files (file_path, file_hash, status)
            VALUES (?, ?, 'SAFE')
            ON CONFLICT(file_path)
            DO UPDATE SET
                file_hash = excluded.file_hash,
                status = 'SAFE'
        """, (file_path, file_hash))

        conn.commit()

    finally:
        conn.close()


# ----------------------------------
# GET ALL FILES
# ----------------------------------

def get_all_files():

    conn = connect_db()

    try:

        records = conn.execute("""
            SELECT * FROM files
            ORDER BY id DESC
        """).fetchall()

        return records

    finally:
        conn.close()


# ----------------------------------
# GET ALL SECURITY EVENTS
# ----------------------------------

def get_all_events(limit=None):

    conn = connect_db()

    try:

        if limit is not None:

            records = conn.execute("""
                SELECT * FROM security_events
                ORDER BY id DESC
                LIMIT ?
            """, (limit,)).fetchall()

        else:

            records = conn.execute("""
                SELECT * FROM security_events
                ORDER BY id DESC
            """).fetchall()

        return records

    finally:
        conn.close()


# ----------------------------------
# ADD SECURITY EVENT
# ----------------------------------

def add_event(file_path, event_type):

    conn = connect_db()

    try:

        conn.execute("""
            INSERT INTO security_events
            (file_path, event_type)
            VALUES (?, ?)
        """, (file_path, event_type))

        conn.commit()

    finally:
        conn.close()


# ----------------------------------
# UPDATE FILE HASH
# ----------------------------------

def update_hash(file_path, new_hash):

    conn = connect_db()

    try:

        conn.execute("""
            UPDATE files
            SET file_hash = ?, status = 'SAFE'
            WHERE file_path = ?
        """, (new_hash, file_path))

        conn.commit()

    finally:
        conn.close()


# ----------------------------------
# UPDATE FILE STATUS
# ----------------------------------

def update_status(file_path, status):

    conn = connect_db()

    try:

        conn.execute("""
            UPDATE files
            SET status = ?
            WHERE file_path = ?
        """, (status, file_path))

        conn.commit()

    finally:
        conn.close()


# ----------------------------------
# GET DASHBOARD STATISTICS
# ----------------------------------

def get_statistics():

    conn = connect_db()

    try:

        total = conn.execute("""
            SELECT COUNT(*) FROM files
        """).fetchone()[0]

        safe = conn.execute("""
            SELECT COUNT(*) FROM files
            WHERE status = 'SAFE'
        """).fetchone()[0]

        modified = conn.execute("""
            SELECT COUNT(*) FROM files
            WHERE status = 'MODIFIED'
        """).fetchone()[0]

        deleted = conn.execute("""
            SELECT COUNT(*) FROM files
            WHERE status = 'DELETED'
        """).fetchone()[0]

        return {
            "total": total,
            "safe": safe,
            "modified": modified,
            "deleted": deleted
        }

    finally:
        conn.close()
