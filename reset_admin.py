
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash
import os

from database import connect_db

load_dotenv()

username = os.getenv("ADMIN_USERNAME")
password = os.getenv("ADMIN_PASSWORD")

if not username or not password:
    raise ValueError("Check ADMIN_USERNAME and ADMIN_PASSWORD in .env")

conn = connect_db()

try:
    password_hash = generate_password_hash(password)

    existing = conn.execute(
        "SELECT id FROM admins WHERE username = ?",
        (username,)
    ).fetchone()

    if existing:
        conn.execute(
            """
            UPDATE admins
            SET password_hash = ?
            WHERE username = ?
            """,
            (password_hash, username)
        )
    else:
        conn.execute(
            """
            INSERT INTO admins (username, password_hash)
            VALUES (?, ?)
            """,
            (username, password_hash)
        )

    conn.commit()

    print("Admin username and password updated successfully!")

finally:
    conn.close()
