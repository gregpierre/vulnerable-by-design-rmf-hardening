"""
Creates helpdesk.db and seeds it with an admin account.

Stage (c) hardening (IA-5, CM-6 -- see HARDENING.md):
  - Admin password is hashed (werkzeug.security), never stored in plaintext.
  - If ADMIN_BOOTSTRAP_PASSWORD is not set in .env, a random password is
    generated and printed ONCE. There is no fixed "admin123" default.
  - The seeded admin is flagged must_change_password so the first login
    forces a password change (IA-5(1)).

Run once: ./venv/bin/python init_db.py
"""
import secrets
import sqlite3

from werkzeug.security import generate_password_hash

import config

conn = sqlite3.connect(config.DATABASE)
c = conn.cursor()

c.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    must_change_password INTEGER NOT NULL DEFAULT 0,
    failed_login_count INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
)
""")

existing = c.execute(
    "SELECT id FROM users WHERE username = ?", (config.ADMIN_BOOTSTRAP_USERNAME,)
).fetchone()

if existing is None:
    admin_password = config.ADMIN_BOOTSTRAP_PASSWORD
    generated = False
    if not admin_password:
        admin_password = secrets.token_urlsafe(12)
        generated = True

    c.execute(
        "INSERT INTO users (username, password_hash, role, must_change_password) "
        "VALUES (?, ?, 'admin', 1)",
        (
            config.ADMIN_BOOTSTRAP_USERNAME,
            generate_password_hash(admin_password, method="pbkdf2:sha256"),
        ),
    )
    conn.commit()

    print(f"Initialized {config.DATABASE} with a seeded admin account.")
    print(f"  username: {config.ADMIN_BOOTSTRAP_USERNAME}")
    if generated:
        print(f"  password: {admin_password}  (generated -- shown once, not stored anywhere)")
    else:
        print("  password: <from ADMIN_BOOTSTRAP_PASSWORD in .env>")
    print("  This account must change its password on first login.")
else:
    print(f"{config.DATABASE} already has a '{config.ADMIN_BOOTSTRAP_USERNAME}' account -- nothing to do.")

conn.close()
