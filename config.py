"""
Stage (c): configuration is loaded from environment variables (via a local
.env, gitignored) instead of being hardcoded in source. See VULN-09 and
VULN-10 in VULNERABILITIES.md, and HARDENING.md for the control rationale
(IA-5, SC-12, SC-28, CM-6).
"""
import os
import secrets

from dotenv import load_dotenv

load_dotenv()


def _env_bool(name, default=False):
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY is not set. Copy .env.example to .env and set a value "
        "(generate one with: python -c \"import secrets; print(secrets.token_hex(32))\")."
    )

DATABASE = "helpdesk.db"

ADMIN_BOOTSTRAP_USERNAME = os.environ.get("ADMIN_BOOTSTRAP_USERNAME", "admin")
ADMIN_BOOTSTRAP_PASSWORD = os.environ.get("ADMIN_BOOTSTRAP_PASSWORD")  # None -> init_db.py generates one

FLASK_DEBUG = _env_bool("FLASK_DEBUG", default=False)
FLASK_HOST = os.environ.get("FLASK_HOST", "127.0.0.1")
FLASK_PORT = int(os.environ.get("FLASK_PORT", "5000"))

SESSION_COOKIE_SECURE = _env_bool("SESSION_COOKIE_SECURE", default=False)

LOG_FILE = "security.log"

LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 15 * 60


def generate_secret():
    return secrets.token_hex(32)
