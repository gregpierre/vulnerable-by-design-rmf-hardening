"""
IT Helpdesk Ticket Tracker -- Stage (c): hardened.

Stage (a) was deliberately insecure; VULNERABILITIES.md has the original
findings and HARDENING.md documents each remediation with its NIST 800-53
control rationale. This file implements those fixes.
"""
import logging
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, abort, g, redirect, render_template, request, session, url_for
from flask_wtf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

import config

app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Only safe to flip on once the app is served over TLS -- see VULN-16 /
# HARDENING.md. Local dev over plain HTTP must keep this False.
app.config["SESSION_COOKIE_SECURE"] = config.SESSION_COOKIE_SECURE

csrf = CSRFProtect(app)

logger = logging.getLogger("helpdesk")
logger.setLevel(logging.INFO)
_handler = logging.FileHandler(config.LOG_FILE)
_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logger.addHandler(_handler)


def log_event(level, event, **fields):
    fields.setdefault("ip", request.remote_addr)
    detail = " ".join(f"{k}={v}" for k, v in fields.items())
    logger.log(level, "%s %s", event, detail)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(config.DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        if session.get("must_change_password") and request.endpoint not in (
            "change_password",
            "logout",
        ):
            return redirect(url_for("change_password"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if session.get("role") != "admin":
            log_event(logging.WARNING, "access_denied", user=session["username"], path=request.path)
            abort(403)
        return view(*args, **kwargs)

    return wrapped


@app.route("/")
def index():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        if not username or not password:
            error = "Username and password are required."
        else:
            db = get_db()
            try:
                db.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'user')",
                    (username, generate_password_hash(password, method="pbkdf2:sha256")),
                )
                db.commit()
            except sqlite3.IntegrityError:
                error = "That username is already taken."
            else:
                log_event(logging.INFO, "register", user=username)
                return redirect(url_for("login"))
    return render_template("register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user and user["locked_until"]:
            locked_until = datetime.fromisoformat(user["locked_until"])
            if datetime.utcnow() < locked_until:
                log_event(logging.WARNING, "login_blocked_locked", user=username)
                return render_template(
                    "login.html", error="Account temporarily locked. Try again later."
                )

        if user and check_password_hash(user["password_hash"], password):
            db.execute(
                "UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE id = ?",
                (user["id"],),
            )
            db.commit()
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["user_id"] = user["id"]
            session["must_change_password"] = bool(user["must_change_password"])
            log_event(logging.INFO, "login_success", user=username)
            if session["must_change_password"]:
                return redirect(url_for("change_password"))
            return redirect(url_for("dashboard"))

        if user:
            new_count = user["failed_login_count"] + 1
            if new_count >= config.LOGIN_MAX_ATTEMPTS:
                locked_until = datetime.utcnow() + timedelta(seconds=config.LOGIN_LOCKOUT_SECONDS)
                db.execute(
                    "UPDATE users SET failed_login_count = ?, locked_until = ? WHERE id = ?",
                    (new_count, locked_until.isoformat(), user["id"]),
                )
                log_event(logging.WARNING, "account_locked", user=username, attempts=new_count)
            else:
                db.execute(
                    "UPDATE users SET failed_login_count = ? WHERE id = ?", (new_count, user["id"])
                )
            db.commit()

        log_event(logging.WARNING, "login_failure", user=username)
        error = "Invalid credentials"
    return render_template("login.html", error=error)


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    error = None
    if request.method == "POST":
        current = request.form["current_password"]
        new = request.form["new_password"]
        confirm = request.form["confirm_password"]
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()

        if not check_password_hash(user["password_hash"], current):
            error = "Current password is incorrect."
        elif len(new) < 8:
            error = "New password must be at least 8 characters."
        elif new != confirm:
            error = "New password and confirmation do not match."
        else:
            db.execute(
                "UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?",
                (generate_password_hash(new, method="pbkdf2:sha256"), user["id"]),
            )
            db.commit()
            session["must_change_password"] = False
            log_event(logging.INFO, "password_changed", user=session["username"])
            return redirect(url_for("dashboard"))
    return render_template("change_password.html", error=error)


@app.route("/logout")
def logout():
    if "username" in session:
        log_event(logging.INFO, "logout", user=session["username"])
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    db = get_db()
    if request.method == "POST":
        title = request.form["title"]
        description = request.form["description"]
        db.execute(
            "INSERT INTO tickets (user_id, title, description) VALUES (?, ?, ?)",
            (session["user_id"], title, description),
        )
        db.commit()
    tickets = db.execute(
        "SELECT * FROM tickets WHERE user_id = ? ORDER BY id DESC",
        (session["user_id"],),
    ).fetchall()
    return render_template("dashboard.html", tickets=tickets, username=session["username"])


@app.route("/tickets/search")
@login_required
def search_tickets():
    q = request.args.get("q", "")
    db = get_db()
    results = db.execute(
        "SELECT * FROM tickets WHERE user_id = ? AND title LIKE ? ORDER BY id DESC",
        (session["user_id"], f"%{q}%"),
    ).fetchall()
    return render_template("dashboard.html", tickets=results, username=session["username"])


@app.route("/admin/tickets")
@admin_required
def admin_tickets():
    db = get_db()
    tickets = db.execute(
        "SELECT tickets.*, users.username FROM tickets JOIN users ON tickets.user_id = users.id ORDER BY tickets.id DESC"
    ).fetchall()
    return render_template("admin_tickets.html", tickets=tickets)


@app.route("/admin/tickets/<int:ticket_id>")
@login_required
def ticket_detail(ticket_id):
    db = get_db()
    ticket = db.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    if ticket is None:
        abort(404)
    if session.get("role") != "admin" and ticket["user_id"] != session["user_id"]:
        log_event(
            logging.WARNING,
            "access_denied",
            user=session["username"],
            path=request.path,
            reason="ticket_not_owned",
        )
        abort(403)
    return render_template("ticket_detail.html", ticket=ticket)


@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="Forbidden"), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Not found"), 404


@app.errorhandler(500)
def server_error(e):
    logger.exception("unhandled_exception")
    return render_template("error.html", code=500, message="Something went wrong"), 500


if __name__ == "__main__":
    # debug/host now come from .env, defaulting to debug=False and
    # host=127.0.0.1 -- see VULN-11, VULN-12 and HARDENING.md.
    app.run(host=config.FLASK_HOST, port=config.FLASK_PORT, debug=config.FLASK_DEBUG)
