# Vulnerability Assessment — Stage (b)

**Subject:** IT Helpdesk Ticket Tracker (Flask/Python, SQLite)
**Methodology:** Manual secure code review of `app.py`, `config.py`, `init_db.py`, and all Jinja2 templates — analogous to the RMF *Assess* step / a SAST-lite pass feeding a POA&M.
**Framework:** NIST SP 800-53 Rev. 5 control families
**Status:** All findings below are open. Stage (c) will implement remediations and record control-implementation status per finding.

Findings are numbered VULN-01 through VULN-16, ordered roughly by exploitability/impact.

---

### VULN-01 — Plaintext password storage
**Location:** `app.py:46-49` (register), `init_db.py` (seeded admin)
**CWE:** CWE-256 (Plaintext Storage of a Password), CWE-522 (Insufficiently Protected Credentials)
**Control family:** IA — Identification and Authentication
**Control(s):** IA-5, IA-5(1)
**Risk:** High. A database compromise (e.g., via VULN-05 or VULN-08) yields every user's password in cleartext, with downstream risk to any other system where a user reused that password.

### VULN-02 — Plaintext password comparison at login
**Location:** `app.py:63-66`
**CWE:** CWE-256, CWE-522
**Control family:** IA
**Control(s):** IA-5
**Risk:** High. Same root cause as VULN-01 — authentication never involves a hash, so there is no cryptographic protection of the credential at rest or in comparison.

### VULN-03 — No account lockout / rate limiting on login
**Location:** `app.py` `login()`
**CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)
**Control family:** AC — Access Control
**Control(s):** AC-7
**Risk:** Medium-High. Nothing prevents an unlimited-rate online brute-force or credential-stuffing attack against `/login`.

### VULN-04 — No authentication event logging
**Location:** Application-wide — no logging calls anywhere in `app.py`
**CWE:** CWE-778 (Insufficient Logging)
**Control family:** AU — Audit and Accountability
**Control(s):** AU-2, AU-3, AU-12
**Risk:** Medium. No record of login success/failure, admin actions, or access to sensitive endpoints — no detective capability for VULN-03, VULN-06, VULN-07, or VULN-08 being exploited.

### VULN-05 — SQL injection in ticket search
**Location:** `app.py:109-113` (`search_tickets`)
**CWE:** CWE-89 (SQL Injection)
**Control family:** SI — System and Information Integrity
**Control(s):** SI-10
**Risk:** Critical. Query is built with `%`-string formatting instead of parameterization. The `q` parameter is fully attacker-controlled, enabling read access beyond the current user's tickets and potential write/DDL depending on SQLite driver behavior.

### VULN-06 — Broken access control on admin ticket view
**Location:** `app.py:117-127` (`admin_tickets`)
**CWE:** CWE-862 (Missing Authorization)
**Control family:** AC
**Control(s):** AC-3, AC-6
**Risk:** High. Checks only that a session exists, never that `session["role"] == "admin"`. Any authenticated user — including a self-registered one — can view every ticket from every user.

### VULN-07 — IDOR on ticket detail
**Location:** `app.py:130-138` (`ticket_detail`)
**CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)
**Control family:** AC
**Control(s):** AC-3, AC-6
**Risk:** High. Same missing role check as VULN-06, compounded by a sequential integer ID — any logged-in user can enumerate `/admin/tickets/<id>` to read arbitrary tickets.

### VULN-08 — Unauthenticated debug endpoint dumping credentials
**Location:** `app.py:141-148` (`debug_users`)
**CWE:** CWE-306 (Missing Authentication for Critical Function), CWE-215 (Information Exposure Through Debug Information)
**Control family:** AC / CM — Configuration Management
**Control(s):** AC-3, CM-7
**Risk:** Critical. `/internal/debug/users` requires no session at all and returns every username, plaintext password, and role in the database. This is the single most severe finding — full credential compromise with zero authentication.

### VULN-09 — Hardcoded application secret key
**Location:** `config.py:4`
**CWE:** CWE-798 (Use of Hard-coded Credentials)
**Control family:** IA / SC — System and Communications Protection
**Control(s):** IA-5, SC-12, SC-28
**Risk:** High. `SECRET_KEY` is committed in source. Anyone with repo access can forge signed session cookies (`itsdangerous`), impersonating any user including admin, without ever touching the database.

### VULN-10 — Hardcoded default admin credentials
**Location:** `config.py:6-7`, `init_db.py`
**CWE:** CWE-798, CWE-1188 (Insecure Default Initialization of Resource)
**Control family:** IA / CM
**Control(s):** IA-5, CM-6
**Risk:** High. `admin`/`admin123` is seeded automatically with no forced rotation on first use — a textbook default-credential finding.

### VULN-11 — Flask debug mode enabled
**Location:** `app.py:155`
**CWE:** CWE-489 (Active Debug Code)
**Control family:** CM / SI
**Control(s):** CM-7, SI-11
**Risk:** Critical. `debug=True` exposes the Werkzeug interactive debugger, which allows arbitrary Python execution from the browser if the debugger PIN is bypassed or unset in some configs, and leaks full stack traces (including source and local variables) on any unhandled exception.

### VULN-12 — Unnecessary network exposure
**Location:** `app.py:155`
**CWE:** CWE-668 (Exposure of Resource to Wrong Sphere)
**Control family:** SC / CM
**Control(s):** SC-7, CM-7
**Risk:** Medium. `host="0.0.0.0"` binds every interface rather than `127.0.0.1`, exposing the dev server to the local network unnecessarily.

### VULN-13 — Outdated, vulnerable dependencies
**Location:** `requirements.txt` (Flask 1.0.2, Werkzeug 0.14.1, Jinja2 2.10, itsdangerous 0.24, MarkupSafe 1.1.1)
**CWE:** CWE-1104 (Use of Unmaintained Third-Party Components)
**Control family:** SI / RA — Risk Assessment
**Control(s):** SI-2, RA-5
**Risk:** High. These pins predate multiple published CVEs against Werkzeug and Jinja2, including debugger and sandbox-escape issues. No mechanism currently exists to detect this (see Stage (d): CI/CD dependency scanning).

### VULN-14 — Stored XSS via disabled autoescaping
**Location:** `templates/dashboard.html`, `templates/ticket_detail.html` (`{{ ticket.description|safe }}`)
**CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)
**Control family:** SI
**Control(s):** SI-10
**Risk:** High. The `|safe` filter disables Jinja2's default autoescaping on ticket descriptions. Any user can submit an HTML/JS payload as a ticket description; it executes in the browser of anyone who views it — including an admin viewing `/admin/tickets`, making session-token theft (compounding VULN-06) plausible.

### VULN-15 — No CSRF protection on state-changing forms
**Location:** `templates/register.html`, `templates/login.html`, `templates/dashboard.html` (ticket-creation POST)
**CWE:** CWE-352 (Cross-Site Request Forgery)
**Control family:** SC
**Control(s):** SC-23
**Risk:** Medium. No CSRF token is issued or validated on any POST form; Flask does not provide this by default without Flask-WTF or similar. An attacker-controlled page could submit a ticket, or under some session configurations, register/log a victim in as an attacker-controlled account.

### VULN-16 — Session cookie not hardened
**Location:** `app.py` (no `SESSION_COOKIE_*` settings configured)
**CWE:** CWE-614 (Sensitive Cookie Without 'Secure' Attribute) — adapted, since the app also serves plain HTTP
**Control family:** SC
**Control(s):** SC-8, SC-23
**Risk:** Medium. `SESSION_COOKIE_SECURE` and `SESSION_COOKIE_SAMESITE` are left at Flask defaults, and the app serves HTTP only — the session cookie can be intercepted on an untrusted network.

---

## Summary by control family

| Family | Findings |
|---|---|
| AC (Access Control) | VULN-06, VULN-07, VULN-08 |
| IA (Identification & Authentication) | VULN-01, VULN-02, VULN-03, VULN-09, VULN-10 |
| AU (Audit & Accountability) | VULN-04 |
| SI (System & Information Integrity) | VULN-05, VULN-11, VULN-13, VULN-14 |
| SC (System & Communications Protection) | VULN-09, VULN-15, VULN-16 |
| CM (Configuration Management) | VULN-08, VULN-10, VULN-11, VULN-12 |
| RA (Risk Assessment) | VULN-13 |

## Severity summary

| Severity | Count | Findings |
|---|---|---|
| Critical | 3 | VULN-05, VULN-08, VULN-11 |
| High | 8 | VULN-01, VULN-02, VULN-06, VULN-07, VULN-09, VULN-10, VULN-13, VULN-14 |
| Medium | 5 | VULN-03, VULN-04, VULN-12, VULN-15, VULN-16 |

**Next:** Stage (c) — control-by-control hardening pass, addressing Critical and High findings first, with RMF rationale recorded per fix.
