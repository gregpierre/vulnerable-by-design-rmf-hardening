# Hardening Pass — Stage (c)

Control-by-control remediation of the findings in `VULNERABILITIES.md`, addressed in priority order (Critical → High → Medium). Each entry records what changed, the NIST 800-53 control(s) it implements, and any residual risk carried forward — the same shape a POA&M closure entry or an SSP control-implementation statement would take.

All fixes below were smoke-tested against a running instance (register → login → forced password change → dashboard → search → admin views → logout), with results referenced where relevant.

---

### VULN-05 — SQL injection (Critical) → SI-10
**Fix:** `search_tickets()` now uses a parameterized query (`?` placeholders) instead of `%`-string formatting.
**Verification:** A payload of `' OR '1'='1` returned zero rows instead of leaking other users' tickets, and the endpoint returned `200` rather than erroring — confirms the query no longer treats input as SQL.
**Residual risk:** None. All queries in the app are now parameterized.

### VULN-08 — Unauthenticated debug endpoint (Critical) → AC-3, CM-7
**Fix:** `/internal/debug/users` was removed outright rather than gated behind auth — CM-7 (least functionality) calls for eliminating unneeded capability, not just restricting it.
**Verification:** Endpoint now returns `404`.
**Residual risk:** None.

### VULN-11 — Debug mode enabled (Critical) → CM-7, SI-11
**Fix:** `debug` is now read from `FLASK_DEBUG` in `.env`, defaulting to `False`. Added `403`/`404`/`500` handlers (`templates/error.html`) that return a generic message; the 500 handler logs the full exception server-side via `logger.exception` instead of exposing a stack trace to the client.
**Verification:** Server startup log shows `Debug mode: off`.
**Residual risk:** None for this app. Note for stage (e): a production WSGI server (gunicorn/uwsgi) should replace the Werkzeug dev server regardless of debug flag — the dev server itself warns against production use.

### VULN-01 / VULN-02 — Plaintext password storage & comparison (High) → IA-5, IA-5(1)
**Fix:** Passwords are hashed with `werkzeug.security.generate_password_hash` (PBKDF2-SHA256) on registration and password change; login uses `check_password_hash`. The `users` table column was renamed `password` → `password_hash` to make the invariant explicit at the schema level.
**Note:** Werkzeug 3's default hash method is `scrypt`, which requires an OpenSSL build of `hashlib`. macOS's bundled Python is built against LibreSSL and lacks `hashlib.scrypt`, so the method is pinned explicitly to `pbkdf2:sha256` (NIST SP 800-63B §5.1.1.2 accepts PBKDF2).
**Verification:** Login/registration/password-change all round-tripped correctly against hashed values.
**Residual risk:** None for hash storage. No password complexity policy beyond a length minimum (see VULN-10 note) — acceptable for a portfolio-scope app, would be revisited for CNSSI 1253-driven password policy in a real ATO.

### VULN-06 / VULN-07 — Broken access control & IDOR (High) → AC-3, AC-6
**Fix:** Added `login_required` and `admin_required` decorators. `admin_tickets()` now requires `session["role"] == "admin"`. `ticket_detail()` checks that the requester is either an admin or the ticket's owner before rendering; otherwise `403`.
**Verification:** A non-admin user hit both `/admin/tickets` and `/admin/tickets/1` (owned by admin) and received `403` on both, logged as `access_denied` with `reason=ticket_not_owned` for the IDOR case.
**Residual risk:** None. Access control is now enforced server-side on every request, not inferred from UI (the "All Tickets (admin)" nav link is also now conditionally rendered, but that's UX, not the control boundary).

### VULN-09 — Hardcoded secret key (High) → IA-5, SC-12, SC-28
**Fix:** `SECRET_KEY` is loaded from `.env` (gitignored) via `python-dotenv`; `config.py` raises `RuntimeError` at startup if unset rather than silently falling back to a known value. `.env.example` documents how to generate one (`secrets.token_hex(32)`).
**Residual risk:** For stage (e)/AWS deployment, this should move to a managed secret store (e.g., AWS Secrets Manager / SSM Parameter Store) rather than a `.env` file on disk — noted for that stage.

### VULN-10 — Hardcoded default admin credentials (High) → IA-5, CM-6
**Fix:** `init_db.py` no longer seeds a fixed `admin/admin123`. If `ADMIN_BOOTSTRAP_PASSWORD` isn't set in `.env`, it generates a random password with `secrets.token_urlsafe(12)`, prints it once, and never stores it in plaintext. The seeded account is flagged `must_change_password`, enforced by `login_required` redirecting to `/change-password` before any other route is reachable.
**Verification:** Fresh `init_db.py` run printed a one-time generated password; logging in with it forced a redirect to `/change-password` before `/dashboard` was reachable; the new password worked on subsequent login.
**Residual risk:** None functionally. A real deployment would also want a password-complexity/rotation policy (IA-5(1)) beyond the 8-character minimum enforced here.

### VULN-13 — Outdated dependencies (High) → SI-2, RA-5
**Fix:** `requirements.txt` bumped to current stable releases: Flask 3.0.3, Werkzeug 3.0.3, Jinja2 3.1.4, itsdangerous 2.2.0, MarkupSafe 2.1.5.
**Verification:** `pip install -r requirements.txt` succeeded; app runs correctly on the new versions.
**Residual risk:** No automated recheck mechanism yet — that's explicitly stage (d) (CI/CD dependency scanning, e.g., `pip-audit` or Dependabot), not closed here.

### VULN-14 — Stored XSS via disabled autoescaping (High) → SI-10
**Fix:** Removed the `|safe` filter from `dashboard.html` and `ticket_detail.html`; ticket descriptions now go through Jinja2's default autoescaping.
**Verification:** Submitting `<script>alert(1)</script>` as a ticket description rendered as the literal text `&lt;script&gt;alert(1)&lt;/script&gt;` in the page source rather than executing.
**Residual risk:** None. No other template uses `|safe` or `Markup()`.

### VULN-03 — No account lockout / rate limiting (Medium) → AC-7
**Fix:** `users` table gained `failed_login_count` and `locked_until` columns. Five consecutive failed logins locks the account for 15 minutes (`config.LOGIN_MAX_ATTEMPTS`, `LOGIN_LOCKOUT_SECONDS`); a successful login resets the counter.
**Verification:** Six consecutive bad-password attempts against the same account returned `Invalid credentials` five times, then `Account temporarily locked` on the sixth — confirmed in `security.log` as `account_locked attempts=5` followed by `login_blocked_locked`.
**Residual risk:** State is per-row in SQLite, which is fine for a single-process app. A multi-instance deployment (stage (e)+) would need a shared store (e.g., Redis) so lockout state is consistent across instances — noted for that stage, not a gap in the current single-instance design.

### VULN-04 — No audit logging (Medium) → AU-2, AU-3, AU-12
**Fix:** Added a dedicated `helpdesk` logger writing to `security.log` (gitignored). Events logged: `register`, `login_success`, `login_failure`, `account_locked`, `login_blocked_locked`, `password_changed`, `logout`, and `access_denied` (with reason, e.g. `ticket_not_owned`) — each with username and source IP.
**Verification:** Full test session produced a complete, readable audit trail (see log excerpt in this session).
**Residual risk:** Logs are local-file only. Centralized/shipped logging (e.g., to CloudWatch) is a stage (e) concern once the app is containerized/deployed.

### VULN-15 — No CSRF protection (Medium) → SC-23
**Fix:** Added `Flask-WTF`'s `CSRFProtect(app)`. Every POST form now includes a hidden `csrf_token` field via the `csrf_token()` Jinja global that `CSRFProtect` registers.
**Verification:** A POST to `/dashboard` with no `csrf_token` field returned `400` (rejected); the same request with a valid token succeeded.
**Residual risk:** None.

### VULN-16 — Session cookie not hardened (Medium) → SC-8, SC-23
**Fix:** `SESSION_COOKIE_HTTPONLY=True` and `SESSION_COOKIE_SAMESITE="Lax"` are set unconditionally. `SESSION_COOKIE_SECURE` is driven by `.env` (`SESSION_COOKIE_SECURE`), defaulting to `False`.
**Verification:** `Set-Cookie` header on login showed `HttpOnly; Path=/; SameSite=Lax` as expected for local HTTP.
**Residual risk — intentional, tracked:** `SESSION_COOKIE_SECURE` stays `False` until the app is served over TLS (stage (e)+). Flipping it on now would silently break login over plain HTTP, since browsers won't send a `Secure` cookie over an insecure connection. This is a documented compensating-control gap, not an oversight — flip to `True` as part of the TLS cutover.

---

## Status after stage (c)

| Severity | Total | Remediated | Residual (tracked for later stage) |
|---|---|---|---|
| Critical | 3 | 3 | 0 |
| High | 8 | 8 | 0 (dependency scanning automation deferred to stage (d)) |
| Medium | 5 | 5 | 1 (`SESSION_COOKIE_SECURE` deferred to TLS at stage (e)) |

**Next:** Stage (d) — CI/CD security scanning (static analysis + dependency scanning) so findings like VULN-13 are caught automatically rather than by manual review.
