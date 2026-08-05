# IT Helpdesk Ticket Tracker — Vulnerable-by-Design → RMF-Hardened

A small Flask/SQLite web app, deliberately built insecure and then walked through a compressed RMF-style lifecycle: assess, harden, automate, containerize, and document — the way a real ATO package accumulates evidence stage by stage.

**16 vulnerabilities found and fixed** (3 Critical, 8 High, 5 Medium) · **NIST 800-53 Rev 5 control mapping** throughout · **CI/CD security gate** (SAST + dependency scan + container image scan) · **Containerized**, non-root, runtime-hardened · **FIPS 199 categorization + SSP-style writeup**

## Why this exists

Built as a hands-on portfolio piece demonstrating the RMF/NIST 800-53 skills a Cyber Security Engineering role actually uses day to day — vulnerability analysis and mitigation planning, control mapping, CI/CD security scanning, and container security — rather than studying them in the abstract.

## The stages

Each stage produced its own evidence document; nothing below is asserted without a paper trail back to one of these.

| Stage | What happened | Evidence |
|---|---|---|
| (a) Build | Intentionally vulnerable Flask helpdesk app | [`app.py`](app.py), [`config.py`](config.py) |
| (b) Assess | 16 findings, each mapped to CWE + a NIST 800-53 control family, severity-rated | [`VULNERABILITIES.md`](VULNERABILITIES.md) |
| (c) Harden | Every finding remediated, with per-fix control rationale and live verification | [`HARDENING.md`](HARDENING.md) |
| (d) Automate | CI/CD gate: static analysis (bandit) + dependency scanning (pip-audit) on every push | [`CI_CD_SECURITY.md`](CI_CD_SECURITY.md) |
| (e) Containerize | Non-root, secrets-free, runtime-hardened container; image scanned (Trivy) | [`CONTAINER_SECURITY.md`](CONTAINER_SECURITY.md) |
| (f) Document | FIPS 199 categorization, control summary, risk burndown, POA&M, ATO-with-conditions recommendation | [`SSP.md`](SSP.md) |

## Results at a glance

| Layer | Before | After |
|---|---|---|
| Application (stage b→c) | 16 findings — 3 Critical, 8 High, 5 Medium | 0 open — all remediated and verified live |
| Dependencies (stage d→e) | 11 known-vulnerable package versions | 0 findings, 0 suppressions |
| Container OS packages (stage e) | 64 HIGH/CRITICAL CVEs | 24 tracked residual (no fix available, or Debian will-not-fix) |

## Architecture

Flask + SQLite, gunicorn in production, packaged as a multi-stage Docker image running as a non-root user with no baked-in secrets. GitHub Actions runs bandit, pip-audit, and Trivy on every push/PR and blocks the merge on any newly-introduced, fixable finding.

## Running it

**Locally:**
```
python -m venv venv && ./venv/bin/pip install -r requirements.txt
cp .env.example .env   # then set SECRET_KEY (see the file for how to generate one)
./venv/bin/python init_db.py
./venv/bin/python app.py
```

**In Docker:**
```
docker build -t lm-rmf-helpdesk .
docker run -d -p 127.0.0.1:8000:8000 \
  -e SECRET_KEY="$(openssl rand -hex 32)" \
  --cap-drop=ALL --security-opt=no-new-privileges --read-only --tmpfs /tmp \
  -v lm-rmf-data:/app/data \
  lm-rmf-helpdesk
```

Both print a one-time generated admin password and force a password change on first login.

## Skills demonstrated

RMF process (Categorize → Select → Implement → Assess → Monitor) · NIST 800-53 control mapping (AC, IA, AU, SI, SC, CM, RA, SA, CA) · vulnerability analysis and mitigation planning · secure coding (auth, access control, injection, XSS, CSRF) · CI/CD security gate design · container security (non-root, capability dropping, image scanning) · risk acceptance documentation (POA&M-style residual risk tracking)
