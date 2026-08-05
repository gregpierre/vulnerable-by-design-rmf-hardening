# CI/CD Security Scanning — Stage (d)

Automates the checks that stages (b)/(c) did by hand: static analysis catches code-level flaws (the class of thing VULN-05, VULN-08, VULN-14 were), and dependency scanning catches drift like VULN-13, where "current stable" at build time silently ages into "known-vulnerable" later. Both run on every push/PR via GitHub Actions (`.github/workflows/security.yml`) and gate the merge.

## Control mapping

| Control | Family | How it's implemented here |
|---|---|---|
| RA-5 | Risk Assessment — Vulnerability Monitoring and Scanning | `pip-audit` checks every dependency in `requirements.txt` against the PyPI Advisory / OSV database on every push |
| SI-2 | System and Information Integrity — Flaw Remediation | A failing dependency scan blocks the merge, forcing remediation before code reaches `main` rather than relying on someone remembering to check |
| SA-11 | System and Services Acquisition — Developer Testing and Evaluation | `bandit` performs static analysis on every push, catching insecure code patterns (hardcoded binds, SQL string-building, etc.) before review |
| CA-7 | Assessment, Authorization, and Monitoring — Continuous Monitoring | The scan isn't a one-time audit (stages b/c) — it re-runs automatically on every future change, which is what turns a point-in-time assessment into continuous monitoring |

## Tooling

- **`bandit`** (SAST) — scans `.py` source for known-insecure patterns (`subprocess` misuse, weak crypto, hardcoded binds, etc.). Excludes `venv/` and `.git/`.
- **`pip-audit`** (dependency/SCA scanning) — resolves `requirements.txt` against the PyPI Advisory Database (via OSV) and flags any package with a published CVE/advisory.
- Both live in `requirements-dev.txt` (dev/CI-only — not shipped with the app).

## Baseline run (local, this session)

**Bandit:** 0 findings across 329 lines of application code — consistent with stage (c) having already closed the code-level issues.

**pip-audit**, run against the stage (c) `requirements.txt` pins, immediately surfaced 11 advisories across 5 packages that postdated those "current stable" choices:

| Package | Version audited | Fixed by |
|---|---|---|
| flask | 3.0.3 | 3.1.3 |
| werkzeug | 3.0.3 | 3.1.6 |
| jinja2 | 3.1.4 | 3.1.6 |
| click | 8.1.7 | 8.3.3 |
| python-dotenv | 1.0.1 | 1.2.2 |

**Action taken:** flask, werkzeug, jinja2, itsdangerous, and Flask-WTF were upgraded to their fixed versions (now `3.1.3` / `3.1.8` / `3.1.6` / `2.2.0` / `1.2.2` respectively) and re-verified against a running instance of the app — no regressions.

## Accepted risk: click and python-dotenv on Python 3.9

`click`'s fix (8.3.3) and `python-dotenv`'s fix (1.2.2) both require Python ≥3.10. This machine runs macOS's bundled system Python 3.9.6, with no Homebrew/pyenv installed to get a newer interpreter — upgrading the interpreter itself is a machine-level change out of scope for this pass, deferred to stage (e) containerization (a Docker base image will pin a modern Python and close this automatically).

Tracked as an accepted risk rather than silently ignored:

- **PYSEC-2026-2132** (click 8.1.8, latest Python-3.9-compatible release) — click is a CLI-argument-parsing library. In this app it's a transitive dependency of Flask's `flask` CLI entrypoint, invoked at developer discretion on a local machine — it never parses attacker-supplied input from an HTTP request. Exploitability in this app's threat model is negligible.
- **PYSEC-2026-2270** (python-dotenv 1.2.1, latest Python-3.9-compatible release) — parses `.env`, a file the developer controls locally and which is gitignored. It never parses untrusted input. Exploitability in this app's threat model is negligible.

Both are pinned to their newest Python-3.9-compatible release (not left on the original, older, more-vulnerable pins) and explicitly suppressed in the CI gate via `pip-audit --ignore-vuln <ID>`, each with an inline comment pointing back to this document — a deliberate, reviewed exception, not a gap the scanner silently missed. Any *other* advisory still fails the build.

## Result

| Tool | Before upgrade | After upgrade + documented suppressions |
|---|---|---|
| bandit | 0 findings | 0 findings |
| pip-audit | 11 vulnerabilities / 5 packages | 0 unaccepted (2 suppressed, tracked above) |

**Next:** Stage (e) — containerize the app; the container's Python base image resolves the click/python-dotenv ceiling, closing this stage's one open item as a side effect.
