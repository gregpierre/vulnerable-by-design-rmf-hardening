# Containerization & Container Security — Stage (e)

Packages the hardened app (stage c) into a Docker image with baseline container security practices, and scans the resulting image for OS-level vulnerabilities the way `pip-audit` (stage d) scans Python dependencies.

## Control mapping

| Control | Family | How it's implemented |
|---|---|---|
| CM-6 | Configuration Management — Configuration Settings | Multi-stage build; runtime config (secrets, DB/log paths) injected via environment at `docker run`, never baked into the image |
| CM-7 | Configuration Management — Least Functionality | Non-root user; minimal runtime image (build tooling stays in the discarded builder stage); `perl-base` removal investigated (see below) |
| AC-6 | Access Control — Least Privilege | Container process runs as an unprivileged `appuser` (uid 999), not root; runtime flags drop all Linux capabilities |
| SC-7 | System and Communications Protection — Boundary Protection | Only port 8000 exposed; app binds `0.0.0.0` *inside* the container network namespace only — the host-level exposure this replaces was VULN-12, see note below |
| SI-2 / RA-5 | Flaw Remediation / Vulnerability Scanning | Trivy scans the built image for OS-package CVEs; `apt-get upgrade` at build time pulls in available patches |

## Dockerfile design

- **Multi-stage build**: dependencies are resolved in a `builder` stage (`pip install --user`); only the resulting `/app/.local` tree is copied into the final image, so no compiler/build toolchain ships in the runtime image.
- **Non-root user**: `appuser` (system account, uid/gid 999, home `/app`) owns the app files and runs the process. Verified: `docker exec ... whoami` → `appuser`, not `root`.
- **No secrets in the image**: `SECRET_KEY` is deliberately not set in the Dockerfile — it's required at `docker run` time via `-e` or `--env-file`, same as local dev (`config.py` still raises `RuntimeError` if it's missing). Baking it in would reintroduce VULN-09 inside the image layer history.
- **Gunicorn, not the dev server**: `CMD` runs `gunicorn` (2 workers) instead of `app.run()` — HARDENING.md flagged the Werkzeug dev server (VULN-11) as unfit for anything beyond local debugging.
- **Configurable data paths**: `DATABASE_PATH` and `LOG_FILE_PATH` (added to `config.py` this stage) point at `/app/data/`, meant to be a mounted volume so the SQLite DB and audit log survive container restarts/recreation.
- **`entrypoint.sh`**: runs `init_db.py` only if no DB file exists yet at `$DATABASE_PATH`, then execs the real command. Seed data is generated at first run, never shipped in the image.
- **Healthcheck**: `HEALTHCHECK` hits `/login` every 30s; used below to confirm the container actually serves traffic, not just that the process started.

### On binding `0.0.0.0` inside the container (not a repeat of VULN-12)

VULN-12 was the Flask dev server binding `0.0.0.0` directly on the **host's** network interfaces, unnecessarily exposing a local dev process to the whole LAN. Here, gunicorn binds `0.0.0.0:8000` inside the container's own network namespace, which Docker isolates by default — nothing is host-reachable until explicitly published with `-p`. The `docker run` invocation below publishes it only to `127.0.0.1:8000` on the host, so the boundary-protection intent of VULN-12's fix is preserved at the host level.

## Runtime hardening (docker run flags)

Verified with:

```
docker run -d --name lm-rmf-test \
  -p 127.0.0.1:8000:8000 \
  -e SECRET_KEY="$(openssl rand -hex 32)" \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --read-only \
  --tmpfs /tmp \
  -v lm-rmf-data:/app/data \
  lm-rmf-helpdesk:stage-e
```

- `--cap-drop=ALL` — strips every Linux capability; the app needs none of them (no raw sockets, no filesystem-ownership changes, etc.)
- `--security-opt=no-new-privileges` — blocks setuid/setgid privilege escalation even if a binary inside the container had that bit set
- `--read-only` + `--tmpfs /tmp` — root filesystem is immutable at runtime; the only writable path is the mounted `/app/data` volume (DB + audit log) and an ephemeral `/tmp`
- Named volume for `/app/data` — confirmed data survives a `docker restart` (no re-initialization message on the second startup, DB and login state intact)

## Verification performed

- `docker build` succeeds; `docker run` with the flags above reaches `healthy` status
- `docker exec ... whoami` / `id` → running as `appuser` (uid 999), not root
- Full functional pass through the running container: login (forced password change on first login) → change-password → dashboard, all `200`/`302` as expected
- Restarted the container and confirmed no "initializing database" message on the second boot — the volume-mounted SQLite DB persisted
- `security.log` (mounted volume) captured `login_success` / `password_changed` events from inside the container, same as the stage (c)/(d) local verification

## Dependency scan resolution (closes a stage (d) open item)

Stage (d)'s `CI_CD_SECURITY.md` accepted a residual risk: `click` and `python-dotenv` had fixed versions requiring Python ≥3.10, but the local dev Mac only has system Python 3.9.6. The container's base image (`python:3.12.9-slim-bookworm`) doesn't have that constraint, so `requirements.txt` was bumped to the fully-patched pins (`click==8.3.3`, `python-dotenv==1.2.2`) as part of this stage. Re-ran `pip-audit` against the updated file (via a throwaway `python:3.12` container, since the local venv still can't resolve these versions) — **result: `No known vulnerabilities found`, zero suppressions needed.** That stage-(d) accepted risk is now resolved, not just carried forward; `CI_CD_SECURITY.md` has been updated to reflect this and the CI workflow's Python version bumped to 3.12 to match.

## Container image scan (Trivy)

Ran `aquasec/trivy image` (via its own container, since Trivy isn't natively installed) against the built image, HIGH/CRITICAL only:

| Pass | Findings | Notes |
|---|---|---|
| Before `apt-get upgrade` | 64 | 40 `fixed` (patch exists, just not in this base image build), 18 `affected`, 5 `fix_deferred`, 1 `will_not_fix` |
| After `apt-get upgrade` layer added | 24 | All 40 `fixed`-status findings closed. Remaining: 18 `affected`, 5 `fix_deferred`, 1 `will_not_fix` |

The 24 remaining findings are OS-package CVEs in Debian Bookworm's base packages (`perl-base`, `util-linux` family, `ncurses` family, `zlib1g`, `libsqlite3-0`) where Debian has not yet shipped a patched version, has explicitly deferred one, or (one case: `zlib1g` / CVE-2023-45853, CRITICAL) has marked it `will_not_fix` — that CVE is in `zipOpenNewFileInZip4_6`, a legacy minizip write path this app's stack never calls (Python's own `zlib` bindings don't invoke it).

**`perl-base` investigated and not removed:** 8 of the 24 remaining findings are in `perl-base`, which this Flask app never invokes — a strong CM-7 least-functionality candidate for removal. `apt-get purge perl-base` was attempted; apt refused, flagging it an **essential** package and requiring `--allow-remove-essential` to force it. Forcing removal of a package Debian marks essential is a known anti-pattern — it risks destabilizing dpkg/base-image tooling in ways that are hard to predict or test for, for a benefit (8 fewer *unreachable* CVEs, since the app never executes Perl) that's already low. Decision: leave it, track the 8 CVEs as an accepted risk alongside the others, rather than override a safety rail the base image maintainers put there deliberately.

**Tracked as accepted risk, re-verified on every CI run (CA-7):** the CI workflow (`.github/workflows/security.yml`) now builds the image and runs this same Trivy scan on every push/PR, with `ignore-unfixed: true` — it fails the build on any HIGH/CRITICAL finding that *does* have an available fix (closing the loop stage (d) demonstrated for Python deps), while the 24 currently-unfixed OS findings above stay visible in scan output without blocking merges on issues nobody can act on yet.

## Status after stage (e)

| Check | Result |
|---|---|
| App builds and runs in container | Yes, verified end-to-end |
| Runs as non-root | Yes (`appuser`, uid 999) |
| Secrets excluded from image | Yes (`SECRET_KEY` required at runtime, not baked in) |
| Data persists across restarts | Yes (volume-mounted) |
| Python dependency scan | Clean, 0 findings, 0 suppressions |
| OS package scan (Trivy) | 24 findings remain, all no-fix-available or deliberately-deferred by Debian; tracked, not blocking |

**Next:** Stage (f) — SSP-style writeup pulling together the findings, fixes, and control implementations from stages (a)-(e) into a single before/after risk narrative.
