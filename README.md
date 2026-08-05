# vulnerable-by-design-rmf-hardening

so i built a helpdesk ticket tracker (flask + sqlite) and made it vulnerable. on purpose.

why would i do that? because i wanted to practice the actual job i'm training for, not just read about it. so i sat down and asked: if i build something insecure the way a rushed junior dev actually would, how many real vulnerabilities can i find in it? then: can i fix every one of them and explain *why* the fix is correct, not just that it "works"? then: can i stop relying on my own memory to catch this stuff again and make a machine catch it instead? then: can i package the fixed app so it ships safely? and finally: can i write all of that up the way a real security team would, as a document someone could actually hand to a decision maker?

that's this repo. six stages, one app, full paper trail.

## the story, stage by stage

**1. build it broken —** a small it helpdesk app: login, register, submit tickets, admin view. built with the kind of shortcuts that show up in real codebases — string-formatted sql queries, plaintext passwords, a debug endpoint nobody meant to leave in, a hardcoded secret key. [`app.py`](app.py), [`config.py`](config.py)

**2. find everything wrong with it —** manual code review, treating my own app like a target. **16 findings** — 3 critical, 8 high, 5 medium — each one mapped to a cwe and a nist 800-53 control family, the same way a real vulnerability assessment gets scored. [`VULNERABILITIES.md`](VULNERABILITIES.md)

**3. fix it, and prove the fix —** every finding remediated, one at a time, with the control it satisfies and how i verified it actually closed (not just "looks fixed" — tested against a running instance). sql injection gone, passwords hashed, access control enforced server-side, debug mode off, secrets out of source. [`HARDENING.md`](HARDENING.md)

**4. stop trusting myself to catch this next time —** a ci/cd pipeline that runs static analysis (bandit) and dependency scanning (pip-audit) on every push, so the next outdated package or sloppy line of code gets caught by a machine before it reaches main — not by me remembering to check. [`CI_CD_SECURITY.md`](CI_CD_SECURITY.md), [`.github/workflows/security.yml`](.github/workflows/security.yml)

**5. package it so it ships securely —** containerized: non-root user, no secrets baked into the image, read-only filesystem at runtime, capabilities dropped, image scanned for os-level cves. [`CONTAINER_SECURITY.md`](CONTAINER_SECURITY.md), [`Dockerfile`](Dockerfile)

**6. write the final report —** everything above rolled into one document, shaped like a real system security plan: fips 199 categorization, control implementation summary, before/after risk posture, a residual-risk register for what's left open and why, and an authorization recommendation. [`SSP.md`](SSP.md)

## results

| | before | after |
|---|---|---|
| app-level vulnerabilities | 16 (3 critical, 8 high, 5 medium) | 0 open — all fixed and verified |
| vulnerable dependencies | 11 known-bad package versions | 0 |
| container os cves | 64 high/critical | 24 tracked (no fix available yet — not ignored, just documented) |

## running it

```
python -m venv venv && ./venv/bin/pip install -r requirements.txt
cp .env.example .env   # set SECRET_KEY — see the file for how to generate one
./venv/bin/python init_db.py
./venv/bin/python app.py
```

or in docker:

```
docker build -t helpdesk .
docker run -d -p 127.0.0.1:8000:8000 \
  -e SECRET_KEY="$(openssl rand -hex 32)" \
  --cap-drop=ALL --security-opt=no-new-privileges --read-only --tmpfs /tmp \
  -v helpdesk-data:/app/data \
  helpdesk
```

both print a one-time admin password and force a password change on first login.

## why this exists

i'm working toward aws aa/cysa+ and a cyber security engineering role, and i didn't want another certificate that says i can define a control without ever having implemented one. this is the version of that skill i can actually show: found the vulnerabilities myself, fixed them myself, automated the check so i don't have to re-find them by hand next time, and documented the whole thing the way it'd need to be documented for someone else to trust it.
