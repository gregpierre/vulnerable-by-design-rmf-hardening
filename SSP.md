# System Security Plan (SSP) — IT Helpdesk Ticket Tracker

**Stage (f)** — this document consolidates stages (a)–(e) into a single system-level artifact: categorization, control implementation, before/after risk posture, and a residual-risk register (POA&M). It's written in the shape of an SSP/SAR pairing a real ATO package would contain, scoped down to what a single-app portfolio exercise can actually demonstrate and evidence.

**System name:** IT Helpdesk Ticket Tracker
**System type:** Minor application (Flask/Python, SQLite, single container)
**Assessment period:** 2026-08-05 (single-session build-and-harden exercise)
**Evidence:** `VULNERABILITIES.md` (stage b), `HARDENING.md` (stage c), `CI_CD_SECURITY.md` (stage d), `CONTAINER_SECURITY.md` (stage e)

---

## 1. System Categorization (RMF Step 1 — Categorize)

FIPS 199 potential-impact analysis for the three security objectives:

| Objective | Impact | Rationale |
|---|---|---|
| Confidentiality | **Moderate** | Stores user credentials (hashed) and free-text ticket descriptions, which can plausibly contain internal system details or PII fragments an end user pastes into a support request. |
| Integrity | **Moderate** | Ticket data and, critically, the admin/user role distinction must be trustworthy — VULN-06/07/08 (broken access control, IDOR, unauthenticated credential dump) show what's at stake if role integrity fails. |
| Availability | **Low** | A helpdesk tool being briefly unavailable is inconvenient, not mission- or safety-critical. |

**System categorization (high-water mark): Moderate.**

**Scoping note:** the controls implemented in stages (a)–(e) are a *representative, evidence-backed subset* addressing the findings this exercise actually surfaced — not a claim of full NIST 800-53 Moderate baseline coverage. A real Moderate-baseline ATO package would additionally require control families never touched here: Contingency Planning (CP), Incident Response (IR), Physical and Environmental Protection (PE), Personnel Security (PS), and Awareness and Training (AT), among others. Listing that gap explicitly here rather than implying full-baseline compliance is itself the point — an SSP that overclaims coverage it can't evidence is a bigger red flag than an honestly scoped one.

## 2. System Boundary

**In scope** (built and assessed this exercise):
- Application code (`app.py`, `config.py`, `init_db.py`, templates)
- SQLite data store
- Container image and its runtime configuration
- CI/CD pipeline (GitHub Actions security gate)

**Out of scope** (explicitly not addressed — noted, not silently omitted):
- Host OS hardening (the underlying Docker host / eventual production host)
- Network-layer controls (firewall rules, network segmentation, IDS/IPS)
- TLS/certificate management (a prerequisite for flipping `SESSION_COOKIE_SECURE` on — see POA&M)
- Secrets management platform (`.env` file is used for this exercise; production would use AWS Secrets Manager, HashiCorp Vault, or equivalent)
- Cloud hosting environment (AWS deployment was discussed as a later, separate initiative — not one of stages a–g)
- Contingency planning / backup and recovery (CP family)
- Multi-factor authentication (IA-2(1) — noted below as a Moderate-baseline gap)

## 3. Control Implementation Summary

Every control below has a corresponding VULN-ID (stage b/c), a CI gate (stage d), or a container control (stage e) as evidence — nothing in this table is asserted without a paper trail.

| Family | Controls | Where implemented |
|---|---|---|
| AC — Access Control | AC-3, AC-6, AC-7 | Role-based access control + IDOR fix (VULN-06/07); login lockout (VULN-03) |
| IA — Identification & Authentication | IA-5, IA-5(1) | Password hashing (VULN-01/02); no hardcoded/default creds, forced first-login change (VULN-09/10) |
| AU — Audit & Accountability | AU-2, AU-3, AU-12 | Security event logging: auth success/failure, lockouts, access-denied, password changes (VULN-04) |
| SI — System & Information Integrity | SI-2, SI-10, SI-11 | SQLi fix (VULN-05); XSS fix (VULN-14); generic error handling, no stack-trace leakage (VULN-11); dependency + OS patching (stages d, e) |
| SC — System & Communications Protection | SC-7, SC-8, SC-12, SC-23, SC-28 | Network exposure minimized (VULN-12); session cookie hardening (VULN-16); env-based secret key (VULN-09); CSRF protection (VULN-15) |
| CM — Configuration Management | CM-6, CM-7 | Debug mode off, no debug endpoint (VULN-08/11); non-root container, minimal runtime image (stage e) |
| RA — Risk Assessment | RA-5 | Dependency scanning (`pip-audit`, stage d); container image scanning (`Trivy`, stage e) |
| SA — System & Services Acquisition | SA-11 | Static analysis (`bandit`) on every push (stage d) |
| CA — Assessment, Authorization & Monitoring | CA-7 | CI/CD gate re-runs every scan on every push/PR — continuous, not point-in-time (stages d, e) |

## 4. Risk Posture — Before / After

| Stage | Finding | Result |
|---|---|---|
| (b) Baseline assessment | 16 findings: 3 Critical, 8 High, 5 Medium | Documented in `VULNERABILITIES.md` |
| (c) Hardening pass | All 16 remediated and verified live | 1 intentional residual (`SESSION_COOKIE_SECURE`, below) |
| (d) Dependency scan | 11 known-vulnerable dependency versions found on first scan | Reduced to 2 accepted-risk suppressions, then to 0 at stage (e) |
| (e) Container scan | 64 HIGH/CRITICAL OS-package CVEs on first image scan | Reduced to 24 via patch layer; remainder is no-fix-available or Debian-deferred |

Net result: every application-layer finding (the 16 from stage b) is closed. Both dependency- and OS-layer scans went from "never run" to "run automatically on every change, with a documented, reviewed list of what's still open and why."

## 5. Residual Risk Register (POA&M)

| ID | Risk | Status | Planned resolution |
|---|---|---|---|
| R-1 | `SESSION_COOKIE_SECURE=False` — session cookie not marked Secure | Accepted, intentional | Flip to `True` when the app is served over TLS. Not done sooner because it would silently break login over the current plain-HTTP local/dev deployment. |
| R-2 | 24 OS-package CVEs in the container base image (Debian Bookworm) | Accepted, tracked | No upstream fix available for most; re-scanned on every CI run via Trivy so this list is never stale. `perl-base` (8 of the 24) was investigated for removal and rejected — apt marks it essential, and forcing removal is a known way to destabilize a base image for a benefit that's already low (app never invokes Perl). |
| R-3 | No multi-factor authentication (IA-2(1)) | Not implemented | Out of scope for this exercise's finding-driven approach; would be required for a real Moderate-baseline ATO. |
| R-4 | No centralized/shipped logging — `security.log` is local to the container/volume | Not implemented | Noted in `HARDENING.md`; would move to CloudWatch or equivalent once a hosting environment is chosen. |
| R-5 | No secrets manager — `.env` file / `docker run -e` | Accepted for this exercise's scope | Production would use AWS Secrets Manager or equivalent (see System Boundary). |
| R-6 | Contingency planning (CP), incident response (IR), and other operational control families not addressed | Out of scope | Would be required for a full ATO package; this exercise is scoped to a single application, not an operational system. |

## 6. Continuous Monitoring (RMF Step 6)

- `.github/workflows/security.yml` runs static analysis (bandit), dependency scanning (pip-audit), and container image scanning (Trivy) on every push and pull request to `main` — findings block the merge rather than waiting for a periodic manual review.
- R-2 (OS-package CVEs) is monitored, not resolved — the Trivy step re-surfaces it on every run so a future fix arriving upstream gets caught automatically rather than requiring someone to remember to re-check.
- No scheduled (cron) re-scan exists yet for dependencies that don't change between pushes but could newly become vulnerable (a CVE published against an already-deployed version). That's a reasonable next hardening step for the CI pipeline, noted here rather than implemented, to keep this stage's scope to what's actually built.

## 7. Authorization Recommendation

Framed the way a real security assessment would close: based on the evidence in stages (b)–(e), the application-layer risk identified in this exercise (all 16 findings, including 3 Critical) has been remediated and verified. Recommend **Authority to Operate (ATO) with conditions**, conditioned on resolving R-1 (TLS) and R-3 (MFA) before handling real user data, and with R-2/R-4/R-5/R-6 accepted as documented, monitored risk appropriate to this system's Moderate categorization and limited operational scope.

**Next:** Stage (g) — turn this SSP and the stage (a)–(e) artifacts into a portfolio piece / resume bullets.
