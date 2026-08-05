# Stage (e): containerization with basic container security practices.
# See CONTAINER_SECURITY.md for the control rationale (CM-6, CM-7, AC-6,
# SC-7) behind each choice below.

# ---- builder: resolve dependencies with build tooling available ----
FROM python:3.12.9-slim-bookworm AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ---- runtime: minimal image, no build tooling, non-root ----
FROM python:3.12.9-slim-bookworm

# Pull in OS-level security patches published since this base image was
# built (SI-2 / RA-5 -- see CONTAINER_SECURITY.md for the Trivy scan
# results this closes vs. what remains an accepted risk). perl-base was
# considered for removal via CM-7 least-functionality reasoning -- this
# app never invokes Perl -- but apt marks it "essential" and refuses
# removal without --allow-remove-essential; forcing that is a known
# anti-pattern (risks destabilizing dpkg/base-image tooling for
# uncertain benefit), so it stays and is tracked as an accepted risk
# instead. See CONTAINER_SECURITY.md.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Non-root service account -- the app never needs root inside the
# container (CM-7 least functionality, AC-6 least privilege).
RUN groupadd --system appuser \
    && useradd --system --gid appuser --create-home --home-dir /app appuser

WORKDIR /app

COPY --from=builder /root/.local /app/.local
COPY app.py config.py init_db.py entrypoint.sh ./
COPY templates ./templates

RUN mkdir -p /app/data \
    && chown -R appuser:appuser /app \
    && chmod +x /app/entrypoint.sh

ENV HOME=/app \
    PATH=/app/.local/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATABASE_PATH=/app/data/helpdesk.db \
    LOG_FILE_PATH=/app/data/security.log

# SECRET_KEY is intentionally NOT set here -- it must be injected at
# `docker run` time (env var, --env-file, or a secret manager). Baking
# it into the image would recreate VULN-09.

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/login', timeout=2)" || exit 1

ENTRYPOINT ["./entrypoint.sh"]
# Gunicorn instead of the Werkzeug dev server -- HARDENING.md (VULN-11)
# flagged the dev server as unfit for anything but local debugging.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "app:app"]
