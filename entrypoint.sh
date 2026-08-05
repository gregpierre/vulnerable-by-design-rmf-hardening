#!/bin/sh
# Stage (e): initialize the DB on first run only -- never bake seed data
# or secrets into the image itself. See CONTAINER_SECURITY.md.
set -e

if [ ! -f "$DATABASE_PATH" ]; then
    echo "No database found at $DATABASE_PATH -- initializing."
    python init_db.py
fi

exec "$@"
