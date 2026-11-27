#!/bin/sh
# Apply database migrations, then start the API. Fails fast if migrations fail.
set -e
echo "[entrypoint] applying database migrations..."
alembic upgrade head
echo "[entrypoint] starting API"
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips='*' --log-level info
