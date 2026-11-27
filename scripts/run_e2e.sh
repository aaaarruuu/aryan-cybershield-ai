#!/usr/bin/env bash
# Reproducible browser E2E: fresh SQLite DB + Chroma, backend + Vite dev server, Playwright flow, then cleanup.
# Requirements: backend venv (VENV=/path/to/venv, default ./backend/.venv), npm deps installed, `pip install playwright` + chromium.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; VENV="${VENV:-$ROOT/backend/.venv}"; W="$(mktemp -d)"
export DATABASE_URL="sqlite:///$W/e2e.db" CHROMA_PATH="$W/chroma" DEMO_MODE=true SECRET_KEY="e2e-secret-key-0123456789-abcdefghijklmnop" E2E_SHOTS="${E2E_SHOTS:-$ROOT/documentation/screenshots}"
cleanup() { kill ${BPID:-} ${FPID:-} 2>/dev/null || true; rm -rf "$W"; }; trap cleanup EXIT
( cd "$ROOT/backend" && "$VENV/bin/alembic" upgrade head >/dev/null && "$VENV/bin/uvicorn" app.main:app --port 8000 >"$W/backend.log" 2>&1 ) & BPID=$!
( cd "$ROOT/frontend" && npx vite --port 5173 --host 127.0.0.1 >"$W/frontend.log" 2>&1 ) & FPID=$!
for _ in $(seq 1 60); do curl -sf -m 2 http://127.0.0.1:5173/api/health >/dev/null && break; sleep 1; done
curl -sf http://127.0.0.1:5173/api/health >/dev/null || { echo "servers did not start"; tail -20 "$W/backend.log"; exit 1; }
python3 "$ROOT/e2e/e2e_ui.py"
