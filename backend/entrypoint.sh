#!/usr/bin/env sh
set -e

echo "[apisentinel] applying database migrations"
alembic upgrade head

echo "[apisentinel] seeding demo data and ground truth (idempotent)"
python -m app.bootstrap || echo "[apisentinel] bootstrap reported a problem; continuing"

echo "[apisentinel] starting API on :8000"
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers
