#!/usr/bin/env sh
# Initialise the SQLite schema and run the API locally (without Docker).
set -e

export BIDI_DB_PATH="${BIDI_DB_PATH:-./data/audit.db}"
python3 -m app.init_db
exec python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000
