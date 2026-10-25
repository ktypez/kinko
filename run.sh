#!/usr/bin/env bash
# Manual launcher for the credentials vault.
# Usage: ./run.sh            (start in foreground)
#        ./run.sh --daemon   (start detached, like the systemd unit)
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p logs
export VAULT_HOST="${VAULT_HOST:-0.0.0.0}"
export VAULT_PORT="${VAULT_PORT:-8787}"

if [[ "${1:-}" == "--daemon" ]]; then
  setsid ./venv/bin/python app.py >> logs/vault.log 2>&1 &
  sleep 1
  echo "started on http://$VAULT_HOST:$VAULT_PORT (pid $!)"
else
  exec ./venv/bin/python app.py
fi
