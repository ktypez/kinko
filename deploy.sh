#!/usr/bin/env bash
# Deploy Kinko from the dev repo to the service root (no git, runtime files).
# Dev = this git repo; Service = $KINKO_SERVICE_ROOT (default ~/.local/share/kinko).
# Data lives in $KINKO_SERVICE_ROOT/data and is never touched by this script.
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
DST="${KINKO_SERVICE_ROOT:-$HOME/.local/share/kinko}"

mkdir -p "$DST"
rsync -a --delete \
  --exclude '.git' \
  --exclude 'node_modules' \
  --exclude '__pycache__' \
  --exclude 'data' \
  "$SRC/" "$DST/"

mkdir -p "$DST/data/logs"
echo "deployed: $SRC -> $DST"

# run installer if present
if [ -x "$DST/install.sh" ]; then
  KINKO_SERVICE_ROOT="$DST" "$DST/install.sh"
fi
