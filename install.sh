#!/usr/bin/env bash
# Install Kinko system files (systemd unit) from the service root.
set -euo pipefail

ROOT="${KINKO_SERVICE_ROOT:-$(cd "$(dirname "$0")" && pwd)}"
UNIT_SRC="$ROOT/systemd/kinko.service"
UNIT_DST="/etc/systemd/system/kinko.service"

if [ ! -f "$UNIT_SRC" ]; then
  echo "Error: $UNIT_SRC not found"
  exit 1
fi

echo "Installing kinko.service..."
sudo cp "$UNIT_SRC" "$UNIT_DST"
sudo systemctl daemon-reload
sudo systemctl enable kinko.service
sudo systemctl restart kinko.service
echo "Kinko is now running."
echo "Status: $(sudo systemctl is-active kinko.service)"
