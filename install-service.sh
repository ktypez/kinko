#!/bin/bash
# Install credentials-vault as a systemd service.
# Source (dev) lives in ~/projects/credentials-vault; runtime data in ~/credentials.

set -e

SERVICE_FILE="systemd/credentials-vault.service"
DEST="/etc/systemd/system/credentials-vault.service"

if [ ! -f "$SERVICE_FILE" ]; then
  echo "Error: $SERVICE_FILE not found (run from project dir)"
  exit 1
fi

echo "Installing credentials-vault.service..."
sudo cp "$SERVICE_FILE" "$DEST"
sudo systemctl daemon-reload
sudo systemctl enable credentials-vault.service
sudo systemctl restart credentials-vault.service

echo "credentials-vault is now running."
echo "Status: $(sudo systemctl is-active credentials-vault.service)"
