# credentials-vault

A small **localhost-only** web service that stores secret key/value entries
encrypted at rest. Access is gated by a single master password.

> **Layout (dev vs runtime, shiori-style)**
> - Dev/source: `~/projects/kinko/` (this git repo)
> - Service root: `~/.local/share/kinko` (deployed via `deploy.sh`, no git)
> - Runtime data: `~/.local/share/kinko/data/` (`credentials.enc`, `sessions.json`, `logs/`)
>
> `deploy.sh` rsyncs the dev repo into the service root (excluding `.git`,
> `__pycache__`, and `data`). The systemd unit `kinko.service` runs from the
> service root with `VAULT_DATA_DIR` pointing at the data dir, so the service
> never runs out of the dev checkout.

## Access

- Local:   http://127.0.0.1:8787
- LAN:     http://192.168.1.47:8787   (this machine's wlan0 IP)
- Tailscale (recommended for remote devices): http://100.122.103.62:8787

## Security

- Master password is **never stored**. Only a PBKDF2 salt and an encrypted
  verifier blob are kept on disk (`vault.json`).
- Key derivation: PBKDF2-HMAC-SHA256, 600,000 iterations -> 32-byte key.
- Encryption: AES-256-GCM with a fresh random 12-byte nonce per value.
- The derived key lives only in server RAM during an unlocked session.
  Restarting the service wipes sessions -> you must re-unlock.
- Brute-force protection: increasing delay after repeated wrong passwords.
- All mutations require a CSRF token.
- `credentials.enc` is written with mode `0600`.

> ⚠️ **LAN exposure**: the service binds to `0.0.0.0` and speaks plain HTTP, so
> the master password and session cookie travel in cleartext. Anyone on the same
> network (192.168.1.0/24) can sniff them. For remote access use the Tailscale
> address (100.122.103.62) or put it behind a TLS reverse proxy. To restrict to
> localhost only, set `VAULT_HOST=127.0.0.1` and restart the service.

## Run / manage

The service runs as a systemd unit (`credentials-vault`) and is enabled to
start on boot:

```bash
sudo systemctl status  credentials-vault
sudo systemctl start   credentials-vault
sudo systemctl stop    credentials-vault
sudo systemctl restart credentials-vault
```

Manual launch:

```bash
./run.sh            # foreground
./run.sh --daemon   # detached
./stop.sh
```

Environment variables (optional):

- `VAULT_HOST` (default `127.0.0.1`)
- `VAULT_PORT` (default `8787`)
- `VAULT_SESSION_TTL` (seconds, default `1800`)
- `VAULT_ITERATIONS` (default `600000`)

## First use

1. Open http://127.0.0.1:8787
2. You will be asked to create a master password (>= 8 chars).
   **If you lose it, the encrypted data cannot be recovered.**
3. Add entries (name -> value), reveal/copy/delete as needed.
4. Lock when done (or just close the tab; sessions expire after 30 min).

## Files

- `~/projects/kinko/` - dev git repo (source)
- `~/.local/share/kinko/` - service root (deployed, no git)
- `~/.local/share/kinko/data/credentials.enc` - encrypted store (runtime data, 0600)
- `~/.local/share/kinko/data/sessions.json` - session cache (runtime data, 0600)
- `~/.local/share/kinko/data/logs/vault.log` - service log

## Backup

Back up `vault.json` (it is encrypted, safe to copy). To restore, drop it
back into this directory and restart the service.
EOF
echo "readme written"
rm -rf /home/admin/credentials/__pycache__