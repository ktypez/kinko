# HTTP API reference

Base URL `http://127.0.0.1:8787` (configurable via `VAULT_HOST`/`VAULT_PORT`).
Mutations require `X-CSRF-Token` (returned by `/api/unlock`). Sessions are
cookie-based (`sid`).

## Endpoints

| Method | Path | Auth | Purpose |
| ------ | ---- | ---- | ------- |
| GET | `/api/status` | none | `{initialized, unlocked}` |
| POST | `/api/setup` | none | first-time init `{password, confirm}` |
| POST | `/api/unlock` | none | open session `{password, remember?}` → `{ok, csrf}` |
| POST | `/api/lock` | session + CSRF | close session |
| GET | `/api/entries` | session | list entry names |
| GET | `/api/entries/<name>` | session | read one value `{name, value}` |
| POST | `/api/entries` | session + CSRF | create/update `{name, value}` |
| DELETE | `/api/entries/<name>` | session + CSRF | remove one |
| POST | `/api/change-password` | session + CSRF | rotate master pw |
| GET | `/api/audit?n=N` | session | last N audit records |

## Errors

| Status | Meaning |
| ------ | ------- |
| 401 | locked (no valid session) |
| 403 | bad/missing CSRF token |
| 400 | invalid input |
| 404 | entry not found |
| 500 | decryption failure |

## Audit record shape

```json
{
  "ts": "2026-10-28T04:48:56Z",
  "action": "get",
  "name": "NOUS_API_KEY",
  "decision": "allow",
  "reason": "ok",
  "remote": "127.0.0.1"
}
```

`action` ∈ {setup, unlock, lock, list, get, set, delete}. `decision` ∈
{allow, deny}. `reason` ∈ {ok, locked, not_found, decrypt_failed,
bad_password, auth, created, …}. Secret values are **never** included.
