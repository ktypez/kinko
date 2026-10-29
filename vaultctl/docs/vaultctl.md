# `vaultctl` CLI reference

The CLI talks to the vault over HTTP. Point it at any instance with
`VAULT_URL` (default `http://127.0.0.1:8787`).

```
vaultctl status                          # initialized / unlocked?
vaultctl list                            # all entry names
vaultctl get <name>                      # print a secret to stdout (trusted shells only)
vaultctl set <name> <value>              # create / update
vaultctl delete <name>                   # remove
vaultctl lock                            # wipe the session
vaultctl unlock                          # open a session (password from env/file)
vaultctl exec <name> [--env VAR] -- <cmd> [args...]   # inject into child env; value never printed
vaultctl audit [N]                       # last N audit records (JSONL, never values)
```

## Authentication

The master password is read from `$VAULT_PASSWORD` or `~/.vault-password`
(mode `0600`). Session state is cached in `~/.vault-cookie` and
`~/.vault-csrf` (mode `0600`) so repeated calls are fast; sessions expire after
30 minutes of inactivity.

```bash
export VAULT_PASSWORD=...        # or create ~/.vault-password
vaultctl list
```

## `exec` — safe consumption

`vaultctl get` prints the plaintext to stdout — the value then lands in your
agent's context, the transcript, and any log that captures command output.
`vaultctl exec` is the safer path: it resolves the value internally, injects it
into the child process's environment, and masks every occurrence (plus any
6+ character fragment) in the child's stdout/stderr. The secret never reaches
the caller's output.

```bash
# pass the key to a command without ever printing it
vaultctl exec NOUS_API_KEY -- my-tool --auth

# override the injected env var name (default: the entry name)
vaultctl exec NOUS_API_KEY --env AUTH_TOKEN -- my-tool --auth

# inspect only what you need, value stays hidden
vaultctl exec NOUS_API_KEY -- python3 -c 'import os; print(len(os.environ["NOUS_API_KEY"]))'
```

The child's exit code is propagated, so `exec` composes like a normal command.
Prefer `exec` over `get` whenever a secret is consumed by a program rather than
read by a human.

## `audit` — review access

```bash
vaultctl audit 50                  # last 50 records
vaultctl audit 1                   # just the most recent
```

Each line is a JSON object: `ts`, `action`, `name`, `decision`, `reason`,
`remote`. Values are never recorded.
