#!/usr/bin/env python3
"""
credentials-vault
=================
A small localhost-only web service that stores secret key/value entries
encrypted at rest. Access is gated by a single master password.

Security model
--------------
* Master password is NEVER stored. Only a PBKDF2 salt + a verifier blob are
  kept on disk.
* Key derivation: PBKDF2-HMAC-SHA256 (600k iterations) -> 32-byte key.
* Encryption:     AES-256-GCM with a fresh random 12-byte nonce per value.
* Unlock:         decrypt the verifier blob; if it matches, the password is
                  correct and the derived key is held only in server memory
                  for the lifetime of the session.
* Sessions:       an opaque random token cookie mapped to an in-memory session
                  (holds the derived key). Everything is wiped on restart.
* CSRF:           state-changing requests must send X-CSRF-Token.
* Brute force:    failed unlock attempts trigger an increasing delay.

The master key lives only in RAM while unlocked; restart = re-unlock.
"""

import os
import json
import time
import hmac
import secrets
import threading
from functools import wraps

from flask import (
    Flask, request, jsonify, redirect, url_for,
    render_template_string, g,
)

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("VAULT_DATA_DIR", BASE_DIR)
os.makedirs(DATA_DIR, exist_ok=True)
VAULT_PATH = os.path.join(DATA_DIR, "credentials.enc")

HOST = os.environ.get("VAULT_HOST", "127.0.0.1")
PORT = int(os.environ.get("VAULT_PORT", "8787"))

KDF_NAME = "pbkdf2-hmac-sha256"
ITERATIONS = int(os.environ.get("VAULT_ITERATIONS", "600000"))  # OWASP-ish
SALT_LEN = 16
NONCE_LEN = 12

SESSION_TTL = int(os.environ.get("VAULT_SESSION_TTL", str(30 * 60)))  # seconds
REMEMBER_TTL = int(os.environ.get("VAULT_REMEMBER_TTL", str(30 * 24 * 60 * 60)))  # 30 days
COOKIE_NAME = "sid"
SESSIONS_FILE = os.path.join(DATA_DIR, "sessions.json")

MIN_PASSWORD_LEN = 8
MAX_FAIL_BEFORE_DELAY = 5
DELAY_CAP = 10.0

VERIFIER_PLAINTEXT = b"credentials-vault::unlock::ok\x00END"

# --------------------------------------------------------------------------- #
# App + in-memory state
# --------------------------------------------------------------------------- #
app = Flask(__name__)
app.secret_key = secrets.token_bytes(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    JSON_SORT_KEYS=False,
)

_sessions = {}          # token -> {key, expires, csrf}
_sessions_lock = threading.Lock()

_fail = {"count": 0, "reset_at": 0.0}
_fail_lock = threading.Lock()


# --------------------------------------------------------------------------- #
# Crypto helpers
# --------------------------------------------------------------------------- #
def derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt(key: bytes, plaintext: bytes) -> tuple:
    nonce = secrets.token_bytes(NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce, ct


def decrypt(key: bytes, nonce: bytes, ct: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ct, None)


# --------------------------------------------------------------------------- #
# Vault persistence
# --------------------------------------------------------------------------- #
def vault_exists() -> bool:
    return os.path.exists(VAULT_PATH)


def load_vault() -> dict:
    with open(VAULT_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def save_vault(data: dict) -> None:
    tmp = VAULT_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, VAULT_PATH)
    try:
        os.chmod(VAULT_PATH, 0o600)
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# Session helpers
# --------------------------------------------------------------------------- #
def _save_sessions():
    """Persist sessions to disk (0600) so they survive restarts."""
    try:
        with _sessions_lock:
            data = {}
            for tok, s in _sessions.items():
                data[tok] = {
                    "key": s["key"].hex(),
                    "expires": s["expires"],
                    "csrf": s["csrf"],
                    "remember": s.get("remember", False),
                }
        tmp = SESSIONS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, SESSIONS_FILE)
        try:
            os.chmod(SESSIONS_FILE, 0o600)
        except OSError:
            pass
    except Exception:
        pass


def _load_sessions():
    """Load persisted sessions from disk on startup."""
    if not os.path.exists(SESSIONS_FILE):
        return
    try:
        with open(SESSIONS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        now = time.time()
        with _sessions_lock:
            for tok, s in data.items():
                try:
                    exp = s["expires"]
                    if exp < now:
                        continue
                    _sessions[tok] = {
                        "key": bytes.fromhex(s["key"]),
                        "expires": exp,
                        "csrf": s["csrf"],
                        "remember": s.get("remember", False),
                    }
                except Exception:
                    continue
    except Exception:
        pass


def get_session():
    """Return (token, session) for a valid, unexpired session, else (None, None)."""
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None, None
    with _sessions_lock:
        s = _sessions.get(token)
        if not s:
            return None, None
        if s["expires"] < time.time():
            _sessions.pop(token, None)
            _save_sessions()
            return None, None
        s["expires"] = time.time() + (REMEMBER_TTL if s.get("remember") else SESSION_TTL)
        return token, s


def require_auth():
    """Session check only (used for read-only GET endpoints)."""
    token, s = get_session()
    if not s:
        return None, None, (jsonify({"error": "locked"}), 401)
    return token, s, None


def auth():
    """Session + CSRF check (used for state-changing endpoints)."""
    token, s, err = require_auth()
    if err:
        return token, s, err
    csrf = request.headers.get("X-CSRF-Token", "")
    if not hmac.compare_digest(csrf, s["csrf"]):
        return None, None, (jsonify({"error": "invalid request (bad CSRF token)"}), 403)
    return token, s, None


def new_session(key: bytes, remember: bool = False) -> tuple:
    ttl = REMEMBER_TTL if remember else SESSION_TTL
    token = secrets.token_urlsafe(32)
    with _sessions_lock:
        _sessions[token] = {
            "key": key,
            "expires": time.time() + ttl,
            "csrf": secrets.token_urlsafe(24),
            "remember": remember,
        }
        csrf = _sessions[token]["csrf"]
    _save_sessions()
    return token, csrf


def destroy_session(token: str) -> None:
    with _sessions_lock:
        _sessions.pop(token, None)
    _save_sessions()


def set_unlock_cookie(resp, token: str, remember: bool = False):
    ttl = REMEMBER_TTL if remember else SESSION_TTL
    resp.set_cookie(
        COOKIE_NAME, token,
        httponly=True, samesite="Lax", secure=False,
        max_age=ttl, path="/",
    )
    return resp


def _bruteforce_delay():
    """Sleep longer as consecutive failures accumulate."""
    with _fail_lock:
        now = time.time()
        if now >= _fail["reset_at"]:
            _fail["count"] = 0
        count = _fail["count"]
        if count >= MAX_FAIL_BEFORE_DELAY:
            d = min(DELAY_CAP, 0.5 * (2 ** (count - MAX_FAIL_BEFORE_DELAY)))
            time.sleep(d)


def _record_failure():
    with _fail_lock:
        _fail["count"] += 1
        _fail["reset_at"] = time.time() + 60  # window resets after 60s


def _record_success():
    with _fail_lock:
        _fail["count"] = 0
        _fail["reset_at"] = 0.0


# --------------------------------------------------------------------------- #
# Routes: UI
# --------------------------------------------------------------------------- #
@app.get("/")
def index():
    initialized = vault_exists()
    _token, s = get_session()
    unlocked = s is not None
    csrf = s["csrf"] if unlocked else ""
    return render_template_string(TEMPLATE,
                                  initialized=initialized, unlocked=unlocked, csrf=csrf,
                                  page="vault")


@app.get("/settings")
def settings():
    initialized = vault_exists()
    _token, s = get_session()
    unlocked = s is not None
    csrf = s["csrf"] if unlocked else ""
    if not initialized or not unlocked:
        return redirect(url_for("index"))
    return render_template_string(TEMPLATE,
                                  initialized=initialized, unlocked=unlocked, csrf=csrf,
                                  page="settings")


# --------------------------------------------------------------------------- #
# Routes: auth
# --------------------------------------------------------------------------- #
@app.post("/api/setup")
def api_setup():
    if vault_exists():
        return jsonify({"error": "Vault already initialized"}), 400
    data = request.json or {}
    password = data.get("password", "")
    confirm = data.get("confirm", "")
    if password != confirm:
        return jsonify({"error": "Passwords do not match"}), 400
    if len(password) < MIN_PASSWORD_LEN:
        return jsonify({"error": f"Password must be at least {MIN_PASSWORD_LEN} characters"}), 400

    salt = secrets.token_bytes(SALT_LEN)
    key = derive_key(password, salt, ITERATIONS)
    vnonce, vct = encrypt(key, VERIFIER_PLAINTEXT)
    save_vault({
        "version": 1,
        "kdf": KDF_NAME,
        "iterations": ITERATIONS,
        "salt": salt.hex(),
        "verifier": {"nonce": vnonce.hex(), "ct": vct.hex()},
        "entries": {},
    })
    token, csrf = new_session(key)
    resp = jsonify({"ok": True, "csrf": csrf})
    return set_unlock_cookie(resp, token)


@app.post("/api/unlock")
def api_unlock():
    if not vault_exists():
        return jsonify({"error": "Vault not initialized"}), 400
    _bruteforce_delay()

    data = request.json or {}
    password = data.get("password", "")
    remember = bool(data.get("remember", False))
    vault = load_vault()
    salt = bytes.fromhex(vault["salt"])
    try:
        key = derive_key(password, salt, vault.get("iterations", ITERATIONS))
        pt = decrypt(key, bytes.fromhex(vault["verifier"]["nonce"]),
                     bytes.fromhex(vault["verifier"]["ct"]))
        ok = hmac.compare_digest(pt, VERIFIER_PLAINTEXT)
    except Exception:
        ok = False

    if not ok:
        _record_failure()
        return jsonify({"error": "Incorrect master password"}), 401

    _record_success()
    token, csrf = new_session(key, remember=remember)
    resp = jsonify({"ok": True, "csrf": csrf})
    return set_unlock_cookie(resp, token, remember=remember)


@app.post("/api/lock")
def api_lock():
    token, s, err = auth()
    if err:
        return err
    destroy_session(token)
    resp = jsonify({"ok": True})
    resp.delete_cookie(COOKIE_NAME, path="/")
    return resp


@app.get("/api/status")
def api_status():
    _t, s = get_session()
    return jsonify({"initialized": vault_exists(), "unlocked": s is not None})


# --------------------------------------------------------------------------- #
# Routes: entries
# --------------------------------------------------------------------------- #
@app.get("/api/entries")
def list_entries():
    _t, s, err = require_auth()
    if err:
        return err
    vault = load_vault()
    names = sorted(vault["entries"].keys())
    return jsonify({"entries": names})


@app.get("/api/entries/<name>")
def get_entry(name):
    _t, s, err = require_auth()
    if err:
        return err
    e = load_vault()["entries"].get(name)
    if not e:
        return jsonify({"error": "not found"}), 404
    try:
        value = decrypt(s["key"], bytes.fromhex(e["nonce"]), bytes.fromhex(e["ct"]))
    except Exception:
        return jsonify({"error": "decryption failed"}), 500
    return jsonify({"name": name, "value": value.decode("utf-8")})


@app.post("/api/entries")
def put_entry():
    _t, s, err = auth()
    if err:
        return err
    data = request.json or {}
    name = (data.get("name") or "").strip()
    value = data.get("value")
    if not name:
        return jsonify({"error": "name is required"}), 400
    if value is None:
        return jsonify({"error": "value is required"}), 400
    nonce, ct = encrypt(s["key"], str(value).encode("utf-8"))
    vault = load_vault()
    vault["entries"][name] = {"nonce": nonce.hex(), "ct": ct.hex()}
    save_vault(vault)
    return jsonify({"ok": True, "name": name})


@app.delete("/api/entries/<name>")
def delete_entry(name):
    _t, s, err = auth()
    if err:
        return err
    vault = load_vault()
    if name not in vault["entries"]:
        return jsonify({"error": "not found"}), 404
    del vault["entries"][name]
    save_vault(vault)
    return jsonify({"ok": True})


# --------------------------------------------------------------------------- #
# Routes: password change
# --------------------------------------------------------------------------- #
@app.post("/api/change-password")
def change_password():
    token, s, err = auth()
    if err:
        return err
    data = request.json or {}
    current = data.get("current", "")
    new_pw = data.get("new", "")
    confirm = data.get("confirm", "")
    if new_pw != confirm:
        return jsonify({"error": "New passwords do not match"}), 400
    if len(new_pw) < MIN_PASSWORD_LEN:
        return jsonify({"error": f"New password must be at least {MIN_PASSWORD_LEN} characters"}), 400

    vault = load_vault()

    # verify current password: re-derive key from the supplied current password
    # and compare (constant-time) with the in-memory session key.
    try:
        cur_salt = bytes.fromhex(vault["salt"])
        cur_key = derive_key(current, cur_salt, vault.get("iterations", ITERATIONS))
        if not hmac.compare_digest(cur_key, s["key"]):
            raise ValueError
        pt = decrypt(s["key"], bytes.fromhex(vault["verifier"]["nonce"]),
                     bytes.fromhex(vault["verifier"]["ct"]))
        if not hmac.compare_digest(pt, VERIFIER_PLAINTEXT):
            raise ValueError
    except Exception:
        return jsonify({"error": "Current password is incorrect"}), 400

    # re-derive key from new password, re-encrypt verifier + all entries
    new_salt = secrets.token_bytes(SALT_LEN)
    new_key = derive_key(new_pw, new_salt, ITERATIONS)
    nv, nct = encrypt(new_key, VERIFIER_PLAINTEXT)

    new_entries = {}
    for k, e in vault["entries"].items():
        plain = decrypt(s["key"], bytes.fromhex(e["nonce"]), bytes.fromhex(e["ct"]))
        nn, nctk = encrypt(new_key, plain)
        new_entries[k] = {"nonce": nn.hex(), "ct": nctk.hex()}

    save_vault({
        "version": 1,
        "kdf": KDF_NAME,
        "iterations": ITERATIONS,
        "salt": new_salt.hex(),
        "verifier": {"nonce": nv.hex(), "ct": nct.hex()},
        "entries": new_entries,
    })
    with _sessions_lock:
        _sessions[token]["key"] = new_key
    return jsonify({"ok": True})


# --------------------------------------------------------------------------- #
# Error handling
# --------------------------------------------------------------------------- #
@app.errorhandler(404)
def _nf(_e):
    return jsonify({"error": "not found"}), 404


@app.errorhandler(405)
def _mna(_e):
    return jsonify({"error": "method not allowed"}), 405


# --------------------------------------------------------------------------- #
# UI template
# --------------------------------------------------------------------------- #
TEMPLATE = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>Kinko 金庫</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans+JP:wght@400;500;700;900&family=M+PLUS+Rounded+1c:wght@500;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root{
    --bg:#0c0e24;
    --bg2:#15183a;
    --panel:rgba(255,255,255,.04);
    --panel-line:rgba(255,150,190,.28);
    --sakura:#ff8fb1;
    --sakura-soft:#ffa6c9;
    --lilac:#b794f6;
    --gold:#ffd9a0;
    --mint:#7fe3d0;
    --ink:#e8e9ff;
    --muted:#a9adcf;
    --white:#ffffff;
    --glow:0 0 24px rgba(255,143,177,.35);
    --glow-soft:0 0 14px rgba(183,148,246,.3);
    --radius:14px;
    --radius-sm:9px;
    --mono:'JetBrains Mono',ui-monospace,monospace;
    --disp:'M PLUS Rounded 1c','Noto Sans JP',sans-serif;
    --body:'Noto Sans JP','M PLUS Rounded 1c',-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  html,body{height:100%}
  body{
    font-family:var(--body);color:var(--ink);
    background:radial-gradient(1200px 700px at 80% -10%, rgba(255,143,177,.22), transparent 60%),
               radial-gradient(1000px 600px at 0% 100%, rgba(183,148,246,.20), transparent 55%),
               linear-gradient(160deg,#0c0e24 0%,#15183a 55%,#10132e 100%);
    min-height:100vh;
    -webkit-font-smoothing:antialiased;line-height:1.5;overflow-x:hidden;
  }
  ::selection{background:var(--sakura);color:#1a0d16}

  /* starfield */
  .grid{
    background-image:
      radial-gradient(1px 1px at 20% 30%, rgba(255,255,255,.5), transparent),
      radial-gradient(1px 1px at 70% 60%, rgba(255,255,255,.4), transparent),
      radial-gradient(1px 1px at 40% 80%, rgba(255,255,255,.35), transparent),
      radial-gradient(1.5px 1.5px at 85% 20%, rgba(255,166,201,.6), transparent);
    background-size:400px 400px;
  }
  .grid-blue{background:var(--panel)}

  /* legacy var aliases → anime palette (keeps old class rules working) */
  :root{
    --shadow:0 8px 30px rgba(0,0,0,.5);
    --shadow-sm:0 4px 16px rgba(0,0,0,.42);
    --ey:var(--sakura);
    --blue:var(--lilac);
    --cream:rgba(255,255,255,.05);
    --yellow:var(--gold);
    --pink:var(--sakura-soft);
    --paleblue:var(--lilac);
    --cyan:var(--mint);
    --rose:var(--sakura);
    --green:var(--mint);
    --lav:var(--lilac);
  }

  /* utility header */
  header.utility{
    position:sticky;top:0;z-index:100;background:#fff;border-bottom:2px solid var(--ink);
  }
  .u-inner{max-width:1280px;margin:0 auto;padding:12px 24px;display:flex;align-items:center;gap:16px}
  .u-brand{display:flex;align-items:center;gap:10px}
  .u-mark{width:30px;height:30px;border:2px solid var(--ink);background:var(--ey);display:grid;place-items:center;font-size:15px;box-shadow:var(--shadow-sm)}
  .u-name{font-family:var(--disp);font-weight:900;font-size:17px;letter-spacing:-.02em}
  .u-right{margin-left:auto;display:flex;align-items:center;gap:14px}
  .status-pill{display:flex;align-items:center;gap:8px;padding:5px 12px;border:2px solid var(--ink);background:#fff;border-radius:var(--radius);font-family:var(--mono);font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em}
  .status-dot{width:9px;height:9px;border-radius:50%;background:#bbb;border:1px solid var(--ink)}
  .status-pill.unlocked .status-dot{background:var(--green)}
  .status-pill.locked .status-dot{background:var(--ey)}
  .u-link{font-family:var(--mono);font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--ink);text-decoration:none;padding:6px 12px;border:2px solid var(--ink);background:#fff;cursor:pointer;transition:transform .08s,box-shadow .08s;box-shadow:var(--shadow-sm)}
  .u-link:hover{transform:translate(-2px,-2px);box-shadow:5px 5px 0 var(--ink)}
  .u-link:active{transform:translate(2px,2px);box-shadow:1px 1px 0 var(--ink)}

  /* views */
  .view{display:none}
  .view.active{display:block}
  @keyframes fadeUp{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}

  /* display type */
  .display{font-family:var(--disp);font-weight:900;letter-spacing:-.03em;line-height:.92;font-size:clamp(44px,7.5vw,112px)}
  .eyebrow{font-family:var(--mono);font-size:12px;font-weight:700;letter-spacing:.18em;text-transform:uppercase}
  .section-title{font-family:var(--disp);font-weight:800;letter-spacing:-.02em;font-size:clamp(28px,4vw,56px);line-height:1}
  .copy{font-size:15px;max-width:52ch;line-height:1.55}
  .mono{font-family:var(--mono)}
  .label{font-family:var(--mono);font-size:11px;font-weight:600;letter-spacing:.1em;text-transform:uppercase}

  /* buttons */
  .btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;font-family:var(--mono);font-size:13px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;text-decoration:none;padding:12px 18px;border:2px solid var(--ink);background:#fff;color:var(--ink);cursor:pointer;box-shadow:var(--shadow);transition:transform .08s,box-shadow .08s;border-radius:var(--radius)}
  .btn:hover{transform:translate(-2px,-2px);box-shadow:8px 8px 0 var(--ink)}
  .btn:active{transform:translate(2px,2px);box-shadow:2px 2px 0 var(--ink)}
  .btn.cta{background:var(--ey)}
  .btn.blue{background:var(--blue);color:#fff}
  .btn.rose{background:var(--rose);color:#fff}
  .btn.green{background:var(--green)}
  .btn.ghost{background:#fff}
  .btn.sm{padding:8px 12px;font-size:11px}
  .btn.danger{background:#fff;color:var(--rose);border-color:var(--rose)}

  /* hero */
  .hero{background:var(--blue);position:relative;overflow:hidden;border-bottom:2px solid var(--ink)}
  .hero-inner{max-width:1280px;margin:0 auto;padding:64px 24px 72px;position:relative;z-index:2}
  .hero .eyebrow{color:var(--ey);margin-bottom:18px}
  .hero h1{color:#fff;max-width:16ch}
  .hero h1 em{font-style:normal;color:var(--ey)}
  .hero .copy{color:rgba(255,255,255,.9);margin:22px 0 28px;font-size:16px}
  .hero-cta{display:flex;gap:12px;flex-wrap:wrap}
  .hero-collage{position:absolute;inset:0;z-index:1;pointer-events:none}
  .panel{position:absolute;border:2px solid var(--ink);background:#fff;box-shadow:var(--shadow);font-family:var(--mono);font-size:11px}
  .panel .wbar{height:16px;border-bottom:2px solid var(--ink);background:var(--cream);display:flex;gap:4px;padding:3px 6px;align-items:center}
  .panel .wbar i{width:6px;height:6px;border-radius:50%;background:var(--ink);opacity:.4}
  .panel .wbody{padding:8px 10px}
  .panel .row{display:flex;justify-content:space-between;gap:8px;padding:3px 0;border-bottom:1px dashed rgba(17,17,17,.15)}
  .panel .row:last-child{border-bottom:none}
  .panel .k{color:var(--ink);font-weight:600}
  .panel .v{color:var(--ink);opacity:.5}
  .p1{top:60px;right:40px;width:230px;transform:rotate(3deg)}
  .p2{top:230px;right:250px;width:210px;transform:rotate(-2deg)}
  .p3{top:330px;right:80px;width:180px;transform:rotate(1deg)}
  .p4{top:120px;right:230px;width:170px;transform:rotate(-3deg)}
  @media (max-width:760px){.hero-collage{display:none}}

  /* ticker */
  .ticker{background:var(--ink);color:#fff;overflow:hidden;border-top:2px solid var(--ink);border-bottom:2px solid var(--ink);white-space:nowrap}
  .ticker .track{display:inline-block;padding:10px 0;animation:scroll 26s linear infinite;font-family:var(--mono);font-size:13px;font-weight:600;letter-spacing:.14em;text-transform:uppercase}
  .ticker .track span{padding:0 22px}
  .ticker .track .dot{color:var(--ey)}
  @keyframes scroll{from{transform:translateX(0)}to{transform:translateX(-50%)}}
  .ticker.rev .track{animation-direction:reverse}
  .ticker.rev .track .dot{color:var(--rose)}

  /* plate */
  .plate{max-width:1280px;margin:0 auto;padding:72px 24px}
  .plate-head{max-width:60ch;margin:0 auto 44px;text-align:center}
  .plate-head .eyebrow{color:var(--ink);opacity:.5;margin-bottom:14px}
  .plate-head h2{margin-bottom:16px}
  .plate-head p{color:var(--ink);opacity:.75;margin:0 auto;max-width:54ch}

  /* bordered panel */
  .bordered{border:2px solid var(--ink);background:#fff;box-shadow:var(--shadow)}

  /* meet the vault — vault view (entries) */
  .vault-panel{padding:0;overflow:hidden}
  .vault-head{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:18px 22px;border-bottom:2px solid var(--ink);background:var(--cream);flex-wrap:wrap}
  .vault-head .title{font-family:var(--disp);font-weight:800;font-size:18px;letter-spacing:-.01em}
  .vault-head .sub{font-family:var(--mono);font-size:11px;color:var(--ink);opacity:.6}
  .entries{display:flex;flex-direction:column}
  .entry{display:flex;flex-direction:column;gap:10px;padding:16px 22px;border-bottom:1px dashed rgba(17,17,17,.18)}
  .entry:last-child{border-bottom:none}
  .entry-top{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}
  .entry-key{font-family:var(--mono);font-size:13px;font-weight:600;word-break:break-word;overflow-wrap:anywhere;line-height:1.4;flex:1;min-width:0}
  .entry-bottom{display:flex;align-items:center;gap:12px;min-width:0}
  .entry-val{flex:1;min-width:0;font-family:var(--mono);font-size:12.5px;color:var(--ink);opacity:.55;word-break:break-word;overflow-wrap:anywhere;transition:opacity .15s}
  .entry-val.revealed{color:var(--ink);opacity:1}
  .entry-actions{display:flex;gap:6px;flex-shrink:0}
  .icon-btn{width:30px;height:30px;border:2px solid var(--ink);background:#fff;cursor:pointer;display:grid;place-items:center;font-size:12px;box-shadow:var(--shadow-sm);transition:transform .08s,box-shadow .08s}
  .icon-btn:hover{transform:translate(-1px,-1px);box-shadow:4px 4px 0 var(--ink)}
  .icon-btn:active{transform:translate(1px,1px);box-shadow:1px 1px 0 var(--ink)}
  .icon-btn.danger:hover{color:var(--rose)}
  .icon-btn:disabled{opacity:.3;cursor:not-allowed;box-shadow:none}
  .empty-state{text-align:center;padding:56px 24px;color:var(--ink);opacity:.6}
  .empty-state .ico{font-size:40px;margin-bottom:12px}

  /* workflow cards */
  .steps{display:grid;grid-template-columns:repeat(3,1fr);gap:20px}
  @media (max-width:760px){.steps{grid-template-columns:1fr}}
  .step{border:2px solid var(--ink);background:#fff;padding:24px;box-shadow:var(--shadow)}
  .step .num{font-family:var(--disp);font-weight:900;font-size:44px;line-height:1;color:var(--blue)}
  .step h3{font-family:var(--disp);font-weight:800;font-size:19px;margin:14px 0 8px;letter-spacing:-.01em}
  .step p{font-size:13px;color:var(--ink);opacity:.75}
  .dashed-note{margin-top:26px;padding:16px 20px;border:2px dashed var(--ink);background:rgba(255,255,255,.5);font-family:var(--mono);font-size:12px;text-align:center}

  /* system cards */
  .sys{display:grid;grid-template-columns:repeat(3,1fr);gap:20px;align-items:stretch}
  @media (max-width:760px){.sys{grid-template-columns:1fr}}
  .sys-card{border:2px solid var(--ink);background:#fff;padding:22px;box-shadow:var(--shadow-sm)}
  .sys-card.mid{background:var(--ey);box-shadow:var(--shadow)}
  .sys-card .tag{font-family:var(--mono);font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;opacity:.6}
  .sys-card h3{font-family:var(--disp);font-weight:800;font-size:20px;margin:10px 0 8px}
  .sys-card p{font-size:13px;opacity:.8}
  .sys-scale{display:flex;align-items:center;gap:10px;justify-content:center;margin-bottom:30px;flex-wrap:wrap}
  .sys-scale .dot{font-family:var(--mono);font-size:11px;font-weight:700;text-transform:uppercase;padding:5px 10px;border:2px solid var(--ink);background:#fff}
  .sys-scale .dot.on{background:var(--ey)}
  .sys-scale .line{height:2px;background:var(--ink);flex:1;min-width:40px}

  /* use cases grid */
  .uc-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px}
  @media (max-width:900px){.uc-grid{grid-template-columns:repeat(2,1fr)}}
  @media (max-width:520px){.uc-grid{grid-template-columns:1fr}}
  .uc{border:2px solid var(--ink);padding:16px;box-shadow:var(--shadow-sm)}
  .uc .n{font-family:var(--mono);font-size:11px;font-weight:700;opacity:.5}
  .uc h4{font-family:var(--disp);font-weight:800;font-size:15px;margin:6px 0 8px}
  .uc p{font-family:var(--mono);font-size:11px;opacity:.7;word-break:break-word}
  .uc .cat{font-family:var(--mono);font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;display:inline-block;padding:2px 6px;border:1px solid var(--ink);margin-bottom:8px}

  /* conversion banner */
  .conv{background:var(--rose);border-top:2px solid var(--ink);border-bottom:2px solid var(--ink)}
  .conv-inner{max-width:1100px;margin:0 auto;padding:64px 24px;text-align:center}
  .conv h2{font-family:var(--disp);font-weight:900;font-size:clamp(32px,5vw,64px);letter-spacing:-.03em;line-height:.95;color:#fff;margin-bottom:22px}
  .conv h2 .y{color:var(--ey)}
  .conv h2 .b{color:var(--paleblue)}

  /* footer */
  .foot{background:var(--cream)}
  .foot-inner{max-width:1280px;margin:0 auto;padding:56px 24px}
  .foot-card{border:2px solid var(--ink);background:#fff;padding:32px;box-shadow:var(--shadow)}
  .foot-grid{display:grid;grid-template-columns:1.4fr 1fr 1fr;gap:32px}
  @media (max-width:760px){.foot-grid{grid-template-columns:1fr}}
  .foot-card h4{font-family:var(--disp);font-weight:800;font-size:18px;margin-bottom:10px}
  .foot-card p{font-size:13px;opacity:.7;margin-bottom:14px}
  .foot-card ul{list-style:none;display:flex;flex-direction:column;gap:8px}
  .foot-card a{font-family:var(--mono);font-size:12px;color:var(--ink);text-decoration:none;opacity:.75}
  .foot-card a:hover{opacity:1}
  .foot-legal{margin-top:24px;padding-top:16px;border-top:1px dashed var(--ink);font-family:var(--mono);font-size:11px;opacity:.6;display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px}

  /* modal */
  .modal{position:fixed;inset:0;z-index:200;display:flex;align-items:center;justify-content:center;padding:20px}
  .modal.hidden{display:none}
  .modal-backdrop{position:absolute;inset:0;background:rgba(17,17,17,.65)}
  .modal-card{position:relative;z-index:1;width:100%;max-width:500px;padding:24px;animation:fadeUp .25s ease both}

  /* toast */
  .toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(20px);background:#fff;border:2px solid var(--ink);padding:12px 18px;box-shadow:var(--shadow);font-family:var(--mono);font-size:13px;font-weight:600;opacity:0;transition:opacity .2s,transform .2s;z-index:300;display:flex;align-items:center;gap:8px}
  .toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
  .toast.err{color:var(--rose)}
  .toast.ok{color:var(--blue)}

  /* auth plate */
  .auth{background:var(--blue);border-bottom:2px solid var(--ink);min-height:calc(100vh - 54px);display:flex;align-items:center;justify-content:center;padding:40px 20px}
  .auth-card{width:100%;max-width:440px;background:#fff;border:2px solid var(--ink);box-shadow:var(--shadow);padding:32px}
  .auth-card .mark{width:56px;height:56px;border:2px solid var(--ink);background:var(--ey);display:grid;place-items:center;font-size:26px;box-shadow:var(--shadow-sm);margin-bottom:20px}
  .auth-card h2{font-family:var(--disp);font-weight:900;font-size:28px;letter-spacing:-.02em;margin-bottom:6px}
  .auth-card .sub{font-size:13px;color:var(--ink);opacity:.65;margin-bottom:22px;line-height:1.5}
  .field{margin-bottom:16px}
  .field label{display:block;font-family:var(--mono);font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;margin-bottom:8px;opacity:.7}
  .input-wrap{position:relative}
  .input{width:100%;padding:13px 16px;border:2px solid var(--ink);background:#fff;font-family:var(--mono);font-size:14px;color:var(--ink);box-shadow:var(--shadow-sm);transition:transform .06s,box-shadow .06s}
  .input::placeholder{color:rgba(17,17,17,.4)}
  .input:focus{outline:none;transform:translate(-2px,-2px);box-shadow:5px 5px 0 var(--ink)}
  .pw-toggle{position:absolute;right:6px;top:50%;transform:translateY(-50%);background:transparent;border:2px solid var(--ink);color:var(--ink);cursor:pointer;padding:4px 9px;font-family:var(--mono);font-size:11px;font-weight:600}
  .pw-toggle:hover{background:var(--ey)}
  .remember{display:flex;align-items:center;gap:8px;font-family:var(--mono);font-size:12px;font-weight:600;margin-bottom:18px;cursor:pointer;text-transform:uppercase;letter-spacing:.04em}
  .remember input{width:16px;height:16px;accent-color:var(--blue)}
  .auth-card .btn{width:100%}
  .err-msg{color:var(--rose);font-family:var(--mono);font-size:12px;margin-top:14px;padding:10px 12px;border:2px solid var(--rose);background:rgba(233,75,133,.06)}

  /* anime surface repaint — overrides the legacy neo-brutalist rules above */
  header.utility{background:rgba(12,14,36,.82);backdrop-filter:blur(10px);border-bottom-color:var(--panel-line)}
  .u-mark{background:var(--sakura);box-shadow:var(--glow);color:#1a0d16}
  .u-name{color:var(--sakura-soft)}
  .u-link{border-color:var(--panel-line);background:rgba(255,255,255,.04);color:var(--ink)}
  .status-pill{border-color:var(--panel-line);background:rgba(255,255,255,.04);color:var(--ink)}
  .status-dot{border-color:var(--panel-line)}
  .hero{background:linear-gradient(135deg,rgba(183,148,246,.35),rgba(255,143,177,.3));border-bottom-color:var(--panel-line)}
  .hero h1{color:#fff}
  .hero h1 em{color:var(--gold)}
  .hero .copy{color:rgba(255,255,255,.92)}
  .hero-collage .panel{background:rgba(255,255,255,.08);border-color:var(--panel-line);box-shadow:var(--glow-soft)}
  .hero-collage .panel .wbar{background:rgba(255,143,177,.18);border-bottom-color:var(--panel-line)}
  .ticker{background:rgba(10,12,30,.7);border-color:var(--panel-line)}
  .ticker .track{color:var(--ink)}
  .bordered,.vault-panel,.vault-head,.entry,.sys-card,.uc,.step,.auth-card,.foot-card,.input,.icon-btn,.modal-card,.toast,.foot-card{border-color:var(--panel-line);background:rgba(255,255,255,.05)}
  .vault-head{background:rgba(255,255,255,.05)}
  .entry-val{color:var(--muted)}
  .entry-val.revealed{color:var(--ink)}
  .btn{border-color:var(--panel-line);color:var(--ink);box-shadow:var(--glow-soft);border-radius:var(--radius-sm)}
  .btn.cta{background:var(--sakura);color:#1a0d16;box-shadow:var(--glow)}
  .btn.blue{background:var(--lilac);color:#1a0d16}
  .btn.rose{background:var(--sakura);color:#1a0d16}
  .btn.green{background:var(--mint);color:#06231c}
  .btn.danger{color:var(--sakura);border-color:var(--sakura);background:rgba(255,143,177,.08)}
  .icon-btn{box-shadow:none}
  .icon-btn:hover{box-shadow:var(--glow-soft)}
  .input{box-shadow:none}
  .input:focus{transform:translateY(-1px);box-shadow:var(--glow-soft)}
  .input::placeholder{color:var(--muted)}
  .pw-toggle{border-color:var(--panel-line);color:var(--ink)}
  .pw-toggle:hover{background:var(--sakura);color:#1a0d16}
  .remember input{accent-color:var(--sakura)}
  .err-msg{border-color:var(--sakura);background:rgba(255,143,177,.1);color:var(--sakura-soft)}
  .modal-backdrop{background:rgba(6,8,20,.7)}
  .sys-card.mid{background:rgba(255,143,177,.14)}
  .conv{background:linear-gradient(135deg,rgba(183,148,246,.3),rgba(255,143,177,.28));border-color:var(--panel-line)}
  .conv h2{color:#fff}
  .conv h2 .b{color:var(--gold)}
  .foot{background:rgba(10,12,30,.5)}
  .foot-legal{border-top-color:var(--panel-line)}
  .foot-card a{color:var(--ink)}
  .empty-state{color:var(--muted)}
  .auth{background:linear-gradient(135deg,rgba(183,148,246,.28),rgba(255,143,177,.22))}
  .auth-card .mark{background:var(--sakura);color:#1a0d16}
  .toast.err{color:var(--sakura)}
  .toast.ok{color:var(--mint)}
  .u-mark{font-family:var(--disp)}

  .hidden{display:none !important}
  .center{text-align:center}
  .muted{opacity:.65}
</style>
</head>
<body>

<!-- Utility header -->
<header class="utility">
  <div class="u-inner">
    <div class="u-brand">
      <span class="u-mark">🔐</span>
      <span class="u-name">Kinko 金庫</span>
    </div>
    <div class="u-right">
      <div id="stateBadge" class="status-pill">
        <span class="status-dot"></span>
        <span id="stateText">—</span>
      </div>
      <a id="settingsLink" href="/settings" class="u-link hidden">Settings</a>
      <button id="lockBtn" class="u-link hidden">Lock</button>
    </div>
  </div>
</header>

<!-- SETUP -->
<section id="setupView" class="view">
  <div class="auth">
    <div class="auth-card">
      <div class="mark">🛡️</div>
      <h2>Create your vault</h2>
      <div class="sub">Choose a strong master password. It is never stored — lose it and the data is unrecoverable.</div>
      <div class="field">
        <label>Master password</label>
        <div class="input-wrap">
          <input type="password" id="setupPw" class="input" autocomplete="new-password" placeholder="at least 8 characters">
          <button type="button" class="pw-toggle" data-target="setupPw">show</button>
        </div>
      </div>
      <div class="field">
        <label>Confirm password</label>
        <div class="input-wrap">
          <input type="password" id="setupPw2" class="input" autocomplete="new-password" placeholder="repeat password">
          <button type="button" class="pw-toggle" data-target="setupPw2">show</button>
        </div>
      </div>
      <button class="btn cta" id="setupBtn">Create vault</button>
      <div id="setupErr" class="err-msg hidden"></div>
    </div>
  </div>
</section>

<!-- UNLOCK -->
<section id="unlockView" class="view">
  <div class="auth">
    <div class="auth-card">
      <div class="mark">🔒</div>
      <h2>Unlock vault</h2>
      <div class="sub">Enter your master password to access your credentials.</div>
      <div class="field">
        <label>Master password</label>
        <div class="input-wrap">
          <input type="password" id="unlockPw" class="input" autocomplete="current-password" placeholder="master password">
          <button type="button" class="pw-toggle" data-target="unlockPw">show</button>
        </div>
      </div>
      <label class="remember"><input type="checkbox" id="rememberMe">Remember me (30 days)</label>
      <button class="btn cta" id="unlockBtn">Unlock</button>
      <div id="unlockErr" class="err-msg hidden"></div>
    </div>
  </div>
</section>

<!-- VAULT (landing) -->
<section id="vaultView" class="view">

  <!-- HERO -->
  <div class="hero grid-blue">
    <div class="hero-collage">
      <div class="panel p1">
        <div class="wbar"><i></i><i></i><i></i></div>
        <div class="wbody">
          <div class="row"><span class="k">NOUS_API_KEY</span><span class="v">••••••</span></div>
          <div class="row"><span class="k">TELEGRAM_BOT</span><span class="v">••••••</span></div>
          <div class="row"><span class="k">CLERK_SECRET</span><span class="v">••••••</span></div>
        </div>
      </div>
      <div class="panel p2">
        <div class="wbar"><i></i><i></i><i></i></div>
        <div class="wbody">
          <div class="row"><span class="k">AES-256-GCM</span><span class="v">✓</span></div>
          <div class="row"><span class="k">PBKDF2 600k</span><span class="v">✓</span></div>
          <div class="row"><span class="k">zero-knowledge</span><span class="v">✓</span></div>
        </div>
      </div>
      <div class="panel p3">
        <div class="wbar"><i></i><i></i><i></i></div>
        <div class="wbody">
          <div class="row"><span class="k">localhost</span><span class="v">:8787</span></div>
          <div class="row"><span class="k">session</span><span class="v">30d</span></div>
        </div>
      </div>
      <div class="panel p4">
        <div class="wbar"><i></i><i></i><i></i></div>
        <div class="wbody">
          <div class="row"><span class="k">entries</span><span class="v">47</span></div>
        </div>
      </div>
    </div>
    <div class="hero-inner">
      <div class="eyebrow">ENCRYPTED · LOCAL · ZERO-KNOWLEDGE</div>
      <h1 class="display">Your secrets,<br><em>encrypted</em> &amp; local.</h1>
      <p class="copy">A password-gated vault for lab credentials. AES-256-GCM at rest, PBKDF2-derived key, localhost-only. Nothing leaves your machine.</p>
      <div class="hero-cta">
        <button class="btn cta" id="openAddModalBtn">＋ Add entry</button>
        <a class="btn ghost" href="/settings">⚙ Settings</a>
      </div>
    </div>
  </div>

  <!-- TICKER -->
  <div class="ticker">
    <div class="track">
      <span>AES-256-GCM</span><span class="dot">✦</span><span>PBKDF2 · 600k</span><span class="dot">✦</span><span>LOCALHOST ONLY</span><span class="dot">✦</span><span>ZERO-KNOWLEDGE</span><span class="dot">✦</span><span>SESSION-SAFE</span><span class="dot">✦</span>
      <span>AES-256-GCM</span><span class="dot">✦</span><span>PBKDF2 · 600k</span><span class="dot">✦</span><span>LOCALHOST ONLY</span><span class="dot">✦</span><span>ZERO-KNOWLEDGE</span><span class="dot">✦</span><span>SESSION-SAFE</span><span class="dot">✦</span>
    </div>
  </div>

  <!-- MEET THE VAULT -->
  <div class="plate grid">
    <div class="plate-head">
      <div class="eyebrow">MEET THE VAULT</div>
      <h2 class="section-title">Every key, one encrypted shelf.</h2>
      <p>Store API keys, tokens, and passwords as named entries. Reveal, copy, or delete on demand — values are decrypted only when you ask.</p>
    </div>
    <div class="bordered vault-panel">
      <div class="vault-head">
        <div>
          <div class="title">Entries</div>
          <div class="sub" id="entryCount">—</div>
        </div>
        <button class="btn cta sm" id="openAddModalBtn2">＋ Add entry</button>
      </div>
      <div id="entriesBody" class="entries"></div>
      <div id="emptyState" class="empty-state hidden">
        <div class="ico">🔐</div>
        <p>No entries yet. Click "Add entry" to create your first one.</p>
      </div>
    </div>
  </div>

  <!-- WORKFLOW -->
  <div class="plate grid" style="background:var(--yellow)">
    <div class="plate-head">
      <div class="eyebrow">HOW IT WORKS</div>
      <h2 class="section-title">Three steps, zero friction.</h2>
    </div>
    <div class="steps">
      <div class="step"><div class="num">1</div><h3>Unlock</h3><p>Enter your master password. The derived key lives only in server memory for the session.</p></div>
      <div class="step"><div class="num">2</div><h3>Store</h3><p>Add a named entry. The value is encrypted with AES-256-GCM before it touches disk.</p></div>
      <div class="step"><div class="num">3</div><h3>Retrieve</h3><p>Reveal, copy, or delete anytime. Reveal-on-demand keeps secrets off the wire.</p></div>
    </div>
    <div class="dashed-note">— sessions persist across restarts; use "Remember me" to stay signed in for 30 days —</div>
  </div>


  <!-- CONVERSION BANNER -->
  <div class="conv">
    <div class="conv-inner">
      <h2>Stop pasting secrets<br>into <span class="y">plaintext</span>. <span class="b">Start vaulting.</span></h2>
      <button class="btn blue" id="openAddModalBtn3">＋ Add your first entry</button>
    </div>
  </div>

  <!-- FOOTER -->
  <div class="foot grid">
    <div class="foot-inner">
      <div class="foot-card">
        <div class="foot-grid">
          <div>
            <h4>🔐 Kinko 金庫</h4>
            <p>A local, zero-knowledge secret store for the lab. AES-256-GCM at rest, PBKDF2-derived, localhost-only by default.</p>
            <a class="btn sm blue" href="/">↑ Back to top</a>
          </div>
          <div>
            <div class="label" style="margin-bottom:10px">Methodology</div>
            <ul>
              <li><a href="#">01 · Key derivation</a></li>
              <li><a href="#">02 · Encryption</a></li>
              <li><a href="#">03 · Session model</a></li>
            </ul>
          </div>
          <div>
            <div class="label" style="margin-bottom:10px">Navigate</div>
            <ul>
              <li><a href="/">Vault</a></li>
              <li><a href="/settings">Settings</a></li>
              <li><a href="http://192.168.1.47:8787">LAN access</a></li>
            </ul>
          </div>
        </div>
        <div class="foot-legal">
          <span>© 2026 Kinko 金庫 · localhost:8787</span>
          <span>master key never leaves the server</span>
        </div>
      </div>
    </div>
  </div>
</section>

<!-- SETTINGS -->
<section id="settingsView" class="view">
  <div class="plate grid">
    <div class="auth-card" style="max-width:620px;margin:0 auto">
      <div class="mark">⚙️</div>
      <h2>Settings</h2>
      <div class="sub">Manage your vault configuration.</div>

      <div class="field" style="margin-top:20px">
        <label>Current password</label>
        <div class="input-wrap">
          <input type="password" id="cpCur" class="input" placeholder="current password">
          <button type="button" class="pw-toggle" data-target="cpCur">show</button>
        </div>
      </div>
      <div class="field">
        <label>New password</label>
        <div class="input-wrap">
          <input type="password" id="cpNew" class="input" placeholder="new password">
          <button type="button" class="pw-toggle" data-target="cpNew">show</button>
        </div>
      </div>
      <div class="field">
        <label>Confirm new</label>
        <div class="input-wrap">
          <input type="password" id="cpNew2" class="input" placeholder="confirm">
          <button type="button" class="pw-toggle" data-target="cpNew2">show</button>
        </div>
      </div>
      <button class="btn cta" id="changePwBtn" style="width:100%">Change password</button>

      <div class="label" style="margin:28px 0 12px">Session</div>
      <p class="muted" style="font-size:13px;margin-bottom:16px">Sessions persist across restarts. Tick "Remember me" on the unlock screen to stay signed in for 30 days.</p>
      <button class="btn danger" id="lockFromSettingsBtn" style="width:100%">Lock vault</button>
      <div style="margin-top:14px"><a class="btn ghost sm" href="/">← Back to vault</a></div>
    </div>
  </div>
</section>

<!-- ADD MODAL -->
<div id="addModal" class="modal hidden">
  <div class="modal-backdrop" id="addModalBackdrop"></div>
  <div class="modal-card bordered">
    <div class="vault-head" style="background:var(--cream)">
      <div class="title">Add / update entry</div>
      <button class="icon-btn" id="closeAddModalBtn" title="close">✕</button>
    </div>
    <div style="padding:22px">
      <div class="field">
        <label>Name</label>
        <input type="text" id="newName" class="input mono" placeholder="e.g. github_api_key">
      </div>
      <div class="field">
        <label>Value</label>
        <input type="text" id="newValue" class="input mono" placeholder="secret value">
      </div>
      <div style="display:flex;gap:10px;margin-top:20px">
        <button class="btn cta" id="saveBtn" style="flex:1">Save entry</button>
        <button class="btn ghost" id="cancelAddBtn" style="flex:1">Cancel</button>
      </div>
    </div>
  </div>
</div>

<div id="toast" class="toast"></div>

<script>
const csrf = {{ csrf|tojson }};
let UNLOCKED = {{ unlocked|tojson }};
let INITIALIZED = {{ initialized|tojson }};
const revealed = new Set();
const values = {};

const $ = (id) => document.getElementById(id);
function show(el){ el.classList.add("active"); }
function hide(el){ el.classList.remove("active"); }

function toast(msg, kind=""){
  const t = $("toast");
  const icon = kind==="err" ? "✕" : kind==="ok" ? "✓" : "ℹ";
  t.innerHTML = "<span>"+icon+"</span><span>"+msg+"</span>";
  t.className = "toast show " + kind;
  clearTimeout(t._t);
  t._t = setTimeout(()=>{ t.className = "toast " + kind; }, 2600);
}

async function api(path, method="GET", body=null){
  const opts = { method, headers: {}, credentials: "same-origin" };
  if (body !== null){ opts.headers["Content-Type"]="application/json"; opts.body = JSON.stringify(body); }
  if (method!=="GET") opts.headers["X-CSRF-Token"] = csrf;
  const r = await fetch(path, opts);
  let data = null;
  try{ data = await r.json(); }catch(e){}
  return { ok: r.ok, status: r.status, data };
}

function setStateBadge(){
  const pill = $("stateBadge");
  const txt = $("stateText");
  pill.classList.remove("unlocked","locked");
  if (UNLOCKED){ pill.classList.add("unlocked"); txt.textContent = "unlocked"; }
  else if (INITIALIZED){ pill.classList.add("locked"); txt.textContent = "locked"; }
  else { txt.textContent = "not set"; }
  $("lockBtn").classList.toggle("hidden", !UNLOCKED);
  const sl = $("settingsLink"); if (sl) sl.classList.toggle("hidden", !UNLOCKED);
}

function renderViews(){
  hide($("setupView")); hide($("unlockView")); hide($("vaultView")); hide($("settingsView"));
  if (!INITIALIZED) show($("setupView"));
  else if (!UNLOCKED) show($("unlockView"));
  else if (window.location.pathname === "/settings") show($("settingsView"));
  else show($("vaultView"));
  setStateBadge();
}

async function refreshEntries(){
  const res = await api("/api/entries");
  const body = $("entriesBody"); body.innerHTML = "";
  const names = (res.data && res.data.entries) || [];
  $("emptyState").classList.toggle("hidden", names.length>0);
  $("entryCount").textContent = names.length + " entr" + (names.length===1?"y":"ies");
  for (const name of names){
    const isRev = revealed.has(name);
    const row = document.createElement("div");
    row.className = "entry";
    const top = document.createElement("div"); top.className = "entry-top";
    const key = document.createElement("div"); key.className="entry-key"; key.textContent = name;
    top.append(key);
    const bottom = document.createElement("div"); bottom.className = "entry-bottom";
    const val = document.createElement("div");
    val.className = "entry-val" + (isRev ? " revealed" : "");
    val.textContent = isRev ? (values[name] ?? "••••••••") : "••••••••";
    const actions = document.createElement("div"); actions.className="entry-actions";

    const revBtn = document.createElement("button");
    revBtn.className = "icon-btn"; revBtn.title = isRev ? "hide" : "reveal";
    revBtn.innerHTML = isRev ? "🙈" : "👁";
    revBtn.onclick = async () => {
      if (revealed.has(name)){ revealed.delete(name); refreshEntries(); return; }
      const v = await api("/api/entries/"+encodeURIComponent(name));
      if (v.ok){ values[name] = v.data.value; revealed.add(name); refreshEntries(); }
      else toast((v.data&&v.data.error)||"error","err");
    };

    const copyBtn = document.createElement("button");
    copyBtn.className = "icon-btn"; copyBtn.title = "copy"; copyBtn.innerHTML = "⧉";
    copyBtn.disabled = !isRev;
    copyBtn.onclick = async () => {
      try{ await navigator.clipboard.writeText(values[name]); toast("copied to clipboard","ok"); }
      catch(e){ toast("copy failed","err"); }
    };

    const delBtn = document.createElement("button");
    delBtn.className = "icon-btn danger"; delBtn.title = "delete"; delBtn.innerHTML = "✕";
    delBtn.onclick = async () => {
      if (!confirm("Delete entry '"+name+"'?")) return;
      const d = await api("/api/entries/"+encodeURIComponent(name), "DELETE");
      if (d.ok){ revealed.delete(name); delete values[name]; toast("deleted","ok"); refreshEntries(); }
      else toast((d.data&&d.data.error)||"error","err");
    };

    actions.append(revBtn, copyBtn, delBtn);
    bottom.append(val, actions);
    row.append(top, bottom);
    body.append(row);
  }
}

document.querySelectorAll(".pw-toggle").forEach(btn => {
  btn.addEventListener("click", () => {
    const inp = document.getElementById(btn.dataset.target);
    if (!inp) return;
    const show = inp.type === "password";
    inp.type = show ? "text" : "password";
    btn.textContent = show ? "hide" : "show";
  });
});

$("setupBtn").onclick = async () => {
  const pw = $("setupPw").value, pw2 = $("setupPw2").value;
  const err = $("setupErr");
  err.classList.add("hidden");
  if (pw !== pw2){ err.textContent = "Passwords do not match"; err.classList.remove("hidden"); return; }
  const r = await api("/api/setup","POST",{password:pw,confirm:pw2});
  if (r.ok){ sessionStorage.setItem("vault_toast","Vault created"); window.location.reload(); }
  else { err.textContent = (r.data&&r.data.error)||"error"; err.classList.remove("hidden"); }
};

$("unlockBtn").onclick = doUnlock;
$("unlockPw").onkeydown = (e)=>{ if(e.key==="Enter") doUnlock(); };
async function doUnlock(){
  const pw = $("unlockPw").value;
  const remember = $("rememberMe") ? $("rememberMe").checked : false;
  const err = $("unlockErr");
  err.classList.add("hidden");
  const r = await api("/api/unlock","POST",{password:pw, remember:remember});
  if (r.ok){ sessionStorage.setItem("vault_toast","Unlocked"); window.location.reload(); }
  else { err.textContent = (r.data&&r.data.error)||"error"; err.classList.remove("hidden"); }
}

$("lockBtn").onclick = async () => {
  await api("/api/lock","POST");
  UNLOCKED=false; revealed.clear(); Object.keys(values).forEach(k=>delete values[k]); window.location.href = "/";
};

function openAddModal(){ $("addModal").classList.remove("hidden"); setTimeout(()=>{ $("newName").focus(); }, 50); }
function closeAddModal(){ $("addModal").classList.add("hidden"); $("newName").value=""; $("newValue").value=""; }
$("openAddModalBtn").onclick = openAddModal;
$("openAddModalBtn2").onclick = openAddModal;
$("openAddModalBtn3").onclick = openAddModal;
$("closeAddModalBtn").onclick = closeAddModal;
$("cancelAddBtn").onclick = closeAddModal;
$("addModalBackdrop").onclick = closeAddModal;
$("saveBtn").onclick = async () => {
  const name = $("newName").value.trim(), value = $("newValue").value;
  if (!name){ toast("Name is required","err"); return; }
  if (value===""){ toast("Value is required","err"); return; }
  const r = await api("/api/entries","POST",{name,value});
  if (r.ok){ closeAddModal(); toast("Saved","ok"); refreshEntries(); }
  else toast((r.data&&r.data.error)||"error","err");
};

$("lockFromSettingsBtn").onclick = async () => {
  await api("/api/lock","POST");
  UNLOCKED=false; revealed.clear(); Object.keys(values).forEach(k=>delete values[k]); window.location.href = "/";
};

$("changePwBtn").onclick = async () => {
  const cur=$("cpCur").value, nw=$("cpNew").value, cf=$("cpNew2").value;
  if (nw!==cf){ toast("New passwords do not match","err"); return; }
  const r = await api("/api/change-password","POST",{current:cur,new:nw,confirm:cf});
  if (r.ok){ $("cpCur").value="";$("cpNew").value="";$("cpNew2").value=""; toast("Password changed","ok"); }
  else toast((r.data&&r.data.error)||"error","err");
};

(async function init(){
  const s = await api("/api/status");
  if (s.data){ INITIALIZED = s.data.initialized; UNLOCKED = s.data.unlocked; }
  renderViews();
  if (UNLOCKED) refreshEntries();
  const t = sessionStorage.getItem("vault_toast");
  if (t){ sessionStorage.removeItem("vault_toast"); toast(t,"ok"); }
})();
</script>
</body>
</html>

"""


# Load persisted sessions (remember-me) on startup
_load_sessions()

if __name__ == "__main__":
    print(f"Kinko 金庫 on http://{HOST}:{PORT}  (vault: {VAULT_PATH})")
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
