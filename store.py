"""Encrypted persistence: accounts (mail credentials), OAuth clients, tokens, auth codes.

Single JSON document encrypted at rest with Fernet (AES-128-CBC + HMAC). The key comes
from MCP_MASTER_KEY / MCP_MASTER_KEY_FILE, or (fallback) a generated DATA_DIR/master.key.
Losing the key + store simply forces every user to re-authenticate. Keeping the key OUTSIDE
DATA_DIR means a backup of the data volume alone cannot decrypt the store.
"""

import copy
import json
import logging
import os
import threading
import time
from pathlib import Path

from cryptography.fernet import Fernet

import config

logger = logging.getLogger(__name__)

DATA_DIR = config.DATA_DIR
KEY_PATH = DATA_DIR / "master.key"
STORE_PATH = DATA_DIR / "store.enc"

_EMPTY = {"accounts": {}, "oauth_clients": {}, "access_tokens": {}, "refresh_tokens": {}, "auth_codes": {}}

_lock = threading.RLock()
_cache = {"mtime": None, "data": None}


def _write_private(path, payload: bytes) -> None:
    """Write with 0600 from creation — no window where the file is world-readable."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)


def _validate_key(key: bytes, source: str) -> bytes:
    try:
        Fernet(key)
    except Exception:
        raise SystemExit(f"invalid master key from {source}: must be a urlsafe-base64 Fernet "
                         "key (generate with: python -c \"from cryptography.fernet import "
                         "Fernet; print(Fernet.generate_key().decode())\")")
    return key


def _ensure_master_key() -> bytes:
    # Precedence: explicit key from env/secret > key file at a chosen path > a keyfile
    # generated inside DATA_DIR. Keeping the key OUT of DATA_DIR means a backup or snapshot
    # of the data volume alone cannot decrypt the store.
    if config.MASTER_KEY:
        return _validate_key(config.MASTER_KEY.encode(), "MCP_MASTER_KEY")
    if config.MASTER_KEY_FILE:
        return _validate_key(Path(config.MASTER_KEY_FILE).read_bytes().strip(), "MCP_MASTER_KEY_FILE")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not KEY_PATH.exists():
        _write_private(KEY_PATH, Fernet.generate_key())
        logger.warning("master key generated at %s (inside the data dir). For stronger "
                       "protection set MCP_MASTER_KEY or MCP_MASTER_KEY_FILE so that a backup "
                       "of the data volume alone cannot decrypt the store.", KEY_PATH)
    return KEY_PATH.read_bytes()


def _fernet() -> Fernet:
    return Fernet(_ensure_master_key())


def _purge_expired(data: dict) -> None:
    now = time.time()
    for table in ("access_tokens", "auth_codes"):
        expired = [k for k, v in data[table].items() if v.get("expires_at", 0) <= now]
        for k in expired:
            del data[table][k]
    # refresh tokens carry an expiry now; purge lapsed ones (legacy tokens have none → kept)
    for k in [k for k, v in data["refresh_tokens"].items() if 0 < v.get("expires_at", 0) <= now]:
        del data["refresh_tokens"][k]


def _load() -> dict:
    with _lock:
        if not STORE_PATH.exists():
            return copy.deepcopy(_EMPTY)
        mtime = STORE_PATH.stat().st_mtime_ns
        if _cache["mtime"] != mtime:
            decrypted = _fernet().decrypt(STORE_PATH.read_bytes())
            data = json.loads(decrypted)
            for key, default in _EMPTY.items():
                data.setdefault(key, copy.deepcopy(default))
            _cache["mtime"] = mtime
            _cache["data"] = data
        _purge_expired(_cache["data"])
        return _cache["data"]


def _save(data: dict) -> None:
    with _lock:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        encrypted = _fernet().encrypt(json.dumps(data).encode("utf-8"))
        _write_private(STORE_PATH, encrypted)
        _cache["mtime"] = STORE_PATH.stat().st_mtime_ns
        _cache["data"] = data


# ---- accounts ----

def upsert_account(label: str, imap: dict, caldav: dict | None) -> None:
    with _lock:
        data = _load()
        data["accounts"][label] = {"imap": imap, "caldav": caldav}
        _save(data)


def get_account(label: str) -> dict | None:
    return _load()["accounts"].get(label)


# ---- oauth clients ----

def save_client(client_id: str, client_info: dict) -> None:
    with _lock:
        data = _load()
        data["oauth_clients"][client_id] = client_info
        _save(data)


def get_client(client_id: str) -> dict | None:
    return _load()["oauth_clients"].get(client_id)


# ---- access tokens ----

def save_access_token(token: str, client_id: str, label: str, scopes: list,
                       expires_at: float, family_id: str = None) -> None:
    with _lock:
        data = _load()
        data["access_tokens"][token] = {"client_id": client_id, "label": label, "scopes": scopes,
                                         "expires_at": expires_at, "family_id": family_id}
        _save(data)


def get_access_token(token: str) -> dict | None:
    entry = _load()["access_tokens"].get(token)
    if entry and entry["expires_at"] > time.time():
        return entry
    return None


def delete_access_token(token: str) -> None:
    with _lock:
        data = _load()
        data["access_tokens"].pop(token, None)
        _save(data)


# ---- refresh tokens ----
# Rotating tokens: the previous token is kept but marked used_at, as a reuse tripwire.
# Presenting an already-used (rotated) token means it leaked → the whole family is revoked.

def save_refresh_token(token: str, client_id: str, label: str, scopes: list,
                        family_id: str, expires_at: float) -> None:
    with _lock:
        data = _load()
        data["refresh_tokens"][token] = {"client_id": client_id, "label": label, "scopes": scopes,
                                          "family_id": family_id, "expires_at": expires_at}
        _save(data)


def get_refresh_token(token: str) -> dict | None:
    return _load()["refresh_tokens"].get(token)


def mark_refresh_token_used(token: str) -> None:
    with _lock:
        data = _load()
        entry = data["refresh_tokens"].get(token)
        if entry is not None:
            entry["used_at"] = time.time()
            _save(data)


def delete_refresh_token(token: str) -> None:
    with _lock:
        data = _load()
        data["refresh_tokens"].pop(token, None)
        _save(data)


def revoke_family(family_id: str) -> None:
    """Revoke a whole refresh-token family plus its access tokens (reuse detected)."""
    if not family_id:
        return
    with _lock:
        data = _load()
        for table in ("refresh_tokens", "access_tokens"):
            for tok in [t for t, v in data[table].items() if v.get("family_id") == family_id]:
                del data[table][tok]
        _save(data)


# ---- authorization codes ----

def save_auth_code(code: str, client_id: str, label: str, scopes: list, expires_at: float,
                    code_challenge: str, redirect_uri: str, redirect_uri_provided_explicitly: bool) -> None:
    with _lock:
        data = _load()
        data["auth_codes"][code] = {
            "client_id": client_id,
            "label": label,
            "scopes": scopes,
            "expires_at": expires_at,
            "code_challenge": code_challenge,
            "redirect_uri": redirect_uri,
            "redirect_uri_provided_explicitly": redirect_uri_provided_explicitly,
        }
        _save(data)


def get_auth_code(code: str) -> dict | None:
    entry = _load()["auth_codes"].get(code)
    if entry and entry["expires_at"] > time.time():
        return entry
    return None


def delete_auth_code(code: str) -> None:
    with _lock:
        data = _load()
        data["auth_codes"].pop(code, None)
        _save(data)
