"""Encrypted persistence: accounts (mail credentials), OAuth clients, tokens, auth codes.

Single JSON document encrypted at rest with Fernet (AES-128-CBC + HMAC).
The only stateful artifacts are DATA_DIR/master.key and DATA_DIR/store.enc —
losing them simply forces every user to re-authenticate.
"""

import copy
import json
import os
import threading
import time

from cryptography.fernet import Fernet

import config

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


def _ensure_master_key() -> bytes:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not KEY_PATH.exists():
        _write_private(KEY_PATH, Fernet.generate_key())
    return KEY_PATH.read_bytes()


def _fernet() -> Fernet:
    return Fernet(_ensure_master_key())


def _purge_expired(data: dict) -> None:
    now = time.time()
    for table in ("access_tokens", "auth_codes"):
        expired = [k for k, v in data[table].items() if v.get("expires_at", 0) <= now]
        for k in expired:
            del data[table][k]


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

def save_access_token(token: str, client_id: str, label: str, scopes: list, expires_at: float) -> None:
    with _lock:
        data = _load()
        data["access_tokens"][token] = {"client_id": client_id, "label": label, "scopes": scopes, "expires_at": expires_at}
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

def save_refresh_token(token: str, client_id: str, label: str, scopes: list) -> None:
    with _lock:
        data = _load()
        data["refresh_tokens"][token] = {"client_id": client_id, "label": label, "scopes": scopes}
        _save(data)


def get_refresh_token(token: str) -> dict | None:
    return _load()["refresh_tokens"].get(token)


def delete_refresh_token(token: str) -> None:
    with _lock:
        data = _load()
        data["refresh_tokens"].pop(token, None)
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
