"""OAuth 2.1 authorization server backed by the mail server itself.

Identity model: a successful IMAP login with the mailbox password IS the proof of
identity — no separate user database. Supports Dynamic Client Registration (RFC 7591),
PKCE (S256), refresh-token rotation and revocation. Serves its own login page.
"""

import html
import secrets
import time

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse

import config
import imap_ops
import store

AUTH_CODE_TTL = 300
ACCESS_TOKEN_TTL = 3600
PENDING_TTL = 900
MAX_LOGIN_ATTEMPTS = 8       # per IP
MAX_GLOBAL_ATTEMPTS = 50     # across ALL IPs — backstop against spoofed-IP rotation
ATTEMPT_WINDOW = 600         # seconds

# pending authorization requests, keyed by short-lived login_id (in-memory)
_pending: dict[str, dict] = {}

# failed login attempts per IP (brute-force protection) + global window
_attempts: dict[str, list] = {}
_global_attempts: list = []


def _cleanup_pending() -> None:
    cutoff = time.time() - PENDING_TTL
    for key in [k for k, v in _pending.items() if v["created_at"] < cutoff]:
        del _pending[key]


def _client_ip(request: Request) -> str:
    # The LAST X-Forwarded-For entry is the one appended by the nearest proxy — the
    # earlier ones are client-supplied and spoofable. Direct exposure: disable trust.
    if config.TRUST_PROXY_HEADERS:
        ip = (request.headers.get("cf-connecting-ip")
              or request.headers.get("x-forwarded-for", "").split(",")[-1].strip())
        if ip:
            return ip
    return request.client.host if request.client else "unknown"


def _rate_limited(ip: str) -> bool:
    cutoff = time.time() - ATTEMPT_WINDOW
    _global_attempts[:] = [t for t in _global_attempts if t > cutoff]
    if len(_global_attempts) >= MAX_GLOBAL_ATTEMPTS:
        return True
    attempts = [t for t in _attempts.get(ip, []) if t > cutoff]
    _attempts[ip] = attempts
    return len(attempts) >= MAX_LOGIN_ATTEMPTS


def _record_failure(ip: str) -> None:
    now = time.time()
    _global_attempts.append(now)
    _attempts.setdefault(ip, []).append(now)
    if len(_attempts) > 1000:  # bound memory against spoofed-IP churn
        cutoff = now - ATTEMPT_WINDOW
        for stale in [k for k, v in _attempts.items() if not any(t > cutoff for t in v)]:
            del _attempts[stale]


def _client_dict_to_model(d: dict) -> OAuthClientInformationFull:
    return OAuthClientInformationFull(**d)


class MailOAuthProvider(OAuthAuthorizationServerProvider):
    # --- clients ---

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        d = store.get_client(client_id)
        return _client_dict_to_model(d) if d else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if not client_info.client_id:
            client_info.client_id = secrets.token_urlsafe(16)
        if client_info.token_endpoint_auth_method in ("client_secret_post", "client_secret_basic") and not client_info.client_secret:
            client_info.client_secret = secrets.token_urlsafe(32)
        client_info.client_id_issued_at = int(time.time())
        store.save_client(client_info.client_id, client_info.model_dump(mode="json", exclude_none=True))

    # --- authorize: hands off to our own login page ---

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        _cleanup_pending()
        login_id = secrets.token_urlsafe(24)
        _pending[login_id] = {
            "client_id": client.client_id,
            "state": params.state,
            "scopes": params.scopes or [],
            "code_challenge": params.code_challenge,
            "redirect_uri": str(params.redirect_uri),
            "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
            "resource": params.resource,
            "created_at": time.time(),
        }
        return f"/login?login_id={login_id}"

    # --- authorization codes ---

    async def load_authorization_code(self, client: OAuthClientInformationFull, authorization_code: str) -> AuthorizationCode | None:
        entry = store.get_auth_code(authorization_code)
        if entry is None or entry["client_id"] != client.client_id:
            return None
        return AuthorizationCode(
            code=authorization_code,
            scopes=entry["scopes"],
            expires_at=entry["expires_at"],
            client_id=entry["client_id"],
            code_challenge=entry["code_challenge"],
            redirect_uri=entry["redirect_uri"],
            redirect_uri_provided_explicitly=entry["redirect_uri_provided_explicitly"],
            subject=entry["label"],
        )

    async def exchange_authorization_code(self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode) -> OAuthToken:
        store.delete_auth_code(authorization_code.code)

        access_token = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(32)
        expires_at = time.time() + ACCESS_TOKEN_TTL

        store.save_access_token(access_token, client.client_id, authorization_code.subject, authorization_code.scopes, expires_at)
        store.save_refresh_token(refresh_token, client.client_id, authorization_code.subject, authorization_code.scopes)

        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_TTL,
            scope=" ".join(authorization_code.scopes),
            refresh_token=refresh_token,
        )

    # --- refresh tokens ---

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        entry = store.get_refresh_token(refresh_token)
        if entry is None or entry["client_id"] != client.client_id:
            return None
        return RefreshToken(token=refresh_token, client_id=entry["client_id"], scopes=entry["scopes"], subject=entry["label"])

    async def exchange_refresh_token(self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list) -> OAuthToken:
        store.delete_refresh_token(refresh_token.token)

        new_access = secrets.token_urlsafe(32)
        new_refresh = secrets.token_urlsafe(32)
        expires_at = time.time() + ACCESS_TOKEN_TTL
        use_scopes = scopes or refresh_token.scopes

        store.save_access_token(new_access, client.client_id, refresh_token.subject, use_scopes, expires_at)
        store.save_refresh_token(new_refresh, client.client_id, refresh_token.subject, use_scopes)

        return OAuthToken(
            access_token=new_access,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_TTL,
            scope=" ".join(use_scopes),
            refresh_token=new_refresh,
        )

    # --- access tokens ---

    async def load_access_token(self, token: str) -> AccessToken | None:
        entry = store.get_access_token(token)
        if entry is None:
            return None
        return AccessToken(token=token, client_id=entry["client_id"], scopes=entry["scopes"],
                            expires_at=int(entry["expires_at"]), subject=entry["label"])

    async def revoke_token(self, token) -> None:
        store.delete_access_token(token.token)
        store.delete_refresh_token(token.token)


LOGIN_FORM = """
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{server_name} - Sign in</title>
<style>
body {{ font-family: system-ui, sans-serif; background:#0f172a; color:#e2e8f0; display:flex; align-items:center; justify-content:center; height:100vh; margin:0; }}
form {{ background:#1e293b; padding:2rem; border-radius:12px; width:340px; }}
h1 {{ font-size:1.1rem; margin-bottom:1.2rem; }}
label {{ font-size:.85rem; color:#94a3b8; }}
.row {{ display:flex; align-items:center; margin:.3rem 0 1rem; }}
input[type=text] {{ flex:1; padding:.6rem; border-radius:6px 0 0 6px; border:1px solid #334155; background:#0f172a; color:#e2e8f0; }}
.suffix {{ padding:.6rem; background:#334155; border-radius:0 6px 6px 0; color:#94a3b8; font-size:.9rem; }}
input[type=password] {{ width:100%; padding:.6rem; border-radius:6px; border:1px solid #334155; background:#0f172a; color:#e2e8f0; box-sizing:border-box; }}
button {{ width:100%; padding:.7rem; background:#2563eb; color:white; border:none; border-radius:6px; font-weight:600; cursor:pointer; }}
.error {{ color:#f87171; font-size:.85rem; margin-bottom:1rem; }}
.client {{ color:#94a3b8; font-size:.8rem; margin:-.6rem 0 1rem; }}
</style></head>
<body>
<form method="post" action="/login">
  <h1>Connect your {server_name} mailbox</h1>
  {client_html}
  {error_html}
  <input type="hidden" name="login_id" value="{login_id}">
  <label>Username</label>
  <div class="row">
    <input type="text" name="username" required autofocus value="{username}">
    <div class="suffix">@{domain}</div>
  </div>
  <label>E-mail password</label>
  <div class="row" style="display:block;">
    <input type="password" name="password" required>
  </div>
  <button type="submit">Authorize</button>
</form>
</body></html>
"""


def _requesting_client(login_id: str) -> str:
    """Human-readable name of the OAuth client behind this login, for the consent page."""
    pending = _pending.get(login_id)
    if not pending:
        return ""
    client = store.get_client(pending["client_id"]) or {}
    return client.get("client_name") or pending["client_id"]


def _render_form(login_id: str, username: str = "", error: str = "") -> str:
    client_name = _requesting_client(login_id)
    return LOGIN_FORM.format(
        server_name=html.escape(config.SERVER_NAME),
        client_html=(f'<div class="client">Access requested by: <b>{html.escape(client_name)}</b></div>'
                     if client_name else ""),
        error_html=f'<div class="error">{html.escape(error)}</div>' if error else "",
        login_id=html.escape(login_id),
        username=html.escape(username),
        domain=config.EMAIL_DOMAIN,
    )


async def login_get(request: Request) -> HTMLResponse:
    login_id = request.query_params.get("login_id", "")
    if login_id not in _pending:
        return HTMLResponse("Invalid or expired link. Start the connection again from your MCP client.", status_code=400)
    return HTMLResponse(_render_form(login_id))


async def login_post(request: Request):
    form = await request.form()
    login_id = form.get("login_id", "")
    username = (form.get("username") or "").strip()
    password = form.get("password") or ""

    pending = _pending.get(login_id)
    if pending is None:
        return HTMLResponse("Invalid or expired link. Start the connection again from your MCP client.", status_code=400)

    ip = _client_ip(request)
    if _rate_limited(ip):
        return HTMLResponse("Too many login attempts. Wait 10 minutes and try again.", status_code=429)

    email = f"{username}@{config.EMAIL_DOMAIN}"

    ok = imap_ops.verify_login(config.IMAP_HOST, config.IMAP_PORT, email, password)
    if not ok:
        _record_failure(ip)
        return HTMLResponse(_render_form(login_id, username, "Invalid username or password."), status_code=401)

    _attempts.pop(ip, None)

    caldav_creds = None
    if config.CALDAV_URL_TEMPLATE:
        caldav_creds = {"base_url": config.CALDAV_URL_TEMPLATE.format(email=email),
                        "user": email, "password": password}
    imap_creds = {"host": config.IMAP_HOST, "port": config.IMAP_PORT, "user": email, "password": password}
    store.upsert_account(email, imap_creds, caldav_creds)

    code = secrets.token_urlsafe(32)
    store.save_auth_code(
        code,
        pending["client_id"],
        email,
        pending["scopes"],
        time.time() + AUTH_CODE_TTL,
        pending["code_challenge"],
        pending["redirect_uri"],
        pending["redirect_uri_provided_explicitly"],
    )

    del _pending[login_id]

    redirect_uri = construct_redirect_uri(pending["redirect_uri"], code=code, state=pending["state"])
    return RedirectResponse(url=redirect_uri, status_code=302)
