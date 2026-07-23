"""OAuth 2.1 authorization server backed by the mail server itself.

Identity model: a successful IMAP login with the mailbox password IS the proof of
identity — no separate user database. Supports Dynamic Client Registration (RFC 7591),
PKCE (S256), refresh-token rotation and revocation. Serves its own login page.
"""

import html
import re
import secrets
import time
from urllib.parse import urlsplit

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
REFRESH_TOKEN_TTL = 30 * 24 * 3600   # absolute lifetime of a refresh-token family
PENDING_TTL = 900
MAX_LOGIN_ATTEMPTS = 8       # failures per source IP per window
MAX_USER_ATTEMPTS = 12       # failures per TARGET username per window (IP-independent)
ATTEMPT_WINDOW = 600         # seconds

# pending authorization requests, keyed by short-lived login_id (in-memory)
_pending: dict[str, dict] = {}

# failed login attempts, per source IP and per target username (brute-force protection).
# Two independent limiters: the per-IP one stops a single host; the per-username one caps
# attempts against any one account even if the attacker rotates/spoofs IPs. There is NO
# global limiter — a single global counter would let anyone lock out every user at once.
_attempts: dict[str, list] = {}
_user_attempts: dict[str, list] = {}


def _cleanup_pending() -> None:
    cutoff = time.time() - PENDING_TTL
    for key in [k for k, v in _pending.items() if v["created_at"] < cutoff]:
        del _pending[key]


def _client_ip(request: Request) -> str:
    # Proxy headers are trusted only when TRUST_PROXY_HEADERS is on (a trusted proxy sets
    # them); otherwise they are client-supplied and spoofable, so use the socket peer.
    # The LAST X-Forwarded-For entry is the one appended by the nearest proxy.
    if config.TRUST_PROXY_HEADERS:
        ip = (request.headers.get("cf-connecting-ip")
              or request.headers.get("x-forwarded-for", "").split(",")[-1].strip())
        if ip:
            return ip
    return request.client.host if request.client else "unknown"


def _prune(bucket: dict, key: str) -> list:
    cutoff = time.time() - ATTEMPT_WINDOW
    kept = [t for t in bucket.get(key, []) if t > cutoff]
    if kept:
        bucket[key] = kept
    else:
        bucket.pop(key, None)
    return kept


def _rate_limited(ip: str, username: str) -> bool:
    return (len(_prune(_attempts, ip)) >= MAX_LOGIN_ATTEMPTS
            or len(_prune(_user_attempts, username.lower())) >= MAX_USER_ATTEMPTS)


def _record_failure(ip: str, username: str) -> None:
    now = time.time()
    _attempts.setdefault(ip, []).append(now)
    _user_attempts.setdefault(username.lower(), []).append(now)
    for bucket in (_attempts, _user_attempts):  # bound memory against key churn
        if len(bucket) > 2000:
            for stale in [k for k in list(bucket) if not _prune(bucket, k)]:
                bucket.pop(stale, None)


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
        family_id = secrets.token_urlsafe(16)      # new token family for this login
        now = time.time()

        store.save_access_token(access_token, client.client_id, authorization_code.subject,
                                authorization_code.scopes, now + ACCESS_TOKEN_TTL, family_id)
        store.save_refresh_token(refresh_token, client.client_id, authorization_code.subject,
                                 authorization_code.scopes, family_id, now + REFRESH_TOKEN_TTL)

        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_TTL,
            scope=" ".join(authorization_code.scopes),
            refresh_token=refresh_token,
        )

    # --- refresh tokens (rotation + reuse detection) ---

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        entry = store.get_refresh_token(refresh_token)
        if entry is None or entry["client_id"] != client.client_id:
            return None
        if entry.get("used_at"):
            # already rotated — presenting it again means it leaked; burn the whole family
            store.revoke_family(entry.get("family_id"))
            return None
        expires_at = entry.get("expires_at")
        return RefreshToken(token=refresh_token, client_id=entry["client_id"], scopes=entry["scopes"],
                            subject=entry["label"], expires_at=int(expires_at) if expires_at else None)

    async def exchange_refresh_token(self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list) -> OAuthToken:
        entry = store.get_refresh_token(refresh_token.token) or {}
        family_id = entry.get("family_id") or secrets.token_urlsafe(16)
        store.mark_refresh_token_used(refresh_token.token)   # keep as reuse tripwire, don't delete

        new_access = secrets.token_urlsafe(32)
        new_refresh = secrets.token_urlsafe(32)
        now = time.time()
        use_scopes = scopes or refresh_token.scopes

        store.save_access_token(new_access, client.client_id, refresh_token.subject,
                                use_scopes, now + ACCESS_TOKEN_TTL, family_id)
        store.save_refresh_token(new_refresh, client.client_id, refresh_token.subject,
                                 use_scopes, family_id, now + REFRESH_TOKEN_TTL)

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
button {{ width:100%; padding:.7rem; background:{accent}; color:white; border:none; border-radius:6px; font-weight:600; cursor:pointer; }}
.logo {{ display:block; max-height:48px; margin:0 auto 1rem; }}
.error {{ color:#f87171; font-size:.85rem; margin-bottom:1rem; }}
.consent {{ background:#0b1220; border:1px solid #334155; border-radius:8px; padding:.7rem .8rem; margin-bottom:1.1rem; font-size:.82rem; line-height:1.5; }}
.consent .dest {{ color:#fbbf24; font-weight:600; word-break:break-all; }}
.consent .name {{ color:#e2e8f0; }}
.consent .muted {{ color:#64748b; }}
</style></head>
<body>
<form method="post" action="/login">
  {logo_html}
  <h1>Connect your {server_name} mailbox</h1>
  {consent_html}
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


def _consent_html(login_id: str) -> str:
    """Consent box for the login page. Shows the DESTINATION HOST the authorization code
    will be delivered to (from the registered redirect_uri, which the SDK validated and
    the client cannot forge) — that is the anti-phishing signal. The client_name is shown
    too but labelled self-reported, because it is attacker-controlled at registration."""
    pending = _pending.get(login_id)
    if not pending:
        return ""
    client = store.get_client(pending["client_id"]) or {}
    name = client.get("client_name") or pending["client_id"]
    dest = urlsplit(pending.get("redirect_uri", "")).netloc or "(unknown)"
    return (
        '<div class="consent">After you sign in, access to this mailbox will be sent to '
        f'<span class="dest">{html.escape(dest)}</span>.'
        f'<br><span class="muted">App name (self-reported): </span>'
        f'<span class="name">{html.escape(name)}</span>'
        '<br><span class="muted">Only continue if you recognize that destination.</span></div>'
    )


def _branding() -> tuple[str, str, str]:
    """(display_name, accent color, logo <img> html) — admin/env branding, sanitized."""
    b = store.get_branding()
    accent = b["brand_color"] if re.match(r"^#[0-9a-fA-F]{3,8}$", b["brand_color"] or "") else "#2563eb"
    logo = b["logo_url"] if (b["logo_url"] or "").startswith(("https://", "data:image/")) else ""
    logo_html = f'<img class="logo" src="{html.escape(logo)}" alt="">' if logo else ""
    return html.escape(b["display_name"]), accent, logo_html


def _render_form(login_id: str, username: str = "", error: str = "") -> str:
    display_name, accent, logo_html = _branding()
    return LOGIN_FORM.format(
        server_name=display_name,
        accent=accent,
        logo_html=logo_html,
        consent_html=_consent_html(login_id),
        error_html=f'<div class="error">{html.escape(error)}</div>' if error else "",
        login_id=html.escape(login_id),
        username=html.escape(username),
        domain=config.EMAIL_DOMAIN,
    )


_EXPIRED_LINK = "Invalid or expired link. Start the connection again from your MCP client."
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._%+-]+$")  # e-mail local-part; blocks CRLF/slash/etc.

# Security headers for the login/consent page: no framing (clickjacking of the password
# field), no referrer leak of login_id, and a CSP tight enough for this self-contained page.
_LOGIN_HEADERS = {
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
    "Cache-Control": "no-store",
}


def _valid_pending(login_id: str) -> dict | None:
    pending = _pending.get(login_id)
    if pending is None:
        return None
    if time.time() - pending["created_at"] > PENDING_TTL:  # enforce TTL at point of use
        _pending.pop(login_id, None)
        return None
    return pending


async def login_get(request: Request) -> HTMLResponse:
    login_id = request.query_params.get("login_id", "")
    if _valid_pending(login_id) is None:
        return HTMLResponse(_EXPIRED_LINK, status_code=400)
    return HTMLResponse(_render_form(login_id), headers=_LOGIN_HEADERS)


async def login_post(request: Request):
    form = await request.form()
    login_id = form.get("login_id", "")
    username = (form.get("username") or "").strip()
    password = form.get("password") or ""

    pending = _valid_pending(login_id)
    if pending is None:
        return HTMLResponse(_EXPIRED_LINK, status_code=400)

    ip = _client_ip(request)
    if _rate_limited(ip, username):
        return HTMLResponse("Too many login attempts. Wait 10 minutes and try again.", status_code=429)

    if not _USERNAME_RE.match(username):
        _record_failure(ip, username)
        return HTMLResponse(_render_form(login_id, "", "Invalid username or password."),
                            status_code=401, headers=_LOGIN_HEADERS)

    email = f"{username}@{config.EMAIL_DOMAIN}"

    ok = imap_ops.verify_login(config.IMAP_HOST, config.IMAP_PORT, email, password)
    if not ok:
        _record_failure(ip, username)
        return HTMLResponse(_render_form(login_id, username, "Invalid username or password."),
                            status_code=401, headers=_LOGIN_HEADERS)

    _attempts.pop(ip, None)
    _user_attempts.pop(username.lower(), None)

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
