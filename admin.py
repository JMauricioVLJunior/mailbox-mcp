"""Admin console: branding, semantics editor, status, and OAuth session management.

Enabled only when MCP_ADMIN_EMAIL is set (routes are not registered otherwise). The admin
signs in with that mailbox's own IMAP password — the same identity proof as regular users —
and gets a short-lived, server-side browser session (HttpOnly/Secure/SameSite cookie).
Config-changing POSTs require a per-session CSRF token. The console never edits credential
infrastructure (IMAP/SMTP hosts, keys) — only runtime-safe things.
"""

import html
import re
import secrets
import time

import yaml
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

import config
import imap_ops
import oauth_provider as op   # reuse client-IP resolution + the login rate limiter
import semantics
import store

ADMIN_SESSION_TTL = 8 * 3600
COOKIE = "admin_session"

_sessions: dict[str, dict] = {}   # token -> {"email", "csrf", "expires_at"}

_HEADERS = {
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": ("default-src 'none'; img-src https: data:; style-src "
                                "'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"),
    "Cache-Control": "no-store",
}

_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{3,8}$")


def enabled() -> bool:
    return bool(config.ADMIN_EMAIL)


# ---------- sessions ----------

def _prune() -> None:
    now = time.time()
    for t in [t for t, s in _sessions.items() if s["expires_at"] < now]:
        del _sessions[t]


def _session(request: Request):
    _prune()
    s = _sessions.get(request.cookies.get(COOKIE, ""))
    return s if s and s["expires_at"] > time.time() else None


def _with_headers(resp: Response) -> Response:
    for k, v in _HEADERS.items():
        resp.headers[k] = v
    return resp


def _redirect(url: str) -> Response:
    return _with_headers(RedirectResponse(url=url, status_code=302))


# ---------- validation / sanitizing ----------

def _safe_logo(url: str) -> str:
    url = (url or "").strip()
    return url if url.startswith(("https://", "data:image/")) else ""


def _safe_color(color: str) -> str:
    color = (color or "").strip()
    return color if _COLOR_RE.match(color) else config.BRAND_COLOR


# ---------- rendering ----------

def _login_page(error: str = "") -> str:
    b = store.get_branding()
    accent = _safe_color(b["brand_color"])
    logo = f'<img src="{html.escape(_safe_logo(b["logo_url"]))}" alt="" style="max-height:52px;margin-bottom:1rem">' if b["logo_url"] else ""
    err = f'<div style="color:#f87171;font-size:.85rem;margin-bottom:1rem">{html.escape(error)}</div>' if error else ""
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>{html.escape(b["display_name"])} — Admin</title><style>
body{{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}
form{{background:#1e293b;padding:2rem;border-radius:12px;width:320px;text-align:center}}
h1{{font-size:1rem;margin:0 0 1.2rem}}
input{{width:100%;padding:.6rem;margin:.3rem 0;border-radius:6px;border:1px solid #334155;background:#0f172a;color:#e2e8f0;box-sizing:border-box}}
button{{width:100%;padding:.7rem;background:{accent};color:#fff;border:none;border-radius:6px;font-weight:600;cursor:pointer;margin-top:.6rem}}
.s{{color:#94a3b8;font-size:.8rem}}</style></head><body>
<form method="post" action="/admin/login">{logo}<h1>Admin sign in</h1>{err}
<input name="username" placeholder="username" required autofocus autocomplete="username">
<div class="s">@{html.escape(config.EMAIL_DOMAIN)}</div>
<input type="password" name="password" placeholder="mailbox password" required autocomplete="current-password">
<button type="submit">Sign in</button></form></body></html>"""


def _field(label: str, name: str, value: str, kind: str = "text") -> str:
    return (f'<label style="display:block;margin:.8rem 0 .2rem;color:#94a3b8;font-size:.85rem">{html.escape(label)}</label>'
            f'<input type="{kind}" name="{name}" value="{html.escape(value)}" '
            'style="width:100%;padding:.55rem;border-radius:6px;border:1px solid #334155;background:#0f172a;color:#e2e8f0;box-sizing:border-box">')


def _current_semantics_text() -> str:
    stored = store.get_settings().get("semantics_yaml")
    if stored:
        return stored
    if config.SEMANTICS_FILE:
        try:
            with open(config.SEMANTICS_FILE, "r", encoding="utf-8") as fh:
                return fh.read()
        except OSError:
            pass
    return "# business_context: >\n#   Whose mailbox this is and the business around it.\n# tags:\n#   Urgent: genuine urgency\n"


def _console_page(csrf: str, saved: str = "", error: str = "", warn: str = "") -> str:
    b = store.get_branding()
    accent = _safe_color(b["brand_color"])
    st = store.stats()
    status = STATUS
    banner = ""
    if saved:
        banner = f'<div style="background:#064e3b;color:#a7f3d0;padding:.6rem .8rem;border-radius:6px;margin-bottom:1rem">Saved: {html.escape(saved)}</div>'
    if warn:
        banner += f'<div style="background:#78350f;color:#fde68a;padding:.6rem .8rem;border-radius:6px;margin-bottom:1rem">Warnings: {html.escape(warn)}</div>'
    if error:
        banner += f'<div style="background:#7f1d1d;color:#fecaca;padding:.6rem .8rem;border-radius:6px;margin-bottom:1rem">{html.escape(error)}</div>'

    brand = store.get_settings().get("branding", {})
    branding_form = f"""<form method="post" action="/admin/branding">
<input type="hidden" name="csrf" value="{csrf}">
{_field("Display name (blank = default)", "display_name", brand.get("display_name",""))}
{_field("Logo URL (https:// or data:image/…)", "logo_url", brand.get("logo_url",""))}
<label style="display:block;margin:.8rem 0 .2rem;color:#94a3b8;font-size:.85rem">Accent color</label>
<input type="color" name="brand_color" value="{html.escape(_safe_color(brand.get('brand_color') or accent))}" style="width:64px;height:34px;background:none;border:1px solid #334155;border-radius:6px">
{_field("Service / support URL", "service_url", brand.get("service_url",""))}
<button type="submit" style="margin-top:1rem;padding:.6rem 1.2rem;background:{accent};color:#fff;border:none;border-radius:6px;font-weight:600;cursor:pointer">Save branding</button></form>"""

    sem = html.escape(_current_semantics_text())
    semantics_form = f"""<form method="post" action="/admin/semantics">
<input type="hidden" name="csrf" value="{csrf}">
<p style="color:#94a3b8;font-size:.85rem">YAML describing what your folders/tags mean (agents read this via mailbox_guide). Validated on save.</p>
<textarea name="semantics_yaml" rows="14" spellcheck="false" style="width:100%;font-family:ui-monospace,monospace;font-size:.82rem;padding:.6rem;border-radius:6px;border:1px solid #334155;background:#0f172a;color:#e2e8f0;box-sizing:border-box">{sem}</textarea>
<button type="submit" style="margin-top:.6rem;padding:.6rem 1.2rem;background:{accent};color:#fff;border:none;border-radius:6px;font-weight:600;cursor:pointer">Save semantics</button></form>"""

    status_rows = "".join(
        f'<tr><td style="padding:.3rem .8rem .3rem 0;color:#94a3b8">{html.escape(k)}</td>'
        f'<td style="padding:.3rem 0">{html.escape(str(v))}</td></tr>'
        for k, v in (("IMAP", status.get("imap", "?")), ("SMTP / sending", status.get("smtp", "?")),
                      ("Calendar", status.get("calendar", "?")), ("Connected accounts", st["accounts"]),
                      ("Registered clients", st["clients"]), ("Active access tokens", st["access_tokens"]),
                      ("Active refresh tokens", st["refresh_tokens"])))
    status_table = f'<table style="font-size:.9rem">{status_rows}</table>'

    sessions = store.list_sessions()
    if sessions:
        rows = "".join(
            f'<tr><td style="padding:.3rem .8rem .3rem 0">{html.escape(s["subject"])}</td>'
            f'<td style="padding:.3rem .8rem;color:#94a3b8">{s["access"]}a / {s["refresh"]}r</td>'
            f'<td style="padding:.3rem 0"><form method="post" action="/admin/revoke" style="margin:0">'
            f'<input type="hidden" name="csrf" value="{csrf}">'
            f'<input type="hidden" name="subject" value="{html.escape(s["subject"])}">'
            f'<button type="submit" style="padding:.3rem .7rem;background:#b91c1c;color:#fff;border:none;border-radius:5px;cursor:pointer;font-size:.8rem">Revoke</button>'
            f'</form></td></tr>' for s in sessions)
        sessions_table = f'<table style="font-size:.9rem">{rows}</table>'
    else:
        sessions_table = '<p style="color:#94a3b8;font-size:.85rem">No active sessions.</p>'

    def card(title, body):
        return (f'<section style="background:#1e293b;padding:1.2rem 1.4rem;border-radius:12px;margin-bottom:1.2rem">'
                f'<h2 style="font-size:1rem;margin:0 0 .6rem">{html.escape(title)}</h2>{body}</section>')

    logo = f'<img src="{html.escape(_safe_logo(b["logo_url"]))}" alt="" style="max-height:40px;vertical-align:middle;margin-right:.6rem">' if b["logo_url"] else ""
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(b["display_name"])} — Admin</title><style>
body{{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:2rem}}
.wrap{{max-width:720px;margin:0 auto}}
header{{display:flex;align-items:center;justify-content:space-between;margin-bottom:1.4rem}}
table{{border-collapse:collapse}} a{{color:{accent}}}</style></head><body><div class="wrap">
<header><div>{logo}<b>{html.escape(b["display_name"])}</b> <span style="color:#64748b">admin</span></div>
<form method="post" action="/admin/logout" style="margin:0"><input type="hidden" name="csrf" value="{csrf}">
<button type="submit" style="padding:.4rem .9rem;background:#334155;color:#e2e8f0;border:none;border-radius:6px;cursor:pointer">Sign out</button></form></header>
{banner}
{card("Branding", branding_form)}
{card("Mailbox semantics (semantics.yml)", semantics_form)}
{card("Status", status_table)}
{card("Active sessions", sessions_table)}
</div></body></html>"""


# ---------- status wiring (set by server at startup) ----------

STATUS: dict = {}


def set_status(d: dict) -> None:
    STATUS.update(d)


# ---------- routes ----------

async def login_get(request: Request) -> Response:
    if not enabled():
        return HTMLResponse("Not found", status_code=404)
    if _session(request):
        return _redirect("/admin")
    return _with_headers(HTMLResponse(_login_page()))


async def login_post(request: Request) -> Response:
    if not enabled():
        return HTMLResponse("Not found", status_code=404)
    form = await request.form()
    username = (form.get("username") or "").strip()
    password = form.get("password") or ""
    ip = op._client_ip(request)
    if op._rate_limited(ip, username):
        return _with_headers(HTMLResponse(_login_page("Too many attempts. Wait 10 minutes."), status_code=429))

    email = f"{username}@{config.EMAIL_DOMAIN}".lower()
    # check admin identity BEFORE touching IMAP, so this endpoint is not a login oracle
    if email != config.ADMIN_EMAIL or not op._USERNAME_RE.match(username) \
            or not imap_ops.verify_login(config.IMAP_HOST, config.IMAP_PORT, email, password):
        op._record_failure(ip, username)
        return _with_headers(HTMLResponse(_login_page("Invalid credentials or not the admin account."), status_code=401))

    op._attempts.pop(ip, None)
    op._user_attempts.pop(username.lower(), None)
    token = secrets.token_urlsafe(32)
    _sessions[token] = {"email": email, "csrf": secrets.token_urlsafe(24),
                        "expires_at": time.time() + ADMIN_SESSION_TTL}
    resp = _redirect("/admin")
    resp.set_cookie(COOKIE, token, max_age=ADMIN_SESSION_TTL, httponly=True,
                    secure=True, samesite="strict", path="/")
    return resp


async def home(request: Request) -> Response:
    if not enabled():
        return HTMLResponse("Not found", status_code=404)
    s = _session(request)
    if not s:
        return _redirect("/admin/login")
    return _with_headers(HTMLResponse(_console_page(s["csrf"], request.query_params.get("saved", ""))))


def _guard(request: Request, form) -> dict | None:
    """Return the session if authed AND CSRF matches, else None."""
    s = _session(request)
    if not s or not secrets.compare_digest(form.get("csrf", ""), s["csrf"]):
        return None
    return s


async def save_branding(request: Request) -> Response:
    if not enabled():
        return HTMLResponse("Not found", status_code=404)
    form = await request.form()
    s = _guard(request, form)
    if not s:
        return _redirect("/admin/login")
    settings = store.get_settings()
    settings["branding"] = {
        "display_name": (form.get("display_name") or "").strip(),
        "logo_url": _safe_logo(form.get("logo_url")),
        "brand_color": _safe_color(form.get("brand_color")),
        "service_url": (form.get("service_url") or "").strip() if (form.get("service_url") or "").startswith(("https://", "http://")) else "",
    }
    store.save_settings(settings)
    return _redirect("/admin?saved=branding")


async def save_semantics(request: Request) -> Response:
    if not enabled():
        return HTMLResponse("Not found", status_code=404)
    form = await request.form()
    s = _guard(request, form)
    if not s:
        return _redirect("/admin/login")
    raw = form.get("semantics_yaml") or ""
    try:
        parsed = yaml.safe_load(raw)
        if parsed is not None and not isinstance(parsed, dict):
            raise ValueError("top level must be a mapping (key: value)")
    except Exception as exc:
        return _with_headers(HTMLResponse(_console_page(s["csrf"], error=f"YAML error: {exc}"), status_code=400))
    settings = store.get_settings()
    settings["semantics_yaml"] = raw
    store.save_settings(settings)
    semantics.invalidate()
    warnings = semantics.validate_semantics(parsed or {})
    if warnings:  # non-fatal — saved, but flag likely mistakes (unknown keys, wrong types)
        return _with_headers(HTMLResponse(_console_page(s["csrf"], saved="semantics", warn="; ".join(warnings))))
    return _redirect("/admin?saved=semantics")


async def revoke(request: Request) -> Response:
    if not enabled():
        return HTMLResponse("Not found", status_code=404)
    form = await request.form()
    s = _guard(request, form)
    if not s:
        return _redirect("/admin/login")
    subject = (form.get("subject") or "").strip()
    if subject:
        store.revoke_subject(subject)
    return _redirect("/admin?saved=session revoked")


async def logout(request: Request) -> Response:
    tok = request.cookies.get(COOKIE, "")
    _sessions.pop(tok, None)
    resp = _redirect("/admin/login")
    resp.delete_cookie(COOKIE, path="/")
    return resp
