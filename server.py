"""Mailbox MCP — IMAP + SMTP + CalDAV server for AI agents (MCP streamable-http).

Multi-user: each user authenticates with their own mailbox password via the built-in
OAuth flow; every tool call is resolved to that user's account. See README.md.
"""

import datetime as dt
import os
import socket

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.responses import JSONResponse
from starlette.routing import Route

import caldav_ops
import config
import imap_ops
import oauth_provider
import semantics
import smtp_ops
import store
from oauth_provider import login_get, login_post

_HAS_CALENDAR = bool(config.CALDAV_URL_TEMPLATE)

mcp = FastMCP(
    name=config.SERVER_NAME,
    instructions=(
        ("E-mail (IMAP/SMTP) and calendar (CalDAV) tools" if _HAS_CALENDAR
         else "E-mail (IMAP/SMTP) tools")
        + " for the authenticated account. "
        "START by calling mailbox_guide() to learn this mailbox's semantics (folders, tags, business context). "
        + ("Day overview: daily_brief() returns unread + agenda + threads awaiting reply in one call. "
           if _HAS_CALENDAR
           else "Day overview: daily_brief() returns unread + threads awaiting reply in one call. ")
        + "Unread: unread_summary (counts) or list_unread (messages). "
        "Pending: list_pending_replies - prioritize items with automated=false (humans waiting). "
        "Batch actions: tag/move/delete/mark accept a list of uids at once. "
        "delete_emails moves to Trash (reversible). send_email/reply_email really send - "
        "confirm with the user first; when in doubt prefer create_draft (saves a draft, does not send)."
    ),
    auth_server_provider=oauth_provider.MailOAuthProvider(),
    auth=AuthSettings(
        issuer_url=config.PUBLIC_URL,
        resource_server_url=config.PUBLIC_URL,
        client_registration_options=ClientRegistrationOptions(
            enabled=True, valid_scopes=["mail", "calendar"], default_scopes=["mail", "calendar"],
        ),
        revocation_options=RevocationOptions(enabled=True),
    ),
    host=config.BIND_HOST,
    port=config.BIND_PORT,
    transport_security=TransportSecuritySettings(
        allowed_hosts=[config.PUBLIC_HOST, f"{config.BIND_HOST}:{config.BIND_PORT}",
                        f"localhost:{config.BIND_PORT}"],
        allowed_origins=[config.PUBLIC_URL],
    ),
)


def _current_account() -> dict:
    access_token = get_access_token()
    if access_token is None or access_token.subject is None:
        raise PermissionError("invalid or missing token")
    account = store.get_account(access_token.subject)
    if account is None:
        raise PermissionError("token does not match any account")
    return account


def _imap() -> dict:
    return _current_account()["imap"]


def _caldav() -> dict:
    cd = _current_account().get("caldav")
    if not cd:
        raise ValueError("this deployment has no CalDAV configured")
    return cd


# ==================== E-MAIL: queries ====================

@mcp.tool(title="Unread summary (all folders)")
def unread_summary() -> list:
    """Unread counts for ALL folders in ONE call (only folders with >0).
    Use this first for 'any new mail?' - it is the fastest check."""
    return imap_ops.unread_summary(_imap())


@mcp.tool(title="List unread emails")
def list_unread(limit_per_folder: int = 10, snippet_len: int = 0) -> list:
    """Unread messages across all folders at once (only visits folders that have unread).
    snippet_len > 0 includes a body excerpt for each."""
    return imap_ops.list_unread(_imap(), limit_per_folder, snippet_len)


@mcp.tool(title="Mailbox statistics (total/unread per folder)")
def mailbox_stats() -> list:
    """Total and unread message counts per folder, in one call. Mailbox overview."""
    return imap_ops.mailbox_stats(_imap())


@mcp.tool(title="List mailbox folders")
def list_folders() -> list:
    """Names of all folders in the mailbox (dot-separated hierarchy, e.g. INBOX.Clients.Acme)."""
    return imap_ops.list_folders(_imap())


@mcp.tool(title="List emails in a folder (with filters)")
def list_emails(folder: str, unread: bool = False, from_contains: str = None,
                 to_contains: str = None, subject_contains: str = None, tag: str = None,
                 since: str = None, before: str = None, limit: int = 50,
                 snippet_len: int = 0) -> list:
    """List/filter e-mails from ONE folder. Dates in ISO (YYYY-MM-DD). snippet_len > 0 adds a body excerpt."""
    return imap_ops.list_emails(_imap(), folder, unread, from_contains, to_contains,
                                 subject_contains, tag, since, before, limit, snippet_len)


@mcp.tool(title="Search emails (text/tag/date, all folders)")
def search_emails(query: str = None, field: str = "any", tag: str = None,
                   since: str = None, before: str = None, folders: list = None,
                   limit_per_folder: int = 50, preview: bool = False) -> list:
    """Search ALL folders (or the given ones) by text (field: any/subject/from/body),
    IMAP keyword (tag) and/or date range. preview=true includes a body excerpt."""
    return imap_ops.search_emails(_imap(), query, field, tag, since, before, folders,
                                   limit_per_folder, preview)


@mcp.tool(title="Read full email")
def read_email(folder: str, uid: str, max_chars: int = 5000) -> dict:
    """Full e-mail (body truncated at max_chars; body_truncated tells if it was cut)."""
    return imap_ops.read_email(_imap(), folder, uid, max_chars)


@mcp.tool(title="View full conversation (thread)")
def get_thread(folder: str, uid: str, max_messages: int = 30, all_folders: bool = False) -> list:
    """Rebuild the conversation of an e-mail: messages sharing the base subject in the
    original folder + Sent + INBOX (all_folders=true scans everything), sorted by date."""
    return imap_ops.get_thread(_imap(), folder, uid, max_messages, all_folders)


@mcp.tool(title="Read attachment (PDF/Word/Excel/text)")
def get_attachment(folder: str, uid: str, filename: str, max_chars: int = 20000) -> dict:
    """Read attachment CONTENT: PDF (text per page), Word .docx, Excel .xlsx (all sheets),
    and text formats (csv/json/xml/html/ics/txt...). Images/zip unsupported.
    Attachment names come from read_email."""
    return imap_ops.get_attachment(_imap(), folder, uid, filename, max_chars)


# ==================== E-MAIL: intelligence ====================

@mcp.tool(title="Mailbox semantic guide (read first)")
def mailbox_guide() -> dict:
    """READ FIRST when working with this mailbox: what each folder means, the tag taxonomy,
    business context and usage conventions for this deployment."""
    imap = _imap()
    special = imap_ops.special_folders(imap)
    folders = [{"name": f, "meaning": semantics.folder_meaning(f, special)}
               for f in imap_ops.list_folders(imap)]
    return {
        "business_context": semantics.business_context(),
        "folders": folders,
        "special_folders": special,
        "tags": semantics.tags(),
        "conventions": semantics.conventions(),
    }


@mcp.tool(title="Threads awaiting reply")
def list_pending_replies(days_back: int = 14, limit: int = 30, folders: list = None) -> list:
    """Threads AWAITING REPLY: conversations whose last message is from the other party,
    with no reply from us afterwards. Humans first (automated=false), oldest first.
    waiting_days = how long it has been stalled. folders restricts the scan (default:
    all except Trash/Drafts/Junk) - use it on large mailboxes for faster answers."""
    return imap_ops.pending_replies(_imap(), days_back, folders, limit)


@mcp.tool(title="Contact history")
def get_contact_history(email: str, days_back: int = 365, limit: int = 20) -> dict:
    """Complete history with a person/address: received and sent counts,
    first and last contact, and the most recent messages both ways."""
    return imap_ops.contact_history(_imap(), email, days_back, limit)


@mcp.tool(title="Morning brief (unread + agenda + pending)")
def daily_brief(days_back: int = 14) -> dict:
    """MORNING REPORT in one call: unread per folder, today's and tomorrow's events,
    and threads awaiting reply. Ideal for a scheduled daily summary."""
    account = _current_account()
    imap = account["imap"]
    today = dt.datetime.now(caldav_ops.TZ).date()

    brief = {
        "date": today.isoformat(),
        "unread": imap_ops.unread_summary(imap),
        "pending_replies": imap_ops.pending_replies(imap, days_back, None, 15),
    }
    if account.get("caldav"):
        try:
            events = caldav_ops.list_events(account["caldav"], days=2)
            brief["events_today"] = [e for e in events if (e["start"] or "").startswith(today.isoformat())]
            brief["events_tomorrow"] = [e for e in events
                                          if (e["start"] or "").startswith((today + dt.timedelta(days=1)).isoformat())]
        except Exception as exc:
            brief["calendar_error"] = str(exc)
    return brief


# ==================== E-MAIL: actions ====================

@mcp.tool(title="SEND new email (real action)")
def send_email(to: str, subject: str, body: str, cc: str = None, bcc: str = None,
               display_name: str = None) -> dict:
    """REALLY SENDS an e-mail (SMTP) and saves a copy to Sent.
    Multiple recipients comma-separated. Confirm with the user before sending."""
    return smtp_ops.send_email(_imap(), to, subject, body, cc, bcc, display_name)


@mcp.tool(title="REPLY to email (real action, keeps thread)")
def reply_email(folder: str, uid: str, body: str, reply_all: bool = False,
                display_name: str = None) -> dict:
    """REPLIES to an e-mail keeping the thread (In-Reply-To/References) and saves to Sent.
    reply_all=true CCs the other recipients. Confirm with the user before sending."""
    return smtp_ops.reply_email(_imap(), folder, uid, body, reply_all, display_name)


@mcp.tool(title="Create draft (does not send)")
def create_draft(to: str, subject: str, body: str, cc: str = None,
                  display_name: str = None) -> dict:
    """Saves a DRAFT to the Drafts folder (sends NOTHING). Safe alternative to send_email:
    the user reviews and sends from their own mail client."""
    return smtp_ops.create_draft(_imap(), to, subject, body, cc, display_name)


@mcp.tool(title="Tag emails (batch)")
def tag_emails(folder: str, uids: list, keyword: str, remove: bool = False) -> str:
    """Apply (or remove) an IMAP keyword on SEVERAL e-mails at once. uids is a list."""
    n = imap_ops.tag_emails(_imap(), folder, uids, keyword, remove)
    return f"{n} e-mail(s) updated"


@mcp.tool(title="Move emails (batch)")
def move_emails(folder: str, uids: list, destination: str) -> str:
    """Move SEVERAL e-mails between folders at once. uids is a list."""
    n = imap_ops.move_emails(_imap(), folder, uids, destination)
    return f"{n} e-mail(s) moved to {destination}"


@mcp.tool(title="Delete emails → Trash (reversible)")
def delete_emails(folder: str, uids: list) -> str:
    """Move SEVERAL e-mails to Trash - reversible, never permanently deletes."""
    n = imap_ops.delete_emails(_imap(), folder, uids)
    return f"{n} e-mail(s) moved to Trash"


@mcp.tool(title="Mark read/unread (batch)")
def mark_read(folder: str, uids: list, read: bool = True) -> str:
    """Mark SEVERAL e-mails as read (read=true) or unread (read=false)."""
    n = imap_ops.mark_read(_imap(), folder, uids, read)
    return f"{n} e-mail(s) marked"


@mcp.tool(title="Create new folder")
def create_folder(name: str) -> str:
    """Create a new folder. Use dot hierarchy, e.g. INBOX.Clients.NewClient."""
    return imap_ops.create_folder(_imap(), name)


# ==================== CALENDAR (CalDAV) ====================
# Only registered when CalDAV is configured — agents never see tools that cannot work.

if config.CALDAV_URL_TEMPLATE:

    @mcp.tool(title="List calendars")
    def list_calendars() -> list:
        """CalDAV calendars for the authenticated account."""
        return caldav_ops.list_calendars(_caldav())

    @mcp.tool(title="List calendar events")
    def list_events(calendar_name: str = None, start_date: str = None, days: int = 14) -> list:
        """Events from start_date (ISO; default today) for `days` days, sorted by start."""
        return caldav_ops.list_events(_caldav(), calendar_name, start_date, days)

    @mcp.tool(title="Create calendar event (real action)")
    def create_event(calendar_name: str, summary: str, start: str, end: str,
                      location: str = "", description: str = "") -> dict:
        """Create an event. start/end in ISO (e.g. 2026-08-01T14:00:00), interpreted in the
        configured timezone. Confirm with the user first."""
        return caldav_ops.create_event(_caldav(), calendar_name, summary, start, end, location, description)

    @mcp.tool(title="Delete calendar event (real action)")
    def delete_event(calendar_name: str, uid: str) -> str:
        """Delete an event by uid (from list_events). Confirm with the user first."""
        return caldav_ops.delete_event(_caldav(), calendar_name, uid)


async def _health(request):
    return JSONResponse({"status": "ok"})


def _check_tls(host: str, port: int, what: str, problems: list) -> None:
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with config.ssl_context().wrap_socket(sock, server_hostname=host):
                pass
    except Exception as exc:
        problems.append(f"cannot establish TLS with {what} {host}:{port} - {exc}")


def preflight() -> bool:
    """Validate configuration and provider connectivity BEFORE serving, so the MCP
    never exposes tools that cannot work. IMAP is required (failure aborts). SMTP is
    optional: if its outbound port is blocked/unreachable the server still runs for
    reading and drafts, and the sending tools are withheld. Returns whether SMTP is up."""
    problems: list = []
    _check_tls(config.IMAP_HOST, config.IMAP_PORT, "IMAP", problems)  # required

    if not config.PUBLIC_URL.startswith("https://"):
        print(f"[preflight] warning: MCP_PUBLIC_URL is not https ({config.PUBLIC_URL}) - "
              "OAuth clients such as claude.ai require https")
    if config.SEMANTICS_FILE and not os.path.exists(config.SEMANTICS_FILE):
        print(f"[preflight] warning: semantics file not found ({config.SEMANTICS_FILE}) - "
              "agents will get neutral defaults")

    if problems:
        for p in problems:
            print(f"[preflight] ERROR: {p}")
        raise SystemExit("[preflight] fix the configuration above and restart "
                         "(MCP_TLS_VERIFY=false only if your mail server uses a self-signed certificate)")

    smtp_ok, smtp_detail = smtp_ops.smtp_reachable()  # optional — degrade, don't abort
    if not smtp_ok:
        print(f"[preflight] warning: SMTP unreachable ({smtp_detail}). Sending is DISABLED; "
              "create_draft still works (it uses IMAP). If your host blocks outbound 465, "
              "try MCP_SMTP_PORT=587 (STARTTLS), or ask the host to unblock the port.")

    print(f"[preflight] ok - imap={config.IMAP_HOST}:{config.IMAP_PORT} "
          f"smtp={smtp_detail if smtp_ok else 'DISABLED'} "
          f"calendar={'on' if _HAS_CALENDAR else 'off'} "
          f"tls_verify={'on' if config.TLS_VERIFY else 'OFF (insecure)'}")
    return smtp_ok


def build_app():
    smtp_ok = preflight()
    if not smtp_ok:  # withhold tools that cannot work; create_draft (IMAP) stays available
        mcp.remove_tool("send_email")
        mcp.remove_tool("reply_email")
    app = mcp.streamable_http_app()
    app.router.routes.insert(0, Route("/login", login_get, methods=["GET"]))
    app.router.routes.insert(0, Route("/login", login_post, methods=["POST"]))
    app.router.routes.insert(0, Route("/health", _health, methods=["GET"]))
    return app


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(build_app(), host=config.BIND_HOST, port=config.BIND_PORT)
