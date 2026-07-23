"""Central configuration, loaded from environment variables (.env supported).

Required:
  MCP_PUBLIC_URL        public https URL of this server (ex: https://mcp-mail.example.com)
  MCP_EMAIL_DOMAIN      e-mail domain users authenticate with (ex: example.com)
  MCP_IMAP_HOST         IMAP server hostname

Optional (defaults shown):
  MCP_IMAP_PORT=993
  MCP_SMTP_HOST=<same as IMAP_HOST>
  MCP_SMTP_PORT=465                 (SSL direct)
  MCP_CALDAV_URL_TEMPLATE=          CalDAV base URL with {email} placeholder; empty disables calendar
  MCP_TIMEZONE=UTC                  IANA name, ex: America/Sao_Paulo
  MCP_SENT_FOLDER=                  empty = autodetect (RFC 6154 SPECIAL-USE, then common names)
  MCP_TRASH_FOLDER=
  MCP_DRAFTS_FOLDER=
  MCP_SEMANTICS_FILE=               path to semantics.yml (mailbox meaning for AI agents)
  MCP_SERVER_NAME=Mailbox MCP
  MCP_BIND_HOST=127.0.0.1
  MCP_BIND_PORT=8787
  MCP_DATA_DIR=<src>/data           encrypted credential store location
  MCP_TLS_VERIFY=true               verify IMAP/SMTP TLS certificates; set false ONLY for
                                    servers with self-signed certificates (insecure)
  MCP_TRUST_PROXY_HEADERS=true      trust CF-Connecting-IP / X-Forwarded-For for login
                                    rate-limiting; set false if the port is exposed directly
                                    (no reverse proxy in front)
"""

import os
import ssl
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def _get(name: str, default: str = None, required: bool = False) -> str:
    value = os.environ.get(name, default)
    if required and not value:
        raise SystemExit(f"missing required environment variable: {name}")
    return value


def _get_bool(name: str, default: str) -> bool:
    return _get(name, default).strip().lower() not in ("0", "false", "no", "off")


PUBLIC_URL = _get("MCP_PUBLIC_URL", required=True).rstrip("/")
PUBLIC_HOST = PUBLIC_URL.split("://", 1)[-1]
SERVER_NAME = _get("MCP_SERVER_NAME", "Mailbox MCP")

EMAIL_DOMAIN = _get("MCP_EMAIL_DOMAIN", required=True)
IMAP_HOST = _get("MCP_IMAP_HOST", required=True)
IMAP_PORT = int(_get("MCP_IMAP_PORT", "993"))
SMTP_HOST = _get("MCP_SMTP_HOST", IMAP_HOST)
SMTP_PORT = int(_get("MCP_SMTP_PORT", "465"))

CALDAV_URL_TEMPLATE = _get("MCP_CALDAV_URL_TEMPLATE", "")
if CALDAV_URL_TEMPLATE and "{email}" not in CALDAV_URL_TEMPLATE:
    raise SystemExit("MCP_CALDAV_URL_TEMPLATE must contain the {email} placeholder "
                     "(ex: https://cal.example.com/calendars/{email}/Personal/)")

TIMEZONE = _get("MCP_TIMEZONE", "UTC")
try:
    from zoneinfo import ZoneInfo as _ZoneInfo
    _ZoneInfo(TIMEZONE)
except Exception:
    raise SystemExit(f"invalid MCP_TIMEZONE '{TIMEZONE}' (use an IANA name, ex: America/Sao_Paulo; "
                     "on systems without a tz database, run: pip install tzdata)")

SENT_FOLDER = _get("MCP_SENT_FOLDER", "")
TRASH_FOLDER = _get("MCP_TRASH_FOLDER", "")
DRAFTS_FOLDER = _get("MCP_DRAFTS_FOLDER", "")

SEMANTICS_FILE = _get("MCP_SEMANTICS_FILE", "")

BIND_HOST = _get("MCP_BIND_HOST", "127.0.0.1")
BIND_PORT = int(_get("MCP_BIND_PORT", "8787"))
DATA_DIR = Path(_get("MCP_DATA_DIR", str(Path(__file__).parent / "data")))

TLS_VERIFY = _get_bool("MCP_TLS_VERIFY", "true")
TRUST_PROXY_HEADERS = _get_bool("MCP_TRUST_PROXY_HEADERS", "true")


def ssl_context() -> ssl.SSLContext:
    """TLS context for IMAP/SMTP. Python's smtplib/imaplib do NOT verify certificates
    unless an explicit context is passed (cpython #91826) — so we always pass this one."""
    ctx = ssl.create_default_context()
    if not TLS_VERIFY:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx
