# Mailbox MCP — IMAP + SMTP + CalDAV for AI agents

A self-hosted [MCP](https://modelcontextprotocol.io) server that gives Claude (claude.ai,
Claude Code, mobile app) full access to any standard **IMAP mailbox** and **CalDAV calendar** —
with a multi-user OAuth flow where **the mailbox password itself is the login**. No user
database, no API keys to copy around: each teammate connects by signing in with their own
e-mail credentials.

Built for the thousands of mailboxes that are *not* Gmail or Microsoft 365 — classic hosting
providers, cPanel, Dovecot, mailbox.org, self-hosted stacks — which have no first-party
AI connector.

## Highlights

- **25 tools**: queries, cross-folder search, threads, attachments, batch actions, sending,
  drafts, calendar, and mailbox intelligence
- **Multi-user OAuth 2.1** with Dynamic Client Registration (RFC 7591) + PKCE — claude.ai
  connects with just a URL; a built-in login page validates credentials against your IMAP
  server (a successful login *is* the identity proof)
- **Semantics layer** (`mailbox_guide` tool + `semantics.yml`): teach agents what your
  folders and tags *mean* and the business context around them — every conversation starts
  already knowing your world
- **Intelligence tools**: `daily_brief` (unread + agenda + pending in one call),
  `list_pending_replies` (threads stalled waiting on you, humans prioritized over
  newsletters/robots), `get_contact_history`
- **Attachment reading**: PDF (text per page), Word `.docx`, Excel `.xlsx` (all sheets),
  CSV/JSON/XML/HTML/ICS/plain text
- **Fast**: per-account IMAP connection pool with automatic reconnection, and all-folder
  unread counts in a single round-trip (`LIST ... RETURN (STATUS ...)` when the server
  supports it, graceful fallback otherwise)
- **Safe by design**: credentials encrypted at rest (Fernet), login rate-limiting,
  deletes go to Trash (reversible), send/delete tools labelled "(real action)" and agents
  are instructed to confirm with the user first — or to prefer `create_draft`, which
  saves a draft for the human to review and send
- **Special folders autodetected** (RFC 6154 SPECIAL-USE, then common names, or explicit config)

## Quickstart

```bash
git clone https://github.com/JMauricioVLJunior/mailbox-mcp.git && cd mailbox-mcp
cp .env.example .env            # fill in: public URL, e-mail domain, IMAP host
cp semantics.example.yml semantics.yml   # optional but recommended: describe YOUR mailbox

# option A — docker
docker compose up -d

# option B — bare python 3.11+
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python server.py                # serves 127.0.0.1:8787
```

Expose the port through any HTTPS front (Cloudflare Tunnel, Caddy, nginx + certbot).
The server must be reachable at exactly `MCP_PUBLIC_URL`.

**Connect from claude.ai**: Settings → Connectors → *Add custom connector* →
URL `https://your-host/mcp` (leave OAuth fields empty) → sign in with your mailbox
username + password on the page that opens. Done.

**Connect from Claude Code**:

```bash
claude mcp add --transport http mailbox https://your-host/mcp
```

## Configuration

Everything via environment variables (`.env` supported) — see [`config.py`](config.py)
for the full reference. Minimum:

| Variable | Example |
|---|---|
| `MCP_PUBLIC_URL` | `https://mcp-mail.example.com` |
| `MCP_EMAIL_DOMAIN` | `example.com` (users type only the local part) |
| `MCP_IMAP_HOST` | `imap.example.com` |

Optional: SMTP host/port (defaults to the IMAP host, SSL 465), CalDAV URL template
(`{email}` placeholder — empty disables calendar tools, which are then not even
registered), timezone, explicit special-folder names, semantics file path,
`MCP_TLS_VERIFY` (default true; set false only for self-signed mail servers) and
`MCP_TRUST_PROXY_HEADERS` (default true; set false if the port is exposed without
a reverse proxy).

On startup the server runs a **preflight check**: static configuration is validated
(CalDAV template, timezone) and connectivity is tested. IMAP is required — a broken IMAP
config aborts startup. SMTP is optional and **degrades gracefully** (see below).

### When the outbound SMTP port is blocked

Many hosting providers (Hetzner among them) block **outbound** SMTP ports (25/465) by
default to fight spam, so the server can't reach your mail provider to *send*. This server
handles that in three ways:

- **Alternate port/mode:** set `MCP_SMTP_PORT=587` (submission over STARTTLS) when `465`
  (implicit SSL) is blocked — often 587 is open when 465 is not. `MCP_SMTP_SECURITY`
  (`ssl`/`starttls`) is inferred from the port but can be set explicitly.
- **Graceful degradation:** the preflight probes SMTP without credentials. If it's
  unreachable, the server still starts — reading, search, calendar and **`create_draft`
  keep working** (drafts are saved via IMAP, no SMTP needed) — and only `send_email` /
  `reply_email` are withheld, so agents never see a send tool that would fail.
- **Unblock:** or ask the host to lift the outbound-port block (e.g. Hetzner's port-25
  removal request), then use 465/587 normally.

## The semantics layer (what makes agents actually useful)

Generic tools tell an agent *how* to read a mailbox. `semantics.yml` tells it *what things
mean*: that `INBOX.Clients.BigCorp` is a client folder, that mail from `@toolsinc.example`
relates to that client, that the `Urgent` tag means operational blockage, which senders are
newsletters to deprioritize. Agents call `mailbox_guide()` first (the server instructions
tell them to) and start every conversation already oriented.

## Tools

**Queries** — `unread_summary`, `list_unread`, `mailbox_stats`, `list_folders`,
`list_emails`, `search_emails`, `read_email`, `get_thread`, `get_attachment`

**Intelligence** — `mailbox_guide`, `daily_brief`, `list_pending_replies`, `get_contact_history`

**Actions** — `send_email`, `reply_email` (thread-aware), `create_draft`, `tag_emails`,
`move_emails`, `delete_emails` (→ Trash), `mark_read`, `create_folder` (batch where it matters)

**Calendar** — `list_calendars`, `list_events`, `create_event`, `delete_event`

## Security model

- Passwords are stored only on your server, encrypted with a locally-generated Fernet key
  (`data/master.key` + `data/store.enc`, created with mode 600). Losing them just forces re-login.
- IMAP/SMTP connections use a **verified TLS context** (Python's `smtplib`/`imaplib` do not
  verify certificates by default — this server always passes an explicit context).
- The OAuth login page proxies authentication to your IMAP server — wrong password, no access.
  Two independent rate limiters: 8 failures per source IP and 12 per target username per
  10 minutes (the per-username one caps brute force against one account even if the attacker
  rotates IPs; there is no global limiter that one attacker could use to lock everyone out).
  Client IP is taken from proxy headers only when `MCP_TRUST_PROXY_HEADERS=true` — it
  defaults to **false** (fail-closed), so enable it only behind a trusted proxy/tunnel.
- The login/consent page shows the **destination host** the authorization code will be sent
  to (from the registered redirect_uri, which the client cannot forge). The app name is
  shown but labelled self-reported, since Dynamic Client Registration lets anyone pick one.
  The page is served with `X-Frame-Options: DENY` and a strict CSP.
- Untrusted attachments are size-capped and zip-bomb-guarded before parsing.
- PKCE S256 enforced; access tokens expire in 1 h; refresh tokens rotate; expired
  tokens/codes are purged automatically.
- DNS-rebinding protection restricted to your public hostname.
- Nothing is ever permanently deleted by agents.

Recommended: in the claude.ai connector permission screen, keep the "(real action)" tools
on *Ask first*.

## License

MIT
