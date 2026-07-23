"""Mailbox semantics layer: teaches AI agents what folders/tags MEAN for this deployment.

Loaded from an optional YAML file (MCP_SEMANTICS_FILE). Everything degrades gracefully
to neutral defaults when the file is absent. Expected YAML shape (all keys optional):

  business_context: >
    One paragraph describing whose mailbox this is and the business around it.
  tags:
    Tag-Name: what this IMAP keyword means
  folders:
    "INBOX.Clients.Acme": exact-match meaning
  folder_prefixes:
    "INBOX.Clients.": "client folder: "     # meaning = label + remainder of the name
  automated_senders:
    - "@some-newsletter.com"                 # extra markers (merged with defaults)
  automated_subject_prefixes:
    - "newsletter"
  conventions:
    - extra convention lines shown to agents
"""

import config

_DEFAULT_AUTOMATED = (
    "no-reply", "noreply", "do-not-reply", "donotreply", "mailer-daemon", "postmaster",
    "notification", "alerts@", "marketing@", "newsletter", "news@", "digest", "promomail",
    "failed-payments", "invites@microsoft.com",
)
_DEFAULT_SUBJECT_PREFIXES = ("newsletter", "promo")

_DEFAULT_CONVENTIONS = [
    "An e-mail is identified by (folder, uid); uid is only valid within its own folder",
    "Threads are grouped by base subject (Re:/Fwd:/RES:/ENC: prefixes stripped)",
    "Tags are IMAP keywords stored on the server - use tag_emails to apply, search_emails(tag=...) to find",
    "delete_emails moves to Trash (reversible); nothing is permanently deleted",
    "pending_replies marks automated=true for machine senders - prioritize automated=false (humans waiting)",
]

_cache = None


def _load() -> dict:
    global _cache
    if _cache is not None:
        return _cache
    data = {}
    if config.SEMANTICS_FILE:
        try:
            import yaml
            with open(config.SEMANTICS_FILE, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
        except FileNotFoundError:
            data = {}
    _cache = data
    return data


def business_context() -> str:
    return _load().get("business_context", "").strip()


def tags() -> dict:
    return _load().get("tags", {})


def automated_markers() -> tuple:
    extra = tuple(_load().get("automated_senders", []))
    return _DEFAULT_AUTOMATED + extra


def automated_subject_prefixes() -> tuple:
    extra = tuple(_load().get("automated_subject_prefixes", []))
    return _DEFAULT_SUBJECT_PREFIXES + extra


def is_automated_sender(sender: str, subject: str = "") -> bool:
    s = (sender or "").lower()
    if any(x in s for x in automated_markers()):
        return True
    subj = (subject or "").strip().lower()
    return any(subj.startswith(p) for p in automated_subject_prefixes())


def folder_meaning(name: str, special: dict = None) -> str:
    data = _load()
    exact = data.get("folders", {})
    if name in exact:
        return exact[name]
    for prefix, label in data.get("folder_prefixes", {}).items():
        if name.startswith(prefix) and name != prefix.rstrip("."):
            return f"{label}{name[len(prefix):]}"
    special = special or {}
    if name == "INBOX":
        return "inbox"
    if name == special.get("sent"):
        return "sent mail"
    if name == special.get("trash"):
        return "trash"
    if name == special.get("drafts"):
        return "drafts"
    if name == special.get("junk"):
        return "spam"
    return "folder"


def conventions() -> list:
    return _DEFAULT_CONVENTIONS + list(_load().get("conventions", []))
