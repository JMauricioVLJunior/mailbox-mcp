"""Mailbox semantics layer: teaches AI agents what folders/tags MEAN for this deployment,
and drives triage (priority, who-is-who, allow/block) — not just described, but consumed.

Loaded from an optional YAML file (MCP_SEMANTICS_FILE) or the admin console. Everything
degrades gracefully to neutral defaults when absent. Expected YAML shape (all keys optional):

  business_context: >
    One paragraph describing whose mailbox this is and the business around it.
  tags:
    Tag-Name: what this IMAP keyword means
  folders:
    "INBOX.Clients.Acme": exact-match meaning
  folder_prefixes:
    "INBOX.Clients.": "client folder: "     # meaning = label + remainder of the name
  entities:                                  # who is who (address or domain -> facts)
    "@toolsinc.example": { client: BigCorp, role: vendor }
    "cfo@acme.com": { person: "Ana (CFO)", vip: true }
  priorities:
    vip_senders: ["ceo@acme.com", "@board.acme.com"]
    urgent_keywords: ["contract", "outage", "overdue"]
  routing:                                   # where things belong (filing hints for agents)
    "invoices / billing": "INBOX.Finance"
  policies:                                  # how to handle mail (shapes agent behavior)
    - "Prefer create_draft over send_email unless told to send."
  allowlist:                                 # trusted senders: never automated/spam
    - "@acme.com"
  blocklist:                                 # always low-priority junk
    - "@known-spam.example"
  automated_senders:
    - "@some-newsletter.com"                 # extra markers (merged with defaults)
  automated_subject_prefixes:
    - "newsletter"
  conventions:
    - extra convention lines shown to agents
"""

import config
import store

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


def invalidate() -> None:
    """Drop the cache so the next read reflects an admin edit."""
    global _cache
    _cache = None


def _load() -> dict:
    global _cache
    if _cache is not None:
        return _cache
    data = {}
    # an admin-set YAML override (from the console) wins over the on-disk file
    override = None
    try:
        override = store.get_settings().get("semantics_yaml")
    except Exception:
        override = None
    if override:
        import yaml
        data = yaml.safe_load(override) or {}
    elif config.SEMANTICS_FILE:
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


# ---- entities, priorities, routing, policies, allow/block ----

def entities() -> dict:
    return _load().get("entities", {}) or {}


def routing() -> dict:
    return _load().get("routing", {}) or {}


def policies() -> list:
    return list(_load().get("policies", []) or [])


def _priorities() -> dict:
    p = _load().get("priorities", {})
    return p if isinstance(p, dict) else {}


def vip_senders() -> tuple:
    return tuple(_priorities().get("vip_senders", []) or [])


def urgent_keywords() -> tuple:
    return tuple(_priorities().get("urgent_keywords", []) or [])


def allowlist() -> tuple:
    return tuple(_load().get("allowlist", []) or [])


def blocklist() -> tuple:
    return tuple(_load().get("blocklist", []) or [])


def _matches(sender: str, markers) -> bool:
    s = (sender or "").lower()
    return any(m and str(m).lower() in s for m in markers)


def entity_of(address: str) -> dict | None:
    """Best entity match for an address (longest matching key wins)."""
    a = (address or "").lower()
    if not a:
        return None
    best_key, best_val = "", None
    for key, val in entities().items():
        if key and str(key).lower() in a and len(str(key)) > len(best_key):
            best_key, best_val = str(key), val
    return best_val if isinstance(best_val, dict) else None


def who(address: str) -> str:
    """Short human label for a sender from the entities table, e.g. 'Ana (CFO) [VIP]'."""
    e = entity_of(address)
    if not e:
        return ""
    label = e.get("person") or e.get("client") or e.get("role") or ""
    if e.get("client") and e.get("person"):
        label = f"{e['person']} ({e['client']})"
    if e.get("vip") and "VIP" not in label:
        label = f"{label} [VIP]".strip()
    return label


def is_automated_sender(sender: str, subject: str = "") -> bool:
    # explicit trust/block override the heuristics
    if _matches(sender, allowlist()):
        return False
    if _matches(sender, blocklist()):
        return True
    s = (sender or "").lower()
    if any(x in s for x in automated_markers()):
        return True
    subj = (subject or "").strip().lower()
    return any(subj.startswith(p) for p in automated_subject_prefixes())


def priority_of(sender: str, subject: str = "", body: str = "") -> str:
    """Triage class: vip | urgent | normal | automated (used to order pending replies)."""
    ent = entity_of(sender)
    if _matches(sender, vip_senders()) or (ent and ent.get("vip")):
        return "vip"
    if is_automated_sender(sender, subject):
        return "automated"
    text = f"{subject} {body}".lower()
    if any(str(k).lower() in text for k in urgent_keywords()):
        return "urgent"
    return "normal"


# ---- validation (for the admin editor) ----

_KNOWN_KEYS = {"business_context", "tags", "folders", "folder_prefixes", "automated_senders",
               "automated_subject_prefixes", "conventions", "entities", "priorities",
               "routing", "policies", "allowlist", "blocklist"}
_LIST_KEYS = {"automated_senders", "automated_subject_prefixes", "conventions",
              "policies", "allowlist", "blocklist"}
_MAP_KEYS = {"tags", "folders", "folder_prefixes", "entities", "routing", "priorities"}


def validate_semantics(data) -> list:
    """Return a list of human-readable warnings (non-fatal). Empty list = clean."""
    if not isinstance(data, dict):
        return ["top level must be a mapping (key: value)"]
    warnings = []
    for k in data:
        if k not in _KNOWN_KEYS:
            warnings.append(f"unknown key '{k}' (ignored)")
    for k in _LIST_KEYS:
        if k in data and not isinstance(data[k], list):
            warnings.append(f"'{k}' should be a list")
    for k in _MAP_KEYS:
        if k in data and not isinstance(data[k], dict):
            warnings.append(f"'{k}' should be a mapping")
    prio = data.get("priorities")
    if isinstance(prio, dict):
        for sub in ("vip_senders", "urgent_keywords"):
            if sub in prio and not isinstance(prio[sub], list):
                warnings.append(f"priorities.{sub} should be a list")
    return warnings


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
