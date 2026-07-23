"""Outbound mail: send, reply (thread-aware) and drafts. SMTP over implicit SSL (465) or
STARTTLS (587), copy saved via IMAP. create_draft needs no SMTP (it is an IMAP append)."""

import smtplib
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

import config
import imap_ops


def _open_smtp(timeout: int = 30) -> smtplib.SMTP:
    """Connect to the configured SMTP server with a verified TLS context, using implicit
    SSL or STARTTLS per config. Caller logs in and sends. Raises on unreachable/blocked port."""
    ctx = config.ssl_context()
    if config.SMTP_SECURITY == "starttls":
        smtp = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=timeout)
        smtp.ehlo()
        smtp.starttls(context=ctx)
        smtp.ehlo()
        return smtp
    return smtplib.SMTP_SSL(config.SMTP_HOST, config.SMTP_PORT, timeout=timeout, context=ctx)


def smtp_reachable(timeout: int = 8) -> tuple[bool, str]:
    """Preflight probe: can we open + TLS-negotiate SMTP? Detects a blocked outbound port
    (e.g. hosts that block 465) WITHOUT credentials, so send tools aren't exposed if dead."""
    detail = f"{config.SMTP_HOST}:{config.SMTP_PORT} ({config.SMTP_SECURITY})"
    try:
        smtp = _open_smtp(timeout=timeout)
        try:
            smtp.ehlo()
        finally:
            try:
                smtp.quit()
            except Exception:
                pass
        return True, detail
    except Exception as exc:
        return False, f"{detail} - {exc}"


def _split_addrs(value) -> list:
    if not value:
        return []
    if isinstance(value, str):
        return [a.strip() for a in value.split(",") if a.strip()]
    return list(value)


def _build_message(imap: dict, to_list, cc_list, subject: str, body: str,
                    display_name: str = None, in_reply_to: str = None, references: str = None) -> EmailMessage:
    msg = EmailMessage()
    sender = imap["user"]
    msg["From"] = formataddr((display_name, sender)) if display_name else sender
    msg["To"] = ", ".join(to_list)
    if cc_list:
        msg["Cc"] = ", ".join(cc_list)
    msg["Subject"] = subject
    msg["Message-ID"] = make_msgid(domain=sender.split("@")[-1])
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
        msg["References"] = f"{references} {in_reply_to}".strip() if references else in_reply_to
    msg.set_content(body)
    return msg


def send_email(imap: dict, to, subject: str, body: str, cc=None, bcc=None,
               display_name: str = None, in_reply_to: str = None, references: str = None) -> dict:
    to_list = _split_addrs(to)
    cc_list = _split_addrs(cc)
    bcc_list = _split_addrs(bcc)
    if not to_list:
        raise ValueError("recipient (to) is required")

    msg = _build_message(imap, to_list, cc_list, subject, body, display_name, in_reply_to, references)

    all_rcpts = to_list + cc_list + bcc_list
    with _open_smtp() as smtp:
        smtp.login(imap["user"], imap["password"])
        smtp.send_message(msg, from_addr=imap["user"], to_addrs=all_rcpts)

    try:
        imap_ops.append_to_sent(imap, msg.as_bytes())
        saved_to_sent = True
    except Exception:
        saved_to_sent = False

    return {
        "message_id": msg["Message-ID"],
        "to": to_list,
        "cc": cc_list,
        "bcc": bcc_list,
        "subject": subject,
        "saved_to_sent": saved_to_sent,
    }


def create_draft(imap: dict, to, subject: str, body: str, cc=None,
                  display_name: str = None) -> dict:
    """Save a draft to the Drafts folder (does NOT send)."""
    to_list = _split_addrs(to)
    cc_list = _split_addrs(cc)
    msg = _build_message(imap, to_list, cc_list, subject, body, display_name)
    drafts = imap_ops.append_draft(imap, msg.as_bytes())
    return {"saved_to": drafts, "to": to_list, "cc": cc_list, "subject": subject}


def reply_email(imap: dict, folder: str, uid: str, body: str, reply_all: bool = False,
                display_name: str = None) -> dict:
    original = imap_ops.fetch_for_reply(imap, folder, uid)
    me = imap["user"].lower()

    to_list = [original["from"]]
    cc_list = []
    if reply_all:
        extras = [a for a in original["to"] + original["cc"] if a.lower() != me and a != original["from"]]
        cc_list = extras

    subject = original["subject"] or ""
    if not subject.lower().startswith(("re:", "res:")):
        subject = f"Re: {subject}"

    return send_email(
        imap,
        to=to_list,
        cc=cc_list or None,
        subject=subject,
        body=body,
        display_name=display_name,
        in_reply_to=original["message_id"] or None,
        references=original["references"] or None,
    )
