"""CalDAV calendar operations with per-account connection cache and configurable timezone."""

import datetime as dt
import threading
from zoneinfo import ZoneInfo

import caldav

import config

TZ = ZoneInfo(config.TIMEZONE)

_clients: dict = {}
_lock = threading.Lock()


def _principal(cd: dict):
    key = (cd["base_url"], cd["user"])
    with _lock:
        entry = _clients.get(key)
        if entry is None:
            client = caldav.DAVClient(url=cd["base_url"], username=cd["user"], password=cd["password"])
            entry = {"client": client, "principal": client.principal()}
            _clients[key] = entry
        return entry["principal"]


def _drop_cache(cd: dict) -> None:
    with _lock:
        _clients.pop((cd["base_url"], cd["user"]), None)


def _with_principal(cd: dict, fn):
    """Run fn(principal) on a cached connection; one retry with reconnection on error."""
    try:
        return fn(_principal(cd))
    except Exception:
        _drop_cache(cd)
        return fn(_principal(cd))


def _get_calendars(principal, calendar_name: str = None) -> list:
    calendars = principal.calendars()
    if calendar_name:
        calendars = [c for c in calendars if c.name == calendar_name]
        if not calendars:
            raise ValueError(f"calendar '{calendar_name}' not found")
    return calendars


def _parse_dt(value: str) -> dt.datetime:
    d = dt.datetime.fromisoformat(value)
    if d.tzinfo is None:
        d = d.replace(tzinfo=TZ)
    return d


def _event_dict(cal_name: str, event) -> dict:
    vevent = event.icalendar_component
    return {
        "calendar": cal_name,
        "uid": str(vevent.get("uid", "")),
        "summary": str(vevent.get("summary", "")),
        "start": str(vevent.get("dtstart").dt) if vevent.get("dtstart") else None,
        "end": str(vevent.get("dtend").dt) if vevent.get("dtend") else None,
        "location": str(vevent.get("location", "")),
        "description": str(vevent.get("description", ""))[:500],
    }


def list_calendars(cd: dict) -> list:
    return _with_principal(cd, lambda p: [{"name": c.name, "url": str(c.url)} for c in _get_calendars(p)])


def list_events(cd: dict, calendar_name: str = None, start_date: str = None, days: int = 14) -> list:
    start = _parse_dt(start_date) if start_date else dt.datetime.now(TZ)
    end = start + dt.timedelta(days=days)

    def fn(principal):
        results = []
        for cal in _get_calendars(principal, calendar_name):
            for event in cal.date_search(start=start, end=end):
                results.append(_event_dict(cal.name, event))
        results.sort(key=lambda e: e["start"] or "")
        return results
    return _with_principal(cd, fn)


def create_event(cd: dict, calendar_name: str, summary: str, start: str, end: str,
                  location: str = "", description: str = "") -> dict:
    def fn(principal):
        cal = _get_calendars(principal, calendar_name)[0]
        event = cal.save_event(
            dtstart=_parse_dt(start),
            dtend=_parse_dt(end),
            summary=summary,
            location=location,
            description=description,
        )
        return {"uid": str(event.icalendar_component.get("uid", "")), "url": str(event.url)}
    return _with_principal(cd, fn)


def delete_event(cd: dict, calendar_name: str, uid: str) -> str:
    def fn(principal):
        cal = _get_calendars(principal, calendar_name)[0]
        cal.event_by_uid(uid).delete()
        return "deleted"
    return _with_principal(cd, fn)
