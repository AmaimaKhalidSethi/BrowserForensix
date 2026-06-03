"""Timeline event construction and session reconstruction."""

import re
from datetime import datetime, timezone
from urllib.parse import urlparse


def domain_of(url: str) -> str:
    netloc = urlparse(url).netloc.lower().split(":")[0]
    return netloc.removeprefix("www.")


def norm_dt(ts: str) -> "datetime | None":
    if not ts:
        return None
    try:
        normalised = ts.strip().replace("Z", "+00:00")
        normalised = re.sub(r" (\d{2}:\d{2})$", r"+\1", normalised)
        return datetime.fromisoformat(normalised).astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def build_unified_events(data: dict, types: "set | None" = None) -> list:
    if types is None:
        types = {"history", "cookies", "downloads"}

    events = []

    if "history" in types:
        for h in data.get("history", []):
            if h.get("last_visit"):
                events.append({
                    "type": "history",
                    "time": h["last_visit"],
                    "url": h.get("url", ""),
                    "title": h.get("title", ""),
                    "domain": domain_of(h.get("url", "")),
                    "risk_score": h.get("risk_score", 0),
                })

    if "cookies" in types:
        for c in data.get("cookies", []):
            if c.get("created"):
                events.append({
                    "type": "cookie",
                    "time": c["created"],
                    "host": c.get("host", ""),
                    "name": c.get("name", ""),
                    "cookie_type": c.get("type", ""),
                    "risk_score": c.get("risk_score", 0),
                })

    if "downloads" in types:
        for dl in data.get("downloads", []):
            if dl.get("start_time"):
                events.append({
                    "type": "download",
                    "time": dl["start_time"],
                    "filename": dl.get("filename", ""),
                    "source_url": dl.get("source_url", ""),
                    "domain": domain_of(dl.get("source_url", "")),
                    "risk_score": dl.get("risk_score", 0),
                })

    def _sort_key(e: dict) -> datetime:
        parsed = norm_dt(e.get("time", ""))
        return parsed if parsed is not None else datetime.fromtimestamp(0, tz=timezone.utc)

    events.sort(key=_sort_key, reverse=True)
    return events


def reconstruct_sessions(events: list, gap_seconds: int = 1800) -> list:
    if not events:
        return []

    sessions: list = []
    current: list = []
    last_t: "datetime | None" = None

    for e in reversed(events):
        t = norm_dt(e.get("time", ""))
        if t is None:
            continue
        if last_t is None or (t - last_t).total_seconds() > gap_seconds:
            if current:
                sessions.append(current)
            current = [e]
        else:
            current.append(e)
        last_t = t

    if current:
        sessions.append(current)

    sessions.reverse()
    return [
        {
            "start": s[0]["time"],
            "end": s[-1]["time"],
            "count": len(s),
            "events": s,
        }
        for s in sessions
    ]
