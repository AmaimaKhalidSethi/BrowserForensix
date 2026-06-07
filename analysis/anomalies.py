"""Anomaly detection for browser artifacts."""

import math
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import urlparse


def _now_utc() -> datetime:
    return datetime.now(tz=timezone.utc)


def _parse_iso(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def extract_domain(url: str) -> str:
    try:
        netloc = urlparse(url).netloc.lower()
        host = netloc.split(":")[0]
        return host.removeprefix("www.")
    except Exception:
        return ""


def domain_matches(candidate: str, domain_set: set) -> bool:
    if not candidate:
        return False
    candidate_parts = candidate.split(".")
    for domain in domain_set:
        domain_parts = domain.split(".")
        if len(candidate_parts) > len(domain_parts) and candidate_parts[-len(domain_parts):] == domain_parts:
            return True
        if len(domain_parts) > len(candidate_parts) and domain_parts[-len(candidate_parts):] == candidate_parts:
            return True
        if candidate_parts == domain_parts:
            return True
    return False


def detect_history_gaps(history: List[Dict], cookies: List[Dict]) -> Optional[Dict]:
    history_domains = {extract_domain(h.get("url", "")) for h in history}
    history_domains.discard("")

    ghost_domains = []
    for c in cookies:
        host = c.get("host", "").lstrip(".").removeprefix("www.")
        if host and host not in history_domains:
            if not any(hd == host or hd.endswith("." + host) or host.endswith("." + hd)
                       for hd in history_domains):
                ghost_domains.append(host)

    if not ghost_domains:
        return None

    unique_ghosts = sorted(set(ghost_domains))
    return {
        "type": "history_gap",
        "severity": "critical",
        "title": "History Clearing Detected",
        "description": (
            f"{len(unique_ghosts)} domain(s) have cookies but no history entries. "
            f"This strongly indicates selective or complete browser history clearing. "
            f"Domains include: {', '.join(unique_ghosts[:8])}"
            + (f" (+{len(unique_ghosts)-8} more)" if len(unique_ghosts) > 8 else "")
        ),
        "domain_count": len(unique_ghosts),
        "affected_domains": unique_ghosts[:20],
    }


def detect_burst_activity(
    history: List[Dict],
    burst_threshold: int = 8,
    window_minutes: int = 5,
) -> List[Dict]:
    timestamped = []
    for h in history:
        dt = _parse_iso(h.get("last_visit", ""))
        if dt:
            timestamped.append((dt, h))
    timestamped.sort(key=lambda x: x[0])

    anomalies = []
    seen_windows = set()

    # Group by domain first
    from collections import defaultdict
    by_domain = defaultdict(list)
    for dt, h in timestamped:
        d = extract_domain(h.get("url", ""))
        if d:
            by_domain[d].append((dt, h))

    for domain, entries in by_domain.items():
        for i, (t0, _) in enumerate(entries):
            window = [h for (t, h) in entries[i:]
                      if (t - t0).total_seconds() <= window_minutes * 60]
            if len(window) >= burst_threshold:
                key = (domain, t0.isoformat())
                if key not in seen_windows:
                    seen_windows.add(key)
                    anomalies.append({
                        "type": "burst_activity",
                        "severity": "moderate",
                        "title": f"Burst Activity - {len(window)} visits to {domain} in {window_minutes} min",
                        "description": (
                            f"{len(window)} visits to {domain} within {window_minutes} minutes "
                            f"starting {t0.isoformat()}."
                        ),
                        "start_time": t0.isoformat(),
                        "url_count": len(window),
                        "domains": [domain],
                    })
    return anomalies


def _circular_mean(hours: list) -> float:
    n = len(hours)
    sin_sum = sum(math.sin(2 * math.pi * h / 24) for h in hours)
    cos_sum = sum(math.cos(2 * math.pi * h / 24) for h in hours)
    mean_rad = math.atan2(sin_sum / n, cos_sum / n)
    return (math.degrees(mean_rad) * 24 / 360) % 24


def _circular_stdev(hours: list, mean_hour: float) -> float:
    n = len(hours)
    sin_sum = sum(math.sin(2 * math.pi * h / 24) for h in hours)
    cos_sum = sum(math.cos(2 * math.pi * h / 24) for h in hours)
    r_value = math.sqrt((sin_sum / n) ** 2 + (cos_sum / n) ** 2)
    r_value = max(1e-10, min(r_value, 1 - 1e-10))
    return math.sqrt(-2 * math.log(r_value)) * 24 / (2 * math.pi)


def detect_offhours_activity(history: List[Dict]) -> Optional[Dict]:
    hours = []
    for h in history:
        dt = _parse_iso(h.get("last_visit", ""))
        if dt is not None:
            hours.append(dt.hour)

    if len(hours) < 50:
        return None

    mean_hour = _circular_mean(hours)
    stdev_hour = _circular_stdev(hours, mean_hour)
    if stdev_hour < 0.1:
        return None

    threshold = 2.0

    def _circular_hour_dist(h: float, mean: float) -> float:
        diff = abs(h - mean) % 24
        return min(diff, 24 - diff)

    offhours_visits = [
        h for h in history
        if (dt := _parse_iso(h.get("last_visit", ""))) is not None
        and _circular_hour_dist(dt.hour, mean_hour) / stdev_hour > threshold
    ]

    if not offhours_visits:
        return None

    normal_start = int(mean_hour - threshold * stdev_hour) % 24
    normal_end = int(mean_hour + threshold * stdev_hour) % 24

    return {
        "type": "offhours_activity",
        "severity": "moderate",
        "title": "Off-Hours Activity Detected",
        "description": (
            f"{len(offhours_visits)} visits outside the user's calculated normal window "
            f"(approx {normal_start:02d}:00-{normal_end:02d}:00 UTC, derived from "
            f"{len(hours)} history timestamps). Mean hour: {mean_hour:.1f}, sigma={stdev_hour:.1f}."
        ),
        "offhours_count": len(offhours_visits),
        "user_mean_hour": round(mean_hour, 2),
        "user_stdev_hour": round(stdev_hour, 2),
    }


def detect_download_without_history(history: List[Dict], downloads: List[Dict]) -> List[Dict]:
    history_domains = {extract_domain(h.get("url", "")) for h in history}
    history_domains.discard("")

    anomalies = []
    for dl in downloads:
        src = dl.get("source_url", "")
        if not src:
            continue
        src_domain = extract_domain(src)
        if not domain_matches(src_domain, history_domains):
            anomalies.append({
                "type": "download_without_history",
                "severity": "moderate",
                "title": f"Download Without History - {dl.get('filename', '')}",
                "description": (
                    f"File '{dl.get('filename', '')}' ({dl.get('size_bytes', 0):,} bytes) "
                    f"downloaded from {urlparse(src).netloc} - source domain absent from history. "
                    f"Possible private browsing or selective history clearing."
                ),
                "filename": dl.get("filename", ""),
                "source_url": src,
                "download_time": dl.get("start_time", ""),
            })
    return anomalies


def detect_zombie_cookies(cookies: List[Dict]) -> List[Dict]:
    host_zombies: dict = defaultdict(list)
    for c in cookies:
        expires = c.get("expires", "")
        if not expires:
            continue
        exp_dt = _parse_iso(expires)
        if exp_dt is not None and exp_dt < _now_utc():
            host_zombies[c.get("host", "unknown")].append({
                "name": c.get("name", ""),
                "expired": exp_dt.isoformat(),
            })

    zombies = []
    for host, entries in sorted(host_zombies.items()):
        names = ", ".join(e["name"] for e in entries[:5])
        extra = f" (+{len(entries)-5} more)" if len(entries) > 5 else ""
        zombies.append({
            "type": "zombie_cookie",
            "severity": "low",
            "title": f"Zombie Cookies - {host}",
            "description": (
                f"{len(entries)} expired cookie(s) still present for {host}: "
                f"{names}{extra}."
            ),
            "host": host,
            "cookie_count": len(entries),
            "cookies": entries[:10],
        })
    return zombies
