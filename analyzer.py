#!/usr/bin/env python3
"""
BrowserForensix — analyzer.py  (PATCHED)

PATCH NOTES:
  FIX-1  _extract_domain(): .lstrip("www.") → .removeprefix("www.")
  FIX-6  run() now pre-computes the activity heatmap and stores it in
         analysis.json["heatmap"]. /api/overview reads it instead of
         recomputing per-request.
  FIX-BURST  detect_burst_activity(): replaced O(n²) inner scan with an
         O(n log n) two-pointer sliding window.
"""

import json
import statistics
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

EVIDENCE_FILE = Path(__file__).parent / "data" / "evidence.json"
ANALYSIS_FILE = Path(__file__).parent / "data" / "analysis.json"

PASTE_SITES = {
    "pastebin.com", "paste.ee", "hastebin.com", "ghostbin.co",
    "privatebin.net", "rentry.co", "dpaste.com", "termbin.com",
    "bin.idrix.fr",
}

FILE_SHARE_SITES = {
    "filebin.net", "file.io", "transfer.sh", "anonfiles.com",
    "gofile.io", "send.firefox.com", "wetransfer.com", "sendspace.com",
    "ufile.io", "uploadfiles.io",
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def _now_utc() -> datetime:
    return datetime.now(tz=timezone.utc)

def _parse_iso(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None

# FIX-1: Use .removeprefix() — .lstrip(chars) strips individual characters
# from the char-set, not the literal string prefix.
def _extract_domain(url: str) -> str:
    try:
        netloc = urlparse(url).netloc.lower()
        return netloc.split(":")[0].removeprefix("www.")
    except Exception:
        return ""

def _is_ip(host: str) -> bool:
    # BUG-15 FIX: validate octet range 0-255. Previously any four dot-separated
    # digit strings passed (e.g. "999.999.999.999", "1.2.3.456").
    parts = host.lstrip(".").split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False

def _is_expired(expires_str: str) -> bool:
    dt = _parse_iso(expires_str)
    return dt is not None and dt < _now_utc()

def _domain_matches(src: str, history_domains: set) -> bool:
    if not src or src.count(".") == 0:
        return False
    if len(src.split(".")) < 2 or all(len(p) <= 2 for p in src.split(".")[:-1]):
        return src in history_domains
    return (
        src in history_domains
        or any(
            hd == src
            or (src.endswith("." + hd) and hd.count(".") >= 1)
            or (hd.endswith("." + src) and src.count(".") >= 1)
            for hd in history_domains
        )
    )

# ── Risk scoring ──────────────────────────────────────────────────────────────

def score_url(
    url: str, visit_time: str,
    domain_cookie_exists: bool, domain_history_count: int,
    transition: int = 0,
) -> Tuple[int, List[str]]:
    score = 0
    reasons: List[str] = []
    parsed = urlparse(url)
    domain = parsed.netloc.lower().split(":")[0]

    local_prefixes = ("localhost", "127.", "192.168.", "10.", "172.16.")
    if parsed.scheme == "http" and not any(domain.startswith(p) for p in local_prefixes):
        score += 20
        reasons.append("HTTP protocol on non-local domain")

    if _is_ip(domain):
        score += 25
        reasons.append("IP address used instead of domain name")

    bare = domain.removeprefix("www.")   # FIX-1 applied here too
    if bare in PASTE_SITES:
        score += 30
        reasons.append(f"Known paste site: {bare}")
    elif bare in FILE_SHARE_SITES:
        score += 30
        reasons.append(f"Known file-sharing site: {bare}")

    dt = _parse_iso(visit_time)
    if dt is not None and (dt.hour >= 23 or dt.hour < 5):
        score += 15
        reasons.append(f"Visited off-hours ({dt.strftime('%H:%M')} UTC)")

    if domain_cookie_exists and domain_history_count == 0:
        score += 25
        reasons.append("Cookie exists for this domain but history was cleared")

    core_transition = transition & 0xFF
    if core_transition == 1:
        # BUG-10 FIX: typed URL signals deliberate user intent — add intentionality
        # weight only when the visit is already in the moderate+ risk band (≥ 31).
        # Previously the threshold was > 20 which penalised low-risk typed URLs.
        reasons.append("URL was typed directly by the user (high intentionality)")
        if score >= 31:
            score = min(score + 10, 100)
    elif core_transition == 8:
        reasons.append("URL reached via form submission")

    return min(score, 100), reasons


def _transition_label(transition: int) -> str:
    core = transition & 0xFF
    labels = {
        0: "link", 1: "typed", 2: "auto_bookmark", 3: "auto_subframe",
        4: "manual_subframe", 5: "generated", 7: "start_page",
        8: "form_submit", 9: "reload", 10: "keyword",
    }
    return labels.get(core, f"unknown({core})")


def score_cookie(cookie: Dict, domain_history_count: int) -> Tuple[int, List[str]]:
    score = 0
    reasons: List[str] = []
    host = cookie.get("host", "")
    expires = cookie.get("expires", "")
    created = cookie.get("created", "")
    secure = cookie.get("secure", True)
    name = cookie.get("name", "").lower()

    if expires and _is_expired(expires):
        score += 10
        reasons.append("Cookie past its expiry date (zombie)")

    if expires and created:
        exp_dt = _parse_iso(expires)
        cre_dt = _parse_iso(created)
        if exp_dt and cre_dt:
            lifespan_days = (exp_dt - cre_dt).days
            if lifespan_days > 365:
                score += 15
                reasons.append(f"Long-lived cookie ({lifespan_days} days)")

    if not secure:
        score += 10
        reasons.append("Cookie missing Secure flag")

    if _is_ip(host.lstrip(".")):
        score += 25
        reasons.append("Cookie set by IP address host")

    if domain_history_count == 0:
        score += 20
        reasons.append("No history entries for this domain — possible cleared history")

    # B7 FIX: removed "sid" — it matches "inside","position","beside" etc.
    # Auth token detection is already handled in classify_cookie(); this +5 is additive.
    auth_names = {"token", "auth", "jwt", "access_token", "id_token", "sessionid"}
    if any(a in name for a in auth_names):
        score += 5
        reasons.append("Appears to be an authentication token")

    return min(score, 100), reasons


def score_download(dl: Dict, source_domain_in_history: bool) -> Tuple[int, List[str]]:
    score = 0
    reasons: List[str] = []
    filename = dl.get("filename", "").lower()
    file_exists = dl.get("file_exists", True)
    danger = dl.get("danger_type", 0)

    exe_exts = (".exe", ".msi", ".bat", ".cmd", ".ps1", ".sh", ".dmg", ".pkg", ".deb", ".rpm")
    if any(filename.endswith(ext) for ext in exe_exts):
        score += 20
        reasons.append(f"Executable file type ({Path(filename).suffix})")

    arch_exts = (".zip", ".tar", ".gz", ".7z", ".rar")
    if any(filename.endswith(ext) for ext in arch_exts):
        score += 10
        reasons.append("Archive file type")

    if not source_domain_in_history:
        score += 30
        reasons.append("Source domain absent from history — possible private browsing or cleared history")

    if not file_exists:
        score += 20
        reasons.append("File no longer present at recorded path — may have been moved or deleted")

    if danger and danger > 0:
        score += 20
        reasons.append(f"Chrome flagged download (danger_type={danger})")

    return min(score, 100), reasons


# ── Cookie classification ─────────────────────────────────────────────────────

def classify_cookie(cookie: Dict) -> str:
    expires = cookie.get("expires", "")
    if expires and _is_expired(expires):
        return "Zombie"

    name = cookie.get("name", "").lower()

    # BUG-12 FIX: Auth must be checked before Tracking.
    # "_ga_token" contains both "_ga" (tracking) and "token" (auth).
    # Auth tokens are higher forensic value — they should take precedence.
    #
    # Also: "uid" was matching "fluid", "invalid", "squid" etc.
    # Replaced with exact-prefix or standalone patterns to reduce false positives.
    auth_patterns     = ["token", "auth", "sid", "jwt", "access_token", "id_token", "csrf", "login"]
    analytics_patterns = ["analytics", "_hj", "hotjar", "mixpanel", "amplitude", "segment"]
    # "uid" replaced with "_uid" and "user_id" to avoid substring false positives
    track_patterns    = ["_ga", "_gid", "_fbp", "_fbc", "track", "_uid", "user_id",
                         "visitor", "adid", "__utma", "__utmz"]

    if any(p in name for p in auth_patterns):
        return "Auth Token"
    if any(p in name for p in analytics_patterns):
        return "Analytics"
    if any(p in name for p in track_patterns):
        return "Tracking"
    if "session" in name:
        return "Session"
    if not expires:
        return "Session"

    return "Unknown"


# ── Anomaly detection ─────────────────────────────────────────────────────────

def detect_history_gaps(history: List[Dict], cookies: List[Dict]) -> Optional[Dict]:
    history_domains: set = set()
    for h in history:
        d = _extract_domain(h.get("url", ""))
        if d:
            history_domains.add(d)

    cookie_only = []
    for c in cookies:
        host = c.get("host", "").lstrip(".").removeprefix("www.")  # FIX-1
        if not host:
            continue
        if not _domain_matches(host, history_domains):
            cookie_only.append({
                "domain": host,
                "cookie_name": c.get("name", ""),
                "cookie_created": c.get("created", ""),
            })

    if not cookie_only:
        return None

    dates = [_parse_iso(d["cookie_created"]) for d in cookie_only if d["cookie_created"]]
    dates = [d for d in dates if d is not None]
    earliest = min(dates).isoformat() if dates else ""
    latest   = max(dates).isoformat() if dates else ""

    return {
        "type": "history_gap",
        "severity": "critical",
        "title": "History Cleared — Cookies Survive",
        "description": (
            f"{len(cookie_only)} domain(s) have cookies but zero history entries. "
            f"History was likely cleared. Oldest surviving cookie: {earliest}. Newest: {latest}."
        ),
        "affected_domains": cookie_only[:50],
        "domain_count": len(cookie_only),
    }


def detect_burst_activity(
    history: List[Dict], threshold: int = 8, window_minutes: int = 5
) -> List[Dict]:
    """
    FIX-BURST: Replaced O(n²) inner scan with a two-pointer sliding window.

    Previous code:
        for i, t in enumerate(times):
            window = [s for s in times[i:] if (s - t).total_seconds() <= window_minutes * 60]

    That rescans the remaining list for every timestamp — O(n²) per domain.
    For a domain with 10,000 visits, that's 10,000 × 10,000 = 100M comparisons.

    Fixed approach:
      - Sort timestamps once: O(n log n)
      - Use two pointers (left, right) to maintain a sliding window: O(n)
      - Total: O(n log n) dominated by the sort.
    """
    domain_times: Dict[str, List[datetime]] = defaultdict(list)
    for h in history:
        dt = _parse_iso(h.get("last_visit", ""))
        if dt is None:
            continue
        d = _extract_domain(h.get("url", ""))
        if d:
            domain_times[d].append(dt)

    window_seconds = window_minutes * 60
    bursts = []

    for domain, times in domain_times.items():
        times.sort()
        left = 0
        for right in range(len(times)):
            # Shrink window from the left until it fits within window_seconds
            while (times[right] - times[left]).total_seconds() > window_seconds:
                left += 1
            window_size = right - left + 1
            if window_size >= threshold:
                bursts.append({
                    "type": "burst_activity",
                    "severity": "moderate",
                    "title": f"Burst Activity — {domain}",
                    "description": (
                        f"{window_size} visits to {domain} within {window_minutes} min "
                        f"starting {times[left].isoformat()}. May indicate automated tooling."
                    ),
                    "domain": domain,
                    "visit_count": window_size,
                    "window_start": times[left].isoformat(),
                    "window_end": times[right].isoformat(),
                })
                break   # one burst report per domain is sufficient

    return bursts


def detect_offhours_activity(history: List[Dict]) -> Optional[Dict]:
    hours = []
    for h in history:
        dt = _parse_iso(h.get("last_visit", ""))
        if dt is not None:
            hours.append(dt.hour)

    if len(hours) < 50:
        return None

    mean_hour = statistics.mean(hours)
    stdev_hour = statistics.stdev(hours)
    if stdev_hour == 0:
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
    normal_end   = int(mean_hour + threshold * stdev_hour) % 24

    return {
        "type": "offhours_activity",
        "severity": "moderate",
        "title": "Off-Hours Activity Detected",
        "description": (
            f"{len(offhours_visits)} visits outside the user's calculated normal window "
            f"(approx {normal_start:02d}:00–{normal_end:02d}:00 UTC, derived from "
            f"{len(hours)} history timestamps). Mean hour: {mean_hour:.1f}, σ={stdev_hour:.1f}."
        ),
        "offhours_count": len(offhours_visits),
        "user_mean_hour": round(mean_hour, 2),
        "user_stdev_hour": round(stdev_hour, 2),
    }


def detect_download_without_history(history: List[Dict], downloads: List[Dict]) -> List[Dict]:
    history_domains = {_extract_domain(h.get("url", "")) for h in history}
    history_domains.discard("")

    anomalies = []
    for dl in downloads:
        src = dl.get("source_url", "")
        if not src:
            continue
        src_domain = _extract_domain(src)
        if not _domain_matches(src_domain, history_domains):
            anomalies.append({
                "type": "download_without_history",
                "severity": "moderate",
                "title": f"Download Without History — {dl.get('filename', '')}",
                "description": (
                    f"File '{dl.get('filename', '')}' ({dl.get('size_bytes', 0):,} bytes) "
                    f"downloaded from {urlparse(src).netloc} — source domain absent from history. "
                    f"Possible private browsing or selective history clearing."
                ),
                "filename": dl.get("filename", ""),
                "source_url": src,
                "download_time": dl.get("start_time", ""),
            })
    return anomalies


def detect_zombie_cookies(cookies: List[Dict]) -> List[Dict]:
    # B6 FIX: was creating one anomaly per expired cookie — with hundreds of expired
    # cookies this produced 800+ entries flooding the anomaly list.
    # Now aggregates by domain: one anomaly per affected host, listing cookie names.
    from collections import defaultdict
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
            "title": f"Zombie Cookies — {host}",
            "description": (
                f"{len(entries)} expired cookie(s) still present for {host}: "
                f"{names}{extra}."
            ),
            "host": host,
            "cookie_count": len(entries),
            "cookies": entries[:10],
        })
    return zombies


# ── Heatmap pre-computation (FIX-6) ──────────────────────────────────────────

def compute_heatmap(history: List[Dict]) -> List[Dict]:
    """
    FIX-6: Pre-compute activity heatmap during analysis rather than per-request.

    Previously /api/overview iterated the full history list on every page load
    to build the 7×24 heatmap. With large evidence files (100k+ rows) this is
    significant repeated CPU work. Computing it once here and storing it in
    analysis.json makes /api/overview a cheap read.

    Returns: list of {day: int, hour: int, count: int} for all 168 cells.
    """
    grid: Dict[int, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
    for h in history:
        ts = h.get("last_visit", "")
        if not ts:
            continue
        dt = _parse_iso(ts)
        if dt is not None:
            grid[dt.weekday()][dt.hour] += 1

    return [
        {"day": day, "hour": hour, "count": grid[day][hour]}
        for day in range(7)
        for hour in range(24)
    ]


# ── Main pipeline ─────────────────────────────────────────────────────────────

def run() -> None:
    if not EVIDENCE_FILE.exists():
        print(f"[ERROR] {EVIDENCE_FILE} not found. Run extract.py first.")
        return

    evidence = json.loads(EVIDENCE_FILE.read_text(encoding="utf-8"))
    history:   List[Dict] = evidence.get("history", [])
    cookies:   List[Dict] = evidence.get("cookies", [])
    bookmarks: List[Dict] = evidence.get("bookmarks", [])
    downloads: List[Dict] = evidence.get("downloads", [])

    domain_history_count: Dict[str, int] = defaultdict(int)
    for h in history:
        d = _extract_domain(h.get("url", ""))
        if d:
            domain_history_count[d] += 1

    domain_has_cookie: Dict[str, bool] = defaultdict(bool)
    for c in cookies:
        host = c.get("host", "").lstrip(".").removeprefix("www.")  # FIX-1
        if host:
            domain_has_cookie[host] = True

    history_domains = {d for d in domain_history_count if d}

    # Score history
    scored_history = []
    for h in history:
        domain = _extract_domain(h.get("url", ""))
        score, reasons = score_url(
            h.get("url", ""), h.get("last_visit", ""),
            domain_has_cookie.get(domain, False), domain_history_count.get(domain, 0),
            h.get("transition", 0),
        )
        scored_history.append({**h, "risk_score": score, "risk_reasons": reasons})

    # Score cookies
    scored_cookies = []
    for c in cookies:
        raw_host = c.get("host", "").lstrip(".")
        cookie_domain = raw_host.removeprefix("www.")  # FIX-1
        hist_count = domain_history_count.get(cookie_domain, 0)
        if hist_count == 0:
            for hd, cnt in domain_history_count.items():
                if hd == cookie_domain or hd.endswith("." + cookie_domain):
                    hist_count = max(hist_count, cnt)
        ctype = classify_cookie(c)
        score, reasons = score_cookie(c, hist_count)
        scored_cookies.append({**c, "type": ctype, "risk_score": score, "risk_reasons": reasons})

    # Score downloads
    scored_downloads = []
    for dl in downloads:
        src_domain = _extract_domain(dl.get("source_url", ""))
        in_history = _domain_matches(src_domain, history_domains)
        score, reasons = score_download(dl, in_history)
        scored_downloads.append({**dl, "in_history": in_history, "risk_score": score, "risk_reasons": reasons})

    # Anomalies
    anomalies = []
    gap = detect_history_gaps(history, cookies)
    if gap:
        anomalies.append(gap)
    anomalies.extend(detect_burst_activity(history))
    offhours = detect_offhours_activity(history)
    if offhours:
        anomalies.append(offhours)
    anomalies.extend(detect_download_without_history(history, downloads))
    anomalies.extend(detect_zombie_cookies(cookies))

    all_scores = (
        [h["risk_score"] for h in scored_history]
        + [c["risk_score"] for c in scored_cookies]
        + [d["risk_score"] for d in scored_downloads]
    )
    flagged   = sum(1 for s in all_scores if s >= 61)
    avg_score = round(statistics.mean(all_scores), 1) if all_scores else 0.0

    domain_visits: Dict[str, int] = defaultdict(int)
    domain_max_risk: Dict[str, int] = defaultdict(int)
    for h in scored_history:
        d = _extract_domain(h.get("url", ""))
        if d:
            domain_visits[d] += 1
            domain_max_risk[d] = max(domain_max_risk[d], h["risk_score"])

    top_domains = sorted(domain_visits.items(), key=lambda x: x[1], reverse=True)[:20]

    # FIX-6: Pre-compute heatmap here once, not per-request in /api/overview
    heatmap = compute_heatmap(scored_history)

    analysis = {
        "meta": {
            **evidence.get("meta", {}),
            "analysis_time": _now_utc().isoformat(),
            "total_flagged": flagged,
            "average_risk_score": avg_score,
            "anomaly_count": len(anomalies),
        },
        "hashes": evidence.get("hashes", {}),
        "summary": {
            "total_artifacts":   len(history) + len(cookies) + len(bookmarks) + len(downloads),
            "history_count":     len(scored_history),
            "cookie_count":      len(scored_cookies),
            "bookmark_count":    len(bookmarks),
            "download_count":    len(scored_downloads),
            "flagged_count":     flagged,
            "average_risk_score": avg_score,
            "anomaly_count":     len(anomalies),
        },
        "top_domains": [
            {"domain": d, "visits": v, "risk_score": domain_max_risk.get(d, 0)}
            for d, v in top_domains
        ],
        "heatmap":   heatmap,   # FIX-6: stored here, read in /api/overview
        "anomalies": anomalies,
        "history":   scored_history,
        "cookies":   scored_cookies,
        "bookmarks": bookmarks,
        "downloads": scored_downloads,
    }

    ANALYSIS_FILE.parent.mkdir(parents=True, exist_ok=True)
    ANALYSIS_FILE.write_text(json.dumps(analysis, indent=2, ensure_ascii=False), encoding="utf-8")
    try:
        ANALYSIS_FILE.chmod(0o600)
    except Exception:
        pass
    print(f"[OK] Analysis complete. {len(anomalies)} anomalies, {flagged} flagged items → {ANALYSIS_FILE}")


if __name__ == "__main__":
    run()