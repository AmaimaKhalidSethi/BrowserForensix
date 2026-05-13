#!/usr/bin/env python3
"""
BrowserForensix — analyzer.py
Scores and annotates all browser artifacts, writes analysis.json.

FIX-10: analysis.json is now written atomically via a temp file + os.replace().
         Previously ANALYSIS_FILE.write_text() wrote directly, so a concurrent
         load_analysis() call could read a torn/partial JSON file and crash with
         JSONDecodeError. os.replace() is atomic on all POSIX systems and on
         Windows (same volume), so readers always see a complete file.
"""

import json
import math
import os
import re
import statistics
import tempfile
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

BASE_DIR      = Path(__file__).parent
DATA_DIR      = BASE_DIR / "data"
EVIDENCE_FILE = DATA_DIR / "evidence.json"
ANALYSIS_FILE = DATA_DIR / "analysis.json"


# ── Datetime helpers ──────────────────────────────────────────────────────────

def _now_utc() -> datetime:
    return datetime.now(tz=timezone.utc)


def _parse_iso(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


# ── Domain helpers ────────────────────────────────────────────────────────────

def _extract_domain(url: str) -> str:
    try:
        netloc = urlparse(url).netloc.lower()
        host   = netloc.split(":")[0]
        return host.removeprefix("www.")
    except Exception:
        return ""


def _domain_matches(candidate: str, domain_set: set) -> bool:
    if not candidate:
        return False
    candidate_parts = candidate.split('.')
    for d in domain_set:
        d_parts = d.split('.')
        # Check if candidate is subdomain of d or vice versa
        if len(candidate_parts) > len(d_parts) and candidate_parts[-len(d_parts):] == d_parts:
            return True
        if len(d_parts) > len(candidate_parts) and d_parts[-len(candidate_parts):] == candidate_parts:
            return True
        if candidate_parts == d_parts:
            return True
    return False


# ── Risk scoring ──────────────────────────────────────────────────────────────

_SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".pw", ".cc", ".su", ".ws", ".biz",
}

_SUSPICIOUS_KEYWORDS = [
    "pastebin", "paste", "hastebin", "ghostbin", "rentry",
    "filebin", "file.io", "transfer.sh", "send.cm",
    "tempfile", "gofile", "anonfiles",
    "onion", "tor2web", "i2p",
    "crypter", "rat", "keylogger", "stealer",
    "exfil", "c2", "c&c", "payload", "dropper",
    "vpngate", "mullvad", "protonvpn",
]

_HIGH_RISK_EXTENSIONS = {
    ".exe", ".msi", ".bat", ".cmd", ".ps1", ".psm1", ".psd1",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".sh", ".bash", ".zsh",
    ".dmg", ".pkg", ".app",
    ".dll", ".sys", ".drv",
    ".scr", ".pif", ".com",
    ".jar", ".class",
    ".py", ".rb", ".pl", ".php",
    ".macro", ".xlsm", ".docm", ".pptm",
}

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def score_url(
    url: str,
    last_visit: str,
    has_cookie: bool,
    visit_count: int,
    transition: int,
) -> Tuple[int, List[str]]:
    score   = 0
    reasons = []

    parsed = urlparse(url)
    host   = parsed.netloc.lower().split(":")[0]
    path   = parsed.path.lower()

    # Protocol
    if url.startswith("http://") and not _IP_RE.match(host):
        score += 5
        reasons.append("plain HTTP")

    # IP address access
    if _IP_RE.match(host):
        score += 30
        reasons.append("direct IP access")

    # Suspicious TLD
    for tld in _SUSPICIOUS_TLDS:
        if host.endswith(tld):
            score += 20
            reasons.append(f"suspicious TLD ({tld})")
            break

    # Suspicious keywords in domain or path
    combined = host + path
    for kw in _SUSPICIOUS_KEYWORDS:
        if kw in combined:
            score += 25
            reasons.append(f"suspicious keyword: {kw}")
            break

    # Off-hours visit (2–5 AM UTC)
    dt = _parse_iso(last_visit)
    if dt and 2 <= dt.hour < 5:
        score += 10
        reasons.append("off-hours visit (2–5am UTC)")

    # Single visit — could indicate recon / one-shot upload
    if visit_count == 1 and transition == 1:
        score += 5
        reasons.append("single visit via typed/redirect")

    return min(score, 100), reasons


def classify_cookie(cookie: dict) -> str:
    # FIX-A: cookie fields (name, value, samesite, expires) can be non-string
    # (e.g. integers) if the evidence extractor serialises them without coercion.
    # All reads now go through str() before any string method is called so we
    # never get "'int' object has no attribute 'lower'".
    name    = str(cookie.get("name",    "") or "").lower()
    value   = str(cookie.get("value",   "") or "")
    expires = str(cookie.get("expires", "") or "")
    flags = {
        "secure":    bool(cookie.get("secure", False)),
        "http_only": bool(cookie.get("http_only", False)),
        "samesite":  str(cookie.get("samesite") or "").lower(),
    }

    # Auth token heuristics
    auth_names = {"token", "jwt", "access_token", "refresh_token",
                  "id_token", "bearer", "api_key", "apikey"}
    if any(a in name for a in auth_names):
        return "Auth Token"

    # Tracking
    track_names = {"_ga", "_gid", "_fbp", "_fbc", "__utma", "__utmz", "fr", "_gcl_au",
                   "mp_", "ajs_", "hubspot", "intercom", "mixpanel"}
    if any(name.startswith(t) for t in track_names):
        return "Tracking"

    # Analytics
    if name.startswith(("_ga", "_gid", "__utm", "amplitude", "heap")):
        return "Analytics"

    # Session cookie (no expiry)
    if not expires:
        return "Session"

    # Zombie (expired)
    exp_dt = _parse_iso(expires)
    if exp_dt and exp_dt < _now_utc():
        return "Zombie"

    return "Unknown"


def score_cookie(cookie: dict, history_count: int) -> Tuple[int, List[str]]:
    score   = 0
    reasons = []

    # FIX-A: str() coercion — host and expires can be int/None from extractor
    host    = str(cookie.get("host",    "") or "").lstrip(".")
    expires = str(cookie.get("expires", "") or "")

    if _IP_RE.match(host):
        score += 35
        reasons.append("cookie from direct IP")

    if not cookie.get("secure", True):
        score += 10
        reasons.append("insecure cookie (no Secure flag)")

    if history_count == 0:
        score += 30
        reasons.append("host absent from history — possible cleared history")

    exp_dt  = _parse_iso(expires)
    if exp_dt and exp_dt < _now_utc():
        score += 5
        reasons.append("expired (zombie) cookie")

    for kw in _SUSPICIOUS_KEYWORDS:
        if kw in host:
            score += 20
            reasons.append(f"suspicious host keyword: {kw}")
            break

    return min(score, 100), reasons


def score_download(download: dict, in_history: bool) -> Tuple[int, List[str]]:
    score   = 0
    reasons = []

    filename = download.get("filename", "").lower()
    source   = download.get("source_url", "").lower()
    exists   = download.get("file_exists", True)
    danger   = download.get("danger_type", 0)

    ext = Path(filename).suffix.lower() if filename else ""

    if not in_history:
        score += 30
        reasons.append("source domain absent from history")

    if ext in _HIGH_RISK_EXTENSIONS:
        score += 20
        reasons.append(f"high-risk extension ({ext})")

    if not exists:
        score += 20
        reasons.append("file missing from disk")

    if danger and danger > 0:
        score += 20
        reasons.append(f"Chrome danger flag ({danger})")

    archive_exts = {".zip", ".tar", ".gz", ".bz2", ".7z", ".rar", ".tgz"}
    if ext in archive_exts:
        score += 10
        reasons.append("archive file")

    if _IP_RE.match(urlparse(source).netloc.split(":")[0]):
        score += 25
        reasons.append("downloaded from IP address")

    return min(score, 100), reasons


# ── Anomaly detectors ─────────────────────────────────────────────────────────

def detect_history_gaps(history: List[Dict], cookies: List[Dict]) -> Optional[Dict]:
    history_domains = {_extract_domain(h.get("url", "")) for h in history}
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
        "type":            "history_gap",
        "severity":        "critical",
        "title":           "History Clearing Detected",
        "description":     (
            f"{len(unique_ghosts)} domain(s) have cookies but no history entries. "
            f"This strongly indicates selective or complete browser history clearing. "
            f"Domains include: {', '.join(unique_ghosts[:8])}"
            + (f" (+{len(unique_ghosts)-8} more)" if len(unique_ghosts) > 8 else "")
        ),
        "domain_count":    len(unique_ghosts),
        "affected_domains": unique_ghosts[:20],
    }


def detect_burst_activity(history: List[Dict], burst_threshold: int = 20,
                           window_minutes: int = 5) -> List[Dict]:
    timestamped = []
    for h in history:
        dt = _parse_iso(h.get("last_visit", ""))
        if dt:
            timestamped.append((dt, h))
    timestamped.sort(key=lambda x: x[0])

    anomalies = []
    for i, (t0, _) in enumerate(timestamped):
        window = [h for (t, h) in timestamped[i:]
                  if (t - t0).total_seconds() <= window_minutes * 60]
        if len(window) >= burst_threshold:
            domains = list({_extract_domain(h.get("url", "")) for h in window})
            anomalies.append({
                "type":        "burst_activity",
                "severity":    "moderate",
                "title":       f"Burst Activity — {len(window)} URLs in {window_minutes} min",
                "description": (
                    f"{len(window)} history entries recorded within {window_minutes} minutes "
                    f"starting {t0.isoformat()}. Domains: {', '.join(domains[:5])}"
                ),
                "start_time":  t0.isoformat(),
                "url_count":   len(window),
                "domains":     domains[:10],
            })
            # Removed break to detect all bursts

    return anomalies


def _circular_mean(hours: list) -> float:
    import math
    n = len(hours)
    sin_sum = sum(math.sin(2 * math.pi * h / 24) for h in hours)
    cos_sum = sum(math.cos(2 * math.pi * h / 24) for h in hours)
    mean_rad = math.atan2(sin_sum / n, cos_sum / n)
    return (math.degrees(mean_rad) * 24 / 360) % 24


def _circular_stdev(hours: list, mean_hour: float) -> float:
    import math
    n = len(hours)
    sin_sum = sum(math.sin(2 * math.pi * h / 24) for h in hours)
    cos_sum = sum(math.cos(2 * math.pi * h / 24) for h in hours)
    R = math.sqrt((sin_sum / n) ** 2 + (cos_sum / n) ** 2)
    R = max(1e-10, min(R, 1 - 1e-10))
    return math.sqrt(-2 * math.log(R)) * 24 / (2 * math.pi)


def detect_offhours_activity(history: List[Dict]) -> Optional[Dict]:
    hours = []
    for h in history:
        dt = _parse_iso(h.get("last_visit", ""))
        if dt is not None:
            hours.append(dt.hour)

    if len(hours) < 50:
        return None

    mean_hour  = _circular_mean(hours)
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
    normal_end   = int(mean_hour + threshold * stdev_hour) % 24

    return {
        "type":        "offhours_activity",
        "severity":    "moderate",
        "title":       "Off-Hours Activity Detected",
        "description": (
            f"{len(offhours_visits)} visits outside the user's calculated normal window "
            f"(approx {normal_start:02d}:00–{normal_end:02d}:00 UTC, derived from "
            f"{len(hours)} history timestamps). Mean hour: {mean_hour:.1f}, σ={stdev_hour:.1f}."
        ),
        "offhours_count":  len(offhours_visits),
        "user_mean_hour":  round(mean_hour, 2),
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
                "type":          "download_without_history",
                "severity":      "moderate",
                "title":         f"Download Without History — {dl.get('filename', '')}",
                "description":   (
                    f"File '{dl.get('filename', '')}' ({dl.get('size_bytes', 0):,} bytes) "
                    f"downloaded from {urlparse(src).netloc} — source domain absent from history. "
                    f"Possible private browsing or selective history clearing."
                ),
                "filename":      dl.get("filename", ""),
                "source_url":    src,
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
                "name":    c.get("name", ""),
                "expired": exp_dt.isoformat(),
            })

    zombies = []
    for host, entries in sorted(host_zombies.items()):
        names = ", ".join(e["name"] for e in entries[:5])
        extra = f" (+{len(entries)-5} more)" if len(entries) > 5 else ""
        zombies.append({
            "type":         "zombie_cookie",
            "severity":     "low",
            "title":        f"Zombie Cookies — {host}",
            "description":  (
                f"{len(entries)} expired cookie(s) still present for {host}: "
                f"{names}{extra}."
            ),
            "host":         host,
            "cookie_count": len(entries),
            "cookies":      entries[:10],
        })
    return zombies


# ── Heatmap ───────────────────────────────────────────────────────────────────

def compute_heatmap(history: List[Dict]) -> List[Dict]:
    grid: Dict[int, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
    for h in history:
        ts = h.get("last_visit", "")
        if not ts:
            continue
        dt = _parse_iso(ts)
        if dt is not None:
            # Adjust weekday to Sunday=0 (Python weekday() is Monday=0)
            day = (dt.weekday() + 1) % 7
            grid[day][dt.hour] += 1

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

    # Load evidence.json with retry to handle concurrent writes
    for attempt in range(3):
        try:
            evidence = json.loads(EVIDENCE_FILE.read_text(encoding="utf-8"))
            break
        except json.JSONDecodeError as e:
            if attempt < 2:
                time.sleep(0.1 * (attempt + 1))  # Exponential backoff
            else:
                raise RuntimeError(f"Failed to load {EVIDENCE_FILE} after 3 attempts: {e}") from e
    history:   List[Dict] = evidence.get("history",   [])
    cookies:   List[Dict] = evidence.get("cookies",   [])
    bookmarks: List[Dict] = evidence.get("bookmarks", [])
    downloads: List[Dict] = evidence.get("downloads", [])

    domain_history_count: Dict[str, int] = defaultdict(int)
    for h in history:
        d = _extract_domain(h.get("url", ""))
        if d:
            domain_history_count[d] += 1

    domain_has_cookie: Dict[str, bool] = defaultdict(bool)
    for c in cookies:
        host = c.get("host", "").lstrip(".").removeprefix("www.")
        if host:
            domain_has_cookie[host] = True

    history_domains = {d for d in domain_history_count if d}

    scored_history = []
    for h in history:
        domain = _extract_domain(h.get("url", ""))
        score, reasons = score_url(
            h.get("url", ""), h.get("last_visit", ""),
            domain_has_cookie.get(domain, False), domain_history_count.get(domain, 0),
            h.get("transition", 0),
        )
        scored_history.append({**h, "risk_score": score, "risk_reasons": reasons})

    scored_cookies = []
    for c in cookies:
        raw_host     = c.get("host", "").lstrip(".")
        cookie_domain = raw_host.removeprefix("www.")
        hist_count   = domain_history_count.get(cookie_domain, 0)
        if hist_count == 0:
            for hd, cnt in domain_history_count.items():
                if hd == cookie_domain or hd.endswith("." + cookie_domain):
                    hist_count = max(hist_count, cnt)
        ctype        = classify_cookie(c)
        score, reasons = score_cookie(c, hist_count)
        scored_cookies.append({**c, "type": ctype, "risk_score": score, "risk_reasons": reasons})

    scored_downloads = []
    for dl in downloads:
        src_domain = _extract_domain(dl.get("source_url", ""))
        in_history = _domain_matches(src_domain, history_domains)
        score, reasons = score_download(dl, in_history)
        scored_downloads.append({**dl, "in_history": in_history, "risk_score": score, "risk_reasons": reasons})

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

    domain_visits:   Dict[str, int] = defaultdict(int)
    domain_max_risk: Dict[str, int] = defaultdict(int)
    for h in scored_history:
        d = _extract_domain(h.get("url", ""))
        if d:
            domain_visits[d]   += 1
            domain_max_risk[d]  = max(domain_max_risk[d], h["risk_score"])

    top_domains = sorted(domain_visits.items(), key=lambda x: x[1], reverse=True)[:20]
    heatmap     = compute_heatmap(scored_history)

    analysis = {
        "meta": {
            **evidence.get("meta", {}),
            "analysis_time":      _now_utc().isoformat(),
            "total_flagged":      flagged,
            "average_risk_score": avg_score,
            "anomaly_count":      len(anomalies),
        },
        "hashes":   evidence.get("hashes", {}),
        "summary": {
            "total_artifacts":    len(history) + len(cookies) + len(bookmarks) + len(downloads),
            "history_count":      len(scored_history),
            "cookie_count":       len(scored_cookies),
            "bookmark_count":     len(bookmarks),
            "download_count":     len(scored_downloads),
            "flagged_count":      flagged,
            "average_risk_score": avg_score,
            "anomaly_count":      len(anomalies),
        },
        "top_domains": [
            {"domain": d, "visits": v, "risk_score": domain_max_risk.get(d, 0)}
            for d, v in top_domains
        ],
        "heatmap":   heatmap,
        "anomalies": anomalies,
        "history":   scored_history,
        "cookies":   scored_cookies,
        "bookmarks": bookmarks,
        "downloads": scored_downloads,
    }

    # FIX-10: Atomic write — write to a sibling temp file then os.replace() into place.
    # This guarantees load_analysis() always reads a complete, valid JSON file even
    # if a server request arrives mid-write. os.replace() is atomic on POSIX and on
    # Windows when src and dst are on the same volume (same DATA_DIR).
    ANALYSIS_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        dir=ANALYSIS_FILE.parent,
        prefix=".analysis_tmp_",
        suffix=".json",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(analysis, f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, ANALYSIS_FILE)
    except Exception:
        # Clean up temp file on failure; don't leave partial files around.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    try:
        ANALYSIS_FILE.chmod(0o600)
    except Exception:
        pass

    print(f"[OK] Analysis complete. {len(anomalies)} anomalies, {flagged} flagged items → {ANALYSIS_FILE}")


if __name__ == "__main__":
    run()