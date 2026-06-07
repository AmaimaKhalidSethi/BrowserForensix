"""Risk scoring and cookie classification helpers."""

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple
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
    score = 0
    reasons = []

    parsed = urlparse(url)
    host = parsed.netloc.lower().split(":")[0]
    path = parsed.path.lower()

    if url.startswith("http://") and not _IP_RE.match(host):
        score += 20
        reasons.append("plain HTTP")

    if _IP_RE.match(host):
        score += 30
        reasons.append("direct IP access")

    for tld in _SUSPICIOUS_TLDS:
        if host.endswith(tld):
            score += 20
            reasons.append(f"suspicious TLD ({tld})")
            break

    combined = host + path
    for keyword in _SUSPICIOUS_KEYWORDS:
        if keyword in combined:
            score += 25
            reasons.append(f"suspicious keyword: {keyword}")
            break

    dt = _parse_iso(last_visit)
    if dt and (dt.hour >= 23 or dt.hour < 5):
        score += 10
        reasons.append("off-hours visit (2-5am UTC)")

    if visit_count == 1 and transition == 1:
        score += 5
        reasons.append("single visit via typed/redirect")

    return min(score, 100), reasons


def classify_cookie(cookie: dict) -> str:
    name = str(cookie.get("name", "") or "").lower()
    expires = str(cookie.get("expires", "") or "")

    auth_names = {
        "token", "jwt", "access_token", "refresh_token",
        "id_token", "bearer", "api_key", "apikey",
    }
    if any(auth_name in name for auth_name in auth_names):
        return "Auth Token"

    track_names = {
        "_fbp", "_fbc", "__utma", "__utmz", "fr", "_gcl_au",
        "mp_", "ajs_", "hubspot", "intercom", "mixpanel",
    }
    if any(name.startswith(track_name) for track_name in track_names):
        return "Tracking"

    if name.startswith(("_ga", "_gid", "__utm", "amplitude", "heap")):
        return "Analytics"

    if not expires:
        return "Session"

    exp_dt = _parse_iso(expires)
    if exp_dt and exp_dt < _now_utc():
        return "Zombie"

    return "Unknown"


def score_cookie(cookie: dict, history_count: int) -> Tuple[int, List[str]]:
    score = 0
    reasons = []

    host = str(cookie.get("host", "") or "").lstrip(".")
    expires = str(cookie.get("expires", "") or "")

    if _IP_RE.match(host):
        score += 35
        reasons.append("cookie from direct IP")

    if not cookie.get("secure", True):
        score += 10
        reasons.append("insecure cookie (no Secure flag)")

    if history_count == 0:
        score += 30
        reasons.append("host absent from history - possible cleared history")

    exp_dt = _parse_iso(expires)
    if exp_dt and exp_dt < _now_utc():
        score += 5
        reasons.append("expired (zombie) cookie")

    if exp_dt and (exp_dt - _now_utc()).days > 365:
        score += 15
        reasons.append("cookie lifetime > 365 days")

    for keyword in _SUSPICIOUS_KEYWORDS:
        if keyword in host:
            score += 20
            reasons.append(f"suspicious host keyword: {keyword}")
            break

    return min(score, 100), reasons


def score_download(download: dict, in_history: bool) -> Tuple[int, List[str]]:
    score = 0
    reasons = []

    filename = download.get("filename", "").lower()
    source = download.get("source_url", "").lower()
    exists = download.get("file_exists", True)
    danger = download.get("danger_type", 0)

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
