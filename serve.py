#!/usr/bin/env python3
"""
BrowserForensix — serve.py  (PATCHED)
Runs analyzer, starts Flask server, opens browser automatically.

PATCH NOTES (all bugs from audit remediated):
  FIX-1  domain_of(): .lstrip("www.") → .removeprefix("www.")
  FIX-2  /api/domain/<domain>: validate input, reject single-char / pure-TLD values
  FIX-3  Duplicate /api/status fetch: removed from base.html inline <script>;
         loadStatus() in app.js is now the sole consumer.
  FIX-4  /api/timeline date filter: string comparison → datetime-aware comparison
         (mirrors the correct approach already used in /api/history).
  FIX-5  /api/sessions now includes cookies so session reconstruction matches
         /api/timeline exactly (same event set → same sessions).
  FIX-6  Heatmap computation moved from /api/overview (per-request) to analyzer.py
         (pre-computed once); /api/overview just reads data["heatmap"].
  FIX-7  CSRF / localhost origin guard added as a before_request hook.
  FIX-8  window._bfxReport removed from global scope — handled in app.js patch.
"""

import json
import math
import re
import threading
import webbrowser
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse
from collections import defaultdict

try:
    from flask import Flask, jsonify, request, render_template, abort
except ImportError:
    print("[ERROR] Flask not installed. Run: pip install flask")
    raise

import analyzer
try:
    from ai_routes import register_ai_routes
    _AI_AVAILABLE = True
except ImportError:
    _AI_AVAILABLE = False
    print("[WARN] ai_routes.py not found — AI features disabled")

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
EVIDENCE_FILE = DATA_DIR / "evidence.json"
ANALYSIS_FILE = DATA_DIR / "analysis.json"

app = Flask(__name__, template_folder="templates", static_folder="static")

# ── Data loader ───────────────────────────────────────────────────────────────

_analysis = None
_analysis_mtime: float = 0.0
_analysis_lock = threading.RLock()   # BUG-6: guard TOCTOU between stat() and read_text()

def load_analysis() -> dict:
    """Load analysis.json, re-reading from disk if the file has been modified.
    Thread-safe: RLock prevents a torn read when analyzer.run() is writing.
    """
    global _analysis, _analysis_mtime
    with _analysis_lock:
        if not ANALYSIS_FILE.exists():
            return {}
        current_mtime = ANALYSIS_FILE.stat().st_mtime
        if _analysis is None or current_mtime != _analysis_mtime:
            _analysis = json.loads(ANALYSIS_FILE.read_text(encoding="utf-8"))
            _analysis_mtime = current_mtime
        return _analysis


def reload_analysis() -> dict:
    global _analysis, _analysis_mtime
    with _analysis_lock:
        _analysis = None
        _analysis_mtime = 0.0
    return load_analysis()


# ── Helpers ───────────────────────────────────────────────────────────────────

def paginate(items: list, page: int, per_page: int = 50) -> dict:
    total = len(items)
    total_pages = max(1, math.ceil(total / per_page))
    page = max(1, min(page, total_pages))
    start = (page - 1) * per_page
    return {
        "items": items[start:start + per_page],
        "page": page,
        "per_page": per_page,
        "total": total,
        "total_pages": total_pages,
    }


def filter_risk(items: list, risk_filter: str) -> list:
    if risk_filter == "flagged":
        return [i for i in items if i.get("risk_score", 0) >= 61]
    elif risk_filter == "moderate":
        return [i for i in items if 31 <= i.get("risk_score", 0) <= 60]
    elif risk_filter == "low":
        return [i for i in items if i.get("risk_score", 0) <= 30]
    return items


def _safe_int(val, default: int = 1, minimum: int = 1, maximum: int = 10_000) -> int:
    """Parse query param as int with bounds. Never raises, never 500s."""
    try:
        return max(minimum, min(maximum, int(val)))
    except (TypeError, ValueError):
        return default


# FIX-1: Use .removeprefix("www.") instead of .lstrip("www.")
# .lstrip(chars) strips individual CHARACTERS from the set, not a literal prefix.
# "wwwwexample.com".lstrip("www.") → "example.com" (wrong — strips too much).
# .removeprefix("www.") strips the literal string only if it appears at the start.
# BUG-9 FIX: validate each label individually — RFC 1035 forbids labels that
# start or end with a hyphen (e.g. "-domain.com", "evil-.com", "a.-b.com").
# The previous single regex allowed these through.
_VALID_LABEL_RE = re.compile(r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$')

def _is_valid_domain(domain: str) -> bool:
    """Return True if domain is syntactically valid per RFC 1035."""
    if not domain or len(domain) > 253:
        return False
    labels = domain.rstrip(".").split(".")
    return len(labels) >= 2 and all(_VALID_LABEL_RE.match(lbl) for lbl in labels)

def domain_of(url: str) -> str:
    netloc = urlparse(url).netloc.lower().split(":")[0]
    return netloc.removeprefix("www.")


def _validate_domain_param(raw: str) -> str:
    """
    FIX-2: Sanitise and validate a domain path parameter.
    Rejects values that are too short, too long, or contain characters that
    would cause every item to match (e.g. ".") or are not valid domain syntax.
    Raises 400 on invalid input so the route never runs a full-list scan.
    """
    domain = raw.lower().strip().removeprefix("www.")
    if not domain or len(domain) < 4 or len(domain) > 253:
        abort(400, description="Invalid domain: must be 4–253 characters.")
    if not _is_valid_domain(domain):
        abort(400, description="Invalid domain: use only letters, digits, hyphens, dots. Labels cannot start or end with a hyphen.")
    return domain


def _norm_dt(ts: str) -> datetime | None:
    """
    Parse an ISO timestamp to a UTC-aware datetime. Returns None on failure.

    Handles two common encoding artifacts:
      - "Z" suffix → replace with "+00:00"
      - space instead of "+" in timezone offset ("+00:00" arrives as " 00:00"
        when the "+" is URL-decoded by form encoding rules rather than %2B)
    """
    if not ts:
        return None
    try:
        # Normalise: "Z" → "+00:00", then fix space-as-plus in tz offset
        # e.g. "2024-01-15T10:30:00 00:00" → "2024-01-15T10:30:00+00:00"
        normalised = ts.strip().replace("Z", "+00:00")
        # Fix space-as-plus in timezone offset: "+00:00" arrives as " 00:00"
        # when the "+" is URL-decoded by form-encoding rules (+ means space).
        # Anchored to end-of-string to avoid touching time separators.
        normalised = re.sub(r' (\d{2}:\d{2})$', r'+\1', normalised)
        return datetime.fromisoformat(normalised).astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


# FIX-7: CSRF / localhost origin guard.
# A malicious webpage can send credentialed fetch() to http://localhost:5000.
# This hook rejects API requests whose Origin or Referer is not localhost.
# Page routes (GET with no Origin) are unaffected.
@app.before_request
def _guard_api_origin():
    if not request.path.startswith("/api/"):
        return  # Only guard JSON API endpoints
    origin = request.headers.get("Origin", "")
    referer = request.headers.get("Referer", "")
    if origin:
        # Allow requests from localhost only (any port, http/https)
        if not re.match(r'^https?://(localhost|127\.0\.0\.1)(:\d+)?$', origin):
            abort(403, description="Cross-origin API access denied.")
    elif referer:
        if not re.match(r'^https?://(localhost|127\.0\.0\.1)(:\d+)?/', referer):
            abort(403, description="Cross-origin API access denied.")
    # No Origin + No Referer = same-origin curl/fetch from the page itself → allow


# ── Page routes ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("overview.html", active="overview")

@app.route("/history")
def history_page():
    return render_template("history.html", active="history")

@app.route("/cookies")
def cookies_page():
    return render_template("cookies.html", active="cookies")

@app.route("/bookmarks")
def bookmarks_page():
    return render_template("bookmarks.html", active="bookmarks")

@app.route("/downloads")
def downloads_page():
    return render_template("downloads.html", active="downloads")

@app.route("/timeline")
def timeline_page():
    return render_template("timeline.html", active="timeline")

@app.route("/investigate")
def investigate_page():
    return render_template("investigate.html", active="investigate")

@app.route("/report")
def report_page():
    return render_template("report.html", active="report")

@app.route("/ai")
def ai_page():
    return render_template("ai.html", active="ai")


# ── API: Status ───────────────────────────────────────────────────────────────

@app.route("/api/status")
def api_status():
    if not EVIDENCE_FILE.exists():
        return jsonify({
            "ready": False,
            "message": "evidence.json not found. Run: python extract.py --browser chrome",
            "evidence_path": str(EVIDENCE_FILE),
        })
    if not ANALYSIS_FILE.exists():
        return jsonify({
            "ready": False,
            "message": "analysis.json not found. Run: python serve.py (it runs the analyzer automatically).",
        })
    data = load_analysis()
    return jsonify({
        "ready": True,
        "meta": data.get("meta", {}),
        "summary": data.get("summary", {}),
        "hashes": data.get("hashes", {}),
    })


# ── API: Profiles ─────────────────────────────────────────────────────────────

@app.route("/api/profiles")
def api_profiles():
    data = load_analysis()
    if not data:
        return jsonify({"profiles": []})
    meta = data.get("meta", {})
    profiles_meta = meta.get("profiles_extracted", [])

    # Artifacts store "profile": label where label = "Default (Person 1)" etc.
    # profiles_extracted stores {"dir": "Default", "label": "Default (Person 1)", "path": "..."}
    # Match on "label" — that is what every artifact's "profile" field contains.
    counts = defaultdict(lambda: {"history": 0, "cookies": 0, "bookmarks": 0, "downloads": 0})
    for h in data.get("history",   []): counts[h.get("profile", "")]["history"]   += 1
    for c in data.get("cookies",   []): counts[c.get("profile", "")]["cookies"]   += 1
    for b in data.get("bookmarks", []): counts[b.get("profile", "")]["bookmarks"] += 1
    for d in data.get("downloads", []): counts[d.get("profile", "")]["downloads"] += 1

    profiles = []
    for p in profiles_meta:
        label = p.get("label") or p.get("name") or p.get("dir", "Unknown")
        dir_name = p.get("dir", "")
        c = counts.get(label, {"history": 0, "cookies": 0, "bookmarks": 0, "downloads": 0})
        profiles.append({
            "name":   label,     # human-readable: "Default (Person 1)", "Profile 2 (amaimakhalid009@gmail.com)"
            "dir":    dir_name,  # directory: "Default", "Profile 2"
            "path":   p.get("path", ""),
            "counts": c,
        })

    # Fallback: if profiles_extracted is empty, derive directly from artifact profile fields
    if not profiles:
        for pname, c in sorted(counts.items()):
            profiles.append({"name": pname or "Default", "dir": "", "path": "", "counts": c})

    return jsonify({"profiles": profiles, "count": len(profiles)})


# ── API: Overview ─────────────────────────────────────────────────────────────

@app.route("/api/overview")
def api_overview():
    data = load_analysis()
    if not data:
        return jsonify({"error": "No analysis data. Run extract.py first."}), 404

    # FIX-6: Heatmap is now pre-computed in analyzer.py and stored in analysis.json.
    # This endpoint simply reads it — no per-request O(n) scan over history.
    meta = data.get("meta", {})
    return jsonify({
        "summary":     data.get("summary", {}),
        "anomalies":   data.get("anomalies", []),
        "top_domains": data.get("top_domains", []),
        "heatmap":     data.get("heatmap", []),
        "meta":        meta,
        "hashes":      data.get("hashes", {}),
        "profiles":    meta.get("profiles_extracted", []),
    })


# ── API: History ──────────────────────────────────────────────────────────────

@app.route("/api/history")
def api_history():
    data = load_analysis()
    items = data.get("history", [])

    q = request.args.get("q", "").lower()
    profile  = request.args.get("profile", "").strip()
    protocol = request.args.get("protocol", "all").lower()
    risk = request.args.get("risk", "any").lower()
    date_from = request.args.get("from", "")
    date_to = request.args.get("to", "")
    page = _safe_int(request.args.get("page", 1))

    if profile:
        items = [i for i in items if i.get("profile", "") == profile]

    if q:
        items = [i for i in items if q in i.get("url", "").lower() or q in i.get("title", "").lower()]

    if protocol in ("http", "https"):
        items = [i for i in items if i.get("url", "").startswith(protocol + "://")]

    if risk != "any":
        items = filter_risk(items, risk)

    if date_from or date_to:
        df = _norm_dt(date_from + "T00:00:00+00:00") if date_from else None
        dt_end = _norm_dt(date_to + "T23:59:59+00:00") if date_to else None

        def _in_range(item):
            ts = _norm_dt(item.get("last_visit", ""))
            if ts is None:
                return True
            if df and ts < df:
                return False
            if dt_end and ts > dt_end:
                return False
            return True
        items = [i for i in items if _in_range(i)]

    return jsonify(paginate(items, page))


# ── API: Cookies ──────────────────────────────────────────────────────────────

@app.route("/api/cookies")
def api_cookies():
    data = load_analysis()
    items = data.get("cookies", [])

    profile = request.args.get("profile", "").strip()
    ctype  = request.args.get("type", "all").lower()
    host   = request.args.get("host", "").strip().lower()
    expired = request.args.get("expired", "all")
    # FIX (secure filter): read the secure param and actually apply it
    secure  = request.args.get("secure", "all")
    page   = _safe_int(request.args.get("page", 1))

    if profile:
        items = [i for i in items if i.get("profile", "") == profile]

    if ctype != "all":
        items = [i for i in items if i.get("type", "").lower() == ctype]

    # FIX (host filter): was never applied because cookieState.host was never
    # set and the param was never sent. Both sides are fixed (see app.js patch).
    if host:
        items = [i for i in items if host in i.get("host", "").lower()]

    if expired == "yes":
        items = [i for i in items if i.get("type") == "Zombie"]
    elif expired == "no":
        items = [i for i in items if i.get("type") != "Zombie"]

    # FIX (secure filter): was stored in cookieState.secure but never sent or
    # applied. Now both sides are wired up.
    if secure == "secure":
        items = [i for i in items if i.get("secure", False)]
    elif secure == "insecure":
        items = [i for i in items if not i.get("secure", False)]

    return jsonify(paginate(items, page))


# ── API: Bookmarks ────────────────────────────────────────────────────────────

@app.route("/api/bookmarks")
def api_bookmarks():
    data = load_analysis()
    bookmarks = data.get("bookmarks", [])

    tree = defaultdict(list)
    for b in bookmarks:
        folder = b.get("folder", "Other")
        tree[folder].append(b)

    q = request.args.get("q", "").lower()
    if q:
        bookmarks = [b for b in bookmarks
                     if q in b.get("title", "").lower() or q in b.get("url", "").lower()]
        return jsonify({"items": bookmarks, "total": len(bookmarks)})

    return jsonify({
        "tree": {k: v for k, v in tree.items()},
        "total": len(bookmarks),
    })


# ── API: Downloads ────────────────────────────────────────────────────────────

@app.route("/api/downloads")
def api_downloads():
    data = load_analysis()
    items = data.get("downloads", [])

    q = request.args.get("q", "").lower()
    profile = request.args.get("profile", "").strip()
    risk = request.args.get("risk", "any").lower()
    page = _safe_int(request.args.get("page", 1))

    if profile:
        items = [i for i in items if i.get("profile", "") == profile]

    if q:
        items = [i for i in items if q in i.get("filename", "").lower()
                 or q in i.get("source_url", "").lower()]
    if risk != "any":
        items = filter_risk(items, risk)

    return jsonify(paginate(items, page))


# ── Session reconstruction ────────────────────────────────────────────────────

def _build_unified_events(data: dict, types: set | None = None) -> list:
    """
    FIX-5: Single source of truth for timeline/session events.
    Both /api/timeline and /api/sessions call this, so they always produce
    identical session groupings for the same type set.

    If types is None, all event types are included.
    """
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
        """Parse event time to UTC datetime for correct sort order.
        Falls back to epoch so unparseable events sink to the bottom."""
        ts = e.get("time", "")
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)
        except (ValueError, TypeError):
            return datetime.fromtimestamp(0, tz=timezone.utc)

    events.sort(key=_sort_key, reverse=True)
    return events


def _reconstruct_sessions(events: list, gap_seconds: int = 1800) -> list:
    """
    Group events (sorted newest-first) into browsing sessions.
    A new session starts when the gap between consecutive events exceeds
    gap_seconds (default 30 min).

    Returns sessions sorted newest-first, each with: start, end, count, events.
    """
    if not events:
        return []

    sessions: list[list] = []
    current: list = []
    last_t: datetime | None = None

    # Work oldest-first to accumulate sessions in chronological order
    for e in reversed(events):
        t = _norm_dt(e.get("time", ""))
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

    sessions.reverse()   # newest session first
    return [
        {
            "start": s[0]["time"],
            "end":   s[-1]["time"],
            "count": len(s),
            "events": s,
        }
        for s in sessions
    ]


# ── API: Timeline ─────────────────────────────────────────────────────────────

@app.route("/api/timeline")
def api_timeline():
    data = load_analysis()
    types_param = request.args.get("types", "history,cookies,downloads")
    types = set(types_param.split(","))

    events = _build_unified_events(data, types)

    # FIX-4: Use datetime-aware comparison for date filtering, not raw string
    # comparison. String comparison breaks when timestamps have mixed timezone
    # suffixes (Z vs +00:00) or different precision.
    date_from_str = request.args.get("from", "")
    date_to_str   = request.args.get("to", "")

    if date_from_str or date_to_str:
        df     = _norm_dt(date_from_str) if date_from_str else None
        dt_end = _norm_dt(date_to_str)   if date_to_str   else None

        def _in_range(e: dict) -> bool:
            ts = _norm_dt(e.get("time", ""))
            if ts is None:
                return True
            if df     and ts < df:     return False
            if dt_end and ts > dt_end: return False
            return True

        events = [e for e in events if _in_range(e)]

    sessions = _reconstruct_sessions(events)
    return jsonify({
        "events": events[:500],
        "sessions": sessions,
        "total": len(events),
    })


# ── API: Domain ───────────────────────────────────────────────────────────────

@app.route("/api/domain/<domain>")
def api_domain(domain: str):
    # FIX-2: Validate domain before running any list comprehensions.
    # Without validation, "." matches every item (every domain contains ".").
    domain = _validate_domain_param(domain)

    data = load_analysis()

    def _matches_domain(candidate: str) -> bool:
        # Exact match OR subdomain match — not a raw substring.
        # "oogle" must NOT match "google.com"; "api.google.com" SHOULD match "google.com".
        return candidate == domain or candidate.endswith("." + domain)

    history   = [h for h in data.get("history",   []) if _matches_domain(domain_of(h.get("url", "")))]
    cookies   = [c for c in data.get("cookies",   []) if _matches_domain(c.get("host", "").lstrip(".").removeprefix("www."))]
    downloads = [d for d in data.get("downloads", []) if _matches_domain(domain_of(d.get("source_url", "")))]

    # BUG-17 FIX: parse timestamps before comparing — string min/max is wrong
    # when timestamps mix "Z" and "+00:00" suffixes ("Z" > "+" in ASCII).
    parsed_times = [_norm_dt(h.get("last_visit", "")) for h in history]
    parsed_times = [t for t in parsed_times if t is not None]
    first_seen = min(parsed_times).isoformat() if parsed_times else ""
    last_seen  = max(parsed_times).isoformat() if parsed_times else ""

    max_risk = max((h.get("risk_score", 0) for h in history), default=0)
    risk_reasons = list({r for h in history for r in h.get("risk_reasons", [])})

    return jsonify({
        "domain":        domain,
        "history":       history,
        "cookies":       cookies,
        "downloads":     downloads,
        "first_seen":    first_seen,
        "last_seen":     last_seen,
        "total_visits":  sum(h.get("visit_count", 1) for h in history),
        "max_risk_score": max_risk,
        "risk_reasons":  risk_reasons,
        "in_history":    len(history) > 0,
    })


# ── API: Sessions ─────────────────────────────────────────────────────────────

@app.route("/api/sessions")
def api_sessions():
    """
    FIX-5: Uses the same _build_unified_events() as /api/timeline, so the
    Session Viewer and Timeline always reconstruct identical sessions.
    Previously /api/sessions omitted cookies, causing the two views to diverge.
    """
    data = load_analysis()
    # Include all three event types to match /api/timeline's default
    events = _build_unified_events(data, types={"history", "cookies", "downloads"})
    return jsonify({"sessions": _reconstruct_sessions(events)})


# ── API: Search ───────────────────────────────────────────────────────────────

@app.route("/api/search")
def api_search():
    data = load_analysis()
    q = request.args.get("q", "").lower()
    if not q or len(q) < 2:
        return jsonify({"error": "Query too short"}), 400

    # BUG-7 FIX: compute true counts before slicing so "total" is accurate
    all_history   = [h for h in data.get("history",   []) if q in h.get("url",      "").lower() or q in h.get("title",      "").lower()]
    all_cookies   = [c for c in data.get("cookies",   []) if q in c.get("host",     "").lower() or q in c.get("name",       "").lower()]
    all_bookmarks = [b for b in data.get("bookmarks", []) if q in b.get("title",    "").lower() or q in b.get("url",        "").lower()]
    all_downloads = [d for d in data.get("downloads", []) if q in d.get("filename", "").lower() or q in d.get("source_url", "").lower()]

    results = {
        "history":       all_history[:20],
        "cookies":       all_cookies[:20],
        "bookmarks":     all_bookmarks[:20],
        "downloads":     all_downloads[:20],
        "total":         len(all_history) + len(all_cookies) + len(all_bookmarks) + len(all_downloads),
        "total_preview": 20,
    }
    return jsonify(results)


# ── API: Report ───────────────────────────────────────────────────────────────

@app.route("/api/report")
def api_report():
    data = load_analysis()
    flagged_history   = [h for h in data.get("history",   []) if h.get("risk_score", 0) >= 61]
    flagged_cookies   = [c for c in data.get("cookies",   []) if c.get("risk_score", 0) >= 61]
    flagged_downloads = [d for d in data.get("downloads", []) if d.get("risk_score", 0) >= 61]

    return jsonify({
        "meta":     data.get("meta", {}),
        "hashes":   data.get("hashes", {}),
        "summary":  data.get("summary", {}),
        "anomalies": data.get("anomalies", []),
        "flagged": {
            "history":   flagged_history,
            "cookies":   flagged_cookies,
            "downloads": flagged_downloads,
        },
    })


# ── Startup ───────────────────────────────────────────────────────────────────

def startup():
    print("\n=== BrowserForensix ===")
    if not EVIDENCE_FILE.exists():
        print(f"[WARN] No evidence.json found at {EVIDENCE_FILE}")
        print("       Run: python extract.py --browser chrome")
        print("       The server will start, but all pages will show a setup banner.\n")
    else:
        print("[INFO] Running analyzer…")
        try:
            analyzer.run()
        except Exception as e:
            print(f"[ERROR] Analyzer failed: {e}")

    if _AI_AVAILABLE:
        register_ai_routes(app, load_analysis)
    else:
        print("[INFO] AI features not available — add ai_engine.py and ai_routes.py")

    print("[INFO] Starting Flask on http://localhost:5000")
    threading.Timer(1.2, lambda: webbrowser.open("http://localhost:5000")).start()


if __name__ == "__main__":
    startup()
    app.run(host="127.0.0.1", port=5000, debug=False)