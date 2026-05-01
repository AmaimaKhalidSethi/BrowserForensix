#!/usr/bin/env python3
"""
BrowserForensix — serve.py
Runs analyzer, starts Flask server, opens browser automatically.
"""

import json
import math
import threading
import webbrowser
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse
from collections import defaultdict

try:
    from flask import Flask, jsonify, request, render_template
except ImportError:
    print("[ERROR] Flask not installed. Run: pip install flask")
    raise

import analyzer

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
EVIDENCE_FILE = DATA_DIR / "evidence.json"
ANALYSIS_FILE = DATA_DIR / "analysis.json"

app = Flask(__name__, template_folder="templates", static_folder="static")

# ── Data loader ───────────────────────────────────────────────────────────────

_analysis = None
_analysis_mtime: float = 0.0

def load_analysis() -> dict:
    """Load analysis.json, re-reading from disk if the file has been modified."""
    global _analysis, _analysis_mtime
    if not ANALYSIS_FILE.exists():
        return {}
    current_mtime = ANALYSIS_FILE.stat().st_mtime
    if _analysis is None or current_mtime != _analysis_mtime:
        _analysis = json.loads(ANALYSIS_FILE.read_text(encoding="utf-8"))
        _analysis_mtime = current_mtime
    return _analysis

def reload_analysis() -> dict:
    global _analysis, _analysis_mtime
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

def domain_of(url: str) -> str:
    return urlparse(url).netloc.lower().split(":")[0].lstrip("www.")

# ── Page routes ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("overview.html")

@app.route("/history")
def history_page():
    return render_template("history.html")

@app.route("/cookies")
def cookies_page():
    return render_template("cookies.html")

@app.route("/bookmarks")
def bookmarks_page():
    return render_template("bookmarks.html")

@app.route("/downloads")
def downloads_page():
    return render_template("downloads.html")

@app.route("/timeline")
def timeline_page():
    return render_template("timeline.html")

@app.route("/investigate")
def investigate_page():
    return render_template("investigate.html")

@app.route("/report")
def report_page():
    return render_template("report.html")

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
    })

# ── API: Overview ─────────────────────────────────────────────────────────────

@app.route("/api/overview")
def api_overview():
    data = load_analysis()
    if not data:
        return jsonify({"error": "No analysis data. Run extract.py first."}), 404

    # Activity heatmap (hour x day of week)
    heatmap = defaultdict(lambda: defaultdict(int))
    for h in data.get("history", []):
        if h.get("last_visit"):
            try:
                dt = datetime.fromisoformat(h["last_visit"].replace("Z", "+00:00"))
                heatmap[dt.weekday()][dt.hour] += 1  # one event = one tick
            except Exception:
                pass

    heatmap_out = [
        {"day": day, "hour": hour, "count": heatmap[day][hour]}
        for day in range(7)
        for hour in range(24)
    ]

    return jsonify({
        "summary": data.get("summary", {}),
        "anomalies": data.get("anomalies", []),
        "top_domains": data.get("top_domains", []),
        "heatmap": heatmap_out,
        "meta": data.get("meta", {}),
        "hashes": data.get("hashes", {}),
    })

# ── API: History ──────────────────────────────────────────────────────────────

@app.route("/api/history")
def api_history():
    data = load_analysis()
    items = data.get("history", [])

    q = request.args.get("q", "").lower()
    protocol = request.args.get("protocol", "all").lower()
    risk = request.args.get("risk", "any").lower()
    date_from = request.args.get("from", "")
    date_to = request.args.get("to", "")
    page = _safe_int(request.args.get("page", 1))

    if q:
        items = [i for i in items if q in i.get("url", "").lower() or q in i.get("title", "").lower()]

    if protocol in ("http", "https"):
        items = [i for i in items if i.get("url", "").startswith(protocol + "://")]

    if risk != "any":
        items = filter_risk(items, risk)

    if date_from or date_to:
        # Parse to datetime for reliable tz-aware comparison instead of
        # fragile string comparison that breaks with mixed timezone offsets
        from datetime import datetime, timezone as _tz
        def _norm(ts):
            if not ts: return None
            try: return datetime.fromisoformat(ts.replace("Z","+00:00")).astimezone(_tz.utc)
            except: return None
        df = _norm(date_from + "T00:00:00+00:00") if date_from else None
        dt_end = _norm(date_to + "T23:59:59+00:00") if date_to else None
        def _in_range(item):
            ts = _norm(item.get("last_visit", ""))
            if ts is None: return True
            if df and ts < df: return False
            if dt_end and ts > dt_end: return False
            return True
        items = [i for i in items if _in_range(i)]

    return jsonify(paginate(items, page))

# ── API: Cookies ──────────────────────────────────────────────────────────────

@app.route("/api/cookies")
def api_cookies():
    data = load_analysis()
    items = data.get("cookies", [])

    ctype = request.args.get("type", "all").lower()
    host = request.args.get("host", "")
    expired = request.args.get("expired", "all")
    page = _safe_int(request.args.get("page", 1))

    if ctype != "all":
        items = [i for i in items if i.get("type", "").lower() == ctype]
    if host:
        host = host.lower()  # normalise before comparison
        items = [i for i in items if host in i.get("host", "").lower()]
    if expired == "yes":
        items = [i for i in items if i.get("type") == "Zombie"]
    elif expired == "no":
        items = [i for i in items if i.get("type") != "Zombie"]

    return jsonify(paginate(items, page))

# ── API: Bookmarks ────────────────────────────────────────────────────────────

@app.route("/api/bookmarks")
def api_bookmarks():
    data = load_analysis()
    bookmarks = data.get("bookmarks", [])

    # Build folder tree
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
    risk = request.args.get("risk", "any").lower()
    page = _safe_int(request.args.get("page", 1))

    if q:
        items = [i for i in items if q in i.get("filename", "").lower()
                 or q in i.get("source_url", "").lower()]
    if risk != "any":
        items = filter_risk(items, risk)

    return jsonify(paginate(items, page))

# ── Session reconstruction helper ────────────────────────────────────────────

def _reconstruct_sessions(events: list, gap_seconds: int = 1800) -> list:
    """
    Group a list of events (sorted newest-first) into browsing sessions.
    A new session starts when the gap between consecutive events exceeds
    gap_seconds (default 30 min).

    Returns sessions sorted newest-first, each with:
      start, end, count, events
    """
    if not events:
        return []

    # Work oldest-first to accumulate sessions in chronological order
    sessions = []
    current: list = []
    last_t = None

    for e in reversed(events):
        try:
            t = datetime.fromisoformat(e["time"].replace("Z", "+00:00"))
        except Exception:
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

    # Return newest session first
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


# ── API: Timeline ─────────────────────────────────────────────────────────────

@app.route("/api/timeline")
def api_timeline():
    data = load_analysis()
    date_from = request.args.get("from", "")
    date_to = request.args.get("to", "")
    types_param = request.args.get("types", "history,cookies,downloads,bookmarks")
    types = set(types_param.split(","))

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

    events.sort(key=lambda e: e.get("time", ""), reverse=True)

    if date_from:
        events = [e for e in events if e.get("time", "") >= date_from]
    if date_to:
        events = [e for e in events if e.get("time", "") <= date_to + "Z"]

    sessions = _reconstruct_sessions(events)

    return jsonify({
        "events": events[:500],
        "sessions": sessions,
        "total": len(events),
    })

# ── API: Domain ───────────────────────────────────────────────────────────────

@app.route("/api/domain/<domain>")
def api_domain(domain: str):
    data = load_analysis()
    domain = domain.lower().lstrip("www.")

    history = [h for h in data.get("history", []) if domain in domain_of(h.get("url", ""))]
    cookies = [c for c in data.get("cookies", []) if domain in c.get("host", "").lstrip(".")]
    downloads = [d for d in data.get("downloads", []) if domain in domain_of(d.get("source_url", ""))]

    times = [h.get("last_visit") for h in history if h.get("last_visit")]
    first_seen = min(times) if times else ""
    last_seen = max(times) if times else ""

    max_risk = max((h.get("risk_score", 0) for h in history), default=0)
    risk_reasons = []
    for h in history:
        risk_reasons.extend(h.get("risk_reasons", []))
    risk_reasons = list(set(risk_reasons))

    return jsonify({
        "domain": domain,
        "history": history,
        "cookies": cookies,
        "downloads": downloads,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "total_visits": sum(h.get("visit_count", 1) for h in history),
        "max_risk_score": max_risk,
        "risk_reasons": risk_reasons,
        "in_history": len(history) > 0,
    })

# ── API: Sessions ─────────────────────────────────────────────────────────────

@app.route("/api/sessions")
def api_sessions():
    """Return reconstructed sessions without duplicating timeline logic."""
    data = load_analysis()
    events = []
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
    events.sort(key=lambda e: e.get("time", ""), reverse=True)
    return jsonify({"sessions": _reconstruct_sessions(events)})

# ── API: Search ───────────────────────────────────────────────────────────────

@app.route("/api/search")
def api_search():
    data = load_analysis()
    q = request.args.get("q", "").lower()
    if not q or len(q) < 2:
        return jsonify({"error": "Query too short"}), 400

    results = {
        "history": [h for h in data.get("history", [])
                    if q in h.get("url", "").lower() or q in h.get("title", "").lower()][:20],
        "cookies": [c for c in data.get("cookies", [])
                    if q in c.get("host", "").lower() or q in c.get("name", "").lower()][:20],
        "bookmarks": [b for b in data.get("bookmarks", [])
                      if q in b.get("title", "").lower() or q in b.get("url", "").lower()][:20],
        "downloads": [d for d in data.get("downloads", [])
                      if q in d.get("filename", "").lower() or q in d.get("source_url", "").lower()][:20],
    }
    results["total"] = sum(len(v) for v in results.values())
    return jsonify(results)

# ── API: Report ───────────────────────────────────────────────────────────────

@app.route("/api/report")
def api_report():
    data = load_analysis()
    flagged_history = [h for h in data.get("history", []) if h.get("risk_score", 0) >= 61]
    flagged_cookies = [c for c in data.get("cookies", []) if c.get("risk_score", 0) >= 61]
    flagged_downloads = [d for d in data.get("downloads", []) if d.get("risk_score", 0) >= 61]

    return jsonify({
        "meta": data.get("meta", {}),
        "hashes": data.get("hashes", {}),
        "summary": data.get("summary", {}),
        "anomalies": data.get("anomalies", []),
        "flagged": {
            "history": flagged_history,
            "cookies": flagged_cookies,
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

    print("[INFO] Starting Flask on http://localhost:5000")
    threading.Timer(1.2, lambda: webbrowser.open("http://localhost:5000")).start()


if __name__ == "__main__":
    startup()
    app.run(host="127.0.0.1", port=5000, debug=False)