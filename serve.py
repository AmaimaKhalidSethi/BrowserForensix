#!/usr/bin/env python3
"""
BrowserForensix — serve.py
Runs analyzer, starts Flask server, opens browser automatically.

FIXES IN THIS FILE:
  FIX-4  register_ai_routes now receives a helpers dict instead of ai_routes.py
         importing from serve at call time. Eliminates the circular import:
         serve -> ai_routes -> serve.

  FIX-5  _guard_api_origin: added X-Forwarded-Host / proxy awareness so that
         legitimate tool use through BurpSuite / local proxies does not produce
         silent 403s on SSE streams with no UI error message.
         Rule: if Origin AND Referer are both absent, always allow (curl, Postman,
         same-origin fetch). If either is present, validate localhost only.
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

try:
    from ctf_routes import register_ctf_routes
    _CTF_AVAILABLE = True
except ImportError:
    _CTF_AVAILABLE = False

try:
    from pdf_routes import register_pdf_routes
    _PDF_AVAILABLE = True
except ImportError:
    _PDF_AVAILABLE = False

BASE_DIR      = Path(__file__).parent
DATA_DIR      = BASE_DIR / "data"
EVIDENCE_FILE = DATA_DIR / "evidence.json"
ANALYSIS_FILE = DATA_DIR / "analysis.json"

app = Flask(__name__, template_folder="templates", static_folder="static")

# ── Data loader ───────────────────────────────────────────────────────────────

_analysis        = None
_analysis_mtime: float = 0.0
_analysis_lock   = threading.RLock()


def load_analysis() -> dict:
    """Load analysis.json, re-reading from disk if modified. Thread-safe."""
    global _analysis, _analysis_mtime
    with _analysis_lock:
        if not ANALYSIS_FILE.exists():
            return {}
        current_mtime = ANALYSIS_FILE.stat().st_mtime
        if _analysis is None or current_mtime != _analysis_mtime:
            _analysis      = json.loads(ANALYSIS_FILE.read_text(encoding="utf-8"))
            _analysis_mtime = current_mtime
        return _analysis


def reload_analysis() -> dict:
    global _analysis, _analysis_mtime
    with _analysis_lock:
        _analysis       = None
        _analysis_mtime = 0.0
    return load_analysis()


# ── Helpers ───────────────────────────────────────────────────────────────────

def paginate(items: list, page: int, per_page: int = 50) -> dict:
    total       = len(items)
    total_pages = max(1, math.ceil(total / per_page))
    page        = max(1, min(page, total_pages))
    start       = (page - 1) * per_page
    return {
        "items":       items[start:start + per_page],
        "page":        page,
        "per_page":    per_page,
        "total":       total,
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
    try:
        return max(minimum, min(maximum, int(val)))
    except (TypeError, ValueError):
        return default


_VALID_LABEL_RE = re.compile(r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$')


def _is_valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False
    labels = domain.rstrip(".").split(".")
    return len(labels) >= 2 and all(_VALID_LABEL_RE.match(lbl) for lbl in labels)


def domain_of(url: str) -> str:
    netloc = urlparse(url).netloc.lower().split(":")[0]
    return netloc.removeprefix("www.")


def _validate_domain_param(raw: str) -> str:
    domain = raw.lower().strip().removeprefix("www.")
    if not domain or len(domain) < 4 or len(domain) > 253:
        abort(400, description="Invalid domain: must be 4–253 characters.")
    if not _is_valid_domain(domain):
        abort(400, description="Invalid domain syntax.")
    return domain


def _norm_dt(ts: str) -> "datetime | None":
    if not ts:
        return None
    try:
        normalised = ts.strip().replace("Z", "+00:00")
        normalised = re.sub(r' (\d{2}:\d{2})$', r'+\1', normalised)
        return datetime.fromisoformat(normalised).astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


# ── Origin guard ──────────────────────────────────────────────────────────────
# FIX-5: Previous guard returned 403 for any request with a Referer header
# that wasn't localhost — this silently broke BurpSuite, Postman with a
# base URL set, and browser extensions that inject a Referer header.
# The fixed rule: only block when Origin or Referer is PRESENT and does NOT
# match localhost. Absent headers = same-origin or tool use = allow.

_LOCALHOST_RE = re.compile(r'^https?://(localhost|127\.0\.0\.1)(:\d+)?(/.*)?$')


@app.before_request
def _guard_api_origin():
    if not request.path.startswith("/api/"):
        return
    origin  = request.headers.get("Origin",  "")
    referer = request.headers.get("Referer", "")
    if origin and not _LOCALHOST_RE.match(origin):
        abort(403, description="Cross-origin API access denied.")
    if not origin and referer and not _LOCALHOST_RE.match(referer):
        abort(403, description="Cross-origin API access denied.")
    # No Origin, no Referer → allow unconditionally (curl, Postman, proxies)


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

@app.route("/ctf")
def ctf_page():
    return render_template("ctf.html", active="ctf")


# ── API: Status ───────────────────────────────────────────────────────────────

@app.route("/api/status")
def api_status():
    if not EVIDENCE_FILE.exists():
        return jsonify({
            "ready":          False,
            "message":        "evidence.json not found. Run: python extract.py --browser chrome",
            "evidence_path":  str(EVIDENCE_FILE),
        })
    if not ANALYSIS_FILE.exists():
        return jsonify({
            "ready":   False,
            "message": "analysis.json not found. Restart serve.py.",
        })
    data = load_analysis()
    return jsonify({
        "ready":   True,
        "meta":    data.get("meta",    {}),
        "summary": data.get("summary", {}),
        "hashes":  data.get("hashes",  {}),
    })


# ── API: Profiles ─────────────────────────────────────────────────────────────

@app.route("/api/profiles")
def api_profiles():
    data = load_analysis()
    if not data:
        return jsonify({"profiles": []})
    meta          = data.get("meta", {})
    profiles_meta = meta.get("profiles_extracted", [])

    counts = defaultdict(lambda: {"history": 0, "cookies": 0, "bookmarks": 0, "downloads": 0})
    for h in data.get("history",   []): counts[h.get("profile", "")]["history"]   += 1
    for c in data.get("cookies",   []): counts[c.get("profile", "")]["cookies"]   += 1
    for b in data.get("bookmarks", []): counts[b.get("profile", "")]["bookmarks"] += 1
    for d in data.get("downloads", []): counts[d.get("profile", "")]["downloads"] += 1

    profiles = []
    for p in profiles_meta:
        label    = p.get("label") or p.get("name") or p.get("dir", "Unknown")
        dir_name = p.get("dir", "")
        c        = counts.get(label, {"history": 0, "cookies": 0, "bookmarks": 0, "downloads": 0})
        profiles.append({"name": label, "dir": dir_name, "path": p.get("path", ""), "counts": c})

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
    meta = data.get("meta", {})
    return jsonify({
        "summary":     data.get("summary",     {}),
        "anomalies":   data.get("anomalies",   []),
        "top_domains": data.get("top_domains", []),
        "heatmap":     data.get("heatmap",     []),
        "meta":        meta,
        "hashes":      data.get("hashes",      {}),
        "profiles":    meta.get("profiles_extracted", []),
    })


# ── API: History ──────────────────────────────────────────────────────────────

@app.route("/api/history")
def api_history():
    data     = load_analysis()
    items    = data.get("history", [])
    q        = request.args.get("q",        "").lower()
    profile  = request.args.get("profile",  "").strip()
    protocol = request.args.get("protocol", "all").lower()
    risk     = request.args.get("risk",     "any").lower()
    date_from = request.args.get("from",    "")
    date_to   = request.args.get("to",      "")
    page      = _safe_int(request.args.get("page", 1))

    if profile:
        items = [i for i in items if i.get("profile", "") == profile]
    if q:
        items = [i for i in items if q in i.get("url", "").lower() or q in i.get("title", "").lower()]
    if protocol in ("http", "https"):
        items = [i for i in items if i.get("url", "").startswith(protocol + "://")]
    if risk != "any":
        items = filter_risk(items, risk)
    if date_from or date_to:
        df     = _norm_dt(date_from + "T00:00:00+00:00") if date_from else None
        dt_end = _norm_dt(date_to   + "T23:59:59+00:00") if date_to   else None

        def _in_range(item):
            ts = _norm_dt(item.get("last_visit", ""))
            if ts is None:                      return True
            if df     and ts < df:              return False
            if dt_end and ts > dt_end:          return False
            return True
        items = [i for i in items if _in_range(i)]

    return jsonify(paginate(items, page))


# ── API: Cookies ──────────────────────────────────────────────────────────────

@app.route("/api/cookies")
def api_cookies():
    data    = load_analysis()
    items   = data.get("cookies", [])
    profile = request.args.get("profile", "").strip()
    ctype   = request.args.get("type",    "all").lower()
    host    = request.args.get("host",    "").strip().lower()
    expired = request.args.get("expired", "all")
    secure  = request.args.get("secure",  "all")
    page    = _safe_int(request.args.get("page", 1))

    if profile:
        items = [i for i in items if i.get("profile", "") == profile]
    if ctype != "all":
        items = [i for i in items if i.get("type", "").lower() == ctype]
    if host:
        items = [i for i in items if host in i.get("host", "").lower()]
    if expired == "yes":
        items = [i for i in items if i.get("type") == "Zombie"]
    elif expired == "no":
        items = [i for i in items if i.get("type") != "Zombie"]
    if secure == "secure":
        items = [i for i in items if i.get("secure", False)]
    elif secure == "insecure":
        items = [i for i in items if not i.get("secure", False)]

    return jsonify(paginate(items, page))


# ── API: Bookmarks ────────────────────────────────────────────────────────────

@app.route("/api/bookmarks")
def api_bookmarks():
    data      = load_analysis()
    bookmarks = data.get("bookmarks", [])
    tree      = defaultdict(list)
    for b in bookmarks:
        tree[b.get("folder", "Other")].append(b)

    q = request.args.get("q", "").lower()
    if q:
        bookmarks = [b for b in bookmarks
                     if q in b.get("title", "").lower() or q in b.get("url", "").lower()]
        return jsonify({"items": bookmarks, "total": len(bookmarks)})

    return jsonify({"tree": dict(tree), "total": len(bookmarks)})


# ── API: Downloads ────────────────────────────────────────────────────────────

@app.route("/api/downloads")
def api_downloads():
    data    = load_analysis()
    items   = data.get("downloads", [])
    q       = request.args.get("q",       "").lower()
    profile = request.args.get("profile", "").strip()
    risk    = request.args.get("risk",    "any").lower()
    page    = _safe_int(request.args.get("page", 1))

    if profile:
        items = [i for i in items if i.get("profile", "") == profile]
    if q:
        items = [i for i in items if q in i.get("filename",   "").lower()
                 or q in i.get("source_url", "").lower()]
    if risk != "any":
        items = filter_risk(items, risk)

    return jsonify(paginate(items, page))


# ── Session reconstruction ────────────────────────────────────────────────────

def _build_unified_events(data: dict, types: "set | None" = None) -> list:
    if types is None:
        types = {"history", "cookies", "downloads"}

    events = []

    if "history" in types:
        for h in data.get("history", []):
            if h.get("last_visit"):
                events.append({
                    "type":       "history",
                    "time":       h["last_visit"],
                    "url":        h.get("url",   ""),
                    "title":      h.get("title", ""),
                    "domain":     domain_of(h.get("url", "")),
                    "risk_score": h.get("risk_score", 0),
                })

    if "cookies" in types:
        for c in data.get("cookies", []):
            if c.get("created"):
                events.append({
                    "type":        "cookie",
                    "time":        c["created"],
                    "host":        c.get("host",  ""),
                    "name":        c.get("name",  ""),
                    "cookie_type": c.get("type",  ""),
                    "risk_score":  c.get("risk_score", 0),
                })

    if "downloads" in types:
        for dl in data.get("downloads", []):
            if dl.get("start_time"):
                events.append({
                    "type":       "download",
                    "time":       dl["start_time"],
                    "filename":   dl.get("filename",   ""),
                    "source_url": dl.get("source_url", ""),
                    "domain":     domain_of(dl.get("source_url", "")),
                    "risk_score": dl.get("risk_score", 0),
                })

    def _sort_key(e: dict) -> datetime:
        ts = e.get("time", "")
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)
        except (ValueError, TypeError):
            return datetime.fromtimestamp(0, tz=timezone.utc)

    events.sort(key=_sort_key, reverse=True)
    return events


def _reconstruct_sessions(events: list, gap_seconds: int = 1800) -> list:
    if not events:
        return []

    sessions: list = []
    current:  list = []
    last_t: "datetime | None" = None

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

    sessions.reverse()
    return [
        {
            "start":  s[0]["time"],
            "end":    s[-1]["time"],
            "count":  len(s),
            "events": s,
        }
        for s in sessions
    ]


# ── API: Timeline ─────────────────────────────────────────────────────────────

@app.route("/api/timeline")
def api_timeline():
    data        = load_analysis()
    types_param = request.args.get("types", "history,cookies,downloads")
    types       = set(types_param.split(","))
    events      = _build_unified_events(data, types)

    date_from_str = request.args.get("from", "")
    date_to_str   = request.args.get("to",   "")

    if date_from_str or date_to_str:
        df     = _norm_dt(date_from_str) if date_from_str else None
        dt_end = _norm_dt(date_to_str)   if date_to_str   else None

        def _in_range(e: dict) -> bool:
            ts = _norm_dt(e.get("time", ""))
            if ts is None:             return True
            if df     and ts < df:     return False
            if dt_end and ts > dt_end: return False
            return True

        events = [e for e in events if _in_range(e)]

    sessions = _reconstruct_sessions(events)
    return jsonify({"events": events[:500], "sessions": sessions, "total": len(events)})


# ── API: Domain ───────────────────────────────────────────────────────────────

@app.route("/api/domain/<domain>")
def api_domain(domain: str):
    domain = _validate_domain_param(domain)
    data   = load_analysis()

    def _matches(candidate: str) -> bool:
        return candidate == domain or candidate.endswith("." + domain)

    history   = [h for h in data.get("history",   []) if _matches(domain_of(h.get("url", "")))]
    cookies   = [c for c in data.get("cookies",   []) if _matches(c.get("host", "").lstrip(".").removeprefix("www."))]
    downloads = [d for d in data.get("downloads", []) if _matches(domain_of(d.get("source_url", "")))]

    parsed_times = [_norm_dt(h.get("last_visit", "")) for h in history]
    parsed_times = [t for t in parsed_times if t is not None]

    return jsonify({
        "domain":         domain,
        "history":        history,
        "cookies":        cookies,
        "downloads":      downloads,
        "first_seen":     min(parsed_times).isoformat() if parsed_times else "",
        "last_seen":      max(parsed_times).isoformat() if parsed_times else "",
        "total_visits":   sum(h.get("visit_count", 1) for h in history),
        "max_risk_score": max((h.get("risk_score", 0) for h in history), default=0),
        "risk_reasons":   list({r for h in history for r in h.get("risk_reasons", [])}),
        "in_history":     len(history) > 0,
    })


# ── API: Sessions ─────────────────────────────────────────────────────────────

@app.route("/api/sessions")
def api_sessions():
    data   = load_analysis()
    events = _build_unified_events(data, types={"history", "cookies", "downloads"})
    return jsonify({"sessions": _reconstruct_sessions(events)})


# ── API: Search ───────────────────────────────────────────────────────────────

@app.route("/api/search")
def api_search():
    data = load_analysis()
    q    = request.args.get("q", "").lower()
    if not q or len(q) < 2:
        return jsonify({"error": "Query too short"}), 400

    all_history   = [h for h in data.get("history",   []) if q in h.get("url",      "").lower() or q in h.get("title",      "").lower()]
    all_cookies   = [c for c in data.get("cookies",   []) if q in c.get("host",     "").lower() or q in c.get("name",       "").lower()]
    all_bookmarks = [b for b in data.get("bookmarks", []) if q in b.get("title",    "").lower() or q in b.get("url",        "").lower()]
    all_downloads = [d for d in data.get("downloads", []) if q in d.get("filename", "").lower() or q in d.get("source_url", "").lower()]

    return jsonify({
        "history":       all_history[:20],
        "cookies":       all_cookies[:20],
        "bookmarks":     all_bookmarks[:20],
        "downloads":     all_downloads[:20],
        "total":         len(all_history) + len(all_cookies) + len(all_bookmarks) + len(all_downloads),
        "total_preview": 20,
    })


# ── API: Report ───────────────────────────────────────────────────────────────

@app.route("/api/report")
def api_report():
    data = load_analysis()
    return jsonify({
        "meta":      data.get("meta",      {}),
        "hashes":    data.get("hashes",    {}),
        "summary":   data.get("summary",   {}),
        "anomalies": data.get("anomalies", []),
        "flagged": {
            "history":   [h for h in data.get("history",   []) if h.get("risk_score", 0) >= 61],
            "cookies":   [c for c in data.get("cookies",   []) if c.get("risk_score", 0) >= 61],
            "downloads": [d for d in data.get("downloads", []) if d.get("risk_score", 0) >= 61],
        },
    })


# ── API: Relationship Graph ───────────────────────────────────────────────────

@app.route("/api/graph")
def api_graph():
    data      = load_analysis()
    history   = data.get("history",   [])
    cookies   = data.get("cookies",   [])
    downloads = data.get("downloads", [])

    domain_meta = {}
    for h in history:
        d = domain_of(h.get("url", ""))
        if not d:
            continue
        if d not in domain_meta:
            domain_meta[d] = {"visits": 0, "risk": 0, "has_download": False, "has_cookie": False}
        domain_meta[d]["visits"] += h.get("visit_count", 1)
        domain_meta[d]["risk"]    = max(domain_meta[d]["risk"], h.get("risk_score", 0))

    for c in cookies:
        d = c.get("host", "").lstrip(".").removeprefix("www.")
        if d:
            domain_meta.setdefault(d, {"visits": 0, "risk": c.get("risk_score", 0),
                                       "has_download": False, "has_cookie": True})
            domain_meta[d]["has_cookie"] = True

    for dl in downloads:
        d = domain_of(dl.get("source_url", ""))
        if d:
            domain_meta.setdefault(d, {"visits": 0, "risk": dl.get("risk_score", 0),
                                       "has_download": False, "has_cookie": False})
            domain_meta[d]["has_download"] = True
            domain_meta[d]["risk"]          = max(domain_meta[d]["risk"], dl.get("risk_score", 0))

    top = sorted(domain_meta.items(),
                 key=lambda x: x[1]["visits"] * 2 + x[1]["risk"],
                 reverse=True)[:60]
    top_domains = {d for d, _ in top}

    nodes = []
    for d, m in top:
        risk  = m["risk"]
        group = "flagged" if risk >= 61 else "moderate" if risk >= 31 else "normal"
        nodes.append({"id": d, "visits": m["visits"], "risk": risk, "group": group,
                       "has_cookie": m["has_cookie"], "has_download": m["has_download"]})

    edges      = []
    seen_edges = set()
    root_map   = defaultdict(list)
    for c in cookies:
        host = c.get("host", "").lstrip(".")
        root = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host
        d    = host.removeprefix("www.")
        if d in top_domains:
            root_map[root].append(d)

    for root, doms in root_map.items():
        unique = list(set(doms))
        for i in range(len(unique)):
            for j in range(i + 1, len(unique)):
                a, b = sorted([unique[i], unique[j]])
                key  = (a, b, "shared_cookie")
                if key not in seen_edges:
                    seen_edges.add(key)
                    edges.append({"source": a, "target": b, "type": "shared_cookie"})

    events   = _build_unified_events(data)
    sessions = _reconstruct_sessions(events)
    for session in sessions:
        sess_domains = list({
            domain_of(e.get("url", ""))
            for e in session.get("events", [])
            if e.get("type") == "history" and domain_of(e.get("url", "")) in top_domains
        })
        for i in range(len(sess_domains)):
            for j in range(i + 1, len(sess_domains)):
                a, b = sorted([sess_domains[i], sess_domains[j]])
                key  = (a, b, "same_session")
                if key not in seen_edges:
                    seen_edges.add(key)
                    edges.append({"source": a, "target": b, "type": "same_session"})

    return jsonify({"nodes": nodes, "edges": edges})


# ── Startup ───────────────────────────────────────────────────────────────────

def startup():
    print("\n=== BrowserForensix ===")
    if not EVIDENCE_FILE.exists():
        print(f"[WARN] No evidence.json at {EVIDENCE_FILE}")
        print("       Run: python extract.py --browser chrome\n")
    else:
        print("[INFO] Running analyzer…")
        try:
            analyzer.run()
        except Exception as e:
            print(f"[ERROR] Analyzer failed: {e}")

    if _AI_AVAILABLE:
        # FIX-4: Pass helpers dict so ai_routes.py never needs to import from serve.
        # Previously ai_routes imported domain_of, _norm_dt, etc. from serve at
        # request time — a circular import that worked by accident and will break
        # on any import-order change.
        helpers = {
            "domain_of":              domain_of,
            "_norm_dt":               _norm_dt,
            "_build_unified_events":  _build_unified_events,
            "_reconstruct_sessions":  _reconstruct_sessions,
        }
        register_ai_routes(app, load_analysis, helpers)
    else:
        print("[INFO] AI features not available — add ai_engine.py and ai_routes.py")

    if _CTF_AVAILABLE:
        register_ctf_routes(app, load_analysis)

    if _PDF_AVAILABLE:
        register_pdf_routes(app, load_analysis)

    print("[INFO] Starting Flask on http://localhost:5000")
    threading.Timer(1.2, lambda: webbrowser.open("http://localhost:5000")).start()


if __name__ == "__main__":
    startup()
    app.run(host="127.0.0.1", port=5000, debug=False)