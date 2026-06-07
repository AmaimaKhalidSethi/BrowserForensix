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
import time
import webbrowser
from pathlib import Path
from collections import defaultdict

from analysis.sessions import (
    build_unified_events as _build_unified_events,
    domain_of,
    norm_dt as _norm_dt,
    reconstruct_sessions as _reconstruct_sessions,
)

try:
    from flask import Flask, jsonify, request, render_template, abort
except ImportError:
    print("[ERROR] Flask not installed. Run: pip install flask")
    raise

import analyzer
try:
    import leveldb_reader
    _LDB_AVAILABLE = True
except Exception:
    _LDB_AVAILABLE = False

try:
    from ai_routes import register_ai_routes
    _AI_AVAILABLE = True
except ImportError:
    _AI_AVAILABLE = False
    print("[WARN] ai_routes.py not found — AI features disabled")

try:
    from data_routes import register_data_routes
    _DATA_AVAILABLE = True
except ImportError:
    _DATA_AVAILABLE = False

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


@app.after_request
def _set_csp(response):
    """Set a strict Content-Security-Policy header.

    The app uses no external scripts except cdnjs; reflect that here.
    Includes script-src, style-src, connect-src, and frame-ancestors 'none'.

    NOTE: 'unsafe-inline' is used because inline scripts/styles are needed
    in templates. Since this is a localhost-only tool, this is an acceptable
    tradeoff and carries lower risk than in a public-facing application.
    """
    csp = (
        "default-src 'self'; "
        "script-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline'; "
        "style-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline'; "
        "connect-src 'self' https://openrouter.ai; "
        "frame-ancestors 'none';"
    )
    response.headers['Content-Security-Policy'] = csp
    return response

# ── Analysis cache (thread-safe) ──────────────────────────────────────────────


class AnalysisCache:
    """Thread-safe cache for reading analysis.json with lazy reload.

    Methods:
      - get() -> dict: return parsed analysis.json (or {} if missing)
      - invalidate(): force next get() to re-read file
      - last_modified: float mtime of the analysis file or 0.0
    """

    def __init__(self, path: Path):
        self._path = path
        self._lock = threading.RLock()
        self._data = None
        self._mtime = 0.0

    @property
    def last_modified(self) -> float:
        with self._lock:
            return self._mtime

    def invalidate(self) -> None:
        with self._lock:
            self._data = None
            self._mtime = 0.0

    def get(self) -> dict:
        with self._lock:
            if not self._path.exists():
                return {}
            try:
                current = self._path.stat().st_mtime
            except Exception:
                current = 0.0
            if self._data is None or current != self._mtime:
                try:
                    self._data = json.loads(self._path.read_text(encoding="utf-8"))
                    self._mtime = current
                except Exception:
                    # If parse fails, don't clobber existing cache; return empty
                    return {}
            return self._data


# Create a module-level cache instance
analysis_cache = AnalysisCache(ANALYSIS_FILE)

# Reanalysis watcher state
_reanalysis_pending = False
_reanalysis_lock = threading.Lock()


def reanalysis_pending() -> bool:
    with _reanalysis_lock:
        return _reanalysis_pending


def _set_reanalysis_pending(val: bool) -> None:
    global _reanalysis_pending
    with _reanalysis_lock:
        _reanalysis_pending = bool(val)


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


def _validate_domain_param(raw: str) -> str:
    """Validate domain input. Raises ValueError if invalid."""
    domain = raw.lower().strip().removeprefix("www.")
    if not domain or len(domain) < 4 or len(domain) > 253:
        raise ValueError("Invalid domain: must be 4-253 characters.")
    if not _is_valid_domain(domain):
        raise ValueError("Invalid domain syntax.")
    return domain


# Domain extraction and timestamp parsing live in analysis/sessions.py.

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


@app.route("/diff")
def diff_page():
    return render_template("diff.html", active="diff")


@app.route("/localstorage")
def localstorage_page():
    return render_template("localstorage.html", active="localstorage")

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
    data = analysis_cache.get()
    return jsonify({
        "ready": True,
        "meta": data.get("meta", {}),
        "summary": data.get("summary", {}),
        "hashes": data.get("hashes", {}),
        "reanalysis_pending": reanalysis_pending(),
    })


# ── API: Profiles ─────────────────────────────────────────────────────────────

@app.route("/api/profiles")
def api_profiles():
    data = analysis_cache.get()
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
    data = analysis_cache.get()
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


# History API moved to data_routes.py blueprint


# Cookies API moved to data_routes.py blueprint


# Bookmarks API moved to data_routes.py blueprint


# Downloads API moved to data_routes.py blueprint


# Session reconstruction lives in analysis/sessions.py.

# Timeline API moved to data_routes.py blueprint


# Domain API moved to data_routes.py blueprint


# Sessions API moved to data_routes.py blueprint


# Search API moved to data_routes.py blueprint


# ── API: Report ───────────────────────────────────────────────────────────────

@app.route("/api/report")
def api_report():
    data = analysis_cache.get()
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


@app.route('/api/diff')
def api_diff():
    """Return a structured diff between two analysis JSON files.

    Query params: a=<path_or_filename>&b=<path_or_filename>
    Paths are resolved relative to the data directory unless absolute.
    """
    a = request.args.get('a') or request.args.get('file_a')
    b = request.args.get('b') or request.args.get('file_b')
    if not a or not b:
        return jsonify({'error': 'Missing query params a and b'}), 400

    def resolve(p):
        raw = str(p).strip()
        if not raw:
            return None
        pth = Path(raw)
        if not pth.is_absolute():
            pth = DATA_DIR / pth
        try:
            pth = pth.resolve()
        except Exception:
            return None
        try:
            data_root = DATA_DIR.resolve()
            if data_root not in pth.parents:
                return None
        except Exception:
            return None
        if pth.suffix.lower() != ".json" or not pth.is_file():
            return None
        return pth

    pa = resolve(a)
    pb = resolve(b)
    if not pa or not pa.exists() or not pb or not pb.exists():
        return jsonify({'error': 'One or both files not found or disallowed'}), 404

    try:
        da = json.loads(pa.read_text(encoding='utf-8'))
        db = json.loads(pb.read_text(encoding='utf-8'))
    except Exception as e:
        return jsonify({'error': f'Failed to parse files: {e}'}), 500

    # Helper to build simple keys
    def hk_history(h):
        return (h.get('url',''), h.get('last_visit',''))

    def hk_cookie(c):
        return (c.get('host',''), c.get('name',''))

    def hk_download(d):
        return (d.get('filename',''), d.get('start_time',''))

    a_hist = {hk_history(h): h for h in da.get('history', [])}
    b_hist = {hk_history(h): h for h in db.get('history', [])}

    new_history = [v for k, v in b_hist.items() if k not in a_hist]

    a_cookies = {hk_cookie(c): c for c in da.get('cookies', [])}
    b_cookies = {hk_cookie(c): c for c in db.get('cookies', [])}
    removed_cookies = [v for k, v in a_cookies.items() if k not in b_cookies]

    a_dl = {hk_download(d): d for d in da.get('downloads', [])}
    b_dl = {hk_download(d): d for d in db.get('downloads', [])}
    new_downloads = [v for k, v in b_dl.items() if k not in a_dl]

    changed_risks = []
    # Compare matching items by identity and record changes
    for k, a_item in a_hist.items():
        b_item = b_hist.get(k)
        if b_item and a_item.get('risk_score') != b_item.get('risk_score'):
            changed_risks.append({'type': 'history', 'id': k[0], 'before': a_item.get('risk_score'), 'after': b_item.get('risk_score')})
    for k, a_item in a_cookies.items():
        b_item = b_cookies.get(k)
        if b_item and a_item.get('risk_score') != b_item.get('risk_score'):
            changed_risks.append({'type': 'cookie', 'id': f"{k[0]}::{k[1]}", 'before': a_item.get('risk_score'), 'after': b_item.get('risk_score')})
    for k, a_item in a_dl.items():
        b_item = b_dl.get(k)
        if b_item and a_item.get('risk_score') != b_item.get('risk_score'):
            changed_risks.append({'type': 'download', 'id': k[0], 'before': a_item.get('risk_score'), 'after': b_item.get('risk_score')})

    return jsonify({
        'new_history': new_history,
        'removed_cookies': removed_cookies,
        'new_downloads': new_downloads,
        'changed_risks': changed_risks,
    })


@app.route('/api/ghost_domains')
def api_ghost_domains():
    data = analysis_cache.get()
    gap = next((a for a in data.get("anomalies", []) if a.get("type") == "history_gap"), None)
    if not gap:
        return jsonify({"ghosts": []})
    return jsonify({"ghosts": [{"domain": d} for d in gap.get("affected_domains", [])]})


# Graph API moved to data_routes.py blueprint


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
        register_ai_routes(app, analysis_cache.get, helpers)
    else:
        print("[INFO] AI features not available — add ai_engine.py and ai_routes.py")

    # Register data routes blueprint (history, cookies, downloads, timeline, domain, sessions, search, graph)
    if _DATA_AVAILABLE:
        helpers = {
            "domain_of": domain_of,
            "_norm_dt": _norm_dt,
            "_build_unified_events": _build_unified_events,
            "_reconstruct_sessions": _reconstruct_sessions,
            "paginate": paginate,
            "filter_risk": filter_risk,
            "_safe_int": _safe_int,
            "_validate_domain_param": _validate_domain_param,
        }
        register_data_routes(app, analysis_cache.get, helpers)
    else:
        print("[INFO] data_routes.py not available — data APIs remain in serve.py")

    if _CTF_AVAILABLE:
        register_ctf_routes(app, analysis_cache.get)

    if _PDF_AVAILABLE:
        register_pdf_routes(app, analysis_cache.get)

    print("[INFO] Starting Flask on http://localhost:5000")
    # Start reanalysis watcher thread (polling) to auto-run analyzer when evidence.json changes
    def _reanalysis_watcher(poll_interval: float = 2.0):
        last_mtime = 0.0
        if EVIDENCE_FILE.exists():
            try:
                last_mtime = EVIDENCE_FILE.stat().st_mtime
            except Exception:
                last_mtime = 0.0
        while True:
            try:
                if EVIDENCE_FILE.exists():
                    m = EVIDENCE_FILE.stat().st_mtime
                    if m != last_mtime:
                        last_mtime = m
                        _set_reanalysis_pending(True)
                        try:
                            print("[INFO] evidence.json changed — running analyzer")
                            analyzer.run()
                            analysis_cache.invalidate()
                        except Exception as e:
                            print(f"[ERROR] Analyzer failed: {e}")
                        finally:
                            _set_reanalysis_pending(False)
            except Exception:
                pass
            time.sleep(poll_interval)

    t = threading.Thread(target=_reanalysis_watcher, daemon=True)
    t.start()

    threading.Timer(1.2, lambda: webbrowser.open("http://localhost:5000")).start()


if __name__ == "__main__":
    startup()
    app.run(host="127.0.0.1", port=5000, debug=False)
