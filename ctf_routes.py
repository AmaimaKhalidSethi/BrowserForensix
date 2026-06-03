"""
BrowserForensix — ctf_routes.py
CTF-oriented analysis features as a self-contained Flask Blueprint.

Register in serve.py:
    try:
        from ctf_routes import register_ctf_routes
        _CTF_AVAILABLE = True
    except ImportError:
        _CTF_AVAILABLE = False

    # inside startup():
    if _CTF_AVAILABLE:
        register_ctf_routes(app, load_analysis)

FIX-B: Removed the @app.route("/ctf") / ctf_page() route from this file.
        serve.py already registers @app.route("/ctf") as ctf_page().
        Flask raises AssertionError when two functions share the same endpoint
        name ("ctf_page"), so having it in both files crashes startup.
        Page routes belong in serve.py; this file owns only /api/ctf/* routes.
"""

import re
import base64
import binascii
from urllib.parse import urlparse, parse_qs, unquote
from flask import Blueprint, jsonify, request

ctf_bp = Blueprint("ctf", __name__, url_prefix="/api/ctf")

# ── Built-in CTF flag patterns ────────────────────────────────────────────────

_BUILTIN_PATTERNS = [
    re.compile(r'(FLAG\{[^}]{1,200}\})',       re.IGNORECASE),
    re.compile(r'(CTF\{[^}]{1,200}\})',        re.IGNORECASE),
    re.compile(r'(picoCTF\{[^}]{1,200}\})',    re.IGNORECASE),
    re.compile(r'(HTB\{[^}]{1,200}\})',        re.IGNORECASE),
    re.compile(r'(THM\{[^}]{1,200}\})',        re.IGNORECASE),
    re.compile(r'(HackTheBox\{[^}]{1,200}\})', re.IGNORECASE),
    re.compile(r'(DUCTF\{[^}]{1,200}\})',      re.IGNORECASE),
    re.compile(r'(ACSC\{[^}]{1,200}\})',       re.IGNORECASE),
    re.compile(r'(BFX\{[^}]{1,200}\})',        re.IGNORECASE),
    re.compile(r'(flag\{[^}]{1,200}\})',       re.IGNORECASE),
    re.compile(r'\b([0-9a-f]{32,64})\b',       re.IGNORECASE),
]

_custom_pattern_cache: dict = {}
_MAX_CUSTOM_PATTERN_LEN = 200


def _get_custom_pattern(custom_re: str):
    if len(custom_re) > _MAX_CUSTOM_PATTERN_LEN:
        return None
    if custom_re not in _custom_pattern_cache:
        try:
            _custom_pattern_cache[custom_re] = re.compile(custom_re, re.IGNORECASE)
        except re.error:
            _custom_pattern_cache[custom_re] = None
    return _custom_pattern_cache[custom_re]


def _scan_string(value: str, custom_re=None) -> list:
    if not value or not isinstance(value, str):
        return []
    matches = []
    patterns = _BUILTIN_PATTERNS[:]
    if custom_re:
        compiled = _get_custom_pattern(custom_re)
        if compiled:
            patterns.append(compiled)
    seen = set()
    for pat in patterns:
        for m in pat.finditer(value):
            token = m.group(1) if pat.groups else m.group(0)
            if token not in seen:
                seen.add(token)
                matches.append({
                    "match":   token,
                    "pattern": pat.pattern,
                    "start":   m.start(),
                    "end":     m.end(),
                })
    return matches


def _artifact_fields(data: dict) -> list:
    fields = []

    for h in data.get("history", []):
        for f in ("url", "title"):
            v = h.get(f, "")
            if v:
                fields.append({"artifact_type": "history", "field": f,
                                "value": v, "artifact": h})
        try:
            qs = parse_qs(urlparse(h.get("url", "")).query)
            for k, vals in qs.items():
                for v in vals:
                    fields.append({"artifact_type": "history",
                                   "field": f"url_param:{k}",
                                   "value": v, "artifact": h})
        except Exception:
            pass

    for c in data.get("cookies", []):
        for f in ("host", "name", "value"):
            v = c.get(f, "")
            if v and v != "[ENCRYPTED]":
                fields.append({"artifact_type": "cookie", "field": f,
                                "value": str(v), "artifact": c})

    for d in data.get("downloads", []):
        for f in ("filename", "source_url", "target_path"):
            v = d.get(f, "")
            if v:
                fields.append({"artifact_type": "download", "field": f,
                                "value": v, "artifact": d})

    for b in data.get("bookmarks", []):
        for f in ("title", "url"):
            v = b.get(f, "")
            if v:
                fields.append({"artifact_type": "bookmark", "field": f,
                                "value": v, "artifact": b})

    return fields


def _decode_attempts(value: str) -> dict:
    out = {}

    try:
        decoded = unquote(value)
        out["url"] = decoded if decoded != value else None
    except Exception:
        out["url"] = None

    out["base64"] = None
    if len(value) >= 4:
        for padded in (value, value + "=", value + "==", value + "==="):
            try:
                raw = base64.b64decode(padded, validate=True)
                if not raw:
                    continue
                text = raw.decode("utf-8", errors="replace")
                if len(text) >= 2:
                    out["base64"] = text
                    break
            except Exception:
                continue

    hex_clean = re.sub(r'\s', '', value)
    if re.fullmatch(r'[0-9a-fA-F]+', hex_clean) and len(hex_clean) % 2 == 0:
        try:
            raw = bytes.fromhex(hex_clean)
            out["hex"] = raw.decode("utf-8", errors="replace")
        except Exception:
            out["hex"] = None
    else:
        out["hex"] = None

    try:
        out["rot13"] = value.translate(
            str.maketrans(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
            )
        )
    except Exception:
        out["rot13"] = None

    return {k: v for k, v in out.items() if v is not None and v != value}


def _summarise_artifact(a: dict, atype: str) -> dict:
    if atype == "history":
        return {
            "label":      a.get("url", ""),
            "title":      a.get("title", ""),
            "time":       a.get("last_visit", ""),
            "risk_score": a.get("risk_score", 0),
        }
    if atype == "cookie":
        return {
            "label":      f"{a.get('name','')} @ {a.get('host','')}",
            "title":      a.get("type", ""),
            "time":       a.get("created", ""),
            "risk_score": a.get("risk_score", 0),
        }
    if atype == "download":
        return {
            "label":      a.get("filename", ""),
            "title":      a.get("source_url", ""),
            "time":       a.get("start_time", ""),
            "risk_score": a.get("risk_score", 0),
        }
    if atype == "bookmark":
        return {
            "label":      a.get("title", ""),
            "title":      a.get("url", ""),
            "time":       a.get("date_added", ""),
            "risk_score": 0,
        }
    return {"label": str(a), "title": "", "time": "", "risk_score": 0}


# ── Routes ────────────────────────────────────────────────────────────────────

def register_ctf_routes(app, load_analysis_fn):
    # FIX-B: No @app.route("/ctf") here. serve.py owns all page routes.
    # Previously this registered ctf_page() which collided with serve.py's
    # own ctf_page() registration, causing Flask to raise AssertionError on startup.

    @ctf_bp.route("/scan/flags")
    def ctf_scan_flags():
        data        = load_analysis_fn()
        custom_re   = request.args.get("custom", "").strip()
        if len(custom_re) > _MAX_CUSTOM_PATTERN_LEN:
            return jsonify({"error": "custom regex is too long"}), 400
        filter_type = request.args.get("artifact_type", "").strip().lower()

        all_fields = _artifact_fields(data)
        if filter_type:
            all_fields = [f for f in all_fields if f["artifact_type"] == filter_type]

        results = []
        for entry in all_fields:
            hits = _scan_string(entry["value"], custom_re or None)
            if hits:
                results.append({
                    "artifact_type": entry["artifact_type"],
                    "field":         entry["field"],
                    "value":         entry["value"][:500],
                    "matches":       hits,
                    "artifact":      _summarise_artifact(entry["artifact"], entry["artifact_type"]),
                })

        return jsonify({
            "total":          len(results),
            "custom_pattern": custom_re or None,
            "results":        results,
        })

    @ctf_bp.route("/decode")
    def ctf_decode():
        data        = load_analysis_fn()
        filter_type = request.args.get("artifact_type", "").strip().lower()
        try:
            min_len = max(4, min(10_000, int(request.args.get("min_length", 8) or 8)))
        except (TypeError, ValueError):
            return jsonify({"error": "min_length must be an integer"}), 400

        all_fields = _artifact_fields(data)
        if filter_type:
            all_fields = [f for f in all_fields if f["artifact_type"] == filter_type]

        results = []
        for entry in all_fields:
            val = entry["value"]
            if len(val) < min_len:
                continue
            decodings = _decode_attempts(val)
            if not decodings:
                continue
            meaningful = {k: v for k, v in decodings.items()
                          if v and len(v.strip()) >= 4}
            if not meaningful:
                continue
            results.append({
                "artifact_type": entry["artifact_type"],
                "field":         entry["field"],
                "original":      val[:300],
                "decodings":     meaningful,
                "artifact":      _summarise_artifact(entry["artifact"], entry["artifact_type"]),
            })

        return jsonify({"total": len(results), "results": results})

    @ctf_bp.route("/url/params")
    def ctf_url_params():
        data = load_analysis_fn()
        q    = request.args.get("q", "").lower().strip()

        results = []
        for h in data.get("history", []):
            url = h.get("url", "")
            if not url:
                continue
            if q and q not in url.lower():
                continue
            try:
                parsed = urlparse(url)
                qs = parse_qs(parsed.query, keep_blank_values=False)
            except Exception:
                continue
            if not qs:
                continue

            params = []
            for k, vals in qs.items():
                for v in vals:
                    if len(v) < 4:
                        continue
                    decodings = _decode_attempts(v)
                    flag_hits = _scan_string(v)
                    for decoded_val in decodings.values():
                        flag_hits += _scan_string(decoded_val)
                    params.append({
                        "key":        k,
                        "value":      v[:300],
                        "decodings":  decodings,
                        "flag_hits":  flag_hits,
                        "suspicious": bool(flag_hits) or len(v) > 50,
                    })

            if params:
                results.append({
                    "url":        url[:500],
                    "domain":     parsed.netloc,
                    "title":      h.get("title", ""),
                    "last_visit": h.get("last_visit", ""),
                    "risk_score": h.get("risk_score", 0),
                    "params":     params,
                })

        results.sort(key=lambda r: (
            -sum(len(p["flag_hits"]) for p in r["params"]),
            -r["risk_score"]
        ))

        return jsonify({"total": len(results), "results": results})

    @ctf_bp.route("/cookie/inspect")
    def ctf_cookie_inspect():
        data   = load_analysis_fn()
        host_q = request.args.get("host", "").lower().strip()
        name_q = request.args.get("name", "").lower().strip()

        results = []
        for c in data.get("cookies", []):
            value = c.get("value", "")
            if not value or value == "[ENCRYPTED]":
                continue
            if host_q and host_q not in c.get("host", "").lower():
                continue
            if name_q and name_q not in str(c.get("name", "")).lower():
                continue

            value = str(value)
            decodings = _decode_attempts(value)
            flag_hits = _scan_string(value)
            for decoded_val in decodings.values():
                flag_hits += _scan_string(decoded_val)

            raw_bytes = value.encode("utf-8", errors="replace")[:64]
            hex_dump  = " ".join(f"{b:02x}" for b in raw_bytes)

            results.append({
                "host":       c.get("host", ""),
                "name":       str(c.get("name", "")),
                "type":       c.get("type", "Unknown"),
                "value":      value[:300],
                "hex_dump":   hex_dump,
                "decodings":  decodings,
                "flag_hits":  flag_hits,
                "risk_score": c.get("risk_score", 0),
                "created":    c.get("created", ""),
                "expires":    c.get("expires", ""),
            })

        results.sort(key=lambda r: (-len(r["flag_hits"]), -r["risk_score"]))
        return jsonify({"total": len(results), "results": results})

    @ctf_bp.route("/summary")
    def ctf_summary():
        data   = load_analysis_fn()
        fields = _artifact_fields(data)

        flag_count    = 0
        encoded_count = 0
        param_count   = 0

        for entry in fields:
            v = entry["value"]
            if _scan_string(v):
                flag_count += 1
            if len(v) >= 8 and _decode_attempts(v):
                encoded_count += 1

        for h in data.get("history", []):
            try:
                qs = parse_qs(urlparse(h.get("url", "")).query)
                if qs:
                    param_count += sum(len(v) for v in qs.values())
            except Exception:
                pass

        return jsonify({
            "flag_hits":      flag_count,
            "encoded_fields": encoded_count,
            "url_params":     param_count,
            "total_artifacts": sum(
                len(data.get(k, [])) for k in ("history", "cookies", "downloads", "bookmarks")
            ),
        })

    app.register_blueprint(ctf_bp)
    print("[CTF] Routes registered — /api/ctf/*")
