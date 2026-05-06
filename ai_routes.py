"""
BrowserForensix — ai_routes.py
All AI API routes. Import and register on the Flask app in serve.py.

Usage in serve.py:
    from ai_routes import register_ai_routes
    register_ai_routes(app, load_analysis)
"""

import json
import hashlib
from flask import Blueprint, jsonify, request, Response, stream_with_context

try:
    import ai_engine as ai
except ImportError:
    ai = None

ai_bp = Blueprint("ai", __name__, url_prefix="/api/ai")


def _analysis_snapshot(data: dict) -> dict:
    """Lightweight summary for the chat system prompt."""
    top_risky = sorted(
        [d for d in data.get("top_domains", []) if d.get("risk_score", 0) >= 31],
        key=lambda d: d["risk_score"], reverse=True
    )
    return {
        "browser":          data.get("meta", {}).get("browser", "Chrome"),
        "total_artifacts":  data.get("summary", {}).get("total_artifacts", 0),
        "flagged_count":    data.get("summary", {}).get("flagged_count", 0),
        "anomaly_count":    data.get("summary", {}).get("anomaly_count", 0),
        "top_risky_domains": [d["domain"] for d in top_risky[:8]],
        "anomaly_titles":   [a["title"] for a in data.get("anomalies", [])[:6]],
    }


def _err(msg: str, code: int = 500):
    return jsonify({"error": msg}), code


def register_ai_routes(app, load_analysis_fn):
    if ai is None:
        @app.route("/api/ai/status")
        def ai_unavailable():
            return jsonify({"available": False, "reason": "ai_engine module not found"}), 503
        return

    # ── Status / health ───────────────────────────────────────────────────────

    @ai_bp.route("/status")
    def ai_status():
        return jsonify({**ai.check_connection(), "available": True})

    # ── Executive summary ─────────────────────────────────────────────────────

    @ai_bp.route("/summary")
    def ai_summary():
        try:
            data = load_analysis_fn()
            if not data:
                return _err("No analysis data", 404)
            return jsonify(ai.ai_executive_summary(data))
        except Exception as e:
            return _err(str(e))

    # ── History item explainer ─────────────────────────────────────────────────

    @ai_bp.route("/explain/history")
    def ai_explain_history():
        url = request.args.get("url", "")
        if not url:
            return _err("url param required", 400)
        try:
            data = load_analysis_fn()
            history = data.get("history", [])
            # Find the item and same-domain context
            item = next((h for h in history if h.get("url") == url), None)
            if not item:
                return _err("URL not found in history", 404)
            from urllib.parse import urlparse
            domain = urlparse(url).netloc
            context = [h for h in history if urlparse(h.get("url","")).netloc == domain and h.get("url") != url]
            return jsonify(ai.ai_explain_history_item(item, context))
        except Exception as e:
            return _err(str(e))

    # ── Domain profile ────────────────────────────────────────────────────────

    @ai_bp.route("/domain/<domain>")
    def ai_domain(domain):
        try:
            data = load_analysis_fn()
            # Reuse the same domain data structure as /api/domain
            from urllib.parse import urlparse
            from serve import domain_of, _norm_dt
            history   = [h for h in data.get("history",   []) if domain in domain_of(h.get("url",""))]
            cookies   = [c for c in data.get("cookies",   []) if domain in c.get("host","").lstrip(".").removeprefix("www.")]
            downloads = [d for d in data.get("downloads", []) if domain in domain_of(d.get("source_url",""))]
            parsed_times = [_norm_dt(h.get("last_visit","")) for h in history]
            parsed_times = [t for t in parsed_times if t is not None]
            domain_data = {
                "total_visits": sum(h.get("visit_count",1) for h in history),
                "first_seen":   min(parsed_times).isoformat() if parsed_times else "",
                "last_seen":    max(parsed_times).isoformat() if parsed_times else "",
                "in_history":   len(history) > 0,
                "max_risk_score": max((h.get("risk_score",0) for h in history), default=0),
                "risk_reasons": list({r for h in history for r in h.get("risk_reasons",[])}),
                "cookies":  cookies,
                "downloads": downloads,
            }
            return jsonify(ai.ai_domain_profile(domain, domain_data))
        except Exception as e:
            return _err(str(e))

    # ── Session narrative (streaming) ─────────────────────────────────────────

    @ai_bp.route("/stream/session")
    def ai_stream_session():
        session_index = int(request.args.get("index", 0))
        try:
            data = load_analysis_fn()
            from serve import _build_unified_events, _reconstruct_sessions
            events = _build_unified_events(data)
            sessions = _reconstruct_sessions(events)
            if session_index >= len(sessions):
                return _err("Session index out of range", 404)
            session = sessions[session_index]

            def generate():
                yield 'data: {"type":"start"}\n\n'
                for delta in ai.ai_session_narrative_stream(session):
                    payload = json.dumps({"type": "delta", "text": delta})
                    yield f"data: {payload}\n\n"
                yield 'data: {"type":"done"}\n\n'

            return Response(stream_with_context(generate()),
                            mimetype="text/event-stream",
                            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
        except Exception as e:
            return _err(str(e))

    # ── Download threat assessment ─────────────────────────────────────────────

    @ai_bp.route("/explain/download")
    def ai_explain_download():
        filename = request.args.get("filename", "")
        if not filename:
            return _err("filename param required", 400)
        try:
            data = load_analysis_fn()
            downloads = data.get("downloads", [])
            item = next((d for d in downloads if d.get("filename") == filename), None)
            if not item:
                return _err("Download not found", 404)
            return jsonify(ai.ai_download_threat(item, downloads))
        except Exception as e:
            return _err(str(e))

    # ── Gap / cleared history analysis ────────────────────────────────────────

    @ai_bp.route("/gap-analysis")
    def ai_gap():
        try:
            data = load_analysis_fn()
            anomalies = data.get("anomalies", [])
            gap = next((a for a in anomalies if a.get("type") == "history_gap"), None)
            if not gap:
                return jsonify({"analysis": "No history gap anomaly detected in this profile.", "model": ai.PRIMARY_MODEL})
            top_cookie_domains = gap.get("affected_domains", [])
            return jsonify(ai.ai_gap_analysis(gap, top_cookie_domains))
        except Exception as e:
            return _err(str(e))

    # ── Anomaly deep dive ─────────────────────────────────────────────────────

    @ai_bp.route("/anomaly")
    def ai_anomaly():
        anomaly_type = request.args.get("type", "")
        if not anomaly_type:
            return _err("type param required", 400)
        try:
            data = load_analysis_fn()
            anomalies = data.get("anomalies", [])
            anomaly = next((a for a in anomalies if a.get("type") == anomaly_type), None)
            if not anomaly:
                return _err("Anomaly type not found", 404)
            domain = anomaly.get("domain", "")
            related_history = []
            related_cookies = []
            if domain:
                from serve import domain_of
                related_history = [h for h in data.get("history",[]) if domain in domain_of(h.get("url",""))][:10]
                related_cookies = [c for c in data.get("cookies",[]) if domain in c.get("host","")][:10]
            return jsonify(ai.ai_anomaly_deep_dive(anomaly, related_history, related_cookies))
        except Exception as e:
            return _err(str(e))

    # ── Narrative report (streaming) ──────────────────────────────────────────

    @ai_bp.route("/stream/report")
    def ai_stream_report():
        case_number = request.args.get("case", "")
        examiner    = request.args.get("examiner", "")
        date        = request.args.get("date", "")
        try:
            data = load_analysis_fn()
            flagged_history   = [h for h in data.get("history",   []) if h.get("risk_score",0) >= 61]
            flagged_cookies   = [c for c in data.get("cookies",   []) if c.get("risk_score",0) >= 61]
            flagged_downloads = [d for d in data.get("downloads", []) if d.get("risk_score",0) >= 61]
            report_data = {
                "meta":      data.get("meta", {}),
                "summary":   data.get("summary", {}),
                "anomalies": data.get("anomalies", []),
                "flagged": {
                    "history":   flagged_history,
                    "cookies":   flagged_cookies,
                    "downloads": flagged_downloads,
                },
            }
            case_meta = {"case_number": case_number, "examiner": examiner, "date": date}

            def generate():
                yield 'data: {"type":"start"}\n\n'
                for delta in ai.ai_narrative_report_stream(report_data, case_meta):
                    payload = json.dumps({"type": "delta", "text": delta})
                    yield f"data: {payload}\n\n"
                yield 'data: {"type":"done"}\n\n'

            return Response(stream_with_context(generate()),
                            mimetype="text/event-stream",
                            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
        except Exception as e:
            return _err(str(e))

    # ── Freeform AI chat (streaming) ──────────────────────────────────────────

    @ai_bp.route("/stream/chat", methods=["POST"])
    def ai_stream_chat():
        body = request.get_json(silent=True) or {}
        user_message = body.get("message", "").strip()
        history      = body.get("history", [])
        if not user_message:
            return _err("message required", 400)
        try:
            data = load_analysis_fn()
            snapshot = _analysis_snapshot(data)

            def generate():
                yield 'data: {"type":"start"}\n\n'
                for delta in ai.ai_chat_stream(user_message, history, snapshot):
                    payload = json.dumps({"type": "delta", "text": delta})
                    yield f"data: {payload}\n\n"
                yield 'data: {"type":"done"}\n\n'

            return Response(stream_with_context(generate()),
                            mimetype="text/event-stream",
                            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
        except Exception as e:
            return _err(str(e))

    app.register_blueprint(ai_bp)
    print("[AI] Routes registered — /api/ai/*")