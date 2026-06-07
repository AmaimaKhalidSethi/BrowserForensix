#!/usr/bin/env python3
"""BrowserForensix — data_routes.py
Blueprint for data API routes moved out of serve.py.

Register with: register_data_routes(app, load_analysis_fn, helpers)
where helpers is a dict containing helper functions used by these routes.
"""
import json
from flask import Blueprint, jsonify, request

data_bp = Blueprint("data", __name__, url_prefix="/api")


def register_data_routes(app, load_analysis_fn, helpers: dict):
    domain_of = helpers["domain_of"]
    norm_dt = helpers["_norm_dt"]
    build_unified_events = helpers["_build_unified_events"]
    reconstruct_sessions = helpers["_reconstruct_sessions"]
    paginate = helpers.get("paginate")
    filter_risk = helpers.get("filter_risk")
    _safe_int = helpers.get("_safe_int")
    _validate_domain_param = helpers.get("_validate_domain_param")

    @data_bp.route('/history')
    def api_history():
        data = load_analysis_fn()
        items = data.get("history", [])
        q = request.args.get("q", "").lower()
        profile = request.args.get("profile", "").strip()
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
            df = norm_dt(date_from + "T00:00:00+00:00") if date_from else None
            dt_end = norm_dt(date_to + "T23:59:59+00:00") if date_to else None

            def _in_range(item):
                ts = norm_dt(item.get("last_visit", ""))
                if ts is None:
                    return True
                if df and ts < df:
                    return False
                if dt_end and ts > dt_end:
                    return False
                return True

            items = [i for i in items if _in_range(i)]

        return jsonify(paginate(items, page))

    @data_bp.route('/cookies')
    def api_cookies():
        data = load_analysis_fn()
        items = data.get("cookies", [])
        profile = request.args.get("profile", "").strip()
        ctype = request.args.get("type", "all").lower()
        host = request.args.get("host", "").strip().lower()
        expired = request.args.get("expired", "all")
        secure = request.args.get("secure", "all")
        page = _safe_int(request.args.get("page", 1))

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

    @data_bp.route('/bookmarks')
    def api_bookmarks():
        data = load_analysis_fn()
        bookmarks = data.get("bookmarks", [])
        tree = {}
        for b in bookmarks:
            tree.setdefault(b.get("folder", "Other"), []).append(b)

        q = request.args.get("q", "").lower()
        if q:
            bookmarks = [b for b in bookmarks if q in b.get("title", "").lower() or q in b.get("url", "").lower()]
            return jsonify({"items": bookmarks, "total": len(bookmarks)})

        return jsonify({"tree": tree, "total": len(bookmarks)})

    @data_bp.route('/downloads')
    def api_downloads():
        data = load_analysis_fn()
        items = data.get("downloads", [])
        q = request.args.get("q", "").lower()
        profile = request.args.get("profile", "").strip()
        risk = request.args.get("risk", "any").lower()
        page = _safe_int(request.args.get("page", 1))

        if profile:
            items = [i for i in items if i.get("profile", "") == profile]
        if q:
            items = [i for i in items if q in i.get("filename", "").lower() or q in i.get("source_url", "").lower()]
        if risk != "any":
            items = filter_risk(items, risk)

        return jsonify(paginate(items, page))

    @data_bp.route('/timeline')
    def api_timeline():
        data = load_analysis_fn()
        types_param = request.args.get("types", "history,cookies,downloads")
        types = set(types_param.split(","))
        events = build_unified_events(data, types)

        date_from_str = request.args.get("from", "")
        date_to_str = request.args.get("to", "")

        if date_from_str or date_to_str:
            df = norm_dt(date_from_str) if date_from_str else None
            dt_end = norm_dt(date_to_str) if date_to_str else None

            def _in_range(e: dict) -> bool:
                ts = norm_dt(e.get("time", ""))
                if ts is None:
                    return True
                if df and ts < df:
                    return False
                if dt_end and ts > dt_end:
                    return False
                return True

            events = [e for e in events if _in_range(e)]

        sessions = reconstruct_sessions(events)
        return jsonify({"events": events[:500], "sessions": sessions, "total": len(events)})

    @data_bp.route('/domain/<domain>')
    def api_domain(domain: str):
        if _validate_domain_param:
            try:
                domain = _validate_domain_param(domain)
            except ValueError as e:
                return jsonify({"error": str(e)}), 400
        else:
            domain = domain.lower().strip().removeprefix("www.")
        data = load_analysis_fn()

        def _matches(candidate: str) -> bool:
            return candidate == domain or candidate.endswith("." + domain)

        history = [h for h in data.get("history", []) if _matches(domain_of(h.get("url", "")))]
        cookies = [c for c in data.get("cookies", []) if _matches(c.get("host", "").lstrip(".").removeprefix("www."))]
        downloads = [d for d in data.get("downloads", []) if _matches(domain_of(d.get("source_url", "")))]

        parsed_times = [norm_dt(h.get("last_visit", "")) for h in history]
        parsed_times = [t for t in parsed_times if t is not None]

        return jsonify({
            "domain": domain,
            "history": history,
            "cookies": cookies,
            "downloads": downloads,
            "first_seen": min(parsed_times).isoformat() if parsed_times else "",
            "last_seen": max(parsed_times).isoformat() if parsed_times else "",
            "total_visits": sum(h.get("visit_count", 1) for h in history),
            "max_risk_score": max((h.get("risk_score", 0) for h in history), default=0),
            "risk_reasons": list({r for h in history for r in h.get("risk_reasons", [])}),
            "in_history": len(history) > 0,
        })

    @data_bp.route('/sessions')
    def api_sessions():
        data = load_analysis_fn()
        events = build_unified_events(data, types={"history", "cookies", "downloads"})
        return jsonify({"sessions": reconstruct_sessions(events)})

    @data_bp.route('/search')
    def api_search():
        data = load_analysis_fn()
        q = request.args.get("q", "").lower()
        if not q or len(q) < 2:
            return jsonify({"error": "Query too short"}), 400

        all_history = [h for h in data.get("history", []) if q in h.get("url", "").lower() or q in h.get("title", "").lower()]
        all_cookies = [c for c in data.get("cookies", []) if q in c.get("host", "").lower() or q in c.get("name", "").lower()]
        all_bookmarks = [b for b in data.get("bookmarks", []) if q in b.get("title", "").lower() or q in b.get("url", "").lower()]
        all_downloads = [d for d in data.get("downloads", []) if q in d.get("filename", "").lower() or q in d.get("source_url", "").lower()]

        return jsonify({
            "history": all_history[:20],
            "cookies": all_cookies[:20],
            "bookmarks": all_bookmarks[:20],
            "downloads": all_downloads[:20],
            "total": len(all_history) + len(all_cookies) + len(all_bookmarks) + len(all_downloads),
            "total_preview": 20,
        })

    @data_bp.route('/graph')
    def api_graph():
        data = load_analysis_fn()
        history = data.get("history", [])
        cookies = data.get("cookies", [])
        downloads = data.get("downloads", [])

        domain_meta = {}
        for h in history:
            d = domain_of(h.get("url", ""))
            if not d:
                continue
            if d not in domain_meta:
                domain_meta[d] = {"visits": 0, "risk": 0, "has_download": False, "has_cookie": False}
            domain_meta[d]["visits"] += h.get("visit_count", 1)
            domain_meta[d]["risk"] = max(domain_meta[d]["risk"], h.get("risk_score", 0))

        for c in cookies:
            d = c.get("host", "").lstrip(".")
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
                domain_meta[d]["risk"] = max(domain_meta[d]["risk"], dl.get("risk_score", 0))

        top = sorted(domain_meta.items(), key=lambda x: x[1]["visits"] * 2 + x[1]["risk"], reverse=True)[:60]
        top_domains = {d for d, _ in top}

        nodes = []
        for d, m in top:
            risk = m["risk"]
            group = "flagged" if risk >= 61 else "moderate" if risk >= 31 else "normal"
            nodes.append({"id": d, "visits": m["visits"], "risk": risk, "group": group,
                          "has_cookie": m["has_cookie"], "has_download": m["has_download"]})

        edges = []
        seen_edges = set()
        root_map = {}
        for c in cookies:
            host = c.get("host", "").lstrip(".")
            root = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host
            d = host.removeprefix("www.")
            if d in top_domains:
                root_map.setdefault(root, []).append(d)

        for root, doms in root_map.items():
            unique = list(set(doms))
            for i in range(len(unique)):
                for j in range(i + 1, len(unique)):
                    a, b = sorted([unique[i], unique[j]])
                    key = (a, b, "shared_cookie")
                    if key not in seen_edges:
                        seen_edges.add(key)
                        edges.append({"source": a, "target": b, "type": "shared_cookie"})

        events = build_unified_events(data)
        sessions = reconstruct_sessions(events)
        for session in sessions:
            sess_domains = list({
                domain_of(e.get("url", ""))
                for e in session.get("events", [])
                if e.get("type") == "history" and domain_of(e.get("url", "")) in top_domains
            })
            for i in range(len(sess_domains)):
                for j in range(i + 1, len(sess_domains)):
                    a, b = sorted([sess_domains[i], sess_domains[j]])
                    key = (a, b, "same_session")
                    if key not in seen_edges:
                        seen_edges.add(key)
                        edges.append({"source": a, "target": b, "type": "same_session"})

        return jsonify({"nodes": nodes, "edges": edges})

    @data_bp.route('/localstorage')
    def api_localstorage():
        data = load_analysis_fn()
        items = data.get("local_storage", [])
        q = request.args.get("q", "").lower()
        origin = request.args.get("origin", "").lower()
        source = request.args.get("source", "").strip()
        page = _safe_int(request.args.get("page", 1))

        if q:
            items = [i for i in items if q in i.get("key", "").lower()
                     or q in i.get("value", "").lower()
                     or q in i.get("origin", "").lower()]
        if origin:
            items = [i for i in items if origin in i.get("origin", "").lower()]
        if source:
            items = [i for i in items if i.get("source", "") == source]

        return jsonify(paginate(items, page))

    app.register_blueprint(data_bp)
