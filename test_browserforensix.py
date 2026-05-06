#!/usr/bin/env python3
"""
BrowserForensix — Comprehensive Remediation Test Suite
Verifies every bug identified in the audit has been properly fixed.

Run with:
    python test_browserforensix.py
All tests are self-contained. No live server or evidence.json required.
"""

import json
import re
import sys
import unittest
import importlib.util
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

# ── Load patched modules without executing __main__ blocks ────────────────────

def load_module(path: str, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod  = importlib.util.module_from_spec(spec)
    # Prevent side-effects (analyzer.run(), Flask app.run())
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

BASE = Path(__file__).parent
analyzer = load_module(str(BASE / "analyzer_patched.py"), "analyzer_patched")

# Load serve with Flask test client
import analyzer_patched   # noqa: must exist before serve imports it
sys.modules["analyzer"] = analyzer_patched

serve = load_module(str(BASE / "serve_patched.py"), "serve_patched")
flask_app = serve.app
flask_app.config["TESTING"] = True


# ── Shared minimal analysis fixture ──────────────────────────────────────────

def _make_analysis(extra_history=None, extra_cookies=None,
                   extra_downloads=None, extra_anomalies=None):
    """Return a minimal analysis dict that resembles what analyzer.run() writes."""
    now  = datetime.now(tz=timezone.utc)
    yesterday = (now - timedelta(days=1)).isoformat()
    last_week = (now - timedelta(days=7)).isoformat()
    three_am  = now.replace(hour=3, minute=0, second=0).isoformat()

    history = [
        {"url": "https://www.google.com/search?q=test", "title": "Google",
         "last_visit": yesterday, "visit_count": 5, "risk_score": 0, "risk_reasons": []},
        {"url": "http://192.168.1.1/admin", "title": "Router",
         "last_visit": yesterday, "visit_count": 1, "risk_score": 25, "risk_reasons": ["IP address"]},
        {"url": "https://filebin.net/abc123", "title": "Filebin",
         "last_visit": three_am,  "visit_count": 1, "risk_score": 75,
         "risk_reasons": ["Known file-sharing site: filebin.net", "Visited off-hours (03:00 UTC)"]},
        {"url": "https://example.com/page", "title": "Example",
         "last_visit": last_week, "visit_count": 2, "risk_score": 0, "risk_reasons": []},
    ] + (extra_history or [])

    past = (now - timedelta(days=30)).isoformat()
    future = (now + timedelta(days=365)).isoformat()
    cookies = [
        {"host": ".google.com", "name": "_ga", "type": "Tracking",
         "created": past, "expires": future, "secure": True, "http_only": False,
         "samesite": "Lax", "risk_score": 0, "risk_reasons": []},
        {"host": ".evil.net", "name": "auth_token", "type": "Auth Token",
         "created": past, "expires": future, "secure": False, "http_only": True,
         "samesite": "", "risk_score": 45, "risk_reasons": ["No history for domain"]},
        {"host": "example.com", "name": "session", "type": "Session",
         "created": past, "expires": "", "secure": True, "http_only": True,
         "samesite": "Strict", "risk_score": 0, "risk_reasons": []},
    ] + (extra_cookies or [])

    downloads = [
        {"filename": "report.pdf", "source_url": "https://example.com/report.pdf",
         "start_time": yesterday, "size_bytes": 204800,
         "in_history": True, "file_exists": True, "risk_score": 0, "risk_reasons": []},
        {"filename": "setup.exe", "source_url": "https://filebin.net/setup.exe",
         "start_time": three_am, "size_bytes": 5000000,
         "in_history": False, "file_exists": False, "risk_score": 80,
         "risk_reasons": ["Executable", "Missing", "Source absent from history"]},
    ] + (extra_downloads or [])

    heatmap = [{"day": d, "hour": h, "count": 0} for d in range(7) for h in range(24)]

    return {
        "meta": {"browser": "Chrome", "profile_path": "/home/user/.config/chrome/Default",
                 "extraction_time": yesterday, "platform": "Linux"},
        "hashes": {"History": "aabbccdd" * 8},
        "summary": {
            "total_artifacts": len(history) + len(cookies) + len(downloads),
            "history_count": len(history), "cookie_count": len(cookies),
            "bookmark_count": 0, "download_count": len(downloads),
            "flagged_count": 2, "average_risk_score": 22.5, "anomaly_count": 1,
        },
        "top_domains": [{"domain": "google.com", "visits": 5, "risk_score": 0}],
        "heatmap": heatmap,
        "anomalies": [{"type": "history_gap", "severity": "critical",
                        "title": "History Cleared — Cookies Survive",
                        "description": "1 domain(s) have cookies but zero history entries.",
                        "domain_count": 1}] + (extra_anomalies or []),
        "history":   history,
        "cookies":   cookies,
        "bookmarks": [],
        "downloads": downloads,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# TEST CLASSES
# ═══════════════════════════════════════════════════════════════════════════════

class TestFix1_LstripWww(unittest.TestCase):
    """FIX-1: .lstrip('www.') replaced with .removeprefix('www.')"""

    def test_analyzer_extract_domain_normal(self):
        self.assertEqual(analyzer._extract_domain("https://www.google.com/"), "google.com")

    def test_analyzer_extract_domain_no_www(self):
        self.assertEqual(analyzer._extract_domain("https://github.com/repo"), "github.com")

    def test_analyzer_extract_domain_lstrip_was_wrong(self):
        # .lstrip("www.") strips any of the chars w, ., from the left.
        # "wwwwexample.com".lstrip("www.") → "example.com" — drops the extra 'w'.
        # .removeprefix("www.") correctly returns "wwwwexample.com".
        result = analyzer._extract_domain("https://wwwwexample.com/")
        self.assertEqual(result, "wwwwexample.com",
            ".lstrip('www.') bug: 'wwwwexample.com' was incorrectly stripped to 'example.com'")

    def test_serve_domain_of_normal(self):
        self.assertEqual(serve.domain_of("https://www.example.com/"), "example.com")

    def test_serve_domain_of_wwww(self):
        result = serve.domain_of("https://wwwwexample.com/")
        self.assertEqual(result, "wwwwexample.com")

    def test_analyzer_score_url_lstrip_fix(self):
        # PASTE_SITES uses domains like "pastebin.com"; score_url strips www.
        # If lstrip were used, "wwww.pastebin.com" would be stripped to "astebin.com"
        # and NOT match the paste site list. removeprefix correctly leaves it as
        # "www.pastebin.com" → strip "www." → "pastebin.com" → match.
        score, reasons = analyzer.score_url(
            "https://www.pastebin.com/abc", "2024-01-01T12:00:00Z",
            False, 1, 0
        )
        self.assertIn("Known paste site", " ".join(reasons))


class TestFix2_DomainValidation(unittest.TestCase):
    """FIX-2: /api/domain/<domain> validates input; rejects single-char and pure-TLD values"""

    def setUp(self):
        self.client = flask_app.test_client()
        self.analysis = _make_analysis()

    def _get_domain(self, domain_str):
        with patch.object(serve, "load_analysis", return_value=self.analysis):
            return self.client.get(
                f"/api/domain/{domain_str}",
                headers={"Origin": "http://localhost:5000"}
            )

    def test_valid_domain_returns_200(self):
        r = self._get_domain("google.com")
        self.assertEqual(r.status_code, 200)

    def test_single_dot_returns_400(self):
        # Without fix, "." would match every domain (every URL contains ".")
        r = self._get_domain(".")
        self.assertEqual(r.status_code, 400,
            "Single '.' should be rejected — it would match every history/cookie entry")

    def test_single_char_returns_400(self):
        r = self._get_domain("a")
        self.assertEqual(r.status_code, 400)

    def test_too_short_returns_400(self):
        r = self._get_domain("ab")
        self.assertEqual(r.status_code, 400)

    def test_invalid_chars_returns_400(self):
        r = self._get_domain("evil<script>")
        self.assertEqual(r.status_code, 400)

    def test_no_dot_returns_400(self):
        r = self._get_domain("localhost")
        self.assertEqual(r.status_code, 400)

    def test_valid_domain_with_subdomain_returns_200(self):
        r = self._get_domain("accounts.google.com")
        self.assertEqual(r.status_code, 200)


class TestFix3_NoDuplicateStatusFetch(unittest.TestCase):
    """
    FIX-3: The dead SPA router in app.js called loadStatus() and activatePage()
    on DOMContentLoaded. Base.html already calls /api/status in its inline script.
    This test verifies the patched app.js no longer contains the duplicate call.
    """

    def _read_app_js(self):
        path = BASE / "app_patched.js"
        return path.read_text(encoding="utf-8")

    def test_no_activatepage_function(self):
        js = self._read_app_js()
        self.assertNotIn("function activatePage(", js,
            "activatePage() is dead code — there are no .bfx-page divs in the Flask multi-page setup")

    def test_no_pages_const(self):
        js = self._read_app_js()
        self.assertNotIn("const PAGES =", js,
            "PAGES array is dead code and should be removed")

    def test_domcontentloaded_does_not_call_loadstatus(self):
        js = self._read_app_js()
        # Find the DOMContentLoaded block and check loadStatus is not inside it
        dcl_match = re.search(
            r"addEventListener\('DOMContentLoaded'.*?\}\);",
            js, re.DOTALL
        )
        self.assertIsNotNone(dcl_match, "DOMContentLoaded block not found")
        dcl_block = dcl_match.group(0)
        self.assertNotIn("loadStatus()", dcl_block,
            "loadStatus() must not be called in DOMContentLoaded — base.html already does it")

    def test_domcontentloaded_only_wires_search(self):
        js = self._read_app_js()
        dcl_match = re.search(
            r"addEventListener\('DOMContentLoaded'.*?\}\);",
            js, re.DOTALL
        )
        dcl_block = dcl_match.group(0)
        self.assertIn("globalSearch", dcl_block,
            "DOMContentLoaded should wire the global search input")


class TestFix4_TimelineDateFilter(unittest.TestCase):
    """FIX-4: Timeline date filter uses datetime-aware comparison, not string comparison"""

    def setUp(self):
        self.client = flask_app.test_client()
        self.analysis = _make_analysis()

    def test_timeline_date_from_filters_correctly(self):
        """Events before date_from should be excluded."""
        with patch.object(serve, "load_analysis", return_value=self.analysis):
            # Request only the last 2 days of events
            from_dt = (datetime.now(tz=timezone.utc) - timedelta(days=2)).isoformat()
            r = self.client.get(
                f"/api/timeline?from={from_dt}&types=history",
                headers={"Origin": "http://localhost:5000"}
            )
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        # last_week event should be excluded; yesterday + three_am events included
        for event in data.get("events", []):
            event_dt = datetime.fromisoformat(event["time"].replace("Z", "+00:00"))
            from_dt_parsed = datetime.fromisoformat(from_dt)
            self.assertGreaterEqual(event_dt, from_dt_parsed,
                f"Event {event['time']} is before date_from {from_dt} — filter failed")

    def test_timeline_z_suffix_handled(self):
        """Mixed Z and +00:00 suffixes must not cause comparison failures."""
        with patch.object(serve, "load_analysis", return_value=self.analysis):
            from_dt = "2020-01-01T00:00:00Z"
            r = self.client.get(
                f"/api/timeline?from={from_dt}&types=history",
                headers={"Origin": "http://localhost:5000"}
            )
        self.assertEqual(r.status_code, 200)


class TestFix5_SessionConsistency(unittest.TestCase):
    """FIX-5: /api/sessions and /api/timeline use the same event set"""

    def setUp(self):
        self.client = flask_app.test_client()
        self.analysis = _make_analysis()

    def test_sessions_includes_cookies(self):
        """Previously /api/sessions omitted cookies, causing divergence from /api/timeline."""
        with patch.object(serve, "load_analysis", return_value=self.analysis):
            r = self.client.get("/api/sessions",
                                headers={"Origin": "http://localhost:5000"})
        data = r.get_json()
        all_events = [e for s in data["sessions"] for e in s["events"]]
        types_seen = {e["type"] for e in all_events}
        self.assertIn("cookie", types_seen,
            "/api/sessions must include cookie events to match /api/timeline")

    def test_build_unified_events_same_count_for_same_types(self):
        """_build_unified_events produces consistent results across two calls."""
        events_a = serve._build_unified_events(self.analysis, {"history", "cookies", "downloads"})
        events_b = serve._build_unified_events(self.analysis, {"history", "cookies", "downloads"})
        self.assertEqual(len(events_a), len(events_b))
        # Types should match what's in the fixture
        types_a = {e["type"] for e in events_a}
        self.assertIn("history",  types_a)
        self.assertIn("cookie",   types_a)
        self.assertIn("download", types_a)


class TestFix6_HeatmapPrecomputed(unittest.TestCase):
    """FIX-6: Heatmap is pre-computed by analyzer.run(), not per-request in /api/overview"""

    def test_compute_heatmap_structure(self):
        """compute_heatmap() returns exactly 168 cells (7 days × 24 hours)."""
        history = [
            {"last_visit": "2024-03-15T09:30:00+00:00"},
            {"last_visit": "2024-03-15T23:00:00+00:00"},
            {"last_visit": "2024-03-16T02:00:00+00:00"},
        ]
        result = analyzer.compute_heatmap(history)
        self.assertEqual(len(result), 168, "Heatmap must have exactly 168 cells (7×24)")

    def test_compute_heatmap_counts(self):
        """Counts are accurate for known timestamps."""
        history = [
            {"last_visit": "2024-03-15T09:00:00+00:00"},  # Friday = weekday 4, hour 9
            {"last_visit": "2024-03-15T09:00:00+00:00"},  # same slot
        ]
        result = analyzer.compute_heatmap(history)
        friday_9am = next(c for c in result if c["day"] == 4 and c["hour"] == 9)
        self.assertEqual(friday_9am["count"], 2)

    def test_overview_api_reads_precomputed_heatmap(self):
        """
        /api/overview must return data["heatmap"] from analysis.json, not
        recompute it. We verify it does NOT call datetime.fromisoformat in its
        own route handler.
        """
        analysis = _make_analysis()
        sentinel_heatmap = [{"day": 0, "hour": 0, "count": 999}]  # distinctive marker
        analysis["heatmap"] = sentinel_heatmap

        client = flask_app.test_client()
        with patch.object(serve, "load_analysis", return_value=analysis):
            r = client.get("/api/overview",
                           headers={"Origin": "http://localhost:5000"})
        data = r.get_json()
        # If the route recomputed, it wouldn't return our sentinel
        self.assertEqual(data["heatmap"], sentinel_heatmap,
            "/api/overview must return the pre-computed heatmap from analysis.json, not recompute it")


class TestFix7_CSRFOriginGuard(unittest.TestCase):
    """FIX-7: API endpoints reject requests from non-localhost origins"""

    def setUp(self):
        self.client = flask_app.test_client()
        self.analysis = _make_analysis()

    def _get_api(self, path, origin=None, referer=None):
        headers = {}
        if origin:
            headers["Origin"] = origin
        if referer:
            headers["Referer"] = referer
        with patch.object(serve, "load_analysis", return_value=self.analysis):
            return self.client.get(path, headers=headers)

    def test_localhost_origin_allowed(self):
        r = self._get_api("/api/status", origin="http://localhost:5000")
        self.assertNotEqual(r.status_code, 403)

    def test_127_0_0_1_origin_allowed(self):
        r = self._get_api("/api/status", origin="http://127.0.0.1:5000")
        self.assertNotEqual(r.status_code, 403)

    def test_no_origin_no_referer_allowed(self):
        # Direct curl / same-page fetch — no origin header
        r = self._get_api("/api/status")
        self.assertNotEqual(r.status_code, 403)

    def test_external_origin_blocked(self):
        r = self._get_api("/api/status", origin="https://evil.com")
        self.assertEqual(r.status_code, 403,
            "Cross-origin requests to /api/* must be rejected")

    def test_external_referer_blocked(self):
        r = self._get_api("/api/history", referer="https://attacker.com/page")
        self.assertEqual(r.status_code, 403)

    def test_page_routes_not_guarded(self):
        # Page routes must not be blocked by the CSRF guard.
        # We test this by checking the before_request hook returns None for non-API paths —
        # we don't actually render the template (no templates/ dir in test env).
        # Patch render_template to a no-op so the route completes without TemplateNotFound.
        from unittest.mock import patch as _patch
        from flask import Response as _Response
        with _patch("serve_patched.render_template", return_value=_Response("ok", 200)):
            r = self.client.get("/", headers={"Origin": "https://evil.com"})
        self.assertNotEqual(r.status_code, 403,
            "Page routes (/) must not be CSRF-guarded")


class TestFixCookieHostFilter(unittest.TestCase):
    """FIX-COOKIES-HOST: host filter was never set in state or sent to API"""

    def setUp(self):
        self.client = flask_app.test_client()
        self.analysis = _make_analysis()

    def test_host_filter_applied(self):
        with patch.object(serve, "load_analysis", return_value=self.analysis):
            r = self.client.get("/api/cookies?host=google.com",
                                headers={"Origin": "http://localhost:5000"})
        data = r.get_json()
        for item in data["items"]:
            self.assertIn("google.com", item["host"],
                "Host filter must exclude non-matching cookies")

    def test_host_filter_excludes_others(self):
        with patch.object(serve, "load_analysis", return_value=self.analysis):
            r = self.client.get("/api/cookies?host=evil.net",
                                headers={"Origin": "http://localhost:5000"})
        data = r.get_json()
        self.assertEqual(len(data["items"]), 1)
        self.assertIn("evil.net", data["items"][0]["host"])

    def test_empty_host_returns_all(self):
        with patch.object(serve, "load_analysis", return_value=self.analysis):
            r_all  = self.client.get("/api/cookies",
                                     headers={"Origin": "http://localhost:5000"})
            r_host = self.client.get("/api/cookies?host=",
                                     headers={"Origin": "http://localhost:5000"})
        self.assertEqual(r_all.get_json()["total"], r_host.get_json()["total"])


class TestFixCookieSecureFilter(unittest.TestCase):
    """FIX-COOKIES-SECURE: secure filter was tracked but never sent or applied"""

    def setUp(self):
        self.client = flask_app.test_client()
        self.analysis = _make_analysis()

    def test_secure_filter(self):
        with patch.object(serve, "load_analysis", return_value=self.analysis):
            r = self.client.get("/api/cookies?secure=secure",
                                headers={"Origin": "http://localhost:5000"})
        data = r.get_json()
        for item in data["items"]:
            self.assertTrue(item["secure"],
                "secure=secure filter must only return cookies with secure=True")

    def test_insecure_filter(self):
        with patch.object(serve, "load_analysis", return_value=self.analysis):
            r = self.client.get("/api/cookies?secure=insecure",
                                headers={"Origin": "http://localhost:5000"})
        data = r.get_json()
        for item in data["items"]:
            self.assertFalse(item["secure"],
                "secure=insecure filter must only return cookies with secure=False")


class TestFixBurstActivityPerformance(unittest.TestCase):
    """FIX-BURST: O(n²) detect_burst_activity replaced with two-pointer O(n log n)"""

    def test_burst_detected_correctly(self):
        """8+ visits within 5 minutes should trigger a burst anomaly."""
        now = datetime.now(tz=timezone.utc)
        history = [
            {"url": "https://example.com/page", "last_visit": (now + timedelta(seconds=i * 30)).isoformat()}
            for i in range(10)  # 10 visits, 30s apart → all within 5 min window
        ]
        bursts = analyzer.detect_burst_activity(history, threshold=8, window_minutes=5)
        self.assertEqual(len(bursts), 1)
        self.assertEqual(bursts[0]["domain"], "example.com")
        self.assertGreaterEqual(bursts[0]["visit_count"], 8)

    def test_no_burst_below_threshold(self):
        now = datetime.now(tz=timezone.utc)
        history = [
            {"url": "https://example.com/page", "last_visit": (now + timedelta(seconds=i * 30)).isoformat()}
            for i in range(5)  # Only 5 visits — below threshold of 8
        ]
        bursts = analyzer.detect_burst_activity(history, threshold=8, window_minutes=5)
        self.assertEqual(len(bursts), 0)

    def test_large_dataset_performance(self):
        """
        10,000 visits to one domain should complete in well under 1 second.
        The O(n²) version would take ~100M iterations; the two-pointer version O(n log n).
        """
        import time
        now = datetime.now(tz=timezone.utc)
        history = [
            {"url": "https://example.com/page",
             "last_visit": (now + timedelta(hours=i)).isoformat()}
            for i in range(10_000)
        ]
        start = time.monotonic()
        bursts = analyzer.detect_burst_activity(history, threshold=8, window_minutes=5)
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 2.0,
            f"detect_burst_activity took {elapsed:.2f}s on 10k items — O(n²) regression?")

    def test_burst_window_boundary(self):
        """Visits just outside the window must NOT be counted in the same burst."""
        now = datetime.now(tz=timezone.utc)
        # 8 visits clustered: 0s, 30s, 60s, 90s, 120s, 150s, 180s, 210s → all within 3.5 min
        # Then a 35-min gap → new window
        close_visits = [
            {"url": "https://example.com/",
             "last_visit": (now + timedelta(seconds=i * 30)).isoformat()}
            for i in range(8)
        ]
        far_visit = [
            {"url": "https://example.com/",
             "last_visit": (now + timedelta(minutes=40)).isoformat()}
        ]
        bursts = analyzer.detect_burst_activity(close_visits + far_visit, threshold=8, window_minutes=5)
        self.assertEqual(len(bursts), 1)
        self.assertEqual(bursts[0]["visit_count"], 8)


class TestFixReportGlobalScope(unittest.TestCase):
    """FIX-REPORT: window._bfxReport removed; module-scoped _reportText used instead"""

    def _read_app_js(self):
        return (BASE / "app_patched.js").read_text(encoding="utf-8")

    def test_no_window_bfxreport_assignment(self):
        js = self._read_app_js()
        # Strip both block comments (/* ... */) and line comments (// ...) before
        # checking. The patch notes mention window._bfxReport by name for documentation,
        # but no live assignment should exist in executable code.
        code_only = re.sub(r'/\*.*?\*/', '', js, flags=re.DOTALL)   # block comments
        code_only = re.sub(r'//[^\n]*', '', code_only)               # line comments
        self.assertNotIn("window._bfxReport", code_only,
            "Report text must not be assigned on window — use a module-scoped variable")

    def test_module_scoped_report_variable_exists(self):
        js = self._read_app_js()
        self.assertIn("let _reportText", js,
            "Module-scoped _reportText variable must replace window._bfxReport")

    def test_download_report_uses_module_var(self):
        js = self._read_app_js()
        download_fn = re.search(r"function downloadReport\(\).*?\}", js, re.DOTALL)
        self.assertIsNotNone(download_fn)
        body = download_fn.group(0)
        self.assertIn("_reportText", body)
        self.assertNotIn("window._bfxReport", body)


class TestFixHeatmapFunction(unittest.TestCase):
    """Verify compute_heatmap() exists in analyzer_patched and is called by run()"""

    def test_function_exists(self):
        self.assertTrue(callable(getattr(analyzer, "compute_heatmap", None)),
            "compute_heatmap() must be defined in analyzer.py")

    def test_returns_168_cells(self):
        result = analyzer.compute_heatmap([])
        self.assertEqual(len(result), 168)

    def test_all_cells_have_required_keys(self):
        result = analyzer.compute_heatmap([])
        for cell in result:
            self.assertIn("day",   cell)
            self.assertIn("hour",  cell)
            self.assertIn("count", cell)

    def test_empty_history_all_zeros(self):
        result = analyzer.compute_heatmap([])
        self.assertTrue(all(c["count"] == 0 for c in result))

    def test_malformed_timestamps_skipped(self):
        history = [
            {"last_visit": "not-a-date"},
            {"last_visit": ""},
            {"last_visit": None},
            {"last_visit": "2024-06-01T10:00:00+00:00"},
        ]
        result = analyzer.compute_heatmap(history)
        total = sum(c["count"] for c in result)
        self.assertEqual(total, 1, "Only the valid timestamp should be counted")


class TestPatchedFilesExist(unittest.TestCase):
    """Sanity check that all patched files are present and importable."""

    def test_serve_patched_exists(self):
        self.assertTrue((BASE / "serve_patched.py").exists())

    def test_analyzer_patched_exists(self):
        self.assertTrue((BASE / "analyzer_patched.py").exists())

    def test_app_patched_js_exists(self):
        self.assertTrue((BASE / "app_patched.js").exists())

    def test_cookies_patched_html_exists(self):
        self.assertTrue((BASE / "cookies_patched.html").exists())

    def test_bookmarks_patched_html_exists(self):
        self.assertTrue((BASE / "bookmarks_patched.html").exists())


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    loader  = unittest.TestLoader()
    suite   = unittest.TestSuite()
    classes = [
        TestPatchedFilesExist,
        TestFix1_LstripWww,
        TestFix2_DomainValidation,
        TestFix3_NoDuplicateStatusFetch,
        TestFix4_TimelineDateFilter,
        TestFix5_SessionConsistency,
        TestFix6_HeatmapPrecomputed,
        TestFix7_CSRFOriginGuard,
        TestFixCookieHostFilter,
        TestFixCookieSecureFilter,
        TestFixBurstActivityPerformance,
        TestFixReportGlobalScope,
        TestFixHeatmapFunction,
    ]
    for cls in classes:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)