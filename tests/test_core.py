import sys
from pathlib import Path

import pytest
from flask import Flask

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import analyzer
import extract
import serve
from analysis import anomalies, heatmap, sessions
from analysis import scoring
from data_routes import register_data_routes


def test_chrome_epoch_to_iso_uses_utc_epoch():
    assert extract.chrome_epoch_to_iso(11644473600000000) == "1970-01-01T00:00:00+00:00"


def test_domain_helpers_normalize_www_and_ports():
    assert serve.domain_of("https://www.example.com:8443/path") == "example.com"


def test_norm_dt_handles_timezone_offsets_and_invalid_values():
    assert serve._norm_dt("2026-05-29T12:30:00+05:30").isoformat() == "2026-05-29T07:00:00+00:00"
    assert serve._norm_dt("not-a-date") is None


def test_invalid_domain_param_rejects_path_tricks():
    with serve.app.test_request_context("/api/domain/bad"):
        with pytest.raises(Exception):
            serve._validate_domain_param("../data/evidence.json")


def test_score_url_flags_direct_ip_and_suspicious_keyword():
    assert analyzer.score_url is scoring.score_url

    score, reasons = scoring.score_url(
        "http://185.220.101.47/payload.exe",
        "2026-05-29T03:10:00+00:00",
        has_cookie=False,
        visit_count=1,
        transition=1,
    )

    assert score >= 60
    assert "direct IP access" in reasons
    assert any("off-hours" in reason for reason in reasons)


def test_cookie_classification_handles_non_string_fields():
    cookie = {"name": 12345, "value": 99, "expires": None, "samesite": None}

    assert scoring.classify_cookie(cookie) == "Session"


def test_cookie_auth_token_takes_precedence_over_tracking_name():
    cookie = {"name": "_ga_token", "value": "abc", "expires": "2030-01-01T00:00:00+00:00"}

    assert scoring.classify_cookie(cookie) == "Auth Token"


def test_download_scoring_marks_missing_executable_without_history():
    score, reasons = scoring.score_download(
        {
            "filename": "dropper.exe",
            "source_url": "https://files.example/dropper.exe",
            "file_exists": False,
            "danger_type": 1,
        },
        in_history=False,
    )

    assert score >= 80
    assert "source domain absent from history" in reasons
    assert any("high-risk extension" in reason for reason in reasons)


def test_detect_history_gap_between_cookies_and_history():
    assert analyzer.detect_history_gaps is anomalies.detect_history_gaps

    anomaly = analyzer.detect_history_gaps(
        history=[{"url": "https://example.com", "last_visit": "2026-05-29T00:00:00+00:00"}],
        cookies=[{"host": ".secret-drop.io", "name": "session", "created": "2026-05-29T01:00:00+00:00"}],
    )

    assert anomaly is not None
    assert anomaly["type"] == "history_gap"


def test_heatmap_is_moved_to_analysis_module():
    assert analyzer.compute_heatmap is heatmap.compute_heatmap

    points = heatmap.compute_heatmap([
        {"last_visit": "2026-05-24T03:00:00+00:00"},
    ])

    assert len(points) == 168
    assert any(p == {"day": 0, "hour": 3, "count": 1} for p in points)


def test_session_helpers_are_moved_to_analysis_module():
    assert serve._build_unified_events is sessions.build_unified_events
    assert serve._reconstruct_sessions is sessions.reconstruct_sessions

    events = sessions.build_unified_events({
        "history": [{"url": "https://www.example.com/a", "last_visit": "2026-05-29T01:00:00+00:00"}],
        "cookies": [],
        "downloads": [],
    })

    assert events[0]["domain"] == "example.com"
    assert sessions.reconstruct_sessions(events)[0]["count"] == 1


def test_data_routes_history_filter_and_pagination():
    app = Flask(__name__)

    sample = {
        "history": [
            {
                "url": "https://safe.example/",
                "title": "Safe",
                "last_visit": "2026-05-29T10:00:00+00:00",
                "risk_score": 5,
                "visit_count": 2,
                "profile": "Default",
            },
            {
                "url": "http://185.220.101.47/payload",
                "title": "Payload",
                "last_visit": "2026-05-29T03:00:00+00:00",
                "risk_score": 75,
                "visit_count": 1,
                "profile": "Default",
            },
        ],
        "cookies": [],
        "bookmarks": [],
        "downloads": [],
    }

    helpers = {
        "domain_of": serve.domain_of,
        "_norm_dt": serve._norm_dt,
        "_build_unified_events": serve._build_unified_events,
        "_reconstruct_sessions": serve._reconstruct_sessions,
        "paginate": serve.paginate,
        "filter_risk": serve.filter_risk,
        "_safe_int": serve._safe_int,
        "_validate_domain_param": serve._validate_domain_param,
    }
    register_data_routes(app, lambda: sample, helpers)

    res = app.test_client().get("/api/history?risk=flagged&page=1")

    assert res.status_code == 200
    body = res.get_json()
    assert body["total"] == 1
    assert body["items"][0]["risk_score"] == 75


def test_api_diff_allows_only_regular_json_files_inside_data_dir(tmp_path, monkeypatch):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text('{"history": [], "cookies": [], "downloads": []}', encoding="utf-8")
    new.write_text(
        '{"history": [{"url": "https://new.example", "last_visit": "2026-05-29T00:00:00+00:00"}], "cookies": [], "downloads": []}',
        encoding="utf-8",
    )
    (tmp_path / "not_json.txt").write_text("{}", encoding="utf-8")

    monkeypatch.setattr(serve, "DATA_DIR", tmp_path)
    client = serve.app.test_client()

    ok = client.get("/api/diff?a=old.json&b=new.json")
    assert ok.status_code == 200
    assert ok.get_json()["new_history"][0]["url"] == "https://new.example"

    assert client.get("/api/diff?a=.&b=new.json").status_code == 404
    assert client.get("/api/diff?a=not_json.txt&b=new.json").status_code == 404
    assert client.get("/api/diff?a=..%2Frequirements.txt&b=new.json").status_code == 404
