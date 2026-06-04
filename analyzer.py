#!/usr/bin/env python3
"""
BrowserForensix — analyzer.py
Scores and annotates all browser artifacts, writes analysis.json.

FIX-10: analysis.json is now written atomically via a temp file + os.replace().
         Previously ANALYSIS_FILE.write_text() wrote directly, so a concurrent
         load_analysis() call could read a torn/partial JSON file and crash with
         JSONDecodeError. os.replace() is atomic on all POSIX systems and on
         Windows (same volume), so readers always see a complete file.
"""

import json
import os
import statistics
import tempfile
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from analysis.anomalies import (
    detect_burst_activity,
    detect_download_without_history,
    detect_history_gaps,
    detect_offhours_activity,
    detect_zombie_cookies,
    domain_matches as _domain_matches,
    extract_domain as _extract_domain,
)
from analysis.heatmap import compute_heatmap
from analysis.scoring import classify_cookie, score_cookie, score_download, score_url

BASE_DIR      = Path(__file__).parent
DATA_DIR      = BASE_DIR / "data"
EVIDENCE_FILE = DATA_DIR / "evidence.json"
ANALYSIS_FILE = DATA_DIR / "analysis.json"


# ── Datetime helpers ──────────────────────────────────────────────────────────

def _now_utc() -> datetime:
    return datetime.now(tz=timezone.utc)


# Domain helpers live in analysis/anomalies.py.

# Risk scoring lives in analysis/scoring.py.

# Anomaly detection lives in analysis/anomalies.py.

# ── Heatmap ───────────────────────────────────────────────────────────────────

# Heatmap generation lives in analysis/heatmap.py.

# ── Main pipeline ─────────────────────────────────────────────────────────────

def run() -> None:
    if not EVIDENCE_FILE.exists():
        print(f"[ERROR] {EVIDENCE_FILE} not found. Run extract.py first.")
        return

    # Load evidence.json with retry to handle concurrent writes
    for attempt in range(3):
        try:
            evidence = json.loads(EVIDENCE_FILE.read_text(encoding="utf-8"))
            break
        except json.JSONDecodeError as e:
            if attempt < 2:
                time.sleep(0.1 * (attempt + 1))  # Exponential backoff
            else:
                raise RuntimeError(f"Failed to load {EVIDENCE_FILE} after 3 attempts: {e}") from e
    history:   List[Dict] = evidence.get("history",   [])
    cookies:   List[Dict] = evidence.get("cookies",   [])
    bookmarks: List[Dict] = evidence.get("bookmarks", [])
    downloads: List[Dict] = evidence.get("downloads", [])

    domain_history_count: Dict[str, int] = defaultdict(int)
    for h in history:
        d = _extract_domain(h.get("url", ""))
        if d:
            domain_history_count[d] += 1

    domain_has_cookie: Dict[str, bool] = defaultdict(bool)
    for c in cookies:
        host = c.get("host", "").lstrip(".").removeprefix("www.")
        if host:
            domain_has_cookie[host] = True

    history_domains = {d for d in domain_history_count if d}

    scored_history = []
    for h in history:
        domain = _extract_domain(h.get("url", ""))
        score, reasons = score_url(
            h.get("url", ""), h.get("last_visit", ""),
            domain_has_cookie.get(domain, False), domain_history_count.get(domain, 0),
            h.get("transition", 0),
        )
        scored_history.append({**h, "risk_score": score, "risk_reasons": reasons})

    scored_cookies = []
    for c in cookies:
        raw_host     = c.get("host", "").lstrip(".")
        cookie_domain = raw_host.removeprefix("www.")
        hist_count   = domain_history_count.get(cookie_domain, 0)
        if hist_count == 0:
            for hd, cnt in domain_history_count.items():
                if hd == cookie_domain or hd.endswith("." + cookie_domain):
                    hist_count = max(hist_count, cnt)
        ctype        = classify_cookie(c)
        score, reasons = score_cookie(c, hist_count)
        scored_cookies.append({**c, "type": ctype, "risk_score": score, "risk_reasons": reasons})

    scored_downloads = []
    for dl in downloads:
        src_domain = _extract_domain(dl.get("source_url", ""))
        in_history = _domain_matches(src_domain, history_domains)
        score, reasons = score_download(dl, in_history)
        scored_downloads.append({**dl, "in_history": in_history, "risk_score": score, "risk_reasons": reasons})

    anomalies = []
    gap = detect_history_gaps(history, cookies)
    if gap:
        anomalies.append(gap)
    anomalies.extend(detect_burst_activity(history))
    offhours = detect_offhours_activity(history)
    if offhours:
        anomalies.append(offhours)
    anomalies.extend(detect_download_without_history(history, downloads))
    anomalies.extend(detect_zombie_cookies(cookies))

    all_scores = (
        [h["risk_score"] for h in scored_history]
        + [c["risk_score"] for c in scored_cookies]
        + [d["risk_score"] for d in scored_downloads]
    )
    flagged   = sum(1 for s in all_scores if s >= 61)
    moderate  = sum(1 for s in all_scores if 31 <= s <= 60)
    avg_score = round(statistics.mean(all_scores), 1) if all_scores else 0.0

    domain_visits:   Dict[str, int] = defaultdict(int)
    domain_max_risk: Dict[str, int] = defaultdict(int)
    for h in scored_history:
        d = _extract_domain(h.get("url", ""))
        if d:
            domain_visits[d]   += 1
            domain_max_risk[d]  = max(domain_max_risk[d], h["risk_score"])

    top_domains = sorted(domain_visits.items(), key=lambda x: x[1], reverse=True)[:20]
    heatmap     = compute_heatmap(scored_history)

    analysis = {
        "meta": {
            **evidence.get("meta", {}),
            "analysis_time":      _now_utc().isoformat(),
            "total_flagged":      flagged,
            "average_risk_score": avg_score,
            "anomaly_count":      len(anomalies),
        },
        "hashes":   evidence.get("hashes", {}),
        "summary": {
            "total_artifacts":    len(history) + len(cookies) + len(bookmarks) + len(downloads),
            "history_count":      len(scored_history),
            "cookie_count":       len(scored_cookies),
            "bookmark_count":     len(bookmarks),
            "download_count":     len(scored_downloads),
            "flagged_count":      flagged,
            "moderate_count":     moderate,
            "average_risk_score": avg_score,
            "anomaly_count":      len(anomalies),
        },
        "top_domains": [
            {"domain": d, "visits": v, "risk_score": domain_max_risk.get(d, 0)}
            for d, v in top_domains
        ],
        "heatmap":   heatmap,
        "anomalies": anomalies,
        "history":   scored_history,
        "cookies":   scored_cookies,
        "bookmarks": bookmarks,
        "downloads": scored_downloads,
        "local_storage": evidence.get("local_storage", []),
    }

    # FIX-10: Atomic write — write to a sibling temp file then os.replace() into place.
    # This guarantees load_analysis() always reads a complete, valid JSON file even
    # if a server request arrives mid-write. os.replace() is atomic on POSIX and on
    # Windows when src and dst are on the same volume (same DATA_DIR).
    ANALYSIS_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        dir=ANALYSIS_FILE.parent,
        prefix=".analysis_tmp_",
        suffix=".json",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(analysis, f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, ANALYSIS_FILE)
    except Exception:
        # Clean up temp file on failure; don't leave partial files around.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    try:
        ANALYSIS_FILE.chmod(0o600)
    except Exception:
        pass

    print(f"[OK] Analysis complete. {len(anomalies)} anomalies, {flagged} flagged items → {ANALYSIS_FILE}")


if __name__ == "__main__":
    run()
