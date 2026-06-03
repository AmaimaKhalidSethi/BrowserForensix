# BrowserForensix Hygiene And Truth Audit

## Current Status

BrowserForensix has enough forensic depth to keep and mature: Chromium/Firefox artifact extraction, WAL-aware SQLite copying, cookie decryption support, LevelDB/localStorage parsing, anomaly scoring, timelines, reports, CTF tooling, and optional AI workflows.

It is not ready to present as a polished public achievement until the repository hygiene, tests, and module boundaries are cleaned up.

## Truth Fixes Applied

- Replaced the stale `test_browserforensix.py` claim with the real `tests/` suite.
- Removed the unsupported "52 tests" claim from the README.
- Updated the cookie decryption limitation to match the current extraction pipeline.
- Removed generated cache artifacts and the stray empty `{data,static,templates}` directory.
- Hardened `/api/diff` so it only reads regular `.json` files inside `data/`.
- Escaped single quotes in the frontend `esc()` helper to reduce inline-handler injection risk.
- Moved scoring, anomaly detection, heatmap generation, and session reconstruction into `analysis/`.

## Immediate Audit Targets

- Security: XSS exposure from `innerHTML`, path handling, CSP, localhost origin checks, sensitive artifact display, and AI data egress.
- Forensic correctness: timestamp conversion, domain matching, risk scoring, cookie expiry handling, LevelDB parsing, WAL behavior, and evidence hashing.
- Reliability: locked databases, corrupt files, large histories, malformed LevelDB entries, missing optional dependencies, and concurrent analyzer/server reads.
- Maintainability: large route/frontend files, patch-history comments, duplicated helpers, and unclear route ownership.

## Modularization Direction

Do not perform a broad file reshuffle until the tests cover the behavior being moved. The first safe boundaries are now in place:

- `analysis/scoring.py`
- `analysis/anomalies.py`
- `analysis/heatmap.py`
- `analysis/sessions.py`

The next pass should target route modularity and frontend event-handler cleanup.
