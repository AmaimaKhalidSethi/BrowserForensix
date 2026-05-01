# BrowserForensix

**Professional Web Browser Forensic Analysis Platform**

A local forensic workstation that extracts, scores, and surfaces browser artifacts
with real investigative logic. Tells you what matters and why — not just what exists.

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. CLOSE YOUR BROWSER (SQLite locks files while the browser is open)

# 3. Extract artifacts
python extract.py --browser chrome

# 4. Serve + analyse
python serve.py
# Opens http://localhost:5000 automatically
```

---

## Supported Browsers

| Browser | Windows | macOS | Linux |
|---------|---------|-------|-------|
| Chrome  | ✓       | ✓     | ✓     |
| Edge    | ✓       | ✓     | —     |
| Firefox | ✓       | ✓     | ✓     |
| Safari  | —       | ✓     | —     |

---

## Extraction Options

```bash
# Default (Chrome, auto-detected profile)
python extract.py --browser chrome

# Firefox
python extract.py --browser firefox

# Custom profile path
python extract.py --browser chrome --profile "/path/to/Chrome/Profile 2"

# Edge
python extract.py --browser edge
```

---

## File Structure

```
browserforensix/
│
├── extract.py          ← extracts real browser SQLite data
├── analyzer.py         ← scoring and anomaly detection logic
├── serve.py            ← Flask server, opens browser on launch
├── requirements.txt
│
├── data/
│   ├── evidence.json   ← full extracted artifact data (written by extract.py)
│   └── analysis.json   ← scored + anomaly output (written by serve.py)
│
├── static/
│   ├── style.css       ← all styles, CSS variables
│   └── app.js          ← all frontend logic
│
└── templates/
    ├── base.html
    ├── overview.html
    ├── history.html
    ├── cookies.html
    ├── bookmarks.html
    ├── downloads.html
    ├── timeline.html
    ├── investigate.html
    └── report.html
```

---

## Pages

| Page        | What it does |
|-------------|--------------|
| Overview    | Stat cards, anomaly summary, domain heatmap, activity grid |
| History     | Paginated + filterable browsing history with risk scores |
| Cookies     | Classified cookies (Auth/Tracking/Session/Zombie/Analytics) |
| Bookmarks   | Folder tree with deleted/blank-target traces surfaced |
| Downloads   | Files saved to disk — source URL, history presence, disk check |
| Timeline    | All artifacts on one timeline, grouped into 30-min sessions |
| Investigate | Domain Inspector, Session Viewer, Gap Detector, Cross-Reference |
| Report      | Generates a structured forensic .txt report |

---

## Risk Scoring

Every artifact is scored 0–100 with written reasons:

| Factor | Score |
|--------|-------|
| HTTP protocol on non-local domain | +20 |
| IP address instead of domain | +25 |
| Known paste / file-share site | +30 |
| Visited 11pm–5am (off-hours) | +15 |
| Visit burst (10+ in 5 min) | +20 |
| Cookie exists, zero history visits | +25 |
| Bookmark to about:blank / removed | +35 |
| Expired cookie still in database | +10 |
| Long-lived session cookie (>1 year) | +15 |

Score 0–30: low · 31–60: moderate · 61–100: flagged

---

## Anomaly Detection

- **History gap** — cookies from domains with no history entries (history cleared)
- **Burst activity** — 8+ visits to one domain in a 5-minute window
- **Off-hours activity** — statistically derived from the user's own data, not a hardcoded rule
- **Download without history** — file in downloads DB but source URL absent from history
- **Zombie cookies** — expired cookies still present in the database

---

## Known Limitations

- Cookie decryption not supported (requires DPAPI on Windows, Keychain on macOS — OS-level, out of scope)
- Network traffic not analysed (requires packet capture)
- Single profile per session
- Mobile browser support requires device extraction tools

---

## Privacy Note

All processing is local. No data leaves your machine. The Flask server binds to
`127.0.0.1` only and is not accessible from the network.
