# BrowserForensix

**Professional Web Browser Forensic Analysis Platform**

A local forensic workstation that extracts, scores, and surfaces browser artifacts with real investigative logic — across multiple profiles simultaneously. Tells you what matters and why.

> All processing is local. No data leaves your machine. The Flask server binds to `127.0.0.1` only.

---

## Quick Start

```bash
pip install flask
# Close your browser first — Chrome locks SQLite files while running
python extract.py --browser chrome
python serve.py
# Opens http://localhost:5000 automatically
```

---

## AI Features (Optional)

```bash
# 1. Get a key at https://openrouter.ai/keys
# 2. Create .env in the project root:
OPENROUTER_API_KEY=sk-or-your-key-here
# 3. Place ai_engine.py and ai_routes.py in the project root
# 4. Start normally — AI registers automatically
python serve.py   # [AI] Routes registered — /api/ai/*
```

AI is silently disabled if `ai_engine.py` is missing. No errors.

---

## Supported Browsers

| Browser | Windows | macOS | Linux |
|---------|:-------:|:-----:|:-----:|
| Chrome  | ✓       | ✓     | ✓     |
| Edge    | ✓       | ✓     | —     |
| Firefox | ✓       | ✓     | ✓     |
| Safari  | —       | ✓     | —     |

---

## Extraction Options

```bash
python extract.py --browser chrome          # all profiles, auto-detected
python extract.py --browser firefox
python extract.py --browser edge
python extract.py --browser chrome --profile "C:\...\Profile 2"  # specific profile
```

**Permission errors on Cookies** are normal when Chrome is running. Close Chrome completely or run as administrator to resolve.

---

## File Structure

```
browserforensix/
├── extract.py          ← extracts browser SQLite data → evidence.json
├── analyzer.py         ← risk scoring, anomaly detection, heatmap
├── serve.py            ← Flask server + all API routes
├── ai_engine.py        ← OpenRouter AI integration (optional)
├── ai_routes.py        ← /api/ai/* Blueprint (optional)
├── requirements.txt
├── .env                ← OPENROUTER_API_KEY (create manually)
│
├── data/
│   ├── evidence.json   ← raw artifacts (chmod 600)
│   └── analysis.json   ← scored + anomaly output (chmod 600)
│
├── static/
│   ├── style.css
│   └── app.js
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
    ├── report.html
    └── ai.html
```

---

## Pages

| Page | What it does |
|------|-------------|
| **Overview** | Stat cards, per-profile breakdown, anomaly list, top domains, activity heatmap, evidence integrity hashes |
| **History** | Paginated history with risk scores, protocol/date/profile filters, per-row AI explanation |
| **Cookies** | Cookie classification (Auth/Tracking/Session/Zombie/Analytics), host/secure/profile filters |
| **Bookmarks** | Folder tree, sort by date or title, deleted/blank-target trace detection |
| **Downloads** | Files saved to disk — source URL, history presence, disk presence, risk score, per-row AI threat assessment |
| **Timeline** | All artifacts on one timeline in 30-minute sessions, off-hours badges |
| **Investigate** | Domain Inspector, Session Viewer, Cleared History Detector, Artifact Cross-Reference |
| **Report** | Structured `.txt` forensic report + AI narrative report (streaming) |
| **AI Analyst** | Freeform chat, quick analysis buttons, executive summary, narrative report |

---

## Risk Scoring

Every artifact is scored 0–100 with written reasons stored in `analysis.json`.

| Factor | Score |
|--------|------:|
| HTTP on non-local domain | +20 |
| IP address instead of domain | +25 |
| Known paste site (pastebin, hastebin, etc.) | +30 |
| Known file-share site (filebin, file.io, etc.) | +30 |
| Visited 11pm–5am UTC | +15 |
| Typed URL — moderate+ risk only | +10 |
| Cookie exists but history cleared | +25 |
| Executable download (.exe, .msi, .ps1, .sh…) | +20 |
| Download source absent from history | +30 |
| Download file missing from disk | +20 |
| Chrome flagged the download | +20 |
| Archive download (.zip, .tar, .7z, .rar) | +10 |
| Cookie missing Secure flag | +10 |
| Expired cookie still in database | +10 |
| Cookie lifetime > 1 year | +15 |

**Score bands:** 0–30 low · 31–60 moderate · 61–100 flagged

---

## Anomaly Detection

| Anomaly | Severity | Description |
|---------|----------|-------------|
| **History Gap** | Critical | Domains with cookies but zero history — history was cleared |
| **Burst Activity** | Moderate | 8+ visits to one domain within 5 minutes |
| **Off-Hours Activity** | Moderate | Derived statistically from the user's own timestamps |
| **Download Without History** | Moderate | Source domain absent from history |
| **Zombie Cookies** | Low | Expired cookies aggregated by domain |

Off-hours detection is data-driven — the threshold is derived from the user's own visit distribution, not a hardcoded time rule.

---

## AI Features

| Feature | Where it appears |
|---------|-----------------|
| Executive Summary | AI Analyst — quick action |
| History Item Explainer | History — expand row, risk ≥ 31 |
| Domain Profile | Investigate — Domain Inspector |
| Session Narrative | Investigate — Session Viewer (streaming) |
| Download Threat Assessment | Downloads — click row, risk ≥ 31 |
| Cleared History Analysis | Investigate — Gap Detector |
| Anomaly Deep Dive | Overview — per-anomaly button |
| Narrative Report | Report page (streaming) |
| Freeform Q&A | AI Analyst — full chat |

**Default model:** `meta-llama/llama-3.3-70b-instruct`
Override: set `OPENROUTER_MODEL=<model-id>` in `.env`

| Model | Best for |
|-------|---------|
| `meta-llama/llama-3.3-70b-instruct` | Default — fast, capable, cheap |
| `anthropic/claude-3-haiku` | Best reasoning quality |
| `mistralai/mistral-7b-instruct` | Fastest, lowest cost |
| `google/gemma-3-27b-it` | Strong open-weight alternative |

---

## Multi-Profile Support

All Chrome profiles are extracted in one pass. The Overview page shows a per-profile breakdown. History, Cookies, and Downloads pages include a Profile filter dropdown when multiple profiles exist.

---

## Running Tests

```bash
python test_browserforensix.py
# 52 tests, 0 failures — no live server or evidence.json needed
```

---

## Security Notes

- Server binds to `127.0.0.1` — not accessible from the network.
- All `/api/*` endpoints reject requests from non-localhost origins (HTTP 403).
- `evidence.json` and `analysis.json` written with `chmod 600` on macOS/Linux.
- Browser databases opened read-only (`?mode=ro`) — tool cannot modify browser data.
- Cookie values are never decrypted. Encrypted values shown as `[ENCRYPTED]`.

---

## Known Limitations

- Cookie decryption not supported (DPAPI / Keychain — OS-level, out of scope).
- Network traffic not analysed (requires packet capture).
- Mobile browsers not supported (requires device extraction tools).
- Single browser type per extraction run (Chrome and Firefox cannot be mixed).