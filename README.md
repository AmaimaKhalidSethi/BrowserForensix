# BrowserForensix

**A local forensic workstation for web browser artifact analysis.**

Extracts, scores, and surfaces browser history, cookies, bookmarks, downloads, and localStorage with real investigative logic — across multiple signed-in profiles simultaneously. All processing is local; no data ever leaves the machine.

> The Flask server binds exclusively to `127.0.0.1`. API endpoints reject cross-origin requests via a `before_request` origin guard.

---

## Quick Start

```bash
pip install flask

# Close your browser first — Chrome locks its SQLite files while running
python extract.py --browser chrome

python serve.py
# Opens http://localhost:5000 automatically
```

`serve.py` runs the analyser automatically on startup. Re-run `extract.py` when you want fresh artifacts — the server picks up changes without a restart.

---

## File Structure

```
browserforensix/
├── extract.py              ← extracts browser SQLite + LevelDB → data/evidence.json
├── analyzer.py             ← risk scoring, anomaly detection, heatmap
├── serve.py                ← Flask server + all /api/* routes
├── leveldb_reader.py       ← LevelDB parser for localStorage/sessionStorage
├── decryptor.py            ← Chrome cookie decryption module (see below)
├── ai_engine.py            ← OpenRouter AI integration (optional)
├── ai_routes.py            ← /api/ai/* Blueprint (optional)
├── ctf_routes.py           ← /ctf + /api/ctf/* Blueprint (optional)
├── make_ctf_challenge.py   ← generates a practice CTF challenge (optional)
├── test_browserforensix.py
├── requirements.txt
├── .env                    ← OPENROUTER_API_KEY (create manually)
│
├── data/
│   ├── evidence.json       ← raw artifacts (chmod 600)
│   └── analysis.json       ← scored + anomaly output (chmod 600)
│
├── static/
│   ├── style.css
│   ├── app.js
│   └── ctf.js              ← CTF tools frontend
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
    ├── ai.html
    └── ctf.html            ← CTF tools page
```

---

## Supported Browsers

| Browser | Windows | macOS | Linux |
|---|:---:|:---:|:---:|
| Chrome | ✓ | ✓ | ✓ |
| Edge | ✓ | ✓ | — |
| Firefox | ✓ | ✓ | ✓ |
| Safari | — | ✓ (stub) | — |

---

## Extraction

```bash
# All profiles, auto-detected
python extract.py --browser chrome
python extract.py --browser firefox
python extract.py --browser edge

# Specific profile directory
python extract.py --browser chrome --profile "/path/to/User Data/Default"
```

Chrome extraction discovers every profile directory (`Default`, `Profile 1`, `Profile 2`, …) in a single pass. When Chrome is running, the extractor copies both `History` and `History-wal` into a temp location and merges the WAL in-process — capturing visits from the last few minutes without requiring Chrome to be closed.

**Permission errors on Cookies** are expected when Chrome is running. Close Chrome completely, or run as administrator, to resolve.

---

## Pages

| Page | What it shows |
|---|---|
| **Overview** | Stat cards, per-profile breakdown, anomaly accordion, top domains, activity heatmap, evidence integrity SHA-256 hashes |
| **History** | Paginated history with risk scores; protocol, date range, risk, and search filters; per-row AI explanation for moderate+ items; CSV export |
| **Cookies** | Cookie classification (Auth Token / Tracking / Session / Zombie / Analytics / Unknown); host, type, expiry, and secure/insecure filters |
| **Bookmarks** | Folder tree view; sort by date or title; deleted-entry and blank-target trace detection |
| **Downloads** | Files saved to disk — source URL, history presence, on-disk presence, risk score; per-row AI threat assessment for flagged items |
| **Timeline** | All artifacts unified on one timeline, grouped into 30-minute sessions; off-hours session badges; type and date-range toggles |
| **Investigate** | Domain Inspector, Session Viewer (streaming AI narrative), Cleared History Detector, Artifact Cross-Reference |
| **Report** | Structured `.txt` forensic report + streaming AI narrative report with case metadata fields |
| **AI Analyst** | Freeform Q&A chat, quick-action buttons (executive summary, gap analysis, top risks, download threats, session patterns) |
| **CTF Tools** | Flag Scanner, Encoding Detector, URL Parameter Decomposer, Cookie Inspector |

---

## Pipeline

```
extract.py → data/evidence.json → analyzer.py → data/analysis.json → serve.py → browser
```

`serve.py` runs `analyzer.py` automatically at startup. `analysis.json` is re-read from disk whenever its `mtime` changes, so you can re-run `extract.py` without restarting the server.

---

## Risk Scoring

Every artifact is scored 0–100. Score and reasons are stored in `analysis.json` and surfaced in the UI.

### History

| Factor | Points |
|---|---:|
| HTTP on a non-local domain | +20 |
| IP address instead of domain name | +25 |
| Known paste site (pastebin.com, hastebin.com, rentry.co, …) | +30 |
| Known file-share site (filebin.net, file.io, gofile.io, …) | +30 |
| Visited between 23:00–05:00 UTC | +15 |
| Cookie exists for this domain but history is absent | +25 |
| Typed URL (Chrome transition = 1), only when score ≥ 31 | +10 |

### Cookies

| Factor | Points |
|---|---:|
| Cookie past its expiry date | +10 |
| Lifetime greater than 365 days | +15 |
| Missing Secure flag | +10 |
| Set by an IP-address host | +25 |
| No history entries for this domain | +20 |

### Downloads

| Factor | Points |
|---|---:|
| Source domain absent from history | +30 |
| Executable file type (.exe .msi .ps1 .sh .dmg …) | +20 |
| File no longer present at recorded path | +20 |
| Chrome flagged the download (`danger_type > 0`) | +20 |
| Archive file type (.zip .tar .7z .rar) | +10 |

**Score bands:** 0–30 low · 31–60 moderate · 61–100 flagged

---

## Anomaly Detection

| Anomaly | Severity | Logic |
|---|---|---|
| **History Cleared — Cookies Survive** | Critical | Domains with cookies but zero history entries |
| **Burst Activity** | Moderate | ≥ 8 visits to one domain within any 5-minute window; detected with an O(n log n) sliding window |
| **Off-Hours Activity** | Moderate | Visits outside the user's statistically derived normal window (mean ± 2σ of their own timestamps — not a hardcoded time rule). Requires ≥ 50 history entries. |
| **Download Without History** | Moderate | Download source domain absent from history |
| **Zombie Cookies** | Low | Expired cookies still in the database, one anomaly per affected domain |

---

## Cookie Classification

| Type | Detection |
|---|---|
| **Auth Token** | Name contains: `token`, `auth`, `sid`, `jwt`, `access_token`, `id_token`, `csrf`, `login` |
| **Analytics** | Name contains: `analytics`, `_hj`, `hotjar`, `mixpanel`, `amplitude`, `segment` |
| **Tracking** | Name contains: `_ga`, `_gid`, `_fbp`, `_fbc`, `track`, `_uid`, `user_id`, `visitor`, `__utma` |
| **Session** | Name contains `session`, or cookie has no expiry |
| **Zombie** | Expiry date is in the past |
| **Unknown** | None of the above |

Auth Token is checked before Tracking, so names like `_ga_token` are classified at the higher forensic value.

---

## localStorage / LevelDB Extraction

`leveldb_reader.py` extracts key-value pairs from Chrome's LevelDB storage directories — not SQLite, not covered by any other open-source browser forensics tool without heavy dependencies.

**Zero external dependencies** — pure Python stdlib. Works immediately with no additional installs.

Extracted sources per profile:

| Directory | Contents |
|---|---|
| `Local Storage/leveldb/` | localStorage — persists across sessions, keyed by origin |
| `Session Storage/` | sessionStorage — ephemeral but present in profile until overwritten |
| `Extension State/` | Extension localStorage — can contain auth tokens, cached API responses |

**Implementation detail:** parses both `.log` files (recent unflushed writes) and `.ldb` SST files (compacted data). Handles Chrome's UTF-16LE value encoding and both old/new localStorage key format variants. If `python-snappy` is installed, Snappy-compressed `.ldb` blocks are also read; otherwise they are skipped gracefully and `.log` files (which contain the most recent data) are always parsed.

Results appear in `evidence.json` under `local_storage` and are automatically scanned by all CTF Tools.

Optional Snappy support:
```bash
pip install python-snappy
```

---

## Cookie Decryption

`decryptor.py` provides AES-256-GCM cookie decryption for Chrome 80+ profiles. Chrome encrypts cookie values using an AES key stored in `Local State`, itself wrapped by the OS credential store.

**This module is provided as a library and is not wired into the extraction pipeline by default.** Integrate it in environments where you have explicit authority over the target profile — acquired evidence, CTF challenges, or your own machine.

```python
from decryptor import CookieDecryptor
from pathlib import Path

# Live system — resolves key from OS credential store automatically
d = CookieDecryptor(user_data_path=Path("/path/to/User Data"))

# Offline / CTF — supply the raw AES key as hex (bypasses all OS calls)
d = CookieDecryptor(cookie_key_hex="aabbccdd...")

plaintext = d.decrypt_to_display(encrypted_value_bytes)
# Returns decrypted string, "[ENCRYPTED]" if key unavailable,
# or "[DECRYPT_FAILED]" if key exists but decryption errored.
```

Platform support:

| Platform | Method |
|---|---|
| Windows | `CryptUnprotectData` via `ctypes` — works as the profile-owning user |
| macOS | Keychain lookup via `security` CLI |
| Linux | Fixed passphrase (`peanuts`) for default Chrome; `secretstorage` for Gnome keyring |
| Any (CTF/offline) | `cookie_key_hex` — bypasses all OS calls entirely |

Requires `cryptography` or `pycryptodome` for AES-GCM:
```bash
pip install cryptography
# or
pip install pycryptodome
```

---

## CTF Tools

Drop-in optional module. Place files as shown in the File Structure section above. `serve.py` and `base.html` are already patched to load them automatically if present.

### Tools

**⚑ Flag Scanner** — scans every string field across all artifacts (URLs, titles, URL query params, cookie values, download filenames, bookmark titles, localStorage keys and values) for known flag formats. Built-in patterns: `FLAG{}`, `CTF{}`, `picoCTF{}`, `HTB{}`, `THM{}`, `DUCTF{}`, `ACSC{}`, `flag{}`, plus 32–64 char hex strings. Accepts a custom regex for challenge-specific formats.

**⇌ Encoding Detector** — attempts base64 decode, hex→UTF-8, URL-decode, and ROT13 on every artifact string field ≥ 8 characters. Only surfaces entries where the decoding produces a meaningfully different result.

**⊞ URL Parameter Decomposer** — breaks every history URL's query string into individual `key=value` pairs, scans each for flag patterns, and attempts all four decodings. URLs with flag hits sort to the top.

**◻ Cookie Inspector** — shows all non-encrypted cookie values with a hex dump of the first 64 bytes, all decoded forms, and flag pattern matches inline.

### CTF API Endpoints

| Endpoint | Params | Description |
|---|---|---|
| `GET /api/ctf/summary` | — | Fast stat counts for dashboard cards |
| `GET /api/ctf/scan/flags` | `artifact_type`, `custom` | Flag pattern scan across all fields |
| `GET /api/ctf/decode` | `artifact_type`, `min_length` | Encoding detection across all fields |
| `GET /api/ctf/url/params` | `q` | URL query string decomposer |
| `GET /api/ctf/cookie/inspect` | `host`, `name` | Cookie value inspector with hex dump |

### Practice Challenge

```bash
python make_ctf_challenge.py   # writes data/evidence.json + data/analysis.json
python serve.py
# → http://localhost:5000/ctf
```

Generates a realistic fake Chrome profile with a flag (`BFX{...}`) split across four artifact types using four different encodings. Full solver walkthrough in `CHALLENGE_WRITEUP.md`.

### Recommended CTF Workflow

```
1. Overview       → check anomalies first; History Gap = something deleted
2. CTF → Flags    → scan immediately, all types, no filter
3. CTF → Params   → decompose all URLs, look for base64/hex params
4. CTF → Cookies  → check raw values and decoded forms
5. History        → filter risk=Flagged; look for paste/file-share/IP domains
6. Downloads      → anything missing from disk + source not in history
7. Investigate    → Domain Inspector on every suspicious domain
```

---

## AI Features (Optional)

```bash
# 1. Get a key: https://openrouter.ai/keys
# 2. Create .env in the project root:
OPENROUTER_API_KEY=sk-or-your-key-here

# 3. Place ai_engine.py and ai_routes.py in the project root
python serve.py   # → [AI] Routes registered — /api/ai/*
```

AI is silently disabled if `ai_engine.py` is absent. Override the default model:

```bash
OPENROUTER_MODEL=anthropic/claude-3-haiku
```

| Model | Characteristics |
|---|---|
| `meta-llama/llama-3.3-70b-instruct` | Default — fast, capable, cheap |
| `anthropic/claude-3-haiku` | Highest reasoning quality |
| `mistralai/mistral-7b-instruct` | Fastest, lowest cost |
| `google/gemma-3-27b-it` | Strong open-weight alternative |

| AI Feature | Where it appears |
|---|---|
| Executive Summary | AI Analyst — Quick Analysis panel |
| History Item Explainer | History — expand any row with risk ≥ 31 |
| Domain Profile | Investigate — Domain Inspector |
| Session Narrative (streaming) | Investigate — Session Viewer |
| Download Threat Assessment | Downloads — click any row with risk ≥ 31 |
| Cleared History Analysis | Investigate — Cleared History Detector |
| Anomaly Deep Dive | Overview — per-anomaly AI Deep Dive button |
| Narrative Report (streaming) | Report page |
| Freeform Q&A Chat (streaming) | AI Analyst — chat panel |

---

## Full API Reference

| Endpoint | Description |
|---|---|
| `GET /api/status` | Ready state, metadata, artifact counts, file hashes |
| `GET /api/overview` | Summary stats, anomalies, top domains, heatmap |
| `GET /api/profiles` | Per-profile artifact counts |
| `GET /api/history` | Paginated — params: `q`, `protocol`, `risk`, `from`, `to`, `profile`, `page` |
| `GET /api/cookies` | Paginated — params: `type`, `host`, `expired`, `secure`, `profile`, `page` |
| `GET /api/bookmarks` | Folder tree or search — param: `q` |
| `GET /api/downloads` | Paginated — params: `q`, `risk`, `profile`, `page` |
| `GET /api/localstorage` | localStorage entries — params: `q`, `origin`, `source`, `page` |
| `GET /api/timeline` | Unified events and sessions — params: `from`, `types` |
| `GET /api/sessions` | Reconstructed browsing sessions |
| `GET /api/domain/<domain>` | All artifacts for a domain |
| `GET /api/search` | Cross-artifact search — param: `q` (min 2 chars) |
| `GET /api/report` | Flagged items and anomalies for report generation |
| `GET /api/ai/status` | AI connection and model info |
| `GET /api/ai/summary` | Executive summary |
| `GET /api/ai/explain/history?url=` | Per-URL risk explanation |
| `GET /api/ai/explain/download?filename=` | Per-file threat assessment |
| `GET /api/ai/domain/<domain>` | AI domain profile |
| `GET /api/ai/gap-analysis` | Cleared history analysis |
| `GET /api/ai/anomaly?type=` | Anomaly deep dive |
| `GET /api/ai/stream/session?index=` | Session narrative (SSE) |
| `GET /api/ai/stream/report` | Narrative forensic report (SSE) |
| `POST /api/ai/stream/chat` | Freeform chat (SSE) — body: `{message, history}` |
| `GET /api/ctf/summary` | CTF stat counts |
| `GET /api/ctf/scan/flags` | Flag pattern scan |
| `GET /api/ctf/decode` | Encoding detection |
| `GET /api/ctf/url/params` | URL parameter decomposer |
| `GET /api/ctf/cookie/inspect` | Cookie value inspector |

---

## Multi-Profile Support

All Chrome profiles are extracted in one pass. The Overview page shows a per-profile breakdown with sparkbars. History, Cookies, and Downloads pages expose a Profile filter dropdown when more than one profile exists.

If profile directories are non-contiguous (e.g. `Default`, `Profile 1`, `Profile 3` with `Profile 2` missing), the Overview page displays a forensic alert — Chrome never reuses profile numbers, so a gap means a profile was deliberately deleted.

---

## Running Tests

```bash
python test_browserforensix.py
```

52 tests covering risk scoring, anomaly detection, API filters, domain validation, timestamp parsing, and cookie classification. No live server or `evidence.json` required — all tests use an in-memory fixture and the Flask test client.

---

## Security Notes

- Server binds to `127.0.0.1` only.
- All `/api/*` endpoints reject requests whose `Origin` or `Referer` is not localhost (HTTP 403).
- `evidence.json` and `analysis.json` are written with `chmod 600` on macOS and Linux.
- Browser databases are opened read-only — the tool cannot modify browser data.
- Cookie values remain `[ENCRYPTED]` unless explicitly decrypted via `decryptor.py`.

---

## Known Limitations

- `decryptor.py` is not wired into the extraction pipeline by default — requires manual integration.
- Safari support is a stub — binary plist and binary cookie parsing not implemented.
- LevelDB Snappy-compressed `.ldb` blocks require `pip install python-snappy`; `.log` files (most recent data) are always parsed without it.
- Network traffic not analysed — requires packet capture.
- Mobile browsers not supported — requires device extraction tools.
- One browser type per extraction run — Chrome and Firefox cannot be mixed in a single `evidence.json`.