#!/usr/bin/env python3
"""
BrowserForensix CTF Challenge Generator
========================================
Creates a fake but realistic evidence.json + analysis.json directly in data/
so you can run serve.py immediately and practice with BrowserForensix.

Flag: BFX{br0wser_4rt1f4cts_t3ll_4ll}  — split across 4 artifact types.

Run:
    python make_ctf_challenge.py
    python serve.py
    # Then go to http://localhost:5000
"""

import base64
import hashlib
import json
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path

OUT_DIR = Path(__file__).parent / "data"
OUT_DIR.mkdir(exist_ok=True)

EVIDENCE_FILE = OUT_DIR / "evidence.json"
ANALYSIS_FILE = OUT_DIR / "analysis.json"

# ── The flag, split into 4 parts ──────────────────────────────────────────────
#
#  Full flag:  BFX{br0wser_4rt1f4cts_t3ll_4ll}
#
#  Part 1 — plain text in a bookmark title (easy warm-up)
#            Title: "part1=BFX{br0wser_"
#
#  Part 2 — base64-encoded in a cookie value (medium)
#            Cookie "session_data" on secret-drop.io
#            value = base64("4rt1f4cts_")  →  "NHJ0MWY0Y3RzXw=="
#
#  Part 3 — hex-encoded in a URL query param (medium)
#            https://paste.internal.corp/view?data=743365
#            hex("t3ll") = "7433 6c6c"  →  "7433 6c6c" wait let me compute
#            "t3ll_" = 74 33 6c 6c 5f  → "7433 6c6c5f"
#
#  Part 4 — ROT13 in a download filename (harder)
#            ROT13("4ll}") = "4yy}"  → filename: flag_part4_4yy}.txt
#
# ─────────────────────────────────────────────────────────────────────────────

def ts(days_ago=0, hour=10, minute=0):
    """Return ISO timestamp string."""
    dt = datetime(2024, 11, 15, hour, minute, 0, tzinfo=timezone.utc) - timedelta(days=days_ago)
    return dt.isoformat()

def b64(s): return base64.b64encode(s.encode()).decode()
def to_hex(s): return s.encode().hex()

# Verify our encodings
assert b64("4rt1f4cts_") == "NHJ0MWY0Y3RzXw=="
assert to_hex("t3ll_") == "7433 6c6c5f".replace(" ", "")

# ── History ───────────────────────────────────────────────────────────────────
history = [
    # Normal browsing — noise
    {"url": "https://www.google.com/search?q=how+to+delete+browser+history", "title": "how to delete browser history - Google Search", "visit_count": 3, "last_visit": ts(7, 9, 12), "profile": "Default", "transition": 1},
    {"url": "https://www.google.com/search?q=secure+file+transfer+free", "title": "secure file transfer - Google Search", "visit_count": 2, "last_visit": ts(6, 14, 5), "profile": "Default", "transition": 1},
    {"url": "https://stackoverflow.com/questions/1234/python-read-file", "title": "Python read file - Stack Overflow", "visit_count": 1, "last_visit": ts(5, 11, 30), "profile": "Default", "transition": 0},
    {"url": "https://github.com/torvalds/linux", "title": "torvalds/linux - GitHub", "visit_count": 4, "last_visit": ts(4, 16, 0), "profile": "Default", "transition": 0},
    {"url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ", "title": "YouTube", "visit_count": 1, "last_visit": ts(3, 20, 0), "profile": "Default", "transition": 0},
    {"url": "https://reddit.com/r/netsec", "title": "r/netsec - Reddit", "visit_count": 6, "last_visit": ts(2, 18, 0), "profile": "Default", "transition": 0},
    {"url": "https://mail.google.com/mail/u/0/", "title": "Gmail", "visit_count": 12, "last_visit": ts(1, 9, 0), "profile": "Default", "transition": 0},
    {"url": "https://drive.google.com/", "title": "Google Drive", "visit_count": 5, "last_visit": ts(1, 9, 5), "profile": "Default", "transition": 0},

    # Suspicious — off-hours activity cluster (2–4am)
    {"url": "https://pastebin.com/xK9mR2Lw", "title": "Pastebin - Untitled", "visit_count": 1, "last_visit": ts(3, 2, 14), "profile": "Default", "transition": 1},
    {"url": "https://pastebin.com/xK9mR2Lw", "title": "Pastebin - Untitled", "visit_count": 1, "last_visit": ts(3, 2, 16), "profile": "Default", "transition": 0},
    {"url": "https://filebin.net/upload", "title": "Filebin — Upload", "visit_count": 1, "last_visit": ts(3, 2, 31), "profile": "Default", "transition": 1},
    {"url": "https://filebin.net/a7x9pqr3mnvb", "title": "Filebin — a7x9pqr3mnvb", "visit_count": 2, "last_visit": ts(3, 2, 44), "profile": "Default", "transition": 0},

    # The URL with hex-encoded flag part 3 in query param
    {"url": "https://paste.internal.corp/view?data=7433 6c6c5f&user=jdoe&ref=email".replace(" ", ""), "title": "Internal Paste - View", "visit_count": 1, "last_visit": ts(3, 3, 5), "profile": "Default", "transition": 1},

    # IP address access (suspicious)
    {"url": "http://185.220.101.47/upload.php", "title": "", "visit_count": 1, "last_visit": ts(3, 3, 22), "profile": "Default", "transition": 1},

    # More noise — daytime
    {"url": "https://news.ycombinator.com/", "title": "Hacker News", "visit_count": 8, "last_visit": ts(0, 10, 0), "profile": "Default", "transition": 0},
    {"url": "https://twitter.com/home", "title": "Twitter", "visit_count": 3, "last_visit": ts(0, 11, 0), "profile": "Default", "transition": 0},
    {"url": "https://docs.python.org/3/", "title": "Python 3 Documentation", "visit_count": 2, "last_visit": ts(0, 14, 0), "profile": "Default", "transition": 0},
]

# ── Cookies ───────────────────────────────────────────────────────────────────
cookies = [
    # Normal cookies — noise
    {"host": ".google.com",    "name": "_ga",          "value": "GA1.2.1234567890.1699900000", "encrypted": False, "path": "/", "expires": ts(-365), "created": ts(30),  "secure": True,  "http_only": False, "samesite": "Lax",    "profile": "Default"},
    {"host": ".google.com",    "name": "_gid",         "value": "GA1.2.9876543210.1700000000", "encrypted": False, "path": "/", "expires": ts(-1),   "created": ts(1),   "secure": True,  "http_only": False, "samesite": "Lax",    "profile": "Default"},
    {"host": ".reddit.com",    "name": "session",      "value": "eyJhbGciOiJIUzI1NiJ9.user123", "encrypted": False, "path": "/", "expires": ts(-30), "created": ts(60),  "secure": True,  "http_only": True,  "samesite": "Strict", "profile": "Default"},
    {"host": ".github.com",    "name": "user_session", "value": "abc123xyz789sessiontoken",      "encrypted": False, "path": "/", "expires": ts(-14), "created": ts(14),  "secure": True,  "http_only": True,  "samesite": "Lax",    "profile": "Default"},

    # Cookie for a domain with NO history (cleared) — ghost domain 1
    {"host": ".dropbox.com",   "name": "gvc",          "value": "8f3kq92mxz",                   "encrypted": False, "path": "/", "expires": ts(-90), "created": ts(20),  "secure": True,  "http_only": False, "samesite": "None",   "profile": "Default"},
    {"host": ".dropbox.com",   "name": "t",            "value": "Kx9mQzVbRt3nWs",               "encrypted": False, "path": "/", "expires": ts(-60), "created": ts(20),  "secure": True,  "http_only": True,  "samesite": "None",   "profile": "Default"},

    # Cookie for ghost domain 2 — exfil site
    {"host": "secret-drop.io", "name": "session_data", "value": b64("4rt1f4cts_"),               "encrypted": False, "path": "/", "expires": ts(-7),  "created": ts(3),   "secure": False, "http_only": False, "samesite": "",       "profile": "Default"},
    {"host": "secret-drop.io", "name": "uid",          "value": "usr_0x4f2a",                    "encrypted": False, "path": "/", "expires": ts(-7),  "created": ts(3),   "secure": False, "http_only": False, "samesite": "",       "profile": "Default"},

    # Cookie for ghost domain 3
    {"host": ".onionshare.org","name": "auth_token",   "value": "tok_9xKmP3rQzW8",               "encrypted": False, "path": "/", "expires": ts(-30), "created": ts(10),  "secure": True,  "http_only": True,  "samesite": "Strict", "profile": "Default"},

    # Filebin cookie — matches history
    {"host": "filebin.net",    "name": "csrftoken",    "value": "mNpQrStUvWxYz12",               "encrypted": False, "path": "/", "expires": ts(-30), "created": ts(3),   "secure": True,  "http_only": False, "samesite": "Lax",    "profile": "Default"},

    # IP address cookie
    {"host": "185.220.101.47", "name": "PHPSESSID",    "value": "7f3a9c2d1e4b6f8a",              "encrypted": False, "path": "/", "expires": "",      "created": ts(3, 3, 22), "secure": False, "http_only": True, "samesite": "", "profile": "Default"},
]

# ── Bookmarks ─────────────────────────────────────────────────────────────────
bookmarks = [
    {"title": "GitHub",              "url": "https://github.com",                  "folder": "bookmark_bar", "date_added": ts(60),  "profile": "Default"},
    {"title": "Gmail",               "url": "https://mail.google.com",             "folder": "bookmark_bar", "date_added": ts(60),  "profile": "Default"},
    {"title": "Stack Overflow",      "url": "https://stackoverflow.com",           "folder": "bookmark_bar", "date_added": ts(45),  "profile": "Default"},
    {"title": "part1=BFX{br0wser_",  "url": "about:blank",                         "folder": "other",        "date_added": ts(3),   "profile": "Default"},
    {"title": "temp notes",          "url": "about:blank",                         "folder": "other",        "date_added": ts(3),   "profile": "Default"},
    {"title": "Hacker News",         "url": "https://news.ycombinator.com",        "folder": "bookmark_bar", "date_added": ts(30),  "profile": "Default"},
    {"title": "Python Docs",         "url": "https://docs.python.org/3/",          "folder": "other",        "date_added": ts(20),  "profile": "Default"},
    {"title": "[deleted]",           "url": "about:blank",                         "folder": "other",        "date_added": ts(4),   "profile": "Default", "deleted": True},
]

# ── Downloads ─────────────────────────────────────────────────────────────────
downloads = [
    # Normal downloads
    {"filename": "python-3.12.0-amd64.exe",  "source_url": "https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe",  "start_time": ts(10, 14, 0), "end_time": ts(10, 14, 2), "size_bytes": 25165824, "file_exists": True,  "danger_type": 0, "profile": "Default"},
    {"filename": "report_q3.pdf",            "source_url": "https://drive.google.com/uc?export=download&id=1abc",                "start_time": ts(5,  10, 0), "end_time": ts(5,  10, 1), "size_bytes": 204800,   "file_exists": True,  "danger_type": 0, "profile": "Default"},
    {"filename": "notes.txt",                "source_url": "https://docs.google.com/document/export",                            "start_time": ts(2,  16, 0), "end_time": ts(2,  16, 0), "size_bytes": 1024,     "file_exists": True,  "danger_type": 0, "profile": "Default"},

    # Suspicious — from filebin, missing from disk
    {"filename": "data_export.zip",          "source_url": "https://filebin.net/a7x9pqr3mnvb/data_export.zip",                   "start_time": ts(3,  2, 50), "end_time": ts(3,  2, 51), "size_bytes": 4718592,  "file_exists": False, "danger_type": 0, "profile": "Default"},

    # Flag part 4 — ROT13 filename. ROT13("4ll}") = "4yy}"
    {"filename": "flag_part4_4yy}.txt",      "source_url": "http://185.220.101.47/upload.php",                                   "start_time": ts(3,  3, 25), "end_time": ts(3,  3, 25), "size_bytes": 18,       "file_exists": False, "danger_type": 1, "profile": "Default"},

    # PS1 script — high risk
    {"filename": "cleanup.ps1",              "source_url": "https://pastebin.com/raw/xK9mR2Lw",                                  "start_time": ts(3,  2, 20), "end_time": ts(3,  2, 20), "size_bytes": 2048,     "file_exists": False, "danger_type": 0, "profile": "Default"},
]

# ── Build evidence.json ───────────────────────────────────────────────────────

evidence = {
    "meta": {
        "browser": "chrome",
        "extraction_time": ts(0, 8, 0),
        "platform": "Windows-10-10.0.19041-SP0",
        "extractor_version": "1.1.0",
        "profiles_extracted": [
            {"dir": "Default", "path": "C:\\Users\\jdoe\\AppData\\Local\\Google\\Chrome\\User Data\\Default", "label": "Default (jdoe@corp.internal)"}
        ],
        "total_artifacts": len(history) + len(cookies) + len(bookmarks) + len(downloads),
        "profile_path": "C:\\Users\\jdoe\\AppData\\Local\\Google\\Chrome\\User Data\\Default",
    },
    "hashes": {
        "Default/History":   hashlib.sha256(b"fake_history_db").hexdigest(),
        "Default/Cookies":   hashlib.sha256(b"fake_cookies_db").hexdigest(),
        "Default/Bookmarks": hashlib.sha256(b"fake_bookmarks").hexdigest(),
    },
    "history":   history,
    "cookies":   cookies,
    "bookmarks": bookmarks,
    "downloads": downloads,
}

EVIDENCE_FILE.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
print(f"[OK] evidence.json written → {EVIDENCE_FILE}")
print(f"     {len(history)} history  {len(cookies)} cookies  {len(bookmarks)} bookmarks  {len(downloads)} downloads")

# ── Now run analyzer to produce analysis.json ─────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).parent))

try:
    import analyzer
    analyzer.run()
    print(f"[OK] analysis.json written → {ANALYSIS_FILE}")
except Exception as e:
    print(f"[WARN] Analyzer failed ({e}) — run 'python analyzer.py' manually")

print()
print("=" * 60)
print("  CTF CHALLENGE READY")
print("=" * 60)
print()
print("  Run:  python serve.py")
print("  Then: http://localhost:5000")
print()
print("  Challenge: 'The Insider'")
print("  Find the full flag hidden across the browser artifacts.")
print("  Format: BFX{...}")
print()
print("  Hints (don't read unless stuck):")
print("  1. Something was bookmarked but not meant to stay.")
print("  2. A domain with cookies but no history visited at 3am.")
print("  3. Not all values are what they look like.")
print("  4. The filename itself is the clue.")
print("=" * 60)