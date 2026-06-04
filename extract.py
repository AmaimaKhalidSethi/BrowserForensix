#!/usr/bin/env python3
"""
BrowserForensix — extract.py
Extracts browser artifacts from Chrome, Firefox, Edge, Safari.

Fix 1: Discovers ALL Chrome profile directories (Default, Profile 1, Profile 2 …)
        and merges their artifacts into evidence.json — one run extracts all
        Google accounts, not just the first one.

Fix 2: History query now joins urls + visits tables so every individual visit
        has its own precise timestamp, not just the aggregate last_visit_time
        from urls. This is why data appeared "3 days old" — the urls table
        only updates its last_visit_time when Chrome checkpoints the WAL
        (often on close). The visits table records each visit as it happens,
        and the WAL copy captures those too.

Fix 3: WAL snapshot — when Chrome is open, copies both History and History-wal
        into a temp location and opens with immutable=0 so SQLite merges the
        WAL in-process. This picks up visits from the last few minutes even if
        Chrome has not been closed.
"""

import os
import sys
import json
import shutil
import sqlite3
import hashlib
import logging
import argparse
import platform
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from leveldb_reader import read_all_storage as _read_storage
    _LEVELDB_OK = True
except ImportError:
    _LEVELDB_OK = False

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger("extract")

OUTPUT_FILE = Path(__file__).parent / "data" / "evidence.json"

# ── Epoch converters ──────────────────────────────────────────────────────────

def chrome_epoch_to_iso(microseconds: int) -> str:
    """Chrome timestamps are microseconds since 1601-01-01 UTC."""
    try:
        if not microseconds:
            return ""
        EPOCH_DIFF = 11644473600  # seconds between 1601-01-01 and 1970-01-01
        ts = (int(microseconds) / 1_000_000) - EPOCH_DIFF
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except Exception:
        return ""

def unix_to_iso(seconds) -> str:
    try:
        return datetime.fromtimestamp(int(seconds), tz=timezone.utc).isoformat()
    except Exception:
        return ""

def firefox_epoch_to_iso(microseconds: int) -> str:
    try:
        return datetime.fromtimestamp(int(microseconds) / 1_000_000, tz=timezone.utc).isoformat()
    except Exception:
        return ""

# ── User Data base paths per OS ───────────────────────────────────────────────

USER_DATA_PATHS = {
    "chrome": {
        "Windows": [
            Path(os.environ.get("LOCALAPPDATA", "")) / "Google/Chrome/User Data",
        ],
        "Darwin": [
            Path.home() / "Library/Application Support/Google/Chrome",
        ],
        "Linux": [
            Path.home() / ".config/google-chrome",
            Path.home() / ".config/chromium",
        ],
    },
    "edge": {
        "Windows": [
            Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft/Edge/User Data",
        ],
        "Darwin": [
            Path.home() / "Library/Application Support/Microsoft Edge",
        ],
    },
}

FIREFOX_PROFILE_PATHS = {
    "Windows": [
        Path(os.environ.get("APPDATA", "")) / "Mozilla/Firefox/Profiles",
    ],
    "Darwin": [
        Path.home() / "Library/Application Support/Firefox/Profiles",
    ],
    "Linux": [
        Path.home() / ".mozilla/firefox",
    ],
}

SAFARI_PATHS = {
    "Darwin": [Path.home() / "Library/Safari"],
}

# ── Profile discovery ─────────────────────────────────────────────────────────

def find_all_chrome_profiles(browser: str, custom_path: Optional[str] = None) -> List[Path]:
    """
    Return every Chrome/Edge profile directory found under User Data.

    Chrome stores each signed-in Google account in its own subdirectory:
      User Data/Default      ← first account
      User Data/Profile 1    ← second account
      User Data/Profile 2    ← third account
      …

    This function discovers all of them so that a user with 4 Google accounts
    gets all 4 profiles extracted in a single run.

    If --profile is supplied it is treated as a single specific profile path,
    not a User Data root.
    """
    if custom_path:
        p = Path(custom_path)
        if p.exists():
            log.info(f"Using custom profile path: {p}")
            return [p]
        log.error(f"Custom profile path not found: {p}")
        return []

    os_name = platform.system()
    base_dirs = USER_DATA_PATHS.get(browser, {}).get(os_name, [])
    found: List[Path] = []

    for base in base_dirs:
        if not base.exists():
            log.info(f"User Data dir not found: {base}")
            continue

        # Read Local State to map profile dirs to account names (best-effort)
        account_names = _read_profile_names(base)

        # Collect every subdirectory that looks like a Chrome profile.
        # A valid profile directory contains at least a "History" or "Cookies" file.
        candidates = [base / "Default"] + sorted(base.glob("Profile *"))
        for profile_dir in candidates:
            if profile_dir.is_dir() and _is_chrome_profile(profile_dir):
                display_name = account_names.get(profile_dir.name, profile_dir.name)
                log.info(f"Profile found: {profile_dir}  [{display_name}]")
                found.append(profile_dir)

    if not found:
        log.error(
            f"{browser} profiles not found. Checked: "
            + ", ".join(str(b) for b in base_dirs)
        )
        log.info("Tip: use --profile /path/to/User Data/Default to specify a profile manually.")

    return found


def _is_chrome_profile(path: Path) -> bool:
    """A directory is a Chrome profile if it contains History or Preferences."""
    return (path / "History").exists() or (path / "Preferences").exists()


def _read_profile_names(user_data: Path) -> Dict[str, str]:
    """
    Parse User Data/Local State for the human-readable name of each profile
    (the Google account display name, e.g. "work@gmail.com").
    Returns a dict of {dir_name: display_name}.
    """
    names: Dict[str, str] = {}
    local_state = user_data / "Local State"
    if not local_state.exists():
        return names
    try:
        state = json.loads(local_state.read_text(encoding="utf-8"))
        profiles_info = state.get("profile", {}).get("info_cache", {})
        for dir_name, info in profiles_info.items():
            display = info.get("name") or info.get("user_name") or dir_name
            names[dir_name] = display
    except Exception as e:
        log.warning(f"Could not read Local State: {e}")
    return names


def find_firefox_profiles(custom_path: Optional[str] = None) -> List[Path]:
    if custom_path:
        p = Path(custom_path)
        return [p] if p.exists() else []

    os_name = platform.system()
    bases = FIREFOX_PROFILE_PATHS.get(os_name, [])
    found = []
    for base in bases:
        if base.exists():
            profiles = (
                list(base.glob("*.default-release"))
                + list(base.glob("*.default"))
                + list(base.glob("*.esr"))
            )
            for p in profiles:
                if p.is_dir():
                    log.info(f"Firefox profile found: {p}")
                    found.append(p)
    if not found:
        log.error(f"Firefox profiles not found. Checked: {[str(b) for b in bases]}")
    return found


# ── WAL-aware SQLite copy ─────────────────────────────────────────────────────

def safe_copy_db(src: Path, label: str) -> Optional[Path]:
    """
    Copy a SQLite database (and its WAL file if present) to a temp directory,
    then open with WAL checkpoint so recent writes from a running Chrome are
    included. This is why data was appearing "3 days old" — without copying
    the WAL, only the checkpointed main file was read.

    Returns the path to the copied main DB, or None on failure.
    """
    if not src.exists():
        log.warning(f"{label}: file not found at {src}")
        return None

    try:
        tmp_dir = Path(tempfile.mkdtemp())
        tmp_db = tmp_dir / src.name

        # Copy main DB file
        shutil.copy2(src, tmp_db)

        # Copy WAL and SHM files if they exist (Chrome open = WAL has recent data)
        wal = src.parent / (src.name + "-wal")
        shm = src.parent / (src.name + "-shm")
        wal_copied = False
        if wal.exists():
            shutil.copy2(wal, tmp_dir / wal.name)
            wal_copied = True
        if shm.exists():
            shutil.copy2(shm, tmp_dir / shm.name)

        if wal_copied:
            # Force WAL checkpoint on the copy so all recent visits are visible
            try:
                conn = sqlite3.connect(str(tmp_db))
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                conn.close()
                log.info(f"{label}: WAL merged — recent visits included (browser was open)")
            except Exception as e:
                log.warning(f"{label}: WAL checkpoint failed ({e}) — some recent data may be missing")
        else:
            log.info(f"{label}: copied from {src}")

        return tmp_db

    except PermissionError:
        log.error(f"{label}: permission denied reading {src}. Try running as administrator.")
        return None
    except Exception as e:
        log.error(f"{label}: failed to copy ({e})")
        return None


def cleanup_tmp(db_path: Optional[Path]) -> None:
    """Remove the temp directory created by safe_copy_db."""
    if db_path and db_path.exists():
        try:
            shutil.rmtree(db_path.parent)
        except Exception:
            pass


# ── SQLite query helper ───────────────────────────────────────────────────────

def query_db(db_path: Optional[Path], sql: str, label: str) -> List[Dict]:
    if not db_path:
        return []
    try:
        # immutable=0 (not 1) allows SQLite to see the merged WAL data
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(sql)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows
    except sqlite3.DatabaseError as e:
        log.error(f"{label}: SQLite error ({e}) — skipping.")
        return []
    except Exception as e:
        log.error(f"{label}: unexpected error ({e})")
        return []


def sha256_file(path: Path) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


# ── Chrome extractors ─────────────────────────────────────────────────────────

def extract_chrome_history(profile: Path, profile_label: str) -> List[Dict]:
    """
    Join urls + visits tables to get one row per individual visit with a
    precise per-visit timestamp.

    Fix: the old query read only from urls (last_visit_time), which is an
    aggregate updated infrequently — causing the "3 days stale" appearance.
    The visits table has visit_time updated on every navigation, and the
    WAL copy captures visits made while the browser is open.
    """
    db = safe_copy_db(profile / "History", f"{profile_label} History")
    rows = query_db(db, """
        SELECT
            u.url,
            u.title,
            u.visit_count,
            u.last_visit_time,
            v.visit_time         AS individual_visit_time,
            v.visit_duration,
            v.transition
        FROM urls u
        JOIN visits v ON v.url = u.id
        ORDER BY v.visit_time DESC
    """, f"{profile_label} History")
    cleanup_tmp(db)

    out = []
    for r in rows:
        # Use the individual visit_time from visits table (precise, per-visit)
        # Fall back to last_visit_time from urls if visits join is missing
        ts = r.get("individual_visit_time") or r.get("last_visit_time") or 0
        out.append({
            "url": r["url"],
            "title": r["title"] or "",
            "visit_count": r["visit_count"],
            "last_visit": chrome_epoch_to_iso(ts),
            "visit_duration_sec": round(r["visit_duration"] / 1_000_000, 1) if r.get("visit_duration") else 0,
            "transition": r.get("transition", 0),
            "profile": profile_label,
        })
    log.info(f"{profile_label} History: {len(out)} individual visit records.")
    return out


def extract_chrome_cookies(profile: Path, profile_label: str,
                           decryptor=None) -> List[Dict]:
    """
    Extract Chrome cookies.
    - v10/v11 (Chrome 80-126): decrypted via DPAPI + AES-256-GCM if decryptor available.
    - v20 (Chrome 127+, App-Bound Encryption): shown as [ENCRYPTED:v20].
      These require SYSTEM-level access and cannot be decrypted externally.
    - No prefix: plaintext (Firefox, old Chrome).
    """
    for name in ["Network/Cookies", "Cookies"]:
        src = profile / name
        if src.exists():
            db = safe_copy_db(src, f"{profile_label} Cookies")
            break
    else:
        log.warning(f"{profile_label} Cookies: file not found.")
        return []

    rows = query_db(db, """
        SELECT host_key, name, value, encrypted_value, path,
               expires_utc, creation_utc, is_secure, is_httponly,
               samesite, source_scheme
        FROM cookies
    """, f"{profile_label} Cookies")
    cleanup_tmp(db)

    decrypted_count = 0
    v20_count       = 0
    out = []

    for r in rows:
        raw_enc = r.get("encrypted_value") or b""
        raw_val = r.get("value") or ""

        prefix    = raw_enc[:3] if len(raw_enc) >= 3 else b""
        is_v20    = prefix == b"v20"
        is_v10v11 = prefix in (b"v10", b"v11")

        if is_v20:
            # Chrome 127+ App-Bound Encryption — cannot decrypt externally
            v20_count    += 1
            display_value = "[ENCRYPTED:v20]"
            is_encrypted  = True

        elif is_v10v11 and decryptor and decryptor.available:
            # DPAPI-wrapped AES-256-GCM — decryptable with resolved key
            result = decryptor.decrypt_to_display(raw_enc)
            if result and result not in ("[ENCRYPTED]", "[DECRYPT_FAILED]"):
                display_value = result
                is_encrypted  = False
                decrypted_count += 1
            else:
                display_value = result
                is_encrypted  = True

        elif raw_enc:
            # Encrypted, no decryptor or key not available
            display_value = "[ENCRYPTED]"
            is_encrypted  = True

        else:
            # Plaintext (Firefox, very old Chrome)
            display_value = raw_val
            is_encrypted  = False

        out.append({
            "host":      r["host_key"],
            "name":      r["name"],
            "value":     display_value,
            "encrypted": is_encrypted,
            "path":      r["path"],
            "expires":   chrome_epoch_to_iso(r["expires_utc"]) if r["expires_utc"] else "",
            "created":   chrome_epoch_to_iso(r["creation_utc"]),
            "secure":    bool(r["is_secure"]),
            "http_only": bool(r["is_httponly"]),
            "samesite":  r["samesite"],
            "profile":   profile_label,
        })

    summary = f"{len(out)} cookies"
    if decrypted_count: summary += f", {decrypted_count} decrypted (v10/v11)"
    if v20_count:       summary += f", {v20_count} App-Bound v20 (not decryptable)"
    log.info(f"{profile_label} Cookies: {summary}")
    return out


def extract_chrome_bookmarks(profile: Path, profile_label: str) -> List[Dict]:
    bm_file = profile / "Bookmarks"
    if not bm_file.exists():
        log.warning(f"{profile_label} Bookmarks: file not found.")
        return []
    try:
        data = json.loads(bm_file.read_text(encoding="utf-8"))
    except Exception as e:
        log.error(f"{profile_label} Bookmarks: failed to parse ({e})")
        return []

    out: List[Dict] = []

    def walk(node: dict, folder_path: str) -> None:
        if node.get("type") == "url":
            added = node.get("date_added", "0")
            out.append({
                "title": node.get("name", ""),
                "url": node.get("url", ""),
                "folder": folder_path,
                "date_added": chrome_epoch_to_iso(int(added)) if added else "",
                "guid": node.get("guid", ""),
                "profile": profile_label,
            })
        elif node.get("type") == "folder":
            name = node.get("name", "")
            for child in node.get("children", []):
                walk(child, f"{folder_path}/{name}" if folder_path else name)

    roots = data.get("roots", {})
    for root_name, root_node in roots.items():
        if isinstance(root_node, dict):
            walk(root_node, root_name)

    log.info(f"{profile_label} Bookmarks: {len(out)} entries.")
    return out


def extract_chrome_downloads(profile: Path, profile_label: str) -> List[Dict]:
    db = safe_copy_db(profile / "History", f"{profile_label} Downloads")
    rows = query_db(db, """
        SELECT tab_url, target_path, start_time, end_time,
               total_bytes, danger_type, state
        FROM downloads
        ORDER BY start_time DESC
    """, f"{profile_label} Downloads")
    cleanup_tmp(db)

    out = []
    for r in rows:
        out.append({
            "source_url": r["tab_url"],
            "file_path": r["target_path"],
            "filename": Path(r["target_path"]).name if r["target_path"] else "",
            "start_time": chrome_epoch_to_iso(r["start_time"]),
            "end_time": chrome_epoch_to_iso(r["end_time"]) if r["end_time"] else "",
            "size_bytes": r["total_bytes"],
            "danger_type": r["danger_type"],
            "state": r["state"],
            "file_exists": Path(r["target_path"]).exists() if r["target_path"] else False,
            "profile": profile_label,
        })
    log.info(f"{profile_label} Downloads: {len(out)} entries.")
    return out


# ── Firefox extractors ────────────────────────────────────────────────────────

def extract_firefox_history(profile: Path, profile_label: str) -> List[Dict]:
    """Firefox also stores individual visit records in moz_historyvisits."""
    db = safe_copy_db(profile / "places.sqlite", f"{profile_label} History")
    rows = query_db(db, """
        SELECT p.url, p.title, p.visit_count,
               v.visit_date AS individual_visit_time
        FROM moz_places p
        JOIN moz_historyvisits v ON p.id = v.place_id
        ORDER BY v.visit_date DESC
    """, f"{profile_label} History")
    cleanup_tmp(db)

    out = []
    for r in rows:
        out.append({
            "url": r["url"],
            "title": r["title"] or "",
            "visit_count": r["visit_count"] or 0,
            "last_visit": firefox_epoch_to_iso(r["individual_visit_time"]) if r["individual_visit_time"] else "",
            "profile": profile_label,
        })
    log.info(f"{profile_label} History: {len(out)} entries.")
    return out


def extract_firefox_cookies(profile: Path, profile_label: str) -> List[Dict]:
    db = safe_copy_db(profile / "cookies.sqlite", f"{profile_label} Cookies")
    rows = query_db(db, """
        SELECT host, name, value, path, expiry, creationTime,
               isSecure, isHttpOnly, sameSite
        FROM moz_cookies
    """, f"{profile_label} Cookies")
    cleanup_tmp(db)

    out = []
    for r in rows:
        out.append({
            "host": r["host"],
            "name": r["name"],
            "value": r["value"],
            "encrypted": False,
            "path": r["path"],
            "expires": unix_to_iso(r["expiry"]) if r["expiry"] else "",
            "created": firefox_epoch_to_iso(r["creationTime"]),
            "secure": bool(r["isSecure"]),
            "http_only": bool(r["isHttpOnly"]),
            "samesite": r["sameSite"],
            "profile": profile_label,
        })
    log.info(f"{profile_label} Cookies: {len(out)} entries.")
    return out


# ── Profile label helper ──────────────────────────────────────────────────────

def _profile_label(profile: Path, account_names: Optional[Dict[str, str]] = None) -> str:
    """
    Build a human-readable label for a profile directory.
    Reads Preferences JSON to find the signed-in account email if available.
    Falls back to the directory name (Default, Profile 1, …).
    """
    # Try Preferences file for signed-in account email
    prefs_file = profile / "Preferences"
    if prefs_file.exists():
        try:
            prefs = json.loads(prefs_file.read_text(encoding="utf-8"))
            account = (
                prefs.get("account_info", [{}])[0].get("email")
                or prefs.get("signin", {}).get("allowed_username")
                or prefs.get("profile", {}).get("name")
            )
            if account:
                return f"{profile.name} ({account})"
        except Exception:
            pass

    if account_names and profile.name in account_names:
        return f"{profile.name} ({account_names[profile.name]})"

    return profile.name


# ── Main ──────────────────────────────────────────────────────────────────────

def run(browser: str, profile_path: Optional[str] = None, cookie_key: Optional[str] = None) -> None:
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    os_name = platform.system()

    evidence: Dict = {
        "meta": {
            "browser": browser,
            "extraction_time": datetime.now(timezone.utc).isoformat(),
            "platform": platform.platform(),
            "extractor_version": "1.1.0",
            "profiles_extracted": [],
        },
        "hashes": {},
        "history": [],
        "cookies": [],
        "bookmarks": [],
        "downloads": [],
        "local_storage": [],
    }

    # ── Cookie decryptor (v10/v11 — Chrome <127, macOS, Linux, CTF profiles) ──
    # Import here so missing 'cryptography' package doesn't break extraction.
    # Gracefully falls back to [ENCRYPTED] if key cannot be resolved.
    _decryptor = None
    try:
        from decryptor import CookieDecryptor as _CD
        _decryptor = _CD  # store class, instantiate per browser-root below
    except ImportError:
        log.info("decryptor.py not found — cookie values shown as [ENCRYPTED]")
    except Exception as _e:
        log.warning(f"decryptor import failed: {_e}")

    # ── Chrome / Edge ──────────────────────────────────────────────────────────
    if browser in ("chrome", "edge"):
        profiles = find_all_chrome_profiles(browser, profile_path)
        if not profiles:
            sys.exit(1)

        # Read account names from Local State (best-effort)
        account_names: Dict[str, str] = {}
        if not profile_path and profiles:
            user_data = profiles[0].parent
            account_names = _read_profile_names(user_data)

        log.info(f"Extracting {len(profiles)} profile(s): {[p.name for p in profiles]}")

        # One decryptor per browser install — Local State is in the User Data root
        _cookie_decryptor = None
        if _decryptor and profiles:
            user_data_root = profiles[0].parent
            cookie_key_hex = cookie_key
            try:
                _cookie_decryptor = _decryptor(
                    user_data_path=user_data_root,
                    cookie_key_hex=cookie_key_hex,
                )
                if _cookie_decryptor.available:
                    log.info("Cookie decryption: key resolved — v10/v11 cookies will be decrypted")
                else:
                    log.info("Cookie decryption: key not resolved — v10/v11 shown as [ENCRYPTED]")
                    log.info("  (Chrome 127+ uses App-Bound Encryption; v20 cookies cannot be")
                    log.info("   decrypted by external tools — this is by design)")
            except Exception as _e:
                log.warning(f"Cookie decryptor init failed: {_e}")
                _cookie_decryptor = None

        for profile in profiles:
            label = _profile_label(profile, account_names)
            evidence["meta"]["profiles_extracted"].append({
                "dir": profile.name,
                "path": str(profile),
                "label": label,
            })

            evidence["history"]   += extract_chrome_history(profile, label)
            evidence["cookies"]   += extract_chrome_cookies(profile, label, _cookie_decryptor)
            evidence["bookmarks"] += extract_chrome_bookmarks(profile, label)
            evidence["downloads"] += extract_chrome_downloads(profile, label)
            try:
                from leveldb_reader import read_all_storage as _read_ls
                ls = _read_ls(profile)
                for entry in ls:
                    entry["profile"] = label
                evidence["local_storage"] += ls
                log.info(f"{label} localStorage: {len(ls)} entries")
            except Exception as _e:
                log.warning(f"{label} localStorage read failed: {_e}")

            # NOTE: History DB is copied once inside each extractor. Both history
            # and downloads extractors copy it independently for snapshot consistency.
            # If disk I/O is a concern use --profile to extract a single profile.

            # Hash source files for evidence integrity
            for art_name, rel_path in [
                ("History", "History"),
                ("Cookies", "Network/Cookies"),
                ("Bookmarks", "Bookmarks"),
            ]:
                src = profile / rel_path
                if not src.exists():
                    src = profile / art_name
                if src.exists():
                    key = f"{profile.name}/{art_name}"
                    evidence["hashes"][key] = sha256_file(src)

    # ── Firefox ────────────────────────────────────────────────────────────────
    elif browser == "firefox":
        profiles = find_firefox_profiles(profile_path)
        if not profiles:
            sys.exit(1)

        for profile in profiles:
            label = profile.name
            evidence["meta"]["profiles_extracted"].append({
                "dir": profile.name,
                "path": str(profile),
                "label": label,
            })
            evidence["history"] += extract_firefox_history(profile, label)
            evidence["cookies"] += extract_firefox_cookies(profile, label)

            for art_name, rel in [("Places", "places.sqlite"), ("Cookies", "cookies.sqlite")]:
                src = profile / rel
                if src.exists():
                    evidence["hashes"][f"{profile.name}/{art_name}"] = sha256_file(src)

    # ── Safari ─────────────────────────────────────────────────────────────────
    elif browser == "safari":
        if os_name != "Darwin":
            log.error("Safari is only available on macOS.")
            sys.exit(1)
        log.warning("Safari extraction: basic stub. Full plist/binary cookie parsing not yet implemented.")

    # ── Summary ────────────────────────────────────────────────────────────────
    total = sum(len(evidence[k]) for k in ("history", "cookies", "bookmarks", "downloads"))
    evidence["meta"]["total_artifacts"] = total
    evidence["meta"]["profile_path"] = (
        ", ".join(p["path"] for p in evidence["meta"]["profiles_extracted"])
        or "unknown"
    )

    raw = json.dumps(evidence, indent=2, ensure_ascii=False)
    # Atomic write: write to a sibling temp file then os.replace() into place.
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        dir=OUTPUT_FILE.parent,
        prefix=".evidence_tmp_",
        suffix=".json",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(raw)
        os.replace(tmp_path, OUTPUT_FILE)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    # Restrict to owner-read-only: evidence.json contains cookie values and file paths
    try:
        OUTPUT_FILE.chmod(0o600)
    except Exception:
        pass  # Windows doesn't support Unix chmod; acceptable

    n_profiles = len(evidence["meta"]["profiles_extracted"])
    log.info(
        f"Done. {total} artifacts from {n_profiles} profile(s) written to {OUTPUT_FILE}"
    )
    for p in evidence["meta"]["profiles_extracted"]:
        log.info(f"  {p['label']}  →  {p['path']}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="BrowserForensix Extractor — extracts all Chrome profiles automatically"
    )
    parser.add_argument(
        "--browser", default="chrome",
        choices=["chrome", "firefox", "edge", "safari"],
        help="Browser to extract from (default: chrome)",
    )
    parser.add_argument(
        "--profile", default=None,
        help=(
            "Path to a specific profile directory (e.g. .../Chrome/User Data/Profile 2). "
            "If omitted, all profiles are discovered and extracted automatically."
        ),
    )
    parser.add_argument(
        "--cookie-key",
        default=None,
        dest="cookie_key",
        metavar="HEX",
        help=(
            "32-byte AES key as 64 hex chars for offline/CTF cookie decryption. "
            "Bypasses OS keychain entirely."
        ),
    )
    args = parser.parse_args()
    run(args.browser, args.profile, args.cookie_key)
