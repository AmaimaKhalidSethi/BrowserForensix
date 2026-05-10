#!/usr/bin/env python3
"""
BrowserForensix — decryptor.py
Chrome AES-256-GCM cookie decryption.

Chrome 80+ encrypts cookie values with AES-256-GCM. The AES key is stored
in Local State as os_crypt.encrypted_key, itself wrapped with the OS
credential store (DPAPI on Windows, Keychain on macOS, fixed passphrase
on Linux).

This module is imported by extract.py. It never modifies browser data.
All decryption is read-only and operates on copied bytes already in memory.

Usage in extract.py:
    from decryptor import CookieDecryptor
    decryptor = CookieDecryptor(user_data_path, cookie_key_hex=args.cookie_key)
    plaintext = decryptor.decrypt(encrypted_value_bytes)

Fallback chain (each step tried silently, never raises):
  1. --cookie-key hex argument (CTF / offline use)
  2. Local State encrypted_key + OS unwrap (DPAPI / Keychain / Linux)
  3. Legacy Chrome < 80 plaintext (no encryption, just return as-is)
  4. Return None  → caller keeps "[ENCRYPTED]"
"""

import os
import sys
import base64
import hashlib
import logging
import platform
import struct
from pathlib import Path
from typing import Optional

log = logging.getLogger("decryptor")

# Chrome v10 prefix on AES-GCM encrypted values
_V10_PREFIX = b"v10"
_V11_PREFIX = b"v11"
_NONCE_LEN  = 12   # AES-GCM standard nonce
_TAG_LEN    = 16   # AES-GCM auth tag

# ── AES-GCM decrypt (stdlib only — no pycryptodome required) ──────────────────

def _aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> Optional[bytes]:
    """
    AES-256-GCM decryption using Python's cryptography package if available,
    falling back to PyCryptodome, then to a pure-Python implementation stub.
    We try imports at call time so missing packages degrade gracefully.
    """
    # Try cryptography (most common)
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext + tag, None)
    except ImportError:
        pass
    except Exception as e:
        log.debug(f"AESGCM decrypt failed: {e}")
        return None

    # Try PyCryptodome
    try:
        from Crypto.Cipher import AES  # type: ignore
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        cipher.verify(tag)
        return plaintext
    except ImportError:
        pass
    except Exception as e:
        log.debug(f"PyCryptodome decrypt failed: {e}")
        return None

    log.warning(
        "No AES-GCM library found. Install either:\n"
        "  pip install cryptography\n"
        "  pip install pycryptodome"
    )
    return None


# ── OS key unwrappers ─────────────────────────────────────────────────────────

def _unwrap_windows(encrypted_key_b64: str) -> Optional[bytes]:
    """
    Unwrap the Chrome AES key using Windows DPAPI (CryptUnprotectData).
    Works only when running as the same Windows user who owns the profile.
    Requires no external packages — uses ctypes on stdlib.
    """
    if platform.system() != "Windows":
        return None
    try:
        import ctypes
        import ctypes.wintypes

        encrypted = base64.b64decode(encrypted_key_b64)
        # Chrome prepends "DPAPI" (5 bytes) before the DPAPI blob
        if encrypted[:5] == b"DPAPI":
            encrypted = encrypted[5:]

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", ctypes.wintypes.DWORD),
                         ("pbData", ctypes.POINTER(ctypes.c_char))]

        p_in = ctypes.create_string_buffer(encrypted)
        blob_in = DATA_BLOB(ctypes.sizeof(p_in), p_in)
        blob_out = DATA_BLOB()

        ok = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in),
            None, None, None, None, 0,
            ctypes.byref(blob_out)
        )
        if not ok:
            log.debug("CryptUnprotectData returned False")
            return None

        result = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)
        return result
    except Exception as e:
        log.debug(f"Windows DPAPI unwrap failed: {e}")
        return None


def _unwrap_macos(encrypted_key_b64: str) -> Optional[bytes]:
    """
    Unwrap Chrome AES key via macOS Keychain using the `security` CLI.
    Only works on a live macOS system with Keychain access.
    """
    if platform.system() != "Darwin":
        return None
    try:
        import subprocess
        result = subprocess.run(
            ["security", "find-generic-password",
             "-w", "-a", "Chrome", "-s", "Chrome Safe Storage"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            # Try Chromium
            result = subprocess.run(
                ["security", "find-generic-password",
                 "-w", "-a", "Chromium", "-s", "Chromium Safe Storage"],
                capture_output=True, text=True, timeout=5
            )
        if result.returncode != 0:
            log.debug("Keychain lookup failed — no Chrome Safe Storage entry")
            return None

        passphrase = result.stdout.strip().encode()
        # Chrome on macOS uses PBKDF2-SHA1 with 1003 iterations, 16-byte salt
        # "saltysalt", 128-bit key
        import hashlib as _hl
        key = _hl.pbkdf2_hmac("sha1", passphrase, b"saltysalt", 1003, dklen=16)
        return key
    except Exception as e:
        log.debug(f"macOS Keychain unwrap failed: {e}")
        return None


def _unwrap_linux() -> Optional[bytes]:
    """
    Linux Chrome uses a fixed passphrase ('peanuts') for most installs,
    or the Gnome/KDE keyring. We try the fixed key first (covers most CTF
    scenarios and default Chrome on Linux), then attempt Secret Service.
    Fixed-key PBKDF2: SHA1, 1 iteration, salt 'saltysalt', 16 bytes.
    """
    if platform.system() != "Linux":
        return None

    def _pbkdf2(passphrase: str) -> bytes:
        return hashlib.pbkdf2_hmac("sha1", passphrase.encode(),
                                   b"saltysalt", 1, dklen=16)

    # 1. Fixed passphrase (peanuts) — default for most Linux Chromes
    try:
        return _pbkdf2("peanuts")
    except Exception:
        pass

    # 2. Gnome keyring via secretstorage
    try:
        import secretstorage  # type: ignore
        bus = secretstorage.dbus_init()
        col = secretstorage.get_default_collection(bus)
        items = list(col.search_items({"application": "chrome"}))
        if not items:
            items = list(col.search_items({"application": "chromium"}))
        if items:
            passphrase = items[0].get_secret().decode()
            return _pbkdf2(passphrase)
    except Exception as e:
        log.debug(f"Linux secretstorage failed: {e}")

    return None


def _unwrap_from_local_state(local_state_path: Path) -> Optional[bytes]:
    """Read Local State and unwrap the Chrome master AES key via OS."""
    try:
        import json
        state = json.loads(local_state_path.read_text(encoding="utf-8"))
        b64_key = state.get("os_crypt", {}).get("encrypted_key", "")
        if not b64_key:
            log.debug("Local State: os_crypt.encrypted_key not found")
            return None
    except Exception as e:
        log.debug(f"Local State read failed: {e}")
        return None

    os_name = platform.system()
    if os_name == "Windows":
        return _unwrap_windows(b64_key)
    elif os_name == "Darwin":
        return _unwrap_macos(b64_key)
    elif os_name == "Linux":
        return _unwrap_linux()
    return None


# ── macOS legacy AES-CBC (Chrome < 80 on macOS) ───────────────────────────────

def _decrypt_cbc(key: bytes, ciphertext: bytes) -> Optional[bytes]:
    """
    Chrome < 80 on macOS/Linux used AES-128-CBC with a fixed IV of 16 spaces.
    ciphertext has a 3-byte version prefix (v10) already stripped by caller.
    """
    iv = b" " * 16
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding as _padding
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        dec = cipher.decryptor()
        raw = dec.update(ciphertext) + dec.finalize()
        # PKCS7 unpad
        unpadder = _padding.PKCS7(128).unpadder()
        return unpadder.update(raw) + unpadder.finalize()
    except ImportError:
        pass
    try:
        from Crypto.Cipher import AES  # type: ignore
        from Crypto.Util.Padding import unpad
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), 16)
    except ImportError:
        pass
    return None


# ── Main decryptor class ──────────────────────────────────────────────────────

class CookieDecryptor:
    """
    Stateful decryptor for a single Chrome profile.
    Resolves the AES key once at construction time, then decrypts on demand.

    Parameters
    ----------
    user_data_path : Path
        The "User Data" directory (parent of Default/, Profile 1/, …).
        Used to locate Local State.
    cookie_key_hex : str, optional
        32-byte AES key as a 64-char hex string. Bypasses all OS calls.
        Use for CTF / offline analysis when you know the key.
    """

    def __init__(self, user_data_path: Optional[Path] = None,
                 cookie_key_hex: Optional[str] = None):
        self._key: Optional[bytes] = None
        self._available = False

        # 1. Explicit key overrides everything (CTF / offline)
        if cookie_key_hex:
            try:
                key = bytes.fromhex(cookie_key_hex.strip())
                if len(key) not in (16, 32):
                    log.warning(f"--cookie-key must be 16 or 32 bytes ({len(key)} given) — ignoring")
                else:
                    self._key = key
                    self._available = True
                    log.info("Cookie decryption: using explicit --cookie-key")
                    return
            except ValueError:
                log.warning("--cookie-key is not valid hex — ignoring")

        # 2. Derive from OS credential store via Local State
        if user_data_path:
            local_state = user_data_path / "Local State"
            if local_state.exists():
                key = _unwrap_from_local_state(local_state)
                if key:
                    self._key = key
                    self._available = True
                    log.info(f"Cookie decryption: OS key resolved ({platform.system()})")
                    return
                else:
                    log.info("Cookie decryption: OS key unwrap failed — values shown as [ENCRYPTED]")
            else:
                # Single profile path given — try parent
                parent_state = user_data_path.parent / "Local State"
                if parent_state.exists():
                    key = _unwrap_from_local_state(parent_state)
                    if key:
                        self._key = key
                        self._available = True
                        log.info(f"Cookie decryption: OS key resolved from parent ({platform.system()})")
                        return

        # 3. Linux fixed key (no Local State needed)
        if platform.system() == "Linux":
            key = _unwrap_linux()
            if key:
                self._key = key
                self._available = True
                log.info("Cookie decryption: Linux fixed key")
                return

        log.info("Cookie decryption: unavailable — values shown as [ENCRYPTED]")

    @property
    def available(self) -> bool:
        return self._available

    def decrypt(self, encrypted_value: bytes) -> Optional[str]:
        """
        Decrypt a single cookie encrypted_value blob.
        Returns the plaintext string, or None if decryption is impossible/fails.
        """
        if not encrypted_value:
            return None

        # Chrome v10/v11 AES-GCM: [prefix(3)] [nonce(12)] [ciphertext] [tag(16)]
        if encrypted_value[:3] in (_V10_PREFIX, _V11_PREFIX):
            if not self._key:
                return None
            payload = encrypted_value[3:]
            if len(payload) < _NONCE_LEN + _TAG_LEN:
                log.debug("Encrypted value too short for AES-GCM")
                return None
            nonce      = payload[:_NONCE_LEN]
            ciphertext = payload[_NONCE_LEN:-_TAG_LEN]
            tag        = payload[-_TAG_LEN:]
            raw = _aes_gcm_decrypt(self._key, nonce, ciphertext, tag)
            if raw is None:
                return None
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError:
                return raw.decode("latin-1")

        # macOS/Linux CBC (v10 prefix but different structure in older Chrome)
        # Handled above; if we reach here with a non-v10 blob it is plaintext
        # that SQLite stored as bytes (edge case in very old profiles).
        try:
            return encrypted_value.decode("utf-8")
        except Exception:
            return None

    def decrypt_to_display(self, encrypted_value: bytes) -> str:
        """
        Returns decrypted string, or '[ENCRYPTED]' if unavailable,
        or '[DECRYPT_FAILED]' if key exists but decryption errored.
        """
        if not encrypted_value:
            return ""
        if not self._available:
            return "[ENCRYPTED]"
        result = self.decrypt(encrypted_value)
        if result is None:
            return "[DECRYPT_FAILED]"
        return result