#!/usr/bin/env python3
"""
BrowserForensix — leveldb_reader.py
Minimal LevelDB reader for Chrome localStorage extraction.
Zero external dependencies — pure Python stdlib only.

Chrome stores localStorage and sessionStorage in LevelDB directories:
  <profile>/Local Storage/leveldb/     ← localStorage per origin
  <profile>/Session Storage/           ← sessionStorage (ephemeral)
  <profile>/Extension State/           ← extension localStorage

LevelDB on-disk format used by Chrome (leveldb 1.20):
  - MANIFEST file: describes which .ldb/.sst files are live
  - *.log files: write-ahead log, most recent unflushed data
  - *.ldb files: sorted string tables (SST), compacted data

Key format in Chrome localStorage LevelDB:
  \x00 + origin_url (UTF-8) + \x00 + \x01  →  value (UTF-8)
  or
  origin_url (no prefix) + \x00 + key (UTF-8)  →  value (UTF-8)

This reader implements:
  1. LevelDB log file parsing (*.log) — captures recent/unflushed writes
  2. LevelDB SST/ldb file parsing (*.ldb) — captures compacted data
  3. Chrome localStorage key format decoding

References:
  https://github.com/google/leveldb/blob/main/doc/log_format.md
  https://github.com/google/leveldb/blob/main/doc/table_format.md
"""

import os
import struct
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("leveldb_reader")

# ── LevelDB log record types ──────────────────────────────────────────────────
_FULL   = 1
_FIRST  = 2
_MIDDLE = 3
_LAST   = 4

# LevelDB block size
_BLOCK_SIZE = 32768

# Value type in WriteBatch
_TYPE_DELETION = 0x00
_TYPE_VALUE    = 0x01


# FIX-LDB-1: CRC32C lookup table built once at module load, not per-call.
# Previously rebuilt 256 entries inside _crc32c() on every invocation.
def _build_crc32c_table():
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ 0x82F63B78 if crc & 1 else crc >> 1
        table.append(crc)
    return table

_CRC32C_TABLE = _build_crc32c_table()


def _crc32c(data: bytes) -> int:
    """CRC32C (Castagnoli) using pre-built module-level lookup table."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc = _CRC32C_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def _masked_crc(data: bytes) -> int:
    """LevelDB stores a 'masked' CRC: ((crc >> 15 | crc << 17) + 0xa282ead8)."""
    crc = _crc32c(data)
    return (((crc >> 15) | (crc << 17)) + 0xa282ead8) & 0xFFFFFFFF


def _read_varint(data: bytes, offset: int) -> Tuple[int, int]:
    """
    Read a varint from data at offset. Returns (value, new_offset).
    FIX-LDB-4: caps shift at 63 bits. Malformed all-continuation-bit input
    previously produced an unbounded Python int, silently corrupting offset
    arithmetic for all subsequent reads in the block.
    """
    result = 0
    shift = 0
    while offset < len(data):
        if shift > 63:  # FIX-LDB-4: 9 bytes max for a 64-bit varint
            break
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            break
        shift += 7
    return result, offset


# ── Log file parser ───────────────────────────────────────────────────────────

def _parse_log_file(path: Path) -> List[Tuple[bytes, bytes, int]]:
    """
    Parse a LevelDB .log file and return all key-value pairs as
    [(key_bytes, value_bytes, value_type), …].
    value_type: 1=put, 0=delete.
    """
    results = []
    try:
        data = path.read_bytes()
    except Exception as e:
        log.debug(f"Log read failed {path}: {e}")
        return results

    # FIX-LDB-2: single active fragment chain instead of a dict keyed by offset.
    # LevelDB guarantees one interleaved sequence per file — the dict approach
    # appended MIDDLE/LAST to ALL active chains simultaneously, corrupting them.
    offset = 0
    active_fragments: List[bytes] = []
    in_fragment = False

    while offset + 7 <= len(data):
        # 7-byte record header: checksum(4) + length(2) + type(1)
        header = data[offset:offset + 7]
        checksum = struct.unpack_from("<I", header, 0)[0]
        length   = struct.unpack_from("<H", header, 4)[0]
        rec_type = header[6]
        offset  += 7

        if length == 0 and rec_type == 0:
            # Padding to block boundary — skip to next block start
            next_block = ((offset - 1) // _BLOCK_SIZE + 1) * _BLOCK_SIZE
            offset = next_block
            continue

        if offset + length > len(data):
            break

        payload = data[offset:offset + length]
        offset += length

        if rec_type == _FULL:
            in_fragment = False
            active_fragments = []
            _parse_write_batch(payload, results)
        elif rec_type == _FIRST:
            # Discard any incomplete previous sequence and start fresh
            in_fragment = True
            active_fragments = [payload]
        elif rec_type == _MIDDLE:
            if in_fragment:
                active_fragments.append(payload)
        elif rec_type == _LAST:
            if in_fragment:
                active_fragments.append(payload)
                _parse_write_batch(b"".join(active_fragments), results)
                active_fragments = []
                in_fragment = False

    return results


def _parse_write_batch(data: bytes, out: List) -> None:
    """
    Parse a LevelDB WriteBatch record.
    Format: sequence(8) + count(4) + [type(1) + key_len_varint + key + val_len_varint + val]*
    """
    if len(data) < 12:
        return
    # sequence = struct.unpack_from("<Q", data, 0)[0]  # not needed
    count  = struct.unpack_from("<I", data, 8)[0]
    # FIX-LDB-3: corrupt log with count=0xFFFFFFFF would spin 4B iterations
    # before the offset-bounds check breaks. Cap at a sane maximum.
    if count > 100_000:
        log.debug(f"WriteBatch count {count} exceeds sanity limit — skipping")
        return
    offset = 12

    for _ in range(count):
        if offset >= len(data):
            break
        val_type = data[offset]
        offset += 1

        key_len, offset = _read_varint(data, offset)
        if offset + key_len > len(data):
            break
        key = data[offset:offset + key_len]
        offset += key_len

        if val_type == _TYPE_VALUE:
            val_len, offset = _read_varint(data, offset)
            if offset + val_len > len(data):
                break
            val = data[offset:offset + val_len]
            offset += val_len
            out.append((key, val, _TYPE_VALUE))
        elif val_type == _TYPE_DELETION:
            out.append((key, b"", _TYPE_DELETION))


# ── SST / .ldb file parser ────────────────────────────────────────────────────

def _parse_ldb_file(path: Path) -> List[Tuple[bytes, bytes, int]]:
    """
    Parse a LevelDB SST (.ldb) file.
    SST format: data_blocks + index_block + footer.
    Footer (48 bytes at end): metaindex_handle + index_handle + padding + magic(8).
    We read the index block to locate data blocks, then scan data blocks.
    LevelDB magic: 0xdb4775248b80fb57
    """
    results = []
    try:
        data = path.read_bytes()
    except Exception as e:
        log.debug(f"LDB read failed {path}: {e}")
        return results

    if len(data) < 48:
        return results

    MAGIC = b"\x57\xfb\x80\x8b\x24\x75\x47\xdb"
    if data[-8:] != MAGIC:
        log.debug(f"LDB magic mismatch: {path.name}")
        return results

    # Parse footer to find index block handle
    footer = data[-48:]
    # metaindex handle: offset varint + size varint (we skip it)
    _, pos = _read_varint(footer, 0)
    _, pos = _read_varint(footer, pos)
    # index block handle: offset + size
    idx_offset, pos = _read_varint(footer, pos)
    idx_size, _     = _read_varint(footer, pos)

    if idx_offset + idx_size > len(data):
        return results

    # Read and decompress index block (Chrome uses Snappy, but we try raw first)
    idx_block_raw = data[idx_offset:idx_offset + idx_size + 5]  # +5 for compression type + crc
    # Block trailer: compression_type(1) + crc(4)
    # compression_type: 0=none, 1=snappy
    if len(idx_block_raw) < 5:
        return results
    compression = idx_block_raw[-5]
    idx_block   = idx_block_raw[:-5]

    if compression == 1:
        idx_block = _snappy_decompress(idx_block)
        if idx_block is None:
            return results

    # Parse index block entries to find data block offsets
    data_handles = _parse_block_entries(idx_block)

    for _key, handle_bytes, _ in data_handles:
        try:
            blk_offset, pos2 = _read_varint(handle_bytes, 0)
            blk_size, _      = _read_varint(handle_bytes, pos2)
        except Exception:
            continue

        if blk_offset + blk_size + 5 > len(data):
            continue

        raw_block = data[blk_offset:blk_offset + blk_size + 5]
        compression = raw_block[-5]
        block = raw_block[:-5]

        if compression == 1:
            block = _snappy_decompress(block)
            if block is None:
                continue

        entries = _parse_block_entries(block)
        for k, v, t in entries:
            results.append((k, v, t))

    return results


def _parse_block_entries(block: bytes) -> List[Tuple[bytes, bytes, int]]:
    """
    Parse key-value entries from a LevelDB data block.
    Block format: [restart_count(4)] at the end; entries use prefix compression.
    Each entry: shared_len(varint) + unshared_len(varint) + val_len(varint) + key_delta + value
    """
    if len(block) < 4:
        return []

    num_restarts = struct.unpack_from("<I", block, len(block) - 4)[0]
    if num_restarts > 10000:
        return []
    data_end = len(block) - 4 - (num_restarts * 4)
    if data_end < 0:
        return []

    results = []
    offset = 0
    last_key = b""

    while offset < data_end:
        if offset + 3 > data_end:
            break
        try:
            shared,   offset = _read_varint(block, offset)
            unshared, offset = _read_varint(block, offset)
            val_len,  offset = _read_varint(block, offset)
        except Exception:
            break

        if offset + unshared + val_len > len(block):
            break

        key_delta = block[offset:offset + unshared]
        offset   += unshared
        key = last_key[:shared] + key_delta
        last_key = key

        val    = block[offset:offset + val_len]
        offset += val_len

        # Internal key format: user_key + sequence(7 bytes) + type(1 byte)
        if len(key) >= 8:
            ikey_type = key[-1] & 0xFF
            user_key  = key[:-8]
            results.append((user_key, val, ikey_type))

    return results


def _snappy_decompress(data: bytes) -> Optional[bytes]:
    """
    Attempt Snappy decompression using the python-snappy package.
    Falls back to None (caller skips the block) if unavailable.
    """
    try:
        import snappy  # type: ignore
        return snappy.decompress(data)
    except ImportError:
        pass
    except Exception as e:
        log.debug(f"Snappy decompress failed: {e}")
    return None


# ── Chrome localStorage key decoder ──────────────────────────────────────────

def _decode_chrome_ls_key(raw_key: bytes) -> Tuple[Optional[str], Optional[str]]:
    """
    Decode a Chrome localStorage LevelDB key into (origin, storage_key).

    Chrome uses two key formats depending on version:
      Format A (older): \x00 + origin_url(utf8) + \x00 + \x01 → metadata
                        \x00 + origin_url(utf8) + \x00 + key(utf8) → value
      Format B (newer): origin_url(utf8) + \x00 + key(utf8) → value
      Format C (newest): \x00 + length(4,BE) + origin + \x00 + key → value

    We try each heuristically.
    """
    if not raw_key:
        return None, None

    try:
        # Format A / Format C: starts with \x00
        if raw_key[0] == 0x00:
            rest = raw_key[1:]

            # FIX-LDB-6: Format C (Chrome 96+) uses \x00 + length(4,BE) + origin + \x00 + key.
            # Distinguish from Format A by checking if bytes 1-4 decode as a big-endian
            # uint32 that matches the length of a valid origin string.
            if len(rest) >= 5:
                try:
                    origin_len = struct.unpack_from(">I", rest, 0)[0]
                    if 4 < origin_len < len(rest) - 4:
                        origin_candidate = rest[4:4 + origin_len]
                        after = rest[4 + origin_len:]
                        if b"\x00" not in origin_candidate and after and after[0] == 0x00:
                            origin_str = origin_candidate.decode("utf-8", errors="replace")
                            if origin_str.startswith(("http", "chrome", "file")):
                                key_part = after[1:]
                                if not key_part or key_part == b"\x01":
                                    return origin_str, "_metadata_"
                                return origin_str, key_part.decode("utf-8", errors="replace")
                except Exception:
                    pass  # Not Format C — fall through to Format A

            # Format A: \x00 + origin + \x00 + key (pre-96 Chrome)
            null_pos = rest.find(b"\x00")
            if null_pos > 0:
                origin = rest[:null_pos].decode("utf-8", errors="replace")
                key_part = rest[null_pos + 1:]
                if key_part == b"\x01" or not key_part:
                    return origin, "_metadata_"
                return origin, key_part.decode("utf-8", errors="replace")

        # Format B: plain origin + \x00 + key (mid-era Chrome)
        null_pos = raw_key.find(b"\x00")
        if null_pos > 0:
            origin   = raw_key[:null_pos].decode("utf-8", errors="replace")
            key_part = raw_key[null_pos + 1:]
            if origin.startswith(("http", "chrome", "file", "chrome-extension")):
                return origin, key_part.decode("utf-8", errors="replace")

    except Exception:
        pass

    return None, None


# ── Public API ────────────────────────────────────────────────────────────────

def read_localstorage(profile_path: Path) -> List[Dict]:
    """
    Extract all localStorage key-value pairs from a Chrome profile directory.
    Returns a list of dicts compatible with evidence.json schema:
    [
      {
        "origin":  "https://example.com",
        "key":     "user_token",
        "value":   "abc123",
        "source":  "Local Storage",
        "profile": profile_label,
      },
      ...
    ]
    """
    results = []
    profile_label = profile_path.name

    storage_dirs = [
        (profile_path / "Local Storage" / "leveldb", "Local Storage"),
        (profile_path / "Session Storage",            "Session Storage"),
        (profile_path / "Extension State",            "Extension State"),
    ]

    for storage_dir, source_label in storage_dirs:
        if not storage_dir.exists():
            continue

        log.info(f"{profile_label} {source_label}: reading LevelDB at {storage_dir}")

        # Collect all KV pairs from log files and ldb files
        raw_kvs: Dict[bytes, Tuple[bytes, int]] = {}  # key → (value, type)

        # Log files first (most recent writes, overwrite ldb data if same key)
        log_files = sorted(storage_dir.glob("*.log"))
        for lf in log_files:
            for k, v, t in _parse_log_file(lf):
                raw_kvs[k] = (v, t)

        # LDB files (older compacted data, lower priority)
        ldb_files = sorted(storage_dir.glob("*.ldb"))
        for lf in ldb_files:
            for k, v, t in _parse_ldb_file(lf):
                if k not in raw_kvs:  # don't overwrite newer log data
                    raw_kvs[k] = (v, t)

        log.info(f"  {source_label}: {len(raw_kvs)} raw KV pairs")

        # Decode Chrome-specific key format
        seen = set()
        for raw_key, (raw_val, val_type) in raw_kvs.items():
            if val_type == _TYPE_DELETION:
                continue  # deleted entry

            origin, storage_key = _decode_chrome_ls_key(raw_key)
            if not origin or not storage_key:
                continue
            if storage_key == "_metadata_":
                continue

            dedup_key = (origin, storage_key)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            try:
                # Chrome stores values as UTF-16LE with a 2-byte length prefix
                # or as raw UTF-8 depending on version
                value_str = _decode_chrome_ls_value(raw_val)
            except Exception:
                value_str = raw_val.decode("utf-8", errors="replace")

            results.append({
                "origin":  origin,
                "key":     storage_key,
                "value":   value_str,
                "source":  source_label,
                "profile": profile_label,
            })

    log.info(f"{profile_label} localStorage: {len(results)} entries total")
    return results


def _decode_chrome_ls_value(raw: bytes) -> str:
    """
    Chrome localStorage values are stored as:
      - UTF-16LE with a 2-byte little-endian length prefix (older Chrome)
      - Raw UTF-8 (newer Chrome / leveldb changes)
    Try UTF-16LE first if it looks right, fall back to UTF-8.
    """
    if len(raw) >= 2:
        declared_len = struct.unpack_from("<H", raw, 0)[0]
        utf16_body   = raw[2:]
        # Valid UTF-16LE: body length == declared_len * 2
        if declared_len * 2 == len(utf16_body):
            try:
                return utf16_body.decode("utf-16-le")
            except Exception:
                pass

    # Fall back to UTF-8
    return raw.decode("utf-8", errors="replace")


def read_all_storage(profile_path: Path) -> List[Dict]:
    """
    Convenience wrapper. Reads localStorage, sessionStorage, and extension state.
    Returns unified list.
    """
    return read_localstorage(profile_path)