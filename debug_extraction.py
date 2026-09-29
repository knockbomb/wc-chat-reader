"""Comprehensive diagnostic for V4 key extraction failure.

Run on Windows with WeChat running.  Tries EVERY possible combination:
- All .db files in data dir
- Multiple pointer offsets around each pattern match
- Validates DB format (SQLCipher vs plaintext vs other)
"""

from __future__ import annotations

import logging
import math
import struct
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(message)s")

from wc_chat_reader.core.constants import (
    SQLCIPHER_KEY_SIZE,
    SQLCIPHER_PAGE_SIZE,
    SQLCIPHER_SALT_SIZE,
    WeChatVersion,
)
from wc_chat_reader.key.memory_scanner import open_scanner
from wc_chat_reader.wechat.process_detector import require_wechat_process

# [0, 32] relaxed pattern
PATTERN = bytes([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
])
MIN_PTR = 0x10000
MAX_PTR = 0x7FFFFFFFFFFF


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    e = 0.0
    for c in counts:
        if c > 0:
            p = c / n
            e -= p * math.log2(p)
    return e


def check_db(path: Path) -> dict:
    """Analyze a database file and return diagnostic info."""
    info = {"path": path, "size": 0, "exists": False}
    try:
        info["size"] = path.stat().st_size
        info["exists"] = True
    except OSError:
        return info

    try:
        with path.open("rb") as f:
            header = f.read(512)
    except Exception as e:
        info["read_error"] = str(e)
        return info

    info["header_hex"] = header[:32].hex()
    info["is_sqlite_plain"] = header[:15] == b"SQLite format 3"
    info["salt"] = header[:16]
    info["salt_entropy"] = entropy(header[:16])

    # Check for SQLCipher V4 (no "SQLite format 3" header, high-entropy salt)
    if not info["is_sqlite_plain"] and info["salt_entropy"] > 3.0:
        info["likely_sqlcipher"] = True
    else:
        info["likely_sqlcipher"] = False

    return info


def try_validate(key: bytes, db_path: Path) -> tuple[bool, str]:
    """Try to validate a key against a database. Returns (ok, config_label)."""
    try:
        from wc_chat_reader.key.multi_validator import MultiValidator
        v = MultiValidator(db_path)
        return v.validate(key)
    except Exception as e:
        return False, ""


def main():
    proc = require_wechat_process()
    print(f"\n{'='*70}")
    print(f" WeChat Diagnostic Tool")
    print(f" pid={proc.pid}  version={proc.version_str}")
    print(f" data_dir={proc.data_dir}")
    print(f" exe={proc.exe_path}")
    print(f"{'='*70}")

    # ── Step 1: Find and analyze all .db files ──────────────────────
    print(f"\n[1/4] Database files in {proc.data_dir}")
    print("-" * 70)

    db_files = []
    if proc.data_dir:
        for p in sorted(proc.data_dir.rglob("*.db")):
            try:
                if p.is_file() and p.stat().st_size > 4096:
                    db_files.append(p)
            except OSError:
                pass

    valid_sqlcipher_dbs = []
    for f in db_files:
        info = check_db(f)
        if info.get("is_sqlite_plain"):
            tag = "PLAINTEXT"
        elif info.get("likely_sqlcipher"):
            tag = "SQLCIPHER?"
            valid_sqlcipher_dbs.append(f)
        else:
            tag = "UNKNOWN"
        print(f"  [{tag:>10}] {info['size']:>10,}B  salt_e={info.get('salt_entropy', 0):.1f}  {f.relative_to(proc.data_dir)}")

    print(f"\n  Total: {len(db_files)} files, {len(valid_sqlcipher_dbs)} likely SQLCipher")

    if not valid_sqlcipher_dbs:
        print("\n  *** ERROR: No SQLCipher databases found! ***")
        print("  Checking if ALL .db files are plaintext SQLite...")
        plain_count = sum(1 for f in db_files if check_db(f).get("is_sqlite_plain"))
        if plain_count == len(db_files) and db_files:
            print(f"  ALL {len(db_files)} files are PLAINTEXT SQLite.")
            print("  WeChat 4.1.15.13 may not encrypt all databases.")
            print("  Trying to find encrypted DBs in other locations...")

            # Check common alternative locations
            alt_dirs = []
            if proc.data_dir:
                parent = proc.data_dir.parent
                for d in parent.rglob("db_storage"):
                    if d.is_dir():
                        alt_dirs.append(d)

            for d in alt_dirs:
                for p in d.rglob("*.db"):
                    if p not in db_files:
                        info = check_db(p)
                        if info.get("likely_sqlcipher"):
                            valid_sqlcipher_dbs.append(p)
                            print(f"  FOUND: {p}")

        if not valid_sqlcipher_dbs:
            print("\n  NO encrypted databases found anywhere.")
            print("  This is the root cause of validation failure.")
            print("  Trying alternative approach: validate against ANY .db file...")
            # Use plaintext DBs as fallback - maybe they're all plaintext
            valid_sqlcipher_dbs = [f for f in db_files if f.stat().st_size > 4096][:5]

    # ── Step 2: Scan memory ─────────────────────────────────────────
    print(f"\n[2/4] Memory scan")
    print("-" * 70)

    scanner = open_scanner(proc.pid).__enter__()
    try:
        rw_regions = list(scanner.iter_rw_all(min_size=64 * 1024))
        total_mb = sum(r.size for r in rw_regions) / 1024 / 1024
        print(f"  RW regions: {len(rw_regions)}, {total_mb:.0f} MB")

        matches = 0
        # Collect ALL candidates from multiple offsets
        all_candidates = {}  # offset_label -> [(ptr_val, key_bytes)]

        PTR_OFFSETS = [-8, -16, -24, -32, 24, 32, 40, 48]

        for off_label in [f"ptr@{o}" for o in PTR_OFFSETS]:
            all_candidates[off_label] = []

        for region in rw_regions:
            pos = 0
            while pos < region.size:
                end = min(pos + 4 * 1024 * 1024, region.size)
                chunk = scanner.read(region.base + pos, end - pos)
                if chunk is None:
                    pos = end
                    continue

                idx = 0
                while True:
                    idx = chunk.find(PATTERN, idx)
                    if idx == -1:
                        break
                    matches += 1

                    # Try multiple pointer offsets
                    for ptr_off in PTR_OFFSETS:
                        p = idx + ptr_off
                        if p < 0 or p + 8 > len(chunk):
                            continue
                        try:
                            (ptr_val,) = struct.unpack_from("<Q", chunk, p)
                        except struct.error:
                            continue
                        if not (MIN_PTR < ptr_val < MAX_PTR):
                            continue
                        key = scanner.read(ptr_val, SQLCIPHER_KEY_SIZE)
                        if key and len(key) == SQLCIPHER_KEY_SIZE:
                            e = entropy(key)
                            if e >= 5.0:
                                label = f"ptr@{ptr_off}"
                                all_candidates[label].append((ptr_val, key))

                    # Also try inline reads at the match position
                    for inline_off in [0, 8, 16, 24, -16, -8]:
                        p = idx + inline_off
                        if p < 0 or p + SQLCIPHER_KEY_SIZE > len(chunk):
                            continue
                        key = chunk[p:p + SQLCIPHER_KEY_SIZE]
                        if len(key) == SQLCIPHER_KEY_SIZE and entropy(key) >= 5.0:
                            label = f"inline@{inline_off}"
                            if label not in all_candidates:
                                all_candidates[label] = []
                            all_candidates[label].append((0, key))

                    idx += 1

                pos = (end - 256) if end < region.size else end
    finally:
        scanner.close()

    print(f"  Pattern matches: {matches}")
    for label, cands in all_candidates.items():
        if cands:
            unique_keys = len(set(k for _, k in cands))
            print(f"  {label:>12}: {len(cands)} candidates, {unique_keys} unique")

    # ── Step 3: Validate against ALL DBs ────────────────────────────
    print(f"\n[3/4] Validation")
    print("-" * 70)

    found = False
    for label, cands in all_candidates.items():
        if not cands:
            continue
        # Deduplicate
        seen = set()
        unique = []
        for ptr_val, key in cands:
            if key not in seen:
                seen.add(key)
                unique.append((ptr_val, key))

        for db_path in valid_sqlcipher_dbs[:5]:
            for i, (ptr_val, key) in enumerate(unique):
                ok, cfg_label = try_validate(key, db_path)
                if ok:
                    print(f"\n  *** FOUND VALID KEY ***")
                    print(f"  Offset: {label}")
                    print(f"  DB: {db_path.relative_to(proc.data_dir) if proc.data_dir else db_path}")
                    print(f"  Config: {cfg_label}")
                    print(f"  Key: {key.hex()}")
                    print(f"  Ptr: 0x{ptr_val:x}")
                    print(f"  Validated after {i+1} attempt(s)")
                    found = True
                    break
            if found:
                break
        if found:
            break

        if unique:
            print(f"  {label:>12}: {len(unique)} unique keys, 0 validated "
                  f"(tested against {min(len(valid_sqlcipher_dbs), 5)} DBs, "
                  f"9 configs each)")

    if not found:
        print(f"\n  *** ALL VALIDATION FAILED ***")

    # ── Step 4: Deep diagnostics ────────────────────────────────────
    print(f"\n[4/4] Deep diagnostics")
    print("-" * 70)

    # Show first DB header
    if valid_sqlcipher_dbs:
        db = valid_sqlcipher_dbs[0]
        with db.open("rb") as f:
            page = f.read(SQLCIPHER_PAGE_SIZE)
        print(f"  First DB: {db.name} ({len(page)} bytes read)")
        print(f"  Salt (16B): {page[:16].hex()}")
        print(f"  Salt entropy: {entropy(page[:16]):.2f}")
        print(f"  Bytes 16-48: {page[16:48].hex()}")
        print(f"  Last 64B: {page[-64:].hex()}")
        is_sqlite = page[:15] == b"SQLite format 3"
        print(f"  Starts with 'SQLite format 3': {is_sqlite}")

    # Show memory context around first match
    print(f"\n  Memory context around first pattern match:")
    scanner = open_scanner(proc.pid).__enter__()
    try:
        for region in rw_regions[:5]:
            chunk = scanner.read(region.base, min(1024 * 1024, region.size))
            if chunk is None:
                continue
            idx = chunk.find(PATTERN)
            if idx >= 0:
                abs_addr = region.base + idx
                start = max(0, idx - 48)
                end = min(len(chunk), idx + 64)
                ctx = chunk[start:end]
                print(f"  Region: 0x{region.base:x}+{region.size:x}, "
                      f"match at 0x{abs_addr:x} (chunk offset {idx})")
                for row in range(0, len(ctx), 16):
                    off = start + row
                    hex_bytes = " ".join(f"{b:02x}" for b in ctx[row:row+16])
                    ascii_repr = "".join(
                        chr(b) if 32 <= b < 127 else "."
                        for b in ctx[row:row+16]
                    )
                    marker = " <-- PATTERN" if off <= idx < off + 16 else ""
                    print(f"    {abs_addr - idx + off:016x}: {hex_bytes:<48} {ascii_repr}{marker}")
                break
    finally:
        scanner.close()

    if not found:
        print(f"\n{'='*70}")
        print(" SUMMARY: Extraction failed. Key candidates found in memory")
        print(" but none validated against any database file.")
        print("")
        print(" Possible causes:")
        print(" 1. DB files are plaintext SQLite (not SQLCipher)")
        print(" 2. Key struct layout changed (ptr@-8 is wrong)")
        print(" 3. Database file doesn't match current WeChat session")
        print(" 4. WeChat 4.1.15.13 uses different encryption")
        print(f"{'='*70}")


if __name__ == "__main__":
    main()
