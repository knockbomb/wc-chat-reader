"""Diagnostic tool for V4 key extraction issues.

Run on Windows with WeChat running to diagnose why extraction fails.
"""

from __future__ import annotations

import logging
import struct
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(message)s")

from wc_chat_reader.core.constants import SQLCIPHER_KEY_SIZE, WeChatVersion
from wc_chat_reader.key.memory_scanner import open_scanner
from wc_chat_reader.key.validator import KeyValidator
from wc_chat_reader.wechat.process_detector import require_wechat_process

# [0, 32] relaxed pattern
PATTERN = bytes([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
])

MIN_PTR = 0x10000
MAX_PTR = 0x7FFFFFFFFFFF


def main():
    proc = require_wechat_process()
    print(f"\n{'='*60}")
    print(f"WeChat: pid={proc.pid}, version={proc.version_str}")
    print(f"Data dir: {proc.data_dir}")
    print(f"{'='*60}")

    # Step 1: Find all .db files in data_dir
    db_files = []
    if proc.data_dir:
        for p in proc.data_dir.rglob("*.db"):
            try:
                if p.is_file():
                    size = p.stat().st_size
                    if size > 4096:
                        db_files.append(p)
            except OSError:
                pass

    print(f"\nFound {len(db_files)} .db files (>4KB):")
    for f in db_files[:20]:
        print(f"  {f.stat().st_size:>10,} bytes  {f}")

    if not db_files:
        print("ERROR: No .db files found!")
        return

    # Step 2: Validate each DB as SQLCipher
    print(f"\n{'='*60}")
    print("SQLCipher DB validation:")
    valid_dbs = []
    for db_path in db_files[:10]:  # check first 10
        try:
            with db_path.open("rb") as f:
                first_page = f.read(4096)
            salt = first_page[:16]
            # Check salt entropy (should not be all zeros)
            if salt == b"\x00" * 16:
                print(f"  SKIP (zero salt): {db_path.name}")
                continue
            # Check if file starts with "SQLite format 3"
            if first_page[:15] == b"SQLite format 3":
                print(f"  SKIP (plaintext SQLite): {db_path.name}")
                continue
            # Try to create validator
            v = KeyValidator(db_path, WeChatVersion.V4)
            valid_dbs.append(db_path)
            print(f"  OK   {db_path.name} (salt={salt.hex()[:16]}...)")
        except Exception as e:
            print(f"  FAIL {db_path.name}: {e}")

    if not valid_dbs:
        print("\nERROR: No valid SQLCipher databases found!")
        return

    print(f"\n{len(valid_dbs)} valid SQLCipher DB(s)")

    # Step 3: Scan memory for [0,32] pattern, extract candidates
    print(f"\n{'='*60}")
    print("Memory scan (RW regions):")
    scanner = open_scanner(proc.pid).__enter__()
    try:
        rw_regions = list(scanner.iter_rw_all(min_size=64 * 1024))
        total_size = sum(r.size for r in rw_regions)
        print(f"  {len(rw_regions)} RW regions, {total_size / 1024 / 1024:.0f} MB")

        matches = 0
        ptr_candidates = []  # (ptr_value, match_addr)

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
                    # Read ptr at offset -8
                    p = idx - 8
                    if 0 <= p and p + 8 <= len(chunk):
                        (ptr_val,) = struct.unpack_from("<Q", chunk, p)
                        if MIN_PTR < ptr_val < MAX_PTR:
                            key = scanner.read(ptr_val, SQLCIPHER_KEY_SIZE)
                            if key and len(key) == SQLCIPHER_KEY_SIZE:
                                ptr_candidates.append((ptr_val, key))
                    idx += 1
                overlap = 256
                pos = (end - overlap) if end < region.size else end

        print(f"  {matches} pattern matches")
        print(f"  {len(ptr_candidates)} key candidates (ptr@-8)")
    finally:
        scanner.close()

    if not ptr_candidates:
        print("\nERROR: No key candidates found!")
        return

    # Deduplicate keys
    seen = set()
    unique = []
    for ptr_val, key in ptr_candidates:
        if key not in seen:
            seen.add(key)
            unique.append((ptr_val, key))
    print(f"  {len(unique)} unique keys")

    # Show first 3 keys
    print(f"\nFirst 3 unique keys (hex):")
    for i, (ptr_val, key) in enumerate(unique[:3]):
        print(f"  [{i}] ptr=0x{ptr_val:x} key={key.hex()}")

    # Step 4: Validate against EACH valid DB
    print(f"\n{'='*60}")
    print("Validation against all DBs:")
    found = False
    for db_path in valid_dbs:
        validator = KeyValidator(db_path, WeChatVersion.V4)
        for i, (ptr_val, key) in enumerate(unique):
            if validator.validate(key):
                print(f"  ✓ VALID! db={db_path.name}, key_idx={i}, ptr=0x{ptr_val:x}")
                found = True
                break
        if found:
            break
        print(f"  ✗ {db_path.name}: 0/{len(unique)} validated")

    if not found:
        print(f"\n  ALL FAILED. Trying different struct offsets...")
        # Try other offsets around the pattern
        print("  Scanning alternative pointer offsets...")
        scanner = open_scanner(proc.pid).__enter__()
        try:
            test_region = rw_regions[0]
            chunk = scanner.read(test_region.base, min(1024 * 1024, test_region.size))
            if chunk:
                idx = chunk.find(PATTERN)
                if idx >= 0:
                    print(f"  First match at chunk offset {idx}")
                    print(f"  Region base: 0x{test_region.base:x}")
                    print(f"  Absolute match addr: 0x{test_region.base + idx:x}")
                    # Show bytes around the match
                    start = max(0, idx - 32)
                    end = min(len(chunk), idx + 48)
                    context = chunk[start:end]
                    print(f"  Context bytes [{start}:{end}]:")
                    for row in range(0, len(context), 16):
                        hex_str = " ".join(f"{b:02x}" for b in context[row:row+16])
                        print(f"    +{start+row:4d}: {hex_str}")
        finally:
            scanner.close()


if __name__ == "__main__":
    main()
