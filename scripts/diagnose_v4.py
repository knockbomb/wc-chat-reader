"""Diagnostic tool for WeChat V4 key extraction.

Scans process memory to find the correct pattern and pointer offset
for WeChat 4.x key extraction. Run as Administrator with WeChat running.

Usage:
    python scripts/diagnose_v4.py [--pid PID] [--sample-db PATH]
"""

from __future__ import annotations

import argparse
import struct
import sys
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from wc_chat_reader.core.constants import SQLCIPHER_KEY_SIZE, WeChatVersion
from wc_chat_reader.key.memory_scanner import WindowsMemoryScanner, open_scanner
from wc_chat_reader.key.validator import KeyValidator
from wc_chat_reader.wechat.process_detector import find_wechat_processes

# Current V4 pattern (24 bytes: 0x00, 0x20, 0x2F as LE uint64)
CURRENT_PATTERN = bytes(
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x2F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]
)

MIN_PTR = 0x10000
MAX_PTR = 0x7FFFFFFFFFFF
CHUNK = 4 * 1024 * 1024  # 4MB


def find_sample_db(data_dir: Path) -> Path | None:
    for name in ("session.db", "message_0.db", "contact.db"):
        for p in data_dir.rglob(name):
            try:
                if p.is_file() and p.stat().st_size > 4096:
                    return p
            except OSError:
                continue
    for p in data_dir.rglob("*.db"):
        try:
            if p.is_file() and p.stat().st_size > 4096:
                return p
        except OSError:
            continue
    return None


def scan_with_current_pattern(scanner, validator, max_regions=50):
    """Scan using current V4 pattern and log details about matches."""
    pattern = CURRENT_PATTERN
    ptr_size = 8
    matches = []
    valid_keys = []
    total_read = 0
    max_bytes = 256 * 1024 * 1024  # 256MB for diagnostics

    print(f"\n=== Scanning with current V4 pattern ===")
    print(f"Pattern hex: {pattern.hex()}")
    print(f"Pattern length: {len(pattern)} bytes")
    print(f"Pointer offset: -{ptr_size} bytes before pattern\n")

    rw_regions = []
    for region in scanner.iter_regions(min_size=1024 * 1024):
        if region.protect & (0x04 | 0x08):
            rw_regions.append(region)

    print(f"RW regions: {len(rw_regions)}")
    regions_to_scan = rw_regions[:max_regions]
    print(f"Scanning first {len(regions_to_scan)} regions (max 256MB)\n")

    for ri, region in enumerate(regions_to_scan):
        if total_read >= max_bytes:
            break
        pos = 0
        while pos < region.size and total_read < max_bytes:
            end = min(pos + CHUNK, region.size)
            chunk = scanner.read(region.base + pos, end - pos)
            if chunk is None:
                pos = end
                continue
            total_read += len(chunk)

            # Find all pattern matches in this chunk
            idx = len(chunk)
            while True:
                idx = chunk.rfind(pattern, 0, idx)
                if idx == -1 or idx - ptr_size < 0:
                    break

                # Read the pointer before the pattern
                (ptr,) = struct.unpack_from("<Q", chunk, idx - ptr_size)
                abs_addr = region.base + pos + idx - ptr_size

                if MIN_PTR < ptr < MAX_PTR:
                    # Try to read the key at the pointer address
                    key = scanner.read(ptr, SQLCIPHER_KEY_SIZE)
                    if key and len(key) == SQLCIPHER_KEY_SIZE:
                        matches.append({
                            "region": ri,
                            "chunk_offset": pos + idx - ptr_size,
                            "abs_addr": abs_addr,
                            "ptr": ptr,
                            "key_hex": key[:8].hex() + "...",
                        })
                        if validator.validate(key):
                            valid_keys.append(key)
                            print(f"  ✓ VALID KEY FOUND at ptr=0x{ptr:x}")
                            print(f"    Key: {key.hex()}")
                else:
                    matches.append({
                        "region": ri,
                        "chunk_offset": pos + idx - ptr_size,
                        "abs_addr": abs_addr,
                        "ptr": ptr,
                        "key_hex": "PTR_OUT_OF_RANGE",
                    })
                idx -= 1

            if end < region.size:
                pos = end - 256
            else:
                pos = end

    print(f"\nTotal scanned: {total_read / 1024 / 1024:.1f} MB")
    print(f"Pattern matches: {len(matches)}")
    print(f"Valid keys found: {len(valid_keys)}")

    if matches:
        print(f"\nFirst 10 matches:")
        for m in matches[:10]:
            print(f"  Region {m['region']}, addr=0x{m['abs_addr']:x}, "
                  f"ptr=0x{m['ptr']:x}, key={m['key_hex']}")

    return matches, valid_keys


def brute_force_scan(scanner, validator, max_regions=20):
    """Try every possible 32-byte value in RW regions as a potential key."""
    print(f"\n=== Brute-force scan (try every 32-byte aligned offset) ===")
    print("This is slow but will find the key if it's in RW memory.\n")

    rw_regions = []
    for region in scanner.iter_regions(min_size=1024 * 1024):
        if region.protect & (0x04 | 0x08):
            rw_regions.append(region)

    regions_to_scan = rw_regions[:max_regions]
    total_checked = 0
    valid_keys = []
    t0 = time.time()

    for ri, region in enumerate(regions_to_scan):
        print(f"  Scanning region {ri+1}/{len(regions_to_scan)} "
              f"(base=0x{region.base:x}, size={region.size/1024/1024:.1f}MB)...",
              end="", flush=True)

        pos = 0
        region_checked = 0
        while pos < region.size:
            end = min(pos + CHUNK, region.size)
            chunk = scanner.read(region.base + pos, end - pos)
            if chunk is None:
                pos = end
                continue

            # Try every 32-byte aligned offset in the chunk
            for offset in range(0, len(chunk) - SQLCIPHER_KEY_SIZE + 1, 32):
                candidate = chunk[offset:offset + SQLCIPHER_KEY_SIZE]
                if len(candidate) == SQLCIPHER_KEY_SIZE:
                    total_checked += 1
                    region_checked += 1
                    if validator.validate(candidate):
                        abs_addr = region.base + pos + offset
                        print(f"\n  ✓ VALID KEY at 0x{abs_addr:x}!")
                        print(f"    Key: {candidate.hex()}")
                        valid_keys.append(candidate)

            pos = end

        elapsed = time.time() - t0
        print(f" checked {region_checked} candidates ({elapsed:.1f}s)")

    elapsed = time.time() - t0
    print(f"\nTotal checked: {total_checked} candidates in {elapsed:.1f}s")
    print(f"Valid keys found: {len(valid_keys)}")
    return valid_keys


def main():
    parser = argparse.ArgumentParser(description="V4 key extraction diagnostic")
    parser.add_argument("--pid", type=int, help="WeChat PID")
    parser.add_argument("--sample-db", type=str, help="Path to sample encrypted DB")
    parser.add_argument("--brute-force", action="store_true",
                        help="Run brute-force scan (slow)")
    args = parser.parse_args()

    if sys.platform != "win32":
        print("Error: This tool requires Windows.")
        sys.exit(1)

    # Find WeChat process
    procs = find_wechat_processes()
    if not procs:
        print("Error: No WeChat process found. Is WeChat running?")
        sys.exit(1)

    if args.pid:
        proc = next((p for p in procs if p.pid == args.pid), None)
        if not proc:
            print(f"Error: PID {args.pid} not found.")
            sys.exit(1)
    else:
        proc = procs[0]

    print(f"Using PID {proc.pid} (version={proc.version.name}, "
          f"version_str={proc.version_str})")

    if proc.version != WeChatVersion.V4:
        print(f"Warning: This tool is designed for V4. Process is {proc.version.name}.")

    # Find sample DB
    if args.sample_db:
        sample_db = Path(args.sample_db)
    elif proc.data_dir:
        sample_db = find_sample_db(proc.data_dir)
    else:
        sample_db = None

    if sample_db is None or not sample_db.exists():
        print("Error: No sample database found. Use --sample-db.")
        sys.exit(1)

    print(f"Sample DB: {sample_db}")
    validator = KeyValidator(sample_db, proc.version)

    # Scan
    print(f"\nStarting diagnostic scan (pid={proc.pid})...")
    with open_scanner(proc.pid) as scanner:
        matches, keys = scan_with_current_pattern(scanner, validator)

        if not keys and args.brute_force:
            keys = brute_force_scan(scanner, validator)

    if keys:
        print(f"\n=== SUCCESS ===")
        print(f"Found {len(keys)} valid key(s).")
        for k in keys:
            print(f"  Key: {k.hex()}")
    else:
        print(f"\n=== NO KEY FOUND ===")
        print("The current V4 pattern did not find a valid key.")
        if not args.brute_force:
            print("Try with --brute-force to search without pattern matching.")


if __name__ == "__main__":
    main()
