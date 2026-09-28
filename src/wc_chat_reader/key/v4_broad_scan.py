"""V4 broad-scan key extractor for WeChat 4.1.13+.

Runtime key struct layout (verified on WeChat 4.1.15.13)::

    [key_ptr (8B)] [flags=0 (8B)] [key_size=32 (8B)] [...]

The relaxed pattern ``[0, 32]`` (16 bytes) matches the runtime struct in
**writable** heap memory.  The actual AES-256 key is an 8-byte pointer
*before* the pattern start (``ptr@-8``).

The full pattern ``[0, 32, 47]`` (24 bytes) is a *compile-time constant*
in Weixin.dll's ``.rdata`` section (PAGE_READONLY).  It describes default
codec parameters but does NOT contain the key pointer — scanning it is
diagnostic only.

Phases:
  0. **Relaxed pattern** ``[0, 32]`` in RW regions → PRIMARY extraction
  1. Full pattern ``[0, 32, 47]`` in RW regions (diagnostic, usually 0 candidates)
  2. Full pattern in ALL readable regions incl. .rdata (diagnostic log only)

Uses entropy pre-filtering to keep PBKDF2 tractable.

Only runs on Windows.  Requires elevation (admin).
"""

from __future__ import annotations

import math
import struct
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING

from wc_chat_reader.core.constants import (
    SQLCIPHER_KEY_SIZE,
    WeChatVersion,
)
from wc_chat_reader.core.exceptions import (
    KeyExtractionError,
    NoValidKeyError,
)
from wc_chat_reader.core.logger import get_logger
from wc_chat_reader.key.base import KeyExtractor, KeyResult
from wc_chat_reader.key.memory_scanner import WindowsMemoryScanner
from wc_chat_reader.key.validator import KeyValidator

if TYPE_CHECKING:
    from wc_chat_reader.key.memory_scanner import MemoryRegion
    from wc_chat_reader.wechat.process_detector import WeChatProcess

logger = get_logger(__name__)

MIN_PTR = 0x10000
MAX_PTR = 0x7FFFFFFFFFFF

# ── Patterns ──────────────────────────────────────────────────────────
#
# Runtime struct (heap, RW): [key_ptr][0][32][...]
#   → Relaxed pattern [0, 32] matches at offset +8 from struct start.
#   → Key pointer is at offset -8 from pattern start.
#
# Compile-time constant (.rdata, RO): [0][32][47]
#   → Full pattern matches but yields NO key candidates (no pointer nearby).

# PRIMARY: relaxed [0, 32] — 16 bytes, matches runtime heap struct
_PATTERN_RELAXED = bytes(
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]
)

# DIAGNOSTIC: full [0, 32, 47] — 24 bytes, matches .rdata constant
_PATTERN_FULL = bytes(
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x2F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]
)

# Pointer offsets from pattern start — ptr@-8 first (verified working)
PTR_OFFSETS = [-8, -16, 24, 32, 40]

# Inline offsets from pattern start
INLINE_OFFSETS = [-40, -32, -24, -16, 24, 32, 40, 48, 56, 64]

_CHUNK = 4 * 1024 * 1024  # 4 MB per read
_OVERLAP = 256


def _entropy_score(data: bytes) -> float:
    """Shannon entropy of a byte sequence (0.0 – 8.0)."""
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


def _is_likely_key(data: bytes) -> bool:
    """Fast heuristic: is this 32-byte block a plausible AES-256 key?"""
    if len(data) != SQLCIPHER_KEY_SIZE:
        return False
    counts = [0] * 256
    nonzero = 0
    for b in data:
        counts[b] += 1
        if b != 0:
            nonzero += 1
    if nonzero < 20:
        return False
    if max(counts) > 3:
        return False
    if _entropy_score(data) < 5.0:
        return False
    return True


def _scan_pattern(
    scanner: WindowsMemoryScanner,
    regions: list[MemoryRegion],
    pattern: bytes,
    max_candidates: int,
    candidates: list[tuple[bytes, str, int]],
) -> int:
    """Scan regions for pattern, extract candidates. Returns match count."""
    matches = 0
    for region in regions:
        for chunk, _ in _read_chunks(scanner, region):
            for off in _find_all(chunk, pattern):
                matches += 1
                for c in _extract_at(chunk, off, scanner):
                    candidates.append(c)
                    if len(candidates) >= max_candidates:
                        return matches
        if len(candidates) >= max_candidates:
            return matches
    return matches


def _count_pattern(
    scanner: WindowsMemoryScanner,
    regions: list[MemoryRegion],
    pattern: bytes,
) -> int:
    """Count pattern matches without extracting candidates (diagnostic)."""
    total = 0
    for region in regions:
        for chunk, _ in _read_chunks(scanner, region):
            total += sum(1 for _ in _find_all(chunk, pattern))
    return total


class V4BroadScanExtractor(KeyExtractor):
    """Broad memory scan: relaxed pattern primary, full pattern diagnostic."""

    name = "v4-broad-scan"
    priority = 4

    def __init__(self, max_candidates: int = 5000) -> None:
        self._max_candidates = max_candidates

    def supports(self, process: WeChatProcess) -> bool:
        return sys.platform == "win32" and process.version == WeChatVersion.V4

    def unsupported_reason(self, process: WeChatProcess) -> str | None:
        if sys.platform != "win32":
            return "memory scanning requires Windows"
        if process.version != WeChatVersion.V4:
            return f"process version is {process.version.name}, expected V4"
        return None

    def extract(
        self,
        process: WeChatProcess,
        sample_db_path: Path | None = None,
    ) -> KeyResult:
        # Collect candidate DBs for multi-file validation
        db_paths: list[Path] = []
        if sample_db_path is not None:
            db_paths.append(sample_db_path)
        else:
            from wc_chat_reader.key._memory_base import _find_all_sample_dbs
            db_paths = _find_all_sample_dbs(process, WeChatVersion.V4)

        if not db_paths:
            raise KeyExtractionError(
                "V4BroadScanExtractor requires a sample_db_path for validation"
            )

        # Build validators for all available DBs
        validators: list[tuple[Path, KeyValidator]] = []
        for db in db_paths[:5]:  # limit to 5 to avoid excessive file I/O
            try:
                validators.append((db, KeyValidator(db, process.version)))
            except Exception as exc:
                logger.debug(f"v4-broad-scan: skip {db.name}: {exc}")

        if not validators:
            raise KeyExtractionError(
                f"V4BroadScanExtractor: no valid SQLCipher DBs found "
                f"among {len(db_paths)} candidate(s)"
            )

        candidates: list[tuple[bytes, str, int]] = []

        logger.info(
            f"v4-broad-scan: starting (pid={process.pid}, "
            f"{len(validators)} DB(s) for validation)"
        )

        scanner = WindowsMemoryScanner(process.pid)
        try:
            # Collect RW regions (primary scan target)
            rw_regions: list[MemoryRegion] = []
            rw_size = 0
            for r in scanner.iter_rw_all(min_size=64 * 1024):
                rw_regions.append(r)
                rw_size += r.size

            logger.info(
                f"v4-broad-scan: {len(rw_regions)} RW region(s), "
                f"{rw_size / 1024 / 1024:.0f} MB"
            )

            # Phase 0: Relaxed pattern [0, 32] in RW → PRIMARY
            p0 = _scan_pattern(
                scanner, rw_regions, _PATTERN_RELAXED,
                self._max_candidates, candidates,
            )
            logger.info(
                f"v4-broad-scan: [phase 0: relaxed pattern, RW] "
                f"{p0} match(es), {len(candidates)} candidate(s)"
            )

            # Phase 1: Full pattern [0, 32, 47] in RW → diagnostic
            if len(candidates) < 200:
                p1 = _scan_pattern(
                    scanner, rw_regions, _PATTERN_FULL,
                    self._max_candidates, candidates,
                )
                logger.info(
                    f"v4-broad-scan: [phase 1: full pattern, RW (diagnostic)] "
                    f"{p1} match(es), {len(candidates)} candidate(s)"
                )

            # Phase 2: Full pattern in ALL readable → diagnostic log only
            if len(candidates) < 200:
                all_regions: list[MemoryRegion] = []
                all_size = 0
                for r in scanner.iter_readable_all(min_size=4 * 1024):
                    all_regions.append(r)
                    all_size += r.size

                ro_only = [
                    r for r in all_regions
                    if r not in rw_regions
                ]
                p2 = _count_pattern(scanner, ro_only, _PATTERN_FULL)
                logger.info(
                    f"v4-broad-scan: [phase 2: full pattern, RO-only "
                    f"(diagnostic)] {p2} match(es) in "
                    f"{len(ro_only)} read-only region(s)"
                )
        finally:
            scanner.close()

        if not candidates:
            raise NoValidKeyError(
                "v4-broad-scan: no candidates found in any RW memory region."
            )

        # Deduplicate
        seen: set[bytes] = set()
        unique: list[tuple[bytes, str, int]] = []
        for key, strat, off in candidates:
            if key not in seen:
                seen.add(key)
                unique.append((key, strat, off))

        logger.info(
            f"v4-broad-scan: {len(unique)} unique candidate(s) "
            f"(from {len(candidates)} total)"
        )

        # Validate against ALL DBs — first match wins
        for i, (key, strat, off) in enumerate(unique):
            for db_path, validator in validators:
                if validator.validate(key):
                    logger.info(
                        f"v4-broad-scan: valid key! strategy={strat}, "
                        f"offset={off}, db={db_path.name}, "
                        f"after {i + 1} validation(s)"
                    )
                    return KeyResult(
                        key=key,
                        strategy=self.name,
                        candidates_scanned=i + 1,
                        meta={
                            "db_path": str(db_path),
                            "version": process.version_str,
                            "extraction_strategy": strat,
                            "extraction_offset": off,
                            "total_unique": len(unique),
                        },
                    )
            if (i + 1) % 100 == 0:
                logger.debug(
                    f"v4-broad-scan: validated {i + 1}/{len(unique)}"
                )

        raise NoValidKeyError(
            f"v4-broad-scan: {len(unique)} unique candidate(s), none matched."
        )


# --- module-level helpers ---------------------------------------------------


def _read_chunks(
    scanner: WindowsMemoryScanner,
    region: MemoryRegion,
) -> Iterator[tuple[bytes, int]]:
    pos = 0
    while pos < region.size:
        end = min(pos + _CHUNK, region.size)
        chunk = scanner.read(region.base + pos, end - pos)
        if chunk is not None:
            yield chunk, pos
        pos = (end - _OVERLAP) if end < region.size else end


def _find_all(data: bytes, pattern: bytes) -> Iterator[int]:
    idx = 0
    while True:
        idx = data.find(pattern, idx)
        if idx == -1:
            break
        yield idx
        idx += 1


def _extract_at(
    chunk: bytes,
    match_off: int,
    scanner: WindowsMemoryScanner,
) -> Iterator[tuple[bytes, str, int]]:
    """Extract candidates from one pattern match."""
    # Pointer dereference
    for off in PTR_OFFSETS:
        p = match_off + off
        if p < 0 or p + 8 > len(chunk):
            continue
        try:
            (ptr_val,) = struct.unpack_from("<Q", chunk, p)
        except struct.error:
            continue
        if not (MIN_PTR < ptr_val < MAX_PTR):
            continue
        key = scanner.read(ptr_val, SQLCIPHER_KEY_SIZE)
        if key and len(key) == SQLCIPHER_KEY_SIZE and _is_likely_key(key):
            yield key, f"ptr@{off}", off

    # Inline read
    for off in INLINE_OFFSETS:
        p = match_off + off
        if p < 0 or p + SQLCIPHER_KEY_SIZE > len(chunk):
            continue
        key = chunk[p : p + SQLCIPHER_KEY_SIZE]
        if len(key) == SQLCIPHER_KEY_SIZE and _is_likely_key(key):
            yield key, f"inline@{off}", off
