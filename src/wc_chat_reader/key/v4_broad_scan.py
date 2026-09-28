"""V4 broad-scan key extractor for WeChat 4.1.13+.

Searches ALL readable memory (including DLL .rdata read-only data sections)
using ReadProcessMemory, with multiple pattern layouts and extraction offsets.

Key insight: the codec descriptor ``[0, 32, 47]`` is a compile-time constant
stored in Weixin.dll's ``.rdata`` section (PAGE_READONLY), NOT in writable
heap or .data sections.  Previous versions only scanned RW regions and
missed it entirely.

Phases:
  0. Full pattern in ALL readable regions (.rdata, .data, heap)
  1. Full pattern in RW regions only
  2. Relaxed pattern ``[0, 32]`` in RW regions
  3. key_size marker ``20 00…`` in RW regions

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

# Pattern A: full original [0, 32, 47] — 24 bytes
_PATTERN_FULL = bytes(
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x2F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]
)

# Pattern B: relaxed [0, 32] — 16 bytes
_PATTERN_RELAXED = bytes(
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]
)

# Pattern C: key_size marker — 8 bytes (most layout-agnostic)
_KEYSIZE_MARKER = b"\x20\x00\x00\x00\x00\x00\x00\x00"

# Pointer offsets from pattern start
PTR_OFFSETS = [-16, -8, 24, 32, 40]

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


class V4BroadScanExtractor(KeyExtractor):
    """Broad memory scan: multi-pattern, multi-offset, all readable regions."""

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
        if sample_db_path is None:
            from wc_chat_reader.key._memory_base import _find_sample_db
            sample_db_path = _find_sample_db(process, WeChatVersion.V4)
        if sample_db_path is None:
            raise KeyExtractionError(
                "V4BroadScanExtractor requires a sample_db_path for validation"
            )

        validator = KeyValidator(sample_db_path, process.version)
        candidates: list[tuple[bytes, str, int]] = []

        logger.info(
            f"v4-broad-scan: starting (pid={process.pid}, "
            f"sample_db={sample_db_path})"
        )

        scanner = WindowsMemoryScanner(process.pid)
        try:
            # Phase 0: Full pattern in ALL readable regions (includes .rdata)
            # The codec descriptor is a compile-time constant in .rdata.
            all_regions: list[MemoryRegion] = []
            all_size = 0
            for r in scanner.iter_readable_all(min_size=4 * 1024):
                all_regions.append(r)
                all_size += r.size

            logger.info(
                f"v4-broad-scan: {len(all_regions)} readable region(s), "
                f"{all_size / 1024 / 1024:.0f} MB total"
            )

            p0 = _scan_pattern(
                scanner, all_regions, _PATTERN_FULL,
                self._max_candidates, candidates,
            )
            logger.info(
                f"v4-broad-scan: [phase 0: full pattern, all readable] "
                f"{p0} match(es), {len(candidates)} candidate(s)"
            )

            # Phase 1-3: RW regions only (for relaxed/marker patterns)
            rw_regions: list[MemoryRegion] = []
            rw_size = 0
            for r in scanner.iter_rw_all(min_size=64 * 1024):
                rw_regions.append(r)
                rw_size += r.size

            logger.info(
                f"v4-broad-scan: {len(rw_regions)} RW region(s), "
                f"{rw_size / 1024 / 1024:.0f} MB"
            )

            # Phase 1: Full pattern in RW only
            if len(candidates) < 200:
                p1 = _scan_pattern(
                    scanner, rw_regions, _PATTERN_FULL,
                    self._max_candidates, candidates,
                )
                logger.info(
                    f"v4-broad-scan: [phase 1: full pattern, RW] "
                    f"{p1} match(es), {len(candidates)} candidate(s)"
                )

            # Phase 2: Relaxed pattern [0, 32]
            if len(candidates) < 200:
                p2 = _scan_pattern(
                    scanner, rw_regions, _PATTERN_RELAXED,
                    self._max_candidates, candidates,
                )
                logger.info(
                    f"v4-broad-scan: [phase 2: relaxed pattern] "
                    f"{p2} match(es), {len(candidates)} candidate(s)"
                )

            # Phase 3: key_size marker
            if len(candidates) < 200:
                p3 = _scan_pattern(
                    scanner, rw_regions, _KEYSIZE_MARKER,
                    self._max_candidates, candidates,
                )
                logger.info(
                    f"v4-broad-scan: [phase 3: key_size marker] "
                    f"{p3} match(es), {len(candidates)} candidate(s)"
                )
        finally:
            scanner.close()

        if not candidates:
            raise NoValidKeyError(
                "v4-broad-scan: no candidates found in any memory region."
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

        # Validate
        for i, (key, strat, off) in enumerate(unique):
            if validator.validate(key):
                logger.info(
                    f"v4-broad-scan: valid key! strategy={strat}, "
                    f"offset={off}, after {i + 1} validation(s)"
                )
                return KeyResult(
                    key=key,
                    strategy=self.name,
                    candidates_scanned=i + 1,
                    meta={
                        "db_path": str(sample_db_path),
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
