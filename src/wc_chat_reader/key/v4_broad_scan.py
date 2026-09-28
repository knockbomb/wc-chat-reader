"""V4 broad-scan key extractor for WeChat 4.1.13+.

Searches ALL writable memory (including DLL MEM_MAPPED data sections)
using ReadProcessMemory, with multiple pattern layouts and extraction
offsets.  Uses entropy pre-filtering to keep PBKDF2 tractable.

Also scans for the key_size marker ``20 00 00 00 00 00 00 00`` (32 as
uint64 LE) as a layout-agnostic fallback — the codec descriptor always
contains the key size, so this marker is present regardless of how the
surrounding struct changed across WeChat versions.

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


class V4BroadScanExtractor(KeyExtractor):
    """Broad memory scan: multi-pattern, multi-offset, all RW regions."""

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
            # Collect regions with logging
            regions: list[MemoryRegion] = []
            total_size = 0
            for r in scanner.iter_rw_all(min_size=64 * 1024):
                regions.append(r)
                total_size += r.size

            logger.info(
                f"v4-broad-scan: {len(regions)} RW region(s), "
                f"{total_size / 1024 / 1024:.0f} MB total"
            )

            # Phase 1: Full pattern [0, 32, 47]
            full_matches = 0
            for region in regions:
                for chunk, _ in self._read_chunks(scanner, region):
                    for off in self._find_all(chunk, _PATTERN_FULL):
                        full_matches += 1
                        for c in self._extract_at(chunk, off, scanner):
                            candidates.append(c)
                            if len(candidates) >= self._max_candidates:
                                break
                        if len(candidates) >= self._max_candidates:
                            break
                    if len(candidates) >= self._max_candidates:
                        break
                if len(candidates) >= self._max_candidates:
                    break

            logger.info(
                f"v4-broad-scan: [full pattern] {full_matches} match(es), "
                f"{len(candidates)} candidate(s)"
            )

            # Phase 2: Relaxed pattern [0, 32]
            if len(candidates) < 200:
                relaxed_matches = 0
                for region in regions:
                    for chunk, _ in self._read_chunks(scanner, region):
                        for off in self._find_all(chunk, _PATTERN_RELAXED):
                            relaxed_matches += 1
                            for c in self._extract_at(chunk, off, scanner):
                                candidates.append(c)
                                if len(candidates) >= self._max_candidates:
                                    break
                            if len(candidates) >= self._max_candidates:
                                break
                        if len(candidates) >= self._max_candidates:
                            break
                    if len(candidates) >= self._max_candidates:
                        break

                logger.info(
                    f"v4-broad-scan: [relaxed pattern] {relaxed_matches} "
                    f"match(es), total {len(candidates)} candidate(s)"
                )

            # Phase 3: key_size marker search (layout-agnostic)
            if len(candidates) < 200:
                ks_matches = 0
                for region in regions:
                    for chunk, _ in self._read_chunks(scanner, region):
                        for off in self._find_all(chunk, _KEYSIZE_MARKER):
                            ks_matches += 1
                            for c in self._extract_at(chunk, off, scanner):
                                candidates.append(c)
                                if len(candidates) >= self._max_candidates:
                                    break
                            if len(candidates) >= self._max_candidates:
                                break
                        if len(candidates) >= self._max_candidates:
                            break
                    if len(candidates) >= self._max_candidates:
                        break

                logger.info(
                    f"v4-broad-scan: [key_size marker] {ks_matches} "
                    f"match(es), total {len(candidates)} candidate(s)"
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

    # --- helpers ----------------------------------------------------------

    @staticmethod
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

    @staticmethod
    def _find_all(data: bytes, pattern: bytes) -> Iterator[int]:
        idx = 0
        while True:
            idx = data.find(pattern, idx)
            if idx == -1:
                break
            yield idx
            idx += 1

    @staticmethod
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
