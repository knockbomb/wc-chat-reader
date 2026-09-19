"""V4 broad-scan key extractor for WeChat 4.1.13.65+.

Why this exists
---------------
WeChat 4.1.13.65 changed the codec descriptor memory layout:

- The old pattern ``[0, 32, 47]`` still matches 277 times in RW memory,
  but the key pointer at offset -8 no longer points to a valid key.
- The key may now be stored *inline* in the struct (not via pointer),
  or the struct layout may have shifted.
- The DLL's .data section (MEM_MAPPED) was not scanned by the original
  extractor which only looked at MEM_PRIVATE (heap) regions.

This extractor tries **all** of the following against every pattern match:

1. Pointer dereference at offsets -8, +24, +32 (the key might be pointed
   to from different positions relative to the pattern).
2. Inline 32-byte reads at offsets -32, -24, -16, +24, +32, +40, +48,
   +56, +64 (the key might be embedded directly in the struct).
3. Both the ``[0, 32, 47]`` pattern AND the more relaxed ``[0, 32]``
   pattern (the third field may have changed in newer versions).
4. Scans ALL readable RW regions including MEM_MAPPED (DLL data sections),
   not just MEM_PRIVATE heap regions.

A fast entropy pre-filter rejects obvious non-key candidates before the
expensive PBKDF2+HMAC validation step, keeping runtime manageable.

Only runs on Windows.  Requires elevation (admin) for ReadProcessMemory.
"""

from __future__ import annotations

import math
import struct
import sys
from collections.abc import Iterator
from dataclasses import dataclass
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
from wc_chat_reader.key.memory_scanner import (
    WindowsMemoryScanner,
)
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
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # 0
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # 32
        0x2F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # 47
    ]
)

# Pattern B: relaxed [0, 32] — 16 bytes (third field may have changed)
_PATTERN_RELAXED = bytes(
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # 0
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # 32
    ]
)

# Pointer offsets to try: read 8 bytes at (match + offset) as a pointer,
# then dereference to get 32-byte key.
PTR_OFFSETS = [-16, -8, 24, 32, 40]

# Inline offsets to try: read 32 bytes directly at (match + offset).
INLINE_OFFSETS = [-40, -32, -24, -16, 24, 32, 40, 48, 56, 64]


def _entropy_score(data: bytes) -> float:
    """Shannon entropy of a byte sequence (0.0 – 8.0 bits/byte)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / n
            entropy -= p * math.log2(p)
    return entropy


def _is_likely_key(data: bytes) -> bool:
    """Fast heuristic: is this 32-byte block a plausible AES-256 key?

    A real AES-256 key is 32 bytes of uniformly random data, so:
    - Shannon entropy should be high (> 5.0 bits/byte out of max 8.0)
    - No byte should repeat more than 3 times
    - Non-zero byte count should be 20+
    """
    if len(data) != SQLCIPHER_KEY_SIZE:
        return False

    # Count byte frequencies.
    counts = [0] * 256
    nonzero = 0
    for b in data:
        counts[b] += 1
        if b != 0:
            nonzero += 1

    # Reject if too many zeros.
    if nonzero < 20:
        return False

    # Reject if any byte repeats more than 3 times.
    if max(counts) > 3:
        return False

    # Reject if all bytes are in the same narrow range (low entropy).
    entropy = _entropy_score(data)
    if entropy < 5.0:
        return False

    return True


class V4BroadScanExtractor(KeyExtractor):
    """Broad memory scan for V4 keys with multi-offset and multi-pattern search.

    Scans ALL readable RW memory (including DLL MEM_MAPPED regions), tries
    multiple pattern layouts and extraction offsets, and uses entropy
    pre-filtering to keep PBKDF2 validation tractable.
    """

    name = "v4-broad-scan"
    priority = 4  # Run before frida-memory-scan (5) and v4-memory-scan (10).

    def __init__(self, max_candidates: int = 5000) -> None:
        self._max_candidates = max_candidates

    def supports(self, process: WeChatProcess) -> bool:
        return (
            sys.platform == "win32"
            and process.version == WeChatVersion.V4
        )

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

        logger.info(
            f"v4-broad-scan: starting broad scan "
            f"(pid={process.pid}, sample_db={sample_db_path})"
        )

        candidates: list[tuple[bytes, str, int]] = []  # (key, strategy, offset)

        with _open_scanner_all_regions(process.pid) as scanner:
            # Phase 1: Full pattern [0, 32, 47] with multi-offset extraction
            count_full = 0
            for region in scanner.iter_rw_regions():
                for chunk_data, _chunk_base in self._iter_chunks(scanner, region):
                    for match_off in self._find_all(chunk_data, _PATTERN_FULL):
                        for key, strategy, offset in self._extract_candidates(
                            chunk_data, match_off, scanner, region
                        ):
                            candidates.append((key, strategy, offset))
                            count_full += 1
                            if len(candidates) >= self._max_candidates:
                                break
                        if len(candidates) >= self._max_candidates:
                            break
                    if len(candidates) >= self._max_candidates:
                        break
                if len(candidates) >= self._max_candidates:
                    break

            logger.info(
                f"v4-broad-scan: full pattern found {count_full} match(es), "
                f"{len(candidates)} candidate(s) so far"
            )

            # Phase 2: If not enough candidates, try relaxed pattern [0, 32]
            if len(candidates) < 100:
                count_relaxed = 0
                for region in scanner.iter_rw_regions():
                    for chunk_data, _chunk_base in self._iter_chunks(scanner, region):
                        for match_off in self._find_all(chunk_data, _PATTERN_RELAXED):
                            for key, strategy, offset in self._extract_candidates(
                                chunk_data, match_off, scanner, region
                            ):
                                candidates.append((key, strategy, offset))
                                count_relaxed += 1
                                if len(candidates) >= self._max_candidates:
                                    break
                            if len(candidates) >= self._max_candidates:
                                break
                        if len(candidates) >= self._max_candidates:
                            break
                    if len(candidates) >= self._max_candidates:
                        break

                logger.info(
                    f"v4-broad-scan: relaxed pattern added {count_relaxed} "
                    f"candidate(s), total: {len(candidates)}"
                )

        if not candidates:
            raise NoValidKeyError(
                "v4-broad-scan: no candidates found in any RW memory region. "
                "The codec descriptor layout may be completely different in "
                f"WeChat {process.version_str}."
            )

        # Deduplicate candidates (same key bytes).
        seen: set[bytes] = set()
        unique: list[tuple[bytes, str, int]] = []
        for key, strategy, offset in candidates:
            if key not in seen:
                seen.add(key)
                unique.append((key, strategy, offset))

        logger.info(
            f"v4-broad-scan: {len(unique)} unique candidate(s) "
            f"(from {len(candidates)} total)"
        )

        # Validate candidates with PBKDF2+HMAC.
        for i, (key, strategy, offset) in enumerate(unique):
            if validator.validate(key):
                logger.info(
                    f"v4-broad-scan: valid key found! "
                    f"strategy={strategy}, offset={offset}, "
                    f"after {i + 1} validation(s)"
                )
                return KeyResult(
                    key=key,
                    strategy=self.name,
                    candidates_scanned=i + 1,
                    meta={
                        "db_path": str(sample_db_path),
                        "version": process.version_str,
                        "extraction_strategy": strategy,
                        "extraction_offset": offset,
                        "total_unique_candidates": len(unique),
                    },
                )
            if (i + 1) % 100 == 0:
                logger.debug(
                    f"v4-broad-scan: validated {i + 1}/{len(unique)} candidates"
                )

        raise NoValidKeyError(
            f"v4-broad-scan: {len(unique)} unique candidate(s) validated, "
            f"none matched. The key storage may have fundamentally changed "
            f"in WeChat {process.version_str}."
        )

    def _iter_chunks(
        self,
        scanner: WindowsMemoryScanner,
        region: MemoryRegion,
    ) -> Iterator[tuple[bytes, int]]:
        """Read a region in 4MB chunks, yielding (data, base_offset)."""
        _CHUNK = 4 * 1024 * 1024
        _OVERLAP = 256  # overlap to catch patterns at chunk boundaries
        pos = 0
        while pos < region.size:
            end = min(pos + _CHUNK, region.size)
            chunk = scanner.read(region.base + pos, end - pos)
            if chunk is not None:
                yield chunk, pos
            if end < region.size:
                pos = end - _OVERLAP
            else:
                pos = end

    @staticmethod
    def _find_all(data: bytes, pattern: bytes) -> Iterator[int]:
        """Find all occurrences of pattern in data, yielding start offsets."""
        idx = 0
        while True:
            idx = data.find(pattern, idx)
            if idx == -1:
                break
            yield idx
            idx += 1

    def _extract_candidates(
        self,
        chunk_data: bytes,
        match_offset: int,
        scanner: WindowsMemoryScanner,
        region: MemoryRegion,
    ) -> Iterator[tuple[bytes, str, int]]:
        """Extract candidate keys from a single pattern match."""
        # Strategy 1: Pointer dereference at various offsets
        for off in PTR_OFFSETS:
            ptr_pos = match_offset + off
            if ptr_pos < 0 or ptr_pos + 8 > len(chunk_data):
                continue
            try:
                (ptr_val,) = struct.unpack_from("<Q", chunk_data, ptr_pos)
            except struct.error:
                continue
            if not (MIN_PTR < ptr_val < MAX_PTR):
                continue
            key = scanner.read(ptr_val, SQLCIPHER_KEY_SIZE)
            if key is not None and len(key) == SQLCIPHER_KEY_SIZE:
                if _is_likely_key(key):
                    yield key, f"ptr@{off}", off

        # Strategy 2: Inline 32-byte reads at various offsets
        for off in INLINE_OFFSETS:
            key_pos = match_offset + off
            if key_pos < 0 or key_pos + SQLCIPHER_KEY_SIZE > len(chunk_data):
                continue
            key = chunk_data[key_pos : key_pos + SQLCIPHER_KEY_SIZE]
            if len(key) == SQLCIPHER_KEY_SIZE and _is_likely_key(key):
                yield key, f"inline@{off}", off


@dataclass(slots=True)
class _AllRegionScanner:
    """Wrapper around WindowsMemoryScanner that iterates ALL RW regions.

    Unlike the default iter_regions() which filters to MEM_PRIVATE,
    this includes MEM_MAPPED regions (DLL .data sections).
    """

    _scanner: WindowsMemoryScanner

    def iter_rw_regions(self) -> Iterator[MemoryRegion]:
        """Yield all committed RW regions (any type, any size >= 64KB)."""
        return self._scanner.iter_rw_all()

    def read(self, addr: int, size: int) -> bytes | None:
        return self._scanner.read(addr, size)

    def close(self) -> None:
        self._scanner.close()

    def __enter__(self) -> _AllRegionScanner:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def _open_scanner_all_regions(pid: int) -> _AllRegionScanner:
    """Open a scanner that includes MEM_MAPPED regions."""
    scanner = WindowsMemoryScanner(pid)
    return _AllRegionScanner(_scanner=scanner)
