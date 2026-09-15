"""Common helpers shared between v3 and v4 memory extractors."""

from __future__ import annotations

import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from wc_chat_reader.core.constants import SQLCIPHER_KEY_SIZE, WeChatVersion
from wc_chat_reader.core.exceptions import (
    KeyExtractionError,
    NoValidKeyError,
)
from wc_chat_reader.core.logger import get_logger
from wc_chat_reader.key.base import KeyExtractor, KeyResult
from wc_chat_reader.key.memory_scanner import WindowsMemoryScanner, open_scanner
from wc_chat_reader.key.validator import KeyValidator

if TYPE_CHECKING:
    from collections.abc import Iterator

    from wc_chat_reader.wechat.process_detector import WeChatProcess

logger = get_logger(__name__)

MIN_PTR = 0x10000
MAX_PTR = 0x7FFFFFFFFFFF


@dataclass(slots=True, frozen=True)
class _ExtractParams:
    """Version-specific search parameters."""

    version: WeChatVersion
    pattern: bytes  # Byte pattern indicating "adjacent memory holds a key pointer"
    ptr_size: int = 8  # 64-bit


class _BaseMemoryExtractor(KeyExtractor):
    """Windows memory-scan extractor. Concrete v3/v4 subclasses set parameters."""

    _params: _ExtractParams

    def supports(self, process: WeChatProcess) -> bool:
        return sys.platform == "win32" and process.version == self._params.version

    def unsupported_reason(self, process: WeChatProcess) -> str | None:
        if sys.platform != "win32":
            return "memory scanning requires Windows"
        if process.version != self._params.version:
            return (
                f"process version is {process.version.name}, "
                f"expected {self._params.version.name}"
            )
        return None

    def extract(
        self,
        process: WeChatProcess,
        sample_db_path: Path | None = None,
    ) -> KeyResult:
        db_path = sample_db_path or _find_sample_db(process, self._params.version)
        if db_path is None:
            raise KeyExtractionError(
                f"No sample database found for validation (pid={process.pid}). "
                f"WeChat may not be fully logged in yet."
            )

        validator = KeyValidator(db_path, self._params.version)
        candidates_scanned = 0

        logger.info(
            f"{self.name}: starting memory scan "
            f"(pid={process.pid}, pattern={self._params.pattern.hex()}, "
            f"sample_db={db_path})"
        )
        with open_scanner(process.pid) as scanner:
            for candidate in self._iter_candidates(scanner):
                candidates_scanned += 1
                if validator.validate(candidate):
                    logger.info(
                        f"{self.name}: valid key found after "
                        f"{candidates_scanned} candidate(s)"
                    )
                    return KeyResult(
                        key=candidate,
                        strategy=self.name,
                        candidates_scanned=candidates_scanned,
                        meta={"db_path": str(db_path)},
                    )

        raise NoValidKeyError(
            f"{self.name}: scanned {candidates_scanned} candidate(s), "
            f"none validated against {db_path}"
        )

    def _iter_candidates(
        self, scanner: WindowsMemoryScanner
    ) -> Iterator[bytes]:
        """Yield 32-byte candidate keys extracted from process memory.

        Three optimisations over the naive full-address-space scan:

        1. **Chunked reads** — instead of pulling an entire region (which can
           be hundreds of MB) into memory at once, we read it in 4 MB chunks.
           This keeps memory pressure low and lets us bail out early once the
           total I/O budget is exhausted.
        2. **RW-first ordering** — heap regions (PAGE_READWRITE /
           PAGE_WRITECOPY) are where the AES key lives; executable regions
           almost never contain it.  Scanning RW regions first finds the key
           sooner in the common case.
        3. **I/O budget cap** — we stop after reading ~512 MB total, which
           covers every realistic WeChat heap while preventing a runaway scan
           on pathological address spaces.
        """
        pattern = self._params.pattern
        ptr_size = self._params.ptr_size

        # --- Tunables --------------------------------------------------
        _CHUNK = 4 * 1024 * 1024          # 4 MB per ReadProcessMemory call
        _OVERLAP = max(256, len(pattern)) # overlap so patterns straddling
                                          # chunk boundaries are not missed
        _MAX_BYTES = 512 * 1024 * 1024    # 512 MB total I/O budget
        # ----------------------------------------------------------------

        # Collect regions and partition by protection: RW/WC first (heap),
        # then everything else.  VirtualQueryEx is cheap; the real cost is
        # ReadProcessMemory, which we cap via _MAX_BYTES below.
        rw_regions: list = []
        other_regions: list = []
        for region in scanner.iter_regions(min_size=1024 * 1024):
            if region.protect & (0x04 | 0x08):  # RW or WRITECOPY
                rw_regions.append(region)
            else:
                other_regions.append(region)

        total_read = 0

        def _scan_chunk(data: bytes, offset_in_region: int) -> Iterator[bytes]:
            """Scan one chunk's worth of data, yielding candidate keys."""
            nonlocal total_read
            total_read += len(data)
            idx = len(data)
            while True:
                idx = data.rfind(pattern, 0, idx)
                if idx == -1 or idx - ptr_size < 0:
                    break
                (ptr,) = struct.unpack_from("<Q", data, idx - ptr_size)
                if MIN_PTR < ptr < MAX_PTR:
                    key = scanner.read(ptr, SQLCIPHER_KEY_SIZE)
                    if key is not None and len(key) == SQLCIPHER_KEY_SIZE:
                        yield key
                idx -= 1

        logger.debug(
            f"{self.name}: {len(rw_regions)} RW region(s), "
            f"{len(other_regions)} other region(s)"
            f"{', rw_only=True' if getattr(self, '_rw_only', False) else ''}"
        )
        # V4 keys live exclusively in heap (RW) regions.  Scanning executable
        # or read-only regions wastes time and produces false-positive pattern
        # matches that don't validate.  Skip them entirely.
        scan_regions = rw_regions if getattr(self, '_rw_only', False) else (*rw_regions, *other_regions)
        for region in scan_regions:
            if total_read >= _MAX_BYTES:
                logger.debug(
                    f"{self.name}: I/O budget exhausted "
                    f"({total_read / 1024 / 1024:.0f} MB read)"
                )
                return
            pos = 0
            while pos < region.size:
                if total_read >= _MAX_BYTES:
                    return
                end = min(pos + _CHUNK, region.size)
                chunk = scanner.read(region.base + pos, end - pos)
                if chunk is None:
                    pos = end
                    continue
                yield from _scan_chunk(chunk, pos)
                # Advance by (chunk - overlap) so the next read covers the
                # tail of this chunk, catching patterns that straddle the
                # boundary.  On the last chunk just finish the region.
                if end < region.size:
                    pos = end - _OVERLAP
                else:
                    pos = end

    @staticmethod
    def _scan_region(
        scanner: WindowsMemoryScanner,
        data: bytes,
        pattern: bytes,
        ptr_size: int,
    ) -> Iterator[bytes]:
        """Scan a single region backwards for the pattern.

        The pattern is placed *after* the key pointer in memory, so we look
        backwards ``ptr_size`` bytes from each match to read the pointer.
        """
        idx = len(data)
        while True:
            idx = data.rfind(pattern, 0, idx)
            if idx == -1 or idx - ptr_size < 0:
                break
            (ptr,) = struct.unpack_from("<Q", data, idx - ptr_size)
            if MIN_PTR < ptr < MAX_PTR:
                key = scanner.read(ptr, SQLCIPHER_KEY_SIZE)
                if key is not None and len(key) == SQLCIPHER_KEY_SIZE:
                    yield key
            idx -= 1


def _find_sample_db(
    process: WeChatProcess, version: WeChatVersion
) -> Path | None:
    """Locate a sample encrypted database file inside the user's data dir."""
    if process.data_dir is None:
        return None

    if version == WeChatVersion.V3:
        preferred = ("MicroMsg.db", "MSG0.db")
    elif version == WeChatVersion.V4:
        preferred = ("session.db", "message_0.db", "contact.db")
    else:
        preferred = ()

    for name in preferred:
        for p in process.data_dir.rglob(name):
            try:
                if p.is_file() and p.stat().st_size > 4096:
                    return p
            except OSError:
                continue

    # Fallback: walk the data_dir looking for any .db file large enough.
    for p in process.data_dir.rglob("*.db"):
        try:
            if p.is_file() and p.stat().st_size > 4096:
                return p
        except OSError:
            continue
    return None
