"""Common helpers shared between v3 and v4 memory extractors."""

from __future__ import annotations

import struct
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
        import sys as _sys
        return _sys.platform == "win32" and process.version == self._params.version

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
        """Yield 32-byte candidate keys extracted from process memory."""
        pattern = self._params.pattern
        ptr_size = self._params.ptr_size
        for region in scanner.iter_regions(min_size=1024 * 1024):
            data = scanner.read(region.base, region.size)
            if data is None:
                continue
            yield from self._scan_region(scanner, data, pattern, ptr_size)

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
