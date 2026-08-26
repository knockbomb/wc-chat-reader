"""Abstract interface for key extraction strategies."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from wc_chat_reader.wechat.process_detector import WeChatProcess


@dataclass(slots=True, frozen=True)
class KeyCandidate:
    """A candidate key found during scanning, not yet validated."""

    key: bytes
    source: str  # e.g., "memory@0x7ffabcd0" or "frida:sqlite3_key"

    def hex(self) -> str:
        return self.key.hex()


@dataclass(slots=True, frozen=True)
class KeyResult:
    """A validated key together with the strategy that produced it."""

    key: bytes
    strategy: str
    candidates_scanned: int = 0
    meta: dict[str, str] = field(default_factory=dict)

    def hex(self) -> str:
        return self.key.hex()


class KeyExtractor(ABC):
    """Abstract base class every extraction strategy implements."""

    #: Human-readable name shown in logs and error messages.
    name: str = "unknown"

    #: Priority — lower runs first. Fast+specific strategies have low numbers.
    priority: int = 100

    @abstractmethod
    def supports(self, process: WeChatProcess) -> bool:
        """Return True if this strategy applies to the given process."""

    @abstractmethod
    def extract(
        self,
        process: WeChatProcess,
        sample_db_path: Path | None = None,
    ) -> KeyResult:
        """Extract a validated key or raise ``KeyExtractionError``.

        ``sample_db_path`` is used by the validator to confirm the key works;
        if omitted, the extractor must locate a sample database on its own.
        """
