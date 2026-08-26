"""Extraction pipeline that runs available strategies in priority order.

The pipeline embodies the "adaptability first" design:

- Multiple strategies are tried until one succeeds.
- Strategies are ordered by priority; fast/specific ones run first.
- Users can inject their own extractors (e.g., updated pattern for a new
  WeChat build) without modifying library code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from wc_chat_reader.core.exceptions import (
    KeyExtractionError,
    NoValidKeyError,
)
from wc_chat_reader.core.logger import get_logger
from wc_chat_reader.key.base import KeyExtractor, KeyResult
from wc_chat_reader.key.frida_extractor import FridaExtractor
from wc_chat_reader.key.v3_extractor import V3MemoryExtractor
from wc_chat_reader.key.v4_extractor import V4MemoryExtractor

if TYPE_CHECKING:
    from wc_chat_reader.wechat.process_detector import WeChatProcess

logger = get_logger(__name__)


@dataclass(slots=True)
class ExtractionPipeline:
    """Ordered collection of extractors."""

    extractors: list[KeyExtractor] = field(default_factory=list)

    @classmethod
    def default(cls) -> ExtractionPipeline:
        """Return the pipeline built from the shipped extractors."""
        return cls(
            extractors=sorted(
                [V3MemoryExtractor(), V4MemoryExtractor(), FridaExtractor()],
                key=lambda e: e.priority,
            )
        )

    def register(self, extractor: KeyExtractor) -> None:
        self.extractors.append(extractor)
        self.extractors.sort(key=lambda e: e.priority)

    def run(
        self,
        process: WeChatProcess,
        sample_db_path: Path | None = None,
    ) -> KeyResult:
        errors: list[str] = []
        for extractor in self.extractors:
            if not extractor.supports(process):
                logger.debug(f"{extractor.name}: unsupported for this process")
                continue
            logger.info(f"Trying {extractor.name}...")
            try:
                return extractor.extract(process, sample_db_path)
            except (KeyExtractionError, NoValidKeyError) as exc:
                logger.warning(f"{extractor.name} failed: {exc}")
                errors.append(f"{extractor.name}: {exc}")
        raise KeyExtractionError(
            "All extractors failed:\n  - " + "\n  - ".join(errors)
        )


def extract_key(
    process: WeChatProcess,
    sample_db_path: Path | None = None,
) -> KeyResult:
    """Convenience entry point: run the default pipeline."""
    return ExtractionPipeline.default().run(process, sample_db_path)
