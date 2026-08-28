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


def _resolve_sample_db(process: WeChatProcess, version: object) -> Path | None:
    """Locate a sample encrypted DB for validators that need one (Frida)."""
    # Deferred imports avoid a cycle: _memory_base imports scanner/validator,
    # which do not depend on the pipeline, so this stays cheap and safe.
    from wc_chat_reader.core.constants import (  # noqa: PLC0415
        WeChatVersion,
    )
    from wc_chat_reader.key._memory_base import (  # noqa: PLC0415
        _find_sample_db,
    )

    if isinstance(version, WeChatVersion):
        return _find_sample_db(process, version)
    return None


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
        skipped: list[str] = []
        # Resolve the sample DB once so every extractor (notably Frida, which
        # cannot infer it on its own) shares the same validation target.
        sample = sample_db_path or _resolve_sample_db(process, process.version)
        for extractor in self.extractors:
            reason = extractor.unsupported_reason(process)
            if reason is not None or not extractor.supports(process):
                if reason is None:
                    reason = "not applicable to this process"
                logger.debug(f"{extractor.name}: skipped ({reason})")
                skipped.append(f"{extractor.name}: {reason}")
                continue
            logger.info(f"Trying {extractor.name}...")
            try:
                return extractor.extract(process, sample)
            except (KeyExtractionError, NoValidKeyError) as exc:
                logger.warning(f"{extractor.name} failed: {exc}")
                errors.append(f"{extractor.name}: {exc}")
        if errors:
            raise KeyExtractionError(
                "All extractors failed:\n  - " + "\n  - ".join(errors)
            )
        raise KeyExtractionError(
            "No extractor supports this WeChat process "
            f"(version={process.version.name}, pid={process.pid}):\n  - "
            + "\n  - ".join(skipped)
        )


def extract_key(
    process: WeChatProcess,
    sample_db_path: Path | None = None,
) -> KeyResult:
    """Convenience entry point: run the default pipeline."""
    return ExtractionPipeline.default().run(process, sample_db_path)
