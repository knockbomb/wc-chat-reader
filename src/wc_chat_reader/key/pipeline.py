"""Extraction pipeline that runs available strategies in priority order.

The pipeline embodies the "adaptability first" design:

- Multiple strategies are tried until one succeeds.
- Strategies are ordered by priority; fast/specific ones run first.
- The order is dynamically re-arranged per-process so that version-matching
  extractors always run before generic fallbacks.
- Users can inject their own extractors (e.g., updated pattern for a new
  WeChat build) without modifying library code.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from wc_chat_reader.core.exceptions import (
    KeyExtractionError,
    NoValidKeyError,
)
from wc_chat_reader.core.logger import get_logger
from wc_chat_reader.key.frida_extractor import FridaExtractor
from wc_chat_reader.key.v3_extractor import V3MemoryExtractor
from wc_chat_reader.key.v4_codec_extractor import V4CodecExtractor
from wc_chat_reader.key.v4_extractor import V4MemoryExtractor

if TYPE_CHECKING:
    from pathlib import Path

    from wc_chat_reader.key.base import KeyExtractor, KeyResult
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


def _version_sort_key(
    extractor: KeyExtractor, process: WeChatProcess
) -> tuple[int, int]:
    """Sort key: version-matching extractors first, then by declared priority.

    Returns ``(match, priority)`` where *match* is 0 for extractors that
    support this process and 1 for those that don't.  Python's stable sort
    keeps the original priority order within each group.
    """
    match = 0 if extractor.supports(process) else 1
    return (match, extractor.priority)


@dataclass(slots=True)
class ExtractionPipeline:
    """Ordered collection of extractors."""

    extractors: list[KeyExtractor] = field(default_factory=list)

    @classmethod
    def default(cls) -> ExtractionPipeline:
        """Return the pipeline built from the shipped extractors."""
        return cls(
            extractors=sorted(
                [
                    V3MemoryExtractor(),
                    V4MemoryExtractor(),
                    V4CodecExtractor(auto_trigger=True),
                    FridaExtractor(auto_trigger=True),
                ],
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

        # Dynamically reorder: version-matching extractors run first, then
        # fallbacks.  Within each group the original priority is preserved.
        ordered = sorted(self.extractors, key=lambda e: _version_sort_key(e, process))

        logger.info(
            f"ExtractionPipeline: {len(self.extractors)} extractor(s), "
            f"process version={process.version.name} "
            f"(pid={process.pid}, version_str={process.version_str!r})"
        )
        for idx, extractor in enumerate(ordered, 1):
            reason = extractor.unsupported_reason(process)
            if reason is not None or not extractor.supports(process):
                if reason is None:
                    reason = "not applicable to this process"
                logger.info(
                    f"  [{idx}/{len(ordered)}] {extractor.name}: "
                    f"skipped ({reason})"
                )
                skipped.append(f"{extractor.name}: {reason}")
                continue
            logger.info(f"  [{idx}/{len(ordered)}] Trying {extractor.name}...")
            t0 = time.monotonic()
            try:
                result = extractor.extract(process, sample)
                elapsed = time.monotonic() - t0
                logger.info(
                    f"  ✓ {extractor.name} succeeded in {elapsed:.1f}s "
                    f"(strategy={result.strategy})"
                )
                return result
            except (KeyExtractionError, NoValidKeyError) as exc:
                elapsed = time.monotonic() - t0
                logger.warning(
                    f"  ✗ {extractor.name} failed after {elapsed:.1f}s: {exc}"
                )
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
    """Run the default pipeline, preferring a locally cached key.

    The cache provides an instant "open-and-go" result on subsequent runs
    for the same WeChat version + data directory, avoiding a repeat of the
    slow in-memory scan or an extra Frida attach. The cache only accelerates
    the lookup; the authoritative source stays the live pipeline, which
    re-validates the captured key against a real database page before we
    ever persist it.
    """
    from wc_chat_reader.key.key_cache import CachedKey, KeyCache

    cache = KeyCache()
    cached = cache.get(process.version_str, process.data_dir)
    if cached is not None:
        logger.info(f"extract_key: cache hit (strategy={cached.strategy})")
        return KeyResult(
            key=cached.key,
            strategy=f"{cached.strategy}(cached)",
            meta={"cached": "true", "captured_at": str(cached.captured_at)},
        )

    result = ExtractionPipeline.default().run(process, sample_db_path)

    if process.data_dir:
        from wc_chat_reader.key.key_cache import _fingerprint

        cache.put(
            CachedKey(
                key=result.key,
                version_str=process.version_str,
                data_dir_fingerprint=_fingerprint(process.data_dir),
                strategy=result.strategy,
            )
        )
    return result
