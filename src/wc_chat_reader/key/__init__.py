"""Multi-strategy WeChat database key extraction.

Layered design so that when WeChat updates and one strategy breaks, another
still works:

- ``base.KeyExtractor`` — abstract interface every strategy implements.
- ``memory_scanner`` — scans a running process's memory for candidate keys.
- ``v3_extractor`` / ``v4_extractor`` — version-specific pattern matchers.
- ``frida_extractor`` — hooks the SQLCipher ``sqlite3_key`` API directly, the
  most resilient fallback because it targets the algorithm, not layout.
- ``validator`` — cryptographic validation against a real database page.
- ``pipeline`` — orchestrates the strategies in priority order.
"""

from wc_chat_reader.key.base import KeyCandidate, KeyExtractor, KeyResult
from wc_chat_reader.key.pipeline import ExtractionPipeline, extract_key
from wc_chat_reader.key.validator import KeyValidator

__all__ = [
    "ExtractionPipeline",
    "KeyCandidate",
    "KeyExtractor",
    "KeyResult",
    "KeyValidator",
    "extract_key",
]
