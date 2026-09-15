"""WeChat 4.0 key extractor (Windows).

WeChat 4.0 changed memory layout — the AES key pointer is now identifiable
by a 24-byte pattern (three 8-byte little-endian values). This matches the
constant pattern used by chatlog v4 extractor.
"""

from __future__ import annotations

from wc_chat_reader.core.constants import WeChatVersion
from wc_chat_reader.key._memory_base import _BaseMemoryExtractor, _ExtractParams


class V4MemoryExtractor(_BaseMemoryExtractor):
    """WeChat 4.0 memory-scan extractor."""

    name = "v4-memory-scan"
    priority = 10
    _rw_only = True  # V4 keys are always in heap; skip non-RW regions.

    _params = _ExtractParams(
        version=WeChatVersion.V4,
        # v4 pattern (from chatlog): three little-endian 64-bit values —
        # 0x00, 0x20 (key size = 32), 0x2F.
        pattern=bytes(
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x2F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        ),
        ptr_size=8,
    )
