"""WeChat 3.x key extractor (Windows).

Searches WeChatWin.dll's writable memory for the pattern that indicates
an adjacent 32-byte AES key pointer.
"""

from __future__ import annotations

from wc_chat_reader.core.constants import WeChatVersion
from wc_chat_reader.key._memory_base import _BaseMemoryExtractor, _ExtractParams


class V3MemoryExtractor(_BaseMemoryExtractor):
    """WeChat 3.x memory-scan extractor."""

    name = "v3-memory-scan"
    priority = 10

    _params = _ExtractParams(
        version=WeChatVersion.V3,
        # v3 pattern: 0x20 0 0 0 0 0 0 0 — key length field followed by 7 zeros.
        pattern=bytes([0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        ptr_size=8,
    )
