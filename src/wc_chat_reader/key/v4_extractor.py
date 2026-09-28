"""WeChat 4.0 key extractor (Windows).

Runtime key struct layout (verified on WeChat 4.1.15.13)::

    [key_ptr (8B)] [flags=0 (8B)] [key_size=32 (8B)] [...]

The relaxed 16-byte pattern ``[0, 32]`` matches the runtime struct in
writable heap memory.  The AES-256 key pointer is 8 bytes before the
pattern start (``ptr@-8``, handled by ``_BaseMemoryExtractor``).

The full 24-byte pattern ``[0, 32, 47]`` is a compile-time constant in
Weixin.dll's .rdata — it does NOT appear in the runtime heap struct.
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
        # Relaxed pattern: [0, 32] — matches runtime heap struct.
        # Key pointer is at idx - ptr_size (= -8 bytes before pattern).
        pattern=bytes(
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        ),
        ptr_size=8,
    )
