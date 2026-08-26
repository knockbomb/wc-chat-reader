"""Content parsers for individual message types.

Each parser transforms raw ``content`` (usually a string, sometimes XML or
JSON) into a dict of structured fields, which lives on ``Message.parsed``.

Adding support for a new message type = writing one function and registering
it in ``_REGISTRY``.
"""

from __future__ import annotations

import re
from typing import Callable

from wc_chat_reader.core.constants import MessageType
from wc_chat_reader.core.logger import get_logger

logger = get_logger(__name__)


def _parse_text(content: str) -> dict[str, object]:
    return {"text": content}


def _parse_image(content: str) -> dict[str, object]:
    # WeChat image messages typically embed an <img /> XML with md5/aeskey.
    md5_match = re.search(r'md5\s*=\s*"([^"]+)"', content)
    length_match = re.search(r'length\s*=\s*"([^"]+)"', content)
    return {
        "kind": "image",
        "md5": md5_match.group(1) if md5_match else "",
        "length": int(length_match.group(1)) if length_match else 0,
    }


def _parse_voice(content: str) -> dict[str, object]:
    duration = re.search(r'voicelength\s*=\s*"(\d+)"', content)
    return {
        "kind": "voice",
        "duration_ms": int(duration.group(1)) if duration else 0,
    }


def _parse_video(content: str) -> dict[str, object]:
    playlen = re.search(r'playlength\s*=\s*"(\d+)"', content)
    md5 = re.search(r'md5\s*=\s*"([^"]+)"', content)
    return {
        "kind": "video",
        "duration_s": int(playlen.group(1)) if playlen else 0,
        "md5": md5.group(1) if md5 else "",
    }


def _parse_app(content: str) -> dict[str, object]:
    # App message: <appmsg><type>N</type>...</appmsg>
    type_match = re.search(r"<type>(\d+)</type>", content)
    title_match = re.search(r"<title>([^<]+)</title>", content)
    des_match = re.search(r"<des>([^<]+)</des>", content)
    url_match = re.search(r"<url>([^<]+)</url>", content)
    return {
        "kind": "app",
        "app_type": int(type_match.group(1)) if type_match else 0,
        "title": title_match.group(1) if title_match else "",
        "description": des_match.group(1) if des_match else "",
        "url": url_match.group(1) if url_match else "",
    }


def _parse_system(content: str) -> dict[str, object]:
    return {"kind": "system", "text": _strip_xml(content)}


def _strip_xml(s: str) -> str:
    """Best-effort strip of XML tags to produce a readable summary."""
    return re.sub(r"<[^>]+>", "", s).strip()


_Parser = Callable[[str], dict[str, object]]

_REGISTRY: dict[int, _Parser] = {
    MessageType.TEXT: _parse_text,
    MessageType.IMAGE: _parse_image,
    MessageType.VOICE: _parse_voice,
    MessageType.VIDEO: _parse_video,
    MessageType.APP: _parse_app,
    MessageType.SYSTEM: _parse_system,
}


def parse_content(message_type: int, content: str) -> dict[str, object]:
    """Dispatch to the registered parser or return a raw fallback."""
    parser = _REGISTRY.get(message_type)
    if parser is None:
        return {"kind": "unknown", "raw": content}
    try:
        return parser(content or "")
    except Exception as exc:  # noqa: BLE001 - parsing must never crash the query
        logger.debug(f"Parser for type={message_type} failed: {exc}")
        return {"kind": "parse_error", "error": str(exc), "raw": content}


def register_parser(message_type: int, parser: _Parser) -> None:
    """Register or override a parser for a message type."""
    _REGISTRY[message_type] = parser
