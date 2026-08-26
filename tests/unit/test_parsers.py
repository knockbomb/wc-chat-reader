"""Unit tests for message content parsers."""

from __future__ import annotations

import pytest

from wc_chat_reader.core.constants import MessageType
from wc_chat_reader.db.parsers import parse_content


@pytest.mark.unit
def test_text_message_parsed():
    parsed = parse_content(MessageType.TEXT, "hello")
    assert parsed == {"text": "hello"}


@pytest.mark.unit
def test_image_message_md5_extracted():
    xml = '<img md5="abc123" length="4096" />'
    parsed = parse_content(MessageType.IMAGE, xml)
    assert parsed["kind"] == "image"
    assert parsed["md5"] == "abc123"
    assert parsed["length"] == 4096


@pytest.mark.unit
def test_voice_duration_parsed():
    xml = '<voicemsg voicelength="3500" />'
    parsed = parse_content(MessageType.VOICE, xml)
    assert parsed["duration_ms"] == 3500


@pytest.mark.unit
def test_app_message_fields():
    xml = "<appmsg><type>5</type><title>hi</title><des>there</des><url>http://x</url></appmsg>"
    parsed = parse_content(MessageType.APP, xml)
    assert parsed["app_type"] == 5
    assert parsed["title"] == "hi"
    assert parsed["url"] == "http://x"


@pytest.mark.unit
def test_unknown_type_returns_raw():
    parsed = parse_content(999, "raw content")
    assert parsed == {"kind": "unknown", "raw": "raw content"}


@pytest.mark.unit
def test_parser_never_raises():
    # Broken payloads should return a parse_error dict, not crash.
    parsed = parse_content(MessageType.IMAGE, "\x00\x01 not xml")
    assert parsed["kind"] in {"image", "parse_error"}
