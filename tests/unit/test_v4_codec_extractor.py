"""Unit tests for the Frida codec-hook extractor (signature routing only).

The actual Frida attach requires a real elevated WeChat process, which we
cannot do in CI / unit tests. We therefore unit-test the pure version-routing
logic and the extractor's supports() gating, and rely on the integration test
for the live attach.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from wc_chat_reader.key.v4_codec_extractor import (
    V4CodecExtractor,
    _choose_signature,
    _parse_version,
)


@pytest.mark.unit
class TestParseVersion:
    def test_standard(self):
        assert _parse_version("4.1.13.12") == (4, 1, 13, 12)

    def test_single_digit(self):
        assert _parse_version("4.0.3") == (4, 0, 3, 0)


@pytest.mark.unit
class TestChooseSignature:
    def test_supported_v4_latest(self):
        sig = _choose_signature("4.1.13.12")
        assert sig is not None
        assert sig.hook_offset == -3
        assert "24 50 48" in sig.pattern

    def test_supported_boundary_lowest(self):
        sig = _choose_signature("4.1.6.15")
        assert sig is not None

    def test_unsupported_below_v4(self):
        assert _choose_signature("3.9.0.0") is None

    def test_unsupported_earlier_v4(self):
        assert _choose_signature("4.0.1.0") is None


@pytest.mark.unit
class TestV4CodecExtractorGating:
    def test_supports_matching_version(self):
        ex = V4CodecExtractor()
        assert ex.supports(_fake_process("4.1.13.12")) is True

    def test_unsupported_reason_low_version(self):
        ex = V4CodecExtractor()
        reason = ex.unsupported_reason(_fake_process("3.9.0.0"))
        assert reason is not None

    def test_none_process_raises(self):
        # The pipeline always passes a real process; None is a misuse and must
        # fail loudly rather than silently return a wrong answer.
        ex = V4CodecExtractor()
        with pytest.raises(AttributeError):
            ex.supports(None)


def _fake_process(version_str: str):
    """Minimal stand-in exposing the fields the extractor queries."""
    from types import SimpleNamespace

    from wc_chat_reader.core.constants import WeChatVersion

    version = (
        WeChatVersion.V4
        if version_str.startswith("4.")
        else WeChatVersion.V3
        if version_str.startswith("3.")
        else WeChatVersion.UNKNOWN
    )
    return SimpleNamespace(
        pid=1234,
        version=version,
        version_str=version_str,
        data_dir=Path("C:/fake/xwechat_files"),
        exe_path="C:/Program Files/Tencent/Weixin/Weixin.exe",
    )