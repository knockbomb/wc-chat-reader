"""Unit tests for the key validator."""

from __future__ import annotations

import pytest

from wc_chat_reader.core.constants import WeChatVersion
from wc_chat_reader.key.validator import KeyValidator


@pytest.mark.unit
class TestKeyValidator:
    def test_valid_key_accepted_v3(self, tmp_encrypted_db_factory):
        db_path, key = tmp_encrypted_db_factory(WeChatVersion.V3)
        assert KeyValidator(db_path, WeChatVersion.V3).validate(key) is True

    def test_wrong_key_rejected_v3(self, tmp_encrypted_db_factory):
        db_path, _ = tmp_encrypted_db_factory(WeChatVersion.V3)
        assert KeyValidator(db_path, WeChatVersion.V3).validate(b"\x00" * 32) is False

    def test_valid_key_accepted_v4(self, tmp_encrypted_db_factory):
        db_path, key = tmp_encrypted_db_factory(WeChatVersion.V4)
        assert KeyValidator(db_path, WeChatVersion.V4).validate(key) is True

    def test_wrong_length_rejected(self, tmp_encrypted_db_factory):
        db_path, _ = tmp_encrypted_db_factory(WeChatVersion.V3)
        assert KeyValidator(db_path, WeChatVersion.V3).validate(b"\x01" * 16) is False
