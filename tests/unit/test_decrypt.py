"""Unit tests for the SQLCipher decryption round-trip.

The fixture builds a synthetic encrypted page, we decrypt it, and check that
the SQLite header shows up at the start of the decrypted output.
"""

from __future__ import annotations

import io

import pytest

from wc_chat_reader.core.constants import SQLITE_HEADER_MAGIC, WeChatVersion
from wc_chat_reader.core.exceptions import HMACMismatchError, InvalidKeyError
from wc_chat_reader.decrypt import V3Decryptor, V4Decryptor


@pytest.mark.unit
class TestV3Decryptor:
    def test_decrypts_synthetic_db(self, tmp_encrypted_db_factory):
        db_path, key = tmp_encrypted_db_factory(WeChatVersion.V3)
        out = io.BytesIO()
        with db_path.open("rb") as src:
            pages = V3Decryptor().decrypt(key, src, out)
        assert pages == 2
        assert out.getvalue().startswith(SQLITE_HEADER_MAGIC)

    def test_wrong_key_raises_hmac(self, tmp_encrypted_db_factory):
        db_path, _ = tmp_encrypted_db_factory(WeChatVersion.V3)
        wrong_key = b"\x00" * 32
        out = io.BytesIO()
        with db_path.open("rb") as src, pytest.raises(HMACMismatchError):
            V3Decryptor().decrypt(wrong_key, src, out)

    def test_short_key_raises(self):
        with pytest.raises(InvalidKeyError):
            V3Decryptor().decrypt(b"short", io.BytesIO(b"x" * 4096), io.BytesIO())


@pytest.mark.unit
class TestV4Decryptor:
    def test_decrypts_synthetic_db(self, tmp_encrypted_db_factory):
        db_path, key = tmp_encrypted_db_factory(WeChatVersion.V4)
        out = io.BytesIO()
        with db_path.open("rb") as src:
            pages = V4Decryptor().decrypt(key, src, out)
        assert pages == 2
        assert out.getvalue().startswith(SQLITE_HEADER_MAGIC)

    def test_v3_key_fails_v4_db(self, tmp_encrypted_db_factory):
        db_path, key = tmp_encrypted_db_factory(WeChatVersion.V4)
        out = io.BytesIO()
        with db_path.open("rb") as src, pytest.raises(HMACMismatchError):
            # v3 decryptor with v4 db → PBKDF2 hash mismatch → HMAC fails
            V3Decryptor().decrypt(key, src, out)
