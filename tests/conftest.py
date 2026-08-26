"""Shared pytest fixtures.

Focus: tests must run without a real WeChat process. We build a synthetic
SQLCipher database in-memory (v3 or v4) so encrypt/decrypt round-trips can
be verified end-to-end.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterator

import pytest
from Crypto.Cipher import AES
from Crypto.Hash import SHA1, SHA512, HMAC
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

from wc_chat_reader.core.constants import (
    SQLCIPHER_HMAC_SHA1_SIZE,
    SQLCIPHER_HMAC_SHA512_SIZE,
    SQLCIPHER_IV_SIZE,
    SQLCIPHER_KEY_SIZE,
    SQLCIPHER_MAC_SALT_XOR,
    SQLCIPHER_PAGE_SIZE,
    SQLCIPHER_SALT_SIZE,
    SQLCIPHER_V3_ITERATIONS,
    SQLCIPHER_V4_ITERATIONS,
    SQLITE_HEADER_MAGIC,
    WeChatVersion,
)


def _reserve(needed: int) -> int:
    block = AES.block_size
    return needed if needed % block == 0 else ((needed // block) + 1) * block


def build_encrypted_page(
    key: bytes,
    version: WeChatVersion,
    plaintext_body: bytes,
    page_no: int,
    salt: bytes | None = None,
) -> tuple[bytes, bytes]:
    """Return ``(page_bytes, salt)`` for a single encrypted SQLCipher page."""
    if version == WeChatVersion.V3:
        iterations = SQLCIPHER_V3_ITERATIONS
        hmac_size = SQLCIPHER_HMAC_SHA1_SIZE
        hash_mod = SHA1
    else:
        iterations = SQLCIPHER_V4_ITERATIONS
        hmac_size = SQLCIPHER_HMAC_SHA512_SIZE
        hash_mod = SHA512

    salt = salt or get_random_bytes(SQLCIPHER_SALT_SIZE)
    reserve = _reserve(SQLCIPHER_IV_SIZE + hmac_size)
    body_size = SQLCIPHER_PAGE_SIZE - (SQLCIPHER_SALT_SIZE if page_no == 1 else 0) - reserve
    if len(plaintext_body) != body_size:
        # Pad or truncate to fit the page body slot.
        plaintext_body = plaintext_body[:body_size].ljust(body_size, b"\x00")

    enc_key = PBKDF2(key, salt, dkLen=SQLCIPHER_KEY_SIZE, count=iterations, hmac_hash_module=hash_mod)
    mac_salt = bytes(b ^ SQLCIPHER_MAC_SALT_XOR for b in salt)
    mac_key = PBKDF2(enc_key, mac_salt, dkLen=SQLCIPHER_KEY_SIZE, count=2, hmac_hash_module=hash_mod)

    iv = get_random_bytes(SQLCIPHER_IV_SIZE)
    cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext_body)

    h = HMAC.new(mac_key, digestmod=hash_mod)
    h.update(ciphertext)
    h.update(iv)
    h.update(struct.pack("<I", page_no))
    mac = h.digest()

    if page_no == 1:
        page = salt + ciphertext + iv + mac
    else:
        page = ciphertext + iv + mac
    page += b"\x00" * (SQLCIPHER_PAGE_SIZE - len(page))
    return page, salt


@pytest.fixture
def tmp_encrypted_db_factory(tmp_path: Path):
    """Factory that writes a fake encrypted SQLCipher DB to disk."""

    def build(
        version: WeChatVersion,
        key: bytes | None = None,
    ) -> tuple[Path, bytes]:
        key = key or get_random_bytes(SQLCIPHER_KEY_SIZE)
        # Page 1 plaintext starts where the SQLite header would after salt.
        # We synthesize the last 96 bytes of the SQLite header (16..112),
        # which is what our decryptor writes back out after the magic.
        header_tail = SQLITE_HEADER_MAGIC[16:] + b"\x00" * 87
        page1, salt = build_encrypted_page(key, version, header_tail, page_no=1)
        page2, _ = build_encrypted_page(
            key, version, b"payload".ljust(SQLCIPHER_PAGE_SIZE - 100, b"\x00"), page_no=2, salt=salt
        )
        db_path = tmp_path / f"fake_{version.name.lower()}.db"
        db_path.write_bytes(page1 + page2)
        return db_path, key

    return build


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Clear WCR_* environment variables to isolate settings tests."""
    import os

    for name in [n for n in os.environ if n.startswith("WCR_")]:
        monkeypatch.delenv(name, raising=False)
    yield
