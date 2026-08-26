"""WeChat 3.x decryptor: PBKDF2-SHA1, 64000 iterations, HMAC-SHA1."""

from __future__ import annotations

from Crypto.Hash import SHA1

from wc_chat_reader.core.constants import (
    SQLCIPHER_HMAC_SHA1_SIZE,
    SQLCIPHER_V3_ITERATIONS,
)
from wc_chat_reader.decrypt.sqlcipher import SQLCipherDecryptor


class V3Decryptor(SQLCipherDecryptor):
    version = "v3"
    iterations = SQLCIPHER_V3_ITERATIONS
    hmac_size = SQLCIPHER_HMAC_SHA1_SIZE
    _hash_module = SHA1
