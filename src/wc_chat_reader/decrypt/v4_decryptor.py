"""WeChat 4.0 decryptor: PBKDF2-SHA512, 256000 iterations, HMAC-SHA512."""

from __future__ import annotations

from Crypto.Hash import SHA512

from wc_chat_reader.core.constants import (
    SQLCIPHER_HMAC_SHA512_SIZE,
    SQLCIPHER_V4_ITERATIONS,
)
from wc_chat_reader.decrypt.sqlcipher import SQLCipherDecryptor


class V4Decryptor(SQLCipherDecryptor):
    version = "v4"
    iterations = SQLCIPHER_V4_ITERATIONS
    hmac_size = SQLCIPHER_HMAC_SHA512_SIZE
    _hash_module = SHA512
