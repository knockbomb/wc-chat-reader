"""SQLCipher-compatible database decryption.

WeChat uses SQLCipher with two variants:

- **v3** (WeChat 3.x): PBKDF2-SHA1, 64000 iterations, HMAC-SHA1 (20 bytes)
- **v4** (WeChat 4.0): PBKDF2-SHA512, 256000 iterations, HMAC-SHA512 (64 bytes)

The wire format for each 4096-byte page is:

    Page 1:  [ salt(16) | ciphertext | IV(16) | HMAC | padding ]
    Page N:  [ ciphertext | IV(16) | HMAC | padding ]

The decrypted output is a plain SQLite database that can be opened with the
stdlib ``sqlite3`` module — no SQLCipher runtime needed on the reading side.
"""

from wc_chat_reader.decrypt.base import DecryptedFile, Decryptor
from wc_chat_reader.decrypt.factory import (
    create_decryptor,
    decrypt_file,
)
from wc_chat_reader.decrypt.v3_decryptor import V3Decryptor
from wc_chat_reader.decrypt.v4_decryptor import V4Decryptor

__all__ = [
    "DecryptedFile",
    "Decryptor",
    "V3Decryptor",
    "V4Decryptor",
    "create_decryptor",
    "decrypt_file",
]
