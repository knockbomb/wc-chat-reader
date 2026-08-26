"""Core SQLCipher page decryption.

Shared implementation used by both v3 and v4 decryptors. The only differences
between v3 and v4 are:
- the KDF hash function (SHA1 vs. SHA512)
- iteration count
- HMAC size

Everything else — the page layout, key derivation flow, MAC verification,
padding — is identical.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.Protocol.KDF import PBKDF2

from wc_chat_reader.core.constants import (
    SQLCIPHER_IV_SIZE,
    SQLCIPHER_KEY_SIZE,
    SQLCIPHER_MAC_SALT_XOR,
    SQLCIPHER_PAGE_SIZE,
    SQLCIPHER_SALT_SIZE,
    SQLITE_HEADER_MAGIC,
)
from wc_chat_reader.core.exceptions import (
    HMACMismatchError,
    InvalidDatabaseError,
    InvalidKeyError,
)
from wc_chat_reader.core.logger import get_logger
from wc_chat_reader.decrypt.base import DecryptedFile, Decryptor

logger = get_logger(__name__)


@dataclass(slots=True, frozen=True)
class _DerivedKeys:
    """Encryption + MAC keys derived from the master key + salt."""

    enc_key: bytes
    mac_key: bytes


class SQLCipherDecryptor(Decryptor):
    """SQLCipher decryptor parameterised by (iterations, hmac_size, hash_module).

    Subclasses only need to set the class-level constants ``version``,
    ``iterations``, ``hmac_size`` and ``_hash_module``.
    """

    _hash_module: Any = None

    def __init__(self) -> None:
        if self._hash_module is None:
            raise TypeError(f"{type(self).__name__} must set _hash_module")
        self.reserve_size = _reserve_size(SQLCIPHER_IV_SIZE + self.hmac_size)

    # -- Public API ----------------------------------------------------------

    def decrypt(
        self,
        key: bytes,
        source: BinaryIO,
        destination: BinaryIO,
    ) -> int:
        if len(key) != SQLCIPHER_KEY_SIZE:
            raise InvalidKeyError(
                f"Key must be {SQLCIPHER_KEY_SIZE} bytes, got {len(key)}"
            )

        first_page = source.read(SQLCIPHER_PAGE_SIZE)
        if len(first_page) < SQLCIPHER_SALT_SIZE:
            raise InvalidDatabaseError("Source file smaller than one page")

        salt = first_page[:SQLCIPHER_SALT_SIZE]
        derived = self._derive_keys(key, salt)

        # Page 1: strip the salt, emit standard SQLite header + decrypted body.
        destination.write(SQLITE_HEADER_MAGIC)
        self._decrypt_page(
            derived, first_page[SQLCIPHER_SALT_SIZE:], 1, destination
        )
        page_no = 2
        while True:
            page = source.read(SQLCIPHER_PAGE_SIZE)
            if not page:
                break
            if len(page) < SQLCIPHER_PAGE_SIZE:
                # SQLite databases are always page-aligned. A short read at
                # the end means the file has trailing garbage (WAL leftover,
                # corrupt tail). Log and stop — silently emitting zeros would
                # produce an invalid SQLite output.
                logger.warning(
                    f"Ignoring {len(page)}-byte trailing fragment after "
                    f"page {page_no - 1} (not page-aligned)"
                )
                break
            self._decrypt_page(derived, page, page_no, destination)
            page_no += 1
        return page_no - 1

    def decrypt_file(
        self,
        key: bytes,
        input_path: Path,
        output_path: Path,
    ) -> DecryptedFile:
        input_path = Path(input_path)
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with input_path.open("rb") as src, output_path.open("wb") as dst:
            pages = self.decrypt(key, src, dst)

        logger.info(
            f"Decrypted {input_path.name} ({pages} pages) -> {output_path}"
        )
        return DecryptedFile(
            input_path=input_path,
            output_path=output_path,
            pages=pages,
            key_hex=key.hex(),
            version=self.version,
        )

    # -- Internals -----------------------------------------------------------

    def _derive_keys(self, key: bytes, salt: bytes) -> _DerivedKeys:
        enc_key = PBKDF2(
            key,
            salt,
            dkLen=SQLCIPHER_KEY_SIZE,
            count=self.iterations,
            hmac_hash_module=self._hash_module,
        )
        mac_salt = bytes(b ^ SQLCIPHER_MAC_SALT_XOR for b in salt)
        mac_key = PBKDF2(
            enc_key,
            mac_salt,
            dkLen=SQLCIPHER_KEY_SIZE,
            count=2,
            hmac_hash_module=self._hash_module,
        )
        return _DerivedKeys(enc_key=enc_key, mac_key=mac_key)

    def _decrypt_page(
        self,
        derived: _DerivedKeys,
        page_body: bytes,
        page_no: int,
        destination: BinaryIO,
    ) -> None:
        reserve = self.reserve_size
        ciphertext_end = len(page_body) - reserve
        ciphertext = page_body[:ciphertext_end]
        iv = page_body[ciphertext_end : ciphertext_end + SQLCIPHER_IV_SIZE]
        stored_hmac = page_body[
            ciphertext_end
            + SQLCIPHER_IV_SIZE : ciphertext_end
            + SQLCIPHER_IV_SIZE
            + self.hmac_size
        ]

        h = HMAC.new(derived.mac_key, digestmod=self._hash_module)
        h.update(ciphertext)
        h.update(iv)
        h.update(page_no.to_bytes(4, "little"))
        try:
            h.verify(stored_hmac)
        except ValueError as exc:
            raise HMACMismatchError(
                f"Page {page_no}: HMAC mismatch (wrong key or corrupt DB)"
            ) from exc

        cipher = AES.new(derived.enc_key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)
        destination.write(plaintext)
        # Preserve original page size by re-emitting the reserve region.
        destination.write(iv)
        destination.write(stored_hmac)
        pad_len = reserve - SQLCIPHER_IV_SIZE - self.hmac_size
        if pad_len > 0:
            destination.write(b"\x00" * pad_len)


def _reserve_size(needed: int) -> int:
    """SQLCipher rounds the reserve region up to the AES block size."""
    block = AES.block_size
    if needed % block == 0:
        return needed
    return ((needed // block) + 1) * block
