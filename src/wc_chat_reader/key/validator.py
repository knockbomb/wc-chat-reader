"""Validate candidate keys against a real SQLCipher database page.

A candidate is accepted when the PBKDF2-derived MAC key correctly authenticates
the first page's HMAC. HMAC verification alone is cryptographically sufficient
(2^-160 false positive for SHA1, 2^-512 for SHA512) — no separate plaintext
sanity check is required.

We validate without touching disk beyond reading the first ``PAGE_SIZE`` bytes,
and never decrypt candidate keys' ciphertext (HMAC is enough).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA1, SHA512
from Crypto.Protocol.KDF import PBKDF2

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
    WeChatVersion,
)
from wc_chat_reader.core.exceptions import InvalidDatabaseError


@dataclass(slots=True, frozen=True)
class _ValidationParams:
    iterations: int
    hmac_size: int
    hash_module: object  # PyCryptodome hash module (SHA1/SHA512)
    version: WeChatVersion


def _params(version: WeChatVersion) -> _ValidationParams:
    if version == WeChatVersion.V3:
        return _ValidationParams(
            iterations=SQLCIPHER_V3_ITERATIONS,
            hmac_size=SQLCIPHER_HMAC_SHA1_SIZE,
            hash_module=SHA1,
            version=WeChatVersion.V3,
        )
    if version == WeChatVersion.V4:
        return _ValidationParams(
            iterations=SQLCIPHER_V4_ITERATIONS,
            hmac_size=SQLCIPHER_HMAC_SHA512_SIZE,
            hash_module=SHA512,
            version=WeChatVersion.V4,
        )
    raise ValueError(f"Unsupported version: {version}")


class KeyValidator:
    """Validate keys against a specific SQLCipher database file."""

    __slots__ = ("_page", "_params", "_path", "_salt")

    def __init__(self, db_path: Path, version: WeChatVersion) -> None:
        self._path = Path(db_path)
        self._params = _params(version)
        page = self._read_first_page()
        if len(page) < SQLCIPHER_SALT_SIZE + SQLCIPHER_IV_SIZE:
            raise InvalidDatabaseError(
                f"{self._path}: file too small to contain a SQLCipher page"
            )
        self._page = page
        self._salt = page[:SQLCIPHER_SALT_SIZE]

    def _read_first_page(self) -> bytes:
        with self._path.open("rb") as f:
            return f.read(SQLCIPHER_PAGE_SIZE)

    def validate(self, key: bytes) -> bool:
        """Return True iff ``key`` decrypts and authenticates the first page."""
        if len(key) != SQLCIPHER_KEY_SIZE:
            return False

        enc_key = PBKDF2(
            key,
            self._salt,
            dkLen=SQLCIPHER_KEY_SIZE,
            count=self._params.iterations,
            hmac_hash_module=self._params.hash_module,  # type: ignore[arg-type]
        )

        mac_salt = bytes(b ^ SQLCIPHER_MAC_SALT_XOR for b in self._salt)
        mac_key = PBKDF2(
            enc_key,
            mac_salt,
            dkLen=SQLCIPHER_KEY_SIZE,
            count=2,
            hmac_hash_module=self._params.hash_module,  # type: ignore[arg-type]
        )

        page = self._page
        hmac_size = self._params.hmac_size
        reserve = _reserve_size(SQLCIPHER_IV_SIZE + hmac_size)
        # Layout: [salt(16)] [ciphertext] [iv(16)] [hmac] [padding]
        # Ciphertext ends right before the IV.
        ciphertext_end = SQLCIPHER_PAGE_SIZE - reserve
        ciphertext = page[SQLCIPHER_SALT_SIZE:ciphertext_end]
        iv = page[ciphertext_end : ciphertext_end + SQLCIPHER_IV_SIZE]
        stored_hmac = page[
            ciphertext_end + SQLCIPHER_IV_SIZE : ciphertext_end
            + SQLCIPHER_IV_SIZE
            + hmac_size
        ]

        # HMAC covers ciphertext + IV + page number (1 for the first page,
        # in little-endian 32-bit).
        h = HMAC.new(mac_key, digestmod=self._params.hash_module)  # type: ignore[arg-type]
        h.update(ciphertext)
        h.update(iv)
        h.update((1).to_bytes(4, "little"))
        try:
            h.verify(stored_hmac)
        except ValueError:
            return False

        # HMAC verification succeeding is cryptographically sufficient proof
        # that ``key`` is correct — the probability of a false positive is
        # 2^-160 (SHA1) or 2^-512 (SHA512). No further plaintext check needed.
        return True


def _reserve_size(needed: int) -> int:
    """SQLCipher pads the reserve region up to the AES block size."""
    block = AES.block_size
    if needed % block == 0:
        return needed
    return ((needed // block) + 1) * block
