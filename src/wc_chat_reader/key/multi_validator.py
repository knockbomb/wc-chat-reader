"""Multi-configuration SQLCipher key validator.

SQLCipher supports two key modes:

1. **Raw key mode** — ``PRAGMA key = "x'...'"``: the bytes in memory ARE the
   AES-256 encryption key directly.  No PBKDF2 derivation for the enc key.
   This is what WeChat (and most performance-sensitive apps) use because it
   avoids the expensive PBKDF2 on every database open.

2. **Password mode** — ``PRAGMA key = "password"``: the bytes are a password
   that must go through PBKDF2 to derive the actual AES encryption key.

We try raw key mode FIRST for every HMAC configuration, then fall back to
password mode.  This covers both possibilities.

HMAC configurations tested:
  - HMAC-SHA512 + reserve=80  (standard SQLCipher V4)
  - HMAC-SHA256 + reserve=48
  - HMAC-SHA1   + reserve=32
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from Crypto.Cipher import AES

from wc_chat_reader.core.constants import (
    SQLCIPHER_IV_SIZE,
    SQLCIPHER_KEY_SIZE,
    SQLCIPHER_MAC_SALT_XOR,
    SQLCIPHER_PAGE_SIZE,
    SQLCIPHER_SALT_SIZE,
)
from wc_chat_reader.core.exceptions import InvalidDatabaseError

if TYPE_CHECKING:
    pass


@dataclass(slots=True, frozen=True)
class _HmacConfig:
    """One HMAC configuration."""

    hmac_algo: str       # hashlib name: 'sha1', 'sha256', 'sha512'
    hmac_size: int       # bytes: 20, 32, 64
    label: str           # human-readable label


# HMAC configs ordered by likelihood for WeChat
_HMAC_CONFIGS: tuple[_HmacConfig, ...] = (
    _HmacConfig("sha512", 64, "SHA512"),
    _HmacConfig("sha256", 32, "SHA256"),
    _HmacConfig("sha1", 20, "SHA1"),
)


def _reserve_size(needed: int) -> int:
    """SQLCipher pads the reserve region up to the AES block size."""
    block = AES.block_size
    if needed % block == 0:
        return needed
    return ((needed // block) + 1) * block


def _validate_raw_key(
    key: bytes,
    page: bytes,
    cfg: _HmacConfig,
) -> bool:
    """Validate assuming key IS the AES encryption key (raw key mode).

    This is what WeChat almost certainly uses: PRAGMA key = "x'...'"
    means the 32 bytes in memory are used directly as the AES-256 key.
    No PBKDF2 for the encryption key — only PBKDF2 for the MAC key.
    """
    if len(key) != SQLCIPHER_KEY_SIZE:
        return False

    # enc_key = key directly (no PBKDF2!)
    enc_key = key

    # Derive MAC key from enc_key via PBKDF2 (this still happens in raw mode)
    salt = page[:SQLCIPHER_SALT_SIZE]
    mac_salt = bytes(b ^ SQLCIPHER_MAC_SALT_XOR for b in salt)
    mac_key = hashlib.pbkdf2_hmac(
        cfg.hmac_algo, enc_key, mac_salt, 2, dklen=SQLCIPHER_KEY_SIZE
    )

    # Extract page components
    hmac_size = cfg.hmac_size
    reserve = _reserve_size(SQLCIPHER_IV_SIZE + hmac_size)
    ciphertext_end = SQLCIPHER_PAGE_SIZE - reserve

    if ciphertext_end <= SQLCIPHER_SALT_SIZE:
        return False

    ciphertext = page[SQLCIPHER_SALT_SIZE:ciphertext_end]
    iv = page[ciphertext_end : ciphertext_end + SQLCIPHER_IV_SIZE]
    stored_hmac = page[
        ciphertext_end + SQLCIPHER_IV_SIZE :
        ciphertext_end + SQLCIPHER_IV_SIZE + hmac_size
    ]

    if len(iv) < SQLCIPHER_IV_SIZE or len(stored_hmac) < hmac_size:
        return False

    # Compute HMAC
    h = hmac_mod.new(mac_key, digestmod=getattr(hashlib, cfg.hmac_algo))
    h.update(ciphertext)
    h.update(iv)
    h.update((1).to_bytes(4, "little"))

    return hmac_mod.compare_digest(h.digest(), stored_hmac)


def _validate_password_key(
    key: bytes,
    page: bytes,
    salt: bytes,
    cfg: _HmacConfig,
    iterations: int,
) -> bool:
    """Validate assuming key is a password that needs PBKDF2 (password mode).

    This is the standard SQLCipher PRAGMA key = "password" path.
    """
    if len(key) != SQLCIPHER_KEY_SIZE:
        return False

    # Derive encryption key via PBKDF2
    enc_key = hashlib.pbkdf2_hmac(
        cfg.hmac_algo, key, salt, iterations, dklen=SQLCIPHER_KEY_SIZE
    )

    # Derive MAC key
    mac_salt = bytes(b ^ SQLCIPHER_MAC_SALT_XOR for b in salt)
    mac_key = hashlib.pbkdf2_hmac(
        cfg.hmac_algo, enc_key, mac_salt, 2, dklen=SQLCIPHER_KEY_SIZE
    )

    # Extract page components
    hmac_size = cfg.hmac_size
    reserve = _reserve_size(SQLCIPHER_IV_SIZE + hmac_size)
    ciphertext_end = SQLCIPHER_PAGE_SIZE - reserve

    if ciphertext_end <= SQLCIPHER_SALT_SIZE:
        return False

    ciphertext = page[SQLCIPHER_SALT_SIZE:ciphertext_end]
    iv = page[ciphertext_end : ciphertext_end + SQLCIPHER_IV_SIZE]
    stored_hmac = page[
        ciphertext_end + SQLCIPHER_IV_SIZE :
        ciphertext_end + SQLCIPHER_IV_SIZE + hmac_size
    ]

    if len(iv) < SQLCIPHER_IV_SIZE or len(stored_hmac) < hmac_size:
        return False

    # Compute HMAC
    h = hmac_mod.new(mac_key, digestmod=getattr(hashlib, cfg.hmac_algo))
    h.update(ciphertext)
    h.update(iv)
    h.update((1).to_bytes(4, "little"))

    return hmac_mod.compare_digest(h.digest(), stored_hmac)


class MultiValidator:
    """Try multiple SQLCipher configs to validate a key.

    For each HMAC config, tries:
    1. Raw key mode (no PBKDF2 for enc key) — fast, likely for WeChat
    2. Password mode with various iteration counts — fallback

    Returns (ok, config_label) on success.
    """

    __slots__ = ("_page", "_path", "_salt", "_is_plaintext")

    def __init__(self, db_path: Path) -> None:
        self._path = Path(db_path)
        with self._path.open("rb") as f:
            page = f.read(SQLCIPHER_PAGE_SIZE)
        if len(page) < SQLCIPHER_SALT_SIZE + SQLCIPHER_IV_SIZE:
            raise InvalidDatabaseError(
                f"{self._path}: file too small"
            )
        self._page = page
        self._salt = page[:SQLCIPHER_SALT_SIZE]
        self._is_plaintext = page[:15] == b"SQLite format 3"

    def validate(self, key: bytes) -> tuple[bool, str]:
        """Validate key against all configs. Returns (ok, config_label).

        Order:
          1. Raw key × all HMAC configs (fast, most likely)
          2. Password key × SHA512 × 256000 (standard V4)
          3. Password key × other configs × iterations
        """
        # FAST PATH: raw key mode (no PBKDF2 for enc key)
        for cfg in _HMAC_CONFIGS:
            if _validate_raw_key(key, self._page, cfg):
                return True, f"RAW-{cfg.label}"

        # SLOW PATH: password mode with PBKDF2
        # Standard V4: SHA512 + 256000
        for cfg in _HMAC_CONFIGS:
            for iterations in (256000, 64000, 4000):
                if _validate_password_key(
                    key, self._page, self._salt, cfg, iterations
                ):
                    return True, f"PWD-{cfg.label}-{iterations//1000}K"

        return False, ""

    def validate_quick(self, key: bytes) -> bool:
        """Fast validation using raw key + SHA512 only."""
        return _validate_raw_key(key, self._page, _HMAC_CONFIGS[0])

    @property
    def salt_hex(self) -> str:
        return self._salt.hex()

    @property
    def page_header_hex(self) -> str:
        return self._page[:32].hex()

    def is_plaintext_sqlite(self) -> bool:
        return self._is_plaintext
