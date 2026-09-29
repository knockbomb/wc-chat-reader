"""Multi-configuration SQLCipher key validator.

Tries multiple SQLCipher parameter combinations to handle non-standard
WeChat builds that may use different HMAC algorithms or iteration counts.

Configurations tested:
  - HMAC-SHA512 + 256000 iter (standard SQLCipher V4)
  - HMAC-SHA1   + 256000 iter
  - HMAC-SHA256 + 256000 iter
  - HMAC-SHA512 + 64000 iter
  - HMAC-SHA1   + 64000 iter
  - HMAC-SHA256 + 64000 iter
"""

from __future__ import annotations

import hashlib
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
class _Config:
    """One SQLCipher parameter combination."""

    hmac_algo: str       # hashlib name: 'sha1', 'sha256', 'sha512'
    hmac_size: int       # bytes: 20, 32, 64
    iterations: int      # PBKDF2 iterations
    label: str           # human-readable label


# All configurations to try, ordered by likelihood
_CONFIGS: tuple[_Config, ...] = (
    # Standard SQLCipher V4
    _Config("sha512", 64, 256000, "V4-SHA512-256K"),
    # Possible WeChat custom variants
    _Config("sha1", 20, 256000, "V4-SHA1-256K"),
    _Config("sha256", 32, 256000, "V4-SHA256-256K"),
    # Lower iteration counts
    _Config("sha512", 64, 64000, "V4-SHA512-64K"),
    _Config("sha1", 20, 64000, "V4-SHA1-64K"),
    _Config("sha256", 32, 64000, "V4-SHA256-64K"),
    # SQLCipher V3-style (even for V4 process)
    _Config("sha1", 20, 4000, "V3-SHA1-4K"),
    # No iterations (raw key, no PBKDF2) — unlikely but test it
    _Config("sha512", 64, 1, "RAW-SHA512-1"),
    _Config("sha1", 20, 1, "RAW-SHA1-1"),
)


def _reserve_size(needed: int) -> int:
    """SQLCipher pads the reserve region up to the AES block size."""
    block = AES.block_size
    if needed % block == 0:
        return needed
    return ((needed // block) + 1) * block


def _validate_one(
    key: bytes,
    page: bytes,
    salt: bytes,
    cfg: _Config,
) -> bool:
    """Validate a key with one specific configuration."""
    if len(key) != SQLCIPHER_KEY_SIZE:
        return False

    # Derive encryption key via PBKDF2
    enc_key = hashlib.pbkdf2_hmac(
        cfg.hmac_algo, key, salt, cfg.iterations, dklen=SQLCIPHER_KEY_SIZE
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
        return False  # reserve too large for this page

    ciphertext = page[SQLCIPHER_SALT_SIZE:ciphertext_end]
    iv = page[ciphertext_end : ciphertext_end + SQLCIPHER_IV_SIZE]
    stored_hmac = page[
        ciphertext_end + SQLCIPHER_IV_SIZE :
        ciphertext_end + SQLCIPHER_IV_SIZE + hmac_size
    ]

    if len(iv) < SQLCIPHER_IV_SIZE or len(stored_hmac) < hmac_size:
        return False

    # Compute HMAC
    import hmac as hmac_mod
    h = hmac_mod.new(mac_key, digestmod=getattr(hashlib, cfg.hmac_algo))
    h.update(ciphertext)
    h.update(iv)
    h.update((1).to_bytes(4, "little"))

    return hmac_mod.compare_digest(h.digest(), stored_hmac)


class MultiValidator:
    """Try multiple SQLCipher configs to validate a key.

    Returns the matching config label on success, or None.
    """

    __slots__ = ("_page", "_path", "_salt", "_configs")

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
        self._configs = _CONFIGS

    def validate(self, key: bytes) -> tuple[bool, str]:
        """Validate key against all configs. Returns (ok, config_label)."""
        for cfg in self._configs:
            if _validate_one(key, self._page, self._salt, cfg):
                return True, cfg.label
        return False, ""

    def validate_quick(self, key: bytes) -> bool:
        """Fast validation using standard V4 config only."""
        return _validate_one(key, self._page, self._salt, _CONFIGS[0])

    @property
    def salt_hex(self) -> str:
        return self._salt.hex()

    @property
    def page_header_hex(self) -> str:
        return self._page[:32].hex()

    def is_plaintext_sqlite(self) -> bool:
        return self._page[:15] == b"SQLite format 3"
