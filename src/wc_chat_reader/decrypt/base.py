"""Abstract decryptor interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO


@dataclass(slots=True, frozen=True)
class DecryptedFile:
    """Metadata describing a successful decryption."""

    input_path: Path
    output_path: Path
    pages: int
    key_hex: str
    version: str


class Decryptor(ABC):
    """Abstract SQLCipher decryptor. Concrete v3/v4 override page params."""

    version: str
    iterations: int
    hmac_size: int
    reserve_size: int

    @abstractmethod
    def decrypt(
        self,
        key: bytes,
        source: BinaryIO,
        destination: BinaryIO,
    ) -> int:
        """Decrypt ``source`` into ``destination``. Returns the page count."""

    @abstractmethod
    def decrypt_file(
        self,
        key: bytes,
        input_path: Path,
        output_path: Path,
    ) -> DecryptedFile:
        """Decrypt a file on disk. Overwrites the destination if it exists."""
