"""Decryptor factory: pick v3 or v4 based on WeChat version."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from wc_chat_reader.core.constants import WeChatVersion
from wc_chat_reader.core.exceptions import UnsupportedVersionError
from wc_chat_reader.decrypt.base import DecryptedFile, Decryptor
from wc_chat_reader.decrypt.v3_decryptor import V3Decryptor
from wc_chat_reader.decrypt.v4_decryptor import V4Decryptor

if TYPE_CHECKING:
    pass


def create_decryptor(version: WeChatVersion) -> Decryptor:
    """Instantiate the appropriate decryptor for the given WeChat version."""
    if version == WeChatVersion.V3:
        return V3Decryptor()
    if version == WeChatVersion.V4:
        return V4Decryptor()
    raise UnsupportedVersionError(f"No decryptor for version {version}")


def decrypt_file(
    key: bytes,
    input_path: Path,
    output_path: Path,
    version: WeChatVersion,
) -> DecryptedFile:
    """One-shot decryption convenience function."""
    decryptor = create_decryptor(version)
    return decryptor.decrypt_file(key, input_path, output_path)
