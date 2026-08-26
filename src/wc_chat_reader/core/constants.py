"""Global constants: versions, defaults, protocol identifiers."""

from __future__ import annotations

from enum import Enum, IntEnum
from typing import Final

VERSION: Final[str] = "0.1.0"

DEFAULT_HTTP_HOST: Final[str] = "127.0.0.1"
DEFAULT_HTTP_PORT: Final[int] = 5030

WECHAT_PROCESS_NAMES: Final[frozenset[str]] = frozenset(
    {"WeChat.exe", "Weixin.exe"}
)

WECHAT_V3_DLL: Final[str] = "WeChatWin.dll"
WECHAT_V4_DLL: Final[str] = "Weixin.dll"

SQLITE_HEADER_MAGIC: Final[bytes] = b"SQLite format 3\x00"

# SQLCipher parameters — matches chatlog v3 & v4 constants
SQLCIPHER_PAGE_SIZE: Final[int] = 4096
SQLCIPHER_KEY_SIZE: Final[int] = 32
SQLCIPHER_SALT_SIZE: Final[int] = 16
SQLCIPHER_IV_SIZE: Final[int] = 16
SQLCIPHER_HMAC_SHA1_SIZE: Final[int] = 20
SQLCIPHER_HMAC_SHA512_SIZE: Final[int] = 64
SQLCIPHER_V3_ITERATIONS: Final[int] = 64000
SQLCIPHER_V4_ITERATIONS: Final[int] = 256000
SQLCIPHER_MAC_SALT_XOR: Final[int] = 0x3A


class WeChatVersion(IntEnum):
    """Major WeChat versions with distinct database formats."""

    UNKNOWN = 0
    V3 = 3
    V4 = 4


class Platform(str, Enum):
    """Supported OS platforms."""

    WINDOWS = "windows"
    DARWIN = "darwin"
    LINUX = "linux"


class MessageType(IntEnum):
    """WeChat message type identifiers (protocol-level, not user-facing)."""

    TEXT = 1
    IMAGE = 3
    VOICE = 34
    VIDEO = 43
    EMOTICON = 47
    LOCATION = 48
    APP = 49
    VOIP = 50
    SYSTEM = 10000
