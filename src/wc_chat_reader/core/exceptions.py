"""Exception hierarchy.

All library errors derive from `WcReaderError`. Callers should catch the closest
specific subclass; the base class is provided only as an escape hatch.
"""

from __future__ import annotations


class WcReaderError(Exception):
    """Base class for every error raised by this library."""


# ---- Process detection -----------------------------------------------------


class ProcessError(WcReaderError):
    """WeChat process could not be located or accessed."""


class WeChatNotFoundError(ProcessError):
    """No running WeChat process was found."""


class WeChatOfflineError(ProcessError):
    """WeChat is running but no user is logged in."""


class UnsupportedVersionError(ProcessError):
    """The detected WeChat version has no adapter."""


# ---- Key extraction --------------------------------------------------------


class KeyError_(WcReaderError):
    """Base class for key-extraction failures.

    Named with a trailing underscore to avoid clashing with the builtin
    `KeyError`. Callers that need to catch both should catch this class.
    """


class KeyExtractionError(KeyError_):
    """Key could not be extracted from the target process memory."""


class NoValidKeyError(KeyError_):
    """Candidate keys were found but none validated against the database."""


class InsufficientPrivilegeError(KeyError_):
    """The process lacks the privilege needed to read WeChat memory."""


# ---- Decryption ------------------------------------------------------------


class DecryptError(WcReaderError):
    """Database decryption failed."""


class InvalidKeyError(DecryptError):
    """The provided key is syntactically invalid (wrong length/encoding)."""


class InvalidDatabaseError(DecryptError):
    """The target file is not a valid SQLCipher database."""


class HMACMismatchError(DecryptError):
    """A page's HMAC did not match — key is wrong or database is corrupt."""


# ---- Data-layer ------------------------------------------------------------


class DatabaseError(WcReaderError):
    """Query-layer errors after successful decryption."""


class SchemaError(DatabaseError):
    """The decrypted database schema does not match the expected version."""


# ---- Configuration ---------------------------------------------------------


class ConfigError(WcReaderError):
    """Invalid or missing configuration."""
