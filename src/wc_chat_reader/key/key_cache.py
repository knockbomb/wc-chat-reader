"""Local key cache — make key extraction "open and it just works".

Motivation
----------
WeChat database keys rarely change for a given install: the passphrase is
bound to the local login, not regenerated per app launch. Re-extracting it on
every start (memory scan or process injection) is slow and needs privileges.
Caching the validated key lets the CLI open instantly on subsequent runs.
"""

from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from wc_chat_reader.core.logger import get_logger

logger = get_logger(__name__)

_ENV_OVERRIDE = "WCR_KEYCACHE_DIR"


@dataclass(slots=True, frozen=True)
class CachedKey:
    """A validated key plus enough context to judge cache freshness."""

    key: bytes
    version_str: str            # WeChat version the key was captured against
    data_dir_fingerprint: str   # identifies the WeChat install/login that owns the key
    strategy: str               # extraction strategy that produced the key
    captured_at: float = field(default_factory=time.time)


def _fingerprint(data_dir: Path | None) -> str:
    """Stable identifier for a WeChat data directory / install."""
    if data_dir is None:
        return "unknown"
    try:
        p = Path(data_dir).resolve()
        # Include mtime of the login key store so a re-login invalidates cache.
        marker = None
        for cand in p.rglob("key_info.db"):
            marker = cand
            break
        if marker is None:
            for cand in p.rglob("*.db"):
                marker = cand
                break
        mtime = marker.stat().st_mtime_ns if marker and marker.is_file() else 0
        return f"{p}::{mtime}"
    except OSError:
        return str(data_dir)


def default_cache_dir() -> Path:
    """Return the platform-appropriate cache directory.

    Honors ``WCR_KEYCACHE_DIR`` so users can relocate it. Falls back to the
    platform user cache dir; if that cannot be determined (rare on Windows/
    macOS) returns a dotdir under the user home.
    """
    override = os.environ.get(_ENV_OVERRIDE)
    if override:
        return Path(override).expanduser()

    home = Path.home()
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
    elif sys.platform == "darwin":
        base = Path(os.environ.get("XDG_CACHE_HOME", home / "Library" / "Caches"))
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME", home / ".cache"))
    return base / "wc-chat-reader"


class KeyCache:
    """Read/write the validated-key cache.

    The cache file is JSON under the user cache dir (never inside the repo, so
    sensitive keys never reach git). All writes go through an atomic
    tmpfile+rename so a crashed run cannot corrupt the cache.
    """

    def __init__(self, path: Path | None = None) -> None:
        self._path = Path(path) if path else default_cache_dir() / "keys.json"

    # ---- read -------------------------------------------------------------
    def load(self) -> dict[str, dict[str, Any]]:
        """Return the raw cache dict (key hex -> record). Empty on any error."""
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except (OSError, ValueError):
            pass
        return {}

    def get(self, version_str: str, data_dir: Path | None) -> CachedKey | None:
        """Return a cached key matching this install, or None.

        A record is usable only when the WeChat version and the data-directory
        fingerprint both match — this prevents serving a stale key after WeChat
        is upgraded or the account is re-logged-in.
        """
        fp = _fingerprint(data_dir)
        records = self.load()
        for _, rec in records.items():
            try:
                if (
                    rec.get("version_str") == version_str
                    and rec.get("data_dir_fingerprint") == fp
                ):
                    return CachedKey(
                        key=bytes.fromhex(rec["key_hex"]),
                        version_str=rec["version_str"],
                        data_dir_fingerprint=rec["data_dir_fingerprint"],
                        strategy=rec.get("strategy", "cache"),
                        captured_at=rec.get("captured_at", 0.0),
                    )
            except (KeyError, ValueError):
                continue
        return None

    # ---- write ------------------------------------------------------------
    def put(self, key: CachedKey) -> bool:
        """Upsert ``key`` into the cache. Returns False on write failure."""
        rec = asdict(key)
        rec["key_hex"] = key.key.hex()
        rec.pop("key", None)
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            return False
        records = self.load()
        # One cache line per data-dir fingerprint — replace any prior entry
        # for this install so the cache never grows unbounded with re-captures.
        cleaned = {
            k: v
            for k, v in records.items()
            if v.get("data_dir_fingerprint") != key.data_dir_fingerprint
        }
        cleaned[key.data_dir_fingerprint] = rec
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        try:
            tmp.write_text(
                json.dumps(cleaned, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            tmp.replace(self._path)
        except OSError:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            return False
        return True