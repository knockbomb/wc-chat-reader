"""Frida hybrid key extractor for WeChat V4.

Strategy
--------
1. **Frida scans from inside** the process using ``Memory.scan()`` — this is
   ~5× faster than cross-process ``ReadProcessMemory`` because there's no
   syscall-per-chunk overhead.  It collects ``(match_addr, ptr_value)`` pairs.
2. **Python reads key data via ReadProcessMemory** — the proven reliable path.
   For each ``ptr_value`` received from Frida, we read 32 bytes at that address
   using ``ReadProcessMemory`` and validate with PBKDF2+HMAC.

Why hybrid?
-----------
Pure Frida (read key from inside) fails silently: Frida's in-process memory
reads produce different bytes than ``ReadProcessMemory`` for some candidates,
causing validation to always fail.  By using Frida only for the fast *scan*
and delegating the *read* to ``ReadProcessMemory``, we get both speed and
reliability.

Runtime key struct layout (verified on WeChat 4.1.15.13)::

    [key_ptr (8B)] [flags=0 (8B)] [key_size=32 (8B)] [...]

The relaxed pattern ``[0, 32]`` matches the runtime struct in writable heap.
The AES-256 key pointer is at offset −8 from the pattern start.

Only runs on Windows against a V4 process with Frida installed.
Requires elevation (admin).
"""

from __future__ import annotations

import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from wc_chat_reader.core.constants import SQLCIPHER_KEY_SIZE, WeChatVersion
from wc_chat_reader.core.exceptions import (
    KeyExtractionError,
    NoValidKeyError,
)
from wc_chat_reader.core.logger import get_logger
from wc_chat_reader.key.base import KeyExtractor, KeyResult
from wc_chat_reader.key.memory_scanner import WindowsMemoryScanner, open_scanner
from wc_chat_reader.key.validator import KeyValidator

if TYPE_CHECKING:
    from wc_chat_reader.wechat.process_detector import WeChatProcess

logger = get_logger(__name__)

# Relaxed pattern [0, 32] — 16 bytes
_PATTERN_HEX = "00 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00"

# Frida script: scan RW heap for [0, 32], read ptr@-8, send (match_addr, ptr).
# CRITICAL: Memory.scan is ASYNC — onComplete fires after all onMatch for that
# range, but multiple ranges scan concurrently.  We must track pending ranges
# and only send 'done' after the LAST range's onComplete fires.
_FRIDA_SCAN_SCRIPT = r"""
(function () {
    'use strict';
    var PATTERN = %(pattern_q)s;
    var PTR_OFFSET = -8;
    var MIN_PTR = 0x10000;
    var MAX_PTR = 0x7fffffffffffd;
    var sent = 0;
    var matches = 0;

    send({tag: 'start'});

    var ranges = Process.enumerateRanges('rw-');
    var queue = [];
    for (var i = 0; i < ranges.length; i++) {
        if (ranges[i].size >= 64 * 1024) queue.push(ranges[i]);
    }

    if (queue.length === 0) {
        send({tag: 'done', matches: 0, candidates: 0});
        return;
    }

    var pending = queue.length;

    for (var i = 0; i < queue.length; i++) {
        (function (range) {
            try {
                Memory.scan(range.base, range.size, PATTERN, {
                    onMatch: function (address, size) {
                        matches++;
                        try {
                            var ptrAddr = address.add(PTR_OFFSET);
                            var ptr = ptrAddr.readPointer();
                            if (ptr >= MIN_PTR && ptr <= MAX_PTR) {
                                sent++;
                                send({
                                    tag: 'match',
                                    matchAddr: address.toString(),
                                    ptrValue: ptr.toString(),
                                });
                            }
                        } catch (e) {}
                    },
                    onComplete: function () {
                        pending--;
                        if (pending === 0) {
                            send({tag: 'done', matches: matches, candidates: sent});
                        }
                    }
                });
            } catch (e) {
                pending--;
                if (pending === 0) {
                    send({tag: 'done', matches: matches, candidates: sent});
                }
            }
        })(queue[i]);
    }
})();
""" % {"pattern_q": '"%s"' % _PATTERN_HEX}


def _event() -> threading.Event:
    return threading.Event()


@dataclass(slots=True, frozen=True)
class _PtrCandidate:
    """A pointer value found by Frida scan, to be validated via RPM."""

    match_addr: str
    ptr_value: int


class FridaHybridExtractor(KeyExtractor):
    """Frida fast scan + ReadProcessMemory reliable read.

    Frida scans RW heap from inside the process (near-memcpy speed) to find
    pattern matches and extract pointer values.  Python then reads the actual
    key bytes via ReadProcessMemory (proven reliable) and validates with
    PBKDF2+HMAC.
    """

    name = "frida-hybrid"
    priority = 3  # Before v4-broad-scan (4).

    def __init__(self, timeout_s: float = 60.0) -> None:
        self._timeout_s = timeout_s

    @staticmethod
    def _frida_available() -> bool:
        try:
            import frida  # noqa: PLC0415, F401
        except ImportError:
            return False
        return True

    def supports(self, process: WeChatProcess) -> bool:
        return (
            sys.platform == "win32"
            and process.version == WeChatVersion.V4
            and self._frida_available()
        )

    def unsupported_reason(self, process: WeChatProcess) -> str | None:
        if sys.platform != "win32":
            return "memory scanning requires Windows"
        if process.version != WeChatVersion.V4:
            return f"process version is {process.version.name}, expected V4"
        if not self._frida_available():
            return "frida package is not installed"
        return None

    def extract(
        self,
        process: WeChatProcess,
        sample_db_path: Path | None = None,
    ) -> KeyResult:
        import frida  # local import: optional dependency

        if sample_db_path is None:
            from wc_chat_reader.key._memory_base import _find_sample_db
            sample_db_path = _find_sample_db(process, WeChatVersion.V4)
        if sample_db_path is None:
            raise KeyExtractionError(
                "FridaHybridExtractor requires a sample_db_path for validation"
            )

        validator = KeyValidator(sample_db_path, process.version)

        # Phase 1: Frida fast scan — collect (match_addr, ptr_value) pairs
        candidates: list[_PtrCandidate] = []
        scan_done = _event()
        fatal_msg: dict[str, str] = {}
        info: dict[str, int] = {}

        def on_message(msg: dict, data: bytes | None) -> None:
            payload = msg.get("payload") or {}
            tag = payload.get("tag")
            if tag == "match":
                try:
                    ptr_val = int(payload["ptrValue"], 16)
                except (ValueError, KeyError):
                    return
                candidates.append(
                    _PtrCandidate(
                        match_addr=payload.get("matchAddr", "?"),
                        ptr_value=ptr_val,
                    )
                )
            elif tag == "done":
                info.update(payload)
                scan_done.set()
            elif tag == "start":
                logger.info("FridaHybrid: scan started")
            elif tag == "fatal":
                fatal_msg["msg"] = payload.get("message", "unknown")
                scan_done.set()

        try:
            session = frida.attach(process.pid)
        except frida.PermissionDeniedError as exc:
            raise KeyExtractionError(
                "Frida attach denied — run as Administrator"
            ) from exc

        try:
            script = session.create_script(_FRIDA_SCAN_SCRIPT)
            script.on("message", on_message)
            script.load()
            scan_done.wait(timeout=self._timeout_s)
        finally:
            try:
                session.detach()
            except Exception:
                pass

        if fatal_msg:
            raise KeyExtractionError(f"FridaHybrid: {fatal_msg['msg']}")

        n_matches = info.get("matches", 0)
        logger.info(
            f"FridaHybrid: scan complete — {n_matches} match(es), "
            f"{len(candidates)} ptr candidate(s)"
        )

        if not candidates:
            raise NoValidKeyError(
                f"FridaHybrid: {n_matches} match(es) but no valid pointers. "
                f"Runtime struct layout may have changed."
            )

        # Deduplicate by ptr_value
        seen_ptrs: set[int] = set()
        unique: list[_PtrCandidate] = []
        for c in candidates:
            if c.ptr_value not in seen_ptrs:
                seen_ptrs.add(c.ptr_value)
                unique.append(c)

        logger.info(
            f"FridaHybrid: {len(unique)} unique pointer(s) "
            f"(from {len(candidates)} total)"
        )

        # Phase 2: Read key data via ReadProcessMemory (proven reliable)
        # and validate with PBKDF2+HMAC.
        with open_scanner(process.pid) as scanner:
            for i, cand in enumerate(unique):
                key = scanner.read(cand.ptr_value, SQLCIPHER_KEY_SIZE)
                if key is None or len(key) != SQLCIPHER_KEY_SIZE:
                    continue
                if validator.validate(key):
                    logger.info(
                        f"FridaHybrid: valid key! ptr=0x{cand.ptr_value:x}, "
                        f"match={cand.match_addr}, after {i + 1} validation(s)"
                    )
                    return KeyResult(
                        key=key,
                        strategy=self.name,
                        candidates_scanned=i + 1,
                        meta={
                            "db_path": str(sample_db_path),
                            "version": process.version_str,
                            "ptr_value": f"0x{cand.ptr_value:x}",
                            "match_addr": cand.match_addr,
                            "total_matches": n_matches,
                            "total_unique": len(unique),
                        },
                    )

        raise NoValidKeyError(
            f"FridaHybrid: {len(unique)} unique pointer(s), none matched."
        )

