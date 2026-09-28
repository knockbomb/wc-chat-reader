"""Frida direct key extractor for WeChat V4.

Uses Frida's in-process ``Memory.scan()`` to find the runtime key struct
``[key_ptr][0][32]`` in writable heap memory, then reads the AES-256 key
via ``ptr@-8``.  Only validated candidates are sent back to Python,
minimising cross-process data transfer.

This is the fastest Frida-based extraction path:

1. Frida scans RW heap from **inside** the process (near-memcpy speed).
2. Pattern ``[0, 32]`` (16 bytes) matches the runtime struct.
3. Key pointer is at offset **−8** from pattern start (verified).
4. Entropy pre-filter in Frida rejects obvious non-keys.
5. Only high-quality candidates are sent to Python for PBKDF2 validation.

Complement to ``V4BroadScanExtractor`` (which uses ReadProcessMemory from
outside).  Runs when Frida is available; falls through to broad-scan
otherwise.

Only runs on Windows against a V4 process when the optional ``frida``
extra is installed.  Requires elevation (admin).
"""

from __future__ import annotations

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
from wc_chat_reader.key.validator import KeyValidator

if TYPE_CHECKING:
    from wc_chat_reader.wechat.process_detector import WeChatProcess

logger = get_logger(__name__)

# Relaxed pattern [0, 32] — 16 bytes
_PATTERN_HEX = "00 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00"

# Minimal Frida script: scan RW heap for [0, 32], read key at ptr@-8,
# entropy-filter, send only valid-looking keys back.
_FRIDA_DIRECT_SCRIPT = r"""
(function () {
    'use strict';
    var PATTERN = %(pattern_q)s;
    var KEY_SIZE = 32;
    var PTR_OFFSET = -8;  // verified on WeChat 4.1.15.13
    var MIN_PTR = 0x10000;
    var MAX_PTR = 0x7fffffffffffd;
    var sent = 0;
    var matches = 0;

    function isLikelyKey(data) {
        if (!data || data.byteLength !== KEY_SIZE) return false;
        var bytes = new Uint8Array(data);
        var counts = new Array(256);
        for (var i = 0; i < 256; i++) counts[i] = 0;
        var nonzero = 0;
        for (var i = 0; i < KEY_SIZE; i++) {
            counts[bytes[i]]++;
            if (bytes[i] !== 0) nonzero++;
        }
        if (nonzero < 20) return false;
        var maxCount = 0;
        for (var i = 0; i < 256; i++) {
            if (counts[i] > maxCount) maxCount = counts[i];
        }
        if (maxCount > 3) return false;
        var entropy = 0;
        for (var i = 0; i < 256; i++) {
            if (counts[i] > 0) {
                var p = counts[i] / KEY_SIZE;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
        }
        return entropy >= 5.0;
    }

    send({tag: 'start', message: 'Frida direct scan: relaxed pattern + ptr@-8'});

    var ranges = Process.enumerateRanges('rw-');
    var totalRanges = ranges.length;

    ranges.forEach(function (range) {
        if (range.size < 64 * 1024) return;
        try {
            Memory.scan(range.base, range.size, PATTERN, {
                onMatch: function (address, size) {
                    matches++;
                    try {
                        var ptrAddr = address.add(PTR_OFFSET);
                        var ptr = ptrAddr.readPointer();
                        if (ptr >= MIN_PTR && ptr <= MAX_PTR) {
                            var key = ptr.readByteArray(KEY_SIZE);
                            if (isLikelyKey(key)) {
                                sent++;
                                send({
                                    tag: 'candidate',
                                    matchAddr: address.toString(),
                                    ptrAddr: ptrAddr.toString(),
                                }, key);
                            }
                        }
                    } catch (e) {}
                },
                onComplete: function () {}
            });
        } catch (e) {}
    });

    send({
        tag: 'done',
        matches: matches,
        candidates: sent,
        ranges: totalRanges,
    });
})();
""" % {"pattern_q": '"%s"' % _PATTERN_HEX}


def _event() -> threading.Event:
    return threading.Event()


@dataclass(slots=True, frozen=True)
class _Candidate:
    key: bytes
    match_addr: str


class FridaDirectExtractor(KeyExtractor):
    """Fastest Frida path: in-process scan + ptr@-8 direct key read."""

    name = "frida-direct"
    priority = 3  # Before v4-broad-scan (4) and frida-memory-scan (5).

    def __init__(self, timeout_s: float = 120.0) -> None:
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
            process.version == WeChatVersion.V4
            and self._frida_available()
        )

    def unsupported_reason(self, process: WeChatProcess) -> str | None:
        if process.version != WeChatVersion.V4:
            return f"process version is {process.version.name}, expected V4"
        if not self._frida_available():
            return "frida package is not installed (pip install 'wc-chat-reader[frida]')"
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
                "FridaDirectExtractor requires a sample_db_path for validation"
            )

        validator = KeyValidator(sample_db_path, process.version)
        candidates: list[_Candidate] = []
        scan_done = _event()
        fatal_msg: dict[str, str] = {}
        info: dict[str, int] = {}

        def on_message(msg: dict, data: bytes | None) -> None:
            payload = msg.get("payload") or {}
            tag = payload.get("tag")
            if tag == "candidate" and data and len(data) == SQLCIPHER_KEY_SIZE:
                candidates.append(
                    _Candidate(
                        key=bytes(data),
                        match_addr=payload.get("matchAddr", "?"),
                    )
                )
            elif tag == "done":
                info.update(payload)
                scan_done.set()
            elif tag == "start":
                logger.info(f"FridaDirect: {payload.get('message', '')}")
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
            script = session.create_script(_FRIDA_DIRECT_SCRIPT)
            script.on("message", on_message)
            script.load()
            scan_done.wait(timeout=self._timeout_s)
        finally:
            try:
                session.detach()
            except Exception:
                pass

        if fatal_msg:
            raise KeyExtractionError(f"FridaDirect: {fatal_msg['msg']}")

        n_matches = info.get("matches", 0)
        n_ranges = info.get("ranges", 0)
        logger.info(
            f"FridaDirect: {n_matches} pattern match(es) in "
            f"{n_ranges} range(s), {len(candidates)} candidate(s)"
        )

        if not candidates:
            raise NoValidKeyError(
                f"FridaDirect: {n_matches} match(es) but no key candidates. "
                f"Runtime struct layout may have changed."
            )

        # Deduplicate
        seen: set[bytes] = set()
        unique: list[_Candidate] = []
        for c in candidates:
            if c.key not in seen:
                seen.add(c.key)
                unique.append(c)

        # Validate
        for i, cand in enumerate(unique):
            if validator.validate(cand.key):
                logger.info(
                    f"FridaDirect: valid key after {i + 1} validation(s), "
                    f"match_addr={cand.match_addr}"
                )
                return KeyResult(
                    key=cand.key,
                    strategy=self.name,
                    candidates_scanned=i + 1,
                    meta={
                        "db_path": str(sample_db_path),
                        "version": process.version_str,
                        "match_addr": cand.match_addr,
                        "total_matches": n_matches,
                        "total_unique": len(unique),
                    },
                )

        raise NoValidKeyError(
            f"FridaDirect: {len(unique)} unique candidate(s), none matched."
        )
