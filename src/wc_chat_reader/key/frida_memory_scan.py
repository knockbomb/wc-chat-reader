"""Frida-assisted memory scan extractor for WeChat V4.

Why this exists
---------------
The original ``V4MemoryExtractor`` reads process memory from the *outside*
via ``ReadProcessMemory`` — 4 MB chunks, one syscall per chunk.  For a
process with gigabytes of address space this is slow (10+ minutes) even
with the I/O budget cap.

This extractor attaches Frida to the target process and uses Frida's
``Memory.scan()`` to search *from within* the process.  This is
fundamentally faster because:

1. No cross-process syscall overhead per chunk.
2. Frida's scanner is implemented natively and can process memory at
   near-memcpy speed.
3. We can scan the full address space without a manual I/O budget.

Additionally, WeChat 4.1.13.12 may have changed the codec descriptor
layout, so the key pointer is no longer at a fixed offset before the
pattern.  This extractor tries *multiple* candidate extraction offsets:
before the pattern, after the pattern, and inline within the struct.

Only runs on Windows against a V4 process when the optional ``frida``
extra is installed.  Requires elevation (admin) for process injection.
"""

from __future__ import annotations

import struct
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

# The same 24-byte pattern used by V4MemoryExtractor.
# Three little-endian 64-bit values: 0x00, 0x20 (32), 0x2F (47).
_V4_PATTERN_HEX = "00 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00 2f 00 00 00 00 00 00 00"

# Frida script: scans all RW regions for the pattern, then extracts
# candidate keys from multiple offsets around each match.
#
# Offsets tried (relative to pattern start):
#   -8        : original layout — pointer immediately before pattern
#   +24       : pointer immediately after pattern (layout shifted)
#   +8        : pointer within the pattern (alternative layout)
#   +32       : pointer 8 bytes after pattern end
#   -16       : pointer 8 bytes before the assumed position
#
# For each candidate pointer that looks valid (canonical address range),
# we read 32 bytes and send them back as a 'candidate' message.
_FRIDA_SCAN_SCRIPT = r"""
(function () {
    'use strict';
    var PATTERN = %(pattern_q)s;
    var KEY_SIZE = 32;
    var MIN_PTR = 0x10000;
    var MAX_PTR = 0x7fffffffffffd;
    var sent = 0;
    var matches = 0;

    // Offsets (in bytes) from pattern start to try reading a key pointer.
    // Each offset is where we read an 8-byte LE pointer, then dereference
    // it to get the 32-byte candidate key.
    var PTR_OFFSETS = [-16, -8, 24, 32, 40, -24, -32];

    // Also try reading the key INLINE at fixed offsets from pattern start
    // (no pointer dereference — the key might be embedded in the struct).
    var INLINE_OFFSETS = [24, 32, -32, -24, 40, 48];

    function isValidPtr(p) {
        return p >= MIN_PTR && p <= MAX_PTR;
    }

    function tryReadKey(addr) {
        try {
            var key = addr.readByteArray(KEY_SIZE);
            if (key && key.byteLength === KEY_SIZE) {
                return key;
            }
        } catch (e) {}
        return null;
    }

    function isLikelyKey(data) {
        // Quick heuristic: a valid key should not be all zeros, all 0xFF,
        // or have very low entropy (e.g., repeating pattern).
        if (!data) return false;
        var bytes = new Uint8Array(data);
        var nonzero = 0, high = 0;
        for (var i = 0; i < bytes.length; i++) {
            if (bytes[i] !== 0) nonzero++;
            if (bytes[i] > 0x80) high++;
        }
        // Reject all-zeros, all-0xFF, or extremely skewed distributions.
        if (nonzero === 0 || nonzero === 32) return false;
        if (high === 0 || high === 32) return false;
        return true;
    }

    send({tag: 'scan_start', message: 'scanning RW memory for V4 key pattern'});

    // Enumerate memory ranges — only RW (heap) regions.
    var ranges = Process.enumerateRanges('rw-');
    var totalRanges = ranges.length;
    var scannedRanges = 0;

    send({tag: 'progress', ranges: totalRanges});

    ranges.forEach(function (range) {
        scannedRanges++;
        if (range.size < 24) return;  // too small for pattern

        try {
            Memory.scan(range.base, range.size, PATTERN, {
                onMatch: function (address, size) {
                    matches++;

                    // Strategy 1: pointer-based — read 8 bytes at offset,
                    // dereference as pointer to 32-byte key.
                    PTR_OFFSETS.forEach(function (off) {
                        try {
                            var ptrAddr = address.add(off);
                            var ptr = ptrAddr.readPointer();
                            if (isValidPtr(ptr)) {
                                var key = tryReadKey(ptr);
                                if (key && isLikelyKey(key)) {
                                    sent++;
                                    send({
                                        tag: 'candidate',
                                        offset: off,
                                        mode: 'ptr',
                                        addr: address.toString(),
                                    }, key);
                                }
                            }
                        } catch (e) {}
                    });

                    // Strategy 2: inline — read 32 bytes directly at offset.
                    INLINE_OFFSETS.forEach(function (off) {
                        try {
                            var key = tryReadKey(address.add(off));
                            if (key && isLikelyKey(key)) {
                                sent++;
                                send({
                                    tag: 'candidate',
                                    offset: off,
                                    mode: 'inline',
                                    addr: address.toString(),
                                }, key);
                            }
                        } catch (e) {}
                    });
                },
                onComplete: function () {
                    if (scannedRanges %% 100 === 0 || scannedRanges === totalRanges) {
                        send({
                            tag: 'progress',
                            scanned: scannedRanges,
                            total: totalRanges,
                            matches: matches,
                            sent: sent,
                        });
                    }
                }
            });
        } catch (e) {
            // Range may have been unmapped between enumerate and scan.
        }
    });

    send({
        tag: 'scan_done',
        matches: matches,
        candidates: sent,
        ranges: totalRanges,
    });
})();
""" % {"pattern_q": '"%s"' % _V4_PATTERN_HEX}


def _event() -> threading.Event:
    return threading.Event()


@dataclass(slots=True, frozen=True)
class _Candidate:
    """A candidate key received from the Frida scanner."""

    key: bytes
    offset: int
    mode: str  # 'ptr' or 'inline'
    addr: str


class FridaMemoryScanExtractor(KeyExtractor):
    """Frida-assisted in-process memory scan for V4.

    Uses Frida's native ``Memory.scan()`` to search the target process's
    memory from within — dramatically faster than cross-process
    ``ReadProcessMemory`` calls.  Tries multiple struct-layout offsets to
    handle WeChat versions that changed the codec descriptor layout.
    """

    name = "frida-memory-scan"
    priority = 5  # Run BEFORE the original v4-memory-scan (10) and codec hook (20).

    def __init__(self, timeout_s: float = 300.0) -> None:
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
                "FridaMemoryScanExtractor requires a sample_db_path for validation"
            )

        validator = KeyValidator(sample_db_path, process.version)
        candidates: list[_Candidate] = []
        scan_done = _event()
        fatal_msg: dict[str, str] = {}
        progress_info: dict[str, int] = {}

        def on_message(msg: dict, data: bytes | None) -> None:
            payload = msg.get("payload") or {}
            tag = payload.get("tag")
            if tag == "candidate" and data and len(data) == SQLCIPHER_KEY_SIZE:
                candidates.append(
                    _Candidate(
                        key=bytes(data),
                        offset=payload.get("offset", 0),
                        mode=payload.get("mode", "?"),
                        addr=payload.get("addr", "?"),
                    )
                )
            elif tag == "scan_done":
                progress_info.update(payload)
                scan_done.set()
            elif tag == "progress":
                scanned = payload.get("scanned", 0)
                total = payload.get("ranges", payload.get("total", 0))
                matches = payload.get("matches", 0)
                sent = payload.get("sent", 0)
                if total > 0:
                    pct = scanned * 100 // total
                    logger.debug(
                        f"FridaMemoryScan: {pct}% ({scanned}/{total} ranges), "
                        f"{matches} pattern matches, {sent} candidates"
                    )
            elif tag == "scan_start":
                logger.info(f"FridaMemoryScan: {payload.get('message', '')}")
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

            # Wait for the scan to complete.
            scan_done.wait(timeout=self._timeout_s)
        finally:
            try:
                session.detach()
            except Exception:
                pass

        if fatal_msg:
            raise KeyExtractionError(
                f"FridaMemoryScan: {fatal_msg['msg']}"
            )

        total_matches = progress_info.get("matches", len(candidates))
        logger.info(
            f"FridaMemoryScan: scan complete — {total_matches} pattern match(es), "
            f"{len(candidates)} candidate(s) extracted"
        )

        if not candidates:
            raise NoValidKeyError(
                f"FridaMemoryScan: pattern matched {total_matches} time(s) but "
                "no usable key candidates could be extracted. The codec descriptor "
                "layout may have changed in this WeChat version."
            )

        # Validate candidates.  Log progress every 100 validations.
        validated = 0
        for i, cand in enumerate(candidates):
            if validator.validate(cand.key):
                logger.info(
                    f"FridaMemoryScan: valid key found! "
                    f"offset={cand.offset}, mode={cand.mode}, "
                    f"addr={cand.addr}, after {i + 1} validation(s)"
                )
                return KeyResult(
                    key=cand.key,
                    strategy=self.name,
                    candidates_scanned=i + 1,
                    meta={
                        "db_path": str(sample_db_path),
                        "version": process.version_str,
                        "offset": cand.offset,
                        "mode": cand.mode,
                        "addr": cand.addr,
                        "total_candidates": len(candidates),
                    },
                )
            validated += 1
            if validated % 100 == 0:
                logger.debug(
                    f"FridaMemoryScan: validated {validated}/{len(candidates)} candidates"
                )

        raise NoValidKeyError(
            f"FridaMemoryScan: {len(candidates)} candidate(s) validated, "
            f"none matched. Pattern offsets may need updating for "
            f"WeChat {process.version_str}."
        )
