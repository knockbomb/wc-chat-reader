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

Runtime key struct layout (verified on WeChat 4.1.15.13)::

    [key_ptr (8B)] [flags=0 (8B)] [key_size=32 (8B)] [...]

The relaxed pattern ``[0, 32]`` matches the runtime struct in **writable**
heap memory.  The AES-256 key pointer is at ``ptr@-8`` from the pattern.

The full pattern ``[0, 32, 47]`` is a compile-time constant in Weixin.dll's
``.rdata`` section — diagnostic only, does NOT yield key candidates.

Only runs on Windows against a V4 process when the optional ``frida``
extra is installed.  Requires elevation (admin) for process injection.
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

# ── Patterns ──────────────────────────────────────────────────────────
# PRIMARY: relaxed [0, 32] — matches runtime heap struct
_V4_RELAXED_HEX = "00 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00"

# DIAGNOSTIC: full [0, 32, 47] — matches .rdata constant (no key nearby)
_V4_FULL_HEX = "00 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00 2f 00 00 00 00 00 00 00"

# Frida script:
# Phase 0 (PRIMARY): Relaxed pattern [0, 32] in RW heap ranges.
#   The runtime key struct lives on the heap. ptr@-8 from the pattern
#   points to the 32-byte AES key.
# Phase 1 (DIAGNOSTIC): Full pattern [0, 32, 47] in Weixin.dll module.
#   Found in .rdata — logs match count but expects 0 key candidates.
_FRIDA_SCAN_SCRIPT = r"""
(function () {
    'use strict';
    var RELAXED = %(relaxed_q)s;
    var FULL = %(full_q)s;
    var KEY_SIZE = 32;
    var MIN_PTR = 0x10000;
    var MAX_PTR = 0x7fffffffffffd;
    var sent = 0;
    var relaxedMatches = 0;
    var fullMatches = 0;

    // ptr@-8 first — verified working on WeChat 4.1.15.13
    var PTR_OFFSETS = [-8, -16, 24, 32, 40, -24, -32, 48, 56, -40, -48];
    var INLINE_OFFSETS = [-40, -32, -24, -16, 24, 32, 40, 48, 56, 64];

    var DLL_NAME = %(module_q)s;

    function isValidPtr(p) {
        return p >= MIN_PTR && p <= MAX_PTR;
    }

    function tryReadKey(addr) {
        try {
            var key = addr.readByteArray(KEY_SIZE);
            if (key && key.byteLength === KEY_SIZE) return key;
        } catch (e) {}
        return null;
    }

    function isLikelyKey(data) {
        if (!data) return false;
        var bytes = new Uint8Array(data);
        var counts = new Array(256);
        for (var i = 0; i < 256; i++) counts[i] = 0;
        var nonzero = 0;
        for (var i = 0; i < bytes.length; i++) {
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
                var p = counts[i] / bytes.length;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
        }
        if (entropy < 5.0) return false;
        return true;
    }

    function extractCandidates(address, label) {
        PTR_OFFSETS.forEach(function (off) {
            try {
                var ptr = address.add(off).readPointer();
                if (isValidPtr(ptr)) {
                    var key = tryReadKey(ptr);
                    if (key && isLikelyKey(key)) {
                        sent++;
                        send({tag: 'candidate', offset: off, mode: 'ptr',
                              addr: address.toString(), label: label}, key);
                    }
                }
            } catch (e) {}
        });
        INLINE_OFFSETS.forEach(function (off) {
            try {
                var key = tryReadKey(address.add(off));
                if (key && isLikelyKey(key)) {
                    sent++;
                    send({tag: 'candidate', offset: off, mode: 'inline',
                          addr: address.toString(), label: label}, key);
                }
            } catch (e) {}
        });
    }

    send({tag: 'scan_start', message: 'scanning for V4 key (relaxed pattern primary)'});

    // ═══ Phase 0 (PRIMARY): Relaxed pattern [0, 32] in RW heap ═══
    var ranges = Process.enumerateRanges('rw-');
    send({tag: 'diag', message: ranges.length + ' rw- range(s)'});
    ranges.forEach(function (range) {
        if (range.size < 64 * 1024) return;  // skip tiny regions
        try {
            Memory.scan(range.base, range.size, RELAXED, {
                onMatch: function (address, sz) {
                    relaxedMatches++;
                    extractCandidates(address, 'heap');
                },
                onComplete: function () {}
            });
        } catch (e) {}
    });
    send({tag: 'progress', phase: 'relaxed-rw', matches: relaxedMatches, candidates: sent});

    // ═══ Phase 1 (DIAGNOSTIC): Full pattern in Weixin.dll module ═══
    var dllModule = Process.findModuleByName(DLL_NAME);
    if (dllModule) {
        send({tag: 'diag', message: DLL_NAME + ' base=0x' + dllModule.base.toString(16) +
              ' size=' + (dllModule.size/1024/1024).toFixed(1) + ' MB'});
        try {
            Memory.scan(dllModule.base, dllModule.size, FULL, {
                onMatch: function (address, sz) {
                    fullMatches++;
                },
                onComplete: function () {}
            });
        } catch (e) {}
        send({tag: 'progress', phase: 'full-module (diag)', matches: fullMatches, candidates: sent});
    }

    send({
        tag: 'scan_done',
        relaxed: relaxedMatches,
        full: fullMatches,
        candidates: sent,
        module: dllModule ? DLL_NAME : 'not found',
    });
})();
""" % {
    "relaxed_q": '"%s"' % _V4_RELAXED_HEX,
    "full_q": '"%s"' % _V4_FULL_HEX,
    "module_q": '"Weixin.dll"',
}


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
    ``ReadProcessMemory`` calls.

    Primary strategy: relaxed pattern ``[0, 32]`` in RW heap ranges with
    ``ptr@-8`` key extraction.  Full pattern ``[0, 32, 47]`` in Weixin.dll
    module is logged as diagnostic only.
    """

    name = "frida-memory-scan"
    priority = 5  # Run BEFORE v4-memory-scan (10) and codec hook (20).

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
                phase = payload.get("phase", "?")
                m = payload.get("matches", 0)
                c = payload.get("candidates", 0)
                logger.info(
                    f"FridaMemoryScan: [{phase}] {m} match(es), {c} candidate(s)"
                )
            elif tag == "diag":
                logger.info(f"FridaMemoryScan: {payload.get('message', '')}")
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

        relaxed_m = progress_info.get("relaxed", 0)
        full_m = progress_info.get("full", 0)
        logger.info(
            f"FridaMemoryScan: scan complete — "
            f"relaxed={relaxed_m}, full(diag)={full_m}, "
            f"{len(candidates)} candidate(s) extracted"
        )

        if not candidates:
            raise NoValidKeyError(
                f"FridaMemoryScan: relaxed pattern matched {relaxed_m} time(s) "
                f"but no usable key candidates extracted. The runtime struct "
                f"layout may have changed in WeChat {process.version_str}."
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
