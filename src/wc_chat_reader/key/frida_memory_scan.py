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

# Relaxed pattern: just [0, 32] — 16 bytes
_V4_RELAXED_HEX = "00 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00"

# key_size marker: 32 as uint64 LE — 8 bytes
_KEYSIZE_MARKER_HEX = "20 00 00 00 00 00 00 00"

# Frida script: scans Weixin.dll module (ALL sections including .rdata)
# for the pattern, then extracts candidate keys from multiple offsets.
#
# WHY scan the module instead of 'rw-' ranges:
# The codec descriptor [0, 32, 47] is a compile-time constant stored in
# .rdata (PAGE_READONLY), NOT in writable heap or .data sections.
# Process.enumerateRanges('rw-') skips .rdata entirely — that's why the
# old scan returned 0 matches.  Scanning by module covers all sections.
_FRIDA_SCAN_SCRIPT = r"""
(function () {
    'use strict';
    var PATTERN = %(pattern_q)s;
    var RELAXED = %(relaxed_q)s;
    var KEYMARKER = %(keymarker_q)s;
    var KEY_SIZE = 32;
    var MIN_PTR = 0x10000;
    var MAX_PTR = 0x7fffffffffffd;
    var sent = 0;
    var matches = 0;
    var relaxedMatches = 0;
    var markerMatches = 0;

    var PTR_OFFSETS = [-16, -8, 24, 32, 40, -24, -32, 48, 56, -40, -48];
    var INLINE_OFFSETS = [-40, -32, -24, -16, 24, 32, 40, 48, 56, 64, -48, -56, 72, 80];

    var DLL_NAME = %(module_q)s;

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
        // Shannon entropy
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

    function scanForPattern(base, size, pattern, label) {
        var localMatches = 0;
        try {
            Memory.scan(base, size, pattern, {
                onMatch: function (address, sz) {
                    localMatches++;
                    // Pointer-based extraction
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
                                        label: label,
                                    }, key);
                                }
                            }
                        } catch (e) {}
                    });
                    // Inline extraction
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
                                    label: label,
                                }, key);
                            }
                        } catch (e) {}
                    });
                },
                onComplete: function () {}
            });
        } catch (e) {
            send({tag: 'diag', message: label + ' scan error: ' + e.message});
        }
        return localMatches;
    }

    send({tag: 'scan_start', message: 'scanning WeChat modules for V4 key'});

    // === Strategy 1: Scan Weixin.dll module (ALL sections: .text, .rdata, .data) ===
    var dllModule = Process.findModuleByName(DLL_NAME);
    if (dllModule) {
        send({tag: 'diag', message: DLL_NAME + ' base=0x' + dllModule.base.toString(16) + ' size=0x' + dllModule.size.toString(16) + ' (' + (dllModule.size/1024/1024).toFixed(1) + ' MB)'});

        // Phase 1: Full pattern [0, 32, 47]
        matches = scanForPattern(dllModule.base, dllModule.size, PATTERN, 'full');
        send({tag: 'progress', phase: 'full', matches: matches, candidates: sent});

        // Phase 2: Relaxed pattern [0, 32]
        if (sent < 200) {
            relaxedMatches = scanForPattern(dllModule.base, dllModule.size, RELAXED, 'relaxed');
            send({tag: 'progress', phase: 'relaxed', matches: relaxedMatches, candidates: sent});
        }

        // Phase 3: key_size marker (layout-agnostic)
        if (sent < 200) {
            markerMatches = scanForPattern(dllModule.base, dllModule.size, KEYMARKER, 'marker');
            send({tag: 'progress', phase: 'marker', matches: markerMatches, candidates: sent});
        }
    } else {
        send({tag: 'diag', message: DLL_NAME + ' not found, falling back to rw- scan'});
    }

    // === Strategy 2: Also scan RW heap ranges (in case key struct is on heap) ===
    if (sent < 200) {
        var ranges = Process.enumerateRanges('rw-');
        send({tag: 'diag', message: 'scanning ' + ranges.length + ' rw- ranges (heap fallback)'});
        var heapMatches = 0;
        ranges.forEach(function (range) {
            if (range.size < 24) return;
            // Only scan large heap blocks to avoid excessive scanning
            if (range.size < 64 * 1024) return;
            try {
                Memory.scan(range.base, range.size, PATTERN, {
                    onMatch: function (address, sz) {
                        heapMatches++;
                        PTR_OFFSETS.forEach(function (off) {
                            try {
                                var ptr = address.add(off).readPointer();
                                if (isValidPtr(ptr)) {
                                    var key = tryReadKey(ptr);
                                    if (key && isLikelyKey(key)) {
                                        sent++;
                                        send({tag: 'candidate', offset: off, mode: 'ptr', addr: address.toString(), label: 'heap'}, key);
                                    }
                                }
                            } catch (e) {}
                        });
                        INLINE_OFFSETS.forEach(function (off) {
                            try {
                                var key = tryReadKey(address.add(off));
                                if (key && isLikelyKey(key)) {
                                    sent++;
                                    send({tag: 'candidate', offset: off, mode: 'inline', addr: address.toString(), label: 'heap'}, key);
                                }
                            } catch (e) {}
                        });
                    },
                    onComplete: function () {}
                });
            } catch (e) {}
        });
        send({tag: 'progress', phase: 'heap', matches: heapMatches, candidates: sent});
    }

    // === Strategy 3: Scan ALL modules' .data sections for key_size marker ===
    if (sent < 200) {
        var allModules = Process.enumerateModules();
        var dataScanCount = 0;
        allModules.forEach(function (mod) {
            if (sent >= 500) return;
            // Only scan modules with "wechat" or "weixin" in name, or the main exe
            var nameLow = mod.name.toLowerCase();
            if (nameLow.indexOf('wechat') === -1 && nameLow.indexOf('weixin') === -1 && nameLow.indexOf('wcdb') === -1) return;
            dataScanCount++;
            try {
                var secs = Module.enumerateSections(mod.name);
                if (!secs) return;
                secs.forEach(function (sec) {
                    if (sent >= 500) return;
                    // .data section is typically writable
                    if (sec.name && (sec.name === '.data' || sec.name === '.Data')) {
                        scanForPattern(sec.base, sec.size, KEYMARKER, mod.name + '!' + sec.name);
                    }
                });
            } catch (e) {}
        });
        if (dataScanCount > 0) {
            send({tag: 'diag', message: 'scanned .data of ' + dataScanCount + ' wechat-related module(s), total candidates: ' + sent});
        }
    }

    send({
        tag: 'scan_done',
        matches: matches,
        relaxed: relaxedMatches,
        marker: markerMatches,
        candidates: sent,
        module: dllModule ? DLL_NAME : 'not found',
    });
})();
""" % {
    "pattern_q": '"%s"' % _V4_PATTERN_HEX,
    "relaxed_q": '"%s"' % _V4_RELAXED_HEX,
    "keymarker_q": '"%s"' % _KEYSIZE_MARKER_HEX,
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

        full_m = progress_info.get("matches", 0)
        relaxed_m = progress_info.get("relaxed", 0)
        marker_m = progress_info.get("marker", 0)
        logger.info(
            f"FridaMemoryScan: scan complete — "
            f"full={full_m}, relaxed={relaxed_m}, marker={marker_m}, "
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
