"""Diagnostic tool: analyze WeChat V4 memory layout to find the correct key pattern.

Usage:
    python tools/diagnose_v4_pattern.py [--pid PID]

Requires frida and the WeChat process to be running.
Outputs detailed memory layout analysis so we can update the V4 pattern.
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
import time

# The old V4 pattern (3 x uint64 LE: 0, 32, 47)
OLD_PATTERN_HEX = "00 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00 2f 00 00 00 00 00 00 00"

# Relaxed patterns: keep first two fields (0, 32) but allow third to vary
RELAXED_PATTERNS = {
    "0_32_any": "00 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ??",
    # Also try: just the key_size field (0x20 = 32)
    "just_32": "20 00 00 00 00 00 00 00",
    # Key size as 4-byte LE
    "32_4byte": "20 00 00 00",
}

# The known codec signature for 4.1.6.15 - 4.1.99.99
CODEC_SIGNATURE = "24 50 48 C7 45 00 FE FF FF FF 44 89 CF 44 89 C3 49 89 D6 48 89 CE 48 89"

_DIAGNOSTIC_SCRIPT = r"""
(function () {
    'use strict';

    var results = {
        weixin_module: null,
        codec_sig_match: null,
        relaxed_pattern_matches: {},
        data_section_scan: {},
        nearby_memory: [],
    };

    // 1. Find Weixin.dll
    var weixin = null;
    Process.enumerateModules().forEach(function (m) {
        if (m.name.toLowerCase().indexOf('weixin') !== -1 || m.name.toLowerCase().indexOf('wechat') !== -1) {
            weixin = m;
            results.weixin_module = {
                name: m.name,
                base: m.base.toString(),
                size: m.size,
                sizeMB: (m.size / 1024 / 1024).toFixed(1),
            };
        }
    });
    send({tag: 'info', message: 'Weixin.dll: ' + (weixin ? weixin.base + ' size=' + weixin.size : 'NOT FOUND')});

    // 2. Scan for the codec signature in Weixin.dll
    if (weixin) {
        var codecPattern = '24 50 48 C7 45 00 FE FF FF FF 44 89 CF 44 89 C3 49 89 D6 48 89 CE 48 89';
        var codecMatches = [];
        try {
            Memory.scan(weixin.base, weixin.size, codecPattern, {
                onMatch: function (addr, size) {
                    codecMatches.push(addr.toString());
                },
                onComplete: function () {}
            });
        } catch (e) {
            send({tag: 'error', message: 'codec scan: ' + e.message});
        }
        results.codec_sig_match = {
            pattern: codecPattern,
            matches: codecMatches.length,
            addresses: codecMatches,
        };
        send({tag: 'info', message: 'Codec signature: ' + codecMatches.length + ' match(es) at ' + codecMatches.join(', ')});

        // 3. Read memory around the codec hook point
        if (codecMatches.length > 0) {
            var hookAddr = ptr(codecMatches[0]);
            // Read 256 bytes before and after the hook point
            try {
                var before = hookAddr.sub(256).readByteArray(256);
                var at_ = hookAddr.readByteArray(64);
                var after = hookAddr.add(64).readByteArray(192);
                results.nearby_memory.push({
                    label: 'codec_hook_context',
                    hook_addr: hookAddr.toString(),
                    before_hex: arrayBufferToHex(before),
                    at_hex: arrayBufferToHex(at_),
                    after_hex: arrayBufferToHex(after),
                });
            } catch (e) {
                send({tag: 'error', message: 'read nearby: ' + e.message});
            }
        }

        // 4. Scan Weixin.dll .data section for patterns
        // Look for the relaxed pattern [0, 0x20, ??] in .data
        var sections = [];
        try {
            // Parse PE headers to find .data section
            var base = weixin.base;
            var e_lfanew = base.add(0x3C).readU32();
            var peStart = base.add(e_lfanew);
            // COFF header starts after "PE\0\0"
            var coffHeader = peStart.add(4);
            var numSections = coffHeader.add(2).readU16();
            var optHeaderSize = coffHeader.add(16).readU16();
            var sectionStart = coffHeader.add(20).add(optHeaderSize);

            for (var i = 0; i < numSections && i < 50; i++) {
                var sec = sectionStart.add(i * 40);
                var name = sec.readUtf8String(8);
                var vSize = sec.add(8).readU32();
                var vAddr = sec.add(12).readU32();
                var rawSize = sec.add(16).readU32();
                var chars = sec.add(36).readU32();
                sections.push({
                    name: name,
                    vAddr: vAddr,
                    vSize: vSize,
                    rawSize: rawSize,
                    chars: '0x' + chars.toString(16),
                });
            }
        } catch (e) {
            send({tag: 'warn', message: 'PE parse: ' + e.message});
        }

        // 5. Scan .data and .rdata sections for key-like patterns
        sections.forEach(function (sec) {
            if (sec.name !== '.data' && sec.name !== '.rdata') return;
            var secAddr = weixin.base.add(sec.vAddr);
            var secSize = Math.min(sec.vSize, 10 * 1024 * 1024); // cap at 10MB

            // Look for [0*8, 0x20*8, XX*8] pattern (old layout)
            var oldMatches = [];
            try {
                Memory.scan(secAddr, secSize, '00 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00', {
                    onMatch: function (addr) {
                        if (oldMatches.length < 20) {
                            // Read the next 8 bytes (the third field)
                            var thirdField = 'N/A';
                            try { thirdField = addr.add(16).readPointer().toString(); } catch(e) {}
                            // Also read 8 bytes before (possible key pointer)
                            var beforePtr = 'N/A';
                            try { beforePtr = addr.sub(8).readPointer().toString(); } catch(e) {}
                            // And read 32 bytes after the pattern
                            var afterBytes = 'N/A';
                            try { afterBytes = arrayBufferToHex(addr.add(24).readByteArray(32)); } catch(e) {}
                            oldMatches.push({
                                addr: addr.toString(),
                                before_ptr: beforePtr,
                                third_field: thirdField,
                                after_32bytes: afterBytes,
                            });
                        }
                    },
                    onComplete: function () {}
                });
            } catch (e) {}
            results.data_section_scan[sec.name + '_partial_0_32'] = oldMatches.length;

            // Look for just [0x20*8] (key size = 32 as uint64 LE)
            var keySizeMatches = [];
            try {
                Memory.scan(secAddr, secSize, '20 00 00 00 00 00 00 00', {
                    onMatch: function (addr) {
                        if (keySizeMatches.length < 10) {
                            // Read context: 32 bytes before and 64 bytes after
                            var before = 'N/A';
                            try { before = arrayBufferToHex(addr.sub(32).readByteArray(32)); } catch(e) {}
                            var after = 'N/A';
                            try { after = arrayBufferToHex(addr.add(8).readByteArray(64)); } catch(e) {}
                            keySizeMatches.push({
                                addr: addr.toString(),
                                before_32bytes: before,
                                after_64bytes: after,
                            });
                        }
                    },
                    onComplete: function () {}
                });
            } catch (e) {}
            results.data_section_scan[sec.name + '_keysize_32'] = {
                count: keySizeMatches.length,
                samples: keySizeMatches,
            };

            send({tag: 'info', message: sec.name + ': scanned ' + secSize + ' bytes'});
        });
    }

    // 6. Scan ALL RW memory for 32-byte sequences that could be AES keys
    //    (high entropy, non-zero, non-repeating)
    send({tag: 'info', message: 'Scanning RW memory for key-like data...'});
    var keyLikeSamples = [];
    var rwRanges = Process.enumerateRanges('rw-');
    var scannedBytes = 0;
    var maxScan = 256 * 1024 * 1024; // 256MB cap

    for (var r = 0; r < rwRanges.length && scannedBytes < maxScan; r++) {
        var range = rwRanges[r];
        var scanSize = Math.min(range.size, maxScan - scannedBytes);
        scannedBytes += scanSize;

        // Search for sequences of 32 bytes where all bytes are non-zero
        // and have reasonable entropy (not all same value)
        try {
            // Quick heuristic: search for a non-zero 32-byte block preceded by
            // something that looks like a size field (0x20 = 32)
            Memory.scan(range.base, scanSize, '20 00 00 00 00 00 00 00', {
                onMatch: function (addr) {
                    if (keyLikeSamples.length >= 20) return;
                    try {
                        // Read 32 bytes after the size field
                        var candidate = addr.add(8).readByteArray(32);
                        if (candidate && candidate.byteLength === 32) {
                            var bytes = new Uint8Array(candidate);
                            var nonzero = 0;
                            for (var i = 0; i < 32; i++) {
                                if (bytes[i] !== 0) nonzero++;
                            }
                            if (nonzero >= 20 && nonzero <= 32) {
                                // Read 8 bytes before the size field (possible pointer)
                                var beforePtr = 'N/A';
                                try { beforePtr = addr.sub(8).readPointer().toString(); } catch(e) {}
                                keyLikeSamples.push({
                                    addr: addr.toString(),
                                    before_ptr: beforePtr,
                                    key_hex: arrayBufferToHex(candidate),
                                    nonzero_bytes: nonzero,
                                });
                            }
                        }
                    } catch (e) {}
                },
                onComplete: function () {}
            });
        } catch (e) {}
    }

    results.key_like_candidates = {
        scanned_mb: (scannedBytes / 1024 / 1024).toFixed(0),
        count: keyLikeSamples.length,
        samples: keyLikeSamples,
    };

    send({tag: 'info', message: 'Key-like candidates: ' + keyLikeSamples.length + ' (scanned ' + (scannedBytes / 1024 / 1024).toFixed(0) + ' MB)'});

    // 7. Also search for the old V4 pattern with relaxed third field
    send({tag: 'info', message: 'Scanning for relaxed V4 patterns...'});
    var relaxedResults = {};

    // Pattern: [0*8, 0x20*8, ??*8] — first two fields fixed, third varies
    var relaxedMatches = [];
    for (var r2 = 0; r2 < rwRanges.length && relaxedMatches.length < 50; r2++) {
        var range2 = rwRanges[r2];
        if (range2.size < 24) continue;
        try {
            // Scan for [0*8, 0x20*8]
            Memory.scan(range2.base, range2.size, '00 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00', {
                onMatch: function (addr) {
                    if (relaxedMatches.length >= 50) return;
                    var thirdVal = 'N/A';
                    try { thirdVal = addr.add(16).readU64().toString(); } catch(e) {}
                    var beforePtr = 'N/A';
                    try { beforePtr = addr.sub(8).readPointer().toString(); } catch(e) {}
                    // Read 32 bytes after pattern
                    var afterKey = 'N/A';
                    try { afterKey = arrayBufferToHex(addr.add(24).readByteArray(32)); } catch(e) {}
                    // Read 32 bytes at the before-ptr location
                    var atBeforePtr = 'N/A';
                    try {
                        var p = addr.sub(8).readPointer();
                        if (p.compare(0x10000) > 0) {
                            atBeforePtr = arrayBufferToHex(p.readByteArray(32));
                        }
                    } catch(e) {}
                    relaxedMatches.push({
                        addr: addr.toString(),
                        before_ptr: beforePtr,
                        third_field_dec: thirdVal,
                        after_32bytes: afterKey,
                        at_before_ptr: atBeforePtr,
                    });
                },
                onComplete: function () {}
            });
        } catch (e) {}
    }
    results.relaxed_v4_pattern = {
        pattern: '[0*8, 0x20*8, ??*8]',
        count: relaxedMatches.length,
        samples: relaxedMatches.slice(0, 20),
    };

    send({tag: 'info', message: 'Relaxed V4 pattern [0,32,??]: ' + relaxedMatches.length + ' matches'});

    // Final output
    send({tag: 'results', data: results});

    function arrayBufferToHex(buf) {
        if (!buf) return 'null';
        var bytes = new Uint8Array(buf);
        var hex = '';
        for (var i = 0; i < bytes.length; i++) {
            hex += ('0' + bytes[i].toString(16)).slice(-2);
            if (i < bytes.length - 1 && i % 4 === 3) hex += ' ';
        }
        return hex;
    }
})();
"""


def _find_wechat_pid() -> int | None:
    """Find the main WeChat process PID."""
    try:
        from wc_chat_reader.wechat.process_detector import find_wechat_processes
        procs = find_wechat_processes()
        # Prefer V4 process with data_dir
        for p in procs:
            if p.version.name == "V4" and p.data_dir:
                return p.pid
        if procs:
            return procs[0].pid
    except Exception as e:
        print(f"Failed to find WeChat process: {e}")
    return None


def main():
    parser = argparse.ArgumentParser(description="Diagnose V4 key pattern for WeChat")
    parser.add_argument("--pid", type=int, help="WeChat process PID")
    args = parser.parse_args()

    pid = args.pid or _find_wechat_pid()
    if pid is None:
        print("ERROR: No WeChat process found. Make sure WeChat is running.")
        sys.exit(1)

    print(f"Attaching to WeChat PID {pid}...")

    import frida

    try:
        session = frida.attach(pid)
    except frida.PermissionDeniedError:
        print("ERROR: Permission denied. Run as Administrator.")
        sys.exit(1)

    results_holder: list = []
    done = False

    def on_message(msg, data):
        nonlocal done
        payload = msg.get("payload") or {}
        tag = payload.get("tag")
        if tag in ("info", "warn", "error"):
            print(f"  [{tag}] {payload.get('message', '')}")
        elif tag == "results":
            results_holder.append(payload.get("data"))
            done = True

    print("Running diagnostic scan (this may take 30-60 seconds)...\n")
    script = session.create_script(_DIAGNOSTIC_SCRIPT)
    script.on("message", on_message)
    script.load()

    # Wait for results
    timeout = 120
    t0 = time.time()
    while not done and time.time() - t0 < timeout:
        time.sleep(0.5)

    try:
        session.detach()
    except Exception:
        pass

    if not results_holder:
        print("\nERROR: No results received. Script may have timed out.")
        sys.exit(1)

    results = results_holder[0]

    # Save full results
    output_file = "diagnose_v4_results.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\nFull results saved to {output_file}")

    # Print summary
    print("\n" + "=" * 70)
    print("DIAGNOSTIC SUMMARY")
    print("=" * 70)

    if results.get("weixin_module"):
        m = results["weixin_module"]
        print(f"\nWeixin.dll: {m['base']} size={m['sizeMB']}MB")

    if results.get("codec_sig_match"):
        c = results["codec_sig_match"]
        print(f"Codec signature matches: {c['matches']}")
        for addr in c.get("addresses", []):
            print(f"  → {addr}")
    else:
        print("Codec signature: NOT FOUND")

    if results.get("relaxed_v4_pattern"):
        r = results["relaxed_v4_pattern"]
        print(f"\nRelaxed V4 pattern [0, 32, ??]: {r['count']} matches")
        for s in r.get("samples", [])[:5]:
            print(f"  addr={s['addr']}")
            print(f"    before_ptr={s.get('before_ptr')}")
            print(f"    third_field={s.get('third_field_dec')}")
            print(f"    after_32bytes={s.get('after_32bytes', 'N/A')[:80]}")
            print(f"    at_before_ptr={s.get('at_before_ptr', 'N/A')[:80]}")

    if results.get("key_like_candidates"):
        k = results["key_like_candidates"]
        print(f"\nKey-like candidates (0x20 followed by 32 non-zero bytes): {k['count']}")
        print(f"Scanned: {k['scanned_mb']} MB")
        for s in k.get("samples", [])[:5]:
            print(f"  addr={s['addr']} before_ptr={s.get('before_ptr')} nonzero={s.get('nonzero_bytes')}")
            print(f"    key_hex={s.get('key_hex', 'N/A')[:80]}")

    print("\n" + "=" * 70)
    print("Please share the output and/or the diagnose_v4_results.json file")
    print("so we can update the V4 pattern for WeChat 4.1.13.65")
    print("=" * 70)


if __name__ == "__main__":
    main()
