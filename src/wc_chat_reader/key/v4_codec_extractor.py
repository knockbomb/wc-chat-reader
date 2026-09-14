"""Frida codec-hook key extractor for WeChat 4.1.6.14+ (V4).

Why this exists
---------------
WeChat 4.1.13+ statically links SQLCipher, so the symbol-based hook in
``frida_extractor`` (``sqlite3_key`` / ``sqlite3_key_v2``) can never fire:
those symbols are no longer exported by any loaded module.

The database passphrase is nonetheless still presented to an internal WCDB
codec-setup function whenever a database is opened in the running process.
On supported builds we locate that function by scanning ``Weixin.dll`` for a
stable byte signature, then attach a Frida ``Interceptor`` at the resolved
address and read the 32-byte passphrase from the codec descriptor the
function receives (x64 calling-convention-visible layout):

    rdx       -> codec descriptor
    [rdx+0x08]-> 32-byte passphrase pointer
    [rdx+0x10]-> key size (must be 32)

The hook is address-based, so it keeps working across memory-layout changes
as long as the byte signature stays unique in the installed ``Weixin.dll``.
If WeChat shifts the signature in a future build, only the per-version table
``_CODEC_SIGNATURES`` needs an update — no other layer changes. This upholds
the project's "adaptability first" contract: the change stays inside the
``key/`` extraction layer.

Only runs on Windows against a V4 process when the optional ``frida`` extra
is installed. Requires elevation (admin) for process injection, the same
constraint as ``FridaExtractor``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from wc_chat_reader.core.constants import (
    SQLCIPHER_KEY_SIZE,
    WECHAT_V4_DLL,
    WeChatVersion,
)
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


@dataclass(slots=True, frozen=True)
class _CodecSignature:
    """Version-range-specific byte signature locating the codec hook point.

    The signature is fully explicit hex (e.g. ``24 50 48 C7 45 00 ...``) with
    no wildcards — reliable and cheap to scan. ``hook_offset`` is the signed
    number of bytes to add to the matched start to reach the hook site.
    """

    min_version: tuple[int, int, int, int]
    max_version: tuple[int, int, int, int]
    pattern: str
    hook_offset: int


# Verified against the installed 4.1.13.12 build: unique single match.
_CODEC_SIGNATURES: tuple[_CodecSignature, ...] = (
    _CodecSignature(
        min_version=(4, 1, 6, 15),
        max_version=(4, 1, 99, 99),
        pattern=(
            "24 50 48 C7 45 00 FE FF FF FF "
            "44 89 CF 44 89 C3 49 89 D6 48 89 CE 48 89"
        ),
        hook_offset=-3,
    ),
)


def _parse_version(version: str) -> tuple[int, int, int, int]:
    """Parse a dotted version string into a comparable 4-tuple."""
    try:
        nums = [int(x) for x in version.strip().split(".")]
    except (ValueError, AttributeError):
        return (0, 0, 0, 0)
    padded = (nums + [0, 0, 0, 0])[:4]
    return tuple(padded)  # type: ignore[return-value]


def _choose_signature(version: str) -> _CodecSignature | None:
    """Return the first signature whose version range covers ``version``."""
    current = _parse_version(version)
    for sig in _CODEC_SIGNATURES:
        if sig.min_version <= current <= sig.max_version:
            return sig
    return None


# Frida JavaScript injected into the target process.
def _build_frida_script(sig: _CodecSignature) -> str:
    return r"""
(function () {
    'use strict';
    var TARGET_PATTERN = %(pattern_q)s;
    var HOOK_OFFSET = %(hook_offset)d;

    function hexaddr(a) { return a ? '0x' + a.toString(16) : 'null'; }

    var targetModule = Process.findModuleByName(%(module_q)s);
    if (!targetModule) {
        send({tag: 'fatal', message: 'module %(module)s not loaded'});
        return;
    }
    send({tag: 'diag', message: 'module ' + targetModule.name + ' base=' + hexaddr(targetModule.base)});

    var found = [];
    try {
        Memory.scan(targetModule.base, targetModule.size, TARGET_PATTERN, {
            onMatch: function (address, size) { found.push(address); },
            onComplete: function () {
                send({tag: 'scan', count: found.length, sig: TARGET_PATTERN});
                if (found.length !== 1) {
                    send({tag: 'fatal', message: 'codec signature matched ' + found.length + ' times (expected 1)'});
                    return;
                }
                var hookAddr = found[0].add(HOOK_OFFSET);
                send({tag: 'diag', message: 'hook addr=' + hexaddr(hookAddr)});
                try {
                    Interceptor.attach(hookAddr, {
                        onEnter: function (args) {
                            try {
                                var desc = this.context.rdx;
                                if (!desc || desc.isNull()) return;
                                var keySize = desc.add(0x10).readS32();
                                if (keySize !== 32) return;
                                var keyPtr = desc.add(0x08).readPointer();
                                var key = keyPtr.readByteArray(32);
                                send({tag: 'key', key: hexaddr(keyPtr), size: keySize}, key);
                            } catch (e) {
                                send({tag: 'error', message: e.message});
                            }
                        }
                    });
                    send({tag: 'ready', hook: hexaddr(hookAddr), sig: TARGET_PATTERN});
                } catch (e) {
                    send({tag: 'fatal', message: 'attach failed: ' + e.message});
                }
            }
        });
    } catch (e) {
        send({tag: 'fatal', message: 'Memory.scan failed: ' + e.message});
    }
})();
""" % {
        "pattern_q": '"%s"' % sig.pattern,
        "hook_offset": sig.hook_offset,
        "module_q": '"%s"' % WECHAT_V4_DLL,
        "module": WECHAT_V4_DLL,
    }


def _event() -> object:
    import threading  # noqa: PLC0415

    return threading.Event()


class V4CodecExtractor(KeyExtractor):
    """Address-hook extractor for WeChat 4.1.6.14+ builds via Frida."""

    name = "frida-codec-hook"
    priority = 20  # Below in-memory V4 scan (10), above FridaExtractor (50).

    def __init__(self, timeout_s: float = 30.0) -> None:
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
            and _choose_signature(process.version_str) is not None
        )

    def unsupported_reason(self, process: WeChatProcess) -> str | None:
        if process.version != WeChatVersion.V4:
            return f"process version is {process.version.name}, expected V4"
        if not self._frida_available():
            return "frida package is not installed (pip install 'wc-chat-reader[frida]')"
        if _choose_signature(process.version_str) is None:
            return (
                f"no codec signature registered for WeChat {process.version_str}; "
                "add one to _CODEC_SIGNATURES in v4_codec_extractor.py"
            )
        return None

    def extract(
        self,
        process: WeChatProcess,
        sample_db_path: Path | None = None,
    ) -> KeyResult:
        import frida  # local import: optional dependency

        sig = _choose_signature(process.version_str)
        if sig is None:
            raise KeyExtractionError(
                f"no codec signature registered for WeChat {process.version_str}"
            )
        if sample_db_path is None:
            raise KeyExtractionError(
                "V4CodecExtractor requires a sample_db_path for validation"
            )
        validator = KeyValidator(sample_db_path, process.version)

        key_holder: dict[str, bytes] = {}
        ready = _event()
        done = _event()
        fatal_msg: dict[str, str] = {}

        def on_message(msg: dict, data: bytes | None) -> None:
            payload = msg.get("payload") or {}
            tag = payload.get("tag")
            if tag == "key" and data and len(data) == SQLCIPHER_KEY_SIZE:
                if validator.validate(data):
                    key_holder["key"] = data
                    done.set()
            elif tag == "ready":
                ready.set()
            elif tag == "fatal":
                fatal_msg["msg"] = payload.get("message", "unknown fatal")
                done.set()
            elif tag in ("scan", "diag", "error"):
                logger.debug(f"Frida script: {payload}")

        try:
            session = frida.attach(process.pid)
        except frida.PermissionDeniedError as exc:  # pragma: no cover
            raise KeyExtractionError(
                "Frida attach denied — run as Administrator"
            ) from exc

        try:
            script = session.create_script(_build_frida_script(sig))
            script.on("message", on_message)
            script.load()
            # Wait for the script to finish scanning and either attach (ready)
            # or report a fatal scan/attach problem.
            done.wait(timeout=15.0)
            if fatal_msg:
                raise NoValidKeyError(
                    "V4CodecExtractor: " + fatal_msg.get("msg", "unknown fatal")
                )
            if not ready.is_set():
                raise NoValidKeyError(
                    "V4CodecExtractor: script produced no 'ready' signal within 15s"
                )
            # Hooks are live: wait for an actual key capture.
            done.wait(timeout=self._timeout_s)
        finally:
            try:
                session.detach()
            except Exception:  # pragma: no cover - teardown noise
                pass

        if "key" not in key_holder:
            raise NoValidKeyError(
                "V4CodecExtractor: hooks were live but no valid key captured "
                f"within {self._timeout_s}s. Interact with WeChat (open a chat "
                "or restart it) to force a database open, then retry."
            )
        return KeyResult(
            key=key_holder["key"],
            strategy=self.name,
            candidates_scanned=1,
            meta={"db_path": str(sample_db_path), "version": process.version_str},
        )