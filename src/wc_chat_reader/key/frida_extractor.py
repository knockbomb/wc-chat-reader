"""Frida-based key extraction (opt-in fallback).

Hooks SQLCipher's ``sqlite3_key`` / ``sqlite3_key_v2`` C functions inside the
running WeChat process. Because we intercept the API call the SQLCipher
library itself makes when unlocking the database, this technique is largely
immune to WeChat's memory-layout changes — it will keep working as long as
WeChat keeps using the SQLCipher library.

**Auto-trigger**: after the hooks are installed, the injected script looks
for an exported ``sqlite3_open`` / ``sqlite3_open_v2`` and calls it on the
sample database, forcing WeChat's SQLCipher layer to invoke
``sqlite3_key`` immediately.  This removes the need for the user to
manually interact with WeChat (open a chat, browse Moments, …) while the
hook is waiting.

Requires the optional ``frida`` extra:

    pip install -e '.[frida]'

Frida attaches with ptrace-like privileges; on Windows this means running
under an administrator account.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any

from wc_chat_reader.core.exceptions import (
    KeyExtractionError,
    NoValidKeyError,
)
from wc_chat_reader.core.logger import get_logger
from wc_chat_reader.key.base import KeyExtractor, KeyResult
from wc_chat_reader.key.validator import KeyValidator

if TYPE_CHECKING:
    from pathlib import Path

    from wc_chat_reader.wechat.process_detector import WeChatProcess

logger = get_logger(__name__)

# JavaScript instrumentation injected into the target process.
#
# WeChat 4.x loads its SQLCipher build inside a WeChat DLL (e.g. a module
# whose name contains "mm" / "xweb" / "wechat"), not necessarily the main
# executable. We therefore hook `sqlite3_key`/`sqlite3_key_v2` in **every**
# already-loaded module via Module.enumerateExports — not just the default
# namespace — and log exactly where each symbol was found so that a "silent
# 30s timeout" becomes an explicit, debuggable signal.
#
# Additionally we locate an exported `sqlite3_open`/`sqlite3_open_v2` so the
# Python side can trigger a database open and force the key hook to fire.
_FRIDA_SCRIPT = r"""
(function () {
    var hookedCount = 0;
    var openFn = null;
    var openFnName = null;
    var modules = Process.enumerateModules();
    send({tag: 'diag', message: 'modules=' + modules.length});

    modules.forEach(function (m) {
        // --- Hook sqlite3_key / sqlite3_key_v2 (key capture) ------------
        ['sqlite3_key', 'sqlite3_key_v2'].forEach(function (name) {
            var addr = null;
            try { addr = Module.findExportByName(m.name, name); } catch (e) {}
            if (!addr) return;
            try {
                Interceptor.attach(addr, {
                    onEnter: function (args) {
                        try {
                            var nKey = args[2].toInt32();
                            send({tag: 'call', source: m.name + '!' + name, nKey: nKey});
                            if (nKey === 32) {
                                var bytes = Memory.readByteArray(args[1], 32);
                                send({tag: 'key', source: m.name + '!' + name}, bytes);
                            }
                        } catch (e) {
                            send({tag: 'error', message: e.message});
                        }
                    }
                });
                hookedCount += 1;
                send({tag: 'hooked', name: m.name + '!' + name});
            } catch (e) {
                send({tag: 'error', message: 'attach ' + m.name + '!' + name + ': ' + e.message});
            }
        });

        // --- Locate sqlite3_open for auto-trigger -----------------------
        if (!openFn) {
            ['sqlite3_open_v2', 'sqlite3_open'].forEach(function (name) {
                if (openFn) return;
                var addr = null;
                try { addr = Module.findExportByName(m.name, name); } catch (e) {}
                if (addr) {
                    openFn = new NativeFunction(addr, 'int', ['pointer', 'int']);
                    openFnName = m.name + '!' + name;
                    send({tag: 'diag', message: 'found ' + name + ' in ' + m.name});
                }
            });
        }
    });

    if (hookedCount === 0) {
        send({tag: 'fatal', message: 'no sqlite3_key export found in any module'});
        return;
    }

    // Export helpers for the Python side.
    rpc.exports = {
        getOpenFnName: function () { return openFnName || ''; },
        triggerOpen: function (dbPathUtf8) {
            if (!openFn) return -1;
            // sqlite3_open(path: const char*, dbOut: sqlite3**)
            // Allocate space for the output pointer.
            var dbOut = Memory.alloc(Process.pointerSize);
            var pathPtr = Memory.allocUtf8String(dbPathUtf8);
            try {
                var rc = openFn(pathPtr, dbOut);
                send({tag: 'diag', message: 'sqlite3_open rc=' + rc});
                return rc;
            } catch (e) {
                send({tag: 'error', message: 'triggerOpen: ' + e.message});
                return -1;
            }
        },
    };

    send({tag: 'ready', hooked: hookedCount, hasOpen: !!openFn, openName: openFnName || ''});
})();
"""


class FridaExtractor(KeyExtractor):
    """Hook-based extractor. Requires the optional ``frida`` package."""

    name = "frida-sqlite3_key"
    priority = 50  # Only runs if faster memory scanners fail

    def __init__(
        self,
        timeout_s: float = 30.0,
        auto_trigger: bool = True,
    ) -> None:
        self._timeout_s = timeout_s
        self._auto_trigger = auto_trigger

    def supports(self, process: WeChatProcess) -> bool:
        try:
            # Function-level import is intentional: frida is an optional
            # dependency; a top-level import would break the CLI for users
            # who have not installed the [frida] extra.
            import frida  # type: ignore[import-not-found]  # noqa: PLC0415, F401
        except ImportError:
            return False
        return True

    def unsupported_reason(self, process: WeChatProcess) -> str | None:
        try:
            import frida  # type: ignore[import-not-found]  # noqa: PLC0415, F401
        except ImportError:
            return "frida package is not installed (pip install 'wc-chat-reader[frida]')"
        return None

    # Wait up to this long for the injected script to report `ready`/`fatal`.
    _READY_TIMEOUT_S = 10.0

    def extract(
        self,
        process: WeChatProcess,
        sample_db_path: Path | None = None,
    ) -> KeyResult:
        try:
            import frida  # type: ignore[import-not-found]  # noqa: PLC0415
        except ImportError as exc:
            raise KeyExtractionError(
                "frida is not installed. Install with: pip install "
                "-e '.[frida]'"
            ) from exc

        if sample_db_path is None:
            raise KeyExtractionError(
                "FridaExtractor requires a sample_db_path for validation"
            )
        validator = KeyValidator(sample_db_path, process.version)

        key_holder: dict[str, bytes] = {}
        ready = threading.Event()
        no_export = threading.Event()
        done = threading.Event()

        def on_message(msg: dict[str, Any], data: bytes | None) -> None:
            payload = msg.get("payload") or {}
            tag = payload.get("tag")
            if tag == "key" and data and len(data) == 32:
                if validator.validate(data):
                    key_holder["key"] = data
                    done.set()
            elif tag == "ready":
                has_open = payload.get("hasOpen", False)
                open_name = payload.get("openName", "")
                logger.info(
                    f"FridaExtractor: hooked {payload.get('hooked')} export(s)"
                    + (f", sqlite3_open found ({open_name})" if has_open else ", no sqlite3_open export")
                )
                ready.set()
            elif tag == "fatal":
                # No module exports sqlite3_key — bail out immediately instead
                # of waiting out the full timeout for a call that never comes.
                no_export.set()
                done.set()
            elif tag in ("hooked", "diag", "call"):
                logger.debug(f"Frida script: {payload}")
            elif tag == "error":
                logger.debug(f"Frida script: {payload.get('message')}")

        try:
            session = frida.attach(process.pid)
        except frida.PermissionDeniedError as exc:  # pragma: no cover
            raise KeyExtractionError(
                "Frida attach denied — run as Administrator"
            ) from exc

        try:
            script = session.create_script(_FRIDA_SCRIPT)
            script.on("message", on_message)
            script.load()
            # Wait for the script to either confirm it hooked something
            # (`ready`) or report that no module exports the symbol (`fatal`).
            done.wait(timeout=self._READY_TIMEOUT_S)
            if no_export.is_set():
                raise NoValidKeyError(
                    "FridaExtractor: no module in the target process exports "
                    f"sqlite3_key/sqlite3_key_v2 (pid={process.pid}). WeChat "
                    "4.1.13+ statically links SQLCipher, so this hook strategy "
                    "cannot work on this build — the V4 memory scanner needs "
                    "an updated pattern instead."
                )
            if not ready.is_set():
                # Neither ready nor fatal arrived — the script itself may have
                # failed to load. Surface that rather than burning 30 more sec.
                raise NoValidKeyError(
                    f"FridaExtractor: script produced no 'ready' signal within "
                    f"{self._READY_TIMEOUT_S}s; hooking likely failed. Re-run "
                    "with `-v` to see the injected script's diagnostics."
                )

            # --- Auto-trigger: call sqlite3_open to force key capture -----
            if self._auto_trigger and not done.is_set():
                open_name = ""
                try:
                    open_name = script.exports_sync.get_open_fn_name()
                except Exception:
                    pass
                if open_name:
                    logger.info(
                        f"FridaExtractor: auto-trigger via {open_name} "
                        f"on {sample_db_path}"
                    )
                    try:
                        rc = script.exports_sync.trigger_open(str(sample_db_path))
                        logger.debug(f"FridaExtractor: sqlite3_open rc={rc}")
                    except Exception as exc:
                        logger.warning(
                            f"FridaExtractor: auto-trigger call failed: {exc}"
                        )
                    # Give the hook a short window to capture the key.
                    done.wait(timeout=5.0)

            # Final wait: either auto-trigger already got the key, or we
            # fall back to waiting for natural WeChat DB activity.
            if "key" not in key_holder:
                remaining = self._timeout_s
                if self._auto_trigger:
                    # Auto-trigger already waited ~5s; reduce the natural
                    # wait accordingly so total time stays bounded.
                    remaining = max(5.0, self._timeout_s - 5.0)
                done.wait(timeout=remaining)
        finally:
            with _SuppressFridaErrors():
                session.detach()

        if "key" not in key_holder:
            raise NoValidKeyError(
                f"FridaExtractor: hooks were live but no valid key was seen "
                f"within {self._timeout_s}s. Interact with WeChat (open a "
                "chat, browse Moments) to force a database open, then retry."
            )
        return KeyResult(
            key=key_holder["key"],
            strategy=self.name,
            candidates_scanned=1,
            meta={"db_path": str(sample_db_path)},
        )


class _SuppressFridaErrors:
    """Silence frida errors that can happen at process teardown."""

    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type: object, *_: object) -> bool | None:
        # Swallow any exception thrown by the inner block (session.detach()
        # after the process has exited raises noisy but harmless errors).
        return exc_type is not None
