"""Frida-based key extraction (opt-in fallback).

Hooks SQLCipher's ``sqlite3_key`` / ``sqlite3_key_v2`` C functions inside the
running WeChat process. Because we intercept the API call the SQLCipher
library itself makes when unlocking the database, this technique is largely
immune to WeChat's memory-layout changes — it will keep working as long as
WeChat keeps using the SQLCipher library.

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

# JavaScript instrumentation injected into the target process. Hooks
# `sqlite3_key` and `sqlite3_key_v2`, captures the pKey argument (32 bytes),
# and emits it back to Python via `send()`.
#
# We deliberately log every step: if neither symbol is exported (common when
# SQLCipher is statically linked into Weixin.exe, as in WeChat 4.1.13+), we
# surface that loudly instead of silently waiting for a timeout that will
# never fire.
_FRIDA_SCRIPT = r"""
(function () {
    function hookOnce(name) {
        const addr = Module.findExportByName(null, name);
        if (!addr) {
            send({tag: 'diag', message: name + ' not exported'});
            return false;
        }
        Interceptor.attach(addr, {
            onEnter: function (args) {
                // sqlite3_key(sqlite3*, const void *pKey, int nKey)
                //                       args[1]         args[2]
                try {
                    const nKey = args[2].toInt32();
                    send({tag: 'call', source: name, nKey: nKey});
                    if (nKey === 32) {
                        const bytes = Memory.readByteArray(args[1], 32);
                        send({tag: 'key', source: name}, bytes);
                    }
                } catch (e) {
                    send({tag: 'error', message: e.message});
                }
            }
        });
        send({tag: 'hooked', name: name});
        return true;
    }
    const ok1 = hookOnce('sqlite3_key');
    const ok2 = hookOnce('sqlite3_key_v2');
    if (!ok1 && !ok2) {
        send({tag: 'fatal', message: 'neither sqlite3_key nor sqlite3_key_v2 is exported'});
    }
})();
"""


class FridaExtractor(KeyExtractor):
    """Hook-based extractor. Requires the optional ``frida`` package."""

    name = "frida-sqlite3_key"
    priority = 50  # Only runs if faster memory scanners fail

    def __init__(self, timeout_s: float = 30.0) -> None:
        self._timeout_s = timeout_s

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
        no_export = threading.Event()
        done = threading.Event()

        def on_message(msg: dict[str, Any], data: bytes | None) -> None:
            payload = msg.get("payload") or {}
            tag = payload.get("tag")
            if tag == "key" and data and len(data) == 32:
                if validator.validate(data):
                    key_holder["key"] = data
                    done.set()
            elif tag == "fatal":
                # Symbols not exported — bail out immediately instead of
                # waiting out the full timeout for a call that never comes.
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
            done.wait(timeout=self._timeout_s)
        finally:
            with _SuppressFridaErrors():
                session.detach()

        if no_export.is_set():
            raise NoValidKeyError(
                "FridaExtractor: neither sqlite3_key nor sqlite3_key_v2 is "
                f"exported by the process (pid={process.pid}). WeChat 4.1.13+ "
                "links SQLCipher statically, so this hook strategy cannot work "
                "on this build — the V4 memory scanner needs an updated "
                "pattern instead."
            )
        if "key" not in key_holder:
            raise NoValidKeyError(
                f"FridaExtractor: no valid key seen within {self._timeout_s}s. "
                "Try interacting with WeChat to trigger a database open."
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
