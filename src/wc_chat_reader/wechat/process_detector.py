"""Detect the running WeChat process and infer its version.

Approach:
1. Scan running processes via ``psutil`` for known WeChat executables.
2. Read the executable's file version metadata (Windows: VerQueryValue).
3. Locate loaded modules (WeChatWin.dll vs. Weixin.dll) to disambiguate v3/v4.
4. Discover the on-disk data directory by inspecting open file handles or
   walking configured defaults.

The detector is deliberately read-only: it never opens the process with write
privilege, never allocates in the target, and never uses any technique that
could crash or destabilize WeChat.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import psutil

from wc_chat_reader.core.constants import (
    WECHAT_PROCESS_NAMES,
    WECHAT_V3_DLL,
    WECHAT_V4_DLL,
    WeChatVersion,
)
from wc_chat_reader.core.exceptions import WeChatNotFoundError
from wc_chat_reader.core.logger import get_logger

if TYPE_CHECKING:
    from collections.abc import Iterator

logger = get_logger(__name__)


@dataclass(slots=True, frozen=True)
class WeChatProcess:
    """A discovered WeChat process.

    Immutable snapshot — re-run detection to get an updated view.
    """

    pid: int
    exe_path: Path
    version: WeChatVersion
    version_str: str
    data_dir: Path | None
    modules: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_online(self) -> bool:
        """Rough liveness check — the data_dir being resolvable implies login."""
        return self.data_dir is not None and self.data_dir.exists()


def find_wechat_processes() -> list[WeChatProcess]:
    """Return every WeChat process currently running.

    Empty list means no WeChat is running; caller decides whether that's fatal.
    """
    results: list[WeChatProcess] = []
    for proc in _iter_wechat_processes():
        try:
            info = _inspect(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            logger.debug(f"Skipping pid={proc.pid}: {exc}")
            continue
        if info is not None:
            results.append(info)
    logger.info(f"Found {len(results)} WeChat process(es)")
    return results


def require_wechat_process() -> WeChatProcess:
    """Return the first running WeChat process or raise WeChatNotFoundError."""
    procs = find_wechat_processes()
    if not procs:
        raise WeChatNotFoundError(
            "No running WeChat process found. Please launch WeChat and log in."
        )
    return procs[0]


def _iter_wechat_processes() -> Iterator[psutil.Process]:
    for proc in psutil.process_iter(["pid", "name", "exe"]):
        try:
            name = proc.info.get("name") or ""
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        if name in WECHAT_PROCESS_NAMES:
            yield proc


def _inspect(proc: psutil.Process) -> WeChatProcess | None:
    exe = proc.exe()
    if not exe:
        return None
    exe_path = Path(exe)

    modules = _list_modules(proc)
    version = _classify_version(modules)
    version_str = _read_file_version(exe_path)
    data_dir = _find_data_dir(proc)

    return WeChatProcess(
        pid=proc.pid,
        exe_path=exe_path,
        version=version,
        version_str=version_str,
        data_dir=data_dir,
        modules=tuple(modules),
    )


def _list_modules(proc: psutil.Process) -> list[str]:
    """Enumerate loaded DLLs. Returns file basenames only, lowercased."""
    try:
        maps = proc.memory_maps(grouped=False)
    except (psutil.AccessDenied, NotImplementedError, OSError):
        return []
    seen: set[str] = set()
    out: list[str] = []
    for entry in maps:
        path = getattr(entry, "path", None)
        if not path:
            continue
        base = Path(path).name.lower()
        if base not in seen:
            seen.add(base)
            out.append(base)
    return out


def _classify_version(modules: list[str]) -> WeChatVersion:
    lowered = {m.lower() for m in modules}
    if WECHAT_V4_DLL.lower() in lowered:
        return WeChatVersion.V4
    if WECHAT_V3_DLL.lower() in lowered:
        return WeChatVersion.V3
    return WeChatVersion.UNKNOWN


def _read_file_version(exe: Path) -> str:
    """Read file version metadata. Best-effort — returns empty string on failure."""
    try:
        import win32api  # type: ignore[import-not-found]
    except ImportError:
        return ""
    try:
        info = win32api.GetFileVersionInfo(str(exe), "\\")
        ms = info["FileVersionMS"]
        ls = info["FileVersionLS"]
        return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"
    except Exception as exc:
        logger.debug(f"GetFileVersionInfo({exe}) failed: {exc}")
        return ""


def _find_data_dir(proc: psutil.Process) -> Path | None:
    """Locate the WeChat user data directory by inspecting open files.

    Heuristic: scan open file handles for a path containing a WeChat data
    directory marker. Uses the longest common ancestor of matching files to
    narrow down the actual root.
    """
    try:
        files = proc.open_files()
    except (psutil.AccessDenied, NotImplementedError):
        return None

    markers = ("WeChat Files", "xwechat_files", "Weixin Files")
    candidates: list[Path] = []
    for f in files:
        p = Path(f.path)
        parts_lower = [part.lower() for part in p.parts]
        for marker in markers:
            marker_lower = marker.lower()
            for idx, part in enumerate(parts_lower):
                if part == marker_lower:
                    # Take one level below the marker (the account subdir)
                    if idx + 1 < len(p.parts):
                        candidates.append(Path(*p.parts[: idx + 2]))
                    else:
                        candidates.append(Path(*p.parts[: idx + 1]))
    if not candidates:
        return None
    # Prefer the most frequently referenced candidate.
    most_common = Counter(candidates).most_common(1)[0][0]
    return most_common if most_common.exists() else None
