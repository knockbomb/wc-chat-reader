"""Windows memory scanner.

Uses ``ReadProcessMemory`` via ``ctypes`` (no external DLLs). This design lets
us open a target process with only ``PROCESS_VM_READ | PROCESS_QUERY_INFORMATION``
— strictly read-only, matching the "least privilege" security principle.

Iterates ``VirtualQueryEx`` over the target's address space and yields readable
private committed regions to the caller.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING

from wc_chat_reader.core.exceptions import (
    InsufficientPrivilegeError,
    ProcessError,
)
from wc_chat_reader.core.logger import get_logger

if TYPE_CHECKING:
    from collections.abc import Iterator

logger = get_logger(__name__)

# Windows constants
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
PAGE_READWRITE = 0x04
PAGE_READONLY = 0x02
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40

READABLE_PROTECTIONS = (
    PAGE_READWRITE
    | PAGE_READONLY
    | PAGE_WRITECOPY
    | PAGE_EXECUTE_READ
    | PAGE_EXECUTE_READWRITE
)


class _MEMORY_BASIC_INFORMATION(ctypes.Structure):
    """MEMORY_BASIC_INFORMATION as defined in winbase.h."""

    _fields_ = (
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("__alignment1", wt.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
        ("__alignment2", wt.DWORD),
    )


@dataclass(slots=True, frozen=True)
class MemoryRegion:
    """A single memory region snapshot."""

    base: int
    size: int
    protect: int
    state: int
    type_: int

    @property
    def is_readable(self) -> bool:
        return bool(self.protect & READABLE_PROTECTIONS)

    @property
    def is_private_committed(self) -> bool:
        return self.state == MEM_COMMIT and self.type_ == MEM_PRIVATE


class WindowsMemoryScanner:
    """Read-only scanner for another process's virtual memory."""

    __slots__ = ("_handle", "_kernel32", "_pid")

    def __init__(self, pid: int) -> None:
        if sys.platform != "win32":
            raise RuntimeError("WindowsMemoryScanner requires Windows")
        self._pid = pid
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._configure_prototypes()
        self._handle = self._open_process(pid)

    def _configure_prototypes(self) -> None:
        k = self._kernel32
        k.OpenProcess.argtypes = (wt.DWORD, wt.BOOL, wt.DWORD)
        k.OpenProcess.restype = wt.HANDLE
        k.CloseHandle.argtypes = (wt.HANDLE,)
        k.CloseHandle.restype = wt.BOOL
        k.VirtualQueryEx.argtypes = (
            wt.HANDLE,
            ctypes.c_void_p,
            ctypes.POINTER(_MEMORY_BASIC_INFORMATION),
            ctypes.c_size_t,
        )
        k.VirtualQueryEx.restype = ctypes.c_size_t
        k.ReadProcessMemory.argtypes = (
            wt.HANDLE,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        )
        k.ReadProcessMemory.restype = wt.BOOL

    def _open_process(self, pid: int) -> int:
        h = self._kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
        )
        if not h:
            err = ctypes.get_last_error()
            if err == 5:  # ERROR_ACCESS_DENIED
                raise InsufficientPrivilegeError(
                    f"OpenProcess(pid={pid}) denied (error 5). "
                    f"Please run as Administrator."
                )
            raise ProcessError(
                f"OpenProcess(pid={pid}) failed with error {err}"
            )
        return h

    def close(self) -> None:
        if self._handle:
            self._kernel32.CloseHandle(self._handle)
            self._handle = 0

    def __enter__(self) -> WindowsMemoryScanner:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def iter_regions(
        self,
        min_addr: int = 0x10000,
        max_addr: int = 0x7FFFFFFFFFFF,
        min_size: int = 64 * 1024,
    ) -> Iterator[MemoryRegion]:
        """Yield ``MemoryRegion`` snapshots meeting the given filters."""
        cur = min_addr
        mbi = _MEMORY_BASIC_INFORMATION()
        while cur < max_addr:
            ret = self._kernel32.VirtualQueryEx(
                self._handle,
                ctypes.c_void_p(cur),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            )
            if ret == 0:
                break
            region = MemoryRegion(
                base=mbi.BaseAddress or 0,
                size=int(mbi.RegionSize),
                protect=int(mbi.Protect),
                state=int(mbi.State),
                type_=int(mbi.Type),
            )
            if (
                region.size >= min_size
                and region.is_readable
                and region.is_private_committed
            ):
                yield region
            # Advance past this region — always use the reported base+size to
            # avoid infinite loops when RegionSize < min_size.
            next_addr = region.base + region.size
            if next_addr <= cur:
                cur += 0x1000
            else:
                cur = next_addr

    def iter_rw_all(
        self,
        min_size: int = 64 * 1024,
    ) -> Iterator[MemoryRegion]:
        """Yield ALL committed RW regions (any type, including MEM_MAPPED).

        Unlike ``iter_regions()`` which filters to MEM_PRIVATE only (heap),
        this includes MEM_MAPPED regions — DLL .data sections, shared memory,
        etc.  Used by V4BroadScanExtractor to search the full writable
        address space.
        """
        cur = 0x10000
        max_addr = 0x7FFFFFFFFFFF
        mbi = _MEMORY_BASIC_INFORMATION()
        while cur < max_addr:
            ret = self._kernel32.VirtualQueryEx(
                self._handle,
                ctypes.c_void_p(cur),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            )
            if ret == 0:
                break
            region = MemoryRegion(
                base=mbi.BaseAddress or 0,
                size=int(mbi.RegionSize),
                protect=int(mbi.Protect),
                state=int(mbi.State),
                type_=int(mbi.Type),
            )
            # Only require: committed, readable, writable, min_size.
            # No filter on type (MEM_PRIVATE vs MEM_MAPPED vs MEM_IMAGE).
            is_rw = bool(
                region.protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE)
            )
            if (
                region.state == MEM_COMMIT
                and region.size >= min_size
                and is_rw
            ):
                yield region
            next_addr = region.base + region.size
            if next_addr <= cur:
                cur += 0x1000
            else:
                cur = next_addr

    def read(self, addr: int, size: int) -> bytes | None:
        """Read ``size`` bytes at ``addr``. Returns None on failure."""
        buf = (ctypes.c_ubyte * size)()
        bytes_read = ctypes.c_size_t(0)
        ok = self._kernel32.ReadProcessMemory(
            self._handle,
            ctypes.c_void_p(addr),
            ctypes.byref(buf),
            size,
            ctypes.byref(bytes_read),
        )
        if not ok or bytes_read.value == 0:
            return None
        return bytes(buf[: bytes_read.value])


@contextmanager
def open_scanner(pid: int) -> Iterator[WindowsMemoryScanner]:
    """Context manager wrapper. Prefer this over instantiating directly."""
    scanner = WindowsMemoryScanner(pid)
    try:
        yield scanner
    finally:
        scanner.close()
