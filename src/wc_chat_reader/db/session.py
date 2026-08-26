"""SQLite connection management.

Databases are opened read-only using URI mode. This prevents accidental
mutations even if a bug in the query layer would attempt one.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from wc_chat_reader.core.exceptions import DatabaseError

if TYPE_CHECKING:
    from collections.abc import Iterator


def open_readonly(path: Path) -> sqlite3.Connection:
    """Open a decrypted SQLite DB in read-only mode."""
    path = Path(path).resolve()
    if not path.exists():
        raise DatabaseError(f"Database not found: {path}")
    # file:...?mode=ro forces SQLite to refuse writes.
    uri = f"file:{path.as_posix()}?mode=ro&immutable=1"
    conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def readonly_connection(path: Path) -> Iterator[sqlite3.Connection]:
    """Read-only connection as a context manager."""
    conn = open_readonly(path)
    try:
        yield conn
    finally:
        conn.close()


def table_exists(conn: sqlite3.Connection, name: str) -> bool:
    cur = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1",
        (name,),
    )
    return cur.fetchone() is not None
