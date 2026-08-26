"""High-level query API used by the HTTP and MCP layers.

The Repository takes a directory of decrypted databases (as produced by the
decrypt layer), figures out which physical files hold what, and exposes a
version-agnostic query surface.

Adding v4 schema support means writing a sibling ``_v4.py`` that implements
the same protocol; the Repository dispatches via a strategy object.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Sequence

from wc_chat_reader.core.constants import WeChatVersion
from wc_chat_reader.core.exceptions import DatabaseError
from wc_chat_reader.core.logger import get_logger
from wc_chat_reader.db.parsers import parse_content
from wc_chat_reader.db.schema import (
    ChatRoom,
    ChatRoomMember,
    Contact,
    Message,
    Session,
)
from wc_chat_reader.db.session import readonly_connection, table_exists

logger = get_logger(__name__)


@dataclass(slots=True)
class Repository:
    """Query API over a directory of decrypted WeChat databases."""

    data_dir: Path
    version: WeChatVersion

    _contact_index: dict[str, Contact] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.data_dir = Path(self.data_dir)
        if not self.data_dir.exists():
            raise DatabaseError(f"data_dir does not exist: {self.data_dir}")

    # ----- Contacts / chatrooms --------------------------------------------

    def list_contacts(self) -> list[Contact]:
        contacts: list[Contact] = []
        for db_path in self._contact_dbs():
            with readonly_connection(db_path) as conn:
                contacts.extend(self._read_contacts(conn))
        self._contact_index = {c.user_name: c for c in contacts}
        return contacts

    def list_chatrooms(self) -> list[ChatRoom]:
        rooms: list[ChatRoom] = []
        for db_path in self._contact_dbs():
            with readonly_connection(db_path) as conn:
                rooms.extend(self._read_chatrooms(conn))
        return rooms

    def list_sessions(self, limit: int = 200) -> list[Session]:
        for db_path in self._session_dbs():
            with readonly_connection(db_path) as conn:
                sessions = list(self._read_sessions(conn, limit=limit))
                if sessions:
                    return sessions
        return []

    # ----- Messages ---------------------------------------------------------

    def get_messages(
        self,
        talker: str | None = None,
        sender: str | None = None,
        keyword: str | None = None,
        time_from: datetime | None = None,
        time_to: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Message]:
        """Fetch messages across every message-carrying database.

        Shards are queried with ``LIMIT limit+offset OFFSET 0`` so the sort
        step below has all the rows it needs; ``offset`` is applied exactly
        once at the very end.
        """
        per_shard_limit = limit + offset
        pool: list[Message] = []
        for db_path in self._message_dbs():
            try:
                with readonly_connection(db_path) as conn:
                    pool.extend(
                        self._read_messages(
                            conn,
                            talker=talker,
                            sender=sender,
                            keyword=keyword,
                            time_from=time_from,
                            time_to=time_to,
                            limit=per_shard_limit,
                        )
                    )
            except (DatabaseError, sqlite3.OperationalError) as exc:
                logger.warning(f"Skipping {db_path}: {exc}")
                continue

        # Sort ascending by time. Filter out messages with the sentinel
        # datetime.min (which _row_to_message uses for corrupt timestamps)
        # to prevent them polluting the top of the page.
        pool = [m for m in pool if m.time != datetime.min]
        pool.sort(key=lambda m: m.time)
        return pool[offset : offset + limit]

    # ----- Discovery -------------------------------------------------------

    def _contact_dbs(self) -> list[Path]:
        if self.version == WeChatVersion.V3:
            # v3 keeps MicroMsg.db either at the root (decrypted output) or
            # under Msg/ (raw WeChat data dir). rglob covers both layouts.
            candidates = list(self.data_dir.rglob("MicroMsg.db"))
        else:
            candidates = list(self.data_dir.rglob("contact.db")) + list(
                self.data_dir.rglob("contact_*.db")
            )
        return sorted({p for p in candidates if p.is_file()})

    def _message_dbs(self) -> list[Path]:
        if self.version == WeChatVersion.V3:
            # v3 message shards live under Multi/. MicroMsg.db carries some
            # message-adjacent tables too.
            paths = sorted(self.data_dir.rglob("MSG*.db"))
            for micromsg in self.data_dir.rglob("MicroMsg.db"):
                if micromsg not in paths:
                    paths.append(micromsg)
            return paths
        return sorted(self.data_dir.rglob("message*.db"))

    def _session_dbs(self) -> list[Path]:
        if self.version == WeChatVersion.V3:
            return list(self.data_dir.rglob("MicroMsg.db"))
        return sorted(self.data_dir.rglob("session*.db"))

    # ----- Row parsing -----------------------------------------------------

    def _read_contacts(self, conn: sqlite3.Connection) -> list[Contact]:
        table = None
        for name in ("Contact", "contact"):
            if table_exists(conn, name):
                table = name
                break
        if table is None:
            return []
        rows = conn.execute(f"SELECT * FROM {table}").fetchall()  # noqa: S608
        out: list[Contact] = []
        for r in rows:
            keys = r.keys()
            user_name = _first(r, keys, ("UserName", "user_name", "username")) or ""
            if not user_name:
                continue
            nickname = _first(r, keys, ("NickName", "nickname", "nick_name")) or ""
            remark = _first(r, keys, ("Remark", "remark")) or ""
            alias = _first(r, keys, ("Alias", "alias"))
            is_chatroom = str(user_name).endswith("@chatroom")
            display = str(remark) or str(nickname) or str(alias or user_name)
            out.append(
                Contact(
                    user_name=str(user_name),
                    nickname=str(nickname),
                    remark=str(remark),
                    alias=str(alias) if alias is not None else None,
                    display_name=display,
                    is_chatroom=is_chatroom,
                )
            )
        return out

    def _read_chatrooms(self, conn: sqlite3.Connection) -> list[ChatRoom]:
        rooms: list[ChatRoom] = []
        if not table_exists(conn, "ChatRoom"):
            return rooms
        rows = conn.execute("SELECT * FROM ChatRoom").fetchall()
        for r in rows:
            keys = r.keys()
            user_name = _first(r, keys, ("ChatRoomName", "user_name")) or ""
            nickname = _first(r, keys, ("DisplayName", "nickname")) or ""
            owner = _first(r, keys, ("RoomOwner", "owner")) or ""
            members_raw = _first(
                r, keys, ("UserNameList", "member_list", "members")
            ) or ""
            members = [
                ChatRoomMember(user_name=m)
                for m in str(members_raw).split(";")
                if m
            ]
            rooms.append(
                ChatRoom(
                    user_name=str(user_name),
                    nickname=str(nickname),
                    display_name=str(nickname) or str(user_name),
                    owner=str(owner),
                    members=members,
                )
            )
        return rooms

    def _read_sessions(
        self, conn: sqlite3.Connection, limit: int
    ) -> list[Session]:
        if not table_exists(conn, "Session"):
            return []
        rows = conn.execute(
            "SELECT * FROM Session ORDER BY LastReadedCreateTime DESC LIMIT ?",
            (limit,),
        ).fetchall()
        out: list[Session] = []
        for r in rows:
            keys = r.keys()
            user_name = _first(r, keys, ("strUsrName", "user_name")) or ""
            if not user_name:
                continue
            display = _first(r, keys, ("strNickName", "display_name")) or user_name
            last_time_raw = _first(
                r, keys, ("LastReadedCreateTime", "last_time")
            )
            last_time = _to_dt(last_time_raw)
            last_msg = _first(r, keys, ("strContent", "last_message")) or ""
            unread = _first(r, keys, ("UnReadCount", "unread")) or 0
            out.append(
                Session(
                    user_name=str(user_name),
                    display_name=str(display),
                    last_time=last_time,
                    last_message=str(last_msg),
                    unread=int(unread or 0),
                    is_chatroom=str(user_name).endswith("@chatroom"),
                )
            )
        return out

    def _read_messages(
        self,
        conn: sqlite3.Connection,
        *,
        talker: str | None,
        sender: str | None,
        keyword: str | None,
        time_from: datetime | None,
        time_to: datetime | None,
        limit: int,
    ) -> list[Message]:
        tables = _list_message_tables(conn)
        if not tables:
            return []

        clauses: list[str] = []
        params: list[object] = []
        if talker:
            clauses.append("(StrTalker = ? OR StrTalker LIKE ?)")
            params.extend([talker, f"%{talker}%"])
        if keyword:
            clauses.append("StrContent LIKE ?")
            params.append(f"%{_escape_like(keyword)}%")
        if time_from:
            clauses.append("CreateTime >= ?")
            params.append(int(time_from.timestamp()))
        if time_to:
            clauses.append("CreateTime <= ?")
            params.append(int(time_to.timestamp()))
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""

        out: list[Message] = []
        for tbl in tables:
            # Table names come from sqlite_master (whitelisted), not user input.
            q = (
                f"SELECT * FROM {tbl}{where} "
                f"ORDER BY CreateTime DESC LIMIT ?"  # noqa: S608
            )
            try:
                rows = conn.execute(q, [*params, limit]).fetchall()
            except sqlite3.OperationalError as exc:
                # e.g., missing column referenced in WHERE clause.
                logger.debug(f"Table {tbl}: {exc}")
                continue
            for r in rows:
                out.append(self._row_to_message(r))
            if len(out) >= limit:
                break
        return out

    def _row_to_message(self, row: sqlite3.Row) -> Message:
        keys = row.keys()
        seq = _safe_int(_first(row, keys, ("MsgSvrID", "seq", "MesLocalID")))
        ts = _to_dt(_first(row, keys, ("CreateTime", "time"))) or datetime.min
        talker = str(_first(row, keys, ("StrTalker", "talker")) or "")
        content = str(_first(row, keys, ("StrContent", "content")) or "")
        msg_type = _safe_int(_first(row, keys, ("Type", "type")))
        sub_type = _safe_int(_first(row, keys, ("SubType", "sub_type")))
        is_self = bool(_safe_int(_first(row, keys, ("IsSender", "is_self"))))
        return Message(
            seq=seq,
            time=ts,
            talker=talker,
            is_chatroom=talker.endswith("@chatroom"),
            is_self=is_self,
            type=msg_type,
            sub_type=sub_type,
            content=content,
            parsed=parse_content(msg_type, content),
        )


# ----- Module helpers -------------------------------------------------------


def _list_message_tables(conn: sqlite3.Connection) -> list[str]:
    """Discover message tables. Handles v3 (``MSG``) and v4 (``Msg_<hash>``)."""
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND (name = 'MSG' OR name LIKE 'Msg\\_%' ESCAPE '\\')"
    ).fetchall()
    return [r[0] for r in rows]


def _first(
    row: sqlite3.Row,
    keys: Sequence[str],
    candidates: tuple[str, ...],
) -> object:
    """Return the first value in ``row`` matching one of ``candidates``.

    Handles case variations because v3 tables use CamelCase and v4 tables
    use snake_case in different databases. Returns ``None`` if no match.
    """
    key_set = set(keys)
    for c in candidates:
        if c in key_set:
            return row[c]
    lowered = {k.lower(): k for k in key_set}
    for c in candidates:
        actual = lowered.get(c.lower())
        if actual is not None:
            return row[actual]
    return None


def _to_dt(v: object) -> datetime | None:
    if v is None or v == "":
        return None
    try:
        return datetime.fromtimestamp(int(v))  # type: ignore[arg-type]
    except (TypeError, ValueError, OSError):
        return None


def _safe_int(v: object) -> int:
    """Coerce column values to int, returning 0 for anything nonsensical."""
    if v is None or v == "":
        return 0
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return v
    if isinstance(v, (str, bytes)):
        try:
            return int(v)
        except (TypeError, ValueError):
            return 0
    return 0


def _escape_like(pattern: str) -> str:
    """Escape SQL LIKE metacharacters. Use with ``ESCAPE '\\'``."""
    return pattern.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
