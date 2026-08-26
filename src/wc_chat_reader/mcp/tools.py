"""MCP tool definitions.

Each tool is a self-describing callable: (name, schema, handler). The server
exports the schema list in ``tools/list`` and dispatches on ``tools/call``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, time
from typing import Any, Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from wc_chat_reader.db.repository import Repository


@dataclass(slots=True, frozen=True)
class Tool:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[["Repository", dict[str, Any]], Any]


def _parse_date(s: str | None, *, end: bool = False) -> datetime | None:
    if not s:
        return None
    try:
        d = datetime.strptime(s.strip(), "%Y-%m-%d")
    except ValueError:
        return None
    return datetime.combine(d.date(), time(23, 59, 59)) if end else d


def _tool_query_chat(repo: "Repository", args: dict[str, Any]) -> dict[str, Any]:
    time_expr = args.get("time")
    t_from: datetime | None = None
    t_to: datetime | None = None
    if isinstance(time_expr, str) and "~" in time_expr:
        a, b = time_expr.split("~", 1)
        t_from, t_to = _parse_date(a), _parse_date(b, end=True)
    elif isinstance(time_expr, str) and time_expr:
        t_from = _parse_date(time_expr)
        t_to = _parse_date(time_expr, end=True)

    messages = repo.get_messages(
        talker=args.get("talker"),
        sender=args.get("sender"),
        keyword=args.get("keyword"),
        time_from=t_from,
        time_to=t_to,
        limit=int(args.get("limit", 100)),
        offset=int(args.get("offset", 0)),
    )
    return {
        "count": len(messages),
        "messages": [m.model_dump(mode="json") for m in messages],
    }


def _tool_list_contacts(repo: "Repository", _args: dict[str, Any]) -> dict[str, Any]:
    contacts = repo.list_contacts()
    return {"count": len(contacts), "contacts": [c.model_dump() for c in contacts]}


def _tool_list_chatrooms(repo: "Repository", _args: dict[str, Any]) -> dict[str, Any]:
    rooms = repo.list_chatrooms()
    return {"count": len(rooms), "chatrooms": [r.model_dump() for r in rooms]}


def _tool_list_sessions(repo: "Repository", args: dict[str, Any]) -> dict[str, Any]:
    limit = int(args.get("limit", 100))
    sessions = repo.list_sessions(limit=limit)
    return {
        "count": len(sessions),
        "sessions": [s.model_dump(mode="json") for s in sessions],
    }


def _tool_get_contact(repo: "Repository", args: dict[str, Any]) -> dict[str, Any]:
    name = str(args.get("name", "")).lower()
    if not name:
        return {"match": None}
    contacts = repo.list_contacts()
    for c in contacts:
        if (
            c.user_name.lower() == name
            or c.nickname.lower() == name
            or c.remark.lower() == name
        ):
            return {"match": c.model_dump()}
    for c in contacts:
        if name in c.nickname.lower() or name in c.remark.lower():
            return {"match": c.model_dump()}
    return {"match": None}


TOOLS: list[Tool] = [
    Tool(
        name="query_chat",
        description=(
            "Query WeChat messages by talker (wxid/nickname/remark), optional "
            "keyword, and optional date range. Returns messages sorted by time."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "talker": {"type": "string"},
                "sender": {"type": "string"},
                "keyword": {"type": "string"},
                "time": {
                    "type": "string",
                    "description": "YYYY-MM-DD or YYYY-MM-DD~YYYY-MM-DD",
                },
                "limit": {"type": "integer", "minimum": 1, "maximum": 10000, "default": 100},
                "offset": {"type": "integer", "minimum": 0, "default": 0},
            },
            "additionalProperties": False,
        },
        handler=_tool_query_chat,
    ),
    Tool(
        name="list_contacts",
        description="List all WeChat contacts.",
        input_schema={"type": "object", "properties": {}},
        handler=_tool_list_contacts,
    ),
    Tool(
        name="list_chatrooms",
        description="List all group chats the user is in.",
        input_schema={"type": "object", "properties": {}},
        handler=_tool_list_chatrooms,
    ),
    Tool(
        name="list_sessions",
        description="List recent conversations, most recent first.",
        input_schema={
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "minimum": 1, "default": 100},
            },
        },
        handler=_tool_list_sessions,
    ),
    Tool(
        name="get_contact",
        description="Resolve a display name / nickname / remark to a contact.",
        input_schema={
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
        handler=_tool_get_contact,
    ),
]


TOOL_INDEX: dict[str, Tool] = {t.name: t for t in TOOLS}
