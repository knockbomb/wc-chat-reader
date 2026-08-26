"""Chat log query endpoint."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, time
from typing import Literal

from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse, Response

from wc_chat_reader.api.deps import get_repository, require_auth
from wc_chat_reader.db.repository import Repository
from wc_chat_reader.db.schema import Message

router = APIRouter(prefix="/api/v1", tags=["chatlog"])

_DATE_FMT = "%Y-%m-%d"


def _parse_time_range(
    time_expr: str | None,
) -> tuple[datetime | None, datetime | None]:
    if not time_expr:
        return None, None
    if "~" in time_expr:
        a, b = time_expr.split("~", 1)
        return _one(a), _one(b, end=True)
    return _one(time_expr), _one(time_expr, end=True)


def _one(s: str, *, end: bool = False) -> datetime | None:
    s = s.strip()
    if not s:
        return None
    try:
        d = datetime.strptime(s, _DATE_FMT)
    except ValueError:
        return None
    if end:
        return datetime.combine(d.date(), time(23, 59, 59, 999999))
    return d


@router.get(
    "/chatlog",
    response_model=None,
    dependencies=[Depends(require_auth)],
)
def get_chatlog(
    time_range: str | None = Query(
        default=None,
        alias="time",
        description="Date range: YYYY-MM-DD or YYYY-MM-DD~YYYY-MM-DD",
    ),
    talker: str | None = Query(default=None),
    sender: str | None = Query(default=None),
    keyword: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=10000),
    offset: int = Query(default=0, ge=0),
    output_format: Literal["json", "text", "csv"] = Query(
        default="text", alias="format"
    ),
    repo: Repository = Depends(get_repository),
) -> Response:
    t_from, t_to = _parse_time_range(time_range)
    messages = repo.get_messages(
        talker=talker,
        sender=sender,
        keyword=keyword,
        time_from=t_from,
        time_to=t_to,
        limit=limit,
        offset=offset,
    )

    if output_format == "json":
        return Response(
            content=_to_json(messages),
            media_type="application/json; charset=utf-8",
        )
    if output_format == "csv":
        return Response(
            content=_to_csv(messages).encode("utf-8"),
            media_type="text/csv; charset=utf-8",
        )
    return PlainTextResponse(_to_text(messages))


def _to_json(messages: list[Message]) -> bytes:
    payload = [m.model_dump(mode="json") for m in messages]
    return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")


def _to_csv(messages: list[Message]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["time", "talker", "sender", "is_self", "type", "content"])
    for m in messages:
        w.writerow(
            [
                m.time.isoformat(),
                m.talker,
                m.sender or "",
                int(m.is_self),
                m.type,
                m.content,
            ]
        )
    return buf.getvalue()


def _to_text(messages: list[Message]) -> str:
    lines: list[str] = []
    for m in messages:
        head = f"{m.time:%Y-%m-%d %H:%M:%S} [{m.talker}]"
        if m.sender:
            head += f" <{m.sender_name or m.sender}>"
        lines.append(f"{head}: {m.content}")
    return "\n".join(lines)
