"""Pydantic models describing HTTP request/response shapes.

Kept separate from ``db.schema`` so we can evolve the wire format without
touching the internal data model.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class MessageOut(BaseModel):
    seq: int
    time: datetime
    talker: str
    talker_name: str = ""
    is_chatroom: bool = False
    sender: str = ""
    sender_name: str = ""
    is_self: bool = False
    type: int
    sub_type: int = 0
    content: str
    parsed: dict[str, Any] = Field(default_factory=dict)


class ContactOut(BaseModel):
    user_name: str
    nickname: str = ""
    remark: str = ""
    display_name: str = ""
    is_chatroom: bool = False


class ChatRoomMemberOut(BaseModel):
    user_name: str
    display_name: str = ""


class ChatRoomOut(BaseModel):
    user_name: str
    nickname: str = ""
    display_name: str = ""
    owner: str = ""
    members: list[ChatRoomMemberOut] = Field(default_factory=list)


class SessionOut(BaseModel):
    user_name: str
    display_name: str = ""
    last_time: datetime | None = None
    last_message: str = ""
    unread: int = 0
    is_chatroom: bool = False


class HealthOut(BaseModel):
    status: str
    version: str
    wechat_version: str | None = None
    data_dir: str | None = None
