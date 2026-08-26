"""Domain-level data models exposed by the query API.

Wire-format quirks (BLOB fields, protobuf blobs, XML payloads) are hidden
from callers — parsers pre-process them into structured fields.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class Contact(BaseModel):
    """A single WeChat contact (person or public account)."""

    model_config = {"frozen": True}

    user_name: str = Field(description="Internal identifier (wxid_...)")
    alias: str | None = None
    nickname: str = ""
    remark: str = ""
    display_name: str = Field(
        default="",
        description="Preferred display name — remark > nickname > user_name.",
    )
    is_friend: bool = True
    is_chatroom: bool = False


class ChatRoomMember(BaseModel):
    """A member of a group chat."""

    model_config = {"frozen": True}

    user_name: str
    display_name: str = ""


class ChatRoom(BaseModel):
    """A group chat."""

    model_config = {"frozen": True}

    user_name: str = Field(description="Chatroom identifier (...@chatroom)")
    nickname: str = ""
    display_name: str = ""
    owner: str = ""
    members: list[ChatRoomMember] = Field(default_factory=list)


class Message(BaseModel):
    """A single chat message."""

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
    content: str = ""
    parsed: dict[str, Any] = Field(default_factory=dict)


class Session(BaseModel):
    """A conversation summary (talker + last-message metadata)."""

    model_config = {"frozen": True}

    user_name: str
    display_name: str = ""
    last_time: datetime | None = None
    last_message: str = ""
    unread: int = 0
    is_chatroom: bool = False


class Media(BaseModel):
    """A referenced media resource."""

    model_config = {"frozen": True}

    kind: str  # "image" | "video" | "file" | "voice"
    md5: str = ""
    path: str = ""
    size: int = 0
    duration_ms: int = 0
    mime_type: str = ""
