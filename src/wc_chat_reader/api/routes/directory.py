"""Contacts, chatrooms and sessions endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from wc_chat_reader.api.deps import get_repository, require_auth
from wc_chat_reader.api.schemas import (
    ChatRoomOut,
    ContactOut,
    SessionOut,
)
from wc_chat_reader.db.repository import Repository

router = APIRouter(prefix="/api/v1", tags=["directory"])


@router.get(
    "/contact",
    response_model=list[ContactOut],
    dependencies=[Depends(require_auth)],
)
def list_contacts(repo: Repository = Depends(get_repository)) -> list[ContactOut]:
    return [ContactOut(**c.model_dump()) for c in repo.list_contacts()]


@router.get(
    "/chatroom",
    response_model=list[ChatRoomOut],
    dependencies=[Depends(require_auth)],
)
def list_chatrooms(repo: Repository = Depends(get_repository)) -> list[ChatRoomOut]:
    return [ChatRoomOut(**c.model_dump()) for c in repo.list_chatrooms()]


@router.get(
    "/session",
    response_model=list[SessionOut],
    dependencies=[Depends(require_auth)],
)
def list_sessions(
    limit: int = 200,
    repo: Repository = Depends(get_repository),
) -> list[SessionOut]:
    return [SessionOut(**s.model_dump()) for s in repo.list_sessions(limit=limit)]
