"""Health and status endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from wc_chat_reader.api.deps import AppState, get_state
from wc_chat_reader.api.schemas import HealthOut
from wc_chat_reader.core.constants import VERSION

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthOut)
def health(state: AppState = Depends(get_state)) -> HealthOut:
    return HealthOut(
        status="ok" if state.repository is not None else "waiting",
        version=VERSION,
        wechat_version=state.wechat_version_str,
        data_dir=state.data_dir,
    )
