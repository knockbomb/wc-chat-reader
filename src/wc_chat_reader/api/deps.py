"""FastAPI dependency wiring.

Bundles the shared ``AppState`` container so every request handler can reach
the ``Repository``, ``Settings`` and other resources without threading them
through function signatures.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from fastapi import Depends, Header, HTTPException, Request, status

from wc_chat_reader.core.config import Settings
from wc_chat_reader.core.exceptions import DatabaseError

if TYPE_CHECKING:
    from wc_chat_reader.db.repository import Repository


@dataclass(slots=True)
class AppState:
    """Runtime container attached to the FastAPI ``app.state``."""

    settings: Settings
    repository: "Repository | None" = None
    wechat_version_str: str | None = None
    data_dir: str | None = None


def get_state(request: Request) -> AppState:
    state: AppState = request.app.state.wcr
    return state


def get_settings_dep(state: AppState = Depends(get_state)) -> Settings:
    return state.settings


def resolve_repository(state: AppState) -> "Repository":
    """Non-Depends helper: return the repo or raise ``DatabaseError``.

    Callable from any context (MCP handlers, tests, background tasks) — not
    just FastAPI request scope.
    """
    if state.repository is None:
        raise DatabaseError(
            "Repository is not initialized. Start the server with "
            "--data-dir pointing at a directory of decrypted databases, "
            "or run `wcreader decrypt` first."
        )
    return state.repository


def get_repository(state: AppState = Depends(get_state)) -> "Repository":
    """FastAPI dependency wrapper around ``resolve_repository``."""
    try:
        return resolve_repository(state)
    except DatabaseError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc


def require_auth(
    state: AppState = Depends(get_state),
    authorization: str | None = Header(default=None),
) -> None:
    token = state.settings.api_token
    if token is None:
        return
    if authorization != f"Bearer {token}":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header",
        )
