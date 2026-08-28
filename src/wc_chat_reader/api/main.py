"""FastAPI application factory.

We build the app with a ``lifespan`` context so state is initialized before
any request lands. The MCP router (SSE) is mounted only when enabled in
settings so the surface area stays minimal by default.
"""

from __future__ import annotations

import ipaddress
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, AsyncIterator

from fastapi import FastAPI

from wc_chat_reader.api.deps import AppState
from wc_chat_reader.api.routes import chatlog, dashboard, directory, health, media
from wc_chat_reader.core.config import Settings, get_settings
from wc_chat_reader.core.constants import VERSION
from wc_chat_reader.core.exceptions import ConfigError
from wc_chat_reader.core.logger import get_logger

if TYPE_CHECKING:
    from wc_chat_reader.db.repository import Repository

logger = get_logger(__name__)


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    logger.info(f"wc-chat-reader {VERSION} starting")
    yield
    logger.info("wc-chat-reader shutting down")


def _assert_local_bind(host: str) -> None:
    """Refuse to serve non-loopback bindings unless explicitly opted out."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Hostname like ``localhost`` — fall through; uvicorn will resolve it.
        if host.lower() != "localhost":
            raise ConfigError(
                f"host={host!r} is not loopback; set bind_local_only=false "
                f"in settings to override"
            )
        return
    if not ip.is_loopback:
        raise ConfigError(
            f"host={host!r} is not loopback; set bind_local_only=false "
            f"in settings to override"
        )


def create_app(
    settings: Settings | None = None,
    repository: "Repository | None" = None,
    wechat_version_str: str | None = None,
    data_dir: str | None = None,
) -> FastAPI:
    """Build a fully-wired FastAPI application."""
    settings = settings or get_settings()
    if settings.bind_local_only:
        _assert_local_bind(settings.http_host)

    app = FastAPI(
        title="WC Chat Reader",
        version=VERSION,
        summary="WeChat local chat history reader with HTTP + MCP APIs",
        lifespan=_lifespan,
    )

    app.state.wcr = AppState(
        settings=settings,
        repository=repository,
        wechat_version_str=wechat_version_str,
        data_dir=data_dir,
    )

    app.include_router(dashboard.router)
    app.include_router(health.router)
    app.include_router(chatlog.router)
    app.include_router(directory.router)
    app.include_router(media.router)

    if settings.enable_mcp:
        from wc_chat_reader.mcp.server import mcp_router

        app.include_router(mcp_router())

    return app
