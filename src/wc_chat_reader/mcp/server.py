"""Minimal MCP JSON-RPC handler + SSE transport.

Enough of the spec is implemented for real MCP clients (Claude Desktop via
mcp-proxy, ChatWise, Cherry Studio) to discover and call tools:

- ``initialize`` — capability handshake
- ``tools/list`` — enumerate tools
- ``tools/call`` — dispatch to a tool handler

The GET /sse endpoint streams SSE events; POST /messages accepts JSON-RPC
messages from the client and puts the reply on the same event stream via
``asyncio.Queue``.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import dataclass, field
from typing import Any, AsyncIterator

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sse_starlette.sse import EventSourceResponse

from wc_chat_reader.api.deps import (
    AppState,
    get_state,
    require_auth,
    resolve_repository,
)
from wc_chat_reader.core.constants import VERSION
from wc_chat_reader.core.exceptions import DatabaseError
from wc_chat_reader.core.logger import get_logger
from wc_chat_reader.mcp.tools import TOOL_INDEX, TOOLS

logger = get_logger(__name__)

PROTOCOL_VERSION = "2025-03-26"


@dataclass(slots=True)
class MCPSession:
    """A single SSE-connected client."""

    session_id: str
    queue: asyncio.Queue[str] = field(default_factory=lambda: asyncio.Queue(maxsize=256))
    initialized: bool = False


_SESSIONS: dict[str, MCPSession] = {}


def _new_session() -> MCPSession:
    sid = uuid.uuid4().hex
    session = MCPSession(session_id=sid)
    _SESSIONS[sid] = session
    return session


def mcp_router() -> APIRouter:
    """Return the FastAPI router hosting the MCP SSE endpoints."""
    router = APIRouter(tags=["mcp"])

    @router.get("/sse", dependencies=[Depends(require_auth)])
    async def sse_endpoint(request: Request) -> EventSourceResponse:
        session = _new_session()
        endpoint = f"/messages?session_id={session.session_id}"

        async def event_stream() -> AsyncIterator[dict[str, Any]]:
            # Per spec: first event tells the client where to POST.
            yield {"event": "endpoint", "data": endpoint}
            try:
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        payload = await asyncio.wait_for(
                            session.queue.get(), timeout=15.0
                        )
                    except asyncio.TimeoutError:
                        # Heartbeat keeps proxies from severing the connection.
                        yield {"event": "ping", "data": ""}
                        continue
                    yield {"event": "message", "data": payload}
            finally:
                _SESSIONS.pop(session.session_id, None)

        return EventSourceResponse(event_stream())

    @router.post("/messages", dependencies=[Depends(require_auth)])
    async def messages_endpoint(
        request: Request,
        session_id: str = Query(..., description="Session ID from the SSE endpoint event."),
        state: AppState = Depends(get_state),
    ) -> dict[str, str]:
        session = _SESSIONS.get(session_id)
        if session is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Unknown session_id: {session_id}",
            )
        try:
            body = await request.json()
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid JSON: {exc}",
            ) from exc
        response = await _handle_message(state, session, body)
        if response is not None:
            await session.queue.put(json.dumps(response, ensure_ascii=False))
        return {"status": "accepted"}

    return router


async def _handle_message(
    state: AppState, session: MCPSession, msg: dict[str, Any]
) -> dict[str, Any] | None:
    """Dispatch a single JSON-RPC message. Returns the reply or None for notifications."""
    method = msg.get("method")
    msg_id = msg.get("id")

    if method == "initialize":
        session.initialized = True
        return _rpc_ok(
            msg_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "serverInfo": {
                    "name": "wc-chat-reader",
                    "version": VERSION,
                },
                "capabilities": {"tools": {}},
            },
        )

    if method == "notifications/initialized":
        return None

    if method == "tools/list":
        return _rpc_ok(
            msg_id,
            {
                "tools": [
                    {
                        "name": t.name,
                        "description": t.description,
                        "inputSchema": t.input_schema,
                    }
                    for t in TOOLS
                ]
            },
        )

    if method == "tools/call":
        params = msg.get("params") or {}
        tool_name = params.get("name", "")
        args = params.get("arguments") or {}
        tool = TOOL_INDEX.get(tool_name)
        if tool is None:
            return _rpc_err(msg_id, -32601, f"Unknown tool: {tool_name}")
        try:
            repo = resolve_repository(state)
        except DatabaseError as exc:
            return _rpc_err(msg_id, -32000, str(exc))
        try:
            result = tool.handler(repo, args)
        except Exception as exc:  # noqa: BLE001 - MCP errors must be reported, not raised
            logger.exception(f"Tool {tool_name} failed")
            return _rpc_err(msg_id, -32000, f"Tool error: {exc}")
        return _rpc_ok(
            msg_id,
            {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(result, ensure_ascii=False, indent=2),
                    }
                ]
            },
        )

    return _rpc_err(msg_id, -32601, f"Method not found: {method}")


def _rpc_ok(msg_id: object, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _rpc_err(msg_id: object, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {"code": code, "message": message},
    }
