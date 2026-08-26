"""Model Context Protocol (MCP) server.

Implements the SSE transport described at:
https://spec.modelcontextprotocol.io/specification/basic/transports/

Exposes chat data via a set of typed tools an AI assistant can call:

- ``query_chat`` — fetch messages by talker/time/keyword
- ``list_contacts`` / ``list_chatrooms`` / ``list_sessions`` — directory
- ``get_contact`` — resolve a display name to a wxid
"""

from wc_chat_reader.mcp.server import mcp_router

__all__ = ["mcp_router"]
