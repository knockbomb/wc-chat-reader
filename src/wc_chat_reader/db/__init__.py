"""Parsed data access layer.

- ``schema`` — Pydantic models (Message, Contact, ChatRoom, Session, Media).
- ``session`` — SQLite connection helpers with WAL/read-only bindings.
- ``repository`` — high-level query API used by the HTTP + MCP servers.
- ``parsers`` — message-type-specific content parsers (text, image, voice,
  quote, link, mini-program, etc.).
"""

from wc_chat_reader.db.repository import Repository
from wc_chat_reader.db.schema import ChatRoom, Contact, Message, Session

__all__ = ["ChatRoom", "Contact", "Message", "Repository", "Session"]
