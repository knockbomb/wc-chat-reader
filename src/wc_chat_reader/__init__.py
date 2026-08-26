"""WeChat local chat history reader.

Modular architecture:
- core: configuration, logging, exceptions, constants
- wechat: process detection, version resolution
- key: multi-strategy key extraction (memory scanner, Frida)
- decrypt: SQLCipher database decryption (v3: PBKDF2-SHA1, v4: PBKDF2-SHA512)
- db: parsed data access (messages, contacts, chatrooms)
- api: FastAPI HTTP server
- mcp: Model Context Protocol server for AI assistants
- cli: Typer-based command-line entry point
"""

from wc_chat_reader.core.constants import VERSION

__version__ = VERSION
__all__ = ["__version__"]
