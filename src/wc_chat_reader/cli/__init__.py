"""Typer-based command-line interface.

Sub-commands:

- ``wcreader key`` — extract and print the AES key
- ``wcreader decrypt`` — decrypt WeChat databases into an output directory
- ``wcreader serve`` — run the HTTP + MCP server
- ``wcreader info`` — list detected WeChat processes and versions
"""

from wc_chat_reader.cli.main import app

__all__ = ["app"]
