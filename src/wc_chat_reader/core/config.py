"""Configuration via pydantic-settings.

Settings resolution order (highest wins):
1. Constructor arguments
2. Environment variables prefixed with ``WCR_``
3. ``.env`` file in the working directory
4. Defaults defined here
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from wc_chat_reader.core.constants import (
    DEFAULT_HTTP_HOST,
    DEFAULT_HTTP_PORT,
    Platform,
)


class Settings(BaseSettings):
    """Application-wide settings."""

    model_config = SettingsConfigDict(
        env_prefix="WCR_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ---- Directories -------------------------------------------------------
    work_dir: Path = Field(
        default_factory=lambda: Path.cwd() / "wechat_data",
        description="Directory holding decrypted databases and extracted media.",
    )
    data_dir: Path | None = Field(
        default=None,
        description=(
            "Path to the WeChat user data directory. If None, auto-detected "
            "from the running WeChat process."
        ),
    )

    # ---- Server ------------------------------------------------------------
    http_host: str = Field(default=DEFAULT_HTTP_HOST)
    http_port: int = Field(default=DEFAULT_HTTP_PORT, ge=1, le=65535)
    enable_mcp: bool = Field(default=True)

    # ---- Behavior ----------------------------------------------------------
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_file: Path | None = None
    auto_decrypt: bool = Field(
        default=False,
        description="Automatically decrypt new database segments on the fly.",
    )
    key_extract_timeout_s: float = Field(default=30.0, gt=0.0)
    max_workers: int = Field(default=8, ge=1, le=64)

    # ---- Security ----------------------------------------------------------
    bind_local_only: bool = Field(
        default=True,
        description=(
            "If True, refuse to bind the HTTP server on non-loopback interfaces."
        ),
    )
    api_token: str | None = Field(
        default=None,
        description="Optional bearer token required on every HTTP request.",
    )

    @field_validator("work_dir")
    @classmethod
    def _ensure_work_dir(cls, v: Path) -> Path:
        v = Path(v).expanduser().resolve()
        v.mkdir(parents=True, exist_ok=True)
        return v

    @field_validator("http_host")
    @classmethod
    def _validate_host(cls, v: str) -> str:
        return v.strip() or DEFAULT_HTTP_HOST

    @property
    def platform(self) -> Platform:
        if sys.platform == "win32":
            return Platform.WINDOWS
        if sys.platform == "darwin":
            return Platform.DARWIN
        return Platform.LINUX


_settings: Settings | None = None


def get_settings() -> Settings:
    """Return a lazily-constructed singleton Settings instance."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings() -> None:
    """Test hook: drop the cached singleton so the next call rebuilds it."""
    global _settings
    _settings = None
