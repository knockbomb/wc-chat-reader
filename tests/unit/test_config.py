"""Unit tests for config resolution and validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from wc_chat_reader.core.config import Settings, reset_settings
from wc_chat_reader.core.exceptions import ConfigError


@pytest.mark.unit
def test_defaults(tmp_path: Path, monkeypatch):
    reset_settings()
    monkeypatch.chdir(tmp_path)
    s = Settings()
    assert s.http_host == "127.0.0.1"
    assert s.http_port == 5030
    assert s.work_dir.exists()


@pytest.mark.unit
def test_env_overrides(monkeypatch, tmp_path: Path):
    reset_settings()
    monkeypatch.setenv("WCR_HTTP_PORT", "9999")
    monkeypatch.setenv("WCR_LOG_LEVEL", "DEBUG")
    monkeypatch.chdir(tmp_path)
    s = Settings()
    assert s.http_port == 9999
    assert s.log_level == "DEBUG"


@pytest.mark.unit
def test_port_range(tmp_path: Path, monkeypatch):
    reset_settings()
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValueError):
        Settings(http_port=99999)
