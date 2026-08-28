"""Tests for the API debug console (dashboard) route."""

from __future__ import annotations

from fastapi.testclient import TestClient

from wc_chat_reader.api.main import create_app
from wc_chat_reader.core.config import Settings


def _client(**settings_kwargs) -> TestClient:
    settings = Settings(**settings_kwargs)
    return TestClient(create_app(settings=settings))


def test_dashboard_served_at_root(tmp_path) -> None:
    client = _client(work_dir=tmp_path)
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    body = resp.text
    # The four tabs and the page title must be present.
    assert "API 接口与调试" in body
    for tab in ("最近会话", "群聊", "联系人", "聊天记录"):
        assert tab in body
    # Endpoint paths the console drives.
    for ep in ("/api/v1/session", "/api/v1/chatroom", "/api/v1/contact", "/api/v1/chatlog"):
        assert ep in body


def test_dashboard_excluded_from_openapi(tmp_path) -> None:
    client = _client(work_dir=tmp_path)
    spec = client.get("/openapi.json").json()
    assert "/" not in spec["paths"]


def test_dashboard_not_blocked_by_api_token(tmp_path) -> None:
    """The static shell must load even when api_token is set; only the
    underlying API calls require the token."""
    client = _client(work_dir=tmp_path, api_token="secret")
    assert client.get("/").status_code == 200
    # …while a real API endpoint still enforces auth.
    assert client.get("/api/v1/contact").status_code == 401
    assert (
        client.get("/api/v1/contact", headers={"Authorization": "Bearer secret"}).status_code
        != 401  # 503 (no repo) is fine — it means auth passed.
    )
