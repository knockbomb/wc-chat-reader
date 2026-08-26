"""End-to-end integration test using a synthetic decrypted database."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from wc_chat_reader.api.main import create_app
from wc_chat_reader.core.config import Settings
from wc_chat_reader.core.constants import WeChatVersion
from wc_chat_reader.db.repository import Repository


def _build_sample_db(dir_: Path) -> Path:
    """Create a plain (unencrypted) sqlite DB with the v3 schema our repo reads."""
    dir_.mkdir(parents=True, exist_ok=True)
    db = dir_ / "MicroMsg.db"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE Contact (
            UserName TEXT PRIMARY KEY,
            NickName TEXT,
            Remark TEXT,
            Alias TEXT
        );
        INSERT INTO Contact VALUES ('wxid_alice', 'Alice', 'Alice remark', 'alice');
        INSERT INTO Contact VALUES ('wxid_bob', 'Bob', '', 'bob');
        """
    )
    conn.commit()
    conn.close()

    multi_dir = dir_ / "Multi"
    multi_dir.mkdir(exist_ok=True)
    msg_db = multi_dir / "MSG0.db"
    conn = sqlite3.connect(msg_db)
    conn.executescript(
        """
        CREATE TABLE MSG (
            MsgSvrID INTEGER,
            CreateTime INTEGER,
            StrTalker TEXT,
            StrContent TEXT,
            Type INTEGER,
            SubType INTEGER,
            IsSender INTEGER
        );
        """
    )
    ts = int(datetime(2024, 1, 1, 12, 0, 0).timestamp())
    for i in range(3):
        conn.execute(
            "INSERT INTO MSG VALUES (?,?,?,?,?,?,?)",
            (100 + i, ts + i, "wxid_alice", f"hello {i}", 1, 0, 0),
        )
    conn.commit()
    conn.close()
    return dir_


@pytest.fixture
def sample_repo(tmp_path: Path) -> Repository:
    data = _build_sample_db(tmp_path / "wechat_data")
    return Repository(data_dir=data, version=WeChatVersion.V3)


@pytest.fixture
def http_client(sample_repo: Repository) -> TestClient:
    app = create_app(
        settings=Settings(bind_local_only=True, enable_mcp=True),
        repository=sample_repo,
        wechat_version_str="V3",
        data_dir=str(sample_repo.data_dir),
    )
    return TestClient(app)


@pytest.mark.integration
def test_repository_reads_contacts(sample_repo: Repository) -> None:
    contacts = sample_repo.list_contacts()
    names = {c.user_name for c in contacts}
    assert names == {"wxid_alice", "wxid_bob"}


@pytest.mark.integration
def test_repository_reads_messages(sample_repo: Repository) -> None:
    msgs = sample_repo.get_messages(talker="wxid_alice", limit=10)
    assert len(msgs) == 3
    contents = {m.content for m in msgs}
    assert contents == {"hello 0", "hello 1", "hello 2"}


@pytest.mark.integration
def test_repository_offset_applied_once(sample_repo: Repository) -> None:
    """Regression: offset was previously applied twice (per shard + final)."""
    msgs = sample_repo.get_messages(talker="wxid_alice", limit=2, offset=0)
    assert len(msgs) == 2
    msgs_off = sample_repo.get_messages(talker="wxid_alice", limit=2, offset=1)
    assert len(msgs_off) == 2
    # offset=2 leaves exactly 1 message
    msgs_off2 = sample_repo.get_messages(talker="wxid_alice", limit=10, offset=2)
    assert len(msgs_off2) == 1


@pytest.mark.integration
def test_http_health_endpoint(http_client: TestClient) -> None:
    r = http_client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["wechat_version"] == "V3"


@pytest.mark.integration
def test_http_chatlog_json(http_client: TestClient) -> None:
    r = http_client.get("/api/v1/chatlog?talker=wxid_alice&format=json")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    assert len(data) == 3


@pytest.mark.integration
def test_http_chatlog_csv(http_client: TestClient) -> None:
    r = http_client.get("/api/v1/chatlog?talker=wxid_alice&format=csv")
    assert r.status_code == 200
    text = r.text
    assert "time,talker,sender" in text
    assert "hello 0" in text


@pytest.mark.integration
def test_http_media_path_traversal_blocked(http_client: TestClient) -> None:
    """Regression: /data/ must reject '..' path traversal."""
    r = http_client.get("/data/..%2f..%2fetc%2fpasswd")
    assert r.status_code == 404


@pytest.mark.integration
def test_http_contact_list(http_client: TestClient) -> None:
    r = http_client.get("/api/v1/contact")
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 2


@pytest.mark.integration
def test_mcp_tools_list_via_dispatch(http_client: TestClient) -> None:
    """Smoke test the MCP dispatch by opening SSE then POSTing."""
    # This test only verifies the dispatch layer via the /messages endpoint.
    # A full SSE round-trip needs an async client; we skip that here.
    from wc_chat_reader.mcp.server import _handle_message
    from wc_chat_reader.api.deps import AppState
    from wc_chat_reader.core.config import Settings

    import asyncio

    state = AppState(
        settings=Settings(enable_mcp=True),
        repository=http_client.app.state.wcr.repository,
    )

    class _S:
        session_id = "test"
        initialized = False
        queue = None

    session = _S()
    resp = asyncio.run(
        _handle_message(state, session, {"method": "tools/list", "id": 1})
    )
    assert resp is not None
    assert "tools" in resp["result"]
    names = {t["name"] for t in resp["result"]["tools"]}
    assert "query_chat" in names


@pytest.mark.integration
def test_mcp_query_chat_tool(http_client: TestClient) -> None:
    from wc_chat_reader.mcp.server import _handle_message
    from wc_chat_reader.api.deps import AppState
    from wc_chat_reader.core.config import Settings

    import asyncio

    state = AppState(
        settings=Settings(enable_mcp=True),
        repository=http_client.app.state.wcr.repository,
    )
    resp = asyncio.run(
        _handle_message(
            state,
            None,  # type: ignore[arg-type] - _handle_message doesn't touch session on tools/call
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "query_chat",
                    "arguments": {"talker": "wxid_alice", "limit": 10},
                },
            },
        )
    )
    assert resp is not None
    text = resp["result"]["content"][0]["text"]
    payload = json.loads(text)
    assert payload["count"] == 3
