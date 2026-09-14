"""Unit tests for the local key cache (open-and-go)."""

from __future__ import annotations

from pathlib import Path

import pytest

from wc_chat_reader.key.key_cache import CachedKey, KeyCache, _fingerprint, default_cache_dir


@pytest.mark.unit
class TestFingerprint:
    def test_none_data_dir(self):
        assert _fingerprint(None) == "unknown"

    def test_stable_for_same_dir(self, tmp_path: Path):
        d = tmp_path / "wechat" / "data"
        d.mkdir(parents=True)
        (d / "key_info.db").write_bytes(b"x" * 16)
        fp1 = _fingerprint(d)
        fp2 = _fingerprint(d)
        assert fp1 == fp2
        assert str(d) in fp1

    def test_mtime_included(self, tmp_path: Path):
        d = tmp_path / "wechat" / "data2"
        d.mkdir(parents=True)
        (d / "key_info.db").write_bytes(b"y" * 16)
        fp1 = _fingerprint(d)
        import time

        time.sleep(0.02)
        (d / "key_info.db").write_bytes(b"z" * 16)
        assert _fingerprint(d) != fp1


@pytest.mark.unit
class TestKeyCache:
    def test_roundtrip_get_put(self, tmp_path: Path):
        cache = KeyCache(tmp_path / "keys.json")
        data_dir = tmp_path / "wx"
        data_dir.mkdir()
        (data_dir / "key_info.db").write_bytes(b"k" * 16)

        ok = cache.put(
            CachedKey(
                key=bytes(range(32)),
                version_str="4.1.13.12",
                data_dir_fingerprint=_fingerprint(data_dir),
                strategy="frida-codec-hook",
            )
        )
        assert ok is True
        assert cache._path.exists()

        got = cache.get("4.1.13.12", data_dir)
        assert got is not None
        assert got.key == bytes(range(32))
        assert got.strategy == "frida-codec-hook"

    def test_miss_on_version_mismatch(self, tmp_path: Path):
        cache = KeyCache(tmp_path / "keys.json")
        data_dir = tmp_path / "wx2"
        data_dir.mkdir()
        (data_dir / "key_info.db").write_bytes(b"a" * 16)
        cache.put(
            CachedKey(
                key=bytes(range(32)),
                version_str="4.1.13.12",
                data_dir_fingerprint=_fingerprint(data_dir),
                strategy="s",
            )
        )
        assert cache.get("4.9.0.1", data_dir) is None

    def test_miss_on_data_dir_mismatch(self, tmp_path: Path):
        cache = KeyCache(tmp_path / "keys.json")
        d1 = tmp_path / "wxA"
        d2 = tmp_path / "wxB"
        for d in (d1, d2):
            d.mkdir()
            (d / "key_info.db").write_bytes(b"b" * 16)
        cache.put(
            CachedKey(
                key=bytes(range(32)),
                version_str="4.1.13.12",
                data_dir_fingerprint=_fingerprint(d1),
                strategy="s",
            )
        )
        assert cache.get("4.1.13.12", d2) is None

    def test_upsert_replaces_same_install(self, tmp_path: Path):
        cache = KeyCache(tmp_path / "keys.json")
        d = tmp_path / "wxC"
        d.mkdir()
        (d / "key_info.db").write_bytes(b"c" * 16)
        fp = _fingerprint(d)
        cache.put(CachedKey(key=b"\x01" * 32, version_str="4.1.13.12", data_dir_fingerprint=fp, strategy="a"))
        cache.put(CachedKey(key=b"\x02" * 32, version_str="4.1.13.12", data_dir_fingerprint=fp, strategy="b"))
        recs = cache.load()
        assert len(recs) == 1
        got = cache.get("4.1.13.12", d)
        assert got is not None and got.key == b"\x02" * 32

    def test_corrupt_file_returns_empty(self, tmp_path: Path):
        path = tmp_path / "keys.json"
        path.write_text("not-json{{{", encoding="utf-8")
        cache = KeyCache(path)
        assert cache.load() == {}
        assert cache.get("4.1.13.12", tmp_path) is None

    def test_atomic_write_no_tmp_leftover(self, tmp_path: Path):
        cache = KeyCache(tmp_path / "keys.json")
        d = tmp_path / "wxD"
        d.mkdir()
        (d / "key_info.db").write_bytes(b"d" * 16)
        cache.put(
            CachedKey(
                key=b"\xee" * 32,
                version_str="4.1.13.12",
                data_dir_fingerprint=_fingerprint(d),
                strategy="s",
            )
        )
        tmp = cache._path.with_suffix(".json.tmp")
        assert not tmp.exists()


@pytest.mark.unit
class TestDefaultCacheDir:
    def test_honors_env(self, monkeypatch, tmp_path: Path):
        monkeypatch.setenv("WCR_KEYCACHE_DIR", str(tmp_path / "custom"))
        assert Path(default_cache_dir()) == tmp_path / "custom"