"""Tests for the Joern CPG cache: key derivation, flock, meta, and prune."""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from auditzoo.backends.base import (
    DEFAULT_CPG_CACHE_DIR,
    JoernConfig,
    make_cpg_cache_key,
)
from auditzoo.backends.joern.client import (
    JoernClient,
    prune_cpg_cache,
)

# ----------------------------------------------------------------------
# Key derivation
# ----------------------------------------------------------------------


def test_make_cpg_cache_key_basic() -> None:
    key = make_cpg_cache_key("CVE-2024-0001", "abcdef1234567890")
    assert key == "CVE-2024-0001_abcdef123456"


def test_make_cpg_cache_key_sanitises_unsafe_chars() -> None:
    key = make_cpg_cache_key("C V E/2024 0002", "ABCdef123456/xy")
    assert "/" not in key and " " not in key
    assert key.startswith("C_V_E_2024_0002_")
    assert key.endswith("abcdef123456")


def test_make_cpg_cache_key_falls_back_when_missing() -> None:
    key = make_cpg_cache_key(None, None)
    assert "unknown" in key and "nosha" in key


def test_joern_config_with_cpg_cache_constructor(monkeypatch: Any) -> None:
    monkeypatch.delenv("AUDITZOO_CPG_CACHE_DIR", raising=False)
    cfg = JoernConfig.with_cpg_cache(
        source_path="/tmp/src",
        cve_id="CVE-2024-9999",
        git_sha="deadbeefcafe1234",
        language="python",
    )
    assert cfg.cpg_cache_key == "CVE-2024-9999_deadbeefcafe"
    assert cfg.project_name == "CVE-2024-9999_deadbeefcafe"
    assert cfg.analysis_path == os.path.abspath(
        os.path.expanduser(DEFAULT_CPG_CACHE_DIR)
    )


def test_joern_config_env_override_cache_dir(monkeypatch: Any, tmp_path) -> None:
    custom = tmp_path / "custom_cache"
    monkeypatch.setenv("AUDITZOO_CPG_CACHE_DIR", str(custom))
    cfg = JoernConfig(
        source_path="/tmp/src",
        language="python",
        cpg_cache_key="CVE-X_abc123456789",
    )
    assert cfg.cpg_cache_dir == str(custom.resolve())
    assert cfg.analysis_path == str(custom.resolve())


# ----------------------------------------------------------------------
# Flock behaviour
# ----------------------------------------------------------------------


def test_cache_flock_creates_and_releases_lock(tmp_path) -> None:
    lock_path = tmp_path / "project.lock"
    with JoernClient._cache_flock(lock_path):
        assert lock_path.exists()
    # Should still exist on disk (lock file is left behind but released).
    assert lock_path.exists()


def test_cache_flock_survives_unsupported_filesystem(
    tmp_path, monkeypatch: Any
) -> None:
    """When flock() fails with ENOLCK we degrade to an unlocked critical section."""
    import errno
    import fcntl as _fcntl

    def fake_flock(fd: int, op: int) -> None:
        raise OSError(errno.ENOLCK, "no locks available")

    monkeypatch.setattr(_fcntl, "flock", fake_flock)
    lock_path = tmp_path / "project.lock"
    with JoernClient._cache_flock(lock_path):
        pass


# ----------------------------------------------------------------------
# Meta file mismatch triggers rebuild
# ----------------------------------------------------------------------


def _build_client(**kwargs: Any) -> JoernClient:
    with (
        patch.object(JoernClient, "_is_port_in_use", return_value=False),
        patch("auditzoo.backends.joern.client.Path") as PathMock,
    ):
        PathMock.return_value.exists.return_value = True
        PathMock.return_value.__truediv__.return_value.exists.return_value = True
        return JoernClient(
            joern_path="/fake/joern",
            host="localhost",
            port=65535,
            query_retry_sleep_s=0.0,
            **kwargs,
        )


@pytest.mark.asyncio
async def test_cache_hit_skips_import_and_overlays(tmp_path) -> None:
    """Warm cache with matching meta: no importCode, no run.* overlay calls."""
    src = tmp_path / "src"
    src.mkdir()
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "_auditzoo_meta.json").write_text(
        '{"run_overlays": ["controlflow", "callgraph"]}'
    )
    client = _build_client()

    calls: list[str] = []

    async def fake_query(q: str) -> str:
        calls.append(q)
        if q.startswith("workspace.projects.exists"):
            return "true"
        return '""'

    client.query = fake_query  # type: ignore[assignment]

    with (
        patch.object(
            client,
            "_start_joern_server",
            side_effect=lambda: setattr(client, "_process", MagicMock(pid=1)),
        ),
        patch("auditzoo.backends.joern.client.CPGQLSClient", return_value=MagicMock()),
        patch("auditzoo.backends.joern.client.psutil.Process") as PsProc,
    ):
        PsProc.return_value.memory_info.return_value = MagicMock(rss=1)
        await client.connect(
            language="auto",
            source_path=str(src),
            analysis_path=str(tmp_path),
            project_name="proj",
            cache_enabled=True,
        )

    assert not any(c.startswith("importCode(") for c in calls)
    assert not any(c.startswith("run.") for c in calls)
    assert any(c.startswith('open("proj")') for c in calls)
    assert client.last_connect_timings["cache_hit"] is True


# ----------------------------------------------------------------------
# Prune routine
# ----------------------------------------------------------------------


def _mk_project(cache_dir: Path, name: str, size_bytes: int, mtime: float) -> Path:
    proj = cache_dir / name
    proj.mkdir(parents=True, exist_ok=True)
    data_file = proj / "data.bin"
    data_file.write_bytes(b"\x00" * size_bytes)
    os.utime(proj, (mtime, mtime))
    os.utime(data_file, (mtime, mtime))
    return proj


def test_prune_cpg_cache_evicts_oldest_until_under_budget(tmp_path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    now = time.time()
    # 3 KB-sized projects, oldest first.
    _mk_project(cache, "old", 1024, now - 300)
    _mk_project(cache, "mid", 1024, now - 200)
    _mk_project(cache, "new", 1024, now - 100)

    # Budget for roughly 1.5 projects -> should evict the oldest two.
    removed = prune_cpg_cache(cache, max_bytes=1500)
    assert "old" in removed
    assert "new" not in removed
    remaining = sorted(p.name for p in cache.iterdir() if p.is_dir())
    assert "new" in remaining


def test_prune_cpg_cache_noop_when_under_budget(tmp_path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    _mk_project(cache, "a", 1024, time.time())
    removed = prune_cpg_cache(cache, max_bytes=10 * 1024 * 1024)
    assert removed == []


def test_prune_cpg_cache_handles_missing_dir(tmp_path) -> None:
    cache = tmp_path / "nope"
    removed = prune_cpg_cache(cache, max_bytes=1024)
    assert removed == []


def test_prune_cpg_cache_removes_lock_for_evicted_project(tmp_path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    now = time.time()
    _mk_project(cache, "old", 1024, now - 300)
    _mk_project(cache, "new", 1024, now - 100)
    (cache / "old.lock").write_bytes(b"")
    prune_cpg_cache(cache, max_bytes=1500)
    assert not (cache / "old.lock").exists()
