"""Tests for the per-phase connect instrumentation on ``JoernClient``.

Covers ``last_connect_timings`` (keys, cache_hit flag, monotonicity),
``last_connect_rss`` (peak bookkeeping), and the GC-log env-var wiring
in ``_build_server_env``.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from auditzoo.backends.joern.client import JoernClient


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


async def _connect_with_fake_query(
    client: JoernClient,
    tmp_path,
    source_path,
    *,
    exists_response: str = "false",
    cache_enabled: bool = False,
    run_overlays: list[str] | None = None,
    rss_sequence: list[int] | None = None,
) -> None:
    async def fake_query(q: str) -> str:
        if q.startswith("workspace.projects.exists"):
            return exists_response
        return '""'

    client.query = fake_query  # type: ignore[assignment]

    def fake_start_server() -> None:
        client._process = MagicMock(pid=1)

    rss_iter = iter(rss_sequence or [100, 200, 300, 150, 180, 160])

    def fake_ps_factory(pid: int) -> Any:
        proc = MagicMock()
        try:
            proc.memory_info.return_value = MagicMock(rss=next(rss_iter))
        except StopIteration:
            proc.memory_info.return_value = MagicMock(rss=0)
        return proc

    with (
        patch.object(client, "_start_joern_server", side_effect=fake_start_server),
        patch("auditzoo.backends.joern.client.CPGQLSClient", return_value=MagicMock()),
        patch(
            "auditzoo.backends.joern.client.psutil.Process",
            side_effect=fake_ps_factory,
        ),
    ):
        await client.connect(
            language="auto",
            source_path=str(source_path),
            analysis_path=str(tmp_path),
            project_name="proj",
            run_overlays=run_overlays,
            cache_enabled=cache_enabled,
        )


@pytest.mark.asyncio
async def test_connect_populates_expected_timing_keys(tmp_path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    client = _build_client()
    await _connect_with_fake_query(client, tmp_path, src)

    t = client.last_connect_timings
    for key in (
        "switch_workspace_s",
        "project_exists_check_s",
        "import_code_s",
        "overlay_controlflow_s",
        "overlay_callgraph_s",
        "warmup_s",
        "total_connect_s",
    ):
        assert key in t, f"missing timing key {key}: got {sorted(t)}"
        assert isinstance(t[key], float)
        assert t[key] >= 0.0
    assert t["cache_hit"] is False
    assert t["overlays"] == ["controlflow", "callgraph"]


@pytest.mark.asyncio
async def test_connect_sets_cache_hit_on_existing_project_with_meta(
    tmp_path,
) -> None:
    """When cache_enabled and project exists + meta matches, skip import."""
    src = tmp_path / "src"
    src.mkdir()
    client = _build_client()
    # Pre-populate meta so overlays match what we'll request.
    proj_dir = tmp_path / "proj"
    proj_dir.mkdir()
    (proj_dir / "_auditzoo_meta.json").write_text(
        '{"run_overlays": ["controlflow", "callgraph"]}'
    )
    await _connect_with_fake_query(
        client,
        tmp_path,
        src,
        exists_response="true",
        cache_enabled=True,
    )
    assert client.last_connect_timings["cache_hit"] is True
    assert "import_code_s" not in client.last_connect_timings


@pytest.mark.asyncio
async def test_connect_cache_miss_when_meta_mismatch_triggers_rebuild(
    tmp_path,
) -> None:
    src = tmp_path / "src"
    src.mkdir()
    client = _build_client()
    proj_dir = tmp_path / "proj"
    proj_dir.mkdir()
    (proj_dir / "_auditzoo_meta.json").write_text('{"run_overlays": ["controlflow"]}')
    await _connect_with_fake_query(
        client,
        tmp_path,
        src,
        exists_response="true",
        cache_enabled=True,
        run_overlays=["controlflow", "callgraph"],
    )
    assert client.last_connect_timings["cache_hit"] is False
    assert "import_code_s" in client.last_connect_timings
    meta = (proj_dir / "_auditzoo_meta.json").read_text()
    assert "callgraph" in meta


@pytest.mark.asyncio
async def test_connect_records_rss_peak(tmp_path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    client = _build_client()
    await _connect_with_fake_query(
        client,
        tmp_path,
        src,
        rss_sequence=[100, 700, 300, 500, 200],
    )
    rss = client.last_connect_rss
    assert rss["peak_bytes"] >= max(
        rss.get(k, 0) for k in rss if k.endswith("_bytes") and k != "peak_bytes"
    )
    assert rss["peak_bytes"] == 700


@pytest.mark.asyncio
async def test_connect_resets_timings_between_calls(tmp_path) -> None:
    """A subsequent ``connect`` attempt must not keep stale phase keys."""
    src = tmp_path / "src"
    src.mkdir()
    client = _build_client()
    await _connect_with_fake_query(client, tmp_path, src)
    first = dict(client.last_connect_timings)
    assert "overlay_controlflow_s" in first

    client._connected_core = None
    client._workspace_dir = None
    await _connect_with_fake_query(
        client,
        tmp_path,
        src,
        run_overlays=["callgraph"],
    )
    second = client.last_connect_timings
    assert "overlay_callgraph_s" in second
    assert "overlay_controlflow_s" not in second


def test_build_server_env_enables_gc_log_when_env_set(
    tmp_path, monkeypatch: Any
) -> None:
    gc_dir = tmp_path / "gc"
    monkeypatch.setenv("AUDITZOO_JOERN_GC_LOG", str(gc_dir))
    client = _build_client()
    env = client._build_server_env()
    assert client.gc_log_path == str(gc_dir)
    assert gc_dir.is_dir()
    opts = env["JAVA_OPTS"]
    assert "-Xlog:gc" in opts
    assert str(gc_dir) in opts


def test_build_server_env_no_gc_log_by_default(monkeypatch: Any) -> None:
    monkeypatch.delenv("AUDITZOO_JOERN_GC_LOG", raising=False)
    client = _build_client()
    env = client._build_server_env()
    assert client.gc_log_path is None
    assert "-Xlog:gc" not in env.get("JAVA_OPTS", "")
