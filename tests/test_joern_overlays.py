"""Tests for the configurable ``run_overlays`` plumbing.

These cover both the config-layer resolution (env var + default) and the
client-layer behaviour (which queries are actually sent to the Joern REPL
for each overlay list, including the empty-list case and the unknown-name
validation).

We stub out ``_start_joern_server`` and ``CPGQLSClient`` so no actual
Joern subprocess is required; the test asserts on the sequence of
``self.query`` calls the client issues.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from auditzoo.backends.base import (
    DEFAULT_RUN_OVERLAYS,
    JoernConfig,
    _parse_overlays_env,
)
from auditzoo.backends.joern.client import (
    ALLOWED_OVERLAYS,
    JoernClient,
)
from auditzoo.core.ir.backend_api import BackendConnectionError


def _build_client_without_binary_checks(**kwargs: Any) -> JoernClient:
    """Instantiate a ``JoernClient`` without the real Joern on disk."""
    with (
        patch.object(JoernClient, "_is_port_in_use", return_value=False),
        patch("auditzoo.backends.joern.client.Path") as PathMock,
    ):
        PathMock.return_value.exists.return_value = True
        PathMock.return_value.__truediv__.return_value.exists.return_value = True
        client = JoernClient(
            joern_path="/fake/joern",
            host="localhost",
            port=65535,
            query_retry_sleep_s=0.0,
            **kwargs,
        )
    return client


async def _run_connect_collecting_queries(
    client: JoernClient,
    tmp_path,
    source_path,
    *,
    run_overlays: list[str] | None,
    exists_response: str = "false",
    cache_enabled: bool = False,
) -> list[str]:
    """Drive ``client.connect`` with a stubbed ``query`` and return the call log.

    ``exists_response`` is the string returned for the
    ``workspace.projects.exists`` query; set to ``"true"`` to simulate a
    cache hit branch (no importCode, no overlays).
    """
    calls: list[str] = []

    async def fake_query(q: str) -> str:
        calls.append(q)
        if q.startswith("workspace.projects.exists"):
            return exists_response
        return '""'

    client.query = fake_query  # type: ignore[assignment]

    def fake_start_server() -> None:
        client._process = MagicMock(pid=1)

    with (
        patch.object(client, "_start_joern_server", side_effect=fake_start_server),
        patch("auditzoo.backends.joern.client.CPGQLSClient", return_value=MagicMock()),
        patch("auditzoo.backends.joern.client.psutil.Process") as PsProc,
    ):
        PsProc.return_value.memory_info.return_value = MagicMock(rss=1)
        await client.connect(
            language="auto",
            source_path=str(source_path),
            analysis_path=str(tmp_path),
            project_name="proj",
            run_overlays=run_overlays,
            cache_enabled=cache_enabled,
        )
    return calls


def _overlay_calls(calls: list[str]) -> list[str]:
    return [c for c in calls if c.startswith("run.")]


def test_parse_overlays_env_splits_on_comma_and_whitespace() -> None:
    assert _parse_overlays_env("controlflow, callgraph") == ["controlflow", "callgraph"]
    assert _parse_overlays_env("controlflow  callgraph") == ["controlflow", "callgraph"]
    assert _parse_overlays_env("callgraph") == ["callgraph"]
    assert _parse_overlays_env("") == []


def test_joern_config_default_overlays_preserved(monkeypatch: Any) -> None:
    monkeypatch.delenv("AUDITZOO_JOERN_OVERLAYS", raising=False)
    cfg = JoernConfig(source_path="/tmp", language="python")
    assert cfg.run_overlays == list(DEFAULT_RUN_OVERLAYS)


def test_joern_config_env_override(monkeypatch: Any) -> None:
    monkeypatch.setenv("AUDITZOO_JOERN_OVERLAYS", "callgraph")
    cfg = JoernConfig(source_path="/tmp", language="python")
    assert cfg.run_overlays == ["callgraph"]


def test_joern_config_explicit_overlays_beats_env(monkeypatch: Any) -> None:
    monkeypatch.setenv("AUDITZOO_JOERN_OVERLAYS", "callgraph")
    cfg = JoernConfig(source_path="/tmp", language="python", run_overlays=[])
    assert cfg.run_overlays == []


def test_joern_config_empty_env_means_no_overlays(monkeypatch: Any) -> None:
    monkeypatch.setenv("AUDITZOO_JOERN_OVERLAYS", "")
    cfg = JoernConfig(source_path="/tmp", language="python")
    assert cfg.run_overlays == []


def test_validate_overlays_allow_list_matches_config_defaults() -> None:
    for o in DEFAULT_RUN_OVERLAYS:
        assert o in ALLOWED_OVERLAYS


def test_validate_overlays_rejects_unknown() -> None:
    client = _build_client_without_binary_checks()
    with pytest.raises(BackendConnectionError):
        client._validate_overlays(["controlflow", "not-a-real-overlay"])


def test_validate_overlays_normalises_empty_and_none() -> None:
    client = _build_client_without_binary_checks()
    assert client._validate_overlays(None) == ["controlflow", "callgraph"]
    assert client._validate_overlays([]) == []
    assert client._validate_overlays(["  callgraph  ", ""]) == ["callgraph"]


@pytest.mark.asyncio
async def test_connect_default_overlays_emitted_in_order(tmp_path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    client = _build_client_without_binary_checks()
    calls = await _run_connect_collecting_queries(
        client,
        tmp_path,
        src,
        run_overlays=None,
    )
    assert _overlay_calls(calls) == ["run.controlflow", "run.callgraph"]


@pytest.mark.asyncio
async def test_connect_empty_overlays_skips_run_calls(tmp_path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    client = _build_client_without_binary_checks()
    calls = await _run_connect_collecting_queries(
        client,
        tmp_path,
        src,
        run_overlays=[],
    )
    assert _overlay_calls(calls) == []
    assert any(c.startswith("importCode(") for c in calls)


@pytest.mark.asyncio
async def test_connect_unknown_overlay_raises(tmp_path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    client = _build_client_without_binary_checks()
    with pytest.raises(BackendConnectionError):
        await _run_connect_collecting_queries(
            client,
            tmp_path,
            src,
            run_overlays=["does-not-exist"],
        )


@pytest.mark.asyncio
async def test_connect_custom_overlay_order_respected(tmp_path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    client = _build_client_without_binary_checks()
    calls = await _run_connect_collecting_queries(
        client,
        tmp_path,
        src,
        run_overlays=["callgraph", "controlflow"],
    )
    assert _overlay_calls(calls) == ["run.callgraph", "run.controlflow"]
