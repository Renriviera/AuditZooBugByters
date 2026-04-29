"""Readiness tests for evaluation-loop timeout behavior."""

from __future__ import annotations

import asyncio
import signal
import time

import pytest

from scripts import run_evaluation


class _SleepingPipeline:
    async def run(self, repo_path: str, cve_id: str = "") -> object:
        await asyncio.sleep(60)
        return {"repo_path": repo_path, "cve_id": cve_id}


class _FastPipeline:
    async def run(self, repo_path: str, cve_id: str = "") -> object:
        return {"repo_path": repo_path, "cve_id": cve_id}


class _BlockingPipeline:
    async def run(self, repo_path: str, cve_id: str = "") -> object:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        time.sleep(60)
        return {"repo_path": repo_path, "cve_id": cve_id}


@pytest.mark.asyncio
async def test_non_joern_run_with_timeout_cleans_up_stray_joern(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleanup_calls = 0

    def fake_cleanup(*_args: object, **_kwargs: object) -> None:
        nonlocal cleanup_calls
        cleanup_calls += 1

    monkeypatch.setattr(run_evaluation, "_cleanup_stray_joern", fake_cleanup)

    cfg = run_evaluation.PipelineConfig(arms=["semgrep"])
    monkeypatch.setattr(run_evaluation, "Pipeline", lambda _cfg: _SleepingPipeline())

    result, timed_out, run_meta, resource_delta = await run_evaluation._run_with_timeout(
        cfg, "/tmp/repo", "CVE-TIMEOUT", 0.01
    )

    assert result is None
    assert timed_out is True
    assert run_meta["timeout_scope"] == "coroutine"
    assert resource_delta == {}
    assert cleanup_calls == 1


@pytest.mark.asyncio
async def test_run_with_timeout_returns_success_without_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleanup_calls = 0

    def fake_cleanup(*_args: object, **_kwargs: object) -> None:
        nonlocal cleanup_calls
        cleanup_calls += 1

    monkeypatch.setattr(run_evaluation, "_cleanup_stray_joern", fake_cleanup)

    cfg = run_evaluation.PipelineConfig(arms=["semgrep"])
    monkeypatch.setattr(run_evaluation, "Pipeline", lambda _cfg: _FastPipeline())

    result, timed_out, run_meta, resource_delta = await run_evaluation._run_with_timeout(
        cfg, "/tmp/repo", "CVE-FAST", 1.0
    )

    assert result == {"repo_path": "/tmp/repo", "cve_id": "CVE-FAST"}
    assert timed_out is False
    assert run_meta["timeout_scope"] == "coroutine"
    assert resource_delta == {}
    assert cleanup_calls == 0


@pytest.mark.asyncio
async def test_joern_timeout_kills_blocking_child_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleanup_calls = 0

    def fake_cleanup(*_args: object, **_kwargs: object) -> None:
        nonlocal cleanup_calls
        cleanup_calls += 1

    monkeypatch.setattr(run_evaluation, "_cleanup_stray_joern", fake_cleanup)
    monkeypatch.setattr(run_evaluation, "Pipeline", lambda _cfg: _BlockingPipeline())

    cfg = run_evaluation.PipelineConfig(arms=["joern"])
    result, timed_out, run_meta, resource_delta = await run_evaluation._run_with_timeout(
        cfg, "/tmp/repo", "CVE-JOERN-HANG", 0.2
    )

    assert result is None
    assert timed_out is True
    assert resource_delta == {}
    assert cleanup_calls == 2
    assert run_meta["timeout_scope"] == "process_group"
    assert run_meta["kill_signal"] == "SIGKILL"


@pytest.mark.asyncio
async def test_joern_run_cleans_up_before_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleanup_calls = 0

    def fake_cleanup(*_args: object, **_kwargs: object) -> None:
        nonlocal cleanup_calls
        cleanup_calls += 1

    monkeypatch.setattr(run_evaluation, "_cleanup_stray_joern", fake_cleanup)
    monkeypatch.setattr(run_evaluation, "Pipeline", lambda _cfg: _FastPipeline())

    cfg = run_evaluation.PipelineConfig(arms=["joern"])
    result, timed_out, run_meta, resource_delta = await run_evaluation._run_with_timeout(
        cfg, "/tmp/repo", "CVE-JOERN-FAST", 10.0
    )

    assert result == {"repo_path": "/tmp/repo", "cve_id": "CVE-JOERN-FAST"}
    assert timed_out is False
    assert run_meta["timeout_scope"] == "process_group"
    assert resource_delta
    assert cleanup_calls == 1
