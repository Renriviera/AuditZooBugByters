"""Run G hardening tests for ``clone_and_checkout``.

The 90-CVE Run G must tolerate transient ``git clone/fetch`` flakes (DNS,
TCP RSTs, GitHub rate-limits) without losing the CVE.  These tests pin the
contract:

* one ``TimeoutExpired`` followed by a successful clone/fetch/checkout
  triplet returns ``True`` after exactly one retry,
* three consecutive failures return ``False`` and emit a WARNING per
  attempt.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

import pytest

from scripts import run_evaluation


def _ok(*, returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=["git"], returncode=returncode, stdout="", stderr=""
    )


def test_clone_and_checkout_retries_after_one_timeout(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    calls: list[list[str]] = []
    fail_remaining = {"n": 1}

    def fake_run(cmd, **_kwargs):  # type: ignore[no-untyped-def]
        calls.append(list(cmd))
        if cmd[:2] == ["git", "clone"] and fail_remaining["n"] > 0:
            fail_remaining["n"] -= 1
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=300)
        return _ok()

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(run_evaluation.time, "sleep", lambda _s: None)
    caplog.set_level(logging.WARNING, logger=run_evaluation.logger.name)

    dest = tmp_path / "repo"
    ok = run_evaluation.clone_and_checkout("https://example.com/x.git", "abc123", dest)

    assert ok is True
    clone_calls = [c for c in calls if c[:2] == ["git", "clone"]]
    fetch_calls = [c for c in calls if c[:2] == ["git", "fetch"]]
    checkout_calls = [c for c in calls if c[:2] == ["git", "checkout"]]
    assert len(clone_calls) == 2  # 1 failure + 1 success
    assert len(fetch_calls) == 1
    assert len(checkout_calls) == 1
    warn_msgs = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert any("attempt 1/3" in m for m in warn_msgs)


def test_clone_and_checkout_returns_false_after_three_failures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    attempts = {"n": 0}

    def fake_run(cmd, **_kwargs):  # type: ignore[no-untyped-def]
        if cmd[:2] == ["git", "clone"]:
            attempts["n"] += 1
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=300)
        return _ok()

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(run_evaluation.time, "sleep", lambda _s: None)
    caplog.set_level(logging.WARNING, logger=run_evaluation.logger.name)

    dest = tmp_path / "repo"
    ok = run_evaluation.clone_and_checkout("https://example.com/x.git", "abc123", dest)

    assert ok is False
    assert attempts["n"] == 3
    warn_msgs = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert any("attempt 1/3" in m for m in warn_msgs)
    assert any("attempt 2/3" in m for m in warn_msgs)
    assert any("attempt 3/3" in m for m in warn_msgs)
    assert any("after 3 attempts" in m for m in warn_msgs)


def test_clone_and_checkout_retries_called_process_error_on_checkout(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    fail_checkout = {"n": 1}

    def fake_run(cmd, **_kwargs):  # type: ignore[no-untyped-def]
        if cmd[:2] == ["git", "checkout"] and fail_checkout["n"] > 0:
            fail_checkout["n"] -= 1
            raise subprocess.CalledProcessError(returncode=128, cmd=cmd)
        return _ok()

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(run_evaluation.time, "sleep", lambda _s: None)
    caplog.set_level(logging.WARNING, logger=run_evaluation.logger.name)

    dest = tmp_path / "repo"
    ok = run_evaluation.clone_and_checkout("https://example.com/x.git", "abc123", dest)

    assert ok is True
    warn_msgs = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert any("attempt 1/3" in m for m in warn_msgs)
