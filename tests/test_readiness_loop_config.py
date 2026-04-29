"""Tests for the fixed 15-CVE readiness-loop command wrapper."""

from __future__ import annotations

from splitEvaluations import run_readiness_loop
from splitEvaluations.readiness_config import (
    DEV_LOOP_CVES,
    JOERN_DIAGNOSTIC_30_CVES,
    JOERN_DEV_MAX_K,
    JOERN_DEV_TIMEOUT_S,
    KNOWN_JOERN_TIMEOUT_CVES,
    SEMGREP_DEV_MAX_K,
    SEMGREP_DEV_TIMEOUT_S,
)


def test_semgrep_readiness_command_uses_fixed_dev_loop() -> None:
    cmd = run_readiness_loop.semgrep_command()
    assert cmd[:2]
    assert "splitEvaluations.run_semgrep_sweep" in cmd
    assert "--only-cves" in cmd
    assert all(cve in cmd for cve in DEV_LOOP_CVES)
    assert cmd[cmd.index("--max-k") + 1] == str(SEMGREP_DEV_MAX_K)
    assert cmd[cmd.index("--per-cve-timeout") + 1] == str(SEMGREP_DEV_TIMEOUT_S)


def test_joern_readiness_command_uses_bounded_vulnerable_only_loop() -> None:
    cmd = run_readiness_loop.joern_command()
    assert "splitEvaluations.run_joern_sweep" in cmd
    assert "--run-patched" not in cmd
    assert all(cve in cmd for cve in DEV_LOOP_CVES)
    assert cmd[cmd.index("--max-k") + 1] == str(JOERN_DEV_MAX_K)
    assert cmd[cmd.index("--per-cve-timeout") + 1] == str(JOERN_DEV_TIMEOUT_S)


def test_joern_diagnostic_30_cves_is_bounded_and_timeout_free() -> None:
    assert len(JOERN_DIAGNOSTIC_30_CVES) == 30
    assert len(set(JOERN_DIAGNOSTIC_30_CVES)) == 30
    assert not (set(JOERN_DIAGNOSTIC_30_CVES) & set(KNOWN_JOERN_TIMEOUT_CVES))
