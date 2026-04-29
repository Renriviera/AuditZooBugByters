"""Readiness checks for the CWE-78 Semgrep seed rules."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

from auditzoo.agents.cwe78_study.semgrep_arm import SemgrepArm
from splitEvaluations.readiness_config import DEV_LOOP_CVES


def _semgrep_bin_dir() -> str | None:
    semgrep = shutil.which("semgrep")
    if semgrep:
        return str(Path(semgrep).parent)
    sibling = Path(sys.executable).with_name("semgrep")
    if sibling.exists():
        return str(sibling.parent)
    return None


def test_seed_rules_cover_dev_source_families(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    semgrep_bin_dir = _semgrep_bin_dir()
    if semgrep_bin_dir is None:
        pytest.skip("semgrep not installed")
    monkeypatch.setenv("PATH", f"{semgrep_bin_dir}:{'/usr/bin:/bin'}")

    app = tmp_path / "app.py"
    app.write_text("""\
import argparse
import json
import os
import shlex
import subprocess


def cli_source():
    args = argparse.ArgumentParser().parse_args()
    os.system(args.cmd)


def django_source(request):
    subprocess.run(request.GET.get("cmd"), shell=True)


def ansible_source(module):
    cmd = module.params.get("cmd")
    subprocess.call(cmd, shell=True)


def config_source(raw):
    cmd = json.loads(raw)["cmd"]
    os.popen(cmd)


def sanitized_source(request):
    cmd = shlex.quote(request.GET.get("cmd"))
    os.system(cmd)


def static_command():
    os.system("echo safe")
""")
    findings = SemgrepArm().scan(tmp_path)
    finding_lines = {finding.line_start for finding in findings}

    assert 10 in finding_lines
    assert 14 in finding_lines
    assert 19 in finding_lines
    assert 24 in finding_lines
    assert 29 not in finding_lines
    assert 33 not in finding_lines


def test_readiness_dev_loop_has_exactly_15_unique_cves() -> None:
    assert len(DEV_LOOP_CVES) == 15
    assert len(set(DEV_LOOP_CVES)) == 15
    assert "CVE-2020-11981" not in DEV_LOOP_CVES
    assert "CVE-2019-14904" not in DEV_LOOP_CVES
    assert "CVE-2025-14287" not in DEV_LOOP_CVES
    assert "CVE-2022-1813" not in DEV_LOOP_CVES
