#!/usr/bin/env python3
"""Run or print the fixed 15-CVE readiness loop commands."""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Sequence

from splitEvaluations.readiness_config import (
    DEV_LOOP_CVES,
    JOERN_DEV_MAX_K,
    JOERN_DEV_TIMEOUT_S,
    SEMGREP_DEV_MAX_K,
    SEMGREP_DEV_TIMEOUT_S,
)


def _base_python() -> list[str]:
    return [sys.executable, "-m"]


def semgrep_command() -> list[str]:
    return [
        *_base_python(),
        "splitEvaluations.run_semgrep_sweep",
        "--only-cves",
        *DEV_LOOP_CVES,
        "--max-k",
        str(SEMGREP_DEV_MAX_K),
        "--per-cve-timeout",
        str(SEMGREP_DEV_TIMEOUT_S),
    ]


def joern_command() -> list[str]:
    return [
        *_base_python(),
        "splitEvaluations.run_joern_sweep",
        "--only-cves",
        *DEV_LOOP_CVES,
        "--max-k",
        str(JOERN_DEV_MAX_K),
        "--per-cve-timeout",
        str(JOERN_DEV_TIMEOUT_S),
    ]


def _quote_cmd(cmd: Sequence[str]) -> str:
    return " ".join(subprocess.list2cmdline([part]) for part in cmd)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--arm",
        choices=("semgrep", "joern", "both"),
        default="both",
        help="Which readiness command(s) to run or print.",
    )
    parser.add_argument(
        "--run",
        action="store_true",
        help="Execute commands. Without this flag, commands are printed only.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    commands: list[list[str]] = []
    if args.arm in {"semgrep", "both"}:
        commands.append(semgrep_command())
    if args.arm in {"joern", "both"}:
        commands.append(joern_command())

    for cmd in commands:
        print(_quote_cmd(cmd))
        if args.run:
            subprocess.run(cmd, check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
