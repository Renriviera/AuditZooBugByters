"""Catalog loader tests for Joern seed rules."""

from __future__ import annotations

from auditzoo.agents.cwe78_study.joern_arm import _load_catalog


def test_common_python_sink_catalog_entries_are_loaded() -> None:
    sinks = set(_load_catalog("sinks"))

    expected = {
        "asyncio.create_subprocess_shell",
        "asyncio.create_subprocess_exec",
        "os.execv",
        "os.execve",
        "os.execl",
        "os.execle",
        "os.execlp",
        "os.execlpe",
        "os.spawnv",
        "os.spawnve",
        "os.spawnvp",
        "os.spawnvpe",
        "os.spawnl",
        "os.spawnle",
        "os.spawnlp",
        "os.spawnlpe",
        "os.popen2",
        "os.popen3",
        "os.popen4",
        "Popen",
        "pexpect.spawn",
        "pexpect.run",
        "pexpect.runu",
        "paramiko.SSHClient.exec_command",
        "fabric.Connection.run",
        "fabric.Connection.sudo",
        "fabric.Connection.local",
        "invoke.run",
        "invoke.sudo",
    }

    assert expected <= sinks
