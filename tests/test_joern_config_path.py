"""Joern install path resolution (no Joern execution)."""

from __future__ import annotations

import os
import sys

from auditzoo.backends.base import JoernConfig


def test_joern_config_uses_sys_prefix_when_conda_unset(monkeypatch) -> None:
    monkeypatch.delenv("CONDA_PREFIX", raising=False)
    monkeypatch.delenv("AUDITZOO_JOERN_PATH", raising=False)
    cfg = JoernConfig(source_path="/tmp", language="python")
    assert cfg.joern_path == os.path.join(sys.prefix, "opt", "joern")


def test_joern_config_respects_auditzoo_joern_path(monkeypatch, tmp_path) -> None:
    fake = tmp_path / "joern"
    monkeypatch.setenv("AUDITZOO_JOERN_PATH", str(fake))
    monkeypatch.delenv("CONDA_PREFIX", raising=False)
    cfg = JoernConfig(source_path="/tmp", language="python")
    assert cfg.joern_path == str(fake)
