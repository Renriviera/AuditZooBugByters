"""Tests for model-generated Semgrep and Joern seed artifacts."""

from __future__ import annotations

import json

import pytest
import yaml

from auditzoo.agents.cwe78_study.model_seed import (
    JoernSeedCatalog,
    parse_joern_seed_catalog,
    parse_semgrep_seed_yaml,
)
from auditzoo.agents.cwe78_study.pipeline import PipelineConfig

_VALID_SEMGREP = """\
rules:
  - id: cwe78-model-os-system
    patterns:
      - pattern: os.system($CMD)
      - pattern-not: os.system("...")
    message: "Potential command injection"
    languages: [python]
    severity: ERROR
    metadata:
      cwe: "CWE-78"
      sink_api: "os.system"
"""


def test_parse_semgrep_seed_yaml_accepts_valid_rules() -> None:
    normalized = parse_semgrep_seed_yaml(_VALID_SEMGREP)
    loaded = yaml.safe_load(normalized)
    assert loaded["rules"][0]["id"] == "cwe78-model-os-system"


def test_parse_semgrep_seed_yaml_rejects_missing_rules() -> None:
    with pytest.raises(ValueError, match="rules list"):
        parse_semgrep_seed_yaml("not_rules: []")


def test_parse_semgrep_seed_yaml_rejects_non_python_rule() -> None:
    bad = _VALID_SEMGREP.replace("languages: [python]", "languages: [javascript]")
    with pytest.raises(ValueError, match="languages"):
        parse_semgrep_seed_yaml(bad)


def test_parse_joern_seed_catalog_accepts_and_deduplicates_json() -> None:
    catalog = parse_joern_seed_catalog(
        json.dumps(
            {
                "sources": ["request.args", "request.args", "sys.argv"],
                "sinks": ["os.system"],
                "sanitizers": ["shlex.quote", ""],
            }
        )
    )
    assert catalog == JoernSeedCatalog(
        sources=["request.args", "sys.argv"],
        sinks=["os.system"],
        sanitizers=["shlex.quote"],
    )


def test_parse_joern_seed_catalog_accepts_yaml() -> None:
    catalog = parse_joern_seed_catalog(
        """\
sources:
  - request.GET
sinks:
  - subprocess.run
sanitizers:
  - shlex.quote
"""
    )
    assert catalog.sinks == ["subprocess.run"]


def test_parse_joern_seed_catalog_rejects_empty_sinks() -> None:
    with pytest.raises(ValueError, match="sinks"):
        parse_joern_seed_catalog(
            {"sources": ["sys.argv"], "sinks": [], "sanitizers": []}
        )


def test_pipeline_config_stores_seed_overrides() -> None:
    cfg = PipelineConfig(
        semgrep_rules_yaml=_VALID_SEMGREP,
        joern_sources=["request.args"],
        joern_sinks=["os.system"],
        joern_sanitizers=["shlex.quote"],
    )
    assert cfg.semgrep_rules_yaml == _VALID_SEMGREP
    assert cfg.joern_sources == ["request.args"]
    assert cfg.joern_sinks == ["os.system"]
    assert cfg.joern_sanitizers == ["shlex.quote"]


def test_pipeline_config_defaults_preserve_static_seed_behavior() -> None:
    cfg = PipelineConfig()
    assert cfg.semgrep_rules_yaml is None
    assert cfg.joern_sources is None
    assert cfg.joern_sinks is None
    assert cfg.joern_sanitizers is None
