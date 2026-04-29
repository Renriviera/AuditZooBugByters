"""Tests for the GPT 5.4 mini Semgrep diagnostic runner."""

from __future__ import annotations

from pathlib import Path

from splitEvaluations import run_gpt54mini_semgrep_diagnostic as diag
from splitEvaluations.readiness_config import GPT54_MINI_DIAGNOSTIC_CVES


def test_default_args_use_fixed_10_cve_diagnostic_set() -> None:
    args = diag.parse_args([])

    assert args.llm_model == diag.GPT54_MINI_MODEL
    assert args.llm_url == diag.GPT54_MINI_BASE_URL
    assert args.max_k == 3
    assert args.per_cve_timeout == 300.0
    assert args.no_patched is False
    assert tuple(args.only_cves) == GPT54_MINI_DIAGNOSTIC_CVES
    assert len(args.only_cves) == 10
    assert len(set(args.only_cves)) == 10
    assert "CVE-2025-1753" not in args.only_cves


def test_api_key_precedence_and_redaction(monkeypatch) -> None:
    monkeypatch.setattr(diag, "GPT54_MINI_API_KEY", "placeholder-key")
    monkeypatch.setenv("OPENAI_API_KEY", "env-key")

    args = diag.parse_args([])
    assert diag.resolve_api_key(args) == "env-key"

    args_cli = diag.parse_args(["--api-key", "cli-key"])
    assert diag.resolve_api_key(args_cli) == "cli-key"

    config = diag._redacted_run_config(args_cli, api_key="cli-key")
    assert config["api_key"] == "<redacted>"
    assert "cli-key" not in str(config)


def test_api_key_falls_back_to_top_level_placeholder(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(diag, "GPT54_MINI_API_KEY", "placeholder-key")

    args = diag.parse_args([])

    assert diag.resolve_api_key(args) == "placeholder-key"


def test_build_diagnostic_summary_flags_refinement_failures() -> None:
    results = [
        {
            "cve_id": "CVE-A",
            "arms": {
                "semgrep_0": {
                    "tp": 1,
                    "fp": 0,
                    "fn": 0,
                    "n_candidates": 1,
                    "metrics": {
                        "llm_usage": {
                            "prompt_tokens": 10,
                            "completion_tokens": 2,
                            "total_tokens": 12,
                            "call_count": 1,
                        },
                        "findings_hash": "hash-a",
                        "rules_yaml_changed": False,
                    },
                    "refinement_actions": [
                        {
                            "action": "refine",
                            "target_rule_id": "cwe78-os-system",
                            "add_pattern_not": ["file:foo.py line:12"],
                            "apply_status": "noop_duplicate",
                            "rationale": "file-specific exclusion",
                        }
                    ],
                },
                "semgrep_1": {
                    "tp": 1,
                    "fp": 0,
                    "fn": 0,
                    "n_candidates": 1,
                    "metrics": {
                        "llm_usage": {
                            "prompt_tokens": 20,
                            "completion_tokens": 4,
                            "total_tokens": 24,
                            "call_count": 2,
                        },
                        "findings_hash": "hash-b",
                        "rules_yaml_changed": True,
                    },
                    "refinement_actions": [
                        {
                            "action": "refine",
                            "target_rule_id": "cwe78-os-system",
                            "add_source_patterns": ["request.args.get(...)"],
                            "apply_status": "structured_sources_added",
                            "rationale": "add source",
                        }
                    ],
                },
            },
        },
        {
            "cve_id": "CVE-B",
            "arms": {
                "semgrep_0": {
                    "tp": 0,
                    "fp": 0,
                    "fn": 2,
                    "n_candidates": 0,
                    "metrics": {"llm_usage": {}, "findings_hash": "empty"},
                    "refinement_actions": [],
                }
            },
        },
    ]
    rules_audit = {
        "refine_actions_no_op": 1,
        "refine_no_op_rate": 0.5,
        "cves_in_audit": 2,
        "cves_with_k_invariant_findings": 1,
        "findings_invariance_frac": 0.5,
    }

    summary = diag.build_diagnostic_summary(results, rules_audit)

    assert summary["zero_candidate_cves"] == ["CVE-B"]
    assert summary["candidate_no_tp_cves"] == []
    assert summary["refinement"]["refine_actions_total"] == 2
    assert summary["refinement"]["actionable_refinements"] == 1
    assert summary["refinement"]["apply_statuses"] == {
        "noop_duplicate": 1,
        "structured_sources_added": 1,
    }
    assert len(summary["refinement"]["file_line_pattern_not"]) == 1
    assert summary["by_k"]["0"]["tp"] == 1
    assert summary["by_k"]["0"]["fn"] == 2
    assert summary["llm_usage"]["llm_total_tokens"] == 36
    assert summary["readiness_gates"]["structured_refinement_seen"] is True
    assert summary["ready_for_full_frontier_sweep"] is False


def test_file_logging_adds_log_file(tmp_path: Path) -> None:
    log_path = tmp_path / "diagnostic.log"

    diag._add_file_logging(log_path)

    assert log_path.parent.exists()
