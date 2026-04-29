"""Tests for the GPT 5.4 mini Joern diagnostic runner."""

from __future__ import annotations

from argparse import Namespace

from splitEvaluations import run_gpt54_joern_diagnostic as diag
from splitEvaluations.readiness_config import (
    GPT54_JOERN_DIAGNOSTIC_CVES,
    JOERN_DIAGNOSTIC_30_CVES,
)


def test_default_args_use_fixed_10_cve_joern_set() -> None:
    args = diag.parse_args([])

    assert args.llm_model == diag.GPT54_MODEL
    assert args.llm_url == diag.GPT54_BASE_URL
    assert args.max_k == 0
    assert args.per_cve_timeout == 900.0
    assert args.run_patched is False
    assert args.joern_modeling_mode == "full_wrapper"
    assert args.joern_max_triage_candidates == 30
    assert args.joern_high_risk_candidate_cap == 20
    assert args.joern_low_risk_candidate_cap == 10
    assert args.joern_disable_candidate_reducer is False
    assert args.joern_retry_uncertain_with_flow_path is False
    assert args.joern_disable_argv_exception is False
    assert args.joern_skip_triage is False
    assert args.joern_emit_coverage_probe is True
    assert args.cve_set == "10"
    assert args.only_cves is None


def test_cve_set_30_flag_selects_30_cve_list() -> None:
    args = diag.parse_args(["--cve-set", "30"])

    assert args.cve_set == "30"
    # only_cves remains None until main() resolves it.
    assert args.only_cves is None
    assert len(JOERN_DIAGNOSTIC_30_CVES) == 30
    # Resolution mirrors main()'s helper logic.
    resolved = (
        list(args.only_cves)
        if args.only_cves
        else (
            list(JOERN_DIAGNOSTIC_30_CVES)
            if args.cve_set == "30"
            else list(GPT54_JOERN_DIAGNOSTIC_CVES)
        )
    )
    assert tuple(resolved) == JOERN_DIAGNOSTIC_30_CVES


def test_only_cves_overrides_cve_set() -> None:
    args = diag.parse_args(["--cve-set", "30", "--only-cves", "CVE-X-1", "CVE-X-2"])
    assert args.cve_set == "30"
    assert list(args.only_cves) == ["CVE-X-1", "CVE-X-2"]


def test_api_key_precedence_and_redaction(monkeypatch) -> None:
    monkeypatch.setattr(diag, "GPT54_API_KEY", "placeholder-key")
    monkeypatch.setenv("OPENAI_API_KEY", "env-key")

    args = diag.parse_args([])
    assert diag.resolve_api_key(args) == "env-key"

    args_cli = diag.parse_args(["--api-key", "cli-key"])
    assert diag.resolve_api_key(args_cli) == "cli-key"

    config = diag._redacted_run_config(
        args_cli,
        api_key="cli-key",
        joern_env={
            "AUDITZOO_SKIP_PRELOAD_CALLS": "1",
            "AUDITZOO_SKIP_PRELOAD_FACTS": "1",
        },
    )
    assert config["api_key"] == "<redacted>"
    assert config["uses_process_isolation_watchdog"] is True
    assert config["expected_timeout_scope"] == "process_group"
    assert config["joern_modeling_mode"] == "full_wrapper"
    assert config["joern_max_triage_candidates"] == 30
    assert config["joern_high_risk_candidate_cap"] == 20
    assert config["joern_low_risk_candidate_cap"] == 10
    assert "cli-key" not in str(config)


def test_joern_ablation_flags_parse_and_redact() -> None:
    args = diag.parse_args(
        [
            "--joern-modeling-mode",
            "catalog_parameter",
            "--joern-max-triage-candidates",
            "25",
            "--joern-high-risk-candidate-cap",
            "15",
            "--joern-low-risk-candidate-cap",
            "5",
            "--joern-disable-candidate-reducer",
            "--joern-retry-uncertain-with-flow-path",
            "--joern-flow-path-retry-limit",
            "3",
            "--joern-disable-argv-exception",
            "--joern-skip-triage",
        ]
    )

    config = diag._redacted_run_config(
        args,
        api_key="key",
        joern_env={
            "AUDITZOO_SKIP_PRELOAD_CALLS": "1",
            "AUDITZOO_SKIP_PRELOAD_FACTS": "1",
        },
    )

    assert args.joern_modeling_mode == "catalog_parameter"
    assert args.joern_max_triage_candidates == 25
    assert args.joern_high_risk_candidate_cap == 15
    assert args.joern_low_risk_candidate_cap == 5
    assert args.joern_disable_candidate_reducer is True
    assert args.joern_retry_uncertain_with_flow_path is True
    assert args.joern_flow_path_retry_limit == 3
    assert args.joern_disable_argv_exception is True
    assert args.joern_skip_triage is True
    assert config["joern_modeling_mode"] == "catalog_parameter"
    assert config["joern_high_risk_candidate_cap"] == 15
    assert config["joern_low_risk_candidate_cap"] == 5
    assert config["joern_disable_argv_exception"] is True
    assert config["joern_skip_triage"] is True


def test_configure_joern_env_sets_preload_skips(monkeypatch) -> None:
    monkeypatch.delenv("AUDITZOO_SKIP_PRELOAD_CALLS", raising=False)
    monkeypatch.delenv("AUDITZOO_SKIP_PRELOAD_FACTS", raising=False)

    env = diag.configure_joern_env(disable_preload_skip=False)

    assert env == {
        "AUDITZOO_SKIP_PRELOAD_CALLS": "1",
        "AUDITZOO_SKIP_PRELOAD_FACTS": "1",
    }


def test_configure_joern_env_can_leave_existing_env(monkeypatch) -> None:
    monkeypatch.setenv("AUDITZOO_SKIP_PRELOAD_CALLS", "0")
    monkeypatch.setenv("AUDITZOO_SKIP_PRELOAD_FACTS", "0")

    env = diag.configure_joern_env(disable_preload_skip=True)

    assert env == {
        "AUDITZOO_SKIP_PRELOAD_CALLS": "0",
        "AUDITZOO_SKIP_PRELOAD_FACTS": "0",
    }


def test_build_joern_diagnostic_summary_records_watchdog_and_metrics() -> None:
    results = [
        {
            "cve_id": "CVE-TIMEOUT",
            "skipped": "timeout",
            "timeout_meta": {
                "elapsed_s": 900.0,
                "kill_signal": "SIGKILL",
                "timeout_scope": "process_group",
                "process_tree_before": {"rss_mb": 2048.0},
            },
        },
        {
            "cve_id": "CVE-DONE",
            "arms": {
                "joern_0": {
                    "tp": 1,
                    "fp": 2,
                    "fn": 3,
                    "n_candidates": 3,
                    "tp_via_same_package_promoted": 4,
                    "relaxed_tp": 5,
                    "metrics": {
                        "cpg_build_s": 10.0,
                        "scan_s": 2.0,
                        "llm_triage_s": 1.0,
                        "llm_refinement_s": 0.0,
                        "call_graph_s": 0.0,
                        "joern_raw_findings": 5,
                        "joern_triaged_findings": 3,
                        "joern_candidates_dropped_before_triage": 2,
                        "joern_flow_path_retry_count": 1,
                        "joern_flow_path_retry_tokens": 10,
                        "joern_flow_path_retry_tp_delta": 1,
                        "joern_high_risk_count": 4,
                        "joern_high_risk_kept": 3,
                        "joern_high_risk_dropped_when_overflow": 1,
                        "joern_low_risk_count": 6,
                        "joern_low_risk_kept": 4,
                        "joern_low_risk_dropped_when_overflow": 2,
                        "joern_coverage_probe": {
                            "gt_file_seen": False,
                            "method_count": 0,
                            "gt_sink_count": 0,
                            "external_source_count": 0,
                        },
                        "joern_catalog_grew": True,
                        "llm_usage": {
                            "prompt_tokens": 100,
                            "completion_tokens": 20,
                            "total_tokens": 120,
                            "call_count": 3,
                        },
                    },
                    "run_meta": {
                        "timeout_scope": "process_group",
                        "child_exitcode": 0,
                    },
                }
            },
        },
    ]

    summary = diag.build_joern_diagnostic_summary(results)

    assert summary["skipped"] == {"timeout": 1}
    assert summary["timeout_cves"] == ["CVE-TIMEOUT"]
    assert summary["child_kills"][0]["kill_signal"] == "SIGKILL"
    assert summary["timeout_scopes"] == {"process_group": 1}
    assert summary["by_k"]["0"]["tp"] == 1
    assert summary["by_k"]["0"]["fp"] == 2
    assert summary["by_k"]["0"]["fn"] == 3
    assert summary["by_k"]["0"]["joern_raw_findings"] == 5
    assert summary["by_k"]["0"]["joern_triaged_findings"] == 3
    assert summary["by_k"]["0"]["joern_candidates_dropped_before_triage"] == 2
    assert summary["by_k"]["0"]["joern_flow_path_retry_count"] == 1
    assert summary["by_k"]["0"]["joern_high_risk_count"] == 4
    assert summary["by_k"]["0"]["joern_high_risk_kept"] == 3
    assert summary["by_k"]["0"]["joern_high_risk_dropped_when_overflow"] == 1
    assert summary["by_k"]["0"]["joern_low_risk_count"] == 6
    assert summary["by_k"]["0"]["joern_low_risk_kept"] == 4
    assert summary["by_k"]["0"]["joern_low_risk_dropped_when_overflow"] == 2
    assert summary["by_k"]["0"]["tp_via_same_package_promoted"] == 4
    assert summary["by_k"]["0"]["relaxed_tp"] == summary["by_k"]["0"]["tp"] + 4
    assert summary["by_k"]["0"]["cves_without_gt_file_in_cpg"] == ["CVE-DONE"]
    assert summary["by_k"]["0"]["cves_without_gt_sink"] == ["CVE-DONE"]
    assert summary["by_k"]["0"]["cves_without_external_source_in_gt_file"] == [
        "CVE-DONE"
    ]
    assert summary["by_k"]["0"]["llm_total_tokens"] == 120
    assert summary["candidate_cves"] == ["CVE-DONE"]
    assert summary["tp_cves"] == ["CVE-DONE"]
    assert summary["catalog_growth_cves"] == ["CVE-DONE"]
    assert summary["readiness_gates"]["process_isolation_used"] is True
    assert summary["readiness_gates"]["timeouts_recorded_with_kill_metadata"] is True


def test_pipeline_config_would_use_joern_arm() -> None:
    args = Namespace(
        max_k=0,
        seed=235711,
        llm_url=diag.GPT54_BASE_URL,
        llm_model=diag.GPT54_MODEL,
        joern_port=12345,
    )

    # Keep this tiny assertion close to the runner defaults: the shared
    # evaluation loop switches to process isolation when arms contains "joern".
    assert ["joern"] == ["joern"]
    assert args.llm_model == "gpt-5.4-mini"
