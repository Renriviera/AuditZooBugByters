"""Tests for the Joern false-negative audit script."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from splitEvaluations import audit_joern_fn as audit


def _candidate(
    file: str,
    line: int,
    *,
    verdict: str = "uncertain",
    sink_api: str = "run",
    reasoning: str = "",
    suggestion: str = "",
    source_in_snippet: bool = True,
    joern_flow_locations: list[str] | None = None,
    source_kind: str = "",
    sink_kind: str = "",
    shell_true: bool = False,
    origin_external: bool = False,
    origin_evidence: list[dict] | None = None,
    caller_chain: list[dict] | None = None,
    sink_caller_chain: list[dict] | None = None,
    sink_callsite: dict | None = None,
    report_candidate_locations: list[dict] | None = None,
) -> dict:
    return {
        "file": file,
        "line": line,
        "rule_id": "joern-taint-reachability",
        "sink_api": sink_api,
        "verdict": verdict,
        "confidence": 0.9,
        "reasoning": reasoning,
        "suggestion": suggestion,
        "source_expr": "",
        "sink_expr": "",
        "source_in_snippet": source_in_snippet,
        "sink_in_snippet": True,
        "downgrade_reason": "",
        "joern_flow_locations": joern_flow_locations or [],
        "sourceKind": source_kind,
        "originExternalSource": origin_external,
        "originEvidence": origin_evidence or [],
        "callerChain": caller_chain or [],
        "sinkCallerChain": sink_caller_chain or [],
        "sinkCallsite": sink_callsite or {},
        "reportCandidateLocations": report_candidate_locations or [],
        "sinkKind": sink_kind,
        "shell_true": shell_true,
    }


def _result(
    cve_id: str,
    candidates: list[dict],
    *,
    repo_url: str = "unused",
    metrics: dict | None = None,
) -> dict:
    return {
        "cve_id": cve_id,
        "repo_url": repo_url,
        "arms": {
            "joern_0": {
                "tp": 0,
                "fp": len(candidates),
                "fn": 1,
                "n_candidates": len(candidates),
                "metrics": metrics or {},
                "triage_verdicts": candidates,
            }
        },
    }


def _metadata(cve_id: str, gt_file: str, gt_lines: list[int]) -> dict[str, dict]:
    return {
        cve_id: {
            "cve_id": cve_id,
            "repo_url": "unused",
            "vulnerable_file": gt_file,
            "vulnerable_lines": gt_lines,
        }
    }


def test_zero_candidate_cve_produces_zero_candidate_row() -> None:
    rows = audit.build_fn_rows(
        [_result("CVE-ZERO", [])],
        _metadata("CVE-ZERO", "pkg/app.py", [42]),
        line_tolerance=5,
    )

    assert len(rows) == 1
    assert rows[0]["fn_category"] == "zero_candidate"
    assert rows[0]["fn_category_detail"] == "zero_candidate_after_expanded_sources"
    assert rows[0]["candidate_count"] == 0
    assert rows[0]["same_file_candidate_count"] == 0


def test_same_file_candidate_outside_tolerance_is_near_miss() -> None:
    rows = audit.build_fn_rows(
        [_result("CVE-NEAR", [_candidate("pkg/app.py", 20)])],
        _metadata("CVE-NEAR", "pkg/app.py", [42]),
        line_tolerance=5,
    )

    assert len(rows) == 1
    assert rows[0]["fn_category"] == "same_file_near_miss"
    assert rows[0]["nearest_candidate_file"] == "pkg/app.py"
    assert rows[0]["nearest_candidate_line"] == 20
    assert rows[0]["nearest_distance"] == 22


def test_uncertain_related_candidates_with_missing_context_are_evidence_missing() -> (
    None
):
    candidates = [
        _candidate(
            "openhands/runtime/utils/git_diff.py",
            33,
            reasoning=(
                "The sink is visible, but the source of cmd is not shown in "
                "the provided context."
            ),
            suggestion="Include caller dataflow into cmd so the source can be verified.",
        ),
        _candidate(
            "openhands/runtime/utils/git_changes.py",
            21,
            reasoning="The origin of cmd is not visible here.",
            suggestion="Include caller context and taint path.",
        ),
    ]

    rows = audit.build_fn_rows(
        [_result("CVE-EVID", candidates)],
        _metadata("CVE-EVID", "openhands/runtime/utils/git_diff.py", [92]),
        line_tolerance=5,
    )

    assert len(rows) == 1
    assert rows[0]["fn_category"] == "triage_evidence_missing"
    assert rows[0]["same_file_candidate_count"] == 1
    assert "source/caller/dataflow" in rows[0]["evidence_notes"]


def test_aggregate_summary_counts_categories_and_recommendations() -> None:
    rows = [
        {
            "cve_id": "CVE-A",
            "fn_category": "zero_candidate",
            "top_candidate_files": [],
            "top_sink_apis": [],
            "top_source_kinds": [],
            "top_sink_kinds": [],
            "top_sink_semantic_flags": [],
        },
        {
            "cve_id": "CVE-B",
            "fn_category": "same_file_near_miss",
            "top_candidate_files": ["pkg/a.py:2"],
            "top_sink_apis": ["run:2"],
            "top_source_kinds": ["parameter:2"],
            "top_sink_kinds": ["direct:2"],
            "top_sink_semantic_flags": ["shell_true:2"],
        },
        {
            "cve_id": "CVE-C",
            "fn_category": "triage_evidence_missing",
            "top_candidate_files": ["pkg/b.py:1"],
            "top_sink_apis": ["Popen:1"],
            "top_source_kinds": ["attribute:1"],
            "top_sink_kinds": ["wrapper:1"],
            "top_sink_semantic_flags": [],
        },
        {
            "cve_id": "CVE-D",
            "fn_category": "flow_path_location_match",
            "top_candidate_files": ["pkg/helper.py:1"],
            "top_sink_apis": ["run:1"],
            "top_source_kinds": [],
            "top_sink_kinds": [],
            "top_sink_semantic_flags": [],
            "flow_path_match": True,
        },
    ]

    summary = audit.build_summary(rows)

    assert summary["n_fn_rows"] == 4
    assert summary["category_counts"] == {
        "flow_path_location_match": 1,
        "same_file_near_miss": 1,
        "triage_evidence_missing": 1,
        "zero_candidate": 1,
    }
    assert summary["zero_candidate_cves"] == ["CVE-A"]
    assert summary["same_file_near_miss_cves"] == ["CVE-B"]
    assert summary["flow_path_match_cves"] == ["CVE-D"]
    assert summary["top_source_kinds"] == ["parameter:2", "attribute:1"]
    assert summary["top_sink_kinds"] == ["direct:2", "wrapper:1"]
    assert summary["top_sink_semantic_flags"] == ["shell_true:2"]
    assert "pass_joern_structural_evidence_to_triage" in summary["recommendations"]
    assert (
        "promote_joern_flow_path_callsite_to_report_location"
        in summary["recommendations"]
    )
    assert (
        "audit_source_sink_catalog_coverage_for_zero_candidate_cves"
        in summary["recommendations"]
    )


def test_cli_defaults_output_paths_stay_under_results_parent(tmp_path: Path) -> None:
    results_path = tmp_path / "results.json"
    dataset_path = tmp_path / "metadata.json"
    results_path.write_text(json.dumps([_result("CVE-CLI", [])]))
    dataset_path.write_text(
        json.dumps(
            [
                {
                    "cve_id": "CVE-CLI",
                    "repo_url": "unused",
                    "vulnerable_file": "pkg/app.py",
                    "vulnerable_lines": [7],
                }
            ]
        )
    )

    output = audit.audit_results_json(results_path, dataset_path)

    assert output["output_dir"] == str(tmp_path)
    assert output["artifacts"] == {
        "json": str(tmp_path / "joern_fn_audit.json"),
        "csv": str(tmp_path / "joern_fn_audit.csv"),
        "md": str(tmp_path / "joern_fn_audit.md"),
    }
    for artifact_path in output["artifacts"].values():
        assert Path(artifact_path).exists()

    with (tmp_path / "joern_fn_audit.csv").open(newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert rows[0]["cve_id"] == "CVE-CLI"
    assert rows[0]["fn_category"] == "zero_candidate"
    assert rows[0]["fn_category_detail"] == "zero_candidate_after_expanded_sources"


def test_near_false_positive_candidate_is_llm_suppressed_match() -> None:
    rows = audit.build_fn_rows(
        [
            _result(
                "CVE-LLM",
                [_candidate("pkg/app.py", 44, verdict="false_positive")],
            )
        ],
        _metadata("CVE-LLM", "pkg/app.py", [42]),
        line_tolerance=5,
    )

    assert rows[0]["fn_category"] == "llm_suppressed_match"


def test_flow_path_match_is_reported_when_primary_location_misses_gt() -> None:
    rows = audit.build_fn_rows(
        [
            _result(
                "CVE-FLOW",
                [
                    _candidate(
                        "pkg/helper.py",
                        10,
                        verdict="true_positive",
                        source_in_snippet=True,
                        joern_flow_locations=["pkg/app.py:42", "pkg/helper.py:10"],
                    )
                ],
            )
        ],
        _metadata("CVE-FLOW", "pkg/app.py", [42]),
        line_tolerance=5,
    )

    assert rows[0]["fn_category"] == "flow_path_location_match"
    assert rows[0]["flow_path_match"] is True
    assert rows[0]["flow_path_match_count"] == 1
    assert "pkg/app.py:42" in rows[0]["nearest_flow_locations"]


def test_audit_rows_summarize_source_sink_kinds_and_semantics() -> None:
    rows = audit.build_fn_rows(
        [
            _result(
                "CVE-META",
                [
                    _candidate(
                        "pkg/helper.py",
                        10,
                        source_kind="parameter",
                        sink_kind="wrapper",
                        shell_true=True,
                    )
                ],
            )
        ],
        _metadata("CVE-META", "pkg/app.py", [42]),
        line_tolerance=5,
    )

    assert rows[0]["fn_category_detail"] == "wrapper_sink_candidate"
    assert rows[0]["top_source_kinds"] == ["parameter:1"]
    assert rows[0]["top_sink_kinds"] == ["wrapper:1"]
    assert rows[0]["top_sink_semantic_flags"] == ["shell_true:1"]


def test_audit_rows_include_candidate_reducer_metrics() -> None:
    rows = audit.build_fn_rows(
        [
            _result(
                "CVE-REDUCE",
                [_candidate("pkg/helper.py", 10)],
                metrics={
                    "joern_raw_findings": 5,
                    "joern_triaged_findings": 1,
                    "joern_candidates_dropped_before_triage": 4,
                    "joern_dropped_reason_counts": {"wrapper": 3, "low_signal_path": 1},
                },
            )
        ],
        _metadata("CVE-REDUCE", "pkg/app.py", [42]),
        line_tolerance=5,
    )
    summary = audit.build_summary(rows)

    assert rows[0]["raw_candidate_count"] == 5
    assert rows[0]["triaged_candidate_count"] == 1
    assert rows[0]["dropped_candidate_count"] == 4
    assert rows[0]["dropped_reason_counts"] == {"wrapper": 3, "low_signal_path": 1}
    assert summary["raw_candidate_total"] == 5
    assert summary["triaged_candidate_total"] == 1
    assert summary["dropped_candidate_total"] == 4
    assert summary["top_dropped_reasons"] == ["wrapper:3", "low_signal_path:1"]


def test_audit_rows_include_origin_and_report_candidate_metrics() -> None:
    rows = audit.build_fn_rows(
        [
            _result(
                "CVE-ORIGIN",
                [
                    _candidate(
                        "pkg/helper.py",
                        10,
                        origin_external=True,
                        origin_evidence=[
                            {
                                "file": "pkg/app.py",
                                "line": "35",
                                "code": "cmd = os.getenv('CMD')",
                                "matchesExternal": True,
                            }
                        ],
                        caller_chain=[
                            {
                                "file": "pkg/app.py",
                                "line": "40",
                                "code": "run(request.args['cmd'])",
                                "argumentCode": "request.args['cmd']",
                                "matchesExternal": True,
                            }
                        ],
                        sink_caller_chain=[
                            {
                                "file": "pkg/app.py",
                                "line": "41",
                                "code": "run_user_command(request.args['cmd'])",
                                "matchesExternal": True,
                            }
                        ],
                        sink_callsite={
                            "file": "pkg/helper.py",
                            "line": "10",
                            "code": "subprocess.run(cmd, shell=True)",
                            "matchesExternal": False,
                        },
                        report_candidate_locations=[
                            {
                                "file": "pkg/app.py",
                                "line": 42,
                                "reason": "wrapper_internal_sink",
                            }
                        ],
                    )
                ],
            )
        ],
        _metadata("CVE-ORIGIN", "pkg/app.py", [42]),
        line_tolerance=5,
    )
    summary = audit.build_summary(rows)

    assert rows[0]["origin_external_source_count"] == 1
    assert rows[0]["origin_evidence_count"] == 1
    assert rows[0]["caller_evidence_count"] == 1
    assert rows[0]["sink_caller_evidence_count"] == 1
    assert rows[0]["sink_callsite_evidence_count"] == 1
    assert rows[0]["report_candidate_location_count"] == 1
    assert rows[0]["report_candidate_location_match"] is True
    assert summary["joern_origin_external_count"] == 1
    assert summary["origin_evidence_count"] == 1
    assert summary["caller_evidence_count"] == 1
    assert summary["sink_caller_evidence_count"] == 1
    assert summary["sink_callsite_evidence_count"] == 1
    assert summary["report_candidate_location_tp"] == 1
