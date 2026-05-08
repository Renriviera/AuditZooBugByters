"""Tests for the Joern FP/FN post-processing audit."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from splitEvaluations.audit_joern_results import audit_results_json, build_audit, main


def _dataset() -> list[dict]:
    return [
        {
            "cve_id": "CVE-TEST-JOERN",
            "vulnerable_file": "app/shell.py",
            "vulnerable_lines": [42, 80, 120],
        }
    ]


def _triage_row(
    *,
    file: str = "app/shell.py",
    line: int,
    verdict: str,
    source_in_snippet: bool = True,
    reason: str = "reason",
) -> dict:
    return {
        "file": file,
        "line": line,
        "rule_id": "joern.cwe78",
        "sink_api": "os.system",
        "verdict": verdict,
        "confidence": 0.8,
        "reasoning": reason,
        "suggestion": "",
        "source_expr": "request.args['cmd']",
        "sink_expr": "os.system(cmd)",
        "source_in_snippet": source_in_snippet,
        "sink_in_snippet": True,
        "downgrade_reason": "",
    }


def _results() -> list[dict]:
    return [
        {
            "cve_id": "CVE-TEST-JOERN",
            "repo_url": "https://example.invalid/repo",
            "loc": 1000,
            "arms": {
                "joern_0": {
                    "tp": 1,
                    "fp": 2,
                    "fn": 2,
                    "fn_by_llm": 1,
                    "fp_by_hallucinated_source": 1,
                    "labels": [
                        "tp",
                        "fn_by_llm",
                        "fp_by_location",
                        "fp_by_hallucinated_source",
                    ],
                    "n_candidates": 4,
                    "metrics": {
                        "findings_hash": "hash-k0",
                        "joern_catalog_grew": True,
                        "llm_tokens_triage": 10,
                        "llm_tokens_refinement": 5,
                        "llm_triage_s": 1.0,
                        "llm_refinement_s": 2.0,
                        "scan_s": 3.0,
                        "cpg_build_s": 4.0,
                    },
                    "triage_verdicts": [
                        _triage_row(line=42, verdict="true_positive"),
                        _triage_row(
                            line=80,
                            verdict="false_positive",
                            reason="triager suppressed",
                        ),
                        _triage_row(
                            line=200,
                            verdict="uncertain",
                            reason="off ground truth",
                        ),
                        _triage_row(
                            line=121,
                            verdict="true_positive",
                            source_in_snippet=False,
                            reason="invented source",
                        ),
                    ],
                    "refinement_actions": [
                        {
                            "classifications": {
                                "wrap_source": "source-wrapper",
                                "safe": "sanitizer",
                            }
                        }
                    ],
                },
                "joern_1": {
                    "tp": 1,
                    "fp": 1,
                    "fn": 2,
                    "fn_by_llm": 0,
                    "fp_by_hallucinated_source": 0,
                    "labels": ["tp", "fp_by_llm_overclaim"],
                    "n_candidates": 2,
                    "metrics": {
                        "findings_hash": "hash-k1",
                        "joern_catalog_grew": False,
                    },
                    "triage_verdicts": [
                        _triage_row(line=42, verdict="true_positive"),
                        _triage_row(
                            line=200,
                            verdict="true_positive",
                            reason="overclaim",
                        ),
                    ],
                    "refinement_actions": [],
                },
                "joern_0_patched": {
                    "n_findings_on_patched": 1,
                    "metrics": {"findings_hash": "hash-patched"},
                    "triage_verdicts": [
                        _triage_row(line=42, verdict="true_positive"),
                    ],
                    "refinement_actions": [],
                },
            },
        },
        {
            "cve_id": "CVE-SKIPPED",
            "repo_url": "https://example.invalid/skipped",
            "skipped": "timeout",
            "per_cve_timeout_s": 1800.0,
        },
    ]


def test_build_audit_classifies_fp_categories_and_patched_alerts() -> None:
    audit = build_audit(_results(), _dataset(), line_tolerance=5)

    fp_causes = {row["fp_cause"] for row in audit["fp_rows"]}
    assert "scanner_location_fp" in fp_causes
    assert "evidence_hallucination" in fp_causes
    assert "triager_overclaim" in fp_causes
    assert "patched_commit_alert" in fp_causes


def test_build_audit_classifies_fn_causes() -> None:
    audit = build_audit(_results(), _dataset(), line_tolerance=5)
    k0_rows = [
        row
        for row in audit["fn_rows"]
        if row["cve_id"] == "CVE-TEST-JOERN" and row["arm_key"] == "joern_0"
    ]

    by_line = {row["vulnerable_line"]: row["fn_cause"] for row in k0_rows}
    assert by_line[80] == "triager_suppressed_gt"
    assert by_line[120] == "hallucinated_source_on_gt"


def test_iteration_summary_includes_refiner_and_delta_fields() -> None:
    audit = build_audit(_results(), _dataset(), line_tolerance=5)

    k0 = next(row for row in audit["iteration_summary"] if row["arm_key"] == "joern_0")
    k1 = next(row for row in audit["iteration_summary"] if row["arm_key"] == "joern_1")
    assert k0["joern_catalog_grew"] is True
    assert k0["refinement_actions_count"] == 1
    assert k0["refinement_roles"] == "sanitizer:1;source-wrapper:1"
    assert k1["findings_changed_vs_k0"] is True


def test_audit_results_json_writes_json_and_csv(tmp_path: Path) -> None:
    results_path = tmp_path / "results.json"
    dataset_path = tmp_path / "metadata.json"
    output_dir = tmp_path / "audit"
    results_path.write_text(json.dumps(_results()))
    dataset_path.write_text(json.dumps(_dataset()))

    audit = audit_results_json(
        results_path,
        dataset_path,
        output_dir,
        line_tolerance=5,
    )

    assert Path(audit["outputs"]["json"]).exists()
    assert Path(audit["outputs"]["fp_csv"]).exists()
    assert Path(audit["outputs"]["fn_csv"]).exists()
    assert Path(audit["outputs"]["iteration_csv"]).exists()

    with Path(audit["outputs"]["fp_csv"]).open(newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert rows
    assert {row["fp_cause"] for row in rows} >= {
        "scanner_location_fp",
        "evidence_hallucination",
        "triager_overclaim",
        "patched_commit_alert",
    }


def test_cli_smoke_writes_outputs(tmp_path: Path, capsys) -> None:
    results_path = tmp_path / "results.json"
    dataset_path = tmp_path / "metadata.json"
    output_dir = tmp_path / "audit"
    results_path.write_text(json.dumps(_results()))
    dataset_path.write_text(json.dumps(_dataset()))

    rc = main(
        [
            str(results_path),
            "--dataset",
            str(dataset_path),
            "--line-tolerance",
            "5",
            "--output-dir",
            str(output_dir),
        ]
    )

    captured = capsys.readouterr()
    assert rc == 0
    assert "FP rows" in captured.out
    assert (output_dir / "joern_fp_fn_audit.json").exists()
