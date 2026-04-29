"""Tests for the Joern false-positive audit sidecar."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from splitEvaluations import audit_joern_fp as audit


def _result_with_candidates(candidates: list[dict], labels: list[str]) -> dict:
    return {
        "cve_id": "CVE-DEMO",
        "arms": {
            "joern_0": {
                "triage_verdicts": candidates,
                "labels": labels,
            }
        },
    }


def _candidate(
    file: str,
    line: int,
    *,
    verdict: str = "uncertain",
    sink_api: str = "run",
    sink_kind: str = "direct",
    source_in_snippet: bool = True,
    origin_external: bool = False,
    literal_command_like: bool = False,
) -> dict:
    return {
        "file": file,
        "line": line,
        "verdict": verdict,
        "confidence": 0.9,
        "sink_api": sink_api,
        "source_in_snippet": source_in_snippet,
        "originExternalSource": origin_external,
        "sinkKind": sink_kind,
        "sourceKind": "parameter",
        "joern_report_reason": "wrapper_caller_relocation",
        "literal_command_like": literal_command_like,
        "sink_expr": "subprocess.run(cmd, shell=True)",
        "source_expr": "cmd",
        "reasoning": "demo",
    }


def test_fp_audit_counts_fp_labels_and_ignores_non_fp() -> None:
    metadata = {
        "CVE-DEMO": {
            "vulnerable_file": "pkg/vuln.py",
            "vulnerable_lines": [42],
        }
    }
    results = [
        _result_with_candidates(
            [
                _candidate("pkg/helper.py", 10, verdict="uncertain"),
                _candidate("pkg/other.py", 20, verdict="true_positive"),
                _candidate(
                    "pkg/vuln.py",
                    42,
                    verdict="true_positive",
                    source_in_snippet=False,
                ),
                _candidate("pkg/vuln.py", 42, verdict="uncertain"),
                _candidate("pkg/safe.py", 5, verdict="false_positive"),
            ],
            [
                "fp_by_location",
                "fp_by_llm_overclaim",
                "fp_by_hallucinated_source",
                "tp",
                "tn",
            ],
        )
    ]

    rows = audit.build_fp_rows(results, metadata)
    summary = audit.build_summary(rows)

    assert len(rows) == 3
    assert summary["total_fp"] == 3
    assert summary["fp_by_location"] == 1
    assert summary["fp_by_llm_overclaim"] == 1
    assert summary["fp_by_hallucinated_source"] == 1
    assert summary["by_verdict"] == {"true_positive": 2, "uncertain": 1}


def test_fp_audit_file_relation_and_top_counts() -> None:
    metadata = {
        "CVE-DEMO": {
            "vulnerable_file": "pkg/vuln.py",
            "vulnerable_lines": [42],
        }
    }
    results = [
        _result_with_candidates(
            [
                _candidate("pkg/helper.py", 10, sink_api="Popen"),
                _candidate("other/file.py", 20, sink_api="system"),
                _candidate("pkg/vuln.py", 99, sink_api="Popen"),
            ],
            ["fp_by_location", "fp_by_location", "fp_by_llm_overclaim"],
        )
    ]

    rows = audit.build_fp_rows(results, metadata)
    summary = audit.build_summary(rows)

    assert summary["by_file_relation"] == {
        "same_package": 1,
        "other_file": 1,
        "gt_file": 1,
    }
    assert summary["by_sink_api"] == {"Popen": 2, "system": 1}
    assert summary["top_cves"] == {"CVE-DEMO": 3}
    assert summary["top_files"]["pkg/helper.py"] == 1


def test_fp_audit_semantic_flag_summary() -> None:
    metadata = {"CVE-DEMO": {"vulnerable_file": "pkg/vuln.py"}}
    results = [
        _result_with_candidates(
            [
                _candidate("pkg/helper.py", 10, literal_command_like=True),
                _candidate("pkg/other.py", 20),
            ],
            ["fp_by_location", "fp_by_location"],
        )
    ]

    summary = audit.build_summary(audit.build_fp_rows(results, metadata))

    assert summary["by_semantic_flag"] == {
        "literal_command_like": 1,
        "no_semantic_flag": 1,
    }


def test_fp_audit_rejects_label_verdict_length_mismatch() -> None:
    metadata = {"CVE-DEMO": {"vulnerable_file": "pkg/vuln.py"}}
    results = [_result_with_candidates([_candidate("pkg/helper.py", 10)], [])]

    rows = audit.build_fp_rows(results, metadata)
    assert rows == []

    mismatched = [_result_with_candidates([_candidate("pkg/helper.py", 10)], ["tp", "tn"])]
    with pytest.raises(ValueError, match="labels length"):
        audit.build_fp_rows(mismatched, metadata)


def test_fp_audit_writes_json_csv_and_markdown(tmp_path: Path) -> None:
    results_path = tmp_path / "results.json"
    dataset_path = tmp_path / "metadata.json"
    results_path.write_text(
        json.dumps(
            [
                _result_with_candidates(
                    [_candidate("pkg/helper.py", 10)],
                    ["fp_by_location"],
                )
            ]
        )
    )
    dataset_path.write_text(
        json.dumps(
            [
                {
                    "cve_id": "CVE-DEMO",
                    "vulnerable_file": "pkg/vuln.py",
                    "vulnerable_lines": [42],
                }
            ]
        )
    )

    output = audit.audit_results_json(results_path, dataset_path)

    assert output["output_dir"] == str(tmp_path)
    assert output["artifacts"] == {
        "json": str(tmp_path / "joern_fp_audit.json"),
        "csv": str(tmp_path / "joern_fp_audit.csv"),
        "md": str(tmp_path / "joern_fp_audit.md"),
    }
    with (tmp_path / "joern_fp_audit.csv").open(newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert rows[0]["label"] == "fp_by_location"
    assert "FP rows: 1" in (tmp_path / "joern_fp_audit.md").read_text()
