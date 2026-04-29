"""Tests for Joern FN audit classification buckets."""

from __future__ import annotations

from splitEvaluations.audit_joern_fn import build_fn_rows, build_summary


def _metadata() -> dict[str, dict[str, object]]:
    return {
        "CVE-TIMEOUT": {
            "vulnerable_file": "app/shell.py",
            "vulnerable_lines": [42],
            "repo_url": "https://example.test/repo",
        },
        "CVE-ERROR": {
            "vulnerable_file": "app/shell.py",
            "vulnerable_lines": [42],
        },
        "CVE-ZERO": {
            "vulnerable_file": "app/shell.py",
            "vulnerable_lines": [42],
        },
        "CVE-PROBE": {
            "vulnerable_file": "app/shell.py",
            "vulnerable_lines": [42],
        },
    }


def test_skipped_timeout_error_and_real_zero_candidate_are_distinct() -> None:
    rows = build_fn_rows(
        [
            {
                "cve_id": "CVE-TIMEOUT",
                "skipped": "timeout",
                "timeout_meta": {
                    "elapsed_s": 900.0,
                    "kill_signal": "SIGKILL",
                    "timeout_scope": "process_group",
                },
            },
            {
                "cve_id": "CVE-ERROR",
                "skipped": "error",
                "error": "boom",
                "error_type": "RuntimeError",
            },
            {
                "cve_id": "CVE-ZERO",
                "arms": {
                    "joern_0": {
                        "metrics": {"joern_raw_findings": 0},
                        "triage_verdicts": [],
                    }
                },
            },
        ],
        _metadata(),
    )

    categories = {row["cve_id"]: row["fn_category"] for row in rows}
    assert categories == {
        "CVE-TIMEOUT": "cpg_timeout",
        "CVE-ERROR": "cpg_error",
        "CVE-ZERO": "zero_candidate",
    }

    summary = build_summary(rows)
    assert summary["category_counts"]["cpg_timeout"] == 1
    assert summary["category_counts"]["cpg_error"] == 1
    assert summary["category_counts"]["zero_candidate"] == 1
    assert "extend_per_cve_timeout_or_split_cpg_build" in summary["recommendations"]


def test_zero_candidate_is_refined_by_coverage_probe() -> None:
    rows = build_fn_rows(
        [
            {
                "cve_id": "CVE-PROBE",
                "arms": {
                    "joern_0": {
                        "metrics": {
                            "joern_raw_findings": 0,
                            "joern_coverage_probe": {
                                "gt_file_seen": True,
                                "method_count": 3,
                                "gt_sink_count": 0,
                                "external_source_count": 1,
                            },
                        },
                        "triage_verdicts": [],
                    }
                },
            }
        ],
        _metadata(),
    )

    assert rows[0]["fn_category"] == "coverage_no_sink"
    summary = build_summary(rows)
    assert summary["cves_without_gt_sink"] == ["CVE-PROBE"]
