"""Tests for the Joern strict-TP audit sidecar."""

from __future__ import annotations

from splitEvaluations.audit_joern_strict_tp import build_strict_tp_rows, build_summary


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


def test_strict_tp_audit_buckets_llm_true_positive_and_uncertain() -> None:
    metadata = {
        "CVE-DEMO": {
            "vulnerable_file": "pkg/vuln.py",
            "vulnerable_lines": [42],
        }
    }
    results = [
        _result_with_candidates(
            [
                {
                    "file": "pkg/vuln.py",
                    "line": 42,
                    "verdict": "true_positive",
                    "source_in_snippet": True,
                    "originExternalSource": True,
                },
                {
                    "file": "pkg/vuln.py",
                    "line": 43,
                    "verdict": "uncertain",
                    "source_in_snippet": False,
                    "originExternalSource": False,
                },
            ],
            ["tp", "tp"],
        )
    ]

    rows = build_strict_tp_rows(results, metadata, line_tolerance=5)
    summary = build_summary(rows)

    assert len(rows) == 2
    assert summary["tp_strict_by_llm_tp"] == 1
    assert summary["tp_strict_by_llm_uncertain"] == 1
    assert summary["tp_strict_by_llm_other"] == 0


def test_strict_tp_audit_excludes_overclaim_even_when_llm_says_tp() -> None:
    metadata = {
        "CVE-DEMO": {
            "vulnerable_file": "pkg/vuln.py",
            "vulnerable_lines": [42],
        }
    }
    results = [
        _result_with_candidates(
            [
                {
                    "file": "pkg/other.py",
                    "line": 99,
                    "verdict": "true_positive",
                    "source_in_snippet": True,
                }
            ],
            ["fp_by_llm_overclaim"],
        )
    ]

    rows = build_strict_tp_rows(results, metadata, line_tolerance=5)

    assert rows == []


def test_strict_tp_audit_excludes_report_candidate_promotions() -> None:
    metadata = {
        "CVE-DEMO": {
            "vulnerable_file": "pkg/vuln.py",
            "vulnerable_lines": [42],
        }
    }
    results = [
        _result_with_candidates(
            [
                {
                    "file": "pkg/wrapper.py",
                    "line": 12,
                    "verdict": "true_positive",
                    "reportCandidateLocations": [{"file": "pkg/vuln.py", "line": 42}],
                }
            ],
            ["tp_via_report_candidate"],
        )
    ]

    rows = build_strict_tp_rows(results, metadata, line_tolerance=5)

    assert rows == []


def test_strict_tp_audit_uses_serialized_strict_match_fields() -> None:
    metadata = {
        "CVE-DEMO": {
            "vulnerable_file": "pkg/vuln.py",
            "vulnerable_lines": [42],
        }
    }
    results = [
        _result_with_candidates(
            [
                {
                    "file": "generated/location.py",
                    "line": 1,
                    "verdict": "uncertain",
                    "is_strict_match": True,
                    "matched_gt_line": 42,
                }
            ],
            ["tp"],
        )
    ]

    rows = build_strict_tp_rows(results, metadata, line_tolerance=5)

    assert len(rows) == 1
    assert rows[0]["gt_line"] == 42
