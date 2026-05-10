"""Tests for splitEvaluations.summarize_sweep_results."""

from __future__ import annotations

from splitEvaluations.summarize_sweep_results import summarize


def test_summarize_two_cves_semgrep_arms() -> None:
    results = [
        {
            "cve_id": "CVE-1",
            "arms": {
                "semgrep_0": {
                    "tp": 1,
                    "fp": 1,
                    "fn": 0,
                    "fn_by_llm": 0,
                    "fp_by_hallucinated_source": 0,
                    "metrics": {
                        "llm_usage": {
                            "prompt_tokens": 10,
                            "completion_tokens": 2,
                            "total_tokens": 12,
                            "call_count": 1,
                        }
                    },
                },
                "semgrep_0_patched": {
                    "tp": 0,
                    "fp": 0,
                    "fn": 0,
                    "metrics": {"llm_usage": {}},
                },
            },
        },
        {
            "cve_id": "CVE-2",
            "arms": {
                "semgrep_0": {
                    "tp": 0,
                    "fp": 0,
                    "fn": 1,
                    "fn_by_llm": 1,
                    "fp_by_hallucinated_source": 0,
                    "metrics": {
                        "llm_usage": {
                            "prompt_tokens": 5,
                            "completion_tokens": 1,
                            "total_tokens": 6,
                            "call_count": 1,
                        }
                    },
                },
            },
        },
    ]
    s = summarize(results, include_patched=False)
    ac = s["all_arms_combined"]
    assert ac["tp"] == 1
    assert ac["fp"] == 1
    assert ac["fn"] == 1
    assert ac["fn_by_llm"] == 1
    assert ac["llm_usage"]["total_tokens"] == 18
    assert ac["micro_precision"] == 0.5
    assert ac["micro_recall"] == 0.5
