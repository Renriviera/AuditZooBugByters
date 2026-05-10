"""Tests for the cluster-/hunk-relaxed scoring lane (Fix #2 + Fix #3).

Covers:
  * Unified-diff hunk parsing (``_load_changed_hunks``).
  * GT-line clustering (``_cluster_lines``).
  * Per-iteration relaxed scoring (``_relaxed_score_for_iter``).
  * End-to-end ``build_audit`` enrichment of ``IterationAudit`` and the
    aggregated ``relaxed_totals_by_k`` / ``uncertain_relaxed_totals_by_k``
    summary panes.
  * Backwards compatibility: pre-existing audits still work when no
    diff directory is present and no relaxed counters are written.

These are post-processing tests; they don't run Joern or any LLM.
"""

from __future__ import annotations

import json
from pathlib import Path

from splitEvaluations.audit_joern_results import (
    DEFAULT_GT_CLUSTER_GAP,
    _cluster_lines,
    _load_changed_hunks,
    _relaxed_score_for_iter,
    audit_results_json,
    build_audit,
)


# ---------------------------------------------------------------- helpers --
def _triage_row(
    *,
    file: str,
    line: int,
    verdict: str,
    source_in_snippet: bool = True,
) -> dict:
    return {
        "file": file,
        "line": line,
        "rule_id": "joern.cwe78",
        "sink_api": "subprocess.Popen",
        "verdict": verdict,
        "confidence": 0.85,
        "reasoning": "test",
        "suggestion": "",
        "source_expr": "request.args['cmd']",
        "sink_expr": "Popen(cmd, shell=True)",
        "source_in_snippet": source_in_snippet,
        "sink_in_snippet": True,
        "downgrade_reason": "",
    }


def _aligned(label: str, triage: dict, *, k: int = 0) -> dict:
    return {
        "cve_id": "CVE-TEST",
        "arm_key": f"joern_{k}",
        "k": k,
        "patched": False,
        "finding_index": 0,
        "label": label,
        "triage": triage,
        "matched_gt_line": None,
    }


# ---------------------------------------------------------------- diffs ----
SIMPLE_DIFF = (
    "diff --git a/app/shell.py b/app/shell.py\n"
    "index abc..def 100644\n"
    "--- a/app/shell.py\n"
    "+++ b/app/shell.py\n"
    "@@ -10,6 +10,8 @@ def run(cmd):\n"
    " x = 1\n"
    " y = 2\n"
    "-os.system(cmd)\n"
    "+import shlex\n"
    "+subprocess.run(shlex.split(cmd))\n"
    " z = 3\n"
    "@@ -42,3 +44,4 @@\n"
    " a = 4\n"
    "-os.system(other)\n"
    "+subprocess.run(['echo', other])\n"
    " b = 5\n"
)


def test_load_changed_hunks_parses_old_side_ranges(tmp_path: Path) -> None:
    diff_path = tmp_path / "CVE-TEST.diff"
    diff_path.write_text(SIMPLE_DIFF)

    hunks = _load_changed_hunks(diff_path)

    assert hunks == {
        "app/shell.py": [(10, 15), (42, 44)],
    }


def test_load_changed_hunks_handles_missing_file(tmp_path: Path) -> None:
    assert _load_changed_hunks(tmp_path / "missing.diff") == {}


def test_load_changed_hunks_skips_pure_add_hunks(tmp_path: Path) -> None:
    """``@@ -0,0 +N,M @@`` adds-only hunks have no OLD-side line range."""
    diff = (
        "--- a/new_file.py\n"
        "+++ b/new_file.py\n"
        "@@ -0,0 +1,3 @@\n"
        "+import os\n"
        "+os.system('rm -rf /')\n"
        "+pass\n"
    )
    diff_path = tmp_path / "addonly.diff"
    diff_path.write_text(diff)

    assert _load_changed_hunks(diff_path) == {}


def test_load_changed_hunks_handles_count_omitted(tmp_path: Path) -> None:
    """``@@ -42 +50 @@`` (no count) means count=1."""
    diff = "--- a/x.py\n" "+++ b/x.py\n" "@@ -42 +50 @@\n" "-old\n" "+new\n"
    diff_path = tmp_path / "x.diff"
    diff_path.write_text(diff)

    assert _load_changed_hunks(diff_path) == {"x.py": [(42, 42)]}


def test_load_changed_hunks_skips_dev_null(tmp_path: Path) -> None:
    """Newly added files have ``--- /dev/null`` and no OLD ranges."""
    diff = "--- /dev/null\n" "+++ b/new.py\n" "@@ -0,0 +1,2 @@\n" "+x = 1\n" "+y = 2\n"
    diff_path = tmp_path / "new.diff"
    diff_path.write_text(diff)

    assert _load_changed_hunks(diff_path) == {}


# ---------------------------------------------------------------- cluster --
def test_cluster_lines_groups_by_gap() -> None:
    assert _cluster_lines([5, 6, 7, 50, 51], gap=8) == [(5, 7), (50, 51)]


def test_cluster_lines_chains_via_8_step_gap() -> None:
    """A run of lines spaced exactly 8 apart still forms one cluster."""
    assert _cluster_lines([5, 13, 21], gap=8) == [(5, 21)]


def test_cluster_lines_gap_too_large_splits_singletons() -> None:
    assert _cluster_lines([5, 14, 23], gap=8) == [(5, 5), (14, 14), (23, 23)]


def test_cluster_lines_handles_empty_and_invalid() -> None:
    assert _cluster_lines([], gap=8) == []
    assert _cluster_lines([0, -3, "x"], gap=8) == []  # all sanitized away
    assert _cluster_lines([10], gap=8) == [(10, 10)]


def test_cluster_lines_default_gap_matches_constant() -> None:
    """Sanity: the default constant must match the helper's default."""
    assert _cluster_lines([1, DEFAULT_GT_CLUSTER_GAP + 1])[0] == (
        1,
        DEFAULT_GT_CLUSTER_GAP + 1,
    )


# -------------------------------------------------- relaxed scoring core --
def _gt() -> dict:
    return {
        "vulnerable_file": "app/shell.py",
        "vulnerable_lines": [42, 43, 44, 80, 120],
    }


def test_relaxed_score_credits_committed_tp_in_cluster() -> None:
    """One LLM TP near a clustered GT line credits that whole cluster."""
    rows = [
        _aligned(
            "tp",
            _triage_row(file="app/shell.py", line=44, verdict="true_positive"),
        ),
    ]

    out = _relaxed_score_for_iter(
        rows, _gt(), {}, line_tolerance=5, cluster_gap=DEFAULT_GT_CLUSTER_GAP
    )

    # Three clusters: (42-44), (80,80), (120,120). One covered.
    assert out["n_gt_clusters"] == 3
    assert out["tp_relaxed"] == 1
    assert out["fn_relaxed"] == 2
    assert out["fp_relaxed"] == 0


def test_relaxed_score_credits_hunk_only_tp() -> None:
    """An LLM TP that lands inside a changed hunk but outside any GT cluster
    counts as TP_relaxed, NOT FP."""
    rows = [
        _aligned(
            "fp_by_llm_overclaim",
            _triage_row(file="app/shell.py", line=12, verdict="true_positive"),
        ),
    ]
    hunks = {"app/shell.py": [(10, 15)]}

    out = _relaxed_score_for_iter(
        rows, _gt(), hunks, line_tolerance=5, cluster_gap=DEFAULT_GT_CLUSTER_GAP
    )

    assert out["tp_relaxed"] == 1
    assert out["fp_relaxed"] == 0
    # No GT cluster covered, all 3 still missing.
    assert out["fn_relaxed"] == 3


def test_relaxed_score_counts_off_target_tp_as_fp() -> None:
    rows = [
        _aligned(
            "fp_by_llm_overclaim",
            _triage_row(file="app/shell.py", line=999, verdict="true_positive"),
        ),
    ]

    out = _relaxed_score_for_iter(
        rows, _gt(), {}, line_tolerance=5, cluster_gap=DEFAULT_GT_CLUSTER_GAP
    )

    assert out["tp_relaxed"] == 0
    assert out["fp_relaxed"] == 1
    assert out["fn_relaxed"] == 3


def test_relaxed_score_keeps_hallucinated_source_as_fp() -> None:
    """Hallucinated-source rows are ALWAYS FP, even if they land on a GT line."""
    rows = [
        _aligned(
            "fp_by_hallucinated_source",
            _triage_row(
                file="app/shell.py",
                line=42,
                verdict="true_positive",
                source_in_snippet=False,
            ),
        ),
    ]

    out = _relaxed_score_for_iter(
        rows, _gt(), {}, line_tolerance=5, cluster_gap=DEFAULT_GT_CLUSTER_GAP
    )

    # Cluster (42,44) is NOT credited: hallucination brake stays on.
    assert out["tp_relaxed"] == 0
    assert out["fp_relaxed"] == 1
    assert out["fn_relaxed"] == 3


def test_relaxed_score_uncertain_credits_cluster_only_for_uncertain_lane() -> None:
    """UNCERTAIN-on-GT credits the cluster ONLY in the uncertain-relaxed lane."""
    rows = [
        _aligned(
            "uncertain_on_gt",
            _triage_row(file="app/shell.py", line=80, verdict="uncertain"),
        ),
    ]

    out = _relaxed_score_for_iter(
        rows, _gt(), {}, line_tolerance=5, cluster_gap=DEFAULT_GT_CLUSTER_GAP
    )

    # Strict relaxed lane: still 0 TP, all 3 FN, no FP.
    assert out["tp_relaxed"] == 0
    assert out["fp_relaxed"] == 0
    assert out["fn_relaxed"] == 3
    # Uncertain lane: cluster (80,80) gains a TP credit, so FN drops by 1.
    assert out["tp_uncertain_relaxed"] == 1
    assert out["fn_uncertain_relaxed"] == 2
    assert out["fp_uncertain_relaxed"] == 0
    assert out["n_uncertain_credits"] == 1


def test_relaxed_score_uncertain_does_not_double_credit() -> None:
    """If a cluster is already covered by a committed TP, the UNCERTAIN-on-GT
    row on the same cluster does NOT add an extra credit."""
    rows = [
        _aligned(
            "tp",
            _triage_row(file="app/shell.py", line=42, verdict="true_positive"),
        ),
        _aligned(
            "uncertain_on_gt",
            _triage_row(file="app/shell.py", line=43, verdict="uncertain"),
        ),
    ]

    out = _relaxed_score_for_iter(
        rows, _gt(), {}, line_tolerance=5, cluster_gap=DEFAULT_GT_CLUSTER_GAP
    )

    assert out["tp_relaxed"] == 1
    assert out["tp_uncertain_relaxed"] == 1  # still 1, not 2
    assert out["n_uncertain_credits"] == 0


def test_relaxed_score_handles_no_gt_lines() -> None:
    """Empty ``vulnerable_lines`` ⇒ no clusters, no FN, off-target TPs are FP."""
    rows = [
        _aligned(
            "fp_by_llm_overclaim",
            _triage_row(file="app/shell.py", line=10, verdict="true_positive"),
        ),
    ]
    gt = {"vulnerable_file": "app/shell.py", "vulnerable_lines": []}

    out = _relaxed_score_for_iter(
        rows, gt, {}, line_tolerance=5, cluster_gap=DEFAULT_GT_CLUSTER_GAP
    )

    assert out["n_gt_clusters"] == 0
    assert out["tp_relaxed"] == 0
    assert out["fp_relaxed"] == 1
    assert out["fn_relaxed"] == 0


# ----------------------------------------------------- end-to-end audit ----
def _e2e_dataset() -> list[dict]:
    return [
        {
            "cve_id": "CVE-RELAX-1",
            "vulnerable_file": "app/shell.py",
            "vulnerable_lines": [42, 43, 80, 120],
            "patch_diff_path": "diffs/CVE-RELAX-1.diff",
        }
    ]


def _e2e_results() -> list[dict]:
    return [
        {
            "cve_id": "CVE-RELAX-1",
            "repo_url": "https://example.invalid/repo",
            "loc": 500,
            "arms": {
                "joern_0": {
                    "tp": 1,
                    "fp": 1,
                    "fn": 2,
                    "fn_by_llm": 0,
                    "fp_by_hallucinated_source": 0,
                    "labels": ["tp", "fp_by_llm_overclaim", "uncertain_on_gt"],
                    "n_candidates": 3,
                    "metrics": {"findings_hash": "h0"},
                    "triage_verdicts": [
                        _triage_row(
                            file="app/shell.py",
                            line=42,
                            verdict="true_positive",
                        ),
                        _triage_row(
                            file="app/shell.py",
                            line=12,  # inside the (10-15) hunk
                            verdict="true_positive",
                        ),
                        _triage_row(
                            file="app/shell.py",
                            line=80,
                            verdict="uncertain",
                        ),
                    ],
                    "refinement_actions": [],
                }
            },
        }
    ]


def test_build_audit_emits_relaxed_panes_when_diffs_present(tmp_path: Path) -> None:
    diffs_dir = tmp_path / "diffs"
    diffs_dir.mkdir()
    (diffs_dir / "CVE-RELAX-1.diff").write_text(SIMPLE_DIFF)

    audit = build_audit(
        _e2e_results(),
        _e2e_dataset(),
        line_tolerance=5,
        diffs_dir=diffs_dir,
        cluster_gap=DEFAULT_GT_CLUSTER_GAP,
    )

    iter_row = next(
        row for row in audit["iteration_summary"] if row["arm_key"] == "joern_0"
    )
    # Three GT clusters: (42,43), (80,80), (120,120).
    assert iter_row["n_gt_clusters"] == 3
    # Committed TPs: line=42 covers cluster (42,43); line=12 hits hunk
    # (10-15) so it's a hunk-only TP. Both contribute to TP_relaxed.
    assert iter_row["tp_relaxed"] == 2
    assert iter_row["fp_relaxed"] == 0
    # Cluster (80,80) and (120,120) still uncovered by committed TP.
    assert iter_row["fn_relaxed"] == 2
    # UNCERTAIN-on-GT row at line=80 credits cluster (80,80).
    assert iter_row["n_uncertain_credits"] == 1
    assert iter_row["tp_uncertain_relaxed"] == 3
    assert iter_row["fn_uncertain_relaxed"] == 1

    relaxed_pane = audit["summary"]["relaxed_totals_by_k"]["0"]
    assert relaxed_pane == {
        "tp": 2,
        "fp": 0,
        "fn": 2,
        "n_gt_clusters": 3,
    }
    uncertain_pane = audit["summary"]["uncertain_relaxed_totals_by_k"]["0"]
    assert uncertain_pane == {
        "tp": 3,
        "fp": 0,
        "fn": 1,
        "n_credits": 1,
    }


def test_build_audit_omits_relaxed_lane_without_gt(tmp_path: Path) -> None:
    """CVE without ``vulnerable_lines`` should leave relaxed fields empty
    (no division-by-zero recall, no spurious counter)."""
    dataset = [
        {
            "cve_id": "CVE-EMPTY",
            "vulnerable_file": "app/shell.py",
            "vulnerable_lines": [],
        }
    ]
    results = [
        {
            "cve_id": "CVE-EMPTY",
            "arms": {
                "joern_0": {
                    "tp": 0,
                    "fp": 0,
                    "fn": 0,
                    "labels": [],
                    "metrics": {"findings_hash": "h"},
                    "triage_verdicts": [],
                    "refinement_actions": [],
                }
            },
        }
    ]

    audit = build_audit(results, dataset, line_tolerance=5)
    iter_row = audit["iteration_summary"][0]
    assert iter_row["tp_relaxed"] == ""
    assert iter_row["fp_relaxed"] == ""
    assert iter_row["fn_relaxed"] == ""
    assert iter_row["n_gt_clusters"] == ""


def test_audit_results_json_writes_relaxed_panes(tmp_path: Path) -> None:
    """End-to-end: audit_results_json picks up <dataset_dir>/diffs by default."""
    bench_dir = tmp_path / "bench"
    bench_dir.mkdir()
    diffs_dir = bench_dir / "diffs"
    diffs_dir.mkdir()
    (diffs_dir / "CVE-RELAX-1.diff").write_text(SIMPLE_DIFF)
    dataset_path = bench_dir / "metadata.json"
    dataset_path.write_text(json.dumps(_e2e_dataset()))
    results_path = tmp_path / "results.json"
    results_path.write_text(json.dumps(_e2e_results()))
    output_dir = tmp_path / "audit"

    audit = audit_results_json(
        results_path,
        dataset_path,
        output_dir,
        line_tolerance=5,
    )

    assert audit["metadata"]["gt_cluster_gap"] == DEFAULT_GT_CLUSTER_GAP
    assert audit["metadata"]["diffs_dir"].endswith("diffs")
    relaxed_pane = audit["summary"]["relaxed_totals_by_k"]["0"]
    assert relaxed_pane["tp"] == 2
    assert relaxed_pane["fn"] == 2
