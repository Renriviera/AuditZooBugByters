"""Regression test: the k-loop must be *able* to move TP/FP/FN metrics.

This test pins the Phase-B1 redesign of ``label_findings``.  It replays
the same candidate set (as would be produced by a deterministic Semgrep
scan) against four scripted triage-verdict sequences -- one per
``k in {0, 1, 2, 3}`` -- and asserts that the GT-based counts are *not*
identical.  If a future refactor regresses back to the old scorer that
collapses TRUE_POSITIVE + UNCERTAIN and ignores the LLM unless it says
FALSE_POSITIVE, this test fails immediately.

The scripted verdict schedule deliberately mirrors the behaviours we
expect the real LLM to exhibit as k grows:

  * k=0: no LLM yet -> all UNCERTAIN (baseline equal to raw candidates)
  * k=1: LLM suppresses a wrong-line candidate as FALSE_POSITIVE -> tn
  * k=2: LLM endorses the correct candidate as TRUE_POSITIVE + another
         wrong-line candidate as TP (over-claim) -> fp_by_llm_overclaim
  * k=3: LLM suppresses a *right-line* candidate as FALSE_POSITIVE
         -> fn_by_llm rises, fn rises

We also assert that ``serialize_triage_verdicts`` emits aligned entries
for downstream ``scripts/analyze_triage.py`` consumption.
"""

from __future__ import annotations

from types import SimpleNamespace

from scripts.run_evaluation import (
    label_findings,
    serialize_triage_verdicts,
)
from auditzoo.agents.cwe78_study.schemas import (
    Finding,
    TriageResult,
    Verdict,
)


# ----------------------------------------------------------------------
# Fixtures
# ----------------------------------------------------------------------

def _cve_fixture() -> dict:
    # Two ground-truth lines on a single file.
    return {
        "cve_id": "CVE-TEST-0001",
        "vulnerable_file": "app/handlers/shell.py",
        "vulnerable_lines": [42, 80],
    }


def _findings_fixture() -> list[Finding]:
    # Deterministic candidate set reused for all k values.  Three
    # findings: (a) close to line 42 (within tolerance=5),
    # (b) close to line 80, and (c) at line 200 which is nowhere
    # near GT (so scoring will classify it by LLM verdict alone).
    return [
        Finding(
            file_path="app/handlers/shell.py",
            line_start=43, line_end=43,
            rule_id="cwe78.os-system-tainted",
            message="os.system with tainted arg",
            code_snippet="os.system(cmd)",
            arm="semgrep",
        ),
        Finding(
            file_path="app/handlers/shell.py",
            line_start=82, line_end=82,
            rule_id="cwe78.subprocess-shell-true",
            message="subprocess shell=True with tainted arg",
            code_snippet="subprocess.run(cmd, shell=True)",
            arm="semgrep",
        ),
        Finding(
            file_path="app/handlers/shell.py",
            line_start=200, line_end=200,
            rule_id="cwe78.os-system-tainted",
            message="os.system literal",
            code_snippet='os.system("ls")',
            arm="semgrep",
        ),
    ]


def _verdicts_for_k(k: int) -> list[TriageResult]:
    # See module docstring for the narrative; return 3 verdicts aligned
    # with the 3 findings above.
    if k == 0:
        return [
            TriageResult(Verdict.UNCERTAIN, 0.5, "baseline"),
            TriageResult(Verdict.UNCERTAIN, 0.5, "baseline"),
            TriageResult(Verdict.UNCERTAIN, 0.5, "baseline"),
        ]
    if k == 1:
        # LLM correctly suppresses the wrong-line literal-arg candidate.
        return [
            TriageResult(Verdict.UNCERTAIN, 0.5, "still ambiguous"),
            TriageResult(Verdict.UNCERTAIN, 0.5, "still ambiguous"),
            TriageResult(Verdict.FALSE_POSITIVE, 0.9, "literal arg, no taint"),
        ]
    if k == 2:
        # LLM commits to TP on the real bug AND over-claims on the literal one.
        return [
            TriageResult(Verdict.TRUE_POSITIVE, 0.8, "argv -> os.system"),
            TriageResult(Verdict.UNCERTAIN, 0.4, "need sink proof"),
            TriageResult(Verdict.TRUE_POSITIVE, 0.6, "looks bad"),  # overclaim
        ]
    if k == 3:
        # LLM mistakenly suppresses a GT-correct candidate.
        return [
            TriageResult(Verdict.FALSE_POSITIVE, 0.7, "assumed sanitised"),
            TriageResult(Verdict.TRUE_POSITIVE, 0.8, "shell=True + tainted"),
            TriageResult(Verdict.FALSE_POSITIVE, 0.9, "literal arg, no taint"),
        ]
    raise ValueError(f"unexpected k={k}")


def _score(k: int) -> dict:
    cve = _cve_fixture()
    findings = _findings_fixture()
    triage = _verdicts_for_k(k)
    return label_findings(findings, triage, cve, line_tolerance=5)


# ----------------------------------------------------------------------
# Tests
# ----------------------------------------------------------------------

class TestKMovesMetrics:
    def test_k0_baseline_matches_raw_candidates(self) -> None:
        r = _score(0)
        assert r["tp"] == 2, "Both in-tolerance findings should be TPs at k=0"
        assert r["fp"] == 1, "Line-200 finding is an fp_by_location at k=0"
        assert r["fn"] == 0
        assert r["fn_by_llm"] == 0
        assert r["labels"] == ["tp", "tp", "fp_by_location"]

    def test_k1_false_positive_suppression_yields_tn(self) -> None:
        r = _score(1)
        assert r["tp"] == 2
        assert r["fp"] == 0, (
            "k=1 must drop the line-200 FP by honouring the LLM's "
            "FALSE_POSITIVE verdict (previously this was fp_by_llm=1)"
        )
        assert r["fn"] == 0
        assert r["fn_by_llm"] == 0
        assert r["labels"].count("tn") == 1

    def test_k2_overclaim_is_counted_as_fp(self) -> None:
        r = _score(2)
        assert r["tp"] == 2
        assert r["fp"] == 1
        assert "fp_by_llm_overclaim" in r["labels"], (
            "TRUE_POSITIVE on a non-GT line must produce fp_by_llm_overclaim; "
            "otherwise the LLM is incentivised to approve everything"
        )

    def test_k3_llm_suppresses_true_bug_raises_fn_by_llm(self) -> None:
        r = _score(3)
        assert r["tp"] == 1, "One real bug suppressed, one still endorsed"
        assert r["fn"] == 1
        assert r["fn_by_llm"] == 1
        assert r["labels"].count("fn_by_llm") == 1

    def test_scores_are_not_identical_across_k(self) -> None:
        tp_fp_fn = [
            (_score(k)["tp"], _score(k)["fp"], _score(k)["fn"])
            for k in (0, 1, 2, 3)
        ]
        assert len(set(tp_fp_fn)) > 1, (
            f"TP/FP/FN must differ across k, got {tp_fp_fn}. "
            "This is the Phase-B1 regression guard."
        )

    def test_precision_improves_when_llm_kills_wrong_line_fps(self) -> None:
        p0 = _score(0)["precision"]
        p1 = _score(1)["precision"]
        assert p1 > p0, (
            "Suppressing fp_by_location via FALSE_POSITIVE verdict must "
            "raise precision; got p(k=0)={:.3f}, p(k=1)={:.3f}".format(p0, p1)
        )


class TestTriageVerdictSerialisation:
    def test_aligned_output_length_and_fields(self) -> None:
        findings = _findings_fixture()
        triage = _verdicts_for_k(2)
        out = serialize_triage_verdicts(findings, triage)
        assert len(out) == len(findings)
        for entry, f, t in zip(out, findings, triage):
            assert entry["file"] == f.file_path
            assert entry["line"] == f.line_start
            assert entry["rule_id"] == f.rule_id
            assert entry["verdict"] == t.verdict.value
            assert isinstance(entry["confidence"], float)
            assert isinstance(entry["reasoning"], str)
