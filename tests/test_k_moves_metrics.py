"""Regression test: the k-loop must be *able* to move TP/FP/FN metrics.

This test pins the Phase-B2 redesign of ``label_findings`` (UNCERTAIN
moved into a dedicated non-scoring bucket).  It replays the same
candidate set (as would be produced by a deterministic Semgrep scan)
against four scripted triage-verdict sequences -- one per
``k in {0, 1, 2, 3}`` -- and asserts that the GT-based counts are *not*
identical and that UNCERTAIN no longer feeds into TP/FP.

Phase-B2 scoring matrix (reflected in the assertions below)::

    FALSE_POSITIVE on no-match  -> tn               (suppressed)
    FALSE_POSITIVE on match     -> fn_by_llm        (LLM killed a real bug)
    TRUE_POSITIVE  on match     -> tp               (committed positive)
    TRUE_POSITIVE  on no-match  -> fp_by_llm_overclaim
    UNCERTAIN      on match     -> uncertain_on_gt  (not credited; FN)
    UNCERTAIN      on no-match  -> uncertain_off_gt (not penalised as FP)

The scripted verdict schedule deliberately mirrors the behaviours we
expect the real LLM to exhibit as k grows:

  * k=0: no LLM commitment yet -> all UNCERTAIN (no positives credited;
         both GT lines remain FN; the off-GT candidate is parked in
         ``uncertain_off_gt``)
  * k=1: LLM suppresses the wrong-line literal-arg candidate as
         FALSE_POSITIVE -> tn (still 0 TP, GT lines still FN)
  * k=2: LLM commits to TRUE_POSITIVE on one real bug and overclaims on
         the off-GT literal -> tp=1, fp_by_llm_overclaim=1
  * k=3: LLM suppresses a *right-line* candidate as FALSE_POSITIVE while
         endorsing the other -> fn_by_llm rises, tp=1

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
    def test_k0_all_uncertain_does_not_credit_any_positive(self) -> None:
        """k=0 baseline: pure UNCERTAIN must not produce TP or FP.

        Replaces the Phase-B1 ``test_k0_baseline_matches_raw_candidates``
        guard.  Under Phase-B2, UNCERTAIN is observable through the
        ``uncertain_*`` keys but never feeds into TP/FP, so an
        unconditioned k=0 step has TP=0, FP=0, and both GT lines remain
        FN until the LLM commits.
        """
        r = _score(0)
        assert r["tp"] == 0
        assert r["fp"] == 0
        assert r["fn"] == 2, "Both GT lines remain FN until the LLM commits"
        assert r["fn_by_llm"] == 0
        assert r["uncertain_total"] == 3
        assert r["uncertain_on_gt"] == 2
        assert r["uncertain_off_gt"] == 1
        assert r["labels"] == [
            "uncertain_on_gt",
            "uncertain_on_gt",
            "uncertain_off_gt",
        ]

    def test_k1_false_positive_suppression_yields_tn(self) -> None:
        """k=1 still has no committed positives; UNCERTAIN-on-GT stays FN.

        The wrong-line literal-arg finding is FALSE_POSITIVE so it
        becomes a ``tn`` (suppressed) instead of an
        ``uncertain_off_gt``.  TP/FP stay at zero because no
        TRUE_POSITIVE verdicts are issued yet.
        """
        r = _score(1)
        assert r["tp"] == 0
        assert r["fp"] == 0
        assert r["fn"] == 2, "Both GT lines still uncommitted -> FN"
        assert r["fn_by_llm"] == 0
        assert r["labels"].count("tn") == 1
        assert r["labels"].count("uncertain_on_gt") == 2
        assert "uncertain_off_gt" not in r["labels"]

    def test_k2_overclaim_is_counted_as_fp(self) -> None:
        r = _score(2)
        # Verdicts at k=2: TP on real bug @ line 43, UNCERTAIN @ line 82,
        # TP-overclaim @ line 200.  Only the first is a committed match.
        assert r["tp"] == 1
        assert r["fp"] == 1
        assert "fp_by_llm_overclaim" in r["labels"], (
            "TRUE_POSITIVE on a non-GT line must produce fp_by_llm_overclaim; "
            "otherwise the LLM is incentivised to approve everything"
        )
        assert r["uncertain_on_gt"] == 1

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
            "This is the Phase-B1/B2 regression guard."
        )

    def test_precision_improves_when_llm_commits_to_true_positives(self) -> None:
        """Phase-B2 precision improvement: k=0 has no committed positives,
        so precision is 0/0 = 0.0; once the LLM commits at k=2, precision
        is non-zero (1 TP / 2 committed).  This replaces the legacy
        ``test_precision_improves_when_llm_kills_wrong_line_fps`` whose
        premise (UNCERTAIN counted as TP/FP) no longer applies.
        """
        p0 = _score(0)["precision"]
        p2 = _score(2)["precision"]
        assert p0 == 0.0
        assert p2 > 0.0
        assert p2 == 0.5  # 1 TP / (1 TP + 1 fp_by_llm_overclaim)


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
