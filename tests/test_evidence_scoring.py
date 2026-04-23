"""Scorer-level hallucination brake tests for ``label_findings``.

``label_findings`` must penalise any ``TRUE_POSITIVE`` whose ``source_expr``
is not a literal substring of the finding's snippet — regardless of GT
line match.  This is the second of the two "brakes" added to kill the
"TP on a line we never even told the LLM about" pattern observed in the
20260421_123649 sweep (193 TPs, 100% on ground-truth-no-match lines).

We also assert the back-compat behaviour: when ``source_expr`` is empty
(legacy ``TriageResult`` without the field, or scripted tests that
predate it) the scorer preserves the Phase-B1 matrix unchanged.
"""

from __future__ import annotations

from scripts.run_evaluation import label_findings, serialize_triage_verdicts
from auditzoo.agents.cwe78_study.schemas import (
    Finding, TriageResult, Verdict,
)


def _cve():
    return {
        "cve_id": "CVE-TEST-EVID",
        "vulnerable_file": "app/shell.py",
        "vulnerable_lines": [42],
    }


def _finding_on_gt_line() -> Finding:
    return Finding(
        file_path="app/shell.py",
        line_start=42, line_end=42,
        rule_id="cwe78.os-system",
        message="os.system with tainted arg",
        code_snippet="os.system(cmd)",
        surrounding_context=(
            "cmd = request.args['cmd']\n"
            "os.system(cmd)\n"
        ),
        arm="semgrep",
    )


def _finding_off_gt_line() -> Finding:
    return Finding(
        file_path="app/shell.py",
        line_start=200, line_end=200,
        rule_id="cwe78.os-system",
        message="os.system literal",
        code_snippet='os.system("ls -la")',
        surrounding_context='os.system("ls -la")\n',
        arm="semgrep",
    )


class TestSourceExprHallucinationBrake:
    def test_tp_on_gt_line_with_valid_source_is_counted(self) -> None:
        findings = [_finding_on_gt_line()]
        triage = [TriageResult(
            Verdict.TRUE_POSITIVE, 0.9,
            "valid flow",
            source_expr="request.args['cmd']",
            sink_expr="os.system(cmd)",
        )]
        r = label_findings(findings, triage, _cve())
        assert r["tp"] == 1
        assert r["fp"] == 0
        assert r["fp_by_hallucinated_source"] == 0
        assert r["labels"] == ["tp"]

    def test_tp_on_gt_line_with_hallucinated_source_is_fp(self) -> None:
        """GT-line TP whose source is NOT in snippet must not be credited."""
        findings = [_finding_on_gt_line()]
        triage = [TriageResult(
            Verdict.TRUE_POSITIVE, 0.95,
            "over-confident",
            source_expr="sys.argv[1]",  # not in snippet
            sink_expr="os.system(cmd)",
        )]
        r = label_findings(findings, triage, _cve())
        assert r["tp"] == 0
        assert r["fp"] == 1
        assert r["fp_by_hallucinated_source"] == 1
        assert r["labels"] == ["fp_by_hallucinated_source"]
        # and the GT line becomes an FN because the hallucinated-source
        # TP cannot count as a match
        assert r["fn"] == 1

    def test_tp_off_gt_line_with_hallucinated_source_counted_as_hallucination(self) -> None:
        """Off-GT + hallucinated source: hallucination dominates over overclaim."""
        findings = [_finding_off_gt_line()]
        triage = [TriageResult(
            Verdict.TRUE_POSITIVE, 0.9,
            "imagined flow",
            source_expr="request.args['q']",  # not in snippet
            sink_expr="os.system",
        )]
        r = label_findings(findings, triage, _cve())
        assert r["tp"] == 0
        assert r["fp"] == 1
        assert r["fp_by_hallucinated_source"] == 1
        assert "fp_by_hallucinated_source" in r["labels"]

    def test_empty_source_expr_is_backcompat_parity(self) -> None:
        """Legacy TriageResult without source_expr must behave as Phase-B1."""
        findings = [_finding_on_gt_line()]
        triage = [TriageResult(
            Verdict.TRUE_POSITIVE, 0.9, "legacy entry"  # no source_expr/sink_expr
        )]
        r = label_findings(findings, triage, _cve())
        assert r["tp"] == 1
        assert r["fp_by_hallucinated_source"] == 0


class TestEvidenceSerialisation:
    def test_serialize_emits_evidence_audit_columns(self) -> None:
        findings = [_finding_on_gt_line(), _finding_off_gt_line()]
        triage = [
            TriageResult(
                Verdict.TRUE_POSITIVE, 0.9, "ok",
                source_expr="request.args['cmd']",
                sink_expr="os.system(cmd)",
            ),
            TriageResult(
                Verdict.TRUE_POSITIVE, 0.9, "bad",
                source_expr="sys.argv[1]",  # not in snippet
                sink_expr="os.system",
                downgrade_reason="",  # didn't get downgraded in this fake
            ),
        ]
        out = serialize_triage_verdicts(findings, triage)
        assert len(out) == 2
        for key in ("source_expr", "sink_expr",
                    "source_in_snippet", "sink_in_snippet",
                    "downgrade_reason"):
            assert key in out[0]
            assert key in out[1]
        assert out[0]["source_in_snippet"] is True
        assert out[1]["source_in_snippet"] is False

    def test_serialize_empty_expr_treated_as_present(self) -> None:
        """Back-compat: empty source_expr/sink_expr report True for parity."""
        findings = [_finding_on_gt_line()]
        triage = [TriageResult(Verdict.UNCERTAIN, 0.5, "legacy")]  # no evidence
        out = serialize_triage_verdicts(findings, triage)
        assert out[0]["source_in_snippet"] is True
        assert out[0]["sink_in_snippet"] is True
        assert out[0]["source_expr"] == ""
        assert out[0]["sink_expr"] == ""
