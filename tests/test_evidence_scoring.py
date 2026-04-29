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

from auditzoo.agents.cwe78_study.schemas import (
    Finding,
    TriageResult,
    Verdict,
)
from scripts.run_evaluation import label_findings, serialize_triage_verdicts


def _cve():
    return {
        "cve_id": "CVE-TEST-EVID",
        "vulnerable_file": "app/shell.py",
        "vulnerable_lines": [42],
    }


def _finding_on_gt_line() -> Finding:
    return Finding(
        file_path="app/shell.py",
        line_start=42,
        line_end=42,
        rule_id="cwe78.os-system",
        message="os.system with tainted arg",
        code_snippet="os.system(cmd)",
        surrounding_context=("cmd = request.args['cmd']\n" "os.system(cmd)\n"),
        arm="semgrep",
    )


def _finding_on_gt_line_with_sink(sink_api: str) -> Finding:
    finding = _finding_on_gt_line()
    finding.sink_api = sink_api
    return finding


def _finding_off_gt_line() -> Finding:
    return Finding(
        file_path="app/shell.py",
        line_start=200,
        line_end=200,
        rule_id="cwe78.os-system",
        message="os.system literal",
        code_snippet='os.system("ls -la")',
        surrounding_context='os.system("ls -la")\n',
        arm="semgrep",
    )


def _joern_helper_finding_with_gt_flow_path() -> Finding:
    return Finding(
        file_path="app/helpers.py",
        line_start=10,
        line_end=10,
        rule_id="joern-taint-reachability",
        message="flow",
        code_snippet="subprocess.run(cmd, shell=True)",
        surrounding_context="subprocess.run(cmd, shell=True)",
        arm="joern",
        metadata={
            "sourceFile": "app/shell.py",
            "sourceLine": "42",
            "sourceCode": "request.args['cmd']",
            "sinkFile": "app/helpers.py",
            "sinkLine": "10",
            "sinkCode": "subprocess.run(cmd, shell=True)",
            "sourceKind": "parameter",
            "sinkKind": "wrapper",
            "wrapperName": "run_user_command",
            "wrappedSinkName": "run",
            "wrappedSinkCode": "subprocess.run(cmd, shell=True)",
            "shell_true": True,
            "flowPath": [
                {
                    "file": "app/shell.py",
                    "line": "42",
                    "code": "run_user_command(request.args['cmd'])",
                    "nodeType": "Call",
                },
                {
                    "file": "app/helpers.py",
                    "line": "10",
                    "code": "subprocess.run(cmd, shell=True)",
                    "nodeType": "Call",
                },
            ],
        },
    )


def _joern_finding_with_gt_report_candidate(
    *, origin_external: bool, caller_external: bool = False
) -> Finding:
    return Finding(
        file_path="app/helpers.py",
        line_start=10,
        line_end=10,
        rule_id="joern-taint-reachability",
        message="flow",
        code_snippet="subprocess.run(cmd, shell=True)",
        surrounding_context="subprocess.run(cmd, shell=True)",
        arm="joern",
        metadata={
            "sourceFile": "app/input.py",
            "sourceLine": "12",
            "sourceCode": "cmd",
            "sinkFile": "app/helpers.py",
            "sinkLine": "10",
            "sinkCode": "subprocess.run(cmd, shell=True)",
            "sourceKind": "parameter",
            "originExternalSource": origin_external,
            "reportCandidateLocations": [
                {
                    "file": "app/shell.py",
                    "line": 42,
                    "reason": "caller_consumer_callsite",
                    "caller_external": caller_external,
                }
            ],
        },
    )


def _joern_same_package_finding(*, origin_external: bool) -> Finding:
    return Finding(
        file_path="app/adjacent.py",
        line_start=88,
        line_end=88,
        rule_id="joern-taint-reachability",
        message="flow",
        code_snippet="subprocess.run(cmd, shell=True)",
        surrounding_context="subprocess.run(cmd, shell=True)",
        arm="joern",
        metadata={
            "sourceCode": "cmd",
            "sinkCode": "subprocess.run(cmd, shell=True)",
            "sourceKind": "parameter",
            "originExternalSource": origin_external,
            "shell_true": True,
        },
    )


class TestSourceExprHallucinationBrake:
    def test_tp_on_gt_line_with_valid_source_is_counted(self) -> None:
        findings = [_finding_on_gt_line()]
        triage = [
            TriageResult(
                Verdict.TRUE_POSITIVE,
                0.9,
                "valid flow",
                source_expr="request.args['cmd']",
                sink_expr="os.system(cmd)",
            )
        ]
        r = label_findings(findings, triage, _cve())
        assert r["tp"] == 1
        assert r["fp"] == 0
        assert r["fp_by_hallucinated_source"] == 0
        assert r["tp_strict_by_llm_tp"] == 1
        assert r["tp_strict_by_llm_uncertain"] == 0
        assert r["labels"] == ["tp"]

    def test_tp_on_gt_line_with_hallucinated_source_is_fp(self) -> None:
        """GT-line TP whose source is NOT in snippet must not be credited."""
        findings = [_finding_on_gt_line()]
        triage = [
            TriageResult(
                Verdict.TRUE_POSITIVE,
                0.95,
                "over-confident",
                source_expr="sys.argv[1]",  # not in snippet
                sink_expr="os.system(cmd)",
            )
        ]
        r = label_findings(findings, triage, _cve())
        assert r["tp"] == 0
        assert r["fp"] == 1
        assert r["fp_by_hallucinated_source"] == 1
        assert r["labels"] == ["fp_by_hallucinated_source"]
        # and the GT line becomes an FN because the hallucinated-source
        # TP cannot count as a match
        assert r["fn"] == 1

    def test_tp_off_gt_line_with_hallucinated_source_counted_as_hallucination(
        self,
    ) -> None:
        """Off-GT + hallucinated source: hallucination dominates over overclaim."""
        findings = [_finding_off_gt_line()]
        triage = [
            TriageResult(
                Verdict.TRUE_POSITIVE,
                0.9,
                "imagined flow",
                source_expr="request.args['q']",  # not in snippet
                sink_expr="os.system",
            )
        ]
        r = label_findings(findings, triage, _cve())
        assert r["tp"] == 0
        assert r["fp"] == 1
        assert r["fp_by_hallucinated_source"] == 1
        assert "fp_by_hallucinated_source" in r["labels"]

    def test_empty_source_expr_is_backcompat_parity(self) -> None:
        """Legacy TriageResult without source_expr must behave as Phase-B1."""
        findings = [_finding_on_gt_line()]
        triage = [
            TriageResult(
                Verdict.TRUE_POSITIVE, 0.9, "legacy entry"  # no source_expr/sink_expr
            )
        ]
        r = label_findings(findings, triage, _cve())
        assert r["tp"] == 1
        assert r["fp_by_hallucinated_source"] == 0
        assert r["tp_strict_by_llm_tp"] == 1
        assert r["tp_strict_by_llm_uncertain"] == 0

    def test_joern_metadata_source_counts_as_evidence_not_hallucination(self) -> None:
        findings = [_joern_helper_finding_with_gt_flow_path()]
        triage = [
            TriageResult(
                Verdict.TRUE_POSITIVE,
                0.9,
                "metadata-backed source",
                source_expr="request.args['cmd']",
                sink_expr="subprocess.run(cmd, shell=True)",
            )
        ]

        r = label_findings(findings, triage, _cve())

        assert r["tp"] == 0  # strict primary location is still helper.py:10
        assert r["fp"] == 1
        assert r["fp_by_hallucinated_source"] == 0
        assert r["flow_path_tp"] == 1
        assert r["same_file_flow_path_tp"] == 1
        assert r["flow_path_matched_lines"] == [42]

    def test_report_candidate_location_promotes_with_external_origin(self) -> None:
        findings = [_joern_finding_with_gt_report_candidate(origin_external=True)]
        triage = [TriageResult(Verdict.TRUE_POSITIVE, 0.9, "metadata-backed")]

        r = label_findings(findings, triage, _cve())

        assert r["tp"] == 1
        assert r["fp"] == 0
        assert r["fn"] == 0
        assert r["tp_via_report_candidate"] == 1
        assert r["report_candidate_location_tp"] == 1
        assert r["origin_external_tp_candidates"] == 1
        assert r["labels"] == ["tp_via_report_candidate"]

    def test_report_candidate_location_requires_external_origin_gate(self) -> None:
        findings = [_joern_finding_with_gt_report_candidate(origin_external=False)]
        triage = [TriageResult(Verdict.UNCERTAIN, 0.5, "metadata-backed")]

        r = label_findings(findings, triage, _cve())

        assert r["tp"] == 0
        assert r["fp"] == 1
        assert r["fn"] == 1
        assert r["tp_via_report_candidate"] == 0
        assert r["report_candidate_location_tp"] == 1
        assert r["report_candidate_promotion_blocked_by_origin_gate"] == 1
        assert r["labels"] == ["fp_by_location"]

    def test_report_candidate_location_promotes_with_caller_external(self) -> None:
        findings = [
            _joern_finding_with_gt_report_candidate(
                origin_external=False,
                caller_external=True,
            )
        ]
        triage = [TriageResult(Verdict.UNCERTAIN, 0.5, "metadata-backed")]

        r = label_findings(findings, triage, _cve())

        assert r["tp"] == 1
        assert r["fp"] == 0
        assert r["fn"] == 0
        assert r["tp_via_report_candidate"] == 1
        assert r["tp_via_report_candidate_caller_external"] == 1
        assert r["report_candidate_promotion_blocked_by_origin_gate"] == 0
        assert r["labels"] == ["tp_via_report_candidate"]

    def test_same_package_diagnostic_does_not_alter_strict_metrics(self) -> None:
        findings = [_joern_same_package_finding(origin_external=False)]
        triage = [TriageResult(Verdict.UNCERTAIN, 0.5, "same package")]

        r = label_findings(findings, triage, _cve())

        assert r["tp"] == 0
        assert r["fp"] == 1
        assert r["fn"] == 1
        assert r["tp_via_same_package"] == 1
        assert r["tp_via_same_package_with_origin"] == 0
        assert r["tp_via_same_package_blocked_by_origin_gate"] == 1
        assert r["labels"] == ["fp_by_location"]

    def test_same_package_with_origin_subcounter(self) -> None:
        findings = [_joern_same_package_finding(origin_external=True)]
        triage = [TriageResult(Verdict.TRUE_POSITIVE, 0.8, "same package")]

        r = label_findings(findings, triage, _cve())

        assert r["tp"] == 0
        assert r["fp"] == 1
        assert r["fn"] == 1
        assert r["tp_via_same_package"] == 1
        assert r["tp_via_same_package_with_origin"] == 1
        assert r["tp_via_same_package_blocked_by_origin_gate"] == 0


class TestSamePackagePromotion:
    """Relaxed-recall promotion that must NOT alter strict tp/fp/fn."""

    def test_does_not_modify_strict_tp_fp_fn(self) -> None:
        findings = [_joern_same_package_finding(origin_external=True)]
        triage = [TriageResult(Verdict.UNCERTAIN, 0.5, "promote me")]

        r = label_findings(findings, triage, _cve())

        assert r["tp"] == 0
        assert r["fp"] == 1
        assert r["fn"] == 1
        assert r["tp_via_same_package_promoted"] == 1
        assert r["relaxed_tp"] == 1
        assert r["same_package_promoted_finding_indexes"] == [0]
        assert r["labels"] == ["fp_by_location"]

    def test_requires_origin_external(self) -> None:
        findings = [_joern_same_package_finding(origin_external=False)]
        triage = [TriageResult(Verdict.UNCERTAIN, 0.5, "no origin")]

        r = label_findings(findings, triage, _cve())

        assert r["tp_via_same_package_promoted"] == 0
        assert r["relaxed_tp"] == r["tp"]
        assert r["same_package_promoted_finding_indexes"] == []

    def test_requires_promotable_verdict(self) -> None:
        findings = [_joern_same_package_finding(origin_external=True)]
        triage_fp = [TriageResult(Verdict.FALSE_POSITIVE, 0.9, "fp suppresses")]
        r_fp = label_findings(findings, triage_fp, _cve())
        assert r_fp["tp_via_same_package_promoted"] == 0
        assert r_fp["same_package_promoted_finding_indexes"] == []

        triage_hallucinated = [
            TriageResult(
                Verdict.TRUE_POSITIVE,
                0.95,
                "hallucinates",
                source_expr="totally_not_in_snippet()",
                sink_expr="subprocess.run(cmd, shell=True)",
            )
        ]
        r_h = label_findings(findings, triage_hallucinated, _cve())
        assert r_h["tp_via_same_package_promoted"] == 0
        assert r_h["fp_by_hallucinated_source"] == 1

    def test_does_not_double_count_strict_tp(self) -> None:
        findings = [_finding_on_gt_line()]
        findings[0].metadata = {"originExternalSource": True}
        triage = [
            TriageResult(
                Verdict.TRUE_POSITIVE,
                0.9,
                "ok",
                source_expr="request.args['cmd']",
                sink_expr="os.system(cmd)",
            )
        ]

        r = label_findings(findings, triage, _cve())

        assert r["tp"] == 1
        assert r["tp_via_same_package_promoted"] == 0
        assert r["relaxed_tp"] == 1
        assert r["tp_strict_by_llm_tp"] == 1
        assert r["tp_strict_by_llm_uncertain"] == 0
        assert r["labels"] == ["tp"]

    def test_does_not_double_count_report_candidate(self) -> None:
        finding = _joern_finding_with_gt_report_candidate(origin_external=True)
        # Place finding in a same-package file too, so both promotion paths
        # would otherwise apply; report-candidate must take precedence.
        finding.file_path = "app/something_adjacent.py"
        triage = [TriageResult(Verdict.TRUE_POSITIVE, 0.9, "metadata-backed")]

        r = label_findings([finding], triage, _cve())

        assert r["tp"] == 1
        assert r["tp_via_report_candidate"] == 1
        assert r["tp_via_same_package_promoted"] == 0


class TestFindingDedup:
    def test_same_key_duplicate_is_counted_once(self) -> None:
        findings = [
            _finding_on_gt_line_with_sink("os.system"),
            _finding_on_gt_line_with_sink("os.system"),
        ]
        triage = [
            TriageResult(Verdict.UNCERTAIN, 0.5, "same location"),
            TriageResult(Verdict.UNCERTAIN, 0.5, "same location"),
        ]

        r = label_findings(findings, triage, _cve())

        assert r["tp"] == 1
        assert r["fp"] == 0
        assert r["dedup_dropped"] == 1
        assert r["labels"] == ["tp", "dedup_dropped"]

    def test_same_line_different_sink_methods_are_retained(self) -> None:
        findings = [
            _finding_on_gt_line_with_sink("os.system"),
            _finding_on_gt_line_with_sink("subprocess.Popen"),
        ]
        triage = [
            TriageResult(Verdict.UNCERTAIN, 0.5, "first sink"),
            TriageResult(Verdict.UNCERTAIN, 0.5, "second sink"),
        ]

        r = label_findings(findings, triage, _cve())

        assert r["tp"] == 2
        assert r["fp"] == 0
        assert r["dedup_dropped"] == 0
        assert r["labels"] == ["tp", "tp"]

    def test_valid_true_positive_beats_false_positive_duplicate(self) -> None:
        findings = [
            _finding_on_gt_line_with_sink("os.system"),
            _finding_on_gt_line_with_sink("os.system"),
        ]
        triage = [
            TriageResult(Verdict.FALSE_POSITIVE, 0.9, "suppressed"),
            TriageResult(
                Verdict.TRUE_POSITIVE,
                0.9,
                "valid source",
                source_expr="request.args['cmd']",
                sink_expr="os.system(cmd)",
            ),
        ]

        r = label_findings(findings, triage, _cve())

        assert r["tp"] == 1
        assert r["fp"] == 0
        assert r["fn_by_llm"] == 0
        assert r["dedup_dropped"] == 1
        assert r["labels"] == ["dedup_dropped", "tp"]

    def test_hallucinated_true_positive_loses_to_clean_uncertain(self) -> None:
        findings = [
            _finding_on_gt_line_with_sink("os.system"),
            _finding_on_gt_line_with_sink("os.system"),
        ]
        triage = [
            TriageResult(
                Verdict.TRUE_POSITIVE,
                0.95,
                "hallucinated source",
                source_expr="sys.argv[1]",
                sink_expr="os.system(cmd)",
            ),
            TriageResult(Verdict.UNCERTAIN, 0.5, "clean uncertain"),
        ]

        r = label_findings(findings, triage, _cve())

        assert r["tp"] == 1
        assert r["fp"] == 0
        assert r["fp_by_hallucinated_source"] == 0
        assert r["dedup_dropped"] == 1
        assert r["labels"] == ["dedup_dropped", "tp"]


class TestPreDedupMetrics:
    """Run G dual-metric contract: ``label_findings`` must surface a
    ``pre_dedup_metrics`` sub-dict with Run E-style path-level counts while
    keeping the top-level dict at Run F-style unique-location counts."""

    def test_duplicates_split_into_pre_and_post_dedup_views(self) -> None:
        findings = [
            _finding_on_gt_line_with_sink("os.system"),
            _finding_on_gt_line_with_sink("os.system"),
        ]
        triage = [
            TriageResult(Verdict.UNCERTAIN, 0.5, "first path"),
            TriageResult(Verdict.UNCERTAIN, 0.5, "second path"),
        ]

        r = label_findings(findings, triage, _cve())

        assert r["tp"] == 1
        assert r["dedup_dropped"] == 1

        pre = r.get("pre_dedup_metrics")
        assert isinstance(pre, dict)
        assert pre["tp"] == 2
        assert pre["fp"] == 0
        assert pre.get("dedup_dropped", 0) == 0
        assert pre["labels"] == ["tp", "tp"]

    def test_run_e_continuity_for_single_unique_tp(self) -> None:
        findings = [_finding_on_gt_line()]
        triage = [TriageResult(Verdict.UNCERTAIN, 0.5, "single")]

        r = label_findings(findings, triage, _cve())

        assert r["tp"] == 1
        assert r["dedup_dropped"] == 0

        pre = r.get("pre_dedup_metrics")
        assert isinstance(pre, dict)
        assert pre["tp"] == r["tp"]
        assert pre["fp"] == r["fp"]
        assert pre["fn"] == r["fn"]
        assert pre.get("dedup_dropped", 0) == 0


class TestEvidenceSerialisation:
    def test_serialize_emits_evidence_audit_columns(self) -> None:
        findings = [_finding_on_gt_line(), _finding_off_gt_line()]
        triage = [
            TriageResult(
                Verdict.TRUE_POSITIVE,
                0.9,
                "ok",
                source_expr="request.args['cmd']",
                sink_expr="os.system(cmd)",
            ),
            TriageResult(
                Verdict.TRUE_POSITIVE,
                0.9,
                "bad",
                source_expr="sys.argv[1]",  # not in snippet
                sink_expr="os.system",
                downgrade_reason="",  # didn't get downgraded in this fake
            ),
        ]
        out = serialize_triage_verdicts(findings, triage)
        assert len(out) == 2
        for key in (
            "source_expr",
            "sink_expr",
            "source_in_snippet",
            "sink_in_snippet",
            "downgrade_reason",
        ):
            assert key in out[0]
            assert key in out[1]
        assert out[0]["source_in_snippet"] is True
        assert out[1]["source_in_snippet"] is False

    def test_serialize_emits_joern_flow_locations(self) -> None:
        findings = [_joern_helper_finding_with_gt_flow_path()]
        triage = [
            TriageResult(
                Verdict.TRUE_POSITIVE,
                0.9,
                "ok",
                source_expr="request.args['cmd']",
                sink_expr="subprocess.run(cmd, shell=True)",
            )
        ]

        [row] = serialize_triage_verdicts(findings, triage)

        assert row["source_in_snippet"] is True
        assert "app/shell.py:42" in row["joern_flow_locations"]
        assert "app/helpers.py:10" in row["joern_flow_locations"]
        assert row["sourceKind"] == "parameter"
        assert row["sinkKind"] == "wrapper"
        assert row["wrapperName"] == "run_user_command"
        assert row["wrappedSinkName"] == "run"
        assert row["shell_true"] is True

    def test_serialize_preserves_ten_report_candidate_locations(self) -> None:
        finding = _joern_finding_with_gt_report_candidate(origin_external=True)
        finding.metadata["reportCandidateLocations"] = [
            {"file": "app/shell.py", "line": i, "reason": "candidate"}
            for i in range(1, 12)
        ]
        triage = [TriageResult(Verdict.UNCERTAIN, 0.5, "ok")]

        [row] = serialize_triage_verdicts([finding], triage)

        assert len(row["reportCandidateLocations"]) == 10
        assert row["reportCandidateLocations"][-1]["line"] == 10

    def test_serialize_empty_expr_treated_as_present(self) -> None:
        """Back-compat: empty source_expr/sink_expr report True for parity."""
        findings = [_finding_on_gt_line()]
        triage = [TriageResult(Verdict.UNCERTAIN, 0.5, "legacy")]  # no evidence
        out = serialize_triage_verdicts(findings, triage)
        assert out[0]["source_in_snippet"] is True
        assert out[0]["sink_in_snippet"] is True
        assert out[0]["source_expr"] == ""
        assert out[0]["sink_expr"] == ""

    def test_serialize_emits_same_package_promoted_flag(self) -> None:
        promoted = _joern_same_package_finding(origin_external=True)
        not_promoted_origin = _joern_same_package_finding(origin_external=False)
        triage = [
            TriageResult(Verdict.UNCERTAIN, 0.5, "promotable"),
            TriageResult(Verdict.UNCERTAIN, 0.5, "blocked"),
        ]

        rows = serialize_triage_verdicts(
            [promoted, not_promoted_origin], triage, ground_truth=_cve()
        )

        assert rows[0]["same_package"] is True
        assert rows[0]["same_package_promoted"] is True
        assert rows[1]["same_package"] is True
        assert rows[1]["same_package_promoted"] is False

    def test_serialize_without_ground_truth_defaults_flags_false(self) -> None:
        finding = _joern_same_package_finding(origin_external=True)
        triage = [TriageResult(Verdict.UNCERTAIN, 0.5, "no gt")]

        [row] = serialize_triage_verdicts([finding], triage)

        assert row["same_package"] is False
        assert row["same_package_promoted"] is False

    def test_serialize_emits_strict_match_geometry_when_ground_truth_supplied(
        self,
    ) -> None:
        findings = [_finding_on_gt_line(), _finding_off_gt_line()]
        triage = [
            TriageResult(Verdict.TRUE_POSITIVE, 0.9, "ok"),
            TriageResult(Verdict.UNCERTAIN, 0.5, "off"),
        ]

        rows = serialize_triage_verdicts(findings, triage, ground_truth=_cve())

        assert rows[0]["is_strict_match"] is True
        assert rows[0]["matched_gt_line"] == 42
        assert rows[1]["is_strict_match"] is False
        assert rows[1]["matched_gt_line"] is None
