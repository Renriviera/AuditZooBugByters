"""Unit tests for the per-iteration phase-timing helpers in ``pipeline.py``."""

from __future__ import annotations

import time

import pytest

from auditzoo.agents.cwe78_study.pipeline import (
    _PHASE_KEYS,
    _joern_structural_evidence,
    _joern_structural_evidence_map,
    _llm_tokens_delta,
    _reduce_joern_findings,
    _stopwatch,
    build_phase_metrics,
)
from auditzoo.agents.cwe78_study.schemas import Finding

EMPTY_USAGE: dict[str, int] = {
    "prompt_tokens": 0,
    "completion_tokens": 0,
    "total_tokens": 0,
    "call_count": 0,
}


def _make_metrics(**phase_times: float) -> dict[str, object]:
    """Build a metrics dict with zero LLM/finding fields but configurable phases."""
    return build_phase_metrics(
        wall_clock_s=phase_times.get("wall_clock_s", 0.0),
        n_findings=0,
        n_tp=0,
        n_fp=0,
        n_uncertain=0,
        llm_usage=EMPTY_USAGE,
        cpg_build_s=phase_times.get("cpg_build_s", 0.0),
        scan_s=phase_times.get("scan_s", 0.0),
        llm_triage_s=phase_times.get("llm_triage_s", 0.0),
        llm_refinement_s=phase_times.get("llm_refinement_s", 0.0),
        call_graph_s=phase_times.get("call_graph_s", 0.0),
    )


class TestBuildPhaseMetrics:
    def test_contains_all_phase_keys_plus_overhead(self) -> None:
        m = _make_metrics(wall_clock_s=1.0)
        for k in _PHASE_KEYS:
            assert k in m, f"missing phase key {k!r}"
        assert "overhead_s" in m
        assert "wall_clock_s" in m
        assert "llm_usage" in m
        assert "llm_tokens_triage" in m
        assert "llm_tokens_refinement" in m

    def test_overhead_is_residual(self) -> None:
        m = _make_metrics(
            wall_clock_s=10.0,
            cpg_build_s=2.0,
            scan_s=1.0,
            llm_triage_s=3.0,
            llm_refinement_s=1.5,
            call_graph_s=0.5,
        )
        # 10 - (2 + 1 + 3 + 1.5 + 0.5) = 2.0
        assert m["overhead_s"] == pytest.approx(2.0)

    def test_overhead_clamped_to_zero_on_minor_skew(self) -> None:
        """Attributed > wall_clock by a tiny margin (clock skew) must not go negative."""
        m = _make_metrics(
            wall_clock_s=1.0,
            scan_s=0.6,
            llm_triage_s=0.5,  # sum=1.1 > 1.0 by 0.1
        )
        assert m["overhead_s"] == 0.0

    def test_phase_sum_plus_overhead_equals_wall_clock_when_no_skew(self) -> None:
        phases = {
            "cpg_build_s": 0.1,
            "scan_s": 0.2,
            "llm_triage_s": 0.3,
            "llm_refinement_s": 0.15,
            "call_graph_s": 0.05,
        }
        wall = sum(phases.values()) + 0.4  # 0.4 overhead
        m = _make_metrics(wall_clock_s=wall, **phases)
        reconstructed = (
            m["cpg_build_s"]
            + m["scan_s"]
            + m["llm_triage_s"]
            + m["llm_refinement_s"]
            + m["call_graph_s"]
            + m["overhead_s"]
        )
        assert reconstructed == pytest.approx(m["wall_clock_s"])

    def test_counts_and_usage_passed_through(self) -> None:
        usage = {
            "prompt_tokens": 100,
            "completion_tokens": 50,
            "total_tokens": 150,
            "call_count": 3,
        }
        m = build_phase_metrics(
            wall_clock_s=1.0,
            n_findings=7,
            n_tp=3,
            n_fp=2,
            n_uncertain=2,
            llm_usage=usage,
            llm_tokens_triage=80,
            llm_tokens_refinement=70,
        )
        assert m["n_findings"] == 7
        assert m["n_tp"] == 3
        assert m["n_fp"] == 2
        assert m["n_uncertain"] == 2
        assert m["llm_usage"] is usage
        assert m["llm_tokens_triage"] == 80
        assert m["llm_tokens_refinement"] == 70


class TestLLMTokensDelta:
    def test_delta_computes_total_tokens_difference(self) -> None:
        before = {"total_tokens": 100, "call_count": 1}
        after = {"total_tokens": 250, "call_count": 3}
        assert _llm_tokens_delta(before, after) == 150

    def test_delta_handles_missing_keys(self) -> None:
        assert _llm_tokens_delta({}, {}) == 0
        assert _llm_tokens_delta({}, {"total_tokens": 42}) == 42


class TestStopwatch:
    def test_stopwatch_measures_elapsed_after_exit(self) -> None:
        with _stopwatch() as t:
            time.sleep(0.02)
        # Stopwatch must have written a value strictly greater than the sleep.
        assert t[0] >= 0.02
        # And be bounded well below a second on any reasonable host.
        assert t[0] < 1.0

    def test_stopwatch_writes_on_exception(self) -> None:
        t_holder: list[float] = []
        try:
            with _stopwatch() as t:
                t_holder = t
                time.sleep(0.01)
                raise RuntimeError("boom")
        except RuntimeError:
            pass
        assert t_holder[0] >= 0.01


class TestJoernStructuralEvidence:
    def test_renders_source_sink_and_flow_from_metadata(self) -> None:
        finding = Finding(
            file_path="pkg/sink.py",
            line_start=20,
            line_end=20,
            rule_id="joern-taint-reachability",
            message="demo",
            sink_api="run",
            metadata={
                "sourceFile": "pkg/source.py",
                "sourceLine": "10",
                "sourceCode": "request.args['cmd']",
                "sinkFile": "pkg/sink.py",
                "sinkLine": "20",
                "sinkCode": "subprocess.run(cmd, shell=True)",
                "sinkName": "run",
                "flowPath": [
                    {
                        "file": "pkg/source.py",
                        "line": "10",
                        "code": "request.args['cmd']",
                        "nodeType": "Call",
                    }
                ],
            },
        )

        evidence = _joern_structural_evidence(finding)

        assert "Joern source: pkg/source.py:10 `request.args['cmd']`" in evidence
        assert (
            "Joern sink: pkg/sink.py:20 run `subprocess.run(cmd, shell=True)`"
            in evidence
        )
        assert (
            "Joern taint flow: `request.args['cmd']` -> "
            "`subprocess.run(cmd, shell=True)`"
        ) in evidence
        assert "Joern flow path:" not in evidence

        full_evidence = _joern_structural_evidence(finding, include_flow_path=True)

        assert "Joern flow path:" in full_evidence
        assert "pkg/source.py:10 Call `request.args['cmd']`" in full_evidence

    def test_evidence_map_only_includes_findings_with_metadata(self) -> None:
        with_metadata = Finding(
            file_path="pkg/sink.py",
            line_start=20,
            line_end=20,
            rule_id="joern-taint-reachability",
            message="demo",
            metadata={"sourceCode": "sys.argv[1]", "sinkCode": "os.system(cmd)"},
        )
        without_metadata = Finding(
            file_path="pkg/other.py",
            line_start=5,
            line_end=5,
            rule_id="joern-taint-reachability",
            message="demo",
        )

        evidence_map = _joern_structural_evidence_map([with_metadata, without_metadata])

        assert list(evidence_map) == [0]
        assert "sys.argv[1]" in evidence_map[0]

    def test_structural_evidence_renders_origin_and_caller_chain(self) -> None:
        finding = Finding(
            file_path="pkg/sink.py",
            line_start=20,
            line_end=20,
            rule_id="joern-taint-reachability",
            message="demo",
            metadata={
                "sourceCode": "cmd",
                "sinkCode": "subprocess.run(cmd, shell=True)",
                "originExternalSource": True,
                "originEvidence": [
                    {
                        "file": "pkg/view.py",
                        "line": "9",
                        "code": "cmd = os.getenv('CMD')",
                        "matchesExternal": True,
                    }
                ],
                "callerChain": [
                    {
                        "file": "pkg/view.py",
                        "line": "12",
                        "code": "run(request.args['cmd'])",
                        "argumentCode": "request.args['cmd']",
                        "matchesExternal": True,
                    }
                ],
            },
        )

        evidence = _joern_structural_evidence(finding)

        assert "Joern origin: external_source_confirmed" in evidence
        assert "Joern origin evidence:" in evidence
        assert "cmd = os.getenv('CMD')" in evidence
        assert "Joern caller evidence:" in evidence
        assert "arg=`request.args['cmd']` [external]" in evidence


class TestJoernCandidateReducer:
    def test_reducer_keeps_high_risk_findings_before_low_signal_ones(self) -> None:
        risky = Finding(
            file_path="app/views.py",
            line_start=12,
            line_end=12,
            rule_id="joern-taint-reachability",
            message="risk",
            metadata={
                "sinkKind": "direct",
                "sourceKind": "parameter",
                "sinkCode": "subprocess.run(cmd, shell=True)",
                "shell_true": True,
                "string_command_like": True,
                "reportReason": "flow_command_construction",
            },
        )
        low_signal = Finding(
            file_path="tests/test_runner.py",
            line_start=20,
            line_end=20,
            rule_id="joern-taint-reachability",
            message="noise",
            metadata={
                "sinkKind": "wrapper",
                "wrapperName": "run",
                "sourceKind": "attribute",
                "sinkCode": "subprocess.run(command.split(' '))",
                "argv_list_like": True,
                "test_file": True,
            },
        )

        kept, metrics = _reduce_joern_findings([low_signal, risky], 1)

        assert kept == [risky]
        assert metrics["joern_raw_findings"] == 2
        assert metrics["joern_triaged_findings"] == 1
        assert metrics["joern_candidates_dropped_before_triage"] == 1
        assert metrics["joern_dropped_reason_counts"] == {"low_signal_path": 1}

    def test_reducer_keeps_external_origin_before_generic_parameter(self) -> None:
        external = Finding(
            file_path="app/views.py",
            line_start=12,
            line_end=12,
            rule_id="joern-taint-reachability",
            message="external",
            metadata={
                "sinkKind": "direct",
                "sourceKind": "attribute",
                "originExternalSource": True,
                "sinkCode": "subprocess.run(cmd, shell=True)",
                "shell_true": True,
            },
        )
        generic = Finding(
            file_path="app/helpers.py",
            line_start=30,
            line_end=30,
            rule_id="joern-taint-reachability",
            message="generic",
            metadata={
                "sinkKind": "direct",
                "sourceKind": "parameter",
                "sinkCode": "subprocess.run(cmd, shell=True)",
                "shell_true": True,
            },
        )

        kept, _ = _reduce_joern_findings([generic, external], 1)

        assert kept == [external]

    def test_reducer_keeps_external_caller_before_generic_parameter(self) -> None:
        caller_external = Finding(
            file_path="app/helpers.py",
            line_start=20,
            line_end=20,
            rule_id="joern-taint-reachability",
            message="caller",
            metadata={
                "sinkKind": "direct",
                "sourceKind": "parameter",
                "sinkCode": "subprocess.run(cmd, shell=True)",
                "shell_true": True,
                "callerChain": [
                    {
                        "file": "app/views.py",
                        "line": "10",
                        "code": "run(request.args['cmd'])",
                        "argumentCode": "request.args['cmd']",
                        "matchesExternal": True,
                    }
                ],
            },
        )
        generic = Finding(
            file_path="app/helpers.py",
            line_start=30,
            line_end=30,
            rule_id="joern-taint-reachability",
            message="generic",
            metadata={
                "sinkKind": "direct",
                "sourceKind": "parameter",
                "sinkCode": "subprocess.run(cmd, shell=True)",
                "shell_true": True,
            },
        )

        kept, _ = _reduce_joern_findings([generic, caller_external], 1)

        assert kept == [caller_external]

    def test_reducer_keeps_shell_true_external_before_literal_noise(self) -> None:
        external = Finding(
            file_path="app/views.py",
            line_start=12,
            line_end=12,
            rule_id="joern-taint-reachability",
            message="external",
            metadata={
                "sinkKind": "direct",
                "sourceKind": "external",
                "sinkCode": "subprocess.run(cmd, shell=True)",
                "shell_true": True,
                "originExternalSource": True,
            },
        )
        literal_noise = Finding(
            file_path="app/maintenance.py",
            line_start=8,
            line_end=8,
            rule_id="joern-taint-reachability",
            message="literal",
            metadata={
                "sinkKind": "direct",
                "sourceKind": "catalog",
                "sinkCode": "os.system('echo ok')",
                "literal_command_like": True,
            },
        )

        kept, _ = _reduce_joern_findings([literal_noise, external], 1)

        assert kept == [external]

    def test_high_risk_findings_kept_when_cap_exceeded(self) -> None:
        high_risk = [
            Finding(
                file_path=f"app/risky_{idx}.py",
                line_start=idx,
                line_end=idx,
                rule_id="joern-taint-reachability",
                message="risk",
                metadata={
                    "sourceKind": "parameter",
                    "sinkKind": "direct",
                    "sinkCode": "subprocess.run(cmd, shell=True)",
                    "shell_true": True,
                },
            )
            for idx in range(10)
        ]
        low_risk = [
            Finding(
                file_path=f"app/noise_{idx}.py",
                line_start=idx,
                line_end=idx,
                rule_id="joern-taint-reachability",
                message="noise",
                metadata={
                    "sourceKind": "attribute",
                    "sinkKind": "direct",
                    "sinkCode": "subprocess.run(cmd)",
                    "argv_list_like": True,
                },
            )
            for idx in range(30)
        ]

        kept, metrics = _reduce_joern_findings(low_risk + high_risk, 20)

        assert len(kept) == 20
        assert all(f in kept for f in high_risk)
        assert metrics["joern_high_risk_count"] == 10
        assert metrics["joern_high_risk_kept"] == 10
        assert metrics["joern_high_risk_dropped_when_overflow"] == 0

    def test_high_risk_overflow_drops_lower_ranked_high_risk_only(self) -> None:
        high_risk = [
            Finding(
                file_path=f"app/risky_{idx}.py",
                line_start=idx,
                line_end=idx,
                rule_id="joern-taint-reachability",
                message="risk",
                metadata={
                    "sourceKind": "parameter",
                    "sinkKind": "direct",
                    "sinkCode": "subprocess.run(cmd, shell=True)",
                    "shell_true": True,
                },
            )
            for idx in range(25)
        ]
        low_risk = [
            Finding(
                file_path="app/noise.py",
                line_start=100,
                line_end=100,
                rule_id="joern-taint-reachability",
                message="noise",
                metadata={"sinkCode": "subprocess.run(cmd)"},
            )
        ]

        kept, metrics = _reduce_joern_findings(low_risk + high_risk, 20)

        assert len(kept) == 20
        assert all(f in high_risk for f in kept)
        assert metrics["joern_high_risk_count"] == 25
        assert metrics["joern_high_risk_kept"] == 20
        assert metrics["joern_high_risk_dropped_when_overflow"] == 5


def _high_risk_finding(idx: int) -> Finding:
    return Finding(
        file_path=f"app/risky_{idx}.py",
        line_start=idx,
        line_end=idx,
        rule_id="joern-taint-reachability",
        message="risk",
        metadata={
            "sourceKind": "parameter",
            "sinkKind": "direct",
            "sinkCode": "subprocess.run(cmd, shell=True)",
            "shell_true": True,
        },
    )


def _low_risk_finding(idx: int) -> Finding:
    return Finding(
        file_path=f"app/noise_{idx}.py",
        line_start=idx,
        line_end=idx,
        rule_id="joern-taint-reachability",
        message="noise",
        metadata={
            "sourceKind": "attribute",
            "sinkKind": "direct",
            "sinkCode": "subprocess.run(cmd)",
            "argv_list_like": True,
        },
    )


class TestTwoBudgetReducer:
    """Two-budget cap (high-risk + low-risk independently capped)."""

    def test_keeps_high_risk_within_cap(self) -> None:
        high_risk = [_high_risk_finding(i) for i in range(30)]
        low_risk = [_low_risk_finding(i) for i in range(30)]

        kept, metrics = _reduce_joern_findings(
            low_risk + high_risk, None, high_risk_cap=20, low_risk_cap=10
        )

        assert len(kept) == 30
        assert sum(1 for f in kept if f in high_risk) == 20
        assert sum(1 for f in kept if f in low_risk) == 10
        assert metrics["joern_high_risk_count"] == 30
        assert metrics["joern_high_risk_kept"] == 20
        assert metrics["joern_high_risk_dropped_when_overflow"] == 10
        assert metrics["joern_low_risk_count"] == 30
        assert metrics["joern_low_risk_kept"] == 10
        assert metrics["joern_low_risk_dropped_when_overflow"] == 20

    def test_falls_back_to_single_cap_when_unset(self) -> None:
        high_risk = [_high_risk_finding(i) for i in range(10)]
        low_risk = [_low_risk_finding(i) for i in range(30)]

        kept, metrics = _reduce_joern_findings(low_risk + high_risk, 20)

        assert len(kept) == 20
        assert sum(1 for f in kept if f in high_risk) == 10
        assert metrics["joern_high_risk_kept"] == 10
        assert metrics["joern_high_risk_dropped_when_overflow"] == 0
        assert metrics["joern_high_risk_cap"] is None
        assert metrics["joern_low_risk_cap"] is None

    def test_low_risk_only_when_no_high_risk(self) -> None:
        low_risk = [_low_risk_finding(i) for i in range(50)]

        kept, metrics = _reduce_joern_findings(
            low_risk, None, high_risk_cap=20, low_risk_cap=10
        )

        assert len(kept) == 10
        assert metrics["joern_high_risk_count"] == 0
        assert metrics["joern_high_risk_kept"] == 0
        assert metrics["joern_low_risk_count"] == 50
        assert metrics["joern_low_risk_kept"] == 10
        assert metrics["joern_low_risk_dropped_when_overflow"] == 40

    def test_records_caps_in_metrics(self) -> None:
        high_risk = [_high_risk_finding(i) for i in range(5)]

        _, metrics = _reduce_joern_findings(
            high_risk, None, high_risk_cap=20, low_risk_cap=10
        )

        assert metrics["joern_high_risk_cap"] == 20
        assert metrics["joern_low_risk_cap"] == 10
        assert metrics["joern_candidate_reducer_cap"] == 30

    def test_reducer_disabled_returns_all(self) -> None:
        high_risk = [_high_risk_finding(i) for i in range(5)]
        low_risk = [_low_risk_finding(i) for i in range(5)]

        kept, metrics = _reduce_joern_findings(
            high_risk + low_risk,
            None,
            enabled=False,
            high_risk_cap=20,
            low_risk_cap=10,
        )

        assert len(kept) == 10
        assert metrics["joern_high_risk_dropped_when_overflow"] == 0
        assert metrics["joern_low_risk_dropped_when_overflow"] == 0
