"""Unit tests for the per-iteration phase-timing helpers in ``pipeline.py``."""

from __future__ import annotations

import time

import pytest

from auditzoo.agents.cwe78_study.pipeline import (
    _PHASE_KEYS,
    _llm_tokens_delta,
    _stopwatch,
    build_phase_metrics,
)


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
        phases = dict(
            cpg_build_s=0.1,
            scan_s=0.2,
            llm_triage_s=0.3,
            llm_refinement_s=0.15,
            call_graph_s=0.05,
        )
        wall = sum(phases.values()) + 0.4  # 0.4 overhead
        m = _make_metrics(wall_clock_s=wall, **phases)
        reconstructed = (
            m["cpg_build_s"] + m["scan_s"] + m["llm_triage_s"]
            + m["llm_refinement_s"] + m["call_graph_s"] + m["overhead_s"]
        )
        assert reconstructed == pytest.approx(m["wall_clock_s"])

    def test_counts_and_usage_passed_through(self) -> None:
        usage = {"prompt_tokens": 100, "completion_tokens": 50,
                 "total_tokens": 150, "call_count": 3}
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
