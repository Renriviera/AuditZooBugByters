"""Unit tests for Joern taint-flow deduplication.

The Joern arm previously emitted one Finding per distinct flow Joern
walked back through, which produced multiple findings on the same sink
line (e.g. ``Popen`` 1400 rows in the 20260508 partial-audit).  The
collapse policy in :func:`JoernArm._parse_taint_results` keys by
``(file, line, sink_api, normalised(sinkCode))`` and aggregates source
expressions into ``metadata['dedup_sources']`` with a count.
"""

from __future__ import annotations

from auditzoo.agents.cwe78_study.joern_arm import JoernArm


def _flow(
    *,
    sink_file: str = "app/shell.py",
    sink_line: int = 42,
    sink_name: str = "Popen",
    sink_code: str = "subprocess.Popen(cmd, shell=True)",
    source_code: str,
    recovery_kind: str | None = None,
) -> dict[str, str | int]:
    record: dict[str, str | int] = {
        "sinkFile": sink_file,
        "sinkLine": sink_line,
        "sinkName": sink_name,
        "sinkCode": sink_code,
        "sourceFile": "app/router.py",
        "sourceLine": 7,
        "sourceCode": source_code,
    }
    if recovery_kind is not None:
        record["recoveryKind"] = recovery_kind
    return record


class TestParseDedup:
    def test_two_flows_same_sink_collapse(self) -> None:
        raw = [
            _flow(source_code="request.args['cmd']"),
            _flow(source_code="sys.argv[1]"),
        ]
        findings = JoernArm._parse_taint_results(raw)

        assert len(findings) == 1
        f = findings[0]
        assert f.metadata["dedup_count"] == 2
        assert sorted(f.metadata["dedup_sources"]) == sorted(
            ["request.args['cmd']", "sys.argv[1]"]
        )
        assert f.sink_api == "Popen"
        assert f.line_start == 42

    def test_distinct_sinks_remain_separate(self) -> None:
        raw = [
            _flow(sink_line=42, source_code="request.args['cmd']"),
            _flow(sink_line=99, source_code="request.args['cmd']"),
        ]
        findings = JoernArm._parse_taint_results(raw)

        assert len(findings) == 2
        for f in findings:
            assert f.metadata["dedup_count"] == 1
            assert f.metadata["dedup_sources"] == ["request.args['cmd']"]

    def test_whitespace_only_difference_collapses(self) -> None:
        # Same canonical sink expression with only line-wrap and indent
        # differences — the most common shape Joern emits across taint
        # paths because it re-renders ``call.code`` per flow.
        raw = [
            _flow(
                sink_code="subprocess.Popen(\n    cmd, shell=True)",
                source_code="request.args['a']",
            ),
            _flow(
                sink_code="subprocess.Popen(    cmd, shell=True)",
                source_code="request.args['b']",
            ),
        ]
        findings = JoernArm._parse_taint_results(raw)

        assert len(findings) == 1
        assert findings[0].metadata["dedup_count"] == 2
        # Both source expressions are preserved as taint-evidence hints
        # for downstream triage.
        assert "request.args['a']" in findings[0].metadata["dedup_sources"]
        assert "request.args['b']" in findings[0].metadata["dedup_sources"]

    def test_dedup_sources_capped(self) -> None:
        raw = [
            _flow(source_code=f"src_{i}") for i in range(JoernArm._DEDUP_SOURCES_CAP + 4)
        ]
        findings = JoernArm._parse_taint_results(raw)

        assert len(findings) == 1
        f = findings[0]
        assert f.metadata["dedup_count"] == JoernArm._DEDUP_SOURCES_CAP + 4
        assert len(f.metadata["dedup_sources"]) == JoernArm._DEDUP_SOURCES_CAP

    def test_empty_input_returns_empty_list(self) -> None:
        assert JoernArm._parse_taint_results([]) == []
        assert JoernArm._parse_taint_results(None) == []
        assert JoernArm._parse_taint_results("not-a-list") == []


class TestRecoveryKindDedup:
    """Mixed-recovery_kind merge behaviour for the recall-recovery sweep."""

    def test_taint_wins_over_direct_sink_for_same_key(self) -> None:
        # Same sink line is hit by both a strict-taint flow (with real
        # source evidence) and a direct-sink emission (no source).
        # Priority order is taint > relaxed > def_use > direct_sink, so
        # the resulting Finding must keep the taint record's source and
        # rule_id while still surfacing both kinds in
        # ``recovery_kinds_seen``.
        raw = [
            _flow(
                source_code="",
                recovery_kind="direct_sink",
            ),
            _flow(
                source_code="request.args['cmd']",
                recovery_kind="taint",
            ),
        ]
        findings = JoernArm._parse_taint_results(raw)

        assert len(findings) == 1
        f = findings[0]
        assert f.metadata["recovery_kind"] == "taint"
        assert f.rule_id == "joern-taint-reachability"
        assert sorted(f.metadata["recovery_kinds_seen"]) == [
            "direct_sink",
            "taint",
        ]
        assert f.metadata["dedup_count"] == 2

    def test_relaxed_overrides_def_use(self) -> None:
        raw = [
            _flow(source_code="", recovery_kind="def_use"),
            _flow(source_code="request.args['cmd']", recovery_kind="relaxed"),
        ]
        findings = JoernArm._parse_taint_results(raw)

        assert len(findings) == 1
        f = findings[0]
        assert f.metadata["recovery_kind"] == "relaxed"
        assert f.rule_id == "joern-relaxed-recovery"
        assert "def_use" in f.metadata["recovery_kinds_seen"]
        assert "relaxed" in f.metadata["recovery_kinds_seen"]

    def test_unknown_recovery_kind_falls_back_to_taint(self) -> None:
        # A defensive fallback: pre-recovery cached results lack the
        # field entirely (default to taint) and unrecognised strings
        # also normalise to taint so the priority order stays defined.
        raw = [
            _flow(source_code="x", recovery_kind="bogus"),
        ]
        findings = JoernArm._parse_taint_results(raw)

        assert len(findings) == 1
        assert findings[0].metadata["recovery_kind"] == "taint"

    def test_default_recovery_kind_is_taint_when_absent(self) -> None:
        raw = [_flow(source_code="x")]
        findings = JoernArm._parse_taint_results(raw)

        assert len(findings) == 1
        assert findings[0].metadata["recovery_kind"] == "taint"
        assert findings[0].metadata["recovery_kinds_seen"] == ["taint"]

    def test_lower_priority_kind_does_not_displace_existing(self) -> None:
        # First record is taint; subsequent direct_sink for same key
        # increments dedup_count but leaves recovery_kind="taint".
        raw = [
            _flow(source_code="request.args['cmd']", recovery_kind="taint"),
            _flow(source_code="", recovery_kind="direct_sink"),
        ]
        findings = JoernArm._parse_taint_results(raw)

        assert len(findings) == 1
        f = findings[0]
        assert f.metadata["recovery_kind"] == "taint"
        assert f.metadata["dedup_count"] == 2
