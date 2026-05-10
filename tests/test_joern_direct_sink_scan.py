"""Tests for the direct-sink CPGQL recovery pass.

The direct-sink pass surfaces every dangerous-sink call irrespective of
whether the strict ``reachableByFlows`` engine connects it back to a
catalog source.  These tests cover both the query string shape (so we
catch regressions in CPGQL syntax during edits) and the dedup
behaviour when direct-sink records are unioned with strict-taint
records via :meth:`JoernArm._parse_taint_results`.
"""

from __future__ import annotations

from auditzoo.agents.cwe78_study.joern_arm import JoernArm


class TestDirectSinkQueryShape:
    """Static-string assertions on the CPGQL query builder.

    We don't run Joern in unit tests; instead we assert on the query
    string so any drift in the prefix regex / Set membership /
    ``recoveryKind`` literal is caught before sweep time.
    """

    def test_emits_recovery_kind_literal(self) -> None:
        query = JoernArm._build_direct_sink_query(["os.system"], cap=10)
        assert '"recoveryKind" -> "direct_sink"' in query

    def test_caps_total_records_via_take(self) -> None:
        query = JoernArm._build_direct_sink_query(["os.system"], cap=37)
        assert ".take(37)" in query

    def test_uses_short_name_set_filter(self) -> None:
        query = JoernArm._build_direct_sink_query(
            ["os.system", "subprocess.Popen", "subprocess.run"], cap=5
        )
        # All three short names should appear in the Scala Set literal.
        assert '"system"' in query
        assert '"Popen"' in query
        assert '"run"' in query

    def test_empty_sinks_yields_neutral_pattern(self) -> None:
        # The CPGQL must remain syntactically valid even when the input
        # sink list is empty (e.g. a partial config).  We rely on
        # ``_build_sink_filter`` substituting ``(?!x)x`` so the query
        # matches nothing rather than failing to compile.
        query = JoernArm._build_direct_sink_query([], cap=5)
        assert "(?!x)x" in query

    def test_sink_name_with_regex_metachars_is_escaped(self) -> None:
        # Catalog entries are sanitised before they reach the builder,
        # but we still defensively escape — this regression guards the
        # ``_safe_union`` helper.
        query = JoernArm._build_direct_sink_query(["a.b+c"], cap=5)
        assert "a\\.b\\+c" in query


class TestDirectSinkDedup:
    """Cross-pass dedup when ``_parse_taint_results`` sees both kinds."""

    def _record(
        self,
        *,
        sink_line: int,
        recovery_kind: str,
        source_code: str = "",
        sink_code: str = "subprocess.Popen(cmd, shell=True)",
    ) -> dict[str, str | int]:
        return {
            "sinkFile": "app/shell.py",
            "sinkLine": sink_line,
            "sinkName": "Popen",
            "sinkCode": sink_code,
            "sourceFile": "app/router.py" if source_code else "",
            "sourceLine": 7 if source_code else -1,
            "sourceCode": source_code,
            "recoveryKind": recovery_kind,
        }

    def test_taint_wins_when_direct_sink_seen_first(self) -> None:
        raw = [
            self._record(sink_line=42, recovery_kind="direct_sink"),
            self._record(
                sink_line=42,
                recovery_kind="taint",
                source_code="request.args['cmd']",
            ),
        ]
        findings = JoernArm._parse_taint_results(raw)

        assert len(findings) == 1
        f = findings[0]
        assert f.metadata["recovery_kind"] == "taint"
        assert f.rule_id == "joern-taint-reachability"
        # Source should reflect the strict-taint record.
        assert "request.args['cmd']" in f.metadata["dedup_sources"]

    def test_distinct_sinks_each_kept(self) -> None:
        raw = [
            self._record(sink_line=42, recovery_kind="direct_sink"),
            self._record(sink_line=99, recovery_kind="direct_sink"),
        ]
        findings = JoernArm._parse_taint_results(raw)

        assert len(findings) == 2
        for f in findings:
            assert f.metadata["recovery_kind"] == "direct_sink"
            assert f.rule_id == "joern-direct_sink-recovery"

    def test_message_for_direct_sink_only_record(self) -> None:
        # When the only record is a direct-sink emission with no source
        # at all, the Finding's message should reflect that ("Direct
        # sink call: …") rather than the misleading
        # "Taint flow: -> …" string the legacy code would have produced.
        raw = [self._record(sink_line=42, recovery_kind="direct_sink")]
        findings = JoernArm._parse_taint_results(raw)

        assert len(findings) == 1
        assert findings[0].message.startswith("Direct sink call:")
