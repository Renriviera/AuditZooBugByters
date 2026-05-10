"""Tests for the relaxed-taint and def-use CPGQL recovery passes.

The relaxed-taint pass widens the strict source set with
``cpg.identifier`` and ``cpg.parameter`` matches so that
attribute/parameter relays reach the sink.  The def-use chase walks
back from sink arguments to any non-literal predecessor regardless of
catalog membership (the broadest "did anything dynamic flow here?"
signal).

These tests check the CPGQL query strings the builders emit — Joern
itself is not invoked — so that we catch regressions in the query
shape (cap, sink Set membership, recoveryKind literal, source widening)
without standing up a full sweep.
"""

from __future__ import annotations

from auditzoo.agents.cwe78_study.joern_arm import JoernArm


class TestRelaxedTaintQuery:
    def test_emits_recovery_kind_relaxed(self) -> None:
        query = JoernArm._build_relaxed_taint_query(
            ["request.args"], ["os.system"], cap=50
        )
        assert '"recoveryKind" -> "relaxed"' in query

    def test_widens_to_identifier_and_parameter_nodes(self) -> None:
        # Relaxed taint must scan ``cpg.identifier`` and
        # ``cpg.parameter`` in addition to the strict
        # ``cpg.fieldAccess``/``cpg.call`` source set.
        query = JoernArm._build_relaxed_taint_query(
            ["request.args"], ["os.system"], cap=50
        )
        assert "cpg.fieldAccess" in query
        assert "cpg.identifier" in query
        assert "cpg.parameter" in query

    def test_caps_total_flows_via_take(self) -> None:
        query = JoernArm._build_relaxed_taint_query(
            ["request.args"], ["os.system"], cap=42
        )
        assert ".take(42)" in query

    def test_uses_strict_sink_short_names(self) -> None:
        query = JoernArm._build_relaxed_taint_query(
            ["request.args"], ["subprocess.Popen", "os.system"], cap=10
        )
        assert '"Popen"' in query
        assert '"system"' in query

    def test_default_cap_constant_matches_pipeline(self) -> None:
        # The pipeline asks the joern arm for the relaxed pass with
        # ``JoernArm._RELAXED_TAINT_CAP`` — keep that constant in sync
        # with the cap actually emitted in the query when the public
        # default is used.
        query = JoernArm._build_relaxed_taint_query(
            ["request.args"], ["os.system"], cap=JoernArm._RELAXED_TAINT_CAP
        )
        assert f".take({JoernArm._RELAXED_TAINT_CAP})" in query


class TestDefUseChaseQuery:
    def test_emits_recovery_kind_def_use(self) -> None:
        query = JoernArm._build_def_use_chase_query(["os.system"], cap=10)
        assert '"recoveryKind" -> "def_use"' in query

    def test_does_not_filter_sources_by_catalog(self) -> None:
        # Def-use chase intentionally has no source-name filter — it
        # walks back to any non-literal predecessor.  Verify the query
        # references the bare ``cpg.fieldAccess.l`` / ``cpg.identifier.l``
        # / ``cpg.parameter.l`` lists with no ``.code(...)`` constraint.
        query = JoernArm._build_def_use_chase_query(["os.system"], cap=10)
        assert "cpg.fieldAccess.l" in query
        assert "cpg.identifier.l" in query
        assert "cpg.parameter.l" in query

    def test_caps_total_flows_via_take(self) -> None:
        query = JoernArm._build_def_use_chase_query(["os.system"], cap=33)
        assert ".take(33)" in query


class TestRelaxedTaintDedupParsing:
    def _record(
        self,
        *,
        recovery_kind: str,
        source_code: str = "",
        sink_line: int = 42,
    ) -> dict[str, str | int]:
        return {
            "sinkFile": "app/shell.py",
            "sinkLine": sink_line,
            "sinkName": "Popen",
            "sinkCode": "subprocess.Popen(cmd, shell=True)",
            "sourceFile": "app/router.py" if source_code else "",
            "sourceLine": 7 if source_code else -1,
            "sourceCode": source_code,
            "recoveryKind": recovery_kind,
        }

    def test_relaxed_priority_above_def_use_and_direct_sink(self) -> None:
        raw = [
            self._record(recovery_kind="def_use"),
            self._record(recovery_kind="direct_sink"),
            self._record(
                recovery_kind="relaxed", source_code="self._cmd"
            ),
        ]
        findings = JoernArm._parse_taint_results(raw)

        assert len(findings) == 1
        f = findings[0]
        assert f.metadata["recovery_kind"] == "relaxed"
        assert f.rule_id == "joern-relaxed-recovery"
        assert "self._cmd" in f.metadata["dedup_sources"]
        assert sorted(f.metadata["recovery_kinds_seen"]) == [
            "def_use",
            "direct_sink",
            "relaxed",
        ]

    def test_def_use_priority_above_direct_sink(self) -> None:
        raw = [
            self._record(recovery_kind="direct_sink"),
            self._record(recovery_kind="def_use", source_code="raw_input"),
        ]
        findings = JoernArm._parse_taint_results(raw)

        assert len(findings) == 1
        f = findings[0]
        assert f.metadata["recovery_kind"] == "def_use"
        assert f.rule_id == "joern-def_use-recovery"
        assert "raw_input" in f.metadata["dedup_sources"]
