"""Unit tests for the structural-evidence wiring into the triage brake.

The 20260509 validation audit attributed most ``joern_candidate_missing``
false negatives to inter-procedural taint flows whose source expression
lived in a caller and therefore was not part of the ±N-line snippet
shown to the triage LLM.  The triager's substring brake then downgraded
the LLM's ``true_positive`` verdict to ``UNCERTAIN`` (audit row pattern:
``nearest_distance=0, verdict=uncertain``) and the audit recorded an
FN for every patched line.

The fix wires :func:`auditzoo.agents.cwe78_study.pipeline.
_build_structural_evidence_map` into both ``triage_batch`` call sites so
the brake's haystack now includes the source expression Joern already
extracted into ``Finding.metadata``.  These tests pin down the helper's
behaviour and the brake interaction end-to-end.
"""

from __future__ import annotations

import pytest

from auditzoo.agents.cwe78_study.pipeline import (
    _STRUCTURAL_EVIDENCE_ALT_SOURCES_CAP,
    _build_structural_evidence_map,
    _is_self_flow_source,
    _structural_evidence_for_finding,
    _truncate_evidence_field,
)
from auditzoo.agents.cwe78_study.schemas import Finding, ToolArm, Verdict
from auditzoo.agents.cwe78_study.triage_agent import TriageAgent

# ---------------------------------------------------------------------------
# Lightweight scripted LLM (mirrors tests/test_triage_prompt.py)
# ---------------------------------------------------------------------------


class _ScriptedLLM:
    def __init__(self, scripted: list[dict]) -> None:
        self._scripted = list(scripted)
        self.calls: list[tuple[str, str]] = []

    async def chat_json(self, system_prompt: str, user_prompt: str):
        self.calls.append((system_prompt, user_prompt))
        if not self._scripted:
            raise RuntimeError("ScriptedLLM ran out of responses")
        return self._scripted.pop(0)


def _joern_finding(
    *,
    file_path: str = "app/views.py",
    line: int = 100,
    source_code: str = "data.get('address')",
    source_file: str = "app/views.py",
    source_line: int = 41,
    sink_code: str = "Popen(cmd, shell=True, stdin=PIPE)",
    sink_name: str = "Popen",
    recovery_kind: str = "taint",
    dedup_sources: list[str] | None = None,
    dedup_count: int = 1,
    surrounding_context: str = (
        "   95|     project_name = data.get('project')\n"
        "   96|     target = path_join(BASE, project_name)\n"
        "   97|     cmd = 'git clone {address} {target}'.format(\n"
        "   98|         address=address, target=target,\n"
        "   99|     )\n"
        "  100|     Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)\n"
        "  101|     return JsonResponse({'ok': True})\n"
    ),
) -> Finding:
    metadata = {
        "sourceCode": source_code,
        "sourceFile": source_file,
        "sourceLine": source_line,
        "sinkCode": sink_code,
        "sinkName": sink_name,
        "sinkFile": file_path,
        "sinkLine": line,
        "recovery_kind": recovery_kind,
        "recovery_kinds_seen": [recovery_kind],
        "dedup_count": dedup_count,
        "dedup_sources": list(dedup_sources or [source_code]),
    }
    return Finding(
        file_path=file_path,
        line_start=line,
        line_end=line,
        rule_id="joern-taint-reachability",
        message=f"Taint flow: {source_code} -> {sink_code}",
        code_snippet=sink_code,
        surrounding_context=surrounding_context,
        sink_api=sink_name,
        arm=ToolArm.JOERN,
        metadata=metadata,
    )


# ---------------------------------------------------------------------------
# Helper-level tests
# ---------------------------------------------------------------------------


class TestStructuralEvidenceHelper:
    def test_renders_source_sink_recovery_for_joern_finding(self) -> None:
        f = _joern_finding()
        text = _structural_evidence_for_finding(f)
        assert "Source: data.get('address')" in text
        assert "(at app/views.py:41)" in text
        assert "Sink: Popen(cmd, shell=True, stdin=PIPE)" in text
        assert "Sink API: Popen" in text
        assert "Sink location: app/views.py:100" in text
        assert "recovery_kind=taint" in text
        assert "kinds_seen=taint" in text

    def test_includes_alt_sources_only_for_distinct_strings(self) -> None:
        f = _joern_finding(
            dedup_sources=[
                "data.get('address')",
                "request.POST.get('address')",
                "form.cleaned_data['address']",
                "data.get('address')",
            ],
            dedup_count=4,
        )
        text = _structural_evidence_for_finding(f)
        assert "Source: data.get('address')" in text
        assert "Alt source: request.POST.get('address')" in text
        assert "Alt source: form.cleaned_data['address']" in text
        # Duplicate of the canonical source must not be re-emitted.
        assert text.count("data.get('address')") == 1
        assert "dedup_count=4" in text

    def test_alt_sources_capped(self) -> None:
        many = [f"src_{i}" for i in range(_STRUCTURAL_EVIDENCE_ALT_SOURCES_CAP + 5)]
        f = _joern_finding(source_code="canonical", dedup_sources=["canonical", *many])
        text = _structural_evidence_for_finding(f)
        emitted = sum(1 for line in text.splitlines() if line.startswith("Alt source:"))
        assert emitted == _STRUCTURAL_EVIDENCE_ALT_SOURCES_CAP

    def test_empty_metadata_returns_empty_string(self) -> None:
        f = Finding(
            file_path="x.py",
            line_start=1,
            line_end=1,
            rule_id="semgrep-cwe78",
            message="",
            code_snippet="os.system('ls')",
            surrounding_context="os.system('ls')",
        )
        assert _structural_evidence_for_finding(f) == ""

    def test_unknown_metadata_types_are_tolerated(self) -> None:
        f = _joern_finding()
        f.metadata["dedup_sources"] = "this should be a list"  # type: ignore[assignment]
        f.metadata["recovery_kinds_seen"] = None  # type: ignore[assignment]
        f.metadata["sinkLine"] = "not-an-int"
        text = _structural_evidence_for_finding(f)
        assert "Source: data.get('address')" in text
        assert "recovery_kind=taint" in text
        # No exception means the helper is robust.

    def test_missing_or_negative_source_line_omits_at_loc(self) -> None:
        f = _joern_finding(source_line=-1, source_file="")
        text = _structural_evidence_for_finding(f)
        assert "Source: data.get('address')" in text
        assert "(at " not in text

    def test_long_fields_are_truncated(self) -> None:
        long_src = "x" * 5_000
        f = _joern_finding(source_code=long_src)
        text = _structural_evidence_for_finding(f)
        # _truncate_evidence_field caps the *field* content (not the
        # whole line) at 240 chars, replacing the tail with "...".
        # The full "Source: ... (at <loc>)" line therefore stays under a
        # comfortably small bound and the literal long_src never appears.
        assert long_src not in text
        assert "..." in text
        for line in text.splitlines():
            if line.startswith("Source: "):
                assert len(line) < 320

    def test_truncate_evidence_field_handles_none_and_short(self) -> None:
        assert _truncate_evidence_field(None) == ""
        assert _truncate_evidence_field("short") == "short"
        assert _truncate_evidence_field("x" * 1000, cap=20).endswith("...")
        assert len(_truncate_evidence_field("x" * 1000, cap=20)) == 20


class TestStructuralEvidenceMap:
    def test_only_findings_with_metadata_are_emitted(self) -> None:
        joern = _joern_finding()
        plain = Finding(
            file_path="lib/util.py",
            line_start=12,
            line_end=12,
            rule_id="semgrep-cwe78",
            message="",
            code_snippet="os.system('ls')",
            surrounding_context="os.system('ls')",
        )
        m = _build_structural_evidence_map([joern, plain])
        assert 0 in m
        assert 1 not in m
        assert "Source: data.get('address')" in m[0]

    def test_indices_are_stable_with_skips(self) -> None:
        a = _joern_finding(file_path="a.py", line=10)
        b = Finding(
            file_path="b.py",
            line_start=20,
            line_end=20,
            rule_id="semgrep-cwe78",
            message="",
            code_snippet="",
            surrounding_context="",
        )
        c = _joern_finding(file_path="c.py", line=30, source_code="argv0")
        m = _build_structural_evidence_map([a, b, c])
        assert set(m.keys()) == {0, 2}
        assert "Source: data.get('address')" in m[0]
        assert "Source: argv0" in m[2]

    def test_evidence_is_persisted_into_metadata(self) -> None:
        """Scorer + serializer rebuild the brake haystack from
        ``f.metadata['structural_evidence']``.  The map builder must
        therefore stamp the rendered evidence back onto the finding so
        the scorer agrees with the triage agent.
        """
        f = _joern_finding()
        m = _build_structural_evidence_map([f])
        assert m[0] == f.metadata["structural_evidence"]
        assert "Source: data.get('address')" in f.metadata["structural_evidence"]

    def test_evidence_is_not_persisted_for_metadata_less_findings(self) -> None:
        plain = Finding(
            file_path="lib/util.py",
            line_start=12,
            line_end=12,
            rule_id="semgrep-cwe78",
            message="",
            code_snippet="os.system('ls')",
            surrounding_context="os.system('ls')",
        )
        _build_structural_evidence_map([plain])
        # No structural_evidence key should be added when there is
        # nothing to render.  This keeps Semgrep findings byte-for-byte
        # compatible with the pre-fix serializer.
        assert "structural_evidence" not in plain.metadata


# ---------------------------------------------------------------------------
# Brake-interaction tests (the actual behaviour we are unblocking)
# ---------------------------------------------------------------------------


class TestStructuralEvidenceUnblocksInterproceduralTPs:
    @pytest.mark.asyncio
    async def test_tp_with_caller_source_is_preserved_when_evidence_passed(
        self,
    ) -> None:
        """source_expr lives in metadata.sourceCode (a caller), NOT in the
        ±10-line slice around the sink.  Pre-fix, the brake downgrades to
        UNCERTAIN.  After the fix, evidence_map carries the source verbatim
        and the verdict is preserved.
        """
        finding = _joern_finding()  # surrounding_context shows only the sink site
        # Brake-relevant invariant: source must NOT appear in surrounding_context
        # so that this test exercises the structural-evidence path, not the
        # default snippet path.
        assert "data.get('address')" not in finding.surrounding_context

        llm = _ScriptedLLM(
            [
                {
                    "verdict": "true_positive",
                    "confidence": 0.95,
                    "reasoning": "request -> Popen(shell=True)",
                    "source_expr": "data.get('address')",
                    "sink_expr": "Popen(cmd, shell=True, stdin=PIPE)",
                }
            ]
        )
        agent = TriageAgent(llm)  # type: ignore[arg-type]
        evidence_map = _build_structural_evidence_map([finding])
        [result] = await agent.triage_batch([finding], evidence_map)
        assert result.verdict == Verdict.TRUE_POSITIVE
        assert result.downgrade_reason == ""
        assert result.source_expr == "data.get('address')"

    @pytest.mark.asyncio
    async def test_tp_is_downgraded_without_structural_evidence(self) -> None:
        """Regression guard: same finding, no evidence_map, gets UNCERTAIN.

        This documents the exact bug the wiring fix addresses.  If this
        assertion ever stops holding, the brake itself has been weakened
        and we should investigate before celebrating.
        """
        finding = _joern_finding()
        assert "data.get('address')" not in finding.surrounding_context
        llm = _ScriptedLLM(
            [
                {
                    "verdict": "true_positive",
                    "confidence": 0.95,
                    "reasoning": "request -> Popen(shell=True)",
                    "source_expr": "data.get('address')",
                    "sink_expr": "Popen(cmd, shell=True, stdin=PIPE)",
                }
            ]
        )
        agent = TriageAgent(llm)  # type: ignore[arg-type]
        [result] = await agent.triage_batch([finding])  # no evidence map
        assert result.verdict == Verdict.UNCERTAIN
        assert result.downgrade_reason == "source_expr_not_in_snippet"

    @pytest.mark.asyncio
    async def test_hallucinated_source_still_downgraded_with_evidence(self) -> None:
        """Brake must still fire when the LLM cites a source that is not
        anywhere in snippet OR structural evidence.  Otherwise the wiring
        fix would re-introduce the hallucination problem the brake was
        designed to stop in the first place.
        """
        finding = _joern_finding(source_code="data.get('address')")
        llm = _ScriptedLLM(
            [
                {
                    "verdict": "true_positive",
                    "confidence": 0.9,
                    "reasoning": "argv -> shell",
                    "source_expr": "sys.argv[42]",  # not in snippet OR evidence
                    "sink_expr": "Popen(cmd, shell=True, stdin=PIPE)",
                }
            ]
        )
        agent = TriageAgent(llm)  # type: ignore[arg-type]
        evidence_map = _build_structural_evidence_map([finding])
        assert "sys.argv[42]" not in evidence_map[0]
        [result] = await agent.triage_batch([finding], evidence_map)
        assert result.verdict == Verdict.UNCERTAIN
        assert result.downgrade_reason == "source_expr_not_in_snippet"


# ---------------------------------------------------------------------------
# Fix #2 — non-self-flow source preference (belt-and-suspenders for the
# clean_seed_catalog hygiene fix).  The catalog cleaner already strips
# sink-coloured sources at build time; these tests pin down the runtime
# fallback so the renderer never echoes "Source: <sink>" when a real
# caller-side alternative is available.
# ---------------------------------------------------------------------------


class TestSelfFlowSourcePredicate:
    @pytest.mark.parametrize(
        "candidate,sink_code,sink_api,expected",
        [
            # Direct equality with sink_code is a self-flow.
            ("subprocess.Popen", "subprocess.Popen", "subprocess.Popen", True),
            # Sink api tail token appearing word-bounded in the candidate.
            (
                "Popen(cmd, shell=True)",
                "subprocess.Popen(cmd)",
                "subprocess.Popen",
                True,
            ),
            ("Popen.communicate", "Popen(cmd)", "subprocess.Popen", True),
            ("os.system('ls')", "os.system('ls')", "os.system", True),
            # Empty / None candidate is treated as self-flow so the caller
            # picks an alt.
            ("", "subprocess.Popen", "subprocess.Popen", True),
            ("   ", "subprocess.Popen", "subprocess.Popen", True),
            # Legitimate caller-side sources are NOT self-flow even if
            # they incidentally contain a related word.
            ("request.body", "subprocess.Popen", "subprocess.Popen", False),
            ("data.get('address')", "Popen(cmd)", "subprocess.Popen", False),
            ("os.environ.get('CMD')", "os.system('ls')", "os.system", False),
            # Substring-but-not-word should NOT match (Popen vs Popened).
            ("popened_text", "Popen(cmd)", "subprocess.Popen", False),
        ],
    )
    def test_predicate_matches_documented_cases(
        self, candidate: str, sink_code: str, sink_api: str, expected: bool
    ) -> None:
        assert _is_self_flow_source(candidate, sink_code, sink_api) is expected

    def test_predicate_handles_missing_sink_metadata(self) -> None:
        # No sink data -> only empty candidates count as self-flow.
        assert _is_self_flow_source("", "", "") is True
        assert _is_self_flow_source("data.get('x')", "", "") is False


class TestStructuralEvidenceSelfFlowPreference:
    def test_self_flow_source_replaced_by_alt_when_available(self) -> None:
        """Catalog leak: Joern reports ``Source: subprocess.Popen`` but
        ``dedup_sources`` has a clean caller-side alt.  The renderer
        must promote the clean alt into the canonical Source: slot and
        must NOT re-emit the demoted self-flow as an Alt source.
        """
        f = _joern_finding(
            source_code="Popen(cmd, shell=True)",
            sink_code="Popen(cmd, shell=True, stdin=PIPE)",
            sink_name="subprocess.Popen",
            dedup_sources=[
                "Popen(cmd, shell=True)",  # demoted self-flow
                "request.POST.get('address')",  # promoted to canonical
                "form.cleaned_data['address']",  # legitimate alt
            ],
            dedup_count=3,
        )
        text = _structural_evidence_for_finding(f)
        # Promoted source becomes the canonical "Source:" line.
        assert "Source: request.POST.get('address')" in text
        # Demoted self-flow must NOT appear anywhere — neither as Source
        # nor as Alt source — so the LLM never sees it.
        assert (
            "Popen(cmd, shell=True)" not in text
            or text.count("Popen(cmd, shell=True") == 1
        )  # only allowed in "Sink: Popen(cmd, shell=True, ..."
        # The remaining clean alt is still emitted.
        assert "Alt source: form.cleaned_data['address']" in text

    def test_self_flow_source_kept_when_all_alts_also_self_flow(self) -> None:
        """Pathological catalog: every dedup_sources entry is also
        sink-coloured.  Renderer has no clean alternative; it must
        fall back to the original source rather than producing an
        empty Source: slot or omitting the line.
        """
        f = _joern_finding(
            source_code="Popen(cmd, shell=True)",
            sink_code="Popen(cmd, shell=True, stdin=PIPE)",
            sink_name="subprocess.Popen",
            dedup_sources=[
                "Popen(cmd, shell=True)",
                "subprocess.Popen(other_cmd)",
                "Popen.communicate()",
            ],
            dedup_count=3,
        )
        text = _structural_evidence_for_finding(f)
        assert "Source: Popen(cmd, shell=True)" in text

    def test_alts_unchanged_when_canonical_source_is_already_clean(self) -> None:
        """Default-path regression guard: when src_code is a legitimate
        caller-side source, Fix #2 must not touch anything — the rendered
        block must be byte-for-byte identical to the pre-fix output.
        """
        f = _joern_finding(
            source_code="data.get('address')",
            dedup_sources=[
                "data.get('address')",
                "request.POST.get('address')",
                "form.cleaned_data['address']",
            ],
            dedup_count=3,
        )
        text = _structural_evidence_for_finding(f)
        assert "Source: data.get('address')" in text
        assert "Alt source: request.POST.get('address')" in text
        assert "Alt source: form.cleaned_data['address']" in text

    def test_self_flow_promotion_skips_other_self_flow_alts(self) -> None:
        """Mixed alt list: first alt is also self-flow, second is clean.
        Renderer must skip the self-flow alt and pick the clean one.
        """
        f = _joern_finding(
            source_code="Popen(...)",
            sink_code="Popen(cmd, shell=True)",
            sink_name="subprocess.Popen",
            dedup_sources=[
                "Popen(...)",  # demoted (self-flow with sink_api tail)
                "subprocess.Popen(other)",  # also self-flow, must be skipped
                "request.body",  # promoted
            ],
            dedup_count=3,
        )
        text = _structural_evidence_for_finding(f)
        assert "Source: request.body" in text
        # The non-promoted self-flow alt is still legitimately a "different"
        # source from the canonical chosen one, so it CAN appear under
        # Alt source.  The contract is only that the original demoted
        # source is suppressed; downstream alts are kept as-is.

    def test_self_flow_promotion_with_no_alts_keeps_original(self) -> None:
        """No dedup_sources at all (Joern direct-sink scan).  Original
        self-flow source is kept; renderer does not crash.
        """
        f = _joern_finding(
            source_code="Popen(cmd, shell=True)",
            sink_code="Popen(cmd, shell=True, stdin=PIPE)",
            sink_name="subprocess.Popen",
            dedup_sources=[],
            dedup_count=1,
        )
        text = _structural_evidence_for_finding(f)
        assert "Source: Popen(cmd, shell=True)" in text
