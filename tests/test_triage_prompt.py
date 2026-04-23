"""Unit tests for the redesigned Phase-B3 triage prompt and agent.

Verifies two properties:

1. ``SYSTEM_PROMPT_B_TRIAGE`` contains the explicit CWE-78 decision rules
   (sink allow-list, input taint sources, ``uncertain`` confidence
   threshold) needed to avoid the UNCERTAIN collapse observed in the
   20260419 full run.
2. ``TriageAgent`` faithfully propagates scripted verdicts from a
   stubbed :class:`LLMClient` — i.e. when the LLM reliably labels
   findings TP/FP, the pipeline's verdict histogram is not 100%
   ``UNCERTAIN``.
"""

from __future__ import annotations

import pytest

from auditzoo.agents.cwe78_study.prompts import SYSTEM_PROMPT_B_TRIAGE
from auditzoo.agents.cwe78_study.schemas import Finding, Verdict
from auditzoo.agents.cwe78_study.triage_agent import TriageAgent


class _ScriptedLLM:
    """Minimal drop-in replacement for :class:`LLMClient` for tests."""

    def __init__(self, scripted: list[dict]) -> None:
        self._scripted = list(scripted)
        self.calls: list[tuple[str, str]] = []

    async def chat_json(self, system_prompt: str, user_prompt: str):
        self.calls.append((system_prompt, user_prompt))
        if not self._scripted:
            raise RuntimeError("ScriptedLLM ran out of responses")
        return self._scripted.pop(0)


def _mk_finding(path: str, line: int, rule_id: str = "cwe78") -> Finding:
    return Finding(
        file_path=path,
        line_start=line,
        line_end=line,
        rule_id=rule_id,
        message="demo",
        code_snippet="os.system(user_input)",
        surrounding_context="user_input = request.args['cmd']\nos.system(user_input)",
    )


class TestTriagePromptStructure:
    def test_prompt_mentions_os_level_sinks(self) -> None:
        for sink in ("os.system", "subprocess", "shell=True", "shlex.quote"):
            assert sink in SYSTEM_PROMPT_B_TRIAGE, (
                f"Expected decision rule to reference {sink!r} so the LLM "
                f"can commit to a decisive verdict"
            )

    def test_prompt_mentions_taint_sources(self) -> None:
        for src in ("argv", "request", "os.environ", "stdin"):
            assert src in SYSTEM_PROMPT_B_TRIAGE, (
                f"Expected decision rule to reference taint source {src!r}"
            )

    def test_prompt_grounds_uncertain_in_source_visibility(self) -> None:
        """UNCERTAIN is now tied to evidence visibility, not a confidence floor.

        This replaces the earlier ``confidence < 0.4`` gate, which the
        20260421_123649 sweep showed caused the opposite failure mode:
        100% TRUE_POSITIVE collapse with 0 UNCERTAIN.  The new rule 3
        makes UNCERTAIN the routine verdict whenever the source of the
        value reaching the sink is not visible in the snippet.
        """
        text = SYSTEM_PROMPT_B_TRIAGE.lower()
        assert "uncertain" in text
        assert "source" in text and "visible" in text, (
            "Prompt must ground UNCERTAIN in whether the attacker-"
            "controlled source is visible in the snippet"
        )
        assert "do not guess" in text or "do not guess a source" in text, (
            "Prompt must explicitly forbid guessing a missing source"
        )

    def test_prompt_requires_verbatim_source_and_sink_for_tp(self) -> None:
        text = SYSTEM_PROMPT_B_TRIAGE.lower()
        assert "verbatim" in text, (
            "Prompt must require verbatim substrings from the snippet"
        )
        for field in ("source_expr", "sink_expr"):
            assert field in SYSTEM_PROMPT_B_TRIAGE, (
                f"Prompt must request a {field} field from the LLM JSON response"
            )


class TestTriageAgentVerdictPropagation:
    @pytest.mark.asyncio
    async def test_scripted_verdicts_are_not_all_uncertain(self) -> None:
        # source_expr / sink_expr are both literal substrings of
        # _mk_finding's surrounding_context, so the TP hallucination
        # brake must NOT fire here.  This isolates the original
        # verdict-propagation property from the new evidence brake.
        llm = _ScriptedLLM([
            {"verdict": "true_positive",  "confidence": 0.9,
             "reasoning": "argv -> os.system",
             "source_expr": "request.args['cmd']",
             "sink_expr": "os.system(user_input)"},
            {"verdict": "false_positive", "confidence": 0.8,
             "reasoning": "literal arg",
             "sink_expr": "os.system(user_input)"},
            {"verdict": "true_positive",  "confidence": 0.7,
             "reasoning": "request.args -> shell",
             "source_expr": "request.args['cmd']",
             "sink_expr": "os.system(user_input)"},
            {"verdict": "false_positive", "confidence": 0.9,
             "reasoning": "shlex.quote used",
             "sink_expr": "os.system(user_input)"},
        ])
        agent = TriageAgent(llm)  # type: ignore[arg-type]
        findings = [
            _mk_finding("a.py", 10), _mk_finding("b.py", 20),
            _mk_finding("c.py", 30), _mk_finding("d.py", 40),
        ]
        results = await agent.triage_batch(findings)

        verdicts = [r.verdict for r in results]
        assert Verdict.TRUE_POSITIVE in verdicts
        assert Verdict.FALSE_POSITIVE in verdicts
        uncertain_frac = (
            sum(1 for v in verdicts if v == Verdict.UNCERTAIN) / len(verdicts)
        )
        assert uncertain_frac < 1.0, (
            "TriageAgent dropped all scripted TP/FP verdicts to UNCERTAIN — "
            "the verdict-propagation path is broken."
        )

    @pytest.mark.asyncio
    async def test_tp_with_missing_source_expr_is_downgraded(self) -> None:
        """Hallucination brake: TP with empty source_expr → UNCERTAIN."""
        llm = _ScriptedLLM([
            {"verdict": "true_positive", "confidence": 0.95,
             "reasoning": "looks bad",
             "source_expr": "",  # agent can't verify
             "sink_expr": "os.system(user_input)"},
        ])
        agent = TriageAgent(llm)  # type: ignore[arg-type]
        [result] = await agent.triage_batch([_mk_finding("x.py", 1)])
        assert result.verdict == Verdict.UNCERTAIN
        assert result.downgrade_reason == "source_expr_not_in_snippet"

    @pytest.mark.asyncio
    async def test_tp_with_hallucinated_source_expr_is_downgraded(self) -> None:
        """Hallucination brake: TP whose source_expr is not in snippet → UNCERTAIN."""
        llm = _ScriptedLLM([
            {"verdict": "true_positive", "confidence": 0.9,
             "reasoning": "argv -> os.system",
             "source_expr": "sys.argv[1]",  # NOT in snippet
             "sink_expr": "os.system(user_input)"},
        ])
        agent = TriageAgent(llm)  # type: ignore[arg-type]
        [result] = await agent.triage_batch([_mk_finding("x.py", 1)])
        assert result.verdict == Verdict.UNCERTAIN
        assert result.downgrade_reason == "source_expr_not_in_snippet"
        assert result.source_expr == "sys.argv[1]"  # preserved for audit

    @pytest.mark.asyncio
    async def test_fp_with_missing_sink_expr_is_preserved_but_tagged(self) -> None:
        """Parallel brake: FP with blank sink_expr stays FP but is flagged."""
        llm = _ScriptedLLM([
            {"verdict": "false_positive", "confidence": 0.9,
             "reasoning": "no evidence",
             "sink_expr": ""},
        ])
        agent = TriageAgent(llm)  # type: ignore[arg-type]
        [result] = await agent.triage_batch([_mk_finding("x.py", 1)])
        assert result.verdict == Verdict.FALSE_POSITIVE
        assert result.downgrade_reason == "sink_expr_not_in_snippet"

    @pytest.mark.asyncio
    async def test_malformed_verdict_falls_back_to_uncertain(self) -> None:
        llm = _ScriptedLLM([
            {"verdict": "definitely_a_bug", "confidence": 0.9, "reasoning": "..."},
        ])
        agent = TriageAgent(llm)  # type: ignore[arg-type]
        [result] = await agent.triage_batch([_mk_finding("x.py", 1)])
        assert result.verdict == Verdict.UNCERTAIN

    @pytest.mark.asyncio
    async def test_llm_error_falls_back_to_uncertain_zero_confidence(self) -> None:
        class _Raiser:
            async def chat_json(self, *_a, **_kw):
                raise RuntimeError("boom")

        agent = TriageAgent(_Raiser())  # type: ignore[arg-type]
        [result] = await agent.triage_batch([_mk_finding("x.py", 1)])
        assert result.verdict == Verdict.UNCERTAIN
        assert result.confidence == 0.0
