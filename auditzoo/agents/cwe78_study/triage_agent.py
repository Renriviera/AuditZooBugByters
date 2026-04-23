"""LLM Call 2 — Finding triage (shared across both arms).

Classifies each static-analysis finding as true_positive, false_positive,
or uncertain based on code context and structural evidence.

Also applies two hallucination brakes before returning a verdict:

1. If the LLM commits to ``true_positive`` but the ``source_expr`` it
   cites is missing or is not a literal substring of the snippet (the
   finding's ``surrounding_context`` or ``code_snippet``), the verdict
   is downgraded to ``uncertain`` and ``downgrade_reason`` is set so
   the audit pipeline can count this separately.
2. If the LLM commits to ``false_positive`` but the ``sink_expr`` it
   cites is missing or is not a literal substring of the snippet, the
   verdict is preserved (an FP is a no-op for scoring) but
   ``downgrade_reason`` is set to ``"sink_expr_not_in_snippet"``, so
   the audit can still flag low-quality negation evidence.
"""

from __future__ import annotations

import logging
from typing import Any

from .llm_client import LLMClient
from .prompts import SYSTEM_PROMPT_B_TRIAGE, build_user_prompt_call2
from .schemas import Finding, TriageResult, Verdict

logger = logging.getLogger(__name__)


def _snippet_text(finding: Finding, structural_evidence: str = "") -> str:
    """Return the text the LLM's ``source_expr`` / ``sink_expr`` must quote.

    We deliberately include structural evidence: Joern findings often
    carry the source expression in ``structural_evidence`` (taint-flow
    dump) rather than in the ±10-line snippet.
    """
    parts = [
        finding.surrounding_context or "",
        finding.code_snippet or "",
        structural_evidence or "",
    ]
    return "\n".join(p for p in parts if p)


def _substring_ok(needle: str, haystack: str) -> bool:
    """Return True iff *needle* is a non-trivial literal substring of *haystack*.

    Empty needles and pure whitespace needles are treated as absent.  A
    2-character minimum avoids trivially-matching single tokens like
    ``"x"``; real source/sink expressions in CWE-78 are always longer.
    """
    n = (needle or "").strip()
    if len(n) < 2:
        return False
    return n in (haystack or "")


class TriageAgent:
    """LLM Call 2: classify findings for both Semgrep and Joern arms."""

    def __init__(self, llm: LLMClient) -> None:
        self._llm = llm

    async def triage(self, finding: Finding, structural_evidence: str = "") -> TriageResult:
        """Classify a single finding via LLM."""
        user_prompt = build_user_prompt_call2(
            file_path=finding.file_path,
            line_number=finding.line_start,
            rule_or_query=finding.rule_id,
            code_snippet=finding.surrounding_context or finding.code_snippet,
            structural_evidence=structural_evidence,
        )
        try:
            data = await self._llm.chat_json(SYSTEM_PROMPT_B_TRIAGE, user_prompt)
        except (ValueError, Exception) as exc:
            logger.warning("Triage LLM call failed for %s:%d — %s", finding.file_path, finding.line_start, exc)
            return TriageResult(
                verdict=Verdict.UNCERTAIN, confidence=0.0, reasoning=str(exc)
            )

        verdict_str = str(data.get("verdict", "uncertain")).lower()
        try:
            verdict = Verdict(verdict_str)
        except ValueError:
            verdict = Verdict.UNCERTAIN

        source_expr = str(data.get("source_expr", "") or "")
        sink_expr = str(data.get("sink_expr", "") or "")
        snippet = _snippet_text(finding, structural_evidence)

        downgrade_reason = ""

        # Brake 1: hallucinated TP source. TP requires the LLM to cite a
        # source expression that is *actually present* in the snippet we
        # gave it.  Anything else is a TP on evidence the LLM invented,
        # which was ~100% of the TPs in the 20260421_123649 sweep.
        if verdict == Verdict.TRUE_POSITIVE and not _substring_ok(source_expr, snippet):
            downgrade_reason = "source_expr_not_in_snippet"
            verdict = Verdict.UNCERTAIN

        # Brake 2: FP with a hallucinated sink_expr.  We preserve the FP
        # (downgrading it to UNCERTAIN would re-inflate the UNCERTAIN
        # bucket we're trying to ground) but flag the low-quality
        # negation evidence so ``label_findings`` / audit tooling can
        # separate "LLM suppressed with real evidence" from "LLM
        # suppressed blind".
        elif verdict == Verdict.FALSE_POSITIVE and not _substring_ok(sink_expr, snippet):
            downgrade_reason = "sink_expr_not_in_snippet"

        try:
            confidence = float(data.get("confidence", 0.5))
        except (TypeError, ValueError):
            confidence = 0.5

        return TriageResult(
            verdict=verdict,
            confidence=confidence,
            reasoning=str(data.get("reasoning", "") or ""),
            suggestion=str(data.get("suggestion", "") or ""),
            source_expr=source_expr,
            sink_expr=sink_expr,
            downgrade_reason=downgrade_reason,
        )

    async def triage_batch(
        self,
        findings: list[Finding],
        structural_evidence_map: dict[int, str] | None = None,
    ) -> list[TriageResult]:
        """Triage a batch of findings sequentially.

        *structural_evidence_map* maps finding index → evidence string.
        """
        evidence = structural_evidence_map or {}
        results: list[TriageResult] = []
        for idx, finding in enumerate(findings):
            result = await self.triage(finding, evidence.get(idx, ""))
            results.append(result)
        return results
