"""LLM Call 2 — Finding triage (shared across both arms).

Classifies each static-analysis finding as true_positive, false_positive,
or uncertain based on code context and structural evidence.
"""

from __future__ import annotations

import logging
from typing import Any

from .llm_client import LLMClient
from .prompts import SYSTEM_PROMPT_B_TRIAGE, build_user_prompt_call2
from .schemas import Finding, TriageResult, Verdict

logger = logging.getLogger(__name__)


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

        verdict_str = data.get("verdict", "uncertain").lower()
        try:
            verdict = Verdict(verdict_str)
        except ValueError:
            verdict = Verdict.UNCERTAIN

        return TriageResult(
            verdict=verdict,
            confidence=float(data.get("confidence", 0.5)),
            reasoning=data.get("reasoning", ""),
            suggestion=data.get("suggestion", ""),
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
