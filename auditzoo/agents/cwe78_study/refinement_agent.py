"""LLM Call 1 — Rule refinement (Semgrep) / Helper identification (Joern).

Shared logic with tool-specific system prompts and output schemas.
"""

from __future__ import annotations

import logging
from typing import Any

import yaml

from .llm_client import LLMClient
from .prompts import (
    SYSTEM_PROMPT_A_JOERN,
    SYSTEM_PROMPT_A_SEMGREP,
    build_user_prompt_call1_joern,
    build_user_prompt_call1_semgrep,
)
from .schemas import (
    HelperRole,
    JoernHelperClassification,
    RefinementAction,
    SemgrepRefinement,
)


def _extract_rule_id(rule_yaml: str) -> str:
    """Best-effort extraction of the ``id:`` field from a rule YAML patch.

    Used to back-fill ``target_rule_id`` when the LLM forgot to emit it
    but did include a valid rule body in ``rule_yaml``.  Returns an empty
    string on any parsing failure.
    """
    if not (rule_yaml or "").strip():
        return ""
    try:
        loaded = yaml.safe_load(rule_yaml)
    except yaml.YAMLError:
        return ""
    if isinstance(loaded, dict) and "rules" in loaded:
        rules = loaded.get("rules") or []
        loaded = rules[0] if rules else None
    elif isinstance(loaded, list):
        loaded = loaded[0] if loaded else None
    if isinstance(loaded, dict):
        return str(loaded.get("id", "") or "")
    return ""

logger = logging.getLogger(__name__)


class RefinementAgent:
    """LLM Call 1 for both arms.

    * **Semgrep mode**: evaluates findings + triage feedback, proposes
      keep / refine / add_rule actions with updated YAML.
    * **Joern mode**: classifies call-graph neighbors as source-wrapper,
      sink-wrapper, transformer, sanitizer, or unrelated.
    """

    def __init__(self, llm: LLMClient) -> None:
        self._llm = llm

    # ------------------------------------------------------------------
    # Semgrep refinement
    # ------------------------------------------------------------------

    async def refine_semgrep(
        self,
        *,
        rule_yaml: str,
        file_path: str,
        line_number: int,
        code_snippet: str,
        triage_summary: dict[str, int],
        common_fp_pattern: str = "",
    ) -> SemgrepRefinement:
        """Ask the LLM to evaluate a Semgrep rule and suggest refinement."""
        user_prompt = build_user_prompt_call1_semgrep(
            rule_yaml=rule_yaml,
            file_path=file_path,
            line_number=line_number,
            code_snippet=code_snippet,
            triage_summary=triage_summary,
            common_fp_pattern=common_fp_pattern,
        )
        try:
            data = await self._llm.chat_json(
                SYSTEM_PROMPT_A_SEMGREP, user_prompt
            )
        except (ValueError, Exception) as exc:
            logger.warning("Semgrep refinement LLM call failed: %s", exc)
            return SemgrepRefinement(action=RefinementAction.KEEP)

        action_str = str(data.get("action", "keep")).lower()
        try:
            action = RefinementAction(action_str)
        except ValueError:
            action = RefinementAction.KEEP

        rule_yaml = str(data.get("rule_yaml", "") or "")
        target_rule_id = str(data.get("target_rule_id", "") or "").strip()

        # Back-fill ``target_rule_id`` from the YAML patch when the LLM
        # emits action=refine with a valid rule body but forgets the id.
        # The 20260422 sweep showed this happens in 100 % of refine calls,
        # which silently no-ops ``SemgrepArm.apply_refinement`` and makes
        # the k-loop cosmetic.
        if action == RefinementAction.REFINE and not target_rule_id:
            target_rule_id = _extract_rule_id(rule_yaml)
            if target_rule_id:
                logger.info(
                    "refine_semgrep: back-filled target_rule_id=%r "
                    "from rule_yaml (LLM omitted it)",
                    target_rule_id,
                )

        return SemgrepRefinement(
            action=action,
            rule_yaml=rule_yaml,
            target_rule_id=target_rule_id,
        )

    # ------------------------------------------------------------------
    # Joern helper identification
    # ------------------------------------------------------------------

    async def classify_helpers_joern(
        self,
        *,
        call_graph_neighborhood: list[dict[str, Any]],
        current_sources: list[str],
        current_sinks: list[str],
        current_sanitizers: list[str],
    ) -> JoernHelperClassification:
        """Classify call-graph neighbors for taint-spec expansion."""
        user_prompt = build_user_prompt_call1_joern(
            call_graph_neighborhood=call_graph_neighborhood,
            current_sources=current_sources,
            current_sinks=current_sinks,
            current_sanitizers=current_sanitizers,
        )
        try:
            data = await self._llm.chat_json(
                SYSTEM_PROMPT_A_JOERN, user_prompt
            )
        except (ValueError, Exception) as exc:
            logger.warning("Joern helper-ID LLM call failed: %s", exc)
            return JoernHelperClassification()

        raw_classes = data.get("classifications", {})
        classifications: dict[str, HelperRole] = {}
        for func_name, role_str in raw_classes.items():
            try:
                classifications[func_name] = HelperRole(role_str)
            except ValueError:
                classifications[func_name] = HelperRole.UNRELATED

        raw_evidence = data.get("evidence") or {}
        evidence: dict[str, str] = {}
        if isinstance(raw_evidence, dict):
            for func_name, value in raw_evidence.items():
                # Coerce to str defensively; the prompt asks for short
                # verbatim substrings but malformed LLM output should
                # not crash refinement.
                evidence[str(func_name)] = (
                    "" if value is None else str(value)
                )

        return JoernHelperClassification(
            classifications=classifications,
            evidence=evidence,
        )
