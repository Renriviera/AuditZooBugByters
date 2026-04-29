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


def _string_list(value: Any) -> list[str]:
    """Normalize an LLM JSON field into a de-duplicated list of strings."""
    if value is None:
        return []
    if isinstance(value, str):
        raw_items = [value]
    elif isinstance(value, list):
        raw_items = value
    else:
        return []

    out: list[str] = []
    seen: set[str] = set()
    for item in raw_items:
        text = str(item or "").strip()
        if text and text not in seen:
            out.append(text)
            seen.add(text)
    return out


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "disable"}
    return bool(value)


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
            data = await self._llm.chat_json(SYSTEM_PROMPT_A_SEMGREP, user_prompt)
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
        add_source_patterns = _string_list(data.get("add_source_patterns"))
        add_sanitizer_patterns = _string_list(data.get("add_sanitizer_patterns"))
        add_pattern_not = _string_list(data.get("add_pattern_not"))
        disable_rule = _as_bool(data.get("disable_rule", False))
        rationale = str(data.get("rationale", "") or "").strip()

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
            add_source_patterns=add_source_patterns,
            add_sanitizer_patterns=add_sanitizer_patterns,
            add_pattern_not=add_pattern_not,
            disable_rule=disable_rule,
            rationale=rationale,
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
        """Classify call-graph neighbors for taint-spec expansion.

        v2 schema: the LLM is asked to return ``classifications``,
        ``evidence``, and ``confidence``.  Older models (or transient
        truncated responses) may emit only ``classifications`` — we treat
        ``evidence``/``confidence`` as optional and ignore parse errors on
        those fields rather than dropping the whole call.
        """
        user_prompt = build_user_prompt_call1_joern(
            call_graph_neighborhood=call_graph_neighborhood,
            current_sources=current_sources,
            current_sinks=current_sinks,
            current_sanitizers=current_sanitizers,
        )
        try:
            data = await self._llm.chat_json(SYSTEM_PROMPT_A_JOERN, user_prompt)
        except (ValueError, Exception) as exc:
            logger.warning("Joern helper-ID LLM call failed: %s", exc)
            return JoernHelperClassification()

        raw_classes = data.get("classifications", {}) if isinstance(data, dict) else {}
        if not isinstance(raw_classes, dict):
            raw_classes = {}
        classifications: dict[str, HelperRole] = {}
        for func_name, role_str in raw_classes.items():
            try:
                classifications[str(func_name)] = HelperRole(str(role_str))
            except ValueError:
                classifications[str(func_name)] = HelperRole.UNRELATED

        raw_evidence = data.get("evidence", {}) if isinstance(data, dict) else {}
        evidence: dict[str, dict[str, Any]] = {}
        if isinstance(raw_evidence, dict):
            for func_name, payload in raw_evidence.items():
                if not isinstance(payload, dict):
                    continue
                quote = str(payload.get("quote", "") or "")
                file_ = str(payload.get("file", "") or "")
                line_raw = payload.get("line", 0) or 0
                try:
                    line = int(line_raw)
                except (TypeError, ValueError):
                    line = 0
                evidence[str(func_name)] = {
                    "quote": quote[:500],
                    "file": file_,
                    "line": line,
                }

        raw_confidence = data.get("confidence", {}) if isinstance(data, dict) else {}
        confidence: dict[str, float] = {}
        if isinstance(raw_confidence, dict):
            for func_name, value in raw_confidence.items():
                try:
                    conf = float(value)
                except (TypeError, ValueError):
                    continue
                confidence[str(func_name)] = max(0.0, min(1.0, conf))

        return JoernHelperClassification(
            classifications=classifications,
            evidence=evidence,
            confidence=confidence,
        )
