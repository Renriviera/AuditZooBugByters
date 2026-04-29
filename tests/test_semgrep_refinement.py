"""Tests for the Semgrep refinement path.

These tests pin down two behaviours whose regression would silently
restore the 20260422 k-invariance bug:

1. ``SemgrepArm.apply_refinement`` must return a status code and actually
   mutate ``rules_yaml`` when given a valid patch, even when the LLM
   omits ``target_rule_id``.
2. ``RefinementAgent.refine_semgrep`` must back-fill ``target_rule_id``
   from the patch's ``id:`` field when the LLM forgets it — which was
   the case in 100 % of refine actions in the 20260422 sweep.

We use a scripted LLM so the tests are hermetic (no network calls).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
import yaml

from auditzoo.agents.cwe78_study.refinement_agent import (
    RefinementAgent,
    _extract_rule_id,
)
from auditzoo.agents.cwe78_study.schemas import RefinementAction
from auditzoo.agents.cwe78_study.semgrep_arm import SemgrepArm

_SEED_YAML = """\
rules:
  - id: cwe78-os-system
    patterns:
      - pattern: os.system($ARG)
    message: "os.system call"
    languages: [python]
    severity: ERROR
    metadata:
      cwe: "CWE-78"
      sink_api: "os.system"
"""

_PATCH_REFINE = """\
- id: cwe78-os-system
  patterns:
    - pattern: os.system($ARG)
    - pattern-not: os.system("...")
  message: "os.system with pattern-not for literals"
  languages: [python]
  severity: ERROR
  metadata:
    cwe: "CWE-78"
    sink_api: "os.system"
"""

_PATCH_NEW = """\
- id: cwe78-os-execvp
  patterns:
    - pattern: os.execvp($ARG, ...)
  message: "os.execvp call"
  languages: [python]
  severity: ERROR
  metadata:
    cwe: "CWE-78"
    sink_api: "os.execvp"
"""


class TestApplyRefinement:
    """Direct unit tests for ``SemgrepArm.apply_refinement``."""

    def test_keep_is_noop(self) -> None:
        arm = SemgrepArm(rules_yaml=_SEED_YAML)
        before = arm.rules_yaml
        status = arm.apply_refinement("keep", "", "")
        assert status == "keep"
        assert arm.rules_yaml == before, "keep must not mutate the YAML"

    def test_refine_with_explicit_target_replaces_rule(self) -> None:
        arm = SemgrepArm(rules_yaml=_SEED_YAML)
        status = arm.apply_refinement(
            "refine", _PATCH_REFINE, target_rule_id="cwe78-os-system"
        )
        assert status == "refine_replaced"
        loaded = yaml.safe_load(arm.rules_yaml)
        rules = loaded["rules"]
        assert len(rules) == 1, "refine must not change rule count"
        rule = rules[0]
        assert rule["id"] == "cwe78-os-system"
        patterns = rule["patterns"]
        assert any(
            "pattern-not" in p for p in patterns
        ), "patched rule must include the new pattern-not"

    def test_refine_without_target_recovers_id_from_patch(self) -> None:
        """The 20260422 regression: LLM emits refine+valid_yaml+empty target."""
        arm = SemgrepArm(rules_yaml=_SEED_YAML)
        before = arm.rules_yaml
        status = arm.apply_refinement("refine", _PATCH_REFINE, target_rule_id="")
        assert (
            status == "refine_replaced"
        ), "empty target_rule_id must be recovered from the patch's id:"
        assert (
            arm.rules_yaml != before
        ), "rules_yaml must actually change when the patch modifies the rule"
        loaded = yaml.safe_load(arm.rules_yaml)
        assert len(loaded["rules"]) == 1
        assert any("pattern-not" in p for p in loaded["rules"][0]["patterns"])

    def test_refine_with_unknown_id_appends_as_add_rule(self) -> None:
        arm = SemgrepArm(rules_yaml=_SEED_YAML)
        status = arm.apply_refinement("refine", _PATCH_NEW, target_rule_id="")
        assert status == "refine_appended", (
            "a refine against an id that isn't in the seed must fall "
            "through to append, not silently drop"
        )
        loaded = yaml.safe_load(arm.rules_yaml)
        ids = [r["id"] for r in loaded["rules"]]
        assert "cwe78-os-system" in ids
        assert "cwe78-os-execvp" in ids

    def test_add_rule_appends(self) -> None:
        arm = SemgrepArm(rules_yaml=_SEED_YAML)
        status = arm.apply_refinement("add_rule", _PATCH_NEW)
        assert status == "add_rule_appended"
        loaded = yaml.safe_load(arm.rules_yaml)
        ids = {r["id"] for r in loaded["rules"]}
        assert ids == {"cwe78-os-system", "cwe78-os-execvp"}

    def test_empty_patch_is_flagged_noop(self) -> None:
        arm = SemgrepArm(rules_yaml=_SEED_YAML)
        before = arm.rules_yaml
        status = arm.apply_refinement("refine", "", target_rule_id="cwe78-os-system")
        assert status == "noop_empty_patch"
        assert arm.rules_yaml == before, (
            "empty patch must not trigger YAML re-serialisation; otherwise "
            "the cosmetic hash change masquerades as a real mutation"
        )

    def test_patch_shapes(self) -> None:
        """Accept bare rule dict, list of rules, and {rules:[...]} wrappers."""
        shapes = [
            _PATCH_NEW,
            "rules:\n" + _PATCH_NEW,
            "- " + _PATCH_NEW.lstrip("- "),
        ]
        for shape in shapes:
            arm = SemgrepArm(rules_yaml=_SEED_YAML)
            status = arm.apply_refinement("add_rule", shape)
            assert status == "add_rule_appended", shape[:40]


# ---------------------------------------------------------------------------
# RefinementAgent integration
# ---------------------------------------------------------------------------


@dataclass
class _ScriptedLLM:
    """Minimal LLMClient stand-in that returns a preset JSON dict."""

    response: dict[str, Any]

    class _Usage:
        def to_dict(self) -> dict[str, int]:
            return {}

    usage = _Usage()

    async def chat_json(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        return self.response


@pytest.mark.asyncio
async def test_refine_semgrep_backfills_target_rule_id() -> None:
    """LLM says refine+yaml but omits target_rule_id; agent must recover it."""
    llm = _ScriptedLLM(
        response={
            "action": "refine",
            "rule_yaml": _PATCH_REFINE,
            # target_rule_id intentionally missing, mirroring the real
            # 20260422 sweep where 100 % of refine calls had it empty.
        }
    )
    agent = RefinementAgent(llm=llm)
    ref = await agent.refine_semgrep(
        rule_yaml=_SEED_YAML,
        file_path="foo/bar.py",
        line_number=42,
        code_snippet="os.system(x)",
        triage_summary={"tp": 1, "fp": 0, "uncertain": 0},
    )
    assert ref.action == RefinementAction.REFINE
    assert (
        ref.target_rule_id == "cwe78-os-system"
    ), "target_rule_id must be recovered from the patch's id: field"


@pytest.mark.asyncio
async def test_refine_semgrep_preserves_explicit_target_rule_id() -> None:
    llm = _ScriptedLLM(
        response={
            "action": "refine",
            "rule_yaml": _PATCH_REFINE,
            "target_rule_id": "cwe78-os-system",
        }
    )
    agent = RefinementAgent(llm=llm)
    ref = await agent.refine_semgrep(
        rule_yaml=_SEED_YAML,
        file_path="x.py",
        line_number=1,
        code_snippet="os.system(x)",
        triage_summary={"tp": 0, "fp": 1, "uncertain": 0},
    )
    assert ref.target_rule_id == "cwe78-os-system"
    assert ref.action == RefinementAction.REFINE


@pytest.mark.asyncio
async def test_refine_semgrep_parses_structured_taint_edits() -> None:
    llm = _ScriptedLLM(
        response={
            "action": "refine",
            "target_rule_id": "cwe78-os-system",
            "add_source_patterns": [
                "request.query_params.get(...)",
                "request.query_params.get(...)",
            ],
            "add_sanitizer_patterns": "allowlisted_command(...)",
            "rationale": "Add FastAPI and allowlist handling.",
        }
    )
    agent = RefinementAgent(llm=llm)
    ref = await agent.refine_semgrep(
        rule_yaml=_SEED_YAML,
        file_path="x.py",
        line_number=1,
        code_snippet="os.system(x)",
        triage_summary={"tp": 0, "fp": 1, "uncertain": 0},
    )
    assert ref.action == RefinementAction.REFINE
    assert ref.target_rule_id == "cwe78-os-system"
    assert ref.add_source_patterns == ["request.query_params.get(...)"]
    assert ref.add_sanitizer_patterns == ["allowlisted_command(...)"]
    assert ref.rationale == "Add FastAPI and allowlist handling."


def test_apply_structured_source_and_sanitizer_edits() -> None:
    seed = """\
rules:
  - id: cwe78-os-system
    mode: taint
    pattern-sources:
      - pattern: sys.argv
    pattern-sinks:
      - pattern: os.system($CMD)
    pattern-sanitizers:
      - pattern: shlex.quote(...)
    message: os.system taint
    languages: [python]
    severity: ERROR
"""
    arm = SemgrepArm(rules_yaml=seed)
    status = arm.apply_refinement(
        "refine",
        "",
        "cwe78-os-system",
        add_source_patterns=["request.query_params.get(...)"],
        add_sanitizer_patterns=["allowlisted_command(...)"],
    )
    assert status == "structured_sources_added_sanitizers_added"
    loaded = yaml.safe_load(arm.rules_yaml)
    rule = loaded["rules"][0]
    sources = [item["pattern"] for item in rule["pattern-sources"]]
    sanitizers = [item["pattern"] for item in rule["pattern-sanitizers"]]
    assert "request.query_params.get(...)" in sources
    assert "allowlisted_command(...)" in sanitizers


def test_apply_structured_duplicate_is_explicit_noop() -> None:
    seed = """\
rules:
  - id: cwe78-os-system
    mode: taint
    pattern-sources:
      - pattern: sys.argv
    pattern-sinks:
      - pattern: os.system($CMD)
    message: os.system taint
    languages: [python]
    severity: ERROR
"""
    arm = SemgrepArm(rules_yaml=seed)
    before = arm.rules_yaml
    status = arm.apply_refinement(
        "refine", "", "cwe78-os-system", add_source_patterns=["sys.argv"]
    )
    assert status == "noop_duplicate"
    assert arm.rules_yaml == before


def test_extract_rule_id_shapes() -> None:
    assert _extract_rule_id(_PATCH_REFINE) == "cwe78-os-system"
    assert _extract_rule_id("rules:\n" + _PATCH_NEW) == "cwe78-os-execvp"
    assert _extract_rule_id("") == ""
    assert _extract_rule_id("not: valid: yaml:::") == ""
    assert _extract_rule_id("- not_a_rule: true") == ""
