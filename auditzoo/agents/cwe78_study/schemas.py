"""Data models for the CWE-78 two-arm comparative study."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ToolArm(str, Enum):
    SEMGREP = "semgrep"
    JOERN = "joern"


class Verdict(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    UNCERTAIN = "uncertain"


class RefinementAction(str, Enum):
    KEEP = "keep"
    REFINE = "refine"
    ADD_RULE = "add_rule"


class HelperRole(str, Enum):
    SOURCE_WRAPPER = "source-wrapper"
    SINK_WRAPPER = "sink-wrapper"
    TRANSFORMER = "transformer"
    SANITIZER = "sanitizer"
    UNRELATED = "unrelated"


@dataclass
class Finding:
    """A single static-analysis finding from either arm."""

    file_path: str
    line_start: int
    line_end: int
    rule_id: str
    message: str
    code_snippet: str = ""
    surrounding_context: str = ""
    sink_api: str = ""
    arm: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class TaintFlow:
    """A single taint flow from Joern."""

    source: str
    sink: str
    path_nodes: list[str] = field(default_factory=list)
    path_length: int = 0


@dataclass
class FindingWithContext(Finding):
    """Finding enriched with triage-relevant context."""

    taint_flows: list[TaintFlow] = field(default_factory=list)
    call_graph_neighbors: list[str] = field(default_factory=list)


@dataclass
class TriageResult:
    """LLM Call 2 output: verdict on a single finding."""

    verdict: Verdict
    confidence: float
    reasoning: str
    suggestion: str = ""


@dataclass
class SemgrepRefinement:
    """LLM Call 1 output for the Semgrep arm."""

    action: RefinementAction
    rule_yaml: str = ""
    target_rule_id: str = ""


@dataclass
class JoernHelperClassification:
    """LLM Call 1 output for the Joern arm."""

    classifications: dict[str, HelperRole] = field(default_factory=dict)


@dataclass
class IterationResult:
    """Results from one iteration (one value of k) of one arm."""

    arm: ToolArm
    iteration: int
    findings: list[Finding] = field(default_factory=list)
    triage_results: list[TriageResult] = field(default_factory=list)
    refinement_actions: list[Any] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)


@dataclass
class RunResult:
    """Full results for one target repository across all iterations and arms."""

    repo_path: str
    cve_id: str = ""
    commit_sha: str = ""
    iterations: list[IterationResult] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
