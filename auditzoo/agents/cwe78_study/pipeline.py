"""Two-arm pipeline orchestrator for the CWE-78 comparative study.

Runs Semgrep and/or Joern arms with k=0..max_iterations, applying
LLM Call 1 (refinement/helper ID) and LLM Call 2 (triage) at each step.
Collects per-iteration metrics for downstream evaluation.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Any

from autogen_core import AgentId

from auditzoo.backends.ingestion import auto_detect_backend
from auditzoo.core.protocol.requests import Request
from auditzoo.core.runtime import AnalysisRuntime

from .joern_arm import JoernArm
from .llm_client import LLMClient, LLMConfig
from .prompts import triage_system_prompt
from .refinement_agent import RefinementAgent
from .schemas import (
    Finding,
    HelperRole,
    IterationResult,
    RunResult,
    ToolArm,
    TriageResult,
    Verdict,
)
from .semgrep_arm import SemgrepArm
from .triage_agent import TriageAgent

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------
# Phase-timing helpers
# ----------------------------------------------------------------------

_PHASE_KEYS: tuple[str, ...] = (
    "cpg_build_s",
    "scan_s",
    "llm_triage_s",
    "llm_refinement_s",
    "call_graph_s",
)

_JOERN_LOW_SIGNAL_PATH_MARKERS = (
    "/.github/",
    "/devscripts/",
    "/docs/",
    "/examples/",
    "/test/",
    "/tests/",
    "/third_party/",
    "/vendor/",
    "_test.py",
    "test_",
)
_JOERN_GENERIC_WRAPPERS = {
    "run",
    "call",
    "system",
    "popen",
    "popen2",
    "popen3",
    "popen4",
}
_JOERN_COMMAND_HINTS = (
    "cmd",
    "command",
    "shell",
    "exec",
    "checkout",
    "clone",
    "subprocess",
    "os.system",
)


@contextmanager
def _stopwatch() -> Iterator[list[float]]:
    """Context manager yielding a 1-element list holding elapsed seconds.

    The elapsed time is written into ``holder[0]`` on exit so it can be
    inspected after the ``with`` block.  Using a list keeps the caller code
    readable without relying on closure tricks::

        with _stopwatch() as t:
            ...work...
        scan_s = t[0]
    """
    holder: list[float] = [0.0]
    start = time.perf_counter()
    try:
        yield holder
    finally:
        holder[0] = time.perf_counter() - start


def _llm_tokens_delta(before: dict[str, int], after: dict[str, int]) -> int:
    """Return the total-token delta between two ``LLMUsage.to_dict()`` snapshots."""
    return int(after.get("total_tokens", 0)) - int(before.get("total_tokens", 0))


def _stable_hash(payload: str) -> str:
    """Short, stable SHA-256 prefix for audit fingerprints (not security-critical)."""
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()[:16]


def _findings_hash(findings: list[Finding]) -> str:
    """Hash the sorted ``(file, line, rule_id, sink_api)`` tuples of *findings*.

    Used to quantify whether consecutive k iterations produce identical
    candidate sets (which would prove refinement never moved the needle).
    """
    keys = sorted(
        f"{f.file_path}:{f.line_start}:{f.rule_id}:{f.sink_api}" for f in findings
    )
    return _stable_hash("\n".join(keys))


async def _connect_joern_with_retry(
    backend_cfg: Any,
    *,
    max_retries: int = 1,
    retry_delay_s: float = 5.0,
):
    """Enter :class:`AnalysisRuntime` with one retry on transient errors.

    The full-run log from 20260419_135557 shows 100% of Joern arms failing
    with ``Port localhost:12345 is already in use`` because the previous
    CVE's JVM had not released the port yet.  Retrying once after a short
    pause converts most of those into successful CPG builds; the rest
    surface as an explicit ``cpg_build_failed`` column on the iteration
    instead of silently aggregating to ``tp/fp/fn = 0``.

    Returns ``(runtime_cm, runtime, last_error)`` where ``runtime`` is
    ``None`` on failure.
    """
    last_exc: BaseException | None = None
    runtime_cm: Any = None
    for attempt in range(max_retries + 1):
        runtime_cm = AnalysisRuntime(backend_cfg)
        try:
            runtime = await runtime_cm.__aenter__()
            return runtime_cm, runtime, None
        except Exception as exc:
            last_exc = exc
            logger.warning(
                "Joern CPG connect attempt %d/%d failed: %s",
                attempt + 1,
                max_retries + 1,
                exc,
            )
            try:
                await runtime_cm.stop()
            except Exception:
                logger.exception("Cleanup during Joern retry failed")
            if attempt < max_retries:
                await asyncio.sleep(retry_delay_s)
    return runtime_cm, None, last_exc


def _joern_catalog_snapshot(joern: Any) -> dict[str, list[str]]:
    """Snapshot a :class:`JoernArm`'s source/sink/sanitizer catalogs for audit."""
    return {
        "sources": list(getattr(joern, "sources", []) or []),
        "sinks": list(getattr(joern, "sinks", []) or []),
        "sanitizers": list(getattr(joern, "sanitizers", []) or []),
    }


def _joern_structural_evidence(
    finding: Finding,
    *,
    include_flow_path: bool = False,
) -> str:
    """Render Joern taint metadata into compact triage evidence.

    Joern findings carry source/sink coordinates from the CPG query in
    ``Finding.metadata``.  Passing this to triage lets the LLM verify a
    source-to-sink relationship even when the ±context snippet only shows the
    sink helper body.
    """
    meta = finding.metadata or {}
    source_file = str(meta.get("sourceFile", "") or "")
    source_line = str(meta.get("sourceLine", "") or "")
    source_code = str(meta.get("sourceCode", "") or "")
    sink_file = str(meta.get("sinkFile", "") or "")
    sink_line = str(meta.get("sinkLine", "") or "")
    sink_code = str(meta.get("sinkCode", "") or "")
    sink_name = str(meta.get("sinkName", "") or finding.sink_api or "")
    report_file = str(meta.get("reportFile", "") or "")
    report_line = str(meta.get("reportLine", "") or "")
    report_reason = str(meta.get("reportReason", "") or "")

    rows: list[str] = []
    if report_file or report_line or report_reason:
        rows.append(
            "Joern report location: "
            f"{report_file}:{report_line} "
            f"{report_reason}".strip()
        )
    if source_code or source_file or source_line:
        rows.append(
            "Joern source: " f"{source_file}:{source_line} " f"`{source_code}`".strip()
        )
    if meta.get("originExternalSource"):
        rows.append("Joern origin: external_source_confirmed")
    origin_evidence = meta.get("originEvidence") or []
    if isinstance(origin_evidence, list) and origin_evidence:
        rows.append("Joern origin evidence:")
        for record in origin_evidence[:3]:
            if not isinstance(record, dict):
                continue
            tag = " [external]" if record.get("matchesExternal") else ""
            code = str(record.get("code", "") or "")
            file_path = str(record.get("file", "") or "")
            line = str(record.get("line", "") or "")
            rows.append(f"  {file_path}:{line} `{code}`{tag}")
    caller_chain = meta.get("callerChain") or []
    if isinstance(caller_chain, list) and caller_chain:
        rows.append("Joern caller evidence:")
        for record in caller_chain[:3]:
            if not isinstance(record, dict):
                continue
            tag = " [external]" if record.get("matchesExternal") else ""
            code = str(record.get("code", "") or "")
            arg_code = str(record.get("argumentCode", "") or "")
            file_path = str(record.get("file", "") or "")
            line = str(record.get("line", "") or "")
            if arg_code:
                rows.append(f"  {file_path}:{line} `{code}` arg=`{arg_code}`{tag}")
            else:
                rows.append(f"  {file_path}:{line} `{code}`{tag}")
    if sink_code or sink_file or sink_line or sink_name:
        rows.append(
            "Joern sink: "
            f"{sink_file}:{sink_line} "
            f"{sink_name} "
            f"`{sink_code}`".strip()
        )
    flow_path = meta.get("flowPath") or []
    if include_flow_path and isinstance(flow_path, list) and flow_path:
        rows.append("Joern flow path:")
        for idx, node in enumerate(flow_path[:12], start=1):
            if not isinstance(node, dict):
                continue
            node_file = str(node.get("file", "") or "")
            node_line = str(node.get("line", "") or "")
            node_type = str(node.get("nodeType", "") or "")
            node_code = str(node.get("code", "") or "")
            rows.append(f"  {idx}. {node_file}:{node_line} {node_type} `{node_code}`")
    if source_code and sink_code:
        rows.append(f"Joern taint flow: `{source_code}` -> `{sink_code}`")
    return "\n".join(rows)


def _joern_structural_evidence_map(
    findings: list[Finding],
    *,
    include_flow_path: bool = False,
) -> dict[int, str]:
    """Build the ``TriageAgent.triage_batch`` evidence map for Joern findings."""
    evidence: dict[int, str] = {}
    for idx, finding in enumerate(findings):
        rendered = _joern_structural_evidence(
            finding,
            include_flow_path=include_flow_path,
        )
        if rendered:
            evidence[idx] = rendered
    return evidence


def _joern_path_is_low_signal(path: str) -> bool:
    lowered = f"/{path.lower().lstrip('/')}"
    return any(marker in lowered for marker in _JOERN_LOW_SIGNAL_PATH_MARKERS)


def _joern_flow_has_command_hint(finding: Finding) -> bool:
    meta = finding.metadata or {}
    flow_path = meta.get("flowPath") or []
    snippets = [
        str(meta.get("sourceCode", "") or ""),
        str(meta.get("sinkCode", "") or ""),
        str(meta.get("reportReason", "") or ""),
        finding.code_snippet or "",
    ]
    if isinstance(flow_path, list):
        snippets.extend(
            str(node.get("code", "") or "")
            for node in flow_path
            if isinstance(node, dict)
        )
    text = " ".join(snippets).lower()
    return any(hint in text for hint in _JOERN_COMMAND_HINTS)


def _joern_has_external_caller(finding: Finding) -> bool:
    meta = finding.metadata or {}
    return any(
        isinstance(record, dict) and bool(record.get("matchesExternal"))
        for record in (meta.get("callerChain") or [])
    )


def _is_high_risk_joern(finding: Finding) -> bool:
    meta = finding.metadata or {}
    sink_code = str(meta.get("sinkCode", "") or finding.code_snippet or "").lower()
    return bool(
        meta.get("originExternalSource")
        or _joern_has_external_caller(finding)
        or meta.get("shell_true")
        or meta.get("string_command_like")
        or "shell=true" in sink_code
        or "os.system" in sink_code
        or "os.popen" in sink_code
    )


def _rank_joern_finding(
    finding: Finding,
) -> tuple[int, int, int, int, int, int, str, int]:
    """Return a sortable risk key; lower values are triaged first."""
    meta = finding.metadata or {}
    sink_kind = str(meta.get("sinkKind", "") or "")
    wrapper_name = str(meta.get("wrapperName", "") or finding.sink_api or "").lower()
    source_kind = str(meta.get("sourceKind", "") or "")
    report_reason = str(meta.get("reportReason", "") or "")
    sink_code = str(meta.get("sinkCode", "") or finding.code_snippet or "").lower()
    high_risk_sink = bool(
        meta.get("shell_true")
        or meta.get("string_command_like")
        or "shell=true" in sink_code
        or "os.system" in sink_code
    )
    low_risk_semantics = bool(
        (meta.get("argv_list_like") or meta.get("shlex_split_input"))
        and not meta.get("shell_true")
    )
    low_signal_path = bool(
        meta.get("test_file")
        or _joern_path_is_low_signal(finding.file_path)
        or _joern_path_is_low_signal(str(meta.get("sinkFile", "") or ""))
    )
    generic_wrapper = sink_kind == "wrapper" and wrapper_name in _JOERN_GENERIC_WRAPPERS
    command_hint = _joern_flow_has_command_hint(finding)
    caller_external = _joern_has_external_caller(finding)

    risk = 0 if high_risk_sink else 1
    directness = 0 if sink_kind != "wrapper" else 1
    source_rank = (
        -2
        if meta.get("originExternalSource")
        else (
            -1
            if caller_external
            else {"external": 0, "parameter": 1, "catalog": 2, "attribute": 3}.get(
                source_kind, 4
            )
        )
    )
    report_rank = (
        0
        if report_reason
        in {"flow_command_construction", "flow_non_wrapper_callsite", "flow_callsite"}
        else 1
    )
    semantic_penalty = (
        int(low_risk_semantics)
        + int(low_signal_path)
        + int(generic_wrapper and not high_risk_sink)
    )
    command_rank = 0 if command_hint else 1
    return (
        risk,
        directness,
        semantic_penalty,
        source_rank,
        report_rank,
        command_rank,
        finding.file_path,
        finding.line_start,
    )


def _reduce_joern_findings(
    findings: list[Finding],
    max_candidates: int | None,
    *,
    enabled: bool = True,
    high_risk_cap: int | None = None,
    low_risk_cap: int | None = None,
) -> tuple[list[Finding], dict[str, Any]]:
    """Rank and cap Joern findings before LLM triage.

    Two-budget mode: if either ``high_risk_cap`` or ``low_risk_cap`` is
    supplied, findings are partitioned into high-risk and lower-risk
    groups (see :func:`_is_high_risk_joern`) and each group is independently
    capped.  Unfilled high-risk budget does NOT spill over to lower-risk
    by design — keeping high-risk strictly bounded matches the diagnostic
    intent of "20 high-risk + 10 low-risk".

    Single-cap fallback (both new caps ``None``): preserves the legacy
    behaviour where ``max_candidates`` is the shared budget and lower-risk
    fills any leftover after high-risk.
    """
    raw_count = len(findings)
    two_budget_mode = high_risk_cap is not None or low_risk_cap is not None

    if not enabled:
        return findings, {
            "joern_raw_findings": raw_count,
            "joern_triaged_findings": raw_count,
            "joern_candidates_dropped_before_triage": 0,
            "joern_candidate_reducer_enabled": False,
            "joern_candidate_reducer_cap": max_candidates,
            "joern_dropped_reason_counts": {},
            "joern_high_risk_count": sum(1 for f in findings if _is_high_risk_joern(f)),
            "joern_high_risk_kept": sum(1 for f in findings if _is_high_risk_joern(f)),
            "joern_high_risk_dropped_when_overflow": 0,
            "joern_low_risk_count": sum(
                1 for f in findings if not _is_high_risk_joern(f)
            ),
            "joern_low_risk_kept": sum(
                1 for f in findings if not _is_high_risk_joern(f)
            ),
            "joern_low_risk_dropped_when_overflow": 0,
            "joern_high_risk_cap": high_risk_cap,
            "joern_low_risk_cap": low_risk_cap,
        }

    if two_budget_mode:
        hr_cap = int(high_risk_cap) if high_risk_cap is not None else 0
        lr_cap = int(low_risk_cap) if low_risk_cap is not None else 0
        effective_total_cap = hr_cap + lr_cap
    else:
        if max_candidates is None or max_candidates <= 0:
            return findings, {
                "joern_raw_findings": raw_count,
                "joern_triaged_findings": raw_count,
                "joern_candidates_dropped_before_triage": 0,
                "joern_candidate_reducer_enabled": True,
                "joern_candidate_reducer_cap": max_candidates,
                "joern_dropped_reason_counts": {},
                "joern_high_risk_count": sum(
                    1 for f in findings if _is_high_risk_joern(f)
                ),
                "joern_high_risk_kept": sum(
                    1 for f in findings if _is_high_risk_joern(f)
                ),
                "joern_high_risk_dropped_when_overflow": 0,
                "joern_low_risk_count": sum(
                    1 for f in findings if not _is_high_risk_joern(f)
                ),
                "joern_low_risk_kept": sum(
                    1 for f in findings if not _is_high_risk_joern(f)
                ),
                "joern_low_risk_dropped_when_overflow": 0,
                "joern_high_risk_cap": None,
                "joern_low_risk_cap": None,
            }
        hr_cap = lr_cap = int(max_candidates)
        effective_total_cap = int(max_candidates)

    high_risk = sorted(
        [finding for finding in findings if _is_high_risk_joern(finding)],
        key=_rank_joern_finding,
    )
    lower_risk = sorted(
        [finding for finding in findings if not _is_high_risk_joern(finding)],
        key=_rank_joern_finding,
    )

    if two_budget_mode:
        kept_high_risk = high_risk[:hr_cap]
        kept_low_risk = lower_risk[:lr_cap]
    else:
        kept_high_risk = high_risk[:hr_cap]
        kept_low_risk = lower_risk[: max(0, hr_cap - len(kept_high_risk))]

    kept = kept_high_risk + kept_low_risk

    if not two_budget_mode and raw_count <= effective_total_cap:
        # Single-cap legacy fast path: no drops.
        return findings, {
            "joern_raw_findings": raw_count,
            "joern_triaged_findings": raw_count,
            "joern_candidates_dropped_before_triage": 0,
            "joern_candidate_reducer_enabled": True,
            "joern_candidate_reducer_cap": max_candidates,
            "joern_dropped_reason_counts": {},
            "joern_high_risk_count": len(high_risk),
            "joern_high_risk_kept": len(high_risk),
            "joern_high_risk_dropped_when_overflow": 0,
            "joern_low_risk_count": len(lower_risk),
            "joern_low_risk_kept": len(lower_risk),
            "joern_low_risk_dropped_when_overflow": 0,
            "joern_high_risk_cap": None,
            "joern_low_risk_cap": None,
        }

    kept_ids = {id(finding) for finding in kept}
    dropped = [
        finding for finding in high_risk + lower_risk if id(finding) not in kept_ids
    ]
    high_risk_dropped = len(high_risk) - len(kept_high_risk)
    low_risk_dropped = len(lower_risk) - len(kept_low_risk)
    reason_counts: dict[str, int] = {}
    for finding in dropped:
        meta = finding.metadata or {}
        reason = "lower_ranked"
        if meta.get("test_file") or _joern_path_is_low_signal(finding.file_path):
            reason = "low_signal_path"
        elif str(meta.get("sinkKind", "")) == "wrapper":
            reason = "wrapper"
        elif (
            meta.get("argv_list_like") or meta.get("shlex_split_input")
        ) and not meta.get("shell_true"):
            reason = "argv_or_split_without_shell"
        elif meta.get("literal_command_like"):
            reason = "literal_command_like"
        reason_counts[reason] = reason_counts.get(reason, 0) + 1
    return kept, {
        "joern_raw_findings": raw_count,
        "joern_triaged_findings": len(kept),
        "joern_candidates_dropped_before_triage": len(dropped),
        "joern_candidate_reducer_enabled": True,
        "joern_candidate_reducer_cap": effective_total_cap,
        "joern_dropped_reason_counts": dict(sorted(reason_counts.items())),
        "joern_high_risk_count": len(high_risk),
        "joern_high_risk_kept": len(kept_high_risk),
        "joern_high_risk_dropped_when_overflow": high_risk_dropped,
        "joern_low_risk_count": len(lower_risk),
        "joern_low_risk_kept": len(kept_low_risk),
        "joern_low_risk_dropped_when_overflow": low_risk_dropped,
        "joern_high_risk_cap": hr_cap if two_budget_mode else None,
        "joern_low_risk_cap": lr_cap if two_budget_mode else None,
    }


def build_phase_metrics(
    *,
    wall_clock_s: float,
    n_findings: int,
    n_tp: int,
    n_fp: int,
    n_uncertain: int,
    llm_usage: dict[str, int],
    cpg_build_s: float = 0.0,
    scan_s: float = 0.0,
    llm_triage_s: float = 0.0,
    llm_refinement_s: float = 0.0,
    call_graph_s: float = 0.0,
    llm_tokens_triage: int = 0,
    llm_tokens_refinement: int = 0,
    refinement_candidates_seen: int = 0,
    refinement_candidates_applied: int = 0,
    refinement_candidates_rejected_by_verification: int = 0,
    refinement_added_sources: int = 0,
    refinement_added_sinks: int = 0,
    refinement_added_sanitizers: int = 0,
) -> dict[str, Any]:
    """Build the per-iteration metrics dict with phase-level attribution.

    ``overhead_s`` captures residual wall time (Python glue, context
    loading, snippet enrichment, agent-message marshalling) not attributed
    to any named phase; it is clamped to zero to hide minor clock skew.

    All phase timings are in seconds. Token counts are cumulative totals
    for the iteration; ``llm_tokens_triage`` and ``llm_tokens_refinement``
    are the subtotals used by the triage and refinement LLM calls
    respectively.

    The ``refinement_*`` counters are populated by the v2 refinement loop:

    - ``refinement_candidates_seen``: total wrapper candidates the LLM was
      asked to classify (post-ranking, post-cap).
    - ``refinement_candidates_applied``: classifications that survived
      symbolic verification and were appended to the Joern catalogs.
    - ``refinement_candidates_rejected_by_verification``: classifications
      the LLM produced but Joern could not confirm (dropped silently;
      logged in ``refinement_actions``).
    - ``refinement_added_{sources,sinks,sanitizers}``: per-role tally.
    """
    attributed = cpg_build_s + scan_s + llm_triage_s + llm_refinement_s + call_graph_s
    overhead_s = max(0.0, wall_clock_s - attributed)
    return {
        "wall_clock_s": wall_clock_s,
        "cpg_build_s": cpg_build_s,
        "scan_s": scan_s,
        "llm_triage_s": llm_triage_s,
        "llm_refinement_s": llm_refinement_s,
        "call_graph_s": call_graph_s,
        "overhead_s": overhead_s,
        "n_findings": n_findings,
        "n_tp": n_tp,
        "n_fp": n_fp,
        "n_uncertain": n_uncertain,
        "llm_usage": llm_usage,
        "llm_tokens_triage": llm_tokens_triage,
        "llm_tokens_refinement": llm_tokens_refinement,
        "refinement_candidates_seen": refinement_candidates_seen,
        "refinement_candidates_applied": refinement_candidates_applied,
        "refinement_candidates_rejected_by_verification": (
            refinement_candidates_rejected_by_verification
        ),
        "refinement_added_sources": refinement_added_sources,
        "refinement_added_sinks": refinement_added_sinks,
        "refinement_added_sanitizers": refinement_added_sanitizers,
    }


def _log_phase_breakdown(
    *, cve_id: str, arm: str, k: int, metrics: dict[str, Any]
) -> None:
    """Emit a compact INFO line summarising phase timings for one iteration."""
    logger.info(
        "[%s | %s k=%d] cpg=%.2fs scan=%.2fs triage=%.2fs refine=%.2fs "
        "cg=%.2fs overhead=%.2fs total=%.2fs findings=%d "
        "tok_triage=%d tok_refine=%d",
        cve_id or "-",
        arm,
        k,
        metrics["cpg_build_s"],
        metrics["scan_s"],
        metrics["llm_triage_s"],
        metrics["llm_refinement_s"],
        metrics["call_graph_s"],
        metrics["overhead_s"],
        metrics["wall_clock_s"],
        metrics["n_findings"],
        metrics["llm_tokens_triage"],
        metrics["llm_tokens_refinement"],
    )


class PipelineConfig:
    """Pipeline configuration (typically populated from Hydra YAML)."""

    def __init__(
        self,
        *,
        max_iterations: int = 3,
        seed: int = 235711,
        context_lines: int = 10,
        max_context_tokens: int = 2000,
        arms: list[str] | None = None,
        llm_base_url: str = "http://localhost:8000/v1",
        llm_model: str = "Qwen/Qwen2.5-Coder-7B-Instruct",
        llm_temperature: float = 0.1,
        llm_api_key: str = "not-needed",
        joern_port: int = 12345,
        call_graph_depth: int = 3,
        llm_log_io_path: str | None = None,
        joern_prompt_flow_path: bool = False,
        joern_max_triage_candidates: int | None = 50,
        joern_candidate_reducer_enabled: bool = True,
        joern_high_risk_candidate_cap: int | None = None,
        joern_low_risk_candidate_cap: int | None = None,
        joern_retry_uncertain_with_flow_path: bool = False,
        joern_flow_path_retry_limit: int = 10,
        joern_triage_argv_exception: bool = True,
        joern_skip_triage: bool = False,
        joern_modeling_mode: str = "full_wrapper",
        joern_emit_coverage_probe: bool = False,
        joern_coverage_probe_targets: dict[str, dict[str, Any]] | None = None,
        joern_refinement_candidate_cap: int = 12,
        joern_refinement_apply_multiple: bool = True,
        joern_refinement_verify: bool = True,
    ) -> None:
        self.max_iterations = max_iterations
        self.seed = seed
        self.context_lines = context_lines
        self.max_context_tokens = max_context_tokens
        self.arms = arms or ["semgrep", "joern"]
        self.llm_base_url = llm_base_url
        self.llm_model = llm_model
        self.llm_temperature = llm_temperature
        self.llm_api_key = llm_api_key
        self.joern_port = joern_port
        self.call_graph_depth = call_graph_depth
        self.llm_log_io_path = llm_log_io_path
        self.joern_prompt_flow_path = joern_prompt_flow_path
        self.joern_max_triage_candidates = joern_max_triage_candidates
        self.joern_candidate_reducer_enabled = joern_candidate_reducer_enabled
        self.joern_high_risk_candidate_cap = joern_high_risk_candidate_cap
        self.joern_low_risk_candidate_cap = joern_low_risk_candidate_cap
        self.joern_retry_uncertain_with_flow_path = joern_retry_uncertain_with_flow_path
        self.joern_flow_path_retry_limit = joern_flow_path_retry_limit
        self.joern_triage_argv_exception = joern_triage_argv_exception
        self.joern_skip_triage = joern_skip_triage
        self.joern_modeling_mode = joern_modeling_mode
        self.joern_emit_coverage_probe = joern_emit_coverage_probe
        self.joern_coverage_probe_targets = joern_coverage_probe_targets or {}
        self.joern_refinement_candidate_cap = joern_refinement_candidate_cap
        self.joern_refinement_apply_multiple = joern_refinement_apply_multiple
        self.joern_refinement_verify = joern_refinement_verify


class Pipeline:
    """Orchestrates the two-arm comparative analysis."""

    def __init__(self, config: PipelineConfig) -> None:
        self._cfg = config
        self._llm = LLMClient(
            LLMConfig(
                base_url=config.llm_base_url,
                model=config.llm_model,
                temperature=config.llm_temperature,
                api_key=config.llm_api_key,
                seed=config.seed,
                log_io_path=config.llm_log_io_path,
            )
        )
        self._triage = TriageAgent(
            self._llm,
            system_prompt=triage_system_prompt(
                include_argv_exception=config.joern_triage_argv_exception
            ),
        )
        self._refinement = RefinementAgent(self._llm)

    async def run(self, repo_path: str | Path, cve_id: str = "") -> RunResult:
        """Run both arms across k=0..max_iterations on *repo_path*."""
        repo_path = str(Path(repo_path).resolve())
        result = RunResult(repo_path=repo_path, cve_id=cve_id)

        if "semgrep" in self._cfg.arms:
            semgrep_iters = await self._run_semgrep_arm(repo_path, cve_id=cve_id)
            result.iterations.extend(semgrep_iters)

        if "joern" in self._cfg.arms:
            joern_iters = await self._run_joern_arm(repo_path, cve_id=cve_id)
            result.iterations.extend(joern_iters)

        result.metadata["llm_usage"] = self._llm.usage.to_dict()
        return result

    # ------------------------------------------------------------------
    # Semgrep arm iterations
    # ------------------------------------------------------------------

    async def _run_semgrep_arm(
        self, repo_path: str, *, cve_id: str = ""
    ) -> list[IterationResult]:
        arm = SemgrepArm(context_lines=self._cfg.context_lines)
        results: list[IterationResult] = []

        for k in range(self._cfg.max_iterations + 1):
            t0 = time.perf_counter()
            self._llm.reset_usage()

            rules_yaml_pre = arm.rules_yaml
            rules_hash_pre = _stable_hash(rules_yaml_pre)

            with _stopwatch() as scan_t:
                findings = arm.scan(repo_path)
                findings = arm.get_findings_with_context(findings)

            tokens_before_triage = self._llm.usage.to_dict()
            with _stopwatch() as triage_t:
                triage_results = await self._triage.triage_batch(findings)
            tokens_after_triage = self._llm.usage.to_dict()
            llm_tokens_triage = _llm_tokens_delta(
                tokens_before_triage, tokens_after_triage
            )

            refinement_actions: list[dict[str, Any]] = []
            refinement_s = 0.0
            llm_tokens_refinement = 0
            if k < self._cfg.max_iterations and findings:
                triage_summary = _triage_summary(triage_results)

                # Previously refinement only fired when at least one triage
                # verdict was FALSE_POSITIVE.  Because the triage LLM almost
                # always returned UNCERTAIN (see Phase-A audit) that gate
                # was effectively dead and Semgrep rules never mutated
                # across k=0..3.  We now always invoke refinement with the
                # full triage batch; the LLM itself decides between
                # ``keep`` / ``refine`` / ``add_rule`` and ``keep`` remains
                # the safe default on any parsing error
                # (see RefinementAgent.refine_semgrep).
                sample = _pick_refinement_target(findings, triage_results)
                tokens_before_ref = self._llm.usage.to_dict()
                with _stopwatch() as refine_t:
                    ref = await self._refinement.refine_semgrep(
                        rule_yaml=arm.rules_yaml,
                        file_path=sample.file_path,
                        line_number=sample.line_start,
                        code_snippet=sample.surrounding_context or sample.code_snippet,
                        triage_summary=triage_summary,
                    )
                    apply_status = arm.apply_refinement(
                        ref.action.value,
                        ref.rule_yaml,
                        ref.target_rule_id,
                        add_source_patterns=ref.add_source_patterns,
                        add_sanitizer_patterns=ref.add_sanitizer_patterns,
                        add_pattern_not=ref.add_pattern_not,
                        disable_rule=ref.disable_rule,
                    )
                    action_dict = asdict(ref)
                    action_dict["apply_status"] = apply_status
                    refinement_actions.append(action_dict)
                refinement_s = refine_t[0]
                llm_tokens_refinement = _llm_tokens_delta(
                    tokens_before_ref, self._llm.usage.to_dict()
                )

            elapsed = time.perf_counter() - t0

            metrics = build_phase_metrics(
                wall_clock_s=elapsed,
                scan_s=scan_t[0],
                llm_triage_s=triage_t[0],
                llm_refinement_s=refinement_s,
                n_findings=len(findings),
                n_tp=sum(
                    1 for t in triage_results if t.verdict == Verdict.TRUE_POSITIVE
                ),
                n_fp=sum(
                    1 for t in triage_results if t.verdict == Verdict.FALSE_POSITIVE
                ),
                n_uncertain=sum(
                    1 for t in triage_results if t.verdict == Verdict.UNCERTAIN
                ),
                llm_usage=self._llm.usage.to_dict(),
                llm_tokens_triage=llm_tokens_triage,
                llm_tokens_refinement=llm_tokens_refinement,
            )
            rules_yaml_post = arm.rules_yaml
            metrics["rules_hash_pre"] = rules_hash_pre
            metrics["rules_hash_post"] = _stable_hash(rules_yaml_post)
            metrics["rules_yaml_bytes_pre"] = len(rules_yaml_pre)
            metrics["rules_yaml_bytes_post"] = len(rules_yaml_post)
            metrics["rules_yaml_changed"] = rules_yaml_pre != rules_yaml_post
            metrics["findings_hash"] = _findings_hash(findings)
            _log_phase_breakdown(cve_id=cve_id, arm="semgrep", k=k, metrics=metrics)

            results.append(
                IterationResult(
                    arm=ToolArm.SEMGREP,
                    iteration=k,
                    findings=findings,
                    triage_results=triage_results,
                    refinement_actions=refinement_actions,
                    metrics=metrics,
                )
            )

        return results

    # ------------------------------------------------------------------
    # Joern arm iterations
    # ------------------------------------------------------------------

    async def _run_joern_arm(
        self, repo_path: str, *, cve_id: str = ""
    ) -> list[IterationResult]:
        backend_cfg = auto_detect_backend(repo_path, port=self._cfg.joern_port)
        results: list[IterationResult] = []

        # CPG construction happens inside AnalysisRuntime.__aenter__
        # (backend.connect -> joern import + workspace load).  We time it
        # directly with perf_counter so the failure path still reports a
        # meaningful partial duration.  On transient failures (notably
        # "port already in use" when the previous CVE's JVM was still
        # releasing the port) we retry once after a short pause.
        cpg_start = time.perf_counter()
        runtime_cm, runtime, cpg_error = await _connect_joern_with_retry(backend_cfg)
        if runtime is None:
            cpg_build_s_total = time.perf_counter() - cpg_start
            logger.error(
                "Joern arm failed during CPG build after %.2fs (with retry): %s",
                cpg_build_s_total,
                cpg_error,
                exc_info=cpg_error is not None,
            )
            if runtime_cm is not None:
                try:
                    await runtime_cm.stop()
                except Exception:
                    logger.exception(
                        "AnalysisRuntime cleanup after __aenter__ failure failed"
                    )
            return [
                IterationResult(
                    arm=ToolArm.JOERN,
                    iteration=0,
                    metrics={
                        "error": str(cpg_error) if cpg_error else "unknown CPG error",
                        "error_type": (
                            type(cpg_error).__name__ if cpg_error else "unknown"
                        ),
                        "cpg_build_s": cpg_build_s_total,
                        "cpg_build_failed": True,
                    },
                )
            ]
        cpg_build_s_total = time.perf_counter() - cpg_start

        try:
            joern_holder: list[JoernArm] = []

            def _joern_factory() -> JoernArm:
                inst = JoernArm(
                    context_lines=self._cfg.context_lines,
                    call_graph_depth=self._cfg.call_graph_depth,
                    modeling_mode=self._cfg.joern_modeling_mode,
                )
                joern_holder.append(inst)
                return inst

            await runtime.register_agent(
                agent_type=JoernArm,
                agent_name="joern_arm",
                agent_factory=_joern_factory,
            )
            runtime.start()

            for k in range(self._cfg.max_iterations + 1):
                t0 = time.perf_counter()
                self._llm.reset_usage()
                # CPG build cost is a one-shot, amortise onto k=0 only.
                cpg_build_s = cpg_build_s_total if k == 0 else 0.0

                joern = joern_holder[0] if joern_holder else None
                catalog_pre = _joern_catalog_snapshot(joern) if joern else {}

                with _stopwatch() as scan_t:
                    scan_resp = await runtime.send_message(
                        Request(type="task.joern_scan", payload={}),
                        AgentId("joern_arm", "default"),
                    )
                    raw_findings = scan_resp.data if scan_resp.success else []
                    findings = [
                        Finding(**f) if isinstance(f, dict) else f for f in raw_findings
                    ]
                    findings, reducer_metrics = _reduce_joern_findings(
                        findings,
                        self._cfg.joern_max_triage_candidates,
                        enabled=self._cfg.joern_candidate_reducer_enabled,
                        high_risk_cap=self._cfg.joern_high_risk_candidate_cap,
                        low_risk_cap=self._cfg.joern_low_risk_candidate_cap,
                    )
                    joern = joern_holder[0]
                    findings = joern.get_findings_with_context(findings, repo_path)

                coverage_probe: dict[str, Any] = {}
                probe_target = self._cfg.joern_coverage_probe_targets.get(cve_id, {})
                if self._cfg.joern_emit_coverage_probe and probe_target:
                    probe_resp = await runtime.send_message(
                        Request(
                            type="task.joern_coverage_probe",
                            payload={
                                "gt_file": probe_target.get("vulnerable_file", ""),
                                "gt_lines": probe_target.get("vulnerable_lines", []),
                            },
                        ),
                        AgentId("joern_arm", "default"),
                    )
                    if probe_resp.success and isinstance(probe_resp.data, dict):
                        coverage_probe = probe_resp.data
                    else:
                        coverage_probe = {
                            "gt_file_seen": False,
                            "method_count": 0,
                            "gt_sink_count": 0,
                            "external_source_count": 0,
                            "methods_in_gt_file": [],
                            "probe_skipped": [],
                            "probe_failed": ["message_failed"],
                        }

                tokens_before_triage = self._llm.usage.to_dict()
                with _stopwatch() as triage_t:
                    flow_path_retry_count = 0
                    flow_path_retry_tokens = 0
                    flow_path_retry_tp_delta = 0
                    if self._cfg.joern_skip_triage:
                        structural_evidence_map: dict[int, str] = {}
                        triage_results: list[TriageResult] = []
                    else:
                        structural_evidence_map = _joern_structural_evidence_map(
                            findings,
                            include_flow_path=self._cfg.joern_prompt_flow_path,
                        )
                        triage_results = await self._triage.triage_batch(
                            findings,
                            structural_evidence_map=structural_evidence_map,
                        )
                    if (
                        not self._cfg.joern_skip_triage
                        and self._cfg.joern_retry_uncertain_with_flow_path
                        and self._cfg.joern_flow_path_retry_limit > 0
                    ):
                        full_evidence_map = _joern_structural_evidence_map(
                            findings,
                            include_flow_path=True,
                        )
                        retry_indices = [
                            idx
                            for idx, result in enumerate(triage_results)
                            if result.verdict == Verdict.UNCERTAIN
                            and idx in full_evidence_map
                        ][: self._cfg.joern_flow_path_retry_limit]
                        for idx in retry_indices:
                            retry_before = self._llm.usage.to_dict()
                            old_is_tp = (
                                triage_results[idx].verdict == Verdict.TRUE_POSITIVE
                            )
                            retried = await self._triage.triage(
                                findings[idx],
                                full_evidence_map[idx],
                            )
                            triage_results[idx] = retried
                            flow_path_retry_count += 1
                            flow_path_retry_tokens += _llm_tokens_delta(
                                retry_before,
                                self._llm.usage.to_dict(),
                            )
                            if (
                                not old_is_tp
                                and retried.verdict == Verdict.TRUE_POSITIVE
                            ):
                                flow_path_retry_tp_delta += 1
                llm_tokens_triage = _llm_tokens_delta(
                    tokens_before_triage, self._llm.usage.to_dict()
                )

                refinement_actions: list[dict[str, Any]] = []
                call_graph_s = 0.0
                refinement_s = 0.0
                llm_tokens_refinement = 0
                refinement_candidates_seen = 0
                refinement_candidates_applied = 0
                refinement_candidates_rejected_by_verification = 0
                refinement_added_sources = 0
                refinement_added_sinks = 0
                refinement_added_sanitizers = 0

                if k < self._cfg.max_iterations and not self._cfg.joern_skip_triage:
                    finding_files = sorted(
                        {f.file for f in findings if getattr(f, "file", "")}
                    )[:10]
                    cap_per_bucket = max(
                        1, int(self._cfg.joern_refinement_candidate_cap)
                    )
                    with _stopwatch() as cg_t:
                        candidates_resp = await runtime.send_message(
                            Request(
                                type="task.joern_refinement_candidates",
                                payload={
                                    "finding_files": finding_files,
                                    "cap_per_bucket": cap_per_bucket,
                                },
                            ),
                            AgentId("joern_arm", "default"),
                        )
                    call_graph_s += cg_t[0]
                    buckets: dict[str, list[dict[str, Any]]] = (
                        candidates_resp.data
                        if candidates_resp.success
                        and isinstance(candidates_resp.data, dict)
                        else {}
                    )
                    pooled: dict[str, dict[str, Any]] = {}
                    for bucket_name, bucket_items in buckets.items():
                        for item in bucket_items or []:
                            name = str(item.get("name", "") or "")
                            if not name:
                                continue
                            pooled_item = pooled.setdefault(name, dict(item))
                            existing = list(pooled_item.get("buckets", []) or [])
                            if bucket_name not in existing:
                                existing.append(bucket_name)
                            pooled_item["buckets"] = existing
                    ranked = JoernArm.rank_wrapper_candidates(
                        list(pooled.values()),
                        finding_files=finding_files,
                        cap=cap_per_bucket,
                    )
                    refinement_candidates_seen = len(ranked)
                    if ranked:
                        tokens_before_ref = self._llm.usage.to_dict()
                        with _stopwatch() as refine_t:
                            classification = (
                                await self._refinement.classify_helpers_joern(
                                    call_graph_neighborhood=ranked,
                                    current_sources=joern.sources,
                                    current_sinks=joern.sinks,
                                    current_sanitizers=joern.sanitizers,
                                )
                            )
                        refinement_s += refine_t[0]
                        llm_tokens_refinement += _llm_tokens_delta(
                            tokens_before_ref, self._llm.usage.to_dict()
                        )

                        proposed_sources = [
                            n
                            for n, r in classification.classifications.items()
                            if r == HelperRole.SOURCE_WRAPPER
                        ]
                        proposed_sinks = [
                            n
                            for n, r in classification.classifications.items()
                            if r == HelperRole.SINK_WRAPPER
                        ]
                        proposed_sanitizers = [
                            n
                            for n, r in classification.classifications.items()
                            if r == HelperRole.SANITIZER
                        ]

                        if self._cfg.joern_refinement_verify and (
                            proposed_sources or proposed_sinks or proposed_sanitizers
                        ):
                            with _stopwatch() as verify_t:
                                verify_resp = await runtime.send_message(
                                    Request(
                                        type="task.joern_verify_wrappers",
                                        payload={
                                            "sources": proposed_sources,
                                            "sinks": proposed_sinks,
                                            "sanitizers": proposed_sanitizers,
                                        },
                                    ),
                                    AgentId("joern_arm", "default"),
                                )
                            call_graph_s += verify_t[0]
                            verified = (
                                verify_resp.data
                                if verify_resp.success
                                and isinstance(verify_resp.data, dict)
                                else {}
                            )
                            verified_sources = list(verified.get("sources", []) or [])
                            verified_sinks = list(verified.get("sinks", []) or [])
                            verified_sanitizers = list(
                                verified.get("sanitizers", []) or []
                            )
                        else:
                            verified_sources = list(proposed_sources)
                            verified_sinks = list(proposed_sinks)
                            verified_sanitizers = list(proposed_sanitizers)

                        rejected_sources = sorted(
                            set(proposed_sources) - set(verified_sources)
                        )
                        rejected_sinks = sorted(
                            set(proposed_sinks) - set(verified_sinks)
                        )
                        rejected_sanitizers = sorted(
                            set(proposed_sanitizers) - set(verified_sanitizers)
                        )
                        refinement_candidates_rejected_by_verification = (
                            len(rejected_sources)
                            + len(rejected_sinks)
                            + len(rejected_sanitizers)
                        )

                        if not self._cfg.joern_refinement_apply_multiple:
                            verified_sources = verified_sources[:1]
                            verified_sinks = verified_sinks[:1]
                            verified_sanitizers = verified_sanitizers[:1]

                        joern.expand_sources(verified_sources)
                        joern.expand_sinks(verified_sinks)
                        joern.expand_sanitizers(verified_sanitizers)
                        refinement_added_sources = len(verified_sources)
                        refinement_added_sinks = len(verified_sinks)
                        refinement_added_sanitizers = len(verified_sanitizers)
                        refinement_candidates_applied = (
                            refinement_added_sources
                            + refinement_added_sinks
                            + refinement_added_sanitizers
                        )

                        action_record = asdict(classification)
                        action_record["candidates_seen"] = refinement_candidates_seen
                        action_record["verified"] = {
                            "sources": verified_sources,
                            "sinks": verified_sinks,
                            "sanitizers": verified_sanitizers,
                        }
                        action_record["rejected"] = {
                            "sources": rejected_sources,
                            "sinks": rejected_sinks,
                            "sanitizers": rejected_sanitizers,
                        }
                        action_record["candidate_buckets"] = {
                            cand.get("name", ""): list(cand.get("buckets", []) or [])
                            for cand in ranked
                            if cand.get("name")
                        }
                        refinement_actions.append(action_record)

                elapsed = time.perf_counter() - t0

                metrics = build_phase_metrics(
                    wall_clock_s=elapsed + cpg_build_s,
                    cpg_build_s=cpg_build_s,
                    scan_s=scan_t[0],
                    llm_triage_s=triage_t[0],
                    llm_refinement_s=refinement_s,
                    call_graph_s=call_graph_s,
                    n_findings=len(findings),
                    n_tp=sum(
                        1 for t in triage_results if t.verdict == Verdict.TRUE_POSITIVE
                    ),
                    n_fp=sum(
                        1 for t in triage_results if t.verdict == Verdict.FALSE_POSITIVE
                    ),
                    n_uncertain=sum(
                        1 for t in triage_results if t.verdict == Verdict.UNCERTAIN
                    ),
                    llm_usage=self._llm.usage.to_dict(),
                    llm_tokens_triage=llm_tokens_triage,
                    llm_tokens_refinement=llm_tokens_refinement,
                )
                catalog_post = _joern_catalog_snapshot(joern)
                metrics["joern_catalog_pre"] = catalog_pre
                metrics["joern_catalog_post"] = catalog_post
                metrics["joern_catalog_grew"] = (
                    len(catalog_post.get("sources", []))
                    > len(catalog_pre.get("sources", []))
                    or len(catalog_post.get("sinks", []))
                    > len(catalog_pre.get("sinks", []))
                    or len(catalog_post.get("sanitizers", []))
                    > len(catalog_pre.get("sanitizers", []))
                )
                metrics["findings_hash"] = _findings_hash(findings)
                metrics.update(reducer_metrics)
                metrics["joern_structural_evidence_count"] = len(
                    structural_evidence_map
                )
                metrics["joern_prompt_flow_path_enabled"] = (
                    self._cfg.joern_prompt_flow_path
                )
                metrics["joern_modeling_mode"] = self._cfg.joern_modeling_mode
                metrics["joern_skip_triage"] = self._cfg.joern_skip_triage
                if coverage_probe:
                    metrics["joern_coverage_probe"] = coverage_probe
                metrics["joern_flow_path_retry_enabled"] = (
                    self._cfg.joern_retry_uncertain_with_flow_path
                )
                metrics["joern_flow_path_retry_count"] = flow_path_retry_count
                metrics["joern_flow_path_retry_tokens"] = flow_path_retry_tokens
                metrics["joern_flow_path_retry_tp_delta"] = flow_path_retry_tp_delta
                _log_phase_breakdown(cve_id=cve_id, arm="joern", k=k, metrics=metrics)

                results.append(
                    IterationResult(
                        arm=ToolArm.JOERN,
                        iteration=k,
                        findings=findings,
                        triage_results=triage_results,
                        refinement_actions=refinement_actions,
                        metrics=metrics,
                    )
                )

        except Exception as exc:
            logger.error("Joern arm failed: %s", exc, exc_info=True)
            if not results:
                results.append(
                    IterationResult(
                        arm=ToolArm.JOERN,
                        iteration=0,
                        metrics={"error": str(exc), "cpg_build_s": cpg_build_s_total},
                    )
                )
        finally:
            try:
                await runtime_cm.__aexit__(None, None, None)
            except Exception:  # pragma: no cover - best-effort cleanup
                logger.exception("AnalysisRuntime cleanup failed")

        return results


def _triage_summary(triage_results: list[Any]) -> dict[str, int]:
    summary: dict[str, int] = {"tp": 0, "fp": 0, "uncertain": 0}
    for t in triage_results:
        if t.verdict == Verdict.TRUE_POSITIVE:
            summary["tp"] += 1
        elif t.verdict == Verdict.FALSE_POSITIVE:
            summary["fp"] += 1
        else:
            summary["uncertain"] += 1
    return summary


def _pick_refinement_target(
    findings: list[Finding],
    triage_results: list[Any],
) -> Finding:
    """Choose the most informative finding to anchor LLM refinement.

    Priority order (falls through to the next if none match):

      1. A ``FALSE_POSITIVE`` — the LLM already flagged it, so refining
         the rule around it directly improves precision.
      2. An ``UNCERTAIN`` — ambiguous cases benefit most from rule
         tightening / widening.
      3. Any ``TRUE_POSITIVE`` — expose the rule to a known-good match so
         the LLM can propose complementary ``add_rule`` suggestions.
      4. First finding as an unconditional fallback.
    """
    pairs = list(zip(findings, triage_results, strict=False))
    for verdict in (Verdict.FALSE_POSITIVE, Verdict.UNCERTAIN, Verdict.TRUE_POSITIVE):
        for f, t in pairs:
            if t.verdict == verdict:
                return f
    return findings[0]
