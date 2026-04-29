#!/usr/bin/env python3
"""CVE evaluation harness for the CWE-78 two-arm comparative study.

For each of the 105 CVEs in the metadata file:
  1. Clone the repo (shallow) and checkout the vulnerable commit.
  2. Run both arms (Semgrep + Joern) with k=0..3.
  3. Checkout the patch commit and re-run (findings on patched = FP).
  4. Label findings against ground truth.
  5. Record all metrics and save structured JSON results.

Usage:
    python scripts/run_evaluation.py                      # defaults
    python scripts/run_evaluation.py --arms semgrep       # Semgrep only
    python scripts/run_evaluation.py --variance           # variance run
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import multiprocessing as mp
import os
import random
import resource
import shutil
import signal
import subprocess
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any

import psutil

from auditzoo.agents.cwe78_study.pipeline import Pipeline, PipelineConfig
from auditzoo.agents.cwe78_study.schemas import (
    Finding,
    ToolArm,
    TriageResult,
    Verdict,
)

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATASET = ROOT / "benchmark" / "python" / "cwe78_cves" / "metadata.json"
DEFAULT_OUTPUT = ROOT / "results"
DEFAULT_CLONE_DIR = Path("/tmp/auditzoo_eval")

LINE_TOLERANCE = 5

_REASONING_CAP = 200


# ======================================================================
# Evidence serialisation
# ======================================================================


def _snippet_for(f: Finding) -> str:
    """Return the text that ``source_expr`` / ``sink_expr`` are validated against."""
    return "\n".join(
        part
        for part in (
            getattr(f, "surrounding_context", "") or "",
            getattr(f, "code_snippet", "") or "",
            _joern_metadata_evidence(f),
        )
        if part
    )


def _joern_metadata_evidence(f: Finding) -> str:
    """Render Joern metadata evidence for scorer/serialization checks."""
    meta = getattr(f, "metadata", {}) or {}
    if not isinstance(meta, dict):
        return ""
    parts: list[str] = []
    for prefix, file_key, line_key, code_key in (
        ("source", "sourceFile", "sourceLine", "sourceCode"),
        ("sink", "sinkFile", "sinkLine", "sinkCode"),
        ("report", "reportFile", "reportLine", "sinkCode"),
    ):
        file_path = str(meta.get(file_key, "") or "")
        line = str(meta.get(line_key, "") or "")
        code = str(meta.get(code_key, "") or "")
        if file_path or line or code:
            parts.append(f"joern {prefix}: {file_path}:{line} {code}")
    for label, key in (("origin", "originEvidence"), ("caller", "callerChain")):
        records = meta.get(key) or []
        if not isinstance(records, list):
            continue
        for idx, record in enumerate(records[:3], start=1):
            if not isinstance(record, dict):
                continue
            code = str(record.get("code", "") or "")
            arg_code = str(record.get("argumentCode", "") or "")
            suffix = f" arg={arg_code}" if arg_code else ""
            parts.append(
                f"joern {label} {idx}: "
                f"{record.get('file', '')}:{record.get('line', '')} {code}{suffix}"
            )
    flow_path = meta.get("flowPath") or []
    if isinstance(flow_path, list):
        for idx, node in enumerate(flow_path[:20], start=1):
            if not isinstance(node, dict):
                continue
            parts.append(
                "joern flow "
                f"{idx}: {node.get('file', '')}:{node.get('line', '')} "
                f"{node.get('nodeType', '')} {node.get('code', '')}"
            )
    return "\n".join(parts)


def _joern_flow_locations(f: Finding) -> list[tuple[str, int]]:
    """Return all Joern metadata locations associated with a finding."""
    meta = getattr(f, "metadata", {}) or {}
    if not isinstance(meta, dict):
        return []

    def _line(value: Any) -> int | None:
        try:
            line = int(value)
        except (TypeError, ValueError):
            return None
        return line if line > 0 else None

    locations: list[tuple[str, int]] = []
    for file_key, line_key in (
        ("reportFile", "reportLine"),
        ("sinkFile", "sinkLine"),
        ("sourceFile", "sourceLine"),
    ):
        file_path = str(meta.get(file_key, "") or "")
        line = _line(meta.get(line_key))
        if file_path and line is not None:
            locations.append((file_path, line))

    flow_path = meta.get("flowPath") or []
    if isinstance(flow_path, list):
        for node in flow_path:
            if not isinstance(node, dict):
                continue
            file_path = str(node.get("file", "") or "")
            line = _line(node.get("line"))
            if file_path and line is not None:
                locations.append((file_path, line))
    report_candidates = meta.get("reportCandidateLocations") or []
    if isinstance(report_candidates, list):
        for location in report_candidates:
            if not isinstance(location, dict):
                continue
            file_path = str(location.get("file", "") or "")
            line = _line(location.get("line"))
            if file_path and line is not None:
                locations.append((file_path, line))

    # Preserve order while removing duplicates.
    seen: set[tuple[str, int]] = set()
    out: list[tuple[str, int]] = []
    for loc in locations:
        if loc not in seen:
            seen.add(loc)
            out.append(loc)
    return out


def _joern_report_candidate_records(f: Finding) -> list[dict[str, Any]]:
    """Return auxiliary Joern report location records with metadata."""
    meta = getattr(f, "metadata", {}) or {}
    if not isinstance(meta, dict):
        return []

    def _line(value: Any) -> int | None:
        try:
            line = int(value)
        except (TypeError, ValueError):
            return None
        return line if line > 0 else None

    records: list[dict[str, Any]] = []
    report_candidates = meta.get("reportCandidateLocations") or []
    if isinstance(report_candidates, list):
        for location in report_candidates:
            if not isinstance(location, dict):
                continue
            file_path = str(location.get("file", "") or "")
            line = _line(location.get("line"))
            if file_path and line is not None:
                records.append(
                    {
                        "file": file_path,
                        "line": line,
                        "reason": str(location.get("reason", "") or ""),
                        "caller_external": bool(
                            location.get("caller_external", False)
                            or location.get("matchesExternal", False)
                        ),
                        "code": str(location.get("code", "") or ""),
                    }
                )
    return records


def _joern_report_candidate_locations(f: Finding) -> list[tuple[str, int]]:
    """Return auxiliary report locations recorded by Joern metadata."""
    return [
        (str(record["file"]), int(record["line"]))
        for record in _joern_report_candidate_records(f)
    ]


def _location_line_match(
    found_file: str,
    found_line: int,
    vuln_file: str,
    vuln_lines: set[int],
    line_tolerance: int,
) -> tuple[bool, int | None]:
    found_name = Path(found_file).name
    gt_file = Path(vuln_file).name
    path_ok = (
        found_name == gt_file
        or vuln_file.endswith(found_file)
        or found_file.endswith(vuln_file)
    )
    if not path_ok:
        return False, None
    for vl in vuln_lines:
        if abs(found_line - vl) <= line_tolerance:
            return True, vl
    return False, None


def _shared_prefix_depth(candidate_file: str, gt_file: str) -> int:
    cand_parts = Path(candidate_file).parts
    gt_parts = Path(gt_file).parts
    depth = 0
    for cand, gt in zip(cand_parts, gt_parts, strict=False):
        if cand != gt:
            break
        depth += 1
    return depth


def _same_package(candidate_file: str, gt_file: str) -> bool:
    if not candidate_file or not gt_file:
        return False
    if Path(candidate_file).parent == Path(gt_file).parent:
        return True
    return _shared_prefix_depth(candidate_file, gt_file) >= 2


def serialize_triage_verdicts(
    findings: list[Finding],
    triage_results: list[TriageResult],
    ground_truth: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Produce an audit-friendly, length-aligned list of triage decisions.

    Each entry joins the finding location and rule with the LLM verdict
    so downstream analysis can compute ``verdict x gt_match`` contingency
    tables without needing the pipeline state.  Reasoning and suggestion
    strings are capped at ``_REASONING_CAP`` characters to keep
    ``results.json`` small.

    In addition to the Phase-B3 schema we emit two evidence-audit
    columns sourced from the new :class:`TriageResult.source_expr` /
    :class:`TriageResult.sink_expr` fields:

    * ``source_in_snippet``: whether ``source_expr`` is a literal
      substring of the finding's snippet (``True`` when ``source_expr``
      is empty — preserves parity with pre-evidence results).
    * ``downgrade_reason``: propagated from the agent-level brake
      (``"source_expr_not_in_snippet"``,
      ``"sink_expr_not_in_snippet"``, or ``""``).

    When ``ground_truth`` is supplied we additionally emit ``same_package``
    and ``same_package_promoted`` per row so downstream auditors can sample
    relaxed-recall candidates without re-deriving the gate.  Both fields
    default to ``False`` when ``ground_truth`` is ``None``.
    """
    gt_file = str((ground_truth or {}).get("vulnerable_file", "") or "")
    gt_lines: set[int] = set((ground_truth or {}).get("vulnerable_lines", []) or [])
    out: list[dict[str, Any]] = []
    for f, t in zip(findings, triage_results, strict=False):
        snippet = _snippet_for(f)
        meta = getattr(f, "metadata", {}) or {}
        if not isinstance(meta, dict):
            meta = {}
        source_expr = (getattr(t, "source_expr", "") or "").strip()
        sink_expr = (getattr(t, "sink_expr", "") or "").strip()
        # Parity rule: empty source_expr reports True so old-format
        # scripted results (which have no source_expr at all) aren't
        # mass-flagged as hallucinations.
        source_in_snippet = (not source_expr) or (source_expr in snippet)
        sink_in_snippet = (not sink_expr) or (sink_expr in snippet)
        flow_locations = [
            f"{file_path}:{line}" for file_path, line in _joern_flow_locations(f)
        ]

        def _evidence_records(
            key: str, metadata: dict[str, Any] = meta
        ) -> list[dict[str, Any]]:
            records = metadata.get(key) or []
            if not isinstance(records, list):
                return []
            out_records: list[dict[str, Any]] = []
            for record in records[:3]:
                if not isinstance(record, dict):
                    continue
                out_records.append(
                    {
                        "file": str(record.get("file", "") or ""),
                        "line": str(record.get("line", "") or ""),
                        "code": str(record.get("code", "") or "")[:_REASONING_CAP],
                        "argumentCode": str(record.get("argumentCode", "") or "")[
                            :_REASONING_CAP
                        ],
                        "matchesExternal": bool(record.get("matchesExternal", False)),
                    }
                )
            return out_records

        def _evidence_record(
            key: str, metadata: dict[str, Any] = meta
        ) -> dict[str, Any]:
            record = metadata.get(key) or {}
            if not isinstance(record, dict):
                return {}
            return {
                "file": str(record.get("file", "") or ""),
                "line": str(record.get("line", "") or ""),
                "code": str(record.get("code", "") or "")[:_REASONING_CAP],
                "argumentCode": str(record.get("argumentCode", "") or "")[
                    :_REASONING_CAP
                ],
                "callerMethod": str(
                    record.get("callerMethod", "")
                    or record.get("methodFullName", "")
                    or ""
                )[:_REASONING_CAP],
                "methodFullName": str(record.get("methodFullName", "") or "")[
                    :_REASONING_CAP
                ],
                "matchesExternal": bool(record.get("matchesExternal", False)),
            }

        report_candidate_locations = meta.get("reportCandidateLocations") or []
        if not isinstance(report_candidate_locations, list):
            report_candidate_locations = []

        origin_external = bool(meta.get("originExternalSource", False))
        same_package = bool(gt_file) and _same_package(f.file_path, gt_file)
        is_strict_match = False
        matched_gt_line: int | None = None
        if gt_file and gt_lines:
            is_strict_match, matched_gt_line = _location_line_match(
                f.file_path, f.line_start, gt_file, gt_lines, LINE_TOLERANCE
            )
        is_report_candidate_match = False
        report_candidate_external = False
        if gt_file and gt_lines:
            for record in _joern_report_candidate_records(f):
                rc_file = str(record.get("file", "") or "")
                try:
                    rc_line = int(record.get("line", 0) or 0)
                except (TypeError, ValueError):
                    continue
                rc_match, _ = _location_line_match(
                    rc_file, rc_line, gt_file, gt_lines, LINE_TOLERANCE
                )
                if rc_match:
                    is_report_candidate_match = True
                    report_candidate_external = bool(
                        record.get("caller_external", False)
                    )
                    break
        verdict_value = getattr(t.verdict, "value", str(t.verdict))
        verdict_promotable = (
            verdict_value == "true_positive" and source_in_snippet
        ) or verdict_value == "uncertain"
        same_package_promoted = bool(
            origin_external
            and same_package
            and verdict_promotable
            and not is_strict_match
            and not (
                is_report_candidate_match
                and bool(origin_external or report_candidate_external)
            )
        )

        out.append(
            {
                "file": f.file_path,
                "line": f.line_start,
                "rule_id": f.rule_id,
                "sink_api": f.sink_api,
                "verdict": verdict_value,
                "confidence": float(getattr(t, "confidence", 0.0) or 0.0),
                "reasoning": (getattr(t, "reasoning", "") or "")[:_REASONING_CAP],
                "suggestion": (getattr(t, "suggestion", "") or "")[:_REASONING_CAP],
                "source_expr": source_expr[:_REASONING_CAP],
                "sink_expr": sink_expr[:_REASONING_CAP],
                "source_in_snippet": source_in_snippet,
                "sink_in_snippet": sink_in_snippet,
                "downgrade_reason": getattr(t, "downgrade_reason", "") or "",
                "joern_flow_locations": flow_locations[:30],
                "reportCandidateLocations": report_candidate_locations[:10],
                "joern_report_reason": meta.get("reportReason", ""),
                "sourceKind": meta.get("sourceKind", ""),
                "originExternalSource": origin_external,
                "originEvidence": _evidence_records("originEvidence"),
                "callerChain": _evidence_records("callerChain"),
                "sinkCallsite": _evidence_record("sinkCallsite"),
                "sinkCallerChain": _evidence_records("sinkCallerChain"),
                "sinkKind": meta.get("sinkKind", ""),
                "sinkMethodName": meta.get("sinkMethodName", ""),
                "wrapperName": meta.get("wrapperName", ""),
                "wrappedSinkName": meta.get("wrappedSinkName", ""),
                "wrappedSinkCode": meta.get("wrappedSinkCode", ""),
                "shell_true": bool(meta.get("shell_true", False)),
                "shell_false": bool(meta.get("shell_false", False)),
                "argv_list_like": bool(meta.get("argv_list_like", False)),
                "string_command_like": bool(meta.get("string_command_like", False)),
                "shlex_split_input": bool(meta.get("shlex_split_input", False)),
                "literal_command_like": bool(meta.get("literal_command_like", False)),
                "test_file": bool(meta.get("test_file", False)),
                "same_package": same_package,
                "same_package_promoted": same_package_promoted,
                "is_strict_match": is_strict_match,
                "matched_gt_line": matched_gt_line,
            }
        )
    return out


# ======================================================================
# Ground-truth labelling
# ======================================================================


def _gt_line_match(
    f: Finding,
    vuln_file: str,
    vuln_lines: set[int],
    line_tolerance: int,
) -> tuple[bool, int | None]:
    """Return ``(is_match, matched_gt_line)`` for a finding against GT."""
    if not vuln_lines:
        return False, None
    return _location_line_match(
        f.file_path, f.line_start, vuln_file, vuln_lines, line_tolerance
    )


def _gt_joern_flow_match(
    f: Finding,
    vuln_file: str,
    vuln_lines: set[int],
    line_tolerance: int,
) -> tuple[bool, int | None]:
    """Return whether any Joern metadata location matches GT."""
    if not vuln_lines:
        return False, None
    for file_path, line in _joern_flow_locations(f):
        matched, matched_line = _location_line_match(
            file_path, line, vuln_file, vuln_lines, line_tolerance
        )
        if matched:
            return True, matched_line
    return False, None


def _gt_joern_report_candidate_match(
    f: Finding,
    vuln_file: str,
    vuln_lines: set[int],
    line_tolerance: int,
) -> tuple[bool, int | None, bool]:
    """Return whether an auxiliary Joern report candidate location matches GT."""
    if not vuln_lines:
        return False, None, False
    for record in _joern_report_candidate_records(f):
        file_path = str(record.get("file", "") or "")
        try:
            line = int(record.get("line", 0) or 0)
        except (TypeError, ValueError):
            continue
        matched, matched_line = _location_line_match(
            file_path, line, vuln_file, vuln_lines, line_tolerance
        )
        if matched:
            return True, matched_line, bool(record.get("caller_external", False))
    return False, None, False


def _dedup_key(f: Finding) -> tuple[str, int, str]:
    """Group Joern flow duplicates by the user-visible reported sink location."""
    meta = getattr(f, "metadata", {}) or {}
    if not isinstance(meta, dict):
        meta = {}
    sink_method = (
        getattr(f, "sink_api", "")
        or meta.get("sinkMethodName", "")
        or meta.get("sinkName", "")
        or ""
    )
    try:
        line_start = int(getattr(f, "line_start", 0) or 0)
    except (TypeError, ValueError):
        line_start = 0
    return (str(getattr(f, "file_path", "") or ""), line_start, str(sink_method))


def _dedup_priority(
    idx: int,
    f: Finding,
    t: Any,
    *,
    vuln_file: str,
    vuln_lines: set[int],
    line_tolerance: int,
) -> tuple[int, int, int, int]:
    """Return a scorer-aware priority for choosing one duplicate finding.

    The tie-break mirrors ``label_findings``: hallucinated-source TPs should
    not beat clean uncertain duplicates, and GT/report-candidate matches beat
    findings that would only contribute an FP.
    """
    meta = getattr(f, "metadata", {}) or {}
    if not isinstance(meta, dict):
        meta = {}

    is_match, _ = _gt_line_match(f, vuln_file, vuln_lines, line_tolerance)
    (
        is_report_candidate_match,
        report_candidate_matched_line,
        report_candidate_external,
    ) = _gt_joern_report_candidate_match(f, vuln_file, vuln_lines, line_tolerance)
    origin_external = bool(meta.get("originExternalSource", False))
    report_candidate_promotable = (
        is_report_candidate_match and report_candidate_matched_line is not None
    )
    report_candidate_origin_ok = bool(origin_external or report_candidate_external)

    source_expr = (getattr(t, "source_expr", "") or "").strip()
    source_in_snippet = (not source_expr) or (source_expr in _snippet_for(f))
    verdict = getattr(t, "verdict", None)
    is_hallucinated_tp = verdict == Verdict.TRUE_POSITIVE and not source_in_snippet
    would_score_tp = (
        verdict != Verdict.FALSE_POSITIVE
        and not is_hallucinated_tp
        and (is_match or (report_candidate_promotable and report_candidate_origin_ok))
    )

    if would_score_tp:
        score_bucket = 3
    elif verdict != Verdict.FALSE_POSITIVE and not is_hallucinated_tp:
        score_bucket = 2
    elif verdict == Verdict.FALSE_POSITIVE:
        score_bucket = 1
    else:
        score_bucket = 0

    verdict_rank = {
        Verdict.TRUE_POSITIVE: 3,
        Verdict.UNCERTAIN: 2,
        Verdict.FALSE_POSITIVE: 1,
    }.get(verdict, 2)
    return (score_bucket, verdict_rank, int(origin_external), -idx)


def _select_dedup_winners(
    findings: list[Finding],
    triage_results: list[Any],
    *,
    vuln_file: str,
    vuln_lines: set[int],
    line_tolerance: int,
) -> tuple[set[int], int]:
    """Choose one scoring representative per ``(file, line, sink)`` key."""
    winners: dict[tuple[str, int, str], tuple[int, tuple[int, int, int, int]]] = {}
    for idx, (f, t) in enumerate(zip(findings, triage_results, strict=False)):
        key = _dedup_key(f)
        priority = _dedup_priority(
            idx,
            f,
            t,
            vuln_file=vuln_file,
            vuln_lines=vuln_lines,
            line_tolerance=line_tolerance,
        )
        current = winners.get(key)
        if current is None or priority > current[1]:
            winners[key] = (idx, priority)

    winner_indexes = {idx for idx, _ in winners.values()}
    dedup_dropped = len(list(zip(findings, triage_results, strict=False))) - len(
        winner_indexes
    )
    return winner_indexes, dedup_dropped


def label_findings(
    findings: list[Finding],
    triage_results: list[Any],
    ground_truth: dict[str, Any],
    *,
    line_tolerance: int = LINE_TOLERANCE,
) -> dict[str, Any]:
    """Score findings against ground truth, honouring the LLM's verdict asymmetrically.

    Previously the scorer only honoured ``FALSE_POSITIVE`` (subtracted from
    matching); ``TRUE_POSITIVE`` and ``UNCERTAIN`` were merged.  That made
    the LLM triage step incapable of moving TP/FP/FN and was the primary
    cause of the k-invariant metrics documented in ``results/full/...``.

    The redesigned matrix (Phase-B1 + evidence extension)::

        verdict           gt_match  source_in_snippet -> label                      TP FP FN
        -------           --------  -----------------    ------                     -- -- --
        FALSE_POSITIVE    no_match        any         -> tn                                 (suppressed)
        FALSE_POSITIVE    match           any         -> fn_by_llm                  .  .  1 (LLM killed a real bug)
        TRUE_POSITIVE     match           true        -> tp                         1  .  .
        TRUE_POSITIVE     match           false       -> fp_by_hallucinated_source  .  1  . (TP on GT line but source_expr invented)
        TRUE_POSITIVE     no_match        true        -> fp_by_llm_overclaim        .  1  .
        TRUE_POSITIVE     no_match        false       -> fp_by_hallucinated_source  .  1  .
        UNCERTAIN         match           any         -> tp                         1  .  . (parity w/ previous)
        UNCERTAIN         no_match        any         -> fp_by_location             .  1  . (parity w/ previous)

    FN over the whole CVE is ``|vuln_lines - matched_lines|`` where
    ``matched_lines`` only counts findings the LLM did *not* suppress
    *and* did not justify with a hallucinated ``source_expr``.  If the
    LLM suppresses a finding that *was* on a ground-truth line, that
    ground-truth line becomes an ``fn_by_llm`` (since a true alert was
    retracted) in addition to still contributing to the ``fn`` count.

    Back-compat: when ``TriageResult.source_expr == ""`` (pre-evidence
    runs or scripted results that predate the field)
    ``source_in_snippet`` is treated as ``True``, preserving the
    Phase-B1 behaviour unchanged.
    """
    vuln_file = ground_truth.get("vulnerable_file", "")
    vuln_lines: set[int] = set(ground_truth.get("vulnerable_lines", []))
    dedup_winner_indexes, dedup_dropped = _select_dedup_winners(
        findings,
        triage_results,
        vuln_file=vuln_file,
        vuln_lines=vuln_lines,
        line_tolerance=line_tolerance,
    )

    pre_dedup_metrics = _score_with_winner_set(
        findings,
        triage_results,
        vuln_file=vuln_file,
        vuln_lines=vuln_lines,
        line_tolerance=line_tolerance,
        winner_indexes=set(range(len(findings))),
        dedup_dropped=0,
    )
    return _score_with_winner_set(
        findings,
        triage_results,
        vuln_file=vuln_file,
        vuln_lines=vuln_lines,
        line_tolerance=line_tolerance,
        winner_indexes=dedup_winner_indexes,
        dedup_dropped=dedup_dropped,
        pre_dedup_metrics=pre_dedup_metrics,
    )


def _score_with_winner_set(
    findings: list[Finding],
    triage_results: list[Any],
    *,
    vuln_file: str,
    vuln_lines: set[int],
    line_tolerance: int,
    winner_indexes: set[int],
    dedup_dropped: int,
    pre_dedup_metrics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Score findings using the provided ``winner_indexes`` for dedup gating.

    Called twice from :func:`label_findings`: once with all indexes treated as
    winners (``pre_dedup_metrics`` view) and once with the dedup-selected set
    (post-dedup view).  The pre-dedup result is returned as a sub-dict on the
    post-dedup view so a single ``label_findings`` call surfaces both metric
    families without changing the top-level shape.
    """
    tp = 0
    fp = 0
    fn_by_llm = 0  # ground-truth alerts the LLM retracted (subset of total FN)
    fp_by_hallucinated_source = 0  # subset of fp: TPs with source_expr not in snippet
    labels: list[str] = []

    matched_vuln_lines: set[int] = (
        set()
    )  # matched by a surviving (non-suppressed, non-hallucinated) finding
    flow_path_matched_vuln_lines: set[int] = set()
    same_file_flow_matched_vuln_lines: set[int] = set()
    report_candidate_matched_vuln_lines: set[int] = set()
    origin_external_tp_candidates = 0
    tp_via_report_candidate = 0
    tp_via_report_candidate_caller_external = 0
    report_candidate_promotion_blocked_by_origin_gate = 0
    tp_via_same_package = 0
    tp_via_same_package_with_origin = 0
    tp_via_same_package_blocked_by_origin_gate = 0
    tp_via_same_package_promoted = 0
    tp_strict_by_llm_tp = 0
    tp_strict_by_llm_uncertain = 0
    same_package_promoted_finding_indexes: list[int] = []

    for idx, (f, t) in enumerate(zip(findings, triage_results, strict=False)):
        if idx not in winner_indexes:
            labels.append("dedup_dropped")
            continue

        is_match, matched_line = _gt_line_match(
            f,
            vuln_file,
            vuln_lines,
            line_tolerance,
        )
        is_flow_match, flow_matched_line = _gt_joern_flow_match(
            f,
            vuln_file,
            vuln_lines,
            line_tolerance,
        )
        (
            is_report_candidate_match,
            report_candidate_matched_line,
            report_candidate_external,
        ) = _gt_joern_report_candidate_match(
            f,
            vuln_file,
            vuln_lines,
            line_tolerance,
        )

        source_expr = (getattr(t, "source_expr", "") or "").strip()
        snippet = _snippet_for(f)
        # Parity: empty source_expr ⇒ treat as "present" so pre-evidence
        # runs aren't mass-flagged as hallucinations.
        source_in_snippet = (not source_expr) or (source_expr in snippet)
        meta = getattr(f, "metadata", {}) or {}
        if not isinstance(meta, dict):
            meta = {}
        origin_external = bool(meta.get("originExternalSource", False))
        report_candidate_promotable = (
            is_report_candidate_match and report_candidate_matched_line is not None
        )
        report_candidate_origin_ok = bool(origin_external or report_candidate_external)

        if t.verdict == Verdict.FALSE_POSITIVE:
            if is_match:
                fn_by_llm += 1
                labels.append("fn_by_llm")
            else:
                labels.append("tn")
            continue

        if t.verdict == Verdict.TRUE_POSITIVE:
            if not source_in_snippet:
                # Hallucination brake at scorer level: a TP citing a
                # source expression not in the snippet/Joern evidence is counted as an
                # FP regardless of line match.  The corresponding GT
                # line does NOT enter matched_vuln_lines, so it still
                # accrues an FN below.
                fp += 1
                fp_by_hallucinated_source += 1
                labels.append("fp_by_hallucinated_source")
                continue
            if is_match:
                tp += 1
                tp_strict_by_llm_tp += 1
                if origin_external:
                    origin_external_tp_candidates += 1
                if matched_line is not None:
                    matched_vuln_lines.add(matched_line)
                labels.append("tp")
            elif report_candidate_promotable and report_candidate_origin_ok:
                tp += 1
                tp_via_report_candidate += 1
                if origin_external:
                    origin_external_tp_candidates += 1
                if report_candidate_external and not origin_external:
                    tp_via_report_candidate_caller_external += 1
                matched_vuln_lines.add(report_candidate_matched_line)
                labels.append("tp_via_report_candidate")
            else:
                if report_candidate_promotable:
                    report_candidate_promotion_blocked_by_origin_gate += 1
                same_package = _same_package(f.file_path, vuln_file)
                if same_package:
                    tp_via_same_package += 1
                    if origin_external:
                        tp_via_same_package_with_origin += 1
                    else:
                        tp_via_same_package_blocked_by_origin_gate += 1
                if origin_external and same_package:
                    tp_via_same_package_promoted += 1
                    same_package_promoted_finding_indexes.append(idx)
                fp += 1
                labels.append("fp_by_llm_overclaim")
            if is_flow_match and flow_matched_line is not None:
                flow_path_matched_vuln_lines.add(flow_matched_line)
                if any(
                    _location_line_match(
                        file_path, line, vuln_file, vuln_lines, line_tolerance
                    )[0]
                    and Path(file_path).name == Path(vuln_file).name
                    for file_path, line in _joern_flow_locations(f)
                ):
                    same_file_flow_matched_vuln_lines.add(flow_matched_line)
            if is_report_candidate_match and report_candidate_matched_line is not None:
                report_candidate_matched_vuln_lines.add(report_candidate_matched_line)
            continue

        # UNCERTAIN (and any unexpected verdict): parity with previous logic.
        if is_match:
            tp += 1
            tp_strict_by_llm_uncertain += 1
            if origin_external:
                origin_external_tp_candidates += 1
            if matched_line is not None:
                matched_vuln_lines.add(matched_line)
            labels.append("tp")
        elif report_candidate_promotable and report_candidate_origin_ok:
            tp += 1
            tp_via_report_candidate += 1
            if origin_external:
                origin_external_tp_candidates += 1
            if report_candidate_external and not origin_external:
                tp_via_report_candidate_caller_external += 1
            matched_vuln_lines.add(report_candidate_matched_line)
            labels.append("tp_via_report_candidate")
        else:
            if report_candidate_promotable:
                report_candidate_promotion_blocked_by_origin_gate += 1
            same_package = _same_package(f.file_path, vuln_file)
            if same_package:
                tp_via_same_package += 1
                if origin_external:
                    tp_via_same_package_with_origin += 1
                else:
                    tp_via_same_package_blocked_by_origin_gate += 1
            if origin_external and same_package:
                tp_via_same_package_promoted += 1
                same_package_promoted_finding_indexes.append(idx)
            fp += 1
            labels.append("fp_by_location")
        if is_flow_match and flow_matched_line is not None:
            flow_path_matched_vuln_lines.add(flow_matched_line)
            if any(
                _location_line_match(
                    file_path, line, vuln_file, vuln_lines, line_tolerance
                )[0]
                and Path(file_path).name == Path(vuln_file).name
                for file_path, line in _joern_flow_locations(f)
            ):
                same_file_flow_matched_vuln_lines.add(flow_matched_line)
        if is_report_candidate_match and report_candidate_matched_line is not None:
            report_candidate_matched_vuln_lines.add(report_candidate_matched_line)

    fn = len(vuln_lines - matched_vuln_lines)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    metrics = {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "fn_by_llm": fn_by_llm,
        "fp_by_hallucinated_source": fp_by_hallucinated_source,
        "flow_path_tp": len(flow_path_matched_vuln_lines),
        "same_file_flow_path_tp": len(same_file_flow_matched_vuln_lines),
        "report_candidate_location_tp": len(report_candidate_matched_vuln_lines),
        "origin_external_tp_candidates": origin_external_tp_candidates,
        "tp_via_report_candidate": tp_via_report_candidate,
        "tp_via_report_candidate_caller_external": (
            tp_via_report_candidate_caller_external
        ),
        "report_candidate_promotion_blocked_by_origin_gate": report_candidate_promotion_blocked_by_origin_gate,
        "tp_via_same_package": tp_via_same_package,
        "tp_via_same_package_with_origin": tp_via_same_package_with_origin,
        "tp_via_same_package_blocked_by_origin_gate": tp_via_same_package_blocked_by_origin_gate,
        "tp_via_same_package_promoted": tp_via_same_package_promoted,
        "tp_strict_by_llm_tp": tp_strict_by_llm_tp,
        "tp_strict_by_llm_uncertain": tp_strict_by_llm_uncertain,
        "same_package_promoted_finding_indexes": same_package_promoted_finding_indexes,
        "relaxed_tp": tp + tp_via_same_package_promoted,
        "dedup_dropped": dedup_dropped,
        "flow_path_matched_lines": sorted(flow_path_matched_vuln_lines),
        "same_file_flow_path_matched_lines": sorted(same_file_flow_matched_vuln_lines),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "detection_rate": 1.0 if tp > 0 else 0.0,
        "labels": labels,
    }
    if pre_dedup_metrics is not None:
        metrics["pre_dedup_metrics"] = pre_dedup_metrics
    return metrics


# ======================================================================
# Repo management
# ======================================================================


def clone_and_checkout(
    repo_url: str, commit: str, dest: Path, *, shallow: bool = True
) -> bool:
    """Clone *repo_url* into *dest* and checkout *commit*.

    Hardened for the 90-CVE Run G sweep: extends the per-step subprocess
    timeouts (clone 300s, fetch 300s, checkout 120s) and retries the full
    clone+fetch+checkout sequence up to ``max_attempts`` times on
    ``TimeoutExpired`` / ``CalledProcessError``.  ``dest`` is wiped between
    attempts to avoid stacking partial state.
    """
    max_attempts = 3
    last_exc: Exception | None = None

    for attempt in range(1, max_attempts + 1):
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        dest.mkdir(parents=True, exist_ok=True)

        try:
            clone_cmd = ["git", "clone"]
            if shallow:
                clone_cmd += ["--depth", "1"]
            clone_cmd += [repo_url, str(dest)]
            subprocess.run(
                clone_cmd, capture_output=True, text=True, timeout=300, check=True
            )

            subprocess.run(
                ["git", "fetch", "--depth=1", "origin", commit],
                cwd=str(dest),
                capture_output=True,
                text=True,
                timeout=300,
            )
            subprocess.run(
                ["git", "checkout", commit],
                cwd=str(dest),
                capture_output=True,
                text=True,
                timeout=120,
                check=True,
            )
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            last_exc = exc
            logger.warning(
                "clone_and_checkout attempt %d/%d failed for %s@%s: %s",
                attempt,
                max_attempts,
                repo_url,
                commit[:8],
                exc,
            )
            if attempt < max_attempts:
                time.sleep(min(5 * attempt, 15))

    logger.warning(
        "Failed to clone/checkout %s@%s after %d attempts: %s",
        repo_url,
        commit[:8],
        max_attempts,
        last_exc,
    )
    return False


def count_loc(repo_path: Path) -> int:
    """Count Python lines of code using tokei if available, else wc."""
    try:
        result = subprocess.run(
            ["tokei", "-t", "Python", "-o", "json", str(repo_path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            py = data.get("Python", data.get("python", {}))
            if isinstance(py, dict):
                return py.get("code", 0)
    except (FileNotFoundError, json.JSONDecodeError, subprocess.TimeoutExpired):
        pass

    total = 0
    for pyfile in repo_path.rglob("*.py"):
        try:
            # Read as bytes so non-UTF-8 source files (e.g. latin-1 / mojibake in
            # older Python 2 code) don't abort the whole evaluation sweep.
            with pyfile.open("rb") as fh:
                for raw in fh:
                    if raw.strip():
                        total += 1
        except OSError:
            pass
    return total


# ======================================================================
# Resource monitoring
# ======================================================================


def get_resource_snapshot() -> dict[str, Any]:
    proc = psutil.Process(os.getpid())
    mem = proc.memory_info()
    ru = resource.getrusage(resource.RUSAGE_SELF)
    return {
        "peak_rss_mb": mem.rss / (1024 * 1024),
        "cpu_user_s": ru.ru_utime,
        "cpu_sys_s": ru.ru_stime,
    }


# ======================================================================
# Main evaluation loop
# ======================================================================


def _cleanup_stray_joern(port: int = 12345) -> None:
    """Best-effort kill of any lingering Joern server subprocesses.

    Called after a per-CVE timeout fires.  The pipeline's ``finally`` block
    should normally tear Joern down, but a cancellation mid-query can leave
    the JVM running and port 12345 bound, which would poison the next CVE.
    """
    matched: list[psutil.Process] = []
    for proc in psutil.process_iter(["pid", "cmdline"]):
        try:
            cmd = " ".join(proc.info.get("cmdline") or [])
            listens_on_port = any(
                conn.laddr.port == port and conn.status == psutil.CONN_LISTEN
                for conn in proc.net_connections(kind="inet")
            )
        except psutil.Error:
            continue
        if listens_on_port or "joern-cli/joern" in cmd or "ReplBridge" in cmd:
            matched.append(proc)

    for proc in matched:
        try:
            for child in proc.children(recursive=True):
                try:
                    child.terminate()
                except psutil.Error:
                    continue
            proc.terminate()
        except psutil.Error:
            continue

    gone, alive = psutil.wait_procs(matched, timeout=5)
    del gone
    for proc in alive:
        try:
            for child in proc.children(recursive=True):
                try:
                    child.kill()
                except psutil.Error:
                    continue
            proc.kill()
        except psutil.Error:
            continue

    try:
        subprocess.run(
            ["pkill", "-9", "-f", "joern-cli/joern|ReplBridge"],
            check=False,
            timeout=10,
        )
    except Exception:
        logger.exception("_cleanup_stray_joern failed")


def _process_tree_stats(pid: int | None) -> dict[str, Any]:
    """Best-effort snapshot of a process plus descendants."""
    if not pid:
        return {"process_count": 0, "rss_mb": 0.0, "pids": []}
    try:
        root = psutil.Process(pid)
        procs = [root, *root.children(recursive=True)]
    except psutil.Error:
        return {"process_count": 0, "rss_mb": 0.0, "pids": []}

    rss = 0
    pids: list[int] = []
    for proc in procs:
        try:
            pids.append(proc.pid)
            rss += proc.memory_info().rss
        except psutil.Error:
            continue
    return {
        "process_count": len(pids),
        "rss_mb": rss / (1024 * 1024),
        "pids": pids,
    }


def _terminate_process_group(
    pid: int | None, *, grace_s: float = 5.0
) -> dict[str, Any]:
    """Terminate a child process group, escalating to SIGKILL if needed."""
    stats_before = _process_tree_stats(pid)
    if not pid:
        return {
            "terminate_signal": None,
            "kill_signal": None,
            "process_tree_before": stats_before,
            "process_tree_after": stats_before,
        }

    try:
        pgid = os.getpgid(pid)
    except OSError:
        return {
            "terminate_signal": None,
            "kill_signal": None,
            "process_tree_before": stats_before,
            "process_tree_after": _process_tree_stats(pid),
        }

    kill_sent = False
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except OSError:
        logger.exception("Failed to SIGTERM process group %s", pgid)

    deadline = time.monotonic() + grace_s
    while time.monotonic() < deadline:
        if not psutil.pid_exists(pid):
            break
        time.sleep(0.1)

    if psutil.pid_exists(pid):
        try:
            os.killpg(pgid, signal.SIGKILL)
            kill_sent = True
        except ProcessLookupError:
            pass
        except OSError:
            logger.exception("Failed to SIGKILL process group %s", pgid)

    return {
        "terminate_signal": "SIGTERM",
        "kill_signal": "SIGKILL" if kill_sent else None,
        "process_tree_before": stats_before,
        "process_tree_after": _process_tree_stats(pid),
    }


def _pipeline_child_main(
    conn: Any,
    pipeline_cfg: PipelineConfig,
    repo_path: str,
    cve_id: str,
) -> None:
    """Child entry point for Joern process-isolated execution."""
    try:
        os.setsid()
    except OSError:
        logger.exception("Child failed to create a new process session")

    try:
        res_before = get_resource_snapshot()
        run_result = asyncio.run(Pipeline(pipeline_cfg).run(repo_path, cve_id=cve_id))
        res_after = get_resource_snapshot()
        conn.send(
            {
                "status": "ok",
                "result": run_result,
                "resource_delta": {
                    key: res_after[key] - res_before.get(key, 0) for key in res_after
                },
            }
        )
    except BaseException as exc:  # noqa: BLE001 - child must report any fatal path
        try:
            conn.send(
                {
                    "status": "error",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "traceback": traceback.format_exc(),
                }
            )
        except Exception:
            pass
    finally:
        conn.close()


def _pipeline_uses_joern(pipeline_cfg: PipelineConfig) -> bool:
    return any(getattr(arm, "value", arm) == "joern" for arm in pipeline_cfg.arms)


async def _run_with_timeout(
    pipeline_cfg: PipelineConfig,
    repo_path: str,
    cve_id: str,
    timeout_s: float,
) -> tuple[Any, bool, dict[str, Any], dict[str, Any]]:
    """Run ``pipeline.run`` with a wall-clock budget.

    Joern runs use process isolation because Joern query/client calls can
    block the event loop.  Non-Joern arms keep the cheaper coroutine timeout.
    """
    run_meta: dict[str, Any] = {
        "per_cve_timeout_s": timeout_s,
        "timeout_scope": "coroutine",
        "timeout_stage": "pipeline.run",
    }

    if not _pipeline_uses_joern(pipeline_cfg):
        pipeline = Pipeline(pipeline_cfg)
        if timeout_s and timeout_s > 0:
            try:
                result = await asyncio.wait_for(
                    pipeline.run(repo_path, cve_id=cve_id),
                    timeout=timeout_s,
                )
                return result, False, run_meta, {}
            except asyncio.TimeoutError:
                logger.warning(
                    "  %s: pipeline.run exceeded %.0fs budget, aborting this CVE",
                    cve_id,
                    timeout_s,
                )
                _cleanup_stray_joern()
                return None, True, run_meta, {}
        return await pipeline.run(repo_path, cve_id=cve_id), False, run_meta, {}

    if not timeout_s or timeout_s <= 0:
        res_before = get_resource_snapshot()
        result = await Pipeline(pipeline_cfg).run(repo_path, cve_id=cve_id)
        res_after = get_resource_snapshot()
        return (
            result,
            False,
            {**run_meta, "timeout_scope": "disabled"},
            {key: res_after[key] - res_before.get(key, 0) for key in res_after},
        )

    # A previous interrupted Joern run can leave the JVM bound to the fixed
    # port.  Clear that before the isolated child starts so one stale server
    # does not poison the rest of the sweep.
    _cleanup_stray_joern(port=getattr(pipeline_cfg, "joern_port", 12345))

    parent_conn, child_conn = mp.Pipe(duplex=False)
    proc = mp.Process(
        target=_pipeline_child_main,
        args=(child_conn, pipeline_cfg, repo_path, cve_id),
        name=f"auditzoo-{cve_id}-pipeline",
    )
    start = time.monotonic()
    proc.start()
    child_conn.close()

    run_meta.update(
        {
            "timeout_scope": "process_group",
            "child_pid": proc.pid,
            "joern_port": getattr(pipeline_cfg, "joern_port", None),
        }
    )

    deadline = start + timeout_s
    payload: dict[str, Any] | None = None
    while proc.is_alive() and time.monotonic() < deadline:
        if parent_conn.poll():
            try:
                payload = parent_conn.recv()
            except EOFError:
                payload = None
            break
        await asyncio.sleep(min(0.25, max(0.01, deadline - time.monotonic())))

    run_meta["elapsed_s"] = time.monotonic() - start

    if proc.is_alive() and payload is None:
        logger.warning(
            "  %s: child pipeline exceeded %.0fs budget, killing process group",
            cve_id,
            timeout_s,
        )
        run_meta.update(_terminate_process_group(proc.pid, grace_s=1.0))
        proc.join(timeout=5)
        _cleanup_stray_joern()
        parent_conn.close()
        return None, True, run_meta, {}

    proc.join(timeout=1)
    run_meta["child_exitcode"] = proc.exitcode

    if payload is None and parent_conn.poll():
        try:
            payload = parent_conn.recv()
        except EOFError:
            payload = None
    parent_conn.close()

    if payload and payload.get("status") == "ok":
        return (
            payload.get("result"),
            False,
            run_meta,
            payload.get("resource_delta", {}) or {},
        )

    if payload and payload.get("status") == "error":
        run_meta.update(
            {
                "child_error_type": payload.get("error_type", ""),
                "child_error": payload.get("error", ""),
                "child_traceback": payload.get("traceback", ""),
            }
        )
    else:
        run_meta["child_error"] = "child exited without sending a result"
    return None, False, run_meta, {}


async def run_main_comparison(
    dataset: list[dict[str, Any]],
    pipeline_cfg: PipelineConfig,
    clone_dir: Path,
    output_dir: Path,
    *,
    line_tolerance: int = LINE_TOLERANCE,
    skip_empty_gt: bool = True,
    per_cve_timeout: float = 900.0,
    skip_cves: list[str] | None = None,
    run_patched: bool = True,
) -> list[dict[str, Any]]:
    """Run 2 tools x 4 k-levels x N CVEs x 2 commits."""
    all_results: list[dict[str, Any]] = []
    skip_set = set(skip_cves or [])

    for idx, cve in enumerate(dataset):
        cve_id = cve["cve_id"]
        logger.info("[%d/%d] Processing %s", idx + 1, len(dataset), cve_id)

        if cve_id in skip_set:
            logger.info("  Skipping %s — on --skip-cves list", cve_id)
            all_results.append({"cve_id": cve_id, "skipped": "explicit"})
            _save_json(all_results, output_dir / "results.json")
            continue

        if skip_empty_gt and not cve.get("vulnerable_lines"):
            logger.info("  Skipping %s — no ground-truth lines", cve_id)
            continue

        repo_dest = clone_dir / cve_id
        try:
            repo_url = cve["repo_url"]
            vuln_commit = cve["vulnerable_commit"]
            patch_commit = cve["patch_commit"]

            # --- vulnerable commit ---
            ok = clone_and_checkout(repo_url, vuln_commit, repo_dest)
            if not ok:
                logger.warning("  Skipping %s — clone failed", cve_id)
                continue

            loc = count_loc(repo_dest)

            vuln_run, timed_out, run_meta, resource_delta = await _run_with_timeout(
                pipeline_cfg,
                str(repo_dest),
                cve_id,
                per_cve_timeout,
            )

            if timed_out:
                all_results.append(
                    {
                        "cve_id": cve_id,
                        "repo_url": repo_url,
                        "loc": loc,
                        "skipped": "timeout",
                        "per_cve_timeout_s": per_cve_timeout,
                        "timeout_meta": run_meta,
                    }
                )
                _save_json(all_results, output_dir / "results.json")
                shutil.rmtree(repo_dest, ignore_errors=True)
                continue
            if vuln_run is None:
                all_results.append(
                    {
                        "cve_id": cve_id,
                        "repo_url": repo_url,
                        "loc": loc,
                        "skipped": "error",
                        "error": run_meta.get(
                            "child_error", "pipeline returned no result"
                        ),
                        "error_type": run_meta.get(
                            "child_error_type", "PipelineNoResult"
                        ),
                        "run_meta": run_meta,
                    }
                )
                _save_json(all_results, output_dir / "results.json")
                shutil.rmtree(repo_dest, ignore_errors=True)
                continue

            # --- patched commit ---
            # ``run_patched=False`` is the v1 Joern-sweep default: Joern's
            # dominant cost is CPG construction, and repeating it on the
            # patched commit inside the same per-CVE budget was the primary
            # timeout driver in the 20260421_123649 sweep.  Skipping it
            # trades the "alerts-on-patched = FP" signal for enough budget
            # headroom to actually finish each CVE.
            patch_run = None
            if run_patched:
                ok_patch = clone_and_checkout(repo_url, patch_commit, repo_dest)
                if ok_patch:
                    patch_run, patch_timed_out, patch_meta, _ = await _run_with_timeout(
                        pipeline_cfg,
                        str(repo_dest),
                        cve_id,
                        per_cve_timeout,
                    )
                    if patch_timed_out:
                        logger.warning(
                            "  %s: patched run timed out: %s",
                            cve_id,
                            patch_meta,
                        )
                        patch_run = None

            # --- labelling ---
            cve_result: dict[str, Any] = {
                "cve_id": cve_id,
                "repo_url": repo_url,
                "loc": loc,
                "cvss_score": cve.get("cvss_score"),
                "arms": {},
            }

            for iteration in vuln_run.iterations:
                arm_key = f"{iteration.arm}_{iteration.iteration}"
                gt_labels = label_findings(
                    iteration.findings,
                    iteration.triage_results,
                    cve,
                    line_tolerance=line_tolerance,
                )
                fp_kloc = gt_labels["fp"] / (loc / 1000) if loc > 0 else 0.0

                arm_entry: dict[str, Any] = {
                    **gt_labels,
                    "fp_kloc": fp_kloc,
                    "metrics": iteration.metrics,
                    "n_candidates": len(iteration.findings),
                    "triage_verdicts": serialize_triage_verdicts(
                        iteration.findings,
                        iteration.triage_results,
                        ground_truth=cve,
                    ),
                    "refinement_actions": list(iteration.refinement_actions or []),
                    "resource_delta": resource_delta,
                    "run_meta": run_meta,
                }
                if iteration.metrics.get("cpg_build_failed"):
                    # Surface CPG build failures as a top-level column so
                    # downstream analysis does not conflate them with
                    # "arm produced zero findings successfully".
                    arm_entry["arm_error"] = iteration.metrics.get("error")
                    arm_entry["arm_error_type"] = iteration.metrics.get("error_type")
                cve_result["arms"][arm_key] = arm_entry

            if patch_run:
                for iteration in patch_run.iterations:
                    arm_key = f"{iteration.arm}_{iteration.iteration}_patched"
                    n_findings_on_patched = len(iteration.findings)
                    cve_result["arms"][arm_key] = {
                        "n_findings_on_patched": n_findings_on_patched,
                        "metrics": iteration.metrics,
                        "triage_verdicts": serialize_triage_verdicts(
                            iteration.findings,
                            iteration.triage_results,
                            ground_truth=cve,
                        ),
                        "refinement_actions": list(iteration.refinement_actions or []),
                    }

            all_results.append(cve_result)

            # save incrementally
            _save_json(all_results, output_dir / "results.json")

        except (KeyboardInterrupt, asyncio.CancelledError):
            # Honour user/system cancellation: flush partial results and re-raise
            # so callers can shut the whole sweep down cleanly.
            _save_json(all_results, output_dir / "results.json")
            shutil.rmtree(repo_dest, ignore_errors=True)
            raise
        except Exception as exc:  # noqa: BLE001 — isolate per-CVE failures
            logger.exception("  %s: unhandled error, skipping CVE: %s", cve_id, exc)
            all_results.append(
                {
                    "cve_id": cve_id,
                    "repo_url": cve.get("repo_url"),
                    "skipped": "error",
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            _save_json(all_results, output_dir / "results.json")
            _cleanup_stray_joern()
        finally:
            shutil.rmtree(repo_dest, ignore_errors=True)

    return all_results


async def run_variance_analysis(
    dataset: list[dict[str, Any]],
    pipeline_cfg: PipelineConfig,
    clone_dir: Path,
    output_dir: Path,
    *,
    n_repos: int = 20,
    seeds: list[int] | None = None,
) -> list[dict[str, Any]]:
    """Variance analysis: Semgrep, k=3, *n_repos* random CVEs, multiple seeds."""
    seeds = seeds or [235711, 123456, 654321, 111111, 999999]

    random.seed(pipeline_cfg.seed)
    subset = random.sample(dataset, min(n_repos, len(dataset)))

    variance_cfg = PipelineConfig(
        max_iterations=3,
        arms=["semgrep"],
        seed=pipeline_cfg.seed,
        llm_base_url=pipeline_cfg.llm_base_url,
        llm_model=pipeline_cfg.llm_model,
        llm_temperature=pipeline_cfg.llm_temperature,
        llm_api_key=pipeline_cfg.llm_api_key,
    )

    all_results: list[dict[str, Any]] = []

    for cve in subset:
        cve_id = cve["cve_id"]
        repo_dest = clone_dir / cve_id
        ok = clone_and_checkout(cve["repo_url"], cve["vulnerable_commit"], repo_dest)
        if not ok:
            continue

        seed_results: dict[str, Any] = {"cve_id": cve_id, "seeds": {}}

        for seed in seeds:
            variance_cfg.seed = seed
            pipeline = Pipeline(variance_cfg)
            run_result = await pipeline.run(str(repo_dest), cve_id=cve_id)

            last_iter = [
                it
                for it in run_result.iterations
                if it.arm == ToolArm.SEMGREP and it.iteration == 3
            ]
            if last_iter:
                gt = label_findings(
                    last_iter[0].findings, last_iter[0].triage_results, cve
                )
                seed_results["seeds"][str(seed)] = {
                    **gt,
                    "metrics": last_iter[0].metrics,
                    "finding_ids": [
                        f"{f.file_path}:{f.line_start}" for f in last_iter[0].findings
                    ],
                    "verdicts": [t.verdict.value for t in last_iter[0].triage_results],
                }

        all_results.append(seed_results)
        shutil.rmtree(repo_dest, ignore_errors=True)

    _save_json(all_results, output_dir / "variance_results.json")
    return all_results


def _save_json(data: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str))


# ======================================================================
# CLI entry point
# ======================================================================


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="CWE-78 evaluation harness")
    p.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    p.add_argument("--clone-dir", type=Path, default=DEFAULT_CLONE_DIR)
    p.add_argument("--arms", nargs="+", default=["semgrep", "joern"])
    p.add_argument("--max-k", type=int, default=3)
    p.add_argument("--seed", type=int, default=235711)
    p.add_argument("--llm-url", default="http://localhost:8000/v1")
    p.add_argument("--llm-model", default="Qwen/Qwen2.5-Coder-7B-Instruct")
    p.add_argument("--joern-port", type=int, default=12345)
    p.add_argument(
        "--variance", action="store_true", help="Run variance analysis instead"
    )
    p.add_argument("--variance-n", type=int, default=20)
    p.add_argument(
        "--variance-seeds",
        nargs="+",
        type=int,
        default=[235711, 123456, 654321, 111111, 999999],
    )
    p.add_argument("--line-tolerance", type=int, default=LINE_TOLERANCE)
    p.add_argument("--skip-empty-gt", action="store_true", default=True)
    p.add_argument(
        "--per-cve-timeout",
        type=float,
        default=900.0,
        help="Wall-clock seconds budget per pipeline.run(); 0 disables.  "
        "On timeout the CVE is recorded as 'timed_out' and we move on.",
    )
    p.add_argument(
        "--skip-cves",
        nargs="+",
        default=[],
        help="CVE IDs to skip entirely (e.g. pathologically large repos).",
    )
    p.add_argument(
        "--only-cves",
        nargs="+",
        default=[],
        help="If non-empty, restrict evaluation to these CVE IDs only "
        "(used for Phase-A3 deep dives).",
    )
    p.add_argument(
        "--log-llm-io",
        type=Path,
        default=None,
        help="Append every LLM chat round-trip (prompt + response) as JSONL "
        "to this path.  Useful for debugging the UNCERTAIN-collapse root "
        "cause; leave unset for production runs (writes are unbatched).",
    )
    return p.parse_args()


async def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    # Silence the very chatty autogen-core message envelope logs so the eval
    # log stays readable (each agent round-trip otherwise produces ~10 KB of
    # INFO-level JSON).  The analysis-relevant info we care about is emitted
    # by the pipeline itself and by __main__ below.
    for noisy in ("autogen_core", "autogen_core.events", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    dataset = json.loads(args.dataset.read_text())
    logger.info("Loaded %d CVEs from %s", len(dataset), args.dataset)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = args.output / timestamp
    output_dir.mkdir(parents=True, exist_ok=True)

    pipeline_cfg = PipelineConfig(
        max_iterations=args.max_k,
        seed=args.seed,
        arms=args.arms,
        llm_base_url=args.llm_url,
        llm_model=args.llm_model,
        joern_port=args.joern_port,
        llm_log_io_path=str(args.log_llm_io) if args.log_llm_io else None,
    )

    if args.only_cves:
        keep = set(args.only_cves)
        before = len(dataset)
        dataset = [c for c in dataset if c.get("cve_id") in keep]
        logger.info(
            "Restricted dataset to %d/%d CVEs via --only-cves: %s",
            len(dataset),
            before,
            sorted(keep),
        )

    # Save run config
    _save_json(vars(args), output_dir / "run_config.json")

    if args.variance:
        logger.info(
            "Running variance analysis (%d repos, %d seeds)",
            args.variance_n,
            len(args.variance_seeds),
        )
        await run_variance_analysis(
            dataset,
            pipeline_cfg,
            args.clone_dir,
            output_dir,
            n_repos=args.variance_n,
            seeds=args.variance_seeds,
        )
    else:
        logger.info(
            "Running main comparison (%d CVEs, arms=%s, k=0..%d, per_cve_timeout=%.0fs, skip=%d)",
            len(dataset),
            args.arms,
            args.max_k,
            args.per_cve_timeout,
            len(args.skip_cves),
        )
        await run_main_comparison(
            dataset,
            pipeline_cfg,
            args.clone_dir,
            output_dir,
            line_tolerance=args.line_tolerance,
            skip_empty_gt=args.skip_empty_gt,
            per_cve_timeout=args.per_cve_timeout,
            skip_cves=args.skip_cves,
        )

    logger.info("Results saved to %s", output_dir)


if __name__ == "__main__":
    asyncio.run(main())
