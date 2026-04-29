#!/usr/bin/env python3
"""Audit false negatives from a Joern diagnostic ``results.json`` file.

The audit is intentionally read-only: it joins already-produced Joern
diagnostic results with the CWE-78 metadata, classifies each unmatched
ground-truth line, and writes compact JSON/CSV/Markdown artifacts for deciding
which Joern fix to attempt next.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from splitEvaluations.common import (  # noqa: E402
    DEFAULT_DATASET,
    LINE_TOLERANCE,
    _save_json,
)

DEFAULT_RESULTS_JSON = (
    ROOT / "results" / "gpt54_joern" / "20260426_131739" / "results.json"
)

OUTPUT_BASENAME = "joern_fn_audit"
MISSING_EVIDENCE_TERMS = (
    "source",
    "caller",
    "context",
    "dataflow",
    "origin",
    "definition",
    "taint",
)
SINK_SEMANTIC_FLAGS = (
    "shell_true",
    "shell_false",
    "argv_list_like",
    "string_command_like",
    "shlex_split_input",
    "literal_command_like",
    "test_file",
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--results-json",
        type=Path,
        default=DEFAULT_RESULTS_JSON if DEFAULT_RESULTS_JSON.exists() else None,
        required=not DEFAULT_RESULTS_JSON.exists(),
        help=(
            "Path to Joern diagnostic results.json "
            "(default: latest known 10-CVE run if present)."
        ),
    )
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Output directory (default: parent of --results-json).",
    )
    parser.add_argument("--arm-key", default="joern_0")
    parser.add_argument("--line-tolerance", type=int, default=LINE_TOLERANCE)
    parser.add_argument(
        "--format",
        nargs="+",
        choices=("json", "csv", "md"),
        default=["json", "csv", "md"],
        help="Artifact formats to write.",
    )
    return parser.parse_args(argv)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def load_metadata(dataset_path: Path) -> dict[str, dict[str, Any]]:
    dataset = load_json(dataset_path)
    return {
        str(row.get("cve_id", "")): row
        for row in dataset
        if isinstance(row, dict) and row.get("cve_id")
    }


def _path_matches(candidate_file: str, gt_file: str) -> bool:
    if not candidate_file or not gt_file:
        return False
    candidate = candidate_file.strip()
    gt = gt_file.strip()
    return (
        Path(candidate).name == Path(gt).name
        or candidate.endswith(gt)
        or gt.endswith(candidate)
    )


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
    return _shared_prefix_depth(candidate_file, gt_file) >= 2


def _candidate_distance(
    candidate: dict[str, Any], gt_file: str, gt_line: int
) -> int | None:
    if not _path_matches(str(candidate.get("file", "")), gt_file):
        return None
    try:
        return abs(int(candidate.get("line", 0)) - gt_line)
    except (TypeError, ValueError):
        return None


def _flow_location_parts(location: str) -> tuple[str, int] | None:
    file_path, sep, line_s = str(location).rpartition(":")
    if not sep or not file_path:
        return None
    try:
        line = int(line_s)
    except ValueError:
        return None
    return file_path, line


def _candidate_flow_match(
    candidate: dict[str, Any],
    gt_file: str,
    gt_line: int,
    line_tolerance: int,
) -> bool:
    for location in candidate.get("joern_flow_locations") or []:
        parsed = _flow_location_parts(str(location))
        if parsed is None:
            continue
        file_path, line = parsed
        if _path_matches(file_path, gt_file) and abs(line - gt_line) <= line_tolerance:
            return True
    return False


def _candidate_report_location_match(
    candidate: dict[str, Any],
    gt_file: str,
    gt_line: int,
    line_tolerance: int,
) -> bool:
    for location in candidate.get("reportCandidateLocations") or []:
        if not isinstance(location, dict):
            continue
        file_path = str(location.get("file", "") or "")
        try:
            line = int(location.get("line", 0) or 0)
        except (TypeError, ValueError):
            continue
        if _path_matches(file_path, gt_file) and abs(line - gt_line) <= line_tolerance:
            return True
    return False


def _evidence_count(candidates: list[dict[str, Any]], key: str) -> int:
    count = 0
    for candidate in candidates:
        records = candidate.get(key) or []
        if isinstance(records, list):
            count += len(records)
    return count


def _evidence_record_count(candidates: list[dict[str, Any]], key: str) -> int:
    count = 0
    for candidate in candidates:
        record = candidate.get(key) or {}
        if isinstance(record, dict) and record.get("file") and record.get("line"):
            count += 1
    return count


def _candidate_sort_key(
    candidate: dict[str, Any], gt_file: str, gt_line: int
) -> tuple[int, int, str]:
    distance = _candidate_distance(candidate, gt_file, gt_line)
    if distance is None:
        # Prefer same-package candidates before unrelated files.
        package_rank = (
            1 if _same_package(str(candidate.get("file", "")), gt_file) else 2
        )
        distance = 10**9
    else:
        package_rank = 0
    return (package_rank, distance, str(candidate.get("file", "")))


def _verdict_counts(candidates: list[dict[str, Any]]) -> dict[str, int]:
    return dict(sorted(Counter(str(c.get("verdict", "")) for c in candidates).items()))


def _top_counts(
    candidates: list[dict[str, Any]], key: str, limit: int = 5
) -> list[str]:
    counts = Counter(str(c.get(key, "")) for c in candidates if c.get(key))
    return [f"{item}:{count}" for item, count in counts.most_common(limit)]


def _top_semantic_flags(candidates: list[dict[str, Any]], limit: int = 8) -> list[str]:
    counts = Counter()
    for candidate in candidates:
        for flag in SINK_SEMANTIC_FLAGS:
            if candidate.get(flag):
                counts[flag] += 1
    return [f"{item}:{count}" for item, count in counts.most_common(limit)]


def _category_detail(category: str, candidates: list[dict[str, Any]]) -> str:
    if not candidates and category == "zero_candidate":
        return "zero_candidate_after_expanded_sources"
    if any(str(c.get("sinkKind", "")) == "wrapper" for c in candidates):
        return "wrapper_sink_candidate"
    if any(c.get(flag) for c in candidates for flag in SINK_SEMANTIC_FLAGS):
        return "semantic_filter_candidate"
    return category


def _has_missing_evidence_text(candidate: dict[str, Any]) -> bool:
    text = " ".join(
        str(candidate.get(field, "")).lower()
        for field in ("reasoning", "suggestion", "downgrade_reason")
    )
    return any(term in text for term in MISSING_EVIDENCE_TERMS) and any(
        marker in text
        for marker in (
            "not visible",
            "not shown",
            "missing",
            "include",
            "cannot",
            "without",
            "unknown",
        )
    )


def _matched_gt_lines(
    candidates: list[dict[str, Any]],
    gt_file: str,
    gt_lines: list[int],
    line_tolerance: int,
) -> set[int]:
    matched: set[int] = set()
    for candidate in candidates:
        verdict = str(candidate.get("verdict", ""))
        if verdict == "false_positive":
            continue
        if verdict == "true_positive" and candidate.get("source_in_snippet") is False:
            continue
        for gt_line in gt_lines:
            distance = _candidate_distance(candidate, gt_file, gt_line)
            if distance is not None and distance <= line_tolerance:
                matched.add(gt_line)
    return matched


def _nearest_candidate(
    candidates: list[dict[str, Any]], gt_file: str, gt_line: int
) -> dict[str, Any] | None:
    if not candidates:
        return None
    return min(candidates, key=lambda c: _candidate_sort_key(c, gt_file, gt_line))


def classify_fn(
    *,
    gt_file: str,
    gt_line: int,
    candidates: list[dict[str, Any]],
    line_tolerance: int,
) -> tuple[str, str]:
    if not candidates:
        return "zero_candidate", "Joern emitted no candidates for this CVE."

    same_file = [
        c for c in candidates if _candidate_distance(c, gt_file, gt_line) is not None
    ]
    near_suppressed = [
        c
        for c in same_file
        if (_candidate_distance(c, gt_file, gt_line) or 10**9) <= line_tolerance
        and str(c.get("verdict", "")) == "false_positive"
    ]
    if near_suppressed:
        return (
            "llm_suppressed_match",
            "A candidate was near the GT line but triage marked it false_positive.",
        )

    flow_matches = [
        c
        for c in candidates
        if str(c.get("verdict", "")) != "false_positive"
        and _candidate_flow_match(c, gt_file, gt_line, line_tolerance)
    ]
    if flow_matches:
        return (
            "flow_path_location_match",
            "A surviving Joern flow path reaches the GT line, but the primary finding location does not.",
        )

    related = [c for c in candidates if _same_package(str(c.get("file", "")), gt_file)]
    evidence_candidates = same_file or related
    if evidence_candidates:
        uncertain = [
            c for c in evidence_candidates if str(c.get("verdict", "")) == "uncertain"
        ]
        missing_evidence = [c for c in uncertain if _has_missing_evidence_text(c)]
        if uncertain and len(uncertain) >= max(1, len(evidence_candidates) // 2):
            if missing_evidence:
                return (
                    "triage_evidence_missing",
                    "Related candidates are mostly uncertain and ask for source/caller/dataflow context.",
                )

    if same_file:
        return (
            "same_file_near_miss",
            "Joern found candidates in the GT file, but not within line tolerance.",
        )

    location_counts = Counter(
        (str(c.get("file", "")), int(c.get("line", 0) or 0)) for c in candidates
    )
    if location_counts:
        _, top_count = location_counts.most_common(1)[0]
        if related and top_count >= max(2, len(candidates) // 3):
            return (
                "helper_sink_location",
                "Candidates cluster on a related helper or sink wrapper rather than the GT line.",
            )

    if related:
        return (
            "helper_sink_location",
            "Joern found related package/module candidates but not the GT file.",
        )

    return (
        "candidate_wrong_file",
        "Joern emitted candidates, but none are in the GT file or package.",
    )


def _coverage_refined_category(
    category: str,
    note: str,
    coverage_probe: dict[str, Any],
) -> tuple[str, str]:
    if category != "zero_candidate" or not coverage_probe:
        return category, note
    if not bool(coverage_probe.get("gt_file_seen", False)):
        return "coverage_no_gt_file", "Coverage probe did not find the GT file in CPG."
    if int(coverage_probe.get("gt_sink_count", 0) or 0) <= 0:
        return (
            "coverage_no_sink",
            "Coverage probe found the GT file but no catalog sink.",
        )
    if int(coverage_probe.get("external_source_count", 0) or 0) <= 0:
        return (
            "coverage_no_external_source",
            "Coverage probe found sinks but no external-source expression in the GT file.",
        )
    return (
        "zero_candidate_with_full_coverage",
        "Coverage probe found GT file, sink, and external-source signals; likely query/dataflow gap.",
    )


def _skipped_category_and_note(cve_result: dict[str, Any]) -> tuple[str, str]:
    skipped = str(cve_result.get("skipped", "") or "")
    if skipped == "timeout":
        meta = cve_result.get("timeout_meta") or {}
        elapsed = meta.get("elapsed_s", "")
        signal = meta.get("kill_signal", "")
        scope = meta.get("timeout_scope", "")
        return (
            "cpg_timeout",
            f"Joern run timed out after {elapsed}s; kill_signal={signal}; timeout_scope={scope}.",
        )
    if skipped == "error":
        error_type = str(cve_result.get("error_type", "") or "")
        error = str(cve_result.get("error", "") or "")[:180]
        return "cpg_error", f"Joern run failed before candidates: {error_type}: {error}"
    if skipped == "explicit":
        return "cpg_explicit_skip", "CVE was skipped by explicit configuration."
    return "", ""


def _empty_counts_row(
    *,
    cve_result: dict[str, Any],
    gt: dict[str, Any],
    gt_file: str,
    gt_line: int,
    arm_key: str,
    line_tolerance: int,
    category: str,
    note: str,
) -> dict[str, Any]:
    return {
        "cve_id": str(cve_result.get("cve_id", "")),
        "repo_url": cve_result.get("repo_url", gt.get("repo_url", "")),
        "gt_file": gt_file,
        "gt_line": gt_line,
        "arm_key": arm_key,
        "line_tolerance": line_tolerance,
        "fn_category": category,
        "fn_category_detail": category,
        "candidate_count": 0,
        "raw_candidate_count": 0,
        "triaged_candidate_count": 0,
        "dropped_candidate_count": 0,
        "dropped_reason_counts": {},
        "same_file_candidate_count": 0,
        "flow_path_match": False,
        "flow_path_match_count": 0,
        "report_candidate_location_match": False,
        "report_candidate_location_match_count": 0,
        "nearest_flow_locations": [],
        "nearest_candidate_file": "",
        "nearest_candidate_line": "",
        "nearest_distance": "",
        "verdict_counts": {},
        "top_candidate_files": [],
        "top_sink_apis": [],
        "top_source_kinds": [],
        "origin_external_source_count": 0,
        "origin_evidence_count": 0,
        "caller_evidence_count": 0,
        "report_candidate_location_count": 0,
        "triage_evidence_missing_with_origin": False,
        "top_sink_kinds": [],
        "top_sink_semantic_flags": [],
        "tp_via_same_package_count": 0,
        "tp_via_same_package_with_origin_count": 0,
        "coverage_probe": {},
        "evidence_notes": note,
    }


def build_fn_rows(
    results: list[dict[str, Any]],
    metadata_by_cve: dict[str, dict[str, Any]],
    *,
    arm_key: str = "joern_0",
    line_tolerance: int = LINE_TOLERANCE,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for cve_result in results:
        cve_id = str(cve_result.get("cve_id", ""))
        gt = metadata_by_cve.get(cve_id, {})
        gt_file = str(gt.get("vulnerable_file", "") or "")
        gt_lines = [int(line) for line in gt.get("vulnerable_lines", []) or []]
        if not gt_file or not gt_lines:
            continue

        skipped_category, skipped_note = _skipped_category_and_note(cve_result)
        if skipped_category:
            for gt_line in gt_lines:
                rows.append(
                    _empty_counts_row(
                        cve_result=cve_result,
                        gt=gt,
                        gt_file=gt_file,
                        gt_line=gt_line,
                        arm_key=arm_key,
                        line_tolerance=line_tolerance,
                        category=skipped_category,
                        note=skipped_note,
                    )
                )
            continue

        arm = (cve_result.get("arms") or {}).get(arm_key) or {}
        metrics = arm.get("metrics") or {}
        coverage_probe = metrics.get("joern_coverage_probe") or {}
        candidates = list(arm.get("triage_verdicts") or [])
        matched = _matched_gt_lines(candidates, gt_file, gt_lines, line_tolerance)
        missed_lines = [line for line in gt_lines if line not in matched]

        for gt_line in missed_lines:
            category, note = classify_fn(
                gt_file=gt_file,
                gt_line=gt_line,
                candidates=candidates,
                line_tolerance=line_tolerance,
            )
            category, note = _coverage_refined_category(category, note, coverage_probe)
            flow_matches = [
                c
                for c in candidates
                if str(c.get("verdict", "")) != "false_positive"
                and _candidate_flow_match(c, gt_file, gt_line, line_tolerance)
            ]
            report_location_matches = [
                c
                for c in candidates
                if str(c.get("verdict", "")) != "false_positive"
                and _candidate_report_location_match(
                    c, gt_file, gt_line, line_tolerance
                )
            ]
            nearest = _nearest_candidate(candidates, gt_file, gt_line)
            nearest_distance = (
                _candidate_distance(nearest, gt_file, gt_line) if nearest else None
            )
            same_file_count = sum(
                1
                for candidate in candidates
                if _candidate_distance(candidate, gt_file, gt_line) is not None
            )
            evidence_notes = [note]
            if nearest:
                for field in ("reasoning", "suggestion"):
                    value = str(nearest.get(field, "") or "").strip()
                    if value:
                        evidence_notes.append(f"{field}: {value[:180]}")

            rows.append(
                {
                    "cve_id": cve_id,
                    "repo_url": cve_result.get("repo_url", gt.get("repo_url", "")),
                    "gt_file": gt_file,
                    "gt_line": gt_line,
                    "arm_key": arm_key,
                    "line_tolerance": line_tolerance,
                    "fn_category": category,
                    "fn_category_detail": _category_detail(category, candidates),
                    "candidate_count": len(candidates),
                    "raw_candidate_count": int(
                        metrics.get("joern_raw_findings", len(candidates)) or 0
                    ),
                    "triaged_candidate_count": int(
                        metrics.get("joern_triaged_findings", len(candidates)) or 0
                    ),
                    "dropped_candidate_count": int(
                        metrics.get("joern_candidates_dropped_before_triage", 0) or 0
                    ),
                    "dropped_reason_counts": metrics.get(
                        "joern_dropped_reason_counts", {}
                    )
                    or {},
                    "same_file_candidate_count": same_file_count,
                    "flow_path_match": bool(flow_matches),
                    "flow_path_match_count": len(flow_matches),
                    "report_candidate_location_match": bool(report_location_matches),
                    "report_candidate_location_match_count": len(
                        report_location_matches
                    ),
                    "nearest_flow_locations": (
                        flow_matches[0].get("joern_flow_locations", [])[:10]
                        if flow_matches
                        else []
                    ),
                    "nearest_candidate_file": (
                        nearest.get("file", "") if nearest else ""
                    ),
                    "nearest_candidate_line": (
                        nearest.get("line", "") if nearest else ""
                    ),
                    "nearest_distance": (
                        "" if nearest_distance is None else nearest_distance
                    ),
                    "verdict_counts": _verdict_counts(candidates),
                    "top_candidate_files": _top_counts(candidates, "file"),
                    "top_sink_apis": _top_counts(candidates, "sink_api"),
                    "top_source_kinds": _top_counts(candidates, "sourceKind"),
                    "tp_via_same_package_count": int(
                        arm.get("tp_via_same_package", 0) or 0
                    ),
                    "tp_via_same_package_with_origin_count": int(
                        arm.get("tp_via_same_package_with_origin", 0) or 0
                    ),
                    "tp_via_same_package_promoted_count": int(
                        arm.get("tp_via_same_package_promoted", 0) or 0
                    ),
                    "relaxed_tp": int(arm.get("relaxed_tp", arm.get("tp", 0)) or 0),
                    "origin_external_source_count": sum(
                        1 for c in candidates if c.get("originExternalSource")
                    ),
                    "origin_evidence_count": _evidence_count(
                        candidates, "originEvidence"
                    ),
                    "caller_evidence_count": _evidence_count(candidates, "callerChain"),
                    "sink_caller_evidence_count": _evidence_count(
                        candidates, "sinkCallerChain"
                    ),
                    "sink_callsite_evidence_count": _evidence_record_count(
                        candidates, "sinkCallsite"
                    ),
                    "report_candidate_location_count": _evidence_count(
                        candidates, "reportCandidateLocations"
                    ),
                    "triage_evidence_missing_with_origin": (
                        category == "triage_evidence_missing"
                        and any(c.get("originExternalSource") for c in candidates)
                    ),
                    "coverage_probe": coverage_probe,
                    "top_sink_kinds": _top_counts(candidates, "sinkKind"),
                    "top_sink_semantic_flags": _top_semantic_flags(candidates),
                    "evidence_notes": " | ".join(evidence_notes),
                }
            )
    return rows


def build_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    category_counts = Counter(str(row["fn_category"]) for row in rows)
    zero_candidate_cves = sorted(
        {str(row["cve_id"]) for row in rows if row["fn_category"] == "zero_candidate"}
    )
    same_file_near_miss_cves = sorted(
        {
            str(row["cve_id"])
            for row in rows
            if row["fn_category"] == "same_file_near_miss"
        }
    )
    flow_path_match_cves = sorted(
        {
            str(row["cve_id"])
            for row in rows
            if row.get("flow_path_match")
            or row["fn_category"] == "flow_path_location_match"
        }
    )
    top_files = Counter()
    top_sinks = Counter()
    top_source_kinds = Counter()
    top_sink_kinds = Counter()
    top_sink_semantic_flags = Counter()
    dropped_reasons = Counter()
    raw_candidate_total = 0
    triaged_candidate_total = 0
    dropped_candidate_total = 0
    origin_external_source_total = 0
    origin_evidence_total = 0
    caller_evidence_total = 0
    sink_caller_evidence_total = 0
    sink_callsite_evidence_total = 0
    report_candidate_location_total = 0
    report_candidate_location_match_total = 0
    triage_evidence_missing_with_origin_total = 0
    tp_via_same_package_total = 0
    tp_via_same_package_with_origin_total = 0
    tp_via_same_package_promoted_total = 0
    relaxed_tp_total = 0
    cves_without_gt_file_in_cpg: set[str] = set()
    cves_without_gt_sink: set[str] = set()
    cves_without_external_source_in_gt_file: set[str] = set()
    for row in rows:
        raw_candidate_total += int(row.get("raw_candidate_count", 0) or 0)
        triaged_candidate_total += int(row.get("triaged_candidate_count", 0) or 0)
        dropped_candidate_total += int(row.get("dropped_candidate_count", 0) or 0)
        origin_external_source_total += int(
            row.get("origin_external_source_count", 0) or 0
        )
        origin_evidence_total += int(row.get("origin_evidence_count", 0) or 0)
        caller_evidence_total += int(row.get("caller_evidence_count", 0) or 0)
        sink_caller_evidence_total += int(row.get("sink_caller_evidence_count", 0) or 0)
        sink_callsite_evidence_total += int(
            row.get("sink_callsite_evidence_count", 0) or 0
        )
        report_candidate_location_total += int(
            row.get("report_candidate_location_count", 0) or 0
        )
        report_candidate_location_match_total += int(
            row.get("report_candidate_location_match_count", 0) or 0
        )
        triage_evidence_missing_with_origin_total += int(
            bool(row.get("triage_evidence_missing_with_origin"))
        )
        tp_via_same_package_total += int(row.get("tp_via_same_package_count", 0) or 0)
        tp_via_same_package_with_origin_total += int(
            row.get("tp_via_same_package_with_origin_count", 0) or 0
        )
        tp_via_same_package_promoted_total += int(
            row.get("tp_via_same_package_promoted_count", 0) or 0
        )
        relaxed_tp_total += int(row.get("relaxed_tp", 0) or 0)
        coverage_probe = row.get("coverage_probe") or {}
        if isinstance(coverage_probe, dict) and coverage_probe:
            cve_id = str(row.get("cve_id", ""))
            if not bool(coverage_probe.get("gt_file_seen", False)):
                cves_without_gt_file_in_cpg.add(cve_id)
            if int(coverage_probe.get("gt_sink_count", 0) or 0) <= 0:
                cves_without_gt_sink.add(cve_id)
            if int(coverage_probe.get("external_source_count", 0) or 0) <= 0:
                cves_without_external_source_in_gt_file.add(cve_id)
        for name, count in (row.get("dropped_reason_counts", {}) or {}).items():
            dropped_reasons[str(name)] += int(count or 0)
        for item in row["top_candidate_files"]:
            name, _, count = item.rpartition(":")
            top_files[name] += int(count or 0)
        for item in row["top_sink_apis"]:
            name, _, count = item.rpartition(":")
            top_sinks[name] += int(count or 0)
        for item in row.get("top_source_kinds", []):
            name, _, count = item.rpartition(":")
            top_source_kinds[name] += int(count or 0)
        for item in row.get("top_sink_kinds", []):
            name, _, count = item.rpartition(":")
            top_sink_kinds[name] += int(count or 0)
        for item in row.get("top_sink_semantic_flags", []):
            name, _, count = item.rpartition(":")
            top_sink_semantic_flags[name] += int(count or 0)

    recommendations: list[str] = []
    if category_counts.get("triage_evidence_missing", 0):
        recommendations.append("pass_joern_structural_evidence_to_triage")
    if category_counts.get("flow_path_location_match", 0):
        recommendations.append("promote_joern_flow_path_callsite_to_report_location")
    if category_counts.get("helper_sink_location", 0):
        recommendations.append("score_or_report_vulnerable_callsites_from_flow_paths")
    if category_counts.get("zero_candidate", 0):
        recommendations.append(
            "audit_source_sink_catalog_coverage_for_zero_candidate_cves"
        )
    if category_counts.get("cpg_timeout", 0):
        recommendations.append("extend_per_cve_timeout_or_split_cpg_build")
    if category_counts.get("same_file_near_miss", 0):
        recommendations.append("inspect_line_mapping_and_flow_path_locations")
    if top_sink_kinds.get("wrapper", 0):
        recommendations.append("review_wrapper_sink_candidates_for_gt_localization")
    if top_sink_semantic_flags:
        recommendations.append("use_sink_semantic_flags_to_prioritize_fp_review")
    if dropped_reasons:
        recommendations.append("review_candidate_reducer_dropped_reason_counts")
    if category_counts.get("flow_path_location_match", 0) and dropped_candidate_total:
        recommendations.append("raise_cap_for_flow_path_matches_if_needed")
    if triage_evidence_missing_with_origin_total:
        recommendations.append("inspect_llm_io_for_origin_evidence_policy_failures")
    if report_candidate_location_match_total:
        recommendations.append("promote_report_candidate_locations_to_primary_reports")

    return {
        "n_fn_rows": len(rows),
        "raw_candidate_total": raw_candidate_total,
        "triaged_candidate_total": triaged_candidate_total,
        "dropped_candidate_total": dropped_candidate_total,
        "joern_origin_external_count": origin_external_source_total,
        "origin_evidence_count": origin_evidence_total,
        "caller_evidence_count": caller_evidence_total,
        "sink_caller_evidence_count": sink_caller_evidence_total,
        "sink_callsite_evidence_count": sink_callsite_evidence_total,
        "report_candidate_location_count": report_candidate_location_total,
        "report_candidate_location_tp": report_candidate_location_match_total,
        "tp_via_same_package_total": tp_via_same_package_total,
        "tp_via_same_package_with_origin_total": tp_via_same_package_with_origin_total,
        "tp_via_same_package_promoted_total": tp_via_same_package_promoted_total,
        "relaxed_tp_total": relaxed_tp_total,
        "cves_without_gt_file_in_cpg": sorted(cves_without_gt_file_in_cpg),
        "cves_without_gt_sink": sorted(cves_without_gt_sink),
        "cves_without_external_source_in_gt_file": sorted(
            cves_without_external_source_in_gt_file
        ),
        "triage_evidence_missing_with_origin": (
            triage_evidence_missing_with_origin_total
        ),
        "category_counts": dict(sorted(category_counts.items())),
        "zero_candidate_cves": zero_candidate_cves,
        "same_file_near_miss_cves": same_file_near_miss_cves,
        "flow_path_match_cves": flow_path_match_cves,
        "top_candidate_files": [f"{k}:{v}" for k, v in top_files.most_common(10)],
        "top_sink_apis": [f"{k}:{v}" for k, v in top_sinks.most_common(10)],
        "top_source_kinds": [f"{k}:{v}" for k, v in top_source_kinds.most_common(10)],
        "top_sink_kinds": [f"{k}:{v}" for k, v in top_sink_kinds.most_common(10)],
        "top_sink_semantic_flags": [
            f"{k}:{v}" for k, v in top_sink_semantic_flags.most_common(10)
        ],
        "top_dropped_reasons": [f"{k}:{v}" for k, v in dropped_reasons.most_common(10)],
        "recommendations": recommendations,
    }


def _csv_value(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return value


def write_csv(rows: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "cve_id",
        "repo_url",
        "gt_file",
        "gt_line",
        "arm_key",
        "line_tolerance",
        "fn_category",
        "fn_category_detail",
        "candidate_count",
        "raw_candidate_count",
        "triaged_candidate_count",
        "dropped_candidate_count",
        "dropped_reason_counts",
        "same_file_candidate_count",
        "flow_path_match",
        "flow_path_match_count",
        "report_candidate_location_match",
        "report_candidate_location_match_count",
        "nearest_flow_locations",
        "nearest_candidate_file",
        "nearest_candidate_line",
        "nearest_distance",
        "verdict_counts",
        "top_candidate_files",
        "top_sink_apis",
        "top_source_kinds",
        "tp_via_same_package_count",
        "tp_via_same_package_with_origin_count",
        "origin_external_source_count",
        "origin_evidence_count",
        "caller_evidence_count",
        "sink_caller_evidence_count",
        "sink_callsite_evidence_count",
        "report_candidate_location_count",
        "triage_evidence_missing_with_origin",
        "coverage_probe",
        "top_sink_kinds",
        "top_sink_semantic_flags",
        "evidence_notes",
    ]
    with path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _csv_value(row.get(key, "")) for key in fieldnames})


def write_markdown(
    rows: list[dict[str, Any]], summary: dict[str, Any], path: Path
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Joern FN Audit",
        "",
        "## Summary",
        "",
        f"- FN rows: {summary['n_fn_rows']}",
        f"- Raw candidates: {summary.get('raw_candidate_total', 0)}",
        f"- Triaged candidates: {summary.get('triaged_candidate_total', 0)}",
        f"- Dropped candidates: {summary.get('dropped_candidate_total', 0)}",
        f"- Category counts: {json.dumps(summary['category_counts'], sort_keys=True)}",
        f"- Zero-candidate CVEs: {', '.join(summary['zero_candidate_cves']) or 'none'}",
        f"- Flow-path match CVEs: {', '.join(summary['flow_path_match_cves']) or 'none'}",
        f"- Origin external candidates: {summary.get('joern_origin_external_count', 0)}",
        f"- Origin evidence records: {summary.get('origin_evidence_count', 0)}",
        f"- Caller evidence records: {summary.get('caller_evidence_count', 0)}",
        f"- Sink-caller evidence records: {summary.get('sink_caller_evidence_count', 0)}",
        f"- Sink-callsite evidence records: {summary.get('sink_callsite_evidence_count', 0)}",
        f"- Report-candidate location matches: {summary.get('report_candidate_location_tp', 0)}",
        f"- Same-package diagnostic matches: {summary.get('tp_via_same_package_total', 0)}",
        f"- Same-package diagnostic matches with origin: {summary.get('tp_via_same_package_with_origin_total', 0)}",
        f"- Same-package promoted (relaxed TP): {summary.get('tp_via_same_package_promoted_total', 0)}",
        f"- Relaxed TP (strict TP + same-package promoted): {summary.get('relaxed_tp_total', 0)}",
        f"- Coverage missing GT file CVEs: {', '.join(summary.get('cves_without_gt_file_in_cpg', [])) or 'none'}",
        f"- Coverage missing sink CVEs: {', '.join(summary.get('cves_without_gt_sink', [])) or 'none'}",
        f"- Coverage missing external-source CVEs: {', '.join(summary.get('cves_without_external_source_in_gt_file', [])) or 'none'}",
        f"- Source kinds: {', '.join(summary.get('top_source_kinds', [])) or 'none'}",
        f"- Sink kinds: {', '.join(summary.get('top_sink_kinds', [])) or 'none'}",
        f"- Sink semantic flags: {', '.join(summary.get('top_sink_semantic_flags', [])) or 'none'}",
        f"- Dropped reasons: {', '.join(summary.get('top_dropped_reasons', [])) or 'none'}",
        f"- Recommendations: {', '.join(summary['recommendations']) or 'none'}",
        "",
        "## Rows",
        "",
        "| CVE | GT | Category | Candidates | Nearest | Notes |",
        "| --- | --- | --- | ---: | --- | --- |",
    ]
    for row in rows:
        nearest = (
            f"{row['nearest_candidate_file']}:{row['nearest_candidate_line']}"
            if row["nearest_candidate_file"]
            else ""
        )
        notes = str(row["evidence_notes"]).replace("|", "/")[:220]
        lines.append(
            "| {cve_id} | {gt_file}:{gt_line} | {fn_category} | "
            "{candidate_count} | {nearest} | {notes} |".format(
                cve_id=row["cve_id"],
                gt_file=row["gt_file"],
                gt_line=row["gt_line"],
                fn_category=row["fn_category"],
                candidate_count=row["candidate_count"],
                nearest=nearest,
                notes=notes,
            )
        )
    path.write_text("\n".join(lines) + "\n")


def audit_results_json(
    results_path: Path,
    dataset_path: Path = DEFAULT_DATASET,
    *,
    output_dir: Path | None = None,
    arm_key: str = "joern_0",
    line_tolerance: int = LINE_TOLERANCE,
    formats: list[str] | tuple[str, ...] = ("json", "csv", "md"),
) -> dict[str, Any]:
    results = load_json(results_path)
    metadata_by_cve = load_metadata(dataset_path)
    rows = build_fn_rows(
        results,
        metadata_by_cve,
        arm_key=arm_key,
        line_tolerance=line_tolerance,
    )
    summary = build_summary(rows)

    out_dir = output_dir or results_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    artifacts: dict[str, str] = {}
    formats_set = set(formats)
    if "json" in formats_set:
        json_path = out_dir / f"{OUTPUT_BASENAME}.json"
        _save_json({"summary": summary, "rows": rows}, json_path)
        artifacts["json"] = str(json_path)
    if "csv" in formats_set:
        csv_path = out_dir / f"{OUTPUT_BASENAME}.csv"
        write_csv(rows, csv_path)
        artifacts["csv"] = str(csv_path)
    if "md" in formats_set:
        md_path = out_dir / f"{OUTPUT_BASENAME}.md"
        write_markdown(rows, summary, md_path)
        artifacts["md"] = str(md_path)

    return {
        "results_path": str(results_path),
        "dataset_path": str(dataset_path),
        "output_dir": str(out_dir),
        "arm_key": arm_key,
        "line_tolerance": line_tolerance,
        "summary": summary,
        "artifacts": artifacts,
    }


def _print_summary(audit: dict[str, Any]) -> None:
    summary = audit["summary"]
    print(f"[audit_joern_fn] output_dir: {audit['output_dir']}")
    print(f"  FN rows        : {summary['n_fn_rows']}")
    print(f"  categories     : {summary['category_counts']}")
    print(f"  recommendations: {summary['recommendations']}")
    for fmt, path in audit["artifacts"].items():
        print(f"  {fmt}: {path}")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.results_json is None or not args.results_json.exists():
        print(f"error: results JSON not found: {args.results_json}", file=sys.stderr)
        return 2
    if not args.dataset.exists():
        print(f"error: dataset not found: {args.dataset}", file=sys.stderr)
        return 2

    audit = audit_results_json(
        args.results_json,
        args.dataset,
        output_dir=args.output_dir,
        arm_key=args.arm_key,
        line_tolerance=args.line_tolerance,
        formats=args.format,
    )
    _print_summary(audit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
