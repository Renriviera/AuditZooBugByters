#!/usr/bin/env python3
"""Audit Joern CWE-78 false positives and false negatives from results.json.

This is a post-processing utility: it does not run Joern and does not call
LLMs.  It joins the saved scorer labels, triager verdict rows, refiner actions,
and dataset ground truth that the Joern sweep already persisted.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from splitEvaluations.common import DEFAULT_DATASET, LINE_TOLERANCE

JOERN_ARM_RE = re.compile(r"^joern_(?P<k>\d+)(?P<patched>_patched)?$")
TEXT_CAP = 500

# Default ``--gt-cluster-gap``: GT lines whose absolute distance is at most this
# many source lines apart belong to the same "GT cluster" for relaxed scoring.
# Patch hunks frequently span 5–8 lines around a fix, so 8 keeps tightly packed
# fixes (back-to-back ``Popen`` rewrites) in one cluster while still
# distinguishing genuinely separate vulnerable regions.
DEFAULT_GT_CLUSTER_GAP = 8

# Pattern for the "@@ -OLD,COUNT +NEW,COUNT @@" hunk headers in unified diffs.
# Capture groups:
#   1: OLD start line (pre-fix file)
#   2: OLD count (optional, defaults to 1 per ``diff`` semantics)
#   3: NEW start line (post-fix file)
#   4: NEW count (optional, defaults to 1)
_HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
# ``--- a/<path>`` line with the OLD-side filename. ``a/`` prefix is the
# default ``git diff`` convention; we strip it on parse.
_OLD_FILE_RE = re.compile(r"^--- (?:a/)?(.+?)(?:\s+\d{4}-\d{2}-\d{2}.*)?$")


def _load_changed_hunks(diff_path: Path) -> dict[str, list[tuple[int, int]]]:
    """Return ``{old_path: [(old_start, old_end), ...]}`` from a unified diff.

    *Why OLD-side*: ``vulnerable_lines`` in the dataset are line numbers in the
    pre-fix (vulnerable) version of the file, which is exactly what Joern
    analyses, so the relaxed scoring lane needs to match against OLD-side
    ranges.  ``+`` lines in the diff don't exist in the pre-fix file so
    they're ignored when computing the OLD-side range; only context (``" "``)
    and ``-`` lines advance the OLD pointer.

    Robust to:
      * ``/dev/null`` markers for new/deleted files (skipped).
      * Hunks with no count (``@@ -42 +50 @@`` ⇒ count 1).
      * Concatenated diff files (multiple ``diff --git`` blocks).

    Returns empty dict when the path doesn't exist or has no parseable hunks.
    Errors during parsing are swallowed (audit is post-processing; we never
    want a malformed diff to abort the whole audit).
    """
    if not diff_path.exists():
        return {}
    try:
        text = diff_path.read_text(errors="replace")
    except OSError:
        return {}

    out: dict[str, list[tuple[int, int]]] = defaultdict(list)
    current_old_path: str | None = None
    for raw_line in text.splitlines():
        if raw_line.startswith("--- "):
            match = _OLD_FILE_RE.match(raw_line)
            if not match:
                current_old_path = None
                continue
            path = match.group(1).strip()
            current_old_path = None if path in {"/dev/null", ""} else path
            continue
        if raw_line.startswith("+++"):
            continue
        if raw_line.startswith("@@"):
            if current_old_path is None:
                continue
            match = _HUNK_HEADER_RE.match(raw_line)
            if not match:
                continue
            old_start = int(match.group(1))
            old_count = int(match.group(2)) if match.group(2) is not None else 1
            if old_count <= 0:
                # ``@@ -0,0 +N,M @@`` is a pure-add hunk (no OLD lines); skip.
                continue
            old_end = old_start + old_count - 1
            out[current_old_path].append((old_start, old_end))
    return dict(out)


def _cluster_lines(
    lines: list[int], gap: int = DEFAULT_GT_CLUSTER_GAP
) -> list[tuple[int, int]]:
    """Group ``lines`` into ``(start, end)`` clusters via a max gap of ``gap``.

    A cluster spans every line up to ``gap`` lines from its predecessor; once
    the next line is more than ``gap`` away, a new cluster starts.

    Examples::

        _cluster_lines([5, 6, 7, 50, 51], gap=8) == [(5, 7), (50, 51)]
        _cluster_lines([5, 13, 21], gap=8)        == [(5, 21)]   # 8-step chain
        _cluster_lines([5, 14, 23], gap=8)        == [(5, 5), (14, 14), (23, 23)]

    Single-line GT lists collapse to one ``(line, line)`` cluster.  Negative
    or non-integer entries are silently skipped (defensive: dataset is hand
    curated).
    """
    sanitized: list[int] = []
    for value in lines:
        try:
            n = int(value)
        except (TypeError, ValueError):
            continue
        if n <= 0:
            continue
        sanitized.append(n)
    if not sanitized:
        return []
    sanitized.sort()
    clusters: list[tuple[int, int]] = []
    start = sanitized[0]
    end = sanitized[0]
    for n in sanitized[1:]:
        if n - end <= gap:
            end = n
        else:
            clusters.append((start, end))
            start = n
            end = n
    clusters.append((start, end))
    return clusters


def _line_in_ranges(
    line: int, ranges: list[tuple[int, int]], *, tolerance: int = 0
) -> bool:
    """Return True if ``line`` falls within any ``(start, end)`` ± ``tolerance``."""
    for start, end in ranges:
        if start - tolerance <= line <= end + tolerance:
            return True
    return False


@dataclass(frozen=True)
class ArmKey:
    """Parsed Joern arm key from a sweep result."""

    raw: str
    k: int
    patched: bool


@dataclass
class AuditFindingRow:
    """One aligned scorer/triager row."""

    cve_id: str
    arm_key: str
    k: int
    patched: bool
    finding_index: int
    label: str
    fp_cause: str
    file: str
    line: int | str
    rule_id: str
    sink_api: str
    verdict: str
    confidence: float
    source_expr: str
    sink_expr: str
    source_in_snippet: bool | str
    sink_in_snippet: bool | str
    downgrade_reason: str
    reasoning: str
    suggestion: str
    matched_gt_line: int | str
    # Joern recovery_kind tags the CPGQL pass that produced the
    # candidate ("taint" / "relaxed" / "def_use" / "direct_sink") —
    # populated by ``serialize_triage_verdicts``.  Empty string for
    # pre-recovery runs or non-Joern arms.
    recovery_kind: str = ""
    recovery_kinds_seen: str = ""


@dataclass
class MissedGroundTruthRow:
    """One missed vulnerable line for one CVE/k."""

    cve_id: str
    arm_key: str
    k: int
    vulnerable_file: str
    vulnerable_line: int | str
    fn_cause: str
    nearest_file: str
    nearest_line: int | str
    nearest_distance: int | str
    nearest_label: str
    nearest_verdict: str
    triager_reason: str
    refiner_actions: str
    findings_hash: str
    joern_catalog_grew: bool | str
    arm_error_type: str
    skipped: str
    # ``nearest_recovery_kind`` is the recovery_kind of the nearest
    # same-file triage row (if any).  ``recovery_kinds_in_iter`` is
    # a "kind:count" CSV summarising which Joern passes contributed
    # candidates in this CVE/k iteration — useful for spotting recall
    # holes ("CVE X had no direct_sink candidates because catalog Y
    # was missing").  Both are empty for pre-recovery runs.
    nearest_recovery_kind: str = ""
    recovery_kinds_in_iter: str = ""


@dataclass
class IterationAudit:
    """Per-CVE, per-k Joern summary row."""

    cve_id: str
    arm_key: str
    k: int
    patched: bool
    tp: int | str
    fp: int | str
    fn: int | str
    fn_by_llm: int | str
    fp_by_hallucinated_source: int | str
    n_candidates: int | str
    findings_hash: str
    findings_changed_vs_k0: bool | str
    joern_catalog_grew: bool | str
    refinement_actions_count: int
    refinement_roles: str
    llm_tokens_triage: int | str
    llm_tokens_refinement: int | str
    llm_triage_s: float | str
    llm_refinement_s: float | str
    scan_s: float | str
    cpg_build_s: float | str
    arm_error_type: str
    skipped: str
    # Recovery-pass attribution from
    # ``metrics["n_findings_by_recovery"]``.  ``raw_*`` are pre-dedup
    # counts emitted by each CPGQL pass; ``post_dedup_*`` are how many
    # finding kinds survived the global dedup.  Filled with ``""``
    # for pre-recovery runs.
    raw_taint: int | str = ""
    raw_relaxed: int | str = ""
    raw_def_use: int | str = ""
    raw_direct_sink: int | str = ""
    post_dedup_taint: int | str = ""
    post_dedup_relaxed: int | str = ""
    post_dedup_def_use: int | str = ""
    post_dedup_direct_sink: int | str = ""
    # Cluster + patch-hunk relaxed scoring (Fix #2 in the
    # ``20260510`` recall plan).  ``tp_relaxed`` counts committed-TP
    # rows that fall within ``±line_tolerance`` of any line in a GT
    # cluster *or* inside a changed hunk on the same file.
    # ``fn_relaxed`` counts GT clusters with no covering committed-TP
    # row.  ``fp_relaxed`` counts committed-TP rows that miss every
    # cluster *and* every changed hunk plus the existing
    # hallucinated-source FPs.  ``n_gt_clusters`` is the relaxed
    # denominator (same for every iteration of a CVE).
    tp_relaxed: int | str = ""
    fp_relaxed: int | str = ""
    fn_relaxed: int | str = ""
    n_gt_clusters: int | str = ""
    # UNCERTAIN-on-GT visibility lane (Fix #3): re-tally with each
    # GT cluster credited as TP if any UNCERTAIN row lands within
    # ``±line_tolerance`` of a cluster line *and* the cluster wasn't
    # already covered by a committed TP.  This quantifies "TPs the
    # hallucination brake is currently swallowing" without changing
    # the canonical metric.
    tp_uncertain_relaxed: int | str = ""
    fp_uncertain_relaxed: int | str = ""
    fn_uncertain_relaxed: int | str = ""
    n_uncertain_credits: int | str = ""


def parse_joern_arm_key(arm_key: str) -> ArmKey | None:
    """Return a parsed Joern arm key or ``None`` for non-Joern arms."""
    match = JOERN_ARM_RE.match(arm_key)
    if not match:
        return None
    return ArmKey(
        raw=arm_key,
        k=int(match.group("k")),
        patched=bool(match.group("patched")),
    )


def load_json(path: Path) -> Any:
    """Load JSON from *path*."""
    return json.loads(path.read_text())


def infer_run_config(results_path: Path) -> dict[str, Any]:
    """Load a sibling run_config.json when present."""
    config_path = results_path.parent / "run_config.json"
    if not config_path.exists():
        return {}
    data = load_json(config_path)
    return data if isinstance(data, dict) else {}


def resolve_dataset_path(results_path: Path, cli_dataset: Path | None) -> Path:
    """Resolve dataset path from CLI, sibling run_config, or project default."""
    if cli_dataset is not None:
        return cli_dataset
    run_config = infer_run_config(results_path)
    configured = run_config.get("dataset")
    if configured:
        return Path(str(configured))
    return DEFAULT_DATASET


def resolve_line_tolerance(results_path: Path, cli_line_tolerance: int | None) -> int:
    """Resolve line tolerance from CLI, sibling run_config, or default."""
    if cli_line_tolerance is not None:
        return cli_line_tolerance
    run_config = infer_run_config(results_path)
    raw = run_config.get("line_tolerance")
    if raw is not None:
        return int(raw)
    return LINE_TOLERANCE


def dataset_by_cve(dataset: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Index dataset records by CVE ID."""
    return {str(row.get("cve_id", "")): row for row in dataset}


def iter_joern_arms(
    cve_result: dict[str, Any],
) -> list[tuple[ArmKey, dict[str, Any]]]:
    """Return sorted Joern arms from one CVE result."""
    arms = cve_result.get("arms")
    if not isinstance(arms, dict):
        return []
    parsed: list[tuple[ArmKey, dict[str, Any]]] = []
    for arm_key, arm_entry in arms.items():
        parsed_key = parse_joern_arm_key(str(arm_key))
        if parsed_key is None or not isinstance(arm_entry, dict):
            continue
        parsed.append((parsed_key, arm_entry))
    return sorted(parsed, key=lambda item: (item[0].k, item[0].patched))


def path_matches(found_file: str, vuln_file: str) -> bool:
    """Match paths with the same loose semantics as the scorer."""
    found_name = Path(found_file).name
    gt_name = Path(vuln_file).name
    return (
        found_name == gt_name
        or vuln_file.endswith(found_file)
        or found_file.endswith(vuln_file)
    )


def matched_gt_line(
    triage_row: dict[str, Any],
    ground_truth: dict[str, Any],
    *,
    line_tolerance: int,
) -> int | None:
    """Return the matched vulnerable line for a saved triage row."""
    vuln_file = str(ground_truth.get("vulnerable_file", ""))
    vuln_lines = [int(line) for line in ground_truth.get("vulnerable_lines", [])]
    if not vuln_file or not vuln_lines:
        return None

    found_file = str(triage_row.get("file", ""))
    if not path_matches(found_file, vuln_file):
        return None

    try:
        found_line = int(triage_row.get("line", 0))
    except (TypeError, ValueError):
        return None

    for vuln_line in vuln_lines:
        if abs(found_line - vuln_line) <= line_tolerance:
            return vuln_line
    return None


def rows_on_gt_line(
    aligned_rows: list[dict[str, Any]],
    ground_truth: dict[str, Any],
    vuln_line: int,
    *,
    line_tolerance: int,
) -> list[dict[str, Any]]:
    """Return aligned rows matching one vulnerable line."""
    vuln_file = str(ground_truth.get("vulnerable_file", ""))
    out: list[dict[str, Any]] = []
    for row in aligned_rows:
        triage = row["triage"]
        if not path_matches(str(triage.get("file", "")), vuln_file):
            continue
        try:
            line = int(triage.get("line", 0))
        except (TypeError, ValueError):
            continue
        if abs(line - vuln_line) <= line_tolerance:
            out.append(row)
    return out


def nearest_row_to_gt_line(
    aligned_rows: list[dict[str, Any]],
    ground_truth: dict[str, Any],
    vuln_line: int,
) -> dict[str, Any] | None:
    """Return nearest same-file triage row for human FN inspection."""
    vuln_file = str(ground_truth.get("vulnerable_file", ""))
    candidates: list[tuple[int, dict[str, Any]]] = []
    for row in aligned_rows:
        triage = row["triage"]
        if not path_matches(str(triage.get("file", "")), vuln_file):
            continue
        try:
            line = int(triage.get("line", 0))
        except (TypeError, ValueError):
            continue
        candidates.append((abs(line - vuln_line), row))
    if not candidates:
        return None
    return min(candidates, key=lambda item: item[0])[1]


def build_aligned_rows(
    cve_id: str,
    arm_key: ArmKey,
    arm_entry: dict[str, Any],
    ground_truth: dict[str, Any],
    *,
    line_tolerance: int,
) -> list[dict[str, Any]]:
    """Join saved labels with saved triage rows for one Joern arm."""
    labels = list(arm_entry.get("labels") or [])
    triage_rows = list(arm_entry.get("triage_verdicts") or [])
    out: list[dict[str, Any]] = []
    for idx, triage in enumerate(triage_rows):
        if not isinstance(triage, dict):
            triage = {}
        label = str(labels[idx]) if idx < len(labels) else ""
        out.append(
            {
                "cve_id": cve_id,
                "arm_key": arm_key.raw,
                "k": arm_key.k,
                "patched": arm_key.patched,
                "finding_index": idx,
                "label": label,
                "triage": triage,
                "matched_gt_line": matched_gt_line(
                    triage, ground_truth, line_tolerance=line_tolerance
                ),
            }
        )
    return out


def classify_fp(row: dict[str, Any]) -> str:
    """Map a saved scorer label and triager verdict to an audit-facing FP cause.

    Recognises the post-Phase-B2 ``uncertain_on_gt`` / ``uncertain_off_gt``
    labels as a separate ``uncertain_unscored`` bucket so they aren't
    silently lumped under ``scanner_location_fp`` (UNCERTAIN no longer
    feeds into TP/FP at all under the new scorer; see
    ``label_findings``).  Legacy runs that lacked the new labels still
    map ``label == 'fp_by_location'`` to ``scanner_location_fp`` for
    backward compatibility.
    """
    if row["patched"]:
        return "patched_commit_alert"

    label = str(row.get("label", ""))
    triage = row.get("triage") or {}
    verdict = str(triage.get("verdict", ""))

    if label == "fp_by_hallucinated_source" or triage.get("source_in_snippet") is False:
        return "evidence_hallucination"
    if label == "fp_by_llm_overclaim" or verdict == "true_positive":
        return "triager_overclaim"
    if label in {"uncertain_on_gt", "uncertain_off_gt"}:
        return "uncertain_unscored"
    if label == "fp_by_location":
        return "scanner_location_fp"
    if not label and verdict == "uncertain":
        # Pre-Phase-B2 sweeps emitted no label for UNCERTAIN findings;
        # preserve the legacy classification path.
        return "scanner_location_fp"
    if label.startswith("fp_"):
        return label
    return ""


def compact_text(value: Any, *, cap: int = TEXT_CAP) -> str:
    """Stringify and cap long text cells for CSV output."""
    text = "" if value is None else str(value)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text[:cap]


def make_fp_rows(aligned_rows: list[dict[str, Any]]) -> list[AuditFindingRow]:
    """Extract false-positive rows from aligned Joern data."""
    fp_rows: list[AuditFindingRow] = []
    for row in aligned_rows:
        label = str(row.get("label", ""))
        if not row["patched"] and not label.startswith("fp_"):
            continue
        if row["patched"]:
            label = label or "patched_commit_alert"

        triage = row.get("triage") or {}
        fp_rows.append(
            AuditFindingRow(
                cve_id=row["cve_id"],
                arm_key=row["arm_key"],
                k=row["k"],
                patched=row["patched"],
                finding_index=row["finding_index"],
                label=label,
                fp_cause=classify_fp(row),
                file=compact_text(triage.get("file")),
                line=triage.get("line", ""),
                rule_id=compact_text(triage.get("rule_id")),
                sink_api=compact_text(triage.get("sink_api")),
                verdict=compact_text(triage.get("verdict")),
                confidence=float(triage.get("confidence") or 0.0),
                source_expr=compact_text(triage.get("source_expr")),
                sink_expr=compact_text(triage.get("sink_expr")),
                source_in_snippet=triage.get("source_in_snippet", ""),
                sink_in_snippet=triage.get("sink_in_snippet", ""),
                downgrade_reason=compact_text(triage.get("downgrade_reason")),
                reasoning=compact_text(triage.get("reasoning")),
                suggestion=compact_text(triage.get("suggestion")),
                matched_gt_line=row.get("matched_gt_line") or "",
                recovery_kind=str(triage.get("recovery_kind", "") or ""),
                recovery_kinds_seen=str(triage.get("recovery_kinds_seen", "") or ""),
            )
        )
    return fp_rows


def refiner_actions_text(arm_entry: dict[str, Any]) -> str:
    """Compactly serialize refiner actions for CSV."""
    actions = arm_entry.get("refinement_actions") or []
    if not actions:
        return ""
    return compact_text(json.dumps(actions, sort_keys=True), cap=1000)


def classify_fn_cause(
    matching_rows: list[dict[str, Any]],
    cve_result: dict[str, Any],
    arm_entry: dict[str, Any],
) -> str:
    """Classify why a vulnerable line is still missed."""
    if cve_result.get("skipped") or arm_entry.get("arm_error_type"):
        return "arm_error_or_timeout"
    labels = [str(row.get("label", "")) for row in matching_rows]
    verdicts = [
        str((row.get("triage") or {}).get("verdict", "")) for row in matching_rows
    ]
    if "fn_by_llm" in labels or "false_positive" in verdicts:
        return "triager_suppressed_gt"
    if "fp_by_hallucinated_source" in labels:
        return "hallucinated_source_on_gt"
    return "joern_candidate_missing"


def _recovery_kinds_in_iter(aligned_rows: list[dict[str, Any]]) -> str:
    """Return a ``"kind:count;..."`` summary of recovery_kind values
    observed in this CVE/k iteration's triage rows.

    Empty string when no row carries a recovery_kind (pre-recovery
    runs or non-Joern arms).
    """
    counts: Counter[str] = Counter()
    for row in aligned_rows:
        kind = str((row.get("triage") or {}).get("recovery_kind", "") or "")
        if kind:
            counts[kind] += 1
    if not counts:
        return ""
    return ";".join(f"{k}:{counts[k]}" for k in sorted(counts))


def make_fn_rows(
    cve_result: dict[str, Any],
    ground_truth: dict[str, Any],
    arm_key: ArmKey,
    arm_entry: dict[str, Any],
    aligned_rows: list[dict[str, Any]],
    *,
    line_tolerance: int,
) -> list[MissedGroundTruthRow]:
    """Extract missed vulnerable-line rows for one Joern arm."""
    vuln_lines = [int(line) for line in ground_truth.get("vulnerable_lines", [])]
    metrics = arm_entry.get("metrics") or {}
    recovery_kinds_in_iter = _recovery_kinds_in_iter(aligned_rows)
    fn_rows: list[MissedGroundTruthRow] = []
    if not vuln_lines:
        fn_rows.append(
            MissedGroundTruthRow(
                cve_id=str(cve_result.get("cve_id", "")),
                arm_key=arm_key.raw,
                k=arm_key.k,
                vulnerable_file=str(ground_truth.get("vulnerable_file", "")),
                vulnerable_line="",
                fn_cause="empty_ground_truth",
                nearest_file="",
                nearest_line="",
                nearest_distance="",
                nearest_label="",
                nearest_verdict="",
                triager_reason="",
                refiner_actions=refiner_actions_text(arm_entry),
                findings_hash=str(metrics.get("findings_hash", "")),
                joern_catalog_grew=metrics.get("joern_catalog_grew", ""),
                arm_error_type=str(arm_entry.get("arm_error_type", "")),
                skipped=str(cve_result.get("skipped", "")),
                nearest_recovery_kind="",
                recovery_kinds_in_iter=recovery_kinds_in_iter,
            )
        )
        return fn_rows

    for vuln_line in vuln_lines:
        matching_rows = rows_on_gt_line(
            aligned_rows, ground_truth, vuln_line, line_tolerance=line_tolerance
        )
        if any(str(row.get("label", "")) == "tp" for row in matching_rows):
            continue

        nearest = nearest_row_to_gt_line(aligned_rows, ground_truth, vuln_line)
        nearest_triage = (nearest or {}).get("triage") or {}
        nearest_line = nearest_triage.get("line", "")
        try:
            nearest_distance: int | str = abs(int(nearest_line) - vuln_line)
        except (TypeError, ValueError):
            nearest_distance = ""

        fn_rows.append(
            MissedGroundTruthRow(
                cve_id=str(cve_result.get("cve_id", "")),
                arm_key=arm_key.raw,
                k=arm_key.k,
                vulnerable_file=str(ground_truth.get("vulnerable_file", "")),
                vulnerable_line=vuln_line,
                fn_cause=classify_fn_cause(matching_rows, cve_result, arm_entry),
                nearest_file=compact_text(nearest_triage.get("file")),
                nearest_line=nearest_line,
                nearest_distance=nearest_distance,
                nearest_label=str((nearest or {}).get("label", "")),
                nearest_verdict=compact_text(nearest_triage.get("verdict")),
                triager_reason=compact_text(nearest_triage.get("reasoning")),
                refiner_actions=refiner_actions_text(arm_entry),
                findings_hash=str(metrics.get("findings_hash", "")),
                joern_catalog_grew=metrics.get("joern_catalog_grew", ""),
                arm_error_type=str(arm_entry.get("arm_error_type", "")),
                skipped=str(cve_result.get("skipped", "")),
                nearest_recovery_kind=str(
                    nearest_triage.get("recovery_kind", "") or ""
                ),
                recovery_kinds_in_iter=recovery_kinds_in_iter,
            )
        )
    return fn_rows


def refinement_roles(arm_entry: dict[str, Any]) -> str:
    """Summarize Joern helper roles emitted by the refiner."""
    role_counts: Counter[str] = Counter()
    for action in arm_entry.get("refinement_actions") or []:
        if not isinstance(action, dict):
            continue
        classifications = action.get("classifications") or {}
        if not isinstance(classifications, dict):
            continue
        for role in classifications.values():
            role_counts[str(role)] += 1
    return ";".join(f"{role}:{count}" for role, count in sorted(role_counts.items()))


def _recovery_breakdown_from_metrics(
    metrics: dict[str, Any],
) -> tuple[dict[str, int], dict[str, int]]:
    """Extract ``raw`` and ``post_dedup`` recovery-kind counts.

    Reads ``metrics["n_findings_by_recovery"]`` (added by the
    pipeline in the joern recovery sweep) and returns two int dicts
    keyed by recovery_kind.  Missing keys default to ``0``; the
    caller emits ``""`` for fields that are entirely absent (legacy
    pre-recovery runs).
    """
    payload = metrics.get("n_findings_by_recovery") or {}
    raw = payload.get("raw") if isinstance(payload, dict) else {}
    post = payload.get("post_dedup") if isinstance(payload, dict) else {}
    raw = raw if isinstance(raw, dict) else {}
    post = post if isinstance(post, dict) else {}

    def _to_int_dict(d: dict[str, Any]) -> dict[str, int]:
        out: dict[str, int] = {}
        for key, value in d.items():
            try:
                out[str(key)] = int(value)
            except (TypeError, ValueError):
                continue
        return out

    return _to_int_dict(raw), _to_int_dict(post)


def _committed_tp_predicate(label: str, verdict: str, source_in_snippet: Any) -> bool:
    """Return True for rows the LLM committed to as TRUE_POSITIVE.

    Uses the saved scorer ``label`` first (canonical post-Phase-B2
    bookkeeping), and falls back to the saved triage row's
    ``verdict`` + ``source_in_snippet`` so legacy results still parse.
    A hallucinated-source TP (``label='fp_by_hallucinated_source'``)
    does NOT count as a committed TP — the strict scorer's
    hallucination brake should still apply in the relaxed lane.
    """
    if label == "tp":
        return True
    if label == "fp_by_llm_overclaim":
        return True
    if label:
        return False
    # Pre-label legacy path.
    if verdict != "true_positive":
        return False
    if source_in_snippet is False:
        return False
    return True


def _is_hallucinated_fp(label: str, verdict: str, source_in_snippet: Any) -> bool:
    """Classify a row as a hallucinated-source FP under the strict scorer."""
    if label == "fp_by_hallucinated_source":
        return True
    if label:
        return False
    return verdict == "true_positive" and source_in_snippet is False


def _relaxed_score_for_iter(
    aligned_rows: list[dict[str, Any]],
    ground_truth: dict[str, Any],
    hunks_for_cve: dict[str, list[tuple[int, int]]],
    *,
    line_tolerance: int,
    cluster_gap: int,
) -> dict[str, int]:
    """Compute cluster-/hunk-relaxed and UNCERTAIN-relaxed counters.

    Returns a dict with the keys consumed by ``IterationAudit``::

        tp_relaxed, fp_relaxed, fn_relaxed,
        tp_uncertain_relaxed, fp_uncertain_relaxed, fn_uncertain_relaxed,
        n_gt_clusters, n_uncertain_credits,

    ``hunks_for_cve`` is the per-file changed-hunk map produced by
    :func:`_load_changed_hunks` for this CVE's diff.  A row hits a hunk
    when its ``(file, line)`` falls inside a registered range *with no
    line tolerance* (the hunk already widens the catchment).

    Pseudo-code::

        for each committed-TP row r:
            covered = any cluster c st any line in c within ±tol of r.line
                       and same file
            in_hunk = any hunk h on r.file st r.line in h
            if covered or in_hunk: TP_relaxed += 1
            else:                 FP_relaxed += 1
        FN_relaxed = #clusters with no committed-TP cover
        FP_relaxed += #hallucinated_source rows (still wrong)

        UNCERTAIN lane:
            extra = clusters not covered by any committed TP
                    that *are* covered by an UNCERTAIN row.
            TP_uncertain = TP_relaxed + extra
            FN_uncertain = FN_relaxed - extra
            FP_uncertain = FP_relaxed
    """
    vuln_file = str(ground_truth.get("vulnerable_file", ""))
    vuln_lines = list(ground_truth.get("vulnerable_lines", []) or [])
    clusters = _cluster_lines(vuln_lines, gap=cluster_gap)
    n_clusters = len(clusters)

    cluster_covered = [False] * n_clusters
    cluster_uncertain = [False] * n_clusters

    tp_relaxed = 0
    fp_relaxed = 0

    for row in aligned_rows:
        if row.get("patched"):
            # Patched-side findings never enter relaxed scoring (their
            # "TPs" are by definition over-eager catalog regressions).
            continue
        triage = row.get("triage") or {}
        label = str(row.get("label", ""))
        verdict = str(triage.get("verdict", ""))
        source_in_snippet = triage.get("source_in_snippet", True)
        try:
            line = int(triage.get("line", 0))
        except (TypeError, ValueError):
            line = 0
        file_path = str(triage.get("file", "") or "")

        same_file = bool(vuln_file) and path_matches(file_path, vuln_file)
        in_cluster_idx: int | None = None
        if same_file and line and clusters:
            for idx, (start, end) in enumerate(clusters):
                if start - line_tolerance <= line <= end + line_tolerance:
                    in_cluster_idx = idx
                    break
        in_hunk = False
        if line and file_path:
            # Try multiple key forms because triage's ``file`` can be a
            # repo-relative path while diff entries are usually
            # repo-relative ``a/<...>``-stripped paths.
            for hunk_path, ranges in hunks_for_cve.items():
                if not (
                    file_path == hunk_path
                    or file_path.endswith(hunk_path)
                    or hunk_path.endswith(file_path)
                ):
                    continue
                if _line_in_ranges(line, ranges, tolerance=0):
                    in_hunk = True
                    break

        if _is_hallucinated_fp(label, verdict, source_in_snippet):
            # Hallucinated-source rows are always wrong; they neither
            # cover GT clusters nor get hunk-credit.
            fp_relaxed += 1
            continue

        if _committed_tp_predicate(label, verdict, source_in_snippet):
            if in_cluster_idx is not None:
                cluster_covered[in_cluster_idx] = True
                tp_relaxed += 1
            elif in_hunk:
                tp_relaxed += 1
            else:
                fp_relaxed += 1
            continue

        # UNCERTAIN (and any non-committed verdict): only contributes
        # to the uncertain-relaxed lane via cluster credit.
        if verdict == "uncertain" and in_cluster_idx is not None:
            cluster_uncertain[in_cluster_idx] = True

    fn_relaxed = sum(1 for covered in cluster_covered if not covered)

    # Uncertain lane: credit clusters that were NOT covered by a
    # committed TP but DO have an UNCERTAIN row in their span.
    uncertain_credits = 0
    for idx in range(n_clusters):
        if not cluster_covered[idx] and cluster_uncertain[idx]:
            uncertain_credits += 1
    tp_uncertain = tp_relaxed + uncertain_credits
    fn_uncertain = fn_relaxed - uncertain_credits
    fp_uncertain = fp_relaxed

    return {
        "tp_relaxed": tp_relaxed,
        "fp_relaxed": fp_relaxed,
        "fn_relaxed": fn_relaxed,
        "tp_uncertain_relaxed": tp_uncertain,
        "fp_uncertain_relaxed": fp_uncertain,
        "fn_uncertain_relaxed": fn_uncertain,
        "n_gt_clusters": n_clusters,
        "n_uncertain_credits": uncertain_credits,
    }


def make_iteration_audit(
    cve_result: dict[str, Any],
    arm_key: ArmKey,
    arm_entry: dict[str, Any],
    k0_hash: str,
    *,
    relaxed: dict[str, int] | None = None,
) -> IterationAudit:
    """Build one per-iteration audit row."""
    metrics = arm_entry.get("metrics") or {}
    findings_hash = str(metrics.get("findings_hash", ""))
    actions = arm_entry.get("refinement_actions") or []
    raw_counts, post_counts = _recovery_breakdown_from_metrics(metrics)
    has_recovery = bool(metrics.get("n_findings_by_recovery"))

    def _maybe(key: str, source: dict[str, int]) -> int | str:
        return source.get(key, 0) if has_recovery else ""

    relaxed_payload = relaxed or {}
    relaxed_present = bool(relaxed_payload) and not arm_key.patched

    def _relaxed_field(name: str) -> int | str:
        return relaxed_payload.get(name, "") if relaxed_present else ""

    return IterationAudit(
        cve_id=str(cve_result.get("cve_id", "")),
        arm_key=arm_key.raw,
        k=arm_key.k,
        patched=arm_key.patched,
        tp=arm_entry.get("tp", ""),
        fp=arm_entry.get("fp", ""),
        fn=arm_entry.get("fn", ""),
        fn_by_llm=arm_entry.get("fn_by_llm", ""),
        fp_by_hallucinated_source=arm_entry.get("fp_by_hallucinated_source", ""),
        n_candidates=arm_entry.get(
            "n_candidates", arm_entry.get("n_findings_on_patched", "")
        ),
        findings_hash=findings_hash,
        findings_changed_vs_k0=bool(
            findings_hash and k0_hash and findings_hash != k0_hash
        ),
        joern_catalog_grew=metrics.get("joern_catalog_grew", ""),
        refinement_actions_count=len(actions),
        refinement_roles=refinement_roles(arm_entry),
        llm_tokens_triage=metrics.get("llm_tokens_triage", ""),
        llm_tokens_refinement=metrics.get("llm_tokens_refinement", ""),
        llm_triage_s=metrics.get("llm_triage_s", ""),
        llm_refinement_s=metrics.get("llm_refinement_s", ""),
        scan_s=metrics.get("scan_s", ""),
        cpg_build_s=metrics.get("cpg_build_s", ""),
        arm_error_type=str(arm_entry.get("arm_error_type", "")),
        skipped=str(cve_result.get("skipped", "")),
        raw_taint=_maybe("taint", raw_counts),
        raw_relaxed=_maybe("relaxed", raw_counts),
        raw_def_use=_maybe("def_use", raw_counts),
        raw_direct_sink=_maybe("direct_sink", raw_counts),
        post_dedup_taint=_maybe("taint", post_counts),
        post_dedup_relaxed=_maybe("relaxed", post_counts),
        post_dedup_def_use=_maybe("def_use", post_counts),
        post_dedup_direct_sink=_maybe("direct_sink", post_counts),
        tp_relaxed=_relaxed_field("tp_relaxed"),
        fp_relaxed=_relaxed_field("fp_relaxed"),
        fn_relaxed=_relaxed_field("fn_relaxed"),
        n_gt_clusters=_relaxed_field("n_gt_clusters"),
        tp_uncertain_relaxed=_relaxed_field("tp_uncertain_relaxed"),
        fp_uncertain_relaxed=_relaxed_field("fp_uncertain_relaxed"),
        fn_uncertain_relaxed=_relaxed_field("fn_uncertain_relaxed"),
        n_uncertain_credits=_relaxed_field("n_uncertain_credits"),
    )


def _hunks_for_cve(
    cve_record: dict[str, Any], diffs_dir: Path | None
) -> dict[str, list[tuple[int, int]]]:
    """Resolve and parse the per-CVE diff hunks (best-effort)."""
    diff_rel = str(cve_record.get("patch_diff_path", "") or "")
    if not diff_rel:
        return {}
    candidates: list[Path] = []
    diff_path = Path(diff_rel)
    if diff_path.is_absolute():
        candidates.append(diff_path)
    if diffs_dir is not None:
        candidates.append(diffs_dir / Path(diff_rel).name)
        candidates.append(diffs_dir / diff_rel)
    for candidate in candidates:
        if candidate.exists():
            return _load_changed_hunks(candidate)
    return {}


def _resolve_diffs_dir(dataset_path: Path, cli_diffs_dir: Path | None) -> Path | None:
    """Pick the diff directory: CLI override, then ``<dataset_dir>/diffs``."""
    if cli_diffs_dir is not None:
        return cli_diffs_dir
    candidate = dataset_path.parent / "diffs"
    if candidate.is_dir():
        return candidate
    return None


def build_audit(
    results: list[dict[str, Any]],
    dataset: list[dict[str, Any]],
    *,
    line_tolerance: int,
    diffs_dir: Path | None = None,
    cluster_gap: int = DEFAULT_GT_CLUSTER_GAP,
) -> dict[str, Any]:
    """Build all audit rows and aggregate summaries."""
    dataset_index = dataset_by_cve(dataset)
    fp_rows: list[AuditFindingRow] = []
    fn_rows: list[MissedGroundTruthRow] = []
    iteration_rows: list[IterationAudit] = []
    skipped_rows: list[dict[str, Any]] = []

    for cve_result in results:
        cve_id = str(cve_result.get("cve_id", ""))
        if cve_result.get("skipped") and not cve_result.get("arms"):
            skipped_rows.append(
                {
                    "cve_id": cve_id,
                    "skipped": cve_result.get("skipped", ""),
                    "per_cve_timeout_s": cve_result.get("per_cve_timeout_s", ""),
                    "repo_url": cve_result.get("repo_url", ""),
                }
            )
            continue

        ground_truth = dataset_index.get(cve_id, {})
        hunks_for_cve = _hunks_for_cve(ground_truth, diffs_dir)
        joern_arms = iter_joern_arms(cve_result)
        k0_hash = ""
        for arm_key, arm_entry in joern_arms:
            if arm_key.k == 0 and not arm_key.patched:
                k0_hash = str((arm_entry.get("metrics") or {}).get("findings_hash", ""))
                break

        for arm_key, arm_entry in joern_arms:
            aligned_rows = build_aligned_rows(
                cve_id,
                arm_key,
                arm_entry,
                ground_truth,
                line_tolerance=line_tolerance,
            )
            relaxed: dict[str, int] | None = None
            if not arm_key.patched and ground_truth.get("vulnerable_lines"):
                relaxed = _relaxed_score_for_iter(
                    aligned_rows,
                    ground_truth,
                    hunks_for_cve,
                    line_tolerance=line_tolerance,
                    cluster_gap=cluster_gap,
                )
            iteration_rows.append(
                make_iteration_audit(
                    cve_result,
                    arm_key,
                    arm_entry,
                    k0_hash,
                    relaxed=relaxed,
                )
            )
            fp_rows.extend(make_fp_rows(aligned_rows))
            if not arm_key.patched:
                fn_rows.extend(
                    make_fn_rows(
                        cve_result,
                        ground_truth,
                        arm_key,
                        arm_entry,
                        aligned_rows,
                        line_tolerance=line_tolerance,
                    )
                )

    return {
        "fp_rows": [asdict(row) for row in fp_rows],
        "fn_rows": [asdict(row) for row in fn_rows],
        "iteration_summary": [asdict(row) for row in iteration_rows],
        "skipped": skipped_rows,
        "summary": summarize_audit(fp_rows, fn_rows, iteration_rows, skipped_rows),
    }


def _recovery_kind_breakdown(
    fp_rows: list[AuditFindingRow],
    fn_rows: list[MissedGroundTruthRow],
    iteration_rows: list[IterationAudit],
) -> dict[str, Any]:
    """Aggregate recovery_kind counters across the audit.

    Reports four views:
      * ``tp_by_kind``: deduped TP-track findings by ``recovery_kind``
        (we infer TP via "label==tp"-equivalent rows whose
        ``fp_cause==""`` from ``fp_rows``-complement; here we just count
        any non-empty recovery_kind on the FP audit by summing
        per-iteration ``post_dedup_*`` columns and subtracting FP.)
      * ``fp_by_kind``: counts from ``fp_rows`` grouped by
        ``recovery_kind``.
      * ``fn_nearest_by_kind``: counts from ``fn_rows`` grouped by
        ``nearest_recovery_kind`` (the kind of the nearest same-file
        triage row, blank when no such row existed).
      * ``raw_total`` / ``post_dedup_total``: column sums across
        non-patched iterations.
    """
    fp_by_kind: Counter[str] = Counter()
    for row in fp_rows:
        kind = row.recovery_kind or "(none)"
        fp_by_kind[kind] += 1

    fn_nearest_by_kind: Counter[str] = Counter()
    for row in fn_rows:
        kind = row.nearest_recovery_kind or "(no_nearest)"
        fn_nearest_by_kind[kind] += 1

    raw_total: Counter[str] = Counter()
    post_total: Counter[str] = Counter()
    for row in iteration_rows:
        if row.patched:
            continue
        for kind in ("taint", "relaxed", "def_use", "direct_sink"):
            raw_value = getattr(row, f"raw_{kind}")
            post_value = getattr(row, f"post_dedup_{kind}")
            if isinstance(raw_value, int):
                raw_total[kind] += raw_value
            if isinstance(post_value, int):
                post_total[kind] += post_value

    return {
        "fp_by_kind": dict(fp_by_kind),
        "fn_nearest_by_kind": dict(fn_nearest_by_kind),
        "raw_total": dict(raw_total),
        "post_dedup_total": dict(post_total),
    }


def _aggregate_relaxed_panes(
    iteration_rows: list[IterationAudit],
) -> dict[str, dict[str, dict[str, int]]]:
    """Build cluster-relaxed and uncertain-relaxed ``totals_by_k`` panes.

    Both panes are *additional* observability lanes that complement
    (never replace) the canonical strict ``totals_by_k`` so historic
    comparisons keep working.

    The cluster-relaxed pane (``relaxed_totals_by_k``) reports
    ``tp_relaxed`` / ``fp_relaxed`` / ``fn_relaxed`` counts and a
    derived ``recall_relaxed`` over the patched-region ``n_gt_clusters``
    denominator.  The uncertain-relaxed pane
    (``uncertain_relaxed_totals_by_k``) goes one step further by
    crediting GT clusters that any UNCERTAIN row touches — useful for
    quantifying how much TP the hallucination brake currently swallows.
    """
    relaxed: dict[str, dict[str, int]] = defaultdict(
        lambda: {
            "tp": 0,
            "fp": 0,
            "fn": 0,
            "n_gt_clusters": 0,
        }
    )
    uncertain: dict[str, dict[str, int]] = defaultdict(
        lambda: {
            "tp": 0,
            "fp": 0,
            "fn": 0,
            "n_credits": 0,
        }
    )

    for row in iteration_rows:
        if row.patched:
            continue
        k_key = str(row.k)
        for src_attr, dest_key in (
            ("tp_relaxed", "tp"),
            ("fp_relaxed", "fp"),
            ("fn_relaxed", "fn"),
            ("n_gt_clusters", "n_gt_clusters"),
        ):
            value = getattr(row, src_attr)
            if isinstance(value, int):
                relaxed[k_key][dest_key] += value
        for src_attr, dest_key in (
            ("tp_uncertain_relaxed", "tp"),
            ("fp_uncertain_relaxed", "fp"),
            ("fn_uncertain_relaxed", "fn"),
            ("n_uncertain_credits", "n_credits"),
        ):
            value = getattr(row, src_attr)
            if isinstance(value, int):
                uncertain[k_key][dest_key] += value

    return {
        "relaxed_totals_by_k": dict(
            sorted(relaxed.items(), key=lambda item: int(item[0]))
        ),
        "uncertain_relaxed_totals_by_k": dict(
            sorted(uncertain.items(), key=lambda item: int(item[0]))
        ),
    }


def summarize_audit(
    fp_rows: list[AuditFindingRow],
    fn_rows: list[MissedGroundTruthRow],
    iteration_rows: list[IterationAudit],
    skipped_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compute compact aggregate counters for stdout and JSON."""
    totals_by_k: dict[str, dict[str, int]] = defaultdict(
        lambda: {"tp": 0, "fp": 0, "fn": 0}
    )
    high_fp: Counter[str] = Counter()
    high_fn: Counter[str] = Counter()
    for row in iteration_rows:
        if row.patched:
            continue
        k_key = str(row.k)
        for metric in ("tp", "fp", "fn"):
            value = getattr(row, metric)
            if isinstance(value, int):
                totals_by_k[k_key][metric] += value
        if isinstance(row.fp, int):
            high_fp[row.cve_id] += row.fp
        if isinstance(row.fn, int):
            high_fn[row.cve_id] += row.fn

    relaxed_panes = _aggregate_relaxed_panes(iteration_rows)
    return {
        "n_iteration_rows": len(iteration_rows),
        "n_fp_rows": len(fp_rows),
        "n_fn_rows": len(fn_rows),
        "n_skipped": len(skipped_rows),
        "totals_by_k": dict(sorted(totals_by_k.items(), key=lambda item: int(item[0]))),
        "fp_causes": dict(Counter(row.fp_cause for row in fp_rows)),
        "fn_causes": dict(Counter(row.fn_cause for row in fn_rows)),
        "top_fp_cves": high_fp.most_common(10),
        "top_fn_cves": high_fn.most_common(10),
        "recovery_kind_breakdown": _recovery_kind_breakdown(
            fp_rows, fn_rows, iteration_rows
        ),
        "relaxed_totals_by_k": relaxed_panes["relaxed_totals_by_k"],
        "uncertain_relaxed_totals_by_k": relaxed_panes["uncertain_relaxed_totals_by_k"],
    }


def write_csv(rows: list[dict[str, Any]], path: Path, fieldnames: list[str]) -> None:
    """Write rows to CSV, preserving headers for empty outputs."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_audit_outputs(audit: dict[str, Any], output_dir: Path) -> dict[str, str]:
    """Persist JSON and CSV audit artifacts."""
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "joern_fp_fn_audit.json"
    fp_csv = output_dir / "fp_rows.csv"
    fn_csv = output_dir / "fn_rows.csv"
    summary_csv = output_dir / "iteration_summary.csv"

    outputs = {
        "json": str(json_path),
        "fp_csv": str(fp_csv),
        "fn_csv": str(fn_csv),
        "iteration_csv": str(summary_csv),
    }

    audit["outputs"] = outputs
    json_path.write_text(json.dumps(audit, indent=2, default=str))
    write_csv(audit["fp_rows"], fp_csv, list(AuditFindingRow.__dataclass_fields__))
    write_csv(audit["fn_rows"], fn_csv, list(MissedGroundTruthRow.__dataclass_fields__))
    write_csv(
        audit["iteration_summary"],
        summary_csv,
        list(IterationAudit.__dataclass_fields__),
    )

    return outputs


def print_summary(
    summary: dict[str, Any],
    output_paths: dict[str, str],
    *,
    score_uncertain_on_gt_as_tp: bool = False,
) -> None:
    """Print a concise terminal summary.

    The strict ``totals_by_k`` pane is always shown.  The cluster-relaxed
    pane (Fix #2) is shown whenever any iteration row carries non-empty
    relaxed counts.  The uncertain-relaxed pane (Fix #3) is shown
    iff ``score_uncertain_on_gt_as_tp`` is True; otherwise it stays in
    the JSON for offline inspection.
    """
    print(f"[audit_joern_results] JSON written to {output_paths['json']}")
    print(f"  iteration rows : {summary['n_iteration_rows']}")
    print(f"  FP rows        : {summary['n_fp_rows']}")
    print(f"  FN rows        : {summary['n_fn_rows']}")
    print(f"  skipped CVEs   : {summary['n_skipped']}")
    print("  totals by k    :")
    for k, totals in summary["totals_by_k"].items():
        print(f"    k={k}: tp={totals['tp']} fp={totals['fp']} fn={totals['fn']}")
    relaxed_pane = summary.get("relaxed_totals_by_k") or {}
    if any(any(v for v in totals.values()) for totals in relaxed_pane.values()):
        print("  relaxed (cluster + hunk):")
        for k, totals in relaxed_pane.items():
            n_clusters = totals.get("n_gt_clusters", 0)
            print(
                f"    k={k}: tp={totals['tp']} fp={totals['fp']} fn={totals['fn']}"
                f" (n_clusters={n_clusters})"
            )
    uncertain_pane = summary.get("uncertain_relaxed_totals_by_k") or {}
    if score_uncertain_on_gt_as_tp and any(
        any(v for v in totals.values()) for totals in uncertain_pane.values()
    ):
        print("  uncertain-on-gt-as-tp:")
        for k, totals in uncertain_pane.items():
            credits = totals.get("n_credits", 0)
            print(
                f"    k={k}: tp={totals['tp']} fp={totals['fp']} fn={totals['fn']}"
                f" (uncertain_credits={credits})"
            )
    print(f"  FP causes      : {summary['fp_causes']}")
    print(f"  FN causes      : {summary['fn_causes']}")
    if summary["top_fp_cves"]:
        print(f"  top FP CVEs    : {summary['top_fp_cves'][:5]}")
    if summary["top_fn_cves"]:
        print(f"  top FN CVEs    : {summary['top_fn_cves'][:5]}")
    breakdown = summary.get("recovery_kind_breakdown") or {}
    if breakdown:
        print("  recovery_kind  :")
        if breakdown.get("post_dedup_total"):
            print(f"    post_dedup   : {breakdown['post_dedup_total']}")
        if breakdown.get("raw_total"):
            print(f"    raw          : {breakdown['raw_total']}")
        if breakdown.get("fp_by_kind"):
            print(f"    fp_by_kind   : {breakdown['fp_by_kind']}")
        if breakdown.get("fn_nearest_by_kind"):
            print(f"    fn_nearest   : {breakdown['fn_nearest_by_kind']}")


def audit_results_json(
    results_path: Path,
    dataset_path: Path | None = None,
    output_dir: Path | None = None,
    *,
    line_tolerance: int | None = None,
    diffs_dir: Path | None = None,
    cluster_gap: int = DEFAULT_GT_CLUSTER_GAP,
) -> dict[str, Any]:
    """Load inputs, build audit rows, write artifacts, and return the audit dict.

    ``diffs_dir`` overrides the auto-resolved ``<dataset_dir>/diffs``
    location used to enrich the cluster-relaxed scoring lane (Fix #2).
    ``cluster_gap`` controls the GT-line gap threshold used to merge
    adjacent vulnerable lines into one logical cluster (Fix #2 default
    matches the historical patch-hunk-spread observation of ~8 lines).
    """
    dataset_path = resolve_dataset_path(results_path, dataset_path)
    line_tolerance = resolve_line_tolerance(results_path, line_tolerance)
    if output_dir is None:
        output_dir = results_path.parent / "audit"

    resolved_diffs_dir = _resolve_diffs_dir(dataset_path, diffs_dir)

    results = load_json(results_path)
    dataset = load_json(dataset_path)
    if not isinstance(results, list):
        raise ValueError(f"{results_path} must contain a list of CVE results")
    if not isinstance(dataset, list):
        raise ValueError(f"{dataset_path} must contain a list of CVE records")

    audit = build_audit(
        results,
        dataset,
        line_tolerance=line_tolerance,
        diffs_dir=resolved_diffs_dir,
        cluster_gap=cluster_gap,
    )
    audit["metadata"] = {
        "results_path": str(results_path),
        "dataset_path": str(dataset_path),
        "output_dir": str(output_dir),
        "line_tolerance": line_tolerance,
        "diffs_dir": str(resolved_diffs_dir) if resolved_diffs_dir else "",
        "gt_cluster_gap": cluster_gap,
    }
    write_audit_outputs(audit, output_dir)
    return audit


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("results_json", type=Path, help="Path to Joern results.json.")
    parser.add_argument(
        "--dataset",
        type=Path,
        default=None,
        help="Dataset metadata JSON. Defaults to run_config.json or project default.",
    )
    parser.add_argument(
        "--line-tolerance",
        type=int,
        default=None,
        help=f"Ground-truth line tolerance. Defaults to run_config or {LINE_TOLERANCE}.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Audit output directory. Defaults to <results_json_dir>/audit.",
    )
    parser.add_argument(
        "--diffs-dir",
        type=Path,
        default=None,
        help=(
            "Directory containing per-CVE patch diffs. Defaults to "
            "<dataset_dir>/diffs. Used by the cluster-relaxed scoring lane "
            "(Fix #2) to extend GT clusters with changed-hunk ranges."
        ),
    )
    parser.add_argument(
        "--gt-cluster-gap",
        type=int,
        default=DEFAULT_GT_CLUSTER_GAP,
        help=(
            "Max line gap to merge vulnerable_lines into one GT cluster for "
            f"the relaxed scoring lane. Default: {DEFAULT_GT_CLUSTER_GAP}."
        ),
    )
    parser.add_argument(
        "--score-uncertain-on-gt-as-tp",
        action="store_true",
        default=False,
        help=(
            "Also print the UNCERTAIN-on-GT-as-TP scoring pane (Fix #3). "
            "Always emitted in the JSON; this flag only controls stdout."
        ),
    )
    args = parser.parse_args(argv)

    if not args.results_json.exists():
        print(f"error: {args.results_json} not found", file=sys.stderr)
        return 2

    try:
        audit = audit_results_json(
            args.results_json,
            args.dataset,
            args.output_dir,
            line_tolerance=args.line_tolerance,
            diffs_dir=args.diffs_dir,
            cluster_gap=args.gt_cluster_gap,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print_summary(
        audit["summary"],
        audit["outputs"],
        score_uncertain_on_gt_as_tp=args.score_uncertain_on_gt_as_tp,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
