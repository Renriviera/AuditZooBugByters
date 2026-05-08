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
    """Map a saved scorer label and triager verdict to an audit-facing FP cause."""
    if row["patched"]:
        return "patched_commit_alert"

    label = str(row.get("label", ""))
    triage = row.get("triage") or {}
    verdict = str(triage.get("verdict", ""))

    if label == "fp_by_hallucinated_source" or triage.get("source_in_snippet") is False:
        return "evidence_hallucination"
    if label == "fp_by_llm_overclaim" or verdict == "true_positive":
        return "triager_overclaim"
    if label == "fp_by_location" or verdict == "uncertain":
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


def make_iteration_audit(
    cve_result: dict[str, Any],
    arm_key: ArmKey,
    arm_entry: dict[str, Any],
    k0_hash: str,
) -> IterationAudit:
    """Build one per-iteration audit row."""
    metrics = arm_entry.get("metrics") or {}
    findings_hash = str(metrics.get("findings_hash", ""))
    actions = arm_entry.get("refinement_actions") or []
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
    )


def build_audit(
    results: list[dict[str, Any]],
    dataset: list[dict[str, Any]],
    *,
    line_tolerance: int,
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
            iteration_rows.append(
                make_iteration_audit(cve_result, arm_key, arm_entry, k0_hash)
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


def print_summary(summary: dict[str, Any], output_paths: dict[str, str]) -> None:
    """Print a concise terminal summary."""
    print(f"[audit_joern_results] JSON written to {output_paths['json']}")
    print(f"  iteration rows : {summary['n_iteration_rows']}")
    print(f"  FP rows        : {summary['n_fp_rows']}")
    print(f"  FN rows        : {summary['n_fn_rows']}")
    print(f"  skipped CVEs   : {summary['n_skipped']}")
    print("  totals by k    :")
    for k, totals in summary["totals_by_k"].items():
        print(f"    k={k}: tp={totals['tp']} fp={totals['fp']} fn={totals['fn']}")
    print(f"  FP causes      : {summary['fp_causes']}")
    print(f"  FN causes      : {summary['fn_causes']}")
    if summary["top_fp_cves"]:
        print(f"  top FP CVEs    : {summary['top_fp_cves'][:5]}")
    if summary["top_fn_cves"]:
        print(f"  top FN CVEs    : {summary['top_fn_cves'][:5]}")


def audit_results_json(
    results_path: Path,
    dataset_path: Path | None = None,
    output_dir: Path | None = None,
    *,
    line_tolerance: int | None = None,
) -> dict[str, Any]:
    """Load inputs, build audit rows, write artifacts, and return the audit dict."""
    dataset_path = resolve_dataset_path(results_path, dataset_path)
    line_tolerance = resolve_line_tolerance(results_path, line_tolerance)
    if output_dir is None:
        output_dir = results_path.parent / "audit"

    results = load_json(results_path)
    dataset = load_json(dataset_path)
    if not isinstance(results, list):
        raise ValueError(f"{results_path} must contain a list of CVE results")
    if not isinstance(dataset, list):
        raise ValueError(f"{dataset_path} must contain a list of CVE records")

    audit = build_audit(results, dataset, line_tolerance=line_tolerance)
    audit["metadata"] = {
        "results_path": str(results_path),
        "dataset_path": str(dataset_path),
        "output_dir": str(output_dir),
        "line_tolerance": line_tolerance,
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
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print_summary(audit["summary"], audit["outputs"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
