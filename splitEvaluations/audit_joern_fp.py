#!/usr/bin/env python3
"""Audit false positives from a Joern diagnostic ``results.json`` file."""

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

from splitEvaluations.common import DEFAULT_DATASET, _save_json  # noqa: E402

OUTPUT_BASENAME = "joern_fp_audit"
FP_LABELS = {
    "fp_by_location",
    "fp_by_llm_overclaim",
    "fp_by_hallucinated_source",
}
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
    parser.add_argument("--results-json", type=Path, required=True)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Output directory (default: parent of --results-json).",
    )
    parser.add_argument("--arm-key", default="joern_0")
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


def _file_relation(candidate_file: str, gt_file: str) -> str:
    if _path_matches(candidate_file, gt_file):
        return "gt_file"
    if (
        candidate_file
        and gt_file
        and (
            Path(candidate_file).parent == Path(gt_file).parent
            or _shared_prefix_depth(candidate_file, gt_file) >= 2
        )
    ):
        return "same_package"
    if candidate_file:
        return "other_file"
    return "missing_file"


def _semantic_flags(candidate: dict[str, Any]) -> list[str]:
    return [flag for flag in SINK_SEMANTIC_FLAGS if candidate.get(flag)]


def build_fp_rows(
    results: list[dict[str, Any]],
    metadata_by_cve: dict[str, dict[str, Any]],
    *,
    arm_key: str = "joern_0",
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for cve_result in results:
        cve_id = str(cve_result.get("cve_id", "") or "")
        ground_truth = metadata_by_cve.get(cve_id, {})
        gt_file = str(ground_truth.get("vulnerable_file", "") or "")
        arm = (cve_result.get("arms") or {}).get(arm_key) or {}
        candidates = list(arm.get("triage_verdicts") or [])
        labels = list(arm.get("labels") or [])
        if labels and len(labels) != len(candidates):
            raise ValueError(
                f"{cve_id} {arm_key}: labels length {len(labels)} does not match "
                f"triage_verdicts length {len(candidates)}"
            )
        if not labels:
            labels = [""] * len(candidates)

        for idx, (candidate, label) in enumerate(zip(candidates, labels, strict=False)):
            label = str(label or "")
            if label not in FP_LABELS:
                continue
            candidate_file = str(candidate.get("file", "") or "")
            flags = _semantic_flags(candidate)
            rows.append(
                {
                    "cve_id": cve_id,
                    "arm_key": arm_key,
                    "finding_index": idx,
                    "label": label,
                    "gt_file": gt_file,
                    "file": candidate_file,
                    "line": int(candidate.get("line", 0) or 0),
                    "file_relation": _file_relation(candidate_file, gt_file),
                    "verdict": str(candidate.get("verdict", "") or ""),
                    "confidence": float(candidate.get("confidence", 0.0) or 0.0),
                    "sink_api": str(candidate.get("sink_api", "") or ""),
                    "source_in_snippet": bool(
                        candidate.get("source_in_snippet", False)
                    ),
                    "originExternalSource": bool(
                        candidate.get("originExternalSource", False)
                    ),
                    "sinkKind": str(candidate.get("sinkKind", "") or ""),
                    "sourceKind": str(candidate.get("sourceKind", "") or ""),
                    "joern_report_reason": str(
                        candidate.get("joern_report_reason", "") or ""
                    ),
                    "semantic_flags": flags,
                    "sink_expr": str(candidate.get("sink_expr", "") or ""),
                    "source_expr": str(candidate.get("source_expr", "") or ""),
                    "reasoning": str(candidate.get("reasoning", "") or ""),
                }
            )
    return rows


def build_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_label = Counter(str(row.get("label", "")) for row in rows)
    by_verdict = Counter(str(row.get("verdict", "")) for row in rows)
    by_file_relation = Counter(str(row.get("file_relation", "")) for row in rows)
    by_sink_api = Counter(str(row.get("sink_api", "")) for row in rows)
    by_cve = Counter(str(row.get("cve_id", "")) for row in rows)
    by_file = Counter(str(row.get("file", "")) for row in rows)
    by_sink_kind = Counter(str(row.get("sinkKind", "")) for row in rows)
    by_report_reason = Counter(str(row.get("joern_report_reason", "")) for row in rows)
    by_semantic_flag = Counter()
    for row in rows:
        flags = row.get("semantic_flags") or []
        if flags:
            by_semantic_flag.update(str(flag) for flag in flags)
        else:
            by_semantic_flag["no_semantic_flag"] += 1

    return {
        "total_fp": len(rows),
        "fp_by_location": by_label.get("fp_by_location", 0),
        "fp_by_llm_overclaim": by_label.get("fp_by_llm_overclaim", 0),
        "fp_by_hallucinated_source": by_label.get("fp_by_hallucinated_source", 0),
        "by_label": dict(by_label.most_common()),
        "by_verdict": dict(by_verdict.most_common()),
        "by_file_relation": dict(by_file_relation.most_common()),
        "by_sink_api": dict(by_sink_api.most_common(15)),
        "by_sink_kind": dict(by_sink_kind.most_common(10)),
        "by_report_reason": dict(by_report_reason.most_common(10)),
        "by_semantic_flag": dict(by_semantic_flag.most_common()),
        "top_cves": dict(by_cve.most_common(15)),
        "top_files": dict(by_file.most_common(15)),
    }


def _csv_value(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return value


def write_csv(rows: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "cve_id",
        "arm_key",
        "finding_index",
        "label",
        "gt_file",
        "file",
        "line",
        "file_relation",
        "verdict",
        "confidence",
        "sink_api",
        "source_in_snippet",
        "originExternalSource",
        "sinkKind",
        "sourceKind",
        "joern_report_reason",
        "semantic_flags",
        "sink_expr",
        "source_expr",
        "reasoning",
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
        "# Joern FP Audit",
        "",
        "## Summary",
        "",
        f"- FP rows: {summary['total_fp']}",
        f"- FP by location: {summary['fp_by_location']}",
        f"- FP by LLM overclaim: {summary['fp_by_llm_overclaim']}",
        f"- FP by hallucinated source: {summary['fp_by_hallucinated_source']}",
        f"- Labels: {json.dumps(summary['by_label'], sort_keys=True)}",
        f"- Verdicts: {json.dumps(summary['by_verdict'], sort_keys=True)}",
        f"- File relations: {json.dumps(summary['by_file_relation'], sort_keys=True)}",
        f"- Top sink APIs: {json.dumps(summary['by_sink_api'], sort_keys=True)}",
        f"- Top semantic flags: {json.dumps(summary['by_semantic_flag'], sort_keys=True)}",
        "",
        "## Top CVEs",
        "",
    ]
    for cve_id, count in summary["top_cves"].items():
        lines.append(f"- `{cve_id}`: {count}")
    lines.extend(["", "## Top Files", ""])
    for file_path, count in summary["top_files"].items():
        lines.append(f"- `{file_path}`: {count}")
    lines.extend(
        [
            "",
            "## Rows",
            "",
            "| CVE | Label | Finding | GT file | Verdict | Relation | Sink |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for row in rows:
        lines.append(
            "| {cve_id} | {label} | {file}:{line} | {gt_file} | {verdict} | "
            "{file_relation} | {sink_api} |".format(**row)
        )
    path.write_text("\n".join(lines) + "\n")


def audit_results_json(
    results_path: Path,
    dataset_path: Path = DEFAULT_DATASET,
    *,
    output_dir: Path | None = None,
    arm_key: str = "joern_0",
    formats: list[str] | tuple[str, ...] = ("json", "csv", "md"),
) -> dict[str, Any]:
    results = load_json(results_path)
    metadata_by_cve = load_metadata(dataset_path)
    rows = build_fp_rows(results, metadata_by_cve, arm_key=arm_key)
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
        "output_dir": str(out_dir),
        "summary": summary,
        "rows": rows,
        "artifacts": artifacts,
    }


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    output = audit_results_json(
        args.results_json,
        args.dataset,
        output_dir=args.output_dir,
        arm_key=args.arm_key,
        formats=args.format,
    )
    summary = output["summary"]
    print(f"[audit_joern_fp] output_dir: {output['output_dir']}")
    print(f"  FP rows        : {summary['total_fp']}")
    print(f"  labels         : {summary['by_label']}")
    print(f"  verdicts       : {summary['by_verdict']}")
    print(f"  file relations : {summary['by_file_relation']}")
    for fmt, path in output["artifacts"].items():
        print(f"  {fmt}: {path}")


if __name__ == "__main__":
    main()
