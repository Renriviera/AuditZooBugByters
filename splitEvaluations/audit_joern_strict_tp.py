#!/usr/bin/env python3
"""Audit strict Joern TPs by LLM verdict from a diagnostic results.json."""

from __future__ import annotations

import argparse
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

OUTPUT_BASENAME = "joern_strict_tp_audit"


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
    parser.add_argument("--line-tolerance", type=int, default=LINE_TOLERANCE)
    parser.add_argument(
        "--format",
        nargs="+",
        choices=("json", "md"),
        default=["json", "md"],
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


def _matched_gt_line(
    candidate: dict[str, Any],
    gt_file: str,
    gt_lines: list[int],
    line_tolerance: int,
) -> int | None:
    if candidate.get("matched_gt_line") is not None:
        try:
            return int(candidate["matched_gt_line"])
        except (TypeError, ValueError):
            return None
    if not _path_matches(str(candidate.get("file", "")), gt_file):
        return None
    try:
        line = int(candidate.get("line", 0) or 0)
    except (TypeError, ValueError):
        return None
    for gt_line in gt_lines:
        if abs(line - int(gt_line)) <= line_tolerance:
            return int(gt_line)
    return None


def _verdict_bucket(verdict: str) -> str:
    if verdict == "true_positive":
        return "llm_true_positive"
    if verdict == "uncertain":
        return "llm_uncertain"
    return "llm_other"


def build_strict_tp_rows(
    results: list[dict[str, Any]],
    metadata_by_cve: dict[str, dict[str, Any]],
    *,
    arm_key: str = "joern_0",
    line_tolerance: int = LINE_TOLERANCE,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for cve_result in results:
        cve_id = str(cve_result.get("cve_id", "") or "")
        ground_truth = metadata_by_cve.get(cve_id, {})
        gt_file = str(ground_truth.get("vulnerable_file", "") or "")
        gt_lines = [
            int(line) for line in ground_truth.get("vulnerable_lines", []) or []
        ]
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
            matched_gt_line = _matched_gt_line(
                candidate, gt_file, gt_lines, line_tolerance
            )
            is_strict_match = bool(candidate.get("is_strict_match", False)) or (
                matched_gt_line is not None
            )
            if not is_strict_match or label != "tp":
                continue
            verdict = str(candidate.get("verdict", "") or "")
            rows.append(
                {
                    "cve_id": cve_id,
                    "arm_key": arm_key,
                    "finding_index": idx,
                    "gt_file": gt_file,
                    "gt_line": matched_gt_line,
                    "file": str(candidate.get("file", "") or ""),
                    "line": int(candidate.get("line", 0) or 0),
                    "label": label,
                    "verdict": verdict,
                    "verdict_bucket": _verdict_bucket(verdict),
                    "source_in_snippet": bool(
                        candidate.get("source_in_snippet", False)
                    ),
                    "originExternalSource": bool(
                        candidate.get("originExternalSource", False)
                    ),
                    "same_package": bool(candidate.get("same_package", False)),
                    "same_package_promoted": bool(
                        candidate.get("same_package_promoted", False)
                    ),
                    "source_expr": str(candidate.get("source_expr", "") or ""),
                    "sink_expr": str(candidate.get("sink_expr", "") or ""),
                    "reasoning": str(candidate.get("reasoning", "") or ""),
                }
            )
    return rows


def build_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_bucket = Counter(str(row.get("verdict_bucket", "")) for row in rows)
    by_cve: dict[str, Counter[str]] = {}
    for row in rows:
        cve_id = str(row.get("cve_id", "") or "")
        by_cve.setdefault(cve_id, Counter())[str(row.get("verdict_bucket", ""))] += 1
    return {
        "tp_strict_total": len(rows),
        "tp_strict_by_llm_tp": by_bucket.get("llm_true_positive", 0),
        "tp_strict_by_llm_uncertain": by_bucket.get("llm_uncertain", 0),
        "tp_strict_by_llm_other": by_bucket.get("llm_other", 0),
        "strict_tp_cves": sorted(by_cve),
        "per_cve": {
            cve_id: {
                "total": sum(counter.values()),
                "llm_true_positive": counter.get("llm_true_positive", 0),
                "llm_uncertain": counter.get("llm_uncertain", 0),
                "llm_other": counter.get("llm_other", 0),
            }
            for cve_id, counter in sorted(by_cve.items())
        },
    }


def write_markdown(
    rows: list[dict[str, Any]], summary: dict[str, Any], path: Path
) -> None:
    lines = [
        "# Joern Strict-TP Audit",
        "",
        f"- Strict TP findings: {summary['tp_strict_total']}",
        f"- Strict TP with LLM true_positive: {summary['tp_strict_by_llm_tp']}",
        f"- Strict TP with LLM uncertain: {summary['tp_strict_by_llm_uncertain']}",
        f"- Strict TP with other LLM verdict: {summary['tp_strict_by_llm_other']}",
        f"- CVEs with strict TP: {', '.join(summary['strict_tp_cves']) or 'none'}",
        "",
        "## Per-CVE Counts",
        "",
        "| CVE | Total | LLM TP | LLM Uncertain | Other |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for cve_id, row in summary["per_cve"].items():
        lines.append(
            f"| {cve_id} | {row['total']} | {row['llm_true_positive']} | "
            f"{row['llm_uncertain']} | {row['llm_other']} |"
        )
    lines.extend(
        [
            "",
            "## Strict TP Findings",
            "",
            "| CVE | GT | Finding | Verdict | Source in snippet | Origin external |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for row in rows:
        lines.append(
            "| {cve_id} | {gt_file}:{gt_line} | {file}:{line} | {verdict} | "
            "{source_in_snippet} | {originExternalSource} |".format(**row)
        )
    path.write_text("\n".join(lines) + "\n")


def audit_results_json(
    results_path: Path,
    dataset_path: Path = DEFAULT_DATASET,
    *,
    output_dir: Path | None = None,
    arm_key: str = "joern_0",
    line_tolerance: int = LINE_TOLERANCE,
    formats: list[str] | tuple[str, ...] = ("json", "md"),
) -> dict[str, Any]:
    results = load_json(results_path)
    metadata_by_cve = load_metadata(dataset_path)
    rows = build_strict_tp_rows(
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


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    result = audit_results_json(
        args.results_json,
        args.dataset,
        output_dir=args.output_dir,
        arm_key=args.arm_key,
        line_tolerance=args.line_tolerance,
        formats=args.format,
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
