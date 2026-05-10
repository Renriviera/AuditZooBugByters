#!/usr/bin/env python3
"""Merge a targeted Semgrep rerun into a prior sweep results.json."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str))


def merge_results(prior_rows: list[dict[str, Any]], rerun_rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Merge *rerun_rows* over *prior_rows* by CVE ID, preserving prior order."""
    rerun_by_cve = {str(row.get("cve_id")): row for row in rerun_rows if row.get("cve_id")}
    prior_seen: set[str] = set()
    merged: list[dict[str, Any]] = []
    replaced = 0

    for row in prior_rows:
        cve_id = str(row.get("cve_id", ""))
        if cve_id and cve_id in rerun_by_cve:
            merged.append(rerun_by_cve[cve_id])
            replaced += 1
        else:
            merged.append(row)
        if cve_id:
            prior_seen.add(cve_id)

    appended = 0
    for row in rerun_rows:
        cve_id = str(row.get("cve_id", ""))
        if cve_id and cve_id not in prior_seen:
            merged.append(row)
            appended += 1

    summary = {
        "prior_rows": len(prior_rows),
        "rerun_rows": len(rerun_rows),
        "merged_rows": len(merged),
        "replaced_rows": replaced,
        "appended_rows": appended,
        "rerun_full_rows": sum(1 for row in rerun_rows if isinstance(row.get("arms"), dict)),
        "rerun_timeout_rows": sum(1 for row in rerun_rows if row.get("skipped") == "timeout"),
        "rerun_error_rows": sum(1 for row in rerun_rows if row.get("skipped") == "error"),
    }
    return merged, summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prior", type=Path, required=True)
    parser.add_argument("--rerun", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--summary-out", type=Path, default=None)
    args = parser.parse_args(argv)

    merged, summary = merge_results(load_json(args.prior), load_json(args.rerun))
    write_json(args.out, merged)
    if args.summary_out is not None:
        write_json(args.summary_out, summary)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
