#!/usr/bin/env python3
"""Pick Semgrep CVEs that should be rerun from a prior sweep."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def pick_targets(prior_dir: Path) -> dict[str, Any]:
    """Return timeout and missing-row CVEs from *prior_dir*."""
    results = load_json(prior_dir / "results.json")
    run_config = load_json(prior_dir / "run_config.json")

    validation_cves = [str(cve) for cve in run_config.get("validation_cves", [])]
    seen = {str(row.get("cve_id")) for row in results if row.get("cve_id")}
    timeout_cves = [
        str(row["cve_id"])
        for row in results
        if row.get("cve_id") and row.get("skipped") == "timeout"
    ]
    missing_cves = [cve for cve in validation_cves if cve not in seen]
    targets = [cve for cve in validation_cves if cve in set(timeout_cves) | set(missing_cves)]
    return {
        "prior_dir": str(prior_dir),
        "validation_count": len(validation_cves),
        "timeout_count": len(timeout_cves),
        "missing_count": len(missing_cves),
        "target_count": len(targets),
        "timeout_cves": timeout_cves,
        "missing_cves": missing_cves,
        "targets": targets,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prior-dir", type=Path, required=True)
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print a structured JSON payload instead of a space-separated CVE list.",
    )
    args = parser.parse_args(argv)

    payload = pick_targets(args.prior_dir)
    print(
        "pick_rerun_targets: "
        f"{payload['target_count']} targets "
        f"({payload['timeout_count']} timeouts, {payload['missing_count']} missing rows)",
        file=sys.stderr,
    )
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(" ".join(payload["targets"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
