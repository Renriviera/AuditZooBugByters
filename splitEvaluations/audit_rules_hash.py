#!/usr/bin/env python3
"""Audit Semgrep refinement effectiveness from a ``results.json`` file.

For every ``semgrep_k`` iteration in every CVE we already record
``rules_hash_pre`` / ``rules_hash_post`` (+ now the YAML byte sizes and
a ``rules_yaml_changed`` flag) in ``iteration.metrics``.  This script
joins those per-iteration rows with the LLM's ``refinement_actions``
log and emits:

1. ``rules_hash_summary.csv`` — one row per (cve_id, arm, k) with
   columns::

      cve_id, arm, k,
      action,                   # from refinement_actions[0] (the only emitted action)
      target_rule_id,
      rules_hash_pre, rules_hash_post,
      rules_yaml_bytes_pre, rules_yaml_bytes_post,
      rules_yaml_changed,
      findings_hash,
      findings_changed_vs_k0,

2. A terminal summary that prints the ``refine_no_op_rate`` =
   (# refine actions where ``rules_yaml_changed == False``) /
   (# refine actions total).  When this rate is high the LLM is
   emitting refine actions that the semgrep_arm.apply_refinement code
   is silently dropping — that's the B2 diagnostic we want to watch.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _iter_semgrep_arms(results: list[dict[str, Any]]):
    """Yield (cve_id, k, arm_entry) for every semgrep_k arm in *results*."""
    for cve in results:
        cve_id = cve.get("cve_id", "")
        arms = cve.get("arms")
        if not isinstance(arms, dict):
            continue
        for arm_key, arm_entry in arms.items():
            if not arm_key.startswith("semgrep_") or arm_key.endswith("_patched"):
                continue
            try:
                k = int(arm_key.rsplit("_", 1)[-1])
            except ValueError:
                continue
            yield cve_id, k, arm_entry


def build_summary_rows(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flatten the semgrep iterations into an audit-friendly table."""
    # For findings_changed_vs_k0 we need each CVE's k=0 findings_hash.
    k0_hash: dict[str, str] = {}
    for cve_id, k, arm in _iter_semgrep_arms(results):
        if k == 0:
            k0_hash[cve_id] = (arm.get("metrics") or {}).get("findings_hash", "")

    rows: list[dict[str, Any]] = []
    for cve_id, k, arm in _iter_semgrep_arms(results):
        metrics = arm.get("metrics") or {}
        actions = arm.get("refinement_actions") or []
        action0 = actions[0] if actions else {}

        rules_yaml_changed = metrics.get("rules_yaml_changed")
        if rules_yaml_changed is None:
            # Back-compat with results.json files predating the
            # yaml_bytes_* columns: approximate "changed" via the hash.
            rules_yaml_changed = (
                metrics.get("rules_hash_pre") != metrics.get("rules_hash_post")
            )

        findings_hash = metrics.get("findings_hash", "")
        rows.append({
            "cve_id": cve_id,
            "arm": "semgrep",
            "k": k,
            "action": action0.get("action", ""),
            "target_rule_id": action0.get("target_rule_id", ""),
            "rules_hash_pre": metrics.get("rules_hash_pre", ""),
            "rules_hash_post": metrics.get("rules_hash_post", ""),
            "rules_yaml_bytes_pre": metrics.get("rules_yaml_bytes_pre", ""),
            "rules_yaml_bytes_post": metrics.get("rules_yaml_bytes_post", ""),
            "rules_yaml_changed": bool(rules_yaml_changed),
            "findings_hash": findings_hash,
            "findings_changed_vs_k0": bool(
                findings_hash and k0_hash.get(cve_id)
                and findings_hash != k0_hash[cve_id]
            ),
        })
    return rows


def compute_no_op_rate(rows: list[dict[str, Any]]) -> tuple[int, int, float]:
    """Return (refine_total, refine_no_op, no_op_rate)."""
    refine_rows = [r for r in rows if r["action"] == "refine"]
    total = len(refine_rows)
    no_op = sum(1 for r in refine_rows if not r["rules_yaml_changed"])
    rate = no_op / total if total else 0.0
    return total, no_op, rate


def compute_findings_invariance(rows: list[dict[str, Any]]) -> tuple[int, int, float]:
    """Return (cves, n_with_k_invariant_findings, frac)."""
    by_cve: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        by_cve.setdefault(r["cve_id"], []).append(r)
    n_cves = len(by_cve)
    n_invariant = 0
    for cve_rows in by_cve.values():
        hashes = {r["findings_hash"] for r in cve_rows if r["findings_hash"]}
        if len(hashes) == 1 and len(cve_rows) > 1:
            n_invariant += 1
    frac = n_invariant / n_cves if n_cves else 0.0
    return n_cves, n_invariant, frac


def write_csv(rows: list[dict[str, Any]], path: Path) -> None:
    """Dump *rows* to CSV at *path* (parents created)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("")
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def audit_results_json(results_path: Path, csv_path: Path | None = None) -> dict[str, Any]:
    """Full audit pass: load results.json, emit CSV, return a summary dict."""
    data = json.loads(results_path.read_text())
    rows = build_summary_rows(data)

    if csv_path is None:
        csv_path = results_path.parent / "rules_hash_summary.csv"
    write_csv(rows, csv_path)

    refine_total, refine_no_op, no_op_rate = compute_no_op_rate(rows)
    n_cves, n_invariant, invariant_frac = compute_findings_invariance(rows)

    summary = {
        "results_path": str(results_path),
        "csv_path": str(csv_path),
        "n_semgrep_rows": len(rows),
        "refine_actions_total": refine_total,
        "refine_actions_no_op": refine_no_op,
        "refine_no_op_rate": no_op_rate,
        "cves_in_audit": n_cves,
        "cves_with_k_invariant_findings": n_invariant,
        "findings_invariance_frac": invariant_frac,
    }
    return summary


def _print_summary(summary: dict[str, Any]) -> None:
    print(f"[audit_rules_hash] rows written to {summary['csv_path']}")
    print(f"  semgrep iteration rows        : {summary['n_semgrep_rows']}")
    print(f"  refine actions                : {summary['refine_actions_total']}")
    print(f"  refine actions that were no-ops: {summary['refine_actions_no_op']}")
    print(
        f"  refine_no_op_rate             : "
        f"{summary['refine_no_op_rate']:.2%} "
        f"(LLM refines but YAML didn't change)"
    )
    print(f"  CVEs audited                  : {summary['cves_in_audit']}")
    print(
        f"  CVEs with k-invariant findings: {summary['cves_with_k_invariant_findings']} "
        f"({summary['findings_invariance_frac']:.2%})"
    )

    if summary["refine_actions_total"] > 0 and summary["refine_no_op_rate"] > 0.5:
        print(
            "[audit_rules_hash] WARNING: >50% of refine actions left "
            "the YAML unchanged — semgrep_arm.apply_refinement is the "
            "likely B2 blocker."
        )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "results_json", type=Path,
        help="Path to a sweep's results.json "
             "(e.g. results/semgrep/20260422_.../results.json).",
    )
    ap.add_argument(
        "--csv", type=Path, default=None,
        help="Override output CSV path "
             "(default: <results_json_dir>/rules_hash_summary.csv).",
    )
    args = ap.parse_args(argv)

    if not args.results_json.exists():
        print(f"error: {args.results_json} not found", file=sys.stderr)
        return 2

    summary = audit_results_json(args.results_json, args.csv)
    _print_summary(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
