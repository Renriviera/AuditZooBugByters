#!/usr/bin/env python3
"""Build Markdown and JSON rollups for Semgrep sweep results."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from splitEvaluations.audit_rules_hash import audit_results_json


def load_json(path: Path | None, default: Any = None) -> Any:
    if path is None or not path.is_file():
        return default
    return json.loads(path.read_text())


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str))


def _token_rollup(row: dict[str, Any]) -> tuple[int, int, int]:
    triage = 0
    refine = 0
    for key, arm in (row.get("arms") or {}).items():
        if not key.startswith("semgrep"):
            continue
        metrics = arm.get("metrics") or {}
        triage += int(metrics.get("llm_tokens_triage") or 0)
        refine += int(metrics.get("llm_tokens_refinement") or 0)
    return triage, refine, triage + refine


def _tpfpfn(row: dict[str, Any], arm_key: str) -> tuple[int, int, int]:
    arm = (row.get("arms") or {}).get(arm_key) or {}
    return int(arm.get("tp") or 0), int(arm.get("fp") or 0), int(arm.get("fn") or 0)


def _patched_stats(results: list[dict[str, Any]], arm_key: str = "semgrep_3_patched") -> dict[str, Any]:
    findings = 0
    triage_counts = {"true_positive": 0, "false_positive": 0, "other_mostly_uncertain": 0}
    for row in results:
        arm = (row.get("arms") or {}).get(arm_key) or {}
        n = arm.get("n_findings_on_patched")
        if n is None:
            n = (arm.get("metrics") or {}).get("n_findings", 0)
        findings += int(n or 0)
        for verdict in arm.get("triage_verdicts") or []:
            value = str(verdict.get("verdict", "")).lower()
            if value == "true_positive":
                triage_counts["true_positive"] += 1
            elif value == "false_positive":
                triage_counts["false_positive"] += 1
            else:
                triage_counts["other_mostly_uncertain"] += 1
    return {
        "note": "Patched arms do not include top-level tp/fp/fn in results.json; metrics below are triage/finding counts only.",
        "total_findings_summed": findings,
        "triage_verdict_counts": triage_counts,
    }


def _rerun_outcome(rerun_results: list[dict[str, Any]], prior_results: list[dict[str, Any]]) -> dict[str, Any]:
    if not rerun_results:
        return {}
    prior_status = {str(row.get("cve_id")): row.get("skipped", "full") for row in prior_results if row.get("cve_id")}
    rerun_cves = [str(row.get("cve_id")) for row in rerun_results if row.get("cve_id")]
    full = [str(row["cve_id"]) for row in rerun_results if isinstance(row.get("arms"), dict)]
    timeout = [str(row["cve_id"]) for row in rerun_results if row.get("skipped") == "timeout"]
    error = [str(row["cve_id"]) for row in rerun_results if row.get("skipped") == "error"]
    other = [
        str(row["cve_id"])
        for row in rerun_results
        if row.get("cve_id")
        and not isinstance(row.get("arms"), dict)
        and row.get("skipped") not in {"timeout", "error"}
    ]
    missing_rows = sorted(set(rerun_cves) - {str(row.get("cve_id")) for row in rerun_results})
    return {
        "rerun_row_count": len(rerun_results),
        "full_after_rerun_count": len(full),
        "still_timeout_count": len(timeout),
        "error_count": len(error),
        "other_skipped_count": len(other),
        "missing_rows_count": len(missing_rows),
        "full_after_rerun_cves": full,
        "still_timeout_cves": timeout,
        "error_cves": error,
        "other_skipped_cves": other,
        "prior_status_by_rerun_cve": {cve: prior_status.get(cve, "missing_row") for cve in rerun_cves},
    }


def build_rollup(
    *,
    results_path: Path,
    run_config_path: Path,
    out_dir: Path,
    label: str,
    seed_usage_path: Path | None = None,
    rerun_results_path: Path | None = None,
    prior_results_path: Path | None = None,
    rerun_run_config_path: Path | None = None,
    seed_meta_path: Path | None = None,
) -> tuple[Path, Path]:
    results = load_json(results_path, [])
    run_config = load_json(run_config_path, {})
    seed_usage = load_json(seed_usage_path, {})
    rerun_results = load_json(rerun_results_path, [])
    prior_results = load_json(prior_results_path, [])
    rerun_run_config = load_json(rerun_run_config_path, {})
    seed_meta = load_json(seed_meta_path, {})

    full_results = [row for row in results if isinstance(row.get("arms"), dict)]
    timeout_cves = [str(row.get("cve_id")) for row in results if row.get("skipped") == "timeout"]
    validation_cves = [str(cve) for cve in run_config.get("validation_cves", [])]
    result_cves = {str(row.get("cve_id")) for row in results if row.get("cve_id")}
    missing_cves = [cve for cve in validation_cves if cve not in result_cves]

    per_cve_tokens = []
    pipeline_triage = 0
    pipeline_refine = 0
    for row in full_results:
        triage, refine, total = _token_rollup(row)
        pipeline_triage += triage
        pipeline_refine += refine
        per_cve_tokens.append({
            "cve_id": row.get("cve_id"),
            "triage_tokens": triage,
            "refinement_tokens": refine,
            "subtotal_tokens": total,
        })
    per_cve_tokens.sort(key=lambda item: -item["subtotal_tokens"])

    seed_total = int(seed_usage.get("total_tokens") or 0)
    totals_3 = [0, 0, 0]
    totals_0 = [0, 0, 0]
    for row in full_results:
        for idx, value in enumerate(_tpfpfn(row, "semgrep_3")):
            totals_3[idx] += value
        for idx, value in enumerate(_tpfpfn(row, "semgrep_0")):
            totals_0[idx] += value

    audit_path = out_dir / f"{label}_rules_hash_summary.csv"
    rules_hash_audit = audit_results_json(results_path, audit_path)

    rollup = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "label": label,
        "source_artifacts": {
            "results_json": str(results_path),
            "run_config_json": str(run_config_path),
            "seed_llm_usage_json": str(seed_usage_path) if seed_usage_path else None,
            "rerun_results_json": str(rerun_results_path) if rerun_results_path else None,
            "prior_results_json": str(prior_results_path) if prior_results_path else None,
        },
        "run_config_summary": {
            "llm_model": run_config.get("llm_model"),
            "seed_model": run_config.get("seed_model"),
            "llm_url": run_config.get("llm_url"),
            "max_k": run_config.get("max_k"),
            "per_cve_timeout_s": run_config.get("per_cve_timeout"),
            "clone_timeout_s": run_config.get("clone_timeout_s"),
            "run_patched": not run_config.get("no_patched", False),
            "dataset_size": run_config.get("dataset_size"),
            "train_fraction": run_config.get("train_fraction"),
            "seed": run_config.get("seed"),
            "selected_count": run_config.get("selected_count"),
            "training_count": run_config.get("training_count"),
            "validation_count": run_config.get("validation_count"),
        },
        "rerun_config_summary": {
            "per_cve_timeout_s": rerun_run_config.get("per_cve_timeout"),
            "clone_timeout_s": rerun_run_config.get("clone_timeout_s"),
            "only_cves": rerun_run_config.get("only_cves", []),
            "seed_cache_fingerprint": rerun_run_config.get("seed_cache_fingerprint"),
            "seed_cache_hit": rerun_run_config.get("seed_cache_hit"),
        },
        "seed_cache": seed_meta,
        "coverage": {
            "validation_cves_planned": len(validation_cves),
            "results_json_rows": len(results),
            "full_evaluations_with_arms": len(full_results),
            "timeout_stubs": len(timeout_cves),
            "missing_rows_no_result_object": len(missing_cves),
        },
        "tokens": {
            "seed": seed_usage,
            "pipeline_full_cves": {
                "triage_tokens": pipeline_triage,
                "refinement_tokens": pipeline_refine,
                "subtotal_tokens": pipeline_triage + pipeline_refine,
            },
            "grand_total_tokens_seed_plus_pipeline_metrics": seed_total + pipeline_triage + pipeline_refine,
            "methodology": "Pipeline totals sum metrics.llm_tokens_triage and metrics.llm_tokens_refinement across all arms whose keys start with 'semgrep'.",
            "per_cve_tokens_sorted_desc": per_cve_tokens,
        },
        "ground_truth_metrics_vulnerable_commit": {
            "arm": "semgrep_3",
            "n_cves": len(full_results),
            "tp": totals_3[0],
            "fp": totals_3[1],
            "fn": totals_3[2],
            "reference_semgrep_0": {"tp": totals_0[0], "fp": totals_0[1], "fn": totals_0[2]},
        },
        "patched_commit_semgrep_3_patched": _patched_stats(full_results),
        "rules_hash_audit": rules_hash_audit,
        "rerun_outcome": _rerun_outcome(rerun_results, prior_results),
        "skipped_cves": {
            "timeout": {"count": len(timeout_cves), "cve_ids": timeout_cves},
            "missing_rows": {"count": len(missing_cves), "cve_ids": missing_cves},
        },
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / f"{label}_rollup.json"
    md_path = out_dir / f"{label}_rollup.md"
    write_json(json_path, rollup)
    md_path.write_text(_render_markdown(rollup, json_path.name))
    return json_path, md_path


def _render_markdown(rollup: dict[str, Any], json_name: str) -> str:
    cfg = rollup["run_config_summary"]
    rerun = rollup["rerun_config_summary"]
    cov = rollup["coverage"]
    tokens = rollup["tokens"]
    metrics = rollup["ground_truth_metrics_vulnerable_commit"]
    ref = metrics["reference_semgrep_0"]
    rerun_outcome = rollup.get("rerun_outcome") or {}

    lines = [
        f"# Semgrep sweep rollup - {rollup['label']}\n",
        f"\nMachine-readable data: `{json_name}`.\n",
        "\n## Run Configuration\n",
    ]
    for key in ("llm_model", "seed_model", "llm_url", "max_k", "per_cve_timeout_s", "clone_timeout_s", "run_patched", "validation_count"):
        lines.append(f"- **{key}:** {cfg.get(key)}\n")
    if rerun:
        lines.append("\n## Rerun Configuration\n")
        lines.append(f"- **per_cve_timeout_s:** {rerun.get('per_cve_timeout_s')}\n")
        lines.append(f"- **clone_timeout_s:** {rerun.get('clone_timeout_s')}\n")
        lines.append(f"- **target_count:** {len(rerun.get('only_cves') or [])}\n")
        lines.append(f"- **seed_cache_fingerprint:** {rerun.get('seed_cache_fingerprint')}\n")
        lines.append(f"- **seed_cache_hit:** {rerun.get('seed_cache_hit')}\n")

    lines.extend([
        "\n## Coverage\n",
        f"- Validation planned: **{cov['validation_cves_planned']}**\n",
        f"- Results rows: **{cov['results_json_rows']}**\n",
        f"- Full evaluations: **{cov['full_evaluations_with_arms']}**\n",
        f"- Timeout stubs: **{cov['timeout_stubs']}**\n",
        f"- Missing rows: **{cov['missing_rows_no_result_object']}**\n",
    ])
    if rerun_outcome:
        lines.extend([
            "\n## Rerun Outcome\n",
            f"- Rerun rows: **{rerun_outcome['rerun_row_count']}**\n",
            f"- Full after rerun: **{rerun_outcome['full_after_rerun_count']}**\n",
            f"- Still timed out: **{rerun_outcome['still_timeout_count']}**\n",
            f"- Error rows: **{rerun_outcome['error_count']}**\n",
        ])

    lines.extend([
        "\n## Token Rollup\n",
        "\n| Item | Tokens |\n|------|-------:|\n",
        f"| Seed | {int((tokens.get('seed') or {}).get('total_tokens') or 0):,} |\n",
        f"| Pipeline triage | {tokens['pipeline_full_cves']['triage_tokens']:,} |\n",
        f"| Pipeline refinement | {tokens['pipeline_full_cves']['refinement_tokens']:,} |\n",
        f"| **Grand total** | **{tokens['grand_total_tokens_seed_plus_pipeline_metrics']:,}** |\n",
        "\n## TP / FP / FN (vulnerable commit, `semgrep_3`)\n",
        "\n| TP | FP | FN |\n|---:|---:|---:|\n",
        f"| {metrics['tp']} | {metrics['fp']} | {metrics['fn']} |\n",
        "\n## Reference: `semgrep_0`\n",
        "\n| TP | FP | FN |\n|---:|---:|---:|\n",
        f"| {ref['tp']} | {ref['fp']} | {ref['fn']} |\n",
        "\n## Rules-Hash Audit\n",
    ])
    for key, value in rollup["rules_hash_audit"].items():
        lines.append(f"- **{key}:** {value}\n")
    return "".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--run-config", type=Path, required=True)
    parser.add_argument("--seed-usage", type=Path, default=None)
    parser.add_argument("--rerun-results", type=Path, default=None)
    parser.add_argument("--prior-results", type=Path, default=None)
    parser.add_argument("--rerun-run-config", type=Path, default=None)
    parser.add_argument("--seed-meta", type=Path, default=None)
    parser.add_argument("--out-dir", type=Path, default=Path("docs/reports"))
    parser.add_argument("--label", required=True)
    args = parser.parse_args(argv)

    json_path, md_path = build_rollup(
        results_path=args.results,
        run_config_path=args.run_config,
        seed_usage_path=args.seed_usage,
        rerun_results_path=args.rerun_results,
        prior_results_path=args.prior_results,
        rerun_run_config_path=args.rerun_run_config,
        seed_meta_path=args.seed_meta,
        out_dir=args.out_dir,
        label=args.label,
    )
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
