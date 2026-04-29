#!/usr/bin/env python3
"""Run a 10-CVE Joern diagnostic loop with GPT 5.4 mini."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from auditzoo.agents.cwe78_study.pipeline import PipelineConfig
from splitEvaluations.common import (
    DEFAULT_CLONE_DIR,
    DEFAULT_DATASET,
    DEFAULT_OUTPUT,
    LINE_TOLERANCE,
    _save_json,
    configure_logging,
    filter_dataset,
    run_main_comparison,
)
from splitEvaluations.readiness_config import (
    GPT54_JOERN_DIAGNOSTIC_CVES,
    JOERN_DIAGNOSTIC_30_CVES,
    KNOWN_JOERN_TIMEOUT_CVES,
)

# Provide the API key via the OPENAI_API_KEY environment variable or --api-key.
# Never hardcode a real key here; this fallback intentionally stays empty.
GPT54_API_KEY = ""
GPT54_MODEL = "gpt-5.4-mini"
GPT54_BASE_URL = "https://api.openai.com/v1"

DEFAULT_TIMEOUT_S = 900.0
DEFAULT_MAX_K = 0
JOERN_MODELING_MODES = (
    "catalog_only",
    "catalog_parameter",
    "catalog_parameter_attribute",
    "full_wrapper",
)

logger = logging.getLogger(__name__)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a 10-CVE Joern diagnostic loop with GPT 5.4 mini."
    )
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--clone-dir",
        type=Path,
        default=DEFAULT_CLONE_DIR / "gpt54_joern",
    )
    parser.add_argument("--max-k", type=int, default=DEFAULT_MAX_K)
    parser.add_argument("--seed", type=int, default=235711)
    parser.add_argument("--line-tolerance", type=int, default=LINE_TOLERANCE)
    parser.add_argument("--skip-empty-gt", action="store_true", default=True)
    parser.add_argument("--per-cve-timeout", type=float, default=DEFAULT_TIMEOUT_S)
    parser.add_argument("--llm-url", default=GPT54_BASE_URL)
    parser.add_argument("--llm-model", default=GPT54_MODEL)
    parser.add_argument("--joern-port", type=int, default=12345)
    parser.add_argument(
        "--api-key",
        default=None,
        help="OpenAI API key. Defaults to OPENAI_API_KEY, then GPT54_API_KEY.",
    )
    parser.add_argument(
        "--cve-set",
        choices=("10", "30", "all_minus_timeouts"),
        default="10",
        help=(
            "Selects the Joern CVE set: 10-CVE (default), 30-CVE, or all "
            "dataset CVEs minus known Joern timeouts."
        ),
    )
    parser.add_argument(
        "--only-cves",
        nargs="+",
        default=None,
        help="Override the diagnostic CVE set entirely with an explicit list.",
    )
    parser.add_argument(
        "--run-patched",
        action="store_true",
        default=False,
        help="Re-scan patched commits. Off by default for Joern cost control.",
    )
    parser.add_argument(
        "--disable-preload-skip",
        action="store_true",
        default=False,
        help="Do not set AUDITZOO_SKIP_PRELOAD_CALLS/FACTS for this run.",
    )
    parser.add_argument(
        "--joern-modeling-mode",
        choices=JOERN_MODELING_MODES,
        default="full_wrapper",
        help="Joern source/sink modeling mode for ablation runs.",
    )
    parser.add_argument(
        "--joern-max-triage-candidates",
        type=int,
        default=30,
        help=(
            "Legacy single-cap budget for Joern findings sent to LLM triage "
            "(<=0 disables cap). Used only when both two-budget caps are unset."
        ),
    )
    parser.add_argument(
        "--joern-high-risk-candidate-cap",
        type=int,
        default=20,
        help="High-risk Joern findings cap for the two-budget reducer (<0 to disable).",
    )
    parser.add_argument(
        "--joern-low-risk-candidate-cap",
        type=int,
        default=10,
        help="Lower-risk Joern findings cap for the two-budget reducer (<0 to disable).",
    )
    parser.add_argument(
        "--joern-disable-candidate-reducer",
        action="store_true",
        default=False,
        help="Send all Joern findings to LLM triage without pre-triage ranking/capping.",
    )
    parser.add_argument(
        "--joern-retry-uncertain-with-flow-path",
        action="store_true",
        default=False,
        help="Retry a small number of high-ranked uncertain Joern findings with full flow-path evidence.",
    )
    parser.add_argument(
        "--joern-flow-path-retry-limit",
        type=int,
        default=10,
        help="Maximum uncertain Joern findings retried with full flow-path evidence.",
    )
    parser.add_argument(
        "--joern-disable-argv-exception",
        action="store_true",
        default=False,
        help="Disable the git/argv-list exception in the Joern triage prompt.",
    )
    parser.add_argument(
        "--joern-skip-triage",
        action="store_true",
        default=False,
        help="Run Joern scan and coverage probe without LLM triage.",
    )
    parser.add_argument(
        "--joern-emit-coverage-probe",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Attach cheap Joern GT file/sink/source coverage facts to metrics.",
    )
    return parser.parse_args(argv)


def resolve_api_key(args: argparse.Namespace) -> str:
    return args.api_key or os.environ.get("OPENAI_API_KEY", "") or GPT54_API_KEY


def configure_joern_env(*, disable_preload_skip: bool = False) -> dict[str, str]:
    if not disable_preload_skip:
        os.environ["AUDITZOO_SKIP_PRELOAD_CALLS"] = "1"
        os.environ["AUDITZOO_SKIP_PRELOAD_FACTS"] = "1"
    return {
        "AUDITZOO_SKIP_PRELOAD_CALLS": os.environ.get(
            "AUDITZOO_SKIP_PRELOAD_CALLS", ""
        ),
        "AUDITZOO_SKIP_PRELOAD_FACTS": os.environ.get(
            "AUDITZOO_SKIP_PRELOAD_FACTS", ""
        ),
    }


def _redacted_run_config(
    args: argparse.Namespace,
    *,
    api_key: str,
    joern_env: dict[str, str],
) -> dict[str, Any]:
    config = vars(args).copy()
    config["api_key"] = "<redacted>" if api_key else ""
    config["sweep"] = "gpt54_joern_diagnostic"
    if args.only_cves:
        config["diagnostic_cves"] = list(args.only_cves)
    elif getattr(args, "cve_set", "10") == "all_minus_timeouts":
        config["diagnostic_cves"] = "all_minus_timeouts"
    elif getattr(args, "cve_set", "10") == "30":
        config["diagnostic_cves"] = list(JOERN_DIAGNOSTIC_30_CVES)
    else:
        config["diagnostic_cves"] = list(GPT54_JOERN_DIAGNOSTIC_CVES)
    config["joern_env"] = joern_env
    config["uses_process_isolation_watchdog"] = True
    config["expected_timeout_scope"] = "process_group"
    return config


def _add_file_logging(log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setLevel(logging.INFO)
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    logging.getLogger().addHandler(handler)


def _all_minus_known_timeout_cves(dataset: list[dict[str, Any]]) -> list[str]:
    skipped = set(KNOWN_JOERN_TIMEOUT_CVES)
    return sorted(
        str(row.get("cve_id", "") or "")
        for row in dataset
        if row.get("cve_id") and str(row.get("cve_id")) not in skipped
    )


def _iter_joern_arms(results: list[dict[str, Any]]):
    for cve in results:
        cve_id = cve.get("cve_id", "")
        arms = cve.get("arms")
        if not isinstance(arms, dict):
            continue
        for arm_key, arm in arms.items():
            if not arm_key.startswith("joern_") or arm_key.endswith("_patched"):
                continue
            try:
                k = int(arm_key.rsplit("_", 1)[-1])
            except ValueError:
                continue
            yield cve_id, k, arm


def build_joern_diagnostic_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    skipped = Counter(
        str(row.get("skipped", "")) for row in results if row.get("skipped")
    )
    timeout_cves = [
        row.get("cve_id", "") for row in results if row.get("skipped") == "timeout"
    ]
    child_kills = [
        {
            "cve_id": row.get("cve_id", ""),
            "elapsed_s": (row.get("timeout_meta") or {}).get("elapsed_s"),
            "kill_signal": (row.get("timeout_meta") or {}).get("kill_signal"),
            "timeout_scope": (row.get("timeout_meta") or {}).get("timeout_scope"),
            "rss_mb_before": (
                (row.get("timeout_meta") or {})
                .get("process_tree_before", {})
                .get("rss_mb")
            ),
        }
        for row in results
        if row.get("skipped") == "timeout"
    ]

    by_k: dict[int, dict[str, Any]] = {}
    cves_with_candidates: set[str] = set()
    cves_with_tp: set[str] = set()
    catalog_growth_cves: set[str] = set()
    arm_errors: list[dict[str, Any]] = []
    timeout_scopes = Counter()
    total_llm_usage = Counter()

    for cve_id, k, arm in _iter_joern_arms(results):
        metrics = arm.get("metrics") or {}
        bucket = by_k.setdefault(
            k,
            {
                "tp": 0,
                "fp": 0,
                "fn": 0,
                "n_candidates": 0,
                "llm_prompt_tokens": 0,
                "llm_completion_tokens": 0,
                "llm_total_tokens": 0,
                "llm_call_count": 0,
                "cpg_build_s": 0.0,
                "scan_s": 0.0,
                "triage_s": 0.0,
                "refinement_s": 0.0,
                "call_graph_s": 0.0,
                "joern_raw_findings": 0,
                "joern_triaged_findings": 0,
                "joern_candidates_dropped_before_triage": 0,
                "joern_flow_path_retry_count": 0,
                "joern_flow_path_retry_tokens": 0,
                "joern_flow_path_retry_tp_delta": 0,
                "tp_via_report_candidate": 0,
                "tp_via_report_candidate_caller_external": 0,
                "report_candidate_location_tp": 0,
                "report_candidate_promotion_blocked_by_origin_gate": 0,
                "tp_via_same_package": 0,
                "tp_via_same_package_with_origin": 0,
                "tp_via_same_package_promoted": 0,
                "tp_strict_by_llm_tp": 0,
                "tp_strict_by_llm_uncertain": 0,
                "relaxed_tp": 0,
                "dedup_dropped": 0,
                "pre_dedup_tp": 0,
                "pre_dedup_fp": 0,
                "pre_dedup_fn": 0,
                "pre_dedup_relaxed_tp": 0,
                "pre_dedup_tp_via_same_package_promoted": 0,
                "pre_dedup_tp_via_report_candidate": 0,
                "pre_dedup_tp_strict_by_llm_uncertain": 0,
                "joern_high_risk_count": 0,
                "joern_high_risk_kept": 0,
                "joern_high_risk_dropped_when_overflow": 0,
                "joern_low_risk_count": 0,
                "joern_low_risk_kept": 0,
                "joern_low_risk_dropped_when_overflow": 0,
                "cves_without_gt_file_in_cpg": [],
                "cves_without_gt_sink": [],
                "cves_without_external_source_in_gt_file": [],
            },
        )
        for field in ("tp", "fp", "fn", "n_candidates"):
            bucket[field] += int(arm.get(field, 0) or 0)
        for field in (
            "tp_via_report_candidate",
            "tp_via_report_candidate_caller_external",
            "report_candidate_location_tp",
            "report_candidate_promotion_blocked_by_origin_gate",
            "tp_via_same_package",
            "tp_via_same_package_with_origin",
            "tp_via_same_package_promoted",
            "tp_strict_by_llm_tp",
            "tp_strict_by_llm_uncertain",
            "dedup_dropped",
        ):
            bucket[field] += int(arm.get(field, 0) or 0)
        bucket["relaxed_tp"] = bucket["tp"] + bucket["tp_via_same_package_promoted"]

        pre_dedup = arm.get("pre_dedup_metrics") or {}
        if isinstance(pre_dedup, dict):
            for src, dst in (
                ("tp", "pre_dedup_tp"),
                ("fp", "pre_dedup_fp"),
                ("fn", "pre_dedup_fn"),
                (
                    "tp_via_same_package_promoted",
                    "pre_dedup_tp_via_same_package_promoted",
                ),
                ("tp_via_report_candidate", "pre_dedup_tp_via_report_candidate"),
                ("tp_strict_by_llm_uncertain", "pre_dedup_tp_strict_by_llm_uncertain"),
            ):
                bucket[dst] += int(pre_dedup.get(src, 0) or 0)
            bucket["pre_dedup_relaxed_tp"] = (
                bucket["pre_dedup_tp"]
                + bucket["pre_dedup_tp_via_same_package_promoted"]
            )
        for metric, dest in (
            ("cpg_build_s", "cpg_build_s"),
            ("scan_s", "scan_s"),
            ("llm_triage_s", "triage_s"),
            ("llm_refinement_s", "refinement_s"),
            ("call_graph_s", "call_graph_s"),
            ("joern_raw_findings", "joern_raw_findings"),
            ("joern_triaged_findings", "joern_triaged_findings"),
            (
                "joern_candidates_dropped_before_triage",
                "joern_candidates_dropped_before_triage",
            ),
            ("joern_flow_path_retry_count", "joern_flow_path_retry_count"),
            ("joern_flow_path_retry_tokens", "joern_flow_path_retry_tokens"),
            ("joern_flow_path_retry_tp_delta", "joern_flow_path_retry_tp_delta"),
            ("joern_high_risk_count", "joern_high_risk_count"),
            ("joern_high_risk_kept", "joern_high_risk_kept"),
            (
                "joern_high_risk_dropped_when_overflow",
                "joern_high_risk_dropped_when_overflow",
            ),
            ("joern_low_risk_count", "joern_low_risk_count"),
            ("joern_low_risk_kept", "joern_low_risk_kept"),
            (
                "joern_low_risk_dropped_when_overflow",
                "joern_low_risk_dropped_when_overflow",
            ),
        ):
            if dest.endswith("_s"):
                bucket[dest] += float(metrics.get(metric, 0.0) or 0.0)
            else:
                bucket[dest] += int(metrics.get(metric, 0) or 0)

        coverage_probe = metrics.get("joern_coverage_probe") or {}
        if isinstance(coverage_probe, dict) and coverage_probe:
            if not bool(coverage_probe.get("gt_file_seen", False)):
                bucket["cves_without_gt_file_in_cpg"].append(cve_id)
            if int(coverage_probe.get("gt_sink_count", 0) or 0) <= 0:
                bucket["cves_without_gt_sink"].append(cve_id)
            if int(coverage_probe.get("external_source_count", 0) or 0) <= 0:
                bucket["cves_without_external_source_in_gt_file"].append(cve_id)

        usage = metrics.get("llm_usage") or {}
        for source, dest in (
            ("prompt_tokens", "llm_prompt_tokens"),
            ("completion_tokens", "llm_completion_tokens"),
            ("total_tokens", "llm_total_tokens"),
            ("call_count", "llm_call_count"),
        ):
            value = int(usage.get(source, 0) or 0)
            bucket[dest] += value
            total_llm_usage[dest] += value

        run_meta = arm.get("run_meta") or {}
        if run_meta.get("timeout_scope"):
            timeout_scopes[str(run_meta.get("timeout_scope"))] += 1
        if int(arm.get("n_candidates", 0) or 0) > 0:
            cves_with_candidates.add(cve_id)
        if int(arm.get("tp", 0) or 0) > 0:
            cves_with_tp.add(cve_id)
        if metrics.get("joern_catalog_grew"):
            catalog_growth_cves.add(cve_id)
        if arm.get("arm_error") or arm.get("arm_error_type"):
            arm_errors.append(
                {
                    "cve_id": cve_id,
                    "k": k,
                    "error": arm.get("arm_error", ""),
                    "error_type": arm.get("arm_error_type", ""),
                }
            )

    completed_cves = sorted({cve_id for cve_id, _, _ in _iter_joern_arms(results)})
    zero_candidate_cves = sorted(set(completed_cves) - cves_with_candidates)
    gates = {
        "process_isolation_used": bool(timeout_scopes)
        and set(timeout_scopes) <= {"process_group"},
        "preload_skips_expected": True,
        "timeouts_recorded_with_kill_metadata": all(
            item.get("timeout_scope") == "process_group"
            and item.get("kill_signal") == "SIGKILL"
            for item in child_kills
        ),
        "at_least_one_cve_completed": bool(completed_cves),
        "at_least_one_candidate": bool(cves_with_candidates),
    }

    return {
        "n_results": len(results),
        "completed_cves": completed_cves,
        "skipped": dict(sorted(skipped.items())),
        "timeout_cves": timeout_cves,
        "child_kills": child_kills,
        "by_k": {str(k): value for k, value in sorted(by_k.items())},
        "zero_candidate_cves": zero_candidate_cves,
        "candidate_cves": sorted(cves_with_candidates),
        "tp_cves": sorted(cves_with_tp),
        "catalog_growth_cves": sorted(catalog_growth_cves),
        "arm_errors": arm_errors,
        "timeout_scopes": dict(sorted(timeout_scopes.items())),
        "llm_usage": dict(total_llm_usage),
        "readiness_gates": gates,
        "ready_for_larger_joern_frontier_sweep": all(gates.values()),
    }


def log_joern_summary(summary: dict[str, Any]) -> None:
    logger.info(
        "Joern diagnostic summary: completed=%d skipped=%s timeouts=%s",
        len(summary["completed_cves"]),
        summary["skipped"],
        summary["timeout_cves"],
    )
    for k, row in summary["by_k"].items():
        logger.info(
            "k=%s tp=%d fp=%d fn=%d candidates=%d cpg=%.2fs scan=%.2fs "
            "triage=%.2fs refine=%.2fs cg=%.2fs llm_calls=%d tokens=%d",
            k,
            row["tp"],
            row["fp"],
            row["fn"],
            row["n_candidates"],
            row["cpg_build_s"],
            row["scan_s"],
            row["triage_s"],
            row["refinement_s"],
            row["call_graph_s"],
            row["llm_call_count"],
            row["llm_total_tokens"],
        )
    for kill in summary["child_kills"]:
        logger.warning("Process-isolation kill recorded: %s", kill)
    failed = [gate for gate, passed in summary["readiness_gates"].items() if not passed]
    if failed:
        logger.warning("Joern readiness gates failed: %s", failed)
    else:
        logger.info("All Joern readiness gates passed")


async def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    api_key = resolve_api_key(args)
    if not api_key:
        raise SystemExit(
            "No API key provided. Set OPENAI_API_KEY, pass --api-key, or fill "
            "GPT54_API_KEY at the top of this script."
        )

    configure_logging()
    joern_env = configure_joern_env(disable_preload_skip=args.disable_preload_skip)
    dataset = json.loads(args.dataset.read_text())
    logger.info("Loaded %d CVEs from %s", len(dataset), args.dataset)

    if args.only_cves:
        cve_list: list[str] = list(args.only_cves)
        cve_set_origin = "only_cves"
    elif args.cve_set == "all_minus_timeouts":
        cve_list = _all_minus_known_timeout_cves(dataset)
        cve_set_origin = "cve_set=all_minus_timeouts"
    elif args.cve_set == "30":
        cve_list = list(JOERN_DIAGNOSTIC_30_CVES)
        cve_set_origin = "cve_set=30"
    else:
        cve_list = list(GPT54_JOERN_DIAGNOSTIC_CVES)
        cve_set_origin = "cve_set=10"
    args.only_cves = cve_list
    logger.info("Diagnostic CVE selection: %s (%d CVEs)", cve_set_origin, len(cve_list))

    dataset = filter_dataset(dataset, cve_list)
    if len(dataset) != len(set(cve_list)):
        logger.warning(
            "Diagnostic CVE count mismatch: requested=%d loaded=%d",
            len(set(cve_list)),
            len(dataset),
        )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = args.output / "gpt54_joern" / timestamp
    output_dir.mkdir(parents=True, exist_ok=True)
    _add_file_logging(output_dir / "diagnostic.log")

    llm_io_path = output_dir / "llm_io.jsonl"
    coverage_targets = {
        str(row.get("cve_id", "")): {
            "vulnerable_file": row.get("vulnerable_file", ""),
            "vulnerable_lines": row.get("vulnerable_lines", []),
        }
        for row in dataset
        if row.get("cve_id")
    }
    pipeline_cfg = PipelineConfig(
        max_iterations=args.max_k,
        seed=args.seed,
        arms=["joern"],
        llm_base_url=args.llm_url,
        llm_model=args.llm_model,
        llm_api_key=api_key,
        joern_port=args.joern_port,
        llm_log_io_path=str(llm_io_path),
        joern_modeling_mode=args.joern_modeling_mode,
        joern_max_triage_candidates=(
            None
            if args.joern_max_triage_candidates <= 0
            else args.joern_max_triage_candidates
        ),
        joern_candidate_reducer_enabled=not args.joern_disable_candidate_reducer,
        joern_high_risk_candidate_cap=(
            None
            if args.joern_high_risk_candidate_cap < 0
            else args.joern_high_risk_candidate_cap
        ),
        joern_low_risk_candidate_cap=(
            None
            if args.joern_low_risk_candidate_cap < 0
            else args.joern_low_risk_candidate_cap
        ),
        joern_retry_uncertain_with_flow_path=args.joern_retry_uncertain_with_flow_path,
        joern_flow_path_retry_limit=args.joern_flow_path_retry_limit,
        joern_triage_argv_exception=not args.joern_disable_argv_exception,
        joern_skip_triage=args.joern_skip_triage,
        joern_emit_coverage_probe=args.joern_emit_coverage_probe,
        joern_coverage_probe_targets=coverage_targets,
    )

    _save_json(
        _redacted_run_config(args, api_key=api_key, joern_env=joern_env),
        output_dir / "run_config.json",
    )

    logger.info(
        "GPT 5.4 mini Joern diagnostic: %d CVEs, k=0..%d, timeout=%.0fs, "
        "patched=%s, preload_env=%s, watchdog=process_group, "
        "modeling_mode=%s, reducer=%s, max_triage=%s, hr_cap=%s, lr_cap=%s, "
        "argv_exception=%s, skip_triage=%s",
        len(dataset),
        args.max_k,
        args.per_cve_timeout,
        args.run_patched,
        joern_env,
        args.joern_modeling_mode,
        not args.joern_disable_candidate_reducer,
        args.joern_max_triage_candidates,
        args.joern_high_risk_candidate_cap,
        args.joern_low_risk_candidate_cap,
        not args.joern_disable_argv_exception,
        args.joern_skip_triage,
    )
    results = await run_main_comparison(
        dataset,
        pipeline_cfg,
        args.clone_dir,
        output_dir,
        line_tolerance=args.line_tolerance,
        skip_empty_gt=args.skip_empty_gt,
        per_cve_timeout=args.per_cve_timeout,
        run_patched=args.run_patched,
    )

    summary = build_joern_diagnostic_summary(results)
    _save_json(summary, output_dir / "diagnostic_summary.json")
    log_joern_summary(summary)

    logger.info("Results saved to %s", output_dir)


if __name__ == "__main__":
    asyncio.run(main())
