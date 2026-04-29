#!/usr/bin/env python3
"""Run the 10-CVE Semgrep diagnostic loop with GPT 5.4 mini.

This is a dev-only diagnostic harness.  It is meant to explain candidate
generation and refinement failures before spending frontier credits on a
larger heldout sweep.
"""

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
from splitEvaluations.audit_rules_hash import _print_summary, audit_results_json
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
from splitEvaluations.readiness_config import GPT54_MINI_DIAGNOSTIC_CVES

# Provide the API key via the OPENAI_API_KEY environment variable or --api-key.
# Never hardcode a real key here; this fallback intentionally stays empty.
GPT54_MINI_API_KEY = ""
GPT54_MINI_MODEL = "gpt-5.4-mini"
GPT54_MINI_BASE_URL = "https://api.openai.com/v1"

DEFAULT_TIMEOUT_S = 300.0
DEFAULT_MAX_K = 3

logger = logging.getLogger(__name__)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a 10-CVE Semgrep diagnostic loop with GPT 5.4 mini."
    )
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--clone-dir",
        type=Path,
        default=DEFAULT_CLONE_DIR / "gpt54mini_semgrep",
    )
    parser.add_argument("--max-k", type=int, default=DEFAULT_MAX_K)
    parser.add_argument("--seed", type=int, default=235711)
    parser.add_argument("--line-tolerance", type=int, default=LINE_TOLERANCE)
    parser.add_argument("--skip-empty-gt", action="store_true", default=True)
    parser.add_argument("--per-cve-timeout", type=float, default=DEFAULT_TIMEOUT_S)
    parser.add_argument("--llm-url", default=GPT54_MINI_BASE_URL)
    parser.add_argument("--llm-model", default=GPT54_MINI_MODEL)
    parser.add_argument(
        "--api-key",
        default=None,
        help="OpenAI API key. Defaults to OPENAI_API_KEY, then GPT54_MINI_API_KEY.",
    )
    parser.add_argument(
        "--only-cves",
        nargs="+",
        default=list(GPT54_MINI_DIAGNOSTIC_CVES),
        help="Override the fixed 10-CVE diagnostic set.",
    )
    parser.add_argument(
        "--no-patched",
        action="store_true",
        default=False,
        help="Skip patched-commit re-scan. The diagnostic default keeps patched scans.",
    )
    return parser.parse_args(argv)


def resolve_api_key(args: argparse.Namespace) -> str:
    return args.api_key or os.environ.get("OPENAI_API_KEY", "") or GPT54_MINI_API_KEY


def _redacted_run_config(args: argparse.Namespace, *, api_key: str) -> dict[str, Any]:
    config = vars(args).copy()
    config["api_key"] = "<redacted>" if api_key else ""
    config["sweep"] = "gpt54mini_semgrep_diagnostic"
    config["diagnostic_cves"] = list(args.only_cves)
    return config


def _add_file_logging(log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setLevel(logging.INFO)
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    logging.getLogger().addHandler(handler)


def _iter_primary_arms(results: list[dict[str, Any]]):
    for cve in results:
        cve_id = cve.get("cve_id", "")
        arms = cve.get("arms")
        if not isinstance(arms, dict):
            continue
        for arm_key, arm in arms.items():
            if not arm_key.startswith("semgrep_") or arm_key.endswith("_patched"):
                continue
            try:
                k = int(arm_key.rsplit("_", 1)[-1])
            except ValueError:
                continue
            yield cve_id, k, arm


def build_diagnostic_summary(
    results: list[dict[str, Any]],
    rules_audit: dict[str, Any],
) -> dict[str, Any]:
    by_k: dict[int, dict[str, Any]] = {}
    zero_candidate_cves: set[str] = set()
    candidate_no_tp_cves: set[str] = set()
    cve_candidate_totals: dict[str, int] = {}
    cve_tp_totals: dict[str, int] = {}
    apply_statuses: Counter[str] = Counter()
    refine_actions_total = 0
    actionable_refinements = 0
    file_line_pattern_not: list[dict[str, Any]] = []
    total_llm_usage = Counter()

    for cve_id, k, arm in _iter_primary_arms(results):
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
                "rules_changed_rows": 0,
                "findings_hashes": {},
            },
        )
        for field in ("tp", "fp", "fn", "n_candidates"):
            bucket[field] += int(arm.get(field, 0) or 0)

        usage = metrics.get("llm_usage") or {}
        usage_map = {
            "prompt_tokens": "llm_prompt_tokens",
            "completion_tokens": "llm_completion_tokens",
            "total_tokens": "llm_total_tokens",
            "call_count": "llm_call_count",
        }
        for source, dest in usage_map.items():
            value = int(usage.get(source, 0) or 0)
            bucket[dest] += value
            total_llm_usage[dest] += value

        if metrics.get("rules_yaml_changed"):
            bucket["rules_changed_rows"] += 1
        bucket["findings_hashes"][cve_id] = metrics.get("findings_hash", "")

        cve_candidate_totals[cve_id] = cve_candidate_totals.get(cve_id, 0) + int(
            arm.get("n_candidates", 0) or 0
        )
        cve_tp_totals[cve_id] = cve_tp_totals.get(cve_id, 0) + int(
            arm.get("tp", 0) or 0
        )

        for action in arm.get("refinement_actions") or []:
            action_name = str(action.get("action", "") or "")
            if action_name == "refine":
                refine_actions_total += 1
            status = str(action.get("apply_status", "") or "missing_status")
            apply_statuses[status] += 1
            if status and not status.startswith("noop") and status != "keep":
                actionable_refinements += 1

            for pattern in action.get("add_pattern_not") or []:
                pattern_text = str(pattern)
                if "file:" in pattern_text or " line:" in pattern_text or ".py" in pattern_text:
                    file_line_pattern_not.append(
                        {
                            "cve_id": cve_id,
                            "k": k,
                            "target_rule_id": action.get("target_rule_id", ""),
                            "pattern": pattern_text,
                            "apply_status": status,
                            "rationale": action.get("rationale", ""),
                        }
                    )

    for cve_id, n_candidates in cve_candidate_totals.items():
        if n_candidates == 0:
            zero_candidate_cves.add(cve_id)
        elif cve_tp_totals.get(cve_id, 0) == 0:
            candidate_no_tp_cves.add(cve_id)

    k0 = by_k.get(0, {})
    k_max = by_k.get(max(by_k), {}) if by_k else {}
    gates = {
        "refine_no_op_rate_lt_0_5": rules_audit.get("refine_no_op_rate", 0.0) < 0.5,
        "findings_changed_for_some_cve": rules_audit.get(
            "findings_invariance_frac", 1.0
        ) < 1.0,
        "zero_candidate_cves_listed": True,
        "structured_refinement_seen": any(
            "sources_added" in status or "sanitizers_added" in status
            for status in apply_statuses
        ),
        "tp_not_decreased_k0_to_kmax": int(k_max.get("tp", 0) or 0)
        >= int(k0.get("tp", 0) or 0),
    }

    return {
        "n_results": len(results),
        "diagnostic_cves": sorted(cve_candidate_totals),
        "by_k": {str(k): value for k, value in sorted(by_k.items())},
        "zero_candidate_cves": sorted(zero_candidate_cves),
        "candidate_no_tp_cves": sorted(candidate_no_tp_cves),
        "refinement": {
            "refine_actions_total": refine_actions_total,
            "refine_actions_no_op": rules_audit.get("refine_actions_no_op", 0),
            "refine_no_op_rate": rules_audit.get("refine_no_op_rate", 0.0),
            "actionable_refinements": actionable_refinements,
            "apply_statuses": dict(sorted(apply_statuses.items())),
            "file_line_pattern_not": file_line_pattern_not,
        },
        "findings_invariance": {
            "cves_in_audit": rules_audit.get("cves_in_audit", 0),
            "cves_with_k_invariant_findings": rules_audit.get(
                "cves_with_k_invariant_findings", 0
            ),
            "findings_invariance_frac": rules_audit.get(
                "findings_invariance_frac", 0.0
            ),
        },
        "llm_usage": dict(total_llm_usage),
        "readiness_gates": gates,
        "ready_for_full_frontier_sweep": all(gates.values()),
    }


def log_diagnostic_summary(summary: dict[str, Any]) -> None:
    logger.info("Diagnostic summary: %d result entries", summary["n_results"])
    for k, row in summary["by_k"].items():
        logger.info(
            "k=%s tp=%d fp=%d fn=%d candidates=%d llm_calls=%d tokens=%d",
            k,
            row["tp"],
            row["fp"],
            row["fn"],
            row["n_candidates"],
            row["llm_call_count"],
            row["llm_total_tokens"],
        )
    logger.info("Zero-candidate CVEs: %s", summary["zero_candidate_cves"])
    logger.info("Candidate-but-no-TP CVEs: %s", summary["candidate_no_tp_cves"])
    logger.info(
        "Refinement apply statuses: %s",
        summary["refinement"]["apply_statuses"],
    )
    for item in summary["refinement"]["file_line_pattern_not"]:
        logger.warning(
            "File/line pattern-not emitted: cve=%s k=%s target=%s status=%s pattern=%r",
            item["cve_id"],
            item["k"],
            item["target_rule_id"],
            item["apply_status"],
            item["pattern"],
        )
    failed = [
        gate for gate, passed in summary["readiness_gates"].items() if not passed
    ]
    if failed:
        logger.warning("Readiness gates failed: %s", failed)
    else:
        logger.info("All readiness gates passed")


async def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    api_key = resolve_api_key(args)
    if not api_key:
        raise SystemExit(
            "No API key provided. Set OPENAI_API_KEY, pass --api-key, or fill "
            "GPT54_MINI_API_KEY at the top of this script."
        )

    configure_logging()
    dataset = json.loads(args.dataset.read_text())
    logger.info("Loaded %d CVEs from %s", len(dataset), args.dataset)
    dataset = filter_dataset(dataset, args.only_cves)
    if len(dataset) != len(set(args.only_cves)):
        logger.warning(
            "Diagnostic CVE count mismatch: requested=%d loaded=%d",
            len(set(args.only_cves)),
            len(dataset),
        )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = args.output / "gpt54mini_semgrep" / timestamp
    output_dir.mkdir(parents=True, exist_ok=True)
    _add_file_logging(output_dir / "diagnostic.log")

    llm_io_path = output_dir / "llm_io.jsonl"
    pipeline_cfg = PipelineConfig(
        max_iterations=args.max_k,
        seed=args.seed,
        arms=["semgrep"],
        llm_base_url=args.llm_url,
        llm_model=args.llm_model,
        llm_api_key=api_key,
        llm_log_io_path=str(llm_io_path),
    )

    _save_json(_redacted_run_config(args, api_key=api_key), output_dir / "run_config.json")

    logger.info(
        "GPT mini Semgrep diagnostic: %d CVEs, k=0..%d, timeout=%.0fs, patched=%s",
        len(dataset),
        args.max_k,
        args.per_cve_timeout,
        not args.no_patched,
    )
    results = await run_main_comparison(
        dataset,
        pipeline_cfg,
        args.clone_dir,
        output_dir,
        line_tolerance=args.line_tolerance,
        skip_empty_gt=args.skip_empty_gt,
        per_cve_timeout=args.per_cve_timeout,
        run_patched=not args.no_patched,
    )

    logger.info("Semgrep diagnostic finished; running rules-hash audit")
    rules_audit = audit_results_json(output_dir / "results.json")
    _save_json(rules_audit, output_dir / "rules_hash_audit.json")
    _print_summary(rules_audit)

    diagnostic_summary = build_diagnostic_summary(results, rules_audit)
    _save_json(diagnostic_summary, output_dir / "diagnostic_summary.json")
    log_diagnostic_summary(diagnostic_summary)

    logger.info("Results saved to %s", output_dir)


if __name__ == "__main__":
    asyncio.run(main())
