#!/usr/bin/env python3
"""Semgrep-only sweep (``arms=['semgrep']``) with built-in rules-hash audit.

Design goals that motivated splitting the sweep:

* Semgrep per-CVE wall-clock is dominated by LLM round-trips and small
  scanner invocations — the 900 s budget that chokes Joern is plenty
  for Semgrep.  Running Semgrep in isolation lets Joern have a much
  larger budget without inflating overall wall time.
* The 20260421_123649 sweep showed Semgrep's findings_hash was
  k-invariant in 17/18 CVEs despite the LLM emitting ``refine``
  actions 74% of the time.  To pin down whether ``apply_refinement``
  is the culprit we need per-iteration ``rules_hash_{pre,post}``
  plus YAML byte sizes.  The pipeline now records all of this; this
  script runs the audit automatically at the end of the sweep so the
  CSV + no-op rate land next to ``results.json``.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path

from auditzoo.agents.cwe78_study.pipeline import PipelineConfig
from splitEvaluations.audit_rules_hash import audit_results_json, _print_summary
from splitEvaluations.common import (
    _save_json,
    add_common_sweep_args,
    configure_logging,
    filter_dataset,
    run_main_comparison,
)

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Semgrep-only CWE-78 sweep")
    add_common_sweep_args(ap)
    ap.add_argument(
        "--per-cve-timeout", type=float, default=900.0,
        help="Wall-clock seconds budget per CVE; 0 disables.",
    )
    ap.add_argument(
        "--no-patched", action="store_true", default=False,
        help="Skip the patched-commit re-scan.  Semgrep is fast enough "
             "that the default is to keep patched, but this flag exists "
             "for parity with the Joern sweep for smoke runs.",
    )
    return ap.parse_args()


async def main() -> None:
    args = parse_args()
    configure_logging()

    dataset = json.loads(args.dataset.read_text())
    logger.info("Loaded %d CVEs from %s", len(dataset), args.dataset)
    dataset = filter_dataset(dataset, args.only_cves)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = args.output / "semgrep" / timestamp
    output_dir.mkdir(parents=True, exist_ok=True)

    pipeline_cfg = PipelineConfig(
        max_iterations=args.max_k,
        seed=args.seed,
        arms=["semgrep"],
        llm_base_url=args.llm_url,
        llm_model=args.llm_model,
        llm_log_io_path=str(args.log_llm_io) if args.log_llm_io else None,
    )

    _save_json(
        {**vars(args), "sweep": "semgrep"},
        output_dir / "run_config.json",
    )

    logger.info(
        "Semgrep sweep: %d CVEs, k=0..%d, per_cve_timeout=%.0fs, "
        "run_patched=%s, skip=%d",
        len(dataset), args.max_k, args.per_cve_timeout,
        not args.no_patched, len(args.skip_cves),
    )
    await run_main_comparison(
        dataset, pipeline_cfg, args.clone_dir, output_dir,
        line_tolerance=args.line_tolerance,
        skip_empty_gt=args.skip_empty_gt,
        per_cve_timeout=args.per_cve_timeout,
        skip_cves=args.skip_cves,
        run_patched=not args.no_patched,
    )

    logger.info("Semgrep sweep finished; running rules-hash audit…")
    summary = audit_results_json(output_dir / "results.json")
    _save_json(summary, output_dir / "rules_hash_audit.json")
    _print_summary(summary)

    logger.info("Results saved to %s", output_dir)


if __name__ == "__main__":
    asyncio.run(main())
