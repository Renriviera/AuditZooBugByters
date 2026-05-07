#!/usr/bin/env python3
"""Joern-only sweep (``arms=['joern']``), v1 no-patched by default.

Design goals that motivated splitting the sweep:

* Joern's dominant per-CVE cost is CPG construction.  In the
  20260421_123649 combined sweep CPG construction on both the
  vulnerable and patched commits inside a single 900 s budget caused
  38/105 CVEs to time out.  By default this script:

  - uses an 1800 s per-CVE budget (vs the legacy 900 s); and
  - runs ``--no-patched`` (v1): only the vulnerable commit is built.

  The "alerts on patched commit = FP" signal is sacrificed for enough
  wall-clock headroom to finish each CPG.  The Semgrep sweep still
  exercises that signal in parallel.
* Running Joern in isolation also means a per-CVE failure can't kill a
  cheap Semgrep iteration — each arm lives or dies on its own.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
from datetime import datetime

from auditzoo.agents.cwe78_study.llm_client import LLMClient, LLMConfig
from auditzoo.agents.cwe78_study.model_seed import (
    collect_training_examples,
    generate_joern_seed,
)
from auditzoo.agents.cwe78_study.pipeline import PipelineConfig
from splitEvaluations.common import (
    _save_json,
    add_common_sweep_args,
    build_split_metadata,
    configure_logging,
    eligible_dataset,
    filter_dataset,
    run_main_comparison,
    select_dataset_subset,
    split_train_validate,
)

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Joern-only CWE-78 sweep")
    add_common_sweep_args(ap)
    ap.add_argument("--joern-port", type=int, default=12345)
    ap.add_argument(
        "--per-cve-timeout", type=float, default=1800.0,
        help="Wall-clock seconds budget per CVE.  Default 1800 s "
             "(vs 900 s for the legacy combined sweep) because Joern "
             "CPG construction on Python projects is O(10 min) for "
             "many of our CVEs.  0 disables the budget.",
    )
    ap.add_argument(
        "--run-patched", action="store_true", default=False,
        help="Re-scan the patched commit to obtain an 'alerts on "
             "patched = FP' signal.  OFF by default (v1) so Joern "
             "doesn't have to build two CPGs per CVE.",
    )
    return ap.parse_args()


async def main() -> None:
    args = parse_args()
    configure_logging()

    dataset = json.loads(args.dataset.read_text())
    logger.info("Loaded %d CVEs from %s", len(dataset), args.dataset)
    dataset = filter_dataset(dataset, args.only_cves)
    eligible = eligible_dataset(
        dataset, skip_cves=args.skip_cves, skip_empty_gt=args.skip_empty_gt
    )
    selected = select_dataset_subset(eligible, args.dataset_size, args.seed)
    training_dataset, validation_dataset = split_train_validate(
        selected, args.train_fraction, args.seed
    )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = args.output / "joern" / timestamp
    output_dir.mkdir(parents=True, exist_ok=True)

    split_metadata = build_split_metadata(
        selected_dataset=selected,
        training_dataset=training_dataset,
        validation_dataset=validation_dataset,
        dataset_size=args.dataset_size,
        train_fraction=args.train_fraction,
        seed=args.seed,
    )
    _save_json(split_metadata, output_dir / "training_split.json")

    logger.info(
        "Generating Joern seed catalog from %d training CVEs using %s",
        len(training_dataset),
        args.seed_model,
    )
    training_examples = collect_training_examples(
        training_dataset=training_dataset,
        clone_dir=args.clone_dir,
        dataset_path=args.dataset,
    )
    seed_llm = LLMClient(
        LLMConfig(
            base_url=args.llm_url,
            model=args.seed_model,
            api_key="not-needed",
            seed=args.seed,
            log_io_path=str(args.log_llm_io) if args.log_llm_io else None,
        )
    )
    joern_catalog, seed_prompt = await generate_joern_seed(
        llm=seed_llm,
        training_examples=training_examples,
    )
    _save_json(joern_catalog.to_dict(), output_dir / "model_seed_joern_catalog.json")
    _save_json(seed_prompt, output_dir / "model_seed_prompt.json")

    pipeline_cfg = PipelineConfig(
        max_iterations=args.max_k,
        seed=args.seed,
        arms=["joern"],
        llm_base_url=args.llm_url,
        llm_model=args.llm_model,
        joern_port=args.joern_port,
        llm_log_io_path=str(args.log_llm_io) if args.log_llm_io else None,
        joern_sources=joern_catalog.sources,
        joern_sinks=joern_catalog.sinks,
        joern_sanitizers=joern_catalog.sanitizers,
    )

    _save_json(
        {**vars(args), "sweep": "joern", **split_metadata},
        output_dir / "run_config.json",
    )

    logger.info(
        "Joern sweep: %d selected CVEs (%d train / %d validate), "
        "k=0..%d, per_cve_timeout=%.0fs, run_patched=%s, skip=%d",
        len(selected), len(training_dataset), len(validation_dataset),
        args.max_k, args.per_cve_timeout,
        args.run_patched, len(args.skip_cves),
    )
    await run_main_comparison(
        validation_dataset, pipeline_cfg, args.clone_dir, output_dir,
        line_tolerance=args.line_tolerance,
        skip_empty_gt=False,
        per_cve_timeout=args.per_cve_timeout,
        skip_cves=[],
        run_patched=args.run_patched,
    )

    logger.info("Results saved to %s", output_dir)


if __name__ == "__main__":
    asyncio.run(main())
