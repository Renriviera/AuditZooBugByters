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

from auditzoo.agents.cwe78_study.llm_client import LLMClient, LLMConfig
from auditzoo.agents.cwe78_study.model_seed import (
    collect_training_examples,
    generate_semgrep_seed,
)
from auditzoo.agents.cwe78_study.pipeline import PipelineConfig
from splitEvaluations.audit_rules_hash import _print_summary, audit_results_json
from splitEvaluations.common import (
    _save_json,
    add_common_sweep_args,
    build_split_metadata,
    configure_logging,
    eligible_dataset,
    filter_dataset,
    redacted_sweep_args,
    resolve_llm_api_key,
    run_main_comparison,
    select_dataset_subset,
    split_train_validate,
)

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Semgrep-only CWE-78 sweep")
    add_common_sweep_args(ap)
    ap.add_argument(
        "--per-cve-timeout",
        type=float,
        default=900.0,
        help="Wall-clock seconds budget per CVE; 0 disables.",
    )
    ap.add_argument(
        "--no-patched",
        action="store_true",
        default=False,
        help="Skip the patched-commit re-scan.  Semgrep is fast enough "
        "that the default is to keep patched, but this flag exists "
        "for parity with the Joern sweep for smoke runs.",
    )
    return ap.parse_args()


async def main() -> None:
    args = parse_args()
    configure_logging()
    llm_api_key = resolve_llm_api_key(args.llm_api_key)

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
    output_dir = args.output / "semgrep" / timestamp
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
        "Generating Semgrep seed from %d training CVEs using %s",
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
            api_key=llm_api_key,
            seed=args.seed,
            log_io_path=str(args.log_llm_io) if args.log_llm_io else None,
        )
    )
    semgrep_rules_yaml, seed_prompt = await generate_semgrep_seed(
        llm=seed_llm,
        training_examples=training_examples,
    )
    (output_dir / "model_seed_semgrep.yaml").write_text(semgrep_rules_yaml)
    _save_json(seed_prompt, output_dir / "model_seed_prompt.json")

    pipeline_cfg = PipelineConfig(
        max_iterations=args.max_k,
        seed=args.seed,
        arms=["semgrep"],
        llm_base_url=args.llm_url,
        llm_model=args.llm_model,
        llm_api_key=llm_api_key,
        llm_log_io_path=str(args.log_llm_io) if args.log_llm_io else None,
        semgrep_rules_yaml=semgrep_rules_yaml,
    )

    _save_json(
        {**redacted_sweep_args(args), "sweep": "semgrep", **split_metadata},
        output_dir / "run_config.json",
    )

    logger.info(
        "Semgrep sweep: %d selected CVEs (%d train / %d validate), "
        "k=0..%d, per_cve_timeout=%.0fs, run_patched=%s, skip=%d",
        len(selected),
        len(training_dataset),
        len(validation_dataset),
        args.max_k,
        args.per_cve_timeout,
        not args.no_patched,
        len(args.skip_cves),
    )
    await run_main_comparison(
        validation_dataset,
        pipeline_cfg,
        args.clone_dir,
        output_dir,
        line_tolerance=args.line_tolerance,
        skip_empty_gt=False,
        per_cve_timeout=args.per_cve_timeout,
        skip_cves=[],
        run_patched=not args.no_patched,
    )

    logger.info("Semgrep sweep finished; running rules-hash audit…")
    summary = audit_results_json(output_dir / "results.json")
    _save_json(summary, output_dir / "rules_hash_audit.json")
    _print_summary(summary)

    logger.info("Results saved to %s", output_dir)


if __name__ == "__main__":
    asyncio.run(main())
