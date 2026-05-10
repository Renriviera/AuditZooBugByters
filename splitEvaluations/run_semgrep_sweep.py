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

from auditzoo.agents.cwe78_study.llm_client import LLMClient, LLMConfig
from auditzoo.agents.cwe78_study.model_seed import (
    collect_training_examples,
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
    llm_api_key,
    run_main_comparison,
    select_dataset_subset,
    split_train_validate,
)
from splitEvaluations.seed_cache import (
    fingerprint_from_run_config,
    load_or_build_semgrep_seed,
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
    ap.add_argument(
        "--seed-cache-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "seeds" / "semgrep",
        help="Directory containing reusable cached Semgrep seed YAML files.",
    )
    ap.add_argument(
        "--force-seed",
        action="store_true",
        default=False,
        help="Ignore any cached seed and call the seed LLM again.",
    )
    ap.add_argument(
        "--seed-cache-fingerprint",
        default="",
        help="Explicit seed cache fingerprint to reuse (used for targeted reruns).",
    )
    ap.add_argument(
        "--seed-source-run-config",
        type=Path,
        default=None,
        help="Previous run_config.json whose training split defines the seed cache fingerprint.",
    )
    ap.add_argument(
        "--no-triage",
        action="store_true",
        default=False,
        help="Disable the LLM triage agent.  Combined with --max-k 0 (and a "
        "cached seed YAML) this produces a Semgrep-only baseline with "
        "zero LLM calls anywhere in the sweep.  Each finding is recorded "
        "with verdict=UNCERTAIN so label_findings scores it as raw "
        "Semgrep would (TP on GT-line match, FP otherwise).",
    )
    return ap.parse_args()


async def main() -> None:
    args = parse_args()
    configure_logging()
    llm_api_key = resolve_llm_api_key(args.llm_api_key)

    dataset = json.loads(args.dataset.read_text())
    logger.info("Loaded %d CVEs from %s", len(dataset), args.dataset)
    targeted_rerun = bool(args.only_cves)
    seed_source_run_config = None
    if args.seed_source_run_config is not None:
        seed_source_run_config = json.loads(args.seed_source_run_config.read_text())

    if targeted_rerun:
        selected = filter_dataset(dataset, args.only_cves)
        training_dataset = []
        validation_dataset = eligible_dataset(
            selected, skip_cves=args.skip_cves, skip_empty_gt=args.skip_empty_gt
        )
    else:
        dataset = filter_dataset(dataset, args.only_cves)
        eligible = eligible_dataset(
            dataset, skip_cves=args.skip_cves, skip_empty_gt=args.skip_empty_gt
        )
        selected = select_dataset_subset(eligible, args.dataset_size, args.seed)
        training_dataset, validation_dataset = split_train_validate(
            selected, args.train_fraction, args.seed
        )

    seed_training_cves = [str(c.get("cve_id", "")) for c in training_dataset]
    seed_dataset_size = args.dataset_size
    seed_train_fraction = args.train_fraction
    seed_cache_fingerprint = args.seed_cache_fingerprint or None
    if seed_source_run_config is not None:
        seed_training_cves = [
            str(cve) for cve in seed_source_run_config.get("training_cves", [])
        ]
        seed_dataset_size = seed_source_run_config.get("dataset_size", args.dataset_size)
        seed_train_fraction = float(
            seed_source_run_config.get("train_fraction", args.train_fraction)
        )
        seed_cache_fingerprint = seed_cache_fingerprint or fingerprint_from_run_config(
            seed_source_run_config
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
        "Loading Semgrep seed (cache=%s, fingerprint=%s, force=%s, require_cache=%s)",
        args.seed_cache_dir,
        seed_cache_fingerprint or "<computed>",
        args.force_seed,
        targeted_rerun,
    )
    training_examples = []
    seed_llm = None
    if not targeted_rerun or args.force_seed:
        if args.no_triage and not args.force_seed:
            # The --no-triage baseline forbids any LLM call.  If the caller
            # is not in targeted-rerun mode (which guarantees a cache hit)
            # we cannot legally generate a fresh seed.  Fail loudly so the
            # baseline run is never silently contaminated by an LLM call.
            raise SystemExit(
                "--no-triage requires a cached Semgrep seed: pass "
                "--only-cves <validation set> together with "
                "--seed-cache-fingerprint <fp> (or --seed-source-run-config) "
                "so load_or_build_semgrep_seed runs in require_cache mode."
            )
        logger.info(
            "Collecting %d training CVEs for Semgrep seed using %s",
            len(training_dataset),
            args.seed_model,
        )
        training_examples = collect_training_examples(
            training_dataset=training_dataset,
            clone_dir=args.clone_dir,
            dataset_path=args.dataset,
            clone_timeout_s=args.clone_timeout_s,
        )
        seed_llm = LLMClient(
            LLMConfig(
                base_url=args.llm_url,
                model=args.seed_model,
                api_key=llm_api_key(),
                seed=args.seed,
                log_io_path=str(args.log_llm_io) if args.log_llm_io else None,
            )
        )
    semgrep_rules_yaml, seed_meta = await load_or_build_semgrep_seed(
        cache_dir=args.seed_cache_dir,
        output_dir=output_dir,
        seed=args.seed,
        seed_model=args.seed_model,
        dataset_size=seed_dataset_size,
        train_fraction=seed_train_fraction,
        training_cves=seed_training_cves,
        llm=seed_llm,
        training_examples=training_examples,
        force_seed=args.force_seed,
        fingerprint=seed_cache_fingerprint,
        require_cache=targeted_rerun and not args.force_seed,
    )
    logger.info(
        "Semgrep seed ready: fingerprint=%s cache_hit=%s",
        seed_meta.get("fingerprint"),
        seed_meta.get("cache_hit", False),
    )

    pipeline_cfg = PipelineConfig(
        max_iterations=args.max_k,
        seed=args.seed,
        arms=["semgrep"],
        llm_base_url=args.llm_url,
        llm_model=args.llm_model,
        llm_api_key=llm_api_key(),
        llm_log_io_path=str(args.log_llm_io) if args.log_llm_io else None,
        semgrep_rules_yaml=semgrep_rules_yaml,
        triage_disabled=args.no_triage,
    )

    _save_json(
        {
            **vars(args),
            "sweep": "semgrep",
            "targeted_rerun": targeted_rerun,
            "no_triage": args.no_triage,
            "seed_cache_fingerprint": seed_meta.get("fingerprint"),
            "seed_cache_hit": seed_meta.get("cache_hit", False),
            "seed_cache_yaml_path": seed_meta.get("cache_yaml_path"),
            "seed_source_training_cves": seed_training_cves,
            "seed_source_dataset_size": seed_dataset_size,
            "seed_source_train_fraction": seed_train_fraction,
            **split_metadata,
        },
        output_dir / "run_config.json",
    )

    logger.info(
        "Semgrep sweep: %d selected CVEs (%d train / %d validate), "
        "k=0..%d, per_cve_timeout=%.0fs, clone_timeout=%.0fs, run_patched=%s, skip=%d",
        len(selected),
        len(training_dataset),
        len(validation_dataset),
        args.max_k,
        args.per_cve_timeout,
        args.clone_timeout_s,
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
        clone_timeout_s=args.clone_timeout_s,
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
