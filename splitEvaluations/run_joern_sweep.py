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
from pathlib import Path

from auditzoo.agents.cwe78_study.llm_client import LLMClient, LLMConfig
from auditzoo.agents.cwe78_study.model_seed import (
    JoernSeedCatalog,
    collect_training_examples,
    generate_joern_seed,
    parse_joern_seed_catalog,
)
from auditzoo.agents.cwe78_study.pipeline import PipelineConfig
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
    ap = argparse.ArgumentParser(description="Joern-only CWE-78 sweep")
    add_common_sweep_args(ap)
    ap.add_argument("--joern-port", type=int, default=12345)
    ap.add_argument(
        "--per-cve-timeout",
        type=float,
        default=1800.0,
        help="Wall-clock seconds budget per CVE.  Default 1800 s "
        "(vs 900 s for the legacy combined sweep) because Joern "
        "CPG construction on Python projects is O(10 min) for "
        "many of our CVEs.  0 disables the budget.",
    )
    ap.add_argument(
        "--run-patched",
        action="store_true",
        default=False,
        help="Re-scan the patched commit to obtain an 'alerts on "
        "patched = FP' signal.  OFF by default (v1) so Joern "
        "doesn't have to build two CPGs per CVE.",
    )
    ap.add_argument(
        "--joern-seed-catalog",
        type=Path,
        default=None,
        help="Pre-generated catalog JSON produced by "
        "splitEvaluations.seed_joern_catalog.  When provided, the "
        "expensive per-sweep training-clones + LLM seed call is "
        "skipped entirely; the catalog is loaded verbatim and the "
        "training split is used only for audit metadata.",
    )
    ap.add_argument(
        "--output-subdir",
        type=str,
        default=None,
        help="If provided, write the sweep into "
        "``<output>/joern/<output-subdir>`` instead of a fresh "
        "``<output>/joern/<timestamp>`` directory.  Used by "
        "``run_joern_validation_full.sh`` to resume a stalled run "
        "into the same directory: the harness streams completed "
        "CVE rows into ``results.json`` after every CVE so a fresh "
        "invocation with the same subdir + ``--only-cves "
        "<remaining>`` picks up exactly where the previous one died.",
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
    if args.joern_seed_catalog is not None:
        # The seed catalog is loaded verbatim, so the training partition
        # is unused.  Evaluate every selected CVE rather than carving out
        # ~train_fraction of them as a phantom "training" split that
        # never gets touched.
        training_dataset, validation_dataset = [], list(selected)
    else:
        training_dataset, validation_dataset = split_train_validate(
            selected, args.train_fraction, args.seed
        )

    subdir_name = args.output_subdir or datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = args.output / "joern" / subdir_name
    output_dir.mkdir(parents=True, exist_ok=True)
    resume_existing = (
        args.output_subdir is not None and (output_dir / "results.json").exists()
    )
    if resume_existing:
        logger.info(
            "Resuming into existing sweep dir %s (results.json present); "
            "previously-completed CVEs will be preserved.",
            output_dir,
        )

    # Default the LLM I/O trace to ``<output_dir>/llm_io.jsonl`` when the
    # caller did not pass ``--log-llm-io``.  Each chat completion appends
    # one JSONL line including the provider's ``usage`` block, which is
    # the only durable way to recover token totals from the seed call
    # (those bytes are not currently persisted in ``results.json``).
    if args.log_llm_io is None:
        args.log_llm_io = output_dir / "llm_io.jsonl"
        logger.info("Defaulting --log-llm-io to %s", args.log_llm_io)

    split_metadata = build_split_metadata(
        selected_dataset=selected,
        training_dataset=training_dataset,
        validation_dataset=validation_dataset,
        dataset_size=args.dataset_size,
        train_fraction=args.train_fraction,
        seed=args.seed,
    )
    _save_json(split_metadata, output_dir / "training_split.json")

    if args.joern_seed_catalog is not None:
        logger.info(
            "Loading pre-generated Joern seed catalog from %s "
            "(skipping per-sweep training clones + LLM seed call)",
            args.joern_seed_catalog,
        )
        catalog_payload = json.loads(args.joern_seed_catalog.read_text())
        # Strip metadata so parse_joern_seed_catalog only sees the three
        # canonical lists; the metadata block is preserved verbatim in
        # the breadcrumb file we write below.
        canonical = {k: catalog_payload.get(k, []) for k in ("sources", "sinks", "sanitizers")}
        joern_catalog = parse_joern_seed_catalog(canonical)
        seed_prompt = {
            "loaded_from": str(args.joern_seed_catalog),
            "metadata": catalog_payload.get("metadata", {}),
        }
    else:
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
                api_key=llm_api_key,
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
        llm_api_key=llm_api_key,
        joern_port=args.joern_port,
        llm_log_io_path=str(args.log_llm_io) if args.log_llm_io else None,
        joern_sources=joern_catalog.sources,
        joern_sinks=joern_catalog.sinks,
        joern_sanitizers=joern_catalog.sanitizers,
        cpg_cache_dir=args.cpg_cache_dir,
    )
    if args.cpg_cache_dir is not None:
        logger.info("CPG cache directory: %s", args.cpg_cache_dir)

    _save_json(
        {**redacted_sweep_args(args), "sweep": "joern", **split_metadata},
        output_dir / "run_config.json",
    )

    logger.info(
        "Joern sweep: %d selected CVEs (%d train / %d validate), "
        "k=0..%d, per_cve_timeout=%.0fs, run_patched=%s, skip=%d",
        len(selected),
        len(training_dataset),
        len(validation_dataset),
        args.max_k,
        args.per_cve_timeout,
        args.run_patched,
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
        run_patched=args.run_patched,
        resume_existing=resume_existing,
    )

    logger.info("Results saved to %s", output_dir)


if __name__ == "__main__":
    asyncio.run(main())
