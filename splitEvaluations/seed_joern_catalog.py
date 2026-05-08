#!/usr/bin/env python3
"""Generate a Joern source/sink/sanitizer catalog from ALL CVEs (one shot).

The two-arm sweep currently regenerates this catalog on every invocation
of :mod:`splitEvaluations.run_joern_sweep`.  That spends ~1-2 hours on
training-snippet clones plus one LLM call each time, even though the
output only changes when (a) the dataset changes or (b) the seed model
changes.

This script materialises the catalog *once* against the entire 105-CVE
training pool and writes it to a stable JSON path.  Subsequent sweeps
load it via ``--joern-seed-catalog`` and skip the LLM step entirely::

    python -m splitEvaluations.seed_joern_catalog \\
        --dataset benchmark/python/cwe78_cves/metadata.json \\
        --output  results/joern_seed/full_catalog.json

The output schema mirrors :class:`JoernSeedCatalog.to_dict` plus a
``metadata`` block recording the seed model, training set size, LLM
usage, and timestamp — so we can always reconstruct *which* dataset and
*which* model produced the catalog the sweep is using.
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
    generate_joern_seed,
)
from splitEvaluations.common import resolve_llm_api_key

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--dataset",
        type=Path,
        required=True,
        help="Path to the CVE metadata.json (typically benchmark/python/cwe78_cves/metadata.json).",
    )
    ap.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Where to write the catalog JSON.  The companion prompt + raw response "
        "is written next to it as <output>.prompt.json.",
    )
    ap.add_argument(
        "--clone-dir",
        type=Path,
        default=Path("/tmp/auditzoo_seed"),
        help="Scratch dir for training-snippet clones (rmtree'd between CVEs).",
    )
    ap.add_argument("--seed-model", default="gpt-5.4-mini")
    ap.add_argument("--llm-url", default="https://api.openai.com/v1")
    ap.add_argument("--llm-api-key", default=None)
    ap.add_argument("--seed", type=int, default=235711)
    ap.add_argument(
        "--log-llm-io",
        type=Path,
        default=None,
        help="Optional JSONL trace of every LLM round-trip (defaults to "
        "<output_dir>/llm_io.jsonl when unset).",
    )
    ap.add_argument(
        "--only-cves",
        nargs="+",
        default=[],
        help="If non-empty, restrict training to these CVE IDs.  Use only "
        "for debugging — the production seed should use the full dataset.",
    )
    ap.add_argument(
        "--limit",
        type=int,
        default=0,
        help="If >0, cap the number of training CVEs after filtering "
        "(useful for smoke tests).  0 means use everything.",
    )
    return ap.parse_args()


async def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    for noisy in ("autogen_core", "autogen_core.events", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.log_llm_io is None:
        args.log_llm_io = args.output.parent / "llm_io.jsonl"

    dataset = json.loads(args.dataset.read_text())
    logger.info("Loaded %d CVEs from %s", len(dataset), args.dataset)

    if args.only_cves:
        keep = set(args.only_cves)
        dataset = [c for c in dataset if c.get("cve_id") in keep]
        logger.info("Restricted to %d CVEs via --only-cves", len(dataset))

    if args.limit and args.limit > 0:
        dataset = dataset[: args.limit]
        logger.info("Capped to %d CVEs via --limit", len(dataset))

    logger.info(
        "Collecting training snippets for %d CVEs (this clones each "
        "vulnerable+patched commit and may take a while)…",
        len(dataset),
    )
    examples = collect_training_examples(
        training_dataset=dataset,
        clone_dir=args.clone_dir,
        dataset_path=args.dataset,
    )
    logger.info("Collected %d training examples", len(examples))

    api_key = resolve_llm_api_key(args.llm_api_key)
    llm = LLMClient(
        LLMConfig(
            base_url=args.llm_url,
            model=args.seed_model,
            api_key=api_key,
            seed=args.seed,
            log_io_path=str(args.log_llm_io),
        )
    )

    logger.info("Calling seed LLM (%s) at %s …", args.seed_model, args.llm_url)
    catalog, prompt_record = await generate_joern_seed(
        llm=llm,
        training_examples=examples,
    )
    logger.info(
        "Seed catalog: %d sources, %d sinks, %d sanitizers (%d total LLM tokens)",
        len(catalog.sources),
        len(catalog.sinks),
        len(catalog.sanitizers),
        llm.usage.total_tokens,
    )

    payload = {
        **catalog.to_dict(),
        "metadata": {
            "n_training_cves": len(examples),
            "training_cve_ids": [
                str(e.get("cve_id", "")) for e in examples if e.get("cve_id")
            ],
            "seed_model": args.seed_model,
            "seed_random_seed": args.seed,
            "dataset_path": str(args.dataset),
            "generated_at": datetime.now().isoformat(),
            "llm_usage": llm.usage.to_dict(),
        },
    }
    args.output.write_text(json.dumps(payload, indent=2))
    logger.info("Wrote catalog to %s", args.output)

    prompt_path = args.output.with_suffix(".prompt.json")
    prompt_path.write_text(json.dumps(prompt_record, indent=2))
    logger.info("Wrote prompt+response audit to %s", prompt_path)


if __name__ == "__main__":
    asyncio.run(main())
