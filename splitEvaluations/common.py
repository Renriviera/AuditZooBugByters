"""Shared helpers for the split Semgrep / Joern evaluation sweeps.

This module is intentionally *thin*: it re-exports the canonical
implementations from :mod:`scripts.run_evaluation` so both split scripts
and the legacy combined harness stay locked to a single source of
truth for labelling, evidence serialisation, repo cloning, resource
sampling, and timeout handling.

If you find yourself adding a second copy of :func:`label_findings` or
:func:`clone_and_checkout` here, stop: add it to
``scripts/run_evaluation.py`` and re-export it instead.
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from scripts.run_evaluation import (  # noqa: F401 — re-exports
    DEFAULT_CLONE_DIR,
    DEFAULT_DATASET,
    DEFAULT_OUTPUT,
    LINE_TOLERANCE,
    _cleanup_stray_joern,
    _run_with_timeout,
    _save_json,
    clone_and_checkout,
    count_loc,
    get_resource_snapshot,
    label_findings,
    run_main_comparison,
    serialize_triage_verdicts,
)

logger = logging.getLogger(__name__)


def add_common_sweep_args(p: argparse.ArgumentParser) -> None:
    """Populate the argparse parser with flags shared by both sweeps."""
    p.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    p.add_argument("--clone-dir", type=Path, default=DEFAULT_CLONE_DIR)
    p.add_argument("--max-k", type=int, default=3)
    p.add_argument("--seed", type=int, default=235711)
    p.add_argument("--llm-url", default="http://localhost:8000/v1")
    p.add_argument("--llm-model", default="Qwen/Qwen2.5-Coder-7B-Instruct")
    p.add_argument("--line-tolerance", type=int, default=LINE_TOLERANCE)
    p.add_argument("--skip-empty-gt", action="store_true", default=True)
    p.add_argument(
        "--skip-cves", nargs="+", default=[],
        help="CVE IDs to skip entirely (e.g. pathologically large repos).",
    )
    p.add_argument(
        "--only-cves", nargs="+", default=[],
        help="If non-empty, restrict evaluation to these CVE IDs only.",
    )
    p.add_argument(
        "--log-llm-io", type=Path, default=None,
        help="Append every LLM chat round-trip as JSONL to this path.",
    )


def filter_dataset(dataset: list[dict], only: list[str]) -> list[dict]:
    """Return only CVEs whose ``cve_id`` is in *only* (if non-empty)."""
    if not only:
        return dataset
    keep = set(only)
    out = [c for c in dataset if c.get("cve_id") in keep]
    logger.info(
        "Restricted dataset to %d/%d CVEs via --only-cves: %s",
        len(out), len(dataset), sorted(keep),
    )
    return out


def configure_logging() -> None:
    """Set up the logging profile shared by both sweep entry points."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    for noisy in ("autogen_core", "autogen_core.events", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
