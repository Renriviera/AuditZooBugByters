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
import math
import os
import random
from pathlib import Path
from typing import Any

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

# Cloud evaluation sweeps (Semgrep / Joern): seed + pipeline use the same model by default.
DEFAULT_EVAL_LLM_MODEL = "gpt-5.4-mini"


def llm_api_key() -> str:
    """Resolve API key for OpenAI-compatible endpoints.

    Order: ``OPENAI_API_KEY_FILE``, ``OPENAI_API_KEY``, repo-local
    ``.openai_api_key``, then ``"not-needed"`` for local vLLM.
    """
    path = os.environ.get("OPENAI_API_KEY_FILE")
    if path:
        p = Path(path)
        if p.is_file():
            return p.read_text().splitlines()[0].strip()
    env_key = os.environ.get("OPENAI_API_KEY")
    if env_key:
        return env_key
    repo_key = DEFAULT_DATASET.parents[3] / ".openai_api_key"
    if repo_key.is_file():
        return repo_key.read_text().splitlines()[0].strip()
    return "not-needed"


def add_common_sweep_args(p: argparse.ArgumentParser) -> None:
    """Populate the argparse parser with flags shared by both sweeps."""
    p.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    p.add_argument("--clone-dir", type=Path, default=DEFAULT_CLONE_DIR)
    p.add_argument("--max-k", type=int, default=3)
    p.add_argument("--seed", type=int, default=235711)
    p.add_argument("--llm-url", default="http://localhost:8000/v1")
    p.add_argument("--llm-model", default=DEFAULT_EVAL_LLM_MODEL)
    p.add_argument(
        "--seed-model",
        default=DEFAULT_EVAL_LLM_MODEL,
        help="Model used for the one-time initial rule/catalog seeding call.",
    )
    p.add_argument(
        "--dataset-size",
        default="full",
        help="Number of eligible CVEs to use before the train/validation split "
        "(for example 10, 30, 100, or 'full').",
    )
    p.add_argument(
        "--train-fraction",
        type=float,
        default=0.25,
        help="Fraction of the selected dataset used to seed initial rules/catalogs.",
    )
    p.add_argument("--line-tolerance", type=int, default=LINE_TOLERANCE)
    p.add_argument(
        "--clone-timeout-s",
        type=float,
        default=300.0,
        help="Seconds budget for each git clone and fetch during checkout.",
    )
    p.add_argument("--skip-empty-gt", action="store_true", default=True)
    p.add_argument(
        "--skip-cves",
        nargs="+",
        default=[],
        help="CVE IDs to skip entirely (e.g. pathologically large repos).",
    )
    p.add_argument(
        "--only-cves",
        nargs="+",
        default=[],
        help="If non-empty, restrict evaluation to these CVE IDs only.",
    )
    p.add_argument(
        "--log-llm-io",
        type=Path,
        default=None,
        help="Append every LLM chat round-trip as JSONL to this path.",
    )
    p.add_argument(
        "--cpg-cache-dir",
        type=Path,
        default=None,
        help="Stable workspace directory for cached Joern CPGs, keyed by "
        "sha256(repo_url, commit, language).  When set, a re-run of the "
        "same CVE skips the expensive importCode step entirely.",
    )
    # ``run_joern_sweep`` reads ``args.llm_api_key`` directly and
    # ``redacted_sweep_args`` indexes ``out["llm_api_key"]``; both
    # paths require this attribute to exist on the Namespace.  We
    # default to None so the resolution chain still falls back to
    # AUDITZOO_LLM_API_KEY / OPENAI_API_KEY / .openai_api_key when no
    # CLI value is given (per ``resolve_llm_api_key`` precedence).
    p.add_argument(
        "--llm-api-key",
        default=None,
        help="API key for the OpenAI-compatible LLM endpoint.  Prefer "
        "setting AUDITZOO_LLM_API_KEY (or OPENAI_API_KEY) instead so "
        "the secret never lands in process listings or run_config.json.",
    )


def resolve_llm_api_key(cli_value: str | None = None) -> str:
    """Resolve the LLM API key without hardcoding or requiring one."""
    if cli_value:
        return cli_value
    return (
        os.getenv("AUDITZOO_LLM_API_KEY") or os.getenv("OPENAI_API_KEY") or "not-needed"
    )


def redacted_sweep_args(args: argparse.Namespace) -> dict[str, Any]:
    """Return ``vars(args)`` with LLM credentials removed for run_config.json."""
    out = dict(vars(args))
    api_key = resolve_llm_api_key(out.get("llm_api_key"))
    out["llm_api_key"] = "<redacted>" if api_key != "not-needed" else "not-needed"
    out["llm_api_key_provided"] = api_key != "not-needed"
    return out


def filter_dataset(dataset: list[dict], only: list[str]) -> list[dict]:
    """Return only CVEs whose ``cve_id`` is in *only* (if non-empty)."""
    if not only:
        return dataset
    keep = set(only)
    out = [c for c in dataset if c.get("cve_id") in keep]
    logger.info(
        "Restricted dataset to %d/%d CVEs via --only-cves: %s",
        len(out),
        len(dataset),
        sorted(keep),
    )
    return out


def eligible_dataset(
    dataset: list[dict[str, Any]],
    *,
    skip_cves: list[str] | None = None,
    skip_empty_gt: bool = True,
) -> list[dict[str, Any]]:
    """Apply eligibility filters before selecting the run subset."""
    skip = set(skip_cves or [])
    out: list[dict[str, Any]] = []
    for cve in dataset:
        cve_id = str(cve.get("cve_id", ""))
        if cve_id in skip:
            continue
        if skip_empty_gt and not cve.get("vulnerable_lines"):
            continue
        out.append(cve)
    return out


def parse_dataset_size(dataset_size: str | int | None, total: int) -> int:
    """Resolve ``--dataset-size`` to a bounded integer count."""
    if dataset_size is None:
        return total
    if isinstance(dataset_size, int):
        requested = dataset_size
    else:
        raw = str(dataset_size).strip().lower()
        if raw in {"", "full", "all"}:
            return total
        requested = int(raw)
    if requested <= 0:
        raise ValueError("dataset_size must be positive or 'full'")
    return min(requested, total)


def select_dataset_subset(
    dataset: list[dict[str, Any]], dataset_size: str | int | None, seed: int
) -> list[dict[str, Any]]:
    """Select a deterministic shuffled subset of eligible CVE records."""
    n = parse_dataset_size(dataset_size, len(dataset))
    rng = random.Random(seed)
    indexed = list(enumerate(dataset))
    rng.shuffle(indexed)
    chosen = sorted(indexed[:n], key=lambda item: item[0])
    return [item for _, item in chosen]


def split_train_validate(
    dataset: list[dict[str, Any]], train_fraction: float, seed: int
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Deterministically split *dataset* into train and validation partitions."""
    if not 0 < train_fraction < 1:
        raise ValueError("train_fraction must be between 0 and 1")
    if not dataset:
        return [], []
    train_n = min(len(dataset) - 1, max(1, math.ceil(len(dataset) * train_fraction)))
    rng = random.Random(seed)
    indexed = list(enumerate(dataset))
    rng.shuffle(indexed)
    train_indices = {idx for idx, _ in indexed[:train_n]}
    train = [item for idx, item in indexed[:train_n]]
    validate = [item for idx, item in enumerate(dataset) if idx not in train_indices]
    return train, validate


def build_split_metadata(
    *,
    selected_dataset: list[dict[str, Any]],
    training_dataset: list[dict[str, Any]],
    validation_dataset: list[dict[str, Any]],
    dataset_size: str | int | None,
    train_fraction: float,
    seed: int,
) -> dict[str, Any]:
    """Return audit metadata for a model-seeded train/validation split."""
    return {
        "dataset_size": dataset_size if dataset_size is not None else "full",
        "train_fraction": train_fraction,
        "seed": seed,
        "selected_count": len(selected_dataset),
        "training_count": len(training_dataset),
        "validation_count": len(validation_dataset),
        "selected_cves": [str(c.get("cve_id", "")) for c in selected_dataset],
        "training_cves": [str(c.get("cve_id", "")) for c in training_dataset],
        "validation_cves": [str(c.get("cve_id", "")) for c in validation_dataset],
    }


def configure_logging() -> None:
    """Set up the logging profile shared by both sweep entry points."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    for noisy in ("autogen_core", "autogen_core.events", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
