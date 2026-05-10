"""Reusable seed-rule cache for split Semgrep sweeps."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from auditzoo.agents.cwe78_study.llm_client import LLMClient
from auditzoo.agents.cwe78_study.model_seed import generate_semgrep_seed


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text())


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str))


def seed_fingerprint(
    *,
    seed: int,
    seed_model: str,
    dataset_size: str | int | None,
    train_fraction: float,
    training_cves: list[str],
) -> str:
    """Fingerprint the inputs that determine the one-time Semgrep seed."""
    payload = {
        "seed": seed,
        "seed_model": seed_model,
        "dataset_size": dataset_size if dataset_size is not None else "full",
        "train_fraction": train_fraction,
        "training_cves": sorted(str(cve) for cve in training_cves),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return _sha256_text(encoded)[:16]


def seed_cache_path(cache_dir: Path, fingerprint: str) -> Path:
    """Return the cached Semgrep seed YAML path for *fingerprint*."""
    return cache_dir / f"{fingerprint}.yaml"


def seed_cache_meta_path(cache_dir: Path, fingerprint: str) -> Path:
    """Return the cached Semgrep seed metadata path for *fingerprint*."""
    return cache_dir / f"{fingerprint}.meta.json"


def fingerprint_from_run_config(run_config: dict[str, Any]) -> str:
    """Compute the seed fingerprint represented by a previous run config."""
    return seed_fingerprint(
        seed=int(run_config["seed"]),
        seed_model=str(run_config["seed_model"]),
        dataset_size=run_config.get("dataset_size", "full"),
        train_fraction=float(run_config["train_fraction"]),
        training_cves=[str(c) for c in run_config.get("training_cves", [])],
    )


def bootstrap_semgrep_seed_from_run(prior_dir: Path, cache_dir: Path) -> dict[str, Any]:
    """Copy a previous run's seed YAML into the shared cache if needed."""
    run_config = _read_json(prior_dir / "run_config.json")
    fingerprint = fingerprint_from_run_config(run_config)
    yaml_src = prior_dir / "model_seed_semgrep.yaml"
    prompt_src = prior_dir / "model_seed_prompt.json"
    usage_src = prior_dir / "seed_llm_usage.json"
    if not yaml_src.is_file():
        raise FileNotFoundError(f"missing seed YAML: {yaml_src}")

    yaml_dst = seed_cache_path(cache_dir, fingerprint)
    meta_dst = seed_cache_meta_path(cache_dir, fingerprint)
    cache_dir.mkdir(parents=True, exist_ok=True)
    if not yaml_dst.exists():
        shutil.copyfile(yaml_src, yaml_dst)

    yaml_text = yaml_dst.read_text()
    prompt_text = prompt_src.read_text() if prompt_src.is_file() else ""
    usage = _read_json(usage_src) if usage_src.is_file() else {}
    meta = {
        "fingerprint": fingerprint,
        "source": "bootstrap_from_run",
        "source_run_dir": str(prior_dir),
        "seed": run_config.get("seed"),
        "seed_model": run_config.get("seed_model"),
        "dataset_size": run_config.get("dataset_size", "full"),
        "train_fraction": run_config.get("train_fraction"),
        "training_cves": run_config.get("training_cves", []),
        "yaml_sha256": _sha256_text(yaml_text),
        "prompt_sha256": _sha256_text(prompt_text) if prompt_text else "",
        "seed_llm_usage": usage,
        "bootstrapped_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    _write_json(meta_dst, meta)
    return meta


async def load_or_build_semgrep_seed(
    *,
    cache_dir: Path,
    output_dir: Path,
    seed: int,
    seed_model: str,
    dataset_size: str | int | None,
    train_fraction: float,
    training_cves: list[str],
    llm: LLMClient | None,
    training_examples: list[dict[str, Any]],
    force_seed: bool = False,
    fingerprint: str | None = None,
    require_cache: bool = False,
) -> tuple[str, dict[str, Any]]:
    """Load a cached Semgrep seed YAML or generate/cache it when allowed."""
    fp = fingerprint or seed_fingerprint(
        seed=seed,
        seed_model=seed_model,
        dataset_size=dataset_size,
        train_fraction=train_fraction,
        training_cves=training_cves,
    )
    yaml_path = seed_cache_path(cache_dir, fp)
    meta_path = seed_cache_meta_path(cache_dir, fp)

    if yaml_path.is_file() and not force_seed:
        semgrep_rules_yaml = yaml_path.read_text()
        meta = _read_json(meta_path) if meta_path.is_file() else {}
        run_meta = {
            **meta,
            "fingerprint": fp,
            "cache_hit": True,
            "cache_yaml_path": str(yaml_path),
        }
        _copy_seed_to_output(output_dir, semgrep_rules_yaml, run_meta, cache_hit=True)
        return semgrep_rules_yaml, run_meta

    if require_cache:
        raise FileNotFoundError(
            f"seed cache miss for fingerprint {fp} at {yaml_path}; "
            "bootstrap the cache or rerun with --force-seed"
        )
    if llm is None:
        raise ValueError("llm is required when generating a Semgrep seed")

    semgrep_rules_yaml, seed_prompt = await generate_semgrep_seed(
        llm=llm,
        training_examples=training_examples,
    )
    cache_dir.mkdir(parents=True, exist_ok=True)
    yaml_path.write_text(semgrep_rules_yaml)
    usage = llm.usage.to_dict()
    prompt_text = json.dumps(seed_prompt, sort_keys=True, default=str)
    meta = {
        "fingerprint": fp,
        "source": "generated",
        "seed": seed,
        "seed_model": seed_model,
        "dataset_size": dataset_size if dataset_size is not None else "full",
        "train_fraction": train_fraction,
        "training_cves": training_cves,
        "yaml_sha256": _sha256_text(semgrep_rules_yaml),
        "prompt_sha256": _sha256_text(prompt_text),
        "seed_llm_usage": usage,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    _write_json(meta_path, meta)
    _copy_seed_to_output(
        output_dir,
        semgrep_rules_yaml,
        {**meta, "cache_hit": False, "cache_yaml_path": str(yaml_path)},
        cache_hit=False,
        seed_prompt=seed_prompt,
        seed_usage=usage,
    )
    return semgrep_rules_yaml, meta


def _copy_seed_to_output(
    output_dir: Path,
    semgrep_rules_yaml: str,
    meta: dict[str, Any],
    *,
    cache_hit: bool,
    seed_prompt: dict[str, Any] | None = None,
    seed_usage: dict[str, Any] | None = None,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "model_seed_semgrep.yaml").write_text(semgrep_rules_yaml)
    _write_json(output_dir / "model_seed_cache_meta.json", meta)
    if seed_prompt is not None:
        _write_json(output_dir / "model_seed_prompt.json", seed_prompt)
    else:
        _write_json(
            output_dir / "model_seed_prompt.json",
            {
                "cache_hit": cache_hit,
                "seed_cache_meta": meta,
                "note": "Seed prompt was not recomputed for this run.",
            },
        )
    if seed_usage is not None:
        _write_json(output_dir / "seed_llm_usage.json", seed_usage)
    else:
        _write_json(
            output_dir / "seed_llm_usage.json",
            {
                "cache_hit": cache_hit,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
                "call_count": 0,
                "original_seed_llm_usage": meta.get("seed_llm_usage", {}),
            },
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    boot = sub.add_parser("bootstrap-from-run")
    boot.add_argument("--prior-dir", type=Path, required=True)
    boot.add_argument("--cache-dir", type=Path, required=True)
    boot.add_argument("--json", action="store_true", help="Print metadata as JSON")

    args = parser.parse_args(argv)
    if args.command == "bootstrap-from-run":
        meta = bootstrap_semgrep_seed_from_run(args.prior_dir, args.cache_dir)
        if args.json:
            print(json.dumps(meta, indent=2, default=str))
        else:
            print(meta["fingerprint"])
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
