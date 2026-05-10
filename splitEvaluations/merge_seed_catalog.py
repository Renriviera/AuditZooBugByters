#!/usr/bin/env python3
"""Merge the frozen LLM-seeded catalog with the local YAML seed_rules.

The "frozen" catalog (``results/joern_seed/full_catalog.json``) is the
deterministic output of one full sweep of
:mod:`splitEvaluations.seed_joern_catalog` over the training pool —
training set leakage rules out re-running it for every YAML edit.  But
the YAML seed_rules under
``auditzoo/agents/cwe78_study/seed_rules/`` capture documented
public framework / stdlib idioms (DRF, Pyramid, Falcon, …), and we
want those entries unioned into the frozen catalog without losing the
training-set provenance metadata.

This merger is purely local: it does **not** clone repos, call the LLM,
or read any validation-set CVE.  It just unions YAML over the frozen
base and records the additions under ``metadata.merged_with``.

Usage::

    python -m splitEvaluations.merge_seed_catalog \
        --frozen   results/joern_seed/full_catalog.json \
        --yaml-dir auditzoo/agents/cwe78_study/seed_rules \
        --output   results/joern_seed/full_catalog_merged.json
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import yaml

_DEFAULT_FROZEN = Path("results/joern_seed/full_catalog.json")
_DEFAULT_YAML_DIR = Path("auditzoo/agents/cwe78_study/seed_rules")
_DEFAULT_OUTPUT = Path("results/joern_seed/full_catalog_merged.json")


def _load_yaml_entries(yaml_path: Path, *, key_field: str) -> list[str]:
    """Return ``key_field`` values from a seed_rules YAML file.

    Sources use ``pattern`` and sinks/sanitizers use ``api`` — the
    distinction predates this script.
    """
    if not yaml_path.exists():
        return []
    data = yaml.safe_load(yaml_path.read_text())
    if not isinstance(data, dict):
        return []
    top_key = yaml_path.stem
    items = data.get(top_key)
    if not isinstance(items, list):
        return []
    out: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        value = item.get(key_field)
        if isinstance(value, str) and value.strip():
            out.append(value.strip())
    return out


def _union_preserve_order(base: list[str], extras: list[str]) -> tuple[list[str], list[str]]:
    """Return ``(merged, added)`` with stable ordering.

    Entries already in ``base`` are kept in their original position;
    every YAML entry that wasn't already present is appended in YAML
    order to the end and recorded in ``added``.
    """
    seen = {entry: idx for idx, entry in enumerate(base)}
    merged = list(base)
    added: list[str] = []
    for extra in extras:
        if extra in seen:
            continue
        merged.append(extra)
        seen[extra] = len(merged) - 1
        added.append(extra)
    return merged, added


def merge_catalog(
    frozen_path: Path = _DEFAULT_FROZEN,
    yaml_dir: Path = _DEFAULT_YAML_DIR,
) -> dict:
    """Build the merged catalog dict (does not write to disk)."""
    frozen = json.loads(frozen_path.read_text())
    if not isinstance(frozen, dict):
        raise ValueError(f"{frozen_path} must hold a JSON object")

    base_sources: list[str] = list(frozen.get("sources", []) or [])
    base_sinks: list[str] = list(frozen.get("sinks", []) or [])
    base_sanitizers: list[str] = list(frozen.get("sanitizers", []) or [])

    yaml_sources = _load_yaml_entries(yaml_dir / "sources.yaml", key_field="pattern")
    yaml_sinks = _load_yaml_entries(yaml_dir / "sinks.yaml", key_field="api")
    yaml_sanitizers = _load_yaml_entries(yaml_dir / "sanitizers.yaml", key_field="api")

    merged_sources, sources_added = _union_preserve_order(base_sources, yaml_sources)
    merged_sinks, sinks_added = _union_preserve_order(base_sinks, yaml_sinks)
    merged_sanitizers, sanitizers_added = _union_preserve_order(
        base_sanitizers, yaml_sanitizers
    )

    metadata = dict(frozen.get("metadata", {}) or {})
    metadata["merged_with"] = {
        "yaml_sources_added": sources_added,
        "yaml_sinks_added": sinks_added,
        "yaml_sanitizers_added": sanitizers_added,
        "yaml_root": str(yaml_dir),
        "merged_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }

    return {
        "sources": merged_sources,
        "sinks": merged_sinks,
        "sanitizers": merged_sanitizers,
        "metadata": metadata,
    }


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--frozen", type=Path, default=_DEFAULT_FROZEN)
    ap.add_argument("--yaml-dir", type=Path, default=_DEFAULT_YAML_DIR)
    ap.add_argument("--output", type=Path, default=_DEFAULT_OUTPUT)
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    payload = merge_catalog(frozen_path=args.frozen, yaml_dir=args.yaml_dir)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2))
    added = payload["metadata"]["merged_with"]
    print(f"Wrote {args.output}")
    print(
        "  sources={} sinks={} sanitizers={}".format(
            len(payload["sources"]), len(payload["sinks"]), len(payload["sanitizers"])
        )
    )
    print(
        "  added: sources={} sinks={} sanitizers={}".format(
            len(added["yaml_sources_added"]),
            len(added["yaml_sinks_added"]),
            len(added["yaml_sanitizers_added"]),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
