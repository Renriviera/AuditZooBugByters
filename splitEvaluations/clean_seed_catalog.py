#!/usr/bin/env python3
"""Apply a semantic-disjointness / blacklist filter to a Joern seed catalog.

Even the deterministic seed catalog produced by
:mod:`splitEvaluations.seed_joern_catalog` plus
:mod:`splitEvaluations.merge_seed_catalog` can carry sink-coloured
patterns in the *sources* list (e.g. ``shell``, ``subprocess``,
``Popen.communicate``).  Joern then reports degenerate self-flows where
a sink flows to itself, the structural-evidence renderer surfaces those
as ``Source: subprocess.Popen``, and the triage LLM correctly downgrades
the verdict to ``UNCERTAIN``.  The 20260510_051918 partial validation
sweep showed that single quality bug eats most of the strict TP budget.

This module is the standalone, deterministic, leakage-safe fix:

    1.  Load a merged catalog JSON (``sources``/``sinks``/``sanitizers``).
    2.  Drop sources matching a documented sink-token blacklist.
    3.  Drop sources that are also in ``sinks`` *or* whose dotted path is
        a strict prefix of any sink (``subprocess`` is a prefix of
        ``subprocess.Popen``).
    4.  Drop sanitizers that double as sinks (cheap belt-and-suspenders).
    5.  Refuse to write the output when the proposed drop ratio exceeds
        ``--max-source-drop-frac`` so a future hostile catalog cannot
        silently nuke the source list.
    6.  Record every dropped pattern under ``metadata.cleaned_with`` and
        echo a per-pattern reason on stdout, so the human reviewer can
        double-check before the sweep launches.

The script is purely local: no LLM call, no network IO, no validation
CVE access.  It is safe to run in CI or as a pre-commit hook.

Usage::

    python -m splitEvaluations.clean_seed_catalog \
        --input  results/joern_seed/full_catalog_merged.json \
        --output results/joern_seed/full_catalog_clean.json \
        --max-source-drop-frac 0.25
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

_DEFAULT_INPUT = Path("results/joern_seed/full_catalog_merged.json")
_DEFAULT_OUTPUT = Path("results/joern_seed/full_catalog_clean.json")
_DEFAULT_MAX_DROP_FRAC = 0.25

# Short tokens that are exclusively sink-coloured for command-injection.
# A source pattern *exactly* matching one of these (case-insensitive) is
# always a leak: even when an LLM justifies it as "Popen.stdout.read
# returns bytes that came from outside the process", the bytes there
# are the *output* of an already-executed command, not an attacker
# channel for unsanitised input.  Matching is exact (after .lower()) so
# legitimate dotted neighbours such as ``request.body`` are preserved.
_SINK_TOKEN_BLACKLIST: tuple[str, ...] = (
    "shell",
    "subprocess",
    "popen",
    "system",
    "exec",
    "eval",
    "popen.communicate",
    "popen.stdout.read",
    "popen.stderr.read",
)


def _strip_pattern(p: str) -> str:
    """Normalise a catalog entry for comparison: trim + drop leading dots."""
    return (p or "").strip().lstrip(".")


def _is_blacklisted_source(pattern: str) -> tuple[bool, str]:
    """Return ``(drop, reason)`` for a single source pattern.

    The check is *exact* (case-insensitive) on the normalised dotted
    path: a pattern matching the literal blacklist token is dropped.
    Patterns that merely *contain* a sink token (``request.shell_form``)
    are intentionally left alone — those would need a separate rule and
    we don't observe them in the current catalog.
    """
    normalized = _strip_pattern(pattern).lower()
    if not normalized:
        return False, ""
    for token in _SINK_TOKEN_BLACKLIST:
        if normalized == token:
            return True, f"blacklist-exact:{token}"
    return False, ""


def _build_sink_prefix_index(sinks: Iterable[str]) -> set[str]:
    """Return the set of dotted ancestors of every sink.

    For ``subprocess.Popen`` we record ``subprocess`` and
    ``subprocess.Popen``; for ``os.system`` we record ``os`` and
    ``os.system``.  A source is then a self-flow risk iff its
    normalised path is in this set.
    """
    out: set[str] = set()
    for sink in sinks:
        path = _strip_pattern(sink)
        if not path:
            continue
        parts = path.split(".")
        for i in range(1, len(parts) + 1):
            out.add(".".join(parts[:i]))
    return out


def _is_disjointness_violation(
    source: str,
    sink_set: set[str],
    sink_prefixes: set[str],
) -> tuple[bool, str]:
    """Return ``(drop, reason)`` if *source* collides with the sink list."""
    normalized = _strip_pattern(source)
    if not normalized:
        return False, ""
    if normalized in sink_set:
        return True, "disjointness:source-equals-sink"
    if normalized in sink_prefixes:
        return True, "disjointness:source-is-prefix-of-sink"
    return False, ""


def _filter_sources(
    sources: list[str], sinks: list[str]
) -> tuple[list[str], list[dict[str, str]]]:
    """Apply the blacklist + disjointness filter.

    Returns ``(kept, dropped)`` where ``dropped`` is a list of
    ``{"pattern": ..., "reason": ...}`` records preserving input order
    of the dropped items.  A source can be dropped for both reasons
    (e.g. ``subprocess``); only the first reason is recorded.
    """
    sink_set = {_strip_pattern(s) for s in sinks if s}
    sink_prefixes = _build_sink_prefix_index(sinks)
    kept: list[str] = []
    dropped: list[dict[str, str]] = []
    seen_kept: set[str] = set()
    for src in sources:
        if not isinstance(src, str) or not src.strip():
            continue
        bl_drop, bl_reason = _is_blacklisted_source(src)
        if bl_drop:
            dropped.append({"pattern": src, "reason": bl_reason})
            continue
        dj_drop, dj_reason = _is_disjointness_violation(src, sink_set, sink_prefixes)
        if dj_drop:
            dropped.append({"pattern": src, "reason": dj_reason})
            continue
        norm = _strip_pattern(src)
        if norm in seen_kept:
            continue
        seen_kept.add(norm)
        kept.append(src)
    return kept, dropped


def _filter_sanitizers(
    sanitizers: list[str], sinks: list[str]
) -> tuple[list[str], list[dict[str, str]]]:
    """Drop sanitizers that double as sinks; preserve everything else."""
    sink_set = {_strip_pattern(s) for s in sinks if s}
    kept: list[str] = []
    dropped: list[dict[str, str]] = []
    for entry in sanitizers:
        if not isinstance(entry, str) or not entry.strip():
            continue
        if _strip_pattern(entry) in sink_set:
            dropped.append({"pattern": entry, "reason": "sanitizer-equals-sink"})
            continue
        kept.append(entry)
    return kept, dropped


def _filter_sinks(sinks: list[str]) -> tuple[list[str], list[dict[str, str]]]:
    """Drop sinks that are short, sink-coloured tokens with no dotted path.

    The merged catalog inherits ``shell`` as a *sink* from one of the
    LLM seeds, but ``shell`` is not a callable API — it's the
    ``shell=True`` parameter on ``subprocess.run``/``Popen``, which the
    Joern arm already handles via the per-sink ``shell_param`` flag.
    Keeping it inflates the prefix index and forces the source filter
    to drop legitimate names like ``shell_safe.run``.
    """
    kept: list[str] = []
    dropped: list[dict[str, str]] = []
    for sink in sinks:
        if not isinstance(sink, str) or not sink.strip():
            continue
        normalized = _strip_pattern(sink).lower()
        if normalized in {"shell", "exec", "eval", "system"} and "." not in normalized:
            dropped.append({"pattern": sink, "reason": "non-api-token-as-sink"})
            continue
        kept.append(sink)
    return kept, dropped


def clean_catalog(payload: dict, *, max_source_drop_frac: float) -> dict:
    """Build the cleaned catalog dict.

    Raises ``ValueError`` when the proposed drop fraction exceeds
    ``max_source_drop_frac`` — the caller is then expected to either
    inspect the input or relax the bound explicitly.
    """
    if not isinstance(payload, dict):
        raise ValueError("input catalog must be a JSON object")

    src_raw: list[str] = list(payload.get("sources", []) or [])
    sink_raw: list[str] = list(payload.get("sinks", []) or [])
    san_raw: list[str] = list(payload.get("sanitizers", []) or [])

    sinks_kept, sinks_dropped = _filter_sinks(sink_raw)
    sources_kept, sources_dropped = _filter_sources(src_raw, sinks_kept)
    san_kept, san_dropped = _filter_sanitizers(san_raw, sinks_kept)

    if src_raw:
        drop_frac = len(sources_dropped) / len(src_raw)
    else:
        drop_frac = 0.0
    if drop_frac > max_source_drop_frac:
        raise ValueError(
            f"refusing to write: proposed source-drop fraction "
            f"{drop_frac:.3f} exceeds bound {max_source_drop_frac:.3f}; "
            f"would drop {len(sources_dropped)}/{len(src_raw)} sources"
        )

    metadata = dict(payload.get("metadata", {}) or {})
    metadata["cleaned_with"] = {
        "blacklist_used": list(_SINK_TOKEN_BLACKLIST),
        "max_source_drop_frac": max_source_drop_frac,
        "dropped_sources": sources_dropped,
        "dropped_sinks": sinks_dropped,
        "dropped_sanitizers": san_dropped,
        "kept_counts": {
            "sources": len(sources_kept),
            "sinks": len(sinks_kept),
            "sanitizers": len(san_kept),
        },
        "input_counts": {
            "sources": len(src_raw),
            "sinks": len(sink_raw),
            "sanitizers": len(san_raw),
        },
        "cleaned_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }

    return {
        "sources": sources_kept,
        "sinks": sinks_kept,
        "sanitizers": san_kept,
        "metadata": metadata,
    }


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", type=Path, default=_DEFAULT_INPUT)
    ap.add_argument("--output", type=Path, default=_DEFAULT_OUTPUT)
    ap.add_argument(
        "--max-source-drop-frac",
        type=float,
        default=_DEFAULT_MAX_DROP_FRAC,
        help="Refuse to write the output when more than this fraction of "
        "sources would be dropped (default 0.25).",
    )
    return ap.parse_args()


def _print_summary(payload: dict) -> None:
    cleaned = payload["metadata"]["cleaned_with"]
    inp = cleaned["input_counts"]
    kept = cleaned["kept_counts"]
    print(
        "[clean_seed_catalog] sources: {} -> {} ({} dropped)".format(
            inp["sources"], kept["sources"], len(cleaned["dropped_sources"])
        )
    )
    print(
        "[clean_seed_catalog] sinks:   {} -> {} ({} dropped)".format(
            inp["sinks"], kept["sinks"], len(cleaned["dropped_sinks"])
        )
    )
    print(
        "[clean_seed_catalog] sanitizers: {} -> {} ({} dropped)".format(
            inp["sanitizers"], kept["sanitizers"], len(cleaned["dropped_sanitizers"])
        )
    )
    if cleaned["dropped_sources"]:
        print("[clean_seed_catalog] dropped sources:")
        for row in cleaned["dropped_sources"]:
            print(f"    - {row['pattern']!r}  [{row['reason']}]")
    if cleaned["dropped_sinks"]:
        print("[clean_seed_catalog] dropped sinks:")
        for row in cleaned["dropped_sinks"]:
            print(f"    - {row['pattern']!r}  [{row['reason']}]")
    if cleaned["dropped_sanitizers"]:
        print("[clean_seed_catalog] dropped sanitizers:")
        for row in cleaned["dropped_sanitizers"]:
            print(f"    - {row['pattern']!r}  [{row['reason']}]")


def main() -> int:
    args = parse_args()
    if not args.input.exists():
        raise SystemExit(f"input not found: {args.input}")
    payload = json.loads(args.input.read_text())
    cleaned = clean_catalog(payload, max_source_drop_frac=args.max_source_drop_frac)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(cleaned, indent=2))
    print(f"[clean_seed_catalog] wrote {args.output}")
    _print_summary(cleaned)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
