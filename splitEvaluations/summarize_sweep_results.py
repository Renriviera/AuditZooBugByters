#!/usr/bin/env python3
"""Aggregate TP/FP/FN and LLM token usage from a sweep ``results.json``.

Usage::

    python -m splitEvaluations.summarize_sweep_results results/semgrep/<ts>/results.json

Optional seed-phase tokens are read from ``seed_llm_usage.json`` in the same
directory when present.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


def _empty_usage() -> dict[str, int]:
    return {
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
        "call_count": 0,
    }


def _sum_usage(a: dict[str, int], b: dict[str, Any] | None) -> dict[str, int]:
    out = dict(a)
    if not b:
        return out
    for k in ("prompt_tokens", "completion_tokens", "total_tokens", "call_count"):
        out[k] = out.get(k, 0) + int(b.get(k, 0))
    return out


def _micro_prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
    return prec, rec, f1


def summarize(
    results: list[dict[str, Any]],
    *,
    include_patched: bool = False,
) -> dict[str, Any]:
    """Return per-arm aggregates for Semgrep sweep CVE rows."""
    arm_pat = re.compile(r"^semgrep_\d+$")
    patched_pat = re.compile(r"^semgrep_\d+_patched$")

    by_arm: dict[str, dict[str, Any]] = {}

    for row in results:
        arms = row.get("arms") or {}
        for arm_key, arm in arms.items():
            if include_patched:
                if not patched_pat.match(arm_key):
                    continue
            else:
                if not arm_pat.match(arm_key):
                    continue

            bucket = by_arm.setdefault(
                arm_key,
                {
                    "tp": 0,
                    "fp": 0,
                    "fn": 0,
                    "fn_by_llm": 0,
                    "fp_by_hallucinated_source": 0,
                    "llm_usage": _empty_usage(),
                    "n_cves": 0,
                },
            )
            bucket["tp"] += int(arm.get("tp", 0))
            bucket["fp"] += int(arm.get("fp", 0))
            bucket["fn"] += int(arm.get("fn", 0))
            bucket["fn_by_llm"] += int(arm.get("fn_by_llm", 0))
            bucket["fp_by_hallucinated_source"] += int(
                arm.get("fp_by_hallucinated_source", 0)
            )
            metrics = arm.get("metrics") or {}
            usage = metrics.get("llm_usage")
            bucket["llm_usage"] = _sum_usage(bucket["llm_usage"], usage)
            bucket["n_cves"] += 1

    out: dict[str, Any] = {
        "by_arm": {},
        "all_arms_combined": {
            "tp": 0,
            "fp": 0,
            "fn": 0,
            "fn_by_llm": 0,
            "fp_by_hallucinated_source": 0,
            "llm_usage": _empty_usage(),
        },
    }

    for arm_key in sorted(by_arm.keys()):
        b = by_arm[arm_key]
        tp, fp, fn_ = b["tp"], b["fp"], b["fn"]
        prec, rec, f1 = _micro_prf(tp, fp, fn_)
        out["by_arm"][arm_key] = {
            **b,
            "micro_precision": prec,
            "micro_recall": rec,
            "micro_f1": f1,
        }
        agg = out["all_arms_combined"]
        for k in ("tp", "fp", "fn", "fn_by_llm", "fp_by_hallucinated_source"):
            agg[k] += b[k]
        agg["llm_usage"] = _sum_usage(agg["llm_usage"], b["llm_usage"])

    ac = out["all_arms_combined"]
    tp, fp, fn_ = ac["tp"], ac["fp"], ac["fn"]
    prec, rec, f1 = _micro_prf(tp, fp, fn_)
    ac["micro_precision"] = prec
    ac["micro_recall"] = rec
    ac["micro_f1"] = f1
    ac["note"] = (
        "Summed across semgrep_k arms (vulnerable snapshot). "
        "Patched arms omitted unless --include-patched."
    )

    return out


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Summarize TP/FP/FN and LLM tokens from results.json"
    )
    ap.add_argument("results_json", type=Path, help="Path to results.json")
    ap.add_argument(
        "--include-patched",
        action="store_true",
        help="Aggregate semgrep_*_patched arms instead of semgrep_k.",
    )
    ap.add_argument(
        "--json", action="store_true", help="Print machine-readable JSON only"
    )
    args = ap.parse_args()

    data = json.loads(args.results_json.read_text())
    summary = summarize(data, include_patched=args.include_patched)

    seed_path = args.results_json.parent / "seed_llm_usage.json"
    seed_usage: dict[str, Any] | None = None
    if seed_path.is_file():
        seed_usage = json.loads(seed_path.read_text())
        summary["seed_llm_usage"] = seed_usage

    eval_usage = summary["all_arms_combined"]["llm_usage"]
    total_run = _sum_usage(eval_usage, seed_usage)
    summary["total_llm_usage"] = {
        "evaluation": eval_usage,
        "seed": seed_usage or _empty_usage(),
        "run_total": total_run,
    }

    if args.json:
        print(json.dumps(summary, indent=2))
        return

    print("=== Semgrep sweep summary ===")
    print(f"Source: {args.results_json}")
    for arm_key, b in summary["by_arm"].items():
        print(
            f"\n{arm_key}: TP={b['tp']} FP={b['fp']} FN={b['fn']} "
            f"fn_by_llm={b['fn_by_llm']} fp_halluc_src={b['fp_by_hallucinated_source']} "
            f"P={b['micro_precision']:.4f} R={b['micro_recall']:.4f} F1={b['micro_f1']:.4f}"
        )
        u = b["llm_usage"]
        print(
            f"  LLM: prompt={u['prompt_tokens']} completion={u['completion_tokens']} "
            f"total={u['total_tokens']} calls={u['call_count']}"
        )

    ac = summary["all_arms_combined"]
    print(
        f"\nALL semgrep arms combined: TP={ac['tp']} FP={ac['fp']} FN={ac['fn']} "
        f"P={ac['micro_precision']:.4f} R={ac['micro_recall']:.4f} F1={ac['micro_f1']:.4f}"
    )
    u = ac["llm_usage"]
    print(
        f"  Evaluation LLM tokens: prompt={u['prompt_tokens']} "
        f"completion={u['completion_tokens']} total={u['total_tokens']} calls={u['call_count']}"
    )
    if seed_usage:
        s = seed_usage
        print(
            f"  Seed LLM tokens: prompt={s.get('prompt_tokens', 0)} "
            f"completion={s.get('completion_tokens', 0)} "
            f"total={s.get('total_tokens', 0)} calls={s.get('call_count', 0)}"
        )
    t = total_run
    print(
        f"  RUN TOTAL tokens: prompt={t['prompt_tokens']} "
        f"completion={t['completion_tokens']} total={t['total_tokens']} calls={t['call_count']}"
    )

    audit = args.results_json.parent / "rules_hash_audit.json"
    if audit.is_file():
        print(f"\nRules-hash audit: {audit}")


if __name__ == "__main__":
    main()
    sys.exit(0)
