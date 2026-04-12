#!/usr/bin/env python3
"""Analyse evaluation results and generate plots + summary table.

Reads ``results/<run>/results.json`` (and optionally ``variance_results.json``)
and produces 16 plots (P1-P16) plus a summary table with Wilcoxon tests.

Usage:
    python scripts/analyze_results.py results/20260315_120000
    python scripts/analyze_results.py results/20260315_120000 --variance results/20260315_120000/variance_results.json
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import defaultdict
from itertools import combinations
from pathlib import Path
from typing import Any

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
from scipy import stats

logger = logging.getLogger(__name__)

ARMS = ["semgrep", "joern"]
K_LEVELS = [0, 1, 2, 3]
PLOT_DPI = 150
FIG_SIZE = (7, 5)


# ======================================================================
# Data loading helpers
# ======================================================================

def load_results(path: Path) -> list[dict[str, Any]]:
    return json.loads(path.read_text())


def extract_arm_data(
    results: list[dict[str, Any]], arm: str, k: int
) -> list[dict[str, Any]]:
    """Pull per-CVE metrics for a given arm and iteration level."""
    key = f"{arm}_{k}"
    rows: list[dict[str, Any]] = []
    for cve in results:
        entry = cve.get("arms", {}).get(key)
        if entry and "precision" in entry:
            rows.append(
                {
                    "cve_id": cve["cve_id"],
                    "loc": cve.get("loc", 0),
                    "cvss_score": cve.get("cvss_score"),
                    **entry,
                }
            )
    return rows


def _metric_arrays(rows: list[dict[str, Any]], key: str) -> np.ndarray:
    return np.array([r.get(key, 0.0) for r in rows], dtype=float)


# ======================================================================
# Summary table
# ======================================================================

def build_summary_table(results: list[dict[str, Any]], out: Path) -> None:
    """Macro-averaged metrics per arm×k with Wilcoxon signed-rank tests."""
    lines: list[str] = []
    header = (
        f"{'arm':<8} {'k':>2} {'n':>4} {'P':>6} {'R':>6} {'F1':>6} "
        f"{'FP/kL':>7} {'DetR':>5} {'time_s':>7} {'tokens':>8}"
    )
    lines.append(header)
    lines.append("-" * len(header))

    paired: dict[int, dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))

    for arm in ARMS:
        for k in K_LEVELS:
            rows = extract_arm_data(results, arm, k)
            if not rows:
                continue
            for r in rows:
                paired[k][arm].append(r)

            n = len(rows)
            p = float(np.mean(_metric_arrays(rows, "precision")))
            r_ = float(np.mean(_metric_arrays(rows, "recall")))
            f1 = float(np.mean(_metric_arrays(rows, "f1")))
            fp_kloc = float(np.mean(_metric_arrays(rows, "fp_kloc")))
            det = float(np.mean(_metric_arrays(rows, "detection_rate")))
            time_s = float(
                np.mean(
                    np.array(
                        [r.get("metrics", {}).get("wall_clock_s", 0) for r in rows]
                    )
                )
            )
            tokens = int(
                np.mean(
                    np.array(
                        [
                            r.get("metrics", {}).get("llm_usage", {}).get("total_tokens", 0)
                            for r in rows
                        ]
                    )
                )
            )
            lines.append(
                f"{arm:<8} {k:>2} {n:>4} {p:>6.3f} {r_:>6.3f} {f1:>6.3f} "
                f"{fp_kloc:>7.2f} {det:>5.2f} {time_s:>7.1f} {tokens:>8d}"
            )

    # Wilcoxon signed-rank test (paired by CVE) at each k
    lines.append("")
    lines.append("Wilcoxon signed-rank tests (Semgrep vs Joern, paired by CVE):")
    for k in K_LEVELS:
        sem = {r["cve_id"]: r for r in paired[k].get("semgrep", [])}
        joe = {r["cve_id"]: r for r in paired[k].get("joern", [])}
        common = sorted(set(sem) & set(joe))
        if len(common) < 5:
            lines.append(f"  k={k}: too few paired samples ({len(common)})")
            continue
        for metric in ("f1", "precision", "recall"):
            a = np.array([sem[c][metric] for c in common])
            b = np.array([joe[c][metric] for c in common])
            diff = a - b
            if np.all(diff == 0):
                lines.append(f"  k={k} {metric}: all differences zero")
                continue
            stat, pval = stats.wilcoxon(a, b, alternative="two-sided")
            sig = "*" if pval < 0.05 else ""
            lines.append(f"  k={k} {metric}: W={stat:.1f}, p={pval:.4f} {sig}")

    text = "\n".join(lines)
    (out / "summary_table.txt").write_text(text)
    logger.info("Summary table:\n%s", text)


# ======================================================================
# P1-P6 — Accuracy vs Efficiency
# ======================================================================

def _scatter(
    results: list[dict[str, Any]],
    x_metric: str,
    y_metric: str,
    xlabel: str,
    ylabel: str,
    title: str,
    out: Path,
    filename: str,
) -> None:
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    for arm in ARMS:
        rows = extract_arm_data(results, arm, k=3)
        if not rows:
            continue
        x = _get_nested(rows, x_metric)
        y = _metric_arrays(rows, y_metric)
        ax.scatter(x, y, label=arm, alpha=0.7, s=30)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.legend()
    fig.tight_layout()
    fig.savefig(out / filename, dpi=PLOT_DPI)
    plt.close(fig)


def _get_nested(rows: list[dict[str, Any]], key: str) -> np.ndarray:
    """Supports dotted keys like 'metrics.wall_clock_s'."""
    parts = key.split(".")
    vals: list[float] = []
    for r in rows:
        v: Any = r
        for p in parts:
            v = v.get(p, 0) if isinstance(v, dict) else 0
        vals.append(float(v))
    return np.array(vals)


def plot_p1_p6(results: list[dict[str, Any]], out: Path) -> None:
    configs = [
        ("metrics.wall_clock_s", "f1", "Runtime (s)", "F1", "P1: F1 vs Runtime", "P01_f1_vs_runtime.png"),
        ("metrics.wall_clock_s", "precision", "Runtime (s)", "Precision", "P2: Precision vs Runtime", "P02_precision_vs_runtime.png"),
        ("metrics.llm_usage.total_tokens", "f1", "Total Tokens", "F1", "P3: F1 vs Token Usage", "P03_f1_vs_tokens.png"),
        ("loc", "f1", "LOC", "F1", "P4: F1 vs LOC", "P04_f1_vs_loc.png"),
        ("metrics.llm_usage.total_tokens", "precision", "Total Tokens", "Precision", "P5: Precision vs Tokens", "P05_precision_vs_tokens.png"),
        ("loc", "recall", "LOC", "Recall", "P6: Recall vs LOC", "P06_recall_vs_loc.png"),
    ]
    for x_m, y_m, xl, yl, title, fname in configs:
        _scatter(results, x_m, y_m, xl, yl, title, out, fname)


# ======================================================================
# P7-P9 — Iteration ablation
# ======================================================================

def plot_p7_p9(results: list[dict[str, Any]], out: Path) -> None:
    metrics_to_plot = [
        ("f1", "F1", "P07_f1_vs_k.png"),
        ("fp", "False Positives", "P08_fp_vs_k.png"),
        ("metrics.llm_usage.total_tokens", "Total Tokens", "P09_cost_vs_k.png"),
    ]
    for m_key, ylabel, fname in metrics_to_plot:
        fig, ax = plt.subplots(figsize=FIG_SIZE)
        for arm in ARMS:
            means, stds = [], []
            for k in K_LEVELS:
                rows = extract_arm_data(results, arm, k)
                if not rows:
                    means.append(0)
                    stds.append(0)
                    continue
                if "." in m_key:
                    vals = _get_nested(rows, m_key)
                else:
                    vals = _metric_arrays(rows, m_key)
                means.append(float(np.mean(vals)))
                stds.append(float(np.std(vals)))
            ax.errorbar(K_LEVELS, means, yerr=stds, label=arm, marker="o", capsize=3)
        ax.set_xlabel("Iteration (k)")
        ax.set_ylabel(ylabel)
        ax.set_title(f"{ylabel} vs Iteration")
        ax.set_xticks(K_LEVELS)
        ax.legend()
        fig.tight_layout()
        fig.savefig(out / fname, dpi=PLOT_DPI)
        plt.close(fig)


# ======================================================================
# P10-P12 — Variance analysis
# ======================================================================

def plot_p10_p12(variance_data: list[dict[str, Any]], out: Path) -> None:
    if not variance_data:
        logger.warning("No variance data — skipping P10-P12")
        return

    # P10: FP boxplot across seeds
    fp_per_seed: dict[str, list[int]] = defaultdict(list)
    for cve_data in variance_data:
        for seed_str, seed_result in cve_data.get("seeds", {}).items():
            fp_per_seed[seed_str].append(seed_result.get("fp", 0))

    if fp_per_seed:
        fig, ax = plt.subplots(figsize=FIG_SIZE)
        data = [fp_per_seed[s] for s in sorted(fp_per_seed)]
        ax.boxplot(data, labels=sorted(fp_per_seed))
        ax.set_xlabel("Seed")
        ax.set_ylabel("False Positives")
        ax.set_title("P10: FP Distribution Across Seeds")
        fig.tight_layout()
        fig.savefig(out / "P10_fp_boxplot.png", dpi=PLOT_DPI)
        plt.close(fig)

    # P11: Jaccard similarity heatmap
    seeds = sorted({s for cve in variance_data for s in cve.get("seeds", {})})
    if len(seeds) >= 2:
        n = len(seeds)
        jaccard_matrix = np.ones((n, n))
        for i, j in combinations(range(n), 2):
            overlaps: list[float] = []
            for cve_data in variance_data:
                s = cve_data.get("seeds", {})
                if seeds[i] in s and seeds[j] in s:
                    a = set(s[seeds[i]].get("finding_ids", []))
                    b = set(s[seeds[j]].get("finding_ids", []))
                    if a or b:
                        overlaps.append(len(a & b) / len(a | b))
            if overlaps:
                jaccard_matrix[i, j] = jaccard_matrix[j, i] = float(np.mean(overlaps))

        fig, ax = plt.subplots(figsize=FIG_SIZE)
        sns.heatmap(
            jaccard_matrix, annot=True, fmt=".2f", xticklabels=seeds,
            yticklabels=seeds, cmap="YlOrRd", ax=ax,
        )
        ax.set_title("P11: Jaccard Similarity Across Seeds")
        fig.tight_layout()
        fig.savefig(out / "P11_jaccard_heatmap.png", dpi=PLOT_DPI)
        plt.close(fig)

    # P12: Verdict flip histogram
    flip_counts: list[int] = []
    for cve_data in variance_data:
        s = cve_data.get("seeds", {})
        verdict_lists = [s[seed].get("verdicts", []) for seed in sorted(s)]
        if len(verdict_lists) < 2:
            continue
        max_len = max(len(vl) for vl in verdict_lists)
        flips = 0
        for idx in range(max_len):
            unique = {
                vl[idx] for vl in verdict_lists if idx < len(vl)
            }
            if len(unique) > 1:
                flips += 1
        flip_counts.append(flips)

    if flip_counts:
        fig, ax = plt.subplots(figsize=FIG_SIZE)
        ax.hist(flip_counts, bins=max(1, max(flip_counts)), edgecolor="black")
        ax.set_xlabel("Number of Verdict Flips")
        ax.set_ylabel("CVE Count")
        ax.set_title("P12: Verdict Flip Distribution")
        fig.tight_layout()
        fig.savefig(out / "P12_flip_histogram.png", dpi=PLOT_DPI)
        plt.close(fig)


# ======================================================================
# P13-P16 — Per-tool deep dives
# ======================================================================

def plot_p13_p16(results: list[dict[str, Any]], out: Path) -> None:
    # P13: Detection rate by sink API
    sink_detect: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    for cve in results:
        sink = cve.get("cvss_score", "unknown")  # placeholder; ideally from metadata
        for arm in ARMS:
            entry = cve.get("arms", {}).get(f"{arm}_3")
            if entry and "detection_rate" in entry:
                sink_detect[arm][str(sink)].append(entry["detection_rate"])

    fig, axes = plt.subplots(1, 2, figsize=(14, 5), sharey=True)
    for idx, arm in enumerate(ARMS):
        data = sink_detect[arm]
        if data:
            keys = sorted(data.keys())
            vals = [np.mean(data[k]) for k in keys]
            axes[idx].bar(range(len(keys)), vals, tick_label=keys)
            axes[idx].set_title(f"P13: Detection Rate — {arm}")
            axes[idx].set_ylabel("Detection Rate")
            axes[idx].tick_params(axis="x", rotation=45)
    fig.tight_layout()
    fig.savefig(out / "P13_detection_by_sink.png", dpi=PLOT_DPI)
    plt.close(fig)

    # P14: F1 vs CVSS score
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    for arm in ARMS:
        rows = extract_arm_data(results, arm, 3)
        cvss = np.array([r.get("cvss_score", 0) or 0 for r in rows], dtype=float)
        f1 = _metric_arrays(rows, "f1")
        ax.scatter(cvss, f1, label=arm, alpha=0.7, s=30)
    ax.set_xlabel("CVSS Score")
    ax.set_ylabel("F1")
    ax.set_title("P14: F1 vs CVSS Severity")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out / "P14_f1_vs_cvss.png", dpi=PLOT_DPI)
    plt.close(fig)

    # P15: Cumulative findings over iterations
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    for arm in ARMS:
        cum_tp: list[float] = []
        for k in K_LEVELS:
            rows = extract_arm_data(results, arm, k)
            if rows:
                cum_tp.append(float(np.sum(_metric_arrays(rows, "tp"))))
            else:
                cum_tp.append(0)
        ax.plot(K_LEVELS, cum_tp, marker="o", label=arm)
    ax.set_xlabel("Iteration (k)")
    ax.set_ylabel("Cumulative TP")
    ax.set_title("P15: Cumulative True Positives vs Iteration")
    ax.set_xticks(K_LEVELS)
    ax.legend()
    fig.tight_layout()
    fig.savefig(out / "P15_cumulative_tp.png", dpi=PLOT_DPI)
    plt.close(fig)

    # P16: Resource usage timeline
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    for idx, (metric_path, ylabel) in enumerate([
        ("metrics.wall_clock_s", "Wall Clock (s)"),
        ("metrics.llm_usage.total_tokens", "Total Tokens"),
    ]):
        for arm in ARMS:
            means = []
            for k in K_LEVELS:
                rows = extract_arm_data(results, arm, k)
                if rows:
                    means.append(float(np.mean(_get_nested(rows, metric_path))))
                else:
                    means.append(0)
            axes[idx].plot(K_LEVELS, means, marker="o", label=arm)
        axes[idx].set_xlabel("Iteration (k)")
        axes[idx].set_ylabel(ylabel)
        axes[idx].set_title(f"P16: {ylabel} per Iteration")
        axes[idx].set_xticks(K_LEVELS)
        axes[idx].legend()
    fig.tight_layout()
    fig.savefig(out / "P16_resource_timeline.png", dpi=PLOT_DPI)
    plt.close(fig)


# ======================================================================
# CLI
# ======================================================================

def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze CWE-78 study results")
    parser.add_argument("results_dir", type=Path, help="Path to results directory")
    parser.add_argument("--variance", type=Path, default=None, help="Path to variance_results.json")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    results_file = args.results_dir / "results.json"
    if not results_file.exists():
        logger.error("results.json not found in %s", args.results_dir)
        sys.exit(1)

    results = load_results(results_file)
    plots_dir = args.results_dir / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Generating plots for %d CVEs ...", len(results))

    build_summary_table(results, args.results_dir)
    plot_p1_p6(results, plots_dir)
    plot_p7_p9(results, plots_dir)
    plot_p13_p16(results, plots_dir)

    # Variance plots (optional)
    var_path = args.variance or (args.results_dir / "variance_results.json")
    if var_path.exists():
        var_data = load_results(var_path)
        plot_p10_p12(var_data, plots_dir)
    else:
        logger.info("No variance_results.json found — skipping P10-P12")

    logger.info("All plots saved to %s", plots_dir)


if __name__ == "__main__":
    main()
