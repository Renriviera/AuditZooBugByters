#!/usr/bin/env python3
"""CVE evaluation harness for the CWE-78 two-arm comparative study.

For each of the 105 CVEs in the metadata file:
  1. Clone the repo (shallow) and checkout the vulnerable commit.
  2. Run both arms (Semgrep + Joern) with k=0..3.
  3. Checkout the patch commit and re-run (findings on patched = FP).
  4. Label findings against ground truth.
  5. Record all metrics and save structured JSON results.

Usage:
    python scripts/run_evaluation.py                      # defaults
    python scripts/run_evaluation.py --arms semgrep       # Semgrep only
    python scripts/run_evaluation.py --variance           # variance run
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import random
import resource
import shutil
import subprocess
import time
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

import psutil

from auditzoo.agents.cwe78_study.pipeline import Pipeline, PipelineConfig
from auditzoo.agents.cwe78_study.schemas import Finding, IterationResult, ToolArm, Verdict

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATASET = ROOT / "benchmark" / "python" / "cwe78_cves" / "metadata.json"
DEFAULT_OUTPUT = ROOT / "results"
DEFAULT_CLONE_DIR = Path("/tmp/auditzoo_eval")

LINE_TOLERANCE = 5


# ======================================================================
# Ground-truth labelling
# ======================================================================

def label_findings(
    findings: list[Finding],
    triage_results: list[Any],
    ground_truth: dict[str, Any],
    *,
    line_tolerance: int = LINE_TOLERANCE,
) -> dict[str, Any]:
    """Compare findings to known vulnerable locations.

    Returns dict with tp, fp, fn counts and per-finding labels.
    """
    vuln_file = ground_truth.get("vulnerable_file", "")
    vuln_lines: set[int] = set(ground_truth.get("vulnerable_lines", []))

    tp = 0
    fp = 0
    labels: list[str] = []

    matched_vuln_lines: set[int] = set()

    for f, t in zip(findings, triage_results):
        if t.verdict == Verdict.FALSE_POSITIVE:
            fp += 1
            labels.append("fp_by_llm")
            continue

        found_file = Path(f.file_path).name
        gt_file = Path(vuln_file).name

        is_match = False
        if found_file == gt_file or vuln_file.endswith(f.file_path) or f.file_path.endswith(vuln_file):
            for vl in vuln_lines:
                if abs(f.line_start - vl) <= line_tolerance:
                    is_match = True
                    matched_vuln_lines.add(vl)
                    break

        if is_match:
            tp += 1
            labels.append("tp")
        else:
            fp += 1
            labels.append("fp_by_location")

    fn = len(vuln_lines - matched_vuln_lines)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "detection_rate": 1.0 if tp > 0 else 0.0,
        "labels": labels,
    }


# ======================================================================
# Repo management
# ======================================================================

def clone_and_checkout(
    repo_url: str, commit: str, dest: Path, *, shallow: bool = True
) -> bool:
    """Clone *repo_url* into *dest* and checkout *commit*."""
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True, exist_ok=True)

    try:
        clone_cmd = ["git", "clone"]
        if shallow:
            clone_cmd += ["--depth", "1"]
        clone_cmd += [repo_url, str(dest)]
        subprocess.run(clone_cmd, capture_output=True, text=True, timeout=120, check=True)

        subprocess.run(
            ["git", "fetch", "--depth=1", "origin", commit],
            cwd=str(dest), capture_output=True, text=True, timeout=120,
        )
        subprocess.run(
            ["git", "checkout", commit],
            cwd=str(dest), capture_output=True, text=True, timeout=60, check=True,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        logger.warning("Failed to clone/checkout %s@%s: %s", repo_url, commit[:8], exc)
        return False


def count_loc(repo_path: Path) -> int:
    """Count Python lines of code using tokei if available, else wc."""
    try:
        result = subprocess.run(
            ["tokei", "-t", "Python", "-o", "json", str(repo_path)],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            py = data.get("Python", data.get("python", {}))
            if isinstance(py, dict):
                return py.get("code", 0)
    except (FileNotFoundError, json.JSONDecodeError, subprocess.TimeoutExpired):
        pass

    total = 0
    for pyfile in repo_path.rglob("*.py"):
        try:
            total += sum(1 for line in pyfile.read_text().splitlines() if line.strip())
        except OSError:
            pass
    return total


# ======================================================================
# Resource monitoring
# ======================================================================

def get_resource_snapshot() -> dict[str, Any]:
    proc = psutil.Process(os.getpid())
    mem = proc.memory_info()
    ru = resource.getrusage(resource.RUSAGE_SELF)
    return {
        "peak_rss_mb": mem.rss / (1024 * 1024),
        "cpu_user_s": ru.ru_utime,
        "cpu_sys_s": ru.ru_stime,
    }


# ======================================================================
# Main evaluation loop
# ======================================================================

async def run_main_comparison(
    dataset: list[dict[str, Any]],
    pipeline_cfg: PipelineConfig,
    clone_dir: Path,
    output_dir: Path,
    *,
    line_tolerance: int = LINE_TOLERANCE,
    skip_empty_gt: bool = True,
) -> list[dict[str, Any]]:
    """Run 2 tools x 4 k-levels x N CVEs x 2 commits."""
    all_results: list[dict[str, Any]] = []

    for idx, cve in enumerate(dataset):
        cve_id = cve["cve_id"]
        logger.info("[%d/%d] Processing %s", idx + 1, len(dataset), cve_id)

        if skip_empty_gt and not cve.get("vulnerable_lines"):
            logger.info("  Skipping %s — no ground-truth lines", cve_id)
            continue

        repo_url = cve["repo_url"]
        vuln_commit = cve["vulnerable_commit"]
        patch_commit = cve["patch_commit"]
        repo_dest = clone_dir / cve_id

        # --- vulnerable commit ---
        ok = clone_and_checkout(repo_url, vuln_commit, repo_dest)
        if not ok:
            logger.warning("  Skipping %s — clone failed", cve_id)
            continue

        loc = count_loc(repo_dest)

        res_before = get_resource_snapshot()
        pipeline = Pipeline(pipeline_cfg)
        vuln_run = await pipeline.run(str(repo_dest), cve_id=cve_id)
        res_after = get_resource_snapshot()

        # --- patched commit ---
        ok_patch = clone_and_checkout(repo_url, patch_commit, repo_dest)
        patch_run = None
        if ok_patch:
            pipeline_patch = Pipeline(pipeline_cfg)
            patch_run = await pipeline_patch.run(str(repo_dest), cve_id=cve_id)

        # --- labelling ---
        cve_result: dict[str, Any] = {
            "cve_id": cve_id,
            "repo_url": repo_url,
            "loc": loc,
            "cvss_score": cve.get("cvss_score"),
            "arms": {},
        }

        for iteration in vuln_run.iterations:
            arm_key = f"{iteration.arm}_{iteration.iteration}"
            gt_labels = label_findings(
                iteration.findings, iteration.triage_results, cve, line_tolerance=line_tolerance
            )
            fp_kloc = gt_labels["fp"] / (loc / 1000) if loc > 0 else 0.0

            cve_result["arms"][arm_key] = {
                **gt_labels,
                "fp_kloc": fp_kloc,
                "metrics": iteration.metrics,
                "n_candidates": len(iteration.findings),
                "resource_delta": {
                    k: res_after[k] - res_before.get(k, 0)
                    for k in res_after
                },
            }

        if patch_run:
            for iteration in patch_run.iterations:
                arm_key = f"{iteration.arm}_{iteration.iteration}_patched"
                n_findings_on_patched = len(iteration.findings)
                cve_result["arms"][arm_key] = {
                    "n_findings_on_patched": n_findings_on_patched,
                    "metrics": iteration.metrics,
                }

        all_results.append(cve_result)

        # save incrementally
        _save_json(all_results, output_dir / "results.json")

        # cleanup
        shutil.rmtree(repo_dest, ignore_errors=True)

    return all_results


async def run_variance_analysis(
    dataset: list[dict[str, Any]],
    pipeline_cfg: PipelineConfig,
    clone_dir: Path,
    output_dir: Path,
    *,
    n_repos: int = 20,
    seeds: list[int] | None = None,
) -> list[dict[str, Any]]:
    """Variance analysis: Semgrep, k=3, *n_repos* random CVEs, multiple seeds."""
    seeds = seeds or [235711, 123456, 654321, 111111, 999999]

    random.seed(pipeline_cfg.seed)
    subset = random.sample(dataset, min(n_repos, len(dataset)))

    variance_cfg = PipelineConfig(
        max_iterations=3,
        arms=["semgrep"],
        seed=pipeline_cfg.seed,
        llm_base_url=pipeline_cfg.llm_base_url,
        llm_model=pipeline_cfg.llm_model,
        llm_temperature=pipeline_cfg.llm_temperature,
        llm_api_key=pipeline_cfg.llm_api_key,
    )

    all_results: list[dict[str, Any]] = []

    for cve in subset:
        cve_id = cve["cve_id"]
        repo_dest = clone_dir / cve_id
        ok = clone_and_checkout(cve["repo_url"], cve["vulnerable_commit"], repo_dest)
        if not ok:
            continue

        seed_results: dict[str, Any] = {"cve_id": cve_id, "seeds": {}}

        for seed in seeds:
            variance_cfg.seed = seed
            pipeline = Pipeline(variance_cfg)
            run_result = await pipeline.run(str(repo_dest), cve_id=cve_id)

            last_iter = [
                it for it in run_result.iterations
                if it.arm == ToolArm.SEMGREP and it.iteration == 3
            ]
            if last_iter:
                gt = label_findings(
                    last_iter[0].findings, last_iter[0].triage_results, cve
                )
                seed_results["seeds"][str(seed)] = {
                    **gt,
                    "metrics": last_iter[0].metrics,
                    "finding_ids": [
                        f"{f.file_path}:{f.line_start}" for f in last_iter[0].findings
                    ],
                    "verdicts": [
                        t.verdict.value for t in last_iter[0].triage_results
                    ],
                }

        all_results.append(seed_results)
        shutil.rmtree(repo_dest, ignore_errors=True)

    _save_json(all_results, output_dir / "variance_results.json")
    return all_results


def _save_json(data: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str))


# ======================================================================
# CLI entry point
# ======================================================================

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="CWE-78 evaluation harness")
    p.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    p.add_argument("--clone-dir", type=Path, default=DEFAULT_CLONE_DIR)
    p.add_argument("--arms", nargs="+", default=["semgrep", "joern"])
    p.add_argument("--max-k", type=int, default=3)
    p.add_argument("--seed", type=int, default=235711)
    p.add_argument("--llm-url", default="http://localhost:8000/v1")
    p.add_argument("--llm-model", default="Qwen/Qwen2.5-Coder-7B-Instruct")
    p.add_argument("--joern-port", type=int, default=12345)
    p.add_argument("--variance", action="store_true", help="Run variance analysis instead")
    p.add_argument("--variance-n", type=int, default=20)
    p.add_argument("--variance-seeds", nargs="+", type=int, default=[235711, 123456, 654321, 111111, 999999])
    p.add_argument("--line-tolerance", type=int, default=LINE_TOLERANCE)
    p.add_argument("--skip-empty-gt", action="store_true", default=True)
    return p.parse_args()


async def main() -> None:
    args = parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    dataset = json.loads(args.dataset.read_text())
    logger.info("Loaded %d CVEs from %s", len(dataset), args.dataset)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = args.output / timestamp
    output_dir.mkdir(parents=True, exist_ok=True)

    pipeline_cfg = PipelineConfig(
        max_iterations=args.max_k,
        seed=args.seed,
        arms=args.arms,
        llm_base_url=args.llm_url,
        llm_model=args.llm_model,
        joern_port=args.joern_port,
    )

    # Save run config
    _save_json(vars(args), output_dir / "run_config.json")

    if args.variance:
        logger.info("Running variance analysis (%d repos, %d seeds)", args.variance_n, len(args.variance_seeds))
        await run_variance_analysis(
            dataset, pipeline_cfg, args.clone_dir, output_dir,
            n_repos=args.variance_n, seeds=args.variance_seeds,
        )
    else:
        logger.info("Running main comparison (%d CVEs, arms=%s, k=0..%d)", len(dataset), args.arms, args.max_k)
        await run_main_comparison(
            dataset, pipeline_cfg, args.clone_dir, output_dir,
            line_tolerance=args.line_tolerance,
            skip_empty_gt=args.skip_empty_gt,
        )

    logger.info("Results saved to %s", output_dir)


if __name__ == "__main__":
    asyncio.run(main())
