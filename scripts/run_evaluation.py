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
import socket
import subprocess
import time
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

import psutil

from auditzoo.agents.cwe78_study.pipeline import Pipeline, PipelineConfig
from auditzoo.agents.cwe78_study.schemas import (
    Finding,
    IterationResult,
    ToolArm,
    TriageResult,
    Verdict,
)

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATASET = ROOT / "benchmark" / "python" / "cwe78_cves" / "metadata.json"
DEFAULT_OUTPUT = ROOT / "results"
DEFAULT_CLONE_DIR = Path("/tmp/auditzoo_eval")

LINE_TOLERANCE = 5
DEFAULT_GIT_TIMEOUT_S = 300

_REASONING_CAP = 200


# ======================================================================
# Evidence serialisation
# ======================================================================


def _snippet_for(f: Finding) -> str:
    """Return the text that ``source_expr`` / ``sink_expr`` are validated against."""
    return (
        (getattr(f, "surrounding_context", "") or "")
        + "\n"
        + (getattr(f, "code_snippet", "") or "")
    )


def serialize_triage_verdicts(
    findings: list[Finding],
    triage_results: list[TriageResult],
) -> list[dict[str, Any]]:
    """Produce an audit-friendly, length-aligned list of triage decisions.

    Each entry joins the finding location and rule with the LLM verdict
    so downstream analysis can compute ``verdict x gt_match`` contingency
    tables without needing the pipeline state.  Reasoning and suggestion
    strings are capped at ``_REASONING_CAP`` characters to keep
    ``results.json`` small.

    In addition to the Phase-B3 schema we emit two evidence-audit
    columns sourced from the new :class:`TriageResult.source_expr` /
    :class:`TriageResult.sink_expr` fields:

    * ``source_in_snippet``: whether ``source_expr`` is a literal
      substring of the finding's snippet (``True`` when ``source_expr``
      is empty — preserves parity with pre-evidence results).
    * ``downgrade_reason``: propagated from the agent-level brake
      (``"source_expr_not_in_snippet"``,
      ``"sink_expr_not_in_snippet"``, or ``""``).
    """
    out: list[dict[str, Any]] = []
    for f, t in zip(findings, triage_results):
        snippet = _snippet_for(f)
        source_expr = (getattr(t, "source_expr", "") or "").strip()
        sink_expr = (getattr(t, "sink_expr", "") or "").strip()
        # Parity rule: empty source_expr reports True so old-format
        # scripted results (which have no source_expr at all) aren't
        # mass-flagged as hallucinations.
        source_in_snippet = (not source_expr) or (source_expr in snippet)
        sink_in_snippet = (not sink_expr) or (sink_expr in snippet)
        out.append(
            {
                "file": f.file_path,
                "line": f.line_start,
                "rule_id": f.rule_id,
                "sink_api": f.sink_api,
                "verdict": getattr(t.verdict, "value", str(t.verdict)),
                "confidence": float(getattr(t, "confidence", 0.0) or 0.0),
                "reasoning": (getattr(t, "reasoning", "") or "")[:_REASONING_CAP],
                "suggestion": (getattr(t, "suggestion", "") or "")[:_REASONING_CAP],
                "source_expr": source_expr[:_REASONING_CAP],
                "sink_expr": sink_expr[:_REASONING_CAP],
                "source_in_snippet": source_in_snippet,
                "sink_in_snippet": sink_in_snippet,
                "downgrade_reason": getattr(t, "downgrade_reason", "") or "",
            }
        )
    return out


# ======================================================================
# Ground-truth labelling
# ======================================================================


def _gt_line_match(
    f: Finding,
    vuln_file: str,
    vuln_lines: set[int],
    line_tolerance: int,
) -> tuple[bool, int | None]:
    """Return ``(is_match, matched_gt_line)`` for a finding against GT."""
    if not vuln_lines:
        return False, None
    found_file = Path(f.file_path).name
    gt_file = Path(vuln_file).name
    path_ok = (
        found_file == gt_file
        or vuln_file.endswith(f.file_path)
        or f.file_path.endswith(vuln_file)
    )
    if not path_ok:
        return False, None
    for vl in vuln_lines:
        if abs(f.line_start - vl) <= line_tolerance:
            return True, vl
    return False, None


def label_findings(
    findings: list[Finding],
    triage_results: list[Any],
    ground_truth: dict[str, Any],
    *,
    line_tolerance: int = LINE_TOLERANCE,
) -> dict[str, Any]:
    """Score findings against ground truth, honouring the LLM's verdict asymmetrically.

    Previously the scorer only honoured ``FALSE_POSITIVE`` (subtracted from
    matching); ``TRUE_POSITIVE`` and ``UNCERTAIN`` were merged.  That made
    the LLM triage step incapable of moving TP/FP/FN and was the primary
    cause of the k-invariant metrics documented in ``results/full/...``.

    The redesigned matrix (Phase-B1 + evidence extension)::

        verdict           gt_match  source_in_snippet -> label                      TP FP FN
        -------           --------  -----------------    ------                     -- -- --
        FALSE_POSITIVE    no_match        any         -> tn                                 (suppressed)
        FALSE_POSITIVE    match           any         -> fn_by_llm                  .  .  1 (LLM killed a real bug)
        TRUE_POSITIVE     match           true        -> tp                         1  .  .
        TRUE_POSITIVE     match           false       -> fp_by_hallucinated_source  .  1  . (TP on GT line but source_expr invented)
        TRUE_POSITIVE     no_match        true        -> fp_by_llm_overclaim        .  1  .
        TRUE_POSITIVE     no_match        false       -> fp_by_hallucinated_source  .  1  .
        UNCERTAIN         match           any         -> tp                         1  .  . (parity w/ previous)
        UNCERTAIN         no_match        any         -> fp_by_location             .  1  . (parity w/ previous)

    FN over the whole CVE is ``|vuln_lines - matched_lines|`` where
    ``matched_lines`` only counts findings the LLM did *not* suppress
    *and* did not justify with a hallucinated ``source_expr``.  If the
    LLM suppresses a finding that *was* on a ground-truth line, that
    ground-truth line becomes an ``fn_by_llm`` (since a true alert was
    retracted) in addition to still contributing to the ``fn`` count.

    Back-compat: when ``TriageResult.source_expr == ""`` (pre-evidence
    runs or scripted results that predate the field)
    ``source_in_snippet`` is treated as ``True``, preserving the
    Phase-B1 behaviour unchanged.
    """
    vuln_file = ground_truth.get("vulnerable_file", "")
    vuln_lines: set[int] = set(ground_truth.get("vulnerable_lines", []))

    tp = 0
    fp = 0
    fn_by_llm = 0  # ground-truth alerts the LLM retracted (subset of total FN)
    fp_by_hallucinated_source = 0  # subset of fp: TPs with source_expr not in snippet
    labels: list[str] = []

    matched_vuln_lines: set[int] = (
        set()
    )  # matched by a surviving (non-suppressed, non-hallucinated) finding

    for f, t in zip(findings, triage_results):
        is_match, matched_line = _gt_line_match(
            f,
            vuln_file,
            vuln_lines,
            line_tolerance,
        )

        source_expr = (getattr(t, "source_expr", "") or "").strip()
        snippet = (
            (getattr(f, "surrounding_context", "") or "")
            + "\n"
            + (getattr(f, "code_snippet", "") or "")
        )
        # Parity: empty source_expr ⇒ treat as "present" so pre-evidence
        # runs aren't mass-flagged as hallucinations.
        source_in_snippet = (not source_expr) or (source_expr in snippet)

        if t.verdict == Verdict.FALSE_POSITIVE:
            if is_match:
                fn_by_llm += 1
                labels.append("fn_by_llm")
            else:
                labels.append("tn")
            continue

        if t.verdict == Verdict.TRUE_POSITIVE:
            if not source_in_snippet:
                # Hallucination brake at scorer level: a TP citing a
                # source expression not in the snippet is counted as an
                # FP regardless of line match.  The corresponding GT
                # line does NOT enter matched_vuln_lines, so it still
                # accrues an FN below.
                fp += 1
                fp_by_hallucinated_source += 1
                labels.append("fp_by_hallucinated_source")
                continue
            if is_match:
                tp += 1
                if matched_line is not None:
                    matched_vuln_lines.add(matched_line)
                labels.append("tp")
            else:
                fp += 1
                labels.append("fp_by_llm_overclaim")
            continue

        # UNCERTAIN (and any unexpected verdict): parity with previous logic.
        if is_match:
            tp += 1
            if matched_line is not None:
                matched_vuln_lines.add(matched_line)
            labels.append("tp")
        else:
            fp += 1
            labels.append("fp_by_location")

    fn = len(vuln_lines - matched_vuln_lines)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "fn_by_llm": fn_by_llm,
        "fp_by_hallucinated_source": fp_by_hallucinated_source,
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
        git_timeout = int(os.environ.get("AUDITZOO_CLONE_TIMEOUT", DEFAULT_GIT_TIMEOUT_S))
        clone_cmd = ["git", "clone"]
        if shallow:
            clone_cmd += ["--depth", "1"]
        clone_cmd += [repo_url, str(dest)]
        subprocess.run(
            clone_cmd, capture_output=True, text=True, timeout=git_timeout, check=True
        )

        subprocess.run(
            ["git", "fetch", "--depth=1", "origin", commit],
            cwd=str(dest),
            capture_output=True,
            text=True,
            timeout=git_timeout,
        )
        subprocess.run(
            ["git", "checkout", commit],
            cwd=str(dest),
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
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
            capture_output=True,
            text=True,
            timeout=30,
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
            # Read as bytes so non-UTF-8 source files (e.g. latin-1 / mojibake in
            # older Python 2 code) don't abort the whole evaluation sweep.
            with pyfile.open("rb") as fh:
                for raw in fh:
                    if raw.strip():
                        total += 1
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


def _is_port_in_use(port: int, host: str = "localhost", timeout: float = 0.5) -> bool:
    """Return ``True`` if a TCP listener is bound to ``(host, port)``.

    A successful ``connect`` proves the socket is bound (likely by a
    lingering Joern JVM).  ``ConnectionRefusedError`` or any other socket
    error is treated as "free".  We deliberately do not distinguish
    "port closed" from "port reset" — both let us proceed.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def _cleanup_stray_joern(
    port: int | None = None,
    *,
    wait_s: float = 30.0,
    poll_s: float = 0.5,
) -> bool:
    """Best-effort kill of any lingering Joern server subprocesses.

    The 20260507_145628 sweep degraded after CVE 11 because a stuck JVM
    held port 12345 for the rest of the run; ``pkill`` returns immediately
    while the kernel still has the listener bound.  When *port* is given
    we poll until the port is actually free or *wait_s* elapses, so the
    next CVE has a clean Joern to connect to.

    Returns ``True`` if the port is free (or no port check was requested),
    ``False`` if it was still bound when the wait elapsed.
    """
    try:
        subprocess.run(
            ["pkill", "-9", "-f", "joern-cli/joern|ReplBridge"],
            check=False,
            timeout=10,
        )
    except Exception:
        logger.exception("_cleanup_stray_joern pkill failed")

    if port is None:
        return True

    deadline = time.time() + max(0.0, wait_s)
    while time.time() < deadline:
        if not _is_port_in_use(port):
            return True
        time.sleep(poll_s)
    logger.warning(
        "Joern port %d still in use after %.0fs cleanup wait", port, wait_s
    )
    return False


async def _run_with_timeout(
    pipeline: Pipeline,
    repo_path: str,
    cve_id: str,
    timeout_s: float,
    *,
    joern_port: int | None = None,
) -> tuple[Any, bool]:
    """Run ``pipeline.run`` with a wall-clock budget.

    Returns ``(run_result, timed_out)``.  On timeout we cancel, reap any
    stray Joern subprocesses, and return ``(None, True)``.  ``joern_port``
    is forwarded to the cleanup so we wait for the JVM's TCP listener to
    actually drop before the caller starts the next CVE.
    """
    if timeout_s and timeout_s > 0:
        try:
            result = await asyncio.wait_for(
                pipeline.run(repo_path, cve_id=cve_id),
                timeout=timeout_s,
            )
            return result, False
        except asyncio.TimeoutError:
            logger.warning(
                "  %s: pipeline.run exceeded %.0fs budget, aborting this CVE",
                cve_id,
                timeout_s,
            )
            _cleanup_stray_joern(joern_port)
            return None, True
    else:
        return await pipeline.run(repo_path, cve_id=cve_id), False


async def run_main_comparison(
    dataset: list[dict[str, Any]],
    pipeline_cfg: PipelineConfig,
    clone_dir: Path,
    output_dir: Path,
    *,
    line_tolerance: int = LINE_TOLERANCE,
    skip_empty_gt: bool = True,
    per_cve_timeout: float = 900.0,
    skip_cves: list[str] | None = None,
    run_patched: bool = True,
) -> list[dict[str, Any]]:
    """Run 2 tools x 4 k-levels x N CVEs x 2 commits."""
    all_results: list[dict[str, Any]] = []
    skip_set = set(skip_cves or [])
    joern_port = (
        getattr(pipeline_cfg, "joern_port", None) if "joern" in pipeline_cfg.arms else None
    )

    # Pre-flight: a stuck Joern from a previous (possibly killed) run will
    # cause every CVE to fail with "port already in use".  Reap it once
    # before we start so the first CVE has a clean slate.
    if joern_port is not None and _is_port_in_use(joern_port):
        logger.warning(
            "Joern port %d already bound at sweep start; reaping stray JVMs",
            joern_port,
        )
        _cleanup_stray_joern(joern_port)

    for idx, cve in enumerate(dataset):
        cve_id = cve["cve_id"]
        logger.info("[%d/%d] Processing %s", idx + 1, len(dataset), cve_id)

        if cve_id in skip_set:
            logger.info("  Skipping %s — on --skip-cves list", cve_id)
            all_results.append({"cve_id": cve_id, "skipped": "explicit"})
            _save_json(all_results, output_dir / "results.json")
            continue

        if skip_empty_gt and not cve.get("vulnerable_lines"):
            logger.info("  Skipping %s — no ground-truth lines", cve_id)
            continue

        repo_dest = clone_dir / cve_id
        try:
            repo_url = cve["repo_url"]
            vuln_commit = cve["vulnerable_commit"]
            patch_commit = cve["patch_commit"]

            # Per-CVE restart guard: even with the post-CVE polling
            # cleanup below, a JVM that crashed mid-query (e.g. OOM with
            # ExitOnOutOfMemoryError disabled, or SIGKILL'd by the OOM
            # killer) can leave the listening socket in TIME_WAIT for
            # multiple seconds.  Polling here gives the kernel time to
            # release the port and turns "port already in use" cascades
            # into a deterministic short wait.
            if joern_port is not None and _is_port_in_use(joern_port):
                logger.warning(
                    "  %s: Joern port %d still bound at CVE start; reaping",
                    cve_id,
                    joern_port,
                )
                _cleanup_stray_joern(joern_port)

            # --- vulnerable commit ---
            ok = clone_and_checkout(repo_url, vuln_commit, repo_dest)
            if not ok:
                logger.warning("  Skipping %s — clone failed", cve_id)
                continue

            loc = count_loc(repo_dest)

            res_before = get_resource_snapshot()
            pipeline = Pipeline(pipeline_cfg)
            vuln_run, timed_out = await _run_with_timeout(
                pipeline,
                str(repo_dest),
                cve_id,
                per_cve_timeout,
                joern_port=joern_port,
            )
            res_after = get_resource_snapshot()

            if timed_out:
                all_results.append(
                    {
                        "cve_id": cve_id,
                        "repo_url": repo_url,
                        "loc": loc,
                        "skipped": "timeout",
                        "per_cve_timeout_s": per_cve_timeout,
                    }
                )
                _save_json(all_results, output_dir / "results.json")
                shutil.rmtree(repo_dest, ignore_errors=True)
                continue

            # --- patched commit ---
            # ``run_patched=False`` is the v1 Joern-sweep default: Joern's
            # dominant cost is CPG construction, and repeating it on the
            # patched commit inside the same per-CVE budget was the primary
            # timeout driver in the 20260421_123649 sweep.  Skipping it
            # trades the "alerts-on-patched = FP" signal for enough budget
            # headroom to actually finish each CVE.
            patch_run = None
            if run_patched:
                ok_patch = clone_and_checkout(repo_url, patch_commit, repo_dest)
                if ok_patch:
                    pipeline_patch = Pipeline(pipeline_cfg)
                    patch_run, patch_timed_out = await _run_with_timeout(
                        pipeline_patch,
                        str(repo_dest),
                        cve_id,
                        per_cve_timeout,
                        joern_port=joern_port,
                    )
                    if patch_timed_out:
                        patch_run = None

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
                    iteration.findings,
                    iteration.triage_results,
                    cve,
                    line_tolerance=line_tolerance,
                )
                fp_kloc = gt_labels["fp"] / (loc / 1000) if loc > 0 else 0.0

                arm_entry: dict[str, Any] = {
                    **gt_labels,
                    "fp_kloc": fp_kloc,
                    "metrics": iteration.metrics,
                    "n_candidates": len(iteration.findings),
                    "triage_verdicts": serialize_triage_verdicts(
                        iteration.findings, iteration.triage_results
                    ),
                    "refinement_actions": list(iteration.refinement_actions or []),
                    "resource_delta": {
                        k: res_after[k] - res_before.get(k, 0) for k in res_after
                    },
                }
                if iteration.metrics.get("cpg_build_failed"):
                    # Surface CPG build failures as a top-level column so
                    # downstream analysis does not conflate them with
                    # "arm produced zero findings successfully".
                    arm_entry["arm_error"] = iteration.metrics.get("error")
                    arm_entry["arm_error_type"] = iteration.metrics.get("error_type")
                cve_result["arms"][arm_key] = arm_entry

            if patch_run:
                for iteration in patch_run.iterations:
                    arm_key = f"{iteration.arm}_{iteration.iteration}_patched"
                    n_findings_on_patched = len(iteration.findings)
                    cve_result["arms"][arm_key] = {
                        "n_findings_on_patched": n_findings_on_patched,
                        "metrics": iteration.metrics,
                        "triage_verdicts": serialize_triage_verdicts(
                            iteration.findings, iteration.triage_results
                        ),
                        "refinement_actions": list(iteration.refinement_actions or []),
                    }

            all_results.append(cve_result)

            # save incrementally
            _save_json(all_results, output_dir / "results.json")

        except (KeyboardInterrupt, asyncio.CancelledError):
            # Honour user/system cancellation: flush partial results and re-raise
            # so callers can shut the whole sweep down cleanly.
            _save_json(all_results, output_dir / "results.json")
            shutil.rmtree(repo_dest, ignore_errors=True)
            _cleanup_stray_joern(joern_port)
            raise
        except Exception as exc:  # noqa: BLE001 — isolate per-CVE failures
            logger.exception("  %s: unhandled error, skipping CVE: %s", cve_id, exc)
            all_results.append(
                {
                    "cve_id": cve_id,
                    "repo_url": cve.get("repo_url"),
                    "skipped": "error",
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            _save_json(all_results, output_dir / "results.json")
            _cleanup_stray_joern(joern_port)
        finally:
            shutil.rmtree(repo_dest, ignore_errors=True)
            # Proactive per-CVE cleanup: even on the success path the
            # pipeline's runtime ``stop()`` occasionally leaves a JVM
            # holding port ``joern_port`` for several seconds, which then
            # poisons the next CVE.  Polling the port before moving on
            # turns the failure mode in 20260507_145628 (CVE 12+ all
            # ``port already in use``) into a deterministic short wait.
            if joern_port is not None and _is_port_in_use(joern_port):
                _cleanup_stray_joern(joern_port)

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
                it
                for it in run_result.iterations
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
                    "verdicts": [t.verdict.value for t in last_iter[0].triage_results],
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
    p.add_argument("--llm-model", default="gpt-5.4-mini")
    p.add_argument("--joern-port", type=int, default=12345)
    p.add_argument(
        "--variance", action="store_true", help="Run variance analysis instead"
    )
    p.add_argument("--variance-n", type=int, default=20)
    p.add_argument(
        "--variance-seeds",
        nargs="+",
        type=int,
        default=[235711, 123456, 654321, 111111, 999999],
    )
    p.add_argument("--line-tolerance", type=int, default=LINE_TOLERANCE)
    p.add_argument("--skip-empty-gt", action="store_true", default=True)
    p.add_argument(
        "--per-cve-timeout",
        type=float,
        default=900.0,
        help="Wall-clock seconds budget per pipeline.run(); 0 disables.  "
        "On timeout the CVE is recorded as 'timed_out' and we move on.",
    )
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
        help="If non-empty, restrict evaluation to these CVE IDs only "
        "(used for Phase-A3 deep dives).",
    )
    p.add_argument(
        "--log-llm-io",
        type=Path,
        default=None,
        help="Append every LLM chat round-trip (prompt + response) as JSONL "
        "to this path.  Useful for debugging the UNCERTAIN-collapse root "
        "cause; leave unset for production runs (writes are unbatched).",
    )
    return p.parse_args()


async def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    # Silence the very chatty autogen-core message envelope logs so the eval
    # log stays readable (each agent round-trip otherwise produces ~10 KB of
    # INFO-level JSON).  The analysis-relevant info we care about is emitted
    # by the pipeline itself and by __main__ below.
    for noisy in ("autogen_core", "autogen_core.events", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

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
        llm_log_io_path=str(args.log_llm_io) if args.log_llm_io else None,
    )

    if args.only_cves:
        keep = set(args.only_cves)
        before = len(dataset)
        dataset = [c for c in dataset if c.get("cve_id") in keep]
        logger.info(
            "Restricted dataset to %d/%d CVEs via --only-cves: %s",
            len(dataset),
            before,
            sorted(keep),
        )

    # Save run config
    _save_json(vars(args), output_dir / "run_config.json")

    if args.variance:
        logger.info(
            "Running variance analysis (%d repos, %d seeds)",
            args.variance_n,
            len(args.variance_seeds),
        )
        await run_variance_analysis(
            dataset,
            pipeline_cfg,
            args.clone_dir,
            output_dir,
            n_repos=args.variance_n,
            seeds=args.variance_seeds,
        )
    else:
        logger.info(
            "Running main comparison (%d CVEs, arms=%s, k=0..%d, per_cve_timeout=%.0fs, skip=%d)",
            len(dataset),
            args.arms,
            args.max_k,
            args.per_cve_timeout,
            len(args.skip_cves),
        )
        await run_main_comparison(
            dataset,
            pipeline_cfg,
            args.clone_dir,
            output_dir,
            line_tolerance=args.line_tolerance,
            skip_empty_gt=args.skip_empty_gt,
            per_cve_timeout=args.per_cve_timeout,
            skip_cves=args.skip_cves,
        )

    logger.info("Results saved to %s", output_dir)


if __name__ == "__main__":
    asyncio.run(main())
