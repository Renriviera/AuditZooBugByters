"""Two-arm pipeline orchestrator for the CWE-78 comparative study.

Runs Semgrep and/or Joern arms with k=0..max_iterations, applying
LLM Call 1 (refinement/helper ID) and LLM Call 2 (triage) at each step.
Collects per-iteration metrics for downstream evaluation.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Any

from autogen_core import AgentId

from auditzoo.backends.ingestion import auto_detect_backend
from auditzoo.core.protocol.requests import Request
from auditzoo.core.runtime import AnalysisRuntime

from .cpg_cache import (
    cpg_cache_location,
    detect_repo_metadata,
    is_cache_hit,
    write_cache_metadata,
)
from .joern_arm import JoernArm
from .llm_client import LLMClient, LLMConfig
from .refinement_agent import RefinementAgent
from .schemas import (
    Finding,
    HelperRole,
    IterationResult,
    RunResult,
    ToolArm,
    Verdict,
)
from .semgrep_arm import SemgrepArm
from .triage_agent import TriageAgent

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------
# Phase-timing helpers
# ----------------------------------------------------------------------

_PHASE_KEYS: tuple[str, ...] = (
    "cpg_build_s",
    "scan_s",
    "llm_triage_s",
    "llm_refinement_s",
    "call_graph_s",
)


@contextmanager
def _stopwatch() -> Iterator[list[float]]:
    """Context manager yielding a 1-element list holding elapsed seconds.

    The elapsed time is written into ``holder[0]`` on exit so it can be
    inspected after the ``with`` block.  Using a list keeps the caller code
    readable without relying on closure tricks::

        with _stopwatch() as t:
            ...work...
        scan_s = t[0]
    """
    holder: list[float] = [0.0]
    start = time.perf_counter()
    try:
        yield holder
    finally:
        holder[0] = time.perf_counter() - start


def _llm_tokens_delta(before: dict[str, int], after: dict[str, int]) -> int:
    """Return the total-token delta between two ``LLMUsage.to_dict()`` snapshots."""
    return int(after.get("total_tokens", 0)) - int(before.get("total_tokens", 0))


def _stable_hash(payload: str) -> str:
    """Short, stable SHA-256 prefix for audit fingerprints (not security-critical)."""
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()[:16]


def _findings_hash(findings: list[Finding]) -> str:
    """Hash the sorted ``(file, line, rule_id, sink_api)`` tuples of *findings*.

    Used to quantify whether consecutive k iterations produce identical
    candidate sets (which would prove refinement never moved the needle).
    """
    keys = sorted(
        f"{f.file_path}:{f.line_start}:{f.rule_id}:{f.sink_api}" for f in findings
    )
    return _stable_hash("\n".join(keys))


async def _connect_joern_with_retry(
    backend_cfg: Any,
    *,
    max_retries: int = 1,
    retry_delay_s: float = 5.0,
):
    """Enter :class:`AnalysisRuntime` with one retry on transient errors.

    The full-run log from 20260419_135557 shows 100% of Joern arms failing
    with ``Port localhost:12345 is already in use`` because the previous
    CVE's JVM had not released the port yet.  Retrying once after a short
    pause converts most of those into successful CPG builds; the rest
    surface as an explicit ``cpg_build_failed`` column on the iteration
    instead of silently aggregating to ``tp/fp/fn = 0``.

    Returns ``(runtime_cm, runtime, last_error)`` where ``runtime`` is
    ``None`` on failure.
    """
    last_exc: BaseException | None = None
    runtime_cm: Any = None
    for attempt in range(max_retries + 1):
        runtime_cm = AnalysisRuntime(backend_cfg)
        try:
            runtime = await runtime_cm.__aenter__()
            return runtime_cm, runtime, None
        except Exception as exc:
            last_exc = exc
            logger.warning(
                "Joern CPG connect attempt %d/%d failed: %s",
                attempt + 1,
                max_retries + 1,
                exc,
            )
            try:
                await runtime_cm.stop()
            except Exception:
                logger.exception("Cleanup during Joern retry failed")
            if attempt < max_retries:
                await asyncio.sleep(retry_delay_s)
    return runtime_cm, None, last_exc


def _joern_catalog_snapshot(joern: Any) -> dict[str, list[str]]:
    """Snapshot a :class:`JoernArm`'s source/sink/sanitizer catalogs for audit."""
    return {
        "sources": list(getattr(joern, "sources", []) or []),
        "sinks": list(getattr(joern, "sinks", []) or []),
        "sanitizers": list(getattr(joern, "sanitizers", []) or []),
    }


def build_phase_metrics(
    *,
    wall_clock_s: float,
    n_findings: int,
    n_tp: int,
    n_fp: int,
    n_uncertain: int,
    llm_usage: dict[str, int],
    cpg_build_s: float = 0.0,
    scan_s: float = 0.0,
    llm_triage_s: float = 0.0,
    llm_refinement_s: float = 0.0,
    call_graph_s: float = 0.0,
    llm_tokens_triage: int = 0,
    llm_tokens_refinement: int = 0,
) -> dict[str, Any]:
    """Build the per-iteration metrics dict with phase-level attribution.

    ``overhead_s`` captures residual wall time (Python glue, context
    loading, snippet enrichment, agent-message marshalling) not attributed
    to any named phase; it is clamped to zero to hide minor clock skew.

    All phase timings are in seconds. Token counts are cumulative totals
    for the iteration; ``llm_tokens_triage`` and ``llm_tokens_refinement``
    are the subtotals used by the triage and refinement LLM calls
    respectively.
    """
    attributed = cpg_build_s + scan_s + llm_triage_s + llm_refinement_s + call_graph_s
    overhead_s = max(0.0, wall_clock_s - attributed)
    return {
        "wall_clock_s": wall_clock_s,
        "cpg_build_s": cpg_build_s,
        "scan_s": scan_s,
        "llm_triage_s": llm_triage_s,
        "llm_refinement_s": llm_refinement_s,
        "call_graph_s": call_graph_s,
        "overhead_s": overhead_s,
        "n_findings": n_findings,
        "n_tp": n_tp,
        "n_fp": n_fp,
        "n_uncertain": n_uncertain,
        "llm_usage": llm_usage,
        "llm_tokens_triage": llm_tokens_triage,
        "llm_tokens_refinement": llm_tokens_refinement,
    }


def _log_phase_breakdown(
    *, cve_id: str, arm: str, k: int, metrics: dict[str, Any]
) -> None:
    """Emit a compact INFO line summarising phase timings for one iteration."""
    logger.info(
        "[%s | %s k=%d] cpg=%.2fs scan=%.2fs triage=%.2fs refine=%.2fs "
        "cg=%.2fs overhead=%.2fs total=%.2fs findings=%d "
        "tok_triage=%d tok_refine=%d",
        cve_id or "-",
        arm,
        k,
        metrics["cpg_build_s"],
        metrics["scan_s"],
        metrics["llm_triage_s"],
        metrics["llm_refinement_s"],
        metrics["call_graph_s"],
        metrics["overhead_s"],
        metrics["wall_clock_s"],
        metrics["n_findings"],
        metrics["llm_tokens_triage"],
        metrics["llm_tokens_refinement"],
    )


class PipelineConfig:
    """Pipeline configuration (typically populated from Hydra YAML)."""

    def __init__(
        self,
        *,
        max_iterations: int = 3,
        seed: int = 235711,
        context_lines: int = 10,
        max_context_tokens: int = 2000,
        arms: list[str] | None = None,
        llm_base_url: str = "http://localhost:8000/v1",
        llm_model: str = "gpt-5.4-mini",
        llm_temperature: float = 0.1,
        llm_api_key: str = "not-needed",
        joern_port: int = 12345,
        call_graph_depth: int = 3,
        llm_log_io_path: str | None = None,
        semgrep_rules_yaml: str | None = None,
        joern_sources: list[str] | None = None,
        joern_sinks: list[str] | None = None,
        joern_sanitizers: list[str] | None = None,
        cpg_cache_dir: str | Path | None = None,
    ) -> None:
        self.max_iterations = max_iterations
        self.seed = seed
        self.context_lines = context_lines
        self.max_context_tokens = max_context_tokens
        self.arms = arms or ["semgrep", "joern"]
        self.llm_base_url = llm_base_url
        self.llm_model = llm_model
        self.llm_temperature = llm_temperature
        self.llm_api_key = llm_api_key
        self.joern_port = joern_port
        self.call_graph_depth = call_graph_depth
        self.llm_log_io_path = llm_log_io_path
        self.semgrep_rules_yaml = semgrep_rules_yaml
        self.joern_sources = list(joern_sources) if joern_sources is not None else None
        self.joern_sinks = list(joern_sinks) if joern_sinks is not None else None
        self.joern_sanitizers = (
            list(joern_sanitizers) if joern_sanitizers is not None else None
        )
        # When set, every Joern run uses ``<cpg_cache_dir>/<sha256(...)>``
        # as the analysis workspace.  The Joern client checks
        # ``workspace.projects.exists(_.name == project_name)`` and skips
        # importCode on a hit — turning second-and-later runs of the
        # same (repo, commit) pair into a near-instant ``open()``.
        self.cpg_cache_dir = Path(cpg_cache_dir) if cpg_cache_dir else None


class Pipeline:
    """Orchestrates the two-arm comparative analysis."""

    def __init__(self, config: PipelineConfig) -> None:
        self._cfg = config
        self._llm = LLMClient(
            LLMConfig(
                base_url=config.llm_base_url,
                model=config.llm_model,
                temperature=config.llm_temperature,
                api_key=config.llm_api_key,
                seed=config.seed,
                log_io_path=config.llm_log_io_path,
            )
        )
        self._triage = TriageAgent(self._llm)
        self._refinement = RefinementAgent(self._llm)

    async def run(self, repo_path: str | Path, cve_id: str = "") -> RunResult:
        """Run both arms across k=0..max_iterations on *repo_path*."""
        repo_path = str(Path(repo_path).resolve())
        result = RunResult(repo_path=repo_path, cve_id=cve_id)

        if "semgrep" in self._cfg.arms:
            semgrep_iters = await self._run_semgrep_arm(repo_path, cve_id=cve_id)
            result.iterations.extend(semgrep_iters)

        if "joern" in self._cfg.arms:
            joern_iters = await self._run_joern_arm(repo_path, cve_id=cve_id)
            result.iterations.extend(joern_iters)

        result.metadata["llm_usage"] = self._llm.usage.to_dict()
        return result

    # ------------------------------------------------------------------
    # Semgrep arm iterations
    # ------------------------------------------------------------------

    async def _run_semgrep_arm(
        self, repo_path: str, *, cve_id: str = ""
    ) -> list[IterationResult]:
        arm = SemgrepArm(
            rules_yaml=self._cfg.semgrep_rules_yaml,
            context_lines=self._cfg.context_lines,
        )
        results: list[IterationResult] = []

        for k in range(self._cfg.max_iterations + 1):
            t0 = time.perf_counter()
            self._llm.reset_usage()

            rules_yaml_pre = arm.rules_yaml
            rules_hash_pre = _stable_hash(rules_yaml_pre)

            with _stopwatch() as scan_t:
                findings = arm.scan(repo_path)
                findings = arm.get_findings_with_context(findings)

            tokens_before_triage = self._llm.usage.to_dict()
            with _stopwatch() as triage_t:
                triage_results = await self._triage.triage_batch(findings)
            tokens_after_triage = self._llm.usage.to_dict()
            llm_tokens_triage = _llm_tokens_delta(
                tokens_before_triage, tokens_after_triage
            )

            refinement_actions: list[dict[str, Any]] = []
            refinement_s = 0.0
            llm_tokens_refinement = 0
            if k < self._cfg.max_iterations and findings:
                triage_summary = _triage_summary(triage_results)

                # Previously refinement only fired when at least one triage
                # verdict was FALSE_POSITIVE.  Because the triage LLM almost
                # always returned UNCERTAIN (see Phase-A audit) that gate
                # was effectively dead and Semgrep rules never mutated
                # across k=0..3.  We now always invoke refinement with the
                # full triage batch; the LLM itself decides between
                # ``keep`` / ``refine`` / ``add_rule`` and ``keep`` remains
                # the safe default on any parsing error
                # (see RefinementAgent.refine_semgrep).
                sample = _pick_refinement_target(findings, triage_results)
                tokens_before_ref = self._llm.usage.to_dict()
                with _stopwatch() as refine_t:
                    ref = await self._refinement.refine_semgrep(
                        rule_yaml=arm.rules_yaml,
                        file_path=sample.file_path,
                        line_number=sample.line_start,
                        code_snippet=sample.surrounding_context or sample.code_snippet,
                        triage_summary=triage_summary,
                    )
                    apply_status = arm.apply_refinement(
                        ref.action.value, ref.rule_yaml, ref.target_rule_id
                    )
                    action_dict = asdict(ref)
                    action_dict["apply_status"] = apply_status
                    refinement_actions.append(action_dict)
                refinement_s = refine_t[0]
                llm_tokens_refinement = _llm_tokens_delta(
                    tokens_before_ref, self._llm.usage.to_dict()
                )

            elapsed = time.perf_counter() - t0

            metrics = build_phase_metrics(
                wall_clock_s=elapsed,
                scan_s=scan_t[0],
                llm_triage_s=triage_t[0],
                llm_refinement_s=refinement_s,
                n_findings=len(findings),
                n_tp=sum(
                    1 for t in triage_results if t.verdict == Verdict.TRUE_POSITIVE
                ),
                n_fp=sum(
                    1 for t in triage_results if t.verdict == Verdict.FALSE_POSITIVE
                ),
                n_uncertain=sum(
                    1 for t in triage_results if t.verdict == Verdict.UNCERTAIN
                ),
                llm_usage=self._llm.usage.to_dict(),
                llm_tokens_triage=llm_tokens_triage,
                llm_tokens_refinement=llm_tokens_refinement,
            )
            rules_yaml_post = arm.rules_yaml
            metrics["rules_hash_pre"] = rules_hash_pre
            metrics["rules_hash_post"] = _stable_hash(rules_yaml_post)
            metrics["rules_yaml_bytes_pre"] = len(rules_yaml_pre)
            metrics["rules_yaml_bytes_post"] = len(rules_yaml_post)
            metrics["rules_yaml_changed"] = rules_yaml_pre != rules_yaml_post
            metrics["findings_hash"] = _findings_hash(findings)
            _log_phase_breakdown(cve_id=cve_id, arm="semgrep", k=k, metrics=metrics)

            results.append(
                IterationResult(
                    arm=ToolArm.SEMGREP,
                    iteration=k,
                    findings=findings,
                    triage_results=triage_results,
                    refinement_actions=refinement_actions,
                    metrics=metrics,
                )
            )

        return results

    # ------------------------------------------------------------------
    # Joern arm iterations
    # ------------------------------------------------------------------

    async def _run_joern_arm(
        self, repo_path: str, *, cve_id: str = ""
    ) -> list[IterationResult]:
        # Resolve a stable workspace + project name from the CPG cache
        # whenever caching is configured.  When repo metadata is missing
        # (eg. a non-git directory) we fall back to the default
        # ``<repo>/.auditzoo`` so caching is a transparent improvement,
        # never a regression.
        cache_meta: dict[str, Any] = {"cpg_cache_enabled": False}
        analysis_path: str | None = None
        project_name: str | None = None
        cache_loc = None
        if self._cfg.cpg_cache_dir is not None:
            repo_url, commit = detect_repo_metadata(repo_path)
            if repo_url and commit:
                cache_loc = cpg_cache_location(
                    self._cfg.cpg_cache_dir,
                    repo_url=repo_url,
                    commit=commit,
                )
                cache_loc.workspace_dir.mkdir(parents=True, exist_ok=True)
                analysis_path = str(cache_loc.workspace_dir)
                project_name = cache_loc.project_name
                hit = is_cache_hit(cache_loc)
                cache_meta = {
                    "cpg_cache_enabled": True,
                    "cpg_cache_key": cache_loc.cache_key,
                    "cpg_cache_dir": str(cache_loc.workspace_dir),
                    "cpg_cache_hit": hit,
                    "cpg_repo_url": repo_url,
                    "cpg_commit": commit,
                }
                logger.info(
                    "[%s | joern] CPG cache %s key=%s dir=%s",
                    cve_id or "-",
                    "HIT" if hit else "MISS",
                    cache_loc.cache_key,
                    cache_loc.workspace_dir,
                )
            else:
                logger.warning(
                    "[%s | joern] CPG cache disabled — could not detect "
                    "repo_url/commit at %s",
                    cve_id or "-",
                    repo_path,
                )

        backend_cfg = auto_detect_backend(
            repo_path,
            port=self._cfg.joern_port,
            analysis_path=analysis_path,
            project_name=project_name,
        )
        results: list[IterationResult] = []

        # CPG construction happens inside AnalysisRuntime.__aenter__
        # (backend.connect -> joern import + workspace load).  We time it
        # directly with perf_counter so the failure path still reports a
        # meaningful partial duration.  On transient failures (notably
        # "port already in use" when the previous CVE's JVM was still
        # releasing the port) we retry once after a short pause.
        cpg_start = time.perf_counter()
        runtime_cm, runtime, cpg_error = await _connect_joern_with_retry(backend_cfg)
        if runtime is None:
            cpg_build_s_total = time.perf_counter() - cpg_start
            logger.error(
                "Joern arm failed during CPG build after %.2fs (with retry): %s",
                cpg_build_s_total,
                cpg_error,
                exc_info=cpg_error is not None,
            )
            if runtime_cm is not None:
                try:
                    await runtime_cm.stop()
                except Exception:
                    logger.exception(
                        "AnalysisRuntime cleanup after __aenter__ failure failed"
                    )
            return [
                IterationResult(
                    arm=ToolArm.JOERN,
                    iteration=0,
                    metrics={
                        "error": str(cpg_error) if cpg_error else "unknown CPG error",
                        "error_type": (
                            type(cpg_error).__name__ if cpg_error else "unknown"
                        ),
                        "cpg_build_s": cpg_build_s_total,
                        "cpg_build_failed": True,
                    },
                )
            ]
        cpg_build_s_total = time.perf_counter() - cpg_start

        try:
            joern_holder: list[JoernArm] = []

            def _joern_factory() -> JoernArm:
                inst = JoernArm(
                    sources=self._cfg.joern_sources,
                    sinks=self._cfg.joern_sinks,
                    sanitizers=self._cfg.joern_sanitizers,
                    context_lines=self._cfg.context_lines,
                    call_graph_depth=self._cfg.call_graph_depth,
                )
                joern_holder.append(inst)
                return inst

            await runtime.register_agent(
                agent_type=JoernArm,
                agent_name="joern_arm",
                agent_factory=_joern_factory,
            )
            runtime.start()

            for k in range(self._cfg.max_iterations + 1):
                t0 = time.perf_counter()
                self._llm.reset_usage()
                # CPG build cost is a one-shot, amortise onto k=0 only.
                cpg_build_s = cpg_build_s_total if k == 0 else 0.0

                joern = joern_holder[0] if joern_holder else None
                catalog_pre = _joern_catalog_snapshot(joern) if joern else {}

                with _stopwatch() as scan_t:
                    scan_resp = await runtime.send_message(
                        Request(type="task.joern_scan", payload={}),
                        AgentId("joern_arm", "default"),
                    )
                    raw_findings = scan_resp.data if scan_resp.success else []
                    findings = [
                        Finding(**f) if isinstance(f, dict) else f for f in raw_findings
                    ]
                    joern = joern_holder[0]
                    findings = joern.get_findings_with_context(findings, repo_path)

                tokens_before_triage = self._llm.usage.to_dict()
                with _stopwatch() as triage_t:
                    triage_results = await self._triage.triage_batch(findings)
                llm_tokens_triage = _llm_tokens_delta(
                    tokens_before_triage, self._llm.usage.to_dict()
                )

                refinement_actions: list[dict[str, Any]] = []
                call_graph_s = 0.0
                refinement_s = 0.0
                llm_tokens_refinement = 0

                if k < self._cfg.max_iterations:
                    for f in findings:
                        if not f.sink_api:
                            continue
                        with _stopwatch() as cg_t:
                            cg_resp = await runtime.send_message(
                                Request(
                                    type="task.joern_call_graph",
                                    payload={"sink_method": f.sink_api},
                                ),
                                AgentId("joern_arm", "default"),
                            )
                        call_graph_s += cg_t[0]
                        neighbors = cg_resp.data if cg_resp.success else []
                        if not neighbors:
                            continue
                        tokens_before_ref = self._llm.usage.to_dict()
                        with _stopwatch() as refine_t:
                            classification = (
                                await self._refinement.classify_helpers_joern(
                                    call_graph_neighborhood=neighbors,
                                    current_sources=joern.sources,
                                    current_sinks=joern.sinks,
                                    current_sanitizers=joern.sanitizers,
                                )
                            )
                            refinement_actions.append(asdict(classification))
                            new_sources = [
                                n
                                for n, r in classification.classifications.items()
                                if r == HelperRole.SOURCE_WRAPPER
                            ]
                            new_sinks = [
                                n
                                for n, r in classification.classifications.items()
                                if r == HelperRole.SINK_WRAPPER
                            ]
                            new_sanitizers = [
                                n
                                for n, r in classification.classifications.items()
                                if r == HelperRole.SANITIZER
                            ]
                            joern.expand_sources(new_sources)
                            joern.expand_sinks(new_sinks)
                            joern.expand_sanitizers(new_sanitizers)
                        refinement_s += refine_t[0]
                        llm_tokens_refinement += _llm_tokens_delta(
                            tokens_before_ref, self._llm.usage.to_dict()
                        )
                        break  # one expansion per iteration

                elapsed = time.perf_counter() - t0

                metrics = build_phase_metrics(
                    wall_clock_s=elapsed + cpg_build_s,
                    cpg_build_s=cpg_build_s,
                    scan_s=scan_t[0],
                    llm_triage_s=triage_t[0],
                    llm_refinement_s=refinement_s,
                    call_graph_s=call_graph_s,
                    n_findings=len(findings),
                    n_tp=sum(
                        1 for t in triage_results if t.verdict == Verdict.TRUE_POSITIVE
                    ),
                    n_fp=sum(
                        1 for t in triage_results if t.verdict == Verdict.FALSE_POSITIVE
                    ),
                    n_uncertain=sum(
                        1 for t in triage_results if t.verdict == Verdict.UNCERTAIN
                    ),
                    llm_usage=self._llm.usage.to_dict(),
                    llm_tokens_triage=llm_tokens_triage,
                    llm_tokens_refinement=llm_tokens_refinement,
                )
                catalog_post = _joern_catalog_snapshot(joern)
                metrics["joern_catalog_pre"] = catalog_pre
                metrics["joern_catalog_post"] = catalog_post
                metrics["joern_catalog_grew"] = (
                    len(catalog_post.get("sources", []))
                    > len(catalog_pre.get("sources", []))
                    or len(catalog_post.get("sinks", []))
                    > len(catalog_pre.get("sinks", []))
                    or len(catalog_post.get("sanitizers", []))
                    > len(catalog_pre.get("sanitizers", []))
                )
                metrics["findings_hash"] = _findings_hash(findings)
                metrics.update(cache_meta)
                _log_phase_breakdown(cve_id=cve_id, arm="joern", k=k, metrics=metrics)

                results.append(
                    IterationResult(
                        arm=ToolArm.JOERN,
                        iteration=k,
                        findings=findings,
                        triage_results=triage_results,
                        refinement_actions=refinement_actions,
                        metrics=metrics,
                    )
                )

        except Exception as exc:
            logger.error("Joern arm failed: %s", exc, exc_info=True)
            if not results:
                results.append(
                    IterationResult(
                        arm=ToolArm.JOERN,
                        iteration=0,
                        metrics={"error": str(exc), "cpg_build_s": cpg_build_s_total},
                    )
                )
        finally:
            try:
                await runtime_cm.__aexit__(None, None, None)
            except Exception:  # pragma: no cover - best-effort cleanup
                logger.exception("AnalysisRuntime cleanup failed")
            # Always drop a breadcrumb (even on error) so the cache
            # directory has an audit trail; the next run still sees the
            # CPG via ``is_cache_hit`` if Joern persisted ``cpg.bin``
            # before the failure.
            if cache_loc is not None:
                try:
                    write_cache_metadata(
                        cache_loc,
                        cve_id=cve_id,
                        last_run_at=time.time(),
                    )
                except Exception:  # pragma: no cover - best-effort breadcrumb
                    logger.exception("CPG cache metadata write failed")

        return results


def _triage_summary(triage_results: list[Any]) -> dict[str, int]:
    summary: dict[str, int] = {"tp": 0, "fp": 0, "uncertain": 0}
    for t in triage_results:
        if t.verdict == Verdict.TRUE_POSITIVE:
            summary["tp"] += 1
        elif t.verdict == Verdict.FALSE_POSITIVE:
            summary["fp"] += 1
        else:
            summary["uncertain"] += 1
    return summary


def _pick_refinement_target(
    findings: list[Finding],
    triage_results: list[Any],
) -> Finding:
    """Choose the most informative finding to anchor LLM refinement.

    Priority order (falls through to the next if none match):

      1. A ``FALSE_POSITIVE`` — the LLM already flagged it, so refining
         the rule around it directly improves precision.
      2. An ``UNCERTAIN`` — ambiguous cases benefit most from rule
         tightening / widening.
      3. Any ``TRUE_POSITIVE`` — expose the rule to a known-good match so
         the LLM can propose complementary ``add_rule`` suggestions.
      4. First finding as an unconditional fallback.
    """
    pairs = list(zip(findings, triage_results, strict=False))
    for verdict in (Verdict.FALSE_POSITIVE, Verdict.UNCERTAIN, Verdict.TRUE_POSITIVE):
        for f, t in pairs:
            if t.verdict == verdict:
                return f
    return findings[0]
