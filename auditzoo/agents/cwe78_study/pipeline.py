"""Two-arm pipeline orchestrator for the CWE-78 comparative study.

Runs Semgrep and/or Joern arms with k=0..max_iterations, applying
LLM Call 1 (refinement/helper ID) and LLM Call 2 (triage) at each step.
Collects per-iteration metrics for downstream evaluation.
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from autogen_core import AgentId, MessageContext

from auditzoo.backends.ingestion import auto_detect_backend
from auditzoo.core.protocol.requests import Request
from auditzoo.core.runtime import AnalysisRuntime

from .joern_arm import JoernArm
from .llm_client import LLMClient, LLMConfig
from .refinement_agent import RefinementAgent
from .schemas import (
    Finding,
    HelperRole,
    IterationResult,
    RefinementAction,
    RunResult,
    ToolArm,
    Verdict,
)
from .semgrep_arm import SemgrepArm
from .triage_agent import TriageAgent

logger = logging.getLogger(__name__)


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
        llm_model: str = "Qwen/Qwen2.5-Coder-7B-Instruct",
        llm_temperature: float = 0.1,
        llm_api_key: str = "not-needed",
        joern_port: int = 12345,
        call_graph_depth: int = 3,
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
            )
        )
        self._triage = TriageAgent(self._llm)
        self._refinement = RefinementAgent(self._llm)

    async def run(self, repo_path: str | Path, cve_id: str = "") -> RunResult:
        """Run both arms across k=0..max_iterations on *repo_path*."""
        repo_path = str(Path(repo_path).resolve())
        result = RunResult(repo_path=repo_path, cve_id=cve_id)

        if "semgrep" in self._cfg.arms:
            semgrep_iters = await self._run_semgrep_arm(repo_path)
            result.iterations.extend(semgrep_iters)

        if "joern" in self._cfg.arms:
            joern_iters = await self._run_joern_arm(repo_path)
            result.iterations.extend(joern_iters)

        result.metadata["llm_usage"] = self._llm.usage.to_dict()
        return result

    # ------------------------------------------------------------------
    # Semgrep arm iterations
    # ------------------------------------------------------------------

    async def _run_semgrep_arm(self, repo_path: str) -> list[IterationResult]:
        arm = SemgrepArm(context_lines=self._cfg.context_lines)
        results: list[IterationResult] = []

        for k in range(self._cfg.max_iterations + 1):
            t0 = time.perf_counter()
            self._llm.reset_usage()

            findings = arm.scan(repo_path)
            findings = arm.get_findings_with_context(findings)

            triage_results = await self._triage.triage_batch(findings)

            refinement_actions: list[dict[str, Any]] = []
            if k < self._cfg.max_iterations and findings:
                triage_summary = _triage_summary(triage_results)

                fp_findings = [
                    (f, t)
                    for f, t in zip(findings, triage_results)
                    if t.verdict == Verdict.FALSE_POSITIVE
                ]
                if fp_findings:
                    sample_fp, _ = fp_findings[0]
                    ref = await self._refinement.refine_semgrep(
                        rule_yaml=arm.rules_yaml,
                        file_path=sample_fp.file_path,
                        line_number=sample_fp.line_start,
                        code_snippet=sample_fp.surrounding_context or sample_fp.code_snippet,
                        triage_summary=triage_summary,
                    )
                    refinement_actions.append(asdict(ref))
                    arm.apply_refinement(ref.action.value, ref.rule_yaml, ref.target_rule_id)

            elapsed = time.perf_counter() - t0

            results.append(
                IterationResult(
                    arm=ToolArm.SEMGREP,
                    iteration=k,
                    findings=findings,
                    triage_results=triage_results,
                    refinement_actions=refinement_actions,
                    metrics={
                        "wall_clock_s": elapsed,
                        "n_findings": len(findings),
                        "n_tp": sum(1 for t in triage_results if t.verdict == Verdict.TRUE_POSITIVE),
                        "n_fp": sum(1 for t in triage_results if t.verdict == Verdict.FALSE_POSITIVE),
                        "n_uncertain": sum(1 for t in triage_results if t.verdict == Verdict.UNCERTAIN),
                        "llm_usage": self._llm.usage.to_dict(),
                    },
                )
            )

        return results

    # ------------------------------------------------------------------
    # Joern arm iterations
    # ------------------------------------------------------------------

    async def _run_joern_arm(self, repo_path: str) -> list[IterationResult]:
        backend_cfg = auto_detect_backend(
            repo_path, port=self._cfg.joern_port
        )
        results: list[IterationResult] = []

        try:
            async with AnalysisRuntime(backend_cfg) as runtime:
                joern = JoernArm(
                    context_lines=self._cfg.context_lines,
                    call_graph_depth=self._cfg.call_graph_depth,
                )
                await runtime.register_agent(
                    agent_type=JoernArm,
                    agent_name="joern_arm",
                    agent_factory=lambda: joern,
                )
                runtime.start()

                for k in range(self._cfg.max_iterations + 1):
                    t0 = time.perf_counter()
                    self._llm.reset_usage()

                    scan_resp = await runtime.send_message(
                        Request(type="task.joern_scan", payload={}),
                        AgentId("joern_arm", "default"),
                    )
                    raw_findings = scan_resp.data if scan_resp.success else []
                    findings = [
                        Finding(**f) if isinstance(f, dict) else f
                        for f in raw_findings
                    ]
                    findings = joern.get_findings_with_context(findings, repo_path)

                    triage_results = await self._triage.triage_batch(findings)

                    refinement_actions: list[dict[str, Any]] = []
                    if k < self._cfg.max_iterations:
                        for f in findings:
                            if f.sink_api:
                                cg_resp = await runtime.send_message(
                                    Request(
                                        type="task.joern_call_graph",
                                        payload={"sink_method": f.sink_api},
                                    ),
                                    AgentId("joern_arm", "default"),
                                )
                                neighbors = cg_resp.data if cg_resp.success else []
                                if neighbors:
                                    classification = await self._refinement.classify_helpers_joern(
                                        call_graph_neighborhood=neighbors,
                                        current_sources=joern.sources,
                                        current_sinks=joern.sinks,
                                        current_sanitizers=joern.sanitizers,
                                    )
                                    refinement_actions.append(asdict(classification))
                                    new_sources = [
                                        n for n, r in classification.classifications.items()
                                        if r == HelperRole.SOURCE_WRAPPER
                                    ]
                                    new_sinks = [
                                        n for n, r in classification.classifications.items()
                                        if r == HelperRole.SINK_WRAPPER
                                    ]
                                    new_sanitizers = [
                                        n for n, r in classification.classifications.items()
                                        if r == HelperRole.SANITIZER
                                    ]
                                    joern.expand_sources(new_sources)
                                    joern.expand_sinks(new_sinks)
                                    joern.expand_sanitizers(new_sanitizers)
                                    break  # one expansion per iteration

                    elapsed = time.perf_counter() - t0

                    results.append(
                        IterationResult(
                            arm=ToolArm.JOERN,
                            iteration=k,
                            findings=findings,
                            triage_results=triage_results,
                            refinement_actions=refinement_actions,
                            metrics={
                                "wall_clock_s": elapsed,
                                "n_findings": len(findings),
                                "n_tp": sum(1 for t in triage_results if t.verdict == Verdict.TRUE_POSITIVE),
                                "n_fp": sum(1 for t in triage_results if t.verdict == Verdict.FALSE_POSITIVE),
                                "n_uncertain": sum(1 for t in triage_results if t.verdict == Verdict.UNCERTAIN),
                                "llm_usage": self._llm.usage.to_dict(),
                            },
                        )
                    )

        except Exception as exc:
            logger.error("Joern arm failed: %s", exc, exc_info=True)
            if not results:
                results.append(
                    IterationResult(
                        arm=ToolArm.JOERN,
                        iteration=0,
                        metrics={"error": str(exc)},
                    )
                )

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
