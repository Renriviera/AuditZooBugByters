"""Joern arm: CPG-based taint analysis for CWE-78.

Uses the existing AuditZoo Joern backend via ``BaseAnalysisAgent.query_ir``
to run interprocedural taint-reachability queries and call-graph expansion.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from autogen_core import MessageContext

from auditzoo.core.agents import BaseAnalysisAgent
from auditzoo.core.protocol.requests import Request
from auditzoo.core.protocol.responses import Response

from .schemas import Finding, TaintFlow, ToolArm

logger = logging.getLogger(__name__)

_SEED_RULES_DIR = Path(__file__).parent / "seed_rules"


def _load_catalog(name: str) -> list[str]:
    path = _SEED_RULES_DIR / f"{name}.yaml"
    data = yaml.safe_load(path.read_text())
    if name == "sources":
        return [s["pattern"] for s in data.get("sources", [])]
    if name == "sinks":
        return [s["api"] for s in data.get("sinks", [])]
    if name == "sanitizers":
        return [s["api"] for s in data.get("sanitizers", [])]
    return []


class JoernArm(BaseAnalysisAgent):
    """Joern-based taint analysis agent for CWE-78.

    Designed to be registered with :class:`AnalysisRuntime`.  All backend
    access goes through the inherited ``query_ir`` helper.
    """

    def __init__(
        self,
        sources: list[str] | None = None,
        sinks: list[str] | None = None,
        sanitizers: list[str] | None = None,
        context_lines: int = 10,
        call_graph_depth: int = 3,
    ) -> None:
        super().__init__(description="Joern CWE-78 taint analysis arm")
        self._sources = sources if sources is not None else _load_catalog("sources")
        self._sinks = sinks if sinks is not None else _load_catalog("sinks")
        self._sanitizers = sanitizers if sanitizers is not None else _load_catalog("sanitizers")
        self._context_lines = context_lines
        self._call_graph_depth = call_graph_depth

    @property
    def sources(self) -> list[str]:
        return list(self._sources)

    @property
    def sinks(self) -> list[str]:
        return list(self._sinks)

    @property
    def sanitizers(self) -> list[str]:
        return list(self._sanitizers)

    def expand_sources(self, new: list[str]) -> None:
        for s in new:
            if s not in self._sources:
                self._sources.append(s)

    def expand_sinks(self, new: list[str]) -> None:
        for s in new:
            if s not in self._sinks:
                self._sinks.append(s)

    def expand_sanitizers(self, new: list[str]) -> None:
        for s in new:
            if s not in self._sanitizers:
                self._sanitizers.append(s)

    # ------------------------------------------------------------------
    # AutoGen message handler
    # ------------------------------------------------------------------

    async def _handle_request(self, message: Request, ctx: MessageContext) -> Response:
        if message.type == "task.joern_scan":
            findings = await self._run_taint_scan(ctx)
            return Response.ok([f.__dict__ for f in findings])
        if message.type == "task.joern_call_graph":
            sink_method = message.payload.get("sink_method", "")
            depth = message.payload.get("depth", self._call_graph_depth)
            neighbors = await self._expand_call_graph(sink_method, depth, ctx)
            return Response.ok(neighbors)
        return Response.fail(f"Unknown type: {message.type}")

    # ------------------------------------------------------------------
    # Core analysis methods
    # ------------------------------------------------------------------

    async def scan(self, ctx: MessageContext) -> list[Finding]:
        """Run taint reachability query and return findings."""
        return await self._run_taint_scan(ctx)

    async def _run_taint_scan(self, ctx: MessageContext) -> list[Finding]:
        """Execute CPGQL taint queries and parse results into Findings."""
        source_re = "|".join(self._sources)
        sink_re = "|".join(self._sinks)
        query = self._build_taint_query(source_re, sink_re)

        try:
            raw = await self.query_ir(query, response_ty="json", ctx=ctx)
        except RuntimeError as exc:
            logger.error("Joern taint query failed: %s", exc)
            return []

        return self._parse_taint_results(raw)

    async def expand_call_graph(
        self,
        sink_method: str,
        depth: int | None = None,
        ctx: MessageContext | None = None,
    ) -> list[dict[str, Any]]:
        """Query k-hop call-graph neighbourhood of *sink_method*."""
        if ctx is None:
            raise ValueError("MessageContext is required for IR access")
        return await self._expand_call_graph(sink_method, depth or self._call_graph_depth, ctx)

    async def _expand_call_graph(
        self, sink_method: str, depth: int, ctx: MessageContext
    ) -> list[dict[str, Any]]:
        query = (
            f'cpg.method.name("{sink_method}")'
            f".repeat(_.caller)(_.times({depth})).l.map {{ m => "
            f'Map("name" -> m.name, "filename" -> m.filename, '
            f'"lineNumber" -> m.lineNumber.getOrElse(-1).toString, '
            f'"code" -> m.code.take(500)) }}'
        )
        try:
            raw = await self.query_ir(query, response_ty="json", ctx=ctx)
        except RuntimeError as exc:
            logger.error("Call-graph expansion failed: %s", exc)
            return []

        if isinstance(raw, list):
            return raw
        return []

    def get_findings_with_context(
        self, findings: list[Finding], repo_path: str | Path
    ) -> list[Finding]:
        """Enrich findings with surrounding lines from the repo."""
        repo = Path(repo_path)
        enriched: list[Finding] = []
        for f in findings:
            fp = Path(f.file_path)
            if not fp.is_absolute():
                fp = repo / fp
            try:
                lines = fp.read_text().splitlines()
            except OSError:
                enriched.append(f)
                continue
            start = max(0, f.line_start - 1 - self._context_lines)
            end = min(len(lines), f.line_end + self._context_lines)
            ctx = "\n".join(f"{i + 1:>5}| {lines[i]}" for i in range(start, end))
            enriched.append(
                Finding(
                    file_path=f.file_path,
                    line_start=f.line_start,
                    line_end=f.line_end,
                    rule_id=f.rule_id,
                    message=f.message,
                    code_snippet=f.code_snippet,
                    surrounding_context=ctx,
                    sink_api=f.sink_api,
                    arm=f.arm,
                    metadata=f.metadata,
                )
            )
        return enriched

    # ------------------------------------------------------------------
    # CPGQL helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_taint_query(source_re: str, sink_re: str) -> str:
        return (
            f'def sources = cpg.call.name(".*({source_re}).*")\n'
            f'def sinks = cpg.call.name(".*({sink_re}).*")\n'
            "sinks.reachableByFlows(sources).p"
        )

    @staticmethod
    def _parse_taint_results(raw: Any) -> list[Finding]:
        """Convert Joern ``reachableByFlows`` output to Finding objects."""
        if raw is None:
            return []

        findings: list[Finding] = []

        if isinstance(raw, str):
            for block in raw.split("\n\n"):
                block = block.strip()
                if not block:
                    continue
                lines = block.splitlines()
                file_path = ""
                line_start = 0
                sink_api = ""
                for line in lines:
                    parts = line.split("|")
                    if len(parts) >= 3:
                        loc = parts[1].strip()
                        if ":" in loc:
                            fp, ln = loc.rsplit(":", 1)
                            file_path = fp.strip()
                            try:
                                line_start = int(ln.strip())
                            except ValueError:
                                pass
                if file_path:
                    findings.append(
                        Finding(
                            file_path=file_path,
                            line_start=line_start,
                            line_end=line_start,
                            rule_id="joern-taint-reachability",
                            message="Taint flow from source to sink",
                            code_snippet=block,
                            sink_api=sink_api,
                            arm=ToolArm.JOERN,
                        )
                    )

        elif isinstance(raw, list):
            for item in raw:
                if isinstance(item, dict):
                    fp = item.get("filename", item.get("file", ""))
                    ls = item.get("lineNumber", item.get("line", 0))
                    findings.append(
                        Finding(
                            file_path=str(fp),
                            line_start=int(ls) if ls else 0,
                            line_end=int(ls) if ls else 0,
                            rule_id="joern-taint-reachability",
                            message="Taint flow from source to sink",
                            code_snippet=str(item),
                            arm=ToolArm.JOERN,
                            metadata=item,
                        )
                    )
                elif isinstance(item, str):
                    findings.append(
                        Finding(
                            file_path="",
                            line_start=0,
                            line_end=0,
                            rule_id="joern-taint-reachability",
                            message="Taint flow",
                            code_snippet=item,
                            arm=ToolArm.JOERN,
                        )
                    )

        return findings
