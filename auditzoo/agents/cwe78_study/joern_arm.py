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
        query = self._build_taint_query(self._sources, self._sinks)

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
        safe_name = sink_method.replace('"', '\\"')
        query = (
            f'cpg.method.name("{safe_name}")'
            f".repeat(_.caller)(_.maxDepth({depth})).dedup.l.map {{ m => "
            f'Map("name" -> m.name, "filename" -> m.filename, '
            f'"lineNumber" -> m.lineNumber.getOrElse(-1).toString, '
            f'"code" -> m.code.take(500).replace("\\n", " ")) }}.toJson'
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
    def _build_taint_query(sources: list[str], sinks: list[str]) -> str:
        """Build a CPGQL taint-reachability query for the Python Joern frontend.

        The Python frontend stores a call's short name in ``call.name`` (e.g.
        ``"run"`` for ``subprocess.run(...)``) and the fully-qualified string
        only in ``call.code``.  Sources like ``sys.argv`` or ``request.form``
        are ``fieldAccess`` nodes, not calls.  So we:

          * split sink catalog entries ``module.foo`` into a *name set*
            (``{"foo"}``) and a qualified *prefix regex*; match calls whose
            short name is in the set AND whose code starts with the qualified
            form (e.g. ``subprocess.run(...)``).
          * match sources as the union of ``fieldAccess.code`` (attribute
            accesses) and ``call`` whose short name matches a tail token
            (e.g. ``input``, ``getenv``).
          * emit structured JSON records via ``.toJson`` so the backend's
            JSON parser succeeds even for empty results (``"[]"``).
        """
        def _escape(s: str) -> str:
            return s.replace("\\", "\\\\").replace("\"", "\\\"").replace(".", "\\.")

        sink_names = sorted({s.rsplit(".", 1)[-1] for s in sinks if s})
        sink_prefix_re = "(?s)^(" + "|".join(_escape(s) for s in sinks) + ")\\(.*"
        sink_names_scala = ",".join(f'"{n}"' for n in sink_names)

        source_tokens = [s for s in sources if s]
        source_code_re = "(?s).*(" + "|".join(_escape(s) for s in source_tokens) + ").*"
        # Calls whose *short* name matches the last segment of the source pattern.
        # E.g. "input", "getenv" are callables; attribute reads remain field accesses.
        source_call_tails = sorted({
            s.rsplit(".", 1)[-1]
            for s in source_tokens
            if "." not in s or s.rsplit(".", 1)[-1] in {"getenv", "input"}
        })
        source_call_names_scala = ",".join(f'"{n}"' for n in source_call_tails)

        # Single-expression query: the CPGQL server echoes *every* top-level
        # val binding, so we inline everything into one chained call whose
        # final result (a JSON string) is the only value the REPL prints.
        return (
            "cpg.call"
            f".filter(c => Set({sink_names_scala}).contains(c.name))"
            f'.code("""{sink_prefix_re}""").iterator'
            ".reachableByFlows("
            "(cpg.fieldAccess"
            f'.code("""{source_code_re}""").l ++ '
            "cpg.call"
            f".filter(c => Set({source_call_names_scala}).contains(c.name)).l"
            ").iterator"
            ").l.map { f => Map("
            '"sinkLine"   -> f.elements.last.lineNumber.getOrElse(-1).toString, '
            '"sinkFile"   -> f.elements.last.file.name.headOption.getOrElse(""), '
            '"sinkCode"   -> f.elements.last.code.take(300).replace("\\n", " "), '
            '"sinkName"   -> (f.elements.last match { '
            "case c: io.shiftleft.codepropertygraph.generated.nodes.Call => c.name; "
            'case _ => "" }), '
            '"sourceLine" -> f.elements.head.lineNumber.getOrElse(-1).toString, '
            '"sourceFile" -> f.elements.head.file.name.headOption.getOrElse(""), '
            '"sourceCode" -> f.elements.head.code.take(200).replace("\\n", " ")'
            ") }.toJson"
        )

    @staticmethod
    def _parse_taint_results(raw: Any) -> list[Finding]:
        """Convert the JSON records produced by ``_build_taint_query`` to Findings."""
        if not raw:
            return []
        if not isinstance(raw, list):
            return []

        findings: list[Finding] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            fp = str(item.get("sinkFile", ""))
            try:
                ls = int(item.get("sinkLine", 0))
            except (TypeError, ValueError):
                ls = 0
            findings.append(
                Finding(
                    file_path=fp,
                    line_start=ls,
                    line_end=ls,
                    rule_id="joern-taint-reachability",
                    message=(
                        f"Taint flow: {item.get('sourceCode', '')} "
                        f"-> {item.get('sinkCode', '')}"
                    ),
                    code_snippet=str(item.get("sinkCode", "")),
                    sink_api=str(item.get("sinkName", "")),
                    arm=ToolArm.JOERN,
                    metadata=item,
                )
            )

        return findings
