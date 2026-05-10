"""Joern arm: CPG-based taint analysis for CWE-78.

Uses the existing AuditZoo Joern backend via ``BaseAnalysisAgent.query_ir``
to run interprocedural taint-reachability queries and call-graph expansion.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

import yaml
from autogen_core import MessageContext

from auditzoo.core.agents import BaseAnalysisAgent
from auditzoo.core.protocol.requests import Request
from auditzoo.core.protocol.responses import Response

from .catalog_sanitizer import sanitize_catalog
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
        raw_sources = sources if sources is not None else _load_catalog("sources")
        raw_sinks = sinks if sinks is not None else _load_catalog("sinks")
        raw_sanitizers = (
            sanitizers if sanitizers is not None else _load_catalog("sanitizers")
        )
        # Defence-in-depth: even if seed parsing already cleaned these, a
        # caller (or a per-iteration ``expand_*`` call below) may inject
        # raw strings.  Always sanitise — drops regex-unsafe entries, dedups,
        # and logs anything thrown out.
        self._sources, _ = sanitize_catalog(raw_sources, label="joern sources")
        self._sinks, _ = sanitize_catalog(raw_sinks, label="joern sinks")
        self._sanitizers, _ = sanitize_catalog(raw_sanitizers, label="joern sanitizers")
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
        cleaned, _ = sanitize_catalog(new, label="joern sources (expand)")
        for s in cleaned:
            if s not in self._sources:
                self._sources.append(s)

    def expand_sinks(self, new: list[str]) -> None:
        cleaned, _ = sanitize_catalog(new, label="joern sinks (expand)")
        for s in cleaned:
            if s not in self._sinks:
                self._sinks.append(s)

    def expand_sanitizers(self, new: list[str]) -> None:
        cleaned, _ = sanitize_catalog(new, label="joern sanitizers (expand)")
        for s in cleaned:
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
        if message.type == "task.joern_direct_sink_scan":
            raw = await self._run_direct_sink_scan(ctx)
            return Response.ok(raw)
        if message.type == "task.joern_relaxed_taint_scan":
            raw = await self._run_relaxed_taint_scan(ctx)
            return Response.ok(raw)
        if message.type == "task.joern_def_use_chase":
            raw = await self._run_def_use_chase(ctx)
            return Response.ok(raw)
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

    async def _run_direct_sink_scan(self, ctx: MessageContext) -> list[dict[str, Any]]:
        """Execute CPGQL direct-sink query; returns raw JSON records.

        The pipeline merges the raw lists returned by every recovery
        pass into a single :meth:`_parse_taint_results` call so dedup
        is global across passes (taint vs direct-sink vs relaxed).
        Returning raw rather than parsed Findings keeps that contract
        intact.
        """
        cap = self._DIRECT_SINK_CAP_PER_FILE * 50  # global cap, generous
        query = self._build_direct_sink_query(self._sinks, cap)
        try:
            raw = await self.query_ir(query, response_ty="json", ctx=ctx)
        except RuntimeError as exc:
            logger.error("Joern direct-sink scan failed: %s", exc)
            return []
        if isinstance(raw, list):
            return raw
        return []

    async def _run_relaxed_taint_scan(self, ctx: MessageContext) -> list[dict[str, Any]]:
        """Execute CPGQL relaxed-taint query; returns raw JSON records."""
        query = self._build_relaxed_taint_query(
            self._sources, self._sinks, self._RELAXED_TAINT_CAP
        )
        try:
            raw = await self.query_ir(query, response_ty="json", ctx=ctx)
        except RuntimeError as exc:
            logger.error("Joern relaxed-taint scan failed: %s", exc)
            return []
        if isinstance(raw, list):
            return raw
        return []

    async def _run_def_use_chase(self, ctx: MessageContext) -> list[dict[str, Any]]:
        """Execute CPGQL def-use chase query; returns raw JSON records."""
        query = self._build_def_use_chase_query(self._sinks, self._DEF_USE_CHASE_CAP)
        try:
            raw = await self.query_ir(query, response_ty="json", ctx=ctx)
        except RuntimeError as exc:
            logger.error("Joern def-use chase failed: %s", exc)
            return []
        if isinstance(raw, list):
            return raw
        return []

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
        """Return k-hop callers of *sink_method* with body + callee evidence.

        The previous query returned only ``name``, ``filename``,
        ``lineNumber``, and a 500-char ``code`` excerpt.  Refinement
        (``classify_helpers_joern``) needs more structural evidence
        before we let the LLM blindly promote a wrapper into the sink
        catalog, so we also surface:

          * ``callees`` — the de-duplicated short names of methods this
            method calls (capped at 50 entries for prompt budget).
            Used by ``verify_sink_wrapper`` to require that a claimed
            sink-wrapper actually invokes a known sink primitive.
          * ``code`` extended to 1500 chars to give the LLM enough body
            to cite a specific evidence expression.
        """
        safe_name = sink_method.replace('"', '\\"')
        query = (
            f'cpg.method.name("{safe_name}")'
            f".repeat(_.caller)(_.maxDepth({depth})).dedup.l.map {{ m => "
            f'Map("name" -> m.name, "filename" -> m.filename, '
            f'"lineNumber" -> m.lineNumber.getOrElse(-1).toString, '
            f'"code" -> m.code.take(1500).replace("\\n", " "), '
            f'"callees" -> m.callee.name.dedup.l.take(50)) }}.toJson'
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

    # Per-pass output caps to bound prompt cost downstream.  The strict
    # taint pass already implicitly bounds candidates via reachability;
    # the recovery passes (direct-sink, relaxed-taint, def-use chase) are
    # broader, so they need explicit ``.take(N)`` ceilings in the CPGQL
    # query.
    _DIRECT_SINK_CAP_PER_FILE: int = 25
    _RELAXED_TAINT_CAP: int = 200
    _DEF_USE_CHASE_CAP: int = 200

    @staticmethod
    def _safe_union(entries: list[str], *, kind: str) -> str:
        """Return a regex alternation of ``re.escape`` (entries) that compiles.

        Entries that fail to compile (post-escape) are dropped with a
        log line; the surviving union is what gets sent to Joern.
        Returning the empty string is left to the caller to handle —
        we never inject a syntactically invalid regex into the CPGQL.
        """
        survivors: list[str] = []
        for raw in entries:
            if not raw:
                continue
            escaped = re.escape(raw)
            try:
                re.compile(escaped)
            except re.error as exc:
                logger.warning(
                    "Dropping %s entry %r: regex compile failed (%s)",
                    kind,
                    raw,
                    exc,
                )
                continue
            survivors.append(escaped)
        return "|".join(survivors)

    @classmethod
    def _build_sink_filter(cls, sinks: list[str]) -> tuple[str, str]:
        """Return ``(sink_names_scala_list, sink_prefix_regex)`` for *sinks*.

        Both strings are safe to splice into a CPGQL Scala literal.  The
        names list is used inside ``Set(...)`` for short-name membership
        and the prefix regex is what we feed to ``.code(...)`` to require
        a qualified call expression.
        """
        sink_names = sorted({s.rsplit(".", 1)[-1] for s in sinks if s})
        sink_union = cls._safe_union(list(sinks), kind="sink")
        sink_prefix_re = (
            f"(?s)^(?:{sink_union})(?:[^A-Za-z0-9_].*)?$" if sink_union else "(?!x)x"
        )
        try:
            re.compile(sink_prefix_re)
        except re.error as exc:
            logger.error("sink_prefix_re failed compile, neutralising: %s", exc)
            sink_prefix_re = "(?!x)x"
        sink_names_scala = ",".join(f'"{n}"' for n in sink_names)
        return sink_names_scala, sink_prefix_re

    @classmethod
    def _build_source_filter(
        cls,
        sources: list[str],
        *,
        widen_with_identifiers: bool = False,
    ) -> tuple[str, str]:
        """Return ``(source_call_names_scala, source_code_regex)``.

        When ``widen_with_identifiers`` is True the resulting regex is
        suitable for matching ``cpg.identifier`` and ``cpg.parameter``
        nodes too — the regex itself is identical, but callers use it to
        drive a wider node-set query (relaxed taint).
        """
        source_tokens = [s for s in sources if s]
        source_union = cls._safe_union(source_tokens, kind="source")
        source_code_re = f"(?s).*(?:{source_union}).*" if source_union else "(?!x)x"
        try:
            re.compile(source_code_re)
        except re.error as exc:
            logger.error("source_code_re failed compile, neutralising: %s", exc)
            source_code_re = "(?!x)x"
        source_call_tails = sorted(
            {
                s.rsplit(".", 1)[-1]
                for s in source_tokens
                if "." not in s or s.rsplit(".", 1)[-1] in {"getenv", "input"}
            }
        )
        source_call_names_scala = ",".join(f'"{n}"' for n in source_call_tails)
        # ``widen_with_identifiers`` is currently a documentation flag —
        # the same regex is reused for identifier/parameter scans.  Kept
        # explicit so callers signal intent at the call site.
        del widen_with_identifiers
        return source_call_names_scala, source_code_re

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

        Inputs are assumed to have been pushed through ``catalog_sanitizer``
        (the JoernArm constructor enforces this) so each entry is a dotted
        identifier.  We still ``re.escape`` defensively and verify that the
        resulting union compiles, dropping any straggler that would trip
        Joern's java.util.regex with ``PatternSyntaxException``.
        """
        sink_names_scala, sink_prefix_re = JoernArm._build_sink_filter(sinks)
        source_call_names_scala, source_code_re = JoernArm._build_source_filter(sources)

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
            '"sourceCode" -> f.elements.head.code.take(200).replace("\\n", " "), '
            '"recoveryKind" -> "taint"'
            ") }.toJson"
        )

    @staticmethod
    def _build_direct_sink_query(sinks: list[str], cap: int) -> str:
        """Build a CPGQL query that emits every direct dangerous-sink call.

        This is the "candidate recovery" pass: we surface every call to a
        known-dangerous primitive irrespective of whether the strict
        ``reachableByFlows`` engine connects it back to a source.  Each
        record carries ``recoveryKind="direct_sink"`` and an empty
        ``sourceCode``, so dedup against ``recoveryKind="taint"`` records
        for the same sink prefers the strict-taint version (which has
        real source evidence).

        ``cap`` bounds total emitted records — set high enough to cover a
        repo's hot files but low enough to keep prompt cost in check.
        """
        sink_names_scala, sink_prefix_re = JoernArm._build_sink_filter(sinks)
        return (
            "cpg.call"
            f".filter(c => Set({sink_names_scala}).contains(c.name))"
            f'.code("""{sink_prefix_re}""").iterator'
            f".take({int(cap)}).l.map {{ c => Map("
            '"sinkLine"   -> c.lineNumber.getOrElse(-1).toString, '
            '"sinkFile"   -> c.file.name.headOption.getOrElse(""), '
            '"sinkCode"   -> c.code.take(300).replace("\\n", " "), '
            '"sinkName"   -> c.name, '
            '"sourceLine" -> "-1", '
            '"sourceFile" -> "", '
            '"sourceCode" -> "", '
            '"recoveryKind" -> "direct_sink"'
            ") }.toJson"
        )

    @staticmethod
    def _build_relaxed_taint_query(
        sources: list[str], sinks: list[str], cap: int
    ) -> str:
        """Build a CPGQL taint query with widened sources for recall recovery.

        Differences from :meth:`_build_taint_query`:
          * Sources include the strict set (``fieldAccess`` + matching
            calls) **plus** ``cpg.identifier`` and ``cpg.parameter``
            nodes whose ``code`` matches the source regex.  This catches
            the common attribute/parameter relay pattern
            (``def cmd(self): self._x = req.args; subprocess.Popen(self._x)``)
            that the strict pass misses because the engine's reach
            depth is bounded.
          * The output cap is enforced via ``.take(cap)`` so a wide-open
            CVE doesn't hand the LLM hundreds of low-precision flows.

        Each record carries ``recoveryKind="relaxed"``.  Dedup priority
        is ``taint > relaxed`` so a strict hit on the same sink line
        wins.  Sanitizers are intentionally not subtracted here — that
        decision is deferred to LLM triage, which already has the call
        site context.
        """
        sink_names_scala, sink_prefix_re = JoernArm._build_sink_filter(sinks)
        _, source_code_re = JoernArm._build_source_filter(
            sources, widen_with_identifiers=True
        )
        source_call_names_scala, _ = JoernArm._build_source_filter(sources)
        return (
            "cpg.call"
            f".filter(c => Set({sink_names_scala}).contains(c.name))"
            f'.code("""{sink_prefix_re}""").iterator'
            ".reachableByFlows("
            "(cpg.fieldAccess"
            f'.code("""{source_code_re}""").l ++ '
            "cpg.call"
            f".filter(c => Set({source_call_names_scala}).contains(c.name)).l ++ "
            "cpg.identifier"
            f'.code("""{source_code_re}""").l ++ '
            "cpg.parameter"
            f'.code("""{source_code_re}""").l'
            ").iterator"
            f").l.take({int(cap)}).map {{ f => Map("
            '"sinkLine"   -> f.elements.last.lineNumber.getOrElse(-1).toString, '
            '"sinkFile"   -> f.elements.last.file.name.headOption.getOrElse(""), '
            '"sinkCode"   -> f.elements.last.code.take(300).replace("\\n", " "), '
            '"sinkName"   -> (f.elements.last match { '
            "case c: io.shiftleft.codepropertygraph.generated.nodes.Call => c.name; "
            'case _ => "" }), '
            '"sourceLine" -> f.elements.head.lineNumber.getOrElse(-1).toString, '
            '"sourceFile" -> f.elements.head.file.name.headOption.getOrElse(""), '
            '"sourceCode" -> f.elements.head.code.take(200).replace("\\n", " "), '
            '"recoveryKind" -> "relaxed"'
            ") }.toJson"
        )

    @staticmethod
    def _build_def_use_chase_query(sinks: list[str], cap: int) -> str:
        """Build a CPGQL query that walks back from sink arguments to any
        non-literal predecessor (call, fieldAccess, identifier, parameter).

        Unlike strict / relaxed taint, this pass does **not** require the
        predecessor to match a known source pattern; it only requires
        that the sink argument is dynamic.  This is the "evidence of
        non-literal input" recall pass, intended to surface
        intra-method or short-callgraph flows that fall outside the
        catalog (e.g. ``os.system(builder.render(req))`` where
        ``builder`` is project-internal).

        Each record carries ``recoveryKind="def_use"``.  Records dedup
        against direct-sink and relaxed taint hits for the same sink
        line; ``taint > relaxed > def_use > direct_sink`` priority
        applies in :meth:`_parse_taint_results`.
        """
        sink_names_scala, sink_prefix_re = JoernArm._build_sink_filter(sinks)
        return (
            "cpg.call"
            f".filter(c => Set({sink_names_scala}).contains(c.name))"
            f'.code("""{sink_prefix_re}""").iterator'
            ".reachableByFlows("
            "(cpg.fieldAccess.l ++ "
            "cpg.identifier.l ++ "
            "cpg.parameter.l).iterator"
            f").l.take({int(cap)}).map {{ f => Map("
            '"sinkLine"   -> f.elements.last.lineNumber.getOrElse(-1).toString, '
            '"sinkFile"   -> f.elements.last.file.name.headOption.getOrElse(""), '
            '"sinkCode"   -> f.elements.last.code.take(300).replace("\\n", " "), '
            '"sinkName"   -> (f.elements.last match { '
            "case c: io.shiftleft.codepropertygraph.generated.nodes.Call => c.name; "
            'case _ => "" }), '
            '"sourceLine" -> f.elements.head.lineNumber.getOrElse(-1).toString, '
            '"sourceFile" -> f.elements.head.file.name.headOption.getOrElse(""), '
            '"sourceCode" -> f.elements.head.code.take(200).replace("\\n", " "), '
            '"recoveryKind" -> "def_use"'
            ") }.toJson"
        )

    # Bound on the number of unique source expressions we keep per
    # deduplicated finding.  Two upstream consumers care: the triage
    # prompt (size budget) and the audit JSON (CSV cell width).
    _DEDUP_SOURCES_CAP: int = 8
    # Bound on the normalised sink-code string used as part of the dedup
    # key.  Joern's ``sinkCode`` field is already capped at 300 chars by
    # the CPGQL query; we trim further so trivial whitespace differences
    # (which the Joern frontend can emit non-deterministically across
    # flows) don't defeat the dedup.
    _DEDUP_NORM_CAP: int = 120

    @staticmethod
    def _normalize_sink_code(code: str) -> str:
        """Whitespace-normalise sink code for dedup keying.

        Collapses any whitespace run to a single space, strips, and caps
        to ``_DEDUP_NORM_CAP`` characters.  The intent is for two flows
        whose only difference is line-wrapping or stray indentation to
        share a key.
        """
        normalised = re.sub(r"\s+", " ", str(code or "")).strip()
        return normalised[: JoernArm._DEDUP_NORM_CAP]

    # Recovery-kind priority for dedup merging.  When multiple records
    # collide on the same key we prefer the one with the strongest
    # evidence: taint (real reachableByFlows w/ catalog source) >
    # relaxed (taint w/ widened sources) > def_use (any non-literal
    # predecessor) > direct_sink (no source at all).  The winning
    # record's source/message dominates; dedup_sources still merges
    # across all records for triage context.
    _RECOVERY_PRIORITY: dict[str, int] = {
        "taint": 4,
        "relaxed": 3,
        "def_use": 2,
        "direct_sink": 1,
    }

    @classmethod
    def _normalize_recovery_kind(cls, value: Any) -> str:
        """Return a canonical recovery_kind string; default ``"taint"``.

        Records produced before the recovery passes were added (legacy
        cached results, fixtures) lack the field — those default to
        ``"taint"`` so historic dedup behaviour is preserved.
        """
        kind = str(value or "taint").strip().lower()
        return kind if kind in cls._RECOVERY_PRIORITY else "taint"

    @staticmethod
    def _parse_taint_results(raw: Any) -> list[Finding]:
        """Convert taint-flow JSON records into deduplicated Findings.

        Joern frequently emits multiple flows that all terminate at the
        same ``(sinkFile, sinkLine, sinkName, sinkCode)`` tuple — one
        per source path it walked back through.  Triaging the same sink
        line N times wastes LLM budget and inflates location-FP counts
        in the scorer (cf. results/joern/20260508_234404 audit, where
        ``Popen`` alone produced 1400 redundant FP rows).

        Collapse policy:
          * key = ``(file_path, line_start, sink_api, normalised(sinkCode))``
          * a higher-priority ``recoveryKind`` overrides the canonical
            record's source/message/metadata (priority order: ``taint >
            relaxed > def_use > direct_sink``),
          * accumulate distinct ``sourceCode`` strings into
            ``metadata['dedup_sources']`` (capped to ``_DEDUP_SOURCES_CAP``),
          * track ``metadata['dedup_count']`` (>= 1),
          * track ``metadata['recovery_kind']`` (winning kind) and
            ``metadata['recovery_kinds_seen']`` (sorted list of every
            kind that contributed to this finding) for audit tooling.
        """
        if not raw:
            return []
        if not isinstance(raw, list):
            return []

        ordered_keys: list[tuple[str, int, str, str]] = []
        by_key: dict[tuple[str, int, str, str], Finding] = {}

        def _make_finding(item: dict[str, Any], recovery_kind: str) -> Finding:
            fp = str(item.get("sinkFile", ""))
            try:
                ls = int(item.get("sinkLine", 0))
            except (TypeError, ValueError):
                ls = 0
            sink_api = str(item.get("sinkName", ""))
            sink_code = str(item.get("sinkCode", ""))
            source_code = str(item.get("sourceCode", ""))
            metadata = dict(item)
            metadata["recovery_kind"] = recovery_kind
            metadata["recovery_kinds_seen"] = [recovery_kind]
            metadata["dedup_count"] = 1
            metadata["dedup_sources"] = [source_code] if source_code else []
            message = (
                f"Taint flow: {source_code} -> {sink_code}"
                if source_code
                else f"Direct sink call: {sink_code}"
            )
            return Finding(
                file_path=fp,
                line_start=ls,
                line_end=ls,
                rule_id="joern-taint-reachability"
                if recovery_kind == "taint"
                else f"joern-{recovery_kind}-recovery",
                message=message,
                code_snippet=sink_code,
                sink_api=sink_api,
                arm=ToolArm.JOERN,
                metadata=metadata,
            )

        for item in raw:
            if not isinstance(item, dict):
                continue
            fp = str(item.get("sinkFile", ""))
            try:
                ls = int(item.get("sinkLine", 0))
            except (TypeError, ValueError):
                ls = 0
            sink_api = str(item.get("sinkName", ""))
            sink_code = str(item.get("sinkCode", ""))
            source_code = str(item.get("sourceCode", ""))
            recovery_kind = JoernArm._normalize_recovery_kind(item.get("recoveryKind"))
            key = (fp, ls, sink_api, JoernArm._normalize_sink_code(sink_code))

            existing = by_key.get(key)
            if existing is None:
                by_key[key] = _make_finding(item, recovery_kind)
                ordered_keys.append(key)
                continue

            md = existing.metadata
            existing_kind = JoernArm._normalize_recovery_kind(md.get("recovery_kind"))
            kinds_seen = list(md.get("recovery_kinds_seen") or [existing_kind])
            if recovery_kind not in kinds_seen:
                kinds_seen.append(recovery_kind)
            kinds_seen = sorted(set(kinds_seen))

            existing_pri = JoernArm._RECOVERY_PRIORITY.get(existing_kind, 0)
            new_pri = JoernArm._RECOVERY_PRIORITY.get(recovery_kind, 0)
            if new_pri > existing_pri:
                merged_sources = list(md.get("dedup_sources") or [])
                if source_code and source_code not in merged_sources:
                    if len(merged_sources) < JoernArm._DEDUP_SOURCES_CAP:
                        merged_sources.append(source_code)
                merged_count = int(md.get("dedup_count", 1)) + 1
                replacement = _make_finding(item, recovery_kind)
                replacement.metadata["dedup_count"] = merged_count
                replacement.metadata["dedup_sources"] = merged_sources
                replacement.metadata["recovery_kinds_seen"] = kinds_seen
                by_key[key] = replacement
                continue

            md["dedup_count"] = int(md.get("dedup_count", 1)) + 1
            md["recovery_kinds_seen"] = kinds_seen
            sources = md.setdefault("dedup_sources", [])
            if (
                source_code
                and source_code not in sources
                and len(sources) < JoernArm._DEDUP_SOURCES_CAP
            ):
                sources.append(source_code)

        return [by_key[key] for key in ordered_keys]
