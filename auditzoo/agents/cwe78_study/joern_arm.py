"""Joern arm: CPG-based taint analysis for CWE-78.

Uses the existing AuditZoo Joern backend via ``BaseAnalysisAgent.query_ir``
to run interprocedural taint-reachability queries and call-graph expansion.
"""

from __future__ import annotations

import asyncio
import logging
import re
from pathlib import Path
from typing import Any

import yaml
from autogen_core import MessageContext

from auditzoo.core.agents import BaseAnalysisAgent
from auditzoo.core.protocol.requests import Request
from auditzoo.core.protocol.responses import Response

from .schemas import Finding, ToolArm

logger = logging.getLogger(__name__)

_SEED_RULES_DIR = Path(__file__).parent / "seed_rules"
_SOURCE_NAME_TOKENS = (
    "cmd",
    "command",
    "args",
    "arg",
    "path",
    "file",
    "filename",
    "url",
    "checkout",
    "branch",
    "template",
    "payload",
    "request",
    "data",
)
_TEST_PATH_MARKERS = ("/test/", "/tests/", "test_", "_test.py")
_LOW_SIGNAL_PATH_MARKERS = (
    "/.github/",
    "/devscripts/",
    "/docs/",
    "/examples/",
    "/test/",
    "/tests/",
    "/third_party/",
    "/vendor/",
    "_test.py",
    "test_",
)
_LOW_SIGNAL_PATH_RE = "(?i).*(/test/|/tests/|test_|_test[.]py|/[.]github/|/devscripts/|/docs/|/examples/|/third_party/|/vendor/).*"
_GENERIC_WRAPPER_NAMES = {
    "run",
    "call",
    "system",
    "popen",
    "popen2",
    "popen3",
    "popen4",
    "execute",
}
_PROJECT_WRAPPER_HINTS = (
    "cmd",
    "command",
    "exec",
    "shell",
    "subprocess",
    "process",
    "git",
    "clone",
    "checkout",
)
_EXTERNAL_SOURCE_PATTERNS = (
    r"sys[.]argv",
    r"sys[.]stdin[.]read",
    r"os[.]environ",
    r"os[.]getenv",
    r"\binput\s*[(]",
    r"\bsocket[.]recv\s*[(]",
    r"\brecv\s*[(]",
    r"\brequest[.](args|form|values|get_json|data|headers|GET|POST|json)",
    r"\bargs[.][A-Za-z_][A-Za-z0-9_]*",
    r"\bparse_args\s*[(]",
    r"\b(click|typer)[.]",
    r"\b(Request|Body|Query|Form|Header|Cookie)\s*[(]",
)
_EXTERNAL_SOURCE_RE = re.compile(
    "(" + "|".join(_EXTERNAL_SOURCE_PATTERNS) + ")",
    flags=re.IGNORECASE | re.DOTALL,
)
_VALID_MODELING_MODES = {
    "catalog_only",
    "catalog_parameter",
    "catalog_parameter_attribute",
    "full_wrapper",
}


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


def _is_external_source_code(code: str) -> bool:
    return bool(_EXTERNAL_SOURCE_RE.search(code or ""))


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
        modeling_mode: str = "full_wrapper",
    ) -> None:
        super().__init__(description="Joern CWE-78 taint analysis arm")
        if modeling_mode not in _VALID_MODELING_MODES:
            raise ValueError(
                f"Unknown Joern modeling mode {modeling_mode!r}; "
                f"expected one of {sorted(_VALID_MODELING_MODES)}"
            )
        self._sources = sources if sources is not None else _load_catalog("sources")
        self._sinks = sinks if sinks is not None else _load_catalog("sinks")
        self._sanitizers = (
            sanitizers if sanitizers is not None else _load_catalog("sanitizers")
        )
        self._context_lines = context_lines
        self._call_graph_depth = call_graph_depth
        self._modeling_mode = modeling_mode

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
        if message.type == "task.joern_coverage_probe":
            probe = await self.coverage_probe(
                gt_file=str(message.payload.get("gt_file", "") or ""),
                gt_lines=[
                    int(line)
                    for line in message.payload.get("gt_lines", []) or []
                    if str(line).isdigit()
                ],
                ctx=ctx,
            )
            return Response.ok(probe)
        if message.type == "task.joern_refinement_candidates":
            payload = message.payload or {}
            finding_files = payload.get("finding_files", []) or []
            cap = int(payload.get("cap_per_bucket", 12) or 12)
            buckets = await self.discover_refinement_candidates(
                ctx,
                finding_files=[
                    str(f) for f in finding_files if isinstance(f, str)
                ],
                cap_per_bucket=cap,
            )
            return Response.ok(buckets)
        if message.type == "task.joern_verify_wrappers":
            payload = message.payload or {}
            verified = await self.verify_wrapper_candidates(
                ctx,
                proposed_sinks=[
                    str(s) for s in payload.get("sinks", []) or [] if s
                ],
                proposed_sources=[
                    str(s) for s in payload.get("sources", []) or [] if s
                ],
                proposed_sanitizers=[
                    str(s) for s in payload.get("sanitizers", []) or [] if s
                ],
            )
            return Response.ok(verified)
        return Response.fail(f"Unknown type: {message.type}")

    # ------------------------------------------------------------------
    # Core analysis methods
    # ------------------------------------------------------------------

    async def scan(self, ctx: MessageContext) -> list[Finding]:
        """Run taint reachability query and return findings."""
        return await self._run_taint_scan(ctx)

    async def _run_taint_scan(self, ctx: MessageContext) -> list[Finding]:
        """Execute CPGQL taint queries and parse results into Findings."""
        wrapper_sinks = (
            await self._discover_wrapper_sinks(ctx)
            if self._modeling_mode == "full_wrapper"
            else []
        )
        logger.info(
            "Joern wrapper sink discovery found %d wrappers", len(wrapper_sinks)
        )
        query = self._build_taint_query(
            self._sources,
            self._sinks,
            wrapper_sinks=wrapper_sinks,
            modeling_mode=self._modeling_mode,
        )

        try:
            logger.info("Running Joern CWE-78 taint query")
            raw = await self.query_ir(query, response_ty="json", ctx=ctx)
        except RuntimeError as exc:
            logger.error("Joern taint query failed: %s", exc)
            return []

        return self._parse_taint_results(raw, wrapper_sinks=wrapper_sinks)

    async def _discover_wrapper_sinks(
        self,
        ctx: MessageContext,
        *,
        limit: int = 12,
    ) -> list[dict[str, Any]]:
        """Discover local functions that call known command-execution sinks."""
        query = self._build_wrapper_discovery_query(self._sinks, limit=limit)
        try:
            raw = await asyncio.wait_for(
                self.query_ir(query, response_ty="json", ctx=ctx),
                timeout=20.0,
            )
        except TimeoutError:
            logger.warning(
                "Joern wrapper sink discovery timed out; continuing without wrappers"
            )
            return []
        except RuntimeError as exc:
            logger.warning("Joern wrapper sink discovery failed: %s", exc)
            return []
        if not isinstance(raw, list):
            return []
        out: list[dict[str, Any]] = []
        for item in raw:
            if isinstance(item, dict) and item.get("name"):
                out.append(item)
        return out[:limit]

    async def expand_call_graph(
        self,
        sink_method: str,
        depth: int | None = None,
        ctx: MessageContext | None = None,
    ) -> list[dict[str, Any]]:
        """Query k-hop call-graph neighbourhood of *sink_method*."""
        if ctx is None:
            raise ValueError("MessageContext is required for IR access")
        return await self._expand_call_graph(
            sink_method, depth or self._call_graph_depth, ctx
        )

    async def _expand_call_graph(
        self, sink_method: str, depth: int, ctx: MessageContext
    ) -> list[dict[str, Any]]:
        """Return callers of ``sink_method`` with structured metadata.

        Each record now includes ``callers``, ``callees``, ``signature``,
        ``body_excerpt``, ``docstring``, and ``code`` so the downstream
        refinement prompt can show the LLM real evidence rather than a bare
        function name.  This replaces the legacy schema that emitted only
        ``name``/``filename``/``lineNumber``/``code``.
        """
        safe_name = sink_method.replace('"', '\\"')
        query = (
            f'cpg.method.name("{safe_name}").repeat(_.caller)'
            f"(using _.maxDepth({depth})).dedup.l.map {{ m => "
            'Map("name" -> m.name, '
            '"filename" -> m.filename, '
            '"lineNumber" -> m.lineNumber.getOrElse(-1).toString, '
            '"code" -> m.code.take(800).replace("\\n", " "), '
            '"callers" -> m.callIn.method.name.dedup.take(5).l, '
            '"callees" -> m.call.name.dedup.take(8).l) '
            "}.toJson"
        )
        try:
            raw = await self.query_ir(query, response_ty="json", ctx=ctx)
        except RuntimeError as exc:
            logger.error("Call-graph expansion failed: %s", exc)
            return []

        if not isinstance(raw, list):
            return []
        enriched: list[dict[str, Any]] = []
        for item in raw:
            if isinstance(item, dict):
                enriched.append(JoernArm._enrich_method_record(item))
        return enriched

    @staticmethod
    def _enrich_method_record(record: dict[str, Any]) -> dict[str, Any]:
        """Augment a Joern method record with signature/body/docstring fields.

        ``record`` arrives with the v1 shape (``name``, ``filename``,
        ``lineNumber``, ``code``) plus optional ``callers``/``callees`` from
        the v2 query.  We derive signature, docstring and a 5-line body
        excerpt heuristically from ``code`` so the LLM prompt can quote
        evidence without us shipping every method body to the model.
        """
        out = dict(record)
        code = str(out.get("code", "") or "")
        # Joern collapses newlines in some queries; restore approximate line
        # boundaries so heuristics work.
        body = code.replace("\\n", "\n")
        # Some queries (the v2 path above) already collapsed real newlines
        # into spaces; if there are no newlines in ``body`` we fall back to
        # token-level splitting on ``;`` which is rare in Python.
        lines = [line.rstrip() for line in body.splitlines() if line.strip()]
        out["signature"] = lines[0] if lines else code[:120]
        out["body_excerpt"] = "\n".join(lines[:5]) if lines else out["signature"]
        out["docstring"] = JoernArm._extract_docstring(body)
        if "callers" in out and not isinstance(out["callers"], list):
            out["callers"] = []
        if "callees" in out and not isinstance(out["callees"], list):
            out["callees"] = []
        return out

    @staticmethod
    def _extract_docstring(body: str) -> str:
        match = re.search(
            r'(?ms)(?:"""(.+?)"""|\'\'\'(.+?)\'\'\')',
            body,
        )
        if not match:
            return ""
        text = match.group(1) or match.group(2) or ""
        first_line = text.strip().splitlines()[0] if text.strip() else ""
        return first_line[:200]

    # ------------------------------------------------------------------
    # Refinement candidate discovery (symbolic, no LLM)
    # ------------------------------------------------------------------

    async def discover_refinement_candidates(
        self,
        ctx: MessageContext,
        *,
        finding_files: list[str] | None = None,
        cap_per_bucket: int = 12,
    ) -> dict[str, list[dict[str, Any]]]:
        """Collect symbolic wrapper candidates for the LLM refinement prompt.

        Returns a dict keyed by candidate bucket:

        - ``sink_wrapper``: methods that transitively call a known sink and
          are not in low-signal paths.  Includes ``callsite_to_sink`` with
          file/line of the first sink call inside the wrapper body.
        - ``source_wrapper``: methods whose body or returned expression
          matches ``_EXTERNAL_SOURCE_RE`` (``os.environ``, ``sys.argv``,
          ``request.*`` and friends).  Includes ``source_evidence``.
        - ``named_wrapper``: methods whose names look like CWE-78 wrappers
          (``run_cmd``, ``execute``, ``shell``, ``spawn``, ``call_subprocess``,
          ``run_command``, ``exec_cmd``, ``cmd``, ``popen``...).
        - ``proximity``: methods that share a package prefix with any of
          ``finding_files`` (≥2 path components shared).  ``finding_files``
          must come from prior iteration findings only — we do not pass
          ground-truth file paths here so the loop stays evaluation-clean.

        Each record is enriched via :meth:`_enrich_method_record` and
        carries ``name``, ``filename``, ``lineNumber``, ``signature``,
        ``body_excerpt``, ``docstring``, ``callers``, ``callees`` plus
        bucket-specific keys.
        """
        cap = max(1, int(cap_per_bucket))
        sink_query = self._build_sink_wrapper_candidate_query(
            self._sinks, limit=cap
        )
        source_query = self._build_source_wrapper_candidate_query(limit=cap)
        named_query = self._build_named_wrapper_candidate_query(limit=cap)
        proximity_query = self._build_proximity_candidate_query(
            finding_files or [], limit=cap
        )

        async def _run(query: str, label: str) -> list[dict[str, Any]]:
            if not query:
                return []
            try:
                raw = await asyncio.wait_for(
                    self.query_ir(query, response_ty="json", ctx=ctx),
                    timeout=20.0,
                )
            except TimeoutError:
                logger.warning(
                    "Joern %s candidate query timed out; skipping bucket",
                    label,
                )
                return []
            except RuntimeError as exc:
                logger.warning(
                    "Joern %s candidate query failed: %s", label, exc
                )
                return []
            if not isinstance(raw, list):
                return []
            return [
                JoernArm._enrich_method_record(item)
                for item in raw
                if isinstance(item, dict)
            ]

        results: dict[str, list[dict[str, Any]]] = {
            "sink_wrapper": await _run(sink_query, "sink_wrapper"),
            "source_wrapper": await _run(source_query, "source_wrapper"),
            "named_wrapper": await _run(named_query, "named_wrapper"),
            "proximity": await _run(proximity_query, "proximity"),
        }
        return results

    def rank_wrapper_candidates(
        self,
        candidate_buckets: dict[str, list[dict[str, Any]]],
        *,
        finding_files: list[str] | None = None,
        cap: int = 12,
    ) -> list[dict[str, Any]]:
        """Deterministically rank and de-duplicate wrapper candidates.

        Sorting tier (lower is better):
          (a) has direct sink callsite or external source evidence
          (b) name-heuristic + proximity score (higher better, negated)
          (c) shorter body excerpt first (small wrappers preferred)

        Each returned candidate includes ``buckets`` (list of bucket names
        the method appeared in), ``name_heuristic_score``, ``proximity_score``,
        and ``evidence_score`` so the prompt can show the ranking signal.
        """
        merged: dict[str, dict[str, Any]] = {}
        for bucket_name, items in candidate_buckets.items():
            for item in items:
                key = (
                    str(item.get("name", "") or "")
                    + "::"
                    + str(item.get("filename", "") or "")
                )
                if not item.get("name"):
                    continue
                if key in merged:
                    merged[key].setdefault("buckets", []).append(bucket_name)
                    # Keep the richest body excerpt across duplicates
                    if len(str(item.get("body_excerpt", ""))) > len(
                        str(merged[key].get("body_excerpt", ""))
                    ):
                        merged[key]["body_excerpt"] = item.get("body_excerpt", "")
                    # Carry over bucket-specific evidence fields if missing.
                    for ev_key in (
                        "callsite_to_sink",
                        "source_evidence",
                        "wrappedSinkName",
                    ):
                        if ev_key in item and ev_key not in merged[key]:
                            merged[key][ev_key] = item[ev_key]
                else:
                    new_item = dict(item)
                    new_item["buckets"] = [bucket_name]
                    merged[key] = new_item

        finding_files = finding_files or []
        ranked: list[dict[str, Any]] = []
        for cand in merged.values():
            name = str(cand.get("name", "") or "")
            filename = str(cand.get("filename", "") or "")
            cand["name_heuristic_score"] = JoernArm._name_heuristic_score(name)
            cand["proximity_score"] = JoernArm._proximity_score(
                filename, finding_files
            )
            cand["evidence_score"] = JoernArm._evidence_score(cand)
            ranked.append(cand)

        def _sort_key(c: dict[str, Any]) -> tuple[int, int, int]:
            has_evidence = (
                bool(c.get("callsite_to_sink"))
                or bool(c.get("source_evidence"))
            )
            score = -(int(c.get("name_heuristic_score", 0))
                      + int(c.get("proximity_score", 0))
                      + int(c.get("evidence_score", 0)))
            body_len = len(str(c.get("body_excerpt", "")))
            return (0 if has_evidence else 1, score, body_len)

        ranked.sort(key=_sort_key)
        return ranked[: max(1, int(cap))]

    @staticmethod
    def _name_heuristic_score(name: str) -> int:
        """Score 0..3 based on how wrapper-like the function name is."""
        if not name:
            return 0
        lowered = name.lower()
        score = 0
        wrapper_tokens = (
            "run_cmd",
            "run_command",
            "call_subprocess",
            "exec_cmd",
            "execute_command",
            "shell_exec",
            "shell_run",
            "spawn_proc",
            "run_shell",
            "exec_shell",
        )
        if any(tok in lowered for tok in wrapper_tokens):
            score += 3
        weak_tokens = (
            "cmd",
            "command",
            "shell",
            "exec",
            "spawn",
            "popen",
            "subprocess",
            "process",
        )
        if any(tok in lowered for tok in weak_tokens):
            score += 1
        # Penalise generic single-word wrappers slightly.
        if lowered in _GENERIC_WRAPPER_NAMES:
            score = max(0, score - 1)
        return score

    @staticmethod
    def _proximity_score(filename: str, finding_files: list[str]) -> int:
        if not filename or not finding_files:
            return 0
        best = 0
        for ff in finding_files:
            if not ff:
                continue
            if filename == ff:
                return 3
            try:
                parts_a = Path(filename).parts
                parts_b = Path(ff).parts
            except (TypeError, ValueError):
                continue
            depth = 0
            for left, right in zip(parts_a, parts_b, strict=False):
                if left != right:
                    break
                depth += 1
            if depth >= 2:
                best = max(best, 2)
            elif depth == 1:
                best = max(best, 1)
        return best

    @staticmethod
    def _evidence_score(record: dict[str, Any]) -> int:
        score = 0
        if record.get("callsite_to_sink"):
            score += 2
        if record.get("source_evidence"):
            score += 2
        if record.get("docstring"):
            score += 1
        return score

    @staticmethod
    def _build_sink_wrapper_candidate_query(
        sinks: list[str], *, limit: int = 12
    ) -> str:
        """Methods whose body calls a known sink, with the sink callsite."""

        def _escape(s: str) -> str:
            return s.replace("\\", "\\\\").replace('"', '\\"').replace(".", "\\.")

        sink_names = sorted({s.rsplit(".", 1)[-1] for s in sinks if s})
        sink_prefix_re = (
            "(?s)^(" + "|".join(_escape(s) for s in sinks if s) + ")\\(.*"
        )
        sink_names_scala = ",".join(f'"{n}"' for n in sink_names)
        return (
            "cpg.call"
            f".filter(c => Set({sink_names_scala}).contains(c.name))"
            f'.filter(c => c.code.matches("""{sink_prefix_re}"""))'
            f'.filter(c => !c.file.name.headOption.getOrElse("").matches("""{_LOW_SIGNAL_PATH_RE}"""))'
            f".take({max(limit * 4, 24)}).l"
            ".groupBy(c => c.method.fullName)"
            ".values"
            ".map { calls => "
            "val first = calls.head; "
            "val m = first.method; "
            'Map("name" -> m.name, '
            '"filename" -> m.filename, '
            '"lineNumber" -> m.lineNumber.getOrElse(-1).toString, '
            '"code" -> m.code.take(800).replace("\\n", " "), '
            '"callers" -> m.callIn.method.name.dedup.take(5).l, '
            '"callees" -> m.call.name.dedup.take(8).l, '
            '"callsite_to_sink" -> Map('
            '"file" -> first.file.name.headOption.getOrElse(""), '
            '"line" -> first.lineNumber.getOrElse(-1).toString, '
            '"sink_name" -> first.name, '
            '"code" -> first.code.take(300).replace("\\n", " ")), '
            '"wrappedSinkName" -> first.name) '
            "}"
            ".toList"
            f".take({limit})"
            ".toJson"
        )

    @staticmethod
    def _build_source_wrapper_candidate_query(*, limit: int = 12) -> str:
        """Methods whose body or returns reference a known external source."""
        external_source_re = (
            "(?si).*(" + "|".join(_EXTERNAL_SOURCE_PATTERNS) + ").*"
        )
        return (
            "cpg.call"
            f'.code("""{external_source_re}""")'
            f'.filter(c => !c.file.name.headOption.getOrElse("").matches("""{_LOW_SIGNAL_PATH_RE}"""))'
            f".take({max(limit * 4, 24)}).l"
            ".groupBy(c => c.method.fullName)"
            ".values"
            ".map { calls => "
            "val first = calls.head; "
            "val m = first.method; "
            'Map("name" -> m.name, '
            '"filename" -> m.filename, '
            '"lineNumber" -> m.lineNumber.getOrElse(-1).toString, '
            '"code" -> m.code.take(800).replace("\\n", " "), '
            '"callers" -> m.callIn.method.name.dedup.take(5).l, '
            '"callees" -> m.call.name.dedup.take(8).l, '
            '"source_evidence" -> Map('
            '"file" -> first.file.name.headOption.getOrElse(""), '
            '"line" -> first.lineNumber.getOrElse(-1).toString, '
            '"code" -> first.code.take(300).replace("\\n", " "))) '
            "}"
            ".toList"
            f".take({limit})"
            ".toJson"
        )

    @staticmethod
    def _build_named_wrapper_candidate_query(*, limit: int = 12) -> str:
        """Methods whose names match CWE-78 wrapper-like patterns."""
        # Match common project wrapper hints; CPGQL .name() takes a regex.
        name_re = (
            "(?i).*(run_cmd|run_command|call_subprocess|exec_cmd|"
            "execute_command|shell_exec|shell_run|spawn_proc|run_shell|"
            "exec_shell|cmd|command|shell|exec|spawn|popen|subprocess).*"
        )
        return (
            f'cpg.method.name("""{name_re}""")'
            f'.filter(m => !m.filename.matches("""{_LOW_SIGNAL_PATH_RE}"""))'
            f".take({limit}).l.map {{ m => "
            'Map("name" -> m.name, '
            '"filename" -> m.filename, '
            '"lineNumber" -> m.lineNumber.getOrElse(-1).toString, '
            '"code" -> m.code.take(800).replace("\\n", " "), '
            '"callers" -> m.callIn.method.name.dedup.take(5).l, '
            '"callees" -> m.call.name.dedup.take(8).l) '
            "}.toJson"
        )

    @staticmethod
    def _build_proximity_candidate_query(
        finding_files: list[str], *, limit: int = 12
    ) -> str:
        """Methods that live in or near the prior iteration's finding files."""
        files = [f for f in finding_files if f]
        if not files:
            return ""

        # Build a regex matching each finding file's basename (.* so any prefix path matches).
        def _escape(s: str) -> str:
            return s.replace("\\", "\\\\").replace('"', '\\"').replace(".", "\\.")

        basenames = sorted({Path(f).name for f in files if Path(f).name})
        if not basenames:
            return ""
        file_re = "(?s).*(" + "|".join(_escape(b) for b in basenames) + ")$"
        return (
            f'cpg.method.filter(m => m.filename.matches("""{file_re}"""))'
            f'.filter(m => !m.filename.matches("""{_LOW_SIGNAL_PATH_RE}"""))'
            f".take({max(limit * 2, 24)}).l.map {{ m => "
            'Map("name" -> m.name, '
            '"filename" -> m.filename, '
            '"lineNumber" -> m.lineNumber.getOrElse(-1).toString, '
            '"code" -> m.code.take(800).replace("\\n", " "), '
            '"callers" -> m.callIn.method.name.dedup.take(5).l, '
            '"callees" -> m.call.name.dedup.take(8).l) '
            f"}}.distinctBy(_(\"name\")).take({limit}).toJson"
        )

    # ------------------------------------------------------------------
    # Verification (LLM classifications -> Joern-confirmed wrappers)
    # ------------------------------------------------------------------

    async def verify_wrapper_candidates(
        self,
        ctx: MessageContext,
        *,
        proposed_sinks: list[str],
        proposed_sources: list[str],
        proposed_sanitizers: list[str],
    ) -> dict[str, list[str]]:
        """Confirm LLM-proposed wrappers symbolically before catalog expansion.

        For each role we run a minimal CPGQL probe.  Names that fail to
        match are dropped; the caller logs the rejection in
        ``refinement_actions``.

        - sink-wrappers must have a method whose body calls a known seed sink.
        - source-wrappers must have a method whose body matches the
          external-source regex or reads a parameter named ``args``/``cmd``/etc.
        - sanitizers must contain ``shlex.quote``, an allowlist token, or a
          boolean validation hint.
        """

        def _escape(s: str) -> str:
            return s.replace("\\", "\\\\").replace('"', '\\"').replace(".", "\\.")

        verified: dict[str, list[str]] = {
            "sources": [],
            "sinks": [],
            "sanitizers": [],
        }

        sink_names = sorted({s.rsplit(".", 1)[-1] for s in self._sinks if s})
        sink_names_scala = ",".join(f'"{n}"' for n in sink_names)
        sink_prefix_re = (
            "(?s)^(" + "|".join(_escape(s) for s in self._sinks if s) + ")\\(.*"
        )
        external_source_re = (
            "(?si).*(" + "|".join(_EXTERNAL_SOURCE_PATTERNS) + ").*"
        )
        sanitizer_re = (
            "(?si).*(shlex[.]quote|re[.]match|re[.]fullmatch|allowlist|"
            "whitelist|isalnum|in\\s+ALLOWED).*"
        )

        async def _probe_count(query: str) -> int:
            try:
                raw = await asyncio.wait_for(
                    self.query_ir(query, response_ty="json", ctx=ctx),
                    timeout=10.0,
                )
            except (TimeoutError, RuntimeError):
                return 0
            if isinstance(raw, list):
                return len(raw)
            if isinstance(raw, dict):
                return 1
            return 0

        for name in proposed_sinks:
            short = name.rsplit(".", 1)[-1]
            if not short:
                continue
            q = (
                f'cpg.method.name("{_escape(short)}").filter(m => '
                f"m.call.filter(c => Set({sink_names_scala}).contains(c.name))"
                f'.code("""{sink_prefix_re}""").nonEmpty)'
                ".take(1).l.map { m => Map(\"name\" -> m.name) }.toJson"
            )
            if await _probe_count(q) > 0:
                verified["sinks"].append(name)

        for name in proposed_sources:
            short = name.rsplit(".", 1)[-1]
            if not short:
                continue
            q = (
                f'cpg.method.name("{_escape(short)}").filter(m => '
                f'(m.ast.isCall.code("""{external_source_re}""").nonEmpty || '
                f'm.parameter.name("(?i)^(args|cmd|command|input|payload|data|url|path)$").nonEmpty))'
                ".take(1).l.map { m => Map(\"name\" -> m.name) }.toJson"
            )
            if await _probe_count(q) > 0:
                verified["sources"].append(name)

        for name in proposed_sanitizers:
            short = name.rsplit(".", 1)[-1]
            if not short:
                continue
            q = (
                f'cpg.method.name("{_escape(short)}").filter(m => '
                f'm.ast.isCall.code("""{sanitizer_re}""").nonEmpty)'
                ".take(1).l.map { m => Map(\"name\" -> m.name) }.toJson"
            )
            if await _probe_count(q) > 0:
                verified["sanitizers"].append(name)

        return verified

    async def coverage_probe(
        self,
        *,
        gt_file: str,
        gt_lines: list[int],
        ctx: MessageContext,
    ) -> dict[str, Any]:
        """Collect cheap coverage facts for zero-candidate Joern diagnostics."""
        del gt_lines  # file-level coverage is sufficient for this diagnostic probe.
        if not gt_file:
            return {
                "gt_file_seen": False,
                "method_count": 0,
                "gt_sink_count": 0,
                "external_source_count": 0,
                "methods_in_gt_file": [],
                "probe_skipped": ["missing_gt_file"],
                "probe_failed": [],
            }

        query = self._build_coverage_probe_query(gt_file, self._sinks)
        try:
            raw = await asyncio.wait_for(
                self.query_ir(query, response_ty="json", ctx=ctx),
                timeout=15.0,
            )
        except TimeoutError:
            return {
                "gt_file_seen": False,
                "method_count": 0,
                "gt_sink_count": 0,
                "external_source_count": 0,
                "methods_in_gt_file": [],
                "probe_skipped": [],
                "probe_failed": ["timeout"],
            }
        except RuntimeError as exc:
            return {
                "gt_file_seen": False,
                "method_count": 0,
                "gt_sink_count": 0,
                "external_source_count": 0,
                "methods_in_gt_file": [],
                "probe_skipped": [],
                "probe_failed": [str(exc)[:200]],
            }

        if isinstance(raw, list) and raw and isinstance(raw[0], dict):
            raw = raw[0]
        if not isinstance(raw, dict):
            return {
                "gt_file_seen": False,
                "method_count": 0,
                "gt_sink_count": 0,
                "external_source_count": 0,
                "methods_in_gt_file": [],
                "probe_skipped": [],
                "probe_failed": ["unexpected_response"],
            }

        methods = raw.get("methods_in_gt_file") or []
        if not isinstance(methods, list):
            methods = []

        def _as_int(value: Any) -> int:
            try:
                return int(value)
            except (TypeError, ValueError):
                return 0

        return {
            "gt_file_seen": str(raw.get("gt_file_seen", "")).lower() == "true"
            or bool(raw.get("gt_file_seen") is True),
            "method_count": _as_int(raw.get("method_count")),
            "gt_sink_count": _as_int(raw.get("gt_sink_count")),
            "external_source_count": _as_int(raw.get("external_source_count")),
            "methods_in_gt_file": methods[:50],
            "probe_skipped": [],
            "probe_failed": [],
        }

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
            metadata = dict(f.metadata or {})
            if metadata:
                JoernArm._add_python_origin_evidence(metadata, repo)
            try:
                lines = fp.read_text().splitlines()
            except OSError:
                if metadata:
                    enriched.append(
                        Finding(
                            file_path=f.file_path,
                            line_start=f.line_start,
                            line_end=f.line_end,
                            rule_id=f.rule_id,
                            message=f.message,
                            code_snippet=f.code_snippet,
                            surrounding_context=f.surrounding_context,
                            sink_api=f.sink_api,
                            arm=f.arm,
                            metadata=metadata,
                        )
                    )
                else:
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
                    metadata=metadata or f.metadata,
                )
            )
        return enriched

    # ------------------------------------------------------------------
    # CPGQL helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_coverage_probe_query(gt_file: str, sinks: list[str]) -> str:
        """Build a single CPGQL query for file/sink/source coverage facts."""

        def _escape(s: str) -> str:
            return s.replace("\\", "\\\\").replace('"', '\\"').replace(".", "\\.")

        gt_basename = Path(gt_file).name or gt_file
        file_re = "(?s).*" + _escape(gt_basename) + "$"
        sink_names = sorted({s.rsplit(".", 1)[-1] for s in sinks if s})
        sink_prefix_re = "(?s)^(" + "|".join(_escape(s) for s in sinks if s) + ")\\(.*"
        sink_names_scala = ",".join(f'"{n}"' for n in sink_names)
        external_source_re = "(?si).*(" + "|".join(_EXTERNAL_SOURCE_PATTERNS) + ").*"
        return (
            "List(Map("
            '"gt_file_seen" -> cpg.file.name("""'
            f"{file_re}"
            '""").nonEmpty.toString, '
            '"method_count" -> cpg.method.filter(m => m.filename.matches("""'
            f"{file_re}"
            '""")).size.toString, '
            '"methods_in_gt_file" -> cpg.method.filter(m => m.filename.matches("""'
            f"{file_re}"
            '""")).take(50).map { m => Map('
            '"name" -> m.name, '
            '"lineNumber" -> m.lineNumber.getOrElse(-1).toString'
            ") }.l, "
            '"gt_sink_count" -> cpg.call.filter(c => Set('
            f"{sink_names_scala}"
            ').contains(c.name)).filter(c => c.code.matches("""'
            f"{sink_prefix_re}"
            '""")).filter(c => c.file.name.headOption.getOrElse("").matches("""'
            f"{file_re}"
            '""")).size.toString, '
            '"external_source_count" -> (cpg.call.code("""'
            f"{external_source_re}"
            '""").filter(c => c.file.name.headOption.getOrElse("").matches("""'
            f"{file_re}"
            '""")).size + cpg.fieldAccess.code("""'
            f"{external_source_re}"
            '""").filter(a => a.file.name.headOption.getOrElse("").matches("""'
            f"{file_re}"
            '""")).size).toString'
            ")).toJson"
        )

    @staticmethod
    def _build_taint_query(
        sources: list[str],
        sinks: list[str],
        *,
        wrapper_sinks: list[dict[str, Any]] | None = None,
        modeling_mode: str = "full_wrapper",
    ) -> str:
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
            return s.replace("\\", "\\\\").replace('"', '\\"').replace(".", "\\.")

        if modeling_mode not in _VALID_MODELING_MODES:
            raise ValueError(
                f"Unknown Joern modeling mode {modeling_mode!r}; "
                f"expected one of {sorted(_VALID_MODELING_MODES)}"
            )
        wrapper_sinks = wrapper_sinks or []
        wrapper_names = (
            sorted({str(w.get("name", "")) for w in wrapper_sinks if w.get("name")})[
                :12
            ]
            if modeling_mode == "full_wrapper"
            else []
        )
        sink_names = sorted(
            {s.rsplit(".", 1)[-1] for s in sinks if s} | set(wrapper_names)
        )
        direct_sink_names = sorted({s.rsplit(".", 1)[-1] for s in sinks if s})
        sink_prefix_re = "(?s)^(" + "|".join(_escape(s) for s in sinks) + ")\\(.*"
        sink_names_scala = ",".join(f'"{n}"' for n in sink_names)
        direct_sink_names_scala = ",".join(f'"{n}"' for n in direct_sink_names)
        wrapper_names_scala = ",".join(f'"{n}"' for n in wrapper_names)

        source_tokens = [s for s in sources if s]
        source_code_re = "(?s).*(" + "|".join(_escape(s) for s in source_tokens) + ").*"
        source_name_re = (
            "(?i)^(" + "|".join(_escape(s) for s in _SOURCE_NAME_TOKENS) + ")$"
        )
        source_attr_re = (
            "(?i).*(self|obj|config|options|args)[.].*("
            + "|".join(_escape(s) for s in _SOURCE_NAME_TOKENS)
            + ")(.*)?"
        )
        external_source_re = "(?si).*(" + "|".join(_EXTERNAL_SOURCE_PATTERNS) + ").*"
        # Calls whose *short* name matches the last segment of the source pattern.
        # E.g. "input", "getenv" are callables; attribute reads remain field accesses.
        source_call_tails = sorted(
            {
                s.rsplit(".", 1)[-1]
                for s in source_tokens
                if "." not in s or s.rsplit(".", 1)[-1] in {"getenv", "input"}
            }
        )
        source_call_names_scala = ",".join(f'"{n}"' for n in source_call_tails)
        source_branches = [
            "cpg.fieldAccess" f'.code("""{source_code_re}""").l',
            "cpg.call"
            f".filter(c => Set({source_call_names_scala}).contains(c.name)).l",
        ]
        if modeling_mode in {
            "catalog_parameter",
            "catalog_parameter_attribute",
            "full_wrapper",
        }:
            source_branches.append(
                "cpg.method.parameter"
                f'.name("""{source_name_re}""")'
                ".filter(p => p.method.call"
                f".filter(c => Set({direct_sink_names_scala}).contains(c.name))"
                f'.code("""{sink_prefix_re}""")'
                ".nonEmpty).l"
            )
        if modeling_mode in {"catalog_parameter_attribute", "full_wrapper"}:
            source_branches.append(
                "cpg.fieldAccess"
                f'.code("""{source_attr_re}""")'
                ".filter(a => a.method.call"
                f".filter(c => Set({direct_sink_names_scala}).contains(c.name))"
                f'.code("""{sink_prefix_re}""")'
                ".nonEmpty).l"
            )
        source_expr = " ++ ".join(source_branches)

        # Single-expression query: the CPGQL server echoes *every* top-level
        # val binding, so we inline everything into one chained call whose
        # final result (a JSON string) is the only value the REPL prints.
        return (
            "cpg.call"
            f".filter(c => Set({sink_names_scala}).contains(c.name))"
            f'.filter(c => Set({wrapper_names_scala}).contains(c.name) || c.code.matches("""{sink_prefix_re}"""))'
            ".iterator"
            ".reachableByFlows("
            f"({source_expr}).iterator"
            ").l.map { f => Map("
            '"sinkLine"   -> f.elements.last.lineNumber.getOrElse(-1).toString, '
            '"sinkFile"   -> f.elements.last.file.name.headOption.getOrElse(""), '
            '"sinkCode"   -> f.elements.last.code.take(300).replace("\\n", " "), '
            '"sinkName"   -> (f.elements.last match { '
            "case c: io.shiftleft.codepropertygraph.generated.nodes.Call => c.name; "
            'case _ => "" }), '
            '"sinkMethodName"   -> (f.elements.last match { '
            "case c: io.shiftleft.codepropertygraph.generated.nodes.Call => c.method.name; "
            'case _ => "" }), '
            '"sinkKind"   -> (f.elements.last match { '
            "case c: io.shiftleft.codepropertygraph.generated.nodes.Call => "
            f'if (Set({wrapper_names_scala}).contains(c.name)) "wrapper" else "direct"; '
            'case _ => "unknown" }), '
            '"sinkCallsite" -> (f.elements.last match { '
            "case c: io.shiftleft.codepropertygraph.generated.nodes.Call => Map("
            '"file" -> c.file.name.headOption.getOrElse(""), '
            '"line" -> c.lineNumber.getOrElse(-1).toString, '
            '"code" -> c.code.take(200).replace("\\n", " "), '
            '"methodFullName" -> c.method.fullName, '
            '"matchesExternal" -> c.code.matches("""'
            f"{external_source_re}"
            '""")); '
            "case _ => Map.empty }), "
            '"sourceKind" -> (f.elements.head.getClass.getSimpleName match { '
            'case _ if f.elements.head.code.matches("""'
            f"{external_source_re}"
            '""") => "external"; '
            'case n if n.toLowerCase.contains("parameter") => "parameter"; '
            'case _ if f.elements.head.code.matches("""'
            f"{source_code_re}"
            '""") => "catalog"; '
            'case _ if f.elements.head.code.matches("""'
            f"{source_attr_re}"
            '""") => "attribute"; '
            'case _ => "catalog" }), '
            '"sourceLine" -> f.elements.head.lineNumber.getOrElse(-1).toString, '
            '"sourceFile" -> f.elements.head.file.name.headOption.getOrElse(""), '
            '"sourceCode" -> f.elements.head.code.take(200).replace("\\n", " "), '
            '"sourceNodeType" -> f.elements.head.getClass.getSimpleName, '
            '"originEvidence" -> (f.elements.head match { '
            "case p: io.shiftleft.codepropertygraph.generated.nodes.MethodParameterIn => "
            "p.method.ast.isCall"
            f'.code("""{external_source_re}""")'
            ".take(3).map { c => Map("
            '"file" -> c.file.name.headOption.getOrElse(""), '
            '"line" -> c.lineNumber.getOrElse(-1).toString, '
            '"code" -> c.code.take(300).replace("\\n", " "), '
            '"matchesExternal" -> true'
            ") }.l; "
            "case _ => List.empty }), "
            '"callerChain" -> (f.elements.head match { '
            "case p: io.shiftleft.codepropertygraph.generated.nodes.MethodParameterIn => "
            "p.method.callIn.take(3).map { c => "
            "val idx = p.index; "
            'val argCode = c.argument.argumentIndex(idx).code.headOption.getOrElse(""); '
            "Map("
            '"file" -> c.file.name.headOption.getOrElse(""), '
            '"line" -> c.lineNumber.getOrElse(-1).toString, '
            '"code" -> c.code.take(300).replace("\\n", " "), '
            '"argumentCode" -> argCode.take(300).replace("\\n", " "), '
            '"matchesExternal" -> argCode.matches("""'
            f"{external_source_re}"
            '""")'
            ") }.l; "
            "case _ => List.empty }), "
            '"sinkCallerChain" -> (f.elements.last match { '
            "case c: io.shiftleft.codepropertygraph.generated.nodes.Call => "
            f"if (Set({direct_sink_names_scala}).contains(c.name)) "
            "{ c.method.callIn.take(8).map { caller => Map("
            '"file" -> caller.file.name.headOption.getOrElse(""), '
            '"line" -> caller.lineNumber.getOrElse(-1).toString, '
            '"code" -> caller.code.take(200).replace("\\n", " "), '
            '"callerMethod" -> caller.method.fullName, '
            '"matchesExternal" -> caller.code.matches("""'
            f"{external_source_re}"
            '""")) }.l } else List.empty; '
            "case _ => List.empty }), "
            '"flowPath"   -> f.elements.map { e => Map('
            '"file" -> e.file.name.headOption.getOrElse(""), '
            '"line" -> e.lineNumber.getOrElse(-1).toString, '
            '"code" -> e.code.take(300).replace("\\n", " "), '
            '"nodeType" -> e.getClass.getSimpleName'
            ") }"
            ") }.toJson"
        )

    @staticmethod
    def _build_wrapper_discovery_query(sinks: list[str], *, limit: int = 12) -> str:
        """Build a query that discovers local sink-wrapper methods."""

        def _escape(s: str) -> str:
            return s.replace("\\", "\\\\").replace('"', '\\"').replace(".", "\\.")

        sink_names = sorted({s.rsplit(".", 1)[-1] for s in sinks if s})
        sink_prefix_re = "(?s)^(" + "|".join(_escape(s) for s in sinks) + ")\\(.*"
        sink_names_scala = ",".join(f'"{n}"' for n in sink_names)
        source_name_re = (
            "(?i)^(" + "|".join(_escape(s) for s in _SOURCE_NAME_TOKENS) + ")$"
        )
        return (
            "cpg.call"
            f".filter(c => Set({sink_names_scala}).contains(c.name))"
            f'.code("""{sink_prefix_re}""")'
            f'.filter(c => !c.file.name.headOption.getOrElse("").matches("""{_LOW_SIGNAL_PATH_RE}"""))'
            f'.filter(c => c.method.parameter.name("""{source_name_re}""").nonEmpty)'
            '.filter(c => !Set("run","call","system","popen","Popen","execute").contains(c.method.name) || '
            f'c.method.name.matches("""(?i).*({"|".join(_PROJECT_WRAPPER_HINTS)}).*"""))'
            f".take({limit}).l.map {{ c => "
            "val m = c.method; "
            'Map("name" -> m.name, '
            '"filename" -> m.filename, '
            '"lineNumber" -> m.lineNumber.getOrElse(-1).toString, '
            '"wrappedSinkName" -> c.name, '
            '"wrappedSinkCode" -> c.code.take(300).replace("\\n", " ")) '
            "}.toJson"
        )

    @staticmethod
    def _parse_taint_results(
        raw: Any,
        *,
        wrapper_sinks: list[dict[str, Any]] | None = None,
    ) -> list[Finding]:
        """Convert the JSON records produced by ``_build_taint_query`` to Findings."""
        if not raw:
            return []
        if not isinstance(raw, list):
            return []

        wrapper_by_name = {
            str(item.get("name", "")): item
            for item in (wrapper_sinks or [])
            if item.get("name")
        }
        findings: list[Finding] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            JoernArm._annotate_finding_metadata(item, wrapper_by_name)
            report = JoernArm._select_report_location(item)
            fp = report["file"]
            ls = report["line"]
            item["reportFile"] = fp
            item["reportLine"] = str(ls)
            item["reportReason"] = report["reason"]
            item["reportCandidateLocations"] = report.get("candidates", [])
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

    @staticmethod
    def _annotate_finding_metadata(
        item: dict[str, Any],
        wrapper_by_name: dict[str, dict[str, Any]],
    ) -> None:
        """Attach source/sink modeling and semantic metadata to a raw finding."""
        source_code = str(item.get("sourceCode", "") or "")
        sink_code = str(item.get("sinkCode", "") or "")
        sink_file = str(item.get("sinkFile", "") or "")
        sink_name = str(item.get("sinkName", "") or "")
        item["sinkMethodName"] = str(item.get("sinkMethodName", "") or "")

        item.setdefault("sourceKind", JoernArm._infer_source_kind(source_code, item))
        wrapper = wrapper_by_name.get(sink_name)
        if wrapper:
            item["sinkKind"] = "wrapper"
            item["wrapperName"] = sink_name
            item["wrappedSinkName"] = str(wrapper.get("wrappedSinkName", "") or "")
            item["wrappedSinkCode"] = str(wrapper.get("wrappedSinkCode", "") or "")
        else:
            item.setdefault("sinkKind", "direct")

        features = JoernArm._sink_semantic_features(sink_code, sink_file)
        item.update(features)
        origin_evidence = JoernArm._normalise_evidence_list(item.get("originEvidence"))
        caller_chain = JoernArm._normalise_evidence_list(
            item.get("callerChain") or item.get("inCallEvidence")
        )
        sink_callsite = JoernArm._normalise_evidence_record(item.get("sinkCallsite"))
        sink_caller_chain = JoernArm._normalise_evidence_list(
            item.get("sinkCallerChain"), limit=8
        )
        item["originEvidence"] = origin_evidence
        item["callerChain"] = caller_chain
        item["sinkCallsite"] = sink_callsite
        item["sinkCallerChain"] = sink_caller_chain
        item["originExternalSource"] = bool(
            item.get("sourceKind") == "external"
            or any(bool(record.get("matchesExternal")) for record in origin_evidence)
            or any(bool(record.get("matchesExternal")) for record in caller_chain)
            or bool(sink_callsite.get("matchesExternal"))
            or any(bool(record.get("matchesExternal")) for record in sink_caller_chain)
        )

    @staticmethod
    def _infer_source_kind(source_code: str, item: dict[str, Any]) -> str:
        explicit = str(item.get("sourceKind", "") or "")
        if explicit:
            return explicit
        node_type = str(item.get("sourceNodeType", "") or "").lower()
        if _is_external_source_code(source_code):
            return "external"
        if "parameter" in node_type:
            return "parameter"
        lowered = source_code.lower()
        if "." in source_code and any(tok in lowered for tok in _SOURCE_NAME_TOKENS):
            return "attribute"
        if lowered in _SOURCE_NAME_TOKENS:
            return "parameter"
        return "catalog"

    @staticmethod
    def _normalise_evidence_record(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            return {}
        return {
            "file": str(value.get("file", "") or ""),
            "line": str(value.get("line", "") or ""),
            "code": str(value.get("code", "") or ""),
            "argumentCode": str(value.get("argumentCode", "") or ""),
            "callerMethod": str(
                value.get("callerMethod", "") or value.get("methodFullName", "") or ""
            ),
            "methodFullName": str(value.get("methodFullName", "") or ""),
            "matchesExternal": bool(value.get("matchesExternal", False)),
        }

    @staticmethod
    def _normalise_evidence_list(value: Any, *, limit: int = 3) -> list[dict[str, Any]]:
        if not isinstance(value, list):
            return []
        out: list[dict[str, Any]] = []
        for item in value[:limit]:
            if isinstance(item, dict):
                normalised = JoernArm._normalise_evidence_record(item)
                if normalised:
                    out.append(normalised)
        return out

    @staticmethod
    def _merge_origin_evidence(
        existing: list[dict[str, Any]],
        new_records: list[dict[str, Any]],
        *,
        limit: int = 3,
    ) -> list[dict[str, Any]]:
        """Merge local-origin evidence while preserving order and cap."""
        merged: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        for record in [*existing, *new_records]:
            key = (
                str(record.get("file", "") or ""),
                str(record.get("line", "") or ""),
                str(record.get("code", "") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(
                {
                    "file": key[0],
                    "line": key[1],
                    "code": key[2],
                    "argumentCode": str(record.get("argumentCode", "") or ""),
                    "matchesExternal": bool(record.get("matchesExternal", False)),
                }
            )
            if len(merged) >= limit:
                break
        return merged

    @staticmethod
    def _add_python_origin_evidence(
        metadata: dict[str, Any],
        repo: Path,
        *,
        radius: int = 20,
    ) -> None:
        """Fallback origin scan around the source node when CPGQL evidence is empty."""
        source_kind = str(metadata.get("sourceKind", "") or "")
        if source_kind not in {"parameter", "attribute"}:
            return
        existing = JoernArm._normalise_evidence_list(metadata.get("originEvidence"))
        if existing:
            metadata["originEvidence"] = existing
            return
        source_file = str(metadata.get("sourceFile", "") or "")
        try:
            source_line = int(metadata.get("sourceLine", 0) or 0)
        except (TypeError, ValueError):
            source_line = 0
        if not source_file or source_line <= 0:
            return
        fp = Path(source_file)
        if not fp.is_absolute():
            fp = repo / fp
        try:
            lines = fp.read_text().splitlines()
        except OSError:
            return
        start = max(0, source_line - 1 - radius)
        end = min(len(lines), source_line + radius)
        records: list[dict[str, Any]] = []
        for idx in range(start, end):
            code = lines[idx].strip()
            if not code or not _EXTERNAL_SOURCE_RE.search(code):
                continue
            records.append(
                {
                    "file": source_file,
                    "line": str(idx + 1),
                    "code": code,
                    "argumentCode": "",
                    "matchesExternal": True,
                }
            )
            if len(records) >= 3:
                break
        if not records:
            return
        metadata["originEvidence"] = JoernArm._merge_origin_evidence(existing, records)
        metadata["originExternalSource"] = bool(
            metadata.get("sourceKind") == "external"
            or any(
                bool(record.get("matchesExternal"))
                for record in metadata.get("originEvidence", [])
            )
            or any(
                bool(record.get("matchesExternal"))
                for record in JoernArm._normalise_evidence_list(
                    metadata.get("callerChain")
                )
            )
            or bool(
                JoernArm._normalise_evidence_record(metadata.get("sinkCallsite")).get(
                    "matchesExternal"
                )
            )
            or any(
                bool(record.get("matchesExternal"))
                for record in JoernArm._normalise_evidence_list(
                    metadata.get("sinkCallerChain"), limit=8
                )
            )
        )

    @staticmethod
    def _sink_semantic_features(sink_code: str, sink_file: str = "") -> dict[str, bool]:
        code = sink_code.lower()
        stripped = sink_code.strip()
        return {
            "shell_true": "shell=true" in code,
            "shell_false": "shell=false" in code,
            "argv_list_like": stripped.startswith("[")
            or "([" in stripped
            or ".split(" in code,
            "string_command_like": "shell=true" in code
            or stripped.startswith(("f'", 'f"', "'", '"')),
            "shlex_split_input": "shlex.split" in code or ".split(" in code,
            "literal_command_like": stripped.startswith(("'", '"'))
            or '("' in stripped
            or "('" in stripped,
            "test_file": any(
                marker in sink_file.lower() for marker in _TEST_PATH_MARKERS
            ),
        }

    @staticmethod
    def _low_signal_path(path: str) -> bool:
        lowered = f"/{path.lower().lstrip('/')}"
        return any(marker in lowered for marker in _LOW_SIGNAL_PATH_MARKERS)

    @staticmethod
    def _select_report_location(item: dict[str, Any]) -> dict[str, Any]:
        """Pick the best primary location for a Joern flow finding.

        The sink endpoint is often a shared helper (`run(cmd)`), while the
        benchmark line may be the caller that constructs or passes the command.
        Prefer call-like flow nodes before the terminal sink, but retain the
        sink endpoint as a deterministic fallback.
        """

        def _to_int(value: Any) -> int:
            try:
                return int(value)
            except (TypeError, ValueError):
                return 0

        sink_file = str(item.get("sinkFile", "") or "")
        sink_line = _to_int(item.get("sinkLine", 0))
        sink_code = str(item.get("sinkCode", "") or "")
        sink_name = str(item.get("sinkName", "") or "")
        sink_kind = str(item.get("sinkKind", "") or "")
        sink_method_name = str(item.get("sinkMethodName", "") or "").lower()
        wrapper_name = str(
            item.get("wrapperName", "") or item.get("sinkName", "") or ""
        ).lower()
        source_line = _to_int(item.get("sourceLine", 0))
        source_node_type = str(item.get("sourceNodeType", "") or "").lower()
        flow_path = item.get("flowPath") or []

        def _known_sink_code(code: str) -> bool:
            lowered = code.lower()
            return any(
                token in lowered
                for token in (
                    "os.system",
                    "subprocess.",
                    "os.popen",
                    "popen(",
                    "commands.getoutput",
                    "create_subprocess_shell",
                    "shell=true",
                )
            )

        def _command_construction_code(code: str) -> bool:
            lowered = code.lower()
            return any(
                token in lowered
                for token in ("cmd", "command", "shell", "checkout", "clone")
            )

        def _shared_prefix_depth(left: str, right: str) -> int:
            left_parts = Path(left).parts
            right_parts = Path(right).parts
            depth = 0
            for left_part, right_part in zip(left_parts, right_parts, strict=False):
                if left_part != right_part:
                    break
                depth += 1
            return depth

        def _same_package(left: str, right: str) -> bool:
            if not left or not right:
                return False
            if Path(left).parent == Path(right).parent:
                return True
            return _shared_prefix_depth(left, right) >= 2

        def _signature_or_declaration_node(code: str, node_type: str = "") -> bool:
            stripped = code.strip()
            lowered = stripped.lower()
            return bool(
                "methodparameter" in node_type.lower()
                or re.match(r"^(async\s+)?def\s+", stripped)
                or re.match(r"^(from\s+\S+\s+)?import\s+", stripped)
                or lowered.startswith("typing.")
                or re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*:\s*typing[.]", stripped)
            )

        def _downstream_relocation(start_idx: int) -> dict[str, Any] | None:
            if not isinstance(flow_path, list):
                return None
            for idx, node in enumerate(flow_path):
                if idx <= start_idx or not isinstance(node, dict):
                    continue
                file_path = str(node.get("file", "") or "")
                line = _to_int(node.get("line", 0))
                code = str(node.get("code", "") or "")
                if not file_path or line <= 0:
                    continue
                if _known_sink_code(code) or _command_construction_code(code):
                    return {
                        "file": file_path,
                        "line": line,
                        "reason": "signature_guard_relocation",
                    }
            return None

        def _evidence_location(
            record: dict[str, Any],
            *,
            default_reason: str,
        ) -> dict[str, Any] | None:
            file_path = str(record.get("file", "") or "")
            line = _to_int(record.get("line", 0))
            if not file_path or line <= 0:
                return None
            low_signal = JoernArm._low_signal_path(file_path)
            reason = "wrapper_caller_callsite_test" if low_signal else default_reason
            return {
                "file": file_path,
                "line": line,
                "reason": reason,
                "code": str(record.get("code", "") or ""),
                "caller_external": bool(record.get("matchesExternal", False)),
                "low_signal": low_signal,
            }

        def _sink_caller_locations() -> list[dict[str, Any]]:
            locations: list[dict[str, Any]] = []
            sink_caller_chain = item.get("sinkCallerChain") or []
            if isinstance(sink_caller_chain, list):
                for record in sink_caller_chain:
                    if not isinstance(record, dict):
                        continue
                    loc = _evidence_location(
                        record, default_reason="wrapper_caller_callsite"
                    )
                    if loc is not None:
                        locations.append(loc)
            sink_callsite = item.get("sinkCallsite") or {}
            if isinstance(sink_callsite, dict):
                loc = _evidence_location(sink_callsite, default_reason="sink_callsite")
                if loc is not None:
                    locations.append(loc)
            return locations

        def _upstream_relocation() -> dict[str, Any] | None:
            wrapper_named_direct_sink = (
                sink_method_name in _GENERIC_WRAPPER_NAMES
                or bool(sink_method_name)
                and any(hint in sink_method_name for hint in _PROJECT_WRAPPER_HINTS)
            )
            wrapper_like_sink = (
                sink_kind == "wrapper"
                or (
                    sink_name.lower() in _GENERIC_WRAPPER_NAMES
                    and not _known_sink_code(sink_code)
                )
                or wrapper_named_direct_sink
            )
            if not wrapper_like_sink:
                return None
            if not sink_file:
                return None
            candidates: list[dict[str, Any]] = []
            for loc in _sink_caller_locations():
                file_path = str(loc.get("file", "") or "")
                if file_path == sink_file:
                    continue
                code = str(loc.get("code", "") or "")
                caller_external = bool(loc.get("caller_external", False))
                if not _same_package(file_path, sink_file):
                    continue
                if caller_external or _command_construction_code(code):
                    rank = (
                        int(not caller_external),
                        int(not _command_construction_code(code)),
                        int(bool(loc.get("low_signal", False))),
                    )
                    candidates.append({**loc, "rank": rank})
            if not candidates:
                return None
            best = sorted(candidates, key=lambda c: c["rank"])[0]
            return {
                "file": best["file"],
                "line": best["line"],
                "reason": "wrapper_caller_relocation",
            }

        def _candidate_locations(
            selected: dict[str, Any],
            flow_candidates: list[dict[str, Any]],
        ) -> list[dict[str, Any]]:
            caller_candidates: list[dict[str, Any]] = []
            caller_chain = item.get("callerChain") or []
            if isinstance(caller_chain, list):
                for record in caller_chain:
                    if not isinstance(record, dict):
                        continue
                    caller_candidates.append(
                        {
                            "file": str(record.get("file", "") or ""),
                            "line": _to_int(record.get("line", 0)),
                            "reason": (
                                "wrapper_caller_callsite_test"
                                if JoernArm._low_signal_path(
                                    str(record.get("file", "") or "")
                                )
                                else "caller_consumer_callsite"
                            ),
                            "code": str(record.get("code", "") or ""),
                            "caller_external": bool(
                                record.get("matchesExternal", False)
                            ),
                        }
                    )
            locations: list[dict[str, Any]] = []
            raw_locations = [
                {
                    "file": selected.get("file", ""),
                    "line": selected.get("line", 0),
                    "reason": selected.get("reason", ""),
                },
                {"file": sink_file, "line": sink_line, "reason": "sink_endpoint"},
                *flow_candidates[:3],
                *caller_candidates,
                *_sink_caller_locations(),
            ]
            seen: set[tuple[str, int, str]] = set()
            for loc in raw_locations:
                file_path = str(loc.get("file", "") or "")
                line = _to_int(loc.get("line", 0))
                reason = str(loc.get("reason", "") or "")
                key = (file_path, line, reason)
                if file_path and line > 0 and key not in seen:
                    seen.add(key)
                    record = {"file": file_path, "line": line, "reason": reason}
                    if "caller_external" in loc:
                        record["caller_external"] = bool(loc.get("caller_external"))
                    if loc.get("code") and (
                        "caller_external" in loc
                        or reason
                        in {
                            "caller_consumer_callsite",
                            "wrapper_caller_callsite",
                            "wrapper_caller_callsite_test",
                            "sink_callsite",
                        }
                    ):
                        record["code"] = str(loc.get("code", ""))
                    locations.append(record)
            return locations

        if isinstance(flow_path, list):
            candidates: list[dict[str, Any]] = []
            internal_sinks: list[dict[str, Any]] = []
            for idx, node in enumerate(flow_path):
                if not isinstance(node, dict):
                    continue
                file_path = str(node.get("file", "") or "")
                line = _to_int(node.get("line", 0))
                code = str(node.get("code", "") or "")
                node_type = str(node.get("nodeType", "") or "").lower()
                if not file_path or line <= 0:
                    continue
                if _known_sink_code(code):
                    internal_sinks.append(
                        {
                            "file": file_path,
                            "line": line,
                            "reason": "wrapper_internal_sink",
                            "rank": (-idx,),
                        }
                    )
                if file_path == sink_file and line == sink_line:
                    continue
                if "call" in node_type or "(" in code:
                    lowered_code = code.lower()
                    is_wrapperish = (
                        wrapper_name
                        and wrapper_name in lowered_code
                        and wrapper_name in _GENERIC_WRAPPER_NAMES
                    )
                    is_low_signal = JoernArm._low_signal_path(file_path)
                    is_command_construction = _command_construction_code(code)
                    if is_command_construction and not is_low_signal:
                        reason = "flow_command_construction"
                    elif not is_wrapperish and not is_low_signal:
                        reason = "flow_non_wrapper_callsite"
                    else:
                        reason = "flow_callsite"
                    candidates.append(
                        {
                            "file": file_path,
                            "line": line,
                            "reason": reason,
                            "code": code,
                            "nodeType": node_type,
                            "idx": idx,
                            "rank": (
                                0 if reason == "flow_command_construction" else 1,
                                0 if reason == "flow_non_wrapper_callsite" else 1,
                                int(is_low_signal),
                                int(is_wrapperish and sink_kind == "wrapper"),
                                -idx,
                            ),
                        }
                    )
            if candidates:
                best = sorted(candidates, key=lambda c: c["rank"])[0]
                wrapper_like = sink_kind == "wrapper" or (
                    sink_name.lower() in _GENERIC_WRAPPER_NAMES
                    and not _known_sink_code(sink_code)
                )
                source_signature_report = (
                    line := _to_int(best.get("line", 0))
                ) == source_line and "parameter" in source_node_type
                declaration_report = _signature_or_declaration_node(
                    str(best.get("code", "") or ""),
                    str(best.get("nodeType", "") or ""),
                )
                if source_signature_report or declaration_report:
                    relocated = _downstream_relocation(_to_int(best.get("idx", -1)))
                    if relocated:
                        selected = relocated
                        selected["candidates"] = _candidate_locations(
                            selected, candidates
                        )
                        return selected
                if wrapper_like:
                    upstream = _upstream_relocation()
                    if upstream:
                        selected = upstream
                        selected["candidates"] = _candidate_locations(
                            selected, candidates
                        )
                        return selected
                if internal_sinks and (wrapper_like or source_signature_report):
                    internal = sorted(internal_sinks, key=lambda c: c["rank"])[0]
                    selected = {
                        "file": internal["file"],
                        "line": internal["line"],
                        "reason": internal["reason"],
                    }
                    selected["candidates"] = _candidate_locations(selected, candidates)
                    return selected
                selected = {
                    "file": best["file"],
                    "line": best["line"],
                    "reason": best["reason"],
                }
                selected["candidates"] = _candidate_locations(selected, candidates)
                return selected
            if internal_sinks:
                upstream = _upstream_relocation()
                if upstream:
                    selected = upstream
                    selected["candidates"] = _candidate_locations(selected, [])
                    return selected
                internal = sorted(internal_sinks, key=lambda c: c["rank"])[0]
                selected = {
                    "file": internal["file"],
                    "line": internal["line"],
                    "reason": internal["reason"],
                }
                selected["candidates"] = _candidate_locations(selected, [])
                return selected

        upstream = _upstream_relocation()
        if upstream:
            selected = upstream
            selected["candidates"] = _candidate_locations(selected, [])
            return selected

        selected = {
            "file": sink_file,
            "line": sink_line,
            "reason": "sink_endpoint",
        }
        selected["candidates"] = _candidate_locations(selected, [])
        return selected
