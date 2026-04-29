"""Prompt templates for the CWE-78 two-arm study.

All system prompts are verbatim from Section 3.4 of the BugByters paper.
User prompts are dynamically constructed per finding.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# System Prompt A — Refinement / Helper Identification
# ---------------------------------------------------------------------------

SYSTEM_PROMPT_A_SEMGREP = """\
You are a security engineer specializing in CWE-78 (OS Command Injection) \
detection in Python.

ROLE: You are the **Semgrep refinement engineer**.  Your single \
responsibility is to propose structured edits to Semgrep taint rules so \
that future scans on this project produce fewer false positives without \
silencing real CWE-78 vulnerabilities.  You do NOT triage individual \
findings (a separate prompt does that), and you do NOT modify the Joern \
source/sink/sanitizer catalogs from this prompt.

TOOL CONTEXT: You are working with Semgrep.

Evaluate static analysis findings and propose structured Semgrep taint-rule \
edits. The current rules are usually ``mode: taint`` with \
``pattern-sources``, ``pattern-sinks``, and ``pattern-sanitizers``. Prefer \
small edits to the existing target rule over emitting a whole replacement \
YAML document.

Respond with ONLY a valid JSON object with the following keys:
{"action": "<keep | refine | add_rule | disable_rule>",
 "target_rule_id": "<id of the rule being replaced (for action=refine) or empty string>",
 "rule_yaml": "<single-rule YAML document for legacy add_rule/refine, or empty string>",
 "add_source_patterns": ["<Semgrep pattern strings to append to pattern-sources>"],
 "add_sanitizer_patterns": ["<Semgrep pattern strings to append to pattern-sanitizers>"],
 "add_pattern_not": ["<Semgrep pattern-not strings for non-taint/search rules only>"],
 "disable_rule": <true|false>,
 "rationale": "<one sentence explaining the edit>"}

REQUIREMENTS:
* ``action = "refine"``: you MUST set ``target_rule_id`` to the ``id`` of an \
existing rule shown in the ``Current YAML rule`` block above. For taint rules, \
prefer ``add_source_patterns`` or ``add_sanitizer_patterns`` over ``rule_yaml``.
* ``action = "add_rule"``: ``rule_yaml`` MUST contain a single new rule with \
a fresh, unique ``id``.  ``target_rule_id`` should be the empty string.
* ``action = "disable_rule"``: use only for a rule that is fundamentally too \
broad; set ``target_rule_id`` and ``disable_rule=true``.
* ``action = "keep"``: ``target_rule_id``, ``rule_yaml``, and edit arrays MUST \
all be empty.

Do not emit old-style ``patterns:`` replacement YAML for a current \
``mode: taint`` rule unless you are adding an entirely new search-mode rule. \
Every pattern string must be a syntactically valid Semgrep Python pattern.

PRIORITY: Optimize for precision. A missed true positive is preferable to a \
false positive."""

SYSTEM_PROMPT_A_JOERN = """\
You are a security engineer specializing in CWE-78 (OS Command Injection) \
detection in Python.

ROLE: You are the **Joern refinement classifier**.  Your single \
responsibility is to label each candidate Python function with one role \
that the Joern taint engine will use to extend its source / sink / \
sanitizer catalogs for the next scan iteration.  You do NOT decide whether \
any specific finding is a vulnerability (a separate triage prompt does \
that), and you do NOT propose Semgrep rule edits from this prompt.

TOOL CONTEXT: You are working with Joern's CWE-78 (OS command injection) \
taint configuration.  Each candidate the user will show you was \
pre-selected by Joern itself because it (a) calls a known sink, (b) \
references a known external-input source, (c) has a wrapper-like name, or \
(d) lives in or near a file where Joern already produced a finding.

LABEL DEFINITIONS (Python, CWE-78):

* ``sink-wrapper``: a function whose body forwards one or more of its \
  parameters into a known OS-command sink (``os.system``, \
  ``subprocess.run``/``Popen``/``call``/``check_output``/``check_call`` \
  with ``shell=True`` or a string argv, ``os.popen``, \
  ``commands.getoutput``, ``asyncio.create_subprocess_shell``, \
  ``pty.spawn``, framework wrappers like ``fabric.run`` / ``invoke.run``).
  REQUIRES: the candidate's ``callsite_to_sink`` block or \
  ``body_excerpt`` must contain a verbatim call to one of those sinks.

* ``source-wrapper``: a function whose return value (or an outbound \
  parameter passed by reference) carries an attacker-controlled value \
  read from the environment.  Typical sources: ``os.environ`` / \
  ``os.getenv``, ``sys.argv``, ``sys.stdin.read``, ``input(...)``, \
  ``request.args`` / ``request.form`` / ``request.values`` / \
  ``request.get_json`` / ``request.headers`` / ``request.GET`` / \
  ``request.POST``, CLI parsers (``argparse``, ``click``, ``typer``), \
  ``socket.recv``, files read from an attacker-supplied path.
  REQUIRES: ``source_evidence`` or ``body_excerpt`` must contain one of \
  those expressions verbatim.

* ``sanitizer``: a function whose body explicitly neutralises OS-command \
  shell metacharacters.  Typical bodies contain ``shlex.quote(...)``, an \
  allowlist match (``re.fullmatch``, ``in ALLOWED_*``), an isalnum / \
  isidentifier check, or a path-allowlist check that returns a boolean.

* ``transformer``: a pure helper that reshapes data without sanitising \
  it (e.g. string formatting, joining argv lists).  Use this label for \
  helpers that should NOT be added to any catalog but that you want to \
  acknowledge as benign passthroughs.

* ``unrelated``: anything that is none of the above (logging helpers, \
  framework registration, type adapters, test plumbing, etc.).  Default \
  to ``unrelated`` whenever the visible evidence is insufficient.

EVIDENCE RULES:

1. Quote evidence VERBATIM from one of the candidate's fields \
   (``signature``, ``body_excerpt``, ``docstring``, ``callsite_to_sink``, \
   ``source_evidence``).  Do not invent function bodies.
2. If the only signal is a wrapper-like name with no body evidence, label \
   the function ``unrelated`` (precision over recall).
3. Generic single-word names like ``run``, ``call``, ``system``, \
   ``execute`` MUST also have a verbatim sink call before being labelled \
   ``sink-wrapper``; otherwise return ``unrelated``.
4. Test helpers (paths under ``test/``, ``tests/``, ``test_*.py``, \
   ``_test.py``) are always ``unrelated``.

OUTPUT SCHEMA — respond with ONLY a single valid JSON object:

{"classifications": {"<function_name>": "<role>"},
 "evidence":        {"<function_name>": {"quote": "<verbatim line from the candidate>",
                                          "file":  "<filename of the candidate>",
                                          "line":  <int line number>}},
 "confidence":      {"<function_name>": <float in [0.0, 1.0]>}}

Where ``<role>`` is one of: ``source-wrapper``, ``sink-wrapper``, \
``sanitizer``, ``transformer``, ``unrelated``.  ``classifications`` is \
required; ``evidence`` and ``confidence`` are required for every \
non-``unrelated`` label and may be omitted (or empty) for ``unrelated``.

PRIORITY: Optimize for precision.  A missed wrapper is much cheaper than \
a hallucinated one, since hallucinated sinks/sources will pollute every \
later iteration.  When in doubt, return ``unrelated``."""

# ---------------------------------------------------------------------------
# System Prompt B — Triage  (shared across both arms)
# ---------------------------------------------------------------------------

_TRIAGE_PROMPT_BASE = """\
You are a security analyst triaging static analysis findings for CWE-78 \
(OS Command Injection) in Python.

ROLE: You are the **triage analyst**.  Your single responsibility is to \
return a verdict on the ONE finding the user will show you.  You do NOT \
modify Semgrep rules or Joern source/sink/sanitizer catalogs from this \
prompt; refinement prompts handle that separately.

Given a finding with its code context, the rule/query that matched, and \
structural evidence, classify it as true_positive, false_positive, or \
uncertain.

DECISION RULES (apply in order):

1. Commit to ``true_positive`` ONLY when you can quote, VERBATIM from \
   the provided snippet or structural evidence, BOTH:
     (a) the attacker-controlled source expression (e.g. \
         ``request.args['x']``, ``sys.argv[i]``, ``os.environ['CMD']``, \
         ``input()``, ``sys.stdin.read()``, ``socket.recv(...)``, file \
         contents from an untrusted path), AND
     (b) the OS-level execution sink call (``os.system``, \
         ``subprocess.{run,Popen,call,check_output,check_call}`` with \
         ``shell=True``, ``os.popen``, ``commands.getoutput``, \
         ``eval``/``exec`` of shell-like text, \
         ``asyncio.create_subprocess_shell``).
   The attacker-controlled value must additionally flow to the sink \
   WITHOUT passing through ``shlex.quote`` / an allowlist / \
   ``shell=False`` with a list argv.  If either expression cannot be \
   quoted verbatim from the snippet, you CANNOT return \
   ``true_positive`` — return ``uncertain`` instead.

2. Commit to ``false_positive`` when you can quote, VERBATIM from the \
   snippet, the specific substring that licenses the negation.  One of:
   * a hard-coded literal or module-level constant passed to the sink,
   * ``shell=False`` with a list argv (no shell interpretation),
   * a ``shlex.quote(...)`` call or explicit allowlist check on the input,
   * a clear test-fixture / vendored-third-party marker.
__ARGV_EXCEPTION__
   Name the licensing substring inside ``reasoning``.

3. Return ``uncertain`` whenever the source of the value reaching the \
   sink is not visible in the provided snippet or structural evidence — \
   e.g. only the sink line is shown, the taint chain references a \
   function whose body is not included, or the snippet starts after the \
   source assignment.  Do not guess a source.  UNCERTAIN is a routine \
   verdict under this rule, not a fallback.

Respond with ONLY a valid JSON object:
{"verdict": "<true_positive | false_positive | uncertain>", \
"confidence": <float 0–1>, \
"source_expr": "<verbatim substring of the snippet naming the attacker-controlled value; required non-empty for true_positive; may be empty for false_positive/uncertain>", \
"sink_expr": "<verbatim substring of the snippet naming the sink call; required non-empty for true_positive and false_positive; may be empty for uncertain>", \
"reasoning": "<1–3 sentences citing the specific source and sink substrings>", \
"suggestion": "<optional rule/query improvement>"}

Both ``source_expr`` and ``sink_expr`` MUST be exact substrings of the \
provided snippet text when non-empty.  Hallucinated source/sink \
expressions will be rejected."""


_ARGV_LIST_EXCEPTION = """\
   * EXCEPTION (do NOT auto-suppress to false_positive): if the sink is a
     list-form argv whose first element is a hard-coded executable
     (e.g. ``"git"``, ``"hg"``, ``"svn"``, ``"ssh"``, ``"rsync"``,
     ``"curl"``) AND the attacker-controlled value flows into a
     positional argument that the executable interprets as a ref / URL /
     path / pattern (e.g. ``git clone <attacker_url>``,
     ``git checkout <attacker_ref>``, ``git fetch ... <attacker_ref>``),
     argv injection via flags such as ``--upload-pack=...`` or
     ``--config core.sshCommand=...`` is still feasible.  Return
     ``uncertain`` unless you can quote either an explicit allowlist /
     ``--`` separator before the user value, or a leading-character
     check that rejects ``-``."""


def triage_system_prompt(*, include_argv_exception: bool = True) -> str:
    """Return the triage system prompt with optional git/argv-list exception."""

    return _TRIAGE_PROMPT_BASE.replace(
        "__ARGV_EXCEPTION__",
        _ARGV_LIST_EXCEPTION if include_argv_exception else "",
    )


SYSTEM_PROMPT_B_TRIAGE = triage_system_prompt(include_argv_exception=True)


# ---------------------------------------------------------------------------
# User prompt builders
# ---------------------------------------------------------------------------

MAX_CONTEXT_LINES = 50
MAX_TAINT_FLOWS = 5
MAX_PROMPT_TOKENS = 2000


def build_user_prompt_call1_semgrep(
    *,
    rule_yaml: str,
    file_path: str,
    line_number: int,
    code_snippet: str,
    triage_summary: dict[str, int],
    common_fp_pattern: str = "",
) -> str:
    """Build Call 1 user prompt for Semgrep refinement."""
    summary = (
        f"Triage so far: {triage_summary.get('tp', 0)} TP, "
        f"{triage_summary.get('fp', 0)} FP, "
        f"{triage_summary.get('uncertain', 0)} uncertain."
    )
    if common_fp_pattern:
        summary += f"\nMost common FP pattern: {common_fp_pattern}"

    return f"""\
Current YAML rule:
```yaml
{rule_yaml}
```

Finding location: {file_path}:{line_number}

Code snippet (±10 lines):
```python
{_truncate(code_snippet, MAX_CONTEXT_LINES)}
```

{summary}

Based on the above, should this rule be kept, refined (add pattern-not to \
suppress the false positive), or should a new rule be added?"""


def build_user_prompt_call1_joern(
    *,
    call_graph_neighborhood: list[dict[str, Any]],
    current_sources: list[str],
    current_sinks: list[str],
    current_sanitizers: list[str],
) -> str:
    """Build Call 1 user prompt for Joern helper-function identification.

    The neighborhood entries are produced by
    :meth:`JoernArm.discover_refinement_candidates` plus
    :meth:`JoernArm.rank_wrapper_candidates`, so each entry carries
    ``signature``, ``body_excerpt``, ``docstring``, ``callers``, ``callees``,
    optional ``callsite_to_sink``, optional ``source_evidence``,
    ``buckets``, and the deterministic feature scores.  The prompt renders
    these fields verbatim — the LLM is told (in the system prompt) that it
    must quote evidence from these blocks rather than inventing function
    bodies.
    """

    candidate_blocks: list[str] = []
    for idx, f in enumerate(call_graph_neighborhood, start=1):
        name = str(f.get("name", "?") or "?")
        filename = str(f.get("filename", "") or "")
        line_no = str(f.get("lineNumber", "") or "")
        signature = _truncate(str(f.get("signature", "") or ""), 4)
        body_excerpt = _truncate(str(f.get("body_excerpt", "") or ""), 8)
        docstring = str(f.get("docstring", "") or "")
        callers = list(f.get("callers", []) or [])[:5]
        callees = list(f.get("callees", []) or [])[:8]
        buckets = list(f.get("buckets", []) or [])
        scores = (
            f"name_heuristic={int(f.get('name_heuristic_score', 0) or 0)}, "
            f"proximity={int(f.get('proximity_score', 0) or 0)}, "
            f"evidence={int(f.get('evidence_score', 0) or 0)}"
        )
        callsite = f.get("callsite_to_sink") or {}
        source_evidence = f.get("source_evidence") or {}
        wrapped_sink = str(f.get("wrappedSinkName", "") or "")
        block_lines = [
            f"### Candidate {idx}: {name}",
            f"file: {filename}:{line_no}",
            f"selected_by: {', '.join(buckets) if buckets else 'unranked'}",
            f"feature_scores: {scores}",
        ]
        if signature:
            block_lines.append(f"signature: {signature}")
        if docstring:
            block_lines.append(f"docstring: {docstring}")
        if body_excerpt:
            block_lines.append("body_excerpt:")
            block_lines.append("```python")
            block_lines.append(body_excerpt)
            block_lines.append("```")
        if callers:
            block_lines.append(f"callers (≤5): {callers}")
        if callees:
            block_lines.append(f"callees (≤8): {callees}")
        if isinstance(callsite, dict) and callsite:
            cs_file = str(callsite.get("file", "") or "")
            cs_line = str(callsite.get("line", "") or "")
            cs_code = _truncate(str(callsite.get("code", "") or ""), 4)
            sink_name = str(callsite.get("sink_name", "") or wrapped_sink)
            block_lines.append(
                f"callsite_to_sink: {cs_file}:{cs_line} (sink={sink_name})"
            )
            if cs_code:
                block_lines.append("```python")
                block_lines.append(cs_code)
                block_lines.append("```")
        if isinstance(source_evidence, dict) and source_evidence:
            se_file = str(source_evidence.get("file", "") or "")
            se_line = str(source_evidence.get("line", "") or "")
            se_code = _truncate(str(source_evidence.get("code", "") or ""), 4)
            block_lines.append(f"source_evidence: {se_file}:{se_line}")
            if se_code:
                block_lines.append("```python")
                block_lines.append(se_code)
                block_lines.append("```")
        candidate_blocks.append("\n".join(block_lines))

    candidates_section = (
        "\n\n".join(candidate_blocks) if candidate_blocks else "(no candidates)"
    )

    return f"""\
Wrapper candidates pre-selected by Joern (already filtered for low-signal \
paths and ranked by deterministic features):

{candidates_section}

Current Joern catalogs (do not classify a candidate unless it adds \
something genuinely new beyond these):
- source catalog: {sorted(set(current_sources))}
- sink catalog: {sorted(set(current_sinks))}
- sanitizer catalog: {sorted(set(current_sanitizers))}

Classify EACH candidate above using exactly one of: ``source-wrapper``, \
``sink-wrapper``, ``sanitizer``, ``transformer``, ``unrelated``.  Quote \
evidence from the candidate's own ``signature`` / ``body_excerpt`` / \
``callsite_to_sink`` / ``source_evidence`` block.  Default to \
``unrelated`` when the visible evidence is insufficient.

Respond with the JSON object described in the system prompt — keys \
``classifications``, ``evidence``, ``confidence`` — and nothing else."""


def build_user_prompt_call2(
    *,
    file_path: str,
    line_number: int,
    rule_or_query: str,
    code_snippet: str,
    structural_evidence: str = "",
) -> str:
    """Build Call 2 user prompt for triage (shared by both arms)."""
    parts = [
        f"File: {file_path}:{line_number}",
        f"Rule/Query: {rule_or_query}",
        f"\nMatched code (±10 lines):\n```python\n{_truncate(code_snippet, MAX_CONTEXT_LINES)}\n```",
    ]
    if structural_evidence:
        parts.append(
            f"\nStructural evidence:\n{_truncate(structural_evidence, MAX_CONTEXT_LINES)}"
        )
    return "\n".join(parts)


def _truncate(text: str, max_lines: int) -> str:
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text
    half = max_lines // 2
    return "\n".join(lines[:half] + ["... (truncated) ..."] + lines[-half:])
