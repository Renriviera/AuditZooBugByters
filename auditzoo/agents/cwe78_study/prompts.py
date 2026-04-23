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

TOOL CONTEXT: You are working with Semgrep.

Evaluate static analysis findings and propose refined Semgrep YAML rules. \
Add pattern-not clauses to eliminate false positives; broaden patterns if \
known sinks are missed.

Respond with ONLY a valid JSON object with the following keys:
{"action": "<keep | refine | add_rule>",
 "target_rule_id": "<id of the rule being replaced (for action=refine) or empty string>",
 "rule_yaml": "<single-rule YAML document (for action=refine or add_rule) or empty string>"}

REQUIREMENTS:
* ``action = "refine"``: you MUST set ``target_rule_id`` to the ``id`` of an \
existing rule shown in the ``Current YAML rule`` block above, AND ``rule_yaml`` \
MUST contain a single rule whose ``id`` equals ``target_rule_id``.  Omitting \
``target_rule_id`` makes the refinement a no-op — do not do this.
* ``action = "add_rule"``: ``rule_yaml`` MUST contain a single new rule with \
a fresh, unique ``id``.  ``target_rule_id`` should be the empty string.
* ``action = "keep"``: ``target_rule_id`` and ``rule_yaml`` MUST both be empty.

``rule_yaml`` must be a YAML snippet of the form\n``- id: <rule-id>\\n  \
patterns: ...\\n  message: ...\\n  languages: [python]\\n  severity: ERROR\\n  \
metadata:\\n    cwe: "CWE-78"\\n    sink_api: "<sink>"``.

PRIORITY: Optimize for precision. A missed true positive is preferable to a \
false positive."""

SYSTEM_PROMPT_A_JOERN = """\
You are a security engineer specializing in CWE-78 (OS Command Injection) \
detection in Python.

TOOL CONTEXT: You are working with Joern.

Classify helper functions discovered in the call graph. For each function, \
determine whether it is a source-wrapper, sink-wrapper, transformer, \
sanitizer, or unrelated.

Output a JSON object with "classifications" mapping function names to their \
role.

PRIORITY: Optimize for precision. A missed true positive is preferable to a \
false positive."""

# ---------------------------------------------------------------------------
# System Prompt B — Triage  (shared across both arms)
# ---------------------------------------------------------------------------

SYSTEM_PROMPT_B_TRIAGE = """\
You are a security analyst triaging static analysis findings for CWE-78 \
(OS Command Injection) in Python.

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
    """Build Call 1 user prompt for Joern helper-function identification."""
    funcs_block = "\n".join(
        f"- {f.get('name', '?')}: callers={f.get('callers', [])}, "
        f"callees={f.get('callees', [])}\n  source:\n{_truncate(f.get('source', ''), 30)}"
        for f in call_graph_neighborhood
    )

    return f"""\
Call-graph neighborhood functions requiring classification:
{funcs_block}

Current source catalog: {current_sources}
Current sink catalog: {current_sinks}
Current sanitizer catalog: {current_sanitizers}

For each function above, classify it as one of:
source-wrapper, sink-wrapper, transformer, sanitizer, or unrelated."""


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
