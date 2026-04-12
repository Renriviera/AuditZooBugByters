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

Output a JSON object with "action" (keep / refine / add_rule) and optionally \
"rule_yaml".

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
You are a security analyst triaging static analysis findings for CWE-78 in \
Python.

Given a finding with its code context, the rule/query that matched, and \
structural evidence, classify it as true_positive, false_positive, or \
uncertain.

Respond with ONLY a valid JSON object:
{"verdict": "<true_positive | false_positive | uncertain>", \
"confidence": <float 0–1>, \
"reasoning": "<1–3 sentences>", \
"suggestion": "<optional rule/query improvement>"}"""


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
