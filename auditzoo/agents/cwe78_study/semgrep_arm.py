"""Semgrep arm: pattern-based static analysis for CWE-78.

Runs Semgrep with custom YAML rules, enriches findings with surrounding
context, and supports iterative rule refinement.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml

from .schemas import Finding, ToolArm

logger = logging.getLogger(__name__)

_SEED_RULES_DIR = Path(__file__).parent / "seed_rules"


def _semgrep_env() -> dict[str, str]:
    """Prefer the active Python environment and Semgrep's bundled core."""
    env = os.environ.copy()
    path_parts: list[str] = [str(Path(sys.executable).resolve().parent)]
    try:
        import semgrep

        core_bin = Path(semgrep.__file__).resolve().parent / "bin"
        if core_bin.is_dir():
            path_parts.append(str(core_bin))
    except Exception as exc:  # pragma: no cover - diagnostic fallback
        logger.debug("Could not locate Semgrep package bin dir: %s", exc)
    path_parts.append(env.get("PATH", ""))
    env["PATH"] = os.pathsep.join(part for part in path_parts if part)
    return env


def _parse_rule_patch(rule_yaml_patch: str) -> dict[str, Any] | None:
    """Normalise an LLM-supplied rule YAML patch into a single rule dict.

    Accepts any of the three shapes we see in the wild:

    * ``{"rules": [<rule>, ...]}`` — full Semgrep rules document,
    * ``[<rule>, ...]``            — bare list of rules,
    * ``<rule>``                   — a single rule dict.

    Returns the first rule dict encountered (with a non-empty ``id``) or
    ``None`` if parsing fails or no rule was found.  A valid Semgrep rule
    must be a mapping with an ``id`` key — empty strings, lists of
    strings, or ``None`` are treated as no-op.
    """
    if not (rule_yaml_patch or "").strip():
        return None
    try:
        patch = yaml.safe_load(rule_yaml_patch)
    except yaml.YAMLError as exc:
        logger.warning("Semgrep refinement patch failed to parse: %s", exc)
        return None

    if isinstance(patch, dict) and "rules" in patch:
        rules = patch.get("rules") or []
        patch = rules[0] if rules else None
    elif isinstance(patch, list):
        patch = patch[0] if patch else None

    if not isinstance(patch, dict):
        return None
    if not patch.get("id"):
        return None
    return patch


class SemgrepArm:
    """Wraps Semgrep CLI invocation and finding extraction."""

    def __init__(
        self,
        rules_yaml: str | None = None,
        context_lines: int = 10,
    ) -> None:
        if rules_yaml is None:
            rules_yaml = (_SEED_RULES_DIR / "cwe78_semgrep.yaml").read_text()
        self._rules_yaml = rules_yaml
        self._context_lines = context_lines

    @property
    def rules_yaml(self) -> str:
        return self._rules_yaml

    @rules_yaml.setter
    def rules_yaml(self, value: str) -> None:
        self._rules_yaml = value

    def scan(self, repo_path: str | Path) -> list[Finding]:
        """Run Semgrep against *repo_path* using current rules.

        Returns a list of :class:`Finding` dataclass instances.
        """
        repo_path = Path(repo_path)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tmp:
            tmp.write(self._rules_yaml)
            tmp.flush()
            rule_file = tmp.name

        try:
            result = subprocess.run(
                [
                    "semgrep",
                    "--config",
                    rule_file,
                    "--json",
                    "--no-git-ignore",
                    str(repo_path),
                ],
                capture_output=True,
                text=True,
                timeout=300,
                env=_semgrep_env(),
            )
        except FileNotFoundError:
            logger.error("semgrep not found on PATH")
            return []
        except subprocess.TimeoutExpired:
            logger.error("semgrep scan timed out after 300 s")
            return []
        finally:
            Path(rule_file).unlink(missing_ok=True)

        if result.returncode not in (0, 1):
            logger.warning(
                "semgrep exited with code %d: %s",
                result.returncode,
                result.stderr[:500],
            )

        return self._parse_output(result.stdout, repo_path)

    def get_findings_with_context(
        self,
        findings: list[Finding],
    ) -> list[Finding]:
        """Enrich each finding with surrounding source lines."""
        enriched: list[Finding] = []
        for f in findings:
            try:
                lines = Path(f.file_path).read_text().splitlines()
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

    def apply_refinement(
        self, action: str, rule_yaml_patch: str, target_rule_id: str = ""
    ) -> str:
        """Mutate the internal rule set based on LLM Call 1 output.

        *action* is one of ``keep``, ``refine``, ``add_rule``.  Returns a
        short audit code describing what actually happened, so callers can
        distinguish genuine mutations from silent no-ops:

        * ``"keep"``                   — action was keep; rules unchanged.
        * ``"refine_replaced"``        — rule with matching id found and
                                         replaced.
        * ``"refine_appended"``        — LLM emitted a refine patch but no
                                         existing rule matched; the patch
                                         was appended instead (treated as
                                         add_rule).
        * ``"add_rule_appended"``      — rule(s) from an add_rule patch
                                         appended.
        * ``"noop_empty_patch"``       — action was refine/add_rule but the
                                         patch could not be parsed as a
                                         rule.

        The function always re-serialises the YAML, so ``rules_hash`` may
        change for purely-cosmetic reasons even when the return code is
        ``"keep"`` (callers should rely on this code, not on the hash, to
        detect real mutations).
        """
        if action == "keep":
            return "keep"

        current = yaml.safe_load(self._rules_yaml)
        if current is None or not isinstance(current, dict):
            current = {"rules": []}
        if "rules" not in current or not isinstance(current.get("rules"), list):
            current["rules"] = []

        patch_rule = _parse_rule_patch(rule_yaml_patch)
        if patch_rule is None:
            # Nothing actionable; skip re-serialisation so callers can
            # see the rules_hash as unchanged.
            return "noop_empty_patch"

        status = ""
        if action == "refine":
            # Prefer an explicit target_rule_id from the LLM; otherwise
            # fall back to the ``id`` field inside the patch itself.
            tid = (target_rule_id or patch_rule.get("id", "")).strip()
            replaced = False
            if tid:
                for idx, rule in enumerate(current["rules"]):
                    if rule.get("id") == tid:
                        current["rules"][idx] = patch_rule
                        replaced = True
                        status = "refine_replaced"
                        break
            if not replaced:
                # Graceful degradation: LLM asked to refine a rule that
                # isn't in the current set, or omitted the id entirely.
                # Treat as add_rule so the k-loop still makes progress.
                current["rules"].append(patch_rule)
                status = "refine_appended"
        elif action == "add_rule":
            current["rules"].append(patch_rule)
            status = "add_rule_appended"
        else:
            return "noop_empty_patch"

        self._rules_yaml = yaml.dump(current, default_flow_style=False, sort_keys=False)
        return status

    # ------------------------------------------------------------------

    @staticmethod
    def _parse_output(stdout: str, repo_path: Path) -> list[Finding]:
        """Convert Semgrep JSON output to Finding list."""
        if not stdout.strip():
            return []
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            logger.error("Failed to parse semgrep JSON output")
            return []

        findings: list[Finding] = []
        for item in data.get("results", []):
            extra = item.get("extra", {})
            metadata = extra.get("metadata", {})
            findings.append(
                Finding(
                    file_path=item.get("path", ""),
                    line_start=item.get("start", {}).get("line", 0),
                    line_end=item.get("end", {}).get("line", 0),
                    rule_id=item.get("check_id", ""),
                    message=extra.get("message", ""),
                    code_snippet=extra.get("lines", ""),
                    sink_api=metadata.get("sink_api", ""),
                    arm=ToolArm.SEMGREP,
                    metadata=metadata,
                )
            )
        return findings
