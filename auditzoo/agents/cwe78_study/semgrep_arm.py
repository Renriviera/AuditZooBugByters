"""Semgrep arm: pattern-based static analysis for CWE-78.

Runs Semgrep with custom YAML rules, enriches findings with surrounding
context, and supports iterative rule refinement.
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import yaml

from .schemas import Finding, ToolArm

logger = logging.getLogger(__name__)

_SEED_RULES_DIR = Path(__file__).parent / "seed_rules"


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
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as tmp:
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
            logger.warning("semgrep exited with code %d: %s", result.returncode, result.stderr[:500])

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
            ctx = "\n".join(
                f"{i + 1:>5}| {lines[i]}" for i in range(start, end)
            )
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

    def apply_refinement(self, action: str, rule_yaml_patch: str, target_rule_id: str = "") -> None:
        """Mutate the internal rule set based on LLM Call 1 output.

        *action* is one of ``keep``, ``refine``, ``add_rule``.
        """
        if action == "keep":
            return

        current = yaml.safe_load(self._rules_yaml)
        if current is None:
            current = {"rules": []}

        if action == "refine" and target_rule_id:
            patch = yaml.safe_load(rule_yaml_patch)
            if isinstance(patch, dict) and "rules" in patch:
                patch_rule = patch["rules"][0] if patch["rules"] else patch
            else:
                patch_rule = patch

            for idx, rule in enumerate(current.get("rules", [])):
                if rule.get("id") == target_rule_id:
                    current["rules"][idx] = patch_rule
                    break
        elif action == "add_rule":
            patch = yaml.safe_load(rule_yaml_patch)
            if isinstance(patch, dict) and "rules" in patch:
                current["rules"].extend(patch["rules"])
            elif isinstance(patch, dict):
                current["rules"].append(patch)

        self._rules_yaml = yaml.dump(current, default_flow_style=False, sort_keys=False)

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
