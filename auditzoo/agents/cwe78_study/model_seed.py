"""One-time model seeding for CWE-78 Semgrep rules and Joern catalogs."""

from __future__ import annotations

import json
import logging
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from scripts.run_evaluation import clone_and_checkout

from .llm_client import LLMClient
from .prompts import (
    SYSTEM_PROMPT_SEED_JOERN,
    SYSTEM_PROMPT_SEED_SEMGREP,
    build_user_prompt_seed_joern,
    build_user_prompt_seed_semgrep,
)

logger = logging.getLogger(__name__)

_MAX_DIFF_CHARS = 6000
_SNIPPET_RADIUS = 12


@dataclass(frozen=True)
class JoernSeedCatalog:
    """Initial Joern taint catalogs produced by the seed model."""

    sources: list[str]
    sinks: list[str]
    sanitizers: list[str]

    def to_dict(self) -> dict[str, list[str]]:
        return {
            "sources": self.sources,
            "sinks": self.sinks,
            "sanitizers": self.sanitizers,
        }


def parse_semgrep_seed_yaml(response_text: str) -> str:
    """Validate and normalize a model-generated Semgrep rules document."""
    text = _strip_markdown_fence(response_text)
    try:
        loaded = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"Semgrep seed is not valid YAML: {exc}") from exc
    if not isinstance(loaded, dict) or not isinstance(loaded.get("rules"), list):
        raise ValueError("Semgrep seed must be a YAML object with a rules list")
    if not loaded["rules"]:
        raise ValueError("Semgrep seed must contain at least one rule")

    seen_ids: set[str] = set()
    for idx, rule in enumerate(loaded["rules"]):
        if not isinstance(rule, dict):
            raise ValueError(f"Semgrep rule {idx} must be a mapping")
        rule_id = str(rule.get("id", "") or "").strip()
        if not rule_id:
            raise ValueError(f"Semgrep rule {idx} is missing id")
        if rule_id in seen_ids:
            raise ValueError(f"Duplicate Semgrep rule id: {rule_id}")
        seen_ids.add(rule_id)
        if "patterns" not in rule and "pattern" not in rule and "pattern-either" not in rule:
            raise ValueError(f"Semgrep rule {rule_id} has no pattern")
        if rule.get("languages") != ["python"]:
            raise ValueError(f"Semgrep rule {rule_id} must use languages: [python]")
    return yaml.dump(loaded, default_flow_style=False, sort_keys=False)


def parse_joern_seed_catalog(response_text: str | dict[str, Any]) -> JoernSeedCatalog:
    """Validate and normalize a model-generated Joern catalog."""
    if isinstance(response_text, dict):
        loaded = response_text
    else:
        text = _strip_markdown_fence(response_text)
        try:
            loaded = json.loads(text)
        except json.JSONDecodeError as exc:
            try:
                loaded = yaml.safe_load(text)
            except yaml.YAMLError as yaml_exc:
                raise ValueError(
                    f"Joern seed is not valid JSON or YAML: {exc}"
                ) from yaml_exc
    if not isinstance(loaded, dict):
        raise ValueError("Joern seed must be a JSON object")

    return JoernSeedCatalog(
        sources=_normalize_catalog_list(loaded, "sources"),
        sinks=_normalize_catalog_list(loaded, "sinks"),
        sanitizers=_normalize_catalog_list(loaded, "sanitizers"),
    )


async def generate_semgrep_seed(
    *,
    llm: LLMClient,
    training_examples: list[dict[str, Any]],
) -> tuple[str, dict[str, str]]:
    """Ask the seed model for initial Semgrep YAML and validate it."""
    user_prompt = build_user_prompt_seed_semgrep(training_examples)
    raw = await llm.chat(SYSTEM_PROMPT_SEED_SEMGREP, user_prompt)
    return parse_semgrep_seed_yaml(raw), {
        "system_prompt": SYSTEM_PROMPT_SEED_SEMGREP,
        "user_prompt": user_prompt,
        "raw_response": raw,
    }


async def generate_joern_seed(
    *,
    llm: LLMClient,
    training_examples: list[dict[str, Any]],
) -> tuple[JoernSeedCatalog, dict[str, str]]:
    """Ask the seed model for initial Joern catalogs and validate them."""
    user_prompt = build_user_prompt_seed_joern(training_examples)
    raw = await llm.chat(SYSTEM_PROMPT_SEED_JOERN, user_prompt)
    return parse_joern_seed_catalog(raw), {
        "system_prompt": SYSTEM_PROMPT_SEED_JOERN,
        "user_prompt": user_prompt,
        "raw_response": raw,
    }


def collect_training_examples(
    *,
    training_dataset: list[dict[str, Any]],
    clone_dir: Path,
    dataset_path: Path,
    clone_timeout_s: float = 300.0,
) -> list[dict[str, Any]]:
    """Clone training commits and extract compact vulnerable/patched evidence."""
    examples: list[dict[str, Any]] = []
    for cve in training_dataset:
        cve_id = str(cve.get("cve_id", "unknown"))
        repo_url = str(cve.get("repo_url", ""))
        vuln_commit = str(cve.get("vulnerable_commit", ""))
        patch_commit = str(cve.get("patch_commit", ""))
        repo_dest = clone_dir / "_seed_training" / cve_id

        vulnerable_snippet = ""
        patched_snippet = ""
        if repo_url and vuln_commit:
            if clone_and_checkout(
                repo_url, vuln_commit, repo_dest, timeout_s=clone_timeout_s
            ):
                vulnerable_snippet = _snippet_from_repo(repo_dest, cve)
        if repo_url and patch_commit:
            if clone_and_checkout(
                repo_url, patch_commit, repo_dest, timeout_s=clone_timeout_s
            ):
                patched_snippet = _snippet_from_repo(repo_dest, cve)
        shutil.rmtree(repo_dest, ignore_errors=True)

        examples.append(
            {
                "cve_id": cve_id,
                "package": cve.get("package", ""),
                "repo_url": repo_url,
                "vulnerable_file": cve.get("vulnerable_file", ""),
                "vulnerable_lines": cve.get("vulnerable_lines", []),
                "sink_api": cve.get("sink_api", ""),
                "notes": cve.get("notes", ""),
                "vulnerable_snippet": vulnerable_snippet,
                "patched_snippet": patched_snippet,
                "patch_diff": _read_patch_diff(dataset_path, cve),
            }
        )
    return examples


def _normalize_catalog_list(data: dict[str, Any], key: str) -> list[str]:
    raw = data.get(key)
    if not isinstance(raw, list):
        raise ValueError(f"Joern seed key {key!r} must be a list")
    out: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            raise ValueError(f"Joern seed key {key!r} contains a non-string item")
        value = item.strip()
        if value and value not in out:
            out.append(value)
    if key in {"sources", "sinks"} and not out:
        raise ValueError(f"Joern seed key {key!r} must not be empty")
    return out


def _strip_markdown_fence(text: str) -> str:
    stripped = (text or "").strip()
    if not stripped.startswith("```"):
        return stripped
    lines = stripped.splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()


def _snippet_from_repo(repo: Path, cve: dict[str, Any]) -> str:
    vuln_file = str(cve.get("vulnerable_file", "") or "")
    vuln_lines = [int(line) for line in cve.get("vulnerable_lines", []) or []]
    if not vuln_file or not vuln_lines:
        return ""
    path = repo / vuln_file
    if not path.exists():
        matches = list(repo.rglob(Path(vuln_file).name))
        path = matches[0] if matches else path
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        logger.warning("Could not read training snippet from %s", path)
        return ""
    start_line = max(1, min(vuln_lines) - _SNIPPET_RADIUS)
    end_line = min(len(lines), max(vuln_lines) + _SNIPPET_RADIUS)
    return "\n".join(
        f"{line_no:>5}| {lines[line_no - 1]}"
        for line_no in range(start_line, end_line + 1)
    )


def _read_patch_diff(dataset_path: Path, cve: dict[str, Any]) -> str:
    diff_rel = str(cve.get("patch_diff_path", "") or "")
    if not diff_rel:
        return ""
    path = dataset_path.parent / diff_rel
    try:
        return path.read_text(errors="replace")[:_MAX_DIFF_CHARS]
    except OSError:
        logger.warning("Could not read patch diff from %s", path)
        return ""
