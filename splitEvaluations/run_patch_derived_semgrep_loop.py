#!/usr/bin/env python3
"""Generate Semgrep rules from dev CVE patches and evaluate on a disjoint set."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from auditzoo.agents.cwe78_study.llm_client import LLMClient, LLMConfig  # noqa: E402
from auditzoo.agents.cwe78_study.schemas import TriageResult, Verdict  # noqa: E402
from auditzoo.agents.cwe78_study.semgrep_arm import (  # noqa: E402
    SemgrepArm,
    _semgrep_executable,
)
from scripts.run_evaluation import (  # noqa: E402
    LINE_TOLERANCE,
    clone_and_checkout,
    label_findings,
)
from splitEvaluations.common import (  # noqa: E402
    DEFAULT_CLONE_DIR,
    DEFAULT_DATASET,
    DEFAULT_OUTPUT,
    _save_json,
)
from splitEvaluations.readiness_config import (  # noqa: E402
    PATCH_RULE_DEV_CVES,
    PATCH_RULE_EVAL_CVES,
)

GPT54_MINI_API_KEY = ""
GPT54_MINI_MODEL = "gpt-5.4-mini"
GPT54_MINI_BASE_URL = "https://api.openai.com/v1"

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are generating Semgrep rules for CWE-78 OS Command Injection in Python.

Given a vulnerable/patched diff and focused snippets, infer generalizable
Semgrep taint-mode rule specs. Return ONLY JSON with this shape:
{"rules":[{"id":"cwe78-derived-...",
"mode":"taint",
"sources":["Semgrep Python pattern", "..."],
"sinks":["Semgrep Python pattern", "..."],
"sanitizers":["Semgrep Python pattern", "..."],
"message":"short message",
"rationale":"why this rule catches the vulnerable pattern"}]}

Rules must be generalizable. Do not include absolute paths, line numbers,
specific CVE IDs, or file-specific suppressions. Prefer source-to-sink taint
rules. If the patch does not support a useful rule, return {"rules":[]}.
"""


@dataclass
class GeneratedRule:
    rule_id: str
    yaml_text: str
    source_cve: str
    rationale: str = ""
    raw_spec: dict[str, Any] = field(default_factory=dict)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--clone-dir",
        type=Path,
        default=DEFAULT_CLONE_DIR / "patch_derived_semgrep",
    )
    parser.add_argument("--llm-url", default=GPT54_MINI_BASE_URL)
    parser.add_argument("--llm-model", default=GPT54_MINI_MODEL)
    parser.add_argument("--seed", type=int, default=235711)
    parser.add_argument("--line-tolerance", type=int, default=LINE_TOLERANCE)
    parser.add_argument("--semgrep-timeout", type=float, default=300.0)
    parser.add_argument("--dev-cves", nargs="+", default=list(PATCH_RULE_DEV_CVES))
    parser.add_argument("--eval-cves", nargs="+", default=list(PATCH_RULE_EVAL_CVES))
    parser.add_argument(
        "--api-key",
        default=None,
        help="OpenAI API key. Defaults to OPENAI_API_KEY, then GPT54_MINI_API_KEY.",
    )
    return parser.parse_args(argv)


def resolve_api_key(args: argparse.Namespace) -> str:
    return args.api_key or os.environ.get("OPENAI_API_KEY", "") or GPT54_MINI_API_KEY


def _add_file_logging(log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setLevel(logging.INFO)
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    logging.getLogger().addHandler(handler)


def validate_split(dev_cves: list[str], eval_cves: list[str]) -> dict[str, Any]:
    dev_set = set(dev_cves)
    eval_set = set(eval_cves)
    overlap = sorted(dev_set & eval_set)
    return {
        "dev_cves": list(dev_cves),
        "eval_cves": list(eval_cves),
        "dev_count": len(dev_cves),
        "eval_count": len(eval_cves),
        "dev_unique": len(dev_set) == len(dev_cves),
        "eval_unique": len(eval_set) == len(eval_cves),
        "dev_eval_overlap": overlap,
        "leakage_check_passed": not overlap
        and len(dev_cves) == 5
        and len(eval_cves) == 20
        and len(dev_set) == 5
        and len(eval_set) == 20,
    }


def _redacted_run_config(
    args: argparse.Namespace, *, api_key: str, split: dict[str, Any]
) -> dict[str, Any]:
    config = vars(args).copy()
    config["api_key"] = "<redacted>" if api_key else ""
    config["sweep"] = "patch_derived_semgrep"
    config.update(split)
    return config


def load_dataset(path: Path) -> dict[str, dict[str, Any]]:
    data = json.loads(path.read_text())
    return {str(row["cve_id"]): row for row in data}


def read_patch_diff(cve: dict[str, Any], dataset_path: Path) -> str:
    diff_path = dataset_path.parent / str(cve.get("patch_diff_path", ""))
    if not diff_path.exists():
        return ""
    return diff_path.read_text(errors="replace")


def focused_snippet(repo_path: Path, cve: dict[str, Any], *, context: int = 20) -> str:
    target = str(cve.get("vulnerable_file", ""))
    lines = [int(line) for line in cve.get("vulnerable_lines", []) or []]
    if not target or not lines:
        return ""
    matches = list(repo_path.rglob(Path(target).name))
    chosen = next((p for p in matches if str(p).endswith(target)), matches[0] if matches else None)
    if chosen is None:
        return ""
    try:
        content = chosen.read_text(errors="replace").splitlines()
    except OSError:
        return ""
    start = max(1, min(lines) - context)
    end = min(len(content), max(lines) + context)
    excerpt = "\n".join(
        f"{idx:>5}| {content[idx - 1]}" for idx in range(start, end + 1)
    )
    return f"File: {target}\n{excerpt}"


def build_generation_prompt(
    *,
    cve: dict[str, Any],
    patch_diff: str,
    vulnerable_snippet: str,
    patched_snippet: str,
) -> str:
    return f"""\
CVE: {cve.get("cve_id")}
Package: {cve.get("package")}
Notes: {cve.get("notes", "")}
Ground-truth file: {cve.get("vulnerable_file")}
Ground-truth lines: {cve.get("vulnerable_lines")}

Patch diff:
```diff
{_truncate(patch_diff, 220)}
```

Vulnerable snippet:
```python
{_truncate(vulnerable_snippet, 120)}
```

Patched snippet:
```python
{_truncate(patched_snippet, 120)}
```

Generate at most 3 Semgrep rule specs that would detect this vulnerability
class before the patch without hardcoding this CVE, file path, or line number.
"""


def _truncate(text: str, max_lines: int) -> str:
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text
    half = max_lines // 2
    return "\n".join(lines[:half] + ["... (truncated) ..."] + lines[-half:])


def _safe_rule_id(source_cve: str, raw_id: str, idx: int) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_.-]+", "-", raw_id.strip().lower()).strip("-")
    if not slug:
        slug = f"cwe78-derived-{source_cve.lower()}-{idx}"
    if not slug.startswith("cwe78-derived-"):
        slug = "cwe78-derived-" + slug
    return slug


def rule_spec_to_yaml(spec: dict[str, Any], *, source_cve: str, idx: int = 0) -> GeneratedRule | None:
    sources = _string_list(spec.get("sources"))
    sinks = _string_list(spec.get("sinks"))
    sanitizers = _string_list(spec.get("sanitizers"))
    if not sources or not sinks:
        return None
    rule_id = _safe_rule_id(source_cve, str(spec.get("id", "")), idx)
    rule = {
        "id": rule_id,
        "mode": "taint",
        "pattern-sources": [{"pattern": pattern} for pattern in sources],
        "pattern-sinks": [{"pattern": pattern} for pattern in sinks],
        "message": str(spec.get("message") or "Patch-derived CWE-78 candidate"),
        "languages": ["python"],
        "severity": "ERROR",
        "metadata": {
            "cwe": "CWE-78",
            "source_cve": source_cve,
            "derived_rule": True,
        },
    }
    if sanitizers:
        rule["pattern-sanitizers"] = [{"pattern": pattern} for pattern in sanitizers]
    yaml_text = yaml.dump({"rules": [rule]}, sort_keys=False)
    return GeneratedRule(
        rule_id=rule_id,
        yaml_text=yaml_text,
        source_cve=source_cve,
        rationale=str(spec.get("rationale", "")),
        raw_spec=spec,
    )


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        raw = [value]
    elif isinstance(value, list):
        raw = value
    else:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in raw:
        text = str(item or "").strip()
        if text and text not in seen:
            out.append(text)
            seen.add(text)
    return out


def reject_overfit_rule(rule: GeneratedRule, cve: dict[str, Any] | None = None) -> str:
    payload = rule.yaml_text
    patterns = _extract_patterns(rule.yaml_text)
    vuln_file = str((cve or {}).get("vulnerable_file", ""))
    checks = [
        (r"\bline\s*:\s*\d+\b", "contains_line_number"),
        (r"/tmp/|/workspace/|/home/|/root/", "contains_absolute_path"),
        (r"CVE-\d{4}-\d+", "contains_cve_id"),
    ]
    for pattern, reason in checks:
        if re.search(pattern, payload, flags=re.IGNORECASE):
            return reason
    if vuln_file and vuln_file in payload:
        return "contains_dev_file_path"
    for pattern in patterns:
        if re.search(r"\b(os\.system|subprocess\.\w+|os\.popen)\(\s*['\"][^$]", pattern):
            return "contains_literal_command_sink"
    return ""


def _extract_patterns(rules_yaml: str) -> list[str]:
    try:
        loaded = yaml.safe_load(rules_yaml)
    except yaml.YAMLError:
        return []
    patterns: list[str] = []
    for rule in (loaded or {}).get("rules", []) if isinstance(loaded, dict) else []:
        if not isinstance(rule, dict):
            continue
        for key in ("pattern-sources", "pattern-sinks", "pattern-sanitizers"):
            for item in rule.get(key, []) or []:
                if isinstance(item, dict) and isinstance(item.get("pattern"), str):
                    patterns.append(item["pattern"])
        for item in rule.get("patterns", []) or []:
            if isinstance(item, dict):
                patterns.extend(str(v) for v in item.values() if isinstance(v, str))
    return patterns


def validate_rules_yaml(rules_yaml: str) -> tuple[bool, str]:
    try:
        loaded = yaml.safe_load(rules_yaml)
    except yaml.YAMLError as exc:
        return False, f"yaml_error: {exc}"
    if not isinstance(loaded, dict) or not isinstance(loaded.get("rules"), list):
        return False, "missing_rules_list"
    with subprocess.Popen(
        [_semgrep_executable(), "--validate", "--config", "-"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ) as proc:
        stdout, stderr = proc.communicate(rules_yaml, timeout=30)
    if proc.returncode != 0:
        return False, (stderr or stdout)[:500]
    return True, "ok"


def _near_gt(finding: Any, cve: dict[str, Any], tolerance: int) -> bool:
    vuln_file = str(cve.get("vulnerable_file", ""))
    vuln_lines = {int(line) for line in cve.get("vulnerable_lines", []) or []}
    if not vuln_lines:
        return False
    fpath = str(getattr(finding, "file_path", ""))
    if not (
        Path(fpath).name == Path(vuln_file).name
        or vuln_file.endswith(fpath)
        or fpath.endswith(vuln_file)
    ):
        return False
    line = int(getattr(finding, "line_start", 0) or 0)
    return any(abs(line - gt) <= tolerance for gt in vuln_lines)


def scan_rule(rule_yaml: str, repo_path: Path) -> list[Any]:
    arm = SemgrepArm(rules_yaml=rule_yaml)
    return arm.get_findings_with_context(arm.scan(repo_path))


def validate_generated_rule(
    rule: GeneratedRule,
    *,
    cve: dict[str, Any],
    vuln_repo: Path,
    patched_repo: Path,
    line_tolerance: int,
) -> dict[str, Any]:
    valid_yaml, validation_message = validate_rules_yaml(rule.yaml_text)
    overfit_reason = reject_overfit_rule(rule, cve)
    record: dict[str, Any] = {
        "rule_id": rule.rule_id,
        "source_cve": rule.source_cve,
        "rationale": rule.rationale,
        "valid_yaml": valid_yaml,
        "validation_message": validation_message,
        "overfit_reason": overfit_reason,
        "accepted": False,
        "reject_reason": "",
        "vulnerable_findings": 0,
        "patched_findings": 0,
        "matched_ground_truth": False,
    }
    if not valid_yaml:
        record["reject_reason"] = "invalid_yaml"
        return record
    if overfit_reason:
        record["reject_reason"] = overfit_reason
        return record
    vuln_findings = scan_rule(rule.yaml_text, vuln_repo)
    patched_findings = scan_rule(rule.yaml_text, patched_repo)
    record["vulnerable_findings"] = len(vuln_findings)
    record["patched_findings"] = len(patched_findings)
    record["matched_ground_truth"] = any(
        _near_gt(finding, cve, line_tolerance) for finding in vuln_findings
    )
    if not record["matched_ground_truth"]:
        record["reject_reason"] = "no_vulnerable_gt_match"
        return record
    record["accepted"] = True
    record["patched_reduced"] = len(patched_findings) < len(vuln_findings)
    return record


def merge_rules(rules: list[GeneratedRule]) -> str:
    merged: dict[str, list[dict[str, Any]]] = {"rules": []}
    seen: set[str] = set()
    for rule in rules:
        loaded = yaml.safe_load(rule.yaml_text)
        for item in loaded.get("rules", []):
            rule_id = str(item.get("id", ""))
            if rule_id and rule_id not in seen:
                merged["rules"].append(item)
                seen.add(rule_id)
    return yaml.dump(merged, sort_keys=False)


def _triage_uncertain(findings: list[Any]) -> list[TriageResult]:
    return [
        TriageResult(
            verdict=Verdict.UNCERTAIN,
            confidence=0.0,
            reasoning="Rule-pack evaluation uses location scoring without LLM triage.",
        )
        for _ in findings
    ]


def evaluate_rule_pack(
    *,
    rules_yaml: str,
    eval_cves: list[dict[str, Any]],
    clone_dir: Path,
    line_tolerance: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    results: list[dict[str, Any]] = []
    per_rule_hits: Counter[str] = Counter()
    per_rule_tp: Counter[str] = Counter()
    per_rule_fp: Counter[str] = Counter()
    totals = Counter()
    zero_candidate_cves: list[str] = []
    candidate_no_tp_cves: list[str] = []
    patched_findings_total = 0

    for cve in eval_cves:
        cve_id = str(cve["cve_id"])
        vuln_repo = clone_dir / "eval" / cve_id / "vulnerable"
        patched_repo = clone_dir / "eval" / cve_id / "patched"
        shutil.rmtree(vuln_repo.parent, ignore_errors=True)
        ok_vuln = clone_and_checkout(cve["repo_url"], cve["vulnerable_commit"], vuln_repo)
        ok_patch = clone_and_checkout(cve["repo_url"], cve["patch_commit"], patched_repo)
        if not ok_vuln:
            results.append({"cve_id": cve_id, "skipped": "clone_failed"})
            continue
        findings = scan_rule(rules_yaml, vuln_repo)
        triage = _triage_uncertain(findings)
        labels = label_findings(findings, triage, cve, line_tolerance=line_tolerance)
        patched_count = len(scan_rule(rules_yaml, patched_repo)) if ok_patch else None
        if patched_count is not None:
            patched_findings_total += patched_count
        for finding, label in zip(findings, labels.get("labels", []), strict=False):
            rule_id = str(getattr(finding, "rule_id", ""))
            per_rule_hits[rule_id] += 1
            if label == "tp":
                per_rule_tp[rule_id] += 1
            elif label.startswith("fp"):
                per_rule_fp[rule_id] += 1
        for metric_name in ("tp", "fp", "fn"):
            totals[metric_name] += int(labels.get(metric_name, 0) or 0)
        totals["n_candidates"] += len(findings)
        if not findings:
            zero_candidate_cves.append(cve_id)
        elif labels.get("tp", 0) == 0:
            candidate_no_tp_cves.append(cve_id)
        results.append(
            {
                "cve_id": cve_id,
                "n_candidates": len(findings),
                "patched_findings": patched_count,
                **labels,
                "findings": [
                    {
                        "file": finding.file_path,
                        "line": finding.line_start,
                        "rule_id": finding.rule_id,
                        "sink_api": finding.sink_api,
                    }
                    for finding in findings
                ],
            }
        )
    summary = {
        "totals": dict(totals),
        "zero_candidate_cves": zero_candidate_cves,
        "candidate_no_tp_cves": candidate_no_tp_cves,
        "patched_findings_total": patched_findings_total,
        "per_rule_hits": dict(per_rule_hits),
        "per_rule_tp": dict(per_rule_tp),
        "per_rule_fp": dict(per_rule_fp),
    }
    return results, summary


async def generate_rules_for_cve(
    *,
    llm: LLMClient,
    cve: dict[str, Any],
    dataset_path: Path,
    clone_dir: Path,
    output_dir: Path,
) -> list[GeneratedRule]:
    cve_id = str(cve["cve_id"])
    vuln_repo = clone_dir / "dev" / cve_id / "vulnerable"
    patched_repo = clone_dir / "dev" / cve_id / "patched"
    shutil.rmtree(vuln_repo.parent, ignore_errors=True)
    ok_vuln = clone_and_checkout(cve["repo_url"], cve["vulnerable_commit"], vuln_repo)
    ok_patch = clone_and_checkout(cve["repo_url"], cve["patch_commit"], patched_repo)
    if not ok_vuln or not ok_patch:
        logger.warning("Skipping %s rule generation because checkout failed", cve_id)
        return []
    prompt = build_generation_prompt(
        cve=cve,
        patch_diff=read_patch_diff(cve, dataset_path),
        vulnerable_snippet=focused_snippet(vuln_repo, cve),
        patched_snippet=focused_snippet(patched_repo, cve),
    )
    raw = await llm.chat_json(SYSTEM_PROMPT, prompt, max_tokens=2048)
    raw_path = output_dir / "generated_rules" / "raw" / f"{cve_id}.json"
    _save_json(raw, raw_path)
    rules: list[GeneratedRule] = []
    for idx, spec in enumerate(raw.get("rules", []) if isinstance(raw, dict) else []):
        if not isinstance(spec, dict):
            continue
        generated = rule_spec_to_yaml(spec, source_cve=cve_id, idx=idx)
        if generated is None:
            continue
        yaml_path = output_dir / "generated_rules" / "yaml" / f"{generated.rule_id}.yaml"
        yaml_path.parent.mkdir(parents=True, exist_ok=True)
        yaml_path.write_text(generated.yaml_text)
        rules.append(generated)
    return rules


async def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    api_key = resolve_api_key(args)
    if not api_key:
        raise SystemExit(
            "No API key provided. Set OPENAI_API_KEY, pass --api-key, or fill "
            "GPT54_MINI_API_KEY at the top of this script."
        )

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    split = validate_split(args.dev_cves, args.eval_cves)
    if not split["leakage_check_passed"]:
        raise SystemExit(f"Invalid dev/eval split: {split}")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = args.output / "patch_derived_semgrep" / timestamp
    output_dir.mkdir(parents=True, exist_ok=True)
    _add_file_logging(output_dir / "generation.log")
    _save_json(
        _redacted_run_config(args, api_key=api_key, split=split),
        output_dir / "run_config.json",
    )

    dataset = load_dataset(args.dataset)
    llm = LLMClient(
        LLMConfig(
            base_url=args.llm_url,
            model=args.llm_model,
            api_key=api_key,
            seed=args.seed,
            log_io_path=str(output_dir / "llm_io.jsonl"),
            max_tokens=2048,
        )
    )

    accepted: list[GeneratedRule] = []
    rejected: list[dict[str, Any]] = []
    dev_validation: list[dict[str, Any]] = []
    for cve_id in args.dev_cves:
        cve = dataset[cve_id]
        rules = await generate_rules_for_cve(
            llm=llm,
            cve=cve,
            dataset_path=args.dataset,
            clone_dir=args.clone_dir,
            output_dir=output_dir,
        )
        vuln_repo = args.clone_dir / "dev" / cve_id / "vulnerable"
        patched_repo = args.clone_dir / "dev" / cve_id / "patched"
        for rule in rules:
            record = validate_generated_rule(
                rule,
                cve=cve,
                vuln_repo=vuln_repo,
                patched_repo=patched_repo,
                line_tolerance=args.line_tolerance,
            )
            dev_validation.append(record)
            if record["accepted"]:
                accepted.append(rule)
            else:
                rejected.append(record)
            logger.info("%s %s accepted=%s reason=%s", cve_id, rule.rule_id, record["accepted"], record.get("reject_reason", ""))

    accepted_yaml = merge_rules(accepted) if accepted else "rules: []\n"
    accepted_path = output_dir / "accepted_rules" / "patch_derived_rules.yaml"
    accepted_path.parent.mkdir(parents=True, exist_ok=True)
    accepted_path.write_text(accepted_yaml)
    _save_json(dev_validation, output_dir / "dev_validation.json")
    _save_json(rejected, output_dir / "rejected_rules.json")

    eval_cves = [dataset[cve_id] for cve_id in args.eval_cves]
    eval_results, eval_summary = evaluate_rule_pack(
        rules_yaml=accepted_yaml,
        eval_cves=eval_cves,
        clone_dir=args.clone_dir,
        line_tolerance=args.line_tolerance,
    )
    eval_summary.update(
        {
            "dev_cves": args.dev_cves,
            "eval_cves": args.eval_cves,
            "leakage_check_passed": split["leakage_check_passed"],
            "dev_eval_overlap": split["dev_eval_overlap"],
            "accepted_rule_count": len(accepted),
            "rejected_rule_count": len(rejected),
            "llm_usage": llm.usage.to_dict(),
        }
    )
    _save_json(eval_results, output_dir / "eval_results.json")
    _save_json(eval_summary, output_dir / "eval_summary.json")
    with (output_dir / "eval_findings.jsonl").open("w", encoding="utf-8") as fh:
        for row in eval_results:
            for finding in row.get("findings", []) or []:
                fh.write(json.dumps({"cve_id": row.get("cve_id"), **finding}) + "\n")
    logger.info("Accepted %d rules; eval summary=%s", len(accepted), eval_summary)
    logger.info("Results saved to %s", output_dir)


if __name__ == "__main__":
    asyncio.run(main())
