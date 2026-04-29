#!/usr/bin/env python3
"""Run AutoGrep rule generation on dev CVEs and evaluate frozen rules."""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

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

# Provide the API key via the OPENAI_API_KEY environment variable or --api-key.
# Never hardcode a real key here; this fallback intentionally stays empty.
GPT54_MINI_API_KEY = ""
GPT54_MINI_MODEL = "gpt-5.4-mini"
GPT54_MINI_BASE_URL = "https://api.openai.com/v1"

logger = logging.getLogger(__name__)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--clone-dir",
        type=Path,
        default=DEFAULT_CLONE_DIR / "autogrep_semgrep",
    )
    parser.add_argument(
        "--autogrep-dir",
        type=Path,
        default=Path("workspace/autogrep"),
        help="Path to an external lambdasec/autogrep checkout.",
    )
    parser.add_argument("--llm-url", default=GPT54_MINI_BASE_URL)
    parser.add_argument("--llm-model", default=GPT54_MINI_MODEL)
    parser.add_argument("--seed", type=int, default=235711)
    parser.add_argument("--line-tolerance", type=int, default=LINE_TOLERANCE)
    parser.add_argument("--max-retries", type=int, default=3)
    parser.add_argument("--max-files-changed", type=int, default=1)
    parser.add_argument("--dev-cves", nargs="+", default=list(PATCH_RULE_DEV_CVES))
    parser.add_argument("--eval-cves", nargs="+", default=list(PATCH_RULE_EVAL_CVES))
    parser.add_argument(
        "--api-key",
        default=None,
        help="OpenAI/OpenRouter API key. Defaults to OPENAI_API_KEY, then GPT54_MINI_API_KEY.",
    )
    return parser.parse_args(argv)


def resolve_api_key(args: argparse.Namespace) -> str:
    return args.api_key or os.environ.get("OPENAI_API_KEY", "") or GPT54_MINI_API_KEY


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


def _redact_text(text: str) -> str:
    text = re.sub(r"sk-proj-[A-Za-z0-9_\-]+", "<redacted-openai-api-key>", text)
    text = re.sub(r"sk-[A-Za-z0-9_\-]{20,}", "<redacted-openai-api-key>", text)
    return text


def _redacted_run_config(
    args: argparse.Namespace, *, api_key: str, split: dict[str, Any]
) -> dict[str, Any]:
    config = vars(args).copy()
    config["api_key"] = "<redacted>" if api_key else ""
    config["sweep"] = "autogrep_semgrep"
    config.update(split)
    return config


def _add_file_logging(log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setLevel(logging.INFO)
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    logging.getLogger().addHandler(handler)


def load_dataset(path: Path) -> dict[str, dict[str, Any]]:
    data = json.loads(path.read_text())
    return {str(row["cve_id"]): row for row in data}


def _github_repo_parts(repo_url: str) -> tuple[str, str]:
    cleaned = repo_url.removesuffix(".git").rstrip("/")
    match = re.search(r"github\.com[:/](?P<owner>[^/]+)/(?P<repo>[^/]+)$", cleaned)
    if not match:
        raise ValueError(f"AutoGrep patch adapter only supports GitHub URLs: {repo_url}")
    return match.group("owner"), match.group("repo")


def autogrep_patch_filename(cve: dict[str, Any]) -> str:
    owner, repo = _github_repo_parts(str(cve["repo_url"]))
    commit = str(cve["patch_commit"])
    return f"github.com_{owner}_{repo}_{commit}.patch"


def prepare_autogrep_patches(
    *,
    dataset: dict[str, dict[str, Any]],
    dataset_path: Path,
    dev_cves: list[str],
    patches_dir: Path,
) -> list[dict[str, str]]:
    shutil.rmtree(patches_dir, ignore_errors=True)
    patches_dir.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, str]] = []
    for cve_id in dev_cves:
        cve = dataset[cve_id]
        source = dataset_path.parent / str(cve.get("patch_diff_path", ""))
        if not source.exists():
            raise FileNotFoundError(f"Missing patch diff for {cve_id}: {source}")
        dest = patches_dir / autogrep_patch_filename(cve)
        dest.write_text(source.read_text(errors="replace"))
        records.append(
            {
                "cve_id": cve_id,
                "source_diff": str(source),
                "autogrep_patch": str(dest),
                "repo_url": str(cve["repo_url"]),
                "patch_commit": str(cve["patch_commit"]),
            }
        )
    return records


def _copy_autogrep_runtime(autogrep_dir: Path, runtime_dir: Path, model: str) -> Path:
    if not autogrep_dir.exists():
        raise FileNotFoundError(
            f"AutoGrep checkout not found: {autogrep_dir}. "
            "Clone https://github.com/lambdasec/autogrep and pass --autogrep-dir."
        )
    main_py = autogrep_dir / "main.py"
    filter_py = autogrep_dir / "rule_filter.py"
    llm_client = autogrep_dir / "llm_client.py"
    for required in (main_py, filter_py, llm_client):
        if not required.exists():
            raise FileNotFoundError(f"AutoGrep checkout is missing {required.name}: {required}")

    shutil.rmtree(runtime_dir, ignore_errors=True)
    shutil.copytree(
        autogrep_dir,
        runtime_dir,
        ignore=shutil.ignore_patterns(
            ".git",
            "__pycache__",
            ".pytest_cache",
            "cache",
            "generated_rules",
            "filtered_rules",
            "cvedataset-patches",
        ),
    )
    _patch_runtime_python_file(runtime_dir / "llm_client.py", model, None)
    return runtime_dir


def _patch_runtime_python_file(
    path: Path,
    model: str,
    llm_url: str | None,
) -> None:
    text = path.read_text()
    text = text.replace('model="deepseek/deepseek-chat"', f'model="{model}"')
    text = text.replace("model='deepseek/deepseek-chat'", f"model='{model}'")
    if llm_url is not None:
        text = text.replace(
            'base_url="https://openrouter.ai/api/v1"',
            f'base_url="{llm_url}"',
        )
    # GPT-5-style endpoints reject temperature in Chat Completions requests.
    if model.lower().replace("_", "-").startswith(("gpt-5", "o1", "o3", "o4")):
        text = re.sub(r"\n\s*temperature\s*=\s*0\.6\s*,", "", text)
        text = re.sub(r"\n\s*temperature\s*=\s*0\.2\s*,", "", text)
    path.write_text(text)


def build_autogrep_commands(
    *,
    runtime_dir: Path,
    patches_dir: Path,
    generated_dir: Path,
    filtered_dir: Path,
    repos_cache_dir: Path,
    api_key: str,
    llm_url: str,
    max_files_changed: int,
    max_retries: int,
) -> tuple[list[str], list[str], dict[str, str]]:
    env = os.environ.copy()
    env["OPENROUTER_API_KEY"] = api_key
    generate_cmd = [
        sys.executable,
        "main.py",
        "--patches-dir",
        str(patches_dir),
        "--output-dir",
        str(generated_dir),
        "--repos-cache-dir",
        str(repos_cache_dir),
        "--max-files-changed",
        str(max_files_changed),
        "--max-retries",
        str(max_retries),
        "--openrouter-api-key",
        api_key,
        "--openrouter-base-url",
        llm_url,
    ]
    filter_cmd = [
        sys.executable,
        "rule_filter.py",
        "--input-dir",
        str(generated_dir),
        "--output-dir",
        str(filtered_dir),
    ]
    del runtime_dir  # commands run with cwd set separately
    return generate_cmd, filter_cmd, env


def _run_logged_subprocess(
    cmd: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    log_path: Path,
    timeout_s: float | None = None,
) -> dict[str, Any]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as log:
        log.write("$ " + " ".join(_redact_text(part) for part in cmd) + "\n\n")
        try:
            result = subprocess.run(
                cmd,
                cwd=cwd,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout_s,
            )
            output = _redact_text(result.stdout or "")
            log.write(output)
            return {
                "cmd": [_redact_text(part) for part in cmd],
                "returncode": result.returncode,
                "log_path": str(log_path),
                "timed_out": False,
            }
        except subprocess.TimeoutExpired as exc:
            output = _redact_text((exc.stdout or "") if isinstance(exc.stdout, str) else "")
            log.write(output)
            log.write(f"\nTimed out after {timeout_s} seconds.\n")
            return {
                "cmd": [_redact_text(part) for part in cmd],
                "returncode": None,
                "log_path": str(log_path),
                "timed_out": True,
            }


def count_autogrep_generated_rules(generated_dir: Path) -> int:
    count = 0
    for path in sorted(generated_dir.rglob("*.yml")) + sorted(generated_dir.rglob("*.yaml")):
        try:
            loaded = yaml.safe_load(path.read_text())
        except (OSError, yaml.YAMLError):
            continue
        rules = loaded.get("rules", []) if isinstance(loaded, dict) else []
        count += len([rule for rule in rules if isinstance(rule, dict)])
    return count


def run_autogrep(
    *,
    autogrep_dir: Path,
    runtime_dir: Path,
    patches_dir: Path,
    generated_dir: Path,
    filtered_dir: Path,
    repos_cache_dir: Path,
    logs_dir: Path,
    api_key: str,
    llm_model: str,
    llm_url: str,
    max_files_changed: int,
    max_retries: int,
) -> dict[str, Any]:
    runtime = _copy_autogrep_runtime(autogrep_dir, runtime_dir, llm_model)
    _patch_runtime_python_file(runtime / "rule_filter.py", llm_model, llm_url)
    generate_cmd, filter_cmd, env = build_autogrep_commands(
        runtime_dir=runtime,
        patches_dir=patches_dir,
        generated_dir=generated_dir,
        filtered_dir=filtered_dir,
        repos_cache_dir=repos_cache_dir,
        api_key=api_key,
        llm_url=llm_url,
        max_files_changed=max_files_changed,
        max_retries=max_retries,
    )
    generate = _run_logged_subprocess(
        generate_cmd,
        cwd=runtime,
        env=env,
        log_path=logs_dir / "autogrep_generate.log",
    )
    if generate["returncode"] != 0:
        return {
            "generate": generate,
            "filter": None,
            "runtime_dir": str(runtime),
            "generated_rule_count": 0,
        }
    generated_rule_count = count_autogrep_generated_rules(generated_dir)
    if generated_rule_count == 0:
        return {
            "generate": generate,
            "filter": None,
            "runtime_dir": str(runtime),
            "generated_rule_count": 0,
            "aborted_before_filter": True,
            "abort_reason": "no_generated_rules",
        }
    filter_result = _run_logged_subprocess(
        filter_cmd,
        cwd=runtime,
        env=env,
        log_path=logs_dir / "autogrep_filter.log",
    )
    return {
        "generate": generate,
        "filter": filter_result,
        "runtime_dir": str(runtime),
        "generated_rule_count": generated_rule_count,
    }


def load_frozen_rules(filtered_dir: Path) -> tuple[str, Path]:
    candidates = [
        filtered_dir / "python" / "repo_rules.yml",
        filtered_dir / "python" / "repo_rules.yaml",
        filtered_dir / "repo_rules.yml",
        filtered_dir / "repo_rules.yaml",
    ]
    for path in candidates:
        if path.exists():
            rules_yaml = path.read_text()
            loaded = yaml.safe_load(rules_yaml)
            rules = loaded.get("rules", []) if isinstance(loaded, dict) else []
            if rules:
                return rules_yaml, path
    python_dir = filtered_dir / "python"
    merged: list[dict[str, Any]] = []
    if python_dir.exists():
        for path in sorted([*python_dir.glob("*.yml"), *python_dir.glob("*.yaml")]):
            loaded = yaml.safe_load(path.read_text())
            rules = loaded.get("rules", []) if isinstance(loaded, dict) else []
            merged.extend(rule for rule in rules if isinstance(rule, dict))
    if merged:
        return yaml.dump({"rules": merged}, sort_keys=False), python_dir
    raise FileNotFoundError(
        f"No non-empty AutoGrep Python rule pack found under {filtered_dir}"
    )


def validate_rules_yaml(rules_yaml: str) -> tuple[bool, str]:
    try:
        loaded = yaml.safe_load(rules_yaml)
    except yaml.YAMLError as exc:
        return False, f"yaml_error: {exc}"
    if not isinstance(loaded, dict) or not isinstance(loaded.get("rules"), list):
        return False, "missing_rules_list"
    if not loaded["rules"]:
        return False, "empty_rules"

    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tmp:
        tmp.write(rules_yaml)
        tmp.flush()
        rule_file = tmp.name
    try:
        result = subprocess.run(
            [_semgrep_executable(), "--validate", "--config", rule_file],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError:
        return True, "semgrep_not_found_structural_only"
    except subprocess.TimeoutExpired:
        return False, "semgrep_validate_timeout"
    finally:
        Path(rule_file).unlink(missing_ok=True)
    if result.returncode != 0:
        return False, (result.stderr or result.stdout)[:500]
    return True, "ok"


def scan_rule_pack(rules_yaml: str, repo_path: Path) -> list[Any]:
    arm = SemgrepArm(rules_yaml=rules_yaml)
    return arm.get_findings_with_context(arm.scan(repo_path))


def _triage_uncertain(findings: list[Any]) -> list[TriageResult]:
    return [
        TriageResult(
            verdict=Verdict.UNCERTAIN,
            confidence=0.0,
            reasoning="AutoGrep rule-pack evaluation uses location scoring without LLM triage.",
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

        findings = scan_rule_pack(rules_yaml, vuln_repo)
        labels = label_findings(
            findings,
            _triage_uncertain(findings),
            cve,
            line_tolerance=line_tolerance,
        )
        patched_count = len(scan_rule_pack(rules_yaml, patched_repo)) if ok_patch else None
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

    return results, {
        "totals": dict(totals),
        "zero_candidate_cves": zero_candidate_cves,
        "candidate_no_tp_cves": candidate_no_tp_cves,
        "patched_findings_total": patched_findings_total,
        "per_rule_hits": dict(per_rule_hits),
        "per_rule_tp": dict(per_rule_tp),
        "per_rule_fp": dict(per_rule_fp),
    }


def _rule_count(rules_yaml: str) -> int:
    loaded = yaml.safe_load(rules_yaml)
    if not isinstance(loaded, dict):
        return 0
    rules = loaded.get("rules", [])
    return len(rules) if isinstance(rules, list) else 0


def _write_eval_findings(results: list[dict[str, Any]], path: Path) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for row in results:
            for finding in row.get("findings", []) or []:
                fh.write(json.dumps({"cve_id": row.get("cve_id"), **finding}) + "\n")


def main(argv: list[str] | None = None) -> None:
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
    output_dir = args.output / "autogrep_semgrep" / timestamp
    output_dir.mkdir(parents=True, exist_ok=True)
    _add_file_logging(output_dir / "autogrep_generation.log")

    _save_json(
        _redacted_run_config(args, api_key=api_key, split=split),
        output_dir / "run_config.json",
    )

    dataset = load_dataset(args.dataset)
    patch_records = prepare_autogrep_patches(
        dataset=dataset,
        dataset_path=args.dataset,
        dev_cves=args.dev_cves,
        patches_dir=output_dir / "prepared_patches",
    )
    _save_json(patch_records, output_dir / "prepared_patches.json")

    autogrep_meta = run_autogrep(
        autogrep_dir=args.autogrep_dir,
        runtime_dir=output_dir / "autogrep_runtime",
        patches_dir=output_dir / "prepared_patches",
        generated_dir=output_dir / "autogrep_generated_rules",
        filtered_dir=output_dir / "autogrep_filtered_rules",
        repos_cache_dir=output_dir / "autogrep_repo_cache",
        logs_dir=output_dir / "logs",
        api_key=api_key,
        llm_model=args.llm_model,
        llm_url=args.llm_url,
        max_files_changed=args.max_files_changed,
        max_retries=args.max_retries,
    )
    _save_json(autogrep_meta, output_dir / "autogrep_subprocesses.json")
    if autogrep_meta.get("generated_rule_count", 0) == 0:
        _save_json(
            {
                "accepted_rule_count": 0,
                "generated_rule_count": 0,
                "validation_message": "no_generated_rules",
                "dev_cves": args.dev_cves,
                "eval_cves": args.eval_cves,
                "leakage_check_passed": split["leakage_check_passed"],
                "dev_eval_overlap": split["dev_eval_overlap"],
                "aborted_before_eval": True,
                "autogrep_subprocesses": autogrep_meta,
            },
            output_dir / "eval_summary.json",
        )
        raise SystemExit("AutoGrep generated zero rules; aborted before filter/eval")
    if autogrep_meta["generate"]["returncode"] != 0 or (
        autogrep_meta.get("filter") and autogrep_meta["filter"]["returncode"] != 0
    ):
        raise SystemExit(f"AutoGrep subprocess failed; see {output_dir / 'logs'}")

    rules_yaml, source_rules = load_frozen_rules(output_dir / "autogrep_filtered_rules")
    valid_rules, validation_message = validate_rules_yaml(rules_yaml)
    accepted_dir = output_dir / "accepted_rules"
    accepted_dir.mkdir(parents=True, exist_ok=True)
    accepted_path = accepted_dir / "autogrep_rules.yaml"
    accepted_path.write_text(rules_yaml)
    if not valid_rules:
        _save_json(
            {
                "accepted_rule_count": _rule_count(rules_yaml),
                "validation_message": validation_message,
                "source_rules": str(source_rules),
                "dev_cves": args.dev_cves,
                "eval_cves": args.eval_cves,
                "leakage_check_passed": split["leakage_check_passed"],
                "dev_eval_overlap": split["dev_eval_overlap"],
                "aborted_before_eval": True,
            },
            output_dir / "eval_summary.json",
        )
        raise SystemExit(f"Frozen AutoGrep rules are invalid or empty: {validation_message}")

    eval_cves = [dataset[cve_id] for cve_id in args.eval_cves]
    eval_results, eval_summary = evaluate_rule_pack(
        rules_yaml=rules_yaml,
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
            "accepted_rule_count": _rule_count(rules_yaml),
            "source_rules": str(source_rules),
            "rules_validation_message": validation_message,
            "autogrep_subprocesses": autogrep_meta,
        }
    )
    _save_json(eval_results, output_dir / "eval_results.json")
    _save_json(eval_summary, output_dir / "eval_summary.json")
    _write_eval_findings(eval_results, output_dir / "eval_findings.jsonl")
    logger.info("AutoGrep Semgrep loop complete; results saved to %s", output_dir)


if __name__ == "__main__":
    main()
