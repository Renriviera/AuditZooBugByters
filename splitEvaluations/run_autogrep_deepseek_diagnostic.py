#!/usr/bin/env python3
"""Run an AutoGrep DeepSeek/OpenRouter diagnostic with decision logs."""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

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
from splitEvaluations.run_autogrep_semgrep_loop import (  # noqa: E402
    _add_file_logging,
    _run_logged_subprocess,
    build_autogrep_commands,
    count_autogrep_generated_rules,
    evaluate_rule_pack,
    load_dataset,
    load_frozen_rules,
    prepare_autogrep_patches,
    validate_rules_yaml,
    validate_split,
)

OPENROUTER_API_KEY = ""
DEEPSEEK_MODEL = "deepseek/deepseek-chat"
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

logger = logging.getLogger(__name__)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--clone-dir",
        type=Path,
        default=DEFAULT_CLONE_DIR / "autogrep_deepseek",
    )
    parser.add_argument(
        "--autogrep-dir",
        type=Path,
        default=Path("workspace/autogrep"),
        help="Path to an external lambdasec/autogrep checkout.",
    )
    parser.add_argument("--llm-url", default=OPENROUTER_BASE_URL)
    parser.add_argument("--llm-model", default=DEEPSEEK_MODEL)
    parser.add_argument("--line-tolerance", type=int, default=5)
    parser.add_argument("--max-retries", type=int, default=3)
    parser.add_argument("--max-files-changed", type=int, default=1)
    parser.add_argument("--skip-eval", action="store_true", default=False)
    parser.add_argument("--dev-cves", nargs="+", default=list(PATCH_RULE_DEV_CVES))
    parser.add_argument("--eval-cves", nargs="+", default=list(PATCH_RULE_EVAL_CVES))
    parser.add_argument(
        "--api-key",
        default=None,
        help="OpenRouter API key. Defaults to OPENROUTER_API_KEY env, then top-level placeholder.",
    )
    return parser.parse_args(argv)


def resolve_api_key(args: argparse.Namespace) -> str:
    return args.api_key or os.environ.get("OPENROUTER_API_KEY", "") or OPENROUTER_API_KEY


def _redacted_run_config(
    args: argparse.Namespace, *, api_key: str, split: dict[str, Any]
) -> dict[str, Any]:
    config = vars(args).copy()
    config["api_key"] = "<redacted>" if api_key else ""
    config["sweep"] = "autogrep_deepseek_diagnostic"
    config.update(split)
    return config


def _jsonl_count(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open(encoding="utf-8") as fh:
        return sum(1 for line in fh if line.strip())


def _iter_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                rows.append({"parse_error": line.strip()[:500]})
    return rows


def _copy_diagnostic_runtime(
    autogrep_dir: Path,
    runtime_dir: Path,
    *,
    llm_model: str,
    llm_url: str,
    diagnostics_dir: Path,
) -> Path:
    if not autogrep_dir.exists():
        raise FileNotFoundError(
            f"AutoGrep checkout not found: {autogrep_dir}. "
            "Clone https://github.com/lambdasec/autogrep and pass --autogrep-dir."
        )
    for required_name in ("main.py", "rule_filter.py", "llm_client.py", "rule_validator.py"):
        required = autogrep_dir / required_name
        if not required.exists():
            raise FileNotFoundError(f"AutoGrep checkout is missing {required_name}: {required}")

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
    patch_runtime_diagnostics(
        runtime_dir,
        llm_model=llm_model,
        llm_url=llm_url,
        diagnostics_dir=diagnostics_dir,
    )
    return runtime_dir


def patch_runtime_diagnostics(
    runtime_dir: Path,
    *,
    llm_model: str,
    llm_url: str,
    diagnostics_dir: Path,
) -> None:
    diagnostics_dir.mkdir(parents=True, exist_ok=True)
    _patch_llm_client(runtime_dir / "llm_client.py", llm_model, diagnostics_dir)
    _patch_rule_validator(runtime_dir / "rule_validator.py", diagnostics_dir)
    _patch_rule_filter(runtime_dir / "rule_filter.py", llm_model, llm_url, diagnostics_dir)


def _diag_helper_code(jsonl_name: str, diagnostics_dir: Path) -> str:
    path_literal = repr(str(diagnostics_dir / jsonl_name))
    return f"""
import hashlib as _ag_diag_hashlib
import json as _ag_diag_json
from pathlib import Path as _ag_diag_Path

_AG_DIAG_PATH = _ag_diag_Path({path_literal})

def _ag_diag_write(record):
    _AG_DIAG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _AG_DIAG_PATH.open("a", encoding="utf-8") as _fh:
        _fh.write(_ag_diag_json.dumps(record, default=str) + "\\n")

def _ag_diag_hash(text):
    return _ag_diag_hashlib.sha256((text or "").encode("utf-8", errors="replace")).hexdigest()[:16]
"""


def _patch_llm_client(path: Path, llm_model: str, diagnostics_dir: Path) -> None:
    text = path.read_text()
    text = text.replace("from pathlib import Path\n", "from pathlib import Path\n" + _diag_helper_code("generation_attempts.jsonl", diagnostics_dir))
    text = text.replace('model="deepseek/deepseek-chat"', f'model="{llm_model}"')
    text = text.replace("model='deepseek/deepseek-chat'", f"model='{llm_model}'")
    text = text.replace(
        "            response = self.client.chat.completions.create(",
        "            _ag_diag_record = {\n"
        "                'repo': f'{patch_info.repo_owner}/{patch_info.repo_name}',\n"
        "                'commit_id': patch_info.commit_id,\n"
        "                'language': patch_info.file_changes[0].language if patch_info.file_changes else None,\n"
        "                'changed_files': [fc.file_path for fc in patch_info.file_changes],\n"
        "                'model': self.config.openrouter_base_url + '|' + self.config.openrouter_api_key[:0] + " + repr(llm_model) + ",\n"
        "                'base_url': self.config.openrouter_base_url,\n"
        "                'prompt_hash': _ag_diag_hash(prompt),\n"
        "                'prompt_excerpt': prompt[:1500],\n"
        "                'error_feedback': error_feedback,\n"
        "            }\n"
        "            response = self.client.chat.completions.create(",
        1,
    )
    text = text.replace(
        "            content = response.choices[0].message.content\n",
        "            content = response.choices[0].message.content\n"
        "            _ag_diag_record['raw_response'] = content\n",
        1,
    )
    text = text.replace(
        "            rule_text = self.extract_response(content)\n",
        "            rule_text = self.extract_response(content)\n"
        "            _ag_diag_record['extracted_response'] = rule_text\n",
        1,
    )
    text = text.replace(
        "            rule_text = self.clean_yaml_text(rule_text)\n",
        "            rule_text = self.clean_yaml_text(rule_text)\n"
        "            _ag_diag_record['cleaned_yaml'] = rule_text\n",
        1,
    )
    text = text.replace(
        "                rule_data = yaml.safe_load(rule_text)\n",
        "                rule_data = yaml.safe_load(rule_text)\n"
        "                _ag_diag_record['parsed_type'] = type(rule_data).__name__\n"
        "                if isinstance(rule_data, dict):\n"
        "                    _ag_diag_record['parsed_keys'] = list(rule_data.keys())\n",
        1,
    )
    text = text.replace(
        "                if not is_valid:\n"
        "                    logging.error(f\"Invalid rule schema: {error}\")\n"
        "                    return None\n",
        "                if not is_valid:\n"
        "                    _ag_diag_record['schema_valid'] = False\n"
        "                    _ag_diag_record['schema_error'] = error\n"
        "                    _ag_diag_record['has_patterns_or_taint'] = any(k in rule for k in ['patterns', 'pattern-either', 'pattern-sources', 'pattern-sinks']) if isinstance(rule, dict) else False\n"
        "                    _ag_diag_write(_ag_diag_record)\n"
        "                    logging.error(f\"Invalid rule schema: {error}\")\n"
        "                    return None\n",
        1,
    )
    text = text.replace(
        "                return rule\n",
        "                _ag_diag_record['schema_valid'] = True\n"
        "                _ag_diag_record['rule_id'] = rule.get('id') if isinstance(rule, dict) else None\n"
        "                _ag_diag_write(_ag_diag_record)\n"
        "                return rule\n",
        1,
    )
    text = text.replace(
        "            except yaml.YAMLError as e:\n"
        "                logging.error(f\"Error parsing generated rule YAML: {e}\")\n"
        "                return None\n",
        "            except yaml.YAMLError as e:\n"
        "                _ag_diag_record['yaml_parse_error'] = str(e)\n"
        "                _ag_diag_write(_ag_diag_record)\n"
        "                logging.error(f\"Error parsing generated rule YAML: {e}\")\n"
        "                return None\n",
        1,
    )
    text = text.replace(
        "        except Exception as e:\n"
        "            logging.error(f\"Error generating rule: {e}\")\n"
        "            return None\n",
        "        except Exception as e:\n"
        "            try:\n"
        "                _ag_diag_record['exception'] = str(e)\n"
        "                _ag_diag_write(_ag_diag_record)\n"
        "            except Exception:\n"
        "                pass\n"
        "            logging.error(f\"Error generating rule: {e}\")\n"
        "            return None\n",
        1,
    )
    path.write_text(text)


def _patch_rule_validator(path: Path, diagnostics_dir: Path) -> None:
    text = path.read_text()
    text = text.replace("import logging\n", "import logging\n" + _diag_helper_code("validation_attempts.jsonl", diagnostics_dir))
    text = text.replace(
        "            # Rule is valid if it detects vulnerability in parent commit but not in fixed commit\n"
        "            is_valid = len(vuln_results) > 0 and len(fixed_results) == 0\n",
        "            _ag_diag_record = {\n"
        "                'repo': f'{patch_info.repo_owner}/{patch_info.repo_name}',\n"
        "                'commit_id': patch_info.commit_id,\n"
        "                'rule_id': rule.get('id') if isinstance(rule, dict) else None,\n"
        "                'vulnerable_findings': len(vuln_results),\n"
        "                'fixed_findings': len(fixed_results),\n"
        "                'skipped_files': skip_count,\n"
        "            }\n"
        "            # Rule is valid if it detects vulnerability in parent commit but not in fixed commit\n"
        "            is_valid = len(vuln_results) > 0 and len(fixed_results) == 0\n",
        1,
    )
    text = text.replace(
        "                return False, error_msg\n",
        "                _ag_diag_record['valid'] = False\n"
        "                _ag_diag_record['reason'] = error_msg\n"
        "                _ag_diag_write(_ag_diag_record)\n"
        "                return False, error_msg\n",
        1,
    )
    text = text.replace(
        "            return True, None\n",
        "            _ag_diag_record['valid'] = True\n"
        "            _ag_diag_record['reason'] = 'detected_vuln_only'\n"
        "            _ag_diag_write(_ag_diag_record)\n"
        "            return True, None\n",
        1,
    )
    text = text.replace(
        "        except git.exc.GitCommandError as e:\n"
        "            return False, f\"Git error during validation: {str(e)}\"\n"
        "        except Exception as e:\n"
        "            return False, f\"Validation error: {str(e)}\"\n",
        "        except git.exc.GitCommandError as e:\n"
        "            _ag_diag_write({'commit_id': getattr(patch_info, 'commit_id', ''), 'rule_id': rule.get('id') if isinstance(rule, dict) else None, 'valid': False, 'reason': 'git_error', 'error': str(e)})\n"
        "            return False, f\"Git error during validation: {str(e)}\"\n"
        "        except Exception as e:\n"
        "            _ag_diag_write({'commit_id': getattr(patch_info, 'commit_id', ''), 'rule_id': rule.get('id') if isinstance(rule, dict) else None, 'valid': False, 'reason': 'validation_exception', 'error': str(e)})\n"
        "            return False, f\"Validation error: {str(e)}\"\n",
        1,
    )
    path.write_text(text)


def _patch_rule_filter(
    path: Path,
    llm_model: str,
    llm_url: str,
    diagnostics_dir: Path,
) -> None:
    text = path.read_text()
    text = text.replace("import os\n", "import os\n" + _diag_helper_code("filter_decisions.jsonl", diagnostics_dir))
    text = text.replace(
        'self.client = OpenAI(api_key= os.getenv("OPENROUTER_API_KEY"), base_url="https://openrouter.ai/api/v1")',
        f'self.client = OpenAI(api_key=os.getenv("OPENROUTER_API_KEY"), base_url="{llm_url}")',
    )
    text = text.replace('model="deepseek/deepseek-chat"', f'model="{llm_model}"')
    text = text.replace("model='deepseek/deepseek-chat'", f"model='{llm_model}'")
    text = text.replace(
        "            decision = lines[0].strip().upper() == 'ACCEPT'\n"
        "            reason = lines[1].strip() if len(lines) > 1 else \"Unknown reason\"\n"
        "            \n"
        "            return decision, reason\n",
        "            decision = lines[0].strip().upper() == 'ACCEPT'\n"
        "            reason = lines[1].strip() if len(lines) > 1 else \"Unknown reason\"\n"
        "            _ag_diag_write({'phase': 'quality', 'model': " + repr(llm_model) + ", 'rule_id': rule.get('id') if isinstance(rule, dict) else None, 'accepted': decision, 'reason': reason, 'raw_response': response.choices[0].message.content})\n"
        "            \n"
        "            return decision, reason\n",
        1,
    )
    text = text.replace(
        "        except Exception as e:\n"
        "            logging.error(f\"Error evaluating rule: {e}\")\n"
        "            return False, str(e)\n",
        "        except Exception as e:\n"
        "            _ag_diag_write({'phase': 'quality', 'rule_id': rule.get('id') if isinstance(rule, dict) else None, 'accepted': False, 'reason': str(e), 'exception': str(e)})\n"
        "            logging.error(f\"Error evaluating rule: {e}\")\n"
        "            return False, str(e)\n",
        1,
    )
    text = text.replace(
        "                if self.is_duplicate(rule, processed_rules):\n"
        "                    self.stats[language].duplicate_rules += 1\n"
        "                    continue\n",
        "                if self.is_duplicate(rule, processed_rules):\n"
        "                    _ag_diag_write({'phase': 'dedupe', 'language': language, 'rule_id': rule.get('id') if isinstance(rule, dict) else None, 'accepted': False, 'reason': 'duplicate'})\n"
        "                    self.stats[language].duplicate_rules += 1\n"
        "                    continue\n",
        1,
    )
    text = text.replace(
        "        print(f\"Overall Acceptance Rate: {(total_stats.accepted_rules / total_stats.total_rules * 100):.1f}%\")\n",
        "        rate = (total_stats.accepted_rules / total_stats.total_rules * 100) if total_stats.total_rules else 0.0\n"
        "        print(f\"Overall Acceptance Rate: {rate:.1f}%\")\n"
        "        _ag_diag_write({'phase': 'summary', 'total_rules': total_stats.total_rules, 'accepted_rules': total_stats.accepted_rules, 'acceptance_rate': rate})\n",
        1,
    )
    path.write_text(text)


def run_autogrep_deepseek(
    *,
    autogrep_dir: Path,
    runtime_dir: Path,
    patches_dir: Path,
    generated_dir: Path,
    filtered_dir: Path,
    repos_cache_dir: Path,
    logs_dir: Path,
    diagnostics_dir: Path,
    api_key: str,
    llm_model: str,
    llm_url: str,
    max_files_changed: int,
    max_retries: int,
) -> dict[str, Any]:
    runtime = _copy_diagnostic_runtime(
        autogrep_dir,
        runtime_dir,
        llm_model=llm_model,
        llm_url=llm_url,
        diagnostics_dir=diagnostics_dir,
    )
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
    generated_rule_count = count_autogrep_generated_rules(generated_dir)
    if generate["returncode"] != 0 or generated_rule_count == 0:
        return {
            "generate": generate,
            "filter": None,
            "runtime_dir": str(runtime),
            "generated_rule_count": generated_rule_count,
            "aborted_before_filter": generated_rule_count == 0,
            "abort_reason": "no_generated_rules" if generated_rule_count == 0 else "generation_failed",
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


def _log_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(errors="replace")


def build_diagnostic_summary(
    *,
    output_dir: Path,
    dev_cves: list[str],
    eval_cves: list[str],
    split: dict[str, Any],
    autogrep_meta: dict[str, Any],
    eval_summary: dict[str, Any] | None = None,
    frozen_rules_exists: bool = False,
) -> dict[str, Any]:
    diagnostics_dir = output_dir / "diagnostics"
    generation_rows = _iter_jsonl(diagnostics_dir / "generation_attempts.jsonl")
    validation_rows = _iter_jsonl(diagnostics_dir / "validation_attempts.jsonl")
    filter_rows = _iter_jsonl(diagnostics_dir / "filter_decisions.jsonl")
    generation_log = _log_text(output_dir / "logs" / "autogrep_generate.log")
    filter_log = _log_text(output_dir / "logs" / "autogrep_filter.log")

    validation_reasons = Counter(str(row.get("reason", "")) for row in validation_rows)
    schema_failures = [
        row for row in generation_rows if row.get("schema_valid") is False
    ]
    output_shape_failures = [
        row for row in schema_failures if row.get("has_patterns_or_taint")
    ]
    quality_rows = [row for row in filter_rows if row.get("phase") == "quality"]
    accepted_quality = [row for row in quality_rows if row.get("accepted") is True]

    log_schema_missing = len(re.findall(r"Missing required fields: pattern", generation_log))
    log_missed_vuln = len(re.findall(r"Rule failed to detect vulnerability", generation_log))
    log_hit_fixed = len(re.findall(r"Rule incorrectly detected vulnerability", generation_log))
    log_git_errors = len(re.findall(r"Error preparing repository|Git error", generation_log))
    llm_successes = len(re.findall(r'chat/completions "HTTP/1\.1 200 OK"', generation_log))
    llm_failures = len(re.findall(r'chat/completions "HTTP/1\.1 (?!200)', generation_log))

    generated_rule_count = int(autogrep_meta.get("generated_rule_count", 0) or 0)
    filtered_return = (
        autogrep_meta.get("filter", {}) or {}
    ).get("returncode")
    eval_ran = eval_summary is not None and not eval_summary.get("aborted_before_eval", False)

    if log_git_errors:
        recommended = "replace_dev_cves"
    elif log_schema_missing or output_shape_failures:
        recommended = "fix_schema_validator"
    elif generated_rule_count == 0 and log_missed_vuln:
        recommended = "prompt_top_level_pattern_only"
    elif generated_rule_count > 0 and not frozen_rules_exists:
        recommended = "inspect_filter_rejections"
    elif frozen_rules_exists and not eval_ran:
        recommended = "run_eval"
    elif eval_ran:
        recommended = "compare_eval_metrics"
    else:
        recommended = "try_other_model"

    return {
        "dev_cves": dev_cves,
        "eval_cves": eval_cves,
        "leakage_check_passed": split["leakage_check_passed"],
        "dev_eval_overlap": split["dev_eval_overlap"],
        "dev_patches_attempted": len(dev_cves),
        "llm_calls_succeeded": llm_successes,
        "llm_calls_failed": llm_failures,
        "generation_attempts_logged": len(generation_rows),
        "validation_attempts_logged": len(validation_rows),
        "filter_decisions_logged": len(filter_rows),
        "yaml_parse_failures": len([row for row in generation_rows if row.get("yaml_parse_error")]),
        "schema_failures": len(schema_failures) or log_schema_missing,
        "patterns_or_taint_shape_failures": len(output_shape_failures),
        "valid_schema_failed_vulnerable_detection": validation_reasons.get(
            "Rule failed to detect vulnerability in original version", 0
        )
        or log_missed_vuln,
        "hit_patched_commit_rejections": validation_reasons.get(
            "Rule incorrectly detected vulnerability in fixed version", 0
        )
        or log_hit_fixed,
        "git_or_checkout_failures": log_git_errors,
        "generated_rule_count": generated_rule_count,
        "filtered_returncode": filtered_return,
        "filter_quality_rejections": len(quality_rows) - len(accepted_quality),
        "filter_quality_acceptances": len(accepted_quality),
        "frozen_rule_pack_exists": frozen_rules_exists,
        "eval_ran": eval_ran,
        "eval_summary": eval_summary if eval_ran else None,
        "autogrep_subprocesses": autogrep_meta,
        "recommended_next_step": recommended,
        "notes": {
            "generation_log": str(output_dir / "logs" / "autogrep_generate.log"),
            "filter_log": str(output_dir / "logs" / "autogrep_filter.log"),
        },
        "raw_filter_summary_contains_zero_input_crash": "ZeroDivisionError" in filter_log,
    }


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    api_key = resolve_api_key(args)
    if not api_key:
        raise SystemExit(
            "No API key provided. Set OPENROUTER_API_KEY, pass --api-key, or fill "
            "OPENROUTER_API_KEY at the top of this script."
        )

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    split = validate_split(args.dev_cves, args.eval_cves)
    if not split["leakage_check_passed"]:
        raise SystemExit(f"Invalid dev/eval split: {split}")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = args.output / "autogrep_deepseek" / timestamp
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

    autogrep_meta = run_autogrep_deepseek(
        autogrep_dir=args.autogrep_dir,
        runtime_dir=output_dir / "autogrep_runtime",
        patches_dir=output_dir / "prepared_patches",
        generated_dir=output_dir / "autogrep_generated_rules",
        filtered_dir=output_dir / "autogrep_filtered_rules",
        repos_cache_dir=output_dir / "autogrep_repo_cache",
        logs_dir=output_dir / "logs",
        diagnostics_dir=output_dir / "diagnostics",
        api_key=api_key,
        llm_model=args.llm_model,
        llm_url=args.llm_url,
        max_files_changed=args.max_files_changed,
        max_retries=args.max_retries,
    )
    _save_json(autogrep_meta, output_dir / "autogrep_subprocesses.json")

    eval_summary: dict[str, Any] | None = None
    frozen_rules_exists = False
    if autogrep_meta.get("generated_rule_count", 0) > 0 and not args.skip_eval:
        try:
            rules_yaml, source_rules = load_frozen_rules(output_dir / "autogrep_filtered_rules")
            valid_rules, validation_message = validate_rules_yaml(rules_yaml)
            if valid_rules:
                accepted_dir = output_dir / "accepted_rules"
                accepted_dir.mkdir(parents=True, exist_ok=True)
                (accepted_dir / "autogrep_rules.yaml").write_text(rules_yaml)
                frozen_rules_exists = True
                eval_cves = [dataset[cve_id] for cve_id in args.eval_cves]
                eval_results, eval_summary = evaluate_rule_pack(
                    rules_yaml=rules_yaml,
                    eval_cves=eval_cves,
                    clone_dir=args.clone_dir,
                    line_tolerance=args.line_tolerance,
                )
                eval_summary.update(
                    {
                        "source_rules": str(source_rules),
                        "rules_validation_message": validation_message,
                        "accepted_rule_count": len(yaml.safe_load(rules_yaml).get("rules", [])),
                    }
                )
                _save_json(eval_results, output_dir / "eval_results.json")
                _save_json(eval_summary, output_dir / "eval_summary.json")
                with (output_dir / "eval_findings.jsonl").open("w", encoding="utf-8") as fh:
                    for row in eval_results:
                        for finding in row.get("findings", []) or []:
                            fh.write(json.dumps({"cve_id": row.get("cve_id"), **finding}) + "\n")
            else:
                eval_summary = {
                    "aborted_before_eval": True,
                    "validation_message": validation_message,
                }
        except FileNotFoundError as exc:
            eval_summary = {"aborted_before_eval": True, "validation_message": str(exc)}
    elif args.skip_eval:
        eval_summary = {"aborted_before_eval": True, "validation_message": "skip_eval"}
    else:
        eval_summary = {"aborted_before_eval": True, "validation_message": "no_generated_rules"}

    summary = build_diagnostic_summary(
        output_dir=output_dir,
        dev_cves=args.dev_cves,
        eval_cves=args.eval_cves,
        split=split,
        autogrep_meta=autogrep_meta,
        eval_summary=eval_summary,
        frozen_rules_exists=frozen_rules_exists,
    )
    _save_json(summary, output_dir / "diagnostic_summary.json")
    logger.info("DeepSeek AutoGrep diagnostic saved to %s", output_dir)


if __name__ == "__main__":
    main()
