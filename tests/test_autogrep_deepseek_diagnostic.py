"""Tests for the DeepSeek/OpenRouter AutoGrep diagnostic runner."""

from __future__ import annotations

import json
from pathlib import Path

from splitEvaluations import run_autogrep_deepseek_diagnostic as diag
from splitEvaluations.readiness_config import PATCH_RULE_DEV_CVES, PATCH_RULE_EVAL_CVES


def test_defaults_use_deepseek_openrouter_and_fixed_split() -> None:
    args = diag.parse_args([])

    assert args.llm_model == diag.DEEPSEEK_MODEL
    assert args.llm_url == diag.OPENROUTER_BASE_URL
    assert tuple(args.dev_cves) == PATCH_RULE_DEV_CVES
    assert tuple(args.eval_cves) == PATCH_RULE_EVAL_CVES
    assert args.skip_eval is False


def test_api_key_precedence_and_redaction(monkeypatch) -> None:
    monkeypatch.setattr(diag, "OPENROUTER_API_KEY", "placeholder-key")
    monkeypatch.setenv("OPENROUTER_API_KEY", "env-key")

    args = diag.parse_args([])
    assert diag.resolve_api_key(args) == "env-key"

    args_cli = diag.parse_args(["--api-key", "sk-or-secret"])
    split = diag.validate_split(list(PATCH_RULE_DEV_CVES), list(PATCH_RULE_EVAL_CVES))
    config = diag._redacted_run_config(args_cli, api_key="sk-or-secret", split=split)

    assert config["api_key"] == "<redacted>"
    assert config["sweep"] == "autogrep_deepseek_diagnostic"
    assert "sk-or-secret" not in str(config)


def test_patch_runtime_diagnostics_adds_hooks_and_deepseek_model(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "llm_client.py").write_text(
        "from pathlib import Path\n"
        "class C:\n"
        "    def generate_rule(self, patch_info, error_feedback=None):\n"
        "        prompt = 'x'\n"
        "        try:\n"
        "            response = self.client.chat.completions.create(\n"
        "                model=\"deepseek/deepseek-chat\",\n"
        "                messages=[]\n"
        "            )\n"
        "            content = response.choices[0].message.content\n"
        "            rule_text = self.extract_response(content)\n"
        "            rule_text = self.clean_yaml_text(rule_text)\n"
        "            try:\n"
        "                rule_data = yaml.safe_load(rule_text)\n"
        "                rule = self._sanitize_rule(rule_data, patch_info)\n"
        "                is_valid, error = self.validate_rule_schema(rule)\n"
        "                if not is_valid:\n"
        "                    logging.error(f\"Invalid rule schema: {error}\")\n"
        "                    return None\n"
        "                return rule\n"
        "            except yaml.YAMLError as e:\n"
        "                logging.error(f\"Error parsing generated rule YAML: {e}\")\n"
        "                return None\n"
        "        except Exception as e:\n"
        "            logging.error(f\"Error generating rule: {e}\")\n"
        "            return None\n"
    )
    (runtime / "rule_validator.py").write_text(
        "import logging\n"
        "class V:\n"
        "    def validate_rule(self, rule, patch_info, repo_path):\n"
        "        skip_count = 0\n"
        "        vuln_results = []\n"
        "        fixed_results = []\n"
        "            # Rule is valid if it detects vulnerability in parent commit but not in fixed commit\n"
        "        is_valid = len(vuln_results) > 0 and len(fixed_results) == 0\n"
        "        if not is_valid:\n"
        "            error_msg = 'Rule failed to detect vulnerability in original version'\n"
        "            return False, error_msg\n"
        "        return True, None\n"
        "        except git.exc.GitCommandError as e:\n"
        "            return False, f\"Git error during validation: {str(e)}\"\n"
        "        except Exception as e:\n"
        "            return False, f\"Validation error: {str(e)}\"\n"
    )
    (runtime / "rule_filter.py").write_text(
        "import os\n"
        "class F:\n"
        "    def __init__(self):\n"
        "        self.client = OpenAI(api_key= os.getenv(\"OPENROUTER_API_KEY\"), base_url=\"https://openrouter.ai/api/v1\")\n"
        "    def evaluate_rule_quality(self, rule):\n"
        "        try:\n"
        "            response = self.client.chat.completions.create(\n"
        "                model=\"deepseek/deepseek-chat\",\n"
        "                messages=[],\n"
        "                temperature=0.2\n"
        "            )\n"
        "            lines = response.choices[0].message.content.strip().split('\\n')\n"
        "            decision = lines[0].strip().upper() == 'ACCEPT'\n"
        "            reason = lines[1].strip() if len(lines) > 1 else \"Unknown reason\"\n"
        "            \n"
        "            return decision, reason\n"
        "        except Exception as e:\n"
        "            logging.error(f\"Error evaluating rule: {e}\")\n"
        "            return False, str(e)\n"
        "    def filter_rules(self):\n"
        "                if self.is_duplicate(rule, processed_rules):\n"
        "                    self.stats[language].duplicate_rules += 1\n"
        "                    continue\n"
        "    def print_summary(self):\n"
        "        print(f\"Overall Acceptance Rate: {(total_stats.accepted_rules / total_stats.total_rules * 100):.1f}%\")\n"
    )

    diag.patch_runtime_diagnostics(
        runtime,
        llm_model=diag.DEEPSEEK_MODEL,
        llm_url=diag.OPENROUTER_BASE_URL,
        diagnostics_dir=tmp_path / "diagnostics",
    )

    assert "generation_attempts.jsonl" in (runtime / "llm_client.py").read_text()
    assert "validation_attempts.jsonl" in (runtime / "rule_validator.py").read_text()
    filter_text = (runtime / "rule_filter.py").read_text()
    assert "filter_decisions.jsonl" in filter_text
    assert 'model="deepseek/deepseek-chat"' in filter_text
    assert "rate = (total_stats.accepted_rules" in filter_text


def test_build_diagnostic_summary_classifies_failures(tmp_path: Path) -> None:
    output_dir = tmp_path
    diag_dir = output_dir / "diagnostics"
    logs_dir = output_dir / "logs"
    diag_dir.mkdir()
    logs_dir.mkdir()
    (diag_dir / "generation_attempts.jsonl").write_text(
        json.dumps(
            {
                "schema_valid": False,
                "schema_error": "Missing required fields: pattern",
                "has_patterns_or_taint": True,
            }
        )
        + "\n"
    )
    (diag_dir / "validation_attempts.jsonl").write_text(
        json.dumps(
            {
                "valid": False,
                "reason": "Rule failed to detect vulnerability in original version",
            }
        )
        + "\n"
    )
    (diag_dir / "filter_decisions.jsonl").write_text(
        json.dumps({"phase": "quality", "accepted": False, "reason": "specific"}) + "\n"
    )
    (logs_dir / "autogrep_generate.log").write_text(
        'HTTP Request: POST https://openrouter.ai/api/v1/chat/completions "HTTP/1.1 200 OK"\n'
        "Invalid rule schema: Missing required fields: pattern\n"
    )
    (logs_dir / "autogrep_filter.log").write_text("")
    split = diag.validate_split(list(PATCH_RULE_DEV_CVES), list(PATCH_RULE_EVAL_CVES))

    summary = diag.build_diagnostic_summary(
        output_dir=output_dir,
        dev_cves=list(PATCH_RULE_DEV_CVES),
        eval_cves=list(PATCH_RULE_EVAL_CVES),
        split=split,
        autogrep_meta={"generated_rule_count": 0, "filter": None},
        eval_summary={"aborted_before_eval": True},
        frozen_rules_exists=False,
    )

    assert summary["llm_calls_succeeded"] == 1
    assert summary["schema_failures"] == 1
    assert summary["patterns_or_taint_shape_failures"] == 1
    assert summary["valid_schema_failed_vulnerable_detection"] == 1
    assert summary["filter_quality_rejections"] == 1
    assert summary["recommended_next_step"] == "fix_schema_validator"


def test_zero_generated_rules_summary_recommends_prompt_or_schema(tmp_path: Path) -> None:
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    (logs_dir / "autogrep_generate.log").write_text(
        "Rule failed to detect vulnerability in original version\n"
    )
    (logs_dir / "autogrep_filter.log").write_text("")
    split = diag.validate_split(list(PATCH_RULE_DEV_CVES), list(PATCH_RULE_EVAL_CVES))

    summary = diag.build_diagnostic_summary(
        output_dir=tmp_path,
        dev_cves=list(PATCH_RULE_DEV_CVES),
        eval_cves=list(PATCH_RULE_EVAL_CVES),
        split=split,
        autogrep_meta={"generated_rule_count": 0, "filter": None},
        eval_summary={"aborted_before_eval": True},
        frozen_rules_exists=False,
    )

    assert summary["generated_rule_count"] == 0
    assert summary["eval_ran"] is False
    assert summary["recommended_next_step"] == "prompt_top_level_pattern_only"
