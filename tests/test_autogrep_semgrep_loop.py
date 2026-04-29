"""Tests for the AutoGrep Semgrep 5-dev/20-eval loop helpers."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

from auditzoo.agents.cwe78_study.schemas import Finding
from splitEvaluations import run_autogrep_semgrep_loop as loop
from splitEvaluations.readiness_config import PATCH_RULE_DEV_CVES, PATCH_RULE_EVAL_CVES


def test_autogrep_splits_are_disjoint_and_sized() -> None:
    split = loop.validate_split(list(PATCH_RULE_DEV_CVES), list(PATCH_RULE_EVAL_CVES))

    assert split["dev_count"] == 5
    assert split["eval_count"] == 20
    assert split["dev_unique"] is True
    assert split["eval_unique"] is True
    assert split["dev_eval_overlap"] == []
    assert split["leakage_check_passed"] is True


def test_api_key_precedence_and_redaction(monkeypatch) -> None:
    monkeypatch.setattr(loop, "GPT54_MINI_API_KEY", "placeholder-key")
    monkeypatch.setenv("OPENAI_API_KEY", "env-key")

    args = loop.parse_args([])
    assert loop.resolve_api_key(args) == "env-key"

    args_cli = loop.parse_args(["--api-key", "sk-proj-secret"])
    split = loop.validate_split(list(PATCH_RULE_DEV_CVES), list(PATCH_RULE_EVAL_CVES))
    config = loop._redacted_run_config(args_cli, api_key="sk-proj-secret", split=split)

    assert config["api_key"] == "<redacted>"
    assert "sk-proj-secret" not in str(config)
    assert loop._redact_text("token sk-proj-secret") == "token <redacted-openai-api-key>"


def test_prepare_autogrep_patches_writes_expected_filenames(tmp_path: Path) -> None:
    dataset_path = tmp_path / "metadata.json"
    diff_path = tmp_path / "diffs" / "CVE-X.diff"
    diff_path.parent.mkdir()
    diff_path.write_text("diff --git a/app.py b/app.py\n-old\n+new\n")
    dataset = {
        "CVE-X": {
            "cve_id": "CVE-X",
            "repo_url": "https://github.com/acme/example",
            "patch_commit": "abcdef1234567890",
            "patch_diff_path": "diffs/CVE-X.diff",
        }
    }

    records = loop.prepare_autogrep_patches(
        dataset=dataset,
        dataset_path=dataset_path,
        dev_cves=["CVE-X"],
        patches_dir=tmp_path / "prepared",
    )

    assert records == [
        {
            "cve_id": "CVE-X",
            "source_diff": str(diff_path),
            "autogrep_patch": str(tmp_path / "prepared" / "github.com_acme_example_abcdef1234567890.patch"),
            "repo_url": "https://github.com/acme/example",
            "patch_commit": "abcdef1234567890",
        }
    ]
    assert Path(records[0]["autogrep_patch"]).read_text().startswith("diff --git")


def test_build_autogrep_commands_redacts_and_sets_model_env() -> None:
    generate_cmd, filter_cmd, env = loop.build_autogrep_commands(
        runtime_dir=Path("runtime"),
        patches_dir=Path("patches"),
        generated_dir=Path("generated"),
        filtered_dir=Path("filtered"),
        repos_cache_dir=Path("repos"),
        api_key="sk-proj-secret",
        llm_url="https://api.openai.com/v1",
        max_files_changed=1,
        max_retries=3,
    )

    assert "main.py" in generate_cmd
    assert "--openrouter-api-key" in generate_cmd
    assert "sk-proj-secret" in generate_cmd
    assert "rule_filter.py" in filter_cmd
    assert env["OPENROUTER_API_KEY"] == "sk-proj-secret"
    assert "sk-proj-secret" not in str([loop._redact_text(part) for part in generate_cmd])


def test_patch_runtime_python_file_uses_gpt_model_url_and_removes_temperature(tmp_path: Path) -> None:
    llm_client = tmp_path / "llm_client.py"
    llm_client.write_text(
        'response = client.chat.completions.create(\n'
        '    model="deepseek/deepseek-chat",\n'
        '    base_url="https://openrouter.ai/api/v1",\n'
        "    messages=[],\n"
        "    temperature=0.2,\n"
        ")\n"
    )

    loop._patch_runtime_python_file(llm_client, "gpt-5.4-mini", "https://api.openai.com/v1")

    text = llm_client.read_text()
    assert 'model="gpt-5.4-mini"' in text
    assert 'base_url="https://api.openai.com/v1"' in text
    assert "temperature=0.2" not in text


def test_load_frozen_rules_rejects_empty_pack(tmp_path: Path) -> None:
    rules = tmp_path / "python" / "repo_rules.yml"
    rules.parent.mkdir()
    rules.write_text("rules: []\n")

    with pytest.raises(FileNotFoundError):
        loop.load_frozen_rules(tmp_path)


def test_count_autogrep_generated_rules_counts_nested_yaml(tmp_path: Path) -> None:
    python_dir = tmp_path / "python"
    python_dir.mkdir()
    (python_dir / "empty.yml").write_text("rules: []\n")
    (python_dir / "one.yml").write_text(
        yaml.dump(
            {
                "rules": [
                    {
                        "id": "x",
                        "pattern": "os.system($X)",
                        "languages": ["python"],
                        "message": "x",
                        "severity": "ERROR",
                    }
                ]
            }
        )
    )

    assert loop.count_autogrep_generated_rules(tmp_path) == 1


def test_load_frozen_rules_merges_repo_named_rule_files(tmp_path: Path) -> None:
    rules = tmp_path / "python" / "Gerapy_rules.yml"
    rules.parent.mkdir()
    rules.write_text(
        yaml.dump(
            {
                "rules": [
                    {
                        "id": "x",
                        "pattern": "Popen($CMD, shell=True)",
                        "languages": ["python"],
                        "message": "x",
                        "severity": "ERROR",
                    }
                ]
            }
        )
    )

    rules_yaml, source = loop.load_frozen_rules(tmp_path)

    assert source == tmp_path / "python"
    assert yaml.safe_load(rules_yaml)["rules"][0]["id"] == "x"


def test_validate_rules_yaml_uses_temp_file(monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_run(cmd, capture_output, text, timeout):  # noqa: ANN001
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(loop.subprocess, "run", fake_run)

    valid, message = loop.validate_rules_yaml(
        yaml.dump(
            {
                "rules": [
                    {
                        "id": "x",
                        "pattern": "os.system($X)",
                        "languages": ["python"],
                        "message": "x",
                        "severity": "ERROR",
                    }
                ]
            }
        )
    )

    assert valid is True
    assert message == "ok"
    assert calls
    assert calls[0][2] != "-"


def test_evaluate_rule_pack_summary_aggregation(monkeypatch, tmp_path: Path) -> None:
    cves = [
        {
            "cve_id": "CVE-A",
            "repo_url": "unused",
            "vulnerable_commit": "v",
            "patch_commit": "p",
            "vulnerable_file": "app.py",
            "vulnerable_lines": [10],
        },
        {
            "cve_id": "CVE-B",
            "repo_url": "unused",
            "vulnerable_commit": "v",
            "patch_commit": "p",
            "vulnerable_file": "other.py",
            "vulnerable_lines": [20],
        },
    ]

    def fake_clone(repo_url: str, commit: str, dest: Path, *, shallow: bool = True) -> bool:
        dest.mkdir(parents=True, exist_ok=True)
        return True

    def fake_scan(rules_yaml: str, repo_path: Path) -> list[Finding]:
        if "CVE-A" in str(repo_path) and "vulnerable" in str(repo_path):
            return [
                Finding(
                    file_path=str(repo_path / "app.py"),
                    line_start=10,
                    line_end=10,
                    rule_id="autogrep-x",
                    message="x",
                )
            ]
        if "CVE-A" in str(repo_path) and "patched" in str(repo_path):
            return [
                Finding(
                    file_path=str(repo_path / "app.py"),
                    line_start=10,
                    line_end=10,
                    rule_id="autogrep-x",
                    message="x",
                )
            ]
        return []

    monkeypatch.setattr(loop, "clone_and_checkout", fake_clone)
    monkeypatch.setattr(loop, "scan_rule_pack", fake_scan)

    results, summary = loop.evaluate_rule_pack(
        rules_yaml="rules: []\n",
        eval_cves=cves,
        clone_dir=tmp_path,
        line_tolerance=5,
    )

    assert len(results) == 2
    assert summary["totals"]["tp"] == 1
    assert summary["totals"]["fn"] == 1
    assert summary["totals"]["n_candidates"] == 1
    assert summary["zero_candidate_cves"] == ["CVE-B"]
    assert summary["patched_findings_total"] == 1
    assert summary["per_rule_hits"] == {"autogrep-x": 1}
    assert summary["per_rule_tp"] == {"autogrep-x": 1}
