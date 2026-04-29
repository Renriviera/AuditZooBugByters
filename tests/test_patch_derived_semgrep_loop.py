"""Tests for patch-derived Semgrep rule generation loop helpers."""

from __future__ import annotations

from pathlib import Path

import yaml

from auditzoo.agents.cwe78_study.schemas import Finding
from splitEvaluations import run_patch_derived_semgrep_loop as loop
from splitEvaluations.readiness_config import PATCH_RULE_DEV_CVES, PATCH_RULE_EVAL_CVES


def test_patch_rule_splits_are_disjoint_and_sized() -> None:
    split = loop.validate_split(list(PATCH_RULE_DEV_CVES), list(PATCH_RULE_EVAL_CVES))

    assert split["dev_count"] == 5
    assert split["eval_count"] == 20
    assert split["dev_unique"] is True
    assert split["eval_unique"] is True
    assert split["dev_eval_overlap"] == []
    assert split["leakage_check_passed"] is True


def test_validate_split_rejects_overlap() -> None:
    split = loop.validate_split(["CVE-A"] * 5, ["CVE-A", *[f"CVE-{i}" for i in range(19)]])

    assert split["leakage_check_passed"] is False
    assert split["dev_eval_overlap"] == ["CVE-A"]


def test_api_key_resolution_and_redaction(monkeypatch) -> None:
    monkeypatch.setattr(loop, "GPT54_MINI_API_KEY", "placeholder-key")
    monkeypatch.setenv("OPENAI_API_KEY", "env-key")

    args = loop.parse_args([])
    assert loop.resolve_api_key(args) == "env-key"

    args_cli = loop.parse_args(["--api-key", "cli-key"])
    split = loop.validate_split(list(PATCH_RULE_DEV_CVES), list(PATCH_RULE_EVAL_CVES))
    config = loop._redacted_run_config(args_cli, api_key="cli-key", split=split)

    assert config["api_key"] == "<redacted>"
    assert config["leakage_check_passed"] is True
    assert "cli-key" not in str(config)


def test_rule_spec_to_yaml_generates_taint_rule() -> None:
    generated = loop.rule_spec_to_yaml(
        {
            "id": "web command",
            "sources": ["request.args.get(...)"],
            "sinks": ["os.system($CMD)"],
            "sanitizers": ["shlex.quote(...)"],
            "message": "Derived command injection",
            "rationale": "Patch added quoting.",
        },
        source_cve="CVE-DEV",
    )

    assert generated is not None
    loaded = yaml.safe_load(generated.yaml_text)
    rule = loaded["rules"][0]
    assert rule["id"] == "cwe78-derived-web-command"
    assert rule["mode"] == "taint"
    assert rule["pattern-sources"] == [{"pattern": "request.args.get(...)"}]
    assert rule["pattern-sinks"] == [{"pattern": "os.system($CMD)"}]
    assert rule["pattern-sanitizers"] == [{"pattern": "shlex.quote(...)"}]
    assert rule["metadata"]["source_cve"] == "CVE-DEV"


def test_rule_spec_missing_sources_or_sinks_is_rejected() -> None:
    assert loop.rule_spec_to_yaml({"sources": [], "sinks": ["os.system($CMD)"]}, source_cve="CVE-X") is None
    assert loop.rule_spec_to_yaml({"sources": ["input(...)"], "sinks": []}, source_cve="CVE-X") is None


def test_overfit_rejection_catches_paths_lines_and_literal_sinks() -> None:
    base = loop.rule_spec_to_yaml(
        {"sources": ["input(...)"], "sinks": ["os.system($CMD)"]},
        source_cve="CVE-DEV",
    )
    assert base is not None
    assert loop.reject_overfit_rule(base, {"vulnerable_file": "pkg/foo.py"}) == ""

    path_rule = loop.GeneratedRule(
        rule_id="x",
        yaml_text="rules:\n- id: x\n  pattern: /tmp/repo/pkg/foo.py\n",
        source_cve="CVE-DEV",
    )
    assert loop.reject_overfit_rule(path_rule) == "contains_absolute_path"

    file_rule = loop.GeneratedRule(
        rule_id="x",
        yaml_text="rules:\n- id: x\n  pattern: pkg/foo.py\n",
        source_cve="CVE-DEV",
    )
    assert loop.reject_overfit_rule(file_rule, {"vulnerable_file": "pkg/foo.py"}) == "contains_dev_file_path"

    line_rule = loop.GeneratedRule(
        rule_id="x",
        yaml_text="rules:\n- id: x\n  pattern: 'line: 42'\n",
        source_cve="CVE-DEV",
    )
    assert loop.reject_overfit_rule(line_rule) == "contains_line_number"

    literal = loop.rule_spec_to_yaml(
        {"sources": ["input(...)"], "sinks": ['os.system("rm -rf /")']},
        source_cve="CVE-DEV",
    )
    assert literal is not None
    assert loop.reject_overfit_rule(literal) == "contains_literal_command_sink"


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

    def fake_scan(rule_yaml: str, repo_path: Path) -> list[Finding]:
        if "CVE-A" in str(repo_path) and "vulnerable" in str(repo_path):
            return [
                Finding(
                    file_path=str(repo_path / "app.py"),
                    line_start=10,
                    line_end=10,
                    rule_id="cwe78-derived-x",
                    message="x",
                )
            ]
        return []

    monkeypatch.setattr(loop, "clone_and_checkout", fake_clone)
    monkeypatch.setattr(loop, "scan_rule", fake_scan)

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
    assert summary["candidate_no_tp_cves"] == []
    assert summary["per_rule_hits"] == {"cwe78-derived-x": 1}
    assert summary["per_rule_tp"] == {"cwe78-derived-x": 1}
