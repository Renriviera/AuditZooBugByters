"""Credential handling tests for split Joern/Semgrep sweep CLIs."""

from __future__ import annotations

from argparse import Namespace
from pathlib import Path

from splitEvaluations.common import redacted_sweep_args, resolve_llm_api_key


def test_resolve_llm_api_key_prefers_cli_value(monkeypatch) -> None:
    monkeypatch.setenv("AUDITZOO_LLM_API_KEY", "env-auditzoo")
    monkeypatch.setenv("OPENAI_API_KEY", "env-openai")

    assert resolve_llm_api_key("cli-key") == "cli-key"


def test_resolve_llm_api_key_prefers_auditzoo_env(monkeypatch) -> None:
    monkeypatch.delenv("AUDITZOO_LLM_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("AUDITZOO_LLM_API_KEY", "env-auditzoo")
    monkeypatch.setenv("OPENAI_API_KEY", "env-openai")

    assert resolve_llm_api_key(None) == "env-auditzoo"


def test_resolve_llm_api_key_falls_back_to_openai_env(monkeypatch) -> None:
    monkeypatch.delenv("AUDITZOO_LLM_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "env-openai")

    assert resolve_llm_api_key(None) == "env-openai"


def test_resolve_llm_api_key_allows_local_not_needed(monkeypatch) -> None:
    monkeypatch.delenv("AUDITZOO_LLM_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    assert resolve_llm_api_key(None) == "not-needed"


def test_redacted_sweep_args_never_persists_raw_key() -> None:
    args = Namespace(
        llm_api_key="secret-key",
        llm_model="gpt-5.4-mini",
        dataset_size=30,
    )

    out = redacted_sweep_args(args)

    assert out["llm_api_key"] == "<redacted>"
    assert out["llm_api_key_provided"] is True
    assert "secret-key" not in str(out)


def test_redacted_sweep_args_preserves_local_not_needed(monkeypatch) -> None:
    monkeypatch.delenv("AUDITZOO_LLM_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    args = Namespace(llm_api_key=None)

    out = redacted_sweep_args(args)

    assert out["llm_api_key"] == "not-needed"
    assert out["llm_api_key_provided"] is False


def test_one_command_runner_does_not_pass_key_as_cli_argument() -> None:
    script = Path("splitEvaluations/run_joern_30_with_audit.sh").read_text()

    assert "--llm-api-key" not in script
    assert "AUDITZOO_LLM_API_KEY" in script
    assert ".env" in script
    assert "/workspace/miniconda3/envs/iris/bin/python" in script
    assert "https://api.openai.com/v1" in script
    assert "gpt-5.4-mini" in script
    assert "sk-" not in script
    assert "splitEvaluations.run_joern_sweep" in script
    assert "splitEvaluations.audit_joern_results" in script
