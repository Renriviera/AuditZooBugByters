"""Tests for model-aware LLM client request parameters."""

from __future__ import annotations

from auditzoo.agents.cwe78_study.llm_client import LLMClient, LLMConfig


def test_gpt5_models_use_max_completion_tokens() -> None:
    client = LLMClient(
        LLMConfig(
            model="gpt-5.4-mini",
            api_key="test-key",
            max_tokens=321,
            seed=235711,
        )
    )

    request = client._chat_request(system_prompt="system", user_prompt="user")

    assert request["model"] == "gpt-5.4-mini"
    assert request["max_completion_tokens"] == 321
    assert "max_tokens" not in request
    assert "temperature" not in request
    assert "seed" not in request


def test_legacy_openai_compatible_models_keep_max_tokens() -> None:
    client = LLMClient(
        LLMConfig(
            model="Qwen/Qwen2.5-Coder-7B-Instruct",
            api_key="test-key",
            max_tokens=123,
            seed=235711,
        )
    )

    request = client._chat_request(system_prompt="system", user_prompt="user")

    assert request["model"] == "Qwen/Qwen2.5-Coder-7B-Instruct"
    assert request["max_tokens"] == 123
    assert request["temperature"] == 0.1
    assert request["seed"] == 235711
    assert "max_completion_tokens" not in request
