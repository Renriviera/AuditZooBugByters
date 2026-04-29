"""Prompt contract tests."""

from __future__ import annotations

from auditzoo.agents.cwe78_study.prompts import (
    SYSTEM_PROMPT_B_TRIAGE,
    triage_system_prompt,
)


def test_triage_prompt_contains_git_argv_list_exception() -> None:
    assert (
        "EXCEPTION (do NOT auto-suppress to false_positive)" in SYSTEM_PROMPT_B_TRIAGE
    )
    assert "--config core.sshCommand=..." in SYSTEM_PROMPT_B_TRIAGE


def test_triage_prompt_builder_can_disable_git_argv_exception() -> None:
    prompt = triage_system_prompt(include_argv_exception=False)

    assert "EXCEPTION (do NOT auto-suppress to false_positive)" not in prompt
    assert "--config core.sshCommand=..." not in prompt
    assert "Commit to ``false_positive``" in prompt
    assert "Name the licensing substring inside ``reasoning``" in prompt


def test_triage_prompt_builder_defaults_to_git_argv_exception() -> None:
    prompt = triage_system_prompt()

    assert "EXCEPTION (do NOT auto-suppress to false_positive)" in prompt
    assert "--config core.sshCommand=..." in prompt
