"""Unit tests for the Joern catalog sanitizer.

The sanitizer is the single source of truth for what counts as a valid
``module.foo`` style entry across the seed parser
(:func:`auditzoo.agents.cwe78_study.model_seed.parse_joern_seed_catalog`)
and the runtime arm
(:class:`auditzoo.agents.cwe78_study.joern_arm.JoernArm`).  Regressions
here directly translate to ``PatternSyntaxException`` blowing up Joern
queries, so we cover the failure modes observed in production.
"""

from __future__ import annotations

import pytest

from auditzoo.agents.cwe78_study.catalog_sanitizer import (
    clean_catalog_entry,
    sanitize_catalog,
)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("os.system", "os.system"),
        ("subprocess.Popen", "subprocess.Popen"),
        ("a.b.c.d", "a.b.c.d"),
        ("input", "input"),
        ("  shlex.quote  ", "shlex.quote"),
        ("os.system  # OS_COMMAND", "os.system"),
        ("subprocess.run  # python", "subprocess.run"),
        ("os.system(", "os.system"),
        ("os.system(cmd", "os.system"),
        ("subprocess.Popen[shell=True]", "subprocess.Popen"),
        ("os.system, shlex.quote", "os.system"),
    ],
)
def test_clean_catalog_entry_accepts_valid(raw: str, expected: str) -> None:
    assert clean_catalog_entry(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "1.foo",  # cannot start with digit
        "os..system",  # empty middle segment
        "os.system!",
        "os/system",
        "os-system",
        "$cmd",
        "(",
    ],
)
def test_clean_catalog_entry_rejects_invalid(raw: str) -> None:
    assert clean_catalog_entry(raw) is None


@pytest.mark.parametrize(
    "raw,expected",
    [
        # Forgive a stray leading/trailing dot — common LLM mistake when
        # emitting "os.system." in a list — rather than reject outright.
        (".os.system", "os.system"),
        ("os.system.", "os.system"),
        # A whitespace-delimited entry keeps only the first token; this
        # documents the recovery rather than over-promising rejection.
        ("os system", "os"),
        # ``$`` and ``(`` are scrubbed by the parameter-list strip even
        # though they would be regex-unsafe on their own.
        ("os.system($CMD)", "os.system"),
    ],
)
def test_clean_catalog_entry_normalises_recoverable(raw: str, expected: str) -> None:
    assert clean_catalog_entry(raw) == expected


def test_sanitize_catalog_dedups_and_preserves_order() -> None:
    kept, dropped = sanitize_catalog(
        [
            "os.system",
            "  os.system  ",
            "subprocess.run",
            "os.system",
            "shlex.quote",
        ]
    )
    assert kept == ["os.system", "subprocess.run", "shlex.quote"]
    assert dropped == []


def test_sanitize_catalog_separates_kept_and_dropped() -> None:
    kept, dropped = sanitize_catalog(
        ["os.system", "(", "subprocess.run(cmd", "1.foo", "input"],
        label="test",
    )
    assert kept == ["os.system", "subprocess.run", "input"]
    assert dropped == ["(", "1.foo"]


def test_sanitize_catalog_handles_none_and_non_strings() -> None:
    kept, dropped = sanitize_catalog([None, 42, "os.system", ""])  # type: ignore[list-item]
    assert kept == ["os.system"]
    # ``""`` cleans to ``None`` (rejected); 42 / None are non-strings.
    assert "None" in dropped
    assert "42" in dropped


def test_sanitize_catalog_empty_input() -> None:
    assert sanitize_catalog(None) == ([], [])
    assert sanitize_catalog([]) == ([], [])


def test_taint_query_drops_invalid_sinks_without_failing() -> None:
    """The full-stack assertion: a poisoned catalog still produces a valid query."""
    from auditzoo.agents.cwe78_study.joern_arm import JoernArm

    arm = JoernArm(
        sources=["sys.argv", "input"],
        sinks=["os.system", "(", "subprocess.run(cmd", "1.bad"],
        sanitizers=["shlex.quote"],
    )
    # ``"("`` and ``"1.bad"`` are dropped; ``"subprocess.run(cmd"`` is
    # *recovered* to ``subprocess.run`` (parameter-list strip).
    assert arm.sinks == ["os.system", "subprocess.run"]
    query = JoernArm._build_taint_query(arm.sources, arm.sinks)
    # Query must be a single, valid string with no unescaped metachars
    # leaking from the originally-malformed input.
    assert "subprocess.run(cmd" not in query
    assert "1.bad" not in query
    assert "PatternSyntax" not in query
    assert "os\\.system" in query
    assert "subprocess\\.run" in query


def test_pipeline_config_seed_overrides_drop_invalid_entries() -> None:
    """parse_joern_seed_catalog drops invalid entries instead of blowing up."""
    from auditzoo.agents.cwe78_study.model_seed import parse_joern_seed_catalog

    catalog = parse_joern_seed_catalog(
        {
            "sources": ["sys.argv", "request.args  # GET", "(invalid"],
            "sinks": ["os.system", "subprocess.Popen(shell=True", "shlex.split"],
            "sanitizers": ["shlex.quote", "1.bad"],
        }
    )
    assert catalog.sources == ["sys.argv", "request.args"]
    assert catalog.sinks == ["os.system", "subprocess.Popen", "shlex.split"]
    assert catalog.sanitizers == ["shlex.quote"]


def test_pipeline_config_seed_rejects_all_invalid_sinks() -> None:
    """All-invalid sinks must raise ValueError so the run fails loudly, not silently."""
    from auditzoo.agents.cwe78_study.model_seed import parse_joern_seed_catalog

    with pytest.raises(ValueError, match="sinks"):
        parse_joern_seed_catalog(
            {
                "sources": ["sys.argv"],
                "sinks": ["1.bad", "(", "$cmd"],
                "sanitizers": [],
            }
        )
