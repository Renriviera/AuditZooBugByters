"""Unit tests for ``splitEvaluations.clean_seed_catalog``.

The cleaner is the deterministic semantic-disjointness / blacklist
filter that wipes sink-coloured patterns out of the seed catalog before
the Joern arm consumes it (see the 20260510_051918 partial validation
audit for the failure mode this fixes).  Regressions here would let
``shell``/``subprocess`` self-flow back into the source list and wreck
strict TP recall again, so we cover every documented drop reason plus
the safety guardrails.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from splitEvaluations.clean_seed_catalog import (
    _SINK_TOKEN_BLACKLIST,
    _build_sink_prefix_index,
    _filter_sanitizers,
    _filter_sinks,
    _filter_sources,
    _is_blacklisted_source,
    _is_disjointness_violation,
    clean_catalog,
)

# ---------------------------------------------------------------------------
# blacklist primitive
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern,expected_drop",
    [
        ("shell", True),
        ("Shell", True),
        ("SHELL", True),
        ("subprocess", True),
        ("Popen.communicate", True),
        ("Popen.stdout.read", True),
        ("popen.stderr.read", True),
        ("system", True),
        ("exec", True),
        ("eval", True),
        # Legitimate framework/stdlib sources must be untouched.
        ("request.body", False),
        ("os.environ", False),
        ("sys.argv", False),
        ("websocket.receive_text", False),
        ("pathlib.Path.read_text", False),
        # Substring of a blacklisted token must NOT be dropped — the
        # filter is intentionally exact-match only.
        ("request.shell_form", False),
        ("subprocess_runner_input", False),
    ],
)
def test_is_blacklisted_source_exact_match(pattern: str, expected_drop: bool) -> None:
    drop, reason = _is_blacklisted_source(pattern)
    assert drop is expected_drop
    if expected_drop:
        assert reason.startswith("blacklist-exact:")
    else:
        assert reason == ""


def test_is_blacklisted_source_handles_empty_and_whitespace() -> None:
    assert _is_blacklisted_source("") == (False, "")
    assert _is_blacklisted_source("   ") == (False, "")
    drop, reason = _is_blacklisted_source("  shell  ")
    assert drop is True
    assert "blacklist-exact:shell" == reason


def test_blacklist_constant_is_non_empty_and_lowercase() -> None:
    assert _SINK_TOKEN_BLACKLIST
    for tok in _SINK_TOKEN_BLACKLIST:
        assert tok == tok.lower()


# ---------------------------------------------------------------------------
# disjointness primitive
# ---------------------------------------------------------------------------


def test_build_sink_prefix_index_collects_dotted_ancestors() -> None:
    sinks = ["subprocess.Popen", "os.system", "subprocess.run"]
    idx = _build_sink_prefix_index(sinks)
    assert {
        "subprocess",
        "subprocess.Popen",
        "subprocess.run",
        "os",
        "os.system",
    } <= idx


def test_disjointness_violation_source_equals_sink() -> None:
    drop, reason = _is_disjointness_violation(
        "os.system", sink_set={"os.system"}, sink_prefixes={"os", "os.system"}
    )
    assert drop is True
    assert "source-equals-sink" in reason


def test_disjointness_violation_source_is_strict_prefix_of_sink() -> None:
    sink_prefixes = _build_sink_prefix_index(["subprocess.Popen", "subprocess.run"])
    drop, reason = _is_disjointness_violation("subprocess", set(), sink_prefixes)
    assert drop is True
    assert "prefix-of-sink" in reason


def test_disjointness_violation_clean_source_kept() -> None:
    sink_prefixes = _build_sink_prefix_index(["subprocess.Popen"])
    drop, _ = _is_disjointness_violation(
        "request.body", sink_set={"subprocess.Popen"}, sink_prefixes=sink_prefixes
    )
    assert drop is False


# ---------------------------------------------------------------------------
# source filter (the integrated path)
# ---------------------------------------------------------------------------


def test_filter_sources_drops_blacklist_and_prefix_overlap() -> None:
    sources = [
        "shell",  # blacklist
        "subprocess",  # blacklist + prefix
        "Popen.communicate",  # blacklist
        "Popen.stdout.read",  # blacklist
        "request.body",  # keep
        "os.environ",  # keep
        "subprocess.run",  # would equal a sink -> disjointness drop
        "request.body",  # duplicate of an earlier kept entry
    ]
    sinks = ["os.system", "subprocess.Popen", "subprocess.run"]
    kept, dropped = _filter_sources(sources, sinks)
    assert kept == ["request.body", "os.environ"]
    dropped_patterns = [d["pattern"] for d in dropped]
    assert "shell" in dropped_patterns
    assert "subprocess" in dropped_patterns
    assert "Popen.communicate" in dropped_patterns
    assert "Popen.stdout.read" in dropped_patterns
    assert "subprocess.run" in dropped_patterns
    # Every drop record must carry a reason string.
    for d in dropped:
        assert d["reason"]


def test_filter_sources_skips_empty_or_non_string_entries() -> None:
    sources = ["", "   ", None, "request.body"]  # type: ignore[list-item]
    kept, dropped = _filter_sources(sources, sinks=[])
    assert kept == ["request.body"]
    assert dropped == []


def test_filter_sources_first_reason_recorded_on_dual_match() -> None:
    """``subprocess`` is both blacklisted *and* a sink prefix.

    The cleaner should record the blacklist hit first (cheaper test,
    runs first) and not append a second drop record for the same input
    pattern.
    """
    kept, dropped = _filter_sources(["subprocess"], ["subprocess.Popen"])
    assert kept == []
    assert len(dropped) == 1
    assert dropped[0]["pattern"] == "subprocess"
    assert dropped[0]["reason"].startswith("blacklist-exact:")


# ---------------------------------------------------------------------------
# sink and sanitizer filters
# ---------------------------------------------------------------------------


def test_filter_sinks_drops_non_api_tokens() -> None:
    sinks = ["os.system", "subprocess.Popen", "shell", "exec", "subprocess.run"]
    kept, dropped = _filter_sinks(sinks)
    assert kept == ["os.system", "subprocess.Popen", "subprocess.run"]
    dropped_patterns = [d["pattern"] for d in dropped]
    assert "shell" in dropped_patterns
    assert "exec" in dropped_patterns
    for d in dropped:
        assert d["reason"] == "non-api-token-as-sink"


def test_filter_sinks_keeps_dotted_apis_even_if_they_share_a_token() -> None:
    sinks = ["os.system", "subprocess.exec", "shutil.shell_command"]
    kept, dropped = _filter_sinks(sinks)
    assert kept == ["os.system", "subprocess.exec", "shutil.shell_command"]
    assert dropped == []


def test_filter_sanitizers_drops_sink_collisions() -> None:
    sanitizers = ["shlex.quote", "shlex.split", "os.system"]
    sinks = ["os.system", "subprocess.Popen"]
    kept, dropped = _filter_sanitizers(sanitizers, sinks)
    assert kept == ["shlex.quote", "shlex.split"]
    assert [d["pattern"] for d in dropped] == ["os.system"]
    assert dropped[0]["reason"] == "sanitizer-equals-sink"


# ---------------------------------------------------------------------------
# clean_catalog (top-level)
# ---------------------------------------------------------------------------


def _sample_payload() -> dict:
    return {
        "sources": [
            "shell",
            "subprocess",
            "Popen.communicate",
            "Popen.stdout.read",
            "request.body",
            "os.environ",
            "sys.argv",
            "websocket.receive_text",
        ],
        "sinks": ["os.system", "subprocess.Popen", "subprocess.run", "shell"],
        "sanitizers": ["shlex.quote", "os.system"],
        "metadata": {"merged_with": {"yaml_root": "demo"}},
    }


def test_clean_catalog_records_all_drops_and_preserves_metadata() -> None:
    payload = _sample_payload()
    cleaned = clean_catalog(payload, max_source_drop_frac=0.5)

    assert cleaned["sources"] == [
        "request.body",
        "os.environ",
        "sys.argv",
        "websocket.receive_text",
    ]
    assert "shell" not in cleaned["sinks"]
    assert "os.system" in cleaned["sinks"]
    assert cleaned["sanitizers"] == ["shlex.quote"]

    cw = cleaned["metadata"]["cleaned_with"]
    assert cw["input_counts"]["sources"] == 8
    assert cw["kept_counts"]["sources"] == 4
    dropped_patterns = {d["pattern"] for d in cw["dropped_sources"]}
    assert {
        "shell",
        "subprocess",
        "Popen.communicate",
        "Popen.stdout.read",
    } <= dropped_patterns
    assert any(d["pattern"] == "shell" for d in cw["dropped_sinks"])
    assert any(d["pattern"] == "os.system" for d in cw["dropped_sanitizers"])
    # Pre-existing metadata is preserved alongside the new "cleaned_with" key.
    assert cleaned["metadata"]["merged_with"] == {"yaml_root": "demo"}
    # Blacklist constant is recorded so the audit trail is reproducible.
    assert cw["blacklist_used"]
    assert cw["max_source_drop_frac"] == 0.5
    assert "cleaned_at" in cw and cw["cleaned_at"].endswith("Z")


def test_clean_catalog_refuses_when_drop_fraction_exceeds_bound() -> None:
    """The guardrail must trip before any output is written."""
    payload = {
        "sources": ["shell", "subprocess", "popen", "request.body"],
        "sinks": ["os.system"],
        "sanitizers": [],
    }
    with pytest.raises(ValueError, match="drop fraction"):
        clean_catalog(payload, max_source_drop_frac=0.25)


def test_clean_catalog_passes_when_drop_fraction_within_bound() -> None:
    payload = {
        "sources": ["shell", "subprocess", "popen", "request.body"],
        "sinks": ["os.system"],
        "sanitizers": [],
    }
    cleaned = clean_catalog(payload, max_source_drop_frac=0.9)
    assert cleaned["sources"] == ["request.body"]


def test_clean_catalog_rejects_non_dict_input() -> None:
    with pytest.raises(ValueError, match="JSON object"):
        clean_catalog([1, 2, 3], max_source_drop_frac=0.25)  # type: ignore[arg-type]


def test_clean_catalog_handles_missing_keys_gracefully() -> None:
    cleaned = clean_catalog({}, max_source_drop_frac=0.25)
    assert cleaned["sources"] == []
    assert cleaned["sinks"] == []
    assert cleaned["sanitizers"] == []
    cw = cleaned["metadata"]["cleaned_with"]
    assert cw["input_counts"] == {"sources": 0, "sinks": 0, "sanitizers": 0}


# ---------------------------------------------------------------------------
# CLI / round-trip
# ---------------------------------------------------------------------------


def test_clean_catalog_round_trip_via_main(tmp_path: Path, monkeypatch) -> None:
    inp = tmp_path / "merged.json"
    out = tmp_path / "clean.json"
    inp.write_text(json.dumps(_sample_payload()))

    from splitEvaluations import clean_seed_catalog as mod

    argv = [
        "clean_seed_catalog",
        "--input",
        str(inp),
        "--output",
        str(out),
        "--max-source-drop-frac",
        "0.6",
    ]
    monkeypatch.setattr("sys.argv", argv)
    assert mod.main() == 0

    written = json.loads(out.read_text())
    assert written["sources"] == [
        "request.body",
        "os.environ",
        "sys.argv",
        "websocket.receive_text",
    ]
    assert "shell" not in written["sinks"]
    assert written["metadata"]["cleaned_with"]["max_source_drop_frac"] == 0.6
