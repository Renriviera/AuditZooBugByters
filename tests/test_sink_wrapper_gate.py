"""Unit tests for the structural sink-wrapper gate.

The 20260508_234404 audit showed that blindly trusting LLM
``sink-wrapper`` classifications dragged wrappers like ``secure_popen``
and ``run_command`` into the Joern sink catalog purely on name, which
then drove ~1500 ``scanner_location_fp`` rows.
:func:`auditzoo.agents.cwe78_study.pipeline.verify_sink_wrapper`
gates expansion on structural evidence pulled from Joern's
call-graph response.
"""

from __future__ import annotations

from auditzoo.agents.cwe78_study.pipeline import verify_sink_wrapper


CURRENT_SINKS = [
    "os.system",
    "subprocess.Popen",
    "subprocess.run",
    "subprocess.check_output",
]


class TestVerifySinkWrapper:
    def test_callee_match_admits_wrapper(self) -> None:
        neighbour = {
            "name": "run_command",
            "callees": ["sanitize", "system", "log"],
            "code": "def run_command(cmd): return system(cmd)",
        }
        assert (
            verify_sink_wrapper("run_command", neighbour, CURRENT_SINKS) is True
        )

    def test_no_callee_or_body_match_rejects_wrapper(self) -> None:
        # ``secure_popen`` looks like a sink wrapper but its body never
        # actually invokes a known sink — the audit shows this is the
        # canonical false-positive driver.
        neighbour = {
            "name": "secure_popen",
            "callees": ["log_info", "validate_inputs"],
            "code": (
                "def secure_popen(cmd):\n"
                "    validate_inputs(cmd)\n"
                "    return SAFE_RESULT"
            ),
        }
        assert (
            verify_sink_wrapper("secure_popen", neighbour, CURRENT_SINKS) is False
        )

    def test_body_regex_admits_wrapper_when_callees_truncated(self) -> None:
        # Joern's callees list is capped at 50 entries; a wrapper whose
        # callees were truncated still gets a chance via the longer
        # ``code`` excerpt.
        neighbour = {
            "name": "run_pipeline",
            "callees": [],
            "code": (
                "def run_pipeline(cmd):\n"
                "    log('starting')\n"
                "    proc = subprocess.Popen(cmd, shell=True)\n"
                "    return proc"
            ),
        }
        assert (
            verify_sink_wrapper("run_pipeline", neighbour, CURRENT_SINKS) is True
        )

    def test_evidence_string_with_known_tail_admits_wrapper(self) -> None:
        # When neither callees nor body show a match (for example
        # because Joern truncated the body too aggressively), an LLM
        # evidence citation that mentions a known sink tail is enough.
        neighbour = {
            "name": "run_command",
            "callees": [],
            "code": "...",
        }
        assert (
            verify_sink_wrapper(
                "run_command",
                neighbour,
                CURRENT_SINKS,
                evidence="invokes os.system on user input",
            )
            is True
        )

    def test_evidence_string_without_known_tail_does_not_admit_wrapper(self) -> None:
        neighbour = {
            "name": "run_command",
            "callees": [],
            "code": "...",
        }
        assert (
            verify_sink_wrapper(
                "run_command",
                neighbour,
                CURRENT_SINKS,
                evidence="looks dangerous to me",
            )
            is False
        )

    def test_empty_neighbour_rejects_wrapper(self) -> None:
        # If the call-graph index is missing this name (the LLM
        # hallucinated the function), the gate must reject.
        assert verify_sink_wrapper("ghost_func", {}, CURRENT_SINKS) is False

    def test_empty_sink_catalog_rejects_wrapper(self) -> None:
        # No reference sink names means there's nothing to verify
        # against; the gate should fail closed.
        neighbour = {"name": "x", "callees": ["system"], "code": "system(...)"}
        assert verify_sink_wrapper("x", neighbour, []) is False
