"""Regression tests for Joern wrapper report-location selection."""

from __future__ import annotations

from auditzoo.agents.cwe78_study.joern_arm import JoernArm


def test_wrapper_internal_sink_relocates_to_same_package_caller() -> None:
    raw = [
        {
            "sourceFile": "pkg/helpers.py",
            "sourceLine": "5",
            "sourceCode": "cmd",
            "sourceNodeType": "MethodParameterIn",
            "sinkFile": "pkg/helpers.py",
            "sinkLine": "8",
            "sinkCode": "subprocess.run(cmd, shell=True)",
            "sinkName": "run",
            "sinkKind": "wrapper",
            "sinkCallerChain": [
                {
                    "file": "pkg/views.py",
                    "line": "42",
                    "code": "run_user_command(command)",
                    "matchesExternal": True,
                }
            ],
            "flowPath": [
                {
                    "file": "pkg/helpers.py",
                    "line": "8",
                    "code": "subprocess.run(cmd, shell=True)",
                    "nodeType": "Call",
                }
            ],
        }
    ]

    [finding] = JoernArm._parse_taint_results(raw)  # noqa: SLF001

    assert finding.file_path == "pkg/views.py"
    assert finding.line_start == 42
    assert finding.metadata["reportReason"] == "wrapper_caller_relocation"
    assert {
        "file": "pkg/helpers.py",
        "line": 8,
        "reason": "sink_endpoint",
    } in finding.metadata["reportCandidateLocations"]


def test_direct_sink_inside_wrapper_method_relocates_to_caller() -> None:
    raw = [
        {
            "sourceFile": "pkg/helpers.py",
            "sourceLine": "5",
            "sourceCode": "cmd",
            "sourceNodeType": "MethodParameterIn",
            "sinkFile": "pkg/helpers.py",
            "sinkLine": "8",
            "sinkCode": "subprocess.run(cmd, shell=True)",
            "sinkName": "run",
            "sinkMethodName": "run_user_command",
            "sinkKind": "direct",
            "sinkCallerChain": [
                {
                    "file": "pkg/views.py",
                    "line": "42",
                    "code": "run_user_command(request.args['cmd'])",
                    "matchesExternal": True,
                }
            ],
            "flowPath": [],
        }
    ]

    [finding] = JoernArm._parse_taint_results(raw)  # noqa: SLF001

    assert finding.file_path == "pkg/views.py"
    assert finding.line_start == 42
    assert finding.metadata["reportReason"] == "wrapper_caller_relocation"


def test_modelled_wrapper_call_keeps_sink_callsite_as_candidate() -> None:
    raw = [
        {
            "sourceFile": "pkg/views.py",
            "sourceLine": "12",
            "sourceCode": "cmd",
            "sinkFile": "pkg/views.py",
            "sinkLine": "42",
            "sinkCode": "run_user_command(cmd)",
            "sinkName": "run_user_command",
            "sinkKind": "wrapper",
            "sinkCallsite": {
                "file": "pkg/views.py",
                "line": "42",
                "code": "run_user_command(request.args['cmd'])",
                "matchesExternal": True,
            },
            "flowPath": [],
        }
    ]

    [finding] = JoernArm._parse_taint_results(raw)  # noqa: SLF001

    assert finding.file_path == "pkg/views.py"
    assert finding.line_start == 42
    assert finding.metadata["reportReason"] == "sink_endpoint"
    assert {
        "file": "pkg/views.py",
        "line": 42,
        "reason": "sink_endpoint",
    } in finding.metadata["reportCandidateLocations"]
    assert {
        "file": "pkg/views.py",
        "line": 42,
        "reason": "sink_callsite",
        "code": "run_user_command(request.args['cmd'])",
        "caller_external": True,
    } in finding.metadata["reportCandidateLocations"]


def test_primary_known_sink_location_is_not_relocated_to_caller() -> None:
    raw = [
        {
            "sourceFile": "pkg/views.py",
            "sourceLine": "12",
            "sourceCode": "cmd",
            "sinkFile": "pkg/views.py",
            "sinkLine": "42",
            "sinkCode": "os.system(cmd)",
            "sinkName": "system",
            "sinkKind": "direct",
            "sinkCallerChain": [
                {
                    "file": "pkg/router.py",
                    "line": "10",
                    "code": "handle(request.args['cmd'])",
                    "matchesExternal": True,
                }
            ],
            "flowPath": [],
        }
    ]

    [finding] = JoernArm._parse_taint_results(raw)  # noqa: SLF001

    assert finding.file_path == "pkg/views.py"
    assert finding.line_start == 42
    assert finding.metadata["reportReason"] == "sink_endpoint"
