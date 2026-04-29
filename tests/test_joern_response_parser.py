"""Unit tests for Joern response parsing edge cases."""

from __future__ import annotations

from typing import Any

import pytest

from auditzoo.agents.cwe78_study.joern_arm import JoernArm
from auditzoo.agents.cwe78_study.schemas import Finding
from auditzoo.backends.joern.utils import parse_joern_response


@pytest.mark.asyncio
async def test_call_graph_query_uses_scala3_using_clause() -> None:
    arm = JoernArm()
    captured: dict[str, str] = {}

    async def fake_query_ir(
        query: str,
        response_ty: str,
        ctx: Any,
    ) -> list[dict[str, Any]]:
        captured["query"] = query
        return []

    arm.query_ir = fake_query_ir  # type: ignore[method-assign]

    await arm._expand_call_graph("run", 3, ctx=object())  # noqa: SLF001

    assert ".repeat(_.caller)(using _.maxDepth(3))" in captured["query"]
    assert ".repeat(_.caller)(_.maxDepth(3))" not in captured["query"]


def test_taint_query_emits_flow_path_elements() -> None:
    query = JoernArm._build_taint_query(
        ["sys.argv"], ["subprocess.run"]
    )  # noqa: SLF001

    assert '"flowPath"' in query
    assert "f.elements.map" in query
    assert '"nodeType" -> e.getClass.getSimpleName' in query


def test_taint_query_includes_parameter_attribute_sources_and_wrappers() -> None:
    query = JoernArm._build_taint_query(  # noqa: SLF001
        ["sys.argv"],
        ["subprocess.run"],
        wrapper_sinks=[{"name": "run_user_command"}],
    )

    assert "cpg.method.parameter" in query
    assert "cpg.identifier" not in query
    assert '"sourceKind"' in query
    assert "run_user_command" in query
    assert '"sinkKind"' in query
    assert '"sinkMethodName"' in query


def test_taint_query_emits_external_source_and_origin_evidence() -> None:
    query = JoernArm._build_taint_query(  # noqa: SLF001
        ["sys.argv"],
        ["subprocess.run"],
        modeling_mode="catalog_parameter_attribute",
    )

    assert '=> "external"' in query
    assert "os[.]getenv" in query
    assert '"originEvidence"' in query
    assert "callIn.take(3)" in query
    assert "argumentIndex(idx)" in query
    assert "matchesExternal" in query
    assert '"sinkCallsite"' in query
    assert '"sinkCallerChain"' in query
    assert "callIn.take(8)" in query


@pytest.mark.asyncio
async def test_coverage_probe_returns_file_sink_and_source_counts() -> None:
    arm = JoernArm(sinks=["subprocess.run"])
    captured: dict[str, str] = {}

    async def fake_query_ir(
        query: str,
        response_ty: str,
        ctx: Any,
    ) -> list[dict[str, Any]]:
        captured["query"] = query
        assert response_ty == "json"
        return [
            {
                "gt_file_seen": "true",
                "method_count": "2",
                "gt_sink_count": "1",
                "external_source_count": "1",
                "methods_in_gt_file": [{"name": "run", "lineNumber": "10"}],
            }
        ]

    arm.query_ir = fake_query_ir  # type: ignore[method-assign]

    probe = await arm.coverage_probe(
        gt_file="app/shell.py",
        gt_lines=[42],
        ctx=object(),
    )

    assert "shell\\.py" in captured["query"]
    assert probe["gt_file_seen"] is True
    assert probe["method_count"] == 2
    assert probe["gt_sink_count"] == 1
    assert probe["external_source_count"] == 1
    assert probe["methods_in_gt_file"] == [{"name": "run", "lineNumber": "10"}]


def test_taint_query_modeling_modes_toggle_expanded_sources_and_wrappers() -> None:
    catalog_only = JoernArm._build_taint_query(  # noqa: SLF001
        ["sys.argv"],
        ["subprocess.run"],
        wrapper_sinks=[{"name": "run_user_command"}],
        modeling_mode="catalog_only",
    )
    parameter = JoernArm._build_taint_query(  # noqa: SLF001
        ["sys.argv"],
        ["subprocess.run"],
        wrapper_sinks=[{"name": "run_user_command"}],
        modeling_mode="catalog_parameter",
    )

    assert "cpg.method.parameter" not in catalog_only
    assert "run_user_command" not in catalog_only
    assert "cpg.method.parameter" in parameter
    assert "run_user_command" not in parameter


def test_wrapper_discovery_query_is_bounded_and_filters_tests() -> None:
    query = JoernArm._build_wrapper_discovery_query(  # noqa: SLF001
        ["subprocess.run"],
        limit=17,
    )

    assert ".take(17)" in query
    assert "!c.file.name.headOption" in query
    assert "/devscripts/" in query
    assert "third_party" in query
    assert '"wrappedSinkName"' in query
    assert '"wrappedSinkCode"' in query


def test_parse_taint_results_prefers_flow_callsite_report_location() -> None:
    raw = [
        {
            "sourceFile": "app/api.py",
            "sourceLine": "10",
            "sourceCode": "request.args['cmd']",
            "sinkFile": "app/helpers.py",
            "sinkLine": "20",
            "sinkCode": "subprocess.run(cmd, shell=True)",
            "sinkName": "run",
            "flowPath": [
                {
                    "file": "app/api.py",
                    "line": "10",
                    "code": "request.args['cmd']",
                    "nodeType": "Call",
                },
                {
                    "file": "app/views.py",
                    "line": "42",
                    "code": "run_user_command(cmd)",
                    "nodeType": "Call",
                },
                {
                    "file": "app/helpers.py",
                    "line": "20",
                    "code": "subprocess.run(cmd, shell=True)",
                    "nodeType": "Call",
                },
            ],
        }
    ]

    [finding] = JoernArm._parse_taint_results(raw)  # noqa: SLF001

    assert finding.file_path == "app/views.py"
    assert finding.line_start == 42
    assert finding.metadata["reportFile"] == "app/views.py"
    assert finding.metadata["reportLine"] == "42"
    assert finding.metadata["reportReason"] == "flow_command_construction"
    assert finding.metadata["reportCandidateLocations"][0] == {
        "file": "app/views.py",
        "line": 42,
        "reason": "flow_command_construction",
    }


def test_parse_taint_results_prefers_non_wrapper_callsite_report_location() -> None:
    raw = [
        {
            "sourceFile": "app/api.py",
            "sourceLine": "10",
            "sourceCode": "cmd",
            "sinkFile": "app/helpers.py",
            "sinkLine": "20",
            "sinkCode": "run(cmd)",
            "sinkName": "run",
            "sinkKind": "wrapper",
            "wrapperName": "run",
            "flowPath": [
                {
                    "file": "tests/test_helpers.py",
                    "line": "5",
                    "code": "run(cmd)",
                    "nodeType": "Call",
                },
                {
                    "file": "app/api.py",
                    "line": "44",
                    "code": "execute_user_request(payload)",
                    "nodeType": "Call",
                },
                {
                    "file": "app/helpers.py",
                    "line": "20",
                    "code": "run(cmd)",
                    "nodeType": "Call",
                },
            ],
        }
    ]

    [finding] = JoernArm._parse_taint_results(raw)  # noqa: SLF001

    assert finding.file_path == "app/api.py"
    assert finding.line_start == 44
    assert finding.metadata["reportReason"] == "flow_non_wrapper_callsite"


def test_parse_taint_results_preserves_modeling_metadata() -> None:
    raw = [
        {
            "sourceFile": "app/api.py",
            "sourceLine": "10",
            "sourceCode": "checkout",
            "sourceNodeType": "MethodParameterIn",
            "sinkFile": "app/helpers.py",
            "sinkLine": "20",
            "sinkCode": "subprocess.run(cmd, shell=True)",
            "sinkName": "run_user_command",
            "flowPath": [],
        }
    ]

    [finding] = JoernArm._parse_taint_results(  # noqa: SLF001
        raw,
        wrapper_sinks=[
            {
                "name": "run_user_command",
                "wrappedSinkName": "run",
                "wrappedSinkCode": "subprocess.run(cmd, shell=True)",
            }
        ],
    )

    assert finding.metadata["sourceKind"] == "parameter"
    assert finding.metadata["sinkKind"] == "wrapper"
    assert finding.metadata["wrapperName"] == "run_user_command"
    assert finding.metadata["wrappedSinkName"] == "run"
    assert finding.metadata["shell_true"] is True
    assert finding.metadata["string_command_like"] is True


def test_parse_taint_results_marks_origin_external_from_caller_chain() -> None:
    raw = [
        {
            "sourceFile": "app/helpers.py",
            "sourceLine": "5",
            "sourceCode": "cmd",
            "sourceNodeType": "MethodParameterIn",
            "sinkFile": "app/helpers.py",
            "sinkLine": "8",
            "sinkCode": "subprocess.run(cmd, shell=True)",
            "sinkName": "run",
            "callerChain": [
                {
                    "file": "app/views.py",
                    "line": "20",
                    "code": "run(request.args['cmd'])",
                    "argumentCode": "request.args['cmd']",
                    "matchesExternal": True,
                }
            ],
            "flowPath": [],
        }
    ]

    [finding] = JoernArm._parse_taint_results(raw)  # noqa: SLF001

    assert finding.metadata["sourceKind"] == "parameter"
    assert finding.metadata["originExternalSource"] is True
    assert finding.metadata["callerChain"][0]["argumentCode"] == "request.args['cmd']"
    assert {
        "file": "app/views.py",
        "line": 20,
        "reason": "caller_consumer_callsite",
        "code": "run(request.args['cmd'])",
        "caller_external": True,
    } in finding.metadata["reportCandidateLocations"]


def test_parse_taint_results_marks_origin_external_from_sink_caller_chain() -> None:
    raw = [
        {
            "sourceFile": "app/helpers.py",
            "sourceLine": "5",
            "sourceCode": "cmd",
            "sourceNodeType": "MethodParameterIn",
            "sinkFile": "app/helpers.py",
            "sinkLine": "8",
            "sinkCode": "subprocess.run(cmd, shell=True)",
            "sinkName": "run",
            "sinkCallerChain": [
                {
                    "file": "app/views.py",
                    "line": "20",
                    "code": "run_user_command(request.args['cmd'])",
                    "matchesExternal": True,
                }
            ],
            "flowPath": [],
        }
    ]

    [finding] = JoernArm._parse_taint_results(raw)  # noqa: SLF001

    assert finding.metadata["originExternalSource"] is True
    assert finding.metadata["sinkCallerChain"][0]["code"] == (
        "run_user_command(request.args['cmd'])"
    )
    assert {
        "file": "app/views.py",
        "line": 20,
        "reason": "wrapper_caller_callsite",
        "code": "run_user_command(request.args['cmd'])",
        "caller_external": True,
    } in finding.metadata["reportCandidateLocations"]


def test_parse_taint_results_preserves_sink_callsite_metadata() -> None:
    raw = [
        {
            "sourceFile": "app/views.py",
            "sourceLine": "5",
            "sourceCode": "cmd",
            "sinkFile": "app/views.py",
            "sinkLine": "20",
            "sinkCode": "run_user_command(cmd)",
            "sinkName": "run_user_command",
            "sinkKind": "wrapper",
            "sinkCallsite": {
                "file": "app/views.py",
                "line": "20",
                "code": "run_user_command(request.args['cmd'])",
                "methodFullName": "app.views.handle",
                "matchesExternal": True,
            },
            "flowPath": [],
        }
    ]

    [finding] = JoernArm._parse_taint_results(raw)  # noqa: SLF001

    assert finding.metadata["originExternalSource"] is True
    assert finding.metadata["sinkCallsite"]["methodFullName"] == "app.views.handle"


def test_parse_taint_results_marks_origin_external_from_local_origin() -> None:
    raw = [
        {
            "sourceFile": "app/views.py",
            "sourceLine": "30",
            "sourceCode": "cmd",
            "sinkFile": "app/views.py",
            "sinkLine": "35",
            "sinkCode": "subprocess.run(cmd, shell=True)",
            "sinkName": "run",
            "originEvidence": [
                {
                    "file": "app/views.py",
                    "line": "29",
                    "code": "cmd = os.getenv('CMD')",
                    "matchesExternal": True,
                }
            ],
            "flowPath": [],
        }
    ]

    [finding] = JoernArm._parse_taint_results(raw)  # noqa: SLF001

    assert finding.metadata["originExternalSource"] is True
    assert finding.metadata["originEvidence"][0]["code"] == "cmd = os.getenv('CMD')"


def test_python_origin_evidence_scan_finds_nearby_external_source(
    tmp_path,
) -> None:
    source = tmp_path / "app" / "views.py"
    source.parent.mkdir()
    source.write_text(
        "\n".join(
            [
                "def handle(cmd):",
                "    default = os.environ['CMD']",
                "    value = cmd or default",
                "    subprocess.run(value, shell=True)",
            ]
        )
    )
    finding = Finding(
        file_path="app/views.py",
        line_start=4,
        line_end=4,
        rule_id="joern-taint-reachability",
        message="flow",
        code_snippet="subprocess.run(value, shell=True)",
        metadata={
            "sourceFile": "app/views.py",
            "sourceLine": "1",
            "sourceCode": "cmd",
            "sourceKind": "parameter",
            "sourceNodeType": "MethodParameterIn",
            "sinkFile": "app/views.py",
            "sinkLine": "4",
            "sinkCode": "subprocess.run(value, shell=True)",
        },
    )

    [enriched] = JoernArm().get_findings_with_context([finding], tmp_path)

    assert enriched.metadata["originExternalSource"] is True
    assert enriched.metadata["originEvidence"] == [
        {
            "file": "app/views.py",
            "line": "2",
            "code": "default = os.environ['CMD']",
            "argumentCode": "",
            "matchesExternal": True,
        }
    ]


def test_parse_taint_results_relocates_wrapper_sink_to_internal_sink_line() -> None:
    raw = [
        {
            "sourceFile": "app/helpers.py",
            "sourceLine": "10",
            "sourceCode": "cmd",
            "sourceNodeType": "MethodParameterIn",
            "sinkFile": "app/helpers.py",
            "sinkLine": "10",
            "sinkCode": "run(cmd)",
            "sinkName": "run",
            "sinkKind": "wrapper",
            "wrapperName": "run",
            "flowPath": [
                {
                    "file": "app/helpers.py",
                    "line": "10",
                    "code": "def run(cmd: str) -> str:",
                    "nodeType": "Method",
                },
                {
                    "file": "app/helpers.py",
                    "line": "15",
                    "code": "subprocess.run(args=cmd, shell=True)",
                    "nodeType": "Call",
                },
            ],
        }
    ]

    [finding] = JoernArm._parse_taint_results(raw)  # noqa: SLF001

    assert finding.file_path == "app/helpers.py"
    assert finding.line_start == 15
    assert finding.metadata["reportReason"] == "wrapper_internal_sink"


def test_wrapper_internal_sink_outranks_command_construction() -> None:
    raw = [
        {
            "sourceFile": "app/helpers.py",
            "sourceLine": "10",
            "sourceCode": "cmd",
            "sourceNodeType": "MethodParameterIn",
            "sinkFile": "app/helpers.py",
            "sinkLine": "20",
            "sinkCode": "run(cmd)",
            "sinkName": "run",
            "sinkKind": "wrapper",
            "wrapperName": "run",
            "flowPath": [
                {
                    "file": "app/helpers.py",
                    "line": "12",
                    "code": "cmd = build_command(cmd)",
                    "nodeType": "Call",
                },
                {
                    "file": "app/helpers.py",
                    "line": "20",
                    "code": "subprocess.run(cmd, shell=True)",
                    "nodeType": "Call",
                },
            ],
        }
    ]

    [finding] = JoernArm._parse_taint_results(raw)  # noqa: SLF001

    assert finding.line_start == 20
    assert finding.metadata["reportReason"] == "wrapper_internal_sink"
    assert any(
        loc["reason"] == "flow_command_construction"
        for loc in finding.metadata["reportCandidateLocations"]
    )


def test_signature_line_relocates_to_downstream_sink() -> None:
    raw = [
        {
            "sourceFile": "app/git_diff.py",
            "sourceLine": "33",
            "sourceCode": "ref",
            "sourceNodeType": "MethodParameterIn",
            "sinkFile": "app/git_diff.py",
            "sinkLine": "94",
            "sinkCode": "subprocess.run(cmd, shell=True)",
            "sinkName": "run",
            "flowPath": [
                {
                    "file": "app/git_diff.py",
                    "line": "33",
                    "code": "def _get_diff(ref: str):",
                    "nodeType": "Method",
                },
                {
                    "file": "app/git_diff.py",
                    "line": "94",
                    "code": "subprocess.run(cmd, shell=True)",
                    "nodeType": "Call",
                },
            ],
        }
    ]

    [finding] = JoernArm._parse_taint_results(raw)  # noqa: SLF001

    assert finding.file_path == "app/git_diff.py"
    assert finding.line_start == 94
    assert finding.metadata["reportReason"] == "signature_guard_relocation"
    assert {
        "file": "app/git_diff.py",
        "line": 33,
        "reason": "flow_non_wrapper_callsite",
    } in finding.metadata["reportCandidateLocations"]


def test_parse_json_response_with_warning_prefixed_repl_assignment() -> None:
    raw = (
        "1 warning found\n"
        "-- Warning: --------------------------------------------------------------------\n"
        '1 |cpg.method.name("run").repeat(_.caller)(_.maxDepth(3)).toJson\n'
        "  |                                        ^^^^^^^^^^^^^\n"
        "  |Implicit parameters should be provided with a `using` clause.\n"
        "  |To disable the warning, please use the following option:\n"
        '  |  "-Wconf:msg=Implicit parameters should be provided with a `using` clause:s"\n'
        'val res10: String = "[{\\"name\\":\\"main\\",\\"lineNumber\\":\\"42\\"}]"\n'
    )

    assert parse_joern_response(raw) == [{"name": "main", "lineNumber": "42"}]


def test_parse_bool_response_with_warning_prefixed_repl_assignment() -> None:
    raw = (
        "1 warning found\n"
        "-- Warning: --------------------------------------------------------------------\n"
        "  |Some Scala warning emitted before the result.\n"
        "val res2: Boolean = true\n"
    )

    assert parse_joern_response(raw, response_ty="bool") is True
