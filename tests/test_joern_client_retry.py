"""Unit tests for the JoernClient recursion-limit retry logic.

These tests don't require a running Joern server — they exercise the raw-
payload inspection and the one-shot retry in ``JoernClient.query`` with a
stubbed ``cpgqls_client`` core.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from auditzoo.backends.joern.client import (
    JoernClient,
    _looks_like_transient_compile_error,
)


_RECURSION_PAYLOAD = (
    "-- [E008] Not Found Error: -------------------------------------\n"
    "1 |cpg.method.id(107374185269L).call.map { call => Map(...) }.toJson\n"
    "  |^^^^^^^^^^\n"
    "  |value method is not a member of io.shiftleft.codepropertygraph"
    ".generated.Cpg.\n"
    "  |Extension methods were tried, but the search failed with:\n"
    "  |    Recursion limit exceeded.\n"
    "1 error found\n"
)


def test_transient_detector_recognises_recursion_limit() -> None:
    assert _looks_like_transient_compile_error(_RECURSION_PAYLOAD) is True


def test_transient_detector_recognises_extension_search_banner() -> None:
    banner = (
        "Extension methods were tried, but the search failed with:\n"
        "    Some other internal compiler hiccup.\n"
    )
    assert _looks_like_transient_compile_error(banner) is True


def test_transient_detector_ignores_normal_payloads() -> None:
    assert _looks_like_transient_compile_error('"[]"') is False
    assert _looks_like_transient_compile_error("res0: Int = 42") is False
    assert _looks_like_transient_compile_error("") is False


def _build_client_without_binary_checks(
    jvm_stack_size: str = "16m",
    jvm_extra_opts: list[str] | None = None,
    query_retries: int = 1,
) -> JoernClient:
    """Instantiate a ``JoernClient`` without triggering filesystem / port
    checks in ``__init__`` — we only need the ``query`` method wired up.
    """

    with patch.object(JoernClient, "_is_port_in_use", return_value=False), \
         patch("auditzoo.backends.joern.client.Path") as PathMock:
        # Make every Path(...) look like an existing executable so __init__
        # succeeds without the real Joern distribution on disk.
        PathMock.return_value.exists.return_value = True
        PathMock.return_value.__truediv__.return_value.exists.return_value = True
        client = JoernClient(
            joern_path="/fake/joern",
            host="localhost",
            port=65535,
            jvm_stack_size=jvm_stack_size,
            jvm_extra_opts=jvm_extra_opts,
            query_retries=query_retries,
            query_retry_sleep_s=0.0,
        )
    return client


@pytest.mark.asyncio
async def test_query_retries_once_on_recursion_limit_and_recovers() -> None:
    client = _build_client_without_binary_checks(query_retries=1)

    core = AsyncMock()
    core._send_query = AsyncMock(
        side_effect=[
            {"success": True, "stdout": _RECURSION_PAYLOAD},
            {"success": True, "stdout": '"[]"'},
        ]
    )
    client._connected_core = core  # type: ignore[assignment]

    result = await client.query("cpg.method.size")

    assert result == '"[]"'
    assert core._send_query.await_count == 2


@pytest.mark.asyncio
async def test_query_returns_payload_after_retries_exhausted() -> None:
    client = _build_client_without_binary_checks(query_retries=1)

    core = AsyncMock()
    core._send_query = AsyncMock(
        return_value={"success": True, "stdout": _RECURSION_PAYLOAD}
    )
    client._connected_core = core  # type: ignore[assignment]

    result = await client.query("cpg.method.size")

    # The compiler payload is returned verbatim so the upstream parser can
    # raise BackendResponseError with the full diagnostic, matching the
    # historical behaviour — we only suppress *recoverable* hits.
    assert _looks_like_transient_compile_error(result)
    assert core._send_query.await_count == 2  # original + 1 retry


@pytest.mark.asyncio
async def test_query_does_not_retry_on_normal_payload() -> None:
    client = _build_client_without_binary_checks(query_retries=1)

    core = AsyncMock()
    core._send_query = AsyncMock(
        return_value={"success": True, "stdout": '"[1,2,3]"'}
    )
    client._connected_core = core  # type: ignore[assignment]

    result = await client.query("cpg.method.size")

    assert result == '"[1,2,3]"'
    assert core._send_query.await_count == 1


@pytest.mark.asyncio
async def test_query_raises_on_hard_failure() -> None:
    client = _build_client_without_binary_checks(query_retries=1)

    core = AsyncMock()
    core._send_query = AsyncMock(
        return_value={"success": False, "error": "connection reset"}
    )
    client._connected_core = core  # type: ignore[assignment]

    from auditzoo.core.ir.backend_api import BackendQueryError

    with pytest.raises(BackendQueryError):
        await client.query("cpg.method.size")


def test_build_server_env_injects_xss_and_extras() -> None:
    client = _build_client_without_binary_checks(
        jvm_stack_size="16m",
        jvm_extra_opts=["-Xmx4g", "-Dfoo=bar"],
    )

    env = client._build_server_env()
    opts = env["JAVA_OPTS"].split()
    assert "-Xss16m" in opts
    assert "-Xmx4g" in opts
    assert "-Dfoo=bar" in opts


def test_build_server_env_preserves_existing_java_opts(monkeypatch: Any) -> None:
    monkeypatch.setenv("JAVA_OPTS", "-Dexisting=1")
    client = _build_client_without_binary_checks(jvm_stack_size="32m")

    env = client._build_server_env()
    opts = env["JAVA_OPTS"].split()
    assert "-Dexisting=1" in opts
    assert "-Xss32m" in opts


def test_build_server_env_omits_xss_when_disabled() -> None:
    client = _build_client_without_binary_checks(jvm_stack_size="")
    env = client._build_server_env()
    # When nothing is injected, JAVA_OPTS is either untouched or set to ""
    assert all("-Xss" not in tok for tok in env.get("JAVA_OPTS", "").split())
