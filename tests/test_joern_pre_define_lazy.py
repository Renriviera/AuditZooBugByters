"""Tests for lazy loading of ``pre_define.sc`` in :class:`JoernBackend`.

``pre_define.sc`` was previously shipped to the Joern REPL from
``connect()`` on every CPG build.  Shipping it triggers Scala
type-check + compile against the freshly-imported CPG, which on the
CWE-78 sweep accounted for ~85% of ``cpg_build_s`` (up to ~450s on a
20k-LoC repo) even for pipelines that never invoked the sole helper it
defines (``minimalCoveringNodeInfo``).

The new behaviour is to load it lazily from
``get_code_unit_by_location`` — the single entry point that needs the
helper today — and to cache the fact that it was loaded so subsequent
callers in the same JVM session don't pay the cost again.  The flag is
reset by ``connect``/``reload``/``disconnect`` because each of those
produces a fresh REPL state in which the helper is no longer defined.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from auditzoo.backends.base import JoernConfig
from auditzoo.backends.joern.backend import JoernBackend
from auditzoo.core.ir.backend_api import BackendUnimplementedError
from auditzoo.core.ir.model.base import CodeLocation


def _make_backend(tmp_path: Path) -> JoernBackend:
    """Build a ``JoernBackend`` with a stubbed-out ``JoernClient``.

    ``JoernClient.__init__`` validates the Joern binary on disk and
    probes the configured port; neither is available in a unit-test
    environment, so we patch the symbol imported by ``backend.py`` to
    a factory that returns a ``MagicMock`` pre-wired with the async
    methods the backend touches.
    """
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    cfg = JoernConfig(source_path=str(src), language="auto")

    fake_client = MagicMock()
    fake_client.connect = AsyncMock(return_value=None)
    fake_client.disconnect = AsyncMock(return_value=None)
    fake_client.load_project = AsyncMock(return_value=None)
    fake_client.last_connect_timings = {}
    fake_client.last_connect_rss = {}
    fake_client.gc_log_path = None
    fake_client.workspace_dir = "/tmp/fake_ws"

    with patch("auditzoo.backends.joern.backend.JoernClient", return_value=fake_client):
        backend = JoernBackend(cfg)
    return backend


@pytest.mark.asyncio
async def test_connect_does_not_load_pre_define(tmp_path: Path) -> None:
    """``connect`` must not ship ``pre_define.sc`` to the REPL anymore."""
    backend = _make_backend(tmp_path)
    queries: list[str] = []

    async def record_query_raw(q: str) -> str:
        queries.append(q)
        return ""

    backend.query_raw = record_query_raw  # type: ignore[assignment]

    await backend.connect()

    # The only distinguishing marker in pre_define.sc is the helper
    # symbol; if ``connect`` emitted it we'd see it in ``queries``.
    assert not any("minimalCoveringNodeInfo" in q for q in queries), queries
    assert backend._pre_define_loaded is False


@pytest.mark.asyncio
async def test_get_code_unit_by_location_triggers_lazy_load(
    tmp_path: Path,
) -> None:
    """First call that needs the helper must load it exactly once."""
    backend = _make_backend(tmp_path)
    load_calls = 0

    async def fake_load() -> None:
        nonlocal load_calls
        load_calls += 1

    backend._load_pre_defined_scripts = fake_load  # type: ignore[assignment]
    backend.query = AsyncMock(return_value=None)  # type: ignore[assignment]

    await backend.connect()
    assert load_calls == 0

    loc = CodeLocation(file_path=Path("a.py"), line_start=1, line_end=2)
    await backend.get_code_unit_by_location(loc)
    assert load_calls == 1
    assert backend._pre_define_loaded is True

    # Subsequent calls hit the cached flag — no more Scala compiles.
    await backend.get_code_unit_by_location(loc)
    await backend.get_code_unit_by_location(loc)
    assert load_calls == 1


@pytest.mark.asyncio
async def test_concurrent_first_callers_only_load_once(tmp_path: Path) -> None:
    """The lock must serialise concurrent first-time callers."""
    backend = _make_backend(tmp_path)
    load_calls = 0
    gate = asyncio.Event()

    async def slow_load() -> None:
        nonlocal load_calls
        # Wait until every caller is blocked on the lock before we
        # complete the load; this maximises the window in which a racy
        # implementation would fire duplicate compiles.
        await gate.wait()
        load_calls += 1

    backend._load_pre_defined_scripts = slow_load  # type: ignore[assignment]
    backend.query = AsyncMock(return_value=None)  # type: ignore[assignment]

    await backend.connect()

    loc = CodeLocation(file_path=Path("a.py"), line_start=1, line_end=2)
    tasks = [
        asyncio.create_task(backend.get_code_unit_by_location(loc)) for _ in range(8)
    ]
    # Let every task reach the lock / inner wait before we release it.
    await asyncio.sleep(0)
    gate.set()
    await asyncio.gather(*tasks)

    assert load_calls == 1
    assert backend._pre_define_loaded is True


@pytest.mark.asyncio
async def test_connect_after_disconnect_reloads_on_next_demand(
    tmp_path: Path,
) -> None:
    """A new JVM session must re-ship the helper on first demand."""
    backend = _make_backend(tmp_path)
    load_calls = 0

    async def fake_load() -> None:
        nonlocal load_calls
        load_calls += 1

    backend._load_pre_defined_scripts = fake_load  # type: ignore[assignment]
    backend.query = AsyncMock(return_value=None)  # type: ignore[assignment]
    backend.query_raw = AsyncMock(return_value="")  # type: ignore[assignment]

    await backend.connect()
    loc = CodeLocation(file_path=Path("a.py"), line_start=1, line_end=2)
    await backend.get_code_unit_by_location(loc)
    assert load_calls == 1

    await backend.disconnect()
    assert backend._pre_define_loaded is False

    await backend.connect()
    assert backend._pre_define_loaded is False

    await backend.get_code_unit_by_location(loc)
    assert load_calls == 2


@pytest.mark.asyncio
async def test_reload_invalidates_loaded_flag(tmp_path: Path) -> None:
    """``reload`` rebuilds the CPG so the helper must be reloaded."""
    backend = _make_backend(tmp_path)
    load_calls = 0

    async def fake_load() -> None:
        nonlocal load_calls
        load_calls += 1

    backend._load_pre_defined_scripts = fake_load  # type: ignore[assignment]
    backend.query = AsyncMock(return_value="proj")  # type: ignore[assignment]
    backend.query_raw = AsyncMock(return_value="")  # type: ignore[assignment]

    await backend.connect()
    loc = CodeLocation(file_path=Path("a.py"), line_start=1, line_end=2)
    await backend.get_code_unit_by_location(loc)
    assert load_calls == 1
    assert backend._pre_define_loaded is True

    await backend.reload()
    assert backend._pre_define_loaded is False

    await backend.get_code_unit_by_location(loc)
    assert load_calls == 2


@pytest.mark.asyncio
async def test_ensure_pre_defined_is_idempotent_without_connect(
    tmp_path: Path,
) -> None:
    """Calling the guard twice on a fresh backend still loads once."""
    backend = _make_backend(tmp_path)
    load_calls = 0

    async def fake_load() -> None:
        nonlocal load_calls
        load_calls += 1

    backend._load_pre_defined_scripts = fake_load  # type: ignore[assignment]

    await backend._ensure_pre_defined_loaded()
    await backend._ensure_pre_defined_loaded()
    await backend._ensure_pre_defined_loaded()
    assert load_calls == 1


@pytest.mark.asyncio
async def test_column_start_bypasses_lazy_load(tmp_path: Path) -> None:
    """The column_start branch raises before the guard is reached."""
    backend = _make_backend(tmp_path)
    load_calls = 0

    async def fake_load() -> None:
        nonlocal load_calls
        load_calls += 1

    backend._load_pre_defined_scripts = fake_load  # type: ignore[assignment]
    backend.query = AsyncMock(return_value=None)  # type: ignore[assignment]

    loc = CodeLocation(file_path=Path("a.py"), line_start=1, line_end=2, column_start=3)
    with pytest.raises(BackendUnimplementedError):
        await backend.get_code_unit_by_location(loc)
    # Guard is only reached after the column_start check, so the load
    # must not have fired for an unsupported request.
    assert load_calls == 0
    assert backend._pre_define_loaded is False


@pytest.mark.asyncio
async def test_pre_define_sc_is_still_shipped_verbatim(tmp_path: Path) -> None:
    """``_load_pre_defined_scripts`` still sends the full script body."""
    backend = _make_backend(tmp_path)
    sent: list[str] = []

    async def record(q: str) -> str:
        sent.append(q)
        return ""

    backend.query_raw = record  # type: ignore[assignment]

    await backend._load_pre_defined_scripts()
    assert len(sent) == 1
    assert "minimalCoveringNodeInfo" in sent[0]
    assert "cpg.file.nameExact" in sent[0]


def test_lock_is_per_instance(tmp_path: Path) -> None:
    """Each backend gets its own lock; state must not leak across them."""
    a = _make_backend(tmp_path)
    b = _make_backend(tmp_path)
    assert a._pre_define_lock is not b._pre_define_lock
    assert a._pre_define_loaded is False
    assert b._pre_define_loaded is False


def _assert_no_unconditional_load_in_connect_or_reload() -> None:
    """Regression: connect/reload must not unconditionally call the loader.

    Static check against the module source — if someone re-adds the
    eager call, this test fails loudly regardless of whether the rest
    of the suite happens to cover it at runtime.
    """
    import inspect

    src = inspect.getsource(JoernBackend.connect)
    assert (
        "_load_pre_defined_scripts" not in src
    ), "JoernBackend.connect must not eagerly load pre_define.sc"
    src_reload = inspect.getsource(JoernBackend.reload)
    assert (
        "_load_pre_defined_scripts" not in src_reload
    ), "JoernBackend.reload must not eagerly load pre_define.sc"


def test_connect_and_reload_source_do_not_eagerly_load() -> None:
    _assert_no_unconditional_load_in_connect_or_reload()
