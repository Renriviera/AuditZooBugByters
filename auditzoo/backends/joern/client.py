"""Joern CPG client.

Low-level wrapper for interacting with Joern and querying the CPG.
"""

import asyncio
import contextlib
import errno
import fcntl
import json
import logging
import os
import re
import socket
import subprocess  # nosec B404 - subprocess needed for Joern interaction
import time
from collections.abc import Iterator
from pathlib import Path

import psutil
from cpgqls_client import CPGQLSClient
from rich.text import Text

from auditzoo.backends.joern.utils import parse_joern_response
from auditzoo.core.ir.backend_api import BackendConnectionError, BackendQueryError

logger = logging.getLogger(__name__)

ALLOWED_OVERLAYS: frozenset[str] = frozenset(
    {"controlflow", "callgraph", "dataflow", "typerelations"}
)

_META_FILENAME = "_auditzoo_meta.json"


def _dir_size_bytes(path: Path) -> int:
    """Return cumulative byte size of all files under *path* (best-effort)."""
    total = 0
    try:
        for entry in path.rglob("*"):
            try:
                if entry.is_file():
                    total += entry.stat().st_size
            except OSError:
                continue
    except OSError:
        return total
    return total


def prune_cpg_cache(cache_dir: str | os.PathLike, max_bytes: int) -> list[str]:
    """Prune a Joern CPG cache dir down to ``max_bytes``.

    Deletes entries (Joern project subdirectories at the top level) in
    ascending order of mtime until the aggregate tree size is under the
    budget.  Returns the list of removed project names.  Non-project
    entries (stray files, lock files) are ignored by the eviction policy
    but still counted in the size.
    """
    import shutil as _shutil

    cache_path = Path(cache_dir).expanduser()
    if not cache_path.exists() or max_bytes <= 0:
        return []

    entries: list[tuple[Path, float, int]] = []
    for child in cache_path.iterdir():
        if not child.is_dir():
            continue
        try:
            mtime = child.stat().st_mtime
        except OSError:
            continue
        entries.append((child, mtime, _dir_size_bytes(child)))

    total = sum(sz for _, _, sz in entries)
    if total <= max_bytes:
        return []

    entries.sort(key=lambda t: t[1])
    removed: list[str] = []
    for child, _mtime, size in entries:
        if total <= max_bytes:
            break
        try:
            _shutil.rmtree(child, ignore_errors=True)
            total -= size
            removed.append(child.name)
            lock = cache_path / f"{child.name}.lock"
            if lock.exists():
                try:
                    lock.unlink()
                except OSError:
                    pass
        except OSError as exc:
            logger.warning(
                "prune_cpg_cache: failed to remove %s: %s",
                child,
                exc,
            )
    return removed


# Regex for the Scala 3 compiler's transient "extension-method recursion limit"
# output.  When the server hits this, the REPL's response "succeeds" but the
# stdout is a compiler error buffer like:
#     -- [E008] Not Found Error: -----
#     1 |cpg.method.id(...).call.map {...}
#       |^^^^^^^^^^
#       |value method is not a member of io.shiftleft.codepropertygraph.generated.Cpg.
#       |Extension methods were tried, but the search failed with:
#       |    Recursion limit exceeded.
# These are recoverable: a warm-up query plus -Xss=16m typically stops them
# happening, and a single retry cleans up any stragglers where the first
# invocation's implicit-search cache got into a bad state.
_RECURSION_LIMIT_RE = re.compile(r"Recursion limit exceeded", re.MULTILINE)


def _looks_like_transient_compile_error(raw: str) -> bool:
    """True iff *raw* is the Scala REPL emitting a recoverable compiler error."""
    if not raw:
        return False
    if "Recursion limit exceeded" in raw:
        return True
    # Also treat the closely-related "Extension methods were tried, but the
    # search failed" banner as transient — it is the same root cause.
    if "Extension methods were tried" in raw and "search failed" in raw:
        return True
    return False


class JoernClient:
    """Client for interacting with Joern CPG.

    This client handles:
    - Starting/stopping Joern server
    - Running CPG queries
    - Mapping query results to Python objects
    """

    def __init__(
        self,
        joern_path: str,
        host: str = "localhost",
        port: int = 8080,
        *,
        jvm_stack_size: str = "16m",
        jvm_extra_opts: list[str] | None = None,
        query_retries: int = 1,
        query_retry_sleep_s: float = 0.5,
    ):
        """Initialize Joern client.

        Args:
            joern_path: Path to Joern installation (e.g., /path/to/joern)
            host: Joern server host
            port: Joern server port
            jvm_stack_size: Value for ``-Xss`` passed to the Joern JVM via
                ``JAVA_OPTS``.  The Scala 3 extension-method resolver in the
                Joern REPL trips "Recursion limit exceeded" on the default
                1 MB stack for non-trivial CPGs — 16m is a well-known safe
                mitigation.  Set to empty string to disable.
            jvm_extra_opts: Additional JVM flags appended to ``JAVA_OPTS``.
            query_retries: How many times to retry a query whose raw response
                is a transient Scala compiler error (e.g. recursion-limit
                compile failures).  ``0`` disables retries.
            query_retry_sleep_s: Delay between query retries, in seconds.
        """
        self.joern_path = Path(joern_path)

        if self._is_port_in_use(host, port):
            raise BackendConnectionError(
                f"Port {host}:{port} is already in use. Cannot connect to Joern."
            )
        self.host = host
        self.port = port

        self.jvm_stack_size = jvm_stack_size or ""
        self.jvm_extra_opts = list(jvm_extra_opts or [])
        self.query_retries = max(0, int(query_retries))
        self.query_retry_sleep_s = max(0.0, float(query_retry_sleep_s))

        # Determine Joern executable path
        self.joern_bin = self.joern_path / "joern-cli" / "joern"
        if not self.joern_bin.exists():
            raise BackendConnectionError(
                f"Joern executable not found at {self.joern_bin}"
            )

        self.joern_parse = self.joern_path / "joern-cli" / "joern-parse"
        if not self.joern_parse.exists():
            raise BackendConnectionError(
                f"Joern parse executable not found at {self.joern_parse}"
            )

        self._process: subprocess.Popen | None = None
        self._connected_core: CPGQLSClient | None = None
        self._workspace_dir: Path | None = None

        # Per-connect instrumentation; populated by ``connect`` and readable
        # by the backend proxy / pipeline for phase-level attribution.
        self.last_connect_timings: dict[str, float | bool] = {}
        self.last_connect_rss: dict[str, int] = {}
        # When set (via AUDITZOO_JOERN_GC_LOG), the dir we passed to the JVM
        # for unified GC logging.  Useful to point ops at the log file that
        # was active during a timed-out build.
        self.gc_log_path: str | None = None

    @property
    def workspace_dir(self) -> Path | None:
        """Get the current workspace directory.

        Returns:
            Path to workspace directory if connected, else None
        """
        return self._workspace_dir

    @property
    def core(self) -> CPGQLSClient:
        """Get the connected CPGQLSClient core.

        Raises:
            BackendConnectionError: If not connected

        Returns:
            CPGQLSClient instance
        """
        if not self._connected_core:
            raise BackendConnectionError("Not connected to Joern")

        return self._connected_core

    @staticmethod
    def _is_port_in_use(host: str, port: int) -> bool:
        """Check if a port is already in use.

        Args:
            port: Port number to check

        Returns:
            True if port is in use
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex((host, port)) == 0

    def _execute_joern_cli_command(self, cmd: list[str]) -> tuple[bytes, bytes]:
        """Execute a Joern cli command.

        Args:
            cmd: Command and arguments as list of strings

        Returns:
            Tuple of (stdout, stderr) from the command execution
        """
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                check=False,
            )  # nosec B603 - Joern binary path controlled by config

            if result.returncode != 0:
                error_msg = result.stderr.decode() if result.stderr else "Unknown error"
                raise BackendConnectionError(f"Joern CPG creation failed: {error_msg}")

            return result.stdout, result.stderr

        except FileNotFoundError as e:
            raise BackendConnectionError(f"Joern binary not found: {cmd[0]}") from e
        except Exception as e:
            raise BackendConnectionError(
                f"Failed to execute Joern command: {cmd} - {e}"
            ) from e

    def get_supported_languages(self) -> list[str]:
        """Get list of programming languages supported by Joern.

        Returns:
            List of supported language names
        """
        cmd = [str(self.joern_parse), "--list-languages"]
        try:
            stdout, _ = self._execute_joern_cli_command(cmd)
            languages = stdout.decode().splitlines()
            return [
                lang.strip().split()[-1]
                for lang in languages
                if lang.strip().startswith("-")
            ]
        except BackendConnectionError as e:
            raise BackendConnectionError(
                f"Failed to get supported languages: {e}"
            ) from e

    @staticmethod
    def _validate_overlays(run_overlays: list[str] | None) -> list[str]:
        """Normalise and validate an overlays list.

        An empty list (``[]``) is legal and means "skip overlays entirely".
        ``None`` is treated as "use defaults" and resolves to
        ``["controlflow", "callgraph"]`` for backwards compatibility.
        """
        if run_overlays is None:
            return ["controlflow", "callgraph"]
        cleaned: list[str] = []
        for raw in run_overlays:
            token = str(raw).strip()
            if not token:
                continue
            if token not in ALLOWED_OVERLAYS:
                raise BackendConnectionError(
                    f"Unknown Joern overlay {token!r}. Allowed: "
                    f"{sorted(ALLOWED_OVERLAYS)}"
                )
            cleaned.append(token)
        return cleaned

    def _sample_rss(self) -> int:
        """Sample the Joern server RSS in bytes, or 0 on error.

        The shipped ``joern`` launcher is a POSIX shell wrapper that
        spawns ``repl-bridge`` (another shell wrapper) which in turn
        spawns the actual JVM — none of them ``exec`` the child, so
        sampling just ``self._process.pid`` returns the outer shell's
        RSS (a few MiB) and misses the JVM entirely.  Walk the process
        tree and sum ``rss`` across the root + every descendant so the
        reported number is the real JVM footprint.
        """
        proc = self._process
        if proc is None:
            return 0
        try:
            root = psutil.Process(proc.pid)
        except (psutil.Error, OSError):
            return 0
        total = 0
        try:
            total += int(root.memory_info().rss)
        except (psutil.Error, OSError):
            pass
        try:
            for child in root.children(recursive=True):
                try:
                    total += int(child.memory_info().rss)
                except (psutil.Error, OSError):
                    continue
        except (psutil.Error, OSError):
            pass
        return total

    def _record_rss(self, label: str) -> None:
        """Record an RSS sample under *label* and update ``peak_bytes``."""
        rss = self._sample_rss()
        self.last_connect_rss[f"{label}_bytes"] = rss
        prev_peak = int(self.last_connect_rss.get("peak_bytes", 0))
        if rss > prev_peak:
            self.last_connect_rss["peak_bytes"] = rss

    @contextlib.contextmanager
    def _phase_timer(self, label: str) -> Iterator[None]:
        """Context manager that records wall-clock seconds under ``label``."""
        start = time.perf_counter()
        try:
            yield
        finally:
            self.last_connect_timings[label] = time.perf_counter() - start

    @staticmethod
    @contextlib.contextmanager
    def _cache_flock(lock_path: Path) -> Iterator[None]:
        """Advisory POSIX lock around a cache project.

        Concurrent eval workers hitting the same ``<cache>/<project>.lock``
        will serialise on the importCode + overlays section so only one
        worker writes to the CPG directory; the rest re-enter the
        ``workspace.projects.exists`` branch on release.  Failures
        (e.g. on filesystems that don't support flock) degrade to a warning
        and proceed unlocked.
        """
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd: int | None = None
        try:
            fd = os.open(
                str(lock_path),
                os.O_CREAT | os.O_RDWR,
                0o644,
            )
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
            except OSError as exc:
                if exc.errno in (errno.ENOLCK, errno.ENOSYS, errno.EINVAL):
                    logger.warning(
                        "Joern CPG cache: flock unsupported on %s (%s); "
                        "proceeding without a lock.",
                        lock_path,
                        exc,
                    )
                else:
                    raise
            yield
        finally:
            if fd is not None:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
                try:
                    os.close(fd)
                except OSError:
                    pass

    @staticmethod
    def _read_cache_meta(meta_path: Path) -> dict | None:
        try:
            return json.loads(meta_path.read_text())
        except (OSError, ValueError):
            return None

    @staticmethod
    def _write_cache_meta(meta_path: Path, meta: dict) -> None:
        try:
            meta_path.parent.mkdir(parents=True, exist_ok=True)
            meta_path.write_text(json.dumps(meta, sort_keys=True))
        except OSError as exc:
            logger.warning(
                "Joern CPG cache: failed to write meta %s: %s",
                meta_path,
                exc,
            )

    async def connect(
        self,
        language: str,
        source_path: str,
        analysis_path: str,
        project_name: str,
        force_create_cpg: bool = False,
        run_overlays: list[str] | None = None,
        cache_enabled: bool = False,
    ) -> None:
        """Connect to Joern and create/load CPG.

        If needed, Joern AUTOMATICALLY detects all languages in a project by file extensions:
        - C/C++ (.c, .cc, .cpp, .h, .hpp)
        - Java (.java, .jar, .class)
        - JavaScript/TypeScript (.js, .ts, .jsx, .tsx)
        - Python (.py)
        - Go (.go)
        - Kotlin (.kt)
        - And more...

        For C/C++, Joern uses compile_commands.json if present for accurate
        preprocessing. Otherwise, it parses source directly.

        Args:
            language: The programming language of the project, "auto" to let Joern detect
            source_path: Path to source code directory
            analysis_path: Path to store analysis artifacts
            project_name: Name of the project
            force_create_cpg: Whether to force create a new CPG even if one exists
            run_overlays: Ordered list of overlays to run after ``importCode``.
                ``None`` defaults to ``["controlflow", "callgraph"]``; an
                empty list skips overlays entirely.
            cache_enabled: When True, (a) treat a pre-existing project with
                matching overlay metadata as a cache hit (skip import +
                overlays) and (b) guard the import/overlay section with an
                advisory POSIX flock so concurrent workers don't race on
                the same CPG directory.

        Raises:
            BackendConnectionError: If connection fails
        """
        overlays = self._validate_overlays(run_overlays)

        # Reset instrumentation for this connect attempt so partial state
        # from a failed earlier build doesn't bleed through.
        self.last_connect_timings = {"cache_hit": False}
        self.last_connect_rss = {}
        connect_start = time.perf_counter()

        if self._connected_core is not None:
            if self._workspace_dir != Path(analysis_path):
                raise BackendConnectionError(
                    "JoernClient is already connected with a different workspace."
                )
            return  # Already connected

        # Source path must exist
        source = Path(source_path)
        if not source.exists():
            raise BackendConnectionError(f"Source path does not exist: {source_path}")

        # Check whether the language is supported
        if language != "auto":
            supported_languages = self.get_supported_languages()
            if language.lower() not in [lang.lower() for lang in supported_languages]:
                raise BackendConnectionError(
                    f"Language '{language}' is not supported by Joern. Supported languages: {supported_languages}"
                )

        # Update workspace directory
        self._workspace_dir = Path(analysis_path)
        if not self._workspace_dir.exists():
            self._workspace_dir.mkdir(parents=True, exist_ok=True)

        # Start Joern server
        try:
            self._start_joern_server()
        except BackendConnectionError as e:
            self._workspace_dir = None
            raise BackendConnectionError(f"Failed to start Joern server: {e}") from e

        self._record_rss("start")

        self._connected_core = CPGQLSClient(f"{self.host}:{self.port}")

        # Set up the workspace and import the project
        # Note that this also flushes buffer from initial connection
        with self._phase_timer("switch_workspace_s"):
            await self.query(f'switchWorkspace("{self._workspace_dir}")')

        with self._phase_timer("project_exists_check_s"):
            exists: bool = parse_joern_response(
                await self.query(
                    f'workspace.projects.exists(_.name == "{project_name}")'
                ),
                "bool",
            )

        # Cache-hit gate: when caching is on, verify that the persisted
        # overlay set matches what we were asked to run.  A mismatch must
        # force a rebuild or downstream queries may silently rely on missing
        # passes (e.g. callgraph).
        meta_path = self._workspace_dir / project_name / _META_FILENAME
        cached_meta = self._read_cache_meta(meta_path) if cache_enabled else None
        overlays_match = (
            cached_meta is not None
            and list(cached_meta.get("run_overlays", [])) == overlays
        )
        cache_hit = cache_enabled and exists and not force_create_cpg and overlays_match
        if cache_enabled and exists and not overlays_match and not force_create_cpg:
            logger.info(
                "Joern CPG cache: overlay mismatch for project %s "
                "(cached=%s, requested=%s); rebuilding.",
                project_name,
                cached_meta.get("run_overlays") if cached_meta else None,
                overlays,
            )
            force_create_cpg = True

        self.last_connect_timings["cache_hit"] = bool(cache_hit)

        lock_cm: contextlib.AbstractContextManager = contextlib.nullcontext()
        if cache_enabled and not cache_hit:
            lock_cm = self._cache_flock(self._workspace_dir / f"{project_name}.lock")

        with lock_cm:
            # Re-check existence under the lock so concurrent workers that
            # lost the race do not double-import the same project.
            if cache_enabled and not cache_hit:
                with self._phase_timer("project_exists_recheck_s"):
                    exists = parse_joern_response(
                        await self.query(
                            f'workspace.projects.exists(_.name == "{project_name}")'
                        ),
                        "bool",
                    )
                cached_meta = self._read_cache_meta(meta_path)
                overlays_match = (
                    cached_meta is not None
                    and list(cached_meta.get("run_overlays", [])) == overlays
                )
                if exists and overlays_match and not force_create_cpg:
                    cache_hit = True
                    self.last_connect_timings["cache_hit"] = True

            if not exists or force_create_cpg or not cache_hit:
                with self._phase_timer("import_code_s"):
                    if language == "auto":
                        await self.query(
                            f'importCode(inputPath="{source_path}", '
                            f'projectName="{project_name}")'
                        )
                    else:
                        await self.query(
                            f'importCode(inputPath="{source_path}", '
                            f'projectName="{project_name}", '
                            f'language="{language}")'
                        )
                self._record_rss("after_import")

                for overlay in overlays:
                    with self._phase_timer(f"overlay_{overlay}_s"):
                        await self.query(f"run.{overlay}")
                self._record_rss("after_overlays")

                if cache_enabled:
                    self._write_cache_meta(
                        meta_path,
                        {
                            "run_overlays": list(overlays),
                            "language": language,
                            "project_name": project_name,
                            "created_at": time.time(),
                        },
                    )
            else:
                with self._phase_timer("open_existing_s"):
                    await self.query(f'open("{project_name}")')
                    await self.query(f'workspace.setActiveProject("{project_name}")')
                self._record_rss("after_open")

        # Warm up the Scala compiler's extension-method cache.  Running a
        # cheap reference to each ``Cpg`` extension we later rely on forces
        # the implicit/extension search once, while the compiler is still
        # cold and the stack is shallow.  Without this, the first real query
        # against a large CPG often hits "Recursion limit exceeded" even with
        # -Xss bumped.  Failures here are logged but non-fatal — the retry
        # wrapper in ``query`` will still handle transient hits later.
        with self._phase_timer("warmup_s"):
            await self._warm_up_extensions()
        self._record_rss("after_warmup")

        self.last_connect_timings["total_connect_s"] = (
            time.perf_counter() - connect_start
        )
        self.last_connect_timings["overlays"] = list(overlays)
        logger.info(
            "Joern connect finished: project=%s cache_hit=%s total=%.2fs "
            "import=%.2fs overlays=%s warmup=%.2fs rss_peak=%.1fMiB",
            project_name,
            self.last_connect_timings.get("cache_hit"),
            float(self.last_connect_timings.get("total_connect_s", 0.0)),
            float(self.last_connect_timings.get("import_code_s", 0.0)),
            {
                o: round(
                    float(self.last_connect_timings.get(f"overlay_{o}_s", 0.0)),
                    2,
                )
                for o in overlays
            },
            float(self.last_connect_timings.get("warmup_s", 0.0)),
            self.last_connect_rss.get("peak_bytes", 0) / (1024 * 1024),
        )

    async def _warm_up_extensions(self) -> None:
        """Touch the common ``Cpg`` extension entry points once.

        The Joern REPL is a Scala 3 compile-then-run loop.  Each fresh
        ``cpg.<member>`` reference forces an extension-method search whose
        intermediate results get cached.  Touching the members we actually
        use early (when the compiler's search depth is small) makes later
        queries either succeed outright or at least be retry-eligible.
        """
        warm_ups = [
            "cpg.method.size",  # used by get_code_units / callees
            "cpg.call.size",  # taint-reachability entry point
            "cpg.file.size",  # used by file-level lookups
            "cpg.tag.size",  # used by get_unit_tags
            "cpg.fieldAccess.size",  # used by source matching
        ]
        for q in warm_ups:
            try:
                await self.query(q)
            except (BackendQueryError, BackendConnectionError) as exc:
                logger.warning(
                    "Joern warm-up query %r failed (continuing): %s",
                    q,
                    exc,
                )

    def _build_server_env(self) -> dict[str, str]:
        """Build the subprocess env for the Joern REPL server.

        Adds ``-Xss<size>`` (and any ``jvm_extra_opts``) to ``JAVA_OPTS`` so
        the Scala 3 compiler has enough stack to resolve deep extension-method
        search trees without tripping "Recursion limit exceeded".

        When ``AUDITZOO_JOERN_GC_LOG`` is set to a directory, also wires
        unified JVM GC logging to ``<dir>/joern-gc-<timestamp>.log`` so
        timed-out builds can be diagnosed as heap thrash vs stuck pass.
        """
        env = os.environ.copy()
        extra: list[str] = []
        if self.jvm_stack_size:
            extra.append(f"-Xss{self.jvm_stack_size}")
        extra.extend(self.jvm_extra_opts)

        gc_log_dir = os.environ.get("AUDITZOO_JOERN_GC_LOG", "").strip()
        if gc_log_dir:
            try:
                gc_log_dir_abs = os.path.abspath(os.path.expanduser(gc_log_dir))
                os.makedirs(gc_log_dir_abs, exist_ok=True)
                gc_log_file = os.path.join(gc_log_dir_abs, "joern-gc-%t.log")
                extra.append(
                    f"-Xlog:gc*,safepoint:file={gc_log_file}" ":tags,time,uptime,level"
                )
                self.gc_log_path = gc_log_dir_abs
                logger.info("Joern GC logging enabled -> %s", gc_log_dir_abs)
            except OSError as exc:
                logger.warning(
                    "Joern GC log dir %r unusable (%s); skipping.",
                    gc_log_dir,
                    exc,
                )
                self.gc_log_path = None
        else:
            self.gc_log_path = None

        if extra:
            existing = env.get("JAVA_OPTS", "").strip()
            env["JAVA_OPTS"] = (existing + " " + " ".join(extra)).strip()
            logger.debug(
                "Joern JVM JAVA_OPTS set to: %s",
                env["JAVA_OPTS"],
            )
        return env

    def _start_joern_server(self) -> None:
        """Start Joern server process."""
        if self._process is not None:
            return  # Already started

        cmd = [
            str(self.joern_bin),
            "--nocolors",
            "--server",
            "--server-host",
            self.host,
            "--server-port",
            str(self.port),
        ]

        self._process = (
            subprocess.Popen(  # nosec B603 - Joern binary path controlled by config
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self._build_server_env(),
            )
        )

        # Wait for the server to be ready
        try:
            self._wait_for_port()
        except Exception as e:
            logs: bytes | None = None
            if self._process.poll() is not None:
                stdout, stderr = self._process.communicate()
                logs = stdout + b"\n" + stderr

            self._process.terminate()
            self._process = None
            raise BackendConnectionError(
                f"Failed to start Joern server: {e}\nLogs:\n{logs.decode() if logs else 'No logs available.'}"
            ) from e

    def _wait_for_port(self, timeout_s: float = 60.0) -> None:
        """Wait for Joern server port to be available.

        Args:
            timeout_s: Maximum time to wait in seconds

        Raises:
            BackendConnectionError: If port is not available within timeout
        """
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            try:
                if self._is_port_in_use(self.host, self.port):
                    return
            except Exception as e:
                raise BackendConnectionError(
                    f"Error checking Joern port {self.host}:{self.port}: {e}"
                ) from e

            time.sleep(1.0)

        raise BackendConnectionError(
            f"Joern server port {self.host}:{self.port} not available after {timeout_s} seconds"
        )

    async def load_project(
        self,
        source_path: str,
        project_name: str,
        language: str = "auto",
        force_create_cpg: bool = False,
        run_overlays: list[str] | None = None,
    ) -> None:
        """Load a project into Joern.

        This recreates the CPG from the source code. Joern will automatically
        detect build configurations as needed.

        Args:
            source_path: Path to source code (directory or file)
            project_name: Name of the project
            language: Programming language (default "auto")
            force_create_cpg: Whether to force create a new CPG even if one exists

        Raises:
            BackendConnectionError: If CPG loading fails
        """
        if not self._connected_core or not self._workspace_dir:
            raise BackendConnectionError("Cannot reload CPG: not connected to Joern.")

        overlays = self._validate_overlays(run_overlays)

        if force_create_cpg:
            if language == "auto":
                await self.query(
                    f'importCode(inputPath="{source_path}", projectName="{project_name}")'
                )
            else:
                await self.query(
                    f'importCode(inputPath="{source_path}", projectName="{project_name}", language="{language}")'
                )
            for overlay in overlays:
                await self.query(f"run.{overlay}")
        else:
            # Load existing project
            await self.query(f'open("{project_name}")')

        await self.query(f'workspace.setActiveProject("{project_name}")')

    def create_cpg(self, source_path: str, project_name: str, language: str = "auto"):
        """Create a new CPG from source code.

        Joern automatically detects build configuration:
           - For C/C++: Uses compile_commands.json if present
           - For Java: Handles .java, .class, .jar, Maven/Gradle
           - For others: Directly parses source files

        Args:
            source_path: Path to source code (directory or file)
            project_name: Name of the project
            language: Programming language (default "auto")

        Raises:
            BackendConnectionError: If CPG creation fails
        """
        source = Path(source_path)
        if not source.exists():
            raise BackendConnectionError(f"Source path does not exist: {source_path}")

        if self._workspace_dir is None or not self._workspace_dir.exists():
            raise BackendConnectionError("Workspace directory is not initialized")

        _project_path = self._workspace_dir / project_name
        if not _project_path.exists():
            raise BackendConnectionError(
                f"Project path does not exist: {_project_path}"
            )

        # Build Joern parse command
        # Joern CLI: joern-parse --language <value> --output <cpg.bin> <source_path>
        cpg_output = _project_path / "cpg.bin"

        cmd = [str(self.joern_parse), "--output", str(cpg_output)]
        if language != "auto":
            cmd.extend(["--language", language])
        cmd.append(str(source))

        try:
            self._execute_joern_cli_command(cmd)
        except BackendConnectionError as e:
            raise BackendConnectionError(f"Failed to create CPG: {e}") from e

    async def disconnect(self):
        """Disconnect from Joern and cleanup resources."""
        if self._process:
            try:
                # Get parent process and all children
                parent = psutil.Process(self._process.pid)
                children = parent.children(recursive=True)

                # Terminate all children and parent
                for child in children:
                    try:
                        child.terminate()
                    except psutil.NoSuchProcess:
                        pass
                parent.terminate()

                # Wait for processes to terminate gracefully
                _, alive = psutil.wait_procs(children + [parent], timeout=5)

                # Force kill any remaining processes
                for p in alive:
                    try:
                        p.kill()
                    except psutil.NoSuchProcess:
                        pass

            except psutil.NoSuchProcess:
                # Process already terminated
                pass
            finally:
                self._process = None

        self._connected_core = None
        self._workspace_dir = None

    async def query(self, query_str: str) -> str:
        """Execute a CPG query using the Joern REPL server.

        A single transparent retry is performed when the REPL returns a
        *transient* Scala compiler error (most commonly "Recursion limit
        exceeded" while resolving ``Cpg`` extension methods).  Such errors
        look like a successful RPC to ``cpgqls-client`` — the compiler just
        writes its diagnostic to stdout in place of a real result — so they
        are detected by scanning the decoded payload.

        Args:
            query_str: Joern query string (e.g., "cpg.method.name.l")

        Returns:
            Query results as string (typically JSON)
        """
        if not self.core:
            raise BackendConnectionError("Not connected to Joern")

        last_raw: str = ""
        attempts = self.query_retries + 1
        for attempt in range(1, attempts + 1):
            response = await self.core._send_query(query_str)
            if not response["success"]:
                raise BackendQueryError(
                    f"Joern query failed: {response.get('error', 'Unknown error')}"
                )

            raw = Text.from_ansi(response["stdout"]).plain  # type: ignore
            last_raw = raw

            if not _looks_like_transient_compile_error(raw):
                return raw

            if attempt >= attempts:
                break

            logger.warning(
                "Joern query hit transient Scala compile error "
                "(attempt %d/%d); retrying in %.2fs. Query head: %s",
                attempt,
                attempts,
                self.query_retry_sleep_s,
                query_str[:120].replace("\n", " "),
            )
            if self.query_retry_sleep_s > 0:
                await asyncio.sleep(self.query_retry_sleep_s)

        # Exhausted retries — return the last payload so the caller's parser
        # raises a BackendResponseError with the compiler text, matching
        # previous behaviour.
        return last_raw

    async def __aenter__(self):
        """Context manager entry.

        Returns:
            Self for use in with statement

        Example:
            async with JoernClient(joern_path="/path/to/joern") as client:
                await client.connect(
                    language="c",
                    source_path="/path/to/source",
                    analysis_path="/path/to/analysis"
                )
                results = client.query("cpg.method.name.l")
        """
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit.

        Automatically disconnects and cleans up resources when exiting the context.
        This ensures proper cleanup even if an exception occurs.

        Args:
            exc_type: Exception type if an exception occurred
            exc_val: Exception value if an exception occurred
            exc_tb: Exception traceback if an exception occurred
        """
        await self.disconnect()
