"""Joern CPG client.

Low-level wrapper for interacting with Joern and querying the CPG.
"""

import asyncio
import logging
import os
import re
import socket
import subprocess  # nosec B404 - subprocess needed for Joern interaction
import time
from pathlib import Path

import psutil
from cpgqls_client import CPGQLSClient
from rich.text import Text

from auditzoo.backends.joern.utils import parse_joern_response
from auditzoo.core.ir.backend_api import BackendConnectionError, BackendQueryError

logger = logging.getLogger(__name__)

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
_RECURSION_LIMIT_RE = re.compile(
    r"Recursion limit exceeded", re.MULTILINE
)


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

    async def connect(
        self,
        language: str,
        source_path: str,
        analysis_path: str,
        project_name: str,
        force_create_cpg: bool = False,
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

        Raises:
            BackendConnectionError: If connection fails
        """
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

        self._connected_core = CPGQLSClient(f"{self.host}:{self.port}")

        # Set up the workspace and import the project
        # Note that this also flushes buffer from initial connection
        await self.query(f'switchWorkspace("{self._workspace_dir}")')

        # Check whether project already exists
        exists: bool = parse_joern_response(
            await self.query(f'workspace.projects.exists(_.name == "{project_name}")'),
            "bool",
        )

        if not exists or force_create_cpg:
            # Create new project
            if language == "auto":
                await self.query(
                    f'importCode(inputPath="{source_path}", projectName="{project_name}")'
                )
            else:
                await self.query(
                    f'importCode(inputPath="{source_path}", projectName="{project_name}", language="{language}")'
                )
            await self.query("run.controlflow")
            await self.query("run.callgraph")
        else:
            # Load existing project
            await self.query(f'open("{project_name}")')
            await self.query(f'workspace.setActiveProject("{project_name}")')

        # Warm up the Scala compiler's extension-method cache.  Running a
        # cheap reference to each ``Cpg`` extension we later rely on forces
        # the implicit/extension search once, while the compiler is still
        # cold and the stack is shallow.  Without this, the first real query
        # against a large CPG often hits "Recursion limit exceeded" even with
        # -Xss bumped.  Failures here are logged but non-fatal — the retry
        # wrapper in ``query`` will still handle transient hits later.
        await self._warm_up_extensions()

    async def _warm_up_extensions(self) -> None:
        """Touch the common ``Cpg`` extension entry points once.

        The Joern REPL is a Scala 3 compile-then-run loop.  Each fresh
        ``cpg.<member>`` reference forces an extension-method search whose
        intermediate results get cached.  Touching the members we actually
        use early (when the compiler's search depth is small) makes later
        queries either succeed outright or at least be retry-eligible.
        """
        warm_ups = [
            "cpg.method.size",       # used by get_code_units / callees
            "cpg.call.size",         # taint-reachability entry point
            "cpg.file.size",         # used by file-level lookups
            "cpg.tag.size",          # used by get_unit_tags
            "cpg.fieldAccess.size",  # used by source matching
        ]
        for q in warm_ups:
            try:
                await self.query(q)
            except (BackendQueryError, BackendConnectionError) as exc:
                logger.warning(
                    "Joern warm-up query %r failed (continuing): %s", q, exc,
                )

    def _build_server_env(self) -> dict[str, str]:
        """Build the subprocess env for the Joern REPL server.

        Adds ``-Xss<size>`` (and any ``jvm_extra_opts``) to ``JAVA_OPTS`` so
        the Scala 3 compiler has enough stack to resolve deep extension-method
        search trees without tripping "Recursion limit exceeded".
        """
        env = os.environ.copy()
        extra: list[str] = []
        if self.jvm_stack_size:
            extra.append(f"-Xss{self.jvm_stack_size}")
        extra.extend(self.jvm_extra_opts)
        if extra:
            existing = env.get("JAVA_OPTS", "").strip()
            env["JAVA_OPTS"] = (existing + " " + " ".join(extra)).strip()
            logger.debug(
                "Joern JVM JAVA_OPTS set to: %s", env["JAVA_OPTS"],
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

        if force_create_cpg:
            if language == "auto":
                await self.query(
                    f'importCode(inputPath="{source_path}", projectName="{project_name}")'
                )
            else:
                await self.query(
                    f'importCode(inputPath="{source_path}", projectName="{project_name}", language="{language}")'
                )
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
                attempt, attempts, self.query_retry_sleep_s,
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
