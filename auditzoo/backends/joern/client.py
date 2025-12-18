"""Joern CPG client.

Low-level wrapper for interacting with Joern and querying the CPG.
"""

import os
import socket
import subprocess  # nosec B404 - subprocess needed for Joern interaction
import time
from pathlib import Path

import psutil
from cpgqls_client import CPGQLSClient
from rich.text import Text

from auditzoo.core.ir.backend_api import BackendConnectionError, BackendQueryError


class JoernClient:
    """Client for interacting with Joern CPG.

    This client handles:
    - Starting/stopping Joern server
    - Running CPG queries
    - Mapping query results to Python objects
    """

    def __init__(self, joern_path: str, host: str = "localhost", port: int = 8080):
        """Initialize Joern client.

        Args:
            joern_path: Path to Joern installation (e.g., /path/to/joern)
            host: Joern server host
            port: Joern server port
        """
        self.joern_path = Path(joern_path)

        if self._is_port_in_use(host, port):
            raise BackendConnectionError(
                f"Port {host}:{port} is already in use. Cannot connect to Joern."
            )
        self.host = host
        self.port = port

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
        self._cpg_path: Path | None = None
        self._first_query_executed: bool = False

    @property
    def cpg_path(self) -> Path | None:
        """Get the current CPG path.

        Returns:
            Path to the CPG file or None if not set
        """
        return self._cpg_path

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

        Raises:
            BackendConnectionError: If connection fails

        Example:
            # Single language project
            await client.connect(language="c", source_path="/path/to/c_project")
        """
        if self._connected_core is not None:
            return

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

        self._cpg_path = self._workspace_dir / "cpg.bin"
        if not self._cpg_path.exists():
            # Parse source code and create new CPG
            self._create_cpg(source_path, language=language)

        # Start Joern server
        try:
            self._start_joern_server()
        except BackendConnectionError as e:
            self._cpg_path = None
            self._workspace_dir = None
            raise BackendConnectionError(f"Failed to start Joern server: {e}") from e

        self._connected_core = CPGQLSClient(f"{self.host}:{self.port}")

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
            str(self._cpg_path),
        ]

        self._process = (
            subprocess.Popen(  # nosec B603 - Joern binary path controlled by config
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=os.environ.copy(),
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

    def _create_cpg(self, source_path: str, language: str = "auto"):
        """Create a new CPG from source code.

        Joern automatically detects build configuration:
           - For C/C++: Uses compile_commands.json if present
           - For Java: Handles .java, .class, .jar, Maven/Gradle
           - For others: Directly parses source files

        Args:
            source_path: Path to source code (directory or file)

        Raises:
            BackendConnectionError: If CPG creation fails
        """
        source = Path(source_path)
        if not source.exists():
            raise BackendConnectionError(f"Source path does not exist: {source_path}")

        if self._workspace_dir is None or not self._workspace_dir.exists():
            raise BackendConnectionError("Workspace directory is not initialized")

        if self._cpg_path is None or self._cpg_path.exists():
            raise BackendConnectionError("CPG path is already set or exists")

        # Build Joern parse command
        # Joern CLI: joern-parse --language <value> --output <cpg.bin> <source_path>
        cpg_output = self._cpg_path

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
        self._cpg_path = None
        self._first_query_executed = False

    async def query(self, query_str: str) -> str:
        """Execute a CPG query using Joern CLI.

        This executes queries by invoking joern with a script.
        For production, consider using Joern's HTTP server mode instead.

        Args:
            query_str: Joern query string (e.g., "cpg.method.name.l")

        Returns:
            Query results as string (typically JSON)
        """
        if not self.core:
            raise BackendConnectionError("Not connected to Joern")

        if not self._first_query_executed:
            # flush buffer from the initial connection
            await self.core._send_query("cpg")
            self._first_query_executed = True

        response = await self.core._send_query(query_str)
        if not response["success"]:
            raise BackendQueryError(
                f"Joern query failed: {response.get('error', 'Unknown error')}"
            )

        return Text.from_ansi(response["stdout"]).plain  # type: ignore

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
