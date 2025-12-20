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

        _project_path = self._workspace_dir / project_name
        if not _project_path.exists():
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

    async def load_project(
        self, source_path: str, project_name: str, language: str = "auto"
    ) -> None:
        """Load a project into Joern.

        This recreates the CPG from the source code. Joern will automatically
        detect build configurations as needed.

        Args:
            source_path: Path to source code (directory or file)
            project_name: Name of the project
            language: Programming language (default "auto")

        Raises:
            BackendConnectionError: If CPG loading fails
        """
        if not self._connected_core or not self._workspace_dir:
            raise BackendConnectionError("Cannot reload CPG: not connected to Joern.")

        if language == "auto":
            await self.query(
                f'importCode(inputPath="{source_path}", projectName="{project_name}")'
            )
        else:
            await self.query(
                f'importCode(inputPath="{source_path}", projectName="{project_name}", language="{language}")'
            )

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
