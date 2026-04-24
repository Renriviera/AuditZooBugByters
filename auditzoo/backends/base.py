"""Base utilities for IR backends.

Common configuration, error handling, and utilities shared by all backends.
"""

import os
import re
from dataclasses import dataclass

from auditzoo.core.ir.backend_api import BackendConfig, BackendConfigError

DEFAULT_RUN_OVERLAYS: tuple[str, ...] = ("controlflow", "callgraph")
DEFAULT_CPG_CACHE_DIR: str = "~/.cache/auditzoo/joern_cpgs"

_CACHE_KEY_SANITIZER = re.compile(r"[^a-zA-Z0-9_.-]+")


def _parse_overlays_env(value: str) -> list[str]:
    """Split a comma/whitespace separated overlays string into a clean list."""
    tokens = [t.strip() for t in re.split(r"[,\s]+", value) if t.strip()]
    return tokens


def make_cpg_cache_key(cve_id: str | None, git_sha: str | None) -> str:
    """Build a stable, filesystem-safe cache key from CVE id + git SHA.

    Falls back to ``"unknown"`` components so upstream code never has to
    special-case missing values; callers should still prefer a hash of
    ``source_path`` when both are absent.
    """
    cve = (cve_id or "unknown").strip() or "unknown"
    sha = (git_sha or "").strip().lower()[:12] or "nosha"
    raw = f"{cve}_{sha}"
    return _CACHE_KEY_SANITIZER.sub("_", raw)


@dataclass
class JoernConfig(BackendConfig):
    """Configuration for Joern backend."""

    joern_path: str  # Path to Joern installation
    force_create_cpg: bool = False
    host: str = "localhost"
    port: int = 8080
    # JVM tuning for the Joern REPL subprocess.  The Scala 3 compiler that
    # powers the Joern REPL walks a deep extension-method search tree when
    # resolving things like ``cpg.method`` / ``cpg.tag``; on the default 1 MB
    # thread stack this intermittently trips "Recursion limit exceeded"
    # (see https://github.com/scala/scala3/issues/ and Joern issue trackers).
    # Bumping -Xss to 16m has been the recommended mitigation for years.
    jvm_stack_size: str = "16m"
    jvm_extra_opts: list[str] | None = None
    # Overlay passes to run after importCode.  Empty list = skip overlays.
    run_overlays: list[str] | None = None
    # CPG cache: when ``cpg_cache_key`` is set we route ``analysis_path``
    # to ``cpg_cache_dir`` and use the key as the Joern project name so the
    # existing ``workspace.projects.exists`` branch in JoernClient reuses
    # the CPG across runs.
    cpg_cache_dir: str | None = None
    cpg_cache_key: str | None = None

    def __init__(
        self,
        source_path: str,
        language: str | None = None,
        analysis_path: str | None = None,
        project_name: str | None = None,
        joern_path: str | None = None,
        **kwargs,
    ):
        cpg_cache_dir = kwargs.get("cpg_cache_dir")
        if cpg_cache_dir is None:
            cpg_cache_dir = os.environ.get(
                "AUDITZOO_CPG_CACHE_DIR", DEFAULT_CPG_CACHE_DIR
            )
        cpg_cache_dir = os.path.abspath(os.path.expanduser(cpg_cache_dir))

        cpg_cache_key = kwargs.get("cpg_cache_key")
        if cpg_cache_key is not None:
            cpg_cache_key = _CACHE_KEY_SANITIZER.sub("_", str(cpg_cache_key))

        # When the cache is active the Joern workspace lives under the cache
        # dir (one shared workspace, many projects) and the project name is
        # the cache key.  These override anything the caller might have passed
        # for analysis_path / project_name.
        if cpg_cache_key:
            analysis_path = cpg_cache_dir
            project_name = cpg_cache_key

        super().__init__(
            backend_type="joern",
            source_path=source_path,
            language=language if language is not None else "auto",
            analysis_path=analysis_path,
            project_name=project_name,
        )
        if self.language is None:
            raise BackendConfigError("Language must be specified for Joern backend")

        joern_path = kwargs.get("joern_path")
        if joern_path is None:
            joern_path = os.path.join(
                os.environ.get("CONDA_PREFIX", "/opt"), "opt/joern"
            )
        self.joern_path = joern_path

        self.host = kwargs.get("host", "localhost")
        self.port = kwargs.get("port", 8080)
        self.force_create_cpg = kwargs.get("force_create_cpg", False)
        # Allow env-var override so ops can tune without code changes.
        self.jvm_stack_size = kwargs.get(
            "jvm_stack_size",
            os.environ.get("AUDITZOO_JOERN_XSS", "16m"),
        )
        extras = kwargs.get("jvm_extra_opts")
        if extras is None:
            env_extras = os.environ.get("AUDITZOO_JOERN_JAVA_OPTS", "").strip()
            extras = env_extras.split() if env_extras else []
        self.jvm_extra_opts = list(extras)

        overlays = kwargs.get("run_overlays")
        if overlays is None:
            env_overlays = os.environ.get("AUDITZOO_JOERN_OVERLAYS")
            if env_overlays is not None:
                overlays = _parse_overlays_env(env_overlays)
            else:
                overlays = list(DEFAULT_RUN_OVERLAYS)
        self.run_overlays = list(overlays)

        self.cpg_cache_dir = cpg_cache_dir
        self.cpg_cache_key = cpg_cache_key

    @classmethod
    def with_cpg_cache(
        cls,
        source_path: str,
        *,
        cve_id: str | None,
        git_sha: str | None,
        language: str | None = None,
        cpg_cache_dir: str | None = None,
        **kwargs,
    ) -> "JoernConfig":
        """Convenience constructor that derives ``cpg_cache_key`` from CVE+SHA."""
        key = make_cpg_cache_key(cve_id, git_sha)
        return cls(
            source_path=source_path,
            language=language,
            cpg_cache_dir=cpg_cache_dir,
            cpg_cache_key=key,
            **kwargs,
        )


@dataclass
class TreeSitterConfig(BackendConfig):
    """Configuration for TreeSitter backend."""

    grammar_path: str | None = None

    def __init__(
        self,
        source_path: str,
        language: str,
        analysis_path: str | None = None,
        project_name: str | None = None,
        **kwargs,
    ):
        super().__init__(
            backend_type="treesitter",
            source_path=source_path,
            language=language,
            analysis_path=analysis_path,
            project_name=project_name,
        )
        self.grammar_path = kwargs.get("grammar_path")
