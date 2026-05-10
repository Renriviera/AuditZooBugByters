"""Stable, content-keyed cache for Joern CPGs.

Joern's dominant per-CVE cost is CPG construction — typically the
``importCode(...)`` call inside :class:`auditzoo.backends.joern.client.JoernClient`.
By default the analysis workspace lives at ``<repo>/.auditzoo`` which the
sweep harness deletes immediately after each CVE (``shutil.rmtree(repo_dest)``
in :mod:`scripts.run_evaluation`), so every re-run pays full CPG cost
even when the source bytes haven't changed.

This module encapsulates a *durable* analysis workspace keyed on
``sha256(repo_url, commit, language, joern_version, cache_version)``.
When :class:`auditzoo.backends.joern.backend.JoernBackend.connect` finds
the project name already exists in that workspace it skips
``importCode`` entirely and falls into the cheap ``open(name)`` branch
— turning subsequent runs of the same CVE/commit into seconds.

Memory / disk envelope (124 GB RAM, 106 GB free disk on the runpod):

* CPG sizes for typical Python projects in the CWE-78 set range from
  ~1 MB (single-module package) to ~500 MB (large monorepos / Django).
* 30-CVE sweeps are well under 30 GB of cache.
* Memory pressure is independent of cache size — Joern still loads at
  most one CPG at a time into the JVM heap.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess  # nosec B404 - git metadata lookup only
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Bump this number to invalidate every cached CPG without touching the
# filesystem (e.g. after a Joern upgrade that changes the on-disk schema).
CACHE_VERSION = 1


@dataclass(frozen=True)
class CpgCacheLocation:
    """Where to point Joern when caching is enabled.

    ``workspace_dir`` is what gets passed as ``analysis_path``; Joern
    creates a subdirectory ``<workspace_dir>/<project_name>`` for the
    actual ``cpg.bin`` and metadata, and reuses it on subsequent runs
    when the project name already exists.
    """

    workspace_dir: Path
    project_name: str
    cache_key: str  # short SHA prefix for logs / audit
    repo_url: str
    commit: str


def cpg_cache_location(
    cache_root: Path | str,
    repo_url: str,
    commit: str,
    *,
    language: str = "python",
    joern_version: str = "",
    cache_version: int = CACHE_VERSION,
) -> CpgCacheLocation:
    """Build a deterministic cache slot for ``(repo_url, commit, ...)``.

    The full SHA is used as the directory name so two close-but-distinct
    commits can never collide; the first 16 hex chars of the SHA are
    embedded in the project name (which Joern uses as a workspace key)
    for compact log lines.
    """
    payload = "|".join(
        [
            str(cache_version),
            repo_url.strip(),
            commit.strip(),
            language.strip(),
            joern_version.strip(),
        ]
    ).encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()
    short = digest[:16]
    workspace_dir = Path(cache_root).expanduser().resolve() / digest
    return CpgCacheLocation(
        workspace_dir=workspace_dir,
        project_name=f"cpg_{short}",
        cache_key=short,
        repo_url=repo_url,
        commit=commit,
    )


def detect_repo_metadata(repo_path: Path | str) -> tuple[str, str]:
    """Return ``(remote_url, commit_sha)`` for *repo_path*.

    Best-effort: empty strings when git is unavailable or the directory
    is not a git checkout.  Both are stripped of trailing whitespace so
    the cache key is stable across newline conventions.
    """
    repo_path = Path(repo_path)
    remote = ""
    commit = ""
    try:
        remote = subprocess.check_output(  # nosec B603, B607
            ["git", "remote", "get-url", "origin"],
            cwd=str(repo_path),
            text=True,
            timeout=10,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        pass
    try:
        commit = subprocess.check_output(  # nosec B603, B607
            ["git", "rev-parse", "HEAD"],
            cwd=str(repo_path),
            text=True,
            timeout=10,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        pass
    return remote, commit


def cache_metadata_path(loc: CpgCacheLocation) -> Path:
    return loc.workspace_dir / "auditzoo_cache.json"


def is_cache_hit(loc: CpgCacheLocation) -> bool:
    """``True`` iff a Joern project directory already exists at *loc*.

    We check for the project subdirectory rather than ``cpg.bin``
    because Joern stores the binary at ``<workspace>/<project>/cpg.bin``
    on first import and only renames it during ``run.commit`` — both
    states are valid cache hits for the open() branch.
    """
    return (loc.workspace_dir / loc.project_name).is_dir()


def write_cache_metadata(loc: CpgCacheLocation, **extra: Any) -> None:
    """Persist a tiny JSON breadcrumb so future runs can audit the cache."""
    payload = {
        "cache_key": loc.cache_key,
        "repo_url": loc.repo_url,
        "commit": loc.commit,
        "project_name": loc.project_name,
        "created_at": time.time(),
        "cache_version": CACHE_VERSION,
        **extra,
    }
    try:
        loc.workspace_dir.mkdir(parents=True, exist_ok=True)
        cache_metadata_path(loc).write_text(json.dumps(payload, indent=2))
    except OSError as exc:
        logger.warning("Failed to write CPG cache metadata at %s: %s", loc.workspace_dir, exc)


def read_cache_metadata(loc: CpgCacheLocation) -> dict[str, Any] | None:
    path = cache_metadata_path(loc)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def cpg_artifact_size_bytes(loc: CpgCacheLocation) -> int:
    """Rough on-disk footprint of the cached project (sum of files)."""
    total = 0
    if not loc.workspace_dir.exists():
        return 0
    for root, _, files in os.walk(loc.workspace_dir):
        for fname in files:
            try:
                total += (Path(root) / fname).stat().st_size
            except OSError:
                pass
    return total
