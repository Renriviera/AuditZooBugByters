"""Unit tests for the CPG cache module.

Joern's CPG construction is the dominant per-CVE cost, so the cache key
must be deterministic, version-bounded, and never collide on close
inputs.  The tests below cover key derivation, cache-hit detection, and
graceful degradation when repo metadata is unavailable.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from auditzoo.agents.cwe78_study.cpg_cache import (
    CACHE_VERSION,
    cpg_cache_location,
    detect_repo_metadata,
    is_cache_hit,
    read_cache_metadata,
    write_cache_metadata,
)


def test_cpg_cache_location_is_deterministic(tmp_path: Path) -> None:
    a = cpg_cache_location(tmp_path, "https://x.example/repo", "abcd1234")
    b = cpg_cache_location(tmp_path, "https://x.example/repo", "abcd1234")
    assert a == b
    assert a.workspace_dir.parent == tmp_path
    assert a.project_name == f"cpg_{a.cache_key}"


def test_cpg_cache_location_distinguishes_close_inputs(tmp_path: Path) -> None:
    a = cpg_cache_location(tmp_path, "https://x.example/repo", "abcd1234")
    b = cpg_cache_location(tmp_path, "https://x.example/repo", "abcd1235")
    c = cpg_cache_location(tmp_path, "https://x.example/repo2", "abcd1234")
    d = cpg_cache_location(
        tmp_path, "https://x.example/repo", "abcd1234", language="java"
    )
    assert len({a.workspace_dir, b.workspace_dir, c.workspace_dir, d.workspace_dir}) == 4


def test_cpg_cache_version_changes_key(tmp_path: Path) -> None:
    a = cpg_cache_location(tmp_path, "u", "c", cache_version=CACHE_VERSION)
    b = cpg_cache_location(tmp_path, "u", "c", cache_version=CACHE_VERSION + 1)
    assert a.workspace_dir != b.workspace_dir


def test_is_cache_hit_false_until_project_dir_exists(tmp_path: Path) -> None:
    loc = cpg_cache_location(tmp_path, "u", "c")
    loc.workspace_dir.mkdir(parents=True, exist_ok=True)
    assert not is_cache_hit(loc)
    (loc.workspace_dir / loc.project_name).mkdir()
    assert is_cache_hit(loc)


def test_write_and_read_cache_metadata(tmp_path: Path) -> None:
    loc = cpg_cache_location(tmp_path, "u", "c")
    loc.workspace_dir.mkdir(parents=True, exist_ok=True)
    write_cache_metadata(loc, cve_id="CVE-2020-1234", note="smoke")
    md = read_cache_metadata(loc)
    assert md is not None
    assert md["cve_id"] == "CVE-2020-1234"
    assert md["repo_url"] == "u"
    assert md["commit"] == "c"
    assert md["cache_version"] == CACHE_VERSION


def test_detect_repo_metadata_on_real_git_checkout(tmp_path: Path) -> None:
    """The cache key generation should plumb cleanly to a real git repo."""
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"], cwd=repo, check=True
    )
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    subprocess.run(
        ["git", "remote", "add", "origin", "https://example.com/foo.git"],
        cwd=repo,
        check=True,
    )
    (repo / "x.txt").write_text("hello")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=repo, check=True)

    remote, commit = detect_repo_metadata(repo)
    assert remote == "https://example.com/foo.git"
    assert len(commit) == 40


def test_detect_repo_metadata_on_non_git_dir(tmp_path: Path) -> None:
    remote, commit = detect_repo_metadata(tmp_path)
    assert remote == ""
    assert commit == ""
