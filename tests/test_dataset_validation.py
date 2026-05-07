"""Tests for the CWE-78 dataset validation script.

The validator gained a duplicate-vulnerable-location check during the v1.2
Joern timeout refresh (see ``benchmark/python/cwe78_cves/DATASET.md``). These
tests pin down its behavior so future dataset edits cannot silently introduce
two CVE records that share the same ``(repo_url, vulnerable_file,
sorted(vulnerable_lines[:5]))`` key.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_VALIDATOR_PATH = (
    _REPO_ROOT / "scripts" / "dataset_collection" / "validate_dataset.py"
)


@pytest.fixture(scope="module")
def validator_module():
    spec = importlib.util.spec_from_file_location(
        "validate_dataset_under_test", _VALIDATOR_PATH
    )
    assert spec and spec.loader, f"Failed to load {_VALIDATOR_PATH}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _record(
    cve_id: str,
    *,
    repo_url: str = "https://github.com/example/example",
    vulnerable_file: str = "src/exec.py",
    vulnerable_lines: list[int] | None = None,
    diff_path: str = "diffs/dummy.diff",
) -> dict:
    return {
        "cve_id": cve_id,
        "ghsa_id": "",
        "package": "example",
        "repo_url": repo_url,
        "vulnerable_commit": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "patch_commit": "feedfacefeedfacefeedfacefeedfacefeedface",
        "patch_diff_path": diff_path,
        "vulnerable_file": vulnerable_file,
        "vulnerable_lines": vulnerable_lines if vulnerable_lines is not None else [10],
        "sink_api": "subprocess.run",
        "loc": 42,
        "cvss_score": 7.5,
        "cvss_severity": "high",
        "source_db": "osv",
        "taint_hops": None,
        "notes": "synthetic test record",
        "manual_review_status": "pending",
    }


def _write_dataset(tmp_path: Path, records: list[dict]) -> Path:
    bench_dir = tmp_path / "cwe78_cves"
    diffs_dir = bench_dir / "diffs"
    diffs_dir.mkdir(parents=True)
    for rec in records:
        diff = bench_dir / rec["patch_diff_path"]
        diff.parent.mkdir(parents=True, exist_ok=True)
        if not diff.exists():
            diff.write_text("--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+new\n")
    meta = bench_dir / "metadata.json"
    meta.write_text(json.dumps(records))
    return meta


def test_validator_passes_on_unique_locations(tmp_path, validator_module):
    records = [
        _record("CVE-2099-0001", vulnerable_lines=[10, 11]),
        _record(
            "CVE-2099-0002",
            vulnerable_file="src/other.py",
            vulnerable_lines=[20],
            diff_path="diffs/other.diff",
        ),
    ]
    meta_path = _write_dataset(tmp_path, records)
    assert validator_module.validate(meta_path) is True


def test_validator_warns_on_duplicate_location_by_default(
    tmp_path, validator_module, caplog
):
    """Duplicate locations are a *warning* by default so historical refreshes
    that don't introduce new collisions still pass validation."""
    rec_a = _record("CVE-2099-1001", vulnerable_lines=[10, 11, 12])
    rec_b = _record(
        "CVE-2099-1002",
        vulnerable_lines=[12, 11, 10],
        diff_path="diffs/dup.diff",
    )
    meta_path = _write_dataset(tmp_path, [rec_a, rec_b])

    with caplog.at_level("WARNING"):
        ok = validator_module.validate(meta_path)

    assert ok is True
    warn_text = "\n".join(rec.message for rec in caplog.records)
    assert "Duplicate vulnerable locations" in warn_text
    assert "CVE-2099-1002" in warn_text


def test_validator_strict_mode_rejects_duplicate_location(
    tmp_path, validator_module, caplog
):
    """`--strict` (the CI/refresh setting) promotes the duplicate-location
    finding to a hard error so dataset PRs cannot silently land collisions."""
    rec_a = _record("CVE-2099-1101", vulnerable_lines=[10, 11, 12])
    rec_b = _record(
        "CVE-2099-1102",
        vulnerable_lines=[12, 11, 10],
        diff_path="diffs/strict.diff",
    )
    meta_path = _write_dataset(tmp_path, [rec_a, rec_b])

    with caplog.at_level("ERROR"):
        ok = validator_module.validate(meta_path, strict=True)

    assert ok is False
    err_text = "\n".join(rec.message for rec in caplog.records)
    assert "Duplicate vulnerable locations" in err_text
    assert "CVE-2099-1102" in err_text


def test_validator_ignores_empty_location_keys(tmp_path, validator_module):
    """Records still pending vulnerable_file/lines extraction must not be
    flagged as duplicates of each other simply because the key collapses to
    empty strings — that would create false positives during early collection
    phases."""
    rec_a = _record("CVE-2099-2001", vulnerable_file="", vulnerable_lines=[])
    rec_b = _record(
        "CVE-2099-2002",
        vulnerable_file="",
        vulnerable_lines=[],
        diff_path="diffs/empty.diff",
    )
    meta_path = _write_dataset(tmp_path, [rec_a, rec_b])
    assert validator_module.validate(meta_path) is True
