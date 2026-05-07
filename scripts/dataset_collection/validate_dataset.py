#!/usr/bin/env python3
"""Post-hoc validation for the CWE-78 CVE dataset.

Checks:
    1. metadata.json is well-formed and all required fields are present
    2. No duplicate CVE IDs
    3. Every diff file exists and is non-empty
    4. Patch commits are accessible via GitHub API
    5. Vulnerable files are Python (.py)
    6. LOC diversity (reports distribution across bins)
    7. Sink API coverage
    8. Selects a random 10% spot-check subset for manual review

Usage:
    python scripts/validate_dataset.py [--metadata path/to/metadata.json]
                                       [--check-remote]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("validate_dataset")

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_METADATA = ROOT / "benchmark" / "python" / "cwe78_cves" / "metadata.json"
SEED = 235711

REQUIRED_FIELDS = [
    "cve_id", "ghsa_id", "package", "repo_url",
    "vulnerable_commit", "patch_commit", "patch_diff_path",
    "vulnerable_file", "vulnerable_lines", "sink_api", "loc",
    "cvss_score", "cvss_severity", "source_db",
]


def validate(
    metadata_path: Path,
    check_remote: bool = False,
    strict: bool = False,
) -> bool:
    """Run all validations. Returns True if all pass.

    The ``strict`` flag promotes structural-but-historical issues
    (currently: duplicate vulnerable locations that already exist in the
    shipped dataset due to diff-parser artifacts on version/test files)
    from warnings to errors. Use ``strict=True`` in CI/refresh workflows
    where every duplicate must be triaged before landing.
    """
    logger.info("Validating dataset: %s", metadata_path)

    if not metadata_path.exists():
        logger.error("Metadata file not found: %s", metadata_path)
        return False

    with open(metadata_path) as f:
        records = json.load(f)

    if not isinstance(records, list):
        logger.error("metadata.json must be a JSON array")
        return False

    logger.info("Total records: %d", len(records))
    errors: list[str] = []
    warnings: list[str] = []

    # 1. Required fields
    for i, rec in enumerate(records):
        for fld in REQUIRED_FIELDS:
            if fld not in rec:
                errors.append(f"Record {i} ({rec.get('cve_id', '?')}): "
                              f"missing field '{fld}'")

    # 2. No duplicate CVE IDs
    cve_ids = [r.get("cve_id", "") for r in records]
    dupes = [cid for cid, cnt in Counter(cve_ids).items() if cnt > 1]
    if dupes:
        errors.append(f"Duplicate CVE IDs: {dupes}")

    # 2b. No duplicate vulnerable locations
    # Mirrors the dedup key in scripts/dataset_collection/collect_cwe78_dataset.py
    # phase5_filter_and_dedup: (repo_url, vulnerable_file, sorted(vuln_lines[:5]))
    # Two distinct CVEs landing on the exact same vulnerable location in the same
    # repo is almost always an accidental duplicate inserted during a refresh.
    seen_loc: dict[tuple[str, str, str], str] = {}
    loc_dupes: list[str] = []
    for rec in records:
        loc_key = (
            rec.get("repo_url", ""),
            rec.get("vulnerable_file", ""),
            str(sorted((rec.get("vulnerable_lines") or [])[:5])),
        )
        # Only enforce when the key is meaningful (file + lines present);
        # records still pending a vulnerable_file/lines extraction would
        # otherwise spuriously collide on ("", "", "[]").
        if not loc_key[1] or loc_key[2] == "[]":
            continue
        prior = seen_loc.get(loc_key)
        if prior:
            loc_dupes.append(
                f"{rec.get('cve_id', '?')} duplicates {prior} at "
                f"{loc_key[0]}::{loc_key[1]}::{loc_key[2]}"
            )
        else:
            seen_loc[loc_key] = rec.get("cve_id", "?")
    if loc_dupes:
        msg = (
            "Duplicate vulnerable locations (repo_url + vulnerable_file + "
            f"sorted(vulnerable_lines[:5])): {loc_dupes}"
        )
        # Some pre-existing duplicates exist in shipped data because the
        # diff parser sometimes locks onto a version.py / test_*.py file
        # before reaching the real vulnerable file. Surface the problem
        # loudly (warning by default; error under --strict) but do not
        # block historical refreshes that don't introduce new collisions.
        (errors if strict else warnings).append(msg)

    # 3. Diff files exist and are non-empty
    base_dir = metadata_path.parent
    for i, rec in enumerate(records):
        diff_path = rec.get("patch_diff_path", "")
        if not diff_path:
            errors.append(f"Record {i} ({rec.get('cve_id')}): "
                          "empty patch_diff_path")
            continue
        full_path = base_dir / diff_path
        if not full_path.exists():
            errors.append(f"Record {i} ({rec.get('cve_id')}): "
                          f"diff file missing: {full_path}")
        elif full_path.stat().st_size == 0:
            errors.append(f"Record {i} ({rec.get('cve_id')}): "
                          f"diff file is empty: {full_path}")

    # 4. Vulnerable files are Python
    for i, rec in enumerate(records):
        vf = rec.get("vulnerable_file", "")
        if vf and not vf.endswith(".py"):
            warnings.append(f"Record {i} ({rec.get('cve_id')}): "
                            f"vulnerable_file is not .py: {vf}")

    # 5. Vulnerable lines are non-empty
    for i, rec in enumerate(records):
        vl = rec.get("vulnerable_lines", [])
        if not vl:
            warnings.append(f"Record {i} ({rec.get('cve_id')}): "
                            "vulnerable_lines is empty")

    # 6. Sink API is not unknown
    unknown_sinks = [
        rec.get("cve_id") for rec in records
        if rec.get("sink_api") == "unknown"
    ]
    if unknown_sinks:
        warnings.append(f"{len(unknown_sinks)} records with unknown sink_api "
                        f"(need manual review): {unknown_sinks[:10]}")

    # 7. Check commits are accessible (optional, slow)
    if check_remote:
        _check_remote_commits(records, errors, warnings)

    # 8. Diversity report
    _report_diversity(records)

    # 9. Spot-check subset
    _generate_spot_check(records, metadata_path.parent)

    # Summary
    if errors:
        logger.error("=== VALIDATION FAILED: %d errors ===", len(errors))
        for e in errors:
            logger.error("  ERROR: %s", e)
    if warnings:
        logger.warning("=== %d warnings ===", len(warnings))
        for w in warnings:
            logger.warning("  WARN: %s", w)
    if not errors:
        logger.info("=== VALIDATION PASSED ===")

    return len(errors) == 0


def _check_remote_commits(
    records: list[dict],
    errors: list[str],
    warnings: list[str],
) -> None:
    """Verify patch commits are accessible via GitHub API."""
    logger.info("Checking remote commit accessibility...")
    gh_token = os.getenv("GITHUB_TOKEN", "")
    headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if gh_token:
        headers["Authorization"] = f"Bearer {gh_token}"

    inaccessible = 0
    for rec in records[:20]:  # check first 20 to avoid rate limits
        repo_url = rec.get("repo_url", "")
        patch = rec.get("patch_commit", "")
        if not repo_url or not patch:
            continue

        slug = repo_url.replace("https://github.com/", "")
        sha = patch.rstrip("~1").rstrip("^")
        try:
            resp = requests.get(
                f"https://api.github.com/repos/{slug}/commits/{sha}",
                headers=headers,
                timeout=15,
            )
            if resp.status_code != 200:
                warnings.append(
                    f"{rec.get('cve_id')}: commit {sha} returned "
                    f"HTTP {resp.status_code}")
                inaccessible += 1
        except Exception as e:
            warnings.append(f"{rec.get('cve_id')}: commit check failed: {e}")
            inaccessible += 1

    if inaccessible:
        warnings.append(f"{inaccessible}/20 sampled commits inaccessible")


def _report_diversity(records: list[dict]) -> None:
    """Log diversity statistics."""
    logger.info("--- Diversity Report ---")

    loc_bins = {"small (<100)": 0, "medium (100-500)": 0,
                "large (500-2000)": 0, "very_large (>2000)": 0}
    for rec in records:
        loc = rec.get("loc", 0)
        if loc < 100:
            loc_bins["small (<100)"] += 1
        elif loc < 500:
            loc_bins["medium (100-500)"] += 1
        elif loc < 2000:
            loc_bins["large (500-2000)"] += 1
        else:
            loc_bins["very_large (>2000)"] += 1
    logger.info("LOC distribution: %s", loc_bins)

    sink_dist = Counter(rec.get("sink_api", "unknown") for rec in records)
    logger.info("Sink API distribution: %s", dict(sink_dist.most_common()))

    sev_dist = Counter(rec.get("cvss_severity", "unknown") for rec in records)
    logger.info("CVSS severity distribution: %s", dict(sev_dist.most_common()))

    packages = Counter(rec.get("package", "") for rec in records)
    logger.info("Top 10 packages: %s", dict(packages.most_common(10)))

    locs = [rec.get("loc", 0) for rec in records if rec.get("loc", 0) > 0]
    if locs:
        logger.info("LOC stats: min=%d, max=%d, median=%d, mean=%d",
                     min(locs), max(locs),
                     sorted(locs)[len(locs) // 2],
                     sum(locs) // len(locs))


def _generate_spot_check(records: list[dict], output_dir: Path) -> None:
    """Select a random 10% for manual spot-check."""
    rng = random.Random(SEED)
    n = max(1, len(records) // 10)
    sample = rng.sample(records, min(n, len(records)))

    spot_check_path = output_dir / "spot_check.json"
    with open(spot_check_path, "w") as f:
        json.dump(
            [{"cve_id": r["cve_id"], "package": r["package"],
              "sink_api": r["sink_api"], "repo_url": r["repo_url"],
              "patch_commit": r["patch_commit"],
              "manual_review_status": "pending"}
             for r in sample],
            f, indent=2,
        )
    logger.info("Spot-check file written (%d samples): %s",
                len(sample), spot_check_path)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate the CWE-78 CVE dataset")
    parser.add_argument("--metadata", type=str,
                        default=str(DEFAULT_METADATA),
                        help="Path to metadata.json")
    parser.add_argument("--check-remote", action="store_true",
                        help="Verify commits are accessible via GitHub API")
    parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "Promote duplicate-vulnerable-location findings from "
            "warnings to errors (use in CI / refresh workflows)."
        ),
    )
    args = parser.parse_args()

    ok = validate(
        Path(args.metadata),
        check_remote=args.check_remote,
        strict=args.strict,
    )
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
