#!/usr/bin/env python3
"""CWE-78 CVE dataset collection pipeline.

Collects 100 confirmed Python CVEs mapped to CWE-78 from GHSA, NVD, huntr,
and OSV.  Each sample includes the vulnerable commit, patch commit, and
patch diff.

Phases:
    1. Clone & filter GHSA advisory-database for CWE-78 + pip
    2. Enrich with NVD CVSS scores
    3. Resolve vulnerable / patch commits
    4. Extract sink APIs, vulnerable lines, LOC
    5. Quality filtering & deduplication
    6. Stratified sampling for diversity

Usage:
    python scripts/collect_cwe78_dataset.py [--phase N] [--config conf/dataset.yaml]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import re
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import requests
import yaml
from dotenv import load_dotenv
from tqdm import tqdm

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("collect_cwe78")

ROOT = Path(__file__).resolve().parent.parent
DATA_RAW = ROOT / "data" / "raw"
ADVISORY_DB_DIR = ROOT / "data" / "advisory-database"
BENCHMARK_DIR = ROOT / "benchmark" / "python" / "cwe78_cves"
DIFFS_DIR = BENCHMARK_DIR / "diffs"
SINKS_YAML = ROOT / "auditzoo" / "agents" / "cwe78" / "corpus" / "sinks.yaml"

SEED = 235711

SINK_PATTERNS: list[str] = []


def _load_sink_patterns() -> list[str]:
    """Load sink API names from the corpus YAML."""
    global SINK_PATTERNS
    if SINK_PATTERNS:
        return SINK_PATTERNS
    if SINKS_YAML.exists():
        with open(SINKS_YAML) as f:
            data = yaml.safe_load(f)
        for entry in data.get("sinks", []):
            api = entry.get("api", "")
            if api:
                SINK_PATTERNS.append(api)
            func = entry.get("function", "")
            if func and func not in SINK_PATTERNS:
                SINK_PATTERNS.append(func)
    if not SINK_PATTERNS:
        SINK_PATTERNS.extend([
            "os.system", "os.popen", "subprocess.run", "subprocess.call",
            "subprocess.Popen", "subprocess.check_output",
            "subprocess.check_call", "commands.getoutput",
            "commands.getstatusoutput", "os.execvp", "os.execvpe",
        ])
    return SINK_PATTERNS


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class CVERecord:
    cve_id: str = ""
    ghsa_id: str = ""
    package: str = ""
    repo_url: str = ""
    vulnerable_commit: str = ""
    patch_commit: str = ""
    patch_diff_path: str = ""
    vulnerable_file: str = ""
    vulnerable_lines: list[int] = field(default_factory=list)
    sink_api: str = ""
    loc: int = 0
    cvss_score: float = 0.0
    cvss_severity: str = ""
    source_db: str = "ghsa"
    taint_hops: int | None = None
    notes: str = ""
    manual_review_status: str = "pending"
    _references: list[str] = field(default_factory=list, repr=False)
    _fixed_version: str = field(default="", repr=False)
    _introduced_version: str = field(default="", repr=False)
    _rejection_reason: str = field(default="", repr=False)

    def to_public_dict(self) -> dict[str, Any]:
        """Return the dict for metadata.json (no private fields)."""
        d = asdict(self)
        return {k: v for k, v in d.items() if not k.startswith("_")}


def _write_jsonl(records: list[CVERecord], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        for r in records:
            f.write(json.dumps(asdict(r), default=str) + "\n")
    logger.info("Wrote %d records to %s", len(records), path)


def _read_jsonl(path: Path) -> list[CVERecord]:
    records: list[CVERecord] = []
    if not path.exists():
        return records
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            private = {k: d.pop(k) for k in list(d) if k.startswith("_")}
            rec = CVERecord(**{k: v for k, v in d.items()
                               if k in CVERecord.__dataclass_fields__})
            for k, v in private.items():
                if hasattr(rec, k):
                    setattr(rec, k, v)
            records.append(rec)
    return records


# ===================================================================
# Phase 1: Clone and filter GHSA Advisory Database
# ===================================================================

def phase1_collect_ghsa(config: dict[str, Any]) -> list[CVERecord]:
    """Clone github/advisory-database and filter for CWE-78 + pip."""
    logger.info("=== Phase 1: Collecting from GHSA advisory-database ===")

    if not ADVISORY_DB_DIR.exists():
        logger.info("Cloning github/advisory-database (shallow)...")
        subprocess.run(
            ["git", "clone", "--depth", "1",
             "https://github.com/github/advisory-database.git",
             str(ADVISORY_DB_DIR)],
            check=True,
        )
    else:
        logger.info("Advisory database already cloned at %s", ADVISORY_DB_DIR)

    reviewed_dir = ADVISORY_DB_DIR / "advisories" / "github-reviewed"
    unreviewed_dir = ADVISORY_DB_DIR / "advisories" / "unreviewed"

    json_files: list[Path] = []
    if reviewed_dir.exists():
        json_files.extend(reviewed_dir.rglob("*.json"))
    if unreviewed_dir.exists():
        json_files.extend(unreviewed_dir.rglob("*.json"))
    if not json_files:
        logger.error("No advisory JSON files found in %s", ADVISORY_DB_DIR)
        return []

    logger.info("Scanning %d advisory JSON files (reviewed + unreviewed)...",
                len(json_files))

    records: list[CVERecord] = []
    seen_cves: set[str] = set()

    for jf in tqdm(json_files, desc="Filtering GHSA", unit="file"):
        try:
            with open(jf) as f:
                adv = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue

        cwe_ids = adv.get("database_specific", {}).get("cwe_ids", [])
        if "CWE-78" not in cwe_ids:
            continue

        affected_list = adv.get("affected", [])
        is_pip = any(
            a.get("package", {}).get("ecosystem", "").lower() in ("pip", "pypi")
            for a in affected_list
        )
        if not is_pip:
            # For unreviewed entries without ecosystem, check text for Python signals
            full_text = json.dumps(adv).lower()
            python_keywords = [
                "python", "pypi", "pip install", ".py",
                "django", "flask", "fastapi", "ansible", "salt",
                "celery", "scrapy", "paramiko",
            ]
            has_python_signal = any(kw in full_text for kw in python_keywords)
            refs = [r.get("url", "") for r in adv.get("references", [])]
            has_commit_ref = any(
                re.search(r"github\.com/[^/]+/[^/]+/(commit|pull)/", r)
                for r in refs
            )
            if not (has_python_signal and has_commit_ref):
                continue

        ghsa_id = adv.get("id", "")
        aliases = adv.get("aliases", [])
        cve_ids = [a for a in aliases if a.startswith("CVE-")]
        cve_id = cve_ids[0] if cve_ids else ghsa_id

        if cve_id in seen_cves:
            continue
        seen_cves.add(cve_id)

        pip_affected = [
            a for a in affected_list
            if a.get("package", {}).get("ecosystem", "").lower()
            in ("pip", "pypi")
        ]
        # Fall back to any affected entry if no pip-specific ones
        search_affected = pip_affected or affected_list
        package = ""
        fixed_version = ""
        introduced_version = ""
        for a in search_affected:
            package = package or a.get("package", {}).get("name", "")
            for rng in a.get("ranges", []):
                for ev in rng.get("events", []):
                    if "fixed" in ev:
                        fixed_version = ev["fixed"]
                    if "introduced" in ev:
                        introduced_version = ev["introduced"]
            if package:
                break

        references = [
            ref.get("url", "")
            for ref in adv.get("references", [])
            if ref.get("url", "")
        ]

        repo_url = _extract_repo_url(references)
        severity = adv.get("database_specific", {}).get("severity", "")

        source_db = "ghsa" if is_pip else "ghsa_unreviewed"

        rec = CVERecord(
            cve_id=cve_id,
            ghsa_id=ghsa_id,
            package=package,
            repo_url=repo_url,
            cvss_severity=severity.lower() if severity else "",
            source_db=source_db,
            notes=adv.get("summary", "")[:200],
            _references=references,
            _fixed_version=fixed_version,
            _introduced_version=introduced_version,
        )
        records.append(rec)

    logger.info("Phase 1 complete: %d CWE-78 pip advisories found", len(records))
    outpath = DATA_RAW / "ghsa_cwe78_pip.jsonl"
    _write_jsonl(records, outpath)
    return records


def _extract_repo_url(references: list[str]) -> str:
    """Extract a GitHub repo URL from a list of reference URLs."""
    for url in references:
        m = re.match(r"https?://github\.com/([^/]+/[^/]+)", url)
        if m:
            return f"https://github.com/{m.group(1)}"
    return ""


# ===================================================================
# Phase 2: Enrich with NVD CVSS scores
# ===================================================================

def phase2_enrich_nvd(records: list[CVERecord],
                      config: dict[str, Any]) -> list[CVERecord]:
    """Query NVD API 2.0 for CVSS scores and CWE confirmation."""
    logger.info("=== Phase 2: Enriching with NVD CVSS scores ===")

    api_key = os.getenv("NVD_API_KEY", "")
    delay = config.get("nvd_delay_s")
    if delay is None:
        delay = 0.7 if api_key else 6.5

    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key
        logger.info("Using NVD API key (higher rate limit)")
    else:
        logger.warning("No NVD_API_KEY set; using unauthenticated rate limit "
                       "(5 req/30s). Set NVD_API_KEY in .env for 10x speedup.")

    cve_records = [r for r in records if r.cve_id.startswith("CVE-")]
    logger.info("Querying NVD for %d CVEs...", len(cve_records))

    for rec in tqdm(cve_records, desc="NVD enrichment", unit="cve"):
        try:
            resp = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": rec.cve_id},
                headers=headers,
                timeout=30,
            )
            if resp.status_code == 403:
                logger.warning("NVD rate limited; sleeping 30s")
                time.sleep(30)
                resp = requests.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={"cveId": rec.cve_id},
                    headers=headers,
                    timeout=30,
                )
            if resp.status_code != 200:
                logger.debug("NVD returned %d for %s", resp.status_code,
                             rec.cve_id)
                time.sleep(delay)
                continue

            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                time.sleep(delay)
                continue

            cve_item = vulns[0].get("cve", {})

            metrics_v31 = cve_item.get("metrics", {}).get(
                "cvssMetricV31", [])
            if metrics_v31:
                cvss_data = metrics_v31[0].get("cvssData", {})
                rec.cvss_score = cvss_data.get("baseScore", 0.0)
                sev = cvss_data.get("baseSeverity", "")
                if sev:
                    rec.cvss_severity = sev.lower()
            elif not rec.cvss_severity:
                metrics_v30 = cve_item.get("metrics", {}).get(
                    "cvssMetricV30", [])
                if metrics_v30:
                    cvss_data = metrics_v30[0].get("cvssData", {})
                    rec.cvss_score = cvss_data.get("baseScore", 0.0)
                    rec.cvss_severity = cvss_data.get(
                        "baseSeverity", "").lower()

            weaknesses = cve_item.get("weaknesses", [])
            nvd_cwes = set()
            for w in weaknesses:
                for desc in w.get("description", []):
                    val = desc.get("value", "")
                    if val.startswith("CWE-"):
                        nvd_cwes.add(val)
            if nvd_cwes and "CWE-78" not in nvd_cwes:
                rec.notes += " [NVD CWE mismatch: " + ",".join(nvd_cwes) + "]"

        except Exception:
            logger.debug("NVD query failed for %s", rec.cve_id, exc_info=True)

        time.sleep(delay)

    outpath = DATA_RAW / "nvd_enriched.jsonl"
    _write_jsonl(records, outpath)
    logger.info("Phase 2 complete: NVD enrichment done")
    return records


# ===================================================================
# Phase 3: Resolve vulnerable and patch commits
# ===================================================================

_COMMIT_RE = re.compile(
    r"https?://github\.com/([^/]+/[^/]+)/commit/([0-9a-fA-F]{7,40})"
)
_PR_RE = re.compile(
    r"https?://github\.com/([^/]+/[^/]+)/pull/(\d+)"
)


def phase3_resolve_commits(records: list[CVERecord],
                           config: dict[str, Any]) -> list[CVERecord]:
    """Resolve patch and vulnerable commit SHAs for each CVE."""
    logger.info("=== Phase 3: Resolving commits ===")

    gh_token = os.getenv("GITHUB_TOKEN", "")
    gh_headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if gh_token:
        gh_headers["Authorization"] = f"Bearer {gh_token}"
        logger.info("Using GITHUB_TOKEN for API access")
    else:
        logger.warning("No GITHUB_TOKEN set; GitHub API calls will be "
                       "rate-limited to 60/hour.")

    resolved = 0
    for rec in tqdm(records, desc="Resolving commits", unit="cve"):
        if rec.patch_commit:
            resolved += 1
            continue
        if not rec.repo_url:
            rec._rejection_reason = "no_repo_url"
            continue

        patch_sha = _resolve_commit_from_references(
            rec, gh_headers, config)

        if patch_sha:
            rec.patch_commit = patch_sha
            parent_sha = _get_parent_commit(
                rec.repo_url.replace("https://github.com/", ""),
                patch_sha, gh_headers,
            )
            rec.vulnerable_commit = parent_sha or f"{patch_sha}~1"
            resolved += 1
        else:
            rec._rejection_reason = "no_commit_resolved"

    logger.info("Phase 3 complete: resolved %d / %d commits",
                resolved, len(records))
    outpath = DATA_RAW / "commits_resolved.jsonl"
    _write_jsonl(records, outpath)
    return records


def _resolve_commit_from_references(
    rec: CVERecord,
    gh_headers: dict[str, str],
    config: dict[str, Any],
) -> str:
    """Try multiple strategies to find the patch commit SHA."""

    # Strategy 1: direct commit link in references
    for url in rec._references:
        m = _COMMIT_RE.search(url)
        if m:
            return m.group(2)

    # Strategy 2: PR link -> merge commit
    for url in rec._references:
        m = _PR_RE.search(url)
        if m:
            repo_slug = m.group(1)
            pr_num = m.group(2)
            sha = _get_pr_merge_commit(repo_slug, pr_num, gh_headers)
            if sha:
                return sha

    # Strategy 3: tag matching via GitHub API
    if rec._fixed_version and rec.repo_url:
        repo_slug = rec.repo_url.replace("https://github.com/", "")
        sha = _get_tag_commit(repo_slug, rec._fixed_version, gh_headers)
        if sha:
            return sha

    # Strategy 4: release tag link in references
    release_re = re.compile(
        r"https?://github\.com/([^/]+/[^/]+)/releases/tag/([^\s/]+)"
    )
    for url in rec._references:
        m = release_re.search(url)
        if m:
            repo_slug = m.group(1)
            tag_name = m.group(2)
            sha = _get_tag_commit(repo_slug, tag_name, gh_headers)
            if sha:
                return sha

    return ""


def _get_pr_merge_commit(repo_slug: str, pr_num: str,
                         headers: dict[str, str]) -> str:
    """Fetch the merge commit SHA for a PR."""
    try:
        resp = requests.get(
            f"https://api.github.com/repos/{repo_slug}/pulls/{pr_num}",
            headers=headers,
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            sha = data.get("merge_commit_sha", "")
            if sha:
                return sha
        elif resp.status_code == 403:
            logger.warning("GitHub rate limited; sleeping 60s")
            time.sleep(60)
    except Exception:
        logger.debug("PR fetch failed for %s#%s", repo_slug, pr_num,
                     exc_info=True)
    return ""


def _get_tag_commit(repo_slug: str, version: str,
                    headers: dict[str, str]) -> str:
    """Find a git tag matching the fixed version and return its commit SHA."""
    try:
        resp = requests.get(
            f"https://api.github.com/repos/{repo_slug}/git/matching-refs"
            f"/tags/{version}",
            headers=headers,
            timeout=15,
        )
        if resp.status_code == 200:
            refs = resp.json()
            if refs:
                obj = refs[0].get("object", {})
                sha = obj.get("sha", "")
                if obj.get("type") == "tag":
                    sha = _dereference_tag(repo_slug, sha, headers)
                return sha

        tag_variants = [f"v{version}", version]
        for tag_name in tag_variants:
            resp = requests.get(
                f"https://api.github.com/repos/{repo_slug}/git/ref"
                f"/tags/{tag_name}",
                headers=headers,
                timeout=15,
            )
            if resp.status_code == 200:
                obj = resp.json().get("object", {})
                sha = obj.get("sha", "")
                if obj.get("type") == "tag":
                    sha = _dereference_tag(repo_slug, sha, headers)
                if sha:
                    return sha
    except Exception:
        logger.debug("Tag lookup failed for %s@%s", repo_slug, version,
                     exc_info=True)
    return ""


def _dereference_tag(repo_slug: str, tag_sha: str,
                     headers: dict[str, str]) -> str:
    """Dereference an annotated tag to its commit SHA."""
    try:
        resp = requests.get(
            f"https://api.github.com/repos/{repo_slug}/git/tags/{tag_sha}",
            headers=headers,
            timeout=15,
        )
        if resp.status_code == 200:
            return resp.json().get("object", {}).get("sha", tag_sha)
    except Exception:
        pass
    return tag_sha


def _get_parent_commit(repo_slug: str, commit_sha: str,
                       headers: dict[str, str]) -> str:
    """Resolve the parent (vulnerable) commit SHA via GitHub API."""
    try:
        resp = requests.get(
            f"https://api.github.com/repos/{repo_slug}/commits/{commit_sha}",
            headers=headers,
            timeout=15,
        )
        if resp.status_code == 200:
            parents = resp.json().get("parents", [])
            if parents:
                return parents[0].get("sha", "")
    except Exception:
        logger.debug("Parent commit lookup failed for %s@%s",
                     repo_slug, commit_sha, exc_info=True)
    return ""


# ===================================================================
# Phase 4: Identify sink APIs and vulnerable lines
# ===================================================================

def phase4_extract_sinks_and_loc(
    records: list[CVERecord],
    config: dict[str, Any],
) -> list[CVERecord]:
    """For each resolved CVE, fetch the diff, identify sinks, count LOC."""
    logger.info("=== Phase 4: Extracting sinks, vulnerable lines, LOC ===")
    sinks = _load_sink_patterns()

    gh_token = os.getenv("GITHUB_TOKEN", "")
    gh_headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if gh_token:
        gh_headers["Authorization"] = f"Bearer {gh_token}"

    for rec in tqdm(records, desc="Extracting sinks", unit="cve"):
        if not rec.patch_commit or rec._rejection_reason:
            continue
        if not rec.repo_url:
            continue

        repo_slug = rec.repo_url.replace("https://github.com/", "")
        diff_text = _fetch_commit_diff(repo_slug, rec.patch_commit,
                                       gh_headers)
        if not diff_text:
            rec._rejection_reason = "diff_fetch_failed"
            continue

        diff_path = DIFFS_DIR / f"{rec.cve_id.replace('/', '_')}.diff"
        diff_path.parent.mkdir(parents=True, exist_ok=True)
        diff_path.write_text(diff_text, encoding="utf-8")
        rec.patch_diff_path = str(
            diff_path.relative_to(ROOT / "benchmark" / "python" / "cwe78_cves")
        )

        vuln_file, vuln_lines = _parse_diff_for_vuln_lines(diff_text)
        rec.vulnerable_file = vuln_file
        rec.vulnerable_lines = vuln_lines

        matched_sink = _match_sink(diff_text, sinks)
        rec.sink_api = matched_sink

        rec.loc = _estimate_loc_from_diff(diff_text)

    outpath = DATA_RAW / "sinks_extracted.jsonl"
    _write_jsonl(records, outpath)
    logger.info("Phase 4 complete")
    return records


def _fetch_commit_diff(repo_slug: str, commit_sha: str,
                       headers: dict[str, str]) -> str:
    """Fetch the diff for a commit via the GitHub API."""
    real_sha = commit_sha.rstrip("~1").rstrip("^")
    try:
        diff_headers = dict(headers)
        diff_headers["Accept"] = "application/vnd.github.diff"
        resp = requests.get(
            f"https://api.github.com/repos/{repo_slug}/commits/{real_sha}",
            headers=diff_headers,
            timeout=30,
        )
        if resp.status_code == 200:
            return resp.text
        elif resp.status_code == 403:
            logger.warning("GitHub rate limited fetching diff; sleeping 60s")
            time.sleep(60)
            resp = requests.get(
                f"https://api.github.com/repos/{repo_slug}/commits/{real_sha}",
                headers=diff_headers,
                timeout=30,
            )
            if resp.status_code == 200:
                return resp.text
    except Exception:
        logger.debug("Diff fetch failed for %s@%s", repo_slug, commit_sha,
                     exc_info=True)
    return ""


def _parse_diff_for_vuln_lines(diff_text: str) -> tuple[str, list[int]]:
    """Parse a unified diff to extract the first changed .py file and
    the line numbers of removed or changed (vulnerable) lines.

    For pure-addition patches (where the fix adds validation), the
    vulnerable lines are the context lines surrounding the addition.
    """
    current_file = ""
    best_file = ""
    best_lines: list[int] = []
    current_lines: list[int] = []
    current_touched = False
    old_line = 0

    def _commit_file():
        nonlocal best_file, best_lines
        if current_file and not best_file:
            if current_lines:
                best_file = current_file
                best_lines = list(current_lines)
            elif current_touched:
                best_file = current_file
                best_lines = [old_line] if old_line > 0 else []

    for line in diff_text.split("\n"):
        if line.startswith("--- a/"):
            _commit_file()
            path = line[6:]
            if path.endswith(".py"):
                current_file = path
                current_lines = []
                current_touched = False
            else:
                current_file = ""
                current_lines = []
                current_touched = False

        elif line.startswith("@@ ") and current_file:
            m = re.search(r"-(\d+)", line)
            if m:
                old_line = int(m.group(1))
            current_touched = True

        elif current_file:
            if line.startswith("-") and not line.startswith("---"):
                current_lines.append(old_line)
                old_line += 1
            elif line.startswith("+"):
                pass
            else:
                old_line += 1

    _commit_file()
    return best_file, best_lines


def _match_sink(diff_text: str, sinks: list[str]) -> str:
    """Match the diff text against known sink APIs."""
    removed_lines = []
    for line in diff_text.split("\n"):
        if line.startswith("-") and not line.startswith("---"):
            removed_lines.append(line)

    full_text = "\n".join(removed_lines)

    for sink in sinks:
        if sink in full_text:
            return sink

    return "unknown"


def _estimate_loc_from_diff(diff_text: str) -> int:
    """Estimate LOC of the vulnerable file from the diff hunk headers.

    Uses the largest old-file line range as a lower bound.
    """
    max_line = 0
    for line in diff_text.split("\n"):
        if line.startswith("@@ "):
            m = re.search(r"-(\d+),?(\d*)", line)
            if m:
                start = int(m.group(1))
                count = int(m.group(2)) if m.group(2) else 1
                end = start + count
                if end > max_line:
                    max_line = end
    return max_line


# ===================================================================
# Phase 5: Quality filtering and deduplication
# ===================================================================

def phase5_filter_and_dedup(
    records: list[CVERecord],
    config: dict[str, Any],
) -> tuple[list[CVERecord], list[CVERecord]]:
    """Apply inclusion criteria and deduplicate."""
    logger.info("=== Phase 5: Filtering and deduplication ===")

    accepted: list[CVERecord] = []
    rejected: list[CVERecord] = []

    seen_cve_ids: set[str] = set()
    seen_locations: set[tuple[str, str, str]] = set()

    for rec in records:
        reason = ""

        if rec._rejection_reason:
            reason = rec._rejection_reason
        elif not rec.cve_id:
            reason = "no_cve_id"
        elif rec.cve_id in seen_cve_ids:
            reason = "duplicate_cve_id"
        elif not rec.patch_commit:
            reason = "no_patch_commit"
        elif not rec.vulnerable_commit:
            reason = "no_vulnerable_commit"

        if not reason:
            loc_key = (rec.repo_url, rec.vulnerable_file,
                       str(sorted(rec.vulnerable_lines[:5])))
            if loc_key in seen_locations:
                reason = "duplicate_location"

        if reason:
            rec._rejection_reason = reason
            rejected.append(rec)
        else:
            seen_cve_ids.add(rec.cve_id)
            loc_key = (rec.repo_url, rec.vulnerable_file,
                       str(sorted(rec.vulnerable_lines[:5])))
            seen_locations.add(loc_key)
            accepted.append(rec)

    logger.info("Phase 5 complete: %d accepted, %d rejected",
                len(accepted), len(rejected))

    _write_jsonl(rejected, DATA_RAW / "rejected.jsonl")
    _write_jsonl(accepted, DATA_RAW / "filtered_accepted.jsonl")
    return accepted, rejected


# ===================================================================
# Phase 6: Stratified sampling for diversity
# ===================================================================

def phase6_stratified_sample(
    records: list[CVERecord],
    config: dict[str, Any],
) -> list[CVERecord]:
    """Select up to target_n diverse samples."""
    logger.info("=== Phase 6: Stratified sampling ===")

    target_n = config.get("target_n", 100)
    rng = random.Random(SEED)

    if len(records) <= target_n:
        logger.info("Only %d candidates available (target %d); "
                     "keeping all.", len(records), target_n)
        return records

    loc_bins = {
        "small": (0, 100),
        "medium": (100, 500),
        "large": (500, 2000),
        "very_large": (2000, float("inf")),
    }
    min_per_loc_bin = config.get("min_per_loc_bin", 10)

    by_loc_bin: dict[str, list[CVERecord]] = defaultdict(list)
    for rec in records:
        for bname, (lo, hi) in loc_bins.items():
            if lo <= rec.loc < hi:
                by_loc_bin[bname].append(rec)
                break

    selected: list[CVERecord] = []
    selected_ids: set[str] = set()

    for bname in loc_bins:
        pool = [r for r in by_loc_bin[bname]
                if r.cve_id not in selected_ids]
        rng.shuffle(pool)
        take = min(min_per_loc_bin, len(pool))
        for rec in pool[:take]:
            selected.append(rec)
            selected_ids.add(rec.cve_id)

    remaining = [r for r in records if r.cve_id not in selected_ids]
    rng.shuffle(remaining)

    sink_counts: dict[str, int] = defaultdict(int)
    for rec in selected:
        sink_counts[rec.sink_api] += 1

    severity_counts: dict[str, int] = defaultdict(int)
    for rec in selected:
        severity_counts[rec.cvss_severity] += 1

    min_per_sink = config.get("min_per_sink", 3)
    min_per_severity = config.get("min_per_severity", 3)

    for rec in list(remaining):
        if len(selected) >= target_n:
            break
        sink_need = sink_counts.get(rec.sink_api, 0) < min_per_sink
        sev_need = severity_counts.get(rec.cvss_severity, 0) < min_per_severity
        if sink_need or sev_need:
            selected.append(rec)
            selected_ids.add(rec.cve_id)
            remaining.remove(rec)
            sink_counts[rec.sink_api] += 1
            severity_counts[rec.cvss_severity] += 1

    while len(selected) < target_n and remaining:
        rec = remaining.pop(0)
        selected.append(rec)
        selected_ids.add(rec.cve_id)

    logger.info("Phase 6 complete: selected %d samples", len(selected))

    _log_diversity_stats(selected, loc_bins)
    return selected


def _log_diversity_stats(
    records: list[CVERecord],
    loc_bins: dict[str, tuple[float, float]],
) -> None:
    """Log summary statistics about the selected dataset."""
    logger.info("--- Dataset diversity summary ---")

    loc_dist: dict[str, int] = defaultdict(int)
    for rec in records:
        for bname, (lo, hi) in loc_bins.items():
            if lo <= rec.loc < hi:
                loc_dist[bname] += 1
                break
    logger.info("LOC distribution: %s", dict(loc_dist))

    sink_dist: dict[str, int] = defaultdict(int)
    for rec in records:
        sink_dist[rec.sink_api] += 1
    logger.info("Sink distribution: %s", dict(sink_dist))

    sev_dist: dict[str, int] = defaultdict(int)
    for rec in records:
        sev_dist[rec.cvss_severity or "unknown"] += 1
    logger.info("Severity distribution: %s", dict(sev_dist))


# ===================================================================
# Output
# ===================================================================

def write_final_dataset(records: list[CVERecord]) -> None:
    """Write the final metadata.json."""
    BENCHMARK_DIR.mkdir(parents=True, exist_ok=True)
    out = [rec.to_public_dict() for rec in records]
    outpath = BENCHMARK_DIR / "metadata.json"
    with open(outpath, "w") as f:
        json.dump(out, f, indent=2, default=str)
    logger.info("Final dataset written to %s (%d records)", outpath, len(out))


# ===================================================================
# Config loading
# ===================================================================

def load_config(config_path: str | None) -> dict[str, Any]:
    """Load dataset collection config from YAML."""
    defaults: dict[str, Any] = {
        "target_n": 100,
        "nvd_delay_s": None,  # auto-detect based on API key
        "min_per_loc_bin": 10,
        "min_per_sink": 3,
        "min_per_severity": 3,
        "seed": SEED,
    }
    if config_path and Path(config_path).exists():
        with open(config_path) as f:
            data = yaml.safe_load(f) or {}
        dataset_cfg = data.get("dataset", data)
        defaults.update(dataset_cfg)
    return defaults


# ===================================================================
# Main
# ===================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect CWE-78 CVE dataset for comparative study")
    parser.add_argument("--phase", type=int, default=0,
                        help="Run a single phase (1-6), or 0 for all")
    parser.add_argument("--config", type=str, default="conf/dataset.yaml",
                        help="Path to dataset config YAML")
    parser.add_argument("--resume", action="store_true",
                        help="Resume from last completed phase")
    args = parser.parse_args()

    config = load_config(args.config)
    global SEED
    SEED = config.get("seed", SEED)

    DATA_RAW.mkdir(parents=True, exist_ok=True)
    DIFFS_DIR.mkdir(parents=True, exist_ok=True)

    if args.phase == 0 or args.phase == 1:
        if args.resume and (DATA_RAW / "ghsa_cwe78_pip.jsonl").exists():
            logger.info("Resuming: loading Phase 1 output")
            records = _read_jsonl(DATA_RAW / "ghsa_cwe78_pip.jsonl")
        else:
            records = phase1_collect_ghsa(config)

        if args.phase == 1:
            return

    elif args.phase > 1:
        latest = _find_latest_checkpoint()
        if latest:
            logger.info("Loading checkpoint: %s", latest)
            records = _read_jsonl(latest)
        else:
            logger.error("No checkpoint found. Run phase 1 first.")
            sys.exit(1)

    if args.phase == 0 or args.phase == 2:
        if args.resume and (DATA_RAW / "nvd_enriched.jsonl").exists():
            logger.info("Resuming: loading Phase 2 output")
            records = _read_jsonl(DATA_RAW / "nvd_enriched.jsonl")
        else:
            records = phase2_enrich_nvd(records, config)
        if args.phase == 2:
            return

    if args.phase == 0 or args.phase == 3:
        if args.resume and (DATA_RAW / "commits_resolved.jsonl").exists():
            logger.info("Resuming: loading Phase 3 output")
            records = _read_jsonl(DATA_RAW / "commits_resolved.jsonl")
        else:
            records = phase3_resolve_commits(records, config)
        if args.phase == 3:
            return

    if args.phase == 0 or args.phase == 4:
        records = phase4_extract_sinks_and_loc(records, config)
        if args.phase == 4:
            return

    if args.phase == 0 or args.phase == 5:
        records, rejected = phase5_filter_and_dedup(records, config)
        if args.phase == 5:
            return

    if args.phase == 0 or args.phase == 6:
        records = phase6_stratified_sample(records, config)

    write_final_dataset(records)

    logger.info("=== Pipeline complete ===")
    logger.info("Total samples: %d", len(records))
    logger.info("Dataset at: %s", BENCHMARK_DIR / "metadata.json")


def _find_latest_checkpoint() -> Path | None:
    """Find the most recent checkpoint JSONL file."""
    candidates = [
        DATA_RAW / "filtered_accepted.jsonl",
        DATA_RAW / "sinks_extracted.jsonl",
        DATA_RAW / "commits_resolved.jsonl",
        DATA_RAW / "nvd_enriched.jsonl",
        DATA_RAW / "ghsa_cwe78_pip.jsonl",
    ]
    for p in candidates:
        if p.exists():
            return p
    return None


if __name__ == "__main__":
    main()
