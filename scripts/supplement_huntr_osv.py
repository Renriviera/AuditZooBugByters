#!/usr/bin/env python3
"""Supplement CWE-78 dataset with entries from OSV.dev, huntr, and PYSEC.

Queries multiple sources for Python CWE-78 vulnerabilities not already in the
dataset, resolves commits, fetches diffs, and merges into metadata.json.

Sources:
    1. OSV.dev API  – aggregates GHSA, PYSEC, huntr, and more
    2. NVD keyword  – CWE-78 CVEs referencing huntr.com with Python signals
    3. Salvage      – retry commit resolution for previously-rejected entries

Usage:
    python scripts/supplement_huntr_osv.py [--dry-run] [--config conf/dataset.yaml]
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

import requests
import yaml
from dotenv import load_dotenv
from tqdm import tqdm

sys.path.insert(0, str(Path(__file__).resolve().parent))

from collect_cwe78_dataset import (
    CVERecord,
    BENCHMARK_DIR,
    DATA_RAW,
    DIFFS_DIR,
    ROOT,
    _extract_repo_url,
    _fetch_commit_diff,
    _get_parent_commit,
    _load_sink_patterns,
    _match_sink,
    _parse_diff_for_vuln_lines,
    _estimate_loc_from_diff,
    _resolve_commit_from_references,
    _write_jsonl,
    load_config,
)

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("supplement")


# ── helpers ─────────────────────────────────────────────────────────

def _load_existing_cve_ids() -> set[str]:
    """Load CVE IDs already in the final metadata.json."""
    meta_path = BENCHMARK_DIR / "metadata.json"
    if not meta_path.exists():
        return set()
    with open(meta_path) as f:
        return {r["cve_id"] for r in json.load(f)}


def _gh_headers() -> dict[str, str]:
    token = os.getenv("GITHUB_TOKEN", "")
    h: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


# ── Source 1: OSV.dev ───────────────────────────────────────────────

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"


def _osv_list_pypi_packages_with_cwe78() -> list[dict]:
    """Query OSV.dev for CWE-78 PyPI vulns using the package list
    extracted from our Phase 1 JSONL (avoids re-scanning 28K files).
    """
    logger.info("=== Source 1: OSV.dev — querying for CWE-78 PyPI vulns ===")

    packages: set[str] = set()

    # Extract packages from Phase 1 JSONL checkpoint
    ghsa_path = DATA_RAW / "ghsa_cwe78_pip.jsonl"
    if ghsa_path.exists():
        with open(ghsa_path) as f:
            for line in f:
                if line.strip():
                    d = json.loads(line)
                    pkg = d.get("package", "")
                    if pkg:
                        packages.add(pkg)

    # Curated list of Python packages known to have CWE-78 history
    packages.update([
        "salt", "ansible", "apache-airflow", "celery", "paramiko",
        "scrapy", "django", "flask", "PaddlePaddle", "mlflow",
        "ray", "vllm", "lollms", "pyload-ng", "Glances", "yt-dlp",
        "youtube-dl", "gerapy", "pgadmin4", "calibreweb", "crmsh",
        "mercurial", "pillow", "supervisor", "nltk", "rengine",
        "label-studio", "gradio", "langchain", "llama-index",
    ])

    logger.info("Querying OSV.dev for %d PyPI packages", len(packages))

    all_vulns: list[dict] = []
    for pkg in tqdm(sorted(packages), desc="OSV.dev queries", unit="pkg"):
        try:
            resp = requests.post(
                OSV_QUERY_URL,
                json={"package": {"ecosystem": "PyPI", "name": pkg}},
                timeout=30,
            )
            if resp.status_code != 200:
                continue
            vulns = resp.json().get("vulns", [])
            for v in vulns:
                cwes = v.get("database_specific", {}).get("cwe_ids", [])
                summary = v.get("summary", "") + " " + json.dumps(v.get("details", ""))
                is_cwe78 = "CWE-78" in cwes or "command injection" in summary.lower()
                if is_cwe78:
                    v["_source_package"] = pkg
                    all_vulns.append(v)
        except Exception:
            continue
        time.sleep(0.3)

    logger.info("OSV.dev returned %d CWE-78 vulns across %d packages",
                len(all_vulns), len(packages))
    return all_vulns


def _osv_to_records(vulns: list[dict], existing_ids: set[str]) -> list[CVERecord]:
    """Convert OSV vulnerability dicts to CVERecord objects."""
    records: list[CVERecord] = []
    seen: set[str] = set(existing_ids)

    for v in vulns:
        vuln_id = v.get("id", "")
        aliases = v.get("aliases", [])
        cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln_id)

        if cve_id in seen:
            continue
        seen.add(cve_id)

        ghsa_id = vuln_id if vuln_id.startswith("GHSA-") else ""
        if not ghsa_id:
            ghsa_id = next((a for a in aliases if a.startswith("GHSA-")), "")

        pkg_name = v.get("_source_package", "")
        references = [r.get("url", "") for r in v.get("references", []) if r.get("url")]
        repo_url = _extract_repo_url(references)

        fixed_version = ""
        for a in v.get("affected", []):
            for rng in a.get("ranges", []):
                if rng.get("type") == "GIT":
                    repo_url = repo_url or rng.get("repo", "")
                for ev in rng.get("events", []):
                    if "fixed" in ev:
                        fixed_version = ev["fixed"]

        severity = v.get("database_specific", {}).get("severity", "")
        summary = v.get("summary", "")

        # Check for huntr references
        huntr_ref = next((r for r in references if "huntr" in r.lower()), "")
        source = "osv"
        if huntr_ref:
            source = "huntr"

        rec = CVERecord(
            cve_id=cve_id,
            ghsa_id=ghsa_id,
            package=pkg_name,
            repo_url=repo_url.rstrip("/"),
            cvss_severity=severity.lower() if severity else "",
            source_db=source,
            notes=summary[:200],
            _references=references,
            _fixed_version=fixed_version,
        )
        records.append(rec)

    return records


# ── Source 2: NVD huntr keyword search ──────────────────────────────

def _nvd_huntr_python_cve78(existing_ids: set[str]) -> list[CVERecord]:
    """Search NVD for CWE-78 CVEs that reference huntr and are Python."""
    logger.info("=== Source 2: NVD — huntr-referenced Python CWE-78 CVEs ===")

    candidates_path = DATA_RAW / "huntr_nvd_candidates.json"
    if not candidates_path.exists():
        logger.info("No huntr NVD candidates file; skipping.")
        return []

    with open(candidates_path) as f:
        candidates = json.load(f)

    records: list[CVERecord] = []
    for c in candidates:
        cve_id = c["cve_id"]
        if cve_id in existing_ids:
            continue

        desc = c.get("desc", "").lower()
        python_kw = ["python", "django", "flask", "fastapi", "ansible",
                     "salt", "celery", "paramiko", "pypi", "rengine"]
        if not any(kw in desc for kw in python_kw):
            continue

        github_refs = c.get("github_refs", [])
        repo_url = ""
        for r in github_refs:
            m = re.match(r"https?://github\.com/([^/]+/[^/]+)", r)
            if m:
                repo_url = f"https://github.com/{m.group(1)}"
                break

        rec = CVERecord(
            cve_id=cve_id,
            repo_url=repo_url,
            source_db="huntr",
            notes=c.get("desc", "")[:200],
            _references=github_refs + [c.get("huntr_url", "")],
        )
        records.append(rec)

    logger.info("NVD huntr search: %d new candidates", len(records))
    return records


# ── Source 3: Salvage rejected entries ──────────────────────────────

def _salvage_rejected(existing_ids: set[str],
                      gh_headers: dict[str, str],
                      config: dict[str, Any]) -> list[CVERecord]:
    """Retry commit resolution for previously-rejected entries."""
    logger.info("=== Source 3: Salvaging rejected entries ===")

    rejected_path = DATA_RAW / "rejected.jsonl"
    if not rejected_path.exists():
        logger.info("No rejected.jsonl found; skipping salvage.")
        return []

    from collect_cwe78_dataset import _read_jsonl
    rejected = _read_jsonl(rejected_path)

    salvageable = [
        r for r in rejected
        if r.cve_id not in existing_ids
        and r._rejection_reason in ("no_commit_resolved", "no_patch_commit")
        and r.repo_url
    ]
    logger.info("Found %d salvageable entries to retry", len(salvageable))

    resolved: list[CVERecord] = []
    for rec in tqdm(salvageable, desc="Salvage commits", unit="cve"):
        rec._rejection_reason = ""

        sha = _resolve_commit_from_references(rec, gh_headers, config)
        if sha:
            rec.patch_commit = sha
            repo_slug = rec.repo_url.replace("https://github.com/", "")
            parent = _get_parent_commit(repo_slug, sha, gh_headers)
            rec.vulnerable_commit = parent or f"{sha}~1"
            resolved.append(rec)
        time.sleep(0.3)

    logger.info("Salvaged %d / %d entries", len(resolved), len(salvageable))
    return resolved


# ── Pipeline: resolve, enrich, filter, merge ────────────────────────

def resolve_and_enrich(records: list[CVERecord],
                       gh_headers: dict[str, str],
                       config: dict[str, Any]) -> list[CVERecord]:
    """Resolve commits, fetch diffs, extract sinks for new records."""
    sinks = _load_sink_patterns()
    good: list[CVERecord] = []

    for rec in tqdm(records, desc="Resolve + enrich", unit="cve"):
        if not rec.patch_commit:
            sha = _resolve_commit_from_references(rec, gh_headers, config)
            if not sha:
                continue
            rec.patch_commit = sha
            repo_slug = rec.repo_url.replace("https://github.com/", "")
            parent = _get_parent_commit(repo_slug, sha, gh_headers)
            rec.vulnerable_commit = parent or f"{sha}~1"

        if not rec.repo_url:
            continue

        repo_slug = rec.repo_url.replace("https://github.com/", "")
        if not rec.patch_diff_path:
            diff_text = _fetch_commit_diff(repo_slug, rec.patch_commit, gh_headers)
            if not diff_text:
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
            rec.sink_api = _match_sink(diff_text, sinks)
            rec.loc = _estimate_loc_from_diff(diff_text)

        # Enrich with NVD CVSS if missing
        if not rec.cvss_score and rec.cve_id.startswith("CVE-"):
            _enrich_single_nvd(rec)

        good.append(rec)
        time.sleep(0.3)

    return good


def _enrich_single_nvd(rec: CVERecord) -> None:
    """Fetch CVSS score for a single CVE from NVD."""
    api_key = os.getenv("NVD_API_KEY", "")
    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key
    try:
        resp = requests.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={rec.cve_id}",
            headers=headers,
            timeout=15,
        )
        if resp.status_code != 200:
            return
        vulns = resp.json().get("vulnerabilities", [])
        if not vulns:
            return
        metrics = vulns[0].get("cve", {}).get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                data = metrics[key][0].get("cvssData", {})
                rec.cvss_score = data.get("baseScore", 0.0)
                rec.cvss_severity = data.get("baseSeverity", "").lower()
                break
    except Exception:
        pass
    time.sleep(0.7)


def dedup_and_merge(new_records: list[CVERecord],
                    existing_ids: set[str]) -> list[CVERecord]:
    """Deduplicate new records against existing dataset and each other."""
    seen = set(existing_ids)
    accepted: list[CVERecord] = []

    for rec in new_records:
        if rec.cve_id in seen:
            continue
        if not rec.patch_commit or not rec.vulnerable_commit:
            continue
        seen.add(rec.cve_id)
        accepted.append(rec)

    logger.info("Dedup: %d new unique records after filtering", len(accepted))
    return accepted


def merge_into_dataset(new_records: list[CVERecord]) -> int:
    """Merge new records into the existing metadata.json."""
    meta_path = BENCHMARK_DIR / "metadata.json"
    existing: list[dict] = []
    if meta_path.exists():
        with open(meta_path) as f:
            existing = json.load(f)

    existing_ids = {r["cve_id"] for r in existing}
    added = 0
    for rec in new_records:
        if rec.cve_id not in existing_ids:
            existing.append(rec.to_public_dict())
            added += 1

    with open(meta_path, "w") as f:
        json.dump(existing, f, indent=2, default=str)

    logger.info("Merged %d new records → total %d in metadata.json",
                added, len(existing))
    return len(existing)


# ── Main ────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="conf/dataset.yaml")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show candidates but don't write to dataset")
    parser.add_argument("--target", type=int, default=100,
                        help="Target total dataset size")
    args = parser.parse_args()

    config = load_config(args.config)
    headers = _gh_headers()
    existing_ids = _load_existing_cve_ids()
    current_count = len(existing_ids)
    needed = max(0, args.target - current_count)

    logger.info("Current dataset: %d records, need %d more to reach %d",
                current_count, needed, args.target)

    if needed == 0:
        logger.info("Target already met. Nothing to do.")
        return

    DATA_RAW.mkdir(parents=True, exist_ok=True)
    DIFFS_DIR.mkdir(parents=True, exist_ok=True)

    all_new: list[CVERecord] = []

    # Source 1: OSV.dev
    osv_vulns = _osv_list_pypi_packages_with_cwe78()
    osv_records = _osv_to_records(osv_vulns, existing_ids)
    logger.info("OSV.dev candidates (after dedup): %d", len(osv_records))

    # Source 2: NVD huntr
    nvd_records = _nvd_huntr_python_cve78(existing_ids)

    # Source 3: Salvage rejected
    salvaged = _salvage_rejected(existing_ids, headers, config)

    combined = osv_records + nvd_records + salvaged
    logger.info("Total raw candidates from all sources: %d", len(combined))

    # Resolve commits, fetch diffs, enrich
    enriched = resolve_and_enrich(combined, headers, config)
    logger.info("Successfully resolved + enriched: %d", len(enriched))

    # Deduplicate
    final_new = dedup_and_merge(enriched, existing_ids)

    if not final_new:
        logger.info("No new records to add.")
        return

    # Save supplement checkpoint
    _write_jsonl(final_new, DATA_RAW / "supplement_accepted.jsonl")

    if args.dry_run:
        logger.info("=== DRY RUN — would add %d records ===", len(final_new))
        for r in final_new:
            logger.info("  %s | %s | %s | %s",
                        r.cve_id, r.package, r.source_db, r.repo_url)
        return

    total = merge_into_dataset(final_new)
    logger.info("=== Supplement complete ===")
    logger.info("Added %d new records → total %d", len(final_new), total)
    if total < args.target:
        logger.warning("Still %d short of target %d", args.target - total, args.target)


if __name__ == "__main__":
    main()
