# CWE-78 Python CVE Dataset

## Overview

A curated dataset of **105** confirmed Python CVE vulnerabilities mapped to
CWE-78 (OS Command Injection). Each record includes the vulnerable commit,
patch commit, patch diff, and metadata needed to evaluate static analysis
tools (Semgrep, Joern) with LLM-augmented triage.

| Property        | Value                            |
|-----------------|----------------------------------|
| Target CWE      | CWE-78 (OS Command Injection)   |
| Language         | Python                           |
| Total records    | 105                              |
| CVE year range   | 2015 – 2026                      |
| Random seed      | 235711                           |
| Collection date  | 2026-04-07                       |
| Config file      | `conf/dataset.yaml`              |

---

## Directory Layout

```
benchmark/python/cwe78_cves/
├── metadata.json          # All 105 records (authoritative)
├── diffs/                 # 106 unified-diff files (one per CVE)
│   ├── CVE-YYYY-NNNNN.diff
│   └── ...
├── spot_check.json        # 10-sample subset for manual QA
└── DATASET.md             # This file

data/raw/                  # Intermediate pipeline checkpoints (gitignored)
├── ghsa_cwe78_pip.jsonl   # Phase 1 output – GHSA filtered candidates
├── nvd_enriched.jsonl     # Phase 2 output – with CVSS scores
├── commits_resolved.jsonl # Phase 3 output – with commit SHAs
├── sinks_extracted.jsonl  # Phase 4 output – with diffs/sinks/LOC
├── filtered_accepted.jsonl# Phase 5 output – quality-filtered
├── rejected.jsonl         # Phase 5 rejects with rejection reasons
├── huntr_nvd_candidates.json  # NVD CWE-78 CVEs referencing huntr
└── supplement_accepted.jsonl  # Supplement script additions

data/advisory-database/    # Cloned github/advisory-database (gitignored)
```

---

## Record Schema

Each entry in `metadata.json` is a JSON object with these fields:

| Field                 | Type          | Description                                                        |
|-----------------------|---------------|--------------------------------------------------------------------|
| `cve_id`              | `str`         | CVE identifier (e.g. `CVE-2023-6940`) or GHSA ID as fallback      |
| `ghsa_id`             | `str`         | GitHub Security Advisory ID (e.g. `GHSA-xxxx-xxxx-xxxx`)          |
| `package`             | `str`         | PyPI package name (e.g. `mlflow`, `apache-airflow`)                |
| `repo_url`            | `str`         | GitHub repository URL                                              |
| `vulnerable_commit`   | `str`         | Git SHA of the vulnerable state (parent of patch commit)           |
| `patch_commit`        | `str`         | Git SHA of the commit that fixes the vulnerability                 |
| `patch_diff_path`     | `str`         | Relative path to the unified diff file (`diffs/CVE-YYYY-NNNNN.diff`) |
| `vulnerable_file`     | `str`         | Path of the vulnerable `.py` file inside the repository            |
| `vulnerable_lines`    | `list[int]`   | Line numbers in the vulnerable file that were removed/changed      |
| `sink_api`            | `str`         | Matched dangerous API (e.g. `os.system`, `subprocess.run`)         |
| `loc`                 | `int`         | Estimated lines-of-code of the vulnerable file (from diff hunks)   |
| `cvss_score`          | `float`       | CVSS v3.1 base score (0.0–10.0) from NVD                          |
| `cvss_severity`       | `str`         | NVD severity label: `low`, `medium`, `high`, `critical`            |
| `source_db`           | `str`         | Data source: `ghsa`, `ghsa_unreviewed`, `osv`, or `huntr`          |
| `taint_hops`          | `int \| null`  | Reserved for taint-path length (populated during analysis)         |
| `notes`               | `str`         | Brief advisory summary (≤200 chars)                                |
| `manual_review_status`| `str`         | One of `pending`, `confirmed`, `disputed`                          |

### Fields that may be empty

- `vulnerable_file` / `vulnerable_lines`: Empty for 18 records where the
  patch diff only touches non-Python files or adds code without removing
  existing lines. The vulnerability is still confirmed via the CVE; the
  static analysis tools should scan the full repo at `vulnerable_commit`.
- `sink_api`: `"unknown"` for 67 records where the diff did not contain a
  recognizable sink pattern from `auditzoo/agents/cwe78/corpus/sinks.yaml`.
  These require manual review or LLM-based classification.
- `cvss_score`: 0.0 for 12 records not yet indexed by NVD at collection time.

---

## Data Sources

| Source             | Records | Description                                                   |
|--------------------|---------|---------------------------------------------------------------|
| `ghsa`             | 69      | GitHub Advisory Database, reviewed section, ecosystem = PyPI  |
| `ghsa_unreviewed`  | 16      | GHSA unreviewed section, matched via Python keyword heuristics|
| `osv`              | 12      | OSV.dev API queries for PyPI packages with CWE-78 history     |
| `huntr`            | 8       | huntr.dev bug bounties surfaced via OSV.dev and NVD references|

---

## Statistics

### Severity Distribution

| Severity | Count |
|----------|-------|
| Critical | 37    |
| High     | 57    |
| Medium   | 10    |
| Low      | 1     |

### LOC Distribution

| Bin              | Range       | Count |
|------------------|-------------|-------|
| Small            | < 100       | 22    |
| Medium           | 100 – 500   | 48    |
| Large            | 500 – 2000  | 23    |
| Very large       | > 2000      | 12    |

LOC stats: min=4, max=33546, median=282, mean=1098

### CVSS Score Stats

min=4.5, max=10.0, median=8.8, mean=8.4

### CVE Year Distribution

| Year | Count | Year | Count |
|------|-------|------|-------|
| 2015 | 1     | 2021 | 12    |
| 2017 | 3     | 2022 | 11    |
| 2018 | 1     | 2023 | 17    |
| 2019 | 2     | 2024 | 17    |
| 2020 | 6     | 2025 | 17    |
|      |       | 2026 | 16    |

### Top Packages

| Package           | Count |
|-------------------|-------|
| apache-airflow    | 9     |
| mlflow            | 6     |
| PaddlePaddle      | 4     |
| ansible           | 3     |
| yt-dlp            | 3     |
| gerapy            | 3     |
| salt              | 3     |
| cai-framework     | 2     |
| praisonai         | 2     |
| bentoml           | 2     |

### Sink API Distribution

| Sink API           | Count |
|--------------------|-------|
| unknown            | 67    |
| subprocess.run     | 11    |
| subprocess.call    | 10    |
| os.system          | 10    |
| subprocess.Popen   | 6     |
| commands.getoutput | 1     |

---

## Reconstruction

### Prerequisites

```bash
# Python ≥ 3.11, virtual environment
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Required environment variables (in `.env`):

```
GITHUB_TOKEN=ghp_...    # GitHub PAT with public_repo scope
NVD_API_KEY=...         # From https://nvd.nist.gov/developers/request-an-api-key
```

### Full rebuild from scratch

```bash
# Phase 1–6: collect from GHSA, enrich from NVD, resolve commits,
#             extract sinks, filter, and sample
python scripts/collect_cwe78_dataset.py --phase 0 --config conf/dataset.yaml

# Supplement with OSV.dev + huntr
python scripts/supplement_huntr_osv.py --config conf/dataset.yaml

# Validate
python scripts/validate_dataset.py --metadata benchmark/python/cwe78_cves/metadata.json
```

### Phase-by-phase rebuild

Each phase reads the latest checkpoint from `data/raw/` and writes its own:

```bash
python scripts/collect_cwe78_dataset.py --phase 1 --config conf/dataset.yaml
python scripts/collect_cwe78_dataset.py --phase 2 --resume --config conf/dataset.yaml
python scripts/collect_cwe78_dataset.py --phase 3 --resume --config conf/dataset.yaml
python scripts/collect_cwe78_dataset.py --phase 4 --config conf/dataset.yaml
python scripts/collect_cwe78_dataset.py --phase 5 --config conf/dataset.yaml
python scripts/collect_cwe78_dataset.py --phase 6 --config conf/dataset.yaml
python scripts/supplement_huntr_osv.py --config conf/dataset.yaml
```

### Adding new records manually

Append a JSON object to `metadata.json` with all required fields. Then
re-run validation:

```bash
python scripts/validate_dataset.py --metadata benchmark/python/cwe78_cves/metadata.json
```

---

## Pipeline Architecture

```
 ┌─────────────────────────────────────────────────────────────────┐
 │  collect_cwe78_dataset.py                                      │
 │                                                                 │
 │  Phase 1 ─► Clone GHSA advisory-database                       │
 │             Filter: CWE-78 ∩ (PyPI ∪ Python keywords)          │
 │             Output: ghsa_cwe78_pip.jsonl                        │
 │                                                                 │
 │  Phase 2 ─► Query NVD API 2.0 for CVSS scores                  │
 │             Output: nvd_enriched.jsonl                          │
 │                                                                 │
 │  Phase 3 ─► Resolve patch + vulnerable commit SHAs              │
 │             Strategies: direct link → PR merge → tag → release  │
 │             Output: commits_resolved.jsonl                      │
 │                                                                 │
 │  Phase 4 ─► Fetch diffs via GitHub API                          │
 │             Parse: vulnerable .py file, changed lines, sink API │
 │             Estimate LOC from diff hunk headers                 │
 │             Output: sinks_extracted.jsonl + diffs/*.diff        │
 │                                                                 │
 │  Phase 5 ─► Deduplicate on CVE ID                               │
 │             Require: patch_commit + vulnerable_commit            │
 │             Output: filtered_accepted.jsonl + rejected.jsonl    │
 │                                                                 │
 │  Phase 6 ─► Stratified sampling for diversity                   │
 │             Bins: LOC × sink × severity                         │
 │             Output: metadata.json                               │
 └─────────────────────────────────────────────────────────────────┘

 ┌─────────────────────────────────────────────────────────────────┐
 │  supplement_huntr_osv.py                                        │
 │                                                                 │
 │  Source 1 ─► OSV.dev API: query PyPI packages for CWE-78 vulns │
 │  Source 2 ─► NVD: CVEs referencing huntr.com with Python signal │
 │  Source 3 ─► Salvage: retry commit resolution for rejects       │
 │                                                                 │
 │  Then: resolve commits → fetch diffs → enrich CVSS → dedup     │
 │  Output: merged into metadata.json                              │
 └─────────────────────────────────────────────────────────────────┘

 ┌─────────────────────────────────────────────────────────────────┐
 │  validate_dataset.py                                            │
 │                                                                 │
 │  Checks: required fields, no duplicates, diff files exist,      │
 │          Python file types, diversity stats, spot-check sample  │
 └─────────────────────────────────────────────────────────────────┘
```

---

## Configuration Reference

See `conf/dataset.yaml`:

| Key                    | Default   | Description                                    |
|------------------------|-----------|------------------------------------------------|
| `target_n`             | 100       | Target dataset size                            |
| `seed`                 | 235711    | Random seed for reproducibility                |
| `nvd_delay_s`          | null      | NVD rate limit delay (auto: 0.7s w/ key)       |
| `min_per_loc_bin`      | 10        | Min samples per LOC bin in stratified sampling  |
| `min_per_sink`         | 3         | Min samples per sink API type                  |
| `min_per_severity`     | 3         | Min samples per CVSS severity bucket           |
| `filters.require_python_file` | true | Reject if no .py file in diff (relaxed in v2) |
| `filters.require_patch_commit`| true | Reject if patch commit unresolved             |
| `filters.require_diff`        | true | Reject if diff fetch failed                   |

---

## Known Limitations

1. **Sink API coverage**: 67/105 records have `sink_api = "unknown"` because
   the diff-based pattern matcher only checks for explicit API names like
   `os.system`. Many vulnerabilities use indirect calls, wrapper functions,
   or dynamic dispatch that require deeper analysis.

2. **Vulnerable lines for add-only patches**: 18 records have empty
   `vulnerable_lines` because the fix only adds validation code without
   modifying existing lines. The vulnerability location must be inferred
   from context.

3. **Non-Python diffs**: 18 records have diffs that touch non-Python files
   (YAML, TypeScript, PHP, docs). These passed filtering because they have
   valid commits but the resolved commit may be a merge or release commit
   rather than the precise code fix.

4. **LOC is estimated**: The `loc` field is derived from diff hunk headers
   (largest old-file line range), not from a full file line count. It
   underestimates for files where the diff only touches a small region.

5. **CVSS scores**: 12 records have `cvss_score = 0.0` because NVD had not
   yet published scores at collection time. Re-running Phase 2 may fill these.

---

## Versioning

| Version | Date       | Records | Changes                                      |
|---------|------------|---------|----------------------------------------------|
| 1.0     | 2026-04-07 | 85      | Initial collection from GHSA + NVD            |
| 1.1     | 2026-04-07 | 105     | Supplement from OSV.dev + huntr (+20 records) |
