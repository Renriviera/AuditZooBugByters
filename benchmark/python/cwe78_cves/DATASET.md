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
| CVE year range   | 2014 – 2026                      |
| Random seed      | 235711                           |
| Collection date  | 2026-04-07 (last refresh: 2026-05-06) |
| Config file      | `conf/dataset.yaml`              |
| Joern verifier   | `pysrc2cpg` + OssDataFlow @ `--per-cve-timeout=1800` |

---

## Directory Layout

```
benchmark/python/cwe78_cves/
├── metadata.json          # All 105 active records (authoritative)
├── joern_1800_timeout_archive.json
│                          # 10 records archived from the active set after they
│                          # exceeded the Joern 1800s per-CVE wall-clock budget,
│                          # plus the timeout evidence (results/joern/...)
├── joern_1800_replacement_verification.json
│                          # Joern build evidence (importCode.python +
│                          # run.ossdataflow, build_s, n_method, n_call) for
│                          # the 10 replacement CVEs that took the timeout
│                          # archive's place. All builds completed well under
│                          # 1800s.
├── diffs/                 # Unified-diff files; includes diffs for both
│   │                      # active and archived (timeout) CVEs
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
| `ghsa`             | 59      | GitHub Advisory Database, reviewed section, ecosystem = PyPI  |
| `osv`              | 22      | OSV.dev (PyPI snapshot, GHSA + PYSEC), incl. v1.2 refresh     |
| `ghsa_unreviewed`  | 16      | GHSA unreviewed section, matched via Python keyword heuristics|
| `huntr`            | 8       | huntr.dev bug bounties surfaced via OSV.dev and NVD references|

---

## Statistics

### Severity Distribution

| Severity | Count |
|----------|-------|
| Critical | 35    |
| High     | 55    |
| Medium   | 14    |
| Low      | 1     |

### LOC Distribution

| Bin              | Range       | Count |
|------------------|-------------|-------|
| Small            | < 100       | 22    |
| Medium           | 100 – 500   | 49    |
| Large            | 500 – 2000  | 25    |
| Very large       | > 2000      | 9     |

LOC stats: min=4, max=33546, median=285, mean=1032

### CVE Year Distribution

| Year | Count | Year | Count |
|------|-------|------|-------|
| 2014 | 1     | 2021 | 12    |
| 2015 | 1     | 2022 | 12    |
| 2017 | 3     | 2023 | 20    |
| 2018 | 1     | 2024 | 18    |
| 2019 | 2     | 2025 | 17    |
| 2020 | 5     | 2026 | 11    |

### Top Packages

| Package           | Count |
|-------------------|-------|
| apache-airflow    | 7     |
| mlflow            | 6     |
| PaddlePaddle      | 4     |
| gerapy            | 3     |
| salt              | 3     |
| ansible           | 2     |
| yt-dlp            | 2     |
| pgadmin4          | 2     |
| motioneye         | 2     |
| fastmcp           | 2     |

### Sink API Distribution

| Sink API           | Count |
|--------------------|-------|
| unknown            | 69    |
| run                | 10    |
| call               | 8     |
| os.system          | 7     |
| Popen              | 3     |
| subprocess.Popen   | 3     |
| subprocess.call    | 2     |
| system             | 2     |
| getoutput          | 1     |

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
| 1.2     | 2026-05-06 | 105     | Joern 1800s timeout refresh: archived 10 records to `joern_1800_timeout_archive.json` and replaced them 1:1 with new Joern-buildable CWE-78 (and tightly-related CWE-77/CWE-94 OS command injection) records. See [Joern Timeout Refresh](#joern-timeout-refresh-v12) below. |

---

## Joern Timeout Refresh (v1.2)

The active dataset previously contained 10 entries whose vulnerable repositories
exceeded the Joern per-CVE wall-clock budget of **1800 seconds** (`pysrc2cpg` +
`OssDataFlow`) during the
[`results/joern/20260423_034702`](../../../results/joern/20260423_034702)
sweep — that run had `per_cve_timeout: 1800.0` and an empty `skip_cves` list,
so the timeouts in `results.json` are direct evidence (`skipped: timeout`).

### Archived records

The 10 timeout records, together with their original metadata and the timeout
evidence (`source_result_path`, `source_run_config_path`, `per_cve_timeout_s`,
observed `loc`, observed `repo_url`, `skipped_status`), are preserved in
[`joern_1800_timeout_archive.json`](joern_1800_timeout_archive.json):

| CVE             | Repository                                | Joern repo LOC |
|-----------------|--------------------------------------------|----------------|
| CVE-2020-11981  | `apache/airflow`                           | 260,716        |
| CVE-2020-11978  | `apache/airflow`                           | 179,661        |
| CVE-2021-41228  | `tensorflow/tensorflow`                    | 978,620        |
| CVE-2019-14904  | `ansible/ansible`                          | 1,280,202      |
| CVE-2026-25130  | `aliasrobotics/cai`                        | 70,544         |
| CVE-2026-26331  | `yt-dlp/yt-dlp`                            | 229,216        |
| CVE-2026-34955  | `MervinPraison/PraisonAI`                  | 529,006        |
| CVE-2026-34935  | `MervinPraison/PraisonAI`                  | 514,590        |
| CVE-2026-35043  | `bentoml/BentoML`                          | 65,005         |
| CVE-2026-33641  | `nicolargo/glances`                        | 33,114         |

### Replacement records

Each archived record was replaced by a Joern-buildable, non-duplicate entry
(no overlap on `cve_id` / `ghsa_id` / `(repo_url, vulnerable_file,
sorted(vulnerable_lines[:5]))` against the active dataset, and **no entry**
in any of the 8 timeout repositories above):

| New CVE           | Package                       | Repository                              | Joern build (s) |
|-------------------|-------------------------------|-----------------------------------------|-----------------|
| CVE-2022-42906    | `powerline-gitstatus`         | `jaspernbrouwer/powerline-gitstatus`    | 4.6             |
| CVE-2023-1000     | `dcnnt`                       | `cyanomiko/dcnnt-py`                    | 5.7             |
| CVE-2019-7537     | `donfig`                      | `pytroll/donfig`                        | 5.3             |
| CVE-2021-23556    | `guake`                       | `Guake/guake`                           | 8.8             |
| CVE-2023-39523    | `scancodeio`                  | `nexB/scancode.io`                      | 10.5            |
| CVE-2014-6633     | `trytond`                     | `tryton/trytond`                        | 12.8            |
| CVE-2020-35459    | `crmsh`                       | `ClusterLabs/crmsh`                     | 12.5            |
| CVE-2024-53526    | `composio-julep`              | `ComposioHQ/composio`                   | 13.4            |
| CVE-2026-33154    | `dynaconf`                    | `dynaconf/dynaconf`                     | 11.3            |
| CVE-2023-34233    | `snowflake-connector-python`  | `snowflakedb/snowflake-connector-python`| 13.1            |

Each replacement was verified by importing the repository at
`vulnerable_commit` with `pysrc2cpg`, applying the `OssDataFlow` overlay and
confirming a non-zero method/call count under the same 1800 s budget. Build
times above are end-to-end including Joern startup; all are well within the
budget.

The replacement diffs live alongside the original diffs under
[`diffs/`](diffs); the archived timeout diffs are intentionally retained so
that the archive entries remain self-contained and reproducible.
