# Dataset collection (archived)

These scripts mined the 105-CVE CWE-78 Python dataset now frozen at
[`benchmark/python/cwe78_cves/metadata.json`](../../benchmark/python/cwe78_cves/metadata.json).
They are **not** part of the live evaluation pipeline and are kept only
for provenance / reproducibility of the dataset described in
[`benchmark/python/cwe78_cves/DATASET.md`](../../benchmark/python/cwe78_cves/DATASET.md).

## Scripts

| Script                        | Purpose                                                                 |
| ----------------------------- | ----------------------------------------------------------------------- |
| `collect_cwe78_dataset.py`    | Main mining pipeline: GHSA + NVD + commit resolution + sink extraction. |
| `supplement_huntr_osv.py`     | Adds OSV.dev / huntr / PYSEC entries not covered by the GHSA pass.      |
| `validate_dataset.py`         | Post-hoc structural validation of `metadata.json`.                      |

## Do not run from CI

The dataset is frozen. Re-running these scripts would hit live GitHub,
NVD, and OSV APIs, and the resulting CVE set is not guaranteed to match
the paper's snapshot. Use them only if you intentionally want to rebuild
the dataset from scratch.

## Live evaluation entry points

For running the evaluation sweep against the frozen dataset, see
[`splitEvaluations/README.md`](../../splitEvaluations/README.md).
