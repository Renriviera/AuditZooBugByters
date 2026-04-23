# scripts/

Utility + library modules for the CWE-78 two-arm study.

## Live entry points

The canonical way to run the 105-CVE evaluation is the **split** sweep
under [`splitEvaluations/`](../splitEvaluations/README.md):

```bash
# Joern-only sweep (1800 s per-CVE budget, no patched re-scan by default)
python -m splitEvaluations.run_joern_sweep

# Semgrep-only sweep (900 s per-CVE budget, rules-hash audit attached)
python -m splitEvaluations.run_semgrep_sweep
```

The old combined CLI (`python scripts/run_evaluation.py ...`) has been
retired. `run_evaluation.py` is now a **shared library**: its helpers
(`run_main_comparison`, `clone_and_checkout`, `label_findings`,
`serialize_triage_verdicts`, `_run_with_timeout`, etc.) are re-exported
by [`splitEvaluations/common.py`](../splitEvaluations/common.py) and
consumed by both split sweeps and the pytest suite. Do not invoke it as
a script.

## Files

| Path                          | Role                                                                 |
| ----------------------------- | -------------------------------------------------------------------- |
| `run_evaluation.py`           | Shared library for the split sweeps (see above). Not a CLI.          |
| `dataset_collection/`         | Archived dataset-mining scripts (frozen dataset).                    |

See [`dataset_collection/README.md`](dataset_collection/README.md) for
the archived mining pipeline that produced
`benchmark/python/cwe78_cves/metadata.json`.
