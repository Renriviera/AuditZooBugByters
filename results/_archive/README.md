# Archived result runs

Superseded evaluation runs kept for audit / historical reference. None
of these are consumed by the live pipeline, analysis notes, or tests.

## Layout

```
_archive/
  smoke/              # early smoke sweeps (2-CVE, used while debugging the pipeline)
    20260419_061223/
    20260419_062715/
    20260419_115133/
    20260419_115642/
    20260420_182538/
  full/               # partial combined sweeps that were cut short
    20260419_123808/
    20260419_130919/
    20260419_135557/
```

## Runs that are NOT archived (still live under `results/`)

| Path                                | Why it is kept                                                                     |
| ----------------------------------- | ---------------------------------------------------------------------------------- |
| `results/full/20260419_171343/`     | 40-CVE sweep analysed in `results/analysis/triage_noop_rootcause.md`.              |
| `results/full/20260421_123649/`     | Combined sweep cited in `splitEvaluations/README.md` as the motivation for splitting. |
| `results/joern/<timestamp>/`        | Split Joern sweeps produced by `splitEvaluations.run_joern_sweep`.                 |
| `results/semgrep/<timestamp>/`      | Split Semgrep sweeps produced by `splitEvaluations.run_semgrep_sweep`.             |
| `results/analysis/`                 | Hand-authored post-hoc analysis notes.                                             |
