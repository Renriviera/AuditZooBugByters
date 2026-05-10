# Split evaluation sweeps

Two thin entry points that wrap `scripts/run_evaluation.py`'s
`run_main_comparison` — one per SAST arm.  Splitting the sweep lets each
tool have its own per-CVE budget and isolates per-tool regressions.

> **Note**: the combined CLI (`python scripts/run_evaluation.py ...`)
> has been retired.  `scripts/run_evaluation.py` is now a shared
> library module whose helpers are re-exported from
> [`splitEvaluations/common.py`](common.py); the split sweeps below are
> the only supported evaluation entry points.

## Why split?

| Problem                                                     | Fix                                                          |
| ----------------------------------------------------------- | ------------------------------------------------------------ |
| 38/105 CVEs timed out in the 20260421_123649 combined sweep | Joern sweep uses 1800 s (vs 900 s), Semgrep keeps 900 s      |
| Joern built CPGs twice (vuln + patched) inside one budget   | Joern sweep defaults to `--no-patched` (v1)                  |
| Semgrep `findings_hash` was k-invariant in 17/18 CVEs       | Semgrep sweep runs `audit_rules_hash.py` automatically       |
| A Joern failure shouldn't poison Semgrep's metrics          | Each sweep has its own output dir and `results.json`         |

Output layout:

```
results/
  semgrep/<timestamp>/
    run_config.json
    results.json
    rules_hash_summary.csv        # one row per (cve_id, k)
    rules_hash_audit.json         # refine_no_op_rate + findings-invariance
  joern/<timestamp>/
    run_config.json
    results.json
```

## Usage

Activate the project env first (gives us Joern, Semgrep, Python deps):

```bash
source /workspace/setup_env.sh
```

### Semgrep sweep

```bash
# Full model-seeded sweep (selected CVEs split 25% train / 75% validate)
python -m splitEvaluations.run_semgrep_sweep

# Smoke run: select 10 eligible CVEs, seed rules from 3, evaluate on 7
python -m splitEvaluations.run_semgrep_sweep \
    --dataset-size 10 --max-k 0 --no-patched \
    --llm-model gpt-5.4-mini --seed-model gpt-5.4-mini
```

The sweep ends with an auto-audit; `rules_hash_summary.csv` and
`rules_hash_audit.json` are written next to `results.json`.  The run
directory also includes `training_split.json`, `model_seed_semgrep.yaml`,
and `model_seed_prompt.json`.

### Joern sweep

```bash
# Full model-seeded sweep (selected CVEs split 25% train / 75% validate)
python -m splitEvaluations.run_joern_sweep

# Smoke run: select 10 eligible CVEs, seed catalogs from 3, evaluate on 7
python -m splitEvaluations.run_joern_sweep \
    --dataset-size 10 --max-k 0 \
    --llm-model gpt-5.4-mini --seed-model gpt-5.4-mini
```

Use `--run-patched` to opt back into the "alerts-on-patched = FP"
signal (expect ~2x wall time).

### Dataset sizing and splits

Both sweeps accept `--dataset-size` before the train/validation split, so
`--dataset-size 10`, `--dataset-size 30`, `--dataset-size 100`, and
`--dataset-size full` all use the same deterministic selection logic.  The
default `--train-fraction 0.25` uses the training records only for the
one-time GPT-5.5-mini seed-generation call; `results.json` is computed only
on the remaining validation records.

### Standalone rules-hash audit

Works on any `results.json` the Semgrep arm produced (old or new):

```bash
python -m splitEvaluations.audit_rules_hash \
    results/semgrep/20260422_120000/results.json
```

Prints the `refine_no_op_rate` and writes
`rules_hash_summary.csv` beside the input.  If
`refine_no_op_rate > 0.5` the LLM is emitting `refine` actions that
`semgrep_arm.apply_refinement` is silently dropping — the current
prime suspect for the Semgrep k-invariance.
