# CWE-78 triage/refinement no-op: root cause and fix

**Question**: why do the TP / FP / FN metrics not move across
`k = 0, 1, 2, 3` on the 105-repo CWE-78 benchmark, for either the
Semgrep arm or the Joern arm?

**Scope**: diagnostic + redesign, performed in a single sweep covering
`auditzoo/agents/cwe78_study/pipeline.py`, `scripts/run_evaluation.py`,
`auditzoo/agents/cwe78_study/prompts.py`, and
`auditzoo/agents/cwe78_study/triage_agent.py`. No changes to the CodeQL
tree or seed rules.

## 1. Aggregate evidence (from `results/full/20260419_171343/results.json`)

40 CVEs were actually processed (the sweep was cut short before 105);
each produced 4 Semgrep iterations and up to 4 Joern iterations. Per
arm × k totals, **all values in aggregate counts across CVEs**:

| arm×k        | count | LLM n_tp | LLM n_fp | LLM n_uncertain | GT tp | GT fp | GT fn |
|--------------|------:|---------:|---------:|----------------:|------:|------:|------:|
| `semgrep_0`  |    40 |      191 |       32 |              29 |     9 |   243 |   316 |
| `semgrep_1`  |    40 |      192 |       31 |              29 |     9 |   243 |   316 |
| `semgrep_2`  |    40 |      192 |       31 |              29 |     9 |   243 |   316 |
| `semgrep_3`  |    40 |      192 |       31 |              29 |     9 |   243 |   316 |
| `joern_0`    |    40 |        1 |        0 |              16 |     0 |    17 |   325 |
| `joern_1..3` |     8 |        1 |        0 |              16 |     0 |    17 |    78 |

- **Per-CVE invariance**: for Semgrep, **0 of 40** CVEs show any change in
  `(tp, fp, fn)` between `k=0` and `k=3`. Exact-zero k-variance.
- **Joern port collisions**: 32 of 40 CVEs produce only a `joern_0`
  stub; their `metrics.error = "Port localhost:12345 is already in use"`
  (see `results/full/20260419_135557/run.log` lines 8, 27, 47, ... —
  100% of the logged Joern attempts hit the same error). Only 8 CVEs
  even reached `joern_1..3`.

The invariance is the central fact. Below we show that three
independent design flaws each produce it, and any one of them is
sufficient on its own.

## 2. Bug #1 — scoring ignores the LLM's TP verdict

`label_findings` (old) in `scripts/run_evaluation.py:73-95`:

```python
if t.verdict == Verdict.FALSE_POSITIVE:
    fp += 1
    labels.append("fp_by_llm")
    continue
# TRUE_POSITIVE and UNCERTAIN both fall through to GT-line matching
```

Only `FALSE_POSITIVE` ever touches `tp/fp/fn`; `TRUE_POSITIVE` is
treated identically to `UNCERTAIN`. That means:

- **191 LLM TP verdicts** at `semgrep_0` produce GT tp = 9, i.e. **95%
  of the LLM's "confirmed bugs" contribute nothing** — they are silently
  rescored by line-tolerance match (±5). A perfect-oracle LLM that
  labels all 191 as `true_positive` would still score `tp = 9`.
- The **LLM has zero incentive to emit TP over UNCERTAIN**, because
  both behave identically in scoring. Combined with PRIORITY
  "a missed true positive is preferable to a false positive" in
  `prompts.py`, this encourages conservative UNCERTAIN output on
  ambiguous code.

**Fix (Phase B1, `scripts/run_evaluation.py`):** rewrite `label_findings`
with an explicit asymmetric matrix. See the new docstring table. Net
effects:

- `TRUE_POSITIVE` + GT-match ⇒ `tp`; no match ⇒ `fp_by_llm_overclaim`
  (**new penalty** for approving a wrong-line alert).
- `FALSE_POSITIVE` + no match ⇒ `tn` (**not** `fp_by_llm` — the LLM did
  the right thing).
- `FALSE_POSITIVE` + match ⇒ `fn_by_llm` (**new penalty** for
  retracting a real alert); counted in `fn` too.
- `UNCERTAIN` keeps previous behaviour.

Guarded by `tests/test_k_moves_metrics.py` which pins distinct
`(tp, fp, fn)` across `k = 0..3` under a scripted verdict schedule.

## 3. Bug #2 — Semgrep refinement gate is effectively dead

Old `pipeline.py:243-251`:

```python
if k < self._cfg.max_iterations and findings:
    ...
    fp_findings = [(f, t) for f, t in zip(findings, triage_results)
                   if t.verdict == Verdict.FALSE_POSITIVE]
    if fp_findings:            # <-- dead on most CVEs
        ...refine rules...
```

Consequence: on any CVE where the triage LLM produces 0
`FALSE_POSITIVE` verdicts, the Semgrep ruleset **cannot mutate** and
`semgrep_1..3` scans are guaranteed byte-identical to `semgrep_0`.

The deep-dive case `CVE-2024-52803` has `n_fp = 0, n_uncertain = 2`
on every iteration, so refinement never fires there at all. More
importantly, even on CVEs where `n_fp > 0`, refinement picks
`fp_findings[0]` only (one rule probe per iteration); when the LLM
returns `action: keep` (the default on any error or uncertainty in
`refinement_agent.py:67-69`), the rule stays identical. Combined with
the CVE-wide k-invariance above, this clearly happens in practice.

**Fix (Phase B2, `pipeline.py`):** drop the `if fp_findings` gate.
Always invoke `refine_semgrep` when `findings` is non-empty; let the
LLM choose `keep` / `refine` / `add_rule` from the full triage
context. Target selection now prefers `FALSE_POSITIVE > UNCERTAIN >
TRUE_POSITIVE` via `_pick_refinement_target`, so when the LLM *does*
flag a false positive we still anchor refinement on it — but we no
longer require one.

## 4. Bug #3 — triage prompt does not constrain UNCERTAIN

Old `SYSTEM_PROMPT_B_TRIAGE` says "classify as tp / fp / uncertain"
with no rule for when each verdict is appropriate. Combined with bug
#1 (TP and UNCERTAIN score identically), the LLM has a free pass to
emit UNCERTAIN on anything ambiguous. We see this directly in
`CVE-2024-52803` (100% UNCERTAIN), and in aggregate across the Joern
arm (16 UNCERTAIN vs 1 TP vs 0 FP).

**Fix (Phase B3, `prompts.py`):** enumerate decisive rules for CWE-78:

- Explicit TP criterion: attacker-controlled source → OS-level sink
  (`os.system`, `subprocess.*(shell=True)`, `os.popen`, `eval`/`exec`
  of shell text, `asyncio.create_subprocess_shell`) without
  `shlex.quote` / allowlist / `shell=False` list argv.
- Explicit FP criterion: literal args, `shell=False` list argv,
  validated/quoted input, or test-fixture code.
- UNCERTAIN capped behind `confidence < 0.4`; otherwise the LLM must
  commit.

Guarded by `tests/test_triage_prompt.py` (prompt structure tests +
scripted TriageAgent verdict propagation).

## 5. Bug #4 — Joern port collisions silently kill 80% of Joern iterations

`run.log` in `results/full/20260419_135557/` shows every Joern attempt
after the first failed with:

```
auditzoo.core.ir.backend_api.BackendConnectionError:
  Port localhost:12345 is already in use. Cannot connect to Joern.
```

The pipeline's `except` at `pipeline.py:321-343` returns a single
stub `IterationResult(iteration=0, metrics={"error": ...})` and no
`joern_1..3` entries, which is why downstream analysis saw "Joern has
always-zero findings at k=0 only". The underlying cause: the JVM
spawned by the previous CVE had not released the port before the
next CVE called `__aenter__()`.

**Fix (Phase B4, `pipeline.py`):** `_connect_joern_with_retry` retries
the CPG connect once after a 5 s pause, calling `runtime_cm.stop()`
between attempts. Failures are surfaced as an explicit
`arm_error` / `arm_error_type` column in `results.json` (not silently
conflated with "the analysis ran and found nothing").

## 6. Persistence of evidence (Phase A1)

Prior to this change, `results.json` only stored the label-findings
output + phase metrics. Nothing about **what the LLM actually said**
or **whether the rules/catalogs changed** was written. That is why
the no-op was invisible for weeks.

New per-iteration keys (see `serialize_triage_verdicts` in
`scripts/run_evaluation.py` and the `metrics` additions in
`pipeline.py`):

- `triage_verdicts`: list aligned with `findings`, each entry
  `{file, line, rule_id, sink_api, verdict, confidence, reasoning[:200], suggestion[:200]}`.
- `refinement_actions`: the `SemgrepRefinement` / `JoernHelperClassification`
  dicts produced this iteration.
- `metrics.rules_hash_pre` / `rules_hash_post` (Semgrep): SHA-256
  prefix of the YAML rules before and after apply_refinement.
- `metrics.findings_hash`: hash of the sorted
  `(file, line, rule_id, sink_api)` tuples — quantifies candidate-set
  invariance across k.
- `metrics.joern_catalog_pre` / `joern_catalog_post` /
  `joern_catalog_grew`: sources/sinks/sanitizers before and after
  taint-catalog expansion.
- `metrics.cpg_build_failed` / `metrics.error_type` (Joern).

## 7. Audit tooling (Phase A2)

`scripts/analyze_triage.py` reads the enriched `results.json` and
prints:

1. Per-arm/per-k **verdict histogram** (TP / FP / UNCERTAIN counts).
2. **Verdict × GT-line-match contingency**: shows whether LLM TPs
   actually land on ground-truth lines. Any future Phase-A3 deep dive
   can focus on cells with `TP · no_match` (overclaim) and
   `FP · gt_match` (wrongful retraction).
3. **Candidate-set invariance** across k via `findings_hash`:
   `identical_across_k / total`. The smoking gun number.
4. **Refinement action summary**: counts of Semgrep
   `keep / refine / add_rule` invocations and Joern role
   classifications; confirms refinement is actually mutating state.

Output is also saved as `results/<run>/triage_audit.json` for
programmatic consumption.

## 8. Deep-dive hook (Phase A3)

`LLMClient` now supports `--log-llm-io <path>` (piped through
`run_evaluation.py` into `PipelineConfig.llm_log_io_path`). When set,
every chat round-trip appends a JSONL record with the system prompt,
user prompt, response text, usage and finish_reason. This makes the
UNCERTAIN-collapse root cause directly attributable to the LLM, the
prompt, or the JSON parser in a single run:

```
python scripts/run_evaluation.py \
    --arms semgrep \
    --max-k 3 \
    --only-cves CVE-2024-52803 \
    --log-llm-io results/deepdive_52803/llm_io.jsonl \
    --output results/deepdive_52803
```

## 9. How to rerun the full benchmark

```
python scripts/run_evaluation.py \
    --arms semgrep joern \
    --max-k 3 \
    --output results/full \
    --per-cve-timeout 900

# then, once the run is done:
python scripts/analyze_triage.py results/full/<timestamp>
python scripts/analyze_results.py results/full/<timestamp>
```

Expected contrast with the 20260419 sweep:

- `semgrep_0..3` TP/FP/FN differ on at least ~20% of CVEs (vs 0/40 before),
  driven by Phase-B1 verdict-honouring and Phase-B2 unconditional rule
  refinement.
- Joern port failures drop to near zero (`arm_error` column counts
  the residual).
- `triage_audit.json` shows non-degenerate verdict histograms and
  non-zero Semgrep `refine` / `add_rule` action counts.

## 10. Regression guards

Added under `tests/`:

- `tests/test_k_moves_metrics.py` — pins the Phase-B1 redesign: a
  scripted verdict schedule for `k=0..3` must produce distinct
  `(tp, fp, fn)`. This is the key guard against silent regression.
- `tests/test_triage_prompt.py` — pins prompt structure
  (mentions `os.system`, `subprocess`, `shell=True`, `shlex.quote`,
  `argv`, `request`, etc., and caps UNCERTAIN behind 0.4 confidence)
  and verifies that `TriageAgent` faithfully propagates scripted
  verdicts (i.e. the JSON parser does not silently demote everything
  to UNCERTAIN).

All 33 tests pass under `tests/`; the 17-test delta over the prior
suite covers Phases B1, B3, B5.

## 11. Non-goals / deferred

- No Hydra migration of `run_evaluation.py`: the argparse ↔ Hydra
  disconnect noted in the plan remains and is out of scope for this
  audit.
- No changes to the Joern CPGQL taint query itself (`joern_arm.py`);
  the 16 UNCERTAIN / 0 FP histogram on Joern indicates the LLM does
  engage with Joern findings but the prompt-level fix (Phase B3)
  should already reduce the UNCERTAIN share there too.
- No variance re-run: orthogonal to this audit.
