# BugByters — Semgrep vs Joern for Python CWE-78 (LLM-assisted)

This repository is a fork of the upstream [`AuditZoo`](#auditzoo) framework
specialised into the **BugByters** empirical study: a head-to-head comparison
of Semgrep (pattern matching on ASTs) and Joern (interprocedural dataflow on
Code Property Graphs) for detecting OS Command Injection vulnerabilities
(CWE-78) in Python, each augmented with an LLM refinement + triage loop.

The companion paper (`Paper/main_results.tex`, **not tracked in this repo**)
is the authoritative description of the methodology, scoring lanes, and
headline numbers. This README only documents how to **re-run** the
underlying sweeps from a fresh clone. The original AuditZoo framework
documentation is preserved verbatim [below](#auditzoo).

## Repository layout

- [`auditzoo/agents/cwe78_study/`](auditzoo/agents/cwe78_study/) — pipeline,
  Joern arm, Semgrep arm, prompts, catalog sanitiser, CPG cache, LLM client.
- [`splitEvaluations/`](splitEvaluations/) — live sweep entry points
  (`run_joern_sweep.py`, `run_semgrep_sweep.py`) plus the audit / merge /
  rollup helpers used to score them. See
  [`splitEvaluations/README.md`](splitEvaluations/README.md).
- [`scripts/`](scripts/) — shell launch wrappers for the Semgrep arms and
  the archived dataset-mining pipeline. See
  [`scripts/README.md`](scripts/README.md) and
  [`scripts/dataset_collection/README.md`](scripts/dataset_collection/README.md).
- [`benchmark/python/cwe78_cves/`](benchmark/python/cwe78_cves/) — the frozen
  105-CVE Python CWE-78 dataset (`metadata.json` + per-CVE `.diff` files).
  See [`benchmark/python/cwe78_cves/DATASET.md`](benchmark/python/cwe78_cves/DATASET.md).
- [`docs/evaluations/`](docs/evaluations/) — frozen seed catalogs
  (`handbuilt_catalog.json`, `full_catalog_v2_clean.json`) consumed via
  `--joern-seed-catalog`, plus markdown rollups of selected sweeps.
- [`seeds/semgrep/`](seeds/semgrep/) — frozen Semgrep YAML seed
  (`a0598ac7f4d195de.yaml`) used by `--no-triage` baseline runs.
- [`conf/`](conf/) — Hydra configs (default seed `235711`, `max_iterations`,
  LLM model, Joern port).
- [`tests/`](tests/) — pytest suite covering audit lanes, catalog
  sanitiser, CPG cache, recovery passes, evidence scoring, and prompts.
- [`JOERN_EVALUATION_ROBUSTNESS_CHANGES.txt`](JOERN_EVALUATION_ROBUSTNESS_CHANGES.txt)
  / [`FORK_FIXES.md`](FORK_FIXES.md) — what this fork changed relative to
  upstream AuditZoo (JVM stack tuning, extension-method warm-up, transient
  retry, CPG cache, multi-pass recovery, sweep-level error handling).

## Quickstart

```bash
bash install.sh              # creates the `auditzoo` conda env (Python 3.10 + Java 17 + Joern)
conda activate auditzoo      # or activate /workspace/miniconda3/envs/iris/ if it is already populated

# Provide an OpenAI-compatible API key for the LLM-driven sweeps.
# Either env var or the gitignored repo-local file is fine.
export OPENAI_API_KEY=sk-...
# echo "sk-..." > .openai_api_key   # alternative; .openai_api_key is gitignored
```

The frozen dataset, Joern seed catalogs, and Semgrep seed YAML used by the
paper are all already in the repo, so each sweep below runs without any
extra setup beyond the API key.

Default knobs (set in [`conf/config.yaml`](conf/config.yaml) and the shared
CLI in [`splitEvaluations/common.py`](splitEvaluations/common.py)):
deterministic seed `235711` (overridable with `--seed`), LLM model
`gpt-5.4-mini`, LLM temperature `0.1`. The paper used the same values; the
Hand-built Joern catalog was generated externally with Claude Opus 4.7 and
checked in at `docs/evaluations/handbuilt_catalog.json`.

## Reproducing each paper sweep

The seven sweeps reported in `Paper/main_results.tex` §V map to the
following commands. Run them from the repo root with the `auditzoo`
environment active. Each sweep writes
`results/{semgrep,joern}/<timestamp>/{run_config,results}.json` (gitignored).

### (1) Semgrep no-LLM baseline (paper §V.A)

Frozen YAML seed, `--no-triage`, `--max-k 0`. Validation CVEs are
re-resolved from the previously-shipped sweep config.

```bash
bash scripts/launch_semgrep_baseline.sh
```

What it does: runs [`splitEvaluations.run_semgrep_sweep`](splitEvaluations/run_semgrep_sweep.py)
with `--no-triage --max-k 0 --seed-cache-fingerprint a0598ac7f4d195de`
against the cached YAML at
[`seeds/semgrep/a0598ac7f4d195de.yaml`](seeds/semgrep/a0598ac7f4d195de.yaml).
Zero LLM calls. Headline: precision ~0.005, recall ~0.069 on 65 CVEs.

### (2) Joern no-LLM baseline (paper §V.B)

The "raw-Joern lens" run that holds every finding at `UNCERTAIN`.
Currently requires a small triage-bypass shim that is **not yet in `main`**:
the original sweep was launched via `AUDITZOO_SKIP_TRIAGE=1` against a
patched [`auditzoo/agents/cwe78_study/triage_agent.py`](auditzoo/agents/cwe78_study/triage_agent.py)
that short-circuits `TriageAgent.triage_batch` to return `Verdict.UNCERTAIN`
for every input. The reference patch ships in the local archive at
`results/joern_only_k0_archives/.../patch/triage_agent_skip_triage.patch`
(also gitignored). Apply that patch, then:

```bash
AUDITZOO_LLM_API_KEY=$OPENAI_API_KEY \
AUDITZOO_SKIP_TRIAGE=1 \
AUDITZOO_MAX_K=0 \
AUDITZOO_TIMEOUT=1800 \
AUDITZOO_JOERN_SEED_CATALOG=docs/evaluations/full_catalog_v2_clean.json \
AUDITZOO_CPG_CACHE_DIR=results/joern_cpg_cache \
bash splitEvaluations/run_joern_validation_full.sh
```

Headline: TP=0 / FP=0 / FN=348 in the strict lane (no committed verdicts);
TP=13 in the UNCERTAIN-on-GT lane on 61 CVEs. Without the patch, omit
`AUDITZOO_SKIP_TRIAGE=1` to get the LLM-triaged equivalent (see sweep 7).

### (3) Semgrep + LLM, k=0..3 (paper §V.C)

Full LLM-assisted Semgrep sweep against the OpenAI cloud endpoint.

```bash
bash scripts/launch_semgrep_sweep.sh
```

What it does: backgrounds [`splitEvaluations.run_semgrep_sweep`](splitEvaluations/run_semgrep_sweep.py)
with `--llm-url https://api.openai.com/v1 --llm-model gpt-5.4-mini
--seed-model gpt-5.4-mini --clone-timeout-s 600`, then auto-runs
[`splitEvaluations.audit_rules_hash`](splitEvaluations/audit_rules_hash.py)
to land `rules_hash_summary.csv` and `rules_hash_audit.json` next to
`results.json`. Targeted re-runs on prior timeouts go through
`bash scripts/launch_semgrep_rerun.sh`. Headline: ~37.5 M tokens, F1 ≈
0.025 at k=3 over 63 scored CVEs.

### (4) Joern + LLM, hand-built Opus catalog, k=0..3 / 61 CVEs (paper §V.D)

Headline Joern configuration: externally hand-engineered Opus 4.7 catalog,
`gpt-5.4-mini` triages and refines.

```bash
python -m splitEvaluations.run_joern_sweep \
  --joern-seed-catalog docs/evaluations/handbuilt_catalog.json \
  --max-k 3 \
  --per-cve-timeout 1800 \
  --llm-url https://api.openai.com/v1 \
  --llm-model gpt-5.4-mini \
  --cpg-cache-dir results/joern_cpg_cache
```

The `--joern-seed-catalog` flag skips the in-pipeline LLM seed call and
loads the provided catalog verbatim (see
[`splitEvaluations/run_joern_sweep.py`](splitEvaluations/run_joern_sweep.py)).
Headline: TP=1 / FP=12 / FN=344 strict; TP=12 UNCERTAIN-on-GT; ~5.8 M
tokens; ~163 min wall-clock. For the long-running 61-CVE run, prefer the
auto-resume wrapper:

```bash
AUDITZOO_LLM_API_KEY=$OPENAI_API_KEY \
AUDITZOO_JOERN_SEED_CATALOG=docs/evaluations/handbuilt_catalog.json \
AUDITZOO_MAX_K=3 \
AUDITZOO_TIMEOUT=1800 \
AUDITZOO_CPG_CACHE_DIR=results/joern_cpg_cache \
bash splitEvaluations/run_joern_validation_full.sh
```

Other knobs documented in the script header:
`AUDITZOO_JOERN_HEAP=8g`, `AUDITZOO_JOERN_PORT=12345`,
`AUDITZOO_SWEEP_DIR=...` (resume into an existing dir),
`AUDITZOO_MAX_RESUMES=4`.

### (5) Joern + LLM, hand-built Opus catalog, k=0..9 / 10 CVEs (paper §V.E)

Deep-`k` pilot to test whether more refinement iterations help. Same
catalog as sweep 4, smaller dataset, longer per-CVE budget.

```bash
python -m splitEvaluations.run_joern_sweep \
  --joern-seed-catalog docs/evaluations/handbuilt_catalog.json \
  --max-k 9 \
  --dataset-size 10 \
  --per-cve-timeout 2400 \
  --llm-url https://api.openai.com/v1 \
  --llm-model gpt-5.4-mini \
  --cpg-cache-dir results/joern_cpg_cache
```

Headline: TP=1 / FP=7 / FN=144 strict; TP=6 UNCERTAIN-on-GT; ~2.46 M
tokens; ~71 min wall-clock.

### (6) Joern + LLM, zero-shot LLM seed, k=0..3 / 61 CVEs (paper §V.F)

Lets the in-pipeline `gpt-5.4-mini` seed call generate the catalog from a
zero-shot prompt (no examples, no `--joern-seed-catalog`).

```bash
python -m splitEvaluations.run_joern_sweep \
  --max-k 3 \
  --per-cve-timeout 1800 \
  --llm-url https://api.openai.com/v1 \
  --llm-model gpt-5.4-mini \
  --seed-model gpt-5.4-mini \
  --cpg-cache-dir results/joern_cpg_cache
```

The catalog generated this way mislabels several execution sinks as
sources, which the catalog sanitiser
([`auditzoo/agents/cwe78_study/catalog_sanitizer.py`](auditzoo/agents/cwe78_study/catalog_sanitizer.py))
mostly cleans up. Headline: TP=2 / FP=10 / FN=323 strict; ~5.7 M tokens.

### (7) Joern + LLM, few-shot seed (catalog A clean), k=0..3 / 61 CVEs (paper §V.G)

Same as sweep 4 but using the few-shot `gpt-5.4-mini` catalog
(`full_catalog_v2_clean.json`, 35 / 22 / 4 after the disjointness pass)
instead of the hand-built Opus one.

```bash
python -m splitEvaluations.run_joern_sweep \
  --joern-seed-catalog docs/evaluations/full_catalog_v2_clean.json \
  --max-k 3 \
  --per-cve-timeout 1800 \
  --llm-url https://api.openai.com/v1 \
  --llm-model gpt-5.4-mini \
  --cpg-cache-dir results/joern_cpg_cache
```

Headline: TP=1 / FP=9 / FN=338 strict; TP=11 UNCERTAIN-on-GT; ~5.3 M
tokens; ~156 min wall-clock.

## Auditing and rolling up sweep results

After any of the sweeps above, the FP/FN / recovery-pass audit is produced
by [`splitEvaluations.audit_joern_results`](splitEvaluations/audit_joern_results.py)
(Joern) or [`splitEvaluations.audit_rules_hash`](splitEvaluations/audit_rules_hash.py)
(Semgrep, also auto-invoked by the Semgrep sweep). Per-CVE rollups and
sweep summaries live in [`splitEvaluations/build_rollup.py`](splitEvaluations/build_rollup.py)
and [`splitEvaluations/summarize_sweep_results.py`](splitEvaluations/summarize_sweep_results.py).

The tables and figures in the paper are produced by the `make_*` scripts
under `PlotsTables/scripts/` from each sweep's `results.json` + `audit/`
tree. **`PlotsTables/` and the rendered tables/plots are intentionally not
tracked in this repo** (see [`.gitignore`](.gitignore)); the paper itself
is the canonical source for those numbers.

## Tests

```bash
pytest -q
```

The suite covers catalog sanitisation, CPG cache, FP/FN audit, evidence
scoring, multi-pass recovery (direct sink, relaxed taint, def-use), and
the rules-hash audit. See [`pyproject.toml`](pyproject.toml) for the
exact pytest config.

## Joern reliability fixes in this fork

Upstream AuditZoo's Joern arm produced zero true positives and crashed on
recursion-limit errors for most non-trivial Python CPGs. The hardening
applied in this fork is summarised in
[`JOERN_EVALUATION_ROBUSTNESS_CHANGES.txt`](JOERN_EVALUATION_ROBUSTNESS_CHANGES.txt)
and [`FORK_FIXES.md`](FORK_FIXES.md): JVM stack-size bump (`-Xss16m` via
`AUDITZOO_JOERN_XSS` / `AUDITZOO_JOERN_JAVA_OPTS`), extension-method
warm-up after `importCode`, transient `[E008]`-payload retry, CPG disk
cache (`results/joern_cpg_cache/`, gitignored), catalog
disjointness sanitiser, multi-pass recovery (taint → direct sink →
relaxed → def-use) with a global deduper, and a sweep-level
`try / except / finally` that records `{"skipped": "error"}` rows and
cleans up stray Joern processes so a single CVE failure no longer kills
the sweep.

---

# AuditZoo

AuditZoo is a CPG-centered, agent-based program analysis framework built on Joern and AutoGen-Core. It provides a unified infrastructure for building and composing program analyses using lightweight agents that communicate through a flexible protocol.

## Installation

### Prerequisites
- Python 3.10+
- Conda (Miniconda or Anaconda)

### Quick Install

```bash
# Clone the repository
git clone https://github.com/Biscope-AI/auditzoo.git
cd auditzoo

# Run the installation script (installs AuditZoo + Joern in a conda environment)
bash install.sh

# Activate the environment
conda activate auditzoo
```

The installation script will:
- Create a conda environment with Python 3.10 and Java 17
- Install AuditZoo and its dependencies
- Download and install Joern
- Configure environment variables

## Usage

### Basic Example

```python
import asyncio
from auditzoo import AnalysisRuntime, UKRegistry, auto_detect_backend, Request, CodeUnit
from auditzoo.core.protocol.utils import to_schema

async def main():
    # Auto-detect backend configuration
    config = auto_detect_backend("./my_project")

    # Initialize runtime (connects to backend, loads IR)
    async with AnalysisRuntime(config) as runtime:
        # Send IR queries
        response = await runtime.send_message(
            Request(
                type="ir.get_all_units_by_kind",
                payload={"kind": UKRegistry.Function()},
                response_schema=to_schema(list[CodeUnit]),
            ),
            runtime.ir_agent_id
        )

        functions = response.unwrap()
        print(f"Found {len(functions)} functions")

asyncio.run(main())
```

### Creating Custom Analysis Agents

```python
from autogen_core import MessageContext, AgentId
from auditzoo import BaseAnalysisAgent, Request, Response

class MyAnalysisAgent(BaseAnalysisAgent):
    def __init__(self):
        super().__init__("My custom analysis agent")

    async def _handle_request(self, message: Request, ctx: MessageContext) -> Response:
        if message.type != "task.my_analysis":
            return Response.fail("Unknown task type")

        functions = await self.get_functions(ctx)
        results = [f.name for f in functions]
        return Response.ok(data={"results": results})

# Register and use
async with AnalysisRuntime(config) as runtime:
    await runtime.register_agent(MyAnalysisAgent, "my_analyzer", lambda: MyAnalysisAgent())
    runtime.start()

    response = await runtime.send_message(
        Request(type="task.my_analysis", payload={}),
        AgentId("my_analyzer", "default")
    )
```

See [examples/find_callers.py](examples/find_callers.py) for complete examples.

## Key Concepts

- **Runtime**: Manages backend, IR, and agent lifecycle
- **Agents**: Lightweight workers for analysis tasks
- **Protocol**: Request/Response messaging
  - `Request`: type (e.g., "ir.*", "task.*"), payload (dict)
  - `Response`: success, data (any type), error
  - `Request`/`Response` are sealed; do not subclass
- **IR Model**: Code representation via Code Property Graphs
  - `CodeUnit`: Code at any granularity (file, function, statement, etc.)
  - `CodeUnitRelation`: Relationships (calls, contains, etc.)
  - `Facts`: Analysis results attached to units/relations

## Development

> **Note**: If you want to contribute to or extend AuditZoo, please refer to [DEVELOPMENT.md](DEVELOPMENT.md) for detailed architecture documentation and development guidelines.

## Project Status

AuditZoo is at a very early stage of development. We welcome contributions and feedback!

Feel free to open pull requests, but please note:
- **IMPORTANT**: Any PR should NOT mix changes in `core/` and changes in other places. Keep core infrastructure changes separate from analysis implementations.

## License

AuditZoo is licensed under the [GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)](LICENSE).

This means:
- ✅ You can freely use, modify, and distribute this software
- ✅ Perfect for academic research and open-source projects
- ⚠️ If you run a modified version as a network service (e.g., SaaS, web application), you **must** make your source code available to users
- ⚠️ Any modifications or derivative works must also be licensed under AGPL-3.0

For commercial licensing options or if AGPL doesn't fit your use case, please contact us.

## Citation

If you use AuditZoo in your research, please cite:

```bibtex
@software{auditzoo,
  author = {Zhang, Zhuo},
  title = {AuditZoo: CPG-centered Agent-based Program Analysis Framework},
  year = {2025},
  url = {https://github.com/Biscope-AI/auditzoo}
}
```
