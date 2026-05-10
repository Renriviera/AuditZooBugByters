#!/usr/bin/env bash
# Joern CWE-78 sweep over the CVEs whose CPGs are already cached on disk
# (status=built or status=hit in joern_cpg_cache/build_summary.json), using
# the pre-generated seed catalog at results/joern_seed/full_catalog.json.
# Skips the per-sweep training-clones + LLM seed call entirely, and skips
# importCode for every CVE whose cache is hit.
#
# Required:
#   AUDITZOO_LLM_API_KEY="..." bash splitEvaluations/run_joern_cached_with_audit.sh
#
# Optional overrides:
#   AUDITZOO_LLM_URL, AUDITZOO_LLM_MODEL, AUDITZOO_DATASET, AUDITZOO_OUTPUT,
#   AUDITZOO_MAX_K, AUDITZOO_TIMEOUT, AUDITZOO_JOERN_PORT, AUDITZOO_JOERN_PATH,
#   AUDITZOO_CLONE_TIMEOUT, AUDITZOO_JOERN_HEAP (default 8g),
#   AUDITZOO_JOERN_JAVA_OPTS, AUDITZOO_CPG_CACHE_DIR (default
#   <output>/joern_cpg_cache), AUDITZOO_JOERN_SEED_CATALOG (default
#   <output>/joern_seed/full_catalog.json), AUDITZOO_CACHED_CVES_FILE
#   (default <cpg_cache_dir>/cached_cves.txt; one CVE id per line),
#   AUDITZOO_RUN_PATCHED=1
#
# Notes
# -----
# - The pipeline still clones each repo so that file-line context is
#   available for triage, but Joern's importCode is skipped for cache
#   hits (the canonical multi-hour cost).
# - --train-fraction is irrelevant here because the seed catalog is
#   loaded verbatim; run_joern_sweep evaluates *every* selected CVE
#   when --joern-seed-catalog is provided.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -f "${ROOT_DIR}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${ROOT_DIR}/.env"
  set +a
fi

if [[ -z "${AUDITZOO_LLM_API_KEY:-}" && -n "${OPENAI_API_KEY:-}" ]]; then
  export AUDITZOO_LLM_API_KEY="$OPENAI_API_KEY"
fi

if [[ -z "${AUDITZOO_LLM_API_KEY:-}" ]]; then
  echo "error: set AUDITZOO_LLM_API_KEY or OPENAI_API_KEY before running" >&2
  exit 2
fi

if [[ -f "/workspace/setup_env.sh" ]]; then
  # shellcheck disable=SC1091
  source "/workspace/setup_env.sh"
fi

if [[ -n "${PYTHON:-}" ]]; then
  PYTHON_BIN="$PYTHON"
elif [[ -x "/workspace/miniconda3/envs/iris/bin/python" ]]; then
  PYTHON_BIN="/workspace/miniconda3/envs/iris/bin/python"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
else
  echo "error: no Python interpreter found; set PYTHON=/path/to/python" >&2
  exit 2
fi

echo "[run_joern_cached_with_audit] Using Python: ${PYTHON_BIN}"

python_prefix="$("$PYTHON_BIN" - <<'PY'
import sys
print(sys.prefix)
PY
)"

if [[ "$PYTHON_BIN" == /workspace/miniconda3/envs/iris/bin/python || "$python_prefix" == /workspace/miniconda3/envs/iris ]]; then
  export CONDA_PREFIX="/workspace/miniconda3/envs/iris"
fi

for java_home_candidate in \
  "${python_prefix}/lib/jvm" \
  "${CONDA_PREFIX:-}/lib/jvm" \
  "/workspace/miniconda3/envs/iris/lib/jvm"; do
  if [[ -x "${java_home_candidate}/bin/java" ]]; then
    export JAVA_HOME="${JAVA_HOME:-$java_home_candidate}"
    export PATH="${java_home_candidate}/bin:${PATH}"
    break
  fi
done

if [[ -d "$python_prefix/bin" ]]; then
  export PATH="${python_prefix}/bin:${PATH}"
fi

if [[ -z "${AUDITZOO_JOERN_PATH:-}" ]]; then
  for candidate in \
    "${python_prefix}/opt/joern" \
    "/workspace/miniconda3/envs/iris/opt/joern" \
    "${CONDA_PREFIX:-}/opt/joern"; do
    if [[ -x "${candidate}/joern-cli/joern" ]]; then
      export AUDITZOO_JOERN_PATH="$candidate"
      break
    fi
  done
fi

if [[ -z "${AUDITZOO_JOERN_PATH:-}" || ! -x "${AUDITZOO_JOERN_PATH}/joern-cli/joern" ]]; then
  echo "error: Joern executable not found. Set AUDITZOO_JOERN_PATH to the Joern install root." >&2
  exit 2
fi

export AUDITZOO_CLONE_TIMEOUT="${AUDITZOO_CLONE_TIMEOUT:-600}"

HEAP="${AUDITZOO_JOERN_HEAP:-8g}"
DEFAULT_JAVA_OPTS="-Xmx${HEAP} -XX:+ExitOnOutOfMemoryError"
if [[ -n "${AUDITZOO_JOERN_JAVA_OPTS:-}" ]]; then
  export AUDITZOO_JOERN_JAVA_OPTS="${DEFAULT_JAVA_OPTS} ${AUDITZOO_JOERN_JAVA_OPTS}"
else
  export AUDITZOO_JOERN_JAVA_OPTS="${DEFAULT_JAVA_OPTS}"
fi

# IRView preload bypass.  ``preload_from_backend`` would otherwise issue
# ``cpg.tag.id(<n>L).filter(...).toJson`` once per CodeUnit (often >5k
# round-trips on real Python repos) and ``cpg.method.id(<n>L).callee``
# for every method.  The CWE-78 JoernArm queries Joern directly and
# never touches the IR-level fact graph, so both preloads are pure
# overhead — and they are the dominant cause of JVM OOMs / websocket
# drops we saw on the cached-CPG smoke run for CVE-2024-13129 (3508
# methods × ~3 s/query in a hot REPL > 8 GB heap).  Honour explicit
# overrides so future arms that DO need the facts can opt back in.
export AUDITZOO_SKIP_PRELOAD_FACTS="${AUDITZOO_SKIP_PRELOAD_FACTS:-1}"
export AUDITZOO_SKIP_PRELOAD_CALLS="${AUDITZOO_SKIP_PRELOAD_CALLS:-1}"

DATASET="${AUDITZOO_DATASET:-benchmark/python/cwe78_cves/metadata.json}"
OUTPUT_ROOT="${AUDITZOO_OUTPUT:-results}"
LLM_URL="${AUDITZOO_LLM_URL:-https://api.openai.com/v1}"
LLM_MODEL="${AUDITZOO_LLM_MODEL:-gpt-5.4-mini}"
SEED_MODEL="${AUDITZOO_SEED_MODEL:-gpt-5.4-mini}"
MAX_K="${AUDITZOO_MAX_K:-3}"
TIMEOUT="${AUDITZOO_TIMEOUT:-1800}"
JOERN_PORT="${AUDITZOO_JOERN_PORT:-12345}"
CPG_CACHE_DIR="${AUDITZOO_CPG_CACHE_DIR:-${OUTPUT_ROOT}/joern_cpg_cache}"
mkdir -p "${CPG_CACHE_DIR}"

CACHED_CVES_FILE="${AUDITZOO_CACHED_CVES_FILE:-${CPG_CACHE_DIR}/cached_cves.txt}"
if [[ ! -f "${CACHED_CVES_FILE}" ]]; then
  echo "[run_joern_cached_with_audit] Materialising cached CVE list at ${CACHED_CVES_FILE}"
  "$PYTHON_BIN" - "$CPG_CACHE_DIR" "$CACHED_CVES_FILE" <<'PY'
import json
import sys
from pathlib import Path

cache_dir = Path(sys.argv[1])
out_path = Path(sys.argv[2])
summary = json.loads((cache_dir / "build_summary.json").read_text())
ids = [r["cve_id"] for r in summary["records"] if r.get("status") in {"built", "hit"}]
out_path.parent.mkdir(parents=True, exist_ok=True)
out_path.write_text("\n".join(ids) + "\n")
print(f"wrote {out_path} ({len(ids)} CVE ids)")
PY
fi

mapfile -t CACHED_CVES < <(grep -v '^[[:space:]]*$' "${CACHED_CVES_FILE}" | sed 's/[[:space:]]*$//')
N_CVES="${#CACHED_CVES[@]}"
if (( N_CVES == 0 )); then
  echo "error: no CVE ids in ${CACHED_CVES_FILE}" >&2
  exit 2
fi

SEED_CATALOG_DEFAULT="${OUTPUT_ROOT}/joern_seed/full_catalog.json"
SEED_CATALOG="${AUDITZOO_JOERN_SEED_CATALOG:-$SEED_CATALOG_DEFAULT}"
if [[ ! -f "${SEED_CATALOG}" ]]; then
  echo "error: seed catalog not found at ${SEED_CATALOG} — run splitEvaluations/seed_joern_catalog.py first" >&2
  exit 2
fi

run_patched_args=()
if [[ "${AUDITZOO_RUN_PATCHED:-0}" == "1" ]]; then
  run_patched_args+=(--run-patched)
fi

echo "[run_joern_cached_with_audit] Using Joern: ${AUDITZOO_JOERN_PATH}/joern-cli/joern"
echo "[run_joern_cached_with_audit] Git clone/fetch timeout: ${AUDITZOO_CLONE_TIMEOUT}s"
echo "[run_joern_cached_with_audit] Joern JVM opts: ${AUDITZOO_JOERN_JAVA_OPTS}"
echo "[run_joern_cached_with_audit] IR preload: facts_skip=${AUDITZOO_SKIP_PRELOAD_FACTS} calls_skip=${AUDITZOO_SKIP_PRELOAD_CALLS}"
echo "[run_joern_cached_with_audit] CPG cache: ${CPG_CACHE_DIR}"
echo "[run_joern_cached_with_audit] Seed catalog: ${SEED_CATALOG}"
echo "[run_joern_cached_with_audit] Cached CVEs: ${N_CVES} (from ${CACHED_CVES_FILE})"
echo "[run_joern_cached_with_audit] LLM endpoint: ${LLM_URL} model=${LLM_MODEL}"
echo "[run_joern_cached_with_audit] max-k=${MAX_K} per-cve-timeout=${TIMEOUT}s"

cmd=(
  "$PYTHON_BIN" -m splitEvaluations.run_joern_sweep
  --dataset "$DATASET"
  --output "$OUTPUT_ROOT"
  --dataset-size full
  --train-fraction 0.25
  --max-k "$MAX_K"
  --seed 235711
  --per-cve-timeout "$TIMEOUT"
  --joern-port "$JOERN_PORT"
  --llm-url "$LLM_URL"
  --llm-model "$LLM_MODEL"
  --seed-model "$SEED_MODEL"
  --cpg-cache-dir "$CPG_CACHE_DIR"
  --joern-seed-catalog "$SEED_CATALOG"
  --only-cves "${CACHED_CVES[@]}"
)
cmd+=("${run_patched_args[@]}")
"${cmd[@]}"

RESULTS_JSON="$(
  AUDITZOO_OUTPUT_ROOT="$OUTPUT_ROOT" "$PYTHON_BIN" - <<'PY'
from pathlib import Path
import os
import sys

root = Path(os.environ["AUDITZOO_OUTPUT_ROOT"]) / "joern"
matches = sorted(root.glob("*/results.json"))
if not matches:
    print("error: no Joern results.json files found", file=sys.stderr)
    raise SystemExit(2)
print(matches[-1])
PY
)"
SWEEP_DIR="$(dirname "$RESULTS_JSON")"
AUDIT_DIR="${SWEEP_DIR}/audit"

echo "[run_joern_cached_with_audit] Running FP/FN audit: ${RESULTS_JSON}"
# --score-uncertain-on-gt-as-tp surfaces the Fix-#3 visibility pane in
# stdout so we can see how many GT clusters are blocked solely by the
# hallucination brake.  The pane is always emitted in the JSON, but
# off-stdout by default to keep the canonical TP/FP/FN print untouched.
"$PYTHON_BIN" -m splitEvaluations.audit_joern_results \
  "$RESULTS_JSON" \
  --dataset "$DATASET" \
  --line-tolerance 5 \
  --output-dir "$AUDIT_DIR" \
  --score-uncertain-on-gt-as-tp

echo "[run_joern_cached_with_audit] Sweep directory: ${SWEEP_DIR}"
echo "[run_joern_cached_with_audit] Audit JSON: ${AUDIT_DIR}/joern_fp_fn_audit.json"
echo "[run_joern_cached_with_audit] FP rows: ${AUDIT_DIR}/fp_rows.csv"
echo "[run_joern_cached_with_audit] FN rows: ${AUDIT_DIR}/fn_rows.csv"
echo "[run_joern_cached_with_audit] Iteration summary: ${AUDIT_DIR}/iteration_summary.csv"
