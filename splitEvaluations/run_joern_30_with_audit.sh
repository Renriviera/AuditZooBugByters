#!/usr/bin/env bash
# Run the 30-CVE Joern CWE-78 sweep and immediately audit FP/FN results.
#
# Required:
#   AUDITZOO_LLM_API_KEY="..." bash splitEvaluations/run_joern_30_with_audit.sh
#
# Optional overrides:
#   AUDITZOO_LLM_URL, AUDITZOO_LLM_MODEL, AUDITZOO_SEED_MODEL,
#   AUDITZOO_DATASET, AUDITZOO_OUTPUT, AUDITZOO_MAX_K, AUDITZOO_TIMEOUT,
#   AUDITZOO_JOERN_PORT, AUDITZOO_JOERN_PATH, AUDITZOO_CLONE_TIMEOUT,
#   AUDITZOO_JOERN_HEAP (default 8g), AUDITZOO_JOERN_JAVA_OPTS (extra JVM flags),
#   AUDITZOO_CPG_CACHE_DIR (CPG cache root; default <output>/joern_cpg_cache),
#   AUDITZOO_RUN_PATCHED=1

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

echo "[run_joern_30_with_audit] Using Python: ${PYTHON_BIN}"

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

# JVM tuning for the Joern REPL.  The 20260507_145628 sweep died with
# OutOfMemoryError: Java heap space on several CVEs because Joern's
# default ~512 MB heap can't pretty-print large taint flows on Python
# CPGs the size of django/numpy.  We lift the cap to 8 GB (well under
# the 124 GB container budget — leaves room for parallel CPG cache
# writes) and tell the JVM to die immediately on OOM so the per-CVE
# port cleanup short-circuits instead of waiting on a comatose REPL.
HEAP="${AUDITZOO_JOERN_HEAP:-8g}"
DEFAULT_JAVA_OPTS="-Xmx${HEAP} -XX:+ExitOnOutOfMemoryError"
if [[ -n "${AUDITZOO_JOERN_JAVA_OPTS:-}" ]]; then
  export AUDITZOO_JOERN_JAVA_OPTS="${DEFAULT_JAVA_OPTS} ${AUDITZOO_JOERN_JAVA_OPTS}"
else
  export AUDITZOO_JOERN_JAVA_OPTS="${DEFAULT_JAVA_OPTS}"
fi

echo "[run_joern_30_with_audit] Using Joern: ${AUDITZOO_JOERN_PATH}/joern-cli/joern"
echo "[run_joern_30_with_audit] Git clone/fetch timeout: ${AUDITZOO_CLONE_TIMEOUT}s"
echo "[run_joern_30_with_audit] Joern JVM opts: ${AUDITZOO_JOERN_JAVA_OPTS}"
echo "[run_joern_30_with_audit] LLM I/O trace: <output>/joern/<ts>/llm_io.jsonl (auto-enabled by run_joern_sweep)"

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
echo "[run_joern_30_with_audit] CPG cache: ${CPG_CACHE_DIR}"

run_patched_args=()
if [[ "${AUDITZOO_RUN_PATCHED:-0}" == "1" ]]; then
  run_patched_args+=(--run-patched)
fi

echo "[run_joern_30_with_audit] Starting Joern sweep: dataset-size=30 train=0.25 max-k=${MAX_K}"
echo "[run_joern_30_with_audit] LLM endpoint: ${LLM_URL}"
cmd=(
  "$PYTHON_BIN" -m splitEvaluations.run_joern_sweep
  --dataset "$DATASET"
  --output "$OUTPUT_ROOT"
  --dataset-size 30
  --train-fraction 0.25
  --max-k "$MAX_K"
  --seed 235711
  --per-cve-timeout "$TIMEOUT"
  --joern-port "$JOERN_PORT"
  --llm-url "$LLM_URL"
  --llm-model "$LLM_MODEL"
  --seed-model "$SEED_MODEL"
  --cpg-cache-dir "$CPG_CACHE_DIR"
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

echo "[run_joern_30_with_audit] Running FP/FN audit: ${RESULTS_JSON}"
"$PYTHON_BIN" -m splitEvaluations.audit_joern_results \
  "$RESULTS_JSON" \
  --dataset "$DATASET" \
  --line-tolerance 5 \
  --output-dir "$AUDIT_DIR"

echo "[run_joern_30_with_audit] Sweep directory: ${SWEEP_DIR}"
echo "[run_joern_30_with_audit] Audit JSON: ${AUDIT_DIR}/joern_fp_fn_audit.json"
echo "[run_joern_30_with_audit] FP rows: ${AUDIT_DIR}/fp_rows.csv"
echo "[run_joern_30_with_audit] FN rows: ${AUDIT_DIR}/fn_rows.csv"
echo "[run_joern_30_with_audit] Iteration summary: ${AUDIT_DIR}/iteration_summary.csv"
