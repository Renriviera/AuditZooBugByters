#!/usr/bin/env bash
# Full validation re-run for the Joern CWE-78 sweep with the structural-evidence
# fix and the new cluster/hunk-relaxed audit panes.  Designed to be robust
# against the v2-style "task_done() called too many times" stall that exits the
# sweep process with code 124 mid-run: the wrapper detects that, computes the
# CVEs that have not yet been written to results.json, and relaunches the
# sweep with --only-cves restricted to the remaining set.
#
# Required:
#   AUDITZOO_LLM_API_KEY="..." bash splitEvaluations/run_joern_validation_full.sh
#
# Optional overrides (forwarded to run_joern_sweep + the audit step):
#   AUDITZOO_OUTPUT          (default results)
#   AUDITZOO_DATASET         (default benchmark/python/cwe78_cves/metadata.json)
#   AUDITZOO_LLM_URL         (default https://api.openai.com/v1)
#   AUDITZOO_LLM_MODEL       (default gpt-5.4-mini)
#   AUDITZOO_SEED_MODEL      (default gpt-5.4-mini)
#   AUDITZOO_MAX_K           (default 3)
#   AUDITZOO_TIMEOUT         (default 1200; per-CVE wall-clock budget)
#   AUDITZOO_JOERN_PORT      (default 12345)
#   AUDITZOO_JOERN_HEAP      (default 8g)
#   AUDITZOO_CPG_CACHE_DIR   (default <output>/joern_cpg_cache)
#   AUDITZOO_JOERN_SEED_CATALOG
#                            (default <output>/joern_seed/full_catalog_clean.json,
#                             falling back to full_catalog_merged.json then
#                             full_catalog.json.  full_catalog_clean.json is
#                             produced by splitEvaluations/clean_seed_catalog.py
#                             and is the post-blacklist/disjointness output.)
#   AUDITZOO_CACHED_CVES_FILE
#                            (default <cpg_cache_dir>/cached_cves.txt)
#   AUDITZOO_VALIDATION_LOG  (default logs/joern_validation_full_<timestamp>.log)
#   AUDITZOO_SWEEP_DIR       (resume into this existing sweep dir; defaults to
#                             a fresh timestamped dir inside <output>/joern)
#   AUDITZOO_MAX_RESUMES     (default 4; bail after this many resume cycles)

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

# IRView preload bypass keeps memory low and avoids the 8g-heap OOM seen on
# CVE-2024-13129 (3508 methods x ~3 s/query in a hot REPL).
export AUDITZOO_SKIP_PRELOAD_FACTS="${AUDITZOO_SKIP_PRELOAD_FACTS:-1}"
export AUDITZOO_SKIP_PRELOAD_CALLS="${AUDITZOO_SKIP_PRELOAD_CALLS:-1}"

DATASET="${AUDITZOO_DATASET:-benchmark/python/cwe78_cves/metadata.json}"
OUTPUT_ROOT="${AUDITZOO_OUTPUT:-results}"
LLM_URL="${AUDITZOO_LLM_URL:-https://api.openai.com/v1}"
LLM_MODEL="${AUDITZOO_LLM_MODEL:-gpt-5.4-mini}"
SEED_MODEL="${AUDITZOO_SEED_MODEL:-gpt-5.4-mini}"
MAX_K="${AUDITZOO_MAX_K:-3}"
# Drop default to 1200s — long enough for the slowest legitimate Joern arm we
# have observed on cached CVEs (~900s on CVE-2025-64340) but short enough that
# a stall costs less wall-clock before resume.
TIMEOUT="${AUDITZOO_TIMEOUT:-1200}"
JOERN_PORT="${AUDITZOO_JOERN_PORT:-12345}"
CPG_CACHE_DIR="${AUDITZOO_CPG_CACHE_DIR:-${OUTPUT_ROOT}/joern_cpg_cache}"
mkdir -p "${CPG_CACHE_DIR}"

CACHED_CVES_FILE="${AUDITZOO_CACHED_CVES_FILE:-${CPG_CACHE_DIR}/cached_cves.txt}"
if [[ ! -f "${CACHED_CVES_FILE}" ]]; then
  echo "[run_joern_validation_full] Materialising cached CVE list at ${CACHED_CVES_FILE}"
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

mapfile -t ALL_CVES < <(grep -v '^[[:space:]]*$' "${CACHED_CVES_FILE}" | sed 's/[[:space:]]*$//')
N_TOTAL="${#ALL_CVES[@]}"
if (( N_TOTAL == 0 )); then
  echo "error: no CVE ids in ${CACHED_CVES_FILE}" >&2
  exit 2
fi

# Prefer the post-blacklist clean catalog (splitEvaluations/clean_seed_catalog.py)
# when present, then fall back to the merged catalog, then to the LLM-seed base.
SEED_CATALOG_DEFAULT="${OUTPUT_ROOT}/joern_seed/full_catalog_clean.json"
if [[ ! -f "${SEED_CATALOG_DEFAULT}" ]]; then
  SEED_CATALOG_DEFAULT="${OUTPUT_ROOT}/joern_seed/full_catalog_merged.json"
fi
if [[ ! -f "${SEED_CATALOG_DEFAULT}" ]]; then
  SEED_CATALOG_DEFAULT="${OUTPUT_ROOT}/joern_seed/full_catalog.json"
fi
SEED_CATALOG="${AUDITZOO_JOERN_SEED_CATALOG:-$SEED_CATALOG_DEFAULT}"
if [[ ! -f "${SEED_CATALOG}" ]]; then
  echo "error: seed catalog not found at ${SEED_CATALOG}" >&2
  exit 2
fi

run_patched_args=()
if [[ "${AUDITZOO_RUN_PATCHED:-0}" == "1" ]]; then
  run_patched_args+=(--run-patched)
fi

# Either resume into a caller-supplied sweep dir or create a fresh timestamped
# dir under <output>/joern.  Re-using a sweep dir is what makes the auto-resume
# loop work: the python harness streams completed CVE rows into results.json.
if [[ -n "${AUDITZOO_SWEEP_DIR:-}" ]]; then
  SWEEP_DIR="${AUDITZOO_SWEEP_DIR}"
  mkdir -p "$SWEEP_DIR"
else
  SWEEP_DIR="$("$PYTHON_BIN" - "$OUTPUT_ROOT" <<'PY'
import os
import sys
import time
from pathlib import Path

output_root = Path(sys.argv[1])
joern_root = output_root / "joern"
joern_root.mkdir(parents=True, exist_ok=True)
ts = time.strftime("%Y%m%d_%H%M%S")
new_dir = joern_root / ts
new_dir.mkdir(parents=True, exist_ok=False)
print(new_dir)
PY
)"
fi

LOG_FILE="${AUDITZOO_VALIDATION_LOG:-logs/joern_validation_full_$(basename "$SWEEP_DIR").log}"
mkdir -p "$(dirname "$LOG_FILE")"
MAX_RESUMES="${AUDITZOO_MAX_RESUMES:-4}"

echo "[run_joern_validation_full] Sweep directory: ${SWEEP_DIR}"
echo "[run_joern_validation_full] Log: ${LOG_FILE}"
echo "[run_joern_validation_full] Total cached CVEs: ${N_TOTAL}"
echo "[run_joern_validation_full] Per-CVE timeout: ${TIMEOUT}s"
echo "[run_joern_validation_full] max-k=${MAX_K}"
echo "[run_joern_validation_full] Seed catalog: ${SEED_CATALOG}"

# Compute remaining CVEs by diffing against any existing results.json.
remaining_cves() {
  local results="$1"; shift
  local all=("$@")
  if [[ ! -f "$results" ]]; then
    printf '%s\n' "${all[@]}"
    return
  fi
  "$PYTHON_BIN" - "$results" "${all[@]}" <<'PY'
import json, sys
results_path = sys.argv[1]
all_cves = sys.argv[2:]
try:
    rows = json.loads(open(results_path).read())
    done = {row.get("cve_id") for row in rows
            if isinstance(row, dict) and (row.get("arms") or row.get("skipped"))}
except Exception:
    done = set()
for cve in all_cves:
    if cve not in done:
        print(cve)
PY
}

attempt=0
while :; do
  RESULTS_JSON="${SWEEP_DIR}/results.json"
  mapfile -t REMAINING < <(remaining_cves "$RESULTS_JSON" "${ALL_CVES[@]}")
  N_REMAINING="${#REMAINING[@]}"
  N_DONE=$(( N_TOTAL - N_REMAINING ))
  echo "[run_joern_validation_full] Cycle ${attempt}: ${N_DONE}/${N_TOTAL} done, ${N_REMAINING} remaining"
  if (( N_REMAINING == 0 )); then
    echo "[run_joern_validation_full] All CVEs processed"
    break
  fi
  if (( attempt >= MAX_RESUMES )); then
    echo "[run_joern_validation_full] Reached AUDITZOO_MAX_RESUMES=${MAX_RESUMES}; giving up"
    break
  fi

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
    --output-subdir "$(basename "$SWEEP_DIR")"
    --only-cves "${REMAINING[@]}"
  )
  cmd+=("${run_patched_args[@]}")

  echo "[run_joern_validation_full] Launching cycle ${attempt}: --only-cves count=${N_REMAINING}"
  set +e
  "${cmd[@]}" 2>&1 | tee -a "$LOG_FILE"
  rc=${PIPESTATUS[0]}
  set -e
  echo "[run_joern_validation_full] Cycle ${attempt} exit code: ${rc}"
  if (( rc == 0 )); then
    break
  fi
  if (( rc == 124 )); then
    echo "[run_joern_validation_full] SystemExit(124) detected (cancel hang); will resume"
    pkill -f 'java.*joern' 2>/dev/null || true
    sleep 5
    attempt=$(( attempt + 1 ))
    continue
  fi
  echo "[run_joern_validation_full] Unexpected non-zero exit; aborting" >&2
  exit "$rc"
done

# Audit step: rich panes + Fix #2/#3 lanes.
RESULTS_JSON="${SWEEP_DIR}/results.json"
AUDIT_DIR="${SWEEP_DIR}/audit"
echo "[run_joern_validation_full] Running FP/FN audit: ${RESULTS_JSON}"
"$PYTHON_BIN" -m splitEvaluations.audit_joern_results \
  "$RESULTS_JSON" \
  --dataset "$DATASET" \
  --line-tolerance 5 \
  --output-dir "$AUDIT_DIR" \
  --score-uncertain-on-gt-as-tp 2>&1 | tee -a "$LOG_FILE"

echo "[run_joern_validation_full] Sweep directory: ${SWEEP_DIR}"
echo "[run_joern_validation_full] Audit JSON: ${AUDIT_DIR}/joern_fp_fn_audit.json"
echo "[run_joern_validation_full] FP rows: ${AUDIT_DIR}/fp_rows.csv"
echo "[run_joern_validation_full] FN rows: ${AUDIT_DIR}/fn_rows.csv"
echo "[run_joern_validation_full] Iteration summary: ${AUDIT_DIR}/iteration_summary.csv"
