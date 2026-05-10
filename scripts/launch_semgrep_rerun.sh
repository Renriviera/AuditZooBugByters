#!/usr/bin/env bash
# Rerun Semgrep only on prior timeout/missing CVEs, then merge and report.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${PY:-/workspace/miniconda3/envs/iris/bin/python}"
PRIOR="${PRIOR:-${ROOT}/results/semgrep/20260507_143958}"
TS="$(/usr/bin/date +%Y%m%d_%H%M%S)"
LOG="${ROOT}/logs/semgrep_rerun_${TS}.log"
LLIO="${ROOT}/logs/semgrep_rerun_llm_io_${TS}.jsonl"
SEED_CACHE_DIR="${ROOT}/seeds/semgrep"
REPORT_DIR="${ROOT}/docs/reports"
MERGED_JSON="${REPORT_DIR}/semgrep_20260507_143958+rerun_${TS}.merged.json"
MERGE_SUMMARY="${REPORT_DIR}/semgrep_20260507_143958+rerun_${TS}.merge_summary.json"
LABEL="semgrep_20260507_143958+rerun_${TS}"

mkdir -p "${ROOT}/logs" "${REPORT_DIR}" "${SEED_CACHE_DIR}"
export PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:${PATH:-}"
export PYTHONUNBUFFERED=1
export OPENAI_API_KEY_FILE="${OPENAI_API_KEY_FILE:-${ROOT}/.openai_api_key}"

cd "${ROOT}"
if [[ ! -f "${OPENAI_API_KEY_FILE}" ]] && [[ -z "${OPENAI_API_KEY:-}" ]]; then
  echo "WARN: No API key yet - create ${ROOT}/.openai_api_key or export OPENAI_API_KEY before rerun LLM calls." >&2
fi

echo "Bootstrapping seed cache from ${PRIOR}" | tee "${LOG}"
FINGERPRINT="$("${PY}" -m splitEvaluations.seed_cache bootstrap-from-run \
  --prior-dir "${PRIOR}" \
  --cache-dir "${SEED_CACHE_DIR}")"
echo "Seed fingerprint: ${FINGERPRINT}" | tee -a "${LOG}"

echo "Picking rerun targets from ${PRIOR}" | tee -a "${LOG}"
TARGETS="$("${PY}" -m splitEvaluations.pick_rerun_targets --prior-dir "${PRIOR}" 2>>"${LOG}")"
TARGET_COUNT="$(wc -w <<<"${TARGETS}")"
if [[ "${TARGET_COUNT}" -eq 0 ]]; then
  echo "No rerun targets found; exiting." | tee -a "${LOG}"
  exit 0
fi
echo "Rerun targets (${TARGET_COUNT}): ${TARGETS}" | tee -a "${LOG}"

BEFORE_LIST="$(mktemp)"
AFTER_LIST="$(mktemp)"
trap 'rm -f "${BEFORE_LIST}" "${AFTER_LIST}"' EXIT
ls -1 "${ROOT}/results/semgrep" > "${BEFORE_LIST}" 2>/dev/null || true

echo "Starting Semgrep rerun with per_cve_timeout=2700s clone_timeout=1500s" | tee -a "${LOG}"
"${PY}" -m splitEvaluations.run_semgrep_sweep \
  --llm-url https://api.openai.com/v1 \
  --llm-model gpt-5.4-mini \
  --seed-model gpt-5.4-mini \
  --per-cve-timeout 2700 \
  --clone-timeout-s 1500 \
  --only-cves ${TARGETS} \
  --seed-cache-dir "${SEED_CACHE_DIR}" \
  --seed-cache-fingerprint "${FINGERPRINT}" \
  --seed-source-run-config "${PRIOR}/run_config.json" \
  --log-llm-io "${LLIO}" \
  >> "${LOG}" 2>&1

ls -1 "${ROOT}/results/semgrep" > "${AFTER_LIST}" 2>/dev/null || true
RERUN_NAME="$(comm -13 <(sort "${BEFORE_LIST}") <(sort "${AFTER_LIST}") | sort | tail -n 1)"
if [[ -z "${RERUN_NAME}" ]]; then
  RERUN_NAME="$(ls -1dt "${ROOT}/results/semgrep"/*/ | head -n 1 | xargs -n1 basename)"
fi
RERUN_DIR="${ROOT}/results/semgrep/${RERUN_NAME}"
echo "Rerun results: ${RERUN_DIR}" | tee -a "${LOG}"

"${PY}" -m splitEvaluations.merge_semgrep_runs \
  --prior "${PRIOR}/results.json" \
  --rerun "${RERUN_DIR}/results.json" \
  --out "${MERGED_JSON}" \
  --summary-out "${MERGE_SUMMARY}" \
  | tee -a "${LOG}"

"${PY}" -m splitEvaluations.build_rollup \
  --results "${MERGED_JSON}" \
  --run-config "${PRIOR}/run_config.json" \
  --seed-usage "${PRIOR}/seed_llm_usage.json" \
  --rerun-results "${RERUN_DIR}/results.json" \
  --prior-results "${PRIOR}/results.json" \
  --rerun-run-config "${RERUN_DIR}/run_config.json" \
  --seed-meta "${RERUN_DIR}/model_seed_cache_meta.json" \
  --out-dir "${REPORT_DIR}" \
  --label "${LABEL}" \
  | tee -a "${LOG}"

ln -sf "$(basename "${LOG}")" "${ROOT}/logs/semgrep_rerun_latest.log"
echo "Done. log=${LOG} llm_io=${LLIO} merged=${MERGED_JSON}" | tee -a "${LOG}"
