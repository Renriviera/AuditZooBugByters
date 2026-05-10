#!/usr/bin/env bash
# Semgrep-only baseline (zero-LLM): k=0, --no-triage, validation CVEs from
# the prior 20260507_143958 sweep, cached LLM-derived seed YAML reused
# verbatim.  Output lands in a fresh results/semgrep/<timestamp>/ dir;
# no prior result, log, or seed cache file is touched.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${PY:-/workspace/miniconda3/envs/iris/bin/python}"
PRIOR="${PRIOR:-${ROOT}/results/semgrep/20260507_143958}"
SEED_CACHE_DIR="${ROOT}/seeds/semgrep"
SEED_FINGERPRINT="${SEED_FINGERPRINT:-a0598ac7f4d195de}"
TS="$(/usr/bin/date +%Y%m%d_%H%M%S)"
LOG="${ROOT}/logs/semgrep_baseline_${TS}.log"

mkdir -p "${ROOT}/logs"
export PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:${PATH:-}"
export PYTHONUNBUFFERED=1

cd "${ROOT}"

if [[ ! -f "${PRIOR}/run_config.json" ]]; then
  echo "ERROR: prior run_config.json not found at ${PRIOR}/run_config.json" >&2
  exit 1
fi
if [[ ! -f "${SEED_CACHE_DIR}/${SEED_FINGERPRINT}.yaml" ]]; then
  echo "ERROR: cached seed YAML not found at ${SEED_CACHE_DIR}/${SEED_FINGERPRINT}.yaml" >&2
  exit 1
fi

# Resolve the validation CVE list from the prior run.  --only-cves on its
# own forces targeted_rerun=True in run_semgrep_sweep.py, which pairs with
# --seed-cache-fingerprint to load the cached seed without any LLM call.
mapfile -t VALIDATION_CVES < <("${PY}" -c "
import json, pathlib, sys
cfg = json.loads(pathlib.Path(sys.argv[1]).read_text())
for cve in cfg.get('validation_cves', []):
    print(cve)
" "${PRIOR}/run_config.json")
TARGET_COUNT="${#VALIDATION_CVES[@]}"
if [[ "${TARGET_COUNT}" -eq 0 ]]; then
  echo "ERROR: no validation CVEs found in ${PRIOR}/run_config.json" >&2
  exit 1
fi
echo "Resolved ${TARGET_COUNT} validation CVEs from ${PRIOR}" | tee "${LOG}"
echo "Seed cache: ${SEED_CACHE_DIR}/${SEED_FINGERPRINT}.yaml" | tee -a "${LOG}"

echo "Starting Semgrep baseline (no_triage=True, max_k=0)" | tee -a "${LOG}"
nohup "${PY}" -m splitEvaluations.run_semgrep_sweep \
  --no-triage \
  --max-k 0 \
  --per-cve-timeout 900 \
  --clone-timeout-s 600 \
  --seed-cache-dir "${SEED_CACHE_DIR}" \
  --seed-cache-fingerprint "${SEED_FINGERPRINT}" \
  --seed-source-run-config "${PRIOR}/run_config.json" \
  --only-cves "${VALIDATION_CVES[@]}" \
  >> "${LOG}" 2>&1 &
echo $! > "${ROOT}/logs/semgrep_baseline_run.pid"
ln -sf "$(basename "${LOG}")" "${ROOT}/logs/semgrep_baseline_latest.log"
echo "Started pid=$(cat "${ROOT}/logs/semgrep_baseline_run.pid") log=${LOG}"
