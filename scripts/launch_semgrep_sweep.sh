#!/usr/bin/env bash
# Full Semgrep sweep against OpenAI cloud. Uses OPENAI_API_KEY_FILE (preferred) or OPENAI_API_KEY.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${PY:-/workspace/miniconda3/envs/iris/bin/python}"
TS="$(/usr/bin/date +%Y%m%d_%H%M%S)"
LOG="${ROOT}/logs/semgrep_full_${TS}.log"
LLIO="${ROOT}/logs/semgrep_llm_io_${TS}.jsonl"
mkdir -p "${ROOT}/logs"
# Ensure git(1) resolves for subprocess even when the parent shell's PATH is minimal.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:${PATH:-}"
# Line-buffer logs when stdout is redirected (otherwise `tail -f` can look "stuck").
export PYTHONUNBUFFERED=1
export OPENAI_API_KEY_FILE="${OPENAI_API_KEY_FILE:-${ROOT}/.openai_api_key}"
cd "${ROOT}"
if [[ ! -f "${OPENAI_API_KEY_FILE}" ]] && [[ -z "${OPENAI_API_KEY:-}" ]]; then
  echo "WARN: No API key yet — create ${ROOT}/.openai_api_key (one line) or export OPENAI_API_KEY before the seed LLM call." >&2
fi
nohup "${PY}" -m splitEvaluations.run_semgrep_sweep \
  --llm-url https://api.openai.com/v1 \
  --llm-model gpt-5.4-mini \
  --seed-model gpt-5.4-mini \
  --clone-timeout-s 600 \
  --log-llm-io "${LLIO}" \
  > "${LOG}" 2>&1 &
echo $! > "${ROOT}/logs/semgrep_full_run.pid"
ln -sf "$(basename "${LOG}")" "${ROOT}/logs/semgrep_full_latest.log"
echo "Started pid=$(cat "${ROOT}/logs/semgrep_full_run.pid") log=${LOG} llm_io=${LLIO}"
