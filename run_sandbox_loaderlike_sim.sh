#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
SAMPLE_PATH="${ROOT_DIR}/samples/sandbox_loaderlike_sim.exe"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-300}"
REPORT_ID="${REPORT_ID:-sandbox_loaderlike_sim}"

if [[ ! -f "${SAMPLE_PATH}" ]]; then
  echo "Missing sample: ${SAMPLE_PATH}" >&2
  exit 1
fi

if [[ -f "${ROOT_DIR}/.venv/bin/activate" ]]; then
  # shellcheck disable=SC1091
  source "${ROOT_DIR}/.venv/bin/activate"
fi

cmd=(
  "${PYTHON_BIN}"
  "${ROOT_DIR}/sandbox/scripts/analyze_sample.py"
  "${SAMPLE_PATH}"
  "--report-id" "${REPORT_ID}"
  "--timeout-seconds" "${TIMEOUT_SECONDS}"
)

if [[ "${INSTALL_RUNTIME:-0}" == "1" ]]; then
  cmd+=("--install-runtime")
fi

if [[ -n "${TASK_PROFILE:-}" ]]; then
  cmd+=("--task-profile" "${TASK_PROFILE}")
fi

echo "+ ${cmd[*]}"
"${cmd[@]}"
