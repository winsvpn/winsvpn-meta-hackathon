#!/usr/bin/env bash
# Materialize one local, evidence-derived dashboard snapshot.
# Gate execution happens only in this explicit local sync phase. The resulting
# cached evidence is bounded and immutable. Snapshot rendering and HTTP GET
# consume that cache read-only and never create verification directories.
# This script performs no network, Git, upload, or deployment operation.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
DASHBOARD_REPO="${WINSVPN_DASHBOARD_REPO_ROOT:-${REPO_ROOT}}"
PYTHON_BIN="${WINSVPN_DASHBOARD_PYTHON:-python3}"
CONFIG="${WINSVPN_DASHBOARD_CONFIG:-${REPO_ROOT}/dashboard/state.json}"
EVIDENCE_ROOT="${WINSVPN_DASHBOARD_EVIDENCE_DIR:-${DASHBOARD_REPO}/.artifacts/dashboard/evidence}"
SNAPSHOT="${WINSVPN_DASHBOARD_SNAPSHOT:-${DASHBOARD_REPO}/.artifacts/dashboard/state.snapshot.json}"
CACHE="${WINSVPN_DASHBOARD_CROSS_STORE_CACHE:-${DASHBOARD_REPO}/.artifacts/dashboard/cross-store-cache.json}"
LOCK_DIR="${SNAPSHOT}.lock"
EXPIRED_SNAPSHOT="${SNAPSHOT}.expired-do-not-use"
WATCH_SECONDS=0

if [[ "${1:-}" == "--watch" ]]; then
  if [[ "$#" -eq 1 ]]; then
    WATCH_SECONDS=5
    shift
  else
    WATCH_SECONDS="$2"
    shift 2
  fi
elif [[ "$#" -ne 0 ]]; then
  printf 'usage: %s [--watch [2..60]]\n' "$0" >&2
  exit 64
fi
if [[ ! "${WATCH_SECONDS}" =~ ^[0-9]+$ ]] || (( WATCH_SECONDS != 0 && (WATCH_SECONDS < 2 || WATCH_SECONDS > 60) )); then
  printf 'dashboard sync refused: watch interval must be 2 through 60 seconds\n' >&2
  exit 64
fi

mkdir -p -- "$(dirname -- "${SNAPSHOT}")" "$(dirname -- "${CACHE}")"
if ! mkdir -- "${LOCK_DIR}" 2>/dev/null; then
  printf 'dashboard sync refused: another sync owns %s\n' "${LOCK_DIR}" >&2
  exit 75
fi

cleanup() {
  rm -f -- "${LOCK_DIR}/pid"
  rmdir -- "${LOCK_DIR}" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

printf '%s\n' "$$" > "${LOCK_DIR}/pid"
while true; do
  if [[ -e "${SNAPSHOT}" || -L "${SNAPSHOT}" ]]; then
    mv -f -- "${SNAPSHOT}" "${EXPIRED_SNAPSHOT}"
  fi
  sync_status=0
  "${PYTHON_BIN}" "${REPO_ROOT}/dashboard/server.py" \
    --config "${CONFIG}" \
    --repo-root "${DASHBOARD_REPO}" \
    --cache "${CACHE}" \
    --refresh-cross-store-cache || sync_status=$?
  if (( sync_status == 0 )); then
    "${PYTHON_BIN}" "${REPO_ROOT}/dashboard/server.py" \
      --config "${CONFIG}" \
      --evidence-root "${EVIDENCE_ROOT}" \
      --repo-root "${DASHBOARD_REPO}" \
      --cache "${CACHE}" \
      --snapshot "${SNAPSHOT}" || sync_status=$?
  fi
  if (( sync_status != 0 )); then
    failure_status=0
    "${PYTHON_BIN}" "${REPO_ROOT}/dashboard/server.py" \
      --failure-snapshot "${SNAPSHOT}" || failure_status=$?
    rm -f -- "${EXPIRED_SNAPSHOT}"
    if (( failure_status != 0 )); then
      exit "${failure_status}"
    fi
    if (( WATCH_SECONDS == 0 )); then
      exit "${sync_status}"
    fi
  else
    rm -f -- "${EXPIRED_SNAPSHOT}"
  fi
  (( WATCH_SECONDS > 0 )) || break
  sleep "${WATCH_SECONDS}"
done
