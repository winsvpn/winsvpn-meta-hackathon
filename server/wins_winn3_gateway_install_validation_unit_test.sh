#!/usr/bin/env bash
# Pure installer function/render regressions. No install, service, or firewall calls.
# Usage: bash wins_winn3_gateway_install_validation_unit_test.sh [installer-path]
set -euo pipefail
# OI-K4 (Round K): the installer reads MemTotal for host fit and fails closed
# without it. These cases test other properties, so they run against a
# 128 TiB fixture on which every explicit session count fits and an unset
# count still selects 64.
export WINN3_GATEWAY_MEMINFO="${WINN3_GATEWAY_MEMINFO:-$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/testdata/winn3_gateway_meminfo/large}"

HERE="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
if [[ "${1:-}" != "--case" ]]; then
  INSTALL="$(python3 -B "${HERE}/../tools/winn3_gateway_test_source.py" "${1:-${HERE}/wins_data_plane_setup_ONETOUCH.sh}")"
  passed=0
  failed=0
  for test_case in recompute overrides partial ordering sessions ingest_off ingest_on ingest_invalid; do
    # TUNNEL-SPEED-2 OI-4: the recompute figures are the capped formula's, so
    # every case runs with WINN3_GATEWAY_DEDICATED=0 (the data-plane default
    # is 1) and with the payment-server probe at a path that does not exist.
    if env -i PATH=/usr/bin:/bin LC_ALL=C WINN3_GATEWAY_MEMINFO="${WINN3_GATEWAY_MEMINFO}" \
        WINN3_GATEWAY_DEDICATED=0 WINN3_GATEWAY_PAYMENT_UNIT=/nonexistent/monero-wallet-rpc.service \
        /bin/bash "$0" --case "${test_case}" "${INSTALL}"; then
      printf 'PASS %s\n' "${test_case}"
      passed=$((passed + 1))
    else
      printf 'FAIL %s\n' "${test_case}" >&2
      failed=$((failed + 1))
    fi
  done
  printf 'SUMMARY pass=%s fail=%s\n' "${passed}" "${failed}"
  [[ "${failed}" == "0" ]]
  exit
fi

test_case="$2"
INSTALL="$3"
# Synthetic inputs only; the parent launches each case with a clean environment.
WINN3_GATEWAY_ID=synthetic-test
WINN3_GATEWAY_PATH_MTU=1450
WINN3_GATEWAY_INNER_V4=192.0.2.1
WINN3_GATEWAY_FORWARD_IF=synthetic0
WINN3_GATEWAY_FORWARD_CIDR=192.0.2.0/24
# shellcheck disable=SC1090
source "${INSTALL}"

case "${test_case}" in
  recompute)
    # Unset count: host fit on the 128 TiB fixture selects 64, so
    # 208M + 64 MiB * 64 = 4304M; an explicit 128 then recomputes 8400M.
    # Each check exits on its own: the installer block this case sources
    # turns errexit off, so a bare [[ ]] here used to be ignored and the
    # case passed on the old 2656M/5216M after the formula moved.
    resolve_gateway_memory 2>/dev/null
    [[ "${WINN3_GATEWAY_EFFECTIVE_MEMORY_MAX:-}" == 4304M ]] || exit 1
    WINN3_GATEWAY_MAX_SESSIONS=128
    resolve_gateway_memory 2>/dev/null
    [[ "${WINN3_GATEWAY_EFFECTIVE_MEMORY_MAX:-}" == 8400M ]] || exit 1
    [[ -z "${WINN3_GATEWAY_MEMORY_MAX+x}${WINN3_GATEWAY_MEMORY_HIGH+x}${WINN3_GATEWAY_GOMEMLIMIT+x}" ]]
    ;;
  overrides)
    WINN3_GATEWAY_MEMORY_MAX=512M
    WINN3_GATEWAY_MEMORY_HIGH=384M
    WINN3_GATEWAY_GOMEMLIMIT=300MiB
    for n in 64 128; do
      WINN3_GATEWAY_MAX_SESSIONS="${n}"
      derive_gateway_memory
      [[ "${WINN3_GATEWAY_MEMORY_MAX}:${WINN3_GATEWAY_MEMORY_HIGH}:${WINN3_GATEWAY_GOMEMLIMIT}" == 512M:384M:300MiB ]]
      [[ "${WINN3_GATEWAY_EFFECTIVE_MEMORY_MAX:-}:${WINN3_GATEWAY_EFFECTIVE_MEMORY_HIGH:-}:${WINN3_GATEWAY_EFFECTIVE_GOMEMLIMIT:-}" == 512M:384M:300MiB ]]
    done
    ;;
  partial)
    WINN3_GATEWAY_MEMORY_MAX=512M
    if derive_gateway_memory >/dev/null 2>&1; then exit 1; fi
    [[ "${WINN3_GATEWAY_MEMORY_MAX}" == 512M ]]
    ;;
  ordering)
    WINN3_GATEWAY_MEMORY_MAX=160M
    WINN3_GATEWAY_MEMORY_HIGH=160M
    WINN3_GATEWAY_GOMEMLIMIT=96MiB
    if derive_gateway_memory >/dev/null 2>&1; then exit 1; fi
    WINN3_GATEWAY_MEMORY_HIGH=120M
    WINN3_GATEWAY_GOMEMLIMIT=120MiB
    if derive_gateway_memory >/dev/null 2>&1; then exit 1; fi
    WINN3_GATEWAY_GOMEMLIMIT=121MiB
    if derive_gateway_memory >/dev/null 2>&1; then exit 1; fi
    ;;
  sessions)
    WINN3_GATEWAY_MEMORY_MAX=160M
    WINN3_GATEWAY_MEMORY_HIGH=120M
    WINN3_GATEWAY_GOMEMLIMIT=96MiB
    for n in 0 064 1000001 18446744073709551617; do
      WINN3_GATEWAY_MAX_SESSIONS="${n}"
      if derive_gateway_memory >/dev/null 2>&1; then exit 1; fi
    done
    ;;
  ingest_off)
    WINN3_GATEWAY_FORWARD=1
    [[ "${WINN3_GATEWAY_SPEEDTEST_INGEST_PORT}" == 0 ]]
    unit="$(emit_unit_text)"
    if [[ "${unit}" == *'-speedtest-ingest-port'* || "${unit}" == *'tcp:8455'* ]]; then exit 1; fi
    if [[ "${unit}" == *speedtest_ingest_line* ]]; then exit 1; fi
    WINN3_GATEWAY_FORWARD=0
    WINN3_GATEWAY_SPEEDTEST_INGEST_PORT=8455
    unit="$(emit_unit_text)"
    if [[ "${unit}" == *'-speedtest-ingest-port'* || "${unit}" == *'tcp:8455'* ]]; then exit 1; fi
    ;;
  ingest_on)
    WINN3_GATEWAY_FORWARD=1
    WINN3_GATEWAY_SPEEDTEST_INGEST_PORT=8455
    unit="$(emit_unit_text)"
    flags=0
    binds=0
    while IFS= read -r line; do
      if [[ "${line}" == *'-speedtest-ingest-port'* ]]; then
        [[ "${line}" == '  -speedtest-ingest-port 8455' ]]
        flags=$((flags + 1))
      fi
      if [[ "${line}" == *'tcp:8455'* ]]; then
        [[ "${line}" == 'SocketBindAllow=ipv4:tcp:8455' ]]
        binds=$((binds + 1))
      fi
    done <<< "${unit}"
    [[ "${flags}" == 1 && "${binds}" == 1 ]]
    [[ "${unit}" == *$' \\\n  -speedtest-ingest-port 8455\n'* ]]
    if [[ "${unit}" == *speedtest_ingest_line* ]]; then exit 1; fi
    ;;
  ingest_invalid)
    for forward in 0 1; do
      WINN3_GATEWAY_FORWARD="${forward}"
      for port in 8456 08455 invalid; do
        WINN3_GATEWAY_SPEEDTEST_INGEST_PORT="${port}"
        if emit_unit_text >/dev/null 2>&1; then exit 1; fi
        if emit_env_text >/dev/null 2>&1; then exit 1; fi
      done
    done
    ;;
  *) exit 2 ;;
esac
