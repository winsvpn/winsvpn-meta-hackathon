#!/usr/bin/env bash
# Pure sizing input and rendering tests. Never invokes installer main or a gateway.
set -euo pipefail
# OI-K4 (Round K): the installer reads MemTotal for host fit and fails closed
# without it. These cases test other properties, so they run against a
# 128 TiB fixture on which every explicit session count fits and an unset
# count still selects 64.
export WINN3_GATEWAY_MEMINFO="${WINN3_GATEWAY_MEMINFO:-$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/testdata/winn3_gateway_meminfo/large}"
HERE="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
if [[ "${1:-}" != --case ]]; then
  INSTALL="$(python3 -B "${HERE}/../tools/winn3_gateway_test_source.py" "${1:-${HERE}/wins_data_plane_setup_ONETOUCH.sh}")"
  for test_case in plans mtu baked revalidate empty_environment; do
    env -i PATH=/usr/bin:/bin LC_ALL=C WINN3_GATEWAY_MEMINFO="${WINN3_GATEWAY_MEMINFO}" /bin/bash "$0" --case "${test_case}" "${INSTALL}"
    printf 'PASS %s\n' "${test_case}"
  done
  exit
fi
test_case="$2"
INSTALL="$3"
WINN3_GATEWAY_ID=synthetic-test
WINN3_GATEWAY_PATH_MTU=1450
WINN3_GATEWAY_INNER_V4=192.0.2.1
if [[ "${test_case}" == empty_environment ]]; then WINN3_GATEWAY_PLAN=""; fi
# shellcheck disable=SC1090
source "${INSTALL}"
case "${test_case}" in
  plans)
    [[ "${WINN3_GATEWAY_PLAN}" == udp ]]
    for plan in udp tcp tls udp,tcp,tls tls,udp tcp,tls,udp; do
      [[ "$(canonical_gateway_plan "${plan}")" == "${plan}" ]]
    done
    [[ "$(canonical_gateway_plan ',udp,,tls,')" == udp,tls ]]
    for plan in '' , ',,,' udp,udp udp,tcp,udp http udp,http UDP 'udp, tcp'; do
      value=''
      if value="$(canonical_gateway_plan "${plan}" 2>/dev/null)"; then exit 1; fi
      [[ -z "${value}" ]]
    done
    ;;
  mtu)
    for mtu in 1421 1450 1500; do
      [[ "$(canonical_gateway_path_mtu "${mtu}")" == "${mtu}" ]]
    done
    for mtu in '' 1280 1420 1501 01450 abc; do
      value=''
      if value="$(canonical_gateway_path_mtu "${mtu}" 2>/dev/null)"; then exit 1; fi
      [[ -z "${value}" ]]
    done
    ;;
  baked)
    WINN3_GATEWAY_PLAN=',udp,,tls,'
    WINN3_GATEWAY_MAX_SESSIONS=64
    unit="$(emit_unit_text)"
    env_text="$(emit_env_text)"
    [[ "${unit}" == *'  -plan udp,tls '* && "${unit}" == *'  -path-mtu 1450 '* && "${unit}" == *'  -max-sessions 64 '* ]]
    [[ "${env_text}" == *$'\nWINN3_GATEWAY_PLAN=udp,tls\n'* && "${env_text}" == *$'\nWINN3_GATEWAY_PATH_MTU=1450\n'* ]]
    [[ "${WINN3_GATEWAY_PLAN}" == ',udp,,tls,' ]]
    if [[ "${unit}" == *'${WINN3_GATEWAY_PLAN}'* || "${unit}" == *'${WINN3_GATEWAY_PATH_MTU}'* ]]; then exit 1; fi
    WINN3_GATEWAY_PLAN=tcp,tls
    WINN3_GATEWAY_PATH_MTU=1500
    WINN3_GATEWAY_MAX_SESSIONS=128
    next="$(emit_unit_text)"
    [[ "${next}" == *'  -plan tcp,tls '* && "${next}" == *'  -path-mtu 1500 '* && "${next}" == *'  -max-sessions 128 '* ]]
    [[ "${unit}" == *'  -plan udp,tls '* && "${unit}" == *'  -path-mtu 1450 '* && "${unit}" == *'  -max-sessions 64 '* ]]
    ;;
  revalidate)
    for emitter in emit_unit_text emit_env_text; do
      WINN3_GATEWAY_PLAN=udp
      WINN3_GATEWAY_PATH_MTU=1450
      "${emitter}" >/dev/null
      for plan in udp,udp http ',,,' ''; do
        WINN3_GATEWAY_PLAN="${plan}"
        value=''
        if value="$("${emitter}" 2>/dev/null)"; then exit 1; fi
        [[ -z "${value}" ]]
      done
      WINN3_GATEWAY_PLAN=udp
      WINN3_GATEWAY_PATH_MTU=1501
      value=''
      if value="$("${emitter}" 2>/dev/null)"; then exit 1; fi
      [[ -z "${value}" ]]
    done
    ;;
  empty_environment)
    [[ -z "${WINN3_GATEWAY_PLAN}" ]]
    for emitter in emit_unit_text emit_env_text; do
      value=''
      if value="$("${emitter}" 2>/dev/null)"; then exit 1; fi
      [[ -z "${value}" ]]
    done
    ;;
  *) exit 2 ;;
esac
