#!/usr/bin/env bash
# WINN3_GATEWAY_FORWARD_ASYNC unit tests (multicore landing, 2026-09-29).
# rev3.4 sits behind the binary's -forward-async-write, default off. Ruling:
# .agent/debates/_decisions/fable_ruling_multicore_r34_landing_20260929.md,
# landing condition 2. The installer value defaults to 0, accepts only 0 and 1,
# is refused at 1 without WINN3_GATEWAY_FORWARD=1, is baked into ExecStart
# (right after -peer-registry) only at 1, reaches the env file as a record, and
# is on the root firewall's closed name allowlist. Pure functions and the
# generated firewall script against stubbed stat and iptables; never invokes
# installer main, a gateway, or the host's real firewall. Same shape as
# wins_winn3_gateway_install_tcp_ingress_unit_test.sh.
# The WINN3_GATEWAY_* assignments are read by the sourced installer.
# shellcheck disable=SC2034
set -euo pipefail
# In the bash macOS ships as /bin/bash (3.2.57) a failing [[ ]] does not stop
# set -e, which silences every assertion below except the last of each case.
# Refuse such a bash instead of passing in it.
if "${BASH}" -c 'set -e; [[ 1 == 2 ]]; exit 0'; then
  printf 'refusing to run: in %s (%s) a failing [[ ]] does not stop set -e\n' "${BASH}" "${BASH_VERSION}" >&2
  exit 2
fi
export WINN3_GATEWAY_MEMINFO="${WINN3_GATEWAY_MEMINFO:-$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/testdata/winn3_gateway_meminfo/large}"
HERE="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
if [[ "${1:-}" != --case ]]; then
  INSTALL="$(python3 -B "${HERE}/../tools/winn3_gateway_test_source.py" "${1:-${HERE}/wins_data_plane_setup_ONETOUCH.sh}")"
  FIXTURES="$(mktemp -d "${TMPDIR:-/tmp}/winn3-forward-async.XXXXXX")"
  trap 'rm -rf "${FIXTURES}"' EXIT
  for test_case in default on needs_forward invalid firewall; do
    env -i PATH=/usr/bin:/bin LC_ALL=C WINN3_GATEWAY_MEMINFO="${WINN3_GATEWAY_MEMINFO}" \
      FIXTURES="${FIXTURES}" "${BASH}" "$0" --case "${test_case}" "${INSTALL}"
    printf 'PASS %s\n' "${test_case}"
  done
  exit
fi
test_case="$2"
INSTALL="$3"
WINN3_GATEWAY_ID=synthetic-test
WINN3_GATEWAY_PATH_MTU=1400
WINN3_GATEWAY_INNER_V4=192.0.2.1
WINN3_GATEWAY_PLAN=udp
WINN3_GATEWAY_MAX_SESSIONS=64
# shellcheck disable=SC1090
source "${INSTALL}"

must_fail() {
  local out
  if out="$("$@" 2>/dev/null)"; then
    printf 'expected failure: %s (printed %s)\n' "$*" "${out}" >&2
    exit 1
  fi
  [[ -z "${out}" ]]
}

# A fresh source with the variables exported, the way an operator runs it.
# $1 FORWARD, $2 FORWARD_ASYNC, $3 the function to print (emit_env_text or
# emit_unit_text).
# shellcheck disable=SC2016  # "$1" is expanded by the child bash
probe() {
  env -i PATH=/usr/bin:/bin LC_ALL=C WINN3_GATEWAY_MEMINFO="${WINN3_GATEWAY_MEMINFO}" \
    WINN3_GATEWAY_ID=synthetic-test WINN3_GATEWAY_INNER_V4=192.0.2.1 \
    WINN3_GATEWAY_PATH_MTU=1400 WINN3_GATEWAY_PLAN=udp WINN3_GATEWAY_MAX_SESSIONS=64 \
    WINN3_GATEWAY_FORWARD_IF=winn3gw0 WINN3_GATEWAY_FORWARD_CIDR=192.0.2.0/24 \
    WINN3_GATEWAY_FORWARD="$1" WINN3_GATEWAY_FORWARD_ASYNC="$2" \
    "${BASH}" -c 'set -euo pipefail; source "$1"; validate_forward_async; "$2"' _ "${INSTALL}" "$3"
}

# ExecStart continuation lines of a unit text, one flag per line, trimmed.
exec_lines() {
  awk '/^ExecStart=/{f=1} f{l=$0; c=(l ~ /\\$/); sub(/^ExecStart=/, "", l); sub(/^[ \t]+/, "", l); sub(/[ \t]*\\$/, "", l); print l; if (!c) exit}' <<< "$1"
}

# Every line of a unit text outside its ExecStart= block.
non_exec_lines() {
  awk '/^ExecStart=/{f=1} f{if ($0 !~ /\\$/) f=0; next} {print}' <<< "$1"
}

# $1 a fresh fixture directory, $2 env file text. Runs the generated root
# firewall script (the literal heredoc body) against it with stubbed stat and
# ip and a stateful iptables fake, which logs every call to $1/iptables.log.
# Prints its output; returns its exit code.
run_firewall() {
  local fw="$1"
  mkdir -p "${fw}/bin"
  awk "/^  cat <<'EOF' # the boot helper: \/usr\/local\/sbin\/winn3-gateway-firewall\$/{f=1; next} f && /^EOF\$/{exit} f{print}" \
    "${INSTALL}" > "${fw}/firewall"
  [[ -s "${fw}/firewall" ]]
  printf '#!/bin/sh\nprintf "0:600\\n"\n' > "${fw}/bin/stat"
  # The fake keeps a fresh host's filter, nat and mangle tables in
  # $1/iptables.state and stores rules in kernel (`iptables -S`) form, so the
  # helper reads back what it wrote: place_winn3gw_input_jump lists INPUT
  # before and after its insert, -C and -D match only rules that exist, and
  # the -D loops end once the old jumps are gone. Same model as the fakes in
  # wins_winn3_gateway_install_firewall_boot_test.sh and
  # wins_winn3_gateway_install_interactions_test.sh. Every call, read or
  # write, is logged to $1/iptables.log as "$*".
  cat > "${fw}/bin/iptables" <<'FAKE'
#!/usr/bin/env python3
import json
import sys
from pathlib import Path

home = Path(__file__).resolve().parent.parent
with open(home / "iptables.log", "a", encoding="utf-8") as log:
    log.write(" ".join(sys.argv[1:]) + "\n")
args, table = sys.argv[1:], "filter"
while len(args) > 1 and args[0] in ("-w", "-t"):
    if args[0] == "-t":
        table = args[1]
    args = args[2:]
BUILTIN = {"filter": ["INPUT", "FORWARD", "OUTPUT"], "nat": ["PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"],
           "mangle": ["PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"]}
if table not in BUILTIN:
    sys.exit(2)
state_path = home / "iptables.state"
state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
chains = state.setdefault(table, {})
for name in BUILTIN[table]:
    chains.setdefault(name, [])


def canon(chain, spec):
    fields, rest, target, i = {}, [], [], 0
    while i < len(spec):
        if spec[i] in ("-s", "-d", "-i", "-o", "-p") and i + 1 < len(spec):
            fields[spec[i]] = spec[i + 1]
            i += 2
        elif spec[i] in ("-j", "-g"):
            target = spec[i:]
            break
        else:
            rest.append(spec[i])
            i += 1
    out = ["-A", chain]
    for flag in ("-s", "-d", "-i", "-o", "-p"):
        if flag in fields:
            value = fields[flag]
            out += [flag, value + "/32" if flag in ("-s", "-d") and "/" not in value else value]
    proto = fields.get("-p")
    if proto in ("tcp", "udp") and ("--dport" in rest or "--sport" in rest) and rest[:2] != ["-m", proto]:
        out += ["-m", proto]
    return " ".join(out + rest + target)


def stored(chain, line):
    return canon(chain, line.split()[2:])


op = args[0] if args else ""
chain = args[1] if len(args) > 1 else ""
user = sorted(c for c in chains if c not in BUILTIN[table])
if op == "-S" and len(args) == 1:
    for name in BUILTIN[table]:
        print(f"-P {name} ACCEPT")
    for name in user:
        print(f"-N {name}")
    for name in BUILTIN[table] + user:
        for line in chains[name]:
            print(line)
    sys.exit(0)
if chain not in chains and op != "-N":
    sys.stderr.write("iptables: No chain/target/match by that name.\n")
    sys.exit(1)
if op == "-S" and len(args) == 2:
    print(f"-P {chain} ACCEPT" if chain in BUILTIN[table] else f"-N {chain}")
    for line in chains[chain]:
        print(line)
    sys.exit(0)
if op == "-C":
    want = canon(chain, args[2:])
    sys.exit(0 if any(stored(chain, line) == want for line in chains[chain]) else 1)
if op == "-N":
    if chain in chains:
        sys.exit(1)
    chains[chain] = []
elif op == "-F" and len(args) == 2:
    chains[chain] = []
elif op == "-A":
    chains[chain].append(canon(chain, args[2:]))
elif op == "-I":
    spec, at = args[2:], 1
    if spec and spec[0].isdigit():
        at, spec = int(spec[0]), spec[1:]
    if not 1 <= at <= len(chains[chain]) + 1:
        sys.exit(1)
    chains[chain].insert(at - 1, canon(chain, spec))
elif op == "-D":
    want = canon(chain, args[2:])
    for index, line in enumerate(chains[chain]):
        if stored(chain, line) == want:
            del chains[chain][index]
            break
    else:
        sys.exit(1)
else:
    sys.exit(2)
state_path.write_text(json.dumps(state), encoding="utf-8")
FAKE
  # The env files here carry WINN3_GATEWAY_FORWARD=1, so the helper asks ip(8)
  # for the WAN device; the stub answers with a documentation-range route.
  printf '#!/bin/sh\nprintf "default via 192.0.2.254 dev eth0 proto static\\n"\n' > "${fw}/bin/ip"
  chmod 755 "${fw}/bin/stat" "${fw}/bin/iptables" "${fw}/bin/ip"
  # The helper holds the shared firewall lock for its whole run (design v17
  # 2.2 item 1). macOS has no flock(1), so every host uses the same fake, on a
  # lock file inside the work directory.
  install -m 700 "${HERE}/testdata/winn3_gateway_fake_flock.py" "${fw}/bin/flock"
  printf '%s\n' "$2" > "${fw}/winn3-gateway.env"
  chmod 600 "${fw}/winn3-gateway.env"
  env -i PATH="${fw}/bin:/usr/bin:/bin" LC_ALL=C WINN3_GATEWAY_ENV_FILE="${fw}/winn3-gateway.env" \
    WINS_FIREWALL_LOCK="${fw}/wins-firewall.lock" \
    "${BASH}" "${fw}/firewall" 2>&1
}

case "${test_case}" in
  default)
    # Default off: the env -i driver leaves WINN3_GATEWAY_FORWARD_ASYNC unset.
    [[ "${WINN3_GATEWAY_FORWARD_ASYNC}" == 0 ]]
    validate_forward_async
    env_text="$(emit_env_text)"
    [[ "${env_text}" == *$'\nWINN3_GATEWAY_FORWARD_ASYNC=0\n'* ]]
    [[ "$(grep -c '^WINN3_GATEWAY_FORWARD_ASYNC=' <<< "${env_text}")" == 1 ]]
    [[ "$(emit_unit_text)" != *'forward-async-write'* ]]
    # Empty is unset. FORWARD=1 with the default emits no flag either, and the
    # forward unit at 0 is byte for byte the unit the installer wrote before.
    [[ "$(probe 0 '' emit_env_text)" == *$'\nWINN3_GATEWAY_FORWARD_ASYNC=0\n'* ]]
    fwd_default="$(probe 1 '' emit_unit_text)"
    fwd_zero="$(probe 1 0 emit_unit_text)"
    [[ "${fwd_default}" == "${fwd_zero}" ]]
    # The ExecStart ends at -peer-registry: the free-tier cap travels in the
    # env file (read live at start), so no -free-mbps flag is baked here.
    [[ "${fwd_zero}" == *'-peer-registry'* && "${fwd_zero}" != *'forward-async-write'* ]]
    [[ "${fwd_zero}" != *'-free-mbps'* ]]
    msg="$(validate_config 2>&1 || true)"
    [[ "${msg}" != *'WINN3_GATEWAY_FORWARD_ASYNC'* ]]
    ;;
  on)
    on_env="$(probe 1 1 emit_env_text)"
    [[ "${on_env}" == *$'\nWINN3_GATEWAY_FORWARD_ASYNC=1\n'* ]]
    [[ "$(grep -c '^WINN3_GATEWAY_FORWARD_ASYNC=' <<< "${on_env}")" == 1 ]]
    on_unit="$(probe 1 1 emit_unit_text)"
    off_unit="$(probe 1 0 emit_unit_text)"
    # Exactly one flag, exactly one new ExecStart line, placed right after
    # -peer-registry; every other line of the unit is unchanged.
    [[ "$(grep -c -- '-forward-async-write' <<< "${on_unit}")" == 1 ]]
    on_exec="$(exec_lines "${on_unit}")"
    off_exec="$(exec_lines "${off_unit}")"
    [[ "$(grep -A1 -- '^-peer-registry ' <<< "${on_exec}" | tail -n 1)" == '-forward-async-write' ]]
    [[ "$(grep -v -x -- '-forward-async-write' <<< "${on_exec}")" == "${off_exec}" ]]
    [[ "$(non_exec_lines "${on_unit}")" == "$(non_exec_lines "${off_unit}")" ]]
    # The live env copy is only a record: the unit reads no FORWARD_ASYNC.
    [[ "${on_unit}" != *'${WINN3_GATEWAY_FORWARD_ASYNC}'* ]]
    # The booleans beside it are untouched.
    [[ "${on_env}" == *$'\nWINN3_GATEWAY_TCP_INGRESS=0\n'* && "${on_env}" == *$'\nWINN3_GATEWAY_LISTENER_DF=0\n'* ]]
    ;;
  needs_forward)
    # 1 without forward is refused by the validator, both emitters and
    # validate_config, and nothing is printed on stdout.
    must_fail probe 0 1 emit_env_text
    must_fail probe 0 1 emit_unit_text
    msg="$(probe 0 1 emit_unit_text 2>&1 || true)"
    [[ "${msg}" == *'WINN3_GATEWAY_FORWARD_ASYNC=1 needs WINN3_GATEWAY_FORWARD=1'* ]]
    WINN3_GATEWAY_FORWARD=0
    WINN3_GATEWAY_FORWARD_ASYNC=1
    must_fail validate_forward_async
    must_fail emit_env_text
    must_fail emit_unit_text
    msg="$(validate_config 2>&1 || true)"
    [[ "${msg}" == *'WINN3_GATEWAY_FORWARD_ASYNC=1 needs WINN3_GATEWAY_FORWARD=1'* ]]
    ;;
  invalid)
    for bad in true false yes no on off TRUE 2 00 01 ' 1' '1 ' $'1\nPATH=/tmp/x'; do
      must_fail probe 1 "${bad}" emit_env_text
      must_fail probe 1 "${bad}" emit_unit_text
      msg="$(probe 1 "${bad}" emit_env_text 2>&1 || true)"
      [[ "${msg}" == *'WINN3_GATEWAY_FORWARD_ASYNC='*'must be 0 or 1.'* ]]
      WINN3_GATEWAY_FORWARD_ASYNC="${bad}"
      must_fail validate_forward_async
      must_fail emit_env_text
      msg="$(validate_config 2>&1 || true)"
      [[ "${msg}" == *'WINN3_GATEWAY_FORWARD_ASYNC='*'must be 0 or 1.'* ]]
    done
    ;;
  firewall)
    # The root firewall unit sources the env file only if every name is on its
    # closed allowlist. Without the name the firewall refuses and the gateway,
    # which Requires it, never starts.
    for value in 0 1; do
      text="$(probe 1 "${value}" emit_env_text)"
      fw_rc=0
      msg="$(run_firewall "${FIXTURES}/fw_${value}" "${text}")" || fw_rc=$?
      if [[ "${msg}" == *'not one of the gateway env keys'* || "${fw_rc}" != 0 ]]; then
        printf 'generated firewall refused the emitted env file with FORWARD_ASYNC=%s (rc %s): %s\n' \
          "${value}" "${fw_rc}" "${msg}" >&2
        exit 1
      fi
      [[ -s "${FIXTURES}/fw_${value}/iptables.log" ]]
    done
    # Control: the same run refuses a name that is not on the allowlist, so the
    # pass above is the allowlist admitting WINN3_GATEWAY_FORWARD_ASYNC.
    fw_rc=0
    msg="$(run_firewall "${FIXTURES}/fw_control" "$(probe 1 1 emit_env_text)"$'\nWINN3_GATEWAY_FORWARD_ASYNX=1')" || fw_rc=$?
    [[ "${fw_rc}" != 0 && "${msg}" == *"variable 'WINN3_GATEWAY_FORWARD_ASYNX' is not one of the gateway env keys"* ]]
    [[ ! -e "${FIXTURES}/fw_control/iptables.log" ]]
    ;;
  *) exit 2 ;;
esac
