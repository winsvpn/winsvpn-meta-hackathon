#!/usr/bin/env bash
# Root-side, source-scoped route observation/forcing primitive for the Android
# physical release lane. Install this immutable file as
# /usr/local/sbin/winsvpn-android-route-guard and grant a dedicated SSH account
# sudo access to this command only. Payloads arrive on bounded stdin so client
# identity never appears in argv, the systemd journal, or process listings.

set -Eeuo pipefail
umask 077

readonly MARKER=winsvpn-android-release-guard
readonly MAX_PAYLOAD_BYTES=32768
readonly TEST_MODE=${WINSVPN_ANDROID_GUARD_TEST_MODE:-0}

die() { printf 'ANDROID REMOTE ROUTE GUARD: FAIL: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"; }

# The test seam is deliberately impossible to enter as root. Production root
# execution always uses fixed paths and a fixed PATH, even if an SSH client
# tries to preserve WINSVPN_* environment variables.
if [[ ${TEST_MODE} == 1 ]]; then
  [[ ${EUID} -ne 0 ]] || die 'test mode is forbidden for root'
  TEST_ROOT=${WINSVPN_ANDROID_GUARD_TEST_ROOT:-}
  [[ ${TEST_ROOT} =~ ^/tmp/winsvpn-route-guard-test-[A-Za-z0-9._-]+$ ]] ||
    die 'test root is invalid'
  readonly EXPECTED_UID=${EUID}
  readonly SECURE_BASE=${TEST_ROOT}
  readonly SELF=${TEST_ROOT}/usr/local/sbin/winsvpn-android-route-guard
  readonly STATE_ROOT=${TEST_ROOT}/run/winsvpn-android-route-guard
  export PATH=${TEST_ROOT}/fakebin:/usr/bin:/bin
else
  [[ ${TEST_MODE} == 0 ]] || die 'invalid test-mode selector'
  [[ ${EUID} -eq 0 ]] || die 'root is required'
  readonly EXPECTED_UID=0
  readonly SECURE_BASE=/
  readonly SELF=/usr/local/sbin/winsvpn-android-route-guard
  readonly STATE_ROOT=/run/winsvpn-android-route-guard
  export PATH=/usr/sbin:/usr/bin:/sbin:/bin
fi
readonly LOCK_FILE=${STATE_ROOT}/guard.lock

for command_name in python3 iptables iptables-restore sha256sum conntrack flock systemd-run systemctl stat dd; do
  need "${command_name}"
done

mode_is_secure() {
  local raw_mode=$1
  local numeric_mode=$((8#${raw_mode}))
  (( (numeric_mode & 0022) == 0 ))
}

assert_secure_directory() {
  local path=$1 label=$2 owner mode
  [[ -d ${path} && ! -L ${path} ]] || die "${label} must be a non-symlink directory"
  read -r owner mode < <(stat -c '%u %a' -- "${path}")
  [[ ${owner} == "${EXPECTED_UID}" ]] || die "${label} ownership is unsafe"
  mode_is_secure "${mode}" || die "${label} is group/world writable"
}

assert_secure_file() {
  local path=$1 label=$2 allowed_modes=$3 owner mode
  [[ -f ${path} && ! -L ${path} ]] || die "${label} must be a regular non-symlink file"
  read -r owner mode < <(stat -c '%u %a' -- "${path}")
  [[ ${owner} == "${EXPECTED_UID}" ]] || die "${label} ownership is unsafe"
  mode_is_secure "${mode}" || die "${label} is group/world writable"
  [[ " ${allowed_modes} " == *" ${mode} "* ]] || die "${label} mode is unsafe"
}

prepare_secure_paths() {
  if [[ ${TEST_MODE} == 1 ]]; then
    assert_secure_directory "${SECURE_BASE}" 'test root'
    assert_secure_directory "${SECURE_BASE}/usr" 'test usr parent'
    assert_secure_directory "${SECURE_BASE}/usr/local" 'test local parent'
    assert_secure_directory "${SECURE_BASE}/usr/local/sbin" 'test sbin parent'
    assert_secure_directory "${SECURE_BASE}/run" 'test run parent'
  else
    assert_secure_directory / 'filesystem root'
    assert_secure_directory /usr 'SELF usr parent'
    assert_secure_directory /usr/local 'SELF local parent'
    assert_secure_directory /usr/local/sbin 'SELF sbin parent'
    assert_secure_directory /run 'STATE_ROOT parent'
  fi

  if [[ -e ${STATE_ROOT} || -L ${STATE_ROOT} ]]; then
    assert_secure_directory "${STATE_ROOT}" 'STATE_ROOT'
  else
    mkdir -m 0700 -- "${STATE_ROOT}"
    assert_secure_directory "${STATE_ROOT}" 'STATE_ROOT'
  fi

  assert_secure_file "${SELF}" 'SELF' '700 755'
  [[ -x ${SELF} ]] || die 'SELF must be owner-executable'

  if [[ -e ${LOCK_FILE} || -L ${LOCK_FILE} ]]; then
    assert_secure_file "${LOCK_FILE}" 'LOCK_FILE' '600'
  fi
}

prepare_secure_paths
GUARD_BINARY_SHA256=$(sha256sum -- "${SELF}" | awk '{print $1}')
readonly GUARD_BINARY_SHA256

exec 9>"${LOCK_FILE}"
chmod 0600 "${LOCK_FILE}"
assert_secure_file "${LOCK_FILE}" 'LOCK_FILE' '600'
flock -x 9

action=${1:-}
operation_id=${2:-}
watchdog_call=${3:-}
[[ ${action} =~ ^(snapshot|apply|observe|restore)$ ]] || die 'unsupported action'
if [[ ${action} != snapshot ]]; then
  [[ ${operation_id} =~ ^[0-9a-f]{32}$ ]] || die 'operation ID must be 32 lowercase hexadecimal characters'
fi

short_id=${operation_id:0:12}
mangle_chain="WARGM_${short_id}"
filter_chain="WARGF_${short_id}"
state_file="${STATE_ROOT}/${operation_id}.json"
timer_unit="winsvpn-android-route-guard-${short_id}"
payload_file=
restore_script=
state_input_file=
observe_mangle_file=
observe_filter_file=
cleanup_on_exit=0

guard_rule_snapshot() {
  {
    iptables -t mangle -S 2>/dev/null || true
    iptables -t filter -S 2>/dev/null || true
  } | grep -E "${MARKER}|WARG[MF]_[0-9a-f]{12}" | LC_ALL=C sort || true
}

guard_unit_snapshot() {
  {
    systemctl list-units --all --plain --no-legend 'winsvpn-android-route-guard-*' 2>/dev/null || true
    systemctl list-unit-files --no-legend 'winsvpn-android-route-guard-*' 2>/dev/null || true
  } | grep -E 'winsvpn-android-route-guard-[0-9a-f]{12}\.(timer|service)' | LC_ALL=C sort -u || true
}

guard_state_snapshot() {
  find "${STATE_ROOT}" -maxdepth 1 -type f -name '*.json' -printf '%f\n' | LC_ALL=C sort
}

guard_temp_snapshot() {
  find "${STATE_ROOT}" -maxdepth 1 -type f \
    \( -name '.*.payload.*' -o -name '.*.restore.*' -o -name '.*.state-input.*' -o -name '.*.observe-*.*' \) \
    -printf '%f\n' | LC_ALL=C sort
}

snapshot_hash() { guard_rule_snapshot | sha256sum | awk '{print $1}'; }

assert_globally_clean() {
  local rules states temps units
  rules=$(guard_rule_snapshot)
  states=$(guard_state_snapshot)
  temps=$(guard_temp_snapshot)
  units=$(guard_unit_snapshot)
  [[ -z ${rules} && -z ${states} && -z ${temps} && -z ${units} ]] ||
    die 'orphan or active WARG rules, state, temporary files, or watchdog units exist'
}

emit_snapshot() {
  local hash
  assert_globally_clean
  hash=$(snapshot_hash)
  python3 - "${hash}" "${GUARD_BINARY_SHA256}" <<'PY'
import json, sys
print(json.dumps({
    "schema_version": 1,
    "contract": "winsvpn-android-remote-route-guard-v1",
    "action": "snapshot",
    "state_sha256": sys.argv[1],
    "guard_binary_sha256": sys.argv[2],
    "active_operation_count": 0,
    "passed": True,
    "secret_material_redacted": True,
}, sort_keys=True, separators=(",", ":")))
PY
}

cleanup_operation() {
  local rule_number
  local -a mangle_hooks=() filter_hooks=()
  mapfile -t mangle_hooks < <(
    iptables -t mangle -L PREROUTING --line-numbers -nv 2>/dev/null |
      awk -v chain="${mangle_chain}" '$0 ~ chain {print $1}' | sort -rn
  )
  for rule_number in "${mangle_hooks[@]}"; do
    if [[ ${rule_number} =~ ^[0-9]+$ ]]; then
      iptables -t mangle -D PREROUTING "${rule_number}" 2>/dev/null || true
    fi
  done
  mapfile -t filter_hooks < <(
    iptables -t filter -L INPUT --line-numbers -nv 2>/dev/null |
      awk -v chain="${filter_chain}" '$0 ~ chain {print $1}' | sort -rn
  )
  for rule_number in "${filter_hooks[@]}"; do
    if [[ ${rule_number} =~ ^[0-9]+$ ]]; then
      iptables -t filter -D INPUT "${rule_number}" 2>/dev/null || true
    fi
  done
  iptables -t mangle -F "${mangle_chain}" 2>/dev/null || true
  iptables -t mangle -X "${mangle_chain}" 2>/dev/null || true
  iptables -t filter -F "${filter_chain}" 2>/dev/null || true
  iptables -t filter -X "${filter_chain}" 2>/dev/null || true
  rm -f -- "${state_file}"
}

cleanup_timer() {
  systemctl stop "${timer_unit}.timer" "${timer_unit}.service" >/dev/null 2>&1 || true
  systemctl reset-failed "${timer_unit}.timer" "${timer_unit}.service" >/dev/null 2>&1 || true
  systemctl daemon-reload >/dev/null 2>&1 || true
}

cleanup_temporaries() {
  rm -f -- "${payload_file:-}" "${restore_script:-}" "${state_input_file:-}" \
    "${observe_mangle_file:-}" "${observe_filter_file:-}"
}

guard_exit() {
  local rc=$1
  trap - EXIT
  if (( cleanup_on_exit != 0 )); then
    cleanup_temporaries
    cleanup_operation
    cleanup_timer
  fi
  exit "${rc}"
}
trap 'guard_exit $?' EXIT

assert_secure_state_file() {
  assert_secure_file "${state_file}" 'operation state' '600'
}

case ${action} in
  snapshot)
    [[ $# -eq 1 ]] || die 'snapshot accepts no operation ID'
    emit_snapshot
    ;;

  apply)
    [[ $# -eq 2 ]] || die 'apply accepts only an operation ID; JSON is read from stdin'
    [[ ! -e ${state_file} && ! -L ${state_file} ]] || die 'operation already exists'
    assert_globally_clean
    cleanup_on_exit=1
    payload_file=$(mktemp "${STATE_ROOT}/.${operation_id}.payload.XXXXXX")
    chmod 0600 "${payload_file}"
    # One bounded read is enough: 32,769 bytes proves oversize without first
    # writing an attacker-controlled unbounded stream to disk.
    dd if=/dev/stdin of="${payload_file}" bs=$((MAX_PAYLOAD_BYTES + 1)) count=1 status=none
    payload_size=$(stat -c '%s' -- "${payload_file}")
    (( payload_size <= MAX_PAYLOAD_BYTES )) || die 'apply payload exceeds 32 KiB'

    if ! parsed=$(python3 - "${payload_file}" <<'PY'
import ipaddress, json, pathlib, re, sys
p = pathlib.Path(sys.argv[1])
try:
    value = json.loads(p.read_text(encoding="utf-8"))
finally:
    p.unlink(missing_ok=True)
expected = {"schema_version", "contract", "source_ipv4", "watchdog_seconds", "observations", "blocks"}
if not isinstance(value, dict) or set(value) != expected:
    raise SystemExit("payload fields are invalid")
if value["schema_version"] != 1 or value["contract"] != "winsvpn-android-route-control-apply-v1":
    raise SystemExit("payload contract is invalid")
ip = ipaddress.ip_address(value["source_ipv4"])
if ip.version != 4 or ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_unspecified:
    raise SystemExit("source must be a public IPv4 address")
seconds = value["watchdog_seconds"]
if isinstance(seconds, bool) or not isinstance(seconds, int) or not 60 <= seconds <= 300:
    raise SystemExit("watchdog_seconds must be between 60 and 300")
def rules(raw, label):
    if not isinstance(raw, list) or len(raw) > 16:
        raise SystemExit(f"{label} list is invalid")
    out, seen = [], set()
    for item in raw:
        keys = {"id", "protocol", "port"} if label == "observations" else {"protocol", "port"}
        if not isinstance(item, dict) or set(item) != keys:
            raise SystemExit(f"{label} rule fields are invalid")
        proto, port = item["protocol"], item["port"]
        if proto not in {"tcp", "udp"} or isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise SystemExit(f"{label} protocol/port is invalid")
        key = (proto, port)
        if key in seen:
            raise SystemExit(f"{label} rule is duplicated")
        seen.add(key)
        if label == "observations":
            ident = item["id"]
            if not isinstance(ident, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,15}", ident):
                raise SystemExit("observation ID is invalid")
            out.append((ident, proto, port))
        else:
            out.append((proto, port))
    return out
observations = rules(value["observations"], "observations")
blocks = rules(value["blocks"], "blocks")
if not observations:
    raise SystemExit("at least one observation rule is required")
print(str(ip))
print(seconds)
for ident, proto, port in observations:
    print(f"O|{ident}|{proto}|{port}")
for proto, port in blocks:
    print(f"B||{proto}|{port}")
PY
); then
      die 'invalid apply payload'
    fi
    payload_file=
    mapfile -t payload_lines <<<"${parsed}"
    source_ipv4=${payload_lines[0]}
    watchdog_seconds=${payload_lines[1]}
    rule_lines=("${payload_lines[@]:2}")

    # Refuse a source identity that already owns another target flow. All
    # matching stays inside bash so neither the address nor conntrack table is
    # copied into a child-process argv.
    conntrack_text=$(conntrack -L -f ipv4 2>/dev/null || true)
    for line in "${rule_lines[@]}"; do
      IFS='|' read -r kind rule_id protocol port <<<"${line}"
      while IFS= read -r conntrack_line; do
        if [[ ${conntrack_line} == "${protocol} "* &&
              ${conntrack_line} == *"src=${source_ipv4} "* &&
              ( ${conntrack_line} == *"dport=${port} "* || ${conntrack_line} == *"dport=${port}" ) ]]; then
          die 'existing target flow makes the public source identity ambiguous'
        fi
      done <<<"${conntrack_text}"
    done
    unset conntrack_text conntrack_line

    before_sha=$(snapshot_hash)
    restore_script=$(mktemp "${STATE_ROOT}/.${operation_id}.restore.XXXXXX")
    chmod 0600 "${restore_script}"
    {
      printf '*mangle\n:%s - [0:0]\n' "${mangle_chain}"
      printf -- '-A PREROUTING -s %s/32 -m comment --comment "%s:%s:hook" -j %s\n' "${source_ipv4}" "${MARKER}" "${operation_id}" "${mangle_chain}"
      for line in "${rule_lines[@]}"; do
        IFS='|' read -r kind rule_id protocol port <<<"${line}"
        [[ ${kind} == O ]] && printf -- '-A %s -p %s -m %s --dport %s -m comment --comment "%s:%s:observe:%s" -j RETURN\n' \
          "${mangle_chain}" "${protocol}" "${protocol}" "${port}" "${MARKER}" "${operation_id}" "${rule_id}"
      done
      printf 'COMMIT\n*filter\n:%s - [0:0]\n' "${filter_chain}"
      printf -- '-A INPUT -s %s/32 -m comment --comment "%s:%s:hook" -j %s\n' "${source_ipv4}" "${MARKER}" "${operation_id}" "${filter_chain}"
      for line in "${rule_lines[@]}"; do
        IFS='|' read -r kind rule_id protocol port <<<"${line}"
        [[ ${kind} == B ]] && printf -- '-A %s -p %s -m %s --dport %s -m comment --comment "%s:%s:block:%s-%s" -j DROP\n' \
          "${filter_chain}" "${protocol}" "${protocol}" "${port}" "${MARKER}" "${operation_id}" "${protocol}" "${port}"
      done
      printf -- '-A %s -j RETURN\nCOMMIT\n' "${filter_chain}"
    } >"${restore_script}"
    iptables-restore --noflush <"${restore_script}"
    rm -f -- "${restore_script}"
    restore_script=
    applied_sha=$(snapshot_hash)
    [[ ${applied_sha} != "${before_sha}" ]] || die 'route-control state did not change'

    state_input_file=$(mktemp "${STATE_ROOT}/.${operation_id}.state-input.XXXXXX")
    chmod 0600 "${state_input_file}"
    {
      printf '%s\n%s\n' "${source_ipv4}" "${watchdog_seconds}"
      printf '%s\n' "${rule_lines[@]}"
    } >"${state_input_file}"
    python3 - "${state_file}" "${before_sha}" "${applied_sha}" "${GUARD_BINARY_SHA256}" "${operation_id}" "${MARKER}" "${state_input_file}" <<'PY'
import hashlib, json, pathlib, sys
path, input_path = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[7])
try:
    lines = input_path.read_text(encoding="utf-8").splitlines()
finally:
    input_path.unlink(missing_ok=True)
source, seconds, *rules = lines
value = {
    "schema_version": 1,
    "contract": "winsvpn-android-remote-route-guard-state-v1",
    "operation_id": sys.argv[5],
    "marker": sys.argv[6],
    "before_state_sha256": sys.argv[2],
    "applied_state_sha256": sys.argv[3],
    "guard_binary_sha256": sys.argv[4],
    "source_ipv4_sha256": hashlib.sha256(source.encode()).hexdigest(),
    "watchdog_seconds": int(seconds),
    "observations": [r for r in rules if r.startswith("O|")],
    "blocks": [r for r in rules if r.startswith("B|")],
}
path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
path.chmod(0o600)
PY
    state_input_file=
    assert_secure_state_file
    systemd-run --collect --quiet --unit "${timer_unit}" --on-active="${watchdog_seconds}s" \
      "${SELF}" restore "${operation_id}" --watchdog
    source_ipv4_sha256=$(printf '%s' "${source_ipv4}" | sha256sum | awk '{print $1}')
    unset source_ipv4
    cleanup_on_exit=0
    python3 - "${before_sha}" "${applied_sha}" "${source_ipv4_sha256}" "${GUARD_BINARY_SHA256}" <<'PY'
import json, sys
print(json.dumps({
    "schema_version": 1,
    "contract": "winsvpn-android-remote-route-guard-v1",
    "action": "apply",
    "before_state_sha256": sys.argv[1],
    "applied_state_sha256": sys.argv[2],
    "source_ipv4_sha256": sys.argv[3],
    "guard_binary_sha256": sys.argv[4],
    "watchdog_armed": True,
    "shared_nat_ambiguity_absent": True,
    "passed": True,
    "secret_material_redacted": True,
}, sort_keys=True, separators=(",", ":")))
PY
    ;;

  observe)
    [[ $# -eq 2 ]] || die 'observe accepts only an operation ID'
    assert_secure_state_file
    cleanup_on_exit=1
    observe_mangle_file=$(mktemp "${STATE_ROOT}/.${operation_id}.observe-mangle.XXXXXX")
    observe_filter_file=$(mktemp "${STATE_ROOT}/.${operation_id}.observe-filter.XXXXXX")
    chmod 0600 "${observe_mangle_file}" "${observe_filter_file}"
    # Only operation-specific chains cross the privilege boundary. Full
    # firewall-table dumps are never stored in shell variables or argv.
    iptables -t mangle -L "${mangle_chain}" -nvx --line-numbers >"${observe_mangle_file}"
    iptables -t filter -L "${filter_chain}" -nvx --line-numbers >"${observe_filter_file}"
    python3 - "${state_file}" "${observe_mangle_file}" "${observe_filter_file}" "${GUARD_BINARY_SHA256}" <<'PY'
import json, pathlib, re, sys
state = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if state.get("contract") != "winsvpn-android-remote-route-guard-state-v1":
    raise SystemExit("operation state contract is invalid")
if state.get("guard_binary_sha256") != sys.argv[4]:
    raise SystemExit("guard binary changed during operation")
mangle = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
filters = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")
def count(text, needle):
    rows = [line for line in text.splitlines() if needle in line]
    if len(rows) != 1:
        raise SystemExit("expected exactly one live counter rule")
    match = re.match(r"^\s*\d+\s+(\d+)\s+(\d+)\s+", rows[0])
    if not match:
        raise SystemExit("counter columns are missing")
    return {"packets": int(match.group(1)), "bytes": int(match.group(2))}
prefix = f'{state["marker"]}:{state["operation_id"]}'
observed = {}
for raw in state["observations"]:
    _, ident, proto, port = raw.split("|")
    observed[ident] = {**count(mangle, f"{prefix}:observe:{ident}"), "protocol": proto, "port": int(port)}
blocked = []
for raw in state["blocks"]:
    _, _, proto, port = raw.split("|")
    blocked.append({**count(filters, f"{prefix}:block:{proto}-{port}"), "protocol": proto, "port": int(port)})
print(json.dumps({
    "schema_version": 1,
    "contract": "winsvpn-android-remote-route-guard-v1",
    "action": "observe",
    "applied_state_sha256": state["applied_state_sha256"],
    "source_ipv4_sha256": state["source_ipv4_sha256"],
    "guard_binary_sha256": state["guard_binary_sha256"],
    "observations": observed,
    "blocks": blocked,
    "passed": True,
    "secret_material_redacted": True,
}, sort_keys=True, separators=(",", ":")))
PY
    rm -f -- "${observe_mangle_file}" "${observe_filter_file}"
    observe_mangle_file=
    observe_filter_file=
    cleanup_on_exit=0
    ;;

  restore)
    [[ $# -eq 2 || (${#} -eq 3 && ${watchdog_call} == --watchdog) ]] || die 'restore arguments are invalid'
    cleanup_on_exit=1
    if [[ ! -e ${state_file} && ! -L ${state_file} ]]; then
      cleanup_operation
      if [[ ${watchdog_call} == --watchdog ]]; then
        cleanup_on_exit=0
        exit 0
      fi
      die 'operation state is missing'
    fi
    assert_secure_state_file
    read -r before_sha state_guard_sha < <(python3 - "${state_file}" <<'PY'
import json, pathlib, sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
print(value["before_state_sha256"], value["guard_binary_sha256"])
PY
)
    [[ ${state_guard_sha} == "${GUARD_BINARY_SHA256}" ]] || die 'guard binary changed during operation'
    cleanup_operation
    if [[ ${watchdog_call} != --watchdog ]]; then
      cleanup_timer
    fi
    after_sha=$(snapshot_hash)
    [[ ${after_sha} == "${before_sha}" ]] || die 'route-control state did not restore exactly'
    cleanup_on_exit=0
    [[ ${watchdog_call} == --watchdog ]] && exit 0
    python3 - "${before_sha}" "${after_sha}" "${GUARD_BINARY_SHA256}" <<'PY'
import json, sys
print(json.dumps({
    "schema_version": 1,
    "contract": "winsvpn-android-remote-route-guard-v1",
    "action": "restore",
    "before_state_sha256": sys.argv[1],
    "after_state_sha256": sys.argv[2],
    "guard_binary_sha256": sys.argv[3],
    "passed": True,
    "secret_material_redacted": True,
}, sort_keys=True, separators=(",", ":")))
PY
    ;;
esac

trap - EXIT
