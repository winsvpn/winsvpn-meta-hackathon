#!/usr/bin/env bash
# shellcheck disable=SC2034  # globals are read by the other files of the bundle
# Tier A fixture library (design v17 5.1 to 5.3). Sourced by fx_main.sh, which
# runs inside `unshare -m -n -p -f --mount-proc` as root on a local colima guest.
#
# Everything the fixtures change is private to that namespace set:
#   * the network namespace holds the iptables rules under test;
#   * /etc, /var/lib and /usr/local are overlay mounts whose upper layer is a
#     tmpfs, and /run is a tmpfs, so the guard programs and the installer
#     functions see their absolute paths but write nowhere on the guest;
#   * a client network namespace is joined by a veth pair, so "dark" means an
#     actual connection attempt from outside the node namespace goes
#     unanswered, not only that a rule exists.
# Output protocol, one line each:  S7 ok|not-ok|skip|note <scenario> <text>

FX_FAILED=0
FX_SCEN=""
FX_CLIENT=""
FX_SHA="0000000000000000000000000000000000000000000000000000000000000000"

fx_say()  { printf 'S7 %s %s %s\n' "$1" "${FX_SCEN:-init}" "$2"; }
fx_ok()   { fx_say ok "$*"; }
fx_fail() { fx_say not-ok "$*"; FX_FAILED=1; }
fx_skip() { fx_say skip "$*"; }
fx_note() { fx_say note "$*"; }

# fx_assert DESCRIPTION CMD...  (passes when CMD succeeds)
fx_assert() {
  local description="$1"
  shift
  if "$@" >/dev/null 2>&1; then fx_ok "${description}"; else fx_fail "${description}"; fi
}
# fx_refute DESCRIPTION CMD...  (passes when CMD fails)
fx_refute() {
  local description="$1"
  shift
  if "$@" >/dev/null 2>&1; then fx_fail "${description}"; else fx_ok "${description}"; fi
}
fx_eq() { # DESCRIPTION EXPECTED ACTUAL
  if [[ "$2" == "$3" ]]; then fx_ok "$1"; else fx_fail "$1 :: expected [$2] got [$3]"; fi
}

# ---------------------------------------------------------------------------
# Namespace setup
# ---------------------------------------------------------------------------
fx_init() {
  mount --make-rprivate / || { echo "S7 not-ok init mount --make-rprivate failed"; exit 90; }
  FX_T="/tmp/s7ns.${FX_RUN:-$$}"; mkdir -p "${FX_T}" || exit 91
  mount -t tmpfs tmpfs "${FX_T}" || exit 92
  mkdir -p "${FX_T}"/{up,wk,stubs,cap,state}
  local d
  for d in etc var/lib usr/local; do
    mkdir -p "${FX_T}/up/${d}" "${FX_T}/wk/${d}"
    mount -t overlay overlay -o "lowerdir=/${d},upperdir=${FX_T}/up/${d},workdir=${FX_T}/wk/${d}" "/${d}" \
      || { echo "S7 not-ok init overlay ${d} failed"; exit 93; }
  done
  mount -t tmpfs tmpfs /run || exit 94
  # A sysfs mounted inside this network namespace lists only this namespace's devices, so a script that writes
  # /sys/class/net/*/queues/* (the edge script binds RPS and XPS) reaches only the fixture's devices, never the guest's.
  mount -t sysfs sysfs /sys || exit 95
  mkdir -p /run/lock /usr/local/sbin /usr/local/libexec/winsvpn /etc/iptables /etc/winsvpn /var/lib/winsvpn
  chmod 700 /etc/winsvpn /var/lib/winsvpn
  ip link set lo up
  ip link add wan0 type dummy
  ip addr add 192.0.2.10/24 dev wan0
  ip link set wan0 up
  ip route add default via 192.0.2.1 dev wan0 onlink
  export FX_T FX_STATE="${FX_T}/state" FX_CAP="${FX_T}/cap"
  export WINS_NODE_SSH_RECOVERY_NODE_ENV_FILE="${FX_T}/node.env"
  export WINS_NODE_SSH_RECOVERY_INSTALLER_PATH="${FX_T}/installer.sh"
  export WINS_DATA_PLANE_INSTALLER_PATH="${FX_T}/installer.sh"
  export NODE_SSH_RECOVERY_STATE_DIR_DEFAULT=/var/lib/winsvpn/ssh-recovery
  export WINS_FIREWALL_LOCK=/run/lock/wins-firewall.lock
  export PATH="${FX_T}/stubs:${PATH}"
  fx_write_stubs
  fx_reset
}

fx_write_stubs() {
  local s="${FX_T}/stubs"
  # A customer service is a listener process: winn3-gateway on 9111, xray on 443, nginx on 80. Stopping the
  # unit kills it, so "a service answered" means a running service really received the packet.
  cat > "${s}/fx_svc" <<'STUB'
#!/bin/bash
# fx_svc start|stop UNIT
port=""
case "$2" in winn3-gateway.service) port=9111 ;; xray.service) port=443 ;; nginx.service) port=80 ;; esac
[[ -n "${port}" ]] || exit 0
pidfile="${FX_STATE}/pid-$2"
if [[ -f "${pidfile}" ]]; then kill "$(cat "${pidfile}")" 2>/dev/null; rm -f "${pidfile}"; fi
if [[ "$1" == start ]]; then
  nohup python3 "${FX_BUNDLE}/fx_listen.py" "${port}" >/dev/null 2>&1 &
  echo $! > "${pidfile}"
  echo $! >> "${FX_T}/bg.pids"
  sleep 0.15
fi
exit 0
STUB
  cat > "${s}/systemctl" <<'STUB'
#!/bin/bash
echo "systemctl $*" >> "${FX_STATE}/trace"
# whether the late-failure record already existed at the handler's first service step (design 5.3 v10 fix 1, step 0)
if [[ ! -e "${FX_STATE}/first-systemctl" ]]; then
  if [[ -e /var/lib/winsvpn/winn3-late-failure.json || -L /var/lib/winsvpn/winn3-late-failure.json ]]; then echo yes; else echo no; fi > "${FX_STATE}/first-systemctl"
fi
verb="${1:-}"
shift || true
args=()
for a in "$@"; do [[ "$a" == -* ]] || args+=("$a"); done
case "${verb}" in
  is-active)   [[ -e "${FX_STATE}/active/${args[0]:-}" ]]; exit $? ;;
  is-enabled)  exit 0 ;;
  stop)        for u in "${args[@]}"; do rm -f "${FX_STATE}/active/${u}"; "$(dirname "$0")/fx_svc" stop "${u}"; done; exit 0 ;;
  disable)     for u in "${args[@]}"; do touch "${FX_STATE}/disabled-${u}"; if [[ " $* " == *" --now "* ]]; then rm -f "${FX_STATE}/active/${u}"; "$(dirname "$0")/fx_svc" stop "${u}"; fi; done; exit 0 ;;
  enable)      for u in "${args[@]}"; do rm -f "${FX_STATE}/disabled-${u}"; done; exit 0 ;;
  start|restart) for u in "${args[@]}"; do touch "${FX_STATE}/active/${u}"; echo "start ${u}" >> "${FX_STATE}/starts"; "$(dirname "$0")/fx_svc" start "${u}"; done; exit 0 ;;
  list-units)  cat "${FX_STATE}/units" 2>/dev/null; exit 0 ;;
  list-jobs)   cat "${FX_STATE}/jobs" 2>/dev/null; exit 0 ;;
  *)           exit 0 ;;
esac
STUB
  cat > "${s}/docker" <<'STUB'
#!/bin/bash
echo "docker $*" >> "${FX_STATE}/trace"
case "${1:-}" in
  stop)    shift; for n in "$@"; do [[ "$n" == -* ]] || { [[ -e "${FX_STATE}/docker/${n}" ]] && echo "false false" > "${FX_STATE}/docker/${n}"; }; done; exit 0 ;;
  inspect) n="${@: -1}"; [[ -e "${FX_STATE}/docker/${n}" ]] && { cat "${FX_STATE}/docker/${n}"; exit 0; }; exit 1 ;;
  update)  shift; if [[ " $* " == *" --restart=no "* ]]; then for n in "$@"; do [[ "$n" == -* ]] || touch "${FX_STATE}/docker-norestart-${n}"; done; fi; exit 0 ;;
  *)       exit 0 ;;
esac
STUB
  # Captures every rules.v4 the guards publish (each rename into place).
  cat > "${s}/mv" <<'STUB'
#!/bin/bash
for last; do :; done
if [[ "${FX_PAUSE_MV:-}" == 1 && "${FX_PAUSE_ENABLED:-}" == 1 && "${last}" == /etc/iptables/rules.v4 ]]; then
  echo "$$ paused ${FX_PAUSE_SECS:-5}s before publishing rules.v4" >> "${FX_STATE}/pauses"
  sleep "${FX_PAUSE_SECS:-5}"
fi
/usr/bin/mv "$@"
rc=$?
if [[ ${rc} == 0 && "${last}" == /etc/iptables/rules.v4 ]]; then
  n=$(ls "${FX_CAP}" 2>/dev/null | wc -l)
  cp -p "${last}" "${FX_CAP}/rules.v4.${n}"
fi
exit ${rc}
STUB
  # sysctl and modprobe are global to the guest (vm.*, kernel.*, module loading), not to this namespace: a script that calls
  # `sysctl --system` or `sysctl -w` would change the guest. The stubs record the call and change nothing.
  for cmd in sysctl modprobe; do
    printf '#!/bin/bash\necho "%s $*" >> "${FX_STATE}/globals-refused"\nexit 0\n' "${cmd}" > "${s}/${cmd}"
  done
  # flock with an optional delay before an fd-9 acquisition, only in processes that set FX_FLOCK_DELAY
  cat > "${s}/flock" <<'STUB'
#!/bin/bash
if [[ -n "${FX_FLOCK_DELAY:-}" && " $* " == *" -x 9 "* ]]; then sleep "${FX_FLOCK_DELAY}"; fi
exec /usr/bin/flock "$@"
STUB
  # Fault injection in front of the real iptables. The counters live in files because each
  # call is its own process.
  cat > "${s}/iptables" <<'STUB'
#!/bin/bash
REAL=/usr/sbin/iptables
state="${FX_STATE:-/tmp}"
args="$*"
echo "${args}" >> "${state}/ipt.log"
mutating=0
case " ${args} " in
  *" -A "*|*" -I "*|*" -D "*|*" -F "*|*" -N "*|*" -X "*|*" -R "*|*" -P "*|*" -Z "*|*" -E "*) mutating=1 ;;
esac
if [[ ${mutating} == 1 ]]; then
  n=$(( $(cat "${state}/ipt.mut" 2>/dev/null || echo 0) + 1 ))
  echo "${n}" > "${state}/ipt.mut"
  if [[ -n "${FX_FAIL_NTH:-}" && "${n}" == "${FX_FAIL_NTH}" && ! -e "${state}/ipt.fired" ]]; then
    touch "${state}/ipt.fired"
    echo "iptables: injected one-shot failure at mutating call ${n}: ${args}" >&2
    echo "${n} ${args}" >> "${state}/ipt.injected"
    exit 1
  fi
fi
if [[ -n "${FX_FAIL_MATCH:-}" && "${args}" =~ ${FX_FAIL_MATCH} && ( -z "${FX_FAIL_ONLYIF:-}" || -n "${!FX_FAIL_ONLYIF:-}" ) ]]; then
  m=$(( $(cat "${state}/ipt.match" 2>/dev/null || echo 0) + 1 ))
  echo "${m}" > "${state}/ipt.match"
  if [[ "${m}" -ge "${FX_FAIL_MATCH_FROM:-1}" && ( -z "${FX_FAIL_MATCH_ONCE:-}" || ! -e "${state}/ipt.matchfired" ) ]]; then
    touch "${state}/ipt.matchfired"
    echo "${FX_FAIL_MSG:-iptables: injected failure}" >&2
    exit "${FX_FAIL_RC:-1}"
  fi
fi
"${REAL}" "$@"
rc=$?
if [[ -n "${FX_REINSERT:-}" && " ${args} " == *" -D WINVPN-INPUT "* && ${rc} == 0 ]]; then
  # a competing writer puts the same rule back right after every delete
  "${REAL}" -w 10 -I WINVPN-INPUT 1 ${FX_REINSERT}
fi
if [[ -n "${FX_PAUSE_MATCH:-}" && "${FX_PAUSE_ENABLED:-}" == 1 && "${args}" =~ ${FX_PAUSE_MATCH} && ! -e "${state}/ipt.paused.$$" ]]; then
  touch "${state}/ipt.paused.$$"
  echo "$$ paused ${FX_PAUSE_SECS:-5}s after: ${args}" >> "${state}/pauses"
  sleep "${FX_PAUSE_SECS:-5}"
fi
if [[ ${mutating} == 1 && -n "${FX_HOOK_AFTER_NTH:-}" && "${n}" == "${FX_HOOK_AFTER_NTH}" && -n "${FX_HOOK_CMD:-}" ]]; then
  # A competing writer acts right after this command (guard delete-and-insert, Fail2Ban insert).
  FX_HOOK_AFTER_NTH="" bash -c "${FX_HOOK_CMD}" >/dev/null 2>&1
fi
exit ${rc}
STUB
  chmod +x "${s}"/*
}

# Reset to a clean node: no rules, no state files, guards installed, services "running".
fx_reset() {
  local pid
  if [[ -s "${FX_T}/bg.pids" ]]; then
    while read -r pid; do kill "${pid}" 2>/dev/null || true; done < "${FX_T}/bg.pids"
    : > "${FX_T}/bg.pids"
    sleep 0.2
  fi
  FX_CLIENT=""
  unset FX_FAIL_NTH FX_FAIL_MATCH FX_FAIL_MATCH_FROM FX_FAIL_MATCH_ONCE FX_FAIL_RC FX_FAIL_MSG FX_HOOK_AFTER_NTH FX_HOOK_CMD FX_FAIL_ONLYIF FX_REINSERT FX_REAL_SETTLE FX_PAUSE_MATCH FX_PAUSE_ENABLED FX_PAUSE_SECS FX_PAUSE_MV
  unset WINS_FIREWALL_LOCK_HELD WINS_FW_LOCK_OWNED WINS_FIREWALL_LOCK_WAIT WINS_NODE_LOCAL_SERVING_LOCK_WAIT WINS_NODE_SSH_RECOVERY_LOCK_WAIT
  local t
  for t in iptables ip6tables; do
    /usr/sbin/${t} -w 10 -P INPUT ACCEPT; /usr/sbin/${t} -w 10 -P FORWARD ACCEPT; /usr/sbin/${t} -w 10 -P OUTPUT ACCEPT
    /usr/sbin/${t} -w 10 -F; /usr/sbin/${t} -w 10 -X
  done
  rm -rf /etc/winsvpn /var/lib/winsvpn /etc/iptables /run/lock /run/wins-suricata-nfq-watchdog /usr/local/libexec/winsvpn
  rm -rf "${FX_STATE}" "${FX_CAP}"
  mkdir -p /etc/winsvpn /var/lib/winsvpn /etc/iptables /run/lock /usr/local/libexec/winsvpn "${FX_STATE}"/{active,docker} "${FX_CAP}"
  chmod 700 /etc/winsvpn /var/lib/winsvpn
  printf 'NODE_MANAGEMENT_TUNNEL_ID=11111111-2222-3333-4444-555555555555\n' > "${FX_T}/node.env"
  chmod 600 "${FX_T}/node.env"
  printf '#!/usr/bin/env bash\n# fixture installer bytes\n' > "${FX_T}/installer.sh"
  FX_SHA="$(sha256sum "${FX_T}/installer.sh" | awk '{print $1}')"
  # The guards are installed under their production names. A one-line wrapper in front records each call
  # (arguments and the lock-convention variables) and execs the production program, so a scenario can assert
  # which guard command the exit path chose and with which bounds.
  local g
  for g in local-serving:wins-node-local-serving:guard_local_serving ssh:wins-node-ssh-recovery-guard:guard_ssh_recovery; do
    IFS=: read -r kind name file <<<"${g}"
    install -o root -g root -m 700 "${FX_BUNDLE}/dp/${file}" "/usr/local/sbin/${name}.real"
    cat > "/usr/local/sbin/${name}" <<WRAP
#!/bin/bash
echo "\$* wait=\${WINS_NODE_LOCAL_SERVING_LOCK_WAIT:-\${WINS_NODE_SSH_RECOVERY_LOCK_WAIT:-unset}} held=\${WINS_FIREWALL_LOCK_HELD:-unset} fwwait=\${WINS_FIREWALL_LOCK_WAIT:-unset}" >> "\${FX_STATE}/${kind}.calls"
exec /usr/local/sbin/${name}.real "\$@"
WRAP
    chmod 700 "/usr/local/sbin/${name}"
  done
  fx_services_up
}

fx_services_up() {
  mkdir -p "${FX_STATE}/active" "${FX_STATE}/docker"
  local u
  for u in winn3-gateway.service xray.service nginx.service; do touch "${FX_STATE}/active/${u}"; "${FX_T}/stubs/fx_svc" start "${u}"; done
  for u in amnezia-awg2 awg amnezia-awg; do echo "true false" > "${FX_STATE}/docker/${u}"; done
}

fx_services_stopped() { # true when no customer service is running
  local u
  for u in winn3-gateway.service xray.service nginx.service; do [[ ! -e "${FX_STATE}/active/${u}" ]] || return 1; done
  for u in amnezia-awg2 awg amnezia-awg; do [[ "$(cat "${FX_STATE}/docker/${u}" 2>/dev/null)" != true* ]] || return 1; done
}

fx_no_service_started() { [[ ! -s "${FX_STATE}/starts" ]]; }

# ---------------------------------------------------------------------------
# Rulesets
# ---------------------------------------------------------------------------
fx_load() { /usr/sbin/iptables-restore --wait 10 < "$1"; } # a restore file (replaces the filter table)

# Is the saved file `$1` safe? Loads it into a throwaway network namespace and runs the
# installer's predicate there, against that namespace's real iptables.
fx_check_saved() {
  local file="$1" mode="${2:-all}"
  [[ -s "${file}" ]] || return 1
  unshare -n bash -c '
    /usr/sbin/iptables-restore --wait 10 < "$1" || exit 3
    python3 "$2/dp/latch_predicate.py" /usr/sbin/iptables "$3"
  ' _ "${file}" "${FX_BUNDLE}" "${mode}"
}

fx_predicate() { # [mode]  (against the current namespace, real iptables via the wrapper)
  python3 "${FX_BUNDLE}/dp/latch_predicate.py" "${IPTABLES_BIN:-iptables}" "${1:-all}"
}

# Every rules.v4 captured so far (and the file on disk) passes S1, S2 and L1.
fx_all_saves_safe() {
  local f bad=0 n=0
  for f in "${FX_CAP}"/rules.v4.*; do
    [[ -e "${f}" ]] || continue
    n=$((n + 1))
    fx_check_saved "${f}" all >"${FX_STATE}/chk.out" 2>&1 || { bad=1; fx_note "unsafe capture ${f##*/}: $(head -c 200 "${FX_STATE}/chk.out" | tr '\n' ' ')"; }
  done
  fx_note "captured saves checked: ${n}"
  return ${bad}
}

# ---------------------------------------------------------------------------
# Real traffic: a client namespace joined by a veth pair
# ---------------------------------------------------------------------------
fx_client_up() {
  [[ -z "${FX_CLIENT}" ]] || return 0
  unshare -n sleep 3000 &
  FX_CLIENT=$!
  echo "${FX_CLIENT}" >> "${FX_T}/bg.pids"
  sleep 0.2
  ip link add fxv0 type veth peer name fxv1 netns "${FX_CLIENT}" || return 1
  ip addr add 10.77.0.1/24 dev fxv0
  ip link set fxv0 up
  nsenter -t "${FX_CLIENT}" -n ip addr add 10.77.0.2/24 dev fxv1
  nsenter -t "${FX_CLIENT}" -n ip link set fxv1 up
  nsenter -t "${FX_CLIENT}" -n ip link set lo up
  sleep 0.2
}

# fx_probe: prints "answered" or "silent" for the three ports on TCP and UDP.
fx_probe() {
  fx_client_up || { echo error; return 1; }
  nsenter -t "${FX_CLIENT}" -n python3 "${FX_BUNDLE}/fx_probe.py" 10.77.0.1 9111 80 443
}
fx_expect_open() { # DESCRIPTION: a control that proves the probe can see a listener
  local out
  out="$(fx_probe)"
  if [[ "${out}" == *silent* || "${out}" == *refused* || "${out}" == error ]]; then fx_fail "$1 :: probe control saw [${out}]"; else fx_ok "$1"; fi
}
fx_expect_dark() { # DESCRIPTION [svc]: net (default) = every probe is silent; svc = nothing answered
  local out
  out="$(fx_probe)"
  if [[ "$2" == svc ]]; then
    if [[ "${out}" == *answered* || "${out}" == error ]]; then fx_fail "$1 :: probe saw [${out}]"; else fx_ok "$1"; fi
  else
    if [[ "${out}" == *answered* || "${out}" == *refused* || "${out}" == error ]]; then fx_fail "$1 :: probe saw [${out}]"; else fx_ok "$1"; fi
  fi
}

# Simulated reboot: a fresh ruleset restored from rules.v4 (netfilter-persistent), then the boot unit's enforce.
# Default: every listener is kept up, so darkness must come from the firewall alone (network level).
# svc: systemd's boot is modelled for the serving units. Every listener is stopped, then each unit that was not disabled
# (`systemctl disable`, recorded by the stub) starts again after the enforce, as an enabled unit does at boot, and each AWG
# container whose restart policy was not set to `no` runs again. Darkness then rests on what the exit path really disabled.
fx_reboot() { # [svc]
  local t
  for t in iptables ip6tables; do
    /usr/sbin/${t} -w 10 -P INPUT ACCEPT; /usr/sbin/${t} -w 10 -P FORWARD ACCEPT; /usr/sbin/${t} -w 10 -F; /usr/sbin/${t} -w 10 -X
  done
  [[ -s /etc/iptables/rules.v4 ]] && /usr/sbin/iptables-restore --wait 10 < /etc/iptables/rules.v4
  rm -rf "${FX_STATE}/starts" "${FX_STATE}/active"
  mkdir -p "${FX_STATE}/active"
  rm -f /run/lock/wins-node-local-serving.lock
  /usr/local/sbin/wins-node-local-serving enforce >"${FX_STATE}/boot-enforce.out" 2>&1
  FX_BOOT_RC=$?
  local u
  for u in winn3-gateway.service xray.service nginx.service; do
    if [[ "${1:-}" == svc ]]; then
      "${FX_T}/stubs/fx_svc" stop "${u}"
      if [[ ! -e "${FX_STATE}/disabled-${u}" ]]; then
        touch "${FX_STATE}/active/${u}"
        echo "boot ${u}" >> "${FX_STATE}/starts"
        "${FX_T}/stubs/fx_svc" start "${u}"
      fi
    else
      [[ -f "${FX_STATE}/pid-${u}" ]] || "${FX_T}/stubs/fx_svc" start "${u}"
    fi
  done
  if [[ "${1:-}" == svc ]]; then
    # Every container went down with the machine. Docker brings back each one whose restart policy is not `no`; a container
    # set to `no` stays down even if it was running at shutdown. Where the real behaviour is not verified on the guest
    # (an `unless-stopped` container that `docker stop` stopped; a boot `systemctl stop` replacing a queued start job), the
    # model starts the unit or container, so a green here never rests on that behaviour (Tier B on amd64t settles both).
    for u in amnezia-awg2 awg amnezia-awg; do
      [[ -e "${FX_STATE}/docker/${u}" ]] || continue
      if [[ -e "${FX_STATE}/docker-norestart-${u}" ]]; then echo "false false"; else echo "true false"; fi > "${FX_STATE}/docker/${u}"
    done
  fi
  sleep 0.2
}

fx_arm_ssh_guard() { # [source]  -> the real `arm`, so the armed.env is the production one
  : > "${FX_STATE}/active/wins-node-ssh-recovery-guard.timer"
  SSH_CONNECTION="${1:-8.8.4.4} 40000 10.0.0.2 22" /usr/local/sbin/wins-node-ssh-recovery-guard arm >"${FX_STATE}/arm.out" 2>&1
}

# A stand-in for the installer's own helpers the extracted functions call.
fx_source_handler() {
  local f
  for f in "${FX_BUNDLE}"/dp/*.sh; do
    # shellcheck disable=SC1090
    source "${f}"
  done
  err()  { printf 'ERR %s\n' "$*" >&2; }
  log()  { printf 'LOG %s\n' "$*" >&2; }
  warn() { printf 'WARN %s\n' "$*" >&2; }
  deploy_firewall_reassert_adguard_owner_guard() { :; }
  require_root() { :; }
}

fx_run_scenario() {
  local name="$1" fn
  fn="sc_${name//-/_}"
  if ! declare -F "${fn}" >/dev/null; then
    FX_SCEN="${name}"
    fx_skip "no such scenario function ${fn}"
    return 0
  fi
  FX_SCEN="${name}"
  fx_reset
  ( "${fn}" )
  FX_SCEN="${name}"
}

# ---------------------------------------------------------------------------
# Small helpers shared by the scenario files
# ---------------------------------------------------------------------------
fx_state()       { fx_load "${FX_BUNDLE}/states/$1.rules"; }
fx_record_on()   { printf '{"stage":"fixture"}' > /var/lib/winsvpn/winn3-late-failure.json; chmod 600 /var/lib/winsvpn/winn3-late-failure.json; }
fx_live_hash()   { /usr/sbin/iptables -S | sort | sha256sum | cut -d' ' -f1; }
fx_file_hash()   { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
fx_seed_rules_v4() { /usr/sbin/iptables-save > /etc/iptables/rules.v4; chmod 600 /etc/iptables/rules.v4; chown root:root /etc/iptables/rules.v4; }
fx_guard()       { /usr/local/sbin/wins-node-local-serving "$@"; }
fx_guard_calls() { cat "${FX_STATE}/local-serving.calls" 2>/dev/null; }    # one line per call: args wait= held= fwwait=
fx_guard_called() { fx_guard_calls | grep -q -- "^$1"; }
fx_sshguard()    { /usr/local/sbin/wins-node-ssh-recovery-guard "$@"; }
fx_wait_bound()  { # SECONDS-LIMIT CMD...: runs CMD, prints elapsed seconds, returns CMD's status
  local limit="$1" start=$SECONDS rc
  shift
  "$@"; rc=$?
  FX_ELAPSED=$(( SECONDS - start ))
  return ${rc}
}
# Hold a lock file with flock for N seconds in the background; the pid is tracked for cleanup.
fx_hold_lock() { # FILE SECONDS
  mkdir -p "$(dirname "$1")"
  [[ -e "$1" ]] || { : > "$1"; chmod 600 "$1"; }
  flock -x "$1" sleep "$2" &
  echo "$!" >> "${FX_T}/bg.pids"
  sleep 0.3
}
fx_latch_file_ok() {
  [[ -f /etc/winsvpn/local-serving.disabled && ! -L /etc/winsvpn/local-serving.disabled ]] \
    && [[ "$(stat -c '%u:%g:%a:%h' /etc/winsvpn/local-serving.disabled)" == 0:0:600:1 ]] \
    && grep -Eq '^REASON=installer-rerun:[0-9a-f]{64}$' /etc/winsvpn/local-serving.disabled
}

# ---------------------------------------------------------------------------
# The real edge firewall artifact (wins-edge-hardening as the installer renders it)
# ---------------------------------------------------------------------------
fx_edge_run() { # builds the authoritative bootstrap ruleset exactly as apply_bootstrap_firewall invokes it
  install -m 755 -o root -g root "${FX_BUNDLE}/dp/edge_hardening" /usr/local/bin/wins-edge-hardening
  printf 'NODE_SLUG=fixture\nNODE_MANAGEMENT_TUNNEL_ENABLED="1"\nPUBLIC_VPN_INGRESS_ADMISSION="0"\n' > "${FX_T}/edge-node.env"
  chmod 600 "${FX_T}/edge-node.env"
  env NODE_ENV_FILE="${FX_T}/edge-node.env" PUBLIC_VPN_INGRESS_ADMISSION=0 INSTALL_DATA_IDS_IPS=0 \
      NODE_MANAGEMENT_TUNNEL_ENABLED=0 IONOS_HUB_IP=8.8.4.4 \
      /usr/local/bin/wins-edge-hardening >"${FX_STATE}/edge.out" 2>&1
  FX_EDGE_RC=$?
}
fx_state_edge() { # the live ruleset becomes the real edge script's output (cached after the first build in a scenario)
  fx_edge_run
  [[ ${FX_EDGE_RC} == 0 ]] || { fx_fail "the edge script failed (rc=${FX_EDGE_RC}): $(tail -3 "${FX_STATE}/edge.out" | tr '\n' ' ')"; return 1; }
}
