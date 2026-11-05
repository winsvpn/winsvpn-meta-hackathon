#!/usr/bin/env bash
# s7_tb09.sh: one run of a Tier B TB-09 variant, "checked starts in flight when the fallback runs" (design v17 5.3,
# variants 1 to 4, 6, 8 and 9). Root on a DEPLOYED guest; staged by tier_b.py into the work directory.
#
#   s7_tb09.sh start     V TAG   launch the unchanged installer as a detached unit, its forced late failure HELD at the
#                                shim (the run's `ip route` after phase B waits for OUT/go), and wait until it is held
#   s7_tb09.sh caller    V TAG   install the variant's stop hook and start the gated caller (the installed
#                                wins_serving_start, as weekly maintenance and vault unlock run it); identify child,
#                                timeout and parent; print their PIDs, process groups and the spawn time
#   s7_tb09.sh interfere V TAG [CLIENT D]   the variant's interference, then release the forced failure (touch OUT/go)
#   s7_tb09.sh finish    V TAG   wait for the installer unit, restore the production activator, SIGCONT the stopped
#                                process groups, wait 30 s, and print what the evaluator judges
#
# Every phase prints key=value lines only (tierb_eval.evaluate_tb09 reads them). Nothing is killed by pattern: every
# signal goes to a PID or process group this script identified from the activation scope's cgroup.
set -u
PHASE="${1:?phase}"
V="${2:?variant}"
TAG="${3:?tag}"
WORK="${S7_WORK:-/root/s7-work}"
OUT="${WORK}/tb09/${TAG}"
INSTALLER="${S7_INSTALLER:-/root/wins_data_plane_setup_ONETOUCH.sh}"
SECRETS="${S7_SECRETS_FILE:-/root/winsvpn-secrets.env}"
SHIM_DIR="${S7_SHIM_DIR:-/run/s7-shims}"
SHIM_STATE="${SHIM_DIR}.state"
ACT=/usr/local/libexec/winsvpn/wins-serving-activate
LOCK=/run/lock/wins-serving-activation.lock
RECORD=/var/lib/winsvpn/winn3-late-failure.json
MAINT=/usr/local/bin/wins-weekly-maintenance
VAULT=/usr/local/sbin/wins-vault-unlock

# each phase's lines also go to OUT/PHASE.out, which the later phases read
emit() {
  printf '%s=%s\n' "$1" "$2"
  [[ -d "${OUT}" ]] && printf '%s=%s\n' "$1" "$2" >> "${OUT}/${PHASE}.out"
  return 0
}
now() { date +%s.%N; }
fail() { emit error "$*"; exit 2; }
awg_name() {
  local n
  for n in amnezia-awg2 awg amnezia-awg; do
    docker inspect "${n}" >/dev/null 2>&1 && { printf '%s' "${n}"; return 0; }
  done
  return 1
}
proc_field() { awk -v k="$2:" '$1 == k {print $2; exit}' "/proc/$1/status" 2>/dev/null; }
pgid_of() { awk '{print $5}' "/proc/$1/stat" 2>/dev/null; }
# The epoch at which PID started: boot time plus its start tick (field 22 of /proc/PID/stat).
start_epoch() {
  python3 - "$1" <<'PY'
import os, sys
pid = sys.argv[1]
try:
    fields = open("/proc/%s/stat" % pid).read().rsplit(")", 1)[1].split()
    ticks = int(fields[19])
    btime = next(int(l.split()[1]) for l in open("/proc/stat") if l.startswith("btime "))
    print("%.2f" % (btime + ticks / os.sysconf("SC_CLK_TCK")))
except Exception:
    print("")
PY
}
# The installed scripts carry wins_serving_start in `declare -f` form (winn3_prepend_shared_functions, DP 22287):
# a `wins_serving_start () ` header line, `{ ` on the next. The installer's own source form is accepted too.
serving_start_fn() { awk '/^wins_serving_start ?\(\)/ {p = 1} p {print} p && /^}$/ {exit}' "$1" 2>/dev/null; }
scopes() { systemctl list-units --plain --no-legend --state=active,activating,deactivating 'wins-serving-activation-*.scope' 2>/dev/null | awk '{print $1}'; }
scope_procs() {
  local cg
  cg="$(systemctl show -p ControlGroup --value "$1" 2>/dev/null)"
  [[ -n "${cg}" ]] && cat "/sys/fs/cgroup${cg}/cgroup.procs" 2>/dev/null
}

caller_command() { # V -> the caller name and the command its gated child runs
  case "$1" in
    1|2|3) printf 'weekly-nginx systemctl restart nginx' ;;
    4) printf 'vault systemctl start nginx.service xray.service' ;;
    8) printf 'weekly-awg docker restart %s' "$(awg_name)" ;;
    *) return 1 ;;
  esac
}

case "${PHASE}" in
start)
  [[ -f "${INSTALLER}" && -f "${SECRETS}" ]] || fail "installer or secrets file not staged"
  [[ ! -e "${RECORD}" ]] || fail "a late-failure record is present; recover with a normal rerun first"
  [[ -x "${SHIM_DIR}/ip" && -x "${SHIM_DIR}/flock" && -x "${SHIM_DIR}/systemctl" && -x "${SHIM_DIR}/docker" ]] || fail "the TB-09 shims are not installed"
  [[ ! -e "${SHIM_STATE}/flock.log" && ! -e "${SHIM_STATE}/systemctl.log" ]] || fail "shim logs from an earlier run are present; reinstall the shims"
  rm -rf "${OUT}"
  install -d -m 700 "${OUT}"
  rm -f /run/s7-phase-b-done
  cp -p "${ACT}" "${OUT}/activate.orig" || fail "no production activator at ${ACT}"
  for u in nginx.service xray.service winn3-gateway.service; do emit "pre_${u%%.*}" "$(systemctl is-active "${u}")"; done
  systemd-run --unit="s7-tb09-installer-${TAG}" --collect --quiet -p Type=exec \
    -p StandardOutput="append:${OUT}/installer.log" -p StandardError="append:${OUT}/installer.log" \
    --setenv=HOME=/root --setenv=DEBIAN_FRONTEND=noninteractive \
    --setenv=PATH="${SHIM_DIR}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    --setenv=WINS_SECRETS_FILE="${SECRETS}" \
    /bin/bash "${INSTALLER}" --deploy || fail "could not start the installer unit"
  emit installer_started "$(now)"
  for _ in $(seq 1 3600); do
    [[ -e "${OUT}/held" ]] && break
    systemctl is-active --quiet "s7-tb09-installer-${TAG}" || break
    sleep 1
  done
  [[ -e "${OUT}/held" ]] || fail "the installer ended or timed out before the forced failure point: $(tail -3 "${OUT}/installer.log" | tr '\n' ' ')"
  emit held_at "$(now)"
  ;;

caller)
  [[ -e "${OUT}/held" ]] || fail "start first"
  case "${V}" in
    6) emit caller none; exit 0 ;;
    9) fail "variant 9 starts its clients in interfere" ;;
  esac
  read -r CALLER CMD <<<"$(caller_command "${V}")" || fail "no caller for variant ${V}"
  [[ -n "${CMD}" ]] || fail "variant ${V}: the caller command is empty (no AWG container?)"
  FN="$(serving_start_fn "${MAINT}")"
  [[ -n "${FN}" ]] || FN="$(serving_start_fn "${VAULT}")"
  [[ "${FN}" == *'timeout -k 5 100 systemd-run --scope'* ]] || fail "the installed wins_serving_start was not found"
  if [[ "${V}" == 4 ]]; then
    # variant 4: the PARENT stops itself after its flock, before it spawns the child
    FN="${FN/  timeout -k 5 100 systemd-run/  kill -STOP \"\${BASHPID}\"
  timeout -k 5 100 systemd-run}"
  else
    # variants 1 to 3 and 8: the bounded child stops itself right after its record check
    python3 - "${ACT}" <<'PY' || fail "could not install the stop hook"
import sys
path = sys.argv[1]
text = open(path).read()
if text.count('exec "$@"') != 1:
    raise SystemExit("unexpected activator text")
open(path, "w").write(text.replace('exec "$@"', 'kill -STOP $$\nexec "$@"'))
PY
  fi
  { printf '%s\n' "${FN}"; printf 'wins_serving_start %s %s\n' "${CALLER}" "${CMD}"; printf 'echo "caller_rc=$?"\n'; } > "${OUT}/caller.sh"
  systemd-run --unit="s7-tb09-caller-${TAG}" --collect --quiet -p Type=exec \
    -p StandardOutput="append:${OUT}/caller.log" -p StandardError="append:${OUT}/caller.log" /bin/bash "${OUT}/caller.sh" \
    || fail "could not start the caller"
  emit caller "${CALLER}"
  emit caller_started "$(now)"
  child="" scope="" parent="" tmo=""
  for _ in $(seq 1 300); do
    sleep 0.1
    if [[ "${V}" == 4 ]]; then
      parent="$(systemctl show -p MainPID --value "s7-tb09-caller-${TAG}" 2>/dev/null)"
      # the subshell that holds fd 6 is the unit's main bash's child; it is the one that stopped itself
      for p in $(pgrep -P "${parent}" 2>/dev/null); do
        [[ "$(proc_field "${p}" State)" == T ]] && { emit parent_pid "${p}"; emit parent_pgid "$(pgid_of "${p}")"; emit parent_stopped_at "$(now)"; exit 0; }
      done
      continue
    fi
    scope="$(scopes | head -n 1)"
    [[ -n "${scope}" ]] || continue
    child="$(scope_procs "${scope}" | head -n 1)"
    [[ -n "${child}" && "$(proc_field "${child}" State)" == T ]] || continue
    tmo="$(proc_field "${child}" PPid)"
    parent="$(proc_field "${tmo}" PPid)"
    emit scope "${scope}"
    emit child_pid "${child}"
    emit child_spawned "$(start_epoch "${child}")"
    emit timeout_pid "${tmo}"
    emit timeout_comm "$(cat "/proc/${tmo}/comm" 2>/dev/null)"
    emit timeout_pgid "$(pgid_of "${tmo}")"
    emit parent_pid "${parent}"
    emit parent_pgid "$(pgid_of "${parent}")"
    emit child_fd6 "$(readlink "/proc/${child}/fd/6" 2>/dev/null)"
    emit stopped_at "$(now)"
    exit 0
  done
  fail "the gated child never stopped after its check"
  ;;

interfere)
  [[ -e "${OUT}/held" ]] || fail "start first"
  cv() { sed -n "s/^$1=//p" "${OUT}/caller.out" 2>/dev/null | tail -n 1; }
  CHILD="$(cv child_pid)"; TMO="$(cv timeout_pid)"; SPAWNED="$(cv child_spawned)"
  go() { emit released_at "$(now)"; : > "${OUT}/go"; }
  case "${V}" in
  1)
    go
    sleep 30
    emit child_continued_at "$(now)"
    kill -CONT "${CHILD}" 2>/dev/null
    ;;
  2)
    go
    python3 -c "import time,sys; time.sleep(max(0.0, float(sys.argv[1]) + 106 - time.time()))" "${SPAWNED}"
    emit checked_at "$(now)"
    if [[ -d "/proc/${CHILD}" ]]; then emit child_at_106 "$(proc_field "${CHILD}" State | cut -c1)"; else emit child_at_106 gone; fi
    ;;
  3)
    kill -STOP "${TMO}" 2>/dev/null && emit timeout_stopped_at "$(now)"
    SCOPE="$(cv scope)"
    SCOPE_START="$(systemctl show -p ActiveEnterTimestamp --value "${SCOPE}" 2>/dev/null)"
    emit scope_started "$(date -d "${SCOPE_START}" +%s.%N 2>/dev/null || cv child_spawned)"
    go
    python3 -c "import time,sys; time.sleep(max(0.0, float(sys.argv[1]) + 106 - time.time()))" "${SPAWNED}"
    emit checked_at "$(now)"
    procs="$(scope_procs "${SCOPE}" | tr '\n' ' ')"
    emit scope_procs_at_106 "${procs:-empty}"
    if [[ -d "/proc/${CHILD}" ]]; then emit child_at_106 "$(proc_field "${CHILD}" State | cut -c1)"; else emit child_at_106 gone; fi
    emit scope_journal "$(journalctl --no-pager -o cat -u "${SCOPE}" 2>/dev/null | grep -E "runtime|Failed with result|Deactivated" | tr '\n' '|' | cut -c1-400)"
    emit timeout_state_at_106 "$(proc_field "${TMO}" State | cut -c1)"
    ;;
  4|6)
    if [[ "${V}" == 6 ]]; then
      ( flock -x "${LOCK}" sleep 130 ) >/dev/null 2>&1 &
      emit holder_pid "$!"
      sleep 1
    fi
    go
    ;;
  8)
    NAME="$(awg_name)" || fail "no AWG container"
    install -d -m 755 /etc/systemd/system/nginx.service.d
    printf '[Service]\nExecStartPre=/bin/sleep 20\n' > /etc/systemd/system/nginx.service.d/s7-tb09.conf
    systemctl daemon-reload
    systemctl stop nginx.service
    systemctl start --no-block nginx.service
    emit nginx_job "$(systemctl list-jobs --no-legend 2>/dev/null | awk '$2 == "nginx.service" {print $1 "/" $3 "/" $4}' | head -n 1)"
    emit restart_requested_at "$(now)"
    kill -CONT "${CHILD}" 2>/dev/null
    sleep 1
    go
    # the in-flight client is killed (its scope SIGKILLed by unit name) once the handler's first `flock -n 6` has run
    # while the client still held fd 6, so the record's window is the contended 120 s, not a timing accident
    for _ in $(seq 1 600); do
      grep -q ' -n 6$' "${SHIM_STATE}/flock.log" 2>/dev/null && break
      sleep 0.1
    done
    emit first_flock_seen "$(awk '$2 == "-n" && $3 == "6" {print $1; exit}' "${SHIM_STATE}/flock.log" 2>/dev/null)"
    systemctl kill --signal=SIGKILL "$(cv scope)" >/dev/null 2>&1
    emit client_killed_at "$(now)"
    emit container "${NAME}"
    ;;
  9)
    CLIENT="${4:?client keep|closed}"
    D="${5:?delay seconds}"
    NAME="$(awg_name)" || fail "no AWG container"
    emit client "${CLIENT}"
    emit d "${D}"
    emit container "${NAME}"
    rm -f "${OUT}/laststop"
    PROXY_SOCK="${OUT}/docker-proxy.sock"
    python3 "${WORK}/s7_docker_proxy.py" "${PROXY_SOCK}" "${OUT}/laststop" "${D}" "${OUT}/proxy.log" >/dev/null 2>&1 &
    emit proxy_pid "$!"
    for _ in $(seq 1 50); do [[ -S "${PROXY_SOCK}" ]] && break; sleep 0.1; done
    FN="$(serving_start_fn "${MAINT}")"
    [[ "${FN}" == *'timeout -k 5 100 systemd-run --scope'* ]] || fail "the installed wins_serving_start was not found"
    if [[ "${CLIENT}" == keep ]]; then
      CMD="env DOCKER_HOST=unix://${PROXY_SOCK} docker restart ${NAME}"
    else
      # the checked child forks a descendant that closes fd 6 and runs the restart, then exits without a start
      CMD="setsid -f /bin/bash -c 'exec 6>&-; exec env DOCKER_HOST=unix://${PROXY_SOCK} docker restart ${NAME}'"
    fi
    { printf '%s\n' "${FN}"; printf 'wins_serving_start weekly-awg %s\n' "${CMD}"; printf 'echo "caller_rc=$?"\n'; } > "${OUT}/caller.sh"
    systemd-run --unit="s7-tb09-caller-${TAG}" --collect --quiet -p Type=exec \
      -p StandardOutput="append:${OUT}/caller.log" -p StandardError="append:${OUT}/caller.log" /bin/bash "${OUT}/caller.sh"
    emit caller_started "$(now)"
    client_pid="" scope=""
    for _ in $(seq 1 80); do
      sleep 0.1
      grep -q '^accepted POST .*/restart' "${OUT}/proxy.log" 2>/dev/null || continue
      scope="$(scopes | head -n 1)"
      [[ -n "${scope}" ]] || continue
      for p in $(scope_procs "${scope}"); do
        [[ "$(cat "/proc/${p}/comm" 2>/dev/null)" == docker ]] && client_pid="${p}"
      done
      [[ -n "${client_pid}" ]] && break
    done
    [[ -n "${client_pid}" ]] || fail "the docker client never reached the proxy inside the activation scope"
    emit scope "${scope}"
    emit client_pid "${client_pid}"
    emit client_spawned "$(start_epoch "${client_pid}")"
    emit client_fd6 "$(readlink "/proc/${client_pid}/fd/6" 2>/dev/null)"
    if [[ "${CLIENT}" == closed ]]; then
      for _ in $(seq 1 50); do systemctl is-active --quiet "s7-tb09-caller-${TAG}" || break; sleep 0.1; done
      emit caller_unit_after_handoff "$(systemctl is-active "s7-tb09-caller-${TAG}" 2>/dev/null)"
      emit lock_holders "$(grep -c " $(stat -c %i "${LOCK}") " /proc/locks 2>/dev/null)"
    fi
    go
    # the hook: the handler's gateway `disable --now` right after its fence, read from the systemctl shim's log
    for _ in $(seq 1 1800); do
      if grep -q 'disable --now winn3-gateway.service' "${SHIM_STATE}/systemctl.log" 2>/dev/null; then
        : > "${OUT}/laststop"; emit laststop_at "$(now)"; emit hook gateway-disable-now; break
      fi
      sleep 0.1
    done
    ;;
  *) fail "variant ${V} has no interference here" ;;
  esac
  ;;

finish)
  for _ in $(seq 1 900); do
    systemctl is-active --quiet "s7-tb09-installer-${TAG}" || break
    sleep 1
  done
  emit installer_active_at_finish "$(systemctl is-active "s7-tb09-installer-${TAG}" 2>/dev/null)"
  emit exit_path_ended "$(now)"
  # the forced failure is the ip shim's held call: `released` when go appeared, `wait-timeout` if it never did
  emit installer_failed "$(grep -c ' released$' "${SHIM_STATE}/ip.log" 2>/dev/null)"
  emit ip_wait_timeout "$(grep -c ' wait-timeout$' "${SHIM_STATE}/ip.log" 2>/dev/null)"
  if [[ -f "${OUT}/activate.orig" ]]; then cp -p "${OUT}/activate.orig" "${ACT}" && emit activator restored; fi
  sed -n 's/^\(timeout_pgid\|parent_pgid\)=//p' "${OUT}/caller.out" 2>/dev/null | sort -u | while read -r g; do
    [[ "${g}" =~ ^[1-9][0-9]*$ ]] && kill -CONT -- "-${g}" 2>/dev/null
  done
  for p in $(sed -n 's/^\(child_pid\|timeout_pid\|parent_pid\)=//p' "${OUT}/caller.out" 2>/dev/null); do kill -CONT "${p}" 2>/dev/null; done
  emit continued_at "$(now)"
  sleep 30
  rm -f /etc/systemd/system/nginx.service.d/s7-tb09.conf && systemctl daemon-reload
  for u in nginx.service xray.service winn3-gateway.service; do emit "after_${u%%.*}" "$(systemctl is-active "${u}")"; done
  for n in amnezia-awg2 awg amnezia-awg; do
    s="$(docker inspect -f '{{.State.Running}} {{.State.StartedAt}}' "${n}" 2>/dev/null)" && emit "container_${n}" "${s}"
  done
  # every `docker stop <name>` the installer issued (handler, fallback, settle check), with its epoch
  for n in amnezia-awg2 awg amnezia-awg; do
    s="$(awk -v n="${n}" '$2 == "stop" {for (i = 3; i <= NF; i++) if ($i == n) {printf "%s ", $1; break}}' "${SHIM_STATE}/docker.log" 2>/dev/null)"
    [[ -n "${s}" ]] && emit "docker_stops_${n}" "${s% }"
  done
  emit record "$(tr -d '\n' < "${RECORD}" 2>/dev/null)"
  emit record_mtime "$(stat -c %Y "${RECORD}" 2>/dev/null)"
  emit first_flock "$(awk '$2 == "-n" && $3 == "6" {print $1; exit}' "${SHIM_STATE}/flock.log" 2>/dev/null)"
  emit last_handler_stop "$( { grep -E '^[0-9.]+ (stop|disable --now|kill) ' "${SHIM_STATE}/systemctl.log"; grep -E '^[0-9.]+ stop ' "${SHIM_STATE}/docker.log"; } 2>/dev/null | awk '{print $1}' | sort -n | tail -n 1)"
  emit serving_starts "$(journalctl --no-pager -o short-unix --since "@$(sed -n 's/^released_at=//p' "${OUT}/interfere.out" | tail -n 1 | cut -d. -f1)" \
    -u nginx.service -u xray.service -u winn3-gateway.service 2>/dev/null | grep -E 'Started |Starting ' | awk '{print $1}' | tr '\n' ' ')"
  emit caller_log "$(tr '\n' '|' < "${OUT}/caller.log" 2>/dev/null | cut -c1-600)"
  emit proxy_log "$(tr '\n' '|' < "${OUT}/proxy.log" 2>/dev/null | cut -c1-600)"
  pid="$(sed -n 's/^proxy_pid=//p' "${OUT}/interfere.out" 2>/dev/null | tail -n 1)"
  [[ "${pid}" =~ ^[1-9][0-9]*$ ]] && kill "${pid}" 2>/dev/null
  pid="$(sed -n 's/^holder_pid=//p' "${OUT}/interfere.out" 2>/dev/null | tail -n 1)"
  [[ "${pid}" =~ ^[1-9][0-9]*$ ]] && kill "${pid}" 2>/dev/null
  emit variant "${V}"
  ;;
*) fail "unknown phase ${PHASE}" ;;
esac
