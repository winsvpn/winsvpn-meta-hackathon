#!/usr/bin/env bash
# shellcheck disable=SC2034  # globals are read by the other files of the bundle
# Scenarios HANDLER-*: the installer's real exit path (winn3_installer_exit: record, fence, gateway stop,
# repair, gate, guard disable, rollback of the pre-deployment snapshot, reassert) on real iptables, with the two
# real guard programs, a client namespace and a simulated reboot. systemctl and docker are stubs that
# record; everything else is production text.

# fx_handler_setup LIVE SNAPSHOT: the pre-deployment snapshot is SNAPSHOT, the ruleset live at failure time is LIVE.
fx_handler_setup() {
  fx_source_handler
  fx_client_up
  fx_state "$2"
  /usr/sbin/iptables-save > "${FX_T}/pre.snapshot"
  fx_state "$1"
  if [[ -z "${FX_REAL_SETTLE:-}" ]]; then
    winn3_late_settle() { WINN3_LATE_STOPS+=""; }   # the 30 s settle window is covered by its own scenario
  fi
  export WINN3_LATE_ARMED=1 DEPLOY_FIREWALL_ROLLBACK_ARMED=1 DEPLOY_FIREWALL_PRE_SNAPSHOT="${FX_T}/pre.snapshot"
  export WINN3_LATE_STAGE=C
}

fx_handler_exit() { # the EXIT trap body; saves are counted from handler step 2 on
  rm -f "${FX_CAP}"/* "${FX_STATE}/local-serving.calls" "${FX_STATE}/ssh.calls"
  winn3_installer_exit 9 0 >"${FX_STATE}/handler.out" 2>&1
}

fx_record_field() { python3 -c 'import json,sys; print(json.load(open("/var/lib/winsvpn/winn3-late-failure.json")).get(sys.argv[1],"<absent>"))' "$1"; }

# After the exit path, what must hold in every scenario.
fx_handler_post() { # EXPECT_LIVE (pass|any) [fallback]: after the fallback every serving service is stopped
  local live="$1"
  fx_assert "the late-failure record exists" test -e /var/lib/winsvpn/winn3-late-failure.json
  fx_assert "the Winn v3 gateway is stopped" test ! -e "${FX_STATE}/active/winn3-gateway.service"
  if [[ "${2:-}" == fallback ]]; then fx_assert "xray, nginx and the AWG containers are stopped" fx_services_stopped; fi
  fx_no_service_started && fx_ok "no serving unit was started" || fx_fail "a serving unit was started: $(cat "${FX_STATE}/starts")"
  if [[ "${live}" == pass ]]; then
    fx_assert "the live rules pass S1, S2 and L1" fx_predicate all
  fi
  fx_all_saves_safe && fx_ok "every rules.v4 published during the exit path passes S1, S2 and L1" \
    || fx_fail "a published rules.v4 failed S1, S2 or L1"
  fx_expect_dark "TCP and UDP 9111, 80 and 443 are not answered (real probe) before a reboot" "${3:-}"
  fx_note "record: $(cat /var/lib/winsvpn/winn3-late-failure.json)"
}

fx_handler_after_reboot() { # net|svc
  local latch
  latch="$(fx_record_field live_latch 2>/dev/null)"
  fx_reboot "$1"
  if [[ "$1" == net ]]; then
    fx_expect_dark "dark after a reboot, listeners kept (network level)"
  else
    # svc: every unit the exit path left enabled has started again (fx_reboot svc). Where the exit path ended without a
    # dominant latch, the safe fallback must have disabled them (design 5.3: xray, nginx and the AWG containers have not started).
    if [[ "${latch}" != dominant ]]; then
      fx_no_service_started && fx_ok "after a reboot no serving unit started (live_latch ${latch:-absent}: every unit was disabled)" \
        || fx_fail "a serving unit started after the reboot: $(tr '\n' ';' < "${FX_STATE}/starts")"
      fx_assert "after a reboot the AWG containers stay stopped (restart policy no)" fx_services_stopped
    fi
    fx_expect_dark "dark after a reboot, enabled units started as at boot (service level)" svc
  fi
}

# --- the plain case: a late failure, the recovery guard present, nothing contended -----------------
sc_handler_live_dominant() {
  fx_handler_setup chain-open chain-open
  fx_expect_open "control: serving ports answer before the failure"
  fx_handler_exit
  fx_handler_post pass
  fx_eq "the record existed before the first service step of the handler (step 0)" yes "$(cat "${FX_STATE}/first-systemctl" 2>/dev/null)"
  fx_eq "record: live_latch" dominant "$(fx_record_field live_latch)"
  fx_guard_called "disable --reason installer-rerun:$(fx_record_field installer_sha256) wait=20 held=1" \
    && fx_ok "step 2b calls disable with the reason installer-rerun:<sha256>, the 20 s guard-lock bound and HELD=1" \
    || fx_fail "disable was not called with the reason, bound and lock convention: $(fx_guard_calls | tr '\n' ';')"
  fx_eq "record: persist" guard "$(fx_record_field persist)"
  fx_eq "record: fw_lock" held "$(fx_record_field fw_lock)"
  fx_eq "record: latch_file" safe "$(fx_record_field latch_file)"
  fx_assert "the latch file is root 0600 with reason installer-rerun:<sha256>" fx_latch_file_ok
  fx_assert "rules.v4 on disk passes S1, S2 and L1" fx_check_saved /etc/iptables/rules.v4
  fx_handler_after_reboot net
}

# --- snapshot fallback: the rollback's guard check fails, the permissive snapshot is restored ----------
fx_snapshot_case() { # LIVE SNAPSHOT LABEL [guard=absent|locked]
  local mode="${4:-absent}"
  fx_handler_setup "$1" "$2"
  case "${mode}" in
    absent) rm -f /usr/local/sbin/wins-node-ssh-recovery-guard ;;
    locked) mkdir -p /var/lib/winsvpn/ssh-recovery; chmod 700 /var/lib/winsvpn/ssh-recovery
            fx_hold_lock /var/lib/winsvpn/ssh-recovery/guard.lock 40 ;;
  esac
  fx_handler_exit
  fx_handler_post pass fallback
  fx_eq "$3: live_latch" unenforceable "$(fx_record_field live_latch)"
  fx_assert "$3: the latch jump is in the base INPUT chain after the restore" fx_predicate structure
  grep -q 'Restored the pre-deployment iptables snapshot' "${FX_STATE}/handler.out" \
    && fx_ok "$3: the rollback restored the pre-deployment snapshot" || fx_fail "$3: no snapshot restore in the handler log"
  fx_guard_called enforce && fx_fail "$3: the reassert step called enforce although S failed on the restored snapshot" \
    || fx_ok "$3: branch 3 ran and enforce was never called"
  fx_handler_after_reboot net
}

sc_handler_snapshot_open_serving()      { fx_snapshot_case chain-open open-serving "permissive snapshot (no latch jumps)"; }
sc_handler_snapshot_jumps_with_accept() { fx_snapshot_case chain-open chain-france "snapshot with both jumps but 9111 ACCEPTs ahead"; }
sc_handler_snapshot_base_accept()       { fx_snapshot_case chain-open base-443-ahead "snapshot with a base-INPUT 443 ACCEPT ahead of -j WINVPN-INPUT"; }
sc_handler_snapshot_open_serving_locked() { fx_snapshot_case chain-open open-serving "snapshot restore after the guard check timed out" locked; }

# A snapshot that passes S but whose latch body is altered: the reassert calls enforce, and the file passes afterwards.
sc_handler_snapshot_altered_latch() {
  fx_handler_setup chain-open chain-open-altered-latch
  rm -f /usr/local/sbin/wins-node-ssh-recovery-guard
  fx_handler_exit
  fx_handler_post pass
  fx_eq "altered latch body: live_latch ends dominant after enforce" dominant "$(fx_record_field live_latch)"
  fx_guard_called "enforce wait=20 held=1" && fx_ok "the reassert step called enforce with the 20 s bound and HELD=1 (S passed, L did not)" \
    || fx_fail "enforce was not called with its bound and the lock convention: $(fx_guard_calls | tr '\n' ';')"
  fx_assert "altered latch body: rules.v4 on disk passes S1, S2 and L1" fx_check_saved /etc/iptables/rules.v4
  fx_handler_after_reboot net
}

# Lock-held nesting: the installer shell owns fd 7 (WINS_FW_LOCK_OWNED=1); the guard check passes with HELD=1,
# there is no 60 s wait and no snapshot restore.
sc_handler_lock_held_nesting() {
  fx_handler_setup chain-open open-serving
  winn3_installer_fw_lock
  fx_eq "the installer shell owns fd 7" 1 "${WINS_FW_LOCK_OWNED}"
  local start=$SECONDS
  fx_handler_exit
  (( SECONDS - start < 25 )) && fx_ok "no lock wait (took $(( SECONDS - start )) s)" || fx_fail "the exit path waited $(( SECONDS - start )) s"
  fx_handler_post pass
  grep -q 'Restored the pre-deployment iptables snapshot' "${FX_STATE}/handler.out" \
    && fx_fail "the snapshot was restored although the check should pass under HELD=1" || fx_ok "no snapshot restore"
  fx_eq "record: live_latch" dominant "$(fx_record_field live_latch)"
  fx_eq "record: fw_lock" held "$(fx_record_field fw_lock)"
  grep -q '^check wait=20 held=1 fwwait=20' "${FX_STATE}/ssh.calls" \
    && fx_ok "the rollback's guard check runs with the lock convention (HELD=1, 20 s bounds)" \
    || fx_fail "the rollback's guard check lacks the lock convention: $(cat "${FX_STATE}/ssh.calls" 2>/dev/null | tr '\n' ';')"
  fx_handler_after_reboot net
}

# Base-INPUT ACCEPT ahead of -j WINVPN-INPUT (Sol's fixture).
sc_handler_base_accept_ahead() {
  fx_handler_setup base-443-ahead base-443-ahead
  fx_expect_open "control: 443 answers before the failure"
  fx_handler_exit
  fx_handler_post pass
  local rules lat acc
  rules="$(/usr/sbin/iptables -S INPUT | grep '^-A ')"
  lat="$(printf '%s\n' "${rules}" | grep -n -- '-j WINVPN-LOCAL-SERVING' | head -1 | cut -d: -f1)"
  acc="$(printf '%s\n' "${rules}" | grep -n -- '--dport 443 -j ACCEPT' | head -1 | cut -d: -f1)"
  [[ -n "${lat}" && ( -z "${acc}" || "${lat}" -lt "${acc}" ) ]] && fx_ok "the base-INPUT latch jump is ahead of the 443 ACCEPT" \
    || fx_fail "latch jump not ahead of the ACCEPT: ${rules}"
  fx_assert "rules.v4 on disk passes S1, S2 and L1, latch jump ahead of the ACCEPT" fx_check_saved /etc/iptables/rules.v4
  fx_handler_after_reboot net
}

# Dominance fixture: France ordering in the snapshot, the recovery guard check failing.
sc_handler_france_dominance() {
  fx_snapshot_case chain-france chain-france "France ordering (9111 ACCEPT ahead of both latch jumps)"
  # second run: the same ordering live at failure time, a rerun failing before its rebuild
  fx_reset
  fx_handler_setup chain-france chain-open
  fx_handler_exit
  fx_handler_post pass
  fx_eq "France ordering live: step 2a deleted the ACCEPTs and the latch is dominant" dominant "$(fx_record_field live_latch)"
  fx_assert "France ordering live: rules.v4 on disk passes S1, S2 and L1" fx_check_saved /etc/iptables/rules.v4
}

# Combined fixture: the latch was already released (file gone) and the rollback is disarmed; the hub completion fails.
sc_handler_late_completion() {
  fx_handler_setup chain-open chain-open
  fx_guard disable --reason "installer-rerun:${FX_SHA}" >/dev/null 2>&1
  WINS_NODE_LOCAL_SERVING_INSTALLER_PATH="${FX_T}/installer.sh" fx_guard release-deployment --installer-sha256 "${FX_SHA}" >/dev/null 2>&1
  fx_refute "release removed the latch file" test -e /etc/winsvpn/local-serving.disabled
  fx_services_up
  export DEPLOY_FIREWALL_ROLLBACK_ARMED=0
  fx_handler_exit
  fx_handler_post pass
  fx_eq "late completion failure: the exit path re-latches (live_latch)" dominant "$(fx_record_field live_latch)"
  fx_assert "late completion failure: the latch file is back" fx_latch_file_ok
  fx_handler_after_reboot net
}

# The injected rollback failures (v9 fix 9), one per run, with the lock convention kept.
sc_handler_injected_save_refusal() {
  fx_handler_setup chain-open open-serving
  fx_arm_ssh_guard 8.8.4.4
  mkdir -p /run/wins-suricata-nfq-watchdog
  echo "fixture" > /run/wins-suricata-nfq-watchdog/UNRECOVERABLE
  local before
  before="$(fx_file_hash /etc/iptables/rules.v4)"
  fx_handler_exit
  fx_handler_post pass fallback
  [[ -z "$(ls "${FX_CAP}")" && "${before}" == "$(fx_file_hash /etc/iptables/rules.v4)" ]] && fx_ok "no rules.v4 was written during the exit path (every save refused)" \
    || fx_fail "a rules.v4 was written: $(ls "${FX_CAP}")"
  fx_eq "record: live_latch" unenforceable "$(fx_record_field live_latch)"
  fx_handler_after_reboot svc
}

sc_handler_injected_read_failure() {
  fx_handler_setup chain-open open-serving
  # the recovery guard's own `iptables -S INPUT` read fails (verify_recovery_base_jump); the predicate's reads do not
  fx_arm_ssh_guard 8.8.4.4
  export FX_FAIL_MATCH='(^| )-S INPUT$' FX_FAIL_ONLYIF=WINS_NODE_SSH_RECOVERY_LOCK_WAIT FX_FAIL_RC=1 FX_FAIL_MSG="injected read failure"
  fx_handler_exit
  unset FX_FAIL_MATCH FX_FAIL_ONLYIF
  fx_handler_post pass
  grep -q 'Restored the pre-deployment iptables snapshot' "${FX_STATE}/handler.out" \
    && fx_ok "the guard check died before its save, the snapshot was restored" \
    || fx_fail "no snapshot restore after the guard's read failure (design 5.3 expects the restore and branch 3): $(tail -5 "${FX_STATE}/handler.out" | tr '\n' ';')"
  fx_handler_after_reboot net
}

# Direct-from-the-record gate for the exit path itself: a competing guard-lock holder (full: real 20 s bounds).
sc_handler_injected_lock_timeout() {
  fx_handler_setup chain-open open-serving
  fx_arm_ssh_guard 8.8.4.4
  fx_hold_lock /var/lib/winsvpn/ssh-recovery/guard.lock 40
  local start=$SECONDS
  fx_handler_exit
  fx_note "exit path took $(( SECONDS - start )) s with the guard lock held"
  fx_handler_post pass fallback
  grep -q 'Restored the pre-deployment iptables snapshot' "${FX_STATE}/handler.out" \
    && fx_ok "the rollback check timed out and the snapshot was restored" || fx_fail "no snapshot restore after the guard lock timeout"
  fx_handler_after_reboot net
}

# No fd 7 at failure time: another process holds wins_fw_lock across the whole exit path (full: 20 s waits).
sc_handler_no_fd7() {
  fx_handler_setup chain-open open-serving
  fx_hold_lock /run/lock/wins-firewall.lock 45
  fx_handler_exit
  fx_eq "record: fw_lock" unavailable "$(fx_record_field fw_lock)"
  fx_assert "customer services are stopped" fx_services_stopped
  fx_no_service_started && fx_ok "no serving unit started" || fx_fail "a serving unit started"
  fx_note "record: $(cat /var/lib/winsvpn/winn3-late-failure.json)"
}

# Direct fd 7 contention is service-level darkness only; assert it before and after a reboot.
sc_handler_no_fd7_reboot() {
  fx_handler_setup chain-open open-serving
  fx_hold_lock /run/lock/wins-firewall.lock 45
  fx_handler_exit
  fx_handler_after_reboot svc
}

# ---------------------------------------------------------------------------
# Whole-transition guard locking (v9 fix 1, Sol's deterministic pauses)
# A competing guard command is paused at a fixed point while it holds fd 7; the late failure is forced meanwhile.
# ---------------------------------------------------------------------------
fx_count_saves_after_fd7() { # clears the capture the moment the exit path obtains fd 7
  eval "$(declare -f winn3_installer_fw_lock | sed '1s/.*/winn3_installer_fw_lock_orig ()/')"
  winn3_installer_fw_lock() {
    winn3_installer_fw_lock_orig || return 1
    rm -f "${FX_CAP}"/*
    : > "${FX_STATE}/fd7.taken"
  }
}

fx_pause_case() { # LABEL SECONDS MATCH|mv COMPETITOR...
  local label="$1" secs="$2" match="$3"
  shift 3
  fx_handler_setup chain-open open-serving
  fx_arm_ssh_guard 8.8.4.4
  fx_guard disable --reason "installer-rerun:${FX_SHA}" >/dev/null 2>&1
  fx_count_saves_after_fd7
  if [[ "${match}" == mv ]]; then export FX_PAUSE_MV=1; else export FX_PAUSE_MATCH="${match}"; fi
  ( export FX_PAUSE_ENABLED=1 FX_PAUSE_SECS="${secs}"; "$@" >"${FX_STATE}/competitor.out" 2>&1 ) &
  local competitor=$! waited
  for (( waited=0; waited<150; waited++ )); do   # up to 30 s: an emulated guest is slow to reach the pause point
    [[ -s "${FX_STATE}/pauses" ]] && break
    sleep 0.2
  done
  unset FX_PAUSE_MV FX_PAUSE_MATCH
  [[ -s "${FX_STATE}/pauses" ]] && fx_ok "${label}: the competing guard command is paused at its point" \
    || fx_fail "${label}: the competitor never reached its pause point: $(cat "${FX_STATE}/competitor.out")"
  local start=$SECONDS
  fx_handler_exit
  FX_PAUSE_ELAPSED=$(( SECONDS - start ))
  wait "${competitor}" 2>/dev/null
}

fx_pause_points() { # SECONDS ASSERT_MODE
  local secs="$1" mode="$2" label
  local -a labels=("recovery flush" "latch flush" "latch file removal" "before the rename")
  local -a matches=('-F WINVPN-SSH-RECOVERY' '-F WINVPN-LOCAL-SERVING' '-F WINVPN-LOCAL-SERVING' mv)
  local -a commands=("/usr/local/sbin/wins-node-ssh-recovery-guard check" "/usr/local/sbin/wins-node-local-serving enforce"
                     "env WINS_NODE_LOCAL_SERVING_INSTALLER_PATH=${FX_T}/installer.sh /usr/local/sbin/wins-node-local-serving release-deployment --installer-sha256 ${FX_SHA}"
                     "/usr/local/sbin/wins-node-local-serving enforce")
  local i
  for i in 0 1 2 3; do
    label="${labels[i]}"
    fx_reset
    fx_pause_case "${label}" "${secs}" "${matches[i]}" ${commands[i]}
    fx_note "${label}: the exit path ran ${FX_PAUSE_ELAPSED} s"
    if [[ "${mode}" == waits ]]; then
      (( FX_PAUSE_ELAPSED >= secs - 2 )) && fx_ok "${label}: the exit path waited for the paused guard's fd 7" || fx_fail "${label}: no wait (${FX_PAUSE_ELAPSED} s)"
      [[ -e "${FX_STATE}/fd7.taken" ]] && fx_ok "${label}: the exit path obtained fd 7 after the pause" || fx_fail "${label}: fd 7 never obtained"
      fx_eq "${label}: fw_lock held" held "$(fx_record_field fw_lock)"
      fx_all_saves_safe && fx_ok "${label}: every save after the exit path took fd 7 passes S1, S2 and L1" || fx_fail "${label}: an unsafe save followed"
      fx_assert "${label}: the live rules pass S1, S2 and L1" fx_predicate all
    else
      fx_eq "${label}: fw_lock unavailable (pause longer than the 20 s bound)" unavailable "$(fx_record_field fw_lock)"
      fx_assert "${label}: customer services are stopped (service-level darkness)" fx_services_stopped
      fx_note "${label}: the invariant is not asserted past the bound (design 5.3)"
    fi
    fx_handler_after_reboot svc
  done
}

sc_handler_guard_pauses() { fx_pause_points 6 waits; }
sc_handler_guard_pauses_long() { fx_pause_points 26 unavailable; }

# ---------------------------------------------------------------------------
# One-shot failure injection with the next save allowed (v10 fixes 1 and 6)
# A harness fails exactly one mutating iptables command of the whole exit path, then lets every later one succeed.
# ---------------------------------------------------------------------------
fx_sweep_prepare() { # VARIANT LIVE (chain-open | edge)
  fx_handler_setup chain-open open-serving
  if [[ "$2" == edge ]]; then fx_edge_run; fi
  if [[ "$1" == armed ]]; then fx_arm_ssh_guard 8.8.4.4; else rm -f /usr/local/sbin/wins-node-ssh-recovery-guard; fi
  : > "${FX_STATE}/ipt.mut"; rm -f "${FX_STATE}/ipt.fired"
}

fx_sweep_variant() { # armed|noguard [chain-open|edge]
  local variant="$1" live="${2:-chain-open}" total n bad=0 notnet=0 first=1
  fx_reset
  fx_sweep_prepare "${variant}" "${live}"
  fx_handler_exit
  total="$(cat "${FX_STATE}/ipt.mut")"
  fx_note "${variant} on ${live}: the exit path issues ${total} mutating iptables commands"
  for (( n=1; n<=total; n++ )); do
    fx_reset
    fx_sweep_prepare "${variant}" "${live}"
    export FX_FAIL_NTH="${n}"
    fx_handler_exit
    unset FX_FAIL_NTH
    local why=""
    [[ -e /var/lib/winsvpn/winn3-late-failure.json ]] || why+="no record; "
    [[ -e "${FX_STATE}/active/winn3-gateway.service" ]] && why+="gateway running; "
    fx_all_saves_safe >/dev/null 2>&1 || why+="unsafe save; "
    local out
    out="$(fx_probe)"
    [[ "${out}" == *answered* ]] && why+="a service answered ($(sed -n "${n}p" "${FX_STATE}/ipt.injected" 2>/dev/null)); "
    [[ "${out}" == *refused* ]] && notnet=$((notnet + 1))
    if [[ -n "${why}" ]]; then bad=1; fx_fail "${variant}: failing mutating command #${n} (${why})"; fi
    fx_reboot svc
    out="$(fx_probe)"
    [[ "${out}" == *answered* ]] && { bad=1; fx_fail "${variant}: after a reboot a service answered with command #${n} failed"; }
  done
  (( bad == 0 )) && fx_ok "${variant}: with each of ${total} mutating commands failed once, every save passed S1, S2 and L1, the record exists, nothing answered, before and after a reboot"
  fx_note "${variant}: runs where the firewall itself replied with a refusal rather than silence: ${notnet}"
}
sc_handler_injection_sweep_armed()   { fx_sweep_variant armed; }
sc_handler_injection_sweep_noguard() { fx_sweep_variant noguard; }
sc_handler_injection_sweep_edge()    { fx_sweep_variant armed edge; }

# ---------------------------------------------------------------------------
# Recovery body through the exit path (v9 fix 3, v10 fix 5)
# ---------------------------------------------------------------------------
sc_handler_recovery_body_live() {
  fx_handler_setup chain-open-recovery-443 chain-open
  fx_arm_ssh_guard 8.8.4.4
  /usr/sbin/iptables -w 10 -F WINVPN-SSH-RECOVERY
  /usr/sbin/iptables -w 10 -A WINVPN-SSH-RECOVERY -p tcp -m tcp --dport 443 -j ACCEPT
  fx_handler_exit
  fx_handler_post pass
  fx_eq "live at failure time: the recovery chain is the pinned rule" "-A WINVPN-SSH-RECOVERY -s 8.8.4.4/32 -p tcp -m tcp --dport 22 -j ACCEPT" "$(fx_recovery_chain)"
  fx_assert "the saved file passes S1, S2 and L1" fx_check_saved /etc/iptables/rules.v4
}

sc_handler_recovery_body_snapshot() {
  # the pre-deployment snapshot carries the extra 443 ACCEPT; the guard check fails, the snapshot is restored
  fx_handler_setup chain-open chain-open-recovery-443
  fx_arm_ssh_guard 8.8.4.4
  fx_hold_lock /var/lib/winsvpn/ssh-recovery/guard.lock 3
  rm -f /usr/local/sbin/wins-node-ssh-recovery-guard
  fx_handler_exit
  fx_handler_post pass fallback
  fx_eq "snapshot restore: branch 3 rebuilt the recovery chain to the pinned rule" "-A WINVPN-SSH-RECOVERY -s 8.8.4.4/32 -p tcp -m tcp --dport 22 -j ACCEPT" "$(fx_recovery_chain)"
  fx_eq "snapshot restore: s2 ok in the record" ok "$(fx_record_field s2)"
}

sc_handler_recovery_body_invalid_armed() {
  local label
  for label in "bad SOURCE_IPV4" "malformed boot id"; do
    fx_reset
    fx_handler_setup chain-open-recovery-443 chain-open-recovery-443
    fx_arm_ssh_guard 8.8.4.4
    case "${label}" in
      "bad SOURCE_IPV4")   sed -i 's/^SOURCE_IPV4=.*/SOURCE_IPV4=10.0.0.9/' /var/lib/winsvpn/ssh-recovery/armed.env ;;
      "malformed boot id") sed -i 's/^ARM_BOOT_ID=.*/ARM_BOOT_ID=zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz/' /var/lib/winsvpn/ssh-recovery/armed.env ;;
    esac
    /usr/sbin/iptables -w 10 -F WINVPN-SSH-RECOVERY
    /usr/sbin/iptables -w 10 -A WINVPN-SSH-RECOVERY -p tcp -m tcp --dport 443 -j ACCEPT
    local before
    before="$(fx_file_hash /etc/iptables/rules.v4)"
    fx_handler_exit
    fx_guard_calls | grep -q . && fx_fail "${label}: the exit path called the guard although S2 could not be repaired: $(fx_guard_calls | tr '\n' ';')" \
      || fx_ok "${label}: no latch guard command was issued (2b needs a passing 2c gate)"
    fx_eq "${label}: the record says s2 unrepaired" unrepaired "$(fx_record_field s2)"
    fx_eq "${label}: the record says the live latch is unenforceable" unenforceable "$(fx_record_field live_latch)"
    [[ -z "$(ls "${FX_CAP}")" && "${before}" == "$(fx_file_hash /etc/iptables/rules.v4)" ]] \
      && fx_ok "${label}: the exit path wrote no rules.v4" || fx_fail "${label}: a rules.v4 was written: $(ls "${FX_CAP}")"
    fx_refute "${label}: the timer's check dies before any change" fx_sshguard check
    fx_assert "${label}: the services are stopped" fx_services_stopped
    fx_handler_after_reboot svc
  done
}

# Boot-time enforce under the gate (v10 fix 3): the recovery-body fixture is seeded live and in rules.v4.
sc_handler_boot_enforce_gate() {
  fx_source_handler
  fx_client_up
  fx_state chain-open-recovery-443
  fx_guard disable --reason "installer-rerun:${FX_SHA}" >/dev/null 2>&1      # latch file + persisted file (no record yet)
  fx_record_on
  local before
  before="$(fx_file_hash /etc/iptables/rules.v4)"
  rm -f "${FX_CAP}"/*
  # The record exists only after the exit path (an S2 failure is never dominant). Its step 1 disables the gateway unit
  # (`systemctl disable --now`, marked here); the installer's real safe fallback then disables xray and nginx and sets the
  # AWG restart policy to `no` (design 5.3 v11 precondition), so the boot below rests on what that code really left.
  touch "${FX_STATE}/disabled-winn3-gateway.service"
  winn3_late_fallback >/dev/null 2>&1
  local u policy=yes
  for u in amnezia-awg2 awg amnezia-awg; do [[ -e "${FX_STATE}/docker-norestart-${u}" ]] || policy=no; done
  fx_eq "the safe fallback set restart policy no on every AWG container" yes "${policy}"
  : > "${FX_STATE}/trace"
  fx_reboot svc
  fx_refute "boot enforce exits non-zero when the gate refuses on S2" test "${FX_BOOT_RC}" = 0
  fx_eq "rules.v4 byte-identical before and after the boot" "${before}" "$(fx_file_hash /etc/iptables/rules.v4)"
  [[ -z "$(ls "${FX_CAP}")" ]] && fx_ok "no save was attempted successfully during the boot" || fx_fail "a save was published at boot"
  grep -qx 'systemctl stop winn3-gateway.service xray.service nginx.service' "${FX_STATE}/trace" \
    && fx_ok "boot enforce stopped the customer services" || fx_fail "boot enforce did not stop the customer services: $(tr '\n' ';' < "${FX_STATE}/trace")"
  grep -qx 'docker stop amnezia-awg2 awg amnezia-awg' "${FX_STATE}/trace" \
    && fx_ok "boot enforce stopped the AWG containers (bounded docker stop, S7-DOCKER)" || fx_fail "boot enforce did not stop the AWG containers: $(tr '\n' ';' < "${FX_STATE}/trace")"
  fx_no_service_started && fx_ok "no disabled serving unit started at boot" || fx_fail "a serving unit started at boot: $(tr '\n' ';' < "${FX_STATE}/starts")"
  fx_assert "the AWG containers (restart policy no) stay stopped after the boot" fx_services_stopped
  fx_expect_dark "the node is dark after the boot (service level)" svc
}

# ---------------------------------------------------------------------------
# Fence and settle (the real functions, stubbed systemd)
# ---------------------------------------------------------------------------
sc_handler_fence_live_scope() {
  fx_handler_setup chain-open chain-open
  printf 'wins-serving-activation-nginx-1-1.scope loaded active running Fixture\n' > "${FX_STATE}/units"
  printf '77 nginx.service start waiting\n78 winn3-gateway.service start waiting\n' > "${FX_STATE}/jobs"
  fx_handler_exit
  fx_eq "a live activation scope extends the settle window to 120" 120 "$(fx_record_field settle_window_seconds)"
  fx_eq "the fence killed a live scope" yes "$(fx_record_field fence_killed)"
  grep -q 'systemctl kill --signal=SIGKILL wins-serving-activation-\*.scope' "${FX_STATE}/trace" \
    && fx_ok "the fence sent SIGKILL to the activation scopes" || fx_fail "no fence kill in the trace"
  grep -q 'systemctl cancel 77' "${FX_STATE}/trace" && grep -q 'systemctl cancel 78' "${FX_STATE}/trace" \
    && fx_ok "queued start jobs of nginx and the gateway were cancelled" || fx_fail "start jobs were not cancelled"
}

sc_handler_settle_stops_late_restart() {
  FX_REAL_SETTLE=1
  fx_handler_setup chain-open chain-open
  # an in-flight docker restart completes 8 s after the exit path started
  ( sleep 8; echo "true false" > "${FX_STATE}/docker/awg" ) &
  echo "$!" >> "${FX_T}/bg.pids"
  local start=$SECONDS
  fx_handler_exit
  fx_note "exit path took $(( SECONDS - start )) s"
  fx_eq "the late-restarted container was stopped by the settle loop" "false false" "$(cat "${FX_STATE}/docker/awg")"
  fx_eq "the settle loop recorded its stop" yes "$(fx_record_field settle_stops | grep -q 'awg@' && echo yes || echo no)"
  (( SECONDS - start >= 28 )) && fx_ok "the settle window (30 s) ran to its end" || fx_fail "the settle ended early (${SECONDS} s)"
}

# The fourth variant: enforce succeeds but the re-check still fails, so the reassert falls through to branch 3.
sc_handler_enforce_recheck_fails() {
  fx_handler_setup chain-open chain-open-altered-latch
  rm -f /usr/local/sbin/wins-node-ssh-recovery-guard
  # the latch DROP rule can be added twice (step 2a, step 2b); every later add fails, so enforce cannot rebuild the body
  export FX_FAIL_MATCH='-A WINVPN-LOCAL-SERVING -j DROP' FX_FAIL_MATCH_FROM=3 FX_FAIL_RC=1 FX_FAIL_MSG="injected: latch DROP cannot be added"
  fx_handler_exit
  unset FX_FAIL_MATCH FX_FAIL_MATCH_FROM
  fx_guard_called enforce && fx_ok "the reassert step called enforce (S passed, L1 failed)" || fx_fail "enforce was not called: $(fx_guard_calls | tr '\n' ';')"
  fx_eq "enforce succeeded or not, the failed re-check falls through to branch 3 (live_latch)" unenforceable "$(fx_record_field live_latch)"
  fx_assert "customer services are stopped" fx_services_stopped
  fx_no_service_started && fx_ok "no serving unit was started" || fx_fail "a serving unit started"
  fx_handler_after_reboot svc
}

# Lock contention (v8 fix 3): a harness flock holds the local-serving guard's lock file; disable returns within
# 20 s plus 2 s, the safe fallback runs, and no process waits without a bound. (full: real 20 s bound)
sc_handler_guard_lock_contention() {
  fx_handler_setup chain-open open-serving
  fx_hold_lock /run/lock/wins-node-local-serving.lock 90
  local start=$SECONDS
  fx_handler_exit
  local took=$(( SECONDS - start ))
  fx_note "exit path took ${took} s with the guard lock held 90 s"
  (( took < 75 )) && fx_ok "no unbounded wait: the exit path returned in ${took} s (the guard lock was held 90 s)" \
    || fx_fail "the exit path waited ${took} s on a lock held 90 s"
  fx_guard_calls | grep -q 'wait=20' && fx_ok "every guard call carried the 20 s lock bound" || fx_fail "a guard call lacked the bound: $(fx_guard_calls | tr '\n' ';')"
  fx_assert "customer services are stopped by the safe fallback" fx_services_stopped
  fx_assert "the live rules pass S1, S2 and L1 (step 2a placed the latch)" fx_predicate all
  fx_handler_after_reboot svc
}

# Combined fixture with fd 9 contention (v9 fix 2): the latch was released, the completion fails, a flock holds
# the local-serving lock from just before the exit path starts. 2b's disable times out, the reassert's disable
# times out again, branch 3 runs, and the record says latch_file absent. enforce is never called. (full)
sc_handler_combined_fd9_contention() {
  fx_handler_setup chain-open chain-open
  fx_guard disable --reason "installer-rerun:${FX_SHA}" >/dev/null 2>&1
  WINS_NODE_LOCAL_SERVING_INSTALLER_PATH="${FX_T}/installer.sh" fx_guard release-deployment --installer-sha256 "${FX_SHA}" >/dev/null 2>&1
  fx_services_up
  export DEPLOY_FIREWALL_ROLLBACK_ARMED=0
  fx_hold_lock /run/lock/wins-node-local-serving.lock 100
  local start=$SECONDS
  fx_handler_exit
  fx_note "exit path took $(( SECONDS - start )) s"
  fx_eq "record: latch_file" absent "$(fx_record_field latch_file)"
  fx_eq "record: live_latch" unenforceable "$(fx_record_field live_latch)"
  fx_guard_called enforce && fx_fail "the reassert step called enforce although the latch file was absent: $(fx_guard_calls | tr '\n' ';')" \
    || fx_ok "the reassert step used disable, never enforce, with the latch file absent"
  [[ "$(fx_guard_calls | grep -c '^disable')" -ge 2 ]] && fx_ok "disable was tried by step 2b and again by the reassert step" \
    || fx_fail "disable calls: $(fx_guard_calls | tr '\n' ';')"
  fx_assert "customer services are stopped" fx_services_stopped
  fx_all_saves_safe && fx_ok "every rules.v4 published from handler step 2 on passes S1, S2 and L1" || fx_fail "an unsafe save"
  fx_assert "the live rules pass S1, S2 and L1" fx_predicate all
  fx_assert "the latch file is still absent" test ! -e /etc/winsvpn/local-serving.disabled
  fx_handler_after_reboot svc
}

# The serving activator (maintenance, vault unlock and every gated caller run their start through it) refuses to run
# anything while the late-failure record exists, regular file or symlink (5.3 checked starts, v10 fix 2).
sc_handler_serving_activator() {
  fx_source_handler
  winn3_write_serving_activator
  local act=/usr/local/libexec/winsvpn/wins-serving-activate rc
  rm -f "${FX_STATE}/ran"
  "${act}" touch "${FX_STATE}/ran"; rc=$?
  fx_eq "no record: the activator runs the command" 0 "${rc}"
  fx_assert "no record: the command ran" test -e "${FX_STATE}/ran"
  local kind
  for kind in regular symlink dangling; do
    rm -f "${FX_STATE}/ran" /var/lib/winsvpn/winn3-late-failure.json
    case "${kind}" in
      regular)  fx_record_on ;;
      symlink)  : > "${FX_STATE}/target"; ln -s "${FX_STATE}/target" /var/lib/winsvpn/winn3-late-failure.json ;;
      dangling) ln -s /nonexistent /var/lib/winsvpn/winn3-late-failure.json ;;
    esac
    "${act}" touch "${FX_STATE}/ran"; rc=$?
    fx_eq "${kind} record: the activator exits 3 (skip)" 3 "${rc}"
    fx_refute "${kind} record: the command did not run" test -e "${FX_STATE}/ran"
  done
}

# The dominance check the reassert step runs after step 2b takes no guard lock and issues no guard command (v8 fix 3:
# `winn3_latch_dominates` must not call the guard's `status`). A holder takes the local-serving lock right before the
# rollback; the exit path must not wait on it and the guard must see no `status`.
sc_handler_dominance_check_takes_no_guard_lock() {
  fx_handler_setup chain-open chain-open
  eval "$(declare -f deploy_firewall_rollback_on_exit | sed '1s/.*/deploy_firewall_rollback_on_exit_orig ()/')"
  deploy_firewall_rollback_on_exit() {
    fx_hold_lock /run/lock/wins-node-local-serving.lock 40
    deploy_firewall_rollback_on_exit_orig "$@"
  }
  local start=$SECONDS
  fx_handler_exit
  local took=$(( SECONDS - start ))
  (( took < 25 )) && fx_ok "the exit path did not wait on the held guard lock (${took} s)" || fx_fail "the exit path waited ${took} s on the guard lock"
  fx_guard_called status && fx_fail "the exit path called the guard's status: $(fx_guard_calls | tr '\n' ';')" \
    || fx_ok "no guard status call was made by the dominance check"
  fx_eq "record: live_latch" dominant "$(fx_record_field live_latch)"
}

# The sixth forced-restore variant (v9 fix 2): an unsafe latch file is present. The reassert step makes no guard call
# at all and goes to branch 3; the record says the file is unsafe.
sc_handler_unsafe_latch_file() {
  fx_handler_setup chain-open chain-open
  printf 'VERSION=1\nREASON=installer-rerun:%s\nDISABLED_EPOCH=1\n' "${FX_SHA}" > /etc/winsvpn/local-serving.disabled
  chmod 644 /etc/winsvpn/local-serving.disabled          # mode 0644: not the 0600 the guard accepts
  fx_handler_exit
  fx_eq "the unsafe file makes step 2b's disable the only guard call" 1 "$(fx_guard_calls | grep -c .)"
  fx_guard_called "disable" && fx_ok "step 2b called disable (the guard refused the unsafe latch)" || fx_fail "no disable call: $(fx_guard_calls | tr '\n' ';')"
  fx_guard_called enforce && fx_fail "the reassert step called enforce on an unsafe latch file" || fx_ok "the reassert step made no enforce call"
  fx_eq "record: latch_file" unsafe "$(fx_record_field latch_file)"
  fx_eq "record: live_latch" unenforceable "$(fx_record_field live_latch)"
  fx_assert "customer services are stopped" fx_services_stopped
  fx_assert "the live rules pass S1 and S2 (the latch chain and jump were repaired live)" fx_predicate structure
  fx_handler_after_reboot svc
}
