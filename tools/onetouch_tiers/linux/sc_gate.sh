#!/usr/bin/env bash
# shellcheck disable=SC2034  # globals are read by the other files of the bundle
# Scenarios GATE-*: the late-failure persistence gate in the two real guard programs (design 5.3, v10 fix 1).

# disable under a ruleset whose S1 fails: record present refuses and leaves rules.v4 byte-identical.
sc_gate_record_present_refuses() {
  fx_state base-443-ahead
  fx_seed_rules_v4
  local before rc
  before="$(fx_file_hash /etc/iptables/rules.v4)"
  fx_record_on
  fx_guard disable --reason "installer-rerun:${FX_SHA}" >"${FX_STATE}/out" 2>&1; rc=$?
  fx_refute "disable exits non-zero when the gate refuses" test "${rc}" = 0
  fx_eq "rules.v4 byte-identical after the refusal" "${before}" "$(fx_file_hash /etc/iptables/rules.v4)"
  grep -q 'late-failure persistence gate refused' "${FX_STATE}/out" \
    && fx_ok "guard log names the gate refusal" || fx_fail "guard log lacks the gate refusal: $(cat "${FX_STATE}/out")"
  fx_assert "customer services were stopped by the guard" fx_services_stopped
  fx_assert "the durable latch file remains" fx_latch_file_ok
  [[ -z "$(ls "${FX_CAP}")" ]] && fx_ok "no rules.v4 was published" || fx_fail "a rules.v4 was published: $(ls "${FX_CAP}")"
}

# The same call with the record absent saves as before (the gate is dormant).
sc_gate_record_absent_saves() {
  fx_state base-443-ahead
  fx_seed_rules_v4
  local before rc
  before="$(fx_file_hash /etc/iptables/rules.v4)"
  fx_guard disable --reason "installer-rerun:${FX_SHA}" >"${FX_STATE}/out" 2>&1; rc=$?
  fx_eq "disable exits 0 with no record" 0 "${rc}"
  [[ "${before}" != "$(fx_file_hash /etc/iptables/rules.v4)" ]] && fx_ok "rules.v4 was rewritten" || fx_fail "rules.v4 unchanged"
  grep -q -- '-A WINVPN-LOCAL-SERVING -j DROP' /etc/iptables/rules.v4 && fx_ok "saved file carries the latch body" || fx_fail "latch body missing"
}

# A symlink at the record path counts as present, even a dangling one.
sc_gate_symlink_record() {
  fx_state base-443-ahead
  fx_seed_rules_v4
  local before rc
  before="$(fx_file_hash /etc/iptables/rules.v4)"
  ln -s /nonexistent-target /var/lib/winsvpn/winn3-late-failure.json
  fx_guard disable --reason "installer-rerun:${FX_SHA}" >"${FX_STATE}/out" 2>&1; rc=$?
  fx_refute "a dangling symlink record still gates (disable fails)" test "${rc}" = 0
  fx_eq "rules.v4 unchanged under a symlink record" "${before}" "$(fx_file_hash /etc/iptables/rules.v4)"
}

# A passing ruleset with the record present saves, and the saved file passes S1, S2 and L1.
sc_gate_record_present_saves_when_safe() {
  fx_state chain-open
  fx_seed_rules_v4
  fx_record_on
  fx_guard disable --reason "installer-rerun:${FX_SHA}" >"${FX_STATE}/out" 2>&1
  fx_eq "disable exits 0 on a safe ruleset under the record" 0 "$?"
  fx_assert "the file published under the record passes S1, S2 and L1" fx_check_saved /etc/iptables/rules.v4
}

# The SSH recovery guard persists through the same gate.
sc_gate_ssh_guard() {
  fx_state base-443-ahead
  fx_arm_ssh_guard
  grep -q 'armed for one pinned' "${FX_STATE}/arm.out" && fx_ok "real arm succeeded" || fx_fail "arm failed: $(cat "${FX_STATE}/arm.out")"
  fx_assert "armed.env exists" test -f /var/lib/winsvpn/ssh-recovery/armed.env
  local before rc
  before="$(fx_file_hash /etc/iptables/rules.v4)"
  fx_record_on
  fx_sshguard check >"${FX_STATE}/out" 2>&1; rc=$?
  fx_refute "check exits non-zero when its save is refused" test "${rc}" = 0
  grep -q 'late-failure persistence gate refused' "${FX_STATE}/out" \
    && fx_ok "ssh guard log names the gate refusal" || fx_fail "no gate refusal in: $(cat "${FX_STATE}/out")"
  fx_eq "rules.v4 byte-identical after the ssh guard's refused save" "${before}" "$(fx_file_hash /etc/iptables/rules.v4)"
}

# fd 7 held past WINS_FIREWALL_LOCK_WAIT: enforce and disable exit non-zero, stop the services, change nothing, and
# change nothing BEFORE they hold fd 7 either (the latch file is not created, a flushed latch chain is not refilled).
sc_gate_fd7_timeout() {
  local command rc live before_file
  for command in "enforce" "disable --reason installer-rerun:${FX_SHA}"; do
    fx_reset
    fx_state chain-open
    fx_guard disable --reason "installer-rerun:${FX_SHA}" >/dev/null 2>&1
    if [[ "${command%% *}" == enforce ]]; then
      /usr/sbin/iptables -w 10 -F WINVPN-LOCAL-SERVING      # a latch file with a lost chain: enforce would rebuild it
    else
      rm -f /etc/winsvpn/local-serving.disabled              # no latch file: disable would write one
    fi
    fx_services_up
    live="$(fx_live_hash)"; before_file="$(fx_file_hash /etc/iptables/rules.v4)"
    fx_hold_lock /run/lock/wins-firewall.lock 12
    WINS_FIREWALL_LOCK_WAIT=2 fx_wait_bound 8 fx_guard ${command} >"${FX_STATE}/out" 2>&1; rc=$?
    fx_refute "${command%% *} exits non-zero when fd 7 is held (rc=${rc})" test "${rc}" = 0
    fx_assert "${command%% *} still stops the customer services on the fd 7 timeout" fx_services_stopped
    fx_eq "${command%% *} changed no chain before or after the timeout" "${live}" "$(fx_live_hash)"
    fx_eq "${command%% *} left rules.v4 unchanged" "${before_file}" "$(fx_file_hash /etc/iptables/rules.v4)"
    if [[ "${command%% *}" == disable ]]; then
      fx_refute "disable did not create the latch file before holding fd 7" test -e /etc/winsvpn/local-serving.disabled
    fi
    (( FX_ELAPSED <= 6 )) && fx_ok "${command%% *} returned within the bounded wait (${FX_ELAPSED} s)" || fx_fail "${command%% *} waited ${FX_ELAPSED} s"
  done
}

# status does not take fd 7, and waits for fd 9 only as long as the caller's bound.
sc_gate_status_bounds() {
  fx_state chain-open
  fx_guard disable --reason "installer-rerun:${FX_SHA}" >/dev/null 2>&1
  fx_hold_lock /run/lock/wins-firewall.lock 8
  fx_wait_bound 5 fx_guard status >"${FX_STATE}/out" 2>&1
  fx_eq "status succeeds while fd 7 is held" 0 "$?"
  fx_eq "status says disabled" disabled "$(tail -n1 "${FX_STATE}/out")"
  fx_hold_lock /run/lock/wins-node-local-serving.lock 10
  WINS_NODE_LOCAL_SERVING_LOCK_WAIT=2 fx_wait_bound 8 fx_guard status >"${FX_STATE}/out" 2>&1; local rc=$?
  fx_refute "status with fd 9 held past its bound exits non-zero" test "${rc}" = 0
  (( FX_ELAPSED <= 5 )) && fx_ok "status waited for fd 9 only its bound (${FX_ELAPSED} s)" || fx_fail "status waited ${FX_ELAPSED} s"
}

# Fail2Ban's and the Cloudflare stealth jumps ahead of the latch are admitted by the gate when their bodies are the checked
# forms (v11 fix 1, v12 fix 4): the guard saves under the record. With an ACCEPT inside f2b-sshd the gate refuses.
sc_gate_admitted_jumps_ahead() {
  local state before rc
  for state in chain-f2b-ahead chain-cf-ahead; do
    fx_reset
    fx_state "${state}"
    fx_seed_rules_v4
    fx_record_on
    fx_guard disable --reason "installer-rerun:${FX_SHA}" >"${FX_STATE}/out" 2>&1; rc=$?
    fx_eq "${state}: disable exits 0 under the record" 0 "${rc}"
    fx_assert "${state}: the saved file passes S1, S2 and L1" fx_check_saved /etc/iptables/rules.v4
  done
  fx_reset
  fx_state chain-f2b-accept-inside
  fx_seed_rules_v4
  before="$(fx_file_hash /etc/iptables/rules.v4)"
  fx_record_on
  fx_guard disable --reason "installer-rerun:${FX_SHA}" >"${FX_STATE}/out" 2>&1; rc=$?
  fx_refute "an ACCEPT inside f2b-sshd: the gate refuses (disable fails)" test "${rc}" = 0
  fx_eq "an ACCEPT inside f2b-sshd: rules.v4 unchanged" "${before}" "$(fx_file_hash /etc/iptables/rules.v4)"
}
