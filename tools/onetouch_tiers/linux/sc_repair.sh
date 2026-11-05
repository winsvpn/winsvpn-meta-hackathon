#!/usr/bin/env bash
# shellcheck disable=SC2034  # globals are read by the other files of the bundle
# Scenarios REPAIR-*: handler step 2a and the branch 3 repair (`winn3_late_repair_live`) on real iptables.

fx_wi_body() { /usr/sbin/iptables -S WINVPN-INPUT | grep '^-A '; }
fx_input_rules() { /usr/sbin/iptables -S INPUT | grep '^-A '; }

# Three identical serving ACCEPTs above the guards are all deleted; a rule that is not an ACCEPT stays.
sc_repair_deletes_accepts() {
  fx_source_handler
  fx_state chain-open-3x9111
  /usr/sbin/iptables -w 10 -I WINVPN-INPUT 1 -s 1.2.3.4/32 -j DROP
  winn3_late_repair_live full
  local body rec acc
  body="$(fx_wi_body)"
  rec="$(printf '%s\n' "${body}" | grep -n -- '-j WINVPN-SSH-RECOVERY' | head -1 | cut -d: -f1)"
  acc="$(printf '%s\n' "${body}" | grep -n -- '--dport 9111 -j ACCEPT' | head -1 | cut -d: -f1)"
  if [[ -z "${acc}" || "${acc}" -gt "${rec}" ]]; then fx_ok "no TCP 9111 ACCEPT remains ahead of the recovery jump (all three copies deleted)"
  else fx_fail "an ACCEPT copy remains ahead of the guards: ${body}"; fi
  printf '%s\n' "${body}" | grep -q -- '-s 1.2.3.4/32 -j DROP' && fx_ok "a rule whose target is not ACCEPT is kept" || fx_fail "the DROP rule was deleted"
  fx_assert "the repaired live rules pass S1, S2 and L1" fx_predicate all
  fx_eq "the repair recorded no failure" "done" "${WINN3_LATE_REPAIR:-}"
}

# A rule that keeps coming back stops the loop at 64 deletions; the base-INPUT latch jump still makes 2c pass.
sc_repair_bound_64() {
  fx_source_handler
  fx_state chain-open
  /usr/sbin/iptables -w 10 -I WINVPN-INPUT 1 -p tcp -m tcp --dport 9111 -j ACCEPT
  export FX_REINSERT="-p tcp -m tcp --dport 9111 -j ACCEPT"
  : > "${FX_STATE}/ipt.log"
  winn3_late_repair_live full
  unset FX_REINSERT
  local deletions
  deletions="$(grep -c -- '-D WINVPN-INPUT -p tcp -m tcp --dport 9111 -j ACCEPT' "${FX_STATE}/ipt.log")"
  fx_eq "the reappearing rule is deleted exactly 64 times" 64 "${deletions}"
  fx_assert "the base-INPUT latch jump still makes the 2c gate pass" wins_latch_rules_dominate
  fx_assert "S1 holds although the serving rule keeps coming back (the latch jump is ahead of WINVPN-INPUT)" fx_predicate structure
}

# Recovery body through the repair (D-TESTS addition, v9 fix 3; v10 fix 5).
fx_recovery_chain() { /usr/sbin/iptables -S WINVPN-SSH-RECOVERY 2>/dev/null | grep '^-A ' || true; }

sc_repair_recovery_body() {
  fx_source_handler
  local pinned='-A WINVPN-SSH-RECOVERY -s 8.8.4.4/32 -p tcp -m tcp --dport 22 -j ACCEPT' got
  # (a) valid armed.env, an extra TCP 443 ACCEPT inside the recovery chain: rebuilt to the pinned rule
  fx_state chain-open-recovery-443
  fx_arm_ssh_guard 8.8.4.4
  /usr/sbin/iptables -w 10 -A WINVPN-SSH-RECOVERY -p tcp -m tcp --dport 443 -j ACCEPT
  winn3_late_repair_live full
  got="$(fx_recovery_chain)"
  fx_eq "valid armed.env: the chain is rebuilt to the pinned /32 rule only" "${pinned}" "${got}"
  fx_assert "valid armed.env: S1, S2 and L1 pass" fx_predicate all
  # (b) valid armed.env, chain missing after a restore: created, then the pinned rule added
  /usr/sbin/iptables -w 10 -D INPUT -j WINVPN-SSH-RECOVERY 2>/dev/null
  /usr/sbin/iptables -w 10 -D WINVPN-INPUT -j WINVPN-SSH-RECOVERY 2>/dev/null
  /usr/sbin/iptables -w 10 -F WINVPN-SSH-RECOVERY; /usr/sbin/iptables -w 10 -X WINVPN-SSH-RECOVERY
  fx_refute "the chain is gone before the repair" /usr/sbin/iptables -w 10 -n -L WINVPN-SSH-RECOVERY
  winn3_late_repair_live resume
  fx_eq "chain missing: created and given the pinned rule" "${pinned}" "$(fx_recovery_chain)"
  # (c) no armed.env: the chain is flushed to empty
  fx_reset; fx_source_handler
  fx_state chain-open-recovery-443
  winn3_late_repair_live full
  fx_eq "no armed.env: the chain is flushed to empty" "" "$(fx_recovery_chain)"
  fx_assert "no armed.env: S2 passes" fx_predicate structure
  # (d) and (e): an armed.env that fails load_armed_state's checks
  local label edit
  for label in "bad SOURCE_IPV4" "malformed boot id"; do
    fx_reset; fx_source_handler
    fx_state chain-open
    fx_arm_ssh_guard 8.8.4.4
    /usr/sbin/iptables -w 10 -A WINVPN-SSH-RECOVERY -p tcp -m tcp --dport 443 -j ACCEPT
    case "${label}" in
      "bad SOURCE_IPV4")   sed -i 's/^SOURCE_IPV4=.*/SOURCE_IPV4=10.0.0.9/' /var/lib/winsvpn/ssh-recovery/armed.env ;;
      "malformed boot id") sed -i 's/^ARM_BOOT_ID=.*/ARM_BOOT_ID=zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz/' /var/lib/winsvpn/ssh-recovery/armed.env ;;
    esac
    WINN3_LATE_REPAIR=unknown WINN3_LATE_ERRORS=""
    winn3_late_repair_live full
    got="$(fx_recovery_chain)"
    printf '%s\n' "${got}" | grep -q -- '--dport 443 -j ACCEPT' && fx_ok "${label}: the chain is left as it is" || fx_fail "${label}: the chain was changed: ${got}"
    fx_eq "${label}: the record says repair failed" failed "${WINN3_LATE_REPAIR}"
    [[ "${WINN3_LATE_ERRORS}" == *"armed.env invalid"* ]] && fx_ok "${label}: the error names the invalid armed.env" || fx_fail "${label}: errors: ${WINN3_LATE_ERRORS}"
    fx_refute "${label}: S2 fails" fx_predicate structure
    winn3_late_diagnose
    fx_eq "${label}: the diagnosis says s2 unrepaired" unrepaired "${WINN3_LATE_S2}"
    fx_refute "${label}: the ssh guard's check dies before any change" fx_sshguard check
  done
}

# Step 2a (iii): the latch jump is placed without reading a position, and the recovery jump ends up ahead of it,
# whatever a competing writer does between any two commands.
fx_r_before_l() { # the recovery jump is not behind the first latch jump
  local rules lat rec
  rules="$(fx_input_rules)"
  lat="$(printf '%s\n' "${rules}" | grep -n -- '-j WINVPN-LOCAL-SERVING' | head -1 | cut -d: -f1)"
  rec="$(printf '%s\n' "${rules}" | grep -n -- '-j WINVPN-SSH-RECOVERY' | tail -1 | cut -d: -f1)"
  [[ -z "${rec}" || -z "${lat}" || "${rec}" -lt "${lat}" ]]
}

sc_repair_position_independent() {
  fx_source_handler
  fx_state base-443-ahead
  /usr/sbin/iptables -w 10 -I INPUT 1 -j WINVPN-SSH-RECOVERY
  # X, R, -j WINVPN-INPUT  (X is the TCP 443 ACCEPT at position 2 after R was put first; make X first)
  /usr/sbin/iptables -w 10 -D INPUT -j WINVPN-SSH-RECOVERY; /usr/sbin/iptables -w 10 -I INPUT 2 -j WINVPN-SSH-RECOVERY
  fx_note "fixture INPUT: $(fx_input_rules | tr '\n' ';')"
  winn3_late_repair_live full
  fx_assert "[X, R, WI]: the 2c predicate passes in the base form" wins_latch_rules_dominate
  fx_assert "[X, R, WI]: the recovery jump ends ahead of the latch jump" fx_r_before_l
  # a competing writer deletes and re-inserts the recovery jump right after command N
  local baseline n total
  fx_reset; fx_source_handler; fx_state base-443-ahead; /usr/sbin/iptables -w 10 -I INPUT 1 -j WINVPN-SSH-RECOVERY
  : > "${FX_STATE}/ipt.mut"
  winn3_late_repair_live full
  total="$(cat "${FX_STATE}/ipt.mut")"
  fx_note "mutating iptables calls in one full repair: ${total}"
  local bad=0
  for (( n=1; n<=total; n++ )); do
    fx_reset; fx_source_handler
    fx_state base-443-ahead
    /usr/sbin/iptables -w 10 -I INPUT 1 -j WINVPN-SSH-RECOVERY
    : > "${FX_STATE}/ipt.mut"
    export FX_HOOK_AFTER_NTH="${n}" FX_HOOK_CMD='/usr/sbin/iptables -w 10 -D INPUT -j WINVPN-SSH-RECOVERY; /usr/sbin/iptables -w 10 -I INPUT 1 -j WINVPN-SSH-RECOVERY'
    winn3_late_repair_live full
    unset FX_HOOK_AFTER_NTH FX_HOOK_CMD
    wins_latch_rules_dominate && fx_r_before_l || { bad=1; fx_note "competing insert after command ${n}: INPUT=$(fx_input_rules | tr '\n' ';')"; }
  done
  (( bad == 0 )) && fx_ok "a competing recovery-jump delete-and-insert after each of the ${total} commands: 2c passes and the order holds" \
    || fx_fail "a competing recovery-jump insert broke the base form"
}

# A failed repair command is recorded as repair=failed with the command and its status (v10 fix 1).
sc_repair_failed_command_recorded() {
  fx_source_handler
  fx_state chain-open
  export FX_FAIL_NTH=2
  winn3_late_repair_live full
  unset FX_FAIL_NTH
  fx_eq "a failed repair command sets repair=failed" failed "${WINN3_LATE_REPAIR}"
  [[ "${WINN3_LATE_ERRORS}" == *iptables*exit=1* ]] && fx_ok "the error list names the command and its exit status: ${WINN3_LATE_ERRORS}" \
    || fx_fail "the failure was not named: [${WINN3_LATE_ERRORS}]"
  fx_note "the repair continued after the failed command: later commands ran ($(wc -l < "${FX_STATE}/ipt.log") iptables calls)"
}
