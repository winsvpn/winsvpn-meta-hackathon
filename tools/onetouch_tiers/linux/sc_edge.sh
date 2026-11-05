#!/usr/bin/env bash
# shellcheck disable=SC2034  # globals are read by the other files of the bundle
# Scenarios EDGE-*: the real edge firewall artifact (design 5.1 step 1) on real iptables.

sc_edge_artifact_ruleset() {
  fx_edge_run
  fx_eq "the edge script exits 0 in the bootstrap invocation" 0 "${FX_EDGE_RC}"
  fx_note "edge script tail: $(grep -v '^$' "${FX_STATE}/edge.out" | tail -2 | tr '\n' '|' | cut -c1-200)"
  fx_note "host-global commands the fixture refused to run: $(tr '\n' ';' < "${FX_STATE}/globals-refused" 2>/dev/null | cut -c1-200)"
  fx_eq "INPUT policy is DROP" "-P INPUT DROP" "$(/usr/sbin/iptables -S INPUT | head -1)"
  fx_eq "INPUT has one jump, to WINVPN-INPUT" "-A INPUT -j WINVPN-INPUT" "$(/usr/sbin/iptables -S INPUT | grep '^-A' | head -1)"
  fx_eq "the first WINVPN-INPUT rule is the recovery jump" "-A WINVPN-INPUT -j WINVPN-SSH-RECOVERY" "$(/usr/sbin/iptables -S WINVPN-INPUT | grep '^-A' | sed -n 1p)"
  fx_eq "the second WINVPN-INPUT rule is the latch jump" "-A WINVPN-INPUT -j WINVPN-LOCAL-SERVING" "$(/usr/sbin/iptables -S WINVPN-INPUT | grep '^-A' | sed -n 2p)"
  fx_assert "the artifact's ruleset passes S1 and S2 (structure) before any latch" fx_predicate structure
  fx_refute "L1 fails before a latch is engaged (the latch chain is empty)" fx_predicate all
  fx_guard disable --reason "installer-rerun:${FX_SHA}" >"${FX_STATE}/out" 2>&1
  fx_eq "disable on the artifact's ruleset exits 0" 0 "$?"
  fx_assert "the artifact's ruleset with the latch engaged passes S1, S2 and L1 (design: winn3_latch_dominates passes on the edge script's own output)" fx_predicate all
  fx_assert "rules.v4 published by the guard on the artifact's ruleset passes S1, S2 and L1" fx_check_saved /etc/iptables/rules.v4
  # idempotent: a second run leaves the same ruleset
  local first second
  first="$(fx_live_hash)"
  fx_edge_run
  second="$(fx_live_hash)"
  fx_eq "a second edge run exits 0" 0 "${FX_EDGE_RC}"
  fx_eq "a second edge run converges on the same ruleset (latch kept)" "${first}" "${second}"
}

# The exit path on the real artifact's ruleset: live dominant, and with the snapshot restored.
sc_edge_handler_live_dominant() {
  fx_handler_setup chain-open permissive
  fx_edge_run
  [[ ${FX_EDGE_RC} == 0 ]] || { fx_fail "edge script failed: $(tail -3 "${FX_STATE}/edge.out" | tr '\n' ' ')"; return 0; }
  fx_services_up
  fx_handler_exit
  fx_handler_post pass
  fx_eq "record: live_latch" dominant "$(fx_record_field live_latch)"
  fx_assert "rules.v4 on disk passes S1, S2 and L1" fx_check_saved /etc/iptables/rules.v4
  fx_handler_after_reboot net
}

sc_edge_handler_snapshot() {
  # The pre-deployment snapshot is the real edge ruleset (S passes, the latch chain is empty); the live rules at failure time
  # are the permissive ones; the recovery guard check fails, so the rollback restores the snapshot. The reassert step finds
  # S passing and L failing with a safe latch file, so it calls enforce and ends dominant.
  fx_handler_setup chain-open permissive
  fx_edge_run
  [[ ${FX_EDGE_RC} == 0 ]] || { fx_fail "edge script failed"; return 0; }
  /usr/sbin/iptables-save > "${FX_T}/pre.snapshot"
  fx_state open-serving
  rm -f /usr/local/sbin/wins-node-ssh-recovery-guard
  fx_services_up
  fx_handler_exit
  fx_handler_post pass
  grep -q 'Restored the pre-deployment iptables snapshot' "${FX_STATE}/handler.out" \
    && fx_ok "the rollback restored the edge-script snapshot" || fx_fail "no snapshot restore"
  fx_guard_called "enforce wait=20 held=1" && fx_ok "the reassert step called enforce (S passed, L1 did not)" || fx_fail "enforce not called: $(fx_guard_calls | tr '\n' ';')"
  fx_eq "record: live_latch" dominant "$(fx_record_field live_latch)"
  fx_assert "rules.v4 on disk passes S1, S2 and L1" fx_check_saved /etc/iptables/rules.v4
  fx_handler_after_reboot net
}

# The edge rebuild transaction itself (design v17 5.3 v9 fix 4 and v10 fix 1; 5.6 "the base-jump removal loops on
# `ipt_read -C` inside the edge transaction, or stages more `-D` lines than live copies", "the edge rebuild's rules.v4
# write saves while the record exists without the predicate passing", "the edge rebuild stages the base-jump deletion
# while the record exists"). A pass-through iptables-restore stub keeps a copy of each `--test` transaction, so the
# staged `-D` lines are counted exactly, and the published rules.v4 is told apart by its inode and mtime.
fx_restore_capture_stub() {
  cat > "${FX_T}/stubs/iptables-restore" <<'STUB'
#!/bin/bash
if [[ -n "${FX_RESTORE_CAPTURE:-}" && " $* " == *" --test "* ]]; then
  tmp="$(mktemp)"
  cat > "${tmp}"
  n="$(ls "${FX_RESTORE_CAPTURE}" 2>/dev/null | wc -l)"
  cp "${tmp}" "${FX_RESTORE_CAPTURE}/tx.${n}"
  /usr/sbin/iptables-restore "$@" < "${tmp}"
  rc=$?
  rm -f "${tmp}"
  exit ${rc}
fi
exec /usr/sbin/iptables-restore "$@"
STUB
  chmod +x "${FX_T}/stubs/iptables-restore"
}

fx_base_latch_copies() { /usr/sbin/iptables -S INPUT | grep -cx -- '-A INPUT -j WINVPN-LOCAL-SERVING'; }
fx_staged_base_deletes() { grep -cx -- '-D INPUT -j WINVPN-LOCAL-SERVING' "$1" 2>/dev/null || true; }

sc_edge_rebuild_transaction() {
  fx_restore_capture_stub
  fx_state_edge || { rm -f "${FX_T}/stubs/iptables-restore"; return 0; }
  local n i copies cap
  # No record: every live copy of the base-INPUT latch jump is removed, one staged -D per live copy.
  for n in 1 2 3; do
    while /usr/sbin/iptables -w 10 -D INPUT -j WINVPN-LOCAL-SERVING 2>/dev/null; do :; done
    for (( i=0; i<n; i++ )); do /usr/sbin/iptables -w 10 -I INPUT 1 -j WINVPN-LOCAL-SERVING; done
    cap="${FX_STATE}/restore-${n}"
    mkdir -p "${cap}"
    export FX_RESTORE_CAPTURE="${cap}"
    fx_edge_run
    unset FX_RESTORE_CAPTURE
    fx_eq "no record, ${n} live base latch jump(s): the edge rebuild exits 0" 0 "${FX_EDGE_RC}"
    fx_eq "no record, ${n} live copies: exactly ${n} -D line(s) staged in the transaction" "${n}" "$(fx_staged_base_deletes "${cap}/tx.0")"
    fx_eq "no record: no copy of the base latch jump remains" 0 "$(fx_base_latch_copies)"
  done
  # Record present and the latch dominant (handler step 2a's base form): the jump is kept, nothing is staged against it.
  fx_guard disable --reason "installer-rerun:${FX_SHA}" >/dev/null 2>&1
  /usr/sbin/iptables -w 10 -I INPUT 1 -j WINVPN-LOCAL-SERVING
  fx_record_on
  cap="${FX_STATE}/restore-record"
  mkdir -p "${cap}"
  export FX_RESTORE_CAPTURE="${cap}"
  fx_edge_run
  unset FX_RESTORE_CAPTURE
  fx_eq "record present, latch dominant: the edge rebuild exits 0" 0 "${FX_EDGE_RC}"
  fx_eq "record present: no base-jump deletion is staged" 0 "$(fx_staged_base_deletes "${cap}/tx.0")"
  fx_eq "record present: the base-INPUT latch jump is kept" 1 "$(fx_base_latch_copies)"
  fx_assert "record present: the live rules pass S1, S2 and L1 after the rebuild" fx_predicate all
  fx_assert "record present: the rules.v4 the rebuild published passes S1, S2 and L1" fx_check_saved /etc/iptables/rules.v4
  # Record present and the latch NOT engaged (L1 fails): the gate refuses, and the previous rules.v4 stays in place.
  fx_reset
  fx_restore_capture_stub
  fx_state_edge || { rm -f "${FX_T}/stubs/iptables-restore"; return 0; }
  fx_record_on
  local before after
  before="$(stat -c '%i %y' /etc/iptables/rules.v4 2>/dev/null)"
  fx_assert "a previous rules.v4 exists, so its survival is observable" test -n "${before}"
  fx_edge_run
  after="$(stat -c '%i %y' /etc/iptables/rules.v4 2>/dev/null)"
  fx_refute "record present, L1 failing: the edge rebuild does not exit 0" test "${FX_EDGE_RC}" = 0
  grep -q 'Late-failure persistence gate refused' "${FX_STATE}/edge.out" \
    && fx_ok "the edge rebuild names the persistence gate refusal" || fx_fail "no gate refusal in the edge output: $(tail -3 "${FX_STATE}/edge.out" | tr '\n' ' ')"
  fx_eq "the previous rules.v4 is the same file (inode and mtime)" "${before}" "${after}"
  rm -f "${FX_T}/stubs/iptables-restore"
}
