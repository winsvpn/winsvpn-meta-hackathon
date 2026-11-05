#!/usr/bin/env bash
# shellcheck disable=SC2034  # globals are read by the other files of the bundle
# Scenarios GUARD-*: the real wins-node-local-serving program through its whole lifecycle,
# with real traffic probes from a client namespace.

sc_guard_lifecycle() {
  fx_state chain-open
  fx_client_up
  fx_expect_open "control: the listeners answer before the latch"
  fx_guard disable --reason "installer-rerun:${FX_SHA}" >"${FX_STATE}/out" 2>&1
  fx_eq "disable exits 0" 0 "$?"
  fx_assert "latch file is 0600 root with a valid installer-rerun reason" fx_latch_file_ok
  fx_assert "live rules pass S1, S2 and L1" fx_predicate all
  fx_assert "rules.v4 published by disable passes S1, S2 and L1" fx_check_saved /etc/iptables/rules.v4
  fx_expect_dark "UDP and TCP 9111, 80 and 443 are dark after disable (real probe)"
  fx_eq "status says disabled" disabled "$(fx_guard status 2>&1 | tail -n1)"
  # rotate to the digest of the current installer bytes: same digest is "already bound"
  WINS_NODE_LOCAL_SERVING_INSTALLER_PATH="${FX_T}/installer.sh" fx_guard rotate-serving --installer-sha256 "${FX_SHA}" >"${FX_STATE}/out" 2>&1
  fx_eq "rotate-serving with the bound digest exits 0" 0 "$?"
  # a different installer: rotate to its digest
  printf '#!/usr/bin/env bash\n# changed installer bytes\n' > "${FX_T}/installer2.sh"
  local sha2
  sha2="$(sha256sum "${FX_T}/installer2.sh" | cut -d' ' -f1)"
  WINS_NODE_LOCAL_SERVING_INSTALLER_PATH="${FX_T}/installer2.sh" fx_guard rotate-serving --installer-sha256 "${sha2}" >"${FX_STATE}/out" 2>&1
  fx_eq "rotate-serving to the changed installer exits 0" 0 "$?"
  grep -q "REASON=installer-rerun:${sha2}" /etc/winsvpn/local-serving.disabled && fx_ok "latch reason rotated to the new digest" || fx_fail "latch reason not rotated"
  fx_expect_dark "still dark after rotation"
  WINS_NODE_LOCAL_SERVING_INSTALLER_PATH="${FX_T}/installer2.sh" fx_guard release-deployment --installer-sha256 "${FX_SHA}" >"${FX_STATE}/out" 2>&1
  fx_refute "release-deployment refuses a digest that is not the latch's" test "$?" = 0
  fx_expect_dark "refused release left the node dark"
  WINS_NODE_LOCAL_SERVING_INSTALLER_PATH="${FX_T}/installer2.sh" fx_guard release-deployment --installer-sha256 "${sha2}" >"${FX_STATE}/out" 2>&1
  fx_eq "release-deployment with the exact digest exits 0" 0 "$?"
  fx_refute "latch file removed by the release" test -e /etc/winsvpn/local-serving.disabled
  fx_assert "the released ruleset keeps S1 and S2" fx_predicate structure
  fx_expect_open "the node serves again after the release"
  fx_assert "the file published by release passes S1 and S2" fx_check_saved /etc/iptables/rules.v4 structure
  fx_reboot
  fx_eq "boot enforce on a released node exits 0" 0 "${FX_BOOT_RC}"
  fx_expect_open "reboot after release keeps serving (no latch file)"
}

sc_guard_boot_enforce_latched() {
  fx_state chain-open
  fx_client_up
  fx_guard disable --reason "installer-rerun:${FX_SHA}" >/dev/null 2>&1
  fx_reboot
  fx_eq "boot enforce on a latched node exits 0" 0 "${FX_BOOT_RC}"
  fx_expect_dark "dark after a reboot with the listeners up"
  fx_assert "live rules pass S1, S2 and L1 after the reboot" fx_predicate all
  # latch file present, rules.v4 lost: enforce must rebuild the chain
  fx_guard disable --reason "installer-rerun:${FX_SHA}" >/dev/null 2>&1
  rm -f /etc/iptables/rules.v4
  fx_reboot
  fx_eq "boot enforce with a latch file and no rules.v4 exits 0" 0 "${FX_BOOT_RC}"
  fx_eq "enforce rebuilt the exact latch body from the latch file" "$(printf '%s\n' '-A WINVPN-LOCAL-SERVING -i lo -j RETURN' '-A WINVPN-LOCAL-SERVING -m conntrack --ctstate RELATED,ESTABLISHED --ctdir REPLY -j RETURN' '-A WINVPN-LOCAL-SERVING -j DROP')" "$(/usr/sbin/iptables -S WINVPN-LOCAL-SERVING | grep '^-A ')"
  fx_note "boot enforce rebuilds the chain body only; the INPUT jump comes from rules.v4 or the edge script, so with rules.v4 lost the node is not dark at the firewall (service ordering carries it)"
}

# A second local-serving command blocked on fd 9 completes only after rotate-serving finishes (5.3 v10 fix 4,
# contender part). The strace trace assertion is NOT done here: strace is not installed on the guest.
sc_guard_rotate_keeps_fd9() {
  fx_state chain-open
  fx_guard disable --reason "installer-rerun:${FX_SHA}" >/dev/null 2>&1
  printf '#!/usr/bin/env bash\n# changed installer bytes\n' > "${FX_T}/installer2.sh"
  local sha2
  sha2="$(sha256sum "${FX_T}/installer2.sh" | cut -d' ' -f1)"
  # make the rotation take 2 s after it holds the lock: sync_path calls `sync`
  cat > "${FX_T}/stubs/sync" <<'STUB'
#!/bin/bash
[[ -e "${FX_STATE}/slow-sync" ]] && sleep 1
exec /usr/bin/sync "$@"
STUB
  chmod +x "${FX_T}/stubs/sync"
  : > "${FX_STATE}/slow-sync"
  (
    # FX_FLOCK_DELAY widens the window in which a re-acquisition would release the lock: every fd-9 flock of this
    # process sleeps 1.5 s first, so a second lock_guard at the former call site frees fd 9 for 1.5 s.
    FX_FLOCK_DELAY=1.5 WINS_NODE_LOCAL_SERVING_INSTALLER_PATH="${FX_T}/installer2.sh" fx_guard rotate-serving --installer-sha256 "${sha2}" >"${FX_STATE}/rot.out" 2>&1
    date +%s.%N > "${FX_STATE}/rot.end"
  ) &
  local rot=$!
  sleep 1.9
  (
    WINS_NODE_LOCAL_SERVING_LOCK_WAIT=20 fx_guard status >"${FX_STATE}/contender.out" 2>&1
    echo "$?" > "${FX_STATE}/contender.rc"
    date +%s.%N > "${FX_STATE}/contender.end"
  ) &
  local con=$!
  wait "${rot}" "${con}"
  rm -f "${FX_STATE}/slow-sync"
  grep -q 'latch rotated' "${FX_STATE}/rot.out" && fx_ok "rotate-serving rotated the latch" || fx_fail "rotate-serving failed: $(cat "${FX_STATE}/rot.out")"
  fx_eq "the contender's status succeeded (no fd 7 or fd 9 timeout)" 0 "$(cat "${FX_STATE}/contender.rc")"
  python3 - "${FX_STATE}/rot.end" "${FX_STATE}/contender.end" <<'PY' && fx_ok "the contender acquired fd 9 only after rotate-serving exited" || fx_fail "the contender overtook rotate-serving"
import sys
rot, con = (float(open(p).read()) for p in sys.argv[1:3])
sys.exit(0 if con >= rot - 0.01 else 1)
PY
}
