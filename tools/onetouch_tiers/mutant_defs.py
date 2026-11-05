"""The 5.6 mutant registry (design v17 section 5.6), as data.

Each entry is one of:
  * a runnable mutant: one or more exact-count text edits of the data-plane installer (DP) and the way to kill
    it (Tier A scenario ids on the guest, and/or pytest files on the operator Mac);
  * a pending mutant: its subject lives in a slice that is not in the tree this lane was given (the hub app, the
    signer, the canary, go-live), or it can only be killed on a real systemd (Tier B). It carries the slice or tier
    that owns it and the kill test the design names, and the runner reports it as `pending`, never as killed.

`design` quotes the 5.6 bullet. The runner (mutants_s7.py) refuses an edit whose pattern does not occur exactly the
stated number of times, so a changed installer shows up as BAD-PATTERN, not as a silent survivor.
"""

S4 = "server/test_winn3_onetouch_s4.py"
S5 = "server/test_winn3_onetouch_s5.py"
S7 = "server/test_winn3_onetouch_s7.py"

MUTANTS = []


BLOCK_CHECK = ["python3", "-B", "tools/winn3_gateway_block.py", "check", "--root", "."]


def m(mid, group, design, edits, tier_a=(), pytest=(), profile="quick", note="", cmd=()):
    """edits: list of (old, new, count) against the data-plane installer. cmd: argv lists run in the mirror root."""
    MUTANTS.append({"id": mid, "group": group, "design": design, "edits": [list(e) for e in edits],
                    "tier_a": list(tier_a), "pytest": list(pytest), "cmd": [list(c) for c in cmd], "profile": profile, "note": note,
                    "status": "runnable"})


def pending(mid, group, design, owner, kill_test, note=""):
    MUTANTS.append({"id": mid, "group": group, "design": design, "edits": [], "tier_a": [], "pytest": [], "cmd": [],
                    "profile": "quick", "note": note, "status": "pending", "owner": owner, "kill_test": kill_test})


# =====================================================================================================
# Node and installer: the exit path, the predicate and the guards (Tier A kills them on real iptables)
# =====================================================================================================
G = "node-exit"

m("N-reason-not-installer-rerun", G, "The late-failure handler uses a reason other than `installer-rerun:<sha256>`.",
  [(r'"installer-rerun:${WINN3_LATE_SHA}"', r'"late-failure:${WINN3_LATE_SHA}"', 2)],
  tier_a=["HANDLER-live-dominant"])
m("N-relies-on-disable-to-stop-gateway", G, "The late-failure handler relies on `disable_serving` to stop the gateway.",
  [("  timeout -k 5 30 systemctl disable --now winn3-gateway.service winn3-gateway-firewall.service || true\n", "", 1)],
  tier_a=["HANDLER-live-dominant"])
m("N-handler-after-rollback", G, "The late-failure handler runs after the firewall rollback.",
  [('  winn3_late_failure_on_exit "${rc}"\n  deploy_firewall_rollback_on_exit "${rc}"\n',
    '  deploy_firewall_rollback_on_exit "${rc}"\n  winn3_late_failure_on_exit "${rc}"\n', 1)],
  tier_a=["HANDLER-snapshot-open-serving", "HANDLER-live-dominant"], pytest=[S4])
m("N-armed-only-in-phase-c", G, "The late-failure handler is armed only when phase C started or restarted the gateway.",
  [("  WINN3_LATE_ARMED=1\n  winn3gw_render_helper\n", "  winn3gw_render_helper\n", 1),
   ("  WINN3_LATE_STAGE=C\n  check_gateway_egress_mtu || return 1\n  winn3gw_activate\n",
    "  WINN3_LATE_STAGE=C\n  WINN3_LATE_ARMED=1\n  check_gateway_egress_mtu || return 1\n  winn3gw_activate\n", 1)],
  pytest=[S4])
MUTANTS.append({"id": "N-waits-on-the-installer-lock-reopen", "group": G, "status": "equivalent", "cmd": [],
                "design": "The late-failure handler waits on a lock the installer holds (here: it re-takes fd 7 although WINS_FW_LOCK_OWNED=1).",
                "edits": [], "tier_a": [], "pytest": [], "profile": "quick",
                "note": "Equivalent as a Tier A mutant: `exec 7>>lockfile` in the process that owns fd 7 closes its own open file description "
                        "first, which releases the lock, so the re-take cannot wait on itself. The observable form is a CHILD that "
                                "re-takes the lock while its parent holds it; that is N-guard-call-without-held below."})
m("N-guard-call-without-held", G, "The late-failure handler waits on a lock the installer holds (the guard child is not told HELD=1).",
  [("WINS_NODE_LOCAL_SERVING_LOCK_WAIT=20 WINS_FIREWALL_LOCK_HELD=1", "WINS_NODE_LOCAL_SERVING_LOCK_WAIT=20", 3)],
  tier_a=["HANDLER-lock-held-nesting"], note="a guard child opens its own description of the lock file and waits on the parent that holds it")
m("N-reassert-removed", G, "The reassert step is removed.",
  [('  winn3_late_failure_reassert\n  [[ "${cloudflare}" != 1 ]]', '  [[ "${cloudflare}" != 1 ]]', 1)],
  tier_a=["HANDLER-snapshot-open-serving"], pytest=[S4])
m("N-reassert-does-not-stop-services", G, "The reassert step does not stop serving services when the live INPUT path lacks the latch chain.",
  [("    winn3_late_repair_live resume\n    winn3_late_diagnose\n    winn3_late_fallback reassert\n",
    "    winn3_late_repair_live resume\n    winn3_late_diagnose\n", 1)],
  tier_a=["HANDLER-snapshot-open-serving"])
m("N-reassert-enforce-without-S", G, "The reassert step calls `enforce` (or anything reaching `persist_firewall`) before, or without, passing S.",
  [('  if [[ "${WINN3_LATE_FW_LOCK}" == held ]] && wins_latch_rules_inspect structure; then',
    '  if [[ "${WINN3_LATE_FW_LOCK}" == held ]]; then', 1)],
  tier_a=["HANDLER-snapshot-jumps-with-accept", "HANDLER-snapshot-open-serving"])
m("N-dominance-membership-only", G, "The dominance check is reduced to membership (the two `iptables -C` checks only).",
  [("        needed.add(admitted(rule))\n", "        pass\n", 1)],
  tier_a=["PRED-matrix"], pytest=[S4])
m("N-step-2a-removed", G, "Handler step 2a is removed.",
  [('  if [[ "${1:-full}" == full ]]; then\n    if rules="$(iptables -w 10 -S WINVPN-INPUT)"; then',
    '  if false; then\n    if rules="$(iptables -w 10 -S WINVPN-INPUT)"; then', 1)],
  tier_a=["REPAIR-deletes-accepts"])
m("N-step-2a-deletes-non-accept", G, "Handler step 2a deletes a rule whose target is not ACCEPT.",
  [("        [[ \" ${rule} \" == *' -j ACCEPT '* ]] || continue\n", "", 1)],
  tier_a=["REPAIR-deletes-accepts"])
m("N-2b-disable-without-2c-gate", G, "Handler step 2b calls `disable` without a passing 2c gate.",
  [("    if wins_latch_rules_dominate \\\n        && WINS_NODE_LOCAL_SERVING_LOCK_WAIT=20 WINS_FIREWALL_LOCK_HELD=1 \\\n",
    "    if WINS_NODE_LOCAL_SERVING_LOCK_WAIT=20 WINS_FIREWALL_LOCK_HELD=1 \\\n", 1)],
  tier_a=["HANDLER-recovery-body-invalid-armed"])
m("N-latch-jump-not-inserted", G, "The base-INPUT latch jump is not inserted.",
  [("  winn3_late_command iptables -w 10 -I INPUT 1 -j WINVPN-LOCAL-SERVING\n", "", 1)],
  tier_a=["REPAIR-bound-64", "HANDLER-base-accept-ahead"])
m("N-latch-ahead-of-recovery-jump", G, "The final base INPUT order leaves the latch jump ahead of a `-j WINVPN-SSH-RECOVERY` jump.",
  [("    if (( count > 0 )); then\n      for (( i=0; i<count; i++ )); do", "    if false; then\n      for (( i=0; i<count; i++ )); do", 1)],
  tier_a=["REPAIR-position-independent"])
m("N-rollback-check-without-lock-convention", G, "The rollback's guard `check` runs without the lock convention.",
  [('          WINS_FIREWALL_LOCK_HELD="${WINS_FW_LOCK_OWNED:-0}" \\\n', "", 1)],
  tier_a=["HANDLER-lock-held-nesting"])
m("N-exit-path-releases-fd7-early", G, "The exit path releases fd 7 between the rollback and the end of the reassert step.",
  [('  deploy_firewall_rollback_on_exit "${rc}"\n  set +e\n  winn3_late_failure_reassert\n',
    '  deploy_firewall_rollback_on_exit "${rc}"\n  set +e\n  [[ "${WINN3_LATE_FW_LOCK}" != held ]] || winn3_installer_fw_unlock\n  winn3_late_failure_reassert\n', 1)],
  pytest=[S7], note="killed by the static ordering test in test_winn3_onetouch_s7.py; a concurrent writer is needed to see it live")
m("N-S2-recovery-body-unchecked", G, "S2 is removed, or does not check the body of `WINVPN-SSH-RECOVERY`.",
  [('    recovery = read("WINVPN-SSH-RECOVERY", absent=True)\n    if recovery:', '    recovery = []\n    if recovery:', 1)],
  tier_a=["PRED-matrix"], pytest=[S4])
m("N-S2-cf-f2b-body-unchecked", G, "S2 does not check the body of `WINVPN-STEALTH-CF` (or the Fail2Ban chain).",
  [("        if kind not in needed:\n            continue\n", "        continue\n", 1)],
  tier_a=["PRED-matrix"], pytest=[S4])
m("N-guard-call-without-lock-wait", G, "The exit path calls a guard without the bounded `*_LOCK_WAIT`.",
  [("WINS_NODE_LOCAL_SERVING_LOCK_WAIT=20 WINS_FIREWALL_LOCK_HELD=1", "WINS_FIREWALL_LOCK_HELD=1", 3)],
  tier_a=["HANDLER-live-dominant", "HANDLER-guard-lock-contention"], profile="full")
m("N-latch-dominates-calls-status", G, "`winn3_latch_dominates` calls the guard's `status`.",
  [("  wins_latch_rules_dominate && winn3_latch_file_safe\n}",
    "  wins_latch_rules_dominate && winn3_latch_file_safe && /usr/local/sbin/wins-node-local-serving status >/dev/null\n}", 1)],
  tier_a=["HANDLER-dominance-takes-no-guard-lock"])
m("N-recheck-after-enforce-no-fallthrough", G, "A failed re-check after `enforce` does not fall through to branch 3.",
  [("      winn3_latch_dominates && repaired=1\n    fi\n  fi\n  if [[ \"${repaired}\" == 0 ]]; then",
    "      repaired=1\n    fi\n  fi\n  if [[ \"${repaired}\" == 0 ]]; then", 1)],
  tier_a=["HANDLER-enforce-recheck-fails"])
m("N-step-2a-loop-unbounded", G, "The step 2a deletion loop has no bound.",
  [("        for (( i=0; i<64; i++ )); do\n          iptables -w 10 -C WINVPN-INPUT", "        for (( i=0; i<640; i++ )); do\n          iptables -w 10 -C WINVPN-INPUT", 1)],
  tier_a=["REPAIR-bound-64"])
m("N-guard-changes-before-fd7", G, "A guard command other than `status` changes the live rules or the latch file before it holds fd 7.",
  [('if [[ "${1:-}" != status ]] && ! guard_hold_firewall_lock; then', "if false; then", 2)],
  tier_a=["GATE-fd7-timeout"])
m("N-reassert-enforce-when-latch-file-absent", G, "The reassert step calls `enforce` when the latch file is absent.",
  [("      command=disable\n    elif ! winn3_latch_file_safe; then", "      command=enforce\n    elif ! winn3_latch_file_safe; then", 1)],
  tier_a=["HANDLER-combined-fd9"], profile="full")
m("N-recovery-body-wrong-address", G, "Step 2a or branch 3 rebuilds the recovery body from any address other than `armed.env`'s SOURCE_IPV4.",
  [('-A WINVPN-SSH-RECOVERY -s "${source}/32" -p tcp --dport 22 -j ACCEPT', '-A WINVPN-SSH-RECOVERY -s 0.0.0.0/0 -p tcp --dport 22 -j ACCEPT', 1)],
  tier_a=["REPAIR-recovery-body", "HANDLER-recovery-body-live"])
m("N-recovery-body-cleared-on-invalid-armed", G, "...or guesses an address when the file is invalid (here: flushes the chain instead of leaving it).",
  [("    WINN3_LATE_ERRORS+='armed.env invalid: recovery body left unchanged;'\n",
    "    WINN3_LATE_ERRORS+='armed.env invalid: recovery body left unchanged;'\n    iptables -w 10 -F WINVPN-SSH-RECOVERY\n", 1)],
  tier_a=["REPAIR-recovery-body"])
m("N-armed-env-boot-id-unchecked", G, "Step 2a (iv) accepts an `armed.env` that fails a `load_armed_state` check (boot id).",
  [(' or not re.fullmatch(uuid, values["ARM_BOOT_ID"]) or not re.fullmatch(uuid, values["TUNNEL_ID"])', ' or not re.fullmatch(uuid, values["TUNNEL_ID"])', 1)],
  tier_a=["REPAIR-recovery-body"])
m("N-armed-env-source-unchecked", G, "Step 2a (iv) accepts an `armed.env` that fails a `load_armed_state` check (source address).",
  [("    if (values[\"VERSION\"] != \"1\" or not source.is_global or source.is_multicast or source.is_reserved\n            or source.is_loopback or source.is_link_local or source.is_unspecified\n",
    "    if (values[\"VERSION\"] != \"1\"\n", 1)],
  tier_a=["REPAIR-recovery-body"])
m("N-missing-recovery-chain-not-created", G, "Step 2a (iv) fails on a missing chain instead of creating it.",
  [("    iptables -w 10 -n -L WINVPN-SSH-RECOVERY >/dev/null 2>&1 \\\n      || winn3_late_command iptables -w 10 -N WINVPN-SSH-RECOVERY\n", "", 1)],
  tier_a=["REPAIR-recovery-body"])
m("N-gate-removed-in-local-serving-guard", G, "`persist_firewall` in the local-serving guard saves while the record exists without the predicate passing.",
  [("persist_firewall() {\n  local rc\n  wins_fw_lock || { printf 'wins-node-local-serving: shared firewall lock unavailable; rules.v4 not written\\n' >&2; return 1; }\n  if wins_late_failure_hold && ! wins_latch_rules_dominate; then\n",
    "persist_firewall() {\n  local rc\n  wins_fw_lock || { printf 'wins-node-local-serving: shared firewall lock unavailable; rules.v4 not written\\n' >&2; return 1; }\n  if false; then\n", 1)],
  tier_a=["GATE-record-present-refuses", "HANDLER-boot-enforce-gate"])
m("N-gate-removed-in-ssh-guard", G, "`persist_firewall` in the SSH recovery guard saves while the record exists without the predicate passing.",
  [("persist_firewall() {\n  local rc\n  wins_fw_lock || { printf 'wins-node-ssh-recovery-guard: shared firewall lock unavailable; rules.v4 not written\\n' >&2; return 1; }\n  if wins_late_failure_hold && ! wins_latch_rules_dominate; then\n",
    "persist_firewall() {\n  local rc\n  wins_fw_lock || { printf 'wins-node-ssh-recovery-guard: shared firewall lock unavailable; rules.v4 not written\\n' >&2; return 1; }\n  if false; then\n", 1)],
  tier_a=["GATE-ssh-guard"])
m("N-gate-removed-in-edge-rebuild", G, "The edge rebuild's `rules.v4` write saves while the record exists without the predicate passing.",
  [("  if wins_late_failure_hold && ! wins_latch_rules_dominate; then\n", "  if false; then\n", 4)],
  pytest=[S4], note="count 4 = the two guards and the edge rebuild's two writers; the edge copies are killed offline by S4")
m("N-predicate-creates-a-directory", G, "`wins_latch_rules_dominate` creates a file, takes fd 7 or fd 9.",
  [("wins_latch_rules_dominate() {\n  wins_latch_rules_inspect all\n}", "wins_latch_rules_dominate() {\n  mkdir -p /run/lock\n  wins_latch_rules_inspect all\n}", 1)],
  tier_a=["PRED-no-side-effects"])
m("N-symlink-record-counts-as-absent", G, "`wins_latch_rules_dominate` ... treats a symlink at the record path as absent.",
  [("  [[ -e /var/lib/winsvpn/winn3-late-failure.json || -L /var/lib/winsvpn/winn3-late-failure.json ]]\n",
    "  [[ -e /var/lib/winsvpn/winn3-late-failure.json ]]\n", 1)],
  tier_a=["GATE-symlink-record"], pytest=[S4])
m("N-record-written-only-at-end", G, "The handler writes the record only at its end, after the first firewall step.",
  [("  if ! winn3_late_record; then\n    if ! install -m 600 -o root -g root /dev/null /var/lib/winsvpn/winn3-late-failure.json; then\n"
    "      logger -t wins-installer 'winn3 late failure: record=unwritten' || true\n    else\n"
    "      sync -f /var/lib/winsvpn || logger -t wins-installer 'winn3 late failure: record durable for running boot only' || true\n    fi\n  fi\n", "", 1)],
  tier_a=["HANDLER-live-dominant"])
m("N-record-removed-by-the-exit-path", G, "Anything other than a successful postflight removes the record.",
  [("    winn3_late_record || logger -t wins-installer 'winn3 late failure: final record update failed' || true\n",
    "    winn3_late_record || logger -t wins-installer 'winn3 late failure: final record update failed' || true\n    rm -f /var/lib/winsvpn/winn3-late-failure.json\n", 1)],
  tier_a=["HANDLER-live-dominant"])
m("N-failed-repair-not-recorded", G, "A failed repair command is not recorded as `\"repair\":\"failed\"`.",
  [('  if (( rc )); then\n    WINN3_LATE_REPAIR=failed\n', '  if (( rc )); then\n', 1)],
  tier_a=["REPAIR-failed-command-recorded"])
m("N-serving-activator-ignores-the-record", G, "Weekly maintenance, the vault-unlock script or any other caller starts a serving unit while the record exists.",
  [("    printf 'wins_late_failure_hold && exit 3\\nexec \"$@\"\\n'\n", "    printf 'exec \"$@\"\\n'\n", 1)],
  tier_a=["HANDLER-serving-activator"])
m("N-fd9-reacquired-by-rotate", G, "A guard command re-acquires its fd 9 after it holds fd 7.",
  [('rotate_serving() {\n  local installer_sha="" old_reason="" tmp="" current_sha=""\n',
    'rotate_serving() {\n  lock_guard\n  local installer_sha="" old_reason="" tmp="" current_sha=""\n', 1)],
  tier_a=["GUARD-rotate-keeps-fd9", "STRACE-fd9-trace"])
m("N-enforce-skips-stop-on-fd7-timeout", G, "`enforce` or `disable` skips `stop_customer_services` on a fd 7 timeout.",
  [("    disable) stop_customer_services ;;\n    enforce) [[ ! -e \"${LATCH_FILE}\" && ! -L \"${LATCH_FILE}\" ]] || stop_customer_services ;;\n",
    "    disable) ;;\n    enforce) ;;\n", 1)],
  tier_a=["GATE-fd7-timeout"])
m("N-status-without-wait-bound", G, "A guard call made under a caller's fd 7 (`status` included) omits the bounded fd 9 wait.",
  [('  if [[ -n "${WINS_NODE_LOCAL_SERVING_LOCK_WAIT:-}" ]]; then\n    [[ "${WINS_NODE_LOCAL_SERVING_LOCK_WAIT}" =~ ^[0-9]+$ ]] || die "invalid guard lock wait"\n    flock -w "${WINS_NODE_LOCAL_SERVING_LOCK_WAIT}" -x 9 || die "guard lock unavailable"\n  else\n    flock -x 9\n  fi\n',
    "  flock -x 9\n", 1)],
  tier_a=["GATE-status-bounds"])
m("N-fence-skipped", G, "The handler stops services without running the fence first.",
  [("  winn3_late_fence\n  timeout -k 5 30 systemctl disable --now winn3-gateway.service", "  timeout -k 5 30 systemctl disable --now winn3-gateway.service", 1)],
  tier_a=["HANDLER-fence-live-scope"], pytest=[S4])
m("N-fallback-leaves-units-enabled", G, "Design 5.3 (anti-vacuity arm for the reboot model): the safe fallback stops xray and nginx but leaves them enabled, so they start at the next boot.",
  [("  timeout -k 5 20 systemctl disable xray.service nginx.service || true\n", "", 1)],
  tier_a=["HANDLER-injected-save-refusal", "HANDLER-boot-enforce-gate"], note="S4, S5 and S7 pytest do not kill it; only the modelled boot of fx_reboot svc can")
m("N-fallback-leaves-awg-restart-policy", G, "Design 5.3 (anti-vacuity arm for the reboot model): the safe fallback stops the AWG containers but leaves their restart policy, so docker starts them at the next boot.",
  [('    timeout -k 5 20 docker update --restart=no "${name}" >/dev/null 2>&1 || true\n', '    :\n', 1)],
  tier_a=["HANDLER-injected-save-refusal", "HANDLER-boot-enforce-gate"],
  note="S4, S5 and S7 pytest do not kill it; the modelled boot brings back every container whose policy is not `no`")
m("N-guard-docker-stop-unbounded", G, "S7-DOCKER (DP 9898): the serving guard's docker stop has no bound, so a boot enforce on its failure path can wait forever on docker.socket.",
  [("    timeout -k 5 20 docker stop amnezia-awg2 awg amnezia-awg >/dev/null 2>&1 || true\n", "    docker stop amnezia-awg2 awg amnezia-awg >/dev/null 2>&1 || true\n", 1)],
  pytest=[S7], note="killed by StaticInstallerProperties; Tier B on amd64t shows the boot behaviour")
m("N-settle-skips-the-normal-path", G, "The settle check skips the normal path.",
  [("  if [[ \"${WINN3_LATE_ACTED:-0}\" == 1 ]]; then\n    winn3_late_settle\n", "  if [[ \"${WINN3_LATE_ACTED:-0}\" == 1 ]]; then\n", 1)],
  tier_a=["HANDLER-settle-late-restart"], profile="full", pytest=[S4])

# =====================================================================================================
# Node and installer: credentials, adoption, identity (the S4 and S5 offline suites kill them)
# =====================================================================================================
G = "node-identity"
m("N-v3-can-be-turned-off", G, "v3 can be turned off.",
  [("  WINN3_GATEWAY_FORWARD=1\n  WINN3_GATEWAY_RESOLVER=1\n", '  WINN3_GATEWAY_FORWARD="${WINN3_ONETOUCH_FORWARD_REQUESTED:-1}"\n  WINN3_GATEWAY_RESOLVER="${WINN3_ONETOUCH_RESOLVER_REQUESTED:-1}"\n', 1),
   ('  [[ -z "${WINN3_ONETOUCH_FORWARD_REQUESTED}" || "${WINN3_ONETOUCH_FORWARD_REQUESTED}" == 1 ]] \\\n    && [[ -z "${WINN3_ONETOUCH_RESOLVER_REQUESTED}" || "${WINN3_ONETOUCH_RESOLVER_REQUESTED}" == 1 ]] || {\n    err "ONETOUCH requires WINN3_GATEWAY_FORWARD=1 and WINN3_GATEWAY_RESOLVER=1"; return 1;\n  }\n', "", 1)],
  pytest=[S4])
m("N-forward-resolver-zero", G, "FORWARD or RESOLVER set to 0.",
  [("  WINN3_GATEWAY_FORWARD=1\n  WINN3_GATEWAY_RESOLVER=1\n", "  WINN3_GATEWAY_FORWARD=0\n  WINN3_GATEWAY_RESOLVER=0\n", 1)],
  pytest=[S4])
m("N-keygen-overwrites", G, "keygen overwrites.",
  [('        if state == "complete":\n            for stage in self.stages():\n                self.remove_stage(stage)\n            return\n',
    '        if state == "complete":\n            for stage in self.stages():\n                self.remove_stage(stage)\n', 1)],
  pytest=[S4])
m("N-digest-pin-bypassed", G, "Digest pin bypassed.",
  [('  [[ "${sha}" == "${WINN3_ONETOUCH_BINARY_SHA256}" ]] || {\n    err "Staged gateway does not match the S1 certified binary pin"; return 1;\n  }\n', "", 1)],
  pytest=[S7], note="phase A of the staged binary; killed by the phase A unit tests in test_winn3_onetouch_s7.py")
m("N-unknown-installed-binary-replaced", G, "An unknown live digest is replaced without WINN3_ALLOW_BINARY_REPLACE=1.",
  [('    [[ "${live}" == "${sha}" || "${WINN3_ALLOW_BINARY_REPLACE:-0}" == 1 ]] || {', "    true || {", 1)],
  pytest=[S7])
m("N-cover-check-skipped", G, "Cover check skipped.",
  [("  winn3gw_cover_material preflight || return 1\n", "", 1)],
  pytest=[S7], note="phase A; the phase B install step is covered by the S4 phase B tests")
m("N-etc-winn-755", G, "`/etc/winn` at 755.",
  [("  install -d -m 750 -o root -g \"${WINN3_GATEWAY_SERVICE_USER}\" /etc/winn\n", "  install -d -m 755 -o root -g \"${WINN3_GATEWAY_SERVICE_USER}\" /etc/winn\n", 2)],
  pytest=[S4, S5, S7])
m("N-latch-before-loses-the-gateway", G, "Latch `Before=` loses the gateway.",
  [("wins-vpn-firewall.service winn3-gateway.service winn3-gateway-firewall.service\n", "wins-vpn-firewall.service\n", 1)],
  pytest=[S4, S5, S7])
m("N-env-after-write-firewall", G, "Env written after `write_firewall`.",
  [("  winn3gw_phase_b\n  write_nginx\n", "  write_nginx\n", 1),
   ("  write_firewall\n  # Reproduce the runtime-only egress NAT", "  write_firewall\n  winn3gw_phase_b\n  # Reproduce the runtime-only egress NAT", 1)],
  pytest=[S7])
m("N-postflight-v3-gate-removed", G, "Postflight v3 gate removed.",
  [("  systemctl is-active --quiet winn3-gateway.service || return 1\n  systemctl is-enabled --quiet winn3-gateway.service || return 1\n  /usr/local/bin/wins-edge-hardening --check-winn3-udp-policy || return 1\n",
    "  /usr/local/bin/wins-edge-hardening --check-winn3-udp-policy || return 1\n", 1)],
  pytest=[S4, S7])
m("N-egress-check-skipped", G, "Egress check skipped.",
  [("  check_gateway_egress_mtu || return 1\n  winn3gw_activate\n", "  winn3gw_activate\n", 1)],
  pytest=[S4, S7])
m("N-postflight-ready-check-removed", G, "Postflight: the identity-ready comparison is removed.",
  [('  [[ "$(/usr/local/libexec/winsvpn/winn3-node identity-ready /etc/winn/public/gateway-identity.json "${WINN3_GATEWAY_CREDENTIALS_DIR}")" == "${WINN3_IDENTITY_DIGEST}" ]] || return 1\n', "", 1)],
  pytest=[S4, S7])
m("N-offnode-exemption-widened-to-24", G, "Off-node exemption widened beyond the exact canary key and `10.8.255.1/32` (for example to the /24).",
  [('$key == "$CANARY_PUBKEY" && $ips_norm == "10.8.255.1/32" ]]', '$key == "$CANARY_PUBKEY" && $ips_norm == 10.8.255.* ]]', 1)],
  pytest=[S4])
m("N-offnode-exemption-any-key", G, "Off-node exemption admits any key carrying `10.8.255.1/32`.",
  [('-n $CANARY_PUBKEY && $key == "$CANARY_PUBKEY" && $ips_norm == "10.8.255.1/32" ]]', '-n $CANARY_PUBKEY && $ips_norm == "10.8.255.1/32" ]]', 1)],
  pytest=[S4])
m("N-session-reads-only-ssh-connection", G, "The direct-session detection reads only `SSH_CONNECTION`.",
  [("            return True\n        return self.attached(self.installer)\n", "            return True\n        return False\n", 1)],
  pytest=[S4])
m("N-session-unevaluable-is-not-direct", G, "The direct-session detection treats a signal it cannot evaluate as \"not direct\".",
  [('        print("winn3 session: " + str(exc), file=sys.stderr)\n        raise SystemExit(0)', '        print("winn3 session: " + str(exc), file=sys.stderr)\n        raise SystemExit(1)', 1)],
  pytest=[S4])
m("N-session-holder-walk-one-hop", G, "Signal 4 evaluates a holder outside every session scope only by signals 2 and 3 (one hop).",
  [("        if depth >= 8:\n", "        if depth >= 1:\n", 1)],
  pytest=[S4])
m("N-session-pts-only", G, "Signal 4 reads only `/dev/pts/` descriptors.",
  [('                if target.startswith(("pipe:[", "socket:[")):\n', "                if False:\n", 1)],
  pytest=[S4])
m("N-session-installer-descendants-not-excluded", G, "Signal 4 evaluates the installer's own descendants as an unresolved remote peer.",
  [("            if pid == self.installer:\n                return True\n", "            if False:\n                return True\n", 1)],
  pytest=[S4])

# =====================================================================================================
# The moved gateway block (S2, S3): the equivalence checker with its enumerated allow-list kills an edit of the block
# =====================================================================================================
G = "gateway-block"
m("B-helper-inserts-at-position-1", G, "Helper inserts at position 1.",
  [('      ipt_gw -I INPUT "$((recovery_at + 1))" -i "${iface}" -d "${inner}" -j WINN3GW-INPUT || return 1', '      ipt_gw -I INPUT 1 -i "${iface}" -d "${inner}" -j WINN3GW-INPUT || return 1', 1)],
  cmd=[BLOCK_CHECK])
m("B-apply-forwarding-without-lock", G, "Any firewall writer without the lock (apply_forwarding_firewall).",
  [('apply_forwarding_firewall() {\n  wins_fw_lock || { winn3gw_err "The shared firewall lock ${WINS_FIREWALL_LOCK} is unavailable; the forwarding firewall was not changed."; return 1; }\n',
    'apply_forwarding_firewall() {\n', 1)],
  cmd=[BLOCK_CHECK])
m("B-teardown-forwarding-without-lock", G, "Any firewall writer without the lock (teardown_forwarding_firewall).",
  [('teardown_forwarding_firewall() {\n  wins_fw_lock || { winn3gw_err "The shared firewall lock ${WINS_FIREWALL_LOCK} is unavailable; the forwarding firewall was not changed."; return 1; }\n',
    'teardown_forwarding_firewall() {\n', 1)],
  cmd=[BLOCK_CHECK])
m("B-backup-variable-collision", G, "Backup variable collision (the standalone hostname-based prefix comes back).",
  [('write_unit() {\n', 'write_unit() {\n  local backup_prefix="gateway-$(hostname -s)"\n', 1)],
  cmd=[BLOCK_CHECK])
m("B-exit-trap-left-in", G, "EXIT trap left in.",
  [('write_unit() {\n', "write_unit() {\n  trap 'true' EXIT\n", 1)],
  cmd=[BLOCK_CHECK])
m("B-etc-winn-755-in-write-env", G, "`/etc/winn` at 755 in the moved write_env_file.",
  [('  install -d -m 750 -o root -g "${WINN3_GATEWAY_SERVICE_USER}" /etc/winn\n  install -d -m 700 -o root -g root "${WINN3_GATEWAY_CREDENTIALS_DIR}"\n',
    '  install -d -m 755 -o root -g "${WINN3_GATEWAY_SERVICE_USER}" /etc/winn\n  install -d -m 700 -o root -g root "${WINN3_GATEWAY_CREDENTIALS_DIR}"\n', 1)],
  cmd=[BLOCK_CHECK])
m("B-weekly-maintenance-restarts-active-gateway", G, "Weekly maintenance restarts an active gateway.",
  [("if systemctl is-failed --quiet winn3-gateway.service; then\n", "if true; then\n", 1)],
  pytest=[S7])

# The node half of 3.17 now lives in the data-plane installer (whole-tree fix), so this mutant runs here; Tier B TB-02
# and the H7 hub tests still cover the hub half.
m("H-fresh-path-skips-complete-fresh", "node-other", "The fresh path skips `deployment/complete-fresh`.",
  [("    mark_data_deployment_ready\n    complete_fresh_deployment_after_postflight || return 1\n",
    "    mark_data_deployment_ready\n", 1)],
  pytest=[S4])

# The four node mutants the S7 report left pending (runbook P2, BLOCK rows 9 and 10), and the fd 9 reacquisition.
# The edge rebuild transaction is the real wins-edge-hardening artifact the EDGE fixtures run; EDGE-rebuild-transaction
# executes its base-jump removal and its gated rules.v4 save on real iptables.
m("N-edge-rebuild-base-jump-loop", "node-other",
  "The base-jump removal loops on `ipt_read -C` inside the edge transaction, or stages more `-D` lines than live copies.",
  [("    for (( latch_index=0; latch_index<latch_count && latch_index<64; latch_index++ )); do\n      ipt -D INPUT -j WINVPN-LOCAL-SERVING\n    done\n",
    "    for (( latch_index=0; latch_index<64; latch_index++ )); do\n      ipt_read -C INPUT -j WINVPN-LOCAL-SERVING 2>/dev/null || break\n      ipt -D INPUT -j WINVPN-LOCAL-SERVING\n    done\n", 1)],
  tier_a=["EDGE-rebuild-transaction"],
  note="Inside the transaction a staged -D is not applied, so -C keeps succeeding and 64 deletions are staged for one live copy.")
m("N-edge-rebuild-extra-base-delete", "node-other",
  "The edge rebuild stages more `-D` lines than live copies (the second arm of the base-jump bullet).",
  [("latch_index<latch_count && latch_index<64", "latch_index<=latch_count && latch_index<64", 1)],
  tier_a=["EDGE-rebuild-transaction"])
m("N-edge-rebuild-saves-without-gate", "node-other",
  "The edge rebuild's `rules.v4` write saves while the record exists without the predicate passing.",
  [('  if wins_late_failure_hold && ! wins_latch_rules_dominate; then\n    err "Late-failure persistence gate refused; previous rules.v4 retained."\n    cleanup_edge_firewall_transaction\n    return 1\n  fi\n', "", 1)],
  tier_a=["EDGE-rebuild-transaction"])
m("N-edge-rebuild-deletes-base-jump-under-record", "node-other",
  "The edge rebuild stages the base-jump deletion while the record exists.",
  [("  if ! wins_late_failure_hold; then\n    local latch_rules latch_count latch_index\n",
    "  if true; then\n    local latch_rules latch_count latch_index\n", 1)],
  tier_a=["EDGE-rebuild-transaction"])
m("N-second-fail2ban-writer", "node-other", "A second fail2ban writer.",
  [("\nremove_legacy_smart_boost() {\n",
    "\nwrite_fail2ban_sshd_jail() {\n  mkdir -p /etc/fail2ban/jail.d\n  cat > /etc/fail2ban/jail.d/winn3-gateway-sshd.conf <<'F2BEOF'\n"
    "[sshd]\nenabled = true\nmaxretry = 5\nF2BEOF\n}\n\nremove_legacy_smart_boost() {\n", 1),
   ("ignoreip = ${ignore_ips}\nEOF\n\n  ssh-keygen -A\n",
    "ignoreip = ${ignore_ips}\nEOF\n  write_fail2ban_sshd_jail\n\n  ssh-keygen -A\n", 1)],
  pytest=[S7],
  note="The retired gateway installer's writer (tools/test_winn3_gateway_block.py names write_fail2ban_sshd_jail), defined "
       "and called beside the data plane's own jail. Killed by StaticInstallerProperties."
       "test_the_data_plane_has_exactly_one_fail2ban_writer. tools/test_sysctl_single_owner.py covers sysctl owners only "
       "and has no fail2ban check, so it is not listed as a kill test.")
m("N-replay-journal-literal-removed", "node-other", "Replay-journal literal removed.",
  [("  WINN3_GATEWAY_REPLAY_JOURNAL=1\n", "  WINN3_GATEWAY_REPLAY_JOURNAL=$((1))\n", 2)],
  pytest=[S7],
  note="The value is unchanged; only the ruled literal is gone, which is what RULINGS.lock guards. Killed by "
       "StaticInstallerProperties.test_the_ruled_data_plane_literals_hold_under_the_real_verify_rulings, which runs the "
       "repository's own tools/verify_rulings.sh over the installer under test.")
m("TB-fd9-trace-reacquisition", "node-exit",
  "A guard command re-acquires its fd 9 after it holds fd 7 (the deterministic strace trace assertion; the Tier A contender test is a necessary condition only).",
  [('  current_sha="$(sha256sum "${INSTALLER_PATH}" | awk \'{print $1}\')"\n  [[ "${current_sha}" == "${installer_sha}" ]] \\\n',
    '  lock_guard\n  current_sha="$(sha256sum "${INSTALLER_PATH}" | awk \'{print $1}\')"\n  [[ "${current_sha}" == "${installer_sha}" ]] \\\n', 1)],
  tier_a=["STRACE-fd9-trace", "GUARD-rotate-keeps-fd9"],
  note="The second lock_guard at the former call site of rotate_serving (5.5: the reacquisition mutant). STRACE-fd9-trace "
       "is the deterministic kill and runs only where strace is installed (D8); GUARD-rotate-keeps-fd9 is the race-dependent "
       "contender check.")

# =====================================================================================================
# Pending: needs a later slice, or only a real systemd can kill it
# =====================================================================================================
T = "Tier B"
for mid, text, kill in (
    ("TB-checked-start-outside-activation-lock", "A gated caller checks or starts outside the activation lock. Or a caller's critical section has no hard bound. Or the handler stops services before it holds the lock or before its 120 s wait has expired.", "TB-09 variants 1, 2, 4, 6"),
    ("TB-child-outside-pid1-scope", "A gated caller runs its check outside the bounded child, or its parent issues a start itself. Or the child runs outside a scope supervised by PID 1.", "TB-09 variants 3, 4"),
    ("TB-handler-fd6-wait-unbounded", "The handler, while it holds fd 7, waits on fd 6 without its 120 s bound. Or a gated child waits on fd 7 outside its 105 s bound.", "TB-09 variant 7"),
    ("TB-settle-ends-early-after-fence", "The settle check ends at 30 s after the fence killed a scope or after the handler's first `flock -n 6` failed.", "TB-09 variants 8, 9"),
    ("TB-direct-ssh-rerun-mutates", "A rerun under the record performs any hub or host mutation from a direct SSH session.", "TB-10 (needs a real ssh session)"),
    ("TB-signal4-service-cgroups-only", "Signal 4 applies only to `.service` and `user@<uid>.service` cgroups.", "TB-10 setsid systemd-run --scope case"),
    ("TB-signal4-holder-walk-one-hop", "Signal 4 evaluates a holder outside every session scope only by signals 2 and 3 (observed shape: `tee` holder).", "TB-10 tee-holder and ssh -T cases"),
    ("TB-maintenance-package-upgrade-starts-disabled-unit", "A package upgrade inside maintenance starts a disabled unit.", "TB-08"),
):
    pending(mid, T, text, "Tier B on amd64t (real systemd, owner-run)", kill)
for mid, text, slice_, kill in (
    ("H-signer-key-owned-by-root", "Signer key owned by root.", "H1", "H1 signer tests"),
    ("H-hub-unit-regains-capability", "The hub unit regains any capability, a broker socket or root's SSH write set (one mutant per D1 to D8).", "H0", "H0 hardening tests D1 to D8"),
    ("H-canary-job-writable-db", "The canary job regains a writable database handle.", "H3", "H3 canary tests"),
    ("H-signer-gets-network", "Signer gets network.", "H1", "H1 unit-text tests"),
    ("H-unticketed-identity-signed", "Unticketed new or changed identity signed.", "H1/H4", "signer ticket tests"),
    ("H-host-key-signature-not-checked", "An identity whose host-key signature is missing, or made by a host key other than the ticket's, is accepted.", "H1/H2", "signer tests"),
    ("H-renewal-with-changed-static-key", "Renewal with a changed static key accepted.", "H1", "signer tests"),
    ("H-ticket-replay", "Ticket replay accepted; a ticket from an older epoch accepted; a descriptor signature accepted as a ticket.", "H1/H4", "signer tests"),
    ("H-go-live-from-unverified-bytes", "`go_live` or `tier` read from anything other than the verified ticket bytes.", "H4/H7", "ticket tests"),
    ("H-idempotency-key-defects", "Renewal idempotency key without `expected_prior_seq`; a key that includes the generation; an orphaned issuance committed by a moved generation; a superseded sequence counted or returned.", "H1/H2", "signer and hub tests"),
    ("H-floor-and-allowance-defects", "`expected_prior_seq` read from the stored descriptor; the no-live-issuance floor rules; recovery allowance defects; sequence bound; floor-reset CLI defects (v8 fixes 6 and 8, v9 fixes 7 and 8, v10 fix 7, A-4, E9).", "H1/H4", "recovery tests in 5.5"),
    ("H-backup-and-bootstrap-defects", "Signer key or ledger checkpoint included in backups; `ledger_bootstrap` reachable from the app socket; no-checkpoint recovery restores a slug as active; `admission_gen` not incremented on a reset.", "H1/H4", "5.5 ledger tests"),
    ("H-hub-key-prune-defects", "Recovery signs a slug whose heartbeat still reports a stale hub key; the prune matches only marked lines or keeps an unmarked line; malformed `authorized_keys` handling; the allow-list installer's grammar (v8 fix 7, v9 fixes 6 and 8).", "H0/H1", "5.5 hub key prune tests"),
    ("H-pipeline-order-defects", "Signing before the pre-sign canary; signing before `deployment_released_at`; the precondition reading `deployment_completed_at`; the carrier enabled before the served-profile canary; served-profile canary against the pulled identity; a result bound to another `seq` or generation.", "H2/H3", "5.5 pipeline tests"),
    ("H-complete-fresh-and-bootstrap-defects", "`complete-fresh` counting old promotion rows or accepting a reset without a valid unconsumed `reset` ticket; re-bootstrap leaving state open or writing the hold; migration default.", "H7", "5.5 go-live tests"),
    ("H-golive-flip-defects", "Go-live flipped with a missing carry proof, a stale canary, a missing off-node gate or an active hold; the gate reading path MTU from the node report; a generation move ignored by an async commit; the lineage and expected-transition rules.", "H7", "5.5 go-live tests"),
    ("H-offnode-core-exit-peer-admitted", "`node_admits_peer` admitting a Core exit peer on a closed node.", "H5", "5.5 off-node and AWG canary tests"),
    ("H-ring-narrowing-defects", "Ordinary signer removal narrows the hub ring while any stored descriptor of that slot exists; recovery removes or keeps the retired slot wrongly; recovery withdraws a descriptor while leaving the node on a winn/3 carrier.", "H1/H8", "5.5 rollback tests"),
    ("H-queue-unit-remain-after-exit", "The rendered `wins-winn3gw-queues.service` text carries `RemainAfterExit=yes`.", "P1", "unit-text assertion in the P1 tests"),
    ("P-cache-key-without-ring-digest", "P-15 cache: a cache key without the ring digest; the on-demand path accepts a proof older than completion.", "P2", "5.7 hub cost tests"),
):
    pending(mid, "hub-and-other", text, slice_, kill)
