"""The Tier A scenario registry (design v17 5.1 to 5.3).

`fixture` names a `sc_*` function in tools/onetouch_tiers/linux (dashes for
underscores). `profile` is `quick` (a few seconds) or `full` (waits out the
installer's real 20 s and 30 s bounds). `blocked` says why a scenario cannot
run against the tree under test; it is never counted as passed. Blocked items
exist so the final integrated tree shows exactly what is still unproven.
`needs` names guest programs a scenario requires; tier_a.py checks the guest
read-only before a run and reports the scenario blocked when one is missing.
"""


def item(identifier, fixture, group, design, profile="quick", blocked=None, needs=()):
    return {"id": identifier, "fixture": fixture, "group": group, "design": design,
            "profile": profile, "blocked": blocked, "needs": list(needs)}


NEEDS_HUB = ("needs a Tier A fixture that drives the hub: the hub app, signer and canary are in the tree, and hub-lite "
             "(tools/onetouch_tiers/hub_lite.py, server/test_winn3_onetouch_hublite.py) runs their 3.1 order on the Mac, but no "
             "namespace fixture pairs it with a running node here; Tier B TB-02 and TB-06 pair it with the real guest")
NEEDS_SYSTEMD = "needs the guest's own PID 1 (real systemd units, scopes and reboots); it is a Tier B scenario, owner-run on amd64t"
NEEDS_GATEWAY = ("needs a running winn3-gateway: it refuses to serve without cover material (a cover certificate and key, the Winn leaf "
                 "and ECH keys: `-cert is required`), a replay journal (a 0640 file and a 0700 .wal directory), a fixed /run/winn3-gateway/status.json "
                 "and a peer registry. No fixture in the tree generates the cover and ECH test material")

SCENARIOS = [
    # ---- the dominance predicate against real iptables (5.3 winn3_latch_dominates) ------------------
    item("PRED-matrix", "pred-matrix", "PRED", "5.3: winn3_latch_dominates passes on / fails on / guard-body negatives"),
    item("PRED-read-errors", "pred-read-errors", "PRED", "5.3 v11 fix 4: every read error fails closed"),
    item("PRED-absence", "pred-absence", "PRED", "5.3 v12 departure 2, v13 fix 3: absence needs status 1 and iptables' own message"),
    item("PRED-unparseable", "pred-unparseable", "PRED", "5.3 fix 2: a line the parser cannot read fails"),
    item("PRED-no-side-effects", "pred-no-side-effects", "PRED", "5.3 the gate itself: no files, no locks, bounded reads"),
    # ---- the persistence gate and the real guard programs (5.3 v10 fix 1, 5.1 steps 9 to 11) ----------
    item("GATE-record-present-refuses", "gate-record-present-refuses", "GATE", "5.3 gate: record present, S1 fails, save refused"),
    item("GATE-record-absent-saves", "gate-record-absent-saves", "GATE", "5.3 gate: record absent, saves as today"),
    item("GATE-symlink-record", "gate-symlink-record", "GATE", "5.3 gate: a symlink at the record path counts as present"),
    item("GATE-safe-save-under-record", "gate-record-present-saves-when-safe", "GATE", "5.3 gate: a safe ruleset saves under the record"),
    item("GATE-admitted-jumps-ahead", "gate-admitted-jumps-ahead", "GATE", "5.3 v11 fix 1, v12 fix 4: Fail2Ban and stealth jumps ahead of the latch are admitted, an ACCEPT inside them is not"),
    item("GATE-ssh-guard", "gate-ssh-guard", "GATE", "5.3 v10 fix 1: the SSH recovery guard's persist_firewall is gated"),
    item("GATE-fd7-timeout", "gate-fd7-timeout", "GATE", "5.3 v10 fix 5: fd 7 timeout in a guard"),
    item("GATE-status-bounds", "gate-status-bounds", "GATE", "5.3 v10 fix 4: status takes no fd 7 and waits for fd 9 only its bound"),
    item("GUARD-lifecycle", "guard-lifecycle", "GUARD", "5.1 steps 9 to 11: disable, rotate, release, reboot, with real probes"),
    item("GUARD-boot-enforce-latched", "guard-boot-enforce-latched", "GUARD", "5.3 boot: enforce restores darkness from rules.v4 and from the latch file"),
    item("GUARD-rotate-keeps-fd9", "guard-rotate-keeps-fd9", "GUARD", "5.3 v10 fix 4: contender part (the strace part is blocked)"),
    # ---- repair (handler step 2a, branch 3) on real iptables (5.3 v8 fix 5, v9 fixes 1 and 3) ---------
    item("REPAIR-deletes-accepts", "repair-deletes-accepts", "REPAIR", "5.3 repair loop bound: three identical ACCEPTs are all deleted"),
    item("REPAIR-bound-64", "repair-bound-64", "REPAIR", "5.3 v8 fix 5: a reappearing rule stops the loop at 64 deletions"),
    item("REPAIR-recovery-body", "repair-recovery-body", "REPAIR", "5.3 v9 fix 3, v10 fix 5: recovery body with valid, missing, absent and invalid armed.env"),
    item("REPAIR-failed-command-recorded", "repair-failed-command-recorded", "REPAIR", "5.3 v10 fix 1: a failed repair command is recorded as repair failed"),
    item("REPAIR-position-independent", "repair-position-independent", "REPAIR", "5.3 v9 fix 1: position-independent latch insert, competing writer after every command"),
    # ---- the real edge firewall artifact (5.1 step 1) ----------------------------------------------------
    item("EDGE-artifact-ruleset", "edge-artifact-ruleset", "EDGE", "5.1 step 1 / 5.3: the real wins-edge-hardening output is dominated by the latch and idempotent"),
    item("EDGE-rebuild-transaction", "edge-rebuild-transaction", "EDGE", "5.3 v9 fix 4, v10 fix 1: the edge rebuild stages one -D per live base latch jump with no record, none under the record, and its gated rules.v4 save refuses while L1 fails"),
    item("EDGE-handler-live-dominant", "edge-handler-live-dominant", "EDGE", "5.3: the exit path on the real edge ruleset"),
    item("EDGE-handler-snapshot", "edge-handler-snapshot", "EDGE", "5.3: the exit path with a snapshot restore over the real edge ruleset"),
    # ---- the exit handler end to end (5.3 snapshot fallback, nesting, injected failures, dominance) -------
    item("HANDLER-live-dominant", "handler-live-dominant", "HANDLER", "5.3 / 2.7: the exit path latches and publishes a dominant ruleset"),
    item("HANDLER-snapshot-open-serving", "handler-snapshot-open-serving", "HANDLER", "5.3 snapshot fallback (v8 fix 1): permissive snapshot restored, branch 3"),
    item("HANDLER-snapshot-jumps-with-accept", "handler-snapshot-jumps-with-accept", "HANDLER", "5.3 forced restores: both jumps but serving ACCEPTs ahead"),
    item("HANDLER-snapshot-base-accept", "handler-snapshot-base-accept", "HANDLER", "5.3 forced restores: snapshot with a base-INPUT ACCEPT ahead of the jump"),
    item("HANDLER-snapshot-altered-latch", "handler-snapshot-altered-latch", "HANDLER", "5.3 forced restores: S passes, latch body altered, enforce repairs"),
    item("HANDLER-lock-held-nesting", "handler-lock-held-nesting", "HANDLER", "5.3 v9 fix 9: lock-held nesting succeeds"),
    item("HANDLER-base-accept-ahead", "handler-base-accept-ahead", "HANDLER", "5.3 v8 fix 1 Sol's fixture: base-INPUT ACCEPT ahead of -j WINVPN-INPUT"),
    item("HANDLER-france-dominance", "handler-france-dominance", "HANDLER", "5.3 dominance fixture (v7): France ordering in the snapshot and live"),
    item("HANDLER-late-completion", "handler-late-completion", "HANDLER", "5.3 combined fixture without contention: latch released, completion fails"),
    item("HANDLER-injected-save-refusal", "handler-injected-save-refusal", "HANDLER", "5.3 v9 fix 9: save refusal (UNRECOVERABLE marker)"),
    item("HANDLER-injected-read-failure", "handler-injected-read-failure", "HANDLER", "5.3 v9 fix 9: the recovery guard's INPUT read fails"),
    item("HANDLER-snapshot-locked-guard", "handler-snapshot-open-serving-locked", "HANDLER", "5.3 snapshot fallback with the guard lock held past 20 s", profile="full"),
    item("HANDLER-injected-lock-timeout", "handler-injected-lock-timeout", "HANDLER", "5.3 v9 fix 9: a competing guard-lock timeout", profile="full"),
    item("HANDLER-no-fd7", "handler-no-fd7", "HANDLER", "5.3 v9 fix 5: no fd 7 at failure time", profile="full"),
    item("HANDLER-no-fd7-reboot", "handler-no-fd7-reboot", "HANDLER", "5.3 v9 fix 5: no fd 7, service-level darkness across a reboot", profile="full"),
    item("HANDLER-guard-pauses", "handler-guard-pauses", "HANDLER", "5.3 v9 fix 1: whole-transition guard locking, pauses under 20 s"),
    item("HANDLER-guard-pauses-long", "handler-guard-pauses-long", "HANDLER", "5.3 v9 fix 1: pauses over 20 s take the no-fd-7 path", profile="full"),
    item("HANDLER-recovery-body-live", "handler-recovery-body-live", "HANDLER", "5.3 v9 fix 3: recovery body live at failure time, valid armed.env"),
    item("HANDLER-recovery-body-snapshot", "handler-recovery-body-snapshot", "HANDLER", "5.3 v9 fix 3: recovery body in the pre-deployment snapshot"),
    item("HANDLER-recovery-body-invalid-armed", "handler-recovery-body-invalid-armed", "HANDLER", "5.3 v9 fix 3, v10 fix 5: armed.env failing load_armed_state"),
    item("HANDLER-boot-enforce-gate", "handler-boot-enforce-gate", "HANDLER", "5.3 v10 fix 3: boot-time enforce under the gate"),
    item("HANDLER-serving-activator", "handler-serving-activator", "HANDLER", "5.3 v10 fix 2: no gated start runs while the record exists (regular, symlink, dangling)"),
    item("HANDLER-dominance-takes-no-guard-lock", "handler-dominance-check-takes-no-guard-lock", "HANDLER", "5.3 v8 fix 3: winn3_latch_dominates takes no guard lock and never calls status"),
    item("HANDLER-unsafe-latch-file", "handler-unsafe-latch-file", "HANDLER", "5.3 v9 fix 2: the sixth forced-restore variant, an unsafe latch file, no guard call from the reassert step"),
    item("HANDLER-fence-live-scope", "handler-fence-live-scope", "HANDLER", "5.3 checked starts in flight: fence, cancel and the 120 s window (stubbed systemd)"),
    item("HANDLER-settle-late-restart", "handler-settle-stops-late-restart", "HANDLER", "5.3 variant 8: an in-flight restart completes inside the settle window", profile="full"),
    item("HANDLER-injection-sweep-armed", "handler-injection-sweep-armed", "HANDLER", "5.3 v10 fixes 1 and 6: one-shot failure of each mutating command, guard armed", profile="full"),
    item("HANDLER-injection-sweep-noguard", "handler-injection-sweep-noguard", "HANDLER", "5.3 v10 fixes 1 and 6: one-shot failure of each mutating command, snapshot path", profile="full"),
    item("HANDLER-injection-sweep-edge", "handler-injection-sweep-edge", "HANDLER", "5.3 v10 fixes 1 and 6: one-shot failure of each mutating command on the real edge ruleset, guard armed", profile="full"),
    item("HANDLER-enforce-recheck-fails", "handler-enforce-recheck-fails", "HANDLER", "5.3 v8 fix 4: enforce succeeds but the re-check still fails, branch 3 runs"),
    item("HANDLER-guard-lock-contention", "handler-guard-lock-contention", "HANDLER", "5.3 v8 fix 3: lock contention, disable bounded at 20 s plus 2 s", profile="full"),
    item("HANDLER-combined-fd9", "handler-combined-fd9-contention", "HANDLER", "5.3 v9 fix 2: the combined fixture with fd 9 contention", profile="full"),
    # ---- blocked: the rest of 5.1 and 5.2 (listed so the integrated tree shows what is still unproven) -----------
    item("STEP-01-bootstrap-to-phase-c", "none", "STEP", "5.1 step 1: bootstrap firewall, phase B, write_firewall, phase C in a systemd container with the real edge artifact",
         blocked="needs a systemd container and the real edge firewall artifact rendered with a gateway; " + NEEDS_GATEWAY),
    item("STEP-02-identity-pull", "none", "STEP", "5.1 step 2: the hub job pulls the identity over SSH and verifies the host-key signature", blocked=NEEDS_HUB),
    item("STEP-03-pre-sign-canary", "none", "STEP", "5.1 step 3: pre-sign canary through a veth into a client namespace", blocked=NEEDS_HUB + "; " + NEEDS_GATEWAY),
    item("STEP-04-sign-and-store", "none", "STEP", "5.1 step 4: sign, then store; the carrier is still winn/1", blocked=NEEDS_HUB),
    item("STEP-05-served-profile-canary", "none", "STEP", "5.1 step 5: served-profile canary on the prospective row", blocked=NEEDS_HUB),
    item("STEP-06-carrier-flip", "none", "STEP", "5.1 step 6: candidate gate, carrier flip, post-flip v3 canary", blocked=NEEDS_HUB),
    item("STEP-07-awg-carrying-canary", "none", "STEP", "5.1 step 7: the AWG carrying canary carries a reply on each transport", blocked=NEEDS_HUB),
    item("STEP-08-offnode-gate", "none", "STEP", "5.1 step 8: the hub-run off-node gate records a source=hub row", blocked=NEEDS_HUB),
    item("STEP-09-fresh-install-flip", "none", "STEP", "5.1 step 9: the fresh_install class flips the latch", blocked=NEEDS_HUB),
    item("STEP-10-handshake-icmp-dns", "none", "STEP", "5.1 step 10: a client handshake carries ICMP and DNS through 10.10.0.1:53", blocked=NEEDS_GATEWAY),
    item("STEP-11-container-restart-boot-order", "none", "STEP", "5.1 step 11: restart the container (boot ordering)", blocked=NEEDS_SYSTEMD),
    item("STEP-12-rerun-no-restart-p14", "none", "STEP", "5.1 step 12: rerun, keys unchanged, gateway MainPID and carrying sessions recorded before and after (P-14)",
         blocked=NEEDS_SYSTEMD + "; " + NEEDS_GATEWAY),
    item("STEP-13-adopt-standalone-tree", "none", "STEP", "5.1 step 13: adopt a tree built by the old standalone installer; ledger reconciliation from a g1 descriptor",
         blocked="a Tier B scenario: TB-13-standalone-adoption (a standalone-built guest adopted by the installer, the hub ledger reconciled in hub-lite); the node side is also covered offline by server/test_winn3_onetouch_s5.py"),
    item("STEP-14-rollback-unsuspend", "none", "STEP", "5.1 step 14: rollback and unsuspend", blocked="a Tier B scenario: TB-14-rollback-unsuspend (the guest's --winn3-rollback and rerun, hub-lite's hold, withhold, suspend and unsuspend); --winn3-rollback is also covered offline by S5"),
    item("STEP-15-negative-cases", "none", "STEP", "5.1 step 15: negative cases", blocked=NEEDS_HUB + " (the node-side negatives are in the PRED, GATE, REPAIR and HANDLER groups)"),
    item("HARDEN-D1-to-D8", "none", "HARDEN", "5.2: hardening tests D1 to D8 against the real extracted hub app", blocked=NEEDS_HUB),
    item("STRACE-fd9-trace", "strace-fd9-trace", "STRACE", "5.5 v11 fix 5, v12 fix 7, v13: the deterministic strace trace of rotate-serving (one fd 9 acquisition before the boundary, none after, no fd 9 change in the guard's shell)",
         needs=("strace",)),
]
