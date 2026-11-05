#!/usr/bin/env python3
"""Follow-up F-DPHIGH-2 (Fable ruling 2026-10-01): apply_firewall keeps the
OUTPUT jump to WINVPN-OUTPUT (the AdGuard admin-API owner guard) FIRST in
OUTPUT on every rebuild, not merely present, and reads the position back.

Runs the production wins-edge-hardening apply_firewall against the stateful
netfilter model (tools/fake_netfilter.py) through the harness of
tools/test_data_plane_low_findings.py, so WINS_FX_DP_LOW_INSTALLER points this
suite at a mutated installer too. No root, network or host firewall.

Usage: python3 tools/test_data_plane_output_jump_first.py [-v]
"""
from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import test_data_plane_low_findings as low  # noqa: E402

JUMP = "-j WINVPN-OUTPUT"


def write_restore_wrapper(box: low.Sandbox, body: str) -> None:
    """Replace the sandbox's iptables-restore with a wrapper around the model."""
    low.write_exec(
        box.bin / "iptables-restore",
        "#!/bin/bash\n" + body + f'exec "{low.PY}" "{low.FAKE_NETFILTER}" iptables-restore "$@"\n',
    )


class OutputJumpFirstTests(unittest.TestCase):
    def setUp(self) -> None:
        self.box = low.Sandbox()

    def tearDown(self) -> None:
        self.box.close()

    def rebuild(self, output: list[str]) -> list[str] | None:
        self.box.seed({"filter": {"OUTPUT": output, "WINVPN-OUTPUT": []}})
        result = low.run_apply_firewall(self.box)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertTrue(self.rules_v4().exists(), "a successful rebuild persists rules.v4")
        return self.box.chain("filter", "OUTPUT")

    def rules_v4(self) -> pathlib.Path:
        return self.box.root / "node-root" / "etc" / "iptables" / "rules.v4"

    def test_an_earlier_accept_is_moved_behind_the_guard_jump(self) -> None:
        self.assertEqual([JUMP, "-j ACCEPT"], self.rebuild(["-j ACCEPT", JUMP]))

    def test_every_exact_copy_is_replaced_by_one_jump_at_the_front(self) -> None:
        self.assertEqual([JUMP, "-o lo -j ACCEPT"], self.rebuild(["-o lo -j ACCEPT", JUMP, JUMP]))
        self.assertEqual([JUMP, "-o lo -j ACCEPT"], self.rebuild([JUMP, "-o lo -j ACCEPT", JUMP]))

    def test_a_missing_jump_is_inserted_first(self) -> None:
        self.assertEqual([JUMP, "-j ACCEPT"], self.rebuild(["-j ACCEPT"]))
        self.assertEqual([JUMP], self.rebuild([]))

    def test_a_first_jump_is_left_alone_and_reruns_are_stable(self) -> None:
        self.assertEqual([JUMP, "-j ACCEPT"], self.rebuild([JUMP, "-j ACCEPT"]))
        result = low.run_apply_firewall(self.box)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual([JUMP, "-j ACCEPT"], self.box.chain("filter", "OUTPUT"))

    def test_the_move_is_staged_in_the_transaction_not_applied_live(self) -> None:
        """A transaction that fails validation leaves OUTPUT exactly as it was:
        the jump is never deleted outside the atomic restore."""
        write_restore_wrapper(self.box, 'for a; do [[ "$a" == --test ]] && exit 1; done\n')
        self.box.seed({"filter": {"OUTPUT": ["-j ACCEPT", JUMP], "WINVPN-OUTPUT": []}})
        result = low.run_apply_firewall(self.box)
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(["-j ACCEPT", JUMP], self.box.chain("filter", "OUTPUT"))

    # ---- read-back failure path (round 2) --------------------------------
    def arm_hook(self) -> pathlib.Path:
        """After the real commit, a provider hook puts an ACCEPT first."""
        marker = self.box.root / "hook-ran"
        write_restore_wrapper(
            self.box,
            'test_only=0; for a; do [[ "$a" == --test ]] && test_only=1; done\n'
            f'if [[ "${{test_only}}" == 0 && ! -e "{marker}" ]]; then\n'
            f'  "{low.PY}" "{low.FAKE_NETFILTER}" iptables-restore "$@" || exit $?\n'
            f'  : > "{marker}"\n'
            f'  exec "{low.PY}" "{low.FAKE_NETFILTER}" iptables -I OUTPUT 1 -j ACCEPT\n'
            "fi\n",
        )
        return marker

    def adguard_doubles(self, stop_works: bool = True, stop_rc: int = 0, state: str = "track") -> None:
        """ss lists AdGuard Home on 3000 and 3100 until it is stopped. systemctl
        records the stop (exit STOP_RC) and answers `show -p ActiveState`:
        "track" is active before the stop and inactive after it, "fail" makes
        the query exit 1, anything else is printed as the state."""
        stopped = self.box.root / "adguard-stopped"
        low.write_exec(
            self.box.bin / "ss",
            f'#!/bin/bash\n[[ -e "{stopped}" ]] && exit 0\n'
            "echo 'LISTEN 0 4096 127.0.0.1:3000 0.0.0.0:* users:((\"AdGuardHome\",pid=77,fd=9))'\n"
            "echo 'LISTEN 0 4096 127.0.0.1:3100 0.0.0.0:* users:((\"AdGuardHome\",pid=77,fd=10))'\n",
        )
        stop = f': > "{stopped}"; exit {stop_rc}' if stop_works else f"exit {stop_rc}"
        if state == "track":
            show = f'if [[ -e "{stopped}" ]]; then echo inactive; else echo active; fi'
        elif state == "fail":
            show = "exit 1"
        else:
            show = f"echo {state}"
        low.write_exec(
            self.box.bin / "systemctl",
            '#!/bin/bash\nprintf "%s\\n" "$*" >> "${FAKE_SYSTEMCTL_LOG:-/dev/null}"\n'
            f'case "$*" in\n  stop*) {stop} ;;\n  *ActiveState*) {show} ;;\n'
            f'  is-active*) [[ ! -e "{stopped}" ]] ;;\n'
            '  show*) echo "ExecStart=/usr/bin/suricata -D -q 0 -c /etc/suricata/suricata.yaml" ;;\nesac\n',
        )

    def fail_live_iptables_when(self, condition: str, then: str = 'echo "iptables: injected failure" >&2; exit 1') -> None:
        """Wrap the model's iptables: run THEN when CONDITION (bash) holds."""
        low.write_exec(
            self.box.bin / "iptables",
            f'#!/bin/bash\nif {condition}; then {then}; fi\n'
            f'exec "{low.PY}" "{low.FAKE_NETFILTER}" iptables "$@"\n',
        )

    def run_failing_reguard(self) -> str:
        self.box.seed({"filter": {"OUTPUT": ["-o lo -j ACCEPT", JUMP], "WINVPN-OUTPUT": []}})
        result = low.run_apply_firewall(self.box)
        out = result.stdout + result.stderr
        self.assertNotEqual(0, result.returncode, out)
        self.assertFalse(self.rules_v4().exists())
        return out

    def test_a_failed_read_back_restores_then_re_guards_the_restored_output(self) -> None:
        """Round 2 (Sol, FU-JUMP): the restored snapshot has a loopback ACCEPT
        ahead of the guard. The run fails, nothing is persisted, and the
        restored OUTPUT gets the owner rules for every configured and listening
        port back behind a jump that is first again."""
        self.arm_hook()
        self.adguard_doubles()
        out = self.run_failing_reguard()
        self.assertIn("is not the first rule after the commit", out)
        self.assertIn("Re-added the AdGuard admin-API owner guard", out)
        self.assertEqual([JUMP, "-o lo -j ACCEPT"], self.box.chain("filter", "OUTPUT"))
        guard = self.box.chain("filter", "WINVPN-OUTPUT") or []
        for port in ("3000", "3100"):
            self.assertTrue(any(f"--dport {port}" in r and "REJECT" in r for r in guard), (port, guard))

    def test_a_re_guard_that_cannot_land_stops_adguard_and_verifies_it(self) -> None:
        marker = self.arm_hook()
        self.adguard_doubles()
        self.fail_live_iptables_when(f'[[ -e "{marker}" && " $* " == *" -I OUTPUT 1 "* ]]')
        out = self.run_failing_reguard()
        self.assertIn("AdGuard Home was stopped instead", out)
        self.assertIn("stop AdGuardHome.service", (self.box.root / "systemctl.log").read_text(encoding="utf-8"))

    def test_a_stop_that_leaves_listeners_is_reported_unconfirmed(self) -> None:
        marker = self.arm_hook()
        self.adguard_doubles(stop_works=False)
        self.fail_live_iptables_when(f'[[ -e "{marker}" && " $* " == *" -I OUTPUT 1 "* ]]')
        out = self.run_failing_reguard()
        self.assertIn("AdGuard Home is not confirmed stopped", out)
        self.assertNotIn("AdGuard Home was stopped instead", out)

    def test_only_a_positive_stopped_state_counts_as_stopped(self) -> None:
        """Round 3 (Sol, FU-JUMP): the stop must succeed, ActiveState must be
        exactly inactive or failed, and no listener may remain. A failed stop,
        a failed query, an unknown or any other state is not confirmed."""
        cases = [
            ({"stop_rc": 1}, False, "stop exit 1"),
            ({"stop_rc": 5}, False, "stop exit 5"),
            ({"state": "fail"}, False, "ActiveState query-failed"),
            ({"state": "unknown"}, False, "ActiveState unknown"),
            ({"state": "active"}, False, "ActiveState active"),
            ({"state": "deactivating"}, False, "ActiveState deactivating"),
            ({"state": '""'}, False, "ActiveState empty"),
            ({"stop_works": False, "state": "inactive"}, False, "ActiveState inactive"),
            ({"state": "failed"}, True, None),
            ({"state": "inactive"}, True, None),
        ]
        for kwargs, stopped, detail in cases:
            with self.subTest(**{k: str(v) for k, v in kwargs.items()}):
                self.tearDown()
                self.setUp()
                marker = self.arm_hook()
                self.adguard_doubles(**kwargs)
                self.fail_live_iptables_when(f'[[ -e "{marker}" && " $* " == *" -I OUTPUT 1 "* ]]')
                out = self.run_failing_reguard()
                if stopped:
                    self.assertIn("AdGuard Home was stopped instead", out)
                else:
                    self.assertIn("AdGuard Home is not confirmed stopped", out)
                    self.assertNotIn("AdGuard Home was stopped instead", out)
                    self.assertIn(detail, out)

    def test_a_jump_that_does_not_read_back_first_after_the_re_guard_stops_adguard(self) -> None:
        """Round 3 (seat C E2): the re-guard's own position read-back counts.
        Another hook puts an ACCEPT first right after the re-guard's insert."""
        marker = self.arm_hook()
        self.adguard_doubles()
        self.fail_live_iptables_when(
            f'[[ -e "{marker}" && " $* " == *" -I OUTPUT 1 -j WINVPN-OUTPUT "* ]]',
            f'"{low.PY}" "{low.FAKE_NETFILTER}" iptables "$@" || exit $?; '
            f'exec "{low.PY}" "{low.FAKE_NETFILTER}" iptables -I OUTPUT 1 -j ACCEPT',
        )
        out = self.run_failing_reguard()
        self.assertNotIn("Re-added the AdGuard admin-API owner guard", out)
        self.assertIn("AdGuard Home was stopped instead", out)

    def test_an_owner_rule_that_does_not_read_back_stops_adguard(self) -> None:
        """Round 3 (seat C E5): the re-guard's -C read-back of each owner rule
        counts. The live -A reports success but lands nothing."""
        marker = self.arm_hook()
        self.adguard_doubles()
        self.fail_live_iptables_when(
            f'[[ -e "{marker}" && " $* " == *" -A WINVPN-OUTPUT "* ]]', "exit 0")
        out = self.run_failing_reguard()
        self.assertNotIn("Re-added the AdGuard admin-API owner guard", out)
        self.assertIn("AdGuard Home was stopped instead", out)

    # ---- query failures (round 2, seat C N-1: X4, X6, X7) -----------------
    def test_a_failed_read_before_staging_aborts_with_nothing_changed(self) -> None:
        self.fail_live_iptables_when('[[ " $* " == *" -S OUTPUT"* ]]')
        seeded = ["-j ACCEPT", JUMP]
        self.box.seed({"filter": {"OUTPUT": seeded, "WINVPN-OUTPUT": []}})
        result = low.run_apply_firewall(self.box)
        out = result.stdout + result.stderr
        self.assertNotEqual(0, result.returncode, out)
        self.assertIn("Could not read or stage the OUTPUT jump", out)
        self.assertNotIn("iptables-restore", self.box.iptlog.read_text(encoding="utf-8"), "a restore ran")
        self.assertEqual(seeded, self.box.chain("filter", "OUTPUT"))
        self.assertFalse(self.rules_v4().exists())

    def test_a_failed_read_after_the_commit_never_persists(self) -> None:
        log = self.box.iptlog
        self.fail_live_iptables_when(
            f'[[ " $* " == *" -S OUTPUT"* ]] && grep -q -- "--noflush$" "{log}" 2>/dev/null')
        self.box.seed({"filter": {"OUTPUT": ["-j ACCEPT", JUMP], "WINVPN-OUTPUT": []}})
        result = low.run_apply_firewall(self.box)
        out = result.stdout + result.stderr
        self.assertNotEqual(0, result.returncode, out)
        self.assertIn("is not the first rule after the commit", out)
        self.assertFalse(self.rules_v4().exists(), "a ruleset whose position could not be read was persisted")

if __name__ == "__main__":
    unittest.main()
