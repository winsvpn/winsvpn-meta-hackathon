#!/usr/bin/env python3
"""TP-S1 (owner, 2026-10-09): server/wins_payment_only_profile.sh.

The shipped script runs under Bash 4+ against a sandbox root (WINS_PO_ROOT)
with systemd, docker, iptables-save, curl and the certified edge rebuild faked.
The fakes model what matters for the ordering rule: the edge rebuild emits
NFQUEUE rules only for admission 1 and refuses admission 1 unless queue 0 is
bound, Suricata binds queue 0 when it starts, and a start of a gated unit is a
no-op while the profile marker exists (ConditionPathExists). Any moment at
which a queue rule exists while nothing is bound to queue 0 is recorded as a
VIOLATION and fails the test.

Run: python3 -B -m pytest -q -p no:cacheprovider server/test_fleet_reset_payment_only_profile.py
     WINS_FLEET_PROFILE=/path/to/script ... (mutant runs)
"""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

import fleet_reset_testlib as lib

SCRIPT = lib.installer("WINS_FLEET_PROFILE", "server/wins_payment_only_profile.sh")

SYSTEMCTL = r'''#!/usr/bin/env bash
U="$FLEET_UNITS"; printf 'systemctl %s\n' "$*" >> "$FLEET_CALLS"
check() {  # a queue rule with nothing bound to queue 0 is the black hole
  if grep -q -- '-j NFQUEUE' "$FLEET_LIVE" 2>/dev/null && ! grep -q '^0 ' "$FLEET_NFQ" 2>/dev/null; then
    echo "VIOLATION after: systemctl $*" >> "$FLEET_CALLS"; fi; }
gated() { [[ -e "$FLEET_ROOT/etc/winsvpn/payment-only.active" && -e "$FLEET_ROOT/etc/systemd/system/$1.d/99-winsvpn-payment-only.conf" ]]; }
case "$1" in
  cat) [[ -e "$U/$2.known" ]] ;;
  is-enabled) [[ -e "$U/$2.enabled" ]] && echo enabled || echo disabled ;;
  is-active) [[ -e "$U/$2.active" ]] && echo active || echo inactive ;;
  enable) touch "$U/$2.enabled" ;;
  disable) shift; [[ "$1" == --now ]] && shift
           rm -f "$U/$1.enabled" "$U/$1.active"
           [[ "$1" == suricata.service ]] && : > "$FLEET_NFQ"; check "disable $1" ;;
  start) if gated "$2"; then echo "gated $2" >> "$FLEET_CALLS"; exit 0; fi
         [[ "$2" == suricata.service && "${FLEET_SURICATA_FAILS:-0}" == 1 ]] && exit 1
         touch "$U/$2.active"
         [[ "$2" == suricata.service && "${FLEET_NOBIND:-0}" != 1 ]] && echo "0 1 0 2 65531 0 0 0 1" > "$FLEET_NFQ"
         check "start $2" ;;
  daemon-reload) ;;
esac
exit 0
'''
EDGE = r'''#!/usr/bin/env bash
# fake certified edge rebuild: PUBLIC_VPN_INGRESS_ADMISSION_FILE= apply_firewall
printf 'edge admission=%s ids=%s\n' "$PUBLIC_VPN_INGRESS_ADMISSION" "${INSTALL_DATA_IDS_IPS:-unset}" >> "$FLEET_CALLS"
if [[ "${FLEET_EDGE_FAILS:-0}" == 1 ]]; then
  # FLEET1 Turn 3: a failure that also breaks the admission restore, either
  # by a symlink in place of the file or by a mode change that cannot land.
  if [[ "${FLEET_EDGE_SYMLINKS_ADMISSION:-0}" == 1 ]]; then
    a="$FLEET_ROOT/etc/winsvpn/public-vpn-ingress-admission.env"
    printf 'PUBLIC_VPN_INGRESS_ADMISSION=0\n' > "$a.elsewhere"; rm -f "$a"; ln -s "$a.elsewhere" "$a"
  fi
  [[ "${FLEET_EDGE_BREAKS_CHMOD:-0}" == 1 ]] && : > "$FLEET_ROOT/.chmod-fails"
  exit 1
fi
if [[ "$PUBLIC_VPN_INGRESS_ADMISSION" == 1 ]]; then
  grep -q '^0 ' "$FLEET_NFQ" 2>/dev/null || { echo "edge refused: queue 0 unhealthy" >> "$FLEET_CALLS"; exit 1; }
  rules='-A WINVPN-INPUT -p tcp --dport 8443 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0 --queue-bypass'
else
  rules='-A WINVPN-INPUT -j DROP'
  [[ "${FLEET_EDGE_LEAVES_QUEUE:-0}" == 1 ]] && rules+=$'\n-A WINVPN-INPUT -j NFQUEUE --queue-num 0'
fi
printf '%s\n' "$rules" > "$FLEET_LIVE"; printf '%s\n' "$rules" > "$FLEET_ROOT/etc/iptables/rules.v4"
'''
DOCKER = r'''#!/usr/bin/env bash
printf 'docker %s\n' "$*" >> "$FLEET_CALLS"
S="$FLEET_UNITS/container"
case "$1" in
  inspect) [[ -e "$S" ]] || exit 1; cat "$S" ;;
  update) read -r run pol < "$S"; echo "$run ${2#--restart=}" > "$S" ;;
  stop) read -r run pol < "$S"; echo "false $pol" > "$S" ;;
  start) read -r run pol < "$S"; echo "true $pol" > "$S" ;;
esac
'''
SAVE = '#!/bin/sh\n[ "${FLEET_SAVE_FAILS:-0}" = 1 ] && exit 1\ncat "$FLEET_LIVE" 2>/dev/null\n'
SAVE6 = '#!/bin/sh\n[ "${FLEET_SAVE6_FAILS:-0}" = 1 ] && exit 1\nexit 0\n'
CHMOD = r'''#!/bin/sh
if [ -e "$FLEET_ROOT/.chmod-fails" ] && [ "$1" = 0600 ]; then exit 1; fi
exec /bin/chmod "$@"
'''
# nginx on Spain: 23000 is BTCPay (a wallet leak answers its digest challenge
# when FLEET_WALLET_ON_23000=1, or only for the Host it names), 23001 is the
# wallet's own listener.
CURL = r'''#!/bin/sh
host=""
for a in "$@"; do
  case "$a" in "Host: "*) host="${a#Host: }" ;; esac
  last="$a"
done
case "$last" in
  *23000/json_rpc*)
    if [ "${FLEET_WALLET_ON_23000:-0}" = 1 ] || [ "${FLEET_WALLET_ON_23000:-0}" = "$host" ]; then
      printf 'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest qop="auth",realm="monero-rpc"\r\n\r\n'
    else
      printf 'HTTP/1.1 404 Not Found\r\n\r\n'
    fi ;;
  *23000*) printf '%s' "${FLEET_BTCPAY_CODE:-302}" ;;
  *23001*) printf '%s' "${FLEET_WALLET_PROXY_CODE:-401}" ;;
  *18083*) printf '401' ;;
esac
'''


class ProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        shims = {"systemctl": SYSTEMCTL, "docker": DOCKER, "iptables-save": SAVE, "ip6tables-save": SAVE6,
                 "curl": CURL, "id": "#!/bin/sh\necho 0\n", "sleep": "#!/bin/sh\n", "chmod": CHMOD}
        self.sb = lib.Sandbox(extra_shims=shims)
        self.root = self.sb.path("root")
        for d in ("etc/winsvpn", "etc/iptables", "etc/systemd/system", "usr/local/bin"):
            (self.root / d).mkdir(parents=True)
        edge = self.root / "usr/local/bin/wins-edge-hardening"
        edge.write_text(EDGE)
        edge.chmod(0o755)
        self.units = self.sb.path("units")
        self.units.mkdir()
        self.live = self.sb.path("live.rules")
        self.nfq = self.sb.path("nfq")
        # A converged, open data plane: Suricata bound, queue rules live.
        for unit in ("suricata.service", "wins-suricata-update.timer", "wins-suricata-nfq-watchdog.service",
                     "winn3-gateway.service", "nginx.service", "docker.service", "monero-wallet-rpc.service",
                     "wins-node-management-tunnel.service", "ssh.service", "wins-commerce-tunnel.service"):
            for suffix in ("known", "enabled", "active"):
                (self.units / f"{unit}.{suffix}").touch()
        (self.units / "container").write_text("true unless-stopped\n")
        self.nfq.write_text("0 1 0 2 65531 0 0 0 1\n")
        self.admission = self.root / "etc/winsvpn/public-vpn-ingress-admission.env"
        self.admission.write_text("PUBLIC_VPN_INGRESS_ADMISSION=1\n")
        self.admission.chmod(0o600)
        rules = "-A WINVPN-INPUT -p tcp --dport 8443 -j NFQUEUE --queue-num 0 --queue-bypass\n"
        self.live.write_text(rules)
        (self.root / "etc/iptables/rules.v4").write_text(rules)

    def tearDown(self) -> None:
        self.sb.cleanup()

    def run_profile(self, cmd: str, **env: str) -> subprocess.CompletedProcess:
        base = dict(WINS_PO_ROOT=str(self.root), WINS_PO_NFQ_PROC=str(self.nfq), FLEET_ROOT=str(self.root),
                    FLEET_UNITS=str(self.units), FLEET_LIVE=str(self.live), FLEET_NFQ=str(self.nfq),
                    WINS_PO_QUEUE_WAIT_SECONDS="3")
        base.update(env)
        return subprocess.run([lib.BASH, str(SCRIPT), cmd], capture_output=True, text=True, timeout=60,
                              env=self.sb.env(**base))

    def calls(self) -> list[str]:
        return self.sb.logged()

    def active(self, unit: str) -> bool:
        return (self.units / f"{unit}.active").exists()

    def assert_no_violation(self) -> None:
        self.assertFalse([c for c in self.calls() if c.startswith("VIOLATION")], self.calls())

    def test_apply_closes_the_queue_before_any_listener_stops(self) -> None:
        r = self.run_profile("apply")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assert_no_violation()
        calls = self.calls()
        edge = calls.index("edge admission=0 ids=0")
        for unit in ("wins-suricata-nfq-watchdog.service", "wins-suricata-update.timer", "suricata.service",
                     "winn3-gateway.service"):
            self.assertLess(edge, calls.index(f"systemctl disable --now {unit}"), unit)
        self.assertLess(calls.index("systemctl disable --now wins-suricata-nfq-watchdog.service"),
                        calls.index("systemctl disable --now suricata.service"))
        self.assertNotIn("NFQUEUE", self.live.read_text())
        self.assertNotIn("NFQUEUE", (self.root / "etc/iptables/rules.v4").read_text())
        self.assertEqual(self.admission.read_text(), "PUBLIC_VPN_INGRESS_ADMISSION=0\n")
        self.assertFalse(self.active("suricata.service"))
        self.assertFalse(self.active("winn3-gateway.service"))
        self.assertEqual((self.units / "container").read_text(), "false no\n")
        for unit in ("nginx.service", "monero-wallet-rpc.service", "wins-node-management-tunnel.service",
                     "wins-commerce-tunnel.service", "ssh.service", "docker.service"):
            self.assertTrue(self.active(unit), f"{unit} must not be touched")
        for unit in ("suricata.service", "winn3-gateway.service"):
            dropin = self.root / f"etc/systemd/system/{unit}.d/99-winsvpn-payment-only.conf"
            self.assertIn("ConditionPathExists=!/etc/winsvpn/payment-only.active", dropin.read_text())
        self.assertTrue((self.root / "etc/winsvpn/payment-only.active").exists())
        self.assertIn("the payment path answers", r.stdout)

    def test_a_started_gated_unit_stays_down(self) -> None:
        self.assertEqual(self.run_profile("apply").returncode, 0)
        subprocess.run([lib.BASH, "-c", "systemctl start suricata.service"], env=self.sb.env(
            FLEET_ROOT=str(self.root), FLEET_UNITS=str(self.units), FLEET_LIVE=str(self.live), FLEET_NFQ=str(self.nfq)))
        self.assertIn("gated suricata.service", self.calls())
        self.assertFalse(self.active("suricata.service"))

    def test_a_failed_rebuild_stops_nothing_and_restores_admission(self) -> None:
        r = self.run_profile("apply", FLEET_EDGE_FAILS="1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Suricata was not touched", r.stderr)
        self.assertTrue(self.active("suricata.service"))
        self.assertEqual(self.admission.read_text(), "PUBLIC_VPN_INGRESS_ADMISSION=1\n")
        self.assertFalse((self.root / "etc/winsvpn/payment-only.state").exists())
        self.assertIn("the admission file is restored", r.stderr)
        self.assertFalse((self.root / "etc/winsvpn/payment-only.active").exists())
        self.assertFalse(any(c.startswith("systemctl disable") for c in self.calls()))

    def test_a_queue_rule_left_behind_keeps_suricata_running(self) -> None:
        r = self.run_profile("apply", FLEET_EDGE_LEAVES_QUEUE="1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Suricata was NOT stopped", r.stderr)
        self.assertTrue(self.active("suricata.service"))
        self.assertFalse((self.root / "etc/winsvpn/payment-only.active").exists())
        self.assert_no_violation()

    def test_an_uncertified_edge_rebuild_is_refused(self) -> None:
        (self.root / "usr/local/bin/wins-edge-hardening").write_text("#!/bin/sh\napply_firewall\n")
        r = self.run_profile("apply")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Rerun the certified data-plane installer", r.stderr)
        self.assertTrue(self.active("suricata.service"))

    def test_a_broken_payment_path_is_reported(self) -> None:
        r = self.run_profile("apply", FLEET_BTCPAY_CODE="502")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("127.0.0.1:23000 (BTCPay) answered 502", r.stderr)
        self.assert_no_violation()

    def test_revert_binds_the_queue_before_admission_returns(self) -> None:
        self.assertEqual(self.run_profile("apply").returncode, 0)
        self.sb.calls.unlink()
        r = self.run_profile("revert")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assert_no_violation()
        calls = self.calls()
        self.assertLess(calls.index("systemctl start suricata.service"), calls.index("edge admission=1 ids=unset"))
        self.assertLess(calls.index("systemctl start winn3-gateway.service"), calls.index("edge admission=1 ids=unset"))
        self.assertIn("NFQUEUE", self.live.read_text())
        self.assertEqual(self.admission.read_text(), "PUBLIC_VPN_INGRESS_ADMISSION=1\n")
        for unit in ("suricata.service", "wins-suricata-update.timer", "wins-suricata-nfq-watchdog.service",
                     "winn3-gateway.service"):
            self.assertTrue(self.active(unit), unit)
            self.assertTrue((self.units / f"{unit}.enabled").exists(), unit)
        self.assertEqual((self.units / "container").read_text(), "true unless-stopped\n")
        for unit in ("suricata.service", "winn3-gateway.service"):
            self.assertFalse((self.root / f"etc/systemd/system/{unit}.d/99-winsvpn-payment-only.conf").exists())
        self.assertFalse((self.root / "etc/winsvpn/payment-only.state").exists())

    def test_revert_without_a_bound_queue_keeps_admission_closed(self) -> None:
        self.assertEqual(self.run_profile("apply").returncode, 0)
        r = self.run_profile("revert", FLEET_NOBIND="1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("did not bind NFQUEUE 0", r.stderr)
        self.assertEqual(self.admission.read_text(), "PUBLIC_VPN_INGRESS_ADMISSION=0\n")
        self.assertNotIn("NFQUEUE", self.live.read_text())
        self.assert_no_violation()

    def test_apply_is_idempotent_and_status_reports(self) -> None:
        self.assertEqual(self.run_profile("apply").returncode, 0)
        r = self.run_profile("apply")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("already active", r.stdout)
        state = (self.root / "etc/winsvpn/payment-only.state").read_text()
        self.assertIn("PRIOR_ADMISSION=1", state)
        self.assertIn("PRIOR_ACTIVE_suricata_service=active", state)
        self.assertIn("PRIOR_CONTAINER=true:unless-stopped", state)
        out = self.run_profile("status").stdout
        self.assertIn("active=yes", out)
        self.assertIn("admission=0", out)
        self.assertIn("nfqueue_rules=0", out)


    # --- FLEET1 Turn 2 (Astra item 3): queue proof fails closed, repeated
    # apply proves before it stops, rollbacks restore what was there. ---

    def stops(self) -> list[str]:
        return [c for c in self.calls() if c.startswith("systemctl disable")]

    def test_an_unreadable_firewall_is_never_zero_queue_rules(self) -> None:
        for env in ({"FLEET_SAVE_FAILS": "1"}, {"FLEET_SAVE6_FAILS": "1"}):
            with self.subTest(env=env):
                self.tearDown()
                self.setUp()
                r = self.run_profile("apply", **env)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn("queue absence is unverified", r.stderr)
                self.assertEqual(self.stops(), [])
                self.assertTrue(self.active("suricata.service"))
                self.assertFalse((self.root / "etc/winsvpn/payment-only.active").exists())
                self.assertIn("nfqueue_rules=unknown", self.run_profile("status", **env).stdout)

    def test_an_unreadable_saved_rules_file_is_never_zero(self) -> None:
        rules6 = self.root / "etc/iptables/rules.v6"
        rules6.mkdir()
        r = self.run_profile("apply")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Cannot read regular saved rules", r.stderr)
        self.assertEqual(self.stops(), [])

    def test_a_repeated_apply_refuses_drift_before_stopping_anything(self) -> None:
        self.assertEqual(self.run_profile("apply").returncode, 0)
        drifts = {
            "queue rule back": lambda: self.live.write_text("-A WINVPN-INPUT -j NFQUEUE --queue-num 0\n"),
            "admission reopened": lambda: self.admission.write_text("PUBLIC_VPN_INGRESS_ADMISSION=1\n"),
            "firewall unreadable": None,
            "state lost": lambda: (self.root / "etc/winsvpn/payment-only.state").unlink(),
        }
        for label, drift in drifts.items():
            with self.subTest(label=label):
                self.tearDown()
                self.setUp()
                self.assertEqual(self.run_profile("apply").returncode, 0)
                (self.units / "suricata.service.active").touch()  # something restarted it
                env = {}
                if drift is None:
                    env["FLEET_SAVE_FAILS"] = "1"
                else:
                    drift()
                self.sb.calls.unlink()
                r = self.run_profile("apply", **env)
                self.assertNotEqual(r.returncode, 0, label)
                self.assertIn("refusing to stop services", r.stderr)
                self.assertEqual(self.stops(), [], label)
                self.assertTrue(self.active("suricata.service"), label)

    def test_a_repeated_apply_reinstalls_missing_gates(self) -> None:
        self.assertEqual(self.run_profile("apply").returncode, 0)
        for unit in ("suricata.service", "winn3-gateway.service"):
            (self.root / f"etc/systemd/system/{unit}.d/99-winsvpn-payment-only.conf").unlink()
        r = self.run_profile("apply")
        self.assertEqual(r.returncode, 0, r.stderr)
        for unit in ("suricata.service", "winn3-gateway.service"):
            dropin = self.root / f"etc/systemd/system/{unit}.d/99-winsvpn-payment-only.conf"
            self.assertIn("ConditionPathExists=!/etc/winsvpn/payment-only.active", dropin.read_text())

    def test_a_failed_rebuild_restores_an_absent_admission_file_to_absence(self) -> None:
        self.admission.unlink()
        r = self.run_profile("apply", FLEET_EDGE_FAILS="1")
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(self.admission.exists())
        self.assertFalse((self.root / "etc/winsvpn/payment-only.state").exists())

    # --- FLEET1 Turn 3 (Astra): a failed restore keeps the recovery state. ---

    def test_a_failed_admission_restore_keeps_the_recorded_state(self) -> None:
        r = self.run_profile("apply", FLEET_EDGE_FAILS="1", FLEET_EDGE_SYMLINKS_ADMISSION="1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("could not be restored; the recorded state is kept", r.stderr)
        self.assertNotIn("the admission file is restored", r.stderr)
        state = self.root / "etc/winsvpn/payment-only.state"
        self.assertIn("PRIOR_ADMISSION=1", state.read_text())
        self.assertEqual(self.stops(), [])
        self.assertTrue(self.active("suricata.service"))
        self.assertFalse((self.root / "etc/winsvpn/payment-only.active").exists())
        # The owner repairs the file; revert still knows the admission was 1.
        self.admission.unlink()
        self.admission.write_text("PUBLIC_VPN_INGRESS_ADMISSION=0\n")
        r = self.run_profile("revert")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.admission.read_text(), "PUBLIC_VPN_INGRESS_ADMISSION=1\n")
        self.assertFalse(state.exists())
        self.assert_no_violation()

    def test_a_restore_whose_write_fails_is_not_reported_as_restored(self) -> None:
        # write_admission runs beneath a conditional here: every step of it
        # must fail the restore explicitly.
        r = self.run_profile("apply", FLEET_EDGE_FAILS="1", FLEET_EDGE_BREAKS_CHMOD="1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("could not be restored; the recorded state is kept", r.stderr)
        self.assertIn("PRIOR_ADMISSION=1", (self.root / "etc/winsvpn/payment-only.state").read_text())
        self.assertEqual(self.admission.read_text(), "PUBLIC_VPN_INGRESS_ADMISSION=0\n")
        self.assertEqual([x.name for x in (self.root / "etc/winsvpn").iterdir() if x.name.startswith(".public")], [],
                         "no temporary admission file is left")
        self.assertEqual(self.stops(), [])
        # A rerun of apply reuses the recorded admission, never the closed one.
        (self.root / ".chmod-fails").unlink()
        r = self.run_profile("apply")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("PRIOR_ADMISSION=1", (self.root / "etc/winsvpn/payment-only.state").read_text())

    def test_a_queue_rule_left_behind_keeps_state_and_revert_restores_admission(self) -> None:
        r = self.run_profile("apply", FLEET_EDGE_LEAVES_QUEUE="1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Admission stays 0 and the recorded state is kept", r.stderr)
        self.assertEqual(self.admission.read_text(), "PUBLIC_VPN_INGRESS_ADMISSION=0\n")
        self.assertTrue((self.root / "etc/winsvpn/payment-only.state").exists())
        r = self.run_profile("revert")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.admission.read_text(), "PUBLIC_VPN_INGRESS_ADMISSION=1\n")
        self.assertTrue(self.active("suricata.service"))
        self.assert_no_violation()

    def test_revert_restores_an_absent_admission_file_to_absence(self) -> None:
        self.admission.unlink()
        self.assertEqual(self.run_profile("apply").returncode, 0)
        self.assertEqual(self.admission.read_text(), "PUBLIC_VPN_INGRESS_ADMISSION=0\n")
        r = self.run_profile("revert")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse(self.admission.exists())

    # --- FLEET1 Turn 2 (Astra item 1): the wallet only on its own listener. ---

    def test_a_wallet_reachable_through_the_btcpay_listener_is_reported(self) -> None:
        r = self.run_profile("apply", FLEET_WALLET_ON_23000="1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("127.0.0.1:23000 (public BTCPay listener) reaches the wallet RPC", r.stderr)

    def test_a_wallet_reachable_under_any_one_host_is_reported(self) -> None:
        # Claude seat's surviving mutant: a probe that sends one Host only.
        for host in ("btcpay.winsvpn.org", "monero-rpc.winsvpn.org", "localhost"):
            with self.subTest(host=host):
                self.tearDown()
                self.setUp()
                r = self.run_profile("apply", FLEET_WALLET_ON_23000=host)
                self.assertNotEqual(r.returncode, 0, host)
                self.assertIn("127.0.0.1:23000 (public BTCPay listener) reaches the wallet RPC", r.stderr)
        self.tearDown()
        self.setUp()
        r = self.run_profile("apply", FLEET_WALLET_ON_23000="other.example")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_the_wallet_listener_must_answer_with_the_digest_challenge(self) -> None:
        r = self.run_profile("apply", FLEET_WALLET_PROXY_CODE="404")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("127.0.0.1:23001 (wallet RPC) answered 404", r.stderr)


if __name__ == "__main__":
    unittest.main()
