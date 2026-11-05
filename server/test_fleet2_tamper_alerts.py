"""FLEET2 tamper alerts (2026-10-10): the shipped collector, checker, units,
installer functions and external watcher setup, run from the installers'
own heredocs and functions in a sandbox. Nothing here touches the host's
systemd, /etc, /var or the network; SMTP is replaced by a recorder."""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import os
import re
import shutil
import smtplib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fleet_reset_testlib as lib  # noqa: E402

CP = lib.installer("WINS_FLEET_CP_INSTALLER", "server/wins_control_plane_setup_ONETOUCH.sh")
DP = lib.installer("WINS_FLEET_DP_INSTALLER", "server/wins_data_plane_setup_ONETOUCH.sh")
WATCH = lib.ROOT / "server" / "wins_hub_watch_setup.sh"
SRC = CP.read_text(encoding="utf-8")
DSRC = DP.read_text(encoding="utf-8")
COLLECT_SRC = lib.heredoc(SRC, "install_generated_file 0644 /usr/local/lib/wins-attest-collect.py <<'ATTESTCOLLECTEOF'", "ATTESTCOLLECTEOF")
ATTEST_SRC = lib.heredoc(SRC, "install_generated_file 0700 /usr/local/sbin/wins-fleet-attest <<'FLEETATTESTEOF'", "FLEETATTESTEOF")
ED_PUB = "AAAAC3NzaC1lZDI1NTE5AAAAIPwqdSfIQ0k6ypaXwqDdTU8BAkZNWaDiQcc9HZhwqRmZ"
NONCE = "0123456789abcdef0123456789abcdef"


def load(name: str, text: str, tmp: Path):
    path = tmp / (name + ".py")
    path.write_text(text)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def between(start: str, end: str) -> str:
    """The installer text from start up to end (functions with Python
    here-documents hold column-0 braces, so function_text cannot cut them)."""
    i = SRC.index(start)
    return SRC[i:SRC.index(end, i)]


def fp(blob: str) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(blob)).digest()).decode().rstrip("=")


SHIM_SSHD = """#!/bin/sh
printf 'port 22\\npermitrootlogin prohibit-password\\npasswordauthentication no\\nauthorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2\\n'
"""
SHIM_JOURNAL = r"""#!/usr/bin/env python3
import json
for ident, msg in [
    ("sshd", "Accepted publickey for root from 203.0.113.9 port 50122 ssh2: ED25519 SHA256:abcHUBKEY"),
    ("sshd", "Accepted password for root from 198.51.100.7 port 4022 ssh2"),
    ("login", "pam_unix(login:session): session opened for user root(uid=0) by LOGIN(uid=0)"),
    ("login", "ROOT LOGIN ON tty1"),
    ("sudo", "  alice : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/id"),
]:
    print(json.dumps({"SYSLOG_IDENTIFIER": ident, "MESSAGE": msg}))
"""
SHIM_SYSTEMCTL = """#!/bin/sh
case "$2" in qemu-guest-agent.service) echo active ;; *) echo inactive; exit 3 ;; esac
"""


class CollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="f2c-"))
        self.mod = load("collect", COLLECT_SRC, self.tmp)
        r = self.tmp / "root"
        files = {
            "etc/passwd": "root:x:0:0:root:/root:/bin/bash\nsvc:x:998:998::/var/lib/svc:/usr/sbin/nologin\n",
            "etc/shadow": "root:$y$j9T$saltsalt$hashhashhash:20000:0:99999:7:::\nsvc:!:19000::::::\n",
            "etc/group": "root:x:0:\n",
            "root/.ssh/authorized_keys": "# owner\nssh-ed25519 %s owner@mac\nrestrict,command=\"/x y\" ssh-ed25519 %s hub\nnot a key line\n" % (ED_PUB, ED_PUB),
            "var/lib/svc/.ssh/authorized_keys2": "ssh-ed25519 %s planted\n" % ED_PUB,
            "etc/ssh/sshd_config": "Port 22\n",
            "etc/ssh/ssh_host_ed25519_key.pub": "ssh-ed25519 %s host\n" % ED_PUB,
            "boot/vmlinuz-6.8.0-1": "kernel", "boot/initrd.img-6.8.0-1": "initrd",
            "proc/sys/kernel/random/boot_id": "11111111-2222-3333-4444-555555555555\n",
            "proc/uptime": "3600.5 100.0\n", "proc/stat": "cpu 1 2 3\nbtime 1760000000\n",
            "proc/cmdline": "BOOT_IMAGE=/vmlinuz root=/dev/sda1\n",
            "var/lib/dpkg/status": "Package: linux-image-6.8.0-1\nStatus: install ok installed\nVersion: 6.8.0-1.1\n\nPackage: vim\nStatus: install ok installed\nVersion: 9\n",
        }
        for rel, text in files.items():
            (r / rel).parent.mkdir(parents=True, exist_ok=True)
            (r / rel).write_text(text)
        (r / "etc/systemd/system").mkdir(parents=True)
        os.symlink("/dev/null", r / "etc/systemd/system/wins-security-alert-monitor.timer")
        self.root = r
        shims = self.tmp / "bin"
        shims.mkdir()
        for name, body in (("sshd", SHIM_SSHD), ("journalctl", SHIM_JOURNAL), ("systemctl", SHIM_SYSTEMCTL)):
            (shims / name).write_text(body)
            (shims / name).chmod(0o755)
        self.mod.SAFE_PATH = "%s:/usr/bin:/bin" % shims

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_snapshot_carries_states_and_fingerprints_never_secrets_or_addresses(self) -> None:
        obs = self.mod.Collector(str(self.root)).collect(NONCE)
        text = json.dumps(obs)
        for secret in ("hashhashhash", "saltsalt", "$y$", "203.0.113.9", "198.51.100.7", "50122", ED_PUB, "/x y"):
            self.assertNotIn(secret, text)
        accounts = {a["name"]: a for a in obs["accounts"]}
        self.assertEqual((accounts["root"]["pw"], accounts["svc"]["pw"]), ("usable", "locked"))
        self.assertEqual(len(accounts["root"]["pwtag"]), 16)
        root_keys = obs["authorized_keys"]["root"]["/root/.ssh/authorized_keys"]
        self.assertEqual([k["fp"] for k in root_keys["keys"]], [fp(ED_PUB)] * 2)
        self.assertEqual(sum(1 for k in root_keys["keys"] if "opts" in k), 1)
        self.assertEqual(root_keys["unparsed"], 1)
        # A key planted for a system account in authorized_keys2 is reported.
        self.assertIn("/var/lib/svc/.ssh/authorized_keys2", obs["authorized_keys"]["svc"])
        self.assertEqual(obs["logins"]["console"], {"root": 1})
        self.assertEqual(obs["logins"]["ttys"], ["tty1"])
        self.assertEqual(obs["logins"]["ssh"], {"root publickey SHA256:abcHUBKEY": 1, "root password -": 1})
        self.assertEqual(obs["logins"]["sudo"], {"alice": 1})
        self.assertEqual(obs["agents"], {"qemu-guest-agent.service": "active"})
        self.assertEqual(obs["boot_pkgs"], ["linux-image-6.8.0-1=6.8.0-1.1"])
        self.assertEqual((obs["boot_id"][:8], obs["btime"], obs["uptime"]), ("11111111", 1760000000, 3600.5))
        self.assertEqual(obs["files"]["persistence"]["/etc/systemd/system/wins-security-alert-monitor.timer"], "link:/dev/null")
        self.assertEqual(obs["sshd"]["auth"]["permitrootlogin"], "prohibit-password")
        self.assertEqual(obs["sshd"]["auth"]["authorizedkeysfile"], ".ssh/authorized_keys .ssh/authorized_keys2")
        self.assertEqual(obs["sshd"]["fields"], {"port": "22"})
        self.assertEqual(obs["sshd"]["digest"], hashlib.sha256(b"port 22").hexdigest())   # the auth lines are not in it
        self.assertEqual(obs["nonce"], NONCE)
        self.assertEqual(obs["rescue"], [])

    def test_a_custom_authorized_keys_file_is_read_from_the_auth_section(self) -> None:
        # Turn 3: AuthorizedKeysFile moved to sshd.auth with the ssh_auth split;
        # the key inventory must follow it there, or a key at a custom path
        # (here /etc/ssh/authorized_keys.d/%u) would never be fingerprinted.
        (self.tmp / "bin/sshd").write_text("#!/bin/sh\nprintf 'port 22\\nauthorizedkeysfile /etc/ssh/authorized_keys.d/%%u\\n'\n")
        keyfile = self.root / "etc/ssh/authorized_keys.d/root"
        keyfile.parent.mkdir(parents=True)
        keyfile.write_text("ssh-ed25519 %s planted-custom\n" % ED_PUB)
        obs = self.mod.Collector(str(self.root)).collect(NONCE)
        self.assertEqual(obs["sshd"]["auth"]["authorizedkeysfile"], "/etc/ssh/authorized_keys.d/%u")
        self.assertEqual(obs["authorized_keys"]["root"]["/etc/ssh/authorized_keys.d/root"]["keys"],
                         [{"type": "ssh-ed25519", "fp": fp(ED_PUB)}])

    def test_the_sshd_digest_moves_only_with_non_auth_lines(self) -> None:
        # Turn 3: ssh and ssh_auth never overlap. An auth line (here
        # AuthorizedKeysCommand) changes sshd.auth and nothing else; any other
        # line (Ciphers) changes only the digest. So acking one kind can leave
        # nothing behind for the other.
        default = self.mod.Collector(str(self.root)).collect(NONCE)["sshd"]
        (self.tmp / "bin/sshd").write_text(SHIM_SSHD.replace("\\n'\n", "\\nauthorizedkeyscommand /usr/local/bin/evil\\n'\n"))
        auth_only = self.mod.Collector(str(self.root)).collect(NONCE)["sshd"]
        self.assertEqual(auth_only["auth"]["authorizedkeyscommand"], "/usr/local/bin/evil")
        self.assertEqual((auth_only["digest"], auth_only["fields"]), (default["digest"], default["fields"]))
        (self.tmp / "bin/sshd").write_text(SHIM_SSHD.replace("\\n'\n", "\\nciphers aes128-ctr\\n'\n"))
        other = self.mod.Collector(str(self.root)).collect(NONCE)["sshd"]
        self.assertNotEqual(other["digest"], default["digest"])
        self.assertEqual((other["auth"], other["fields"]), (default["auth"], default["fields"]))

    def test_rescue_markers_name_the_marker_never_the_command_line(self) -> None:
        (self.root / "proc/cmdline").write_text("BOOT_IMAGE=/vmlinuz root=UUID=abcd-secretish ro init=/tmp/evil-init single systemd.unit=rescue.target\n")
        obs = self.mod.Collector(str(self.root)).collect(NONCE)
        self.assertEqual(obs["rescue"], ["init=", "single", "systemd.unit=rescue"])
        self.assertNotIn("evil-init", json.dumps(obs))
        self.assertNotIn("abcd-secretish", json.dumps(obs))

    def test_fingerprint_matches_ssh_keygen(self) -> None:
        keygen = shutil.which("ssh-keygen")
        if not keygen:
            self.skipTest("ssh-keygen not installed")
        pub = self.tmp / "k.pub"
        pub.write_text("ssh-ed25519 %s x\n" % ED_PUB)
        out = subprocess.run([keygen, "-l", "-E", "sha256", "-f", str(pub)], capture_output=True, text=True).stdout
        self.assertIn(self.mod.Collector.fingerprint(ED_PUB), out)

    def test_main_refuses_a_bad_nonce_and_runs_from_stdin(self) -> None:
        bad = subprocess.run([sys.executable, "-I", "-", "nonce; rm -rf /"], input=COLLECT_SRC, capture_output=True, text=True)
        self.assertEqual(bad.returncode, 2)
        self.assertEqual(bad.stdout, "")


def base_obs(**over):
    obs = {
        "v": 1, "nonce": NONCE, "now": 1_760_000_000.0, "boot_id": "aaaaaaaa-1", "btime": 1_759_990_000,
        "uptime": 10000.0, "kernel": "6.8.0-1", "cmdline_sha256": "c" * 64,
        "files": {"accounts": {"/etc/shadow": "s1", "/etc/passwd": "p1"}, "sudo": {"/etc/sudoers": "x"},
                  "pam": {"/etc/pam.d/sshd": "y"}, "ssh": {"/etc/ssh/sshd_config": "z"},
                  "hostkeys": {"/etc/ssh/ssh_host_ed25519_key.pub": "h"},
                  "boot": {"/boot/vmlinuz-6.8.0-1": "k1", "/boot/initrd.img-6.8.0-1": "i1"},
                  "persistence": {"/etc/crontab": "c"}},
        "accounts": [{"name": "root", "uid": "0", "gid": "0", "home": "/root", "shell": "/bin/bash",
                      "pw": "locked", "pwtag": "t" * 16, "lastchg": "20000"}],
        "sshd": {"digest": "d1", "fields": {"port": "22"},
                 "auth": {"permitrootlogin": "prohibit-password", "passwordauthentication": "no"}},
        "authorized_keys": {"root": {"/root/.ssh/authorized_keys": {"digest": "a", "unparsed": 0,
                                                                     "keys": [{"type": "ssh-ed25519", "fp": "SHA256:HUB"}]}}},
        "boot_pkgs": ["linux-image-6.8.0-1=1"], "agents": {}, "errors": [],
        "logins": {"state": "ok", "console": {}, "console_failed": 0, "ttys": [], "ssh": {"root publickey SHA256:HUB": 3},
                   "ssh_failed": 0, "su": 0, "sudo": {}},
    }
    obs.update(over)
    return obs


class CheckerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="f2a-"))
        self.mod = load("attest", ATTEST_SRC, self.tmp)
        env = self.tmp / "env"
        env.write_text("SMTP_USER='u'\nSMTP_PASS='p'\"'\"'q'\nEMAIL_SENDER='support@winsvpn.org'\n"
                       "SECURITY_ALERT_EMAIL='security@winsvpn.com'\n")
        self.state = self.tmp / "state"
        self.sent = []
        self.fail_mail = False
        self.reject = {}            # X-Wins-Alert-Seq -> the exception the SMTP server raises for it
        self.app = self.make("hub")
        self.clock = 1_760_000_000.0

    def make(self, role):
        app = self.mod.Attest(role, str(self.state), str(self.tmp / "env"), collector="/nonexistent")

        def send(msg):
            if self.fail_mail:
                raise OSError("smtp down")
            if msg["X-Wins-Alert-Seq"] in self.reject:
                raise self.reject[msg["X-Wins-Alert-Seq"]]
            self.sent.append(msg)
        app.smtp_send = send
        return app

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def step(self, obs=None, failure=None, name="de-1", dt=120, heartbeat=None, role="hub"):
        """One checker run for one target at clock + dt; returns the mails it sent."""
        self.clock += dt
        app = self.make(role)
        app.now = self.clock
        before = len(self.sent)
        target = {"name": name}
        if heartbeat is not None:
            target["heartbeat"] = heartbeat
        if obs is not None:
            obs = copy.deepcopy(obs)
            obs["now"] = self.clock
        app.evaluate(target, obs, failure)
        app.log()
        app.queue_alerts()
        app.flush()
        self.app = app
        return [m["Subject"] + "\n" + m.get_content() for m in self.sent[before:]]

    def open_kinds(self, name="de-1"):
        return sorted(json.loads((self.state / "targets" / (name + ".json")).read_text())["open"])

    def test_hub_targets_are_the_non_retired_nodes_plus_itself(self) -> None:
        import sqlite3
        db = self.tmp / "vpn_users.db"
        conn = sqlite3.connect(db)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("CREATE TABLE nodes (slug TEXT PRIMARY KEY, ssh_host TEXT, last_heartbeat TEXT, retired_at TEXT, node_token_hash TEXT)")
        conn.executemany("INSERT INTO nodes VALUES (?, ?, ?, ?, 'secret')", [
            ("de-1", "de-1-mgmt.example.test", "2026-10-10T10:00:00", None),
            ("sg-1", "sg-1-mgmt.example.test", None, "2026-10-08T00:00:00"),
            ("hub", "x", None, None), ("Bad Slug", "y", None, None)])
        conn.commit()
        (self.tmp / "env").write_text("DATABASE_PATH='%s'\n" % db)
        app = self.make("hub")
        targets = app.targets()
        conn.close()
        self.assertEqual([t["name"] for t in targets], ["hub", "de-1"])
        self.assertTrue(targets[0]["local"])
        self.assertEqual(targets[1]["known_hosts"], str(self.tmp / "managed_known_hosts"))
        self.assertEqual(targets[1]["heartbeat"], "2026-10-10T10:00:00")
        self.assertNotIn("secret", json.dumps(targets))

    def test_env_values_are_unquoted_like_write_env_kv(self) -> None:
        self.assertEqual(self.app.env["SMTP_PASS"], "p'q")

    def test_first_run_records_a_baseline_and_mails_it(self) -> None:
        mails = self.step(base_obs())
        self.assertEqual(len(mails), 1)
        self.assertIn("baseline recorded", mails[0])
        self.assertIn("[Wins VPN Tamper P2]", mails[0])
        self.assertEqual(self.step(base_obs()), [])

    def test_a_changed_root_password_is_p1_and_reminds_until_acked(self) -> None:
        self.step(base_obs())
        changed = base_obs()
        changed["accounts"] = [dict(changed["accounts"][0], pw="usable", pwtag="u" * 16, lastchg="20371")]
        changed["files"]["accounts"]["/etc/shadow"] = "s2"
        mails = self.step(changed)
        self.assertEqual(len(mails), 1)
        self.assertIn("[Wins VPN Tamper P1]", mails[0])
        self.assertIn("password of root changed (locked -> usable; shadow last-change day 20000 -> 20371)", mails[0])
        self.assertNotIn("uuuu", mails[0])
        self.assertEqual(self.step(changed), [])           # no repeat inside 6 h
        later = self.step(changed, dt=6 * 3600)
        self.assertEqual(len(later), 1)
        self.assertIn("STILL OPEN since", later[0])
        self.assertIn("credentials", self.open_kinds())

    def test_a_reverted_change_closes_without_mail(self) -> None:
        self.step(base_obs())
        changed = base_obs()
        changed["authorized_keys"]["root"]["/root/.ssh/authorized_keys"]["keys"].append({"type": "ssh-ed25519", "fp": "SHA256:EVIL"})
        self.assertIn("key added for root in /root/.ssh/authorized_keys: ssh-ed25519 SHA256:EVIL", self.step(changed)[0])
        self.assertEqual(self.step(base_obs()), [])
        self.assertEqual(self.open_kinds(), [])

    def test_reboot_console_login_and_unknown_key_login_alert(self) -> None:
        self.step(base_obs())
        rebooted = base_obs(boot_id="bbbbbbbb-2", btime=int(self.clock) + 60, uptime=30.0)
        rebooted["logins"] = dict(rebooted["logins"], console={"root": 1}, ttys=["tty1"],
                                  ssh={"root publickey SHA256:HUB": 1, "root publickey SHA256:EVIL": 1})
        mail = self.step(rebooted)[0]
        self.assertIn("rebooted: boot aaaaaaaa -> bbbbbbbb", mail)
        self.assertIn("console login as root (1 new; ttys tty1)", mail)
        self.assertIn("SSH login as root by publickey SHA256:EVIL (1), not a key in the accepted set", mail)
        self.assertNotIn("SHA256:HUB (", mail)            # the hub's own key is known
        self.assertEqual(self.step(rebooted), [])         # counts are per boot; nothing new

    def test_forged_boot_identity_and_nonce_are_flagged(self) -> None:
        self.step(base_obs())
        forged = base_obs(boot_id="cccccccc-3", btime=int(self.clock) - 4000)
        self.assertIn("report may be forged", self.step(forged)[0])
        replay = base_obs(boot_id="cccccccc-3", btime=int(self.clock) - 4000)
        replay["_nonce_mismatch"] = True
        self.assertIn("did not echo this run's nonce", self.step(replay)[0])

    def test_unreachable_is_p2_at_two_misses_p1_at_five_and_recovery_is_mailed(self) -> None:
        self.step(base_obs())
        down = ("unreachable", "timed out")
        self.assertEqual(self.step(failure=down), [])
        mails = self.step(failure=down)
        self.assertIn("[Wins VPN Tamper P2]", mails[0])
        self.assertIn("off-host check failed 2 times in a row (timed out)", mails[0])
        self.assertEqual(self.step(failure=down), [])
        self.assertEqual(self.step(failure=down), [])
        mails = self.step(failure=down)
        self.assertIn("[Wins VPN Tamper P1]", mails[0])
        self.assertIn("failed 5 times in a row", mails[0])
        self.assertEqual(self.step(failure=down), [])
        self.assertIn("reachable again; the outage lasted about 14m", self.step(base_obs())[0])

    def test_a_changed_host_key_is_p1_at_once(self) -> None:
        self.step(base_obs())
        mail = self.step(failure=("hostkey_mismatch", "the SSH host key no longer matches the pinned key"))[0]
        self.assertIn("[Wins VPN Tamper P1]", mail)
        self.assertIn("hostkey_mismatch", mail)

    def test_stale_heartbeat_is_reported_once(self) -> None:
        self.step(base_obs())
        mail = self.step(base_obs(), heartbeat="2025-10-09T08:00:00")
        self.assertIn("no heartbeat since 2025-10-09 08:00:00Z", mail[0])
        self.assertEqual(self.step(base_obs(), heartbeat="2025-10-09T08:00:00"), [])
        # Dark both ways: P2 (the unreachable finding carries the P1).
        mail = self.step(failure=("unreachable", "timed out"), heartbeat="2025-10-09T08:00:00")
        self.assertIn("[Wins VPN Tamper P2]", mail[0])

    def test_window_covers_a_planned_reboot_but_never_credentials(self) -> None:
        self.step(base_obs())
        self.app.cmd_window("de-1", 60, ["reboot", "boot"], "kernel update", False)
        self.assertIn("maintenance window opened for 60 min (kernel update)", self.sent[-1].get_content())
        rebooted = base_obs(boot_id="bbbbbbbb-2", btime=int(self.clock) + 60, kernel="6.8.0-2")
        rebooted["files"]["boot"]["/boot/vmlinuz-6.8.0-2"] = "k2"
        self.assertEqual(self.step(rebooted), [])         # logged only
        sneaky = copy.deepcopy(rebooted)
        sneaky["accounts"] = [dict(sneaky["accounts"][0], pw="usable", pwtag="u" * 16)]
        mail = self.step(sneaky)[0]
        self.assertIn("password of root changed", mail)
        self.assertNotIn("rebooted", mail)
        # The window ends: the baseline is NOT advanced while credentials are open.
        closing = self.step(sneaky, dt=3600)
        self.assertTrue(any("the baseline was NOT advanced" in m for m in closing))
        self.assertIn("boot", self.open_kinds())
        self.assertIn("credentials", self.open_kinds())

    def test_window_close_accepts_only_its_kinds(self) -> None:
        self.step(base_obs())
        self.app.cmd_window("de-1", 30, ["reboot", "boot"], "kernel update", False)
        rebooted = base_obs(boot_id="bbbbbbbb-2", btime=int(self.clock) + 60, kernel="6.8.0-2")
        self.step(rebooted)
        mails = self.step(rebooted, dt=1800)
        self.assertTrue(any("accepted into the baseline: boot: kernel: 6.8.0-1 -> 6.8.0-2" in m for m in mails))
        self.assertEqual(self.open_kinds(), [])
        self.assertEqual(self.step(rebooted), [])

    def test_a_rescue_boot_is_p1_even_inside_a_window(self) -> None:
        self.step(base_obs())
        self.app.cmd_window("de-1", 60, ["reboot", "boot"], "planned", False)
        rescued = base_obs(boot_id="dddddddd-4", btime=int(self.clock) + 60, rescue=["init=", "single"])
        mail = self.step(rescued)[0]
        self.assertIn("[Wins VPN Tamper P1]", mail)
        self.assertIn("rescue or single-user markers: init=, single", mail)
        self.assertNotIn("rescue_boot", self.mod.WINDOWABLE)
        self.assertEqual(self.step(rescued), [])
        normal = base_obs(boot_id="eeeeeeee-5", btime=int(self.clock) + 60)
        self.step(normal, dt=3600)
        self.assertNotIn("rescue_boot", self.open_kinds())

    def test_a_stopped_heartbeat_on_a_reachable_node_is_p1(self) -> None:
        self.step(base_obs())
        mail = self.step(base_obs(), heartbeat="2025-10-09T08:00:00")[0]
        self.assertIn("[Wins VPN Tamper P1]", mail)
        self.assertIn("still reaches it: its heartbeat agent was stopped", mail)

    def test_window_and_ack_kinds_are_validated(self) -> None:
        self.assertNotIn("credentials", self.mod.WINDOWABLE)
        self.assertNotIn("keys", self.mod.WINDOWABLE)
        self.assertNotIn("console_login", self.mod.WINDOWABLE)
        self.assertNotIn("ssh_login", self.mod.WINDOWABLE)
        self.assertNotIn("hostkey_mismatch", self.mod.WINDOWABLE)
        self.assertNotIn("hostkeys", self.mod.WINDOWABLE)
        self.assertNotIn("ssh_auth", self.mod.WINDOWABLE)
        self.assertIn("ssh", self.mod.WINDOWABLE)
        # The CLI refuses a never-windowable kind BY NAME, before its root
        # gate: a refusal that only said "runs as root only" would prove
        # nothing about the kinds check from an unprivileged test.
        for kind in ("credentials", "ssh_auth"):
            r = subprocess.run([sys.executable, str(self.tmp / "attest.py"), "--role", "hub", "window", "de-1",
                                "--minutes", "30", "--kinds", kind, "--reason", "x"], capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("never windowable: %s" % kind, r.stderr)
            self.assertNotIn("runs as root only", r.stderr)
        r = subprocess.run([sys.executable, str(self.tmp / "attest.py"), "--role", "hub", "window", "de-1",
                            "--minutes", "30", "--kinds", "reboot", "--reason", "x"], capture_output=True, text=True)
        if os.geteuid() != 0:
            self.assertIn("runs as root only", r.stderr)      # the kinds passed; only the root gate stopped it

    def test_an_sshd_auth_change_is_p1_inside_an_ssh_window_and_blocks_its_close(self) -> None:
        self.step(base_obs())
        self.app.cmd_window("de-1", 30, ["ssh"], "sshd drop-in rewrite", False)
        planted = base_obs()
        planted["sshd"]["auth"]["authorizedkeyscommand"] = "/usr/local/bin/evil"   # an auth line never moves the digest
        planted["files"]["ssh"]["/etc/ssh/sshd_config.d/99-x.conf"] = "e1"
        mails = self.step(planted)
        self.assertEqual(len(mails), 1)
        self.assertIn("[Wins VPN Tamper P1]", mails[0])
        self.assertIn("sshd authorizedkeyscommand: (unset) -> /usr/local/bin/evil", mails[0])
        self.assertNotIn("99-x.conf", mails[0])                 # the windowed ssh finding is logged only
        self.assertNotIn("sshd effective configuration changed", mails[0])
        # The ssh kind names only the drop-in; the digest item is never doubled
        # onto an auth change that already names its field.
        self.assertEqual(self.mod.cmp_ssh(base_obs(), planted), ["added: /etc/ssh/sshd_config.d/99-x.conf"])
        self.assertEqual(self.mod.cmp_ssh_auth(base_obs(), planted), ["sshd authorizedkeyscommand: (unset) -> /usr/local/bin/evil"])
        both = copy.deepcopy(planted)
        both["sshd"]["digest"] = "d2"                              # a non-auth line changed in the same edit
        self.assertEqual(self.mod.cmp_ssh(base_obs(), both),
                         ["sshd effective configuration changed (sshd -T)", "added: /etc/ssh/sshd_config.d/99-x.conf"])
        self.assertEqual(self.open_kinds(), ["ssh", "ssh_auth"])
        closing = self.step(planted, dt=1800)
        self.assertTrue(any("the baseline was NOT advanced" in m for m in closing))
        self.assertIn("ssh_auth", self.open_kinds())
        # An ack of the windowable ssh kind accepts the drop-in and nothing else.
        app = self.make("hub")
        app.now = self.clock + 10
        app.targets = lambda: [{"name": "de-1"}]
        app.collect = lambda t: (copy.deepcopy(planted), None)
        app.cmd_ack("de-1", "the drop-in rewrite was ours", ["ssh"])
        self.assertEqual(self.open_kinds(), ["ssh_auth"])
        self.assertNotIn("authorizedkeyscommand", self.sent[-1].get_content())
        app.cmd_ack("de-1", "the command is ours after all", ["ssh_auth"])
        self.assertIn("sshd authorizedkeyscommand: (unset) -> /usr/local/bin/evil", self.sent[-1].get_content())
        self.assertEqual(self.open_kinds(), [])
        self.assertEqual(self.step(planted), [])

    def test_a_non_auth_sshd_change_beside_an_auth_change_is_named_at_once(self) -> None:
        # Turn 3: the digest excludes the auth lines, so a Ciphers change made
        # in the same edit as an AuthorizedKeysCommand is named in the same
        # run (P1 ssh beside P1 ssh_auth), never after the ssh_auth ack, and
        # an ack of ssh_auth alone leaves no digest finding behind.
        self.step(base_obs())
        planted = base_obs()
        planted["sshd"]["auth"]["authorizedkeyscommand"] = "/usr/local/bin/evil"
        planted["sshd"]["digest"] = "d2"
        mail = self.step(planted)[0]
        self.assertIn("sshd authorizedkeyscommand: (unset) -> /usr/local/bin/evil", mail)
        self.assertIn("sshd effective configuration changed (sshd -T)", mail)
        self.assertEqual(self.open_kinds(), ["ssh", "ssh_auth"])
        app = self.make("hub")
        app.now = self.clock + 10
        app.targets = lambda: [{"name": "de-1"}]
        app.collect = lambda t: (copy.deepcopy(planted), None)
        app.cmd_ack("de-1", "the command is ours", ["ssh_auth"])
        self.assertEqual(self.open_kinds(), ["ssh"])
        self.assertEqual(self.step(planted), [])                   # no second P1 for the same change
        app.cmd_ack("de-1", "the cipher change is ours too", ["ssh"])
        self.assertEqual(self.open_kinds(), [])
        self.assertEqual(self.step(planted), [])

    def test_ack_accepts_the_current_state_and_mails_a_notice(self) -> None:
        self.step(base_obs())
        changed = base_obs()
        changed["authorized_keys"]["root"]["/root/.ssh/authorized_keys"]["keys"].append({"type": "ssh-ed25519", "fp": "SHA256:OWNER2"})
        self.step(changed)
        app = self.make("hub")
        app.now = self.clock + 10
        app.targets = lambda: [{"name": "de-1"}]
        app.collect = lambda t: (copy.deepcopy(changed), None)
        app.cmd_ack("de-1", "owner added a laptop key", [])
        notice = self.sent[-1].get_content()
        self.assertIn("operator accepted the current state (owner added a laptop key)", notice)
        self.assertIn("SHA256:OWNER2", notice)
        self.assertEqual(self.open_kinds(), [])
        self.assertEqual(self.step(changed), [])

    def test_an_explained_boot_update_is_absorbed_and_a_later_change_is_not(self) -> None:
        self.step(base_obs())
        updated = base_obs(boot_pkgs=["linux-image-6.8.0-2=1"])
        updated["files"]["boot"]["/boot/vmlinuz-6.8.0-2"] = "k2"
        self.assertEqual(self.step(updated), [])
        tampered = copy.deepcopy(updated)
        tampered["files"]["boot"]["/boot/initrd.img-6.8.0-1"] = "evil"
        mail = self.step(tampered)[0]
        self.assertIn("[Wins VPN Tamper P1]", mail)
        self.assertIn("changed: /boot/initrd.img-6.8.0-1", mail)

    def test_a_hostile_report_cannot_stop_other_targets_or_inject_lines(self) -> None:
        app = self.make("hub")
        app.now = self.clock
        bad = base_obs(accounts="not a list")
        hostile = base_obs()
        hostile["files"]["pam"]["/etc/pam.d/x\nSubject: all clear"] = "1"
        app.targets = lambda: [{"name": "evil"}, {"name": "de-1"}]
        results = {"evil": (bad, None), "de-1": (base_obs(), None)}
        app.collect = lambda t: results[t["name"]]
        app.cmd_run()
        app2 = self.make("hub")
        app2.now = self.clock + 120
        app2.targets = lambda: [{"name": "de-1"}]
        app2.collect = lambda t: (copy.deepcopy(hostile), None)
        app2.cmd_run()
        text = self.sent[-1].get_content()
        self.assertIn("added: /etc/pam.d/x?Subject: all clear", text)
        self.assertNotIn("\nSubject: all clear", text)
        first = self.sent[0].get_content()
        self.assertIn("evil", first)
        self.assertIn("de-1", first)

    def test_failed_mail_stays_queued_and_sequence_numbers_have_no_gap(self) -> None:
        self.fail_mail = True
        self.step(base_obs())
        self.assertEqual(len(list((self.state / "outbox").iterdir())), 1)
        status = json.loads((self.state / "mail.json").read_text())
        self.assertEqual(status["error"], "OSError")
        self.fail_mail = False
        changed = base_obs(boot_id="bbbbbbbb-2", btime=int(self.clock) + 300)
        mails = self.step(changed)
        self.assertEqual(len(mails), 2)
        self.assertIn("baseline recorded", mails[0])
        self.assertEqual([m.split("(sequence ")[1][:5] for m in mails], ["hub-1", "hub-2"])
        self.assertEqual(list((self.state / "outbox").iterdir()), [])
        msg = self.sent[-1]
        self.assertEqual(msg["Auto-Submitted"], "auto-generated")
        self.assertEqual(msg["To"], "security@winsvpn.com")

    def test_a_message_rejected_for_good_does_not_block_the_newer_ones(self) -> None:
        # Turn 3: a 5xx the server gives for THIS message (after DATA, or every
        # recipient refused) leaves it in place, tried again every 6 h, and the
        # newer messages behind it still go out; a 4xx, a connection failure
        # or an account failure still blocks the queue as before. Nothing is
        # ever deleted unsent. Turn 4: it stops holding the queue only once a
        # newer message is delivered after its refusal (then it is parked and
        # one fixed-text notice is queued), and the three refusals that make
        # it rest for 6 h count once it is parked.
        self.step(base_obs())                                      # hub-1 delivered
        self.reject = {"hub-2": smtplib.SMTPDataError(554, b"5.7.1 message rejected")}
        changed = base_obs()
        changed["authorized_keys"]["root"]["/root/.ssh/authorized_keys"]["keys"].append({"type": "ssh-ed25519", "fp": "SHA256:EVIL"})
        self.assertEqual(self.step(changed), [])                   # hub-2, the key alert, was refused and kept
        self.assertEqual(json.loads((self.state / "mail.json").read_text())["error"], "SMTPDataError")
        everything = lambda: [json.loads(p.read_text()) for p in sorted((self.state / "outbox").iterdir())]
        kept = lambda: [i for i in everything() if not i.get("dead_letter_notice")]
        notices = lambda: [i for i in everything() if i.get("dead_letter_notice")]
        self.assertEqual([(i["seq"], i["rejected"], i.get("parked", False)) for i in kept()], [(2, 1, False)])
        rebooted = copy.deepcopy(changed)
        rebooted.update(boot_id="bbbbbbbb-2", btime=int(self.clock) + 300)
        mails = self.step(rebooted)
        self.assertEqual(len(mails), 1)                            # hub-3 went out behind the refused hub-2
        self.assertIn("rebooted", mails[0])
        self.assertIn("(sequence hub-3", mails[0])
        self.assertEqual([(i["seq"], i["rejected"], i["parked"]) for i in kept()], [(2, 2, True)])
        self.assertIn("SMTPDataError: (554", kept()[0]["error"])
        self.assertEqual([i["seq"] for i in notices()], [4])
        mails = self.step(rebooted)                                # third refusal: it now rests for 6 h
        self.assertEqual([(i["seq"], i["rejected"]) for i in kept()], [(2, 3)])
        self.assertEqual(len(mails), 1)
        self.assertIn("alert mail hub-2 was refused by SMTP (5xx) and parked", mails[0])
        self.assertNotIn("SHA256:EVIL", mails[0])
        self.assertEqual(notices(), [])
        self.reject = {}
        self.step(rebooted)
        self.assertEqual([(i["seq"], i["rejected"]) for i in kept()], [(2, 3)])   # not tried inside the 6 h
        mails = self.step(rebooted, dt=6 * 3600 + 1)               # tried again after 6 h: delivered
        self.assertTrue(any("(sequence hub-2" in m and "SHA256:EVIL" in m for m in mails), mails)
        self.assertEqual(kept(), [])
        # Still blocking, as before: a 4xx after DATA, a refused login, a refused sender.
        for exc in (smtplib.SMTPDataError(451, b"try later"), smtplib.SMTPAuthenticationError(535, b"bad"),
                    smtplib.SMTPSenderRefused(550, b"unverified sender", "support@winsvpn.org")):
            seq = json.loads((self.state / "seq.json").read_text())["seq"] + 1
            self.reject = {"hub-%d" % seq: exc}
            rebooted = copy.deepcopy(rebooted)
            rebooted.update(boot_id="%08x-9" % seq, btime=int(self.clock) + 300)
            self.assertEqual(self.step(rebooted, dt=6 * 3600), [])
            self.assertEqual([(i["seq"], "rejected" in i) for i in kept()], [(seq, False)])
            self.reject = {}
            self.assertIn("(sequence hub-%d" % seq, self.step(rebooted)[0])
            self.assertEqual(kept(), [])
        # Every recipient refused with a 5xx is for good too: a newer message passes it.
        seq = json.loads((self.state / "seq.json").read_text())["seq"] + 1
        self.reject = {"hub-%d" % seq: smtplib.SMTPRecipientsRefused({"security@winsvpn.com": (550, b"no such user")})}
        rebooted = copy.deepcopy(rebooted)
        rebooted.update(boot_id="%08x-a" % seq, btime=int(self.clock) + 300)
        self.assertEqual(self.step(rebooted, dt=6 * 3600), [])
        self.assertEqual([(i["seq"], i["rejected"]) for i in kept()], [(seq, 1)])
        rebooted = copy.deepcopy(rebooted)
        rebooted.update(boot_id="%08x-b" % seq, btime=int(self.clock) + 300)
        self.assertIn("(sequence hub-%d" % (seq + 1), self.step(rebooted)[0])
        self.assertEqual([(i["seq"], i["rejected"], i["parked"]) for i in kept()], [(seq, 2, True)])

    # ---------------------------------------------- Turn 4: refused mail (SMTP5XX)
    def mailer(self, refuse):
        """An Attest whose SMTP refuses, by subject marker, with the given
        exception; every attempt is recorded in self.attempts."""
        self.attempts = []
        app = self.make("hub")
        app.now = self.clock

        def send(msg):
            self.attempts.append(msg["Subject"])
            for marker, exc in refuse.items():
                if marker in msg["Subject"]:
                    raise exc
            self.sent.append(msg)
        app.smtp_send = send
        return app

    def outbox_items(self):
        return [(p, json.loads(p.read_text())) for p in sorted((self.state / "outbox").iterdir())]

    def run_flush(self, app, dt=120):
        self.clock += dt
        app.now = self.clock
        before = len(self.attempts)
        app.flush()
        return self.attempts[before:]

    def test_a_refused_message_holds_the_queue_until_a_newer_one_is_delivered(self) -> None:
        # GLM's proof rule: a 5xx for one message may really be the account or
        # the server, so it keeps holding the queue (and is tried every run,
        # three refusals or not) until a newer message is delivered after it,
        # in a later run here. Mythos's base: it is never deleted unsent and
        # keeps its age for outbox_oldest; once parked the three refusals make
        # it rest for 6 h.
        app = self.mailer({"POISON": smtplib.SMTPDataError(554, b"5.7.1 content rejected")})
        app.queue("[Wins VPN Tamper P1] POISON de-1 keys", "x\n")
        poison = self.outbox_items()[0][0]
        born = poison.stat().st_mtime_ns
        for run in range(4):
            self.assertEqual(len(self.run_flush(app)), 1, run)         # tried every run before the proof
        _, item = self.outbox_items()[0]
        self.assertEqual((item["rejected"], item.get("parked", False)), (4, False))
        self.assertEqual(len(self.outbox_items()), 1)                 # no notice before the proof
        self.assertEqual(app.pipeline()["parked"], [])
        app.queue("[Wins VPN Tamper P1] de-2 credentials", "password of root changed\n")
        tried = self.run_flush(app)
        self.assertEqual(tried, ["[Wins VPN Tamper P1] POISON de-1 keys", "[Wins VPN Tamper P1] de-2 credentials"])
        self.assertEqual([m["Subject"] for m in self.sent], ["[Wins VPN Tamper P1] de-2 credentials"])
        self.assertTrue(poison.exists())                              # never deleted unsent
        self.assertEqual(poison.stat().st_mtime_ns, born)             # still counted from when it was queued
        self.assertEqual(app.pipeline()["outbox_oldest"], poison.stat().st_mtime)
        _, item = self.outbox_items()[0]
        self.assertEqual((item["rejected"], item["parked"]), (5, True))
        self.assertEqual(app.pipeline()["parked"], ["hub-1"])
        self.assertEqual(self.run_flush(app), ["[Wins VPN Alerting P1] alert mail hub-1 was refused by SMTP (5xx) and parked"])
        self.assertEqual(self.run_flush(app, dt=6 * 3600 - 300), [])  # parked and refused 5 times: rests 6 h
        self.assertEqual(self.run_flush(app, dt=301), ["[Wins VPN Tamper P1] POISON de-1 keys"])
        self.assertTrue(poison.exists())

    def test_a_channel_that_refuses_everything_keeps_the_whole_queue(self) -> None:
        # Without a delivery nothing is parked and nothing is notified: the
        # queue stays held. Each run tries the oldest message and one message
        # never refused before, then only the oldest once every message has
        # been refused once.
        app = self.mailer({"[Wins": smtplib.SMTPDataError(550, b"5.7.1 sender domain not verified")})
        for n in range(4):
            app.queue("[Wins VPN Tamper P1] m%d" % n, "x\n")
        self.assertEqual([len(self.run_flush(app)) for _ in range(5)], [2, 2, 2, 1, 1])
        items = self.outbox_items()
        self.assertEqual(len(items), 4)
        self.assertEqual([i.get("parked", False) for _, i in items], [False] * 4)
        self.assertEqual([i["rejected"] for _, i in items], [5, 1, 1, 1])
        self.assertEqual(self.sent, [])
        self.assertEqual(app.pipeline()["parked"], [])

    def test_consecutive_refused_messages_cannot_hold_the_queue(self) -> None:
        # Two refused messages in a row (a node can make several alerts carry
        # the same text) are passed within two runs: the probe moves on to a
        # message never refused before, and its delivery parks both.
        app = self.mailer({"POISON": smtplib.SMTPDataError(554, b"5.7.1 content rejected")})
        app.queue("[Wins VPN Tamper P1] POISON a", "x\n")
        app.queue("[Wins VPN Tamper P1] POISON b", "x\n")
        app.queue("[Wins VPN Tamper P1] de-3 reboot", "y\n")
        self.assertEqual(self.run_flush(app), ["[Wins VPN Tamper P1] POISON a", "[Wins VPN Tamper P1] POISON b"])
        self.assertEqual(self.run_flush(app), ["[Wins VPN Tamper P1] POISON a", "[Wins VPN Tamper P1] de-3 reboot"])
        self.assertEqual([m["Subject"] for m in self.sent], ["[Wins VPN Tamper P1] de-3 reboot"])
        self.assertEqual([(i["seq"], i.get("parked", False)) for _, i in self.outbox_items()],
                         [(1, True), (2, True), (4, False), (5, False)])
        self.assertEqual(app.pipeline()["parked"], ["hub-1", "hub-2"])

    def test_the_parked_notice_is_fixed_text_sent_once_and_never_parked(self) -> None:
        # Claude's notice: one P1 per parked message, naming only its sequence
        # number and the reply class, never its subject or body.
        app = self.mailer({"POISON": smtplib.SMTPDataError(554, b"5.7.1 content rejected")})
        app.queue("[Wins VPN Tamper P1] POISON de-1 keys", "added: /etc/pam.d/x buy cheap pills\n")
        app.queue("[Wins VPN Tamper P1] de-2 credentials", "y\n")
        app.queue("[Wins VPN Tamper P1] de-3 reboot", "z\n")       # a second delivery in the same run
        self.run_flush(app)
        for _ in range(3):
            self.run_flush(app)
        notices = [m for m in self.sent if "Alerting" in m["Subject"]]
        self.assertEqual(len(notices), 1)
        self.assertEqual(notices[0]["Subject"], "[Wins VPN Alerting P1] alert mail hub-1 was refused by SMTP (5xx) and parked")
        body = notices[0].get_content()
        self.assertIn("SMTP refused alert message hub-1 with a permanent 5xx reply", body)
        for leak in ("POISON", "pills", "pam.d", "554", "content rejected"):
            self.assertNotIn(leak, body + notices[0]["Subject"])
        # A notice the server refuses holds the queue and is never parked, so
        # it cannot breed notices about itself.
        shutil.rmtree(self.state)
        self.sent.clear()
        app = self.mailer({"POISON": smtplib.SMTPDataError(554, b"rejected"),
                           "refused by SMTP": smtplib.SMTPDataError(554, b"rejected")})
        app.queue("[Wins VPN Tamper P1] POISON", "x\n")
        app.queue("[Wins VPN Tamper P1] good-1", "x\n")
        self.run_flush(app)                                           # good-1 delivered, POISON parked, notice queued
        app.queue("[Wins VPN Tamper P1] good-2", "x\n")
        for _ in range(4):
            self.run_flush(app)
        subjects = [i["subject"] for _, i in self.outbox_items()]
        self.assertEqual(subjects, ["[Wins VPN Tamper P1] POISON",
                                    "[Wins VPN Alerting P1] alert mail hub-1 was refused by SMTP (5xx) and parked",
                                    "[Wins VPN Tamper P1] good-2"])
        self.assertEqual([i.get("parked", False) for _, i in self.outbox_items()], [True, False, False])
        self.assertEqual([m["Subject"] for m in self.sent], ["[Wins VPN Tamper P1] good-1"])

    def test_account_and_temporary_failures_still_hold_the_queue(self) -> None:
        # Mythos's base: only a 5xx for this message is for good. Behind a
        # parked message, a 4xx, a refused login, sender or (4xx) recipient, a
        # dropped connection or a network error still stops the run, parks
        # nothing and sends nothing newer.
        for exc in (smtplib.SMTPDataError(451, b"4.3.0 try later"),
                    smtplib.SMTPAuthenticationError(535, b"bad credentials"),
                    smtplib.SMTPSenderRefused(550, b"sender not verified", "support@winsvpn.org"),
                    smtplib.SMTPRecipientsRefused({"security@winsvpn.com": (450, b"mailbox busy")}),
                    smtplib.SMTPServerDisconnected("gone"),
                    OSError("network down")):
            shutil.rmtree(self.state, ignore_errors=True)
            self.sent.clear()
            app = self.mailer({"POISON": smtplib.SMTPDataError(554, b"rejected"), "HELD": exc})
            app.queue("[Wins VPN Tamper P1] POISON", "x\n")
            app.queue("[Wins VPN Tamper P1] good", "x\n")
            self.run_flush(app)
            self.assertEqual(app.pipeline()["parked"], ["hub-1"], type(exc).__name__)
            app.queue("[Wins VPN Tamper P1] HELD one", "x\n")
            app.queue("[Wins VPN Tamper P1] after", "x\n")
            tried = self.run_flush(app)
            self.assertEqual(tried, ["[Wins VPN Tamper P1] POISON",
                                     "[Wins VPN Alerting P1] alert mail hub-1 was refused by SMTP (5xx) and parked",
                                     "[Wins VPN Tamper P1] HELD one"], type(exc).__name__)
            held = [i for _, i in self.outbox_items() if "HELD" in i["subject"]][0]
            self.assertNotIn("rejected", held, type(exc).__name__)
            self.assertEqual(app.pipeline()["parked"], ["hub-1"], type(exc).__name__)
            self.assertNotIn("[Wins VPN Tamper P1] after", [m["Subject"] for m in self.sent], type(exc).__name__)

    def test_parked_mail_is_reported_by_the_digest_and_to_the_watcher(self) -> None:
        # Claude's reporting: the daily digest names parked messages, and the
        # hub's report makes the external watcher raise a P1 about them.
        app = self.mailer({"POISON": smtplib.SMTPDataError(554, b"rejected")})
        app.queue("[Wins VPN Tamper P1] POISON", "x\n")
        app.queue("[Wins VPN Tamper P1] good", "x\n")
        self.run_flush(app)
        app.cmd_digest()
        self.assertIn("PARKED after a permanent SMTP refusal (5xx): hub-1", self.sent[-1].get_content())
        fresh = dict(app.pipeline(), monitor_ok_at=self.clock, attest_finished_at=self.clock,
                     watchdog_ok_at=self.clock, mail_ok_at=self.clock, outbox_oldest=None)
        self.assertEqual(self.mod.pipeline_conditions(fresh, self.clock),
                         ["1 alert mail(s) refused by SMTP (5xx) and parked: hub-1"])
        hostile = dict(fresh, parked=["hub-1\nTo: x@evil", 7])
        self.assertEqual(self.mod.pipeline_conditions(hostile, self.clock),
                         ["2 alert mail(s) refused by SMTP (5xx) and parked: hub-1?To??x?evil, 7"])
        hub_obs = base_obs()
        hub_obs["pipeline"] = dict(fresh, monitor_ok_at=self.clock + 100, attest_finished_at=self.clock + 100,
                                   watchdog_ok_at=self.clock + 100)
        shutil.rmtree(self.state)                                     # the watcher keeps its own state
        mails = self.step(hub_obs, name="hub", role="watcher")
        self.assertTrue(any("[Wins VPN Tamper P1]" in m and "refused by SMTP (5xx) and parked: hub-1" in m for m in mails), mails)

    def test_watcher_reports_a_silent_hub_pipeline(self) -> None:
        hub_obs = base_obs()
        hub_obs["pipeline"] = {"monitor_ok_at": self.clock + 100, "attest_finished_at": self.clock + 100,
                               "watchdog_ok_at": self.clock + 100, "mail_ok_at": self.clock, "outbox_depth": 0, "outbox_oldest": None}
        self.step(hub_obs, name="hub", role="watcher")
        stale = copy.deepcopy(hub_obs)
        mails = self.step(stale, name="hub", role="watcher", dt=900)
        self.assertIn("security monitor has not completed a run for", mails[0])
        self.assertIn("[Wins VPN Tamper P1]", mails[0])

    def test_digest_says_all_clear_or_lists_open_findings(self) -> None:
        self.step(base_obs())
        app = self.make("hub")
        app.now = self.clock
        app.cmd_digest()
        self.assertIn("[Wins VPN Digest] ALL CLEAR (hub)", self.sent[-1]["Subject"])
        changed = base_obs(agents={"qemu-guest-agent.service": "active"})
        self.step(changed)
        app = self.make("hub")
        app.now = self.clock
        app.cmd_digest()
        self.assertIn("1 OPEN FINDING(S)", self.sent[-1]["Subject"])
        self.assertIn("qemu-guest-agent.service: inactive -> active", self.sent[-1].get_content())


class CollectPathTests(unittest.TestCase):
    """The checker's own SSH call: pinned keys, classification, the nonce."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="f2s-"))
        self.mod = load("attest_ssh", ATTEST_SRC, self.tmp)
        (self.tmp / "env").write_text("")
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.mod.SAFE_PATH = str(self.bin)
        self.mod.PYTHON = sys.executable
        self.kh = self.tmp / "known_hosts"
        self.kh.write_text("de-1-mgmt.example.test ssh-ed25519 %s\n" % ED_PUB)
        self.kh.chmod(0o600)
        (self.tmp / "collector.py").write_text(COLLECT_SRC)
        self.app = self.mod.Attest("hub", str(self.tmp / "state"), str(self.tmp / "env"), collector=str(self.tmp / "collector.py"))
        self.target = {"name": "de-1", "host": "de-1-mgmt.example.test", "user": "root", "port": "22",
                       "access": True, "key": "/root/.ssh/id_rsa", "known_hosts": str(self.kh)}

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def fake_ssh(self, body: str) -> None:
        (self.bin / "ssh").write_text("#!/bin/sh\n" + body)
        (self.bin / "ssh").chmod(0o755)

    def test_argv_pins_the_host_key_and_goes_through_access(self) -> None:
        argv = self.app.ssh_argv(self.target, "python3 -I - " + NONCE)
        for opt in ("StrictHostKeyChecking=yes", "UserKnownHostsFile=%s" % self.kh, "GlobalKnownHostsFile=/dev/null",
                    "UpdateHostKeys=no", "BatchMode=yes", "ProxyCommand=/usr/bin/cloudflared access ssh --hostname %h"):
            self.assertIn(opt, argv)
        self.assertEqual(argv[-2:], ["root@de-1-mgmt.example.test", "python3 -I - " + NONCE])
        with self.assertRaises(LookupError):
            self.app.ssh_argv(dict(self.target, host="192.0.2.10"), "x")
        with self.assertRaises(LookupError):
            self.app.ssh_argv(dict(self.target, host="other-mgmt.example.test"), "x")
        kh2 = self.tmp / "kh2"
        kh2.write_text("[hub.example]:2200 ssh-ed25519 %s\n" % ED_PUB)
        kh2.chmod(0o600)
        watch = {"host": "hub.example", "port": "2200", "user": "root", "key": "k", "known_hosts": str(kh2), "access": False}
        self.assertIn("-p", self.app.ssh_argv(watch, NONCE))
        self.assertNotIn("ProxyCommand=/usr/bin/cloudflared access ssh --hostname %h", self.app.ssh_argv(watch, NONCE))
        with self.assertRaises(LookupError):
            self.app.ssh_argv(dict(watch, port="22"), NONCE)
        self.kh.chmod(0o644)
        with self.assertRaises(LookupError):
            self.app.ssh_argv(self.target, "x")

    def test_a_changed_host_key_and_a_replayed_report_are_classified(self) -> None:
        self.fake_ssh('echo "@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! 192.0.2.10" >&2; exit 255\n')
        obs, failure = self.app.collect(self.target)
        self.assertEqual(failure[0], "hostkey_mismatch")
        self.assertNotIn("192.0.2.10", failure[1])
        self.fake_ssh('cat >/dev/null; echo \'{"v": 1, "nonce": "%s"}\'\n' % ("f" * 32))
        obs, failure = self.app.collect(self.target)
        self.assertIsNone(failure)
        self.assertTrue(obs["_nonce_mismatch"])
        # A real round trip: the collector arrives on stdin, the nonce is the
        # last word of the remote command.
        (self.bin / "ssh").write_text("#!%s\nnonce=\"${@: -1}\"; exec %s -I - \"${nonce##* }\"\n" % (lib.BASH, sys.executable))
        obs, failure = self.app.collect(self.target)
        self.assertIsNone(failure)
        self.assertNotIn("_nonce_mismatch", obs)
        self.assertEqual(obs["v"], 1)

    def test_the_hub_runs_its_own_collector_locally(self) -> None:
        obs, failure = self.app.collect({"name": "hub", "local": True})
        self.assertIsNone(failure)
        self.assertEqual(obs["v"], 1)
        self.assertNotIn("_nonce_mismatch", obs)


class InstallerTests(unittest.TestCase):
    def test_monitor_timer_is_wall_clock_and_restarted(self) -> None:
        fn = between("\nwrite_security_alert_monitor() {\n", "\n# --- FLEET2: tamper alerts")
        timer = lib.heredoc(fn, "cat > /etc/systemd/system/wins-security-alert-monitor.timer <<'EOF'", "EOF")
        self.assertIn("\nOnCalendar=*-*-* *:*:00\n", timer)
        self.assertIn("\nPersistent=true\n", timer)
        self.assertNotIn("OnUnitActiveSec", timer)
        self.assertNotIn("OnBootSec", timer)
        self.assertIn("  systemctl enable wins-security-alert-monitor.timer\n  systemctl restart wins-security-alert-monitor.timer\n", fn)
        self.assertNotIn("wins_enable_monotonic_timer wins-security-alert-monitor.timer", fn)
        service = lib.heredoc(fn, "cat > /etc/systemd/system/wins-security-alert-monitor.service <<'EOF'", "EOF")
        self.assertIn("OnFailure=wins-alert-watchdog.service", service)
        mon = lib.heredoc(SRC, "cat > /usr/local/bin/wins-security-alert-monitor <<'PYEOF'", "PYEOF")
        main = mon[mon.index("def main():"):]
        self.assertLess(main.index("monitor_journal()"), main.index('write_journal_cursor(STATE_DIR / "monitor.ok"'))

    def test_new_timers_are_wall_clock_and_persistent(self) -> None:
        fn = between("\nwrite_fleet_attest() {\n", "\ninstall_hub_watcher_key() {\n")
        for name in ("wins-fleet-attest.timer", "wins-alert-watchdog.timer", "wins-fleet-attest-digest.timer"):
            body = lib.heredoc(fn, "/etc/systemd/system/%s <<'EOF'" % name, "EOF")
            self.assertRegex(body, r"\nOnCalendar=\S")
            self.assertIn("\nPersistent=true\n", body)
            self.assertNotIn("OnUnitActiveSec", body)
        for name in ("wins-fleet-attest.service", "wins-fleet-attest-digest.service"):
            self.assertIn("OnFailure=wins-alert-watchdog.service", lib.heredoc(fn, "/etc/systemd/system/%s <<'EOF'" % name, "EOF"))

    def test_main_and_postflight_wire_it(self) -> None:
        main = SRC[SRC.rindex("\nmain() {\n"):]
        self.assertLess(main.index("  write_security_alert_monitor\n"), main.index("  write_fleet_attest || exit 1\n"))
        self.assertLess(main.index("  harden_crash_artifacts\n"), main.index("  mask_hypervisor_guest_agent || exit 1\n"))
        self.assertIn("  verify_fleet_attest || return 1\n", lib.function_text(SRC, "postflight_control"))
        dmain = DSRC[DSRC.rindex("\nmain() {\n"):]
        self.assertLess(dmain.index("  install_volatile_node_logs || exit 1\n"), dmain.index("  mask_hypervisor_guest_agent || exit 1\n"))
        self.assertEqual(lib.function_text(SRC, "mask_hypervisor_guest_agent"), lib.function_text(DSRC, "mask_hypervisor_guest_agent"))

    def run_mask(self, src, loadstate, **env):
        sb = lib.Sandbox({"systemctl": """#!/bin/sh
printf 'systemctl %%s\\n' "$*" >> "$FLEET_CALLS"
if [ "$1" = show ]; then
  if [ -z "$FLEET_MASK_FAILS" ] && grep -q "^systemctl mask $5" "$FLEET_CALLS"; then echo masked; else echo %s; fi
fi
""" % loadstate})
        try:
            script = lib.LOG_STUBS + 'WINS_GUEST_AGENT_UNITS_DEFAULT="qemu-guest-agent.service"\n' + lib.function_text(src, "mask_hypervisor_guest_agent") + "mask_hypervisor_guest_agent\n"
            r = sb.run(script, **env)
            return r, sb.logged()
        finally:
            sb.cleanup()

    def test_guest_agent_is_masked_skipped_or_kept_by_owner_decision(self) -> None:
        for src in (SRC, DSRC):
            r, calls = self.run_mask(src, "loaded")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("systemctl disable --now qemu-guest-agent.service", calls)
            self.assertIn("systemctl mask qemu-guest-agent.service", calls)
            r, calls = self.run_mask(src, "not-found")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertFalse(any("mask" in c and "show" not in c for c in calls), calls)
            r, calls = self.run_mask(src, "loaded", WINS_KEEP_GUEST_AGENT="1")
            self.assertEqual((r.returncode, calls), (0, []))
            r, calls = self.run_mask(src, "loaded", FLEET_MASK_FAILS="1")
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("Could not mask qemu-guest-agent.service", r.stderr)

    def watcher_key(self, ak_text, key_text, **env):
        sb = lib.Sandbox()
        try:
            ssh = sb.path("root", ".ssh")
            ssh.mkdir(parents=True)
            if ak_text is not None:
                (ssh / "authorized_keys").write_text(ak_text)
            (sb.tmp / "watcher.pub").write_text(key_text)
            script = lib.LOG_STUBS + lib.function_text(SRC, "install_hub_watcher_key") + "install_hub_watcher_key\n"
            r = sb.run(script, HUB_WATCHER_SSH_PUBKEY_FILE=str(sb.tmp / "watcher.pub"), WINS_ROOT_SSH_DIR=str(ssh), **env)
            out = (ssh / "authorized_keys").read_text() if (ssh / "authorized_keys").exists() else None
            return r, out
        finally:
            sb.cleanup()

    def test_watcher_key_is_forced_command_only_and_keeps_every_other_line(self) -> None:
        owner = "ssh-ed25519 %s owner@mac" % ED_PUB
        r, out = self.watcher_key(owner, "ssh-ed25519 %s wins-hub-watcher\n" % ED_PUB, HUB_WATCHER_FROM="192.0.2.0/24")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(out, owner + "\nrestrict,command=\"/usr/local/sbin/wins-fleet-attest --role hub hub-report\","
                         "from=\"192.0.2.0/24\" ssh-ed25519 %s wins-hub-watcher\n" % ED_PUB)
        r, again = self.watcher_key(out, "ssh-ed25519 %s wins-hub-watcher\n" % ED_PUB)
        self.assertEqual(again.count("wins-hub-watcher"), 1)
        self.assertTrue(again.startswith(owner + "\n"))
        for bad in ("ssh-rsa AAAAB3Nza owner\n", "ssh-ed25519 %s a\nssh-ed25519 %s b\n" % (ED_PUB, ED_PUB)):
            r, kept = self.watcher_key(owner, bad)
            self.assertNotEqual(r.returncode, 0)
            self.assertEqual(kept, owner)
        r, kept = self.watcher_key(owner, "ssh-ed25519 %s x\n" % ED_PUB, HUB_WATCHER_FROM='1.2.3.4" ,command="sh')
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(kept, owner)

    def test_an_unreadable_authorized_keys_is_left_alone(self) -> None:
        sb = lib.Sandbox()
        try:
            ssh = sb.path("ssh")
            ssh.mkdir()
            ak = ssh / "authorized_keys"
            ak.write_text("ssh-ed25519 %s owner\n" % ED_PUB)
            ak.chmod(0o000)
            (sb.tmp / "w.pub").write_text("ssh-ed25519 %s w\n" % ED_PUB)
            script = lib.LOG_STUBS + lib.function_text(SRC, "install_hub_watcher_key") + "install_hub_watcher_key\n"
            r = sb.run(script, HUB_WATCHER_SSH_PUBKEY_FILE=str(sb.tmp / "w.pub"), WINS_ROOT_SSH_DIR=str(ssh))
            if os.geteuid() == 0:
                self.skipTest("root reads a 000 file")
            self.assertNotEqual(r.returncode, 0)
            ak.chmod(0o600)
            self.assertEqual(ak.read_text(), "ssh-ed25519 %s owner\n" % ED_PUB)
            self.assertEqual([p.name for p in ssh.iterdir()], ["authorized_keys"])
        finally:
            sb.cleanup()

    def test_no_watcher_key_file_changes_nothing(self) -> None:
        sb = lib.Sandbox()
        try:
            script = lib.LOG_STUBS + lib.function_text(SRC, "install_hub_watcher_key") + "install_hub_watcher_key\n"
            r = sb.run(script, HUB_WATCHER_SSH_PUBKEY_FILE=str(sb.tmp / "absent.pub"), WINS_ROOT_SSH_DIR=str(sb.tmp / "ssh"))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertFalse((sb.tmp / "ssh").exists())
        finally:
            sb.cleanup()


DIG_SHIM = r'''#!/usr/bin/env python3
import os, sys
rc = int(os.environ.get("FLEET_DIG_RC", "0"))
if rc:
    sys.exit(rc)
name = sys.argv[-1]
print(os.environ.get("FLEET_DIG_DMARC" if name.startswith("_dmarc.") else "FLEET_DIG_SPF", ""), end="")
'''


class EmailAuthDnsTests(unittest.TestCase):
    """The one postflight DNS check for the sending domain (Turn 3 merge of the
    Claude seat's check_alert_mail_dns and the Mythos seat's
    verify_email_auth_dns): warn only, exact records, a failed query is
    unchecked and never missing."""

    def check(self, env_text="EMAIL_SENDER='support@winsvpn.org'\n", prelude="", **env):
        sb = lib.Sandbox({"dig": DIG_SHIM})
        try:
            if env_text is not None:
                (sb.tmp / "env").write_text(env_text)
            script = (prelude + lib.LOG_STUBS + lib.function_text(SRC, "verify_email_auth_dns")
                      + "verify_email_auth_dns\necho FLEET_DNS_DONE\n")
            return sb.run(script, WINS_EMAIL_AUTH_ENV_FILE=str(sb.tmp / "env"), **env)
        finally:
            sb.cleanup()

    def test_missing_records_are_named_exactly_and_never_fail_the_deploy(self) -> None:
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('winsvpn.org TXT "v=spf1 include:_spf.protonmail.ch include:spf.smtp2go.com ~all"', r.stderr)
        self.assertIn("winsvpn.org publishes no SPF record", r.stderr)
        self.assertIn("_dmarc.winsvpn.org publishes no DMARC record", r.stderr)
        self.assertIn('_dmarc.winsvpn.org TXT "v=DMARC1; p=quarantine; adkim=r; aspf=r; fo=1; rua=mailto:dmarc@winsvpn.org"', r.stderr)
        self.assertIn("verified sender domain at SMTP2GO", r.stdout)

    def test_present_records_warn_only_about_what_is_missing(self) -> None:
        r = self.check(FLEET_DIG_SPF='"v=spf1 include:_spf.protonmail.ch ~all"',
                       FLEET_DIG_DMARC='"v=DMARC1; p=none; rua=mailto:dmarc@winsvpn.com"')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("does not include SMTP2GO", r.stderr)
        self.assertIn("keep its other includes", r.stderr)
        self.assertNotIn("publishes no SPF record", r.stderr)
        self.assertNotIn("publishes no DMARC record", r.stderr)
        self.assertIn("is p=none, neither quarantine nor reject", r.stderr)
        self.assertIn('winsvpn.org._report._dmarc.winsvpn.com TXT "v=DMARC1"', r.stderr)
        r = self.check(FLEET_DIG_SPF='"v=spf1 include:_spf.protonmail.ch" "include:spf.smtp2go.com -all"',
                       FLEET_DIG_DMARC='"v=DMARC1; p=reject; adkim=r; aspf=r; rua=mailto:dmarc@winsvpn.org"')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("[WARN]", r.stderr)
        r = self.check(FLEET_DIG_SPF='"v=spf1 include:_spf.protonmail.ch include:spf.smtp2go.com ~all"',
                       FLEET_DIG_DMARC='"v=DMARC1; p=quarantine; rua=mailto:dmarc@mail.winsvpn.org"')
        self.assertNotIn("[WARN]", r.stderr)                    # a subdomain rua needs no authorization
        r = self.check(FLEET_DIG_SPF='"v=spf1 -all"\n"v=spf1 include:spf.smtp2go.com ~all"')
        self.assertIn("has 2 SPF records", r.stderr)
        r = self.check(FLEET_DIG_DMARC='"v=DMARC1; sp=reject; rua=mailto:dmarc@winsvpn.org"')
        self.assertIn("is p=unset, neither quarantine nor reject", r.stderr)   # sp= is not p=

    def test_a_failed_query_is_reported_as_unchecked_not_as_missing(self) -> None:
        r = self.check(FLEET_DIG_RC="9")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("could not query TXT winsvpn.org (dig exit 9)", r.stderr)
        self.assertIn("could not query TXT _dmarc.winsvpn.org", r.stderr)
        self.assertNotIn("publishes no SPF", r.stderr)
        self.assertNotIn("publishes no DMARC", r.stderr)

    def test_a_failed_query_cannot_abort_an_errexit_installer(self) -> None:
        # The installer runs under set -Eeuo pipefail. Called bare (not only
        # behind `verify_fleet_attest || return 1`), a failing dig must still
        # be a warning, never an exit.
        r = self.check(prelude="set -Eeuo pipefail\n", FLEET_DIG_RC="9")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("FLEET_DNS_DONE", r.stdout)
        self.assertIn("could not query TXT winsvpn.org (dig exit 9)", r.stderr)
        r = self.check(env_text=None, prelude="set -Eeuo pipefail\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("FLEET_DNS_DONE", r.stdout)

    def test_the_sender_comes_from_the_runtime_env_then_the_default(self) -> None:
        r = self.check(env_text="EMAIL_SENDER='alerts@example.net'\n")
        self.assertIn("example.net publishes no SPF record", r.stderr)
        r = self.check(env_text=None, prelude='EMAIL_SENDER_DEFAULT="support@winsvpn.org"\n')
        self.assertIn("winsvpn.org publishes no SPF record", r.stderr)
        r = self.check(env_text="EMAIL_SENDER='nobody'\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("cannot derive the sending domain", r.stderr)
        r = self.check(env_text="EMAIL_SENDER='x@evil.org;rm -rf /'\n", FLEET_DIG_SPF="v=spf1 include:spf.smtp2go.com ~all")
        self.assertIn("cannot derive the sending domain", r.stderr)
        self.assertNotIn("evil.org", r.stderr + r.stdout)                   # never handed to dig or echoed as a domain

    def test_postflight_runs_it_last_and_it_cannot_fail_the_deploy(self) -> None:
        fn = lib.function_text(SRC, "verify_fleet_attest")
        self.assertTrue(fn.rstrip().endswith("  verify_email_auth_dns\n}"), fn[-120:])
        self.assertNotIn("check_alert_mail_dns", SRC)                       # one check, not two
        body = lib.function_text(SRC, "verify_email_auth_dns")
        self.assertNotIn("return 1", body)
        self.assertNotIn("err \"", body)


class WatcherSetupTests(unittest.TestCase):
    def test_setup_installs_the_installers_own_programs_and_units(self) -> None:
        if not shutil.which("ssh-keygen"):
            self.skipTest("ssh-keygen not installed")
        sb = lib.Sandbox({"systemctl": '#!/bin/sh\nprintf "systemctl %s\\n" "$*" >> "$FLEET_CALLS"\n'})
        try:
            root = sb.tmp / "r"
            etc = root / "etc" / "winsvpn"
            etc.mkdir(parents=True)
            (etc / "hub-watch.env").write_text("HUB_WATCH_SSH_HOST='hub.example'\nSMTP_USER='u'\nSMTP_PASS='p'\nSECURITY_ALERT_EMAIL='security@winsvpn.com'\n")
            (etc / "hub-watch.known_hosts").write_text("hub.example ssh-ed25519 %s\n" % ED_PUB)
            for f in etc.iterdir():
                f.chmod(0o600)
            (root / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/bash\nowner:x:1000:1000::/home/owner:/bin/bash\n")
            hubpub = sb.tmp / "hub.pub"
            hubpub.write_text("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDHUBKEYHUBKEYHUBKEYHUBKEYHUBKEYHUBKEYHUBKEYHUBKEY root@hub\n")
            run = 'bash "%s" --from "%s" --hub-pubkey "%s"' % (WATCH, CP, hubpub)
            (root / "home/owner/.ssh").mkdir(parents=True)
            (root / "home/owner/.ssh/authorized_keys").write_text("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDHUBKEYHUBKEYHUBKEYHUBKEYHUBKEYHUBKEYHUBKEYHUBKEY wins-hub-managed\n")
            r = sb.run(run, WINS_HUB_WATCH_ROOT=str(root))
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("The hub can log in to this host", r.stderr)
            self.assertIn("/home/owner/.ssh/authorized_keys", r.stderr)
            self.assertFalse((root / "usr/local/sbin/wins-fleet-attest").exists())
            (root / "home/owner/.ssh/authorized_keys").write_text("ssh-ed25519 %s owner@mac\n" % ED_PUB)
            r = sb.run(run, WINS_HUB_WATCH_ROOT=str(root))
            self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
            self.assertEqual((root / "usr/local/sbin/wins-fleet-attest").read_text(), ATTEST_SRC)
            self.assertEqual((root / "usr/local/lib/wins-attest-collect.py").read_text(), COLLECT_SRC)
            service = (root / "etc/systemd/system/wins-hub-watch.service").read_text()
            self.assertIn("ExecStart=/usr/local/sbin/wins-fleet-attest --role watcher run\n", service)
            self.assertIn("OnFailure=wins-hub-watch-watchdog.service\n", service)
            timer = (root / "etc/systemd/system/wins-hub-watch.timer").read_text()
            self.assertIn("OnCalendar=*-*-* *:01/2:00\n", timer)
            self.assertIn("Persistent=true\n", timer)
            self.assertIn("systemctl restart wins-hub-watch.timer", sb.logged())
            self.assertIn("wins-hub-watcher", (etc / "hub-watch_ed25519.pub").read_text())
            (etc / "hub-watch.env").chmod(0o644)
            r = sb.run(run, WINS_HUB_WATCH_ROOT=str(root))
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("mode 0600", r.stderr)
        finally:
            sb.cleanup()


if __name__ == "__main__":
    unittest.main()
