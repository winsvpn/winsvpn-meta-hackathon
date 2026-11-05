"""S4 source-backed offline fixtures. No real keys, network, or host services."""
import base64
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "server/wins_data_plane_setup_ONETOUCH.sh").read_text()
BASH = os.environ.get("WINS_TEST_BASH", "/bin/bash")


def embedded(marker):
    return SOURCE.split("<<'" + marker + "'\n", 1)[1].split("\n" + marker + "\n", 1)[0]


def module(marker):
    value = types.ModuleType(marker)
    exec(compile(embedded(marker), marker, "exec"), value.__dict__)
    return value


NODE = module("WINS_S4_NODE_PY")
CHECK_HALVES = NODE.check_halves
SESSION = module("WINS_S4_SESSION_PY")
LATCH = embedded("WINS_LATCH_PY")
OFFNODE = embedded("WINS_OFFNODE_CHECK_EOF") + "\n"


def shell_function(name):
    # Production's structural parser accounts for quoted heredocs and braces.
    sys.path.insert(0, str(ROOT / "tools"))
    from winn3_gateway_block import segment
    lines = SOURCE.split("\n")
    for item in segment(lines):
        if item["kind"] == "func" and item["name"] == name:
            return "\n".join(lines[item["start"]:item["end"] + 1])
    raise AssertionError("missing production function: " + name)


class RootFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.addCleanup(self.temp.cleanup)
        self.area = Path(self.temp.name)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        original = NODE.secure_directory
        def directory(path, private=False):
            path = Path(path)
            if not path.is_relative_to(self.area):
                raise NODE.Refusal("fixture directory escaped")
            for ancestor in (path, *path.parents):
                if ancestor == self.area.parent:
                    break
                info = ancestor.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
                    raise NODE.Refusal("unsafe directory")
            if private and stat.S_IMODE(path.lstat().st_mode) != 0o700:
                raise NODE.Refusal("unsafe private directory")
        self.stack.enter_context(patch.object(NODE, "secure_directory", directory))
        fstat = os.fstat
        def metadata(fd):
            info = fstat(fd)
            return types.SimpleNamespace(st_uid=0, st_gid=0, st_mode=info.st_mode, st_nlink=info.st_nlink,
                                         st_dev=info.st_dev, st_ino=info.st_ino)
        self.stack.enter_context(patch.object(NODE.os, "fstat", metadata))
        self.stack.enter_context(patch.object(NODE.os, "fchown", lambda *args: None))
        self.stack.enter_context(patch.object(NODE, "check_halves", lambda bodies: None))
        self.credentials = self.area / "credentials"
        self.credentials.mkdir(mode=0o700)
        self.store = NODE.Credentials(self.credentials, "node-gw1")
        # Deliberately artificial hex, never valid generated key material.
        self.bodies = {name: bytes([index + 1]).hex().encode() * size
                       for index, (name, size) in enumerate(NODE.SIZES.items())}

    def populate(self, destination, complete=False):
        (destination / "public").mkdir(mode=0o755, exist_ok=True)
        for name in NODE.ORDER:
            path = destination / name
            path.write_bytes(self.bodies[name])
            path.chmod(0o644 if name.startswith("public/") else 0o600)
        manifest = {"gateway_id": "node-gw1", "sha256": {n: NODE.digest(self.bodies[n]) for n in NODE.ORDER}}
        if complete:
            NODE.atomic_file(destination / "winn3-identity.complete", NODE.canonical(manifest), 0o600)
        return manifest

    def stage(self):
        stage = self.credentials / ".staging-fixture"
        stage.mkdir(mode=0o700)
        manifest = self.populate(stage)
        NODE.atomic_file(stage / "staging.complete", NODE.canonical(manifest), 0o600)
        return stage, manifest


class CredentialTests(RootFixture):
    def test_identity_endpoint_and_slug_changes_refuse_before_render(self):
        path = self.area / "identity.json"
        NODE.atomic_file(path, NODE.canonical({"slug": "fixture", "endpoint": "1.2.3.4:9111"}), 0o644)
        before = path.read_bytes()
        for slug, endpoint, field in (("other", "1.2.3.4:9111", "slug"),
                                      ("fixture", "1.2.3.5:9111", "endpoint")):
            with self.subTest(field=field), patch.object(sys, "argv", ["node", "identity-context", str(path), slug, endpoint]):
                with self.assertRaisesRegex(NODE.Refusal, "identity conflict: " + field):
                    NODE.main()
                self.assertEqual(path.read_bytes(), before)

    def test_fresh_keygen_once_and_client_pair_never_published(self):
        original_mkdtemp = tempfile.mkdtemp
        calls = []
        def temporary(prefix, dir):
            if prefix == "winn3-keygen.":
                self.assertEqual(dir, "/run")
                return original_mkdtemp(prefix=prefix, dir=self.area)
            return original_mkdtemp(prefix=prefix, dir=dir)
        def keygen(command, **kwargs):
            calls.append(command)
            self.assertEqual(command[:3], ["fixture-binary", "-mode", "keygen"])
            destination = Path(command[-1])
            for name, body in self.bodies.items():
                path = destination / Path(name).name
                path.write_bytes(body)
                path.chmod(0o600)
            for name in ("client.key", "client.pub"):
                path = destination / name
                path.write_bytes(b"synthetic unused client fixture")
                path.chmod(0o600)
            return types.SimpleNamespace(returncode=0)
        with patch.object(NODE.tempfile, "mkdtemp", temporary), patch.object(NODE.subprocess, "run", keygen):
            self.store.install("fixture-binary")
            self.store.install("fixture-binary")
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.store.classify(), "complete")
        self.assertFalse(list(self.credentials.rglob("client.*")))
        self.assertFalse(list(self.area.glob("winn3-keygen.*")))

    def test_fresh_classification_has_no_write(self):
        before = list(self.credentials.iterdir())
        self.assertEqual(self.store.classify(), "fresh")
        self.assertEqual(list(self.credentials.iterdir()), before)

    def test_complete_rerun_never_changes_credentials(self):
        self.populate(self.credentials, True)
        before = {p: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_ino)
                  for p in self.credentials.rglob("*") if p.is_file()}
        self.store.install("never-executed")
        after = {p: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_ino)
                 for p in self.credentials.rglob("*") if p.is_file()}
        self.assertEqual(before, after)

    def test_every_partial_live_set_names_missing_file(self):
        for name in NODE.ORDER:
            with self.subTest(name=name):
                self.populate(self.credentials)
                (self.credentials / name).unlink()
                with self.assertRaisesRegex(NODE.Refusal, re.escape("missing " + name)):
                    self.store.classify()

    def test_complete_legacy_set_is_classified_for_adoption_and_never_regenerated(self):
        self.populate(self.credentials)
        self.assertEqual(self.store.classify(), "legacy")
        with patch.object(NODE.subprocess, "run", side_effect=AssertionError("keygen must not run")):
            with self.assertRaisesRegex(NODE.Refusal, "requires adoption"):
                self.store.install("never-executed")

    def test_staging_resume_does_not_run_keygen(self):
        self.stage()
        with patch.object(NODE.subprocess, "run", side_effect=AssertionError("keygen must not run")):
            self.store.install("never-executed")
        self.assertEqual(self.store.classify(), "complete")

    def test_staging_live_conflict_refuses_without_any_rename(self):
        stage, manifest = self.stage()
        victim = self.credentials / "auth_mldsa65.seed"
        victim.write_bytes(b"ff" * 32)
        victim.chmod(0o600)
        before = {p: p.read_bytes() for p in self.credentials.rglob("*") if p.is_file()}
        with self.assertRaisesRegex(NODE.Refusal, "live credential conflicts"):
            self.store.classify()
        self.assertEqual(before, {p: p.read_bytes() for p in self.credentials.rglob("*") if p.is_file()})

    def test_crash_after_each_credential_rename_resumes_same_identity(self):
        real_replace = os.replace
        for index in range(len(NODE.ORDER)):
            with self.subTest(index=index), tempfile.TemporaryDirectory(dir=self.area) as directory:
                root = Path(directory)
                root.chmod(0o700)
                stage = root / ".staging-fixture"
                stage.mkdir(mode=0o700)
                manifest = self.populate(stage)
                NODE.atomic_file(stage / "staging.complete", NODE.canonical(manifest), 0o600)
                store = NODE.Credentials(root, "node-gw1")
                count = 0
                def crash(source, destination):
                    nonlocal count
                    real_replace(source, destination)
                    if Path(source).name != "staging.complete":
                        if count == index:
                            raise OSError("synthetic power loss after rename")
                        count += 1
                with patch.object(NODE.os, "replace", crash), self.assertRaises(OSError):
                    store.commit(stage, manifest)
                self.assertEqual(store.classify(), "resume")
                store.install("never-executed")
                self.assertEqual(store.classify(), "complete")
                for name in NODE.ORDER:
                    self.assertEqual((root / name).read_bytes(), self.bodies[name])

    def test_record_committed_before_stage_cleanup_resumes_cleanup(self):
        stage, manifest = self.stage()
        with patch.object(self.store, "remove_stage", side_effect=OSError("synthetic cleanup interruption")):
            with self.assertRaises(OSError):
                self.store.commit(stage, manifest)
        self.assertEqual(self.store.classify(), "complete")
        self.store.install("never-executed")
        self.assertFalse(stage.exists())

    def test_incomplete_staging_discard_preserves_live_namespace(self):
        stage = self.credentials / ".staging-fixture"
        stage.mkdir(mode=0o700)
        (stage / "static.key").write_bytes(b"partial")
        (stage / "static.key").chmod(0o600)
        self.assertEqual(self.store.classify(), "discard")
        self.store.remove_stage(stage)
        self.assertEqual(self.store.classify(), "fresh")

    def test_unknown_staging_file_is_not_deleted(self):
        stage = self.credentials / ".staging-fixture"
        stage.mkdir(mode=0o700)
        victim = stage / "operator-data"
        victim.write_text("preserve")
        with self.assertRaises(NODE.Refusal):
            self.store.remove_stage(stage)
        self.assertEqual(victim.read_text(), "preserve")

    def test_multiple_stages_refuse(self):
        self.stage()
        (self.credentials / ".staging-second").mkdir(mode=0o700)
        with self.assertRaisesRegex(NODE.Refusal, "multiple"):
            self.store.classify()

    def test_completion_corruption_cases(self):
        manifest = self.populate(self.credentials, True)
        path = self.store.record
        cases = [b"{}", b"{", json.dumps(manifest).encode(), NODE.canonical({**manifest, "extra": 1}),
                 NODE.canonical({**manifest, "gateway_id": "different"}),
                 NODE.canonical({**manifest, "sha256": {}})]
        for body in cases:
            with self.subTest(body=body[:25]):
                path.write_bytes(body)
                with self.assertRaises((NODE.Refusal, ValueError)):
                    self.store.classify()

    def test_each_corrupt_credential_digest_refuses(self):
        self.populate(self.credentials, True)
        for name in NODE.ORDER:
            with self.subTest(name=name):
                path = self.credentials / name
                old = path.read_bytes()
                path.write_bytes(b"0" * len(old))
                with self.assertRaisesRegex(NODE.Refusal, "digest mismatch"):
                    self.store.classify()
                path.write_bytes(old)

    def test_symlink_and_hardlink_credentials_refuse_without_touching_victim(self):
        self.populate(self.credentials, True)
        for name in NODE.ORDER:
            with self.subTest(name=name):
                path = self.credentials / name
                body = path.read_bytes()
                path.unlink()
                victim = self.area / "victim"
                victim.write_bytes(body)
                victim.chmod(0o644 if name.startswith("public/") else 0o600)
                path.symlink_to(victim)
                with self.assertRaises(OSError):
                    self.store.classify()
                path.unlink()
                os.link(victim, path)
                with self.assertRaises(NODE.Refusal):
                    self.store.classify()
                path.unlink()
                path.write_bytes(body)
                path.chmod(0o644 if name.startswith("public/") else 0o600)
                self.assertEqual(victim.read_bytes(), body)

    def test_wrong_permissions_on_every_live_file_refuse(self):
        self.populate(self.credentials, True)
        for name in NODE.ORDER:
            with self.subTest(name=name):
                path = self.credentials / name
                mode = stat.S_IMODE(path.stat().st_mode)
                path.chmod(0o666)
                with self.assertRaises(NODE.Refusal):
                    self.store.classify()
                path.chmod(mode)

    def test_hex_format_is_exact(self):
        for name, size in NODE.SIZES.items():
            body = self.bodies[name]
            for bad in (body + b"\n\n", body + b"\r\n", body[:-1], body + b"0", b"F" * len(body),
                        b" " + body, body[:4] + b"\n" + body[4:]):
                with self.subTest(name=name, bad=bad[:6]), self.assertRaises(NODE.Refusal):
                    NODE.hex_body(bad, size, name)
            self.assertEqual(NODE.hex_body(body, size, name), NODE.hex_body(body + b"\n", size, name))


class LatchTests(unittest.TestCase):
    def setUp(self):
        self.rules = {"INPUT": "-A INPUT -j WINVPN-LOCAL-SERVING\n",
                      "WINVPN-SSH-RECOVERY": "", "WINVPN-LOCAL-SERVING":
                      "-A WINVPN-LOCAL-SERVING -i lo -j RETURN\n"
                      "-A WINVPN-LOCAL-SERVING -m conntrack --ctstate RELATED,ESTABLISHED --ctdir REPLY -j RETURN\n"
                      "-A WINVPN-LOCAL-SERVING -j DROP\n"}
        self.failures = {}
        self.calls = []

    def check(self, expected=True, mode="all"):
        def run(command, **kwargs):
            self.calls.append(command)
            key = (command[-2], command[-1])
            if key in self.failures:
                rc, error = self.failures[key]
                return types.SimpleNamespace(returncode=rc, stderr=error, stdout="")
            chain = command[-1]
            if chain not in self.rules:
                return types.SimpleNamespace(returncode=1, stderr="No chain/target/match by that name", stdout="")
            return types.SimpleNamespace(returncode=0, stderr="", stdout=self.rules[chain] if "-S" in command else "")
        with patch.object(subprocess, "run", run), patch.object(sys, "argv", ["predicate", "iptables", mode]):
            try:
                exec(compile(LATCH, "production-latch", "exec"), {})
                actual = True
            except SystemExit as exc:
                actual = exc.code == 0
        self.assertEqual(actual, expected)

    def test_base_and_chain_forms(self):
        self.check()
        self.rules["INPUT"] = "-A INPUT -j WINVPN-INPUT\n"
        self.rules["WINVPN-INPUT"] = "-A WINVPN-INPUT -j WINVPN-SSH-RECOVERY\n-A WINVPN-INPUT -j WINVPN-LOCAL-SERVING\n-A WINVPN-INPUT -j ACCEPT\n"
        self.check()

    def test_every_relevant_read_error_fails_closed(self):
        for chain in tuple(self.rules):
            for operation in ("-L", "-S"):
                for rc in (1, 2, 4, 127):
                    with self.subTest(chain=chain, operation=operation, rc=rc):
                        self.failures = {(operation, chain): (rc, "inspection failure")}
                        self.check(False)

    def test_absence_requires_exact_status_and_message(self):
        for rc, message, allowed in ((1, "No chain/target/match by that name", True),
                                     (4, "No chain/target/match by that name", False),
                                     (1, "xtables lock busy", False), (2, "resource failure", False)):
            with self.subTest(rc=rc, message=message):
                self.failures = {("-L", "WINVPN-SSH-RECOVERY"): (rc, message)}
                self.check(allowed)

    def test_no_mutation_or_extra_locks(self):
        self.check()
        self.assertTrue(all("-w" in call and call[2] == "10" and ("-S" in call or "-L" in call)
                            for call in self.calls))

    def test_admitted_prefixes_and_checked_bodies(self):
        prefixes = ["-j WINVPN-SSH-RECOVERY", "-p tcp -m multiport --dports 80,443 -j WINVPN-STEALTH-CF",
                    "-d 10.10.0.1/32 -i winn3gw0 -j WINN3GW-INPUT",
                    "-p tcp -m multiport --dports 22 -j f2b-sshd", "-s 1.2.3.4/32 -j DROP"]
        self.rules["WINVPN-STEALTH-CF"] = "-A WINVPN-STEALTH-CF -i lo -j RETURN\n-A WINVPN-STEALTH-CF -s 1.2.3.0/24 -j RETURN\n-A WINVPN-STEALTH-CF -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN\n-A WINVPN-STEALTH-CF -j DROP\n"
        self.rules["f2b-sshd"] = "-A f2b-sshd -s 1.2.3.4/32 -j REJECT --reject-with icmp-port-unreachable\n-A f2b-sshd -j RETURN\n"
        for prefix in prefixes:
            with self.subTest(prefix=prefix):
                self.rules["INPUT"] = "-A INPUT " + prefix + "\n-A INPUT -j WINVPN-LOCAL-SERVING\n"
                self.check()

    def test_accept_unknown_jump_goto_and_negation_fail_s1(self):
        for prefix in ("-p tcp --dport 443 -j ACCEPT", "-j UNKNOWN", "-g WINVPN-LOCAL-SERVING",
                       "! -i winn3gw0 -d 10.10.0.1/32 -j WINN3GW-INPUT",
                       "-d 10.10.0.1/32 -i eth0 -j WINN3GW-INPUT",
                       "-p tcp -m multiport --dports 22,443 -j f2b-sshd"):
            with self.subTest(prefix=prefix):
                self.rules["INPUT"] = "-A INPUT " + prefix + "\n-A INPUT -j WINVPN-LOCAL-SERVING\n"
                self.check(False)

    def test_recovery_shape_is_exact(self):
        good = "-A WINVPN-SSH-RECOVERY -s 1.2.3.4/32 -p tcp -m tcp --dport 22 -j ACCEPT\n"
        self.rules["WINVPN-SSH-RECOVERY"] = good
        self.check()
        for bad in (good * 2, good.replace("/32", "/24"), good.replace("22", "443"),
                    good.replace("tcp", "udp"), good.replace("ACCEPT", "RETURN"),
                    good.replace("1.2.3.4", "999.2.3.4")):
            with self.subTest(bad=bad):
                self.rules["WINVPN-SSH-RECOVERY"] = bad
                self.check(False)

    def test_cf_and_fail2ban_bodies_cannot_accept_or_jump(self):
        for chain, prefix, final in (("WINVPN-STEALTH-CF", "-p tcp -m multiport --dports 80,443", "DROP"),
                                     ("f2b-sshd", "-p tcp -m multiport --dports 22", "RETURN")):
            self.rules["INPUT"] = f"-A INPUT {prefix} -j {chain}\n-A INPUT -j WINVPN-LOCAL-SERVING\n"
            for body in (f"-A {chain} -j ACCEPT\n", f"-A {chain} -g OTHER\n", f"-A {chain} ! -s 1.2.3.4/32 -j RETURN\n",
                         f"-A {chain} -p tcp -j RETURN\n", f"-A {chain} -j OTHER\n"):
                with self.subTest(chain=chain, body=body):
                    self.rules[chain] = body + f"-A {chain} -j {final}\n"
                    self.check(False)

    def test_cf_and_fail2ban_final_rule_must_be_exact(self):
        for chain, prefix, first, finals in (
            ("WINVPN-STEALTH-CF", "-p tcp -m multiport --dports 80,443", "-A WINVPN-STEALTH-CF -i lo -j RETURN\n",
             ("", "-A WINVPN-STEALTH-CF -j RETURN\n", "-A WINVPN-STEALTH-CF -s 1.2.3.4/32 -j DROP\n")),
            ("f2b-sshd", "-p tcp -m multiport --dports 22",
             "-A f2b-sshd -s 1.2.3.4/32 -j REJECT --reject-with icmp-port-unreachable\n",
             ("", "-A f2b-sshd -j DROP\n", "-A f2b-sshd -s 1.2.3.4/32 -j RETURN\n")),
        ):
            self.rules["INPUT"] = f"-A INPUT {prefix} -j {chain}\n-A INPUT -j WINVPN-LOCAL-SERVING\n"
            for final in finals:
                with self.subTest(chain=chain, final=final):
                    self.rules[chain] = first + final
                    self.check(False)

    def test_latch_exactness_and_structural_reassert_inspection(self):
        good = self.rules["WINVPN-LOCAL-SERVING"]
        for bad in ("", good + "-A WINVPN-LOCAL-SERVING -j DROP\n", good.replace("REPLY", "ORIGINAL"),
                    good.replace("DROP", "RETURN"), good.replace("-i lo", "-i eth0")):
            with self.subTest(bad=bad):
                self.rules["WINVPN-LOCAL-SERVING"] = bad
                self.check(False)
                self.check(True, "structure")


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.addCleanup(self.temp.cleanup)
        self.proc = Path(self.temp.name)
        self.process(1, 0, "systemd")
        self.process(10, 1, "installer")
        self.detector = SESSION.Detector(10, self.proc)
        self.responses = {"Remote": "yes\n", "RemoteHost": "127.0.0.1\n", "tcp": "", "unix": ""}
        self.commands = []
        def command(args):
            self.commands.append(args)
            if args[0] == "loginctl":
                return self.responses[args[3].split("=", 1)[1]]
            return self.responses["tcp" if "-Htnp" in args else "unix"]
        self.detector.command = command

    def process(self, pid, parent, comm, cgroup="0::/system.slice/detached.service\n"):
        directory = self.proc / str(pid)
        directory.mkdir(exist_ok=True)
        (directory / "status").write_text(f"PPid:\t{parent}\n")
        (directory / "comm").write_text(comm + "\n")
        (directory / "cgroup").write_text(cgroup)
        (directory / "fd").mkdir(exist_ok=True)
        for fd in range(3):
            path = directory / "fd" / str(fd)
            if path.is_symlink():
                path.unlink()
            path.symlink_to("/dev/null")

    def descriptor(self, pid, fd, target):
        path = self.proc / str(pid) / "fd" / str(fd)
        path.unlink()
        path.symlink_to(target)

    def test_script_entry_treats_an_unevaluable_signal_as_direct(self):
        source = embedded("WINS_S4_SESSION_PY").replace('proc=Path("/proc")', 'proc=Path("/nonexistent-s4-proc")')
        result = subprocess.run([sys.executable, "-c", source, "1"], capture_output=True, text=True,
                                env=dict(os.environ, SSH_CONNECTION=""), timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("winn3 session:", result.stderr)

    def test_environment_signal_catches_direct_and_ipv6(self):
        for host in ("1.2.3.4", "2001:db8::1", "invalid"):
            self.assertTrue(self.detector.direct(host + " 123 4.5.6.7 22"))

    def test_console_and_all_loopback_forms_pass(self):
        for host in ("127.0.0.1", "127.23.4.5", "::1", "::ffff:127.2.3.4"):
            self.assertFalse(self.detector.direct(host + " 123 4.5.6.7 22"))
        self.assertFalse(self.detector.direct(""))

    def test_sudo_session_signal_survives_missing_environment(self):
        self.process(10, 1, "sudo", "0::/user.slice/session-9.scope\n")
        self.responses["RemoteHost"] = "1.2.3.4\n"
        self.assertTrue(self.detector.direct(""))

    def test_loopback_session_ancestry_allows_listener_without_connection(self):
        self.process(10, 11, "sudo", "0::/user.slice/session-9.scope\n")
        self.process(11, 12, "sshd-session", "0::/user.slice/session-9.scope\n")
        self.process(12, 1, "sshd")
        self.responses["tcp"] = 'ESTAB 0 0 127.0.0.1:22 127.0.0.1:33000 users:(("sshd-session",pid=11,fd=3))\n'
        self.assertFalse(self.detector.direct(""))
        self.assertEqual(sum("-Htnp" in call for call in self.commands), 1)

    def test_ss_rows_with_and_without_state_column(self):
        self.process(10, 11, "sudo", "0::/user.slice/session-9.scope\n")
        self.process(11, 1, "sshd-session")
        for row in ('0 0 127.0.0.1:22 127.0.0.1:33000 users:(("sshd",pid=11,fd=3))',
                    'ESTAB 0 0 [::1]:22 [::1]:33000 users:(("sshd",pid=11,fd=3))'):
            with self.subTest(row=row):
                self.detector.tcp = None
                self.detector.visited.clear()
                self.responses["tcp"] = row
                self.assertFalse(self.detector.direct(""))

    def test_any_external_ancestral_connection_is_direct(self):
        self.process(10, 11, "sudo", "0::/user.slice/session-9.scope\n")
        self.process(11, 1, "sshd-session")
        self.responses["tcp"] = 'ESTAB 0 0 4.5.6.7:22 1.2.3.4:33000 users:(("sshd",pid=11,fd=3))\n'
        self.assertTrue(self.detector.direct(""))

    def test_missing_cgroup_status_comm_and_empty_sshd_fail_closed(self):
        for name in ("cgroup", "status", "comm"):
            with self.subTest(name=name):
                path = self.proc / "10" / name
                original = path.read_text()
                path.unlink()
                with self.assertRaises(SESSION.Uncertain):
                    SESSION.Detector(10, self.proc).direct("")
                path.write_text(original)
        self.process(10, 11, "sudo")
        self.process(11, 1, "sshd")
        with self.assertRaisesRegex(SESSION.Uncertain, "no established"):
            self.detector.direct("")

    def test_pts_in_every_non_session_cgroup_refuses(self):
        for group in ("system.slice/run.service", "user.slice/user@1000.service/tmux-spawn-1.scope", "run-9.scope"):
            with self.subTest(group=group):
                self.process(10, 1, "installer", "0::/" + group + "\n")
                self.descriptor(10, 0, "/dev/pts/9")
                self.assertTrue(SESSION.Detector(10, self.proc).direct(""))

    def test_pipe_remote_holder_and_recursive_outside_session_holder(self):
        self.descriptor(10, 1, "pipe:[101]")
        self.process(20, 1, "tee")
        self.descriptor(20, 0, "pipe:[101]")
        self.descriptor(20, 1, "pipe:[102]")
        self.process(30, 1, "systemd-run", "0::/session-7.scope\n")
        self.descriptor(30, 1, "pipe:[102]")
        self.responses["RemoteHost"] = "1.2.3.4\n"
        self.assertTrue(self.detector.direct(""))

    def test_detached_tee_to_journald_is_allowed(self):
        self.descriptor(10, 1, "pipe:[101]")
        self.process(20, 1, "tee")
        self.descriptor(20, 0, "pipe:[101]")
        self.descriptor(20, 1, "socket:[202]")
        self.process(30, 1, "systemd-journald")
        self.descriptor(30, 0, "socket:[303]")
        self.responses["unix"] = 'u_str ESTAB 0 0 * 202 * 303 users:(("systemd-journald",pid=30,fd=0))\n'
        self.assertFalse(self.detector.direct(""))
        self.assertEqual(sum("-Hxp" in call for call in self.commands), 1)

    def test_pid1_installer_descendants_excluded_and_empty_pipe_refuses(self):
        self.descriptor(10, 1, "pipe:[101]")
        self.descriptor(1, 1, "pipe:[101]")
        self.process(20, 10, "scanner")
        self.descriptor(20, 0, "pipe:[101]")
        with self.assertRaisesRegex(SESSION.Uncertain, "no remaining holder"):
            self.detector.direct("")

    def test_eight_holder_cutoff_is_direct_uncertainty(self):
        self.descriptor(10, 1, "pipe:[100]")
        for index in range(9):
            pid = 20 + index
            self.process(pid, 1, "tee")
            self.descriptor(pid, 0, f"pipe:[{100 + index}]")
            self.descriptor(pid, 1, f"pipe:[{101 + index}]")
        with self.assertRaisesRegex(SESSION.Uncertain, "eight holders"):
            self.detector.direct("")


class IdentityAndWiringTests(unittest.TestCase):
    def test_openssl_public_comparisons_and_full_ed_seed_are_enforced(self):
        bodies = {"static.key": b"01" * 32, "public/static.pub": b"02" * 32,
                  "auth_ed25519.seed": b"03" * 32 + b"04" * 32, "public/auth_ed25519.pub": b"04" * 32}
        calls = []
        def pkey(command, **kwargs):
            calls.append((command, kwargs["input"]))
            private = kwargs["input"]
            if private.startswith(bytes.fromhex("302e020100300506032b656e04220420")):
                public = bytes.fromhex("302a300506032b656e032100") + b"\x02" * 32
            else:
                public = bytes.fromhex("302a300506032b6570032100") + b"\x04" * 32
            return types.SimpleNamespace(returncode=0, stdout=public)
        with patch.object(NODE.subprocess, "run", pkey):
            CHECK_HALVES(bodies)
            self.assertEqual(len(calls), 2)
            self.assertTrue(all(len(body) == 48 for command, body in calls))
            self.assertTrue(all("01" * 32 not in command and "03" * 32 not in command for command, body in calls))
            with self.assertRaisesRegex(NODE.Refusal, "embedded public half"):
                CHECK_HALVES({**bodies, "auth_ed25519.seed": b"03" * 32 + b"05" * 32})
            with self.assertRaisesRegex(NODE.Refusal, "public half does not match"):
                CHECK_HALVES({**bodies, "public/static.pub": b"06" * 32})
        with patch.object(NODE.subprocess, "run", return_value=types.SimpleNamespace(returncode=1, stdout=b"")):
            with self.assertRaisesRegex(NODE.Refusal, "public half does not match"):
                CHECK_HALVES(bodies)

    def test_h1_descriptor_digest_differs_from_identity_file_hash(self):
        identity = {"slug": "fixture", "gateway_id": "fixture-gw1", "endpoint": "1.2.3.4:9111",
                    "static_pub_hex": "01" * 32, "auth_ed25519_hex": "02" * 32,
                    "auth_mldsa65_hex": "03" * 1952, "inner_router_v4": "10.10.0.1",
                    "inner_resolver_v4": "10.10.0.1", "admission_fingerprint": "1234567890abcdef",
                    "path_mtu": 1450, "plan": "udp", "credential_record_sha256": "f" * 64,
                    "ssh_host_ed25519_key": "ssh-ed25519 fixture"}
        descriptor = {"node": "fixture", "gateway_id": base64.b64encode(b"fixture-gw1").decode(),
                      "endpoint": "1.2.3.4:9111", "static_pub": base64.b64encode(b"\x01" * 32).decode(),
                      "auth_ed25519": base64.b64encode(b"\x02" * 32).decode(),
                      "auth_mldsa65": base64.b64encode(b"\x03" * 1952).decode(),
                      "inner_router_v4": "10.10.0.1", "inner_resolver_v4": "10.10.0.1",
                      "admission_fingerprint": "1234567890abcdef"}
        expected = hashlib.sha256(json.dumps(descriptor, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        self.assertEqual(NODE.identity_digest(identity), expected)
        self.assertNotEqual(expected, NODE.digest(NODE.canonical(identity)))

    def test_both_exit_traps_route_to_ordered_handler(self):
        self.assertIn('trap \'winn3_installer_exit "$?" 0\' EXIT', SOURCE)
        self.assertIn('trap \'winn3_installer_exit "$?" 1\' EXIT', SOURCE)
        body = shell_function("winn3_installer_exit")
        names = ["winn3_late_failure_on_exit", "deploy_firewall_rollback_on_exit",
                 "winn3_late_failure_reassert", "cloudflare_redirect_transaction_on_exit", "winn3_late_settle"]
        self.assertEqual(sorted(names, key=body.index), names)
        self.assertNotIn("install-failed", shell_function("winn3_late_failure_on_exit"))

    def test_late_handler_armed_through_last_main_statement(self):
        main = shell_function("main")
        phase_b = shell_function("winn3gw_phase_b")
        self.assertLess(phase_b.index("WINN3_LATE_ARMED=1"), phase_b.index("winn3gw_render_helper"))
        self.assertTrue(main.rstrip().endswith("WINN3_LATE_ARMED=0\n}"))
        self.assertLess(main.index("winn3gw_clear_late_record_after_postflight"), main.index("complete_data_deployment_after_postflight"))

    def test_offnode_check_is_pinned_and_phase_a_checks_it_before_withdrawal(self):
        phase_a = shell_function("winn3gw_phase_a")
        self.assertTrue(phase_a.rstrip().endswith("winn3_offnode_check_digest_ok || return 1\n}"))
        self.assertNotIn("whole install refused before mutation", phase_a)
        main = shell_function("main")
        self.assertLess(main.index("preflight_data_plane"), main.index("begin_data_deployment_withdrawal_before_mutation"))
        phase_b = shell_function("winn3gw_phase_b")
        self.assertLess(phase_b.index("winn3_write_offnode_check"), phase_b.index("WINN3_LATE_ARMED=1"))
        pinned = re.search(r"^WINN3_OFFNODE_CHECK_SHA256=([0-9a-f]{64})$", SOURCE, re.M).group(1)
        self.assertEqual(pinned, hashlib.sha256(OFFNODE.encode()).hexdigest())

    def test_offnode_check_differs_from_certified_l46_v5_only_by_the_canary_exemption(self):
        text = OFFNODE
        for added, original in (
            (" --canary-pubkey BASE64\n", "\n"),
            ("CANARY_PUBKEY=\n", ""),
            ("    --canary-pubkey) CANARY_PUBKEY=${2:-}; shift 2 ;;\n", ""),
            ('[[ -z $CANARY_PUBKEY || $CANARY_PUBKEY =~ ^[A-Za-z0-9+/]{43}=$ ]] || { echo "[l46_node_check] usage error: bad --canary-pubkey" >&2; exit 2; }\n', ""),
            # D5 (FREE-CAP): the registry validator accepts the gateway's own
            # optional tier word, the second narrow change from the certified v5.
            ('{"static_public", "inner_v4", "not_after", "tier"}', '{"static_public", "inner_v4", "not_after"}'),
            # R25: the unit's main pid comes from ExecMainPID, not from the pid= field of
            # ExecStart (a daemon-reload resets that field to 0), the third narrow change.
            ('gw_main=$(systemctl show -p ExecMainPID --value "$GW_UNIT" </dev/null 2>/dev/null || echo "")\n'
             '[[ $gw_main =~ ^[0-9]+$ ]] || gw_main=""\n', ""),
            (" L46_EXECMAINPID=$gw_main", ""),
            ('        want, _ = execstart_tokens(os.environ.get("L46_EXECSTART", ""))\n'
             '        # The pid of the unit\'s main command is ExecMainPID, which a daemon-reload keeps.\n'
             '        # The pid= field inside ExecStart is reset to 0 by one (the SSH recovery guard runs\n'
             '        # one), so it cannot say whether MainPID is the process systemd started.\n'
             '        main_pid = os.environ.get("L46_EXECMAINPID", "")\n'
             '        if main_pid.isdigit() and int(main_pid) not in (0, pid):\n'
             '            raise ValueError("execstart_pid_differs")\n',
             '        want, sd_pid = execstart_tokens(os.environ.get("L46_EXECSTART", ""))\n'
             '        if sd_pid is not None and sd_pid != pid:\n'
             '            raise ValueError("execstart_pid_differs")\n'),
            ('            # The optional tier word (cmd/winn3-gateway peer_registry.go): the\n'
             '            # hub writes it only for a node whose binary reported\n'
             '            # peer-registry-tier, omitted means premium, and it is never\n'
             '            # anything but the two words. A service class, not an identity.\n'
             '            if "tier" in p and p["tier"] not in ("free", "premium"):\n'
             '                raise ValueError("invalid_traffic_tier")\n', ""),
        ):
            self.assertEqual(text.count(added), 1, added)
            text = text.replace(added, original)
        exemption = re.search(r"    # Design 2\.9: the one exemption\..*?\n    fi\n", text, re.S).group(0)
        text = text.replace(exemption, '    echo "AWGPEER $(d16 "$key") $class $(d16 "$ips_norm") $hs"\n')
        # SHA-256 of offnode_node_check.sh v5 in the lane's SHA256SUMS.txt.
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(),
                         "872cdf9cb4254d1d23d422ed8e2c22fda29138254a2ec89d8e95de0a05a72a2d")

    def test_host_key_signature_is_made_by_production_code_and_verifies_only_for_the_signed_bytes_and_key(self):
        root = Path(tempfile.mkdtemp(dir=os.environ.get("TMPDIR")))
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        for name in ("host", "other"):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(root / name)], check=True)
        public = root / "public"
        bin_dir = root / "bin"
        bin_dir.mkdir()
        for name, body in (("install", '#!/bin/bash\nargs=()\nwhile (($#)); do case "$1" in -o|-g) shift 2 ;; *) args+=("$1"); shift ;; esac; done\nexec /usr/bin/install "${args[@]}"\n'),
                           ("sync", "#!/bin/bash\nexit 0\n")):
            (bin_dir / name).write_text(body)
            (bin_dir / name).chmod(0o755)

        def text(function, host):
            return (shell_function(function).replace("/etc/winn/public", str(public))
                    .replace("/run/winn3-allowed-signers", str(root / "allowed"))
                    .replace("/etc/ssh/ssh_host_ed25519_key", str(root / host)))

        def run(program):
            return subprocess.run([BASH, "-c", program], capture_output=True, text=True, timeout=60,
                                  env=dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}"))
        prefix = ('winn3_node_tool() { mkdir -p "' + str(public) + '"; printf \'{"slug":"fixture"}\' > "' + str(public)
                  + '/gateway-identity.json"; printf digest; }\nNODE_SLUG=fixture\n')
        signed = run(prefix + text("winn3gw_verify_identity_signature", "host") + "\n"
                     + text("winn3gw_sign_identity", "host") + "\nwinn3gw_sign_identity")
        self.assertEqual(signed.returncode, 0, signed.stderr)
        self.assertTrue((public / "gateway-identity.json.sshsig").exists())
        self.assertFalse(list(public.glob(".winn3-sign.*")))

        def verify(host):
            return run(text("winn3gw_verify_identity_signature", host)
                       + "\nwinn3gw_verify_identity_signature").returncode
        self.assertEqual(verify("host"), 0)
        self.assertNotEqual(verify("other"), 0)
        (public / "gateway-identity.json").write_text('{"slug":"changed"}')
        self.assertNotEqual(verify("host"), 0)

    def offnode_lines(self, peers, *arguments):
        root = Path(tempfile.mkdtemp(dir=os.environ.get("TMPDIR")))
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        bin_dir = root / "bin"
        bin_dir.mkdir()
        listing = "".join(f"{key}\t{ips}\n" for key, ips in peers)
        handshakes = "".join(f"{key}\t0\n" for key, _ in peers)
        (root / "peers").write_text("".join(f"{key}\n" for key, _ in peers))
        (root / "allowed").write_text(listing)
        (root / "handshakes").write_text(handshakes)
        stubs = {
            "docker": '#!/bin/bash\ncase "$1 $2" in\n"ps --format") echo awg ;;\n"exec awg") case "$6" in peers) cat "$ROOT/peers" ;; allowed-ips) cat "$ROOT/allowed" ;; latest-handshakes) cat "$ROOT/handshakes" ;; esac ;;\nesac\n',
            "systemctl": "#!/bin/bash\nexit 0\n",
            "journalctl": "#!/bin/bash\nexit 0\n",
            "sha256sum": '#!/bin/bash\nexec shasum -a 256 "$@"\n',
        }
        for name, body in stubs.items():
            (bin_dir / name).write_text(body)
            (bin_dir / name).chmod(0o755)
        script = root / "wins-offnode-check"
        script.write_text(OFFNODE)
        environment = dict(os.environ, ROOT=str(root), PATH=f"{bin_dir}:{os.environ['PATH']}")
        result = subprocess.run([BASH, str(script), "--registry", str(root / "missing.json"), *arguments],
                                env=environment, capture_output=True, text=True, timeout=60)
        return [line for line in result.stdout.splitlines() if line.startswith("AWG")], result

    def test_canary_exemption_is_exact(self):
        canary = "A" * 43 + "="
        other = "B" * 43 + "="
        exact = [(canary, "10.8.255.1/32")]
        lines, _ = self.offnode_lines(exact, "--canary-pubkey", canary)
        self.assertTrue(lines[0].startswith("AWGSYSPEER ") and " canary " in lines[0], lines)
        for peers, arguments in (
            (exact, ()),
            ([(other, "10.8.255.1/32")], ("--canary-pubkey", canary)),
            ([(canary, "10.8.255.1/32 10.8.255.2/32")], ("--canary-pubkey", canary)),
            ([(canary, "10.8.255.0/24")], ("--canary-pubkey", canary)),
            ([(canary, "10.8.255.2/32")], ("--canary-pubkey", canary)),
            ([(other, "10.8.255.2/32")], ("--canary-pubkey", canary)),
        ):
            with self.subTest(peers=peers, arguments=arguments):
                lines, _ = self.offnode_lines(peers, *arguments)
                self.assertTrue(lines[0].startswith("AWGPEER ") and " core_exit " in lines[0], lines)
        _, result = self.offnode_lines(exact, "--canary-pubkey", "not-a-key")
        self.assertEqual(result.returncode, 2)

    def gateway_facts(self, exec_main_pid, exec_start_pid="0", main_pid="4242"):
        """The GW line of the node check against a fake /proc and a fake systemctl."""
        root = Path(tempfile.mkdtemp(dir=os.environ.get("TMPDIR")))
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        bin_dir = root / "bin"
        bin_dir.mkdir()
        registry = "/etc/winn/winn3-peers.json"
        argv = ["/usr/local/libexec/winn/winn3-gateway", "-mode", "serve", "-forward", "-peer-registry", registry]
        proc = root / "proc"
        (proc / "4242").mkdir(parents=True)
        (proc / "4242" / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")
        (proc / "4242" / "status").write_text("Uid:\t999\t999\t999\t999\nGid:\t999\t999\t999\t999\nGroups:\t999\n")
        execstart = ("{ path=" + argv[0] + " ; argv[]=" + " ".join(argv) + " ; ignore_errors=no ; "
                     "start_time=[n/a] ; stop_time=[n/a] ; pid=" + exec_start_pid + " ; code=(null) ; status=0/0 }")
        (root / "execstart").write_text(execstart + "\n")
        stubs = {
            "docker": '#!/bin/bash\ncase "$1 $2" in\n"ps --format") echo awg ;;\n"exec awg") ;;\nesac\n',
            "systemctl": ('#!/bin/bash\ncase "$*" in\n'
                          '  "is-active winn3-gateway") echo active ;;\n'
                          '  "show -p MainPID --value winn3-gateway") echo ' + main_pid + ' ;;\n'
                          '  "show -p ExecMainPID --value winn3-gateway") echo "' + exec_main_pid + '" ;;\n'
                          '  "show -p ExecMainStartTimestampMonotonic --value winn3-gateway") echo 1000000 ;;\n'
                          '  "show -p ExecStart --value winn3-gateway") cat "$ROOT/execstart" ;;\n'
                          'esac\nexit 0\n'),
            "journalctl": "#!/bin/bash\nexit 0\n",
            "sha256sum": '#!/bin/bash\nexec shasum -a 256 "$@"\n',
        }
        for name, body in stubs.items():
            (bin_dir / name).write_text(body)
            (bin_dir / name).chmod(0o755)
        script = root / "wins-offnode-check"
        script.write_text(OFFNODE)
        environment = dict(os.environ, ROOT=str(root), PATH=f"{bin_dir}:{os.environ['PATH']}")
        result = subprocess.run([BASH, str(script), "--registry", str(root / "missing.json"), "--proc-root", str(proc)],
                                env=environment, capture_output=True, text=True, timeout=60)
        lines = [line for line in result.stdout.splitlines() if line.startswith("GW ")]
        self.assertEqual(len(lines), 1, result.stdout + result.stderr)
        return lines[0]

    def test_the_gateway_pid_is_judged_by_execmainpid_not_the_execstart_pid_field(self):
        # Three nodes, 2026-10-19: a daemon-reload (the SSH recovery guard runs
        # one) resets the pid= field inside ExecStart to 0 while the gateway keeps
        # running, and the check then reported argv_check=execstart_pid_differs.
        for label, exec_main_pid, exec_start_pid, expected in (
            ("reset ExecStart pid, ExecMainPID matches", "4242", "0", "argv_check=ok"),
            ("ExecStart pid is stale, ExecMainPID matches", "4242", "777", "argv_check=ok"),
            ("ExecMainPID unknown", "", "0", "argv_check=ok"),
            ("ExecMainPID reads 0", "0", "0", "argv_check=ok"),
            ("ExecMainPID is another process", "4243", "4242", "argv_check=execstart_pid_differs"),
        ):
            with self.subTest(label):
                line = self.gateway_facts(exec_main_pid, exec_start_pid)
                self.assertIn(expected, line.split(), line)
                self.assertIn("pid_known=1", line.split(), line)

    def test_credential_and_gateway_moved_block_remains_byte_identical(self):
        before = ROOT / ".s4-validation/entry/server/wins_data_plane_setup_ONETOUCH.sh"
        if not before.exists():
            self.skipTest("entry receipt unavailable")
        marker = "# --- begin winn3 gateway block ---"
        end = "# --- end winn3 gateway block ---"
        old = before.read_text().split(marker, 1)[1].split(end, 1)[0]
        new = SOURCE.split(marker, 1)[1].split(end, 1)[0]
        self.assertEqual(old, new)

    def test_activation_uses_both_supervisors_and_no_parent_start(self):
        body = shell_function("wins_serving_start")
        self.assertIn("flock -w 90 6", body)
        self.assertIn("timeout -k 5 100 systemd-run --scope --quiet --collect", body)
        self.assertIn("--property=RuntimeMaxSec=100 --property=TimeoutStopSec=5", body)
        self.assertNotIn("systemctl start", body)
        self.assertNotIn("systemctl restart", body)

    def test_rollback_guard_has_both_bounds_and_inherited_fd7(self):
        body = shell_function("deploy_firewall_rollback_on_exit")
        self.assertIn("WINS_NODE_SSH_RECOVERY_LOCK_WAIT=20", body)
        self.assertIn("WINS_FIREWALL_LOCK_WAIT=20", body)
        self.assertIn('WINS_FIREWALL_LOCK_HELD="${WINS_FW_LOCK_OWNED:-0}"', body)

    def test_guard_transition_has_one_guard_lock_and_whole_transition_fd7(self):
        for marker in ("WINS_NODE_LOCAL_SERVING_GUARD", "WINS_NODE_SSH_RECOVERY_GUARD"):
            body = embedded(marker)
            self.assertIn('if [[ "${1:-}" != status ]] && ! guard_hold_firewall_lock', body)
            self.assertIn("wins_late_failure_hold && ! wins_latch_rules_dominate", body)
        self.assertEqual(body.count("\nlock_guard\n"), 1)
        self.assertNotIn("  lock_guard\n", body)


class ShellBehaviorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.addCleanup(self.temp.cleanup)
        self.area = Path(self.temp.name)
        (self.area / "locks").mkdir()
        self.trace = self.area / "trace"

    def run_shell(self, source, rc=0):
        env = dict(os.environ, TEST_TRACE=str(self.trace))
        result = subprocess.run([BASH, "-c", source], env=env, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, rc, result.stderr + result.stdout)
        return self.trace.read_text().splitlines() if self.trace.exists() else []

    def test_exit_trace_orders_record_fence_stop_rollback_and_settle(self):
        for unavailable in (0, 1):
            with self.subTest(unavailable=unavailable):
                self.trace.write_text("")
                definitions = "\n".join(shell_function(n) for n in (
                    "winn3_installer_exit", "winn3_late_failure_on_exit", "winn3_late_failure_reassert"))
                definitions = definitions.replace("/run/lock", str(self.area / "locks"))
                script = '''set -Eeuo pipefail
trace() { printf '%s\\n' "$*" >> "$TEST_TRACE"; }
data_plane_installer_sha256() { printf '%064d' 0; }
winn3_late_record() { trace record; }
install() { trace install; }
flock() { trace "flock $*"; return 0; }
timeout() { trace "stop $*"; return 0; }
winn3_late_fence() { trace fence; WINN3_LATE_FENCE=done; }
winn3_installer_fw_lock() { trace fd7; return FW_RESULT; }
winn3_installer_fw_unlock() { trace unlock7; }
winn3_late_repair_live() { trace "repair $*"; }
wins_latch_rules_dominate() { trace gate; return 1; }
wins_latch_rules_inspect() { trace structure; return 1; }
winn3_latch_file_safe() { return 1; }
winn3_late_fallback() { trace "fallback $*"; }
deploy_firewall_rollback_on_exit() { trace rollback; set -e; }
cloudflare_redirect_transaction_on_exit() { trace cloudflare; }
winn3_late_settle() { trace settle; }
'''.replace("FW_RESULT", str(unavailable))
                script += definitions + '''
WINN3_LATE_ARMED=1
trap 'winn3_installer_exit "$?" 1' EXIT
exit 9
'''
                lines = self.run_shell(script, 9)
                self.assertLess(lines.index("record"), lines.index("fence"))
                self.assertLess(lines.index("fence"), next(i for i, line in enumerate(lines) if line.startswith("stop ")))
                self.assertLess(lines.index("fallback initial"), lines.index("rollback"))
                self.assertLess(lines.index("rollback"), lines.index("repair resume"))
                self.assertLess(lines.index("repair resume"), lines.index("cloudflare"))
                self.assertLess(lines.index("cloudflare"), lines.index("settle"))
                self.assertEqual(lines.count("record"), 2)
                self.assertEqual("unlock7" in lines, unavailable == 0)

    def test_unarmed_exit_and_zero_status_have_no_late_actions(self):
        definition = shell_function("winn3_late_failure_on_exit")
        for armed, status in ((0, 9), (1, 0)):
            script = 'set -Eeuo pipefail\nwinn3_late_record() { exit 77; }\n' + definition
            script += f"\nWINN3_LATE_ARMED={armed}\nwinn3_late_failure_on_exit {status}\n"
            self.run_shell(script)

    def test_phase_calls_preserve_nested_renderer_error_exits(self):
        for caller, phase in (("preflight_data_plane", "a"), ("main", "b"),
                              ("main", "c"), ("postflight_data_plane", "d")):
            with self.subTest(caller=caller, phase=phase):
                self.assertRegex(shell_function(caller), r"(?m)^  winn3gw_phase_" + phase + r"$")
        script = '''set -Eeuo pipefail
trace() { printf '%s\n' "$*" >> "$TEST_TRACE"; }
winn3gw_bundle_digest() { printf fixture; }
check_gateway_egress_mtu() { return 0; }
invalidate_gateway_code_stamp() { return 0; }
ensure_service_user() { trace failure; false; trace continued; }
'''
        script += shell_function("winn3gw_phase_b") + '\nwinn3gw_phase_b\nprintf finished >> "$TEST_TRACE"\n'
        self.assertEqual(self.run_shell(script, 1), ["failure"])

    def test_serving_child_holds_on_regular_and_symlink_records(self):
        record = self.area / "record"
        activator = self.area / "activate"
        # Use the exact production child statements, with only its record path mapped.
        child = shell_function("wins_late_failure_hold").replace("/var/lib/winsvpn/winn3-late-failure.json", str(record))
        activator.write_text('#!/bin/bash\nset -Eeuo pipefail\n' + child + '\nwins_late_failure_hold && exit 3\nexec "$@"\n')
        activator.chmod(0o755)
        starter = self.area / "start"
        starter.write_text('#!/bin/sh\nprintf started >> "$TEST_TRACE"\n')
        starter.chmod(0o755)
        definition = shell_function("wins_serving_start").replace("/run/lock", str(self.area / "locks"))
        definition = definition.replace("/usr/local/libexec/winsvpn/wins-serving-activate", str(activator))
        stubs = '''set -Eeuo pipefail
install() { return 0; }
flock() { return 0; }
timeout() { [[ "$1 $2 $3" == '-k 5 100' ]] || exit 91; shift 3; "$@"; }
systemd-run() {
  [[ "$1 $2 $3" == '--scope --quiet --collect' ]] || exit 92
  [[ "$5" == --property=RuntimeMaxSec=100 && "$6" == --property=TimeoutStopSec=5 ]] || exit 93
  shift 6
  "$@"
}
'''
        for state in ("absent", "regular", "symlink"):
            with self.subTest(state=state):
                if os.path.lexists(record):
                    record.unlink()
                if state == "regular":
                    record.touch()
                elif state == "symlink":
                    record.symlink_to(self.area / "missing")
                self.trace.write_text("")
                script = stubs + definition + f'\nwins_serving_start fixture "{starter}"\n'
                self.run_shell(script)
                self.assertEqual(self.trace.read_text(), "started" if state == "absent" else "")

    def test_late_persistence_gate_leaves_previous_rules_byte_identical(self):
        for marker in ("WINS_NODE_SSH_RECOVERY_GUARD", "WINS_NODE_LOCAL_SERVING_GUARD"):
            with self.subTest(marker=marker):
                body = embedded(marker)
                start = body.index("persist_firewall() {\n")
                end = body.index("\npersist_firewall_locked()", start)
                function = body[start:end]
                rules = self.area / "rules.v4"
                rules.write_bytes(b"original saved image\n")
                stubs = f'''set -Eeuo pipefail
wins_fw_lock() {{ return 0; }}
wins_fw_unlock() {{ return 0; }}
wins_late_failure_hold() {{ return 0; }}
wins_latch_rules_dominate() {{ return 1; }}
persist_firewall_locked() {{ printf corrupted > "{rules}"; }}
'''
                result = subprocess.run([BASH, "-c", stubs + function + '\nif persist_firewall; then exit 70; fi\n'],
                                        capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("persistence gate refused", result.stderr)
                self.assertEqual(rules.read_bytes(), b"original saved image\n")

    def test_declared_shared_predicate_is_rendered_into_each_program(self):
        names = ("wins_late_failure_hold", "wins_latch_rules_inspect", "wins_latch_rules_dominate")
        definitions = "\n".join(shell_function(name) for name in (*names, "winn3gw_render_chains", "winn3_prepend_shared_functions"))
        for marker in ("WINS_NODE_SSH_RECOVERY_GUARD", "WINS_NODE_LOCAL_SERVING_GUARD", "WINS_EDGE_EOF"):
            with self.subTest(marker=marker):
                target = self.area / (marker + ".sh")
                target.write_text(embedded(marker))
                target.chmod(0o700)
                script = 'set -Eeuo pipefail\nstat() { printf 700; }\nchown() { return 0; }\n' + definitions
                script += f'\nwinn3_prepend_shared_functions "{target}" ' + " ".join(names) + '\n'
                self.run_shell(script)
                output = target.read_text()
                for name in names:
                    self.assertIn(name + " ()", output)
                result = subprocess.run([BASH, "-n", str(target)], capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_forward_and_resolver_zero_mutants_are_killed(self):
        actual = shell_function("winn3gw_resolve_onetouch")
        setup = '''set -Eeuo pipefail
err() { printf '%s\\n' "$*" >&2; }
winn3_node_tool() { printf '\\n\\n\\n\\n'; }
WINN3_ONETOUCH_FORWARD_REQUESTED=""
WINN3_ONETOUCH_RESOLVER_REQUESTED=""
WINN3_ONETOUCH_STAGING_REQUESTED=fixture
WINN3_GATEWAY_CREDENTIALS_DIR=/fixture/credentials
WINN3_GATEWAY_ID=""
WINN3_GATEWAY_PATH_MTU=""
WINN3_GATEWAY_INNER_V4=""
WINN3_GATEWAY_FORWARD_CIDR=""
WINN3_GATEWAY_FORWARD_ASYNC=0
WINN3_GATEWAY_LISTEN=0.0.0.0:9111
WINN3_GATEWAY_PLAN=udp
WINN3_GATEWAY_TCP_INGRESS=0
WINN3_GATEWAY_LISTENER_DF=0
WINN3_GATEWAY_RESOLVER_UPSTREAM=""
NODE_SLUG=fixture
'''
        acceptance = '''
winn3gw_resolve_onetouch
[[ "$WINN3_GATEWAY_FORWARD" == 1 && "$WINN3_GATEWAY_RESOLVER" == 1 ]] || exit 81
[[ "$WINN3_GATEWAY_ID" == fixture-gw1 && "$WINN3_GATEWAY_INNER_V4" == 10.10.0.1 ]] || exit 82
'''
        self.run_shell(setup + actual + acceptance)
        for variable in ("WINN3_GATEWAY_FORWARD", "WINN3_GATEWAY_RESOLVER"):
            with self.subTest(variable=variable):
                self.assertIn(variable + "=1", actual)
                mutant = actual.replace(variable + "=1", variable + "=0")
                self.run_shell(setup + mutant + acceptance, 81)


# ---------------------------------------------------------------------------
# Turn 1 to Turn 2 fixes (Sol, Gemini, Claude reviews of the Turn 1 candidate).
# ---------------------------------------------------------------------------

def shell_function_or_empty(name):
    try:
        return shell_function(name)
    except AssertionError:
        return ""


class ShellFixBase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.addCleanup(self.temp.cleanup)
        self.area = Path(self.temp.name)
        self.trace = self.area / "trace"

    def run_shell(self, source, rc=0, **extra):
        env = dict(os.environ, TEST_TRACE=str(self.trace), AREA=str(self.area), **extra)
        result = subprocess.run([BASH, "-c", source], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, rc, result.stderr + result.stdout)
        return result


class SettleAndRepairTests(ShellFixBase):
    def test_settle_never_runs_a_command_past_its_window(self):
        # Each hung command costs its whole timeout; the window must still hold.
        script = r"""set -u
SECONDS=0
timeout() {
  while [[ "$1" == -* ]]; do case "$1" in -s|-k) shift 2 ;; *) shift ;; esac; done
  printf '%s %s %s\n' "$1" "$2" "$3" >> "$TEST_TRACE"
  SECONDS=$((SECONDS + $1)); return 124
}
systemctl() { SECONDS=$((SECONDS + 1000)); return 1; }
docker() { SECONDS=$((SECONDS + 1000)); return 1; }
sleep() { SECONDS=$((SECONDS + $1)); }
WINN3_LATE_WINDOW=30
WINN3_LATE_STOPS=""
""" + shell_function_or_empty("winn3_late_settle_command") + "\n" + shell_function("winn3_late_settle") + r"""
winn3_late_settle
echo "elapsed=${SECONDS}"
(( SECONDS <= 35 ))
"""
        self.trace.write_text("")
        self.run_shell(script)
        calls = [line.split() for line in self.trace.read_text().splitlines()]
        self.assertTrue(calls)
        for seconds, command, action in calls:
            # Every command runs under a positive remainder of the window, and under its own limit.
            self.assertTrue(1 <= int(seconds) <= {"systemctl": 5, "docker": 10}[command], (seconds, command, action))

    def test_settle_keeps_the_stop_extension_and_records_each_stop(self):
        script = r"""set -u
SECONDS=0
svc_up=1
timeout() { while [[ "$1" == -* ]]; do case "$1" in -s|-k) shift 2 ;; *) shift ;; esac; done; shift; "$@"; }
systemctl() {
  case "$1" in
    is-active) [[ "${svc_up}" == 1 && "$3" == xray.service ]] ;;
    stop) svc_up=0 ;;
  esac
}
docker() { return 1; }
sleep() { SECONDS=$((SECONDS + $1)); }
WINN3_LATE_WINDOW=30
WINN3_LATE_STOPS=""
""" + shell_function_or_empty("winn3_late_settle_command") + "\n" + shell_function("winn3_late_settle") + r"""
winn3_late_settle
[[ "${WINN3_LATE_STOPS}" == xray.service@0\; ]]
"""
        self.run_shell(script)

    def test_every_late_fallback_path_drops_ipv6_input(self):
        for argument in ("initial", "reassert"):
            with self.subTest(argument=argument):
                self.trace.write_text("")
                script = r"""set -u
trace() { printf '%s\n' "$*" >> "$TEST_TRACE"; }
timeout() { :; }
ip6tables() { trace "ip6tables $*"; }
winn3_late_stop_services() { :; }
""" + shell_function("winn3_late_fallback") + "\nwinn3_late_fallback " + argument + "\n"
                self.run_shell(script)
                self.assertIn("ip6tables -w 10 -P INPUT DROP", self.trace.read_text())

    def repair_script(self, copies, fail=False):
        rules = self.area / "rules"
        rules.write_text("-N WINVPN-INPUT\n" + "-A WINVPN-INPUT -p tcp -m tcp --dport 80 -j ACCEPT\n" * copies
                         + "-A WINVPN-INPUT -j WINVPN-SSH-RECOVERY\n")
        (self.area / "fail").write_text("1") if fail else None
        return r"""set -u
iptables() {
  [[ "$1 $2" == "-w 10" ]] && shift 2
  case "$1" in
    -S) if [[ "$2" == WINVPN-INPUT ]]; then [[ ! -e "$AREA/fail" ]] || return 1; cat "$AREA/rules"; fi ;;
    -C) shift; grep -Fxq -- "-A $*" "$AREA/rules" ;;
    -D) shift; line="-A $*"; python3 - "$AREA/rules" "${line}" <<'PYDEL'
import sys
path, line = sys.argv[1:]
rows = open(path).read().splitlines()
rows.remove(line)
open(path, "w").write("\n".join(rows) + "\n")
PYDEL
      ;;
    *) return 0 ;;
  esac
}
winn3_recovery_source() { return 0; }
iptables-restore() { cat >/dev/null; }
WINN3_LATE_ERRORS=""
""" + shell_function("winn3_late_command") + "\n" + shell_function("winn3_late_repair_live") + r"""
winn3_late_repair_live full
echo "repair=${WINN3_LATE_REPAIR} errors=${WINN3_LATE_ERRORS}"
"""

    def test_repair_deletes_at_most_64_copies_per_distinct_rule(self):
        self.run_shell(self.repair_script(128))
        remaining = (self.area / "rules").read_text().count("--dport 80 -j ACCEPT")
        self.assertEqual(remaining, 64)

    def test_repair_records_a_failed_rule_listing(self):
        result = self.run_shell(self.repair_script(3, fail=True))
        self.assertIn("repair=failed", result.stdout)
        self.assertIn("iptables -S WINVPN-INPUT failed", result.stdout)


class PhaseCTests(ShellFixBase):
    def phase_c(self, journal, flip_pid=False):
        (self.area / "journal").write_text(journal)
        (self.area / "journal_args").write_text("")
        (self.area / "counter").write_text("0")
        (self.area / "queue_calls").write_text("")
        script = r"""set -u
err() { echo "$*" >&2; }
check_gateway_egress_mtu() { return 0; }
winn3gw_activate() { return 0; }
winn3gw_bundle_digest() { printf same; }
WINN3_GATEWAY_PRIOR_BUNDLE=same
# P-5's queue unit and step (server/test_winn3gw_queues_p5.py tests them).
winn3gw_install_queue_unit() { echo install-queue-unit >> "$AREA/queue_calls"; }
winn3gw_run_queue_step() { echo run-queue-step >> "$AREA/queue_calls"; }
sleep() { :; }
ss() { printf 'x 0 0 0.0.0.0:9111 0.0.0.0:* users:(("winn3-gateway",pid=4242,fd=3))\n'; }
journalctl() { printf '%s\n' "$*" >> "$AREA/journal_args"; cat "$AREA/journal"; }
systemctl() {
  case "$*" in
    "is-active --quiet winn3-gateway.service") return 0 ;;
    "show winn3-gateway.service -p MainPID --value")
      n=$(( $(cat "$AREA/counter") + 1 )); echo "$n" > "$AREA/counter"
      if [[ "${FLIP_PID}" == 1 && "$n" -ge 2 ]]; then echo 4243; else echo 4242; fi ;;
    "show winn3-gateway.service -p InvocationID --value") echo 0123456789abcdef0123456789abcdef ;;
    *) return 0 ;;
  esac
}
""" + shell_function("winn3gw_phase_c") + "\nwinn3gw_phase_c\n"
        env = dict(os.environ, AREA=str(self.area), FLIP_PID="1" if flip_pid else "0")
        return subprocess.run([BASH, "-c", script], env=env, capture_output=True, text=True, timeout=60)

    HUMAN = ("winn3-gateway: listening on 0.0.0.0:9111\n"
             "winn3-gateway: UDP socket buffers requested 1, granted read=1 write=1\n")

    def test_mixed_human_and_json_output_with_ready_status_succeeds(self):
        result = self.phase_c(self.HUMAN + '{"event":"listening","ready":true}\n' + self.HUMAN)
        self.assertEqual(result.returncode, 0, result.stderr)
        args = (self.area / "journal_args").read_text()
        self.assertIn("_SYSTEMD_INVOCATION_ID=0123456789abcdef0123456789abcdef", args)
        self.assertIn("_PID=4242", args)
        self.assertEqual("install-queue-unit\nrun-queue-step\n", (self.area / "queue_calls").read_text())

    def test_latest_status_decides_readiness(self):
        for journal in ('{"event":"listening","ready":true}\n{"event":"posture","ready":false}\n',
                        '{"event":"posture","ready":false}\n', self.HUMAN, ""):
            with self.subTest(journal=journal):
                self.assertEqual(self.phase_c(journal).returncode, 1)
        self.assertEqual(self.phase_c('{"event":"posture","ready":false}\n{"event":"posture","ready":true}\n').returncode, 0)

    def test_a_main_pid_change_during_the_check_refuses(self):
        result = self.phase_c('{"event":"listening","ready":true}\n', flip_pid=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("did not establish", result.stderr)


class NodeDefaultsAndDiagnosticsTests(ShellFixBase):
    def test_phase_a_preflight_reuses_resolved_node_defaults(self):
        for resolved, calls in (("1", 0), ("0", 1)):
            with self.subTest(resolved=resolved):
                env_file = self.area / "node.env"
                env_file.write_text("x=1\n")
                script = f"""set -u
NODE_ENV_FILE='{env_file}'
DATA_NODE_DEFAULTS_RESOLVED={resolved}
DATA_AUTO_NAME=name
NODE_NAME=name
calls=0
data_resolve_node_defaults() {{ calls=$((calls + 1)); }}
maybe_prompt_or_default() {{ :; }}
valid_node_display_name() {{ return 0; }}
err() {{ echo "$*" >&2; }}
""" + shell_function("data_preflight_public_identity") + f"""
data_preflight_public_identity
[[ "${{calls}}" == {calls} ]]
"""
                self.run_shell(script)

    def fence(self, active="", fail_units=False, fail_jobs=False):
        (self.area / "active").write_text(active)
        script = r"""set -u
systemctl() {
  case "$1" in
    list-units)
      [[ "${FAIL_UNITS}" != 1 ]] || return 1
      if [[ "$*" == *--all* ]]; then echo "wins-serving-activation-x.scope loaded inactive dead"; fi
      if [[ "$*" == *--state=* ]]; then cat "$AREA/active"; fi ;;
    list-jobs) [[ "${FAIL_JOBS}" != 1 ]] ;;
    *) return 0 ;;
  esac
}
sleep() { :; }
WINN3_LATE_WINDOW=30
""" + shell_function("winn3_late_fence") + r"""
winn3_late_fence
echo "fence=${WINN3_LATE_FENCE} killed=${WINN3_LATE_FENCE_KILLED:-unset} window=${WINN3_LATE_WINDOW}"
"""
        return self.run_shell(script, FAIL_UNITS="1" if fail_units else "0",
                              FAIL_JOBS="1" if fail_jobs else "0").stdout.strip()

    def test_fence_ignores_retained_inactive_scopes(self):
        self.assertEqual(self.fence(), "fence=done killed=no window=30")

    def test_fence_with_a_live_scope_extends_the_window_and_records_the_kill(self):
        out = self.fence(active="wins-serving-activation-y.scope loaded active running\n")
        self.assertTrue(out.startswith("fence=residual:wins-serving-activation-y.scope"), out)
        self.assertTrue(out.endswith("killed=yes window=120"), out)

    def test_fence_never_reports_done_after_a_failed_inspection(self):
        self.assertEqual(self.fence(fail_units=True), "fence=failed killed=unknown window=30")
        self.assertTrue(self.fence(fail_jobs=True).startswith("fence=failed "))

    def test_diagnose_names_the_s2_outcome_and_failing_rule(self):
        for output, status, expected, detail in (
            ("wins-latch: S2: unsafe recovery body", 1, "unrepaired", "wins-latch: S2: unsafe recovery body"),
            ("wins-latch: L1: latch body is not exact", 1, "ok", "wins-latch: L1: latch body is not exact"),
            ("wins-latch: S1: inadmissible rule ahead of latch in INPUT", 1, "unchecked",
             "wins-latch: S1: inadmissible rule ahead of latch in INPUT"),
            ("", 0, "ok", ""),
        ):
            with self.subTest(output=output):
                script = f"""set -u
wins_latch_rules_inspect() {{ [[ -z '{output}' ]] || echo '{output}' >&2; echo ignored-stdout; return {status}; }}
""" + shell_function_or_empty("winn3_late_diagnose") + r"""
winn3_late_diagnose
echo "${WINN3_LATE_S2}|${WINN3_LATE_DETAIL}"
"""
                self.assertEqual(self.run_shell(script).stdout.strip(), expected + "|" + detail)

    def test_handler_keeps_the_first_nonblocking_lock_outcome(self):
        definitions = shell_function("winn3_late_failure_on_exit") + "\n" + shell_function_or_empty("winn3_late_diagnose")
        definitions = definitions.replace("/run/lock", str(self.area))
        for first, expected in (("1", "contended"), ("0", "acquired")):
            with self.subTest(first=first):
                script = f"""set -u
data_plane_installer_sha256() {{ printf '%064d' 0; }}
winn3_late_record() {{ echo "record first_lock=${{WINN3_LATE_FIRST_LOCK:-unset}} lock=${{WINN3_LATE_ACTIVATION_LOCK:-unset}} window=${{WINN3_LATE_WINDOW}} s2=${{WINN3_LATE_S2:-unset}}"; }}
install() {{ :; }}
flock() {{ [[ "$1" == -n ]] && return {first}; return 0; }}
timeout() {{ :; }}
winn3_late_fence() {{ :; }}
winn3_installer_fw_lock() {{ return 0; }}
winn3_late_repair_live() {{ :; }}
wins_latch_rules_dominate() {{ return 1; }}
wins_latch_rules_inspect() {{ echo 'wins-latch: S2: unsafe recovery body' >&2; return 1; }}
winn3_late_fallback() {{ :; }}
WINS_FW_LOCK_OWNED=0
WINN3_LATE_ARMED=1
""" + definitions + "\nwinn3_late_failure_on_exit 9\nwinn3_late_record\n"
                out = self.run_shell(script).stdout
                last = [line for line in out.splitlines() if line.startswith("record")][-1]
                self.assertIn("first_lock=" + expected, last)
                self.assertIn("lock=held", last)
                self.assertIn("s2=unrepaired", last)

    def test_record_carries_every_new_field_in_the_python_key_order(self):
        keys = re.search(r"keys = \((.*?)\)\n", embedded("WINS_LATE_RECORD_PY"), re.S).group(1)
        names = re.findall(r'"([a-z_0-9]+)"', keys)
        self.assertEqual(names[-4:], ["first_lock", "fence_killed", "s2", "latch_detail"])
        script = r"""set -u
python3() { printf '%s\0' "$@" > "$AREA/args"; cat > /dev/null; }
WINN3_LATE_FIRST_LOCK=contended
WINN3_LATE_FENCE_KILLED=yes
WINN3_LATE_S2=unrepaired
WINN3_LATE_DETAIL='wins-latch: S2: x'
""" + shell_function("winn3_late_record") + "\nwinn3_late_record\n"
        self.run_shell(script)
        args = (self.area / "args").read_bytes().decode().split("\0")[:-1]
        self.assertEqual(len(args) - 1, len(names))
        self.assertEqual(args[-4:], ["contended", "yes", "unrepaired", "wins-latch: S2: x"])

    def test_record_python_writes_the_new_keys(self):
        source = embedded("WINS_LATE_RECORD_PY")
        source = source.replace('directory = "/var/lib/winsvpn"', 'directory = ' + repr(str(self.area)))
        source = source.replace("info.st_uid != 0 or info.st_gid != 0 or ", "")
        source = source.replace("os.fchown(fd, 0, 0)", "pass")
        names = re.findall(r'"([a-z_0-9]+)"', re.search(r"keys = \((.*?)\)\n", source, re.S).group(1))
        arguments = [name + "-value" for name in names]
        subprocess.run([sys.executable, "-c", source, *arguments], check=True, timeout=60)
        record = json.loads((self.area / "winn3-late-failure.json").read_text())
        for name in ("first_lock", "fence_killed", "s2", "latch_detail"):
            self.assertEqual(record[name], name + "-value")

    def test_phase_d_requires_the_pinned_checker_and_the_prune_tool(self):
        check = self.area / "check"
        prune = self.area / "prune"
        check.write_text("#!/bin/bash\necho pinned\n")
        prune.write_text("#!/usr/bin/env python3\n")
        for name in ("edge", "reg"):
            (self.area / name).write_text("#!/bin/bash\nexit 0\n")
            (self.area / name).chmod(0o755)
        (self.area / "node").write_text("#!/bin/bash\necho DIGEST\n")
        (self.area / "node").chmod(0o755)
        pinned = hashlib.sha256(check.read_bytes()).hexdigest()
        function = (shell_function("winn3gw_phase_d")
                    .replace("/usr/local/bin/wins-edge-hardening", str(self.area / "edge"))
                    .replace("/usr/local/bin/wins-node-register", str(self.area / "reg"))
                    .replace("/usr/local/libexec/winsvpn/winn3-node", str(self.area / "node")))
        script = f"""set -u
systemctl() {{ [[ "$1 $2" == "show winn3-gateway.service" ]] && echo '{{ argv[]=/x -forward -resolver ; }}'; return 0; }}
iptables() {{ return 0; }}
check_gateway_egress_mtu() {{ return 0; }}
winn3_node_tool() {{ case "$1" in classify) echo complete ;; identity-digest) echo DIGEST ;; esac; }}
winn3gw_verify_identity_signature() {{ return 0; }}
stat() {{ if [[ "${{@: -1}}" == '{check}' ]]; then echo "${{STAT_CHECK}}"; else echo "${{STAT_PRUNE}}"; fi; }}
sha256sum() {{ shasum -a 256 "$@"; }}
WINN3_OFFNODE_CHECK_PATH='{check}'
WINN3_OFFNODE_CHECK_SHA256='{pinned}'
WINN3_HUB_KEY_PRUNE_PATH='{prune}'
WINN3_IDENTITY_DIGEST=DIGEST
WINN3_GATEWAY_CREDENTIALS_DIR=x
WINN3_GATEWAY_ID=g
""" + function + "\nwinn3gw_phase_d\n"
        good = {"STAT_CHECK": "0:0:755:1", "STAT_PRUNE": "0:0:700:1"}
        self.run_shell(script, **good)
        for label, change in (("wrong mode", {"STAT_CHECK": "0:0:777:1"}), ("hard link", {"STAT_CHECK": "0:0:755:2"}),
                              ("wrong owner", {"STAT_CHECK": "1000:0:755:1"}),
                              ("prune world readable", {"STAT_PRUNE": "0:0:755:1"})):
            with self.subTest(label=label):
                self.run_shell(script, 1, **dict(good, **change))
        with self.subTest(label="digest drift"):
            check.write_text("#!/bin/bash\necho replaced\n")
            self.run_shell(script, 1, **good)
        check.write_text("#!/bin/bash\necho pinned\n")
        with self.subTest(label="symlink"):
            check.unlink()
            check.symlink_to(self.area / "edge")
            self.run_shell(script, 1, **good)
        check.unlink()
        check.write_text("#!/bin/bash\necho pinned\n")
        with self.subTest(label="prune missing"):
            prune.unlink()
            self.run_shell(script, 1, **good)


class VaultAndIdentityTests(RootFixture):
    def setUp(self):
        super().setUp()
        # A symlink target resolves through /private on macOS; the fixture compares real paths.
        self.area = self.area.resolve()

    def record(self, link, gateway_id="node-gw1"):
        argv = ["node", "record-node-env", str(link), gateway_id, "1450", "10.10.3.1", "10.10.3.0/24"]
        with patch.object(sys, "argv", argv):
            NODE.main()

    def test_node_env_vault_link_is_followed_to_its_root_owned_target(self):
        vault = self.area / "vault"
        vault.mkdir(mode=0o700)
        target = vault / "node.env"
        target.write_text("KEEP=1\nWINN3_GATEWAY_ID=old\n")
        target.chmod(0o600)
        link = self.area / "node.env"
        link.symlink_to(target)
        real = type(link).lstat

        def lstat(path, *args, **kwargs):
            info = real(path, *args, **kwargs)
            if path == link:
                return types.SimpleNamespace(st_uid=0, st_gid=0, st_mode=info.st_mode)
            return info
        with patch.object(type(link), "lstat", lstat):
            self.record(link)
            updated = target.read_text()
            self.assertTrue(link.is_symlink())
            self.assertEqual(os.readlink(link), str(target))
            self.assertIn("KEEP=1", updated)
            self.assertIn("WINN3_GATEWAY_ID=node-gw1", updated)
            self.assertIn("WINN3_INNER_SLICE=3", updated)
            self.assertNotIn("=old", updated)
            before = target.stat().st_mtime_ns
            self.record(link)
            self.assertEqual(target.stat().st_mtime_ns, before, "an unchanged body must not be rewritten")

    def test_node_env_link_not_owned_by_root_is_refused_untouched(self):
        vault = self.area / "vault"
        vault.mkdir(mode=0o700)
        target = vault / "node.env"
        target.write_text("KEEP=1\n")
        target.chmod(0o600)
        link = self.area / "node.env"
        link.symlink_to(target)
        with self.assertRaisesRegex(NODE.Refusal, "unsafe node.env link"):
            self.record(link)
        self.assertEqual(target.read_text(), "KEEP=1\n")

    def test_gateway_ids_with_colons_pass_both_the_store_and_the_recorded_check(self):
        NODE.Credentials(self.credentials, "node:gw1")
        with self.assertRaisesRegex(NODE.Refusal, "invalid gateway ID"):
            NODE.Credentials(self.credentials, "node gw1")
        public = self.area / "identity.json"
        with patch.object(sys, "argv", ["node", "recorded", str(self.credentials), str(public), "node:gw1",
                                        "1450", "10.10.0.1", "0"]):
            import contextlib
            import io
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                NODE.main()
        self.assertEqual(captured.getvalue().splitlines()[0], "node:gw1")


class HubKeyPruneTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.addCleanup(self.temp.cleanup)
        self.area = Path(self.temp.name)
        self.ssh = self.area / "ssh"
        self.ssh.mkdir(mode=0o700)
        self.keys = self.ssh / "authorized_keys"
        self.tool = self.area / "wins-hub-key-prune"
        self.tool.write_text(self.program())
        self.history = self.area / "history"
        self.allow = self.area / "allow"

    def program(self):
        return embedded("WINS_HUB_KEY_PRUNE_PY")

    @staticmethod
    def make(seed, kind="ssh-ed25519"):
        def string(data):
            return len(data).to_bytes(4, "big") + data
        key = hashlib.sha256(seed.encode()).digest()
        if kind == "sk-ssh-ed25519@openssh.com":
            blob = string(kind.encode()) + string(key) + string(b"ssh:")
        elif kind == "sk-ecdsa-sha2-nistp256@openssh.com":
            point = bytes.fromhex(
                "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
                "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
            )
            blob = string(kind.encode()) + string(b"nistp256") + string(point) + string(b"ssh:")
        else:
            blob = string(kind.encode()) + string(key)
        text = base64.b64encode(blob).decode()
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
        return {"type": kind, "blob": text, "fp": fingerprint, "line": kind + " " + text}

    def run_tool(self, *arguments, wait="2", **extra):
        env = dict(os.environ, WINS_ROOT_SSH_DIR=str(self.ssh), WINS_HUB_KEY_LOCK_WAIT=wait, **extra)
        return subprocess.run([sys.executable, str(self.tool), *arguments], env=env, capture_output=True,
                              text=True, timeout=60)

    def prune(self, keep, allow=(), history=(), **extra):
        self.allow.write_text("# operator allow-list\n\n" + "".join(fp + "\n" for fp in allow))
        self.history.write_text("".join("2026-01-0%dT00:00:00Z %s %s %s\n" % (n + 1, k["type"], k["blob"], k["fp"])
                                        for n, k in enumerate(history)))
        return self.run_tool("--keep-sha256", keep["fp"], "--keep-list", str(self.allow),
                             "--history", str(self.history), **extra)

    def lines(self):
        return self.keys.read_text().splitlines()

    def test_allow_list_prune_leaves_the_new_key_once_plus_allow_listed_operator_keys(self):
        new, old, older, operator, unknown = (self.make(n) for n in ("new", "old", "older", "operator", "unknown"))
        self.keys.write_text("\n".join([
            "# comment kept", "",
            old["line"] + " wins-hub-managed",
            old["line"],
            'command="echo a b",no-pty ' + old["line"] + " options and comment",
            old["line"] + " wins-hub-managed",
            older["line"],
            operator["line"] + " operator@laptop",
            unknown["line"] + " stranger",
            new["line"] + " wins-hub-managed",
            new["line"],
        ]) + "\n")
        result = self.prune(new, allow=[operator["fp"]], history=[old])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.lines(), ["# comment kept", "", operator["line"] + " operator@laptop",
                                        new["line"] + " wins-hub-managed"])
        self.assertEqual(stat.S_IMODE(self.keys.stat().st_mode), 0o600)
        self.assertEqual(result.stdout.count("known hub key"), 4)
        self.assertEqual(result.stdout.count("unclassified"), 2)
        self.assertEqual(result.stdout.count("duplicate"), 1)
        for fp in (new["fp"], operator["fp"], old["fp"], older["fp"], unknown["fp"]):
            self.assertIn(fp, result.stdout)
        for secret in (old["blob"], operator["blob"], "operator@laptop", "stranger", "options and comment"):
            self.assertNotIn(secret, result.stdout + result.stderr)
        before = self.keys.read_bytes()
        self.assertEqual(self.prune(new, allow=[operator["fp"]], history=[old]).returncode, 0)
        self.assertEqual(self.keys.read_bytes(), before)

    def test_every_malformed_line_is_removed_and_reported_never_kept(self):
        new = self.make("new")
        truncated = new["line"][:-12]
        self.keys.write_text("\n".join([
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 no-key-bytes",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5",
            "ssh-unknown! " + new["blob"],
            'command="open ' + new["line"],
            truncated,
            "ssh-rsa not-base64!!",
            new["line"],
        ]) + "\n")
        result = self.prune(new)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.lines(), [new["line"]])
        self.assertEqual(result.stdout.count("malformed"), 6)

    def test_malformed_wire_keys_are_reported_and_removed_even_if_allow_listed(self):
        def string(data):
            return len(data).to_bytes(4, "big") + data
        new = self.make("new")
        cases = (
            ("ssh-ed25519", string(b"ssh-ed25519") + string(b"x")),
            ("ssh-ed25519-cert-v01@openssh.com",
             string(b"ssh-ed25519-cert-v01@openssh.com")),
            ("ssh-madeup", string(b"ssh-madeup") + string(b"x")),
        )
        bad_lines = [kind + " " + base64.b64encode(blob).decode() for kind, blob in cases]
        bad_fingerprints = ["SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
                            for kind, blob in cases]
        self.keys.write_text("\n".join(bad_lines + [new["line"]]) + "\n")
        report = json.loads(self.run_tool("--inventory").stdout)
        self.assertEqual(report["malformed"], [1, 2, 3])
        self.assertEqual(report["malformed_count"], 3)
        self.assertEqual([item["sha256"] for item in report["keys"]], [new["fp"]])
        result = self.prune(new, allow=bad_fingerprints)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.lines(), [new["line"]])
        self.assertEqual(result.stdout.count("malformed"), 3)

    def test_truncated_rsa_line_is_malformed_and_certificates_use_the_ssh_keygen_fingerprint(self):
        for name in ("rsa", "ca", "operator"):
            subprocess.run(["ssh-keygen", "-q", "-t", "rsa" if name == "rsa" else "ed25519", "-N", "",
                            "-C", name, "-f", str(self.area / name)], check=True)
        subprocess.run(["ssh-keygen", "-q", "-s", str(self.area / "ca"), "-I", "operator", "-n", "root",
                        str(self.area / "operator.pub")], check=True, capture_output=True)
        rsa = (self.area / "rsa.pub").read_text().split()
        certificate = (self.area / "operator-cert.pub").read_text().split()

        def printed(path):
            row = subprocess.run(["ssh-keygen", "-l", "-E", "sha256", "-f", str(path)], check=True,
                                 capture_output=True, text=True).stdout.split()
            return row[1]
        operator_fp = printed(self.area / "operator.pub")
        self.assertEqual(printed(self.area / "operator-cert.pub"), operator_fp)
        new = self.make("new")
        # A real RSA key cut after its exponent: the blob is two complete strings.
        self.keys.write_text("ssh-rsa " + rsa[1][:24] + "\n" + " ".join(certificate[:2]) + " operator\n"
                             + new["line"] + "\n")
        report = json.loads(self.run_tool("--inventory").stdout)
        self.assertEqual((report["malformed"], report["malformed_count"], report["total"]), ([1], 1, 3))
        self.assertEqual([item["sha256"] for item in report["keys"]], [operator_fp, new["fp"]])
        result = self.prune(new, allow=[operator_fp])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.lines(), [" ".join(certificate[:2]) + " operator", new["line"]])
        self.assertIn("removed line 1 - malformed", result.stdout)

    def test_a_failing_key_validator_refuses_and_never_reports_a_line_as_malformed(self):
        new = self.make("new")
        body = new["line"] + "\n"
        validator = self.area / "validator"
        self.tool.write_text(self.program().replace('"/usr/bin/ssh-keygen"', '"%s"' % validator))
        for code in (1, 255):
            with self.subTest(code=code):
                self.keys.write_text(body)
                validator.write_text("#!/bin/sh\necho 'out of memory' >&2\nexit %d\n" % code)
                validator.chmod(0o755)
                inventory = self.run_tool("--inventory")
                self.assertNotEqual(inventory.returncode, 0)
                self.assertEqual(inventory.stdout, "")
                result = self.prune(new)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("SSH public-key validation failed", result.stderr)
                self.assertEqual(self.keys.read_text(), body)
                self.assertEqual(sorted(path.name for path in self.ssh.iterdir()), ["authorized_keys"])

    def test_a_late_validator_failure_refuses_before_any_write(self):
        import contextlib
        import io
        new, old = self.make("new"), self.make("old")
        body = (old["line"] + "\n" + new["line"] + "\n").encode()
        self.allow.write_text("")
        self.history.write_text("")
        environment = {"WINS_ROOT_SSH_DIR": str(self.ssh), "WINS_HUB_KEY_LOCK_WAIT": "1"}
        real_run = subprocess.run
        for failure in ("exit1", "exit255", "bad-output", "timeout", "unavailable"):
            with self.subTest(failure=failure):
                self.keys.write_bytes(body)
                module = types.ModuleType("prune")
                exec(compile(self.program(), "prune", "exec"), module.__dict__)
                calls = 0

                def validator(command, **kwargs):
                    nonlocal calls
                    calls += 1
                    if calls == 3:
                        if failure == "timeout":
                            raise subprocess.TimeoutExpired(command, 5)
                        if failure == "unavailable":
                            raise OSError("validator unavailable")
                        if failure == "bad-output":
                            return subprocess.CompletedProcess(command, 0, b"invalid\n", b"")
                        code = 255 if failure == "exit255" else 1
                        return subprocess.CompletedProcess(command, code, b"", b"out of memory\n")
                    return real_run(command, **kwargs)

                stdout, stderr = io.StringIO(), io.StringIO()
                with patch.dict(os.environ, environment), patch.object(module.subprocess, "run", validator):
                    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                        status = module.main(["--keep-sha256", new["fp"], "--keep-list", str(self.allow),
                                              "--history", str(self.history)])
                self.assertEqual(calls, 3)
                self.assertEqual(status, 2)
                self.assertEqual(stdout.getvalue(), "")
                self.assertIn("refused", stderr.getvalue())
                self.assertEqual(self.keys.read_bytes(), body)
                self.assertEqual(sorted(path.name for path in self.ssh.iterdir()), ["authorized_keys"])

    def test_no_validator_call_occurs_after_temporary_creation(self):
        import contextlib
        import io
        new, old = self.make("new"), self.make("old")
        self.keys.write_text(old["line"] + "\n" + new["line"] + "\n")
        self.allow.write_text("")
        self.history.write_text("")
        module = types.ModuleType("prune")
        exec(compile(self.program(), "prune", "exec"), module.__dict__)
        environment = {"WINS_ROOT_SSH_DIR": str(self.ssh), "WINS_HUB_KEY_LOCK_WAIT": "1"}
        real_run, real_mkstemp = subprocess.run, tempfile.mkstemp
        created = False

        def mkstemp(*args, **kwargs):
            nonlocal created
            created = True
            return real_mkstemp(*args, **kwargs)

        def validator(command, **kwargs):
            self.assertFalse(created, "validator called after temporary creation")
            return real_run(command, **kwargs)

        with patch.dict(os.environ, environment), patch.object(module.subprocess, "run", validator), \
                patch.object(module.tempfile, "mkstemp", mkstemp):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                status = module.main(["--keep-sha256", new["fp"], "--keep-list", str(self.allow),
                                      "--history", str(self.history)])
        self.assertTrue(created)
        self.assertEqual(status, 0)
        self.assertEqual(self.keys.read_text(), new["line"] + "\n")

    def test_a_final_line_without_a_newline_never_absorbs_the_installed_hub_key(self):
        new, old, operator = self.make("new"), self.make("old"), self.make("operator")
        for tail in ("# operator note", "# operator note\r", "   "):
            with self.subTest(tail=tail):
                self.keys.write_bytes((operator["line"] + "\n" + old["line"] + "\n" + tail).encode())
                result = self.prune(new, allow=[operator["fp"]], history=[new])
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.keys.read_bytes(), (operator["line"] + "\n" + tail + "\n" + new["line"]
                                                          + " wins-hub-managed\n").encode())
                self.assertIn("installed the new hub key from the history, marked: " + new["fp"], result.stdout)

    def test_a_history_line_with_an_invalid_key_never_supplies_the_new_hub_key(self):
        def string(data):
            return len(data).to_bytes(4, "big") + data
        blob = string(b"ssh-ed25519") + string(b"x")
        bad = {"type": "ssh-ed25519", "blob": base64.b64encode(blob).decode(),
               "fp": "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")}
        body = self.make("operator")["line"] + "\n"
        self.keys.write_text(body)
        result = self.prune(bad, history=[bad])
        self.assertEqual(result.returncode, 2)
        self.assertIn("new hub key not in history", result.stderr)
        self.assertEqual(self.keys.read_text(), body)

    def test_security_key_lines_are_valid_keys_not_malformed(self):
        new = self.make("new")
        listed = self.make("listed", "sk-ssh-ed25519@openssh.com")
        unlisted = self.make("unlisted", "sk-ecdsa-sha2-nistp256@openssh.com")
        self.keys.write_text("\n".join([listed["line"] + " yubikey", unlisted["line"], new["line"]]) + "\n")
        result = self.prune(new, allow=[listed["fp"]])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.lines(), [listed["line"] + " yubikey", new["line"]])
        self.assertIn(unlisted["fp"] + " unclassified", result.stdout)
        self.assertNotIn("malformed", result.stdout)
        inventory = json.loads(self.run_tool("--inventory").stdout)
        self.assertEqual(inventory["malformed"], [])

    def test_a_missing_new_key_is_installed_marked_from_the_history_only(self):
        new, old = self.make("new"), self.make("old")
        self.keys.write_text(old["line"] + "\n")
        result = self.prune(new, history=[old, new])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.lines(), [new["line"] + " wins-hub-managed"])
        self.assertIn("installed the new hub key from the history", result.stdout)

    def test_a_new_key_in_neither_file_refuses_before_any_edit(self):
        new, old = self.make("new"), self.make("old")
        self.keys.write_text(old["line"] + "\n")
        before = self.keys.read_bytes()
        result = self.prune(new, history=[old])
        self.assertEqual(result.returncode, 2)
        self.assertIn("new hub key not in history", result.stderr)
        self.assertEqual(self.keys.read_bytes(), before)
        self.assertEqual([p.name for p in self.ssh.iterdir()], ["authorized_keys"])

    def test_history_lines_with_a_wrong_fingerprint_do_not_authorize_a_key(self):
        new, other = self.make("new"), self.make("other")
        self.keys.write_text("")
        self.allow.write_text("")
        self.history.write_text("2026-01-01T00:00:00Z %s %s %s\n" % (new["type"], other["blob"], new["fp"]))
        result = self.run_tool("--keep-sha256", new["fp"], "--keep-list", str(self.allow), "--history", str(self.history))
        self.assertEqual(result.returncode, 2)
        self.assertIn("new hub key not in history", result.stderr)

    def test_allow_list_grammar_is_exact(self):
        new = self.make("new")
        self.keys.write_text(new["line"] + "\n")
        good = new["fp"]
        bad = {"hex digest": hashlib.sha256(b"x").hexdigest(), "padded": good + "=", "short": good[:-1],
               "long": good + "A", "trailing blank": good + " ", "carriage return": good + "\r",
               "stray text": "operator laptop"}
        self.history.write_text("")
        for label, text in bad.items():
            with self.subTest(label=label):
                self.allow.write_text(text + "\n")
                before = self.keys.read_bytes()
                result = self.run_tool("--keep-sha256", good, "--keep-list", str(self.allow), "--history", str(self.history))
                self.assertEqual(result.returncode, 2, label)
                self.assertIn("malformed allow-list line 1", result.stderr)
                self.assertEqual(self.keys.read_bytes(), before)
        self.allow.write_text("# header\n\n   \n" + good + "\n")
        result = self.run_tool("--keep-sha256", good, "--keep-list", str(self.allow), "--history", str(self.history))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("allow-list 1 fingerprint, 2 blank, 1 comment", result.stdout)

    def test_keep_fingerprint_and_flags_are_validated(self):
        self.keys.write_text("")
        self.allow.write_text("")
        self.history.write_text("")
        for arguments in (("--keep-sha256", "abc", "--keep-list", str(self.allow), "--history", str(self.history)),
                          ("--keep-sha256", "SHA256:" + "A" * 43, "--keep-list", str(self.allow)),
                          ("--bogus",), ()):
            with self.subTest(arguments=arguments):
                self.assertEqual(self.run_tool(*arguments).returncode, 2)

    def test_the_directory_flock_blocks_the_prune_like_the_add_only_writer(self):
        import fcntl
        new = self.make("new")
        self.keys.write_text(new["line"] + "\n")
        descriptor = os.open(self.ssh, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        result = self.prune(new, wait="1")
        self.assertEqual(result.returncode, 2)
        self.assertIn("could not take the lock", result.stderr)
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        self.assertEqual(self.prune(new).returncode, 0)

    def test_a_symlinked_authorized_keys_is_refused_untouched(self):
        new = self.make("new")
        real = self.area / "elsewhere"
        real.write_text(new["line"] + "\nignored\n")
        self.keys.symlink_to(real)
        result = self.prune(new)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(real.read_text(), new["line"] + "\nignored\n")
        self.assertTrue(self.keys.is_symlink())

    def test_inventory_counts_every_line_and_names_malformed_ones_by_number(self):
        new, old = self.make("new"), self.make("old")
        self.keys.write_text("\n".join([
            "# c", old["line"] + " wins-hub-managed", "", old["line"][:-9], "ssh-unknown! x",
            'command="open ' + new["line"], new["line"] + " operator",
        ]) + "\n")
        before = self.keys.read_bytes()
        out = self.run_tool("--inventory")
        self.assertEqual(out.returncode, 0, out.stderr)
        report = json.loads(out.stdout)
        self.assertEqual((report["state"], report["total"], report["marked"], report["malformed"],
                          report["malformed_count"], report["truncated"]), ("ok", 5, 1, [4, 5, 6], 3, False))
        self.assertEqual(report["keys"], [{"line": 2, "sha256": old["fp"], "marked": True},
                                          {"line": 7, "sha256": new["fp"], "marked": False}])
        for secret in (old["blob"], "operator"):
            self.assertNotIn(secret, out.stdout)
        self.assertEqual(self.keys.read_bytes(), before)

    def test_inventory_states_for_absent_and_unreadable_files(self):
        self.assertEqual(json.loads(self.run_tool("--inventory").stdout)["state"], "absent")
        self.keys.write_bytes(b"#" * (1024 * 1024 + 1))
        self.assertEqual(json.loads(self.run_tool("--inventory").stdout)["state"], "unreadable")

    def test_options_with_blanks_and_comments_with_quotes_are_valid_keys(self):
        new = self.make("new")
        spaced = self.make("spaced")
        quoted = self.make("quoted")
        self.keys.write_text("\n".join([
            'command="echo a b",from="10.0.0.1, 10.0.0.2" ' + spaced["line"] + " ops",
            quoted["line"] + ' alice\'s "laptop',
            new["line"],
        ]) + "\n")
        report = json.loads(self.run_tool("--inventory").stdout)
        self.assertEqual(report["malformed"], [])
        self.assertEqual([item["sha256"] for item in report["keys"]], [spaced["fp"], quoted["fp"], new["fp"]])

    def test_non_utf8_comment_bytes_survive_a_prune_unchanged(self):
        new, operator = self.make("new"), self.make("operator")
        raw = (operator["line"] + " caf\xe9 \xff\n").encode("latin-1") + (new["line"] + "\n").encode()
        comment = b"# a\xe2\x80\xa8 stray line separator inside a comment\n"
        self.keys.write_bytes(comment + raw)
        result = self.prune(new, allow=[operator["fp"]])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.keys.read_bytes(), comment + raw)
        self.assertNotIn("removed line", result.stdout)

    def test_a_post_write_verification_failure_is_refused_not_reported_as_success(self):
        new, other = self.make("new"), self.make("other")
        self.keys.write_text(new["line"] + "\n")
        self.allow.write_text("")
        self.history.write_text("")
        module = types.ModuleType("prune")
        exec(compile(self.program(), "prune", "exec"), module.__dict__)
        real_replace = os.replace

        def corrupting_replace(source, destination):
            with open(source, "a") as stream:
                stream.write(other["line"] + "\n")
            real_replace(source, destination)
        # A second key line makes the result differ from the body, so a write happens.
        self.keys.write_text(other["line"] + "\n" + new["line"] + "\n")
        environment = {"WINS_ROOT_SSH_DIR": str(self.ssh), "WINS_HUB_KEY_LOCK_WAIT": "1"}
        with patch.dict(os.environ, environment), patch.object(module.os, "replace", corrupting_replace):
            import contextlib
            import io
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors), contextlib.redirect_stdout(io.StringIO()):
                status = module.main(["--keep-sha256", new["fp"], "--keep-list", str(self.allow),
                                      "--history", str(self.history)])
        self.assertEqual(status, 2)
        self.assertIn("verification after the write failed", errors.getvalue())

    def test_inventory_marks_a_malformed_report_over_the_cap_as_truncated(self):
        self.keys.write_text("ssh-unknown! x\n" * 1030)
        report = json.loads(self.run_tool("--inventory").stdout)
        self.assertEqual((report["total"], report["malformed_count"], len(report["malformed"]), report["truncated"]),
                         (1030, 1030, 1024, True))

    def test_inventory_marks_a_report_over_the_cap_as_truncated(self):
        lines = [self.make("k%d" % n)["line"] for n in range(1030)]
        self.keys.write_text("\n".join(lines) + "\n")
        report = json.loads(self.run_tool("--inventory").stdout)
        self.assertEqual((report["total"], len(report["keys"]), report["truncated"]), (1030, 1024, True))

    def test_the_installed_tool_is_exactly_the_embedded_program(self):
        function = shell_function("winn3_write_hub_key_prune")
        self.assertIn("chmod 700", function)
        self.assertIn("/usr/local/sbin/wins-hub-key-prune", SOURCE)
        self.assertTrue(self.program().startswith("#!/usr/bin/env python3\n"))
        phase_b = shell_function("winn3gw_phase_b")
        self.assertLess(phase_b.index("winn3_write_hub_key_prune"), phase_b.index("WINN3_LATE_ARMED=1"))


class HeartbeatInventoryTests(ShellFixBase):
    def block(self):
        start = SOURCE.index("hub_ssh_key_inventory=null\n")
        end = SOURCE.index("fi\nfi\n", start) + len("fi\nfi\n")
        return SOURCE[start:end]

    def merge(self):
        start = SOURCE.index("# SYNC-15/16/22: the reports join the payload here")
        end = SOURCE.index('registration_response=""', start)
        return SOURCE[start:end]

    def run_block(self, tool_body):
        tool = self.area / "tool"
        if tool_body is not None:
            tool.write_text("#!/bin/bash\n" + tool_body)
            tool.chmod(0o755)
        block = self.block().replace("/usr/local/sbin/wins-hub-key-prune", str(tool))
        base = {"slug": "lab"}
        script = ("set -Eeuo pipefail\n" + block + f"payload={json.dumps(json.dumps(base))}\n"
                  "winn3_gateway_report='{\"state\":\"absent\"}'\nwinn3_identity_ready=false\n"
                  "winn3_identity_sha256=\"\"\norigin_cert_not_after=\"\"\n" + self.merge()
                  + "\nprintf '%s' \"${payload}\"\n")
        return json.loads(self.run_shell(script).stdout)

    def test_the_payload_carries_the_inventory_the_tool_prints(self):
        good = '{"version":1,"state":"ok","total":1,"marked":0,"malformed":[],"keys":[]}'
        out = self.run_block("echo '" + good + "'\n")
        self.assertEqual(out["authorized_keys_inventory"], json.loads(good))

    def test_a_tool_that_fails_or_prints_garbage_reports_an_error_state(self):
        for body in ("exit 3\n", "echo not-json\n", "echo '[1]'\n", "echo '{\"state\":7}'\n"):
            with self.subTest(body=body):
                out = self.run_block(body)
                self.assertEqual(out["authorized_keys_inventory"], {"version": 1, "state": "error"})

    def test_a_node_without_the_tool_sends_no_inventory_field(self):
        self.assertNotIn("authorized_keys_inventory", self.run_block(None))



# ---------------------------------------------------------------------------
# Whole-tree fix (Astra WHOLE-DP): the fresh branch's complete-fresh call
# (design 3.17, node side). The production function runs under bash with a
# fake curl on PATH; nothing reaches a network or a hub.
# ---------------------------------------------------------------------------

FRESH_FAKE_CURL = r"""#!/bin/bash
cat > "$AREA/config"
printf '%s\n' "$@" > "$AREA/args"
prev=""
for arg in "$@"; do
  if [[ "$prev" == --data-binary ]]; then
    cp "${arg#@}" "$AREA/body"
    python3 -c 'import os,sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o777))' "${arg#@}" > "$AREA/mode"
  fi
  prev="$arg"
done
[[ -f "$AREA/response" ]] && cat "$AREA/response"
exit "$(cat "$AREA/curl_rc" 2>/dev/null || echo 0)"
"""

FRESH_OK = {"ok": True, "slug": "lab", "operator_enabled": False, "auto_golive_pending": True, "reasons": []}


class FreshCompletionTests(ShellFixBase):
    TOKEN = "fixture-node-token-0123456789"

    def setUp(self):
        super().setUp()
        (self.area / "bin").mkdir()
        curl = self.area / "bin" / "curl"
        curl.write_text(FRESH_FAKE_CURL)
        curl.chmod(0o755)
        (self.area / "tmp").mkdir()
        self.installer = self.area / "installer.sh"
        self.installer.write_text("#!/bin/bash\necho fixture installer\n")
        self.digest = hashlib.sha256(self.installer.read_bytes()).hexdigest()

    def script(self, function=None):
        body = function if function is not None else shell_function("complete_fresh_deployment_after_postflight")
        return ("set -Eeuo pipefail\n"
                "log() { printf 'LOG %s\\n' \"$*\"; }\n"
                "warn() { printf 'WARN %s\\n' \"$*\"; }\n"
                "err() { printf 'ERR %s\\n' \"$*\"; }\n"
                + shell_function("data_plane_installer_path") + "\n"
                + shell_function("data_plane_installer_sha256") + "\n"
                + body + "\n"
                "NODE_SLUG=lab\nNODE_TOKEN=" + self.TOKEN + "\nHUB_API_BASE=https://hub.example/\n"
                "complete_fresh_deployment_after_postflight\n")

    def run_fresh(self, response, rc=0, curl_rc=0, function=None, installer=None, keep_args=False):
        if response is not None:
            (self.area / "response").write_text(response)
        (self.area / "curl_rc").write_text(str(curl_rc))
        path = str(self.area / "bin") + ":" + os.environ["PATH"]
        result = self.run_shell(self.script(function), rc, PATH=path, TMPDIR=str(self.area / "tmp"),
                                WINS_DATA_PLANE_INSTALLER_PATH=str(installer or self.installer))
        self.assertEqual(list((self.area / "tmp").iterdir()), [], "the request body file is always removed")
        args = self.area / "args"
        if args.exists():
            sent = [a for a in args.read_text().splitlines() if a.startswith("@")]
            self.assertEqual(len(sent), 1, sent)
            self.assertFalse(os.path.exists(sent[0][1:]), "the request body file is always removed")
            if not keep_args:
                args.unlink()
        return result

    def test_a_passing_fresh_install_posts_complete_fresh_with_the_installer_digest(self):
        result = self.run_fresh(json.dumps(FRESH_OK), keep_args=True)
        config = (self.area / "config").read_text().splitlines()
        self.assertEqual(config, [
            'header = "x-node-token: %s"' % self.TOKEN,
            'header = "Content-Type: application/json"',
            'url = "https://hub.example/api/v1/nodes/lab/deployment/complete-fresh"',
            'request = "POST"',
        ])
        args = (self.area / "args").read_text().splitlines()
        self.assertEqual(args[:6], ["-fsS", "--connect-timeout", "10", "--max-time", "30", "--config"])
        self.assertEqual(args[6], "-")
        self.assertEqual(args[7], "--data-binary")
        self.assertTrue(args[8].startswith("@/"), args)
        self.assertEqual(len(args), 9, args)
        self.assertNotIn(self.TOKEN, "\n".join(args), "the node token never reaches argv")
        self.assertEqual(json.loads((self.area / "body").read_text()), {"installer_sha256": self.digest})
        self.assertEqual((self.area / "mode").read_text().strip(), "0o600")
        self.assertIn("LOG Released the fresh Data deployment after postflight; the hub recorded it for automatic go-live",
                      result.stdout)
        self.assertNotIn("ERR", result.stdout)

    def test_the_request_matches_the_rerun_completion_transport(self):
        fresh = shell_function("complete_fresh_deployment_after_postflight")
        rerun = shell_function("complete_data_deployment_after_postflight")
        for text in ("printf 'header = \"x-node-token: %s\"\\nheader = \"Content-Type: application/json\"\\nurl = \"%s\"\\nrequest = \"POST\"\\n'",
                     "curl -fsS --connect-timeout 10 --max-time 30 --config - \\\n      --data-binary \"@${request_file}\" 2>/dev/null",
                     'chmod 600 "${request_file}"', 'rm -f -- "${request_file}"'):
            with self.subTest(text=text[:40]):
                self.assertIn(text, rerun)
                self.assertIn(text, fresh)

    def test_a_manual_completion_is_released_and_names_the_hub_reasons(self):
        manual = dict(FRESH_OK, auto_golive_pending=False, reasons=["the go-live ticket carries go_live=manual"])
        result = self.run_fresh(json.dumps(manual))
        self.assertIn("a manual evidenced promotion is still required", result.stdout)
        self.assertIn("WARN Hub: automatic go-live not recorded: the go-live ticket carries go_live=manual", result.stdout)

    def test_an_idempotent_replay_of_the_same_completion_is_accepted(self):
        self.run_fresh(json.dumps(dict(FRESH_OK, idempotent=True)))

    def test_a_rejected_or_malformed_response_fails_the_install_closed(self):
        cases = {
            "ok false": json.dumps(dict(FRESH_OK, ok=False)),
            "ok missing": json.dumps({k: v for k, v in FRESH_OK.items() if k != "ok"}),
            "ok a string": json.dumps(dict(FRESH_OK, ok="true")),
            "operator latch opened": json.dumps(dict(FRESH_OK, operator_enabled=True)),
            "operator latch missing": json.dumps({k: v for k, v in FRESH_OK.items() if k != "operator_enabled"}),
            "operator latch null": json.dumps(dict(FRESH_OK, operator_enabled=None)),
            "another slug": json.dumps(dict(FRESH_OK, slug="other")),
            "slug missing": json.dumps({k: v for k, v in FRESH_OK.items() if k != "slug"}),
            "malformed json": '{"ok": true, "slug": "lab", "operator_enabled": false',
            "empty body": "",
            "two documents": json.dumps(FRESH_OK) + "\n" + json.dumps(dict(FRESH_OK, ok=False)),
            "two documents, good last": json.dumps(dict(FRESH_OK, ok=False)) + "\n" + json.dumps(FRESH_OK),
            "an array": json.dumps([FRESH_OK]),
            "a string": json.dumps("ok"),
        }
        for name, response in cases.items():
            with self.subTest(case=name):
                result = self.run_fresh(response, rc=1)
                self.assertIn("ERR Fresh postflight passed, but the hub did not confirm a dark fresh deployment release",
                              result.stdout)
                self.assertNotIn("LOG Released", result.stdout)

    def test_a_refused_or_unanswered_request_fails_the_install_closed(self):
        for curl_rc in (22, 28, 7, 6):
            with self.subTest(curl_rc=curl_rc):
                # curl -f answers a 409 with exit 22 and no body; a stray body never rescues it.
                result = self.run_fresh(json.dumps(FRESH_OK), rc=1, curl_rc=curl_rc)
                self.assertIn("ERR Fresh postflight passed, but the hub refused or did not answer the fresh completion",
                              result.stdout)
                self.assertNotIn("LOG Released", result.stdout)

    def test_an_unhashable_installer_never_posts(self):
        result = self.run_fresh(json.dumps(FRESH_OK), rc=1, installer=self.area / "absent.sh")
        self.assertIn("ERR Fresh postflight passed, but the installer digest could not be computed", result.stdout)
        self.assertFalse((self.area / "config").exists(), "no request is sent without a digest")
        stub = shell_function("complete_fresh_deployment_after_postflight")
        for digest in ("", "A" * 64, "a" * 63, "g" * 64):
            with self.subTest(digest=digest):
                script = ("data_plane_installer_sha256() { printf '%s' '" + digest + "'; }\n")
                result = self.run_shell("set -Eeuo pipefail\nlog() { :; }\nwarn() { :; }\n"
                                        "err() { printf 'ERR %s\\n' \"$*\"; }\n" + stub + "\n" + script
                                        + "NODE_SLUG=lab NODE_TOKEN=t HUB_API_BASE=https://hub.example\n"
                                        "complete_fresh_deployment_after_postflight\n", 1,
                                        PATH=str(self.area / "bin") + ":" + os.environ["PATH"])
                self.assertIn("installer digest could not be computed", result.stdout)
                self.assertFalse((self.area / "config").exists())

    def test_response_check_mutants_are_killed(self):
        actual = shell_function("complete_fresh_deployment_after_postflight")
        mutants = {
            "ok not checked": ("type == \"object\" and .ok == true and ", "type == \"object\" and ",
                               dict(FRESH_OK, ok=False)),
            "operator latch not checked": (" and .operator_enabled == false", "", dict(FRESH_OK, operator_enabled=True)),
            "operator latch read as falsy": (".operator_enabled == false", "(.operator_enabled | not)",
                                             {k: v for k, v in FRESH_OK.items() if k != "operator_enabled"}),
            "slug not checked": (" and .slug == $slug", "", dict(FRESH_OK, slug="other")),
        }
        for name, (old, new, response) in mutants.items():
            with self.subTest(mutant=name):
                self.assertEqual(actual.count(old), 1, old)
                self.run_fresh(json.dumps(response), rc=1)
                self.run_fresh(json.dumps(response), rc=0, function=actual.replace(old, new))
        transport = actual.replace('2>/dev/null)" || rc=$?', '2>/dev/null)" || true')
        self.assertNotEqual(transport, actual)
        self.run_fresh(json.dumps(FRESH_OK), rc=1, curl_rc=22)
        self.run_fresh(json.dumps(FRESH_OK), rc=0, curl_rc=22, function=transport)


class FreshCompletionWiringTests(ShellFixBase):
    BLOCK_START = '  if [[ "${DATA_INSTALLER_RERUN_ACTIVE}" == "1" ]]; then\n    complete_data_deployment_after_postflight\n'

    def completion_block(self):
        main = shell_function("main")
        start = main.index(self.BLOCK_START)
        end = main.index("  cloudflare_redirect_transaction_commit\n", start) + len("  cloudflare_redirect_transaction_commit\n")
        return main[start:end]

    def run_block(self, rerun, fresh_rc=0):
        stubs = "".join("%s() { printf '%%s\\n' %s >> \"$TEST_TRACE\"; %s }\n" % (
            name, name, "return " + str(fresh_rc) + ";" if name == "complete_fresh_deployment_after_postflight" else "")
            for name in ("mark_data_deployment_ready", "complete_fresh_deployment_after_postflight",
                         "complete_data_deployment_after_postflight", "cloudflare_redirect_transaction_commit"))
        script = ("set -Eeuo pipefail\n" + stubs + "DATA_INSTALLER_RERUN_ACTIVE=" + rerun + "\n"
                  "block() {\n" + self.completion_block() + "  printf 'after\\n' >> \"$TEST_TRACE\"\n}\n"
                  "block\nexit 0\n")
        result = subprocess.run([BASH, "-c", script], env=dict(os.environ, TEST_TRACE=str(self.trace)),
                                capture_output=True, text=True, timeout=20)
        trace = self.trace.read_text().splitlines() if self.trace.exists() else []
        self.trace.write_text("")
        return result.returncode, trace

    def test_the_fresh_branch_releases_through_complete_fresh_before_the_cloudflare_commit(self):
        self.assertEqual(self.run_block("0"), (0, [
            "mark_data_deployment_ready", "complete_fresh_deployment_after_postflight",
            "cloudflare_redirect_transaction_commit", "after"]))

    def test_a_failed_fresh_completion_stops_main_before_the_cloudflare_commit(self):
        self.assertEqual(self.run_block("0", fresh_rc=1), (1, [
            "mark_data_deployment_ready", "complete_fresh_deployment_after_postflight"]))

    def test_the_rerun_branch_is_unchanged(self):
        self.assertEqual(self.run_block("1"), (0, [
            "complete_data_deployment_after_postflight", "cloudflare_redirect_transaction_commit", "after"]))
        rerun = shell_function("complete_data_deployment_after_postflight")
        self.assertIn('[[ "${DATA_INSTALLER_RERUN_ACTIVE}" == "1" ]] || return 0', rerun)
        self.assertIn("/api/v1/nodes/${NODE_SLUG}/deployment/complete\"", rerun)
        self.assertIn("'{withdrawal_id:$withdrawal_id}'", rerun)
        self.assertNotIn("complete-fresh", rerun)
        self.assertNotIn("complete_fresh", rerun)
        self.assertEqual(SOURCE.count("complete_fresh_deployment_after_postflight"), 2,
                         "one definition and one call, on the fresh branch only")
        self.assertEqual(SOURCE.count("/deployment/complete-fresh"), 1)

    def test_the_late_failure_handler_is_armed_across_the_fresh_completion(self):
        main = shell_function("main")
        call = main.index("    complete_fresh_deployment_after_postflight || return 1\n")
        self.assertLess(main.index("winn3gw_clear_late_record_after_postflight"), call)
        self.assertLess(main.index("deploy_firewall_rollback_disarm"), call)
        self.assertLess(main.index("    mark_data_deployment_ready\n"), call)
        self.assertLess(call, main.index("cloudflare_redirect_transaction_commit"))
        self.assertLess(call, main.rindex("WINN3_LATE_ARMED=0"))
        self.assertEqual(main.count("WINN3_LATE_ARMED=0"), 1)


if __name__ == "__main__":
    unittest.main()
