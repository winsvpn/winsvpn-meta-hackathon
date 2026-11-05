"""S7 tests: the Tier A and Tier B harnesses, their mutant registry and evidence, and the static installer
properties that have no live fixture (design v17 5.1 to 5.7).

These run on the operator Mac and touch no guest, host or network. The Tier A scenarios themselves run on the
colima guest through `tools/onetouch_tiers/tier_a.py`; set WINS_S7_VM=l80 (or amd64t) to include one real run here.
"""
import contextlib
import importlib.util
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TIERS = ROOT / "tools" / "onetouch_tiers"
sys.path.insert(0, str(TIERS))
sys.path.insert(0, str(ROOT / "tools"))
import bench  # noqa: E402
import mutant_defs  # noqa: E402
import pred_cases  # noqa: E402
import readbacks  # noqa: E402
import scenarios  # noqa: E402
import shims  # noqa: E402
import tier_a  # noqa: E402
import tier_b  # noqa: E402
import tier_b_catalogue  # noqa: E402
import tier_common  # noqa: E402
import tierb_eval  # noqa: E402
from tier_common import HarnessRefusal, HostGuard, Installer, VmRunner  # noqa: E402

BASH = os.environ.get("WINS_TEST_BASH", "/bin/bash")
INSTALLER = Installer(ROOT / "server/wins_data_plane_setup_ONETOUCH.sh")


def staged_reading(installer=INSTALLER, **changes):
    """What the catalogue's STAGING_CHECK prints on a correctly staged guest; `changes` overrides single facts."""
    facts = {"installer_sha256": installer.sha256, "binary_sha256": installer.binary_pin, "binary_record": installer.binary_pin,
             "binary_record_check": "ok", "amneziawg_builder": "present", "cloudflare_gpg": "present", "secrets_mode": "root 600"}
    facts.update({"cover_" + k: "1" for k in tier_b_catalogue.COVER_KEYS})
    facts.update(changes)
    return "".join("%s=%s\n" % kv for kv in facts.items())


def run_with_stubs(script, stubs, env=None, timeout=60):
    """Run a target-side command under bash on this Mac with PATH stubs (name -> bash body). Returns stdout."""
    d = Path(tempfile.mkdtemp())
    try:
        for name, body in stubs.items():
            (d / name).write_text("#!/bin/bash\n" + body)
            (d / name).chmod(0o755)
        environment = dict(os.environ, PATH=str(d) + ":/usr/bin:/bin:/usr/sbin:/sbin")
        environment.update(env or {})
        done = subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=timeout, env=environment)
        return done.stdout
    finally:
        shutil.rmtree(d, ignore_errors=True)


class NoContact(unittest.TestCase):
    """Any attempt to run a process fails the test: dry runs and refusals must not reach for a guest or a host."""

    def setUp(self):
        self.calls = []

        def forbid(*args, **kwargs):
            self.calls.append(args)
            raise AssertionError("a subprocess was started: %r" % (args,))
        self.patches = [mock.patch.object(tier_common.subprocess, "run", forbid), mock.patch.object(tier_b.subprocess, "run", forbid)]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)


class VmRunnerTests(NoContact):
    def test_only_the_two_local_profiles_are_accepted(self):
        for profile in ("l80", "amd64t"):
            VmRunner(profile)
        for profile in ("default", "winthos", "l20", "l90", "l68", "l13awg", "prod", "", "l80 ", "../l80"):
            with self.subTest(profile=profile), self.assertRaises(HarnessRefusal):
                VmRunner(profile)

    def test_a_timed_out_guest_run_returns_rc_124_with_its_partial_output(self):
        def hang(*args, **kwargs):
            raise subprocess.TimeoutExpired(args[0], kwargs.get("timeout"), output=b"partial", stderr=b"err")
        with mock.patch.object(tier_common.subprocess, "run", hang):
            result = VmRunner("l80", dry_run=False).run("sleep 999", timeout=5)
        self.assertEqual((result.returncode, result.stdout), (124, "partial"))
        self.assertIn("harness timeout", result.stderr)

    def test_dry_run_records_and_runs_nothing(self):
        plan = []
        runner = VmRunner("l80", dry_run=True, plan=plan)
        result = runner.run("sudo -n true", purpose="probe")
        self.assertTrue(result.dry)
        self.assertEqual(plan[0]["remote"], "sudo -n true")
        self.assertEqual(self.calls, [])

    def test_vm_management_and_power_commands_are_refused(self):
        runner = VmRunner("l80", dry_run=True)
        for remote in ("colima stop l80", "sudo colima restart", "limactl delete x", "echo a; colima start amd64t",
                       "sudo reboot", "poweroff", "systemctl reboot", "sudo systemctl poweroff", "shutdown -h now",
                       "pkill -f unshare", "killall python3", "true && colima delete l80"):
            with self.subTest(remote=remote), self.assertRaises(HarnessRefusal):
                runner.run(remote)

    def test_ordinary_commands_pass_the_guard(self):
        runner = VmRunner("l80", dry_run=True)
        for remote in ("uname -m; id", "sudo -n env FX_RUN=ab12 unshare -m -n -p -f --mount-proc bash /x/fx_main.sh --profile quick a b; rc=$?; exit $rc",
                       "grep -m1 -E '^(model name|Model)' /proc/cpuinfo || echo unknown", "sudo -n rmdir /tmp/s7ns.x 2>/dev/null; exit 0"):
            with self.subTest(remote=remote):
                runner.run(remote)

    def test_unparseable_remote_commands_are_refused(self):
        with self.assertRaises(HarnessRefusal):
            VmRunner("l80", dry_run=True).run("echo 'unterminated")

    def test_every_remote_command_the_tier_a_runner_builds_passes_the_guard(self):
        runner = VmRunner("l80", dry_run=True)
        for profile in ("quick", "full"):
            runner.run(tier_a.remote_command(Path("/Users/x/bundle"), "abcd1234", profile, [i["fixture"] for i in scenarios.SCENARIOS]))
        runner.run(tier_common.NODE_CLASS_COMMAND)

    def test_forbidden_command_scanner_for_long_scripts(self):
        for bad in ("echo hi; reboot", "sudo systemctl reboot", "x && pkill -f foo", "colima stop l80", "(halt)", "rm -rf /",
                    "true; rm -rf / ", "sudo rm -fr /\necho x", "rm -Rf /", "rm -rf /*", "rm -rf -- /", "rm -r -f /",
                    "sudo -n rm -rf /", "rm -rf \"/\"", "x; rm -rf /;y", "sudo -n reboot"):
            with self.subTest(bad=bad), self.assertRaises(HarnessRefusal):
                tier_common.scan_forbidden(bad)
        for fine in ("echo reboot is owner only", "# the owner reboots the guest", "journalctl -t wins-serving", "ssh -T h 'sudo systemd-run --pipe x'",
                     "rm -rf /tmp/s7shims", "rm -rf /root/s7work/x", "rm -rf /tmp/s7shims/*", "sudo -n rmdir /tmp/s7ns.x"):
            with self.subTest(fine=fine):
                tier_common.scan_forbidden(fine)


class BundleStagingTests(unittest.TestCase):
    class FakeRunner:
        def __init__(self, visible):
            self.visible = visible
            self.calls = []

        def run(self, remote, timeout=300, purpose="", input_text=None):
            self.calls.append((remote, input_text))
            ok = self.visible if remote.startswith("test -f") else True
            return mock.Mock(ok=ok, stderr="")

    def make_bundle(self, d):
        bundle = Path(d) / "bundle"
        (bundle / "dp").mkdir(parents=True)
        (bundle / "MANIFEST.json").write_text("{}")
        (bundle / "dp" / "x.sh").write_text("echo hi\n")
        return bundle

    def test_a_visible_bundle_is_used_in_place(self):
        with tempfile.TemporaryDirectory() as d:
            runner = self.FakeRunner(True)
            path, pushed = tier_a.stage_bundle(runner, self.make_bundle(d), "abcd1234")
            self.assertEqual((path, pushed), (str(Path(d) / "bundle"), None))
            self.assertEqual(len(runner.calls), 1)

    def test_an_invisible_bundle_is_pushed_as_a_tar_and_unpacks_identically(self):
        import base64, io, tarfile
        with tempfile.TemporaryDirectory() as d:
            runner = self.FakeRunner(False)
            path, pushed = tier_a.stage_bundle(runner, self.make_bundle(d), "abcd1234")
            self.assertEqual((path, pushed), ("/tmp/s7bundle.abcd1234", "/tmp/s7bundle.abcd1234"))
            remote, data = runner.calls[1]
            self.assertIn("base64 -d | tar -xzf - -C /tmp/s7bundle.abcd1234", remote)
            names = tarfile.open(fileobj=io.BytesIO(base64.b64decode(data)), mode="r:gz").getnames()
            self.assertIn("./dp/x.sh", names)
            self.assertIn("./MANIFEST.json", names)
            VmRunner("amd64t", dry_run=True).run(remote)

    def test_the_vm_runner_runs_colima_from_a_directory_every_guest_has(self):
        seen = {}

        def fake(argv, **kwargs):
            seen.update(kwargs)
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch.object(tier_common.subprocess, "run", fake):
            VmRunner("amd64t", dry_run=False).run("true")
        self.assertEqual(seen["cwd"], "/tmp")


class TierBGateTests(NoContact):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = tier_b.main(list(argv))
            except HarnessRefusal as exc:
                rc = "refused: %s" % exc
        return rc, out.getvalue(), err.getvalue()

    def test_list_and_plan_make_no_connection(self):
        rc, out, _ = self.run_cli("list")
        self.assertEqual(rc, 0)
        self.assertIn("TB-00-facts", out)
        rc, out, _ = self.run_cli("plan", "--target", "ssh:example-host")
        self.assertEqual(rc, 0)
        plan = json.loads(out)
        self.assertTrue(plan["dry_run"])
        self.assertEqual(len(plan["plan_sha256"]), 64)
        self.assertEqual(self.calls, [])

    def test_plan_digest_is_deterministic_and_changes_with_the_target_and_the_variables(self):
        digest = lambda *a: json.loads(self.run_cli("plan", *a)[1])["plan_sha256"]  # noqa: E731
        base = digest("--target", "colima:amd64t")
        self.assertEqual(base, digest("--target", "colima:amd64t"))
        self.assertNotEqual(base, digest("--target", "ssh:a"))
        self.assertNotEqual(base, digest("--target", "colima:amd64t", "--var", "work=/root/other"))
        # `--have` decides which scenarios run, so it is part of what the owner authorizes
        self.assertNotEqual(base, digest("--target", "colima:amd64t", "--have", "deployed"))
        self.assertEqual(digest("--target", "colima:amd64t", "--have", "reboot,deployed"), digest("--target", "colima:amd64t", "--have", "deployed,reboot"))

    def test_a_run_with_another_have_set_than_the_authorized_plan_is_refused(self):
        digest = json.loads(self.run_cli("plan", "--target", "ssh:h", "--only", "TB-00-facts")[1])["plan_sha256"]
        with tempfile.TemporaryDirectory() as d:
            auth = Path(d) / "auth"
            auth.write_text("plan_sha256=%s\ntarget=ssh:h\n" % digest)
            rc, _, _ = self.run_cli("run", "--target", "ssh:h", "--only", "TB-00-facts", "--have", "deployed", "--execute",
                                    "--authorization", str(auth), "--evidence", str(Path(d) / "ev"))
            self.assertIn("refused", str(rc))
        self.assertEqual(self.calls, [])

    def test_run_without_execute_does_not_execute(self):
        rc, out, err = self.run_cli("run", "--target", "ssh:example-host")
        self.assertEqual(rc, 0)
        self.assertIn("not executing", err)
        self.assertEqual(self.calls, [])

    def test_execute_needs_an_owner_authorization_with_this_plan_and_target(self):
        rc, _, _ = self.run_cli("run", "--target", "ssh:example-host", "--execute")
        self.assertIn("refused", str(rc))
        digest = json.loads(self.run_cli("plan", "--target", "ssh:example-host")[1])["plan_sha256"]
        with tempfile.TemporaryDirectory() as d:
            for lines, expect in ((["plan_sha256=" + "0" * 64, "target=ssh:example-host"], "digest"),
                                  (["plan_sha256=" + digest], "target")):
                path = Path(d) / "auth"
                path.write_text("\n".join(lines) + "\n")
                rc, _, _ = self.run_cli("run", "--target", "ssh:example-host", "--execute", "--authorization", str(path))
                self.assertIn("refused", str(rc), expect)
        self.assertEqual(self.calls, [])

    def test_authorized_run_executes_steps_and_stops_at_owner_checkpoints(self):
        commands = []

        class Fake:
            name = "fake"

            def run(self, remote, timeout, input_text=None):
                commands.append(remote)
                if "iptables --version" in remote or "os-release" in remote:
                    return 0, "NAME=Ubuntu\nUbuntu 24.04.4 LTS\nsystemd 255 (255.4)\n", ""
                if "binary_record_check=" in remote:
                    return 0, staged_reading(), ""
                return 0, "", ""
        digest = json.loads(self.run_cli("plan", "--target", "ssh:example-host", "--only", "TB-00-facts,TB-04-late-failure-after-B",
                                         "--have", "installer-staged,deployed,reboot", "--installer", str(INSTALLER.path))[1])["plan_sha256"]
        with tempfile.TemporaryDirectory() as d:
            auth = Path(d) / "auth"
            auth.write_text("plan_sha256=%s\ntarget=ssh:example-host\n" % digest)
            state = Path(d) / "state.json"
            with mock.patch.object(tier_b, "make_target", lambda spec, dry_run: Fake()):
                rc, out, _ = self.run_cli("run", "--target", "ssh:example-host", "--only", "TB-00-facts,TB-04-late-failure-after-B",
                                          "--have", "installer-staged,deployed,reboot", "--installer", str(INSTALLER.path),
                                          "--execute", "--authorization", str(auth),
                                          "--state", str(state), "--evidence", str(Path(d) / "ev"))
            self.assertEqual(rc, tier_b.EXIT_OWNER, out)
            self.assertIn("OWNER CHECKPOINT in TB-04-late-failure-after-B", out)
            saved = json.loads(state.read_text())
            self.assertEqual(saved["scenario"], 1)
            self.assertGreater(saved["step"], 0)
            index = [json.loads(line) for line in (Path(d) / "ev" / "index.jsonl").read_text().splitlines()]
            self.assertEqual(index[0]["scenario"], "TB-00-facts")
        # helpers were pushed first; no command is a power or VM command
        self.assertTrue(any("install -d -m 700" in c for c in commands))
        for command in commands:
            tier_common.scan_forbidden(command)

    def test_scenarios_whose_requirements_are_not_declared_are_blocked_not_run(self):
        digest = json.loads(self.run_cli("plan", "--target", "ssh:h", "--only", "TB-02-fresh-deploy-state")[1])["plan_sha256"]
        with tempfile.TemporaryDirectory() as d:
            auth = Path(d) / "auth"
            auth.write_text("plan_sha256=%s\ntarget=ssh:h\n" % digest)
            fake = mock.Mock()
            fake.run.return_value = (0, "", "")
            with mock.patch.object(tier_b, "make_target", lambda spec, dry_run: fake):
                rc, out, _ = self.run_cli("run", "--target", "ssh:h", "--only", "TB-02-fresh-deploy-state", "--execute",
                                          "--authorization", str(auth), "--evidence", str(Path(d) / "ev"))
            self.assertIn("blocked", out)
            rows = [json.loads(l) for l in (Path(d) / "ev" / "index.jsonl").read_text().splitlines()]
            self.assertEqual(rows[0]["status"], "blocked")
            # only the helper push ran, no scenario step
            self.assertTrue(all("fx_probe" in c or "install -d" in c or "s7_" in c or "latch_predicate" in c for c in
                                [call.args[0] for call in fake.run.call_args_list]))

    def test_outline_scenarios_refuse_to_run(self):
        digest = json.loads(self.run_cli("plan", "--target", "ssh:h", "--only", "TB-09-variant-5", "--have", "installer-staged,deployed,systemd,reboot")[1])["plan_sha256"]
        with tempfile.TemporaryDirectory() as d:
            auth = Path(d) / "auth"
            auth.write_text("plan_sha256=%s\ntarget=ssh:h\n" % digest)
            fake = mock.Mock()
            fake.run.return_value = (0, "", "")
            with mock.patch.object(tier_b, "make_target", lambda spec, dry_run: fake):
                rc, out, _ = self.run_cli("run", "--target", "ssh:h", "--only", "TB-09-variant-5", "--have", "installer-staged,deployed,systemd,reboot",
                                          "--execute", "--authorization", str(auth), "--evidence", str(Path(d) / "ev"))
            self.assertIn("outline", out)

    def test_ssh_alias_must_be_plain(self):
        for alias in ("a b", "a;b", "-oProxyCommand=x", "a/b", "$(x)"):
            with self.subTest(alias=alias), self.assertRaises(HarnessRefusal):
                tier_b.SshTarget(alias)


class TierBDigestBindingTests(unittest.TestCase):
    """The plan digest binds the control-plane installer and every harness file Tier B loads or ships
    (tier_b.harness_files), and no other repository file. Each probe edits a copy under a scratch root that
    tier_b.ROOT is pointed at; the tree itself is never written."""

    PLAN = ("plan", "--target", "ssh:h", "--have", "installer-staged", "--installer", str(INSTALLER.path))

    def digest(self, root=None):
        out = io.StringIO()
        with contextlib.ExitStack() as stack:
            if root is not None:
                stack.enter_context(mock.patch.object(tier_b, "ROOT", Path(root)))
            stack.enter_context(contextlib.redirect_stdout(out))
            self.assertEqual(tier_b.main(list(self.PLAN)), 0)
        return json.loads(out.getvalue())["plan_sha256"]

    def mirror(self, extra=()):
        """A scratch root holding copies of the CP installer, every harness file and `extra` (ROOT-relative)."""
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        for rel in [tier_b.CP_RELATIVE] + tier_b.harness_files() + list(extra):
            (d / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / rel, d / rel)
        self.assertEqual(self.digest(d), self.digest(), "the mirror must plan exactly as the tree does")
        return d

    def unbound(self, root, rels):
        """The paths among `rels` whose one-line edit under `root` leaves the plan digest unchanged."""
        base, same = self.digest(root), []
        for rel in rels:
            path = Path(root) / rel
            original = path.read_bytes()
            path.write_bytes(original + b"\n# s6 digest probe\n")
            try:
                if self.digest(root) == base:
                    same.append(rel)
            finally:
                path.write_bytes(original)
        return same

    def test_the_harness_list_is_derived_and_covers_the_directory_and_what_the_tools_import(self):
        files = tier_b.harness_files()
        self.assertEqual(files, sorted(set(files)))
        here = tier_b.HERE_RELATIVE
        expected = {p.relative_to(ROOT).as_posix() for p in TIERS.glob("*.py")}
        expected |= {p.relative_to(ROOT).as_posix() for p in (TIERS / "linux").iterdir() if p.is_file()}
        expected |= {"%s/linux/%s" % (here, name) for name in tier_b.HELPERS}
        # anti-vacuity: the modules outside this directory that tier_common and hub_lite import
        expected |= {"tools/winn3_gateway_block.py", "server/test_hub_h1_descriptor_signer.py", "server/_toolchain.py"}
        self.assertEqual(sorted(expected - set(files)), [])
        self.assertIn("server/wins_control_plane_setup_ONETOUCH.sh", tier_b.CP_RELATIVE)
        self.assertEqual(tier_b.ROOT / tier_b.CP_RELATIVE, tier_b.hub_lite.CP_INSTALLER)

    @unittest.skipUnless(all(importlib.util.find_spec(n) for n in ("fastapi", "pydantic", "dateutil", "pytest")),
                         "hub-lite needs the real fastapi, pydantic, dateutil and pytest")
    def test_every_repository_module_a_plan_and_a_hub_lite_run_load_is_listed(self):
        """Runtime cross-check of the static derivation: plan, then a hub-lite init and node (the code the local steps
        run), in a fresh interpreter started as local_argv starts the tools; every repository file it loaded is bound."""
        probe = (
            "import contextlib, io, sys\nfrom pathlib import Path\n"
            "sys.path.insert(0, %r)\nimport tier_b, hub_lite\n"
            "with contextlib.redirect_stdout(io.StringIO()):\n    tier_b.main(['plan', '--target', 'ssh:h'])\n"
            "hub = hub_lite.HubLite(Path(sys.argv[1]) / 'hub', init=True)\n"
            "try:\n    hub.node('s6-probe')\nfinally:\n    hub.close()\n"
            "root = tier_b.ROOT\n"
            "for m in list(sys.modules.values()):\n"
            "    f = getattr(m, '__file__', None)\n"
            "    if f and Path(f).resolve().is_file() and Path(f).resolve().is_relative_to(root):\n"
            "        print(Path(f).resolve().relative_to(root).as_posix())\n") % str(TIERS)
        with tempfile.TemporaryDirectory() as d:
            done = subprocess.run([sys.executable, "-E", "-P", "-B", "-c", probe, d], capture_output=True, text=True,
                                  cwd=d, timeout=300)
        self.assertEqual(done.returncode, 0, done.stderr[-2000:])
        loaded = set(done.stdout.split())
        self.assertIn("tools/onetouch_tiers/hub_lite.py", loaded)
        self.assertIn("server/test_hub_h1_descriptor_signer.py", loaded)
        self.assertEqual(sorted(loaded - set(tier_b.harness_files())), [])

    def test_changing_the_cp_installer_or_any_harness_file_changes_the_plan_digest(self):
        root = self.mirror()
        rels = [tier_b.CP_RELATIVE] + tier_b.harness_files()
        self.assertGreater(len(rels), 30)
        self.assertEqual(self.unbound(root, rels), [])

    def test_an_unrelated_repository_file_does_not_change_the_plan_digest(self):
        unrelated = ["server/test_winn3_onetouch_s4.py", "tools/validate_deployment_scripts.py"]
        self.assertEqual([rel for rel in unrelated if rel in tier_b.harness_files()], [])
        root = self.mirror(unrelated)
        cache = root / tier_b.HERE_RELATIVE / "__pycache__" / "tier_b.cpython-0.pyc"
        cache.parent.mkdir()
        cache.write_bytes(b"\0")
        unrelated.append(cache.relative_to(root).as_posix())
        self.assertEqual(self.unbound(root, unrelated), unrelated)

    def test_mutant_a_harness_list_that_drops_one_entry_leaves_that_file_unbound(self):
        """Mutant: harness_files() without one entry. The edit probe must then see that file's change go unbound
        (killed for every single-entry drop), so the binding test above is not vacuous."""
        root, full = self.mirror(), tier_b.harness_files()
        for dropped in full:
            with self.subTest(dropped=dropped), mock.patch.object(tier_b, "harness_files",
                                                                  lambda d=dropped: [r for r in full if r != d]):
                self.assertEqual(self.unbound(root, [dropped]), [dropped])


class TierBQuotingTests(unittest.TestCase):
    def test_the_remote_script_reaches_root_bash_unexpanded(self):
        remote = "false; echo rc=$?\nfor i in 1 2; do echo run=$i; done\npython3 - <<'PY'\nprint('heredoc-ok')\nPY"
        line = tier_b.SshTarget("example-host").argv(remote)[-1]
        self.assertEqual(line, tier_b.root_command(remote))
        colima = tier_b.ColimaTarget("amd64t", dry_run=True)
        colima.run(remote, 10)
        self.assertEqual(colima.runner.plan[-1]["remote"], line)
        prefix = "sudo -n bash -c "
        self.assertTrue(line.startswith(prefix))
        # the target's outer shell parses the line first; without sudo here, it must hand bash the script byte for byte
        done = subprocess.run(["/bin/sh", "-c", BASH + " -c " + line[len(prefix):]], capture_output=True, text=True, timeout=20)
        self.assertEqual(done.stdout.split(), ["rc=1", "run=1", "run=2", "heredoc-ok"], done.stderr)


class TierBTransportTests(unittest.TestCase):
    """The string Tier B hands to the target's outer shell (`sh -c` on the guest, the login shell over ssh) must reach
    the root `bash -c` unchanged: no expansion by the unprivileged outer shell, newlines and here-documents intact."""

    def test_wrapped_command_reaches_root_bash_unchanged(self):
        script = "echo \"shell=$0\"\ncat <<'EOF'\nheredoc line\nEOF"
        colima = tier_b.ColimaTarget("amd64t", dry_run=True)
        colima.run(script, 10)
        for label, wrapped in (("ssh", tier_b.SshTarget("h").argv(script)[-1]), ("colima", colima.runner.plan[-1]["remote"])):
            with self.subTest(target=label):
                self.assertTrue(wrapped.startswith("sudo -n bash -c "), wrapped)
                done = subprocess.run(["sh", "-c", wrapped[len("sudo -n "):]], capture_output=True, text=True, timeout=20)
                self.assertEqual((done.returncode, done.stdout), (0, "shell=bash\nheredoc line\n"), done.stderr)

    def test_every_rendered_shim_install_reaches_root_bash_intact(self):
        """The real catalogue's shim steps (multi-line here-documents) through the real wrapper and a real local sh."""
        plan = tier_b.render_scenarios(tier_b_catalogue.catalogue(), dict(tier_b_catalogue.VARS))
        installs = [step["install"] for item in plan for step in item["steps"] if step["kind"] == "shim"]
        self.assertGreater(len(installs), 0)
        for install in installs[:3]:
            line = tier_b.root_command(install)
            # the outer shell's argv for bash -c must be the install script byte for byte
            done = subprocess.run(["sh", "-c", "printf %s " + line[len("sudo -n bash -c "):]], capture_output=True, text=True, timeout=20)
            self.assertEqual(done.stdout, install)

    def test_a_hung_ssh_step_returns_a_timeout_row_instead_of_raising(self):
        def hang(*args, **kwargs):
            raise subprocess.TimeoutExpired(args[0], kwargs.get("timeout"), output=b"partial", stderr=None)
        with mock.patch.object(tier_b.subprocess, "run", hang):
            rc, out, err = tier_b.SshTarget("h").run("sleep 999", 5)
        self.assertEqual((rc, out), (124, "partial"))
        self.assertIn("harness timeout", err)


class CatalogueStructure(unittest.TestCase):
    def test_ids_are_unique_and_requirements_are_known(self):
        items = tier_b_catalogue.catalogue()
        ids = [i["id"] for i in items]
        self.assertEqual(len(ids), len(set(ids)))
        known = {"installer-staged", "fresh-guest", "hub-lite", "edge-stub", "standalone-tree", "deployed", "reboot", "systemd",
                 "direct-ssh-session", "console-session", "canary-node", "phone", "aicore"}
        for item in items:
            self.assertFalse(set(item["requires"]) - known, item["id"])
            self.assertTrue(item["design"].startswith(("5.", "5")), item["id"])

    def test_every_step_resolves_and_contains_no_forbidden_command(self):
        plan = tier_b.render_scenarios(tier_b_catalogue.catalogue(), dict(tier_b_catalogue.VARS))
        steps = 0
        for item in plan:
            for step in item["steps"]:
                steps += 1
                if step["kind"] == "run":
                    tier_common.scan_forbidden(step["cmd"])
                    self.assertNotRegex(step["cmd"], r"\{(installer|secrets_file|shim_dir|work|deploy_args)\}")
                if step["kind"] == "shim":
                    for _, (real, rules) in step["shims"].items():
                        for rule in rules:
                            re.compile(rule["match"])
                if step["kind"] in ("owner", "hub"):
                    self.assertNotRegex(step["text"], r"\{(installer|secrets_file|shim_dir|work|deploy_args)\}")
        self.assertGreater(steps, 100)

    def test_every_expect_names_an_earlier_capture(self):
        for item in tier_b_catalogue.catalogue():
            captured = set()
            for step in item["steps"]:
                if step["kind"] in ("run", "local") and step.get("capture"):
                    captured.add(step["capture"])
                if step["kind"] == "local" and step.get("stdin_capture"):
                    self.assertIn(step["stdin_capture"], captured, item["id"])
                if step["kind"] == "expect":
                    self.assertIn(step["capture"], captured, "%s expects %s before it is captured" % (item["id"], step["capture"]))
                    if step["how"] == "equals_capture":
                        self.assertIn(step["value"], captured, item["id"])
                if step["kind"] == "evaluate":
                    for name in step["args"]:
                        if name.startswith("@"):
                            self.assertIn(name[1:], tier_b.EVALUATE_FACTS, item["id"])
                        else:
                            self.assertIn(name, captured, item["id"])

    def test_no_tier_b_step_reboots_or_power_manages_a_guest(self):
        for item in tier_b_catalogue.catalogue():
            for step in item["steps"]:
                if step["kind"] == "run":
                    self.assertNotRegex(step["cmd"], r"(^|[;&|] *)(sudo +)?(reboot|poweroff|halt|shutdown)\b")

    def test_forced_failure_scenarios_have_an_owner_reboot_checkpoint(self):
        for sid in ("TB-04-late-failure-after-B", "TB-05-late-failure-after-C", "TB-07-snapshot-fallback-guard-locked"):
            item = next(i for i in tier_b_catalogue.catalogue() if i["id"] == sid)
            self.assertIn("owner", [s["kind"] for s in item["steps"]], sid)

    def test_design_checks_are_all_represented(self):
        text = " ".join(i["design"] for i in tier_b_catalogue.catalogue())
        for needle in ("--preflight", "forced failure after phase B", "forced failure after phase C", "snapshot fallback",
                       "checked starts in flight", "Direct SSH", "Fail2Ban", "fd 7", "read-backs", "go-live latency",
                       "connect time", "Ryzen"):
            self.assertIn(needle.lower(), text.lower(), needle)


class BenchPlanTests(unittest.TestCase):
    def test_order_is_p17_then_latency_then_throughput(self):
        order = bench.ordered()
        self.assertEqual(order[0]["id"], "P-17")
        stages = [t["stage"] for t in order]
        self.assertEqual(stages, sorted(stages))
        kinds = [t["kind"] for t in order]
        first_throughput = kinds.index("throughput")
        self.assertTrue(all(k == "latency" for k in kinds[:first_throughput]))
        self.assertTrue(all(k == "throughput" for k in kinds[first_throughput:]))

    def test_every_design_trial_is_present_and_installer_side_ones_are_not(self):
        ids = {t["id"] for t in bench.TRIALS}
        for needle in ("P-17", "P-4", "P-22", "P-3", "P-10", "P-24", "P-20", "P-21", "P-25", "P-44", "P-39"):
            self.assertTrue(any(needle in i for i in ids), needle)
        for installer_side in bench.INSTALLER_SIDE:
            self.assertFalse(any(installer_side == i for i in ids), installer_side)

    def test_the_documented_arms(self):
        by = {t["id"]: t for t in bench.TRIALS}
        self.assertEqual([a["flow_limit"] for a in by["P-4"]["arms"]], [100, 256, 1024, 2048])
        self.assertEqual({(a["ring"], a["cpus"]) for a in by["P-17"]["arms"]}, {(r, c) for r in (10000, 4096, 2048, 1024) for c in (1, 2)})
        self.assertEqual([a["quantum"] for a in by["P-22"]["arms"]], [1514, 1280])
        self.assertEqual([a["busy"] for a in by["P-3"]["arms"]], [0, 50])

    def test_the_bench_scenario_lists_every_trial_in_order_and_is_owner_only(self):
        item = next(i for i in tier_b_catalogue.catalogue() if i["id"] == "TB-31-throughput-matrix")
        self.assertTrue(all(s["kind"] == "owner" for s in item["steps"]))
        text = "\n".join(s["text"] for s in item["steps"])
        positions = [text.index("trial %s " % t["id"]) for t in bench.ordered()]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("amd64t", item["steps"][0]["text"])

    def test_record_fields_cover_the_design_list(self):
        for field in ("loaded_ping_p50_ms", "loaded_ping_p99_ms", "jitter_ms", "probe_loss", "session_start_failures", "softnet_drops",
                      "gateway_inbox_drops", "rcvbuf_errors", "winn3gw0_tx_drops", "tcp_retransmissions", "node_class", "binary_sha256"):
            self.assertIn(field, bench.RECORD_FIELDS)


class ShimTests(unittest.TestCase):
    def build(self, rules, real_body):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        real = d / "real"
        real.write_text("#!/bin/bash\n" + real_body)
        real.chmod(0o755)
        shim = d / "tool"
        shim.write_text(shims.shim_script(str(real), rules, state_dir=str(d / "state")))
        shim.chmod(0o755)
        return d, shim

    def call(self, shim, *args):
        return subprocess.run([BASH, str(shim), *args], capture_output=True, text=True, timeout=20)

    def test_a_shim_runs_the_real_command_when_no_rule_matches(self):
        d, shim = self.build([{"match": "^never$", "fail": 9}], 'echo "real:$*"\n')
        done = self.call(shim, "a", "b")
        self.assertEqual((done.returncode, done.stdout.strip()), (0, "real:a b"))

    def test_nth_call_fails_once(self):
        d, shim = self.build([{"match": r"^go( |$)", "nth": 2, "fail": 7, "message": "boom"}], 'echo ok\n')
        self.assertEqual(self.call(shim, "go").returncode, 0)
        second = self.call(shim, "go")
        self.assertEqual(second.returncode, 7)
        self.assertIn("boom", second.stderr)
        self.assertEqual(self.call(shim, "go").returncode, 0)

    def test_every_from_nth_fails_all_later_calls(self):
        d, shim = self.build([{"match": r"^go( |$)", "nth": 2, "fail": 3, "every": True}], 'echo ok\n')
        codes = [self.call(shim, "go").returncode for _ in range(4)]
        self.assertEqual(codes, [0, 3, 3, 3])

    def test_marker_rules_chain_two_commands(self):
        d, a = self.build([{"match": r"^enable x", "sets": "MARK"}], "echo a\n")
        marker = d / "marker"
        rules_a = [{"match": r"^enable x", "sets": str(marker)}]
        rules_b = [{"match": r"route", "requires": str(marker), "fail": 1, "every": True}]
        sa = d / "a"; sa.write_text(shims.shim_script(str(d / "real"), rules_a, str(d / "sa"))); sa.chmod(0o755)
        sb = d / "b"; sb.write_text(shims.shim_script(str(d / "real"), rules_b, str(d / "sb"))); sb.chmod(0o755)
        self.assertEqual(self.call(sb, "route", "show").returncode, 0)
        self.call(sa, "enable", "x")
        self.assertTrue(marker.exists())
        self.assertEqual(self.call(sb, "route", "show").returncode, 1)

    def test_generated_installer_text_is_valid_bash(self):
        text = shims.install_commands("/run/s7-shims", {"ip": ("/usr/sbin/ip", [{"match": "route", "fail": 1, "hold_lock": "/x/y.lock", "hold_seconds": 5}])})
        done = subprocess.run([BASH, "-n"], input=text, capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_a_held_rule_marks_the_moment_and_waits_for_the_harness(self):
        """TB-09's forced failure: the rule creates held_file, waits for wait_file, logs `released` once, then fails.
        Without the file it gives up after wait_seconds and logs `wait-timeout` instead (never both)."""
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        held, go = d / "held", d / "go"
        rule = {"match": "route", "fail": 1, "held_file": str(held), "wait_file": str(go), "wait_seconds": 30}
        built, shim = self.build([rule], "echo real\n")
        proc = subprocess.Popen([BASH, str(shim), "route", "get"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for _ in range(100):
            if held.exists():
                break
            time.sleep(0.05)
        self.assertTrue(held.exists())
        time.sleep(0.5)
        self.assertIsNone(proc.poll(), "it waits while the harness has not released it")
        go.touch()
        out, err = proc.communicate(timeout=10)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("s7 shim: injected failure", err)
        log = (built / "state" / "tool.log").read_text()
        self.assertEqual((log.count(" released\n"), log.count(" wait-timeout\n")), (1, 0), log)
        built2, shim2 = self.build([dict(rule, held_file=str(d / "held2"), wait_file=str(d / "never"), wait_seconds=1)], "echo real\n")
        done = subprocess.run([BASH, str(shim2), "route"], capture_output=True, text=True, timeout=20)
        self.assertEqual(done.returncode, 1)
        log = (built2 / "state" / "tool.log").read_text()
        self.assertEqual((log.count(" released\n"), log.count(" wait-timeout\n")), (0, 1), log)

    def test_bad_rules_are_rejected(self):
        with self.assertRaises(ValueError):
            shims.shim_script("/bin/true", [{"nth": 1}])
        with self.assertRaises(re.error):
            shims.shim_script("/bin/true", [{"match": "("}])


class ReadbackTests(unittest.TestCase):
    def owners(self, *files, rmem=134217728, wmem=134217728):
        return "".join("%s:net.core.rmem_max=%d\n%s:net.core.wmem_max=%d\n" % (f, rmem, f, wmem) for f in files)

    def test_sysctl_floor_and_single_owner(self):
        good = "134217728 134217728 212992 212992 1 5000"
        node, edge = readbacks.DATA_PLANE_SYSCTL_FILES
        self.assertTrue(readbacks.evaluate_sysctls(good, self.owners(node))["pass"])
        self.assertFalse(readbacks.evaluate_sysctls("26214400 134217728 212992 212992 1 5000", self.owners(node))["pass"])
        self.assertFalse(readbacks.evaluate_sysctls(good, self.owners(node, "/etc/sysctl.d/60-winn3-gateway-udp-buffers.conf"))["pass"])
        self.assertFalse(readbacks.evaluate_sysctls("134217728 134217728 212992 212992 0 5000", self.owners(node))["pass"])
        self.assertFalse(readbacks.evaluate_sysctls("garbage", "")["pass"])

    def test_sysctl_owner_is_the_data_plane_with_one_value_per_key(self):
        """FINAL4 T3 (TB-20 P-1): the data plane writes both UDP buffer maxima in 99-winsvpn-node.conf and mirrors them
        in 99-winsvpn-edge.conf. That is one owner with one value; a file count refused every correct node."""
        good = "134217728 134217728 212992 212992 1 5000"
        raised = "268435456 134217728 212992 212992 1 5000"
        node, edge = readbacks.DATA_PLANE_SYSCTL_FILES
        self.assertTrue(readbacks.evaluate_sysctls(good, self.owners(edge, node))["pass"])
        self.assertTrue(readbacks.evaluate_sysctls(good, self.owners(edge, node).replace("=", " = "))["pass"])
        self.assertTrue(readbacks.evaluate_sysctls(raised, self.owners(edge, node, rmem=268435456))["pass"])
        split = self.owners(edge) + self.owners(node, rmem=268435456)
        self.assertFalse(readbacks.evaluate_sysctls(raised, split)["pass"], "two values for one key")
        self.assertFalse(readbacks.evaluate_sysctls(raised, self.owners(edge, node))["pass"], "the files disagree with live")
        self.assertFalse(readbacks.evaluate_sysctls(good, self.owners(node, "/etc/sysctl.conf"))["pass"], "a second owner")
        self.assertFalse(readbacks.evaluate_sysctls(good, "%s\n%s\n" % (edge, node))["pass"], "file names only do not parse")
        self.assertFalse(readbacks.evaluate_sysctls(good, "%s:net.core.rmem_max=134217728\n" % node)["pass"], "wmem_max unread")
        self.assertFalse(readbacks.evaluate_sysctls(good, self.owners(edge, node) + "/etc/sysctl.d/my tune.conf:net.core.rmem_max=134217728\n")["pass"],
                         "an unparsed line beside the data plane's lines")

    def test_sysctl_owner_reading_of_the_shipped_installer_passes(self):
        # Astra T3: build the owners reading from the data-plane installer's own sysctl heredocs, not sample lines.
        spec = importlib.util.spec_from_file_location("sysctl_single_owner", ROOT / "tools/test_sysctl_single_owner.py")
        owner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(owner)
        files = owner.sysctl_heredocs(str(ROOT / "server/wins_data_plane_setup_ONETOUCH.sh"))
        keys = ("net.core.rmem_max", "net.core.wmem_max")
        names = sorted(name for name, body in files.items() if set(body) & set(keys))
        self.assertEqual(names, ["99-winsvpn-edge.conf", "99-winsvpn-node.conf"])
        reading = "".join("/etc/sysctl.d/%s:%s=%s\n" % (name, key, files[name][key])
                          for name in names for key in keys if key in files[name])
        live = {key: owner.effective(files, key) for key in keys}
        good = "%s %s 212992 212992 1 5000" % (live["net.core.rmem_max"], live["net.core.wmem_max"])
        self.assertTrue(readbacks.evaluate_sysctls(good, reading)["pass"], readbacks.evaluate_sysctls(good, reading)["reason"])
        self.assertFalse(readbacks.evaluate_sysctls(good, "")["pass"])
        self.assertFalse(readbacks.evaluate_sysctls(
            good, reading + "/etc/sysctl.d/60-winn3-gateway-udp-buffers.conf:net.core.rmem_max=%s\n" % live["net.core.rmem_max"])["pass"])
        self.assertFalse(readbacks.evaluate_sysctls(good.replace(live["net.core.rmem_max"], "67108864", 1), reading)["pass"])

    def test_granted_buffers_are_twice_the_request(self):
        line = "requested 16777216, granted read=33554432 write=33554432"
        self.assertTrue(readbacks.evaluate_granted_buffers(line)["pass"])
        self.assertFalse(readbacks.evaluate_granted_buffers("requested 16777216, granted read=16777216 write=33554432")["pass"])
        self.assertFalse(readbacks.evaluate_granted_buffers("nothing")["pass"])

    # 131072 / 32768 on the WAN root (tunnel-speed round 2, Turn 14): the limits
    # in the supplied Canada measurement records.
    WAN = ("dev=eth0\nmem_kb=12242036\n== root\n"
           "qdisc fq 8001: root refcnt 2 limit 131072p flow_limit 32768p buckets 1024 orphan_mask 1023 quantum 1280b "
           "initial_quantum 25Kb low_rate_threshold 550Kbit refill_delay 1ms timer_slack 10us horizon 10s horizon_drop\n"
           "== edge_queues\nenabled\n== overrides\n")

    def test_wan_queue(self):
        """P-4 on the collector's own output: right reading passes, each wrong one fails."""
        self.assertTrue(readbacks.evaluate_wan_queue(self.WAN)["pass"], readbacks.evaluate_wan_queue(self.WAN))
        self.assertTrue(readbacks.evaluate_wan_queue(self.WAN, 32768)["pass"])
        wrong = {
            "fleet flow_limit 100": (self.WAN, 100),
            "flow_limit 100p": (self.WAN.replace("flow_limit 32768p", "flow_limit 100p"), None),
            "the old fleet flow_limit 256p": (self.WAN.replace("flow_limit 32768p", "flow_limit 256p"), None),
            "the round-2 installer's 1024p": (self.WAN.replace("flow_limit 32768p", "flow_limit 1024p"), None),
            "quantum": (self.WAN.replace("quantum 1280b", "quantum 16384b"), None),
            "initial quantum": (self.WAN.replace("initial_quantum 25Kb", "initial_quantum 16Kb"), None),
            "refill": (self.WAN.replace("refill_delay 1ms", "refill_delay 40ms"), None),
            "pacing": (self.WAN.replace("horizon_drop", "horizon_drop nopacing"), None),
            "maxrate": (self.WAN.replace("horizon_drop", "horizon_drop maxrate 1Gbit"), None),
            "mq root": (self.WAN.replace("qdisc fq 8001: root", "qdisc mq 0: root"), None),
            "unit disabled": (self.WAN.replace("== edge_queues\nenabled", "== edge_queues\ndisabled"), None),
            "small RAM wants 16384": (self.WAN.replace("mem_kb=12242036", "mem_kb=4000000"), None),
            "MemTotal unreadable": (self.WAN.replace("mem_kb=12242036", "mem_kb="), None),
            "no default route": (self.WAN.replace("dev=eth0", "dev="), None),
            "the old unsectioned form": ("dev=eth0\nqdisc fq 8001: root refcnt 2 limit 10000p flow_limit 256p\nenabled\n", None),
        }
        for name, (text, fleet) in wrong.items():
            with self.subTest(name):
                self.assertFalse(readbacks.evaluate_wan_queue(text, fleet)["pass"])
        small = self.WAN.replace("mem_kb=12242036", "mem_kb=4000000").replace("limit 131072p", "limit 16384p")
        self.assertTrue(readbacks.evaluate_wan_queue(small)["pass"], "the small-RAM fleet limit passes on a small node")
        overrides = readbacks.evaluate_wan_queue(self.WAN + "WAN_FQ_LIMIT\n")
        self.assertTrue(overrides["pass"])
        self.assertEqual(overrides["node_env_overrides"], ["WAN_FQ_LIMIT"], "an override name is reported, the fleet values still rule")
        self.assertIn("/root/node.env", readbacks.COLLECT_WAN_QDISC, "node.env lives in /root (DP NODE_ENV_FILE)")

    CHILD = ("qdisc fq 0: parent 1:%d limit 20480p flow_limit 256p buckets 1024 orphan_mask 1023 quantum 1280b "
             "initial_quantum 25Kb low_rate_threshold 550Kbit refill_delay 1ms timer_slack 10us horizon 10s horizon_drop")
    STATE = '{"result":"ok","main_pid":4242,"ifindex":7,"tries":1,"recorded_at":1,"qdisc":"mq","reason":""}'

    def winn3gw0(self, **change):
        parts = {"qdisc": "qdisc mq 1: root\n" + self.CHILD % 1 + "\n" + self.CHILD % 2,
                 "facts": "main_pid=4242\nactive=active\nifindex=7\nqlen=10000\ntx_queues=2\nmem_kb=12242036",
                 "state": self.STATE, "helper": "Result=success\nExecMainStatus=0"}
        parts.update(change)
        return "".join("== %s\n%s\n" % kv for kv in parts.items())

    def test_winn3gw0(self):
        """P-5 on the collector's own output, including the helper state bound to the current incarnation."""
        right = readbacks.evaluate_winn3gw0(self.winn3gw0())
        self.assertTrue(right["pass"], right)
        facts = "main_pid=4242\nactive=active\nifindex=7\nqlen=10000\ntx_queues=2\nmem_kb=12242036"
        wrong = {
            "a pfifo child": {"qdisc": "qdisc mq 1: root\n" + self.CHILD % 1 + "\nqdisc pfifo 0: parent 1:2 limit 1000p"},
            "one child for two queues": {"qdisc": "qdisc mq 1: root\n" + self.CHILD % 1},
            "an uncalibrated quantum": {"qdisc": "qdisc mq 1: root\n" + self.CHILD % 1 + "\n" + (self.CHILD % 2).replace("quantum 1280b", "quantum 1514b")},
            "noqueue root": {"qdisc": "qdisc noqueue 0: root refcnt 2"},
            "qlen 1000": {"facts": facts.replace("qlen=10000", "qlen=1000")},
            "the gateway inactive": {"facts": facts.replace("active=active", "active=inactive")},
            "a stale MainPID in the state": {"state": self.STATE.replace('"main_pid":4242', '"main_pid":4000')},
            "a stale ifindex in the state": {"state": self.STATE.replace('"ifindex":7', '"ifindex":6')},
            "the helper failed": {"state": self.STATE.replace('"result":"ok"', '"result":"failed"')},
            "no state file": {"state": "head: cannot open '/run/winsvpn/winn3gw-queues.state' for reading: No such file or directory"},
        }
        for name, change in wrong.items():
            with self.subTest(name):
                self.assertFalse(readbacks.evaluate_winn3gw0(self.winn3gw0(**change))["pass"])
        self.assertFalse(readbacks.evaluate_winn3gw0(self.winn3gw0(), 4096)["pass"], "another fleet qlen")
        rows = [{"kind": "restart", "matched": True, "helper_runs": 1}] * 20 + [{"kind": "reboot", "matched": True, "helper_runs": 1}] * 3
        self.assertTrue(readbacks.evaluate_restart_series(rows)["pass"])
        self.assertFalse(readbacks.evaluate_restart_series(rows[:-1])["pass"])
        rows[3] = {"kind": "restart", "matched": True, "helper_runs": 2}
        self.assertFalse(readbacks.evaluate_restart_series(rows)["pass"])

    def series(self, restarts=20, reboots=3, **change):
        state = lambda pid, ifx: '{"result":"ok","main_pid":%d,"ifindex":%d,"tries":1,"recorded_at":1,"qdisc":"mq","reason":""}' % (pid, ifx)  # noqa: E731
        lines = ["kind=restart run=%d main=%d ifindex=%d helper_runs=1 old_main=%d state=%s" % (i, 1000 + i, 10 + i, 999 + i, state(1000 + i, 10 + i))
                 for i in range(1, restarts + 1)]
        boots = ["kind=reboot run=%d main=%d ifindex=%d helper_runs=1 old_main=- state=%s" % (b, 500 + b, 3, state(500 + b, 3))
                 for b in range(1, reboots + 1)]
        text = "\n".join(lines) + "\n"
        for old, new in change.items():
            text = text.replace(old, new)
        return [text] + boots

    def test_restart_series_capture(self):
        """TB-21's evaluate step on the collectors' lines: 20 of 20 and 3 of 3 must match, one helper run each."""
        right = readbacks.evaluate_restart_series_capture(*self.series())
        self.assertTrue(right["pass"], right)
        self.assertEqual((right["restarts"], right["reboots"]), (20, 3))
        wrong = {
            "19 restarts": self.series(restarts=19),
            "2 reboots": self.series(reboots=2),
            "the helper ran twice": self.series(**{"run=4 main=1004 ifindex=14 helper_runs=1": "run=4 main=1004 ifindex=14 helper_runs=2"}),
            "the state names an older MainPID": self.series(**{'"main_pid":1007,': '"main_pid":1006,'}),
            "the state names another ifindex": self.series(**{'"ifindex":17,': '"ifindex":16,'}),
            "a restart kept its MainPID": self.series(**{"old_main=1008 ": "old_main=1009 "}),
        }
        failed = self.series()
        failed[0] = failed[0].replace('{"result":"ok","main_pid":1005', '{"result":"failed","main_pid":1005')
        wrong["result failed"] = failed
        duplicated = self.series(restarts=19)
        duplicated[0] += duplicated[0].splitlines()[0] + "\n"
        wrong["a duplicated line fills the count"] = duplicated
        garbled = self.series()
        garbled[0] = garbled[0].replace("kind=restart run=20 ", "kind=restart run=x ")
        wrong["an unparsed line"] = garbled
        for name, texts in wrong.items():
            with self.subTest(name):
                self.assertFalse(readbacks.evaluate_restart_series_capture(*texts)["pass"])

    def test_restart_collectors_pace_starts_under_the_unit_start_limit(self):
        """The gateway unit allows 5 starts in 60 s (DP StartLimitBurst=5, StartLimitIntervalSec=60). The series must not
        trip it: 20 kills 8 s apart (the earlier collector) would; the loop waits until 15 s after each kill."""
        unit = INSTALLER.text
        self.assertIn("StartLimitIntervalSec=60\nStartLimitBurst=5\n", unit)
        self.assertIn("while [ $(( $(date +%s) - t )) -lt 15 ]", readbacks.COLLECT_RESTART_SERIES)
        self.assertGreaterEqual(60 // 15, 1)
        self.assertLessEqual(60 // 15, 5, "at most 4 starts fall into any 60 s window")
        for script in (readbacks.COLLECT_RESTART_SERIES, readbacks.COLLECT_REBOOT_LINE.replace("{boot}", "1")):
            self.assertEqual(subprocess.run([BASH, "-n"], input=script, capture_output=True, text=True).returncode, 0)
        item = next(i for i in tier_b_catalogue.catalogue() if i["id"] == "TB-21-winn3gw0-restart-series")
        self.assertEqual([s["kind"] for s in item["steps"]].count("owner"), 3)
        self.assertEqual(item["steps"][-1]["fn"], "evaluate_restart_series_capture")

    GATE = ("== execstart\n{ path=/usr/local/bin/winn3-gateway ; argv[]=/usr/local/bin/winn3-gateway -mode serve -forward "
            "-peer-registry /etc/winn/winn3-peers.json -forward-async-write ; ignore_errors=no ; start_time=[n/a] }\n"
            "== gate\nwinn3-gateway: -forward-async-write enabled: 2.00 usable CPUs (affinity 6, no cgroup CPU limit, cpuset 6)\n"
            "== cpus\n0-5\n")

    def test_forward_async_gate(self):
        """P-9: the gateway's own gate line (forward_cpugate.go) against the flag in ExecStart and the cgroup's cpuset."""
        right = readbacks.judge_forward_async(self.GATE)
        self.assertTrue(right["pass"], right)
        self.assertEqual((right["flag_present"], right["usable_cpus"]), (True, 6))
        no_flag = self.GATE.replace(" -forward-async-write ;", " ;").replace(
            "-forward-async-write enabled: 2.00", "-forward-async-write DISABLED (below 2 usable CPUs; x): 1.00")
        self.assertTrue(readbacks.judge_forward_async(no_flag.replace("0-5", "0"))["pass"], "1 CPU and no flag")
        wrong = {
            "gate DISABLED with the flag": self.GATE.replace("enabled: 2.00", "DISABLED (a CPU limit could not be read; x): 2.00"),
            "enabled below 2 CPUs": self.GATE.replace("enabled: 2.00", "enabled: 1.00"),
            "the flag on a 1-CPU gateway": self.GATE.replace("== cpus\n0-5", "== cpus\n0"),
            "no gate line with the flag": self.GATE.replace("winn3-gateway: -forward-async-write enabled: 2.00 usable CPUs (affinity 6, no cgroup CPU limit, cpuset 6)", ""),
            "an enabled line without the flag": self.GATE.replace(" -forward-async-write ;", " ;"),
            "an unreadable cpuset with the flag": self.GATE.replace("== cpus\n0-5", "== cpus\ncat: no such file"),
            "no ExecStart": self.GATE.replace("{ path=/usr/local/bin/winn3-gateway ; argv[]=/usr/local/bin/winn3-gateway -mode serve -forward "
                                              "-peer-registry /etc/winn/winn3-peers.json -forward-async-write ; ignore_errors=no ; start_time=[n/a] }", ""),
        }
        for name, text in wrong.items():
            with self.subTest(name):
                self.assertFalse(readbacks.judge_forward_async(text)["pass"])
        self.assertTrue(readbacks.evaluate_forward_async("winn3-gateway: -forward-async-write enabled: 4.00 usable CPUs (affinity 4, x)", 4, True)["pass"])
        self.assertFalse(readbacks.evaluate_forward_async("winn3-gateway: -forward-async-write enabled: 1.00 usable CPUs (affinity 1, x)", 4, True)["pass"])
        self.assertTrue(readbacks.evaluate_forward_async("", 1, False)["pass"])
        self.assertFalse(readbacks.evaluate_forward_async("", 1, True)["pass"])
        self.assertEqual(readbacks.GATE_RE.pattern, re.search(r'^GATE_RE = re\.compile\(r"(.*)"\)$', INSTALLER.text, re.M).group(1),
                         "the harness reads the gate line exactly as the data plane's own read-back does")

    def test_granted_buffer_collector_keeps_the_start_line_after_long_uptime(self):
        """The gateway logs its buffer line once at start and a status line every second. The collector selects the
        line; the earlier `tail -n 400` lost it after about 400 s, which this test shows with the same journal."""
        status = '{"event":"status","ready":true,"sessions":0,"carrying":0}'
        journal = ("echo 'winn3-gateway: UDP socket buffers requested 16777216, granted read=33554432 write=33554432'\n"
                   "for i in $(seq 1 600); do echo '%s'; done\n" % status)
        stubs = {"systemctl": "echo 0123456789abcdef0123456789abcdef\n", "journalctl": journal}
        good = run_with_stubs(readbacks.COLLECT_GATEWAY_JOURNAL, stubs)
        self.assertTrue(readbacks.evaluate_granted_buffers(good)["pass"], good)
        old = ("inv=$(systemctl show winn3-gateway.service -p InvocationID --value 2>/dev/null); "
               "if [ -n \"$inv\" ]; then journalctl --no-pager -o cat _SYSTEMD_INVOCATION_ID=\"$inv\" 2>&1 | tail -n 400; "
               "else journalctl -u winn3-gateway.service --no-pager -o cat -n 400 2>&1; fi")
        self.assertFalse(readbacks.evaluate_granted_buffers(run_with_stubs(old, stubs))["pass"], "the tail form loses the line")

    def test_percentile(self):
        self.assertEqual(readbacks.percentile(list(range(1, 11)), 95), 10)
        self.assertEqual(readbacks.percentile([5], 95), 5)

    def test_golive_budget_and_stale_proofs(self):
        runs = [{"completed": 100.0 + i, "enabled": 100.0 + i + 60, "proof_ok_at": {"canary": 100.0 + i + 20}} for i in range(10)]
        self.assertTrue(readbacks.evaluate_golive(runs)["pass"])
        runs[0]["enabled"] = runs[0]["completed"] + 400
        self.assertFalse(readbacks.evaluate_golive(runs)["pass"], "p95 over ten runs is the slowest run")
        many = [{"completed": 100.0 + i, "enabled": 100.0 + i + 60, "proof_ok_at": {"canary": 100.0 + i + 20}} for i in range(40)]
        many[0]["enabled"] = many[0]["completed"] + 400
        self.assertTrue(readbacks.evaluate_golive(many)["pass"], "one slow run in forty is under the p95 rank")
        stale = [{"completed": 100.0, "enabled": 150.0, "proof_ok_at": {"canary": 90.0}}] * 10
        self.assertFalse(readbacks.evaluate_golive(stale)["pass"])
        self.assertFalse(readbacks.evaluate_golive(runs[:5])["pass"])

    def test_connect_time_rule(self):
        ok = {("wifi", "a"): [2.0] * 10, ("cellular", "a"): [3.9] * 10}
        self.assertTrue(readbacks.evaluate_connect(ok)["pass"])
        self.assertFalse(readbacks.evaluate_connect({("wifi", "a"): [2.0] * 9 + [4.5] * 1 + [4.5]})["pass"])
        self.assertFalse(readbacks.evaluate_connect({("wifi", "a"): [2.0] * 9})["pass"])
        self.assertTrue(readbacks.stage_blocks_signoff(1.5, 1.0, 0.3))
        self.assertFalse(readbacks.stage_blocks_signoff(1.2, 1.0, 0.3))

    def test_ryzen_acceptance_and_emulation_refusal(self):
        self.assertTrue(readbacks.evaluate_ryzen([1.9] * 10, [1.85] * 10)["pass"])
        miss = readbacks.evaluate_ryzen([1.9] * 10, [1.5] * 10)
        self.assertFalse(miss["pass"])
        self.assertFalse(miss["blocks_s7"], "a miss opens a gateway round and blocks nothing in this design")
        with self.assertRaises(ValueError):
            readbacks.refuse_emulated({"emulated": True})
        with self.assertRaises(ValueError):
            readbacks.refuse_emulated({"virt": "qemu"})
        self.assertTrue(readbacks.refuse_emulated({"virt": "apple"}))

    def test_rule_r(self):
        base = {"rise_ms": 120, "throughput_gbit": 1.0, "loss": 0.0, "jitter_ms": 5}
        better = dict(base, rise_ms=90)
        verdict = readbacks.rule_r_adopt(base, better)
        self.assertEqual((verdict["adopt"], verdict["branch"]), (True, "3(a)"), "adopted even above the 50 ms bar")
        self.assertEqual(verdict["owner_bar"], "owner bar not met: rise 90 ms, gap 40 ms")
        faster = dict(base, throughput_gbit=1.5)
        self.assertFalse(readbacks.rule_r_adopt(base, faster)["adopt"], "a throughput-only candidate above the bar is refused")
        self.assertTrue(readbacks.rule_r_adopt(dict(base, rise_ms=40), dict(base, rise_ms=40, throughput_gbit=1.5))["adopt"])
        worse = dict(base, rise_ms=90, loss=0.1)
        self.assertFalse(readbacks.rule_r_adopt(base, worse)["adopt"])
        # item 1 rejects before the bar is looked at: a throughput gain under 50 ms that raises p50, jitter or loss is refused
        low = {"rise_ms": 30, "throughput_gbit": 1.0, "loss": 0.0, "jitter_ms": 5}
        for key, value in (("rise_ms", 45), ("jitter_ms", 20), ("loss", 0.05)):
            verdict = readbacks.rule_r_adopt(low, dict(low, throughput_gbit=1.5, **{key: value}))
            self.assertEqual((verdict["adopt"], verdict["branch"]), (False, "1"), key)
        # inside the run's own noise it is not a rise, and the gain is adopted under 3(b)
        self.assertTrue(readbacks.rule_r_adopt(low, dict(low, throughput_gbit=1.5, rise_ms=33), noise={"rise_ms": 5})["adopt"])
        # a gain inside the noise serves no purpose; a lower AWG throughput or a new failure class rejects
        self.assertEqual(readbacks.rule_r_adopt(low, dict(low, throughput_gbit=1.02), noise={"throughput_gbit": 0.05})["branch"], "2")
        self.assertFalse(readbacks.rule_r_adopt(dict(low, awg_throughput_gbit=0.5), dict(low, rise_ms=20, awg_throughput_gbit=0.4))["adopt"])
        self.assertFalse(readbacks.rule_r_adopt(low, dict(low, rise_ms=20, new_failure_class=True))["adopt"])
        self.assertFalse(readbacks.rule_r_adopt(dict(low, cpu_pct=40), dict(low, rise_ms=20, cpu_pct=46), cpu_ceiling_points=5)["adopt"])
        # the Claude seat's Turn 1 input: item 1 rejects it before the bar is looked at
        self.assertEqual(readbacks.rule_r_adopt(low, {"rise_ms": 45, "throughput_gbit": 1.5, "loss": 0.05, "jitter_ms": 20}),
                         {"adopt": False, "branch": "1", "reason": "rise_ms worse beyond noise"})
        # 3(b) above the bar: the base stays and the pair is an owner ruling candidate
        refused = readbacks.rule_r_adopt(base, faster)
        self.assertEqual((refused["adopt"], refused["branch"], refused["owner_ruling_candidate"]), (False, "3(b)", True))
        # both profiles: a p50 rise on profile a is rejected even when profile b, the worse one, is unchanged
        two = {"a": dict(low), "b": dict(low, rise_ms=60)}
        verdict = readbacks.rule_r_adopt_profiles(two, {"a": dict(low, rise_ms=40, throughput_gbit=1.5), "b": dict(low, rise_ms=60, throughput_gbit=1.5)})
        self.assertEqual((verdict["adopt"], verdict["branch"], verdict["profile"]), (False, "1", "a"))
        verdict = readbacks.rule_r_adopt_profiles(two, {"a": dict(low, rise_ms=20), "b": dict(low, rise_ms=55)})
        self.assertEqual((verdict["adopt"], verdict["owner_bar"]), (True, "b: owner bar not met: rise 55 ms, gap 5 ms"))
        # item 1 does not name v3 throughput: a lower v3 throughput fails item 2 (and 3's both-improve clause), not item 1
        self.assertEqual(readbacks.rule_r_adopt(low, dict(low, rise_ms=20, throughput_gbit=0.8)),
                         {"adopt": False, "branch": "2", "reason": "throughput_gbit lower beyond noise"})


class FixtureInputs(unittest.TestCase):
    def test_every_registered_fixture_is_defined_in_a_linux_script(self):
        defined = set()
        for path in (TIERS / "linux").glob("sc_*.sh"):
            defined |= set(re.findall(r"^(sc_[a-z0-9_]+)\(\)", path.read_text(), re.M))
        ids = set()
        for item in scenarios.SCENARIOS:
            self.assertNotIn(item["id"], ids)
            ids.add(item["id"])
            if not item.get("blocked"):
                self.assertIn("sc_" + item["fixture"].replace("-", "_"), defined, item["id"])
        defined_but_unregistered = {d for d in defined if d[3:].replace("_", "-") not in {i["fixture"] for i in scenarios.SCENARIOS}}
        self.assertEqual(defined_but_unregistered, set(), "a fixture function exists that no scenario runs")

    def test_blocked_scenarios_carry_a_reason(self):
        for item in scenarios.SCENARIOS:
            if item.get("blocked"):
                self.assertGreater(len(item["blocked"]), 20, item["id"])

    def test_predicate_cases_are_well_formed(self):
        ids = set()
        for case in pred_cases.cases():
            self.assertNotIn(case["id"], ids)
            ids.add(case["id"])
            self.assertIn(case["expect"], ("pass", "S1", "S2", "L1", "inspection"))
            self.assertTrue(case["rules"].startswith("*filter\n") and case["rules"].endswith("COMMIT\n"))
            declared = set(re.findall(r"^:(\S+) ", case["rules"], re.M))
            for target in re.findall(r"-[jg] (\S+)", case["rules"]):
                self.assertTrue(target in pred_cases.BUILTIN or target in declared, (case["id"], target))
        # the matrix covers each failure tag and a pass for each admitted prefix of the design list
        tags = {c["expect"] for c in pred_cases.cases()}
        self.assertEqual(tags, {"pass", "S1", "S2", "L1", "inspection"})
        self.assertGreaterEqual(len(ids), 35)
        for needle in ("france", "WG-negated", "F2B-ports", "CF-accept", "recovery-443", "goto", "two-recovery", "R-WG-L-WI", "CF-R-L-WI", "F2B-R-L-WI"):
            self.assertTrue(any(needle in i for i in ids), needle)

    def test_node_states_load_and_cover_the_designed_fixtures(self):
        states = pred_cases.states()
        for name in ("permissive", "open-serving", "chain-open", "chain-france", "base-443-ahead", "chain-open-altered-latch",
                     "chain-open-recovery-443", "chain-open-3x9111"):
            self.assertIn(name, states)
            self.assertTrue(states[name].endswith("COMMIT\n"))

    def test_bundle_is_self_contained_and_every_script_is_valid_bash(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "bundle"
            digest = tier_common.bundle(INSTALLER, out, tier_a.case_files(INSTALLER))
            self.assertEqual(len(digest), 64)
            manifest = json.loads((out / "MANIFEST.json").read_text())
            self.assertEqual(manifest["installer_sha256"], INSTALLER.sha256)
            for guard in ("guard_local_serving", "guard_ssh_recovery"):
                text = (out / "dp" / guard).read_text()
                self.assertTrue(text.startswith("#!/usr/bin/env bash\nwins_late_failure_hold()"), guard)
                self.assertIn("wins_latch_rules_inspect()", text)
                self.assertEqual(subprocess.run([BASH, "-n", str(out / "dp" / guard)], capture_output=True, text=True).returncode, 0)
            edge = (out / "dp" / "edge_hardening").read_text()
            self.assertTrue(edge.startswith("#!/usr/bin/env bash\nwins_late_failure_hold()"))
            self.assertIn("winn3gw_render_chains()", edge)
            self.assertIn('WINS_EDGE_QUEUES_ONLY=0', edge)
            self.assertEqual(subprocess.run([BASH, "-n", str(out / "dp" / "edge_hardening")], capture_output=True, text=True).returncode, 0)
            for path in list(out.glob("*.sh")) + list((out / "dp").glob("*.sh")):
                done = subprocess.run([BASH, "-n", str(path)], capture_output=True, text=True)
                self.assertEqual(done.returncode, 0, "%s: %s" % (path.name, done.stderr))
            for name in tier_common.HANDLER_FUNCTIONS:
                self.assertTrue((out / "dp" / (name + ".sh")).read_text().startswith(name + "()"), name)
            self.assertEqual(subprocess.run([sys.executable, "-B", "-m", "py_compile", str(out / "dp" / "latch_predicate.py")],
                                            capture_output=True).returncode, 0)

    def test_rendered_guards_match_what_the_installer_installs(self):
        # The installer prepends `declare -f` of the three shared functions to each guard heredoc. The bundle does it
        # from the function text; both must keep the same three names and the same guard body.
        text = INSTALLER.text
        for marker in ("WINS_NODE_LOCAL_SERVING_GUARD", "WINS_NODE_SSH_RECOVERY_GUARD"):
            self.assertIn("winn3_prepend_shared_functions \"${guard_tmp}\" wins_late_failure_hold wins_latch_rules_inspect wins_latch_rules_dominate", text)
            body = INSTALLER.heredoc(marker)
            rendered = tier_common.render_guard(INSTALLER, marker)
            self.assertTrue(rendered.endswith(body.split("\n", 1)[1] + "\n"))
        self.assertEqual(tier_common.GUARD_FUNCTIONS, ("wins_late_failure_hold", "wins_latch_rules_inspect", "wins_latch_rules_dominate"))
        self.assertIn("winn3_prepend_shared_functions /usr/local/bin/wins-edge-hardening wins_late_failure_hold wins_latch_rules_inspect "
                      "wins_latch_rules_dominate winn3gw_render_chains", INSTALLER.text)
        self.assertEqual(tier_common.EDGE_FUNCTIONS, tier_common.GUARD_FUNCTIONS + ("winn3gw_render_chains",))

    def test_tier_a_dry_plan_runs_nothing(self):
        with mock.patch.object(tier_common.subprocess, "run", side_effect=AssertionError("started a process")):
            with tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(tier_a.main(["plan", "--scratch", d]), 0)
        plan = json.loads(out.getvalue())
        self.assertTrue(plan["scenarios"])
        self.assertTrue(all(r["vm"] == "l80" for r in plan["plan"]))

    def test_tier_a_lanes_split_quick_scenarios_and_keep_every_timed_one_in_a_later_single_lane(self):
        runnable = [i for i in tier_a.select("full", set()) if not i.get("blocked")]
        self.assertEqual(tier_a.lane_split(runnable, 1), [(0, [i["fixture"] for i in runnable])])
        groups = tier_a.lane_split(runnable, 3)
        full = [i["fixture"] for i in runnable if i["profile"] == "full"]
        self.assertEqual(groups[-1], (1, full))
        self.assertEqual([g[0] for g in groups[:-1]], [0, 0, 0])
        quick = sorted(f for _, ids in groups[:-1] for f in ids)
        self.assertEqual(quick, sorted(i["fixture"] for i in runnable if i["profile"] != "full"))

        class Recorder:
            def __init__(self):
                self.commands = []

            def run(self, command, timeout=0, purpose=""):
                self.commands.append(command)
                lane = re.search(r"FX_RUN=(\S+)", command).group(1)
                return type("R", (), {"stdout": "S7 ok x %s\n" % lane, "stderr": "", "returncode": 0})()
        recorder = Recorder()
        stdout, _, rc, commands = tier_a.run_lanes(recorder, "/b", "abcd", "full", groups, 10)
        self.assertEqual(rc, 0)
        self.assertEqual(len(set(re.findall(r"FX_RUN=(\S+)", " ".join(commands)))), len(groups), "each lane has its own FX_RUN")
        self.assertIn("fx_main.sh --profile full " + " ".join(full), recorder.commands[-1], "the timed lane runs last")

    def test_tier_a_evidence_header_records_the_commands_really_run(self):
        """With --lanes N the header names each lane's command, and it uses the guest path the bundle was read from."""
        class Fake:
            instances = []

            def __init__(self, vm, dry_run=True, plan=None):
                self.dry_run, self.profile, self.commands = dry_run, vm, []
                Fake.instances.append(self)

            def run(self, remote, timeout=300, purpose="", input_text=None):
                self.commands.append(remote)
                return mock.Mock(ok=True, stdout="", stderr="", returncode=0)
        for lanes in ("1", "3"):
            with self.subTest(lanes=lanes), tempfile.TemporaryDirectory() as d, mock.patch.object(tier_a, "VmRunner", Fake), \
                    contextlib.redirect_stdout(io.StringIO()):
                tier_a.main(["run", "--vm", "l80", "--profile", "full", "--lanes", lanes, "--scratch", d, "--evidence", str(Path(d) / "ev")])
                header = json.loads((Path(d) / "ev" / "header.json").read_text())
                ran = [c for c in Fake.instances[-1].commands if "fx_main.sh" in c]
                if lanes == "1":
                    self.assertEqual(header["command"], ran[0])
                else:  # phase-0 lanes start concurrently, so compare as sets; every lane has its own FX_RUN
                    self.assertEqual((len(header["command"]), sorted(header["command"])), (len(ran), sorted(ran)))
                    self.assertGreater(len(ran), 1)
                self.assertEqual(header["lanes"], int(lanes))

    def test_tier_a_refuses_other_profiles(self):
        with mock.patch.object(tier_common.subprocess, "run", side_effect=AssertionError("started a process")):
            for vm in ("default", "winthos", "l20"):
                with tempfile.TemporaryDirectory() as d:
                    with self.assertRaises(HarnessRefusal):
                        tier_a.main(["plan", "--vm", vm, "--scratch", d])


class PhaseATests(unittest.TestCase):
    """winn3gw_phase_a with every callee stubbed: the staged-binary pin, the replacement refusal and the cover preflight
    (5.6: digest pin bypassed, cover check skipped). The real functions are the ones in the installer."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.addCleanup(self.temp.cleanup)
        self.area = Path(self.temp.name)
        (self.area / "stage").mkdir()
        self.staged = self.area / "stage" / "winn3-gateway-linux-amd64"
        self.staged.write_bytes(b"fixture staged gateway bytes")
        self.sha = tier_common.sha256_bytes(self.staged.read_bytes())
        self.installed = self.area / "installed"

    def run_phase(self, pin=None, installed=None, allow="0", cover_rc=0):
        if installed is not None:
            self.installed.write_bytes(installed)
        elif self.installed.exists():
            self.installed.unlink()
        script = f'''set -u
TRACE={self.area}/trace
trace() {{ echo "$*" >> "$TRACE"; }}
sha256sum() {{ shasum -a 256 "$@"; }}
err() {{ echo "ERR $*" >&2; }}
winn3gw_log() {{ :; }}
wins_late_failure_hold() {{ return 1; }}
deployment_session_is_direct_remote() {{ return 1; }}
data_resolve_node_defaults() {{ :; }}
winn3_node_tool() {{ trace "tool $1"; [[ "$1" != classify ]] || echo fresh; }}
winn3gw_adoption_identity() {{ :; }}
winn3gw_resolve_onetouch() {{ :; }}
validate_config() {{ :; }}
verify_staged_binary() {{ :; }}
require_root_regular_file() {{ [[ -f "$1" ]]; }}
require_root_private_keyfile() {{ :; }}
winn3gw_cover_material() {{ trace "cover $1"; return {cover_rc}; }}
winn3gw_adoption_verify() {{ :; }}
winn3_offnode_check_digest_ok() {{ trace offnode; }}
DATA_NODE_DEFAULTS_RESOLVED=1 NODE_SLUG=fixture DATA_DETECTED_PUBLIC_IPV4=198.51.100.7
WINN3_GATEWAY_STAGING_DIR={self.area}/stage WINN3_GATEWAY_BIN_NAME=winn3-gateway-linux-amd64
WINN3_GATEWAY_INSTALL_PATH={self.installed} WINN3_GATEWAY_CREDENTIALS_DIR=/nonexistent WINN3_GATEWAY_ID=fixture-gw1
WINN3_ONETOUCH_BINARY_SHA256={pin or self.sha} WINN3_ALLOW_BINARY_REPLACE={allow}
''' + INSTALLER.function("winn3gw_phase_a") + "\nwinn3gw_phase_a\n"
        done = subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=30)
        trace = (self.area / "trace").read_text().splitlines() if (self.area / "trace").exists() else []
        return done.returncode, done.stderr, trace

    def test_a_matching_stage_passes_through_the_cover_preflight_to_the_last_check(self):
        rc, err, trace = self.run_phase()
        self.assertEqual(rc, 0, err)
        self.assertEqual(trace[-1], "offnode")
        self.assertIn("cover preflight", trace)

    def test_a_staged_binary_that_is_not_the_certified_pin_is_refused_before_anything_else(self):
        rc, err, trace = self.run_phase(pin="0" * 64)
        self.assertEqual(rc, 1)
        self.assertIn("certified binary pin", err)
        self.assertNotIn("cover preflight", trace)
        self.assertNotIn("offnode", trace)

    def test_an_unknown_installed_binary_needs_the_explicit_replacement_switch(self):
        rc, err, trace = self.run_phase(installed=b"some other gateway")
        self.assertEqual(rc, 1)
        self.assertIn("WINN3_ALLOW_BINARY_REPLACE=1 is required", err)
        self.assertNotIn("cover preflight", trace)
        rc, err, _ = self.run_phase(installed=b"some other gateway", allow="1")
        self.assertEqual(rc, 0, err)
        rc, err, _ = self.run_phase(installed=self.staged.read_bytes())
        self.assertEqual(rc, 0, err)

    def test_a_failing_cover_preflight_refuses_the_whole_install_before_credentials(self):
        rc, err, trace = self.run_phase(cover_rc=1)
        self.assertEqual(rc, 1)
        self.assertIn("cover preflight", trace)
        self.assertNotIn("tool classify", trace)
        self.assertNotIn("offnode", trace)


class MaintenanceTests(unittest.TestCase):
    def test_weekly_maintenance_restarts_the_gateway_only_when_it_has_failed(self):
        text = INSTALLER.text
        index = text.index("run_step \"restart failed Winn v3 gateway\" wins_serving_start weekly-gateway systemctl restart winn3-gateway.service")
        window = text[max(0, index - 200):index]
        self.assertIn("if systemctl is-failed --quiet winn3-gateway.service; then", window)
        self.assertEqual(text.count("weekly-gateway"), 1, "one gateway restart in weekly maintenance, through the gated start")


class MutantRegistry(unittest.TestCase):
    def test_registry_is_well_formed(self):
        ids = [m["id"] for m in mutant_defs.MUTANTS]
        self.assertEqual(len(ids), len(set(ids)))
        scenario_ids = {i["id"] for i in scenarios.SCENARIOS}
        for mu in mutant_defs.MUTANTS:
            self.assertIn(mu["status"], ("runnable", "pending", "equivalent"))
            if mu["status"] == "equivalent":
                self.assertGreater(len(mu["note"]), 80, "an equivalent mutant must say why")
            elif mu["status"] == "runnable":
                self.assertTrue(mu["tier_a"] or mu["pytest"] or mu["cmd"], mu["id"])
                self.assertTrue(mu["edits"], mu["id"])
                for sid in mu["tier_a"]:
                    self.assertIn(sid, scenario_ids, mu["id"])
                for path in mu["pytest"]:
                    self.assertTrue((ROOT / path).exists(), path)
            else:
                self.assertTrue(mu.get("owner") and mu.get("kill_test"), mu["id"])

    def test_every_edit_applies_the_stated_number_of_times(self):
        import mutants_s7
        for mu in mutant_defs.MUTANTS:
            if mu["status"] != "runnable":
                continue
            text, why = mutants_s7.apply_edits(INSTALLER.text, mu["edits"])
            self.assertIsNotNone(text, "%s: %s" % (mu["id"], why))
            self.assertNotEqual(text, INSTALLER.text, mu["id"])

    def test_every_design_5_6_bullet_group_is_represented(self):
        design = Path(os.environ.get("WINS_S7_DESIGN_FILE", str(ROOT / ".agent/debates/v3-onetouch-20261003/DESIGN_V17.md")))
        if not design.exists():
            self.skipTest("design file unavailable: set WINS_S7_DESIGN_FILE to DESIGN_V17.md")
        section = design.read_text().split("### 5.6 Mutants that must be killed", 1)[1].split("### 5.7", 1)[0]
        bullets = [l for l in section.splitlines() if l.startswith("- ")]
        self.assertGreaterEqual(len(bullets), 100)
        # the registry carries the bullet text of every runnable mutant verbatim in `design`
        runnable_text = " ".join(m["design"] for m in mutant_defs.MUTANTS)
        for needle in ("late-failure handler uses a reason", "dominance check is reduced to membership", "Handler step 2a is removed",
                       "persist_firewall` in the local-serving guard", "re-acquires its fd 9", "v3 can be turned off", "Off-node exemption widened"):
            self.assertIn(needle, runnable_text)

    def test_the_registry_self_check_never_counts_as_a_kill(self):
        """In a mirror the installer is the mutated one, so the self-check above fails for every registered mutant. The
        runner deselects it, and the kill detail names the real test that failed."""
        import mutants_s7
        file_name, cls, method = mutants_s7.REGISTRY_SELF_CHECK.split("::")
        self.assertEqual(file_name, Path(__file__).name)
        self.assertTrue(callable(getattr(globals()[cls], method, None)), mutants_s7.REGISTRY_SELF_CHECK)
        seen = []

        def fake(argv, **kwargs):
            seen.append(argv)
            return mock.Mock(returncode=1, stdout="F\nFAILED test_winn3_onetouch_s7.py::StaticInstallerProperties::test_x - AssertionError\n"
                                                    "1 failed, 3 passed in 0.5s\n", stderr="")
        with tempfile.TemporaryDirectory() as d, mock.patch.object(mutants_s7.subprocess, "run", fake):
            ok, detail = mutants_s7.run_pytest(INSTALLER.text, [mutant_defs.S7], d, "probe")
        self.assertFalse(ok)
        argv = seen[0]
        self.assertEqual(argv[argv.index("--deselect") + 1], mutants_s7.REGISTRY_SELF_CHECK)
        self.assertTrue(detail.startswith("FAILED test_winn3_onetouch_s7.py::StaticInstallerProperties::test_x"), detail)

    def test_the_reboot_anti_vacuity_mutants_list_only_kill_tests_that_kill_them(self):
        """Measured: S4, S5 and S7 pytest all pass on both edits, so neither lists a pytest file; the modelled boot kills
        them in the save-refusal scenario and in the boot-enforce gate, which now rests on the real safe fallback."""
        by = {m["id"]: m for m in mutant_defs.MUTANTS}
        for mid in ("N-fallback-leaves-units-enabled", "N-fallback-leaves-awg-restart-policy"):
            self.assertEqual(by[mid]["pytest"], [], mid)
            self.assertEqual(by[mid]["tier_a"], ["HANDLER-injected-save-refusal", "HANDLER-boot-enforce-gate"], mid)
        self.assertEqual(by["N-guard-docker-stop-unbounded"]["pytest"], [mutant_defs.S7])

    def test_the_mutant_runner_counts_a_wrong_pattern_as_bad_not_survived(self):
        import mutants_s7
        text, why = mutants_s7.apply_edits("abc", [("zzz", "y", 1)])
        self.assertIsNone(text)
        self.assertIn("found 0 times", why)


class StaticInstallerProperties(unittest.TestCase):
    """Properties of the installer with no live fixture here; the mutants named in the registry rely on them."""

    @staticmethod
    def function(name):
        return INSTALLER.function(name)

    def test_the_serving_guard_bounds_its_service_and_docker_stops(self):
        """At boot the guard runs as a oneshot (no start timeout) ordered Before=docker.service. An unbounded docker call
        that reaches docker.socket waits on a docker.service start job that waits on the guard, so enforce never ends."""
        text = INSTALLER.text
        self.assertEqual(text.count("\nstop_customer_services() {\n"), 1)
        body = text.split("\nstop_customer_services() {\n", 1)[1].split("\n}\n", 1)[0]  # inside the guard's here-document
        self.assertIn("timeout -k 5 20 docker stop amnezia-awg2 awg amnezia-awg", body)
        self.assertIn("timeout -k 5 20 systemctl stop winn3-gateway.service xray.service nginx.service", body)
        self.assertIsNone(re.search(r"^\s*(docker|systemctl)\s+stop\b", body, re.M), body)

    def test_the_exit_path_releases_fd7_only_after_the_settle_check(self):
        body = self.function("winn3_installer_exit")
        reassert = body.index("winn3_late_failure_reassert")
        settle = body.index("winn3_late_settle")
        unlock = body.index("winn3_installer_fw_unlock")
        self.assertLess(reassert, settle)
        self.assertLess(settle, unlock)
        self.assertEqual(body.count("winn3_installer_fw_unlock"), 1)
        self.assertLess(body.index("winn3_late_failure_on_exit"), body.index("deploy_firewall_rollback_on_exit"))
        self.assertLess(body.index("deploy_firewall_rollback_on_exit"), reassert)

    def test_phase_order_in_main(self):
        body = self.function("main")
        order = [body.index("\n  " + name + "\n") for name in
                 ("winn3gw_phase_b", "write_firewall", "write_runtime_vpn_firewall_unit", "winn3gw_phase_c", "postflight_data_plane")]
        self.assertEqual(order, sorted(order), "env and units (B) before the authoritative rebuild, then C, then postflight")
        self.assertLess(body.index("\n  apply_bootstrap_firewall\n"), body.index("\n  winn3gw_phase_b\n"))

    def test_phase_c_starts_with_the_egress_check_and_phase_d_keeps_its_gates(self):
        c = self.function("winn3gw_phase_c")
        self.assertLess(c.index("check_gateway_egress_mtu"), c.index("winn3gw_activate"))
        d = self.function("winn3gw_phase_d")
        for needle in ("systemctl is-active --quiet winn3-gateway.service", "systemctl is-enabled --quiet winn3-gateway.service",
                       "--check-winn3-udp-policy", "winn3_node_tool classify", "winn3gw_verify_identity_signature", "identity-ready",
                       "check_gateway_egress_mtu", "WINN3_OFFNODE_CHECK_SHA256", "stat -c '%u:%g:%a:%h' \"${WINN3_HUB_KEY_PRUNE_PATH}\""):
            self.assertIn(needle, d, needle)

    def test_etc_winn_is_0750_everywhere_and_the_latch_unit_names_both_gateway_units(self):
        modes = re.findall(r"install -d -m (\d+) -o root -g \"\$\{WINN3_GATEWAY_SERVICE_USER\}\" /etc/winn\n", INSTALLER.text)
        self.assertGreaterEqual(len(modes), 2)
        self.assertEqual(set(modes), {"750"})
        before = re.search(r"^Before=docker\.service nginx\.service.*$", INSTALLER.text, re.M).group(0)
        self.assertIn("winn3-gateway.service", before)
        self.assertIn("winn3-gateway-firewall.service", before)

    def test_the_exit_handler_is_armed_from_phase_b_and_disarmed_only_at_the_end_of_main(self):
        b = self.function("winn3gw_phase_b")
        self.assertIn("WINN3_LATE_ARMED=1", b)
        self.assertLess(b.index("WINN3_LATE_ARMED=1"), b.index("enable_service"))
        main = self.function("main")
        self.assertEqual(main.count("WINN3_LATE_ARMED=0"), 1)
        self.assertTrue(main.rstrip().rstrip("}").rstrip().endswith("WINN3_LATE_ARMED=0"))

    def test_every_guard_call_of_the_exit_path_is_bounded(self):
        for name in ("winn3_late_failure_on_exit", "winn3_late_failure_reassert"):
            body = self.function(name)
            for call in re.finditer(r"/usr/local/sbin/wins-node-local-serving (disable|enforce)", body):
                window = body[max(0, call.start() - 160):call.start()]
                self.assertIn("WINS_NODE_LOCAL_SERVING_LOCK_WAIT=20", window, name)
                self.assertIn("WINS_FIREWALL_LOCK_HELD=1", window, name)

    def test_no_fixture_writes_a_guest_global_setting(self):
        """sysctl and modprobe are stubbed in every namespace and no fixture calls ethtool, tc on a guest device,
        or writes under /sys or /proc/sys; the one place that must not happen is the host (see the incident in the report)."""
        for path in (TIERS / "linux").glob("*.sh"):
            text = path.read_text()
            for call in re.findall(r"^[^#\n]*\b(sysctl|modprobe|ethtool)\b[^\n]*", text, re.M):
                self.assertIn(path.name, ("fx_lib.sh", "sc_edge.sh"), "%s calls %s" % (path.name, call))
            self.assertNotRegex(text, r">\s*/proc/sys/|>\s*/sys/(?!class/net/s7)", path.name)
        lib = (TIERS / "linux" / "fx_lib.sh").read_text()
        self.assertIn("mount -t sysfs sysfs /sys", lib)
        self.assertIn("for cmd in sysctl modprobe", lib)

    def test_the_bundled_edge_script_reaches_guest_globals_only_through_the_stubbed_names(self):
        """The l80 incident came from the edge script, which the scan above does not read. In the namespace it calls sysctl,
        modprobe and ethtool by bare name, so the PATH stubs intercept them, and it writes no /proc/sys file directly."""
        edge = tier_common.render_edge(INSTALLER)
        self.assertNotRegex(edge, r"/s?bin/(sysctl|modprobe|ethtool)\b")
        self.assertNotRegex(edge, r"(^|[\s;])(export\s+)?PATH=", "the edge script must not reset PATH past the stubs")
        self.assertNotIn("/proc/sys/", edge)

    def test_the_data_plane_has_exactly_one_fail2ban_writer(self):
        """5.6 "A second fail2ban writer": the data plane writes one jail file (DP harden step, winsvpn-sshd.conf). The
        retired gateway installer's writer (write_fail2ban_sshd_jail, named in tools/test_winn3_gateway_block.py) and
        any other write to /etc/fail2ban (a redirect, tee, install, cp, mv, ln, sed -i, or a runtime `fail2ban-client
        set`) is a second writer."""
        writer = re.compile(r"(>>?\s*/etc/fail2ban/\S+|\btee\b[^|;]*\s/etc/fail2ban/|\b(install|cp|mv|ln)\b[^;|&]*\s/etc/fail2ban/\S*[^/\s]"
                            r"|\bsed\s+-i\b[^;|&]*/etc/fail2ban/|\bfail2ban-client\s+set\b)")
        found = []
        for number, line in enumerate(INSTALLER.text.split("\n"), 1):
            if line.lstrip().startswith("#"):
                continue
            if writer.search(line):
                found.append((number, line.strip()))
        self.assertEqual([l for _, l in found], ["cat > /etc/fail2ban/jail.d/winsvpn-sshd.conf <<EOF"], found)
        self.assertNotIn("write_fail2ban_sshd_jail", INSTALLER.text)
        self.assertIn("write_fail2ban_sshd_jail", (ROOT / "tools" / "test_winn3_gateway_block.py").read_text(),
                      "the retired writer's name is still recorded where the block check names it")

    def test_the_ruled_data_plane_literals_hold_under_the_real_verify_rulings(self):
        """RULINGS.lock entries on the data-plane installer (the replay-journal literal among them), checked by the
        repository's own tools/verify_rulings.sh over the installer under test. The script's git-index and Apple checks
        need the real work tree (BLOCK row 14 runs it there); here only the lock entries on this installer are kept, and
        every one of them must print `ok`. A mutated installer in a mirror is checked the same way."""
        path = "server/wins_data_plane_setup_ONETOUCH.sh"
        # the lock and the script come from the repository (tier_common.ROOT: in a mutant mirror only server/ is the
        # mirror's); the installer checked is the one under test
        lock = (tier_common.ROOT / "docs" / "rulings" / "RULINGS.lock").read_text()
        entries = [l for l in lock.splitlines() if not l.startswith("#") and " :: %s :: " % path in l]
        self.assertIn("REQUIRE :: %s :: WINN3_GATEWAY_REPLAY_JOURNAL=1" % path, entries)
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "docs" / "rulings").mkdir(parents=True)
            (Path(d) / "docs" / "rulings" / "RULINGS.lock").write_text("\n".join(entries) + "\n")
            (Path(d) / "server").mkdir()
            (Path(d) / path).write_text(INSTALLER.text)
            done = subprocess.run([BASH, str(tier_common.ROOT / "tools" / "verify_rulings.sh"), d], capture_output=True, text=True, timeout=120)
        lines = done.stdout.splitlines()
        for entry in entries:
            kind, _, literal = entry.split(" :: ", 2)
            self.assertIn("RULINGS: ok   %s %s :: %s" % (kind.strip(), path, literal), lines, done.stdout[-1500:])
        self.assertEqual([l for l in lines if l.startswith("RULINGS: FAIL") and path in l], [])

    def test_no_em_or_en_dash_in_the_harness_files(self):
        for path in list(TIERS.rglob("*")) + [Path(__file__)]:
            if path.is_file() and path.suffix in (".py", ".sh", ".md", ""):
                text = path.read_text(errors="replace")
                self.assertNotIn(chr(0x2014), text, str(path))
                self.assertNotIn(chr(0x2013), text, str(path))


class TierBRunnerTests(NoContact):
    """The step kinds the P2 harness adds: staging, local (hub-lite on this Mac), evaluate with plan facts and stop,
    and private captures. Every test here plans or runs against a fake target; nothing reaches a guest."""

    def plan_for(self, scenario_ids, have, variables=None):
        chosen = [s for s in tier_b_catalogue.catalogue() if s["id"] in scenario_ids]
        return tier_b.render_scenarios(chosen, dict(tier_b_catalogue.VARS, **(variables or {})))

    def run_plan(self, plan, answers, have=("installer-staged",)):
        commands = []

        class Fake:
            name = "fake"

            def run(self, remote, timeout, input_text=None):
                commands.append(remote)
                for needle, reply in answers.items():
                    if needle in remote:
                        return 0, reply, ""
                return 0, "", ""
        with tempfile.TemporaryDirectory() as d:
            ev = tier_common.Evidence(Path(d) / "ev", {"tier": "B"})
            with contextlib.redirect_stdout(io.StringIO()):
                rc = tier_b.execute(plan, Fake(), ev, dict(tier_b_catalogue.VARS), {}, set(have), None, str(Path(d) / "st"),
                                    facts={"installer_sha256": INSTALLER.sha256, "binary_pin": INSTALLER.binary_pin})
            rows = [json.loads(l) for l in (Path(d) / "ev" / "index.jsonl").read_text().splitlines()]
            raws = {r["scenario"]: (Path(d) / "ev" / r["raw"]).read_text() for r in rows}
        return rc, commands, rows, raws

    def test_staging_subcommand_names_the_pins_and_contacts_nothing(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(tier_b.main(["staging"]), 0)
        text = json.loads(out.getvalue())
        self.assertEqual(text["installer_sha256"], INSTALLER.sha256)
        self.assertEqual(text["binary_pin"], INSTALLER.binary_pin)
        self.assertEqual(text["binary_record_line"], INSTALLER.binary_pin + "  winn3-gateway-linux-amd64")
        paths = [i["path"] for i in text["items"]]
        self.assertIn("/root/winn3-gateway-linux-amd64.sha256", paths, "plan A run 1 stopped without it")
        self.assertEqual(text["cover_keys"], list(tier_b_catalogue.COVER_KEYS), "plan A run 2 stopped without them")
        self.assertNotRegex(text["check"], r"\{(installer|secrets_file|shim_dir|work|deploy_args|slug|hublite_state)\}")
        self.assertEqual(self.calls, [])

    def test_a_short_staging_stops_the_scenario_before_the_installer_runs(self):
        plan = self.plan_for({"TB-01-preflight-no-change"}, {"installer-staged"})
        rc, commands, rows, raws = self.run_plan(plan, {"binary_record_check=": staged_reading(binary_record_check="failed")})
        self.assertEqual((rc, rows[0]["status"]), (1, "fail"))
        self.assertFalse(any("--preflight" in c for c in commands), "nothing after the failed staging step ran")
        self.assertIn("STOP: staging failed", raws["TB-01-preflight-no-change"])
        rc, commands, rows, _ = self.run_plan(plan, {"binary_record_check=": staged_reading(), "sha256sum | cut": "d1\n"})
        self.assertEqual((rc, rows[0]["status"]), (0, "pass"))
        self.assertTrue(any("--preflight" in c for c in commands))

    def test_evaluate_steps_are_checked_at_plan_time(self):
        good = [{"id": "X", "design": "5.3 x", "requires": (), "destructive": False, "outline": False,
                 "steps": [tier_b_catalogue.evaluate("n", "evaluate_staging", ["a", "@installer_sha256"])]}]
        tier_b.render_scenarios(good, dict(tier_b_catalogue.VARS))
        for fn, args in (("no_such_evaluator", ["a"]), ("evaluate_staging", ["@token"]), ("_json", ["a"])):
            bad = [dict(good[0], steps=[tier_b_catalogue.evaluate("n", fn, args)])]
            with self.subTest(fn=fn, args=args), self.assertRaises(HarnessRefusal):
                tier_b.render_scenarios(bad, dict(tier_b_catalogue.VARS))
        verdict = tier_b.run_evaluate({"fn": "evaluate_staging", "args": ["missing"], "name": "x"}, {}, {})
        self.assertFalse(verdict["pass"], "an evaluator that raises on a reading is a failed check, not a crash")
        self.assertIn("raised", verdict["reason"])

    def test_local_steps_run_only_the_hub_tools_with_the_state_and_the_capture_on_stdin(self):
        bad = [{"id": "X", "design": "5.3 x", "requires": (), "destructive": False, "outline": False,
                "steps": [tier_b_catalogue.local(["bash", "-c", "true"])]}]
        with self.assertRaises(HarnessRefusal):
            tier_b.render_scenarios(bad, dict(tier_b_catalogue.VARS))
        step = tier_b_catalogue.local(["tierb_hub.py", "import-node", "--slug", "{slug}"], stdin_capture="pulled")
        rendered = tier_b.render_scenarios([dict(bad[0], steps=[step])], dict(tier_b_catalogue.VARS, hublite_state="~/hl"))[0]["steps"][0]
        self.assertEqual(rendered["argv"], ["tierb_hub.py", "import-node", "--slug", "tierb-amd64t"])
        seen = {}

        def fake(argv, **kwargs):
            seen.update(argv=argv, input=kwargs.get("input"))
            return mock.Mock(returncode=0, stdout='{"ok": true}\n', stderr="")
        with mock.patch.object(tier_b.subprocess, "run", fake):
            rc, out, _ = tier_b.run_local(rendered, {"hublite_state": "~/hl"}, {"pulled": "IDENTITY"})
        self.assertEqual(rc, 0)
        self.assertEqual(seen["argv"][:5], [sys.executable, "-E", "-P", "-B", str(tier_b.HERE / "tierb_hub.py")])
        self.assertEqual(seen["argv"][-2:], ["--state", os.path.expanduser("~/hl")])
        self.assertEqual(seen["input"], "IDENTITY")

    def test_a_private_capture_reaches_later_steps_but_never_the_evidence(self):
        secret = "admission-secret-" + "f" * 32
        step = tier_b_catalogue.run("python3 -I -c pull", capture="pulled", private=True)
        check = tier_b_catalogue.expect("pulled", "contains", "admission-secret", "the capture is usable")
        plan = tier_b.render_scenarios([{"id": "P", "design": "5.3 p", "requires": (), "destructive": False, "outline": False,
                                         "steps": [step, check]}], dict(tier_b_catalogue.VARS))
        rc, _, rows, raws = self.run_plan(plan, {"python3 -I -c pull": '{"admission_secret":"%s"}' % secret}, have=())
        self.assertEqual((rc, rows[0]["status"]), (0, "pass"))
        self.assertNotIn(secret, raws["P"])
        self.assertIn("private capture", raws["P"])

    def test_the_pull_step_is_the_hubs_own_identity_pull_program(self):
        remote = tier_b_catalogue.PULL_IDENTITY
        compile(remote, "pull", "exec")
        for needle in ('"/etc/winn/public/gateway-identity.json"', '"/etc/winn/credentials/admission.key"',
                       'line.startswith("DETECTED_PUBLIC_IP=")', 'print(json.dumps(result,separators=(",",":")))'):
            self.assertIn(needle, remote)
        steps = [s for s in tier_b_catalogue.catalogue() if s["id"] == "TB-02-fresh-deploy-state"][0]["steps"]
        pull = next(s for s in steps if s.get("capture") == "pulled")
        self.assertTrue(pull["private"])
        self.assertIn(shlex_quote(remote), pull["cmd"])

    def test_every_hub_lite_requirement_is_wired_to_local_steps(self):
        for item in tier_b_catalogue.catalogue():
            if "hub-lite" in item["requires"] and item["id"] != "TB-30-golive-latency":
                kinds = [s["kind"] for s in item["steps"]]
                self.assertNotIn("hub", kinds, item["id"])
                self.assertIn("local", kinds, item["id"])
                self.assertIn("evaluate", kinds, item["id"])
                self.assertIn("edge-stub", item["requires"], item["id"])
        for sid in ("TB-13-standalone-adoption", "TB-14-rollback-unsuspend"):
            self.assertTrue(any(i["id"] == sid for i in tier_b_catalogue.catalogue()), sid)

    def test_tb06_forces_exactly_the_completion_call(self):
        """The completion's URL travels on curl's stdin, so the shim keys on the jq call that builds its body. That call
        must exist once, inside complete_data_deployment_after_postflight, after release-deployment, and the next curl
        must be the --data-binary completion. Every log text TB-02 and TB-06 expect must be the installer's."""
        body = INSTALLER.function("complete_data_deployment_after_postflight")
        self.assertEqual(INSTALLER.text.count("jq -n --arg withdrawal_id"), 1)
        self.assertLess(body.index("release-deployment"), body.index("jq -n --arg withdrawal_id"))
        after = body.split("jq -n --arg withdrawal_id", 1)[1]
        self.assertLess(after.index("/deployment/complete\""), after.index("--data-binary"))
        self.assertLess(after.index("--data-binary"), after.index("the hub deployment block was not released"))
        for item in tier_b_catalogue.catalogue():
            if item["id"] not in ("TB-02-fresh-deploy-state", "TB-06-completion-failure-after-release"):
                continue
            for step in item["steps"]:
                if step["kind"] == "expect" and step["how"] == "contains" and step["capture"] in ("deploy", "forced", "recover"):
                    self.assertIn(step["value"], INSTALLER.text, (item["id"], step["value"]))

    def test_tb20_and_tb21_judge_every_read_back(self):
        items = {i["id"]: i for i in tier_b_catalogue.catalogue()}
        fns = [s["fn"] for s in items["TB-20-readbacks"]["steps"] if s["kind"] == "evaluate"]
        self.assertEqual(fns, ["evaluate_sysctls", "evaluate_granted_buffers", "evaluate_wan_queue", "evaluate_winn3gw0", "judge_forward_async"])
        fns = [s["fn"] for s in items["TB-21-winn3gw0-restart-series"]["steps"] if s["kind"] == "evaluate"]
        self.assertEqual(fns, ["evaluate_restart_series_capture"])

    def test_tb09_variants_are_driven_except_5_and_7(self):
        items = {i["id"]: i for i in tier_b_catalogue.catalogue()}
        for n in (1, 2, 3, 4, 6, 8, 9):
            item = items["TB-09-variant-%d" % n]
            self.assertFalse(item["outline"], n)
            text = "\n".join(s.get("cmd", "") for s in item["steps"])
            self.assertIn("s7_tb09.sh start %d" % n, text)
            self.assertIn("evaluate_tb09", [s.get("fn") for s in item["steps"]])
            shim_step = next(s for s in item["steps"] if s["kind"] == "shim")
            rules = shim_step["shims"]["ip"][1][0]
            self.assertTrue(rules["held_file"].endswith("/held") and rules["wait_file"].endswith("/go"))
            self.assertNotIn("message", rules, "the driver counts the shim's own `released` line, any message is fine")
            self.assertEqual(set(shim_step["shims"]), {"ip", "systemctl", "flock", "docker"})
        nine = "\n".join(s.get("cmd", "") for s in items["TB-09-variant-9"]["steps"])
        for client in ("keep", "closed"):
            for delay in (45, 150):
                self.assertIn(" %s %d" % (client, delay), nine)
        for n in (5, 7):
            self.assertTrue(items["TB-09-variant-%d" % n]["outline"], n)
        for name in ("s7_tb09.sh", "s7_docker_proxy.py"):
            self.assertIn(name, tier_b.HELPERS)


def shlex_quote(text):
    import shlex
    return shlex.quote(text)


class StateDigestTests(unittest.TestCase):
    """TB-01's STATE_DIGEST (tierb_planA/RESULTS.md: the raw digest hashed iptables-save's timestamp comments, so it
    differed on an idle guest seconds apart). Run on this Mac with stubbed iptables-save, systemctl and find."""

    def digest(self, digest_text, stamp, counter, rule="-A INPUT -p tcp --dport 22 -j ACCEPT", files="/etc/a 1 644 0 0 1.0"):
        save = ("echo '# Generated by iptables-save v1.8.10 (nf_tables) on %s'\necho '*filter'\n"
                "echo ':INPUT DROP [%d:%d]'\necho '[%d:%d] %s'\necho 'COMMIT'\necho '# Completed on %s'\n"
                % (stamp, counter, counter * 60, counter, counter * 60, rule, stamp))
        stubs = {"iptables-save": save, "ip6tables-save": save, "systemctl": "echo 'ssh.service enabled enabled'\n",
                 "find": "echo '%s'\n" % files, "sha256sum": "exec shasum -a 256\n"}
        return run_with_stubs(digest_text, stubs).strip()

    def test_the_digest_ignores_comment_lines_and_counters_but_not_state(self):
        new = tier_b_catalogue.STATE_DIGEST
        first = self.digest(new, "Thu Oct  8 19:00:01 2026", 10)
        self.assertRegex(first, r"^[0-9a-f]{64}$")
        self.assertEqual(first, self.digest(new, "Thu Oct  8 19:00:09 2026", 4711), "idle guest, seconds apart")
        self.assertNotEqual(first, self.digest(new, "Thu Oct  8 19:00:09 2026", 10, rule="-A INPUT -p tcp --dport 23 -j ACCEPT"))
        self.assertNotEqual(first, self.digest(new, "Thu Oct  8 19:00:09 2026", 10, files="/etc/a 2 644 0 0 1.0"))
        raw = new.replace(" | " + tier_b_catalogue.SAVE_STABLE, "")
        self.assertNotEqual(self.digest(raw, "Thu Oct  8 19:00:01 2026", 10), self.digest(raw, "Thu Oct  8 19:00:09 2026", 10),
                            "the unstripped digest of plan A differs on the same state")

    def test_tb01_uses_the_stable_digest_on_both_sides(self):
        item = next(i for i in tier_b_catalogue.catalogue() if i["id"] == "TB-01-preflight-no-change")
        digests = [s for s in item["steps"] if s["kind"] == "run" and s.get("capture") in ("before", "after")]
        self.assertEqual([s["cmd"] for s in digests], [tier_b_catalogue.STATE_DIGEST] * 2)
        self.assertEqual(tier_b_catalogue.STATE_DIGEST.count(tier_b_catalogue.SAVE_STABLE), 2)


class TierBEvaluatorTests(unittest.TestCase):
    """Every evaluator the P2 harness adds: a right reading passes, each wrong reading fails."""

    def test_staging(self):
        ev = tierb_eval.evaluate_staging
        self.assertTrue(ev(staged_reading(), INSTALLER.sha256, INSTALLER.binary_pin)["pass"])
        wrong = {"another installer": {"installer_sha256": "0" * 64}, "another binary": {"binary_sha256": "1" * 64},
                 "a record naming another digest": {"binary_record": "2" * 64}, "the record check failed": {"binary_record_check": "failed"},
                 "no builder": {"amneziawg_builder": "absent"}, "no apt key": {"cloudflare_gpg": "absent"},
                 "secrets 0644": {"secrets_mode": "root 644"}, "no secrets file": {"secrets_mode": ""},
                 "a cover key missing": {"cover_WINN3_COVER_ECH_KEYS_B64": "0"}, "a cover key twice": {"cover_WINN3_COVER_KEY_B64": "2"}}
        for name, change in wrong.items():
            with self.subTest(name):
                self.assertFalse(ev(staged_reading(**change), INSTALLER.sha256, INSTALLER.binary_pin)["pass"])
        self.assertFalse(ev("", INSTALLER.sha256, INSTALLER.binary_pin)["pass"])

    SNAP = ("main=4242\nactive=active\nkey %s /etc/winn/credentials/static.key\nkey %s /etc/winn/credentials/admission.key\n"
            "sessions=3\ncarrying=2\nready=True\n" % ("a" * 64, "b" * 64))

    def test_rerun_unchanged(self):
        ev = tierb_eval.evaluate_rerun_unchanged
        right = ev(self.SNAP, self.SNAP)
        self.assertTrue(right["pass"], right)
        self.assertFalse(right["carrying_vacuous"])
        wrong = {"a new MainPID": self.SNAP.replace("main=4242", "main=4300"), "a changed key": self.SNAP.replace("a" * 64, "c" * 64),
                 "a carrying session lost": self.SNAP.replace("carrying=2", "carrying=1"),
                 "the gateway stopped": self.SNAP.replace("active=active", "active=inactive"),
                 "the count unreadable": self.SNAP.replace("sessions=3\ncarrying=2\nready=True\n", "status=unreadable\n")}
        for name, after in wrong.items():
            with self.subTest(name):
                self.assertFalse(ev(self.SNAP, after)["pass"])
        self.assertFalse(ev(self.SNAP.replace("main=4242", "main=0"), self.SNAP.replace("main=4242", "main=0"))["pass"], "no gateway at all")
        idle = self.SNAP.replace("carrying=2", "carrying=0")
        self.assertTrue(ev(idle, idle)["carrying_vacuous"], "zero on both sides is reported as vacuous")

    def test_the_session_count_comes_from_the_gateways_serve_status(self):
        """main.go serveStatus carries sessions, carrying and ready; /run/winn3-gateway/status.json (the proof status)
        carries none of them, so the earlier snapshot always read them as unreadable."""
        gateway = (tier_common.ROOT / "winn_protocol_experimental/cmd/winn3-gateway/main.go").read_text()
        for field in ('`json:"sessions"`', '`json:"carrying"`', '`json:"ready"`'):
            self.assertIn(field, gateway)
        status = '{"event":"status","ready":true,"forward":true,"sessions":3,"carrying":2}'
        stubs = {"systemctl": 'case "$*" in *InvocationID*) echo inv1 ;; *MainPID*) echo 4242 ;; *) echo active ;; esac\n',
                 "journalctl": "echo 'winn3-gateway: UDP socket buffers requested 16777216, granted read=33554432 write=33554432'\n"
                               "echo '%s'\necho 'some other line'\n" % status,
                 "sha256sum": "exec shasum -a 256 \"$@\"\n"}
        out = run_with_stubs(tierb_eval.SNAPSHOT_RERUN, stubs)
        facts = tierb_eval.kv(out)
        self.assertEqual((facts.get("main"), facts.get("sessions"), facts.get("carrying"), facts.get("ready")), ("4242", "3", "2", "True"), out)
        stubs["journalctl"] = "echo 'no status yet'\n"
        self.assertIn("status=unreadable", run_with_stubs(tierb_eval.SNAPSHOT_RERUN, stubs))

    # --- TB-09 ----------------------------------------------------------------------------------------------------
    T0 = 1791500000.0

    @staticmethod
    def recorded():
        import datetime as dt
        return dt.datetime.fromisoformat("2026-10-08T20:00:00+00:00").timestamp()

    def record(self, **fields):
        base = {"stage": "B", "activation_lock": "held", "activation_fence": "done", "first_lock": "contended",
                "settle_window_seconds": "120", "settle_stops": "", "fence_killed": "no", "time": "2026-10-08T20:00:00+00:00"}
        base.update(fields)
        return json.dumps(base, separators=(",", ":"))

    def tb09(self, variant, **facts):
        import datetime as dt
        recorded = dt.datetime.fromisoformat("2026-10-08T20:00:00+00:00").timestamp()
        base = {"variant": str(variant), "installer_failed": "1", "ip_wait_timeout": "0", "released_at": "%.3f" % (recorded - 200),
                "last_handler_stop": "%.3f" % (recorded - 150), "serving_starts": "", "after_nginx": "inactive",
                "after_xray": "inactive", "after_winn3-gateway": "inactive", "record": self.record(),
                "first_flock": "%.3f" % (recorded - 190), "container_amnezia-awg2": "false 2026-10-08T19:50:00Z"}
        base.update(facts)
        return ["%s=%s" % kv for kv in base.items()]

    def ok(self, lines):
        verdict = tierb_eval.evaluate_tb09("\n".join(lines))
        self.assertTrue(verdict["pass"], verdict)

    def bad(self, lines):
        self.assertFalse(tierb_eval.evaluate_tb09("\n".join(lines))["pass"])

    def test_tb09_common_darkness(self):
        self.ok(self.tb09(6, record=self.record(activation_lock="unavailable")))
        six = dict(record=self.record(activation_lock="unavailable"))
        for name, change in {"a start after the last stop": {"serving_starts": "%.3f" % (self.T0 * 2)},
                             "nginx active": {"after_nginx": "active"}, "a container running": {"container_awg": "true 2026-10-08T20:00:00Z"},
                             "the failure never fired": {"installer_failed": "0"}, "the hold timed out": {"ip_wait_timeout": "1"},
                             "no record": {"record": ""}, "the fence failed": {"record": self.record(activation_lock="unavailable", activation_fence="failed")},
                             "the driver stopped": {"error": "the installer ended"}, "no stop read": {"last_handler_stop": ""}}.items():
            with self.subTest(name):
                self.bad(self.tb09(6, **dict(six, **change)))
        self.bad(self.tb09(6))  # variant 6 must take the unavailable path

    def test_tb09_variants_1_to_4(self):
        self.ok(self.tb09(1, caller_log="caller_rc=0|"))
        self.bad(self.tb09(1, caller_log="caller_rc=0|", record=self.record(activation_lock="unavailable")))
        self.bad(self.tb09(1, caller_log="caller_rc=0|", record=self.record(first_lock="acquired")))
        self.bad(self.tb09(1, caller_log="wins-serving: skip|"))
        self.ok(self.tb09(2, child_at_106="gone"))
        self.ok(self.tb09(2, child_at_106="Z"))
        self.bad(self.tb09(2, child_at_106="T"))
        self.bad(self.tb09(2, child_at_106="gone", record=self.record(activation_lock="unavailable")))
        three = dict(scope_procs_at_106="empty", child_at_106="gone", scope_journal="x.scope: Failed with result 'timeout'.|",
                     timeout_state_at_106="T", timeout_pgid="300", parent_pgid="200",
                     record=self.record(activation_lock="unavailable", time="2026-10-08T20:00:00+00:00"))
        self.ok(self.tb09(3, **three))
        for name, change in {"the scope still holds a process": {"scope_procs_at_106": "4321 "},
                             "the child alive": {"child_at_106": "S"},
                             "ended by timeout's signal": {"scope_journal": "x.scope: Deactivated successfully.|"},
                             "timeout not held stopped": {"timeout_state_at_106": "S"},
                             "the normal path": {"record": self.record(activation_lock="held")},
                             "before t_p + 120 s": {"first_flock": "%.3f" % (self.recorded() - 60)},
                             "no process groups": {"timeout_pgid": ""}}.items():
            with self.subTest(name):
                self.bad(self.tb09(3, **dict(three, **change)))
        self.ok(self.tb09(4, record=self.record(activation_lock="unavailable"), caller_log="wins-serving: skip vault: late-failure hold|"))
        self.bad(self.tb09(4, record=self.record(activation_lock="unavailable"), caller_log="caller_rc=0|"))
        self.bad(self.tb09(4, caller_log="wins-serving: skip vault: late-failure hold|"))

    def test_tb09_variant_8_needs_a_stop_after_dockerd_completed(self):
        import datetime as dt
        done = dt.datetime(2026, 10, 8, 20, 0, 10, tzinfo=dt.timezone.utc)
        requested = done.timestamp() - 8
        eight = dict(container="awg", container_awg="false 2026-10-08T20:00:10.500000000Z",
                     restart_requested_at="%.3f" % requested, docker_stops_awg="%.3f" % (done.timestamp() + 12))
        self.ok(self.tb09(8, **eight))
        self.bad(self.tb09(8, **dict(eight, docker_stops_awg="%.3f" % (done.timestamp() - 1))))
        self.bad(self.tb09(8, **dict(eight, docker_stops_awg="")))
        self.bad(self.tb09(8, **dict(eight, after_nginx="active")))
        self.bad(self.tb09(8, **dict(eight, record=self.record(settle_window_seconds="30"))))
        self.bad(self.tb09(8, **dict(eight, container_awg="")))
        self.assertAlmostEqual(tierb_eval.docker_time("2026-10-08T20:00:10.5Z"), done.timestamp() + 0.5, places=3)

    def test_tb09_variant_9(self):
        def proxy(forwarded, completed):
            return ("listening /s 1.000|accepted POST POST_/v1.45/containers/awg/restart?t=10_HTTP/1.1 100.000|"
                    "forwarded POST_/v1.45/containers/awg/restart?t=10_HTTP/1.1 %.3f|"
                    "completed POST_/v1.45/containers/awg/restart?t=10_HTTP/1.1 HTTP/1.1_204_No_Content %.3f|" % (forwarded, completed))
        keep = dict(client="keep", d="45", container="awg", client_fd6="/run/lock/wins-serving-activation.lock",
                    proxy_log=proxy(1000.0, 1002.0), docker_stops_awg="1003.000",
                    record=self.record(first_lock="contended", fence_killed="no"))
        self.ok(self.tb09(9, **keep))
        self.assertEqual(tierb_eval.evaluate_tb09("\n".join(self.tb09(9, **keep)))["trigger"], "first_lock contended")
        for name, change in {"the first flock -n 6 succeeded": {"record": self.record(first_lock="acquired")},
                             "the fence killed the client": {"record": self.record(fence_killed="yes")},
                             "fd 6 not shown": {"client_fd6": ""},
                             "never forwarded": {"proxy_log": "listening /s 1.000|"},
                             "no stop after completion": {"docker_stops_awg": "1001.000"},
                             "the window is 30": {"record": self.record(settle_window_seconds="30")}}.items():
            with self.subTest(name):
                self.bad(self.tb09(9, **dict(keep, **change)))
        closed = dict(keep, client="closed", caller_unit_after_handoff="inactive", record=self.record(fence_killed="yes"))
        self.ok(self.tb09(9, **closed))
        self.bad(self.tb09(9, **dict(closed, record=self.record(fence_killed="no"))))
        self.bad(self.tb09(9, **dict(closed, caller_unit_after_handoff="active")))
        late = dict(keep, d="150", docker_stops_awg="", container_awg="true 2026-10-08T20:05:00Z", serving_starts="", after_nginx="active")
        self.ok(self.tb09(9, **late))  # D = 150 s: completion after the window is outside 2.7's claim; recorded only
        self.bad(self.tb09(9, **dict(keep, client="other")))

    # --- hub-lite outputs ---------------------------------------------------------------------------------------------
    STATUS = {"ok": True, "slug": "s", "operator_enabled": 0, "protocol_version": "winn/1", "deployment_released_at": "t1",
              "deployment_completed_at": "t1", "health_closed_reason": "fresh_install", "descriptor_seq": None, "descriptor_kid": None,
              "latest_promotion_source": None}

    def status(self, **change):
        return json.dumps(dict(self.STATUS, **change))

    def test_fresh_golive(self):
        ev = tierb_eval.evaluate_fresh_golive
        released = self.status()
        provision = json.dumps({"ok": True, "result": {"ok": True, "seq": 0}})
        flipped = self.status(protocol_version="winn/3", descriptor_seq=0, descriptor_kid="g2")
        live = dict(self.STATUS, operator_enabled=1, protocol_version="winn/3", latest_promotion_source="auto_golive_fresh_install",
                    latest_promotion_tier="free")
        sweep = json.dumps({"ok": True, "reopened": ["s"], "held": {}, "status": live})
        served = json.dumps({"ok": True, "platforms": {p: {"listed": True} for p in ("default", "android", "linux", "ios")}})
        self.assertTrue(ev(released, provision, flipped, sweep, served)["pass"])
        wrong = {"not released": (self.status(deployment_released_at=None), provision, flipped, sweep, served),
                 "released open": (self.status(operator_enabled=1), provision, flipped, sweep, served),
                 "not fresh_install": (self.status(health_closed_reason="installer_rerun"), provision, flipped, sweep, served),
                 "not signed": (released, json.dumps({"ok": False, "result": {"ok": False, "reason": "deployment-not-released"}}), flipped, sweep, served),
                 "no flip": (released, provision, self.status(descriptor_seq=0), sweep, served),
                 "the flip opened it": (released, provision, self.status(protocol_version="winn/3", descriptor_seq=0, operator_enabled=1), sweep, served),
                 "held": (released, provision, flipped, json.dumps({"reopened": [], "held": {"s": "x"}, "status": live}), served),
                 "another source": (released, provision, flipped, json.dumps({"reopened": ["s"], "status": dict(live, latest_promotion_source="manual")}), served),
                 "not served on ios": (released, provision, flipped, sweep, served.replace('"ios": {"listed": true}', '"ios": {"listed": false}')),
                 "no output": ("", "", "", "", "")}
        for name, args in wrong.items():
            with self.subTest(name):
                self.assertFalse(ev(*args)["pass"])

    def test_completion_failure(self):
        ev = tierb_eval.evaluate_completion_failure
        before = self.status(operator_enabled=1)
        withdrawn = self.status(operator_enabled=0)
        after = self.status(operator_enabled=1, latest_promotion_source="auto_reopen_installer_rerun")
        sweep = json.dumps({"reopened": ["s"], "held": {}})
        self.assertTrue(ev(before, withdrawn, sweep, after)["pass"])
        for name, args in {"was not live": (withdrawn, withdrawn, sweep, after), "stayed open": (before, before, sweep, after),
                           "never reopened": (before, withdrawn, json.dumps({"reopened": [], "held": {"s": "streak"}}), withdrawn),
                           "reopened by hand": (before, withdrawn, sweep, self.status(operator_enabled=1, latest_promotion_source="manual"))}.items():
            with self.subTest(name):
                self.assertFalse(ev(*args)["pass"])

    KEYS = "".join("key %s %s\n" % (c * 64, n) for c, n in zip("abcd", ("admission.key", "dual-auth-ed-key", "dual-auth-ml-seed", "static.key")))

    def test_adoption_node(self):
        ev = tierb_eval.evaluate_adoption_node
        before = "role=data-winn3\ngateway_id=n-gw1\n" + self.KEYS + "identity_file=absent\nbackups=0\ngateway_active=active\n"
        after = ("role=data-cover\ngateway_id=n-gw1\n" + self.KEYS + "identity_file=present\nbackups=1\nbackup_check=ok\n"
                 "backup_files=MANIFEST.sha256 files manifest.json restore.sh winn3-node.py \ngateway_active=active\n")
        self.assertTrue(ev(before, after)["pass"], ev(before, after))
        wrong = {"not standalone-built": (before.replace("data-winn3", "data-cover"), after),
                 "a key changed": (before, after.replace("a" * 64, "e" * 64)),
                 "three keys only": (before.replace("key " + "d" * 64 + " static.key\n", ""), after.replace("key " + "d" * 64 + " static.key\n", "")),
                 "another gateway id": (before, after.replace("gateway_id=n-gw1", "gateway_id=n-gw2")),
                 "marker kept": (before, after.replace("role=data-cover", "role=data-winn3")),
                 "no backup": (before, after.replace("backups=1", "backups=0")),
                 "a manifest that fails": (before, after.replace("backup_check=ok", "backup_check=failed")),
                 "no restore script": (before, after.replace("restore.sh ", "")),
                 "gateway down": (before, after.replace("gateway_active=active", "gateway_active=failed"))}
        for name, (b, a) in wrong.items():
            with self.subTest(name):
                self.assertFalse(ev(b, a)["pass"])

    def test_step14_node(self):
        ev = tierb_eval.evaluate_step14_node
        keys = "".join("key %s /etc/winn/credentials/%s\n" % (c * 64, n) for c, n in zip("abcd", ("static.key", "admission.key", "auth_ed25519.seed", "auth_mldsa65.seed")))
        before = "gateway_id=n-gw1\n" + keys + "gateway_active=active\ngateway_enabled=enabled\nfirewall_enabled=enabled\nenv_file=present\nlisten_9111=1 1\n"
        rolled = "gateway_id=\n" + keys + "gateway_active=inactive\ngateway_enabled=disabled\nfirewall_enabled=disabled\nenv_file=absent\nlisten_9111=0 0\n"
        self.assertTrue(ev(before, rolled, before)["pass"], ev(before, rolled, before))
        wrong = {"still running": (before, rolled.replace("gateway_active=inactive", "gateway_active=active"), before),
                 "still enabled": (before, rolled.replace("firewall_enabled=disabled", "firewall_enabled=enabled"), before),
                 "env kept": (before, rolled.replace("env_file=absent", "env_file=present"), before),
                 "9111 bound": (before, rolled.replace("listen_9111=0 0", "listen_9111=1 0"), before),
                 "keys removed": (before, rolled.replace("key " + "a" * 64 + " /etc/winn/credentials/static.key\n", ""), before),
                 "new keys after the rerun": (before, rolled, before.replace("b" * 64, "f" * 64)),
                 "another gateway id": (before, rolled, before.replace("n-gw1", "n-gw9")),
                 "not restored": (before, rolled, rolled)}
        for name, args in wrong.items():
            with self.subTest(name):
                self.assertFalse(ev(*args)["pass"])

    def test_adoption_and_step14_hub_readings(self):
        adopt = json.dumps({"ok": True, "stored_status": 200, "ledger_state": "suspended", "ledger_live_kid": "g1",
                            "ledger_live_seq": 41, "ledger_floor": 1000041})
        unsuspend = json.dumps({"ok": True, "state": "active"})
        rekey = json.dumps({"ok": True, "request": {"expected_prior_seq": 41}, "seq": 1000042, "kid": "g2"})
        status = self.status(descriptor_kid="g2")
        ev = tierb_eval.evaluate_adoption_hub
        self.assertTrue(ev(adopt, unsuspend, rekey, status)["pass"])
        for name, args in {"not reconciled": (adopt.replace('"suspended"', '"active"'), unsuspend, rekey, status),
                           "presented -1": (adopt, unsuspend, rekey.replace('"expected_prior_seq": 41', '"expected_prior_seq": -1'), status),
                           "issued below the floor": (adopt, unsuspend, rekey.replace("1000042", "42"), status),
                           "still suspended": (adopt, json.dumps({"ok": False, "error": "slug-suspended"}), rekey, status),
                           "rekey refused": (adopt, unsuspend, json.dumps({"ok": False, "error": "deployment-not-released"}), status),
                           "still g1": (adopt, unsuspend, rekey, self.status(descriptor_kid="g1"))}.items():
            with self.subTest(name):
                self.assertFalse(ev(*args)["pass"])
        hold = json.dumps({"ok": True, "generation_before": 3, "deployment_generation": 4, "winn3_operator_hold": 1, "protocol_version": "winn/1"})
        withhold = json.dumps({"ok": True, "descriptor_stored": False})
        suspend = json.dumps({"ok": True, "state": "suspended"})
        unhold = json.dumps({"ok": True, "winn3_operator_hold": 0})
        ev = tierb_eval.evaluate_step14_hub
        self.assertTrue(ev(hold, withhold, suspend, unsuspend, unhold, status)["pass"])
        for name, args in {"no bump": (hold.replace('"deployment_generation": 4', '"deployment_generation": 3'), withhold, suspend, unsuspend, unhold, status),
                           "still winn/3": (hold.replace("winn/1", "winn/3"), withhold, suspend, unsuspend, unhold, status),
                           "descriptor kept": (hold, withhold.replace("false", "true"), suspend, unsuspend, unhold, status),
                           "suspend refused": (hold, withhold, json.dumps({"ok": False, "error": "generation-not-bumped-first"}), unsuspend, unhold, status),
                           "unsuspend refused": (hold, withhold, suspend, json.dumps({"ok": False}), unhold, status),
                           "hold kept": (hold, withhold, suspend, unsuspend, unhold.replace('"winn3_operator_hold": 0', '"winn3_operator_hold": 1'), status)}.items():
            with self.subTest(name):
                self.assertFalse(ev(*args)["pass"])


class FailClosedEvaluatorTests(unittest.TestCase):
    """F4-HARNESS (Astra, FINAL4 Turn 2): kv dropped every key with a hyphen, so TB-09 passed with
    after_winn3-gateway=active or container_amnezia-awg2=true, and it passed with every service-state reading omitted.
    Each case is a reading an evaluator must refuse (missing, unparsable, or carried under a hyphenated name) or a right
    reading under the real hyphenated names it must accept; FINAL4 tree.t2 judged every one of them the other way. A
    refusal is pass False, adopt False or ValueError. Each mutant reverts one piece of the fix and must break a case."""

    FX = TierBEvaluatorTests()
    PROXY = ("listening /s 1.000|accepted POST POST_/v1.45/containers/{0}/restart?t=10_HTTP/1.1 100.000|"
             "forwarded POST_/v1.45/containers/{0}/restart?t=10_HTTP/1.1 1000.000|"
             "completed POST_/v1.45/containers/{0}/restart?t=10_HTTP/1.1 HTTP/1.1_204_No_Content 1002.000|")

    @staticmethod
    def accepted(thunk, ev, rb):
        try:
            return bool(thunk(ev, rb))
        except ValueError:
            return False

    def cases(self):
        """[(label, accepted, thunk)]: thunk(tierb_eval, readbacks) judges one reading."""
        fx = self.FX

        def tb09(variant, drop=(), **facts):
            text = "\n".join(line for line in fx.tb09(variant, **facts) if line.split("=", 1)[0] not in drop)
            return lambda ev, rb: ev.evaluate_tb09(text)["pass"]

        def record_without(key):
            record = json.loads(fx.record())
            del record[key]
            return json.dumps(record, separators=(",", ":"))

        six = dict(record=fx.record(activation_lock="unavailable"))
        units = ("after_nginx", "after_xray", "after_winn3-gateway")
        keep = dict(client="keep", d="45", container="awg", client_fd6="/run/lock/wins-serving-activation.lock",
                    proxy_log=self.PROXY.format("awg"), docker_stops_awg="1003.000",
                    record=fx.record(first_lock="contended", fence_killed="no"))
        closed = dict(keep, client="closed", caller_unit_after_handoff="inactive", record=fx.record(fence_killed="yes"))
        done = fx.recorded() + 10
        eight = {"container": "amnezia-awg2", "container_amnezia-awg2": "false 2026-10-08T20:00:10.500000000Z",
                 "restart_requested_at": "%.3f" % (done - 8), "docker_stops_amnezia-awg2": "%.3f" % (done + 12)}
        nine = dict(keep, container="amnezia-awg2", proxy_log=self.PROXY.format("amnezia-awg2"), **{"docker_stops_amnezia-awg2": "1003.000"})
        del nine["docker_stops_awg"]
        refused = {
            "evaluate_tb09": {
                "Astra: the gateway unit active under its hyphenated key": tb09(6, **six, **{"after_winn3-gateway": "active"}),
                "Astra: the AWG container running under its hyphenated name": tb09(6, **six, **{"container_amnezia-awg2": "true 2026-10-08T20:00:00Z"}),
                "Astra: every service-state reading omitted": tb09(6, drop=units + ("container_amnezia-awg2",), **six),
                "the gateway unit state omitted": tb09(6, drop=("after_winn3-gateway",), **six),
                "the nginx state omitted": tb09(6, drop=("after_nginx",), **six),
                "a unit still activating": tb09(6, after_xray="activating", **six),
                "no AWG container state": tb09(6, drop=("container_amnezia-awg2",), **six),
                "a hyphen-named container state that does not parse": tb09(6, **six, **{"container_amnezia-awg2": "running"}),
                "a container state that does not parse": tb09(6, container_awg="yes", **six),
                "a container start that is not a date": tb09(6, **six, **{"container_amnezia-awg2": "false 2026-13-45T00:00:00Z"}),
                "the wait-timeout count omitted": tb09(6, drop=("ip_wait_timeout",), **six),
                "a forced-failure count that does not parse": tb09(6, installer_failed="yes", **six),
                "serving_starts omitted": tb09(6, drop=("serving_starts",), **six),
                "a serving start that does not parse": tb09(6, serving_starts="soon", **six),
                "a last handler stop that is not a number": tb09(6, last_handler_stop="nan", **six),
                "variant 1: activation_lock unknown": tb09(1, caller_log="caller_rc=0|", record=fx.record(activation_lock="unknown")),
                "variant 1: activation_lock omitted": tb09(1, caller_log="caller_rc=0|", record=record_without("activation_lock")),
                "variant 2: activation_lock unknown": tb09(2, child_at_106="gone", record=fx.record(activation_lock="unknown")),
                "variant 9 keep: fence_killed unknown": tb09(9, **dict(keep, record=fx.record(fence_killed="unknown"))),
                "variant 9 closed: the caller unit's state omitted": tb09(9, drop=("caller_unit_after_handoff",), **closed),
                "variant 9: D omitted": tb09(9, drop=("d",), **keep),
                "variant 9: a D that is not driven": tb09(9, **dict(keep, d="90")),
            },
        }
        accepted = {
            "evaluate_tb09": {
                "variant 8 on the data plane's container amnezia-awg2": tb09(8, **eight),
                "variant 9 D=45 on the data plane's container amnezia-awg2": tb09(9, **nine),
            },
        }

        def staging(plan_digest, plan_pin, **change):
            return lambda ev, rb: ev.evaluate_staging(staged_reading(**change), plan_digest, plan_pin)["pass"]

        refused["evaluate_staging"] = {
            "no plan installer digest": staging("", INSTALLER.binary_pin, installer_sha256=""),
            "no binary pin": staging(INSTALLER.sha256, "", binary_sha256="", binary_record=""),
        }

        keys = "".join("key %s /etc/winn/credentials/%s\n" % (c * 64, n) for c, n in zip("abcd", ("static.key", "admission.key", "auth_ed25519.seed", "auth_mldsa65.seed")))
        before = "gateway_id=n-gw1\n" + keys + "gateway_active=active\ngateway_enabled=enabled\nfirewall_enabled=enabled\nenv_file=present\nlisten_9111=1 1\n"
        rolled = {"gateway_id": "", "gateway_active": "inactive", "gateway_enabled": "disabled", "firewall_enabled": "disabled",
                  "env_file": "absent", "listen_9111": "0 0"}

        def step14(drop=(), **change):
            text = keys + "".join("%s=%s\n" % kv for kv in dict(rolled, **change).items() if kv[0] not in drop)
            return lambda ev, rb: ev.evaluate_step14_node(before, text, before)["pass"]

        refused["evaluate_step14_node"] = {
            "the rolled-back gateway state omitted": step14(drop=("gateway_active",)),
            "both is-enabled states omitted": step14(drop=("gateway_enabled", "firewall_enabled")),
            "a unit enabled-runtime": step14(firewall_enabled="enabled-runtime"),
            "the gateway still activating": step14(gateway_active="activating"),
        }

        hub = {"hold": {"ok": True, "generation_before": 3, "deployment_generation": 4, "winn3_operator_hold": 1, "protocol_version": "winn/1"},
               "withhold": {"ok": True, "descriptor_stored": False}, "suspend": {"ok": True, "state": "suspended"},
               "unsuspend": {"ok": True, "state": "active"}, "unhold": {"ok": True, "winn3_operator_hold": 0},
               "status": dict(fx.STATUS, descriptor_kid="g2")}

        def hub14(**change):
            args = [json.dumps(change.get(name, value)) for name, value in hub.items()]
            return lambda ev, rb: ev.evaluate_step14_hub(*args)["pass"]

        refused["evaluate_step14_hub"] = {
            "a hold without generation_before": hub14(hold={k: v for k, v in hub["hold"].items() if k != "generation_before"} | {"deployment_generation": 1}),
            "a final status without ok": hub14(status={k: v for k, v in hub["status"].items() if k != "ok"}),
        }

        def unslugged(**change):
            return {k: v for k, v in dict(fx.STATUS, **change).items() if k != "slug"}

        live = unslugged(operator_enabled=1, protocol_version="winn/3", latest_promotion_source="auto_golive_fresh_install", latest_promotion_tier="free")
        golive = [json.dumps(x) for x in (unslugged(), {"ok": True, "result": {"ok": True, "seq": 0}},
                                          unslugged(protocol_version="winn/3", descriptor_seq=0, descriptor_kid="g2"),
                                          {"ok": True, "reopened": [None], "held": {}, "status": live},
                                          {"ok": True, "platforms": {p: {"listed": True} for p in ("default", "android", "linux", "ios")}})]
        recovery = [json.dumps(x) for x in (fx.STATUS | {"operator_enabled": 1}, fx.STATUS, {"reopened": [None], "held": {}},
                                            unslugged(operator_enabled=1, latest_promotion_source="auto_reopen_installer_rerun"))]
        refused["evaluate_fresh_golive"] = {"no slug read from the hub": lambda ev, rb: ev.evaluate_fresh_golive(*golive)["pass"]}
        refused["evaluate_completion_failure"] = {"no slug read after recovery": lambda ev, rb: ev.evaluate_completion_failure(*recovery)["pass"]}

        nan = float("nan")
        good = "134217728 134217728 212992 212992 1 5000"

        def golive_runs(**change):
            runs = [{"completed": 100.0 + i, "enabled": 160.0 + i, "proof_ok_at": {"canary": 120.0 + i}} for i in range(10)]
            runs[0].update(change)
            return lambda ev, rb: rb.evaluate_golive(runs)["pass"]

        low = {"rise_ms": 30, "throughput_gbit": 1.0, "loss": 0.0, "jitter_ms": 5}

        def rule(base, candidate, **kw):
            return lambda ev, rb: rb.rule_r_adopt(base, candidate, **kw)["adopt"]

        no_loss = {k: v for k, v in low.items() if k != "loss"} | {"rise_ms": 20}
        refused.update({
            "evaluate_sysctls": {"an empty owners reading": lambda ev, rb: rb.evaluate_sysctls(good, "")["pass"],
                                 "the two data-plane files at two values": lambda ev, rb: rb.evaluate_sysctls(
                                     "268435456 134217728 1 1 1 1", "".join(
                                         "/etc/sysctl.d/99-winsvpn-%s.conf:net.core.%s_max=%s\n" % (f, k, v) for f, k, v in (
                                             ("edge", "rmem", "134217728"), ("edge", "wmem", "134217728"),
                                             ("node", "rmem", "268435456"), ("node", "wmem", "134217728"))))["pass"]},
            "evaluate_golive": {"a run with no proof reading": golive_runs(proof_ok_at={}),
                                "a proof time that is not a number": golive_runs(proof_ok_at={"canary": nan})},
            "evaluate_connect": {"no samples": lambda ev, rb: rb.evaluate_connect({})["pass"],
                                 "a sample that is not a number": lambda ev, rb: rb.evaluate_connect({("wifi", "a"): [nan] * 10})["pass"]},
            "evaluate_ryzen": {"a run that is not a number": lambda ev, rb: rb.evaluate_ryzen([nan] * 10, [1.9] * 10)["pass"]},
            "rule_r_adopt": {"the candidate's loss omitted": rule(low, no_loss),
                             "p99 recorded on the base only": rule(dict(low, p99_rise_ms=40), dict(low, rise_ms=20)),
                             "the CPU ceiling without cpu_pct": rule(low, dict(low, rise_ms=20), cpu_ceiling_points=5),
                             "a loss that is not a number": rule(low, dict(low, rise_ms=20, loss=nan)),
                             "a noise reading that is not a number": rule(low, dict(low, rise_ms=33, throughput_gbit=1.5), noise={"rise_ms": nan})},
            "rule_r_adopt_profiles": {"a profile without loss": lambda ev, rb: rb.rule_r_adopt_profiles({"a": low}, {"a": no_loss})["adopt"]},
            "refuse_emulated": {"a node class with no virt reading": lambda ev, rb: rb.refuse_emulated({}),
                                "the dry-run node class": lambda ev, rb: rb.refuse_emulated({"dry_run": True})},
        })
        both = "".join("/etc/sysctl.d/99-winsvpn-%s.conf:net.core.%s_max=134217728\n" % (f, k)
                       for f in ("edge", "node") for k in ("rmem", "wmem"))
        accepted["evaluate_sysctls"] = {"the data plane's node and edge files at one value": lambda ev, rb: rb.evaluate_sysctls(good, both)["pass"]}
        out = [("%s: %s" % (fn, name), False, thunk) for fn, named in refused.items() for name, thunk in named.items()]
        return out + [("%s: %s" % (fn, name), True, thunk) for fn, named in accepted.items() for name, thunk in named.items()]

    def test_each_reading_is_judged_the_right_way(self):
        cases = self.cases()
        self.assertGreaterEqual(len(cases), 45)
        for label, want, thunk in cases:
            with self.subTest(label):
                self.assertEqual(self.accepted(thunk, tierb_eval, readbacks), want)

    def emitted_keys(self):
        """Every key s7_tb09.sh's emit() prints, with its loop variables expanded, and every key the node snapshots echo."""
        script = (tier_common.LINUX_DIR / "s7_tb09.sh").read_text()
        loops = {}
        for var, words in re.findall(r"\bfor (\w+) in ([^;$`]+?); do", script):
            loops.setdefault(var, set()).update(words.split())
        keys = set()
        for key in re.findall(r'\bemit\s+"?([^\s"]+)"?\s', script):
            names = [key]
            for var, cut in set(re.findall(r"\$\{(\w+)(%%\.\*)?\}", key)):
                names = [n.replace("${%s%s}" % (var, cut), word.split(".")[0] if cut else word) for n in names for word in loops[var]]
            keys.update(names)
        for snapshot in (tierb_eval.SNAPSHOT_RERUN, tierb_eval.SNAPSHOT_ADOPTION, tierb_eval.SNAPSHOT_STEP14):
            keys.update(re.findall(r'(?:echo |print\()"?([A-Za-z0-9_.-]+)=', snapshot))
        return keys

    def unread_keys(self, kv):
        return sorted(key for key in self.emitted_keys() if "$" in key or kv("%s=v" % key) != {key: "v"})

    def test_every_key_the_drivers_emit_is_read(self):
        keys = self.emitted_keys()
        self.assertTrue({"after_winn3-gateway", "container_amnezia-awg2", "docker_stops_amnezia-awg2", "pre_winn3-gateway",
                         "variant", "record", "main", "carrying", "gateway_active", "listen_9111"} <= keys, sorted(keys))
        self.assertEqual(self.unread_keys(tierb_eval.kv), [])

    # (name, module, the fixed text, the text it reverts to); each applies exactly once
    MUTANTS = (
        ("kv drops hyphenated keys", "tierb_eval", 'r"[A-Za-z0-9_][A-Za-z0-9_.-]*"', 'r"[A-Za-z_0-9]+"'),
        ("a unit state is dark unless it reads active", "tierb_eval", "if state not in STOPPED:", 'if state == "active":'),
        ("no AWG container state is required", "tierb_eval", "if not any(name in containers for name in AWG_CONTAINERS):", "if False:"),
        ("an unparsable container state is ignored", "tierb_eval",
         'problems.append("the %s container state does not parse: %r" % (name, value))', "pass"),
        ("an omitted wait-timeout count passes", "tierb_eval", 'if facts.get("ip_wait_timeout") != "0":',
         'if facts.get("ip_wait_timeout") not in (None, "", "0"):'),
        ("any forced-failure count but 0 passes", "tierb_eval", 'if not re.fullmatch(r"[1-9]\\d*", facts.get("installer_failed") or ""):',
         'if facts.get("installer_failed") in (None, "", "0"):'),
        ("omitted serving_starts read as none", "tierb_eval", "if last is None or text is None:\n        return None\n    starts = [_num(x) for x in text.split()]",
         'if last is None:\n        return None\n    starts = [_num(x) for x in (text or "").split()]'),
        ("an unparsable serving start is dropped", "tierb_eval", "if None in starts:\n        return None\n    return [s for s in starts if s >= last]",
         "return [s for s in starts if s is not None and s >= last]"),
        ("_num accepts nan", "tierb_eval", "return value if math.isfinite(value) else None", "return value"),
        ("variant 1 only refuses unavailable", "tierb_eval", 'if lock != "held":\n            problems.append("variant 1',
         'if lock == "unavailable":\n            problems.append("variant 1'),
        ("variant 2 only refuses unavailable", "tierb_eval", 'if lock != "held":\n            problems.append("variant 2',
         'if lock == "unavailable":\n            problems.append("variant 2'),
        ("variant 9 keep only refuses fence_killed yes", "tierb_eval", 'if rec.get("fence_killed") != "no":', 'if rec.get("fence_killed") == "yes":'),
        ("variant 9 closed only refuses an active caller", "tierb_eval", 'if facts.get("caller_unit_after_handoff") not in STOPPED:',
         'if facts.get("caller_unit_after_handoff") == "active":'),
        ("variant 9 takes any D", "tierb_eval", 'if facts.get("d") not in ("45", "150"):', "if False:"),
        ("staging takes an empty plan digest", "tierb_eval", 'if not re.fullmatch(r"[0-9a-f]{64}", value or ""):', "if False:"),
        ("TB-02 takes no slug", "tierb_eval", 'if not slug:\n        problems.append("no slug was read from the hub")\n', "if False:\n        pass\n"),
        ("TB-06 takes no slug", "tierb_eval", 'if not slug:\n        problems.append("no slug was read from the hub after recovery")', "if False:\n        pass"),
        ("STEP-14 rollback only refuses an active gateway", "tierb_eval", 'if r.get("gateway_active") not in STOPPED:', 'if r.get("gateway_active") == "active":'),
        ("STEP-14 rollback only refuses enabled", "tierb_eval", 'if r.get("gateway_enabled") != "disabled" or r.get("firewall_enabled") != "disabled":',
         'if r.get("gateway_enabled") == "enabled" or r.get("firewall_enabled") == "enabled":'),
        ("STEP-14 hold reads a missing generation as 0", "tierb_eval",
         'not isinstance(h.get("generation_before"), int) or h.get("deployment_generation") != h["generation_before"] + 1',
         'h.get("deployment_generation") != (h.get("generation_before") or 0) + 1'),
        ("STEP-14 status without ok passes", "tierb_eval", 'st.get("ok") is not True', 'st.get("ok") is False'),
        ("sysctls take no owner", "readbacks",
         'problems.append("no file read as setting %s (an empty owners reading is not one owner)" % key)\n            continue',
         "continue"),
        ("sysctls count files again", "readbacks", "values = sorted({value for found in files.values() for value in found})",
         "values = [got[key]] if len(files) == 1 else [0]"),
        ("go-live takes an unread run", "readbacks", "if unread:\n", "if False:\n"),
        ("_finite accepts nan", "readbacks", "and math.isfinite(value)", ""),
        ("connect takes no samples", "readbacks", "if not samples:\n", "if False:\n"),
        ("connect takes a non-number", "readbacks", 'if not all(_finite(v) for v in values):\n            problems.append("%s: a sample', 'if False:\n            problems.append("%s: a sample'),
        ("Ryzen takes a non-number", "readbacks", 'if not all(_finite(v) for v in values):\n            problems.append("%s: a run', 'if False:\n            problems.append("%s: a run'),
        ("rule R needs no core reading", "readbacks", "needed = set(RULE_R_REQUIRED) | ", "needed = set() | "),
        ("rule R skips a one-sided key", "readbacks", "if k in base or k in candidate}", "if k in base and k in candidate}"),
        ("rule R takes the ceiling without cpu_pct", "readbacks", "if cpu_ceiling_points is not None:\n        needed.add", "if False:\n        needed.add"),
        ("rule R takes non-numeric noise", "readbacks", 'missing += sorted("noise " + k for k, v in noise.items() if not _finite(v))', "missing += []"),
        ("refuse_emulated takes no virt", "readbacks", 'if not node_class.get("virt"):', "if False:"),
    )

    @staticmethod
    def load(module, text):
        mutant = importlib.util.module_from_spec(importlib.util.spec_from_loader(module.__name__ + "_mutant", loader=None))
        exec(compile(text, module.__file__, "exec"), mutant.__dict__)
        return mutant

    def broken(self, ev, rb):
        wrong = [label for label, want, thunk in self.cases() if self.accepted(thunk, ev, rb) != want]
        return wrong + ["kv: " + key for key in self.unread_keys(ev.kv)]

    def test_each_mutant_breaks_a_case(self):
        modules = {"tierb_eval": tierb_eval, "readbacks": readbacks}
        texts = {name: Path(module.__file__).read_text() for name, module in modules.items()}
        self.assertEqual(self.broken(self.load(tierb_eval, texts["tierb_eval"]), self.load(readbacks, texts["readbacks"])), [],
                         "an unmutated copy loaded the same way breaks no case")
        self.assertGreaterEqual(len(self.MUTANTS), 30)
        for name, module, fixed, reverted in self.MUTANTS:
            with self.subTest(name):
                self.assertEqual(texts[module].count(fixed), 1, "the mutant must apply exactly once")
                mutant = self.load(modules[module], texts[module].replace(fixed, reverted))
                ev, rb = (mutant, readbacks) if module == "tierb_eval" else (tierb_eval, mutant)
                self.assertTrue(self.broken(ev, rb), "survived")


def _hub_lite_available():
    try:
        import hub_lite  # noqa: F401
        import fastapi  # noqa: F401
        import starlette  # noqa: F401
    except ImportError:
        return False
    return shutil.which("ssh-keygen") is not None


@unittest.skipUnless(_hub_lite_available(), "hub-lite needs fastapi, starlette and ssh-keygen")
class HubLiteWiring(unittest.TestCase):
    """The catalogue's own local steps for TB-02, TB-13 and TB-14, executed in order by tier_b.run_local against a real
    hub-lite state. hub-lite's emulated node stands in for the guest: its bootstrap, registration and complete-fresh
    are the calls the real installer makes through the served hub, and its pulled identity is what the guest's
    identity pull returns. The evaluators then judge the real outputs."""

    def setUp(self):
        import hub_lite
        self.hl = hub_lite
        self.dir = Path(tempfile.mkdtemp(prefix="s7hub-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.state = self.dir / "hub"
        self.vars = dict(tier_b_catalogue.VARS, hublite_state=str(self.state))

    def guest(self, slug, **kwargs):
        hub = self.hl.HubLite(self.state, init=not (self.state / "manifest.json").exists(), endpoint_pin_workaround=True, **kwargs)
        return hub

    def steps(self, scenario_id, slug):
        item = next(i for i in tier_b_catalogue.catalogue() if i["id"] == scenario_id)
        rendered = tier_b.render_scenarios([item], dict(self.vars, slug=slug))[0]["steps"]
        return [s for s in rendered if s["kind"] in ("local", "evaluate") or s.get("capture") == "pulled"]

    def run_locals(self, steps, captures, until=None):
        for step in steps:
            if step["kind"] != "local" or (until and step.get("capture") == until):
                if until and step.get("capture") == until:
                    return
                continue
            rc, out, err = tier_b.run_local(step, self.vars, captures)
            self.assertTrue(step["rc"] is None or rc == step["rc"], (step["argv"], out[-500:], err[-1500:]))
            if step.get("capture"):
                captures[step["capture"]] = out

    def test_tb02_hub_steps_reach_go_live_and_the_evaluator_agrees(self):
        slug = "tb02-node"
        hub = self.guest(slug)
        try:
            hub.node(slug, endpoint_ip="198.51.100.10")                     # the guest bootstraps and registers
            host_key = hub._host_key(slug)[1] + " root@guest\n"
            pulled = json.dumps(hub.pulled_identity(slug))
        finally:
            hub.close()
        steps = self.steps("TB-02-fresh-deploy-state", slug)
        captures = {"host_key": host_key, "pulled": pulled}
        ticket = next(s for s in steps if s.get("capture") == "ticket")
        rc, out, err = tier_b.run_local(ticket, self.vars, captures)
        self.assertEqual(rc, 0, out + err[-1000:])
        self.assertEqual(json.loads(out)["posted_status"], 200)
        hub = self.guest(slug)
        try:
            done = hub.complete_fresh(slug)                                 # the installer's complete-fresh
            self.assertEqual(done["status_code"], 200, done)
            self.assertTrue(done["body"]["auto_golive_pending"], "the go_live=auto ticket was in place before complete-fresh")
        finally:
            hub.close()
        self.run_locals([s for s in steps if s.get("capture") != "ticket"], captures)
        verdict = tierb_eval.evaluate_fresh_golive(*(captures[k] for k in ("hub_released", "provision", "hub_flipped", "sweep", "served")))
        self.assertTrue(verdict["pass"], (verdict, captures["sweep"][-800:]))
        self.assertEqual(verdict["descriptor_kid"], "g2")
        for value in (json.loads(pulled)["admission_secret"], (self.state / "admin_token").read_text().strip()):
            for text in captures.values():
                if text is not pulled:
                    self.assertNotIn(value, text, "no local step prints a secret")

    def test_tb14_hub_steps_hold_suspend_unsuspend_and_the_evaluator_agrees(self):
        slug = "tb14-node"
        hub = self.guest(slug)
        try:
            hub.node(slug, endpoint_ip="198.51.100.11")
            hub.ticket(slug, "new")
            self.assertEqual(hub.complete_fresh(slug)["status_code"], 200)
            self.assertTrue(hub.provision(slug)["result"]["ok"])
            pulled = json.dumps(hub.pulled_identity(slug))
        finally:
            hub.close()
        captures = {"pulled": pulled}
        steps = self.steps("TB-14-rollback-unsuspend", slug)
        self.run_locals(steps, captures)
        verdict = tierb_eval.evaluate_step14_hub(*(captures[k] for k in ("hold", "withhold", "suspend", "unsuspend", "unhold", "hub_after")))
        self.assertTrue(verdict["pass"], (verdict, {k: v[-300:] for k, v in captures.items() if k != "pulled"}))
        self.assertEqual(json.loads(captures["suspend"])["state"], "suspended")

    def test_tb13_hub_steps_reconcile_from_g1_and_rekey_and_the_evaluator_agrees(self):
        slug = "tb13-node"
        hub = self.guest(slug)
        try:
            hub.node(slug, endpoint_ip="198.51.100.12")
            pulled = json.dumps(hub.pulled_identity(slug))
        finally:
            hub.close()
        captures = {"pulled": pulled}
        steps = self.steps("TB-13-standalone-adoption", slug)
        before_rekey = [s for s in steps if s.get("capture") in ("imported", "adopt_g1")]
        self.run_locals(before_rekey, captures)
        hub = self.guest(slug)
        try:
            self.assertEqual(hub.complete_fresh(slug)["status_code"], 200)  # the adopting installer run released it
        finally:
            hub.close()
        self.run_locals([s for s in steps if s.get("capture") in ("unsuspend", "rekey_ticket", "rekey", "adopted_status")], captures)
        verdict = tierb_eval.evaluate_adoption_hub(*(captures[k] for k in ("adopt_g1", "unsuspend", "rekey", "adopted_status")))
        self.assertTrue(verdict["pass"], (verdict, {k: v[-300:] for k, v in captures.items() if k != "pulled"}))


class FD9TraceJudge(unittest.TestCase):
    """linux/s7_fd9_trace.py on canned `strace -f -o` traces: the unmutated shape passes; the reacquisition mutant's shape
    (a second open of the lock file onto fd 9 in the guard's shell and a second flock utility process) fails."""

    def judge(self, text):
        sys.path.insert(0, str(TIERS / "linux"))
        try:
            import s7_fd9_trace
        finally:
            sys.path.remove(str(TIERS / "linux"))
        return s7_fd9_trace.judge(text, "100", "/run/lock/wins-node-local-serving.lock")

    GOOD = "\n".join([
        '100 openat(AT_FDCWD, "/run/lock/wins-node-local-serving.lock", O_RDWR|O_CREAT, 0666) = 3',
        "100 dup2(3, 9) = 9",
        "100 close(3) = 0",
        "101 close(3) = 0",
        "101 flock(9, LOCK_EX) = 0",
        "101 +++ exited with 0 +++",
        '100 openat(AT_FDCWD, "/etc/winsvpn/local-serving.disabled.tmp", O_WRONLY|O_CREAT|O_TRUNC, 0600) = 3',
        "100 close(3) = 0",
        "102 close(9) = 0",
        "102 flock(7, LOCK_EX) = 0",
        "102 +++ exited with 0 +++",
        "100 +++ exited with 0 +++",
    ]) + "\n"

    def test_the_unmutated_trace_passes(self):
        verdict = self.judge(self.GOOD)
        self.assertTrue(verdict["pass"], verdict)
        self.assertEqual((verdict["utility_pid"], verdict["acquisitions_before"], verdict["acquisitions_after"]), (101, 1, 0))

    def test_wrong_traces_fail(self):
        reacquired = self.GOOD.replace("100 +++ exited with 0 +++",
                                       '100 openat(AT_FDCWD, "/run/lock/wins-node-local-serving.lock", O_RDWR|O_CREAT, 0666) = 3\n'
                                       "100 dup2(3, 9) = 9\n103 flock(9, LOCK_EX) = 0\n103 +++ exited with 0 +++\n100 +++ exited with 0 +++")
        cases = {
            "the reacquisition mutant": reacquired,
            "a close of fd 9 in the guard's shell": self.GOOD.replace("100 close(3) = 0\n102", "100 close(9) = 0\n102"),
            "a dup onto fd 9 in the guard's shell": self.GOOD.replace("100 close(3) = 0\n102", "100 dup2(4, 9) = 9\n102"),
            "close_range over fd 9": self.GOOD.replace("100 close(3) = 0\n102", "100 close_range(3, 4294967295, 0) = 0\n102"),
            "the shell locks fd 9 itself": self.GOOD.replace("101 flock(9, LOCK_EX) = 0", "100 flock(9, LOCK_EX) = 0"),
            "the utility failed": self.GOOD.replace("101 +++ exited with 0 +++", "101 +++ exited with 1 +++"),
            "an empty trace": "",
        }
        for name, text in cases.items():
            with self.subTest(name):
                self.assertFalse(self.judge(text)["pass"])
        unfinished = self.GOOD.replace("101 flock(9, LOCK_EX) = 0", "101 flock(9, LOCK_EX <unfinished ...>\n100 close(3) = 0\n101 <... flock resumed>) = 0")
        self.assertTrue(self.judge(unfinished)["pass"], "an interleaved, resumed call is joined")


class TierAAvailability(unittest.TestCase):
    def test_a_missing_guest_program_blocks_the_scenario_instead_of_passing_it(self):
        items = [i for i in scenarios.SCENARIOS if i["id"] == "STRACE-fd9-trace"]
        self.assertEqual(items[0]["needs"], ["strace"])

        class Runner:
            def run(self, command, timeout=60, purpose=""):
                self.command = command
                return mock.Mock(stdout="missing strace\n", stderr="", returncode=0, dry=False)
        runner = Runner()
        self.assertEqual(tier_a.missing_tools(runner, items), {"STRACE-fd9-trace": ["strace"]})
        self.assertIn("command -v", runner.command)
        Runner.run = lambda self, command, timeout=60, purpose="": mock.Mock(stdout="", stderr="", returncode=0, dry=False)
        self.assertEqual(tier_a.missing_tools(Runner(), items), {})
        Runner.run = lambda self, command, timeout=60, purpose="": mock.Mock(stdout="", stderr="", returncode=255, dry=False)
        self.assertEqual(tier_a.missing_tools(Runner(), items), {"STRACE-fd9-trace": ["strace"]}, "an unreadable probe blocks")

    def test_a_mutant_whose_only_kill_scenario_cannot_run_is_unavailable_not_survived(self):
        import mutants_s7
        mutant = {"id": "M", "status": "runnable", "edits": [("a", "b", 1)], "cmd": [], "pytest": [], "tier_a": ["STRACE-fd9-trace"],
                  "profile": "quick"}
        args = mock.Mock(command="run", all_kills=False, profile="quick", vm="l80", timeout=10)
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(mutants_s7.tier_a, "missing_tools", lambda runner, items: {"STRACE-fd9-trace": ["strace"]}), \
                mock.patch.object(mutants_s7.tier_a, "run_fixtures", side_effect=AssertionError("nothing may run")):
            outcome = mutants_s7.run_one(mutant, "a", args, d)
        self.assertEqual(outcome[1], "UNAVAILABLE", outcome)
        self.assertIn("strace", outcome[2])
        both = dict(mutant, tier_a=["STRACE-fd9-trace", "GUARD-rotate-keeps-fd9"])
        summary = {"guard-rotate-keeps-fd9": {"ok": 3, "not-ok": 1, "failures": ["contender overtook"]}}
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(mutants_s7.tier_a, "missing_tools", lambda runner, items: {"STRACE-fd9-trace": ["strace"]}), \
                mock.patch.object(mutants_s7.tier_a, "run_fixtures", return_value=(summary, "", "", 0, None)):
            outcome = mutants_s7.run_one(both, "a", args, d)
        self.assertEqual(outcome[1], "KILLED")
        self.assertIn("unavailable: STRACE-fd9-trace needs strace", outcome[2], "the deterministic arm's absence is recorded")


class DriverScripts(unittest.TestCase):
    def test_the_tb09_driver_finds_the_installed_serving_start(self):
        """The installed scripts carry wins_serving_start in `declare -f` form; the driver's reader takes that and the source form."""
        source = INSTALLER.function("wins_serving_start")
        rendered = subprocess.run([BASH, "-c", source + "\ndeclare -f wins_serving_start"], capture_output=True, text=True).stdout
        self.assertTrue(rendered.startswith("wins_serving_start () \n{ \n"), rendered[:40])
        self.assertIn("timeout -k 5 100 systemd-run --scope", rendered)
        driver = (TIERS / "linux" / "s7_tb09.sh").read_text()
        reader = re.search(r"^serving_start_fn\(\) \{ (awk '.*?' )\"\$1\"", driver, re.M).group(1)
        for form in (rendered, source + "\n"):
            with tempfile.NamedTemporaryFile("w", suffix=".sh") as f:
                f.write("#!/bin/bash\nx=1\n" + form + "wins_serving_start weekly-nginx true\n")
                f.flush()
                out = subprocess.run([BASH, "-c", reader + shlex_quote(f.name)], capture_output=True, text=True).stdout
            self.assertTrue(out.strip().endswith("}"), out[-80:])
            self.assertIn("timeout -k 5 100 systemd-run --scope", out)
            self.assertEqual(subprocess.run([BASH, "-n"], input=out, capture_output=True, text=True).returncode, 0)
        for path in (TIERS / "linux" / "s7_tb09.sh", TIERS / "linux" / "sc_strace.sh", TIERS / "linux" / "sc_edge.sh"):
            self.assertEqual(subprocess.run([BASH, "-n", str(path)], capture_output=True, text=True).returncode, 0, path.name)

    def test_the_tb09_driver_reads_the_installers_real_names(self):
        driver = (TIERS / "linux" / "s7_tb09.sh").read_text()
        text = INSTALLER.text
        for name in ("/usr/local/libexec/winsvpn/wins-serving-activate", "/run/lock/wins-serving-activation.lock",
                     "/var/lib/winsvpn/winn3-late-failure.json", "/usr/local/bin/wins-weekly-maintenance", "/usr/local/sbin/wins-vault-unlock"):
            self.assertIn(name, driver)
            self.assertIn(name, text)
        self.assertIn("wins-serving-activation-", text)
        self.assertIn("timeout -k 5 30 systemctl disable --now winn3-gateway.service winn3-gateway-firewall.service", text,
                      "the variant 9 hook greps this handler stop")
        self.assertIn("flock -n 6", self.function_text("winn3_late_failure_on_exit"))
        for field in ('"activation_lock"', '"activation_fence"', '"first_lock"', '"settle_window_seconds"', '"settle_stops"', '"fence_killed"'):
            self.assertIn(field.strip('"'), self.function_text("winn3_late_record"))

    def function_text(self, name):
        return INSTALLER.function(name)



@unittest.skipUnless(os.environ.get("WINS_S7_VM"), "set WINS_S7_VM=l80 to run Tier A on the guest")
class TierAOnTheGuest(unittest.TestCase):
    def test_quick_profile_passes_on_the_unmutated_installer(self):
        vm = os.environ["WINS_S7_VM"]
        scratch = Path(os.environ.get("WINS_S7_SCRATCH", str(Path.home() / ".cache" / "winsvpn-s7-tiers")))
        scratch.mkdir(parents=True, exist_ok=True)
        items = tier_a.select("quick", set())
        fixtures = [i["fixture"] for i in items if not i.get("blocked")]
        summary, stdout, stderr, rc, _ = tier_a.run_fixtures(INSTALLER, vm, fixtures, "quick", scratch, timeout=1500)
        bad = {k: v["failures"][:3] for k, v in summary.items() if v["not-ok"]}
        self.assertEqual(bad, {}, stdout[-2000:])
        self.assertEqual(rc, 0, stderr[-500:])
        for fixture in fixtures:
            self.assertGreater(summary.get(fixture, {}).get("ok", 0), 0, fixture)


if __name__ == "__main__":
    unittest.main()
