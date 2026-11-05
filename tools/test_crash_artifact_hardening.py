#!/usr/bin/env python3
"""F-11 regression tests: crash dumps, journals, swap and hibernation.

HANDOFF 3g F-11 requires core dumps disabled for every secret-bearing service
and system-wide, covering BOTH systemd-coredump and Ubuntu apport; journald
behaviour stated explicitly rather than inherited from `Storage=auto`; swap,
hibernation and crash artifacts checked for secret persistence; and -- the part
that actually matters -- verification with a harmless test process, because a
configuration that was never observed to work is not a control.

Before this change none of the five roles touched any of it: no core_pattern,
no LimitCORE, no coredump.conf, no apport, no journald.conf drop-in.

What is real and what is a fake (HANDOFF 3b evidence category B):

  REAL: the shipped harden_crash_artifacts and
        verify_crash_artifacts_suppressed, extracted verbatim from the role
        scripts. When Docker and a Linux image are available these run FOR REAL
        against a real kernel: a real /proc/sys/kernel/core_pattern is set, a
        real process is sent a real SIGABRT, and the absence of a real core file
        is checked. That is the "harmless test process" F-11 asks for.

  FAKE: nothing, in the container path. The static tests below parse the shipped
        text and prove the block is present and identical in all five roles;
        they do not execute anything.

macOS has no /proc and no systemd, so the execution tests SKIP there and run in
a container instead. They never silently pass.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "server"
ROLES = (
    "wins_control_plane_setup_ONETOUCH.sh",
    "wins_core_server_setup_ONETOUCH.sh",
    "wins_data_plane_setup_ONETOUCH.sh",
    "wins_cowrie_honeypot_ONETOUCH.sh",
    "wins_honeynet_setup_ONETOUCH.sh",
)
BLOCK_START = "# --- F-11: crash dumps, journals, swap and hibernation (HANDOFF 3g) --------"


def extract_block(text: str) -> str:
    start = text.index(BLOCK_START)
    terminator = "  verify_crash_artifacts_suppressed\n}"
    end = text.index(terminator, start) + len(terminator)
    return text[start:end]


class AllRolesCoveredTests(unittest.TestCase):
    """F-11 says 'all five roles'. Prove it, and prove they cannot drift."""

    def setUp(self):
        self.sources = {r: (SERVER / r).read_text(encoding="utf-8") for r in ROLES}

    def test_every_role_has_the_block(self):
        for role, text in self.sources.items():
            self.assertIn("harden_crash_artifacts()", text, role)
            self.assertIn("verify_crash_artifacts_suppressed()", text, role)

    def test_the_block_is_byte_identical_across_roles(self):
        blocks = {r: extract_block(t) for r, t in self.sources.items()}
        reference = blocks[ROLES[0]]
        for role, block in blocks.items():
            self.assertEqual(
                block, reference,
                f"{role}'s F-11 block has drifted from {ROLES[0]}'s; "
                "these must stay identical or the roles diverge silently",
            )

    def test_every_role_actually_calls_it(self):
        # Defining the function and never calling it is the classic way a
        # hardening control is 'present' and does nothing.
        for role, text in self.sources.items():
            block = extract_block(text)
            # Everything outside the block's own definition. The call site
            # differs per role (main, deploy, or a --deploy branch), so look at
            # the whole file rather than at one expected location.
            outside = text.replace(block, "")
            calls = [
                line.strip()
                for line in outside.split("\n")
                if "harden_crash_artifacts" in line and not line.strip().startswith("#")
            ]
            self.assertTrue(
                calls, f"{role} defines harden_crash_artifacts but never calls it",
            )

    def test_verification_is_not_optional(self):
        # harden_crash_artifacts must END by verifying, and the verification
        # must be able to fail the deploy.
        source = self.sources[ROLES[0]]
        block = extract_block(source)
        self.assertIn("  verify_crash_artifacts_suppressed\n}", block)
        verifier = source[source.index("verify_crash_artifacts_suppressed() {"):]
        self.assertIn("VERIFICATION FAILED", verifier)
        self.assertIn("Refusing to continue", verifier)


class CoverageContentTests(unittest.TestCase):
    """Each F-11 bullet must be addressed by something concrete."""

    def setUp(self):
        self.block = extract_block((SERVER / ROLES[0]).read_text(encoding="utf-8"))

    def test_kernel_core_pattern_discards(self):
        self.assertIn("kernel.core_pattern=|/bin/false", self.block)
        self.assertIn("fs.suid_dumpable=0", self.block)

    def test_systemd_default_limit_core_is_zero(self):
        # limits.d only covers PAM logins; systemd services never consult it.
        self.assertIn("DefaultLimitCORE=0:0", self.block)
        self.assertIn("/etc/systemd/system.conf.d", self.block)

    def test_systemd_coredump_is_covered(self):
        self.assertIn("Storage=none", self.block)
        self.assertIn("systemctl mask systemd-coredump.socket", self.block)

    def test_apport_is_covered(self):
        self.assertIn("/etc/default/apport", self.block)
        self.assertIn("enabled=0", self.block)
        self.assertIn("mask apport.service", self.block)
        self.assertLess(
            self.block.index("systemctl stop apport.service"),
            self.block.index("sysctl -q -p /etc/sysctl.d/99-winsvpn-coredump.conf"),
            "apport must be stopped before applying the discard core_pattern",
        )

    def test_existing_crash_artifacts_are_removed(self):
        self.assertIn("/var/crash", self.block)
        self.assertIn("/var/lib/systemd/coredump", self.block)

    def test_journald_storage_is_explicit_and_bounded(self):
        self.assertIn("/etc/systemd/journald.conf.d", self.block)
        self.assertIn("Storage=${journal_storage}", self.block)
        self.assertIn('WINS_JOURNAL_STORAGE:-volatile', self.block)
        for bound in ("RuntimeMaxUse=", "SystemMaxUse=", "MaxRetentionSec="):
            self.assertIn(bound, self.block)

    def test_journald_storage_value_is_validated(self):
        self.assertIn("volatile|persistent|auto|none", self.block)

    def test_stale_persistent_journal_is_removed_when_volatile(self):
        self.assertIn("rm -rf -- /var/log/journal", self.block)

    def test_hibernation_is_blocked(self):
        # A resume image is the entire contents of RAM, written to swap.
        self.assertIn("AllowHibernation=no", self.block)
        self.assertIn("mask hibernate.target", self.block)
        self.assertIn("/sys/power/resume", self.block)

    def test_hub_unit_pins_limit_core_explicitly(self):
        control = (SERVER / ROLES[0]).read_text(encoding="utf-8")
        unit = control.split('cat > "${SERVICE_FILE}" <<EOF')[1].split("\nEOF\n")[0]
        self.assertIn("LimitCORE=0", unit)


def _docker_image():
    """A local Linux image to run the real verification in. No pull."""
    if not shutil.which("docker"):
        return None
    try:
        proc = subprocess.run(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
            capture_output=True, text=True, timeout=60,
        )
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    available = set(proc.stdout.split())
    for candidate in ("debian:bookworm-slim", "ubuntu:24.04", "python:3.12-slim"):
        if candidate in available:
            return candidate
    return None


DOCKER_IMAGE = _docker_image()


@unittest.skipUnless(
    DOCKER_IMAGE,
    "no local Linux container image; the real F-11 verification cannot run on macOS "
    "(no /proc, no systemd). Run this suite on Linux or with a cached image.",
)
class RealVerificationTests(unittest.TestCase):
    """Runs verify_crash_artifacts_suppressed FOR REAL against a real kernel.

    This is the 'harmless test process' F-11 requires: a real process gets a
    real SIGABRT and the absence of a real core file is observed.
    """

    @classmethod
    def setUpClass(cls):
        text = (SERVER / ROLES[0]).read_text(encoding="utf-8")
        block = extract_block(text)
        # Only the verification half: the hardening half masks systemd units and
        # restarts journald, neither of which exists in a container.
        cls.verify_fn = block[block.index("verify_crash_artifacts_suppressed() {"):]
        cls.tmp = tempfile.mkdtemp(prefix="wins-f11-")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def run_in_container(self, preamble: str):
        script = (
            "#!/usr/bin/env bash\n"
            "log()  { printf '[INFO] %s\\n' \"$*\"; }\n"
            "warn() { printf '[WARN] %s\\n' \"$*\" >&2; }\n"
            "err()  { printf '[ERR] %s\\n' \"$*\" >&2; }\n"
            "_f11_log()  { log \"$@\"; }\n"
            "_f11_warn() { warn \"$@\"; }\n"
            "_f11_err()  { err \"$@\"; }\n"
            + preamble + "\n" + self.verify_fn
            + "\nverify_crash_artifacts_suppressed\n"
        )
        path = os.path.join(self.tmp, "verify.sh")
        Path(path).write_text(script, encoding="utf-8")
        # Baked into the image rather than bind-mounted: the mount layer on this
        # host caches stale entries for the scratch directory.
        ctx = os.path.join(self.tmp, "ctx")
        os.makedirs(ctx, exist_ok=True)
        shutil.copy(path, os.path.join(ctx, "verify.sh"))
        Path(os.path.join(ctx, "Dockerfile")).write_text(
            f"FROM {DOCKER_IMAGE}\nCOPY verify.sh /verify.sh\n", encoding="utf-8"
        )
        tag = "wins-f11-verify:test"
        build = subprocess.run(
            ["docker", "build", "-q", "-t", tag, ctx],
            capture_output=True, text=True, timeout=300,
        )
        self.assertEqual(build.returncode, 0, build.stderr)
        return subprocess.run(
            # --privileged so the container can write /proc/sys/kernel/core_pattern,
            # which is what makes this a real test of the real control.
            ["docker", "run", "--rm", "--privileged", tag, "bash", "/verify.sh"],
            capture_output=True, text=True, timeout=300,
        )

    def test_verification_passes_once_the_control_is_applied(self):
        preamble = (
            "echo '|/bin/false' > /proc/sys/kernel/core_pattern\n"
            "echo 0 > /proc/sys/fs/suid_dumpable\n"
        )
        proc = self.run_in_container(preamble)
        self.assertEqual(proc.returncode, 0, f"stdout={proc.stdout}\nstderr={proc.stderr}")
        self.assertIn("F-11 verified", proc.stdout)
        self.assertIn("produced no core dump", proc.stdout)

    def test_verification_fails_when_cores_are_still_enabled(self):
        # The control that matters. If core_pattern still writes files, the
        # verification MUST fail rather than report success.
        preamble = (
            "echo 'core' > /proc/sys/kernel/core_pattern\n"
            "echo 0 > /proc/sys/fs/suid_dumpable\n"
        )
        proc = self.run_in_container(preamble)
        self.assertNotEqual(proc.returncode, 0, f"stdout={proc.stdout}")
        self.assertIn("VERIFICATION FAILED", proc.stderr)
        self.assertIn("Refusing to continue", proc.stderr)

    def test_verification_fails_when_suid_dumpable_is_left_on(self):
        preamble = (
            "echo '|/bin/false' > /proc/sys/kernel/core_pattern\n"
            "echo 2 > /proc/sys/fs/suid_dumpable\n"
        )
        proc = self.run_in_container(preamble)
        self.assertNotEqual(proc.returncode, 0, f"stdout={proc.stdout}")
        self.assertIn("suid_dumpable", proc.stderr)

    def test_a_real_core_file_is_actually_produced_without_the_control(self):
        """Proves the test process really would dump, so the pass is meaningful.

        Without this, 'no core file appeared' could just mean the test process
        never dumps in the first place -- a tautology rather than evidence.
        """
        script = (
            "set -u\n"
            "echo 'core' > /proc/sys/kernel/core_pattern\n"
            "echo 0 > /proc/sys/fs/suid_dumpable\n"
            "mkdir -p /tmp/coretest && cd /tmp/coretest\n"
            "ulimit -c unlimited\n"
            "sleep 30 & child=$!\n"
            "kill -ABRT $child 2>/dev/null || true\n"
            "wait $child 2>/dev/null || true\n"
            "sleep 1\n"
            "ls /tmp/coretest\n"
            "find /tmp/coretest -maxdepth 1 -type f -name 'core*' -print -quit | grep -q . && echo CORE_PRODUCED || echo NO_CORE\n"
        )
        ctx = os.path.join(self.tmp, "ctx-control")
        os.makedirs(ctx, exist_ok=True)
        Path(os.path.join(ctx, "t.sh")).write_text(script, encoding="utf-8")
        Path(os.path.join(ctx, "Dockerfile")).write_text(
            f"FROM {DOCKER_IMAGE}\nCOPY t.sh /t.sh\n", encoding="utf-8"
        )
        build = subprocess.run(
            ["docker", "build", "-q", "-t", "wins-f11-control:test", ctx],
            capture_output=True, text=True, timeout=300,
        )
        self.assertEqual(build.returncode, 0, build.stderr)
        proc = subprocess.run(
            ["docker", "run", "--rm", "--privileged", "wins-f11-control:test", "bash", "/t.sh"],
            capture_output=True, text=True, timeout=300,
        )
        if "NO_CORE" in proc.stdout:
            self.skipTest(
                "this kernel/container does not produce core files even with "
                "core_pattern=core, so the positive control cannot be established here"
            )
        self.assertIn("CORE_PRODUCED", proc.stdout)


if __name__ == "__main__":
    if not DOCKER_IMAGE:
        print("NOTE: no local Linux image; real verification tests will skip")
    result = unittest.main(module=__name__, argv=["crash-artifacts"], exit=False, verbosity=2)
    if not result.result.wasSuccessful():
        raise SystemExit(1)
    print("Crash artifact hardening tests passed")
