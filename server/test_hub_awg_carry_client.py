#!/usr/bin/env python3
"""The pinned AWG carrying canary client (design v17 3.15, ruling E; P-16).

wins-awg-carry-client is the userspace AmneziaWG client the hub's carrying
probe (wins_node_dataplane_probe.py --carry, slice H5, P2-SEAM-H5) drives.
Its source is tools/awg_carry_client; its linux amd64 and arm64 binaries and
their receipt (awg-carry-client.build.json) sit beside the control-plane
installer, which stages the binary root-only under /usr/local/bin and pins
its digest (install_awg_carry_client, awg_carry_client_pin).

This file holds, in the pattern of test_hub_h3_canary.py for winn3-probe:
  * the receipt describes the real sources and the shipped binaries, every
    linked module has a known license, and the installer pins exactly the
    shipped digests;
  * the installer's pin block refuses other bytes or another architecture
    (mutants of the pin and of the ELF check are killed);
  * the env writer names the staged client and its pin by default, refuses a
    pin without a client, and still validates an operator's own client; on a
    rerun (the previous env already loaded) the staged client gets this
    installer's pin, not the previous release's;
  * the carry lanes never probe one slug at the same moment (one canary key
    is one WireGuard peer on the node), for a fleet run and a --slug run;
  * end to end on this machine: the REAL client, built from the real source
    with the local Go toolchain, driven by the REAL probe code extracted from
    the installer (probe_carry, CarryClientProcess, StealthRelay) against a
    REAL userspace AmneziaWG peer with a DNS responder inside the tunnel:
    reachable with the served profile over udp and over the stealth path, and
    unreachable with a wrong profile, a wrong key, a silent peer or a peer
    whose resolver never answers; a profile the engine refuses to configure
    is no verdict ("error"), never unreachable.

The end-to-end cases need a Go toolchain (go 1.27 or newer) and a warm module
cache; without one they skip and say so. Nothing contacts the network: the
build runs with GOPROXY=off. Every key is a throwaway minted by the fixture.

Run:  python3 server/test_hub_awg_carry_client.py
"""
import _toolchain  # noqa: F401  (V-01 preflight)
import glob
import hashlib
import json
import os
import platform
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path

import test_hub_awg_carry_canary_h5 as h5

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
MODULE = ROOT / "tools" / "awg_carry_client"
RECEIPT = HERE / "awg-carry-client.build.json"
STAGED = "/usr/local/bin/wins-awg-carry-client"
MACHINES = {"amd64": 62, "arm64": 183}
ARCH = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine())

# A non-default profile with every base parameter, as a node serves it.
PROFILE = {"Jc": 3, "Jmin": 40, "Jmax": 70, "S1": 21, "S2": 37, "S3": 16, "S4": 0,
           "H1": 1234567, "H2": 2345678, "H3": 3456789, "H4": 4567890}


def receipt():
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def source_digests():
    files = {}
    for path in sorted(MODULE.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(MODULE).as_posix()
        if path.suffix == ".go" or relative in ("go.mod", "go.sum", "build_release.py"):
            files[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return files


def pin_block(source=None):
    """The python heredoc of install_awg_carry_client, as the installer runs it."""
    text = h5.hub_source() if source is None else source
    start = text.index("install_awg_carry_client() {")
    marker = '  python3 -I - "${SCRIPT_DIR}" "${arch}" "${pin}" "${AWG_CARRY_CLIENT_STAGED}" <<\'PYEOF\'\n'
    begin = text.index(marker, start) + len(marker)
    return text[begin:text.index("\nPYEOF\n", begin)]


def shell_pin(arch):
    """awg_carry_client_pin ARCH, run under bash from the installer's own text."""
    text = h5.hub_source()
    a = text.index('AWG_CARRY_CLIENT_STAGED="')
    b = text.index("# Env: the public key", a)
    script = 'err() { echo "[ERR] $*" >&2; }\n' + text[a:b] + f'awg_carry_client_pin "{arch}"\n'
    done = subprocess.run([h5.BASH, "--noprofile", "--norc", "-c", script], capture_output=True, text=True)
    return done.returncode, done.stdout.strip()


class ReceiptAndPinTests(unittest.TestCase):
    def test_build_receipt_and_binaries_describe_the_real_sources(self):
        """D1 pattern: the receipt and the pins derive from the real module."""
        data = receipt()
        self.assertEqual(data["source_files"], source_digests(), "the receipt digests are not the shipped sources")
        self.assertEqual(data["module"], "winsvpn.local/awgcarryclient")
        self.assertEqual(data["flags"], ["-trimpath", "-buildvcs=false"])
        self.assertEqual(data["environment"], {"CGO_ENABLED": "0", "GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local"})
        self.assertGreaterEqual(data["repeats"], 3, "fewer than three builds were compared")
        for arch, machine in MACHINES.items():
            binary = (HERE / f"awg-carry-client-linux-{arch}").read_bytes()
            artifact = data["artifacts"][arch]
            self.assertEqual(artifact["sha256"], hashlib.sha256(binary).hexdigest(), arch)
            self.assertEqual(artifact["bytes"], len(binary), arch)
            self.assertEqual(set(artifact["repeat_sha256"]), {artifact["sha256"]}, f"{arch}: the repeated builds differ")
            self.assertEqual(len(artifact["repeat_sha256"]), data["repeats"])
            self.assertEqual((binary[:6], int.from_bytes(binary[18:20], "little")), (b"\x7fELF\x02\x01", machine))
            self.assertIn(b"winsvpn.local/awgcarryclient", binary, "not built from the real module path")
            self.assertNotIn(b"Product.local", binary, "built from masked source")
            self.assertIn(b"github.com/amnezia-vpn/amneziawg-go/v3", binary, "the official v3 engine is not linked")

    def test_the_engine_is_the_version_the_nodes_run_and_every_module_has_a_license(self):
        data = receipt()
        modules = {module["path"]: module for module in data["modules"]}
        engine = modules["github.com/amnezia-vpn/amneziawg-go/v3"]
        self.assertEqual(engine["version"], "v3.1.20260828")
        data_plane = (HERE / "wins_data_plane_setup_ONETOUCH.sh").read_text(encoding="utf-8")
        self.assertIn('AWG_DOCKER_IMAGE_DEFAULT="amneziavpn/amneziawg-go:v3.1.20260828"', data_plane,
                      "the client engine version no longer matches the node image; bump both together")
        responder = (ROOT / "android" / "devicecheck" / "awgresponder" / "go.mod").read_text(encoding="utf-8")
        self.assertIn("github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260828", responder)
        go_mod = (MODULE / "go.mod").read_text(encoding="utf-8")
        self.assertIn("github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260828", go_mod)
        for path, module in modules.items():
            self.assertIn(module["license"]["kind"], ("MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause"), path)
            self.assertTrue(module["sum"] and module["sum"].startswith("h1:"), f"{path}: no module hash")
            self.assertIn(f"{path} {module['version']} {module['sum']}", (MODULE / "go.sum").read_text(), path)

    def test_the_installer_pins_exactly_the_shipped_digests(self):
        data = receipt()
        for arch in MACHINES:
            rc, pin = shell_pin(arch)
            self.assertEqual(rc, 0, arch)
            self.assertEqual(pin, data["artifacts"][arch]["sha256"], f"{arch}: the installer pin is not the receipt digest")
        rc, pin = shell_pin("mips")
        self.assertEqual((rc, pin), (1, ""), "an unknown architecture must have no pin")
        source = h5.hub_source()
        self.assertIn(f'AWG_CARRY_CLIENT_STAGED="{STAGED}"', source)
        self.assertLess(source.index("  install_awg_carry_client || return 1\n"),
                        source.index("cat > /etc/systemd/system/wins-awg-carry-probe.service <<'EOF'\n"),
                        "the client is staged before the carry unit is written")
        self.assertEqual(source.count("install_awg_carry_client() {"), 1)

    def test_the_pin_block_installs_only_the_pinned_bytes_root_only(self):
        data = receipt()
        for arch in MACHINES:
            with self.subTest(arch):
                self.run_pin_block(arch, data["artifacts"][arch]["sha256"], expect=None)
                self.run_pin_block(arch, "0" * 64, expect="mismatch")
                other = "arm64" if arch == "amd64" else "amd64"
                self.run_pin_block(arch, data["artifacts"][other]["sha256"], expect="mismatch")
                # The right digest named for the wrong machine: the ELF check holds.
                self.run_pin_block(arch, data["artifacts"][arch]["sha256"], expect="mismatch", machine=other)
                self.run_pin_block(arch, data["artifacts"][arch]["sha256"], expect="not root-only", loose=True)

    def run_pin_block(self, arch, pin, expect, machine=None, loose=False):
        """Exec the installer's pin block with a fake root-owned destination: lstat
        of the destination directories is answered as root-owned and closed,
        or group-writable when `loose`."""
        import os as real_os
        code = pin_block()
        with tempfile.TemporaryDirectory(prefix="awg-pin-") as scratch:
            scratch_path = Path(scratch)
            source_dir = scratch_path / "server"
            source_dir.mkdir()
            data = (HERE / f"awg-carry-client-linux-{machine or arch}").read_bytes()
            (source_dir / f"awg-carry-client-linux-{arch}").write_bytes(data)
            dest_dir = scratch_path / "usr" / "local" / "bin"
            dest_dir.mkdir(parents=True)
            staged = dest_dir / "wins-awg-carry-client"
            fake_mode = 0o40775 if loose else 0o40755
            fake_stat = type("S", (), {"st_uid": 0, "st_gid": 0, "st_mode": fake_mode})()
            real_stat = Path.stat
            calls = {"chown": []}

            def stat(self, *a, **k):
                if self == dest_dir or self in dest_dir.parents:
                    return fake_stat
                return real_stat(self, *a, **k)

            def fchown(fd, uid, gid):
                calls["chown"].append((uid, gid))

            namespace = {"__name__": "awg_pin_block"}
            saved = (Path.stat, real_os.fchown, sys.argv)
            try:
                Path.stat = stat
                real_os.fchown = fchown
                sys.argv = ["pins", str(source_dir), arch, pin, str(staged)]
                if expect:
                    with self.assertRaises(SystemExit) as raised:
                        exec(compile(code, "<awg-carry-client-pins>", "exec"), namespace)
                    self.assertIn(expect, str(raised.exception))
                    self.assertFalse(staged.exists(), "nothing is installed on a refusal")
                    self.assertEqual([p for p in dest_dir.iterdir()], [], "no temporary file is left behind")
                else:
                    exec(compile(code, "<awg-carry-client-pins>", "exec"), namespace)
                    self.assertEqual(staged.read_bytes(), data)
                    self.assertEqual(staged.stat().st_mode & 0o777, 0o755)
                    self.assertEqual(calls["chown"], [(0, 0)])
                    self.assertEqual([p.name for p in dest_dir.iterdir()], [staged.name])
            finally:
                Path.stat, real_os.fchown, sys.argv = saved


class InstallerEnvTests(unittest.TestCase):
    """write_awg_canary_runtime_env under bash, with H5's harness."""
    setUp = h5.InstallerKeyTests.setUp
    extract = h5.InstallerKeyTests.extract
    run_bash = h5.InstallerKeyTests.run_bash
    private = h5.InstallerKeyTests.private
    READ = 'write_awg_canary_runtime_env; echo "rc=$?"; printf "%s" "$env_kv_buffer"'

    def test_the_staged_client_and_its_pin_are_the_default(self):
        if ARCH is None:
            self.skipTest(f"no pin for {platform.machine()}")
        done = self.run_bash(self.READ)
        self.assertIn("rc=0", done.stdout, done.stdout + done.stderr)
        self.assertIn(f"AWG_CARRY_CLIENT_BIN='{STAGED}'", done.stdout)
        self.assertIn(f"AWG_CARRY_CLIENT_SHA256='{receipt()['artifacts'][ARCH]['sha256']}'", done.stdout)

    def test_a_pin_without_a_client_is_refused(self):
        done = self.run_bash(self.READ, extra_env={"AWG_CARRY_CLIENT_SHA256": "ab" * 32})
        self.assertIn("rc=1", done.stdout, done.stdout + done.stderr)
        self.assertNotIn("AWG_CARRY_CLIENT_BIN='", done.stdout)
        self.assertNotIn("AWG_CARRY_CLIENT_SHA256='", done.stdout)
        self.assertIn("without AWG_CARRY_CLIENT_BIN", done.stdout + done.stderr)

    def test_an_operator_client_still_needs_its_own_pin_and_a_usr_path(self):
        done = self.run_bash(self.READ, extra_env={"AWG_CARRY_CLIENT_BIN": "/usr/local/lib/other-client"})
        self.assertIn("rc=1", done.stdout, "an operator client without a digest is not given the staged pin")
        self.assertNotIn("AWG_CARRY_CLIENT_SHA256='", done.stdout)
        done = self.run_bash(self.READ, extra_env={"AWG_CARRY_CLIENT_BIN": "/usr/local/lib/other-client",
                                                   "AWG_CARRY_CLIENT_SHA256": "ab" * 32})
        self.assertIn("rc=0", done.stdout, done.stdout + done.stderr)
        self.assertIn("AWG_CARRY_CLIENT_BIN='/usr/local/lib/other-client'", done.stdout)
        self.assertIn(f"AWG_CARRY_CLIENT_SHA256='{'ab' * 32}'", done.stdout)
        self.assertNotIn(STAGED, done.stdout)

    def test_the_unit_still_holds_every_sandbox_barrier(self):
        facts = h5.carry_unit_facts(h5.hub_source())
        self.assertEqual({k: v for k, v in facts.items() if not v}, {})

    def test_installer_mutants_are_killed(self):
        mutants = {
            "the staged pin is written for an operator client without one": [(
                '    [[ "${AWG_CARRY_CLIENT_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] || {',
                '    AWG_CARRY_CLIENT_SHA256="$(awg_carry_client_pin)"\n    [[ "${AWG_CARRY_CLIENT_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] || {')],
            "a pin without a client is accepted": [(
                '  if [[ -z "${AWG_CARRY_CLIENT_BIN:-}" && -n "${AWG_CARRY_CLIENT_SHA256:-}" ]]; then', "  if false; then")],
            "the default pin is not this machine's": [(
                '    client_sha256="$(awg_carry_client_pin)" || return 1', '    client_sha256="$(printf %064d 0)"')],
            "the default client is not the staged path": [(
                '    write_env_kv AWG_CARRY_CLIENT_BIN "${AWG_CARRY_CLIENT_STAGED}" || return 1',
                '    write_env_kv AWG_CARRY_CLIENT_BIN "/root/vpn_auth/wins-awg-carry-client" || return 1')],
        }
        for name, edits in mutants.items():
            with self.subTest(name):
                mutated = h5.hub_source()
                for old, new in edits:
                    mutated = h5.replace_once(mutated, old, new)
                self.assertTrue(self.broken(mutated), f"mutant survived: {name}")

    def broken(self, source):
        """True when any env fact the shipped source satisfies no longer holds."""
        expected_pin = receipt()["artifacts"][ARCH]["sha256"] if ARCH else ""
        default = self.run_bash(self.READ, source=source)
        if f"AWG_CARRY_CLIENT_BIN='{STAGED}'" not in default.stdout or f"AWG_CARRY_CLIENT_SHA256='{expected_pin}'" not in default.stdout:
            return True
        shutil.rmtree(self.canary_dir, ignore_errors=True)
        pin_only = self.run_bash(self.READ, source=source, extra_env={"AWG_CARRY_CLIENT_SHA256": "ab" * 32})
        if "rc=1" not in pin_only.stdout:
            return True
        shutil.rmtree(self.canary_dir, ignore_errors=True)
        unpinned = self.run_bash(self.READ, source=source, extra_env={"AWG_CARRY_CLIENT_BIN": "/usr/local/lib/other-client"})
        return "rc=1" not in unpinned.stdout


class RerunPinTests(unittest.TestCase):
    """A rerun loads the previous run's env first (write_env: load_existing_envs
    before write_awg_canary_runtime_env), so the staged client's pin must come
    from this installer, not from that env."""
    setUp = h5.InstallerKeyTests.setUp
    extract = h5.InstallerKeyTests.extract
    run_bash = h5.InstallerKeyTests.run_bash
    READ = InstallerEnvTests.READ
    FIX = '  if [[ -n "${AWG_CARRY_CLIENT_BIN:-}" && "${AWG_CARRY_CLIENT_BIN}" != "${AWG_CARRY_CLIENT_STAGED}" ]]; then\n'

    def rerun_after_upgrade(self, source):
        """(first run, second run): the second from installer text whose pins
        are new digests, after sourcing the first run's env lines."""
        old = receipt()["artifacts"]
        upgraded = source
        for arch, fake in (("amd64", "aa" * 32), ("arm64", "bb" * 32)):
            upgraded = upgraded.replace(old[arch]["sha256"], fake)
        shutil.rmtree(self.canary_dir, ignore_errors=True)
        first = self.run_bash(self.READ, source=source)
        env_file = Path(self.dir, "vpn_auth.env")
        env_file.write_text("".join(line + "\n" for line in first.stdout.splitlines() if line.startswith("AWG_")))
        second = self.run_bash(f"source {str(env_file)!r}; " + self.READ, source=upgraded)
        return first, second

    def test_a_rerun_after_a_client_upgrade_writes_the_new_pin(self):
        old = receipt()["artifacts"]
        first, second = self.rerun_after_upgrade(h5.hub_source())
        self.assertIn("rc=0", first.stdout, first.stdout + first.stderr)
        self.assertIn(f"AWG_CARRY_CLIENT_BIN='{STAGED}'", first.stdout, "anti-vacuity: the first run staged the client")
        self.assertIn("rc=0", second.stdout, second.stdout + second.stderr)
        self.assertIn(f"AWG_CARRY_CLIENT_BIN='{STAGED}'", second.stdout)
        for artifact in old.values():
            self.assertNotIn(artifact["sha256"], second.stdout, "a rerun kept the previous release's pin")
        self.assertRegex(second.stdout, r"AWG_CARRY_CLIENT_SHA256='(a{64}|b{64})'")

    def test_an_operator_client_from_the_previous_env_keeps_its_own_pin(self):
        env_file = Path(self.dir, "vpn_auth.env")
        env_file.write_text("AWG_CARRY_CLIENT_BIN='/usr/local/lib/other-client'\n"
                            f"AWG_CARRY_CLIENT_SHA256='{'cd' * 32}'\n")
        done = self.run_bash(f"source {str(env_file)!r}; " + self.READ)
        self.assertIn("rc=0", done.stdout, done.stdout + done.stderr)
        self.assertIn("AWG_CARRY_CLIENT_BIN='/usr/local/lib/other-client'", done.stdout)
        self.assertIn(f"AWG_CARRY_CLIENT_SHA256='{'cd' * 32}'", done.stdout)

    def test_the_rerun_mutant_is_killed(self):
        """The candidate's condition (any client in the env is the operator's)."""
        source = h5.hub_source()
        self.assertEqual(source.count(self.FIX), 1)
        mutated = h5.replace_once(source, self.FIX, '  if [[ -n "${AWG_CARRY_CLIENT_BIN:-}" ]]; then\n')
        _first, second = self.rerun_after_upgrade(mutated)
        self.assertTrue(any(a["sha256"] in second.stdout for a in receipt()["artifacts"].values()),
                        "mutant survived: a rerun after an upgrade no longer keeps the old pin without the fix")


class CarryLaneExclusionTests(unittest.TestCase):
    """One canary key is one peer on the node: no two lanes probe one slug at once."""
    CARRY = h5.CarryRunTests.CARRY
    setUp = h5.CarryRunTests.setUp
    run_carry = h5.CarryRunTests.run_carry
    status = h5.CarryRunTests.status
    aged = h5.CarryRunTests.aged

    def spans(self, slug="", source=None):
        spans, guard = [], threading.Lock()

        def probe_carry(row, transport, private_key):
            start = time.monotonic()
            time.sleep(0.3)
            with guard:
                spans.append((row["slug"], transport, start, time.monotonic()))
            return ("reachable", "carried")

        self.run_carry(slug=slug, source=source, probe_carry=probe_carry)
        overlaps = [(a[0], a[1], b[1]) for i, a in enumerate(spans) for b in spans[i + 1:]
                    if a[0] == b[0] and a[2] < b[3] and b[2] < a[3]]
        return spans, overlaps

    def pending(self):
        return h5.seed_node(self.mod, operator_enabled=0, deployment_completed_at=self.aged(10),
                            health_closed_reason="fresh_install")

    def test_one_pending_slugs_transports_are_probed_one_at_a_time(self):
        slug = self.pending()
        spans, overlaps = self.spans(slug)
        self.assertEqual((len(spans), overlaps), (3, []))
        for transport in self.CARRY:
            self.assertEqual(self.status(slug)[transport][0], "ok")

    def test_a_fleet_run_still_probes_every_transport_of_every_slug(self):
        slugs = [h5.seed_node(self.mod, operator_enabled=1) for _ in range(4)]
        spans, overlaps = self.spans()
        self.assertEqual(overlaps, [])
        self.assertEqual(sorted((s, t) for s, t, _a, _b in spans),
                         sorted((s, t) for s in slugs for t in self.CARRY))
        # The lanes still run side by side across slugs: 12 probes of 0.3 s
        # one after another would take 3.6 s.
        self.assertLess(max(b for *_x, b in spans) - min(a for *_x, a, _b in spans), 3.0)

    def test_the_lock_mutant_is_killed(self):
        """Without the per-slug lock the three lanes probe one slug at once."""
        source = h5.hub_source()
        mutated = h5.replace_once(source, "        return _carry_slug_locks.setdefault(slug, threading.Lock())\n",
                                  "        return threading.Lock()\n")
        slug = self.pending()
        _spans, overlaps = self.spans(slug, source=mutated)
        self.assertTrue(overlaps, "mutant survived: the lanes never overlapped without the lock")


# ---------------------------------------------------------------- end to end

def go_toolchain():
    """A Go toolchain of 1.27 or newer: AWG_CARRY_CLIENT_GO, the module-cache
    toolchains, then PATH."""
    candidates = [os.environ.get("AWG_CARRY_CLIENT_GO", "")]
    candidates += sorted(glob.glob(os.path.expanduser("~/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.*/bin/go")), reverse=True)
    candidates.append(shutil.which("go") or "")
    for candidate in candidates:
        if not candidate or not os.access(candidate, os.X_OK):
            continue
        try:
            version = subprocess.run([candidate, "version"], capture_output=True, text=True, timeout=30,
                                     env={"PATH": "/usr/bin:/bin", "HOME": os.environ.get("HOME", "/"), "GOTOOLCHAIN": "local"}).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        parts = version.split()
        if len(parts) >= 3 and parts[2].startswith("go"):
            major_minor = parts[2][2:].split(".")[:2]
            try:
                if (int(major_minor[0]), int(major_minor[1])) >= (1, 27):
                    return candidate
            except ValueError:
                continue
    return ""


_BUILT = {}


def built(name, package):
    """Build one binary of the module once per process, offline."""
    if name in _BUILT:
        if isinstance(_BUILT[name], Exception):
            raise _BUILT[name]
        return _BUILT[name]
    go = go_toolchain()
    if not go:
        _BUILT[name] = unittest.SkipTest("no Go toolchain of 1.27 or newer (set AWG_CARRY_CLIENT_GO)")
        raise _BUILT[name]
    out_dir = Path(tempfile.mkdtemp(prefix="awg-carry-e2e-"))
    target = out_dir / name
    done = subprocess.run([go, "build", "-trimpath", "-o", str(target), package], cwd=MODULE, capture_output=True, text=True,
                          env={"PATH": "/usr/bin:/bin", "HOME": os.environ.get("HOME", "/"), "GOTOOLCHAIN": "local",
                               "GOFLAGS": "-mod=mod", "GOPROXY": "off",
                               **({"GOMODCACHE": os.environ["GOMODCACHE"]} if "GOMODCACHE" in os.environ else {})})
    if done.returncode != 0:
        if "module lookup disabled" in done.stderr or "missing go.sum entry" in done.stderr:
            _BUILT[name] = unittest.SkipTest("the Go module cache lacks the client's modules (offline build)")
        else:
            _BUILT[name] = AssertionError(f"{name} does not build: {done.stderr[-2000:]}")
        raise _BUILT[name]
    _BUILT[name] = str(target)
    return _BUILT[name]


def profile_uapi(profile):
    return ",".join(f"{key.lower()}={value}" for key, value in profile.items())


class TestPeer:
    """The node end: a real userspace AmneziaWG responder with a DNS responder
    inside the tunnel, as a subprocess that mints the throwaway canary key."""

    def __init__(self, profile=PROFILE, silent=False, name="hub.example.test"):
        args = [built("awg-carry-testpeer", "./cmd/awg-carry-testpeer"), "--profile", profile_uapi(profile), "--name", name]
        if silent:
            args.append("--silent")
        self.proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        ready = self.proc.stdout.readline()
        if not ready:
            raise AssertionError("test peer did not start: " + self.proc.stderr.read())
        info = json.loads(ready)
        self.port = info["port"]
        self.public_key = info["public_key"]
        self.canary_private = info["client_private_key"]
        self.canary_public = info["client_public_key"]

    def status(self):
        self.proc.stdin.write("status\n")
        self.proc.stdin.flush()
        return json.loads(self.proc.stdout.readline())

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=10)
        except Exception:  # noqa: BLE001
            self.proc.kill()
            self.proc.wait(timeout=10)
        finally:
            self.proc.stdout.close()
            self.proc.stderr.close()


class ForwardingVlessNode(threading.Thread):
    """A plaintext WebSocket + VLESS v0 UDP endpoint that FORWARDS: every
    datagram record from the probe's relay goes to the AmneziaWG peer over
    loopback UDP, and every reply comes back as a framed record, the first one
    behind the VLESS response header, exactly as Xray frames them."""

    def __init__(self, uid, awg_port, forward_port):
        super().__init__(daemon=True)
        self.uid, self.awg_port, self.forward_port = uid, awg_port, forward_port
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(1)
        self.server.settimeout(15)
        self.port = self.server.getsockname()[1]
        self.header_ok = None
        self.forwarded = 0
        self.returned = 0
        self.stop = threading.Event()

    def run(self):
        try:
            conn, _ = self.server.accept()
        except OSError:
            return
        request = b""
        with conn:
            conn.settimeout(15)
            while b"\r\n\r\n" not in request:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                request += chunk
            conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.settimeout(0.2)
            lock = threading.Lock()
            first = [True]

            def back():
                while not self.stop.is_set():
                    try:
                        data, _ = udp.recvfrom(65535)
                    except socket.timeout:
                        continue
                    except OSError:
                        return
                    body = struct.pack("!H", len(data)) + data
                    with lock:
                        prefix = b"\x00\x00" if first[0] else b""
                        first[0] = False
                        try:
                            conn.sendall(h5.ws_frame(prefix + body))
                        except OSError:
                            return
                    self.returned += 1

            threading.Thread(target=back, daemon=True).start()
            conn.settimeout(0.5)
            header_seen = False
            try:
                while not self.stop.is_set():
                    try:
                        opcode, payload = h5.ws_read_frame(conn)
                    except socket.timeout:
                        continue
                    except (ConnectionError, OSError):
                        return
                    if opcode == 8:
                        return
                    if not header_seen:
                        self.header_ok = (
                            payload[0] == 0 and payload[1:17] == self.uid and payload[17] == 0
                            and payload[18] == 2 and struct.unpack("!H", payload[19:21])[0] == self.awg_port
                            and payload[21] == 1 and payload[22:26] == bytes([127, 0, 0, 1]))
                        payload = payload[26:]
                        header_seen = True
                    while len(payload) >= 2:
                        size = struct.unpack("!H", payload[:2])[0]
                        datagram, payload = payload[2:2 + size], payload[2 + size:]
                        udp.sendto(datagram, ("127.0.0.1", self.forward_port))
                        self.forwarded += 1
            finally:
                udp.close()

    def close(self):
        self.stop.set()
        self.server.close()


class EndToEndTests(unittest.TestCase):
    """The real client through the real probe code against a real peer."""

    @classmethod
    def setUpClass(cls):
        cls.client = built("wins-awg-carry-client", ".")
        built("awg-carry-testpeer", "./cmd/awg-carry-testpeer")

    def setUp(self):
        self.peers = []

    def tearDown(self):
        for peer in self.peers:
            peer.close()

    def peer(self, **kw):
        peer = TestPeer(**kw)
        self.peers.append(peer)
        return peer

    def probe(self, timeout=20):
        # The real client lives in a temp dir on this machine; the D6 placement
        # and the pin have their own tests (H5 and ReceiptAndPinTests).
        return h5.load_probe(CARRY_CLIENT_BIN=self.client, CARRY_DNS_NAME="hub.example.test",
                             CARRY_CLIENT_TIMEOUT=timeout, carry_client_untrusted=lambda _path: "")

    def row(self, peer, profile=PROFILE, **fields):
        row = {"slug": "lab-1", "endpoint": f"127.0.0.1:{peer.port}", "wg_port": peer.port, "public_key": peer.public_key,
               "direct_awg_enabled": 1, "obfuscation_json": json.dumps(profile),
               "stealth_endpoint": "127.0.0.1:80", "xray_security": "none", "stealth_transports": "[]",
               "xray_path": "/stealth", "xray_uuid": h5.XRAY_UUID}
        row.update(fields)
        return row

    def test_udp_the_served_profile_carries_a_validated_dns_reply(self):
        peer = self.peer()
        probe = self.probe()
        verdict, detail = probe["probe_carry"](self.row(peer), "udp", peer.canary_private)
        self.assertEqual(verdict, "reachable", detail)
        self.assertIn("address record(s) carried through the tunnel", detail)
        status = peer.status()
        self.assertTrue(status["handshook"], "the peer saw no handshake")
        self.assertGreaterEqual(status["queries"], 1, "no query arrived inside the tunnel")

    def test_udp_one_long_lived_client_serves_several_probes_and_a_refusal(self):
        peer = self.peer()
        probe = self.probe()
        client = probe["CarryClientProcess"]("udp")
        self.addCleanup(client.close)
        probe["_carry_lane"].client = client
        self.addCleanup(setattr, probe["_carry_lane"], "client", None)
        row = self.row(peer)
        for _ in range(2):
            verdict, detail = probe["probe_carry"](row, "udp", peer.canary_private)
            self.assertEqual(verdict, "reachable", detail)
        self.assertEqual(client.spawn_count, 1, "a second probe spawned a second client")
        self.assertEqual(client._request_id, 2)
        # A request the client refuses (a key that is not a key) is an error,
        # not a verdict: no dns_reply_hex comes back, and the parent restarts
        # the client afterwards.
        status, detail, reply = client.exchange({"version": 1, "private_key": "not-a-key",
                                                 "peer_public_key": peer.public_key, "local_address": "10.8.255.1/32",
                                                 "endpoint": f"127.0.0.1:{peer.port}", "obfuscation": PROFILE,
                                                 "dns_server": "10.8.1.1", "dns_port": 53,
                                                 "dns_query_hex": probe["build_dns_query"]("hub.example.test")[0].hex(),
                                                 "timeout_seconds": 5}, "lab-1")
        self.assertEqual((status, reply), ("error", b""), detail)
        self.assertIn("no readable result", detail)
        self.assertIsNone(client.pid(), "the refused client was killed")
        # The parent holds a restart backoff after a kill (P-16); inside it a
        # probe is "unavailable", after it the client is started again.
        verdict, detail = probe["probe_carry"](row, "udp", peer.canary_private)
        self.assertEqual(verdict, "unavailable", detail)
        time.sleep(max(0.0, client.not_before - time.monotonic()))
        verdict, detail = probe["probe_carry"](row, "udp", peer.canary_private)
        self.assertEqual(verdict, "reachable", detail)
        self.assertEqual(client.spawn_count, 2, "the client was restarted after the refusal")

    def test_udp_a_wrong_profile_is_unreachable_within_the_deadline(self):
        peer = self.peer()
        probe = self.probe(timeout=5)
        wrong = dict(PROFILE, H1=7654321)
        verdict, detail = probe["probe_carry"](self.row(peer, profile=wrong), "udp", peer.canary_private)
        self.assertEqual(verdict, "unreachable", detail)
        self.assertIn("no DNS reply came back through the tunnel", detail)
        status = peer.status()
        self.assertFalse(status["handshook"], "a mismatched profile must not handshake")
        self.assertEqual(status["queries"], 0)

    def test_udp_a_wrong_key_is_unreachable(self):
        peer = self.peer()
        other = self.peer()
        probe = self.probe(timeout=5)
        verdict, detail = probe["probe_carry"](self.row(peer), "udp", other.canary_private)
        self.assertEqual(verdict, "unreachable", detail)
        self.assertFalse(peer.status()["handshook"])
        verdict, detail = probe["probe_carry"](self.row(peer, public_key=other.public_key), "udp", peer.canary_private)
        self.assertEqual(verdict, "unreachable", detail)
        self.assertFalse(peer.status()["handshook"])

    def test_udp_a_silent_endpoint_is_unreachable_within_the_deadline(self):
        peer = self.peer()
        silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        silent.bind(("127.0.0.1", 0))
        self.addCleanup(silent.close)
        port = silent.getsockname()[1]
        probe = self.probe(timeout=5)
        verdict, detail = probe["probe_carry"](self.row(peer, endpoint=f"127.0.0.1:{port}", wg_port=port), "udp",
                                               peer.canary_private)
        self.assertEqual(verdict, "unreachable", detail)

    def test_udp_a_handshake_without_a_resolver_answer_is_unreachable(self):
        peer = self.peer(silent=True)
        probe = self.probe(timeout=5)
        verdict, detail = probe["probe_carry"](self.row(peer), "udp", peer.canary_private)
        self.assertEqual(verdict, "unreachable", detail)
        status = peer.status()
        self.assertTrue(status["handshook"], "the handshake itself should complete")
        self.assertGreaterEqual(status["queries"], 1, "the query should arrive inside the tunnel")

    def test_udp_a_resolver_that_answers_another_name_is_unreachable(self):
        # NXDOMAIN carries no address record: the probe's validator refuses it.
        peer = self.peer(name="other.example.test")
        probe = self.probe(timeout=5)
        verdict, detail = probe["probe_carry"](self.row(peer), "udp", peer.canary_private)
        self.assertEqual(verdict, "unreachable", detail)
        self.assertIn("DNS rcode 3", detail)

    def test_udp_a_profile_the_engine_refuses_is_no_verdict(self):
        # An I1 chain the engine cannot parse: the client never sends a packet,
        # so the probe must not call the node unreachable.
        peer = self.peer()
        probe = self.probe(timeout=5)
        verdict, detail = probe["probe_carry"](self.row(peer, profile=dict(PROFILE, I1="<")), "udp", peer.canary_private)
        self.assertEqual(verdict, "error", detail)
        self.assertIn("no readable result", detail)
        status = peer.status()
        self.assertFalse(status["handshook"])
        self.assertEqual(status["queries"], 0)

    def test_stealth_the_relay_carries_the_tunnel_through_websocket_and_vless(self):
        peer = self.peer()
        node = ForwardingVlessNode(uuid.UUID(h5.XRAY_UUID).bytes, peer.port, peer.port)
        node.start()
        self.addCleanup(node.close)
        probe = self.probe()
        row = self.row(peer, stealth_endpoint=f"127.0.0.1:{node.port}")
        verdict, detail = probe["probe_carry"](row, "stealth", peer.canary_private)
        self.assertEqual(verdict, "reachable", detail)
        self.assertTrue(node.header_ok, "VLESS v0 UDP request to 127.0.0.1:<awg port> with the node uuid")
        self.assertGreaterEqual(node.forwarded, 3, "junk, initiation and the query all cross the relay")
        self.assertGreaterEqual(node.returned, 2, "the response and the reply came back")
        self.assertTrue(peer.status()["handshook"])

    def test_stealth_a_wrong_profile_through_the_relay_is_unreachable(self):
        peer = self.peer()
        node = ForwardingVlessNode(uuid.UUID(h5.XRAY_UUID).bytes, peer.port, peer.port)
        node.start()
        self.addCleanup(node.close)
        probe = self.probe(timeout=5)
        row = self.row(peer, profile=dict(PROFILE, S1=22), stealth_endpoint=f"127.0.0.1:{node.port}")
        verdict, detail = probe["probe_carry"](row, "stealth", peer.canary_private)
        self.assertEqual(verdict, "unreachable", detail)
        self.assertFalse(peer.status()["handshook"])

    def test_the_key_never_reaches_the_client_log_or_the_reply(self):
        peer = self.peer()
        probe = self.probe()
        client = probe["CarryClientProcess"]("udp")
        self.addCleanup(client.close)
        request = {"version": 1, "private_key": peer.canary_private, "peer_public_key": peer.public_key,
                   "local_address": "10.8.255.1/32", "endpoint": f"127.0.0.1:{peer.port}", "obfuscation": PROFILE,
                   "dns_server": "10.8.1.1", "dns_port": 53,
                   "dns_query_hex": probe["build_dns_query"]("hub.example.test")[0].hex(), "timeout_seconds": 10}
        status, detail, reply = client.exchange(request, "lab-1")
        self.assertEqual(status, "reply", detail)
        self.assertTrue(reply)
        self.assertNotIn(peer.canary_private.encode(), reply)
        self.assertNotIn(peer.canary_private, detail)
        self.assertEqual(probe["carry_client_env"]().keys() - {"PATH", "HOME", "LANG", "LC_ALL", "TZ"}, set())


if __name__ == "__main__":
    unittest.main(verbosity=2)
