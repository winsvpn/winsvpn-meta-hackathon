#!/usr/bin/env python3
"""Behavioural tests for android/tools/prepare_android_winn_assets.sh.

The script is run for real against a throwaway project root: a copy of the
script, a stub tools/winn_release.py that speaks the driver's verify/build
contract, synthetic ELF engines that carry the v3 package paths, and a symlink
to the real winn_protocol_experimental module so the freshness gate's `go list`
runs unchanged. Nothing touches the network, git, or this checkout's jniLibs.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import struct
import subprocess
import base64
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "tools"))
import winn_release_testkit as testkit  # noqa: E402
SCRIPT = ROOT / "android/tools/prepare_android_winn_assets.sh"
MODULE = ROOT / "winn_protocol_experimental"
ABIS = (("arm64-v8a", "arm64", 183), ("armeabi-v7a", "arm", 40), ("x86_64", "amd64", 62))
VARIANTS = ("main", "debug", "profile", "release")
ENGINE = "libwinnengine.so"
STAMP = "winn-release.json"
STAMP_CONTRACT = "winsvpn-winn-release-android-stage-v1"
TEST_PUBLIC_KEY = testkit.public_key_hex(testkit.TEST_SEED)
V3_STRINGS = (
    b"winsvpn.local/winnprotocol/winn3/core",
    b"winsvpn.local/winnprotocol/winn3/session",
    b"winsvpn.local/winnprotocol/winn3/carrier",
    b"winsvpn.local/winnprotocol/winn3/tun",
    b"winsvpn.local/winnprotocol/winn3/driver",
    b"payloads ip-packet awg-datagram",
)

STUB_DRIVER = r'''
import hashlib, importlib.util, json, os, pathlib, sys

# `verify` and `verify-android-stamp` run the REAL driver copied beside this
# stub (tools/real_winn_release.py, pinned to a throwaway test key); only
# `build` is simulated, because it needs Go and the NDK.
here = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("real_winn_release", here / "real_winn_release.py")
real = importlib.util.module_from_spec(spec)
spec.loader.exec_module(real)

def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

argv = sys.argv[1:]
with open(os.environ["STUB_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps(argv) + "\n")

def opt(name):
    return argv[argv.index(name) + 1] if name in argv else None

if argv[0] in ("verify", "verify-android-stamp"):
    if argv[0] == "verify" and os.environ.get("STUB_VERIFY_EXIT"):
        print("TOOLCHAIN-MISSING: stub", file=sys.stderr)
        sys.exit(int(os.environ["STUB_VERIFY_EXIT"]))
    sys.exit(real.main(argv))

if argv[0] == "build":
    if os.environ.get("STUB_BUILD_EXIT"):
        print("TOOLCHAIN-MISSING: stub", file=sys.stderr)
        sys.exit(int(os.environ["STUB_BUILD_EXIT"]))
    out = pathlib.Path(opt("--out"))
    if out.exists():
        sys.exit(1)
    fixture = pathlib.Path(os.environ["STUB_FIXTURE"])
    artifacts = []
    for goarch, abi in (("arm64", "arm64-v8a"), ("arm", "armeabi-v7a"), ("amd64", "x86_64")):
        target = "datapath-android-" + goarch
        dest = out / "artifacts" / target / "libwinnengine.so"
        dest.parent.mkdir(parents=True)
        dest.write_bytes((fixture / abi / "libwinnengine.so").read_bytes())
        digest = sha(dest)
        artifacts.append({"target": target, "path": str(dest.relative_to(out)), "sha256": digest,
                          "size": dest.stat().st_size, "header_path": None, "header_sha256": None,
                          "build_a_sha256": digest, "build_b_sha256": digest})
    (out / "manifest.json").write_bytes(real.canonical_json({
        "contract": "winsvpn-winn-release-manifest-v1", "artifacts": artifacts,
        "source": {"binding": "git-archive", "commit": opt("--source-commit")}}))
    sys.exit(0)
sys.exit(2)
'''

STUB_XRAY = r'''#!/usr/bin/env bash
set -euo pipefail
cp "${STUB_FIXTURE}/xray-$1" "$2"
'''


def fake_elf(machine: int, extra: bytes = b"") -> bytes:
    """A minimal ELF whose header, e_machine and PT_LOAD pass the script's gates."""
    payload = b"\0".join(V3_STRINGS) + b"\0" + extra
    if machine == 40:
        header = bytearray(52)
        header[:6] = b"\x7fELF\x01\x01"
        struct.pack_into("<H", header, 18, machine)
        return bytes(header) + payload
    size = 64 + 56 + len(payload)
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<HHI", header, 16, 3, machine, 1)
    struct.pack_into("<Q", header, 32, 64)
    struct.pack_into("<HH", header, 54, 56, 1)
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, size, size, 16384)
    return bytes(header) + phdr + payload


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@unittest.skipUnless(shutil.which("go") and (MODULE / "go.mod").is_file(),
                     "Go and winn_protocol_experimental are needed for the freshness gate")
class PrepareAndroidWinnAssetsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="prep-android-winn.")).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = self.tmp / "project"
        (self.root / "android/tools").mkdir(parents=True)
        shutil.copy2(SCRIPT, self.root / "android/tools/prepare_android_winn_assets.sh")
        (self.root / "tools").mkdir()
        (self.root / "tools/winn_release.py").write_text(STUB_DRIVER)
        shutil.copyfile(testkit.DRIVER, self.root / "tools/real_winn_release.py")
        (self.root / "tools/winn_release_authority.json").write_bytes(
            testkit.authority_document(testkit.TEST_SEED))
        (self.root / "tools/build_xray_engine.sh").write_text(STUB_XRAY)
        (self.root / "winn_protocol_experimental").symlink_to(MODULE, target_is_directory=True)
        self.fixture = self.tmp / "fixture"
        for abi, goarch, machine in ABIS:
            (self.fixture / abi).mkdir(parents=True)
            (self.fixture / abi / ENGINE).write_bytes(fake_elf(machine, abi.encode()))
            (self.fixture / f"xray-android-{goarch}").write_bytes(fake_elf(machine, b"xray"))
        self.ndk = self.tmp / "ndk"
        self.ndk.mkdir()
        (self.ndk / "source.properties").write_text("Pkg.Revision = 30.0.16248370\n")
        self.log = self.tmp / "driver.log"
        self.log.write_text("")
        self.env = {
            key: value for key, value in os.environ.items()
            if not key.startswith(("ANDROID_", "STUB_", "WINN_", "WINS_"))
        }
        self.env.update({
            "STUB_LOG": str(self.log),
            "STUB_FIXTURE": str(self.fixture),
            "GOPROXY": "off",
            "TMPDIR": str(self.tmp),
            "ANDROID_HOME": str(self.tmp / "no-sdk"),
            "ANDROID_NDK_HOME": str(self.ndk),
        })

    # ------------------------------------------------------------------

    def make_release(self, name: str, *, signed: bool = True, mutate=None,
                     seed: bytes = testkit.TEST_SEED) -> pathlib.Path:
        driver = testkit.load_driver()
        release = self.tmp / name
        artifacts = []
        for abi, goarch, _ in ABIS:
            target = f"datapath-android-{goarch}"
            dest = release / "artifacts" / target / ENGINE
            dest.parent.mkdir(parents=True)
            shutil.copyfile(self.fixture / abi / ENGINE, dest)
            digest = sha256(dest)
            artifacts.append({
                "target": target, "path": f"artifacts/{target}/{ENGINE}", "sha256": digest,
                "size": dest.stat().st_size, "header_path": None, "header_sha256": None,
                "build_a_sha256": digest, "build_b_sha256": digest,
            })
        manifest = {"contract": "winsvpn-winn-release-manifest-v1", "artifacts": artifacts,
                    "source": {"binding": "git-archive", "commit": "1" * 40}}
        if mutate:
            mutate(manifest)
        raw = driver.canonical_json(manifest)
        (release / "manifest.json").write_bytes(raw)
        if signed:
            signature = driver.ed25519_sign(seed, driver.SIGNATURE_DOMAIN + raw)
            (release / "manifest.sig.json").write_bytes(driver.canonical_json({
                "contract": "winsvpn-winn-release-signature-v1", "algorithm": "ed25519",
                "public_key": driver.ed25519_public(seed).hex(),
                "manifest_sha256": hashlib.sha256(raw).hexdigest(),
                "signature": signature.hex(),
            }))
        return release

    def stage_engines_by_hand(self) -> None:
        for variant in VARIANTS:
            for abi, _, _ in ABIS:
                engine = self.staged(variant, abi)
                engine.parent.mkdir(parents=True, exist_ok=True)
                engine.write_bytes((self.fixture / abi / ENGINE).read_bytes())
                engine.chmod(0o755)

    def run_script(self, *args: str, env=None) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["bash", str(self.root / "android/tools/prepare_android_winn_assets.sh"), *args],
            cwd=self.root, env=env or self.env, capture_output=True, text=True, timeout=600,
        )

    def driver_calls(self) -> list[list[str]]:
        return [json.loads(line) for line in self.log.read_text().splitlines() if line]

    def staged(self, variant: str, abi: str, name: str = ENGINE) -> pathlib.Path:
        return self.root / "android/app/src" / variant / "jniLibs" / abi / name

    def assert_nothing_installed(self) -> None:
        jni = self.root / "android/app/src"
        found = sorted(str(p.relative_to(jni)) for p in jni.rglob("*") if p.is_file()) if jni.exists() else []
        self.assertEqual([p for p in found if not p.endswith("libxray.so")], [])

    # ------------------------------------------------------------------

    def test_stage_release_installs_verified_engines_and_writes_stamps(self) -> None:
        sentinel = b"old transport, must stay"
        for variant in VARIANTS:
            for abi, _, _ in ABIS:
                xray = self.staged(variant, abi, "libxray.so")
                xray.parent.mkdir(parents=True, exist_ok=True)
                xray.write_bytes(sentinel)
        release = self.make_release("signed")
        result = self.run_script("--stage-release", str(release))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("libxray.so is left untouched", result.stdout)

        calls = self.driver_calls()
        verifies = [call for call in calls if call[0] == "verify"]
        # One verification for all three ABIs; its stdout is the held manifest.
        self.assertEqual(verifies, [["verify", "--release", str(release), "--print-manifest"]])
        stamp_checks = [call for call in calls if call[0] == "verify-android-stamp"]
        self.assertEqual(len(stamp_checks), 6, "3 before install and 3 in the post-install gate")
        for call in calls:
            self.assertNotIn("--allow-unsigned", call)
            self.assertNotIn("--trust-public-key", call)

        manifest_raw = (release / "manifest.json").read_bytes()
        manifest_sha = hashlib.sha256(manifest_raw).hexdigest()
        signature = json.loads((release / "manifest.sig.json").read_text())["signature"]
        for variant in VARIANTS:
            stamp = json.loads((self.root / "android/app/src" / variant / STAMP).read_text())
            self.assertEqual(stamp["contract"], STAMP_CONTRACT)
            self.assertIs(stamp["signed"], True)
            self.assertEqual(stamp["release_manifest_sha256"], manifest_sha)
            self.assertEqual(stamp["signature_public_key"], TEST_PUBLIC_KEY)
            # The stamp carries the signed bytes themselves.
            self.assertEqual(base64.b64decode(stamp["manifest_b64"]), manifest_raw)
            self.assertEqual(stamp["manifest_signature"], signature)
            for abi, goarch, _ in ABIS:
                engine = self.staged(variant, abi)
                self.assertEqual(engine.read_bytes(), (self.fixture / abi / ENGINE).read_bytes())
                self.assertTrue(os.access(engine, os.X_OK))
                self.assertEqual(stamp["engines"][abi],
                                 {"sha256": sha256(engine), "size": engine.stat().st_size,
                                  "target": f"datapath-android-{goarch}"})
                self.assertEqual(self.staged(variant, abi, "libxray.so").read_bytes(), sentinel)
        leftovers = [p for p in (self.root / "android").rglob("*")
                     if p.name.endswith(".pending_androidstale") or ".pending." in p.name]
        self.assertEqual(leftovers, [])

        check = self.run_script("--release-check")
        self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
        self.assertEqual(check.stdout.count("ANDROID STAMP OK"), 3)

        # A staged release engine that no longer matches its stamp must fail the
        # release gate.
        tampered = self.staged("release", "x86_64")
        tampered.write_bytes(fake_elf(62, b"different build"))
        check = self.run_script("--release-check")
        self.assertEqual(check.returncode, 1)
        self.assertIn("staged Android engine differs from the signed manifest", check.stderr)

    def test_stage_release_never_writes_through_a_planted_pending_name(self) -> None:
        # Astra SEALED-T2 follow-up: pending copies used the predictable name
        # <dest>.pending_androidstale and were written with `cp`, which follows
        # a planted link. They are now created exclusively under unpredictable
        # names, so the planted link is neither written through nor removed.
        victim = self.tmp / "victim"
        victim.write_bytes(b"victim")
        planted = self.staged("main", "arm64-v8a").with_name(ENGINE + ".pending_androidstale")
        planted.parent.mkdir(parents=True)
        planted.symlink_to(victim)
        release = self.make_release("signed")
        result = self.run_script("--stage-release", str(release))
        self.assertEqual(victim.read_bytes(), b"victim")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(planted.is_symlink())
        self.assertEqual(self.staged("main", "arm64-v8a").read_bytes(),
                         (self.fixture / "arm64-v8a" / ENGINE).read_bytes())

    def test_stage_release_refuses_a_destination_that_became_a_directory(self) -> None:
        # `mv` would move the engine inside such a directory and carry on.
        # rename(2) refuses, and no stamp is written for any variant.
        blocker = self.staged("release", "x86_64")
        blocker.mkdir(parents=True)
        release = self.make_release("signed")
        result = self.run_script("--stage-release", str(release))
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(list(blocker.iterdir()), [])
        for variant in VARIANTS:
            self.assertFalse((self.root / "android/app/src" / variant / STAMP).exists(), variant)
        leftovers = [p for p in (self.root / "android").rglob("*") if ".pending." in p.name]
        self.assertEqual(leftovers, [])

    def test_stage_release_refuses_an_unsigned_release(self) -> None:
        release = self.make_release("unsigned", signed=False)
        result = self.run_script("--stage-release", str(release))
        self.assertEqual(result.returncode, 1)
        self.assertIn("manifest.sig.json is missing", result.stderr)
        self.assertEqual(self.driver_calls(), [])
        self.assert_nothing_installed()

    def test_stage_release_refuses_a_failed_driver_verify(self) -> None:
        release = self.make_release("tampered")
        (release / "artifacts/datapath-android-arm/libwinnengine.so").write_bytes(fake_elf(40, b"swap"))
        result = self.run_script("--stage-release", str(release))
        self.assertEqual(result.returncode, 1)
        self.assertIn("winn_release.py verify exited 1", result.stderr)
        self.assert_nothing_installed()

    def test_stage_release_passes_through_toolchain_missing(self) -> None:
        release = self.make_release("signed")
        env = dict(self.env, STUB_VERIFY_EXIT="3")
        result = self.run_script("--stage-release", str(release), env=env)
        self.assertEqual(result.returncode, 3)
        self.assertIn("TOOLCHAIN-MISSING", result.stderr)
        self.assert_nothing_installed()

    def test_stage_release_refuses_non_reproducible_manifest_entries(self) -> None:
        def split(manifest):
            manifest["artifacts"][0]["build_b_sha256"] = "0" * 64
        release = self.make_release("split", mutate=split)
        result = self.run_script("--stage-release", str(release))
        self.assertEqual(result.returncode, 1)
        self.assertIn("not recorded as identical", result.stderr)
        self.assert_nothing_installed()

    def test_stage_release_refuses_a_wrong_architecture_engine(self) -> None:
        (self.fixture / "arm64-v8a" / ENGINE).write_bytes(fake_elf(62, b"x86 in arm slot"))
        release = self.make_release("wrong-abi")
        result = self.run_script("--stage-release", str(release))
        self.assertEqual(result.returncode, 1)
        self.assertIn("is ELF e_machine 62, expected 183", result.stderr)
        self.assert_nothing_installed()

    def test_stage_builds_through_the_driver_unsigned_and_drops_stamps(self) -> None:
        for variant in VARIANTS:
            stale = self.root / "android/app/src" / variant / STAMP
            stale.parent.mkdir(parents=True, exist_ok=True)
            stale.write_text("{}")
        env = dict(self.env, ANDROID_NDK_HOME=str(self.ndk), WINN_SOURCE_COMMIT="2" * 40)
        result = self.run_script("--stage", env=env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.driver_calls()
        build = calls[0]
        self.assertEqual(build[:3], ["build", "--set", "android"])
        self.assertEqual(build[build.index("--source-commit") + 1], "2" * 40)
        self.assertEqual(build[build.index("--ndk") + 1], str(self.ndk))
        self.assertNotIn("--trust-public-key", build)
        verifies = calls[1:]
        self.assertEqual(verifies, [["verify", "--release", build[build.index("--out") + 1],
                                     "--allow-unsigned", "--print-manifest"]])
        for variant in VARIANTS:
            self.assertFalse((self.root / "android/app/src" / variant / STAMP).exists())
            for abi, goarch, _ in ABIS:
                self.assertEqual(self.staged(variant, abi).read_bytes(),
                                 (self.fixture / abi / ENGINE).read_bytes())
                self.assertEqual(self.staged(variant, abi, "libxray.so").read_bytes(),
                                 (self.fixture / f"xray-android-{goarch}").read_bytes())
        check = self.run_script("--release-check")
        self.assertEqual(check.returncode, 1)
        self.assertIn("stage a signed release with --stage-release", check.stderr)

    def test_stage_refuses_an_unpinned_ndk(self) -> None:
        (self.ndk / "source.properties").write_text("Pkg.Revision = 29.0.14206865\n")
        env = dict(self.env, ANDROID_NDK_HOME=str(self.ndk), WINN_SOURCE_COMMIT="2" * 40)
        result = self.run_script("--stage", env=env)
        self.assertEqual(result.returncode, 1)
        self.assertIn("does not match the project pin 30.0.16248370", result.stderr)
        self.assertEqual(self.driver_calls(), [])

    def test_stage_passes_through_toolchain_missing_from_build(self) -> None:
        env = dict(self.env, ANDROID_NDK_HOME=str(self.ndk), WINN_SOURCE_COMMIT="2" * 40,
                   STUB_BUILD_EXIT="3")
        result = self.run_script("--stage", env=env)
        self.assertEqual(result.returncode, 3)
        self.assertIn("TOOLCHAIN-MISSING", result.stderr)
        self.assert_nothing_installed()


    # Astra Turn 1 finding 1: the release gate accepted a stamp it could not
    # authenticate. These fail on the Turn 1 candidate.

    def write_stamp(self, variant: str, stamp: dict) -> None:
        path = self.root / "android/app/src" / variant / STAMP
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(stamp, indent=2, sort_keys=True) + "\n")

    def test_release_check_refuses_a_fabricated_unsigned_stamp(self) -> None:
        # Exactly the probe: unsigned, hashes that match the staged bytes, and
        # fabricated manifest digest and public key fields.
        self.stage_engines_by_hand()
        engines = {}
        for abi, goarch, _ in ABIS:
            engine = self.staged("main", abi)
            engines[abi] = {"sha256": sha256(engine), "size": engine.stat().st_size,
                            "target": f"datapath-android-{goarch}"}
        self.write_stamp("release", {
            "contract": STAMP_CONTRACT, "engines": engines, "signed": True,
            "release_manifest_sha256": "cd" * 32, "signature_public_key": TEST_PUBLIC_KEY,
            "source_commit": "1" * 40,
        })
        check = self.run_script("--release-check")
        self.assertEqual(check.returncode, 1, check.stdout + check.stderr)
        self.assertIn("lacks signed manifest bytes", check.stderr)

    def test_release_check_refuses_a_stamp_signed_by_another_key(self) -> None:
        self.stage_engines_by_hand()
        release = self.make_release("other-key", seed=testkit.WRONG_SEED)
        raw = (release / "manifest.json").read_bytes()
        signature = json.loads((release / "manifest.sig.json").read_text())
        engines = {abi: {"sha256": sha256(self.staged("main", abi)),
                         "size": self.staged("main", abi).stat().st_size,
                         "target": f"datapath-android-{goarch}"} for abi, goarch, _ in ABIS}
        stamp = {
            "contract": STAMP_CONTRACT, "engines": engines, "signed": True,
            "manifest_b64": base64.b64encode(raw).decode(), "manifest_signature": signature["signature"],
            "release_manifest_sha256": hashlib.sha256(raw).hexdigest(),
            "signature_public_key": TEST_PUBLIC_KEY, "source_commit": "1" * 40,
        }
        self.write_stamp("release", stamp)
        check = self.run_script("--release-check")
        self.assertEqual(check.returncode, 1, check.stdout + check.stderr)
        self.assertIn("Android stamp signature does not verify", check.stderr)
        # The same envelope signed by the pinned (test) key passes.
        good = self.make_release("pinned-key")
        raw = (good / "manifest.json").read_bytes()
        stamp["manifest_b64"] = base64.b64encode(raw).decode()
        stamp["manifest_signature"] = json.loads((good / "manifest.sig.json").read_text())["signature"]
        self.write_stamp("release", stamp)
        check = self.run_script("--release-check")
        self.assertEqual(check.returncode, 0, check.stdout + check.stderr)

    # Turn 2: staging takes every digest from the bytes the driver verified.

    def test_stage_release_never_trusts_a_manifest_read_outside_verification(self) -> None:
        genuine_images = {f"datapath-android-{goarch}": (ENGINE, (self.fixture / abi / ENGINE).read_bytes())
                          for abi, goarch, _ in ABIS}
        attacker_images = {f"datapath-android-{goarch}": (ENGINE, fake_elf(machine, b"attacker " + abi.encode()))
                           for abi, goarch, machine in ABIS}
        release, genuine, attacker = testkit.prepare_race(self.tmp, genuine_images, attacker_images)
        testkit.install_racing_driver(self.root / "tools")
        env = dict(self.env, **testkit.race_environment(genuine, attacker, self.log))
        result = self.run_script("--stage-release", str(release), env=env)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        # Refused by the binding to the verified manifest itself, before the
        # stamp authentication that would also catch the forged signature.
        self.assertIn("does not match the manifest", result.stderr)
        self.assert_nothing_installed()


class PrepareAndroidWinnAssetsSourceTest(unittest.TestCase):
    def test_ndk_pin_is_r30_everywhere(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("29.0.14206865", text)
        self.assertIn('ANDROID_NDK_PIN="30.0.16248370"', text)

    def test_usage_requires_a_release_dir(self) -> None:
        for args in (["--stage-release"], ["--bogus"], ["--check", "extra"]):
            with self.subTest(args=args):
                result = subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True,
                                        timeout=60)
                self.assertEqual(result.returncode, 2)
                self.assertIn("--stage-release RELEASE_DIR", result.stderr)


if __name__ == "__main__":
    unittest.main()
