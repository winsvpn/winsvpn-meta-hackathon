#!/usr/bin/env python3
"""Regressions for tools/build_winn_protocol_engine.sh (sealed single-target builder).

The builder runs here against a fake Go root whose bin/go is a shell stub, and a
private copy of toolchain-pins.json that pins that stub's SHA-256. Everything
else (sealed source and module-cache digests, output freshness, buildinfo
identity, mutation detection, receipt shape) is the real script.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "tools" / "build_winn_protocol_engine.sh"
DRIVER = ROOT / "tools" / "winn_release.py"
SOURCE = SCRIPT.read_text(encoding="utf-8")
PINS = json.loads((ROOT / "tools" / "toolchain-pins.json").read_text(encoding="utf-8"))
GO_VERSION = PINS["tools"]["go"]["version"]
sys.path.insert(0, str(ROOT / "tools"))
import winn_release as wr  # noqa: E402


def _host() -> str:
    os_name = {"Darwin": "darwin", "Linux": "linux"}[platform.system()]
    arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64"}[platform.machine()]
    return f"{os_name}/{arch}"


FAKE_GO = r"""#!/bin/bash
set -eu
if [[ "$1" == version && $# -eq 1 ]]; then
  echo "go version go__VERSION__ __HOST__"; exit 0
fi
if [[ "$1" == mod && "$2" == verify ]]; then
  [[ -n "${FAKE_MOD_VERIFY_FAIL:-}" ]] && exit 23
  exit 0
fi
if [[ "$1" == version && "$2" == -m ]]; then
  IFS='|' read -r _ goos goarch pkg < "$4"  || true
  path="winsvpn.local/winnprotocol/${pkg#./}"
  [[ -n "${FAKE_BUILDINFO_PATH:-}" ]] && path="${FAKE_BUILDINFO_PATH}"
  feature=GOARM64; value=v8.0
  [[ "$goarch" == amd64 ]] && { feature=GOAMD64; value=v1; }
  [[ "$goarch" == arm ]] && { feature=GOARM; value=7; }
  printf '{"GoVersion":"go__VERSION__","Path":"%s","Settings":[{"Key":"GOOS","Value":"%s"},{"Key":"GOARCH","Value":"%s"},{"Key":"CGO_ENABLED","Value":"%s"},{"Key":"-trimpath","Value":"true"},{"Key":"%s","Value":"%s"}]}\n' \
    "$path" "$goos" "$goarch" "${CGO_ENABLED}" "$feature" "$value"
  exit 0
fi
if [[ "$1" == build ]]; then
  out=""; prev=""
  for arg in "$@"; do [[ "$prev" == -o ]] && out="$arg"; prev="$arg"; done
  pkg="${!#}"
  if [[ -n "${FAKE_MUTATE:-}" ]]; then chmod u+w "${FAKE_MUTATE}"; printf 'mutation' >> "${FAKE_MUTATE}"; fi
  [[ -n "${FAKE_COMPILE_MARKER:-}" ]] && : > "${FAKE_COMPILE_MARKER}"
  [[ -n "${FAKE_ENV_LOG:-}" ]] && printf '%s|%s\n' "${GOCACHE}" "${GODEBUG:-}" >> "${FAKE_ENV_LOG}"
  printf 'fake|%s|%s|%s' "${GOOS}" "${GOARCH}" "$pkg" > "$out"
  exit 0
fi
exit 9
"""


class Fixture:
    def __init__(self, tmp: pathlib.Path) -> None:
        self.tmp = tmp
        tools = tmp / "repo" / "tools"
        tools.mkdir(parents=True)
        shutil.copy2(SCRIPT, tools / SCRIPT.name)
        shutil.copy2(DRIVER, tools / DRIVER.name)
        self.builder = tools / SCRIPT.name
        go_root = tmp / "go"
        (go_root / "bin").mkdir(parents=True)
        stub = go_root / "bin" / "go"
        stub.write_text(FAKE_GO.replace("__VERSION__", GO_VERSION).replace("__HOST__", _host()))
        stub.chmod(0o755)
        pins = json.loads(json.dumps(PINS))
        pins["tools"]["go"]["executable_sha256"] = wr.sha256_file(stub)
        (tools / "toolchain-pins.json").write_text(json.dumps(pins))
        self.go_root = go_root
        self.source = tmp / "src"
        self.source.mkdir()
        (self.source / "go.mod").write_text("module winsvpn.local/winnprotocol\n")
        (self.source / "go.sum").write_text("")
        (self.source / "main.go").write_text("package main\n")
        wr.seal_tree(self.source)
        self.cache = tmp / "modcache"
        (self.cache / "cache").mkdir(parents=True)
        (self.cache / "cache" / "marker").write_text("x")
        wr.seal_tree(self.cache)
        self.out = tmp / "out"

    def env(self, **extra: str) -> dict[str, str]:
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(self.tmp),
            "TMPDIR": str(self.tmp),
            "WINS_WINN_SOURCE_ROOT": str(self.source.resolve()),
            "WINS_WINN_SOURCE_TREE_SHA256": wr.sealed_tree_digest(self.source),
            "WINS_STORE_GOMODCACHE": str(self.cache.resolve()),
            "WINS_STORE_GOMODCACHE_TREE_SHA256": wr.sealed_tree_digest(self.cache),
            "WINS_RELEASE_GO_ROOT": str(self.go_root),
        }
        env.update(extra)
        return env

    def run(self, target: str, name: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["/bin/bash", str(self.builder), target, str(self.out / name)],
                              env=env, capture_output=True, text=True, timeout=120)

    def close(self) -> None:
        for path in (self.source, self.cache):
            if path.exists():
                wr.remove_tree(path)


class BuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.fx = Fixture(pathlib.Path(self._dir.name).resolve())

    def tearDown(self) -> None:
        self.fx.close()
        self._dir.cleanup()

    def test_shell_syntax(self) -> None:
        subprocess.run(["/bin/bash", "-n", str(SCRIPT)], check=True)

    def test_retained_producer_gate_is_gone(self) -> None:
        for gone in ("WINS_RETAINED_BUILDER_PATH", "WINS_RETAINED_BUILDER_CUSTODY_FD",
                     "ReleaseWinnProtocolAuthority", "consumption-ledger", "wins_release_go_run",
                     "verify_owner_authorization", "OWNER-BLOCKED"):
            self.assertNotIn(gone, SOURCE)
        self.assertNotIn("[[ $- == *p* ]]", SOURCE)

    def test_flags_are_the_reviewed_reproducible_set(self) -> None:
        self.assertIn("-mod=readonly -pgo=off -trimpath -buildvcs=false", SOURCE)
        self.assertIn("-ldflags='-s -w -buildid='", SOURCE)
        self.assertIn("GOPROXY=off", SOURCE)
        self.assertIn("GOTOOLCHAIN=local", SOURCE)
        self.assertIn("-buildmode=c-archive", SOURCE)
        self.assertIn("export ZERO_AR_DATE=1", SOURCE)

    def test_sealed_build_emits_v4_receipt_and_fresh_output(self) -> None:
        result = self.fx.run("datapath-linux-arm64", "winn-datapath", self.fx.env())
        self.assertEqual(result.returncode, 0, result.stderr)
        receipts = [line for line in result.stdout.splitlines() if line.startswith("WINN_BUILD_RECEIPT ")]
        self.assertEqual(len(receipts), 1)
        receipt = json.loads(receipts[0].split(" ", 1)[1])
        output = self.fx.out / "winn-datapath"
        self.assertEqual(receipt["contract"], "winsvpn-winn-core-build-v4")
        self.assertEqual(receipt["artifact"]["sha256"], hashlib.sha256(output.read_bytes()).hexdigest())
        self.assertEqual(receipt["package"], "./cmd/winn-datapath")
        self.assertEqual(receipt["target"], {"cgo_enabled": False, "goarch": "arm64", "goos": "linux",
                                             "id": "datapath-linux-arm64"})
        self.assertEqual(receipt["source_tree_sha256"], self.fx.env()["WINS_WINN_SOURCE_TREE_SHA256"])
        self.assertEqual((self.fx.out / "winn-datapath.receipt.json").read_text(),
                         receipts[0].split(" ", 1)[1] + "\n")
        self.assertEqual(sorted(p.name for p in self.fx.out.iterdir()),
                         ["winn-datapath", "winn-datapath.receipt.json"])

    def test_existing_output_is_never_replaced(self) -> None:
        self.fx.out.mkdir()
        (self.fx.out / "winn-clientinfo").write_bytes(b"previous\n")
        result = self.fx.run("linux-amd64", "winn-clientinfo", self.fx.env())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be fresh", result.stderr)
        self.assertEqual((self.fx.out / "winn-clientinfo").read_bytes(), b"previous\n")

    def test_receipt_is_never_staged_at_a_predictable_name_beside_the_output(self) -> None:
        # Astra SEALED-T2 follow-up: the receipt used to be written with `>` to
        # OUTPUT.receipt.json.stage.<pid>, so a link planted there was written
        # through. exec keeps the pid, so the wrapper below plants exactly that
        # name before the builder starts.
        self.fx.out.mkdir()
        victim = self.fx.tmp / "victim"
        victim.write_bytes(b"victim")
        output = self.fx.out / "winn-datapath"
        wrapper = ('ln -s "$1" "$2.receipt.json.stage.$$"; '
                   'exec /bin/bash "$3" datapath-linux-arm64 "$2"')
        result = subprocess.run(["/bin/bash", "-c", wrapper, "wrapper", str(victim), str(output),
                                 str(self.fx.builder)], env=self.fx.env(), capture_output=True,
                                text=True, timeout=120)
        self.assertEqual(victim.read_bytes(), b"victim")
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = pathlib.Path(str(output) + ".receipt.json")
        self.assertFalse(receipt.is_symlink())
        self.assertEqual(json.loads(receipt.read_text())["artifact"]["sha256"],
                         hashlib.sha256(output.read_bytes()).hexdigest())
        leftovers = sorted(p.name for p in self.fx.out.iterdir() if p.name.startswith(".winn-protocol-build."))
        self.assertEqual(leftovers, [])

    def test_wrong_source_digest_is_refused_before_building(self) -> None:
        result = self.fx.run("linux-amd64", "x", self.fx.env(WINS_WINN_SOURCE_TREE_SHA256="0" * 64))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match the sealed snapshot", result.stderr)
        self.assertFalse((self.fx.out / "x").exists())

    def test_writable_source_is_refused(self) -> None:
        env = self.fx.env()
        (self.fx.source / "main.go").chmod(0o644)
        result = self.fx.run("linux-amd64", "x", env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not a sealed", result.stderr)

    def test_wrong_module_cache_digest_is_refused(self) -> None:
        result = self.fx.run("linux-amd64", "x", self.fx.env(WINS_STORE_GOMODCACHE_TREE_SHA256="1" * 64))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match the sealed cache", result.stderr)

    def test_unpinned_go_executable_is_refused(self) -> None:
        stub = self.fx.go_root / "bin" / "go"
        stub.write_text(stub.read_text() + "# changed\n")
        result = self.fx.run("linux-amd64", "x", self.fx.env())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is not the pinned Go", result.stderr)

    def test_source_mutation_during_build_removes_the_output(self) -> None:
        env = self.fx.env(FAKE_MUTATE=str(self.fx.source / "main.go"))
        result = self.fx.run("linux-amd64", "winn-clientinfo", env)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("WINN_BUILD_RECEIPT", result.stdout)
        self.assertFalse((self.fx.out / "winn-clientinfo").exists())

    def test_failed_go_mod_verify_stops_before_compiling(self) -> None:
        # Astra Turn 1 finding 3: the subshell was the left operand of ||, so
        # errexit never applied and a failed `go mod verify` was ignored.
        marker = self.fx.tmp / "compiled"
        env = self.fx.env(FAKE_MOD_VERIFY_FAIL="1", FAKE_COMPILE_MARKER=str(marker))
        result = self.fx.run("linux-amd64", "winn-clientinfo", env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("go mod verify failed for linux-amd64", result.stderr)
        self.assertFalse(marker.exists(), "go build ran after go mod verify failed")
        self.assertFalse((self.fx.out / "winn-clientinfo").exists())

    def test_variant_build_cache_is_shared_only_when_the_driver_names_it(self) -> None:
        log = self.fx.tmp / "env.log"
        cache = self.fx.tmp / "variant-cache-a"
        cache.mkdir(mode=0o700)
        result = self.fx.run("linux-amd64", "one", self.fx.env(FAKE_ENV_LOG=str(log),
                                                                 WINS_WINN_VARIANT_GOCACHE=str(cache)))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(log.read_text().splitlines(), [f"{cache}|gocacheverify=0"])
        self.assertTrue(cache.is_dir(), "the driver's variant cache must outlive one build")
        log.unlink()
        result = self.fx.run("linux-amd64", "two", self.fx.env(FAKE_ENV_LOG=str(log)))
        self.assertEqual(result.returncode, 0, result.stderr)
        fresh, debug = log.read_text().splitlines()[0].split("|")
        self.assertNotEqual(fresh, str(cache))
        self.assertEqual(debug, "gocacheverify=1")
        self.assertFalse(pathlib.Path(fresh).exists(), "a private fresh cache is removed after the build")
        result = self.fx.run("linux-amd64", "three", self.fx.env(WINS_WINN_VARIANT_GOCACHE="relative/cache"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("WINS_WINN_VARIANT_GOCACHE must be an absolute directory", result.stderr)

    def test_role_swapped_buildinfo_is_refused(self) -> None:
        env = self.fx.env(FAKE_BUILDINFO_PATH="winsvpn.local/winnprotocol/cmd/winn-server")
        result = self.fx.run("datapath-linux-amd64", "winn-datapath", env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match selected artifact role", result.stderr)
        self.assertFalse((self.fx.out / "winn-datapath").exists())

    def test_android_needs_the_pinned_ndk(self) -> None:
        result = self.fx.run("datapath-android-arm64", "libwinnengine.so", self.fx.env())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Android NDK not found", result.stderr)
        fake_ndk = self.fx.tmp / "ndk"
        fake_ndk.mkdir()
        (fake_ndk / "source.properties").write_text("Pkg.Revision = 29.0.14206865\n")
        result = self.fx.run("datapath-android-arm64", "libwinnengine.so",
                             self.fx.env(WINS_ANDROID_NDK_ROOT=str(fake_ndk)))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("the pin is 30.0.16248370", result.stderr)

    def test_relay_needs_a_sealed_relay_module_bound_to_the_same_source(self) -> None:
        result = self.fx.run("winn3-relay-windows-amd64", "winsvpn_winn3_engine.exe", self.fx.env())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("WINS_WINN_RELAY_SOURCE_ROOT", result.stderr)
        relay = self.fx.tmp / "relay"
        relay.mkdir()
        (relay / "go.mod").write_text("module winsvpn.local/winsvpnwinn3engine\n"
                                      "replace winsvpn.local/winnprotocol => ../../winn_protocol_experimental\n")
        wr.seal_tree(relay)
        env = self.fx.env(WINS_WINN_RELAY_SOURCE_ROOT=str(relay.resolve()),
                          WINS_WINN_RELAY_SOURCE_TREE_SHA256=wr.sealed_tree_digest(relay))
        result = self.fx.run("winn3-relay-windows-amd64", "winsvpn_winn3_engine.exe", env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("replaced Winn module", result.stderr)
        self.assertFalse((self.fx.out / "winsvpn_winn3_engine.exe").exists())
        wr.remove_tree(relay)

    def test_unknown_target_is_refused(self) -> None:
        result = self.fx.run("datapath-plan9-amd64", "x", self.fx.env())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unknown target", result.stderr)

    def test_direct_mode_delegates_to_commit_bound_driver(self) -> None:
        env = {"PATH": "/usr/bin:/bin", "HOME": str(self.fx.tmp), "TMPDIR": str(self.fx.tmp)}
        result = self.fx.run("datapath-linux-arm64", "winn-datapath", env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("need a git checkout", result.stderr)


class HostGoPinTests(unittest.TestCase):
    """bin/go is pinned per build host, not to the darwin_arm64 measurement alone."""

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.fx = Fixture(pathlib.Path(self._dir.name).resolve())
        self.pins_path = self.fx.builder.parent / "toolchain-pins.json"
        self.stub_sha = wr.sha256_file(self.fx.go_root / "bin" / "go")

    def tearDown(self) -> None:
        self.fx.close()
        self._dir.cleanup()

    def _write_go_pins(self, executable: str, by_platform: dict[str, str] | None) -> None:
        pins = json.loads(self.pins_path.read_text())
        pins["tools"]["go"]["executable_sha256"] = executable
        pins["tools"]["go"].pop("executable_sha256_by_platform", None)
        if by_platform is not None:
            pins["tools"]["go"]["executable_sha256_by_platform"] = by_platform
        self.pins_path.write_text(json.dumps(pins))

    def _pretend_host(self, system: str, machine: str, go_host: str) -> None:
        # The builder reads the host only through /usr/bin/uname; the fixture
        # copy points that at a fake, and the fake Go reports the same host.
        fake = self.fx.tmp / "fake-uname"
        fake.write_text(
            "#!/bin/bash\n"
            f'case "$1" in -s) echo {system} ;; -m) echo {machine} ;; *) exit 9 ;; esac\n'
        )
        fake.chmod(0o755)
        text = self.fx.builder.read_text()
        self.assertEqual(text.count("/usr/bin/uname"), 2)
        self.fx.builder.write_text(text.replace("/usr/bin/uname", str(fake)))
        stub = self.fx.go_root / "bin" / "go"
        stub.write_text(FAKE_GO.replace("__VERSION__", GO_VERSION).replace("__HOST__", go_host))
        self.stub_sha = wr.sha256_file(stub)

    def test_host_platform_pin_wins_over_the_darwin_pin(self) -> None:
        host = _host().replace("/", "_")
        self._write_go_pins("0" * 64, {host: self.stub_sha})
        result = self.fx.run("datapath-linux-arm64", "winn-datapath", self.fx.env())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_mismatched_host_platform_pin_refuses_even_if_the_darwin_pin_matches(self) -> None:
        host = _host().replace("/", "_")
        self._write_go_pins(self.stub_sha, {host: "1" * 64})
        result = self.fx.run("datapath-linux-arm64", "winn-datapath", self.fx.env())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is not the pinned Go", result.stderr)
        self.assertFalse((self.fx.out / "winn-datapath").exists())

    def test_linux_host_without_its_own_pin_refuses_with_the_missing_pin(self) -> None:
        self._pretend_host("Linux", "x86_64", "linux/amd64")
        # Even a darwin pin equal to this bin/go must not authorize a Linux host.
        self._write_go_pins(self.stub_sha, None)
        result = self.fx.run("datapath-linux-amd64", "winn-datapath", self.fx.env())
        self.assertEqual(result.returncode, 65, result.stderr)
        self.assertIn(
            "missing pin: tools.go.executable_sha256_by_platform.linux_amd64 is absent "
            "from tools/toolchain-pins.json; measure it with sha256sum go/bin/go",
            result.stderr,
        )
        self.assertFalse((self.fx.out / "winn-datapath").exists())

    def test_linux_host_builds_with_its_own_pin(self) -> None:
        self._pretend_host("Linux", "x86_64", "linux/amd64")
        self._write_go_pins("0" * 64, {"linux_amd64": self.stub_sha, "linux_arm64": "2" * 64})
        result = self.fx.run("datapath-linux-amd64", "winn-datapath", self.fx.env())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.fx.out / "winn-datapath").is_file())

    def test_malformed_host_platform_pin_is_refused(self) -> None:
        host = _host().replace("/", "_")
        self._write_go_pins(self.stub_sha, {host: self.stub_sha.upper()})
        result = self.fx.run("datapath-linux-arm64", "winn-datapath", self.fx.env())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is not a lowercase SHA-256", result.stderr)


if __name__ == "__main__":
    unittest.main()
