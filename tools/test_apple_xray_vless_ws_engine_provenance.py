#!/usr/bin/env python3
"""Fail-closed Apple Xray delivered-artifact provenance regressions.

Compiling WinsXrayVlessWsTransport.m in a harness is not evidence that a
provenance-bound iOS/macos/simulator dylib was built from that source.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
WRAPPERS = ROOT / "tools" / "build_apple_engine_wrappers.sh"
STAGING = ROOT / "tools" / "stage_apple_engine_artifacts.sh"
README = ROOT / "apple" / "EngineArtifacts" / "README.md"
SCHEMA = ROOT / "tools" / "apple_xray_vless_ws_engine_provenance.schema.json"
VERIFIER = ROOT / "tools" / "apple_xray_vless_ws_engine_provenance.py"
SOURCE = ROOT / "apple" / "EngineWrappers" / "WinsXrayVlessWsTransport.m"
PROVENANCE = ROOT / "apple" / "EngineArtifacts" / "apple_xray_vless_ws_engine_provenance.json"

REQUIRED_UNDEFINED = (
    "LibXraySetSockCallback",
    "dup2",
    "getifaddrs",
    "setsockopt",
)
REQUIRED_EXPORTED = (
    "wins_xray_vless_ws_transport_configure",
    "wins_xray_vless_ws_transport_contract_version",
    "wins_xray_vless_ws_transport_start",
    "wins_xray_vless_ws_transport_stop",
)
WRAPPERS_RELATIVE = (
    ("ios/iphoneos/libWinsXrayVlessWsTransport.dylib", "iphoneos", "arm64", "IOS"),
    (
        "ios/iphonesimulator/libWinsXrayVlessWsTransport.dylib",
        "iphonesimulator",
        "arm64",
        "IOSSIMULATOR",
    ),
    ("macos/libWinsXrayVlessWsTransport.dylib", "macosx", "arm64", "MACOS"),
)
TRIPLES = {
    ("macosx", "arm64"): "arm64-apple-macos13.0",
    ("macosx", "x86_64"): "x86_64-apple-macos13.0",
    ("iphoneos", "arm64"): "arm64-apple-ios13.0",
    ("iphonesimulator", "arm64"): "arm64-apple-ios14.0-simulator",
    ("iphonesimulator", "x86_64"): "x86_64-apple-ios13.0-simulator",
}
XRAY_STUB = """\
#include <ifaddrs.h>
#include <sys/socket.h>
#include <unistd.h>
extern char *LibXraySetSockCallback(void *cb, void *ctx);
int wins_xray_vless_ws_transport_contract_version(void) { return 1; }
int wins_xray_vless_ws_transport_configure(const char *config_json) {
  (void)config_json;
  return 1;
}
int wins_xray_vless_ws_transport_start(void) {
  struct ifaddrs *list = 0;
  (void)getifaddrs(&list);
  (void)setsockopt(0, 0, 0, 0, 0);
  (void)dup2(0, 1);
  (void)LibXraySetSockCallback(0, 0);
  return 1;
}
void wins_xray_vless_ws_transport_stop(void) {}
"""
XRAY_STUB_NO_SOCK = """\
#include <ifaddrs.h>
#include <sys/socket.h>
#include <unistd.h>
int wins_xray_vless_ws_transport_contract_version(void) { return 1; }
int wins_xray_vless_ws_transport_configure(const char *config_json) {
  (void)config_json;
  return 1;
}
int wins_xray_vless_ws_transport_start(void) {
  struct ifaddrs *list = 0;
  (void)getifaddrs(&list);
  (void)setsockopt(0, 0, 0, 0, 0);
  (void)dup2(0, 1);
  return 1;
}
void wins_xray_vless_ws_transport_stop(void) {}
"""


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def consumer_normalized_sha256(path: pathlib.Path, scratch: pathlib.Path) -> str:
    """The macOS verifier's signature-normalized digest of one file.

    The verifier holds the file and watches its nine nearest ancestors, so the
    copy it holds sits nine quiet directories deep under scratch.
    """
    sys.path.insert(0, str(ROOT / "tools"))
    try:
        import verify_macos_release_artifact as consumer
    finally:
        sys.path.remove(str(ROOT / "tools"))
    scratch.mkdir(mode=0o700, parents=True, exist_ok=True)
    # The verifier refuses any symbolic path component (for example /var).
    scratch = scratch.resolve()
    held_dir = scratch.joinpath("held", *"abcdefgh")
    held_dir.mkdir(mode=0o700, parents=True)
    work = scratch / "work"
    work.mkdir(mode=0o700)
    copy = held_dir / "engine"
    copy.write_bytes(path.read_bytes())
    with consumer.HeldFile(copy, "fixture engine") as held:
        return consumer.signature_normalized_sha256(
            held, work, "engine", consumer.run_command
        )


def _clang() -> str:
    return subprocess.check_output(["xcrun", "-f", "clang"], text=True).strip()


def _sdk(name: str) -> str:
    return subprocess.check_output(
        ["xcrun", "--sdk", name, "--show-sdk-path"], text=True
    ).strip()


def compile_xray_dylib(
    path: pathlib.Path,
    platform_name: str,
    arch: str,
    source: str = XRAY_STUB,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    src = path.with_suffix(".c")
    src.write_text(source, encoding="utf-8")
    completed = subprocess.run(
        [
            _clang(),
            "-dynamiclib",
            "-target",
            TRIPLES[(platform_name, arch)],
            "-isysroot",
            _sdk(platform_name),
            "-Wl,-undefined,dynamic_lookup",
            "-Wl,-install_name,@rpath/WinsXrayVlessWsTransport.framework/WinsXrayVlessWsTransport",
            str(src),
            "-o",
            str(path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    src.unlink(missing_ok=True)
    if completed.returncode != 0:
        raise AssertionError(
            f"clang -dynamiclib failed for {path}: {completed.stderr or completed.stdout}"
        )


class AppleXrayVlessWsEngineProvenanceTests(unittest.TestCase):
    def source(self, path: pathlib.Path) -> str:
        return path.read_text(encoding="utf-8")

    def test_schema_binds_wrapper_source_and_production_imports(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        self.assertEqual(
            schema["properties"]["component"]["const"],
            "xray-apple-vless-ws-engine-wrappers",
        )
        self.assertNotIn("amneziawg", json.dumps(schema))
        self.assertNotIn("winn-apple", json.dumps(schema))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            set(schema["required"]),
            {
                "builders",
                "component",
                "generation",
                "required_exported_symbols",
                "required_undefined_symbols",
                "schema_version",
                "source",
                "wrappers",
            },
        )
        self.assertEqual(
            schema["properties"]["source"]["properties"]["path"]["const"],
            "apple/EngineWrappers/WinsXrayVlessWsTransport.m",
        )
        self.assertEqual(
            set(schema["properties"]["wrappers"]["required"]),
            {"iphoneos", "iphonesimulator", "macosx"},
        )
        undefined = schema["properties"]["required_undefined_symbols"]["items"]["enum"]
        for name in REQUIRED_UNDEFINED:
            self.assertIn(name, undefined)
        exported = schema["properties"]["required_exported_symbols"]["items"]["enum"]
        for name in REQUIRED_EXPORTED:
            self.assertIn(name, exported)
        self.assertEqual(
            set(schema["$defs"]["wrapper_record"]["required"]),
            {
                "architectures",
                "exported_symbols",
                "filetype",
                "path",
                "platform",
                "sha256",
                "undefined_symbols",
            },
        )

    def test_producer_and_staging_require_xray_source_binding(self) -> None:
        wrappers = self.source(WRAPPERS)
        staging = self.source(STAGING)
        readme = self.source(README)
        self.assertIn("write_xray_provenance", wrappers)
        self.assertIn("verify-xray-provenance", wrappers)
        self.assertIn("apple_refuse_live_xray_provenance_hash_without_rebuild", wrappers)
        self.assertIn("require_undefined_symbols", wrappers)
        self.assertIn("XRAY_REQUIRED_UNDEFINED_SYMBOLS", wrappers)
        for name in REQUIRED_UNDEFINED:
            self.assertIn(name, wrappers)
        self.assertIn("verify_and_stage_xray_provenance", staging)
        self.assertIn("verify-xray-provenance", staging)
        self.assertIn("APPLE_ENGINE_ARTIFACTS_DIR", staging.split(
            "verify_and_stage_xray_provenance() {", 1
        )[1].split("apple_winn_engine_provenance_path() {", 1)[0])
        self.assertIn("apple_xray_vless_ws_engine_provenance.json", readme)
        self.assertIn("WinsXrayVlessWsTransport.m", readme)
        self.assertIn("LibXraySetSockCallback", readme)
        self.assertIn("test harness is not evidence", readme.lower())
        awg_branch = wrappers.split('if [[ "${target}" == "awg" ]]; then', 1)[1]
        awg_branch = awg_branch.split("\n  fi\n", 1)[0]
        self.assertIn("write_xray_provenance", awg_branch)
        after_awg = wrappers.rsplit("write_engine_provenance", 1)[-1]
        self.assertIn("write_xray_provenance", after_awg)
        verify_awg = wrappers.split('if [[ "${target}" == "verify-awg-provenance" ]]; then', 1)[1]
        verify_awg = verify_awg.split("\n  fi\n", 1)[0]
        self.assertIn("verify_xray_provenance", verify_awg)

    def test_shell_syntax(self) -> None:
        for script in (WRAPPERS, STAGING):
            subprocess.run(["bash", "-n", str(script)], cwd=ROOT, check=True)

    def _materialize(self, root: pathlib.Path, *, stub: str = XRAY_STUB) -> dict[str, pathlib.Path]:
        source_dir = root / "wrappers"
        engines = root / "engines"
        source_dir.mkdir()
        wrapper = source_dir / "WinsXrayVlessWsTransport.m"
        wrapper.write_text(
            SOURCE.read_text(encoding="utf-8") + "\n/* provenance fixture */\n",
            encoding="utf-8",
        )
        for relative, platform_name, arch, _platform in WRAPPERS_RELATIVE:
            compile_xray_dylib(engines / relative, platform_name, arch, stub)
        return {
            "source_dir": source_dir,
            "wrapper": wrapper,
            "engines": engines,
            "provenance": engines / "apple_xray_vless_ws_engine_provenance.json",
        }

    def _env(self, paths: dict[str, pathlib.Path]) -> dict[str, str]:
        environment = os.environ.copy()
        environment["PROJECT_ROOT"] = str(ROOT)
        environment["APPLE_ENGINE_WRAPPER_SOURCE_DIR"] = str(paths["source_dir"])
        environment["APPLE_ENGINE_WRAPPER_OUTPUT_ROOT"] = str(paths["engines"])
        environment["APPLE_XRAY_ENGINE_PROVENANCE_FILE"] = str(paths["provenance"])
        return environment

    def _run(
        self,
        args: list[str],
        environment: dict[str, str],
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(WRAPPERS), *args],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=check,
            timeout=60,
        )

    def test_write_and_verify_bind_source_hash_and_production_imports(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-xray-prov-") as raw:
            paths = self._materialize(pathlib.Path(raw))
            environment = self._env(paths)
            written = self._run(["write-xray-provenance"], environment)
            self.assertIn(
                "Apple Xray VLESS-WS engine provenance:",
                written.stdout,
                written.stderr,
            )
            verified = self._run(["verify-xray-provenance"], environment)
            self.assertIn("APPLE XRAY VLESS-WS ENGINE PROVENANCE: PASS", verified.stdout)
            manifest = json.loads(paths["provenance"].read_text(encoding="utf-8"))
            self.assertEqual(manifest["component"], "xray-apple-vless-ws-engine-wrappers")
            self.assertEqual(manifest["generation"], "vless-ws")
            self.assertEqual(manifest["schema_version"], 1)
            self.assertIsInstance(manifest["schema_version"], int)
            self.assertNotIsInstance(manifest["schema_version"], bool)
            self.assertEqual(
                manifest["source"]["path"],
                "apple/EngineWrappers/WinsXrayVlessWsTransport.m",
            )
            self.assertEqual(manifest["source"]["sha256"], sha256(paths["wrapper"]))
            self.assertEqual(
                manifest["required_undefined_symbols"], list(REQUIRED_UNDEFINED)
            )
            self.assertEqual(
                manifest["required_exported_symbols"], list(REQUIRED_EXPORTED)
            )
            macos = paths["engines"] / "macos/libWinsXrayVlessWsTransport.dylib"
            entry = manifest["wrappers"]["macosx"]
            self.assertEqual(entry["sha256"], sha256(macos))
            self.assertEqual(entry["platform"], "MACOS")
            self.assertEqual(entry["filetype"], "mach-o-dylib")
            for name in REQUIRED_UNDEFINED:
                self.assertIn(name, entry["undefined_symbols"])
            for name in REQUIRED_EXPORTED:
                self.assertIn(name, entry["exported_symbols"])
            self.assertEqual(manifest["wrappers"]["iphoneos"]["platform"], "IOS")
            self.assertEqual(
                manifest["wrappers"]["iphonesimulator"]["platform"], "IOSSIMULATOR"
            )
            self.assertEqual(
                manifest["builders"]["wrapper_builder"]["sha256"], sha256(WRAPPERS)
            )

    def test_macos_record_carries_the_consumer_signature_normalized_digest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-xray-normalized-") as raw:
            root = pathlib.Path(raw)
            paths = self._materialize(root)
            environment = self._env(paths)
            self._run(["write-xray-provenance"], environment)
            manifest = json.loads(paths["provenance"].read_text(encoding="utf-8"))
            macos = paths["engines"] / "macos/libWinsXrayVlessWsTransport.dylib"
            entry = manifest["wrappers"]["macosx"]
            self.assertEqual(entry["sha256"], sha256(macos))
            expected = consumer_normalized_sha256(macos, root / "consumer-scratch")
            self.assertEqual(entry["signature_normalized_sha256"], expected)
            self.assertNotEqual(expected, entry["sha256"])
            for key in ("iphoneos", "iphonesimulator"):
                self.assertNotIn("signature_normalized_sha256", manifest["wrappers"][key])

            del manifest["wrappers"]["macosx"]["signature_normalized_sha256"]
            paths["provenance"].write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            failed = self._run(["verify-xray-provenance"], environment, check=False)
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("mismatch", failed.stderr + failed.stdout)

    def test_mutate_source_after_artifact_creation_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-xray-src-") as raw:
            paths = self._materialize(pathlib.Path(raw))
            environment = self._env(paths)
            self._run(["write-xray-provenance"], environment)
            original = paths["wrapper"].read_text(encoding="utf-8")
            paths["wrapper"].write_text(original + "\n/* drifted source */\n", encoding="utf-8")
            failed = self._run(["verify-xray-provenance"], environment, check=False)
            self.assertNotEqual(failed.returncode, 0)
            combined = (failed.stderr + failed.stdout).lower()
            self.assertTrue("mismatch" in combined or "rebuild" in combined)

    def test_dylib_missing_libxray_setsockcallback_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-xray-import-") as raw:
            paths = self._materialize(pathlib.Path(raw), stub=XRAY_STUB_NO_SOCK)
            environment = self._env(paths)
            failed = self._run(["write-xray-provenance"], environment, check=False)
            self.assertNotEqual(failed.returncode, 0)
            combined = failed.stderr + failed.stdout
            self.assertIn("LibXraySetSockCallback", combined)

    def test_symbol_complete_dylib_substitution_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-xray-sub-") as raw:
            paths = self._materialize(pathlib.Path(raw))
            environment = self._env(paths)
            self._run(["write-xray-provenance"], environment)
            dylib = paths["engines"] / "macos/libWinsXrayVlessWsTransport.dylib"
            compile_xray_dylib(dylib, "macosx", "arm64", XRAY_STUB.replace(
                "int wins_xray_vless_ws_transport_contract_version(void) { return 1; }",
                "int wins_xray_vless_ws_transport_contract_version(void) { return 2; }",
                1,
            ))
            os.utime(dylib, None)
            failed = self._run(["verify-xray-provenance"], environment, check=False)
            self.assertNotEqual(failed.returncode, 0)
            combined = (failed.stderr + failed.stdout).lower()
            self.assertTrue("mismatch" in combined or "rebuild" in combined)

    def test_malformed_and_symlink_provenance_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-xray-bad-") as raw:
            paths = self._materialize(pathlib.Path(raw))
            environment = self._env(paths)
            self._run(["write-xray-provenance"], environment)
            real = paths["provenance"].with_suffix(".json.real")
            paths["provenance"].replace(real)
            paths["provenance"].symlink_to(real.name)
            linked = self._run(["verify-xray-provenance"], environment, check=False)
            self.assertNotEqual(linked.returncode, 0)
            paths["provenance"].unlink()
            paths["provenance"].write_text("{not json\n", encoding="utf-8")
            malformed = self._run(["verify-xray-provenance"], environment, check=False)
            self.assertNotEqual(malformed.returncode, 0)
            self.assertIn("invalid JSON", malformed.stderr)

    def test_duplicate_keys_bool_schema_version_and_extras_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-xray-schema-") as raw:
            paths = self._materialize(pathlib.Path(raw))
            environment = self._env(paths)
            self._run(["write-xray-provenance"], environment)
            original = paths["provenance"].read_text(encoding="utf-8")
            manifest = json.loads(original)

            paths["provenance"].write_text(
                original.replace(
                    '"schema_version": 1',
                    '"schema_version": 1,\n  "schema_version": 1',
                    1,
                ),
                encoding="utf-8",
            )
            dup = self._run(["verify-xray-provenance"], environment, check=False)
            self.assertNotEqual(dup.returncode, 0)
            self.assertIn("duplicate JSON key", dup.stderr)

            manifest["schema_version"] = True
            paths["provenance"].write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            as_bool = self._run(["verify-xray-provenance"], environment, check=False)
            self.assertNotEqual(as_bool.returncode, 0)
            combined = as_bool.stderr + as_bool.stdout
            self.assertTrue(
                "bool-as-int" in combined or "must be an integer" in combined
            )

            manifest["schema_version"] = 1
            manifest["extra_field"] = "nope"
            paths["provenance"].write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            extra = self._run(["verify-xray-provenance"], environment, check=False)
            self.assertNotEqual(extra.returncode, 0)
            self.assertIn("extra field", extra.stderr)

    def test_hardlink_and_empty_source_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-xray-empty-") as raw:
            paths = self._materialize(pathlib.Path(raw))
            environment = self._env(paths)
            paths["wrapper"].write_bytes(b"")
            failed_empty = self._run(["write-xray-provenance"], environment, check=False)
            self.assertNotEqual(failed_empty.returncode, 0)
            combined = (failed_empty.stderr + failed_empty.stdout).lower()
            self.assertTrue("empty" in combined or "nonempty" in combined)

        with tempfile.TemporaryDirectory(prefix="wins-xray-link-") as raw:
            paths = self._materialize(pathlib.Path(raw))
            environment = self._env(paths)
            os.link(paths["wrapper"], paths["source_dir"] / "hardlink.m")
            failed_link = self._run(["write-xray-provenance"], environment, check=False)
            self.assertNotEqual(failed_link.returncode, 0)
            self.assertIn("single-link", failed_link.stderr)

    def test_current_checkout_is_owner_blocked_without_fabricated_evidence(self) -> None:
        # A checkout may carry the provenance a verified rebuild published, but never the
        # gitignored wrapper dylibs it binds, so verification still refuses here and no
        # refused write may create or rewrite the committed provenance bytes.
        committed = PROVENANCE.read_bytes() if PROVENANCE.exists() else None
        failed = subprocess.run(
            ["bash", str(WRAPPERS), "verify-xray-provenance"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(failed.returncode, 0)
        combined = (failed.stderr + failed.stdout).lower()
        self.assertTrue(
            "owner-blocked" in combined
            or "rebuild" in combined
            or "missing" in combined
        )
        hashed = subprocess.run(
            ["bash", str(WRAPPERS), "write-xray-provenance"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(hashed.returncode, 0)
        self.assertIn("without a verified rebuild", hashed.stderr)
        self.assertEqual(
            PROVENANCE.read_bytes() if PROVENANCE.exists() else None,
            committed,
            "live hash-without-rebuild must not publish Xray provenance",
        )

        awg = subprocess.run(
            ["bash", str(WRAPPERS), "verify-awg-provenance"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(awg.returncode, 0)

    def test_verifier_is_ascii_and_does_not_network(self) -> None:
        text = self.source(VERIFIER)
        self.assertTrue(text.isascii())
        self.assertNotIn("github.com", text)
        self.assertNotIn("http://", text)
        self.assertNotIn("https://", text)
        self.assertIn("LibXraySetSockCallback", text)
        self.assertIn("mutating the wrapper source after artifact creation", text.lower())
        self.assertIn("mutating the wrapper source after artifact creation", self.source(SCHEMA).lower())


if __name__ == "__main__":
    unittest.main()
