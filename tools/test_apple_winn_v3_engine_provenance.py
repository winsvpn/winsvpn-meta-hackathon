#!/usr/bin/env python3
"""Fail-closed Apple Winn v3 engine provenance regressions."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
WRAPPERS = ROOT / "tools" / "build_apple_engine_wrappers.sh"
STAGING = ROOT / "tools" / "stage_apple_engine_artifacts.sh"
RELEASE = ROOT / "tools" / "build_apple_release_candidates.sh"
FREEZE = ROOT / "tools" / "release_dependency_freeze.py"
DRIVER = ROOT / "tools" / "winn_release.py"
SCHEMA = ROOT / "tools" / "apple_winn_v3_engine_provenance.schema.json"
PINS = json.loads(
    (ROOT / "tools" / "toolchain-pins.json").read_text(encoding="utf-8")
)
# Throwaway Ed25519 seeds for fixture releases. Neither is the owner key.
TEST_SEED = bytes(range(1, 33))
OTHER_SEED = bytes(range(33, 65))
RELEASE_TARGETS = {
    "datapath-ios-arm64": ("iphoneos", "arm64", "libwinn-datapath-ios-arm64"),
    "datapath-iossimulator-arm64": ("iphonesimulator", "arm64", "libwinn-datapath-iossimulator-arm64"),
    "datapath-iossimulator-amd64": ("iphonesimulator", "x86_64", "libwinn-datapath-iossimulator-amd64"),
    "datapath-archive-darwin-arm64": ("macosx", "arm64", "libwinn-datapath-darwin-arm64"),
    "datapath-archive-darwin-amd64": ("macosx", "x86_64", "libwinn-datapath-darwin-amd64"),
}

ARCHIVES = (
    (
        "libwinn-datapath-ios-arm64.a",
        "iphoneos",
        "arm64",
        "IOS",
        "iphoneos_arm64",
    ),
    (
        "libwinn-datapath-darwin-arm64.a",
        "macosx",
        "arm64",
        "MACOS",
        "macosx_arm64",
    ),
    (
        "libwinn-datapath-darwin-amd64.a",
        "macosx",
        "x86_64",
        "MACOS",
        "macosx_x86_64",
    ),
    (
        "libwinn-datapath-iossimulator-arm64.a",
        "iphonesimulator",
        "arm64",
        "IOSSIMULATOR",
        "iphonesimulator_arm64",
    ),
    (
        "libwinn-datapath-iossimulator-amd64.a",
        "iphonesimulator",
        "x86_64",
        "IOSSIMULATOR",
        "iphonesimulator_x86_64",
    ),
)
WRAPPERS_RELATIVE = (
    (
        "ios/iphoneos/libWinsWinnPacketEngine.dylib",
        "iphoneos",
        ("arm64",),
        "IOS",
        "iphoneos",
    ),
    (
        "ios/iphonesimulator/libWinsWinnPacketEngine.dylib",
        "iphonesimulator",
        ("arm64", "x86_64"),
        "IOSSIMULATOR",
        "iphonesimulator",
    ),
    (
        "macos/libWinsWinnPacketEngine.dylib",
        "macosx",
        ("arm64", "x86_64"),
        "MACOS",
        "macosx",
    ),
)
TRIPLES = {
    ("macosx", "arm64"): "arm64-apple-macos13.0",
    ("macosx", "x86_64"): "x86_64-apple-macos13.0",
    ("iphoneos", "arm64"): "arm64-apple-ios13.0",
    ("iphonesimulator", "arm64"): "arm64-apple-ios14.0-simulator",
    ("iphonesimulator", "x86_64"): "x86_64-apple-ios13.0-simulator",
}
WINN_EXPORTS = (
    "wins_winn_packet_engine_contract_version",
    "wins_winn_packet_engine_create",
    "wins_winn_packet_engine_start",
    "wins_winn_packet_engine_stop",
    "wins_winn_packet_engine_destroy",
    "wins_winn_packet_engine_awg_seam_port",
    "wins_winn_packet_engine_seam_stats",
    "wins_winn_packet_engine_status_json",
    "WinnTunnelFreeString",
    "WinnTunnelContractVersion",
    "WinnTunnelProtocolVersion",
    "WinnTunnelMaxDatagram",
    "WinnTunnelCreate",
    "WinnTunnelCreateWithCarrier",
    "WinnTunnelCreateWinn3",
    "WinnTunnelWriteInbound",
    "WinnTunnelReadOutbound",
    "WinnTunnelStatusJSON",
    "WinnTunnelClose",
)


# Strings from the dropped retained-producer gate. None of them may remain in
# the Apple wrapper builder or the staging script.
RETIRED_WINN_GATE = (
    "/Library/WinsVPN/ReleaseWinnProtocolAuthority",
    "wins_release_go_run",
    "WINS_RELEASE_GO",
    "WINS_RETAINED_BUILDER",
    "WINN_ARCHIVE_BUILDER_SHA256",
    "WINN_CONFORMANCE_VERIFIER_SHA256",
    "authorization_sha256",
    "consumption-ledger",
    "producer_execution_sha256",
    'source "${PROJECT_ROOT}/tools/build_winn_protocol_engine.sh"',
)


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


def _validate_schema_instance(
    instance: object,
    schema: dict[str, object],
    node: dict[str, object],
) -> None:
    reference = node.get("$ref")
    if reference is not None:
        name = str(reference).rsplit("/", 1)[-1]
        node = schema["$defs"][name]  # type: ignore[index]
    for subschema in node.get("allOf", []):  # type: ignore[union-attr]
        _validate_schema_instance(instance, schema, subschema)
    expected_type = node.get("type")
    if expected_type == "object":
        if type(instance) is not dict:
            raise ValueError("not an object")
        for key in node.get("required", []):
            if key not in instance:
                raise ValueError(f"missing {key}")
        properties = node.get("properties", {})
        for key, value in instance.items():
            if key in properties:
                _validate_schema_instance(value, schema, properties[key])
            elif node.get("additionalProperties", True) is False:
                raise ValueError(f"extra {key}")
    elif expected_type == "array":
        if type(instance) is not list:
            raise ValueError("not an array")
        for item in instance:
            if "items" in node:
                _validate_schema_instance(item, schema, node["items"])
    elif expected_type == "string" and type(instance) is not str:
        raise ValueError("not a string")
    elif expected_type == "integer" and type(instance) is not int:
        raise ValueError("not an integer")
    if "const" in node and (
        instance != node["const"] or type(instance) is not type(node["const"])
    ):
        raise ValueError("const mismatch")
    if "enum" in node and instance not in node["enum"]:
        raise ValueError("enum mismatch")


def load_freeze():
    spec = importlib.util.spec_from_file_location("release_dependency_freeze", FREEZE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _clang() -> str:
    return subprocess.check_output(["xcrun", "-f", "clang"], text=True).strip()


def _sdk(name: str) -> str:
    return subprocess.check_output(
        ["xcrun", "--sdk", name, "--show-sdk-path"], text=True
    ).strip()


def _compile_object(
    path: pathlib.Path, platform_name: str, arch: str, marker: str
) -> None:
    src = path.with_suffix(".c")
    obj = path.with_suffix(".o")
    src.write_text(f"int {marker}(void) {{ return {len(marker)}; }}\n", encoding="utf-8")
    completed = subprocess.run(
        [
            _clang(),
            "-c",
            "-target",
            TRIPLES[(platform_name, arch)],
            "-isysroot",
            _sdk(platform_name),
            str(src),
            "-o",
            str(obj),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    src.unlink(missing_ok=True)
    if completed.returncode != 0:
        raise AssertionError(
            f"clang -c failed for {path}: {completed.stderr or completed.stdout}"
        )
    subprocess.run(["/usr/bin/ar", "rcs", str(path), str(obj)], check=True)
    obj.unlink(missing_ok=True)


def _compile_dylib(
    path: pathlib.Path,
    platform_name: str,
    arch: str,
    marker: str,
    *,
    exports: tuple[str, ...] | None = None,
    strip: bool = True,
    target: str | None = None,
    install_name: str = "@rpath/WinsWinnPacketEngine.framework/WinsWinnPacketEngine",
    link_mode: str = "-dynamiclib",
    extra_linker_args: tuple[str, ...] = (),
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    src = path.with_suffix(".c")
    declarations = [
        f'__attribute__((visibility("default"))) void {symbol}(void) {{}}'
        for symbol in (WINN_EXPORTS if exports is None else exports)
    ]
    declarations.insert(0, f"static int {marker}_local(void) {{ return {len(marker)}; }}")
    declarations.append(
        f'__attribute__((visibility("default"))) int {marker}(void) {{ return {marker}_local(); }}'
    )
    src.write_text("\n".join(declarations) + "\n", encoding="utf-8")
    completed = subprocess.run(
        [
            _clang(),
            link_mode,
            "-target",
            target or TRIPLES[(platform_name, arch)],
            "-isysroot",
            _sdk(platform_name),
            *(
                [f"-Wl,-install_name,{install_name}"]
                if link_mode == "-dynamiclib"
                else []
            ),
            *extra_linker_args,
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
    if strip:
        subprocess.run(["xcrun", "strip", "-x", str(path)], check=True)


def _lipo_archs(path: pathlib.Path) -> list[str]:
    text = subprocess.check_output(["/usr/bin/lipo", "-archs", str(path)], text=True)
    return sorted(item for item in text.split() if item)


def load_driver():
    spec = importlib.util.spec_from_file_location("winn_release_fixture_driver", DRIVER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def public_key(seed: bytes = TEST_SEED) -> str:
    return load_driver().ed25519_public(seed).hex()


def write_manifest(release: pathlib.Path, manifest: dict, seed: bytes | None = TEST_SEED) -> None:
    """Write a canonical manifest and, when seed is given, sign it."""
    driver = load_driver()
    payload = driver.canonical_json(manifest)
    manifest_path = release / "manifest.json"
    signature_path = release / "manifest.sig.json"
    for path in (manifest_path, signature_path):
        if path.exists():
            path.chmod(0o644)
            path.unlink()
    manifest_path.write_bytes(payload)
    if seed is None:
        return
    signature = driver.ed25519_sign(seed, driver.SIGNATURE_DOMAIN + payload)
    signature_path.write_bytes(
        driver.canonical_json(
            {
                "algorithm": "ed25519",
                "contract": driver.SIGNATURE_CONTRACT,
                "manifest_sha256": hashlib.sha256(payload).hexdigest(),
                "public_key": driver.ed25519_public(seed).hex(),
                "signature": signature.hex(),
            }
        )
    )


def make_release(release: pathlib.Path, seed: bytes | None = TEST_SEED) -> dict:
    """A release directory in the driver's layout holding the five Apple slices.

    The archives are small real Mach-O ar archives of the right platform and
    architecture, so every Mach-O gate downstream sees genuine metadata.
    """
    artifacts = []
    for target, (platform_name, arch, _stem) in RELEASE_TARGETS.items():
        directory = release / "artifacts" / target
        directory.mkdir(parents=True)
        archive = directory / "libwinn-datapath.a"
        header = directory / "libwinn-datapath.h"
        _compile_object(archive, platform_name, arch, "winn_" + target.replace("-", "_"))
        header.write_text(f"/* {target} generated header */\n", encoding="utf-8")
        digest = sha256(archive)
        artifacts.append(
            {
                "build_a_sha256": digest,
                "build_b_sha256": digest,
                "header_path": f"artifacts/{target}/libwinn-datapath.h",
                "header_sha256": sha256(header),
                "path": f"artifacts/{target}/libwinn-datapath.a",
                "sha256": digest,
                "size": archive.stat().st_size,
                "target": target,
            }
        )
    manifest = {
        "artifacts": artifacts,
        "contract": "winsvpn-winn-release-manifest-v1",
        "producer": {
            "build_winn_protocol_engine.sh": "1" * 64,
            "toolchain-pins.json": "3" * 64,
            "winn_release.py": "2" * 64,
        },
        "source": {
            "binding": "export",
            "commit": "260da56",
            "path": "winn_protocol_experimental",
            "tree_sha256": "4" * 64,
        },
        "toolchains": {
            "go": {
                "archive_sha256": PINS["tools"]["go"]["archive_sha256"]["darwin_arm64"],
                "executable_sha256": PINS["tools"]["go"]["executable_sha256"],
                "install_tree_sha256": "6" * 64,
                "version": PINS["tools"]["go"]["version"],
            }
        },
    }
    write_manifest(release, manifest, seed)
    return manifest


def run_wrappers(
    args: list[str], environment: dict[str, str], check: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(WRAPPERS), *args],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=check,
        timeout=300,
    )


def release_env(**extra: str) -> dict[str, str]:
    environment = os.environ.copy()
    for name in (
        "WINS_WINN_RELEASE_DIR",
        "WINS_APPLE_WINN3_RELEASE",
        "WINS_WINN_TRUST_PUBLIC_KEY",
        "APPLE_ENGINE_ARTIFACTS_DIR",
        "APPLE_ENGINE_WRAPPER_ARCHS",
    ):
        environment.pop(name, None)
    environment["PROJECT_ROOT"] = str(ROOT)
    environment.update(extra)
    return environment


def release_facts(stdout: str) -> dict:
    body, _, _tail = stdout.rpartition("APPLE WINN RELEASE: ACCEPTED")
    return json.loads(body)


class AppleWinnV3EngineProvenanceTests(unittest.TestCase):
    def source(self, path: pathlib.Path) -> str:
        return path.read_text(encoding="utf-8")

    def test_schema_is_distinct_from_awg_and_binds_required_inputs(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        self.assertEqual(
            schema["properties"]["component"]["const"],
            "winn-apple-engine-wrappers",
        )
        self.assertNotIn("amneziawg", json.dumps(schema))
        self.assertEqual(schema["properties"]["schema_version"]["type"], "integer")
        self.assertEqual(schema["properties"]["schema_version"]["const"], 5)
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            set(schema["required"]),
            {
                "archives",
                "apple_toolchain",
                "builders",
                "component",
                "generation",
                "release",
                "role_binding",
                "schema_version",
                "source",
                "wrappers",
            },
        )
        for retired in ("transaction", "go_toolchain"):
            self.assertNotIn(retired, schema["properties"])
        for retired in ("authorization_binding", "candidate_binding", "source_freeze_binding"):
            self.assertNotIn(retired, schema["$defs"])
        self.assertEqual(
            set(schema["properties"]["source"]["required"]),
            {"module", "wrapper_path", "wrapper_sha256"},
        )
        self.assertEqual(
            schema["properties"]["source"]["properties"]["module"]["const"],
            "winsvpn.local/winnprotocol",
        )
        release = schema["properties"]["release"]
        self.assertFalse(release["additionalProperties"])
        self.assertEqual(
            set(release["required"]),
            {
                "contract",
                "go",
                "manifest_sha256",
                "producer",
                "signature_public_key",
                "signature_state",
                "source",
            },
        )
        self.assertEqual(
            release["properties"]["contract"]["const"], "winsvpn-winn-release-manifest-v1"
        )
        self.assertEqual(
            release["properties"]["signature_state"]["enum"], ["signed", "unsigned-dev"]
        )
        self.assertEqual(
            set(release["properties"]["go"]["required"]),
            {"archive_sha256", "executable_sha256", "install_tree_sha256", "version"},
        )
        self.assertEqual(
            set(release["properties"]["producer"]["required"]),
            {"builder_sha256", "driver_sha256", "toolchain_pins_sha256"},
        )
        self.assertEqual(
            set(schema["properties"]["archives"]["required"]),
            {
                "iphoneos_arm64",
                "iphonesimulator_arm64",
                "iphonesimulator_x86_64",
                "macosx_arm64",
                "macosx_x86_64",
            },
        )
        self.assertEqual(
            set(schema["properties"]["wrappers"]["required"]),
            {"iphoneos", "iphonesimulator", "macosx"},
        )
        self.assertEqual(
            set(schema["properties"]["builders"]["required"]),
            {"wrapper_builder", "wrapper_header"},
        )
        self.assertEqual(
            set(schema["$defs"]["archive_record"]["required"]),
            {
                "architectures",
                "build_a_sha256",
                "build_b_sha256",
                "filetype",
                "header_path",
                "header_sha256",
                "path",
                "platform",
                "sha256",
                "target",
            },
        )
        self.assertEqual(
            sorted(schema["$defs"]["archive_record"]["properties"]["target"]["enum"]),
            sorted(RELEASE_TARGETS),
        )
        self.assertEqual(
            schema["$defs"]["archive_record"]["properties"]["filetype"]["enum"],
            ["ar-archive", "mach-o-archive"],
        )
        self.assertEqual(
            set(schema["$defs"]["wrapper_record"]["required"]),
            {
                "architectures",
                "filetype",
                "path",
                "platform",
                "roles",
                "sha256",
                "slices",
                "strip_state",
            },
        )
        self.assertEqual(
            schema["$defs"]["wrapper_record"]["properties"]["filetype"]["const"],
            "mach-o-dylib",
        )
        self.assertFalse(schema["$defs"]["archive_record"]["additionalProperties"])
        self.assertFalse(schema["$defs"]["wrapper_record"]["additionalProperties"])
        self.assertEqual(
            set(schema["$defs"]["dylib_slice"]["required"]),
            {
                "architecture",
                "dependencies",
                "filetype",
                "install_name",
                "minos",
                "platform",
                "role_symbols",
                "uuid",
            },
        )
        self.assertEqual(
            schema["properties"]["wrappers"]["properties"]["iphoneos"]["$ref"],
            "#/$defs/iphoneos_wrapper_record",
        )
        self.assertEqual(
            schema["properties"]["wrappers"]["properties"]["macosx"]["$ref"],
            "#/$defs/macosx_wrapper_record",
        )

    def test_schema_rejects_hostile_missing_thin_and_extra_slice_closures(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

        def slice_record(architecture: str, platform_name: str, minos: str) -> dict[str, object]:
            return {
                "architecture": architecture,
                "dependencies": ["/usr/lib/libSystem.B.dylib"],
                "filetype": "MH_DYLIB",
                "install_name": "@rpath/WinsWinnPacketEngine.framework/WinsWinnPacketEngine",
                "minos": minos,
                "platform": platform_name,
                "role_symbols": {
                    "core": ["WinnTunnelCreateWinn3"],
                    "relay": ["WinnTunnelCreate", "WinnTunnelCreateWithCarrier"],
                },
                "uuid": "11111111-1111-1111-1111-111111111111",
            }

        def wrapper(
            architectures: list[str], platform_name: str, slices: dict[str, object]
        ) -> dict[str, object]:
            return {
                "architectures": architectures,
                "filetype": "mach-o-dylib",
                "path": "fixture/libWinsWinnPacketEngine.dylib",
                "platform": platform_name,
                "roles": ["core", "relay"],
                "sha256": "0" * 64,
                "slices": slices,
                "strip_state": "stripped",
            }

        macos = wrapper(
            ["arm64", "x86_64"],
            "MACOS",
            {
                "arm64": slice_record("arm64", "MACOS", "13.0"),
                "x86_64": slice_record("x86_64", "MACOS", "13.0"),
            },
        )
        iphoneos = wrapper(
            ["arm64"],
            "IOS",
            {"arm64": slice_record("arm64", "IOS", "13.0")},
        )
        _validate_schema_instance(macos, schema, schema["$defs"]["macosx_wrapper_record"])
        _validate_schema_instance(
            iphoneos, schema, schema["$defs"]["iphoneos_wrapper_record"]
        )

        missing = json.loads(json.dumps(macos))
        del missing["slices"]["x86_64"]
        with self.assertRaisesRegex(ValueError, "missing x86_64"):
            _validate_schema_instance(
                missing, schema, schema["$defs"]["macosx_wrapper_record"]
            )

        thin = json.loads(json.dumps(macos))
        thin["architectures"] = ["arm64"]
        with self.assertRaisesRegex(ValueError, "const mismatch"):
            _validate_schema_instance(
                thin, schema, schema["$defs"]["macosx_wrapper_record"]
            )

        extra = json.loads(json.dumps(iphoneos))
        extra["slices"]["x86_64"] = slice_record("x86_64", "IOS", "13.0")
        with self.assertRaisesRegex(ValueError, "extra x86_64"):
            _validate_schema_instance(
                extra, schema, schema["$defs"]["iphoneos_wrapper_record"]
            )

    def test_release_path_replaces_the_retained_producer_gate(self) -> None:
        wrappers = self.source(WRAPPERS)
        staging = self.source(STAGING)
        for needle in RETIRED_WINN_GATE:
            self.assertNotIn(needle, wrappers, needle)
            self.assertNotIn(needle, staging, needle)

        # The driver and its pinned key are resolved beside the script, the
        # release is verified once with `verify --print-manifest`, and every
        # Apple slice digest comes from the manifest bytes it printed.
        self.assertIn(
            'WINN_RELEASE_DRIVER="${WINS_WRAPPER_TOOLS_DIR}/winn_release.py"', wrappers
        )
        self.assertIn('WINN_RELEASE_PYTHON="/usr/bin/python3"', wrappers)
        acquire = wrappers.split("acquire_winn_release() {", 1)[1].split(
            "\nbuild_winn_dev_release() {", 1
        )[0]
        for needle in (
            '"verify", "--release"',
            'command.append("--print-manifest")',
            "manifest_bytes = completed.stdout",
            "--allow-unsigned",
            "--trust-public-key",
            "build_a == build_b == sha256",
            "TOOLCHAIN-MISSING",
            "O_NOFOLLOW",
            "O_EXCL",
        ):
            self.assertIn(needle, acquire, needle)
        # The release directory's manifest and signature files are never read
        # by the wrapper itself; only the driver reads them, once.
        self.assertNotIn('release / "manifest.json"', acquire)
        self.assertNotIn('release / "manifest.sig.json"', acquire)
        self.assertNotIn('"--print-artifact"', acquire)
        self.assertEqual(acquire.count("subprocess.run("), 1)
        for target in RELEASE_TARGETS:
            self.assertIn(f'"{target}:', wrappers)
        dev = wrappers.split("build_winn_dev_release() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn("build --set apple --out", dev)
        self.assertIn("UNSIGNED DEV BUILD", dev)

        transaction = wrappers.split("build_winn_release_transaction() (", 1)[1].split(
            "\n)\n", 1
        )[0]
        order = [
            transaction.index("acquire_winn_release"),
            transaction.index("verify_winn_abi"),
            transaction.index("build_winn_platform macosx"),
            transaction.index("write_winn_provenance"),
            transaction.index("publish_winn_transaction_file"),
        ]
        self.assertEqual(order, sorted(order))
        abi = wrappers.split("verify_winn_abi() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn("WINN_ABI_SKIP_BUILD=1", abi)
        self.assertIn("iphonesimulator:x86_64:13.0", abi)

        inputs = wrappers.split("apple_require_exact_winn_release_inputs() {", 1)[1].split(
            "\n}\n", 1
        )[0]
        self.assertIn("APPLE_ENGINE_ARTIFACTS_DIR reuse is forbidden", inputs)
        self.assertIn("exact declared universal architecture sets", inputs)
        self.assertIn("Release mode requires a signed Winn release directory", inputs)
        self.assertIn("Release mode never accepts an unsigned Winn release", inputs)
        self.assertIn("WINS_WINN_TRUST_PUBLIC_KEY is refused", inputs)

        # Every existing Mach-O gate on the wrapper candidate is still present.
        platform_pass = wrappers.split("build_winn_platform() {", 1)[1].split("\n}\n", 1)[0]
        for gate in (
            "strip_and_validate_dylib",
            "require_platform",
            "require_minimum_os",
            "require_archs",
            "require_install_name",
            "WINN_REQUIRED_SYMBOLS",
            "WINN_CORE_REQUIRED_SYMBOLS",
        ):
            self.assertIn(gate, platform_pass)

        self.assertIn("apple_winn_v3_provenance_sha256", staging)
        self.assertIn("verify_and_stage_winn_provenance", staging)
        self.assertIn("WINS_APPLE_ENGINE_TRANSACTION_PROVENANCE_SHA256", staging)
        self.assertIn("dest_bytes = stable_read", staging)
        self.assertIn("destination Winn dylib", staging)
        self.assertIn("staged destination bytes do not match the source artifact", staging)
        self.assertIn("requires a signed Winn release", staging)
        self.assertIn("pinned release authority key", staging)
        self.assertIn("winn_release_authority.json", staging)
        self.assertIn("verify-winn-provenance", staging)
        self.assertIn("WINS_WINN_RELEASE_DIR", staging)

        freeze = load_freeze()
        for platform_name in ("macos", "ios"):
            self.assertIn("winn_protocol_experimental", freeze.PLATFORM_ROOTS[platform_name])
            self.assertIn(
                "apple/EngineArtifacts/apple_winn_v3_engine_provenance.json",
                freeze.PLATFORM_NATIVE_EXTRA_PATHS[platform_name],
            )

    def test_hash_helpers_fail_closed_under_bash_32(self) -> None:
        wrappers = self.source(WRAPPERS)
        staging = self.source(STAGING)
        for text, label in ((wrappers, "wrappers"), (staging, "staging")):
            self.assertNotRegex(
                text,
                r"local [A-Za-z_][A-Za-z0-9_]*=\"\$\((wins_sha256|digest_of|shasum)",
                f"{label} must not assign hash helpers in the same local statement",
            )
        self.assertIn('published_sha="$(wins_sha256', wrappers)
        self.assertIn("|| die", wrappers.split('published_sha="$(wins_sha256', 1)[1][:180])
        self.assertIn('dest_sha="$(wins_sha256 "${dest_executable}")"', staging)
        self.assertIn(
            "|| die",
            staging.split('dest_sha="$(wins_sha256 "${dest_executable}")"', 1)[1][:180],
        )

    def test_exclusive_randomized_publication_and_nofollow_snapshots(self) -> None:
        wrappers = self.source(WRAPPERS)
        winn_py = wrappers.split("run_winn_provenance_tool() {", 1)[1].split(
            "verify_winn_provenance() {", 1
        )[0]
        self.assertIn("secrets.token_hex(16)", winn_py)
        self.assertIn("O_EXCL", winn_py)
        self.assertIn("O_NOFOLLOW", winn_py)
        self.assertIn("st_nlink != 1", winn_py)
        self.assertNotIn('str(output) + ".tmp"', winn_py)
        self.assertNotIn('".tmp"', winn_py.replace("tempfile.mkdtemp", ""))
        self.assertIn("stable_snapshot_file", wrappers)
        self.assertIn("O_NOFOLLOW is required for Apple engine snapshots", wrappers)
        self.assertIn("Refusing a thin substitute", wrappers)
        self.assertIn('"${kind}" != *[Uu]niversal*', wrappers)
        staging = self.source(STAGING)
        self.assertIn("thin engines are refused", staging)
        self.assertIn("inspect_dylib_slice", staging)

    def test_staged_manifest_binds_winn_archives_from_the_verified_root(self) -> None:
        # R11a: the Xcode staging phase verified the Winn archives under
        # tools/winn_conformance_build_out but the manifest writer reopened them
        # beside apple/EngineArtifacts/apple_winn_v3_engine_provenance.json,
        # so every iOS build failed with FileNotFoundError.
        staging = STAGING.read_text(encoding="utf-8")
        root = '${WINN_DATAPATH_ARCHIVE_DIR:-${APPLE_ENGINE_ARTIFACTS_DIR:-${PROJECT_ROOT}/tools/winn_conformance_build_out}}'
        self.assertIn(f'archive_root="{root}"', staging)
        writer = staging.split('"${dest_dir}/apple_engine_artifacts_manifest.json"', 1)[1].split("\nPY\n", 1)[0]
        self.assertIn(f'"${{WINS_REQUIRE_APPLE_ENGINE}}" "{root}" "$(destination_directory)"', writer)
        self.assertIn("winn_archive_root = pathlib.Path(sys.argv[16])", writer)
        self.assertNotIn("pathlib.Path(source_provenance_paths[2]).parent", writer)

    def test_staged_manifest_finds_macos_frameworks_beside_resources(self) -> None:
        # R11a: on macOS the manifest is written to Contents/Resources but the
        # engines are staged in Contents/Frameworks; the writer looked in
        # Contents/Resources/Frameworks and every macOS build failed.
        staging = STAGING.read_text(encoding="utf-8")
        writer = staging.split('"${dest_dir}/apple_engine_artifacts_manifest.json"', 1)[1].split("\nPY\n", 1)[0]
        self.assertIn('"$(destination_directory)" "${staged_components[@]}" <<\'PY\'', writer)
        self.assertIn("staged_framework_root = pathlib.Path(sys.argv[17])", writer)
        self.assertIn("staged = sys.argv[18:]", writer)
        self.assertIn("framework_root = staged_framework_root", writer)
        self.assertNotIn('framework_root = resource_dir / "Frameworks"', writer)

    def test_shell_syntax(self) -> None:
        for script in (WRAPPERS, STAGING, RELEASE):
            subprocess.run(["bash", "-n", str(script)], cwd=ROOT, check=True)

    def test_hostile_release_environment_and_reuse_are_refused(self) -> None:
        for name, value in {
            "GOFLAGS": "-mod=mod",
            "GOWORK": "/tmp/hostile.go.work",
            "GOPROXY": "https://hostile.invalid",
            "GOSUMDB": "off.example.invalid",
            "GOEXPERIMENT": "arenas",
        }.items():
            environment = release_env(**{name: value})
            failed = run_wrappers(["winn"], environment, check=False)
            self.assertNotEqual(failed.returncode, 0, name)
            self.assertIn(f"hostile {name}", failed.stderr)
        reused = run_wrappers(
            ["winn"],
            release_env(APPLE_ENGINE_ARTIFACTS_DIR="/tmp/reused-apple-engines"),
            check=False,
        )
        self.assertNotEqual(reused.returncode, 0)
        self.assertIn("APPLE_ENGINE_ARTIFACTS_DIR reuse is forbidden", reused.stderr)
        narrowed = run_wrappers(
            ["winn"], release_env(APPLE_ENGINE_WRAPPER_ARCHS="arm64"), check=False
        )
        self.assertNotEqual(narrowed.returncode, 0)
        self.assertIn("exact declared universal architecture sets", narrowed.stderr)

    # Release acquisition through the real tools/winn_release.py verifier.

    def test_signed_release_is_accepted_only_for_the_trusted_key(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-winn-rel-signed-") as raw:
            release = pathlib.Path(raw) / "release"
            manifest = make_release(release)
            trusted = release_env(WINS_WINN_TRUST_PUBLIC_KEY=public_key())
            accepted = run_wrappers(["verify-winn-release", "--release", str(release)], trusted)
            facts = release_facts(accepted.stdout)
            record = facts["release"]
            self.assertEqual(record["signature_state"], "signed")
            self.assertEqual(record["signature_public_key"], public_key())
            self.assertEqual(
                record["manifest_sha256"], sha256(release / "manifest.json")
            )
            self.assertEqual(record["producer"]["builder_sha256"], "1" * 64)
            self.assertEqual(record["producer"]["driver_sha256"], "2" * 64)
            self.assertEqual(record["source"]["commit"], "260da56")
            self.assertEqual(set(facts["archives"]), {key for *_, key in ARCHIVES})
            by_target = {entry["target"]: entry for entry in manifest["artifacts"]}
            for entry in facts["archives"].values():
                self.assertEqual(entry["sha256"], by_target[entry["target"]]["sha256"])
                self.assertEqual(entry["build_a_sha256"], entry["sha256"])

            # Without the test-key override only the pinned owner key is trusted.
            pinned = run_wrappers(
                ["verify-winn-release", "--release", str(release)], release_env(), check=False
            )
            self.assertNotEqual(pinned.returncode, 0)
            self.assertIn("not the trusted release authority", pinned.stderr)

            other = run_wrappers(
                ["verify-winn-release", "--release", str(release)],
                release_env(WINS_WINN_TRUST_PUBLIC_KEY=public_key(OTHER_SEED)),
                check=False,
            )
            self.assertNotEqual(other.returncode, 0)

            # Release mode refuses the test-key override outright.
            release_mode = run_wrappers(
                ["verify-winn-release", "--release", str(release)],
                release_env(
                    WINS_WINN_TRUST_PUBLIC_KEY=public_key(), WINS_APPLE_WINN3_RELEASE="1"
                ),
                check=False,
            )
            self.assertNotEqual(release_mode.returncode, 0)
            self.assertIn("WINS_WINN_TRUST_PUBLIC_KEY is refused", release_mode.stderr)

    def test_unsigned_release_is_dev_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-winn-rel-unsigned-") as raw:
            release = pathlib.Path(raw) / "release"
            make_release(release, seed=None)
            refused = run_wrappers(
                ["verify-winn-release", "--release", str(release)],
                release_env(WINS_WINN_TRUST_PUBLIC_KEY=public_key()),
                check=False,
            )
            self.assertNotEqual(refused.returncode, 0)
            dev = run_wrappers(
                ["verify-winn-release", "--release", str(release), "--allow-unsigned"],
                release_env(),
            )
            record = release_facts(dev.stdout)["release"]
            self.assertEqual(record["signature_state"], "unsigned-dev")
            self.assertEqual(record["signature_public_key"], "")
            self.assertIn("UNSIGNED: dev use only", dev.stderr)
            release_mode = run_wrappers(
                ["verify-winn-release", "--release", str(release), "--allow-unsigned"],
                release_env(WINS_APPLE_WINN3_RELEASE="1"),
                check=False,
            )
            self.assertNotEqual(release_mode.returncode, 0)
            self.assertIn("never accepts an unsigned Winn release", release_mode.stderr)
            no_release = run_wrappers(
                ["winn"], release_env(WINS_APPLE_WINN3_RELEASE="1"), check=False
            )
            self.assertNotEqual(no_release.returncode, 0)
            self.assertIn("requires a signed Winn release directory", no_release.stderr)

    def test_tampered_or_irreproducible_releases_are_refused(self) -> None:
        trusted = release_env(WINS_WINN_TRUST_PUBLIC_KEY=public_key())
        with tempfile.TemporaryDirectory(prefix="wins-winn-rel-tamper-") as raw:
            release = pathlib.Path(raw) / "release"
            manifest = make_release(release)
            archive = release / "artifacts" / "datapath-archive-darwin-amd64" / "libwinn-datapath.a"
            original = archive.read_bytes()
            archive.write_bytes(original + b"\0")
            changed = run_wrappers(
                ["verify-winn-release", "--release", str(release)], trusted, check=False
            )
            self.assertNotEqual(changed.returncode, 0)
            archive.write_bytes(original)

            header = release / "artifacts" / "datapath-ios-arm64" / "libwinn-datapath.h"
            header_original = header.read_bytes()
            header.write_bytes(header_original + b"/* drift */\n")
            header_changed = run_wrappers(
                ["verify-winn-release", "--release", str(release)], trusted, check=False
            )
            self.assertNotEqual(header_changed.returncode, 0)
            header.write_bytes(header_original)

            # A correctly signed manifest whose two builds disagree is refused.
            split = json.loads(json.dumps(manifest))
            split["artifacts"][0]["build_b_sha256"] = "f" * 64
            write_manifest(release, split)
            irreproducible = run_wrappers(
                ["verify-winn-release", "--release", str(release)], trusted, check=False
            )
            self.assertNotEqual(irreproducible.returncode, 0)

            # A signed manifest that omits an Apple slice is refused.
            partial = json.loads(json.dumps(manifest))
            partial["artifacts"] = [
                entry for entry in partial["artifacts"]
                if entry["target"] != "datapath-iossimulator-amd64"
            ]
            write_manifest(release, partial)
            missing = run_wrappers(
                ["verify-winn-release", "--release", str(release)], trusted, check=False
            )
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn("datapath-iossimulator-amd64", missing.stderr)

            # A symbolic artifact is refused even when its bytes match.
            write_manifest(release, manifest)
            outside = pathlib.Path(raw) / "outside.a"
            outside.write_bytes(original)
            archive.unlink()
            archive.symlink_to(outside)
            linked = run_wrappers(
                ["verify-winn-release", "--release", str(release)], trusted, check=False
            )
            self.assertNotEqual(linked.returncode, 0)

            # A signature over different bytes is refused.
            archive.unlink()
            archive.write_bytes(original)
            write_manifest(release, manifest)
            signature = release / "manifest.sig.json"
            document = json.loads(signature.read_text(encoding="ascii"))
            document["manifest_sha256"] = "0" * 64
            signature.write_text(json.dumps(document), encoding="ascii")
            forged = run_wrappers(
                ["verify-winn-release", "--release", str(release)], trusted, check=False
            )
            self.assertNotEqual(forged.returncode, 0)

    def test_slices_are_bound_to_the_verified_manifest_only(self) -> None:
        # The real driver verifies a genuinely signed release; before and after
        # that read the directory holds a changed slice and a manifest naming
        # it. Digests read from the directory outside verification accept it.
        sys.path.insert(0, str(ROOT / "tools"))
        import winn_release_testkit as testkit

        with tempfile.TemporaryDirectory(prefix="wins-winn-rel-race-") as raw:
            base = pathlib.Path(raw)
            genuine = base / "genuine"
            manifest = make_release(genuine)
            attacker = base / "attacker"
            shutil.copytree(genuine, attacker)
            target = "datapath-archive-darwin-arm64"
            archive = attacker / "artifacts" / target / "libwinn-datapath.a"
            archive.write_bytes(archive.read_bytes() + b"\0" * 8)
            forged = json.loads(json.dumps(manifest))
            for entry in forged["artifacts"]:
                if entry["target"] == target:
                    digest = sha256(archive)
                    entry.update(sha256=digest, build_a_sha256=digest, build_b_sha256=digest,
                                 size=archive.stat().st_size)
            write_manifest(attacker, forged, seed=None)
            payload = (attacker / "manifest.json").read_bytes()
            (attacker / "manifest.sig.json").write_text(json.dumps({
                "algorithm": "ed25519", "contract": "winsvpn-winn-release-signature-v1",
                "manifest_sha256": hashlib.sha256(payload).hexdigest(),
                "public_key": public_key(), "signature": "00" * 64,
            }), encoding="ascii")
            release = base / "release"
            shutil.copytree(attacker, release)
            tools = base / "tools"
            tools.mkdir()
            shutil.copy2(WRAPPERS, tools / WRAPPERS.name)
            testkit.install_racing_driver(tools, seed=TEST_SEED)
            environment = release_env(**testkit.race_environment(genuine, attacker))
            raced = subprocess.run(
                ["bash", str(tools / WRAPPERS.name), "verify-winn-release", "--release", str(release)],
                cwd=ROOT, env=environment, text=True, capture_output=True, check=False, timeout=300,
            )
            self.assertNotEqual(raced.returncode, 0, raced.stdout + raced.stderr)
            self.assertIn("archive bytes do not match the verified release manifest", raced.stderr)
            self.assertNotIn("APPLE WINN RELEASE: ACCEPTED", raced.stdout)

    def test_toolchain_missing_exit_code_is_preserved(self) -> None:
        wrappers = self.source(WRAPPERS)
        acquire = wrappers.split("acquire_winn_release() {", 1)[1].split(
            "\nbuild_winn_dev_release() {", 1
        )[0]
        self.assertIn("if completed.returncode == 3:", acquire)
        self.assertIn('fail("TOOLCHAIN-MISSING while verifying the release", 3)', acquire)
        for function in ("build_winn_release_transaction() (", "verify_winn_release_binding() (", "build_winn_dev_release() {"):
            body = wrappers.split(function, 1)[1][:6000]
            self.assertIn("exit 3", body, function)

    # Provenance written from an accepted release.

    def _materialize(self, root: pathlib.Path) -> dict[str, pathlib.Path]:
        release = root / "release"
        archives = root / "archives"
        engines = root / "engines"
        provenance = engines / "apple_winn_v3_engine_provenance.json"
        facts = root / "release-facts.json"
        archives.mkdir()
        make_release(release)
        accepted = run_wrappers(
            ["verify-winn-release", "--release", str(release)],
            release_env(WINS_WINN_TRUST_PUBLIC_KEY=public_key()),
        )
        facts.write_text(
            json.dumps(release_facts(accepted.stdout), indent=2, sort_keys=True) + "\n",
            encoding="ascii",
        )
        for target, (_platform, _arch, stem) in RELEASE_TARGETS.items():
            shutil.copyfile(release / "artifacts" / target / "libwinn-datapath.a", archives / f"{stem}.a")
            shutil.copyfile(release / "artifacts" / target / "libwinn-datapath.h", archives / f"{stem}.h")
        slices_root = engines / ".slices"
        for relative, platform_name, archs, _platform, key in WRAPPERS_RELATIVE:
            output = engines / relative
            slice_paths = []
            for arch in archs:
                slice_path = slices_root / f"{key}-{arch}.dylib"
                _compile_dylib(
                    slice_path, platform_name, arch, f"winn_{key}_{arch}_dylib"
                )
                slice_paths.append(slice_path)
            output.parent.mkdir(parents=True, exist_ok=True)
            if len(slice_paths) == 1:
                slice_paths[0].replace(output)
            else:
                subprocess.run(
                    ["/usr/bin/xcrun", "lipo", "-create", "-output", str(output), *map(str, slice_paths)],
                    check=True,
                )
                subprocess.run(["/usr/bin/xcrun", "strip", "-x", str(output)], check=True)
        return {
            "release": release,
            "archives": archives,
            "engines": engines,
            "provenance": provenance,
            "facts": facts,
        }

    def _env(self, paths: dict[str, pathlib.Path]) -> dict[str, str]:
        environment = release_env(WINS_WINN_TRUST_PUBLIC_KEY=public_key())
        environment["WINN_DATAPATH_ARCHIVE_DIR"] = str(paths["archives"])
        environment["APPLE_ENGINE_WRAPPER_OUTPUT_ROOT"] = str(paths["engines"])
        environment["APPLE_ENGINE_ARTIFACTS_DIR"] = str(paths["engines"])
        environment["APPLE_WINN_ENGINE_PROVENANCE_FILE"] = str(paths["provenance"])
        environment["APPLE_WINN_RELEASE_FACTS"] = str(paths["facts"])
        return environment

    def _run(
        self,
        args: list[str],
        environment: dict[str, str],
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return run_wrappers(args, environment, check)

    def test_write_and_verify_bind_release_archives_headers_and_dylibs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-winn-v3-prov-") as raw:
            paths = self._materialize(pathlib.Path(raw))
            environment = self._env(paths)
            written = self._run(["write-winn-provenance"], environment)
            self.assertIn("Apple Winn v3 engine provenance:", written.stdout, written.stderr)
            verified = self._run(["verify-winn-provenance"], environment)
            self.assertIn("APPLE WINN V3 ENGINE PROVENANCE: PASS", verified.stdout)
            bound = self._run(
                ["verify-winn-provenance", "--release", str(paths["release"])], environment
            )
            self.assertIn("APPLE WINN V3 RELEASE BINDING: PASS (signed)", bound.stdout)
            manifest = json.loads(paths["provenance"].read_text(encoding="utf-8"))
            self.assertEqual(manifest["component"], "winn-apple-engine-wrappers")
            self.assertEqual(manifest["generation"], "v3")
            self.assertEqual(manifest["schema_version"], 5)
            self.assertIsInstance(manifest["schema_version"], int)
            self.assertNotIsInstance(manifest["schema_version"], bool)
            self.assertEqual(manifest["source"]["module"], "winsvpn.local/winnprotocol")
            self.assertEqual(
                manifest["source"]["wrapper_sha256"],
                sha256(ROOT / "apple/EngineWrappers/WinsWinnPacketEngine.m"),
            )
            release = manifest["release"]
            self.assertEqual(release["manifest_sha256"], sha256(paths["release"] / "manifest.json"))
            self.assertEqual(release["signature_public_key"], public_key())
            self.assertEqual(release["signature_state"], "signed")
            self.assertEqual(release["go"]["version"], PINS["tools"]["go"]["version"])
            self.assertEqual(len(manifest["archives"]), 5)
            for target, (_platform, _arch, stem) in RELEASE_TARGETS.items():
                entry = next(
                    item for item in manifest["archives"].values() if item["target"] == target
                )
                released = paths["release"] / "artifacts" / target / "libwinn-datapath.a"
                self.assertEqual(entry["sha256"], sha256(released))
                self.assertEqual(entry["build_a_sha256"], entry["sha256"])
                self.assertEqual(entry["build_b_sha256"], entry["sha256"])
                self.assertEqual(entry["path"], f"{stem}.a")
                self.assertEqual(entry["header_path"], f"{stem}.h")
            self.assertEqual(
                set(manifest["wrappers"]),
                {"iphoneos", "iphonesimulator", "macosx"},
            )
            macos = paths["engines"] / "macos/libWinsWinnPacketEngine.dylib"
            self.assertEqual(manifest["wrappers"]["macosx"]["sha256"], sha256(macos))
            self.assertEqual(manifest["wrappers"]["macosx"]["architectures"], _lipo_archs(macos))
            self.assertEqual(manifest["wrappers"]["macosx"]["platform"], "MACOS")
            self.assertEqual(manifest["wrappers"]["macosx"]["strip_state"], "stripped")
            for arch, slice_record in manifest["wrappers"]["macosx"]["slices"].items():
                self.assertEqual(slice_record["architecture"], arch)
                self.assertEqual(slice_record["filetype"], "MH_DYLIB")
                self.assertEqual(slice_record["minos"], "13.0")
                self.assertEqual(
                    slice_record["install_name"],
                    "@rpath/WinsWinnPacketEngine.framework/WinsWinnPacketEngine",
                )
                self.assertIn("/usr/lib/libSystem.B.dylib", slice_record["dependencies"])
            self.assertEqual(
                manifest["wrappers"]["iphonesimulator"]["architectures"],
                ["arm64", "x86_64"],
            )
            self.assertEqual(
                manifest["role_binding"]["core"]["entry_symbol"],
                "WinnTunnelCreateWinn3",
            )
            self.assertEqual(
                set(manifest["apple_toolchain"]["tools"]),
                {"ar", "clang", "file", "lipo", "nm", "otool", "strip", "vtool"},
            )
            self.assertEqual(
                manifest["builders"]["wrapper_builder"]["sha256"], sha256(WRAPPERS)
            )
            ios_archive = paths["archives"] / "libwinn-datapath-ios-arm64.a"
            bound_archive = self._run(
                ["archive-bound-winn-provenance", str(ios_archive)],
                environment,
            )
            self.assertIn("APPLE WINN V3 ARCHIVE BINDING: PASS", bound_archive.stdout)

    def test_macos_record_carries_the_consumer_signature_normalized_digest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-winn-v3-normalized-") as raw:
            root = pathlib.Path(raw)
            paths = self._materialize(root)
            environment = self._env(paths)
            self._run(["write-winn-provenance"], environment)
            manifest = json.loads(paths["provenance"].read_text(encoding="utf-8"))
            macos = paths["engines"] / "macos/libWinsWinnPacketEngine.dylib"
            record = manifest["wrappers"]["macosx"]
            self.assertEqual(record["sha256"], sha256(macos))
            expected = consumer_normalized_sha256(macos, root / "consumer-scratch")
            self.assertEqual(record["signature_normalized_sha256"], expected)
            self.assertNotEqual(expected, record["sha256"])
            for key in ("iphoneos", "iphonesimulator"):
                self.assertNotIn("signature_normalized_sha256", manifest["wrappers"][key])
            del record["signature_normalized_sha256"]
            paths["provenance"].write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            failed = self._run(["verify-winn-provenance"], environment, check=False)
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("mismatch", failed.stderr + failed.stdout)

    def test_provenance_requires_release_facts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-winn-v3-nofacts-") as raw:
            paths = self._materialize(pathlib.Path(raw))
            environment = self._env(paths)
            environment.pop("APPLE_WINN_RELEASE_FACTS")
            failed = self._run(["write-winn-provenance"], environment, check=False)
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("only be written from a verified Winn release", failed.stderr)
            self.assertFalse(paths["provenance"].exists())

    def test_release_record_tamper_and_foreign_release_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-winn-v3-rebind-") as raw:
            paths = self._materialize(pathlib.Path(raw))
            environment = self._env(paths)
            self._run(["write-winn-provenance"], environment)
            original = paths["provenance"].read_text(encoding="utf-8")

            for field, value in (
                ("manifest_sha256", "0" * 64),
                ("signature_public_key", public_key(OTHER_SEED)),
            ):
                manifest = json.loads(original)
                manifest["release"][field] = value
                paths["provenance"].write_text(
                    json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
                )
                tampered = self._run(
                    ["verify-winn-provenance", "--release", str(paths["release"])],
                    environment,
                    check=False,
                )
                self.assertNotEqual(tampered.returncode, 0, field)

            manifest = json.loads(original)
            manifest["release"]["signature_state"] = "unsigned-dev"
            paths["provenance"].write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            downgraded = self._run(["verify-winn-provenance"], environment, check=False)
            self.assertNotEqual(downgraded.returncode, 0)
            self.assertIn("unsigned-dev", downgraded.stderr)

            manifest = json.loads(original)
            manifest["archives"]["macosx_arm64"]["build_b_sha256"] = "f" * 64
            paths["provenance"].write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            split = self._run(["verify-winn-provenance"], environment, check=False)
            self.assertNotEqual(split.returncode, 0)

            # A different signed release cannot vouch for these engines.
            paths["provenance"].write_text(original, encoding="utf-8")
            other = pathlib.Path(raw) / "other-release"
            make_release(other)
            foreign = self._run(
                ["verify-winn-provenance", "--release", str(other)],
                environment,
                check=False,
            )
            self.assertNotEqual(foreign.returncode, 0)
            self.assertIn("not bound to the release", foreign.stderr)

            # Release mode demands the release directory.
            release_mode = dict(environment)
            release_mode.pop("WINS_WINN_TRUST_PUBLIC_KEY")
            release_mode["WINS_APPLE_WINN3_RELEASE"] = "1"
            unbound = self._run(["verify-winn-provenance"], release_mode, check=False)
            self.assertNotEqual(unbound.returncode, 0)
            self.assertIn("requires the signed Winn release directory", unbound.stderr)

    def test_release_go_must_match_the_pinned_toolchain(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-winn-v3-go-") as raw:
            paths = self._materialize(pathlib.Path(raw))
            environment = self._env(paths)
            facts = json.loads(paths["facts"].read_text(encoding="ascii"))
            for field, value, expected in (
                ("version", "1.26.0", "Go version"),
                ("archive_sha256", "0" * 64, "pinned official darwin archive"),
            ):
                mutated = json.loads(json.dumps(facts))
                mutated["release"]["go"][field] = value
                paths["facts"].write_text(json.dumps(mutated), encoding="ascii")
                failed = self._run(["write-winn-provenance"], environment, check=False)
                self.assertNotEqual(failed.returncode, 0, field)
                self.assertIn(expected, failed.stderr)
            mutated = json.loads(json.dumps(facts))
            mutated["release"]["signature_state"] = "unsigned-dev"
            paths["facts"].write_text(json.dumps(mutated), encoding="ascii")
            claimed = self._run(["write-winn-provenance"], environment, check=False)
            self.assertNotEqual(claimed.returncode, 0)
            self.assertIn("must not claim a signature public key", claimed.stderr)

    def test_symbol_complete_dylib_substitution_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-winn-v3-sub-") as raw:
            paths = self._materialize(pathlib.Path(raw))
            environment = self._env(paths)
            self._run(["write-winn-provenance"], environment)
            dylib = paths["engines"] / "macos/libWinsWinnPacketEngine.dylib"
            _compile_dylib(dylib, "macosx", "arm64", "winn_macosx_dylib_substitute")
            failed = self._run(["verify-winn-provenance"], environment, check=False)
            self.assertNotEqual(failed.returncode, 0)
            combined = (failed.stderr + failed.stdout).lower()
            self.assertTrue("mismatch" in combined or "rebuild" in combined)

    def test_core_and_relay_role_exports_are_required(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-winn-v3-role-") as raw:
            paths = self._materialize(pathlib.Path(raw))
            environment = self._env(paths)
            device = paths["engines"] / "ios/iphoneos/libWinsWinnPacketEngine.dylib"
            _compile_dylib(
                device,
                "iphoneos",
                "arm64",
                "winn_iphoneos_missing_relay",
                exports=tuple(
                    symbol
                    for symbol in WINN_EXPORTS
                    if symbol != "WinnTunnelCreateWithCarrier"
                ),
            )
            failed = self._run(["write-winn-provenance"], environment, check=False)
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("required exported symbols", failed.stderr)

    def test_unstripped_dylib_is_rejected_before_provenance_write(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-winn-v3-strip-") as raw:
            paths = self._materialize(pathlib.Path(raw))
            environment = self._env(paths)
            device = paths["engines"] / "ios/iphoneos/libWinsWinnPacketEngine.dylib"
            _compile_dylib(
                device,
                "iphoneos",
                "arm64",
                "winn_iphoneos_unstripped",
                strip=False,
            )
            failed = self._run(["write-winn-provenance"], environment, check=False)
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("not stripped", failed.stderr)

    def test_simulator_architecture_substitution_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-winn-v3-arch-") as raw:
            paths = self._materialize(pathlib.Path(raw))
            environment = self._env(paths)
            simulator = (
                paths["engines"]
                / "ios/iphonesimulator/libWinsWinnPacketEngine.dylib"
            )
            _compile_dylib(
                simulator,
                "iphonesimulator",
                "arm64",
                "winn_simulator_device_slice",
            )
            failed = self._run(["write-winn-provenance"], environment, check=False)
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("architectures", failed.stderr)

    def test_hostile_macho_slice_metadata_is_rejected(self) -> None:
        cases = (
            (
                "platform",
                {"platform_name": "iphonesimulator"},
                "platform",
            ),
            (
                "minos",
                {"platform_name": "iphoneos", "target": "arm64-apple-ios12.0"},
                "minimum OS",
            ),
            (
                "install-name",
                {
                    "platform_name": "iphoneos",
                    "install_name": "/tmp/hostile-WinsWinnPacketEngine.dylib",
                },
                "install name",
            ),
            (
                "uuid",
                {
                    "platform_name": "iphoneos",
                    "extra_linker_args": ("-Wl,-no_uuid",),
                },
                "LC_UUID",
            ),
            (
                "filetype",
                {"platform_name": "iphoneos", "link_mode": "-bundle"},
                "MH_DYLIB",
            ),
        )
        for label, options, expected_error in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory(
                prefix=f"wins-winn-v3-{label}-"
            ) as raw:
                paths = self._materialize(pathlib.Path(raw))
                environment = self._env(paths)
                device = paths["engines"] / "ios/iphoneos/libWinsWinnPacketEngine.dylib"
                _compile_dylib(
                    device,
                    options["platform_name"],
                    "arm64",
                    f"winn_iphoneos_hostile_{label.replace('-', '_')}",
                    target=options.get("target"),
                    install_name=options.get(
                        "install_name",
                        "@rpath/WinsWinnPacketEngine.framework/WinsWinnPacketEngine",
                    ),
                    link_mode=options.get("link_mode", "-dynamiclib"),
                    extra_linker_args=options.get("extra_linker_args", ()),
                )
                failed = self._run(
                    ["write-winn-provenance"], environment, check=False
                )
                self.assertNotEqual(failed.returncode, 0)
                self.assertIn(expected_error, failed.stderr)

        with tempfile.TemporaryDirectory(prefix="wins-winn-v3-dependency-") as raw:
            paths = self._materialize(pathlib.Path(raw))
            environment = self._env(paths)
            dependency = pathlib.Path(raw) / "hostile-provider.dylib"
            _compile_dylib(
                dependency,
                "iphoneos",
                "arm64",
                "winn_hostile_dependency_provider",
                install_name="/tmp/hostile-provider.dylib",
            )
            device = paths["engines"] / "ios/iphoneos/libWinsWinnPacketEngine.dylib"
            _compile_dylib(
                device,
                "iphoneos",
                "arm64",
                "winn_iphoneos_hostile_dependency",
                extra_linker_args=(f"-Wl,-needed_library,{dependency}",),
            )
            failed_dependency = self._run(
                ["write-winn-provenance"], environment, check=False
            )
            self.assertNotEqual(failed_dependency.returncode, 0)
            self.assertIn("non-system dependency", failed_dependency.stderr)

    def test_archive_and_header_drift_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-winn-v3-arc-") as raw:
            paths = self._materialize(pathlib.Path(raw))
            environment = self._env(paths)
            self._run(["write-winn-provenance"], environment)
            archive = paths["archives"] / "libwinn-datapath-darwin-arm64.a"
            original = archive.read_bytes()
            _compile_object(archive, "macosx", "arm64", "winn_macosx_arm64_object_stale")
            failed = self._run(["verify-winn-provenance"], environment, check=False)
            self.assertNotEqual(failed.returncode, 0)
            # A substitute archive cannot be re-recorded: the release facts
            # still name the released bytes.
            rewritten = self._run(["write-winn-provenance"], environment, check=False)
            self.assertNotEqual(rewritten.returncode, 0)
            self.assertIn("Winn release archive macosx_arm64 SHA-256", rewritten.stderr)
            archive.write_bytes(original)
            self._run(["write-winn-provenance"], environment)
            header = paths["archives"] / "libwinn-datapath-darwin-arm64.h"
            header.write_text(
                header.read_text(encoding="utf-8") + "/* drift */\n",
                encoding="utf-8",
            )
            failed_header = self._run(
                ["verify-winn-provenance"], environment, check=False
            )
            self.assertNotEqual(failed_header.returncode, 0)

    def test_mtime_reuse_cannot_bypass_unbound_archives(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-winn-v3-reuse-") as raw:
            paths = self._materialize(pathlib.Path(raw))
            environment = self._env(paths)
            archive = paths["archives"] / "libwinn-datapath-ios-arm64.a"
            missing = self._run(
                ["archive-bound-winn-provenance", str(archive)],
                environment,
                check=False,
            )
            self.assertNotEqual(missing.returncode, 0)
            self._run(["write-winn-provenance"], environment)
            self._run(["archive-bound-winn-provenance", str(archive)], environment)
            newer = archive.stat().st_mtime + 3600
            os.utime(archive, (newer, newer))
            header = paths["archives"] / "libwinn-datapath-ios-arm64.h"
            header.write_text(
                header.read_text(encoding="utf-8") + "/* drift */\n", encoding="utf-8"
            )
            os.utime(header, (newer - 7200, newer - 7200))
            bypassed = self._run(
                ["archive-bound-winn-provenance", str(archive)],
                environment,
                check=False,
            )
            self.assertNotEqual(bypassed.returncode, 0)

    def test_malformed_and_symlink_provenance_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-winn-v3-bad-") as raw:
            paths = self._materialize(pathlib.Path(raw))
            environment = self._env(paths)
            self._run(["write-winn-provenance"], environment)
            real = paths["provenance"].with_suffix(".json.real")
            paths["provenance"].replace(real)
            paths["provenance"].symlink_to(real.name)
            linked = self._run(["verify-winn-provenance"], environment, check=False)
            self.assertNotEqual(linked.returncode, 0)
            paths["provenance"].unlink()
            paths["provenance"].write_text("{not json\n", encoding="utf-8")
            malformed = self._run(
                ["verify-winn-provenance"], environment, check=False
            )
            self.assertNotEqual(malformed.returncode, 0)
            self.assertIn("invalid JSON", malformed.stderr)

    def test_empty_archive_and_hardlink_inputs_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-winn-v3-empty-") as raw:
            paths = self._materialize(pathlib.Path(raw))
            environment = self._env(paths)
            empty = paths["archives"] / "libwinn-datapath-ios-arm64.a"
            empty.write_bytes(b"")
            failed_empty = self._run(
                ["write-winn-provenance"], environment, check=False
            )
            self.assertNotEqual(failed_empty.returncode, 0)
            combined = (failed_empty.stderr + failed_empty.stdout).lower()
            self.assertTrue("empty" in combined or "nonempty" in combined)

        with tempfile.TemporaryDirectory(prefix="wins-winn-v3-link-") as raw:
            paths = self._materialize(pathlib.Path(raw))
            environment = self._env(paths)
            archive = paths["archives"] / "libwinn-datapath-ios-arm64.a"
            os.link(archive, paths["archives"] / "hardlink.a")
            failed_link = self._run(["write-winn-provenance"], environment, check=False)
            self.assertNotEqual(failed_link.returncode, 0)
            self.assertIn("single-link", failed_link.stderr)

        with tempfile.TemporaryDirectory(prefix="wins-winn-v3-sym-") as raw:
            paths = self._materialize(pathlib.Path(raw))
            environment = self._env(paths)
            archive = paths["archives"] / "libwinn-datapath-darwin-arm64.a"
            real = archive.with_name("real-darwin-arm64.a")
            archive.replace(real)
            archive.symlink_to(real.name)
            failed_sym = self._run(["write-winn-provenance"], environment, check=False)
            self.assertNotEqual(failed_sym.returncode, 0)

    def test_duplicate_keys_bool_schema_version_and_extras_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-winn-v3-schema-") as raw:
            paths = self._materialize(pathlib.Path(raw))
            environment = self._env(paths)
            self._run(["write-winn-provenance"], environment)
            original = paths["provenance"].read_text(encoding="utf-8")
            manifest = json.loads(original)

            paths["provenance"].write_text(
                original.replace('"schema_version": 5', '"schema_version": 5,\n  "schema_version": 5', 1),
                encoding="utf-8",
            )
            dup = self._run(["verify-winn-provenance"], environment, check=False)
            self.assertNotEqual(dup.returncode, 0)
            self.assertIn("duplicate JSON key", dup.stderr)

            manifest["schema_version"] = True
            paths["provenance"].write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            as_bool = self._run(["verify-winn-provenance"], environment, check=False)
            self.assertNotEqual(as_bool.returncode, 0)
            combined = as_bool.stderr + as_bool.stdout
            self.assertTrue(
                "bool-as-int" in combined or "must be an integer" in combined
            )

            manifest["schema_version"] = 5
            manifest["extra_field"] = "nope"
            paths["provenance"].write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            extra = self._run(["verify-winn-provenance"], environment, check=False)
            self.assertNotEqual(extra.returncode, 0)
            self.assertIn("extra field", extra.stderr)

    def test_core_relay_role_binding_tamper_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-winn-v3-role-manifest-") as raw:
            paths = self._materialize(pathlib.Path(raw))
            environment = self._env(paths)
            self._run(["write-winn-provenance"], environment)
            manifest = json.loads(paths["provenance"].read_text(encoding="utf-8"))
            manifest["role_binding"]["relay"]["payload_class"] = "ip-packet"
            paths["provenance"].write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            failed = self._run(["verify-winn-provenance"], environment, check=False)
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("payload_class", failed.stderr)

    def test_current_checkout_is_refused_without_a_release(self) -> None:
        provenance = ROOT / "apple" / "EngineArtifacts" / "apple_winn_v3_engine_provenance.json"
        # A checkout may carry the provenance a verified rebuild published, but never the
        # gitignored Winn archives it binds, so verification still refuses here and no
        # refused write may create or rewrite the committed provenance bytes.
        committed = provenance.read_bytes() if provenance.exists() else None
        failed = run_wrappers(["verify-winn-provenance"], release_env(), check=False)
        self.assertNotEqual(failed.returncode, 0)
        combined = (failed.stderr + failed.stdout).lower()
        self.assertTrue("rebuild" in combined or "missing" in combined)
        hashed = run_wrappers(
            ["write-winn-provenance"],
            release_env(APPLE_WINN_RELEASE_FACTS="/nonexistent/facts.json"),
            check=False,
        )
        self.assertNotEqual(hashed.returncode, 0)
        self.assertIn("without a verified rebuild", hashed.stderr)
        self.assertEqual(
            provenance.read_bytes() if provenance.exists() else None,
            committed,
            "live hash-without-rebuild must not publish Winn provenance",
        )

        # Release mode never falls back to an unsigned dev build.
        winn_rebuild = run_wrappers(
            ["winn"], release_env(WINS_APPLE_WINN3_RELEASE="1"), check=False
        )
        self.assertNotEqual(winn_rebuild.returncode, 0)
        self.assertIn("requires a signed Winn release directory", winn_rebuild.stderr)
        self.assertEqual(
            provenance.read_bytes() if provenance.exists() else None,
            committed,
            "a refused release must not publish Winn provenance",
        )


if __name__ == "__main__":
    unittest.main()
