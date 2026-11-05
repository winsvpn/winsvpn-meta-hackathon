#!/usr/bin/env python3
"""Hostile tests for ReleasePython production input custody."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import inspect
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tools" / "macos_release_python_inputs.custody.json"
GENERATOR = ROOT / "tools" / "build_macos_release_python_inputs_manifest.py"
INSTALLER = ROOT / "tools" / "install_macos_release_python_inputs.py"
PRODUCER = ROOT / "tools" / "produce_macos_release_python_runtime_13.py"
PRODUCTION_IMPLEMENTATION = ROOT / "tools" / "macos_release_python_runtime_production.py"
ENTRYPOINT_SOURCE = ROOT / "tools" / "macos_release_python_entrypoint.c"
PINS = ROOT / "tools" / "toolchain-pins.json"
RUNTIME_CUSTODY = ROOT / "tools" / "macos_release_python_runtime.custody.json"


def load_module(name: str, path: Path):
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


GENERATOR_MODULE = load_module("release_python_input_manifest", GENERATOR)
INSTALLER_MODULE = load_module("release_python_input_installer", INSTALLER)
PRODUCER_MODULE = load_module("release_python_producer_entrypoint", PRODUCER)
PRODUCTION_MODULE = load_module("release_python_production", PRODUCTION_IMPLEMENTATION)


def snapshot_fixture(root: Path) -> tuple[Path, Path, dict[str, bytes], list[dict[str, str]]]:
    source = root / "source"
    source.mkdir(mode=0o700)
    document = copy.deepcopy(json.loads(MANIFEST.read_text(encoding="ascii")))
    payloads: dict[str, bytes] = {}
    for index, record in enumerate(document["artifacts"]):
        payload = f"snapshot-fixture-{index}-{record['kind']}\n".encode("ascii")
        digest = hashlib.sha256(payload).hexdigest()
        record["sha256"] = digest
        record["path"] = (
            f"/Library/WinsVPN/ReleasePythonInputs/sha256/{digest}/{record['leaf']}"
        )
        target = source / record["leaf"]
        target.write_bytes(payload)
        target.chmod(int(record["mode"], 8))
        payloads[record["leaf"]] = payload
    manifest = root / "manifest.json"
    manifest.write_text(
        json.dumps(document, sort_keys=True, indent=2) + "\n",
        encoding="ascii",
    )
    return source, manifest, payloads, document["artifacts"]


class ReleasePythonInputsCustodyTest(unittest.TestCase):
    def test_generated_manifest_is_current_and_complete(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(GENERATOR), "--check"],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        document = json.loads(MANIFEST.read_text(encoding="ascii"))
        pins = json.loads(PINS.read_text(encoding="ascii"))
        archive = pins["tools"]["python"]["archive_custody"]["darwin_arm64"]
        self.assertEqual(document["artifact_count"], 34)
        self.assertEqual(archive["runtime_wheel_count"], 25)
        self.assertEqual(archive["wheel_count"], 28)
        self.assertEqual(
            {item["kind"] for item in document["artifacts"]},
            {
                "package",
                "sigstore-bundle",
                "sigstore-trusted-root",
                "sigstore-verifier",
                "source-archive",
                "source-sigstore-bundle",
                "wheel",
            },
        )
        self.assertEqual(
            sum(item["kind"] == "wheel" for item in document["artifacts"]), 28
        )
        expected_x86 = {
            "pillow-12.3.0-cp314-cp314-macosx_10_15_x86_64.whl":
                "ba54cfebe86920a559a7c4d6b9050791c20513650a1952ebe3368c7dc70306f8",
            "pydantic_core-2.46.4-cp314-cp314-macosx_10_12_x86_64.whl":
                "428e04521a40150c85216fc8b85e8d39fece235a9cf5e383761238c7fa9b96fb",
            "pyyaml-6.0.3-cp314-cp314-macosx_10_13_x86_64.whl":
                "8d1fab6bb153a416f9aeb4b8763bc0f22a5586065f86f7664fc23339fc1c1fac",
        }
        self.assertEqual(
            {
                item["leaf"]: item["sha256"]
                for item in document["artifacts"]
                if item["leaf"] in expected_x86
            },
            expected_x86,
        )

    def test_every_pin_is_content_addressed_and_no_download_path_remains(self) -> None:
        pins = json.loads(PINS.read_text(encoding="ascii"))
        release_python = pins["tools"]["python"]["archive_custody"]["darwin_arm64"]
        self.assertNotIn("/Users/", json.dumps(release_python, sort_keys=True))
        document = json.loads(MANIFEST.read_text(encoding="ascii"))
        root = Path(document["destination_root"])
        for record in document["artifacts"]:
            with self.subTest(path=record["path"]):
                self.assertEqual(
                    Path(record["path"]),
                    root / record["sha256"] / record["leaf"],
                )

    def test_manifest_builder_rejects_non_content_addressed_wheel(self) -> None:
        pins = json.loads(PINS.read_text(encoding="ascii"))
        pins["tools"]["python"]["archive_custody"]["darwin_arm64"]["wheels"]["7"]["path"] = "/private/tmp/substituted.whl"
        with self.assertRaisesRegex(ValueError, r"outside fixed content-addressed"):
            GENERATOR_MODULE.build(
                (json.dumps(pins, sort_keys=True) + "\n").encode("ascii")
            )

    def test_manifest_builder_rejects_runtime_and_x86_partition_drift(self) -> None:
        original = json.loads(PINS.read_text(encoding="ascii"))
        cases = []
        wrong_count = copy.deepcopy(original)
        wrong_count["tools"]["python"]["archive_custody"]["darwin_arm64"][
            "runtime_wheel_count"
        ] = 24
        cases.append(wrong_count)
        reordered = copy.deepcopy(original)
        wheels = reordered["tools"]["python"]["archive_custody"]["darwin_arm64"]["wheels"]
        wheels["0"], wheels["25"] = wheels["25"], wheels["0"]
        cases.append(reordered)
        for pins in cases:
            with self.subTest(runtime_count=pins["tools"]["python"]["archive_custody"]["darwin_arm64"]["runtime_wheel_count"]):
                with self.assertRaises(ValueError):
                    GENERATOR_MODULE.build(
                        (json.dumps(pins, sort_keys=True) + "\n").encode("ascii")
                    )

    def test_installer_rejects_destination_and_inventory_substitution(self) -> None:
        original = json.loads(MANIFEST.read_text(encoding="ascii"))
        cases = []
        escaped = copy.deepcopy(original)
        escaped["artifacts"][0]["path"] = "/private/tmp/package"
        cases.append(escaped)
        duplicate = copy.deepcopy(original)
        duplicate["artifacts"][-1] = copy.deepcopy(duplicate["artifacts"][-2])
        cases.append(duplicate)
        for document in cases:
            with self.subTest(case=document["artifacts"][-1]["path"]):
                data = (json.dumps(document, sort_keys=True, indent=2) + "\n").encode(
                    "ascii"
                )
                path = ROOT / "tools" / ".test-release-python-inputs.invalid.json"
                try:
                    path.write_bytes(data)
                    with self.assertRaises(INSTALLER_MODULE.Refused):
                        INSTALLER_MODULE.load_manifest(path)
                finally:
                    path.unlink(missing_ok=True)

    def test_runtime_producer_has_terminal_flat_package_staple_order(self) -> None:
        entrypoint = PRODUCER.read_text(encoding="ascii")
        source = PRODUCTION_IMPLEMENTATION.read_text(encoding="ascii")
        main_source = inspect.getsource(PRODUCTION_MODULE.main)
        notary_source = inspect.getsource(PRODUCTION_MODULE.notarize_and_staple)
        distribution_source = inspect.getsource(PRODUCTION_MODULE.build_signed_distribution)
        expansion_source = inspect.getsource(PRODUCTION_MODULE.expand_distribution)
        self.assertIn("authenticated_closure", entrypoint)
        self.assertNotIn("importlib", entrypoint)
        self.assertIn("Developer ID Application: Win's VPN Inc (5YT8H4U72M)", source)
        self.assertIn("Developer ID Installer: Win's VPN Inc (5YT8H4U72M)", source)
        self.assertIn("notarytool", source)
        self.assertIn("stapler", source)
        self.assertIn("--options", source)
        self.assertIn("runtime", source)
        self.assertIn("--timestamp", source)
        self.assertNotIn('"--deep"', source)
        self.assertIn("unexpected entitlements", source)
        self.assertIn("com.apple.security.cs.allow-unsigned-executable-memory", source)
        self.assertNotIn("com.apple.security.cs.disable-library-validation", source)
        self.assertNotIn("com.apple.security.cs.disable-executable-page-protection", source)
        self.assertNotIn("codesign", notary_source)
        self.assertLess(
            notary_source.index("clean_notary_log("),
            notary_source.index('"staple"'),
        )
        self.assertLess(
            main_source.index("developer_id_seal(candidate"),
            main_source.index("build_signed_distribution("),
        )
        self.assertLess(
            main_source.index("build_signed_distribution("),
            main_source.index("notarize_and_staple("),
        )
        self.assertLess(
            main_source.index("notarize_and_staple("),
            main_source.index("verify_final_distribution("),
        )
        self.assertLess(
            main_source.index("notary_authentication_arguments()"),
            main_source.index('scratch = output / "scratch"'),
        )
        self.assertNotIn("Python.app.notary.zip", source)
        self.assertNotIn("vtool", source)
        self.assertIn('TOOLS["pkgbuild"]', distribution_source)
        self.assertIn('TOOLS["productsign"]', distribution_source)
        self.assertIn('"--ownership", "recommended"', distribution_source)
        self.assertIn('"--timestamp"', distribution_source)
        self.assertIn('"--component-plist", component_plist', distribution_source)
        self.assertIn('"--type", "install"', inspect.getsource(
            PRODUCTION_MODULE.verify_final_distribution
        ))
        self.assertLess(
            distribution_source.index('TOOLS["pkgbuild"]'),
            distribution_source.index('TOOLS["productsign"]'),
        )
        self.assertLess(
            distribution_source.index("pre_sign_sha256 = sha256(unsigned)"),
            distribution_source.index("make_tree_mutable(package_root)"),
        )
        self.assertLess(
            distribution_source.index("make_tree_mutable(package_root)"),
            distribution_source.index("shutil.rmtree(package_root)"),
        )
        self.assertLess(
            expansion_source.index("make_tree_mutable(destination)"),
            expansion_source.index("shutil.rmtree(destination)"),
        )
        self.assertNotIn("hdiutil", source)
        self.assertNotIn("UDIF", source)

    def test_producer_uses_only_held_input_snapshot_after_authentication(self) -> None:
        main_source = inspect.getsource(PRODUCTION_MODULE.main)
        snapshot = main_source.index("snapshot_release_inputs(")
        first_consumer = main_source.index("pinned_leaf(custody", snapshot)
        self.assertLess(snapshot, first_consumer)
        self.assertNotIn("source_inputs", main_source[first_consumer:])
        self.assertIn(
            '[TOOLS["python3"], "-I", "-S", base_producer, snapshot_inputs, base]',
            main_source,
        )
        self.assertIn("snapshot_inputs,\n            x86_wheel_pins(custody)", main_source)

    def test_input_snapshot_survives_later_source_substitution(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-rp-snapshot-", dir="/private/tmp") as raw:
            root = Path(raw)
            source, manifest, payloads, records = snapshot_fixture(root)
            destination = root / "snapshot"
            try:
                result = PRODUCTION_MODULE.snapshot_release_inputs(
                    source,
                    destination,
                    manifest,
                )
                self.assertEqual(result["artifact_count"], 34)
                verifier = next(
                    record for record in records if record["kind"] == "sigstore-verifier"
                )
                target = source / verifier["leaf"]
                target.chmod(0o755)
                target.write_bytes(b"substituted-after-snapshot\n")
                self.assertEqual(
                    (destination / verifier["leaf"]).read_bytes(),
                    payloads[verifier["leaf"]],
                )
            finally:
                if destination.exists() and not destination.is_symlink():
                    destination.chmod(0o700)

    def test_input_snapshot_rejects_coordinated_cosign_and_x86_wheel_swaps(self) -> None:
        target_kinds = ("sigstore-verifier", "wheel")
        for target_kind in target_kinds:
            with self.subTest(target_kind=target_kind):
                with tempfile.TemporaryDirectory(
                    prefix="wins-rp-snapshot-race-",
                    dir="/private/tmp",
                ) as raw:
                    root = Path(raw)
                    source, manifest, _payloads, records = snapshot_fixture(root)
                    candidates = [record for record in records if record["kind"] == target_kind]
                    record = candidates[-1]
                    target = source / record["leaf"]
                    target_inode = target.stat().st_ino
                    backup = source / f"{record['leaf']}.held-original"
                    destination = root / "snapshot"
                    real_read = PRODUCTION_MODULE.os.read
                    swapped = False

                    def racing_read(descriptor: int, maximum: int) -> bytes:
                        nonlocal swapped
                        block = real_read(descriptor, maximum)
                        if not swapped and os.fstat(descriptor).st_ino == target_inode:
                            target.replace(backup)
                            target.write_bytes(b"hostile-substitution\n")
                            swapped = True
                        return block

                    with mock.patch.object(
                        PRODUCTION_MODULE.os,
                        "read",
                        side_effect=racing_read,
                    ):
                        with self.assertRaisesRegex(
                            PRODUCTION_MODULE.ProducerError,
                            "source.*changed while held|directory changed while held",
                        ):
                            PRODUCTION_MODULE.snapshot_release_inputs(
                                source,
                                destination,
                                manifest,
                            )
                    self.assertTrue(swapped)

    def test_clean_notary_log_requires_accepted_matching_job_without_issues(self) -> None:
        submission = "12345678-1234-1234-1234-123456789abc"
        digest = "ab" * 32
        accepted = {
            "archiveFilename": PRODUCTION_MODULE.PACKAGE_NAME,
            "issues": [],
            "jobId": submission,
            "sha256": digest,
            "status": "Accepted",
        }
        self.assertEqual(
            PRODUCTION_MODULE.clean_notary_log(accepted, submission, digest),
            accepted,
        )
        hostile = (
            {**accepted, "status": "Invalid"},
            {**accepted, "jobId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
            {**accepted, "jobId": 7},
            {**accepted, "issues": [{"severity": "warning"}]},
            {**accepted, "sha256": "cd" * 32},
            {**accepted, "archiveFilename": "nested-app.zip"},
        )
        for document in hostile:
            with self.subTest(document=document):
                with self.assertRaises(PRODUCTION_MODULE.ProducerError):
                    PRODUCTION_MODULE.clean_notary_log(document, submission, digest)

    def test_codesign_flags_require_exact_hardened_runtime_field(self) -> None:
        good = (
            "Executable=/private/tmp/runtime-name/Python\n"
            "CodeDirectory v=20500 size=100 flags=0x10000(runtime) hashes=1+0 location=embedded\n"
        )
        PRODUCTION_MODULE.require_hardened_runtime_detail(good, "good")
        bad = (
            "Executable=/private/tmp/runtime-name/Python\n"
            "CodeDirectory v=20500 size=100 flags=0x0(none) hashes=1+0 location=embedded\n"
        )
        with self.assertRaisesRegex(
            PRODUCTION_MODULE.ProducerError,
            "hardened-runtime flags are not exact",
        ):
            PRODUCTION_MODULE.require_hardened_runtime_detail(bad, "bad")

    def test_runtime_exception_entitlement_is_path_scoped(self) -> None:
        self.assertEqual(
            PRODUCTION_MODULE.ENTITLED_EXECUTABLES,
            {
                "Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python",
                "Python.framework/Versions/3.14/bin/python3.14",
                "Python.framework/Versions/3.14/bin/python3.14-intel64",
            },
        )

    def test_load_command_parser_binds_ids_dylinker_and_hostile_commands(self) -> None:
        output = """
Load command 0
      cmd LC_BUILD_VERSION
  cmdsize 32
 platform 1
    minos 13.0
      sdk 26.5
Load command 1
          cmd LC_LOAD_DYLIB
      cmdsize 64
         name @loader_path/../Python (offset 24)
Load command 2
          cmd LC_ID_DYLIB
      cmdsize 64
         name @rpath/Python.framework/Versions/3.14/Python (offset 24)
Load command 3
          cmd LC_LOAD_DYLINKER
      cmdsize 32
         name /usr/lib/dyld (offset 12)
"""
        self.assertEqual(
            PRODUCTION_MODULE.parse_load_command_records(Path("fixture"), output),
            (
                ["13.0"],
                [],
                ["@loader_path/../Python"],
                ["@rpath/Python.framework/Versions/3.14/Python"],
                ["/usr/lib/dyld"],
            ),
        )
        legacy = """
Load command 0
      cmd LC_VERSION_MIN_MACOSX
  cmdsize 16
  version 10.12
      sdk 15.5
"""
        self.assertEqual(
            PRODUCTION_MODULE.parse_load_command_records(Path("legacy"), legacy)[0],
            ["10.12"],
        )
        with self.assertRaisesRegex(
            PRODUCTION_MODULE.ProducerError,
            "non-macOS LC_BUILD_VERSION",
        ):
            PRODUCTION_MODULE.parse_load_command_records(
                Path("ios"),
                output.replace("platform 1", "platform 2"),
            )
        for command in (
            "LC_DYLD_ENVIRONMENT",
            "LC_LAZY_LOAD_DYLIB",
            "LC_LOAD_UPWARD_DYLIB",
            "LC_LOAD_WEAK_DYLIB",
        ):
            with self.subTest(command=command):
                with self.assertRaisesRegex(
                    PRODUCTION_MODULE.ProducerError,
                    "forbidden load command",
                ):
                    PRODUCTION_MODULE.parse_load_command_records(
                        Path("fixture"),
                        f"Load command 0\n          cmd {command}\n",
                    )

    def test_per_slice_load_command_policy_rejects_aggregate_masking(self) -> None:
        candidate = Path("/private/tmp/wins-rp-slice-fixture")
        path = candidate / "bin/python3.14"
        dependency = "/usr/lib/libSystem.B.dylib"
        good = (["10.12"], [], [dependency], [], ["/usr/lib/dyld"])
        self.assertEqual(
            PRODUCTION_MODULE.enforce_slice_load_command_policy(
                candidate,
                path,
                "x86_64",
                "EXECUTE",
                good,
            )["minimum"],
            "10.12",
        )
        hostile = (
            ((["13.0"], [], [dependency], [], ["/usr/lib/dyld", "/usr/lib/dyld"]), "LC_LOAD_DYLINKER"),
            ((["13.0"], [], [dependency, dependency], [], ["/usr/lib/dyld"]), "duplicated"),
            (([], [], [dependency], [], ["/usr/lib/dyld"]), "deployment target"),
            ((["14.0"], [], [dependency], [], ["/usr/lib/dyld"]), "deployment target"),
        )
        for records, expected in hostile:
            with self.subTest(expected=expected):
                with self.assertRaisesRegex(PRODUCTION_MODULE.ProducerError, expected):
                    PRODUCTION_MODULE.enforce_slice_load_command_policy(
                        candidate,
                        path,
                        "x86_64",
                        "EXECUTE",
                        records,
                    )

    def test_base_policy_violation_allowlist_rejects_signature_failures(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-rp-violations-", dir="/private/tmp") as raw:
            evidence = Path(raw) / "native-policy-violations.json"
            allowed = [{
                "kind": "minimum-macos",
                "minimums": ["10.15", "11.0"],
                "path": "Python.framework/Versions/3.14/Python",
            }]
            evidence.write_text(json.dumps(allowed), encoding="ascii")
            self.assertEqual(
                PRODUCTION_MODULE.parse_base_policy_violations(evidence, 3),
                allowed,
            )
            removed_development_object = [{
                "kind": "minimum-macos",
                "minimums": [],
                "path": (
                    "Python.framework/Versions/3.14/lib/python3.14/"
                    "config-3.14-darwin/python.o"
                ),
            }]
            evidence.write_text(
                json.dumps(removed_development_object),
                encoding="ascii",
            )
            self.assertEqual(
                PRODUCTION_MODULE.parse_base_policy_violations(evidence, 3),
                removed_development_object,
            )
            empty_retained = [{
                "kind": "minimum-macos",
                "minimums": [],
                "path": "Python.framework/Versions/3.14/Python",
            }]
            evidence.write_text(json.dumps(empty_retained), encoding="ascii")
            with self.assertRaisesRegex(
                PRODUCTION_MODULE.ProducerError,
                "minimum-macos violation is invalid",
            ):
                PRODUCTION_MODULE.parse_base_policy_violations(evidence, 3)
            fatal = [{
                "kind": "static-signature",
                "path": "Python.framework/Versions/3.14/Python",
            }]
            evidence.write_text(json.dumps(fatal), encoding="ascii")
            with self.assertRaisesRegex(
                PRODUCTION_MODULE.ProducerError,
                "non-remediable",
            ):
                PRODUCTION_MODULE.parse_base_policy_violations(evidence, 3)
            evidence.write_text("[]", encoding="ascii")
            self.assertEqual(
                PRODUCTION_MODULE.parse_base_policy_violations(evidence, 0),
                [],
            )
            with self.assertRaisesRegex(
                PRODUCTION_MODULE.ProducerError,
                "exit and violation inventory disagree",
            ):
                PRODUCTION_MODULE.parse_base_policy_violations(evidence, 3)

    def test_absolute_framework_dependency_is_rejected_after_relocation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-rp-dependency-", dir="/private/tmp") as raw:
            candidate = Path(raw) / "candidate"
            loader = candidate / "vendor/native.so"
            loader.parent.mkdir(mode=0o700, parents=True)
            loader.write_bytes(b"fixture")
            with self.assertRaisesRegex(
                PRODUCTION_MODULE.ProducerError,
                "dependency escapes",
            ):
                PRODUCTION_MODULE.validate_dependency(
                    candidate,
                    loader,
                    "/Library/Frameworks/Python.framework/Versions/3.14/Python",
                )
            with self.assertRaisesRegex(
                PRODUCTION_MODULE.ProducerError,
                "dependency escapes",
            ):
                PRODUCTION_MODULE.validate_dependency(
                    candidate,
                    loader,
                    "@executable_path/../Python",
                )

    def test_symlink_closure_rejects_escape_and_dangling_targets(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-rp-symlink-", dir="/private/tmp") as raw:
            root = Path(raw)
            candidate = root / "candidate"
            retained = candidate / "vendor/retained"
            retained.parent.mkdir(mode=0o700, parents=True)
            retained.write_bytes(b"retained")
            safe = candidate / "vendor/safe"
            safe.symlink_to("retained")
            self.assertEqual(PRODUCTION_MODULE.audit_symlink_closure(candidate), 1)
            outside = root / "outside"
            outside.write_bytes(b"outside")
            escaping = candidate / "vendor/escaping"
            escaping.symlink_to("../../outside")
            with self.assertRaisesRegex(
                PRODUCTION_MODULE.ProducerError,
                "escapes or dangles",
            ):
                PRODUCTION_MODULE.audit_symlink_closure(candidate)
            escaping.unlink()
            dangling = candidate / "vendor/dangling"
            dangling.symlink_to("absent")
            with self.assertRaisesRegex(
                PRODUCTION_MODULE.ProducerError,
                "escapes or dangles",
            ):
                PRODUCTION_MODULE.audit_symlink_closure(candidate)

    def test_distribution_staging_copies_the_complete_payload(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-rp-distribution-", dir="/private/tmp") as raw:
            root = Path(raw)
            candidate = root / "candidate"
            for name in ("Python.framework", "vendor", "launcher"):
                directory = candidate / name
                directory.mkdir(mode=0o755, parents=True)
                (directory / "retained").write_bytes(name.encode("ascii"))
            _records, digest = PRODUCTION_MODULE.tree_manifest(candidate)
            destination = root / "distribution"
            destination.mkdir(mode=0o700)
            evidence_digest = PRODUCTION_MODULE.stage_distribution_payload(
                candidate,
                destination,
                {"classification": "TEST"},
                digest,
            )
            payload = destination / "ReleasePython/3.14.7"
            self.assertEqual(
                {path.name for path in payload.iterdir()},
                {"Python.framework", "vendor", "launcher"},
            )
            self.assertEqual(PRODUCTION_MODULE.tree_manifest(payload)[1], digest)
            evidence = json.loads(
                (destination / "evidence/pre-submission.json").read_text(encoding="ascii")
            )
            self.assertEqual(evidence, {"classification": "TEST"})
            self.assertEqual(
                evidence_digest,
                hashlib.sha256(
                    (destination / "evidence/pre-submission.json").read_bytes()
                ).hexdigest(),
            )

    def test_flat_package_layout_and_metadata_are_exact_and_evidence_bound(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-rp-layout-", dir="/private/tmp") as raw:
            expanded = Path(raw) / "expanded"
            expanded.mkdir(mode=0o700)
            (expanded / "Bom").write_bytes(b"bom")
            (expanded / "PackageInfo").write_text(
                '<?xml version="1.0" encoding="utf-8"?>\n'
                '<pkg-info auth="root" identifier="org.winsvpn.releasepython.pkg" '
                'install-location="/Library/WinsVPN" postinstall-action="none" '
                'relocatable="false" version="3.14.7">'
                '<payload numberOfFiles="6" installKBytes="1"/>'
                '<relocate/>'
                '</pkg-info>\n',
                encoding="ascii",
            )
            payload_root = expanded / "Payload"
            payload = payload_root / "ReleasePython/3.14.7"
            payload.mkdir(mode=0o755, parents=True)
            payload_root.chmod(0o755)
            payload.parent.chmod(0o755)
            payload.chmod(0o755)
            evidence = payload_root / "evidence/pre-submission.json"
            evidence.parent.mkdir(mode=0o755)
            evidence.parent.chmod(0o755)
            evidence.write_bytes(b"{}\n")
            evidence.chmod(0o644)
            digest = hashlib.sha256(evidence.read_bytes()).hexdigest()
            bom_output = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=(
                    "40755\troot\twheel\t\t.\n"
                    "40755\troot\twheel\t\t./ReleasePython\n"
                    "40755\troot\twheel\t\t./ReleasePython/3.14.7\n"
                    "40755\troot\twheel\t\t./evidence\n"
                    "40755\troot\twheel\t0\t./._evidence\n"
                    "100644\troot\twheel\t3\t./evidence/pre-submission.json\n"
                ).encode("ascii"),
                stderr=b"",
            )
            with mock.patch.object(PRODUCTION_MODULE, "run", return_value=bom_output):
                self.assertEqual(
                    PRODUCTION_MODULE.verify_expanded_distribution_layout(
                        expanded, digest, {}
                    ),
                    payload,
                )
            package_info = expanded / "PackageInfo"
            valid_metadata = package_info.read_bytes()
            package_info.write_bytes(
                valid_metadata.replace(b'/Library/WinsVPN', b'/Library/OtherVPN')
            )
            with mock.patch.object(PRODUCTION_MODULE, "run", return_value=bom_output):
                with self.assertRaisesRegex(
                    PRODUCTION_MODULE.ProducerError,
                    "metadata contract is not exact",
                ):
                    PRODUCTION_MODULE.verify_expanded_distribution_layout(
                        expanded, digest, {}
                    )
            package_info.write_bytes(valid_metadata)
            injected = expanded / "Scripts"
            injected.write_bytes(b"injected")
            with self.assertRaisesRegex(
                PRODUCTION_MODULE.ProducerError,
                "structure is not exact",
            ):
                PRODUCTION_MODULE.verify_expanded_distribution_layout(expanded, digest, {})
            injected.unlink()
            hostile_bom = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=bom_output.stdout.replace(b"40755", b"40700", 1),
                stderr=b"",
            )
            with mock.patch.object(PRODUCTION_MODULE, "run", return_value=hostile_bom):
                with self.assertRaisesRegex(
                    PRODUCTION_MODULE.ProducerError,
                    "BOM install-root metadata is not exact",
                ):
                    PRODUCTION_MODULE.verify_expanded_distribution_layout(
                        expanded, digest, {}
                    )

    def test_package_component_inventory_is_exact_and_nonrelocatable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-rp-components-", dir="/private/tmp") as raw:
            path = Path(raw) / "components.plist"
            path.write_bytes(plistlib.dumps([
                {
                    "BundleIsVersionChecked": True,
                    "RootRelativeBundlePath": "ReleasePython/3.14.7/Python.framework",
                    "ChildBundles": [{
                        "BundleHasStrictIdentifier": True,
                        "RootRelativeBundlePath": (
                            "ReleasePython/3.14.7/Python.framework/Versions/3.14/"
                            "Resources/Python.app"
                        ),
                    }],
                },
            ]))
            paths = PRODUCTION_MODULE.disable_bundle_relocation(path)
            self.assertEqual(len(paths), 2)
            document = plistlib.loads(path.read_bytes())
            self.assertIs(document[0]["BundleIsRelocatable"], False)
            self.assertIs(document[0]["BundleIsVersionChecked"], False)
            self.assertIs(document[0]["ChildBundles"][0]["BundleIsRelocatable"], False)
            self.assertIs(
                document[0]["ChildBundles"][0]["BundleIsVersionChecked"], False
            )

    def test_readonly_package_scratch_can_be_made_removable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-rp-cleanup-", dir="/private/tmp") as raw:
            scratch = Path(raw) / "expanded"
            nested = scratch / "Payload/ReleasePython/3.14.7/launcher"
            nested.mkdir(mode=0o755, parents=True)
            leaf = nested / "python3"
            leaf.write_bytes(b"signed-runtime")
            leaf.chmod(0o444)
            for path in sorted(
                (item for item in scratch.rglob("*") if item.is_dir()),
                key=lambda item: len(item.parts),
                reverse=True,
            ):
                path.chmod(0o555)
            scratch.chmod(0o555)
            PRODUCTION_MODULE.make_tree_mutable(scratch)
            shutil.rmtree(scratch)
            self.assertFalse(scratch.exists())

    def test_package_signature_requires_exact_installer_identity_and_timestamp(self) -> None:
        good = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=(
                "Package certificate:\n"
                "   Status: signed by a developer certificate issued by Apple for distribution\n"
                "   Signed with a trusted timestamp on: 2026-09-01\n"
                "   Certificate Chain:\n"
                "    1. Developer ID Installer: Win's VPN Inc (5YT8H4U72M)\n"
                "    2. Developer ID Certification Authority\n"
                "    3. Apple Root CA\n"
            ).encode("ascii"),
            stderr=b"",
        )
        with mock.patch.object(PRODUCTION_MODULE, "run", return_value=good):
            detail = PRODUCTION_MODULE.verify_package_signature(Path("release.pkg"), {})
        self.assertIn(PRODUCTION_MODULE.OWNER_INSTALLER, detail)
        for needle in (
            b"Signed with a trusted timestamp",
            b"Status: signed by a developer certificate issued by Apple for distribution",
        ):
            hostile = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=good.stdout.replace(needle, b"missing"),
                stderr=b"",
            )
            with mock.patch.object(PRODUCTION_MODULE, "run", return_value=hostile):
                with self.assertRaisesRegex(
                    PRODUCTION_MODULE.ProducerError,
                    "Developer ID Installer signature policy failed",
                ):
                    PRODUCTION_MODULE.verify_package_signature(Path("release.pkg"), {})
        hostile = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=good.stdout.replace(b"Developer ID Installer", b"Developer ID Application"),
            stderr=b"",
        )
        with mock.patch.object(PRODUCTION_MODULE, "run", return_value=hostile):
            with self.assertRaisesRegex(
                PRODUCTION_MODULE.ProducerError,
                "Developer ID Installer signature policy failed",
            ):
                PRODUCTION_MODULE.verify_package_signature(Path("release.pkg"), {})

    def test_notarization_refuses_signed_byte_drift_before_external_call(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-rp-notary-", dir="/private/tmp") as raw:
            root = Path(raw)
            package = root / "distribution.pkg"
            package.write_bytes(b"changed")
            with mock.patch.object(
                PRODUCTION_MODULE,
                "owner_credential_env",
                side_effect=AssertionError("external authentication must not run"),
            ):
                with self.assertRaisesRegex(
                    PRODUCTION_MODULE.ProducerError,
                    "changed before notarization submission",
                ):
                    PRODUCTION_MODULE.notarize_and_staple(
                        package,
                        root / "notary.json",
                        hashlib.sha256(b"reviewed").hexdigest(),
                        ["--issuer", "00000000-0000-0000-0000-000000000000"],
                        {},
                    )

    def test_terminal_distribution_hash_rejects_one_late_byte(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-rp-terminal-", dir="/private/tmp") as raw:
            package = Path(raw) / "distribution.pkg"
            package.write_bytes(b"signed-and-stapled")
            expected = hashlib.sha256(package.read_bytes()).hexdigest()
            self.assertEqual(
                PRODUCTION_MODULE.require_terminal_distribution_hash(package, expected),
                expected,
            )
            package.write_bytes(package.read_bytes() + b"x")
            with self.assertRaisesRegex(
                PRODUCTION_MODULE.ProducerError,
                "changed after terminal stapling",
            ):
                PRODUCTION_MODULE.require_terminal_distribution_hash(package, expected)

    def test_cpython_source_archive_rejects_unsafe_or_duplicate_members(self) -> None:
        source = ENTRYPOINT_SOURCE.read_bytes()
        expected = hashlib.sha256(source).hexdigest()
        with tempfile.TemporaryDirectory(prefix="wins-rp-source-", dir="/private/tmp") as raw:
            root = Path(raw)
            good = root / "good.tar.xz"
            with tarfile.open(good, "w:xz") as archive:
                info = tarfile.TarInfo("Python-3.14.7/Programs/python.c")
                info.size = len(source)
                archive.addfile(info, io.BytesIO(source))
            self.assertEqual(
                PRODUCTION_MODULE.extract_authenticated_entrypoint(good, expected),
                source,
            )

            unsafe = root / "unsafe.tar.xz"
            with tarfile.open(unsafe, "w:xz") as archive:
                info = tarfile.TarInfo("Python-3.14.7/Programs/python.c")
                info.type = tarfile.SYMTYPE
                info.linkname = "../../substitute.c"
                archive.addfile(info)
            with self.assertRaises(PRODUCTION_MODULE.ProducerError):
                PRODUCTION_MODULE.extract_authenticated_entrypoint(unsafe, expected)

            duplicate = root / "duplicate.tar.xz"
            with tarfile.open(duplicate, "w:xz") as archive:
                for _index in range(2):
                    info = tarfile.TarInfo("Python-3.14.7/Programs/python.c")
                    info.size = len(source)
                    archive.addfile(info, io.BytesIO(source))
            with self.assertRaises(PRODUCTION_MODULE.ProducerError):
                PRODUCTION_MODULE.extract_authenticated_entrypoint(duplicate, expected)

    def test_producer_closure_authenticates_implementation_inputs_and_tests(self) -> None:
        document = json.loads(RUNTIME_CUSTODY.read_text(encoding="ascii"))
        records = document["producer_closure"]
        expected = {
            "tools/build_macos_release_python_inputs_manifest.py",
            "tools/install_macos_release_python_inputs.py",
            "tools/macos_release_python_entrypoint.c",
            "tools/macos_release_python_inputs.custody.json",
            "tools/macos_release_python_owner_launcher.c",
            "tools/macos_release_python_runtime_production.py",
            "tools/materialize_macos_release_python_psf_candidate.py",
            "tools/release_python_archive_custody.sh",
            "tools/test_macos_release_python_inputs_custody.py",
            "tools/test_macos_release_python_owner_launcher.py",
            "tools/test_macos_release_python_runtime_receipt.py",
            "tools/test_release_gate_determinism.py",
            "tools/test_release_python_archive_custody.py",
            "tools/toolchain-pins.json",
        }
        self.assertEqual({record["path"] for record in records}, expected)
        for record in records:
            self.assertEqual(
                record["sha256"],
                hashlib.sha256((ROOT / record["path"]).read_bytes()).hexdigest(),
            )
        self.assertEqual(
            PRODUCER_MODULE.EXPECTED_CUSTODY_SHA256,
            hashlib.sha256(RUNTIME_CUSTODY.read_bytes()).hexdigest(),
        )

    def test_producer_closure_refuses_one_perturbed_member(self) -> None:
        document = json.loads(RUNTIME_CUSTODY.read_text(encoding="ascii"))
        with tempfile.TemporaryDirectory(prefix="wins-rp-closure-", dir="/private/tmp") as raw:
            copied_root = Path(raw)
            for record in document["producer_closure"]:
                source = ROOT / record["path"]
                target = copied_root / record["path"]
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                shutil.copyfile(source, target)
            copied_custody = copied_root / "tools/macos_release_python_runtime.custody.json"
            shutil.copyfile(RUNTIME_CUSTODY, copied_custody)
            implementation = copied_root / "tools/macos_release_python_runtime_production.py"
            implementation.write_bytes(implementation.read_bytes() + b"\n")
            original_root = PRODUCER_MODULE.ROOT
            original_custody = PRODUCER_MODULE.CUSTODY
            try:
                PRODUCER_MODULE.ROOT = copied_root
                PRODUCER_MODULE.CUSTODY = copied_custody
                with self.assertRaisesRegex(
                    PRODUCER_MODULE.EntrypointError,
                    "closure digest mismatch",
                ):
                    PRODUCER_MODULE.authenticated_closure()
            finally:
                PRODUCER_MODULE.ROOT = original_root
                PRODUCER_MODULE.CUSTODY = original_custody

    def test_direct_entrypoint_is_exact_cpython_3_14_7_source(self) -> None:
        self.assertEqual(
            GENERATOR_MODULE.digest(ENTRYPOINT_SOURCE.read_bytes()),
            "e95aa9b44746ea3b42859fdbbd07cda8f223e78e49556678d87f1283fcfaa1f0",
        )


if __name__ == "__main__":
    unittest.main()
