#!/usr/bin/env python3
"""Hostile contract tests for canonical Linux Winn v3 dual-auth releases."""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import subprocess
import tarfile
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PRODUCER = ROOT / "tools" / "build_linux_release.sh"
DEB_PRODUCER = ROOT / "tools" / "build_linux_deb.sh"
ATTESTATION_NAME = "winn3-dual-auth-release-attestation.json"
DEFINE_ARG = "--dart-define=WINS_WINN3_DUAL_AUTH=true"


def run_producer(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(PRODUCER), *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


class LinuxWinn3DualAuthDefineTest(unittest.TestCase):
    def assert_define_rejected(self, *args: str) -> None:
        result = run_producer("--self-test-winn3-dual-auth-defines", *args)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_exact_true_define_is_accepted_once(self) -> None:
        result = run_producer("--self-test-winn3-dual-auth-defines", DEFINE_ARG)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("DEFINE SELF-TEST: PASS", result.stdout)

    def test_missing_define_is_rejected(self) -> None:
        self.assert_define_rejected()

    def test_false_define_is_rejected(self) -> None:
        self.assert_define_rejected("--dart-define=WINS_WINN3_DUAL_AUTH=false")

    def test_identical_duplicate_is_rejected(self) -> None:
        self.assert_define_rejected(DEFINE_ARG, DEFINE_ARG)

    def test_malformed_defines_are_rejected(self) -> None:
        for malformed in (
            "--dart-define=WINS_WINN3_DUAL_AUTH",
            "--dart-define=WINS_WINN3_DUAL_AUTH=",
            "--dart-define=WINS_WINN3_DUAL_AUTH=TRUE",
            "WINS_WINN3_DUAL_AUTH=true",
            "--dart-define-from-file=hostile.json",
        ):
            with self.subTest(malformed=malformed):
                self.assert_define_rejected(malformed)

    def test_conflicting_true_and_false_is_rejected(self) -> None:
        self.assert_define_rejected(
            DEFINE_ARG,
            "--dart-define=WINS_WINN3_DUAL_AUTH=false",
        )

    def test_secondary_cmake_or_backend_injection_is_forbidden(self) -> None:
        result = run_producer("--self-test-winn3-dual-auth-secondary")
        self.assertEqual(result.returncode, 0, result.stderr)


RELAY_DEFINE_ARG = "--dart-define=WINS_WINN3_RELAY_ENABLED_PLATFORMS=linux"


class LinuxWinn3RelayDefineTest(unittest.TestCase):
    """The Linux release passes the relay define exactly once, as exactly this argv entry."""

    def assert_relay_rejected(self, *args: str) -> subprocess.CompletedProcess[str]:
        result = run_producer("--self-test-winn3-relay-define", *args)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("RELAY DEFINE SELF-TEST: PASS", result.stdout)
        return result

    def test_exact_define_is_accepted_once_among_other_defines(self) -> None:
        result = run_producer(
            "--self-test-winn3-relay-define",
            "--dart-define=WINS_WINN3_ENABLED_PLATFORMS=linux",
            RELAY_DEFINE_ARG,
            DEFINE_ARG,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("LINUX WINN3 RELAY DEFINE SELF-TEST: PASS", result.stdout)

    def test_missing_define_is_rejected(self) -> None:
        self.assertIn("found 0", self.assert_relay_rejected().stderr)
        self.assert_relay_rejected("--dart-define=WINS_WINN3_ENABLED_PLATFORMS=linux")

    def test_duplicate_define_is_rejected(self) -> None:
        self.assertIn(
            "found 2", self.assert_relay_rejected(RELAY_DEFINE_ARG, RELAY_DEFINE_ARG).stderr
        )

    def test_other_platforms_values_and_spellings_are_rejected(self) -> None:
        for hostile in (
            "--dart-define=WINS_WINN3_RELAY_ENABLED_PLATFORMS=android",
            "--dart-define=WINS_WINN3_RELAY_ENABLED_PLATFORMS=ios",
            "--dart-define=WINS_WINN3_RELAY_ENABLED_PLATFORMS=windows",
            "--dart-define=WINS_WINN3_RELAY_ENABLED_PLATFORMS=linux,ios",
            "--dart-define=WINS_WINN3_RELAY_ENABLED_PLATFORMS=Linux",
            "--dart-define=WINS_WINN3_RELAY_ENABLED_PLATFORMS=linux ",
            "--dart-define=WINS_WINN3_RELAY_ENABLED_PLATFORMS=",
            "--dart-define=WINS_WINN3_RELAY_ENABLED_PLATFORMS",
            "WINS_WINN3_RELAY_ENABLED_PLATFORMS=linux",
            "--dart-define-from-file=hostile.json",
        ):
            with self.subTest(hostile=hostile):
                self.assert_relay_rejected(RELAY_DEFINE_ARG, hostile)
                if not hostile.startswith("--dart-define-from-file"):
                    self.assert_relay_rejected(hostile)

    def test_unrelated_enabled_platforms_define_does_not_count_as_relay(self) -> None:
        self.assert_relay_rejected("--dart-define=WINS_WINN3_ENABLED_PLATFORMS=linux")

    def test_secondary_relay_define_is_refused_by_the_release_guard(self) -> None:
        source = PRODUCER.read_text(encoding="utf-8")
        start = source.index("assert_no_secondary_linux_winn3_dual_auth_injection() {")
        end = source.index("\n}\n", start) + 2
        guard = source[start:end]
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            cmake = root / "linux/flutter/Winn3DescriptorRing.cmake"
            backend = root / "linux/flutter/winn3_tool_backend.sh"
            for path in (cmake, backend):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("# baseline\n", encoding="ascii")
            script = 'ROOT="$1"\n' + guard + "\nassert_no_secondary_linux_winn3_dual_auth_injection\n"
            def run_guard() -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    ["bash", "-c", script, "bash", str(root)],
                    capture_output=True, text=True, check=False,
                )
            self.assertEqual(run_guard().returncode, 0)
            encoded = base64.b64encode(
                b"WINS_WINN3_RELAY_ENABLED_PLATFORMS=ios"
            ).decode("ascii")
            cmake.write_text(f'set(WINN3_RING_DART_DEFINES "{encoded}")\n', encoding="ascii")
            result = run_guard()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("secondary encoded WINS_WINN3_RELAY_ENABLED_PLATFORMS", result.stderr)
            cmake.write_text("# baseline\n", encoding="ascii")
            backend.write_text("WINS_WINN3_RELAY_ENABLED_PLATFORMS=ios\n", encoding="ascii")
            result = run_guard()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("secondary plaintext WINS_WINN3_RELAY_ENABLED_PLATFORMS", result.stderr)


class LinuxWinn3DualAuthAttestationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.bundle = pathlib.Path(self.temp.name) / "bundle"
        (self.bundle / "lib").mkdir(parents=True)
        (self.bundle / "wins_vpn").write_bytes(b"linux-runner-fixture\n")
        (self.bundle / "lib" / "libapp.so").write_bytes(b"linux-aot-fixture\n")
        (self.bundle / "winn-datapath").write_bytes(b"winn-datapath-fixture\n")
        self.document = self.make_document()
        self.write_document(self.document)

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def digest(path: pathlib.Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def make_document(self) -> dict[str, object]:
        artifacts = {
            relative: self.digest(self.bundle / relative)
            for relative in ("wins_vpn", "lib/libapp.so", "winn-datapath")
        }
        return {
            "schema_version": 2,
            "contract": "winsvpn-linux-winn3-dual-auth-release-v2",
            "build_mode": "release",
            "dart_define": {
                "name": "WINS_WINN3_DUAL_AUTH",
                "value": "true",
                "occurrences": 1,
                "source": "flutter-cli",
            },
            "native_gates": ["linux_winn3_host_test", "linux_winn_gate_test"],
            "producer": {
                "path": "tools/build_linux_release.sh",
                "sha256": self.digest(PRODUCER),
            },
            "capability_proof": {
                "contract": "winsvpn-linux-compiled-capability-proof-v3",
                "source_path": "lib/winn_protocol_dispatch.dart",
                "source_sha256": "d" * 64,
                "release_input_index_sha256": "e" * 64,
                "define": "WINS_WINN3_DUAL_AUTH=true",
                "enabled_platforms_define": "WINS_WINN3_ENABLED_PLATFORMS=linux",
                "relay_enabled_platforms_define": "WINS_WINN3_RELAY_ENABLED_PLATFORMS=linux",
                "compiled_test": "linux_dual_auth_compiled_capability_test",
                "verified_artifact": "lib/libapp.so",
                "verified_artifact_sha256": artifacts["lib/libapp.so"],
            },
            "artifacts": artifacts,
        }

    def write_document(self, document: dict[str, object]) -> None:
        (self.bundle / ATTESTATION_NAME).write_text(
            json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="ascii",
        )

    def verify_attestation(self) -> subprocess.CompletedProcess[str]:
        return run_producer(
            "--self-test-winn3-dual-auth-attestation",
            str(self.bundle),
        )

    def write_archive(self) -> pathlib.Path:
        archive_path = pathlib.Path(self.temp.name) / "linux-release.tar.gz"
        with tarfile.open(archive_path, "w:gz") as archive:
            for relative in (
                "wins_vpn",
                "lib/libapp.so",
                "winn-datapath",
                ATTESTATION_NAME,
            ):
                archive.add(self.bundle / relative, arcname=relative)
        return archive_path

    def test_exact_release_attestation_is_accepted(self) -> None:
        result = self.verify_attestation()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_attestation_is_rejected(self) -> None:
        (self.bundle / ATTESTATION_NAME).unlink()
        self.assertNotEqual(self.verify_attestation().returncode, 0)

    def test_false_duplicate_malformed_or_conflicting_attestation_is_rejected(self) -> None:
        hostile_defines: tuple[dict[str, object], ...] = (
            {
                "name": "WINS_WINN3_DUAL_AUTH",
                "value": "false",
                "occurrences": 1,
                "source": "flutter-cli",
            },
            {
                "name": "WINS_WINN3_DUAL_AUTH",
                "value": "true",
                "occurrences": 2,
                "source": "flutter-cli",
            },
            {
                "name": "WINS_WINN3_DUAL_AUTH",
                "value": "TRUE",
                "occurrences": 1,
                "source": "flutter-cli",
            },
            {
                "name": "WINS_WINN3_DUAL_AUTH",
                "value": ["true", "false"],
                "occurrences": 2,
                "source": "flutter-cli",
            },
        )
        for hostile in hostile_defines:
            with self.subTest(hostile=hostile):
                document = self.make_document()
                document["dart_define"] = hostile
                self.write_document(document)
                self.assertNotEqual(self.verify_attestation().returncode, 0)

    def test_artifact_or_producer_tampering_is_rejected(self) -> None:
        (self.bundle / "lib" / "libapp.so").write_bytes(b"tampered\n")
        self.assertNotEqual(self.verify_attestation().returncode, 0)
        (self.bundle / "lib" / "libapp.so").write_bytes(b"linux-aot-fixture\n")
        document = self.make_document()
        document["producer"] = {
            "path": "tools/build_linux_release.sh",
            "sha256": "0" * 64,
        }
        self.write_document(document)
        self.assertNotEqual(self.verify_attestation().returncode, 0)

    def test_retired_v1_runtime_report_attestation_is_rejected(self) -> None:
        document = self.make_document()
        document["schema_version"] = 1
        document["contract"] = "winsvpn-linux-winn3-dual-auth-release-v1"
        self.write_document(document)
        self.assertNotEqual(self.verify_attestation().returncode, 0)
        document = self.make_document()
        proof = dict(document["capability_proof"])  # type: ignore[arg-type]
        proof["runtime_report_sha256"] = "f" * 64
        proof["runtime_report"] = {"contract": "winsvpn-linux-final-aot-capability-runtime-v1"}
        document["capability_proof"] = proof
        self.write_document(document)
        result = self.verify_attestation()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("compiled capability proof fields are not exact", result.stderr)

    def test_capability_proof_must_bind_the_linux_enabled_platforms_define(self) -> None:
        for hostile in ("WINS_WINN3_ENABLED_PLATFORMS=android", "", None):
            with self.subTest(hostile=hostile):
                document = self.make_document()
                proof = dict(document["capability_proof"])  # type: ignore[arg-type]
                if hostile is None:
                    del proof["enabled_platforms_define"]
                else:
                    proof["enabled_platforms_define"] = hostile
                document["capability_proof"] = proof
                self.write_document(document)
                self.assertNotEqual(self.verify_attestation().returncode, 0)

    def test_capability_proof_must_bind_the_linux_relay_enabled_platforms_define(self) -> None:
        for hostile in (
            "WINS_WINN3_RELAY_ENABLED_PLATFORMS=android",
            "WINS_WINN3_RELAY_ENABLED_PLATFORMS=linux,ios",
            "WINS_WINN3_ENABLED_PLATFORMS=linux",
            "",
            None,
        ):
            with self.subTest(hostile=hostile):
                document = self.make_document()
                proof = dict(document["capability_proof"])  # type: ignore[arg-type]
                if hostile is None:
                    del proof["relay_enabled_platforms_define"]
                else:
                    proof["relay_enabled_platforms_define"] = hostile
                document["capability_proof"] = proof
                self.write_document(document)
                expected = (
                    "compiled capability proof fields are not exact"
                    if hostile is None
                    else "relay enabled-platforms define"
                )
                bundle = self.verify_attestation()
                self.assertNotEqual(bundle.returncode, 0)
                self.assertIn(expected, bundle.stderr)
                archive = run_producer(
                    "--self-test-winn3-dual-auth-archive", str(self.write_archive())
                )
                self.assertNotEqual(archive.returncode, 0, archive.stdout + archive.stderr)
                self.assertIn(expected, archive.stderr)

    def test_retired_v2_capability_proof_without_relay_is_rejected(self) -> None:
        document = self.make_document()
        proof = dict(document["capability_proof"])  # type: ignore[arg-type]
        proof["contract"] = "winsvpn-linux-compiled-capability-proof-v2"
        del proof["relay_enabled_platforms_define"]
        document["capability_proof"] = proof
        self.write_document(document)
        result = self.verify_attestation()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("compiled capability proof fields are not exact", result.stderr)
        # The v3 field set under the retired v2 name is refused on the name alone.
        proof = dict(self.make_document()["capability_proof"])  # type: ignore[arg-type]
        proof["contract"] = "winsvpn-linux-compiled-capability-proof-v2"
        document = self.make_document()
        document["capability_proof"] = proof
        self.write_document(document)
        renamed = self.verify_attestation()
        self.assertNotEqual(renamed.returncode, 0)
        self.assertIn("compiled capability proof contract is invalid", renamed.stderr)

    def test_archive_verifier_rejects_v1_and_unbound_enabled_platforms(self) -> None:
        document = self.make_document()
        proof = dict(document["capability_proof"])  # type: ignore[arg-type]
        proof["enabled_platforms_define"] = "WINS_WINN3_ENABLED_PLATFORMS=ios"
        document["capability_proof"] = proof
        self.write_document(document)
        archive = self.write_archive()
        hostile = run_producer("--self-test-winn3-dual-auth-archive", str(archive))
        self.assertNotEqual(hostile.returncode, 0, hostile.stdout + hostile.stderr)
        document = self.make_document()
        document["contract"] = "winsvpn-linux-winn3-dual-auth-release-v1"
        self.write_document(document)
        archive = self.write_archive()
        retired = run_producer("--self-test-winn3-dual-auth-archive", str(archive))
        self.assertNotEqual(retired.returncode, 0, retired.stdout + retired.stderr)

    def test_archive_binding_accepts_exact_bytes_and_rejects_tampering(self) -> None:
        archive = self.write_archive()
        valid = run_producer(
            "--self-test-winn3-dual-auth-archive",
            str(archive),
        )
        self.assertEqual(valid.returncode, 0, valid.stderr)

        (self.bundle / "winn-datapath").write_bytes(b"tampered-datapath\n")
        archive = self.write_archive()
        hostile = run_producer(
            "--self-test-winn3-dual-auth-archive",
            str(archive),
        )
        self.assertNotEqual(hostile.returncode, 0, hostile.stdout + hostile.stderr)


class LinuxWinn3DualAuthProducerWiringTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.release_source = PRODUCER.read_text(encoding="utf-8")
        cls.deb_source = DEB_PRODUCER.read_text(encoding="utf-8")

    def test_only_canonical_flutter_release_command_receives_define_array(self) -> None:
        command_start = self.release_source.index("flutter_release_command=(")
        command_end = self.release_source.index("\n)", command_start)
        command = self.release_source[command_start:command_end]
        self.assertEqual(command.count('"${FLUTTER_COMMAND}" build linux --release'), 1)
        self.assertEqual(command.count('"${WINN3_DUAL_AUTH_RELEASE_DEFINES[@]}"'), 1)
        self.assertEqual(
            self.release_source.count('"${WINN3_DUAL_AUTH_RELEASE_DEFINES[@]}"'),
            2,
        )
        self.assertNotIn("--dart-define=WINS_WINN3_DUAL_AUTH", self.deb_source)

    def test_relay_define_reaches_the_release_command_and_probe_exactly_once(self) -> None:
        source = self.release_source
        arg_ref = '"${LINUX_WINN3_RELAY_ENABLED_PLATFORMS_DEFINE_ARG}"'
        defines_ref = '"${LINUX_WINN3_RELAY_RELEASE_DEFINES[@]}"'
        # The release define array holds the one argument and is audited like the
        # dual-auth array: exactly one exact entry, before the build starts.
        self.assertEqual(
            source.count(
                f"LINUX_WINN3_RELAY_RELEASE_DEFINES=({arg_ref})"
            ),
            1,
        )
        command_start = source.index("flutter_release_command=(")
        command_end = source.index("\n)", command_start)
        command = source[command_start:command_end]
        self.assertEqual(command.count(defines_ref), 1)
        self.assertNotIn("WINS_WINN3_RELAY_ENABLED_PLATFORMS", command)
        audit = f"assert_linux_winn3_relay_define_argv {defines_ref}"
        self.assertEqual(source.count(audit), 1)
        self.assertLess(source.index(audit), command_start)
        self.assertGreater(
            source.index(audit),
            source.index('log "Building Linux release"'),
        )
        # The compiled capability probe measures the same argument.
        probe_start = source.index("prove_linux_winn3_dual_auth_compiled_capability() {")
        probe_end = source.index("assert_userspace_awg_runtime_pin_ready() {", probe_start)
        probe = source[probe_start:probe_end]
        self.assertEqual(probe.count(arg_ref), 1, "one flutter test argument")
        self.assertIn(
            "${LINUX_WINN3_ENABLED_PLATFORMS_DEFINE_ARG} "
            "${LINUX_WINN3_RELAY_ENABLED_PLATFORMS_DEFINE_ARG} "
            "${WINN3_DUAL_AUTH_DEFINE_ARG}",
            probe,
            "the refusal message names the relay define that was measured",
        )
        self.assertEqual(
            source.count(
                'LINUX_WINN3_RELAY_ENABLED_PLATFORMS_DEFINE_ARG='
                '"--dart-define=WINS_WINN3_RELAY_ENABLED_PLATFORMS=linux"'
            ),
            1,
        )
        # The define text itself is spelled exactly once in the producer.
        self.assertEqual(
            source.count("--dart-define=WINS_WINN3_RELAY_ENABLED_PLATFORMS="), 1
        )
        # The Debian packager only packages a bundle; it never owns the define.
        self.assertNotIn("WINS_WINN3_RELAY_ENABLED_PLATFORMS", self.deb_source)

    def test_expanded_release_command_carries_the_relay_define_exactly_once(self) -> None:
        # Evaluate the producer's own array, not a copy of it: the relay define
        # must appear once, for linux only, and must pass the producer's audit.
        script = r"""
set -Eeuo pipefail
src="$1"
eval "$(sed -n '/^WINN3_DUAL_AUTH_DEFINE_NAME=/,/^LINUX_WINN3_RELAY_RELEASE_DEFINES=/p' "$src")"
eval "$(sed -n '/^assert_linux_winn3_relay_define_argv() {/,/^}/p' "$src")"
FLUTTER_COMMAND=flutter
LINUX_SYMBOL_DIR=/symbols
WINN3_RING_DEFINES=("--dart-define=WINS_WINN3_DESCRIPTOR_RING_SHA256=0")
eval "$(sed -n '/^flutter_release_command=(/,/^)/p' "$src")"
assert_linux_winn3_relay_define_argv "${flutter_release_command[@]}"
printf '%s\n' "${flutter_release_command[@]}"
"""
        result = subprocess.run(
            ["bash", "-c", script, "bash", str(PRODUCER)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = result.stdout.splitlines()
        self.assertEqual(arguments[:4], ["flutter", "build", "linux", "--release"])
        self.assertEqual(
            [arg for arg in arguments if "WINS_WINN3_RELAY_ENABLED_PLATFORMS" in arg],
            [RELAY_DEFINE_ARG],
        )
        self.assertEqual(
            [arg for arg in arguments if "WINS_WINN3_ENABLED_PLATFORMS" in arg
             and "RELAY" not in arg],
            ["--dart-define=WINS_WINN3_ENABLED_PLATFORMS=linux"],
        )

    def test_native_gates_and_attestation_precede_packaging(self) -> None:
        source = self.release_source
        build = source.index('"${FLUTTER_COMMAND}" build linux --release')
        host_gate = source.index('cmake --build "${LINUX_CMAKE_BUILD_DIR}" --target linux_winn3_host_test', build)
        fallback_gate = source.index('cmake --build "${LINUX_CMAKE_BUILD_DIR}" --target linux_winn_gate_test', host_gate)
        attestation = source.index('write_linux_winn3_dual_auth_attestation "${BUNDLE_DIR}"', fallback_gate)
        package = source.index('log "Packaging release bundle"', attestation)
        self.assertLess(build, host_gate)
        self.assertLess(host_gate, fallback_gate)
        self.assertLess(fallback_gate, attestation)
        self.assertLess(attestation, package)

    def test_formal_receipt_and_deb_revalidate_bound_artifact(self) -> None:
        receipt_function = self.release_source[
            self.release_source.index("complete_formal_linux_receipt()") :
            self.release_source.index("reject_unsupported_release_switches()")
        ]
        self.assertLess(
            receipt_function.index("verify_linux_winn3_dual_auth_archive"),
            receipt_function.index('release_dependency_freeze.py" finish-build'),
        )
        self.assertEqual(
            self.deb_source.count("--verify-winn3-dual-auth-bundle"),
            2,
        )


if __name__ == "__main__":
    unittest.main()
