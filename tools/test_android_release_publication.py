#!/usr/bin/env python3
"""Failure-injection tests for group-consistent Android publication."""

from __future__ import annotations

import io
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parent.parent
HELPER = ROOT / "tools" / "android_release_publication.py"
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

import verify_android_aab_signers as signers  # noqa: E402


def der_len(size: int) -> bytes:
    if size < 0x80:
        return bytes([size])
    raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + der_len(len(body)) + body


def fake_cert(cn: str) -> bytes:
    cn_oid = tlv(0x06, bytes.fromhex("550403"))
    cn_value = tlv(0x0C, cn.encode("ascii"))
    subject = tlv(0x30, tlv(0x31, tlv(0x30, cn_oid + cn_value)))
    tbs = tlv(0x30, tlv(0x02, b"\x01") + subject)
    algorithm = tlv(0x30, tlv(0x06, bytes.fromhex("2a864886f70d01010b")))
    return tlv(0x30, tbs + algorithm + tlv(0x03, b"\x00\x00"))


def fake_pkcs7(certificate: bytes) -> bytes:
    signed_data_oid = tlv(0x06, bytes.fromhex("2a864886f70d010702"))
    version = tlv(0x02, b"\x01")
    digest_algorithms = tlv(0x31, b"")
    content_info = tlv(
        0x30, tlv(0x06, bytes.fromhex("2a864886f70d010701"))
    )
    certificates = tlv(0xA0, certificate)
    signer_info = tlv(
        0x30, tlv(0x02, b"\x01") + tlv(0x30, b"") + tlv(0x30, b"")
    )
    signed = tlv(
        0x30,
        version
        + digest_algorithms
        + content_info
        + certificates
        + tlv(0x31, signer_info),
    )
    return tlv(0x30, signed_data_oid + tlv(0xA0, signed))


SIGNING_BLOCK = fake_pkcs7(fake_cert("Win's VPN Test Upload"))


def encode_aab_proto_manifest(form: str, version_code: int) -> bytes:
    android = signers.ANDROID_NS

    def node(name: str, attributes: list[bytes], children: list[bytes] | None = None) -> bytes:
        return signers.encode_xml_node_element(
            signers.encode_xml_element(name, attributes, children or [])
        )

    def named(tag: str, value: str) -> bytes:
        return node(
            tag,
            [
                signers.encode_xml_attribute(
                    "name",
                    value,
                    namespace=android,
                    resource_id=signers.ATTR_NAME,
                )
            ],
        )

    children: list[bytes] = [
        node(
            "uses-sdk",
            [
                signers.encode_xml_attribute(
                    "minSdkVersion",
                    "24",
                    namespace=android,
                    compiled=signers.encode_compiled_int(24),
                ),
                signers.encode_xml_attribute(
                    "targetSdkVersion",
                    "36",
                    namespace=android,
                    compiled=signers.encode_compiled_int(36),
                ),
            ],
        )
    ]
    categories: list[str] = []
    if form == "tv":
        children.append(named("uses-feature", "android.software.leanback"))
        categories.append("android.intent.category.LEANBACK_LAUNCHER")
    if form == "wear":
        children.append(
            node(
                "uses-feature",
                [
                    signers.encode_xml_attribute(
                        "name",
                        "android.hardware.type.watch",
                        namespace=android,
                        resource_id=signers.ATTR_NAME,
                    ),
                    signers.encode_xml_attribute(
                        "required",
                        "true",
                        namespace=android,
                        resource_id=signers.ATTR_REQUIRED,
                        compiled=signers.encode_compiled_bool(True),
                    ),
                ],
            )
        )
    intent_children = [named("action", "android.intent.action.MAIN")]
    for category in categories:
        intent_children.append(named("category", category))
    activity = node(
        "activity",
        [
            signers.encode_xml_attribute(
                "name",
                "org.winsvpn.app.MainActivity",
                namespace=android,
                resource_id=signers.ATTR_NAME,
            )
        ],
        [node("intent-filter", [], intent_children)],
    )
    children.append(node("application", [], [activity]))
    return signers.encode_xml_node_element(
        signers.encode_xml_element(
            "manifest",
            [
                signers.encode_xml_attribute("package", "org.winsvpn.app"),
                signers.encode_xml_attribute(
                    "versionName",
                    "1.0.16",
                    namespace=android,
                    resource_id=signers.ATTR_VERSION_NAME,
                ),
                signers.encode_xml_attribute(
                    "versionCode",
                    str(version_code),
                    namespace=android,
                    resource_id=signers.ATTR_VERSION_CODE,
                    compiled=signers.encode_compiled_int(version_code),
                ),
            ],
            children,
            ns_decls=[signers.encode_xml_namespace("android", android)],
        )
    )


def package_spec(destination_name: str) -> tuple[str, str, int]:
    kind = "apk" if destination_name.endswith(".apk") else "aab"
    if "tv" in destination_name:
        return kind, "tv", 3302
    return kind, "phone", 33


def write_signed_package(
    path: pathlib.Path,
    marker: str,
    *,
    kind: str = "apk",
    form: str = "phone",
    version_code: int = 33,
    signing_block: bytes = SIGNING_BLOCK,
) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("marker.txt", marker)
        archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\n\r\n")
        archive.writestr("META-INF/CERT.SF", "Signature-Version: 1.0\r\n\r\n")
        archive.writestr("META-INF/CERT.RSA", signing_block)
        if kind == "aab":
            archive.writestr(
                "base/manifest/AndroidManifest.xml",
                encode_aab_proto_manifest(form, version_code),
            )
        else:
            archive.writestr(
                "AndroidManifest.xml",
                signers.encode_apk_binary_manifest(
                    package="org.winsvpn.app",
                    version_name="1.0.16",
                    version_code=version_code,
                    form="tv" if form == "tv" else "phone",
                ),
            )
    path.write_bytes(buffer.getvalue())


def package_marker(path: pathlib.Path) -> str:
    with zipfile.ZipFile(path) as archive:
        return archive.read("marker.txt").decode("utf-8")


def write_symbol_dir(path: pathlib.Path, marker_name: str, marker: str) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / marker_name).write_text(marker, encoding="utf-8")
    (path / "proguard-mapping.txt").write_bytes(b"# compiler: R8\n" + b"x" * 64)
    (path / "app.arm64-v8a.symbols").write_bytes(b"S" * 64)


class AndroidReleasePublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_parent = pathlib.Path("/private/tmp") if sys.platform == "darwin" else None
        self.temporary = tempfile.TemporaryDirectory(dir=temporary_parent)
        self.root = pathlib.Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.state = self.repo / ".artifacts" / "android-release-publication.state.json"
        self.pairs: list[tuple[pathlib.Path, pathlib.Path]] = []
        definitions = (
            (
                "directory",
                self.repo / ".artifacts/private-release-symbols/android-apk",
                "1.0.16+33",
            ),
            (
                "directory",
                self.repo / ".artifacts/private-release-symbols/android-aab",
                "1.0.16+33",
            ),
            (
                "directory",
                self.repo / ".artifacts/private-release-symbols/android-tv-apk",
                "1.0.16+33",
            ),
            (
                "directory",
                self.repo / ".artifacts/private-release-symbols/android-tv-aab",
                "1.0.16+33",
            ),
            ("file", self.repo / "build/app/outputs/flutter-apk", "app-release.apk"),
            ("file", self.repo / "build/app/outputs/bundle/release", "app-release.aab"),
            ("file", self.repo / "build/app/outputs/flutter-apk", "app-tv-release.apk"),
            ("file", self.repo / "build/app/outputs/bundle/tvRelease", "app-tv-release.aab"),
        )
        for index, (kind, parent, destination_name) in enumerate(definitions):
            parent.mkdir(parents=True, exist_ok=True)
            prepared = parent / f".winsvpn-android-publication-prepared-{index}"
            destination = parent / destination_name
            if kind == "directory":
                write_symbol_dir(destination, "old.txt", f"old-{index}\n")
            else:
                pkg_kind, form, version_code = package_spec(destination_name)
                write_signed_package(
                    destination,
                    f"old-{index}\n",
                    kind=pkg_kind,
                    form=form,
                    version_code=version_code,
                )
            self.pairs.append((prepared, destination))
        self.restore_prepared_outputs()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def command(self, action: str, *extra: str) -> list[str]:
        result = [sys.executable, str(HELPER), action, "--state", str(self.state)]
        if action == "commit":
            for prepared, destination in self.pairs:
                result.extend(("--pair", str(prepared), str(destination)))
        result.extend(extra)
        return result

    def restore_prepared_outputs(self) -> None:
        for index, (prepared, _) in enumerate(self.pairs):
            if prepared.exists() or prepared.is_symlink():
                continue
            destination = self.pairs[index][1]
            is_symbol_directory = "private-release-symbols" in destination.parts
            if is_symbol_directory:
                write_symbol_dir(prepared, "new.txt", f"new-{index}\n")
            else:
                pkg_kind, form, version_code = package_spec(destination.name)
                write_signed_package(
                    prepared,
                    f"new-{index}\n",
                    kind=pkg_kind,
                    form=form,
                    version_code=version_code,
                )

    def extend_with_tv_aab_pairs(self) -> None:
        extra_definitions = (
            (
                "directory",
                self.repo / ".artifacts/private-release-symbols/android-tv-aab",
                "1.0.16+33",
            ),
            (
                "file",
                self.repo / "build/app/outputs/bundle/tvRelease",
                "app-tv-release.aab",
            ),
        )
        for offset, (kind, parent, destination_name) in enumerate(
            extra_definitions,
            start=len(self.pairs),
        ):
            parent.mkdir(parents=True, exist_ok=True)
            prepared = parent / f".winsvpn-android-publication-prepared-{offset}"
            destination = parent / destination_name
            if kind == "directory":
                write_symbol_dir(destination, "old.txt", f"old-{offset}\n")
                write_symbol_dir(prepared, "new.txt", f"new-{offset}\n")
            else:
                pkg_kind, form, version_code = package_spec(destination_name)
                write_signed_package(
                    destination,
                    f"old-{offset}\n",
                    kind=pkg_kind,
                    form=form,
                    version_code=version_code,
                )
                write_signed_package(
                    prepared,
                    f"new-{offset}\n",
                    kind=pkg_kind,
                    form=form,
                    version_code=version_code,
                )
            self.pairs.append((prepared, destination))

    def select_phone_and_tv_aab_pairs(self) -> None:
        # Phone APK/AAB plus TV AAB only: six pairs, missing TV APK.
        self.pairs = [self.pairs[index] for index in (0, 1, 3, 4, 5, 7)]

    def run_helper(
        self,
        action: str,
        *extra: str,
        expect_success: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            self.command(action, *extra),
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if expect_success:
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            result = json.loads(completed.stdout)
            self.assertTrue(result["ok"])
        else:
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        return completed

    def assert_old_destinations_and_new_prepared(self) -> None:
        for index, (prepared, destination) in enumerate(self.pairs):
            if prepared.is_dir():
                self.assertEqual(
                    (prepared / "new.txt").read_text(encoding="utf-8"),
                    f"new-{index}\n",
                )
                self.assertEqual(
                    (destination / "old.txt").read_text(encoding="utf-8"),
                    f"old-{index}\n",
                )
            else:
                self.assertEqual(package_marker(prepared), f"new-{index}\n")
                self.assertEqual(package_marker(destination), f"old-{index}\n")

    def assert_new_destinations(self) -> None:
        for index, (prepared, destination) in enumerate(self.pairs):
            self.assertFalse(prepared.exists())
            if destination.is_dir():
                self.assertEqual(
                    (destination / "new.txt").read_text(encoding="utf-8"),
                    f"new-{index}\n",
                )
            else:
                self.assertEqual(package_marker(destination), f"new-{index}\n")

    def assert_old_destinations_and_no_prepared(self) -> None:
        for index, (prepared, destination) in enumerate(self.pairs):
            self.assertFalse(prepared.exists())
            if destination.is_dir():
                self.assertEqual(
                    (destination / "old.txt").read_text(encoding="utf-8"),
                    f"old-{index}\n",
                )
            else:
                self.assertEqual(package_marker(destination), f"old-{index}\n")

    def test_every_rename_boundary_rolls_back_the_complete_old_set(self) -> None:
        # Eight pre-existing destinations produce sixteen rename boundaries:
        # old -> backup, then prepared -> destination for each pair.
        for fail_after in range(1, 17):
            with self.subTest(fail_after=fail_after):
                self.run_helper(
                    "commit",
                    "--test-fail-after",
                    str(fail_after),
                    expect_success=False,
                )
                self.assertFalse(self.state.exists())
                self.assert_old_destinations_and_no_prepared()
                self.restore_prepared_outputs()

    def test_every_process_abort_boundary_recovers_the_complete_old_set(self) -> None:
        # Unlike --test-fail-after, this terminates the helper without its
        # caught-error rollback and proves the durable journal is sufficient.
        for abort_after in range(1, 17):
            with self.subTest(abort_after=abort_after):
                completed = subprocess.run(
                    self.command("commit", "--test-abort-after", str(abort_after)),
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(completed.returncode, 86)
                self.assertTrue(self.state.exists())
                recovered = self.run_helper("recover")
                self.assertEqual(json.loads(recovered.stdout)["result"], "rolled_back")
                self.assertFalse(self.state.exists())
                self.assert_old_destinations_and_no_prepared()
                self.restore_prepared_outputs()

    def test_commit_then_explicit_rollback_restores_the_complete_old_set(self) -> None:
        self.run_helper("commit")
        self.assert_new_destinations()
        self.assertTrue(self.state.exists())
        self.run_helper("rollback")
        self.assertFalse(self.state.exists())
        self.assert_old_destinations_and_no_prepared()

    def test_recover_rolls_back_an_unfinalized_committed_set(self) -> None:
        self.run_helper("commit")
        recovered = self.run_helper("recover")
        self.assertEqual(json.loads(recovered.stdout)["result"], "rolled_back")
        self.assertFalse(self.state.exists())
        self.assert_old_destinations_and_no_prepared()

    def test_finalize_keeps_only_the_complete_new_set(self) -> None:
        self.run_helper("commit")
        self.run_helper("finalize")
        self.assertFalse(self.state.exists())
        self.assert_new_destinations()
        backups = list(self.root.rglob(".winsvpn-android-publication-backup-*"))
        self.assertEqual(backups, [])

    def test_recover_finishes_an_interrupted_finalization(self) -> None:
        self.run_helper("commit")
        value = json.loads(self.state.read_text(encoding="utf-8"))
        value["phase"] = "finalizing"
        self.state.write_text(json.dumps(value) + "\n", encoding="utf-8")
        recovered = self.run_helper("recover")
        self.assertEqual(json.loads(recovered.stdout)["result"], "finalized")
        self.assertFalse(self.state.exists())
        self.assert_new_destinations()
        self.assertEqual(
            list(self.root.rglob(".winsvpn-android-publication-backup-*")),
            [],
        )

    def test_fresh_publication_failure_restores_absent_destinations(self) -> None:
        for _, destination in self.pairs:
            if destination.is_dir():
                for child in destination.iterdir():
                    child.unlink()
                destination.rmdir()
            else:
                destination.unlink()
        for fail_after in range(1, 9):
            with self.subTest(fail_after=fail_after):
                self.run_helper(
                    "commit",
                    "--test-fail-after",
                    str(fail_after),
                    expect_success=False,
                )
                self.assertFalse(self.state.exists())
                for prepared, destination in self.pairs:
                    self.assertFalse(prepared.exists())
                    self.assertFalse(destination.exists())
                self.restore_prepared_outputs()

    def test_recover_without_state_is_a_noop(self) -> None:
        completed = self.run_helper("recover")
        self.assertEqual(json.loads(completed.stdout)["result"], "none")
        self.assert_old_destinations_and_new_prepared()

    def test_parent_directory_swap_restore_cannot_fabricate_commit(self) -> None:
        module = self.publication_module()
        parent = self.pairs[4][1].parent
        hidden = parent.with_name(parent.name + "-held")
        real_write_state = module._write_state
        calls = 0

        def swap_after_journal(path: pathlib.Path, value: dict[str, object]) -> None:
            nonlocal calls
            calls += 1
            real_write_state(path, value)
            if calls == 1:
                parent.rename(hidden)
                shutil.copytree(hidden, parent)

        try:
            with mock.patch.object(
                module, "_write_state", side_effect=swap_after_journal
            ):
                with self.assertRaisesRegex(
                    module.PublicationError, "parent directory changed after preflight"
                ):
                    module.commit(
                        self.state,
                        [
                            (str(prepared), str(destination))
                            for prepared, destination in self.pairs
                        ],
                        None,
                        None,
                    )
            self.assertTrue(self.state.is_file())
        finally:
            if hidden.is_dir():
                shutil.rmtree(parent)
                hidden.rename(parent)
        self.assertEqual(module.recover(self.state), "rolled_back")
        self.assert_old_destinations_and_no_prepared()

    def test_rejects_a_symbolic_prepared_output_before_mutation(self) -> None:
        prepared, destination = self.pairs[0]
        target = prepared.with_name("unsafe-target")
        prepared.rename(target)
        try:
            prepared.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("Symbolic links are unavailable on this host")
        completed = self.run_helper("commit", expect_success=False)
        self.assertIn("symbolic link", completed.stderr)
        self.assertFalse(self.state.exists())
        self.assertEqual(
            (destination / "old.txt").read_text(encoding="utf-8"),
            "old-0\n",
        )

    def test_rejects_a_wrong_prepared_output_kind_before_mutation(self) -> None:
        prepared, destination = self.pairs[4]
        prepared.unlink()
        prepared.mkdir()
        (prepared / "not-an-apk.txt").write_text("new\n", encoding="utf-8")
        completed = self.run_helper("commit", expect_success=False)
        self.assertIn("must be a file", completed.stderr)
        self.assertFalse(self.state.exists())
        self.assertEqual(package_marker(destination), "old-4\n")

    def test_rejects_mismatched_symbol_version_destinations_before_mutation(self) -> None:
        prepared, destination = self.pairs[1]
        replacement = destination.with_name("1.0.14+29")
        destination.rename(replacement)
        self.pairs[1] = (prepared, replacement)
        completed = self.run_helper("commit", expect_success=False)
        self.assertIn("same release version identity", completed.stderr)
        self.assertFalse(self.state.exists())
        self.assertEqual(
            (replacement / "old.txt").read_text(encoding="utf-8"),
            "old-1\n",
        )

    def test_recover_rejects_a_noncanonical_state_path(self) -> None:
        outside_state = self.root / "arbitrary-state.json"
        completed = subprocess.run(
            [
                sys.executable,
                str(HELPER),
                "recover",
                "--state",
                str(outside_state),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("<repo>/.artifacts", completed.stderr)
        self.assert_old_destinations_and_new_prepared()

    def test_tampered_state_cannot_name_an_outside_destination(self) -> None:
        sentinel = self.root / "outside-sentinel.txt"
        sentinel.write_text("preserve\n", encoding="utf-8")
        self.run_helper("commit")
        value = json.loads(self.state.read_text(encoding="utf-8"))
        value["pairs"][0]["destination"] = str(sentinel)
        self.state.write_text(json.dumps(value) + "\n", encoding="utf-8")
        completed = self.run_helper("recover", expect_success=False)
        self.assertIn("canonical Android output", completed.stderr)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve\n")

    def test_tampered_state_cannot_mix_symbol_version_identities(self) -> None:
        self.run_helper("commit")
        value = json.loads(self.state.read_text(encoding="utf-8"))
        record = value["pairs"][1]
        destination = pathlib.Path(record["destination"]).with_name("1.0.14+29")
        record["destination"] = str(destination)
        record["backup"] = str(
            destination.parent
            / f".winsvpn-android-publication-backup-{value['transaction_id']}-1"
        )
        self.state.write_text(json.dumps(value) + "\n", encoding="utf-8")
        completed = self.run_helper("recover", expect_success=False)
        self.assertIn("mixes Android", completed.stderr)
        self.assert_new_destinations()

    def test_phone_only_four_pair_transaction_is_rejected(self) -> None:
        self.pairs = [self.pairs[index] for index in (0, 1, 4, 5)]
        completed = self.run_helper("commit", expect_success=False)
        self.assertIn("eight complete phone-plus-TV pairs", completed.stderr)
        self.assertFalse(self.state.exists())
        self.assertEqual(package_marker(self.pairs[2][1]), "old-4\n")

    def test_six_pair_phone_and_tv_aab_transaction_is_rejected(self) -> None:
        self.select_phone_and_tv_aab_pairs()
        completed = self.run_helper("commit", expect_success=False)
        self.assertIn("eight complete phone-plus-TV pairs", completed.stderr)
        self.assertFalse(self.state.exists())

    def test_six_pair_phone_and_tv_apk_transaction_is_rejected(self) -> None:
        self.pairs = [self.pairs[index] for index in (0, 1, 2, 4, 5, 6)]
        completed = self.run_helper("commit", expect_success=False)
        self.assertIn("eight complete phone-plus-TV pairs", completed.stderr)
        self.assertFalse(self.state.exists())

    def test_complete_eight_pair_phone_and_tv_transaction(self) -> None:
        self.run_helper("commit")
        self.run_helper("finalize")
        self.assert_new_destinations()

    def test_eight_pair_every_rename_boundary_rolls_back(self) -> None:
        for fail_after in range(1, 17):
            with self.subTest(fail_after=fail_after):
                self.run_helper(
                    "commit",
                    "--test-fail-after",
                    str(fail_after),
                    expect_success=False,
                )
                self.assertFalse(self.state.exists())
                self.assert_old_destinations_and_no_prepared()
                self.restore_prepared_outputs()

    def test_eight_pair_every_process_abort_boundary_recovers(self) -> None:
        for abort_after in range(1, 17):
            with self.subTest(abort_after=abort_after):
                completed = subprocess.run(
                    self.command("commit", "--test-abort-after", str(abort_after)),
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(completed.returncode, 86)
                self.assertTrue(self.state.exists())
                recovered = self.run_helper("recover")
                self.assertEqual(json.loads(recovered.stdout)["result"], "rolled_back")
                self.assertFalse(self.state.exists())
                self.assert_old_destinations_and_no_prepared()
                self.restore_prepared_outputs()


    def test_symbol_destinations_bind_canonical_1015_identity(self) -> None:
        for prepared, destination in self.pairs:
            if destination.is_dir():
                self.assertEqual(destination.name, "1.0.16+33")
        self.run_helper("commit")
        self.run_helper("finalize")
        for _, destination in self.pairs:
            if destination.is_dir():
                self.assertEqual(destination.name, "1.0.16+33")
                self.assertTrue((destination / "new.txt").is_file())
                self.assertTrue((destination / "proguard-mapping.txt").is_file())
                self.assertTrue((destination / "app.arm64-v8a.symbols").is_file())

    def test_rejects_unsigned_package_bytes_before_mutation(self) -> None:
        prepared, destination = self.pairs[4]
        prepared.write_text("not-a-signed-apk\n", encoding="utf-8")
        completed = self.run_helper("commit", expect_success=False)
        self.assertIn("Android ZIP package", completed.stderr)
        self.assertFalse(self.state.exists())
        self.assertEqual(package_marker(destination), "old-4\n")

    def test_rejects_missing_produced_package_bytes_as_owner_blocked(self) -> None:
        prepared, destination = self.pairs[5]
        prepared.unlink()
        completed = self.run_helper("commit", expect_success=False)
        self.assertIn(
            "OWNER-BLOCKED: produced Android AAB/APK bytes are absent",
            completed.stderr,
        )
        self.assertFalse(self.state.exists())
        self.assertEqual(package_marker(destination), "old-5\n")

    def test_rejects_zip_without_owner_signature_block(self) -> None:
        prepared, destination = self.pairs[5]
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("marker.txt", "unsigned\n")
        prepared.write_bytes(buffer.getvalue())
        completed = self.run_helper("commit", expect_success=False)
        self.assertIn("embedded JAR certificate block", completed.stderr)
        self.assertFalse(self.state.exists())
        self.assertEqual(package_marker(destination), "old-5\n")

    def test_rejects_unparseable_fabricated_signature_block(self) -> None:
        prepared, destination = self.pairs[5]
        write_signed_package(
            prepared,
            "new-5\n",
            kind="aab",
            form="phone",
            version_code=33,
            signing_block=b"fabricated-signature-block",
        )
        completed = self.run_helper("commit", expect_success=False)
        self.assertIn("parseable signer certificate", completed.stderr)
        self.assertFalse(self.state.exists())
        self.assertEqual(package_marker(destination), "old-5\n")

    def test_rejects_symbol_dir_without_r8_or_flutter_evidence(self) -> None:
        prepared, destination = self.pairs[0]
        for child in prepared.iterdir():
            if child.name != "new.txt":
                child.unlink()
        completed = self.run_helper("commit", expect_success=False)
        self.assertIn("private R8 mapping or Flutter .symbols evidence", completed.stderr)
        self.assertFalse(self.state.exists())
        self.assertEqual((destination / "old.txt").read_text(encoding="utf-8"), "old-0\n")

    def publication_module(self):
        import android_release_publication as publication

        return publication

    def run_preflight(
        self,
        phone: pathlib.Path,
        tv: pathlib.Path,
        wear: pathlib.Path,
        *extra: str,
        expect_success: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            [
                sys.executable,
                str(HELPER),
                "preflight",
                "--phone-aab",
                str(phone),
                "--tv-aab",
                str(tv),
                "--wear-aab",
                str(wear),
                *extra,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if expect_success:
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            result = json.loads(completed.stdout)
            self.assertTrue(result["ok"])
        else:
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        return completed

    def test_rejects_identity_less_signed_zip_before_mutation(self) -> None:
        prepared, destination = self.pairs[5]
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("marker.txt", "new-5\n")
            archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\n\r\n")
            archive.writestr("META-INF/CERT.SF", "Signature-Version: 1.0\r\n\r\n")
            archive.writestr("META-INF/CERT.RSA", SIGNING_BLOCK)
        prepared.write_bytes(buffer.getvalue())
        completed = self.run_helper("commit", expect_success=False)
        self.assertIn("package/version/build identity", completed.stderr)
        self.assertFalse(self.state.exists())
        self.assertEqual(package_marker(destination), "old-5\n")

    def test_rejects_phone_identity_at_tv_aab_destination(self) -> None:
        prepared, destination = self.pairs[7]
        write_signed_package(
            prepared, "new-7\n", kind="aab", form="phone", version_code=33
        )
        completed = self.run_helper("commit", expect_success=False)
        self.assertIn("another exact candidate", completed.stderr)
        self.assertFalse(self.state.exists())
        self.assertEqual(package_marker(destination), "old-7\n")

    def test_rejects_tv_identity_at_phone_apk_destination(self) -> None:
        prepared, destination = self.pairs[4]
        write_signed_package(
            prepared, "new-4\n", kind="apk", form="tv", version_code=3302
        )
        completed = self.run_helper("commit", expect_success=False)
        self.assertIn("another exact candidate", completed.stderr)
        self.assertFalse(self.state.exists())
        self.assertEqual(package_marker(destination), "old-4\n")

    def test_rejects_wear_identity_at_phone_aab_destination(self) -> None:
        prepared, destination = self.pairs[5]
        write_signed_package(
            prepared, "new-5\n", kind="aab", form="wear", version_code=3301
        )
        completed = self.run_helper("commit", expect_success=False)
        self.assertIn("Wear candidate identity cannot enter phone/TV publication", completed.stderr)
        self.assertFalse(self.state.exists())
        self.assertEqual(package_marker(destination), "old-5\n")

    def test_rejects_wear_destination_path_before_mutation(self) -> None:
        prepared, _destination = self.pairs[5]
        parent = self.repo / "build" / "wear" / "bundle"
        parent.mkdir(parents=True)
        new_prepared = parent / prepared.name
        new_destination = parent / "app-release.aab"
        prepared.rename(new_prepared)
        write_signed_package(
            new_destination, "old-wear\n", kind="aab", form="phone", version_code=33
        )
        self.pairs[5] = (new_prepared, new_destination)
        completed = self.run_helper("commit", expect_success=False)
        self.assertIn("Wear candidate identity cannot enter phone/TV publication", completed.stderr)
        self.assertFalse(self.state.exists())

    def test_rejects_mismatched_owner_signing_identity(self) -> None:
        prepared, destination = self.pairs[5]
        write_signed_package(
            prepared,
            "new-5\n",
            kind="aab",
            form="phone",
            version_code=33,
            signing_block=fake_pkcs7(fake_cert("Other Test Upload")),
        )
        completed = self.run_helper("commit", expect_success=False)
        self.assertIn("share one embedded certificate identity", completed.stderr)
        self.assertFalse(self.state.exists())
        self.assertEqual(package_marker(destination), "old-5\n")

    def test_rejects_debug_signer_before_mutation(self) -> None:
        prepared, destination = self.pairs[4]
        write_signed_package(
            prepared,
            "new-4\n",
            kind="apk",
            form="phone",
            version_code=33,
            signing_block=b"CN=Android Debug\ntest-signature-block",
        )
        completed = self.run_helper("commit", expect_success=False)
        self.assertIn("Android debug signer", completed.stderr)
        self.assertFalse(self.state.exists())
        self.assertEqual(package_marker(destination), "old-4\n")

    def test_equal_candidate_bytes_still_use_the_recoverable_transaction(self) -> None:
        self.run_helper("commit")
        self.run_helper("finalize")
        for prepared, destination in self.pairs:
            if destination.is_dir():
                shutil.copytree(destination, prepared)
            else:
                shutil.copyfile(destination, prepared)
        completed = self.run_helper("commit")
        self.assertEqual(json.loads(completed.stdout)["result"], "committed")
        self.assertTrue(self.state.exists())
        self.run_helper("finalize")
        self.assert_new_destinations()

    def test_finalize_re_audits_package_identity(self) -> None:
        self.run_helper("commit")
        value = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertRegex(value["preflight_digest"], r"^[0-9a-f]{64}$")
        self.assertEqual(value["pairs"][5]["identity"]["package"], "org.winsvpn.app")
        self.assertEqual(value["pairs"][5]["identity"]["version_code"], 33)
        self.assertEqual(value["pairs"][7]["identity"]["version_code"], 3302)
        self.run_helper("finalize")
        self.assert_new_destinations()

    def test_tampered_state_cannot_swap_package_identity(self) -> None:
        self.run_helper("commit")
        value = json.loads(self.state.read_text(encoding="utf-8"))
        value["pairs"][5]["identity"]["version_code"] = 3302
        value["pairs"][5]["identity"]["is_tv"] = True
        self.state.write_text(json.dumps(value) + "\n", encoding="utf-8")
        completed = self.run_helper("recover", expect_success=False)
        self.assertIn("package/version/build identity", completed.stderr)
        self.assert_new_destinations()

    def test_preflight_preserves_owner_blocked_store_authority(self) -> None:
        wear = self.root / "wear-candidate.aab"
        write_signed_package(wear, "wear\n", kind="aab", form="wear", version_code=3301)
        completed = self.run_preflight(
            self.pairs[5][0],
            self.pairs[7][0],
            wear,
            expect_success=False,
        )
        self.assertIn(
            "OWNER-BLOCKED: Android Play Store publication authority is absent",
            completed.stderr,
        )

    def test_preflight_rejects_self_minted_authorization_and_replay(self) -> None:
        wear = self.root / "wear-candidate.aab"
        write_signed_package(wear, "wear\n", kind="aab", form="wear", version_code=3301)
        phone = self.pairs[5][0]
        tv = self.pairs[7][0]
        token = "AUTHORIZE_ANDROID_AAB_PUBLICATION_SHA256_" + ("a" * 64)
        for _attempt in range(2):
            completed = self.run_preflight(
                phone,
                tv,
                wear,
                "--confirm-owner-authorization",
                token,
                expect_success=False,
            )
            self.assertIn(
                "OWNER-BLOCKED: Android Play Store publication authority is absent",
                completed.stderr,
            )
            self.assertNotIn('"publication_authorized":true', completed.stdout)

    def test_preflight_rejects_swapped_phone_and_tv_candidates(self) -> None:
        wear = self.root / "wear-candidate.aab"
        write_signed_package(wear, "wear\n", kind="aab", form="wear", version_code=3301)
        completed = self.run_preflight(
            self.pairs[7][0],
            self.pairs[5][0],
            wear,
            "--confirm-owner-authorization",
            "AUTHORIZE_ANDROID_AAB_PUBLICATION_SHA256_" + ("a" * 64),
            expect_success=False,
        )
        self.assertIn("another exact candidate", completed.stderr)

    def test_preflight_rejects_wear_candidate_in_phone_slot(self) -> None:
        wear = self.root / "wear-candidate.aab"
        write_signed_package(wear, "wear\n", kind="aab", form="wear", version_code=3301)
        completed = self.run_preflight(
            wear,
            self.pairs[7][0],
            self.pairs[5][0],
            expect_success=False,
        )
        self.assertIn("Wear candidate identity cannot enter phone/TV publication", completed.stderr)

    def test_publication_helper_never_calls_play_or_stores_credentials(self) -> None:
        source = HELPER.read_text(encoding="utf-8")
        for forbidden in (
            "androidpublisher",
            "play.google.com",
            "googleapis.com",
            "GOOGLE_APPLICATION_CREDENTIALS",
        ):
            self.assertNotIn(forbidden, source)
        self.assertNotIn("wear_os", source)
        self.assertNotIn("wear-os", source)
        self.assertNotIn('"publication_authorized": True', source)
        self.assertNotIn('"result": "authorized"', source)


if __name__ == "__main__":
    unittest.main()
