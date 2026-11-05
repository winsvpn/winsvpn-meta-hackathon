#!/usr/bin/env python3
from __future__ import annotations

import gzip
import importlib.util
import io
import json
import os
import shutil
import stat
import sys
import tarfile
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools/verify_release_legal_compliance.py"
SPEC = importlib.util.spec_from_file_location("verify_release_legal_compliance", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
legal = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = legal
SPEC.loader.exec_module(legal)

STAGE_PATHS = (
    "legal",
    "docs/THIRD_PARTY_NOTICES_AND_COMPONENT_INVENTORY.md",
    "docs/AMNEZIAWG_ENGINE_PROVENANCE.md",
    "pubspec.yaml",
    "pubspec.lock",
    "winn_protocol_experimental/LICENSE",
    "installer/windows/licenses",
)


class StrictJsonBoundaryTest(unittest.TestCase):
    def test_duplicate_key_still_fails_closed(self) -> None:
        with self.assertRaisesRegex(legal.LegalComplianceError, "duplicate JSON key: value"):
            legal._load_json(b'{"outer":{"value":1,"value":2}}', "hostile nested JSON")

    def assert_nested_nonfinite_rejected(self, constant: str) -> None:
        payload = f'{{"outer":{{"values":[0,{constant},1]}}}}'.encode("ascii")
        with self.assertRaises(legal.LegalComplianceError) as raised:
            legal._load_json(payload, "hostile nested JSON")
        self.assertEqual(
            str(raised.exception),
            f"non-finite JSON constant is forbidden: {constant}",
        )

    def test_nested_nan_fails_closed(self) -> None:
        self.assert_nested_nonfinite_rejected("NaN")

    def test_nested_positive_infinity_fails_closed(self) -> None:
        self.assert_nested_nonfinite_rejected("Infinity")

    def test_nested_negative_infinity_fails_closed(self) -> None:
        self.assert_nested_nonfinite_rejected("-Infinity")


class ReleaseLegalComplianceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.contract = legal.load_contract(ROOT)

    def stage_repo(self) -> Path:
        dest = self.work / "repo"
        dest.mkdir()
        for relative in STAGE_PATHS:
            source = ROOT / relative
            target = dest / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.is_dir():
                shutil.copytree(source, target)
            else:
                shutil.copy2(source, target)
        return dest

    def rewrite_contract(self, repo: Path, mutator) -> None:
        path = repo / "legal/release/LEGAL_BUNDLE_MANIFEST.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        mutator(document)
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

    def refresh_file_hash(self, repo: Path, relative: str) -> None:
        path = repo / "legal/release/LEGAL_BUNDLE_MANIFEST.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        source_name = document["files"][relative]["repository_source"]
        document["files"][relative]["sha256"] = legal._sha256_file(repo / source_name)
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

    def package(
        self,
        platform: str = "android",
        *,
        omit: set[str] | None = None,
        overrides: dict[str, bytes] | None = None,
        manifest: bytes | None = None,
        notices: bytes | None = None,
        markers: list[str] | None = None,
        extra_aot: bytes = b"",
        path: Path | None = None,
    ) -> Path:
        omit = omit or set()
        overrides = overrides or {}
        selected = self.contract.platforms[platform]
        output = path or self.work / f"{platform}.zip"
        prefix = "package/assets/legal/release/"
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            if "LEGAL_BUNDLE_MANIFEST.json" not in omit:
                archive.writestr(
                    prefix + "LEGAL_BUNDLE_MANIFEST.json",
                    self.contract.raw if manifest is None else manifest,
                )
            for relative in selected["required_files"]:
                if relative in omit:
                    continue
                source = ROOT / self.contract.files[relative]["repository_source"]
                archive.writestr(prefix + relative, overrides.get(relative, source.read_bytes()))
            if selected["requires_flutter_notices"] and "NOTICES.Z" not in omit:
                if notices is None:
                    license_body = (
                        "Copyright 2026 Example Authors.\n\n"
                        "Redistribution and use in source and binary forms, with or without "
                        "modification, are permitted provided that the copyright notice and "
                        "this permission remain intact. THE SOFTWARE IS PROVIDED AS IS, "
                        "WITHOUT WARRANTY OF ANY KIND. "
                    )
                    notice_text = "\n--------------------------------------------------------------------------------\n".join(
                        f"{marker}\n\n{license_body}" for marker in self.contract.document["flutter_notice_markers"]
                    )
                    notices = gzip.compress(notice_text.encode("utf-8"), mtime=0)
                archive.writestr("package/flutter_assets/NOTICES.Z", notices)
            compiled_markers = selected["in_app_markers"] if markers is None else markers
            if compiled_markers or extra_aot:
                archive.writestr(
                    "package/lib/arm64-v8a/libapp.so",
                    b"\x7fELF\x00" + b"\x00".join(item.encode("utf-8") for item in compiled_markers) + extra_aot,
                )
        return output

    def test_canonical_contract_passes(self) -> None:
        contract = legal.load_contract(ROOT)
        self.assertEqual(contract.document["contract"], legal.CONTRACT_NAME)
        self.assertIn("windows", contract.platforms)
        self.assertEqual(contract.document["owner_legal_approval"]["status"], legal.OWNER_BLOCKED)
        self.assertEqual(contract.document["publication_evidence"]["status"], legal.OWNER_BLOCKED)
        self.assertEqual(
            contract.document["publication_evidence"]["source_archive_sha256"],
            legal.OWNER_BLOCKED,
        )
        self.assertIn("amneziawg-windows-client", contract.components)
        self.assertIn(
            "amneziawg-windows-client",
            contract.platforms["windows"]["required_components"],
        )

    def test_designated_source_archive_names_this_release(self) -> None:
        # R24 V2 F-14: the 1.0.16+33 source offer, the legal manifest and the
        # verifier constant named the 1.0.15 archive while the website source page
        # already named the 1.0.16 one. The offer must name this release's archive.
        pubspec = (ROOT / "pubspec.yaml").read_text(encoding="utf-8")
        version = next(
            line.split(":", 1)[1].strip()
            for line in pubspec.splitlines()
            if line.startswith("version:")
        )
        marketing, _, _build = version.partition("+")
        expected = f"https://downloads.winsvpn.org/source/wins-vpn-{marketing}.tar.gz"
        self.assertEqual(legal.DESIGNATED_SOURCE_ARCHIVE_URL, expected)
        manifest = json.loads(
            (ROOT / "legal/release/LEGAL_BUNDLE_MANIFEST.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["publication_evidence"]["source_archive_url"], expected)
        self.assertEqual(manifest["app_release"], version)
        for name in ("winn-protocol-v3", "wins-vpn-application"):
            self.assertIn(version, manifest["components"][name]["identity"], name)
        for relative in ("legal/release/SOURCE_OFFER.txt", "web/source/index.html"):
            self.assertIn(expected, (ROOT / relative).read_text(encoding="utf-8"), relative)

    def test_check_contract_keeps_owner_and_publication_blocked(self) -> None:
        captured = io.StringIO()
        with redirect_stdout(captured):
            status = legal.main(["--check-contract"])
        output = captured.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("release legal contract mechanical PASS:", output)
        self.assertIn("owner/legal approval: OWNER-BLOCKED: ABSENT", output)
        self.assertIn("publication evidence: OWNER-BLOCKED: ABSENT", output)
        self.assertIn("store-release legal compliance: BLOCKED", output)
        self.assertNotIn("store-release legal compliance PASS", output)
        self.assertNotIn("release legal contract PASS:", output)

    def test_android_package_and_receipt_round_trip(self) -> None:
        artifact = self.package()
        receipt = legal.build_receipt(artifact, "android", repo_root=ROOT)
        self.assertEqual(receipt["platform"], "android")
        self.assertEqual(receipt["artifact"]["sha256"], legal._sha256_file(artifact))
        self.assertEqual(receipt["store_release_legal_compliance"], "BLOCKED")
        self.assertEqual(receipt["owner_legal_approval"]["status"], legal.OWNER_BLOCKED)
        self.assertEqual(receipt["publication_evidence"]["status"], legal.OWNER_BLOCKED)
        self.assertEqual(
            set(receipt["components"]),
            set(self.contract.platforms["android"]["required_components"]),
        )
        receipt_path = self.work / "receipt.json"
        legal.write_receipt(receipt_path, receipt)
        verified = legal.verify_receipt(artifact, "android", receipt_path, repo_root=ROOT)
        self.assertEqual(verified, receipt)

    def test_wear_package_has_narrow_legal_set(self) -> None:
        artifact = self.package("wear-os")
        receipt = legal.build_receipt(artifact, "wear-os", repo_root=ROOT)
        self.assertIsNone(receipt["bundle"]["flutter_notices"])
        self.assertEqual(set(receipt["components"]), {"wins-vpn-application"})

    def test_missing_license_fails_closed(self) -> None:
        artifact = self.package(omit={"licenses/Apache-2.0.txt"})
        with self.assertRaisesRegex(legal.LegalComplianceError, "missing=.*Apache-2.0"):
            legal.build_receipt(artifact, "android", repo_root=ROOT)

    def test_missing_source_offer_fails_closed(self) -> None:
        artifact = self.package(omit={"SOURCE_OFFER.txt"})
        with self.assertRaisesRegex(legal.LegalComplianceError, "missing=.*SOURCE_OFFER"):
            legal.build_receipt(artifact, "android", repo_root=ROOT)

    def test_substituted_legal_file_fails_closed(self) -> None:
        artifact = self.package(overrides={"SOURCE_OFFER.txt": b"attacker replacement\n"})
        with self.assertRaisesRegex(legal.LegalComplianceError, "stale or substituted: SOURCE_OFFER"):
            legal.build_receipt(artifact, "android", repo_root=ROOT)

    def test_stale_component_identity_manifest_fails_closed(self) -> None:
        stale = json.loads(self.contract.raw)
        stale["components"]["amneziawg-go"]["identity"] = "v0.0.0 stale"
        artifact = self.package(manifest=legal._canonical_json(stale))
        with self.assertRaisesRegex(legal.LegalComplianceError, "manifest is stale or substituted"):
            legal.build_receipt(artifact, "android", repo_root=ROOT)

    def test_duplicate_key_embedded_manifest_fails_closed(self) -> None:
        duplicate = b'{"contract":"one","contract":"two"}\n'
        artifact = self.package(manifest=duplicate)
        with self.assertRaisesRegex(legal.LegalComplianceError, "duplicate JSON key"):
            legal.build_receipt(artifact, "android", repo_root=ROOT)

    def test_missing_flutter_notices_fails_closed(self) -> None:
        artifact = self.package(omit={"NOTICES.Z"})
        with self.assertRaisesRegex(legal.LegalComplianceError, "exactly one Flutter NOTICES"):
            legal.build_receipt(artifact, "android", repo_root=ROOT)

    def test_invalid_flutter_notices_fails_closed(self) -> None:
        artifact = self.package(notices=b"not gzip")
        with self.assertRaisesRegex(legal.LegalComplianceError, "not valid gzip"):
            legal.build_receipt(artifact, "android", repo_root=ROOT)

    def test_incomplete_flutter_notices_fails_closed(self) -> None:
        artifact = self.package(notices=gzip.compress(b"country_flags only", mtime=0))
        with self.assertRaisesRegex(legal.LegalComplianceError, "exactly one license block"):
            legal.build_receipt(artifact, "android", repo_root=ROOT)

    def test_stale_compiled_in_app_identity_fails_closed(self) -> None:
        markers = [
            marker
            for marker in self.contract.platforms["android"]["in_app_markers"]
            if not marker.startswith("amneziawg-android ")
        ]
        markers.append("amneziawg-android v2.3.7")
        artifact = self.package(markers=markers)
        with self.assertRaisesRegex(legal.LegalComplianceError, "compiled in-app notice marker is missing"):
            legal.build_receipt(artifact, "android", repo_root=ROOT)

    def test_fake_extra_aot_cannot_supply_missing_markers(self) -> None:
        artifact = self.package()
        with zipfile.ZipFile(artifact, "a") as archive:
            archive.writestr("package/lib/x86_64/libapp.so", b"\x7fELF\x00stale notices")
        with self.assertRaisesRegex(legal.LegalComplianceError, "missing from"):
            legal.build_receipt(artifact, "android", repo_root=ROOT)

    def test_absent_component_in_app_claim_fails_closed(self) -> None:
        artifact = self.package(extra_aot=b"\x00hev-socks5-tunnel / lwIP\x00")
        with self.assertRaisesRegex(legal.LegalComplianceError, "falsely claims absent component"):
            legal.build_receipt(artifact, "android", repo_root=ROOT)

    def test_zip_symlink_fails_closed(self) -> None:
        artifact = self.work / "symlink.zip"
        with zipfile.ZipFile(artifact, "w") as archive:
            link = zipfile.ZipInfo("package/assets/legal/release/LEGAL_BUNDLE_MANIFEST.json")
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(link, "../../attacker")
        with self.assertRaisesRegex(legal.LegalComplianceError, "link or special"):
            legal.build_receipt(artifact, "android", repo_root=ROOT)

    def test_tar_symlink_fails_closed(self) -> None:
        artifact = self.work / "symlink.tar.gz"
        with tarfile.open(artifact, "w:gz") as archive:
            link = tarfile.TarInfo("package/assets/legal/release/LEGAL_BUNDLE_MANIFEST.json")
            link.type = tarfile.SYMTYPE
            link.linkname = "../../attacker"
            archive.addfile(link)
        with self.assertRaisesRegex(legal.LegalComplianceError, "link or special"):
            legal.build_receipt(artifact, "android", repo_root=ROOT)

    def test_explicit_zip_directories_do_not_change_file_set(self) -> None:
        artifact = self.package()
        with zipfile.ZipFile(artifact, "a") as archive:
            for directory in (
                "package/assets/",
                "package/assets/legal/",
                "package/assets/legal/release/",
                "package/assets/legal/release/licenses/",
            ):
                entry = zipfile.ZipInfo(directory)
                entry.create_system = 3
                entry.external_attr = (stat.S_IFDIR | 0o755) << 16
                archive.writestr(entry, b"")
        receipt = legal.build_receipt(artifact, "android", repo_root=ROOT)
        self.assertEqual(receipt["platform"], "android")

    def test_zip_path_escape_fails_closed(self) -> None:
        artifact = self.work / "escape.zip"
        with zipfile.ZipFile(artifact, "w") as archive:
            archive.writestr("../LEGAL_BUNDLE_MANIFEST.json", self.contract.raw)
        with self.assertRaisesRegex(legal.LegalComplianceError, "unsafe path segment"):
            legal.build_receipt(artifact, "android", repo_root=ROOT)

    def test_casefold_alias_fails_closed(self) -> None:
        artifact = self.work / "alias.zip"
        with zipfile.ZipFile(artifact, "w") as archive:
            archive.writestr("A/file.txt", b"one")
            archive.writestr("a/file.txt", b"two")
        with self.assertRaisesRegex(legal.LegalComplianceError, "duplicate or aliased"):
            legal.build_receipt(artifact, "android", repo_root=ROOT)

    def test_receipt_rejects_artifact_substitution(self) -> None:
        original = self.package(path=self.work / "original.zip")
        receipt = legal.build_receipt(original, "android", repo_root=ROOT)
        receipt_path = self.work / "receipt.json"
        legal.write_receipt(receipt_path, receipt)
        substituted = self.package(path=self.work / "substituted.zip", extra_aot=b"substitution")
        with self.assertRaisesRegex(legal.LegalComplianceError, "receipt does not bind"):
            legal.verify_receipt(substituted, "android", receipt_path, repo_root=ROOT)

    def test_duplicate_key_receipt_fails_closed(self) -> None:
        artifact = self.package()
        receipt_path = self.work / "receipt.json"
        receipt_path.write_bytes(b'{"contract":"one","contract":"two"}\n')
        with self.assertRaisesRegex(legal.LegalComplianceError, "duplicate JSON key"):
            legal.verify_receipt(artifact, "android", receipt_path, repo_root=ROOT)

    def test_receipt_symlink_fails_closed(self) -> None:
        artifact = self.package()
        target = self.work / "target.json"
        target.write_text("{}\n", encoding="utf-8")
        link = self.work / "receipt.json"
        os.symlink(target, link)
        with self.assertRaisesRegex(legal.LegalComplianceError, "regular non-symbolic"):
            legal.verify_receipt(artifact, "android", link, repo_root=ROOT)

    def test_narrow_browser_package_rejects_flutter_payload(self) -> None:
        artifact = self.package("chrome")
        with zipfile.ZipFile(artifact, "a") as archive:
            archive.writestr(
                "package/flutter_assets/NOTICES.Z",
                gzip.compress(b"unexpected Flutter payload", mtime=0),
            )
        with self.assertRaisesRegex(legal.LegalComplianceError, "unexpectedly contains Flutter"):
            legal.build_receipt(artifact, "chrome", repo_root=ROOT)

    def test_windows_package_includes_inventory_windows_client(self) -> None:
        artifact = self.package("windows")
        receipt = legal.build_receipt(artifact, "windows", repo_root=ROOT)
        self.assertIn("amneziawg-windows-client", receipt["components"])
        self.assertEqual(receipt["store_release_legal_compliance"], "BLOCKED")

    def test_truncated_apache_license_fails_closed(self) -> None:
        stub = b"Apache License Version 2.0 stub\n"
        with self.assertRaisesRegex(legal.LegalComplianceError, "truncated|missing required license text"):
            legal.assert_complete_license_text("licenses/Apache-2.0.txt", stub)
        repo = self.stage_repo()
        (repo / "legal/release/licenses/Apache-2.0.txt").write_bytes(stub)
        self.refresh_file_hash(repo, "licenses/Apache-2.0.txt")
        with self.assertRaisesRegex(legal.LegalComplianceError, "truncated|missing required license text"):
            legal.load_contract(repo)

    def test_truncated_agpl_license_fails_closed(self) -> None:
        stub = b"GNU AFFERO GENERAL PUBLIC LICENSE stub\n"
        with self.assertRaisesRegex(legal.LegalComplianceError, "truncated|missing required license text"):
            legal.assert_complete_license_text("licenses/AGPL-3.0-or-later.txt", stub)

    def test_truncated_mpl_license_fails_closed(self) -> None:
        stub = b"Mozilla Public License Version 2.0\n1. Definitions\n"
        with self.assertRaisesRegex(legal.LegalComplianceError, "truncated|missing required license text"):
            legal.assert_complete_license_text("licenses/MPL-2.0.txt", stub)

    def test_owner_legal_approval_cannot_be_greened_without_evidence(self) -> None:
        repo = self.stage_repo()
        self.rewrite_contract(
            repo,
            lambda document: document["owner_legal_approval"].update(status="APPROVED"),
        )
        with self.assertRaisesRegex(legal.LegalComplianceError, "owner_legal_approval.status must remain"):
            legal.load_contract(repo)

    def test_publication_digest_cannot_be_greened_without_evidence(self) -> None:
        repo = self.stage_repo()
        fake = "ab" * 32
        self.rewrite_contract(
            repo,
            lambda document: document["publication_evidence"].update(source_archive_sha256=fake),
        )
        with self.assertRaisesRegex(
            legal.LegalComplianceError, "publication_evidence.source_archive_sha256 must remain"
        ):
            legal.load_contract(repo)

    def test_source_offer_present_tense_archive_claim_fails_closed(self) -> None:
        repo = self.stage_repo()
        offer = repo / "legal/release/SOURCE_OFFER.txt"
        offer.write_text(
            "The complete Corresponding Source is available without charge at "
            "the designated URL.\n" + offer.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        self.refresh_file_hash(repo, "SOURCE_OFFER.txt")
        with self.assertRaisesRegex(legal.LegalComplianceError, "asserts unpublished archive as live"):
            legal.load_contract(repo)

    def test_source_offer_fake_archive_digest_fails_closed(self) -> None:
        repo = self.stage_repo()
        offer = repo / "legal/release/SOURCE_OFFER.txt"
        offer.write_text(
            offer.read_text(encoding="utf-8")
            + "\nSHA-256 "
            + ("ab" * 32)
            + "\n",
            encoding="utf-8",
        )
        self.refresh_file_hash(repo, "SOURCE_OFFER.txt")
        with self.assertRaisesRegex(
            legal.LegalComplianceError, "source digest without publication evidence"
        ):
            legal.load_contract(repo)

    def test_notices_missing_inventory_commit_fails_closed(self) -> None:
        repo = self.stage_repo()
        notices = repo / "legal/release/THIRD_PARTY_RUNTIME_NOTICES.txt"
        notices.write_text(
            notices.read_text(encoding="utf-8").replace(
                "b5928efb6ca19f0153958460c3d141f04abc5c2e",
                "0" * 40,
            ),
            encoding="utf-8",
        )
        self.refresh_file_hash(repo, "THIRD_PARTY_RUNTIME_NOTICES.txt")
        with self.assertRaisesRegex(legal.LegalComplianceError, "runtime notices omits required marker"):
            legal.load_contract(repo)

    def test_stale_pubspec_lock_identity_fails_closed(self) -> None:
        repo = self.stage_repo()

        def mutate(document: dict) -> None:
            document["components"]["flutter-dart-runtime"]["identity"] = (
                "pubspec.lock sha256 " + ("0" * 64) + " plus package NOTICES.Z"
            )

        self.rewrite_contract(repo, mutate)
        with self.assertRaisesRegex(legal.LegalComplianceError, "does not match pubspec.lock"):
            legal.load_contract(repo)

    def test_missing_direct_flutter_marker_fails_closed(self) -> None:
        repo = self.stage_repo()

        def mutate(document: dict) -> None:
            document["flutter_notice_markers"] = [
                marker for marker in document["flutter_notice_markers"] if marker != "crypto"
            ]

        self.rewrite_contract(repo, mutate)
        with self.assertRaisesRegex(legal.LegalComplianceError, "exact sorted direct hosted runtime packages"):
            legal.load_contract(repo)

    def test_receipt_rejects_owner_legal_greenwash(self) -> None:
        artifact = self.package()
        receipt = legal.build_receipt(artifact, "android", repo_root=ROOT)
        receipt["owner_legal_approval"] = dict(receipt["owner_legal_approval"])
        receipt["owner_legal_approval"]["status"] = "APPROVED"
        receipt_path = self.work / "greened-receipt.json"
        legal.write_receipt(receipt_path, receipt)
        with self.assertRaisesRegex(legal.LegalComplianceError, "receipt does not bind"):
            legal.verify_receipt(artifact, "android", receipt_path, repo_root=ROOT)


if __name__ == "__main__":
    unittest.main()
