#!/usr/bin/env python3
"""Phone/TV Play store metadata and AAB/APK gate contracts for 1.0.16+33."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import shutil
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_signer():
    spec = importlib.util.spec_from_file_location(
        "verify_android_aab_signers_store", ROOT / "tools/verify_android_aab_signers.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AndroidPhoneTvStoreMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_signer()

    def test_phone_and_tv_packages_are_ascii_and_distinct(self) -> None:
        phone = ROOT / "app_store/android/phone"
        tv = ROOT / "app_store/android/tv"
        wear = ROOT / "app_store/android/wear"
        self.assertTrue(phone.is_dir())
        self.assertTrue(tv.is_dir())
        self.assertTrue(wear.is_dir())
        for path in phone.rglob("*"):
            if path.is_file():
                path.read_bytes().decode("ascii")
        for path in tv.rglob("*"):
            if path.is_file():
                path.read_bytes().decode("ascii")
        phone_meta = self.module._reviewed_store_metadata("android-phone-tablet-aab")
        tv_meta = self.module._reviewed_store_metadata("android-tv-aab")
        self.assertNotEqual(phone_meta["sha256"], tv_meta["sha256"])
        self.assertEqual(phone_meta["version_code"], 33)
        self.assertEqual(tv_meta["version_code"], 3302)
        self.assertEqual(phone_meta["form"], "phone-tablet")
        self.assertEqual(tv_meta["form"], "tv")

    def test_protocol_and_pending_publication_gates(self) -> None:
        for target in ("android-phone-tablet-aab", "android-tv-aab"):
            reviewed = self.module._reviewed_store_metadata(target)
            self.assertEqual(reviewed["canonical_release"], "1.0.16+33")
            self.assertEqual(reviewed["application_id"], "org.winsvpn.app")
            self.assertEqual(reviewed["tunnel_protocol"]["primary"], "winn-v3")
            self.assertEqual(reviewed["tunnel_protocol"]["fallback"], ["awg"])
            self.assertEqual(
                reviewed["tunnel_protocol"]["required_local_engines"],
                ["libwinnengine.so", "libam-go.so"],
            )
            self.assertEqual(
                reviewed["tunnel_protocol"]["forbidden_local_engines"],
                ["libam.so", "libam-quick.so", "libxray.so"],
            )
            self.assertFalse(reviewed["submission_approved"])
            self.assertFalse(reviewed["upload_authorized"])
            self.assertEqual(reviewed["query_all_packages_status"], "PENDING")
            self.assertEqual(reviewed["listing_screenshot_inventory"], "owner-blocked")
        phone_listing = (
            ROOT / "app_store/android/phone/metadata/en-US/full_description.txt"
        ).read_text(encoding="ascii")
        tv_listing = (
            ROOT / "app_store/android/tv/metadata/en-US/full_description.txt"
        ).read_text(encoding="ascii")
        self.assertIn("Calculator disguise", phone_listing)
        self.assertIn("Leanback", tv_listing)
        self.assertNotIn("Calculator camouflage is phone-only", tv_listing)
        phone_short = (
            ROOT / "app_store/android/phone/metadata/en-US/short_description.txt"
        ).read_text(encoding="ascii").strip()
        tv_short = (
            ROOT / "app_store/android/tv/metadata/en-US/short_description.txt"
        ).read_text(encoding="ascii").strip()
        self.assertLessEqual(len(phone_short), 80)
        self.assertLessEqual(len(tv_short), 80)

    def test_owner_signoff_and_candidate_remain_unuploaded(self) -> None:
        for relative, version_code, target in (
            ("app_store/android/phone", 33, "android-phone-tablet-aab"),
            ("app_store/android/tv", 3302, "android-tv-aab"),
        ):
            signoff = json.loads(
                (ROOT / relative / "review/owner_signoff.json").read_text(encoding="utf-8")
            )
            candidate = json.loads(
                (ROOT / relative / "artifacts/release_candidate.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertFalse(signoff["submission_approved"])
            self.assertFalse(signoff["upload_authorized"])
            self.assertEqual(signoff["version_code"], version_code)
            self.assertEqual(candidate["target_id"], target)
            self.assertFalse(candidate["artifact"]["produced"])
            self.assertFalse(candidate["artifact"]["upload_performed"])
            self.assertFalse(candidate["artifact"]["publication_authorized"])
            self.assertFalse(candidate["private_symbols"]["uploaded"])
            if target == "android-phone-tablet-aab":
                self.assertEqual(
                    candidate["production_upload"], "android-phone-tablet-aab"
                )
                self.assertTrue(candidate["apk_sidecar_only"])
                self.assertEqual(candidate["artifact"]["production_upload"], "aab")
                self.assertEqual(candidate["artifact"]["apk_role"], "sidecar-only")

    def test_store_metadata_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="android-store-") as name:
            repo = pathlib.Path(name)
            for form in ("phone", "tv"):
                shutil.copytree(
                    ROOT / f"app_store/android/{form}",
                    repo / f"app_store/android/{form}",
                )
            self.module.ROOT = repo
            try:
                signoff = repo / "app_store/android/phone/review/owner_signoff.json"
                payload = json.loads(signoff.read_text(encoding="utf-8"))
                payload["upload_authorized"] = True
                signoff.write_text(json.dumps(payload) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(self.module.SignerError, "owner signoff"):
                    self.module._reviewed_store_metadata("android-phone-tablet-aab")
                payload["upload_authorized"] = False
                payload["canonical_release"] = "9.9.9+1"
                signoff.write_text(json.dumps(payload) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(self.module.SignerError, "owner signoff"):
                    self.module._reviewed_store_metadata("android-phone-tablet-aab")
                listing = repo / "app_store/android/tv/metadata/en-US/full_description.txt"
                listing.write_text("Android TV app without a protocol.\n", encoding="ascii")
                with self.assertRaisesRegex(self.module.SignerError, "Winn v3"):
                    self.module._reviewed_store_metadata("android-tv-aab")
            finally:
                self.module.ROOT = ROOT

    def test_phone_receipt_binds_current_store_metadata_hash(self) -> None:
        reviewed = self.module._reviewed_store_metadata("android-phone-tablet-aab")
        files = reviewed["files"]
        self.assertIn(
            "app_store/android/phone/review/privacy_label_manifest.json", files
        )
        privacy = json.loads(
            (
                ROOT / "app_store/android/phone/review/privacy_label_manifest.json"
            ).read_text(encoding="utf-8")
        )
        digest = hashlib.sha256(
            (
                ROOT / "app_store/android/phone/review/privacy_label_manifest.json"
            ).read_bytes()
        ).hexdigest()
        self.assertEqual(
            files["app_store/android/phone/review/privacy_label_manifest.json"], digest
        )
        self.assertEqual(privacy["application_label"], "Calculator")
        self.assertEqual(privacy["query_all_packages_status"], "PENDING")
        tv_privacy = json.loads(
            (ROOT / "app_store/android/tv/review/privacy_label_manifest.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(tv_privacy["application_label"], "Win's VPN")
        self.assertFalse(tv_privacy["camouflage"])
        self.assertTrue(tv_privacy["leanback"])

    def test_phone_and_tv_play_text_claims_no_xray(self) -> None:
        # Android refuses Xray mode (VpnTunnelService.kt) and the Gradle
        # packaging excludes libxray.so, so no Play-facing phone/TV text may
        # promise an Xray fallback, and the machine-readable protocol records
        # must agree with the packaged engines.
        for form in ("phone", "tv"):
            root = ROOT / f"app_store/android/{form}"
            for relative in (
                "metadata/en-US/full_description.txt",
                "metadata/en-US/short_description.txt",
                "metadata/en-US/whats_new.txt",
                "review/data_safety.md",
                "review/play_console_notes.txt",
            ):
                with self.subTest(form=form, file=relative):
                    text = (root / relative).read_text(encoding="ascii")
                    self.assertIn("AWG", text)
                    self.assertNotIn("Xray", text)
            for relative in (
                "review/privacy_label_manifest.json",
                "artifacts/release_candidate.json",
            ):
                with self.subTest(form=form, file=relative):
                    record = json.loads((root / relative).read_text(encoding="utf-8"))
                    self.assertEqual(record["tunnel_protocol"]["fallback"], ["awg"])
            privacy = json.loads(
                (root / "review/privacy_label_manifest.json").read_text(encoding="utf-8")
            )
            self.assertNotIn(
                "libxray.so", privacy["tunnel_protocol"]["required_local_engines"]
            )
            self.assertIn(
                "libxray.so", privacy["tunnel_protocol"]["forbidden_local_engines"]
            )
        short = (ROOT / "app_store/android/phone/metadata/en-US/short_description.txt")
        broken = short.read_text(encoding="ascii").replace("AWG fallback", "AWG then Xray fallback")
        with tempfile.TemporaryDirectory(prefix="android-store-") as name:
            repo = pathlib.Path(name)
            for form in ("phone", "tv"):
                shutil.copytree(
                    ROOT / f"app_store/android/{form}",
                    repo / f"app_store/android/{form}",
                )
            (repo / "app_store/android/phone/metadata/en-US/short_description.txt").write_text(
                broken, encoding="ascii"
            )
            (repo / "app_store/android/phone/metadata/en-US/full_description.txt").write_text(
                "Winn v3 primary. Winn v1 AWG then Xray fallback.\n", encoding="ascii"
            )
            self.module.ROOT = repo
            try:
                with self.assertRaisesRegex(self.module.SignerError, "must not claim an Xray"):
                    self.module._reviewed_store_metadata("android-phone-tablet-aab")
            finally:
                self.module.ROOT = ROOT

    def test_whats_new_and_wear_listings_are_ascii_protocol_copy(self) -> None:
        wear = ROOT / "app_store/android/wear"
        for path in wear.rglob("*"):
            if path.is_file():
                path.read_bytes().decode("ascii")
        for form, limit_name in (
            ("phone", "android-phone-tablet-aab"),
            ("tv", "android-tv-aab"),
        ):
            whats_new = (
                ROOT / f"app_store/android/{form}/metadata/en-US/whats_new.txt"
            ).read_text(encoding="ascii")
            self.assertIn("Winn v3", whats_new)
            self.assertIn("AWG fallback", whats_new)
            self.assertNotIn("Xray", whats_new)
            self.assertLessEqual(len(whats_new.strip()), 500)
            reviewed = self.module._reviewed_store_metadata(limit_name)
            self.assertIn(
                f"app_store/android/{form}/metadata/en-US/whats_new.txt",
                reviewed["files"],
            )
        wear_short = (
            ROOT / "app_store/android/wear/metadata/en-US/short_description.txt"
        ).read_text(encoding="ascii").strip()
        self.assertLessEqual(len(wear_short), 80)
        self.assertIn("Winn v3", wear_short)
        self.assertIn("AWG then Xray", wear_short)
        wear_listing = (
            ROOT / "app_store/android/wear/metadata/en-US/full_description.txt"
        ).read_text(encoding="ascii")
        self.assertIn("https://www.winsvpn.org/privacy/", wear_listing)


if __name__ == "__main__":
    unittest.main()
