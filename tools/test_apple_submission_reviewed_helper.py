#!/usr/bin/env python3
"""Submission validator must freeze only the current Apple cross-store helper."""

from __future__ import annotations

import builtins
import hashlib
import os
import select
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import validate_apple_submission_package as submission
import release_obfuscation_contract as obfuscation


STALE_APPLE_CROSS_STORE_GATE_HELPER_SHA256 = (
    "2d11bcda648035986be286c3ca2de248dae35e2d631a1744fc6e1a2eccd70ad5"
)
APP_STORE = "macos-app-store-pkg"
DEVELOPER_ID = "macos-developer-id-app"
IOS = "ios-app-store-ipa"
TARGETS = (IOS, APP_STORE, DEVELOPER_ID)


class AppleSubmissionReviewedHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.scratch = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _load_helper(self):
        path = submission.APPLE_CROSS_STORE_GATE_HELPER
        return submission._load_reviewed_helper(
            path,
            submission.APPLE_CROSS_STORE_GATE_HELPER_SHA256,
            "apple_cross_store_artifact_gate",
        )

    def _mutated_helper(self, payload: bytes, name: str) -> Path:
        path = self.scratch / name
        path.write_bytes(payload)
        return path

    def test_frozen_hash_matches_current_helper_after_macos_channel_contract(self) -> None:
        helper_path = submission.APPLE_CROSS_STORE_GATE_HELPER
        self.assertEqual(helper_path.name, "apple_cross_store_artifact_gate.py")
        self.assertEqual(
            helper_path.resolve(),
            (TOOLS / "apple_cross_store_artifact_gate.py").resolve(),
        )
        helper = self._load_helper()
        suffixes = helper.TARGET_SUFFIXES
        self.assertEqual(suffixes[IOS], (".ipa",))
        self.assertEqual(suffixes[APP_STORE], (".pkg",))
        self.assertEqual(suffixes[DEVELOPER_ID], (".app.zip",))
        self.assertFalse(set(suffixes[APP_STORE]) & set(suffixes[DEVELOPER_ID]))
        contract = helper.MACOS_PACKAGE_CHANNEL_CONTRACT
        self.assertEqual(set(contract), {APP_STORE, DEVELOPER_ID})
        app_store = contract[APP_STORE]
        developer_id = contract[DEVELOPER_ID]
        self.assertEqual(app_store["channel"], "mac-app-store")
        self.assertEqual(developer_id["channel"], "developer-id")
        self.assertEqual(app_store["signing_contract"], "apple-distribution")
        self.assertEqual(developer_id["signing_contract"], "developer-id-application")
        self.assertEqual(
            app_store["expected_authority"], "Authority=Apple Distribution:"
        )
        self.assertEqual(
            developer_id["expected_authority"],
            "Authority=Developer ID Application:",
        )
        self.assertIs(app_store["required"], True)
        self.assertIs(developer_id["required"], False)
        self.assertNotEqual(app_store["channel"], developer_id["channel"])
        self.assertNotEqual(
            app_store["signing_contract"], developer_id["signing_contract"]
        )
        self.assertNotEqual(
            app_store["expected_authority"], developer_id["expected_authority"]
        )
        bound_app = helper.macos_package_channel_contract(APP_STORE)
        bound_dev = helper.macos_package_channel_contract(DEVELOPER_ID)
        self.assertEqual(bound_app["suffixes"], (".pkg",))
        self.assertEqual(bound_dev["suffixes"], (".app.zip",))
        self.assertIs(bound_app["signature_verified"], False)
        self.assertIs(bound_dev["signature_verified"], False)
        with self.assertRaisesRegex(
            helper.AppleArtifactGateError, "unsupported macOS package channel"
        ):
            helper.macos_package_channel_contract(IOS)
        digest = submission.sha256_file(helper_path)
        self.assertEqual(len(digest), 64)
        self.assertNotEqual(digest, STALE_APPLE_CROSS_STORE_GATE_HELPER_SHA256)
        self.assertEqual(
            submission.APPLE_RELEASE_CONTAMINATION_GATE_HELPER_SHA256,
            submission.sha256_file(submission.APPLE_RELEASE_CONTAMINATION_GATE_HELPER),
        )
        self.assertEqual(helper.CANONICAL_RELEASE, "1.0.17+34")
        self.assertEqual(helper.WATCH_BUNDLE_ID, "org.winsvpn.app.watchkitapp")
        self.assertEqual(
            helper.REQUIRED_APPLE_UPLOAD_TARGETS,
            ("ios-app-store-ipa", "macos-app-store-pkg"),
        )

    def test_stale_or_substituted_helper_bytes_are_refused(self) -> None:
        current = submission.APPLE_CROSS_STORE_GATE_HELPER.read_bytes()
        comment_mutated = self._mutated_helper(
            current + b"\n# substituted-reviewed-helper\n",
            "comment-mutated.py",
        )
        flipped = bytearray(current)
        flipped[-1] ^= 0x01
        byte_mutated = self._mutated_helper(bytes(flipped), "byte-mutated.py")
        swapped = self._mutated_helper(
            submission.APPLE_RELEASE_CONTAMINATION_GATE_HELPER.read_bytes(),
            "swapped-contamination.py",
        )
        mutations = (
            comment_mutated,
            byte_mutated,
            swapped,
        )
        for mutated in mutations:
            self.assertNotEqual(
                submission.sha256_file(mutated),
                submission.APPLE_CROSS_STORE_GATE_HELPER_SHA256,
            )
            for target_id in TARGETS:
                with self.subTest(mutated=mutated.name, target_id=target_id):
                    with mock.patch.object(
                        submission, "APPLE_CROSS_STORE_GATE_HELPER", mutated
                    ):
                        with self.assertRaisesRegex(
                            AssertionError, "source hash is not reviewed"
                        ):
                            submission.validate_cross_store_artifact(
                                target_id, "artifacts/reviewed-helper-mutation.pkg"
                            )
        with mock.patch.object(
            submission,
            "APPLE_CROSS_STORE_GATE_HELPER_SHA256",
            STALE_APPLE_CROSS_STORE_GATE_HELPER_SHA256,
        ):
            with self.assertRaisesRegex(
                AssertionError, "source hash is not reviewed"
            ):
                submission.validate_cross_store_artifact(
                    APP_STORE, "artifacts/reviewed-helper-mutation.pkg"
                )

    def test_exact_current_helper_is_the_only_accepted_hash(self) -> None:
        exact_copy = self._mutated_helper(
            submission.APPLE_CROSS_STORE_GATE_HELPER.read_bytes(),
            "exact-copy.py",
        )
        live = submission.sha256_file(submission.APPLE_CROSS_STORE_GATE_HELPER)
        self.assertEqual(submission.sha256_file(exact_copy), live)
        live_helper = submission._load_reviewed_helper(
            submission.APPLE_CROSS_STORE_GATE_HELPER,
            live,
            "apple_cross_store_artifact_gate",
        )
        self.assertEqual(live_helper.CANONICAL_RELEASE, "1.0.17+34")
        with self.assertRaisesRegex(Exception, "root injection is not exact"):
            submission._load_reviewed_helper(
                exact_copy,
                live,
                "apple_cross_store_artifact_gate_copy",
            )

        poisoned = types.ModuleType("apple_cross_store_artifact_gate")
        poisoned.CANONICAL_RELEASE = "9.9.9+999"
        with mock.patch.dict(sys.modules, {"apple_cross_store_artifact_gate": poisoned}):
            isolated = submission._load_reviewed_helper(
                submission.APPLE_CROSS_STORE_GATE_HELPER,
                live,
                "apple_cross_store_artifact_gate_poison_control",
            )
        self.assertEqual(isolated.CANONICAL_RELEASE, "1.0.17+34")

        with self.assertRaisesRegex(AssertionError, "source hash is not reviewed"):
            submission._load_reviewed_helper(
                submission.APPLE_CROSS_STORE_GATE_HELPER,
                STALE_APPLE_CROSS_STORE_GATE_HELPER_SHA256,
                "apple_cross_store_artifact_gate",
            )

        if hasattr(select, "kqueue"):
            for loader, error_type in (
                (submission._load_reviewed_helper, AssertionError),
                (obfuscation._load_reviewed_helper, obfuscation.ObfuscationError),
            ):
                with self.subTest(loader=loader.__module__):
                    slot = self.scratch / loader.__module__
                    trusted = slot / "trusted"
                    attacker = slot / "attacker"
                    held = slot / "held"
                    trusted_tools = trusted / "tools"
                    attacker_tools = attacker / "tools"
                    trusted_tools.mkdir(parents=True)
                    attacker_tools.mkdir(parents=True)
                    source = (
                        b"from pathlib import Path\n"
                        b"SUPPORT = Path(__file__).resolve().with_name('support.txt').read_text()\n"
                    )
                    helper_path = trusted_tools / "reviewed.py"
                    helper_path.write_bytes(source)
                    (trusted_tools / "support.txt").write_text(
                        "TRUSTED", encoding="utf-8"
                    )
                    (attacker_tools / "reviewed.py").write_bytes(source)
                    (attacker_tools / "support.txt").write_text(
                        "MALICIOUS", encoding="utf-8"
                    )
                    real_exec = builtins.exec
                    attacked = False

                    def swap_ancestor(code, namespace, *args, **kwargs):
                        nonlocal attacked
                        attacked = True
                        os.rename(trusted, held)
                        os.rename(attacker, trusted)
                        try:
                            return real_exec(code, namespace, *args, **kwargs)
                        finally:
                            os.rename(trusted, attacker)
                            os.rename(held, trusted)

                    with (
                        mock.patch("builtins.exec", side_effect=swap_ancestor),
                        self.assertRaisesRegex(
                            error_type,
                            "trusted ancestor changed|trusted ancestor path was replaced",
                        ),
                    ):
                        loader(
                            helper_path,
                            hashlib.sha256(source).hexdigest(),
                            "ancestor_swap_control",
                        )
                    self.assertTrue(attacked)
                    self.assertEqual(
                        (trusted_tools / "support.txt").read_text(encoding="utf-8"),
                        "TRUSTED",
                    )

    def test_obfuscation_loader_ignores_preloaded_fake_gate(self) -> None:
        poisoned = types.ModuleType("apple_cross_store_artifact_gate")
        poisoned.CANONICAL_RELEASE = "9.9.9+999"
        with mock.patch.dict(sys.modules, {"apple_cross_store_artifact_gate": poisoned}):
            helper = obfuscation._load_reviewed_helper(
                obfuscation.APPLE_CROSS_STORE_GATE_HELPER,
                obfuscation.APPLE_CROSS_STORE_GATE_HELPER_SHA256,
                "apple_cross_store_artifact_gate_poison_control",
            )
            self.assertEqual(helper.CANONICAL_RELEASE, "1.0.17+34")
            self.assertIs(sys.modules.get("apple_cross_store_artifact_gate"), poisoned)

        fake_minifier = types.ModuleType("store_js_minifier")
        fake_minifier.require_zip_javascript_matches_producer = lambda _archive: None
        with (
            mock.patch.dict(sys.modules, {"store_js_minifier": fake_minifier}),
            mock.patch.object(obfuscation, "_STORE_JS_MINIFIER", None),
        ):
            reviewed = obfuscation._store_js_minifier()
            self.assertIsNot(reviewed, fake_minifier)
            self.assertEqual(
                reviewed.__winsvpn_source_sha256__,
                obfuscation.STORE_JS_MINIFIER_SHA256,
            )
            self.assertIs(sys.modules.get("store_js_minifier"), fake_minifier)
        with (
            mock.patch.object(obfuscation, "_STORE_JS_MINIFIER", fake_minifier),
            self.assertRaisesRegex(
                obfuscation.ObfuscationError, "cached store JavaScript minifier"
            ),
        ):
            obfuscation._store_js_minifier()

        hostile_receipts = (
            ('{"receipt":{"ok":true,"ok":false}}', "duplicate key"),
            ('{"receipt":NaN}', "non-finite"),
            ('{"receipt":1e400}', "non-finite"),
        )
        for payload, message in hostile_receipts:
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(AssertionError, message):
                    submission._strict_json_loads(payload, "submission receipt")
                with self.assertRaisesRegex(obfuscation.ObfuscationError, message):
                    obfuscation._strict_receipt_json_loads(
                        payload.encode("ascii"), "obfuscation receipt"
                    )
        with self.assertRaisesRegex(AssertionError, "size is invalid"):
            submission._strict_json_loads("{}", "submission receipt", max_bytes=1)
        with self.assertRaisesRegex(obfuscation.ObfuscationError, "size is invalid"):
            obfuscation._strict_receipt_json_loads(
                b"{}", "obfuscation receipt", max_bytes=1
            )


if __name__ == "__main__":
    unittest.main()
