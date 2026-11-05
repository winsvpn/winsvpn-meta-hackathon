#!/usr/bin/env python3
"""Direct tests for the shared release secret-scan policy."""

from __future__ import annotations

import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

import release_secret_scan_policy as policy


class ReleaseSecretScanPolicyTests(unittest.TestCase):
    def test_service_account_json_and_filename_are_rejected(self) -> None:
        payload = (
            b'{"type":"service_account","project_id":"wins-proof",'
            b'"client_email":"proof@wins-proof.iam.gserviceaccount.com"}'
        )
        self.assertEqual(
            policy.reusable_secret_category(payload), "google_service_account_json"
        )
        self.assertTrue(
            policy.service_account_member_name("assets/google-service-account.json")
        )
        self.assertTrue(
            policy.service_account_member_name("google-service-account.json")
        )
        self.assertTrue(
            policy.service_account_member_name(
                "named-sa.zip!/google-service-account.json"
            )
        )
        self.assertTrue(
            policy.service_account_member_name(
                "BOOT-INF/application_default_credentials.json"
            )
        )
        self.assertFalse(policy.service_account_member_name("assets/config.json"))

    def test_activation_secret_assignment_is_rejected_and_header_name_alone_is_not(
        self,
    ) -> None:
        self.assertTrue(
            policy.packaged_credential_assignment(
                b'activation_secret="one-time-enrollment-secret-value-001"'
            )
        )
        self.assertTrue(
            policy.packaged_credential_assignment(
                b"x-wins-activation: one-time-enrollment-secret-value-001"
            )
        )
        self.assertFalse(
            policy.packaged_credential_assignment(b"headers['X-Wins-Activation'] = activationSecret;")
        )

    def test_only_the_exact_reviewed_keychain_sentinel_is_not_a_credential(self) -> None:
        self.assertFalse(
            policy.packaged_credential_assignment(
                b"PrivateKey = __WINS_EXISTING_KEYCHAIN_PRIVATE_KEY__\n"
            )
        )
        for value in (
            b"__WINS_EXISTING_KEYCHAIN_PRIVATE_KEY__X",
            b"__WINS_OTHER_PRIVATE_KEY__",
            b"aGVsbG8gd29ybGQgdGhpcyBpcyBhIHByaXZhdGUga2V5MDE=",
        ):
            with self.subTest(value=value):
                self.assertTrue(
                    policy.packaged_credential_assignment(b"PrivateKey = " + value + b"\n")
                )

    def test_runtime_public_pins_and_public_keys_are_not_secrets(self) -> None:
        pins = (
            b"const String kSpkiWinsvpnOrgWildcard = "
            b"'H6Mj7DsLr6FAGUz4jLll4sc9AXDe3XcOsv4qWwUzY98=';\n"
            b"const String kReviewedAnnouncementPubkeyA1 = "
            b"'d9hwDSlQpYvnph33NJFHAbOm3hKR1wWEhC/kFiNoeoo=';\n"
            b"const String server_public_key = "
            b"'d9hwDSlQpYvnph33NJFHAbOm3hKR1wWEhC/kFiNoeoo=';\n"
            b"-----BEGIN PUBLIC KEY-----\nMIIBfixture\n-----END PUBLIC KEY-----\n"
            b"-----BEGIN CERTIFICATE-----\nMIIBfixture\n-----END CERTIFICATE-----\n"
        )
        self.assertIsNone(policy.reusable_secret_category(pins))
        self.assertFalse(policy.packaged_credential_assignment(pins))
        self.assertTrue(
            policy.contains_only_public_crypto_material(
                b"-----BEGIN PUBLIC KEY-----\nMIIBfixture\n-----END PUBLIC KEY-----\n"
            )
        )
        self.assertTrue(
            policy.is_public_material_assignment_name(b"server_public_key")
        )
        self.assertTrue(
            policy.is_runtime_public_pin_or_key_value(
                b"H6Mj7DsLr6FAGUz4jLll4sc9AXDe3XcOsv4qWwUzY98="
            )
        )

    def test_private_key_pem_is_never_treated_as_public_material(self) -> None:
        pem = (
            b"-----BEGIN PRIVATE KEY-----\n"
            b"SYNTHETICONLYNOTAREALPRIVATEKEYMATERIALFORTESTSXX\n"
            b"-----END PRIVATE KEY-----\n"
        )
        self.assertEqual(policy.reusable_secret_category(pem), "private_key_material")
        self.assertFalse(policy.contains_only_public_crypto_material(pem))
        mixed = (
            b"-----BEGIN PUBLIC KEY-----\nMIIBfixture\n-----END PUBLIC KEY-----\n" + pem
        )
        self.assertFalse(policy.contains_only_public_crypto_material(mixed))


if __name__ == "__main__":
    unittest.main()
