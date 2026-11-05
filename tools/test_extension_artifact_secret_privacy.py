#!/usr/bin/env python3
"""Adversarial extension-package tests for reusable credential detection."""

from __future__ import annotations

import os
import pathlib
import shutil
import sys
import tempfile
import threading
import time
import unittest
import zipfile


ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

import release_obfuscation_contract as obfuscation
import release_secret_inventory as secret_inventory
import validate_release_artifact_privacy as privacy

ESBUILD_CACHE = pathlib.Path("/tmp/winsvpn-extension-esbuild-test-cache")
# The operator-supplied offline cache, captured before setUp redirects the
# environment to the private test cache. Archive bytes are re-verified.
CONFIGURED_ESBUILD_CACHE = os.environ.get("WINS_EXTENSION_ESBUILD_CACHE", "").strip()


def _churn_tempdir_siblings(tag: str) -> None:
    root = pathlib.Path(tempfile.gettempdir())
    sibling = root / f"wins-relpriv-churn-{os.getpid()}-{tag}-{time.time_ns()}"
    sibling.mkdir()
    try:
        (sibling / "nlink").mkdir()
        try:
            os.utime(root, None)
        except OSError:
            pass
    finally:
        shutil.rmtree(sibling, ignore_errors=True)


def _churn_bound_ancestors(path: pathlib.Path, index: int) -> None:
    _churn_tempdir_siblings(f"{path.name}-{index}")
    parent = path.parent
    local = parent / f"wins-local-churn-{index}-{time.time_ns()}"
    local.mkdir()
    try:
        (local / "nlink").mkdir()
    finally:
        shutil.rmtree(local, ignore_errors=True)
    bound = pathlib.Path(*path.parts[: index + 1])
    try:
        os.utime(bound, None)
    except OSError:
        pass


# A one-member zip is scanned as two blobs: the member and the zip residual
# (headers, gaps and the central directory; R22 Y3-01).
ONE_MEMBER_ZIP_BLOBS = 2


class ExtensionArtifactSecretPrivacyTests(unittest.TestCase):
    def setUp(self) -> None:
        cache = ESBUILD_CACHE
        os.environ["WINS_EXTENSION_ESBUILD_CACHE"] = str(cache)
        os.environ["WINS_EXTENSION_ESBUILD_FETCH"] = "0"
        minifier = obfuscation._store_js_minifier()
        pin = minifier.pin_for_host()
        slot = cache / minifier.host_platform_key() / str(pin["archive_sha256"])
        slot.mkdir(parents=True, exist_ok=True)
        dest = slot / str(pin["archive_name"])
        discovered = (
            pathlib.Path("/tmp/winsvpn-esbuild-discovery/archives")
            / str(pin["archive_name"])
        )
        if dest.is_file() and minifier.sha256_file(dest) == pin["archive_sha256"]:
            return
        sources = [discovered]
        if CONFIGURED_ESBUILD_CACHE:
            sources.insert(0, (
                pathlib.Path(CONFIGURED_ESBUILD_CACHE) / minifier.host_platform_key()
                / str(pin["archive_sha256"]) / str(pin["archive_name"])
            ))
        for source in sources:
            if source.is_file():
                payload = source.read_bytes()
                minifier.verify_archive_bytes(payload, pin)
                dest.write_bytes(payload)
                dest.chmod(0o444)
                return

    def authenticated_inventory(self) -> secret_inventory.SecretInventory:
        loaded = secret_inventory.SecretInventory(
            "extension-privacy-fixture-v1",
            {"TEST_RELEASE_SECRET": "synthetic-release-secret-123456"},
            digest="d" * 64,
            identity=(11, 12, 13, 14, 15, 16, 17),
        )
        authorization = secret_inventory._InventoryAuthorization(
            revision=loaded.revision,
            labels=loaded.labels,
            inventory_digest=loaded.digest,
            inventory_identity=loaded.identity,
            inventory_path=pathlib.Path("/nonexistent/wins-release-secret-inventory.json"),
            repository_root=ROOT,
        )
        return secret_inventory._make_authenticated_inventory(loaded, authorization)

    def artifact(self, root: pathlib.Path, payload: bytes, name: str = "background.js") -> pathlib.Path:
        path = root / "extension.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(name, payload)
        return path

    def test_google_aiza_api_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            artifact = self.artifact(
                pathlib.Path(temp_name),
                b"const routingKey = 'AIza" + (b"A" * 35) + b"';\n",
            )
            with self.assertRaisesRegex(privacy.PrivacyError, "google_api_key"):
                privacy.validate_artifacts((artifact,), {})

    def test_generic_credential_assignments_are_rejected(self) -> None:
        fixtures = (
            b'const api_key = "' + (b"A" * 32) + b'";\n',
            b'{"client_secret":"' + (b"b" * 40) + b'"}\n',
            b"access-token='" + (b"C" * 28) + b"'\n",
            ("password=" + ("d" * 30)).encode("utf-16-le"),
        )
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            for index, payload in enumerate(fixtures):
                with self.subTest(index=index):
                    artifact = self.artifact(root, payload, f"fixture-{index}.js")
                    with self.assertRaisesRegex(
                        privacy.PrivacyError, "credential_assignment"
                    ):
                        privacy.validate_artifacts((artifact,), {})

    def test_runtime_references_and_explicit_placeholders_remain_allowed(self) -> None:
        benign = b"""
const api_key = process.env.GEMINI_API_KEY;
const access_token = import.meta.env.ACCESS_TOKEN;
const client_secret = "REPLACE_WITH_CLIENT_SECRET";
const password = "YOUR_PASSWORD_PLACEHOLDER";
// Credentials are injected by the native host at runtime and are not packaged.
"""
        with tempfile.TemporaryDirectory() as temp_name:
            artifact = self.artifact(pathlib.Path(temp_name), benign)
            self.assertEqual(
                privacy.validate_artifacts((artifact,), {}), ONE_MEMBER_ZIP_BLOBS
            )

    def test_non_credential_configuration_assignments_remain_allowed(self) -> None:
        benign = b"""
const selected_route_id = "us-east-low-latency-route";
const model_name = "gemma-routing-decision-model";
const public_client_id = "public-browser-client-identifier";
"""
        with tempfile.TemporaryDirectory() as temp_name:
            artifact = self.artifact(pathlib.Path(temp_name), benign)
            self.assertEqual(
                privacy.validate_artifacts((artifact,), {}), ONE_MEMBER_ZIP_BLOBS
            )

    def test_split_javascript_string_literals_match_known_secrets(self) -> None:
        secret = "synthetic-inventory-secret-alpha-0001"
        payload = b'const token = "synthetic-inventory-secret-" + "alpha-0001";\n'
        with tempfile.TemporaryDirectory() as temp_name:
            artifact = self.artifact(pathlib.Path(temp_name), payload)
            with self.assertRaisesRegex(privacy.PrivacyError, "SYNTHETIC_ALPHA"):
                privacy.validate_artifacts((artifact,), {"SYNTHETIC_ALPHA": secret})
            error = ""
            try:
                privacy.validate_artifacts((artifact,), {"SYNTHETIC_ALPHA": secret})
            except privacy.PrivacyError as exc:
                error = str(exc)
            self.assertNotIn(secret, error)

    def test_zip_archive_and_member_comments_match_known_secrets(self) -> None:
        secret = "synthetic-inventory-secret-alpha-0001"
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            archive_comment = root / "archive-comment.zip"
            with zipfile.ZipFile(archive_comment, "w") as archive:
                archive.writestr("background.js", b"const ok = true;\n")
                archive.comment = secret.encode("utf-8")
            with self.assertRaisesRegex(privacy.PrivacyError, "SYNTHETIC_ALPHA"):
                privacy.validate_artifacts(
                    (archive_comment,), {"SYNTHETIC_ALPHA": secret}
                )

            member_comment = root / "member-comment.zip"
            info = zipfile.ZipInfo("background.js")
            info.comment = secret.encode("utf-8")
            with zipfile.ZipFile(member_comment, "w") as archive:
                archive.writestr(info, b"const ok = true;\n")
            with self.assertRaisesRegex(privacy.PrivacyError, "SYNTHETIC_ALPHA"):
                privacy.validate_artifacts(
                    (member_comment,), {"SYNTHETIC_ALPHA": secret}
                )

            extra = root / "member-extra.zip"
            extra_info = zipfile.ZipInfo("background.js")
            extra_info.extra = b"UX\x1f\x00" + secret.encode("utf-8")
            with zipfile.ZipFile(extra, "w") as archive:
                archive.writestr(extra_info, b"const ok = true;\n")
            with self.assertRaisesRegex(privacy.PrivacyError, "SYNTHETIC_ALPHA"):
                privacy.validate_artifacts((extra,), {"SYNTHETIC_ALPHA": secret})

    def test_public_certificate_and_spki_material_remain_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            cert = self.artifact(
                root,
                b"-----BEGIN CERTIFICATE-----\nMIIBfixturepubliccertnotasecretXX\n-----END CERTIFICATE-----\n",
                "ca.pem",
            )
            self.assertGreaterEqual(privacy.validate_artifacts((cert,), {}), 1)
            public_key = root / "public-key.zip"
            with zipfile.ZipFile(public_key, "w") as archive:
                archive.writestr(
                    "client.pub",
                    b"-----BEGIN PUBLIC KEY-----\nMIIBfixturepublickeynotasecretXX\n-----END PUBLIC KEY-----\n",
                )
            self.assertGreaterEqual(privacy.validate_artifacts((public_key,), {}), 1)
            spki = root / "spki.zip"
            with zipfile.ZipFile(spki, "w") as archive:
                archive.writestr(
                    "client.spki", privacy.ED25519_SPKI_PREFIX + (b"\x11" * 32)
                )
            self.assertGreaterEqual(privacy.validate_artifacts((spki,), {}), 1)

    def test_service_account_json_and_activation_secrets_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            sa = self.artifact(
                root,
                b'{"type":"service_account","project_id":"wins-proof",'
                b'"private_key_id":"abc123def456","client_email":'
                b'"proof@wins-proof.iam.gserviceaccount.com"}',
                "adc.json",
            )
            with self.assertRaisesRegex(
                privacy.PrivacyError, "google_service_account_json"
            ):
                privacy.validate_artifacts((sa,), {})
            named = root / "named.zip"
            with zipfile.ZipFile(named, "w") as archive:
                archive.writestr(
                    "google-service-account.json", b'{"project_id":"wins-proof"}'
                )
            with self.assertRaisesRegex(
                privacy.PrivacyError, "google_service_account_json"
            ):
                privacy.validate_artifacts((named,), {})
            activation = self.artifact(
                root,
                b'activation_secret="one-time-enrollment-secret-value-001"\n',
                "config.js",
            )
            with self.assertRaisesRegex(privacy.PrivacyError, "activation_secret"):
                privacy.validate_artifacts((activation,), {})
            header = self.artifact(
                root,
                b"x-wins-activation: one-time-enrollment-secret-value-001\n",
                "headers.js",
            )
            with self.assertRaisesRegex(privacy.PrivacyError, "activation_secret"):
                privacy.validate_artifacts((header,), {})

    def test_runtime_public_pins_and_public_keys_remain_allowed(self) -> None:
        payload = b"""
const String kSpkiWinsvpnOrgWildcard = 'H6Mj7DsLr6FAGUz4jLll4sc9AXDe3XcOsv4qWwUzY98=';
const String kReviewedAnnouncementPubkeyA1 = 'd9hwDSlQpYvnph33NJFHAbOm3hKR1wWEhC/kFiNoeoo=';
const String server_public_key = 'd9hwDSlQpYvnph33NJFHAbOm3hKR1wWEhC/kFiNoeoo=';
"""
        with tempfile.TemporaryDirectory() as temp_name:
            artifact = self.artifact(pathlib.Path(temp_name), payload, "pins.dart")
            self.assertEqual(
                privacy.validate_artifacts((artifact,), {}), ONE_MEMBER_ZIP_BLOBS
            )

    def test_private_key_pem_in_extension_package_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            artifact = self.artifact(
                pathlib.Path(temp_name),
                b"-----BEGIN PRIVATE KEY-----\nSYNTHETICONLYNOTAREALPRIVATEKEYMATERIALFORTESTSXX\n-----END PRIVATE KEY-----\n",
                "client.js",
            )
            with self.assertRaisesRegex(privacy.PrivacyError, "private_key_material"):
                privacy.validate_artifacts((artifact,), {})

    def test_unrelated_tempdir_sibling_churn_is_not_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            artifact = self.artifact(root, b"const ok = true;\n")
            stop = threading.Event()
            errors: list[BaseException] = []
            cycles = {"n": 0}

            def worker() -> None:
                try:
                    while not stop.is_set():
                        _churn_tempdir_siblings(f"ext-{cycles['n']}")
                        cycles["n"] += 1
                except BaseException as exc:
                    errors.append(exc)

            thread = threading.Thread(target=worker, daemon=True)
            thread.start()
            privacy._POST_PARENT_BIND_HOOK = _churn_bound_ancestors
            try:
                for _ in range(8):
                    self.assertEqual(
                        privacy.validate_artifacts((artifact,), {}), ONE_MEMBER_ZIP_BLOBS
                    )
            finally:
                privacy._POST_PARENT_BIND_HOOK = None
                stop.set()
                thread.join(timeout=5)
            self.assertFalse(errors)
            self.assertGreater(cycles["n"], 0)

    def test_parent_path_swap_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            base = pathlib.Path(temp_name)
            nested = base / "nested"
            nested.mkdir()
            other = base / "other"
            other.mkdir()
            artifact = self.artifact(nested, b"const ok = true;\n")
            self.artifact(other, b"const other = true;\n")
            file_index = len(artifact.parts) - 2

            def swap_parent(_path, index):
                if index != file_index:
                    return
                os.rename(nested, base / "nested-old")
                os.rename(other, nested)

            privacy._POST_PARENT_BIND_HOOK = swap_parent
            try:
                with self.assertRaisesRegex(privacy.PrivacyError, "replaced"):
                    privacy.validate_artifacts((artifact,), {})
            finally:
                privacy._POST_PARENT_BIND_HOOK = None

    def test_parent_swap_restore_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            base = pathlib.Path(temp_name)
            nested = base / "nested"
            nested.mkdir()
            other = base / "other"
            other.mkdir()
            artifact = self.artifact(nested, b"const ok = true;\n")
            self.artifact(other, b"const other = true;\n")
            nested_old = base / "nested-old"
            parent_index = len(artifact.parts) - 3
            file_index = len(artifact.parts) - 2

            def swap_restore(_path, index):
                if index == parent_index:
                    os.rename(nested, nested_old)
                    os.rename(other, nested)
                elif index == file_index:
                    os.rename(nested, other)
                    os.rename(nested_old, nested)

            privacy._POST_PARENT_BIND_HOOK = swap_restore
            try:
                with self.assertRaisesRegex(privacy.PrivacyError, "replaced"):
                    privacy.validate_artifacts((artifact,), {})
            finally:
                privacy._POST_PARENT_BIND_HOOK = None

    def test_minified_javascript_without_secrets_passes_privacy(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            artifact = self.artifact(
                pathlib.Path(temp_name),
                b"const ok=true;function start(){return 1;}",
            )
            self.assertEqual(
                privacy.validate_artifacts((artifact,), {}), ONE_MEMBER_ZIP_BLOBS
            )
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError,
                "not the reproducible esbuild producer output",
            ):
                obfuscation.verify_extension_javascript_hardening("chrome", [artifact])

    def test_minified_javascript_with_known_secret_is_rejected(self) -> None:
        secret = "synthetic-inventory-secret-alpha-0001"
        with tempfile.TemporaryDirectory() as temp_name:
            artifact = self.artifact(
                pathlib.Path(temp_name),
                b'const token="' + secret.encode("ascii") + b'";function start(){return 1;}',
            )
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError,
                "not the reproducible esbuild producer output",
            ):
                obfuscation.verify_extension_javascript_hardening("edge", [artifact])
            with self.assertRaisesRegex(privacy.PrivacyError, "SYNTHETIC_ALPHA") as raised:
                privacy.validate_artifacts((artifact,), {"SYNTHETIC_ALPHA": secret})
            self.assertNotIn(secret, str(raised.exception))

    def test_pretty_printed_javascript_fails_minification_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            artifact = self.artifact(
                pathlib.Path(temp_name),
                b"function start() {\n  const ok = true;\n  return ok;\n}\n",
            )
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError, "not store-permitted minified"
            ) as raised:
                obfuscation.verify_extension_javascript_hardening("firefox", [artifact])
            self.assertIn("does not protect client-held secrets", str(raised.exception))

    def test_obfuscated_javascript_is_rejected_without_security_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            artifact = self.artifact(
                pathlib.Path(temp_name),
                b"var _0xabcd=function(){return 1;}",
            )
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError, "Chrome forbids"
            ) as raised:
                obfuscation.verify_extension_javascript_hardening("chrome", [artifact])
            self.assertIn("not secret protection", str(raised.exception))
            self.assertIn("--minify", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
