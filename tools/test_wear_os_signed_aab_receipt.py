#!/usr/bin/env python3
"""Mutation tests for the Wear OS signed-AAB receipt and identity gates."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from contextlib import ExitStack, contextmanager
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

from test_wear_os_assert_release_aab import r8_mapping_bytes

RECEIPT_PY = ROOT / "wear_os/tools/signed_aab_receipt.py"
CREATE_RECEIPT_PY = ROOT / "wear_os/tools/create_signed_aab_receipt.py"
PREPARE = ROOT / "wear_os/tools/prepare_release.sh"
PIN_MANIFEST = ROOT / "wear_os/tools/external_tool_pins.json"
PHONE_PUBLICATION = ROOT / "tools/android_release_publication.py"
MACOS_PRODUCER = ROOT / "tools/build_android_release_macos.sh"
WIN_PRODUCER = ROOT / "tools/build_android_release.ps1"
SIGNER_TOOL = ROOT / "tools/verify_android_aab_signers.py"
PRIVACY_VALIDATOR = ROOT / "tools/validate_release_artifact_privacy.py"


def load_module(path: pathlib.Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_aab(path: pathlib.Path, mapping_bytes: bytes, extra: dict[str, bytes] | None = None) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("BundleConfig.pb", b"ok")
        archive.writestr(
            "BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map",
            mapping_bytes,
        )
        archive.writestr("base/manifest/AndroidManifest.xml", b"compiled-manifest-placeholder")
        for name, data in (extra or {}).items():
            archive.writestr(name, data)


def sign_aab(module, path: pathlib.Path, work: pathlib.Path, *, debug_cert: bool = False) -> None:
    keystore = work / ("debug.p12" if debug_cert else "upload.p12")
    dname = (
        "CN=Android Debug, O=Android, C=US"
        if debug_cert
        else "CN=WinsVPN Wear Test, O=WinsVPN, C=US"
    )
    with module._exact_release_tool(module.KEYTOOL_ENV, "keytool") as keytool:
        generated = module._run_exact_release_tool(
            keytool,
            [
                "-genkeypair",
                "-keystore",
                str(keystore),
                "-storetype",
                "PKCS12",
                "-storepass",
                "testpass",
                "-keypass",
                "testpass",
                "-alias",
                "upload",
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
                "-validity",
                "7",
                "-dname",
                dname,
            ],
        )
    if generated.returncode != 0:
        raise RuntimeError("test keytool failed closed")
    with module._exact_release_tool(module.JARSIGNER_ENV, "jarsigner") as jarsigner:
        signed = module._run_exact_release_tool(
            jarsigner,
            [
                "-keystore",
                str(keystore),
                "-storepass",
                "testpass",
                "-keypass",
                "testpass",
                "-sigalg",
                "SHA256withRSA",
                "-digestalg",
                "SHA-256",
                str(path),
                "upload",
            ],
        )
    if signed.returncode != 0:
        raise RuntimeError("test jarsigner failed closed")


def canonical_wear_inspected_manifest() -> dict[str, object]:
    return {
        "package": "org.winsvpn.app",
        "version_name": "1.0.16",
        "version_code": 3301,
        "min_sdk": 30,
        "target_sdk": 37,
        "minify_enabled": True,
        "watch_feature_required": True,
        "standalone": False,
    }


class WearOsSignedAabReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module(RECEIPT_PY, "wear_signed_aab_receipt")
        cls.signer = load_module(SIGNER_TOOL, "wear_test_signer_verifier")

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="wear-aab-receipt-")
        self.work = pathlib.Path(self.temporary.name)
        self.receipts = self.work / "receipts"
        self.receipts.mkdir()
        self.mapping = self.work / "mapping.txt"
        self.mapping_bytes = r8_mapping_bytes()
        self.mapping.write_bytes(self.mapping_bytes)

    def tearDown(self) -> None:
        for dirpath, _dirnames, filenames in os.walk(self.work):
            try:
                os.chmod(dirpath, 0o700)
            except FileNotFoundError:
                continue
            for name in filenames:
                try:
                    os.chmod(pathlib.Path(dirpath) / name, 0o600)
                except FileNotFoundError:
                    continue
        self.temporary.cleanup()

    def keystore_cert_sha256(self, keystore: pathlib.Path) -> str:
        with self.module._exact_release_tool(self.module.KEYTOOL_ENV, "keytool") as keytool:
            exported = self.module._run_exact_release_tool(
                keytool,
                [
                    "-exportcert",
                    "-alias",
                    "upload",
                    "-keystore",
                    str(keystore),
                    "-storepass",
                    "testpass",
                ],
            )
        if exported.returncode != 0 or not exported.stdout:
            raise RuntimeError("test keytool export failed closed")
        with self.module._exact_release_tool(self.module.OPENSSL_ENV, "OpenSSL") as openssl:
            fingerprint = self.module._run_exact_release_tool(
                openssl,
                ["x509", "-inform", "DER", "-noout", "-fingerprint", "-sha256"],
                input_bytes=exported.stdout,
            )
        if fingerprint.returncode != 0:
            raise RuntimeError("test openssl fingerprint failed closed")
        raw = fingerprint.stdout.decode("ascii", errors="replace")
        if "=" not in raw:
            raise RuntimeError("test openssl fingerprint is unusable")
        digest = raw.split("=", 1)[1].replace(":", "").strip().lower()
        if len(digest) != 64:
            raise RuntimeError("test certificate SHA-256 is malformed")
        return digest

    def signed_wear_aab(
        self,
        name: str = "app-release.aab",
        *,
        debug_cert: bool = False,
        mapping_bytes: bytes | None = None,
        extra: dict[str, bytes] | None = None,
    ) -> pathlib.Path:
        for environment_name, label in (
            (self.module.KEYTOOL_ENV, "keytool"),
            (self.module.JARSIGNER_ENV, "jarsigner"),
            (self.module.OPENSSL_ENV, "OpenSSL"),
        ):
            try:
                with self.module._exact_release_tool(environment_name, label):
                    pass
            except self.module.ReceiptError as error:
                self.skipTest(str(error))
        keys = self.work / f"keys-{name}"
        keys.mkdir()
        aab = self.work / name
        write_aab(aab, mapping_bytes if mapping_bytes is not None else self.mapping_bytes, extra)
        sign_aab(self.module, aab, keys, debug_cert=debug_cert)
        return aab

    def _inspected(self, aab: pathlib.Path) -> dict[str, object]:
        self.module._verify_android_signer_module(self.signer, aab)
        self.module._verify_jar_signature(aab)
        return {
            "ok": True,
            "manifest_decoder": {
                "decoder": "bundletool",
                "version": "1.18.3",
                "jar_sha256": "a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29",
            },
            "manifest": canonical_wear_inspected_manifest(),
            "native_libraries": [],
            "approved_native_library_count": 0,
        }

    def _external_gates(self, _repo, aab: pathlib.Path, _symbols_dir) -> dict[str, object]:
        return {
            "artifact_privacy": {
                "passed": True,
                "artifact_sha256": hashlib.sha256(aab.read_bytes()).hexdigest(),
            },
            "private_symbol_custody": {
                "passed": True,
                "manifest_sha256": "1" * 64,
                "sidecar_sha256": "2" * 64,
            },
        }

    @contextmanager
    def patched_release_gates(
        self,
        aab: pathlib.Path,
        *,
        expected_certificate: str | None = None,
        patch_identity: bool = True,
    ):
        certificate = expected_certificate or self.module._certificate(aab)[0]
        with ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    self.module,
                    "_assert_wear_signed_aab",
                    side_effect=lambda _repo, candidate: self._inspected(candidate),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    self.module,
                    "_verify_release_gates",
                    side_effect=self._external_gates,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    self.module,
                    "_verify_aab_page_alignment",
                    return_value=None,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    self.module,
                    "_reject_receipt_reuse",
                    return_value=None,
                )
            )
            if patch_identity:
                stack.enter_context(
                    mock.patch.object(
                        self.module,
                        "_reviewed_upload_certificate_sha256",
                        return_value=certificate,
                    )
                )
            yield

    def record(self, aab: pathlib.Path, receipt_dir: pathlib.Path):
        with self.patched_release_gates(aab):
            return self.module.record(ROOT, aab, self.mapping, receipt_dir)

    def verify(self, aab: pathlib.Path, receipt_dir: pathlib.Path):
        with self.patched_release_gates(aab):
            return self.module.verify(ROOT, aab, self.mapping, receipt_dir)

    def _fixture_executable(self, name: str, content: str = "#!/bin/sh\nexit 0\n") -> pathlib.Path:
        path = self.work / name
        path.write_text(content, encoding="ascii")
        path.chmod(0o500)
        return path

    def test_release_privacy_gate_uses_only_fixed_root_inventory(self) -> None:
        aab = self.work / "candidate.aab"
        aab.write_bytes(b"synthetic-aab")
        symbols = self.work / "symbols"
        symbols.mkdir()
        (symbols / "custody-manifest.json").write_bytes(b"{}\n")
        (symbols / "custody-manifest.sha256").write_bytes(b"1" * 64 + b"\n")
        calls: list[tuple[list[str], str]] = []

        def capture(arguments: list[str], label: str) -> None:
            calls.append((list(arguments), label))

        with mock.patch.object(self.module, "_run_gate", side_effect=capture):
            self.module._verify_release_gates(ROOT, aab, symbols)

        privacy_arguments, privacy_label = calls[0]
        self.assertEqual(privacy_label, "Wear release artifact privacy gate")
        self.assertIn("--authenticated-inventory", privacy_arguments)
        self.assertNotIn("--secret-inventory", privacy_arguments)
        self.assertNotIn("--inventory-contract", privacy_arguments)
        self.assertEqual(
            privacy_arguments[-2:],
            ["--target", self.module.CANONICAL_CROSS_STORE_TARGET],
        )

    def test_private_staged_bundle_satisfies_the_privacy_validator_target_identity(self) -> None:
        # The receipt hands the privacy gate its private copy of the AAB. The
        # validator refuses a wear-os-aab target whose file name is not
        # app-release.aab or whose path has no wear_os component.
        name = "wear_receipt_privacy_validator"
        spec = importlib.util.spec_from_file_location(name, PRIVACY_VALIDATOR)
        assert spec is not None and spec.loader is not None
        privacy = importlib.util.module_from_spec(spec)
        sys.modules[name] = privacy
        self.addCleanup(sys.modules.pop, name, None)
        spec.loader.exec_module(privacy)
        aab = self.work / "source" / "app-release.aab"
        aab.parent.mkdir()
        aab.write_bytes(b"synthetic-aab")
        mapping = self.work / "source" / "mapping.txt"
        mapping.write_bytes(b"synthetic-mapping")
        with self.module._private_input_snapshots(aab, mapping) as (staged_aab, staged_mapping):
            self.assertEqual(staged_aab.read_bytes(), b"synthetic-aab")
            self.assertEqual(staged_mapping.read_bytes(), b"synthetic-mapping")
            target = self.module.CANONICAL_CROSS_STORE_TARGET
            self.assertIn(staged_aab.name.casefold(), privacy.TARGET_CANONICAL_FILENAMES[target])
            self.assertTrue(privacy._path_markers_match(target, staged_aab))
            self.assertEqual(oct(staged_aab.parent.stat().st_mode & 0o777), "0o700")

    def _gate_environment_seen_by(self, arguments: list[str], inventory: str | None) -> dict[str, str]:
        seen: dict[str, dict[str, str]] = {}

        def fake_run(command, **options):
            seen["env"] = dict(options["env"])
            return subprocess.CompletedProcess(command, 0, b"", b"")

        environment = {"HOME": "/hostile-home", "FOO": "ambient"}
        if inventory is not None:
            environment[self.module.SECRET_INVENTORY_ENV] = inventory
        with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(
            self.module.subprocess, "run", side_effect=fake_run
        ):
            self.module._run_gate(arguments, "gate")
        return seen["env"]

    def test_privacy_gate_child_receives_only_the_inventory_path(self) -> None:
        privacy = [sys.executable, "privacy.py", self.module.AUTHENTICATED_INVENTORY_SWITCH, "--target", "wear-os-aab"]
        env = self._gate_environment_seen_by(privacy, "/outside/inventory.json")
        self.assertEqual(
            env,
            {
                "PATH": "/usr/bin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
                self.module.SECRET_INVENTORY_ENV: "/outside/inventory.json",
            },
        )

    def test_other_gate_children_never_receive_the_inventory_path(self) -> None:
        custody = [sys.executable, "custody.py", "verify", "--platform", "wear-os"]
        env = self._gate_environment_seen_by(custody, "/outside/inventory.json")
        self.assertEqual(env, {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})

    def test_privacy_gate_child_without_a_configured_inventory_gets_none(self) -> None:
        privacy = [sys.executable, "privacy.py", self.module.AUTHENTICATED_INVENTORY_SWITCH]
        for inventory in (None, ""):
            with self.subTest(inventory=inventory):
                env = self._gate_environment_seen_by(privacy, inventory)
                self.assertNotIn(self.module.SECRET_INVENTORY_ENV, env)

    def test_exact_tool_contract_rejects_missing_relative_and_invalid_paths(self) -> None:
        variable = self.module.OPENSSL_ENV
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(variable, None)
            with self.assertRaises(self.module.ReceiptError):
                with self.module._exact_release_tool(variable, "OpenSSL"):
                    pass

        relative = "relative/openssl"
        with mock.patch.dict(os.environ, {variable: relative}, clear=False):
            with self.assertRaises(self.module.ReceiptError):
                with self.module._exact_release_tool(variable, "OpenSSL"):
                    pass

        directory = self.work / "openssl-directory"
        directory.mkdir()
        with mock.patch.dict(os.environ, {variable: str(directory)}, clear=False):
            with self.assertRaises(self.module.ReceiptError):
                with self.module._exact_release_tool(variable, "OpenSSL"):
                    pass

        non_executable = self._fixture_executable("openssl-non-executable")
        non_executable.chmod(0o400)
        with mock.patch.dict(os.environ, {variable: str(non_executable)}, clear=False):
            with self.assertRaises(self.module.ReceiptError):
                with self.module._exact_release_tool(variable, "OpenSSL"):
                    pass

    def test_exact_tool_contract_rejects_symlink(self) -> None:
        executable = self._fixture_executable("real-openssl")
        linked = self.work / "linked-openssl"
        linked.symlink_to(executable)
        with mock.patch.dict(
            os.environ, {self.module.OPENSSL_ENV: str(linked)}, clear=False
        ):
            with self.assertRaises(self.module.ReceiptError):
                with self.module._exact_release_tool(self.module.OPENSSL_ENV, "OpenSSL"):
                    pass

    def test_exact_tool_contract_detects_path_replacement_during_execution(self) -> None:
        executable = self._fixture_executable("custody-openssl")
        replacement = self._fixture_executable("replacement-openssl")

        def replace_tool(*_args, **_kwargs):
            os.replace(replacement, executable)
            return subprocess.CompletedProcess([], 0, b"", b"")

        with mock.patch.dict(
            os.environ, {self.module.OPENSSL_ENV: str(executable)}, clear=False
        ), mock.patch.object(self.module.subprocess, "run", side_effect=replace_tool):
            with self.assertRaises(self.module.ReceiptError) as raised:
                with self.module._exact_release_tool(
                    self.module.OPENSSL_ENV, "OpenSSL"
                ) as tool:
                    self.module._run_exact_release_tool(tool, ["version"])
        self.assertIn("identity changed", str(raised.exception))

    def test_exact_tool_contract_detects_environment_substitution(self) -> None:
        executable = self._fixture_executable("custody-jarsigner")
        substitute = self._fixture_executable("substitute-jarsigner")

        def replace_environment(*_args, **_kwargs):
            os.environ[self.module.JARSIGNER_ENV] = str(substitute)
            return subprocess.CompletedProcess([], 0, b"jar verified", b"")

        with mock.patch.dict(
            os.environ, {self.module.JARSIGNER_ENV: str(executable)}, clear=False
        ), mock.patch.object(self.module.subprocess, "run", side_effect=replace_environment):
            with self.assertRaises(self.module.ReceiptError) as raised:
                self.module._verify_jar_signature(self.work / "candidate.aab")
        self.assertIn("path was substituted", str(raised.exception))

    def test_imported_signer_cannot_fall_back_to_ambient_tools(self) -> None:
        keytool = self._fixture_executable("exact-keytool")
        jarsigner = self._fixture_executable("exact-jarsigner")
        ambient_calls: list[str] = []
        observed: dict[str, object] = {}

        class FakeSigner:
            @staticmethod
            def _required_tool(name: str) -> str:
                ambient_calls.append(name)
                return f"/ambient/{name}"

            @staticmethod
            def _safe_tool_environment() -> dict[str, str]:
                return {"PATH": "/hostile"}

            def verify(self, _aab: pathlib.Path) -> None:
                observed["keytool"] = self._required_tool("keytool")
                observed["jarsigner"] = self._required_tool("jarsigner")
                observed["environment"] = self._safe_tool_environment()

        signer = FakeSigner()
        original_required_tool = signer._required_tool
        original_safe_environment = signer._safe_tool_environment
        with mock.patch.dict(
            os.environ,
            {
                self.module.KEYTOOL_ENV: str(keytool),
                self.module.JARSIGNER_ENV: str(jarsigner),
                "PATH": "/hostile",
            },
            clear=False,
        ):
            self.module._verify_android_signer_module(
                signer, self.work / "candidate.aab"
            )
        self.assertEqual(ambient_calls, [])
        self.assertEqual(observed["keytool"], str(keytool))
        self.assertEqual(observed["jarsigner"], str(jarsigner))
        self.assertEqual(
            observed["environment"],
            {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
        self.assertEqual(signer._required_tool, original_required_tool)
        self.assertEqual(signer._safe_tool_environment, original_safe_environment)

    def test_imported_signer_rejects_unexpected_tool_requests(self) -> None:
        keytool = self._fixture_executable("exact-keytool-unknown")
        jarsigner = self._fixture_executable("exact-jarsigner-unknown")

        class FakeSigner:
            @staticmethod
            def _required_tool(name: str) -> str:
                return f"/ambient/{name}"

            @staticmethod
            def _safe_tool_environment() -> dict[str, str]:
                return {"PATH": "/hostile"}

            def verify(self, _aab: pathlib.Path) -> None:
                self._required_tool("unexpected-tool")

        with mock.patch.dict(
            os.environ,
            {
                self.module.KEYTOOL_ENV: str(keytool),
                self.module.JARSIGNER_ENV: str(jarsigner),
            },
            clear=False,
        ):
            with self.assertRaises(self.module.ReceiptError):
                self.module._verify_android_signer_module(
                    FakeSigner(), self.work / "candidate.aab"
                )

    def test_tool_failures_do_not_log_secrets_or_forward_inherited_values(self) -> None:
        executable = self._fixture_executable("failing-jarsigner")
        secret = "wear-test-secret-do-not-log"
        observed_environments: list[dict[str, str]] = []

        def fail_with_secret(*_args, **kwargs):
            observed_environments.append(dict(kwargs["env"]))
            return subprocess.CompletedProcess([], 9, secret.encode(), secret.encode())

        inherited = {
            self.module.JARSIGNER_ENV: str(executable),
            "WINS_ANDROID_STORE_PASSWORD": secret,
            "WINS_ANDROID_KEY_PASSWORD": secret,
            "JAVA_HOME": f"/{secret}",
            "PATH": f"/{secret}",
        }
        with mock.patch.dict(os.environ, inherited, clear=False), mock.patch.object(
            self.module.subprocess, "run", side_effect=fail_with_secret
        ):
            with self.assertRaises(self.module.ReceiptError) as raised:
                self.module._verify_jar_signature(self.work / "candidate.aab")
        self.assertNotIn(secret, str(raised.exception))
        self.assertEqual(
            observed_environments,
            [{"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}],
        )

    def test_source_has_no_ambient_release_tool_discovery(self) -> None:
        source = RECEIPT_PY.read_text(encoding="utf-8")
        self.assertNotIn("shutil.which", source)
        self.assertNotIn('os.environ.get("PATH"', source)
        for variable in (
            "WINS_RELEASE_OPENSSL",
            "WINS_RELEASE_KEYTOOL",
            "WINS_RELEASE_JARSIGNER",
        ):
            self.assertIn(variable, source)

    def test_record_and_verify_bind_exact_signer_without_upload(self) -> None:
        aab = self.signed_wear_aab()
        certificate = self.module._certificate(aab)[0]
        receipt_dir = self.receipts / "ok"
        result = self.record(aab, receipt_dir)
        self.assertTrue(result["ok"])
        self.assertEqual(result["receipt_protection"], "permission-frozen")
        self.assertFalse(result["publication_authorized"])
        self.assertFalse(result["upload_performed"])
        self.assertTrue(self.verify(aab, receipt_dir)["ok"])

        payload = json.loads((receipt_dir / self.module.RECEIPT_NAME).read_text(encoding="utf-8"))
        self.assertEqual(payload["contract"], self.module.CONTRACT)
        self.assertEqual(payload["schema_version"], 2)
        self.assertEqual(payload["canonical_release"], "1.0.16+33")
        self.assertEqual(payload["signing"]["certificate_sha256"], certificate)
        self.assertEqual(
            payload["signing"]["expected_android_upload_certificate_sha256"], certificate
        )
        self.assertTrue(payload["signing"]["identity_match"])
        self.assertEqual(payload["receipt_storage"]["protection"], "permission-frozen")
        self.assertFalse(payload["receipt_storage"]["os_immutability_claimed"])
        self.assertFalse(payload["receipt_storage"]["external_append_only_store_claimed"])
        self.assertTrue(payload["gates"]["artifact_privacy"]["passed"])
        self.assertTrue(payload["gates"]["private_symbol_custody"]["passed"])
        mapping_digest = hashlib.sha256(self.mapping_bytes).hexdigest()
        self.assertEqual(payload["custody"]["mapping"]["sha256"], mapping_digest)
        self.assertEqual(
            payload["custody"]["embedded_proguard_map"]["sha256"], mapping_digest
        )
        self.assertTrue(payload["custody"]["binding"]["exact_bytes"])
        self.assertEqual(payload["custody"]["binding"]["canonicalization"], "identity")
        self.assertEqual(
            payload["gates"]["r8_mapping_bound"]["external_sha256"], mapping_digest
        )
        self.assertEqual(
            payload["gates"]["r8_mapping_bound"]["embedded_sha256"], mapping_digest
        )
        self.assertTrue(payload["gates"]["r8_mapping_bound"]["passed"])
        self.assertEqual(
            payload["artifact"]["sha256"], hashlib.sha256(aab.read_bytes()).hexdigest()
        )
        self.assertFalse(stat.S_IMODE(receipt_dir.stat().st_mode) & stat.S_IWUSR)
        self.assertEqual(payload["signing"]["package"], "org.winsvpn.app")
        self.assertEqual(payload["signing"]["version_name"], "1.0.16")
        self.assertEqual(payload["signing"]["version_code"], 3301)
        self.assertEqual(payload["signing"]["min_sdk"], 30)
        self.assertEqual(payload["signing"]["target_sdk"], 37)
        self.assertEqual(payload["store_metadata"]["canonical_release"], "1.0.16+33")
        self.assertEqual(payload["store_metadata"]["version_code"], 3301)
        self.assertFalse(payload["store_metadata"]["upload_authorized"])
        self.assertFalse(payload["store_metadata"]["submission_approved"])
        self.assertEqual(payload["store_metadata"]["companion_protocol"]["primary"], "winn-v3")
        self.assertEqual(
            payload["store_metadata"]["companion_protocol"]["fallback"], ["awg", "xray"]
        )
        self.assertFalse(payload["store_metadata"]["companion_protocol"]["local_wear_inclusion"])
        self.assertTrue(payload["gates"]["phone_vpn_engines_absent"])
        self.assertEqual(payload["gates"]["companion_protocol"]["primary"], "winn-v3")

    def test_arbitrary_non_debug_signer_is_rejected_against_authoritative_pin(self) -> None:
        aab = self.signed_wear_aab("arbitrary.aab")
        with self.patched_release_gates(aab, patch_identity=False):
            with self.assertRaises(self.module.ReceiptError) as raised:
                self.module.record(ROOT, aab, self.mapping, self.receipts / "arbitrary")
        self.assertIn("reviewed Android upload certificate", str(raised.exception))

    def test_debug_certificate_is_rejected_even_when_pin_matches(self) -> None:
        aab = self.signed_wear_aab("debug-pin-match.aab", debug_cert=True)
        digest = self.keystore_cert_sha256(
            self.work / "keys-debug-pin-match.aab" / "debug.p12"
        )
        with self.patched_release_gates(aab, expected_certificate=digest):
            with self.assertRaises(self.module.ReceiptError) as raised:
                self.module.record(ROOT, aab, self.mapping, self.receipts / "debug-pin-match")
        self.assertIn("Android debug signer", str(raised.exception))

    def test_mismatched_and_debug_certificates_are_rejected(self) -> None:
        cases = (
            ("mismatch.aab", False, "reviewed Android upload certificate"),
            ("debug.aab", True, "Android debug signer"),
        )
        for name, debug, expected in cases:
            with self.subTest(name=name):
                aab = self.signed_wear_aab(name, debug_cert=debug)
                with self.patched_release_gates(aab, expected_certificate="0" * 64):
                    with self.assertRaises(self.module.ReceiptError) as raised:
                        self.module.record(ROOT, aab, self.mapping, self.receipts / name)
                self.assertIn(expected, str(raised.exception))

    def test_unsigned_aab_is_rejected(self) -> None:
        aab = self.work / "unsigned.aab"
        write_aab(aab, self.mapping_bytes)
        with self.patched_release_gates(aab, expected_certificate="0" * 64):
            with self.assertRaises(Exception):
                self.module.record(ROOT, aab, self.mapping, self.receipts / "unsigned")

    def test_external_privacy_or_custody_failure_blocks_record(self) -> None:
        aab = self.signed_wear_aab("external-gate.aab")
        certificate = self.module._certificate(aab)[0]
        with mock.patch.object(
            self.module,
            "_assert_wear_signed_aab",
            side_effect=lambda _repo, candidate: self._inspected(candidate),
        ), mock.patch.object(
            self.module,
            "_reviewed_upload_certificate_sha256",
            return_value=certificate,
        ), mock.patch.object(
            self.module,
            "_verify_release_gates",
            side_effect=self.module.ReceiptError("custody failed closed"),
        ):
            with self.assertRaises(self.module.ReceiptError):
                self.module.record(ROOT, aab, self.mapping, self.receipts / "gate-fail")

    def test_source_replacement_during_private_staging_is_rejected(self) -> None:
        aab = self.signed_wear_aab("race.aab")
        replacement = self.work / "replacement.aab"
        replacement.write_bytes(aab.read_bytes())
        original_copy = self.module._copy_open_file
        original_identity = aab.stat()
        swapped = False

        def copy_then_swap(source_fd: int, destination_fd: int) -> None:
            nonlocal swapped
            original_copy(source_fd, destination_fd)
            observed = os.fstat(source_fd)
            if (
                not swapped
                and observed.st_dev == original_identity.st_dev
                and observed.st_ino == original_identity.st_ino
            ):
                os.replace(replacement, aab)
                swapped = True

        with mock.patch.object(self.module, "_copy_open_file", side_effect=copy_then_swap):
            with self.assertRaises(self.module.ReceiptError) as raised:
                self.module.record(ROOT, aab, self.mapping, self.receipts / "race")
        self.assertIn("changed during private staging", str(raised.exception))

    def test_symlink_input_is_rejected(self) -> None:
        aab = self.signed_wear_aab("real.aab")
        link = self.work / "linked.aab"
        link.symlink_to(aab)
        with self.assertRaises(self.module.ReceiptError):
            self.module.record(ROOT, link, self.mapping, self.receipts / "link")

    def test_existing_receipt_directory_cannot_be_overwritten(self) -> None:
        aab = self.signed_wear_aab("once.aab")
        receipt_dir = self.receipts / "once"
        self.record(aab, receipt_dir)
        os.chmod(receipt_dir, 0o700)
        with self.patched_release_gates(aab):
            with self.assertRaises(self.module.ReceiptError):
                self.module.record(ROOT, aab, self.mapping, receipt_dir)

    def test_tampered_aab_and_mapping_fail_verify(self) -> None:
        aab = self.signed_wear_aab("tamper.aab")
        receipt_dir = self.receipts / "tamper"
        self.record(aab, receipt_dir)
        aab.write_bytes(aab.read_bytes() + b"\x00")
        with self.assertRaises(self.module.ReceiptError):
            self.verify(aab, receipt_dir)

        aab = self.signed_wear_aab("tamper-map.aab")
        receipt_dir = self.receipts / "tamper-map"
        self.record(aab, receipt_dir)
        self.mapping.write_text(self.mapping.read_text(encoding="utf-8") + "tamper\n")
        with self.assertRaises(self.module.ReceiptError):
            self.verify(aab, receipt_dir)

    def test_writable_receipt_fails_verify(self) -> None:
        aab = self.signed_wear_aab("writable.aab")
        receipt_dir = self.receipts / "writable"
        self.record(aab, receipt_dir)
        os.chmod(receipt_dir, 0o755)
        with self.assertRaises(self.module.ReceiptError):
            self.verify(aab, receipt_dir)

    def test_permission_refreeze_does_not_create_an_immutability_claim(self) -> None:
        aab = self.signed_wear_aab("authorized.aab")
        receipt_dir = self.receipts / "authorized"
        self.record(aab, receipt_dir)
        receipt = receipt_dir / self.module.RECEIPT_NAME
        sidecar = receipt_dir / self.module.SIDECAR_NAME
        os.chmod(receipt_dir, 0o700)
        os.chmod(receipt, 0o644)
        os.chmod(sidecar, 0o644)
        payload = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertFalse(payload["receipt_storage"]["os_immutability_claimed"])
        payload["publication_authorized"] = True
        serialized = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
        receipt.write_bytes(serialized)
        sidecar.write_text(
            f"{hashlib.sha256(serialized).hexdigest()}  {self.module.RECEIPT_NAME}\n",
            encoding="ascii",
        )
        os.chmod(receipt, 0o444)
        os.chmod(sidecar, 0o444)
        os.chmod(receipt_dir, 0o555)
        with self.assertRaises(self.module.ReceiptError):
            self.verify(aab, receipt_dir)

    def test_provenance_covers_producer_and_all_release_gates(self) -> None:
        expected = {
            "wear_os/tools/prepare_release.sh",
            "wear_os/tools/assert_release_aab.py",
            "wear_os/tools/signed_aab_receipt.py",
            "wear_os/tools/create_signed_aab_receipt.py",
            "tools/build_android_release_macos.sh",
            "tools/private_release_symbol_custody.py",
            "tools/validate_release_artifact_privacy.py",
            "tools/verify_android_aab_signers.py",
            "tools/verify_android_aab_page_alignment.py",
            "docs/rulings/RELEASE_IDENTITY_MAP_20260824.json",
        }
        self.assertTrue(expected.issubset(set(self.module.PROVENANCE_PATHS)))
        pin = self.module._reviewed_upload_certificate_sha256(ROOT)
        self.assertRegex(pin, r"^[0-9a-f]{64}$")

    def test_producer_is_independent_and_never_uploads(self) -> None:
        script = PREPARE.read_text(encoding="utf-8")
        self.assertIn(":app:bundleRelease", script)
        self.assertIn("create_signed_aab_receipt.py", script)
        self.assertIn("android-release.env", script)
        self.assertIn("OWNER-BLOCKED: missing Android upload keystore", script)
        self.assertIn("chmod 0444", script)
        self.assertIn("Publication remains unauthorized", script)
        self.assertNotIn("upload-ready", script)
        self.assertIn("private_release_symbol_custody.py", script)
        self.assertIn("validate_release_artifact_privacy.py", script)
        self.assertIn("verify_android_aab_signers.py", script)
        self.assertIn("permission-frozen", script)
        self.assertIn("No Play Console upload or publication occurred.", script)
        self.assertNotIn("android_release_publication.py commit", script)
        self.assertNotIn("build_android_release_macos.sh", script)
        self.assertNotIn("build_android_release.ps1", script)
        self.assertNotIn("play.google.com", script)
        self.assertNotIn("androidpublisher", script)
        self.assertNotIn("bundletool upload", script)
        self.assertNotIn("curl ", script)
        self.assertNotIn("wget ", script)
        self.assertIn('"${VERSION_NAME}" == "1.0.16"', script)
        self.assertIn('"${VERSION_CODE}" == "3301"', script)
        publication = PHONE_PUBLICATION.read_text(encoding="utf-8")
        self.assertNotIn("wear_os", publication)
        self.assertNotIn("wear-os", publication)
        # The phone producer stages wear_os/app/build.gradle.kts only so the
        # obfuscation static contract can read it; nothing else may name Wear.
        macos_producer = MACOS_PRODUCER.read_text(encoding="utf-8")
        self.assertEqual(macos_producer.count("'wear_os/app/build.gradle.kts',"), 1)
        self.assertNotIn(
            "wear_os",
            macos_producer.replace("'wear_os/app/build.gradle.kts',", "", 1),
        )
        self.assertNotIn("wear_os", WIN_PRODUCER.read_text(encoding="utf-8"))

    def test_tiny_mapping_cannot_record_even_when_embedded_matches(self) -> None:
        tiny = b"# compiler: R8\nclass org.winsvpn.app.wear.MainActivity\n"
        self.mapping.write_bytes(tiny)
        aab = self.signed_wear_aab("tiny.aab", mapping_bytes=tiny)
        with self.patched_release_gates(aab):
            with self.assertRaises(self.module.ReceiptError) as raised:
                self.module.record(ROOT, aab, self.mapping, self.receipts / "tiny")
        self.assertIn("too small", str(raised.exception))

    def test_mismatched_external_and_embedded_mappings_fail_record(self) -> None:
        aab = self.signed_wear_aab("mismatch-map.aab", mapping_bytes=r8_mapping_bytes(41))
        with self.patched_release_gates(aab):
            with self.assertRaises(self.module.ReceiptError) as raised:
                self.module.record(ROOT, aab, self.mapping, self.receipts / "mismatch-map")
        self.assertIn("not bound", str(raised.exception))

    def test_absent_and_duplicate_embedded_mappings_fail_record(self) -> None:
        for name, extra in (
            ("absent-map.aab", None),
            ("duplicate-map.aab", {"assets/proguard.map": self.mapping_bytes}),
        ):
            with self.subTest(name=name):
                aab = self.work / name
                with zipfile.ZipFile(aab, "w") as archive:
                    archive.writestr("BundleConfig.pb", b"ok")
                    if extra is not None:
                        archive.writestr(
                            "BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map",
                            self.mapping_bytes,
                        )
                        for member, data in extra.items():
                            archive.writestr(member, data)
                    archive.writestr(
                        "base/manifest/AndroidManifest.xml",
                        b"compiled-manifest-placeholder",
                    )
                with self.assertRaises(self.module.ReceiptError) as raised:
                    self.module.record(ROOT, aab, self.mapping, self.receipts / name)
                message = str(raised.exception)
                self.assertTrue("missing release proguard.map" in message or "duplicate proguard.map" in message)

    def test_crlf_embedded_mapping_records_both_raw_hashes(self) -> None:
        crlf = r8_mapping_bytes(newline="\r\n")
        aab = self.signed_wear_aab("crlf.aab", mapping_bytes=crlf)
        receipt_dir = self.receipts / "crlf"
        result = self.record(aab, receipt_dir)
        self.assertTrue(result["ok"])
        payload = json.loads((receipt_dir / self.module.RECEIPT_NAME).read_text(encoding="utf-8"))
        self.assertFalse(payload["custody"]["binding"]["exact_bytes"])
        self.assertEqual(payload["custody"]["binding"]["canonicalization"], "utf-8-lf")
        self.assertEqual(
            payload["custody"]["mapping"]["sha256"],
            hashlib.sha256(self.mapping_bytes).hexdigest(),
        )
        self.assertEqual(
            payload["custody"]["embedded_proguard_map"]["sha256"],
            hashlib.sha256(crlf).hexdigest(),
        )
        self.assertNotEqual(
            payload["custody"]["mapping"]["sha256"],
            payload["custody"]["embedded_proguard_map"]["sha256"],
        )
        self.assertEqual(
            payload["gates"]["r8_mapping_bound"]["canonical_sha256"],
            hashlib.sha256(self.mapping_bytes).hexdigest(),
        )
        self.assertTrue(self.verify(aab, receipt_dir)["ok"])


class WearOsCreateSignedAabReceiptCustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module(CREATE_RECEIPT_PY, "wear_create_signed_aab_receipt")
        cls.legacy = load_module(RECEIPT_PY, "wear_signed_aab_receipt")

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="wear-create-receipt-")
        self.work = pathlib.Path(self.temporary.name)
        self.receipts = self.work / "receipts"
        self.receipts.mkdir()
        self.mapping = self.work / "mapping.txt"
        self.mapping_bytes = r8_mapping_bytes()
        self.mapping.write_bytes(self.mapping_bytes)
        self.index = self.work / "RELEASE_INPUT_INDEX.json"
        self.index.write_text("{}\n", encoding="ascii")

    def tearDown(self) -> None:
        for dirpath, _dirnames, filenames in os.walk(self.work):
            try:
                os.chmod(dirpath, 0o700)
            except FileNotFoundError:
                continue
            for name in filenames:
                try:
                    os.chmod(pathlib.Path(dirpath) / name, 0o600)
                except FileNotFoundError:
                    continue
        self.temporary.cleanup()

    def dummy_aab(self, name: str = "app-release.aab", mapping_bytes: bytes | None = None) -> pathlib.Path:
        aab = self.work / name
        write_aab(aab, mapping_bytes if mapping_bytes is not None else self.mapping_bytes)
        return aab

    def freeze_binding(self) -> dict[str, object]:
        return {
            "lock_path": ".artifacts/release-freeze-1.0.16+33/APP_SOURCE_LOCK.json",
            "source_fingerprint_sha256": "a" * 64,
            "app_source_fingerprint_sha256": "b" * 64,
            "source_file_count": 12,
            "issuance_id": "abcdef0123456789abcdef0123456789",
            "issuance_sha256": "c" * 64,
            "issuance_path": str((ROOT / "tools/release_source_freeze.trust.json").resolve()),
            "authenticated": True,
        }

    def dependency_binding(self) -> dict[str, object]:
        return {
            "index_path": ".artifacts/example/RELEASE_INPUT_INDEX.json",
            "index_sha256": "d" * 64,
            "release": "1.0.16+33",
            "platform": "wear_os",
            "wear_os_artifact_input_fingerprint_sha256": "e" * 64,
            "authenticated": True,
        }

    def _inspected(self, _aab: pathlib.Path) -> dict[str, object]:
        pin = json.loads(PIN_MANIFEST.read_text(encoding="ascii"))["bundletool"]
        return {
            "ok": True,
            "manifest_decoder": {
                "decoder": "bundletool",
                "version": pin["version"],
                "jar_sha256": pin["sha256"],
                "source_url": pin["source_url"],
            },
            "manifest": canonical_wear_inspected_manifest(),
            "native_libraries": [],
            "approved_native_library_count": 0,
        }

    def _external_gates(self, _repo, aab: pathlib.Path, _symbols_dir) -> dict[str, object]:
        return {
            "artifact_privacy": {
                "passed": True,
                "artifact_sha256": hashlib.sha256(aab.read_bytes()).hexdigest(),
            },
            "private_symbol_custody": {
                "passed": True,
                "manifest_sha256": "1" * 64,
                "sidecar_sha256": "2" * 64,
            },
        }

    @contextmanager
    def patched_record(self, aab: pathlib.Path, *, expected_certificate: str | None = None):
        certificate = expected_certificate or ("f" * 64)
        with ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    self.module,
                    "_bind_source_freeze",
                    return_value=self.freeze_binding(),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    self.module,
                    "_bind_dependency_freeze",
                    return_value=self.dependency_binding(),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    self.legacy,
                    "_assert_wear_signed_aab",
                    side_effect=lambda _repo, candidate: self._inspected(candidate),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    self.legacy,
                    "_verify_release_gates",
                    side_effect=self._external_gates,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    self.legacy,
                    "_verify_aab_page_alignment",
                    return_value=None,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    self.legacy,
                    "_reject_receipt_reuse",
                    return_value=None,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    self.legacy,
                    "_reviewed_upload_certificate_sha256",
                    return_value=certificate,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    self.legacy,
                    "_certificate",
                    return_value=(certificate if expected_certificate is None else ("a" * 64), "subject"),
                )
            )
            stack.enter_context(
                mock.patch.object(self.module, "_legacy", return_value=self.legacy)
            )
            yield

    def run_prepare(self, env: dict[str, str], home: pathlib.Path) -> subprocess.CompletedProcess[str]:
        environment = {
            "HOME": str(home),
            "PATH": env.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"),
            "LANG": "C",
            "LC_ALL": "C",
        }
        environment.update(env)
        return subprocess.run(
            ["/bin/bash", "-p", str(PREPARE)],
            cwd=ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_current_positive_fixture_binds_freeze_producer_and_schema_v2(self) -> None:
        aab = self.dummy_aab("positive.aab")
        receipt_dir = self.receipts / "positive"
        with self.patched_record(aab):
            result = self.module.record(
                ROOT, aab, self.mapping, receipt_dir, self.index
            )
            self.assertTrue(result["ok"])
            verified = self.module.verify(
                ROOT, aab, self.mapping, receipt_dir, self.index
            )
        self.assertTrue(verified["ok"])
        payload = json.loads((receipt_dir / self.module.RECEIPT_NAME).read_text(encoding="utf-8"))
        self.assertEqual(payload["schema_version"], 2)
        self.assertEqual(payload["contract"], self.module.CONTRACT)
        self.assertEqual(payload["canonical_release"], "1.0.16+33")
        self.assertEqual(payload["signing"]["package"], "org.winsvpn.app")
        self.assertEqual(payload["signing"]["version_code"], 3301)
        self.assertEqual(payload["signing"]["version_name"], "1.0.16")
        self.assertEqual(payload["signing"]["min_sdk"], 30)
        self.assertEqual(payload["signing"]["target_sdk"], 37)
        self.assertEqual(payload["store_metadata"]["application_id"], "org.winsvpn.app")
        self.assertEqual(payload["store_metadata"]["version_code"], 3301)
        self.assertFalse(payload["store_metadata"]["upload_authorized"])
        self.assertTrue(payload["gates"]["phone_vpn_engines_absent"])
        self.assertEqual(payload["gates"]["companion_protocol"]["primary"], "winn-v3")
        self.assertEqual(payload["source_freeze"]["issuance_id"], self.freeze_binding()["issuance_id"])
        self.assertEqual(payload["dependency_freeze"]["platform"], "wear_os")
        self.assertEqual(payload["private_symbol_custody"]["schema_version"], 2)
        self.assertEqual(
            payload["private_symbol_custody"]["contract"],
            self.module.SYMBOL_CONTRACT,
        )
        producer = payload["producer"]
        for relative in self.module.PRODUCER_PATHS:
            self.assertEqual(
                producer[relative]["sha256"],
                hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(),
            )
        self.assertFalse(payload["publication_authorized"])

    def test_wrong_signer_is_rejected(self) -> None:
        aab = self.dummy_aab("wrong-signer.aab")
        with self.patched_record(aab, expected_certificate="0" * 64):
            with self.assertRaises(self.module.ReceiptError) as raised:
                self.module.record(
                    ROOT, aab, self.mapping, self.receipts / "wrong-signer", self.index
                )
        self.assertIn("reviewed Android upload certificate", str(raised.exception))

    def test_missing_symbol_is_rejected(self) -> None:
        aab = self.dummy_aab("missing-symbol.aab")
        missing = self.work / "absent-mapping.txt"
        with self.patched_record(aab):
            with self.assertRaises(self.module.ReceiptError) as raised:
                self.module.record(
                    ROOT, aab, missing, self.receipts / "missing-symbol", self.index
                )
        self.assertIn("missing Wear R8 mapping symbol", str(raised.exception))

    def test_self_authored_receipt_cannot_authorize(self) -> None:
        receipt_dir = self.receipts / "self-auth"
        receipt_dir.mkdir()
        forged = receipt_dir / self.module.RECEIPT_NAME
        forged.write_text("{}", encoding="ascii")
        binding = self.freeze_binding()
        binding["issuance_path"] = str(forged)
        with self.assertRaises(self.module.ReceiptError) as raised:
            self.module._reject_self_authorized(binding, receipt_dir)
        self.assertIn("self-authored", str(raised.exception))
        zeros = self.freeze_binding()
        zeros["issuance_id"] = "0" * 32
        with self.assertRaises(self.module.ReceiptError) as raised:
            self.module._reject_self_authorized(zeros, receipt_dir)
        self.assertIn("self-authored", str(raised.exception))
        with self.assertRaises(self.module.ReceiptError) as raised:
            self.module._bind_source_freeze(ROOT)
        self.assertIn("OWNER-BLOCKED", str(raised.exception))

    def test_hostile_path_does_not_run_ambient_tools(self) -> None:
        home = self.work / "hostile-home"
        home.mkdir()
        marker = home / "hostile-ran"
        for name in ("python3", "java", "curl", "wget", "gradle", "bundletool"):
            fake = home / name
            fake.write_text(
                f"#!/bin/sh\nprintf ran >> '{marker}'\nexit 0\n",
                encoding="ascii",
            )
            fake.chmod(0o755)
        completed = self.run_prepare({"PATH": str(home)}, home)
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse(marker.exists())
        combined = completed.stdout + completed.stderr
        self.assertIn("android-release.env", combined)
        self.assertIn("OWNER-BLOCKED", combined)

    def test_partial_env_fails_closed(self) -> None:
        home = self.work / "partial-home"
        private = home / ".winsvpn"
        private.mkdir(parents=True)
        env_file = private / "android-release.env"
        env_file.write_text("WINS_ANDROID_KEY_ALIAS=winsvpn-release\n", encoding="ascii")
        env_file.chmod(0o600)
        completed = self.run_prepare({}, home)
        self.assertNotEqual(completed.returncode, 0)
        combined = completed.stdout + completed.stderr
        self.assertIn("OWNER-BLOCKED", combined)
        self.assertRegex(combined, r"partial env|android-release.env|KEYSTORE|missing owner keystore")

    def test_missing_keystore_is_owner_blocked(self) -> None:
        home = self.work / "missing-keystore-home"
        private = home / ".winsvpn"
        private.mkdir(parents=True)
        os.chmod(home, 0o700)
        os.chmod(private, 0o700)
        env_file = private / "android-release.env"
        env_file.write_text(
            "WINS_ANDROID_KEYSTORE=/outside/missing.keystore\n"
            "WINS_ANDROID_KEY_ALIAS=winsvpn-release\n"
            "WINS_ANDROID_KEY_PASSWORD=password\n"
            "WINS_ANDROID_STORE_PASSWORD=password\n",
            encoding="ascii",
        )
        env_file.chmod(0o600)
        completed = self.run_prepare({}, home)
        self.assertNotEqual(completed.returncode, 0)
        combined = completed.stdout + completed.stderr
        self.assertIn("OWNER-BLOCKED: missing Android upload keystore", combined)
        self.assertNotIn("stale Wear AAB already exists", combined)

    def test_stale_existing_aab_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as name:
            home = pathlib.Path(name)
            private = home / ".winsvpn"
            private.mkdir(parents=True)
            keystore = home / "upload.keystore"
            keystore.write_bytes(b"test-only-keystore-placeholder")
            keystore.chmod(0o600)
            env_file = private / "android-release.env"
            env_file.write_text(
                f'WINS_ANDROID_KEYSTORE="{keystore}"\n'
                "WINS_ANDROID_KEY_ALIAS=winsvpn-release\n"
                "WINS_ANDROID_KEY_PASSWORD=password\n"
                "WINS_ANDROID_STORE_PASSWORD=password\n",
                encoding="ascii",
            )
            env_file.chmod(0o600)
            canonical = ROOT / "wear_os/app/build/outputs/bundle/release/app-release.aab"
            canonical.parent.mkdir(parents=True, exist_ok=True)
            planted = False
            try:
                if not canonical.exists():
                    canonical.write_bytes(b"stale-aab-fixture")
                    planted = True
                completed = self.run_prepare({}, home)
                self.assertNotEqual(completed.returncode, 0)
                combined = completed.stdout + completed.stderr
                self.assertIn("stale Wear AAB already exists", combined)
            finally:
                if planted:
                    canonical.unlink(missing_ok=True)

    def test_pin_manifest_names_latest_stable_bundletool_source_and_hash(self) -> None:
        payload = json.loads(PIN_MANIFEST.read_text(encoding="ascii"))
        self.assertTrue(payload["latest_stable"])
        bundletool = payload["bundletool"]
        self.assertTrue(bundletool["latest_stable"])
        self.assertEqual(bundletool["artifact"], "bundletool-all-1.18.3.jar")
        self.assertRegex(bundletool["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            bundletool["source_url"],
            "https://github.com/google/bundletool/releases/download/1.18.3/bundletool-all-1.18.3.jar",
        )
        self.assertTrue(pathlib.Path(bundletool["archive_path"]).is_absolute())


class WearOsCrossStoreReceiptBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module(RECEIPT_PY, "wear_receipt_binding")
        cls.creator = load_module(CREATE_RECEIPT_PY, "wear_create_receipt_binding")

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="wear-bind-")
        self.repo = pathlib.Path(self.temporary.name)
        self.aab = self.repo / "app-release.aab"
        self.aab.write_bytes(b"wear-candidate-bytes-1.0.16+33")
        self.pins = {
            "application_id": "org.winsvpn.app",
            "version_name": "1.0.16",
            "version_code": 3301,
        }
        self.digest = hashlib.sha256(self.aab.read_bytes()).hexdigest()
        self.size = self.aab.stat().st_size

    def tearDown(self) -> None:
        for dirpath, _dirnames, filenames in os.walk(self.repo):
            try:
                os.chmod(dirpath, 0o700)
            except FileNotFoundError:
                continue
            for name in filenames:
                try:
                    os.chmod(pathlib.Path(dirpath) / name, 0o600)
                except FileNotFoundError:
                    continue
        self.temporary.cleanup()

    def payload(self, **overrides: object) -> dict[str, object]:
        record: dict[str, object] = {
            "schema_version": 2,
            "contract": self.module.CONTRACT,
            "canonical_release": "1.0.16+33",
            "application_id": "org.winsvpn.app",
            "version_name": "1.0.16",
            "version_code": 3301,
            "platform": "wear-os",
            "play_track": "wear-os",
            "publication_authorized": False,
            "upload_performed": False,
            "artifact": {
                "name": "app-release.aab",
                "size_bytes": self.size,
                "sha256": self.digest,
            },
            "source_freeze": {
                "authenticated": True,
                "issuance_id": "abcdef0123456789abcdef0123456789",
                "issuance_path": str((ROOT / "tools/release_source_freeze.trust.json").resolve()),
            },
            "dependency_freeze": {
                "index_path": ".artifacts/index.json",
                "authenticated": True,
            },
            "receipt_storage": {
                "protection": "permission-frozen",
                "os_immutability_claimed": False,
                "external_append_only_store_claimed": False,
            },
        }
        record.update(overrides)
        return record

    def freeze_receipt(self, name: str, payload: dict[str, object]) -> pathlib.Path:
        receipt_dir = self.repo / ".artifacts/release-build-receipts/wear-os" / name
        receipt_dir.mkdir(parents=True)
        serialized = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
        receipt = receipt_dir / self.module.RECEIPT_NAME
        sidecar = receipt_dir / self.module.SIDECAR_NAME
        receipt.write_bytes(serialized)
        sidecar.write_text(
            f"{hashlib.sha256(serialized).hexdigest()}  {self.module.RECEIPT_NAME}\n",
            encoding="ascii",
        )
        os.chmod(receipt, 0o444)
        os.chmod(sidecar, 0o444)
        os.chmod(receipt_dir, 0o555)
        return receipt_dir

    def test_canonical_identity_is_exact_1015_wear_candidate(self) -> None:
        identity = self.module._canonical_release_identity(ROOT)
        self.assertEqual(identity["canonical_release"], "1.0.16+33")
        self.assertEqual(identity["package"], "org.winsvpn.app")
        self.assertEqual(identity["version_name"], "1.0.16")
        self.assertEqual(identity["version_code"], 3301)
        pins = self.module._require_pin_alignment(ROOT)
        self.assertEqual(pins["canonical_release"], "1.0.16+33")
        self.assertEqual(pins["application_id"], "org.winsvpn.app")
        self.assertEqual(pins["version_code"], 3301)
        candidate = json.loads(
            (ROOT / self.module.RELEASE_CANDIDATE_RELATIVE).read_text(encoding="ascii")
        )
        artifact = candidate["artifact"]
        self.assertEqual(artifact["build_variant"], "release")
        self.assertIs(artifact["obfuscated"], True)
        self.assertIs(artifact["debug_artifact_allowed"], False)
        self.assertIs(artifact["owner_signing_required"], True)

    def test_missing_receipt_is_pending_owner_blocker(self) -> None:
        with self.assertRaises(self.module.ReceiptError) as raised:
            self.module._bind_unique_wear_receipt(
                self.repo, self.aab, self.digest, self.size, self.pins
            )
        self.assertIn("owner/build-system blocker", str(raised.exception))
        self.assertIn("OWNER-BLOCKED", str(raised.exception))
        self.assertIn("no immutable Wear signed-AAB receipt", str(raised.exception))

    def test_copied_receipt_reuse_fails_closed_not_pending(self) -> None:
        first = self.freeze_receipt("one", self.payload())
        self.freeze_receipt("copied", self.payload())
        with mock.patch.object(self.module, "_verify_source_closure"):
            with self.assertRaises(self.module.ReceiptError) as raised:
                self.module._bind_unique_wear_receipt(
                    self.repo, self.aab, self.digest, self.size, self.pins
                )
        self.assertIn("receipt reuse", str(raised.exception))
        self.assertNotIn("owner/build-system blocker", str(raised.exception))
        os.chmod(first, 0o700)

    def test_unique_receipt_binds_and_stays_unauthorized(self) -> None:
        receipt_dir = self.freeze_receipt("only", self.payload())
        with mock.patch.object(self.module, "_verify_source_closure") as closure:
            bound = self.module._bind_unique_wear_receipt(
                self.repo, self.aab, self.digest, self.size, self.pins
            )
        self.assertEqual(bound.resolve(), receipt_dir.resolve())
        closure.assert_called_once()
        payload = self.module._load_receipt(receipt_dir)
        self.assertFalse(payload["publication_authorized"])
        self.assertFalse(payload["upload_performed"])
        self.assertEqual(payload["canonical_release"], "1.0.16+33")

    def test_identity_swap_of_bound_bytes_fails_closed(self) -> None:
        self.freeze_receipt(
            "wrong-code",
            self.payload(version_code=30),
        )
        with self.assertRaises(self.module.ReceiptError) as raised:
            self.module._bind_unique_wear_receipt(
                self.repo, self.aab, self.digest, self.size, self.pins
            )
        self.assertIn("canonical 1.0.16+33 candidate", str(raised.exception))
        self.assertNotIn("owner/build-system blocker", str(raised.exception))

    def test_origin_swap_is_not_pending(self) -> None:
        before = self.aab.stat()
        self.aab.write_bytes(self.aab.read_bytes() + b"X")
        with self.assertRaises(self.module.ReceiptError) as raised:
            self.module._reject_origin_swap(self.aab, before, "Wear AAB")
        self.assertIn("swapped or restored", str(raised.exception))
        self.assertNotIn("owner/build-system blocker", str(raised.exception))

    def test_page_alignment_is_required_for_native_wear_aab(self) -> None:
        with zipfile.ZipFile(self.aab, "w") as archive:
            archive.writestr("BundleConfig.pb", b"not-a-proto")
            archive.writestr("base/lib/arm64-v8a/libapp.so", b"native")
        with self.assertRaises(self.module.ReceiptError) as raised:
            self.module._verify_aab_page_alignment(ROOT, self.aab)
        self.assertIn("16 KiB page alignment", str(raised.exception))

    def test_create_receipt_payload_stays_pending_without_owner_signing(self) -> None:
        source = CREATE_RECEIPT_PY.read_text(encoding="utf-8")
        self.assertIn('publication_authorized": False', source)
        self.assertIn("canonical_release", source)
        self.assertIn("_verify_aab_page_alignment", source)
        self.assertIn("_reject_receipt_reuse", source)
        self.assertIn("_reviewed_store_metadata", source)
        self.assertIn("_signing_claims", source)
        self.assertIn("_hold_aab_bytes", source)
        self.assertIn("_revalidate_held_aab", source)
        self.assertIn("wear_os/tools/signed_aab_receipt.py", source)
        self.assertIn("1.0.16+33", source)
        self.assertNotIn("publication_authorized\": True", source)

    def test_source_closure_missing_is_pending(self) -> None:
        receipt_dir = self.freeze_receipt(
            "no-freeze",
            self.payload(source_freeze="missing"),
        )
        with self.assertRaises(self.module.ReceiptError) as raised:
            self.module._bind_unique_wear_receipt(
                self.repo, self.aab, self.digest, self.size, self.pins
            )
        self.assertIn("owner/build-system blocker", str(raised.exception))
        self.assertIn("OWNER-BLOCKED", str(raised.exception))
        os.chmod(receipt_dir, 0o700)

    def test_missing_upload_candidate_aab_is_owner_blocked(self) -> None:
        with self.assertRaises(self.module.ReceiptError) as raised:
            self.module._canonical_gate_artifact(
                self.repo, "wear-os-aab", "wear_os/app/build/outputs/bundle/release/app-release.aab"
            )
        self.assertIn("OWNER-BLOCKED", str(raised.exception))
        self.assertIn("missing Wear signed AAB", str(raised.exception))

    def test_writable_upload_candidate_aab_is_not_permission_frozen(self) -> None:
        relative = "wear_os/app/build/outputs/bundle/release/app-release.aab"
        candidate = self.repo / relative
        candidate.parent.mkdir(parents=True)
        candidate.write_bytes(b"leftover-writable-aab")
        candidate.chmod(0o644)
        with self.assertRaises(self.module.ReceiptError) as raised:
            self.module._canonical_gate_artifact(self.repo, "wear-os-aab", relative)
        self.assertIn("writable and not permission-frozen", str(raised.exception))
        self.assertNotIn("OWNER-BLOCKED", str(raised.exception))

    def test_missing_producer_closure_is_owner_blocked(self) -> None:
        receipt_dir = self.freeze_receipt("no-producer", self.payload())

        class FakeCreator:
            ReceiptError = self.module.ReceiptError

            @staticmethod
            def _reject_self_authorized(_source, _receipt_dir):
                return None

            @staticmethod
            def _bind_source_freeze(_repo):
                return self.payload()["source_freeze"]

            @staticmethod
            def _bind_dependency_freeze(_repo, _index):
                return self.payload()["dependency_freeze"]

            @staticmethod
            def _producer_bytes(_repo, _legacy):
                raise AssertionError("producer bytes must not be consulted when absent")

        with mock.patch.object(self.module, "_load_py", return_value=FakeCreator):
            with self.assertRaises(self.module.ReceiptError) as raised:
                self.module._verify_source_closure(
                    self.repo, self.payload(), receipt_dir
                )
        self.assertIn("OWNER-BLOCKED", str(raised.exception))
        self.assertIn("producer/verifier closure", str(raised.exception))
        os.chmod(receipt_dir, 0o700)

    def _store_repo(self) -> pathlib.Path:
        self._store_repo_count = getattr(self, "_store_repo_count", 0) + 1
        repo = self.repo / f"metadata-root-{self._store_repo_count}"
        for relative in self.module.STORE_METADATA_FILES:
            dest = repo / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes((ROOT / relative).read_bytes())
        return repo

    def _mapping_binding(self) -> dict[str, object]:
        digest = "a" * 64
        return {
            "bound": True,
            "external_sha256": digest,
            "embedded_sha256": digest,
            "exact_bytes": True,
            "canonicalization": "identity",
            "canonical_sha256": digest,
        }

    def test_reviewed_store_metadata_binds_canonical_companion_contract(self) -> None:
        reviewed = self.module._reviewed_store_metadata(ROOT)
        self.assertEqual(reviewed["canonical_release"], "1.0.16+33")
        self.assertEqual(reviewed["application_id"], "org.winsvpn.app")
        self.assertEqual(reviewed["version_name"], "1.0.16")
        self.assertEqual(reviewed["version_code"], 3301)
        self.assertFalse(reviewed["standalone"])
        self.assertFalse(reviewed["upload_authorized"])
        self.assertFalse(reviewed["submission_approved"])
        self.assertEqual(reviewed["listing_screenshot_inventory"], "owner-blocked")
        self.assertEqual(reviewed["companion_protocol"]["primary"], "winn-v3")
        self.assertEqual(reviewed["companion_protocol"]["fallback"], ["awg", "xray"])
        self.assertFalse(reviewed["companion_protocol"]["local_wear_inclusion"])
        self.assertIn("libwinnengine.so", reviewed["companion_protocol"]["forbidden_local_engines"])
        self.assertIn("libxray.so", reviewed["companion_protocol"]["forbidden_local_engines"])
        self.assertRegex(reviewed["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            reviewed["sha256"],
            self.module._reviewed_store_metadata(ROOT)["sha256"],
        )
        for relative in self.module.STORE_METADATA_FILES:
            self.assertIn(relative, reviewed["files"])
            self.assertIn(relative, self.module.PROVENANCE_PATHS)
        self.assertIn(
            "app_store/android/wear/metadata/en-US/whats_new.txt",
            reviewed["files"],
        )

    def test_reviewed_store_metadata_fails_closed_on_identity_protocol_or_upload_drift(
        self,
    ) -> None:
        cases = (
            (self.module.PRIVACY_MANIFEST_RELATIVE, {"version_code": 33}),
            (self.module.PRIVACY_MANIFEST_RELATIVE, {"application_id": "org.winsvpn.app.debug"}),
            (self.module.OWNER_SIGNOFF_RELATIVE, {"upload_authorized": True}),
            (self.module.OWNER_SIGNOFF_RELATIVE, {"submission_approved": True}),
            (self.module.RELEASE_CANDIDATE_RELATIVE, {"version_code": 3302}),
        )
        for relative, fields in cases:
            with self.subTest(relative=relative, fields=fields):
                repo = self._store_repo()
                path = repo / relative
                payload = json.loads(path.read_text(encoding="utf-8"))
                payload.update(fields)
                path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
                with self.assertRaises(self.module.ReceiptError):
                    self.module._reviewed_store_metadata(repo)

        repo = self._store_repo()
        path = repo / self.module.PRIVACY_MANIFEST_RELATIVE
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["phone_tunnel_protocol"]["local_wear_inclusion"] = True
        path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
        with self.assertRaises(self.module.ReceiptError):
            self.module._reviewed_store_metadata(repo)

        repo = self._store_repo()
        path = repo / self.module.RELEASE_CANDIDATE_RELATIVE
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["artifact"]["produced"] = True
        path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
        with self.assertRaises(self.module.ReceiptError):
            self.module._reviewed_store_metadata(repo)

        repo = self._store_repo()
        listing = repo / "app_store/android/wear/metadata/en-US/short_description.txt"
        listing.write_text("Wrist remote without a protocol.\n", encoding="ascii")
        with self.assertRaises(self.module.ReceiptError):
            self.module._reviewed_store_metadata(repo)

    def test_gate_claims_fill_companion_protocol_when_inspector_omits_it(self) -> None:
        inspected = {
            "manifest_decoder": {"decoder": "bundletool", "version": "1.18.3"},
            "manifest": canonical_wear_inspected_manifest(),
            "native_libraries": [],
            "approved_native_library_count": 0,
        }
        external = {
            "artifact_privacy": {"passed": True},
            "private_symbol_custody": {"passed": True},
        }
        claims = self.module._gate_claims(
            inspected, "c" * 64, external, self._mapping_binding()
        )
        self.assertEqual(claims["companion_protocol"]["primary"], "winn-v3")
        self.assertEqual(claims["companion_protocol"]["fallback"], ["awg", "xray"])
        self.assertFalse(claims["companion_protocol"]["local_wear_inclusion"])
        self.assertTrue(claims["phone_vpn_engines_absent"])
        self.assertFalse(claims["publication_authorized"])
        self.assertEqual(claims["package_identity"]["package"], "org.winsvpn.app")
        self.assertEqual(claims["package_identity"]["version_name"], "1.0.16")
        self.assertEqual(claims["package_identity"]["version_code"], 3301)
        self.assertEqual(claims["package_identity"]["min_sdk"], 30)
        self.assertEqual(claims["package_identity"]["target_sdk"], 37)
        self.assertTrue(claims["package_identity"]["minify_enabled"])

    def test_gate_claims_refuse_missing_or_wrong_aab_identity(self) -> None:
        external = {
            "artifact_privacy": {"passed": True},
            "private_symbol_custody": {"passed": True},
        }
        missing = {
            "manifest_decoder": {"decoder": "bundletool"},
            "native_libraries": [],
            "approved_native_library_count": 0,
        }
        with self.assertRaises(self.module.ReceiptError) as raised:
            self.module._gate_claims(
                missing, "c" * 64, external, self._mapping_binding()
            )
        self.assertIn("canonical 1.0.16+33 watch identity", str(raised.exception))

        contaminated = {
            "manifest_decoder": {"decoder": "bundletool"},
            "manifest": {
                "package": "org.winsvpn.app",
                "version_name": "1.0.16",
                "version_code": 33,
                "min_sdk": 30,
                "target_sdk": 37,
                "minify_enabled": True,
            },
            "native_libraries": [],
            "approved_native_library_count": 0,
        }
        with self.assertRaises(self.module.ReceiptError) as raised:
            self.module._gate_claims(
                contaminated, "c" * 64, external, self._mapping_binding()
            )
        self.assertIn("canonical 1.0.16+33 watch identity", str(raised.exception))

    def test_gate_claims_refuse_protocol_drift_and_local_engines(self) -> None:
        protocol = dict(self.module._companion_protocol_claims())
        protocol["local_wear_inclusion"] = True
        inspected = {
            "manifest_decoder": {"decoder": "bundletool"},
            "manifest": canonical_wear_inspected_manifest(),
            "native_libraries": [],
            "approved_native_library_count": 0,
            "companion_protocol": protocol,
        }
        external = {
            "artifact_privacy": {"passed": True},
            "private_symbol_custody": {"passed": True},
        }
        with self.assertRaises(self.module.ReceiptError) as raised:
            self.module._gate_claims(
                inspected, "c" * 64, external, self._mapping_binding()
            )
        self.assertIn("companion protocol", str(raised.exception))

        inspected = {
            "manifest_decoder": {"decoder": "bundletool"},
            "manifest": canonical_wear_inspected_manifest(),
            "native_libraries": [
                {
                    "path": "base/lib/arm64-v8a/libwinnengine.so",
                    "sha256": "0" * 64,
                }
            ],
            "approved_native_library_count": 0,
        }
        with self.assertRaises(self.module.ReceiptError) as raised:
            self.module._gate_claims(
                inspected, "c" * 64, external, self._mapping_binding()
            )
        self.assertIn("phone VPN engine", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
