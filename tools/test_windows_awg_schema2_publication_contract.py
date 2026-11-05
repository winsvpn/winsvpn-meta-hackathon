#!/usr/bin/env python3
"""Adversarial regressions for the Windows AWG maintenance-helper provenance contract.

The contract binds the rebuilt helper to its reviewed source, the pinned Go
1.27.1 archive, the AWG 3.1 module identities and the producer's own helper
SHA-256 pin. It no longer reads owner publication tokens (owner_blocked,
publication_*, provenance_is_commit_marker, helper_kind, signing_boundary,
authenticode_status, release_signing_required).
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
ZIP_PATH = ROOT / "installer/windows/build_zip_installer.ps1"
INSTALLER_PATH = ROOT / "installer/windows/build_installer.ps1"
VERIFY_PATH = ROOT / "tools/verify_deployment_supply_chain.py"
CLIENT_PATH = ROOT / "tools/build_windows_amneziawg_client.ps1"
DEPENDENCIES = ROOT / "installer/windows/dependencies"
PROVENANCE_PATH = DEPENDENCIES / "amneziawg.exe.provenance.json"
HELPER_PATH = DEPENDENCIES / "amneziawg.exe"
BEGIN = "# BEGIN-WINDOWS-AWG-SCHEMA2-OWNER-PUBLICATION-CONTRACT"
END = "# END-WINDOWS-AWG-SCHEMA2-OWNER-PUBLICATION-CONTRACT"
PRODUCER_HELPER_PIN = (
    "12525f397d957659354df03ac1e9568170d8842aa8fa0d16942d8a59d7307d41"
)
COERCION_MARKERS = (
    "[int]$evidence.schema_version",
    "-not [bool]$evidence.provenance_is_commit_marker",
    "[bool]$evidence.provenance_is_commit_marker",
    "[bool]$evidence.release_signing_required",
    "[bool]$evidence.owner_blocked",
)
# What tools/build_windows_amneziawg_client.ps1 writes beside the real pins.
# The contract must accept these fields without depending on them.
PRODUCER_EXTRAS = {
    "publication_contract": "winsvpn.windows-awg-publication.v2",
    "publication_transaction_id": "0123456789abcdef0123456789abcdef",
    "provenance_is_commit_marker": True,
    "owner_blocked": False,
    "helper_kind": "canonical_unsigned_product_maintenance_helper",
    "signing_boundary": "release_staged_copy_only",
    "authenticode_status": "pending_release_signing",
    "release_signing_required": True,
}
PWSH = shutil.which("pwsh")


def load_verifier():
    spec = importlib.util.spec_from_file_location(
        "verify_deployment_supply_chain", VERIFY_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load verify_deployment_supply_chain")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def contract_block(path: pathlib.Path) -> str:
    text = path.read_text(encoding="utf-8")
    return text[text.index(BEGIN) : text.index(END) + len(END)]


def valid_schema2(module, digest: str) -> dict:
    return {
        "schema_version": 2,
        "source_repository": module.WINDOWS_AMNEZIAWG_SOURCE_REPOSITORY,
        "source_version": module.WINDOWS_AMNEZIAWG_SOURCE_VERSION,
        "source_commit": module.WINDOWS_AMNEZIAWG_SOURCE_COMMIT,
        "source_go_mod_sha256": module.WINDOWS_AMNEZIAWG_GO_MOD_SHA256,
        "source_go_sum_sha256": module.WINDOWS_AMNEZIAWG_GO_SUM_SHA256,
        "source_build_bat_sha256": module.WINDOWS_AMNEZIAWG_SOURCE_BUILD_BAT_SHA256,
        "patched_build_bat_sha256": module.WINDOWS_AMNEZIAWG_PATCHED_BUILD_BAT_SHA256,
        "build_patch_sha256": module.WINDOWS_AMNEZIAWG_BUILD_PATCH_SHA256,
        "windows_library_repository": (
            "https://github.com/amnezia-vpn/amneziawg-windows.git"
        ),
        "windows_library_version": module.WINDOWS_AMNEZIAWG_LIBRARY_VERSION,
        "windows_library_commit": module.WINDOWS_AMNEZIAWG_LIBRARY_COMMIT,
        "engine_module": "github.com/amnezia-vpn/amneziawg-go/v3",
        "engine_version": module.WINDOWS_AMNEZIAWG_ENGINE_VERSION,
        "engine_commit": module.WINDOWS_AMNEZIAWG_ENGINE_COMMIT,
        "go_version": module.WINDOWS_REVIEWED_GO_VERSION,
        "go_archive": module.WINDOWS_AMNEZIAWG_GO_ARCHIVE,
        "go_archive_sha256": module.WINDOWS_AMNEZIAWG_GO_ARCHIVE_SHA256,
        "go_toolchain_policy": "verified_archive_only",
        "go_module_policy": "readonly",
        "go_checksum_database": "sum.golang.org",
        "target": "windows-amd64",
        "unsigned_artifact_sha256": digest,
        "expected_unsigned_artifact_sha256": digest,
        "module_build_info": [
            "dep github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260828 h1:test=",
            "dep github.com/amnezia-vpn/amneziawg-windows/v3 v3.1.20260814 h1:test=",
        ],
    }


def run_contract(provenance: pathlib.Path, helper: pathlib.Path, digest: str,
                 target: str = "windows-amd64") -> subprocess.CompletedProcess:
    command = (
        "$ErrorActionPreference = 'Stop'\n"
        f"{contract_block(INSTALLER_PATH)}\n"
        "try {\n"
        "    Assert-WindowsAwgSchema2OwnerPublicationContract `\n"
        f"        -ProvenancePath '{provenance}' `\n"
        f"        -HelperPath '{helper}' `\n"
        f"        -ExpectedUnsignedSha256 '{digest}' `\n"
        f"        -ExpectedTarget '{target}'\n"
        "    Write-Output 'CONTRACT-ACCEPTED'\n"
        "    exit 0\n"
        "} catch {\n"
        "    Write-Output ('CONTRACT-REFUSED: ' + $_.Exception.Message)\n"
        "    exit 2\n"
        "}\n"
    )
    return subprocess.run(
        [PWSH, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "NO_COLOR": "1"},
    )


class WindowsAwgSchema2PublicationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_verifier()
        cls.digest = "ab" * 32
        cls.valid = valid_schema2(cls.module, cls.digest)

    def test_zip_and_inno_owner_publication_contracts_are_byte_identical(self) -> None:
        # Depends on lane WP copying the installer block into the ZIP producer.
        self.assertEqual(contract_block(ZIP_PATH), contract_block(INSTALLER_PATH))

    def test_builders_reject_powershell_coercion_and_rehash_after_copy(self) -> None:
        text = INSTALLER_PATH.read_text(encoding="utf-8")
        block = contract_block(INSTALLER_PATH)
        for marker in COERCION_MARKERS:
            self.assertNotIn(marker, block)
            self.assertNotIn(marker, text.split("function Assert-RebuiltAmneziaWgHelper", 1)[0])
        self.assertIn("Assert-JsonIntegerEquals", block)
        self.assertIn("repeats JSON key", block)
        for retired in self.module.WINDOWS_AWG_RETIRED_OWNER_TOKEN_ASSERTS:
            self.assertNotIn(retired, block)
        self.assertNotIn("owner_blocked", block)
        self.assertNotIn("publication_transaction_id", block)
        for kept in (
            "-Expected '1.27.1' -Name 'go_version'",
            "-Expected 'a3911b5e0e1b1053f25ed0675f4c1c6aad1e2bfcf253df2b9be4caabd2edd95d' -Name 'go_archive_sha256'",
            "-Expected 'ca5dd3b983bd19c335ab095ccd21fc2f804ec968' -Name 'source_commit'",
            "two_clean_builds_byte_identical",
            "unsigned digest does not agree with the helper bytes and reviewed pin",
            "lacks the exact AWG 3.1 module identities",
        ):
            self.assertIn(kept, block)
        self.assertIn(
            "Re-verifying staged dependency bytes against reviewed pins after copy",
            text,
        )
        self.assertIn("bytes that changed after the pre-copy pin check", text)

    def test_python_contract_ignores_owner_tokens_and_keeps_real_pins(self) -> None:
        require = self.module.require_windows_awg_schema2_evidence
        require(copy.deepcopy(self.valid), self.digest, "windows-amd64")
        require({**self.valid, **PRODUCER_EXTRAS}, self.digest, "windows-amd64")
        stale_tokens = {
            **self.valid,
            "owner_blocked": True,
            "owner_blocked_reason": "no longer read",
            "required_schema_version": 2,
        }
        require(stale_tokens, self.digest, "windows-amd64")

        # The independent audit's exact Python footgun: 1 == True.
        self.assertEqual(1, True)
        probes = (
            ({"schema_version": "2"}, "schema_version"),
            ({"schema_version": True}, "schema_version"),
            ({"schema_version": 1}, "schema_version"),
            ({"go_version": "1.27.0"}, "go_version"),
            ({"go_archive": "go1.27.0.windows-amd64.zip"}, "go_archive"),
            (
                {"go_archive_sha256": "f0c0a0d33ba94f4d2c5dbc887334ce678b21813504ddb3aafcb06e60a5a667c4"},
                "go_archive_sha256",
            ),
            ({"source_commit": "0" * 40}, "source_commit"),
            ({"engine_version": "v3.1.20260801"}, "engine_version"),
            ({"target": "windows-arm64"}, "target"),
            ({"unsigned_artifact_sha256": "cd" * 32}, "unsigned_artifact_sha256"),
            ({"expected_unsigned_artifact_sha256": "cd" * 32}, "expected_unsigned_artifact_sha256"),
        )
        for patch, field in probes:
            evidence = copy.deepcopy(self.valid)
            evidence.update(patch)
            with self.subTest(patch=patch):
                with self.assertRaisesRegex(RuntimeError, field):
                    require(evidence, self.digest, "windows-amd64")

        for field in (
            "source_repository",
            "go_archive",
            "module_build_info",
            "expected_unsigned_artifact_sha256",
        ):
            evidence = copy.deepcopy(self.valid)
            del evidence[field]
            with self.subTest(missing=field):
                with self.assertRaisesRegex(RuntimeError, field):
                    require(evidence, self.digest, "windows-amd64")

        coerced_module = copy.deepcopy(self.valid)
        coerced_module["module_build_info"] = "\n".join(
            self.valid["module_build_info"]
        )
        with self.assertRaisesRegex(RuntimeError, "module_build_info"):
            require(coerced_module, self.digest, "windows-amd64")

        wrong_module = copy.deepcopy(self.valid)
        wrong_module["module_build_info"] = [
            "dep github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260801 h1:test=",
            "dep github.com/amnezia-vpn/amneziawg-windows/v3 v3.1.20260814 h1:test=",
        ]
        with self.assertRaisesRegex(RuntimeError, "module identities"):
            require(wrong_module, self.digest, "windows-amd64")

        arm64 = {**self.valid, "target": "windows-arm64"}
        with self.assertRaisesRegex(RuntimeError, "reproducibility"):
            require(arm64, self.digest, "windows-arm64")
        require(
            {
                **arm64,
                "reproducibility_builds": 2,
                "reproducibility_status": "two_clean_builds_byte_identical",
            },
            self.digest,
            "windows-arm64",
        )

    def test_duplicate_json_keys_are_rejected_and_committed_helper_meets_its_go_pin(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = pathlib.Path(raw) / "dup.json"
            path.write_text(
                '{"schema_version": 2, "schema_version": 1}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "repeats JSON key"):
                self.module.load_unique_json_object(path)

        self.assertFalse(hasattr(self.module, "is_honest_schema1_owner_block"))
        self.assertFalse(hasattr(self.module, "WINDOWS_AWG_SCHEMA2_OWNER_BLOCK_MESSAGE"))
        committed = self.module.load_unique_json_object(PROVENANCE_PATH)
        # Observed committed data: the 2026-10-09 producer transaction rebuilt
        # the helper with Go 1.27.1 and wrote schema-2 provenance.
        self.assertEqual(committed.get("schema_version"), 2)
        self.assertEqual(committed.get("go_version"), "1.27.1")
        self.module.require_windows_awg_schema2_evidence(
            committed, PRODUCER_HELPER_PIN, "windows-amd64"
        )
        # The same evidence with the previous Go 1.27.0 toolchain identity is
        # still refused by the real Go 1.27.1 archive pin.
        downgraded = dict(committed)
        downgraded["go_version"] = "1.27.0"
        downgraded["go_archive"] = "go1.27.0.windows-amd64.zip"
        downgraded["go_archive_sha256"] = (
            "f0c0a0d33ba94f4d2c5dbc887334ce678b21813504ddb3aafcb06e60a5a667c4"
        )
        with self.assertRaises(RuntimeError) as raised:
            self.module.require_windows_awg_schema2_evidence(
                downgraded, PRODUCER_HELPER_PIN, "windows-amd64"
            )
        self.assertRegex(
            str(raised.exception), r": go_version, go_archive, go_archive_sha256$"
        )
        self.module.verify_windows_amneziawg_client_rebuild_pins()

    def test_verifier_and_installer_use_the_producer_helper_pin(self) -> None:
        verify = VERIFY_PATH.read_text(encoding="utf-8")
        client = CLIENT_PATH.read_text(encoding="utf-8")
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertEqual(
            self.module.WINDOWS_AMNEZIAWG_HELPER_UNSIGNED_SHA256, PRODUCER_HELPER_PIN
        )
        self.assertIn(f"ProductHelperSha256 = '{PRODUCER_HELPER_PIN}'", client)
        self.assertIn(f"'x64' = '{PRODUCER_HELPER_PIN}'", installer)
        self.assertNotIn("actual = hashlib.sha256(binary.read_bytes()).hexdigest()", verify)
        self.assertIn(
            "require_file_sha256(\n        binary,\n        WINDOWS_AMNEZIAWG_HELPER_UNSIGNED_SHA256,",
            verify,
        )
        helper = installer[
            installer.index("function Assert-RebuiltAmneziaWgHelper") :
            installer.index("function Assert-AmneziaWgPayloadSignatures")
        ]
        self.assertLess(
            helper.index("$expectedUnsigned = $AmneziaWgHelperUnsignedSha256"),
            helper.index("Assert-WindowsAwgSchema2OwnerPublicationContract"),
        )
        self.assertIn(
            "$stagedPinMap['amneziawg.exe'] = $script:AmneziaWgHelperReviewedSha256",
            installer,
        )
        self.assertEqual(hashlib.sha256(HELPER_PATH.read_bytes()).hexdigest(), PRODUCER_HELPER_PIN)

    @unittest.skipUnless(PWSH, "pwsh is unavailable for live contract probes")
    def test_powershell_contract_accepts_real_evidence_and_rejects_pin_drift(self) -> None:
        helper_bytes = b"winsvpn-awg-schema2-probe"
        digest = hashlib.sha256(helper_bytes).hexdigest()
        valid = valid_schema2(self.module, digest)
        accepted = {
            "real-fields-only": valid,
            "with-producer-extras": {**valid, **PRODUCER_EXTRAS},
            "stale-owner-fields-ignored": {
                **valid,
                "owner_blocked": True,
                "owner_blocked_reason": "no longer read",
                "required_schema_version": 2,
            },
        }
        refused = {
            "string-schema": {**valid, "schema_version": "2"},
            "bool-schema": {**valid, "schema_version": True},
            "schema-1": {**valid, "schema_version": 1},
            "go-1-27-0": {**valid, "go_version": "1.27.0"},
            "go-archive-sha": {
                **valid,
                "go_archive_sha256": "f0c0a0d33ba94f4d2c5dbc887334ce678b21813504ddb3aafcb06e60a5a667c4",
            },
            "source-commit": {**valid, "source_commit": "0" * 40},
            "wrong-target": {**valid, "target": "windows-arm64"},
            "digest-mismatch": {
                **valid,
                "unsigned_artifact_sha256": "cd" * 32,
                "expected_unsigned_artifact_sha256": "cd" * 32,
            },
            "missing-module-info": {
                k: v for k, v in valid.items() if k != "module_build_info"
            },
        }
        with tempfile.TemporaryDirectory(prefix="winsvpn-awg-schema2-") as raw:
            root = pathlib.Path(raw)
            helper = root / "amneziawg.exe"
            helper.write_bytes(helper_bytes)
            for name, payload in {**accepted, **refused}.items():
                provenance = root / f"{name}.json"
                provenance.write_text(
                    json.dumps(payload, indent=2) + "\n", encoding="utf-8"
                )
                completed = run_contract(provenance, helper, digest)
                with self.subTest(probe=name):
                    expected = 0 if name in accepted else 2
                    self.assertEqual(
                        completed.returncode,
                        expected,
                        completed.stdout + completed.stderr,
                    )
                    marker = "CONTRACT-ACCEPTED" if expected == 0 else "CONTRACT-REFUSED"
                    self.assertIn(marker, completed.stdout)

            duplicate = root / "duplicate.json"
            duplicate.write_text(
                json.dumps(valid).replace(
                    '"go_version": "1.27.1"',
                    '"go_version": "1.27.0", "go_version": "1.27.1"',
                    1,
                ),
                encoding="utf-8",
            )
            dup_completed = run_contract(duplicate, helper, digest)
            self.assertEqual(
                dup_completed.returncode,
                2,
                dup_completed.stdout + dup_completed.stderr,
            )
            self.assertIn("repeats JSON key go_version", dup_completed.stdout)

        # The committed 2026-10-09 generation (Go 1.27.1, schema 2) passes the
        # real contract; the same evidence with the Go 1.27.0 identity does not.
        committed = run_contract(PROVENANCE_PATH, HELPER_PATH, PRODUCER_HELPER_PIN)
        self.assertEqual(committed.returncode, 0, committed.stdout + committed.stderr)
        self.assertIn("CONTRACT-ACCEPTED", committed.stdout)
        self.assertNotIn("owner", committed.stdout.lower())
        downgraded = json.loads(PROVENANCE_PATH.read_text(encoding="utf-8"))
        downgraded["go_version"] = "1.27.0"
        downgraded["go_archive"] = "go1.27.0.windows-amd64.zip"
        downgraded["go_archive_sha256"] = (
            "f0c0a0d33ba94f4d2c5dbc887334ce678b21813504ddb3aafcb06e60a5a667c4"
        )
        with tempfile.TemporaryDirectory(prefix="winsvpn-awg-schema2-") as raw:
            provenance = pathlib.Path(raw) / "downgraded.json"
            provenance.write_text(
                json.dumps(downgraded, indent=2) + "\n", encoding="utf-8"
            )
            refused = run_contract(provenance, HELPER_PATH, PRODUCER_HELPER_PIN)
        self.assertEqual(refused.returncode, 2, refused.stdout + refused.stderr)
        self.assertIn("CONTRACT-REFUSED", refused.stdout)
        self.assertIn("go_version", refused.stdout)

    @unittest.skipUnless(PWSH, "pwsh is unavailable for helper pin probes")
    def test_installer_helper_check_passes_the_producer_pin_not_the_file_hash(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-awg-helper-pin-") as raw:
            root = pathlib.Path(raw)
            helper = root / "amneziawg.exe"
            helper.write_bytes(b"helper bytes that are not the pinned helper")
            file_hash = hashlib.sha256(helper.read_bytes()).hexdigest()
            prelude = (
                "$ErrorActionPreference = 'Stop'\n"
                "$__ast = [System.Management.Automation.Language.Parser]::ParseFile("
                f"'{INSTALLER_PATH}', [ref]$null, [ref]$null)\n"
                "$__def = @($__ast.FindAll({ param($n) $n -is "
                "[System.Management.Automation.Language.FunctionDefinitionAst] -and "
                "$n.Name -ceq 'Assert-RebuiltAmneziaWgHelper' }, $true)) | Select-Object -First 1\n"
                ". ([scriptblock]::Create($__def.Extent.Text))\n"
                "function Assert-WindowsAwgSchema2OwnerPublicationContract {\n"
                "    param($ProvenancePath, $HelperPath, $ExpectedUnsignedSha256, $ExpectedTarget)\n"
                "    Write-Output ('EXPECTED=' + $ExpectedUnsignedSha256 + '|' + $ExpectedTarget) }\n"
                "function Get-AuthenticodeSignature { param($LiteralPath)\n"
                "    [pscustomobject]@{ Status = [System.Management.Automation.SignatureStatus]::NotSigned } }\n"
                f"$AmneziaWgExe = '{helper}'\n"
                f"$AmneziaWgExeProvenance = '{helper}.provenance.json'\n"
            )
            cases = {
                "x64-pin": (
                    f"$AmneziaWgHelperUnsignedSha256 = '{PRODUCER_HELPER_PIN}'\n"
                    "$script:WindowsAwgGoArch = 'amd64'\n",
                    f"EXPECTED={PRODUCER_HELPER_PIN}|windows-amd64",
                ),
                "arm64-without-pin": (
                    "$AmneziaWgHelperUnsignedSha256 = $null\n"
                    "$script:WindowsAwgGoArch = 'arm64'\n",
                    "REFUSED: No reviewed unsigned AmneziaWG helper SHA-256 pin exists for windows-arm64.",
                ),
                "x64-without-pin": (
                    "$AmneziaWgHelperUnsignedSha256 = $null\n"
                    "$script:WindowsAwgGoArch = 'amd64'\n",
                    "REFUSED: No reviewed unsigned AmneziaWG helper SHA-256 pin exists for windows-amd64.",
                ),
            }
            for name, (setup, expected) in cases.items():
                script = (
                    prelude
                    + setup
                    + "try { Assert-RebuiltAmneziaWgHelper; Write-Output ('REVIEWED=' + $script:AmneziaWgHelperReviewedSha256) }\n"
                    + "catch { Write-Output ('REFUSED: ' + $_.Exception.Message) }\n"
                )
                completed = subprocess.run(
                    [PWSH, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
                    cwd=raw,
                    check=False,
                    capture_output=True,
                    text=True,
                    env={**os.environ, "NO_COLOR": "1"},
                )
                with self.subTest(case=name):
                    self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                    self.assertIn(expected, completed.stdout)
                    if name == "x64-pin":
                        self.assertIn(f"REVIEWED={PRODUCER_HELPER_PIN}", completed.stdout)
                        self.assertNotIn(file_hash, completed.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
