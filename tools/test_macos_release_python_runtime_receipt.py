#!/usr/bin/env python3
"""Exact schema tests for the macOS owner-provisioned Python runtime receipt."""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import importlib.util
import json
import os
import plistlib
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "macos_release_python_runtime_receipt.py"
NATIVE_LAUNCHER_SOURCE = ROOT / "tools" / "macos_release_python_owner_launcher.c"

HELD_TOOL_FD = os.environ.get("WINS_RECEIPT_TEST_HELD_TOOL_FD", "")
if HELD_TOOL_FD:
    if not HELD_TOOL_FD.isdigit():
        raise RuntimeError("held Python runtime receipt descriptor is malformed")
    held_fd = int(HELD_TOOL_FD)
    os.lseek(held_fd, 0, os.SEEK_SET)
    held_source = bytearray()
    while True:
        held_block = os.read(held_fd, 1024 * 1024)
        if not held_block:
            break
        held_source.extend(held_block)
    MODULE = types.ModuleType("macos_release_python_runtime_receipt")
    MODULE.__file__ = str(TOOL)
    exec(compile(bytes(held_source), str(TOOL), "exec"), MODULE.__dict__)
else:
    SPEC = importlib.util.spec_from_file_location("macos_release_python_runtime_receipt", TOOL)
    if SPEC is None or SPEC.loader is None:
        raise RuntimeError("cannot load Python runtime receipt schema")
    MODULE = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(MODULE)


PSF_LEAF = "Developer ID Application: Python Software Foundation (BMM5U3QVKW)"
PSF_CHAIN = [
    PSF_LEAF,
    "Developer ID Certification Authority",
    "Apple Root CA",
]
TRUSTED_NOW = datetime(2026, 8, 26, 12, 0, 0, tzinfo=timezone.utc)
DESIGNATED_SUFFIX = (
    " and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] "
    "/* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] "
    "/* exists */ and certificate leaf[subject.OU] = BMM5U3QVKW"
)
CAPTURED_PYTHON = Path(MODULE.DEFAULT_RUNTIME) / MODULE.EXECUTABLE_RELATIVE
CAPTURED_REQUIREMENT = (
    "identifier python3 and anchor apple generic and certificate "
    "1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate "
    "leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate "
    'leaf[subject.OU] = "5YT8H4U72M"'
)
CAPTURED_REQUIREMENT_STDOUT = f"designated => {CAPTURED_REQUIREMENT}\n".encode(
    "ascii"
)
CAPTURED_REQUIREMENT_STDERR = f"Executable={CAPTURED_PYTHON}\n".encode("ascii")
CAPTURED_PYTHON_APP = Path(MODULE.DEFAULT_RUNTIME) / MODULE.PYTHON_APP_RELATIVE
CAPTURED_GATEKEEPER_ORIGIN = (
    "Developer ID Application: Win's VPN Inc (5YT8H4U72M)"
)
CAPTURED_GATEKEEPER_STDERR = (
    f"{CAPTURED_PYTHON_APP}: accepted\n"
    f"source={MODULE.REQUIRED_GATEKEEPER_SOURCE}\n"
).encode("ascii")
CAPTURED_ENTITLEMENTS_STDOUTS = tuple(
    b'<?xml version="1.0" encoding="UTF-8"?>'
    + doctype
    + b'<plist version="1.0"><dict>'
    + b"<key>com.apple.security.cs.allow-unsigned-executable-memory</key><true/>"
    + b"</dict></plist>\n"
    for doctype in MODULE.STANDARD_ENTITLEMENT_DOCTYPES
)


def requirement_for(relative_path: str) -> str:
    identifiers = {
        MODULE.EXECUTABLE_RELATIVE: "python3",
        MODULE.AUTHORITY_ENTRYPOINTS[1]: "python3.14-intel64",
        MODULE.PYTHON_APP_RELATIVE: '"org.python.python"',
    }
    return f"identifier {identifiers[relative_path]}{DESIGNATED_SUFFIX}"


def clean_codesign_entrypoint(
    relative_path: str,
    executable_relative_path: str,
    architecture: str,
    codesign_kind: str,
    index: int,
) -> dict[str, object]:
    identifiers = (
        "org.python.python3",
        "org.python.python3",
        "org.python.python3-intel64",
        "org.python.python",
        "org.python.python",
    )
    return {
        "architecture": architecture,
        "codesign_authority": PSF_LEAF,
        "codesign_authority_chain": list(PSF_CHAIN),
        "codesign_cdhash": format(index + 10, "02x") * 20,
        "codesign_entitlements": dict(MODULE.REQUIRED_EXECUTABLE_ENTITLEMENTS),
        "codesign_flags": MODULE.REQUIRED_CODESIGN_FLAGS,
        "codesign_identifier": identifiers[index],
        "codesign_kind": codesign_kind,
        "codesign_requirement": requirement_for(relative_path),
        "codesign_team_identifier": "BMM5U3QVKW",
        "executable_relative_path": executable_relative_path,
        "relative_path": relative_path,
    }


def valid_document(**overrides: object) -> dict[str, object]:
    identity = "1:2:0:0:555:3:64:131072"
    entrypoints = [
        clean_codesign_entrypoint(relative, executable, architecture, kind, index)
        for index, (relative, executable, architecture, kind) in enumerate(
            MODULE.AUTHORITY_CODE_SLICES
        )
    ]
    primary = entrypoints[0]
    document: dict[str, object] = {
        "authenticated": True,
        "codesign_authority": primary["codesign_authority"],
        "codesign_authority_chain": primary["codesign_authority_chain"],
        "codesign_cdhash": primary["codesign_cdhash"],
        "codesign_entitlements": primary["codesign_entitlements"],
        "codesign_entrypoints": entrypoints,
        "codesign_flags": primary["codesign_flags"],
        "codesign_identifier": primary["codesign_identifier"],
        "codesign_kind": primary["codesign_kind"],
        "codesign_requirement": primary["codesign_requirement"],
        "codesign_team_identifier": primary["codesign_team_identifier"],
        "contract": MODULE.CONTRACT,
        "controller": MODULE.CONTROLLER,
        "controller_sha256": "aa" * 32,
        "custody_closure": valid_migration_closure(),
        "executable_identity": "1:3:0:0:555:1:1234:131072",
        "executable_path": f"{MODULE.DEFAULT_RUNTIME}/{MODULE.EXECUTABLE_RELATIVE}",
        "executable_sha256": "bb" * 32,
        "framework_dir_identity": identity,
        "framework_identity_sha256": "cc" * 32,
        "framework_tree_sha256": "dd" * 32,
        "gatekeeper_assessment": {
            "origin": PSF_LEAF,
            "relative_path": MODULE.PYTHON_APP_RELATIVE,
            "source": "Developer ID",
        },
        "implementation": MODULE.IMPLEMENTATION,
        "issuer": MODULE.ISSUER,
        "launcher_dir_identity": identity,
        "launcher_identity_sha256": "ee" * 32,
        "launcher_primary_sha256": "56" * 32,
        "launcher_tree_sha256": "ff" * 32,
        "owner_provision_launcher": str(MODULE.OWNER_PROVISION_LAUNCHER),
        "owner_provision_launcher_build_sha256": "8a" * 32,
        "owner_provision_launcher_compiler_sha256": "8b" * 32,
        "owner_provision_launcher_device": 123,
        "owner_provision_launcher_inode": 456,
        "owner_provision_launcher_linker_sha256": "8c" * 32,
        "owner_provision_launcher_sdk_closure_sha256": "8d" * 32,
        "owner_provision_launcher_sha256": "88" * 32,
        "owner_provision_launcher_source_sha256": "89" * 32,
        "package_sha256": "11" * 32,
        "package_signature_status": "Status: signed by a certificate trusted by Mac OS X",
        "platform": MODULE.PLATFORM,
        "provisioner": MODULE.PROVISIONER,
        "provisioner_sha256": "22" * 32,
        "python_version": MODULE.PYTHON_VERSION,
        "receipt_schema": MODULE.RECEIPT_SCHEMA,
        "receipt_schema_sha256": "33" * 32,
        "runtime_dir_identity": identity,
        "runtime_path": MODULE.DEFAULT_RUNTIME,
        "schema_version": MODULE.SCHEMA_VERSION,
        "vendor_dir_identity": identity,
        "vendor_identity_sha256": "44" * 32,
        "vendor_tree_sha256": "55" * 32,
        "wheel_count": 1,
        "wheels": [
            {
                "name": "pytest-9.1.1-py3-none-any.whl",
                "sha256": "66" * 32,
            }
        ],
    }
    document.update(overrides)
    return document


def legacy_document() -> dict[str, object]:
    document = valid_document(schema_version=1)
    legacy = {key: document[key] for key in MODULE.LEGACY_RECEIPT_KEYS}
    legacy["contract"] = MODULE.LEGACY_CONTRACT
    return legacy


def valid_migration_authority(
    current_receipt: bytes,
    *,
    closure: dict[str, str] | None = None,
    repo: Path = ROOT,
) -> dict[str, object]:
    return {
        "active_receipt_sha256": MODULE.digest_bytes(current_receipt),
        "active_sequence": 7,
        "authorized_repo_root": str(repo),
        "authority_id": "71" * 32,
        "closure": closure or valid_migration_closure(),
        "contract": MODULE.MIGRATION_AUTHORITY_CONTRACT,
        "key_id": "72" * 32,
        "expires_utc": "2026-08-28T00:00:00Z",
        "not_before_utc": "2026-08-25T00:00:00Z",
        "owner_provision_boundary": str(MODULE.OWNER_PROVISION_BOUNDARY),
        "owner_provision_boundary_sha256": "73" * 32,
        "owner_provision_launcher": str(MODULE.OWNER_PROVISION_LAUNCHER),
        "owner_provision_launcher_build_sha256": "8a" * 32,
        "owner_provision_launcher_compiler_sha256": "8b" * 32,
        "owner_provision_launcher_device": 123,
        "owner_provision_launcher_inode": 456,
        "owner_provision_launcher_linker_sha256": "8c" * 32,
        "owner_provision_launcher_sdk_closure_sha256": "8d" * 32,
        "owner_provision_launcher_sha256": "88" * 32,
        "owner_provision_launcher_source_sha256": "89" * 32,
        "runtime_launcher_sha256": "56" * 32,
        "runtime_python_sha256": "bb" * 32,
        "schema_version": 3,
        "signing_policy": {
            "authority_chain": list(PSF_CHAIN),
            "gatekeeper_origin": PSF_LEAF,
            "gatekeeper_source": "Developer ID",
            "requirements": {
                relative: requirement_for(relative)
                for relative in dict.fromkeys(
                    item[0] for item in MODULE.AUTHORITY_CODE_SLICES
                )
            },
            "team_identifier": "BMM5U3QVKW",
        },
        "signature_algorithm": "external-owner-approval-v1",
    }


def valid_migration_closure() -> dict[str, str]:
    return {
        key: format(index + 80, "02x") * 32
        for index, key in enumerate(MODULE.MIGRATION_CLOSURE_KEYS)
    }


def valid_migration_plan() -> dict[str, object]:
    current = MODULE.canonical_bytes(legacy_document())
    closure = valid_migration_closure()
    return MODULE.build_migration_plan(
        current_receipt_data=current,
        candidate=valid_document(),
        closure=closure,
        authority=valid_migration_authority(current, closure=closure),
        now=TRUSTED_NOW,
    )


def document_with_posture(
    *,
    flags: object = MODULE.REQUIRED_CODESIGN_FLAGS,
    entitlements: object | None = None,
) -> dict[str, object]:
    document = valid_document()
    posture = (
        dict(MODULE.REQUIRED_EXECUTABLE_ENTITLEMENTS)
        if entitlements is None
        else entitlements
    )
    document["codesign_flags"] = flags
    document["codesign_entitlements"] = copy.deepcopy(posture)
    for entrypoint in document["codesign_entrypoints"]:
        entrypoint["codesign_flags"] = flags
        entrypoint["codesign_entitlements"] = copy.deepcopy(posture)
    return document


def codesign_detail(
    path: Path,
    *,
    executable_path: Path | None = None,
    architecture: str = "arm64",
    codesign_kind: str = "mach-o-thin",
    flags: int = MODULE.REQUIRED_CODESIGN_FLAGS,
) -> bytes:
    names: list[str] = []
    if flags & MODULE.CS_REQUIRE_LV:
        names.append("library")
    if flags & MODULE.CS_RUNTIME:
        names.append("runtime")
    label = ",".join(names) if names else "none"
    executable = path if executable_path is None else executable_path
    format_text = {
        "mach-o-thin": f"Mach-O thin ({architecture})",
        "app-bundle": f"app bundle with Mach-O thin ({architecture})",
    }[codesign_kind]
    return (
        f"Executable={executable}\n"
        "Identifier=org.python.python3\n"
        f"Format={format_text}\n"
        f"CodeDirectory v=20500 size=467 flags=0x{flags:x}({label}) "
        "hashes=4+7 location=embedded\n"
        f"CDHash={'ab' * 20}\n"
        f"Authority={PSF_CHAIN[0]}\n"
        f"Authority={PSF_CHAIN[1]}\n"
        f"Authority={PSF_CHAIN[2]}\n"
        "TeamIdentifier=BMM5U3QVKW\n"
    ).encode("ascii")


def codesign_responses(
    path: Path,
    *,
    executable_path: Path | None = None,
    architecture: str = "arm64",
    codesign_kind: str = "mach-o-thin",
    requirement: str | None = None,
    flags: int = MODULE.REQUIRED_CODESIGN_FLAGS,
    entitlements: bytes | None = None,
) -> list[subprocess.CompletedProcess[bytes]]:
    if entitlements is None:
        entitlements = plistlib.dumps(
            MODULE.REQUIRED_EXECUTABLE_ENTITLEMENTS,
            fmt=plistlib.FMT_XML,
            sort_keys=True,
        )
    path_text = str(path)
    executable = path if executable_path is None else executable_path
    verify = [
        MODULE.CODESIGN,
        "--verify",
        "--strict",
        "--architecture",
        architecture,
        path_text,
    ]
    detail = [
        MODULE.CODESIGN,
        "--display",
        "--architecture",
        architecture,
        "--verbose=4",
        path_text,
    ]
    entitlement = [
        MODULE.CODESIGN,
        "--display",
        "--architecture",
        architecture,
        "--entitlements",
        "-",
        "--xml",
        path_text,
    ]
    requirement_argv = [
        MODULE.CODESIGN,
        "--display",
        "--architecture",
        architecture,
        "--requirements",
        "-",
        path_text,
    ]
    designated = requirement or requirement_for(MODULE.EXECUTABLE_RELATIVE)
    return [
        subprocess.CompletedProcess(verify, 0, stdout=b"", stderr=b""),
        subprocess.CompletedProcess(
            detail,
            0,
            stdout=b"",
            stderr=codesign_detail(
                path,
                executable_path=executable,
                architecture=architecture,
                codesign_kind=codesign_kind,
                flags=flags,
            ),
        ),
        subprocess.CompletedProcess(
            requirement_argv,
            0,
            stdout=f"designated => {designated}\n".encode("ascii"),
            stderr=f"Executable={executable}\n".encode("ascii"),
        ),
        subprocess.CompletedProcess(
            entitlement,
            0,
            stdout=entitlements,
            stderr=f"Executable={executable}\n".encode("utf-8"),
        ),
    ]


class MacosReleasePythonRuntimeReceiptTest(unittest.TestCase):
    def test_native_launcher_intel_shim_path_matches_receipt_contract(self) -> None:
        source = NATIVE_LAUNCHER_SOURCE.read_text(encoding="ascii")
        match = re.search(
            r'^#define WINS_RUNTIME_INTEL_SHIM "([^"]+)"$',
            source,
            re.MULTILINE,
        )
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), MODULE.AUTHORITY_ENTRYPOINTS[1])

    def test_canonical_document_parses(self) -> None:
        data = MODULE.canonical_bytes(valid_document())
        parsed = MODULE.parse_receipt(data)
        self.assertEqual(parsed["python_version"], "3.14.7")
        self.assertEqual(parsed["runtime_path"], MODULE.DEFAULT_RUNTIME)
        self.assertTrue(parsed["authenticated"] is True)

    def test_non_canonical_json_is_rejected(self) -> None:
        document = valid_document()
        messy = (json.dumps(document, indent=2) + "\n").encode("ascii")
        with self.assertRaisesRegex(MODULE.Refused, r"not canonical ASCII JSON"):
            MODULE.parse_receipt(messy)

    def test_extra_field_is_rejected(self) -> None:
        document = valid_document()
        document["extra"] = "nope"
        with self.assertRaisesRegex(MODULE.Refused, r"keys are not exact"):
            MODULE.parse_receipt(MODULE.canonical_bytes(document))

    def test_missing_field_is_rejected(self) -> None:
        document = valid_document()
        document.pop("issuer")
        with self.assertRaisesRegex(MODULE.Refused, r"keys are not exact"):
            MODULE.parse_receipt(MODULE.canonical_bytes(document))

    def test_authenticated_must_be_json_true(self) -> None:
        with self.assertRaisesRegex(MODULE.Refused, r"authenticated must be JSON true"):
            MODULE.parse_receipt(MODULE.canonical_bytes(valid_document(authenticated=1)))

    def test_wrong_version_is_rejected(self) -> None:
        with self.assertRaisesRegex(MODULE.Refused, r"frozen Python 3.14.7"):
            MODULE.parse_receipt(MODULE.canonical_bytes(valid_document(python_version="3.13.0")))

    def test_wrong_runtime_path_is_rejected(self) -> None:
        with self.assertRaisesRegex(MODULE.Refused, r"runtime_path is not the owner prefix"):
            MODULE.parse_receipt(
                MODULE.canonical_bytes(
                    valid_document(runtime_path="/private/tmp/wins-release-python-archive.fake")
                )
            )

    def test_zero_digest_is_rejected(self) -> None:
        with self.assertRaisesRegex(MODULE.Refused, r"invalid Python digest pin"):
            MODULE.parse_receipt(MODULE.canonical_bytes(valid_document(package_sha256="0" * 64)))

    def test_old_schema_is_rejected(self) -> None:
        for schema in (1, 2):
            with self.subTest(schema=schema):
                document = valid_document(schema_version=schema)
                with self.assertRaisesRegex(MODULE.Refused, r"schema_version mismatch"):
                    MODULE.parse_receipt(MODULE.canonical_bytes(document))

    def test_legacy_schema_is_migration_input_only(self) -> None:
        data = MODULE.canonical_bytes(legacy_document())
        legacy = MODULE.parse_legacy_receipt_for_migration(data)
        self.assertEqual(legacy["schema_version"], 1)
        with self.assertRaisesRegex(MODULE.Refused, r"schema_version mismatch"):
            MODULE.parse_receipt(data)
        extra = legacy_document()
        extra["codesign_flags"] = MODULE.REQUIRED_CODESIGN_FLAGS
        with self.assertRaisesRegex(MODULE.Refused, r"legacy.*keys are not exact"):
            MODULE.parse_legacy_receipt_for_migration(MODULE.canonical_bytes(extra))

        schema_two = legacy_document()
        schema_two["schema_version"] = 2
        with self.assertRaisesRegex(MODULE.Refused, r"legacy.*schema_version"):
            MODULE.parse_legacy_receipt_for_migration(
                MODULE.canonical_bytes(schema_two)
            )

    def test_v1_authority_and_v1_plan_contracts_are_rejected(self) -> None:
        current = MODULE.canonical_bytes(legacy_document())
        authority = valid_migration_authority(current)
        authority["contract"] = (
            "winsvpn-macos-release-python-runtime-receipt-authority-v1"
        )
        authority["schema_version"] = 2
        with self.assertRaisesRegex(MODULE.Refused, r"authority contract mismatch"):
            MODULE.parse_migration_authority(MODULE.canonical_bytes(authority))

        plan = valid_migration_plan()
        plan["contract"] = (
            "winsvpn-macos-release-python-runtime-receipt-migration-v1"
        )
        plan["schema_version"] = 1
        with self.assertRaisesRegex(MODULE.Refused, r"plan contract mismatch"):
            MODULE.parse_migration_plan(
                MODULE.canonical_bytes(plan), now=TRUSTED_NOW
            )

    def test_migration_candidate_cannot_downgrade_schema(self) -> None:
        current = MODULE.canonical_bytes(legacy_document())
        candidate = valid_document(schema_version=1)
        with self.assertRaisesRegex(MODULE.Refused, r"schema_version mismatch"):
            MODULE.build_migration_plan(
                current_receipt_data=current,
                candidate=candidate,
                closure=valid_migration_closure(),
                authority=valid_migration_authority(current),
                now=datetime(2026, 8, 26, 12, 0, 0, tzinfo=timezone.utc),
            )

    def test_migration_plan_is_canonical_bound_and_owner_blocked(self) -> None:
        with mock.patch.object(MODULE, "write_receipt") as write:
            plan = valid_migration_plan()
        write.assert_not_called()
        data = MODULE.canonical_bytes(plan)
        self.assertEqual(MODULE.parse_migration_plan(data, now=TRUSTED_NOW), plan)
        self.assertEqual(plan["status"], MODULE.OWNER_BLOCKED_MIGRATION)
        self.assertEqual(plan["contract"], MODULE.MIGRATION_CONTRACT)
        self.assertEqual(plan["schema_version"], 2)
        self.assertEqual(plan["authority"]["schema_version"], 3)
        candidate = MODULE.parse_receipt(plan["candidate_receipt_ascii"].encode("ascii"))
        self.assertTrue(candidate["authenticated"])
        self.assertEqual(candidate["contract"], MODULE.CONTRACT)
        self.assertEqual(candidate["schema_version"], 3)
        self.assertEqual(
            plan["expected_external_authority_operation"]["next_sequence"], 8
        )

    def test_migration_output_drift_is_rejected(self) -> None:
        cases: list[tuple[str, object]] = []
        candidate = valid_migration_plan()
        candidate["candidate_receipt_ascii"] += " "
        cases.append(("candidate output drift", candidate))
        identity = valid_migration_plan()
        identity["migration_id"] = "99" * 32
        cases.append(("identity drift", identity))
        operation = valid_migration_plan()
        operation["expected_external_authority_operation"]["receipt_path"] = (
            "/private/tmp/self-authored.json"
        )
        cases.append(("external operation drift", operation))
        for pattern, plan in cases:
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(MODULE.Refused, pattern):
                    MODULE.parse_migration_plan(
                        MODULE.canonical_bytes(plan), now=TRUSTED_NOW
                    )

    def test_migration_candidate_native_launcher_drift_is_rejected(self) -> None:
        plan = valid_migration_plan()
        candidate = json.loads(plan["candidate_receipt_ascii"])
        candidate["owner_provision_launcher_sha256"] = "ef" * 32
        candidate_bytes = MODULE.canonical_bytes(candidate)
        plan["candidate_receipt_ascii"] = candidate_bytes.decode("ascii")
        plan["candidate_receipt_sha256"] = MODULE.digest_bytes(candidate_bytes)
        operation = plan["expected_external_authority_operation"]
        operation["candidate_receipt_sha256"] = plan["candidate_receipt_sha256"]
        plan["migration_id"] = MODULE._migration_id(
            current_receipt_sha256=plan["current_receipt_sha256"],
            candidate_receipt_sha256=plan["candidate_receipt_sha256"],
            closure=plan["closure"],
            authority=plan["authority"],
            created_utc=plan["created_utc"],
            expires_utc=plan["expires_utc"],
        )
        operation["migration_id"] = plan["migration_id"]
        with self.assertRaisesRegex(MODULE.Refused, r"native binding differ"):
            MODULE.parse_migration_plan(
                MODULE.canonical_bytes(plan), now=TRUSTED_NOW
            )

    def test_migration_authority_rejects_caller_key_replay_and_time_drift(self) -> None:
        current = MODULE.canonical_bytes(legacy_document())
        wrong_key = valid_migration_authority(current)
        wrong_key["key_id"] = "caller-selected-key"
        with self.assertRaisesRegex(MODULE.Refused, r"key_id is invalid"):
            MODULE.parse_migration_authority(MODULE.canonical_bytes(wrong_key))

        replay = valid_migration_authority(b"different receipt\n")
        with self.assertRaisesRegex(MODULE.Refused, r"replayed or stale"):
            MODULE.build_migration_plan(
                current_receipt_data=current,
                candidate=valid_document(),
                closure=valid_migration_closure(),
                authority=replay,
                now=datetime(2026, 8, 26, 12, 0, 0, tzinfo=timezone.utc),
            )

        expired = valid_migration_authority(current)
        expired["expires_utc"] = "2026-08-26T12:00:00Z"
        with self.assertRaisesRegex(MODULE.Refused, r"expired"):
            MODULE.build_migration_plan(
                current_receipt_data=current,
                candidate=valid_document(),
                closure=valid_migration_closure(),
                authority=expired,
                now=TRUSTED_NOW,
            )

        plan = valid_migration_plan()
        with self.assertRaisesRegex(MODULE.Refused, r"plan is not currently valid"):
            MODULE.parse_migration_plan(
                MODULE.canonical_bytes(plan),
                now=datetime(2026, 8, 27, 12, 0, 0, tzinfo=timezone.utc),
            )

        future = valid_migration_authority(current)
        future["not_before_utc"] = "2026-08-27T00:00:00Z"
        with self.assertRaisesRegex(MODULE.Refused, r"not yet valid"):
            MODULE.build_migration_plan(
                current_receipt_data=current,
                candidate=valid_document(),
                closure=valid_migration_closure(),
                authority=future,
                now=datetime(2026, 8, 26, 12, 0, 0, tzinfo=timezone.utc),
            )

    def test_one_time_migration_replaces_authority_bound_legacy_runtime(self) -> None:
        legacy = legacy_document()
        legacy["runtime_dir_identity"] = "9:9:0:0:555:1:1:1"
        legacy["framework_tree_sha256"] = "91" * 32
        legacy["vendor_tree_sha256"] = "92" * 32
        legacy["launcher_tree_sha256"] = "93" * 32
        legacy["executable_sha256"] = "94" * 32
        legacy["package_signature_status"] = (
            'Package "python-3.14.7-macos11.pkg":    '
            f"{MODULE.APPROVED_PACKAGE_SIGNATURE_STATUS}    "
            "Notarization: trusted by the Apple notary service"
        )
        current = MODULE.canonical_bytes(legacy)
        authority = valid_migration_authority(current)
        MODULE.require_legacy_migration_input(
            current,
            authority,
        )
        self.assertEqual(
            MODULE.legacy_package_signature_status(
                legacy,
                str(legacy["package_sha256"]),
            ),
            MODULE.APPROVED_PACKAGE_SIGNATURE_STATUS,
        )

        stale = dict(authority)
        stale["active_receipt_sha256"] = "fe" * 32
        with self.assertRaisesRegex(MODULE.Refused, r"replayed or stale"):
            MODULE.require_legacy_migration_input(
                current,
                stale,
            )

        with self.assertRaisesRegex(MODULE.Refused, r"schema_version 1"):
            MODULE.parse_legacy_receipt_for_migration(
                MODULE.canonical_bytes(valid_document())
            )
        with self.assertRaisesRegex(MODULE.Refused, r"differs"):
            MODULE.legacy_package_signature_status(legacy, "ff" * 32)

    def test_legacy_replacement_does_not_relax_normal_runtime_matching(self) -> None:
        document = valid_document(
            runtime_dir_identity="substituted",
            runtime_path=str(ROOT),
        )
        tree = {
            "content": str(document["framework_tree_sha256"]),
            "identity": str(document["framework_identity_sha256"]),
            "dir_identity": str(document["framework_dir_identity"]),
        }
        with self.assertRaisesRegex(MODULE.Refused, r"changed inode"):
            MODULE.match_receipt_to_runtime(
                document,
                runtime=ROOT,
                framework=tree,
                vendor={
                    "content": str(document["vendor_tree_sha256"]),
                    "identity": str(document["vendor_identity_sha256"]),
                    "dir_identity": str(document["vendor_dir_identity"]),
                },
                launcher={
                    "content": str(document["launcher_tree_sha256"]),
                    "identity": str(document["launcher_identity_sha256"]),
                    "dir_identity": str(document["launcher_dir_identity"]),
                },
                executable=TOOL,
                controllers={"controller_sha256": str(document["controller_sha256"])},
                package_sha256=str(document["package_sha256"]),
                wheels=copy.deepcopy(document["wheels"]),
                codesign={},
                package_signature_status=str(document["package_signature_status"]),
            )

    def test_normal_authentication_binds_authority_active_receipt_digest(self) -> None:
        closure = valid_migration_closure()
        receipt_data = MODULE.canonical_bytes(
            valid_document(custody_closure=closure)
        )
        held = types.SimpleNamespace(
            closure=lambda: closure,
            data={
                "pin_manifest_sha256": b"{}\n",
                "custody_metadata_sha256": b"{}\n",
            },
            assert_current=lambda: None,
        )
        common = (
            mock.patch.object(MODULE.sys, "platform", "darwin"),
            mock.patch.object(MODULE.os, "geteuid", return_value=501),
            mock.patch.object(MODULE, "parse_pin_manifest_bytes", return_value={}),
            mock.patch.object(MODULE, "pin_wheels", return_value=("11" * 32, [])),
            mock.patch.object(
                MODULE,
                "require_external_receipt",
                return_value=(Path(MODULE.DEFAULT_RECEIPT), receipt_data),
            ),
            mock.patch.object(MODULE, "require_authority_current"),
            mock.patch.object(MODULE, "require_authority_for_repo"),
        )
        with common[0], common[1], common[2], common[3], common[4], common[5], common[6], mock.patch.dict(
            MODULE.os.environ,
            {MODULE.EXECUTED_SOURCE_SHA256_ENV: closure["custody_controller_sha256"]},
            clear=False,
        ), mock.patch.object(
            MODULE,
            "_read_migration_authority",
            return_value=valid_migration_authority(
                b"caller-selected-stale-receipt\n", closure=closure
            ),
        ):
            with self.assertRaisesRegex(MODULE.Refused, r"active receipt is replayed or stale"):
                MODULE._authenticate_held(
                    ROOT,
                    ROOT / MODULE.PIN_MANIFEST,
                    held,
                )

    def test_migration_refuses_source_path_swap_and_fake_interpreter(self) -> None:
        with self.assertRaisesRegex(MODULE.Refused, r"cannot self-authorize"):
            MODULE.snapshot_migration_closure(
                ROOT / "tools",
                ROOT / "tools" / "toolchain-pins.json",
            )
        closure = valid_migration_closure()
        with mock.patch.object(
            MODULE,
            "_held_descriptor_digest",
            side_effect=[
                closure["custody_controller_sha256"],
                closure["receipt_test_sha256"],
            ],
        ), mock.patch.dict(
            MODULE.os.environ,
            {
                MODULE.MIGRATION_EXECUTED_SOURCE_SHA256_ENV: closure[
                    "custody_controller_sha256"
                ]
            },
            clear=False,
        ):
            MODULE.require_held_migration_sources(closure)
        with mock.patch.object(
            MODULE,
            "_held_descriptor_digest",
            side_effect=["ff" * 32, closure["receipt_test_sha256"]],
        ), mock.patch.dict(
            MODULE.os.environ,
            {MODULE.MIGRATION_EXECUTED_SOURCE_SHA256_ENV: "ff" * 32},
            clear=False,
        ):
            with self.assertRaisesRegex(MODULE.Refused, r"source/path swap"):
                MODULE.require_held_migration_sources(closure)
        measured = {
            "executable_path": MODULE.DEFAULT_RUNTIME + "/" + MODULE.EXECUTABLE_RELATIVE,
            "executable_sha256": "aa" * 32,
            "executable_identity": "1:2:0:0:555:1:1:1",
        }
        with mock.patch.object(MODULE.sys, "platform", "darwin"), mock.patch.object(
            MODULE.sys, "executable", "/private/tmp/fake-python"
        ):
            with self.assertRaisesRegex(MODULE.Refused, r"authenticated ReleasePython"):
                MODULE.require_authenticated_planner_interpreter(measured)

    def test_plan_migration_does_not_accept_caller_authority_or_key_arguments(self) -> None:
        with mock.patch.object(MODULE, "plan_migration") as planner:
            result = MODULE.main(
                [
                    "plan-migration",
                    str(ROOT),
                    str(ROOT / "tools" / "toolchain-pins.json"),
                    "/private/tmp/caller-authority.json",
                    "caller-key",
                ]
            )
        self.assertEqual(result, 1)
        planner.assert_not_called()

    def test_fixed_authority_binds_repo_and_complete_closure_dag(self) -> None:
        closure = MODULE.snapshot_migration_closure(
            ROOT, ROOT / "tools" / "toolchain-pins.json"
        )
        current = MODULE.canonical_bytes(legacy_document())
        authority = valid_migration_authority(current, closure=closure)
        MODULE.require_authority_for_repo(authority, ROOT, closure)
        MODULE.require_authority_bound_custody_metadata(ROOT, closure)
        expected_paths = {
            key: ROOT / relative
            for key, relative in MODULE.REPO_CLOSURE_PATHS.items()
        }
        self.assertIn(
            "fin_release_gate_sha256", expected_paths
        )
        self.assertEqual(
            expected_paths["fin_release_gate_sha256"],
            ROOT / "tools" / "fin_release_gate.sh",
        )
        self.assertEqual(
            {
                expected_paths[key]
                for key in (
                    "android_custody_sha256",
                    "openssl_custody_sha256",
                    "node_custody_sha256",
                    "browser_custody_sha256",
                    "go_custody_sha256",
                )
            },
            {ROOT / relative for relative in MODULE.FIN_RELEASE_GATE_SOURCE_CLOSURE},
        )
        self.assertEqual(
            expected_paths["gcp_proof_collector_sha256"],
            ROOT / "tools" / "gcp_proof_evidence.py",
        )
        self.assertEqual(
            expected_paths["gcp_proof_live_probe_sha256"],
            ROOT / "tools" / "gcp_proof_live_probe.py",
        )
        legacy_expected_paths = {
            "archive_test_sha256": ROOT / MODULE.ARCHIVE_TEST,
            "custody_controller_sha256": ROOT / MODULE.RECEIPT_SCHEMA,
            "custody_metadata_sha256": ROOT / MODULE.CUSTODY_METADATA,
            "fin_g00_test_sha256": ROOT / MODULE.FIN_G00_TEST,
            "pin_manifest_sha256": ROOT / MODULE.PIN_MANIFEST,
            "provision_test_sha256": ROOT / MODULE.PROVISION_TEST,
            "provisioner_sha256": ROOT / MODULE.PROVISIONER,
            "receipt_test_sha256": ROOT / MODULE.RECEIPT_TEST,
            "wrapper_sha256": ROOT / MODULE.CONTROLLER,
        }
        self.assertTrue(legacy_expected_paths.items() <= expected_paths.items())
        self.assertEqual(set(closure), set(expected_paths))
        for key, path in expected_paths.items():
            self.assertEqual(closure[key], MODULE.digest_file(path))

    def test_held_full_closure_rejects_same_uid_path_substitution_and_drift(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-rp-closure-", dir="/private/tmp") as raw:
            repo = Path(raw)
            for relative in MODULE.REPO_CLOSURE_PATHS.values():
                destination = repo / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            manifest = repo / MODULE.PIN_MANIFEST
            with mock.patch.object(MODULE, "tools_dir", return_value=repo / "tools"):
                held = MODULE.HeldRepoClosure(repo, manifest)
                try:
                    target = repo / MODULE.FIN_RELEASE_GATE
                    replacement = target.with_name("fin_release_gate.replacement")
                    replacement.write_bytes(target.read_bytes())
                    replacement.replace(target)
                    with self.assertRaisesRegex(
                        MODULE.Refused, r"closure path or bytes drift"
                    ):
                        held.assert_current()
                finally:
                    held.close()

                held = MODULE.HeldRepoClosure(repo, manifest)
                try:
                    target = repo / MODULE.FIN_RELEASE_GATE
                    target.write_bytes(target.read_bytes() + b"# same-uid drift\n")
                    with self.assertRaisesRegex(
                        MODULE.Refused, r"closure path or bytes drift"
                    ):
                        held.assert_current()
                finally:
                    held.close()

    def test_copied_repo_and_arbitrary_matching_self_hash_are_owner_blocked(self) -> None:
        closure = valid_migration_closure()
        current = MODULE.canonical_bytes(legacy_document())
        authority = valid_migration_authority(current, closure=closure)
        with self.assertRaisesRegex(MODULE.Refused, r"copied or replacement"):
            MODULE.require_authority_for_repo(
                authority, Path("/private/tmp/copied-repo"), closure
            )
        self_closure = dict(closure)
        self_closure["custody_controller_sha256"] = "fe" * 32
        with mock.patch.object(
            MODULE,
            "_held_descriptor_digest",
            side_effect=["fe" * 32, self_closure["receipt_test_sha256"]],
        ), mock.patch.dict(
            MODULE.os.environ,
            {MODULE.MIGRATION_EXECUTED_SOURCE_SHA256_ENV: "fe" * 32},
            clear=False,
        ):
            MODULE.require_held_migration_sources(self_closure)
        with self.assertRaisesRegex(MODULE.Refused, r"authority hash drift"):
            MODULE.require_authority_for_repo(authority, ROOT, self_closure)

    def test_authority_wrapper_provisioner_and_sequence_drift_are_rejected(self) -> None:
        current = MODULE.canonical_bytes(legacy_document())
        closure = valid_migration_closure()
        for key in ("wrapper_sha256", "provisioner_sha256"):
            drifted = dict(closure)
            drifted[key] = "ee" * 32
            authority = valid_migration_authority(current, closure=closure)
            with self.subTest(key=key), self.assertRaisesRegex(
                MODULE.Refused, r"authority hash drift"
            ):
                MODULE.require_authority_for_repo(authority, ROOT, drifted)
        plan = valid_migration_plan()
        plan["expected_external_authority_operation"]["expected_active_sequence"] = 6
        with self.assertRaisesRegex(MODULE.Refused, r"external operation drift"):
            MODULE.parse_migration_plan(
                MODULE.canonical_bytes(plan), now=TRUSTED_NOW
            )

    def test_root_migration_execution_is_refused_before_measurement(self) -> None:
        with mock.patch.object(MODULE.sys, "platform", "darwin"), mock.patch.object(
            MODULE.os, "geteuid", return_value=0
        ), mock.patch.object(MODULE, "require_external_receipt") as receipt:
            with self.assertRaisesRegex(MODULE.Refused, r"non-root user"):
                MODULE.plan_migration(ROOT, ROOT / "tools" / "toolchain-pins.json")
        receipt.assert_not_called()

    def test_module_refuses_root_before_exposing_dispatch_actions(self) -> None:
        source = TOOL.read_text(encoding="ascii")
        guard = source.index("if os.geteuid() == 0:")
        first_action = source.index("def _nofollow()")
        dispatch = source.index("def main(")
        self.assertLess(guard, first_action)
        self.assertLess(guard, dispatch)

    def test_duplicate_json_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(MODULE.Refused, r"duplicate JSON key"):
            MODULE.parse_receipt(b'{"schema_version":2,"schema_version":2}\n')

    def test_hardened_runtime_is_required_and_real_psf_flags_are_accepted(self) -> None:
        with self.assertRaisesRegex(MODULE.Refused, r"missing the hardened runtime flag"):
            MODULE.parse_receipt(
                MODULE.canonical_bytes(document_with_posture(flags=MODULE.CS_REQUIRE_LV))
            )
        parsed = MODULE.parse_receipt(
            MODULE.canonical_bytes(document_with_posture(flags=MODULE.CS_RUNTIME))
        )
        self.assertEqual(parsed["codesign_flags"], MODULE.CS_RUNTIME)

    def test_absent_receipt_flags_are_rejected(self) -> None:
        document = valid_document()
        document.pop("codesign_flags")
        with self.assertRaisesRegex(MODULE.Refused, r"keys are not exact"):
            MODULE.parse_receipt(MODULE.canonical_bytes(document))

        document = valid_document()
        document["codesign_entrypoints"][2].pop("codesign_flags")
        with self.assertRaisesRegex(MODULE.Refused, r"entrypoint 2 keys are not exact"):
            MODULE.parse_receipt(MODULE.canonical_bytes(document))

    def test_every_forbidden_entitlement_is_rejected(self) -> None:
        required = {
            "com.apple.security.get-task-allow",
            "com.apple.security.cs.debugger",
            "com.apple.security.cs.disable-library-validation",
            "com.apple.security.cs.allow-dyld-environment-variables",
            "com.apple.security.cs.disable-executable-page-protection",
        }
        self.assertTrue(required.issubset(MODULE.FORBIDDEN_ENTITLEMENTS))
        for entitlement in sorted(MODULE.FORBIDDEN_ENTITLEMENTS):
            with self.subTest(entitlement=entitlement):
                document = document_with_posture(entitlements={entitlement: True})
                with self.assertRaisesRegex(
                    MODULE.Refused,
                    r"forbidden entitlement",
                ):
                    MODULE.parse_receipt(MODULE.canonical_bytes(document))

    def test_runtime_entitlement_is_exactly_required(self) -> None:
        expected = {
            "com.apple.security.cs.allow-unsigned-executable-memory": True,
        }
        self.assertEqual(MODULE.REQUIRED_EXECUTABLE_ENTITLEMENTS, expected)
        parsed = MODULE.parse_receipt(MODULE.canonical_bytes(document_with_posture()))
        self.assertEqual(parsed["codesign_entitlements"], expected)
        for entitlements in ({}, {next(iter(expected)): False}):
            with self.subTest(entitlements=entitlements):
                with self.assertRaisesRegex(
                    MODULE.Refused,
                    r"executable entitlement policy is not exact",
                ):
                    MODULE.parse_receipt(
                        MODULE.canonical_bytes(
                            document_with_posture(entitlements=entitlements)
                        )
                    )

    def test_unknown_security_sensitive_entitlement_state_is_rejected(self) -> None:
        document = document_with_posture(
            entitlements={"com.apple.developer.unreviewed-capability": False}
        )
        with self.assertRaisesRegex(
            MODULE.Refused, r"unknown security-sensitive entitlement state"
        ):
            MODULE.parse_receipt(MODULE.canonical_bytes(document))

    def test_wrong_typed_posture_values_are_rejected(self) -> None:
        for flags in (True, "0x12000", 73728.0, None):
            with self.subTest(field="codesign_flags", value=flags):
                document = document_with_posture(flags=flags)
                with self.assertRaisesRegex(MODULE.Refused, r"CodeDirectory flags are invalid"):
                    MODULE.parse_receipt(MODULE.canonical_bytes(document))
        for entitlements in ([], "{}", True, 1):
            with self.subTest(field="codesign_entitlements", value=entitlements):
                document = valid_document()
                document["codesign_entitlements"] = entitlements
                for entrypoint in document["codesign_entrypoints"]:
                    entrypoint["codesign_entitlements"] = entitlements
                with self.assertRaisesRegex(MODULE.Refused, r"must be a JSON object"):
                    MODULE.parse_receipt(MODULE.canonical_bytes(document))

    def test_nonfinite_receipt_value_is_rejected(self) -> None:
        for nonfinite in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=repr(nonfinite)):
                document = document_with_posture(flags=nonfinite)
                data = (
                    json.dumps(
                        document,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=True,
                        allow_nan=True,
                    )
                    + "\n"
                ).encode("ascii")
                with self.assertRaisesRegex(MODULE.Refused, r"non-finite JSON value"):
                    MODULE.parse_receipt(data)

    def test_exact_entrypoint_set_is_required(self) -> None:
        documents: list[dict[str, object]] = []
        missing = valid_document()
        missing["codesign_entrypoints"].pop()
        documents.append(missing)
        reordered = valid_document()
        reordered["codesign_entrypoints"][1], reordered["codesign_entrypoints"][2] = (
            reordered["codesign_entrypoints"][2],
            reordered["codesign_entrypoints"][1],
        )
        documents.append(reordered)
        substituted = valid_document()
        substituted["codesign_entrypoints"][1]["relative_path"] = (
            "Python.framework/Versions/3.14/bin/substituted"
        )
        documents.append(substituted)
        for index, document in enumerate(documents):
            with self.subTest(case=index):
                with self.assertRaisesRegex(
                    MODULE.Refused, r"exact authority entrypoint set|cross-kind/path/architecture substitution"
                ):
                    MODULE.parse_receipt(MODULE.canonical_bytes(document))

    def test_cross_entrypoint_and_primary_drift_are_rejected(self) -> None:
        cross = valid_document()
        cross["codesign_entrypoints"][1]["codesign_flags"] = (
            MODULE.REQUIRED_CODESIGN_FLAGS | 0x1
        )
        with self.assertRaisesRegex(MODULE.Refused, r"cross-entrypoint codesign_flags drift"):
            MODULE.parse_receipt(MODULE.canonical_bytes(cross))

        primary = valid_document(codesign_cdhash="fe" * 20)
        with self.assertRaisesRegex(MODULE.Refused, r"primary codesign field"):
            MODULE.parse_receipt(MODULE.canonical_bytes(primary))

    def test_live_cross_entrypoint_drift_is_rejected(self) -> None:
        entrypoints = copy.deepcopy(valid_document()["codesign_entrypoints"])
        primary = {
            key: entrypoints[0][key]
            for key in MODULE.CODESIGN_ENTRYPOINT_KEYS
            if key not in {"architecture", "executable_relative_path", "relative_path"}
        }
        tree = {"content": "11" * 32, "identity": "22" * 32, "dir_identity": "1:2:0:0:755:1:1:1"}
        controllers = {"controller_sha256": "33" * 32}
        receipt = {
            "runtime_path": str(ROOT),
            "runtime_dir_identity": MODULE.dir_identity(ROOT.lstat()),
            "framework_tree_sha256": tree["content"],
            "framework_identity_sha256": tree["identity"],
            "framework_dir_identity": tree["dir_identity"],
            "vendor_tree_sha256": tree["content"],
            "vendor_identity_sha256": tree["identity"],
            "vendor_dir_identity": tree["dir_identity"],
            "launcher_tree_sha256": tree["content"],
            "launcher_identity_sha256": tree["identity"],
            "launcher_dir_identity": tree["dir_identity"],
            "executable_identity": MODULE.file_identity(TOOL.lstat()),
            "executable_sha256": MODULE.digest_file(TOOL),
            "executable_path": str(TOOL),
            "package_sha256": "44" * 32,
            "wheels": [{"name": "fixture.whl", "sha256": "55" * 32}],
            "wheel_count": 1,
            "controller_sha256": controllers["controller_sha256"],
            "package_signature_status": "Status: signed fixture",
            "codesign_entrypoints": entrypoints,
            **primary,
        }
        kwargs = {
            "runtime": ROOT,
            "framework": tree,
            "vendor": tree,
            "launcher": tree,
            "executable": TOOL,
            "controllers": controllers,
            "package_sha256": receipt["package_sha256"],
            "wheels": receipt["wheels"],
            "codesign": primary,
            "package_signature_status": receipt["package_signature_status"],
        }
        MODULE.match_receipt_to_runtime(
            receipt,
            **kwargs,
            codesign_entrypoints=entrypoints,
        )
        drifted = copy.deepcopy(entrypoints)
        drifted[2]["codesign_cdhash"] = "ef" * 20
        with self.assertRaisesRegex(MODULE.Refused, r"cross-entrypoint.*drift"):
            MODULE.match_receipt_to_runtime(
                receipt,
                **kwargs,
                codesign_entrypoints=drifted,
            )

    def test_live_cross_entrypoint_authority_chain_drift_is_rejected(self) -> None:
        records: list[dict[str, object]] = []
        for index, (relative, executable, architecture, kind) in enumerate(
            MODULE.AUTHORITY_CODE_SLICES
        ):
            record = clean_codesign_entrypoint(
                relative,
                executable,
                architecture,
                kind,
                index,
            )
            records.append(
                {
                    key: value
                    for key, value in record.items()
                    if key
                    not in {"architecture", "executable_relative_path", "relative_path"}
                }
            )
        records[2]["codesign_authority_chain"] = [PSF_LEAF, "substituted"]
        with mock.patch.object(
            MODULE,
            "codesign_record",
            side_effect=records,
        ), self.assertRaisesRegex(
            MODULE.Refused, r"cross-entrypoint codesign_authority_chain drift"
        ):
            MODULE.codesign_entrypoint_records(Path("/captured"))

    def test_malformed_duplicate_and_unsupported_plist_values_are_rejected(self) -> None:
        prefix = (
            b'<?xml version="1.0" encoding="UTF-8"?>\n'
            b'<plist version="1.0">'
        )
        suffix = b"</plist>"
        cases = (
            (
                prefix + b"<dict><string>not-a-key</string><true/></dict>" + suffix,
                r"dictionary key is malformed",
            ),
            (
                prefix
                + b"<dict><key>same</key><true/><key>same</key><false/></dict>"
                + suffix,
                r"duplicate codesign entitlement key",
            ),
            (
                prefix + b"<dict><key>number</key><real>NaN</real></dict>" + suffix,
                r"value type is unsupported",
            ),
        )
        for data, pattern in cases:
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(MODULE.Refused, pattern):
                    MODULE.parse_codesign_entitlements(data)

    def test_entitlement_doctype_allowlist_is_exactly_two_apple_spellings(
        self,
    ) -> None:
        self.assertEqual(
            MODULE.STANDARD_ENTITLEMENT_DOCTYPES,
            (
                b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
                b'"http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
                b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
                b'"https://www.apple.com/DTDs/PropertyList-1.0.dtd">',
            ),
        )

    def test_captured_entitlement_document_is_accepted_in_both_apple_dtd_spellings(
        self,
    ) -> None:
        self.assertEqual(len(CAPTURED_ENTITLEMENTS_STDOUTS), 2)
        for data in CAPTURED_ENTITLEMENTS_STDOUTS:
            with self.subTest(doctype=data.split(b">", 2)[1]):
                self.assertEqual(
                    MODULE.parse_codesign_entitlements(data),
                    MODULE.REQUIRED_EXECUTABLE_ENTITLEMENTS,
                )

    def test_unexpected_entitlement_document_types_are_rejected(self) -> None:
        declaration = b'<?xml version="1.0" encoding="UTF-8"?>'
        body = b'<plist version="1.0"><dict></dict></plist>\n'
        https = MODULE.STANDARD_ENTITLEMENT_DOCTYPES[1]
        hostile = (
            https.replace(b"https://", b"httpss://"),
            https.replace(b"https://", b"HTTPS://"),
            https.replace(b"https://", b"//"),
            https.replace(b".dtd\">", b".dtd/\">"),
            https.replace(b"www.apple.com/", b"www.apple.com.evil.example/"),
            https.replace(b"PLIST 1.0", b"PLIST 1.1"),
            b'<!DOCTYPE plist SYSTEM "https://www.apple.com/DTDs/PropertyList-1.0.dtd">',
            https.replace(b'"-//Apple//DTD PLIST 1.0//EN"', b"'-//Apple//DTD PLIST 1.0//EN'"),
            https.replace(b" PUBLIC ", b"  PUBLIC "),
            https[:-1] + b" [<!ELEMENT plist ANY>]>",
            https.lower(),
            MODULE.STANDARD_ENTITLEMENT_DOCTYPES[0] + https,
        )
        for doctype in hostile:
            with self.subTest(doctype=doctype), self.assertRaisesRegex(
                MODULE.Refused, r"unexpected document type"
            ):
                MODULE.parse_codesign_entitlements(declaration + doctype + body)
        with self.assertRaisesRegex(MODULE.Refused, r"ambiguous XML constructs"):
            MODULE.parse_codesign_entitlements(
                declaration + https + b"<!-- comment -->" + body
            )

    def test_clean_synthetic_codesign_posture_uses_exact_commands(self) -> None:
        entitlements = plistlib.dumps(
            MODULE.REQUIRED_EXECUTABLE_ENTITLEMENTS,
            fmt=plistlib.FMT_XML,
            sort_keys=True,
        )
        responses = codesign_responses(TOOL, entitlements=entitlements)
        with mock.patch.object(MODULE.subprocess, "run", side_effect=responses) as run:
            record = MODULE.codesign_record(TOOL, "arm64")
        self.assertEqual(record["codesign_flags"], MODULE.CS_RUNTIME)
        self.assertEqual(
            record["codesign_entitlements"],
            MODULE.REQUIRED_EXECUTABLE_ENTITLEMENTS,
        )
        self.assertEqual(
            [call.args[0] for call in run.call_args_list],
            [response.args for response in responses],
        )
        for call in run.call_args_list:
            self.assertEqual(call.kwargs["timeout"], MODULE.CODESIGN_TIMEOUT_SECONDS)
            self.assertEqual(call.kwargs["env"]["LC_ALL"], "C")
            self.assertTrue(call.kwargs["capture_output"])
            self.assertIs(call.kwargs["stdin"], subprocess.DEVNULL)

    def test_captured_release_python_requirement_stream_split_is_accepted_per_architecture(
        self,
    ) -> None:
        for architecture in ("arm64", "x86_64"):
            with self.subTest(architecture=architecture):
                self.assertEqual(
                    MODULE._parse_codesign_requirement(
                        CAPTURED_REQUIREMENT_STDOUT,
                        CAPTURED_REQUIREMENT_STDERR,
                        CAPTURED_PYTHON,
                    ),
                    CAPTURED_REQUIREMENT,
                )

    def test_captured_gatekeeper_stream_binds_measured_origin(self) -> None:
        expected = {
            "origin": CAPTURED_GATEKEEPER_ORIGIN,
            "relative_path": MODULE.PYTHON_APP_RELATIVE,
            "source": MODULE.REQUIRED_GATEKEEPER_SOURCE,
        }
        self.assertEqual(
            MODULE._parse_gatekeeper_assessment(
                CAPTURED_GATEKEEPER_STDERR,
                CAPTURED_PYTHON_APP,
                CAPTURED_GATEKEEPER_ORIGIN,
            ),
            expected,
        )
        with_origin = CAPTURED_GATEKEEPER_STDERR + (
            f"origin={CAPTURED_GATEKEEPER_ORIGIN}\n"
        ).encode("ascii")
        self.assertEqual(
            MODULE._parse_gatekeeper_assessment(
                with_origin,
                CAPTURED_PYTHON_APP,
                CAPTURED_GATEKEEPER_ORIGIN,
            ),
            expected,
        )
        with self.assertRaisesRegex(MODULE.Refused, r"measured signing identity"):
            MODULE._parse_gatekeeper_assessment(
                CAPTURED_GATEKEEPER_STDERR + b"origin=substituted\n",
                CAPTURED_PYTHON_APP,
                CAPTURED_GATEKEEPER_ORIGIN,
            )

    def test_gatekeeper_stream_shape_is_exact_and_fail_closed(self) -> None:
        app_line = f"{CAPTURED_PYTHON_APP}: accepted\n".encode("ascii")
        cases = (
            ("one line", app_line, r"stream shape"),
            (
                "four lines",
                CAPTURED_GATEKEEPER_STDERR + b"origin=x\nwarning=x\n",
                r"stream shape",
            ),
            (
                "unterminated",
                CAPTURED_GATEKEEPER_STDERR[:-1],
                r"stream shape",
            ),
            (
                "leading blank",
                b"\n" + CAPTURED_GATEKEEPER_STDERR,
                r"exact Python.app bundle",
            ),
            (
                "CRLF",
                CAPTURED_GATEKEEPER_STDERR.replace(b"\n", b"\r\n"),
                r"ambiguous line endings",
            ),
            (
                "non-UTF-8",
                app_line + b"source=\xff\n",
                r"not UTF-8",
            ),
            (
                "unicode separator",
                app_line + "source=Notarized\u2028Developer ID\n".encode("utf-8"),
                r"identity is incomplete",
            ),
            (
                "vertical tab",
                app_line + b"source=Notarized\x0bDeveloper ID\n",
                r"identity is incomplete",
            ),
            (
                "path collision",
                f"{CAPTURED_PYTHON_APP}.other: accepted\n".encode("ascii")
                + f"source={MODULE.REQUIRED_GATEKEEPER_SOURCE}\n".encode("ascii"),
                r"exact Python.app bundle",
            ),
            (
                "rejected",
                f"{CAPTURED_PYTHON_APP}: rejected\n".encode("ascii")
                + f"source={MODULE.REQUIRED_GATEKEEPER_SOURCE}\n".encode("ascii"),
                r"exact Python.app bundle",
            ),
            ("empty source", app_line + b"source=\n", r"identity is incomplete"),
        )
        for label, data, pattern in cases:
            with self.subTest(label=label), self.assertRaisesRegex(
                MODULE.Refused, pattern
            ):
                MODULE._parse_gatekeeper_assessment(
                    data,
                    CAPTURED_PYTHON_APP,
                    CAPTURED_GATEKEEPER_ORIGIN,
                )

    def test_gatekeeper_assessment_uses_exact_command_and_source_floor(self) -> None:
        runtime = Path(MODULE.DEFAULT_RUNTIME)
        argv = [
            MODULE.SPCTL,
            "--assess",
            "--type",
            "execute",
            "--verbose=4",
            str(CAPTURED_PYTHON_APP),
        ]
        completed = subprocess.CompletedProcess(
            argv,
            0,
            stdout=b"",
            stderr=CAPTURED_GATEKEEPER_STDERR,
        )
        with mock.patch.object(MODULE.subprocess, "run", return_value=completed) as run:
            assessment = MODULE.gatekeeper_assessment(
                runtime,
                expected_origin=CAPTURED_GATEKEEPER_ORIGIN,
            )
        self.assertEqual(assessment["source"], MODULE.REQUIRED_GATEKEEPER_SOURCE)
        self.assertEqual(run.call_args.args[0], argv)
        self.assertEqual(run.call_args.kwargs["timeout"], MODULE.CODESIGN_TIMEOUT_SECONDS)
        self.assertEqual(run.call_args.kwargs["env"]["LC_ALL"], "C")
        self.assertTrue(run.call_args.kwargs["capture_output"])
        self.assertTrue(run.call_args.kwargs["close_fds"])
        self.assertEqual(run.call_args.kwargs["cwd"], "/")
        self.assertEqual(run.call_args.kwargs["pass_fds"], ())
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertIs(run.call_args.kwargs["stdin"], subprocess.DEVNULL)

        for source in ("Developer ID", "Unnotarized Developer ID", "Insufficient Context"):
            hostile = subprocess.CompletedProcess(
                argv,
                0,
                stdout=b"",
                stderr=(
                    f"{CAPTURED_PYTHON_APP}: accepted\nsource={source}\n"
                ).encode("ascii"),
            )
            with self.subTest(source=source), mock.patch.object(
                MODULE.subprocess, "run", return_value=hostile
            ), self.assertRaisesRegex(MODULE.Refused, r"notarized Developer ID"):
                MODULE.gatekeeper_assessment(
                    runtime,
                    expected_origin=CAPTURED_GATEKEEPER_ORIGIN,
                )

        for origin in ("", "adhoc", "a\nb", "a\0b"):
            with self.subTest(origin=origin), mock.patch.object(
                MODULE.subprocess, "run"
            ) as run, self.assertRaisesRegex(MODULE.Refused, r"identity binding"):
                MODULE.gatekeeper_assessment(runtime, expected_origin=origin)
            run.assert_not_called()

    def test_codesign_command_gate_rejects_non_template_and_mutating_argv(self) -> None:
        target = str(TOOL)
        hostile = (
            ["/usr/local/bin/codesign", "--verify", target],
            [MODULE.CODESIGN, "--sign", "Developer ID", target],
            [MODULE.CODESIGN, "-s", "-", target],
            [MODULE.CODESIGN, "--remove-signature", target],
            [
                MODULE.CODESIGN,
                "--display",
                "--architecture",
                "ppc",
                "--requirements",
                "-",
                target,
            ],
            [
                MODULE.CODESIGN,
                "--display",
                "--architecture",
                "arm64",
                "--requirements",
                target,
            ],
            [MODULE.SPCTL, "--assess", "--type", "install", "--verbose=4", target],
            [
                MODULE.CODESIGN,
                "--display",
                "--architecture",
                "arm64",
                "--requirements",
                "-",
                str(TOOL.parent / ".." / TOOL.parent.name / TOOL.name),
            ],
        )
        for argv in hostile:
            with self.subTest(argv=argv), mock.patch.object(
                MODULE.subprocess, "run"
            ) as run, self.assertRaisesRegex(
                MODULE.Refused,
                r"(?:command drift|mutating codesign|architecture selector|argv shape|target path)",
            ):
                MODULE._run_codesign(argv, label="hostile command")
            run.assert_not_called()

        with tempfile.TemporaryDirectory(prefix="wins-codesign-link-", dir="/private/tmp") as raw:
            link = Path(raw) / "linked-tool"
            link.symlink_to(TOOL)
            argv = [
                MODULE.CODESIGN,
                "--display",
                "--architecture",
                "arm64",
                "--requirements",
                "-",
                str(link),
            ]
            with mock.patch.object(MODULE.subprocess, "run") as run, self.assertRaisesRegex(
                MODULE.Refused, r"target path indirection"
            ):
                MODULE._run_codesign(argv, label="symlink command")
            run.assert_not_called()

    def test_codesign_invocation_budget_is_exact_and_fail_closed(self) -> None:
        argv = [
            MODULE.CODESIGN,
            "--display",
            "--architecture",
            "arm64",
            "--requirements",
            "-",
            str(TOOL),
        ]
        with mock.patch.dict(
            os.environ,
            {
                MODULE.CODESIGN_INVOCATION_LIMIT_ENV: str(
                    MODULE.CODESIGN_INVOCATION_LIMIT
                ),
                MODULE.REAUTH_MODE_ENV: "candidate",
            },
        ), mock.patch.object(
            MODULE,
            "_codesign_invocation_count",
            MODULE.CODESIGN_INVOCATION_LIMIT,
        ), mock.patch.object(
            MODULE.subprocess, "run"
        ) as run, self.assertRaisesRegex(
            MODULE.Refused, r"invocation budget exhausted"
        ):
            MODULE._run_codesign(argv, label="budgeted command")
        run.assert_not_called()

        with mock.patch.dict(
            os.environ,
            {
                MODULE.CODESIGN_INVOCATION_LIMIT_ENV: "22",
                MODULE.REAUTH_MODE_ENV: "candidate",
            },
        ), mock.patch.object(MODULE.subprocess, "run") as run, self.assertRaisesRegex(
            MODULE.Refused, r"budget configuration"
        ):
            MODULE._run_codesign(argv, label="misconfigured budget")
        run.assert_not_called()

        with mock.patch.dict(
            os.environ,
            {MODULE.REAUTH_MODE_ENV: "candidate"},
            clear=True,
        ), mock.patch.object(MODULE.subprocess, "run") as run, self.assertRaisesRegex(
            MODULE.Refused, r"budget configuration"
        ):
            MODULE._run_codesign(argv, label="missing budget")
        run.assert_not_called()

    def test_requirement_stream_split_is_exact_and_fail_closed(self) -> None:
        legacy = CAPTURED_REQUIREMENT_STDERR + CAPTURED_REQUIREMENT_STDOUT
        cases = (
            ("legacy merged stderr", b"", legacy, r"response substitution"),
            (
                "requirement appended to stderr",
                CAPTURED_REQUIREMENT_STDOUT,
                legacy,
                r"response substitution",
            ),
            (
                "swapped streams",
                CAPTURED_REQUIREMENT_STDERR,
                CAPTURED_REQUIREMENT_STDOUT,
                r"response substitution",
            ),
            (
                "executable appended to stdout",
                CAPTURED_REQUIREMENT_STDOUT + CAPTURED_REQUIREMENT_STDERR,
                CAPTURED_REQUIREMENT_STDERR,
                r"stream shape",
            ),
            ("empty stdout", b"", CAPTURED_REQUIREMENT_STDERR, r"stream shape"),
            (
                "empty stderr",
                CAPTURED_REQUIREMENT_STDOUT,
                b"",
                r"response substitution",
            ),
            (
                "duplicate designated line",
                CAPTURED_REQUIREMENT_STDOUT * 2,
                CAPTURED_REQUIREMENT_STDERR,
                r"stream shape",
            ),
            (
                "trailing warning",
                CAPTURED_REQUIREMENT_STDOUT + b"warning\n",
                CAPTURED_REQUIREMENT_STDERR,
                r"stream shape",
            ),
            (
                "leading blank line",
                b"\n" + CAPTURED_REQUIREMENT_STDOUT,
                CAPTURED_REQUIREMENT_STDERR,
                r"stream shape",
            ),
            (
                "unterminated",
                CAPTURED_REQUIREMENT_STDOUT[:-1],
                CAPTURED_REQUIREMENT_STDERR,
                r"stream shape",
            ),
            (
                "CRLF",
                CAPTURED_REQUIREMENT_STDOUT[:-1] + b"\r\n",
                CAPTURED_REQUIREMENT_STDERR,
                r"ambiguous line endings",
            ),
            (
                "non-UTF-8",
                b"designated => \xff\n",
                CAPTURED_REQUIREMENT_STDERR,
                r"not UTF-8",
            ),
            (
                "unicode separator",
                "designated => identifier python3\u2028\n".encode("utf-8"),
                CAPTURED_REQUIREMENT_STDERR,
                r"malformed",
            ),
            (
                "trailing space",
                CAPTURED_REQUIREMENT_STDOUT[:-1] + b" \n",
                CAPTURED_REQUIREMENT_STDERR,
                r"malformed",
            ),
            (
                "missing prefix space",
                b"designated =>identifier python3\n",
                CAPTURED_REQUIREMENT_STDERR,
                r"missing",
            ),
            (
                "wrong requirement tag",
                b"host => identifier python3\n",
                CAPTURED_REQUIREMENT_STDERR,
                r"missing",
            ),
            (
                "empty requirement",
                b"designated => \n",
                CAPTURED_REQUIREMENT_STDERR,
                r"malformed",
            ),
            (
                "substituted executable",
                CAPTURED_REQUIREMENT_STDOUT,
                b"Executable=/private/tmp/substituted\n",
                r"response substitution",
            ),
        )
        for label, stdout, stderr, pattern in cases:
            with self.subTest(label=label), self.assertRaisesRegex(
                MODULE.Refused, pattern
            ):
                MODULE._parse_codesign_requirement(stdout, stderr, CAPTURED_PYTHON)
        with self.assertRaisesRegex(MODULE.Refused, r"output type is malformed"):
            MODULE._parse_codesign_requirement(
                CAPTURED_REQUIREMENT_STDOUT.decode("ascii"),
                CAPTURED_REQUIREMENT_STDERR,
                CAPTURED_PYTHON,
            )

    def test_codesign_requirement_stage_retains_process_boundary_checks(self) -> None:
        clean = codesign_responses(TOOL)
        requirement = clean[2]
        hostile = (
            (
                "nonzero return",
                subprocess.CompletedProcess(
                    requirement.args,
                    1,
                    stdout=requirement.stdout,
                    stderr=requirement.stderr,
                ),
                r"requirement output is missing or ambiguous",
            ),
            (
                "oversized stdout",
                subprocess.CompletedProcess(
                    requirement.args,
                    0,
                    stdout=b"X" * (MODULE.MAX_CODESIGN_OUTPUT + 1),
                    stderr=requirement.stderr,
                ),
                r"requirement output exceeds the size limit",
            ),
            (
                "NUL in stdout",
                subprocess.CompletedProcess(
                    requirement.args,
                    0,
                    stdout=b"designated => identifier\0python3\n",
                    stderr=requirement.stderr,
                ),
                r"requirement output contains a NUL",
            ),
            (
                "substituted argv",
                subprocess.CompletedProcess(
                    ["/private/tmp/substituted-codesign", "--requirements"],
                    0,
                    stdout=requirement.stdout,
                    stderr=requirement.stderr,
                ),
                r"requirement response substitution",
            ),
        )
        for label, response, pattern in hostile:
            responses = codesign_responses(TOOL)
            responses[2] = response
            with self.subTest(label=label), mock.patch.object(
                MODULE.subprocess, "run", side_effect=responses
            ), self.assertRaisesRegex(MODULE.Refused, pattern):
                MODULE.codesign_record(TOOL, "arm64")

    def test_real_python_3_14_7_codesign_formats_are_parsed_by_code_kind(self) -> None:
        leaf = Path("/captured/Python.framework/Versions/3.14/bin/python3.14")
        app = Path("/captured/Python.framework/Versions/3.14/Resources/Python.app")
        app_executable = app / "Contents/MacOS/Python"
        leaf_output = (
            f"Executable={leaf}\n"
            "Identifier=python3\n"
            "Format=Mach-O thin (arm64)\n"
            "CodeDirectory v=20500 size=467 flags=0x10000(runtime) hashes=4+7 location=embedded\n"
            "CDHash=f342cd51acc213fd1654afa8e44f19a27488eda0\n"
            f"Authority={PSF_CHAIN[0]}\nAuthority={PSF_CHAIN[1]}\nAuthority={PSF_CHAIN[2]}\n"
            "TeamIdentifier=BMM5U3QVKW\n"
        ).encode("ascii")
        app_output = (
            f"Executable={app_executable}\n"
            "Identifier=org.python.python\n"
            "Format=app bundle with Mach-O thin (x86_64)\n"
            "CodeDirectory v=20500 size=477 flags=0x10000(runtime) hashes=4+7 location=embedded\n"
            "CDHash=6cfe948f749e4bc0f29d9c8ba7bda08013b7a67a\n"
            f"Authority={PSF_CHAIN[0]}\nAuthority={PSF_CHAIN[1]}\nAuthority={PSF_CHAIN[2]}\n"
            "TeamIdentifier=BMM5U3QVKW\n"
        ).encode("ascii")
        self.assertEqual(
            MODULE._parse_codesign_details(
                leaf_output, leaf, "arm64", "mach-o-thin"
            )["codesign_kind"],
            "mach-o-thin",
        )
        self.assertEqual(
            MODULE._parse_codesign_details(
                app_output, app_executable, "x86_64", "app-bundle"
            )["codesign_kind"],
            "app-bundle",
        )
        hostile = (
            (leaf_output, leaf, "arm64", "app-bundle"),
            (app_output, app_executable, "arm64", "app-bundle"),
            (app_output, leaf, "x86_64", "app-bundle"),
        )
        for data, executable, architecture, kind in hostile:
            with self.subTest(architecture=architecture, kind=kind), self.assertRaisesRegex(
                MODULE.Refused, r"(?:detail|kind/path/architecture) response substitution"
            ):
                MODULE._parse_codesign_details(data, executable, architecture, kind)

    def test_codesign_record_accepts_exact_app_bundle_target_kind(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-codesign-app-", dir="/private/tmp") as raw:
            app = Path(raw) / "Python.app"
            executable = app / "Contents/MacOS/Python"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"fixture")
            responses = codesign_responses(
                app,
                executable_path=executable,
                codesign_kind="app-bundle",
                flags=MODULE.CS_RUNTIME,
            )
            with mock.patch.object(MODULE.subprocess, "run", side_effect=responses):
                record = MODULE.codesign_record(
                    app,
                    "arm64",
                    executable_path=executable,
                    codesign_kind="app-bundle",
                )
            self.assertEqual(record["codesign_kind"], "app-bundle")
            with self.assertRaisesRegex(MODULE.Refused, r"target kind/path substitution"):
                MODULE.codesign_record(app, "arm64", codesign_kind="mach-o-thin")
            with self.assertRaisesRegex(MODULE.Refused, r"target kind/path substitution"):
                MODULE.codesign_record(executable, "arm64", codesign_kind="app-bundle")

    def test_owner_policy_rejects_adhoc_measured_and_gatekeeper_substitutions(self) -> None:
        current = MODULE.canonical_bytes(legacy_document())
        authority = valid_migration_authority(current)
        entrypoints = copy.deepcopy(valid_document()["codesign_entrypoints"])
        gatekeeper = copy.deepcopy(valid_document()["gatekeeper_assessment"])
        MODULE.require_owner_signing_policy(authority, entrypoints, gatekeeper)
        hostile = copy.deepcopy(entrypoints)
        hostile[0]["codesign_authority"] = "adhoc"
        hostile[0]["codesign_authority_chain"] = ["adhoc"]
        with self.assertRaisesRegex(MODULE.Refused, r"not owner-authorized"):
            MODULE.require_owner_signing_policy(authority, hostile, gatekeeper)
        hostile = copy.deepcopy(entrypoints)
        hostile[0]["codesign_authority"] = "Developer ID Application: Measured Only"
        hostile[0]["codesign_authority_chain"] = [
            "Developer ID Application: Measured Only"
        ]
        with self.assertRaisesRegex(MODULE.Refused, r"not owner-authorized"):
            MODULE.require_owner_signing_policy(authority, hostile, gatekeeper)
        with self.assertRaisesRegex(MODULE.Refused, r"Gatekeeper policy"):
            MODULE.require_owner_signing_policy(
                authority,
                entrypoints,
                dict(gatekeeper, source="Unnotarized Developer ID"),
            )

    def test_codesign_measurement_requires_hardened_runtime(self) -> None:
        responses = codesign_responses(TOOL, flags=MODULE.CS_REQUIRE_LV)
        with mock.patch.object(MODULE.subprocess, "run", side_effect=responses):
            with self.assertRaisesRegex(MODULE.Refused, r"missing the hardened runtime flag"):
                MODULE.codesign_record(TOOL, "arm64")

    def test_codesign_response_and_command_substitution_are_rejected(self) -> None:
        responses = codesign_responses(TOOL)
        responses[0] = subprocess.CompletedProcess(
            ["/private/tmp/substituted-codesign", "--verify"],
            0,
            stdout=b"",
            stderr=b"",
        )
        with mock.patch.object(MODULE.subprocess, "run", side_effect=responses):
            with self.assertRaisesRegex(MODULE.Refused, r"response substitution"):
                MODULE.codesign_record(TOOL, "arm64")

        responses = codesign_responses(TOOL)
        responses[1] = subprocess.CompletedProcess(
            responses[1].args,
            0,
            stdout=b"",
            stderr=codesign_detail(TOOL, architecture="x86_64"),
        )
        with mock.patch.object(MODULE.subprocess, "run", side_effect=responses):
            with self.assertRaisesRegex(MODULE.Refused, r"architecture response substitution"):
                MODULE.codesign_record(TOOL, "arm64")

        responses = codesign_responses(TOOL)
        responses[1] = subprocess.CompletedProcess(
            responses[1].args,
            0,
            stdout=b"",
            stderr=codesign_detail(Path("/private/tmp/substituted")),
        )
        with mock.patch.object(MODULE.subprocess, "run", side_effect=responses):
            with self.assertRaisesRegex(MODULE.Refused, r"response substitution"):
                MODULE.codesign_record(TOOL, "arm64")

    def test_absent_or_ambiguous_codesign_flags_are_rejected(self) -> None:
        responses = codesign_responses(TOOL)
        detail = b"\n".join(
            line
            for line in codesign_detail(TOOL).splitlines()
            if not line.startswith(b"CodeDirectory ")
        ) + b"\n"
        responses[1] = subprocess.CompletedProcess(
            responses[1].args, 0, stdout=b"", stderr=detail
        )
        with mock.patch.object(MODULE.subprocess, "run", side_effect=responses):
            with self.assertRaisesRegex(MODULE.Refused, r"flags are incomplete"):
                MODULE.codesign_record(TOOL, "arm64")

        responses = codesign_responses(TOOL)
        duplicate = codesign_detail(TOOL) + f"CDHash={'cd' * 20}\n".encode("ascii")
        responses[1] = subprocess.CompletedProcess(
            responses[1].args, 0, stdout=b"", stderr=duplicate
        )
        with mock.patch.object(MODULE.subprocess, "run", side_effect=responses):
            with self.assertRaisesRegex(MODULE.Refused, r"duplicate cdhash"):
                MODULE.codesign_record(TOOL, "arm64")

    def test_codesign_output_is_bounded_and_warning_state_is_rejected(self) -> None:
        responses = codesign_responses(TOOL)
        responses[1] = subprocess.CompletedProcess(
            responses[1].args,
            0,
            stdout=b"",
            stderr=b"X" * (MODULE.MAX_CODESIGN_OUTPUT + 1),
        )
        with mock.patch.object(MODULE.subprocess, "run", side_effect=responses):
            with self.assertRaisesRegex(MODULE.Refused, r"exceeds the size limit"):
                MODULE.codesign_record(TOOL, "arm64")

        responses = codesign_responses(TOOL)
        responses[3] = subprocess.CompletedProcess(
            responses[3].args,
            0,
            stdout=b"",
            stderr=responses[3].stderr + b"warning: invalid entitlements blob\n",
        )
        with mock.patch.object(MODULE.subprocess, "run", side_effect=responses):
            with self.assertRaisesRegex(MODULE.Refused, r"entitlements output.*ambiguous"):
                MODULE.codesign_record(TOOL, "arm64")

    def test_codesign_measurement_rejects_each_forbidden_entitlement(self) -> None:
        required = (
            "com.apple.security.get-task-allow",
            "com.apple.security.cs.debugger",
            "com.apple.security.cs.disable-library-validation",
            "com.apple.security.cs.allow-dyld-environment-variables",
            "com.apple.security.cs.disable-executable-page-protection",
        )
        for entitlement in required:
            with self.subTest(entitlement=entitlement):
                plist = plistlib.dumps(
                    {entitlement: True}, fmt=plistlib.FMT_XML, sort_keys=True
                )
                responses = codesign_responses(TOOL, entitlements=plist)
                with mock.patch.object(MODULE.subprocess, "run", side_effect=responses):
                    with self.assertRaisesRegex(MODULE.Refused, r"forbidden entitlement"):
                        MODULE.codesign_record(TOOL, "arm64")

    def test_installed_release_python_3_14_7_live_codesign_streams(self) -> None:
        installed = Path(MODULE.DEFAULT_RUNTIME) / MODULE.EXECUTABLE_RELATIVE
        if sys.platform != "darwin" or not installed.is_file():
            self.skipTest("installed ReleasePython 3.14.7 is unavailable")
        for architecture in ("arm64", "x86_64"):
            argv = [
                MODULE.CODESIGN,
                "--display",
                "--architecture",
                architecture,
                "--requirements",
                "-",
                str(installed),
            ]
            with self.subTest(architecture=architecture):
                completed = MODULE._run_codesign(
                    argv, label="codesign requirement"
                )
                self.assertEqual(completed.returncode, 0)
                self.assertEqual(completed.stdout, CAPTURED_REQUIREMENT_STDOUT)
                self.assertEqual(completed.stderr, CAPTURED_REQUIREMENT_STDERR)
                entitlement = MODULE._run_codesign(
                    [
                        MODULE.CODESIGN,
                        "--display",
                        "--architecture",
                        architecture,
                        "--entitlements",
                        "-",
                        "--xml",
                        str(installed),
                    ],
                    label="codesign entitlements",
                )
                self.assertEqual(entitlement.returncode, 0)
                self.assertIn(entitlement.stdout, CAPTURED_ENTITLEMENTS_STDOUTS)
                self.assertEqual(entitlement.stderr, CAPTURED_REQUIREMENT_STDERR)
                self.assertEqual(
                    MODULE.parse_codesign_entitlements(entitlement.stdout),
                    MODULE.REQUIRED_EXECUTABLE_ENTITLEMENTS,
                )
                record = MODULE.codesign_record(installed, architecture)
                self.assertEqual(
                    record["codesign_requirement"], CAPTURED_REQUIREMENT
                )
                self.assertEqual(
                    record["codesign_entitlements"],
                    MODULE.REQUIRED_EXECUTABLE_ENTITLEMENTS,
                )

    def test_installed_release_python_3_14_7_live_entrypoint_slices(self) -> None:
        runtime = Path(MODULE.DEFAULT_RUNTIME)
        installed = runtime / MODULE.EXECUTABLE_RELATIVE
        if sys.platform != "darwin" or not installed.is_file():
            self.skipTest("installed ReleasePython 3.14.7 is unavailable")
        records = MODULE.codesign_entrypoint_records(runtime)
        self.assertEqual(len(records), len(MODULE.AUTHORITY_CODE_SLICES))
        for record in records:
            self.assertEqual(
                record["codesign_entitlements"],
                MODULE.REQUIRED_EXECUTABLE_ENTITLEMENTS,
            )
            self.assertEqual(record["codesign_flags"], MODULE.CS_RUNTIME)
        self.assertEqual(
            MODULE.gatekeeper_assessment(
                runtime,
                expected_origin=CAPTURED_GATEKEEPER_ORIGIN,
            ),
            {
                "origin": CAPTURED_GATEKEEPER_ORIGIN,
                "relative_path": MODULE.PYTHON_APP_RELATIVE,
                "source": MODULE.REQUIRED_GATEKEEPER_SOURCE,
            },
        )

    def test_owner_action_is_fixed_and_external(self) -> None:
        action = MODULE.owner_provision_action(ROOT / "tools" / "toolchain-pins.json")
        self.assertEqual(action, MODULE.OWNER_PROVISION_ACTION)
        self.assertIn(str(MODULE.OWNER_PROVISION_BOUNDARY), action)
        self.assertNotIn(str(ROOT), action)
        self.assertNotIn("sudo", action.lower())


if __name__ == "__main__":
    unittest.main()
