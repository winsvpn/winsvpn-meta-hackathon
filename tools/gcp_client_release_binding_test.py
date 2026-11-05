#!/usr/bin/env python3
"""Fail-closed tests for exact Linux GCP client release provenance."""

from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import os
import pathlib
import struct
import sys
import tempfile
import types
import unittest
from unittest import mock


SCRIPT = pathlib.Path(__file__).with_name("gcp_client_release_binding.py")
SPEC = importlib.util.spec_from_file_location("gcp_client_release_binding", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
BASE_MODULE = MODULE

REAL_PIN_PATH = pathlib.Path(__file__).with_name("toolchain-pins.json")
REAL_GENERATED_PIN = (
    pathlib.Path(__file__).with_name("gcp_proof_client") / "gcloud_pin_generated.go"
)
REAL_GENERATOR_PATH = pathlib.Path(__file__).with_name("generate_gcloud_go_pin.py")
ISOLATED_IMPORT_NAMES = (
    "build_gcp_proof_client",
    "release_dependency_freeze",
    "release_source_freeze",
)


def _load_binding_from_repo(repo: pathlib.Path) -> types.ModuleType:
    """Load the binding and builder from the exact temporary repository bytes."""

    tools = repo / "tools"
    script = tools / "gcp_client_release_binding.py"
    module_name = f"gcp_client_release_binding_fixture_{id(repo):x}"
    preserved = {name: sys.modules.get(name) for name in ISOLATED_IMPORT_NAMES}
    sys.path.insert(0, os.fspath(tools))
    try:
        for name in ISOLATED_IMPORT_NAMES:
            sys.modules.pop(name, None)
        spec = importlib.util.spec_from_file_location(module_name, script)
        if spec is None or spec.loader is None:
            raise AssertionError("temporary release binding has no source loader")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(os.fspath(tools))
        for name, previous in preserved.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous


def _linux_amd64_elf(payload: bytes = b"proof-client") -> bytes:
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4:8] = b"\x02\x01\x01\x00"
    struct.pack_into("<HHI", header, 16, 2, 62, 1)
    struct.pack_into("<H", header, 52, 64)
    return bytes(header) + payload


def _encode_ed25519_point(point: tuple[int, int, int, int]) -> bytes:
    x, y, z, _t = point
    inverse = pow(z, MODULE._ED25519_P - 2, MODULE._ED25519_P)
    affine_x = x * inverse % MODULE._ED25519_P
    affine_y = y * inverse % MODULE._ED25519_P
    encoded = affine_y | ((affine_x & 1) << 255)
    return encoded.to_bytes(32, "little")


def _sign_ed25519(seed: bytes, message: bytes) -> tuple[bytes, bytes]:
    expanded = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(expanded[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    public_key = _encode_ed25519_point(
        MODULE._ed25519_mul(MODULE._ED25519_BASE, scalar)
    )
    nonce = int.from_bytes(
        hashlib.sha512(expanded[32:] + message).digest(), "little"
    ) % MODULE._ED25519_L
    encoded_nonce = _encode_ed25519_point(
        MODULE._ed25519_mul(MODULE._ED25519_BASE, nonce)
    )
    challenge = int.from_bytes(
        hashlib.sha512(encoded_nonce + public_key + message).digest(), "little"
    ) % MODULE._ED25519_L
    signature_scalar = (nonce + challenge * scalar) % MODULE._ED25519_L
    return public_key, encoded_nonce + signature_scalar.to_bytes(32, "little")


class ClientReleaseBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        global MODULE
        MODULE = BASE_MODULE
        self.addCleanup(self._restore_base_module)
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temporary.name).resolve()
        self._write("pubspec.yaml", "name: wins_vpn\nversion: 1.0.15+30\n")
        self._write("pubspec.lock", "packages: {}\n")
        self._write("lib/main.dart", "void main() {}\n")
        self._write(
            "tools/gcp_proof_client/go.mod",
            "module winsvpn.local/gcpproofclient\n\ngo 1.27.1\n",
        )
        self._write("tools/gcp_proof_client/main.go", "package main\nfunc main() {}\n")
        self._write("tools/gcp_proof_client/main_test.go", "package main\n")
        self._write("tools/gcp_proof_client/gcloud_custody.go", "package main\n")
        self._write("tools/gcp_proof_client/gcloud_custody_test.go", "package main\n")
        for platform, roots in MODULE.freeze.PLATFORM_ROOTS.items():
            for root in roots:
                self._write(f"{root}/{platform}-input.txt", f"{platform}\n")
        for platform, paths in MODULE.freeze.PLATFORM_NATIVE_EXTRA_PATHS.items():
            for path in paths:
                self._write(path, f"{platform} extra input\n")
        for alias, target in MODULE.freeze.WINDOWS_NATIVE_HOST_LIB_SYMLINK_ALIASES:
            alias_path = self.repo / alias
            target_path = (alias_path.parent / target).resolve()
            target_relative = target_path.relative_to(self.repo.resolve()).as_posix()
            self._write(
                target_relative,
                f"native host shared input: {target_relative}\n",
            )
            alias_path.parent.mkdir(parents=True, exist_ok=True)
            alias_path.symlink_to(target)
        for paths in MODULE.freeze.PLATFORM_PRODUCER_PATHS.values():
            for path in paths:
                self._write(path, f"producer: {path}\n")
        for path in MODULE.freeze.PLATFORM_BUILD_PRODUCERS.values():
            self._write(path, f"build producer: {path}\n")
        reviewed_sources = (
            "tools/gcp_client_release_binding.py",
            BASE_MODULE.proof_builder.BUILDER_PATH,
            *BASE_MODULE.proof_builder.REVIEWED_SUPPORT_INPUTS,
        )
        for relative in reviewed_sources:
            self._write_bytes(relative, (SCRIPT.parent.parent / relative).read_bytes())
        fixture_freeze = self.repo / "tools/release_dependency_freeze.py"
        fixture_freeze.write_bytes(
            fixture_freeze.read_bytes()
            + b"\n# Isolated fixture mode cannot authorize publication.\n"
            + b"_FIXTURE_MODE = True\n"
        )
        pin_path = self.repo / "tools/toolchain-pins.json"
        pin_path.parent.mkdir(parents=True, exist_ok=True)
        pin_document = json.loads(REAL_PIN_PATH.read_bytes())
        go_pin = pin_document["tools"]["go"]
        go_pin["install_tree_sha256"]["linux_amd64"] = "c" * 64
        go_pin["executable_sha256"] = {
            "darwin_arm64": go_pin["executable_sha256"],
            "linux_amd64": "d" * 64,
        }
        go_pin["platform"] = "linux-amd64"
        pin_path.write_text(
            json.dumps(pin_document, indent=2, sort_keys=True) + "\n",
            encoding="ascii",
        )
        self._write_bytes(
            "tools/gcp_proof_client/gcloud_pin_generated.go",
            REAL_GENERATED_PIN.read_bytes(),
        )

        MODULE = _load_binding_from_repo(self.repo)

        self.freeze_dir = self.repo / ".artifacts" / "freeze"
        shared = self.freeze_dir / "SHARED_INPUTS.json"
        MODULE.freeze.create_shared_manifest(self.repo, shared, "shared-linux-proof")
        for platform in MODULE.freeze.PLATFORM_ROOTS:
            MODULE.freeze.create_platform_manifest(
                self.repo,
                platform,
                shared,
                self.freeze_dir / f"{platform.upper()}_INPUTS.json",
            )
        self.index = self.freeze_dir / "RELEASE_INPUT_INDEX.json"
        MODULE.freeze.create_release_index(self.repo, self.freeze_dir, self.index)

        self.receipt = self.freeze_dir / "LINUX_BUILD_RECEIPT.json"
        self.artifact = (
            self.repo
            / "build"
            / "linux"
            / "x64"
            / "winsvpn-gcp-proof-client-linux-amd64"
        )
        self.artifact.parent.mkdir(parents=True, exist_ok=True)
        self.artifact.write_bytes(_linux_amd64_elf())
        self.artifact.chmod(0o555)
        provenance = MODULE.proof_builder.expected_provenance(
            self.repo, self.index, MODULE.PROOF_CLIENT_TARGET
        )
        artifact_data = self.artifact.read_bytes()
        receipt = {
            "artifact": {
                "bytes": len(artifact_data),
                "mode": "0555",
                "path": self.artifact.relative_to(self.repo).as_posix(),
                "sha256": hashlib.sha256(artifact_data).hexdigest(),
            },
            "build_contract": provenance["build_contract"],
            "build_identity": provenance["build_identity"],
            "builder": provenance["builder"],
            "contract": MODULE.proof_builder.RECEIPT_CONTRACT,
            "defines": provenance["defines"],
            "publication_authorized": False,
            "release": provenance["release"],
            "release_input_index": provenance["release_input_index"],
            "schema_version": MODULE.proof_builder.SCHEMA_VERSION,
            "shared_revision": provenance["shared_revision"],
            "source": provenance["source"],
            "target": provenance["target"],
            "toolchain": provenance["toolchain"],
            "toolchain_pin_manifest": provenance["toolchain_pin_manifest"],
        }
        self.receipt.write_bytes(MODULE.proof_builder.canonical_bytes(receipt))
        self._reanchor(self.receipt)
        self.authority_data = b""
        self.authorization_data = b""
        self._refresh_authorization()
        authorization_patch = mock.patch.object(
            MODULE,
            "_load_owner_authorization_documents",
            side_effect=lambda _repo: (
                self.authority_data,
                self.authorization_data,
            ),
        )
        authorization_patch.start()
        self.addCleanup(authorization_patch.stop)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _restore_base_module() -> None:
        global MODULE
        MODULE = BASE_MODULE

    def _write(self, relative: str, contents: str) -> pathlib.Path:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
        return path

    def _write_bytes(self, relative: str, contents: bytes) -> pathlib.Path:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
        return path

    def _held_builder_paths(self) -> tuple[str, ...]:
        return (
            *MODULE.proof_builder.SOURCE_PATHS,
            MODULE.proof_builder.BUILDER_PATH,
            MODULE.proof_builder.PIN_PATH,
            self.index.relative_to(self.repo).as_posix(),
        )

    @staticmethod
    def _reanchor(path: pathlib.Path) -> None:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        anchor = path.with_name(path.name + ".sha256")
        if anchor.exists():
            anchor.chmod(0o600)
        anchor.write_text(
            f"{digest}  {path.name}\n", encoding="ascii"
        )

    def _rewrite_json(self, path: pathlib.Path, mutate: object) -> None:
        record = json.loads(path.read_text(encoding="utf-8"))
        assert isinstance(record, dict)
        mutate(record)  # type: ignore[operator]
        path.chmod(0o600)
        path.write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        self._reanchor(path)

    def _refresh_authorization(
        self,
        *,
        issued_offset: dt.timedelta = dt.timedelta(0),
        expires_offset: dt.timedelta = dt.timedelta(hours=1),
        seed: bytes = b"\x11" * 32,
    ) -> None:
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        issued = now + issued_offset
        expires = now + expires_offset
        receipt = json.loads(self.receipt.read_bytes())
        artifact_data = self.artifact.read_bytes()
        payload = {
            "artifact_bytes": len(artifact_data),
            "artifact_name": self.artifact.name,
            "artifact_sha256": hashlib.sha256(artifact_data).hexdigest(),
            "authorization_id": "1" * 32,
            "build_identity": receipt["build_identity"],
            "build_receipt_sha256": hashlib.sha256(
                self.receipt.read_bytes()
            ).hexdigest(),
            "contract": MODULE.ARTIFACT_AUTHORIZATION_CONTRACT,
            "expires_utc": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "issued_utc": issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "purpose": "gcp-proof-client-execution",
            "release": receipt["release"],
            "release_input_index_sha256": hashlib.sha256(
                self.index.read_bytes()
            ).hexdigest(),
            "schema_version": 1,
            "shared_revision": receipt["shared_revision"],
            "source_sha256": receipt["source"]["sha256"],
            "target": "linux/amd64",
        }
        public_key, signature = _sign_ed25519(
            seed, MODULE.OWNER_SIGNATURE_DOMAIN + MODULE.canonical_bytes(payload)
        )
        key_id = hashlib.sha256(public_key).hexdigest()
        authority = {
            "algorithm": MODULE.OWNER_ALGORITHM,
            "contract": MODULE.OWNER_AUTHORITY_CONTRACT,
            "key_id": key_id,
            "owner_uid": 0,
            "public_key": public_key.hex(),
            "schema_version": 1,
        }
        issuance = {
            "algorithm": MODULE.OWNER_ALGORITHM,
            "authorization": payload,
            "contract": MODULE.OWNER_AUTHORIZATION_CONTRACT,
            "issuer": MODULE.OWNER_ISSUER,
            "key_id": key_id,
            "schema_version": 1,
            "signature": signature.hex(),
        }
        self.authority_data = MODULE.canonical_bytes(authority)
        self.authorization_data = MODULE.canonical_bytes(issuance)

    def _verify(self, **overrides: object) -> dict[str, object]:
        return MODULE.verify_client_release(
            overrides.get("repo", self.repo),  # type: ignore[arg-type]
            overrides.get("index", self.index),  # type: ignore[arg-type]
            overrides.get("receipt", self.receipt),  # type: ignore[arg-type]
            overrides.get("artifact", self.artifact),  # type: ignore[arg-type]
            platform=str(overrides.get("platform", "linux")),
        )

    def test_valid_binding_is_exact_derived_and_canonical_ascii(self) -> None:
        result = self._verify()
        artifact_sha = hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        self.assertEqual(result["schema_version"], 3)
        self.assertEqual(result["contract"], MODULE.CONTRACT)
        self.assertEqual(result["platform"], "linux")
        self.assertEqual(
            result["build_identity"],
            f"linux:1.0.15+30:{result['proof_build']['build_identity']}",  # type: ignore[index]
        )
        self.assertEqual(
            result["proof_build"]["defines"]["release"],  # type: ignore[index]
            "1.0.15+30",
        )
        self.assertEqual(
            result["artifact"]["sha256"], artifact_sha  # type: ignore[index]
        )
        self.assertEqual(
            result["artifact"]["bytes"],  # type: ignore[index]
            self.artifact.stat().st_size,
        )
        proof_build = result["proof_build"]  # type: ignore[assignment]
        self.assertEqual(
            proof_build["build_contract"]["contract"],  # type: ignore[index]
            "winsvpn-gcp-proof-client-build-contract-v5",
        )
        self.assertEqual(
            proof_build["source"]["contract"],  # type: ignore[index]
            "winsvpn-gcp-proof-client-source-v4",
        )
        source_paths = {
            item["path"]
            for item in proof_build["source"]["compiler_inputs"]  # type: ignore[index]
        }
        self.assertIn("tools/gcp_proof_client/gcloud_custody.go", source_paths)
        self.assertIn("tools/gcp_proof_client/gcloud_custody_test.go", source_paths)
        self.assertIn("tools/gcp_proof_client/gcloud_pin_generated.go", source_paths)
        support_paths = {
            item["path"]
            for item in proof_build["source"]["reviewed_support"]  # type: ignore[index]
        }
        self.assertIn("tools/create_gcloud_custody_receipt.py", support_paths)
        self.assertIn("tools/release_go_archive_custody.py", support_paths)
        self.assertEqual(
            proof_build["toolchain"]["custody"],  # type: ignore[index]
            "root-owned-immutable-runtime",
        )
        self.assertEqual(proof_build["target"], MODULE.PROOF_CLIENT_TARGET)
        encoded = MODULE.canonical_bytes(result)
        self.assertTrue(encoded.isascii())
        self.assertTrue(encoded.endswith(b"\n"))
        self.assertNotIn(b" ", encoded)
        self.assertEqual(json.loads(encoded), result)

    def test_wrong_platform_is_refused(self) -> None:
        with self.assertRaisesRegex(
            MODULE.ClientReleaseBindingError, "must be linux"
        ):
            self._verify(platform="windows")

    def test_missing_index_receipt_artifact_or_anchor_is_refused(self) -> None:
        cases = (
            ("index", self.repo / ".artifacts/freeze/MISSING_INDEX.json"),
            ("receipt", self.repo / ".artifacts/freeze/MISSING_RECEIPT.json"),
            ("artifact", self.repo / "build/linux/x64/missing"),
        )
        for key, path in cases:
            with self.subTest(key=key), self.assertRaises(
                MODULE.ClientReleaseBindingError
            ):
                self._verify(**{key: path})
        self.index.with_name(self.index.name + ".sha256").unlink()
        with self.assertRaises(MODULE.ClientReleaseBindingError):
            self._verify()

    def test_traversal_and_outside_paths_are_refused(self) -> None:
        traversal = (
            self.artifact.parent
            / ".."
            / self.artifact.parent.name
            / self.artifact.name
        )
        with self.assertRaisesRegex(
            MODULE.ClientReleaseBindingError, "without traversal"
        ):
            self._verify(artifact=traversal)
        outside = pathlib.Path(self.temporary.name).parent / "outside-probe"
        outside.write_bytes(b"outside")
        self.addCleanup(lambda: outside.unlink(missing_ok=True))
        with self.assertRaisesRegex(
            MODULE.ClientReleaseBindingError, "inside the repository"
        ):
            self._verify(artifact=outside.resolve())

    def test_symlink_and_hardlink_inputs_are_refused(self) -> None:
        symlink = self.artifact.with_name("probe-symlink")
        try:
            symlink.symlink_to(self.artifact)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks are unavailable")
        with self.assertRaises(MODULE.ClientReleaseBindingError):
            self._verify(artifact=symlink)
        symlink.unlink()

        hardlink = self.artifact.with_name("probe-hardlink")
        try:
            os.link(self.artifact, hardlink)
        except OSError:
            self.skipTest("Hardlinks are unavailable")
        with self.assertRaisesRegex(
            MODULE.ClientReleaseBindingError, "single-link"
        ):
            self._verify(artifact=self.artifact)

    def test_non_executable_or_writable_probe_is_refused(self) -> None:
        self.artifact.chmod(0o644)
        with self.assertRaisesRegex(MODULE.ClientReleaseBindingError, "executable"):
            self._verify()
        self.artifact.chmod(0o777)
        with self.assertRaisesRegex(MODULE.ClientReleaseBindingError, "writable"):
            self._verify()

    def test_altered_artifact_receipt_and_stale_index_are_refused(self) -> None:
        self.artifact.chmod(0o755)
        self.artifact.write_bytes(b"altered executable\n")
        self.artifact.chmod(0o555)
        with self.assertRaises(MODULE.ClientReleaseBindingError):
            self._verify()

    def test_altered_receipt_is_refused(self) -> None:
        self._rewrite_json(
            self.receipt, lambda record: record.__setitem__("release", "9.9.9+9")
        )
        with self.assertRaises(MODULE.ClientReleaseBindingError):
            self._verify()

    def test_stale_index_is_refused(self) -> None:
        self._write("linux/linux-input.txt", "linux source changed\n")
        with self.assertRaises(MODULE.ClientReleaseBindingError):
            self._verify()

    def test_duplicate_json_keys_are_refused_before_freeze_validation(self) -> None:
        text = self.index.read_text(encoding="utf-8")
        self.assertIn('"schema_version": 1,', text)
        self.index.chmod(0o600)
        self.index.write_text(
            text.replace(
                '"schema_version": 1,',
                '"schema_version": 1,\n  "schema_version": 1,',
                1,
            ),
            encoding="utf-8",
        )
        self._reanchor(self.index)
        with self.assertRaisesRegex(
            MODULE.ClientReleaseBindingError, "Duplicate JSON key"
        ):
            self._verify()

    def test_unknown_key_in_receipt_is_refused(self) -> None:
        self._rewrite_json(
            self.receipt, lambda record: record.__setitem__("unexpected", True)
        )
        with self.assertRaisesRegex(
            MODULE.ClientReleaseBindingError, "unknown keys"
        ):
            self._verify()

    def test_unknown_key_in_index_is_refused(self) -> None:
        self._rewrite_json(
            self.index, lambda record: record.__setitem__("unexpected", True)
        )
        with self.assertRaisesRegex(
            MODULE.ClientReleaseBindingError, "unknown keys"
        ):
            self._verify()

    def test_old_receipt_schema_is_refused(self) -> None:
        self._rewrite_json(
            self.receipt, lambda record: record.__setitem__("schema_version", 0)
        )
        with self.assertRaisesRegex(
            MODULE.ClientReleaseBindingError, "unsupported"
        ):
            self._verify()

    def test_old_index_schema_is_refused(self) -> None:
        self._rewrite_json(
            self.index, lambda record: record.__setitem__("schema_version", 0)
        )
        with self.assertRaisesRegex(
            MODULE.ClientReleaseBindingError, "unsupported"
        ):
            self._verify()

    def test_exact_index_not_semantic_carry_forward_is_required(self) -> None:
        other = self.repo / ".artifacts" / "equivalent"
        shared = other / "SHARED_INPUTS.json"
        MODULE.freeze.create_shared_manifest(
            self.repo, shared, "shared-linux-proof"
        )
        for platform in MODULE.freeze.PLATFORM_ROOTS:
            MODULE.freeze.create_platform_manifest(
                self.repo,
                platform,
                shared,
                other / f"{platform.upper()}_INPUTS.json",
            )
        equivalent_index = other / "RELEASE_INPUT_INDEX.json"
        MODULE.freeze.create_release_index(self.repo, other, equivalent_index)
        self.assertTrue(
            MODULE.freeze.verify_release_index(
                self.repo, equivalent_index, "linux"
            )["ok"]
        )
        with self.assertRaisesRegex(
            MODULE.ClientReleaseBindingError, "exact supplied"
        ):
            self._verify(index=equivalent_index)

    def test_mutation_during_verification_is_refused(self) -> None:
        original = MODULE.freeze.verify_release_index

        def mutate_then_verify(*args: object, **kwargs: object) -> dict[str, object]:
            result = original(*args, **kwargs)  # type: ignore[arg-type]
            self.artifact.chmod(0o755)
            self.artifact.write_bytes(b"changed during verification\n")
            self.artifact.chmod(0o555)
            return result

        with mock.patch.object(
            MODULE.freeze, "verify_release_index", side_effect=mutate_then_verify
        ), self.assertRaises(MODULE.ClientReleaseBindingError):
            self._verify()

    def test_prior_plaintext_artifact_is_refused_even_when_owner_authorized(self) -> None:
        plaintext = b"verified linux probe executable\n"
        self.artifact.chmod(0o755)
        self.artifact.write_bytes(plaintext)
        self.artifact.chmod(0o555)

        def bind_plaintext(record: dict[str, object]) -> None:
            artifact = record["artifact"]
            assert isinstance(artifact, dict)
            artifact["bytes"] = len(plaintext)
            artifact["sha256"] = hashlib.sha256(plaintext).hexdigest()

        self._rewrite_json(self.receipt, bind_plaintext)
        self._refresh_authorization()
        with self.assertRaisesRegex(
            MODULE.ClientReleaseBindingError, "not a Linux amd64 ELF64"
        ):
            self._verify()

    def test_missing_external_authorization_is_owner_blocked(self) -> None:
        with mock.patch.object(
            MODULE,
            "_load_owner_authorization_documents",
            side_effect=MODULE.ClientReleaseBindingError(
                MODULE.OWNER_BLOCKED_AUTHORIZATION
            ),
        ), self.assertRaisesRegex(
            MODULE.ClientReleaseBindingError, "OWNER-BLOCKED"
        ):
            self._verify()

    def test_caller_fabricated_authorization_signature_is_refused(self) -> None:
        issuance = json.loads(self.authorization_data)
        issuance["signature"] = "0" * 128
        self.authorization_data = MODULE.canonical_bytes(issuance)
        with self.assertRaisesRegex(
            MODULE.ClientReleaseBindingError, "signature is invalid"
        ):
            self._verify()

    def test_authorization_for_other_artifact_or_receipt_is_refused(self) -> None:
        for key in ("artifact_sha256", "build_receipt_sha256"):
            original = self.authorization_data
            issuance = json.loads(original)
            issuance["authorization"][key] = "a" * 64
            self.authorization_data = MODULE.canonical_bytes(issuance)
            try:
                with self.subTest(key=key), self.assertRaisesRegex(
                    MODULE.ClientReleaseBindingError, "does not bind exact"
                ):
                    self._verify()
            finally:
                self.authorization_data = original

    def test_stale_owner_authorization_is_refused(self) -> None:
        self._refresh_authorization(
            issued_offset=-dt.timedelta(hours=8),
            expires_offset=-dt.timedelta(hours=1),
        )
        with self.assertRaisesRegex(
            MODULE.ClientReleaseBindingError, "stale or future-dated"
        ):
            self._verify()

    def test_owner_authorization_change_during_binding_is_refused(self) -> None:
        calls = 0

        def changing_loader(_repo: pathlib.Path) -> tuple[bytes, bytes]:
            nonlocal calls
            calls += 1
            if calls == 1:
                return self.authority_data, self.authorization_data
            return self.authority_data, self.authorization_data + b"\n"

        with mock.patch.object(
            MODULE,
            "_load_owner_authorization_documents",
            side_effect=changing_loader,
        ), self.assertRaisesRegex(
            MODULE.ClientReleaseBindingError, "changed during verification"
        ):
            self._verify()

    def test_authorization_paths_are_fixed_not_caller_interfaces(self) -> None:
        actions = {action.dest for action in MODULE._parser()._actions}
        self.assertNotIn("artifact_authorization", actions)
        self.assertEqual(
            MODULE.OWNER_AUTHORITY_PATH,
            pathlib.Path("/var/lib/winsvpn/gcloud-owner-authority-v1.json"),
        )
        self.assertEqual(
            MODULE.OWNER_ARTIFACT_AUTHORIZATION_PATH,
            pathlib.Path(
                "/var/lib/winsvpn/gcp-proof-client-artifact-authorization-v1.json"
            ),
        )

    def test_hardlinked_index_is_refused(self) -> None:
        link = self.index.with_name("INDEX_HARDLINK.json")
        try:
            os.link(self.index, link)
        except OSError:
            self.skipTest("Hardlinks are unavailable")
        with self.assertRaisesRegex(
            MODULE.ClientReleaseBindingError, "single-link"
        ):
            self._verify()

    def test_temp_pin_copy_cannot_self_authorize_production_bind(self) -> None:
        fixture_pin = self.repo / "tools/toolchain-pins.json"
        fixture_document = json.loads(fixture_pin.read_bytes())
        real_document = json.loads(REAL_PIN_PATH.read_bytes())
        self.assertEqual(
            fixture_document["tools"]["google_cloud_cli"],
            real_document["tools"]["google_cloud_cli"],
        )
        self.assertNotEqual(fixture_pin.read_bytes(), REAL_PIN_PATH.read_bytes())
        with MODULE.proof_builder._DescriptorRepoInputs(
            self.repo, self._held_builder_paths()
        ):
            custody = MODULE.proof_builder.gcloud_custody
            with self.assertRaisesRegex(custody.GcloudCustodyError, "trust|owner"):
                custody.validate_google_cloud_cli_pin(fixture_pin)

    def test_import_time_fake_generator_cannot_become_pin_authority(self) -> None:
        builder = MODULE.proof_builder
        fake = types.ModuleType("generate_gcloud_go_pin")
        fake_calls: list[pathlib.Path | None] = []

        def fake_render(pin: pathlib.Path | None = None) -> str:
            fake_calls.append(pin)
            return "package main\nconst hostile = true\n"

        fake.render = fake_render  # type: ignore[attr-defined]
        previous = sys.modules.get("generate_gcloud_go_pin")
        sys.modules["generate_gcloud_go_pin"] = fake
        builder.gcloud_pin_generator = fake
        try:
            with builder._DescriptorRepoInputs(
                self.repo, self._held_builder_paths()
            ) as inputs:
                reviewed = builder.gcloud_pin_generator
                self.assertIsNot(reviewed, fake)
                self.assertEqual(
                    inputs.bytes("tools/generate_gcloud_go_pin.py"),
                    REAL_GENERATOR_PATH.read_bytes(),
                )
                self.assertEqual(
                    reviewed.__winsvpn_file_ref__,  # type: ignore[union-attr]
                    inputs.ref("tools/generate_gcloud_go_pin.py"),
                )
                self.assertTrue(callable(reviewed.render))  # type: ignore[union-attr]
                with self.assertRaisesRegex(
                    reviewed.gcloud_custody.GcloudCustodyError,  # type: ignore[union-attr]
                    "trust|owner",
                ):
                    reviewed.render(  # type: ignore[union-attr]
                        self.repo / "tools/toolchain-pins.json"
                    )
                builder._verify_generated_gcloud_pin(self.repo, inputs)
                self.assertEqual(fake_calls, [])
        finally:
            builder.gcloud_pin_generator = None
            if previous is None:
                sys.modules.pop("generate_gcloud_go_pin", None)
            else:
                sys.modules["generate_gcloud_go_pin"] = previous

    def test_synthetic_google_cloud_cli_pin_is_refused(self) -> None:
        pin_path = self.repo / "tools/toolchain-pins.json"
        record = json.loads(pin_path.read_text(encoding="utf-8"))
        assert isinstance(record, dict)
        tools = record["tools"]
        assert isinstance(tools, dict)
        pin = tools["google_cloud_cli"]
        assert isinstance(pin, dict)
        hashes = pin["archive_sha256"]
        assert isinstance(hashes, dict)
        hashes["linux_amd64"] = "d" * 64
        pin_path.write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        with MODULE.proof_builder._DescriptorRepoInputs(
            self.repo, self._held_builder_paths()
        ) as inputs, self.assertRaisesRegex(
            MODULE.proof_builder.ProofBuildError,
            "does not match the independent platform pin",
        ):
            MODULE.proof_builder._verify_generated_gcloud_pin(self.repo, inputs)


if __name__ == "__main__":
    unittest.main()
