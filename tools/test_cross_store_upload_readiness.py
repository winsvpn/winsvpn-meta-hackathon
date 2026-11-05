#!/usr/bin/env python3
"""Tests for exact, fail-closed cross-store upload readiness."""

from __future__ import annotations

import datetime as dt
import dataclasses
import gzip
import hashlib
import importlib.util
import io
import json
import lzma
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock
import zipfile


TOOLS = pathlib.Path(__file__).resolve().parent
ROOT = TOOLS.parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import cross_store_upload_readiness as readiness
import cross_store_gate_runner as gate_runner
import cross_store_target_receipt as receipt_producer
import release_dependency_freeze as freeze
import release_source_freeze as source_freeze


class FakeExplicitArgvRunner:
    TEST_ONLY = True

    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.results: list[gate_runner.GateProcessResult] = []

    def run(
        self, argv: tuple[str, ...], *, cwd: pathlib.Path
    ) -> gate_runner.GateProcessResult:
        exact = tuple(argv)
        self.calls.append(exact)
        if self.results:
            result = self.results.pop(0)
            if result.argv != ("true",):
                result = dataclasses.replace(result, argv=exact)
            return result
        return gate_runner.GateProcessResult(
            argv=exact,
            stdout="verified " + " ".join(exact),
            stderr="",
            exit_code=0,
            executed=True,
            runner_id=gate_runner.SubprocessExplicitArgvRunner.RUNNER_ID,
            shell_enabled=False,
        )


class ExternalSourceFreezeTestIssuance:
    """Source-freeze test-contract issuance outside the candidate repository.

    Structurally test-only: it cannot emit accepted production PASS and must not
    use or mutate the real owner issuance beside release_source_freeze.py.
    """

    TEST_ONLY = True
    _WRITABLE = stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH

    def __init__(self) -> None:
        self._restored = False
        self._saved_external_trust_path = source_freeze._EXTERNAL_TRUST_PATH
        self._saved_tree_hook = source_freeze._POST_TREE_CAPTURE_HOOK
        self._saved_directory_hook = source_freeze._POST_DIRECTORY_BIND_HOOK
        self._saved_final_hook = source_freeze._POST_FINAL_CAPTURE_HOOK
        self._captured_trust_path = True
        self._owner_issue = None
        self.trust_temp: tempfile.TemporaryDirectory | None = None
        self.parent: pathlib.Path | None = None
        self.path: pathlib.Path | None = None
        self.lock_path: pathlib.Path | None = None
        self.scope_path: pathlib.Path | None = None
        self.issuance_id = "a" * 32
        self.created_utc = source_freeze._utc_now_text()
        self.file_identity: tuple[int, ...] | None = None
        self.parent_identity: tuple[int, ...] | None = None
        self.app_source_lock_sha256 = ""
        self.scope_freeze_sha256 = ""

    def production_pass_allowed(self) -> bool:
        return False

    def install(self, repo: pathlib.Path) -> None:
        if self.production_pass_allowed() or self.TEST_ONLY is not True:
            raise AssertionError("test-only issuance cannot emit production PASS")
        repo = repo.resolve()
        release = freeze._release_identity(repo)
        freeze_dir = repo / freeze._freeze_metadata_relative(release)
        freeze_dir.mkdir(parents=True, exist_ok=True)
        digest = "0" * 64
        self.scope_path = freeze_dir / freeze.SCOPE_FREEZE_NAME
        scope = {
            "schema_version": 1,
            "contract": source_freeze.SCOPE_CONTRACT,
            "release": release,
            "scope_frozen": True,
            "source_fingerprint_sha256": digest,
            "publication_locked": True,
            "issuance_id": self.issuance_id,
            "created_utc": self.created_utc,
        }
        self.scope_path.write_text(
            json.dumps(scope, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.scope_freeze_sha256 = hashlib.sha256(
            self.scope_path.read_bytes()
        ).hexdigest()
        self.lock_path = freeze_dir / freeze.APP_SOURCE_LOCK_NAME
        lock = {
            "schema_version": 1,
            "contract": freeze.APP_SOURCE_LOCK_CONTRACT,
            "release": release,
            "scope_frozen": True,
            "publication_locked": True,
            "scope_freeze_sha256": self.scope_freeze_sha256,
            "frozen_combined_source_fingerprint_sha256": digest,
            "frozen_combined_source_file_count": 1,
            "app_source_contract": freeze.APP_SOURCE_CONTRACT,
            "app_source_fingerprint_sha256": digest,
            "app_source_file_count": 1,
            "website_source_contract": freeze.WEBSITE_SOURCE_CONTRACT,
            "website_source_fingerprint_sha256_at_freeze": digest,
            "website_source_file_count_at_freeze": 0,
            "website_index_sha256_at_freeze": digest,
            "immutable_website_source_fingerprint_sha256_at_freeze": digest,
            "immutable_website_source_file_count_at_freeze": 0,
            "website_mutable_paths_after_scope_freeze": ["web/index.html"],
            "website_staging_allowed_after_scope_freeze": True,
            "issuance_id": self.issuance_id,
            "created_utc": self.created_utc,
        }
        self.lock_path.write_text(
            json.dumps(lock, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.app_source_lock_sha256 = hashlib.sha256(
            self.lock_path.read_bytes()
        ).hexdigest()
        self.trust_temp = tempfile.TemporaryDirectory(
            prefix="wins-cross-store-sf-trust-"
        )
        self.parent = pathlib.Path(self.trust_temp.name).resolve()
        self.path = self.parent / source_freeze.EXTERNAL_TRUST_NAME
        real_owner = pathlib.Path(source_freeze.__file__).resolve().with_name(
            source_freeze.EXTERNAL_TRUST_NAME
        )
        if self.path == real_owner or self.parent == real_owner.parent:
            raise AssertionError(
                "test-only issuance must not use the real owner issuance"
            )
        if self.path.is_relative_to(repo) or self.parent.is_relative_to(repo):
            raise AssertionError(
                "test-only issuance must live outside the candidate repository"
            )
        self.write_record(
            {
                "schema_version": 1,
                "contract": source_freeze.EXTERNAL_TRUST_CONTRACT,
                "release": release,
                "created_utc": self.created_utc,
                "issuance_id": self.issuance_id,
                "authenticated": True,
                "issuer": source_freeze.EXTERNAL_TRUST_ISSUER,
                "app_source_lock_sha256": self.app_source_lock_sha256,
                "scope_freeze_sha256": self.scope_freeze_sha256,
                "website_stage_sha256": None,
                "controller_sha256": hashlib.sha256(
                    pathlib.Path(source_freeze.__file__).resolve().read_bytes()
                ).hexdigest(),
                "test_sha256": hashlib.sha256(
                    (TOOLS / source_freeze.TEST_NAME).read_bytes()
                ).hexdigest(),
                "manifest_sha256": hashlib.sha256(
                    (TOOLS / source_freeze.TOOLCHAIN_PIN_NAME).read_bytes()
                ).hexdigest(),
            }
        )
        source_freeze._EXTERNAL_TRUST_PATH = str(self.path)

    def write_record(self, record: dict[str, object]) -> None:
        if self.path is None or self.parent is None:
            raise AssertionError("test-only issuance has no external path")
        self._unlock()
        if self.path.exists() or self.path.is_symlink():
            self.path.unlink()
        self.path.write_text(json.dumps(record), encoding="utf-8")
        self._lock()

    def stop_owner_issue_patch(self) -> None:
        if self._owner_issue is None:
            return
        try:
            self._owner_issue.stop()
        except RuntimeError:
            pass
        self._owner_issue = None

    def restore(self) -> None:
        if self._restored:
            return
        self._restored = True
        if self._captured_trust_path:
            source_freeze._EXTERNAL_TRUST_PATH = self._saved_external_trust_path
        source_freeze._POST_TREE_CAPTURE_HOOK = self._saved_tree_hook
        source_freeze._POST_DIRECTORY_BIND_HOOK = self._saved_directory_hook
        source_freeze._POST_FINAL_CAPTURE_HOOK = self._saved_final_hook
        self.stop_owner_issue_patch()
        try:
            if self.parent is not None and self.parent.is_dir():
                os.chmod(self.parent, 0o700)
            if self.path is not None and self.path.exists():
                os.chmod(self.path, 0o644)
        except OSError:
            pass
        if self.trust_temp is not None:
            self.trust_temp.cleanup()
            self.trust_temp = None

    def _unlock(self) -> None:
        if self.parent is None:
            return
        os.chmod(self.parent, 0o700)
        if self.path is not None and (self.path.exists() or self.path.is_symlink()):
            os.chmod(self.path, 0o644)

    def _lock(self) -> None:
        if self.path is None or self.parent is None:
            raise AssertionError("test-only issuance has no external path")
        os.chmod(self.path, 0o444)
        os.chmod(self.parent, 0o555)
        file_info = os.lstat(self.path)
        parent_info = os.lstat(self.parent)
        if file_info.st_mode & self._WRITABLE:
            raise AssertionError("test-only issuance file identity is writable")
        if parent_info.st_mode & self._WRITABLE:
            raise AssertionError("test-only issuance parent identity is writable")
        self.file_identity = source_freeze._identity(file_info)
        self.parent_identity = source_freeze._identity(parent_info)


class CrossStoreUploadReadinessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.bytecode_patch = mock.patch.object(sys, "dont_write_bytecode", True)
        self.bytecode_patch.start()
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temporary.name)
        self._write("pubspec.yaml", "name: wins_vpn\nversion: 1.0.17+34\n")
        self._write("pubspec.lock", "packages: {}\n")
        self._write("lib/main.dart", "void main() {}\n")
        identity_source = ROOT / "docs/rulings/RELEASE_IDENTITY_MAP_20260824.json"
        identity_destination = (
            self.repo / "docs/rulings/RELEASE_IDENTITY_MAP_20260824.json"
        )
        identity_destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(identity_source, identity_destination)
        for platform, roots in freeze.PLATFORM_ROOTS.items():
            for root in roots:
                self._write(f"{root}/{platform}-input.txt", f"{platform}\n")
        for platform, paths in freeze.PLATFORM_NATIVE_EXTRA_PATHS.items():
            for path in paths:
                self._write(path, f"{platform} extra input\n")
        for alias, target in freeze.WINDOWS_NATIVE_HOST_LIB_SYMLINK_ALIASES:
            alias_path = self.repo / alias
            target_path = (alias_path.parent / target).resolve()
            target_relative = target_path.relative_to(self.repo.resolve()).as_posix()
            self._write(target_relative, f"native host shared input: {target_relative}\n")
            alias_path.parent.mkdir(parents=True, exist_ok=True)
            alias_path.symlink_to(target)
        for paths in freeze.PLATFORM_PRODUCER_PATHS.values():
            for path in paths:
                self._write(path, f"producer: {path}\n")
        for path in freeze.PLATFORM_BUILD_PRODUCERS.values():
            self._write(path, f"build producer: {path}\n")
        for target in readiness.ALL_UPLOAD_TARGETS:
            for path in target.producer_ids:
                source = ROOT / path
                if target.manifest_verifier_path is not None:
                    destination = self.repo / path
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source, destination)
                else:
                    self._write(path, f"target producer: {path}\n")
        self._install_extension_verifier()
        for paths in readiness.GATE_PRODUCER_IDS.values():
            for path in paths:
                destination = self.repo / path
                if destination.exists():
                    continue
                source = ROOT / path
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
        self._install_release_freeze_fixture_module()
        self._install_test_only_manifest_wrappers()
        self._install_exit0_gate_producers()
        self._install_witnessed_build_producer_fixtures()
        contract_source = ROOT / "linux/packaging/store_manifest_contract.py"
        contract_destination = self.repo / "linux/packaging/store_manifest_contract.py"
        contract_destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(contract_source, contract_destination)
        helper = self._linux_store_contract_helper()
        fixture_dir = self.repo / "linux/packaging" / helper.ENGINE_ARCHIVE_DIR
        fixture_dir.mkdir(parents=True, exist_ok=True)
        try:
            xray_source = helper.reviewed_engine_archive_path(
                helper.XRAY_SOURCE_ARCHIVE_NAME,
                "Xray source",
            )
        except helper.ManifestContractError as error:
            self.assertEqual(
                str(error),
                helper.OWNER_INPUT_ARCHIVE_MISSING.format(label="Xray source"),
            )
            self._write_tar_gz(
                fixture_dir / helper.XRAY_SOURCE_ARCHIVE_NAME,
                [
                    (helper.XRAY_SOURCE_STRIP_PREFIX, "dir", None),
                    (
                        f"{helper.XRAY_SOURCE_STRIP_PREFIX}/LICENSE",
                        "file",
                        (
                            ROOT / "installer/windows/licenses/Xray-core-MPL-2.0.txt"
                        ).read_bytes(),
                    ),
                    (
                        f"{helper.XRAY_SOURCE_STRIP_PREFIX}/go.mod",
                        "file",
                        b"module github.com/xtls/xray-core\n",
                    ),
                ],
            )
            xray_payload = (fixture_dir / helper.XRAY_SOURCE_ARCHIVE_NAME).read_bytes()
            xray_archive_digest = helper.sha256_bytes(xray_payload)
            xray_tree_digest = helper.xray_owner_tree_sha256_from_archive_bytes(
                xray_payload
            )
        else:
            shutil.copy2(
                xray_source,
                fixture_dir / helper.XRAY_SOURCE_ARCHIVE_NAME,
            )
            xray_archive_digest, xray_tree_digest = helper.xray_source_identities()
        self.assertNotEqual(xray_archive_digest, xray_tree_digest)
        try:
            gomod_source = helper.reviewed_engine_archive_path(
                helper.STORE_GOMODCACHE_ARCHIVE_NAME,
                "Go module cache",
            )
        except helper.ManifestContractError as error:
            self.assertEqual(
                str(error),
                helper.OWNER_INPUT_ARCHIVE_MISSING.format(label="Go module cache"),
            )
            self._write_tar_gz(
                fixture_dir / helper.STORE_GOMODCACHE_ARCHIVE_NAME,
                [
                    (helper.STORE_GOMODCACHE_STRIP_PREFIX, "dir", None),
                    (
                        f"{helper.STORE_GOMODCACHE_STRIP_PREFIX}/README",
                        "file",
                        b"winsvpn-store-gomodcache-fixture\n",
                    ),
                ],
            )
        else:
            shutil.copy2(
                gomod_source,
                fixture_dir / helper.STORE_GOMODCACHE_ARCHIVE_NAME,
            )
        self.original_allowed_targets = freeze.PLATFORM_ALLOWED_TARGETS
        expanded_targets = {
            platform: list(targets)
            for platform, targets in self.original_allowed_targets.items()
        }
        for target in readiness.ALL_UPLOAD_TARGETS:
            if target.build_receipt_target not in expanded_targets[target.platform]:
                expanded_targets[target.platform].append(target.build_receipt_target)
        freeze.PLATFORM_ALLOWED_TARGETS = {
            platform: tuple(targets) for platform, targets in expanded_targets.items()
        }
        self.addCleanup(
            lambda: setattr(
                freeze, "PLATFORM_ALLOWED_TARGETS", self.original_allowed_targets
            )
        )
        self._write(
            readiness.PLAY_DECLARATIONS,
            "Approval status: `PENDING` - owner Play Console gate.\n",
        )
        self._write(
            readiness.OWNER_SIGNOFF,
            json.dumps({"schema_version": 1, "submission_approved": False}) + "\n",
        )
        self._write(
            readiness.CHECKLIST,
            "Purchase History is **not collected**. Live App Store Connect still "
            "lists it. Do not publish that console change from this repository.\n",
        )
        self._install_platform_owner_signoffs()
        self._install_linux_store_manifest_fixture()
        self.freeze_dir = self.repo / ".artifacts" / "freeze"
        shared = self.freeze_dir / "SHARED_INPUTS.json"
        freeze.create_shared_manifest(self.repo, shared, "sr1")
        for platform in freeze.PLATFORM_ROOTS:
            freeze.create_platform_manifest(
                self.repo,
                platform,
                shared,
                self.freeze_dir / f"{platform.upper()}_INPUTS.json",
            )
        self.index = self.freeze_dir / "RELEASE_INPUT_INDEX.json"
        freeze.create_release_index(self.repo, self.freeze_dir, self.index)
        self.issuance = ExternalSourceFreezeTestIssuance()
        self.addCleanup(self.issuance.restore)
        self.issuance.install(self.repo)
        freeze._SOURCE_FREEZE_TRUST_PATH = str(self.issuance.path)
        freeze._SOURCE_FREEZE_SELF_AUTHORED_OVERRIDE = False
        freeze._SOURCE_FREEZE_MODULE = None
        self.gcp_receipt = self._write(
            ".artifacts/gcp-proof/acceptance-receipt.json", "fixture receipt\n"
        )
        self.gcp_reference = {
            "path": str(self.gcp_receipt),
            "sha256": "a" * 64,
            "created_utc": "2026-08-24T00:00:00Z",
            "release": "1.0.17+34",
            "release_input_index": {
                "path": str(self.index),
                "sha256": self._sha(self.index),
            },
            "client_build_identity": "linux:1.0.17+34:" + "b" * 64,
        }
        self.gcp_receipt_patch = mock.patch.object(
            readiness,
            "_verify_gcp_proof_acceptance_receipt",
            return_value=self.gcp_reference,
        )
        self.gcp_receipt_patch.start()
        self.gcp_receipt_environment = mock.patch.dict(
            os.environ,
            {"WINS_GCP_PROOF_ACCEPTANCE_RECEIPT": str(self.gcp_receipt)},
        )
        self.gcp_receipt_environment.start()
        self.receipts = self._create_all_target_receipts()
        self.bindings = tuple(
            f"{target.target_id}="
            f"{self.receipts[target.target_id].relative_to(self.repo).as_posix()}"
            for target in readiness.REQUIRED_UPLOAD_TARGETS
        )

    def tearDown(self) -> None:
        self.gcp_receipt_environment.stop()
        self.gcp_receipt_patch.stop()
        freeze.PLATFORM_ALLOWED_TARGETS = self.original_allowed_targets
        issuance = getattr(self, "issuance", None)
        if issuance is not None:
            issuance.restore()
        self.temporary.cleanup()
        self.bytecode_patch.stop()

    def _write(self, relative: str, contents: str) -> pathlib.Path:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
        return path

    def _install_release_freeze_fixture_module(self) -> None:
        canonical_paths = (
            "tools/release_dependency_freeze.py",
            "tools/release_source_freeze.py",
            "tools/test_release_source_freeze.py",
            "tools/toolchain-pins.json",
        )
        for relative in canonical_paths:
            source = ROOT / relative
            destination = self.repo / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)

        module_path = self.repo / "tools/release_dependency_freeze.py"
        module_name = f"_winsvpn_cross_store_release_freeze_{id(self):x}"
        self.assertNotIn(module_name, sys.modules)
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            sys.modules.pop(module_name, None)
            raise

        original_freeze = globals()["freeze"]
        original_readiness_freeze = readiness.freeze
        original_receipt_freeze = receipt_producer.freeze
        original_fixture_mode = module._FIXTURE_MODE
        original_trust_path = module._SOURCE_FREEZE_TRUST_PATH
        original_self_authored = module._SOURCE_FREEZE_SELF_AUTHORED_OVERRIDE
        original_source_module = module._SOURCE_FREEZE_MODULE

        def restore() -> None:
            globals()["freeze"] = original_freeze
            readiness.freeze = original_readiness_freeze
            receipt_producer.freeze = original_receipt_freeze
            module._FIXTURE_MODE = original_fixture_mode
            module._SOURCE_FREEZE_TRUST_PATH = original_trust_path
            module._SOURCE_FREEZE_SELF_AUTHORED_OVERRIDE = original_self_authored
            module._SOURCE_FREEZE_MODULE = original_source_module
            if sys.modules.get(module_name) is module:
                del sys.modules[module_name]

        self.addCleanup(restore)
        module._FIXTURE_MODE = True
        original_artifact_validator = module._validate_release_artifact_bytes
        fixture_artifacts = {
            (
                target.platform,
                target.build_receipt_target,
                f"wins-vpn-{target.target_id}{target.artifact_suffixes[0]}",
            )
            for target in readiness.ALL_UPLOAD_TARGETS
            if target.manifest_verifier_path is None
            and target.platform != "extension"
        }

        def validate_test_fixture_artifact(
            platform: str,
            target: str,
            artifact_name: str,
            payload: bytes,
        ) -> None:
            if platform == "extension":
                original_artifact_validator(
                    platform, target, artifact_name, payload
                )
                return
            identity = (platform, target, artifact_name)
            expected = f"artifact:{artifact_name}\n".encode("ascii")
            if identity not in fixture_artifacts or payload != expected:
                raise module.DependencyFreezeError(
                    "Cross-store test artifact does not match its exact "
                    "fixture-only target binding."
                )

        module._validate_release_artifact_bytes = validate_test_fixture_artifact
        globals()["freeze"] = module
        readiness.freeze = module
        receipt_producer.freeze = module

    def _install_extension_verifier(self) -> None:
        source_tree = ROOT / "extension/src"
        destination_tree = self.repo / "extension/src"
        if destination_tree.exists():
            shutil.rmtree(destination_tree)
        shutil.copytree(source_tree, destination_tree)
        manifest_tree = self.repo / "extension/manifest"
        if manifest_tree.exists():
            shutil.rmtree(manifest_tree)
        shutil.copytree(ROOT / "extension/manifest", manifest_tree)
        for relative in readiness.EXTENSION_VERIFIER_SOURCE_PATHS:
            source = ROOT / relative
            destination = self.repo / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        replacements = {
            "chrome": "abcdefghijklmnopabcdefghijklmnop",
            "edge": "ponmlkjihgfedcbaponmlkjihgfedcba",
        }
        for browser, store_id in replacements.items():
            template = (
                self.repo
                / f"tools/native_messaging/manifests/org.winsvpn.bridge.{browser}.json"
            )
            contents = template.read_text(encoding="utf-8")
            contents = re.sub(
                rf"PLACEHOLDER_{browser.upper()}_EXTENSION_ID", store_id, contents
            )
            template.write_text(contents, encoding="utf-8")
        for asset_path in freeze._declared_pubspec_assets(self.repo):
            if not (self.repo / asset_path).exists():
                self._write(asset_path, f"fixture asset: {asset_path}\n")

    def _install_exit0_gate_producers(self) -> None:
        skip = {
            target.manifest_verifier_path
            for target in readiness.ALL_UPLOAD_TARGETS
            if target.manifest_verifier_path is not None
        }
        for paths in readiness.GATE_PRODUCER_IDS.values():
            for relative in paths:
                path = self.repo / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                if relative in skip:
                    os.chmod(path, 0o755)
                    continue
                if path.suffix.lower() == ".sh":
                    path.write_text("#!/bin/bash\nexit 0\n", encoding="ascii")
                else:
                    path.write_text(
                        "#!/usr/bin/env python3\nimport sys\nraise SystemExit(0)\n",
                        encoding="ascii",
                    )
                os.chmod(path, 0o755)

    def _install_test_only_manifest_wrappers(self) -> None:
        wrapper = (
            "#!/usr/bin/env python3\n"
            '"""Structurally test-only manifest producer wrapper."""\n'
            "from __future__ import annotations\n"
            "\n"
            "import importlib.util\n"
            "import pathlib\n"
            "\n"
            "TEST_ONLY = True\n"
            "\n"
            "def production_pass_allowed() -> bool:\n"
            "    return False\n"
            "\n"
            'if __name__ == "__main__":\n'
            "    raise SystemExit(0)\n"
            "\n"
            "_impl_path = pathlib.Path(__file__).with_name(\n"
            '    "_test_only_manifest_impl.py"\n'
            ")\n"
            "_spec = importlib.util.spec_from_file_location(\n"
            '    __name__ + "_impl", _impl_path\n'
            ")\n"
            "if _spec is None or _spec.loader is None:\n"
            '    raise RuntimeError("test-only manifest impl cannot be loaded")\n'
            "_impl = importlib.util.module_from_spec(_spec)\n"
            "_spec.loader.exec_module(_impl)\n"
            "produce_manifest = _impl.produce_manifest\n"
            "verify_receipt = _impl.verify_receipt\n"
        )
        for target in readiness.ALL_UPLOAD_TARGETS:
            relative = target.manifest_verifier_path
            if relative is None:
                continue
            producer = self.repo / relative
            producer.parent.mkdir(parents=True, exist_ok=True)
            impl = producer.with_name("_test_only_manifest_impl.py")
            source = ROOT / relative
            if producer.exists():
                shutil.copy2(producer, impl)
            else:
                shutil.copy2(source, impl)
            producer.write_text(wrapper, encoding="ascii")
            os.chmod(producer, 0o755)

    def _linux_store_contract_helper(self):
        name = "_winsvpn_cross_store_store_contract_helper"
        existing = sys.modules.get(name)
        if existing is not None:
            return existing
        spec = readiness.importlib.util.spec_from_file_location(
            name, ROOT / "linux/packaging/store_manifest_contract.py"
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = readiness.importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module

    @staticmethod
    def _ustar(members: list[tuple[str, str, bytes | None]]) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, kind, payload in members:
                info = tarfile.TarInfo(name)
                if kind == "dir":
                    info.type = tarfile.DIRTYPE
                    info.size = 0
                    archive.addfile(info)
                else:
                    data = payload or b""
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
        return buffer.getvalue()

    def _write_tar_gz(
        self, path: pathlib.Path, members: list[tuple[str, str, bytes | None]]
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(gzip.compress(self._ustar(members), mtime=0))

    def _write_tar_xz(
        self, path: pathlib.Path, members: list[tuple[str, str, bytes | None]]
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(lzma.compress(self._ustar(members), format=lzma.FORMAT_XZ))

    def _install_linux_store_manifest_fixture(self) -> None:
        helper = self._linux_store_contract_helper()
        metainfo = self.repo / helper.METADATA_RELATIVE
        metainfo.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / helper.METADATA_RELATIVE, metainfo)
        expected_metainfo = (ROOT / helper.METADATA_RELATIVE).read_bytes()
        self.assertEqual(metainfo.read_bytes(), expected_metainfo)
        self.assertGreater(len(expected_metainfo), 0)
        self.linux_store_source_url = (
            "https://downloads.winsvpn.org/source/wins-vpn-1.0.17.tar.gz"
        )
        self.linux_store_source_archive = (
            self.repo / ".artifacts/source/wins-vpn-1.0.17.tar.gz"
        )
        self._write_tar_gz(
            self.linux_store_source_archive,
            [
                ("wins-vpn-1.0.17", "dir", None),
                ("wins-vpn-1.0.17/README", "file", b"winsvpn-source-snapshot\n"),
            ],
        )
        x64 = self.repo / ".artifacts/flutter/flutter_linux_x64_3.47.6-stable.tar.xz"
        arm64 = (
            self.repo / ".artifacts/flutter/flutter_linux_arm64_3.47.6-stable.tar.xz"
        )
        self._write_tar_xz(
            x64,
            [
                ("flutter", "dir", None),
                ("flutter/bin", "dir", None),
                ("flutter/bin/flutter", "file", b"flutter-linux-x64-sdk\n"),
            ],
        )
        self._write_tar_xz(
            arm64,
            [
                ("flutter", "dir", None),
                ("flutter/bin", "dir", None),
                ("flutter/bin/flutter", "file", b"flutter-linux-arm64-sdk\n"),
            ],
        )
        source_identity = helper.stream_archive_identity(
            self.repo,
            self.linux_store_source_archive,
            "fixture source",
            kind="tar.gz",
            expected_root=None,
            allow_symlinks=False,
            max_bytes=helper.MAX_SOURCE_ARCHIVE_BYTES,
        )
        x64_identity = helper.stream_archive_identity(
            self.repo,
            x64,
            "fixture flutter x64",
            kind="tar.xz",
            expected_root="flutter",
            allow_symlinks=True,
            max_bytes=helper.MAX_FLUTTER_ARCHIVE_BYTES,
        )
        arm64_identity = helper.stream_archive_identity(
            self.repo,
            arm64,
            "fixture flutter arm64",
            kind="tar.xz",
            expected_root="flutter",
            allow_symlinks=True,
            max_bytes=helper.MAX_FLUTTER_ARCHIVE_BYTES,
        )
        self.linux_store_source_sha256 = source_identity[0]
        created_utc = helper._utc_now()
        module_path = self.repo / "linux/packaging/store_manifest_contract.py"
        freeze_record = {
            "schema_version": 1,
            "contract": "winsvpn-linux-store-source-freeze-receipt-v1",
            "created_utc": created_utc,
            "issuance_id": "c" * 32,
            "release": "1.0.17+34",
            "authenticated": True,
            "issuer": "winsvpn-release-source-freeze",
            "module": {
                "path": "linux/packaging/store_manifest_contract.py",
                "sha256": self._sha(module_path),
                "bytes": module_path.stat().st_size,
            },
            "source": {
                "url": self.linux_store_source_url,
                "sha256": source_identity[0],
                "archive_path": self.linux_store_source_archive.relative_to(
                    self.repo
                ).as_posix(),
                "bytes": source_identity[1],
                "tree_sha256": source_identity[2],
            },
        }
        freeze_path = (
            self.repo
            / ".artifacts/release-freeze-1.0.17+34"
            / "STORE_SOURCE_RECEIPT.json"
        )
        freeze_path.parent.mkdir(parents=True, exist_ok=True)
        self._json_write(freeze_path, freeze_record)
        trust = {
            "schema_version": 1,
            "contract": "winsvpn-linux-store-source-toolchain-trust-v1",
            "created_utc": created_utc,
            "issuance_id": freeze_record["issuance_id"],
            "release": freeze_record["release"],
            "issuer": "winsvpn-release-source-freeze",
            "module": freeze_record["module"],
            "source": freeze_record["source"],
            "flutter": {
                "channel": "stable",
                "dart_version": "3.13.5",
                "issuance_id": "d" * 32,
                "issuer": "winsvpn-linux-flutter-toolchain-custody",
                "revision": "5fc346839b5d0eef006ed8404392afb4dfae428d",
                "version": "3.47.6",
            },
        }
        self._json_write(self.repo / "linux/packaging/STORE_SOURCE_TRUST.json", trust)
        self.linux_store_toolchain_receipt = (
            self.repo / ".artifacts/flutter/FLUTTER_SDK_RECEIPT.json"
        )
        self._json_write(
            self.linux_store_toolchain_receipt,
            {
                "schema_version": 2,
                "contract": "winsvpn-linux-flutter-sdk-receipt-v1",
                "version": "3.47.6",
                "revision": "5fc346839b5d0eef006ed8404392afb4dfae428d",
                "channel": "stable",
                "dart_version": "3.13.5",
                "created_utc": created_utc,
                "issuance_id": "d" * 32,
                "authenticated": True,
                "issuer": "winsvpn-linux-flutter-toolchain-custody",
                "archives": {
                    "x64": {
                        "archive_path": x64.relative_to(self.repo).as_posix(),
                        "bytes": x64_identity[1],
                        "name": x64.name,
                        "sha256": x64_identity[0],
                        "tree_sha256": x64_identity[2],
                        "url": (
                            "https://storage.googleapis.com/flutter_infra_release/"
                            "releases/stable/linux/" + x64.name
                        ),
                    },
                    "arm64": {
                        "archive_path": arm64.relative_to(self.repo).as_posix(),
                        "bytes": arm64_identity[1],
                        "name": arm64.name,
                        "sha256": arm64_identity[0],
                        "tree_sha256": arm64_identity[2],
                        "url": (
                            "https://storage.googleapis.com/flutter_infra_release/"
                            "releases/stable/linux/" + arm64.name
                        ),
                    },
                },
            },
        )

    def _write_extension_zip(self, target_id: str, artifact_path: pathlib.Path) -> None:
        browser = readiness.EXTENSION_BROWSER_BY_TARGET_ID[target_id]
        spec = readiness.importlib.util.spec_from_file_location(
            f"fixture_extension_build_{browser}",
            ROOT / "extension/build.py",
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        builder = readiness.importlib.util.module_from_spec(spec)
        with mock.patch.object(sys, "dont_write_bytecode", True):
            spec.loader.exec_module(builder)
        builder.DIST = artifact_path.parent / f".stage-{target_id}"
        if builder.DIST.exists():
            shutil.rmtree(builder.DIST)
        produced = builder.zip_package(builder.stage(browser), browser)
        shutil.copyfile(produced, artifact_path)

    def _install_witnessed_build_producer_fixtures(self) -> None:
        extension_payloads: dict[str, str] = {}
        with tempfile.TemporaryDirectory() as temporary:
            payload_root = pathlib.Path(temporary)
            for target in readiness.ALL_UPLOAD_TARGETS:
                if target.platform != "extension":
                    continue
                artifact_name = (
                    f"wins-vpn-{target.target_id}{target.artifact_suffixes[0]}"
                )
                artifact_path = payload_root / artifact_name
                self._write_extension_zip(target.target_id, artifact_path)
                extension_payloads[artifact_name] = artifact_path.read_bytes().hex()

        extension_impl_hex = (ROOT / "extension/build.py").read_bytes().hex()

        def producer_source(
            implementation_hex: str, *, shell_gate: bool = False
        ) -> str:
            prelude = "#!/usr/bin/env python3\n"
            if shell_gate:
                prelude = (
                    "#!/bin/sh\n"
                    '""":"\n'
                    'if [ "${1:-}" = "--verify" ]; then exit 0; fi\n'
                    'exec /usr/bin/python3 "$0" "$@"\n'
                    '":"""\n'
                )
            return prelude + (
                "# WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_V2\n"
                "import os\n"
                "import pathlib\n"
                "import re\n"
                "import sys\n"
                f"PAYLOADS = {extension_payloads!r}\n"
                f"SWITCH = {freeze.BUILD_ATTEMPT_SWITCH!r}\n"
                f"CONTRACT = {freeze.BUILD_ATTEMPT_CONTRACT!r}\n"
                f"IMPLEMENTATION_HEX = {implementation_hex!r}\n"
                "def _fixture_main():\n"
                "    if sys.argv[1:] != [SWITCH]:\n"
                "        return 0\n"
                "    if os.environ.get('WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_CONTRACT') != CONTRACT:\n"
                "        return 65\n"
                "    nonce = os.environ.get('WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_NONCE', '')\n"
                "    if re.fullmatch(r'[0-9a-f]{64}', nonce) is None:\n"
                "        return 66\n"
                "    output_name = os.environ.get('WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_OUTPUT', '')\n"
                "    if not output_name or pathlib.PurePath(output_name).name != output_name:\n"
                "        return 67\n"
                "    output_fd_text = os.environ.get('WINS_RELEASE_DEPENDENCY_OUTPUT_FD', '')\n"
                "    if not output_fd_text.isdecimal():\n"
                "        return 68\n"
                "    output_fd = int(output_fd_text)\n"
                "    if os.fstat(output_fd).st_size != 0:\n"
                "        return 69\n"
                "    payload_hex = PAYLOADS.get(output_name)\n"
                "    payload = (bytes.fromhex(payload_hex) if payload_hex is not None "
                "else ('artifact:' + output_name + '\\n').encode('ascii'))\n"
                "    with os.fdopen(os.dup(output_fd), 'wb', closefd=True) as output:\n"
                "        output.write(payload)\n"
                "        output.flush()\n"
                "    return 0\n"
                "if __name__ == '__main__':\n"
                "    raise SystemExit(_fixture_main())\n"
                "if IMPLEMENTATION_HEX:\n"
                "    exec(compile(bytes.fromhex(IMPLEMENTATION_HEX), __file__, 'exec'), globals(), globals())\n"
            )

        for path in set(freeze.PLATFORM_BUILD_PRODUCERS.values()):
            implementation = extension_impl_hex if path == "extension/build.py" else ""
            self._write(
                path,
                producer_source(implementation, shell_gate=path.endswith(".sh")),
            )

    @staticmethod
    def _json_write(path: pathlib.Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def _tamper_anchored_fixture(
        self, path: pathlib.Path, value: object
    ) -> None:
        anchor = path.with_name(path.name + ".sha256")
        path.chmod(0o600)
        anchor.chmod(0o600)
        try:
            self._json_write(path, value)
            anchor.write_text(
                f"{self._sha(path)}  {path.name}\n", encoding="ascii"
            )
        finally:
            path.chmod(0o400)
            anchor.chmod(0o400)

    @staticmethod
    def _sha(path: pathlib.Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    @staticmethod
    def _replace_zip_member(
        payload: bytes, member_name: str, replacement: bytes
    ) -> bytes:
        source = io.BytesIO(payload)
        output = io.BytesIO()
        replaced = 0
        with zipfile.ZipFile(source, "r") as incoming:
            with zipfile.ZipFile(output, "w") as outgoing:
                for info in incoming.infolist():
                    member = incoming.read(info)
                    if info.filename == member_name:
                        member = replacement
                        replaced += 1
                    outgoing.writestr(info, member)
        if replaced != 1:
            raise AssertionError(f"expected exactly one {member_name} member")
        return output.getvalue()

    def _source_binding(self, platform: str) -> dict[str, object]:
        index_record = json.loads(self.index.read_text(encoding="utf-8"))
        reference = index_record["platform_manifests"][platform]
        manifest = self.index.parent / reference["path"]
        return {
            "index_path": self.index.relative_to(self.repo).as_posix(),
            "index_sha256": self._sha(self.index),
            "platform_manifest_path": manifest.relative_to(self.repo).as_posix(),
            "platform_manifest_sha256": reference["sha256"],
            "artifact_input_fingerprint_sha256": reference[
                "artifact_input_fingerprint_sha256"
            ],
            "shared_revision": "sr1",
        }

    def _create_all_target_receipts(self) -> dict[str, pathlib.Path]:
        receipts: dict[str, pathlib.Path] = {}
        build_receipt_root = self.repo / ".artifacts" / "build-receipts"
        build_receipt_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        build_receipt_root.chmod(0o700)
        gate_receipt_root = self.repo / ".artifacts" / "upload-gates"
        gate_receipt_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        gate_receipt_root.chmod(0o700)
        for target in readiness.ALL_UPLOAD_TARGETS:
            suffix = target.artifact_suffixes[0]
            artifact_root = (
                self.repo / ".artifacts" / "store-manifests"
                if target.manifest_verifier_path is not None
                else self.repo / "build" / "upload"
            )
            if target.target_id == "linux-flathub-manifest":
                artifact_name = "org.winsvpn.app.json"
            elif target.target_id == "linux-snap-manifest":
                artifact_name = "snapcraft.yaml"
            else:
                artifact_name = f"wins-vpn-{target.target_id}{suffix}"
            artifact_path = artifact_root / target.target_id / artifact_name
            artifact_path.parent.mkdir(parents=True, exist_ok=True)
            if target.manifest_verifier_path is not None:
                build_receipt_path = artifact_path.with_name(
                    artifact_path.name + ".receipt.json"
                )
            else:
                build_receipt_path = (
                    self.repo
                    / ".artifacts"
                    / "build-receipts"
                    / f"{target.target_id}-build.json"
                )
            if target.manifest_verifier_path is not None:
                verifier = self.repo / target.manifest_verifier_path
                spec = readiness.importlib.util.spec_from_file_location(
                    f"fixture_{target.target_id.replace('-', '_')}", verifier
                )
                self.assertIsNotNone(spec)
                self.assertIsNotNone(spec.loader)
                module = readiness.importlib.util.module_from_spec(spec)
                with mock.patch.object(sys, "dont_write_bytecode", True):
                    spec.loader.exec_module(module)
                module.produce_manifest(
                    self.repo,
                    self.linux_store_source_url,
                    self.linux_store_source_sha256,
                    "1.0.17",
                    artifact_path,
                    build_receipt_path,
                    self.linux_store_source_archive,
                    self.linux_store_toolchain_receipt,
                )
                producer_id = target.manifest_verifier_path
            else:
                begin_path = (
                    self.repo
                    / ".artifacts"
                    / "build-receipts"
                    / f"{target.target_id}-begin.json"
                )
                freeze.begin_build_receipt(
                    self.repo, self.index, target.platform, begin_path
                )
                producer_id = freeze.PLATFORM_BUILD_PRODUCERS[target.platform]
                freeze.finish_build_receipt(
                    self.repo,
                    self.index,
                    target.platform,
                    begin_path,
                    artifact_path,
                    producer_id,
                    "fixture-toolchain",
                    "1.0",
                    "fixture",
                    target.build_receipt_target,
                    build_receipt_path,
                )
            artifact = {
                "path": artifact_path.relative_to(self.repo).as_posix(),
                "sha256": self._sha(artifact_path),
                "bytes": artifact_path.stat().st_size,
            }
            producer = self.repo / producer_id
            gate_commands = {
                gate_id: (
                    readiness.GATE_PRODUCER_IDS[gate_id][0],
                    "--verify",
                    target.target_id,
                    artifact_path.relative_to(self.repo).as_posix(),
                )
                for gate_id in (target.signing_gate_id, target.hardening_gate_id)
            }
            gate_references = readiness.execute_target_gate_transaction(
                self.repo,
                target.target_id,
                artifact_path,
                gate_commands,
                pathlib.Path(".artifacts/upload-gates"),
            )
            verified_utc = (
                dt.datetime.now(tz=dt.timezone.utc)
                .isoformat()
                .replace("+00:00", "Z")
            )
            receipt = {
                "ok": True,
                "schema_version": readiness.TARGET_RECEIPT_SCHEMA_VERSION,
                "contract": readiness.TARGET_RECEIPT_CONTRACT,
                "release": "1.0.17+34",
                "target_id": target.target_id,
                "platform": target.platform,
                "verified_utc": verified_utc,
                "build_receipt": {
                    "path": build_receipt_path.relative_to(self.repo).as_posix(),
                    "sha256": self._sha(build_receipt_path),
                    "target": target.build_receipt_target,
                },
                "artifact": artifact,
                "producer": {
                    "id": producer_id,
                    "path": producer_id,
                    "sha256": self._sha(producer),
                },
                "signing_verification_gate": gate_references[
                    target.signing_gate_id
                ],
                "obfuscation_privacy_gate": gate_references[
                    target.hardening_gate_id
                ],
                "dependency_source_freeze": self._source_binding(target.platform),
                "publication_authorized": False,
                "upload_attempted": False,
            }
            if target.platform == "extension":
                receipt["verifier_source_closure"] = (
                    readiness.extension_verifier_source_closure(self.repo)
                )
            receipt_path = (
                self.repo
                / ".artifacts"
                / "upload-receipts"
                / f"{target.target_id}.json"
            )
            self._json_write(receipt_path, receipt)
            receipts[target.target_id] = receipt_path
        return receipts

    def _mutate_receipt(self, target_id: str, mutate) -> None:
        path = self.receipts[target_id]
        value = json.loads(path.read_text(encoding="utf-8"))
        mutate(value)
        self._json_write(path, value)

    def _mutate_gate_evidence(self, target_id: str, receipt_key: str, mutate) -> None:
        receipt_path = self.receipts[target_id]
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        gate_ref = receipt[receipt_key]
        evidence_path = self.repo / gate_ref["evidence_path"]
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        mutate(evidence)
        self._tamper_anchored_fixture(evidence_path, evidence)
        gate_ref["evidence_sha256"] = self._sha(evidence_path)
        self._json_write(receipt_path, receipt)

    def _gate_commands(
        self, target: readiness.UploadTarget
    ) -> dict[str, tuple[str, ...]]:
        receipt = json.loads(
            self.receipts[target.target_id].read_text(encoding="utf-8")
        )
        artifact_path = str(receipt["artifact"]["path"])
        return {
            gate_id: (
                readiness.GATE_PRODUCER_IDS[gate_id][0],
                "--verify",
                target.target_id,
                artifact_path,
            )
            for gate_id in (target.signing_gate_id, target.hardening_gate_id)
        }

    def _output(self, name: str = "CROSS_STORE_UPLOAD_READINESS.json") -> pathlib.Path:
        return self.repo / ".artifacts" / name

    def _install_platform_owner_signoffs(self) -> None:
        for spec in readiness.PLATFORM_OWNER_EVIDENCE:
            source = ROOT / spec.path
            destination = self.repo / spec.path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)

    @staticmethod
    def _blocker_ids(payload: dict[str, object]) -> set[str]:
        blockers = payload["owner_blockers"]
        assert isinstance(blockers, list)
        return {str(item["id"]) for item in blockers}

    @staticmethod
    def _blocker_target_ids(payload: dict[str, object]) -> set[str]:
        blockers = payload["owner_blockers"]
        assert isinstance(blockers, list)
        covered: set[str] = set()
        for item in blockers:
            covered.update(str(target_id) for target_id in item["target_ids"])
        return covered

    def _assert_owner_blocked(
        self, payload: dict[str, object], *, local_artifacts_ready: bool
    ) -> None:
        self.assertEqual(payload["status"], readiness.READINESS_STATUS_BLOCKED)
        self.assertIs(payload["ok"], False)
        self.assertFalse(payload["store_upload_authorized"])
        self.assertFalse(payload["publication_authorized"])
        self.assertEqual(payload["local_artifacts_ready"], local_artifacts_ready)
        self.assertTrue(payload["owner_blockers"])
        self.assertEqual(
            self._blocker_ids(payload) & self.EXPECTED_PENDING_OWNER_BLOCKER_IDS,
            self.EXPECTED_PENDING_OWNER_BLOCKER_IDS,
        )
        self.assertEqual(self._blocker_target_ids(payload), readiness.REQUIRED_TARGET_IDS)

    EXPECTED_PENDING_OWNER_BLOCKER_IDS = frozenset(
        {
            "play-query-all-packages",
            "apple-owner-signoff",
            "apple-live-purchase-history",
            "android-phone-owner-signoff",
            "android-tv-owner-signoff",
            "wear-os-owner-signoff",
            "windows-owner-signoff",
            "linux-owner-signoff",
            "extension-owner-signoff",
        }
    )

    def test_required_target_set_is_explicit_and_complete(self) -> None:
        expected = {
            "android-phone-tablet-aab",
            "android-tv-aab",
            "wear-os-aab",
            "ios-app-store-ipa",
            "macos-app-store-pkg",
            "windows-x64-installer",
            "windows-x64-partner-center",
            "windows-arm64-installer",
            "windows-arm64-partner-center",
            "linux-x64-package",
            "linux-arm64-package",
            "linux-flathub-manifest",
            "linux-snap-manifest",
            "chrome-extension-package",
            "edge-extension-package",
            "firefox-extension-package",
        }
        self.assertIsInstance(readiness.REQUIRED_UPLOAD_TARGETS, tuple)
        self.assertIsInstance(readiness.REQUIRED_TARGET_IDS, frozenset)
        self.assertEqual(readiness.REQUIRED_TARGET_IDS, expected)
        self.assertEqual(
            readiness.OPTIONAL_TARGET_IDS,
            {"macos-developer-id-app"},
        )
        self.assertEqual(
            readiness.KNOWN_TARGET_IDS,
            expected | {"macos-developer-id-app"},
        )
        self.assertEqual(len(readiness.REQUIRED_TARGET_IDS), 16)
        self.assertEqual(len(readiness.OPTIONAL_TARGET_IDS), 1)
        self.assertFalse(readiness.REQUIRED_TARGET_IDS & readiness.OPTIONAL_TARGET_IDS)
        self.assertEqual(readiness.PLANNED_UNSUPPORTED_TARGETS, {})
        linux_gate = (readiness.LINUX_ARTIFACT_GATE_RELATIVE,)
        windows_gate = (readiness.WINDOWS_ARTIFACT_GATE_RELATIVE,)
        for target_id in readiness.LINUX_UPLOAD_TARGET_IDS:
            target = readiness.TARGET_BY_ID[target_id]
            self.assertEqual(
                readiness.GATE_PRODUCER_IDS[target.signing_gate_id],
                linux_gate,
            )
        for target_id in readiness.WINDOWS_UPLOAD_TARGET_IDS:
            target = readiness.TARGET_BY_ID[target_id]
            self.assertEqual(
                readiness.GATE_PRODUCER_IDS[target.signing_gate_id],
                windows_gate,
            )
        for target_id in readiness.APPLE_REQUIRED_UPLOAD_TARGET_IDS:
            target = readiness.TARGET_BY_ID[target_id]
            self.assertIn(
                readiness.APPLE_ARTIFACT_GATE_RELATIVE,
                readiness.GATE_PRODUCER_IDS[target.signing_gate_id],
            )
        closure_paths = readiness._required_producer_verifier_paths()
        self.assertIn(readiness.LINUX_ARTIFACT_GATE_RELATIVE, closure_paths)
        self.assertIn(readiness.APPLE_ARTIFACT_GATE_RELATIVE, closure_paths)
        self.assertIn(readiness.WINDOWS_ARTIFACT_GATE_RELATIVE, closure_paths)
        self.assertIn(readiness.RELEASE_IDENTITY_RELATIVE, closure_paths)
        self.assertEqual(len(closure_paths), len(set(closure_paths)))
        readiness._assert_target_contract()
        self.assertTrue(
            all(
                target_id not in readiness.REQUIRED_TARGET_IDS
                for target_id in readiness.PLANNED_UNSUPPORTED_TARGETS
            )
        )

    def test_production_runner_uses_exact_argv_and_shell_false(self) -> None:
        completed = subprocess.CompletedProcess(
            args=("producer", "--verify", "target"),
            returncode=0,
            stdout="raw stdout",
            stderr="raw stderr",
        )
        with mock.patch.object(
            gate_runner.subprocess, "run", return_value=completed
        ) as run:
            result = gate_runner.SubprocessExplicitArgvRunner().run(
                ("producer", "--verify", "target"), cwd=self.repo
            )
        self.assertTrue(result.executed)
        self.assertFalse(result.shell_enabled)
        self.assertEqual(result.argv, ("producer", "--verify", "target"))
        self.assertEqual(result.stdout, "raw stdout")
        self.assertEqual(result.stderr, "raw stderr")
        self.assertEqual(result.exit_code, 0)
        run.assert_called_once_with(
            ("producer", "--verify", "target"),
            cwd=self.repo,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="strict",
            shell=False,
            check=False,
            env=mock.ANY,
        )
        environment = run.call_args.kwargs["env"]
        self.assertEqual(environment["PYTHONDONTWRITEBYTECODE"], "1")
        self.assertEqual(
            result.environment_overrides,
            (("PYTHONDONTWRITEBYTECODE", "1"),),
        )

    def test_shell_command_evaluation_argv_is_rejected(self) -> None:
        target = readiness.TARGET_BY_ID["linux-x64-package"]
        receipt = json.loads(self.receipts[target.target_id].read_text(encoding="utf-8"))
        artifact = self.repo / receipt["artifact"]["path"]
        commands = self._gate_commands(target)
        commands[target.signing_gate_id] = (
            "bash",
            "-c",
            readiness.GATE_PRODUCER_IDS[target.signing_gate_id][0],
        )
        runner = FakeExplicitArgvRunner()
        with self.assertRaisesRegex(readiness.UploadReadinessError, "shell command"):
            readiness.execute_target_gate_transaction(
                self.repo,
                target.target_id,
                artifact,
                commands,
                pathlib.Path(".artifacts/adversarial-shell"),
                runner=runner,
            )
        self.assertEqual(runner.calls, [])

    def test_source_evaluation_is_fail_closed_without_execution(self) -> None:
        result = readiness.evaluate_source_gates(self.repo)
        self._assert_owner_blocked(result, local_artifacts_ready=False)
        self.assertEqual(
            result["missing_target_receipts"],
            [target.target_id for target in readiness.REQUIRED_UPLOAD_TARGETS],
        )
        self.assertEqual(
            result["optional_target_ids"],
            ["macos-developer-id-app"],
        )
        self.assertFalse(result["local_gates_executed"])
        self.assertFalse(result["upload_attempted"])
        self.assertTrue(result["local_gate_bindings_complete"])
        self.assertEqual(result["unsupported_build_receipt_targets"], [])
        self.assertEqual(
            result["producer_verifier_closure"],
            readiness._producer_verifier_closure(self.repo),
        )

    def test_real_tree_evaluate_cli_exits_nonzero_without_exact_receipts(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools/cross_store_upload_readiness.py"),
                "evaluate",
                "--repo",
                str(ROOT),
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        if completed.stdout:
            payload = json.loads(completed.stdout)
            self.assertFalse(payload["ok"])
            self.assertEqual(payload["status"], readiness.READINESS_STATUS_BLOCKED)
            self.assertTrue(
                self.EXPECTED_PENDING_OWNER_BLOCKER_IDS
                <= self._blocker_ids(payload)
            )
            self.assertEqual(
                self._blocker_target_ids(payload), readiness.REQUIRED_TARGET_IDS
            )
        else:
            self.assertIn("CROSS-STORE UPLOAD READINESS: FAIL:", completed.stderr)
            self.assertIn("owner authorization schema v2 is stale", completed.stderr)

    def test_complete_exact_receipts_record_and_verify(self) -> None:
        evidence = self._output()
        record = readiness.record_evidence(
            self.repo, evidence, self.index, self.bindings
        )
        self._assert_owner_blocked(record, local_artifacts_ready=True)
        self.assertEqual(set(record["target_receipts"]), readiness.REQUIRED_TARGET_IDS)
        self.assertEqual(
            len(
                {
                    receipt["build_receipt"]["path"]
                    for receipt in record["target_receipts"].values()
                }
            ),
            len(readiness.REQUIRED_TARGET_IDS),
        )
        self.assertEqual(record["missing_target_receipts"], [])
        self.assertTrue(record["local_gates_executed"])
        self.assertEqual(
            record["producer_verifier_closure"],
            readiness._producer_verifier_closure(self.repo),
        )
        verified = readiness.verify_evidence(self.repo, evidence, self.index)
        self.assertEqual(
            verified["verified_target_count"],
            len(readiness.REQUIRED_UPLOAD_TARGETS),
        )
        self.assertEqual(verified["required_target_count"], 16)
        self.assertNotIn("macos-developer-id-app", record["target_receipts"])
        self.assertTrue(verified["local_gates_executed"])
        self._assert_owner_blocked(verified, local_artifacts_ready=True)

    def test_successful_record_main_returns_zero_and_prints_ok_true(self) -> None:
        output = io.StringIO()
        argv = [
            "cross_store_upload_readiness.py",
            "record",
            "--repo",
            str(self.repo),
            "--output",
            str(self._output()),
            "--index",
            str(self.index),
        ]
        with (
            mock.patch.object(sys, "argv", argv),
            mock.patch.object(
                readiness,
                "record_evidence",
                return_value={"ok": True, "status": readiness.READINESS_STATUS_LOCAL_READY},
            ),
            redirect_stdout(output),
        ):
            self.assertEqual(readiness.main(), 0)
        self.assertIs(json.loads(output.getvalue())["ok"], True)

    def test_blocked_record_main_exits_nonzero_and_prints_status(self) -> None:
        output = io.StringIO()
        argv = [
            "cross_store_upload_readiness.py",
            "record",
            "--repo",
            str(self.repo),
            "--output",
            str(self._output("blocked-cli.json")),
            "--index",
            str(self.index),
        ]
        for binding in self.bindings:
            argv.extend(["--receipt", binding])
        with mock.patch.object(sys, "argv", argv), redirect_stdout(output):
            self.assertEqual(readiness.main(), 1)
        payload = json.loads(output.getvalue())
        self._assert_owner_blocked(payload, local_artifacts_ready=True)

    def test_gate_evidence_records_canonical_and_actual_execution_vectors(self) -> None:
        target = readiness.TARGET_BY_ID["android-phone-tablet-aab"]
        receipt = json.loads(
            self.receipts[target.target_id].read_text(encoding="utf-8")
        )
        evidence_path = self.repo / receipt["signing_verification_gate"][
            "evidence_path"
        ]
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        command = evidence["command"]
        producer_index = command["producer_arg_index"]
        self.assertEqual(
            command["argv"][producer_index],
            readiness.GATE_PRODUCER_IDS[target.signing_gate_id][0],
        )
        self.assertNotEqual(command["executed_argv"], command["argv"])
        self.assertIn(
            ".winsvpn-gate-", command["executed_argv"][producer_index]
        )
        exact = evidence["runner"]["exact_byte_execution"]
        self.assertEqual(
            command["executed_argv"][producer_index], exact["snapshot_path"]
        )
        self.assertTrue(exact["hardlink_same_inode"])
        self.assertTrue(exact["cleanup_complete"])
        self.assertEqual(
            evidence["runner"]["environment_overrides"],
            {"PYTHONDONTWRITEBYTECODE": "1"},
        )

    def test_tampered_actual_execution_vector_is_rejected(self) -> None:
        target_id = "android-phone-tablet-aab"

        def replace_actual_vector(evidence: dict[str, object]) -> None:
            command = evidence["command"]
            command["executed_argv"] = list(command["argv"])

        self._mutate_gate_evidence(
            target_id, "signing_verification_gate", replace_actual_vector
        )
        with self.assertRaisesRegex(readiness.UploadReadinessError, "binding is invalid"):
            readiness.record_evidence(
                self.repo, self._output(), self.index, self.bindings
            )

    def test_missing_receipt_is_rejected(self) -> None:
        with self.assertRaisesRegex(readiness.UploadReadinessError, "missing:"):
            readiness.record_evidence(
                self.repo, self._output(), self.index, self.bindings[:-1]
            )

    def test_duplicate_target_receipt_is_rejected(self) -> None:
        with self.assertRaisesRegex(readiness.UploadReadinessError, "Duplicate"):
            readiness.record_evidence(
                self.repo,
                self._output(),
                self.index,
                self.bindings + (self.bindings[0],),
            )

    def test_unexpected_target_is_rejected(self) -> None:
        bad = list(self.bindings)
        bad[-1] = "unknown-store=.artifacts/upload-receipts/unknown.json"
        with self.assertRaisesRegex(readiness.UploadReadinessError, "Unexpected"):
            readiness.record_evidence(self.repo, self._output(), self.index, tuple(bad))

    def test_same_receipt_path_for_two_targets_is_rejected(self) -> None:
        bad = list(self.bindings)
        first_path = bad[0].split("=", 1)[1]
        second_id = bad[1].split("=", 1)[0]
        bad[1] = f"{second_id}={first_path}"
        with self.assertRaisesRegex(readiness.UploadReadinessError, "distinct"):
            readiness.record_evidence(self.repo, self._output(), self.index, tuple(bad))

    @unittest.skipUnless(hasattr(os, "link"), "hard links unavailable")
    def test_hard_linked_build_receipts_are_not_distinct(self) -> None:
        first = self.repo / ".artifacts" / "hardlink-build-a.json"
        second = self.repo / ".artifacts" / "hardlink-build-b.json"
        first.write_text("{}\n", encoding="utf-8")
        os.link(first, second)
        bindings = {
            "a": {"build_receipt": {"path": first.relative_to(self.repo).as_posix()}},
            "b": {"build_receipt": {"path": second.relative_to(self.repo).as_posix()}},
        }
        with self.assertRaisesRegex(readiness.UploadReadinessError, "distinct"):
            readiness._assert_distinct_build_receipts(self.repo, bindings)

    def test_wrong_target_binding_is_rejected(self) -> None:
        target_id = "android-phone-tablet-aab"
        self._mutate_receipt(
            target_id,
            lambda value: value.__setitem__("target_id", "android-tv-aab"),
        )
        with self.assertRaisesRegex(readiness.UploadReadinessError, "binding"):
            readiness.record_evidence(
                self.repo, self._output(), self.index, self.bindings
            )

    def test_missing_exact_build_receipt_is_rejected(self) -> None:
        target_id = "ios-app-store-ipa"
        receipt = json.loads(self.receipts[target_id].read_text(encoding="utf-8"))
        build_receipt = self.repo / receipt["build_receipt"]["path"]
        build_receipt.unlink()
        with self.assertRaisesRegex(freeze.DependencyFreezeError, "does not exist"):
            readiness.record_evidence(
                self.repo, self._output(), self.index, self.bindings
            )

    def test_cross_target_build_receipt_is_rejected(self) -> None:
        target_id = "android-tv-aab"
        other = json.loads(
            self.receipts["android-phone-tablet-aab"].read_text(encoding="utf-8")
        )
        self._mutate_receipt(
            target_id,
            lambda value: value["build_receipt"].update(
                {
                    "path": other["build_receipt"]["path"],
                    "sha256": other["build_receipt"]["sha256"],
                }
            ),
        )
        with self.assertRaisesRegex(
            freeze.DependencyFreezeError,
            "Exact built artifact|Build attempt journal binding changed",
        ):
            readiness.record_evidence(
                self.repo, self._output(), self.index, self.bindings
            )

    def test_mismatched_artifact_is_rejected(self) -> None:
        target_id = "ios-app-store-ipa"
        record = json.loads(self.receipts[target_id].read_text(encoding="utf-8"))
        artifact = self.repo / record["artifact"]["path"]
        artifact.write_bytes(b"replaced artifact")
        with self.assertRaisesRegex(readiness.UploadReadinessError, "identity"):
            readiness.record_evidence(
                self.repo, self._output(), self.index, self.bindings
            )

    def test_failed_gate_is_rejected(self) -> None:
        target_id = "windows-x64-installer"
        self._mutate_receipt(
            target_id,
            lambda value: value["signing_verification_gate"].__setitem__(
                "status", "failed"
            ),
        )
        with self.assertRaisesRegex(readiness.UploadReadinessError, "did not pass"):
            readiness.record_evidence(
                self.repo, self._output(), self.index, self.bindings
            )

    def test_fake_runner_cannot_turn_nonzero_exit_into_success(self) -> None:
        target = readiness.TARGET_BY_ID["android-phone-tablet-aab"]
        receipt = json.loads(self.receipts[target.target_id].read_text(encoding="utf-8"))
        artifact = self.repo / receipt["artifact"]["path"]
        commands = self._gate_commands(target)
        first_argv = commands[target.signing_gate_id]
        runner = FakeExplicitArgvRunner()
        runner.results.append(
            gate_runner.GateProcessResult(
                argv=first_argv,
                stdout='{"status":"passed"}\n',
                stderr="real verifier failure\n",
                exit_code=7,
                executed=True,
                runner_id=gate_runner.SubprocessExplicitArgvRunner.RUNNER_ID,
                shell_enabled=False,
            )
        )
        with self.assertRaisesRegex(readiness.UploadReadinessError, "exited with 7"):
            readiness.execute_target_gate_transaction(
                self.repo,
                target.target_id,
                artifact,
                commands,
                pathlib.Path(".artifacts/adversarial-nonzero"),
                runner=runner,
            )

    def test_record_reexecutes_instead_of_trusting_complete_success_json(self) -> None:
        target = readiness.REQUIRED_UPLOAD_TARGETS[0]
        commands = self._gate_commands(target)
        runner = FakeExplicitArgvRunner()
        runner.results.append(
            gate_runner.GateProcessResult(
                argv=commands[target.signing_gate_id],
                stdout="caller JSON claimed success",
                stderr="machine verifier failed",
                exit_code=9,
                executed=True,
                runner_id=gate_runner.SubprocessExplicitArgvRunner.RUNNER_ID,
                shell_enabled=False,
            )
        )
        with self.assertRaisesRegex(readiness.UploadReadinessError, "exited with 9"):
            readiness.record_evidence(
                self.repo,
                self._output(),
                self.index,
                self.bindings,
                runner=runner,
            )

    def test_verify_reexecutes_instead_of_trusting_historical_success(self) -> None:
        evidence = self._output()
        readiness.record_evidence(self.repo, evidence, self.index, self.bindings)
        target = readiness.REQUIRED_UPLOAD_TARGETS[0]
        commands = self._gate_commands(target)
        runner = FakeExplicitArgvRunner()
        runner.results.append(
            gate_runner.GateProcessResult(
                argv=commands[target.signing_gate_id],
                stdout="historical evidence claimed success",
                stderr="current verifier failed",
                exit_code=11,
                executed=True,
                runner_id=gate_runner.SubprocessExplicitArgvRunner.RUNNER_ID,
                shell_enabled=False,
            )
        )
        with self.assertRaisesRegex(readiness.UploadReadinessError, "exited with 11"):
            readiness.verify_evidence(
                self.repo, evidence, self.index, runner=runner
            )

    def test_single_receipt_current_verification_executes_both_exact_gates(self) -> None:
        target = readiness.TARGET_BY_ID["android-phone-tablet-aab"]
        verified = readiness.verify_target_receipt_current(
            self.repo,
            self.index,
            target.target_id,
            self.receipts[target.target_id],
            evidence_dir=pathlib.Path(".artifacts/adversarial-current-target"),
        )
        receipt = json.loads(
            self.receipts[target.target_id].read_text(encoding="utf-8")
        )
        written = list(
            (self.repo / ".artifacts/adversarial-current-target").glob("*.json")
        )
        self.assertEqual(len(written), 2)
        for path in written:
            evidence = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(evidence["command"]["argv"][-3], "--verify")
            self.assertEqual(evidence["command"]["argv"][-2], target.target_id)
            self.assertEqual(
                evidence["runner"]["id"],
                gate_runner.SubprocessExplicitArgvRunner.RUNNER_ID,
            )
            self.assertTrue(evidence["runner"]["production_pass_allowed"])
            self.assertEqual(
                evidence["runner"]["controller_path"],
                readiness.PRODUCTION_GATE_CONTROLLER,
            )
        self.assertEqual(
            verified["artifact"]["sha256"],
            receipt["artifact"]["sha256"],
        )

    def test_single_receipt_current_verification_rejects_forged_stored_success(
        self,
    ) -> None:
        target = readiness.TARGET_BY_ID["android-phone-tablet-aab"]
        commands = self._gate_commands(target)
        runner = FakeExplicitArgvRunner()
        runner.results.append(
            gate_runner.GateProcessResult(
                argv=commands[target.signing_gate_id],
                stdout='{"status":"passed","stored_evidence":"forged"}\n',
                stderr="ANDROID AAB SIGNER: FAIL: invalid AAB ZIP archive\n",
                exit_code=1,
                executed=True,
                runner_id=gate_runner.SubprocessExplicitArgvRunner.RUNNER_ID,
                shell_enabled=False,
            )
        )
        with self.assertRaisesRegex(readiness.UploadReadinessError, "exited with 1"):
            readiness.verify_target_receipt_current(
                self.repo,
                self.index,
                target.target_id,
                self.receipts[target.target_id],
                runner=runner,
                evidence_dir=pathlib.Path(".artifacts/adversarial-forged-success"),
            )
        self.assertEqual(len(runner.calls), 1)

    def test_actual_android_signing_gate_rejects_non_zip_aab(self) -> None:
        artifact_root = ROOT / ".artifacts"
        artifact_root.mkdir(mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="cross-store-nonzip-", dir=artifact_root
        ) as temporary:
            temporary_root = pathlib.Path(temporary)
            artifact = temporary_root / "forged.aab"
            artifact.write_bytes(b"stored evidence says this is signed\n")
            relative = artifact.relative_to(ROOT).as_posix()
            jdk_bin = temporary_root / "sealed-jdk" / "bin"
            jdk_bin.mkdir(parents=True)
            jdk_tools: dict[str, pathlib.Path] = {}
            for name in ("java", "jarsigner", "keytool"):
                tool = jdk_bin / name
                tool.write_text("#!/bin/sh\nexit 1\n", encoding="ascii")
                tool.chmod(0o755)
                jdk_tools[name] = tool
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools/verify_android_aab_signers.py"),
                    "--verify",
                    "android-phone-tablet-aab",
                    relative,
                    "--java",
                    str(jdk_tools["java"]),
                    "--jarsigner",
                    str(jdk_tools["jarsigner"]),
                    "--keytool",
                    str(jdk_tools["keytool"]),
                ],
                cwd=ROOT,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=30,
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("invalid AAB ZIP archive", completed.stderr)

    def test_actual_linux_gate_rejects_unsigned_tarball(self) -> None:
        artifact_root = ROOT / ".artifacts"
        artifact_root.mkdir(mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="cross-store-linux-unsigned-", dir=artifact_root
        ) as temporary:
            temporary_root = pathlib.Path(temporary)
            artifact = temporary_root / "wins-vpn-linux-x64.tar.gz"
            artifact.write_bytes(b"artifact:linux-x64-package\n")
            relative = artifact.relative_to(ROOT).as_posix()
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / readiness.LINUX_ARTIFACT_GATE_RELATIVE),
                    "--verify",
                    "linux-x64-package",
                    relative,
                ],
                cwd=ROOT,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=60,
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("ERROR:", completed.stderr)

    def test_linux_appstream_fixture_is_exact_current_metainfo(self) -> None:
        helper = self._linux_store_contract_helper()
        fixture = self.repo / helper.METADATA_RELATIVE
        current = ROOT / helper.METADATA_RELATIVE
        self.assertTrue(fixture.is_file())
        self.assertEqual(fixture.read_bytes(), current.read_bytes())
        self.assertIn(b'id>org.winsvpn.app</id>', fixture.read_bytes())
        self.assertIn(b'version="1.0.17"', fixture.read_bytes())

    def test_runner_that_did_not_execute_is_rejected(self) -> None:
        target = readiness.TARGET_BY_ID["android-phone-tablet-aab"]
        receipt = json.loads(self.receipts[target.target_id].read_text(encoding="utf-8"))
        artifact = self.repo / receipt["artifact"]["path"]
        commands = self._gate_commands(target)
        first_argv = commands[target.signing_gate_id]
        runner = FakeExplicitArgvRunner()
        runner.results.append(
            gate_runner.GateProcessResult(
                argv=first_argv,
                stdout="pretend success",
                stderr="",
                exit_code=0,
                executed=False,
                runner_id=gate_runner.SubprocessExplicitArgvRunner.RUNNER_ID,
                shell_enabled=False,
            )
        )
        with self.assertRaisesRegex(readiness.UploadReadinessError, "did not prove"):
            readiness.execute_target_gate_transaction(
                self.repo,
                target.target_id,
                artifact,
                commands,
                pathlib.Path(".artifacts/adversarial-unexecuted"),
                runner=runner,
            )

    def test_shell_enabled_runner_result_is_rejected(self) -> None:
        target = readiness.TARGET_BY_ID["android-phone-tablet-aab"]
        receipt = json.loads(self.receipts[target.target_id].read_text(encoding="utf-8"))
        artifact = self.repo / receipt["artifact"]["path"]
        commands = self._gate_commands(target)
        first_argv = commands[target.signing_gate_id]
        runner = FakeExplicitArgvRunner()
        runner.results.append(
            gate_runner.GateProcessResult(
                argv=first_argv,
                stdout="pretend success",
                stderr="",
                exit_code=0,
                executed=True,
                runner_id=gate_runner.SubprocessExplicitArgvRunner.RUNNER_ID,
                shell_enabled=True,
            )
        )
        with self.assertRaisesRegex(readiness.UploadReadinessError, "shell-disabled"):
            readiness.execute_target_gate_transaction(
                self.repo,
                target.target_id,
                artifact,
                commands,
                pathlib.Path(".artifacts/adversarial-shell-result"),
                runner=runner,
            )

    def test_runner_exception_is_rejected_as_nonexecution(self) -> None:
        target = readiness.TARGET_BY_ID["android-phone-tablet-aab"]
        receipt = json.loads(self.receipts[target.target_id].read_text(encoding="utf-8"))
        artifact = self.repo / receipt["artifact"]["path"]

        class RaisingRunner(FakeExplicitArgvRunner):
            def run(self, argv, *, cwd):
                raise OSError("exec denied")

        with self.assertRaisesRegex(readiness.UploadReadinessError, "did not execute"):
            readiness.execute_target_gate_transaction(
                self.repo,
                target.target_id,
                artifact,
                self._gate_commands(target),
                pathlib.Path(".artifacts/adversarial-runner-exception"),
                runner=RaisingRunner(),
            )

    def test_runner_returning_different_argv_is_rejected(self) -> None:
        target = readiness.TARGET_BY_ID["android-phone-tablet-aab"]
        receipt = json.loads(self.receipts[target.target_id].read_text(encoding="utf-8"))
        artifact = self.repo / receipt["artifact"]["path"]
        commands = self._gate_commands(target)
        runner = FakeExplicitArgvRunner()
        runner.results.append(
            gate_runner.GateProcessResult(
                argv=("true",),
                stdout="success",
                stderr="",
                exit_code=0,
                executed=True,
                runner_id=gate_runner.SubprocessExplicitArgvRunner.RUNNER_ID,
                shell_enabled=False,
            )
        )
        with self.assertRaisesRegex(readiness.UploadReadinessError, "exact shell-disabled"):
            readiness.execute_target_gate_transaction(
                self.repo,
                target.target_id,
                artifact,
                commands,
                pathlib.Path(".artifacts/adversarial-argv"),
                runner=runner,
            )

    def test_producer_mismatch_is_rejected_before_execution(self) -> None:
        target = readiness.TARGET_BY_ID["android-phone-tablet-aab"]
        receipt = json.loads(self.receipts[target.target_id].read_text(encoding="utf-8"))
        artifact = self.repo / receipt["artifact"]["path"]
        commands = self._gate_commands(target)
        commands[target.signing_gate_id] = (
            "tools/release_dependency_freeze.py",
            "--verify",
            target.target_id,
        )
        runner = FakeExplicitArgvRunner()
        with self.assertRaisesRegex(readiness.UploadReadinessError, "allowed producer"):
            readiness.execute_target_gate_transaction(
                self.repo,
                target.target_id,
                artifact,
                commands,
                pathlib.Path(".artifacts/adversarial-producer"),
                runner=runner,
            )
        self.assertEqual(runner.calls, [])

    def test_producer_named_as_nonexecuted_argument_is_rejected(self) -> None:
        target = readiness.TARGET_BY_ID["android-phone-tablet-aab"]
        receipt = json.loads(self.receipts[target.target_id].read_text(encoding="utf-8"))
        artifact = self.repo / receipt["artifact"]["path"]
        commands = self._gate_commands(target)
        producer = readiness.GATE_PRODUCER_IDS[target.signing_gate_id][0]
        commands[target.signing_gate_id] = (
            sys.executable,
            "-c",
            producer,
        )
        runner = FakeExplicitArgvRunner()
        with self.assertRaisesRegex(readiness.UploadReadinessError, "does not execute"):
            readiness.execute_target_gate_transaction(
                self.repo,
                target.target_id,
                artifact,
                commands,
                pathlib.Path(".artifacts/adversarial-producer-argument"),
                runner=runner,
            )
        self.assertEqual(runner.calls, [])

    def test_command_for_a_different_exact_target_is_rejected(self) -> None:
        target = readiness.TARGET_BY_ID["android-phone-tablet-aab"]
        receipt = json.loads(self.receipts[target.target_id].read_text(encoding="utf-8"))
        artifact = self.repo / receipt["artifact"]["path"]
        commands = self._gate_commands(target)
        producer = readiness.GATE_PRODUCER_IDS[target.signing_gate_id][0]
        commands[target.signing_gate_id] = (
            producer,
            "--verify",
            "android-tv-aab",
            receipt["artifact"]["path"],
        )
        runner = FakeExplicitArgvRunner()
        with self.assertRaisesRegex(readiness.UploadReadinessError, "exact target"):
            readiness.execute_target_gate_transaction(
                self.repo,
                target.target_id,
                artifact,
                commands,
                pathlib.Path(".artifacts/adversarial-wrong-target"),
                runner=runner,
            )
        self.assertEqual(runner.calls, [])

    def test_command_for_a_different_artifact_is_rejected(self) -> None:
        target = readiness.TARGET_BY_ID["android-phone-tablet-aab"]
        receipt = json.loads(self.receipts[target.target_id].read_text(encoding="utf-8"))
        artifact = self.repo / receipt["artifact"]["path"]
        other_receipt = json.loads(
            self.receipts["android-tv-aab"].read_text(encoding="utf-8")
        )
        commands = self._gate_commands(target)
        producer = readiness.GATE_PRODUCER_IDS[target.signing_gate_id][0]
        commands[target.signing_gate_id] = (
            producer,
            "--verify",
            target.target_id,
            other_receipt["artifact"]["path"],
        )
        runner = FakeExplicitArgvRunner()
        with self.assertRaisesRegex(readiness.UploadReadinessError, "exact target"):
            readiness.execute_target_gate_transaction(
                self.repo,
                target.target_id,
                artifact,
                commands,
                pathlib.Path(".artifacts/adversarial-wrong-artifact"),
                runner=runner,
            )
        self.assertEqual(runner.calls, [])

    def test_artifact_mutation_during_gate_is_rejected(self) -> None:
        target = readiness.TARGET_BY_ID["android-phone-tablet-aab"]
        receipt = json.loads(self.receipts[target.target_id].read_text(encoding="utf-8"))
        artifact = self.repo / receipt["artifact"]["path"]
        commands = self._gate_commands(target)

        class MutatingRunner(FakeExplicitArgvRunner):
            def run(self, argv, *, cwd):
                artifact.write_bytes(b"mutated during gate")
                return super().run(argv, cwd=cwd)

        with self.assertRaisesRegex(readiness.UploadReadinessError, "mutated the artifact"):
            readiness.execute_target_gate_transaction(
                self.repo,
                target.target_id,
                artifact,
                commands,
                pathlib.Path(".artifacts/adversarial-mutation"),
                runner=MutatingRunner(),
            )

    @unittest.skipIf(os.name == "nt", "POSIX swap/restore regression")
    def test_higher_ancestor_swap_restore_cannot_preserve_gate_pass(self) -> None:
        target = readiness.TARGET_BY_ID["chrome-extension-package"]
        receipt = json.loads(
            self.receipts[target.target_id].read_text(encoding="utf-8")
        )
        artifact = self.repo / receipt["artifact"]["path"]
        valid_payload = artifact.read_bytes()
        with zipfile.ZipFile(io.BytesIO(valid_payload), "r") as archive:
            manifest = archive.read("manifest.json").decode("utf-8")
        manifest_record = json.loads(manifest)
        current_version = manifest_record.get("version")
        self.assertIsInstance(current_version, str)
        stale_manifest, substitutions = re.subn(
            r'("version"\s*:\s*)' + re.escape(json.dumps(current_version)),
            r'\g<1>"9.9.9"',
            manifest,
            count=1,
        )
        self.assertEqual(substitutions, 1)
        stale_payload = self._replace_zip_member(
            valid_payload, "manifest.json", stale_manifest.encode("utf-8")
        )
        artifact.write_bytes(stale_payload)
        stale_sha256 = self._sha(artifact)
        snapshot = gate_runner.artifact_snapshot_path_for(artifact, stale_sha256)
        swapped_ancestor = self.repo / "build"
        saved_ancestor = self.repo / ".build-parent-swap-saved"
        replacement_ancestor = (
            self.repo / ".artifacts" / "parent-swap-replacement-build"
        )
        replacement_artifact = replacement_ancestor / artifact.relative_to(
            swapped_ancestor
        )
        replacement_snapshot = replacement_ancestor / snapshot.relative_to(
            swapped_ancestor
        )
        replacement_artifact.parent.mkdir(parents=True, exist_ok=True)
        replacement_snapshot.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        replacement_artifact.write_bytes(valid_payload)
        replacement_snapshot.write_bytes(valid_payload)
        replacement_snapshot.chmod(0o600)
        real_run = subprocess.run
        observed_gate_results: list[subprocess.CompletedProcess[str]] = []

        def swap_restore_run(*args, **kwargs):
            swapped_ancestor.rename(saved_ancestor)
            replacement_ancestor.rename(swapped_ancestor)
            try:
                completed = real_run(*args, **kwargs)
                observed_gate_results.append(completed)
                return completed
            finally:
                swapped_ancestor.rename(replacement_ancestor)
                saved_ancestor.rename(swapped_ancestor)

        try:
            with mock.patch.object(
                gate_runner.subprocess, "run", side_effect=swap_restore_run
            ):
                with self.assertRaisesRegex(
                    readiness.UploadReadinessError,
                    "mutated the artifact execution boundary|Kernel monitoring",
                ):
                    readiness.execute_target_gate_transaction(
                        self.repo,
                        target.target_id,
                        artifact,
                        self._gate_commands(target),
                        pathlib.Path(".artifacts/adversarial-parent-swap"),
                    )
            self.assertEqual(len(observed_gate_results), 1)
            self.assertEqual(observed_gate_results[0].returncode, 0)
        finally:
            artifact.write_bytes(valid_payload)
            if saved_ancestor.exists() and not swapped_ancestor.exists():
                saved_ancestor.rename(swapped_ancestor)
            if replacement_ancestor.exists():
                shutil.rmtree(replacement_ancestor)

    def test_artifact_custody_inventory_tamper_is_rejected(self) -> None:
        target_id = "android-phone-tablet-aab"

        def tamper(evidence: dict[str, object]) -> None:
            custody = evidence["artifact_custody"]
            retained = custody["retained_objects"]
            retained[0]["identity"][0] += 1

        self._mutate_gate_evidence(
            target_id, "signing_verification_gate", tamper
        )
        with self.assertRaisesRegex(
            readiness.UploadReadinessError, "artifact custody"
        ):
            readiness._verify_target_receipt(
                self.repo, self.index, target_id, self.receipts[target_id]
            )

    def test_edited_raw_output_is_rejected_even_if_outer_hashes_are_updated(self) -> None:
        target_id = "android-phone-tablet-aab"
        self._mutate_gate_evidence(
            target_id,
            "signing_verification_gate",
            lambda evidence: evidence.__setitem__("stdout", "edited success\n"),
        )
        with self.assertRaisesRegex(readiness.UploadReadinessError, "binding is invalid"):
            readiness.record_evidence(
                self.repo, self._output(), self.index, self.bindings
            )

    def test_reordered_gate_commands_are_rejected(self) -> None:
        target_id = "android-phone-tablet-aab"

        def reorder(evidence: dict[str, object]) -> None:
            evidence["command_order"] = 1
            command = evidence["command"]
            producer = evidence["producer"]
            command["identity_sha256"] = readiness._command_identity(
                target_id,
                str(evidence["gate_id"]),
                1,
                tuple(command["argv"]),
                str(producer["path"]),
                str(producer["sha256"]),
            )

        self._mutate_gate_evidence(
            target_id, "signing_verification_gate", reorder
        )
        with self.assertRaisesRegex(readiness.UploadReadinessError, "command order"):
            readiness.record_evidence(
                self.repo, self._output(), self.index, self.bindings
            )

    def test_old_caller_authored_success_json_is_rejected(self) -> None:
        target_id = "android-phone-tablet-aab"

        def replace_with_old_format(evidence: dict[str, object]) -> None:
            evidence.clear()
            evidence.update(
                {
                    "schema_version": 1,
                    "contract": "winsvpn-executed-local-gate-v1",
                    "target_id": target_id,
                    "gate_id": "android-upload-certificate",
                    "artifact": {},
                    "executed_utc": dt.datetime.now(tz=dt.timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "command": ["tools/verify_android_aab_signers.py"],
                    "exit_code": 0,
                    "status": "passed",
                    "producer": {},
                }
            )

        self._mutate_gate_evidence(
            target_id, "signing_verification_gate", replace_with_old_format
        )
        with self.assertRaisesRegex(readiness.UploadReadinessError, "schema fields"):
            readiness.record_evidence(
                self.repo, self._output(), self.index, self.bindings
            )

    def test_stale_receipt_is_rejected(self) -> None:
        stale = (
            (
                dt.datetime.now(tz=dt.timezone.utc)
                - readiness.MAX_RECEIPT_AGE
                - dt.timedelta(minutes=1)
            )
            .isoformat()
            .replace("+00:00", "Z")
        )
        self._mutate_receipt(
            "linux-x64-package",
            lambda value: value.__setitem__("verified_utc", stale),
        )
        with self.assertRaisesRegex(readiness.UploadReadinessError, "stale"):
            readiness.record_evidence(
                self.repo, self._output(), self.index, self.bindings
            )

    def test_fresh_receipt_cannot_revalidate_an_old_artifact(self) -> None:
        target_id = "linux-x64-package"
        receipt = json.loads(self.receipts[target_id].read_text(encoding="utf-8"))
        artifact = self.repo / receipt["artifact"]["path"]
        stale = (
            dt.datetime.now(tz=dt.timezone.utc)
            - readiness.MAX_RECEIPT_AGE
            - dt.timedelta(minutes=1)
        )
        os.utime(artifact, (stale.timestamp(), stale.timestamp()))
        receipt["artifact"]["sha256"] = self._sha(artifact)
        self._json_write(self.receipts[target_id], receipt)
        with self.assertRaisesRegex(readiness.UploadReadinessError, "freshness"):
            readiness.record_evidence(
                self.repo, self._output(), self.index, self.bindings
            )

    def test_target_receipt_must_explicitly_report_success(self) -> None:
        self._mutate_receipt(
            "chrome-extension-package",
            lambda value: value.__setitem__("ok", False),
        )
        with self.assertRaisesRegex(readiness.UploadReadinessError, "binding"):
            readiness.record_evidence(
                self.repo, self._output(), self.index, self.bindings
            )

    def _produce_from_fixture(
        self,
        target_id: str,
        *,
        artifact_target_id: str | None = None,
        build_target_id: str | None = None,
        output_name: str | None = None,
        clock=None,
    ) -> tuple[pathlib.Path, dict[str, object]]:
        artifact_receipt = json.loads(
            self.receipts[artifact_target_id or target_id].read_text(encoding="utf-8")
        )
        build_receipt = json.loads(
            self.receipts[build_target_id or target_id].read_text(encoding="utf-8")
        )
        output = (
            self.repo
            / ".artifacts"
            / "produced-upload-receipts"
            / (output_name or f"{target_id}.json")
        )
        result = receipt_producer.produce_target_receipt(
            self.repo,
            self.index,
            target_id,
            pathlib.Path(str(artifact_receipt["artifact"]["path"])),
            pathlib.Path(str(build_receipt["build_receipt"]["path"])),
            output,
            pathlib.Path(f".artifacts/produced-upload-gates/{target_id}"),
            clock=clock,
        )
        return output, result

    def test_receipt_producer_supports_all_sixteen_required_targets(self) -> None:
        produced: set[str] = set()
        for target in readiness.REQUIRED_UPLOAD_TARGETS:
            output, result = self._produce_from_fixture(target.target_id)
            self.assertTrue(result["ok"])
            self.assertEqual(result["target_id"], target.target_id)
            self.assertTrue(output.is_file())
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            produced.add(target.target_id)
        self.assertEqual(produced, readiness.REQUIRED_TARGET_IDS)

    def test_receipt_producer_preserves_developer_id_as_optional_evidence(self) -> None:
        target_id = "macos-developer-id-app"
        output, result = self._produce_from_fixture(target_id)
        self.assertTrue(result["ok"])
        self.assertEqual(result["target_id"], target_id)
        self.assertTrue(output.is_file())
        verified = readiness._verify_target_receipt(
            self.repo,
            self.index,
            target_id,
            output,
        )
        self.assertEqual(verified["release"], "1.0.17+34")
        self.assertEqual(
            verified["receipt_path"],
            output.relative_to(self.repo).as_posix(),
        )
        self.assertNotIn(target_id, readiness.REQUIRED_TARGET_IDS)

    def test_optional_receipt_binding_cannot_enter_required_evidence(self) -> None:
        optional = self.receipts["macos-developer-id-app"]
        binding = f"macos-developer-id-app={optional.relative_to(self.repo).as_posix()}"
        with self.assertRaisesRegex(
            readiness.UploadReadinessError,
            "Unexpected upload target",
        ):
            readiness.record_evidence(
                self.repo,
                self._output(),
                self.index,
                self.bindings + (binding,),
            )

    def test_receipt_producer_rejects_stale_artifact_without_receipt(self) -> None:
        target_id = "linux-x64-package"
        fixture = json.loads(self.receipts[target_id].read_text(encoding="utf-8"))
        artifact = self.repo / fixture["artifact"]["path"]
        stale = (
            dt.datetime.now(tz=dt.timezone.utc)
            - readiness.MAX_RECEIPT_AGE
            - dt.timedelta(minutes=1)
        )
        os.utime(artifact, (stale.timestamp(), stale.timestamp()))
        output = self.repo / ".artifacts/produced-upload-receipts/stale.json"
        with self.assertRaisesRegex(receipt_producer.TargetReceiptError, "freshness"):
            self._produce_from_fixture(target_id, output_name="stale.json")
        self.assertFalse(output.exists())

    def test_receipt_producer_rejects_artifact_hash_change(self) -> None:
        target_id = "chrome-extension-package"
        fixture = json.loads(self.receipts[target_id].read_text(encoding="utf-8"))
        artifact = self.repo / fixture["artifact"]["path"]
        artifact.write_bytes(artifact.read_bytes() + b"tampered\n")
        output = self.repo / ".artifacts/produced-upload-receipts/hash.json"
        with self.assertRaisesRegex(
            (readiness.UploadReadinessError, freeze.DependencyFreezeError),
            "artifact|Artifact",
        ):
            self._produce_from_fixture(target_id, output_name="hash.json")
        self.assertFalse(output.exists())

    def test_receipt_producer_rejects_target_substitution(self) -> None:
        output = self.repo / ".artifacts/produced-upload-receipts/substitution.json"
        with self.assertRaisesRegex(
            (receipt_producer.TargetReceiptError, readiness.UploadReadinessError),
            "target|binding|substituted",
        ):
            self._produce_from_fixture(
                "chrome-extension-package",
                artifact_target_id="edge-extension-package",
                build_target_id="edge-extension-package",
                output_name="substitution.json",
            )
        self.assertFalse(output.exists())

    def test_receipt_producer_partial_write_never_publishes(self) -> None:
        target_id = "firefox-extension-package"
        output = self.repo / ".artifacts/produced-upload-receipts/partial.json"
        real_write = receipt_producer.os.write

        def fail_after_partial(descriptor: int, payload) -> None:
            real_write(descriptor, bytes(payload[:8]))
            raise OSError("injected partial write")

        with mock.patch.object(receipt_producer, "_write_all", fail_after_partial):
            with self.assertRaisesRegex(
                receipt_producer.TargetReceiptError,
                "stage or verify|snapshot",
            ):
                self._produce_from_fixture(target_id, output_name="partial.json")
        self.assertFalse(output.exists())
        if output.parent.exists():
            self.assertEqual(list(output.parent.iterdir()), [])

    def test_inode_cleanup_preserves_replacement_that_wins_before_rename(self) -> None:
        parent = self.repo / ".artifacts/cleanup-race"
        parent.mkdir(parents=True, mode=0o700)
        parent.chmod(0o700)
        output = parent / "receipt.json"
        saved = parent / "original.saved"
        output.write_bytes(b"original receipt\n")
        original = output.lstat()
        identity = (original.st_dev, original.st_ino)
        real_rename = receipt_producer.os.rename
        injected = False

        def replace_before_quarantine(source, destination, **kwargs) -> None:
            nonlocal injected
            if not injected and source == output.name:
                injected = True
                real_rename(output, saved)
                output.write_bytes(b"raced replacement\n")
            real_rename(source, destination, **kwargs)

        with mock.patch.object(
            receipt_producer.os, "rename", replace_before_quarantine
        ):
            removed = receipt_producer._unlink_matching_inode(output, identity)

        self.assertFalse(removed)
        self.assertTrue(injected)
        self.assertEqual(output.read_bytes(), b"raced replacement\n")
        self.assertEqual(saved.read_bytes(), b"original receipt\n")
        self.assertEqual(
            sorted(path.name for path in parent.iterdir()),
            ["original.saved", "receipt.json"],
        )

    def test_receipt_producer_refuses_to_replace_existing_receipt(self) -> None:
        target_id = "android-phone-tablet-aab"
        output, first = self._produce_from_fixture(target_id, output_name="immutable.json")
        before = output.read_bytes()
        with self.assertRaisesRegex(receipt_producer.TargetReceiptError, "overwrite"):
            self._produce_from_fixture(target_id, output_name="immutable.json")
        self.assertEqual(output.read_bytes(), before)
        self.assertTrue(first["ok"])

    def test_receipt_producer_rejects_hardlinked_artifact(self) -> None:
        target_id = "chrome-extension-package"
        fixture = json.loads(self.receipts[target_id].read_text(encoding="utf-8"))
        artifact = self.repo / fixture["artifact"]["path"]
        alias = artifact.with_name("hardlink-alias.zip")
        os.link(artifact, alias)
        output = self.repo / ".artifacts/produced-upload-receipts/hardlink.json"
        with self.assertRaisesRegex(readiness.UploadReadinessError, "hardlink alias"):
            self._produce_from_fixture(target_id, output_name="hardlink.json")
        self.assertFalse(output.exists())

    def test_receipt_producer_rejects_unsafe_output_filename(self) -> None:
        output = self.repo / ".artifacts/produced-upload-receipts/bad\nname.json"
        with self.assertRaisesRegex(receipt_producer.TargetReceiptError, "safe .json"):
            self._produce_from_fixture(
                "firefox-extension-package", output_name="bad\nname.json"
            )
        self.assertFalse(output.exists())

    def test_receipt_producer_rejects_non_private_output_directory(self) -> None:
        parent = self.repo / ".artifacts/produced-upload-receipts"
        parent.mkdir(parents=True, mode=0o755)
        parent.chmod(0o755)
        output = parent / "permissions.json"
        with self.assertRaisesRegex(receipt_producer.TargetReceiptError, "0700"):
            self._produce_from_fixture(
                "linux-x64-package", output_name="permissions.json"
            )
        self.assertFalse(output.exists())

    def test_receipt_producer_rejects_clock_rollback(self) -> None:
        current = dt.datetime.now(tz=dt.timezone.utc)
        values = iter(
            (
                current,
                current,
                current,
                current,
                current,
                current - dt.timedelta(seconds=1),
            )
        )
        output = self.repo / ".artifacts/produced-upload-receipts/clock.json"
        with self.assertRaisesRegex(receipt_producer.TargetReceiptError, "moved backwards"):
            self._produce_from_fixture(
                "edge-extension-package",
                output_name="clock.json",
                clock=lambda: next(values),
            )
        self.assertFalse(output.exists())

    def test_duplicate_json_key_is_rejected_at_any_depth(self) -> None:
        path = self.repo / ".artifacts/duplicate.json"
        path.write_text('{"artifact":{"path":"a","path":"b"}}\n', encoding="utf-8")
        with self.assertRaisesRegex(readiness.UploadReadinessError, "duplicate JSON key"):
            readiness._load_json(path, "duplicate fixture")

    def test_boolean_schema_version_cannot_alias_integer_one(self) -> None:
        self._mutate_receipt(
            "chrome-extension-package",
            lambda value: value.__setitem__("schema_version", True),
        )
        with self.assertRaisesRegex(readiness.UploadReadinessError, "binding"):
            readiness.record_evidence(
                self.repo, self._output(), self.index, self.bindings
            )

    def test_target_receipt_release_identity_is_exact(self) -> None:
        self._mutate_receipt(
            "android-phone-tablet-aab",
            lambda value: value.__setitem__("release", "1.0.14+29"),
        )
        with self.assertRaisesRegex(readiness.UploadReadinessError, "receipt binding"):
            readiness._verify_target_receipt(
                self.repo,
                self.index,
                "android-phone-tablet-aab",
                self.receipts["android-phone-tablet-aab"],
            )

    def test_produced_gate_evidence_is_owner_only(self) -> None:
        target_id = "wear-os-aab"
        self._produce_from_fixture(target_id, output_name="modes.json")
        evidence_dir = self.repo / f".artifacts/produced-upload-gates/{target_id}"
        self.assertEqual(stat.S_IMODE(evidence_dir.stat().st_mode), 0o700)
        for path in evidence_dir.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)

    def test_each_target_rejects_one_contract_dimension_substitution(self) -> None:
        mutations = (
            lambda value: value.__setitem__("target_id", "substituted-target"),
            lambda value: value.__setitem__("platform", "substituted-platform"),
            lambda value: value["build_receipt"].__setitem__(
                "target", "substituted-build-target"
            ),
            lambda value: value["signing_verification_gate"].__setitem__(
                "id", "substituted-signing-gate"
            ),
        )
        for index, target in enumerate(readiness.REQUIRED_UPLOAD_TARGETS):
            path = self.receipts[target.target_id]
            original = path.read_bytes()
            value = json.loads(original)
            mutations[index % len(mutations)](value)
            self._json_write(path, value)
            try:
                with self.subTest(target=target.target_id):
                    with self.assertRaises(readiness.UploadReadinessError):
                        readiness._verify_target_receipt(
                            self.repo, self.index, target.target_id, path
                        )
            finally:
                path.write_bytes(original)

    def test_legacy_owner_signoff_cannot_authorize_unbound_artifacts(self) -> None:
        self._write(
            readiness.OWNER_SIGNOFF,
            json.dumps({"schema_version": 1, "submission_approved": True}) + "\n",
        )
        with self.assertRaisesRegex(
            readiness.UploadReadinessError, "not bound to exact release artifacts"
        ):
            readiness.evaluate_source_gates(self.repo)

    def test_missing_platform_owner_signoff_is_blocked_absent(self) -> None:
        path = self.repo / "app_store/windows/review/owner_signoff.json"
        path.unlink()
        result = readiness.evaluate_source_gates(self.repo)
        self.assertEqual(result["status"], readiness.READINESS_STATUS_BLOCKED)
        self.assertIs(result["ok"], False)
        windows = next(
            item for item in result["owner_blockers"] if item["id"] == "windows-owner-signoff"
        )
        self.assertIn("OWNER-BLOCKED: ABSENT", windows["detail"])
        self.assertEqual(
            set(windows["target_ids"]), set(readiness.WINDOWS_UPLOAD_TARGET_IDS)
        )
        self.assertEqual(self._blocker_target_ids(result), readiness.REQUIRED_TARGET_IDS)

    def test_platform_owner_identity_mismatch_is_stale(self) -> None:
        path = self.repo / "app_store/linux/review/owner_signoff.json"
        record = json.loads(path.read_text(encoding="utf-8"))
        record["appstream_version"] = "9.9.9"
        self._json_write(path, record)
        with self.assertRaisesRegex(
            readiness.UploadReadinessError, "stale for identity/version"
        ):
            readiness.evaluate_source_gates(self.repo)

    def test_schema1_authenticode_hash_cannot_go_green(self) -> None:
        path = self.repo / "app_store/windows/review/owner_signoff.json"
        record = json.loads(path.read_text(encoding="utf-8"))
        record["authenticode_leaf_sha256"] = "ab" * 32
        self._json_write(path, record)
        with self.assertRaisesRegex(
            readiness.UploadReadinessError, "cannot bind an Authenticode signer"
        ):
            readiness.evaluate_source_gates(self.repo)

    def test_owner_evidence_hashes_are_separate_from_upload_receipts(self) -> None:
        result = readiness.evaluate_source_gates(self.repo)
        self._assert_owner_blocked(result, local_artifacts_ready=False)
        receipt_paths = {
            path.relative_to(self.repo).as_posix() for path in self.receipts.values()
        }
        for item in result["owner_blockers"]:
            evidence_path = item.get("evidence_path")
            if evidence_path is None:
                continue
            self.assertNotIn(evidence_path, receipt_paths)
            self.assertFalse(str(evidence_path).startswith(".artifacts/"))
            digest = item.get("evidence_sha256")
            self.assertIsInstance(digest, str)
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            self.assertEqual(digest, self._sha(self.repo / str(evidence_path)))

    def test_upload_receipt_cannot_reuse_owner_evidence_path(self) -> None:
        owner = "app_store/linux/review/owner_signoff.json"
        hostile = tuple(
            f"linux-x64-package={owner}"
            if binding.startswith("linux-x64-package=")
            else binding
            for binding in self.bindings
        )
        with self.assertRaisesRegex(
            readiness.UploadReadinessError,
            "must stay under .artifacts|separate from owner evidence|"
            r"target-id=\.artifacts",
        ):
            readiness.record_evidence(
                self.repo, self._output(), self.index, hostile
            )

    def test_schema1_platform_approval_cannot_go_green(self) -> None:
        path = self.repo / "app_store/linux/review/owner_signoff.json"
        record = json.loads(path.read_text(encoding="utf-8"))
        record["submission_approved"] = True
        record["upload_authorized"] = True
        self._json_write(path, record)
        with self.assertRaisesRegex(
            readiness.UploadReadinessError, "not bound to exact release artifacts"
        ):
            readiness.evaluate_source_gates(self.repo)

    def test_producer_verifier_closure_change_is_rejected(self) -> None:
        evidence = self._output("closure.json")
        readiness.record_evidence(self.repo, evidence, self.index, self.bindings)
        producer = self.repo / "tools/verify_android_aab_signers.py"
        producer.write_bytes(producer.read_bytes() + b"\n# hostile producer mutation\n")
        with self.assertRaisesRegex(
            (readiness.UploadReadinessError, freeze.DependencyFreezeError),
            "producer identity changed|Producer/verifier closure|invalid or changed|"
            "dependency inputs changed",
        ):
            readiness.verify_evidence(self.repo, evidence, self.index)

    def test_group_writable_artifact_is_rejected(self) -> None:
        target_id = "linux-x64-package"
        receipt = json.loads(self.receipts[target_id].read_text(encoding="utf-8"))
        artifact = self.repo / receipt["artifact"]["path"]
        os.chmod(artifact, 0o664)
        with self.assertRaisesRegex(
            readiness.UploadReadinessError, "writable by group or other"
        ):
            readiness._artifact_execution_snapshot(self.repo, artifact, target_id)

    def test_test_only_manifest_cannot_claim_production_pass(self) -> None:
        original = readiness.importlib.util.spec_from_file_location

        def load_and_allow_production(name, path, *args, **kwargs):
            spec = original(name, path, *args, **kwargs)
            loader = spec.loader
            assert loader is not None
            exec_module = loader.exec_module

            def hostile_exec(module, *exec_args, **exec_kwargs):
                exec_module(module, *exec_args, **exec_kwargs)
                if getattr(module, "TEST_ONLY", False) is True:
                    module.production_pass_allowed = lambda: True

            loader.exec_module = hostile_exec  # type: ignore[method-assign]
            return spec

        with mock.patch.object(
            readiness.importlib.util,
            "spec_from_file_location",
            load_and_allow_production,
        ):
            with self.assertRaisesRegex(
                readiness.UploadReadinessError, "cannot emit production PASS"
            ):
                readiness._verify_target_receipt(
                    self.repo,
                    self.index,
                    "linux-flathub-manifest",
                    self.receipts["linux-flathub-manifest"],
                )

    def test_malformed_receipt_extra_key_is_rejected(self) -> None:
        self._mutate_receipt(
            "chrome-extension-package",
            lambda value: value.__setitem__("unexpected", True),
        )
        with self.assertRaisesRegex(
            readiness.UploadReadinessError, "schema fields are invalid"
        ):
            readiness.record_evidence(
                self.repo, self._output(), self.index, self.bindings
            )

    def test_malformed_gate_command_is_rejected(self) -> None:
        target_id = "wear-os-aab"
        self._mutate_gate_evidence(
            target_id,
            "signing_verification_gate",
            lambda gate: gate.__setitem__("command", {}),
        )
        with self.assertRaisesRegex(readiness.UploadReadinessError, "command"):
            readiness.record_evidence(
                self.repo, self._output(), self.index, self.bindings
            )

    def test_gate_command_must_identify_the_bound_producer(self) -> None:
        target_id = "wear-os-aab"
        self._mutate_gate_evidence(
            target_id,
            "signing_verification_gate",
            lambda gate: gate["command"].__setitem__("argv", ["true"]),
        )
        with self.assertRaisesRegex(readiness.UploadReadinessError, "allowed producer"):
            readiness.record_evidence(
                self.repo, self._output(), self.index, self.bindings
            )

    def test_unrelated_gate_producer_is_rejected(self) -> None:
        target_id = "android-phone-tablet-aab"
        wrong = self.repo / "tools/release_dependency_freeze.py"
        self._mutate_gate_evidence(
            target_id,
            "signing_verification_gate",
            lambda gate: gate.__setitem__(
                "producer",
                {
                    "path": "tools/release_dependency_freeze.py",
                    "sha256": self._sha(wrong),
                },
            ),
        )
        with self.assertRaisesRegex(readiness.UploadReadinessError, "not allowed"):
            readiness.record_evidence(
                self.repo, self._output(), self.index, self.bindings
            )

    def test_malformed_json_receipt_is_rejected(self) -> None:
        self.receipts["linux-arm64-package"].write_text("{not-json\n", encoding="utf-8")
        with self.assertRaisesRegex(readiness.UploadReadinessError, "Unable to read"):
            readiness.record_evidence(
                self.repo, self._output(), self.index, self.bindings
            )

    def test_wrong_source_freeze_hash_is_rejected(self) -> None:
        self._mutate_receipt(
            "firefox-extension-package",
            lambda value: value["dependency_source_freeze"].__setitem__(
                "index_sha256", "0" * 64
            ),
        )
        with self.assertRaisesRegex(readiness.UploadReadinessError, "freeze binding"):
            readiness.record_evidence(
                self.repo, self._output(), self.index, self.bindings
            )

    def test_wrong_producer_is_rejected(self) -> None:
        self._mutate_receipt(
            "macos-app-store-pkg",
            lambda value: value["producer"].update(
                {
                    "id": "tools/build_linux_release.sh",
                    "path": "tools/build_linux_release.sh",
                    "sha256": self._sha(self.repo / "tools/build_linux_release.sh"),
                }
            ),
        )
        with self.assertRaisesRegex(readiness.UploadReadinessError, "producer id"):
            readiness.record_evidence(
                self.repo, self._output(), self.index, self.bindings
            )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_symlink_receipt_is_rejected(self) -> None:
        target_id = "edge-extension-package"
        receipt = self.receipts[target_id]
        real = receipt.with_suffix(".real.json")
        receipt.rename(real)
        receipt.symlink_to(real.name)
        with self.assertRaisesRegex(freeze.DependencyFreezeError, "symlink|reparse"):
            readiness.record_evidence(
                self.repo, self._output(), self.index, self.bindings
            )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_symlink_artifact_is_rejected(self) -> None:
        target_id = "android-tv-aab"
        record = json.loads(self.receipts[target_id].read_text(encoding="utf-8"))
        artifact = self.repo / record["artifact"]["path"]
        real = artifact.with_name("real.aab")
        artifact.rename(real)
        artifact.symlink_to(real.name)
        with self.assertRaisesRegex(freeze.DependencyFreezeError, "symlink|reparse"):
            readiness.record_evidence(
                self.repo, self._output(), self.index, self.bindings
            )

    def test_outside_root_artifact_is_rejected(self) -> None:
        outside = pathlib.Path(self.temporary.name).parent / "outside-winsvpn.aab"
        outside.write_bytes(b"outside")
        try:
            self._mutate_receipt(
                "android-phone-tablet-aab",
                lambda value: value["artifact"].update(
                    {
                        "path": str(outside),
                        "sha256": self._sha(outside),
                        "bytes": outside.stat().st_size,
                    }
                ),
            )
            with self.assertRaisesRegex(
                freeze.DependencyFreezeError, "inside the repository"
            ):
                readiness.record_evidence(
                    self.repo, self._output(), self.index, self.bindings
                )
        finally:
            outside.unlink(missing_ok=True)

    def test_evidence_tamper_and_overwrite_are_rejected(self) -> None:
        evidence = self._output()
        readiness.record_evidence(self.repo, evidence, self.index, self.bindings)
        with self.assertRaisesRegex(freeze.DependencyFreezeError, "overwrite"):
            readiness.record_evidence(self.repo, evidence, self.index, self.bindings)
        record = json.loads(evidence.read_text(encoding="utf-8"))
        record["store_upload_authorized"] = True
        self._tamper_anchored_fixture(evidence, record)
        with self.assertRaisesRegex(
            readiness.UploadReadinessError, "invalid or changed"
        ):
            readiness.verify_evidence(self.repo, evidence, self.index)

    def test_gcp_acceptance_receipt_is_required_before_recording(self) -> None:
        with mock.patch.dict(
            os.environ, {"WINS_GCP_PROOF_ACCEPTANCE_RECEIPT": ""}, clear=False
        ), self.assertRaisesRegex(
            readiness.UploadReadinessError, "GCP_PROOF_ACCEPTANCE_RECEIPT"
        ):
            readiness.record_evidence(
                self.repo, self._output(), self.index, self.bindings
            )

    def test_gcp_acceptance_receipt_binding_is_persisted_and_reverified(self) -> None:
        evidence = self._output()
        readiness.record_evidence(self.repo, evidence, self.index, self.bindings)
        record = json.loads(evidence.read_text(encoding="utf-8"))
        self.assertEqual(record["gcp_proof_acceptance_receipt"], self.gcp_reference)
        result = readiness.verify_evidence(self.repo, evidence, self.index)
        self.assertTrue(result["gcp_proof_accepted"])

    def test_changed_gcp_acceptance_receipt_reference_is_rejected(self) -> None:
        evidence = self._output()
        readiness.record_evidence(self.repo, evidence, self.index, self.bindings)
        record = json.loads(evidence.read_text(encoding="utf-8"))
        record["gcp_proof_acceptance_receipt"]["sha256"] = "0" * 64
        self._tamper_anchored_fixture(evidence, record)
        with self.assertRaisesRegex(
            readiness.UploadReadinessError, "GCP proof acceptance receipt identity"
        ):
            readiness.verify_evidence(self.repo, evidence, self.index)

    def test_duplicate_play_approval_status_is_rejected(self) -> None:
        declarations = self.repo / readiness.PLAY_DECLARATIONS
        declarations.write_text(
            declarations.read_text(encoding="utf-8") + "Approval status: `APPROVED`\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(readiness.UploadReadinessError, "exactly once"):
            readiness.evaluate_source_gates(self.repo)

    def test_cli_exposes_no_upload_or_publish_command(self) -> None:
        parser = readiness._parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["upload"])
        with self.assertRaises(SystemExit):
            parser.parse_args(["publish"])

    def test_real_tree_remains_locally_unexecuted_and_upload_closed(self) -> None:
        with mock.patch.object(
            freeze, "PLATFORM_ALLOWED_TARGETS", self.original_allowed_targets
        ):
            with self.assertRaisesRegex(
                readiness.UploadReadinessError,
                "Apple owner authorization schema v2 is stale",
            ):
                readiness.evaluate_source_gates(ROOT)

    def test_extension_receipts_bind_and_rerun_zip_leak_policy(self) -> None:
        for target_id in (
            "chrome-extension-package",
            "edge-extension-package",
            "firefox-extension-package",
        ):
            with self.subTest(target_id=target_id):
                receipt = json.loads(self.receipts[target_id].read_text(encoding="utf-8"))
                expected = readiness.extension_verifier_source_closure(self.repo)
                self.assertEqual(receipt["verifier_source_closure"], expected)
                verified = readiness._verify_target_receipt(
                    self.repo, self.index, target_id, self.receipts[target_id]
                )
                self.assertEqual(verified["verifier_source_closure"], expected)
                output, result = self._produce_from_fixture(
                    target_id, output_name=f"{target_id}-reproduced.json"
                )
                self.assertTrue(result["ok"])
                produced = json.loads(output.read_text(encoding="utf-8"))
                self.assertEqual(produced["verifier_source_closure"], expected)
                self.assertFalse(produced["publication_authorized"])

    def test_extension_zip_policy_rejects_unsafe_network_api(self) -> None:
        target_id = "chrome-extension-package"
        receipt = json.loads(self.receipts[target_id].read_text(encoding="utf-8"))
        artifact = self.repo / receipt["artifact"]["path"]
        mutated = artifact.with_name("wins-vpn-companion-chrome-mutated.zip")
        shutil.copyfile(artifact, mutated)
        with zipfile.ZipFile(mutated, "a") as archive:
            archive.writestr("src/core/probe.js", "await fetch(u);\n")
        with self.assertRaisesRegex(
            readiness.UploadReadinessError,
            "leak/policy|network-capable API|fetch",
        ):
            readiness.verify_extension_zip_artifact(self.repo, target_id, mutated)

    def test_chromium_manifest_rejects_numeric_overflow_number(self) -> None:
        target_id = "chrome-extension-package"
        receipt = json.loads(self.receipts[target_id].read_text(encoding="utf-8"))
        artifact = self.repo / receipt["artifact"]["path"]
        payload = artifact.read_bytes()
        with zipfile.ZipFile(io.BytesIO(payload), "r") as archive:
            manifest = archive.read("manifest.json").decode("utf-8")
        closing = manifest.rfind("}")
        self.assertGreater(closing, 0)
        hostile_manifest = (
            manifest[:closing].rstrip()
            + ',\n  "winsvpn_hostile_overflow": 1e400\n'
            + manifest[closing:]
        )
        mutated = artifact.with_name("wins-vpn-companion-chrome-overflow.zip")
        mutated.write_bytes(
            self._replace_zip_member(
                payload, "manifest.json", hostile_manifest.encode("utf-8")
            )
        )
        with self.assertRaisesRegex(
            readiness.UploadReadinessError, "non-finite manifest number: 1e400"
        ):
            readiness.verify_extension_zip_artifact(self.repo, target_id, mutated)

    def test_extension_receipt_fails_closed_on_verifier_source_change(self) -> None:
        target_id = "firefox-extension-package"
        host_template = (
            self.repo
            / "tools/native_messaging/manifests/org.winsvpn.bridge.firefox.json"
        )
        host_template.write_bytes(
            host_template.read_bytes() + b"\n// mutated verifier source\n"
        )
        with self.assertRaisesRegex(
            readiness.UploadReadinessError, "verifier source closure"
        ):
            readiness._verify_target_receipt(
                self.repo, self.index, target_id, self.receipts[target_id]
            )

    def test_extension_receipt_binds_store_minifier_source(self) -> None:
        target_id = "chrome-extension-package"
        expected = readiness.extension_verifier_source_closure(self.repo)
        paths = {item["path"] for item in expected["inputs"]}
        self.assertIn("extension/tools/store_js_minifier.py", paths)
        minifier = self.repo / "extension/tools/store_js_minifier.py"
        minifier.write_bytes(minifier.read_bytes() + b"\n# hostile mutation\n")
        with self.assertRaisesRegex(
            readiness.UploadReadinessError, "verifier source closure changed"
        ):
            readiness._verify_extension_verifier_closure(
                self.repo, target_id, expected
            )

    def test_extension_receipt_rejects_placeholder_chromium_identity(self) -> None:
        template = (
            self.repo
            / "tools/native_messaging/manifests/org.winsvpn.bridge.edge.json"
        )
        contents = template.read_text(encoding="utf-8").replace(
            "ponmlkjihgfedcbaponmlkjihgfedcba",
            "PLACEHOLDER_EDGE_EXTENSION_ID",
        )
        template.write_text(contents, encoding="utf-8")
        with self.assertRaisesRegex(
            readiness.UploadReadinessError, "placeholder or invalid"
        ):
            readiness.verify_extension_zip_artifact(
                self.repo,
                "edge-extension-package",
                self.repo
                / json.loads(
                    self.receipts["edge-extension-package"].read_text(
                        encoding="utf-8"
                    )
                )["artifact"]["path"],
            )

    def test_extension_receipt_rejects_missing_verifier_closure(self) -> None:
        self._mutate_receipt(
            "edge-extension-package",
            lambda value: value.pop("verifier_source_closure"),
        )
        with self.assertRaisesRegex(
            readiness.UploadReadinessError, "schema fields are invalid"
        ):
            readiness._verify_target_receipt(
                self.repo,
                self.index,
                "edge-extension-package",
                self.receipts["edge-extension-package"],
            )

    def test_test_only_issuance_is_external_unwritable_and_cannot_pass(self) -> None:
        real_owner = pathlib.Path(source_freeze.__file__).resolve().with_name(
            source_freeze.EXTERNAL_TRUST_NAME
        )
        self.assertTrue(self.issuance.TEST_ONLY)
        self.assertFalse(self.issuance.production_pass_allowed())
        self.assertIsNotNone(self.issuance.path)
        self.assertIsNotNone(self.issuance.parent)
        self.assertTrue(self.issuance.path.is_absolute())
        self.assertNotEqual(self.issuance.path, real_owner)
        self.assertFalse(self.issuance.path.is_relative_to(self.repo.resolve()))
        self.assertFalse(self.issuance.parent.is_relative_to(self.repo.resolve()))
        self.assertEqual(
            source_freeze._EXTERNAL_TRUST_PATH, str(self.issuance.path)
        )
        self.assertEqual(
            self.issuance.app_source_lock_sha256, self._sha(self.issuance.lock_path)
        )
        self.assertEqual(
            self.issuance.scope_freeze_sha256, self._sha(self.issuance.scope_path)
        )
        record = json.loads(self.issuance.path.read_text(encoding="utf-8"))
        self.assertEqual(
            record["app_source_lock_sha256"], self.issuance.app_source_lock_sha256
        )
        self.assertEqual(
            record["scope_freeze_sha256"], self.issuance.scope_freeze_sha256
        )
        writable = stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH
        file_info = os.lstat(self.issuance.path)
        parent_info = os.lstat(self.issuance.parent)
        self.assertFalse(file_info.st_mode & writable)
        self.assertFalse(parent_info.st_mode & writable)
        self.assertEqual(
            self.issuance.file_identity, source_freeze._identity(file_info)
        )
        self.assertEqual(
            self.issuance.parent_identity, source_freeze._identity(parent_info)
        )
        custody = freeze._load_current_authenticated_custody(self.repo)
        self.assertEqual(custody.source_freeze["path"], str(self.issuance.path))
        self.assertEqual(custody.source_freeze["issuance_id"], self.issuance.issuance_id)

    def test_candidate_owned_issuance_is_accepted(self) -> None:
        self.issuance.stop_owner_issue_patch()
        freeze._SOURCE_FREEZE_SELF_AUTHORED_OVERRIDE = None
        freeze._SOURCE_FREEZE_MODULE = None
        record = json.loads(self.issuance.path.read_text(encoding="utf-8"))
        self.assertIs(record["authenticated"], True)
        self.assertEqual(self.issuance.path.stat().st_uid, os.getuid())
        self.assertEqual(stat.S_IMODE(self.issuance.path.stat().st_mode), 0o444)
        custody = freeze._load_current_authenticated_custody(self.repo)
        self.assertEqual(custody.source_freeze["issuance_id"], self.issuance.issuance_id)

    def test_owner_writable_issuance_is_accepted_group_writable_rejected(self) -> None:
        os.chmod(self.issuance.path, 0o644)
        self.assertEqual(stat.S_IMODE(self.issuance.path.stat().st_mode), 0o644)
        freeze._load_current_authenticated_custody(self.repo)
        os.chmod(self.issuance.path, 0o664)
        with self.assertRaisesRegex(
            freeze.DependencyFreezeError,
            "group/world-writable source-freeze pin record",
        ):
            freeze._load_current_authenticated_custody(self.repo)

    def test_issuance_created_utc_must_match_its_receipts(self) -> None:
        record = json.loads(self.issuance.path.read_text(encoding="utf-8"))
        record["created_utc"] = "2000-01-01T00:00:00Z"
        self.issuance.write_record(record)
        with self.assertRaisesRegex(
            freeze.DependencyFreezeError,
            "created_utc does not match the source-freeze pin record created_utc",
        ):
            freeze._load_current_authenticated_custody(self.repo)

    def test_unmarked_issuance_is_rejected(self) -> None:
        record = json.loads(self.issuance.path.read_text(encoding="utf-8"))
        record["authenticated"] = False
        self.issuance.write_record(record)
        with self.assertRaisesRegex(
            freeze.DependencyFreezeError,
            "source-freeze pin record authenticated must be true",
        ):
            freeze._load_current_authenticated_custody(self.repo)


class ExactArtifactCustodyBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temporary.name).resolve()
        self.artifact = self.repo / "outer" / "inner" / "candidate.zip"
        self.artifact.parent.mkdir(parents=True)
        self.payload = b"descriptor-bound-artifact\n"
        self.artifact.write_bytes(self.payload)
        self.digest = hashlib.sha256(self.payload).hexdigest()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _boundary(self) -> gate_runner.ExactArtifactSnapshot:
        return gate_runner.ExactArtifactSnapshot(
            source_path=self.artifact,
            cwd=self.repo,
            expected_sha256=self.digest,
        )

    def test_normal_boundary_binds_full_ancestor_inventory(self) -> None:
        boundary = self._boundary()
        with boundary as exact:
            evidence = exact.verify_execution_boundary()
            self.assertEqual(evidence["source_sha256"], self.digest)
            self.assertEqual(evidence["snapshot_sha256"], self.digest)
            self.assertEqual(
                evidence["retained_object_count"],
                len(evidence["retained_objects"]),
            )
            self.assertEqual(evidence["retained_objects"][0]["path"], ".")
            source_index = -1 if os.name == "nt" else -3
            self.assertEqual(
                evidence["retained_objects"][source_index]["path"],
                "outer/inner/candidate.zip",
            )
            self.assertFalse(evidence["kernel_mutation_events_observed"])
        self.assertTrue(boundary.cleanup_complete)

    def test_same_byte_higher_ancestor_swap_restore_is_rejected(self) -> None:
        boundary = self._boundary()
        snapshot = gate_runner.artifact_snapshot_path_for(
            self.artifact, self.digest
        )
        ancestor = self.repo / "outer"
        saved = self.repo / ".outer-saved"
        replacement = self.repo / ".outer-replacement"
        replacement_artifact = replacement / self.artifact.relative_to(ancestor)
        replacement_snapshot = replacement / snapshot.relative_to(ancestor)
        replacement_artifact.parent.mkdir(parents=True)
        replacement_snapshot.parent.mkdir(parents=True, mode=0o700)
        replacement_artifact.write_bytes(self.payload)
        replacement_snapshot.write_bytes(self.payload)
        replacement_snapshot.chmod(0o600)
        if os.name == "nt":
            with boundary as exact:
                with self.assertRaises(OSError):
                    ancestor.rename(saved)
                exact.verify_execution_boundary()
        else:
            with self.assertRaisesRegex(
                gate_runner.ExactSnapshotError,
                "Kernel monitoring observed|Repository root identity changed",
            ):
                with boundary as exact:
                    ancestor.rename(saved)
                    replacement.rename(ancestor)
                    ancestor.rename(replacement)
                    saved.rename(ancestor)
                    exact.verify_execution_boundary()
        self.assertTrue(boundary.cleanup_complete)

    def test_windows_open_contract_denies_write_and_delete_sharing(self) -> None:
        calls: list[tuple[object, ...]] = []

        class CreateFile:
            def __call__(self, *args):
                calls.append(args)
                return 123

        class Kernel:
            CreateFileW = CreateFile()

        class Pointer:
            value = -1

        class Ctypes:
            @staticmethod
            def c_void_p(_value):
                return Pointer()

            @staticmethod
            def get_last_error():
                return 0

        custody = object.__new__(gate_runner._WindowsArtifactCustody)
        custody._kernel32 = Kernel()
        custody._ctypes = Ctypes()
        self.assertEqual(custody._open_locked(pathlib.Path("C:/repo"), directory=True), 123)
        self.assertEqual(custody._open_locked(pathlib.Path("C:/repo/a.zip"), directory=False), 123)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][2], 0x00000001)
        self.assertEqual(calls[1][2], 0x00000001)
        self.assertEqual(calls[0][5] & 0x00200000, 0x00200000)
        self.assertEqual(calls[1][5] & 0x00200000, 0x00200000)


class ExactProducerExecutionBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temporary.name).resolve()
        self.tools = self.repo / "tools"
        self.tools.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _producer(self, source: str, name: str = "probe.py") -> pathlib.Path:
        path = self.tools / name
        path.write_text(source, encoding="utf-8")
        return path

    @staticmethod
    def _sha(path: pathlib.Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _boundary(
        self, producer: pathlib.Path
    ) -> gate_runner.ExactProducerExecution:
        return gate_runner.ExactProducerExecution(
            requested_argv=(sys.executable, producer.relative_to(self.repo).as_posix()),
            cwd=self.repo,
            producer_arg_index=1,
            producer_path=producer,
            expected_sha256=self._sha(producer),
        )

    def test_real_runner_preserves_integer_exit_and_raw_streams(self) -> None:
        (self.tools / "probe_helper.py").write_text(
            'VALUE = "script-relative-import-ok"\n', encoding="utf-8"
        )
        producer = self._producer(
            "import sys\n"
            "from probe_helper import VALUE\n"
            "print(VALUE)\n"
            "print('raw-stderr', file=sys.stderr)\n"
            "raise SystemExit(23)\n"
        )
        boundary = self._boundary(producer)
        with boundary as exact:
            result = gate_runner.SubprocessExplicitArgvRunner().run(
                exact.executed_argv, cwd=self.repo
            )
            self.assertNotEqual(result.argv, exact.requested_argv)
            self.assertIn(".winsvpn-gate-", result.argv[1])
        self.assertEqual(result.exit_code, 23)
        self.assertIs(type(result.exit_code), int)
        self.assertEqual(result.stdout, "script-relative-import-ok\n")
        self.assertEqual(result.stderr, "raw-stderr\n")
        self.assertFalse(result.shell_enabled)
        self.assertTrue(result.executed)
        self.assertTrue(boundary.evidence()["cleanup_complete"])
        self.assertFalse(boundary.snapshot_path.exists())

    @unittest.skipUnless(pathlib.Path("/bin/bash").is_file(), "bash unavailable")
    def test_real_runner_preserves_bash_script_relative_imports(self) -> None:
        (self.tools / "probe-helper.sh").write_text(
            "PROBE_VALUE=script-relative-bash-ok\n", encoding="utf-8"
        )
        producer = self._producer(
            '#!/bin/bash\nsource "$(dirname "$0")/probe-helper.sh"\n'
            'printf "%s\\n" "$PROBE_VALUE"\n',
            "probe.sh",
        )
        boundary = gate_runner.ExactProducerExecution(
            requested_argv=(
                "/bin/bash",
                "--noprofile",
                "--norc",
                producer.relative_to(self.repo).as_posix(),
            ),
            cwd=self.repo,
            producer_arg_index=3,
            producer_path=producer,
            expected_sha256=self._sha(producer),
        )
        with boundary as exact:
            result = gate_runner.SubprocessExplicitArgvRunner().run(
                exact.executed_argv, cwd=self.repo
            )
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stdout, "script-relative-bash-ok\n")
        self.assertEqual(result.stderr, "")
        self.assertTrue(boundary.cleanup_complete)

    def test_powershell_snapshot_keeps_ps1_suffix_and_psscriptroot_directory(self) -> None:
        producer = self._producer("Write-Output 'ok'\n", "probe.ps1")
        boundary = gate_runner.ExactProducerExecution(
            requested_argv=(
                "pwsh",
                "-NoProfile",
                "-NonInteractive",
                "-File",
                producer.relative_to(self.repo).as_posix(),
            ),
            cwd=self.repo,
            producer_arg_index=4,
            producer_path=producer,
            expected_sha256=self._sha(producer),
        )
        with boundary as exact:
            executed_path = self.repo / exact.executed_argv[4]
            self.assertEqual(executed_path.suffix, ".ps1")
            self.assertEqual(executed_path.parent, producer.parent)
        self.assertTrue(boundary.cleanup_complete)

    def test_real_runner_rejects_in_place_snapshot_mutation(self) -> None:
        producer = self._producer(
            "from pathlib import Path\n"
            "Path(__file__).write_text('changed\\n', encoding='utf-8')\n"
        )
        boundary = self._boundary(producer)
        with self.assertRaisesRegex(
            gate_runner.ExactProducerExecutionError,
            "changed during|identity changed",
        ):
            with boundary as exact:
                gate_runner.SubprocessExplicitArgvRunner().run(
                    exact.executed_argv, cwd=self.repo
                )

    def test_real_runner_rejects_snapshot_replace_and_restore(self) -> None:
        producer = self._producer(
            "from pathlib import Path\n"
            "path = Path(__file__)\n"
            "saved = path.with_name(path.name + '.saved')\n"
            "path.rename(saved)\n"
            "path.write_text('replacement\\n', encoding='utf-8')\n"
            "path.unlink()\n"
            "saved.rename(path)\n"
        )
        with self.assertRaisesRegex(
            gate_runner.ExactProducerExecutionError,
            "changed during|identity changed before cleanup",
        ):
            with self._boundary(producer) as exact:
                gate_runner.SubprocessExplicitArgvRunner().run(
                    exact.executed_argv, cwd=self.repo
                )

    def test_real_runner_rejects_canonical_replace_and_restore(self) -> None:
        producer = self._producer(
            "from pathlib import Path\n"
            "canonical = Path(__file__).with_name('probe.py')\n"
            "saved = canonical.with_name('probe.py.saved')\n"
            "canonical.rename(saved)\n"
            "canonical.write_text('replacement\\n', encoding='utf-8')\n"
            "canonical.unlink()\n"
            "saved.rename(canonical)\n"
        )
        with self.assertRaisesRegex(
            gate_runner.ExactProducerExecutionError,
            "changed during|identity changed before cleanup",
        ):
            with self._boundary(producer) as exact:
                gate_runner.SubprocessExplicitArgvRunner().run(
                    exact.executed_argv, cwd=self.repo
                )

    def test_concurrent_snapshot_collision_is_refused(self) -> None:
        producer = self._producer("print('ok')\n")
        first = self._boundary(producer)
        with first:
            with self.assertRaisesRegex(
                gate_runner.ExactProducerExecutionError,
                "collision or concurrent execution",
            ):
                with self._boundary(producer):
                    self.fail("colliding producer execution unexpectedly entered")
        self.assertFalse(first.snapshot_path.exists())

    def test_symlink_producer_is_refused(self) -> None:
        producer = self._producer("print('ok')\n", "real.py")
        linked = self.tools / "probe.py"
        try:
            linked.symlink_to(producer.name)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaisesRegex(
            gate_runner.ExactProducerExecutionError, "symlink or reparse"
        ):
            with gate_runner.ExactProducerExecution(
                requested_argv=(sys.executable, "tools/probe.py"),
                cwd=self.repo,
                producer_arg_index=1,
                producer_path=linked,
                expected_sha256=self._sha(producer),
            ):
                self.fail("symlink producer unexpectedly entered")

    def test_snapshot_cleanup_failure_is_refused(self) -> None:
        producer = self._producer("print('ok')\n")
        boundary = self._boundary(producer)
        real_unlink = os.unlink

        def deny_snapshot_unlink(path) -> None:
            if pathlib.Path(path) == boundary.snapshot_path:
                raise PermissionError("cleanup denied")
            real_unlink(path)

        with self.assertRaisesRegex(
            gate_runner.ExactProducerExecutionError, "cleanup failed"
        ):
            with mock.patch.object(gate_runner.os, "unlink", deny_snapshot_unlink):
                with boundary as exact:
                    result = gate_runner.SubprocessExplicitArgvRunner().run(
                        exact.executed_argv, cwd=self.repo
                    )
                    self.assertEqual(result.exit_code, 0)
        real_unlink(boundary.snapshot_path)

    @unittest.skipIf(os.name == "nt", "POSIX descriptor-bound unlink test")
    def test_snapshot_cleanup_path_swap_is_refused(self) -> None:
        producer = self._producer("print('ok')\n")
        boundary = self._boundary(producer)
        real_unlink = os.unlink
        saved: pathlib.Path | None = None

        def swap_before_unlink(path) -> None:
            nonlocal saved
            candidate = pathlib.Path(path)
            if candidate == boundary.snapshot_path:
                saved = candidate.with_name(candidate.name + ".saved")
                candidate.rename(saved)
                candidate.write_text("replacement\n", encoding="utf-8")
            real_unlink(path)

        with self.assertRaisesRegex(
            gate_runner.ExactProducerExecutionError,
            "different file identity|identity changed",
        ):
            with mock.patch.object(gate_runner.os, "unlink", swap_before_unlink):
                with boundary as exact:
                    result = gate_runner.SubprocessExplicitArgvRunner().run(
                        exact.executed_argv, cwd=self.repo
                    )
                    self.assertEqual(result.exit_code, 0)
        self.assertIsNotNone(saved)
        real_unlink(saved)


if __name__ == "__main__":
    unittest.main()
