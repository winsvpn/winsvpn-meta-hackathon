#!/usr/bin/env python3
"""Focused Linux receipt-to-artifact binding tests for the cross-store gate."""

from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock

import tools.linux_cross_store_artifact_gate as gate


ROOT = pathlib.Path(__file__).resolve().parents[1]
RELEASE = "1.0.17+34"
FLUTTER_VERSION = "3.47.6"
FLUTTER_REVISION = "5fc346839b5d0eef006ed8404392afb4dfae428d"


class LinuxReceiptArtifactBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = pathlib.Path(self.temporary.name)
        self.root_patch = mock.patch.object(gate, "ROOT", self.repo)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.snapshots: list[gate.AuthenticatedSnapshot] = []
        self.trust_temp = None
        self._install_release_freeze_fixture_module()
        self._install_freeze_repo()

    def tearDown(self) -> None:
        for snapshot in self.snapshots:
            snapshot.close()
            shutil.rmtree(snapshot.root, ignore_errors=True)
        if getattr(gate.source_freeze, "_EXTERNAL_TRUST_PATH", None) is not None:
            gate.source_freeze._EXTERNAL_TRUST_PATH = None
        self._cleanup_trust_temp()
        self._restore_release_freeze_fixture_module()

    def _cleanup_trust_temp(self) -> None:
        if self.trust_temp is None:
            return
        parent = pathlib.Path(self.trust_temp.name)
        try:
            os.chmod(parent, 0o700)
            for child in parent.iterdir():
                os.chmod(child, 0o644)
        except OSError:
            pass
        self.trust_temp.cleanup()
        self.trust_temp = None

    def _write(self, relative: str, contents: str) -> pathlib.Path:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
        os.chmod(path, 0o644)
        return path

    def _write_json(self, relative: str, record: dict[str, object]) -> pathlib.Path:
        return self._write(
            relative, json.dumps(record, indent=2, sort_keys=True) + "\n"
        )

    def _file_sha256(self, relative: str) -> str:
        return hashlib.sha256((self.repo / relative).read_bytes()).hexdigest()

    def _install_host_lib_aliases(self) -> None:
        freeze = gate.freeze
        for alias, target in freeze.WINDOWS_NATIVE_HOST_LIB_SYMLINK_ALIASES:
            name = pathlib.PurePosixPath(alias).name
            lib_rel = f"lib/{name}"
            if not (self.repo / lib_rel).exists():
                self._write(lib_rel, f"shared {name}\n")
            path = self.repo / alias
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists() or path.is_symlink():
                path.unlink()
            try:
                path.symlink_to(target)
            except (OSError, NotImplementedError) as exc:
                raise unittest.SkipTest(
                    "Symlink creation is unavailable on this host"
                ) from exc

    def _rewrite_anchored(self, path: pathlib.Path, record: dict[str, object]) -> None:
        anchor = path.with_name(path.name + ".sha256")
        os.chmod(path, 0o600)
        if anchor.exists():
            os.chmod(anchor, 0o600)
        path.write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        anchor.write_text(
            f"{digest}  {path.name}\n", encoding="ascii"
        )

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
        module_name = f"_winsvpn_linux_receipt_release_freeze_{id(self):x}"
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

        self.fixture_freeze_module = module
        self.fixture_freeze_module_name = module_name
        self.original_gate_freeze = gate.freeze
        self.original_gate_source_freeze = gate.source_freeze
        self.original_fixture_mode = module._FIXTURE_MODE
        self.original_trust_path = module._SOURCE_FREEZE_TRUST_PATH
        self.original_self_authored = module._SOURCE_FREEZE_SELF_AUTHORED_OVERRIDE
        self.original_source_module = module._SOURCE_FREEZE_MODULE
        self.original_artifact_validator = module._validate_release_artifact_bytes

        def fixture_artifact_validator(
            platform: str, target: str, artifact_name: str, payload: bytes
        ) -> None:
            if (
                platform == "linux"
                and target == "linux-x64"
                and artifact_name == "wins-vpn-linux-x64.tar.gz"
                and payload == b"linux-package-bytes"
            ):
                return
            raise module.DependencyFreezeError(
                "test-only Linux artifact validator rejected non-fixture bytes"
            )

        module._FIXTURE_MODE = True
        module._validate_release_artifact_bytes = fixture_artifact_validator
        source_module = module._source_freeze_module()
        gate.freeze = module
        gate.source_freeze = source_module
        self.addCleanup(self._restore_release_freeze_fixture_module)

    def _restore_release_freeze_fixture_module(self) -> None:
        module = getattr(self, "fixture_freeze_module", None)
        if module is None:
            return
        gate.freeze = self.original_gate_freeze
        gate.source_freeze = self.original_gate_source_freeze
        module._FIXTURE_MODE = self.original_fixture_mode
        module._SOURCE_FREEZE_TRUST_PATH = self.original_trust_path
        module._SOURCE_FREEZE_SELF_AUTHORED_OVERRIDE = self.original_self_authored
        module._SOURCE_FREEZE_MODULE = self.original_source_module
        module._validate_release_artifact_bytes = self.original_artifact_validator
        module_name = self.fixture_freeze_module_name
        if sys.modules.get(module_name) is module:
            del sys.modules[module_name]
        self.fixture_freeze_module = None

    def _install_freeze_repo(self) -> None:
        freeze = gate.freeze
        source_freeze = gate.source_freeze
        fixture_support = {
            "tools/release_dependency_freeze.py",
            "tools/release_source_freeze.py",
            "tools/test_release_source_freeze.py",
            "tools/toolchain-pins.json",
        }
        self._write("pubspec.yaml", f"name: wins_vpn\nversion: {RELEASE}\n")
        self._write("pubspec.lock", "packages: {}\n")
        self._write("lib/main.dart", "void main() {}\n")
        self._write("assets/icon.txt", "shared\n")
        for platform, roots in freeze.PLATFORM_ROOTS.items():
            for root in roots:
                self._write(f"{root}/{platform}-input.txt", f"{platform}\n")
        for platform, paths in freeze.PLATFORM_NATIVE_EXTRA_PATHS.items():
            for path in paths:
                self._write(path, f"{platform} extra input\n")
        for paths in freeze.PLATFORM_PRODUCER_PATHS.values():
            for path in paths:
                if path in fixture_support:
                    continue
                self._write(path, f"producer: {path}\n")
        for path in freeze.PLATFORM_BUILD_PRODUCERS.values():
            if path == freeze.PLATFORM_BUILD_PRODUCERS["linux"]:
                self._write(path, self._linux_witnessed_producer_source())
            else:
                self._write(path, f"build producer: {path}\n")
        identity = ROOT / gate.RELEASE_IDENTITY_PATH
        dest = self.repo / gate.RELEASE_IDENTITY_PATH
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(identity.read_bytes())
        os.chmod(dest, 0o644)
        freeze_dir = f".artifacts/release-freeze-{RELEASE}"
        issuance_id = "a" * 32
        created_utc = source_freeze._utc_now_text()
        digest = "0" * 64
        scope_relative = f"{freeze_dir}/{freeze.SCOPE_FREEZE_NAME}"
        self._write_json(
            scope_relative,
            {
                "schema_version": 1,
                "contract": source_freeze.SCOPE_CONTRACT,
                "release": RELEASE,
                "scope_frozen": True,
                "source_fingerprint_sha256": digest,
                "publication_locked": True,
                "issuance_id": issuance_id,
                "created_utc": created_utc,
            },
        )
        scope_sha256 = self._file_sha256(scope_relative)
        lock_relative = f"{freeze_dir}/{freeze.APP_SOURCE_LOCK_NAME}"
        self._write_json(
            lock_relative,
            {
                "schema_version": 1,
                "contract": freeze.APP_SOURCE_LOCK_CONTRACT,
                "release": RELEASE,
                "scope_frozen": True,
                "publication_locked": True,
                "scope_freeze_sha256": scope_sha256,
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
                "issuance_id": issuance_id,
                "created_utc": created_utc,
            },
        )
        lock_sha256 = self._file_sha256(lock_relative)
        self._write_json(
            f"{freeze_dir}/{freeze.SOURCE_FREEZE_RECEIPT_NAME}",
            {
                "schema_version": 1,
                "contract": freeze.SOURCE_FREEZE_RECEIPT_CONTRACT,
                "release": RELEASE,
                "created_utc": created_utc,
                "issuance_id": issuance_id,
                "authenticated": True,
                "issuer": freeze.SOURCE_FREEZE_RECEIPT_ISSUER,
                "app_source_lock": {
                    "path": lock_relative,
                    "sha256": lock_sha256,
                },
            },
        )
        pin_relative = "tools/toolchain-pins.json"
        self._write_json(
            f"{freeze_dir}/{freeze.TOOLCHAIN_CUSTODY_RECEIPT_NAME}",
            {
                "schema_version": 1,
                "contract": freeze.TOOLCHAIN_CUSTODY_RECEIPT_CONTRACT,
                "release": RELEASE,
                "created_utc": created_utc,
                "issuance_id": "b" * 32,
                "authenticated": True,
                "issuer": freeze.TOOLCHAIN_CUSTODY_RECEIPT_ISSUER,
                "pin": {
                    "path": pin_relative,
                    "sha256": self._file_sha256(pin_relative),
                },
                "toolchain": {
                    "name": "flutter",
                    "version": FLUTTER_VERSION,
                    "revision": FLUTTER_REVISION,
                },
            },
        )
        self.trust_temp = tempfile.TemporaryDirectory(prefix="winsvpn-linux-sf-trust-")
        self.addCleanup(self._cleanup_trust_temp)
        trust_parent = pathlib.Path(self.trust_temp.name).resolve()
        trust_path = trust_parent / source_freeze.EXTERNAL_TRUST_NAME
        if trust_path.is_relative_to(self.repo) or trust_parent.is_relative_to(self.repo):
            raise AssertionError("test-only issuance must live outside the candidate repository")
        trust_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "contract": source_freeze.EXTERNAL_TRUST_CONTRACT,
                    "release": RELEASE,
                    "created_utc": created_utc,
                    "issuance_id": issuance_id,
                    "authenticated": True,
                    "issuer": source_freeze.EXTERNAL_TRUST_ISSUER,
                    "app_source_lock_sha256": lock_sha256,
                    "scope_freeze_sha256": scope_sha256,
                    "website_stage_sha256": None,
                    "controller_sha256": hashlib.sha256(
                        pathlib.Path(source_freeze.__file__).resolve().read_bytes()
                    ).hexdigest(),
                    "test_sha256": hashlib.sha256(
                        (self.repo / "tools" / source_freeze.TEST_NAME).read_bytes()
                    ).hexdigest(),
                    "manifest_sha256": hashlib.sha256(
                        (
                            self.repo / "tools" / source_freeze.TOOLCHAIN_PIN_NAME
                        ).read_bytes()
                    ).hexdigest(),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        os.chmod(trust_path, 0o444)
        os.chmod(trust_parent, 0o555)
        source_freeze._EXTERNAL_TRUST_PATH = str(trust_path)
        freeze._SOURCE_FREEZE_TRUST_PATH = str(trust_path)
        freeze._SOURCE_FREEZE_SELF_AUTHORED_OVERRIDE = False
        freeze._SOURCE_FREEZE_MODULE = None
        self._install_host_lib_aliases()
        self.output = self.repo / ".artifacts" / "freeze"
        self.shared_path = self.output / "SHARED_INPUTS.json"
        freeze.create_shared_manifest(self.repo, self.shared_path, "sr1")
        for platform in freeze.PLATFORM_ROOTS:
            freeze.create_platform_manifest(
                self.repo,
                platform,
                self.shared_path,
                self.output / f"{platform.upper()}_INPUTS.json",
            )
        self.index = self.output / "RELEASE_INPUT_INDEX.json"
        freeze.create_release_index(self.repo, self.output, self.index)

    def _linux_witnessed_producer_source(self) -> str:
        freeze = gate.freeze
        return (
            "#!/bin/sh\n"
            "''':'\n"
            "if [ \"${1:-}\" = \"--verify\" ]; then exit 0; fi\n"
            "exec /usr/bin/python3 \"$0\" \"$@\"\n"
            "':'''\n"
            "# WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_V2\n"
            "import os\n"
            "import re\n"
            "import sys\n"
            f"SWITCH = {freeze.BUILD_ATTEMPT_SWITCH!r}\n"
            f"CONTRACT = {freeze.BUILD_ATTEMPT_CONTRACT!r}\n"
            "if sys.argv[1:] != [SWITCH]:\n"
            "    raise SystemExit(0)\n"
            "if os.environ.get('WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_CONTRACT') != CONTRACT:\n"
            "    raise SystemExit(65)\n"
            "nonce = os.environ.get('WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_NONCE', '')\n"
            "if re.fullmatch(r'[0-9a-f]{64}', nonce) is None:\n"
            "    raise SystemExit(66)\n"
            "output_fd_text = os.environ.get('WINS_RELEASE_DEPENDENCY_OUTPUT_FD', '')\n"
            "if not output_fd_text.isdecimal():\n"
            "    raise SystemExit(67)\n"
            "output_fd = int(output_fd_text)\n"
            "with os.fdopen(os.dup(output_fd), 'wb', closefd=True) as output:\n"
            "    output.write(b'linux-package-bytes')\n"
            "    output.flush()\n"
        )

    def _create_bound_receipt(
        self, *, namespace: str = "fixture", payload: bytes = b"linux-package-bytes"
    ) -> tuple[pathlib.Path, pathlib.Path]:
        freeze = gate.freeze
        receipt_dir = (
            self.repo / ".artifacts/release-build-receipts/linux" / namespace
        )
        receipt_dir.mkdir(parents=True, exist_ok=False)
        begin = receipt_dir / "LINUX_BUILD_BEGIN.json"
        receipt = receipt_dir / "LINUX_BUILD_RECEIPT.json"
        artifact = self.repo / ".artifacts/linux/wins-vpn-linux-x64.tar.gz"
        freeze.begin_build_receipt(self.repo, self.index, "linux", begin)
        artifact.parent.mkdir(parents=True, exist_ok=True)
        self.assertEqual(payload, b"linux-package-bytes")
        freeze.finish_build_receipt(
            self.repo,
            self.index,
            "linux",
            begin,
            artifact,
            freeze.PLATFORM_BUILD_PRODUCERS["linux"],
            "flutter",
            FLUTTER_VERSION,
            FLUTTER_REVISION,
            "linux-x64",
            receipt,
        )
        return artifact, receipt

    def _snapshot(self, artifact: pathlib.Path) -> gate.AuthenticatedSnapshot:
        snapshot = gate._snapshot_artifact(artifact.resolve(), "Linux package artifact")
        self.snapshots.append(snapshot)
        return snapshot

    def test_real_receipt_binds_descriptor_snapshot_origin(self) -> None:
        artifact, receipt = self._create_bound_receipt()
        snapshot = self._snapshot(artifact)
        calls: list[object] = []
        real = gate.freeze.verify_build_receipt

        def wrapped(
            repo: pathlib.Path,
            index_path: pathlib.Path,
            platform: str,
            receipt_path: pathlib.Path,
            artifact_path: pathlib.Path | None = None,
        ) -> dict[str, object]:
            calls.append(artifact_path)
            self.assertIsNotNone(artifact_path)
            self.assertEqual(pathlib.Path(artifact_path).resolve(), snapshot.origin.resolve())
            return real(repo, index_path, platform, receipt_path, artifact_path)

        with mock.patch.object(gate.freeze, "verify_build_receipt", side_effect=wrapped):
            bound = gate._verify_build_provenance(snapshot, "linux-x64")
        self.assertEqual(bound.resolve(), receipt.resolve())
        self.assertEqual(calls, [snapshot.origin])
        record = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(record["artifact"]["sha256"], snapshot.digest)
        self.assertEqual(record["toolchain"]["target"], "linux-x64")
        self.assertEqual(record["release"], RELEASE)
        self.assertEqual(
            record["producer"]["path"], gate.freeze.PLATFORM_BUILD_PRODUCERS["linux"]
        )
        self.assertEqual(set(record["source_freeze"]), gate.freeze.CUSTODY_BINDING_KEYS)
        self.assertEqual(set(record["toolchain_custody"]), gate.freeze.CUSTODY_BINDING_KEYS)

    def test_mismatched_artifact_fails_closed(self) -> None:
        artifact, _receipt = self._create_bound_receipt()
        artifact.write_bytes(b"different-linux-package-bytes")
        snapshot = self._snapshot(artifact)
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            r"exactly one current immutable Linux build receipt must bind the artifact|owner/build-system blocker|OWNER-BLOCKED|no immutable source/dependency closure",
        ):
            gate._verify_build_provenance(snapshot, "linux-x64")

    def test_swapped_origin_after_receipt_verify_fails_closed(self) -> None:
        artifact, _receipt = self._create_bound_receipt()
        snapshot = self._snapshot(artifact)
        real = gate.freeze.verify_build_receipt

        def swap_after_verify(
            repo: pathlib.Path,
            index_path: pathlib.Path,
            platform: str,
            receipt_path: pathlib.Path,
            artifact_path: pathlib.Path | None = None,
        ) -> dict[str, object]:
            result = real(repo, index_path, platform, receipt_path, artifact_path)
            artifact.write_bytes(artifact.read_bytes() + b"X")
            return result

        with (
            mock.patch.object(
                gate.freeze, "verify_build_receipt", side_effect=swap_after_verify
            ),
            self.assertRaisesRegex(
                gate.LinuxArtifactGateError, "swapped or restored"
            ),
        ):
            gate._verify_build_provenance(snapshot, "linux-x64")

    def test_stale_receipt_fails_closed(self) -> None:
        artifact, receipt = self._create_bound_receipt()
        snapshot = self._snapshot(artifact)
        record = json.loads(receipt.read_text(encoding="utf-8"))
        stale = (
            dt.datetime.now(tz=dt.timezone.utc) - dt.timedelta(days=10)
        ).isoformat().replace("+00:00", "Z")
        record["begun_utc"] = stale
        record["finished_utc"] = stale
        self._rewrite_anchored(receipt, record)
        begin = self.repo / str(record["build_begin_receipt"]["path"])
        begin_record = json.loads(begin.read_text(encoding="utf-8"))
        begin_record["begun_utc"] = stale
        self._rewrite_anchored(begin, begin_record)
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "stale|does not bind the artifact"
        ):
            gate._verify_build_provenance(snapshot, "linux-x64")

    def test_synthetic_receipt_is_not_swallowed(self) -> None:
        artifact, valid = self._create_bound_receipt()
        snapshot = self._snapshot(artifact)
        synthetic_dir = (
            self.repo / ".artifacts/release-build-receipts/linux/aaa-synthetic"
        )
        synthetic = synthetic_dir / "LINUX_BUILD_RECEIPT.json"
        synthetic_dir.mkdir(parents=True, exist_ok=True)
        synthetic.write_text(
            json.dumps(
                {
                    "artifact": {
                        "name": artifact.name,
                        "size_bytes": snapshot.size,
                        "sha256": snapshot.digest,
                        "modified_time_ns": snapshot.origin_identity[6],
                    },
                    "toolchain": {
                        "name": "flutter",
                        "version": FLUTTER_VERSION,
                        "revision": FLUTTER_REVISION,
                        "target": "linux-x64",
                    },
                    "release": RELEASE,
                    "platform": "linux",
                    "publication_authorized": False,
                    "release_input_index": {
                        "path": ".artifacts/missing-index.json",
                        "sha256": "0" * 64,
                    },
                    "producer": {
                        "path": "tools/not-the-linux-producer.sh",
                        "sha256": "c" * 64,
                    },
                    "source_freeze": {
                        "path": ".artifacts/missing-source-freeze.json",
                        "sha256": "d" * 64,
                        "issuance_id": "e" * 32,
                    },
                    "toolchain_custody": {
                        "path": ".artifacts/missing-toolchain-custody.json",
                        "sha256": "f" * 64,
                        "issuance_id": "1" * 32,
                    },
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        self.assertTrue(valid.exists())
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "does not bind the artifact"
        ):
            gate._verify_build_provenance(snapshot, "linux-x64")

    def test_none_origin_fails_closed_without_calling_verifier(self) -> None:
        calls: list[object] = []

        def forbidden(*_args: object, **_kwargs: object) -> dict[str, object]:
            calls.append((_args, _kwargs))
            raise AssertionError("verify_build_receipt must not run without an origin")

        snapshot = gate.AuthenticatedSnapshot(
            origin=None,  # type: ignore[arg-type]
            path=self.repo / "missing.bin",
            fd=-1,
            origin_identity=(0, 0, 0, 0, 0, 0, 0, 0),
            identity=(0, 0, 0, 0, 0, 0, 0, 0),
            digest="0" * 64,
            size=1,
            root=self.repo,
        )
        with (
            mock.patch.object(gate.freeze, "verify_build_receipt", side_effect=forbidden),
            self.assertRaisesRegex(
                gate.LinuxArtifactGateError,
                "descriptor-bound immutable artifact snapshot origin",
            ),
        ):
            gate._verify_build_provenance(snapshot, "linux-x64")
        self.assertEqual(calls, [])

    def test_copied_receipt_reuse_fails_closed(self) -> None:
        artifact, receipt = self._create_bound_receipt()
        reused = (
            self.repo / ".artifacts/release-build-receipts/linux/reused/LINUX_BUILD_RECEIPT.json"
        )
        reused.parent.mkdir(parents=True)
        shutil.copy2(receipt, reused)
        shutil.copy2(
            receipt.with_name(receipt.name + ".sha256"),
            reused.with_name(reused.name + ".sha256"),
        )
        snapshot = self._snapshot(artifact)
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            r"receipt reuse|journal binding changed|does not bind the artifact",
        ):
            gate._verify_build_provenance(snapshot, "linux-x64")

    def test_store_closure_does_not_convert_receipt_reuse_into_pending(self) -> None:
        artifact, receipt = self._create_bound_receipt()
        reused = (
            self.repo / ".artifacts/release-build-receipts/linux/reused/LINUX_BUILD_RECEIPT.json"
        )
        reused.parent.mkdir(parents=True)
        shutil.copy2(receipt, reused)
        shutil.copy2(
            receipt.with_name(receipt.name + ".sha256"),
            reused.with_name(reused.name + ".sha256"),
        )
        snapshot = self._snapshot(artifact)
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            r"receipt reuse|journal binding changed|does not bind the artifact",
        ) as raised:
            gate._verify_store_package_closure(snapshot, "x64", "Snap")
        self.assertNotIn("owner/build-system blocker", str(raised.exception))

    def test_mixed_architecture_receipt_fails_closed(self) -> None:
        artifact, _receipt = self._create_bound_receipt()
        snapshot = self._snapshot(artifact)
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            r"exactly one current immutable Linux build receipt must bind the artifact|owner/build-system blocker|OWNER-BLOCKED|no immutable source/dependency closure",
        ):
            gate._verify_build_provenance(snapshot, "linux-arm64")

    def test_invented_deb_target_is_unsupported(self) -> None:
        artifact, _receipt = self._create_bound_receipt()
        snapshot = self._snapshot(artifact)
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "unsupported exact Linux receipt architecture target"
        ):
            gate._verify_build_provenance(snapshot, "linux-x64-deb")

    def test_stale_release_hash_fails_closed(self) -> None:
        artifact, receipt = self._create_bound_receipt()
        snapshot = self._snapshot(artifact)
        record = json.loads(receipt.read_text(encoding="utf-8"))
        record["artifact"]["sha256"] = "0" * 64
        self._rewrite_anchored(receipt, record)
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            r"exactly one|does not bind the artifact|owner/build-system blocker|OWNER-BLOCKED|no immutable source/dependency closure",
        ):
            gate._verify_build_provenance(snapshot, "linux-x64")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_symlink_receipt_is_not_accepted(self) -> None:
        artifact, receipt = self._create_bound_receipt()
        linked = (
            self.repo / ".artifacts/release-build-receipts/linux/linked/LINUX_BUILD_RECEIPT.json"
        )
        linked.parent.mkdir(parents=True)
        os.symlink(os.path.relpath(receipt, linked.parent), linked)
        snapshot = self._snapshot(artifact)
        bound = gate._verify_build_provenance(snapshot, "linux-x64")
        self.assertEqual(bound.resolve(), receipt.resolve())
        receipt.unlink()
        receipt.with_name(receipt.name + ".sha256").unlink()
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            r"exactly one current immutable Linux build receipt must bind the artifact|owner/build-system blocker|OWNER-BLOCKED|no immutable source/dependency closure",
        ):
            gate._verify_build_provenance(snapshot, "linux-x64")

    @unittest.skipUnless(hasattr(os, "link"), "hard links unavailable")
    def test_hardlinked_receipt_fails_closed(self) -> None:
        artifact, receipt = self._create_bound_receipt()
        linked = (
            self.repo / ".artifacts/release-build-receipts/linux/hard/LINUX_BUILD_RECEIPT.json"
        )
        linked.parent.mkdir(parents=True)
        os.link(receipt, linked)
        snapshot = self._snapshot(artifact)
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError,
            r"exactly one current immutable Linux build receipt must bind the artifact|owner/build-system blocker|OWNER-BLOCKED|no immutable source/dependency closure",
        ):
            gate._verify_build_provenance(snapshot, "linux-x64")

    def test_missing_receipt_evidence_is_pending_for_store_packages(self) -> None:
        artifact, receipt = self._create_bound_receipt()
        receipt.unlink()
        receipt.with_name(receipt.name + ".sha256").unlink()
        snapshot = self._snapshot(artifact)
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "owner/build-system blocker"
        ):
            gate._verify_store_package_closure(snapshot, "x64", "Snap")

    def test_duplicate_json_key_receipt_fails_closed(self) -> None:
        artifact, receipt = self._create_bound_receipt()
        snapshot = self._snapshot(artifact)
        poisoned = (
            self.repo / ".artifacts/release-build-receipts/linux/poison/LINUX_BUILD_RECEIPT.json"
        )
        poisoned.parent.mkdir(parents=True)
        poisoned.write_text(
            '{"artifact":{"sha256":"%s"},"platform":"linux","platform":"windows"}\n'
            % snapshot.digest,
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "duplicate JSON key"
        ):
            gate._verify_build_provenance(snapshot, "linux-x64")

    def test_path_swapped_receipt_origin_is_not_pending(self) -> None:
        artifact, _receipt = self._create_bound_receipt()
        snapshot = self._snapshot(artifact)
        real = gate.freeze.verify_build_receipt

        def swap_after_verify(
            repo: pathlib.Path,
            index_path: pathlib.Path,
            platform: str,
            receipt_path: pathlib.Path,
            artifact_path: pathlib.Path | None = None,
        ) -> dict[str, object]:
            result = real(repo, index_path, platform, receipt_path, artifact_path)
            artifact.write_bytes(artifact.read_bytes() + b"X")
            return result

        with (
            mock.patch.object(
                gate.freeze, "verify_build_receipt", side_effect=swap_after_verify
            ),
            self.assertRaisesRegex(
                gate.LinuxArtifactGateError, "swapped or restored"
            ) as raised,
        ):
            gate._verify_store_package_closure(snapshot, "x64", "Snap")
        self.assertNotIn("owner/build-system blocker", str(raised.exception))


class LinuxUploadReceiptPendingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temporary.name)
        identity = self.repo / gate.RELEASE_IDENTITY_PATH
        identity.parent.mkdir(parents=True, exist_ok=True)
        identity.write_bytes((ROOT / gate.RELEASE_IDENTITY_PATH).read_bytes())
        self.root_patch = mock.patch.object(gate, "ROOT", self.repo)
        self.root_patch.start()

    def tearDown(self) -> None:
        self.root_patch.stop()
        self.temporary.cleanup()

    def test_missing_and_invented_upload_receipts_stay_pending_or_fail_closed(self) -> None:
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "pending without owner evidence"
        ):
            gate.bind_linux_package_upload_receipts({}, {})
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "unsupported exact Linux package/upload target"
        ):
            gate.bind_package_upload_receipt(
                "linux-x64-deb",
                {},
                artifact_sha256="a" * 64,
                artifact_bytes=8,
            )
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "unsupported exact Linux package/upload target"
        ):
            gate.bind_package_upload_receipt(
                "linux-x64-appimage",
                {},
                artifact_sha256="a" * 64,
                artifact_bytes=8,
            )

    def test_unauthenticated_upload_receipt_fails_closed(self) -> None:
        spec = gate.LINUX_PACKAGE_UPLOAD_TARGETS["linux-x64-package"]
        digest = hashlib.sha256(b"linux-x64").hexdigest()
        record = {
            "ok": True,
            "schema_version": 2,
            "contract": gate.PACKAGE_UPLOAD_RECEIPT_CONTRACT,
            "release": gate.CANONICAL_RELEASE,
            "target_id": "linux-x64-package",
            "platform": "linux",
            "artifact": {
                "path": f".artifacts/linux/{spec['artifact_name']}",
                "sha256": digest,
                "bytes": 8,
            },
            "build_receipt": {
                "path": ".artifacts/receipt.json",
                "sha256": hashlib.sha256(b"build").hexdigest(),
                "target": spec["build_receipt_target"],
            },
            "producer": {
                "id": spec["producer"],
                "path": spec["producer"],
                "sha256": hashlib.sha256(b"producer").hexdigest(),
            },
            "package_identity": {
                "name": spec["package_name"],
                "appstream_version": "1.0.17",
                "debian_version": "1.0.17-34",
                "elf_machine": 62,
            },
            "architectures": ["x64"],
            "signing": {
                "contract": spec["signing_contract"],
                "trust_anchor": spec["trust_anchor"],
                "status": spec["signing_status"],
            },
            "store_evidence": {
                "surface": spec["store_surface"],
                "status": "not_uploaded",
                "metadata_sha256": "0" * 64,
            },
            "descriptor": {
                "path": "tools/linux_cross_store_artifact_gate.py",
                "sha256": hashlib.sha256(b"desc").hexdigest(),
            },
            "source_freeze": {
                "path": ".artifacts/source.json",
                "sha256": hashlib.sha256(b"source").hexdigest(),
            },
            "obfuscation_privacy": {
                "path": "tools/release_obfuscation_contract.py",
                "sha256": hashlib.sha256(b"privacy").hexdigest(),
            },
            "winn3_descriptor_ring_attestation": gate._winn3_descriptor_ring_attestation_receipt_binding(
                "linux-x64-package"
            ),
            "publication_authorized": False,
            "upload_attempted": False,
            "owner_authorization": {
                "contract": gate.OWNER_AUTHORIZATION_CONTRACT,
                "schema_version": 2,
                "status": "pending",
                "credentials_authorized": False,
                "upload_authorized": False,
            },
        }
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "schema fields are invalid"
        ):
            gate.bind_package_upload_receipt(
                "linux-x64-package",
                record,
                artifact_sha256=digest,
                artifact_bytes=8,
            )

    def test_stale_release_and_publication_approval_fail_closed(self) -> None:
        spec = gate.LINUX_PACKAGE_UPLOAD_TARGETS["linux-x64-package"]
        digest = hashlib.sha256(b"linux-x64").hexdigest()
        record = {
            "ok": True,
            "schema_version": 2,
            "contract": gate.PACKAGE_UPLOAD_RECEIPT_CONTRACT,
            "release": "9.9.9+999",
            "target_id": "linux-x64-package",
            "platform": "linux",
            "artifact": {
                "path": f".artifacts/linux/{spec['artifact_name']}",
                "sha256": digest,
                "bytes": 8,
            },
            "build_receipt": {
                "path": ".artifacts/receipt.json",
                "sha256": hashlib.sha256(b"build").hexdigest(),
                "target": spec["build_receipt_target"],
            },
            "producer": {
                "id": spec["producer"],
                "path": spec["producer"],
                "sha256": hashlib.sha256(b"producer").hexdigest(),
            },
            "package_identity": {
                "name": spec["package_name"],
                "appstream_version": "1.0.17",
                "debian_version": "1.0.17-34",
                "elf_machine": 62,
            },
            "architectures": ["x64"],
            "signing": {
                "contract": spec["signing_contract"],
                "trust_anchor": spec["trust_anchor"],
                "status": spec["signing_status"],
            },
            "store_evidence": {
                "surface": spec["store_surface"],
                "status": "not_uploaded",
                "metadata_sha256": "0" * 64,
            },
            "descriptor": {
                "path": "tools/linux_cross_store_artifact_gate.py",
                "sha256": hashlib.sha256(b"desc").hexdigest(),
            },
            "source_freeze": {
                "path": ".artifacts/source.json",
                "sha256": hashlib.sha256(b"source").hexdigest(),
            },
            "obfuscation_privacy": {
                "path": "tools/release_obfuscation_contract.py",
                "sha256": hashlib.sha256(b"privacy").hexdigest(),
            },
            "winn3_descriptor_ring_attestation": gate._winn3_descriptor_ring_attestation_receipt_binding(
                "linux-x64-package"
            ),
            "publication_authorized": False,
            "upload_attempted": False,
            "owner_authorization": {
                "contract": gate.OWNER_AUTHORIZATION_CONTRACT,
                "schema_version": 2,
                "status": "pending",
                "credentials_authorized": False,
                "upload_authorized": False,
            },
            "authentication": {
                "authenticated": True,
                "issuer": gate.UPLOAD_RECEIPT_ISSUER,
                "run_id": hashlib.sha256(b"run").hexdigest(),
                "nonce": hashlib.sha256(b"nonce").hexdigest(),
                "issued_at": "2026-08-25T00:00:00+00:00",
                "challenge": hashlib.sha256(b"challenge").hexdigest() * 2,
                "target_id": "linux-x64-package",
                "architectures": ["x64"],
                "release": "9.9.9+999",
                "artifact_sha256": digest,
                "artifact_bytes": 8,
            },
        }
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "receipt binding is invalid"
        ):
            gate.bind_package_upload_receipt(
                "linux-x64-package",
                record,
                artifact_sha256=digest,
                artifact_bytes=8,
            )
        record["release"] = gate.CANONICAL_RELEASE
        record["publication_authorized"] = True
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "receipt binding is invalid"
        ):
            gate.bind_package_upload_receipt(
                "linux-x64-package",
                record,
                artifact_sha256=digest,
                artifact_bytes=8,
            )
        record["publication_authorized"] = False
        record["artifact"]["path"] = ".artifacts/../tools/wins-vpn-linux-x64.tar.gz"
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "canonical repository-relative path"
        ):
            gate.bind_package_upload_receipt(
                "linux-x64-package",
                record,
                artifact_sha256=digest,
                artifact_bytes=8,
            )


class LinuxWinn3DescriptorRingAttestationReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temporary.name)
        identity = self.repo / gate.RELEASE_IDENTITY_PATH
        identity.parent.mkdir(parents=True, exist_ok=True)
        identity.write_bytes((ROOT / gate.RELEASE_IDENTITY_PATH).read_bytes())
        self.root_patch = mock.patch.object(gate, "ROOT", self.repo)
        self.root_patch.start()

    def tearDown(self) -> None:
        self.root_patch.stop()
        self.temporary.cleanup()

    def _receipt(self, target_id: str) -> dict[str, object]:
        spec = gate.LINUX_PACKAGE_UPLOAD_TARGETS[target_id]
        identity: dict[str, object] = {
            "name": spec["package_name"],
            "appstream_version": "1.0.17",
            "debian_version": "1.0.17-34",
        }
        if "elf_machine" in spec["identity_keys"]:
            identity["elf_machine"] = spec["elf_machine"]
        else:
            identity["elf_machines"] = dict(spec["elf_machines"])
        digest = hashlib.sha256(target_id.encode("ascii")).hexdigest()
        return {
            "ok": True,
            "schema_version": 2,
            "contract": gate.PACKAGE_UPLOAD_RECEIPT_CONTRACT,
            "release": gate.CANONICAL_RELEASE,
            "target_id": target_id,
            "platform": "linux",
            "artifact": {
                "path": f".artifacts/linux/{spec['artifact_name']}",
                "sha256": digest,
                "bytes": 8,
            },
            "build_receipt": {
                "path": ".artifacts/receipt.json",
                "sha256": hashlib.sha256(b"build").hexdigest(),
                "target": spec["build_receipt_target"],
            },
            "producer": {
                "id": spec["producer"],
                "path": spec["producer"],
                "sha256": hashlib.sha256(b"producer").hexdigest(),
            },
            "package_identity": identity,
            "architectures": list(spec["architectures"]),
            "signing": {
                "contract": spec["signing_contract"],
                "trust_anchor": spec["trust_anchor"],
                "status": spec["signing_status"],
            },
            "store_evidence": {
                "surface": spec["store_surface"],
                "status": "not_uploaded",
                "metadata_sha256": "0" * 64,
            },
            "descriptor": {
                "path": "tools/linux_cross_store_artifact_gate.py",
                "sha256": hashlib.sha256(b"desc").hexdigest(),
            },
            "source_freeze": {
                "path": ".artifacts/source.json",
                "sha256": hashlib.sha256(b"source").hexdigest(),
            },
            "obfuscation_privacy": {
                "path": "tools/release_obfuscation_contract.py",
                "sha256": hashlib.sha256(b"privacy").hexdigest(),
            },
            "winn3_descriptor_ring_attestation": gate._winn3_descriptor_ring_attestation_receipt_binding(
                target_id
            ),
            "publication_authorized": False,
            "upload_attempted": False,
            "owner_authorization": {
                "contract": gate.OWNER_AUTHORIZATION_CONTRACT,
                "schema_version": 2,
                "status": "pending",
                "credentials_authorized": False,
                "upload_authorized": False,
            },
            "authentication": {
                "authenticated": True,
                "issuer": gate.UPLOAD_RECEIPT_ISSUER,
                "run_id": hashlib.sha256(f"{target_id}-run".encode("ascii")).hexdigest(),
                "nonce": hashlib.sha256(f"{target_id}-nonce".encode("ascii")).hexdigest(),
                "issued_at": "2026-08-25T00:00:00+00:00",
                "challenge": hashlib.sha256(f"{target_id}-challenge".encode("ascii")).hexdigest() * 2,
                "target_id": target_id,
                "architectures": list(spec["architectures"]),
                "release": gate.CANONICAL_RELEASE,
                "artifact_sha256": digest,
                "artifact_bytes": 8,
            },
        }

    def test_tarball_debian_snap_and_flathub_bind_exact_attestation(self) -> None:
        from tools.winn3_descriptor_ring_defines import (
            CEREMONY_MANIFEST_SHA256,
            REVIEWED_RING_SHA256,
        )

        expected_hash = hashlib.sha256(
            gate._canonical_winn3_descriptor_ring_attestation(
                gate.REVIEWED_WINN3_DESCRIPTOR_RING_SHA256
            )
        ).hexdigest()
        expected_paths = {
            "linux-x64-package": "winn3-descriptor-ring-attestation.json",
            "linux-arm64-package": "winn3-descriptor-ring-attestation.json",
            "linux-snap-manifest": "share/winsvpn/winn3-descriptor-ring-attestation.json",
            "linux-flathub-manifest": (
                "files/share/winsvpn/winn3-descriptor-ring-attestation.json"
            ),
        }
        expected_verified = {
            "linux-x64-package": "lib/libapp.so",
            "linux-arm64-package": "lib/libapp.so",
            "linux-snap-manifest": "lib/libapp.so",
            "linux-flathub-manifest": "files/lib/winsvpn/libapp.so",
        }
        expected_arches = {
            "linux-x64-package": ["x64"],
            "linux-arm64-package": ["arm64"],
            "linux-snap-manifest": ["x64", "arm64"],
            "linux-flathub-manifest": ["x64", "arm64"],
        }
        self.assertEqual(
            gate.REVIEWED_WINN3_DESCRIPTOR_RING_SHA256, REVIEWED_RING_SHA256
        )
        self.assertNotEqual(
            gate.REVIEWED_WINN3_DESCRIPTOR_RING_SHA256, CEREMONY_MANIFEST_SHA256
        )
        self.assertNotIn(
            "winn3_descriptor_ring_attestation",
            gate.UNIQUE_UPLOAD_RECEIPT_DIGEST_FIELDS,
        )
        self.assertNotIn(
            "winn3_descriptor_ring_attestation",
            gate.SHARED_UPLOAD_RECEIPT_PATH_FIELDS,
        )
        for target_id, packaged_path in expected_paths.items():
            bound = gate._winn3_descriptor_ring_attestation_receipt_binding(target_id)
            self.assertEqual(bound["path"], packaged_path)
            self.assertEqual(bound["mode"], gate.WINN3_DESCRIPTOR_RING_ATTESTATION_MODE)
            self.assertEqual(bound["mode"], 0o644)
            self.assertEqual(bound["sha256"], expected_hash)
            self.assertEqual(
                bound["identity_sha256"], gate.REVIEWED_WINN3_DESCRIPTOR_RING_SHA256
            )
            self.assertEqual(bound["architectures"], expected_arches[target_id])
            self.assertEqual(bound["verified_artifact"], expected_verified[target_id])
            record = self._receipt(target_id)
            digest = str(record["artifact"]["sha256"])
            with self.assertRaisesRegex(
                gate.LinuxArtifactGateError,
                "pending without owner evidence|receipt was swapped or does not bind|OWNER-BLOCKED|schema fields are invalid",
            ):
                gate.bind_package_upload_receipt(
                    target_id,
                    record,
                    artifact_sha256=digest,
                    artifact_bytes=8,
                )

    def test_missing_attestation_field_fails_closed(self) -> None:
        record = self._receipt("linux-x64-package")
        del record["winn3_descriptor_ring_attestation"]
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "schema fields are invalid"
        ):
            gate.bind_package_upload_receipt(
                "linux-x64-package",
                record,
                artifact_sha256=str(record["artifact"]["sha256"]),
                artifact_bytes=8,
            )

    def test_wrong_path_mode_hash_architecture_and_identity_fail_closed(self) -> None:
        from tools.winn3_descriptor_ring_defines import CEREMONY_MANIFEST_SHA256

        record = self._receipt("linux-x64-package")
        digest = str(record["artifact"]["sha256"])
        attestation = dict(record["winn3_descriptor_ring_attestation"])
        record["winn3_descriptor_ring_attestation"] = dict(attestation)
        record["winn3_descriptor_ring_attestation"]["path"] = (
            "share/winsvpn/winn3-descriptor-ring-attestation.json"
        )
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "attestation path is not exact"
        ):
            gate.bind_package_upload_receipt(
                "linux-x64-package",
                record,
                artifact_sha256=digest,
                artifact_bytes=8,
            )
        record["winn3_descriptor_ring_attestation"] = dict(attestation)
        record["winn3_descriptor_ring_attestation"]["mode"] = 0o755
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "attestation mode is not exact"
        ):
            gate.bind_package_upload_receipt(
                "linux-x64-package",
                record,
                artifact_sha256=digest,
                artifact_bytes=8,
            )
        record["winn3_descriptor_ring_attestation"] = dict(attestation)
        record["winn3_descriptor_ring_attestation"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "stale or unbound"
        ):
            gate.bind_package_upload_receipt(
                "linux-x64-package",
                record,
                artifact_sha256=digest,
                artifact_bytes=8,
            )
        record["winn3_descriptor_ring_attestation"] = dict(attestation)
        record["winn3_descriptor_ring_attestation"]["architectures"] = ["arm64"]
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "architecture inventory is not exact"
        ):
            gate.bind_package_upload_receipt(
                "linux-x64-package",
                record,
                artifact_sha256=digest,
                artifact_bytes=8,
            )
        record["winn3_descriptor_ring_attestation"] = dict(attestation)
        record["winn3_descriptor_ring_attestation"]["identity_sha256"] = (
            CEREMONY_MANIFEST_SHA256
        )
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "stale or unbound"
        ):
            gate.bind_package_upload_receipt(
                "linux-x64-package",
                record,
                artifact_sha256=digest,
                artifact_bytes=8,
            )

    def test_snap_and_flathub_cannot_cross_bind_attestation_paths(self) -> None:
        snap = self._receipt("linux-snap-manifest")
        flathub = self._receipt("linux-flathub-manifest")
        snap["winn3_descriptor_ring_attestation"] = dict(
            flathub["winn3_descriptor_ring_attestation"]
        )
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "attestation path is not exact"
        ):
            gate.bind_package_upload_receipt(
                "linux-snap-manifest",
                snap,
                artifact_sha256=str(snap["artifact"]["sha256"]),
                artifact_bytes=8,
            )
        flathub["winn3_descriptor_ring_attestation"] = (
            gate._winn3_descriptor_ring_attestation_receipt_binding(
                "linux-snap-manifest"
            )
        )
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "attestation path is not exact"
        ):
            gate.bind_package_upload_receipt(
                "linux-flathub-manifest",
                flathub,
                artifact_sha256=str(flathub["artifact"]["sha256"]),
                artifact_bytes=8,
            )
        mixed = self._receipt("linux-flathub-manifest")
        mixed["winn3_descriptor_ring_attestation"] = dict(
            mixed["winn3_descriptor_ring_attestation"]
        )
        mixed["winn3_descriptor_ring_attestation"]["architectures"] = ["x64"]
        with self.assertRaisesRegex(
            gate.LinuxArtifactGateError, "architecture inventory is not exact"
        ):
            gate.bind_package_upload_receipt(
                "linux-flathub-manifest",
                mixed,
                artifact_sha256=str(mixed["artifact"]["sha256"]),
                artifact_bytes=8,
            )


if __name__ == "__main__":
    unittest.main()
