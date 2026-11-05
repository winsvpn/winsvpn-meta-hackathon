#!/usr/bin/env python3
"""Fail-closed tests for the native-app/website post-freeze boundary."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT = pathlib.Path(__file__).with_name("release_source_freeze.py")
if str(SCRIPT.parent) not in sys.path:
    sys.path.insert(0, str(SCRIPT.parent))
import release_source_freeze as freeze


def file_hash(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def control_trust_fields() -> dict[str, str]:
    return {
        "controller_sha256": file_hash(SCRIPT),
        "test_sha256": file_hash(pathlib.Path(__file__).resolve()),
        "manifest_sha256": file_hash(SCRIPT.with_name(freeze.TOOLCHAIN_PIN_NAME)),
    }


class ReleaseSourceFreezeTests(unittest.TestCase):
    def setUp(self) -> None:
        freeze._FIXTURE_MODE = True
        freeze._PRODUCTION_REQUIRED = False
        freeze.INTENTIONALLY_UNTRACKED_SOURCE = frozenset()
        self.temp = tempfile.TemporaryDirectory(prefix="wins-release-freeze-test-")
        self.trust_temp = tempfile.TemporaryDirectory(prefix="wins-source-freeze-trust-")
        self.repo = pathlib.Path(self.temp.name)
        self.trust_path = pathlib.Path(self.trust_temp.name) / freeze.EXTERNAL_TRUST_NAME
        self.issuance_id = "a" * 32
        self.created_utc = freeze._utc_now_text()
        (self.repo / "lib").mkdir()
        (self.repo / "web").mkdir()
        native_host = set(freeze.SOURCE_PATHS_NATIVE_HOST)
        for relative in freeze.SOURCE_PATHS_APP:
            if relative in {"pubspec.yaml", "pubspec.lock", "lib"} or relative in native_host:
                continue
            directory = self.repo / relative
            directory.mkdir(parents=True, exist_ok=True)
            (directory / ".release-freeze-input").write_text(
                f"{relative}\n", encoding="utf-8"
            )
        (self.repo / "pubspec.yaml").write_text("version: 1.2.3+4\n", encoding="utf-8")
        (self.repo / "pubspec.lock").write_text("packages: {}\n", encoding="utf-8")
        (self.repo / "lib" / "main.dart").write_text("const app = 1;\n", encoding="utf-8")
        for relative in freeze.SOURCE_PATHS_NATIVE_HOST:
            path = self.repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"{relative}\n", encoding="utf-8")
        self.install_host_aliases()
        (self.repo / "web" / "index.html").write_text("<span>pending</span>\n", encoding="utf-8")
        (self.repo / "web" / "_worker.js").write_text("export default {};\n", encoding="utf-8")
        self.freeze_dir = self.repo / ".artifacts" / "release-freeze-1.2.3+4"
        self.freeze_dir.mkdir(parents=True)
        app = freeze.tree_state(self.repo, freeze.SOURCE_PATHS_APP)
        web = freeze.tree_state(self.repo, freeze.SOURCE_PATHS_WEBSITE)
        immutable_web = freeze.tree_state(
            self.repo,
            freeze.SOURCE_PATHS_WEBSITE,
            ("web/index.html",),
        )
        combined = freeze.tree_state(self.repo, freeze.SOURCE_PATHS_COMBINED)
        self.frozen_combined = combined.sha256
        scope = {
            "schema_version": 1,
            "contract": freeze.SCOPE_CONTRACT,
            "release": "1.2.3+4",
            "scope_frozen": True,
            "source_fingerprint_sha256": combined.sha256,
            "publication_locked": True,
            "issuance_id": self.issuance_id,
            "created_utc": self.created_utc,
        }
        self.scope_path = self.freeze_dir / "SCOPE_FREEZE.json"
        self.scope_path.write_text(json.dumps(scope), encoding="utf-8")
        self.lock_path = self.freeze_dir / "APP_SOURCE_LOCK.json"
        lock = {
            "schema_version": 1,
            "contract": freeze.LOCK_CONTRACT,
            "release": "1.2.3+4",
            "scope_frozen": True,
            "publication_locked": True,
            "scope_freeze_sha256": file_hash(self.scope_path),
            "frozen_combined_source_fingerprint_sha256": combined.sha256,
            "frozen_combined_source_file_count": combined.file_count,
            "app_source_contract": freeze.APP_SOURCE_CONTRACT,
            "app_source_fingerprint_sha256": app.sha256,
            "app_source_file_count": app.file_count,
            "website_source_contract": freeze.WEBSITE_SOURCE_CONTRACT,
            "website_source_fingerprint_sha256_at_freeze": web.sha256,
            "website_source_file_count_at_freeze": web.file_count,
            "website_index_sha256_at_freeze": file_hash(self.repo / "web" / "index.html"),
            "immutable_website_source_fingerprint_sha256_at_freeze": immutable_web.sha256,
            "immutable_website_source_file_count_at_freeze": immutable_web.file_count,
            "website_mutable_paths_after_scope_freeze": ["web/index.html"],
            "website_staging_allowed_after_scope_freeze": True,
            "issuance_id": self.issuance_id,
            "created_utc": self.created_utc,
        }
        self.lock_path.write_text(json.dumps(lock), encoding="utf-8")
        self.issue_current_trust()

    def tearDown(self) -> None:
        freeze._POST_TREE_CAPTURE_HOOK = None
        freeze._POST_DIRECTORY_BIND_HOOK = None
        freeze._POST_FINAL_CAPTURE_HOOK = None
        freeze._EXTERNAL_TRUST_PATH = None
        freeze._FIXTURE_MODE = False
        freeze._PRODUCTION_REQUIRED = False
        freeze.INTENTIONALLY_UNTRACKED_SOURCE = frozenset()
        self.trust_temp.cleanup()
        self.temp.cleanup()

    def install_host_aliases(self) -> None:
        for alias, target in freeze.SOURCE_SYMLINK_ALIASES:
            lib_name = pathlib.PurePosixPath(alias).name
            lib_path = self.repo / "lib" / lib_name
            if not lib_path.exists():
                lib_path.write_text(f"const {lib_name} = 1;\n", encoding="utf-8")
            alias_path = self.repo / alias
            alias_path.parent.mkdir(parents=True, exist_ok=True)
            if alias_path.exists() or alias_path.is_symlink():
                alias_path.unlink()
            alias_path.symlink_to(target)

    def restore_alias(self, alias: str, target: str) -> None:
        path = self.repo / alias
        if path.exists() or path.is_symlink():
            path.unlink()
        path.symlink_to(target)

    def issue_current_trust(self) -> None:
        stage_path = self.freeze_dir / "WEBSITE_STAGE.json"
        stage_digest = None
        if stage_path.is_file():
            stage_digest = file_hash(stage_path)
        record = {
            "schema_version": 1,
            "contract": freeze.EXTERNAL_TRUST_CONTRACT,
            "release": "1.2.3+4",
            "created_utc": self.created_utc,
            "issuance_id": self.issuance_id,
            "authenticated": True,
            "issuer": freeze.EXTERNAL_TRUST_ISSUER,
            "app_source_lock_sha256": file_hash(self.lock_path),
            "scope_freeze_sha256": file_hash(self.scope_path),
            "website_stage_sha256": stage_digest,
        }
        record.update(control_trust_fields())
        if self.trust_path.exists() or self.trust_path.is_symlink():
            os.chmod(self.trust_path, 0o644)
            self.trust_path.unlink()
        self.trust_path.write_text(json.dumps(record), encoding="utf-8")
        # A committed pin record is an ordinary file owned by the checkout user.
        os.chmod(self.trust_path, 0o644)
        freeze._EXTERNAL_TRUST_PATH = str(self.trust_path)

    def rewrite_trust(self, record: dict) -> None:
        os.chmod(self.trust_path, 0o644)
        self.trust_path.write_text(json.dumps(record), encoding="utf-8")

    def rewrite_json(self, path: pathlib.Path, record: dict) -> None:
        path.write_text(json.dumps(record), encoding="utf-8")

    def assert_fails(self, message: str) -> None:
        with self.assertRaisesRegex(freeze.SourceFreezeError, message):
            freeze.verified_release_source_state(self.repo)

    @contextlib.contextmanager
    def capture_hook(self, hook):
        previous = freeze._POST_TREE_CAPTURE_HOOK
        freeze._POST_TREE_CAPTURE_HOOK = hook
        try:
            yield
        finally:
            freeze._POST_TREE_CAPTURE_HOOK = previous

    @contextlib.contextmanager
    def directory_bind_hook(self, hook):
        previous = freeze._POST_DIRECTORY_BIND_HOOK
        freeze._POST_DIRECTORY_BIND_HOOK = hook
        try:
            yield
        finally:
            freeze._POST_DIRECTORY_BIND_HOOK = previous

    @contextlib.contextmanager
    def final_capture_hook(self, hook):
        previous = freeze._POST_FINAL_CAPTURE_HOOK
        freeze._POST_FINAL_CAPTURE_HOOK = hook
        try:
            yield
        finally:
            freeze._POST_FINAL_CAPTURE_HOOK = previous

    @contextlib.contextmanager
    def case_sensitive_repo_copy(self):
        staging = pathlib.Path(tempfile.mkdtemp(prefix="wins-source-freeze-cs-"))
        image = staging / "cs.sparseimage"
        mount = staging / "mnt"
        mount.mkdir()
        attached = False
        try:
            subprocess.run(
                [
                    "hdiutil",
                    "create",
                    "-size",
                    "64m",
                    "-fs",
                    "Case-sensitive APFS",
                    "-volname",
                    "WINSSFCS",
                    "-type",
                    "SPARSE",
                    "-ov",
                    str(image),
                ],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["hdiutil", "attach", str(image), "-mountpoint", str(mount)],
                check=True,
                capture_output=True,
            )
            attached = True
            dest = mount / "repo"
            shutil.copytree(self.repo, dest, symlinks=True)
            yield dest
        finally:
            if attached:
                subprocess.run(
                    ["hdiutil", "detach", str(mount), "-force"],
                    check=False,
                    capture_output=True,
                )
            shutil.rmtree(staging, ignore_errors=True)

    def write_valid_stage(self, *, issue: bool = True) -> None:
        lock = json.loads(self.lock_path.read_text(encoding="utf-8"))
        app = freeze.tree_state(self.repo, freeze.SOURCE_PATHS_APP)
        web = freeze.tree_state(self.repo, freeze.SOURCE_PATHS_WEBSITE)
        immutable_web = freeze.tree_state(
            self.repo,
            freeze.SOURCE_PATHS_WEBSITE,
            ("web/index.html",),
        )
        stage = {
            "schema_version": 1,
            "contract": freeze.WEBSITE_STAGE_CONTRACT,
            "release": "1.2.3+4",
            "boundary_lock_sha256": file_hash(self.lock_path),
            "app_source_fingerprint_sha256": app.sha256,
            "app_source_file_count": app.file_count,
            "immutable_website_source_fingerprint_sha256": immutable_web.sha256,
            "immutable_website_source_file_count": immutable_web.file_count,
            "website_index_sha256_before": lock["website_index_sha256_at_freeze"],
            "website_index_sha256_after": file_hash(self.repo / "web" / "index.html"),
            "staged_website_source_fingerprint_sha256": web.sha256,
            "staged_website_source_file_count": web.file_count,
            "mutated_paths": ["web/index.html"],
            "publication_authorized": False,
            "issuance_id": self.issuance_id,
            "created_utc": self.created_utc,
        }
        (self.freeze_dir / "WEBSITE_STAGE.json").write_text(json.dumps(stage), encoding="utf-8")
        if issue:
            self.issue_current_trust()

    def test_baseline_preserves_original_combined_identity(self) -> None:
        state = freeze.verified_release_source_state(self.repo)
        self.assertEqual(state.source_fingerprint_sha256, self.frozen_combined)
        self.assertFalse(state.website_changed_from_freeze)

    def test_app_source_change_fails(self) -> None:
        (self.repo / "lib" / "main.dart").write_text("const app = 2;\n", encoding="utf-8")
        self.assert_fails("app/runtime/installer source fingerprint changed")

    def test_immutable_web_change_and_unexpected_file_fail(self) -> None:
        (self.repo / "web" / "_worker.js").write_text("export default {changed: true};\n", encoding="utf-8")
        self.assert_fails("Immutable website source changed")
        (self.repo / "web" / "_worker.js").write_text("export default {};\n", encoding="utf-8")
        (self.repo / "web" / "unexpected.js").write_text("unexpected\n", encoding="utf-8")
        self.assert_fails("Immutable website source changed")

    def test_index_change_requires_exact_stage_attestation(self) -> None:
        index = self.repo / "web" / "index.html"
        index.write_text("<a href='/downloads/current.exe'>Windows</a>\n", encoding="utf-8")
        self.assert_fails("lacks a valid WEBSITE_STAGE.json")
        self.write_valid_stage()
        state = freeze.verified_release_source_state(self.repo)
        self.assertTrue(state.website_changed_from_freeze)
        self.assertEqual(state.source_fingerprint_sha256, self.frozen_combined)
        index.write_text("<a href='/downloads/swapped.exe'>Windows</a>\n", encoding="utf-8")
        self.assert_fails("website_index_sha256_after")

    def test_stage_cannot_authorize_publication(self) -> None:
        (self.repo / "web" / "index.html").write_text("<a>staged</a>\n", encoding="utf-8")
        self.write_valid_stage()
        stage_path = self.freeze_dir / "WEBSITE_STAGE.json"
        stage = json.loads(stage_path.read_text(encoding="utf-8"))
        stage["publication_authorized"] = True
        stage_path.write_text(json.dumps(stage), encoding="utf-8")
        self.issue_current_trust()
        self.assert_fails("publication_authorized")

    def test_wear_os_and_extension_are_native_app_sources(self) -> None:
        self.assertIn("wear_os", freeze.SOURCE_PATHS_APP)
        self.assertIn("extension", freeze.SOURCE_PATHS_APP)
        wear = self.repo / "wear_os" / ".release-freeze-input"
        wear.write_text("watch changed\n", encoding="utf-8")
        self.assert_fails("app/runtime/installer source fingerprint changed")
        wear.write_text("wear_os\n", encoding="utf-8")
        extension = self.repo / "extension" / ".release-freeze-input"
        extension.write_text("extension changed\n", encoding="utf-8")
        self.assert_fails("app/runtime/installer source fingerprint changed")

    def test_winn_runtime_is_an_app_source(self) -> None:
        self.assertIn("winn_protocol_experimental", freeze.SOURCE_PATHS_APP)
        runtime = self.repo / "winn_protocol_experimental" / ".release-freeze-input"
        runtime.write_text("Winn runtime changed\n", encoding="utf-8")
        self.assert_fails("app/runtime/installer source fingerprint changed")

    def test_native_host_shipping_sources_are_exact_app_inputs(self) -> None:
        expected = (
            "tools/native_messaging/host/pubspec.yaml",
            "tools/native_messaging/host/pubspec.lock",
            "tools/native_messaging/host/bin/wins_bridge_host.dart",
            "tools/native_messaging/install_native_host.sh",
            "tools/native_messaging/native_host_layout.py",
            "tools/native_messaging/render_host_manifest.py",
            "tools/native_messaging/manifests/store_ids.json",
        )
        self.assertEqual(freeze.SOURCE_PATHS_NATIVE_HOST, expected)
        self.assertEqual(freeze.SOURCE_PATHS_APP[-len(expected) :], expected)
        self.assertNotIn("tools", freeze.SOURCE_PATHS_APP)
        self.assertNotIn("tools/native_messaging", freeze.SOURCE_PATHS_APP)
        self.assertNotIn(
            "tools/native_messaging/host/bin/wins_bridge_host_harness.dart",
            freeze.SOURCE_PATHS_APP,
        )
        self.assertNotIn(
            "tools/native_messaging/manifests/org.winsvpn.bridge.chrome.json",
            freeze.SOURCE_PATHS_APP,
        )

    def test_each_native_host_source_mutation_invalidates_app_source_lock(self) -> None:
        for relative in freeze.SOURCE_PATHS_NATIVE_HOST:
            with self.subTest(relative=relative):
                path = self.repo / relative
                original = path.read_text(encoding="utf-8")
                path.write_text(original + "mutated\n", encoding="utf-8")
                self.assert_fails("app/runtime/installer source fingerprint changed")
                path.write_text(original, encoding="utf-8")
        freeze.verified_release_source_state(self.repo)

    def test_each_native_host_source_is_required(self) -> None:
        for relative in freeze.SOURCE_PATHS_NATIVE_HOST:
            with self.subTest(relative=relative):
                path = self.repo / relative
                original = path.read_bytes()
                path.unlink()
                self.assert_fails(f"Required release source root is missing: {relative}")
                path.write_bytes(original)
        freeze.verified_release_source_state(self.repo)

    def test_native_host_cache_and_generated_mutations_do_not_invalidate_lock(self) -> None:
        dart_tool = self.repo / "tools/native_messaging/host/.dart_tool/package_config.json"
        dart_tool.parent.mkdir(parents=True, exist_ok=True)
        dart_tool.write_text("{}\n", encoding="utf-8")
        host_build = self.repo / "tools/native_messaging/host/build/host.dill"
        host_build.parent.mkdir(parents=True, exist_ok=True)
        host_build.write_bytes(b"generated-aot")
        generated = self.repo / "ios/Flutter/Generated.xcconfig"
        generated.parent.mkdir(parents=True, exist_ok=True)
        generated.write_text("FLUTTER_BUILD_NAME=9.9.9\n", encoding="utf-8")
        gradle_cache = self.repo / "android" / ".gradle" / "cache.bin"
        gradle_cache.parent.mkdir(parents=True, exist_ok=True)
        gradle_cache.write_bytes(b"gradle-cache")
        pods = self.repo / "ios" / "Pods" / "cache.bin"
        pods.parent.mkdir(parents=True, exist_ok=True)
        pods.write_bytes(b"pods-cache")
        harness = (
            self.repo / "tools/native_messaging/host/bin/wins_bridge_host_harness.dart"
        )
        harness.write_text("void main() {}\n", encoding="utf-8")
        chrome = (
            self.repo / "tools/native_messaging/manifests/org.winsvpn.bridge.chrome.json"
        )
        chrome.write_text("{}\n", encoding="utf-8")
        freeze.verified_release_source_state(self.repo)

    def test_app_source_lock_schema_is_consumed_by_dependency_freeze(self) -> None:
        self.assertIn("issuance_id", freeze.LOCK_KEYS)
        self.assertIn("created_utc", freeze.LOCK_KEYS)
        self.assertEqual(freeze.LOCK_CONTRACT, "winsvpn-app-source-lock-v1")

    def test_missing_lock_never_reports_a_release_pass(self) -> None:
        self.lock_path.unlink()
        self.assert_fails("No immutable APP_SOURCE_LOCK")

    def test_missing_required_target_source_root_fails_closed(self) -> None:
        path = self.repo / "wear_os" / ".release-freeze-input"
        path.unlink()
        (self.repo / "wear_os").rmdir()
        self.assert_fails("Required release source root is missing: wear_os")

    def test_source_symlink_aliases_are_exact_relative_lib_targets(self) -> None:
        expected = (
            (
                "tools/native_messaging/host/lib/browser_bridge_app_ipc.dart",
                "../../../../lib/browser_bridge_app_ipc.dart",
            ),
            (
                "tools/native_messaging/host/lib/browser_bridge_framing.dart",
                "../../../../lib/browser_bridge_framing.dart",
            ),
            (
                "tools/native_messaging/host/lib/browser_bridge_protocol.dart",
                "../../../../lib/browser_bridge_protocol.dart",
            ),
            (
                "tools/native_messaging/host/lib/browser_bridge_proxy.dart",
                "../../../../lib/browser_bridge_proxy.dart",
            ),
            (
                "tools/native_messaging/host/lib/vpn_config_validation.dart",
                "../../../../lib/vpn_config_validation.dart",
            ),
            (
                "tools/native_messaging/host/lib/windows_system_executable.dart",
                "../../../../lib/windows_system_executable.dart",
            ),
            (
                "tools/native_messaging/host/lib/winn_carrier_profile_keys.dart",
                "../../../../lib/winn_carrier_profile_keys.dart",
            ),
            (
                "tools/native_messaging/host/lib/winn_protocol_dispatch.dart",
                "../../../../lib/winn_protocol_dispatch.dart",
            ),
        )
        self.assertEqual(freeze.SOURCE_SYMLINK_ALIASES, expected)
        self.assertEqual(len(freeze.SOURCE_SYMLINK_ALIASES), 8)
        first = freeze._capture_source_tree(
            freeze._canonical_repo(self.repo),
            freeze.SOURCE_PATHS_APP,
            (),
            freeze._allowed_owners(freeze._canonical_repo(self.repo)),
            False,
        )
        self.assertEqual(first.aliases, expected)
        freeze.verified_release_source_state(self.repo)

    def test_each_host_lib_alias_retarget_to_excluded_lib_build_fails(self) -> None:
        for alias, expected in freeze.SOURCE_SYMLINK_ALIASES:
            with self.subTest(alias=alias):
                path = self.repo / alias
                path.unlink()
                path.symlink_to("../../../../lib/build/evil.dart")
                self.assert_fails("source symlink alias")
                self.restore_alias(alias, expected)
        freeze.verified_release_source_state(self.repo)

    def test_escaping_and_absolute_aliases_fail(self) -> None:
        alias, expected = freeze.SOURCE_SYMLINK_ALIASES[0]
        lib_name = pathlib.PurePosixPath(alias).name
        path = self.repo / alias
        absolute_correct = str((self.repo / "lib" / lib_name).resolve())
        cases = (
            "../../../../../../etc/passwd",
            f"../../../../lib/../build/{lib_name}",
            "/tmp/wins-source-freeze-absolute.dart",
            absolute_correct,
        )
        for target in cases:
            with self.subTest(target=target):
                path.unlink()
                path.symlink_to(target)
                self.assert_fails("source symlink alias")
                self.restore_alias(alias, expected)
        freeze.verified_release_source_state(self.repo)

    def test_chained_aliases_fail(self) -> None:
        alias, expected = freeze.SOURCE_SYMLINK_ALIASES[0]
        path = self.repo / alias
        mid = path.with_name("chain-mid.dart")
        path.unlink()
        mid.symlink_to(expected)
        path.symlink_to(mid.name)
        self.assert_fails("source symlink alias")
        mid.unlink()
        self.restore_alias(alias, expected)

        lib_file = self.repo / "lib" / pathlib.PurePosixPath(alias).name
        payload = lib_file.read_bytes()
        real = self.repo / "lib" / "chained-real.dart"
        real.write_bytes(payload)
        lib_file.unlink()
        lib_file.symlink_to(real.name)
        self.assert_fails("Unexpected source symlink")
        lib_file.unlink()
        lib_file.write_bytes(payload)
        real.unlink()
        freeze.verified_release_source_state(self.repo)

    def test_source_hardlink_is_rejected(self) -> None:
        source = self.repo / "lib" / "main.dart"
        outside = self.repo / "hardlink-outside.dart"
        os.link(source, outside)
        self.assert_fails("link count 1")
        outside.unlink()
        freeze.verified_release_source_state(self.repo)

    def test_post_hash_delete_cannot_pass(self) -> None:
        victim = self.repo / "lib" / "main.dart"

        def hook() -> None:
            victim.unlink()

        with self.capture_hook(hook):
            self.assert_fails("source tree changed during freeze capture")
        victim.write_text("const app = 1;\n", encoding="utf-8")
        freeze.verified_release_source_state(self.repo)

    def test_post_hash_replace_cannot_pass(self) -> None:
        victim = self.repo / "lib" / "main.dart"

        def hook() -> None:
            victim.unlink()
            victim.write_text("const app = replaced;\n", encoding="utf-8")

        with self.capture_hook(hook):
            self.assert_fails("source tree changed during freeze capture")
        victim.write_text("const app = 1;\n", encoding="utf-8")
        freeze.verified_release_source_state(self.repo)

    def test_source_set_insertion_during_capture_fails(self) -> None:
        inserted = self.repo / "lib" / "inserted.dart"

        def hook() -> None:
            inserted.write_text("inserted\n", encoding="utf-8")

        with self.capture_hook(hook):
            self.assert_fails("source tree changed during freeze capture")
        inserted.unlink()
        freeze.verified_release_source_state(self.repo)

    def test_source_set_removal_during_capture_fails(self) -> None:
        victim = self.repo / "lib" / "main.dart"

        def hook() -> None:
            victim.unlink()

        with self.capture_hook(hook):
            self.assert_fails("source tree changed during freeze capture")
        victim.write_text("const app = 1;\n", encoding="utf-8")
        freeze.verified_release_source_state(self.repo)

    def test_unexpected_source_symlink_is_rejected(self) -> None:
        sneaky = self.repo / "lib" / "sneaky.dart"
        sneaky.symlink_to("main.dart")
        self.assert_fails("Unexpected source symlink")
        sneaky.unlink()
        freeze.verified_release_source_state(self.repo)

    def test_missing_store_ids_record_refuses_the_freeze(self) -> None:
        recorded = (
            pathlib.Path(__file__).resolve().parent
            / "native_messaging"
            / "manifests"
            / "store_ids.json"
        )
        self.assertTrue(recorded.is_file())
        self.assertIn(
            "tools/native_messaging/manifests/store_ids.json",
            freeze.SOURCE_PATHS_NATIVE_HOST,
        )
        path = self.repo / "tools/native_messaging/manifests/store_ids.json"
        path.unlink()
        self.assert_fails(
            "Required release source root is missing: "
            "tools/native_messaging/manifests/store_ids.json"
        )
        self.assertTrue(recorded.is_file())

    def test_exclusions_are_exact_reviewed_paths_not_component_names(self) -> None:
        self.assertNotIn("build", freeze.REVIEWED_EXCLUDED_DIRECTORIES)
        self.assertNotIn("pods", freeze.REVIEWED_EXCLUDED_DIRECTORIES)
        self.assertIn("android/.gradle", freeze.REVIEWED_EXCLUDED_DIRECTORIES)
        self.assertIn("ios/Pods", freeze.REVIEWED_EXCLUDED_DIRECTORIES)
        self.assertEqual(len(freeze.SOURCE_SYMLINK_ALIASES), 8)

    def test_parent_directory_swap_cannot_redirect_capture(self) -> None:
        attacker = self.repo / "attacker-lib"
        attacker.mkdir()
        (attacker / "main.dart").write_text("attacker payload\n", encoding="utf-8")
        for alias, _target in freeze.SOURCE_SYMLINK_ALIASES:
            name = pathlib.PurePosixPath(alias).name
            (attacker / name).write_text("attacker alias\n", encoding="utf-8")
        original = self.repo / "lib"
        backup = self.repo / "lib-original"

        def hook(relative: str) -> None:
            if relative != "lib" or backup.exists():
                return
            original.rename(backup)
            attacker.rename(original)

        try:
            with self.directory_bind_hook(hook):
                self.assert_fails(
                    "source directory identity changed while traversing: lib"
                )
        finally:
            current = self.repo / "lib"
            if backup.exists():
                if current.exists() or current.is_symlink():
                    if current.is_symlink():
                        current.unlink()
                    else:
                        current.rename(attacker)
                backup.rename(original)
        freeze.verified_release_source_state(self.repo)

    def test_symlinked_source_directory_is_rejected_not_omitted(self) -> None:
        real = self.repo / "lib" / "nested-real"
        real.mkdir()
        (real / "hidden.dart").write_text("hidden shipping source\n", encoding="utf-8")
        nested = self.repo / "lib" / "nested"
        nested.symlink_to("nested-real")
        self.assert_fails("Unexpected source symlink: lib/nested")
        nested.unlink()
        self.assert_fails("app/runtime/installer source fingerprint changed")
        (real / "hidden.dart").unlink()
        real.rmdir()
        freeze.verified_release_source_state(self.repo)

    def test_case_fold_collision_is_rejected(self) -> None:
        info = os.lstat(self.repo / "lib" / "main.dart")
        identity = freeze._identity(info)
        first = freeze._HashedFile("lib/stra\u00dfe.dart", b"case-a\n", identity, info)
        second = freeze._HashedFile("lib/STRASSE.dart", b"case-b\n", identity, info)
        self.assertEqual("lib/stra\u00dfe.dart".casefold(), "lib/STRASSE.dart".casefold())
        selected: dict[str, freeze._HashedFile] = {}
        freeze._add_selected(selected, first, aggregate_bytes=0)
        with self.assertRaisesRegex(freeze.SourceFreezeError, "case-fold collision"):
            freeze._add_selected(
                selected, second, aggregate_bytes=first.info.st_size
            )
        freeze.verified_release_source_state(self.repo)

    def test_group_world_writable_file_and_directory_are_rejected(self) -> None:
        source = self.repo / "lib" / "main.dart"
        original_file_mode = source.stat().st_mode
        os.chmod(source, 0o666)
        self.assert_fails("group/world-writable source file: lib/main.dart")
        os.chmod(source, original_file_mode)
        lib = self.repo / "lib"
        original_dir_mode = lib.stat().st_mode
        os.chmod(lib, 0o777)
        self.assert_fails("group/world-writable source directory: lib")
        os.chmod(lib, original_dir_mode)
        freeze.verified_release_source_state(self.repo)

    def test_duplicate_key_and_bool_json_are_rejected(self) -> None:
        original_scope = self.scope_path.read_text(encoding="utf-8")
        original_lock = self.lock_path.read_text(encoding="utf-8")
        self.scope_path.write_text(
            original_scope.replace(
                '"schema_version": 1',
                '"schema_version": 1, "schema_version": 1',
                1,
            ),
            encoding="utf-8",
        )
        self.assert_fails("duplicate JSON key: schema_version")
        self.scope_path.write_text(original_scope, encoding="utf-8")
        lock = json.loads(original_lock)
        lock["schema_version"] = True
        self.lock_path.write_text(json.dumps(lock), encoding="utf-8")
        self.issue_current_trust()
        self.assert_fails("APP_SOURCE_LOCK.json schema_version must be a JSON integer")
        lock = json.loads(original_lock)
        lock["extra_field"] = "nope"
        self.lock_path.write_text(json.dumps(lock), encoding="utf-8")
        self.issue_current_trust()
        self.assert_fails("APP_SOURCE_LOCK.json schema fields are invalid")
        lock = json.loads(original_lock)
        del lock["contract"]
        self.lock_path.write_text(json.dumps(lock), encoding="utf-8")
        self.issue_current_trust()
        self.assert_fails("APP_SOURCE_LOCK.json schema fields are invalid")
        self.lock_path.write_text(original_lock, encoding="utf-8")
        self.issue_current_trust()
        freeze.verified_release_source_state(self.repo)

    def test_scope_requires_exact_schema_contract_and_release_identity(self) -> None:
        original = json.loads(self.scope_path.read_text(encoding="utf-8"))
        original["contract"] = "winsvpn-scope-freeze-v0"
        self.scope_path.write_text(json.dumps(original), encoding="utf-8")
        self._rebind_scope_hash()
        self.assert_fails("SCOPE_FREEZE.json has an unsupported schema or contract")
        original["contract"] = freeze.SCOPE_CONTRACT
        original["release"] = "9.9.9+9"
        self.scope_path.write_text(json.dumps(original), encoding="utf-8")
        self._rebind_scope_hash()
        self.assert_fails("Scope-freeze release does not match pubspec.yaml")
        original["release"] = "1.2.3+4"
        original["schema_version"] = True
        self.scope_path.write_text(json.dumps(original), encoding="utf-8")
        self._rebind_scope_hash()
        self.assert_fails("SCOPE_FREEZE.json schema_version must be a JSON integer")
        original["schema_version"] = 1
        self.scope_path.write_text(json.dumps(original), encoding="utf-8")
        self._rebind_scope_hash()
        freeze.verified_release_source_state(self.repo)

    def test_unexpected_excluded_shipping_source_under_source_root_fails(self) -> None:
        shipping = self.repo / "lib" / "build" / "shipping.dart"
        shipping.parent.mkdir()
        shipping.write_text("void shipping() {}\n", encoding="utf-8")
        self.assert_fails(
            "unexpected excluded shipping source under source-bearing root: lib/build"
        )
        shipping.unlink()
        shipping.parent.rmdir()
        freeze.verified_release_source_state(self.repo)

    def test_selected_file_count_and_aggregate_byte_bombs_fail(self) -> None:
        previous_count = freeze.MAX_SOURCE_FILE_COUNT
        previous_bytes = freeze.MAX_SOURCE_AGGREGATE_BYTES
        try:
            freeze.MAX_SOURCE_FILE_COUNT = 3
            self.assert_fails("source file count is outside the accepted bound")
            freeze.MAX_SOURCE_FILE_COUNT = previous_count
            freeze.MAX_SOURCE_AGGREGATE_BYTES = 8
            self.assert_fails("source aggregate size is outside the accepted bound")
        finally:
            freeze.MAX_SOURCE_FILE_COUNT = previous_count
            freeze.MAX_SOURCE_AGGREGATE_BYTES = previous_bytes
        freeze.verified_release_source_state(self.repo)

    def test_app_mutation_after_final_app_capture(self) -> None:
        def hook() -> None:
            (self.repo / "lib" / "main.dart").write_text(
                "const app = mutated-after-final;\n", encoding="utf-8"
            )

        with self.final_capture_hook(hook):
            self.assert_fails("source tree changed after freeze hashing")
        (self.repo / "lib" / "main.dart").write_text(
            "const app = 1;\n", encoding="utf-8"
        )
        freeze.verified_release_source_state(self.repo)

    def test_unstaged_website_mutation_after_website_capture(self) -> None:
        def hook() -> None:
            (self.repo / "web" / "index.html").write_text(
                "<a>unstaged after website capture</a>\n", encoding="utf-8"
            )

        self.assertFalse((self.freeze_dir / "WEBSITE_STAGE.json").exists())
        with self.final_capture_hook(hook):
            self.assert_fails("source tree changed after freeze hashing")
        (self.repo / "web" / "index.html").write_text(
            "<span>pending</span>\n", encoding="utf-8"
        )
        freeze.verified_release_source_state(self.repo)

    def test_repo_root_substitution_while_descriptor_remains_readable(self) -> None:
        attacker = self.repo.parent / (self.repo.name + "-attacker")
        original = self.repo.parent / (self.repo.name + "-original")
        shutil.copytree(self.repo, attacker, symlinks=True)
        (attacker / "lib" / "main.dart").write_text(
            "attacker payload\n", encoding="utf-8"
        )

        def hook() -> None:
            if original.exists():
                return
            self.repo.rename(original)
            attacker.rename(self.repo)

        try:
            with self.final_capture_hook(hook):
                self.assert_fails(
                    "release repository path was replaced while a bound "
                    "descriptor remained readable"
                )
        finally:
            if original.exists():
                if self.repo.exists() or self.repo.is_symlink():
                    if self.repo.is_symlink() or self.repo.is_file():
                        self.repo.unlink()
                    else:
                        shutil.rmtree(self.repo)
                original.rename(self.repo)
            if attacker.exists():
                shutil.rmtree(attacker)
        freeze.verified_release_source_state(self.repo)

    def test_lib_LIB_collision_on_case_sensitive_fixture(self) -> None:
        with self.case_sensitive_repo_copy() as repo:
            lib = repo / "lib"
            colliding = repo / "LIB"
            self.assertTrue(lib.is_dir())
            colliding.mkdir()
            (colliding / "evil.dart").write_text("evil\n", encoding="utf-8")
            self.assertNotEqual(lib.stat().st_ino, colliding.stat().st_ino)
            with self.assertRaisesRegex(
                freeze.SourceFreezeError,
                r"case-fold collision: (lib and LIB|LIB and lib)",
            ):
                freeze.verified_release_source_state(repo)

    def test_website_stage_bool_and_float_counts_are_rejected(self) -> None:
        (self.repo / "web" / "index.html").write_text("<a>staged</a>\n", encoding="utf-8")
        self.write_valid_stage()
        stage_path = self.freeze_dir / "WEBSITE_STAGE.json"
        original = json.loads(stage_path.read_text(encoding="utf-8"))
        self.assertEqual(original["immutable_website_source_file_count"], 1)
        original["immutable_website_source_file_count"] = True
        stage_path.write_text(json.dumps(original), encoding="utf-8")
        self.issue_current_trust()
        self.assert_fails(
            "WEBSITE_STAGE.json immutable_website_source_file_count must be a JSON integer"
        )
        original["immutable_website_source_file_count"] = 1
        original["app_source_file_count"] = float(original["app_source_file_count"])
        original["staged_website_source_file_count"] = float(
            original["staged_website_source_file_count"]
        )
        stage_path.write_text(json.dumps(original), encoding="utf-8")
        self.issue_current_trust()
        self.assert_fails("WEBSITE_STAGE.json app_source_file_count must be a JSON integer")

    def test_not_semver_plus_build_is_rejected(self) -> None:
        original = (self.repo / "pubspec.yaml").read_text(encoding="utf-8")
        cases = (
            "not-semver+4",
            "1.2.3-+4",
            "1.2.3-01+4",
            "1.2.3+01",
            "1.2.3+4.5",
        )
        for version in cases:
            with self.subTest(version=version):
                (self.repo / "pubspec.yaml").write_text(
                    f"version: {version}\n", encoding="utf-8"
                )
                self.assert_fails(
                    r"pubspec.yaml must contain version: <semver>\+<integer>"
                )
        (self.repo / "pubspec.yaml").write_text(original, encoding="utf-8")
        freeze.verified_release_source_state(self.repo)

    def test_frozen_combined_count_100001_is_rejected(self) -> None:
        lock = json.loads(self.lock_path.read_text(encoding="utf-8"))
        original_count = lock["frozen_combined_source_file_count"]
        lock["frozen_combined_source_file_count"] = 100001
        self.lock_path.write_text(json.dumps(lock), encoding="utf-8")
        self.issue_current_trust()
        self.assert_fails(
            "APP_SOURCE_LOCK.json frozen_combined_source_file_count is outside the accepted bound"
        )
        lock["frozen_combined_source_file_count"] = original_count
        self.lock_path.write_text(json.dumps(lock), encoding="utf-8")
        self.issue_current_trust()
        freeze.verified_release_source_state(self.repo)

    def test_receipt_rebind_after_final_capture_fails(self) -> None:
        original = self.lock_path.read_bytes()

        def hook() -> None:
            self.lock_path.unlink()
            self.lock_path.write_bytes(original)

        with self.final_capture_hook(hook):
            self.assert_fails("identity changed before freeze verification returned")
        freeze.verified_release_source_state(self.repo)

    def test_freeze_directory_rebind_after_final_capture_fails(self) -> None:
        original = self.freeze_dir
        backup = original.with_name(original.name + "-original")
        attacker = original.with_name(original.name + "-attacker")

        def hook() -> None:
            if backup.exists():
                return
            shutil.copytree(original, attacker, symlinks=True)
            original.rename(backup)
            attacker.rename(original)

        try:
            with self.final_capture_hook(hook):
                self.assert_fails(
                    r"identity changed before freeze verification returned|"
                    r"freeze receipt directory"
                )
        finally:
            current = self.freeze_dir
            if backup.exists():
                if current.exists() or current.is_symlink():
                    shutil.rmtree(current)
                backup.rename(original)
            if attacker.exists():
                shutil.rmtree(attacker)
        freeze.verified_release_source_state(self.repo)

    def test_mutated_app_cannot_self_author_replacement_lock(self) -> None:
        (self.repo / "lib" / "main.dart").write_text(
            "const app = 2;\n", encoding="utf-8"
        )
        app = freeze.tree_state(self.repo, freeze.SOURCE_PATHS_APP)
        lock = json.loads(self.lock_path.read_text(encoding="utf-8"))
        lock["app_source_fingerprint_sha256"] = app.sha256
        lock["app_source_file_count"] = app.file_count
        self.lock_path.write_text(json.dumps(lock), encoding="utf-8")
        self.assert_fails(
            "APP_SOURCE_LOCK.json does not match the app_source_lock_sha256 pin"
        )

    def test_scope_digest_pin_mismatch_is_refused(self) -> None:
        record = json.loads(self.trust_path.read_text(encoding="utf-8"))
        record["scope_freeze_sha256"] = "0" * 64
        self.rewrite_trust(record)
        self.assert_fails(
            "SCOPE_FREEZE.json does not match the scope_freeze_sha256 pin: "
            f"pinned={'0' * 64} current={file_hash(self.scope_path)}"
        )

    def test_mutated_website_cannot_self_author_replacement_stage(self) -> None:
        (self.repo / "web" / "index.html").write_text("<a>staged</a>\n", encoding="utf-8")
        self.write_valid_stage(issue=False)
        self.assert_fails(
            "missing pin: source-freeze pin record has website_stage_sha256 null"
        )

    def test_missing_pin_record_names_the_pin_and_how_to_measure_it(self) -> None:
        missing = pathlib.Path(self.trust_temp.name) / "missing.trust.json"
        freeze._EXTERNAL_TRUST_PATH = str(missing)
        self.assert_fails(
            f"missing pin: source-freeze pin record {re.escape(str(missing))} is "
            "absent or unreadable; measure each pin with shasum -a 256"
        )

    def test_trust_owned_by_running_uid_in_0644_or_0444_is_accepted(self) -> None:
        info = self.trust_path.stat()
        self.assertEqual(info.st_uid, os.getuid())
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o644)
        record = json.loads(self.trust_path.read_text(encoding="utf-8"))
        self.assertTrue(record["authenticated"] is True)
        state = freeze.verified_release_source_state(self.repo)
        self.assertEqual(state.source_fingerprint_sha256, self.frozen_combined)
        os.chmod(self.trust_path, 0o444)
        freeze.verified_release_source_state(self.repo)
        os.chmod(self.trust_path, 0o600)
        freeze.verified_release_source_state(self.repo)

    def test_group_or_world_writable_trust_is_refused(self) -> None:
        for mode in (0o664, 0o646, 0o666):
            with self.subTest(mode=oct(mode)):
                os.chmod(self.trust_path, mode)
                self.assert_fails(
                    "group/world-writable source-freeze pin record: "
                    f"{re.escape(str(self.trust_path))}"
                )
        os.chmod(self.trust_path, 0o644)
        freeze.verified_release_source_state(self.repo)

    def test_symlinked_trust_is_refused(self) -> None:
        link = self.trust_path.with_name("linked.trust.json")
        link.symlink_to(self.trust_path.name)
        freeze._EXTERNAL_TRUST_PATH = str(link)
        self.assert_fails(
            "source-freeze pin record must be a regular non-symlink file: "
            f"{re.escape(str(link))}"
        )
        freeze._EXTERNAL_TRUST_PATH = str(self.trust_path)
        freeze.verified_release_source_state(self.repo)

    def test_hardlinked_trust_is_refused(self) -> None:
        second = self.trust_path.with_name("second.trust.json")
        os.link(self.trust_path, second)
        self.assert_fails(
            "source-freeze pin record must have link count 1: "
            f"{re.escape(str(self.trust_path))}"
        )
        second.unlink()
        freeze.verified_release_source_state(self.repo)

    def test_issuance_inside_artifacts_is_refused(self) -> None:
        planted = self.freeze_dir / freeze.EXTERNAL_TRUST_NAME
        planted.write_bytes(self.trust_path.read_bytes())
        os.chmod(planted, 0o444)
        freeze._EXTERNAL_TRUST_PATH = str(planted)
        self.assert_fails("source-freeze pin record must not be inside the candidate .artifacts")

    def test_receipts_and_trust_older_than_72_hours_are_accepted(self) -> None:
        for created in ("2000-01-01T00:00:00Z", "2999-01-01T00:00:00Z"):
            with self.subTest(created_utc=created):
                for path in (self.lock_path, self.scope_path):
                    record = json.loads(path.read_text(encoding="utf-8"))
                    record["created_utc"] = created
                    path.write_text(json.dumps(record), encoding="utf-8")
                lock = json.loads(self.lock_path.read_text(encoding="utf-8"))
                lock["scope_freeze_sha256"] = file_hash(self.scope_path)
                self.lock_path.write_text(json.dumps(lock), encoding="utf-8")
                self.created_utc = created
                self.issue_current_trust()
                state = freeze.verified_release_source_state(self.repo)
                self.assertEqual(state.source_fingerprint_sha256, self.frozen_combined)

    def test_receipt_timestamp_format_is_still_validated(self) -> None:
        original = self.created_utc
        for created in ("2000-01-01T00:00:00", "yesterday", "2000-13-01T00:00:00Z"):
            with self.subTest(created_utc=created):
                self.created_utc = created
                self.issue_current_trust()
                self.assert_fails("source-freeze issuance created_utc timestamp is invalid")
        self.created_utc = original
        lock = json.loads(self.lock_path.read_text(encoding="utf-8"))
        lock["created_utc"] = "garbage"
        self.lock_path.write_text(json.dumps(lock), encoding="utf-8")
        self.issue_current_trust()
        self.assert_fails("APP_SOURCE_LOCK.json created_utc timestamp is invalid")

    def test_issuance_mismatch_breaks_transaction_continuity(self) -> None:
        lock = json.loads(self.lock_path.read_text(encoding="utf-8"))
        lock["issuance_id"] = "b" * 32
        self.lock_path.write_text(json.dumps(lock), encoding="utf-8")
        self.issue_current_trust()
        self.assert_fails(
            "APP_SOURCE_LOCK.json issuance_id does not match the source-freeze "
            "pin record issuance_id"
        )

    def test_receipt_created_utc_mismatch_is_refused(self) -> None:
        scope = json.loads(self.scope_path.read_text(encoding="utf-8"))
        scope["created_utc"] = "2000-01-01T00:00:00Z"
        self.scope_path.write_text(json.dumps(scope), encoding="utf-8")
        self._rebind_scope_hash()
        self.assert_fails(
            "SCOPE_FREEZE.json created_utc does not match the source-freeze pin "
            "record created_utc"
        )

    def test_trust_release_mismatch_names_the_pin(self) -> None:
        record = json.loads(self.trust_path.read_text(encoding="utf-8"))
        record["release"] = "0.0.0+0"
        self.rewrite_trust(record)
        self.assert_fails(
            r"source-freeze pin record release 0\.0\.0\+0 does not match "
            r"pubspec.yaml release 1\.2\.3\+4; measure each pin"
        )

    def test_placeholder_shaped_trust_names_each_missing_pin(self) -> None:
        record = json.loads(self.trust_path.read_text(encoding="utf-8"))
        for key in ("controller_sha256", "test_sha256", "manifest_sha256"):
            del record[key]
        self.rewrite_trust(record)
        self.assert_fails(
            "missing pin: source-freeze pin record lacks controller_sha256, "
            "manifest_sha256, test_sha256; measure each pin with shasum -a 256 "
            "and record it in tools/release_source_freeze.trust.json: "
            "controller_sha256 of tools/release_source_freeze.py"
        )

    def test_duplicate_and_malformed_pubspec_version_declarations_fail(self) -> None:
        original = (self.repo / "pubspec.yaml").read_text(encoding="utf-8")
        (self.repo / "pubspec.yaml").write_text(
            "version: 1.2.3+4\nversion: 1.2.3+4\n", encoding="utf-8"
        )
        self.assert_fails("exactly one version declaration")
        (self.repo / "pubspec.yaml").write_text(
            "version: 1.2.3+4\nversion: garbage\n", encoding="utf-8"
        )
        self.assert_fails("exactly one version declaration")
        (self.repo / "pubspec.yaml").write_text(original, encoding="utf-8")
        freeze.verified_release_source_state(self.repo)

    def test_excluded_directory_fifo_symlink_socket_hardlink_and_modes_fail(self) -> None:
        gradle = self.repo / "android" / ".gradle"
        gradle.mkdir(parents=True, exist_ok=True)
        fifo = gradle / "pipe"
        try:
            os.mkfifo(fifo)
        except (OSError, AttributeError, NotImplementedError):
            self.skipTest("FIFO creation is unavailable on this host")
        self.assert_fails("regular file or directory")
        fifo.unlink()
        sneaky = self.repo / "ios" / "Pods" / "sneaky"
        sneaky.parent.mkdir(parents=True, exist_ok=True)
        sneaky.symlink_to("cache.bin")
        self.assert_fails("Unexpected source symlink: ios/Pods/sneaky")
        sneaky.unlink()
        cache = gradle / "cache.bin"
        cache.write_bytes(b"gradle-cache")
        outside = self.repo / "hardlink-cache.bin"
        os.link(cache, outside)
        self.assert_fails("link count 1")
        outside.unlink()
        sock_path = gradle / "sock"
        bound = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            bound.bind(str(sock_path))
            self.assert_fails("regular file or directory")
        except OSError:
            self.skipTest("UNIX socket bind is unavailable on this host")
        finally:
            bound.close()
            if sock_path.exists():
                sock_path.unlink()
        original_mode = gradle.stat().st_mode
        os.chmod(gradle, 0o777)
        self.assert_fails("group/world-writable source directory: android/.gradle")
        os.chmod(gradle, original_mode)
        freeze.verified_release_source_state(self.repo)

    def test_excluded_directory_oversized_sparse_data_fails(self) -> None:
        gradle = self.repo / "android" / ".gradle"
        gradle.mkdir(parents=True, exist_ok=True)
        sparse = gradle / "sparse.bin"
        fd = os.open(sparse, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o644)
        try:
            os.ftruncate(fd, freeze.MAX_SOURCE_FILE_BYTES + 1)
        finally:
            os.close(fd)
        info = os.lstat(sparse)
        self.assertGreater(info.st_size, freeze.MAX_SOURCE_FILE_BYTES)
        self.assert_fails("outside the accepted bound")
        sparse.unlink()
        freeze.verified_release_source_state(self.repo)

    def test_excluded_shipping_source_extension_fails_without_hashing_caches(self) -> None:
        hidden = self.repo / "android" / ".gradle" / "Hidden.dart"
        hidden.parent.mkdir(parents=True, exist_ok=True)
        hidden.write_text("void hidden() {}\n", encoding="utf-8")
        self.assert_fails(
            "unexpected excluded shipping source under source-bearing root: "
            "android/.gradle/Hidden.dart"
        )
        hidden.unlink()
        cache = self.repo / "android" / ".gradle" / "cache.bin"
        cache.write_bytes(b"ordinary-cache")
        freeze.verified_release_source_state(self.repo)

    def test_nfkc_collision_is_rejected(self) -> None:
        info = os.lstat(self.repo / "lib" / "main.dart")
        identity = freeze._identity(info)
        first = freeze._HashedFile("lib/caf\u00e9.dart", b"nfc\n", identity, info)
        second = freeze._HashedFile("lib/cafe\u0301.dart", b"nfd\n", identity, info)
        self.assertEqual(
            freeze._fold_key("lib/caf\u00e9.dart"),
            freeze._fold_key("lib/cafe\u0301.dart"),
        )
        selected: dict[str, freeze._HashedFile] = {}
        freeze._add_selected(selected, first, aggregate_bytes=0)
        with self.assertRaisesRegex(freeze.SourceFreezeError, "case-fold collision"):
            freeze._add_selected(
                selected, second, aggregate_bytes=first.info.st_size
            )
        freeze.verified_release_source_state(self.repo)

    def test_nfkc_collision_on_case_sensitive_fixture(self) -> None:
        with self.case_sensitive_repo_copy() as repo:
            ligature = repo / "lib" / "\ufb01.dart"
            plain = repo / "lib" / "fi.dart"
            ligature.write_text("ligature\n", encoding="utf-8")
            plain.write_text("plain\n", encoding="utf-8")
            self.assertTrue(ligature.exists())
            self.assertTrue(plain.exists())
            self.assertNotEqual(ligature.stat().st_ino, plain.stat().st_ino)
            self.assertEqual(
                freeze._fold_key(ligature.name), freeze._fold_key(plain.name)
            )
            with self.assertRaisesRegex(freeze.SourceFreezeError, "case-fold collision"):
                freeze.verified_release_source_state(repo)

    def test_case_sensitive_apfs_suite_preserves_descriptor_safe_parent_handling(self) -> None:
        with self.case_sensitive_repo_copy() as repo:
            freeze.verified_release_source_state(repo)
            fifo = repo / "android" / ".gradle" / "pipe"
            fifo.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.mkfifo(fifo)
            except (OSError, AttributeError, NotImplementedError):
                self.skipTest("FIFO creation is unavailable on this host")
            with self.assertRaisesRegex(
                freeze.SourceFreezeError, "regular file or directory"
            ):
                freeze.verified_release_source_state(repo)
            fifo.unlink()
            freeze.verified_release_source_state(repo)

    def test_leftover_website_stage_is_partial_publication(self) -> None:
        (self.freeze_dir / freeze.FREEZE_STAGE_NAME).write_text("{}\n", encoding="utf-8")
        self.assert_fails("exact lock/scope/stage publication set")

    def test_extra_freeze_dir_file_is_partial_publication(self) -> None:
        (self.freeze_dir / "APP_SOURCE_LOCK.json.bak").write_text("x\n", encoding="utf-8")
        self.assert_fails("exact lock/scope/stage publication set")

    def test_partial_stage_rollback_cannot_pass(self) -> None:
        (self.repo / "web" / "index.html").write_text("<a>staged</a>\n", encoding="utf-8")
        self.write_valid_stage()
        freeze.verified_release_source_state(self.repo)
        (self.repo / "web" / "index.html").write_text(
            "<span>pending</span>\n", encoding="utf-8"
        )
        record = json.loads(self.trust_path.read_text(encoding="utf-8"))
        record["website_stage_sha256"] = None
        os.chmod(self.trust_path, 0o644)
        self.trust_path.write_text(json.dumps(record), encoding="utf-8")
        os.chmod(self.trust_path, 0o444)
        self.assert_fails("exact lock/scope/stage publication set")

    def test_controller_hash_mismatch_is_producer_injection(self) -> None:
        record = json.loads(self.trust_path.read_text(encoding="utf-8"))
        record["controller_sha256"] = "0" * 64
        os.chmod(self.trust_path, 0o644)
        self.trust_path.write_text(json.dumps(record), encoding="utf-8")
        os.chmod(self.trust_path, 0o444)
        self.assert_fails("producer identity")

    def test_test_hash_mismatch_is_test_injection(self) -> None:
        record = json.loads(self.trust_path.read_text(encoding="utf-8"))
        record["test_sha256"] = "0" * 64
        os.chmod(self.trust_path, 0o644)
        self.trust_path.write_text(json.dumps(record), encoding="utf-8")
        os.chmod(self.trust_path, 0o444)
        self.assert_fails("test identity")

    def test_manifest_hash_mismatch_breaks_toolchain_closure(self) -> None:
        record = json.loads(self.trust_path.read_text(encoding="utf-8"))
        record["manifest_sha256"] = "0" * 64
        os.chmod(self.trust_path, 0o644)
        self.trust_path.write_text(json.dumps(record), encoding="utf-8")
        os.chmod(self.trust_path, 0o444)
        self.assert_fails("toolchain manifest/controller/test closure")

    def test_trust_missing_controller_hash_is_refused(self) -> None:
        record = json.loads(self.trust_path.read_text(encoding="utf-8"))
        del record["controller_sha256"]
        os.chmod(self.trust_path, 0o644)
        self.trust_path.write_text(json.dumps(record), encoding="utf-8")
        os.chmod(self.trust_path, 0o444)
        self.assert_fails("missing pin: source-freeze pin record lacks controller_sha256;")
        record["controller_sha256"] = control_trust_fields()["controller_sha256"]
        record["unexpected"] = "field"
        self.rewrite_trust(record)
        self.assert_fails("source-freeze pin record schema fields are invalid")

    def test_issuance_binds_exact_controller_test_and_manifest(self) -> None:
        fields = control_trust_fields()
        record = json.loads(self.trust_path.read_text(encoding="utf-8"))
        self.assertEqual(record["controller_sha256"], fields["controller_sha256"])
        self.assertEqual(record["test_sha256"], fields["test_sha256"])
        self.assertEqual(record["manifest_sha256"], fields["manifest_sha256"])
        freeze.verified_release_source_state(self.repo)

    def test_fixture_cli_cannot_claim_pass(self) -> None:
        freeze._FIXTURE_MODE = True
        with mock.patch.object(
            sys,
            "argv",
            ["release_source_freeze.py", "--repo", str(self.repo)],
        ):
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(freeze.main(), 1)
        self.assertIn("isolated fixture/test mode cannot authorize", stdout.getvalue())
        self.assertNotIn("RELEASE SOURCE FREEZE: PASS", stdout.getvalue())

    def test_production_cli_without_git_cannot_claim_pass(self) -> None:
        freeze._FIXTURE_MODE = False
        freeze._PRODUCTION_REQUIRED = False
        with mock.patch.object(
            sys,
            "argv",
            ["release_source_freeze.py", "--repo", str(self.repo)],
        ):
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(freeze.main(), 1)
        self.assertIn("requires a Git repository", stdout.getvalue())
        self.assertNotIn("RELEASE SOURCE FREEZE: PASS", stdout.getvalue())

    def test_reviewed_python_major_minor_is_3_14(self) -> None:
        self.assertEqual(freeze.REVIEWED_PYTHON_MAJOR_MINOR, (3, 14))
        self.assertEqual(sys.version_info[:2], (3, 14))
        freeze.verified_release_source_state(self.repo)

    def _rebind_scope_hash(self) -> None:
        lock = json.loads(self.lock_path.read_text(encoding="utf-8"))
        lock["scope_freeze_sha256"] = file_hash(self.scope_path)
        self.lock_path.write_text(json.dumps(lock), encoding="utf-8")
        self.issue_current_trust()


class GitDenominatorTests(unittest.TestCase):
    def setUp(self) -> None:
        if shutil.which("git") is None:
            self.skipTest("git is required for tracked-tree freeze tests")
        freeze._FIXTURE_MODE = False
        freeze._PRODUCTION_REQUIRED = True
        freeze.INTENTIONALLY_UNTRACKED_SOURCE = frozenset()
        self.temporary = tempfile.TemporaryDirectory(prefix="wins-source-freeze-git-")
        self.repo = pathlib.Path(self.temporary.name)

    def tearDown(self) -> None:
        freeze._FIXTURE_MODE = False
        freeze._PRODUCTION_REQUIRED = False
        freeze.INTENTIONALLY_UNTRACKED_SOURCE = frozenset()
        self.temporary.cleanup()

    def _git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        for key in (
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_COMMON_DIR",
        ):
            env.pop(key, None)
        env["GIT_CONFIG_GLOBAL"] = os.devnull
        env["GIT_CONFIG_SYSTEM"] = os.devnull
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        env["GIT_AUTHOR_NAME"] = "Freeze Test"
        env["GIT_AUTHOR_EMAIL"] = "freeze-test@winsvpn.example"
        env["GIT_COMMITTER_NAME"] = "Freeze Test"
        env["GIT_COMMITTER_EMAIL"] = "freeze-test@winsvpn.example"
        env["GIT_TERMINAL_PROMPT"] = "0"
        return subprocess.run(
            ["git", "-C", str(self.repo), *args],
            check=check,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def _write(self, relative: str, contents: str | bytes) -> pathlib.Path:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(contents, bytes):
            path.write_bytes(contents)
        else:
            path.write_text(contents, encoding="utf-8")
        return path

    def _commit_tree(self, files: dict[str, str], *, message: str = "tracked") -> None:
        self._git("init", "-q", "-b", "main")
        self._git("config", "core.autocrlf", "false")
        for relative, contents in files.items():
            self._write(relative, contents)
            self._git("add", "--", relative.replace("\\", "/"))
        self._git(
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "--no-gpg-sign",
            "-m",
            message,
        )

    def _inputs(
        self,
        payloads: tuple[tuple[str, bytes], ...],
        *,
        aliases: tuple[tuple[str, str], ...] = (),
        roots: tuple[str, ...] = ("lib",),
        identities: tuple[tuple[str, tuple[int, ...]], ...] = (),
    ) -> None:
        tree = freeze._bind_production_git_tree(self.repo)
        freeze._require_production_git_inputs(
            tree, payloads, aliases, roots, identities
        )

    def test_production_without_git_is_required(self) -> None:
        with self.assertRaisesRegex(freeze.SourceFreezeError, freeze.GIT_REQUIRED):
            freeze._bind_production_git_tree(self.repo)

    def test_exact_tracked_denominator_passes(self) -> None:
        self._commit_tree({"lib/main.dart": "const app = 1;\n"})
        self._inputs((("lib/main.dart", b"const app = 1;\n"),))

    def test_untracked_shipping_source_is_rejected(self) -> None:
        self._commit_tree({"lib/main.dart": "const app = 1;\n"})
        self._write("lib/evil.dart", "evil\n")
        with self.assertRaisesRegex(
            freeze.SourceFreezeError, freeze.GIT_UNTRACKED_INPUT
        ):
            self._inputs(
                (
                    ("lib/main.dart", b"const app = 1;\n"),
                    ("lib/evil.dart", b"evil\n"),
                )
            )

    def test_tracked_file_omitted_from_hash_set_is_rejected(self) -> None:
        self._commit_tree(
            {
                "lib/main.dart": "const app = 1;\n",
                "lib/other.dart": "other\n",
            }
        )
        with self.assertRaisesRegex(
            freeze.SourceFreezeError, "missing from the freeze denominator"
        ):
            self._inputs((("lib/main.dart", b"const app = 1;\n"),))

    def test_staged_only_source_is_rejected(self) -> None:
        self._commit_tree({"lib/main.dart": "const app = 1;\n"})
        self._write("lib/extra.dart", "staged only\n")
        self._git("add", "--", "lib/extra.dart")
        with self.assertRaisesRegex(
            freeze.SourceFreezeError, freeze.GIT_STAGED_ONLY_INPUT
        ):
            self._inputs(
                (
                    ("lib/main.dart", b"const app = 1;\n"),
                    ("lib/extra.dart", b"staged only\n"),
                )
            )

    def test_index_worktree_split_is_rejected(self) -> None:
        self._commit_tree({"lib/main.dart": "const app = 1;\n"})
        self._write("lib/main.dart", "const app = 2;\n")
        with self.assertRaisesRegex(
            freeze.SourceFreezeError,
            r"index/worktree split|does not match the exact tracked Git tree|CRLF",
        ):
            self._inputs((("lib/main.dart", b"const app = 2;\n"),))

    def test_crlf_worktree_versus_lf_git_is_rejected(self) -> None:
        self._commit_tree({"lib/main.dart": "const app = 1;\n"})
        self._write("lib/main.dart", b"const app = 1;\r\n")
        with self.assertRaisesRegex(freeze.SourceFreezeError, freeze.GIT_CRLF_DRIFT):
            self._inputs((("lib/main.dart", b"const app = 1;\r\n"),))

    def test_executable_bit_metadata_drift_is_rejected(self) -> None:
        self._commit_tree({"lib/main.dart": "const app = 1;\n"})
        source = self.repo / "lib" / "main.dart"
        os.chmod(source, 0o755)
        identity = freeze._identity(os.lstat(source))
        with self.assertRaisesRegex(
            freeze.SourceFreezeError, freeze.GIT_METADATA_DRIFT
        ):
            self._inputs(
                (("lib/main.dart", b"const app = 1;\n"),),
                identities=(("lib/main.dart", identity),),
            )

    def test_assume_unchanged_concealed_drift_is_rejected(self) -> None:
        self._commit_tree({"lib/main.dart": "const app = 1;\n"})
        self._git("update-index", "--assume-unchanged", "--", "lib/main.dart")
        self._write("lib/main.dart", "const app = 2;\n")
        with self.assertRaisesRegex(
            freeze.SourceFreezeError, freeze.GIT_INDEX_WORKTREE_SPLIT
        ):
            self._inputs((("lib/main.dart", b"const app = 2;\n"),))

    def test_skip_worktree_concealed_drift_is_rejected(self) -> None:
        self._commit_tree({"lib/main.dart": "const app = 1;\n"})
        self._git("update-index", "--skip-worktree", "--", "lib/main.dart")
        self._write("lib/main.dart", "const app = 2;\n")
        with self.assertRaisesRegex(
            freeze.SourceFreezeError, freeze.GIT_INDEX_WORKTREE_SPLIT
        ):
            self._inputs((("lib/main.dart", b"const app = 2;\n"),))

    def test_intentionally_untracked_source_is_accepted_when_enumerated(self) -> None:
        freeze.INTENTIONALLY_UNTRACKED_SOURCE = frozenset({"lib/local.dart"})
        self._commit_tree({"lib/main.dart": "const app = 1;\n"})
        self._write("lib/local.dart", "local\n")
        self._inputs(
            (
                ("lib/main.dart", b"const app = 1;\n"),
                ("lib/local.dart", b"local\n"),
            )
        )

    def test_missing_intentionally_untracked_source_is_rejected(self) -> None:
        freeze.INTENTIONALLY_UNTRACKED_SOURCE = frozenset({"lib/local.dart"})
        self._commit_tree({"lib/main.dart": "const app = 1;\n"})
        with self.assertRaisesRegex(
            freeze.SourceFreezeError, "intentionally untracked source is missing"
        ):
            self._inputs((("lib/main.dart", b"const app = 1;\n"),))

    def test_dirty_tree_outside_source_roots_cannot_pass(self) -> None:
        self._commit_tree({"lib/main.dart": "const app = 1;\n"})
        self._write("README", "dirty\n")
        with self.assertRaisesRegex(freeze.SourceFreezeError, freeze.GIT_DIRTY_SOURCE):
            self._inputs((("lib/main.dart", b"const app = 1;\n"),))

    def test_pathname_replacement_of_git_dir_is_rejected(self) -> None:
        self._commit_tree({"lib/main.dart": "const app = 1;\n"})
        git_dir = self.repo / ".git"
        backup = self.repo / ".git-original"
        git_dir.rename(backup)
        git_dir.symlink_to(backup)
        try:
            with self.assertRaisesRegex(freeze.SourceFreezeError, "symlink"):
                freeze._bind_production_git_tree(self.repo)
        finally:
            if git_dir.is_symlink():
                git_dir.unlink()
            if backup.exists():
                backup.rename(git_dir)


class GitTrackedSourceFreezeTests(unittest.TestCase):
    def setUp(self) -> None:
        if shutil.which("git") is None:
            self.skipTest("git is required for tracked-tree freeze tests")
        self.inner = ReleaseSourceFreezeTests()
        self.inner.setUp()
        self.repo = self.inner.repo
        freeze._FIXTURE_MODE = False
        freeze._PRODUCTION_REQUIRED = True
        (self.repo / ".gitignore").write_text(".artifacts/\n", encoding="utf-8")
        tools = self.repo / "tools"
        tools.mkdir(parents=True, exist_ok=True)
        shutil.copy2(SCRIPT, tools / freeze.CONTROLLER_NAME)
        shutil.copy2(pathlib.Path(__file__).resolve(), tools / freeze.TEST_NAME)
        shutil.copy2(
            SCRIPT.with_name(freeze.TOOLCHAIN_PIN_NAME),
            tools / freeze.TOOLCHAIN_PIN_NAME,
        )
        env = os.environ.copy()
        for key in (
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_COMMON_DIR",
        ):
            env.pop(key, None)
        env["GIT_CONFIG_GLOBAL"] = os.devnull
        env["GIT_CONFIG_SYSTEM"] = os.devnull
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        env["GIT_AUTHOR_NAME"] = "Freeze Test"
        env["GIT_AUTHOR_EMAIL"] = "freeze-test@winsvpn.example"
        env["GIT_COMMITTER_NAME"] = "Freeze Test"
        env["GIT_COMMITTER_EMAIL"] = "freeze-test@winsvpn.example"
        env["GIT_TERMINAL_PROMPT"] = "0"
        subprocess.run(
            ["git", "-C", str(self.repo), "init", "-q", "-b", "main"],
            check=True,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        subprocess.run(
            ["git", "-C", str(self.repo), "config", "core.autocrlf", "false"],
            check=True,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        subprocess.run(
            ["git", "-C", str(self.repo), "add", "-A"],
            check=True,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(self.repo),
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "--no-gpg-sign",
                "-m",
                "tracked source",
            ],
            check=True,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._git_env = env

    def tearDown(self) -> None:
        freeze._FIXTURE_MODE = False
        freeze._PRODUCTION_REQUIRED = False
        self.inner.tearDown()

    def assert_fails(self, message: str) -> None:
        self.inner.assert_fails(message)

    def final_capture_hook(self, hook):
        return self.inner.final_capture_hook(hook)

    def test_clean_tracked_tree_verifies(self) -> None:
        freeze.verified_release_source_state(self.repo)

    def test_injected_controller_in_candidate_tree_fails(self) -> None:
        attacker = self.repo / "tools" / freeze.CONTROLLER_NAME
        original = attacker.read_bytes()
        attacker.write_bytes(original + b"# injected\n")
        subprocess.run(
            ["git", "-C", str(self.repo), "add", "--", f"tools/{freeze.CONTROLLER_NAME}"],
            check=True,
            env=self._git_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(self.repo),
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "--no-gpg-sign",
                "-m",
                "inject controller",
            ],
            check=True,
            env=self._git_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assert_fails("does not match the exact tracked Git tree|producer identity|toolchain")

    def test_untracked_lib_file_cannot_claim_pass(self) -> None:
        (self.repo / "lib" / "hostile.dart").write_text("hostile\n", encoding="utf-8")
        self.assert_fails(
            r"untracked filesystem file is not a tracked Git tree input|"
            r"source state is not immutable/clean"
        )

    def test_concurrent_untracked_insert_cannot_claim_pass(self) -> None:
        inserted = self.repo / "lib" / "race.dart"

        def hook() -> None:
            inserted.write_text("race\n", encoding="utf-8")

        with self.final_capture_hook(hook):
            self.assert_fails(
                r"source tree changed after freeze hashing|"
                r"untracked filesystem file|"
                r"source state is not immutable/clean"
            )
        if inserted.exists():
            inserted.unlink()
        freeze.verified_release_source_state(self.repo)


if __name__ == "__main__":
    unittest.main()
