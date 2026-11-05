#!/usr/bin/env python3
"""Fail-closed Chrome/Edge/Firefox hardening and native-host identity receipts."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest import mock


TOOLS = pathlib.Path(__file__).resolve().parent
ROOT = TOOLS.parent
NATIVE = TOOLS / "native_messaging"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import cross_store_upload_readiness as readiness
import release_obfuscation_contract as obfuscation
import validate_release_artifact_privacy as privacy
import cross_store_gate_runner as gate_runner


FIXTURE_CHROME_ID = "abcdefghijklmnopabcdefghijklmnop"
FIXTURE_EDGE_ID = "ponmlkjihgfedcbaponmlkjihgfedcba"
MINIFIED_JS = b"const ok=true;function start(){return 1;}"
UNMINIFIED_JS = b"function start() {\n  const ok = true;\n  return ok;\n}\n"
ESBUILD_CACHE = pathlib.Path("/tmp/winsvpn-extension-esbuild-test-cache")
# The operator-supplied offline cache, captured before _seed_esbuild_cache
# redirects the environment to the private test cache. Archive bytes are
# re-verified.
CONFIGURED_ESBUILD_CACHE = os.environ.get("WINS_EXTENSION_ESBUILD_CACHE", "").strip()
_PRODUCER_ZIPS: dict[str, bytes] | None = None
SYNTHETIC_CASES = (
    (
        "chrome-extension-package",
        "chrome",
        "wins-vpn-companion-chrome.zip",
        "extension/tools/assert_chrome_zip.py",
    ),
    (
        "edge-extension-package",
        "edge",
        "wins-vpn-companion-edge.zip",
        "extension/tools/assert_chrome_zip.py",
    ),
    (
        "firefox-extension-package",
        "firefox",
        "wins-vpn-companion-firefox.xpi",
        "extension/tools/assert_firefox_zip.py",
    ),
)


def _seed_esbuild_cache() -> None:
    os.environ["WINS_EXTENSION_ESBUILD_CACHE"] = str(ESBUILD_CACHE)
    os.environ["WINS_EXTENSION_ESBUILD_FETCH"] = "0"
    spec = importlib.util.spec_from_file_location(
        "store_js_minifier_cross_store_gate",
        ROOT / "extension" / "tools" / "store_js_minifier.py",
    )
    assert spec is not None and spec.loader is not None
    minifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(minifier)
    pin = minifier.pin_for_host()
    slot = ESBUILD_CACHE / minifier.host_platform_key() / str(pin["archive_sha256"])
    slot.mkdir(parents=True, exist_ok=True)
    dest = slot / str(pin["archive_name"])
    discovered = (
        pathlib.Path("/tmp/winsvpn-esbuild-discovery/archives") / str(pin["archive_name"])
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


def _load_extension_builder():
    spec = importlib.util.spec_from_file_location(
        "extension_build_cross_store_minification", ROOT / "extension" / "build.py"
    )
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    return builder


def _producer_zip(browser: str) -> bytes:
    global _PRODUCER_ZIPS
    if _PRODUCER_ZIPS is None:
        _seed_esbuild_cache()
        builder = _load_extension_builder()
        dist = pathlib.Path(tempfile.mkdtemp(prefix="winsvpn-xstore-producer-"))
        builder.DIST = dist
        packages: dict[str, bytes] = {}
        for name in ("chrome", "edge", "firefox"):
            artifact = builder.zip_package(builder.stage(name), name)
            packages[name] = artifact.read_bytes()
        _PRODUCER_ZIPS = packages
    return _PRODUCER_ZIPS[browser]


def _write_producer(path: pathlib.Path, browser: str) -> pathlib.Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_producer_zip(browser))
    os.chmod(path, 0o644)
    return path


def _load_checker():
    spec = importlib.util.spec_from_file_location(
        "check_host_manifests_focused_gate", NATIVE / "check_host_manifests.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_zip(
    path: pathlib.Path,
    javascript: bytes,
    extras: dict[str, bytes] | None = None,
) -> pathlib.Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        # This is only the manifest numeric-boundary precondition for the JS
        # hardening fixtures below, not a complete browser manifest.
        if not extras or "manifest.json" not in extras:
            archive.writestr("manifest.json", b"{}")
        archive.writestr("src/background/background.js", javascript)
        if extras:
            for name, payload in extras.items():
                archive.writestr(name, payload)
    return path


def _write_zip_members(
    path: pathlib.Path, members: list[tuple[str, bytes]]
) -> pathlib.Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in members:
            archive.writestr(name, payload)
    return path


class ExtensionCrossStoreMinificationAndChromiumIdentityReceiptTests(
    unittest.TestCase
):
    def setUp(self) -> None:
        _seed_esbuild_cache()
    def test_canonical_hardening_contract_lists_privacy_and_obfuscation(self) -> None:
        expected = (
            "tools/validate_release_artifact_privacy.py",
            "tools/release_obfuscation_contract.py",
        )
        self.assertEqual(readiness.EXTENSION_HARDENING_PRODUCER_IDS, expected)
        self.assertEqual(
            readiness.GATE_PRODUCER_IDS["extension-minification-privacy"],
            expected,
        )
        for target_id in (
            "chrome-extension-package",
            "edge-extension-package",
            "firefox-extension-package",
        ):
            target = readiness.TARGET_BY_ID[target_id]
            self.assertEqual(target.hardening_gate_id, "extension-minification-privacy")
        source = (TOOLS / "cross_store_upload_readiness.py").read_text(encoding="utf-8")
        execute = source[
            source.index("def execute_target_gate_transaction") : source.index(
                "def _safe_time"
            )
        ]
        zip_verify = source[
            source.index("def verify_extension_zip_artifact") : source.index(
                "def _verify_target_receipt"
            )
        ]
        self.assertIn("verify_extension_cross_store_hardening", execute)
        self.assertIn("verify_extension_cross_store_hardening", zip_verify)
        self.assertIn("validate_artifacts", source)
        self.assertIn("verify_extension_javascript_hardening", source)

    def test_unminified_package_cannot_pass_while_privacy_alone_would(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            pretty = _write_zip(
                pathlib.Path(raw) / "wins-vpn-companion-chrome.zip", UNMINIFIED_JS
            )
            privacy.validate_artifacts((pretty,), {})
            with self.assertRaises(obfuscation.ObfuscationError):
                obfuscation.verify_extension_javascript_hardening("chrome", [pretty])
            with self.assertRaisesRegex(
                readiness.UploadReadinessError,
                "minification/obfuscation",
            ):
                readiness.verify_extension_cross_store_hardening(
                    "chrome-extension-package", pretty
                )

    def test_minified_fixture_routes_privacy_and_obfuscation_for_each_browser(
        self,
    ) -> None:
        cases = (
            ("chrome-extension-package", "chrome", "wins-vpn-companion-chrome.zip"),
            ("edge-extension-package", "edge", "wins-vpn-companion-edge.zip"),
            ("firefox-extension-package", "firefox", "wins-vpn-companion-firefox.xpi"),
        )
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            packages = []
            for target_id, browser, name in cases:
                artifact = _write_producer(root / name, browser)
                packages.append(artifact.read_bytes())
                privacy.validate_artifacts((artifact,), {})
                obfuscation.verify_extension_javascript_hardening(browser, [artifact])
                readiness.verify_extension_cross_store_hardening(target_id, artifact)
            self.assertEqual(len(set(packages)), 3)

    def test_unrecorded_unsafe_and_placeholder_store_ids_cannot_pass(
        self,
    ) -> None:
        checker = _load_checker()
        renderer = checker.renderer
        env_free = {"WINSVPN_CHROME_STORE_ID": "", "WINSVPN_EDGE_STORE_ID": ""}
        completed = subprocess.run(
            [sys.executable, str(NATIVE / "check_host_manifests.py")],
            check=False,
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            env={**os.environ, **env_free},
        )
        output = completed.stdout + completed.stderr
        # Owner ruling (EXT2): no receipt is read; the recorded identities bind.
        self.assertEqual(completed.returncode, 0, output)
        self.assertIn("allowed_origins names the recorded store id", output)
        self.assertNotIn("FAIL", completed.stdout)
        self.assertFalse(hasattr(renderer, "OWNER_BLOCKED_IDENTITY"))
        refusals = (
            renderer.OwnerIdentityBlocked(renderer.missing_store_id_message("edge")),
            renderer.OwnerIdentityInvalid(
                "native-host store id record must not be a symlink"
            ),
            renderer.OwnerIdentityInvalid(
                "chrome extension id is missing or is a placeholder"
            ),
        )
        for error in refusals:
            with self.subTest(error=str(error)):
                checker.FAILED = False

                def blocked(_error=error) -> dict[str, str]:
                    raise _error

                original = renderer.owner_issued_chromium_ids
                renderer.owner_issued_chromium_ids = blocked
                try:
                    ids = checker.known_ids()
                finally:
                    renderer.owner_issued_chromium_ids = original
                self.assertEqual(ids, {})
                self.assertTrue(checker.FAILED)
        # EXT2: a missing or inconsistent store identity record refuses too.
        listing_refusals = (
            renderer.OwnerIdentityInvalid("store identity record is unavailable"),
            renderer.OwnerIdentityInvalid("chrome: the store identity record is inconsistent"),
            ValueError("chrome extension id is missing or is a placeholder"),
        )
        for error in listing_refusals:
            with self.subTest(error=str(error)):
                checker.FAILED = False

                def blocked(_error=error) -> dict[str, str]:
                    raise _error

                original = checker.recorded_store_identity
                checker.recorded_store_identity = blocked
                try:
                    ids = checker.known_ids()
                finally:
                    checker.recorded_store_identity = original
                self.assertEqual(ids, {})
                self.assertTrue(checker.FAILED)
        previous = {key: os.environ.get(key) for key in env_free}
        original_file = renderer.STORE_IDS_FILE
        original_root = renderer.REPO_ROOT
        with tempfile.TemporaryDirectory() as raw:
            record = pathlib.Path(raw) / "manifests" / "store_ids.json"
            record.parent.mkdir()
            os.chmod(record.parent, 0o755)
            renderer.STORE_IDS_FILE = record
            # No store_identity.json listing beside the fixture record.
            renderer.REPO_ROOT = pathlib.Path(raw)
            os.environ.update(env_free)
            try:
                for payload in (
                    {"chrome": "PLACEHOLDER_CHROME_EXTENSION_ID"},
                    {"chrome": FIXTURE_CHROME_ID, "edge": FIXTURE_CHROME_ID},
                ):
                    with self.subTest(payload=payload):
                        record.write_text(json.dumps(payload) + "\n", encoding="ascii")
                        os.chmod(record, 0o644)
                        with self.assertRaises(
                            (renderer.OwnerIdentityInvalid, ValueError)
                        ):
                            renderer.recorded_store_ids()
                record.write_text(
                    json.dumps({"chrome": FIXTURE_CHROME_ID}) + "\n", encoding="ascii"
                )
                os.chmod(record, 0o644)
                with self.assertRaises(renderer.OwnerIdentityBlocked) as raised:
                    renderer.owner_issued_chromium_ids()
                self.assertIn("edge store-listing id is missing", str(raised.exception))
                record.unlink()
                with self.assertRaises(renderer.OwnerIdentityBlocked):
                    renderer.owner_issued_chromium_ids()
            finally:
                renderer.STORE_IDS_FILE = original_file
                renderer.REPO_ROOT = original_root
                for key, value in previous.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value

    def test_manifest_numeric_boundary_refusals_precede_javascript_hardening(
        self,
    ) -> None:
        javascript = ("src/background/background.js", MINIFIED_JS)
        cases = {
            "no-manifest": [javascript],
            "duplicate-member": [
                ("manifest.json", b"{}"),
                ("manifest.json", b"{}"),
                javascript,
            ],
            "nan": [("manifest.json", b'{"value": NaN}'), javascript],
            "infinity": [("manifest.json", b'{"value": -Infinity}'), javascript],
            "overflow-float": [("manifest.json", b'{"value": 1e400}'), javascript],
            "duplicate-key": [
                ("manifest.json", b'{"value": 1, "value": 2}'),
                javascript,
            ],
            "invalid-utf8": [("manifest.json", b'{"value": "\xff"}'), javascript],
            "oversize": [
                (
                    "manifest.json",
                    b'{"value": "' + b"x" * (1024 * 1024) + b'"}',
                ),
                javascript,
            ],
        }
        with tempfile.TemporaryDirectory() as raw:
            for name, members in cases.items():
                with self.subTest(case=name):
                    artifact = _write_zip_members(
                        pathlib.Path(raw)
                        / name
                        / "wins-vpn-companion-chrome.zip",
                        members,
                    )
                    with self.assertRaisesRegex(
                        readiness.UploadReadinessError,
                        "manifest numeric boundary is invalid",
                    ):
                        readiness.verify_extension_cross_store_hardening(
                            "chrome-extension-package", artifact
                        )

    def test_valid_fixture_identity_routes_native_host_and_both_hardening_gates(
        self,
    ) -> None:
        checker = _load_checker()
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            artifact = _write_producer(
                root / "wins-vpn-companion-edge.zip", "edge"
            )
            readiness.verify_extension_cross_store_hardening(
                "edge-extension-package", artifact
            )
            manifests = root / "manifests"
            manifests.mkdir()
            for browser, extension_id in (
                ("chrome", FIXTURE_CHROME_ID),
                ("edge", FIXTURE_EDGE_ID),
            ):
                (manifests / f"org.winsvpn.bridge.{browser}.json").write_text(
                    json.dumps(
                        {
                            "name": "org.winsvpn.bridge",
                            "allowed_origins": [
                                f"chrome-extension://{extension_id}/"
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
            (manifests / "org.winsvpn.bridge.firefox.json").write_text(
                json.dumps(
                    {
                        "name": "org.winsvpn.bridge",
                        "allowed_extensions": ["companion@winsvpn.org"],
                    }
                ),
                encoding="utf-8",
            )
            original_manifests = checker.MANIFESTS
            original_ids = checker.renderer.owner_issued_chromium_ids
            original_listing = checker.recorded_store_identity
            checker.MANIFESTS = manifests
            checker.FAILED = False

            def issued() -> dict[str, str]:
                return {"chrome": FIXTURE_CHROME_ID, "edge": FIXTURE_EDGE_ID}

            checker.renderer.owner_issued_chromium_ids = issued
            checker.recorded_store_identity = issued
            try:
                self.assertEqual(checker.main(), 0)
            finally:
                checker.MANIFESTS = original_manifests
                checker.renderer.owner_issued_chromium_ids = original_ids
                checker.recorded_store_identity = original_listing
                checker.FAILED = False

    def _install_exit0_producer(self, repo: pathlib.Path, relative: str) -> None:
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "#!/usr/bin/env python3\nimport sys\nraise SystemExit(0)\n",
            encoding="ascii",
        )
        os.chmod(path, 0o755)

    def _synthetic_gate_commands(
        self,
        repo: pathlib.Path,
        target_id: str,
        artifact: pathlib.Path,
        signing_producer: str,
    ) -> dict[str, tuple[str, ...]]:
        target = readiness.TARGET_BY_ID[target_id]
        relative_artifact = artifact.relative_to(repo).as_posix()
        return {
            target.signing_gate_id: (
                sys.executable,
                signing_producer,
                "--verify",
                target_id,
                relative_artifact,
            ),
            target.hardening_gate_id: (
                sys.executable,
                "tools/validate_release_artifact_privacy.py",
                "--verify",
                target_id,
                relative_artifact,
            ),
        }

    @contextlib.contextmanager
    def _spy_live_hardening(self):
        privacy = readiness._live_extension_hardening_module(
            "tools/validate_release_artifact_privacy.py"
        )
        obfuscation = readiness._live_extension_hardening_module(
            "tools/release_obfuscation_contract.py"
        )
        seen: dict[str, list[object]] = {"privacy": [], "obfuscation": []}
        real_privacy = privacy.validate_artifacts
        real_js = obfuscation.verify_extension_javascript_hardening

        def privacy_wrap(paths, secrets):
            for path in paths:
                seen["privacy"].append(
                    hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
                )
            return real_privacy(paths, secrets)

        def js_wrap(browser, paths):
            for path in paths:
                seen["obfuscation"].append(
                    (
                        browser,
                        hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest(),
                    )
                )
            return real_js(browser, paths)

        privacy.validate_artifacts = privacy_wrap
        obfuscation.verify_extension_javascript_hardening = js_wrap
        try:
            yield seen
        finally:
            privacy.validate_artifacts = real_privacy
            obfuscation.verify_extension_javascript_hardening = real_js

    def test_synthetic_zip_transactions_execute_both_gates_on_snapshot_bytes(
        self,
    ) -> None:
        for target_id, browser, filename, signing_producer in SYNTHETIC_CASES:
            with self.subTest(target_id=target_id):
                with tempfile.TemporaryDirectory() as raw:
                    repo = pathlib.Path(raw)
                    artifact = _write_producer(
                        repo / "build" / "upload" / target_id / filename, browser
                    )
                    self._install_exit0_producer(repo, signing_producer)
                    self._install_exit0_producer(
                        repo, "tools/validate_release_artifact_privacy.py"
                    )
                    evidence_dir = repo / ".artifacts" / "extension-gate"
                    evidence_dir.mkdir(parents=True, mode=0o700)
                    os.chmod(evidence_dir, 0o700)
                    bound_digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
                    with self._spy_live_hardening() as seen:
                        references = readiness.execute_target_gate_transaction(
                            repo,
                            target_id,
                            artifact,
                            self._synthetic_gate_commands(
                                repo, target_id, artifact, signing_producer
                            ),
                            evidence_dir,
                        )
                    self.assertEqual(seen["privacy"], [bound_digest])
                    self.assertEqual(seen["obfuscation"], [(browser, bound_digest)])
                    target = readiness.TARGET_BY_ID[target_id]
                    evidence_path = (
                        repo / references[target.hardening_gate_id]["evidence_path"]
                    )
                    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
                    executed = evidence["command"]["executed_argv"]
                    self.assertIn(".winsvpn-art-", executed[4])
                    self.assertEqual(
                        evidence["runner"]["id"],
                        gate_runner.SubprocessExplicitArgvRunner.RUNNER_ID,
                    )

    def test_privacy_only_argv_cannot_pass_unminified_javascript(self) -> None:
        target_id, _browser, filename, signing_producer = SYNTHETIC_CASES[0]
        with tempfile.TemporaryDirectory() as raw:
            repo = pathlib.Path(raw)
            artifact = _write_zip(
                repo / "build" / "upload" / target_id / filename, UNMINIFIED_JS
            )
            privacy.validate_artifacts((artifact,), {})
            self._install_exit0_producer(repo, signing_producer)
            self._install_exit0_producer(
                repo, "tools/validate_release_artifact_privacy.py"
            )
            evidence_dir = repo / ".artifacts" / "extension-gate"
            evidence_dir.mkdir(parents=True, mode=0o700)
            os.chmod(evidence_dir, 0o700)
            with self.assertRaisesRegex(
                readiness.UploadReadinessError,
                "minification/obfuscation",
            ):
                readiness.execute_target_gate_transaction(
                    repo,
                    target_id,
                    artifact,
                    self._synthetic_gate_commands(
                        repo, target_id, artifact, signing_producer
                    ),
                    evidence_dir,
                )

    def test_extra_unminified_javascript_cannot_pass_transaction(self) -> None:
        target_id, _browser, filename, signing_producer = SYNTHETIC_CASES[1]
        with tempfile.TemporaryDirectory() as raw:
            repo = pathlib.Path(raw)
            artifact = _write_producer(
                repo / "build" / "upload" / target_id / filename,
                "edge",
            )
            with zipfile.ZipFile(artifact, "a") as archive:
                archive.writestr("src/extra.js", UNMINIFIED_JS)
            privacy.validate_artifacts((artifact,), {})
            self._install_exit0_producer(repo, signing_producer)
            self._install_exit0_producer(
                repo, "tools/validate_release_artifact_privacy.py"
            )
            evidence_dir = repo / ".artifacts" / "extension-gate"
            evidence_dir.mkdir(parents=True, mode=0o700)
            os.chmod(evidence_dir, 0o700)
            with self.assertRaisesRegex(
                readiness.UploadReadinessError,
                "minification/obfuscation",
            ):
                readiness.execute_target_gate_transaction(
                    repo,
                    target_id,
                    artifact,
                    self._synthetic_gate_commands(
                        repo, target_id, artifact, signing_producer
                    ),
                    evidence_dir,
                )

    def test_post_snapshot_tamper_cannot_satisfy_bound_hardening_identity(
        self,
    ) -> None:
        target_id, _browser, filename, signing_producer = SYNTHETIC_CASES[2]
        with tempfile.TemporaryDirectory() as raw:
            repo = pathlib.Path(raw)
            artifact = _write_zip(
                repo / "build" / "upload" / target_id / filename, UNMINIFIED_JS
            )
            minified_bytes = _write_producer(
                repo / "build" / "upload" / target_id / "minified-swap.xpi",
                "firefox",
            ).read_bytes()
            original_bytes = artifact.read_bytes()
            self._install_exit0_producer(repo, signing_producer)
            self._install_exit0_producer(
                repo, "tools/validate_release_artifact_privacy.py"
            )
            evidence_dir = repo / ".artifacts" / "extension-gate"
            evidence_dir.mkdir(parents=True, mode=0o700)
            os.chmod(evidence_dir, 0o700)
            real = readiness.verify_extension_cross_store_hardening

            def swapped(target, path, expected_sha256=None):
                path.write_bytes(minified_bytes)
                try:
                    return real(
                        target, path, expected_sha256=expected_sha256
                    )
                finally:
                    path.write_bytes(original_bytes)

            with mock.patch.object(
                readiness, "verify_extension_cross_store_hardening", swapped
            ):
                with self.assertRaisesRegex(
                    readiness.UploadReadinessError,
                    "bound snapshot identity|changed after|minification/obfuscation|snapshot changed|snapshot execution failed",
                ):
                    readiness.execute_target_gate_transaction(
                        repo,
                        target_id,
                        artifact,
                        self._synthetic_gate_commands(
                            repo, target_id, artifact, signing_producer
                        ),
                        evidence_dir,
                    )
            self.assertEqual(artifact.read_bytes(), original_bytes)

    def test_compact_foreign_javascript_cannot_pass_hardening(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            artifact = _write_zip(
                pathlib.Path(raw) / "wins-vpn-companion-chrome.zip", MINIFIED_JS
            )
            privacy.validate_artifacts((artifact,), {})
            with self.assertRaisesRegex(
                obfuscation.ObfuscationError,
                "not the reproducible esbuild producer output",
            ):
                obfuscation.verify_extension_javascript_hardening("chrome", [artifact])
            with self.assertRaisesRegex(
                readiness.UploadReadinessError,
                "minification/obfuscation",
            ):
                readiness.verify_extension_cross_store_hardening(
                    "chrome-extension-package", artifact
                )

    def test_hostile_producer_mutations_cannot_pass_cross_store_hardening(self) -> None:
        chrome = _producer_zip("chrome")
        member = "src/core/constants.js"
        with zipfile.ZipFile(io.BytesIO(chrome)) as archive:
            original = archive.read(member)

        def rewrite(*, replace=None, comment=None):
            source = zipfile.ZipFile(io.BytesIO(chrome))
            out = io.BytesIO()
            with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dest:
                for info in source.infolist():
                    data = source.read(info.filename)
                    if replace and info.filename in replace:
                        data = replace[info.filename]
                    dest.writestr(info.filename, data)
                if comment is not None:
                    dest.comment = comment
            return out.getvalue()

        cases = (
            rewrite(replace={member: b" " + original}),
            rewrite(
                replace={
                    member: b"export function start() {\nconst ok = true;\nreturn ok;\n}\n"
                }
            ),
            rewrite(replace={member: original.replace(b"\n", b"\n\xc2\xa0", 1)}),
            rewrite(
                replace={member: original + b"\n//# sourceMappingURL:hidden.js.map\n"}
            ),
            rewrite(
                replace={
                    member: original + b"\n//# source Mapping URL = hidden.js.map\n"
                }
            ),
            rewrite(
                replace={
                    member: original
                    + "//# sourceMappingURL\u200b=hidden.js.map\n".encode("utf-8")
                }
            ),
            rewrite(comment=b"sourceMappingURL=hidden.js.map"),
            rewrite(comment=b"sourceMappingURL:hidden.js.map"),
            rewrite(replace={member: original + b"\n"}),
            rewrite(
                replace={member: b"const ok=true;function start(){return 1;}\n"}
            ),
        )
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            for index, payload in enumerate(cases):
                artifact = root / f"wins-vpn-companion-chrome-{index}.zip"
                artifact.write_bytes(payload)
                os.chmod(artifact, 0o644)
                with self.subTest(index=index):
                    with self.assertRaisesRegex(
                        readiness.UploadReadinessError,
                        "minification/obfuscation",
                    ):
                        readiness.verify_extension_cross_store_hardening(
                            "chrome-extension-package", artifact
                        )

    def test_receipt_cross_browser_substitution_is_refused(self) -> None:
        checker = _load_checker()
        with tempfile.TemporaryDirectory() as raw:
            manifests = pathlib.Path(raw)
            for browser, extension_id in (
                ("chrome", FIXTURE_EDGE_ID),
                ("edge", FIXTURE_CHROME_ID),
            ):
                (manifests / f"org.winsvpn.bridge.{browser}.json").write_text(
                    json.dumps(
                        {
                            "name": "org.winsvpn.bridge",
                            "allowed_origins": [
                                f"chrome-extension://{extension_id}/"
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
            (manifests / "org.winsvpn.bridge.firefox.json").write_text(
                json.dumps(
                    {
                        "name": "org.winsvpn.bridge",
                        "allowed_extensions": ["companion@winsvpn.org"],
                    }
                ),
                encoding="utf-8",
            )
            original_manifests = checker.MANIFESTS
            original_ids = checker.renderer.owner_issued_chromium_ids
            original_listing = checker.recorded_store_identity
            checker.MANIFESTS = manifests
            checker.FAILED = False

            def issued() -> dict[str, str]:
                return {"chrome": FIXTURE_CHROME_ID, "edge": FIXTURE_EDGE_ID}

            checker.renderer.owner_issued_chromium_ids = issued
            checker.recorded_store_identity = issued
            try:
                self.assertEqual(checker.main(), 1)
            finally:
                checker.MANIFESTS = original_manifests
                checker.renderer.owner_issued_chromium_ids = original_ids
                checker.recorded_store_identity = original_listing
                checker.FAILED = False


if __name__ == "__main__":
    unittest.main()
