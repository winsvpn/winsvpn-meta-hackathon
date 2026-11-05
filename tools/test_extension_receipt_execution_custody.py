#!/usr/bin/env python3
"""Adversarial custody tests for extension receipt helper origin and artifacts."""

from __future__ import annotations

import builtins
import contextlib
import datetime as dt
import functools
import hashlib
import importlib.util
import ipaddress
import json
import os
import pathlib
import py_compile
import shutil
import sys
import tempfile
import types
import unicodedata
import unittest
import zipfile
from unittest import mock

TOOLS = pathlib.Path(__file__).resolve().parent
ROOT = TOOLS.parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
EXTENSION_TOOLS = ROOT / "extension" / "tools"
if str(EXTENSION_TOOLS) not in sys.path:
    sys.path.insert(0, str(EXTENSION_TOOLS))

import checks as extension_checks
import cross_store_gate_runner as gate_runner
import cross_store_upload_readiness as readiness
import jsonc as extension_jsonc
import release_dependency_freeze as freeze


class FakeExplicitArgvRunner:
    TEST_ONLY = True

    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def run(
        self, argv: tuple[str, ...], *, cwd: pathlib.Path
    ) -> gate_runner.GateProcessResult:
        exact = tuple(argv)
        self.calls.append(exact)
        return gate_runner.GateProcessResult(
            argv=exact,
            stdout="verified " + " ".join(exact),
            stderr="",
            exit_code=0,
            executed=True,
            runner_id=gate_runner.SubprocessExplicitArgvRunner.RUNNER_ID,
            shell_enabled=False,
        )


class ExtensionReceiptExecutionCustodyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.bytecode_patch = mock.patch.object(sys, "dont_write_bytecode", True)
        self.bytecode_patch.start()
        self.saved_modules = {
            name: sys.modules.get(name) for name in ("jsonc", "checks", "leakscan")
        }
        self.saved_path = list(sys.path)
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temporary.name)
        self._install_extension_verifier()
        self.target_id = "chrome-extension-package"
        self.artifact = (
            self.repo
            / "build"
            / "upload"
            / self.target_id
            / "wins-vpn-chrome-extension-package.zip"
        )
        self.artifact.parent.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        self.bytecode_patch.stop()
        sys.path[:] = self.saved_path
        for name, module in self.saved_modules.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module
        leftover_private = [
            name
            for name in sys.modules
            if name.startswith("winsvpn_ext_receipt_")
        ]
        for name in leftover_private:
            sys.modules.pop(name, None)
        self.temporary.cleanup()
        self.assertEqual(leftover_private, [])

    def _install_extension_verifier(self) -> None:
        shutil.copytree(ROOT / "extension/src", self.repo / "extension/src")
        shutil.copytree(ROOT / "extension/manifest", self.repo / "extension/manifest")
        for relative in readiness.EXTENSION_VERIFIER_SOURCE_PATHS:
            source = ROOT / relative
            destination = self.repo / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)

    def test_bound_host_templates_are_valid_and_distinct(self) -> None:
        identities: dict[str, str] = {}
        for browser in ("chrome", "edge"):
            template = (
                self.repo
                / f"tools/native_messaging/manifests/org.winsvpn.bridge.{browser}.json"
            )
            document = extension_jsonc.loads(template.read_text(encoding="utf-8"))
            identities[browser] = extension_checks.validated_chromium_allowed_origin(
                document, browser
            )
            self.assertRegex(identities[browser], r"^[a-p]{32}$")
        self.assertNotEqual(identities["chrome"], identities["edge"])

    def _write_extension_zip(self, artifact_path: pathlib.Path) -> bytes:
        saved_modules = {
            name: sys.modules.get(name) for name in ("jsonc", "checks", "leakscan")
        }
        saved_path = list(sys.path)
        spec = readiness.importlib.util.spec_from_file_location(
            "fixture_extension_build_chrome_custody",
            ROOT / "extension/build.py",
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        builder = readiness.importlib.util.module_from_spec(spec)
        try:
            with mock.patch.object(sys, "dont_write_bytecode", True):
                spec.loader.exec_module(builder)
            builder.DIST = artifact_path.parent / ".stage-chrome-custody"
            if builder.DIST.exists():
                shutil.rmtree(builder.DIST)
            produced = builder.zip_package(builder.stage("chrome"), "chrome")
            shutil.copyfile(produced, artifact_path)
        finally:
            sys.modules.pop("fixture_extension_build_chrome_custody", None)
            sys.path[:] = saved_path
            for name, module in saved_modules.items():
                if module is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = module
        payload = artifact_path.read_bytes()
        self.assertGreater(len(payload), 0)
        return payload

    def _write_unsafe_zip(self, artifact_path: pathlib.Path) -> bytes:
        self._write_extension_zip(artifact_path)
        with zipfile.ZipFile(artifact_path, "a") as archive:
            archive.writestr("src/core/probe.js", "await fetch(u);\n")
        return artifact_path.read_bytes()

    def _install_fake_helpers(self) -> dict[str, types.ModuleType]:
        checks = types.ModuleType("checks")
        checks.selftest = lambda: True
        checks.run = lambda *args, **kwargs: []
        leakscan = types.ModuleType("leakscan")
        leakscan.selftest = lambda verbose=True: True
        leakscan.scan_tree = lambda root: []
        jsonc = types.ModuleType("jsonc")
        jsonc.loads = json.loads
        jsonc.strip_comments = lambda text: text
        sys.modules["checks"] = checks
        sys.modules["leakscan"] = leakscan
        sys.modules["jsonc"] = jsonc
        return {"checks": checks, "leakscan": leakscan, "jsonc": jsonc}

    def _snapshot_leftovers(self) -> list[pathlib.Path]:
        found: list[pathlib.Path] = []
        for path in self.repo.rglob("*"):
            try:
                if not path.is_file() or path.is_symlink():
                    continue
            except OSError:
                continue
            if ".winsvpn-ext-" in path.name or ".winsvpn-art-" in path.name:
                found.append(path)
        return found

    def test_fake_sys_modules_cannot_bypass_unsafe_zip(self) -> None:
        unsafe_bytes = self._write_unsafe_zip(self.artifact)
        fakes = self._install_fake_helpers()
        with self.assertRaisesRegex(
            readiness.UploadReadinessError,
            "leak/policy|network-capable API|fetch",
        ):
            readiness.verify_extension_zip_artifact(
                self.repo, self.target_id, self.artifact
            )
        self.assertEqual(self.artifact.read_bytes(), unsafe_bytes)
        self.assertIs(sys.modules["checks"], fakes["checks"])
        self.assertIs(sys.modules["leakscan"], fakes["leakscan"])
        self.assertIs(sys.modules["jsonc"], fakes["jsonc"])
        self.assertEqual(self._snapshot_leftovers(), [])

    def test_executed_closure_uses_private_snapshot_identities(self) -> None:
        self._write_extension_zip(self.artifact)
        fakes = self._install_fake_helpers()
        executed: dict[str, object] = {}
        checks_digest = hashlib.sha256(
            (self.repo / "extension/tools/checks.py").read_bytes()
        ).hexdigest()
        builder_digest = hashlib.sha256(
            (self.repo / "extension/build.py").read_bytes()
        ).hexdigest()
        with readiness._bound_extension_builder(self.repo) as builder:
            executed["checks"] = builder.checks
            executed["builder"] = builder
            executed["checks_file"] = pathlib.Path(builder.checks.__file__)
            executed["builder_file"] = pathlib.Path(builder.__file__)
            self.assertEqual(
                builder.checks.__name__,
                f"winsvpn_ext_receipt_checks_{checks_digest}",
            )
            self.assertEqual(
                builder.__name__,
                f"winsvpn_ext_receipt_builder_{builder_digest}",
            )
            self.assertIn(".winsvpn-ext-", executed["checks_file"].name)
            self.assertIn(".winsvpn-ext-", executed["builder_file"].name)
            self.assertTrue(executed["checks_file"].is_file())
            self.assertTrue(executed["builder_file"].is_file())
            self.assertIsNot(builder.checks, fakes["checks"])
            self.assertIsNot(builder.leakscan, fakes["leakscan"])
            self.assertIsNot(builder.jsonc, fakes["jsonc"])
            self.assertIs(sys.modules["checks"], builder.checks)
            self.assertIs(sys.modules["leakscan"], builder.leakscan)
            self.assertIs(sys.modules["jsonc"], builder.jsonc)
        self.assertIs(sys.modules["checks"], fakes["checks"])
        self.assertIsNot(executed["checks"], fakes["checks"])
        self.assertFalse(pathlib.Path(executed["checks"].__file__).exists())
        self.assertFalse(pathlib.Path(executed["builder"].__file__).exists())
        self.assertEqual(
            [
                name
                for name in sys.modules
                if name.startswith("winsvpn_ext_receipt_")
            ],
            [],
        )
        self.assertEqual(self._snapshot_leftovers(), [])

    def test_checker_version_parser_replacement_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            readiness.UploadReadinessError,
            "helper binding changed during execution",
        ):
            with readiness._bound_extension_builder(self.repo) as builder:
                builder.checks.read_pubspec_manifest_version = lambda _pubspec: "9.9.9"
        self.assertEqual(self._snapshot_leftovers(), [])

    def test_remaining_load_time_bindings_fail_closed_after_execution(self) -> None:
        mutations = {
            "checks.jsonc": lambda builder: setattr(
                builder.checks, "jsonc", types.ModuleType("replacement_jsonc")
            ),
            "VERIFIER_SOURCE_PATHS": lambda builder: setattr(
                builder, "VERIFIER_SOURCE_PATHS", ()
            ),
            "verify_existing_package": lambda builder: setattr(
                builder, "verify_existing_package", lambda *args, **kwargs: None
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name):
                with self.assertRaisesRegex(
                    readiness.UploadReadinessError,
                    "helper binding changed during execution",
                ):
                    with readiness._bound_extension_builder(self.repo) as builder:
                        mutate(builder)
                self.assertEqual(self._snapshot_leftovers(), [])

    def test_verifier_replacement_with_matching_module_name_fails_closed(self) -> None:
        for kind in ("existing_builder_function", "relabeled_lambda"):
            with self.subTest(kind=kind):
                with self.assertRaisesRegex(
                    readiness.UploadReadinessError,
                    "helper binding changed during execution",
                ):
                    with readiness._bound_extension_builder(self.repo) as builder:
                        if kind == "existing_builder_function":
                            replacement = builder.verifier_source_closure
                        else:
                            replacement = lambda *args, **kwargs: None
                            replacement.__module__ = builder.__name__
                        builder.verify_existing_package = replacement
                self.assertEqual(self._snapshot_leftovers(), [])

    def test_verifier_identity_is_checked_on_exceptional_exit(self) -> None:
        class BodyFailure(RuntimeError):
            pass

        with self.assertRaises(BodyFailure):
            with readiness._bound_extension_builder(self.repo):
                raise BodyFailure("unmodified builder keeps the original error")
        self.assertEqual(self._snapshot_leftovers(), [])
        with self.assertRaisesRegex(
            readiness.UploadReadinessError,
            "helper binding changed during execution",
        ) as raised:
            with readiness._bound_extension_builder(self.repo) as builder:
                replacement = lambda *args, **kwargs: None
                replacement.__module__ = builder.__name__
                builder.verify_existing_package = replacement
                raise BodyFailure("body failed after the verifier was replaced")
        self.assertIsInstance(raised.exception.__cause__, BodyFailure)
        self.assertEqual(self._snapshot_leftovers(), [])

    def test_bound_module_rebinding_and_function_mutation_fail_closed(self) -> None:
        def swap_verifier_code(builder) -> None:
            builder.verify_existing_package.__code__ = (
                lambda *args, **kwargs: None
            ).__code__

        def mutate_verifier_kwdefaults(builder) -> None:
            builder.verify_existing_package.__kwdefaults__["verbose"] = True

        def rebind_builder_helper(builder) -> None:
            builder.reject_untrusted_store_zip = lambda *args, **kwargs: None

        def rebind_minifier_function(builder) -> None:
            builder.store_js_minifier.producer_packaged_javascript = (
                lambda *args, **kwargs: {}
            )

        def shadow_builtin_in_builder(builder) -> None:
            builder.len = lambda value: 0

        for mutate in (
            swap_verifier_code,
            mutate_verifier_kwdefaults,
            rebind_builder_helper,
            rebind_minifier_function,
            shadow_builtin_in_builder,
        ):
            with self.subTest(mutation=mutate.__name__):
                with self.assertRaisesRegex(
                    readiness.UploadReadinessError,
                    "helper binding changed during execution",
                ):
                    with readiness._bound_extension_builder(self.repo) as builder:
                        mutate(builder)
                self.assertEqual(self._snapshot_leftovers(), [])

    def test_declared_minifier_cache_fill_passes_post_execution_check(self) -> None:
        with readiness._bound_extension_builder(self.repo) as builder:
            builder.store_js_minifier._PRODUCER_PACKAGED_JS = {}
        self.assertEqual(self._snapshot_leftovers(), [])

    def test_owned_state_beyond_namespace_bindings_fails_closed(self) -> None:
        def empty_network_api_denylist(builder) -> None:
            builder.leakscan.NETWORK_APIS.clear()

        def widen_permitted_permissions(builder) -> None:
            builder.checks.PERMITTED_PERMISSIONS.add("tabs")

        def rebind_helper_class_method(builder) -> None:
            builder.checks.ScriptSourceCheck.handle_starttag = (
                lambda *args, **kwargs: None
            )

        def swap_helper_method_code(builder) -> None:
            builder.checks.ScriptSourceCheck.handle_starttag.__code__ = (
                lambda *args, **kwargs: None
            ).__code__

        def swap_closure_cell(builder) -> None:
            klass = builder.checks.ScriptSourceCheck
            klass.__init__.__closure__[0].cell_contents = type(
                "Swapped", (klass,), {}
            )

        real_all = all

        def rebind_builtin(builder) -> None:
            builder.__builtins__["all"] = lambda iterable: real_all(iterable)

        for mutate in (
            empty_network_api_denylist,
            widen_permitted_permissions,
            rebind_helper_class_method,
            swap_helper_method_code,
            swap_closure_cell,
            rebind_builtin,
        ):
            with self.subTest(mutation=mutate.__name__):
                try:
                    with self.assertRaisesRegex(
                        readiness.UploadReadinessError,
                        "helper binding changed during execution",
                    ):
                        with readiness._bound_extension_builder(self.repo) as builder:
                            mutate(builder)
                finally:
                    builtins.all = real_all
                self.assertEqual(self._snapshot_leftovers(), [])

    def test_builtin_zip_cannot_skip_binding_comparisons(self) -> None:
        class EmptyZip:
            def __call__(self, *args: object, **kwargs: object) -> object:
                return iter(())

        real_zip = builtins.zip
        for swap_code in (False, True):
            with self.subTest(swap_code=swap_code):
                try:
                    with self.assertRaisesRegex(
                        readiness.UploadReadinessError,
                        "helper binding changed during execution",
                    ):
                        with readiness._bound_extension_builder(self.repo) as builder:
                            builder.__builtins__["zip"] = EmptyZip()
                            if swap_code:
                                builder.verify_existing_package.__code__ = (
                                    lambda *args, **kwargs: None
                                ).__code__
                finally:
                    builtins.zip = real_zip
                self.assertEqual(self._snapshot_leftovers(), [])

    def test_builtin_zip_replaced_by_a_class_cannot_skip_binding_comparisons(
        self,
    ) -> None:
        # A class replacement keeps the recorded fingerprint length of the real
        # `zip` class (a foreign class is recorded by identity, one entry), so
        # the length check cannot see it; only the captured `zip` can.
        class EmptyZip:
            def __new__(cls, *args: object, **kwargs: object) -> object:
                return iter(())

        real_zip = builtins.zip
        try:
            with self.assertRaisesRegex(
                readiness.UploadReadinessError,
                "helper binding changed during execution",
            ):
                with readiness._bound_extension_builder(self.repo) as builder:
                    builder.__builtins__["zip"] = EmptyZip
                    builder.verify_existing_package.__code__ = (
                        lambda *args, **kwargs: None
                    ).__code__
        finally:
            builtins.zip = real_zip
        self.assertEqual(self._snapshot_leftovers(), [])

    def test_declared_engine_cache_and_lazy_annotations_pass_post_execution_check(
        self,
    ) -> None:
        with readiness._bound_extension_builder(self.repo) as builder:
            minifier = builder.store_js_minifier
            minifier._ENGINE_SNAPSHOTS["0" * 64] = self.repo / "esbuild"
            minifier._ENGINE_CUSTODY.append(object())
            self.assertIn("PLATFORM_PINS", minifier.__annotations__)
            for module in (builder, builder.checks, builder.leakscan, minifier):
                module.__annotations__
                for value in list(vars(module).values()):
                    if isinstance(value, type):
                        value.__annotations__
        self.assertEqual(self._snapshot_leftovers(), [])

    def test_foreign_class_instances_held_by_helpers_fail_closed(self) -> None:
        def widen_v4_leak_allowlist_in_place(builder) -> None:
            builder.leakscan.PERMITTED_V4_NETS[8].netmask = ipaddress.IPv4Address(0)
            self.assertTrue(builder.leakscan._v4_permitted("93.184.216.34"))

        def widen_v6_leak_allowlist_in_place(builder) -> None:
            builder.leakscan.PERMITTED_V6_NETS[1].netmask = ipaddress.IPv6Address(0)

        def redirect_authored_source_root(builder) -> None:
            builder.store_js_minifier.EXTENSION_SRC._raw_paths[:] = [
                str(self.repo / "elsewhere")
            ]

        def rebind_cached_path_string(builder) -> None:
            builder.SRC._str = str(self.repo / "elsewhere")

        for mutate in (
            widen_v4_leak_allowlist_in_place,
            widen_v6_leak_allowlist_in_place,
            redirect_authored_source_root,
            rebind_cached_path_string,
        ):
            with self.subTest(mutation=mutate.__name__):
                with self.assertRaisesRegex(
                    readiness.UploadReadinessError,
                    "helper binding changed during execution",
                ):
                    with readiness._bound_extension_builder(self.repo) as builder:
                        mutate(builder)
                self.assertEqual(self._snapshot_leftovers(), [])

    def test_helper_reads_of_held_instances_pass_post_execution_check(self) -> None:
        with readiness._bound_extension_builder(self.repo) as builder:
            leakscan = builder.leakscan
            minifier = builder.store_js_minifier
            self.assertFalse(leakscan._v4_permitted("93.184.216.34"))
            self.assertTrue(leakscan._v6_permitted("2001:db8::1"))
            for network in leakscan.PERMITTED_V4_NETS + leakscan.PERMITTED_V6_NETS:
                network.broadcast_address
                network.hostmask
            paths = [
                builder.ROOT,
                builder.REPO_ROOT,
                builder.SRC,
                builder.MANIFEST_DIR,
                builder.DIST,
                minifier.EXTENSION_ROOT,
                minifier.EXTENSION_SRC,
            ]
            sorted(paths)
            {path: str(path) for path in paths}
            [(path / "x", path.parts, path.name) for path in paths]
            self.assertTrue(minifier.authored_source_files())
            for module in (builder, builder.checks, leakscan, minifier):
                vars(module.__spec__)
                dir(module.__loader__)
        self.assertEqual(self._snapshot_leftovers(), [])

    def test_unmodified_bound_builder_passes_post_execution_check(self) -> None:
        with readiness._bound_extension_builder(self.repo):
            pass
        self.assertEqual(self._snapshot_leftovers(), [])

    def _mutate_during_isolated_run(self, mutate):
        real_run = readiness._run_isolated_extension_child

        def mutating_run(request, repo, result_path):
            mutate()
            try:
                return real_run(request, repo, result_path)
            finally:
                self._after_isolated_run()

        return mock.patch.object(readiness, "_run_isolated_extension_child", mutating_run)

    def _after_isolated_run(self) -> None:
        return None

    def test_helper_replacement_during_verify_fails_closed(self) -> None:
        self._write_extension_zip(self.artifact)
        checks_path = self.repo / "extension/tools/checks.py"
        original = checks_path.read_bytes()

        def replace_helper() -> None:
            checks_path.write_bytes(original + b"\nHELPER_REPLACED = True\n")

        with self._mutate_during_isolated_run(replace_helper):
            with self.assertRaisesRegex(
                readiness.UploadReadinessError,
                "not bound to the artifact|closure changed|snapshot changed|origin is not the bound",
            ):
                readiness.verify_extension_zip_artifact(
                    self.repo, self.target_id, self.artifact
                )
        self.assertEqual(self._snapshot_leftovers(), [])

    def test_builder_source_replacement_during_verify_fails_closed(self) -> None:
        self._write_extension_zip(self.artifact)
        builder_path = self.repo / "extension/build.py"
        original = builder_path.read_bytes()

        def replace_builder() -> None:
            builder_path.write_bytes(original + b"\n# source replaced\n")

        with self._mutate_during_isolated_run(replace_builder):
            with self.assertRaisesRegex(
                readiness.UploadReadinessError,
                "not bound to the artifact|closure changed|snapshot changed|origin is not the bound",
            ):
                readiness.verify_extension_zip_artifact(
                    self.repo, self.target_id, self.artifact
                )
        self.assertEqual(self._snapshot_leftovers(), [])

    def test_live_path_swap_restore_cannot_hide_unsafe_snapshot(self) -> None:
        clean_path = self.artifact.with_name("wins-vpn-chrome-extension-clean.zip")
        clean_bytes = self._write_extension_zip(clean_path)
        unsafe_bytes = self._write_unsafe_zip(self.artifact)

        def swap_live_path_to_clean() -> None:
            self.artifact.write_bytes(clean_bytes)

        def restore_unsafe_live_path() -> None:
            self.artifact.write_bytes(unsafe_bytes)

        self._after_isolated_run = restore_unsafe_live_path
        with self._mutate_during_isolated_run(swap_live_path_to_clean):
            with self.assertRaisesRegex(
                readiness.UploadReadinessError,
                "leak/policy|network-capable API|fetch",
            ):
                readiness.verify_extension_zip_artifact(
                    self.repo, self.target_id, self.artifact
                )
        self.assertEqual(self.artifact.read_bytes(), unsafe_bytes)
        self.assertEqual(self._snapshot_leftovers(), [])

    # ------------------------------------------------------------------
    # Fresh-interpreter verification. These tests install a stub
    # verify_existing_package into the temporary repo copy of extension/build.py
    # (the parent pins whatever bytes the repo holds), so they run without the
    # frozen esbuild archive and exercise the real subprocess.
    # ------------------------------------------------------------------

    STUB_VERIFIER = """

if os.environ.get("STUB_SHRINK_VERIFIER_PATHS"):
    VERIFIER_SOURCE_PATHS = tuple(VERIFIER_SOURCE_PATHS)[:-1]
if os.environ.get("STUB_REBIND_JSONC"):
    jsonc = object()
if os.environ.get("STUB_RESOLVE_OWN_FILE"):
    __file__ = os.path.realpath(__file__)
if os.environ.get("STUB_FOREIGN_OWN_FILE"):
    __file__ = os.path.join(os.path.dirname(os.path.abspath(__file__)), "build.py")


def verify_existing_package(archive, target, *, repo=None, verbose=False):
    import hashlib as _hashlib
    import ipaddress as _ipaddress
    import os as _os
    import sys as _sys
    import unicodedata as _unicodedata
    import zipfile as _zipfile

    if _os.environ.get("STUB_VERIFIER_RAISES"):
        raise PackageVerifyError("stub verifier rejected the artifact")
    if _os.environ.get("STUB_IMPORT_UNPINNED"):
        _sys.path.insert(0, _os.environ["STUB_IMPORT_UNPINNED"])
        import unpinned_helper
    if _os.environ.get("STUB_SWAP_IMPORT_DIRECTORY"):
        import importlib as _importlib

        _directory, _target = _os.environ["STUB_SWAP_IMPORT_DIRECTORY"].split(_os.pathsep)
        _sys.path.insert(0, _directory)
        import outside_first
        _os.rename(_directory, _directory + ".gone")
        _os.symlink(_target, _directory)
        _importlib.invalidate_caches()
        import unpinned_second
    if _os.environ.get("STUB_LOAD_BY_LOCATION"):
        import importlib.util as _importlib_util

        _spec = _importlib_util.spec_from_file_location(
            "unpinned_by_location", _os.environ["STUB_LOAD_BY_LOCATION"]
        )
        _spec.loader.exec_module(_importlib_util.module_from_spec(_spec))
    if _os.environ.get("STUB_EXEC_UNIDENTIFIABLE"):
        exec(
            compile(
                _os.environ["STUB_EXEC_UNIDENTIFIABLE"],
                "/nonexistent-winsvpn-origin/helper.py",
                "exec",
            ),
            {},
        )
    payload = Path(archive).read_bytes()
    reported = _hashlib.sha256(payload).hexdigest()
    if _os.environ.get("STUB_VERIFIER_WRONG_SHA"):
        reported = "0" * 64
    return {
        "ok": True,
        "target_id": "chrome-extension-package",
        "browser": "chrome",
        "artifact": Path(archive).as_posix(),
        "sha256": reported,
        "bytes": len(payload),
        "verifier_source_closure": verifier_source_closure(repo),
        "rebuilt": False,
        "trusted_loose_source": False,
        "probe": {
            "pid": _os.getpid(),
            "ipaddress_file": _ipaddress.__file__,
            "zipfile_class": _zipfile.ZipFile.__module__ + "." + _zipfile.ZipFile.__qualname__,
            "normalize_ok": _unicodedata.normalize("NFC", "e\\u0301") == "\\u00e9",
            "zip_pairs": [list(pair) for pair in zip([1, 2], [3, 4])],
            "all_true": all([True, True]),
            "netmask": str(_ipaddress.ip_network("93.184.216.0/24").netmask),
            "public_names": sorted(
                name
                for name in _sys.modules
                if name in ("checks", "jsonc", "leakscan", "store_version", "store_js_minifier")
            ),
            "argv": list(_sys.argv),
            "loaded_private": sorted(
                name for name in _sys.modules if name.startswith("winsvpn_ext_receipt_")
            ),
        },
    }
"""

    def _install_stub_verifier(self) -> None:
        build = self.repo / "extension/build.py"
        build.write_text(
            build.read_text(encoding="utf-8") + self.STUB_VERIFIER, encoding="utf-8"
        )
        self.artifact.write_bytes(b"PK stub artifact bytes for the isolated verifier")

    def _isolated_outcome(self):
        with readiness._isolated_extension_verification(
            self.repo, self.target_id, self.artifact
        ) as outcome:
            pass
        return outcome

    def test_isolated_verifier_runs_in_fresh_interpreter_from_pinned_bytes(self) -> None:
        self._install_stub_verifier()
        outcome = self._isolated_outcome()
        self.assertIsNone(outcome.error)
        probe = outcome.result["probe"]
        self.assertNotEqual(probe["pid"], os.getpid())
        self.assertEqual(probe["argv"], ["-c"])
        self.assertEqual(
            probe["public_names"],
            sorted(readiness._EXTENSION_PUBLIC_HELPER_NAMES),
        )
        self.assertEqual(len(probe["loaded_private"]), 6)
        self.assertEqual(sorted(outcome.native_host), ["chrome", "edge"])
        self.assertEqual(
            [name for name in sys.modules if name.startswith("winsvpn_ext_receipt_")],
            [],
        )
        self.assertEqual(self._snapshot_leftovers(), [])

    def test_caller_process_state_cannot_reach_the_isolated_verifier(self) -> None:
        # Every vector the in-process binding walk had to be extended for, one
        # turn at a time, plus the classes it could not cover (stdlib module
        # attributes, builtins the comparison itself uses, the environment and
        # the working directory), applied to the caller while the child runs.
        self._install_stub_verifier()
        evil = pathlib.Path(self.temporary.name) / "evil-pythonpath"
        evil.mkdir()
        (evil / "ipaddress.py").write_text("raise RuntimeError('hijacked')\n")
        (self.repo / "ipaddress.py").write_text("raise RuntimeError('hijacked')\n")
        real_run = readiness._run_isolated_extension_child

        def hostile_run(request, repo, result_path):
            with contextlib.ExitStack() as stack:
                stack.enter_context(
                    mock.patch.dict(os.environ, {"PYTHONPATH": str(evil)})
                )
                stack.enter_context(
                    mock.patch.object(
                        ipaddress, "ip_network", side_effect=AssertionError("hijacked")
                    )
                )
                stack.enter_context(mock.patch.object(zipfile, "ZipFile", object))
                stack.enter_context(
                    mock.patch.object(unicodedata, "normalize", lambda form, text: "")
                )
                stack.enter_context(
                    mock.patch.object(builtins, "zip", lambda *a, **k: iter(()))
                )
                stack.enter_context(
                    mock.patch.object(builtins, "all", lambda iterable: False)
                )
                return real_run(request, repo, result_path)

        with mock.patch.object(readiness, "_run_isolated_extension_child", hostile_run):
            outcome = self._isolated_outcome()
        probe = outcome.result["probe"]
        self.assertIsNone(outcome.error)
        self.assertNotIn(str(evil), probe["ipaddress_file"])
        self.assertNotIn(self.temporary.name, probe["ipaddress_file"])
        self.assertEqual(probe["zipfile_class"], "zipfile.ZipFile")
        self.assertTrue(probe["normalize_ok"])
        self.assertEqual(probe["zip_pairs"], [[1, 3], [2, 4]])
        self.assertTrue(probe["all_true"])
        self.assertEqual(probe["netmask"], "255.255.255.0")
        self.assertEqual(self._snapshot_leftovers(), [])

    def test_child_import_of_an_unpinned_repository_file_is_rejected(self) -> None:
        self._install_stub_verifier()
        (self.repo / "unpinned_helper.py").write_text("VALUE = 1\n", encoding="utf-8")
        with mock.patch.dict(os.environ, {"STUB_IMPORT_UNPINNED": str(self.repo)}):
            with self.assertRaisesRegex(
                readiness.UploadReadinessError, "unpinned repository modules"
            ):
                self._isolated_outcome()
        self.assertEqual(self._snapshot_leftovers(), [])

    def test_child_import_through_an_aliased_repository_path_is_rejected(
        self,
    ) -> None:
        # The repository root given to the child is lexical; the verifier's own
        # paths are resolved (`Path(__file__).resolve()`), macOS paths are
        # case-insensitive, and a symlink outside the repository can point into
        # it. A repo module reached through any alias is still unpinned.
        self._install_stub_verifier()
        for directory in (self.repo, self.repo / "extension"):
            (directory / "unpinned_helper.py").write_text("VALUE = 1\n", encoding="utf-8")
        outside = pathlib.Path(tempfile.mkdtemp(prefix="repo-alias-"))
        self.addCleanup(shutil.rmtree, outside, True)
        (outside / "extension-link").symlink_to(
            self.repo / "extension", target_is_directory=True
        )
        aliases = {
            os.path.realpath(self.repo),
            str(self.repo.with_name(self.repo.name.swapcase())),
            str(outside / "extension-link"),
        }
        aliases = sorted(
            alias
            for alias in aliases
            if alias != str(self.repo) and os.path.isdir(alias)
        )
        if not aliases:
            self.skipTest("the repository path has no alias on this filesystem")
        for alias in aliases:
            with self.subTest(alias=alias):
                with mock.patch.dict(os.environ, {"STUB_IMPORT_UNPINNED": alias}):
                    with self.assertRaisesRegex(
                        readiness.UploadReadinessError, "unpinned repository modules"
                    ):
                        self._isolated_outcome()
                self.assertEqual(self._snapshot_leftovers(), [])

    def test_symlinked_import_paths_are_judged_by_both_ends(self) -> None:
        # A file symlink outside the repository whose target is a repository
        # file, and a repository symlink whose target is outside: in both the
        # repository decides which bytes run, so both are unpinned.
        self._install_stub_verifier()
        outside = pathlib.Path(tempfile.mkdtemp(prefix="symlink-ends-"))
        self.addCleanup(shutil.rmtree, outside, True)
        marker = pathlib.Path(self.temporary.name) / "symlinked-code-ran"
        repo_helper = self.repo / "extension" / "unpinned_target.py"
        repo_helper.write_text(self.MARKER_SOURCE, encoding="utf-8")
        file_link_dir = outside / "file-link"
        file_link_dir.mkdir()
        (file_link_dir / "unpinned_helper.py").symlink_to(repo_helper)
        target_dir = outside / "target"
        target_dir.mkdir()
        (target_dir / "unpinned_helper.py").write_text(
            self.MARKER_SOURCE, encoding="utf-8"
        )
        repo_link = self.repo / "extension" / "outside-link"
        repo_link.symlink_to(target_dir, target_is_directory=True)
        for label, entry in (
            ("outside_file_symlink_into_the_repository", file_link_dir),
            ("repository_directory_symlink_to_outside", repo_link),
        ):
            with self.subTest(case=label):
                marker.unlink(missing_ok=True)
                with mock.patch.dict(
                    os.environ,
                    {"STUB_IMPORT_UNPINNED": str(entry), "STUB_MARKER": str(marker)},
                ):
                    with self.assertRaisesRegex(
                        readiness.UploadReadinessError, "unpinned repository modules"
                    ):
                        self._isolated_outcome()
                self.assertFalse(marker.exists(), "symlinked code ran in the child")
                self.assertEqual(self._snapshot_leftovers(), [])

    def test_directory_replaced_after_its_first_check_is_judged_again(self) -> None:
        # The child memoizes directory decisions. A directory first seen
        # outside the repository and then replaced by a symlink into it must
        # not keep its earlier verdict.
        self._install_stub_verifier()
        outside = pathlib.Path(tempfile.mkdtemp(prefix="swapped-dir-"))
        self.addCleanup(shutil.rmtree, outside, True)
        directory = outside / "imports"
        directory.mkdir()
        (directory / "outside_first.py").write_text("VALUE = 1\n", encoding="utf-8")
        marker = pathlib.Path(self.temporary.name) / "swapped-code-ran"
        (self.repo / "extension" / "unpinned_second.py").write_text(
            self.MARKER_SOURCE, encoding="utf-8"
        )
        environment = {
            "STUB_SWAP_IMPORT_DIRECTORY": os.pathsep.join(
                (str(directory), str(self.repo / "extension"))
            ),
            "STUB_MARKER": str(marker),
        }
        with mock.patch.dict(os.environ, environment):
            with self.assertRaisesRegex(
                readiness.UploadReadinessError, "unpinned repository modules"
            ):
                self._isolated_outcome()
        self.assertFalse(marker.exists(), "code from the swapped directory ran")
        self.assertEqual(self._snapshot_leftovers(), [])

    MARKER_SOURCE = "import os\nopen(os.environ['STUB_MARKER'], 'w').close()\n"

    def test_unpinned_repository_code_is_refused_before_it_runs(self) -> None:
        # Detecting an unpinned module after it ran is not enough: its bytes
        # already executed in the child and can hide themselves or silence the
        # scan. Each helper below writes a marker the moment its code runs; the
        # child must refuse it (no marker) and the parent must reject the run.
        self._install_stub_verifier()
        marker = pathlib.Path(self.temporary.name) / "unpinned-code-ran"
        helper = self.repo / "unpinned_helper.py"
        bytecode = self.repo / "unpinned_helper.pyc"
        by_location = self.repo / "extension" / "unpinned_by_location.py"
        hiding = {
            "removes_itself_from_sys_modules": "import sys\n"
            "sys.modules.pop(__name__, None)\n",
            "rewrites_its_own_file": "__file__ = os.__file__\n",
            "silences_the_child_scan": "import __main__\n"
            "__main__.sorted = lambda *args, **kwargs: []\n",
        }

        def import_helper(body: str) -> dict[str, str]:
            helper.write_text(self.MARKER_SOURCE + body, encoding="utf-8")
            return {"STUB_IMPORT_UNPINNED": str(self.repo)}

        def import_sourceless_bytecode() -> dict[str, str]:
            # Sourceless bytecode names any file it likes as its code filename,
            # so only the real import origin can identify it.
            source = pathlib.Path(self.temporary.name) / "sourceless_src.py"
            source.write_text(
                self.MARKER_SOURCE + hiding["removes_itself_from_sys_modules"],
                encoding="utf-8",
            )
            py_compile.compile(
                str(source), cfile=str(bytecode), dfile=os.__file__, doraise=True
            )
            return {"STUB_IMPORT_UNPINNED": str(self.repo)}

        def load_by_location() -> dict[str, str]:
            # A loader the verifier drives itself bypasses the import finders
            # and never registers the module in sys.modules.
            by_location.write_text(self.MARKER_SOURCE, encoding="utf-8")
            return {"STUB_LOAD_BY_LOCATION": str(by_location)}

        def unidentifiable_code_filename() -> dict[str, str]:
            return {"STUB_EXEC_UNIDENTIFIABLE": self.MARKER_SOURCE}

        cases = {
            label: functools.partial(import_helper, body)
            for label, body in hiding.items()
        }
        cases["sourceless_bytecode_with_a_forged_filename"] = import_sourceless_bytecode
        cases["loaded_by_location_outside_sys_modules"] = load_by_location
        cases["code_filename_that_cannot_be_stat_ed"] = unidentifiable_code_filename
        for label, prepare in cases.items():
            with self.subTest(case=label):
                for leftover in (helper, bytecode, by_location, marker):
                    leftover.unlink(missing_ok=True)
                environment = dict(prepare(), STUB_MARKER=str(marker))
                with mock.patch.dict(os.environ, environment):
                    with self.assertRaisesRegex(
                        readiness.UploadReadinessError, "unpinned repository modules"
                    ):
                        self._isolated_outcome()
                self.assertFalse(marker.exists(), "unpinned code ran in the child")
                self.assertEqual(self._snapshot_leftovers(), [])

    def test_pinned_file_reached_under_another_name_is_unpinned(self) -> None:
        # The snapshot path is deterministic, so the repository can carry a
        # symlink to it. Imported through that symlink, the origin shares the
        # pinned identity while the loader runs the cached bytecode beside it.
        self._install_stub_verifier()
        marker = pathlib.Path(self.temporary.name) / "cached-bytecode-ran"
        extension = self.repo / "extension"
        digest = hashlib.sha256((extension / "build.py").read_bytes()).hexdigest()
        helper = extension / "unpinned_helper.py"
        helper.symlink_to(f".build.winsvpn-ext-{digest}.py")
        source = pathlib.Path(self.temporary.name) / "cached_src.py"
        source.write_text(self.MARKER_SOURCE, encoding="utf-8")
        py_compile.compile(
            str(source),
            cfile=importlib.util.cache_from_source(str(helper)),
            doraise=True,
            invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
        )
        environment = {"STUB_IMPORT_UNPINNED": str(extension), "STUB_MARKER": str(marker)}
        with mock.patch.dict(os.environ, environment):
            with self.assertRaisesRegex(
                readiness.UploadReadinessError, "unpinned repository modules"
            ):
                self._isolated_outcome()
        self.assertFalse(marker.exists(), "cached bytecode behind a pinned alias ran")
        self.assertEqual(self._snapshot_leftovers(), [])

    def test_child_compares_loaded_origins_by_file_identity(self) -> None:
        # A pinned module whose `__file__` names its own snapshot through a
        # resolved alias is the same file; one that names another file is not.
        self._install_stub_verifier()
        if os.path.realpath(self.repo) == str(self.repo):
            self.skipTest("the repository path has no resolved alias here")
        with mock.patch.dict(os.environ, {"STUB_RESOLVE_OWN_FILE": "1"}):
            outcome = self._isolated_outcome()
        self.assertIsNone(outcome.error)
        with mock.patch.dict(os.environ, {"STUB_FOREIGN_OWN_FILE": "1"}):
            with self.assertRaisesRegex(
                readiness.UploadReadinessError,
                "loaded origin is not the pinned snapshot",
            ):
                self._isolated_outcome()
        self.assertEqual(self._snapshot_leftovers(), [])

    def test_native_host_templates_are_judged_from_closure_bound_bytes(self) -> None:
        self._install_stub_verifier()
        template = (
            self.repo
            / "tools/native_messaging/manifests/org.winsvpn.bridge.chrome.json"
        )
        original = template.read_bytes()
        expected = extension_jsonc.loads(original.decode("utf-8"))
        other = '{"allowed_origins": ["chrome-extension://' + "p" * 32 + '/"]}\n'
        outside = pathlib.Path(tempfile.mkdtemp(prefix="native-host-outside-"))
        self.addCleanup(shutil.rmtree, outside, True)
        (outside / "chrome.json").write_text(other, encoding="utf-8")
        real_run = readiness._run_isolated_extension_child

        def restore() -> None:
            template.unlink(missing_ok=True)
            template.write_bytes(original)

        def rewrite() -> None:
            template.write_text(other, encoding="utf-8")

        def symlink_outside() -> None:
            template.unlink()
            template.symlink_to(outside / "chrome.json")

        # Swapped while the child runs and restored before the parent's
        # closure recheck: the child must still judge the bound bytes.
        for label, swap in (("rewritten", rewrite), ("symlinked", symlink_outside)):
            with self.subTest(swap=label):

                def swap_run_restore(request, repo, result_path, swap=swap):
                    swap()
                    try:
                        return real_run(request, repo, result_path)
                    finally:
                        restore()

                try:
                    with mock.patch.object(
                        readiness, "_run_isolated_extension_child", swap_run_restore
                    ):
                        outcome = self._isolated_outcome()
                finally:
                    restore()
                self.assertEqual(outcome.native_host["chrome"], {"manifest": expected})
                self.assertEqual(self._snapshot_leftovers(), [])

        # Changed after the closure was bound and restored before the recheck:
        # the bytes the child would judge are not the closure's bytes.
        with self.subTest(swap="after_closure_bound"):
            real_closure = readiness.extension_verifier_source_closure
            calls: list[int] = []

            def closure_then_swap(repo):
                closure = real_closure(repo)
                if not calls:
                    rewrite()
                calls.append(1)
                return closure

            def run_then_restore(request, repo, result_path):
                try:
                    return real_run(request, repo, result_path)
                finally:
                    restore()

            try:
                with mock.patch.object(
                    readiness, "extension_verifier_source_closure", closure_then_swap
                ), mock.patch.object(
                    readiness, "_run_isolated_extension_child", run_then_restore
                ):
                    with self.assertRaisesRegex(
                        readiness.UploadReadinessError,
                        "native-host template changed after the verifier closure",
                    ):
                        self._isolated_outcome()
            finally:
                restore()
            self.assertEqual(self._snapshot_leftovers(), [])

    def test_child_refuses_a_verifier_not_bound_to_the_pinned_helpers(self) -> None:
        self._install_stub_verifier()
        for variable in ("STUB_SHRINK_VERIFIER_PATHS", "STUB_REBIND_JSONC"):
            with self.subTest(variable=variable):
                with mock.patch.dict(os.environ, {variable: "1"}):
                    with self.assertRaisesRegex(
                        readiness.UploadReadinessError,
                        "not bound to the pinned helper snapshots",
                    ):
                        self._isolated_outcome()
                self.assertEqual(self._snapshot_leftovers(), [])

    def test_child_refuses_helper_bytes_that_differ_from_the_parent_pin(self) -> None:
        self._install_stub_verifier()
        real_run = readiness._run_isolated_extension_child

        def tamper_then_run(request, repo, result_path):
            _role, path, _pin = request["modules"][2]
            snapshot = pathlib.Path(path)
            os.chmod(snapshot, 0o600)
            snapshot.write_bytes(snapshot.read_bytes() + b"\nTAMPERED = True\n")
            return real_run(request, repo, result_path)

        with mock.patch.object(readiness, "_run_isolated_extension_child", tamper_then_run):
            with self.assertRaisesRegex(
                readiness.UploadReadinessError, "pinned source bytes changed"
            ):
                self._isolated_outcome()
        self.assertEqual(self._snapshot_leftovers(), [])

    def test_source_swap_during_isolated_run_fails_closed(self) -> None:
        self._install_stub_verifier()
        real_run = readiness._run_isolated_extension_child
        for relative in ("extension/tools/checks.py", "extension/build.py"):
            with self.subTest(relative=relative):
                path = self.repo / relative
                original = path.read_bytes()

                def swap_then_run(request, repo, result_path, path=path, original=original):
                    path.write_bytes(original + b"\n# replaced during the run\n")
                    return real_run(request, repo, result_path)

                try:
                    with mock.patch.object(
                        readiness, "_run_isolated_extension_child", swap_then_run
                    ):
                        with self.assertRaisesRegex(
                            readiness.UploadReadinessError, "closure changed"
                        ):
                            self._isolated_outcome()
                finally:
                    path.write_bytes(original)
                self.assertEqual(self._snapshot_leftovers(), [])

    def test_source_swap_is_rechecked_when_the_body_raises(self) -> None:
        self._install_stub_verifier()
        path = self.repo / "extension/tools/checks.py"
        original = path.read_bytes()

        class BodyFailure(RuntimeError):
            pass

        with self.assertRaisesRegex(
            readiness.UploadReadinessError, "closure changed"
        ) as raised:
            with readiness._isolated_extension_verification(
                self.repo, self.target_id, self.artifact
            ):
                path.write_bytes(original + b"\n# replaced after the run\n")
                raise BodyFailure("body failed after the source was replaced")
        self.assertIsInstance(raised.exception.__cause__, BodyFailure)
        self.assertEqual(self._snapshot_leftovers(), [])

    def _install_fake_interpreter(self, mode: str) -> contextlib.ExitStack:
        script = pathlib.Path(tempfile.mkdtemp(prefix="fake-interpreter-")) / "python"
        script.write_text(
            "#!" + sys.executable + "\n"
            "import json, os, sys, time\n"
            "request = json.loads(sys.stdin.buffer.read())\n"
            "mode = os.environ['FAKE_CHILD_MODE']\n"
            "posture = {'isolated': 1, 'ignore_environment': 1, 'no_user_site': 1,\n"
            "           'no_site': 1, 'dont_write_bytecode': 1, 'argv': ['-c']}\n"
            "loaded = {r: [p, 'winsvpn_ext_receipt_%s_%s' % (r, d)]\n"
            "          for r, p, d in request['modules']}\n"
            "report = {'posture': posture, 'native_host': {}, 'loaded': loaded,\n"
            "          'unpinned_repo_modules': [], 'error': 'forged'}\n"
            "if mode == 'bad_posture':\n"
            "    report['posture'] = dict(posture, isolated=0)\n"
            "elif mode == 'bad_argv':\n"
            "    report['posture'] = dict(posture, argv=['-c', 'x'])\n"
            "elif mode == 'unpinned_module':\n"
            "    report['unpinned_repo_modules'] = ['ipaddress']\n"
            "elif mode == 'wrong_module_name':\n"
            "    report['loaded']['checks'][1] = 'checks'\n"
            "elif mode == 'wrong_module_path':\n"
            "    report['loaded']['checks'][0] = report['loaded']['jsonc'][0]\n"
            "elif mode == 'missing_role':\n"
            "    del report['loaded']['leakscan']\n"
            "elif mode == 'extra_role':\n"
            "    report['loaded']['rogue'] = ['/x', 'rogue']\n"
            "elif mode == 'extra_key':\n"
            "    report['extra'] = 1\n"
            "elif mode == 'missing_key':\n"
            "    del report['native_host']\n"
            "elif mode == 'no_error_no_result':\n"
            "    del report['error']\n"
            "elif mode == 'array_report':\n"
            "    report = []\n"
            "elif mode == 'resolved_module_path':\n"
            "    path = report['loaded']['checks'][0]\n"
            "    report['loaded']['checks'][0] = os.path.realpath(path)\n"
            "elif mode == 'aliased_module_path':\n"
            "    path = report['loaded']['checks'][0]\n"
            "    link = os.path.join(os.path.dirname(path), '.forged-alias-link')\n"
            "    os.symlink(os.sep, link)\n"
            "    report['loaded']['checks'][0] = os.path.join(\n"
            "        link, os.pardir, os.path.basename(path))\n"
            "elif mode == 'sleep':\n"
            "    open(os.environ['FAKE_PID_FILE'], 'w').write(str(os.getpid()))\n"
            "    time.sleep(60)\n"
            "if mode != 'no_result':\n"
            "    with open(request['result_path'], 'w') as handle:\n"
            "        json.dump(report, handle)\n"
            "sys.exit(3 if mode == 'exit_nonzero' else 0)\n",
            encoding="utf-8",
        )
        os.chmod(script, 0o755)
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch.object(sys, "executable", str(script)))
        stack.enter_context(
            mock.patch.dict(os.environ, {"FAKE_CHILD_MODE": mode})
        )
        stack.callback(shutil.rmtree, script.parent, True)
        return stack

    def test_forged_child_reports_are_rejected(self) -> None:
        self._install_stub_verifier()
        with self._install_fake_interpreter("honest"):
            outcome = self._isolated_outcome()
        self.assertEqual(outcome.error, "forged")
        cases = {
            "bad_posture": "did not run in an isolated interpreter",
            "bad_argv": "did not run in an isolated interpreter",
            "unpinned_module": "unpinned repository modules",
            "wrong_module_name": "executed origin is not the bound snapshot",
            "wrong_module_path": "executed origin is not the bound snapshot",
            "missing_role": "unexpected helper set",
            "extra_role": "unexpected helper set",
            "extra_key": "result is malformed",
            "missing_key": "result is malformed",
            "no_error_no_result": "result is malformed",
            "array_report": "result is malformed",
            "no_result": "produced no result",
            "exit_nonzero": "exited 3",
        }
        for mode, pattern in cases.items():
            with self.subTest(mode=mode):
                with self._install_fake_interpreter(mode):
                    with self.assertRaisesRegex(readiness.UploadReadinessError, pattern):
                        self._isolated_outcome()
                self.assertEqual(self._snapshot_leftovers(), [])

    def test_forged_report_origins_are_compared_by_file_identity(self) -> None:
        # The parent decides by file identity: a resolved alias of the snapshot
        # is the snapshot, and a path that only normalizes lexically to the
        # snapshot (`link/..` through a symlink) is not.
        self._install_stub_verifier()
        if os.path.realpath(self.repo) != str(self.repo):
            with self.subTest(mode="resolved_module_path"):
                with self._install_fake_interpreter("resolved_module_path"):
                    outcome = self._isolated_outcome()
                self.assertEqual(outcome.error, "forged")
        with self.subTest(mode="aliased_module_path"):
            with self._install_fake_interpreter("aliased_module_path"):
                with self.assertRaisesRegex(
                    readiness.UploadReadinessError,
                    "executed origin is not the bound snapshot",
                ):
                    self._isolated_outcome()
        self.assertEqual(self._snapshot_leftovers(), [])

    def test_hung_isolated_verifier_is_killed_at_the_timeout(self) -> None:
        self._install_stub_verifier()
        pid_file = pathlib.Path(self.temporary.name) / "child.pid"
        with mock.patch.object(readiness, "_EXTENSION_ISOLATED_TIMEOUT_SECONDS", 1):
            with mock.patch.dict(os.environ, {"FAKE_PID_FILE": str(pid_file)}):
                with self._install_fake_interpreter("sleep"):
                    with self.assertRaisesRegex(
                        readiness.UploadReadinessError, "timed out"
                    ):
                        self._isolated_outcome()
        pid = int(pid_file.read_text())
        deadline = dt.datetime.now() + dt.timedelta(seconds=5)
        alive = True
        while alive and dt.datetime.now() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                alive = False
        self.assertFalse(alive)
        self.assertEqual(self._snapshot_leftovers(), [])

    def test_verify_extension_zip_artifact_binds_the_isolated_result(self) -> None:
        self._install_stub_verifier()
        with mock.patch.object(readiness, "verify_extension_cross_store_hardening"):
            result = readiness.verify_extension_zip_artifact(
                self.repo, self.target_id, self.artifact
            )
        self.assertTrue(result["ok"])
        self.assertEqual(
            result["artifact_sha256"],
            hashlib.sha256(self.artifact.read_bytes()).hexdigest(),
        )
        self.assertEqual(self._snapshot_leftovers(), [])
        for variable, pattern in (
            ("STUB_VERIFIER_RAISES", "leak/policy verification failed: stub verifier"),
            ("STUB_VERIFIER_WRONG_SHA", "not bound to the artifact"),
        ):
            with self.subTest(variable=variable):
                with mock.patch.dict(os.environ, {variable: "1"}):
                    with mock.patch.object(
                        readiness, "verify_extension_cross_store_hardening"
                    ):
                        with self.assertRaisesRegex(
                            readiness.UploadReadinessError, pattern
                        ):
                            readiness.verify_extension_zip_artifact(
                                self.repo, self.target_id, self.artifact
                            )
                self.assertEqual(self._snapshot_leftovers(), [])

    def test_isolated_native_host_identity_rules_still_apply(self) -> None:
        self._install_stub_verifier()
        template = (
            self.repo
            / "tools/native_messaging/manifests/org.winsvpn.bridge.chrome.json"
        )
        original = template.read_text(encoding="utf-8")
        edge = (
            self.repo / "tools/native_messaging/manifests/org.winsvpn.bridge.edge.json"
        ).read_text(encoding="utf-8")
        cases = {
            "placeholder or invalid": '{"allowed_origins": ["chrome-extension://REPLACE_ME/"]}',
            "is not exact": '{"allowed_origins": []}',
            "template is invalid": "{not json",
            "must be distinct": edge,
        }
        try:
            for pattern, body in cases.items():
                with self.subTest(pattern=pattern):
                    template.write_text(body, encoding="utf-8")
                    with mock.patch.object(
                        readiness, "verify_extension_cross_store_hardening"
                    ):
                        with self.assertRaisesRegex(
                            readiness.UploadReadinessError, pattern
                        ):
                            readiness.verify_extension_zip_artifact(
                                self.repo, self.target_id, self.artifact
                            )
                    self.assertEqual(self._snapshot_leftovers(), [])
        finally:
            template.write_text(original, encoding="utf-8")

    def test_symlink_artifact_is_rejected(self) -> None:
        self._write_extension_zip(self.artifact)
        link = self.artifact.with_name("wins-vpn-chrome-extension-package-link.zip")
        os.symlink(self.artifact.name, link)
        with self.assertRaises((readiness.UploadReadinessError, freeze.DependencyFreezeError)):
            readiness.verify_extension_zip_artifact(
                self.repo, self.target_id, link
            )
        self.assertEqual(self._snapshot_leftovers(), [])

    def test_hardlink_artifact_is_rejected(self) -> None:
        self._write_extension_zip(self.artifact)
        alias = self.artifact.with_name("wins-vpn-chrome-extension-package-alias.zip")
        os.link(self.artifact, alias)
        info = self.artifact.lstat()
        self.assertGreater(info.st_nlink, 1)
        with self.assertRaisesRegex(
            readiness.UploadReadinessError,
            "hardlink|not regular|changed",
        ):
            readiness.verify_extension_zip_artifact(
                self.repo, self.target_id, self.artifact
            )
        self.assertEqual(self._snapshot_leftovers(), [])

    def test_successful_verify_leaves_no_snapshots(self) -> None:
        self._write_extension_zip(self.artifact)
        result = readiness.verify_extension_zip_artifact(
            self.repo, self.target_id, self.artifact
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["artifact_sha256"], hashlib.sha256(self.artifact.read_bytes()).hexdigest())
        self.assertEqual(self._snapshot_leftovers(), [])

    def test_gate_executed_argv_uses_artifact_snapshot_not_live_path(self) -> None:
        self._write_extension_zip(self.artifact)
        for relative in (
            "extension/tools/assert_chrome_zip.py",
            "tools/validate_release_artifact_privacy.py",
        ):
            destination = self.repo / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        self._install_exit0_gate_producers()
        evidence_dir = self.repo / ".artifacts" / "extension-gate"
        evidence_dir.mkdir(parents=True, mode=0o700)
        os.chmod(evidence_dir, 0o700)
        relative_artifact = self.artifact.relative_to(self.repo).as_posix()
        target = readiness.TARGET_BY_ID[self.target_id]
        commands = {
            target.signing_gate_id: (
                sys.executable,
                "extension/tools/assert_chrome_zip.py",
                "--verify",
                self.target_id,
                relative_artifact,
            ),
            target.hardening_gate_id: (
                sys.executable,
                "tools/validate_release_artifact_privacy.py",
                "--verify",
                self.target_id,
                relative_artifact,
            ),
        }
        references = readiness.execute_target_gate_transaction(
            self.repo,
            self.target_id,
            self.artifact,
            commands,
            evidence_dir,
        )
        evidence_path = self.repo / references[target.signing_gate_id]["evidence_path"]
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        command = evidence["command"]
        self.assertEqual(command["argv"][4], relative_artifact)
        self.assertIn(".winsvpn-art-", command["executed_argv"][4])
        self.assertIn(".winsvpn-gate-", command["executed_argv"][1])
        self.assertEqual(
            command["executed_argv"][1],
            evidence["runner"]["exact_byte_execution"]["snapshot_path"],
        )
        self.assertTrue(evidence["runner"]["exact_byte_execution"]["hardlink_same_inode"])
        self.assertTrue(evidence["runner"]["exact_byte_execution"]["cleanup_complete"])
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
            evidence["runner"]["controller_sha256"],
            readiness._live_production_controller_digest(),
        )
        artifact_bytes, mtime_ns, artifact_sha = readiness._stable_identity(
            self.artifact, "chrome custody artifact"
        )
        artifact_binding = {
            "path": relative_artifact,
            "sha256": artifact_sha,
            "bytes": artifact_bytes,
        }
        now = dt.datetime.now(tz=dt.timezone.utc)
        artifact_time = dt.datetime.fromtimestamp(
            mtime_ns / 1_000_000_000, tz=dt.timezone.utc
        )
        for gate_id in (target.signing_gate_id, target.hardening_gate_id):
            readiness._verify_gate_evidence(
                self.repo,
                target,
                references[gate_id],
                gate_id,
                artifact_binding,
                artifact_time,
                now,
            )
        self.assertEqual(self._snapshot_leftovers(), [])

    def test_python_symlink_to_same_interpreter_is_accepted(self) -> None:
        self._prepare_chrome_gate_paths()
        link = self.repo / "bin" / "python3"
        link.parent.mkdir(parents=True)
        os.symlink(sys.executable, link)
        argv = (
            str(link),
            "extension/tools/assert_chrome_zip.py",
            "--verify",
            self.target_id,
            self.artifact.relative_to(self.repo).as_posix(),
        )
        validated, _producer_id, _producer_file, producer_index = (
            readiness._validate_gate_argv(
                self.repo,
                self.target_id,
                "chrome-package-verification",
                self.artifact,
                argv,
            )
        )
        self.assertEqual(validated[0], str(link))
        self.assertEqual(producer_index, 1)

    def test_python_name_pointing_at_different_file_is_rejected(self) -> None:
        self._prepare_chrome_gate_paths()
        impostor = self.repo / "bin" / "python3"
        impostor.parent.mkdir(parents=True)
        impostor.write_bytes(b"#!/bin/sh\necho substituted-interpreter\n")
        os.chmod(impostor, 0o755)
        argv = (
            str(impostor),
            "extension/tools/assert_chrome_zip.py",
            "--verify",
            self.target_id,
            self.artifact.relative_to(self.repo).as_posix(),
        )
        with self.assertRaisesRegex(
            readiness.UploadReadinessError,
            "does not execute the bound producer",
        ):
            readiness._validate_gate_argv(
                self.repo,
                self.target_id,
                "chrome-package-verification",
                self.artifact,
                argv,
            )

    def _prepare_chrome_gate_paths(self) -> None:
        self.artifact.write_bytes(b"PK\x03\x04chrome-dummy-artifact\n")
        destination = self.repo / "extension/tools/assert_chrome_zip.py"
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "extension/tools/assert_chrome_zip.py", destination)

    def _install_exit0_gate_producers(self) -> None:
        for relative in (
            "extension/tools/assert_chrome_zip.py",
            "tools/validate_release_artifact_privacy.py",
        ):
            path = self.repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                "#!/usr/bin/env python3\nimport sys\nraise SystemExit(0)\n",
                encoding="ascii",
            )
            os.chmod(path, 0o755)

    def _chrome_gate_commands(self) -> dict[str, tuple[str, ...]]:
        target = readiness.TARGET_BY_ID[self.target_id]
        relative_artifact = self.artifact.relative_to(self.repo).as_posix()
        return {
            target.signing_gate_id: (
                sys.executable,
                "extension/tools/assert_chrome_zip.py",
                "--verify",
                self.target_id,
                relative_artifact,
            ),
            target.hardening_gate_id: (
                sys.executable,
                "tools/validate_release_artifact_privacy.py",
                "--verify",
                self.target_id,
                relative_artifact,
            ),
        }

    def _prepare_chrome_gate_execution(self) -> pathlib.Path:
        self._write_extension_zip(self.artifact)
        self._install_exit0_gate_producers()
        evidence_dir = self.repo / ".artifacts" / "extension-gate"
        evidence_dir.mkdir(parents=True, mode=0o700)
        os.chmod(evidence_dir, 0o700)
        return evidence_dir

    def _spoofed_result(
        self,
        argv: tuple[str, ...],
        **fields: object,
    ) -> gate_runner.GateProcessResult:
        values = {
            "argv": argv,
            "stdout": "verified",
            "stderr": "",
            "exit_code": 0,
            "executed": True,
            "runner_id": gate_runner.SubprocessExplicitArgvRunner.RUNNER_ID,
            "shell_enabled": False,
        }
        values.update(fields)
        return gate_runner.GateProcessResult(**values)

    def test_spoofed_gate_process_result_cannot_mint_production_pass(self) -> None:
        evidence_dir = self._prepare_chrome_gate_execution()
        commands = self._chrome_gate_commands()
        runner = FakeExplicitArgvRunner()
        with self.assertRaisesRegex(
            readiness.UploadReadinessError,
            "test-only runner cannot emit accepted production PASS",
        ):
            readiness.execute_target_gate_transaction(
                self.repo,
                self.target_id,
                self.artifact,
                commands,
                evidence_dir,
                runner=runner,
            )
        self.assertEqual(len(runner.calls), 1)
        self.assertEqual(list(evidence_dir.glob("*.json")), [])

    def test_caller_supplied_production_runner_instance_is_rejected(self) -> None:
        evidence_dir = self._prepare_chrome_gate_execution()
        with self.assertRaisesRegex(
            readiness.UploadReadinessError,
            "caller-supplied or mocked runner identity",
        ):
            readiness.execute_target_gate_transaction(
                self.repo,
                self.target_id,
                self.artifact,
                self._chrome_gate_commands(),
                evidence_dir,
                runner=gate_runner.SubprocessExplicitArgvRunner(),
            )

    def test_unmarked_lookalike_runner_is_rejected(self) -> None:
        evidence_dir = self._prepare_chrome_gate_execution()

        class Lookalike:
            def run(self, argv, *, cwd):
                exact = tuple(argv)
                return gate_runner.GateProcessResult(
                    argv=exact,
                    stdout="verified",
                    stderr="",
                    exit_code=0,
                    executed=True,
                    runner_id=gate_runner.SubprocessExplicitArgvRunner.RUNNER_ID,
                    shell_enabled=False,
                )

        with self.assertRaisesRegex(
            readiness.UploadReadinessError,
            "caller-supplied or mocked runner identity",
        ):
            readiness.execute_target_gate_transaction(
                self.repo,
                self.target_id,
                self.artifact,
                self._chrome_gate_commands(),
                evidence_dir,
                runner=Lookalike(),
            )

    def test_default_factory_patch_cannot_replace_sealed_runner(self) -> None:
        evidence_dir = self._prepare_chrome_gate_execution()
        commands = self._chrome_gate_commands()
        fake = FakeExplicitArgvRunner()
        with mock.patch.object(
            readiness, "DEFAULT_GATE_RUNNER_FACTORY", FakeExplicitArgvRunner
        ):
            references = readiness.execute_target_gate_transaction(
                self.repo,
                self.target_id,
                self.artifact,
                commands,
                evidence_dir,
            )
        self.assertEqual(fake.calls, [])
        target = readiness.TARGET_BY_ID[self.target_id]
        evidence_path = self.repo / references[target.signing_gate_id]["evidence_path"]
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        self.assertEqual(
            evidence["runner"]["id"],
            gate_runner.SubprocessExplicitArgvRunner.RUNNER_ID,
        )
        self.assertTrue(evidence["runner"]["production_pass_allowed"])
        self.assertEqual(
            evidence["runner"]["controller_sha256"],
            readiness._live_production_controller_digest(),
        )
        self.assertNotEqual(
            evidence["runner"]["id"],
            readiness.TEST_ONLY_GATE_RUNNER_ID,
        )

    def test_spoofed_result_field_mutations_are_rejected(self) -> None:
        evidence_dir = self._prepare_chrome_gate_execution()
        commands = self._chrome_gate_commands()
        mutations = (
            ({"executed": False}, "did not prove exact"),
            ({"shell_enabled": True}, "shell-disabled"),
            ({"argv": ("true",)}, "did not prove exact"),
            ({"stdout": 1}, "did not prove exact"),
        )
        for fields, pattern in mutations:
            runner = FakeExplicitArgvRunner()

            def run(self_runner, argv, *, cwd, applied=fields):
                exact = tuple(argv)
                self_runner.calls.append(exact)
                spoof_argv = applied.get("argv", exact)
                extras = {key: value for key, value in applied.items() if key != "argv"}
                return self._spoofed_result(spoof_argv, **extras)

            runner.run = run.__get__(runner, FakeExplicitArgvRunner)
            with self.assertRaisesRegex(readiness.UploadReadinessError, pattern):
                readiness.execute_target_gate_transaction(
                    self.repo,
                    self.target_id,
                    self.artifact,
                    commands,
                    evidence_dir,
                    runner=runner,
                )
            self.assertEqual(list(evidence_dir.glob("*.json")), [])

    def test_evidence_controller_mutations_fail_closed(self) -> None:
        evidence_dir = self._prepare_chrome_gate_execution()
        commands = self._chrome_gate_commands()
        references = readiness.execute_target_gate_transaction(
            self.repo,
            self.target_id,
            self.artifact,
            commands,
            evidence_dir,
        )
        target = readiness.TARGET_BY_ID[self.target_id]
        artifact_bytes, mtime_ns, artifact_sha = readiness._stable_identity(
            self.artifact, "chrome custody artifact"
        )
        artifact_binding = {
            "path": self.artifact.relative_to(self.repo).as_posix(),
            "sha256": artifact_sha,
            "bytes": artifact_bytes,
        }
        now = dt.datetime.now(tz=dt.timezone.utc)
        artifact_time = dt.datetime.fromtimestamp(
            mtime_ns / 1_000_000_000, tz=dt.timezone.utc
        )

        def mutate_and_verify(mutator, pattern: str) -> None:
            gate_id = target.signing_gate_id
            evidence_path = self.repo / references[gate_id]["evidence_path"]
            anchor = evidence_path.with_name(evidence_path.name + ".sha256")
            evidence_mode = evidence_path.lstat().st_mode & 0o777
            anchor_mode = anchor.lstat().st_mode & 0o777
            self.assertEqual(evidence_mode, 0o400)
            self.assertEqual(anchor_mode, 0o400)
            original = evidence_path.read_bytes()
            original_anchor = anchor.read_bytes()

            def write_custody(record: bytes, anchor_bytes: bytes) -> None:
                os.chmod(evidence_path, 0o600)
                os.chmod(anchor, 0o600)
                try:
                    evidence_path.write_bytes(record)
                    anchor.write_bytes(anchor_bytes)
                finally:
                    os.chmod(evidence_path, evidence_mode)
                    os.chmod(anchor, anchor_mode)

            payload = json.loads(original.decode("utf-8"))
            mutator(payload)
            mutated = (
                json.dumps(payload, indent=2, sort_keys=True) + "\n"
            ).encode("utf-8")
            digest = hashlib.sha256(mutated).hexdigest()
            try:
                write_custody(
                    mutated,
                    f"{digest}  {evidence_path.name}\n".encode("ascii"),
                )
                mutated_ref = dict(references[gate_id])
                mutated_ref["evidence_sha256"] = digest
                with self.assertRaisesRegex(
                    readiness.UploadReadinessError, pattern
                ):
                    readiness._verify_gate_evidence(
                        self.repo,
                        target,
                        mutated_ref,
                        gate_id,
                        artifact_binding,
                        artifact_time,
                        now,
                    )
            finally:
                write_custody(original, original_anchor)
            self.assertEqual(evidence_path.read_bytes(), original)
            self.assertEqual(anchor.read_bytes(), original_anchor)
            self.assertEqual(evidence_path.lstat().st_mode & 0o777, evidence_mode)
            self.assertEqual(anchor.lstat().st_mode & 0o777, anchor_mode)

        mutate_and_verify(
            lambda payload: payload["runner"].__setitem__(
                "controller_sha256", "0" * 64
            ),
            "binding is invalid",
        )
        mutate_and_verify(
            lambda payload: payload["runner"].__setitem__(
                "production_pass_allowed", False
            ),
            "binding is invalid",
        )
        mutate_and_verify(
            lambda payload: payload["runner"].__setitem__(
                "id", readiness.TEST_ONLY_GATE_RUNNER_ID
            ),
            "binding is invalid",
        )
        mutate_and_verify(
            lambda payload: payload["runner"].__setitem__(
                "controller_path", "tools/test_extension_receipt_execution_custody.py"
            ),
            "binding is invalid",
        )
        mutate_and_verify(
            lambda payload: payload.__setitem__("stdout", "mutated-output\n"),
            "binding is invalid",
        )

    def test_post_snapshot_tamper_cannot_pass_zip_hardening(self) -> None:
        original = self._write_extension_zip(self.artifact)
        swapped = original + b"\n"
        before = self.artifact.lstat()
        real = readiness.verify_extension_cross_store_hardening
        observed: dict[str, pathlib.Path] = {}

        def tamper_after_success(target_id, artifact_path, expected_sha256=None):
            result = real(
                target_id, artifact_path, expected_sha256=expected_sha256
            )
            observed["snapshot_path"] = artifact_path
            artifact_path.write_bytes(swapped)
            return result

        with mock.patch.object(
            readiness,
            "verify_extension_cross_store_hardening",
            tamper_after_success,
        ):
            with self.assertRaises(readiness.UploadReadinessError) as caught:
                readiness.verify_extension_zip_artifact(
                    self.repo, self.target_id, self.artifact
                )

        chain: list[str] = []
        error: BaseException | None = caught.exception
        while error is not None and len(chain) < 16:
            chain.append(str(error))
            error = error.__cause__ or error.__context__
        self.assertRegex(
            chain[0],
            r"artifact snapshot verification failed: "
            r"Descriptor-bound artifact cleanup failed: "
            r"Artifact cleanup refused a substituted snapshot entry\.",
        )
        self.assertTrue(
            any(
                "artifact snapshot is not the bound identity" in text
                for text in chain
            ),
            chain,
        )
        self.assertNotEqual(observed["snapshot_path"], self.artifact)
        after = self.artifact.lstat()
        self.assertEqual(self.artifact.read_bytes(), original)
        self.assertEqual(
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns),
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
        )


if __name__ == "__main__":
    unittest.main()
