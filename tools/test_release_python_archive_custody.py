#!/usr/bin/env python3
"""Fixture tests for macOS release-Python archive custody and owner provisioning."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tools" / "release_python_archive_custody.sh"
PROVISIONER = ROOT / "tools" / "provision_macos_release_python_runtime.sh"
RECEIPT_TOOL = ROOT / "tools" / "macos_release_python_runtime_receipt.py"
PIN_MANIFEST = ROOT / "tools" / "toolchain-pins.json"
EXECUTION_BLOCKER = (
    "owner/environment blocker: this host cannot make the Python tree "
    "immutable against same-user path replacement through execution"
)

SPEC = importlib.util.spec_from_file_location(
    "macos_release_python_runtime_receipt", RECEIPT_TOOL
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Python runtime receipt schema")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def shlex_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


@unittest.skipUnless(sys.platform == "darwin", "macOS package tools are required")
class ReleasePythonArchiveCustodyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.base = Path(tempfile.mkdtemp(prefix="wins-python-custody-", dir="/private/tmp"))
        cls.inputs = cls.base / "inputs"
        cls.inputs.mkdir(mode=0o700)
        cls.package = cls._make_package()
        cls.wheel = cls._make_wheel("pytest-9.1.1-py3-none-any.whl", safe=True)
        cls.package.chmod(0o444)
        cls.wheel.chmod(0o444)

    @classmethod
    def tearDownClass(cls) -> None:
        for path in cls.base.rglob("*"):
            if not path.is_symlink():
                try:
                    path.chmod(path.stat().st_mode | stat.S_IWUSR | stat.S_IXUSR)
                except FileNotFoundError:
                    pass
        shutil.rmtree(cls.base, ignore_errors=True)

    @classmethod
    def _make_package(cls) -> Path:
        payload = cls.base / "framework-payload"
        executable = payload / "Versions" / "3.14" / "bin" / "python3.14"
        executable.parent.mkdir(parents=True)
        source = cls.base / "python-fixture.c"
        source.write_text(
            "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <unistd.h>\n"
            "int main(int argc, char **argv) {\n"
            "  const char *framework = getenv(\"DYLD_FRAMEWORK_PATH\");\n"
            "  const char *library = getenv(\"DYLD_LIBRARY_PATH\");\n"
            "  if (argc < 2 || strcmp(argv[1], \"-S\") != 0) return 91;\n"
            "  if (!framework) return 92;\n"
            "  if (!library || strncmp(framework, library, strlen(framework)) != 0) return 93;\n"
            "  if (getenv(\"DYLD_INSERT_LIBRARIES\") || getenv(\"PYTHONSTARTUP\") || "
            "getenv(\"PYTHONINSPECT\") || getenv(\"PYTHONWARNINGS\")) return 94;\n"
            "  fputs(\"custody-env-clean\\n\", stderr);\n"
            "  argv[1] = (char *)\"-S\";\n"
            "  execv(\"/usr/bin/python3\", argv);\n"
            "  return 95;\n}\n",
            encoding="utf-8",
        )
        subprocess.run(
            ["/usr/bin/clang", "-Os", "-o", str(executable), str(source)],
            check=True,
            capture_output=True,
            text=True,
        )
        stdlib = payload / "Versions" / "3.14" / "lib" / "python3.14"
        dynload = stdlib / "lib-dynload"
        dynload.mkdir(parents=True)
        (stdlib / "os.py").write_text("def getcwd():\n    return '/'\n", encoding="ascii")
        (stdlib / "sitecustomize.py").write_text("# fixture sitecustomize\n", encoding="ascii")
        with zipfile.ZipFile(stdlib / "python314.zip", "w") as archive:
            archive.writestr("encodings/__init__.py", "# fixture stdlib zip\n")
        dylib_src = cls.base / "python-dylib.c"
        dylib_src.write_text("int wins_python_fixture_dylib = 1;\n", encoding="ascii")
        dylib = payload / "Versions" / "3.14" / "Python"
        subprocess.run(
            [
                "/usr/bin/clang",
                "-Os",
                "-dynamiclib",
                "-install_name",
                "@rpath/Python.framework/Versions/3.14/Python",
                "-o",
                str(dylib),
                str(dylib_src),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        extension = dynload / "_socket.cpython-314-darwin.so"
        subprocess.run(
            [
                "/usr/bin/clang",
                "-Os",
                "-bundle",
                "-o",
                str(extension),
                str(dylib_src),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        resources = payload / "Versions" / "3.14" / "Resources"
        resources.mkdir()
        (resources / "Info.plist").write_text(
            '<?xml version="1.0"?><plist version="1.0"><dict>'
            "<key>CFBundleIdentifier</key><string>org.python.python</string>"
            "</dict></plist>\n",
            encoding="ascii",
        )
        os.symlink("3.14", payload / "Versions" / "Current")
        os.symlink("Versions/Current/Python", payload / "Python")
        os.symlink("Versions/Current/Resources", payload / "Resources")
        component = cls.base / "Python_Framework.pkg"
        outer = cls.inputs / "python-3.14.7-macos11.pkg"
        subprocess.run(
            [
                "/usr/bin/pkgbuild",
                "--root",
                str(payload),
                "--identifier",
                "org.python.Python.PythonFramework",
                "--version",
                "3.14.7",
                str(component),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            ["/usr/bin/productbuild", "--package", str(component), str(outer)],
            check=True,
            capture_output=True,
            text=True,
        )
        return outer

    @classmethod
    def _make_wheel(cls, name: str, *, safe: bool) -> Path:
        wheel = cls.inputs / name
        with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(
                "fixture_probe.py",
                "import os\nprint('module:' + os.environ.get('PYTHONPATH', 'missing'))\n",
            )
            archive.writestr("pytest/__init__.py", "__version__ = 'fixture'\n")
            archive.writestr("pytest-9.1.1.dist-info/METADATA", "Name: pytest\nVersion: 9.1.1\n")
            if not safe:
                archive.writestr("pytest_startup.pth", "raise RuntimeError('must not execute')\n")
        return wheel

    def setUp(self) -> None:
        self.package.chmod(0o444)
        self.wheel.chmod(0o444)
        self.case = Path(tempfile.mkdtemp(prefix="case-", dir=self.base))
        os.environ.pop(MODULE.RECEIPT_ENV, None)

    def tearDown(self) -> None:
        os.environ.pop(MODULE.RECEIPT_ENV, None)
        for path in self.case.rglob("*"):
            if not path.is_symlink():
                try:
                    path.chmod(path.stat().st_mode | stat.S_IWUSR | stat.S_IXUSR)
                except FileNotFoundError:
                    pass
        shutil.rmtree(self.case, ignore_errors=True)

    def _manifest(
        self,
        *,
        package: Path | None = None,
        package_hash: str | None = None,
        wheel: Path | None = None,
        wheel_hash: str | None = None,
    ) -> Path:
        package = package or self.package
        wheel = wheel or self.wheel
        data = {
            "tools": {
                "python": {
                    "archive_custody": {
                        "darwin_arm64": {
                            "package": {
                                "path": str(package),
                                "sha256": package_hash or sha256(package),
                            },
                            "framework_component": "Python_Framework.pkg",
                            "python_executable": "Versions/3.14/bin/python3.14",
                            "runtime_wheel_count": 1,
                            "wheel_count": 1,
                            "wheels": {
                                "0": {
                                    "path": str(wheel),
                                    "sha256": wheel_hash or sha256(wheel),
                                }
                            },
                        }
                    }
                }
            }
        }
        manifest = self.case / "pins.json"
        manifest.write_text(json.dumps(data), encoding="utf-8")
        manifest.chmod(0o600)
        return manifest

    def _shell(
        self,
        body: str,
        *,
        env: dict[str, str] | None = None,
        timeout: int = 60,
    ) -> subprocess.CompletedProcess[str]:
        script = textwrap.dedent(
            f"""
            set -euo pipefail
            source {shlex_quote(str(HELPER))}
            {body}
            """
        )
        return subprocess.run(
            ["/bin/bash", "-c", script],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout,
        )

    def _assert_owner_blocked_not_run(
        self,
        completed: subprocess.CompletedProcess[str],
        *,
        ran_markers: tuple[str, ...] = (),
    ) -> None:
        combined = completed.stdout + completed.stderr
        self.assertNotEqual(completed.returncode, 0, combined)
        if EXECUTION_BLOCKER in completed.stderr:
            self.assertIn(
                "owner-provisioned root-owned Python 3.14.7 runtime is unavailable",
                combined,
            )
            self.assertIn("fixed ReleasePython owner-provisioning boundary", combined)
            self.assertIn("/Library/WinsVPN/ReleasePythonAuthority/v2/owner-provision", combined)
            self.assertNotIn("sudo", combined.lower())
        else:
            self.assertRegex(
                completed.stderr,
                r"wrong archive/tree|replacement repository or pin manifest cannot self-authorize custody",
            )
        for marker in ran_markers:
            self.assertNotIn(marker, completed.stdout)

    def test_shell_syntax(self) -> None:
        for path in (HELPER, PROVISIONER):
            completed = subprocess.run(
                ["/bin/bash", "-n", str(path)], capture_output=True, text=True
            )
            self.assertEqual(completed.returncode, 0, path.name + completed.stderr)

    def test_source_binds_owner_runtime_not_tmp_clone(self) -> None:
        source = HELPER.read_text(encoding="ascii")
        provisioner = PROVISIONER.read_text(encoding="ascii")
        receipt = RECEIPT_TOOL.read_text(encoding="ascii")
        self.assertIn("/Library/WinsVPN/ReleasePython/3.14.7", source)
        self.assertIn("UF_IMMUTABLE is insufficient", source)
        self.assertIn("SF_IMMUTABLE is required", receipt)
        self.assertIn(EXECUTION_BLOCKER, source)
        self.assertIn("macos_release_python_runtime_receipt.py", source)
        self.assertNotIn("fclonefileat", source)
        self.assertNotIn("wins-release-python-archive.", source)
        self.assertNotIn("kernel_seal_tree", source)
        self.assertIn("deny file-write*", source)
        self.assertIn("never elevates privilege", provisioner)
        self.assertIn("fixed root-owned SF_IMMUTABLE boundary", provisioner)
        self.assertIn("refuse root execution", provisioner)
        self.assertIn("macos_release_python_runtime.custody.json", provisioner)
        self.assertNotIn("sudo", provisioner.lower())
        self.assertIn("WINS_RECEIPT_MIGRATION_HELD_SOURCE_FD", source)
        self.assertIn("WINS_RECEIPT_MIGRATION_EXECUTED_SOURCE_SHA256", source)
        self.assertIn("WINS_RECEIPT_EXECUTED_SOURCE_SHA256", source)
        self.assertIn("fd=os.open(path,os.O_RDONLY|nofollow", source)
        self.assertIn('"$python_bin" -I -S -c "$bootstrap"', source)
        self.assertNotRegex(provisioner, r"inspect-existing[\s\S]{0,120}\|\|\s*true")
        self.assertIn('if [[ "${BASH_SOURCE[0]}" == /dev/fd/8 ]]', source)
        normal_source = source.split("else\n", 1)[1].split("fi\n", 1)[0]
        self.assertNotIn("_WINS_RP_HELD_HELPER_DIR", normal_source)
        self.assertIn(f"_WINS_RP_RECEIPT_MODULE_SHA256={sha256(RECEIPT_TOOL)}", source)
        receipt_test = ROOT / "tools" / "test_macos_release_python_runtime_receipt.py"
        self.assertIn(f"_WINS_RP_RECEIPT_TEST_SHA256={sha256(receipt_test)}", source)
        self.assertIn('getattr(os,"O_NOFOLLOW",0)', source)
        self.assertIn("identity(opened)==identity(after)==identity(latest)", source)
        migration_bootstrap = source.split("  bootstrap='", 2)[2].split(
            "'\n  \"$_WINS_RP_ENV\"", 1
        )[0]
        compile(migration_bootstrap, "migration-bootstrap", "exec")
        self.assertNotIn("hold=lambda", migration_bootstrap)
        self.assertIn(
            "before=os.lstat(path);fd=os.open(path,os.O_RDONLY|nofollow",
            migration_bootstrap,
        )
        collector = ROOT / "tools" / "gcp_proof_evidence.py"
        live_probe = ROOT / "tools" / "gcp_proof_live_probe.py"
        self.assertIn(
            f"_WINS_RP_GCP_COLLECTOR_SHA256={sha256(collector)}",
            source,
        )
        self.assertIn(
            f"_WINS_RP_GCP_PROBE_SHA256={sha256(live_probe)}",
            source,
        )
        gcp_bootstrap = source.split("    gcp_bootstrap='", 1)[1].split(
            "'\n    exec \"$_WINS_RP_SANDBOX_EXEC\"", 1
        )[0]
        compile(gcp_bootstrap, "gcp-custody-bootstrap", "exec")
        self.assertIn("collector_data,collector_fds=hold", gcp_bootstrap)
        self.assertIn("probe_data,probe_fds=hold", gcp_bootstrap)
        self.assertIn('sys.modules["gcp_proof_live_probe"]', gcp_bootstrap)
        self.assertLess(
            gcp_bootstrap.index("exec(compile(collector_data"),
            gcp_bootstrap.index("os.environ[name]=value"),
        )

    def test_same_uid_controller_byte_drift_is_rejected_before_execution(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-rp-controller-drift-", dir="/private/tmp") as raw:
            helper = Path(raw) / HELPER.name
            controller = Path(raw) / RECEIPT_TOOL.name
            shutil.copy2(HELPER, helper)
            shutil.copy2(RECEIPT_TOOL, controller)
            controller.write_bytes(controller.read_bytes() + b"\nprint('FORGED-CONTROLLER-RAN')\n")
            completed = subprocess.run(
                [
                    "/bin/bash",
                    "-p",
                    "-c",
                    f"source {shlex_quote(str(helper))}; _wins_rp_receipt_py owner-action x",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertNotIn("FORGED-CONTROLLER-RAN", completed.stdout + completed.stderr)

    def test_every_sourceable_mutation_or_execution_helper_refuses_euid_zero(self) -> None:
        source = HELPER.read_text(encoding="ascii")
        for name in (
            "_wins_rp_receipt_py",
            "_wins_rp_copy_authenticated",
            "_wins_rp_merge_wheel",
            "wins_release_python_cleanup",
            "wins_release_python_materialize_unsealed",
            "wins_release_python_prepare",
            "_wins_release_python_run_impl",
            "wins_release_python_run_bootstrap_test",
        ):
            body = source.split(f"{name}()", 1)[1].split("\n}", 1)[0]
            self.assertIn("_wins_rp_refuse_root", body, name)
        self.assertIn('"$_WINS_RP_ID" -u', source)
        self.assertIn("refuse euid 0", source)

    def test_prepare_without_owner_runtime_is_owner_blocked(self) -> None:
        manifest = self._manifest()
        completed = self._shell(
            f"""
            wins_release_python_prepare {shlex_quote(str(manifest))}
            wins_release_python_run -c 'print("must-not-run")'
            """
        )
        self._assert_owner_blocked_not_run(completed, ran_markers=("must-not-run",))

    def test_provision_helper_without_root_unsigned_package_does_not_mutate(self) -> None:
        manifest = self._manifest()
        before = list(Path("/Library/WinsVPN").glob("**/*")) if Path("/Library/WinsVPN").exists() else []
        completed = subprocess.run(
            ["/bin/bash", str(PROVISIONER), str(manifest)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )
        after = list(Path("/Library/WinsVPN").glob("**/*")) if Path("/Library/WinsVPN").exists() else []
        self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("fixed ReleasePython owner-provisioning boundary", completed.stderr)
        self.assertIn(EXECUTION_BLOCKER, completed.stderr)
        self.assertNotIn("sudo", (completed.stdout + completed.stderr).lower())
        self.assertEqual(before, after)

    def test_materialize_constructs_read_only_framework_and_vendor(self) -> None:
        manifest = self._manifest()
        dest = self.case / "materialized"
        dest.mkdir(mode=0o700)
        completed = self._shell(
            f"""
            wins_release_python_materialize_unsealed {shlex_quote(str(dest))} {shlex_quote(str(manifest))}
            test -x {shlex_quote(str(dest / 'Python.framework/Versions/3.14/bin/python3.14'))}
            test -f {shlex_quote(str(dest / 'vendor/pytest/__init__.py'))}
            test -f {shlex_quote(str(dest / 'Python.framework/Versions/3.14/lib/python3.14/os.py'))}
            test -f {shlex_quote(str(dest / 'launcher/python3.14'))}
            test $((8#$(/usr/bin/stat -f '%Lp' {shlex_quote(str(dest / 'Python.framework/Versions/3.14/bin/python3.14'))}) & 0222)) -eq 0
            test $((8#$(/usr/bin/stat -f '%Lp' {shlex_quote(str(dest / 'vendor/pytest/__init__.py'))}) & 0222)) -eq 0
            """
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        launcher = (dest / "launcher" / "python3.14").read_text(encoding="ascii")
        self.assertIn(MODULE.DEFAULT_RUNTIME, launcher)
        self.assertNotIn(str(dest), launcher)

    def test_rejects_bad_package_hash(self) -> None:
        manifest = self._manifest(package_hash="0" * 64)
        completed = self._shell(
            f"_wins_rp_validate_pinned_archives {shlex_quote(str(manifest))}"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("SHA-256 mismatch", completed.stderr)

    def test_rejects_writable_archive(self) -> None:
        archive = self.case / "writable.pkg"
        shutil.copy2(self.package, archive)
        archive.chmod(0o644)
        manifest = self._manifest(package=archive)
        completed = self._shell(
            f"_wins_rp_validate_pinned_archives {shlex_quote(str(manifest))}"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("writable input rejected", completed.stderr)

    def test_rejects_symlink_archive(self) -> None:
        archive = self.case / "linked.pkg"
        archive.symlink_to(self.package)
        manifest = self._manifest(package=archive, package_hash=sha256(self.package))
        completed = self._shell(
            f"_wins_rp_validate_pinned_archives {shlex_quote(str(manifest))}"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("symlink path component rejected", completed.stderr)

    def test_rejects_hardlinked_wheel(self) -> None:
        first = self.case / "pytest-hardlink.whl"
        second = self.case / "pytest-hardlink-copy.whl"
        shutil.copy2(self.wheel, first)
        os.link(first, second)
        first.chmod(0o444)
        manifest = self._manifest(wheel=first)
        completed = self._shell(
            f"_wins_rp_validate_pinned_archives {shlex_quote(str(manifest))}"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("hardlinked input rejected", completed.stderr)

    def test_rejects_group_writable_input_path_component(self) -> None:
        unsafe = self.case / "unsafe-parent"
        unsafe.mkdir(mode=0o770)
        unsafe.chmod(0o770)
        archive = unsafe / "python.pkg"
        shutil.copy2(self.package, archive)
        archive.chmod(0o444)
        manifest = self._manifest(package=archive)
        completed = self._shell(
            f"_wins_rp_validate_pinned_archives {shlex_quote(str(manifest))}"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("group/world-writable path component rejected", completed.stderr)

    def test_rejects_wheel_startup_hooks_without_executing_them(self) -> None:
        wheel = self._make_wheel_in_case("pytest-hostile.whl", safe=False)
        wheel.chmod(0o444)
        manifest = self._manifest(wheel=wheel)
        dest = self.case / "hostile"
        dest.mkdir(mode=0o700)
        completed = self._shell(
            f"wins_release_python_materialize_unsealed {shlex_quote(str(dest))} {shlex_quote(str(manifest))}"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("Python startup hook rejected", completed.stderr)

    def test_rejects_wheel_symlink_before_extraction(self) -> None:
        wheel = self.case / "pytest-symlink.whl"
        link = zipfile.ZipInfo("pytest/link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr(link, "../../outside")
        wheel.chmod(0o444)
        manifest = self._manifest(wheel=wheel)
        dest = self.case / "symlink-wheel"
        dest.mkdir(mode=0o700)
        completed = self._shell(
            f"wins_release_python_materialize_unsealed {shlex_quote(str(dest))} {shlex_quote(str(manifest))}"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("wheel symlink metadata rejected", completed.stderr)

    def test_launcher_execution_without_owner_runtime_does_not_run(self) -> None:
        manifest = self._manifest()
        completed = self._shell(
            f"""
            trap wins_release_python_cleanup EXIT
            wins_release_python_prepare {shlex_quote(str(manifest))}
            wins_release_python_run -c 'print("c-ok")'
            """
        )
        self._assert_owner_blocked_not_run(completed, ran_markers=("c-ok",))

    def test_exported_pointer_tampering_cannot_create_a_false_green(self) -> None:
        manifest = self._manifest()
        completed = self._shell(
            f"""
            trap wins_release_python_cleanup EXIT
            wins_release_python_prepare {shlex_quote(str(manifest))}
            WINS_RELEASE_PYTHON_BIN=/usr/bin/true
            wins_release_python_run -c 'print("fixture")'
            """
        )
        self._assert_owner_blocked_not_run(completed, ran_markers=("fixture",))

    def test_bootstrap_rejects_browser_runtime_custody_suite(self) -> None:
        manifest = self._manifest()
        rejected = ROOT / "extension" / "tools" / "test_browser_runtime_custody.py"
        completed = self._shell(
            f"""
            trap wins_release_python_cleanup EXIT
            wins_release_python_prepare {shlex_quote(str(manifest))}
            wins_release_python_run_bootstrap_test {shlex_quote(str(rejected))}
            """
        )
        self._assert_owner_blocked_not_run(completed)

    def test_browser_mode_environment_omits_java_openssl_node_and_secrets(self) -> None:
        source = HELPER.read_text(encoding="utf-8")
        browser_mode = source.split('if [[ "$mode" == release-tools-browser ]]; then', 1)[1]
        browser_mode = browser_mode.split('if [[ "$mode" == release-tools ]]; then', 1)[0]
        self.assertIn('exec "$_WINS_RP_ENV" -i', browser_mode)
        self.assertIn("BROWSER_BIN=$release_browser", browser_mode)
        for leaked in (
            "WINS_RELEASE_OPENSSL=$WINS_RELEASE_OPENSSL",
            "WINS_RELEASE_KEYTOOL=$release_keytool",
            "WINS_RELEASE_JARSIGNER=$release_jarsigner",
            "WINS_RELEASE_NODE=$release_node",
            "OPENSSL_CONF=/dev/null",
            "WINS_ANDROID_KEY_PASSWORD",
            "${WINS_RELEASE_JAVA_HOME}/bin",
            "${WINS_RELEASE_OPENSSL%/*}",
        ):
            self.assertNotIn(leaked, browser_mode)

    def test_consumer_child_handoff_preserves_scrub_without_generic_wins_passthrough(self) -> None:
        source = HELPER.read_text(encoding="ascii")
        materializer = source.split("launcher_source=", 1)[1].split(
            'printf \'%s\' "$launcher_source"', 1
        )[0]
        runner = source.split("_wins_release_python_run_impl()", 1)[1].split(
            "wins_release_python_run()", 1
        )[0]
        raw_python = (
            "${_WINS_RP_OWNER_RUNTIME}/Python.framework/Versions/3.14/"
            "bin/python3.14"
        )

        self.assertIn("exec /usr/bin/env -i", materializer)
        self.assertIn(f"PYTHONEXECUTABLE='{raw_python}'", materializer)
        self.assertNotIn("PYTHONEXECUTABLE='${_WINS_RP_OWNER_RUNTIME}/launcher", materializer)
        self.assertIn('export PYTHONEXECUTABLE="$python_bin"', runner)
        self.assertGreaterEqual(runner.count('"$_WINS_RP_ENV" -i'), 4)
        for caller_field in (
            "WINS_GCP_PYTHON_RUNTIME_RECEIPT",
            "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_CONTRACT",
            "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_NONCE",
            "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_OUTPUT",
            "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_PLATFORM",
        ):
            self.assertNotIn(caller_field, materializer)
            self.assertNotIn(f'"{caller_field}=', runner)

    def test_user_owned_tree_is_wrong_owner_for_production_bind(self) -> None:
        manifest = self._manifest()
        dest = self.case / "user-tree"
        dest.mkdir(mode=0o700)
        completed = self._shell(
            f"wins_release_python_materialize_unsealed {shlex_quote(str(dest))} {shlex_quote(str(manifest))}"
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        with self.assertRaisesRegex(MODULE.Refused, r"wrong owner"):
            MODULE.bind_tree(
                dest / "Python.framework",
                required_uid=0,
                allow_symlinks=True,
            )

    def test_writable_ancestry_is_rejected(self) -> None:
        unsafe = self.case / "writable-anc"
        unsafe.mkdir(mode=0o777)
        unsafe.chmod(0o777)
        leaf = unsafe / "tree"
        leaf.mkdir(mode=0o700)
        with self.assertRaisesRegex(MODULE.Refused, r"group/world-writable path component rejected"):
            MODULE.require_path_components(
                leaf,
                allowed_uids={0, os.getuid()},
                allow_sticky_tmp=True,
                leaf_must_match=os.getuid(),
            )

    def test_symlink_substitution_is_rejected(self) -> None:
        real = self.case / "real-dir"
        real.mkdir(mode=0o700)
        linked = self.case / "linked-dir"
        linked.symlink_to(real)
        with self.assertRaisesRegex(MODULE.Refused, r"symlink path component rejected"):
            MODULE.require_path_components(
                linked,
                allowed_uids={0, os.getuid()},
                allow_sticky_tmp=True,
                leaf_must_match=os.getuid(),
            )

    def test_hardlink_substitution_is_rejected(self) -> None:
        first = self.case / "one.bin"
        second = self.case / "two.bin"
        first.write_bytes(b"payload")
        first.chmod(0o444)
        os.link(first, second)
        with self.assertRaisesRegex(MODULE.Refused, r"hardlinked input rejected"):
            MODULE.require_regular_file(
                first,
                allowed_uids={0, os.getuid()},
                allow_sticky_tmp=True,
                forbid_owner_write=True,
                leaf_uid=os.getuid(),
            )

    def test_symlink_inside_vendor_tree_is_rejected(self) -> None:
        manifest = self._manifest()
        dest = self.case / "vendor-symlink-tree"
        dest.mkdir(mode=0o700)
        completed = self._shell(
            f"wins_release_python_materialize_unsealed {shlex_quote(str(dest))} {shlex_quote(str(manifest))}"
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        vendor = dest / "vendor"
        self._chmod_tree_user_writable(vendor)
        sneak = vendor / "pytest" / "sneak.py"
        sneak.symlink_to("__init__.py")
        self._seal_tree_not_writable(vendor)
        with self.assertRaisesRegex(MODULE.Refused, r"custody tree symlink rejected"):
            MODULE.bind_tree(vendor, required_uid=os.getuid(), allow_symlinks=False)

    def test_hardlink_inside_vendor_tree_is_rejected(self) -> None:
        manifest = self._manifest()
        dest = self.case / "vendor-hardlink-tree"
        dest.mkdir(mode=0o700)
        completed = self._shell(
            f"wins_release_python_materialize_unsealed {shlex_quote(str(dest))} {shlex_quote(str(manifest))}"
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        vendor = dest / "vendor"
        self._chmod_tree_user_writable(vendor)
        target = vendor / "pytest" / "__init__.py"
        extra = vendor / "pytest" / "dup.py"
        os.link(target, extra)
        self._seal_tree_not_writable(vendor)
        with self.assertRaisesRegex(MODULE.Refused, r"hardlinked tree file rejected"):
            MODULE.bind_tree(vendor, required_uid=os.getuid(), allow_symlinks=False)

    def test_same_user_mutation_changes_complete_tree_bind(self) -> None:
        manifest = self._manifest()
        dest = self.case / "mutate-tree"
        dest.mkdir(mode=0o700)
        completed = self._shell(
            f"wins_release_python_materialize_unsealed {shlex_quote(str(dest))} {shlex_quote(str(manifest))}"
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        framework = dest / "Python.framework"
        before = MODULE.bind_tree(framework, required_uid=os.getuid(), allow_symlinks=True)
        target = framework / "Versions/3.14/lib/python3.14/os.py"
        target.chmod(0o600)
        target.write_text('print("ATTACKED")\n', encoding="ascii")
        target.chmod(0o444)
        after = MODULE.bind_tree(framework, required_uid=os.getuid(), allow_symlinks=True)
        self.assertNotEqual(before["content"], after["content"])
        self.assertNotEqual(before["identity"], after["identity"])

    def _chmod_tree_user_writable(self, root: Path) -> None:
        for path in [root, *root.rglob("*")]:
            if path.is_symlink() or not path.exists():
                continue
            try:
                path.chmod(path.stat().st_mode | stat.S_IWUSR | stat.S_IXUSR)
            except FileNotFoundError:
                pass

    def _seal_tree_not_writable(self, root: Path) -> None:
        for path in [root, *root.rglob("*")]:
            if path.is_symlink() or not path.exists():
                continue
            mode = path.stat().st_mode
            if stat.S_ISDIR(mode):
                path.chmod(0o555)
            else:
                path.chmod(0o444)

    def _owner_path_binds(self, dest: Path) -> dict[str, object]:
        framework = dest / "Python.framework"
        vendor = dest / "vendor"
        launcher = dest / "launcher"
        executable = dest / MODULE.EXECUTABLE_RELATIVE
        return {
            "framework": MODULE.bind_tree(
                framework, required_uid=os.getuid(), allow_symlinks=True
            ),
            "vendor": MODULE.bind_tree(
                vendor, required_uid=os.getuid(), allow_symlinks=False
            ),
            "launcher": MODULE.bind_tree(
                launcher, required_uid=os.getuid(), allow_symlinks=False
            ),
            "executable": executable,
            "executable_sha256": MODULE.digest_file(executable),
            "executable_identity": MODULE.file_identity(executable.lstat()),
            "runtime_dir_identity": MODULE.dir_identity(dest.lstat()),
        }

    def test_changed_inode_is_rejected_by_directory_identity(self) -> None:
        manifest = self._manifest()
        dest = self.case / "inode-tree"
        dest.mkdir(mode=0o700)
        completed = self._shell(
            f"wins_release_python_materialize_unsealed {shlex_quote(str(dest))} {shlex_quote(str(manifest))}"
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        framework = dest / "Python.framework"
        before = MODULE.bind_tree(framework, required_uid=os.getuid(), allow_symlinks=True)
        swapped = dest / "Python.framework.swapped"
        shutil.copytree(framework, swapped, symlinks=True)
        self._chmod_tree_user_writable(framework)
        shutil.rmtree(framework)
        swapped.rename(framework)
        after = MODULE.bind_tree(framework, required_uid=os.getuid(), allow_symlinks=True)
        self.assertNotEqual(before["dir_identity"], after["dir_identity"])
        self.assertNotEqual(before["identity"], after["identity"])

    def test_production_owner_path_match_accepts_unmutated_measurement(self) -> None:
        manifest = self._manifest()
        dest = self.case / "owner-path"
        dest.mkdir(mode=0o700)
        completed = self._shell(
            f"wins_release_python_materialize_unsealed {shlex_quote(str(dest))} {shlex_quote(str(manifest))}"
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        measured = self._owner_path_binds(dest)
        package_sha, wheels = MODULE.pin_wheels(MODULE.load_pin_manifest(manifest))
        codesign = {
            "codesign_cdhash": "ab" * 20,
            "codesign_identifier": "org.python.python3",
            "codesign_team_identifier": "BMM5U3QVKW",
            "codesign_authority": "Developer ID Application: Python Software Foundation",
        }
        controllers = {
            "controller_sha256": "a" * 64,
            "provisioner_sha256": "b" * 64,
            "receipt_schema_sha256": "c" * 64,
        }
        receipt = {
            "runtime_path": str(dest),
            "runtime_dir_identity": measured["runtime_dir_identity"],
            "framework_tree_sha256": measured["framework"]["content"],
            "framework_identity_sha256": measured["framework"]["identity"],
            "framework_dir_identity": measured["framework"]["dir_identity"],
            "vendor_tree_sha256": measured["vendor"]["content"],
            "vendor_identity_sha256": measured["vendor"]["identity"],
            "vendor_dir_identity": measured["vendor"]["dir_identity"],
            "launcher_tree_sha256": measured["launcher"]["content"],
            "launcher_identity_sha256": measured["launcher"]["identity"],
            "launcher_dir_identity": measured["launcher"]["dir_identity"],
            "executable_path": str(measured["executable"]),
            "executable_sha256": measured["executable_sha256"],
            "executable_identity": measured["executable_identity"],
            "package_sha256": package_sha,
            "wheels": wheels,
            "wheel_count": len(wheels),
            "controller_sha256": controllers["controller_sha256"],
            "provisioner_sha256": controllers["provisioner_sha256"],
            "receipt_schema_sha256": controllers["receipt_schema_sha256"],
            "codesign_cdhash": codesign["codesign_cdhash"],
            "codesign_identifier": codesign["codesign_identifier"],
            "codesign_team_identifier": codesign["codesign_team_identifier"],
            "codesign_authority": codesign["codesign_authority"],
            "package_signature_status": "Status: signed fixture",
        }
        match_kwargs = {
            "runtime": dest,
            "framework": measured["framework"],
            "vendor": measured["vendor"],
            "launcher": measured["launcher"],
            "executable": Path(str(measured["executable"])),
            "controllers": controllers,
            "package_sha256": package_sha,
            "wheels": wheels,
            "codesign": codesign,
            "package_signature_status": "Status: signed fixture",
        }
        MODULE.match_receipt_to_runtime(receipt, **match_kwargs)
        with self.assertRaisesRegex(MODULE.Refused, r"wrong archive/tree"):
            MODULE.match_receipt_to_runtime(
                dict(receipt, package_sha256="d" * 64),
                **match_kwargs,
            )
        with self.assertRaisesRegex(MODULE.Refused, r"stale receipt"):
            MODULE.match_receipt_to_runtime(
                receipt,
                runtime=dest,
                framework=measured["framework"],
                vendor=measured["vendor"],
                launcher=measured["launcher"],
                executable=Path(str(measured["executable"])),
                controllers={
                    "controller_sha256": "e" * 64,
                    "provisioner_sha256": "b" * 64,
                    "receipt_schema_sha256": "c" * 64,
                },
                package_sha256=package_sha,
                wheels=wheels,
                codesign=codesign,
                package_signature_status="Status: signed fixture",
            )
        with self.assertRaisesRegex(MODULE.Refused, r"changed inode"):
            MODULE.match_receipt_to_runtime(
                dict(receipt, runtime_dir_identity="9:9:0:0:555:1:64:0"),
                **match_kwargs,
            )
        mutated = dest / "Python.framework/Versions/3.14/lib/python3.14/os.py"
        mutated.chmod(0o600)
        mutated.write_text("# mutated\n", encoding="ascii")
        mutated.chmod(0o444)
        live = MODULE.bind_tree(
            dest / "Python.framework",
            required_uid=os.getuid(),
            allow_symlinks=True,
        )
        with self.assertRaisesRegex(MODULE.Refused, r"wrong archive/tree|changed inode"):
            MODULE.match_receipt_to_runtime(
                receipt,
                runtime=dest,
                framework=live,
                vendor=measured["vendor"],
                launcher=measured["launcher"],
                executable=Path(str(measured["executable"])),
                controllers=controllers,
                package_sha256=package_sha,
                wheels=wheels,
                codesign=codesign,
                package_signature_status="Status: signed fixture",
            )

    def test_self_authored_receipt_is_owner_blocked(self) -> None:
        receipt = self.case / "self.json"
        receipt.write_bytes(b"{}\n")
        receipt.chmod(0o444)
        os.environ[MODULE.RECEIPT_ENV] = str(receipt)
        with self.assertRaisesRegex(MODULE.Refused, r"cannot self-authorize"):
            MODULE.require_external_receipt(ROOT, required_uid=0)

    def test_adjacent_receipt_is_owner_blocked(self) -> None:
        adjacent = ROOT / "tools" / "macos-release-python-self-auth.receipt.json"
        self.addCleanup(lambda: adjacent.exists() and adjacent.unlink())
        adjacent.write_bytes(b"{}\n")
        adjacent.chmod(0o444)
        os.environ[MODULE.RECEIPT_ENV] = str(adjacent)
        with self.assertRaisesRegex(MODULE.Refused, r"external to the candidate repository"):
            MODULE.require_external_receipt(ROOT, required_uid=0)

    def test_same_user_mutation_probe_fails_closed_on_user_tree(self) -> None:
        target = self.case / "probe.bin"
        target.write_bytes(b"payload")
        target.chmod(0o444)
        with self.assertRaisesRegex(MODULE.Refused, EXECUTION_BLOCKER):
            MODULE.prove_not_user_mutable([target])

    def test_kernel_bound_owner_path_is_required_and_fails_closed(self) -> None:
        source = HELPER.read_text(encoding="utf-8")
        self.assertIn("SF_IMMUTABLE", RECEIPT_TOOL.read_text(encoding="ascii"))
        self.assertIn("SF_IMMUTABLE is required", RECEIPT_TOOL.read_text(encoding="ascii"))
        self.assertIn("UF_IMMUTABLE is insufficient", source)
        self.assertIn(EXECUTION_BLOCKER, source)
        self.assertIn("/Library/WinsVPN/ReleasePython/3.14.7", source)
        manifest = self._manifest()
        completed = self._shell(
            f"""
            trap wins_release_python_cleanup EXIT
            wins_release_python_prepare {shlex_quote(str(manifest))}
            wins_release_python_run -c 'print("must-not-run")'
            """
        )
        self._assert_owner_blocked_not_run(completed, ran_markers=("must-not-run",))

    def test_real_macos_arm64_python_archive(self) -> None:
        pin = json.loads(PIN_MANIFEST.read_text(encoding="utf-8"))
        custody = pin["tools"]["python"]["archive_custody"]["darwin_arm64"]
        package = Path(custody["package"]["path"])
        if not package.is_file():
            self.skipTest("real python-3.14.7-macos11.pkg is unavailable")
        self.assertEqual(sha256(package), custody["package"]["sha256"])
        self.assertEqual(stat.S_IMODE(package.stat().st_mode) & 0o222, 0)
        completed = self._shell(
            f"""
            trap wins_release_python_cleanup EXIT
            if wins_release_python_prepare {shlex_quote(str(PIN_MANIFEST))}; then
              printf 'PREPARE=OWNER_RUNTIME\\n'
              wins_release_python_run -c 'import sys; print("real-python-ok", sys.version_info[:3])'
            else
              printf 'PREPARE=OWNER_BLOCKED\\n'
              exit 1
            fi
            """,
            timeout=300,
        )
        combined = completed.stdout + completed.stderr
        if "PREPARE=OWNER_RUNTIME" in completed.stdout:
            self.assertEqual(completed.returncode, 0, combined)
            self.assertIn("real-python-ok (3, 14, 7)", completed.stdout)
            return
        self.assertNotEqual(completed.returncode, 0, combined)
        self.assertIn("PREPARE=OWNER_BLOCKED", completed.stdout)
        self.assertIn(EXECUTION_BLOCKER, completed.stderr)
        self.assertNotIn("real-python-ok", completed.stdout)

    def _make_wheel_in_case(self, name: str, *, safe: bool) -> Path:
        wheel = self.case / name
        with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("fixture_probe.py", "print('fixture')\n")
            if not safe:
                archive.writestr("sitecustomize.py", "raise RuntimeError('executed')\n")
        return wheel


if __name__ == "__main__":
    unittest.main()
