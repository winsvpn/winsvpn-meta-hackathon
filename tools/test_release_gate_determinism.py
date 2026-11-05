#!/usr/bin/env python3
"""Adversarial tests for checkout-independent release/conformance gates."""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import sys
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
FIN_GATE = ROOT / "tools" / "fin_release_gate.sh"
CONFORMANCE_GATE = ROOT / "tools" / "verify_winn3_conformance.sh"
RELEASE_ENABLEMENT_TEST = ROOT / "tools" / "test_winn3_release_enablement.py"
RELEASE_TEST_RUNNER = ROOT / "tools" / "run_test_suite.py"

_CUSTODY_FIXTURE = tempfile.TemporaryDirectory(
    prefix="wins-fin-python-custody-", dir="/private/tmp"
)
_CUSTODY_ROOT = Path(_CUSTODY_FIXTURE.name)


def _select_custody_fixture_python() -> Path:
    candidate = Path(shutil.which("python3.14") or sys.executable).resolve()
    framework = os.environ.get("DYLD_FRAMEWORK_PATH", "")
    library = os.environ.get("DYLD_LIBRARY_PATH", "")
    if framework and candidate.is_relative_to(Path(framework)):
        wrapper = _CUSTODY_ROOT / "python3.14"
        wrapper_source = (
            "#!/bin/sh\nexec /usr/bin/env "
            f"DYLD_FRAMEWORK_PATH={shlex.quote(framework)} "
            f"DYLD_LIBRARY_PATH={shlex.quote(library)} "
            f"{shlex.quote(str(candidate))} \"$@\"\n"
        )
        wrapper.write_text(wrapper_source, encoding="utf-8")
        wrapper.chmod(0o555)
        python3_wrapper = _CUSTODY_ROOT / "python3"
        python3_wrapper.write_text(wrapper_source, encoding="utf-8")
        python3_wrapper.chmod(0o555)
        return wrapper
    return candidate


_CUSTODY_PYTHON = _select_custody_fixture_python()
_CUSTODY_IDENTITY = json.loads(
    subprocess.run(
        [
            str(_CUSTODY_PYTHON),
            "-S",
            "-c",
            "import json,sys; print(json.dumps({'version': '.'.join(map(str, sys.version_info[:3])), 'implementation': sys.implementation.name}))",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
)


def _build_python_custody_fixture() -> tuple[Path, Path]:
    payload = _CUSTODY_ROOT / "payload"
    executable = payload / "Versions/3.14/bin/python3.14"
    executable.parent.mkdir(parents=True)
    executable.write_text(
        f"#!/bin/sh\nexec {str(_CUSTODY_PYTHON)!r} \"$@\"\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    component = _CUSTODY_ROOT / "Python_Framework.pkg"
    package = _CUSTODY_ROOT / "python-fixture.pkg"
    subprocess.run(
        [
            "/usr/bin/pkgbuild",
            "--root",
            str(payload),
            "--identifier",
            "org.winsvpn.fixture.PythonFramework",
            "--version",
            _CUSTODY_IDENTITY["version"],
            str(component),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["/usr/bin/productbuild", "--package", str(component), str(package)],
        check=True,
        capture_output=True,
        text=True,
    )
    wheel = _CUSTODY_ROOT / "pytest-fixture-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("pytest/__init__.py", "__version__ = 'fixture'\n")
        archive.writestr(
            "pytest-fixture.dist-info/METADATA", "Name: pytest\nVersion: fixture\n"
        )
    package.chmod(0o444)
    wheel.chmod(0o444)
    return package, wheel


_CUSTODY_PACKAGE, _CUSTODY_WHEEL = _build_python_custody_fixture()

PYTHON_EXECUTION_BLOCKER = (
    "owner/environment blocker: this host cannot make the Python tree "
    "immutable against same-user path replacement through execution"
)
REPLACEMENT_REPO_CUSTODY_BLOCKER = (
    "replacement repository or pin manifest cannot self-authorize custody"
)


def _run(
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    if len(argv) >= 2 and argv[0] == "bash" and Path(argv[1]) == FIN_GATE:
        argv = ["/bin/bash", "-p", *argv[1:]]
    run_env = os.environ.copy()
    if env:
        run_env.update(env)
    if run_env.get("WIN_DIR"):
        run_env["WIN_DIR"] = str(Path(run_env["WIN_DIR"]).resolve())
    run_env["PATH"] = str(_CUSTODY_PYTHON.parent) + os.pathsep + run_env.get("PATH", "")
    return subprocess.run(
        argv,
        cwd=ROOT,
        env=run_env,
        check=False,
        capture_output=True,
        text=True,
    )


def _combined(result: subprocess.CompletedProcess[str]) -> str:
    return result.stdout + result.stderr


def _python_execution_blocked(result: subprocess.CompletedProcess[str]) -> bool:
    combined = _combined(result)
    return (
        PYTHON_EXECUTION_BLOCKER in combined
        or REPLACEMENT_REPO_CUSTODY_BLOCKER in combined
    )


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _running_python_pin() -> dict[str, object]:
    executable = _CUSTODY_PYTHON
    platform_key = "darwin_arm64" if os.uname().machine == "arm64" else "darwin_amd64"
    return {
        "version": _CUSTODY_IDENTITY["version"],
        "implementation": _CUSTODY_IDENTITY["implementation"],
        "archive_custody": {
            platform_key: {
                "package": {
                    "path": str(_CUSTODY_PACKAGE),
                    "sha256": hashlib.sha256(_CUSTODY_PACKAGE.read_bytes()).hexdigest(),
                },
                "framework_component": "Python_Framework.pkg",
                "python_executable": "Versions/3.14/bin/python3.14",
                "runtime_wheel_count": 1,
                "wheel_count": 1,
                "wheels": {
                    "0": {
                        "path": str(_CUSTODY_WHEEL),
                        "sha256": hashlib.sha256(_CUSTODY_WHEEL.read_bytes()).hexdigest(),
                    }
                },
            }
        },
        "reviewed_executable_path": {platform_key: str(executable)},
        "executable_sha256": {
            platform_key: hashlib.sha256(executable.read_bytes()).hexdigest()
        },
    }


def _fake_tool(directory: Path, name: str, output: str) -> None:
    path = directory / name
    _write(path, "#!/bin/sh\nprintf '%s\\n' \"$@\" >/dev/null\nprintf '%s\\n' '" + output + "'\n")
    path.chmod(0o755)


def _critical_release_test_files(app: Path) -> None:
    _write(
        app / "tools/run_test_suite.py",
        "#!/usr/bin/env python3\n"
        "import pathlib, sys\n"
        "root = pathlib.Path(__file__).resolve().parents[1]\n"
        "def control(name, default):\n"
        "    path = root / name\n"
        "    return path.read_text(encoding='utf-8') if path.is_file() else default\n"
        "if sys.argv[1:] == ['--list', '--exclude-python-custody-bootstrap']:\n"
        "    print(control('.fake_suite_list', 'tools/test_fixture.py'))\n"
        "    raise SystemExit(int(control('.fake_suite_list_status', '0')))\n"
        "if sys.argv[1:] == ['--release-critical', '--exclude-python-custody-bootstrap']:\n"
        "    log = control('.fake_runner_log', '').strip()\n"
        "    if log:\n"
        "        with open(log, 'a', encoding='utf-8') as handle:\n"
        "            handle.write('\\n'.join(sys.argv) + '\\n')\n"
        "    raise SystemExit(int(control('.fake_suite_status', '0')))\n"
        "raise SystemExit(64)\n",
    )
    _write(app / "tools/test_fixture.py", "# release-gate fixture\n")
    _write(app / "tools/test_release_python_archive_custody.py", "# bootstrap fixture\n")
    _write(app / "tools/test_release_gate_determinism.py", "# bootstrap fixture\n")
    _write(
        app / "tools/toolchain-pins.json",
        json.dumps({"tools": {"python": _running_python_pin()}}, sort_keys=True) + "\n",
    )


def _write_running_python_pin(app: Path) -> None:
    _write(
        app / "tools/toolchain-pins.json",
        json.dumps({"tools": {"python": _running_python_pin()}}, sort_keys=True) + "\n",
    )


def _g19_readiness_env(app: Path) -> dict[str, str]:
    evidence = app / ".artifacts/CROSS_STORE_READINESS.json"
    index = app / ".artifacts/RELEASE_INPUT_INDEX.json"
    _write(app / "tools/cross_store_upload_readiness.py", "# fixture verifier\n")
    _write(evidence, "{}\n")
    _write(index, "{}\n")
    return {
        "WINS_CROSS_STORE_READINESS_EVIDENCE": str(evidence),
        "WINS_RELEASE_INPUT_INDEX": str(index),
    }


def _source_freeze_roots(app: Path) -> None:
    source = ROOT / "tools" / "release_source_freeze.py"
    _write(app / "tools/release_source_freeze.py", source.read_text(encoding="utf-8"))
    _write_running_python_pin(app)
    _write(app / "pubspec.yaml", "version: 1.2.3+4\n")
    for relative in (
        "lib",
        "assets",
        "android",
        "wear_os",
        "extension",
        "windows",
        "linux",
        "ios",
        "macos",
        "apple",
        "installer/windows",
        "winn_protocol_experimental",
    ):
        _write(app / relative / ".release-freeze-input", relative + "\n")
    _write(app / "pubspec.lock", "packages: {}\n")
    _write(app / "web/index.html", "<html></html>\n")


def _fake_go_security_module(root: Path, *, failing: bool = False) -> None:
    module = root / "winn_protocol_experimental"
    _write(module / "go.mod", "module example.invalid/winn\n\ngo 1.27\n")
    _write(module / "winn3/core/core.go", "package core\nfunc Safe() bool { return true }\n")
    assertion = "false" if failing else "Safe()"
    _write(
        module / "winn3/core/core_test.go",
        "package core\nimport \"testing\"\n"
        f"func TestSafe(t *testing.T) {{ if !({assertion}) {{ t.Fatal(\"unsafe\") }} }}\n",
    )
    _write(
        module / "winn3/core/replaystore/replaystore.go",
        "package replaystore\nfunc Durable() bool { return true }\n",
    )
    _write(
        module / "winn3/core/replaystore/replaystore_test.go",
        "package replaystore\nimport \"testing\"\n"
        "func TestDurable(t *testing.T) { if !Durable() { t.Fatal(\"unsafe\") } }\n",
    )


def _fake_jar(
    cache: Path,
    group: str,
    artifact: str,
    version: str,
    digest: str = "reviewed",
) -> Path:
    path = cache / group / artifact / version / digest / f"{artifact}-{version}.jar"
    _write(path, "fixture\n")
    return path


def _fake_kotlin_closure(cache: Path, version: str = "2.4.20") -> None:
    coordinates = (
        ("org.jetbrains.kotlin", "kotlin-compiler-embeddable", version),
        ("org.jetbrains.kotlin", "kotlin-stdlib", version),
        ("org.jetbrains.kotlin", "kotlin-reflect", "1.6.10"),
        ("org.jetbrains.kotlin", "kotlin-daemon-embeddable", version),
        ("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.8.0"),
        ("org.jetbrains.intellij.deps", "trove4j", "1.0.20200330"),
        ("org.jetbrains", "annotations", "13.0"),
        ("androidx.annotation", "annotation-jvm", "1.8.1"),
    )
    for coordinate in coordinates:
        _fake_jar(cache, *coordinate)


class FinReleaseGateDeterminismTest(unittest.TestCase):
    def test_gate_rejects_non_privileged_bash_bootstrap(self) -> None:
        completed = subprocess.run(
            ["/bin/bash", str(FIN_GATE), "--list"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 126)
        self.assertIn("/bin/bash -p", completed.stderr)

    def test_gate_sources_have_no_foreign_checkout_dependencies(self) -> None:
        sources = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (FIN_GATE, CONFORMANCE_GATE, RELEASE_ENABLEMENT_TEST)
        )
        for forbidden in (
            "/Users/owner/xprize/v3-lane",
            "/Users/owner/xprize/SPEC.md",
            "wins_security_mr",
            'WIN_DIR}/../wins_security',
            'SECURITY_DIR}/core',
        ):
            self.assertNotIn(forbidden, sources)

    def test_g05_runs_canonical_non_executable_script_through_bash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = Path(tmp) / "app"
            runner = app / "tools/verify_winn3_conformance.sh"
            _write(runner, "#!/usr/bin/env bash\nprintf 'fixture conformance pass\\n'\n")
            self.assertEqual(runner.stat().st_mode & 0o777, 0o644)
            result = _run(
                ["bash", str(FIN_GATE), "G05"],
                env={"WIN_DIR": str(app)},
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("all reachable hosts agreed", result.stdout)

    def test_g00_requires_exact_reviewed_toolchain_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = Path(tmp) / "app"
            bin_dir = Path(tmp) / "bin"
            _write(app / "pubspec.yaml", "version: 1.2.3+4\n")
            _write(
                app / "tools/toolchain-pins.json",
                json.dumps(
                    {
                        "tools": {
                            "python": _running_python_pin(),
                            "go": {"version": "1.27.1"},
                            "flutter": {
                                "version": "3.47.6",
                                "revision": "5fc346839b5d0eef006ed8404392afb4dfae428d",
                                "dart_version": "3.13.5",
                            },
                            "cocoapods": {"version": "1.17.0"},
                        }
                    },
                    sort_keys=True,
                )
                + "\n",
            )
            _fake_tool(bin_dir, "go", "go version go1.27.1 darwin/arm64")
            _fake_tool(
                bin_dir,
                "flutter",
                json.dumps(
                    {
                        "frameworkVersion": "3.47.6",
                        "frameworkRevision": "5fc346839b5d0eef006ed8404392afb4dfae428d",
                    },
                    sort_keys=True,
                ),
            )
            _fake_tool(bin_dir, "dart", "Dart SDK version: 3.13.5 (stable)")
            _fake_tool(bin_dir, "pod", "1.17.0")
            _fake_tool(bin_dir, "swiftc", "Apple Swift version 6.3")
            result = _run(
                ["bash", str(FIN_GATE), "G00"],
                env={
                    "WIN_DIR": str(app),
                    "WINS_RELEASE_PYTHON": str(_CUSTODY_PYTHON),
                    "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
                },
            )
        combined = result.stdout + result.stderr
        if _python_execution_blocked(result):
            self.assertNotEqual(result.returncode, 0, combined)
            self.assertIn("authenticated release Python custody", combined)
            return
        self.assertEqual(result.returncode, 0, combined)
        self.assertIn("reviewed python custody matches pins", result.stdout)

    def test_g00_ignores_ambient_path_go_flutter_and_dart(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp)
            app = sandbox / "app"
            bin_dir = sandbox / "bin"
            marker = sandbox / "ambient-toolchain-ran"
            _write(app / "pubspec.yaml", "version: 1.2.3+4\n")
            _write(
                app / "tools/toolchain-pins.json",
                json.dumps(
                    {
                        "tools": {
                            "python": _running_python_pin(),
                            "go": {"version": "1.27.1"},
                            "flutter": {
                                "version": "3.47.6",
                                "revision": "5fc346839b5d0eef006ed8404392afb4dfae428d",
                                "dart_version": "3.13.5",
                            },
                            "cocoapods": {"version": "1.17.0"},
                        }
                    },
                    sort_keys=True,
                )
                + "\n",
            )
            stub = (
                "#!/bin/sh\n"
                f"printf ran >> {shlex.quote(str(marker))}\n"
                "printf '%s\\n' 'go version go1.26.5 darwin/arm64'\n"
            )
            for name in ("go", "flutter", "dart", "java", "python3", "node", "openssl", "ISCC"):
                path = bin_dir / name
                _write(path, stub)
                path.chmod(0o755)
            result = _run(
                ["bash", str(FIN_GATE), "G00"],
                env={
                    "WIN_DIR": str(app),
                    "WINS_RELEASE_PYTHON": str(_CUSTODY_PYTHON),
                    "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
                },
            )
            marker_ran = marker.exists()
        combined = result.stdout + result.stderr
        self.assertFalse(marker_ran)
        if _python_execution_blocked(result):
            self.assertNotEqual(result.returncode, 0, combined)
            self.assertIn("authenticated release Python custody", combined)
            return
        self.assertEqual(result.returncode, 0, combined)
        self.assertIn("reviewed python custody matches pins", result.stdout)
        self.assertIn("require authenticated custody before execution", result.stdout)
        self.assertNotIn("go expected=1.27.1 actual=1.26.5", result.stdout)

    def test_g00_stops_on_release_python_version_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = Path(tmp) / "app"
            bin_dir = Path(tmp) / "bin"
            _write(app / "pubspec.yaml", "version: 1.2.3+4\n")
            python_pin = _running_python_pin()
            actual_parts = [int(part) for part in python_pin["version"].split(".")]
            python_pin["version"] = f"{actual_parts[0]}.{actual_parts[1]}.{actual_parts[2] + 1}"
            _write(
                app / "tools/toolchain-pins.json",
                json.dumps(
                    {
                        "tools": {
                            "python": python_pin,
                            "go": {"version": "1.27.1"},
                            "flutter": {
                                "version": "3.47.6",
                                "revision": "5fc346839b5d0eef006ed8404392afb4dfae428d",
                                "dart_version": "3.13.5",
                            },
                            "cocoapods": {"version": "1.17.0"},
                        }
                    },
                    sort_keys=True,
                )
                + "\n",
            )
            _fake_tool(bin_dir, "go", "go version go1.27.1 darwin/arm64")
            _fake_tool(
                bin_dir,
                "flutter",
                json.dumps(
                    {
                        "frameworkVersion": "3.47.6",
                        "frameworkRevision": "5fc346839b5d0eef006ed8404392afb4dfae428d",
                    },
                    sort_keys=True,
                ),
            )
            _fake_tool(bin_dir, "dart", "Dart SDK version: 3.13.5 (stable)")
            _fake_tool(bin_dir, "pod", "1.17.0")
            _fake_tool(bin_dir, "swiftc", "Apple Swift version 6.3")
            result = _run(
                ["bash", str(FIN_GATE), "G00"],
                env={
                    "WIN_DIR": str(app),
                    "WINS_RELEASE_PYTHON": str(_CUSTODY_PYTHON),
                    "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
                },
            )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("authenticated release Python custody", result.stdout)

    def test_g00_stops_on_release_python_implementation_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = Path(tmp) / "app"
            bin_dir = Path(tmp) / "bin"
            _write(app / "pubspec.yaml", "version: 1.2.3+4\n")
            python_pin = _running_python_pin()
            python_pin["implementation"] = "pypy" if python_pin["implementation"] != "pypy" else "cpython"
            _write(
                app / "tools/toolchain-pins.json",
                json.dumps(
                    {
                        "tools": {
                            "python": python_pin,
                            "go": {"version": "1.27.1"},
                            "flutter": {
                                "version": "3.47.6",
                                "revision": "5fc346839b5d0eef006ed8404392afb4dfae428d",
                                "dart_version": "3.13.5",
                            },
                            "cocoapods": {"version": "1.17.0"},
                        }
                    },
                    sort_keys=True,
                )
                + "\n",
            )
            _fake_tool(bin_dir, "go", "go version go1.27.1 darwin/arm64")
            _fake_tool(
                bin_dir,
                "flutter",
                json.dumps(
                    {
                        "frameworkVersion": "3.47.6",
                        "frameworkRevision": "5fc346839b5d0eef006ed8404392afb4dfae428d",
                    },
                    sort_keys=True,
                ),
            )
            _fake_tool(bin_dir, "dart", "Dart SDK version: 3.13.5 (stable)")
            _fake_tool(bin_dir, "pod", "1.17.0")
            _fake_tool(bin_dir, "swiftc", "Apple Swift version 6.3")
            result = _run(
                ["bash", str(FIN_GATE), "G00"],
                env={
                    "WIN_DIR": str(app),
                    "WINS_RELEASE_PYTHON": str(_CUSTODY_PYTHON),
                    "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
                },
            )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("authenticated release Python custody", result.stdout)

    def test_release_python_pin_is_exact_reviewed_cpython_3_14_7(self) -> None:
        manifest = json.loads((ROOT / "tools/toolchain-pins.json").read_text(encoding="utf-8"))
        pin = manifest["tools"]["python"]
        self.assertEqual(pin["version"], "3.14.7")
        self.assertEqual(pin["implementation"], "cpython")
        self.assertEqual(
            pin["reviewed_executable_path"]["darwin_arm64"],
            "/Users/owner/.local/toolchains/python3.14.7/bin/python3.14",
        )
        self.assertRegex(pin["executable_sha256"]["darwin_arm64"], r"^[0-9a-f]{64}$")
        self.assertIn("private custody directory", pin["note"])

    def test_release_python_rejects_an_explicit_self_attesting_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp)
            app = sandbox / "app"
            fake = sandbox / "python3.14"
            _critical_release_test_files(app)
            _write(
                fake,
                "#!/bin/sh\n"
                "printf '%s\\n' \"$2\"\n"
                "exit 0\n",
            )
            fake.chmod(0o755)
            release_env = _g19_readiness_env(app)
            result = _run(
                ["bash", str(FIN_GATE), "G19"],
                env={
                    "WIN_DIR": str(app),
                    "WINS_RELEASE_PYTHON": str(fake),
                    **release_env,
                },
            )
        combined = result.stdout + result.stderr
        self.assertEqual(result.returncode, 2, combined)
        self.assertIn("authenticated archive-derived release Python custody", combined)
        self.assertIn(REPLACEMENT_REPO_CUSTODY_BLOCKER, combined)
        self.assertNotIn(str(fake), combined)

    def test_g17_requires_an_immutable_source_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp)
            app = sandbox / "app"
            bin_dir = sandbox / "bin"
            _source_freeze_roots(app)
            _fake_tool(bin_dir, "python3", "forged path python passed")
            result = _run(
                ["bash", str(FIN_GATE), "G17"],
                env={
                    "WIN_DIR": str(app),
                    "WINS_RELEASE_PYTHON": str(_CUSTODY_PYTHON),
                    "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
                },
            )
        combined = result.stdout + result.stderr
        self.assertEqual(result.returncode, 2, combined)
        if _python_execution_blocked(result):
            self.assertIn("authenticated archive-derived release Python custody", combined)
            return
        self.assertIn("missing current APP_SOURCE_LOCK is an owner/external blocker", result.stdout)
        self.assertTrue(
            "No immutable APP_SOURCE_LOCK" in combined
            or "owner blocked:" in combined
            or "missing pin: source-freeze pin record" in combined,
            combined,
        )

    def test_g18_requires_an_explicit_dependency_index(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = Path(tmp) / "app"
            _write(
                app / "tools/release_dependency_freeze.py",
                (ROOT / "tools/release_dependency_freeze.py").read_text(encoding="utf-8"),
            )
            _write_running_python_pin(app)
            result = _run(
                ["bash", str(FIN_GATE), "G18"],
                env={
                    "WIN_DIR": str(app),
                    "WINS_RELEASE_PYTHON": str(_CUSTODY_PYTHON),
                },
            )
        combined = result.stdout + result.stderr
        self.assertEqual(result.returncode, 2, combined)
        if _python_execution_blocked(result):
            self.assertIn("authenticated archive-derived release Python custody", combined)
            return
        self.assertIn("WINS_RELEASE_INPUT_INDEX must explicitly name", result.stdout)

    def test_g18_cannot_fall_back_to_passing_path_python(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp)
            app = sandbox / "app"
            bin_dir = sandbox / "bin"
            _write(
                app / "tools/release_dependency_freeze.py",
                (ROOT / "tools/release_dependency_freeze.py").read_text(encoding="utf-8"),
            )
            _write_running_python_pin(app)
            index = app / ".artifacts/RELEASE_INPUT_INDEX.json"
            _write(index, "{}\n")
            _fake_tool(bin_dir, "python3", "forged path python passed")
            result = _run(
                ["bash", str(FIN_GATE), "G18"],
                env={
                    "WIN_DIR": str(app),
                    "WINS_RELEASE_PYTHON": str(_CUSTODY_PYTHON),
                    "WINS_RELEASE_INPUT_INDEX": str(index),
                    "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
                },
            )
        combined = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0, combined)
        if _python_execution_blocked(result):
            self.assertIn("authenticated archive-derived release Python custody", combined)
            return
        self.assertEqual(result.returncode, 1, combined)
        self.assertIn("explicit dependency input index is stale or invalid", result.stdout)

    def test_g07_rejects_fake_flutter_even_with_invalid_main_and_reduced_suite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp)
            app = sandbox / "app"
            fake_flutter = sandbox / "bin/flutter"
            _write(app / "pubspec.yaml", "name: gate_fixture\nversion: 1.0.0+1\n")
            _write(app / "lib/main.dart", "this is not valid Dart\n")
            _write(app / "test/only.dart", "void main() {}\n")
            _write_running_python_pin(app)
            _write(fake_flutter, "#!/bin/sh\nexit 0\n")
            fake_flutter.chmod(0o755)
            result = _run(
                ["bash", str(FIN_GATE), "G07"],
                env={
                    "WIN_DIR": str(app),
                    "WINS_RELEASE_PYTHON": str(_CUSTODY_PYTHON),
                    "WINS_RELEASE_FLUTTER": str(fake_flutter),
                    "FLUTTER_TEST_SUITES": "test/only.dart",
                },
            )
        combined = result.stdout + result.stderr
        self.assertEqual(result.returncode, 2, combined)
        if _python_execution_blocked(result):
            self.assertIn("authenticated archive-derived release Python custody", combined)
            return
        self.assertIn("G07 requires authenticated archive-derived Android/Flutter custody", result.stdout)

    def test_g07_commands_are_fixed_to_main_and_complete_test_suite(self) -> None:
        source = FIN_GATE.read_text(encoding="utf-8")
        self.assertNotIn('FLUTTER_TEST_SUITES="', source)
        self.assertIn('run_release_flutter analyze --no-pub lib/main.dart', source)
        self.assertIn(
            'run_release_flutter build bundle --release --no-pub --target lib/main.dart', source
        )
        self.assertIn('run_release_flutter test --no-pub', source)

    def test_g19_lists_then_executes_the_authoritative_runner_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp)
            app = sandbox / "app"
            runner_log = sandbox / "runner.argv"
            _critical_release_test_files(app)
            release_env = _g19_readiness_env(app)
            _write(app / ".fake_runner_log", str(runner_log) + "\n")
            result = _run(
                ["bash", str(FIN_GATE), "G19"],
                env={
                    "WIN_DIR": str(app),
                    "WINS_RELEASE_PYTHON": str(_CUSTODY_PYTHON),
                    **release_env,
                },
            )
            runner_logged = runner_log.is_file()
            runner_argv = (
                runner_log.read_text(encoding="utf-8").splitlines() if runner_logged else []
            )
        combined = result.stdout + result.stderr
        if _python_execution_blocked(result):
            self.assertEqual(result.returncode, 2, combined)
            self.assertIn("authenticated archive-derived release Python custody", combined)
            self.assertFalse(runner_logged)
            return
        self.assertEqual(result.returncode, 0, combined)
        self.assertEqual(
            runner_argv,
            [
                f"{app.resolve()}/tools/run_test_suite.py",
                "--release-critical",
                "--exclude-python-custody-bootstrap",
            ],
        )
        self.assertIn(
            "all 1 discovered release-critical Python suites and exact cross-store artifact evidence pass",
            result.stdout,
        )

    def test_g19_splits_only_the_browser_runtime_from_seatbelt(self) -> None:
        source = FIN_GATE.read_text(encoding="utf-8")
        python_custody = (
            ROOT / "tools/release_python_archive_custody.sh"
        ).read_text(encoding="utf-8")
        runner = (ROOT / "tools/run_test_suite.py").read_text(encoding="utf-8")
        self.assertIn('source "${SCRIPT_DIR}/release_browser_archive_custody.sh"', source)
        self.assertIn("--exclude-browser-runtime", source)
        self.assertIn("--browser-runtime-only", source)
        self.assertIn("run_release_python_with_release_browser", source)
        self.assertIn("wins_release_python_run_with_release_browser", python_custody)
        self.assertIn("release-tools-browser", python_custody)
        self.assertIn('exec "$_WINS_RP_ENV" -i', python_custody)
        self.assertNotIn(
            'release-tools-browser)\n    exec "$_WINS_RP_SANDBOX_EXEC"',
            python_custody,
        )
        self.assertIn(
            'BROWSER_RUNTIME_TESTS = frozenset({"extension/tools/core_tests.py"})',
            runner,
        )
        self.assertNotIn("test_browser_runtime_custody.py", runner)
        self.assertIn(
            "Only extension/tools/core_tests.py is executed through this unsandboxed",
            python_custody,
        )
        browser_mode = python_custody.split("if [[ \"$mode\" == release-tools-browser ]]; then", 1)[1]
        browser_mode = browser_mode.split("if [[ \"$mode\" == release-tools ]]; then", 1)[0]
        self.assertIn("BROWSER_BIN=$release_browser", browser_mode)
        self.assertIn("WINS_RELEASE_BROWSER=$release_browser", browser_mode)
        self.assertIn("WINS_RELEASE_BROWSER_SHA256=$release_browser_sha", browser_mode)
        self.assertIn("WINS_RELEASE_BROWSER_TREE_SHA256=$release_browser_tree", browser_mode)
        self.assertNotIn("WINS_RELEASE_OPENSSL=$WINS_RELEASE_OPENSSL", browser_mode)
        self.assertNotIn("WINS_RELEASE_KEYTOOL=$release_keytool", browser_mode)
        self.assertNotIn("WINS_RELEASE_JARSIGNER=$release_jarsigner", browser_mode)
        self.assertNotIn("WINS_RELEASE_NODE=$release_node", browser_mode)
        self.assertNotIn("OPENSSL_CONF=/dev/null", browser_mode)
        self.assertNotIn("WINS_ANDROID_KEY_PASSWORD", browser_mode)
        self.assertNotIn("${WINS_RELEASE_OPENSSL%/*}", browser_mode)
        self.assertNotIn("${WINS_RELEASE_JAVA_HOME}/bin", browser_mode)

    def test_g19_uses_explicit_release_python(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp)
            app = sandbox / "app"
            runner_log = sandbox / "runner.argv"
            _critical_release_test_files(app)
            release_env = _g19_readiness_env(app)
            _write(app / ".fake_runner_log", str(runner_log) + "\n")
            result = _run(
                ["bash", str(FIN_GATE), "G19"],
                env={
                    "WIN_DIR": str(app),
                    "WINS_RELEASE_PYTHON": str(_CUSTODY_PYTHON),
                    **release_env,
                },
            )
            combined = result.stdout + result.stderr
            if _python_execution_blocked(result):
                self.assertEqual(result.returncode, 2, combined)
                self.assertIn("authenticated archive-derived release Python custody", combined)
                self.assertFalse(runner_log.is_file())
                return
            self.assertEqual(result.returncode, 0, combined)
            self.assertTrue(runner_log.is_file())

    def test_g19_blocks_without_exact_artifact_readiness_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp)
            app = sandbox / "app"
            _critical_release_test_files(app)
            _write(app / "tools/cross_store_upload_readiness.py", "# fixture verifier\n")
            result = _run(
                ["bash", str(FIN_GATE), "G19"],
                env={
                    "WIN_DIR": str(app),
                    "WINS_RELEASE_PYTHON": str(_CUSTODY_PYTHON),
                },
            )
        combined = result.stdout + result.stderr
        self.assertEqual(result.returncode, 2, combined)
        if _python_execution_blocked(result):
            self.assertIn("authenticated archive-derived release Python custody", combined)
            return
        self.assertIn("WINS_CROSS_STORE_READINESS_EVIDENCE must explicitly name", result.stdout)

    def test_g19_blocks_duplicate_discovery_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp)
            app = sandbox / "app"
            _critical_release_test_files(app)
            _write(
                app / ".fake_suite_list",
                "tools/test_fixture.py\ntools/test_fixture.py\n",
            )
            result = _run(
                ["bash", str(FIN_GATE), "G19"],
                env={
                    "WIN_DIR": str(app),
                    "WINS_RELEASE_PYTHON": str(_CUSTODY_PYTHON),
                },
            )
        combined = result.stdout + result.stderr
        if _python_execution_blocked(result):
            self.assertEqual(result.returncode, 2, combined)
            self.assertIn("authenticated archive-derived release Python custody", combined)
            return
        self.assertEqual(result.returncode, 1, combined)
        self.assertIn("discovery emitted duplicate test paths", result.stdout)

    def test_g19_blocks_a_symbolic_discovery_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp)
            app = sandbox / "app"
            _critical_release_test_files(app)
            target = app / "tools/fixture.py"
            _write(target, "# target\n")
            (app / "tools/test_fixture.py").unlink()
            (app / "tools/test_fixture.py").symlink_to(target)
            result = _run(
                ["bash", str(FIN_GATE), "G19"],
                env={"WIN_DIR": str(app), "WINS_RELEASE_PYTHON": str(_CUSTODY_PYTHON)},
            )
        combined = result.stdout + result.stderr
        self.assertEqual(result.returncode, 2, combined)
        if _python_execution_blocked(result):
            self.assertIn("authenticated archive-derived release Python custody", combined)
            return
        self.assertIn("authoritative Python suite path missing or symbolic", result.stdout)

    def test_g19_rejects_a_passing_path_python_without_explicit_authority(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp)
            app = sandbox / "app"
            bin_dir = sandbox / "bin"
            _critical_release_test_files(app)
            _fake_tool(bin_dir, "python3", "forged path python passed")
            release_env = _g19_readiness_env(app)
            result = _run(
                ["bash", str(FIN_GATE), "G19"],
                env={
                    "WIN_DIR": str(app),
                    "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
                    "WINS_RELEASE_PYTHON": "",
                    **release_env,
                },
            )
        combined = result.stdout + result.stderr
        self.assertNotIn("forged path python passed", combined)
        if _python_execution_blocked(result):
            self.assertEqual(result.returncode, 2, combined)
            self.assertIn("authenticated archive-derived release Python custody", combined)
            return
        self.assertEqual(result.returncode, 0, combined)

    def test_g19_stops_ship_when_a_critical_suite_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp)
            app = sandbox / "app"
            _critical_release_test_files(app)
            _write(app / ".fake_suite_status", "1\n")
            result = _run(
                ["bash", str(FIN_GATE), "G19"],
                env={
                    "WIN_DIR": str(app),
                    "WINS_RELEASE_PYTHON": str(_CUSTODY_PYTHON),
                },
            )
        combined = result.stdout + result.stderr
        if _python_execution_blocked(result):
            self.assertEqual(result.returncode, 2, combined)
            self.assertIn("authenticated archive-derived release Python custody", combined)
            return
        self.assertEqual(result.returncode, 1, combined)
        self.assertIn("release-critical Python suites failed", result.stdout)

    def test_g19_sandbox_prevents_one_test_replacing_python_for_later_tests(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp)
            app = sandbox / "app"
            marker = sandbox / "interpreter-replaced"
            _write(
                app / "tools/run_test_suite.py",
                RELEASE_TEST_RUNNER.read_text(encoding="utf-8"),
            )
            _write_running_python_pin(app)
            _write(app / "tools/test_release_python_archive_custody.py", "# bootstrap fixture\n")
            _write(app / "tools/test_release_gate_determinism.py", "# bootstrap fixture\n")
            _write(
                app / "tools/test_00_mutate_python.py",
                "import os, pathlib\n"
                "target = pathlib.Path(os.environ['WINS_RELEASE_PYTHON_RUNTIME']) / "
                "'Python.framework/Versions/3.14/bin/python3.14'\n"
                "try:\n"
                "    target.chmod(0o700)\n"
                "    target.write_text('#!/bin/sh\\nexit 0\\n')\n"
                f"    pathlib.Path({str(marker)!r}).write_text('replaced')\n"
                "except OSError:\n"
                "    pass\n",
            )
            _write(app / "tools/test_01_must_fail.py", "raise SystemExit(97)\n")
            result = _run(
                ["bash", str(FIN_GATE), "G19"],
                env={"WIN_DIR": str(app)},
            )
            marker_ran = marker.exists()
        combined = result.stdout + result.stderr
        self.assertFalse(marker_ran)
        if _python_execution_blocked(result):
            self.assertEqual(result.returncode, 2, combined)
            self.assertIn("authenticated archive-derived release Python custody", combined)
            return
        self.assertEqual(result.returncode, 1, combined)
        self.assertIn("release-critical Python suites failed", result.stdout)

    def test_g06_uses_only_current_repo_security_packages(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp)
            app = sandbox / "app"
            bin_dir = sandbox / "bin"
            marker = sandbox / "ambient-go-ran"
            _fake_go_security_module(app)
            _write_running_python_pin(app)
            _write(
                sandbox / "wins_security/core/Cargo.toml",
                "this is deliberately not a valid Cargo manifest\n",
            )
            _write(
                bin_dir / "go",
                "#!/bin/sh\n"
                f"printf ran > {shlex.quote(str(marker))}\n"
                "printf 'ok\\n'\n",
            )
            (bin_dir / "go").chmod(0o755)
            result = _run(
                ["bash", str(FIN_GATE), "G06"],
                env={
                    "WIN_DIR": str(app),
                    "WINS_RELEASE_PYTHON": str(_CUSTODY_PYTHON),
                    "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
                },
            )
            marker_ran = marker.exists()
        combined = result.stdout + result.stderr
        self.assertFalse(marker_ran)
        self.assertNotIn("cargo", result.stdout.lower())
        self.assertEqual(result.returncode, 2, combined)
        if _python_execution_blocked(result):
            self.assertIn("authenticated archive-derived release Python custody", combined)
            return
        self.assertIn("G06 requires authenticated archive-derived release Go custody", result.stdout)

    def test_g06_failure_is_stop_ship(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = Path(tmp) / "app"
            _fake_go_security_module(app, failing=True)
            _write_running_python_pin(app)
            result = _run(
                ["bash", str(FIN_GATE), "G06"],
                env={"WIN_DIR": str(app), "WINS_RELEASE_PYTHON": str(_CUSTODY_PYTHON)},
            )
        combined = result.stdout + result.stderr
        self.assertEqual(result.returncode, 2, combined)
        if _python_execution_blocked(result):
            self.assertIn("authenticated archive-derived release Python custody", combined)
            return
        self.assertIn("G06 requires authenticated archive-derived release Go custody", result.stdout)

    def test_g12_uses_only_canonical_current_repo_arb_pair(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = Path(tmp) / "app"
            _write(
                app / "lib/l10n/app_en.arb",
                '{"a":"English","@a":{"description":"template metadata"}}\n',
            )
            _write(app / "lib/l10n/app_my.arb", '{"a":"Burmese"}\n')
            _write_running_python_pin(app)
            result = _run(
                ["bash", str(FIN_GATE), "G12"],
                env={"WIN_DIR": str(app), "WINS_RELEASE_PYTHON": str(_CUSTODY_PYTHON)},
            )
        combined = result.stdout + result.stderr
        if _python_execution_blocked(result):
            self.assertEqual(result.returncode, 2, combined)
            self.assertIn("authenticated archive-derived release Python custody", combined)
            return
        self.assertEqual(result.returncode, 0, combined)
        self.assertIn("app_en.arb / app_my.arb key parity holds", result.stdout)

    def test_g12_ignores_pythonpath_sitecustomize_before_gate_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp)
            app = sandbox / "app"
            injection = sandbox / "python-injection"
            marker = sandbox / "sitecustomize-ran"
            _write(app / "lib/l10n/app_en.arb", '{"a":"English"}\n')
            _write(app / "lib/l10n/app_my.arb", '{"a":"Burmese"}\n')
            _write_running_python_pin(app)
            _write(
                injection / "sitecustomize.py",
                "import os\n"
                "from pathlib import Path\n"
                "Path(os.environ['WINS_SITECUSTOMIZE_MARKER']).write_text('executed')\n",
            )
            result = _run(
                ["bash", str(FIN_GATE), "G12"],
                env={
                    "WIN_DIR": str(app),
                    "WINS_RELEASE_PYTHON": str(_CUSTODY_PYTHON),
                    "PYTHONPATH": str(injection),
                    "WINS_SITECUSTOMIZE_MARKER": str(marker),
                },
            )
            marker_ran = marker.exists()
        combined = result.stdout + result.stderr
        self.assertFalse(marker_ran, "sitecustomize executed before authenticated gate code")
        if _python_execution_blocked(result):
            self.assertEqual(result.returncode, 2, combined)
            self.assertIn("authenticated archive-derived release Python custody", combined)
            return
        self.assertEqual(result.returncode, 0, combined)

    def test_g12_ignores_hostile_path_dirname_and_bash_env(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp)
            app = sandbox / "app"
            bin_dir = sandbox / "bin"
            marker = sandbox / "bash-env-ran"
            _write(app / "lib/l10n/app_en.arb", '{"a":"English"}\n')
            _write(app / "lib/l10n/app_my.arb", '{"a":"Burmese"}\n')
            _write_running_python_pin(app)
            _write(bin_dir / "dirname", "#!/bin/sh\nexit 99\n")
            (bin_dir / "dirname").chmod(0o755)
            bash_env = sandbox / "hostile-bash-env"
            _write(
                bash_env,
                f"printf owned > {marker}\n"
                "wins_release_python_prepare() { return 0; }\n"
                "wins_release_python_run() { return 0; }\n",
            )
            result = _run(
                ["bash", str(FIN_GATE), "G12"],
                env={
                    "WIN_DIR": str(app),
                    "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
                    "BASH_ENV": str(bash_env),
                },
            )
            marker_ran = marker.exists()
        combined = result.stdout + result.stderr
        self.assertFalse(marker_ran)
        if _python_execution_blocked(result):
            self.assertEqual(result.returncode, 2, combined)
            self.assertIn("authenticated archive-derived release Python custody", combined)
            return
        self.assertEqual(result.returncode, 0, combined)

    def test_g12_missing_message_key_is_stop_ship(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = Path(tmp) / "app"
            _write(app / "lib/l10n/app_en.arb", '{"a":"English","b":"More"}\n')
            _write(app / "lib/l10n/app_my.arb", '{"a":"Burmese"}\n')
            _write_running_python_pin(app)
            result = _run(
                ["bash", str(FIN_GATE), "G12"],
                env={"WIN_DIR": str(app), "WINS_RELEASE_PYTHON": str(_CUSTODY_PYTHON)},
            )
        combined = result.stdout + result.stderr
        if _python_execution_blocked(result):
            self.assertEqual(result.returncode, 2, combined)
            self.assertIn("authenticated archive-derived release Python custody", combined)
            return
        self.assertEqual(result.returncode, 1, combined)
        self.assertIn("ARB key parity broken", result.stdout)

    def test_g12_does_not_accept_foreign_or_explicit_arb_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp)
            app = sandbox / "app"
            foreign_en = sandbox / "foreign/app_en.arb"
            foreign_my = sandbox / "foreign/app_my.arb"
            _write(foreign_en, '{"a":"English"}\n')
            _write(foreign_my, '{"a":"Burmese"}\n')
            result = _run(
                ["bash", str(FIN_GATE), "G12"],
                env={
                    "WIN_DIR": str(app),
                    "ARB_EN": str(foreign_en),
                    "ARB_MY": str(foreign_my),
                },
            )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("canonical ARB pair missing", result.stdout)


class KotlinCompilerDeterminismTest(unittest.TestCase):
    def test_swift_module_cache_is_run_local(self) -> None:
        source = CONFORMANCE_GATE.read_text(encoding="utf-8")
        self.assertIn('SWIFT_MODULE_CACHE="${WORK_DIR}/swift-module-cache"', source)
        self.assertIn('-module-cache-path "${SWIFT_MODULE_CACHE}"', source)

    def test_exact_stable_pin_wins_over_newer_rc_cache_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "cache"
            _fake_kotlin_closure(cache)
            _fake_jar(
                cache,
                "org.jetbrains.kotlin",
                "kotlin-compiler-embeddable",
                "2.4.21-RC",
            )
            _fake_jar(
                cache,
                "org.jetbrains.kotlin",
                "kotlin-stdlib",
                "2.4.21-RC",
            )
            result = _run(
                ["bash", str(CONFORMANCE_GATE), "--check-kotlin-toolchain"],
                env={"GRADLE_CACHE": str(cache)},
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("version=2.4.20", result.stdout)
        self.assertIn("kotlin-compiler-embeddable-2.4.20.jar", result.stdout)
        self.assertNotIn("2.4.21-RC", result.stdout)

    def test_prerelease_repository_pin_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            cache = Path(tmp) / "cache"
            pin = {"tools": {"kotlin": {"version": "2.4.21-RC"}}}
            _write(
                project / "tools/toolchain-pins.json",
                json.dumps(pin, sort_keys=True) + "\n",
            )
            _fake_kotlin_closure(cache, version="2.4.21-RC")
            result = _run(
                ["bash", str(CONFORMANCE_GATE), "--check-kotlin-toolchain"],
                env={"PROJECT_ROOT": str(project), "GRADLE_CACHE": str(cache)},
            )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("exact stable numeric version", result.stderr)

    def test_duplicate_exact_compiler_candidates_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "cache"
            _fake_kotlin_closure(cache)
            _fake_jar(
                cache,
                "org.jetbrains.kotlin",
                "kotlin-compiler-embeddable",
                "2.4.20",
                digest="duplicate",
            )
            result = _run(
                ["bash", str(CONFORMANCE_GATE), "--check-kotlin-toolchain"],
                env={"GRADLE_CACHE": str(cache)},
            )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("expected exactly one cached", result.stderr)
        self.assertIn("found 2", result.stderr)

    def test_symlinked_compiler_candidate_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "cache"
            _fake_kotlin_closure(cache)
            compiler = next(cache.rglob("kotlin-compiler-embeddable-2.4.20.jar"))
            target = compiler.with_name("compiler-real.jar")
            compiler.rename(target)
            compiler.symlink_to(target)
            result = _run(
                ["bash", str(CONFORMANCE_GATE), "--check-kotlin-toolchain"],
                env={"GRADLE_CACHE": str(cache)},
            )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("not a regular non-symlink file", result.stderr)


if __name__ == "__main__":
    unittest.main()
