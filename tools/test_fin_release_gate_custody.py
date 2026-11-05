#!/usr/bin/env python3
"""Focused final-gate custody integration: ambient PATH refusal and wrappers."""

from __future__ import annotations

import os
from pathlib import Path
import re
import shlex
import sys
import tempfile
import unittest

from test_release_gate_determinism import (
    FIN_GATE,
    ROOT,
    _CUSTODY_PYTHON,
    _critical_release_test_files,
    _g19_readiness_env,
    _python_execution_blocked,
    _run,
    _write,
    _write_running_python_pin,
)


GATE_SOURCE = FIN_GATE.read_text(encoding="utf-8")
AMBIENT_TOOLS = (
    "go",
    "ISCC",
    "ISCC.exe",
    "flutter",
    "dart",
    "java",
    "python3",
    "python",
    "node",
    "openssl",
    "chrome",
    "google-chrome",
    "dpkg-deb",
    "flatpak",
    "snapcraft",
    "makensis",
)


def _marker_stub(directory: Path, name: str, marker: Path) -> Path:
    path = directory / name
    _write(
        path,
        "#!/bin/sh\n"
        f"printf ran >> {shlex.quote(str(marker))}\n"
        "printf '%s\\n' ambient-ok\n"
        "exit 0\n",
    )
    path.chmod(0o755)
    return path


def _gate_body(name: str) -> str:
    match = re.search(
        rf"(?ms)^gate_{name}\(\) \{{.*?\n^}}\n",
        GATE_SOURCE,
    )
    if match is None:
        raise AssertionError(f"missing gate_{name} body")
    return match.group(0)


class FinReleaseGateCustodyTest(unittest.TestCase):
    def test_static_source_locks_path_and_sources_every_custody_wrapper(self) -> None:
        self.assertIn("PATH=/usr/bin:/bin:/usr/sbin:/sbin\n", GATE_SOURCE)
        self.assertNotIn("${PATH:-}", GATE_SOURCE)
        self.assertIn("hash -r", GATE_SOURCE)
        self.assertIn("trap cleanup_release_custody EXIT", GATE_SOURCE)
        for wrapper in (
            "release_python_archive_custody.sh",
            "release_android_toolchain_archive_custody.sh",
            "release_openssl_archive_custody.sh",
            "release_node_archive_custody.sh",
            "release_browser_archive_custody.sh",
            "release_go_archive_custody.sh",
        ):
            self.assertIn(f'source "${{SCRIPT_DIR}}/{wrapper}"', GATE_SOURCE)
        self.assertIn("release_inno_toolchain_custody.py", GATE_SOURCE)
        self.assertIn("wins_release_go_prepare", GATE_SOURCE)
        self.assertIn("wins_release_go_verify", GATE_SOURCE)
        self.assertIn("wins_release_go_run", GATE_SOURCE)
        self.assertIn("wins_release_go_cleanup", GATE_SOURCE)
        self.assertIn("wins_release_android_toolchains_prepare", GATE_SOURCE)
        self.assertIn("wins_release_android_flutter", GATE_SOURCE)
        self.assertIn("wins_release_openssl_prepare", GATE_SOURCE)
        self.assertIn("wins_release_openssl_run", GATE_SOURCE)
        self.assertIn("wins_release_node_prepare", GATE_SOURCE)
        self.assertIn("wins_release_node_run", GATE_SOURCE)
        self.assertIn("wins_release_browser_prepare", GATE_SOURCE)
        self.assertIn("wins_release_browser_run", GATE_SOURCE)
        self.assertIn("run_release_inno_verify_pins", GATE_SOURCE)
        self.assertIn("verify_release_go_custody || return 126", GATE_SOURCE)
        self.assertIn("verify_release_android_custody || return 126", GATE_SOURCE)
        self.assertIn("MAX_EVIDENCE_AGE", GATE_SOURCE)
        self.assertIn("timedelta(hours=6)", GATE_SOURCE)
        self.assertIn("gcp-receipt-window-hours=6", GATE_SOURCE)
        self.assertIn("G17 G18 G19 G20 G21", GATE_SOURCE)
        self.assertIn("final reviews must complete before GCP proof", GATE_SOURCE)
        self.assertIn("no production deployment", GATE_SOURCE)
        self.assertIn("GitHub remains backup storage only", GATE_SOURCE)
        for forbidden in (
            "workflow_dispatch",
            "gcp_proof_deploy.py",
            "gh workflow",
            "wins_control_plane_setup_ONETOUCH.sh --deploy",
        ):
            self.assertNotIn(forbidden, GATE_SOURCE)
        self.assertNotRegex(GATE_SOURCE, r'(?m)^\s*go (build|vet|test|version)\b')
        self.assertNotRegex(GATE_SOURCE, r'(?m)^\s*flutter\s')
        self.assertNotRegex(GATE_SOURCE, r'(?m)^\s*dart\s')
        self.assertNotRegex(GATE_SOURCE, r'command -v (go|flutter|dart|java|python3|node|openssl|ISCC)\b')

    def test_static_each_orphaned_wrapper_is_called_from_its_gate(self) -> None:
        g01 = _gate_body("G01")
        self.assertIn("authenticate_release_python", g01)
        self.assertIn("authenticate_release_go", g01)
        self.assertIn("run_release_go", g01)
        self.assertLess(g01.index("authenticate_release_python"), g01.index("authenticate_release_go"))
        self.assertLess(g01.index("authenticate_release_go"), g01.index("run_release_go"))

        g07 = _gate_body("G07")
        self.assertIn("authenticate_release_python", g07)
        self.assertIn("authenticate_release_android", g07)
        self.assertIn("run_release_flutter", g07)
        self.assertLess(g07.index("authenticate_release_android"), g07.index("run_release_flutter"))

        g19 = _gate_body("G19")
        self.assertIn("authenticate_release_python", g19)
        self.assertIn("authenticate_release_tools", g19)
        self.assertIn("RELEASE_NODE_REQUIRED=1", g19)
        self.assertIn("RELEASE_BROWSER_REQUIRED=1", g19)

        tools = GATE_SOURCE.split("authenticate_release_tools()", 1)[1].split(
            "run_release_python_with_release_tools()", 1
        )[0]
        self.assertIn("wins_release_android_toolchains_prepare", GATE_SOURCE)
        self.assertIn("wins_release_openssl_prepare", tools)
        self.assertIn("wins_release_node_prepare", tools)
        self.assertIn("wins_release_browser_prepare", tools)

        g21 = _gate_body("G21")
        self.assertIn("authenticate_release_python", g21)
        self.assertIn("run_release_inno_verify_pins", g21)
        self.assertIn("owner/external blocker", g21)
        self.assertIn("timedelta(hours=6)", g21)
        self.assertIn("final reviews must complete before GCP proof", g21)
        self.assertLess(g21.index("run_release_inno_verify_pins"), g21.index("WINS_GCP_PROOF_ACCEPTANCE_RECEIPT"))

        cleanup = GATE_SOURCE.split("cleanup_release_custody()", 1)[1].split(
            "cleanup_release_python_custody()", 1
        )[0]
        for fn in (
            "wins_release_browser_cleanup",
            "wins_release_node_cleanup",
            "wins_release_openssl_cleanup",
            "wins_release_go_cleanup",
            "wins_release_android_toolchains_cleanup",
            "wins_release_python_cleanup",
        ):
            self.assertIn(fn, cleanup)

    def test_g17_and_g18_classify_a_missing_source_freeze_pin_as_a_blocker(
        self,
    ) -> None:
        for name in ("G17", "G18"):
            self.assertIn('"$out" == *"missing pin:"*', _gate_body(name))
        with tempfile.TemporaryDirectory() as tmp:
            app = Path(tmp) / "app"
            _write(
                app / "tools/release_source_freeze.py",
                (ROOT / "tools/release_source_freeze.py").read_text(encoding="utf-8"),
            )
            _write(app / "pubspec.yaml", "version: 1.2.3+4\n")
            harness = Path(tmp) / "g17.sh"
            _write(
                harness,
                "PASS=PASS; FAIL=FAIL; BLOCKED=BLOCKED\n"
                f"WIN_DIR={shlex.quote(str(app))}\n"
                "record() { printf '%s|%s|%s\\n' \"$1\" \"$2\" \"$3\"; }\n"
                "authenticate_release_python() { return 0; }\n"
                f"run_release_python() {{ {shlex.quote(sys.executable)} \"$@\"; }}\n"
                + _gate_body("G17")
                + "gate_G17\n",
            )
            result = _run(["bash", str(harness)], env={})
        combined = result.stdout + result.stderr
        self.assertIn(
            "G17|BLOCKED|missing current APP_SOURCE_LOCK is an owner/external blocker",
            result.stdout,
            combined,
        )
        self.assertIn("missing pin: source-freeze pin record", combined)

    def test_canonical_order_runs_g17_before_g18_before_g19(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp)
            app = sandbox / "app"
            _critical_release_test_files(app)
            release_env = _g19_readiness_env(app)
            _write(
                app / "tools/release_source_freeze.py",
                (ROOT / "tools/release_source_freeze.py").read_text(encoding="utf-8"),
            )
            _write(
                app / "tools/release_dependency_freeze.py",
                (ROOT / "tools/release_dependency_freeze.py").read_text(encoding="utf-8"),
            )
            result = _run(
                ["bash", str(FIN_GATE), "G19", "G18", "G17"],
                env={
                    "WIN_DIR": str(app),
                    "WINS_RELEASE_PYTHON": str(_CUSTODY_PYTHON),
                    **release_env,
                },
            )
        names = [
            line.split()[0]
            for line in result.stdout.splitlines()
            if line.startswith(("G17", "G18", "G19"))
        ]
        self.assertEqual(names, ["G17", "G18", "G19"], result.stdout + result.stderr)
        self.assertNotEqual(result.returncode, 0)

    def test_g21_blocks_missing_owner_external_proofs_and_proves_six_hour_window(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp)
            app = sandbox / "app"
            bin_dir = sandbox / "bin"
            marker = sandbox / "ambient-iscc-ran"
            _write_running_python_pin(app)
            _write(app / "pubspec.yaml", "version: 1.2.3+4\n")
            _marker_stub(bin_dir, "ISCC", marker)
            _marker_stub(bin_dir, "go", marker)
            _marker_stub(bin_dir, "gcloud", marker)
            _marker_stub(bin_dir, "gh", marker)
            result = _run(
                ["bash", str(FIN_GATE), "G21"],
                env={
                    "WIN_DIR": str(app),
                    "WINS_RELEASE_PYTHON": str(_CUSTODY_PYTHON),
                    "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
                },
            )
            marker_ran = marker.exists()
        combined = result.stdout + result.stderr
        self.assertFalse(marker_ran)
        self.assertEqual(result.returncode, 2, combined)
        self.assertIn("release-python custody:", combined)
        if _python_execution_blocked(result):
            self.assertIn("authenticated archive-derived release Python custody", combined)
            return
        self.assertIn("gcp-receipt-window-hours=6", combined)
        self.assertNotIn("Windows trust/ISCC identity is an owner/external blocker", combined)
        self.assertNotIn("Windows Inno toolchain pins failed verification", combined)
        self.assertIn("Apple installer identity is an owner/external blocker", combined)
        self.assertIn("final Fable 5, GLM 5.3, and Daybreak Blue reviews", combined)
        self.assertIn("GCP acceptance proof is an owner/external blocker", combined)
        self.assertIn("no production deployment", combined)
        self.assertIn("status|unmeasured", combined)

    def test_g21_inno_blocker_follows_verify_pins_exit_code_only(self) -> None:
        g21 = _gate_body("G21")
        start = g21.index("    local inno_out inno_rc\n")
        end = g21.index("    fi\n", start) + len("    fi\n")
        block = g21[start:end]
        self.assertIn("run_release_inno_verify_pins", block)
        self.assertIn("$inno_rc -ne 0", block)
        script = (
            "run_release_inno_verify_pins() { printf '%s\\n' \"$STUB_OUT\"; return \"$STUB_RC\"; }\n"
            "probe() {\n"
            "    local blockers=()\n"
            + block
            + "    printf 'count=%s\\n' \"${#blockers[@]}\"\n"
            "    if [[ ${#blockers[@]} -gt 0 ]]; then printf 'blocker=%s\\n' \"${blockers[@]}\"; fi\n"
            "}\n"
            "probe\n"
        )
        cases = [
            ("status|unmeasured\ncompilers_pinned|False", "0", []),
            ("status|pinned\ncompilers_pinned|True", "0", []),
            ("status|owner_inputs_required", "0", []),
            ("INNO CUSTODY REFUSED: pin status must be pinned", "1", ["Windows Inno toolchain pins failed verification"]),
            ("", "126", ["Windows Inno toolchain pins failed verification"]),
        ]
        for out, rc, expected in cases:
            with self.subTest(out=out, rc=rc):
                result = _run(
                    ["/bin/bash", "-c", script],
                    env={"STUB_OUT": out, "STUB_RC": rc, "PATH": "/usr/bin:/bin"},
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                lines = result.stdout.splitlines()
                self.assertIn(f"count={len(expected)}", lines, result.stdout + result.stderr)
                self.assertEqual(
                    [line[len("blocker="):] for line in lines if line.startswith("blocker=")],
                    expected,
                )
        self.assertNotIn("owner_inputs_required", g21)

    def test_g21_refuses_gcp_proof_before_final_reviews(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp)
            app = sandbox / "app"
            receipt = sandbox / "acceptance-receipt.json"
            _write_running_python_pin(app)
            _write(app / "pubspec.yaml", "version: 1.2.3+4\n")
            _write(receipt, "{}\n")
            result = _run(
                ["bash", str(FIN_GATE), "G21"],
                env={
                    "WIN_DIR": str(app),
                    "WINS_RELEASE_PYTHON": str(_CUSTODY_PYTHON),
                    "WINS_GCP_PROOF_ACCEPTANCE_RECEIPT": str(receipt),
                },
            )
        combined = result.stdout + result.stderr
        if _python_execution_blocked(result):
            self.assertEqual(result.returncode, 2, combined)
            self.assertIn("authenticated archive-derived release Python custody", combined)
            return
        self.assertEqual(result.returncode, 1, combined)
        self.assertIn("final reviews must complete before GCP proof", result.stdout)
        self.assertIn("production deployment is refused", result.stdout)

    def test_each_ambient_tool_is_refused_and_go_wrapper_is_invoked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp)
            app = sandbox / "app"
            bin_dir = sandbox / "bin"
            marker = sandbox / "ambient-tools-ran"
            _write_running_python_pin(app)
            _write(app / "pubspec.yaml", "version: 1.2.3+4\n")
            _write(
                app / "winn_protocol_experimental/winn3/core/core.go",
                "package core\n",
            )
            _write(
                app / "winn_protocol_experimental/winn3/core/replaystore/store.go",
                "package replaystore\n",
            )
            for name in AMBIENT_TOOLS:
                _marker_stub(bin_dir, name, marker)
            result = _run(
                ["bash", str(FIN_GATE), "G01"],
                env={
                    "WIN_DIR": str(app),
                    "WINS_RELEASE_PYTHON": str(_CUSTODY_PYTHON),
                    "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
                },
            )
            marker_ran = marker.exists()
        combined = result.stdout + result.stderr
        self.assertFalse(marker_ran)
        self.assertEqual(result.returncode, 2, combined)
        self.assertIn("release-python custody:", combined)
        if _python_execution_blocked(result):
            self.assertIn("authenticated archive-derived release Python custody", combined)
            return
        self.assertIn("G01 requires authenticated archive-derived release Go custody", combined)
        self.assertIn("release-go custody:", combined)

    def test_browser_node_openssl_and_inno_wrappers_are_invoked_not_path_bins(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp)
            app = sandbox / "app"
            bin_dir = sandbox / "bin"
            marker = sandbox / "ambient-packaging-ran"
            _critical_release_test_files(app)
            _write(
                app / ".fake_suite_list",
                "extension/tools/core_tests.py\n"
                "test/web_download_asset_decision_test.py\n",
            )
            _write(app / "extension/tools/core_tests.py", "# browser fixture\n")
            _write(app / "test/web_download_asset_decision_test.py", "# node fixture\n")
            for name in ("node", "openssl", "chrome", "ISCC", "java", "flutter"):
                _marker_stub(bin_dir, name, marker)
            result = _run(
                ["bash", str(FIN_GATE), "G19"],
                env={
                    "WIN_DIR": str(app),
                    "WINS_RELEASE_PYTHON": str(_CUSTODY_PYTHON),
                    "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
                },
            )
            marker_ran = marker.exists()
        combined = result.stdout + result.stderr
        self.assertFalse(marker_ran)
        self.assertEqual(result.returncode, 2, combined)
        self.assertIn("release-python custody:", combined)
        if _python_execution_blocked(result):
            self.assertIn("authenticated archive-derived release Python custody", combined)
            return
        self.assertIn(
            "G19 requires authenticated OpenSSL, Java, Flutter, Pub-cache, and every discovered Node/browser runtime",
            combined,
        )
        self.assertIn("release-android-toolchain custody:", combined)
        self.assertIn("release-openssl custody:", combined)
        self.assertIn("release-node custody:", combined)
        self.assertIn("release-browser custody:", combined)

    def test_g07_invokes_android_flutter_wrapper_and_refuses_ambient_flutter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp)
            app = sandbox / "app"
            bin_dir = sandbox / "bin"
            marker = sandbox / "ambient-flutter-ran"
            _write(app / "lib/main.dart", "void main() {}\n")
            _write_running_python_pin(app)
            for name in ("flutter", "dart", "java"):
                _marker_stub(bin_dir, name, marker)
            result = _run(
                ["bash", str(FIN_GATE), "G07"],
                env={
                    "WIN_DIR": str(app),
                    "WINS_RELEASE_PYTHON": str(_CUSTODY_PYTHON),
                    "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
                },
            )
            marker_ran = marker.exists()
        combined = result.stdout + result.stderr
        self.assertFalse(marker_ran)
        self.assertEqual(result.returncode, 2, combined)
        self.assertIn("release-python custody:", combined)
        if _python_execution_blocked(result):
            self.assertIn("authenticated archive-derived release Python custody", combined)
            return
        self.assertIn("G07 requires authenticated archive-derived Android/Flutter custody", combined)
        self.assertIn("release-android-toolchain custody:", combined)

    def test_github_is_backup_only_in_the_final_gate(self) -> None:
        lowered = GATE_SOURCE.lower()
        self.assertIn("github remains backup storage only", lowered)
        self.assertNotIn("workflow_dispatch", lowered)
        self.assertNotIn("actions/checkout", lowered)
        self.assertNotRegex(GATE_SOURCE, r'\bgh\s+(workflow|pr|release)\b')


if __name__ == "__main__":
    unittest.main(verbosity=2)
