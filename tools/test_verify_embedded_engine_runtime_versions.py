#!/usr/bin/env python3
"""Focused tests for the exact Go 1.27.1 embedded-engine runtime gate."""

from __future__ import annotations

import importlib.util
import io
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load_gate():
    spec = importlib.util.spec_from_file_location(
        "wins_embedded_engine_runtime_gate",
        ROOT / "tools" / "verify_embedded_engine_runtime_versions.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load verify_embedded_engine_runtime_versions")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


GATE = load_gate()


def _blob(token: str) -> bytes:
    return b"\x00" * 16 + token.encode("ascii") + b"\x00" + b"filler" * 20


def _engine(path: Path, label: str = "synthetic engine") -> GATE.EngineBinary:
    return GATE.EngineBinary(
        label,
        path,
        GATE.REVIEWED_GO,
        "synthetic mutation",
        requires_exact_go_version=True,
    )


class ParseGoVersionTextTests(unittest.TestCase):
    def test_exact_reviewed_token_parses(self) -> None:
        self.assertEqual(GATE.parse_go_version_text("go1.27.1"), (1, 27, 1))
        self.assertEqual(
            GATE.parse_go_version_text("xray.exe: go1.27.1"),
            (1, 27, 1),
        )
        self.assertTrue(GATE.is_reviewed_go_version((1, 27, 1)))

    def test_older_newer_prerelease_missing_and_malformed_fail_to_be_reviewed(
        self,
    ) -> None:
        cases = {
            "1.26.7": "go1.26.7",
            "1.26.5": "go1.26.5",
            "1.27rc": "go1.27rc",
            "1.27rc1": "go1.27rc1",
            "1.27.0": "go1.27.0",
            "1.27.2": "go1.27.2",
            "missing": "",
            "malformed-two-component": "go1.27",
            "malformed-extra-component": "go1.27.1.1",
            "malformed-rc-after-patch": "go1.27.1rc1",
            "malformed-junk": "not-a-go-version",
            "malformed-spaces": "go 1.27.1",
        }
        for name, text in cases.items():
            with self.subTest(name=name, text=text):
                parsed = GATE.parse_go_version_text(text)
                self.assertFalse(
                    GATE.is_reviewed_go_version(parsed),
                    f"{name!r} parsed as reviewed: {parsed}",
                )
                if name in {"1.26.7", "1.26.5", "1.27.0", "1.27.2"}:
                    self.assertIsNotNone(parsed)
                    self.assertNotEqual(parsed, GATE.REVIEWED_GO)
                else:
                    self.assertIsNone(parsed)

    def test_go_version_m_rc_line_is_not_go_1_27_1(self) -> None:
        self.assertIsNone(
            GATE.parse_go_version_text(
                "/tmp/libxray.so: go1.27rc1\n\tpath\tgithub.com/xtls/xray-core/main\n"
            )
        )
        self.assertEqual(
            GATE.parse_go_version_text(
                "/tmp/libxray.so: go1.27.1\n\tpath\tgithub.com/xtls/xray-core/main\n"
            ),
            (1, 27, 1),
        )


class ExactPolicyConstantTests(unittest.TestCase):
    def test_gate_is_exact_1_27_1_not_older_minimums(self) -> None:
        self.assertEqual(GATE.REVIEWED_GO, (1, 27, 1))
        self.assertEqual(GATE.REVIEWED_GO_VERSION, "1.27.1")
        self.assertEqual(GATE.REVIEWED_GO_DISCOVERY_DATE, "2026-10-06")
        self.assertEqual(GATE.OFFICIAL_GO_MACOS_MINIMUM, "13")
        self.assertEqual(GATE.WINSVPN_MACOS_APP_DEPLOYMENT_FLOOR, "13")
        self.assertFalse(hasattr(GATE, "REVIEWED_GO_MACOS_MINIMUM"))
        self.assertEqual(GATE.WINDOWS_REVIEWED_GO_VERSION, "1.27.1")
        self.assertFalse(hasattr(GATE, "MINIMUM_GO_1_26"))
        self.assertFalse(hasattr(GATE, "MINIMUM_GO_1_25"))
        self.assertFalse(hasattr(GATE, "MINIMUM_WINDOWS_GO"))
        source = (
            ROOT / "tools" / "verify_embedded_engine_runtime_versions.py"
        ).read_text(encoding="ascii")
        self.assertNotIn("MINIMUM_GO_1_26", source)
        self.assertNotIn("MINIMUM_GO_1_25", source)
        self.assertNotIn("REVIEWED_GO_MACOS_MINIMUM", source)
        self.assertIn("discovered 2026-10-06", source)
        self.assertNotIn("macOS 12 or later", source)
        self.assertIn("macOS 13 Ventura or later", source)
        self.assertIn("also uses macOS 13", source)
        self.assertIn("They are no longer latest stable", source)


class CheckBinaryMutationTests(unittest.TestCase):
    def test_exact_1_27_1_passes_and_listed_mutations_fail(self) -> None:
        mutations = (
            ("pass-1.27.1", "go1.27.1", True),
            ("fail-1.26.7", "go1.26.7", False),
            ("fail-1.26.5", "go1.26.5", False),
            ("fail-1.27rc", "go1.27rc", False),
            ("fail-1.27.0", "go1.27.0", False),
            ("fail-1.27.2", "go1.27.2", False),
            ("fail-malformed", "go1..0", False),
        )
        with tempfile.TemporaryDirectory() as temp_name:
            temp_dir = Path(temp_name)
            for name, token, should_pass in mutations:
                path = temp_dir / f"{name}.bin"
                path.write_bytes(_blob(token))
                error = GATE.check_binary(_engine(path, name))
                with self.subTest(name=name, token=token):
                    if should_pass:
                        self.assertIsNone(error)
                    else:
                        self.assertIsNotNone(error)
                        self.assertIn(name, error)

            missing = GATE.check_binary(
                _engine(temp_dir / "missing.bin", "fail-missing")
            )
            self.assertIsNotNone(missing)
            self.assertIn("file not found", missing)

            empty = temp_dir / "empty.bin"
            empty.write_bytes(b"\x00" * 64 + b"no version here " * 4)
            malformed_empty = GATE.check_binary(_engine(empty, "fail-malformed-empty"))
            self.assertIsNotNone(malformed_empty)
            self.assertIn("could not determine embedded Go version", malformed_empty)


class AarMutationTests(unittest.TestCase):
    def _write_aar(self, root: Path, token: str) -> None:
        aar = root / "android" / "app" / "libs" / "amneziawg.aar"
        aar.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(aar, "w") as archive:
            archive.writestr("jni/arm64-v8a/libam-go.so", _blob(token))

    def test_aar_accepts_exact_1_27_1_and_rejects_old_new_and_rc(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            with mock.patch.object(GATE, "ROOT", root):
                self._write_aar(root, "go1.27.1")
                self.assertEqual(GATE.check_amneziawg_android_aar(), [])

                self._write_aar(root, "go1.26.5")
                errors = GATE.check_amneziawg_android_aar()
                self.assertTrue(errors)
                self.assertIn("go1.26.5", errors[0])
                self.assertIn("requires exactly reviewed Go go1.27.1", errors[0])

                self._write_aar(root, "go1.26.7")
                errors = GATE.check_amneziawg_android_aar()
                self.assertTrue(errors)
                self.assertIn("go1.26.7", errors[0])

                self._write_aar(root, "go1.27.0")
                errors = GATE.check_amneziawg_android_aar()
                self.assertTrue(errors)
                self.assertIn("go1.27.0", errors[0])

                self._write_aar(root, "go1.27.2")
                errors = GATE.check_amneziawg_android_aar()
                self.assertTrue(errors)
                self.assertIn("go1.27.2", errors[0])

                self._write_aar(root, "go1.27rc")
                errors = GATE.check_amneziawg_android_aar()
                self.assertTrue(errors)
                self.assertIn("could not determine embedded Go version", errors[0])


class VendoredBinaryGateTests(unittest.TestCase):
    def test_committed_windows_and_android_engines_are_exact_1_27_1(self) -> None:
        expected = {
            "Windows Xray (installer/windows/dependencies/xray.exe)",
            "Windows AmneziaWG maintenance helper "
            "(installer/windows/dependencies/amneziawg.exe)",
            "Android Xray (android/app/src/main/jniLibs/arm64-v8a/libxray.so)",
            "Android Xray (android/app/src/main/jniLibs/armeabi-v7a/libxray.so)",
            "Android Xray (android/app/src/main/jniLibs/x86_64/libxray.so)",
        }
        candidates = GATE._candidate_engine_binaries()
        labels = {engine.label for engine in candidates}
        self.assertTrue(expected.issubset(labels), labels)
        for engine in candidates:
            if engine.label not in expected:
                continue
            error = GATE.check_binary(engine)
            self.assertIsNone(error, error)
            version, _method = GATE.detect_go_version(engine.path)
            self.assertEqual(version, (1, 27, 1), engine.label)

        self.assertEqual(GATE.check_windows_amneziawg_provenance(), [])
        self.assertEqual(GATE.check_amneziawg_android_aar(), [])

    def test_real_verifier_passes_current_vendored_binaries(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(sys, "stdout", stdout), mock.patch.object(
            sys, "stderr", stderr
        ):
            status = GATE.main()
        self.assertEqual(status, 0, stderr.getvalue())
        self.assertIn("embedded engine runtime version gate passed.", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")


if __name__ == "__main__":
    raise SystemExit(unittest.main())
