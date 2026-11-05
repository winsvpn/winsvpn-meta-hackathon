#!/usr/bin/env python3
"""Source tests for Apple isTelevision method-channel readiness."""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BRIDGES = (
    ROOT / "ios" / "Runner" / "AppDelegate.swift",
    ROOT / "macos" / "Runner" / "MainFlutterWindow.swift",
)


def case_body(source: str, method: str) -> str:
    needle = f'case "{method}":'
    start = source.index(needle)
    next_case = source.find("\n    case ", start + 1)
    if next_case < 0:
        raise AssertionError(f"unterminated case {method!r}")
    return source[start:next_case]


class AppleIsTelevisionMethodChannelTests(unittest.TestCase):
    def test_contract_verifier_passes(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools" / "verify_apple_method_channel_contract.py"),
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            completed.returncode,
            0,
            completed.stdout + completed.stderr,
        )
        self.assertIn("Apple method channel contract passed", completed.stdout)
        self.assertIn("isTelevision", completed.stdout)

    def test_nested_block_comment_is_never_code(self) -> None:
        # R23 W2-3: Dart block comments nest, so a guard after an inner `*/`
        # is still comment and must not prove the call unreachable.
        sys.path.insert(0, str(ROOT / "tools"))
        try:
            import verify_apple_method_channel_contract as contract
        finally:
            sys.path.pop(0)
        sample = (
            "class A {\n"
            "  Future<void> f() async {\n"
            "    /* outer /* inner */ if (!Platform.isIOS) return; { */\n"
            "    await c.invokeMethod('pi');\n"
            "  }\n"
            "}\n"
        )
        masked = contract.mask_non_code(sample)
        self.assertNotIn("Platform", masked)
        self.assertEqual(len(masked), len(sample))
        pairs = contract.brace_pairs(sample)
        self.assertEqual(len(pairs), 2, pairs)
        self.assertFalse(
            contract.guard_controls_call(
                masked, pairs, sample.index("'pi'"), "Platform.isIOS",
                frozenset({"Platform.isMacOS"}),
            )
        )

    def test_literal_inside_an_interpolation_cannot_shift_the_nesting(self) -> None:
        # A `'{'` inside `${...}` used to end the outer literal early and open a
        # phantom block, so the next function's call looked guarded by the
        # previous function's early exit.
        sys.path.insert(0, str(ROOT / "tools"))
        try:
            import verify_apple_method_channel_contract as contract
        finally:
            sys.path.pop(0)
        for inner in ("'{'", "'}'", "\"'\"", "r'\\'"):
            with self.subTest(inner=inner):
                sample = (
                    "class A {\n"
                    "  Future<void> f(List<String> a) async {\n"
                    "    if (!Platform.isIOS) return;\n"
                    f"    final s = '${{a.join({inner})}}';\n"
                    "  }\n"
                    "  Future<void> g() async {\n"
                    "    await c.invokeMethod('rho');\n"
                    "  }\n"
                    "}\n"
                )
                pairs = contract.brace_pairs(sample)
                self.assertEqual(len(pairs), 3, pairs)
                masked = contract.mask_non_code(sample)
                self.assertNotIn("join", masked)
                self.assertFalse(
                    contract.guard_controls_call(
                        masked, pairs, sample.index("'rho'"), "Platform.isIOS",
                        frozenset({"Platform.isMacOS"}),
                    )
                )

    def test_apple_bridges_answer_false(self) -> None:
        for path in BRIDGES:
            with self.subTest(path=str(path.relative_to(ROOT))):
                source = path.read_text(encoding="utf-8")
                body = case_body(source, "isTelevision")
                self.assertIn("result(false)", body)
                self.assertNotIn("result(true)", body)
                self.assertNotIn("FlutterMethodNotImplemented", body)

    def test_dart_only_probes_android_and_keeps_apple_on_phone(self) -> None:
        dart = (ROOT / "lib" / "main.dart").read_text(encoding="utf-8")
        self.assertIn("On iOS/macOS it", dart)
        self.assertIn("stays phone (no TV form factor in this product).", dart)

        early_guard = dart.index("if (Platform.isAndroid) {")
        early_call = dart.index("invokeMethod('isTelevision')")
        licenses = dart.index("registerNativeComponentLicenses();")
        self.assertLess(early_guard, early_call)
        self.assertLess(early_call, licenses)

        refresh_start = dart.index("Future<void> _refreshFormFactor() async {")
        refresh_end = dart.index("\n  }", refresh_start)
        refresh = dart[refresh_start:refresh_end]
        self.assertIn("if (!Platform.isAndroid) return;", refresh)
        self.assertIn("invokeMethod('isTelevision')", refresh)


if __name__ == "__main__":
    unittest.main()
