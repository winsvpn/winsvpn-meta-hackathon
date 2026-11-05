#!/usr/bin/env python3
"""Regression contracts for the Android clean-install physical harness."""

from __future__ import annotations

import pathlib
import re
import unittest


SOURCE = (
    pathlib.Path(__file__).resolve().parent / "android_fresh_release_regression.ps1"
).read_text(encoding="utf-8")


class AndroidFreshReleaseRegressionTests(unittest.TestCase):
    def test_apksigner_legacy_and_sdk37_labels_are_accepted(self) -> None:
        match = re.search(
            r"Select-String -Pattern '([^']*certificate SHA-256 digest:[^']*)'",
            SOURCE,
        )
        self.assertIsNotNone(match)
        pattern = re.compile(match.group(1))
        digest = "5" * 64
        for line in (
            f"Signer #1 certificate SHA-256 digest: {digest}",
            f"V2 Signer: certificate SHA-256 digest: {digest}",
            f"V3.1 Signer: certificate SHA-256 digest: {digest}",
        ):
            parsed = pattern.search(line)
            self.assertIsNotNone(parsed, line)
            self.assertEqual(parsed.group(1), digest)

    def test_distinct_signer_digests_remain_fail_closed(self) -> None:
        self.assertIn("Sort-Object -Unique", SOURCE)
        self.assertIn("$digests.Count -ne 1", SOURCE)
        self.assertIn(
            "Expected exactly one distinct APK signer certificate digest", SOURCE
        )

    def test_privacy_and_battery_prompts_follow_the_tunnel_order(self) -> None:
        privacy = SOURCE.index("PRIVACY_CONSENT_ACTION=accepted_without_battery_prompt")
        pin = SOURCE.index("$editFields = @(")
        connect = SOURCE.index("Tap-UiNode $connectButton")
        vpn_permission = SOURCE.index("VPN_PERMISSION_ACTION=already_granted")
        battery = SOURCE.index("Resolve-PostTunnelBatteryExemption -TimeoutSeconds 45")
        self.assertLess(privacy, pin)
        self.assertLess(pin, connect)
        self.assertLess(connect, vpn_permission)
        self.assertLess(vpn_permission, battery)
        self.assertIn("BATTERY_PRE_TUNNEL_PROMPT=absent_during_initialization", SOURCE)
        self.assertIn("BATTERY_PROMPT_TIMING=post_tunnel_only", SOURCE)
        execution = SOURCE[privacy:]
        pre_connect = execution[: execution.index("Tap-UiNode $connectButton")]
        self.assertNotIn("BATTERY_BACKGROUND_ACTION=allowed_after_secured_tunnel", pre_connect)


if __name__ == "__main__":
    unittest.main()
