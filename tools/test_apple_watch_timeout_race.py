#!/usr/bin/env python3
"""Execute the exact production request-generation logic in a Swift harness."""

from __future__ import annotations

import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PHONE_LINK = ROOT / "ios" / "WinsWatch Watch App" / "PhoneLink.swift"
BEGIN = "// BEGIN PHONE_LINK_REQUEST_GENERATION"
END = "// END PHONE_LINK_REQUEST_GENERATION"


def production_generation_source() -> str:
    source = PHONE_LINK.read_text(encoding="utf-8")
    if source.count(BEGIN) != 1 or source.count(END) != 1:
        raise AssertionError("PhoneLink request-generation test markers are not unique")
    block = source.split(BEGIN, 1)[1].split(END, 1)[0].strip()
    if "struct PhoneLinkRequestGeneration" not in block:
        raise AssertionError("PhoneLink request-generation implementation is missing")
    return block


class AppleWatchTimeoutRaceTests(unittest.TestCase):
    def test_old_shared_flag_model_reproduces_cross_request_timeout(self) -> None:
        sending = True
        # Request A completes, then request B starts before A's four-second
        # closure runs. The old closure sees only B's shared flag.
        sending = False
        sending = True
        old_timeout_failed_new_request = sending
        self.assertTrue(old_timeout_failed_new_request)

    def test_exact_production_generation_rejects_old_timeout(self) -> None:
        block = production_generation_source()
        harness = f"""import Foundation

{block}

var generation = PhoneLinkRequestGeneration()
let requestA = generation.begin()
let requestB = generation.begin()
precondition(!generation.complete(requestA), "old timeout completed newer request")
precondition(generation.complete(requestB), "current request did not complete")
precondition(!generation.complete(requestB), "request completed more than once")
let requestC = generation.begin()
generation.cancel()
precondition(!generation.complete(requestC), "cancelled request still completed")
print("PASS request-correlated Watch timeout generation")
"""
        with tempfile.TemporaryDirectory(prefix="wins-watch-timeout-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "WatchTimeoutRace.swift"
            executable = root / "WatchTimeoutRace"
            source.write_text(harness, encoding="utf-8")
            compile_result = subprocess.run(
                ["/usr/bin/xcrun", "swiftc", str(source), "-o", str(executable)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run_result = subprocess.run(
                [str(executable)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
                check=False,
            )
        self.assertEqual(run_result.returncode, 0, run_result.stderr)
        self.assertIn("PASS request-correlated Watch timeout generation", run_result.stdout)

    def test_callbacks_and_deadline_are_bound_to_captured_request(self) -> None:
        source = PHONE_LINK.read_text(encoding="utf-8")
        self.assertGreaterEqual(source.count("complete(requestID: requestID)"), 3)
        self.assertIn("let requestID = requestGeneration.begin()", source)
        self.assertIn("guard requestGeneration.complete(requestID) else { return false }", source)


if __name__ == "__main__":
    unittest.main()
