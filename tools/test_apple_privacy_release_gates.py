#!/usr/bin/env python3
"""Focused privacy-gate tests for the 2026-08-24 Product Interaction contract."""

from __future__ import annotations

import copy
import json
import plistlib
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import validate_apple_submission_package as submission


COARSE = "NSPrivacyCollectedDataTypeCoarseLocation"
DEVICE = "NSPrivacyCollectedDataTypeDeviceID"
USER = "NSPrivacyCollectedDataTypeUserID"
PRODUCT = "NSPrivacyCollectedDataTypeProductInteraction"
PURCHASE = "NSPrivacyCollectedDataTypePurchaseHistory"
APP_FN = "NSPrivacyCollectedDataTypePurposeAppFunctionality"
OLD_THREE = (COARSE, DEVICE, USER)
REQUIRED = (COARSE, DEVICE, USER, PRODUCT)
REQUIRED_LABELS = (
    "Coarse Location",
    "Device ID",
    "User ID",
    "Product Interaction",
)
STALE_LIVE_LABELS = (
    "Coarse Location",
    "User ID",
    "Device ID",
    "Purchase History",
)
REBUILD_AND_REFRESH_SWITCHES = (
    "WINS_APPLE_RELEASE_CANDIDATE_REBUILD",
    "WINS_APPLE_RUNTIME_EVIDENCE_REFRESH",
    "WINS_APPLE_EXISTING_EXPORT_EVIDENCE_REFRESH",
    "WINS_MACOS_APP_STORE_PKG_INSTALL_EVIDENCE_REFRESH",
    "WINS_MACOS_APP_STORE_PKG_ROOT_GATE_REFRESH",
    "WINS_APPLE_SOURCE_READINESS_EVIDENCE_REFRESH",
)
UPLOAD_LANE_SWITCHES = (
    "WINS_IOS_TESTFLIGHT_INTERNAL_UPLOAD_SMOKE",
    "WINS_IOS_APP_STORE_CONNECT_UPLOAD_SMOKE",
    "WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE",
)
PRIVACY_MANIFEST = ROOT / "app_store" / "apple" / "review" / "privacy_label_manifest.json"
IOS_HOST = ROOT / "ios" / "Runner" / "PrivacyInfo.xcprivacy"
MACOS_HOST = ROOT / "macos" / "Runner" / "PrivacyInfo.xcprivacy"
EMPTY_TARGETS = (
    ROOT / "ios" / "PacketTunnel" / "PrivacyInfo.xcprivacy",
    ROOT / "macos" / "PacketTunnel" / "PrivacyInfo.xcprivacy",
    ROOT / "ios" / "WinsWatch Watch App" / "PrivacyInfo.xcprivacy",
)


def extract_heredoc_containing(source: str, needle: str) -> str:
    for body in re.findall(r"<<'PY'\n(.*?)\nPY\n", source, re.DOTALL):
        if needle in body:
            return body
    raise AssertionError(f"missing Python heredoc containing {needle!r}")


def readiness_privacy_live_check(readiness: str, env: dict[str, str]) -> str:
    """Run the real section 9 selector block under bash and return its choice."""
    start = readiness.index('\nprivacy_live_check="')
    end = readiness.index('"${PYTHON_BIN}" - "${privacy_live_check}" <<')
    result = subprocess.run(
        ["/bin/bash", "-c", readiness[start:end] + 'printf "%s" "${privacy_live_check}"'],
        env={"PATH": "/usr/bin:/bin", **env},
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    return result.stdout


def readiness_submission_package_calls(readiness: str, env: dict[str, str]) -> list[str]:
    """Run the real section 21 function with a stub validator; return its calls."""
    start = readiness.index("wins_readiness_section_21_apple_submission_package() {")
    end = readiness.index("\n}\n", start) + 3
    with tempfile.TemporaryDirectory() as raw:
        stub = Path(raw) / "python"
        stub.write_text('#!/bin/sh\nprintf "VALIDATOR %s\\n" "$*"\n', encoding="ascii")
        stub.chmod(0o700)
        result = subprocess.run(
            [
                "/bin/bash",
                "-c",
                "set -Eeuo pipefail\nsection() { :; }\n"
                + readiness[start:end]
                + "wins_readiness_section_21_apple_submission_package\n",
            ],
            env={"PATH": "/usr/bin:/bin", "PYTHON_BIN": str(stub), **env},
            capture_output=True,
            text=True,
            timeout=60,
        )
    if result.returncode != 0:
        raise AssertionError(result.stdout + result.stderr)
    return [line for line in result.stdout.splitlines() if line.startswith("VALIDATOR ")]


def extract_def(source: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^def {re.escape(name)}\(.*?(?=\n(?:def |[A-Za-z_]))",
        source,
    )
    if not match:
        raise AssertionError(f"missing def {name}")
    return match.group(0).rstrip() + "\n\n"


def extract_assignment(source: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^{re.escape(name)} = (?:\{{.*?^\}}|\"[^\"]*\")\n",
        source,
    )
    if not match:
        raise AssertionError(f"missing assignment {name}")
    return match.group(0)


def host_entry(
    data_type: str,
    linked: bool = True,
    tracking: bool = False,
    purposes: list[str] | None = None,
) -> dict[str, object]:
    return {
        "NSPrivacyCollectedDataType": data_type,
        "NSPrivacyCollectedDataTypeLinked": linked,
        "NSPrivacyCollectedDataTypeTracking": tracking,
        "NSPrivacyCollectedDataTypePurposes": list(
            purposes if purposes is not None else [APP_FN]
        ),
    }


def default_host_entries() -> list[dict[str, object]]:
    return [host_entry(data_type) for data_type in REQUIRED]


def host_plist_manifest(
    entries: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "NSPrivacyTracking": False,
        "NSPrivacyTrackingDomains": [],
        "NSPrivacyAccessedAPITypes": [
            {
                "NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPICategoryFileTimestamp",
                "NSPrivacyAccessedAPITypeReasons": ["C617.1"],
            },
            {
                "NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPICategoryUserDefaults",
                "NSPrivacyAccessedAPITypeReasons": ["CA92.1"],
            },
            {
                "NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPICategorySystemBootTime",
                "NSPrivacyAccessedAPITypeReasons": ["35F9.1"],
            },
        ],
        "NSPrivacyCollectedDataTypes": (
            default_host_entries() if entries is None else entries
        ),
    }


def archive_item(
    data_type: str,
    linked: bool = True,
    tracking: bool = False,
    purposes: list[str] | None = None,
) -> dict[str, object]:
    return {
        "data_type": data_type,
        "linked": linked,
        "tracking": tracking,
        "purposes": list(purposes if purposes is not None else [APP_FN]),
    }


def accessed_api(api_type: str, *reasons: str) -> dict[str, object]:
    return {"api_type": api_type, "reasons": list(reasons)}


HOST_ACCESSED_APIS = [
    accessed_api("NSPrivacyAccessedAPICategoryFileTimestamp", "C617.1"),
    accessed_api("NSPrivacyAccessedAPICategoryUserDefaults", "CA92.1"),
    accessed_api("NSPrivacyAccessedAPICategorySystemBootTime", "35F9.1"),
]
TUNNEL_ACCESSED_APIS = [
    accessed_api("NSPrivacyAccessedAPICategoryFileTimestamp", "C617.1"),
    accessed_api("NSPrivacyAccessedAPICategorySystemBootTime", "35F9.1"),
]
XRAY_ACCESSED_APIS = [
    accessed_api("NSPrivacyAccessedAPICategoryFileTimestamp", "C617.1"),
]
WINN_ACCESSED_APIS = [
    accessed_api("NSPrivacyAccessedAPICategoryFileTimestamp", "C617.1"),
    accessed_api("NSPrivacyAccessedAPICategorySystemBootTime", "35F9.1"),
]
AWG_ACCESSED_APIS = [
    accessed_api("NSPrivacyAccessedAPICategoryFileTimestamp", "C617.1"),
]


def archive_manifest(
    path: str,
    kind: str,
    collected: list[dict[str, object]] | None = None,
    apis: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "path": path,
        "subject_kind": kind,
        "tracking": False,
        "tracking_domains": [],
        "collected_data_types": list(collected or []),
        "accessed_api_types": list(apis or []),
    }


def ios_archive_manifests(
    host_items: list[dict[str, object]],
    packet_items: list[dict[str, object]] | None = None,
    framework_items: list[dict[str, object]] | None = None,
) -> list[dict[str, object]]:
    engines = [
        archive_manifest(
            (
                "Products/Applications/Runner.app/Frameworks/"
                "WinsAmneziaWGPacketEngine.framework/PrivacyInfo.xcprivacy"
            ),
            "WinsAmneziaWGPacketEngine",
            apis=AWG_ACCESSED_APIS,
        ),
        archive_manifest(
            (
                "Products/Applications/Runner.app/Frameworks/"
                "WinsXrayVlessWsTransport.framework/PrivacyInfo.xcprivacy"
            ),
            "WinsXrayVlessWsTransport",
            apis=XRAY_ACCESSED_APIS,
        ),
        archive_manifest(
            (
                "Products/Applications/Runner.app/Frameworks/"
                "WinsWinnPacketEngine.framework/PrivacyInfo.xcprivacy"
            ),
            "WinsWinnPacketEngine",
            apis=WINN_ACCESSED_APIS,
        ),
    ]
    return [
        archive_manifest(
            "Products/Applications/Runner.app/PrivacyInfo.xcprivacy",
            "runner",
            host_items,
            HOST_ACCESSED_APIS,
        ),
        archive_manifest(
            (
                "Products/Applications/Runner.app/PlugIns/"
                "PacketTunnel.appex/PrivacyInfo.xcprivacy"
            ),
            "packet_tunnel",
            packet_items,
            TUNNEL_ACCESSED_APIS,
        ),
        archive_manifest(
            (
                "Products/Applications/Runner.app/Watch/"
                "WinsWatch.app/PrivacyInfo.xcprivacy"
            ),
            "watch",
        ),
        archive_manifest(
            (
                "Products/Applications/Runner.app/Frameworks/"
                "Flutter.framework/PrivacyInfo.xcprivacy"
            ),
            "flutter",
            framework_items,
        ),
        *engines,
    ]


def archive_report(
    host_items: list[dict[str, object]],
    packet_items: list[dict[str, object]] | None = None,
    framework_items: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "archive": "wins-vpn-ios.xcarchive",
        "privacy_manifests": ios_archive_manifests(
            host_items, packet_items, framework_items
        ),
    }


def expected_ios_archive(count: int = 7) -> dict[str, object]:
    return {
        "archive": "wins-vpn-ios.xcarchive",
        "application_count": 1,
        "privacy_manifest_count": count,
        "host_app_collected_data_types": list(OLD_THREE),
        "packet_tunnel_collected_data_types": [],
        "framework_collected_data_types": [],
    }


def inventory_report(
    host_items: list[dict[str, object]],
    packet_items: list[dict[str, object]] | None = None,
    framework_items: list[dict[str, object]] | None = None,
    count: int | None = None,
    manifests: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    privacy_manifests = (
        manifests
        if manifests is not None
        else ios_archive_manifests(host_items, packet_items, framework_items)
    )
    return {
        "report_type": "local_archive_privacy_manifest_inventory",
        "generated_at": "2026-08-24T00:00:00Z",
        "archives": [
            {
                "archive": "wins-vpn-ios.xcarchive",
                "application_count": 1,
                "privacy_manifest_count": (
                    len(privacy_manifests) if count is None else count
                ),
                "privacy_manifests": privacy_manifests,
            }
        ],
    }


def load_readiness_privacy() -> dict[str, object]:
    source = (TOOLS / "verify_apple_readiness.sh").read_text(encoding="utf-8")
    heredoc = extract_heredoc_containing(source, "def require_host_collected_data")
    defs, separator, _rest = heredoc.partition("\nfor path, host in")
    if separator == "":
        raise AssertionError("readiness privacy heredoc missing verification loop")
    namespace: dict[str, object] = {}
    exec(defs, namespace)
    return namespace


def load_smoke_bundle_privacy() -> dict[str, object]:
    source = (TOOLS / "apple_runtime_smoke.sh").read_text(encoding="utf-8")
    heredoc = extract_heredoc_containing(source, "def require_privacy_manifest")
    namespace: dict[str, object] = {
        "plistlib": plistlib,
        "Path": Path,
        "label": "fixture",
    }
    exec(extract_assignment(heredoc, "FILE_TIMESTAMP_API"), namespace)
    exec(extract_assignment(heredoc, "USER_DEFAULTS_API"), namespace)
    exec(extract_assignment(heredoc, "SYSTEM_BOOT_TIME_API"), namespace)
    exec(extract_assignment(heredoc, "APP_FUNCTIONALITY_PURPOSE"), namespace)
    exec(extract_assignment(heredoc, "EXPECTED_HOST_COLLECTED_DATA"), namespace)
    exec(extract_def(heredoc, "require_privacy_manifest"), namespace)
    exec(extract_def(heredoc, "require_empty_privacy_manifest"), namespace)
    return namespace


def load_smoke_archive_privacy() -> dict[str, object]:
    source = (TOOLS / "apple_runtime_smoke.sh").read_text(encoding="utf-8")
    heredoc = extract_heredoc_containing(source, "def require_archive_manifest_contract")
    namespace: dict[str, object] = {}
    exec(extract_assignment(heredoc, "EXPECTED_HOST_COLLECTED_DATA"), namespace)
    exec(extract_assignment(heredoc, "APP_FUNCTIONALITY_PURPOSE"), namespace)
    exec(extract_def(heredoc, "data_type_map"), namespace)
    exec(extract_def(heredoc, "api_type_map"), namespace)
    exec(extract_def(heredoc, "require_archive_manifest_contract"), namespace)
    return namespace


def system_exit_message(exc: BaseException) -> str:
    if isinstance(exc, SystemExit):
        return str(exc.code)
    return str(exc)


class ApplePrivacyReleaseGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.readiness = load_readiness_privacy()
        cls.smoke_bundle = load_smoke_bundle_privacy()
        cls.smoke_archive = load_smoke_archive_privacy()
        cls.live_manifest = json.loads(PRIVACY_MANIFEST.read_text(encoding="ascii"))

    def test_scoped_gate_files_are_ascii(self) -> None:
        python_files = (
            "tools/validate_apple_submission_package.py",
            "tools/test_apple_privacy_release_gates.py",
        )
        for relative in python_files:
            with self.subTest(path=relative):
                (ROOT / relative).read_text(encoding="ascii")
        readiness = (TOOLS / "verify_apple_readiness.sh").read_text(encoding="utf-8")
        smoke = (TOOLS / "apple_runtime_smoke.sh").read_text(encoding="utf-8")
        snippets = (
            extract_heredoc_containing(readiness, "def require_host_collected_data"),
            extract_heredoc_containing(readiness, "REQUIRED_LABELS"),
            extract_heredoc_containing(smoke, "def require_privacy_manifest"),
            extract_heredoc_containing(smoke, "def require_archive_manifest_contract"),
        )
        for snippet in snippets:
            snippet.encode("ascii")

    def test_all_three_gates_share_the_four_type_host_set(self) -> None:
        expected = set(REQUIRED)
        self.assertEqual(submission.PRIVACY_REQUIRED_DATA_TYPES, expected)
        self.assertEqual(self.readiness["EXPECTED_HOST_COLLECTED_DATA"], expected)
        self.assertEqual(self.smoke_bundle["EXPECTED_HOST_COLLECTED_DATA"], expected)
        self.assertEqual(self.smoke_archive["EXPECTED_HOST_COLLECTED_DATA"], expected)
        self.assertNotEqual(set(OLD_THREE), expected)
        self.assertIn(PRODUCT, expected)

    def test_source_host_plists_pass_and_non_host_sets_stay_empty(self) -> None:
        for path in (IOS_HOST, MACOS_HOST):
            with self.subTest(path=str(path.relative_to(ROOT))):
                with path.open("rb") as handle:
                    manifest = plistlib.load(handle)
                submission._validate_host_collected_plist(manifest, str(path))
                self.readiness["require_host_collected_data"](str(path), manifest)
        for path in EMPTY_TARGETS:
            with self.subTest(path=str(path.relative_to(ROOT))):
                with path.open("rb") as handle:
                    manifest = plistlib.load(handle)
                self.assertEqual(
                    submission._privacy_collected_data_from_plist(manifest, str(path)),
                    {},
                )
                self.readiness["require_no_collection"](
                    str(path), manifest, path.name
                )

        for key, (relative_path, kind) in submission.PRIVACY_SOURCE_MANIFESTS.items():
            with self.subTest(source=key):
                submission._validate_source_privacy_plist(relative_path, kind)

    def test_recorded_archive_evidence_was_not_rewritten(self) -> None:
        evidence = self.live_manifest["binary_evidence"]
        self.assertEqual(set(evidence["source_host_collected_data_types"]), set(REQUIRED))
        for archive in evidence["expected_archives"]:
            self.assertEqual(set(archive["host_app_collected_data_types"]), set(OLD_THREE))
            self.assertNotIn(PRODUCT, archive["host_app_collected_data_types"])
            self.assertEqual(archive["packet_tunnel_collected_data_types"], [])
            self.assertEqual(archive["framework_collected_data_types"], [])

    def test_live_portal_still_fails_until_product_interaction_replaces_purchase_history(
        self,
    ) -> None:
        live = self.live_manifest["live_app_store_connect_sync"]
        self.assertEqual(tuple(live["published_data_types"]), STALE_LIVE_LABELS)
        self.assertIs(live["app_store_connect_updated"], False)
        submission.require_live_portal_stale_status_recorded(self.live_manifest)
        with self.assertRaises(AssertionError) as caught:
            submission.require_live_portal_matches_source_privacy(self.live_manifest)
        self.assertEqual(str(caught.exception), submission.LIVE_PORTAL_STALE_MESSAGE)
        self.assertEqual(
            submission.live_portal_stale_message(set(STALE_LIVE_LABELS)),
            (
                "live App Store Connect privacy labels are stale; "
                "add Product Interaction; remove Purchase History. "
                "This gate does not claim App Store Connect was updated."
            ),
        )
        messages = submission.validate_privacy_label_manifest()
        self.assertTrue(
            any("matches source PrivacyInfo plists" in item for item in messages)
        )
        self.assertTrue(
            any(
                "unbound without a current candidate" in item
                or "archive privacy report matches" in item
                for item in messages
            )
        )

    def test_live_portal_passes_only_after_exact_four_labels(self) -> None:
        passing = json.loads(json.dumps(self.live_manifest))
        passing["live_app_store_connect_sync"]["published_data_types"] = list(
            REQUIRED_LABELS
        )
        submission.require_live_portal_matches_source_privacy(passing)

        duplicate = json.loads(json.dumps(passing))
        duplicate["live_app_store_connect_sync"]["published_data_types"].append(
            "Product Interaction"
        )
        with self.assertRaises(AssertionError) as caught:
            submission.require_live_portal_matches_source_privacy(duplicate)
        self.assertEqual(
            str(caught.exception),
            "privacy_label_manifest.json published_data_types must not contain duplicates",
        )

    def test_readiness_live_label_check_follows_the_release_ready_flip(self) -> None:
        readiness = (TOOLS / "verify_apple_readiness.sh").read_text(encoding="utf-8")
        body = extract_heredoc_containing(readiness, "REQUIRED_LABELS")
        # The rebuild and every refresh check the pre-flip record (T3-2), also
        # when an upload lane is requested with them; plain runs do too. Only
        # upload lanes demand the exact live labels.
        selector_cases = [({}, "recorded-pre-flip")]
        selector_cases += [({flag: "1"}, "recorded-pre-flip") for flag in REBUILD_AND_REFRESH_SWITCHES]
        selector_cases += [
            (
                {"WINS_APPLE_RELEASE_CANDIDATE_REBUILD": "1", lane: "1"},
                "recorded-pre-flip",
            )
            for lane in UPLOAD_LANE_SWITCHES
        ]
        selector_cases += [({lane: "1"}, "exact-live-match") for lane in UPLOAD_LANE_SWITCHES]
        selector_cases += [({lane: "0"}, "recorded-pre-flip") for lane in UPLOAD_LANE_SWITCHES]
        for env, expected in selector_cases:
            with self.subTest(selector=env):
                self.assertEqual(readiness_privacy_live_check(readiness, env), expected)

        recorded = copy.deepcopy(self.live_manifest)
        self.assertEqual(
            tuple(recorded["live_app_store_connect_sync"]["published_data_types"]),
            STALE_LIVE_LABELS,
        )
        claimed = copy.deepcopy(recorded)
        claimed["live_app_store_connect_sync"]["app_store_connect_updated"] = True
        relabelled = copy.deepcopy(recorded)
        relabelled["live_app_store_connect_sync"]["published_data_types"] = list(
            REQUIRED_LABELS
        )
        flipped = copy.deepcopy(relabelled)
        flipped["live_app_store_connect_sync"]["app_store_connect_updated"] = True
        reordered = copy.deepcopy(recorded)
        reordered["live_app_store_connect_sync"]["published_data_types"] = sorted(
            STALE_LIVE_LABELS
        )
        pre_flip_refusal = "must keep the recorded stale portal labels"
        cases = (
            ("recorded-pre-flip", recorded, 0, "Deferring the live App Store Connect"),
            ("recorded-pre-flip", claimed, 1, pre_flip_refusal),
            ("recorded-pre-flip", relabelled, 1, pre_flip_refusal),
            ("recorded-pre-flip", flipped, 1, pre_flip_refusal),
            ("recorded-pre-flip", reordered, 1, pre_flip_refusal),
            (
                "exact-live-match",
                recorded,
                1,
                "live App Store Connect privacy labels are stale; "
                "add Product Interaction; remove Purchase History.",
            ),
            ("exact-live-match", flipped, 0, "match source truth"),
            ("lenient", recorded, 1, "unknown privacy label check"),
        )
        for check, manifest, expected_rc, expected_text in cases:
            with self.subTest(check=check, state=expected_text), tempfile.TemporaryDirectory() as raw:
                target = Path(raw) / "app_store" / "apple" / "review"
                target.mkdir(parents=True)
                (target / "privacy_label_manifest.json").write_text(
                    json.dumps(manifest), encoding="utf-8"
                )
                result = subprocess.run(
                    [sys.executable, "-I", "-c", body, check],
                    cwd=raw,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                self.assertEqual(result.returncode, expected_rc, result.stderr)
                self.assertIn(expected_text, result.stdout + result.stderr)

    def test_readiness_upload_lanes_validate_release_ready_and_plain_runs_stay_pre_flip(
        self,
    ) -> None:
        readiness = (TOOLS / "verify_apple_readiness.sh").read_text(encoding="utf-8")
        plain = ["VALIDATOR tools/validate_apple_submission_package.py"]
        release_ready = ["VALIDATOR tools/validate_apple_submission_package.py --release-ready"]
        rebuild = {
            "WINS_APPLE_RELEASE_CANDIDATE_REBUILD": "1",
            "WINS_IOS_APP_STORE_LOCAL_EXPORT_SMOKE": "1",
            "WINS_MACOS_APP_STORE_LOCAL_EXPORT_SMOKE": "1",
        }
        cases = [({}, plain)]
        cases += [({lane: "1"}, release_ready) for lane in UPLOAD_LANE_SWITCHES]
        cases += [({lane: "0"}, plain) for lane in UPLOAD_LANE_SWITCHES]
        cases += [({**rebuild, lane: "1"}, []) for lane in UPLOAD_LANE_SWITCHES]
        cases += [({"WINS_APPLE_SOURCE_READINESS_EVIDENCE_REFRESH": "1"}, [])]
        for env, expected in cases:
            with self.subTest(section21=env):
                calls = readiness_submission_package_calls(readiness, env)
                self.assertEqual(calls, expected)
                # Sections 9 and 21 must agree on the release-ready state
                # whenever section 21 validates at all.
                check = readiness_privacy_live_check(readiness, env)
                if calls == release_ready:
                    self.assertEqual(check, "exact-live-match")
                elif calls == plain:
                    self.assertEqual(check, "recorded-pre-flip")

    def test_source_readiness_refresh_refuses_every_upload_lane(self) -> None:
        # R24 X-03: the refresh guard listed two of the three upload lanes, so the
        # TestFlight lane combined with the refresh deferred its validation.
        readiness = (TOOLS / "verify_apple_readiness.sh").read_text(encoding="utf-8")
        start = readiness.index(
            'if [[ "${WINS_APPLE_SOURCE_READINESS_EVIDENCE_REFRESH:-0}" == "1" ]]; then\n'
            "  for conflicting_flag in"
        )
        end = readiness.index("\n  done\nfi\n", start) + len("\n  done\nfi\n")
        guard = readiness[start:end]

        def run(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                ["/bin/bash", "-c", "set -Eeuo pipefail\n" + guard],
                env={"PATH": "/usr/bin:/bin", **env},
                capture_output=True,
                text=True,
                timeout=60,
            )

        refresh = {"WINS_APPLE_SOURCE_READINESS_EVIDENCE_REFRESH": "1"}
        self.assertEqual(run(refresh).returncode, 0)
        for lane in UPLOAD_LANE_SWITCHES:
            with self.subTest(lane=lane):
                result = run({**refresh, lane: "1"})
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(f"cannot be combined with {lane}=1", result.stderr)
                self.assertEqual(run({**refresh, lane: "0"}).returncode, 0)

    def test_smoke_upload_lane_runs_the_release_ready_submission_validator(self) -> None:
        # An upload lane also requires the approved owner signoff; the plain
        # validator refuses an approved signoff, so only --release-ready can
        # pass together with it.
        smoke = (TOOLS / "apple_runtime_smoke.sh").read_text(encoding="utf-8")
        start = smoke.index("\nrequire_valid_apple_submission_package_for_upload() {\n") + 1
        function = smoke[start : smoke.index("\n}\n", start) + 3]
        lane = smoke.index("\nif app_store_connect_upload_lane_requested; then\n")
        lane_block = smoke[lane : smoke.index("\nfi\n", lane) + 1]
        self.assertLess(
            lane_block.index("  require_valid_apple_submission_package_for_upload\n"),
            lane_block.index("  require_owner_signoff_for_app_store_upload\n"),
        )
        self.assertIn(
            '"${PYTHON_BIN}" tools/validate_apple_owner_signoff.py --require-approved',
            smoke,
        )
        with tempfile.TemporaryDirectory() as raw:
            validator = Path(raw) / "validator.py"
            validator.write_text(
                "import sys\nprint('VALIDATOR ARGS', sys.argv[1:])\n", encoding="ascii"
            )
            result = subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    "set -Eeuo pipefail\nsection() { :; }\n"
                    + function
                    + "require_valid_apple_submission_package_for_upload\n",
                ],
                env={
                    "PATH": "/usr/bin:/bin",
                    "PYTHON_BIN": sys.executable,
                    "APPLE_SUBMISSION_PACKAGE_VALIDATOR": str(validator),
                },
                capture_output=True,
                text=True,
                timeout=60,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("VALIDATOR ARGS ['--release-ready']", result.stdout)

    def _privacy_manifest_messages(
        self, manifest: dict[str, object], *, release_ready: bool
    ) -> list[str]:
        text = json.dumps(manifest, indent=2)
        read_text = submission.read_text

        def fake_read_text(path: Path, **kwargs: object) -> str:
            if path == submission.PRIVACY_LABEL_MANIFEST:
                return text
            return read_text(path, **kwargs)  # type: ignore[arg-type]

        with mock.patch.object(submission, "read_text", fake_read_text):
            return submission.validate_privacy_label_manifest(release_ready=release_ready)

    def test_release_ready_privacy_manifest_accepts_only_the_recorded_flip(self) -> None:
        # R24 F-R24-01: --release-ready demanded the pre-flip stale record and
        # the exact live match at once, so no manifest could ever pass it.
        recorded = copy.deepcopy(self.live_manifest)
        flipped = copy.deepcopy(recorded)
        flipped["live_app_store_connect_sync"]["app_store_connect_updated"] = True
        flipped["live_app_store_connect_sync"]["published_data_types"] = list(
            REQUIRED_LABELS
        )
        flipped["app_store_connect_summary"]["purchase_history_status"] = "not_collected"
        flipped["app_store_connect_summary"]["product_interaction_status"] = (
            "disclosed_linked_app_functionality"
        )
        self._privacy_manifest_messages(recorded, release_ready=False)
        self._privacy_manifest_messages(flipped, release_ready=True)

        relabelled_only = copy.deepcopy(flipped)
        relabelled_only["live_app_store_connect_sync"]["app_store_connect_updated"] = False
        stale_statuses = copy.deepcopy(flipped)
        stale_statuses["app_store_connect_summary"] = copy.deepcopy(
            recorded["app_store_connect_summary"]
        )
        for label, manifest, release_ready, message in (
            ("pre-flip record at release", recorded, True, submission.LIVE_PORTAL_STALE_MESSAGE),
            ("labels without the update", relabelled_only, True, "app_store_connect_updated true"),
            ("flip with pre-flip statuses", stale_statuses, True, "purchase history status mismatch"),
            ("flip before release", flipped, False, "purchase history status mismatch"),
        ):
            with self.subTest(case=label):
                with self.assertRaises(AssertionError) as caught:
                    self._privacy_manifest_messages(manifest, release_ready=release_ready)
                self.assertIn(message, str(caught.exception))

        # The --release-ready branch runs the release-ready privacy check, so the
        # flipped manifest passes it and the pre-flip record does not.
        source = (TOOLS / "validate_apple_submission_package.py").read_text(encoding="ascii")
        branch = source[source.index('elif argv == ["--release-ready"]:'):]
        branch = branch[: branch.index("elif argv:")]
        self.assertIn("validate_privacy_label_manifest(release_ready=True)", branch)
        self.assertNotIn("validate_privacy_label_manifest()", branch)

    def test_screenshot_upload_runs_the_release_ready_submission_gate(self) -> None:
        # R24 F-R24-01: the plain validator refuses an approved owner sign-off
        # and require_approved=True refuses an unapproved one, so the screenshot
        # upload gate could never pass; upload lanes validate --release-ready.
        import apple_upload_exact_screenshots as uploader

        completed = subprocess.CompletedProcess(args=[], returncode=0)
        with mock.patch.object(
            uploader.subprocess, "run", return_value=completed
        ) as run, mock.patch.object(uploader, "validate_owner_signoff") as owner:
            uploader.run_submission_gate()
        self.assertEqual(
            run.call_args.args[0],
            [sys.executable, "tools/validate_apple_submission_package.py", "--release-ready"],
        )
        owner.assert_called_once_with(uploader.ROOT, require_approved=True)

    def test_submission_source_mutations_use_exact_messages(self) -> None:
        label = "fixture host"
        submission._validate_host_collected_plist(host_plist_manifest(), label)

        missing = [host_entry(data_type) for data_type in OLD_THREE]
        with self.assertRaises(AssertionError) as caught:
            submission._validate_host_collected_plist(host_plist_manifest(missing), label)
        self.assertEqual(
            str(caught.exception),
            f"{label} collected data {sorted(OLD_THREE)}, expected {sorted(REQUIRED)}",
        )

        extra = default_host_entries() + [host_entry(PURCHASE)]
        with self.assertRaises(AssertionError) as caught:
            submission._validate_host_collected_plist(host_plist_manifest(extra), label)
        self.assertEqual(
            str(caught.exception),
            f"{label} collected data {sorted(REQUIRED + (PURCHASE,))}, "
            f"expected {sorted(REQUIRED)}",
        )

        duplicate = default_host_entries() + [host_entry(PRODUCT)]
        with self.assertRaises(AssertionError) as caught:
            submission._validate_host_collected_plist(
                host_plist_manifest(duplicate), label
            )
        self.assertEqual(
            str(caught.exception),
            f"{label} duplicate collected data type {PRODUCT}",
        )

        unlinked = [host_entry(data_type) for data_type in OLD_THREE]
        unlinked.append(host_entry(PRODUCT, linked=False))
        with self.assertRaises(AssertionError) as caught:
            submission._validate_host_collected_plist(
                host_plist_manifest(unlinked), label
            )
        self.assertEqual(str(caught.exception), f"{label} {PRODUCT} must be linked")

        tracking = [host_entry(data_type) for data_type in OLD_THREE]
        tracking.append(host_entry(PRODUCT, tracking=True))
        with self.assertRaises(AssertionError) as caught:
            submission._validate_host_collected_plist(
                host_plist_manifest(tracking), label
            )
        self.assertEqual(
            str(caught.exception), f"{label} {PRODUCT} must not be tracking"
        )

        wrong_purpose = [host_entry(data_type) for data_type in OLD_THREE]
        wrong_purpose.append(
            host_entry(
                PRODUCT,
                purposes=["NSPrivacyCollectedDataTypePurposeAnalytics"],
            )
        )
        with self.assertRaises(AssertionError) as caught:
            submission._validate_host_collected_plist(
                host_plist_manifest(wrong_purpose), label
            )
        self.assertEqual(
            str(caught.exception),
            f"{label} {PRODUCT} must include app functionality purpose",
        )

    def test_submission_archive_mutations_use_exact_messages(self) -> None:
        label = "fixture host_app"
        good = [archive_item(data_type) for data_type in REQUIRED]
        submission._validate_archive_host_data(
            {"collected_data_types": good}, label
        )

        old = [archive_item(data_type) for data_type in OLD_THREE]
        with self.assertRaises(AssertionError) as caught:
            submission._validate_archive_host_data(
                {"collected_data_types": old}, label
            )
        self.assertEqual(str(caught.exception), f"{label} host archive collected data mismatch")

        duplicate = good + [archive_item(PRODUCT)]
        with self.assertRaises(AssertionError) as caught:
            submission._validate_archive_host_data(
                {"collected_data_types": duplicate}, label
            )
        self.assertEqual(
            str(caught.exception),
            f"{label} duplicate collected data type {PRODUCT}",
        )

        unlinked = [archive_item(data_type) for data_type in OLD_THREE]
        unlinked.append(archive_item(PRODUCT, linked=False))
        with self.assertRaises(AssertionError) as caught:
            submission._validate_archive_host_data(
                {"collected_data_types": unlinked}, label
            )
        self.assertEqual(
            str(caught.exception), f"{label} host collected data must be linked"
        )

        tracking = [archive_item(data_type) for data_type in OLD_THREE]
        tracking.append(archive_item(PRODUCT, tracking=True))
        with self.assertRaises(AssertionError) as caught:
            submission._validate_archive_host_data(
                {"collected_data_types": tracking}, label
            )
        self.assertEqual(
            str(caught.exception),
            f"{label} host collected data must not be tracking",
        )

        wrong_purpose = [archive_item(data_type) for data_type in OLD_THREE]
        wrong_purpose.append(
            archive_item(
                PRODUCT,
                purposes=["NSPrivacyCollectedDataTypePurposeAnalytics"],
            )
        )
        with self.assertRaises(AssertionError) as caught:
            submission._validate_archive_host_data(
                {"collected_data_types": wrong_purpose}, label
            )
        self.assertEqual(
            str(caught.exception),
            f"{label} host collected data missing app functionality purpose",
        )

        expected_archives = [expected_ios_archive()]
        passing_report = inventory_report(good)
        submission._validate_archive_privacy_report(
            passing_report, expected_archives
        )

        stale_report = inventory_report(old)
        with self.assertRaises(AssertionError) as caught:
            submission._validate_archive_privacy_report(stale_report, expected_archives)
        self.assertEqual(
            str(caught.exception),
            "wins-vpn-ios.xcarchive runner collected data "
            f"{sorted(OLD_THREE)}, expected {sorted(REQUIRED)}",
        )

        packet_report = inventory_report(
            good, packet_items=[archive_item(PRODUCT)]
        )
        with self.assertRaises(AssertionError) as caught:
            submission._validate_archive_privacy_report(packet_report, expected_archives)
        self.assertEqual(
            str(caught.exception),
            "wins-vpn-ios.xcarchive packet_tunnel collected data "
            f"{[PRODUCT]}, expected {[]}",
        )

    def test_readiness_mutations_use_exact_messages(self) -> None:
        path = "fixture.xcprivacy"
        require = self.readiness["require_host_collected_data"]
        require_no = self.readiness["require_no_collection"]
        require(path, host_plist_manifest())

        missing = [host_entry(data_type) for data_type in OLD_THREE]
        with self.assertRaises(SystemExit) as caught:
            require(path, host_plist_manifest(missing))
        self.assertEqual(
            system_exit_message(caught.exception),
            f"{path}: collected data types {sorted(OLD_THREE)!r}, "
            f"expected {sorted(REQUIRED)!r}",
        )

        duplicate = default_host_entries() + [host_entry(PRODUCT)]
        with self.assertRaises(SystemExit) as caught:
            require(path, host_plist_manifest(duplicate))
        self.assertEqual(
            system_exit_message(caught.exception),
            f"{path}: duplicate collected data type {PRODUCT}",
        )

        unlinked = [host_entry(data_type) for data_type in OLD_THREE]
        unlinked.append(host_entry(PRODUCT, linked=False))
        with self.assertRaises(SystemExit) as caught:
            require(path, host_plist_manifest(unlinked))
        self.assertEqual(
            system_exit_message(caught.exception),
            f"{path}: {PRODUCT} must be marked linked to the user/account",
        )

        tracking = [host_entry(data_type) for data_type in OLD_THREE]
        tracking.append(host_entry(PRODUCT, tracking=True))
        with self.assertRaises(SystemExit) as caught:
            require(path, host_plist_manifest(tracking))
        self.assertEqual(
            system_exit_message(caught.exception),
            f"{path}: {PRODUCT} must not be marked for tracking",
        )

        wrong_purpose = [host_entry(data_type) for data_type in OLD_THREE]
        wrong_purpose.append(host_entry(PRODUCT, purposes=[]))
        with self.assertRaises(SystemExit) as caught:
            require(path, host_plist_manifest(wrong_purpose))
        self.assertEqual(
            system_exit_message(caught.exception),
            f"{path}: {PRODUCT} must include app functionality purpose",
        )

        with self.assertRaises(SystemExit) as caught:
            require_no(path, host_plist_manifest([host_entry(PRODUCT)]), "watch")
        self.assertEqual(
            system_exit_message(caught.exception),
            f"{path}: watch should not declare collected data: {[PRODUCT]!r}",
        )

    def test_smoke_bundle_mutations_use_exact_messages(self) -> None:
        require = self.smoke_bundle["require_privacy_manifest"]
        require_empty = self.smoke_bundle["require_empty_privacy_manifest"]
        host_apis = {
            "NSPrivacyAccessedAPICategoryFileTimestamp": {"C617.1"},
            "NSPrivacyAccessedAPICategoryUserDefaults": {"CA92.1"},
            "NSPrivacyAccessedAPICategorySystemBootTime": {"35F9.1"},
        }
        tunnel_apis = {
            "NSPrivacyAccessedAPICategoryFileTimestamp": {"C617.1"},
            "NSPrivacyAccessedAPICategorySystemBootTime": {"35F9.1"},
        }
        with tempfile.TemporaryDirectory(prefix="wins-privacy-gate-") as tmp:
            host_path = Path(tmp) / "host.xcprivacy"
            with host_path.open("wb") as handle:
                plistlib.dump(host_plist_manifest(), handle)
            require(host_path, "host app", host_apis, host=True)

            missing_path = Path(tmp) / "missing.xcprivacy"
            with missing_path.open("wb") as handle:
                plistlib.dump(
                    host_plist_manifest(
                        [host_entry(data_type) for data_type in OLD_THREE]
                    ),
                    handle,
                )
            with self.assertRaises(SystemExit) as caught:
                require(missing_path, "host app", host_apis, host=True)
            self.assertEqual(
                system_exit_message(caught.exception),
                "fixture: host app privacy collected data "
                f"{sorted(OLD_THREE)!r}, expected {sorted(REQUIRED)!r}",
            )

            duplicate_path = Path(tmp) / "duplicate.xcprivacy"
            with duplicate_path.open("wb") as handle:
                plistlib.dump(
                    host_plist_manifest(default_host_entries() + [host_entry(PRODUCT)]),
                    handle,
                )
            with self.assertRaises(SystemExit) as caught:
                require(duplicate_path, "host app", host_apis, host=True)
            self.assertEqual(
                system_exit_message(caught.exception),
                f"fixture: host app duplicate collected data type {PRODUCT}",
            )

            unlinked_path = Path(tmp) / "unlinked.xcprivacy"
            unlinked = [host_entry(data_type) for data_type in OLD_THREE]
            unlinked.append(host_entry(PRODUCT, linked=False))
            with unlinked_path.open("wb") as handle:
                plistlib.dump(host_plist_manifest(unlinked), handle)
            with self.assertRaises(SystemExit) as caught:
                require(unlinked_path, "host app", host_apis, host=True)
            self.assertEqual(
                system_exit_message(caught.exception),
                f"fixture: host app {PRODUCT} must be linked",
            )

            tracking_path = Path(tmp) / "tracking.xcprivacy"
            tracking = [host_entry(data_type) for data_type in OLD_THREE]
            tracking.append(host_entry(PRODUCT, tracking=True))
            with tracking_path.open("wb") as handle:
                plistlib.dump(host_plist_manifest(tracking), handle)
            with self.assertRaises(SystemExit) as caught:
                require(tracking_path, "host app", host_apis, host=True)
            self.assertEqual(
                system_exit_message(caught.exception),
                f"fixture: host app {PRODUCT} must not be tracking",
            )

            purpose_path = Path(tmp) / "purpose.xcprivacy"
            wrong_purpose = [host_entry(data_type) for data_type in OLD_THREE]
            wrong_purpose.append(
                host_entry(
                    PRODUCT,
                    purposes=["NSPrivacyCollectedDataTypePurposeAnalytics"],
                )
            )
            with purpose_path.open("wb") as handle:
                plistlib.dump(host_plist_manifest(wrong_purpose), handle)
            with self.assertRaises(SystemExit) as caught:
                require(purpose_path, "host app", host_apis, host=True)
            self.assertEqual(
                system_exit_message(caught.exception),
                f"fixture: host app {PRODUCT} missing app functionality purpose",
            )

            tunnel_path = Path(tmp) / "tunnel.xcprivacy"
            tunnel = host_plist_manifest([host_entry(PRODUCT)])
            tunnel["NSPrivacyAccessedAPITypes"] = [
                {
                    "NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPICategoryFileTimestamp",
                    "NSPrivacyAccessedAPITypeReasons": ["C617.1"],
                },
                {
                    "NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPICategorySystemBootTime",
                    "NSPrivacyAccessedAPITypeReasons": ["35F9.1"],
                },
            ]
            with tunnel_path.open("wb") as handle:
                plistlib.dump(tunnel, handle)
            with self.assertRaises(SystemExit) as caught:
                require(tunnel_path, "PacketTunnel extension", tunnel_apis)
            self.assertEqual(
                system_exit_message(caught.exception),
                "fixture: PacketTunnel extension privacy manifest should not "
                f"declare collected data: {[PRODUCT]!r}",
            )

            watch_path = Path(tmp) / "watch.xcprivacy"
            watch = {
                "NSPrivacyTracking": False,
                "NSPrivacyTrackingDomains": [],
                "NSPrivacyAccessedAPITypes": [],
                "NSPrivacyCollectedDataTypes": [host_entry(PRODUCT)],
            }
            with watch_path.open("wb") as handle:
                plistlib.dump(watch, handle)
            with self.assertRaises(SystemExit) as caught:
                require_empty(watch_path, "watch companion app")
            self.assertEqual(
                system_exit_message(caught.exception),
                "fixture: watch companion app must not declare collected data",
            )

    def test_smoke_archive_mutations_use_exact_messages(self) -> None:
        require = self.smoke_archive["require_archive_manifest_contract"]
        good = [archive_item(data_type) for data_type in REQUIRED]
        require(archive_report(good))

        old = [archive_item(data_type) for data_type in OLD_THREE]
        with self.assertRaises(SystemExit) as caught:
            require(archive_report(old))
        self.assertEqual(
            system_exit_message(caught.exception),
            "wins-vpn-ios.xcarchive: archive host privacy manifest collected data "
            f"{sorted(OLD_THREE)!r}, expected {sorted(REQUIRED)!r}",
        )

        duplicate = good + [archive_item(PRODUCT)]
        with self.assertRaises(SystemExit) as caught:
            require(archive_report(duplicate))
        self.assertEqual(
            system_exit_message(caught.exception),
            "wins-vpn-ios.xcarchive: archive host privacy manifest: "
            f"duplicate collected data type {PRODUCT}",
        )

        unlinked = [archive_item(data_type) for data_type in OLD_THREE]
        unlinked.append(archive_item(PRODUCT, linked=False))
        with self.assertRaises(SystemExit) as caught:
            require(archive_report(unlinked))
        self.assertEqual(
            system_exit_message(caught.exception),
            f"wins-vpn-ios.xcarchive: archive host privacy manifest {PRODUCT} "
            "must be linked",
        )

        tracking = [archive_item(data_type) for data_type in OLD_THREE]
        tracking.append(archive_item(PRODUCT, tracking=True))
        with self.assertRaises(SystemExit) as caught:
            require(archive_report(tracking))
        self.assertEqual(
            system_exit_message(caught.exception),
            f"wins-vpn-ios.xcarchive: archive host privacy manifest {PRODUCT} "
            "must not be tracking",
        )

        wrong_purpose = [archive_item(data_type) for data_type in OLD_THREE]
        wrong_purpose.append(archive_item(PRODUCT, purposes=[]))
        with self.assertRaises(SystemExit) as caught:
            require(archive_report(wrong_purpose))
        self.assertEqual(
            system_exit_message(caught.exception),
            f"wins-vpn-ios.xcarchive: archive host privacy manifest {PRODUCT} "
            "must include app functionality purpose",
        )

        with self.assertRaises(SystemExit) as caught:
            require(archive_report(good, packet_items=[archive_item(PRODUCT)]))
        self.assertEqual(
            system_exit_message(caught.exception),
            "wins-vpn-ios.xcarchive: archive PacketTunnel privacy manifest "
            "must not collect data",
        )

        with self.assertRaises(SystemExit) as caught:
            require(archive_report(good, framework_items=[archive_item(PRODUCT)]))
        self.assertEqual(
            system_exit_message(caught.exception),
            "wins-vpn-ios.xcarchive: flutter privacy manifest must not collect data",
        )

    def test_smoke_archive_framework_contract(self) -> None:
        require = self.smoke_archive["require_archive_manifest_contract"]
        frameworks = (
            "flutter",
            "WinsAmneziaWGPacketEngine",
            "WinsXrayVlessWsTransport",
            "WinsWinnPacketEngine",
        )
        for platform in ("ios", "macos"):
            def fixture():
                report = archive_report([archive_item(kind) for kind in REQUIRED])
                report["archive"] = f"wins-vpn-{platform}.xcarchive"
                if platform == "macos":
                    report["privacy_manifests"] = [
                        item for item in report["privacy_manifests"]
                        if item["subject_kind"] != "watch"
                    ]
                return copy.deepcopy(report)

            require(fixture())
            for subject in frameworks:
                mutations = ["missing", "duplicate", "tracking", "domains", "collection"]
                if subject != "flutter":
                    mutations += ["missing_api", "wrong_reason", "extra_api", "duplicate_api"]
                for mutation in mutations:
                    with self.subTest(platform=platform, subject=subject, mutation=mutation):
                        report = fixture()
                        manifests = report["privacy_manifests"]
                        manifest = next(item for item in manifests if item["subject_kind"] == subject)
                        if mutation == "missing":
                            manifests.remove(manifest)
                        elif mutation == "duplicate":
                            manifests.append(manifest.copy())
                        elif mutation == "tracking":
                            manifest["tracking"] = True
                        elif mutation == "domains":
                            manifest["tracking_domains"] = ["tracker.example.invalid"]
                        elif mutation == "collection":
                            manifest["collected_data_types"] = [archive_item(PRODUCT)]
                        elif mutation == "missing_api":
                            manifest["accessed_api_types"] = []
                        elif mutation == "wrong_reason":
                            manifest["accessed_api_types"][0]["reasons"] = ["INVALID.1"]
                        elif mutation == "extra_api":
                            manifest["accessed_api_types"].append({
                                "api_type": "NSPrivacyAccessedAPICategoryUserDefaults",
                                "reasons": ["CA92.1"],
                            })
                        elif mutation == "duplicate_api":
                            manifest["accessed_api_types"].append(manifest["accessed_api_types"][0].copy())
                        with self.assertRaises(SystemExit) as caught:
                            require(report)
                        self.assertIn(subject.lower(), system_exit_message(caught.exception).lower())

    def test_engine_self_test_fixture_declares_product_interaction(self) -> None:
        smoke = (TOOLS / "apple_runtime_smoke.sh").read_text(encoding="utf-8")
        self.assertIn(
            "<string>NSPrivacyCollectedDataTypeProductInteraction</string>",
            smoke,
        )
        self.assertIn("EXPECTED_HOST_COLLECTED_DATA", smoke)
        self.assertIn(
            "live App Store Connect privacy labels are stale",
            (TOOLS / "verify_apple_readiness.sh").read_text(encoding="utf-8"),
        )
        self.assertIn(
            PRODUCT,
            (TOOLS / "validate_apple_submission_package.py").read_text(encoding="ascii"),
        )
        self.assertEqual(
            submission.PRIVACY_HOST_ARCHIVE_MARKDOWN,
            "collected data: NSPrivacyCollectedDataTypeCoarseLocation, "
            "NSPrivacyCollectedDataTypeDeviceID, "
            "NSPrivacyCollectedDataTypeProductInteraction, "
            "NSPrivacyCollectedDataTypeUserID",
        )


class AppleSubmissionPrivacyManifestClosureTests(unittest.TestCase):
    def test_winn_engine_imports_mach_absolute_time_and_packet_tunnel_does_not(
        self,
    ) -> None:
        self.assertTrue(submission.winn_engine_imports_mach_absolute_time())
        self.assertFalse(submission.packet_tunnel_imports_mach_absolute_time())
        self.assertTrue(
            submission._privacy_source_text_imports_mach_absolute_time(
                "uint64_t now = mach_absolute_time();"
            )
        )
        self.assertTrue(
            submission._privacy_source_text_imports_mach_absolute_time(
                "return clock_gettime_nsec_np(CLOCK_MONOTONIC);"
            )
        )
        self.assertFalse(
            submission._privacy_source_text_imports_mach_absolute_time(
                "elapsed uses ProcessInfo only in comments"
            )
        )

    def test_source_accessed_api_maps_are_exact(self) -> None:
        host = {
            submission.PRIVACY_FILE_TIMESTAMP_API: frozenset(
                {submission.PRIVACY_FILE_TIMESTAMP_REASON}
            ),
            submission.PRIVACY_USER_DEFAULTS_API: frozenset(
                {submission.PRIVACY_USER_DEFAULTS_REASON}
            ),
            submission.PRIVACY_SYSTEM_BOOT_TIME_API: frozenset(
                {submission.PRIVACY_SYSTEM_BOOT_TIME_REASON}
            ),
        }
        self.assertEqual(submission.expected_source_accessed_apis("host"), host)
        self.assertEqual(submission.expected_source_accessed_apis("watch"), {})
        self.assertEqual(
            submission.expected_source_accessed_apis("tunnel"),
            {
                submission.PRIVACY_FILE_TIMESTAMP_API: frozenset(
                    {submission.PRIVACY_FILE_TIMESTAMP_REASON}
                ),
                submission.PRIVACY_SYSTEM_BOOT_TIME_API: frozenset(
                    {submission.PRIVACY_SYSTEM_BOOT_TIME_REASON}
                ),
            },
        )
        winn = submission._expected_engine_accessed_apis("WinsWinnPacketEngine")
        self.assertEqual(
            winn[submission.PRIVACY_SYSTEM_BOOT_TIME_API],
            frozenset({submission.PRIVACY_SYSTEM_BOOT_TIME_REASON}),
        )
        self.assertEqual(
            winn[submission.PRIVACY_FILE_TIMESTAMP_API],
            frozenset({submission.PRIVACY_FILE_TIMESTAMP_REASON}),
        )

    def test_packet_tunnel_mach_absolute_time_import_requires_35f9(self) -> None:
        from unittest import mock

        with mock.patch.object(
            submission, "packet_tunnel_imports_mach_absolute_time", return_value=True
        ):
            mapping = submission.expected_tunnel_accessed_apis()
        self.assertEqual(
            mapping[submission.PRIVACY_SYSTEM_BOOT_TIME_API],
            frozenset({submission.PRIVACY_SYSTEM_BOOT_TIME_REASON}),
        )

        extra = host_plist_manifest()
        extra["NSPrivacyAccessedAPITypes"] = extra["NSPrivacyAccessedAPITypes"] + [
            {
                "NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPICategoryDiskSpace",
                "NSPrivacyAccessedAPITypeReasons": ["E174.1"],
            }
        ]
        actual = submission._privacy_api_reasons(extra, "fixture host")
        with self.assertRaises(AssertionError) as caught:
            submission._require_exact_api_mapping(
                actual,
                submission.expected_source_accessed_apis("host"),
                "fixture host",
            )
        self.assertIn("accessed API mapping", str(caught.exception))
        self.assertIn("NSPrivacyAccessedAPICategoryDiskSpace", str(caught.exception))

    def test_duplicate_accessed_api_type_fails_closed(self) -> None:
        duplicate = host_plist_manifest()
        duplicate["NSPrivacyAccessedAPITypes"] = (
            list(duplicate["NSPrivacyAccessedAPITypes"])
            + duplicate["NSPrivacyAccessedAPITypes"][:1]
        )
        with self.assertRaises(AssertionError) as caught:
            submission._privacy_api_reasons(duplicate, "fixture host")
        self.assertEqual(
            str(caught.exception),
            "fixture host duplicate accessed API type "
            "NSPrivacyAccessedAPICategoryFileTimestamp",
        )

    def test_archive_inventory_requires_runner_tunnel_watch_flutter_and_engines(
        self,
    ) -> None:
        good = [archive_item(data_type) for data_type in REQUIRED]
        expected = [expected_ios_archive()]
        submission._validate_archive_privacy_report(inventory_report(good), expected)

        manifests = ios_archive_manifests(good)
        missing_watch = [item for item in manifests if "Watch/" not in item["path"]]
        with self.assertRaises(AssertionError) as caught:
            submission._validate_archive_privacy_report(
                inventory_report(good, manifests=missing_watch),
                [expected_ios_archive()],
            )
        self.assertEqual(
            str(caught.exception),
            "wins-vpn-ios.xcarchive privacy_manifest_count is 6, expected 7",
        )

        replaced = []
        for item in manifests:
            if "Flutter.framework" in item["path"]:
                replaced.append(
                    archive_manifest(
                        (
                            "Products/Applications/Runner.app/Frameworks/"
                            "App.framework/PrivacyInfo.xcprivacy"
                        ),
                        "framework",
                    )
                )
            else:
                replaced.append(item)
        with self.assertRaises(AssertionError) as caught:
            submission._validate_archive_privacy_report(
                inventory_report(good, manifests=replaced),
                [expected_ios_archive()],
            )
        self.assertIn("unexpected privacy manifest path", str(caught.exception))

        duplicate = []
        for item in manifests:
            if "Watch/" in item["path"]:
                duplicate.append(
                    archive_manifest(
                        (
                            "Products/Applications/Runner.app/Frameworks/"
                            "WinsWinnPacketEngine.framework/PrivacyInfo.xcprivacy"
                        ),
                        "framework",
                        apis=WINN_ACCESSED_APIS,
                    )
                )
            else:
                duplicate.append(item)
        with self.assertRaises(AssertionError) as caught:
            submission._validate_archive_privacy_report(
                inventory_report(good, manifests=duplicate),
                [expected_ios_archive()],
            )
        self.assertIn(
            "duplicate privacy manifest for WinsWinnPacketEngine",
            str(caught.exception),
        )

    def test_winn_engine_missing_35f9_fails_closed(self) -> None:
        good = [archive_item(data_type) for data_type in REQUIRED]
        manifests = ios_archive_manifests(good)
        for item in manifests:
            if "WinsWinnPacketEngine.framework" in item["path"]:
                item["accessed_api_types"] = list(AWG_ACCESSED_APIS)
        with self.assertRaises(AssertionError) as caught:
            submission._validate_archive_privacy_report(
                inventory_report(good, manifests=manifests),
                [expected_ios_archive()],
            )
        message = str(caught.exception)
        self.assertIn("WinsWinnPacketEngine accessed API mapping", message)
        self.assertIn("35F9.1", message)

    def test_stale_three_manifest_inventory_fails_closed(self) -> None:
        good = [archive_item(data_type) for data_type in REQUIRED]
        stale_expected = [expected_ios_archive(count=3)]
        with self.assertRaises(AssertionError) as caught:
            submission._validate_archive_privacy_report(
                inventory_report(good), stale_expected
            )
        self.assertEqual(
            str(caught.exception),
            "wins-vpn-ios.xcarchive expected privacy_manifest_count is 3, expected 7",
        )

    def test_macos_archive_inventory_omits_watch(self) -> None:
        good = [archive_item(data_type) for data_type in REQUIRED]
        macos_manifests = [
            archive_manifest(
                "Products/Applications/Runner.app/Contents/Resources/PrivacyInfo.xcprivacy",
                "host_app",
                good,
                HOST_ACCESSED_APIS,
            ),
            archive_manifest(
                (
                    "Products/Applications/Runner.app/Contents/PlugIns/"
                    "PacketTunnel.appex/Contents/Resources/PrivacyInfo.xcprivacy"
                ),
                "packet_tunnel_extension",
                apis=TUNNEL_ACCESSED_APIS,
            ),
            archive_manifest(
                (
                    "Products/Applications/Runner.app/Contents/Frameworks/"
                    "FlutterMacOS.framework/Versions/A/Resources/PrivacyInfo.xcprivacy"
                ),
                "framework",
            ),
            archive_manifest(
                (
                    "Products/Applications/Runner.app/Contents/Frameworks/"
                    "WinsAmneziaWGPacketEngine.framework/Versions/A/Resources/"
                    "PrivacyInfo.xcprivacy"
                ),
                "framework",
                apis=AWG_ACCESSED_APIS,
            ),
            archive_manifest(
                (
                    "Products/Applications/Runner.app/Contents/Frameworks/"
                    "WinsXrayVlessWsTransport.framework/Versions/A/Resources/"
                    "PrivacyInfo.xcprivacy"
                ),
                "framework",
                apis=XRAY_ACCESSED_APIS,
            ),
            archive_manifest(
                (
                    "Products/Applications/Runner.app/Contents/Frameworks/"
                    "WinsWinnPacketEngine.framework/Versions/A/Resources/"
                    "PrivacyInfo.xcprivacy"
                ),
                "framework",
                apis=WINN_ACCESSED_APIS,
            ),
        ]
        report = {
            "report_type": "local_archive_privacy_manifest_inventory",
            "generated_at": "2026-08-24T00:00:00Z",
            "archives": [
                {
                    "archive": "wins-vpn-macos.xcarchive",
                    "application_count": 1,
                    "privacy_manifest_count": 6,
                    "privacy_manifests": macos_manifests,
                }
            ],
        }
        expected = [
            {
                "archive": "wins-vpn-macos.xcarchive",
                "application_count": 1,
                "privacy_manifest_count": 6,
            }
        ]
        submission._validate_archive_privacy_report(report, expected)
        self.assertEqual(
            submission.required_archive_privacy_subjects("wins-vpn-macos.xcarchive"),
            [
                "runner",
                "packet_tunnel",
                "flutter",
                "WinsAmneziaWGPacketEngine",
                "WinsXrayVlessWsTransport",
                "WinsWinnPacketEngine",
            ],
        )

    def test_archive_subjects_follow_the_real_product_names(self) -> None:
        # Rehearsal r47: the archive privacy inventory names the hosts
        # BasicCalc.app (iOS) and Win's VPN.app (macOS), not Runner.app.
        expected = {
            "Products/Applications/BasicCalc.app/PrivacyInfo.xcprivacy": "runner",
            "Products/Applications/BasicCalc.app/PlugIns/PacketTunnel.appex/PrivacyInfo.xcprivacy": "packet_tunnel",
            "Products/Applications/BasicCalc.app/Watch/WinsWatch.app/PrivacyInfo.xcprivacy": "watch",
            "Products/Applications/BasicCalc.app/Frameworks/Flutter.framework/PrivacyInfo.xcprivacy": "flutter",
            "Products/Applications/BasicCalc.app/Frameworks/WinsWinnPacketEngine.framework/PrivacyInfo.xcprivacy": "WinsWinnPacketEngine",
            "Products/Applications/Win's VPN.app/Contents/Resources/PrivacyInfo.xcprivacy": "runner",
            "Products/Applications/Win's VPN.app/Contents/PlugIns/PacketTunnel.appex/Contents/Resources/PrivacyInfo.xcprivacy": "packet_tunnel",
            "Products/Applications/Win's VPN.app/Contents/Frameworks/FlutterMacOS.framework/Versions/A/Resources/PrivacyInfo.xcprivacy": "flutter",
        }
        for path, subject in expected.items():
            with self.subTest(path=path):
                self.assertEqual(submission.archive_privacy_subject(path), subject)
        for path in (
            "Products/Applications/BasicCalc.app/Extra/PrivacyInfo.xcprivacy",
            "Products/Applications/A.app/B.app/PrivacyInfo.xcprivacy",
            "Products/Other/BasicCalc.app/PrivacyInfo.xcprivacy",
            "BasicCalc.app/PrivacyInfo.xcprivacy",
            "Products/Applications/Win's VPN.app/Contents/PrivacyInfo.xcprivacy",
            # R24 X-01: a name that merely contains a reviewed subject is not it.
            "Products/Applications/BasicCalc.app/Frameworks/XWinsWinnPacketEngine.framework/PrivacyInfo.xcprivacy",
            "Products/Applications/BasicCalc.app/Frameworks/NotFlutter.framework/PrivacyInfo.xcprivacy",
            "Products/Applications/BasicCalc.app/Frameworks/Flutter.framework.bak/PrivacyInfo.xcprivacy",
            "Products/Applications/BasicCalc.app/PlugIns/XPacketTunnel.appex/PrivacyInfo.xcprivacy",
        ):
            with self.subTest(refused=path):
                with self.assertRaisesRegex(AssertionError, "unexpected privacy manifest path"):
                    submission.archive_privacy_subject(path)

    def test_packet_tunnel_35f9_contract_is_not_weakened_by_source_scan(self) -> None:
        from unittest import mock

        good = [archive_item(data_type) for data_type in REQUIRED]
        manifests = ios_archive_manifests(good)
        for item in manifests:
            if "PacketTunnel.appex" in item["path"]:
                item["accessed_api_types"] = list(WINN_ACCESSED_APIS)
        with mock.patch.object(
            submission, "packet_tunnel_imports_mach_absolute_time", return_value=False
        ), mock.patch.object(
            submission, "winn_engine_imports_mach_absolute_time", return_value=True
        ):
            submission._validate_archive_privacy_report(
                inventory_report(good, manifests=manifests),
                [expected_ios_archive()],
            )
            self.assertEqual(
                submission.expected_tunnel_accessed_apis(),
                {
                    str(item["api_type"]): frozenset(item["reasons"])
                    for item in WINN_ACCESSED_APIS
                },
            )


if __name__ == "__main__":
    unittest.main()
