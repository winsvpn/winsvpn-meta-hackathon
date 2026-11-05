#!/usr/bin/env python3
"""Regression checks for the first-run privacy and store disclosure contract."""

from __future__ import annotations

import re
import unittest
from functools import lru_cache
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CLIENT = (ROOT / "lib" / "main.dart").read_text(encoding="utf-8")
ANDROID = (
    ROOT
    / "android"
    / "app"
    / "src"
    / "main"
    / "kotlin"
    / "org"
    / "winsvpn"
    / "app"
    / "MainActivity.kt"
).read_text(encoding="utf-8")
WEB = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
WORKER = (ROOT / "web" / "_worker.js").read_text(encoding="utf-8")
REDIRECTS = (ROOT / "web" / "_redirects").read_text(encoding="utf-8")
CONTROL = (ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh").read_text(
    encoding="utf-8"
)
PLAY = (ROOT / "docs" / "GOOGLE_PLAY_RELEASE_DECLARATIONS.md").read_text(
    encoding="utf-8"
)


# Trees whose compiled/shipped sources must never touch the Android hardware
# identifier. `drop_in/` is deliberately excluded: it is an unbuilt legacy
# snapshot (excluded in analysis_options.yaml, no Gradle root, not on any build
# path), so it is not part of the shipping app.
IDENTIFIER_SCAN_ROOTS = ("android", "lib")
IDENTIFIER_SCAN_SUFFIXES = (".kt", ".java", ".dart")
IDENTIFIER_SCAN_SKIP_DIRS = {"build", ".gradle", ".dart_tool"}


def hardware_identifier_references() -> list[tuple[str, int, str]]:
    """Every line under the shipping Android/Dart trees naming ANDROID_ID."""
    hits: list[tuple[str, int, str]] = []
    for root_name in IDENTIFIER_SCAN_ROOTS:
        for path in sorted((ROOT / root_name).rglob("*")):
            if path.name.startswith("._"):
                # AppleDouble resource-fork sidecar (macOS Finder artifact,
                # ubiquitous in this tree after an exFAT migration). It is a
                # binary file, not source; decoding it as UTF-8 raises, and a
                # crash here silently skips every assertion below.
                continue
            if path.suffix not in IDENTIFIER_SCAN_SUFFIXES or not path.is_file():
                continue
            if IDENTIFIER_SCAN_SKIP_DIRS.intersection(path.parts):
                continue
            lines = path.read_text(encoding="utf-8").splitlines()
            for number, line in enumerate(lines, 1):
                if "android_id" in line.lower():
                    relative = path.relative_to(ROOT).as_posix()
                    hits.append((relative, number, line.strip()))
    return hits


@lru_cache(maxsize=8)
def dart_code_mask(source: str) -> str:
    """Blank comments and strings while preserving source offsets and newlines."""
    masked = list(source)
    index = 0

    def blank(start: int, end: int) -> None:
        for offset in range(start, end):
            if masked[offset] not in ("\n", "\r"):
                masked[offset] = " "

    while index < len(source):
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            if end < 0:
                end = len(source)
            blank(index, end)
            index = end
            continue
        if source.startswith("/*", index):
            start = index
            depth = 1
            index += 2
            while index < len(source) and depth:
                if source.startswith("/*", index):
                    depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            blank(start, index)
            continue
        if source[index] in ("'", '"'):
            start = index
            quote = source[index]
            triple = source.startswith(quote * 3, index)
            delimiter = quote * (3 if triple else 1)
            raw = (
                index > 0
                and source[index - 1] in ("r", "R")
                and (index < 2 or not source[index - 2].isalnum())
                and (index < 2 or source[index - 2] != "_")
            )
            index += len(delimiter)
            while index < len(source):
                if not raw and source[index] == "\\":
                    index = min(index + 2, len(source))
                    continue
                if source.startswith(delimiter, index):
                    index += len(delimiter)
                    break
                index += 1
            blank(start, index)
            continue
        index += 1
    return "".join(masked)


def dart_method_body(
    source: str,
    method_name: str,
    *,
    occurrence: int | None = None,
) -> str:
    """Return one class method without depending on its return type or neighbor."""
    masked_source = dart_code_mask(source)
    declaration = re.compile(
        rf"(?m)^  [A-Za-z_][A-Za-z0-9_<>, ?]*\s+{re.escape(method_name)}\s*\("
    )
    matches = list(declaration.finditer(masked_source))
    if occurrence is None and len(matches) != 1:
        raise AssertionError(
            f"expected exactly one declaration of {method_name}, found {len(matches)}"
        )
    if occurrence is not None and not 0 <= occurrence < len(matches):
        raise AssertionError(
            f"expected occurrence {occurrence} of {method_name}, found {len(matches)}"
        )

    declaration_match = matches[occurrence or 0]
    signature_start = declaration_match.start()
    opening_paren = masked_source.index(
        "(", declaration_match.start(), declaration_match.end()
    )
    paren_depth = 0
    signature_end = -1
    for index in range(opening_paren, len(masked_source)):
        char = masked_source[index]
        if char == "(":
            paren_depth += 1
        elif char == ")":
            paren_depth -= 1
            if paren_depth == 0:
                signature_end = index + 1
                break
    if signature_end < 0:
        raise AssertionError(f"unterminated signature for {method_name}")

    opening_brace = masked_source.find("{", signature_end)
    if opening_brace < 0:
        raise AssertionError(f"missing body for {method_name}")
    brace_depth = 0
    for index in range(opening_brace, len(masked_source)):
        char = masked_source[index]
        if char == "{":
            brace_depth += 1
        elif char == "}":
            brace_depth -= 1
            if brace_depth == 0:
                return source[signature_start : index + 1]
    raise AssertionError(f"unterminated body for {method_name}")


def dart_arrow_member_body(source: str, member_name: str) -> str:
    """Return one expression-bodied (`=>`) class member through its `;`."""
    masked_source = dart_code_mask(source)
    declaration = re.compile(
        rf"(?m)^  [A-Za-z_][A-Za-z0-9_<>, ?]*\s+{re.escape(member_name)}"
        rf"\s*\([^)]*\)\s*=>"
    )
    matches = list(declaration.finditer(masked_source))
    if len(matches) != 1:
        raise AssertionError(
            f"expected exactly one arrow declaration of {member_name}, "
            f"found {len(matches)}"
        )
    depth = 0
    for index in range(matches[0].end(), len(masked_source)):
        char = masked_source[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == ";" and depth == 0:
            return source[matches[0].start() : index + 1]
    raise AssertionError(f"unterminated arrow body for {member_name}")


def replace_in_dart_method(
    source: str,
    method_name: str,
    old: str,
    new: str,
) -> str:
    """Apply one hostile mutation while leaving same-named decoy methods intact."""
    body = dart_method_body(source, method_name)
    if body.count(old) != 1:
        raise AssertionError(
            f"expected one {old!r} in {method_name}, found {body.count(old)}"
        )
    start = source.index(body)
    mutated_body = body.replace(old, new, 1)
    return source[:start] + mutated_body + source[start + len(body) :]


def privacy_activation_call_graph_failures(source: str) -> list[str]:
    """Return fail-closed violations in the live privacy and activation graph."""
    failures: list[str] = []

    def body(method_name: str, *, occurrence: int | None = None) -> str:
        try:
            return dart_method_body(source, method_name, occurrence=occurrence)
        except AssertionError as error:
            failures.append(str(error))
            return ""

    def require_call(caller: str, callee: str) -> None:
        caller_body = body(caller)
        caller_code = normalize_whitespace(dart_code_mask(caller_body))
        if caller_body and f"{callee}(" not in caller_code:
            failures.append(f"{caller} must call {callee}")

    init_body = body("initState", occurrence=0)
    if (
        init_body
        and "_initializeLocalSecurityThenPrivacyConsent("
        not in normalize_whitespace(dart_code_mask(init_body))
    ):
        failures.append(
            "dashboard initState must call _initializeLocalSecurityThenPrivacyConsent"
        )
    require_call(
        "_initializeLocalSecurityThenPrivacyConsent",
        "_initializePrivacyConsentGate",
    )
    require_call(
        "_initializePrivacyConsentGate",
        "_startPostPrivacyConsentInitialization",
    )
    # Round UI (8a26835) routes startup discovery through _sharedNodeDiscovery,
    # which coalesces concurrent walks. It must start nothing but the guarded
    # sink, and no other code may publish the walk it hands to callers.
    require_call(
        "_startPostPrivacyConsentInitialization",
        "_sharedNodeDiscovery",
    )
    require_call("_sharedNodeDiscovery", "_fetchAvailableNodes")
    shared_discovery = body("_sharedNodeDiscovery")
    if shared_discovery:
        shared_code = normalize_whitespace(dart_code_mask(shared_discovery))
        if "walk = _fetchAvailableNodes()" not in shared_code:
            failures.append(
                "_sharedNodeDiscovery must publish only the guarded "
                "_fetchAvailableNodes walk"
            )
        wrapper_start = source.index(shared_discovery)
        wrapper_end = wrapper_start + len(shared_discovery)
        for publish in re.finditer(
            r"\b_sharedNodeDiscoveryWalk\s*(?:\?\?)?=(?!=)\s*([^;]*);",
            dart_code_mask(source),
        ):
            if not wrapper_start <= publish.start() < wrapper_end or (
                publish.group(1).strip() not in ("walk", "null")
            ):
                failures.append(
                    "only _sharedNodeDiscovery may assign _sharedNodeDiscoveryWalk, "
                    "and only its guarded walk or null"
                )
                break

    legal_guard = body("_ensureLegalAcceptanceForActivation")
    if legal_guard:
        normalized = normalize_whitespace(dart_code_mask(legal_guard))
        privacy_guard = "if (!await _ensurePrivacyConsentForNetworkUse()) return null;"
        if privacy_guard not in normalized:
            failures.append(
                "_ensureLegalAcceptanceForActivation must fail closed on privacy consent"
            )
        privacy_position = normalized.find(privacy_guard)
        legal_fetch_position = normalized.find("_loadLegalDocumentForAcceptance(")
        if legal_fetch_position < 0:
            failures.append(
                "_ensureLegalAcceptanceForActivation must load the legal document"
            )
        elif privacy_position < 0 or privacy_position > legal_fetch_position:
            failures.append("privacy consent must precede legal-document network use")

    activation_callers = (
        "_loginWithAccountNumber",
        "_loginWithFreeAccess",
        "_refreshFreeVpnConfig",
        "_refreshVpnConfigForCurrentSelection",
    )
    for caller in activation_callers:
        caller_body = normalize_whitespace(dart_code_mask(body(caller)))
        privacy_call = "_ensurePrivacyConsentForNetworkUse("
        legal_call = "_ensureLegalAcceptanceForActivation("
        if privacy_call not in caller_body:
            failures.append(f"{caller} must call _ensurePrivacyConsentForNetworkUse")
        if legal_call not in caller_body:
            failures.append(f"{caller} must call _ensureLegalAcceptanceForActivation")
        if (
            privacy_call in caller_body
            and legal_call in caller_body
            and caller_body.index(privacy_call) > caller_body.index(legal_call)
        ):
            failures.append(f"{caller} must obtain privacy consent before legal consent")

    connect_body = normalize_whitespace(
        dart_code_mask(body("_connectWithSmartProtocol"))
    )
    for marker in (
        "Platform.isAndroid",
        "!_hasCurrentAndroidVpnServiceDisclosureConsent",
        "_ensureLegalAcceptanceForActivation(",
        "if (legalFields == null || transitionCancelled()) return;",
    ):
        if marker not in connect_body:
            failures.append(
                f"_connectWithSmartProtocol is missing Android disclosure gate: {marker}"
            )
    legal_position = connect_body.find("_ensureLegalAcceptanceForActivation(")
    tunnel_start_position = connect_body.find("_startTunnelCandidate(")
    if tunnel_start_position < 0:
        failures.append("_connectWithSmartProtocol must reach the tunnel-start funnel")
    elif legal_position < 0 or legal_position > tunnel_start_position:
        failures.append("Android disclosure recheck must precede the tunnel-start funnel")

    return failures


def normalize_whitespace(text: str) -> str:
    # `dart format` is free to rewrap long argument lists across lines, so
    # marker checks against source text must not depend on exact line breaks.
    return re.sub(r"\s+", " ", text)


class PrivacyConsentContractTests(unittest.TestCase):
    def test_init_is_local_only_until_privacy_acceptance(self) -> None:
        body = dart_method_body(CLIENT, "initState", occurrence=0)
        # M-14: initState now runs local-only security (the Apple legacy
        # secret->Keychain migration, which needs no network or consent)
        # before the privacy gate, via this wrapper. The wrapper still hands
        # off to _initializePrivacyConsentGate, so network/sensitive init
        # stays gated behind privacy acceptance -- verified below by the
        # forbidden-call list, and by the Dart secure_sensitive_state
        # contract test for the migration-before-gate ordering.
        self.assertIn("_initializeLocalSecurityThenPrivacyConsent", body)
        for forbidden in (
            "_loadDeviceHardwareDetails",
            "_determineSecurityOnboardingLayer",
            "_startStatusHeartbeat",
            "_fetchAvailableNodes",
            "_sharedNodeDiscovery",
            "_fetchPreVpnCountryCode",
            "_retryPendingLogout",
            "_maybeRunAppleLiveTunnelSmoke",
            "_maybeRunSpeedTestSmoke",
            "_requestAndroidBatteryExemptionAfterTunnelCommit",
        ):
            self.assertNotIn(forbidden, body)

    def test_post_consent_coordinator_contains_sensitive_initialization(self) -> None:
        body = dart_method_body(CLIENT, "_startPostPrivacyConsentInitialization")
        self.assertIn("if (!_privacyConsentGranted", body)
        for required in (
            "_loadDeviceHardwareDetails",
            "_determineSecurityOnboardingLayer",
            "_startStatusHeartbeat",
            "_sharedNodeDiscovery",
            "_retryPendingLogout",
            "_maybeRunAppleLiveTunnelSmoke",
            "_maybeRunSpeedTestSmoke",
        ):
            self.assertIn(required, body)
        # 8a26835: node discovery reaches the guarded sink through the
        # coalescing wrapper (see privacy_activation_call_graph_failures).
        self.assertIn(
            "_fetchAvailableNodes()",
            dart_method_body(CLIENT, "_sharedNodeDiscovery"),
        )
        self.assertNotIn("_requestAndroidBatteryExemptionAfterTunnelCommit", body)
        self.assertNotIn("requestBatteryExemption", body)

    def test_decline_is_reopenable_and_records_only_protected_local_choice(self) -> None:
        self.assertIn("'Not now'", CLIENT)
        # b748339 shortened the visible label to 'Privacy Policy'; the
        # pre-consent meaning moved to the semantics label. After 'Not now'
        # the same rendered action must reopen the consent prompt.
        action = dart_arrow_member_body(CLIENT, "_buildPrivacyPolicyAction")
        self.assertIn(
            "label: _privacyConsentGranted ? 'View bundled Privacy Policy' "
            ": 'Review and accept bundled Privacy Policy'",
            normalize_whitespace(action),
        )
        self.assertIn(
            "_showPrivacyPolicyDialog(requireConsent: !_privacyConsentGranted)",
            normalize_whitespace(dart_code_mask(action)),
        )
        self.assertGreaterEqual(
            dart_code_mask(CLIENT).count("_buildPrivacyPolicyAction()"),
            2,
            "the reopenable privacy action must be rendered, not only declared",
        )
        self.assertIn("_mutateVpnRuntimeSettings((data)", CLIENT)
        self.assertIn("privacy_policy_accepted_version", CLIENT)
        self.assertIn("_privacyConsentPromptOpen", CLIENT)

    def test_sensitive_entry_points_are_guarded(self) -> None:
        guarded_methods = (
            "_fetchPreVpnCountryCode",
            "_fetchAvailableNodes",
            "_fetchLiveNetworkIp",
            "_loadDeviceHardwareDetails",
            "_determineSecurityOnboardingLayer",
            "_requestAndroidBatteryExemptionAfterTunnelCommit",
        )
        for method_name in guarded_methods:
            fragment = dart_method_body(CLIENT, method_name)[:420]
            self.assertIn("_privacyConsentGranted", fragment, method_name)
        self.assertIn(
            "if (!await _ensurePrivacyConsentForNetworkUse()) return;",
            dart_method_body(CLIENT, "_loginWithAccountNumber"),
        )

    def test_android_vpn_service_disclosure_is_versioned_and_migrated(self) -> None:
        body = dart_method_body(CLIENT, "_ensureLegalAcceptanceForActivation")
        normalized_body = normalize_whitespace(body)
        for marker in (
            "hasCurrentAndroidVpnServiceDisclosure",
            "_hasCurrentAndroidVpnServiceDisclosureConsent",
            "!hasCurrentAndroidVpnServiceDisclosure",
            "androidVpnServiceDisclosureConsentVersion:",
        ):
            self.assertIn(normalize_whitespace(marker), normalized_body)
        self.assertGreaterEqual(
            CLIENT.count("android_vpn_service_disclosure_consent_version"),
            2,
            "the current disclosure version must be persisted and restored",
        )
        for marker in (
            "_androidVpnServiceDisclosureAcceptedAtUtc",
            "DateTime.now().toUtc().toIso8601String()",
            "android_vpn_service_disclosure_accepted_at",
            "androidVpnServiceDisclosureAcceptedAtUtc:",
        ):
            self.assertIn(marker, CLIENT)
        self.assertGreaterEqual(
            CLIENT.count("android_vpn_service_disclosure_accepted_at"),
            3,
            "the separate disclosure timestamp must be sent, persisted, and restored",
        )
        for marker in (
            'ANDROID_VPN_SERVICE_DISCLOSURE_VERSION = "2026-08-31.v3"',
            "accepted_android_vpn_service_disclosure INTEGER DEFAULT 0",
            "android_vpn_service_disclosure_accepted_at TEXT DEFAULT ''",
            'getattr(payload, "android_vpn_service_disclosure_accepted_at"',
            'row.get("android_vpn_service_disclosure_accepted_at")',
        ):
            self.assertIn(marker, CONTROL)

    def test_live_activation_call_graph_is_consent_gated(self) -> None:
        self.assertEqual(privacy_activation_call_graph_failures(CLIENT), [])

    def test_hostile_call_graph_renames_fail_closed(self) -> None:
        mutations = {
            "post-consent node fetch renamed away from the guarded sink":
                replace_in_dart_method(
                    CLIENT,
                    "_startPostPrivacyConsentInitialization",
                    "_sharedNodeDiscovery()",
                    "_sharedNodeDiscoveryWithoutConsent()",
                ),
            "shared discovery rewired around the guarded sink":
                replace_in_dart_method(
                    CLIENT,
                    "_sharedNodeDiscovery",
                    "_fetchAvailableNodes()",
                    "_fetchAvailableNodesWithoutConsent()",
                ),
            "shared discovery walk published from outside the wrapper":
                replace_in_dart_method(
                    CLIENT,
                    "_startPostPrivacyConsentInitialization",
                    "unawaited(_sharedNodeDiscovery());",
                    "_sharedNodeDiscoveryWalk = _fetchNodesWithoutConsent(); "
                    "unawaited(_sharedNodeDiscovery());",
                ),
            "shared discovery publishes a walk other than the guarded one":
                replace_in_dart_method(
                    CLIENT,
                    "_sharedNodeDiscovery",
                    "_sharedNodeDiscoveryWalk = walk;",
                    "_sharedNodeDiscoveryWalk = _fetchNodesWithoutConsent();",
                ),
            "paid activation rewired around the legal gate": replace_in_dart_method(
                CLIENT,
                "_loginWithAccountNumber",
                "_ensureLegalAcceptanceForActivation(rawToken)",
                "_acceptRenamedLegalContract(rawToken)",
            ),
            "legal fetch guard renamed away": replace_in_dart_method(
                CLIENT,
                "_ensureLegalAcceptanceForActivation",
                "_ensurePrivacyConsentForNetworkUse()",
                "_assumePrivacyConsentForNetworkUse()",
            ),
            "pre-tunnel Android disclosure recheck renamed away":
                replace_in_dart_method(
                    CLIENT,
                    "_connectWithSmartProtocol",
                    "_ensureLegalAcceptanceForActivation(",
                    "_acceptRenamedLegalContract(",
                ),
        }
        for label, mutated_source in mutations.items():
            with self.subTest(label=label):
                self.assertTrue(
                    privacy_activation_call_graph_failures(mutated_source),
                    "a live call-site rename left the old guarded method in "
                    "place and must not create a false green",
                )

    def test_android_identifier_runtime_and_disclosure_are_consistent(self) -> None:
        # The app does not touch the Android hardware identifier ANYWHERE.
        # Device identity is the random per-install ID, which is what every
        # disclosure describes. Previously the two agreed only by accident: the
        # native side hashed ANDROID_ID into "device_id_hash" while Dart read a
        # key named "android_id" that the map never contained, so the hashed
        # path was dead. Both sides are now deleted, making the agreement
        # deliberate -- and closing the trap where "fixing" the key name would
        # silently change device identity for every existing install, trip the
        # three-device limit, and invalidate the published disclosures.
        #
        # Assert that as a zero-occurrence scan rather than trusting the two
        # call sites, so the identifier cannot reappear anywhere in the shipping
        # Android or Dart source. The only tolerated mentions are guardrail
        # comments saying not to reintroduce it; anything on a code line fails.
        references = hardware_identifier_references()
        for relative_path, number, line in references:
            self.assertTrue(
                line.startswith("//"),
                f"{relative_path}:{number} names the Android hardware "
                f"identifier outside a comment, so the app may be reading it "
                f"again: {line}",
            )
        self.assertEqual(
            {relative_path for relative_path, _, _ in references},
            {"android/app/src/main/kotlin/org/winsvpn/app/MainActivity.kt"},
            "only MainActivity's do-not-reintroduce guardrail comment may "
            "mention the Android hardware identifier",
        )
        # The native map must expose device_model/app_version and nothing
        # identifier-shaped; device_id_hash had no consumer and is gone.
        self.assertIn('"device_model" to', ANDROID)
        self.assertIn('"app_version" to BuildConfig.VERSION_NAME', ANDROID)
        self.assertNotIn("device_id_hash", ANDROID)
        self.assertNotIn("deviceIdHash", ANDROID)
        self.assertNotIn("device_id_hash", CLIENT)
        self.assertNotIn("_hardwareIdHash", CLIENT)
        self.assertIn("_appScopedDeviceId", CLIENT)
        self.assertIn("_loadOrCreateInstallId", CLIENT)
        for marker in (
            "Device or other ID",
            "app-install identifier",
            "not derived from a device hardware identifier",
            "not used for ads or tracking",
            "deleted or overwritten",
        ):
            self.assertIn(marker, CLIENT)
            self.assertIn(marker, CONTROL)
        # No published disclosure may claim the raw hardware ID is transmitted.
        for document in (CLIENT, CONTROL, WEB):
            self.assertNotIn("Settings.Secure.ANDROID_ID", document)
        self.assertIn("linked to the account", CLIENT)
        self.assertIn("account-linked", CONTROL)

    def test_versions_and_canonical_privacy_route_match(self) -> None:
        versions = {
            re.search(r"_legalDocumentVersion = '([^']+)'", CLIENT).group(1),
            re.search(r"Version (\d{4}-\d{2}-\d{2}\.v\d+)", WEB).group(1),
            re.search(r'LEGAL_DOCUMENT_VERSION_DEFAULT="([^"]+)"', CONTROL).group(1),
        }
        self.assertEqual(versions, {"2026-08-31.v4"})
        self.assertIn("https://www.winsvpn.org/privacy/", CLIENT)
        self.assertIn("https://www.winsvpn.org/privacy/", CONTROL)
        self.assertIn("https://www.winsvpn.org/privacy/", PLAY)
        self.assertIn("/privacy /privacy/index.html 200", REDIRECTS)
        self.assertIn('["/privacy/", "/privacy/"]', WORKER)
        self.assertNotIn("/privacy /index.html 200", REDIRECTS)
        self.assertNotIn("/privacy/ /index.html 200", REDIRECTS)
        self.assertIn("dedicatedDocumentRoutes.get(url.pathname)", WORKER)
        privacy_page = (ROOT / "web" / "privacy" / "index.html").read_text(encoding="utf-8")
        self.assertIn('<h1 id="privacy-policy">Privacy Policy</h1>', privacy_page)

    def test_play_data_safety_matrix_covers_actual_fields(self) -> None:
        for marker in (
            "Data Safety Matrix",
            "Device or other IDs",
            "User IDs",
            "Email address",
            "Approximate location",
            "Purchase history",
            "Installed apps",
            "Browsing history, DNS query history",
            "Play SDK Index/data-disclosure report",
        ):
            self.assertIn(marker, PLAY)


if __name__ == "__main__":
    unittest.main()
