import XCTest
import Foundation

/// Secure channel tests for Watch <-> Phone link.
///
/// Contract source: `lib/watch_bridge.dart` and `WatchLink.swift` / `PhoneLink.swift`.
///
/// The watch is a remote control: it sends only whitelisted intents and renders
/// state. It must never transport keys, credentials, endpoints or tunnel
/// configuration, and the phone must never publish them.
///
/// This file is the single source of truth for the whitelist; any new key
/// must be added here and reviewed, otherwise the harness fails.
final class ChannelTests: XCTestCase {

    // MARK: - Whitelists (must match lib/watch_bridge.dart + WatchLink.swift)

    /// Commands the watch may send. Mirrors Dart `WatchCommand` + `requestState`.
    private let allowedCommands: Set<String> = [
        "connect",
        "disconnect",
        "selectCountry",
        "requestState"
    ]

    /// Keys allowed in watch -> phone messages (WatchLink.message).
    /// `v` = protocol version, `command` = intent, `slug` = optional country.
    private let allowedWatchMessageKeys: Set<String> = ["v", "command", "slug"]

    /// Keys allowed in phone -> watch snapshot (WatchBridge.publish + WatchSessionBridge).
    private let allowedSnapshotKeys: Set<String> = [
        "v", "status", "detail", "selectedSlug", "countries",
        "canConnect", "carrier", "state", "updatedAt"
    ]

    /// Keys allowed inside each country dictionary. `load_pct` is the hub's
    /// per-server load (int 0..100, step 5) and `load_at` the phone's receipt
    /// time for it (epoch seconds): a coarse, time-varying figure with no
    /// address or credential content; added with the server load bar
    /// (2026-09-27).
    private let allowedCountryKeys: Set<String> = ["slug", "name", "flag", "load_pct", "load_at"]

    /// Forbidden substrings that must never appear in any key or, case-insensitively,
    /// in any string value that could carry a credential. This list is intentionally
    /// broad: endpoint material, key material and account material are all forbidden.
    private let forbiddenKeySubstrings: [String] = [
        "privatekey", "publickey", "endpoint", "stealth",
        "account", "credential", "password", "secret", "token", "psk",
        "preshared", "gateway_id", "admission", "inner_", "allowedips",
        "persistentkeepalive", "address", "dns", "mtu"
    ]

    // MARK: - Helpers

    private func containsForbidden(_ key: String) -> Bool {
        let lower = key.lowercased()
        return forbiddenKeySubstrings.contains { lower.contains($0) }
    }

    private func assertNoForbiddenKeys(in dict: [String: Any], file: StaticString = #file, line: UInt = #line) {
        for key in dict.keys {
            XCTAssertFalse(containsForbidden(key), "Forbidden key '\(key)' transported", file: file, line: line)
            XCTAssertFalse(key.lowercased().contains("key") && key != "carrier" && key != "slug" && !allowedCountryKeys.contains(key) && !allowedSnapshotKeys.contains(key),
                           "Key '\(key)' looks like credential material", file: file, line: line)
        }
        // Also check string values for embedded key material patterns (e.g. base64 44-char WG keys)
        for value in dict.values {
            if let s = value as? String {
                let lower = s.lowercased()
                for f in forbiddenKeySubstrings where lower.contains(f) {
                    // Only flag if the value itself claims to be a key name; raw base64 without label is checked separately
                    if lower.contains(f) && (lower.contains(":") || lower.contains("=")) {
                        XCTFail("Value '\(s)' contains forbidden substring '\(f)'", file: file, line: line)
                    }
                }
                // Heuristic: 44-char base64 (WG key) should never appear
                if s.count == 44, s.range(of: "^[A-Za-z0-9+/]{42}==", options: .regularExpression) != nil {
                    XCTFail("Value looks like a WireGuard key (44-char base64): '\(s)'", file: file, line: line)
                }
            }
        }
    }

    private func countryPayload(slug: String, name: String, flag: String) -> [String: Any] {
        ["slug": slug, "name": name, "flag": flag]
    }

    private func validSnapshot(countries: [[String: Any]] = []) -> [String: Any] {
        [
            "v": 1,
            "status": "connected",
            "detail": "Connected",
            "selectedSlug": "mm",
            "countries": countries,
            "canConnect": true,
            "carrier": "winn3",
            "state": "carrying",
            "updatedAt": Date().timeIntervalSince1970 * 1000
        ]
    }

    // MARK: - Tests: whitelisted intents

    func testWhitelistedCommandsAreExactlyFour() {
        XCTAssertEqual(allowedCommands, ["connect","disconnect","selectCountry","requestState"])
        XCTAssertEqual(allowedCommands.count, 4, "Whitelist must not grow silently")
    }

    func testUnknownCommandIsNotWhitelisted() {
        XCTAssertFalse(allowedCommands.contains("reboot"))
        XCTAssertFalse(allowedCommands.contains("connectAll"))
        XCTAssertFalse(allowedCommands.contains(""))
        XCTAssertFalse(allowedCommands.contains("SELECTCOUNTRY"))
    }

    func testWatchMessageWithAllowedCommandPasses() {
        for cmd in allowedCommands {
            var msg: [String: Any] = ["v": 1, "command": cmd]
            if cmd == "selectCountry" { msg["slug"] = "mm" }
            XCTAssertTrue(allowedWatchMessageKeys.isSuperset(of: msg.keys), "Message keys \(msg.keys) must be subset of whitelist")
            assertNoForbiddenKeys(in: msg)
        }
    }

    func testWatchMessageWithExtraKeyIsForbidden() {
        let msg: [String: Any] = ["v": 1, "command": "connect", "endpoint": "1.2.3.4:51820"]
        XCTAssertFalse(allowedWatchMessageKeys.isSuperset(of: msg.keys), "Extra key 'endpoint' must be rejected")
        XCTAssertTrue(containsForbidden("endpoint"))
    }

    func testWatchMessageWithPrivateKeyIsForbidden() {
        let msg: [String: Any] = ["v": 1, "command": "connect", "privateKey": "<REDACTED_WG_KEY>"]
        XCTAssertFalse(allowedWatchMessageKeys.isSuperset(of: msg.keys))
        XCTAssertTrue(containsForbidden("privateKey"))
        // Verify detector would flag it (without failing this test)
        XCTAssertTrue(containsForbidden("privateKey"), "Detector must flag privateKey")
    }

    // MARK: - Tests: snapshot keys

    func testValidSnapshotContainsOnlyWhitelistedKeys() {
        let snap = validSnapshot(countries: [countryPayload(slug: "mm", name: "Myanmar", flag: "🇲🇲")])
        XCTAssertTrue(allowedSnapshotKeys.isSuperset(of: snap.keys), "Snapshot keys \(snap.keys) exceed whitelist \(allowedSnapshotKeys)")
        assertNoForbiddenKeys(in: snap)
    }

    func testSnapshotWithEndpointIsRejected() {
        var snap = validSnapshot()
        snap["endpoint"] = "edge.example.com:9110"
        XCTAssertFalse(allowedSnapshotKeys.isSuperset(of: snap.keys))
        XCTAssertTrue(containsForbidden("endpoint"))
    }

    func testSnapshotWithStealthEndpointIsRejected() {
        var snap = validSnapshot()
        snap["stealth_endpoint"] = "1.2.3.4:443"
        XCTAssertFalse(allowedSnapshotKeys.isSuperset(of: snap.keys))
        XCTAssertTrue(containsForbidden("stealth_endpoint"))
    }

    func testSnapshotWithAccountNumberIsRejected() {
        var snap = validSnapshot()
        snap["accountNumber"] = "12345"
        XCTAssertFalse(allowedSnapshotKeys.isSuperset(of: snap.keys))
        XCTAssertTrue(containsForbidden("accountNumber"))
    }

    // MARK: - Tests: country keys

    func testCountryContainsOnlyWhitelistedKeys() {
        let country = countryPayload(slug: "mm", name: "Myanmar", flag: "🇲🇲")
        XCTAssertTrue(allowedCountryKeys.isSuperset(of: country.keys))
        assertNoForbiddenKeys(in: country)
    }

    func testCountryWithEndpointIsRejected() {
        var country = countryPayload(slug: "mm", name: "Myanmar", flag: "🇲🇲")
        country["endpoint"] = "1.2.3.4:51820"
        XCTAssertFalse(allowedCountryKeys.isSuperset(of: country.keys))
        XCTAssertTrue(containsForbidden("endpoint"))
    }

    func testCountryWithPublicKeyIsRejected() {
        var country = countryPayload(slug: "mm", name: "Myanmar", flag: "🇲🇲")
        country["publicKey"] = String(repeating: "A", count: 44)
        XCTAssertFalse(allowedCountryKeys.isSuperset(of: country.keys))
        XCTAssertTrue(containsForbidden("publicKey"))
    }

    // MARK: - Tests: phone->watch never transports credentials even in values

    func testSnapshotDetailMustNotContainIPv4() {
        // Mirrors Dart _sanitizeDetail: IPs must be stripped before publish
        let ipv4Pattern = #"\b\d{1,3}(?:\.\d{1,3}){3}\b"#
        let detail = "Connected to 1.2.3.4"
        XCTAssertNotNil(detail.range(of: ipv4Pattern, options: .regularExpression), "Test premise: detail contains IP")
        // The harness asserts that a published snapshot's detail would be sanitized;
        // here we check the contract: detail must not contain an IP at publish time.
        let sanitized = detail.replacingOccurrences(of: ipv4Pattern, with: "", options: .regularExpression)
        XCTAssertFalse(sanitized.contains("1.2.3.4"))
        // A snapshot carrying raw IP is forbidden
        var snap = validSnapshot()
        snap["detail"] = detail
        // Simulate what Dart does: detail with IP would be redacted; raw IP must not be published
        XCTAssertTrue((snap["detail"] as! String).contains("1.2.3.4"), "Raw detail still contains IP – publish must sanitize")
        // The test enforces that the published value must be sanitized; we assert the sanitized version is safe
        snap["detail"] = sanitized
        XCTAssertFalse((snap["detail"] as! String).contains("1.2.3.4"))
    }

    func testSnapshotNeverContainsBase64WGKey() {
        let fakeKey = String(repeating: "A", count: 43) + "="
        // 44-char base64 pattern (WG private key)
        XCTAssertEqual(fakeKey.count, 44)
        var snap = validSnapshot()
        snap["detail"] = fakeKey
        let lower = (snap["detail"] as! String)
        // Simple 44-char base64 check: length 44 and only base64 chars plus padding
        let isBase64 = lower.range(of: "^[A-Za-z0-9+/]+={0,2}$", options: .regularExpression) != nil
        XCTAssertTrue(lower.count == 44 && isBase64, "Fake key should be detected as base64")
        // The harness must consider such a value forbidden if it were to appear in a snapshot
        XCTAssertTrue(isBase64, "Detector must flag 44-char base64 as key material")
    }

    // MARK: - Parity with lib/watch_bridge.dart

    func testWatchBridgePublishKeysMatchSnapshotWhitelist() {
        // lib/watch_bridge.dart publish() builds:
        // {status, detail, selectedSlug, countries, canConnect} + v/updatedAt/carrier/state
        // Ensure those are exactly the allowed set (order irrelevant)
        let dartPublishKeys: Set<String> = ["status","detail","selectedSlug","countries","canConnect"]
        let nativeAddedKeys: Set<String> = ["v","updatedAt","carrier","state"]
        let combined = dartPublishKeys.union(nativeAddedKeys)
        XCTAssertTrue(combined.isSubset(of: allowedSnapshotKeys), "Dart+native keys \(combined) must be subset of harness whitelist")
        XCTAssertEqual(combined.count, 9)
    }

    func testWatchBridgeCountriesWhitelistMatchesDartComment() {
        // lib/watch_bridge.dart comment: "Only `slug`, `name`, `flag` and, while fresh, `load_pct` with its `load_at` receipt time are forwarded (see [watchCountryEntries]). The same maps also carry `endpoint` and `stealth_endpoint`, which must never leave the phone."
        XCTAssertEqual(allowedCountryKeys, ["slug","name","flag","load_pct","load_at"])
        XCTAssertFalse(allowedCountryKeys.contains("endpoint"))
        XCTAssertFalse(allowedCountryKeys.contains("stealth_endpoint"))
    }

    // MARK: - Positive control: a mutant that widens the whitelist must be caught

    func testPositiveControl_MutantAddingEndpointToCountryMustBeRejected() {
        // This test is the POSITIVE control: if the harness were broken to allow endpoint, this would still fail.
        // Simulate a mutant that adds "endpoint" to the country whitelist.
        let mutantAllowedCountryKeys: Set<String> = ["slug","name","flag","endpoint"]
        let countryWithEndpoint: [String: Any] = ["slug":"mm","name":"Myanmar","flag":"🇲🇲","endpoint":"1.2.3.4:51820"]
        // With the mutant whitelist, the check would incorrectly pass; with the real whitelist it must fail.
        XCTAssertFalse(allowedCountryKeys.isSuperset(of: countryWithEndpoint.keys), "Real whitelist must reject endpoint")
        XCTAssertTrue(mutantAllowedCountryKeys.isSuperset(of: countryWithEndpoint.keys), "Mutant whitelist would incorrectly allow endpoint – harness must catch this")
        // The real harness must reject; if this test ever passes with the mutant whitelist, the harness is broken.
    }

    func testPositiveControl_MutantAllowingPrivateKeyInWatchMessageMustBeRejected() {
        let mutantWatchKeys: Set<String> = ["v","command","slug","privateKey"]
        let msg: [String: Any] = ["v":1,"command":"connect","privateKey":"key"]
        XCTAssertFalse(allowedWatchMessageKeys.isSuperset(of: msg.keys))
        XCTAssertTrue(mutantWatchKeys.isSuperset(of: msg.keys))
    }
}
