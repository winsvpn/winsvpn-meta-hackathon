import Foundation
import Security

// Shared Keychain-backed helper for the `secureStateRead` / `secureStateWrite`
// / `secureStateDelete` Flutter method-channel handlers (see
// WinsAppleTunnelBridge in AppDelegate.swift and WinsMacOSTunnelBridge in
// MainFlutterWindow.swift). Both host-app bridges call into this single
// implementation instead of duplicating Keychain logic.
//
// THIS STORE IS NOT APP-LOCAL, AND OMITTING kSecAttrAccessGroup NEVER MADE IT
// SO. This comment used to describe the store as app-local on the grounds that
// it names no shared Keychain access group. That was wrong, and the mistake was
// load-bearing: it is what let several lanes believe only a COLLIDING INSTALL
// could endanger the owner's credentials. Measured 2026-08-08 (see
// docs/handoff/KEYCHAIN_ACCESS_GROUP_RISK_20260808.md):
//
//   * There is no "no access group" item. A generic-password add from a process
//     with no keychain-access-groups entitlement returns errSecMissingEntitlement
//     (-34018) on both the iOS keychain and the macOS data-protection keychain.
//     Every item must resolve to some access group.
//   * Which one is fixed by Apple, in SecItem.h: "The application-identifier
//     entitlement contains the application's single access group, unless there
//     is a keychain-access-groups entitlement present. The latter has as its
//     value a list of access groups; the first item in this list is the default
//     access group." So the bundle id does NOT scope these items once that
//     entitlement exists.
//   * Every target here -- ios/Runner, ios/PacketTunnel, macos/Runner,
//     macos/PacketTunnel, in Debug and in Release -- declares exactly one entry,
//     $(AppIdentifierPrefix)org.winsvpn.shared. On the signed build that expands
//     to 5YT8H4U72M.org.winsvpn.shared.
//
// So these items land in the SHARED group, the same one WinsClientKeyStore uses.
// The service and account names below are compile-time constants that do not
// mention the bundle id, so a build under a different bundle id (the coexisting
// org.winsvpn.app.debug lab build) addressed the SAME Keychain rows as the
// shipping app: same class, same service, same account, same access group. A lab
// PIN enrolment overwrote the owner's production PIN, and a lab
// client_keypair.json write could replace their WireGuard client identity -- with
// no uninstall involved, simply by running. write() adds and then updates on
// duplicate, so this never failed loudly; it succeeded quietly.
//
// Two changes make the separation structural rather than conventional:
//   1. the access group is now stated EXPLICITLY rather than inherited from
//      entitlement order, so it cannot drift if that array is ever reordered; and
//   2. the service name is scoped by build configuration, so a DEBUG build
//      cannot name the production rows at all. Release is byte-for-byte the
//      service string it has always been -- the owner's enrolled PIN and stored
//      keypair stay exactly where they are and are not migrated or touched.
//
// apple_keychain_access_group_isolation_test.dart pins all of this, including
// that any FUTURE generic-password query added to these files carries an access
// group.
//
// Errors are thrown as NSErrors in the "org.winsvpn." domain family (matching
// WinsClientKeyStore/WinsTunnelSecretStore) so WinsTunnelDiagnostics treats
// their messages as already-controlled/safe instead of redacting them.
enum WinsSecureStateStore {
  // Release keeps the historical service string EXACTLY. Changing it would
  // orphan the owner's already-enrolled PIN and their stored client keypair,
  // which is a worse outcome than the hazard being closed here.
  //
  // DEBUG gets its own service, which is what actually stops a lab build from
  // reaching production rows: kSecAttrService is part of a generic password's
  // primary key, and `#if DEBUG` is decided by the compiler, not by a caller
  // remembering to pass something. org.winsvpn.app.debug -- the coexisting lab
  // bundle id -- is defined in the Debug configuration only, so this scoping
  // lines up exactly with the builds that can carry it.
  //
  // Consequence, and it is intended: a debug build sees an EMPTY store and
  // behaves like a fresh install. It will ask for PIN enrolment rather than
  // silently adopting -- or overwriting -- the owner's.
  #if DEBUG
    private static let service = "org.winsvpn.app.secure-state.debug"
  #else
    private static let service = "org.winsvpn.app.secure-state"
  #endif
  static let nameNotAllowedCode = 3301
  static let corruptStoredValueCode = 3302

  // Fixed allowlist: only names the app actually needs are ever accepted.
  // Every other name — including anything an untrusted or future Dart-side
  // caller might pass — is rejected outright rather than silently namespaced
  // or truncated.
  //
  // These must be byte-for-byte the same strings Dart actually sends, which
  // is the full _sensitiveStateFileNames set in lib/main.dart (each one a
  // legacy plaintext-file name carried forward as the cross-platform wire
  // name for this store, matching Android's SecureFileStore and Linux's
  // libsecret-backed store — see linux_secure_store_native_contract_test
  // .dart, which pins the same names on that side). Previously this set
  // held "cleaned up" bare names ("user_pin", "vpn_settings",
  // "pending_logout") with no file extension, which never matched anything
  // Dart actually sent — every secureStateRead/Write/Delete call on iOS and
  // macOS was rejected by isNameAllowed() before ever reaching Keychain
  // (nameNotAllowedError, code 3301). That is what made the Privacy Policy
  // consent write (name "vpn_settings.txt") — and, silently, the PIN and
  // pending-logout writes — fail on every launch. See the dated handoff doc
  // under docs/handoff/ for the full incident writeup.
  private static let allowedNames: Set<String> = [
    "client_keypair.json",
    "calc_session.json",
    "calc_state.json",
    "install_id.txt",
    "node_cache.json",
    "pending_logout.json",
    "user_pin.txt",
    "vpn_config.txt",
    "vpn_settings.txt",
    "wins_vpn_restart_config.conf",
    // The winn/3 static identity of this device (lib/winn3_device_key.dart).
    "winn3_keypair.json",
    "direct_udp_transport_memory.json"
  ]

  static func isNameAllowed(_ name: String) -> Bool {
    allowedNames.contains(name)
  }

  static func read(name: String) throws -> String? {
    guard isNameAllowed(name) else {
      throw nameNotAllowedError()
    }

    var query = baseQuery(name: name)
    query[kSecReturnData as String] = kCFBooleanTrue
    query[kSecMatchLimit as String] = kSecMatchLimitOne

    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    if status == errSecItemNotFound {
      return nil
    }
    guard status == errSecSuccess else {
      throw keychainError(status, action: "read secure state")
    }
    guard let data = item as? Data, let value = String(data: data, encoding: .utf8) else {
      throw NSError(
        domain: "org.winsvpn.SecureStateStore",
        code: corruptStoredValueCode,
        userInfo: [NSLocalizedDescriptionKey: "Stored secure state value is corrupt."]
      )
    }
    return value
  }

  static func write(name: String, value: String) throws {
    guard isNameAllowed(name) else {
      throw nameNotAllowedError()
    }
    guard let valueData = value.data(using: .utf8) else {
      throw NSError(
        domain: "org.winsvpn.SecureStateStore",
        code: corruptStoredValueCode,
        userInfo: [NSLocalizedDescriptionKey: "Secure state value could not be encoded."]
      )
    }

    let key = baseQuery(name: name)
    var attributes: [String: Any] = [
      kSecValueData as String: valueData
    ]
    #if os(iOS) || os(macOS)
    attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    #endif

    var item = key
    attributes.forEach { item[$0.key] = $0.value }

    // Add first and update-on-duplicate rather than delete-then-add: Keychain
    // has no atomic upsert, but a crash, termination, or Keychain lock/quota
    // failure in the window between a delete and the following add would
    // otherwise lose the previous value outright (e.g. the PIN-attempt
    // ledger stored under "vpn_settings") with nothing left to read back.
    // Never delete an existing item as part of an ordinary write.
    let addStatus = SecItemAdd(item as CFDictionary, nil)
    if addStatus == errSecDuplicateItem {
      let updateStatus = SecItemUpdate(key as CFDictionary, attributes as CFDictionary)
      guard updateStatus == errSecSuccess else {
        // Never fall back to a plaintext file after a Keychain failure — the
        // caller must see this as a failed write, not lose the write silently.
        throw keychainError(updateStatus, action: "update secure state")
      }
    } else {
      guard addStatus == errSecSuccess else {
        // Never fall back to a plaintext file after a Keychain failure — the
        // caller must see this as a failed write, not lose the write silently.
        throw keychainError(addStatus, action: "write secure state")
      }
    }
  }

  static func delete(name: String) throws {
    guard isNameAllowed(name) else {
      throw nameNotAllowedError()
    }
    let status = SecItemDelete(baseQuery(name: name) as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw keychainError(status, action: "delete secure state")
    }
  }

  private static func nameNotAllowedError() -> NSError {
    NSError(
      domain: "org.winsvpn.SecureStateStore",
      code: nameNotAllowedCode,
      userInfo: [NSLocalizedDescriptionKey: "This secure state name is not allowed."]
    )
  }

  private static func baseQuery(name: String) -> [String: Any] {
    var query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: name,
      kSecAttrSynchronizable as String: kCFBooleanFalse as Any
    ]
    // STATED, not inherited. Leaving kSecAttrAccessGroup off does not make an
    // item app-local -- it silently adopts keychain-access-groups[0] (SecItem.h,
    // quoted in the type comment above). Naming the group here means these items
    // stay in the group they are already in even if that array is ever reordered
    // or extended, and it means the group is visible at the call site instead of
    // being an invisible consequence of an entitlements file.
    //
    // preferred() resolves from Info.plist's WinsAppleSharedKeychainAccessGroup,
    // which Xcode expands at build time (verified on the signed Release build:
    // 5YT8H4U72M.org.winsvpn.shared). It returns nil only if that key is missing
    // or still unexpanded, in which case the query is left as it always was and
    // the default applies -- the same group -- so this cannot strand an item.
    if let accessGroup = WinsKeychainAccessGroup.preferred() {
      query[kSecAttrAccessGroup as String] = accessGroup
    }
    #if os(macOS)
      query[kSecUseDataProtectionKeychain as String] = kCFBooleanTrue
    #endif
    return query
  }

  private static func keychainError(_ status: OSStatus, action: String) -> NSError {
    let statusMessage = SecCopyErrorMessageString(status, nil) as String?
    return NSError(
      domain: "org.winsvpn.SecureStateStore",
      code: Int(status),
      userInfo: [
        NSLocalizedDescriptionKey: "Could not \(action): \(statusMessage ?? "Keychain status \(status)")."
      ]
    )
  }
}
