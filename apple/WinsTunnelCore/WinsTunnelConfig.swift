import CryptoKit
import Darwin
import Foundation
import Security

struct WinsTunnelValidationError: LocalizedError {
  let code: Int
  let message: String

  var errorDescription: String? {
    message
  }

  var nsError: NSError {
    NSError(
      domain: "org.winsvpn.WinsTunnelConfig",
      code: code,
      userInfo: [NSLocalizedDescriptionKey: message]
    )
  }
}

struct WinsBoundedUTF8FileReadResult {
  let text: String
  let byteCount: Int
}

struct WinsSharedConfigPathValidation {
  let url: URL?
  let statusFields: [String: Any]
}

struct WinsAppleAppGroupValidation {
  let containerURL: URL?
  let statusFields: [String: Any]
}

enum WinsAppleAppGroup {
  private static let baseIdentifier = "group.org.winsvpn.app"
  private static let fallbackMacOSTeamIdentifier = "5YT8H4U72M"

  /// DEV-ONLY, iOS-ONLY. The App Group a *debug* iOS build uses instead of
  /// `baseIdentifier`.
  ///
  /// # Why a dev build must not share the production container
  ///
  /// A debug iOS build now installs alongside the shipping app under its own
  /// bundle identifier (`org.winsvpn.app.debug`) so a dev session cannot
  /// destroy the App Store review build. That isolation is worthless if both
  /// builds then read and write the SAME App Group container: the handoff file
  /// `Tunnel/latest_tunnel.conf` and the status document
  /// `Tunnel/latest_status.json` are keyed only by path, so a dev session would
  /// overwrite the production app's tunnel config and its provider status —
  /// leaving the real app pointing at a dev document, or reading a dev
  /// session's status as its own.
  ///
  /// This value is not invented: `group.org.winsvpn.devicecheck` is the App
  /// Group already carried by the existing, Apple-issued provisioning profiles
  /// for `org.winsvpn.app.debug` and `org.winsvpn.app.debug.PacketTunnel`. No
  /// new App ID and no new App Group had to be registered.
  private static let devIdentifier = "group.org.winsvpn.devicecheck"

  /// SCOPING, EXACTLY. The `os(macOS)` branch is evaluated FIRST and is
  /// byte-identical to its previous form, so macOS — Debug or Release — is
  /// completely unaffected by the dev branch below. Only a DEBUG build for a
  /// non-macOS platform (i.e. iOS) sees `devIdentifier`, and an iOS Release or
  /// Profile build still returns `baseIdentifier` exactly as before.
  ///
  /// Both the app target and the appex target must agree on this value, so BOTH
  /// iOS targets define `SWIFT_ACTIVE_COMPILATION_CONDITIONS = DEBUG` in their
  /// Debug configuration and neither defines it in Release or Profile. If those
  /// ever disagree the app and its provider would use different containers and
  /// the provider status would silently never be found — which
  /// `tools/verify_apple_readiness.sh` asserts against per target and per
  /// configuration.
  static var identifier: String {
    #if os(macOS)
      return "\(macOSTeamIdentifier() ?? fallbackMacOSTeamIdentifier).\(baseIdentifier)"
    #elseif DEBUG
      return devIdentifier
    #else
      return baseIdentifier
    #endif
  }

  #if os(macOS)
    private static func macOSTeamIdentifier() -> String? {
      guard let task = SecTaskCreateFromSelf(nil),
            let value = SecTaskCopyValueForEntitlement(
              task,
              "com.apple.developer.team-identifier" as CFString,
              nil
            ) else {
        return nil
      }
      guard let teamIdentifier = value as? String else {
        return nil
      }
      let trimmed = teamIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)
      guard !trimmed.isEmpty,
            trimmed.rangeOfCharacter(from: CharacterSet.alphanumerics.inverted) == nil else {
        return nil
      }
      return trimmed
    }
  #endif

  static func statusFields(
    rawIdentifier: String?,
    containerAvailable: Bool
  ) -> [String: Any] {
    let trimmedIdentifier = rawIdentifier?
      .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    let allowed = trimmedIdentifier == identifier
    return [
      "config_app_group_id_present": !trimmedIdentifier.isEmpty,
      "config_app_group_id_allowed": allowed,
      "config_app_group_container_available": allowed && containerAvailable
    ]
  }

  static func validate(
    rawIdentifier: String?,
    fileManager: FileManager = .default
  ) -> WinsAppleAppGroupValidation {
    let baseFields = statusFields(rawIdentifier: rawIdentifier, containerAvailable: false)
    guard baseFields["config_app_group_id_allowed"] as? Bool == true else {
      return WinsAppleAppGroupValidation(containerURL: nil, statusFields: baseFields)
    }
    let containerURL = fileManager.containerURL(
      forSecurityApplicationGroupIdentifier: identifier
    )
    var fields = baseFields
    fields["config_app_group_container_available"] = containerURL != nil
    return WinsAppleAppGroupValidation(containerURL: containerURL, statusFields: fields)
  }
}

enum WinsTunnelManagerIdentity {
  static let schemaVersion = 3
  private static let maxComponentLength = 32

  static func signature(
    shortVersion: String?,
    buildVersion: String?,
    location: String
  ) -> String {
    let version = sanitizedComponent(shortVersion)
    let build = sanitizedComponent(buildVersion)
    let locationClass = sanitizedComponent(location)
    return "wins_vpn.apple_packet_tunnel.v\(schemaVersion).\(version).\(build).\(locationClass)"
  }

  static func currentSignature(bundle: Bundle = .main) -> String {
    let bundlePath = bundle.bundleURL.standardizedFileURL.path
    let pathIdentity = bundlePathIdentity(bundlePath)
    #if os(macOS)
      let userApplicationsPrefix = URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)
        .appendingPathComponent("Applications", isDirectory: true)
        .standardizedFileURL.path + "/"
      let locationClass = bundlePath.hasPrefix("/Applications/")
        || bundlePath.hasPrefix(userApplicationsPrefix)
        ? "installed"
        : "development"
      let location = "\(locationClass)-\(pathIdentity)"
    #else
      let location = "ios-\(pathIdentity)"
    #endif
    return signature(
      shortVersion: bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String,
      buildVersion: bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String,
      location: location
    )
  }

  private static func sanitizedComponent(_ rawValue: String?) -> String {
    let raw = rawValue?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: ".-_"))
    let sanitized = raw.unicodeScalars.map { scalar in
      allowed.contains(scalar) ? String(scalar) : "-"
    }.joined()
    let bounded = String(sanitized.prefix(maxComponentLength))
    return bounded.isEmpty ? "unknown" : bounded
  }

  private static func bundlePathIdentity(_ path: String) -> String {
    SHA256.hash(data: Data(path.utf8)).prefix(6).map {
      String(format: "%02x", $0)
    }.joined()
  }
}

enum WinsAppGroupFileWriter {
  static let unsafeSymbolicLinkCode = 1601
  static let directoryUnavailableCode = 1602
  static let writeFailedCode = 1603
  /// B-APP-003: the file was written but could not be hardened (owner-only
  /// permissions, backup exclusion, and on iOS the data-protection class).
  /// The write still fails closed: a config file that lands at
  /// container-default protection is a credential-exposure defect, not a
  /// degraded success.
  static let hardeningFailedCode = 1604

  static func ensureDirectory(
    at directory: URL,
    fileManager: FileManager = .default
  ) throws {
    try removeSymbolicLinkIfPresent(at: directory, fileManager: fileManager)
    var isDirectory: ObjCBool = false
    if fileManager.fileExists(atPath: directory.path, isDirectory: &isDirectory) {
      guard isDirectory.boolValue else {
        throw writerError(
          code: directoryUnavailableCode,
          message: "App Group handoff directory is not available."
        )
      }
      return
    }
    do {
      try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
    } catch {
      throw writerError(
        code: directoryUnavailableCode,
        message: "App Group handoff directory could not be created."
      )
    }
  }

  static func writeString(
    _ text: String,
    to url: URL,
    fileManager: FileManager = .default
  ) throws {
    guard let data = text.data(using: .utf8) else {
      throw writerError(
        code: writeFailedCode,
        message: "App Group handoff file could not be encoded."
      )
    }
    try writeData(data, to: url, fileManager: fileManager)
  }

  static func writeData(
    _ data: Data,
    to url: URL,
    fileManager: FileManager = .default
  ) throws {
    try ensureDirectory(at: url.deletingLastPathComponent(), fileManager: fileManager)
    try removeSymbolicLinkIfPresent(at: url, fileManager: fileManager)
    // F-05/C-01/C-03 (audits 2026-08-28): harden FIRST on a private
    // temporary file in the same directory, then publish atomically, then
    // RE-APPLY and READ BACK the hardening on the published URL.
    //
    // The order matters three ways. (1) The temp is CREATED with 0600 and
    // (on iOS) the protection class as creation attributes, so no byte ever
    // exists at container-default protection -- data.write(to:options:[])
    // used to create the temp at 0644/unprotected and harden afterwards,
    // leaving an orphan at default protection forever if the process died
    // in between. (2) Backup exclusion cannot be a creation attribute, so
    // it is set on the temp before any publish. (3) replaceItemAt can reset
    // resource values on the destination even with .usingNewMetadataOnly
    // (observed nondeterministically in the 2026-08-28 audit harness), so
    // after publishing, all attributes are re-applied to the FINAL URL and
    // read back; any mismatch removes the published file and fails -- the
    // write never reports success over an unhardened destination.
    let tempURL = url.deletingLastPathComponent()
      .appendingPathComponent(".\(url.lastPathComponent).tmp-\(UUID().uuidString)")
    do {
      // Creation attributes: permissions and protection apply to the file
      // as it comes into existence, before contents are handed to disk.
      var creationAttributes: [FileAttributeKey: Any] = [
        .posixPermissions: 0o600
      ]
      #if os(iOS)
        creationAttributes[.protectionKey] =
          URLFileProtection.completeUntilFirstUserAuthentication
      #endif
      if !fileManager.createFile(
        atPath: tempURL.path,
        contents: data,
        attributes: creationAttributes
      ) {
        throw CocoaError(.fileWriteUnknown)
      }
      var resourceValues = URLResourceValues()
      resourceValues.isExcludedFromBackup = true
      var excluded = tempURL
      try excluded.setResourceValues(resourceValues)
    } catch {
      try? fileManager.removeItem(at: tempURL)
      NSLog(
        "WinsAppGroupFileWriter: hardening failed for \"%@\" (underlying error %ld): %@",
        url.lastPathComponent,
        (error as NSError).code,
        error.localizedDescription
      )
      throw writerError(
        code: hardeningFailedCode,
        message: "App Group handoff file could not be hardened (owner-only permissions, backup exclusion, file protection)."
      )
    }
    // Publish. replaceItemAt performs the atomic rename-over for an existing
    // destination.
    do {
      if fileManager.fileExists(atPath: url.path) {
        _ = try fileManager.replaceItemAt(
          url,
          withItemAt: tempURL,
          options: []
        )
      } else {
        try fileManager.moveItem(at: tempURL, to: url)
      }
    } catch {
      try? fileManager.removeItem(at: tempURL)
      NSLog(
        "WinsAppGroupFileWriter: atomic publish failed for \"%@\" (underlying error %ld): %@",
        url.lastPathComponent,
        (error as NSError).code,
        error.localizedDescription
      )
      throw writerError(
        code: writeFailedCode,
        message: "App Group handoff file could not be published."
      )
    }
    // Post-publication hardening + verification: apply every attribute to
    // the FINAL URL (the publish step may have reset them) and read each
    // one back. A mismatch removes the published file and fails the write.
    do {
      try fileManager.setAttributes(
        [.posixPermissions: 0o600],
        ofItemAtPath: url.path
      )
      var resourceValues = URLResourceValues()
      resourceValues.isExcludedFromBackup = true
      var excluded = url
      try excluded.setResourceValues(resourceValues)
      #if os(iOS)
        try (url as NSURL).setResourceValue(
          URLFileProtection.completeUntilFirstUserAuthentication,
          forKey: .fileProtectionKey
        )
      #endif
      // Read-back verification.
      let attributes = try fileManager.attributesOfItem(atPath: url.path)
      let mode = (attributes[.posixPermissions] as? NSNumber)?.intValue ?? 0
      if mode & 0o777 != 0o600 {
        throw CocoaError(.fileReadUnknown)
      }
      let excludedNow = try url.resourceValues(
        forKeys: [.isExcludedFromBackupKey]
      ).isExcludedFromBackup
      if excludedNow != true {
        throw CocoaError(.fileReadUnknown)
      }
      #if os(iOS)
        let protection = try url.resourceValues(
          forKeys: [.fileProtectionKey]
        ).fileProtection
        if protection != .completeUntilFirstUserAuthentication {
          throw CocoaError(.fileReadUnknown)
        }
      #endif
    } catch {
      // The published file exists but is not verifiably hardened: remove it
      // rather than leave an unverified destination behind.
      try? fileManager.removeItem(at: url)
      NSLog(
        "WinsAppGroupFileWriter: post-publication verification failed for \"%@\" (underlying error %ld); the file was removed",
        url.lastPathComponent,
        (error as NSError).code
      )
      throw writerError(
        code: hardeningFailedCode,
        message: "App Group handoff file could not be verified after publication (permissions, backup exclusion, file protection)."
      )
    }
  }

  private static func removeSymbolicLinkIfPresent(
    at url: URL,
    fileManager: FileManager
  ) throws {
    guard (try? fileManager.destinationOfSymbolicLink(atPath: url.path)) != nil else {
      return
    }
    do {
      try fileManager.removeItem(at: url)
    } catch {
      throw writerError(
        code: unsafeSymbolicLinkCode,
        message: "App Group handoff symbolic link could not be replaced."
      )
    }
  }

  private static func writerError(code: Int, message: String) -> NSError {
    NSError(
      domain: "org.winsvpn.AppGroupFileWriter",
      code: code,
      userInfo: [NSLocalizedDescriptionKey: message]
    )
  }
}

/// What a purge of the App Group container actually did, observed by
/// re-reading the directory afterwards rather than by trusting the removals.
///
/// `remainingRelativePaths` is the load-bearing field. A purge that reports
/// success without having looked again is the exact defect class this project
/// spent a night cataloguing -- roughly eight guards that had never once
/// fired. So the report says what is STILL THERE, and `complete` is false
/// whenever anything is.
///
/// PATHS ARE RELATIVE, ALWAYS. These fields cross the method channel into
/// Dart and can reach a debug log. `WinsTunnelDiagnostics` treats
/// "group containers" and "/users/" as unsafe fragments for exactly that
/// reason; a relative path names the file without naming the device.
struct WinsAppGroupPurgeReport {
  let containerAvailable: Bool
  /// Whether the directory was successfully RE-READ after the removals.
  ///
  /// Separate from "nothing remains" on purpose, and the difference is the
  /// whole point of the type. An unreadable directory yields an empty list
  /// from the same expression an empty directory does, so without this flag
  /// "I could not look" and "I looked and it was clean" are the same answer.
  /// `complete` therefore requires the observation to have happened, not just
  /// to have come back empty.
  let remainingObserved: Bool
  let removedRelativePaths: [String]
  let failedRelativePaths: [String]
  let remainingRelativePaths: [String]

  var complete: Bool {
    containerAvailable
      && remainingObserved
      && failedRelativePaths.isEmpty
      && remainingRelativePaths.isEmpty
  }

  var statusFields: [String: Any] {
    [
      "app_group_container_available": containerAvailable,
      "app_group_purge_remaining_observed": remainingObserved,
      "app_group_purge_complete": complete,
      "app_group_purge_removed_count": removedRelativePaths.count,
      "app_group_purge_failed_count": failedRelativePaths.count,
      "app_group_purge_remaining_count": remainingRelativePaths.count,
      "app_group_purge_removed": removedRelativePaths,
      "app_group_purge_failed": failedRelativePaths,
      "app_group_purge_remaining": remainingRelativePaths
    ]
  }
}

/// Clears the App Group container on the duress path.
///
/// # Why this has to exist in native code at all
///
/// The App Group container is SHARED between the host app and the Packet
/// Tunnel network extension, so anything the appex writes there survives
/// independently of the app's own storage. Dart cannot see it: no Flutter
/// plugins are registered on either Apple platform
/// (`GeneratedPluginRegistrant` is empty on both), so the only directory the
/// duress sweep in `lib/main.dart` can enumerate is the one
/// `getAppDocumentsDirectory` hands it -- the app's OWN
/// `Application Support/wins_vpn`. The sweep stops at that edge, and until
/// this existed nothing on any duress, logout or account-deletion path
/// removed a single byte from the container.
///
/// # Why the rule is inverted rather than a list of names
///
/// Deliberately the same rule `duressWipeKeepsEntry` uses on the Dart side:
/// EVERYTHING GOES except a closed keep-set. A named-file list is what let
/// `node_cache.json` survive an Android duress wipe in plaintext -- the list
/// was correct about the files someone had thought of. A future writer that
/// drops a new file into this container is swept by this code without anyone
/// having to remember it.
enum WinsAppGroupDuressPurge {
  /// Container-manager bookkeeping (`.com.apple.containermanagerd.metadata.plist`
  /// on macOS, `.com.apple.mobile_container_manager.metadata.plist` on iOS).
  /// Owned by the OS, holds no app data, and removing it damages the
  /// container's own metadata rather than clearing anything. Every other
  /// entry -- hidden or not, file or directory -- is app-owned and goes.
  static func isPreservedEntry(_ name: String) -> Bool {
    name.hasPrefix(".com.apple.")
  }

  /// Removes every app-owned entry at the container root.
  ///
  /// Symbolic links are unlinked, never followed: `removeItem` on a link
  /// removes the link itself, which is the same defensive posture
  /// `WinsAppGroupFileWriter` takes above and the reason a link planted inside
  /// the container cannot be used to make this delete something outside it.
  ///
  /// Never throws. A duress wipe that aborts on the first unlinkable entry
  /// leaves more behind than one that keeps going and reports what it could
  /// not remove.
  static func purge(
    containerURL: URL,
    fileManager: FileManager = .default
  ) -> WinsAppGroupPurgeReport {
    // A container this code cannot even list was not cleared by it. Falling
    // back to an empty name list here would report `complete` for a directory
    // that was missing, unreadable, or not a directory at all -- absence
    // standing in for success, which is precisely the failure this audit
    // exists to remove.
    var isDirectory: ObjCBool = false
    guard fileManager.fileExists(atPath: containerURL.path, isDirectory: &isDirectory),
          isDirectory.boolValue,
          let namesBefore = try? fileManager.contentsOfDirectory(atPath: containerURL.path) else {
      return containerUnavailableReport
    }

    var removed: [String] = []
    var failed: [String] = []
    for name in namesBefore.sorted() {
      guard !isPreservedEntry(name) else { continue }
      do {
        try fileManager.removeItem(at: containerURL.appendingPathComponent(name))
        removed.append(name)
      } catch {
        failed.append(name)
      }
    }

    // OBSERVED, NOT ASSUMED. Re-read the directory rather than reporting the
    // removals back as if they were the outcome. If the re-read itself fails
    // the outcome is UNKNOWN, and unknown is reported as not-complete.
    guard let namesAfter = try? fileManager.contentsOfDirectory(atPath: containerURL.path) else {
      return WinsAppGroupPurgeReport(
        containerAvailable: true,
        remainingObserved: false,
        removedRelativePaths: removed,
        failedRelativePaths: failed,
        remainingRelativePaths: []
      )
    }
    return WinsAppGroupPurgeReport(
      containerAvailable: true,
      remainingObserved: true,
      removedRelativePaths: removed,
      failedRelativePaths: failed,
      remainingRelativePaths: namesAfter.filter { !isPreservedEntry($0) }.sorted()
    )
  }

  /// The report for a device whose container could not be resolved at all.
  ///
  /// Reported, never swallowed. "The container was not there" and "the
  /// container was cleared" are different outcomes and the caller has to be
  /// able to tell them apart -- silent absence standing in for success is the
  /// failure mode this whole audit was about.
  static var containerUnavailableReport: WinsAppGroupPurgeReport {
    WinsAppGroupPurgeReport(
      containerAvailable: false,
      remainingObserved: false,
      removedRelativePaths: [],
      failedRelativePaths: [],
      remainingRelativePaths: []
    )
  }
}

enum WinsSharedConfigPathGuard {
  static func expectedConfigURL(
    containerURL: URL,
    directoryName: String,
    fileName: String
  ) -> URL {
    containerURL
      .appendingPathComponent(directoryName, isDirectory: true)
      .appendingPathComponent(fileName, isDirectory: false)
      .standardizedFileURL
  }

  static func validateSharedConfigPath(
    _ rawPath: String?,
    containerURL: URL,
    directoryName: String,
    fileName: String
  ) -> WinsSharedConfigPathValidation {
    let trimmedPath = rawPath?
      .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    let expectedURL = expectedConfigURL(
      containerURL: containerURL,
      directoryName: directoryName,
      fileName: fileName
    )
    var fields: [String: Any] = [
      "config_shared_path_present": !trimmedPath.isEmpty,
      "config_shared_path_allowed": false,
      "config_shared_path_matches_expected": false,
      "config_shared_path_inside_app_group": false
    ]
    guard !trimmedPath.isEmpty else {
      return WinsSharedConfigPathValidation(url: nil, statusFields: fields)
    }

    let suppliedURL = URL(fileURLWithPath: trimmedPath).standardizedFileURL
    let suppliedPath = normalizedPath(suppliedURL.path)
    let expectedPath = normalizedPath(expectedURL.path)
    let containerPath = normalizedPath(containerURL.standardizedFileURL.path)
    let insideAppGroup = suppliedPath == containerPath ||
      suppliedPath.hasPrefix("\(containerPath)/")
    let matchesExpected = suppliedPath == expectedPath
    fields["config_shared_path_inside_app_group"] = insideAppGroup
    fields["config_shared_path_matches_expected"] = matchesExpected
    fields["config_shared_path_allowed"] = matchesExpected
    return WinsSharedConfigPathValidation(
      url: matchesExpected ? expectedURL : nil,
      statusFields: fields
    )
  }

  private static func normalizedPath(_ path: String) -> String {
    var normalized = path
    while normalized.count > 1, normalized.hasSuffix("/") {
      normalized.removeLast()
    }
    return normalized
  }
}

enum WinsBoundedUTF8FileReader {
  static let fileTooLargeCode = 1501
  static let fileUnreadableCode = 1502
  static let invalidUTF8Code = 1503
  static let symbolicLinkCode = 1504

  static func read(
    url: URL,
    maxBytes: Int,
    fileManager: FileManager = .default
  ) throws -> WinsBoundedUTF8FileReadResult {
    guard maxBytes > 0 else {
      throw WinsTunnelValidationError(
        code: fileTooLargeCode,
        message: "Maximum file size must be positive."
      )
    }

    if (try? fileManager.destinationOfSymbolicLink(atPath: url.path)) != nil {
      throw WinsTunnelValidationError(
        code: symbolicLinkCode,
        message: "File must not be a symbolic link."
      )
    }

    let attributes = try? fileManager.attributesOfItem(atPath: url.path)
    let fileSize = (attributes?[.size] as? NSNumber)?.uint64Value
    if let fileSize, fileSize > UInt64(maxBytes) {
      throw WinsTunnelValidationError(
        code: fileTooLargeCode,
        message: "File exceeds the allowed size."
      )
    }

    guard let fileHandle = try? FileHandle(forReadingFrom: url) else {
      throw WinsTunnelValidationError(
        code: fileUnreadableCode,
        message: "File could not be read."
      )
    }
    defer {
      fileHandle.closeFile()
    }

    let data = fileHandle.readData(ofLength: maxBytes + 1)
    guard data.count <= maxBytes else {
      throw WinsTunnelValidationError(
        code: fileTooLargeCode,
        message: "File exceeds the allowed size."
      )
    }
    guard let text = String(data: data, encoding: .utf8) else {
      throw WinsTunnelValidationError(
        code: invalidUTF8Code,
        message: "File is not valid UTF-8."
      )
    }

    return WinsBoundedUTF8FileReadResult(text: text, byteCount: data.count)
  }
}

struct WinsIPv4Route {
  let destinationAddress: String
  let subnetMask: String
  let prefixLength: Int

  var isDefaultRoute: Bool {
    destinationAddress == "0.0.0.0" && prefixLength == 0
  }

  #if os(macOS)
  /// The two `/1` routes a macOS full tunnel installs INSTEAD of a bare `0.0.0.0/0`.
  ///
  /// WHY NOT `NEIPv4Route.default()`. On 2026-08-09 this box measured that
  /// `tunnelProtocol.enforceRoutes = true` admitted ZERO host flows: the flag's
  /// flow-level NECP policy outranked the engine's own outer-socket `/32`
  /// carve-out in `NEIPv4Settings.excludedRoutes` (a locally-defined, on-link
  /// route in the lab), so the carrier's datagrams were captured back into the
  /// tunnel and the gateway's `rx_packets` never left 0 in all four controlled
  /// rows — see `WINN3_MACOS_ENFORCEROUTES_NECP_20260809.md` and
  /// `WINN3_MACOS_ENFORCEROUTES_SELFSTRANGULATION_20260810_fin_mac_routes.md`.
  ///
  /// That measurement used a carrier endpoint on the Mac's own link, the one
  /// shape whose `/32` carve-out is a locally-defined route that enforcement
  /// suppresses; the production remote-endpoint shape is unmeasured
  /// (SELFSTRANGULATION doc, section 5). The shipping macOS posture is
  /// `enforceRoutes = true` (RULED 2026-08-10, reinstated 2026-08-11;
  /// `WinsMacRoutePosture` in macos/Runner/RouteAudit.swift, registered in
  /// docs/rulings/RULINGS.lock), because under `false` a hostile network can
  /// push a competing default or a shredded default (`0.0.0.0/1` +
  /// `128.0.0.0/1`, the DHCP-option-121 pair) onto the physical interface and
  /// silently pull traffic beside the tunnel, the TunnelVision class.
  ///
  /// This `/1` pair is DEFENSE-IN-DEPTH under that ruling, not a substitute
  /// for it. It is already this product's Windows posture
  /// (`lib/split_tunnel_routes.dart` `windowsPerAppAllowedIpCidrs`): an
  /// injected `0.0.0.0/1` ties the tunnel's same-length route instead of
  /// outranking a `/0`, and the `/32` carrier carve-out still outranks both.
  /// The tie-break for an EQUAL-length injected `/1` is not measured, and any
  /// injection more specific than `/1` beats the pair outright, which is why
  /// the pair alone was never leak-safety; the upgrade from the bare `/0` is
  /// only that an injected `/0` or the option-121 `/1` pair can no longer beat
  /// the capture outright.
  static let macosFullTunnelDefaultPair: [WinsIPv4Route] = [
    WinsIPv4Route(destinationAddress: "0.0.0.0", subnetMask: "128.0.0.0", prefixLength: 1),
    WinsIPv4Route(destinationAddress: "128.0.0.0", subnetMask: "128.0.0.0", prefixLength: 1)
  ]
  #endif
}

/// DEV-ONLY. The complete description of a CONTAINED packet-tunnel start:
/// what a dev/test session is allowed to install instead of the full-tunnel
/// settings that ship.
///
/// # This type is inert
///
/// Building a plan applies nothing. It is a value, computed from a parsed
/// config, that the provider may consult. In `macos/PacketTunnel/`
/// `PacketTunnelProvider.swift` the ONLY code that turns a plan into an
/// `NEPacketTunnelNetworkSettings` sits inside `#if DEBUG`, which the Xcode
/// project defines exclusively in the Debug configuration
/// (`SWIFT_ACTIVE_COMPILATION_CONDITIONS = DEBUG` appears once, in the
/// project-level Debug config; the PacketTunnel target inherits it and neither
/// Release nor Profile sets it). A Release appex therefore has no call site,
/// and `WinsDevContainmentApplication.absenceProbe` is absent from its binary.
///
/// # What "contained" means, and why each part
///
///  1. NO default IPv4 route. Exactly one /32 to the test endpoint, and
///     nothing else. The host's own default route is untouched, so a datapath
///     that carries nothing costs the session, not the machine.
///  2. NO IPv6 settings at all. `ipv6LeakProtectionEnabled` would install a
///     sink address plus `NEIPv6Route.default()`; a contained start installs
///     neither, leaving host IPv6 exactly as it was.
///  3. NO DNS settings at all. The full-tunnel path sets resolvers with an
///     EMPTY match domain, which matches every domain on the system; a
///     contained start sets no `dnsSettings`, so the host keeps its working
///     resolvers and name resolution never depends on the tunnel.
///
/// # This is not, and must never become, a production split tunnel
///
/// Full-tunnel behaviour is leak protection for people under a hostile state,
/// and a split tunnel would leak their real traffic. Nothing in this type is
/// reachable from a production start: it needs a marker no shipping writer
/// emits AND a Debug-only call site. Both, not either.
struct WinsDevContainmentPlan {
  let requested: Bool
  let testRoute: WinsIPv4Route?
  let testRouteRawPresent: Bool
  let transportExclusionRoute: WinsIPv4Route?
  /// What the config ASKED for, recorded so a status reader can see the gap
  /// between the document's full-tunnel intent and what was actually installed.
  let configuredDefaultIPv4Route: Bool
  let configuredIPv6LeakProtection: Bool
  let configuredFullTunnelDNSMatch: Bool

  /// A contained start is possible only with a usable narrow route. When a
  /// marker is present and this is false the start must FAIL, never widen:
  /// falling back to the shipping full-tunnel settings for a session that
  /// asked to be contained is how the blackout comes back.
  var usable: Bool {
    requested && testRoute != nil
  }

  /// True when a marker was present but no /32 could be derived — the refusal
  /// case, kept separate from "no marker at all" so the status says which.
  var unusableTestRoute: Bool {
    requested && testRoute == nil
  }

  /// Status fields describing what a contained start installed. Every key is
  /// namespaced `dev_containment_*` so no existing reader can confuse a
  /// contained run with a validated full-tunnel one.
  ///
  /// `dev_containment_active` is the field the app-side leak-protection check
  /// reads: `WinsAppleReadiness.fullTunnelLeakProtectionConfigFields` fails
  /// `leak_protection_config_passed` whenever it is true, so a contained
  /// session can never report a passing full-tunnel leak-protection posture.
  var statusFields: [String: Any] {
    [
      "dev_containment_active": true,
      "dev_containment_kind": "dev_narrow_route_no_ipv6_no_dns",
      "dev_containment_default_ipv4_route_installed": false,
      "dev_containment_ipv6_settings_installed": false,
      "dev_containment_dns_settings_installed": false,
      "dev_containment_test_route_explicit": testRouteRawPresent,
      "dev_containment_test_route_prefix_length": testRoute?.prefixLength ?? 0,
      "dev_containment_included_route_count": testRoute == nil ? 0 : 1,
      "dev_containment_transport_exclusion_route_present": transportExclusionRoute != nil,
      "dev_containment_config_requested_default_route": configuredDefaultIPv4Route,
      "dev_containment_config_requested_ipv6_leak_protection": configuredIPv6LeakProtection,
      "dev_containment_config_requested_full_tunnel_dns": configuredFullTunnelDNSMatch
    ]
  }
}

/// One `H1`..`H4` value: a single number, or an inclusive range the engine
/// draws from once PER PACKET.
///
/// AmneziaWG's `device/magic-header.go` accepts both spellings on these four
/// fields and stores a bare value as the degenerate range `start == end`, so
/// this type mirrors the engine rather than treating a scalar as a special
/// case. That is what keeps the legacy 11/22/33/44 set validating through the
/// identical code path: these parameters are never negotiated, so a value the
/// far end cannot parse is a fleet lockout, not a downgrade.
///
/// Contract: `VpnConfigValidator.AwgHeaderSpec` in
/// `lib/vpn_config_validation.dart` is the same type with the same rules.
struct WinsAwgHeaderSpec: Equatable {
  let start: Int
  let end: Int

  var isRange: Bool { end > start }

  /// The wire spelling, matching the engine's own `GenSpec()`.
  var spec: String { isRange ? "\(start)-\(end)" : "\(start)" }

  /// `mergeWithDevice`'s rule in `device/uapi.go` verbatim. The engine refuses
  /// a device whose four headers intersect, because the receiver classifies by
  /// testing the header word against each range in turn. For two scalars this
  /// is equality, i.e. exactly the pairwise-distinctness rule that was here
  /// before ranges existed.
  func overlaps(_ other: WinsAwgHeaderSpec) -> Bool {
    start <= other.end && other.start <= end
  }
}

struct WinsAwgObfuscation {
  let jc: Int
  let jmin: Int
  let jmax: Int
  let s1: Int
  let s2: Int
  let s3: Int
  let s4: Int
  let h1: WinsAwgHeaderSpec
  let h2: WinsAwgHeaderSpec
  let h3: WinsAwgHeaderSpec
  let h4: WinsAwgHeaderSpec
  let i1: Int?
  let i2: Int?
  let i3: Int?
  let i4: Int?
  let i5: Int?

  var fieldCount: Int {
    11 + [i1, i2, i3, i4, i5].compactMap { $0 }.count
  }
}

struct WinsXrayRuntimeConfig {
  let uuid: String
  let host: String
  let port: Int
  let serverName: String
  let path: String
  let security: String
  let localPort: Int
  let remoteAwgHost: String
  let remoteAwgPort: Int
}

struct WinsTunnelConfig {
  static let redactedPrivateKeyPlaceholder = "__WINS_KEYCHAIN_PRIVATE_KEY__"
  static let redactedPresharedKeyPlaceholder = "__WINS_KEYCHAIN_PRESHARED_KEY__"
  static let redactedXrayUUIDPlaceholder = "__WINS_KEYCHAIN_XRAY_UUID__"
  static let redactedWinnStaticPrivatePlaceholder = "__WINS_KEYCHAIN_WINN_STATIC_PRIVATE__"
  static let redactedWinnAdmissionKeyPlaceholder = "__WINS_KEYCHAIN_WINN_ADMISSION_KEY__"
  static let redactedWinnPSKPlaceholder = "__WINS_KEYCHAIN_WINN_PSK__"
  /// A random RFC 4193 /128, drawn once per appex process (so once per
  /// session). A literal shared by every install names this product to any
  /// local process that can list interface addresses.
  static let ipv6SinkAddress: String = {
    var random = [UInt8](repeating: 0, count: 15)
    if SecRandomCopyBytes(kSecRandomDefault, random.count, &random) != errSecSuccess {
      random = (0..<15).map { _ in UInt8.random(in: 0...255) }
    }
    let address: [UInt8] = [0xfd] + random
    return stride(from: 0, to: 16, by: 2)
      .map { String(format: "%x", (UInt16(address[$0]) << 8) | UInt16(address[$0 + 1])) }
      .joined(separator: ":")
  }()
  static let ipv6SinkPrefixLength = 128
  static let maxRuntimeConfigFileBytes = 262_144
  static let runtimeConfigTooLargeCode = 1005

  let sections: [String: [String: String]]

  var interfaceAddress: String {
    sections["interface"]?["address"] ?? ""
  }

  var interfacePrivateKey: String {
    sections["interface"]?["privatekey"] ?? ""
  }

  var interfaceAddresses: [String] {
    Self.csvValues(interfaceAddress)
  }

  var interfaceIPv4Address: String {
    let firstIPv4 = interfaceAddresses.first {
      Self.parseIPv4CIDR($0) != nil
    }
    return Self.parseIPv4CIDR(firstIPv4 ?? "")?.address ?? ""
  }

  var interfaceIPv4SubnetMask: String {
    let firstIPv4 = interfaceAddresses.first {
      Self.parseIPv4CIDR($0) != nil
    }
    guard let prefixLength = Self.parseIPv4CIDR(firstIPv4 ?? "")?.prefixLength else {
      return ""
    }
    return Self.subnetMask(prefixLength: prefixLength)
  }

  var dnsServers: [String] {
    Self.csvValues(sections["interface"]?["dns"] ?? "")
  }

  /// The empty match domain, ALWAYS. Every DNS query goes to the tunnel's
  /// resolver, split tunnel or not.
  ///
  /// This used to read `defaultIPv4RouteEnabled ? [""] : []` — the same coupling
  /// that produced the IPv6 leak, applied to DNS. One IPv4 bypass CIDR makes
  /// `defaultIPv4RouteEnabled` false, this returned `[]`, and both providers
  /// skip the assignment entirely (`if !config.dnsMatchDomains.isEmpty`), so
  /// `NEDNSSettings.matchDomains` was left nil.
  ///
  /// WHAT NIL ACTUALLY DOES, from Apple's own documentation rather than
  /// assumption. `man 5 resolver`, SEARCH STRATEGY: macOS routes each query
  /// through a "Super" DNS client that picks the configured client whose NAME
  /// best matches the queried domain, by maximum number of matching components,
  /// and — the load-bearing sentence — "If there are no matches, the
  /// configuration settings in the default client, generally corresponding to
  /// the /etc/resolv.conf file or to the 'primary' DNS configuration on the
  /// system are used for the query."
  ///
  /// `matchDomains` IS that client name. `NEDNSSettings.matchDomains` is
  /// documented as: "If this property is non-nil, the DNS settings will only be
  /// used to resolve host names within the specified domains." Setting `[""]`
  /// names the tunnel's resolver after the root domain, so every name is within
  /// it and the Super client routes everything to it. Leaving it nil registers
  /// no such client, so the tunnel's resolvers are reachable only as the
  /// interface-scoped resolver or as the default client — and the default client
  /// is the PRIMARY service's, which a split tunnel is not, precisely because it
  /// declines the default route. On a live macOS 26.6 host with Wi-Fi up,
  /// `scutil --dns` shows exactly that shape: the default `resolver #1` is the
  /// physical interface's `192.168.50.1` on `en0`, the same interface
  /// `netstat -rn` shows owning the default route.
  ///
  /// So under the old form a split tunnel sent every unmatched query — which is
  /// nearly all of them — to the resolver of the physical interface, in
  /// cleartext, in front of the ISP. Under the Myanmar threat model that is the
  /// worst single leak in the client: DNS names the site before any packet is
  /// sent, it leaks for destinations that DO go through the tunnel, and it is
  /// trivially logged and poisoned by a state-controlled ISP. It is not
  /// second-order to the IPv6 route leak, it is worse, because it reports intent
  /// rather than traffic.
  ///
  /// Corroborating detail from the same platform: `NEDNSSettings.allowFailover`
  /// (macOS 26 / iOS 26) is documented as "failover to the default system
  /// resolver is permitted on resolution failure", and measured on this host it
  /// defaults to `false`. Apple would not have needed to add an opt-in for
  /// falling back to a "default system resolver" if tunnel DNS settings already
  /// displaced it unconditionally.
  ///
  /// THE COST, weighed rather than waved away. Forcing `[""]` sends names to the
  /// in-tunnel gateway (e.g. `10.8.0.1`), so a name that only the LAN's own
  /// resolver knows will now fail instead of resolving. Three things bound that:
  ///
  ///  1. This product's split tunnelling is ADDRESS-based, not name-based. The
  ///     field is "Destinations outside VPN" and takes IPv4 CIDRs
  ///     (`lib/split_tunnel_routes.dart` rejects anything that is not an IPv4
  ///     CIDR). A user who excludes `192.168.0.0/16` to reach a local service
  ///     reaches it BY ADDRESS and needs no DNS for it at all.
  ///  2. mDNS is unaffected. `.local` is served by its own resolver client named
  ///     `local` (visible in `scutil --dns`), and one matching component beats
  ///     the root's zero, so Bonjour discovery and every `*.local` name still
  ///     resolve off-tunnel exactly as before.
  ///  3. The residue is unicast names served only by the LAN/ISP resolver —
  ///     router admin hostnames and split-horizon corporate names. Losing those
  ///     is a name that fails loudly, which the user can work around with an
  ///     address. The alternative is DNS that succeeds silently by telling a
  ///     hostile ISP every site they visit. For these users that trade is not
  ///     close.
  ///
  /// A per-domain bypass list (resolve `corp.example` off-tunnel, everything
  /// else through it) is expressible — it is just a longer `matchDomains` — but
  /// it needs a UI that does not exist, and every entry in it is a name
  /// deliberately leaked to the ISP. Not built here; noted as the shape any
  /// future exception must take.
  ///
  /// FULL TUNNEL IS BIT-IDENTICAL. It already carries `0.0.0.0/0`, so the old
  /// expression already returned `[""]`. This can only ever ADD the empty match
  /// domain, never remove it.
  var dnsMatchDomains: [String] {
    [""]
  }

  /// True when the tunnel's resolver captures every domain. Now constant by
  /// construction, and still ANDed into
  /// `WinsAppleReadiness.fullTunnelLeakProtectionConfigFields`, where
  /// `defaultRouteEnabled` remains a SEPARATE term — so a split tunnel reports
  /// "DNS fully tunnelled: yes" (true, and now actually true) while still
  /// failing the full-tunnel posture on the route term, which is the honest
  /// reading of what it is.
  var fullTunnelDNSMatchEnabled: Bool {
    dnsMatchDomains.contains("")
  }

  var mtu: Int {
    Int(sections["interface"]?["mtu"] ?? "") ?? 1_280
  }

  var peerEndpoint: String {
    sections["peer"]?["endpoint"] ?? ""
  }

  var peerPublicKey: String {
    sections["peer"]?["publickey"] ?? ""
  }

  var peerPresharedKey: String {
    sections["peer"]?["presharedkey"] ?? ""
  }

  static let keepaliveSecondsDefault = 25
  static let keepaliveSecondsFloor = 15
  static let keepaliveSecondsCeiling = 120

  var persistentKeepaliveSeconds: Int {
    guard
      let raw = sections["peer"]?["persistentkeepalive"],
      let parsed = Int(raw.trimmingCharacters(in: .whitespacesAndNewlines))
    else {
      return Self.keepaliveSecondsDefault
    }
    if parsed <= 0 {
      return Self.keepaliveSecondsDefault
    }
    return min(max(parsed, Self.keepaliveSecondsFloor), Self.keepaliveSecondsCeiling)
  }

  var persistentKeepaliveWasDeclared: Bool {
    guard
      let raw = sections["peer"]?["persistentkeepalive"],
      let parsed = Int(raw.trimmingCharacters(in: .whitespacesAndNewlines))
    else {
      return false
    }
    return parsed > 0
  }

  var peerEndpointHost: String {
    Self.parseEndpoint(peerEndpoint)?.host ?? ""
  }

  var peerEndpointKind: String {
    Self.hostKind(peerEndpointHost)
  }

  var peerEndpointPort: Int {
    Self.parseEndpoint(peerEndpoint)?.port ?? 0
  }

  var allowedIPs: [String] {
    Self.csvValues(sections["peer"]?["allowedips"] ?? "")
  }

  var allowedIPv4Routes: [WinsIPv4Route] {
    allowedIPs.compactMap { allowedIP in
      guard let parsedRoute = Self.parseIPv4CIDR(allowedIP) else {
        return nil
      }
      return WinsIPv4Route(
        destinationAddress: Self.ipv4NetworkAddress(
          address: parsedRoute.address,
          prefixLength: parsedRoute.prefixLength
        ),
        subnetMask: Self.subnetMask(prefixLength: parsedRoute.prefixLength),
        prefixLength: parsedRoute.prefixLength
      )
    }
  }

  /// The IPv4 route list the Apple network settings install for this
  /// configuration, as a list of `NEIPv4Route`-shaped values.
  ///
  /// IDENTICAL to `allowedIPv4Routes` EXCEPT on macOS, where a full-tunnel
  /// default (`0.0.0.0/0`) expands to the `/1` pair — see
  /// `WinsIPv4Route.macosFullTunnelDefaultPair`, whose comment carries the
  /// measured 2026-08-09 history and the reason the bare `/0` cannot ship here
  /// safely. iOS is deliberately untouched: it is unmeasured for carriage and
  /// its route shape is not changed by this lane.
  var appleIncludedIPv4Routes: [WinsIPv4Route] {
    allowedIPv4Routes.flatMap { route in
      guard route.isDefaultRoute else { return [route] }
      #if os(macOS)
      return WinsIPv4Route.macosFullTunnelDefaultPair
      #else
      return [route]
      #endif
    }
  }

  var allowedIPv6DefaultRouteEnabled: Bool {
    allowedIPs.contains {
      $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "::/0"
    }
  }

  var defaultIPv4RouteEnabled: Bool {
    allowedIPv4Routes.contains { $0.isDefaultRoute }
  }

  /// Whether the provider must install the IPv6 sink plus `NEIPv6Route`
  /// `.default()`. This asks ONE question — does the document request `::/0`? —
  /// and deliberately does NOT consult `defaultIPv4RouteEnabled`.
  ///
  /// IT USED TO CONSULT IT, AND THAT WAS A LEAK.
  ///
  /// The old form was `defaultIPv4RouteEnabled && allowedIPv6DefaultRouteEnabled`.
  /// That reads as "IPv6 leak protection is a property of the full tunnel", which
  /// is true of the POSTURE but false of the ROUTE. Split tunnelling is a
  /// shipping, user-facing feature ("Destinations outside VPN (all operating
  /// systems)", `lib/main.dart`), and `_buildConfig` emits
  /// `AllowedIPs = <IPv4 complement>, ::/0` — the IPv4 default route disappears
  /// while `::/0` stays. Under the old form a user who excluded one IPv4 range
  /// to reach a local service silently turned IPv6 leak protection OFF: the
  /// provider left `settings.ipv6Settings` nil, and every IPv6 packet left on the
  /// physical interface in the clear while the app still reported protection and
  /// the engine was still told `allowed_ip=::/0`. On the IPv6-enabled mobile
  /// carriers our users are actually on, that is the real traffic, unencrypted,
  /// in front of a hostile state.
  ///
  /// There is no platform constraint behind the old coupling.
  /// `NEPacketTunnelNetworkSettings` treats `ipv4Settings` and `ipv6Settings` as
  /// independent address families; an IPv6 default route alongside a non-default
  /// IPv4 route set is the STANDARD split-tunnel IPv6-leak-protection topology,
  /// not a rejected one.
  ///
  /// FULL TUNNEL IS UNCHANGED. A full-tunnel document carries `0.0.0.0/0, ::/0`,
  /// so both terms were true and this still returns true — same sink, same
  /// default route, same settings object. This can only ever make IPv6 capture
  /// MORE true, never less. A document that asks for no `::/0` at all still
  /// returns false, because there is then no IPv6 route to install.
  ///
  /// The full-tunnel POSTURE check is unaffected and still requires both terms:
  /// `WinsAppleReadiness.fullTunnelLeakProtectionConfigFields` ANDs
  /// `defaultRouteEnabled` in separately, so a split-tunnel session still cannot
  /// report a passing full-tunnel leak-protection posture.
  var ipv6LeakProtectionEnabled: Bool {
    allowedIPv6DefaultRouteEnabled
  }

  var ipv6SinkAddress: String {
    Self.ipv6SinkAddress
  }

  var ipv6SinkPrefixLength: Int {
    Self.ipv6SinkPrefixLength
  }

  /// The host the tunnel's OUTER socket actually talks to, and therefore the
  /// only correct source for `transportIPv4ExclusionRoute`.
  ///
  /// The fallback to the AmneziaWG peer endpoint is a live hazard for every
  /// carrier that repoints that peer endpoint at loopback, and both of them do.
  /// Xray survives it by supplying the real carrier host through `[xray] host`;
  /// Winn must supply it the same way, from `[winn] endpoint`, for two separate
  /// reasons:
  ///
  ///  1. The Winn gateway need not be the AmneziaWG gateway. `[winn] endpoint`
  ///     comes from `protocol_params.gateway_endpoint` when the server sends
  ///     one, and only falls back to `server_endpoint`
  ///     (`lib/winn_protocol_dispatch.dart`). A /32 derived from the peer
  ///     endpoint would then exclude the wrong address.
  ///  2. `WinsPacketTunnelEngine` rewrites the AmneziaWG peer endpoint to the
  ///     Winn loopback seam at start. Reading it here would yield 127.0.0.1,
  ///     `transportIPv4ExclusionRoute` would return nil, and the /32 that keeps
  ///     the Winn engine's own outer UDP socket off the tunnel would silently
  ///     disappear — leaving that socket captured by the tunnel's own default
  ///     route and the tunnel dead-looping.
  ///
  /// `validate()` refuses a Winn config whose endpoint cannot produce that /32,
  /// so this is a fail-closed pairing rather than a best effort.
  /// STACKED IS THE ONE EXCEPTION, and it is the same rule rather than a new
  /// one: this property is "the host the OUTER socket actually talks to", and
  /// in the stacked arrangement the socket that leaves the device is XRAY'S.
  /// The Winn engine's socket targets 127.0.0.1, which needs no /32 because
  /// `127.0.0.0/8` is more specific than the tunnel's own default route and is
  /// never matched by it. Returning the Winn endpoint here would yield a /32
  /// for 127.0.0.1 -- useless -- and would leave Xray's real edge unexcluded,
  /// which is the dead loop this property exists to prevent.
  var transportEndpointHost: String {
    if winnEnabled && !winnStealthChainEnabled {
      return winnEndpointHost
    }
    return xrayRuntimeConfig?.host ?? peerEndpointHost
  }

  var transportEndpointKind: String {
    Self.hostKind(transportEndpointHost)
  }

  var networkSettingsRemoteAddress: String {
    if Self.validIPv4Address(transportEndpointHost) {
      return transportEndpointHost
    }
    if let gateway = tunnelGatewayIPv4Address {
      return gateway
    }
    return dnsServers.first(where: Self.validIPv4Address) ?? ""
  }

  var networkSettingsRemoteAddressKind: String {
    Self.hostKind(networkSettingsRemoteAddress)
  }

  var networkSettingsRemoteAddressSource: String {
    if Self.validIPv4Address(transportEndpointHost) {
      return "transport_endpoint_ipv4"
    }
    if tunnelGatewayIPv4Address != nil {
      return "interface_gateway_ipv4"
    }
    if dnsServers.contains(where: Self.validIPv4Address) {
      return "dns_server_ipv4"
    }
    return "missing"
  }

  private var tunnelGatewayIPv4Address: String? {
    guard let value = Self.ipv4AddressValue(interfaceIPv4Address) else {
      return nil
    }
    let gatewayValue = (value & 0xffff_ff00) | 1
    guard gatewayValue != value else {
      return nil
    }
    return Self.ipv4AddressString(gatewayValue)
  }

  var transportIPv4ExclusionRoute: WinsIPv4Route? {
    guard Self.validIPv4Address(transportEndpointHost) else {
      return nil
    }
    return WinsIPv4Route(
      destinationAddress: transportEndpointHost,
      subnetMask: Self.subnetMask(prefixLength: 32),
      prefixLength: 32
    )
  }

  // MARK: - DEV-ONLY host containment marker
  //
  // These accessors READ a marker; nothing here acts on it. The only code that
  // turns the marker into applied network settings lives inside `#if DEBUG` in
  // `macos/PacketTunnel/PacketTunnelProvider.swift`, so a Release/Profile appex
  // has no call site at all — see `WinsDevContainmentPlan`'s doc comment.
  //
  // WHY THIS EXISTS. `makeNetworkSettings` installs a default IPv4 route, an
  // IPv6 sink with a default IPv6 route, and DNS with an empty match domain
  // (= every domain). That is DELIBERATE, CORRECT leak protection for real
  // users, and it is unchanged. But a proving session whose datapath does not
  // yet carry packets takes all three and carries nothing, which is a total
  // host blackout that outlives the app (the appex keeps the settings). A dev
  // session must not be able to do that to the machine it is being developed on.

  /// The INI section a DEV-ONLY session writes to ask the provider for a
  /// contained start. Absent from every config the shipping app produces:
  /// `_buildRawAmneziaConfig` (`lib/main.dart`) does not emit it, and the only
  /// writer in the tree is `lib/winn_protocol_dev_session.dart`, which a
  /// release build does not contain at all.
  static let devContainmentSection = "winsdevcontainment"

  /// True when the config carries `[WinsDevContainment] enabled = true`.
  ///
  /// Reading true here does NOT contain anything by itself. In a Release appex
  /// this value is never read, and a marker-carrying config therefore starts
  /// exactly as it does today: full tunnel, full leak protection.
  var devContainmentRequested: Bool {
    (sections[Self.devContainmentSection]?["enabled"] ?? "false")
      .trimmingCharacters(in: .whitespacesAndNewlines)
      .lowercased() == "true"
  }

  /// The operator-supplied narrow test route, verbatim, or "".
  var devContainmentTestRouteRaw: String {
    (sections[Self.devContainmentSection]?["testroute"] ?? "")
      .trimmingCharacters(in: .whitespacesAndNewlines)
  }

  /// The ONE route a contained session may install, or nil when none can be
  /// derived — in which case the contained start is refused rather than widened.
  ///
  /// Deliberately /32 ONLY. An operator-supplied `testroute` that is anything
  /// broader (a /24, and above all `0.0.0.0/0`) returns nil and fails the start,
  /// so the containment knob cannot be used to re-create the very blackout it
  /// exists to prevent. With no `testroute` this falls back to the tunnel's own
  /// gateway address (`x.y.z.1` for a `x.y.z.n` interface) — an address inside
  /// the VPN's own space, which is what you ping to prove the datapath carries
  /// packets, and which routes nothing the host owns.
  var devContainmentTestRoute: WinsIPv4Route? {
    let raw = devContainmentTestRouteRaw
    if !raw.isEmpty {
      guard let parsed = Self.parseIPv4CIDR(raw), parsed.prefixLength == 32 else {
        return nil
      }
      return WinsIPv4Route(
        destinationAddress: parsed.address,
        subnetMask: Self.subnetMask(prefixLength: 32),
        prefixLength: 32
      )
    }
    guard let gateway = tunnelGatewayIPv4Address else {
      return nil
    }
    return WinsIPv4Route(
      destinationAddress: gateway,
      subnetMask: Self.subnetMask(prefixLength: 32),
      prefixLength: 32
    )
  }

  /// The complete, inert description of what a contained start would install.
  /// Computing one changes nothing; only the `#if DEBUG` call site applies it.
  var devContainmentPlan: WinsDevContainmentPlan {
    WinsDevContainmentPlan(
      requested: devContainmentRequested,
      testRoute: devContainmentTestRoute,
      testRouteRawPresent: !devContainmentTestRouteRaw.isEmpty,
      transportExclusionRoute: transportIPv4ExclusionRoute,
      configuredDefaultIPv4Route: defaultIPv4RouteEnabled,
      configuredIPv6LeakProtection: ipv6LeakProtectionEnabled,
      configuredFullTunnelDNSMatch: fullTunnelDNSMatchEnabled
    )
  }

  /// Resolve hostname carrier endpoints before route installation.
  /// Full and split route sets both need a literal IPv4 carrier exclusion.
  /// This A-only lookup precedes the tunnel and is not protected by it.
  func resolvingFullTunnelTransportIPv4(
    using resolver: (String) -> String? = Self.systemIPv4Address
  ) throws -> WinsTunnelConfig {
    guard transportEndpointKind == "hostname" else {
      return self
    }

    let transportHost = transportEndpointHost
    guard let rawResolvedAddress = resolver(transportHost) else {
      throw validationError(
        code: 1401,
        message: "The full-tunnel transport hostname could not be resolved before route installation."
      )
    }
    let resolvedAddress = rawResolvedAddress
      .trimmingCharacters(in: .whitespacesAndNewlines)
    guard Self.validIPv4Address(resolvedAddress) else {
      throw validationError(
        code: 1402,
        message: "The full-tunnel transport hostname did not resolve to a valid IPv4 address."
      )
    }

    var resolvedSections = sections
    // `winnStealthChainEnabled` is excluded here for the same reason it is
    // excluded from `transportEndpointHost`: in the stacked arrangement the
    // host being resolved is Xray's edge, so the resolved literal belongs in
    // `[xray] host`. Writing it into `[winn] endpoint` would repoint the Winn
    // engine away from the local Xray inbound and straight at the edge, where
    // nothing speaks AmneziaWG datagrams.
    if winnEnabled && !winnStealthChainEnabled {
      // Unreachable while `validate()` holds — it requires `[winn] endpoint` to
      // be an IPv4 literal, so a Winn transport host is never "hostname" — but
      // written out rather than left to the `else` branch, which would resolve
      // a Winn hostname into the AmneziaWG peer endpoint and leave the Winn
      // engine's own gateway unresolved and unexcluded.
      guard winnEndpointPort > 0 else {
        throw validationError(
          code: 1403,
          message: "The full-tunnel Winn gateway port is unavailable."
        )
      }
      resolvedSections["winn"]?["endpoint"] = "\(resolvedAddress):\(winnEndpointPort)"
    } else if xrayEnabled {
      resolvedSections["xray"]?["host"] = resolvedAddress
    } else {
      guard peerEndpointPort > 0 else {
        throw validationError(
          code: 1403,
          message: "The full-tunnel peer endpoint port is unavailable."
        )
      }
      resolvedSections["peer"]?["endpoint"] = "\(resolvedAddress):\(peerEndpointPort)"
    }

    let resolvedConfig = WinsTunnelConfig(sections: resolvedSections)
    try resolvedConfig.validate()
    return resolvedConfig
  }

  private static func systemIPv4Address(_ host: String) -> String? {
    var hints = addrinfo()
    hints.ai_family = AF_INET
    hints.ai_socktype = SOCK_STREAM
    hints.ai_protocol = IPPROTO_TCP

    var result: UnsafeMutablePointer<addrinfo>?
    guard getaddrinfo(host, nil, &hints, &result) == 0,
          let firstResult = result else {
      return nil
    }
    defer { freeaddrinfo(firstResult) }

    var addresses = Set<String>()
    var cursor: UnsafeMutablePointer<addrinfo>? = firstResult
    while let current = cursor {
      if current.pointee.ai_family == AF_INET,
         let rawAddress = current.pointee.ai_addr {
        var ipv4 = rawAddress.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
          $0.pointee.sin_addr
        }
        var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        if inet_ntop(AF_INET, &ipv4, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil {
          let address = String(cString: buffer)
          if validIPv4Address(address) {
            addresses.insert(address)
          }
        }
      }
      cursor = current.pointee.ai_next
    }
    return addresses.sorted().first
  }

  var xrayEnabled: Bool {
    (sections["xray"]?["enabled"] ?? "false").lowercased() == "true"
  }

  /// THE STACKED ARRANGEMENT. True when Winn is not an alternative to the Xray
  /// stealth leg but sits IN FRONT OF it:
  ///
  /// ```
  ///   AmneziaWG -> Winn seam -> Winn engine (direct-awg)
  ///             -> 127.0.0.1:<xray localport> -> Xray VLESS/WS(/TLS) -> edge
  /// ```
  ///
  /// Derived from the document rather than served as a flag, and that is the
  /// point: the arrangement is ALREADY fully described by where the Winn
  /// engine's own gateway endpoint points. Stacked, it is the Xray inbound on
  /// loopback; competing, it is a real gateway and the two transports genuinely
  /// do both want the one AmneziaWG peer-endpoint field. A served boolean could
  /// disagree with the endpoint; this cannot.
  ///
  /// The equality is against the Xray LOCAL port, not merely "some loopback
  /// address": a loopback Winn endpoint on any other port is not this
  /// arrangement, has no relay behind it, and still fails 1502/1504 below.
  var winnStealthChainEnabled: Bool {
    guard winnEnabled,
          xrayEnabled,
          let localPort = Self.parsedPort(sections["xray"]?["localport"] ?? "") else {
      return false
    }
    return Self.loopbackHost(winnEndpointHost) && winnEndpointPort == localPort
  }

  /// Winn Protocol is the additive second carrier. It is opt-in per config and
  /// is absent from every config the app produces today: `lib/main.dart` still
  /// refuses `winn/3`, and enabling it in production is a governance decision,
  /// not an engineering one (WINN_PROTOCOL_PLATFORM_PLAN.md rule 2). With no
  /// `[winn]` section every value below is identical to the AmneziaWG-only
  /// behaviour that ships.
  var winnEnabled: Bool {
    (sections["winn"]?["enabled"] ?? "false").lowercased() == "true"
  }

  /// The REAL gateway the Winn engine's own outer UDP socket sends to,
  /// `host:port`. Never loopback, and never the seam: the seam is an ephemeral
  /// loopback port the wrapper binds at start and reports back, and it is
  /// deliberately not writable from configuration.
  var winnEndpoint: String {
    (sections["winn"]?["endpoint"] ?? "")
      .trimmingCharacters(in: .whitespacesAndNewlines)
  }

  var winnEndpointHost: String {
    Self.parseEndpoint(winnEndpoint)?.host ?? ""
  }

  var winnEndpointPort: Int {
    Self.parseEndpoint(winnEndpoint)?.port ?? 0
  }

  /// The component that OWNS THE TUN. On Apple that is AmneziaWG for every
  /// config, including a Winn one.
  ///
  /// This deliberately no longer switches to `winn_packet_engine` when Winn is
  /// enabled. Winn is not an alternative to AmneziaWG here, it sits BELOW it:
  /// AmneziaWG keeps the utun device and keeps doing all of the cryptography,
  /// and only its already-encapsulated OUTER datagrams are diverted through the
  /// Winn loopback seam. Selecting Winn *instead* would hand raw IP packets to
  /// a datapath that contains no AmneziaWG implementation — which
  /// `apple/EngineWrappers/WinsWinnPacketEngine.m` refuses at create time
  /// (`"payload":"awg-datagram"`) precisely so that mistake fails at the
  /// handshake rather than forwarding cleartext on the wire.
  var packetCarrierComponent: String {
    "amneziawg_packet_engine"
  }

  /// The Winn loopback seam, when the config asks for one. Additive: it never
  /// replaces `packetCarrierComponent`, it is started before it and stopped
  /// after it.
  ///
  /// NOT selected for a `winn3` standalone configuration. The seam component's
  /// whole job is the AmneziaWG loopback seam and the UAPI repoint, which a
  /// standalone session has neither of; selecting it would hand raw inner IP to
  /// a wrapper that refuses `"payload":"ip-packet"` at create time. Returning
  /// nil here means a standalone start has no relay component to fall through
  /// to, which is the shape a fail-closed refusal needs.
  var winnSeamComponent: String? {
    guard winnEnabled, !winn3Enabled else {
      return nil
    }
    return "winn_packet_engine"
  }

  /// `[winn] carrier` values this Apple build can honour without a carrier
  /// profile. Must equal `WINS_WINN_SUPPORTED_CARRIER` in
  /// `apple/EngineWrappers/WinsWinnPacketEngine.m`, which refuses the same
  /// values one layer lower.
  static let supportedWinnCarrier = "direct-awg"

  /// The authenticated carrier this build can now honour WITH a carrier
  /// profile (see `WinsWinnCarrierProfile`). Must equal
  /// `WINS_WINN_SUPPORTED_CARRIER_HTTP3` in `WinsWinnPacketEngine.m`. Widened
  /// by name, the way Android and Linux widened first: this does not relax
  /// the carrier gate, it names a second carrier the gate accepts. Every
  /// other value -- `http2-stream` included, for the same host-cannot-supply-
  /// the-socket reason Android and Linux refuse it -- is still refused below.
  static let supportedWinnCarrierHttp3 = "http3-connect-udp"

  /// Every `[winn] carrier` value `validate()` accepts at all. Deliberately
  /// NOT a check that a carrier profile is present and valid for the http3
  /// case -- that is a config-shaped question this INI validator cannot
  /// answer, because the profile's credential paths are resolved against this
  /// device's App Group container, not against anything `[winn]` carries. A
  /// carrier session with no usable profile still fails the WHOLE start; it
  /// just fails at `WinsPacketTunnelEngine.start()`, the same layer that
  /// already refuses a `[winn]` section with mismatched `h1..h4` or an
  /// oversize `max_datagram` -- see `runDowngradeTests()` in
  /// tools/verify_apple_winn_seam_harness.swift.
  ///
  /// `winn3` joins the set for the same "widened by name" reason
  /// `http3-connect-udp` did, and with the same limits: naming it here is not a
  /// claim that a winn/3 session HAS run on this device. A configuration that
  /// carries a complete gateway descriptor may now be ATTEMPTED — see
  /// `winn3StartRefusalReason`, which names what a configuration is missing
  /// rather than refusing the whole platform — but no such configuration is
  /// served today, no standalone session has ever completed on Apple, and
  /// `kWinnHostCapabilities` still reports `.absent` for every platform.
  static let supportedWinnCarriers: Set<String> = [
    supportedWinnCarrier, supportedWinnCarrierHttp3, supportedWinnCarrierWinn3
  ]

  /// The winn/3 STANDALONE carrier. Must equal `WinsWinn3.carrierName` and the
  /// Go archive's `winn3Carrier`.
  ///
  /// It is categorically different from the other two and the difference is the
  /// reason it is named separately rather than added to
  /// `supportedWinnCarriers` alone. `direct-awg` and `http3-connect-udp` are
  /// RELAY carriers: AmneziaWG owns the tun, does all of the cryptography, and
  /// Winn carries its already-encapsulated outer datagrams. `winn3` is
  /// STANDALONE: there is no AmneziaWG anywhere in it, the winn/3 session owns
  /// the datapath, and the bytes crossing the engine boundary are inner IP
  /// packets rather than AmneziaWG datagrams.
  ///
  /// That is why `winnSeamComponent` must NOT be selected for it. The seam
  /// component is `WinsWinnPacketEngine.m`, whose entire job is the AmneziaWG
  /// loopback seam and the UAPI repoint; handing it a standalone session would
  /// be the silent downgrade the carrier gate exists to prevent, and it refuses
  /// the create for exactly that reason one layer lower.
  static let supportedWinnCarrierWinn3 = "winn3"

  /// The resolved `[winn] carrier`, lowercased. Empty when there is no `[winn]`
  /// section at all; an absent key inside one normalizes to `direct-awg`,
  /// exactly as `WinnEngineConfig` does on Android.
  var winnCarrier: String {
    guard winnEnabled else {
      return ""
    }
    let raw = (sections["winn"]?["carrier"] ?? "")
      .trimmingCharacters(in: .whitespacesAndNewlines)
      .lowercased()
    return raw.isEmpty ? Self.supportedWinnCarrier : raw
  }

  /// True for a winn/3 STANDALONE configuration.
  var winn3Enabled: Bool {
    winnCarrier == Self.supportedWinnCarrierWinn3
  }

  /// Why a winn/3 standalone session cannot start, or nil.
  ///
  /// Still non-nil for every configuration the control plane serves today, and
  /// that is still deliberate — but it is now non-nil for a REASON THE
  /// OPERATOR CAN CHECK AND CLOSE, rather than as a matter of standing policy.
  /// The whole predicate lives in `WinsWinn3StartRequirements`, next to the
  /// create document it protects; see that type for what each refusal means and
  /// for what is deliberately not checked here.
  ///
  /// # What changed on 2026-08-09, and why it is not a weakening
  ///
  /// This property used to end in a blanket refusal — *"winn/3 standalone is
  /// not enabled on this build: kWinnHostCapabilities reports .absent for every
  /// platform"*. That was correct while nothing on Apple could move a packet.
  /// Once `WinsWinn3Datapath` existed it became CIRCULAR: the capability is
  /// retired only by a measured session, a session needs a permitted start, and
  /// that clause permitted none — so it guaranteed its own premise forever.
  ///
  /// Removing it lifts NO safety property. The refusals that remain are the
  /// ones that describe a configuration that cannot physically work: no
  /// gateway, no inner assignment, no admission profile, no static key, or a
  /// carrier exclusion that excludes nothing. Everything downstream is
  /// untouched — the bootstrap posture is still narrow, the promotion predicate
  /// is still `Gate.State() == StateCarrying` AND `Stats().RxPackets > 0`, and
  /// a session that proves neither still fails closed with the host's routing,
  /// IPv6 and DNS never claimed. `kWinnHostCapabilities` also still reports
  /// `.absent` on every platform, because a start that is PERMITTED is not a
  /// session that HAPPENED, and only the second retires a capability.
  ///
  /// A caller MUST treat a non-nil value as a refusal to start. It must never
  /// be treated as a reason to fall back to `direct-awg`: a standalone session
  /// downgraded to a relay is precisely the outcome the standalone ruling
  /// retires, and doing it silently would mean the gateway negotiated one
  /// transport while the client ran another with nobody told.
  var winn3StartRefusalReason: String? {
    guard winn3Enabled else {
      return nil
    }
    return WinsWinn3StartRequirements.refusalReason(self)
  }

  var transportMode: String {
    let carrier = winnEnabled ? "winn" : "amneziawg"
    return xrayEnabled ? "xray_vless_ws_\(carrier)" : carrier
  }

  /// Every native component the tunnel needs, with the tun owner FIRST.
  ///
  /// The order matters in exactly one place: `WinsPacketCarrier.carrier(for:)`
  /// resolves the tun owner by scanning this list, so AmneziaWG must come
  /// first. It is not the start order — the Winn seam binds an ephemeral port
  /// that AmneziaWG's endpoint has to be written to, so the engine starts the
  /// seam first regardless of where it appears here.
  var requiredEngineComponents: [String] {
    var components = [packetCarrierComponent]
    if let winnSeamComponent {
      components.append(winnSeamComponent)
    }
    if xrayEnabled {
      components.append("xray_vless_ws_transport")
    }
    return components
  }

  var awgObfuscation: WinsAwgObfuscation? {
    guard let interface = sections["interface"],
          let jc = Self.parsedNonNegativeInt(interface["jc"]),
          let jmin = Self.parsedNonNegativeInt(interface["jmin"]),
          let jmax = Self.parsedNonNegativeInt(interface["jmax"]),
          let s1 = Self.parsedNonNegativeInt(interface["s1"]),
          let s2 = Self.parsedNonNegativeInt(interface["s2"]),
          let s3 = Self.parsedNonNegativeInt(interface["s3"]),
          let s4 = Self.parsedNonNegativeInt(interface["s4"]),
          let h1 = Self.parsedHeaderSpec(interface["h1"]),
          let h2 = Self.parsedHeaderSpec(interface["h2"]),
          let h3 = Self.parsedHeaderSpec(interface["h3"]),
          let h4 = Self.parsedHeaderSpec(interface["h4"]) else {
      return nil
    }
    return WinsAwgObfuscation(
      jc: jc,
      jmin: jmin,
      jmax: jmax,
      s1: s1,
      s2: s2,
      s3: s3,
      s4: s4,
      h1: h1,
      h2: h2,
      h3: h3,
      h4: h4,
      i1: Self.parsedNonNegativeInt(interface["i1"]),
      i2: Self.parsedNonNegativeInt(interface["i2"]),
      i3: Self.parsedNonNegativeInt(interface["i3"]),
      i4: Self.parsedNonNegativeInt(interface["i4"]),
      i5: Self.parsedNonNegativeInt(interface["i5"])
    )
  }

  var xrayRuntimeConfig: WinsXrayRuntimeConfig? {
    guard xrayEnabled,
          let xray = sections["xray"],
          let port = Self.parsedPort(xray["port"] ?? ""),
          let localPort = Self.parsedPort(xray["localport"] ?? ""),
          let remoteAwgPort = Self.parsedPort(xray["remoteawgport"] ?? "") else {
      return nil
    }
    return WinsXrayRuntimeConfig(
      uuid: xray["uuid"] ?? "",
      host: xray["host"] ?? "",
      port: port,
      serverName: xray["servername"] ?? "",
      path: xray["path"] ?? "",
      security: (xray["security"] ?? "").lowercased(),
      localPort: localPort,
      remoteAwgHost: xray["remoteawghost"] ?? "",
      remoteAwgPort: remoteAwgPort
    )
  }

  static func parse(_ rawConfig: String) -> WinsTunnelConfig {
    var currentSection = ""
    var sections: [String: [String: String]] = [:]

    for rawLine in rawConfig.components(separatedBy: .newlines) {
      let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
      if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") {
        continue
      }
      if line.hasPrefix("[") && line.hasSuffix("]") {
        currentSection = String(line.dropFirst().dropLast()).lowercased()
        sections[currentSection, default: [:]] = sections[currentSection] ?? [:]
        continue
      }
      guard !currentSection.isEmpty, let separator = line.firstIndex(of: "=") else {
        continue
      }
      let key = line[..<separator].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
      let value = line[line.index(after: separator)...].trimmingCharacters(in: .whitespacesAndNewlines)
      sections[currentSection, default: [:]][key] = value
    }

    return WinsTunnelConfig(sections: sections)
  }

  static func parseAndValidate(_ rawConfig: String) throws -> WinsTunnelConfig {
    try validateRuntimeConfigSize(rawConfig)
    try validateUniqueWinnSecurityBindings(rawConfig)
    let config = parse(rawConfig)
    try config.validate()
    return config
  }

  private static func validateUniqueWinnSecurityBindings(_ rawConfig: String) throws {
    let protectedKeys: Set<String> = [
      "node", "selected_node", "auth_ed25519", "auth_mldsa65"
    ]
    var currentSection = ""
    var counts: [String: Int] = [:]
    for rawLine in rawConfig.components(separatedBy: .newlines) {
      let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
      if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") {
        continue
      }
      if line.hasPrefix("[") && line.hasSuffix("]") {
        currentSection = String(line.dropFirst().dropLast()).lowercased()
        continue
      }
      guard currentSection == "winn", let separator = line.firstIndex(of: "=") else {
        continue
      }
      let key = line[..<separator]
        .trimmingCharacters(in: .whitespacesAndNewlines)
        .lowercased()
      guard protectedKeys.contains(key) else {
        continue
      }
      counts[key, default: 0] += 1
      if counts[key, default: 0] > 1 {
        let subject = key == "node" || key == "selected_node"
          ? "node binding"
          : "dual-auth public key \(key)"
        throw WinsTunnelValidationError(
          code: 1040,
          message: "The Winn Protocol v3 \(subject) is duplicated."
        )
      }
    }
  }

  static func validateRuntimeConfigSize(_ rawConfig: String) throws {
    guard rawConfig.utf8.count <= maxRuntimeConfigFileBytes else {
      throw WinsTunnelValidationError(
        code: runtimeConfigTooLargeCode,
        message: "Win's VPN tunnel config is too large."
      )
    }
  }

  /// Redacts every reusable tunnel credential (interface private key, peer
  /// preshared key, Xray UUID, and the winn/3 `[winn]` device static private
  /// key and admission key) before the config is written to the
  /// App Group handoff file. Each placeholder is restored from the
  /// Keychain-backed stores at connect time — see `restoredRuntimeConfig`,
  /// `WinsClientKeyStore`, and `WinsTunnelSecretStore`.
  static func redactedForStorage(_ rawConfig: String) -> String {
    var currentSection = ""
    return rawConfig.components(separatedBy: .newlines).map { rawLine in
      let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
      if line.hasPrefix("[") && line.hasSuffix("]") {
        currentSection = String(line.dropFirst().dropLast()).lowercased()
        return rawLine
      }
      guard let separator = rawLine.firstIndex(of: "=") else {
        return rawLine
      }
      let key = rawLine[..<separator]
        .trimmingCharacters(in: .whitespacesAndNewlines)
        .lowercased()
      switch (currentSection, key) {
      case ("interface", "privatekey"):
        return "\(rawLine[...separator]) \(redactedPrivateKeyPlaceholder)"
      case ("peer", "presharedkey"):
        return "\(rawLine[...separator]) \(redactedPresharedKeyPlaceholder)"
      case ("xray", "uuid"):
        return "\(rawLine[...separator]) \(redactedXrayUUIDPlaceholder)"
      case ("winn", "static_private"):
        return "\(rawLine[...separator]) \(redactedWinnStaticPrivatePlaceholder)"
      case ("winn", "admission_key"):
        return "\(rawLine[...separator]) \(redactedWinnAdmissionKeyPlaceholder)"
      case ("winn", "psk"):
        return "\(rawLine[...separator]) \(redactedWinnPSKPlaceholder)"
      default:
        return rawLine
      }
    }.joined(separator: "\n")
  }

  static func containsRedactedPrivateKey(_ rawConfig: String) -> Bool {
    parse(rawConfig).sections["interface"]?["privatekey"] == redactedPrivateKeyPlaceholder
  }

  static func containsRedactedPresharedKey(_ rawConfig: String) -> Bool {
    parse(rawConfig).sections["peer"]?["presharedkey"] == redactedPresharedKeyPlaceholder
  }

  static func containsRedactedXrayUUID(_ rawConfig: String) -> Bool {
    parse(rawConfig).sections["xray"]?["uuid"] == redactedXrayUUIDPlaceholder
  }

  static func containsRedactedWinnStaticPrivate(_ rawConfig: String) -> Bool {
    parse(rawConfig).sections["winn"]?["static_private"] == redactedWinnStaticPrivatePlaceholder
  }

  static func containsRedactedWinnAdmissionKey(_ rawConfig: String) -> Bool {
    parse(rawConfig).sections["winn"]?["admission_key"] == redactedWinnAdmissionKeyPlaceholder
  }

  static func containsRedactedWinnPSK(_ rawConfig: String) -> Bool {
    parse(rawConfig).sections["winn"]?["psk"] == redactedWinnPSKPlaceholder
  }

  func amneziaWGUAPIConfiguration() throws -> String {
    guard let privateKeyHex = Self.wireGuardKeyHex(interfacePrivateKey),
          let peerPublicKeyHex = Self.wireGuardKeyHex(peerPublicKey) else {
      throw validationError(code: 1401, message: "Cannot create AmneziaWG UAPI from invalid keys.")
    }

    var lines = [
      "private_key=\(privateKeyHex)"
    ]
    if let obfuscation = awgObfuscation {
      lines.append("jc=\(obfuscation.jc)")
      lines.append("jmin=\(obfuscation.jmin)")
      lines.append("jmax=\(obfuscation.jmax)")
      lines.append("s1=\(obfuscation.s1)")
      lines.append("s2=\(obfuscation.s2)")
      lines.append("s3=\(obfuscation.s3)")
      lines.append("s4=\(obfuscation.s4)")
      lines.append("h1=\(obfuscation.h1.spec)")
      lines.append("h2=\(obfuscation.h2.spec)")
      lines.append("h3=\(obfuscation.h3.spec)")
      lines.append("h4=\(obfuscation.h4.spec)")
      if let i1 = obfuscation.i1 { lines.append("i1=\(i1)") }
      if let i2 = obfuscation.i2 { lines.append("i2=\(i2)") }
      if let i3 = obfuscation.i3 { lines.append("i3=\(i3)") }
      if let i4 = obfuscation.i4 { lines.append("i4=\(i4)") }
      if let i5 = obfuscation.i5 { lines.append("i5=\(i5)") }
    }
    lines.append("replace_peers=true")
    lines.append("public_key=\(peerPublicKeyHex)")
    if let preSharedKeyHex = Self.wireGuardKeyHex(peerPresharedKey) {
      lines.append("preshared_key=\(preSharedKeyHex)")
    }
    lines.append("endpoint=\(peerEndpoint)")
    lines.append("persistent_keepalive_interval=\(persistentKeepaliveSeconds)")
    if !allowedIPs.isEmpty {
      lines.append("replace_allowed_ips=true")
      allowedIPs.forEach { lines.append("allowed_ip=\($0)") }
    }
    return lines.joined(separator: "\n") + "\n"
  }

  /// The AmneziaWG UAPI document with its single `endpoint=` line repointed at
  /// `endpoint`, or nil when the document does not contain exactly one.
  ///
  /// This is the step that actually puts AmneziaWG's outer datagrams into the
  /// Winn loopback seam, and it is why the seam is reachable at all: the AWG
  /// wrapper reads nothing but `amneziawg_uapi_config`, so this line is the
  /// whole mechanism.
  ///
  /// Returning nil on anything other than exactly one match — rather than
  /// appending a line, or leaving the document alone — is the point. A document
  /// that quietly kept the real gateway would produce a tunnel that is
  /// configured as Winn, reports itself as Winn, and is classical AmneziaWG on
  /// the wire. That is the silent downgrade the three gates exist to prevent,
  /// arriving through the one path none of them watch.
  static func amneziaWGUAPIConfiguration(
    _ uapiConfiguration: String,
    rewritingEndpointTo endpoint: String
  ) -> String? {
    guard parseEndpoint(endpoint) != nil else {
      return nil
    }
    var rewrites = 0
    let lines = uapiConfiguration.components(separatedBy: "\n").map { line -> String in
      guard line.hasPrefix("endpoint=") else {
        return line
      }
      rewrites += 1
      return "endpoint=\(endpoint)"
    }
    guard rewrites == 1 else {
      return nil
    }
    return lines.joined(separator: "\n")
  }

  /// Restores whichever placeholders `redactedForStorage` wrote, using the
  /// secrets supplied by the caller. `presharedKey`/`xrayUUID`/
  /// `winnStaticPrivate`/`winnAdmissionKey` default to `nil` so existing
  /// single-secret (private-key-only) call sites keep compiling and behaving
  /// exactly as before; a `nil` value simply leaves that field's placeholder
  /// (if any) untouched.
  static func restoredRuntimeConfig(
    _ rawConfig: String,
    privateKey: String,
    presharedKey: String? = nil,
    xrayUUID: String? = nil,
    winnStaticPrivate: String? = nil,
    winnAdmissionKey: String? = nil,
    winnPSK: String? = nil
  ) -> String {
    var currentSection = ""
    return rawConfig.components(separatedBy: .newlines).map { rawLine in
      let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
      if line.hasPrefix("[") && line.hasSuffix("]") {
        currentSection = String(line.dropFirst().dropLast()).lowercased()
        return rawLine
      }
      guard let separator = rawLine.firstIndex(of: "=") else {
        return rawLine
      }
      let key = rawLine[..<separator]
        .trimmingCharacters(in: .whitespacesAndNewlines)
        .lowercased()
      let value = rawLine[rawLine.index(after: separator)...]
        .trimmingCharacters(in: .whitespacesAndNewlines)
      switch (currentSection, key) {
      case ("interface", "privatekey") where value == redactedPrivateKeyPlaceholder:
        return "\(rawLine[...separator]) \(privateKey)"
      case ("peer", "presharedkey") where value == redactedPresharedKeyPlaceholder:
        guard let presharedKey else { return rawLine }
        return "\(rawLine[...separator]) \(presharedKey)"
      case ("xray", "uuid") where value == redactedXrayUUIDPlaceholder:
        guard let xrayUUID else { return rawLine }
        return "\(rawLine[...separator]) \(xrayUUID)"
      case ("winn", "static_private") where value == redactedWinnStaticPrivatePlaceholder:
        guard let winnStaticPrivate else { return rawLine }
        return "\(rawLine[...separator]) \(winnStaticPrivate)"
      case ("winn", "admission_key") where value == redactedWinnAdmissionKeyPlaceholder:
        guard let winnAdmissionKey else { return rawLine }
        return "\(rawLine[...separator]) \(winnAdmissionKey)"
      case ("winn", "psk") where value == redactedWinnPSKPlaceholder:
        guard let winnPSK else { return rawLine }
        return "\(rawLine[...separator]) \(winnPSK)"
      default:
        return rawLine
      }
    }.joined(separator: "\n")
  }

  static func validWireGuardPublicKey(_ value: String) -> Bool {
    validWireGuardKey(value)
  }

  func validate() throws {
    guard Self.validWireGuardKey(sections["interface"]?["privatekey"] ?? "") else {
      throw validationError(code: 1101, message: "Missing or invalid interface private key.")
    }
    guard !interfaceAddresses.isEmpty,
          interfaceAddresses.allSatisfy(Self.validIPv4CIDR),
          !interfaceIPv4Address.isEmpty,
          !interfaceIPv4SubnetMask.isEmpty else {
      throw validationError(code: 1102, message: "Missing or invalid interface IPv4 address.")
    }
    guard !dnsServers.isEmpty,
          dnsServers.allSatisfy(Self.validDNSServer) else {
      throw validationError(code: 1103, message: "Missing or invalid DNS server.")
    }
    guard Self.validMTU(mtu) else {
      throw validationError(code: 1104, message: "Missing or invalid MTU.")
    }
    guard Self.validOptionalAwgObfuscationValues(sections["interface"] ?? [:]) else {
      throw validationError(code: 1106, message: "Missing or invalid AmneziaWG obfuscation settings.")
    }
    guard let obfuscation = awgObfuscation,
          Self.validAwgObfuscation(obfuscation) else {
      throw validationError(code: 1106, message: "Missing or invalid AmneziaWG obfuscation settings.")
    }
    guard Self.validWireGuardKey(sections["peer"]?["publickey"] ?? "") else {
      throw validationError(code: 1201, message: "Missing or invalid peer public key.")
    }
    guard Self.validEndpoint(peerEndpoint) else {
      throw validationError(code: 1202, message: "Missing or invalid peer endpoint.")
    }
    // EVERY accepted document must request `::/0`. Unconditionally.
    //
    // This used to read `!defaultIPv4RouteEnabled || allowedIPv6DefaultRouteEnabled`
    // — "require `::/0` only when the IPv4 default route is present" — which
    // exempted precisely the split tunnels. A document with non-default IPv4
    // routes and no `::/0` was ACCEPTED, `ipv6LeakProtectionEnabled` was
    // therefore false, both providers left `settings.ipv6Settings` nil, and
    // every IPv6 packet left on the physical interface in the clear. That is
    // the same leak class fixed in `ipv6LeakProtectionEnabled` on 2026-08-06
    // (docs/handoff/APPLE_SPLIT_TUNNEL_IPV6_LEAK_20260806.md), left open one
    // layer up: the property now follows the requested IPv6 route honestly, so
    // the only remaining way to lose IPv6 capture is to hand it a document that
    // never asked for `::/0`. This closes that door.
    //
    // DEFENCE IN DEPTH, NOT A LIVE BUG. No shipping path emits such a document:
    // `lib/main.dart` `_buildRawAmneziaConfig` (:3751-3753) appends `'::/0'`
    // unconditionally on every non-Windows platform, so the three shapes that
    // can reach this parser — full tunnel `0.0.0.0/0, ::/0`, split tunnel
    // `<IPv4 complement>, ::/0`, and the debug-only Winn dev session — all carry
    // it. The point is that a future config generator, a server-side change or a
    // refactor of the Dart builder cannot reintroduce the leak silently: it now
    // fails closed at parse time with 1203 instead of connecting unprotected.
    //
    // WINDOWS IS NOT AFFECTED. `lib/split_tunnel_routes.dart`
    // `windowsPerAppAllowedIpCidrs` emits `::/1` + `8000::/1` rather than
    // `::/0`, but it is called from exactly one site (`lib/main.dart:3752`)
    // behind `Platform.isWindows`, and Windows consumes its config in
    // `windows/runner/windows_tunnel_backend.cpp`, never here. Those halves
    // would in any case already fail the `allowedRouteCount` term below: they
    // parse as neither an IPv4 route nor `::/0`, so the count would not match.
    //
    // The full-tunnel POSTURE is untouched. Being a valid document is not being
    // a full tunnel — `WinsAppleReadiness.fullTunnelLeakProtectionConfigFields`
    // ANDs `defaultRouteEnabled` in separately, so a split tunnel still cannot
    // report a passing full-tunnel leak-protection posture. This guard can only
    // ever REJECT documents it previously accepted, never accept new ones.
    let allowedRouteCount = allowedIPv4Routes.count + (allowedIPv6DefaultRouteEnabled ? 1 : 0)
    guard !allowedIPs.isEmpty,
          allowedRouteCount == allowedIPs.count,
          allowedIPv6DefaultRouteEnabled else {
      throw validationError(code: 1203, message: "Missing or invalid allowed IP routes.")
    }
    if xrayEnabled {
      guard let xray = sections["xray"] else {
        throw validationError(code: 1301, message: "Missing Xray section.")
      }
      guard UUID(uuidString: xray["uuid"] ?? "") != nil else {
        throw validationError(code: 1304, message: "Missing or invalid Xray UUID.")
      }
      guard Self.validHostNameOrAddress(xray["host"] ?? "") else {
        throw validationError(code: 1301, message: "Missing Xray host.")
      }
      guard Self.validPort(xray["port"] ?? "") else {
        throw validationError(code: 1305, message: "Missing or invalid Xray port.")
      }
      guard Self.validHostNameOrAddress(xray["servername"] ?? "") else {
        throw validationError(code: 1306, message: "Missing or invalid Xray server name.")
      }
      guard Self.validXrayPath(xray["path"] ?? "") else {
        throw validationError(code: 1302, message: "Missing or invalid Xray path.")
      }
      guard Self.validXraySecurity(xray["security"] ?? "") else {
        throw validationError(code: 1307, message: "Missing or invalid Xray security mode.")
      }
      guard let localPort = Self.parsedPort(xray["localport"] ?? "") else {
        throw validationError(code: 1303, message: "Missing or invalid Xray local port.")
      }
      // NOT IN THE STACKED ARRANGEMENT, where it is the WINN engine that
      // targets this local port and the AmneziaWG peer endpoint names the real
      // gateway instead -- rewritten to the Winn seam at start, exactly as on a
      // plain winn/3 config. That peer endpoint is not unchecked: 1505 below
      // still requires it to be the real gateway rather than loopback, and
      // `winnStealthChainEnabled` still requires the Winn endpoint to be this
      // very port on loopback, so the chain is pinned end to end.
      guard winnStealthChainEnabled ||
              (peerEndpointHost == "127.0.0.1" && peerEndpointPort == localPort) else {
        throw validationError(code: 1308, message: "Xray peer endpoint must target the configured local transport port.")
      }
      guard Self.validHostNameOrAddress(xray["remoteawghost"] ?? "") else {
        throw validationError(code: 1309, message: "Missing or invalid Xray remote AWG host.")
      }
      guard Self.validPort(xray["remoteawgport"] ?? "") else {
        throw validationError(code: 1310, message: "Missing or invalid Xray remote AWG port.")
      }
    }
    if winnEnabled {
      // The Winn analogue of the Xray loopback-peer rule above. Xray can state
      // its rule as an equality because its local port is configured; the Winn
      // seam binds an EPHEMERAL port that does not exist until the engine is
      // running, so what can be pinned here is the other end — the real gateway
      // the outer socket leaves for, and the /32 that keeps it off the tunnel.
      guard sections["winn"] != nil else {
        throw validationError(code: 1501, message: "Missing Winn section.")
      }
      // Winn and Xray are mutually exclusive OUTER transports WHEN THEY
      // COMPETE: each then wants the AmneziaWG peer endpoint pointed at its own
      // loopback relay and only one of them can have it.
      // `resolveWinnProtocolStart` refuses the same combination in Dart as
      // `stealth_transport_conflict`; this is the native half, so a config that
      // reached the provider by some other route fails closed instead of
      // silently losing one of the two transports.
      //
      // NARROWED, not removed. `winnStealthChainEnabled` is the arrangement in
      // which they do not compete: the Winn engine's endpoint IS the Xray
      // inbound, so the two relays sit in a fixed order on two distinct
      // loopback ports and nothing contends for the peer-endpoint field. Every
      // other pairing -- Xray enabled beside a Winn endpoint that names a real
      // gateway, or one on the wrong loopback port -- still throws here.
      guard !xrayEnabled || winnStealthChainEnabled else {
        throw validationError(
          code: 1502,
          message: "Winn Protocol and the Xray stealth transport cannot both carry one tunnel."
        )
      }
      // An IPv4 literal with a port. The Winn engine refuses a hostname because
      // that lookup would leave the device outside the tunnel, and this is also
      // the address the /32 below is derived from.
      guard Self.validIPv4Address(winnEndpointHost), winnEndpointPort > 0 else {
        throw validationError(code: 1503, message: "Missing or invalid Winn gateway endpoint.")
      }
      // THE HAZARD, REFUSED. On Apple there is no `protect()`: the Winn
      // engine's own outer UDP socket is kept off the tunnel by
      // `NEIPv4Settings.excludedRoutes` alone, which is a property of the route
      // table rather than of a descriptor. A loopback Winn endpoint yields no
      // /32, the outer socket is then matched by the tunnel's own default
      // route, and every datagram it sends is written back into the tun,
      // re-encapsulated and re-sent forever. Fail here rather than start that.
      //
      // ONE EXCEPTION, and it is the case where the hazard does not exist. In
      // the stacked arrangement the Winn engine's socket targets 127.0.0.1, and
      // `127.0.0.0/8` is more specific than the tunnel's own default route, so
      // that socket is never captured by it -- there is nothing to re-encapsulate
      // and no /32 to be missing. The socket that DOES leave the device is
      // Xray's, and the guard immediately below is what proves its /32 exists:
      // `transportEndpointHost` returns the Xray edge in this arrangement, so
      // `transportIPv4ExclusionRoute` is the Xray exclusion route that v1
      // stealth already installs today. The two guards together are therefore
      // still "the socket that leaves is excluded", stated for whichever socket
      // that is.
      guard !Self.loopbackHost(winnEndpointHost) || winnStealthChainEnabled else {
        throw validationError(
          code: 1504,
          message: "Winn gateway endpoint must be the real gateway, not a loopback address."
        )
      }
      guard !defaultIPv4RouteEnabled || transportIPv4ExclusionRoute != nil else {
        throw validationError(
          code: 1504,
          message: "Winn full-tunnel configuration has no transport exclusion route for the Winn gateway."
        )
      }
      // THE CARRIER.
      //
      // `WinnTunnelCreate` takes a C string; every carrier other than
      // `direct-awg` needs an authenticated carrier profile (MASQUE template,
      // suite, ECH config list, device signing key, pinned controller
      // verifiers). `WinnTunnelCreateWithCarrier` is now the C export that
      // takes one -- as a second C string, built by `WinsWinnCarrierProfile`
      // -- so `http3-connect-udp` joins the set this gate names rather than
      // refuses. `http2-stream` does not: its dialer needs a connected,
      // protected TCP socket, and this host opens one unconnected UDP socket
      // for the outer transport, the same reason Android and Linux refuse it
      // by name instead of by falling through this default case.
      //
      // Every OTHER value is still refused, loudly. Running direct-awg for a
      // config that asked for an authenticated post-quantum outer transport
      // would start a tunnel that works, carries traffic, and is not the
      // session the gateway negotiated — a downgrade of the outer transport
      // rather than of the protocol version, which none of the three version
      // gates would catch. `lib/winn_protocol_dispatch.dart` emits this key on
      // every winn/3 config; an absent value is a pre-carrier config and
      // normalizes to direct-awg, exactly as `WinnEngineConfig` does on
      // Android.
      //
      // NOT CHECKED HERE: whether a carrier profile actually exists and is
      // valid for an `http3-connect-udp` config. That is `WinsPacketTunnelEngine`'s
      // question, not this INI validator's -- see `supportedWinnCarriers`'s
      // doc comment.
      let carrier = (sections["winn"]?["carrier"] ?? "")
        .trimmingCharacters(in: .whitespacesAndNewlines)
        .lowercased()
      guard carrier.isEmpty || Self.supportedWinnCarriers.contains(carrier) else {
        throw validationError(
          code: 1506,
          message: "This Apple build carries Winn Protocol over \(Self.supportedWinnCarrier), \(Self.supportedWinnCarrierHttp3) or \(Self.supportedWinnCarrierWinn3) only, and the configuration selected another transport."
        )
      }
      // A winn/3 STANDALONE config is startable only when it carries
      // everything the create document needs and a carrier exclusion that
      // actually excludes something; `WinsWinn3StartRequirements` names each
      // missing piece. Refusing here, with the reasons, is the fail-closed half
      // of "alongside rather than instead of": the alternative to a refusal is
      // a start that quietly becomes an AmneziaWG relay, which is the downgrade
      // the standalone ruling retires.
      if let reason = winn3StartRefusalReason {
        throw validationError(code: 1507, message: reason)
      }
      // The AmneziaWG peer endpoint is rewritten to the seam at start. One that
      // is ALREADY loopback describes a different arrangement — most likely a
      // stale Xray endpoint — and its real gateway is unrecoverable from here.
      guard !Self.loopbackHost(peerEndpointHost) else {
        throw validationError(
          code: 1505,
          message: "Winn AmneziaWG peer endpoint must name the real gateway, not a loopback address."
        )
      }
    }
  }

  func validateInterfacePrivateKeyMatches(_ keyPair: WinsClientKeyPair) throws {
    try validateInterfacePrivateKeyMatchesPublicKey(keyPair.publicKey)
  }

  func validateInterfacePrivateKeyMatchesPublicKey(_ publicKey: String) throws {
    guard Self.validWireGuardKey(publicKey) else {
      throw validationError(
        code: 1105,
        message: "Apple client public key is missing or invalid."
      )
    }
    let derivedPublicKey = try WinsClientKeyStore.publicKeyBase64(
      privateKeyBase64: interfacePrivateKey
    )
    guard derivedPublicKey == publicKey else {
      throw validationError(
        code: 1105,
        message: "Interface private key does not match the expected Apple client public key."
      )
    }
  }

  private func validationError(code: Int, message: String) -> WinsTunnelValidationError {
    WinsTunnelValidationError(code: code, message: message)
  }

  private static func validWireGuardKey(_ value: String) -> Bool {
    guard let data = Data(base64Encoded: value.trimmingCharacters(in: .whitespacesAndNewlines)) else {
      return false
    }
    return data.count == 32
  }

  private static func wireGuardKeyHex(_ value: String) -> String? {
    guard let data = Data(base64Encoded: value.trimmingCharacters(in: .whitespacesAndNewlines)),
          data.count == 32 else {
      return nil
    }
    return data.map { String(format: "%02x", $0) }.joined()
  }

  private static func validEndpoint(_ value: String) -> Bool {
    parseEndpoint(value) != nil
  }

  private static func parseEndpoint(_ value: String) -> (host: String, port: Int)? {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else { return nil }
    if trimmed.hasPrefix("[") {
      guard let endBracket = trimmed.firstIndex(of: "]") else { return nil }
      let portStart = trimmed.index(after: endBracket)
      guard portStart < trimmed.endIndex, trimmed[portStart] == ":" else { return nil }
      let host = String(trimmed[trimmed.index(after: trimmed.startIndex)..<endBracket])
      let portValue = String(trimmed[trimmed.index(after: portStart)...])
      guard let port = parsedPort(portValue), !host.isEmpty else { return nil }
      return (host, port)
    }
    guard let separator = trimmed.lastIndex(of: ":") else { return nil }
    let host = trimmed[..<separator].trimmingCharacters(in: .whitespacesAndNewlines)
    let port = trimmed[trimmed.index(after: separator)...].trimmingCharacters(in: .whitespacesAndNewlines)
    guard let parsedPort = parsedPort(String(port)), !host.isEmpty else { return nil }
    return (String(host), parsedPort)
  }

  private static func validPort(_ value: String) -> Bool {
    parsedPort(value) != nil
  }

  private static func parsedNonNegativeInt(_ value: String?) -> Int? {
    guard let value,
          let parsed = Int(value.trimmingCharacters(in: .whitespacesAndNewlines)),
          parsed >= 0 else {
      return nil
    }
    return parsed
  }

  /// Parses one `h1`..`h4` field in either spelling: `44` or `1000-4000`.
  ///
  /// `Int(_:)` accepts a leading `+`/`-` and Swift's `Int` is 64-bit here, so
  /// the digits are checked explicitly before conversion rather than after --
  /// otherwise `-5` parses to a negative and `-` alone splits into two empty
  /// halves. Bounds are applied by `validAwgObfuscation`, which owns the
  /// cross-language contract; this function only decides shape.
  private static func parsedHeaderSpec(_ value: String?) -> WinsAwgHeaderSpec? {
    guard let value else { return nil }
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else { return nil }

    let parts = trimmed.components(separatedBy: "-")
    guard parts.count <= 2 else { return nil }
    var bounds: [Int] = []
    for part in parts {
      guard !part.isEmpty,
            part.count <= 10,
            part.allSatisfy({ $0.isASCII && $0.isNumber }),
            let parsed = Int(part) else {
        return nil
      }
      bounds.append(parsed)
    }
    let start = bounds[0]
    let end = bounds.count == 2 ? bounds[1] : start
    guard end >= start else { return nil }
    return WinsAwgHeaderSpec(start: start, end: end)
  }

  // AmneziaWG obfuscation bounds. These three numbers are the Apple half of a
  // cross-language contract: they must equal `VpnConfigValidator.awgJunkMax`,
  // `.awgHeaderMin` and `.awgHeaderMax` in `lib/vpn_config_validation.dart`.
  // `test/awg_obfuscation_bounds_parity_test.dart` reads this file and asserts
  // exactly that, because widening one language alone is what produced the
  // 2026-08-07 lockout risk: Dart accepted a full-width header while this
  // validator still refused it, on the live connect path, for both iOS and
  // macOS.
  //
  // jc/jmin/jmax/s1..s4 and i1..i5 are packet and byte counts, so the small
  // ceiling is correct for them and must not inherit the widened one. h1..h4
  // replace WireGuard's four message-type values in the leading little-endian
  // uint32: anything below 2^24 leaves the top byte zero and preserves the
  // exact shape DPI matches on, so they need the whole uint32. That is the
  // bound `WinsWinnPacketEngine.m:847` already applies on the winn/3 path;
  // this is the classic-AWG path catching up to it, not a new invention.
  private static let awgJunkMax = 1_000_000
  private static let awgHeaderMin = 5
  private static let awgHeaderMax = 4_294_967_295

  private static func validAwgObfuscation(_ value: WinsAwgObfuscation) -> Bool {
    let junkValues = [
      value.jc,
      value.jmin,
      value.jmax,
      value.s1,
      value.s2,
      value.s3,
      value.s4,
      value.i1,
      value.i2,
      value.i3,
      value.i4,
      value.i5
    ]
    guard junkValues.compactMap({ $0 }).allSatisfy({ $0 <= awgJunkMax }),
          value.jmin <= value.jmax else {
      return false
    }
    // 1..4 are WireGuard's own message types, so reusing one puts the vanilla
    // value straight back on the wire. Two headers sharing a value is worse
    // than weak -- it leaves the peer unable to tell a handshake from a
    // transport packet -- so a collision is a broken config, not a soft one.
    // The legacy 11/22/33/44 set still passes both rules, which is required:
    // these parameters are not negotiated, so rejecting them would lock out
    // every peer still configured with them.
    // A range is bounded on BOTH endpoints, so every word the engine can draw
    // is inside the contract -- checking only the start would let `5-99999999999`
    // through. `awgHeaderMin` keeps the whole range clear of WireGuard's own
    // types, and the engine's own `Generate()` overflows its uint32 width
    // computation and panics crypto/rand at a span of 2^32; `awgHeaderMin`
    // being non-zero already makes that span unreachable here.
    let headers = [value.h1, value.h2, value.h3, value.h4]
    guard headers.allSatisfy({
      $0.start >= awgHeaderMin && $0.end <= awgHeaderMax && $0.end >= $0.start
    }) else {
      return false
    }
    for a in 0..<headers.count {
      for b in (a + 1)..<headers.count where headers[a].overlaps(headers[b]) {
        return false
      }
    }
    return true
  }

  private static func validOptionalAwgObfuscationValues(_ interface: [String: String]) -> Bool {
    ["i1", "i2", "i3", "i4", "i5"].allSatisfy { key in
      interface[key] == nil || parsedNonNegativeInt(interface[key]) != nil
    }
  }

  private static func parsedPort(_ value: String) -> Int? {
    guard let port = Int(value.trimmingCharacters(in: .whitespacesAndNewlines)) else {
      return nil
    }
    guard port > 0 && port <= 65_535 else {
      return nil
    }
    return port
  }

  private static func csvValues(_ value: String) -> [String] {
    value
      .split(separator: ",")
      .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
      .filter { !$0.isEmpty }
  }

  private static func validMTU(_ value: Int) -> Bool {
    value >= 1280 && value <= 9_000
  }

  private static func validDNSServer(_ value: String) -> Bool {
    validIPv4Address(value)
  }

  private static func validHostNameOrAddress(_ value: String) -> Bool {
    let host = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !host.isEmpty,
          host.count <= 253,
          host.rangeOfCharacter(from: .whitespacesAndNewlines) == nil,
          !host.contains("/"),
          !host.contains(":") else {
      return false
    }
    if host == "localhost" || validIPv4Address(host) {
      return true
    }
    guard !host.hasPrefix("."),
          !host.hasSuffix(".") else {
      return false
    }
    let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")
    return host.split(separator: ".").allSatisfy { label in
      guard !label.isEmpty,
            label.count <= 63,
            !label.hasPrefix("-"),
            !label.hasSuffix("-") else {
        return false
      }
      return String(label).rangeOfCharacter(from: allowed.inverted) == nil
    }
  }

  /// True for anything that names this device. Deliberately the whole
  /// 127.0.0.0/8 block and `localhost`, not just 127.0.0.1: 127.0.0.2 is every
  /// bit as unroutable off-device and would slip an equality check.
  private static func loopbackHost(_ value: String) -> Bool {
    let host = value.trimmingCharacters(in: .whitespacesAndNewlines)
    if host.lowercased() == "localhost" {
      return true
    }
    guard validIPv4Address(host), let address = ipv4AddressValue(host) else {
      return false
    }
    return (address & 0xff00_0000) == 0x7f00_0000
  }

  private static func hostKind(_ value: String) -> String {
    let host = value.trimmingCharacters(in: .whitespacesAndNewlines)
    if host.isEmpty {
      return "missing"
    }
    if host == "127.0.0.1" || host.lowercased() == "localhost" {
      return "loopback"
    }
    if validIPv4Address(host) {
      return "ipv4"
    }
    return "hostname"
  }

  private static func validXrayPath(_ value: String) -> Bool {
    let path = value.trimmingCharacters(in: .whitespacesAndNewlines)
    return path.hasPrefix("/")
      && path.count <= 2_048
      && path.rangeOfCharacter(from: .whitespacesAndNewlines) == nil
  }

  private static func validXraySecurity(_ value: String) -> Bool {
    // `none` puts the VLESS UUID, the WebSocket path and the Host header on
    // the wire in cleartext HTTP. The stealth leg is TLS or it does not start.
    value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "tls"
  }

  private static func validIPv4CIDR(_ value: String) -> Bool {
    parseIPv4CIDR(value) != nil
  }

  private static func parseIPv4CIDR(_ value: String) -> (address: String, prefixLength: Int)? {
    let parts = value.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: "/")
    guard parts.count == 2,
          let prefixLength = Int(parts[1]),
          prefixLength >= 0,
          prefixLength <= 32 else {
      return nil
    }
    let address = String(parts[0])
    guard validIPv4Address(address) else {
      return nil
    }
    return (address, prefixLength)
  }

  private static func validIPv4Address(_ value: String) -> Bool {
    let octets = value.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: ".")
    guard octets.count == 4 else {
      return false
    }
    return octets.allSatisfy { octet in
      guard !octet.isEmpty, let value = Int(octet), value >= 0, value <= 255 else {
        return false
      }
      return String(value) == String(octet)
    }
  }

  private static func ipv4NetworkAddress(address: String, prefixLength: Int) -> String {
    guard let value = ipv4AddressValue(address) else {
      return address
    }
    let mask: UInt32 = prefixLength == 0
      ? 0
      : UInt32.max << UInt32(32 - prefixLength)
    return ipv4AddressString(value & mask)
  }

  private static func ipv4AddressValue(_ value: String) -> UInt32? {
    let octets = value.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: ".")
    guard octets.count == 4 else {
      return nil
    }
    var result = UInt32(0)
    for octet in octets {
      guard let parsed = UInt32(octet), parsed <= 255 else {
        return nil
      }
      result = (result << 8) | parsed
    }
    return result
  }

  private static func ipv4AddressString(_ value: UInt32) -> String {
    (0..<4)
      .map { shift in
        String((value >> UInt32(24 - (shift * 8))) & 0xff)
      }
      .joined(separator: ".")
  }

  private static func subnetMask(prefixLength: Int) -> String {
    guard prefixLength > 0 else {
      return "0.0.0.0"
    }
    let mask = UInt32.max << UInt32(32 - prefixLength)
    return (0..<4)
      .map { shift in
        String((mask >> UInt32(24 - (shift * 8))) & 0xff)
      }
      .joined(separator: ".")
  }
}

struct WinsClientKeyPair {
  static let format = "wireguard-x25519-v2"

  let privateKey: String
  let publicKey: String

  var dictionary: [String: String] {
    [
      "format": Self.format,
      "private_key": privateKey,
      "public_key": publicKey,
      "storage": "keychain"
    ]
  }
}

enum WinsKeychainAccessGroup {
  private static let keychainAccessGroupsEntitlement = "keychain-access-groups"
  private static let infoPlistAccessGroupKey = "WinsAppleSharedKeychainAccessGroup"
  private static let sharedAccessGroupSuffix = ".org.winsvpn.shared"
  private static let winsAccessGroupFragment = ".org.winsvpn."

  static func preferred() -> String? {
    if let infoPlistGroup = preferredFromInfoPlist() {
      return infoPlistGroup
    }

    #if os(macOS)
    guard let task = SecTaskCreateFromSelf(kCFAllocatorDefault),
          let value = SecTaskCopyValueForEntitlement(
            task,
            keychainAccessGroupsEntitlement as CFString,
            nil as UnsafeMutablePointer<Unmanaged<CFError>?>?
          ) else {
      return nil
    }

    if let groups = value as? [String] {
      return preferred(from: groups)
    }
    if let group = value as? String {
      return preferred(from: [group])
    }
    return nil
    #else
    return nil
    #endif
  }

  private static func preferredFromInfoPlist(bundle: Bundle = .main) -> String? {
    guard let group = bundle.object(forInfoDictionaryKey: infoPlistAccessGroupKey) as? String else {
      return nil
    }
    return preferred(from: [group])
  }

  private static func preferred(from groups: [String]) -> String? {
    let resolvedGroups = groups
      .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
      .filter { group in
        !group.isEmpty &&
          !group.contains("$(") &&
          !group.contains("${") &&
          group.rangeOfCharacter(from: .controlCharacters) == nil
      }
    return resolvedGroups.first { $0.hasSuffix(sharedAccessGroupSuffix) }
      ?? resolvedGroups.first { $0.contains(winsAccessGroupFragment) }
  }
}

enum WinsClientKeyStore {
  private static let service = "org.winsvpn.client-keypair"
  // Pre-scoping installs only ever had one Keychain item for the whole
  // device. Keeping that fixed name as the fallback for an empty scope means
  // an already-saved NETunnelProviderProtocol.providerConfiguration (written
  // before this change) keeps resolving to the same item it always did, until
  // the app reconnects and starts sending a real scope again.
  private static let legacyAccount = "wireguard-x25519-v2"
  private static let scopedAccountPrefix = "wireguard-x25519-v3:"

  // accountScope identifies which logged-in account (or the free-access
  // account) a key pair belongs to, so switching accounts on one install can
  // never resume another account's WireGuard identity. Callers must derive it
  // the same way Dart does (see _clientKeyScopeToken in lib/main.dart) and
  // pass it consistently across loadOrCreate/loadExisting for a given tunnel
  // start.
  static func keychainAccount(for accountScope: String) -> String {
    let trimmed = accountScope.trimmingCharacters(in: .whitespacesAndNewlines)
    return trimmed.isEmpty ? legacyAccount : "\(scopedAccountPrefix)\(trimmed)"
  }

  #if os(macOS)
    private static var isRunningInAppExtension: Bool {
      Bundle.main.bundleURL.pathExtension == "appex" ||
        Bundle.main.bundleIdentifier?.hasSuffix(".PacketTunnel") == true
    }
  #endif

  static func loadOrCreate(accountScope: String) throws -> WinsClientKeyPair {
    if let existing = try loadExisting(accountScope: accountScope) {
      return existing
    }

    let keyPair = try makeNewKeyPair()
    try save(keyPair, accountScope: accountScope)
    return keyPair
  }

  static func replace(_ keyPair: WinsClientKeyPair, accountScope: String) throws {
    try validate(keyPair)
    try save(keyPair, accountScope: accountScope)
    guard let readBack = try loadExisting(accountScope: accountScope),
          readBack.privateKey == keyPair.privateKey,
          readBack.publicKey == keyPair.publicKey else {
      throw NSError(
        domain: "org.winsvpn.ClientKeyStore",
        code: 3004,
        userInfo: [NSLocalizedDescriptionKey: "Client key replacement failed durable read-back."]
      )
    }
  }

  static func loadExisting(accountScope: String) throws -> WinsClientKeyPair? {
    let account = keychainAccount(for: accountScope)
    let accessGroup = WinsKeychainAccessGroup.preferred()
    if let accessGroup,
       let shared = try load(account: account, accessGroup: accessGroup) {
      do {
        try validate(shared)
        return shared
      } catch {
        try delete(account: account, accessGroup: accessGroup)
      }
    }

    if let ungrouped = try load(account: account, accessGroup: nil) {
      do {
        try validate(ungrouped)
      } catch {
        try delete(account: account, accessGroup: nil)
        return nil
      }
      if let accessGroup {
        try save(ungrouped, account: account, accessGroup: accessGroup)
      }
      return ungrouped
    }

    #if os(macOS)
      // A macOS keychain access group is honored only by the Data Protection
      // Keychain. Migrate file-keychain items in the host app so extensions
      // never trigger an authentication dialog while starting a tunnel.
      guard !isRunningInAppExtension else {
        return nil
      }
      let legacy = try load(
        account: account,
        accessGroup: accessGroup,
        useDataProtectionKeychain: false
      ) ?? load(
        account: account,
        accessGroup: nil,
        useDataProtectionKeychain: false
      )
      guard let legacy else {
        return nil
      }
      do {
        try validate(legacy)
      } catch {
        try? delete(
          account: account,
          accessGroup: accessGroup,
          useDataProtectionKeychain: false
        )
        try? delete(account: account, accessGroup: nil, useDataProtectionKeychain: false)
        return nil
      }
      try save(legacy, account: account, accessGroup: accessGroup)
      try? delete(
        account: account,
        accessGroup: accessGroup,
        useDataProtectionKeychain: false
      )
      try? delete(account: account, accessGroup: nil, useDataProtectionKeychain: false)
      return legacy
    #else
      return nil
    #endif
  }

  // Removes only the given account's scoped Keychain item, so logging out of
  // one account on a shared device can never leave behind a key another
  // account could later resume. Deliberately does not touch the legacy
  // unscoped item or other accounts' scoped items.
  static func delete(accountScope: String) throws {
    let account = keychainAccount(for: accountScope)
    if let accessGroup = WinsKeychainAccessGroup.preferred() {
      try delete(account: account, accessGroup: accessGroup)
    }
    try delete(account: account, accessGroup: nil)
  }

  static func makeNewKeyPair() throws -> WinsClientKeyPair {
    var privateBytes = [UInt8](repeating: 0, count: 32)
    let randomStatus = privateBytes.withUnsafeMutableBufferPointer { buffer -> OSStatus in
      guard let baseAddress = buffer.baseAddress else {
        return errSecParam
      }
      return SecRandomCopyBytes(kSecRandomDefault, buffer.count, baseAddress)
    }
    guard randomStatus == errSecSuccess else {
      throw keychainError(randomStatus, action: "generate secure random bytes")
    }

    privateBytes[0] &= 248
    privateBytes[31] &= 127
    privateBytes[31] |= 64

    let privateData = Data(privateBytes)
    let privateKey = privateData.base64EncodedString()
    let publicKey = try publicKeyBase64(privateKeyBase64: privateKey)
    return WinsClientKeyPair(privateKey: privateKey, publicKey: publicKey)
  }

  static func publicKeyBase64(privateKeyBase64: String) throws -> String {
    guard let privateData = Data(base64Encoded: privateKeyBase64), privateData.count == 32 else {
      throw NSError(
        domain: "org.winsvpn.ClientKeyStore",
        code: 3001,
        userInfo: [NSLocalizedDescriptionKey: "Invalid WireGuard private key material."]
      )
    }
    let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateData)
    return privateKey.publicKey.rawRepresentation.base64EncodedString()
  }

  private static func load(
    account: String,
    accessGroup: String?,
    useDataProtectionKeychain: Bool = true
  ) throws -> WinsClientKeyPair? {
    var query = baseQuery(
      account: account,
      accessGroup: accessGroup,
      useDataProtectionKeychain: useDataProtectionKeychain
    )
    query[kSecReturnData as String] = kCFBooleanTrue
    query[kSecMatchLimit as String] = kSecMatchLimitOne

    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    if status == errSecItemNotFound {
      return nil
    }
    guard status == errSecSuccess else {
      throw keychainError(status, action: "load client key pair")
    }
    guard
      let data = item as? Data,
      let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      object["format"] as? String == WinsClientKeyPair.format,
      let privateKey = object["private_key"] as? String,
      let publicKey = object["public_key"] as? String
    else {
      throw NSError(
        domain: "org.winsvpn.ClientKeyStore",
        code: 3002,
        userInfo: [NSLocalizedDescriptionKey: "Stored client key pair is corrupt."]
      )
    }
    return WinsClientKeyPair(privateKey: privateKey, publicKey: publicKey)
  }

  private static func save(_ keyPair: WinsClientKeyPair, accountScope: String) throws {
    try save(
      keyPair,
      account: keychainAccount(for: accountScope),
      accessGroup: WinsKeychainAccessGroup.preferred()
    )
  }

  private static func save(
    _ keyPair: WinsClientKeyPair,
    account: String,
    accessGroup: String?,
    useDataProtectionKeychain: Bool = true
  ) throws {
    try validate(keyPair)
    let data = try JSONSerialization.data(
      withJSONObject: keyPair.dictionary,
      options: [.sortedKeys]
    )

    var addQuery = baseQuery(
      account: account,
      accessGroup: accessGroup,
      useDataProtectionKeychain: useDataProtectionKeychain
    )
    addQuery[kSecValueData as String] = data
    #if os(iOS) || os(macOS)
    addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    #endif

    let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
    if addStatus == errSecDuplicateItem {
      let updateStatus = SecItemUpdate(
        baseQuery(
          account: account,
          accessGroup: accessGroup,
          useDataProtectionKeychain: useDataProtectionKeychain
        ) as CFDictionary,
        [kSecValueData as String: data] as CFDictionary
      )
      guard updateStatus == errSecSuccess else {
        throw keychainError(updateStatus, action: "update client key pair")
      }
      return
    }
    guard addStatus == errSecSuccess else {
      throw keychainError(addStatus, action: "save client key pair")
    }
  }

  private static func delete(
    account: String,
    accessGroup: String?,
    useDataProtectionKeychain: Bool = true
  ) throws {
    let status = SecItemDelete(
      baseQuery(
        account: account,
        accessGroup: accessGroup,
        useDataProtectionKeychain: useDataProtectionKeychain
      ) as CFDictionary
    )
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw keychainError(status, action: "delete corrupt client key pair")
    }
  }

  private static func validate(_ keyPair: WinsClientKeyPair) throws {
    let derivedPublicKey = try publicKeyBase64(privateKeyBase64: keyPair.privateKey)
    guard derivedPublicKey == keyPair.publicKey else {
      throw NSError(
        domain: "org.winsvpn.ClientKeyStore",
        code: 3003,
        userInfo: [NSLocalizedDescriptionKey: "Stored client public key does not match the private key."]
      )
    }
  }

  private static func baseQuery(
    account: String,
    accessGroup: String?,
    useDataProtectionKeychain: Bool = true
  ) -> [String: Any] {
    var query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
      kSecAttrSynchronizable as String: kCFBooleanFalse as Any
    ]
    if let accessGroup {
      query[kSecAttrAccessGroup as String] = accessGroup
    }
    #if os(macOS)
      if useDataProtectionKeychain {
        query[kSecUseDataProtectionKeychain as String] = kCFBooleanTrue
      }
    #endif
    return query
  }

  private static func keychainError(_ status: OSStatus, action: String) -> NSError {
    let statusMessage = SecCopyErrorMessageString(status, nil) as String?
    return NSError(
      domain: "org.winsvpn.ClientKeyStore",
      code: Int(status),
      userInfo: [
        NSLocalizedDescriptionKey: "Could not \(action): \(statusMessage ?? "Keychain status \(status)")."
      ]
    )
  }
}

// Holds the reusable tunnel values that `redactedForStorage` strips
// out of the App Group handoff file, so `PacketTunnelProvider` can hydrate
// them back in at connect time — the same pattern `WinsClientKeyStore` already
// uses for the interface private key. Kept as its own Keychain service
// (rather than folded into WinsClientKeyStore's item) because these values
// are per-connection server-issued secrets, not a stable local identity.
struct WinsTunnelSecrets {
  static let format = "wins-tunnel-secrets-v2"
  static let legacyFormat = "wins-tunnel-secrets-v1"

  let presharedKey: String
  let xrayUUID: String
  let winnStaticPrivate: String
  let winnAdmissionKey: String
  let winnPSK: String

  init(
    presharedKey: String,
    xrayUUID: String,
    winnStaticPrivate: String = "",
    winnAdmissionKey: String = "",
    winnPSK: String = ""
  ) {
    self.presharedKey = presharedKey
    self.xrayUUID = xrayUUID
    self.winnStaticPrivate = winnStaticPrivate
    self.winnAdmissionKey = winnAdmissionKey
    self.winnPSK = winnPSK
  }

  var isEmpty: Bool {
    presharedKey.isEmpty && xrayUUID.isEmpty &&
      winnStaticPrivate.isEmpty && winnAdmissionKey.isEmpty && winnPSK.isEmpty
  }

  var dictionary: [String: String] {
    [
      "format": Self.format,
      "preshared_key": presharedKey,
      "xray_uuid": xrayUUID,
      "winn_static_private": winnStaticPrivate,
      "winn_admission_key": winnAdmissionKey,
      "winn_psk": winnPSK
    ]
  }
}

enum WinsTunnelSecretStore {
  private static let service = "org.winsvpn.tunnel-secrets"

  // Reuses WinsClientKeyStore's account-scoping so both stores agree on which
  // logged-in account (or the free-access account) a given item belongs to,
  // without duplicating that derivation logic.
  static func save(_ secrets: WinsTunnelSecrets, accountScope: String) throws {
    try save(
      secrets,
      account: WinsClientKeyStore.keychainAccount(for: accountScope),
      accessGroup: WinsKeychainAccessGroup.preferred()
    )
  }

  static func loadExisting(accountScope: String) throws -> WinsTunnelSecrets? {
    let account = WinsClientKeyStore.keychainAccount(for: accountScope)
    let accessGroup = WinsKeychainAccessGroup.preferred()
    if let accessGroup,
       let shared = try load(account: account, accessGroup: accessGroup) {
      return shared
    }
    return try load(account: account, accessGroup: nil)
  }

  static func delete(accountScope: String) throws {
    let account = WinsClientKeyStore.keychainAccount(for: accountScope)
    if let accessGroup = WinsKeychainAccessGroup.preferred() {
      try delete(account: account, accessGroup: accessGroup)
    }
    try delete(account: account, accessGroup: nil)
  }

  /// Session end for a winn/3 transition key (Sol, OI-KEYSAPP-13): clears
  /// ONLY `winn_static_private` from this scope's tunnel-secrets item, in the
  /// shared access group and the legacy default one, and keeps the peer
  /// preshared key, the Xray UUID and the admission key. The AWG client
  /// identity lives in `WinsClientKeyStore` and is never touched here.
  ///
  /// `keepStaticPrivate` is the device's own v3 private key for this scope
  /// (empty when it has none). A stored value equal to it is kept, so an
  /// on-demand restart of a session on the device's own key still works;
  /// any other value is a hub-served session key and is removed. Decided by
  /// value, like the Dart side. Returns whether anything was cleared.
  @discardableResult
  static func clearWinnStaticPrivate(
    accountScope: String,
    keeping keepStaticPrivate: String
  ) throws -> Bool {
    let account = WinsClientKeyStore.keychainAccount(for: accountScope)
    var groups: [String?] = []
    if let accessGroup = WinsKeychainAccessGroup.preferred() {
      groups.append(accessGroup)
    }
    groups.append(nil)
    var cleared = false
    for group in groups {
      guard let existing = try load(account: account, accessGroup: group),
        !existing.winnStaticPrivate.isEmpty,
        keepStaticPrivate.isEmpty || existing.winnStaticPrivate != keepStaticPrivate
      else {
        continue
      }
      let remaining = WinsTunnelSecrets(
        presharedKey: existing.presharedKey,
        xrayUUID: existing.xrayUUID,
        winnStaticPrivate: "",
        winnAdmissionKey: existing.winnAdmissionKey,
        winnPSK: existing.winnPSK
      )
      if remaining.isEmpty {
        try delete(account: account, accessGroup: group)
      } else {
        try save(remaining, account: account, accessGroup: group)
      }
      cleared = true
    }
    return cleared
  }

  private static func load(account: String, accessGroup: String?) throws -> WinsTunnelSecrets? {
    var query = baseQuery(account: account, accessGroup: accessGroup)
    query[kSecReturnData as String] = kCFBooleanTrue
    query[kSecMatchLimit as String] = kSecMatchLimitOne

    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    if status == errSecItemNotFound {
      return nil
    }
    guard status == errSecSuccess else {
      throw keychainError(status, action: "load tunnel secrets")
    }
    guard
      let data = item as? Data,
      let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      let format = object["format"] as? String,
      format == WinsTunnelSecrets.format || format == WinsTunnelSecrets.legacyFormat
    else {
      throw NSError(
        domain: "org.winsvpn.TunnelSecretStore",
        code: 3201,
        userInfo: [NSLocalizedDescriptionKey: "Stored tunnel secrets are corrupt."]
      )
    }
    return WinsTunnelSecrets(
      presharedKey: object["preshared_key"] as? String ?? "",
      xrayUUID: object["xray_uuid"] as? String ?? "",
      winnStaticPrivate: object["winn_static_private"] as? String ?? "",
      winnAdmissionKey: object["winn_admission_key"] as? String ?? "",
      winnPSK: object["winn_psk"] as? String ?? ""
    )
  }

  private static func save(
    _ secrets: WinsTunnelSecrets,
    account: String,
    accessGroup: String?
  ) throws {
    let data = try JSONSerialization.data(
      withJSONObject: secrets.dictionary,
      options: [.sortedKeys]
    )

    var addQuery = baseQuery(account: account, accessGroup: accessGroup)
    addQuery[kSecValueData as String] = data
    #if os(iOS) || os(macOS)
    addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    #endif

    let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
    if addStatus == errSecDuplicateItem {
      let updateStatus = SecItemUpdate(
        baseQuery(account: account, accessGroup: accessGroup) as CFDictionary,
        [kSecValueData as String: data] as CFDictionary
      )
      guard updateStatus == errSecSuccess else {
        throw keychainError(updateStatus, action: "update tunnel secrets")
      }
      return
    }
    guard addStatus == errSecSuccess else {
      throw keychainError(addStatus, action: "save tunnel secrets")
    }
  }

  private static func delete(account: String, accessGroup: String?) throws {
    let status = SecItemDelete(baseQuery(account: account, accessGroup: accessGroup) as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw keychainError(status, action: "delete tunnel secrets")
    }
  }

  private static func baseQuery(account: String, accessGroup: String?) -> [String: Any] {
    var query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
      kSecAttrSynchronizable as String: kCFBooleanFalse as Any
    ]
    if let accessGroup {
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
      domain: "org.winsvpn.TunnelSecretStore",
      code: Int(status),
      userInfo: [
        NSLocalizedDescriptionKey: "Could not \(action): \(statusMessage ?? "Keychain status \(status)")."
      ]
    )
  }
}

enum WinsInstallIdentityStore {
  private static let service = "org.winsvpn.install-identity"
  private static let account = "install-id-v1"
  private static let allowedCharacters = CharacterSet(
    charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
  )

  static func loadOrCreate() throws -> String {
    if let existing = try loadExisting() {
      return existing
    }

    let installId = try makeNewInstallId()
    try save(installId)
    return installId
  }

  static func loadExisting() throws -> String? {
    let accessGroup = WinsKeychainAccessGroup.preferred()
    if let accessGroup,
       let shared = try load(accessGroup: accessGroup) {
      if validInstallId(shared) {
        return shared
      }
      try delete(accessGroup: accessGroup)
    }

    guard let legacy = try load(accessGroup: nil) else {
      return nil
    }
    guard validInstallId(legacy) else {
      try delete(accessGroup: nil)
      return nil
    }
    if let accessGroup {
      try save(legacy, accessGroup: accessGroup)
    }
    return legacy
  }

  static func makeNewInstallId() throws -> String {
    var bytes = [UInt8](repeating: 0, count: 24)
    let randomStatus = bytes.withUnsafeMutableBufferPointer { buffer -> OSStatus in
      guard let baseAddress = buffer.baseAddress else {
        return errSecParam
      }
      return SecRandomCopyBytes(kSecRandomDefault, buffer.count, baseAddress)
    }
    guard randomStatus == errSecSuccess else {
      throw keychainError(randomStatus, action: "generate install identity")
    }

    return Data(bytes)
      .base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  static func validInstallId(_ value: String) -> Bool {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard trimmed.count >= 24 else {
      return false
    }
    return trimmed.rangeOfCharacter(from: allowedCharacters.inverted) == nil
  }

  private static func load(accessGroup: String?) throws -> String? {
    var query = baseQuery(accessGroup: accessGroup)
    query[kSecReturnData as String] = kCFBooleanTrue
    query[kSecMatchLimit as String] = kSecMatchLimitOne

    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    if status == errSecItemNotFound {
      return nil
    }
    guard status == errSecSuccess else {
      throw keychainError(status, action: "load install identity")
    }
    guard let data = item as? Data,
          let installId = String(data: data, encoding: .utf8) else {
      throw NSError(
        domain: "org.winsvpn.InstallIdentityStore",
        code: 3101,
        userInfo: [NSLocalizedDescriptionKey: "Stored install identity is corrupt."]
      )
    }
    return installId
  }

  private static func save(_ installId: String) throws {
    try save(installId, accessGroup: WinsKeychainAccessGroup.preferred())
  }

  private static func save(_ installId: String, accessGroup: String?) throws {
    guard validInstallId(installId), let data = installId.data(using: .utf8) else {
      throw NSError(
        domain: "org.winsvpn.InstallIdentityStore",
        code: 3102,
        userInfo: [NSLocalizedDescriptionKey: "Invalid install identity."]
      )
    }

    var addQuery = baseQuery(accessGroup: accessGroup)
    addQuery[kSecValueData as String] = data
    #if os(iOS)
    addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    #endif

    let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
    if addStatus == errSecDuplicateItem {
      let updateStatus = SecItemUpdate(
        baseQuery(accessGroup: accessGroup) as CFDictionary,
        [kSecValueData as String: data] as CFDictionary
      )
      guard updateStatus == errSecSuccess else {
        throw keychainError(updateStatus, action: "update install identity")
      }
      return
    }
    guard addStatus == errSecSuccess else {
      throw keychainError(addStatus, action: "save install identity")
    }
  }

  private static func delete(accessGroup: String?) throws {
    let status = SecItemDelete(baseQuery(accessGroup: accessGroup) as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw keychainError(status, action: "delete install identity")
    }
  }

  private static func baseQuery(accessGroup: String?) -> [String: Any] {
    var query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
      kSecAttrSynchronizable as String: kCFBooleanFalse as Any
    ]
    if let accessGroup {
      query[kSecAttrAccessGroup as String] = accessGroup
    }
    return query
  }

  private static func keychainError(_ status: OSStatus, action: String) -> NSError {
    let statusMessage = SecCopyErrorMessageString(status, nil) as String?
    return NSError(
      domain: "org.winsvpn.InstallIdentityStore",
      code: Int(status),
      userInfo: [
        NSLocalizedDescriptionKey: "Could not \(action): \(statusMessage ?? "Keychain status \(status)")."
      ]
    )
  }
}

/// Which Keychain a purge query is aimed at.
///
/// On iOS there is one Keychain and this collapses to the access-group axis.
/// On macOS there are TWO, and the app's own stores are split across both:
/// `WinsClientKeyStore`, `WinsTunnelSecretStore` and `WinsSecureStateStore` set
/// `kSecUseDataProtectionKeychain` (the modern, iOS-like keychain), while
/// `WinsInstallIdentityStore` sets it NOWHERE and therefore lands in the legacy
/// FILE keychain -- and `WinsClientKeyStore` keeps a file-keychain migration
/// path of its own (`useDataProtectionKeychain: false`) for installs that
/// predate the split. A purge that queried only one of the two would find
/// nothing in the other and report a clean sweep over an item it never looked
/// at.
struct WinsKeychainQueryScope: Equatable {
  let useDataProtectionKeychain: Bool
  /// nil means "do not constrain the access group", which on a search or
  /// delete spans every group this process is entitled to reach. The explicit
  /// group pass is kept beside it because macOS honours access groups only in
  /// the Data Protection Keychain, so the two axes are not independent.
  let accessGroup: String?

  /// Every scope an item written by this app could be sitting in.
  static func productionScopes(accessGroup: String?) -> [WinsKeychainQueryScope] {
    var scopes: [WinsKeychainQueryScope] = []
    #if os(macOS)
      let dataProtectionOptions = [true, false]
    #else
      let dataProtectionOptions = [true]
    #endif
    for dataProtection in dataProtectionOptions {
      scopes.append(
        WinsKeychainQueryScope(
          useDataProtectionKeychain: dataProtection,
          accessGroup: nil
        )
      )
      if let accessGroup, !accessGroup.isEmpty {
        scopes.append(
          WinsKeychainQueryScope(
            useDataProtectionKeychain: dataProtection,
            accessGroup: accessGroup
          )
        )
      }
    }
    return scopes
  }
}

/// One Keychain service to sweep, and the accounts within it that must SURVIVE.
///
/// `keptAccounts` exists for exactly one record and it is a safety record, not
/// a convenience: `vpn_settings.txt` in `org.winsvpn.app.secure-state` carries
/// the QUEUED DURESS DISPATCH when an alert could not be delivered. Destroying
/// it would silently throw away the only copy of an undelivered call for help
/// -- the same failure `SecureFileStore.migrateLegacyLayout` was written to
/// avoid on Android. Everything else in every listed service goes.
struct WinsKeychainPurgeTarget {
  /// A short, stable, non-identifying name for the report. NEVER an account
  /// value: `WinsClientKeyStore`'s accounts embed the account scope token, so
  /// a report that named them would carry the account number it exists to
  /// destroy across a method channel and into a log.
  let label: String
  let service: String
  let keptAccounts: Set<String>

  init(label: String, service: String, keptAccounts: Set<String> = []) {
    self.label = label
    self.service = service
    self.keptAccounts = keptAccounts
  }
}

/// What a purge of one service actually turned out to be, observed rather than
/// assumed.
///
/// # Why `complete` requires the store to have held something
///
/// This is the Keychain's version of the trap `WinsAppGroupPurgeReport` calls
/// out, and it is sharper here. A directory can be LISTED: you can enumerate
/// every entry and know you saw them all. A Keychain cannot -- you can only ask
/// it a question, and a question aimed at the wrong service, the wrong access
/// group, or (on macOS) the wrong one of the two keychains answers
/// `errSecItemNotFound`, which is byte-for-byte the answer an empty store
/// gives. So "I found nothing before and nothing after" is NOT evidence the
/// item is gone; it is evidence only that this query matches nothing, which is
/// equally true when the private key is sitting untouched one access group
/// over.
///
/// `complete` therefore means: I observed material here, and I observed it
/// gone. A store that never held anything reports `absent`, which is neither
/// success nor failure and is deliberately not folded into either.
struct WinsKeychainStorePurgeOutcome {
  let label: String
  /// Whether every query variant for this service answered (success or a
  /// clean `errSecItemNotFound`). False means at least one variant could not
  /// be evaluated at all -- a locked keychain, a missing entitlement -- and
  /// the outcome for that variant is UNKNOWN, never assumed empty.
  let observedBefore: Bool
  let itemsBefore: Int
  let deleteFailed: Bool
  let observedAfter: Bool
  let itemsRemaining: Int

  var blocked: Bool {
    !observedBefore || !observedAfter || deleteFailed || itemsRemaining > 0
  }

  var complete: Bool {
    !blocked && itemsBefore > 0
  }

  var absent: Bool {
    !blocked && itemsBefore == 0
  }

  /// One of `purged`, `absent`, `blocked`. Safe to log: a fixed vocabulary
  /// plus a fixed label, never an account or a value.
  var status: String {
    if blocked { return "blocked" }
    return complete ? "purged" : "absent"
  }
}

struct WinsKeychainPurgeReport {
  let outcomes: [WinsKeychainStorePurgeOutcome]

  var purgedCount: Int { outcomes.filter { $0.complete }.count }
  var absentCount: Int { outcomes.filter { $0.absent }.count }
  var blockedCount: Int { outcomes.filter { $0.blocked }.count }
  var remainingItemCount: Int { outcomes.reduce(0) { $0 + $1.itemsRemaining } }

  /// Strict on purpose. Nothing blocked, nothing left, and at least one store
  /// observed to have held material and then observed empty. A run in which
  /// every store answered "nothing here" is reported as `absent`, not as a
  /// completed purge -- see `WinsKeychainStorePurgeOutcome.complete`.
  var complete: Bool {
    blockedCount == 0 && remainingItemCount == 0 && purgedCount > 0
  }

  /// Fixed-vocabulary summary, e.g. `["client-keypair:purged",
  /// "tunnel-secrets:absent"]`. Contains no account, no scope token, no value.
  var storyStatuses: [String] {
    outcomes.map { "\($0.label):\($0.status)" }
  }

  var statusFields: [String: Any] {
    [
      "keychain_purge_complete": complete,
      "keychain_purge_store_count": outcomes.count,
      "keychain_purge_purged_count": purgedCount,
      "keychain_purge_absent_count": absentCount,
      "keychain_purge_blocked_count": blockedCount,
      "keychain_purge_remaining_items": remainingItemCount,
      "keychain_purge_stores": storyStatuses
    ]
  }
}

/// Clears the identity-bearing Keychain items on the duress path.
///
/// # Why this had to exist
///
/// Keychain items SURVIVE APP DELETION on iOS. Until this existed, a duress
/// wipe removed the app's files and the App Group container and left behind
/// `org.winsvpn.client-keypair` -- the WireGuard client PRIVATE KEY -- in a
/// shared access group, along with the peer preshared key, the Xray UUID and
/// the stable per-install identifier the backend knows this handset by. Set
/// against the threat model that is the worst of the three stores to leave: a
/// key that proves which account a seized phone belonged to, and which
/// uninstalling the app does not remove.
///
/// # Why a scope-independent sweep and not the existing deletes
///
/// `WinsClientKeyStore.delete(accountScope:)` removes ONE account's item, by
/// design -- it serves logout and Deactivate Device, where scoping is correct.
/// Duress is the opposite case: every scope this install ever used has to go,
/// including accounts the user has since switched away from and the pre-scoping
/// `wireguard-x25519-v2` item. So the query here names the SERVICE and nothing
/// else.
///
/// # The delete loop is not defensive padding
///
/// OBSERVED on a real macOS Keychain, 2026-08-07: `SecItemDelete` over a
/// service-scoped query removes exactly ONE matching item per call. Four items
/// took four calls, and the fifth returned `errSecItemNotFound`. A single
/// delete would have left three of four client keys behind. Loop until the
/// store says there is nothing left, bounded so a Keychain that keeps
/// answering `errSecSuccess` cannot spin.
enum WinsKeychainDuressPurge {
  /// Bound on delete passes per query variant. Far above any plausible number
  /// of account scopes on one install; present so a pathological Keychain
  /// cannot hang the duress path.
  static let maxDeletePasses = 128

  static let clientKeyPairLabel = "client-keypair"
  static let tunnelSecretsLabel = "tunnel-secrets"
  static let installIdentityLabel = "install-identity"
  static let secureStateLabel = "secure-state"

  /// The secure-state service, scoped EXACTLY as `WinsSecureStateStore` scopes
  /// its own, because the purge must sweep the store this build actually wrote.
  ///
  /// # This is a de-aliasing, not a narrowing of the wipe
  ///
  /// The governing invariant for this whole target list: *each entry names the
  /// service the corresponding store writes IN THE SAME BUILD.* Nothing more,
  /// nothing less. The other three entries stay unconditional because their
  /// stores are unconditional -- `WinsClientKeyStore`, `WinsTunnelSecretStore`
  /// and `WinsInstallIdentityStore` write the shared group's services in both
  /// configurations, deliberately (see `ios/Runner/RunnerDebug.entitlements`:
  /// the lab build is MEANT to reuse the key pair the gateway already knows).
  /// Scoping those would point the sweep at services nothing writes and let a
  /// lab build's real client key SURVIVE its own duress wipe, which is strictly
  /// worse. This one entry is conditional for the opposite reason: since
  /// 2026-08-08 `WinsSecureStateStore.service` is itself `#if DEBUG`-scoped, so
  /// an unconditional literal here is the ONLY place in the codebase where the
  /// duress wipe reaches a store the running build does not own.
  ///
  /// # What the unconditional literal actually did in a DEBUG build
  ///
  /// Both halves of the duress path disagreed about which store the app has.
  /// `_wipeIncriminatingStateForDuress` deletes its five named records through
  /// the secure-state method channel -- i.e. through `WinsSecureStateStore`,
  /// correctly scoped -- while THIS sweep named the production service. So a
  /// DEBUG duress run destroyed the owner's production PIN and their
  /// `client_keypair.json` blob, and left the lab build's own secure-state rows
  /// standing.
  ///
  /// That also disabled the sweep's entire reason for existing. Per the list's
  /// own comment below, the sweep is the backstop for records the named list
  /// FORGOT. Pointed at a service the build never writes, it cannot catch a
  /// forgotten DEBUG record -- it is guaranteed to miss it and to report on
  /// production's rows instead. Scoping is what makes that backstop testable in
  /// a debug build for the first time.
  ///
  /// # Why `#if DEBUG` and not a parameter
  ///
  /// `WinsSecureStateStore.swift` and this file are both compiled into the host
  /// Runner target (and only the host invokes `purgeKeychainIdentity`), so the
  /// two constants are resolved by the same compiler with the same
  /// `SWIFT_ACTIVE_COMPILATION_CONDITIONS`. They cannot drift apart the way a
  /// caller-supplied service string could. Keep these two branches in this
  /// order and keep them agreeing with that store; `apple_duress_purge_build_
  /// scoping_test.dart` fails if either stops being true.
  ///
  /// Release is byte-for-byte the string it has always been, so a Release
  /// duress wipe still takes EVERYTHING under the production service --
  /// including rows a pre-2026-08-08 lab build wrote there, which are
  /// indistinguishable from the owner's own and which no debug build should be
  /// the one to decide to delete.
  #if DEBUG
    static let secureStateService = "org.winsvpn.app.secure-state.debug"
  #else
    static let secureStateService = "org.winsvpn.app.secure-state"
  #endif

  /// The complete set of Keychain services this app or its appex writes.
  ///
  /// There are exactly four, all `kSecClassGenericPassword`; the app registers
  /// no `SecIdentity`, no certificate and no `kSecClassKey` item, and neither
  /// `NETunnelProviderProtocol.passwordReference` nor `identityReference` is
  /// ever set, so the system VPN profile holds no Keychain reference of ours
  /// either.
  ///
  /// The secure-state service is in the list WITH A KEEP-SET rather than left
  /// out. The named deletes in `_wipeIncriminatingStateForDuress` already reach
  /// its six records, but a named list is only ever correct about the names
  /// somebody remembered -- which is exactly how `node_cache.json` survived a
  /// duress wipe in plaintext. Sweeping the service and keeping one record by
  /// name inverts that rule here too. It is the one entry taken from a constant
  /// rather than written inline, because it is the one store whose service name
  /// depends on the build shape -- see `secureStateService` above.
  static func targets(preserveEmergencyQueue: Bool) -> [WinsKeychainPurgeTarget] {
    [
      WinsKeychainPurgeTarget(label: clientKeyPairLabel, service: "org.winsvpn.client-keypair"),
      WinsKeychainPurgeTarget(label: tunnelSecretsLabel, service: "org.winsvpn.tunnel-secrets"),
      WinsKeychainPurgeTarget(label: installIdentityLabel, service: "org.winsvpn.install-identity"),
      WinsKeychainPurgeTarget(
        label: secureStateLabel,
        service: secureStateService,
        // The ONLY record that may survive a duress Keychain purge, and only
        // while an alert is still queued inside it. See WinsKeychainPurgeTarget.
        keptAccounts: preserveEmergencyQueue ? ["vpn_settings.txt"] : []
      )
    ]
  }

  /// Recovery from an account cleanup journal that cannot be read
  /// (`_eraseLocalAccountDataKeepingDevice` in lib/main.dart): every
  /// scope's client key pair and tunnel secret, and every secure-state row
  /// except the journal, which Dart deletes last and only after this pass and
  /// its own checks succeed, and the per-install id, which names this device
  /// rather than an account. Not a duress purge: the install identity stays.
  static func unreadableCleanupJournalTargets() -> [WinsKeychainPurgeTarget] {
    [
      WinsKeychainPurgeTarget(label: clientKeyPairLabel, service: "org.winsvpn.client-keypair"),
      WinsKeychainPurgeTarget(label: tunnelSecretsLabel, service: "org.winsvpn.tunnel-secrets"),
      WinsKeychainPurgeTarget(
        label: secureStateLabel,
        service: secureStateService,
        keptAccounts: ["calc_session.json", "install_id.txt"]
      )
    ]
  }

  static func purgeAccountDataKeepingCleanupJournal(
    accessGroup: String? = WinsKeychainAccessGroup.preferred()
  ) -> WinsKeychainPurgeReport {
    purge(
      targets: unreadableCleanupJournalTargets(),
      scopes: WinsKeychainQueryScope.productionScopes(accessGroup: accessGroup)
    )
  }

  static func purge(
    preserveEmergencyQueue: Bool,
    accessGroup: String? = WinsKeychainAccessGroup.preferred()
  ) -> WinsKeychainPurgeReport {
    purge(
      targets: targets(preserveEmergencyQueue: preserveEmergencyQueue),
      scopes: WinsKeychainQueryScope.productionScopes(accessGroup: accessGroup)
    )
  }

  static func purge(
    targets: [WinsKeychainPurgeTarget],
    scopes: [WinsKeychainQueryScope]
  ) -> WinsKeychainPurgeReport {
    WinsKeychainPurgeReport(
      outcomes: targets.map { purge(target: $0, scopes: scopes) }
    )
  }

  static func purge(
    target: WinsKeychainPurgeTarget,
    scopes: [WinsKeychainQueryScope]
  ) -> WinsKeychainStorePurgeOutcome {
    var observedBefore = !scopes.isEmpty
    var observedAfter = !scopes.isEmpty
    var itemsBefore = 0
    var itemsRemaining = 0
    var deleteFailed = false

    for scope in scopes {
      switch countPurgeableAccounts(target: target, scope: scope) {
      case .observed(let accounts):
        itemsBefore += accounts.count
        for account in accounts {
          if !deleteAll(target: target, scope: scope, account: account) {
            deleteFailed = true
          }
        }
      case .unobserved:
        // NOT assumed empty. A variant that could not be evaluated is a
        // variant whose contents are unknown, and unknown is never success.
        observedBefore = false
      }
    }

    // OBSERVED, NOT ASSUMED. Ask again rather than reporting the deletes back
    // as though they were the outcome.
    for scope in scopes {
      switch countPurgeableAccounts(target: target, scope: scope) {
      case .observed(let accounts):
        itemsRemaining += accounts.count
      case .unobserved:
        observedAfter = false
      }
    }

    return WinsKeychainStorePurgeOutcome(
      label: target.label,
      observedBefore: observedBefore,
      itemsBefore: itemsBefore,
      deleteFailed: deleteFailed,
      observedAfter: observedAfter,
      itemsRemaining: itemsRemaining
    )
  }

  enum AccountObservation {
    case observed([String])
    case unobserved
  }

  /// Accounts under this service that the purge is allowed to remove.
  ///
  /// `kSecReturnData` is DELIBERATELY NEVER REQUESTED. Counting how many items
  /// are present does not require reading the private key, and a purge that
  /// pulled key material into memory to count it would be a worse leak than
  /// the one it is closing. Attributes only, and the account strings never
  /// leave this function.
  static func countPurgeableAccounts(
    target: WinsKeychainPurgeTarget,
    scope: WinsKeychainQueryScope
  ) -> AccountObservation {
    var query = baseQuery(service: target.service, scope: scope)
    query[kSecMatchLimit as String] = kSecMatchLimitAll
    query[kSecReturnAttributes as String] = kCFBooleanTrue

    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    if status == errSecItemNotFound {
      return .observed([])
    }
    guard status == errSecSuccess else {
      return .unobserved
    }
    let attributes = (item as? [[String: Any]]) ?? []
    let accounts = attributes
      .compactMap { $0[kSecAttrAccount as String] as? String }
      .filter { !target.keptAccounts.contains($0) }
    return .observed(accounts)
  }

  /// Deletes every item for one account under one service, looping because a
  /// single `SecItemDelete` removes one match per call (see the type comment).
  /// Returns false only on a real Keychain refusal; `errSecItemNotFound` is
  /// the loop's normal exit and is success.
  private static func deleteAll(
    target: WinsKeychainPurgeTarget,
    scope: WinsKeychainQueryScope,
    account: String
  ) -> Bool {
    var query = baseQuery(service: target.service, scope: scope)
    query[kSecAttrAccount as String] = account
    for _ in 0..<maxDeletePasses {
      let status = SecItemDelete(query as CFDictionary)
      if status == errSecItemNotFound {
        return true
      }
      guard status == errSecSuccess else {
        return false
      }
    }
    // Ran out of passes with the Keychain still reporting success. Treat as a
    // failure rather than walking away: the re-read will confirm it, and a
    // wipe that gives up quietly is the defect this path was audited for.
    return false
  }

  private static func baseQuery(
    service: String,
    scope: WinsKeychainQueryScope
  ) -> [String: Any] {
    var query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      // The stores all write `synchronizable: false`, but the purge asks for
      // ANY. A build that ever wrote a synchronizable item, or an item
      // restored from a backup as one, must not be able to hide from the wipe
      // behind an attribute the wipe was too specific to match.
      kSecAttrSynchronizable as String: kSecAttrSynchronizableAny
    ]
    if let accessGroup = scope.accessGroup, !accessGroup.isEmpty {
      query[kSecAttrAccessGroup as String] = accessGroup
    }
    #if os(macOS)
      if scope.useDataProtectionKeychain {
        query[kSecUseDataProtectionKeychain as String] = kCFBooleanTrue
      }
    #endif
    return query
  }
}

enum WinsAppleExternalUrl {
  static let maxLength = 2_048
  // WARNING -- `sms` AND `mailto` ARE HERE FOR ORDINARY USER-INITIATED LINKS
  // ONLY, AND NOTHING ON THE DURESS PATH MAY EVER USE THEM.
  //
  // iOS duress is a LOCAL WIPE, with no network signal, by owner decision: of
  // the five duress method-channel handlers, iOS implements only
  // `monotonicMilliseconds`, and there is no duress, SMS, mail or push symbol
  // anywhere under ios/ or macos/. This allowlist is the one tempting door
  // left in the codebase, because reaching it from a future "iOS parity"
  // attempt would compile and appear to work.
  //
  // It would not be covert. Opening an `sms:`/`mailto:` URL hands control to
  // the system Messages/Mail compose UI, with the recipient and the body
  // filled in, ON SCREEN, and waits for a human to press Send. On a phone
  // that is being held by a captor -- the only situation in which a duress
  // code is ever entered -- that is the loudest possible failure: it shows
  // the alert, the trusted contact's number and the coordinates to exactly
  // the person the alert is about, and it does not send unless they let it.
  // Route nothing from _armDuress, DuressDispatch or any retry through here.
  private static let allowedSchemes: Set<String> = [
    "http",
    "https",
    "mailto",
    "tel",
    "sms"
  ]
  private static let webSchemes: Set<String> = ["http", "https"]
  private static let phonePayloadScalars = CharacterSet(
    charactersIn: "+0123456789*#(),;-."
  )

  static func safeUrl(from rawValue: String?) -> URL? {
    let raw = rawValue?
      .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    guard !raw.isEmpty,
          raw.count <= maxLength,
          raw.rangeOfCharacter(from: .whitespacesAndNewlines) == nil,
          raw.rangeOfCharacter(from: .controlCharacters) == nil,
          let url = URL(string: raw),
          let scheme = url.scheme?.lowercased(),
          allowedSchemes.contains(scheme),
          url.user == nil,
          url.password == nil else {
      return nil
    }
    if webSchemes.contains(scheme) {
      guard let host = url.host?.trimmingCharacters(in: .whitespacesAndNewlines),
            !host.isEmpty else {
        return nil
      }
    } else {
      guard url.host == nil,
            safeDirectSchemePayload(scheme: scheme, raw: raw) else {
        return nil
      }
    }
    return url
  }

  private static func safeDirectSchemePayload(scheme: String, raw: String) -> Bool {
    let payload = directSchemePayload(from: raw)
    guard !payload.isEmpty,
          !directPayloadLooksLocalOrScript(payload) else {
      return false
    }

    switch scheme {
    case "mailto":
      let address = payload
        .split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false)
        .first
        .map(String.init)?
        .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
      return !address.isEmpty &&
        !address.hasPrefix("/") &&
        !address.hasPrefix("\\") &&
        !address.hasPrefix(".")
    case "tel", "sms":
      let destination = payload
        .split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false)
        .first
        .map(String.init)?
        .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
      return !destination.isEmpty &&
        destination.unicodeScalars.allSatisfy { phonePayloadScalars.contains($0) }
    default:
      return false
    }
  }

  private static func directPayloadLooksLocalOrScript(_ payload: String) -> Bool {
    let lowercased = payload.lowercased()
    if lowercased.contains("://") {
      return true
    }
    let unsafePrefixes = [
      "/",
      "\\",
      ".",
      "~",
      "file:",
      "javascript:",
      "data:",
      "about:",
      "blob:"
    ]
    return unsafePrefixes.contains { lowercased.hasPrefix($0) }
  }

  private static func directSchemePayload(from raw: String) -> String {
    guard let separatorIndex = raw.firstIndex(of: ":") else {
      return ""
    }
    let payloadStart = raw.index(after: separatorIndex)
    return String(raw[payloadStart...])
      .trimmingCharacters(in: .whitespacesAndNewlines)
  }
}

struct WinsAppleExternalLeakAuditRequest {
  let requested: Bool
  let urls: [URL]
  let minimumEndpointCount: Int
  let rawEndpointCount: Int
  let invalidEndpointCount: Int
}

enum WinsAppleExternalLeakAudit {
  static let defaultMinimumEndpointCount = 2
  static let maxEndpointCount = 6
  static let maxUrlLength = 512
  static let timeoutSeconds: TimeInterval = 6

  private static let blockedHostFragments = [
    "google",
    "gstatic",
    "googleapis",
    "youtube",
    "cloudflare",
    "cloudflare-dns",
    "1dot1dot1dot1"
  ]

  static func request(from rawArguments: Any?) -> WinsAppleExternalLeakAuditRequest {
    let args = rawArguments as? [String: Any] ?? [:]
    let rawValues = rawUrlValues(args["externalLeakAuditUrls"])
    let requested = WinsAppleReadiness.bool(args, "externalLeakAuditRequested") ||
      !rawValues.isEmpty
    let requestedMinimum = WinsAppleReadiness.int(args, "externalLeakAuditMinimumEndpoints")
    let minimumEndpointCount = min(
      max(requestedMinimum > 0 ? requestedMinimum : defaultMinimumEndpointCount, 1),
      maxEndpointCount
    )
    var validUrls: [URL] = []
    for rawValue in rawValues.prefix(maxEndpointCount) {
      guard let url = safeCanaryUrl(from: rawValue) else {
        continue
      }
      validUrls.append(url)
    }
    let consideredCount = min(rawValues.count, maxEndpointCount)
    return WinsAppleExternalLeakAuditRequest(
      requested: requested,
      urls: validUrls,
      minimumEndpointCount: minimumEndpointCount,
      rawEndpointCount: consideredCount,
      invalidEndpointCount: max(0, consideredCount - validUrls.count)
    )
  }

  static func baseFields(for request: WinsAppleExternalLeakAuditRequest) -> [String: Any] {
    var fields: [String: Any] = [
      "external_leak_audit_requested": request.requested,
      "external_leak_audit_attempted": false,
      "external_leak_audit_passed": false,
      "external_leak_audit_endpoint_count": request.urls.count,
      "external_leak_audit_minimum_endpoint_count": request.minimumEndpointCount,
      "external_leak_audit_invalid_endpoint_count": request.invalidEndpointCount,
      "external_leak_audit_https_canary_count": request.urls.count,
      "external_leak_audit_dns_canary_count": request.urls.count,
      "external_leak_audit_non_google_cloudflare_only":
        request.requested && request.invalidEndpointCount == 0 && !request.urls.isEmpty,
      "external_leak_audit_url_kind":
        request.urls.isEmpty ? "" : "public_https_hostname_canary",
      "external_leak_audit_blocked_by_configuration": false,
      "external_leak_audit_success_count": 0,
      "external_leak_audit_failure_count": 0,
      "external_leak_audit_transport_error_count": 0,
      "external_leak_audit_server_error_count": 0
    ]
    if request.requested && request.urls.count < request.minimumEndpointCount {
      fields["external_leak_audit_blocked_by_configuration"] = true
    }
    return fields
  }

  static func run(
    _ request: WinsAppleExternalLeakAuditRequest,
    completion: @escaping ([String: Any]) -> Void
  ) {
    var fields = baseFields(for: request)
    guard request.requested else {
      completion(fields)
      return
    }
    guard request.urls.count >= request.minimumEndpointCount else {
      completion(fields)
      return
    }

    fields["external_leak_audit_attempted"] = true
    let configuration = URLSessionConfiguration.ephemeral
    configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
    configuration.timeoutIntervalForRequest = timeoutSeconds
    configuration.timeoutIntervalForResource = timeoutSeconds
    let session = URLSession(configuration: configuration)
    let group = DispatchGroup()
    let lock = NSLock()
    var successCount = 0
    var failureCount = 0
    var transportErrorCount = 0
    var serverErrorCount = 0

    for url in request.urls {
      group.enter()
      var urlRequest = URLRequest(url: url)
      urlRequest.httpMethod = "GET"
      urlRequest.timeoutInterval = timeoutSeconds
      urlRequest.setValue("bytes=0-0", forHTTPHeaderField: "Range")
      urlRequest.setValue("text/plain,*/*;q=0.1", forHTTPHeaderField: "Accept")
      session.dataTask(with: urlRequest) { _, response, error in
        let statusCode = (response as? HTTPURLResponse)?.statusCode ?? 0
        let succeeded = error == nil && statusCode > 0 && statusCode < 500
        lock.lock()
        if succeeded {
          successCount += 1
        } else {
          failureCount += 1
        }
        if error != nil {
          transportErrorCount += 1
        }
        if statusCode >= 500 || statusCode == 0 {
          serverErrorCount += 1
        }
        lock.unlock()
        group.leave()
      }.resume()
    }

    group.notify(queue: .main) {
      session.invalidateAndCancel()
      fields["external_leak_audit_success_count"] = successCount
      fields["external_leak_audit_failure_count"] = failureCount
      fields["external_leak_audit_transport_error_count"] = transportErrorCount
      fields["external_leak_audit_server_error_count"] = serverErrorCount
      fields["external_leak_audit_passed"] =
        successCount == request.urls.count &&
        failureCount == 0 &&
        request.urls.count >= request.minimumEndpointCount
      completion(fields)
    }
  }

  private static func rawUrlValues(_ rawValue: Any?) -> [String] {
    if let values = rawValue as? [String] {
      return values.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        .filter { !$0.isEmpty }
    }
    if let values = rawValue as? [Any] {
      return values.map { String(describing: $0).trimmingCharacters(in: .whitespacesAndNewlines) }
        .filter { !$0.isEmpty }
    }
    let raw = (rawValue as? String)?
      .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    guard !raw.isEmpty else {
      return []
    }
    return raw.split { character in
      character == "," || character == ";" || character.isWhitespace
    }
    .map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
    .filter { !$0.isEmpty }
  }

  private static func safeCanaryUrl(from rawValue: String) -> URL? {
    let raw = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !raw.isEmpty,
          raw.count <= maxUrlLength,
          raw.rangeOfCharacter(from: .whitespacesAndNewlines) == nil,
          raw.rangeOfCharacter(from: .controlCharacters) == nil,
          let url = URL(string: raw),
          url.scheme?.lowercased() == "https",
          url.user == nil,
          url.password == nil,
          let host = url.host?.trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased(),
          !host.isEmpty,
          !hostLooksLocal(host),
          !hostLooksLikeIPAddress(host),
          !hostLooksBlocked(host) else {
      return nil
    }
    return url
  }

  private static func hostLooksLocal(_ host: String) -> Bool {
    host == "localhost" ||
      host.hasSuffix(".localhost") ||
      host.hasSuffix(".local") ||
      host.hasSuffix(".lan") ||
      host.hasSuffix(".home") ||
      host.hasSuffix(".internal")
  }

  private static func hostLooksLikeIPAddress(_ host: String) -> Bool {
    if host.contains(":") {
      return true
    }
    return host.range(
      of: #"^\d{1,3}(?:\.\d{1,3}){3}$"#,
      options: .regularExpression
    ) != nil
  }

  private static func hostLooksBlocked(_ host: String) -> Bool {
    blockedHostFragments.contains { host.contains($0) }
  }
}

struct WinsAppleNotificationPayload {
  let title: String
  let body: String
}

struct WinsAppleSharePayload {
  let title: String?
  let text: String
}

enum WinsAppleText {
  static func boundedText(
    _ rawValue: String?,
    fallback: String,
    maxLength: Int
  ) -> String {
    let trimmed = rawValue?
      .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    let value = trimmed.isEmpty ? fallback : trimmed
    guard value.count > maxLength, maxLength > 3 else {
      return value
    }
    return "\(value.prefix(maxLength - 3))..."
  }
}

enum WinsAppleShare {
  static let maxTitleLength = 80
  static let maxTextLength = 4_000

  static func sharePayload(
    title rawTitle: String?,
    text rawText: String?
  ) -> WinsAppleSharePayload? {
    let text = WinsAppleText.boundedText(
      rawText,
      fallback: "",
      maxLength: maxTextLength
    )
    guard !text.isEmpty else {
      return nil
    }
    let title = WinsAppleText.boundedText(
      rawTitle,
      fallback: "",
      maxLength: maxTitleLength
    )
    return WinsAppleSharePayload(title: title.isEmpty ? nil : title, text: text)
  }
}

enum WinsAppleReadiness {
  static func bool(_ fields: [String: Any], _ key: String) -> Bool {
    guard let value = fields[key] else {
      return false
    }
    if let boolValue = value as? Bool {
      return boolValue
    }
    if let intValue = value as? Int {
      return intValue != 0
    }
    return String(describing: value)
      .trimmingCharacters(in: .whitespacesAndNewlines)
      .lowercased() == "true"
  }

  static func int(_ fields: [String: Any], _ key: String) -> Int {
    guard let value = fields[key] else {
      return 0
    }
    if let intValue = value as? Int {
      return intValue
    }
    if let numberValue = value as? NSNumber,
       CFGetTypeID(numberValue) != CFBooleanGetTypeID() {
      return numberValue.intValue
    }
    return Int(
      String(describing: value)
        .trimmingCharacters(in: .whitespacesAndNewlines)
    ) ?? 0
  }

  static func string(_ fields: [String: Any], _ key: String) -> String {
    guard let value = fields[key] else {
      return ""
    }
    return String(describing: value)
      .trimmingCharacters(in: .whitespacesAndNewlines)
  }

  static func providerSchemaUnsupported(_ fields: [String: Any]) -> Bool {
    let supported = string(fields, "provider_status_schema_supported")
    return bool(fields, "provider_status_schema_unsupported") ||
      (!supported.isEmpty && !bool(fields, "provider_status_schema_supported"))
  }

  static func providerSchemaSupported(_ fields: [String: Any]) -> Bool {
    bool(fields, "provider_status_schema_supported") &&
      !bool(fields, "provider_status_schema_unsupported")
  }

  static func providerStatusCurrent(_ fields: [String: Any]) -> Bool {
    bool(fields, "provider_status_available") &&
      providerSchemaSupported(fields) &&
      !bool(fields, "provider_status_stale") &&
      !bool(fields, "provider_status_bundle_mismatch") &&
      !bool(fields, "provider_status_extension_type_mismatch") &&
      !bool(fields, "provider_status_timestamp_invalid") &&
      !bool(fields, "provider_status_stage_invalid") &&
      !providerSchemaUnsupported(fields)
  }

  static func fullTunnelLeakProtectionConfigFields(_ fields: [String: Any]) -> [String: Any] {
    let providerCurrent = providerStatusCurrent(fields)
    let defaultRouteEnabled = bool(fields, "provider_default_route_enabled")
    let providerIPv6Protection = bool(fields, "provider_ipv6_leak_protection_enabled")
    let engineIPv6Protection = bool(fields, "provider_engine_ipv6_leak_protection_enabled")
    let providerDNSFullTunnel = bool(fields, "provider_dns_full_tunnel_match_enabled")
    let engineDNSFullTunnel = bool(fields, "provider_engine_full_tunnel_dns_match_enabled")
    let providerDNSCount = int(fields, "provider_dns_count")
    let engineDNSCount = int(fields, "provider_engine_dns_server_count")
    // DEV-ONLY CONTAINMENT, TREATED AS A HARD FAIL.
    //
    // Every field above describes what the CONFIG asked for. A contained dev
    // session's config still says full tunnel — it carries `0.0.0.0/0, ::/0`
    // and full-tunnel DNS — while the Debug-only provider deliberately installs
    // none of it. Without this term the six checks above would all read true and
    // `leak_protection_config_passed` would claim a validated full-tunnel
    // posture for a session that installed a single /32 and no DNS at all. That
    // is the exact confusion this term exists to make impossible.
    //
    // PRODUCTION IS UNAFFECTED. A Release appex never writes
    // `dev_containment_active`, so this reads false and `passed` is computed
    // from precisely the same eight terms as before. This can only ever make
    // `passed` MORE false, never less.
    let devContainmentActive = bool(fields, "provider_dev_containment_active")
    let passed = providerCurrent &&
      defaultRouteEnabled &&
      providerIPv6Protection &&
      engineIPv6Protection &&
      providerDNSFullTunnel &&
      engineDNSFullTunnel &&
      providerDNSCount > 0 &&
      engineDNSCount > 0 &&
      !devContainmentActive
    return [
      "leak_protection_config_checked": true,
      // A contained dev session reports a DIFFERENT kind, not merely a failing
      // full-tunnel one. "full_tunnel_route_dns_ipv6 / passed: false" is what a
      // real leak-protection regression looks like, and a developer who sees it
      // every time they run a contained session learns to ignore exactly the
      // signal that matters in production. Naming the contained case makes the
      // two distinguishable at a glance. Production is untouched: without
      // `provider_dev_containment_active` this is the original string.
      "leak_protection_config_kind": devContainmentActive
        ? "dev_contained_not_full_tunnel"
        : "full_tunnel_route_dns_ipv6",
      "leak_protection_provider_status_current": providerCurrent,
      "leak_protection_default_route_enabled": defaultRouteEnabled,
      "leak_protection_ipv6_enabled": providerIPv6Protection,
      "leak_protection_engine_ipv6_enabled": engineIPv6Protection,
      "leak_protection_dns_full_tunnel_match_enabled": providerDNSFullTunnel,
      "leak_protection_engine_dns_full_tunnel_match_enabled": engineDNSFullTunnel,
      "leak_protection_dns_server_count": providerDNSCount,
      "leak_protection_engine_dns_server_count": engineDNSCount,
      "leak_protection_dev_containment_active": devContainmentActive,
      "leak_protection_config_passed": passed
    ]
  }

  static func providerAppMessageStatusTrusted(_ fields: [String: Any]) -> Bool {
    guard string(fields, "provider_stage") == "app_message" else {
      return true
    }
    let statusMessageTrusted = bool(fields, "provider_app_message_accepted") &&
      bool(fields, "provider_app_message_command_is_health") &&
      bool(fields, "provider_app_message_raw_payload_redacted")
    let probeMessageTrusted = bool(fields, "provider_message_probe_healthy") &&
      bool(fields, "provider_message_probe_engine_running")
    return statusMessageTrusted || probeMessageTrusted
  }

  static func providerLifecycleStatusTrusted(_ fields: [String: Any]) -> Bool {
    string(fields, "provider_stage") != "sleeping" &&
      !bool(fields, "provider_lifecycle_suspended")
  }

  static func providerReady(_ fields: [String: Any]) -> Bool {
    let active = bool(fields, "active") || string(fields, "status") == "connected"
    let providerMessageProbeAttempted = bool(fields, "provider_message_probe_attempted")
    let providerMessageProbeHealthy = bool(fields, "provider_message_probe_healthy")
    let providerMessageProbeEngineRunning = bool(fields, "provider_message_probe_engine_running")
    let providerEngineReady = bool(fields, "provider_engine_ready") ||
      (providerMessageProbeHealthy && providerMessageProbeEngineRunning)
    let providerNetworkReady = bool(fields, "provider_network_settings_applied") ||
      bool(fields, "provider_network_settings_ready") ||
      (active && providerMessageProbeHealthy)
    let providerHealthy = bool(fields, "provider_healthy") ||
      (providerMessageProbeHealthy && providerEngineReady && providerNetworkReady)
    return active &&
      providerStatusCurrent(fields) &&
      providerEngineReady &&
      providerNetworkReady &&
      providerHealthy &&
      providerAppMessageStatusTrusted(fields) &&
      providerLifecycleStatusTrusted(fields) &&
      (!providerMessageProbeAttempted || providerMessageProbeHealthy)
  }
}

enum WinsAppleNotification {
  static let defaultTitle = "Win's VPN Announcement"
  static let maxTitleLength = 80
  static let maxBodyLength = 900

  static func announcementPayload(
    title rawTitle: String?,
    body rawBody: String?
  ) -> WinsAppleNotificationPayload? {
    let title = boundedText(
      rawTitle,
      fallback: defaultTitle,
      maxLength: maxTitleLength
    )
    let body = boundedText(
      rawBody,
      fallback: "",
      maxLength: maxBodyLength
    )
    guard !body.isEmpty else {
      return nil
    }
    return WinsAppleNotificationPayload(title: title, body: body)
  }

  static func boundedText(
    _ rawValue: String?,
    fallback: String,
    maxLength: Int
  ) -> String {
    WinsAppleText.boundedText(rawValue, fallback: fallback, maxLength: maxLength)
  }
}

enum WinsTunnelDiagnostics {
  static let maxControlledErrorMessageLength = 240
  static let redactedAppleSystemErrorMessage =
    "Apple system error occurred. See native error domain and code."
  static let redactedProviderSystemErrorMessage =
    "Apple system error occurred. See provider_error_domain and provider_error_code."
  static let redactedSystemErrorMessage = redactedProviderSystemErrorMessage

  static func redactedAppleErrorMessage(_ error: Error) -> String {
    let nsError = error as NSError
    if nsError.domain.hasPrefix("org.winsvpn."),
       let safeMessage = safeControlledErrorMessage(nsError.localizedDescription) {
      return safeMessage
    }
    return redactedAppleSystemErrorMessage
  }

  static func nativeErrorDetails(_ error: Error) -> [String: Any] {
    let nsError = error as NSError
    return [
      "native_error_domain": nsError.domain,
      "native_error_code": nsError.code
    ]
  }

  static func redactedAppleErrorFields(_ error: Error) -> [String: Any] {
    var fields = nativeErrorDetails(error)
    fields["error"] = redactedAppleErrorMessage(error)
    return fields
  }

  static func redactedProviderErrorMessage(_ error: Error) -> String {
    let nsError = error as NSError
    if nsError.domain.hasPrefix("org.winsvpn."),
       let safeMessage = safeControlledErrorMessage(nsError.localizedDescription) {
      return safeMessage
    }
    return redactedProviderSystemErrorMessage
  }

  private static func safeControlledErrorMessage(_ rawMessage: String) -> String? {
    let message = rawMessage.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !message.isEmpty,
          message.count <= maxControlledErrorMessageLength,
          message.rangeOfCharacter(from: .controlCharacters) == nil,
          !containsUnsafeControlledErrorFragment(message) else {
      return nil
    }
    return message
  }

  private static func containsUnsafeControlledErrorFragment(_ message: String) -> Bool {
    let lower = message.lowercased()
    let rawFragments = [
      "/users/",
      "/var/",
      "/private/",
      "/tmp/",
      "/etc/",
      "group containers",
      "latest_tunnel.conf",
      "latest_status.json",
      "privatekey",
      "private key",
      "presharedkey",
      "preshared key",
      "endpoint =",
      "publickey =",
      "allowedips =",
      "address =",
      "http://",
      "https://",
      "file://"
    ]
    guard !rawFragments.contains(where: { lower.contains($0) }) else {
      return true
    }
    return matches(message, #"(?<![0-9])(?:\d{1,3}\.){3}\d{1,3}(?![0-9])"#) ||
      matches(
        message,
        #"(^|[^A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?=$|[^A-Za-z0-9_-])"#
      ) ||
      containsIPv6Literal(message) ||
      matches(
        message,
        #"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"#
      )
  }

  private static func containsIPv6Literal(_ message: String) -> Bool {
    let pattern = #"(^|[^A-Za-z0-9])((?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f]{0,4})(?=$|[^A-Za-z0-9])"#
    guard let regex = try? NSRegularExpression(pattern: pattern) else {
      return false
    }
    let range = NSRange(message.startIndex..<message.endIndex, in: message)
    for match in regex.matches(in: message, range: range) {
      guard match.numberOfRanges > 2,
            let candidateRange = Range(match.range(at: 2), in: message) else {
        continue
      }
      let candidate = String(message[candidateRange])
      let colonCount = candidate.filter { $0 == ":" }.count
      if candidate.contains("::") || colonCount >= 3 {
        return true
      }
    }
    return false
  }

  private static func matches(_ value: String, _ pattern: String) -> Bool {
    value.range(of: pattern, options: .regularExpression) != nil
  }
}
