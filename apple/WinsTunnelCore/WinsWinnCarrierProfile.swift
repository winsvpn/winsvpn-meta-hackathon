import Foundation
import Security

/// The carrier profile document `WinnTunnelCreateWithCarrier` reads as its
/// second C string.
///
/// THE SCHEMA IS THE ENGINE'S, NOT THIS FILE'S. Every key this type emits is a
/// field of `carrierhost.Profile` in
/// `winn_protocol_experimental/datapath/carrierhost/profile.go`, which decodes
/// with `DisallowUnknownFields` and refuses a document that does not declare
/// `profileVersion`. A misspelled key is therefore a hard refusal in the
/// engine, not a silent default -- so this type emits those keys and nothing
/// else. It is the Apple sibling of
/// `android/app/src/main/kotlin/org/winsvpn/app/WinnCarrierProfile.kt` and
/// `linux/runner/linux_winn_host.cc`'s `LinuxWinnCarrierProfile`; field order
/// in `toJSON()` matches both, so the three platforms' documents can be
/// compared byte for byte in review.
///
/// # Why a string, and not a file
///
/// Android and Windows spawn the engine as a SUBPROCESS speaking the framed
/// duplex protocol, so the child has argv and a filesystem, and the profile
/// travels as a file path named on argv -- see the Kotlin type's doc comment.
/// iOS and macOS reach the datapath through the C ABI in
/// `winn_protocol_experimental/cdatapath/`, which has neither: there is no
/// child process to hand a path to, only one process linking a Go archive
/// in-process. `WinnTunnelCreateWithCarrier` therefore takes the document as a
/// second C string, exactly the way `WinnTunnelCreate` already takes
/// `datapath.Config` as one.
///
/// This is not a weaker version of "deliver it as a path". The reason a path
/// was chosen on Android and Linux is stated explicitly in both of their
/// sources: "a path is a reference the child resolves under its own
/// authority, whereas an authenticated configuration inlined into a frame
/// would be material the child had to trust because the peer said so." On
/// Apple there is no child and no peer -- Swift and the Go archive run in the
/// same process, the same sandbox, the same uid, and Swift already trusts Go
/// completely by linking it in-process. Writing this document to a file and
/// having the SAME process read it back immediately would add a disk
/// round-trip, a cleanup obligation, and a class of TOCTOU and leftover-file
/// risk, for a trust boundary that does not exist here. Moving the bytes in
/// memory is not merely adequate, it is strictly safer.
///
/// # Key material never appears in this document
///
/// Every secret -- the device ML-DSA seed, the client private key -- is named
/// by PATH and read by the loader that already owns that file format
/// (`pqauth.LoadSigner`, `tlsconfig.Client*`, both in Go). This type never
/// opens a credential file, never parses one, and never holds one in memory:
/// `CredentialSet.resolve` checks that each exists, is a regular file (not a
/// symbolic link), is non-empty and is readable, and writes only its path.
/// That the ENGINE, not this process, does the opening is proven by
/// `winn_protocol_experimental/cdatapath/winn_datapath_carrier_test.go`,
/// whose credential-less-profile test fails on a file this Go test process
/// never touched.
///
/// The document this type builds is still secret-ADJACENT -- it names every
/// private credential file on this device -- so `toJSON()`'s result must never
/// be logged. Use `describeForLog()`.
struct WinsWinnCarrierProfile {
  // MARK: - Constants shared with the Go schema, Kotlin and C++

  /// `carrierhost.ProfileVersion`.
  static let profileVersion = "winn-carrier-profile/1"

  /// `connectivity.CarrierHTTP3`.
  static let carrierHTTP3 = "http3-connect-udp"

  /// `connectivity.CarrierHTTP2`. Never built here -- see `from(section:...)`.
  static let carrierHTTP2 = "http2-stream"

  /// `carrierauth.AuthModeIdentity`. The only mode `carrierhost` builds.
  static let authModeIdentity = "identity"

  static let privacyStandard = "standard"
  static let privacyHighRisk = "high-risk"

  /// `tlsconfig.ParseSuite`'s hybrid post-quantum groups.
  ///
  /// LOAD-BEARING, not defensive duplication. `carrierhost.normalize` checks
  /// only that `suite` is non-empty; `ParseSuite` runs inside `BuildDialer`,
  /// which the engine calls at create time -- after this host has already
  /// opened and protected the outer socket (`allow_own_socket`). Refusing an
  /// unrecognised suite here keeps the failure before that point, exactly as
  /// `WinnCarrierProfile.kt`'s identical allowlist does on Android.
  static let supportedSuites: Set<String> = [
    "x25519-mlkem768", "p256-mlkem768", "p384-mlkem1024"
  ]

  /// `pqauth.MLDSA65` / `MLDSA87`'s wire spellings.
  static let supportedDeviceAlgorithms: Set<String> = ["mldsa65", "mldsa87"]

  static let minInnerDatagram = 32
  static let maxInnerDatagram = 1500

  /// The `[winn]` keys that describe a carrier. Consumed here and never
  /// forwarded into `datapath.Config`, whose decoder would reject every one of
  /// them. Mirrors `WinnCarrierProfile.CARRIER_KEYS` on Android and the last
  /// eleven of `linux_winn_host.cc`'s `kKnownKeys`.
  /// NOT WRITTEN HERE ANY MORE. `WinsWinnCarrierProfileKeys.served` is
  /// generated from `carrierhost.Profile`'s own json tags, and
  /// `carrierhost.TestGeneratedPlatformKeyFilesAreCurrent` fails an ordinary
  /// `go test ./...` if it drifts.
  ///
  /// This used to be a hand-typed list, one of four identical copies across
  /// Swift, Kotlin, Dart and C++. That all four agreed with each other is
  /// exactly why nobody noticed that none of them agreed with the schema:
  /// `carrierhost.Profile` grew five `spa_*` fields, every copy silently
  /// excluded them, nothing failed anywhere, and single packet authorization
  /// was unreachable from every platform at once.
  static let carrierProfileKeys: Set<String> = WinsWinnCarrierProfileKeys.served

  /// `knock.HeaderSize` (a 16-byte nonce plus a 32-byte tag) and
  /// `carrier.AbsoluteMaxDatagram`. A knock is ONE unfragmented datagram: a
  /// censor that already drops or flags fragmented UDP would turn the knock
  /// into a worse fingerprint than having no SPA at all.
  static let minSPAPacketSize = 48
  static let maxSPAPacketSize = 1500

  /// Where the six credential files live, relative to the App Group
  /// container. Matches Android's `filesDir/winn/credentials` and Linux's
  /// private-state-directory layout in file NAME, so provisioning tooling can
  /// use one name per credential across every platform.
  static let credentialDirectoryComponents = ["winn", "credentials"]

  // MARK: - Stored fields (mirror carrierhost.Profile)

  let carrier: String
  let masqueTemplate: String
  let publicTarget: String
  let serverName: String
  let suite: String
  let controllerID: String
  let credentials: ResolvedCredentials
  let deviceID: String
  let deviceAlgorithm: String
  let sessionID: String
  let sequenceEpoch: String
  let manifestDigest: String
  let maxInnerDatagramValue: Int
  let privacyProfile: String

  /// The ACTIVE single-packet-authorization configuration, or nil when SPA is
  /// off. Its existence is the mode -- see `ResolvedSPA`.
  let spa: ResolvedSPA?

  /// The six credential files, resolved to absolute paths. Never their
  /// contents -- see `CredentialSet.resolve`.
  struct ResolvedCredentials {
    let controllerPins: String
    let rootCA: String
    let echConfigList: String
    let deviceSeed: String
    let clientCert: String
    let clientKey: String
  }

  /// An ACTIVE single-packet-authorization configuration.
  ///
  /// Its existence is the mode: a non-nil `ResolvedSPA` means `spa_mode` is
  /// "required", and nil means the fields are not emitted at all. Modelling it
  /// as an optional rather than as a mode string beside five loose fields is
  /// what makes "half-enabled SPA" unrepresentable here -- the engine refuses
  /// that combination, and a shape that cannot express it cannot produce it.
  ///
  /// `keyPath` is a PATH and never key material. Nothing in this type opens it.
  ///
  /// The three scalars are zero when the served config did not name them,
  /// meaning "use the engine's own derived or default value" -- the same
  /// meaning zero has in `carrierhost.Profile`.
  struct ResolvedSPA {
    let keyPath: String
    let target: String
    let packetSize: Int
    let bucketWindowSeconds: Int
    let maxSkewSeconds: Int
  }

  /// The document. Contains no key material -- only paths -- but names every
  /// private file this device holds, so it must never be logged. Field order
  /// matches `WinnCarrierProfile.toJson()` (Kotlin) and
  /// `BuildLinuxWinnCarrierProfileJson()` (C++) exactly.
  func toJSON() -> String {
    var fields: [(String, String, quoted: Bool)] = []
    fields.append(("profile", Self.profileVersion, true))
    fields.append(("carrier", carrier, true))
    // masque_template is HTTP/3 only, and h2_url set on an HTTP/3 profile is
    // ErrCarrierFieldMismatch, so the field belonging to the other carrier is
    // never emitted rather than emitted empty.
    if carrier == Self.carrierHTTP3 {
      fields.append(("masque_template", masqueTemplate, true))
    }
    fields.append(("public_target", publicTarget, true))
    fields.append(("server_name", serverName, true))
    fields.append(("suite", suite, true))
    fields.append(("controller_id", controllerID, true))
    fields.append(("controller_pins_path", credentials.controllerPins, true))
    fields.append(("root_ca_path", credentials.rootCA, true))
    fields.append(("ech_config_list_path", credentials.echConfigList, true))
    fields.append(("authorization_mode", Self.authModeIdentity, true))
    fields.append(("device_id", deviceID, true))
    fields.append(("device_pq_algorithm", deviceAlgorithm, true))
    fields.append(("device_seed_path", credentials.deviceSeed, true))
    fields.append(("client_cert_path", credentials.clientCert, true))
    fields.append(("client_key_path", credentials.clientKey, true))
    fields.append(("session_id", sessionID, true))
    if !sequenceEpoch.isEmpty {
      fields.append(("sequence_epoch", sequenceEpoch, true))
    }
    fields.append(("manifest_digest", manifestDigest, true))
    fields.append(("max_inner_datagram", String(maxInnerDatagramValue), false))
    fields.append(("privacy_profile", privacyProfile, true))
    // SINGLE PACKET AUTHORIZATION. Emitted only when it is actually on, so
    // every field below is inside the optional binding rather than emitted
    // empty.
    //
    // Be exact about why. `carrierhost.normalizeSPA` REFUSES a document that
    // carries a NON-EMPTY `spa_` field while the mode is off or absent
    // (`ErrSPAFieldWithoutMode`), because a stray target left behind after SPA
    // was turned off is the operator believing something is armed that is not.
    // It does NOT refuse an empty one: the stray sweep tests
    // `TrimSpace(...) != ""` for strings and `!= 0` for the scalars, so
    // `"spa_mode":"off"` and `"spa_target":""` parse fine and are
    // indistinguishable from absent. An earlier version of this comment claimed
    // they were a hard parse failure; that was checked against ParseProfile and
    // is false. Omitting is still the rule, because a document with no `spa_`
    // substring cannot be misread, and because the failure that IS real is
    // one-sided: a non-empty stray refuses the whole profile, and an emitter
    // that never writes these keys unless SPA is on can never produce one.
    //
    // Field order matches `carrierhost.Profile`'s own declaration order, and
    // `WinnCarrierProfile.toJson()` on Android.
    if let spa {
      fields.append(("spa_mode", WinsWinnCarrierProfileKeys.spaModeRequired, true))
      // A PATH, never the key. This type resolves it from the credential
      // directory and never opens it: `knock.LoadKeysFromFile`, the loader that
      // owns the format, reads it inside the engine's BuildDialer.
      fields.append(("spa_key_path", spa.keyPath, true))
      fields.append(("spa_target", spa.target, true))
      // Zero means "use the engine's derived or default value" for each of
      // these, and the engine does exactly that, so omitting is identical to
      // sending 0 and produces a smaller document.
      if spa.packetSize != 0 {
        fields.append(("spa_packet_size", String(spa.packetSize), false))
      }
      if spa.bucketWindowSeconds != 0 {
        fields.append(
          ("spa_bucket_window_seconds", String(spa.bucketWindowSeconds), false))
      }
      if spa.maxSkewSeconds != 0 {
        fields.append(("spa_max_skew_seconds", String(spa.maxSkewSeconds), false))
      }
    }
    // manifest_path is NEVER emitted. Naming a manifest makes carrierhost
    // refuse the profile outright (ErrManifestRouteUnimplemented) rather than
    // reading this document's own transport fields and calling them verified.

    var text = "{"
    for (index, field) in fields.enumerated() {
      if index > 0 { text += "," }
      text += Self.jsonString(field.0) + ":"
      text += field.quoted ? Self.jsonString(field.1) : field.1
    }
    text += "}"
    return text
  }

  /// Key names, modes and scalars only -- never a path, because a path names a
  /// private file. Safe to log; `toJSON()` is not.
  func describeForLog() -> String {
    "winn carrier profile: version=\(Self.profileVersion) carrier=\(carrier) " +
      "suite=\(suite) mode=\(Self.authModeIdentity) privacy=\(privacyProfile) " +
      "pq_algorithm=\(deviceAlgorithm) max_inner_datagram=\(maxInnerDatagramValue) " +
      "manifest_verified=false " +
      // The MODE only. Never the key path, never the target: the path names a
      // credential file and the target names a host that is supposed to be
      // invisible, and the whole point of SPA is that neither is discoverable
      // from this device's logs. Matches `carrierhost.Profile.DescribeForLog`,
      // which prints the same one field for the same reason.
      "spa=\(spa == nil ? WinsWinnCarrierProfileKeys.spaModeOff : WinsWinnCarrierProfileKeys.spaModeRequired)"
  }

  // MARK: - Construction

  /// Builds and validates the profile for a `[winn]` section whose carrier is
  /// not direct-awg.
  ///
  /// - Parameters:
  ///   - section: the `[winn]` INI section.
  ///   - carrier: the carrier `WinsTunnelConfig.validate()` already accepted.
  ///     Passed in rather than re-read from `section` so the two can never
  ///     disagree about which carrier this session is.
  ///   - credentialDirectory: where the six credential files live.
  ///   - fileManager: injectable for testing; defaults to `.default`.
  /// - Throws: `WinsWinnCarrierProfileError` naming the first field or file
  ///   that is wrong. Never returns a partially built profile.
  static func from(
    section: [String: String],
    carrier: String,
    credentialDirectory: URL,
    fileManager: FileManager = .default
  ) throws -> WinsWinnCarrierProfile {
    guard carrier == carrierHTTP3 else {
      if carrier == carrierHTTP2 {
        // Named specifically rather than lumped in with "unknown". H2 is
        // implemented in the engine and refused HERE, and the reason is a
        // host capability, not a protocol gap -- the same distinction
        // WinnCarrierProfile.kt draws.
        throw WinsWinnCarrierProfileError(
          "Winn carrier '\(carrierHTTP2)' needs a CONNECTED, protected TCP " +
            "socket. This host opens one UNCONNECTED UDP socket for the outer " +
            "transport, which is what \(carrierHTTP3) takes. Building an H2 " +
            "profile would produce a dialer the engine then refuses for a " +
            "socket-kind mismatch, so it is refused here where the reason can " +
            "be stated."
        )
      }
      throw WinsWinnCarrierProfileError(
        "Winn carrier '\(carrier)' has no carrier profile; only \(carrierHTTP3) does"
      )
    }

    let masqueTemplate = trimmed(section["masque_template"])
    guard isAbsoluteHTTPSURL(masqueTemplate) else {
      throw WinsWinnCarrierProfileError(
        "Winn masque_template must be an absolute https URL naming a host"
      )
    }

    let publicTarget = trimmed(section["public_target"])
    // The proxy resolves this, not the device, so the DNS-leak rule that
    // governs the gateway endpoint does not apply -- but the AmneziaWG
    // gateway is named by address everywhere else in this client and a
    // hostname here would be a second, silent naming scheme. carrierhost
    // enforces the same rule.
    guard isIPLiteralEndpoint(publicTarget) else {
      throw WinsWinnCarrierProfileError(
        "Winn public_target must be an IP literal with a port, not a hostname"
      )
    }

    let serverName = trimmed(section["server_name"])
    guard !serverName.isEmpty, serverName.utf8.count <= 253,
          !serverName.contains(where: { $0.isWhitespace || $0 == "\"" || $0 == "\\" })
    else {
      throw WinsWinnCarrierProfileError(
        "Winn server_name is required and must be a host name; it is the " +
          "inner ClientHello name the carrier certificate must match"
      )
    }

    let suite = trimmed(section["suite"]).lowercased()
    guard supportedSuites.contains(suite) else {
      throw WinsWinnCarrierProfileError(
        "Winn suite '\(suite)' is not a hybrid post-quantum group this engine " +
          "offers; refusing rather than letting the session negotiate a " +
          "weaker one. The engine does not check this until create time, by " +
          "which point a protected socket has already been handed to it."
      )
    }

    let controllerID = trimmed(section["controller_id"])
    guard !controllerID.isEmpty, controllerID.utf8.count <= 128 else {
      throw WinsWinnCarrierProfileError(
        "Winn controller_id is required; it identifies the controller whose " +
          "ML-DSA signature every carrier response must carry"
      )
    }

    let deviceID = trimmed(section["device_id"])
    guard !deviceID.isEmpty, deviceID.utf8.count <= 128 else {
      throw WinsWinnCarrierProfileError("Winn device_id is required in identity mode")
    }

    let deviceAlgorithm = trimmed(section["device_pq_algorithm"]).lowercased()
    guard supportedDeviceAlgorithms.contains(deviceAlgorithm) else {
      throw WinsWinnCarrierProfileError(
        "Winn device_pq_algorithm must name the ML-DSA parameter set the " +
          "device key was generated for"
      )
    }

    let manifestDigest = trimmed(section["manifest_digest"]).lowercased()
    guard isLowercaseHex(manifestDigest, length: 64) else {
      throw WinsWinnCarrierProfileError(
        "Winn manifest_digest must be 64 lowercase hexadecimal characters; " +
          "the carrier server compares it, so an absent value would silently " +
          "claim a different deployment"
      )
    }

    let sequenceEpoch = trimmed(section["sequence_epoch"]).lowercased()
    guard sequenceEpoch.isEmpty || isLowercaseHex(sequenceEpoch, length: 32) else {
      throw WinsWinnCarrierProfileError(
        "Winn sequence_epoch must be 32 lowercase hexadecimal characters"
      )
    }

    var maxInnerDatagramValue = maxInnerDatagram
    if let raw = section["max_inner_datagram"]?.trimmingCharacters(in: .whitespacesAndNewlines),
       !raw.isEmpty {
      guard let parsed = Int(raw), parsed >= minInnerDatagram, parsed <= maxInnerDatagram else {
        throw WinsWinnCarrierProfileError(
          "Winn max_inner_datagram must be within [\(minInnerDatagram), \(maxInnerDatagram)]"
        )
      }
      maxInnerDatagramValue = parsed
    }

    var privacyProfile = trimmed(section["privacy_profile"]).lowercased()
    if privacyProfile.isEmpty {
      // The zero value pads, matching carrierauth.PrivacyHighRisk / Android's
      // default, so a section that says nothing about padding still gets the
      // defence.
      privacyProfile = privacyHighRisk
    }
    guard privacyProfile == privacyStandard || privacyProfile == privacyHighRisk else {
      throw WinsWinnCarrierProfileError(
        "Winn privacy_profile must be '\(privacyStandard)' or '\(privacyHighRisk)'"
      )
    }

    // SINGLE PACKET AUTHORIZATION.
    //
    // Parsed before the credentials so a malformed spa_ field fails on itself
    // rather than on a knock key that is merely absent, and so the `spa_mode`
    // off path never touches the credential directory at all.
    //
    // No http3-versus-http2 check is needed here: this whole method already
    // refuses every carrier but `carrierHTTP3` at its first statement, which is
    // strictly stronger than the engine's own SPA rule
    // (`ErrSPAStreamCarrierUnsupported`).
    let spa = try resolvedSPA(
      section: section,
      credentialDirectory: credentialDirectory,
      fileManager: fileManager
    )

    // Resolved LAST, so a malformed section fails on the field that is wrong
    // rather than on credentials that are merely absent -- matches the
    // ordering `WinnCarrierProfile.from` and `ParseLinuxWinnSection` document
    // explicitly.
    let credentials = try CredentialSet.resolve(in: credentialDirectory, fileManager: fileManager)

    return WinsWinnCarrierProfile(
      carrier: carrier,
      masqueTemplate: masqueTemplate,
      publicTarget: publicTarget,
      serverName: serverName,
      suite: suite,
      controllerID: controllerID,
      credentials: credentials,
      deviceID: deviceID,
      deviceAlgorithm: deviceAlgorithm,
      // Generated here, never served. It is bound into every signed carrier
      // request and the server verifies the signature over it rather than
      // pre-agreeing it, so a device-chosen value is both correct and the
      // anti-correlation choice: a session identifier the control plane
      // picked would link the session to the account that fetched the
      // config. Matches WinnCarrierProfile.kt's newSessionId().
      sessionID: try newSessionID(),
      sequenceEpoch: sequenceEpoch,
      manifestDigest: manifestDigest,
      maxInnerDatagramValue: maxInnerDatagramValue,
      privacyProfile: privacyProfile,
      spa: spa
    )
  }

  /// The active SPA configuration a `[winn]` section asks for, or nil when it
  /// asks for none.
  ///
  /// - Throws: `WinsWinnCarrierProfileError` naming the first field or file
  ///   that is wrong.
  static func resolvedSPA(
    section: [String: String],
    credentialDirectory: URL,
    fileManager: FileManager = .default
  ) throws -> ResolvedSPA? {
    let mode = trimmed(section["spa_mode"]).lowercased()
    let otherFieldsPresent = WinsWinnCarrierProfileKeys.spa
      .filter { $0 != "spa_mode" }
      .filter { !trimmed(section[$0]).isEmpty }
      .sorted()

    if mode.isEmpty || mode == WinsWinnCarrierProfileKeys.spaModeOff {
      // Refused, not ignored -- `ErrSPAFieldWithoutMode`. A target left behind
      // after SPA was turned off is the operator believing a defence is armed
      // that is not.
      guard otherFieldsPresent.isEmpty else {
        throw WinsWinnCarrierProfileError(
          "Winn \(otherFieldsPresent[0]) is set without spa_mode = " +
            "\(WinsWinnCarrierProfileKeys.spaModeRequired); refusing rather " +
            "than silently ignoring a configured single-packet-authorization " +
            "parameter"
        )
      }
      return nil
    }
    guard mode == WinsWinnCarrierProfileKeys.spaModeRequired else {
      throw WinsWinnCarrierProfileError(
        "Winn spa_mode must be '\(WinsWinnCarrierProfileKeys.spaModeOff)' or " +
          "'\(WinsWinnCarrierProfileKeys.spaModeRequired)'"
      )
    }

    let target = trimmed(section["spa_target"])
    // No default, deliberately: the gate may sit in front of the carrier
    // listener or in front of the AmneziaWG gateway, and a wrong guess sends
    // the deployment's shared credential to a host that is not supposed to
    // have it.
    guard isIPLiteralEndpoint(target) else {
      throw WinsWinnCarrierProfileError(
        "Winn spa_target is required when spa_mode is " +
          "\(WinsWinnCarrierProfileKeys.spaModeRequired), and must be an IP " +
          "literal with a port, not a hostname"
      )
    }

    let packetSize = try spaScalar(section, "spa_packet_size")
    guard packetSize == 0 ||
            (packetSize >= minSPAPacketSize && packetSize <= maxSPAPacketSize)
    else {
      throw WinsWinnCarrierProfileError(
        "Winn spa_packet_size must be within [\(minSPAPacketSize), \(maxSPAPacketSize)]"
      )
    }
    let bucket = try spaScalar(section, "spa_bucket_window_seconds")
    let skew = try spaScalar(section, "spa_max_skew_seconds")
    // `knock.Options.resolve`: a bucket is at least a second and the skew is at
    // least a bucket. A pair that violates this produces a knock that silently
    // never verifies, which looks identical to a wrong key -- so it is refused
    // where the reason can still be stated.
    guard bucket == 0 || bucket >= 1 else {
      throw WinsWinnCarrierProfileError(
        "Winn spa_bucket_window_seconds must be at least 1 second"
      )
    }
    guard skew == 0 || bucket == 0 || skew >= bucket else {
      throw WinsWinnCarrierProfileError(
        "Winn spa_max_skew_seconds must be at least spa_bucket_window_seconds"
      )
    }

    return ResolvedSPA(
      keyPath: try CredentialSet.resolveSPAKey(
        in: credentialDirectory, fileManager: fileManager
      ),
      target: target,
      packetSize: packetSize,
      bucketWindowSeconds: bucket,
      maxSkewSeconds: skew
    )
  }

  /// An optional non-negative `spa_` scalar. Zero means absent, which is the
  /// same thing zero means in `carrierhost.Profile`: use the engine's own
  /// derived or default value.
  private static func spaScalar(
    _ section: [String: String], _ key: String
  ) throws -> Int {
    let raw = trimmed(section[key])
    if raw.isEmpty { return 0 }
    guard let parsed = Int(raw), parsed >= 0 else {
      throw WinsWinnCarrierProfileError(
        "Winn \(key) must be a non-negative whole number"
      )
    }
    return parsed
  }

  /// `mobility.ValidSessionID`: 32 lowercase hexadecimal characters, drawn
  /// from a CSPRNG (`SecRandomCopyBytes`, the Apple analogue of
  /// `java.security.SecureRandom` in `WinnCarrierProfile.kt`).
  static func newSessionID() throws -> String {
    var bytes = [UInt8](repeating: 0, count: 16)
    let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
    guard status == errSecSuccess else {
      throw WinsWinnCarrierProfileError(
        "Winn carrier profile session id could not be generated (SecRandomCopyBytes status \(status))"
      )
    }
    return bytes.map { String(format: "%02x", $0) }.joined()
  }

  private static func trimmed(_ value: String?) -> String {
    (value ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
  }

  private static func isLowercaseHex(_ value: String, length: Int) -> Bool {
    guard value.utf8.count == length else { return false }
    return value.allSatisfy { ("0"..."9").contains($0) || ("a"..."f").contains($0) }
  }

  /// Mirrors `carrierhost.validateAbsoluteHTTPS`: the https scheme and a
  /// non-empty host. Written by hand rather than with `URL` / `URLComponents`
  /// because the RFC 9298 template carries `{target_host}` and
  /// `{target_port}` expansions, which both reject as illegal characters --
  /// the same reason `WinnCarrierProfile.kt` hand-writes this check instead of
  /// using `java.net.URI`.
  static func isAbsoluteHTTPSURL(_ value: String) -> Bool {
    let prefix = "https://"
    guard value.hasPrefix(prefix) else { return false }
    let rest = value.dropFirst(prefix.count)
    guard !rest.isEmpty else { return false }
    let hostEnd = rest.firstIndex { $0 == "/" || $0 == "?" || $0 == "#" }
    let host = hostEnd.map { rest[rest.startIndex..<$0] } ?? rest
    guard !host.isEmpty else { return false }
    return !host.contains { $0.isWhitespace }
  }

  /// Mirrors `carrierhost.validateIPLiteralEndpoint` / `WinnEngineConfig.isIpLiteralEndpoint`:
  /// an IP literal with a nonzero port, not a hostname.
  static func isIPLiteralEndpoint(_ value: String) -> Bool {
    guard let colonIndex = value.lastIndex(of: ":") else { return false }
    let host = String(value[value.startIndex..<colonIndex])
    let portText = String(value[value.index(after: colonIndex)...])
    guard let port = UInt16(portText), port != 0 else { return false }
    guard !host.isEmpty else { return false }
    var address = in6_addr()
    if host.withCString({ inet_pton(AF_INET6, $0, &address) }) == 1 { return true }
    var address4 = in_addr()
    if host.withCString({ inet_pton(AF_INET, $0, &address4) }) == 1 {
      // 0.0.0.0 is unspecified, not a routable literal; reject it the same
      // way carrierhost's netip-based check does.
      return address4.s_addr != 0
    }
    return false
  }

  /// Minimal, deterministic JSON string escaping: quote, backslash, and every
  /// control character below 0x20. Mirrors
  /// `wins_winn_append_json_string` in `WinsWinnPacketEngine.m` exactly, so
  /// the two hand-built JSON builders in this carrier seam agree on what
  /// "escaped" means.
  static func jsonString(_ value: String) -> String {
    var out = "\""
    for scalar in value.unicodeScalars {
      switch scalar {
      case "\"": out += "\\\""
      case "\\": out += "\\\\"
      case "\n": out += "\\n"
      case "\r": out += "\\r"
      case "\t": out += "\\t"
      default:
        if scalar.value < 0x20 {
          out += String(format: "\\u%04x", scalar.value)
        } else {
          out.unicodeScalars.append(scalar)
        }
      }
    }
    out += "\""
    return out
  }

  /// The credential files a carrier profile references, by fixed name inside
  /// one directory. Mirrors `WinnCarrierProfile.CredentialSet` (Kotlin) and
  /// `ResolveLinuxWinnCarrierCredentials` (C++) file for file.
  ///
  /// NONE OF THESE IS PRODUCED BY THIS APP TODAY, on any platform. Provisioning
  /// them is a PKI-and-deployment programme, not code in this repository. So
  /// `resolve` FAILS CLOSED and names the first file that is absent -- the
  /// honest state of every platform that has reached this point: the seam is
  /// wired, the credentials are not there yet.
  enum CredentialSet {
    /// Ordered; the order maps positionally onto `ResolvedCredentials`'s
    /// members. Each entry is (file name, what it is) so a refusal can say
    /// what is missing rather than only that something is. Identical file
    /// names to Android's `CredentialSet.REQUIRED_FILES` and Linux's
    /// `ResolveLinuxWinnCarrierCredentials`.
    static let requiredFiles: [(name: String, purpose: String)] = [
      ("controller_pins.json",
       "the PINNED controller ML-DSA verifier set, the profile's trust anchor"),
      ("winn_root_ca.pem",
       "the Winn CA the carrier certificate must chain to; the system trust " +
         "store is not it"),
      ("ech_config_list.bin",
       "the Encrypted Client Hello config list, without which the TLS " +
         "profile is a single-probe fingerprint"),
      ("device_mldsa_seed.bin", "the device's ML-DSA private seed"),
      ("client_cert.pem", "the mTLS client certificate identity mode requires"),
      ("client_key.pem", "the mTLS client private key")
    ]

    /// - Throws: `WinsWinnCarrierProfileError` naming the first missing,
    ///   empty, symlinked or unreadable file. Never returns a partially
    ///   resolved set.
    static func resolve(
      in directory: URL,
      fileManager: FileManager = .default
    ) throws -> ResolvedCredentials {
      var paths: [String] = []
      for (name, purpose) in requiredFiles {
        paths.append(try checkCredentialFile(
          in: directory, name: name, purpose: purpose, fileManager: fileManager
        ))
      }
      return ResolvedCredentials(
        controllerPins: paths[0], rootCA: paths[1], echConfigList: paths[2],
        deviceSeed: paths[3], clientCert: paths[4], clientKey: paths[5]
      )
    }

    /// The SPA key file's absolute path, or a refusal naming it.
    ///
    /// SEPARATE FROM `resolve` ON PURPOSE. The six files above are needed by
    /// every carrier session; this one is needed only by a session whose served
    /// config turned SPA on. Folding it into `requiredFiles` would make every
    /// existing carrier profile fail on a device with no knock key, which is
    /// every device today.
    ///
    /// IT FAILS CLOSED, and that is the whole reason this exists rather than
    /// the caller simply writing the path. `carrierhost` accepts any non-empty
    /// `spa_key_path` at parse time -- the file is not opened until
    /// `BuildDialer`, at create time, long after the host has opened and
    /// protected the outer socket. So a device with no provisioned key would
    /// build a perfectly valid-looking profile, start a tunnel, and then fail
    /// somewhere the user experiences as "it just doesn't connect". Checking
    /// here converts that into a named refusal before anything is allocated.
    static func resolveSPAKey(
      in directory: URL,
      fileManager: FileManager = .default
    ) throws -> String {
      do {
        return try checkCredentialFile(
          in: directory,
          name: WinsWinnCarrierProfileKeys.spaKeyCredentialFileName,
          purpose: "the single-packet-authorization knock key, a " +
            "deployment-scoped shared secret the operator distributes out of " +
            "band; nothing in this app generates one. Without it the engine " +
            "would send a knock no gate can verify and the connection would " +
            "fail with nothing reporting why",
          fileManager: fileManager
        )
      }
    }

    private static func checkCredentialFile(
      in directory: URL,
      name: String,
      purpose: String,
      fileManager: FileManager
    ) throws -> String {
      let url = directory.appendingPathComponent(name, isDirectory: false)
      let path = url.path

      // A symbolic link is refused outright rather than followed: naming
      // secrets by path is meant to keep this process from ever reading one,
      // and a link would let something outside the credential directory
      // answer for a name inside it. Mirrors Linux's O_NOFOLLOW and is the
      // defensive posture WinsAppGroupFileWriter already uses elsewhere in
      // this file for the same reason.
      if (try? fileManager.destinationOfSymbolicLink(atPath: path)) != nil {
        throw WinsWinnCarrierProfileError(
          "Winn carrier credential '\(name)' (\(purpose)) is a symbolic link, " +
            "which is refused rather than followed. Expected a regular file at: \(path)"
        )
      }

      var isDirectory: ObjCBool = false
      guard fileManager.fileExists(atPath: path, isDirectory: &isDirectory),
            !isDirectory.boolValue
      else {
        throw WinsWinnCarrierProfileError(
          "Winn carrier credential '\(name)' (\(purpose)) is not provisioned " +
            "on this device. The Winn carrier needs a device ML-DSA identity, " +
            "a client certificate issued by the Winn CA, the Winn root CA, an " +
            "ECH config list and the pinned controller verifier set. None of " +
            "these is generated by this app; until they are provisioned, a " +
            "winn/3 session cannot use an authenticated carrier. Refusing " +
            "rather than starting an unauthenticated one. Expected at: \(path)"
        )
      }

      // stat, NOT open. The point of naming secrets by path is that this
      // process never holds them; opening one here to "check" it would defeat
      // exactly that. The engine opens them.
      guard let attributes = try? fileManager.attributesOfItem(atPath: path) else {
        throw WinsWinnCarrierProfileError(
          "Winn carrier credential '\(name)' (\(purpose)) could not be inspected at: \(path)"
        )
      }
      if let size = attributes[.size] as? Int, size <= 0 {
        throw WinsWinnCarrierProfileError(
          "Winn carrier credential '\(name)' (\(purpose)) is empty at: \(path)"
        )
      }
      guard fileManager.isReadableFile(atPath: path) else {
        throw WinsWinnCarrierProfileError(
          "Winn carrier credential '\(name)' (\(purpose)) is present but unreadable at: \(path)"
        )
      }
      return path
    }
  }
}

/// Errors from `WinsWinnCarrierProfile` construction. Never carries key
/// material -- see the type's own doc comment -- but a message may name a
/// credential file PATH, which is why callers must route this into
/// `WinsPacketTunnelEngine`'s existing redaction (`adapterFailure`), never log
/// it directly.
struct WinsWinnCarrierProfileError: LocalizedError, CustomStringConvertible {
  let message: String

  init(_ message: String) {
    self.message = message
  }

  var errorDescription: String? { message }
  var description: String { message }
}
