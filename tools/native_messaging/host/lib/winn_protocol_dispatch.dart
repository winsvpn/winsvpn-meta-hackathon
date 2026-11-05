/// Winn Protocol v3 client-side dispatch policy.
///
/// This decides, for one served `vpn_config`, whether this build can honour a
/// `protocol_version` of `winn/3` -- and if it can, what `[winn]` section the
/// native tunnel config must carry. It is deliberately a pure, top-level
/// library rather than a private method on the app State so it can be tested
/// directly: Dart privacy is per-library, so anything behind a leading
/// underscore in `lib/main.dart` is unreachable from `test/`.
///
/// # The schema is derived, not invented
///
/// Two documents have to agree, and neither of them is this file:
///
///  1. `android/app/src/main/kotlin/org/winsvpn/app/WinnEngineConfig.kt`
///     consumes an INI `[winn]` section. It accepts `enabled`, `endpoint`,
///     `session_id`, `max_datagram`, `carrier`, `h1`..`h4`, `s1`..`s4` and the
///     carrier profile keys in [kWinnCarrierProfileParams], and it THROWS on
///     any other key rather than dropping it.
///  2. `winn_protocol_experimental/datapath/config.go` decodes the JSON that
///     `WinnEngineConfig.toConfigJson()` produces, with
///     `DisallowUnknownFields`, so a misspelled key is a hard create-time
///     error rather than a silent default.
///  3. `winn_protocol_experimental/datapath/carrierhost/profile.go` decodes the
///     SEPARATE carrier profile document that
///     `WinnCarrierProfile.toJson()` produces, also with
///     `DisallowUnknownFields`. It travels as a file path on the engine's argv,
///     never inside a frame.
///
/// Every constant and every rule below is a restatement of one of those three,
/// cited where it matters. This file adds no field of its own.
///
/// # What `winn/3` buys, and what it still does not
///
/// The Winn path always carries `payload:"awg-datagram"`. AmneziaWG keeps the
/// tun and keeps doing all of the cryptography; the Winn datapath relays its
/// already-encrypted OUTER datagrams. What the `carrier` decides is how those
/// datagrams reach the gateway:
///
///  - [kWinnCarrierDirectAwg] sends them straight to the gateway over one
///    host-protected UDP socket. That is a transport change and nothing more:
///    no post-quantum handshake happens anywhere in the session.
///  - [kWinnCarrierHttp3] wraps each one in an authenticated Winn envelope
///    carried over HTTP/3 CONNECT-UDP, and the session that carries them really
///    does perform a post-quantum handshake: TLS 1.3 restricted to a hybrid
///    group (`x25519-mlkem768` and friends), Encrypted Client Hello, ML-DSA
///    request signing by the device key and ML-DSA verification of every
///    response against PINNED controller keys.
///
/// What [kWinnCarrierHttp3] still does NOT buy is node selection. The
/// production route binds the transport, the suite, the ECH list and the public
/// target to a controller-signed, transparency-logged gateway manifest;
/// `carrierhost` refuses a profile that names one rather than pretending to
/// verify it. Until that lands, a carrier session is exactly as trustworthy as
/// the channel that served this config, and no more.
///
/// It also does not buy anything on a device with no credentials. The profile
/// names a device ML-DSA seed, a client certificate, the Winn CA, an ECH config
/// list and a pinned controller verifier set, none of which this app provisions
/// today; `WinnCarrierProfile.CredentialSet.resolve` fails closed and names the
/// first one missing.
///
/// A `protocol_params` key this build does not recognise is still a refusal,
/// for the same reason `WinnEngineConfig.from` refuses an unrecognised `[winn]`
/// key: quietly dropping it would leave the operator believing it took effect.
///
/// # Anti-downgrade
///
/// Nothing here ever returns "fall back to AmneziaWG". A `winn/3` config that
/// cannot start Winn produces a [WinnStartDecision] with
/// [WinnStartDecision.supported] false and a reason -- and the only correct
/// response to that is to fail the connection. Falling through to the
/// classical `winn/1` AWG path would be a silent downgrade of a negotiation
/// the gateway believes it made.
///
/// # Single packet authorization, and what serving it costs
///
/// The `spa_*` params are the alternative connection-initiation step
/// (`winn_protocol_experimental/docs/SPA_DESIGN.md`). They are optional, they
/// are inert unless `spa_mode` is `required`, and a config that names none of
/// them describes exactly the session it described before they existed.
///
/// Their key list is NOT written here. It is generated into
/// `lib/winn_carrier_profile_keys.dart` from `carrierhost.Profile` itself, and
/// a Go test fails if it drifts -- because the reason SPA was unreachable from
/// every platform for as long as it was is that four hand-maintained copies of
/// this list all agreed with each other and none of them agreed with the
/// schema.
///
/// **Serving an `spa_*` param to a client that predates this file's support for
/// it STOPS THAT CLIENT'S CONNECTION.** It lands in the unknown-param sweep
/// below and becomes [WinnRefusalReason.unhonourableProtocolParams] -- correct
/// behaviour, because claiming to have knocked when the app cannot knock would
/// be worse, but it makes these capability-gated params rather than free ones.
/// The control plane must serve them only to a client that has advertised
/// [kWinnClientCapabilitySpa].
library;

import 'dart:convert';

import 'package:crypto/crypto.dart' as hashes;
import 'package:cryptography/cryptography.dart';

import 'vpn_config_validation.dart';
import 'winn_carrier_profile_keys.dart';

export 'winn_carrier_profile_keys.dart'
    show
        kWinnServedCarrierProfileKeys,
        kWinnRequiredCarrierProfileKeys,
        kWinnSpaCarrierProfileKeys,
        kWinnSpaModeOff,
        kWinnSpaModeRequired,
        kWinnSpaKeyCredentialFileName;

/// The release build flips this define per-platform once that platform's
/// `[winn]` parser accepts the dual-signature attestation keys and its host
/// can verify them. Default-off keeps every shipped and legacy host on the
/// code path it has today, byte for byte.
const bool kWinn3DualAuthHostSupported =
    bool.fromEnvironment('WINS_WINN3_DUAL_AUTH', defaultValue: false);

/// The shipping protocol: AmneziaWG, unchanged. An absent or blank
/// `protocol_version` normalizes to this.
const String kWinnProtocolV1 = 'winn/1';

/// Winn Protocol v3.
const String kWinnProtocolV3 = 'winn/3';

/// The INI section name the native host reads. Must equal
/// `WinnEngineConfig.SECTION`.
const String kWinnConfigSection = 'winn';

/// The served slot that NAMES the outer transport arrangement a `winn/3`
/// session is to use. Hub-served, per-node, and ABSENT BY DEFAULT.
///
/// This key exists because the refusals below are correct and must stay: a
/// config carrying `stealth_active` and `winn/3` with nothing else has asked
/// for two outer transports and does not say which arrangement it means, so it
/// is still refused. This is the only way for a hub to say the other thing.
const String kWinnOuterTransportKey = 'winn_outer_transport';

/// The one value [kWinnOuterTransportKey] accepts today: winn/3 STACKED IN
/// FRONT OF the v1 stealth leg rather than competing with it.
///
/// ```
///   AmneziaWG -> Winn seam -> Winn engine (direct-awg)
///             -> 127.0.0.1:<xray localport> -> Xray VLESS/WS(/TLS) -> edge
/// ```
///
/// Each relay owns a distinct loopback port, so nothing contends for the one
/// AmneziaWG peer-endpoint field, and the socket that actually leaves the
/// device is Xray's -- which already gets whatever exclusion v1's stealth leg
/// gives it. Measured 2026-08-07: a full winn/3 session with zero UDP on the
/// wire on a network dropping all UDP, wire image indistinguishable from v1
/// stealth. See
/// `docs/handoff/WINN3_OVER_THE_STEALTH_LEG_MEASURED_AND_THE_FOUR_REFUSALS_20260807.md`.
const String kWinnOuterTransportStealthChain = 'stealth-chain';

/// `datapath.MinDatagram` / `WinnEngineConfig.MIN_DATAGRAM`.
const int kWinnMinDatagram = 32;

/// `datapath.MaxDatagramCeiling` / `WinnEngineConfig.MAX_DATAGRAM_CEILING`.
const int kWinnMaxDatagramCeiling = 1500;

/// `datapath.normalize`: `session_id` may not exceed 128 bytes.
const int kWinnMaxSessionIdBytes = 128;

/// `WinnEngineConfig.from`: the MTU bound the native host enforces.
const int kWinnMinMtu = 576;
const int kWinnMaxMtu = 9000;

/// `WinnEngineConfig.CARRIER_DIRECT_AWG` / `datapath.CarrierDirectAWG`. The
/// carrier an absent `carrier` param normalizes to, and the only one that
/// needs no carrier profile.
const String kWinnCarrierDirectAwg = 'direct-awg';

/// `connectivity.CarrierHTTP3`. AmneziaWG datagrams inside authenticated Winn
/// envelopes over HTTP/3 CONNECT-UDP (MASQUE), with a post-quantum TLS 1.3
/// handshake, Encrypted Client Hello and ML-DSA signing.
const String kWinnCarrierHttp3 = 'http3-connect-udp';

/// `connectivity.CarrierHTTP2`. The same envelopes over one long-lived HTTP/2
/// stream. Deliberately NOT in [kWinnSupportedCarriers]: its dialer takes a
/// connected, protected TCP socket and the Android host opens an unconnected
/// UDP one, so accepting it here would advertise a transport the host cannot
/// supply the socket for.
const String kWinnCarrierHttp2 = 'http2-stream';

/// The winn/3 STANDALONE carrier. Must equal
/// `WinsTunnelConfig.supportedWinnCarrierWinn3`, `WinsWinn3.carrierName`, the
/// Go archive's `winn3Carrier`, and `WINN3_CARRIER_WINN3` in the control plane.
///
/// # It is categorically different from the other two
///
/// [kWinnCarrierDirectAwg] and [kWinnCarrierHttp3] are RELAY carriers:
/// AmneziaWG owns the tun, does all of the cryptography, and Winn carries its
/// already-encapsulated outer datagrams. `winn3` is STANDALONE -- there is no
/// AmneziaWG anywhere in it, the winn/3 session owns the datapath, and the
/// bytes crossing the engine boundary are inner IP packets rather than
/// AmneziaWG datagrams.
///
/// Everything the standalone branch below does differently follows from that
/// one fact, and none of it is a relaxation:
///
///  * **No carrier profile.** A standalone session performs its own handshake
///    over its own transport. There is no MASQUE document to build, so
///    [kWinnRequiredCarrierParams] does not apply and a profile param served on
///    a standalone node is as inert as one served on `direct-awg`.
///  * **No `h1`..`h4` / `s1`..`s4`.** Those are AmneziaWG obfuscation
///    parameters for an AmneziaWG engine that is not in this session.
///  * **No stealth chain.** The chain works by repointing AmneziaWG's peer
///    endpoint at a local Xray inbound; with no AmneziaWG there is nothing to
///    repoint, and pointing a standalone session's own dialer at a loopback
///    Xray inbound would neither reach the gateway nor be the session it
///    negotiated.
///  * **Six key-bearing `[winn]` fields**, none of which can travel through
///    `protocol_params`: the control plane's own
///    `WINN3_PARAM_NAME_NEVER_SERVED` matches `static_private` by construction
///    and refuses it there by design. Four arrive on the signed descriptor and
///    two per-device on `vpn_config`.
const String kWinnCarrierWinn3 = 'winn3';

/// The carriers this build can actually start.
///
/// MUST MIRROR `WinnEngineConfig.SUPPORTED_CARRIERS`. A carrier accepted here
/// and refused there fails deep in the native host with a less useful message;
/// a carrier accepted there and refused here is unreachable. The native side is
/// the authority, and it is the one that refuses last.
///
/// A carrier joins this set when the HOST can supply what the carrier's dialer
/// takes, not when the engine gains the carrier.
const Set<String> kWinnSupportedCarriers = <String>{
  kWinnCarrierDirectAwg,
  kWinnCarrierHttp3,
  kWinnCarrierWinn3,
};

/// The carriers that need a carrier profile: everything that is neither the
/// profile-free relay default nor the standalone session.
///
/// A set difference rather than a literal, so a carrier added to
/// [kWinnSupportedCarriers] is refused a profile it does not have rather than
/// silently exempted from one it needs. Mirrors
/// `WINN3_CARRIER_PROFILE_CARRIERS` in the control plane, which is written the
/// same way for the same reason.
Set<String> get kWinnCarrierProfileCarriers => kWinnSupportedCarriers
    .where((c) => c != kWinnCarrierDirectAwg && c != kWinnCarrierWinn3)
    .toSet();

/// The `protocol_params` keys that describe a CARRIER PROFILE.
///
/// These do not reach `datapath.Config` at all. `WinnEngineConfig` consumes
/// them from the `[winn]` section and `WinnCarrierProfile` turns them into the
/// separate document `winn-datapath` reads from `-carrier-profile PATH`.
///
/// EVERY ONE OF THEM IS PUBLIC. A URI template, an address, a suite name, two
/// identifiers, a digest, and three tuning scalars. The material that would be
/// dangerous to serve in a config -- the device ML-DSA seed, the client private
/// key, the pinned controller verifiers, the Winn CA, the ECH config list --
/// is deliberately absent: it lives on the device and the profile names it by
/// path. A gateway cannot put key material into a Winn session by serving a
/// config, because there is no key-material-shaped slot for it to serve into.
/// NOT WRITTEN HERE. This is the generated list, derived from
/// `carrierhost.Profile`'s own json tags by
/// `winn_protocol_experimental/cmd/winn-carrier-keys`, and
/// `carrierhost.TestGeneratedPlatformKeyFilesAreCurrent` fails an ordinary
/// `go test ./...` if this file has drifted from the schema.
///
/// It used to be a hand-typed copy, one of four. All four copies were
/// identical, all four excluded every `spa_*` field the schema had gained, and
/// nothing failed anywhere -- the capability was simply unreachable from every
/// platform at once. Generating it is what makes that failure mode impossible
/// rather than merely unlikely.
const Set<String> kWinnCarrierProfileParams = kWinnServedCarrierProfileKeys;

/// The carrier profile params that have no safe default, mirroring
/// `WinnEngineConfig.REQUIRED_CARRIER_KEYS`. A carrier session missing any of
/// these is refused rather than started with a guess.
///
/// No `spa_*` param is here, and a Go test enforces that
/// (`TestNoSPAKeyIsRequired`). It is the whole backward-compatibility argument
/// for the SPA fields: a served config naming none of them is exactly the
/// config it was before they existed.
const Set<String> kWinnRequiredCarrierParams = kWinnRequiredCarrierProfileKeys;

/// The capability string a client advertises when it can actually emit a knock.
///
/// # Why a client-advertised capability and not an app-version check
///
/// Serving `spa_mode` to a client that cannot honour it stops that client's
/// connection (see the library doc). So the control plane needs to know, per
/// request, whether SPA is safe to serve. A version number is the obvious
/// answer and the wrong one: shipping the CODE that understands `spa_*` and
/// holding the KEY that makes a knock verify are different events, and only the
/// device knows whether the second has happened. A client on the right version
/// with no provisioned key would be served SPA, would build a profile naming a
/// key file that is not there, and would fail every connection -- which is the
/// exact "capability that reports success while carrying nothing" failure this
/// project keeps hitting.
///
/// So this capability is reported by [winnClientCapabilities] only when the
/// native host can carry `winn/3` AND the SPA key is actually provisioned. It
/// is derived from device state, never from a build flag.
const String kWinnClientCapabilitySpa = 'winn3-spa';

/// The exact hub flag a client advertises when it can consume both dual-auth
/// public keys from a signed descriptor (`auth_ed25519` and `auth_mldsa65`).
///
/// Default-off: iOS, macOS, Linux, and Windows builds leave
/// [kWinn3DualAuthHostSupported] false, so they must advertise false. An
/// Android release that actually emits both keys into `[winn]` may advertise
/// true. The hub serves the pair only to a client that sent this flag as true.
const String kWinnClientCapabilityDualAuth = 'supports_winn3_dualauth';

/// The `protocol_params` keys this build knows how to honour.
///
/// Each one maps 1:1 onto a key `WinnEngineConfig.from` accepts. There is
/// deliberately no key here that this client would have to interpret itself:
/// the gateway's `protocol_params` is an opaque pass-through blob
/// (`parse_protocol_params` in the control plane hands whatever was stored
/// straight to the client), so an allowlist is the only honest way to read it.
///
/// `h1`..`h4` are absent on purpose. They must match the header types the
/// AmneziaWG engine is actually configured with, which come from
/// `obfuscation`, so `obfuscation` stays their single source of truth and a
/// `protocol_params` copy that disagreed with it could never arise.
const Set<String> kWinnKnownProtocolParams = <String>{
  'gateway_endpoint',
  'max_datagram',
  'session_id',
  'carrier',
  ...kWinnCarrierProfileParams,
};

/// Why a `winn/3` start was refused. Stable identifiers: they are written into
/// the tunnel failure diagnostic and asserted on by tests.
enum WinnRefusalReason {
  /// No refusal; the start may proceed.
  none('none'),

  /// This operating system has no Winn path at all.
  unsupportedPlatform('unsupported_platform'),

  /// `stealth_active` and Winn are mutually exclusive outer transports.
  /// `VpnTunnelService.onStartCommand` refuses the combination natively; this
  /// catches it earlier, with a message that says which two things collided.
  stealthTransportConflict('stealth_transport_conflict'),

  /// The gateway endpoint is missing, or is a hostname rather than an IP
  /// literal. Not resolvable here: the engine refuses a hostname precisely
  /// because that lookup would leave outside the tunnel.
  gatewayEndpointNotIpLiteral('gateway_endpoint_not_ip_literal'),

  /// `mtu` is outside the range the native host accepts.
  mtuOutOfRange('mtu_out_of_range'),

  /// `max_datagram` is outside `[kWinnMinDatagram, kWinnMaxDatagramCeiling]`.
  maxDatagramOutOfRange('max_datagram_out_of_range'),

  /// `session_id` is longer than the datapath permits.
  sessionIdTooLong('session_id_too_long'),

  /// The AmneziaWG header types are not a usable classification table.
  headerTypesInvalid('header_types_invalid'),

  /// `protocol_params` carries something this build does not understand --
  /// including any post-quantum material. Refusing is the point.
  unhonourableProtocolParams('unhonourable_protocol_params'),

  /// The served `carrier` is not one this build can start. NEVER a fallback to
  /// [kWinnCarrierDirectAwg]: a gateway that selected an authenticated carrier
  /// believes the session is authenticated, and starting classical AmneziaWG
  /// instead would be exactly the silent downgrade this file exists to prevent.
  carrierUnsupported('carrier_unsupported'),

  /// The served `carrier` needs a carrier profile and the config did not carry
  /// the fields to build one, or carried one that is malformed.
  carrierProfileIncomplete('carrier_profile_incomplete'),

  /// The served single-packet-authorization params cannot be honoured: an
  /// unknown `spa_mode`, an `spa_*` field without the mode, SPA asked for on a
  /// carrier that cannot carry a knock, or a missing/malformed `spa_target`.
  ///
  /// NEVER "start without knocking". A gateway that served `spa_mode=required`
  /// has a gate in front of it; connecting without the knock reaches a port
  /// that is dropping our packets, so the honest outcome is a named refusal
  /// rather than a connection that times out for a reason nothing reports.
  spaParamsUnhonourable('spa_params_unhonourable'),

  /// The served config selected the STANDALONE carrier and carried no gateway
  /// descriptor, or one this build could not verify.
  ///
  /// NEVER a start. The descriptor carries the gateway's static public key,
  /// the admission secret and the gateway id; a standalone session without
  /// them cannot seal an initiation the gateway will admit, and a v3 gateway
  /// does not answer a datagram it could not authenticate -- so starting
  /// anyway produces a session that reports up, carries nothing, and looks
  /// exactly like censorship. A named refusal is strictly more useful.
  winn3DescriptorUnverified('winn3_descriptor_unverified'),

  /// The signed descriptor names a different node than the selected config,
  /// or the served config omitted the selected node identity entirely.
  ///
  /// Signature validity is not enough: without this binding a valid descriptor
  /// for gateway A can be substituted into gateway B's config and the client
  /// will seal initiations only A can open. A v3 gateway stays silent on that
  /// failure, so it must be a named pre-start refusal.
  winn3DescriptorNodeMismatch('winn3_descriptor_node_mismatch'),

  /// The served config selected the STANDALONE carrier and did not carry the
  /// per-device half: `winn3_inner_v4` and `winn3_static_private`.
  ///
  /// Separate from [winn3DescriptorUnverified] because the two halves come
  /// from different places and fail for different reasons -- one is the
  /// gateway's signed record, the other is this device's own provisioning --
  /// and an operator reading a diagnostic needs to know which is missing.
  winn3DeviceMaterialMissing('winn3_device_material_missing'),

  /// A standalone `[winn]` field is present but malformed: an inner address
  /// that is not a dotted quad, a key that is not base64, a `gateway_id` that
  /// does not decode to operator text, or a value that could forge an INI key.
  winn3FieldMalformed('winn3_field_malformed'),

  /// Dual-signature authentication keys were present on a signed descriptor
  /// while this native host had not declared support for both. Mixed clients
  /// now omit the keys and continue as a legacy standalone session rather
  /// than refusing; a dual-auth build advertises supports_winn3_dualauth and
  /// emits both keys. The named reason is kept so a future fail-closed path
  /// can reuse it.
  winn3DualAuthUnsupported('winn3_dual_auth_unsupported'),

  /// The served `winn3_relay` (the Core relay route of a ciphertext relay
  /// Double VPN, w3r/1) is present but is not the exact shape this build
  /// accepts, or it does not agree with the rest of the served config: the
  /// config is not labelled Double, names no Core, names another exit than the
  /// signed descriptor, or points at the exit's own address.
  ///
  /// NEVER read as "no relay". A route that cannot be trusted must not turn a
  /// Double config into a direct single-hop dial, so it is a named refusal.
  winn3RelayMalformed('winn3_relay_malformed'),

  /// The served config is labelled Double VPN, selects the standalone carrier
  /// and carries no relay route. A two-hop label must never ride a single-hop
  /// descriptor: the session would dial the exit directly while the app tells
  /// the user two hops protect them.
  winn3DoubleLabelWithoutRelay('winn3_double_label_without_relay'),

  /// A config reached the Winn gate while declaring a `protocol_version`
  /// other than `"winn/3"` -- e.g. `"winn/1"` with a `winn3` carrier.
  ///
  /// Everything this gate decides describes a `winn/3` session: the carrier,
  /// the header types, the `[winn]` section it builds. A config that reaches
  /// it under any other version is internally contradictory, and resolving it
  /// would build a session the config never negotiated. The shipping seam
  /// routes `winn/1` straight to the classical AmneziaWG path and routes
  /// unknown versions to an update prompt, both BEFORE calling here; this is
  /// the structural backstop that keeps a second entry point -- above all the
  /// dev override's borrowed decision -- from turning that ordering into a
  /// hole.
  protocolVersionMismatch('protocol_version_mismatch');

  const WinnRefusalReason(this.code);

  /// A stable snake_case identifier, safe to persist in a diagnostic.
  final String code;
}

/// The outcome of asking whether a served config may start the Winn path.
class WinnStartDecision {
  const WinnStartDecision._({
    required this.supported,
    required this.reason,
    required this.message,
    required this.iniSection,
  });

  /// A start that may proceed, carrying the `[winn]` section to append to the
  /// native tunnel config.
  factory WinnStartDecision.start(String iniSection) => WinnStartDecision._(
        supported: true,
        reason: WinnRefusalReason.none,
        message: '',
        iniSection: iniSection,
      );

  /// A start that must fail. Never a fallback: see the library doc.
  factory WinnStartDecision.refuse(WinnRefusalReason reason, String message) =>
      WinnStartDecision._(
        supported: false,
        reason: reason,
        message: message,
        iniSection: '',
      );

  /// True only when the Winn path can actually be started on this platform
  /// with this config.
  final bool supported;

  /// Why not, when [supported] is false.
  final WinnRefusalReason reason;

  /// A user-facing explanation. Never contains a config value, so it is safe
  /// to display and to log.
  final String message;

  /// The `[winn]` INI section to append to the native tunnel config. Empty
  /// unless [supported].
  final String iniSection;
}

/// What one platform's native host has to have built before it may carry
/// `winn/3`, and -- when it has not -- the one thing it is still missing.
///
/// # Why this is a record and not a boolean
///
/// The predicate this replaced was `operatingSystem == 'android'`. That was
/// accurate, but it made "turn a platform on" a one-character edit, and the two
/// things a host has to get right before that edit is honest are exactly the
/// two this project has already got wrong once each:
///
///  1. **The payload boundary.** The engine's Inbound/Outbound frames carry
///     AmneziaWG OUTER DATAGRAMS, not raw tun packets. The datapath module
///     contains no AmneziaWG implementation, so a host that pumps its tun
///     device into those frames forwards CLEARTEXT to the gateway. Both the
///     Apple wrapper and the Windows engine were once written with the pump on
///     the wrong side of the AWG engine. NEITHER IS ANY LONGER: both now bind a
///     127.0.0.1 loopback seam that the AmneziaWG peer `Endpoint` is rewritten
///     to point at, so the AWG engine keeps the tun and only its already-
///     encrypted outer datagrams reach the frames -- the same shape Android
///     (`WinnAwgLoopbackSeam.kt`) and Linux (`linux/runner/linux_winn_host.cc`)
///     use. See `apple/EngineWrappers/WinsWinnPacketEngine.m` and
///     `windows/runner/windows_winn_engine.cpp`. This history is kept rather
///     than deleted because it is one of the two mistakes that motivated this
///     record existing at all; it is NOT a description of either host today.
///
///     A SECOND defect on that same seam has also been closed, on Apple, Linux
///     and Android: an unpaced outbound burst silently dropped datagrams
///     (measured at 46.27% on Apple -- 9,255 of 20,000) because one loop both
///     drained the seam socket and wrote to the engine. Those three now split
///     the drainer from the writer and COUNT what they drop instead of losing
///     it quietly. Windows was deliberately left UNVERIFIED and unchanged on
///     this point, and its entry below stays absent for other reasons anyway.
///  2. **The outer socket.** The one socket that does touch the network must be
///     kept out of the tunnel it is carrying, or its datagrams match the
///     tunnel's own routes, re-enter the host's tun, and loop forever. Each
///     platform's mechanism is different and none of them is optional.
///
/// So a platform may only be declared supported by naming both. These are
/// prose fields rather than a second boolean on purpose: a lane cannot fill
/// them in without having actually decided, and a reviewer can check the claim
/// against the file it names. [kWinnHostCapabilities] is the single place any
/// of this changes.
class WinnHostCapability {
  /// A platform with no Winn path this build can start. [missing] names the one
  /// thing that would have to exist, in terms of a real file or a real call.
  const WinnHostCapability.absent({
    required this.platform,
    required this.missing,
  })  : awgDatagramSeam = '',
        outerSocketExclusion = '';

  /// A platform whose native host can carry `winn/3` end to end.
  const WinnHostCapability.present({
    required this.platform,
    required this.awgDatagramSeam,
    required this.outerSocketExclusion,
  }) : missing = '';

  /// The `Platform.operatingSystem` value this describes.
  final String platform;

  /// Empty exactly when this platform can carry `winn/3`.
  final String missing;

  /// Where the host gets AmneziaWG outer datagrams, given that the AWG engine
  /// normally sends them itself. Empty when [supported] is false.
  final String awgDatagramSeam;

  /// How the single outer socket is kept from being routed back into the
  /// tunnel. Empty when [supported] is false.
  final String outerSocketExclusion;

  /// True only when this platform's host has both of the above.
  bool get supported => missing.isEmpty;
}

/// Every platform this app runs on, and the honest state of its Winn host.
///
/// A platform absent from this map is treated as unsupported, so a new
/// `Platform.operatingSystem` value can never be silently supported.
const Map<String, WinnHostCapability> kWinnHostCapabilities =
    <String, WinnHostCapability>{
  // ANDROID IS .absent AS OF 2026-08-08 -- read the DEMOTED paragraph at the
  // end of this comment block before believing the promotion prose that
  // follows. What follows is the historical record of the 2026-08-04 run,
  // preserved because it is accurate about that run; it is not the evidence a
  // `.present` claim needs and this entry no longer makes that claim.
  //
  // The Android SOURCE path is complete, and as of 2026-08-04 it had what
  // every other entry in this table was then still waiting on: a REAL,
  // EXECUTED winn/3 session on a real device, not just a build.
  //
  // Real device run: motorola edge plus 2023 (serial ZY22GTV6Z3), Android 15
  // / sdk 35, arm64-v8a, android/devicecheck rebuilt fresh against this
  // change (WINN_DEVICECHECK_ENGINE=real). Logcat 2026-08-04 11:55:56 --
  // 11:56:04 local (tag WINNCHECK, pid 18583). 29/29 RESULT lines PASS, 0
  // FAIL. Full log:
  // .winn_platform_progress/evidence/devicecheck_20260804T155556Z_motorola_edge_plus_2023.log
  //
  // RESULT 8-awg-handshake PASS: "AmneziaWG handshake completed=true
  // (last_handshake_time_sec=1785858962); the responder independently
  // reported completion=true; every outer datagram crossed the seam (out=10
  // in=1) and the real winn-datapath engine (tx_datagrams=9 rx_datagrams=1)"
  // -- a real handshake, through the real seam, into the real engine
  // subprocess, not a JVM double. RESULT 4-scm-rights-descriptor-adopted
  // PASS: the socket the engine adopted over SCM_RIGHTS is the one
  // VpnService.protect() marked ("match=true; socket_owned_by_engine=
  // false"). RESULT 1c-protect-differential PASS: on this device, right
  // now, a protected socket reaches the network and an unprotected one
  // times out.
  //
  // This entry previously read WinnHostCapability.present with nothing
  // beyond a JVM double behind it, was correctly demoted to .absent for
  // exactly that reason, and a first real device run
  // (devicecheck_20260804T105214Z_motorola_edge_plus_2023.log, same device)
  // then earned 28/29: RESULT 9c-double-teardown-is-a-no-op FAILED, a real
  // defect and not harness noise -- AmneziaWG reissued the same integer
  // engine handle to a second, unrelated tunnel, and stopAwgEngineIfOwned
  // identified "the engine I started" by comparing only that bare integer,
  // so a superseded session's late teardown could match and silently stop a
  // live successor's tunnel. Fixed by AwgHandleOwnership.kt
  // (android/app/src/main/kotlin/org/winsvpn/app/), which pairs the handle
  // with the tunnel generation that published it -- reusing the generation
  // counter VpnTunnelService already threads through every other supersede
  // check, not a second identity scheme -- and releases only when both
  // match. AwgHandleOwnershipTest.kt's regression test reproduces this exact
  // scenario and was confirmed (by mutation) to fail without the fix. This
  // run, with the fix in place and android/devicecheck's WinnSessionReplica
  // using the same real AwgHandleOwnership class (synced by
  // syncWinnHostSources, not hand-copied), is the first 29/29 clean winn/3
  // result on Android.
  //
  // DEMOTED TO .absent ON 2026-08-08 BY ADJUDICATION. Everything above this
  // paragraph is the record of what the 2026-08-04 devicecheck run actually
  // showed, and it is kept rather than deleted because it is true about that
  // run -- but it is NOT the shipping-path evidence a `.present` claim needs,
  // and it never was. docs/handoff/ADJUDICATION_20260808.md, Contradiction 1
  // and Decision (a), ruled the eight-criterion bar NOT met and directed this
  // entry to `.absent`. The three grounds, in the adjudication's own order:
  //
  //  1. The run this entry cites is a SAME-HANDSET LOOPBACK HARNESS. The log
  //     named above is `package=org.winsvpn.devicecheck` (line 4) -- a
  //     separate harness app, not the shipping app -- and its
  //     `gateway_endpoint` is the IPv4 loopback address (line 57), i.e. the
  //     far end is a thread in the same pid. tx_bytes 706, rx_bytes 172, an
  //     8-second window, zero rekeys. Against the bar recorded at
  //     OWNER_DELEGATED_DECISIONS_20260807.md:589-597 that fails criteria 1
  //     (shipping path, not a harness), 3 (never loopback/in-process), 5 (a
  //     4 MiB floor) and 6 (5 minutes and 2 rekeys) outright.
  //  2. The stronger run is GENUINE BUT UNCHECKABLE. A 18.73 MiB physical-hop
  //     session on 2026-08-08 (WINN3_ANDROID_FULL_BAR_20260808.md) very
  //     probably happened substantially as described -- every claim of it that
  //     survives was re-verified and held -- but its proof artefacts were
  //     deleted by that lane's own teardown (:335) and are on no disk anyone
  //     can read. Genuine is not proven, and this table records what a
  //     reviewer can check.
  //  3. It would not describe winn/3 EVEN IF PROVEN. The owner ruled on
  //     2026-08-08 that Winn Protocol v3 is a STANDALONE protocol -- its own
  //     handshake, its own crypto, its own datapath, with AmneziaWG and Xray
  //     removed. The seam and exclusion prose this entry used to carry
  //     described an AmneziaWG-RELAYING datapath: a loopback seam that
  //     rewrites an AmneziaWG peer Endpoint so a real AWG engine keeps the
  //     tun. That is v3-as-a-relay, which is not the protocol v3 now means, so
  //     the claim could not be honest under the new definition regardless of
  //     how well it was evidenced.
  //
  // The demotion is free today: no node serves winn/3 at all, so this flag is
  // never read by any real client (RELEASE_BLOCKERS_20260808.md:438-439,
  // :459-462). Leaving it `.present` would have cost something -- the first
  // winn/3 config an Android client ever saw would have been the FIRST
  // exercise of the datapath on a shipping build, a production-first test, in
  // the Myanmar threat model.
  //
  // FLIP-BACK GATE (identical for every platform, ADJUDICATION_20260808.md:189):
  // a signed release build completes the seven applicable criteria in one
  // session against a real winn/3 gateway across a physical hop, with the
  // runtime evidence COMMITTED under .winn_platform_progress/evidence/ and the
  // `runEvidence` test in test/winn_protocol_dispatch_test.dart extended to
  // ASSERT CONTENT -- reject loopback endpoints, require the byte floor,
  // require digest_match_full_set -- rather than mere existsSync. The flip
  // itself is owner-reserved (OWNER_DELEGATED_DECISIONS_20260807.md section 8
  // item L). Source that compiles and a harness that passes are not a session;
  // that was true when this entry was demoted the first time and it is what
  // demoted it again.
  'android': WinnHostCapability.absent(
    platform: 'android',
    missing:
        'a winn/3 session on the SHIPPING PATH. The Android host source is '
        'complete and its mechanism is genuinely proven at the transfer '
        'level -- android/app/src/main/kotlin/org/winsvpn/app/'
        'WinnAwgLoopbackSeam.kt binds the seam and '
        'WinnAndroidEngineHost.kt hands the ONE protected outer socket to '
        'the engine over SCM_RIGHTS -- but no session has ever completed '
        'the bar on a signed release build. The run this entry cited for '
        'four days was a same-handset LOOPBACK HARNESS: '
        'package=org.winsvpn.devicecheck, gateway_endpoint on the IPv4 '
        'loopback address, 706 bytes over 8 seconds with zero rekeys '
        '(.winn_platform_progress/evidence/devicecheck_20260804T155556Z_'
        'motorola_edge_plus_2023.log lines 4 and 57), which fails criteria '
        '1, 3, 5 and 6. The stronger 18.73 MiB physical-hop run of '
        '2026-08-08 was ruled genuine but its proof artefacts were deleted '
        'by that lane\'s teardown, so nobody can check it; it also ran a '
        '.profile build driven through appops/run-as, not a Release. And '
        'the datapath both runs exercised RELAYS AmneziaWG, which winn/3 no '
        'longer is: the owner ruled on 2026-08-08 that v3 is a standalone '
        'protocol with its own handshake, crypto and datapath and with '
        'AmneziaWG and Xray removed, so the old seam/exclusion claims '
        'describe a protocol this entry is no longer about. See '
        'docs/handoff/ADJUDICATION_20260808.md, Contradiction 1 and '
        'Decision (a).',
  ),
  // The Apple SOURCE path is complete and exercised end to end against the real
  // Go archive by tools/verify_apple_winn_seam.sh: the ObjC wrapper relays AWG
  // outer datagrams over a loopback seam, WinsPacketTunnelEngine starts it
  // first and repoints the AmneziaWG UAPI endpoint at the port it reports, and
  // transportIPv4ExclusionRoute reads [winn] endpoint so the /32 that keeps the
  // engine's outer socket off the tunnel survives.
  //
  // BUILD CUSTODY IS NO LONGER THE GAP EITHER, and saying it still is would
  // send the next lane to do work that is already done. As of 2026-08-04 a real
  // libWinsWinnPacketEngine.dylib IS staged for all three Apple slices --
  // apple/EngineArtifacts/macos/ (fat x86_64+arm64),
  // apple/EngineArtifacts/ios/iphoneos/ and .../iphonesimulator/ -- and the
  // macOS one passed tools/build_apple_engine_wrappers.sh's 15/15 symbol gate
  // with 3,787 Go symbols and no test-double markers.
  //
  // What is missing now is EXECUTION IN AN APPEX, and it is the same shape of
  // gap the Windows entry names.
  //
  // DANGLING CITATION REPAIRED 2026-08-06. This paragraph used to attribute a
  // command-line-host seam session -- 4 MiB each way, SHA-256 791f5b77...
  // matching -- to "docs/handoff/
  // WINN_PROTOCOL_MACOS_NE_BUILD_AND_SEAM_TRAFFIC_20260804.md". That document
  // DOES NOT EXIST: not on disk, and `git log --all -S` for its exact name
  // finds it in no commit either. Nothing else in this repository
  // corroborates those specific numbers, so they are withdrawn rather than
  // repeated against a citation that does not resolve -- a comment can claim
  // a run happened that never did, and a claim nobody can check is exactly
  // what WinnHostCapability's own doc comment (above) says these prose
  // fields exist to prevent.
  //
  // What replaces it is real and citable. On 2026-08-06 a winn/3 session ran
  // on macOS through the ACTUAL org.winsvpn.app.PacketTunnel
  // NEPacketTunnelProvider appex -- a real utun6, not packet_flow == NULL --
  // against an AmneziaWG gateway on a separate physical machine. It completed
  // a handshake confirmed independently at both ends, SURVIVED FOUR REKEYS
  // with zero packet loss, and carried 10.125 MiB each way with an exact
  // end-to-end SHA-256 match (cc61b3e2...) -- more than the 4 MiB this
  // paragraph used to claim, and through a real provider rather than a
  // command-line host. Full account: docs/handoff/
  // WINN3_MACOS_REMOTE_GATEWAY_RIGOROUS_SESSION_20260806.md. Raw log, in-repo
  // and citeable: .winn_platform_progress/evidence/
  // winn3_macos_20260806T155246Z_contained_remote_gateway_session.txt.
  //
  // That closes the "carried in a real appex" half of the gap this paragraph
  // used to name for macOS -- but the run's own scorecard says plainly that
  // it does not clear this table's bar yet: the config came from a dev JSON
  // file and a dev-harness trigger rather than the shipping /free/verify +
  // Connect path, the far end was a lab machine on the same LAN rather than
  // Spain (no NAT, no carrier network, no censorship), the
  // gateway_sender_filter NAT-rebind hazard remains untested, and the
  // packet-tunnel settings-release error is unchanged. The session's own
  // write-up did not flip kWinnHostCapabilities['macos'], and neither does
  // this citation repair -- it stays absent until the owner judges those
  // gaps closed enough. See the macos entry below for the same correction
  // applied to its own `missing` field.
  //
  // iOS caught up later that same day, and its evidence now has the same
  // shape as the macOS run above. On 2026-08-06 a CONTAINED winn/3 session
  // ran for 485.6 s inside the real PacketTunnel appex on a physical
  // iPhone 16 Pro Max (dev bundle id org.winsvpn.app.debug), against the
  // same remote lab gateway on a separate physical machine: four rekeys
  // survived with zero loss, 8.698 MiB each way with a THREE-way SHA-256
  // agreement (client-sent, client-returned and gateway-received all
  // 5c7c45ed...), and the iOS-specific question finally measured on
  // device -- phys_footprint peaked at 22.95 MiB against an
  // os_proc_available_memory() budget of exactly 50.00 MiB. Full account:
  // docs/handoff/IOS_WINN3_FIRST_PROVEN_SESSION_AND_MEMORY_20260806.md.
  // Raw logs, in-repo: .winn_platform_progress/evidence/
  // winn3_ios_20260806T174554Z_contained_remote_gateway_session.txt (and
  // the _175500Z_ teardown and _150600Z_ tier-2 companions).
  //
  // That session does NOT clear this table's bar either, and iOS carries a
  // blocker macOS does not: the SHIPPING appex cannot start the engine at
  // all. -lWinsWinnPacketEngine was added to the Debug configuration ONLY,
  // and the tier-2 dlopen fallback that carries macOS was run as a
  // controlled experiment on the device and did NOT resolve
  // (stage=engine_missing, code 1003, "not bundled" -- the resolver's
  // framework lookup, not a load denial). On that evidence a Release
  // build, which lacks the flag, reaches engine_missing on every winn/3
  // start -- so flipping this entry today would advertise a capability the
  // shipping app demonstrably cannot honour, which is the exact failure
  // this table exists to prevent.
  // RE-SCOPED 2026-08-09, FOR BOTH APPLE ENTRIES. Everything the two `missing`
  // fields below used to lead with was RELAY-ERA EVIDENCE described as if it
  // were progress toward the protocol this table is about.
  //
  // The 2026-08-06 macOS and iOS runs were real, were measured carefully, and
  // ran AGAINST AN AMNEZIAWG GATEWAY. In that arrangement AmneziaWG owns the
  // utun and performs all of the cryptography, and Winn carries its
  // already-encapsulated OUTER datagrams -- payload class "awg-datagram". The
  // owner ruled on 2026-08-08 that winn/3 is a STANDALONE protocol: its own
  // handshake, its own crypto, its own framing and its own datapath, with
  // AmneziaWG and Xray removed (docs/handoff/ADJUDICATION_20260808.md,
  // Decision (a)). Those runs therefore measure a datapath winn/3 no longer
  // is, exactly as the Linux entry below already says about its own corpus.
  //
  // Read as they stood, both entries said a winn/3 session "HAS now been
  // carried" on Apple and then listed narrow residual gaps -- dev config, lab
  // gateway, NAT rebind. That reads as one shipping-path run away from
  // promotion. The truth is further back: NO STANDALONE winn/3 SESSION HAS EVER
  // RUN ON APPLE, and none can until a v3 gateway exists to hand-shake with.
  // The `.absent` values do not change -- they were already correct -- but the
  // prose now says what the evidence actually shows, because a `missing` field
  // that overstates where a platform stands is how a demotion rots back into a
  // promotion: the next lane closes what it reads, not what is true.
  //
  // CONDITIONAL, 2026-08-10. This entry stays `.absent` -- no standalone winn/3
  // session has ever run on a shipping iOS build, so a blanket `.present` would
  // be the "capability reports success while carrying nothing" lie this table
  // exists to prevent. But it is no longer a blanket absence either: the winn/3
  // datapath archive IS staged into the iOS app as of 2026-08-10
  // (docs/handoff/HW_IOS_DEVICE_WINN3_20260810.md), so the gap that used to be
  // "the appex links no Go archive" is closed at the source level. What gates
  // iOS now is a RUNTIME fact, not a build flag: [winn3IosReportsCarryingCapability]
  // / [resolveIosWinn3Start] report winn/3-capable only while the native host is
  // genuinely carrying a winn/3 datapath. The `.absent` record below records
  // that a standalone SESSION is still the unmet bar; the conditional gate
  // wraps this entry so iOS resolves a standalone winn/3 start decision when --
  // and only when -- it is truly carrying.
  'ios': WinnHostCapability.absent(
    platform: 'ios',
    missing:
        'a STANDALONE winn/3 session. iOS is now CONDITIONAL: it may resolve a '
        'standalone winn/3 start decision, but only while its native host is '
        'genuinely carrying a winn/3 datapath -- see '
        '[winn3IosReportsCarryingCapability] and [resolveIosWinn3Start], the '
        'wrapping gate for this entry. A compiled build is not carrying, so it '
        'stays `.absent`. What iOS has carried is a RELAY: the '
        '2026-08-06 contained run inside the real PacketTunnel appex on a '
        'physical iPhone -- 485.6 s, four rekeys with zero loss, 8.698 MiB '
        'each way with a three-way SHA-256 agreement, the excludedRoutes /32 '
        'observed installed, phys_footprint peaking at 22.95 MiB against a '
        'measured 50.00 MiB os_proc_available_memory() budget (docs/handoff/'
        'IOS_WINN3_FIRST_PROVEN_SESSION_AND_MEMORY_20260806.md) -- ran '
        'against an AmneziaWG gateway, with AmneziaWG owning the utun and all '
        'of the cryptography while Winn relayed its outer datagrams. The '
        'owner ruled on 2026-08-08 that winn/3 is a standalone protocol with '
        'AmneziaWG and Xray removed (docs/handoff/ADJUDICATION_20260808.md, '
        'Decision (a)), so that run is relay-era evidence and measures '
        'nothing about the protocol this entry names. NO STANDALONE SESSION '
        'HAS EVER RUN ON iOS. The standalone host does now exist and is '
        'exercised against the real Go archive IN THE iOS SIMULATOR -- the '
        'C ABI, the promotion predicate, the packet pump and the start '
        'decision, 198/198 in tools/verify_apple_winn3_host_contract_'
        'iossimulator.sh -- and ios/PacketTunnel/PacketTunnelProvider.swift '
        'now starts it, installs a narrow bootstrap and promotes only on '
        'Gate.State()==StateCarrying plus Stats().RxPackets>0. The winn/3 '
        'datapath archive IS now staged into the iOS app and the symbol '
        'WinnTunnelCreateWinn3 is present in a signed dev build '
        '(docs/handoff/HW_IOS_DEVICE_WINN3_20260810.md), so the old '
        '"appex links no Go archive" gap (3) below is closed at the source '
        'level and is no longer the blocker; the host Debug build currently '
        'segfaults in the Flutter engine at cold launch, so no session has '
        'dialed yet. None of that is a session. What is still unmet for a '
        'standalone session: (1) no reachable winn/3 gateway exists '
        'to complete a handshake with, so the promotion gate has never been '
        'satisfied by anything; (2) the control plane emits none of the '
        '[winn] descriptor fields a standalone start requires (inner_v4, '
        'inner_router_v4, static_private, gateway_static, gateway_id, '
        'admission_key), so every served config is refused by name at '
        'WinsTunnelConfig.winn3StartRefusalReason; and (3) no standalone '
        'winn/3 session has run end to end on iOS, so the promotion predicate '
        'has never been satisfied by a real session. (4) the whole 2026-08-06 '
        'run was the dev path end to end -- dev bundle id, dev config JSON, '
        'dev-harness trigger, Debug build -- not the shipping /free/verify '
        'plus Connect path; (5) the lifecycle bar is unmet on iOS: no '
        'kill-engine-mid-session test and no same-process reconnect has been '
        'run there; and (6) the 22.95 MiB relay peak does not fit the ~15 MB '
        'jetsam ceiling of the iOS 13/14 cohort, and a standalone session has '
        'never been measured at all, so the runtime memory gate is '
        'uncalibrated where it actually bites.',
  ),
  'macos': WinnHostCapability.absent(
    platform: 'macos',
    missing:
        'a STANDALONE winn/3 session. What macOS has carried is a RELAY: the '
        '2026-08-06 run through the real org.winsvpn.app.PacketTunnel appex '
        '-- 10.125 MiB each way with a matching end-to-end SHA-256, four '
        'rekeys survived with zero packet loss, handshake confirmed '
        'independently at both ends (docs/handoff/WINN3_MACOS_REMOTE_GATEWAY_'
        'RIGOROUS_SESSION_20260806.md) -- ran against an AmneziaWG gateway, '
        'with AmneziaWG owning the utun and all of the cryptography while '
        'Winn relayed its already-encapsulated outer datagrams. The owner '
        'ruled on 2026-08-08 that winn/3 is a standalone protocol with '
        'AmneziaWG and Xray removed (docs/handoff/ADJUDICATION_20260808.md, '
        'Decision (a)), so that run is relay-era evidence and measures '
        'nothing about the protocol this entry names -- the same correction '
        'the linux entry below already carries. NO STANDALONE SESSION HAS '
        'EVER RUN ON macOS. The standalone host does now exist and is '
        'exercised against the real Go archive: the C ABI, the promotion '
        'predicate, the bootstrap-posture check, the packet pump and the '
        'start decision, 198/198 in tools/verify_apple_winn3_host_contract.'
        'sh, and macos/PacketTunnel/PacketTunnelProvider.swift now starts it, '
        'installs a narrow bootstrap and promotes only on '
        'Gate.State()==StateCarrying plus Stats().RxPackets>0. None of that '
        'is a session. What is unmet: (1) no reachable winn/3 gateway exists '
        'to complete a handshake with, so the promotion gate has never been '
        'satisfied by anything; (2) the control plane emits none of the '
        '[winn] descriptor fields a standalone start requires (inner_v4, '
        'inner_router_v4, static_private, gateway_static, gateway_id, '
        'admission_key), so every served config is refused by name at '
        'WinsTunnelConfig.winn3StartRefusalReason; (3) the appex links no Go '
        'archive at build time, so WinnTunnelCreateWinn3 resolves only where '
        'a native engine component carrying it has been loaded; and (4) the '
        'older shipping-path gaps are unchanged -- dev JSON config and '
        'dev-harness trigger rather than /free/verify plus Connect, a lab '
        'gateway on the same LAN rather than Spain (no NAT, no carrier '
        'network, no censorship), the gateway_sender_filter NAT-rebind hazard '
        'untested, and the packet-tunnel settings-release error. Closing '
        'these and flipping this entry afterwards are separate decisions and '
        'the second belongs to the owner.',
  ),
  // The Windows SOURCE path is now the same shape as Linux and Apple: the
  // second WinTun adapter is gone, windows/runner/windows_winn_engine.cpp binds
  // a 127.0.0.1 seam that the AmneziaWG peer Endpoint is rewritten to, the
  // Create frame is a real datapath.Config with no key material in it, the
  // `[winn]` section is on ValidateRestrictedTunnelConfig's allowlist, and
  // InstallPrivilegedTunnel branches on `[winn] enabled` so the elevated
  // kStart command reaches it. Route promotion is gated on
  // transport_observed_both_ways AND a recent AWG handshake.
  //
  // What is missing is EXECUTION, and it is deliberately what keeps this entry
  // absent. No winn/3 session has been carried on a real Windows machine: the
  // seam, the engine subprocess and the framed exchange have been run there,
  // but the pinned /32 on the physical LUID, the AmneziaWG peer-endpoint
  // rewrite reaching a live AWG runtime, and the promotion gate have only been
  // compiled. This table is the first anti-downgrade gate and its tests refuse
  // a claim without evidence, so it stays absent until a real session runs.
  'windows': WinnHostCapability.absent(
    platform: 'windows',
    missing:
        'the host is built -- windows/runner/windows_winn_engine.cpp binds a '
        '127.0.0.1 seam, rewrites the AmneziaWG peer Endpoint to it, sends a '
        'real datapath.Config, and windows_tunnel_backend.cpp pins the '
        '[winn] endpoint /32 on the physical LUID before any tunnel route and '
        'promotes only on transport_observed_both_ways plus a recent AWG '
        'handshake -- but NO winn/3 SESSION HAS BEEN CARRIED on a real '
        'Windows machine. The seam, the engine subprocess and the framed '
        'exchange run there; the route pin, the live AWG rewrite and the '
        'promotion gate are compiled only. Windows arm64 is separately '
        'blocked: the build box has no HostX64\\arm64 MSVC toolset and '
        'Flutter exposes no windows-arm64 target.',
  ),
  // LINUX IS .absent AS OF 2026-08-08 -- read the DEMOTED paragraph at the end
  // of this comment block before believing the promotion prose that follows.
  // What follows is the historical record of the 2026-08-06/08 runs, preserved
  // because it is accurate about them; it is not shipping-path evidence and
  // this entry no longer claims it is.
  //
  // Linux was flipped to .present on 2026-08-04 on the strength of a real
  // executed session -- and it WAS real; the run is not in dispute. But its
  // entire evidence set was written to ~/.winn-e2e-lab/linuxhost/out/
  // 20260804T100013Z/, OUTSIDE this repository. Nobody reading this file could
  // open it, `git clean` would never have been the thing that lost it because
  // it was never here in the first place, and a reviewer had no way to check
  // the claim -- which is exactly what WinnHostCapability's own doc comment
  // (above) says these fields exist to prevent. Android's evidence is
  // committed; macOS's and iOS's are committed. Linux alone rested on files
  // that could not be cited.
  //
  // RE-EARNED IN-REPO ON 2026-08-06, against a harder bar than the original.
  // Full raw log, in this repository and citeable -- the paths below are on one
  // line each on purpose, because the test that checks them greps this file's
  // raw text and a wrapped path is a path it cannot find:
  // .winn_platform_progress/evidence/winn3_linux_20260806T194436Z_two_host_lan_gateway_session.txt
  // .winn_platform_progress/evidence/winn3_linux_20260806T194436Z_gateway_far_end_timeline.txt
  // .winn_platform_progress/evidence/winn3_linux_20260806T203726Z_flutter_app_shipping_path_session.txt
  // .winn_platform_progress/evidence/winn3_linux_20260808_exact_4MiB_fullset.txt
  // Narrative: docs/handoff/
  // WINN3_LINUX_TWO_HOST_CITABLE_EVIDENCE_20260806.md and
  // WINN3_LINUX_FIRST_SHIPPING_PATH_SESSION_20260806.md and
  // WINN3_LINUX_FULL_BAR_20260808.md and docs/handoff/WINN3_LINUX_CRIT1_20260808.md.
  //
  // What that run is. TWO SEPARATE PHYSICAL MACHINES on a LAN -- an aarch64
  // Linux laptop as the client and an aarch64 NVIDIA GB10 as the AmneziaWG
  // gateway -- rather than the original run's two containers on one host, with
  // a real NAT between them. The shipping Dart gate emitted the [winn]
  // section, linux/runner/linux_winn_host.cc (compiled unmodified) ran it, and
  // activate_winn_transport was extracted verbatim from PrivilegedTunnelScript()
  // by awk rather than retyped. 470 s of session spanning THREE AmneziaWG
  // rekeys, each confirmed independently at BOTH ends (client
  // tx_handshake_initiations=4 / rx_handshake_responses=4; the gateway logged
  // four "Received handshake initiation"/"Sending handshake response" pairs
  // ~120 s apart on the other machine). 9.409 MiB of inner payload sent and
  // 9.291 MiB returned BYTE-IDENTICAL with matching SHA-256 (0f06fb69...),
  // 0 corrupt and 0 duplicate. transport_observed_both_ways=true with
  // tx_rejected=0, rx_dropped=0, rx_oversize=0, rx_foreign_sender=0, and the
  // seam ring conserved exactly (received=7921 written=7921). The 1.26% of
  // datagrams that did not come back are located by the far end's own count on
  // the outbound 802.11 hop, before the gateway saw them -- not in the
  // datapath, whose every drop counter is zero. A second independent session
  // repeated it at 4.298 MiB sent / 4.204 MiB verified.
  //
  // The route-exclusion defect the 2026-08-04 lane found by execution
  // reproduces unchanged on this topology and is fixed by the same shipped
  // code: `ip route get <gateway>` returns `dev winsvpn table 51820 src
  // 10.99.0.2` BEFORE activate_winn_transport and `via <lan> dev <phys> src
  // <physical address> mark 0xca6c` after it, and reverts the moment
  // cleanup_winn_transport removes it. The gateway learned the peer endpoint as
  // the client's PHYSICAL address on the port the engine's own local_endpoint
  // reports, never a tunnel-internal one.
  //
  // Lifecycle, all three: a clean stop (LinuxWinnEngineRunning false, no engine
  // process left); one stop->start reconnect onto a new seam port carrying an
  // exact 4.001 MiB block; and one kill-engine-mid-session in which the
  // interface stays UP with its routes and a recent handshake while the tunnel
  // carries NOTHING (4 pings, 0 replies) -- and LinuxWinnEngineRunning reports
  // false within a second, which is the whole reason it is channel liveness
  // rather than waitpid.
  //
  // CRITERION 1, BY CONSTRUCTION, on the two_host harness alone: the run drove
  // linux_winn_host.cc directly, not through a live Flutter app, so
  // linux_tunnel_backend.cc's GTK-side wiring remains proven by compilation only;
  // awg-quick itself was never invoked; the kill switch was not installed; and
  // the client ran in a network namespace. Section 16 of the two_host evidence
  // lists all eight. THOSE FOUR GAPS ARE CLOSED by the Flutter app session at
  // .winn_platform_progress/evidence/winn3_linux_20260806T203726Z_flutter_app_shipping_path_session.txt,
  // which used the shipping GTK runner (flutter build linux --debug
  // --target=lib/winn_protocol_dev_session_main.dart, WINN_DEV_SESSION=true,
  // UNCONTAINED_FULL_TUNNEL_ON_A_DISPOSABLE_VM), owned the host's default route
  // (default dev winsvpn table 51820 src 10.99.0.2), ran awg-quick verbatim and
  // installed the WINSVPN_KS kill switch (863 mark-RETURN, 205 REJECT, mangle 3
  // rules for the gateway). That file is the criterion-1 artefact; the two_host
  // files remain the artefacts for the transfer/handshake/rekey proofs where
  // off-subnet topology matters. See docs/handoff/WINN3_LINUX_CRIT1_20260808.md §1.
  //
  // DIGEST, RESTRICTED vs FULL: the two_host 7880-datagram bulk has
  // digest_match_over_returned_set true (0f06fb69..., 7781/7880, 1.26% wireless
  // loss located on the outbound 802.11 hop before the gateway saw it, not in
  // datapath -- every drop counter zero) but digest_match_full_set false, which
  // is the honest reporting the audit flagged. The EXACT 3351-datagram block at
  // .winn_platform_progress/evidence/winn3_linux_20260808_exact_4MiB_fullset.txt
  // is the same bytes, same seam (received 3378 written 3378), same 192.168.50.104
  // Mac echo gateway, with ZERO loss (3351/3351, 6905aef... sent == returned) so
  // digest_match_full_set true. That file is the 4-MiB full-set artefact; the
  // two_host bulk remains the rekey/transfer proof where the burst overran the
  // radio. See WINN3_LINUX_LINK_QUALITY_AND_CRITERION5_DIAGNOSIS_20260807.md §2.
  //
  // DEMOTED TO .absent ON 2026-08-08 BY ADJUDICATION, alongside Android and
  // for the same reasons. Everything above is kept because it is true about
  // those runs; none of it is shipping-path evidence. See
  // docs/handoff/ADJUDICATION_20260808.md, Decision (a) ("Linux ... is the
  // same case and should move with it") and the harness-vs-shipping-path
  // Finding. The three grounds:
  //
  //  1. THE CITED EVIDENCE IS A HARNESS, AND ITS OWN DOCUMENT SAYS SO --
  //     WINN3_LINUX_CRIT1_20260808.md:15 states it in those words. The
  //     two_host run drove linux/runner/linux_winn_host.cc as a standalone
  //     binary inside a network namespace (:24-31). The stronger Flutter-app
  //     session started from dev_winn3_linux.json via
  //     lib/winn_protocol_dev_session_main.dart -- a dev entry point, not a
  //     fetched config plus a user-triggered Connect -- so that document
  //     scores its own criterion 1 as PARTIAL (:88).
  //  2. THE RELEASE PIPELINE CANNOT BUILD THE ONLY ARCHITECTURE LINUX EVER
  //     RAN ON. Every Linux winn/3 session in the corpus ran on aarch64, and
  //     tools/build_linux_release.sh:178-210 cannot target arm64: Flutter
  //     hard-refuses the x64-host-to-arm64-target cross-build (:178-181), and
  //     Xray, the AmneziaWG userspace tools archive and the Go archive are
  //     amd64-only pins (:206-210) -- "an arm64 release needs a genuine arm64
  //     Linux host or CI runner" (:183-186). So the shipping artefact for the
  //     tested architecture cannot be produced at all today. That is strictly
  //     worse than Android, where the Release is merely owner-gated.
  //  3. IT DESCRIBES A PROTOCOL WINN/3 NO LONGER IS. The owner ruled on
  //     2026-08-08 that v3 is a STANDALONE protocol -- own handshake, own
  //     crypto, own datapath, AmneziaWG and Xray removed. The seam and
  //     exclusion prose this entry used to carry was explicitly about keeping
  //     awg-quick's tun and reusing awg-quick's fwmark: an AmneziaWG-relaying
  //     datapath. Those claims cannot describe v3 under the new definition
  //     however well they were evidenced.
  //
  // As with Android the demotion is free today (no node serves winn/3) and
  // leaving it `.present` would have planted a production-first-test hazard.
  // The flip-back gate is the one written on the Android entry above, and it
  // applies identically here.
  'linux': WinnHostCapability.absent(
    platform: 'linux',
    missing:
        'a winn/3 session on the SHIPPING PATH, on an architecture this repo '
        'can actually build a release for. The Linux host source is complete '
        'and its mechanism is genuinely proven at the transfer level -- '
        'linux/runner/linux_winn_host.cc binds the seam and '
        'linux/runner/linux_tunnel_backend.cc excludes the outer datagrams by '
        'route -- and real multi-megabyte sessions with byte-identical '
        'digests and surviving rekeys did run across two physical hosts. But '
        'the cited criterion-1 evidence is a HARNESS and its own document '
        'says so (docs/handoff/WINN3_LINUX_CRIT1_20260808.md:15): the '
        'two_host run drove the host binary directly inside a network '
        'namespace, and the Flutter-app session entered through '
        'lib/winn_protocol_dev_session_main.dart with a dev JSON rather than '
        'a fetched config plus Connect, which that document scores PARTIAL '
        '(:88). Worse, the release pipeline CANNOT TARGET arm64 -- the only '
        'architecture Linux ever ran winn/3 on -- because Flutter refuses the '
        'x64-host-to-arm64 cross-build and Xray, the AmneziaWG tools archive '
        'and the Go archive are amd64-only pins '
        '(tools/build_linux_release.sh:178-210), so the shipping artefact for '
        'the tested architecture cannot be produced at all. And the datapath '
        'proven here RELAYS AmneziaWG -- it keeps awg-quick\'s tun and reuses '
        'awg-quick\'s fwmark -- which winn/3 no longer is: the owner ruled on '
        '2026-08-08 that v3 is a standalone protocol with AmneziaWG and Xray '
        'removed. See docs/handoff/ADJUDICATION_20260808.md, Decision (a) and '
        'the harness-vs-shipping-path Finding.',
  ),
};

/// The Winn host state of [operatingSystem], matched case- and
/// whitespace-insensitively. An unknown platform is unsupported.
WinnHostCapability winnHostCapability(String operatingSystem) {
  final key = operatingSystem.trim().toLowerCase();
  return kWinnHostCapabilities[key] ??
      WinnHostCapability.absent(
        platform: key,
        missing: 'this build has no Winn host for "$key".',
      );
}

/// Owner-controlled release enablement for the standalone host implementations.
///
/// The historical evidence table remains fail-closed by default. A release
/// candidate can enable only the platforms being built and physically tested,
/// for example `--dart-define=WINS_WINN3_ENABLED_PLATFORMS=android,ios`.
/// Unknown, duplicated, padded, or cased values invalidate the entire define.
const String kWinn3EnabledPlatformsBuildValue = String.fromEnvironment(
  'WINS_WINN3_ENABLED_PLATFORMS',
  defaultValue: '',
);

/// Standalone-v3 hosts that have a complete shipping executor in this RC.
/// Release producers opt in one target at a time after compiling the native
/// host and descriptor ring. Historical capability evidence remains in
/// [kWinnHostCapabilities]; the exact release build declaration is the
/// controlling fact for these standalone executors.
const Set<String> kWinn3StandaloneReleasePlatforms = <String>{
  'android',
  'ios',
  'linux',
  'macos',
  'windows',
};

Set<String> winn3BuildEnabledPlatforms([String? buildValue]) {
  final raw = buildValue ?? kWinn3EnabledPlatformsBuildValue;
  if (raw.isEmpty) return <String>{};
  final parts = raw.split(',');
  final enabled = <String>{};
  for (final part in parts) {
    if (part.isEmpty ||
        part != part.trim() ||
        part != part.toLowerCase() ||
        !kWinn3StandaloneReleasePlatforms.contains(part) ||
        !enabled.add(part)) {
      return <String>{};
    }
  }
  return enabled;
}

/// The platforms this exact build can carry, sorted, for user-facing copy.
List<String> winnSupportedPlatforms({String? buildValue}) {
  final releaseEnabled = winn3BuildEnabledPlatforms(buildValue);
  final names = kWinnHostCapabilities.entries
      .where((e) => e.value.supported || releaseEnabled.contains(e.key))
      .map((e) => e.key)
      .toList()
    ..sort();
  return names;
}

/// Whether [operatingSystem] has a Winn Protocol path this build can start.
bool platformSupportsWinnProtocol(
  String operatingSystem, {
  String? buildValue,
}) {
  final platform = operatingSystem.trim().toLowerCase();
  return winnHostCapability(platform).supported ||
      winn3BuildEnabledPlatforms(buildValue).contains(platform);
}

/// The display name for a `Platform.operatingSystem` value, for the one message
/// a user actually reads.
String _winnPlatformDisplayName(String platform) {
  switch (platform) {
    case 'android':
      return 'Android';
    case 'ios':
      return 'iOS';
    case 'macos':
      return 'macOS';
    case 'windows':
      return 'Windows';
    case 'linux':
      return 'Linux';
    default:
      return platform;
  }
}

/// "Android", or "Android or macOS", or "Android, macOS or Windows".
String winnSupportedPlatformsSentence({String? buildValue}) =>
    winnPlatformsSentence(winnSupportedPlatforms(buildValue: buildValue));

/// The joining half of [winnSupportedPlatformsSentence], over an arbitrary
/// list of `Platform.operatingSystem` keys.
///
/// Split out on 2026-08-08 so the copy a user actually reads can be tested on
/// every branch. It used to be reachable only through the live table, which
/// meant the one-name and two-name joins were covered incidentally by whatever
/// happened to be `.present` and the three-name join was covered by nothing at
/// all. Now that the adjudication has demoted every entry, going through the
/// table would exercise only the empty branch -- and the day a platform is
/// re-promoted is the wrong day to discover the sentence reads badly.
String winnPlatformsSentence(List<String> platforms) {
  final names = platforms.map(_winnPlatformDisplayName).toList();
  if (names.isEmpty) return 'no platform in this build';
  if (names.length == 1) return names.single;
  return '${names.sublist(0, names.length - 1).join(', ')} or ${names.last}';
}

/// Normalizes a served `protocol_version` slot.
///
/// Absent, null or blank means the shipping AmneziaWG protocol, so old configs
/// and old hubs behave exactly as they did before the field existed.
String normalizedWinnProtocolVersion(Object? raw) {
  final text = (raw ?? '').toString().trim();
  return text.isEmpty ? kWinnProtocolV1 : text;
}

String? strictWinnProtocolVersionForTunnelConfig(
  Map<String, dynamic> config,
) {
  final observed = <String>[];
  for (final key in const <String>['protocol_version', 'protocolversion']) {
    if (!config.containsKey(key)) continue;
    final raw = config[key];
    if (raw is! String) return null;
    final version = raw.trim();
    if (version.isEmpty) return null;
    observed.add(version);
  }
  if (observed.isEmpty || observed.toSet().length != 1) return null;
  final version = observed.first;
  return version == kWinnProtocolV1 || version == kWinnProtocolV3
      ? version
      : null;
}

/// Preserves every supplied version alias until strict dispatch validates them.
Map<String, dynamic> copyWinnProtocolVersionAliases({
  required Map<String, dynamic> dest,
  required Map<String, dynamic> raw,
}) {
  for (final key in const <String>['protocol_version', 'protocolversion']) {
    if (raw.containsKey(key)) dest[key] = raw[key];
  }
  if (!raw.containsKey('protocol_version')) {
    dest['protocol_version'] = raw.containsKey('protocolversion')
        ? raw['protocolversion']
        : kWinnProtocolV1;
  }
  return dest;
}

/// Mirrors `WinnEngineConfig.isIpLiteralEndpoint` and, through it,
/// `datapath.validateIPLiteralEndpoint`: an IP literal and a nonzero port,
/// never a hostname. IPv6 is bracketed, as in `[2001:db8::1]:51820`.
bool isWinnIpLiteralEndpoint(String endpoint) {
  if (endpoint.isEmpty) return false;
  final String host;
  final String portText;
  if (endpoint.startsWith('[')) {
    final end = endpoint.indexOf(']');
    if (end < 0 || end + 1 >= endpoint.length || endpoint[end + 1] != ':') {
      return false;
    }
    host = endpoint.substring(1, end);
    portText = endpoint.substring(end + 2);
    if (!_isIpv6Literal(host)) return false;
  } else {
    final colon = endpoint.lastIndexOf(':');
    if (colon <= 0) return false;
    host = endpoint.substring(0, colon);
    portText = endpoint.substring(colon + 1);
    if (!_isIpv4Literal(host)) return false;
  }
  // Hub `winn3_is_ip_literal_endpoint` requires `port.isdigit()`. Dart's
  // `int.tryParse` (and Kotlin `toIntOrNull`) accept a leading '+', and
  // Go `netip.ParseAddrPort` does not. A stolen signing key that minted
  // `203.0.113.7:+51820` would verify here and then fail closed at the
  // engine with no named reason: the silent-failure class.
  if (portText.isEmpty) return false;
  for (var i = 0; i < portText.length; i++) {
    final c = portText.codeUnitAt(i);
    if (c < 0x30 || c > 0x39) return false;
  }
  final port = int.tryParse(portText);
  if (port == null) return false;
  return port >= 1 && port <= 65535;
}

bool _isIpv4Literal(String host) {
  final parts = host.split('.');
  if (parts.length != 4) return false;
  var allZero = true;
  for (final part in parts) {
    if (part.isEmpty || part.length > 3) return false;
    if (!part
        .split('')
        .every((c) => c.codeUnitAt(0) >= 0x30 && c.codeUnitAt(0) <= 0x39)) {
      return false;
    }
    // Same leading-zero refusal as [isWinnInnerIpv4] and the hub's
    // `ipaddress.IPv4Address`: "01" and "1" are different strings for the
    // same address, and Python's ipaddress rejects the padded form.
    if (part.length > 1 && part.startsWith('0')) return false;
    final value = int.tryParse(part);
    if (value == null || value < 0 || value > 255) return false;
    if (value != 0) allZero = false;
  }
  // Unspecified and multicast are not routable unicast literals.
  if (allZero) return false;
  final first = int.parse(parts[0]);
  return first < 224 || first > 239;
}

bool _isIpv6Literal(String host) {
  if (host.isEmpty || host == '::') return false;
  // A zone id (`fe80::1%lo0`) names a local interface. Accepting one would
  // make the client bind a scoped address the gateway never has.
  if (host.contains('%')) return false;
  final List<int> bytes;
  try {
    bytes = Uri.parseIPv6Address(host);
  } catch (_) {
    return false;
  }
  if (bytes.length != 16) return false;
  if (bytes.every((b) => b == 0)) return false; // unspecified
  if (bytes[0] == 0xff) return false; // multicast ff00::/8
  // IPv4-mapped ::ffff:a.b.c.d. The v4 unspecified/multicast checks only
  // see the IPv6 form, so ::ffff:0.0.0.0 and ::ffff:224.0.0.1 used to
  // pass. Unmap and apply the same v4 rule the hub's ipaddress check
  // applies to a native IPv4 literal.
  var mapped = true;
  for (var i = 0; i < 10; i++) {
    if (bytes[i] != 0) {
      mapped = false;
      break;
    }
  }
  if (mapped && bytes[10] == 0xff && bytes[11] == 0xff) {
    if (bytes[12] == 0 && bytes[13] == 0 && bytes[14] == 0 && bytes[15] == 0) {
      return false;
    }
    if (bytes[12] >= 224 && bytes[12] <= 239) return false;
  }
  return true;
}

/// The Xray inbound port a stacked `stealth-chain` session would drive, or
/// null when [config] has not asked for the stack or cannot carry it.
///
/// FOUR conditions, all required, because each one is a way the stack could be
/// half-present and the resulting session would then be neither arrangement:
///
///  1. The hub explicitly served [kWinnOuterTransportStealthChain]. An absent
///     slot means every existing config behaves exactly as it did.
///  2. `stealth_active`, because the `[Xray]` section `_buildRawAmneziaConfig`
///     emits -- and therefore the Xray process every native host starts -- is
///     gated on it. Without it there is no stealth leg to stack on.
///  3. `xray.enabled`, the native hosts' own test for the same thing.
///  4. A usable `local_port`. It becomes the Winn engine's gateway endpoint,
///     so a missing or malformed one would point the engine at nothing.
///
/// Returning null is never "start direct-awg instead" -- callers turn it into
/// a refusal.
int? winnStealthChainXrayLocalPort(Map<String, dynamic> config) {
  final requested =
      (config[kWinnOuterTransportKey] ?? '').toString().trim().toLowerCase();
  if (requested != kWinnOuterTransportStealthChain) return null;
  if (!_isTrue(config['stealth_active'])) return null;
  final xray = config['xray'] is Map
      ? Map<String, dynamic>.from(config['xray'] as Map)
      : const <String, dynamic>{};
  if (!_isTrue(xray['enabled'])) return null;
  final port = int.tryParse(
      (xray['local_port'] ?? xray['localport'] ?? '').toString().trim());
  if (port == null || port < 1 || port > 65535) return null;
  return port;
}

/// True when [config] is a `winn/3` config that will actually run stacked on
/// the stealth leg.
///
/// The one thing outside this file that needs to know: `_buildRawAmneziaConfig`
/// must leave the AmneziaWG peer endpoint pointed at the real gateway (the
/// native hosts rewrite it to the Winn seam at start) instead of pointing it at
/// the Xray inbound as v1 stealth does. Both relays would otherwise want the
/// same field, which is the conflict the refusals were written against.
bool winnConfigUsesStealthChain(Map<String, dynamic> config) {
  if (normalizedWinnProtocolVersion(config['protocol_version']) !=
      kWinnProtocolV3) {
    return false;
  }
  return winnStealthChainXrayLocalPort(config) != null;
}

/// Decides whether a `winn/3` config may start the Winn path on
/// [operatingSystem], and builds the `[winn]` section if it may.
///
/// [config] is a normalized served `vpn_config` (the shape
/// `_normalizeVpnConfig` produces, plus [applyWinn3ServedFields] so the
/// hub A3 `winn3_*` envelope and device half are still present). Only callers
/// that have already established `protocol_version == 'winn/3'` should call this.
///
/// Never returns a decision that means "use AmneziaWG instead".
// =============================================================================
// THE SIGNED GATEWAY DESCRIPTOR
// =============================================================================
//
// The hub has served `vpn_config["winn3_descriptor"]` since 2026-08-08 and NO
// DART CODE READ IT. This is that reader, and it verifies before it reads.
//
// WHY VERIFICATION IS NOT OPTIONAL HERE, when the transport is already
// authenticated. The descriptor carries the gateway's static public key, the
// per-gateway admission secret and the gateway id -- an attacker who could
// substitute one would hand this client an attacker's static key, an
// attacker's admission secret and an attacker's endpoint in a single object,
// and the client would build a perfectly working tunnel to them. That is the
// whole reason the hub HOLDS NO SIGNING KEY: it verifies an offline-signed
// envelope and stores it verbatim, so a leaked admin token can withhold or
// replay a descriptor but never mint one. Verifying only at the hub would
// throw that property away at the last hop.
//
// A MISSING OR UNVERIFIABLE DESCRIPTOR IS "STANDALONE UNAVAILABLE", NEVER A
// REFUSED CONNECTION -- unless the served carrier is `winn3`, in which case
// there is no session to fall back to and the refusal is named. This asymmetry
// is deliberate and matches the hub's: withholding is a supported operator
// action, so it must not break clients that were not going to run standalone.

/// The descriptor payload format this build understands.
///
/// MUST equal `WINN3_DESCRIPTOR_FORMAT_VERSION` in the control plane. `v` is
/// inside the signed bytes, so a descriptor of any other version is refused
/// rather than partially read -- an unknown format is either a typo or a newer
/// hub, and guessing at either is how a client ends up sealing initiations no
/// gateway can open.
const int kWinn3DescriptorFormatVersion = 3;

/// Descriptor bounds shared with the control-plane validator.
///
/// A client must enforce these independently after signature verification.
/// Otherwise a stolen signing key, a stale hub, or a substituted signed
/// descriptor can publish a lifetime or tag geometry the gateway contract
/// would never accept.
const int kWinn3MinDescriptorTtlSeconds = 3600;
const int kWinn3MaxDescriptorTtlSeconds = 30 * 24 * 3600;
const int kWinn3MinDescriptorTagSize = 16;
const int kWinn3MaxDescriptorTagSize = 32;

// The shipping host and gateway constructors currently implement only this
// wire profile. These signed fields are not negotiated, so accepting any other
// value would claim to verify one profile while silently running another.
const int kWinn3SupportedTagSize = 32;
const String kWinn3SupportedPadding = 'bucket';
const int kWinn3SupportedBucketWindowSeconds = 10;
const int kWinn3SupportedMaxSkewSeconds = 60;

/// Closed payload schema shared with the format-v3 control plane.
///
/// Unknown fields are refused so a newer descriptor format cannot be
/// partially interpreted by this client. The two dual-auth fields are an
/// optional pair; every other field is required.
const Set<String> kWinn3DescriptorRequiredFields = <String>{
  'admission_gen',
  'admission_secret',
  'alg',
  'bucket_window_s',
  'endpoint',
  'gateway_id',
  'iat',
  'inner_resolver_v4',
  'inner_router_v4',
  'kid',
  'max_skew_s',
  'node',
  'not_after',
  'padding',
  'seq',
  'static_pub',
  'tag_size',
  'v',
};
const Set<String> kWinn3DescriptorOptionalFields = <String>{
  'auth_ed25519',
  'auth_mldsa65',
};

/// The descriptor signing slots, disjoint from the announcement family
/// (`a1..a3`) and the discovery family (`d1..d3`). Three families, three blast
/// radii; see the control plane's WINN3_DESCRIPTOR_KEY_SLOTS.
const List<String> kWinn3DescriptorSlotIds = <String>['g1', 'g2', 'g3'];

/// The signing domain, byte for byte `WINN3_DESCRIPTOR_DOMAIN`. The signed
/// message is `DOMAIN || 0x00 || payload`, and the separator is what stops a
/// signature over an announcement or a discovery record ever verifying here.
const String kWinn3DescriptorDomain = 'winsvpn-winn3-descriptor/v1';

/// Ceiling on the decoded payload bytes, byte-for-byte
/// `WINN3_MAX_DESCRIPTOR_BYTES` in the control plane.
///
/// Checked AFTER base64 decode and BEFORE `json.decode`, because the JSON
/// parse runs on unauthenticated bytes (kid has to be read to select the
/// slot). Without this bound a hostile envelope allocates and walks an
/// arbitrary JSON graph, then fails the signature: a denial of service on
/// the client that verifies descriptors from the network.
const int kWinn3MaxDescriptorBytes = 4096;

/// Maximum unescaped object/array nesting in a descriptor payload.
///
/// A legitimate descriptor is a flat object (depth 1). The Go host-profile
/// parser uses 8 for the same reason (`maxWinn3ProfileJSONDepth`): dart:convert
/// recurses while decoding, and a nesting bomb inside the 4096-byte ceiling is
/// a stack overflow, which is a panic, which is a denial of service of the
/// client that verifies descriptors from the network. Checked on the raw
/// bytes BEFORE `json.decode`, because the overflow happens during decode.
/// `kid` has to be read to select the slot, so this parse runs on
/// unauthenticated bytes.
const int kWinn3MaxDescriptorJSONDepth = 8;

/// Ceiling on the envelope's base64 `payload` STRING, checked BEFORE
/// `base64.decode`. 4096 decoded bytes are at most 5464 base64 characters;
/// 8192 leaves room for padding. Without this a hostile envelope allocates
/// the decoded buffer of an arbitrary-length string, then fails the byte
/// ceiling: a denial of service on the client that verifies descriptors
/// from the network.
const int kWinn3MaxDescriptorPayloadB64Chars = 8192;

/// Ceiling on the envelope's base64 `sig` STRING. A 64-byte signature is
/// 88 characters; 256 refuses a hostile megabyte before decode.
const int kWinn3MaxDescriptorSignatureB64Chars = 256;

/// Reviewed ceremony public keys (Track B, 2026-08-18T21:42:23Z).
///
/// These are PUBLIC Ed25519 halves. A client with no compiled key cannot tell
/// a real descriptor from a forged one, so they are the `String.fromEnvironment`
/// defaults. `--dart-define=WINS_WINN3_DESCRIPTOR_PUBKEY_G*` still overrides
/// them; an empty or unusable override drops that slot
/// ([Winn3DescriptorKeyRing.fromEncoded]) and fail-closes.
///
/// Source: `xprize/v3-lane/ceremony/ring-manifest.json` / README.md, and
/// `tools/winn3_descriptor_ring_defines.py` `RING`. Recomputed this change
/// via `tools/winn3_descriptor_ring_identity.py` (WIRE-FORM).
/// Dart compile-time env: https://dart.dev/libraries/core/environment-declarations
const String kWinn3ReviewedDescriptorPubkeyG1 =
    'L2mAYdYIXPCFuNoH5ntgBBubFSnnlzIAnXwKttpehaQ=';
const String kWinn3ReviewedDescriptorPubkeyG2 =
    'eVCAHWXqUM1+m5nlVy2JR+Q4/mkYGTxlk119aiQh89M=';
const String kWinn3ReviewedDescriptorPubkeyG3 =
    '53JhsQBxKH5DG145LcaBunOX4lbt+J7Js0oPyJnj9Q0=';

/// WIRE-FORM ring identity: sha256 of `g1=<hex>\ng2=<hex>\ng3=<hex>\n`.
///
/// Manifest digest `29c66c18f5aef6eb064e065a5d7c3c98aa1548f758ac6d19b19a9d4a7863e7fb`
/// is provenance only and MUST never be compiled as this define.
const String kWinn3ReviewedDescriptorRingSha256 =
    '52e91c72ca52d23059724e0a6c25c2f45bae574a85a84c884c5b7fd367cbf032';

const String _kWinn3PubKeyG1 = String.fromEnvironment(
  'WINS_WINN3_DESCRIPTOR_PUBKEY_G1',
  defaultValue: kWinn3ReviewedDescriptorPubkeyG1,
);
const String _kWinn3PubKeyG2 = String.fromEnvironment(
  'WINS_WINN3_DESCRIPTOR_PUBKEY_G2',
  defaultValue: kWinn3ReviewedDescriptorPubkeyG2,
);
const String _kWinn3PubKeyG3 = String.fromEnvironment(
  'WINS_WINN3_DESCRIPTOR_PUBKEY_G3',
  defaultValue: kWinn3ReviewedDescriptorPubkeyG3,
);
const String _kWinn3DescriptorRingSha256 = String.fromEnvironment(
  'WINS_WINN3_DESCRIPTOR_RING_SHA256',
  defaultValue: kWinn3ReviewedDescriptorRingSha256,
);

/// Raw Ed25519 public key length. The ceremony emits raw 32 bytes base64,
/// because that is what a `--dart-define` carries.
const int kWinn3DescriptorPublicKeyBytes = 32;
const int kWinn3DescriptorSignatureBytes = 64;

/// The compiled-in verification ring, `g1 g2 g3`.
///
/// A slot that is set but unusable is DROPPED rather than tolerated, exactly as
/// `DiscoveryKeyRing` does: a typo must degrade to "that key does not exist",
/// never to a verifier that accepts something it should not.
class Winn3DescriptorKeyRing {
  Winn3DescriptorKeyRing._(this._keys);

  factory Winn3DescriptorKeyRing.fromEncoded(Map<String, String> encoded) {
    final keys = <String, List<int>>{};
    for (final slotId in kWinn3DescriptorSlotIds) {
      final value = (encoded[slotId] ?? '').trim();
      if (value.isEmpty) continue;
      List<int> raw;
      try {
        raw = base64.decode(value);
      } catch (_) {
        continue;
      }
      if (raw.length != kWinn3DescriptorPublicKeyBytes) continue;
      keys[slotId] = raw;
    }
    return Winn3DescriptorKeyRing._(keys);
  }

  factory Winn3DescriptorKeyRing.fromCompiledDefines() =>
      Winn3DescriptorKeyRing.fromEncoded(<String, String>{
        'g1': _kWinn3PubKeyG1,
        'g2': _kWinn3PubKeyG2,
        'g3': _kWinn3PubKeyG3,
      });

  final Map<String, List<int>> _keys;

  /// Slots that yielded a usable key, in `g1 g2 g3` order.
  List<String> get compiledSlotIds =>
      kWinn3DescriptorSlotIds.where(_keys.containsKey).toList(growable: false);

  /// False means this build cannot verify a descriptor at all, which is
  /// "standalone v3 unavailable" -- never "accept it unverified".
  bool get enforcing => _keys.isNotEmpty;

  /// Stable public identity of the usable ring, without exposing key bytes.
  /// The canonical input is one `slot=hex` line per populated slot.
  String get identitySha256 {
    final canonical = StringBuffer();
    for (final slot in compiledSlotIds) {
      canonical
        ..write(slot)
        ..write('=')
        ..write(_keys[slot]!
            .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
            .join())
        ..write('\n');
    }
    return hashes.sha256.convert(utf8.encode(canonical.toString())).toString();
  }

  bool attestsExpectedIdentity(String expectedSha256) {
    final expected = expectedSha256.trim().toLowerCase();
    return enforcing &&
        RegExp(r'^[0-9a-f]{64}$').hasMatch(expected) &&
        identitySha256 == expected;
  }

  /// Verify [signature] over [message] under the slot named by [kid].
  ///
  /// Bound to ONE slot rather than tried against every key, because `kid` is
  /// inside the signed bytes: a signature that verifies under a slot other than
  /// the one it claims is a signature that has been moved, and accepting it
  /// would make the slot field decorative.
  Future<bool> verify({
    required List<int> message,
    required List<int> signature,
    required String kid,
  }) async {
    final keyBytes = _keys[kid];
    if (keyBytes == null) return false;
    if (signature.length != kWinn3DescriptorSignatureBytes) return false;
    try {
      return await Ed25519().verify(
        message,
        signature: Signature(
          signature,
          publicKey: SimplePublicKey(keyBytes, type: KeyPairType.ed25519),
        ),
      );
    } catch (_) {
      return false;
    }
  }
}

/// A verified gateway descriptor: the GATEWAY's half of a standalone config.
///
/// Every byte-valued field stays in its DESCRIPTOR ENCODING (base64) except
/// [innerRouterV4], which is dotted-quad text in the descriptor and dotted-quad
/// text in the `[winn]` section. Nothing is re-encoded on the way through --
/// see [gatewayIdBase64] for why that matters more than it looks.
class Winn3Descriptor {
  const Winn3Descriptor({
    required this.node,
    required this.endpoint,
    required this.innerRouterV4,
    required this.gatewayStaticBase64,
    required this.gatewayIdBase64,
    required this.admissionKey,
    required this.kid,
    required this.notAfter,
    this.innerResolverV4 = '',
    this.authEd25519Base64 = '',
    this.authMldsa65Base64 = '',
  });

  /// The node slug this descriptor names, INSIDE the signed bytes.
  final String node;

  /// `host:port`, an IP literal with a nonzero port.
  final String endpoint;

  /// The inner next hop, dotted-quad plain text.
  final String innerRouterV4;

  /// The gateway's inner DNS responder address, in dotted-quad notation.
  ///
  /// Required and equal to the inner router in verified format-3 descriptors.
  ///
  /// The control plane is at `WINN3_DESCRIPTOR_FORMAT_VERSION = 3` with
  /// `inner_resolver_v4` in its required field set, validated exactly as
  /// `inner_router_v4` is (dotted quad, in-pool, reserved against device
  /// allocation). The hub and this verifier additionally require equality
  /// with `inner_router_v4`, matching the gateway's resolver binding.
  ///
  /// This client pins [kWinn3DescriptorFormatVersion] at 3, matching the hub.
  /// The 2 → 3 bump shipped 2026-08-12 after the three preconditions named by
  /// the former advertisement-interlock guard (a resolver answering on a real
  /// node, forwarding verified end to end, and the desktop halves consuming
  /// the field rather than merely tolerating it) were recorded as met. This
  /// file is the interlock release those measurements authorised.
  ///
  /// The constructor permits an empty value for unverified local objects.
  /// Format-3 descriptor verification requires a valid IPv4 value and rejects
  /// a value different from the inner router. A verified value is carried
  /// through to the `[winn]` section without inventing a resolver.
  ///
  /// A descriptor that NAMES a resolver before one answers still converts four
  /// loud, diagnosable refusals into a GREEN promotion in which names resolve
  /// (or worse, do not) while every TCP connection black-holes. That failure
  /// is now an operator-ordering constraint (resolver live, then sign), not a
  /// client format pin. See the gateway deployment runbook §0.2.
  ///
  /// It is a SIGNED fact and it rides the descriptor for the same reason
  /// `inner_router_v4` does: it is a property of the gateway, identical for
  /// every device, and an unsigned `vpn_config` key would let anyone who can
  /// forge a hub response repoint DNS while the tunnel stays up.
  /// `conform.ServedWinnSectionCarriesNoPostureKey` still pins `dns`,
  /// `dns_are_inner`, `dns_servers` and `resolvers` ABSENT and this field does
  /// not touch that list: an ADDRESS the client then runs its own derivation
  /// against is different in kind from a transported boolean asserting "this
  /// resolver is inside the tunnel", which is the leak wearing a flag.
  final String innerResolverV4;

  /// The gateway's X25519 static public key, base64. Descriptor field
  /// `static_pub`; `[winn] gateway_static` on the way out.
  final String gatewayStaticBase64;

  /// Optional dual-signature attestation public keys from the signed
  /// descriptor (base64, as transported). Both present on a dual-provisioned
  /// node, both absent otherwise (docs/DUAL_SIGNATURE_SPEC.md).
  final String authEd25519Base64;
  final String authMldsa65Base64;

  /// True exactly when this descriptor is dual-provisioned.
  bool get hasDualAuth =>
      authEd25519Base64.isNotEmpty && authMldsa65Base64.isNotEmpty;

  /// The gateway id, STILL BASE64.
  ///
  /// # This value is passed through verbatim and that is load-bearing
  ///
  /// `gateway_id` is an authenticated input to the admission tag and is NEVER
  /// TRANSMITTED, so the two ends never discover that they disagree about it.
  /// A client whose bytes differ from the gateway's computes a tag the gateway
  /// cannot verify, and a v3 gateway does not answer a datagram it could not
  /// authenticate: no response, no ICMP, no log line. On a censored network
  /// that is indistinguishable from the gateway being blocked.
  ///
  /// The decode therefore happens EXACTLY ONCE, at the descriptor boundary in
  /// the host that reads descriptor-shaped fields --
  /// `WinsTunnelConfig.winn3GatewayIDOperatorText` on Apple -- and the engine
  /// is handed the raw operator-string bytes. This class does not decode it,
  /// and neither does the INI writer; both would be a second decode, and a
  /// second decode is how the `gateway-id-is-raw-operator-bytes` defect
  /// happened. [gatewayIdOperatorText] exists only to VALIDATE that it decodes
  /// to text, so a malformed value is a named refusal here rather than a
  /// session that starts and is ignored forever.
  final String gatewayIdBase64;

  /// The admission secret, base64, OPAQUE.
  ///
  /// # It is opaque bytes and nothing here may interpret it
  ///
  /// `keygen` writes it as hex TEXT and every consumer keys with the key file's
  /// 64 ASCII characters after trimming a trailing CR/LF and nothing else.
  /// Hex-decoding it, or re-encoding base64 of the 32 DECODED bytes, keys one
  /// end with 32 bytes against the other's 64 -- and that failure is WORSE than
  /// a refusal: the datagram passes the gateway's size pre-filter, a session is
  /// BUILT, and then the gateway goes completely silent. A host watching for
  /// "did the gateway see me" sees yes. Nothing distinguishes it from the
  /// censor. So this value crosses this class untouched.
  final String admissionKey;

  /// The signing slot that produced the accepted signature.
  final String kid;

  /// Unix seconds after which this descriptor must not be used. It bounds how
  /// stale a CACHED config may be, and the client does fast-connect from cache.
  final int notAfter;

  /// The gateway id decoded to operator text, or null when it is not text.
  ///
  /// FOR VALIDATION ONLY. See [gatewayIdBase64]: the value that ships is the
  /// base64, and the single decode belongs to the host.
  String? get gatewayIdOperatorText {
    List<int> raw;
    try {
      raw = base64.decode(gatewayIdBase64);
    } catch (_) {
      return null;
    }
    if (raw.isEmpty) return null;
    try {
      final text = utf8.decode(raw);
      return text.isEmpty ? null : text;
    } catch (_) {
      return null;
    }
  }
}

/// The outcome of verifying the descriptor on one served config.
///
/// [descriptor] is non-null only when [verified] is true. [reason] is a stable
/// identifier for a diagnostic and never carries a field VALUE: `endpoint` is a
/// node address and the admission secret is the secret this whole design
/// exists to protect.
class Winn3DescriptorCheck {
  const Winn3DescriptorCheck._({
    required this.verified,
    required this.reason,
    required this.descriptor,
  });

  const Winn3DescriptorCheck.absent(this.reason)
      : verified = false,
        descriptor = null;

  factory Winn3DescriptorCheck.ok(Winn3Descriptor descriptor) =>
      Winn3DescriptorCheck._(
        verified: true,
        reason: 'winn3-descriptor-verified',
        descriptor: descriptor,
      );

  final bool verified;
  final String reason;
  final Winn3Descriptor? descriptor;
}

/// Hub/client node-slug alphabet: 2-40 ASCII letters, digits, or hyphens,
/// starting with an alphanumeric. Same pattern as `WINN3_STANDALONE_NODE_SLUG`
/// and the signed descriptor `node` field.
final RegExp kWinn3NodeIdentityPattern = RegExp(r'^[a-z0-9][a-z0-9-]{1,39}$');

/// Exact control-plane generation alphabet shared by the Dart and native
/// ordinary-v3-failure gates.
final RegExp kWinn3SelectionGenerationPattern =
    RegExp(r'^[A-Za-z0-9][A-Za-z0-9._:-]{7,63}$');

/// One minute, measured by a monotonic clock. A reviewed v1 compatibility
/// engine must start promptly after the exact v3 failure that authorized it.
const int kWinn1FallbackDispatchGrantTtlMs = 60000;

/// Served-config keys that name the route-selected node.
///
/// Underscored names, no-underscore compat twins, and the native INI/start
/// option spelling `selected_node`. A first-wins read of these keys is a
/// substitution hole: a matching decoy `node_slug` must not hide a different
/// `location_slug` or `selected_node`. All present identities must agree.
const List<String> kWinn3SelectedNodeIdentityKeys = <String>[
  'node_slug',
  'nodeslug',
  'location_slug',
  'locationslug',
  'selected_node',
  'selectednode',
];

const List<String> _kWinn3NestedSelectedNodeSlugKeys = <String>[
  'slug',
  'node_slug',
  'nodeslug',
  'location_slug',
  'locationslug',
];

/// ASCII-only lowercase, matching native `LowerAscii` on Windows and Linux.
///
/// Dart's `toLowerCase()` is Unicode-aware and would fold U+212A KELVIN SIGN
/// onto `k`, so a selected node of `K1` could match a signed `k1`. Native
/// Apple/Android hosts still use Unicode `lowercased()`; Dart must not emit
/// that fold into `[winn]`.
String winn3AsciiLowercase(String value) {
  final units = value.codeUnits;
  final out = StringBuffer();
  for (final unit in units) {
    if (unit >= 0x41 && unit <= 0x5A) {
      out.writeCharCode(unit + 0x20);
    } else {
      out.writeCharCode(unit);
    }
  }
  return out.toString();
}

/// Trim, reject non-ASCII, ASCII-lowercase, then the slug alphabet.
///
/// Returns null when [raw] is not a node identity. A Map/List/number is never
/// `.toString()`-coerced into a slug.
String? winn3NormalizedNodeIdentity(Object? raw) {
  if (raw is! String) return null;
  // Scan the untrimmed value. Dart's trim() strips NBSP/other Unicode
  // spaces that native ASCII Trim leaves in place; those must not fold
  // onto an ASCII slug.
  for (final unit in raw.codeUnits) {
    if (unit > 0x7F) return null;
  }
  final trimmed = raw.trim();
  if (trimmed.isEmpty) return null;
  final lowered = winn3AsciiLowercase(trimmed);
  if (!kWinn3NodeIdentityPattern.hasMatch(lowered)) return null;
  return lowered;
}

class _Winn3NodeIdentityRead {
  const _Winn3NodeIdentityRead._(this.present, this.value);
  const _Winn3NodeIdentityRead.absent() : this._(false, null);
  const _Winn3NodeIdentityRead.invalid() : this._(true, null);
  const _Winn3NodeIdentityRead.ok(String value) : this._(true, value);

  final bool present;
  final String? value;
}

_Winn3NodeIdentityRead _readWinn3NodeIdentityValue(Object? raw) {
  if (raw == null) return const _Winn3NodeIdentityRead.absent();
  if (raw is String) {
    if (raw.trim().isEmpty) return const _Winn3NodeIdentityRead.absent();
    final normalized = winn3NormalizedNodeIdentity(raw);
    if (normalized == null) return const _Winn3NodeIdentityRead.invalid();
    return _Winn3NodeIdentityRead.ok(normalized);
  }
  if (raw is Map) {
    String? bound;
    var sawSlug = false;
    for (final key in _kWinn3NestedSelectedNodeSlugKeys) {
      if (!raw.containsKey(key)) continue;
      final nested = raw[key];
      if (nested == null) continue;
      sawSlug = true;
      if (nested is! String || nested.trim().isEmpty) {
        return const _Winn3NodeIdentityRead.invalid();
      }
      final normalized = winn3NormalizedNodeIdentity(nested);
      if (normalized == null) return const _Winn3NodeIdentityRead.invalid();
      if (bound == null) {
        bound = normalized;
      } else if (bound != normalized) {
        return const _Winn3NodeIdentityRead.invalid();
      }
    }
    if (!sawSlug || bound == null) {
      return const _Winn3NodeIdentityRead.invalid();
    }
    return _Winn3NodeIdentityRead.ok(bound);
  }
  return const _Winn3NodeIdentityRead.invalid();
}

/// Route-selected node identity from a served config.
///
/// Empty means missing, malformed, Unicode, or conflicting aliases. The
/// standalone start must treat empty the same as a cross-node mismatch:
/// refuse [WinnRefusalReason.winn3DescriptorNodeMismatch] before reading
/// `inner_v4`, `static_private`, or any descriptor credential.
String winn3SelectedNodeIdentity(Map<String, dynamic> config) {
  String? bound;
  var sawPresent = false;
  for (final key in kWinn3SelectedNodeIdentityKeys) {
    final read = _readWinn3NodeIdentityValue(config[key]);
    if (!read.present) continue;
    sawPresent = true;
    final value = read.value;
    if (value == null) return '';
    if (bound == null) {
      bound = value;
    } else if (bound != value) {
      return '';
    }
  }
  if (!sawPresent) return '';
  return bound ?? '';
}

/// Whether a verified [descriptor] names the route-selected node of [served].
///
/// The ONE node-binding rule, shared by the standalone start and by the hub
/// reply validator (hub_verify_candidate.dart), so the two can never disagree.
/// Missing, malformed or conflicting served aliases read as empty and never
/// bind.
bool winn3DescriptorBindsSelectedNode({
  required Map<String, dynamic> served,
  required Winn3Descriptor descriptor,
}) {
  final selectedNode = winn3SelectedNodeIdentity(served);
  // Written in the ruled form (docs/rulings/RULINGS.lock pins this literal).
  if (selectedNode.isEmpty || selectedNode != descriptor.node) {
    return false;
  }
  return true;
}

/// Served key carrying the Core relay route of a ciphertext relay Double VPN
/// (w3r/1). Present ONLY when the hub serves the relay; absent (not null, not
/// empty) for every other config. [kWinn3RelayKeyCompat] is the no-underscore
/// compat twin the hub also emits.
///
/// The relay is a PATH, not an identity: the session is end to end encrypted to
/// the exit's own signed key, so the endpoint is deliberately not signed. Only
/// the dialled address changes; the descriptor, the admission and the node
/// binding are the exit's own.
const String kWinn3RelayKey = 'winn3_relay';
const String kWinn3RelayKeyCompat = 'winn3relay';

/// Every spelling of the Double route keys the relay binding reads. With a
/// relay present they are preserved as served (see [applyWinn3ServedFields]).
const List<String> kWinn3RelayRouteKeys = <String>[
  'double_vpn_active',
  'doublevpnactive',
  'double_vpn',
  'doublevpn',
  'double_vpn_core_id',
  'doublevpncoreid',
  'double_vpn_exit_slug',
  'doublevpnexitslug',
];

/// The only relay version this build understands.
const int kWinn3RelayVersion = 1;

/// Lowest relay port this build accepts. The hub's range sits well above it.
const int kWinn3RelayMinPort = 1024;

/// A parsed, strict `winn3_relay`: the Core address the phone dials instead of
/// the exit's own descriptor endpoint.
class Winn3Relay {
  const Winn3Relay({required this.host, required this.port});

  /// Dotted IPv4 literal of the Core, global unicast.
  final String host;

  /// UDP port of the Core relay for the selected exit.
  final int port;

  /// `host:port`, the exact value emitted as `[winn] endpoint`.
  String get endpoint => '$host:$port';
}

enum Winn3RelayReadKind { absent, valid, invalid }

/// The outcome of reading `winn3_relay` off a served config. Three states and
/// no fourth: a malformed relay is [Winn3RelayReadKind.invalid], never
/// "absent", so garbage cannot turn a Double config into a direct dial.
class Winn3RelayRead {
  const Winn3RelayRead._(this.kind, this.relay);
  const Winn3RelayRead.absent() : this._(Winn3RelayReadKind.absent, null);
  const Winn3RelayRead.invalid() : this._(Winn3RelayReadKind.invalid, null);
  const Winn3RelayRead.valid(Winn3Relay relay)
      : this._(Winn3RelayReadKind.valid, relay);

  final Winn3RelayReadKind kind;

  /// Non-null exactly when [kind] is [Winn3RelayReadKind.valid].
  final Winn3Relay? relay;
}

/// Whether the four octets of a dotted IPv4 literal are a global unicast
/// address a Core can sit behind: not "this network" (0/8), private (10/8,
/// 172.16/12, 192.168/16), carrier grade NAT (100.64/10), loopback (127/8),
/// link local (169.254/16), multicast (224/4) or reserved (240/4).
bool _isGlobalUnicastIpv4Octets(List<int> octets) {
  final a = octets[0];
  final b = octets[1];
  if (a == 0 || a == 10 || a == 127) return false;
  if (a == 100 && b >= 64 && b <= 127) return false;
  if (a == 169 && b == 254) return false;
  if (a == 172 && b >= 16 && b <= 31) return false;
  if (a == 192 && b == 168) return false;
  if (a >= 224) return false;
  return true;
}

/// Strict parser for one `winn3_relay` value, or null when it is anything but
/// the exact w3r/1 shape: a map with EXACTLY the keys `v` and `endpoint`; `v`
/// the integer 1; `endpoint` a string `a.b.c.d:port` with a dotted IPv4 literal
/// that is global unicast and a canonical decimal port in
/// [kWinn3RelayMinPort]..65535. Nothing is trimmed, folded or
/// `.toString()`-coerced: a padded, hostname, IPv6, signed or non-string value
/// is refused.
Winn3Relay? parseWinn3Relay(Object? raw) {
  if (raw is! Map || raw.length != 2) return null;
  for (final key in raw.keys) {
    if (key is! String || (key != 'v' && key != 'endpoint')) return null;
  }
  final version = raw['v'];
  if (version is! int || version != kWinn3RelayVersion) return null;
  final endpoint = raw['endpoint'];
  if (endpoint is! String || endpoint.length < 9 || endpoint.length > 21) {
    return null;
  }
  final colon = endpoint.indexOf(':');
  // Exactly one colon: a bracketed or bare IPv6 literal has more.
  if (colon <= 0 || colon != endpoint.lastIndexOf(':')) return null;
  final host = endpoint.substring(0, colon);
  final portText = endpoint.substring(colon + 1);
  if (!_isIpv4Literal(host)) return null;
  final octets = host.split('.').map(int.parse).toList(growable: false);
  if (!_isGlobalUnicastIpv4Octets(octets)) return null;
  if (portText.isEmpty || portText.length > 5) return null;
  for (var i = 0; i < portText.length; i++) {
    final c = portText.codeUnitAt(i);
    if (c < 0x30 || c > 0x39) return null;
  }
  // Canonical decimal only: "09211" and "9211" must not be two spellings.
  if (portText.length > 1 && portText.startsWith('0')) return null;
  final port = int.parse(portText);
  if (port < kWinn3RelayMinPort || port > 65535) return null;
  final relay = Winn3Relay(host: host, port: port);
  if (!_isSafeIniValue(relay.endpoint)) return null;
  return relay;
}

/// Reads the relay off a served config. Both spellings are read; a present
/// value must parse, and when both are present they must agree. A `null` value
/// is malformed because the hub omits the key when no relay is served.
Winn3RelayRead readWinn3ServedRelay(Map<String, dynamic> config) {
  Winn3Relay? primary;
  Winn3Relay? compat;
  var sawPrimary = false;
  var sawCompat = false;
  if (config.containsKey(kWinn3RelayKey)) {
    sawPrimary = true;
    primary = parseWinn3Relay(config[kWinn3RelayKey]);
    if (primary == null) return const Winn3RelayRead.invalid();
  }
  if (config.containsKey(kWinn3RelayKeyCompat)) {
    sawCompat = true;
    compat = parseWinn3Relay(config[kWinn3RelayKeyCompat]);
    if (compat == null) return const Winn3RelayRead.invalid();
  }
  if (!sawPrimary && !sawCompat) return const Winn3RelayRead.absent();
  if (primary != null &&
      compat != null &&
      (primary.host != compat.host || primary.port != compat.port)) {
    return const Winn3RelayRead.invalid();
  }
  return Winn3RelayRead.valid((primary ?? compat)!);
}

/// True when the config carries a `winn3_relay` under either spelling, valid
/// or not. Used by cache rules, which must treat even a malformed relay as
/// "this config may not skip the hub".
bool winn3ConfigCarriesRelay(Map<String, dynamic> config) {
  return config.containsKey(kWinn3RelayKey) ||
      config.containsKey(kWinn3RelayKeyCompat);
}

/// The Double flag of a served config: true, false (absent counts as false),
/// or null when the two spellings disagree.
bool? _servedDoubleVpnFlag(Map<String, dynamic> config) {
  bool? agreed;
  for (final key in const <String>[
    'double_vpn_active', 'doublevpnactive', 'double_vpn', 'doublevpn'
  ]) {
    final value = config[key];
    if (value == null) continue;
    if (value is! bool) return null;
    final flag = value;
    if (agreed == null) {
      agreed = flag;
    } else if (agreed != flag) {
      return null;
    }
  }
  return agreed ?? false;
}

/// The single trimmed value the present spellings of a key agree on: '' when
/// none is present, null when two present spellings differ.
String? _agreedConfigString(Map<String, dynamic> config, List<String> keys) {
  String? agreed;
  for (final key in keys) {
    if (!config.containsKey(key) || config[key] == null) continue;
    final raw = config[key];
    if (raw is! String) return null;
    final value = raw.trim();
    if (value.isEmpty) return null;
    if (agreed == null) {
      agreed = value;
    } else if (agreed != value) {
      return null;
    }
  }
  return agreed ?? '';
}

/// The host part of an IP literal endpoint (`a.b.c.d:port` or `[v6]:port`).
String _winn3EndpointHost(String endpoint) {
  if (endpoint.startsWith('[')) {
    final end = endpoint.indexOf(']');
    return end < 0 ? endpoint : endpoint.substring(1, end);
  }
  final colon = endpoint.lastIndexOf(':');
  return colon < 0 ? endpoint : endpoint.substring(0, colon);
}

/// The outcome of the relay binding of a served standalone config.
class Winn3RelayBinding {
  const Winn3RelayBinding._(this.relay, this.refusal);

  /// No relay and no Double label: an ordinary single-hop session.
  const Winn3RelayBinding.singleHop() : this._(null, WinnRefusalReason.none);

  /// A valid relay bound to this config: dial [relay], verify the exit.
  const Winn3RelayBinding.relay(Winn3Relay relay)
      : this._(relay, WinnRefusalReason.none);

  /// The config may not start; [reason] names why.
  const Winn3RelayBinding.refused(WinnRefusalReason reason)
      : this._(null, reason);

  final Winn3Relay? relay;
  final WinnRefusalReason refusal;

  bool get accepted => refusal == WinnRefusalReason.none;
}

/// The relay binding shared by the standalone start and the hub reply
/// validator (hub_verify_candidate.dart). It never replaces
/// [winn3DescriptorBindsSelectedNode] (a ruled invariant, the descriptor is
/// still the SELECTED exit's own); it runs after it.
///
///  * relay absent and no Double label: an ordinary single hop, unchanged;
///  * relay absent but the config is labelled Double (or the spellings
///    disagree): REFUSED [WinnRefusalReason.winn3DoubleLabelWithoutRelay]. A
///    two-hop label must never ride a single-hop descriptor;
///  * relay malformed or ambiguous: REFUSED [WinnRefusalReason.winn3RelayMalformed];
///  * relay present: the config must be labelled Double, name a Core, name the
///    exit the signed descriptor and every selected-node alias name, and the
///    relay address must not be the exit's own (a relay that names the exit is
///    a Double label on a direct dial). Otherwise REFUSED
///    [WinnRefusalReason.winn3RelayMalformed].
Winn3RelayBinding winn3RelayBindingForServedConfig({
  required Map<String, dynamic> served,
  required Winn3Descriptor descriptor,
}) {
  final read = readWinn3ServedRelay(served);
  final doubleFlag = _servedDoubleVpnFlag(served);
  switch (read.kind) {
    case Winn3RelayReadKind.absent:
      if (doubleFlag == false) return const Winn3RelayBinding.singleHop();
      return const Winn3RelayBinding.refused(
          WinnRefusalReason.winn3DoubleLabelWithoutRelay);
    case Winn3RelayReadKind.invalid:
      return const Winn3RelayBinding.refused(
          WinnRefusalReason.winn3RelayMalformed);
    case Winn3RelayReadKind.valid:
      final relay = read.relay!;
      if (doubleFlag != true) {
        return const Winn3RelayBinding.refused(
            WinnRefusalReason.winn3RelayMalformed);
      }
      final coreId = _agreedConfigString(
          served, const <String>['double_vpn_core_id', 'doublevpncoreid']);
      if (coreId == null || coreId.isEmpty) {
        return const Winn3RelayBinding.refused(
            WinnRefusalReason.winn3RelayMalformed);
      }
      final exitSlug = _agreedConfigString(
          served, const <String>['double_vpn_exit_slug', 'doublevpnexitslug']);
      final exitIdentity =
          exitSlug == null ? null : winn3NormalizedNodeIdentity(exitSlug);
      final selected = winn3SelectedNodeIdentity(served);
      if (exitIdentity == null ||
          selected.isEmpty ||
          exitIdentity != descriptor.node ||
          selected != descriptor.node) {
        return const Winn3RelayBinding.refused(
            WinnRefusalReason.winn3RelayMalformed);
      }
      if (relay.host == _winn3EndpointHost(descriptor.endpoint)) {
        return const Winn3RelayBinding.refused(
            WinnRefusalReason.winn3RelayMalformed);
      }
      return Winn3RelayBinding.relay(relay);
  }
}

enum _Winn1FallbackDispatchLeg { awg, xray }

class _Winn1FallbackDispatchGrant {
  const _Winn1FallbackDispatchGrant({
    required this.startToken,
    required this.startGeneration,
    required this.selectionGeneration,
    required this.failedV3Node,
    required this.issuedMonotonicMs,
    required this.nextLeg,
    required this.exactV1Target,
    required this.primaryHub,
  });

  final int startToken;
  final int startGeneration;
  final String selectionGeneration;
  final String failedV3Node;
  final int issuedMonotonicMs;
  final _Winn1FallbackDispatchLeg nextLeg;
  final String exactV1Target;
  final bool primaryHub;

  String get identity =>
      '$startToken:$startGeneration:$selectionGeneration:$failedV3Node';

  _Winn1FallbackDispatchGrant copyWith({
    required _Winn1FallbackDispatchLeg nextLeg,
    required String exactV1Target,
  }) {
    return _Winn1FallbackDispatchGrant(
      startToken: startToken,
      startGeneration: startGeneration,
      selectionGeneration: selectionGeneration,
      failedV3Node: failedV3Node,
      issuedMonotonicMs: issuedMonotonicMs,
      nextLeg: nextLeg,
      exactV1Target: exactV1Target,
      primaryHub: primaryHub,
    );
  }
}

final Stopwatch _winn1FallbackDispatchClock = Stopwatch()..start();
String _winn1FallbackSelectionGeneration = '';
bool _winn1FallbackOrdinaryFailureAuthorized = false;
bool _winn1PrimaryHubDispatchIssued = false;
String _burnedWinn1FallbackDispatchIdentity = '';
_Winn1FallbackDispatchGrant? _winn1FallbackDispatchGrant;

/// Synchronizes the config-builder gate with one control-plane selection.
///
/// A matching ordinary-failure request field is necessary but not sufficient:
/// [armWinn1FallbackDispatchAuthorization] must also have observed the exact
/// typed native verdict. Withholding ordinary-failure authorization revokes
/// fallback grants, but preserves a fresh primary-hub grant in the same
/// generation, including its consumed-leg state. A new or malformed
/// generation destroys every earlier grant.
void synchronizeWinn1FallbackDispatchGeneration({
  required String selectionGeneration,
  required bool ordinaryConnectivityAuthorized,
}) {
  if (!kWinn3SelectionGenerationPattern.hasMatch(selectionGeneration)) {
    resetWinn1FallbackDispatchAuthorization();
    return;
  }
  _expireWinn1FallbackDispatchGrantIfNeeded();
  if (_winn1FallbackSelectionGeneration != selectionGeneration) {
    _winn1FallbackDispatchGrant = null;
    _burnedWinn1FallbackDispatchIdentity = '';
    _winn1PrimaryHubDispatchIssued = false;
  }
  _winn1FallbackSelectionGeneration = selectionGeneration;
  final primaryHubAuthorized = _winn1FallbackDispatchGrant?.primaryHub ==
          true &&
      _winn1FallbackDispatchGrant?.selectionGeneration == selectionGeneration;
  _winn1FallbackOrdinaryFailureAuthorized =
      ordinaryConnectivityAuthorized || primaryHubAuthorized;
  if (!ordinaryConnectivityAuthorized && !primaryHubAuthorized) {
    final current = _winn1FallbackDispatchGrant;
    if (current != null) {
      _burnedWinn1FallbackDispatchIdentity = current.identity;
    }
    _winn1FallbackDispatchGrant = null;
  } else if (_winn1FallbackDispatchGrant?.selectionGeneration !=
      selectionGeneration) {
    _winn1FallbackDispatchGrant = null;
  }
}

/// Arms the Dart config-builder only from an exact native ordinary-v3-failure
/// verdict. Re-observing the same sticky readiness result is idempotent: it
/// cannot refresh the TTL or rewind an AWG-consumed grant back to AWG.
bool armWinn1FallbackDispatchAuthorization({
  required int startToken,
  required int startGeneration,
  required String selectionGeneration,
  required String failedV3Node,
}) {
  final failed = winn3NormalizedNodeIdentity(failedV3Node);
  if (startToken <= 0 ||
      startToken > 0x7fffffffffffffff ||
      startGeneration <= 0 ||
      !kWinn3SelectionGenerationPattern.hasMatch(selectionGeneration) ||
      selectionGeneration != _winn1FallbackSelectionGeneration ||
      failed == null ||
      failed == 'auto') {
    return false;
  }
  final candidate = _Winn1FallbackDispatchGrant(
    startToken: startToken,
    startGeneration: startGeneration,
    selectionGeneration: selectionGeneration,
    failedV3Node: failed,
    issuedMonotonicMs: _winn1FallbackDispatchClock.elapsedMilliseconds,
    nextLeg: _Winn1FallbackDispatchLeg.awg,
    exactV1Target: '',
    primaryHub: false,
  );
  final current = _winn1FallbackDispatchGrant;
  if (current != null && current.identity == candidate.identity) {
    return true;
  }
  if (_burnedWinn1FallbackDispatchIdentity == candidate.identity) {
    return false;
  }
  if (current != null &&
      (startGeneration < current.startGeneration ||
          (startGeneration == current.startGeneration &&
              startToken != current.startToken))) {
    return false;
  }
  _winn1FallbackDispatchGrant = candidate;
  return true;
}

/// Arms a primary v1 compatibility grant when the hub freshly serves a strict
/// winn/1 config as the primary transport for the active selection generation.
///
/// This unblocks non-Winn3 hosts (e.g. iOS) without requiring an impossible
/// preceding native Winn3 failure verdict, while preserving the exact-target,
/// generation-bound, single-use lifecycle of the v1 dispatch grant.
/// Re-observation cannot rewind AWG, extend the TTL, change targets, or revive
/// a grant already consumed, expired, or explicitly cleared in this generation.
bool armWinn1PrimaryHubDispatchAuthorization({
  required Map<String, dynamic> config,
  required String selectionGeneration,
}) {
  _expireWinn1FallbackDispatchGrantIfNeeded();
  if (strictWinnProtocolVersionForTunnelConfig(config) != kWinnProtocolV1) {
    return false;
  }
  final target = _winn1FallbackTarget(config);
  if (target.isEmpty ||
      !kWinn3SelectionGenerationPattern.hasMatch(selectionGeneration) ||
      selectionGeneration != _winn1FallbackSelectionGeneration) {
    return false;
  }
  final current = _winn1FallbackDispatchGrant;
  if (current != null) {
    return current.primaryHub &&
        current.selectionGeneration == selectionGeneration &&
        current.exactV1Target == target;
  }
  if (_winn1PrimaryHubDispatchIssued) return false;
  _winn1PrimaryHubDispatchIssued = true;
  _winn1FallbackOrdinaryFailureAuthorized = true;
  _winn1FallbackDispatchGrant = _Winn1FallbackDispatchGrant(
    startToken: 1,
    startGeneration: 1,
    selectionGeneration: selectionGeneration,
    failedV3Node: '',
    issuedMonotonicMs: _winn1FallbackDispatchClock.elapsedMilliseconds,
    nextLeg: _Winn1FallbackDispatchLeg.awg,
    exactV1Target: target,
    primaryHub: true,
  );
  return true;
}

/// Invalidates the current Dart-side v1 compatibility authorization.
///
/// When [selectionGeneration] is supplied, a stale prior-generation readiness
/// sample cannot erase a newer selection's state. Omitting it is the explicit
/// full reset used when a generation is malformed or a test/app lifecycle ends.
void clearWinn1FallbackDispatchAuthorization({
  String? selectionGeneration,
}) {
  if (selectionGeneration != null &&
      selectionGeneration != _winn1FallbackSelectionGeneration) {
    return;
  }
  final current = _winn1FallbackDispatchGrant;
  if (current != null) {
    _burnedWinn1FallbackDispatchIdentity = current.identity;
  }
  _winn1FallbackDispatchGrant = null;
  _winn1FallbackOrdinaryFailureAuthorized = false;
}

/// Clears every process-local v1 authorization fact.
void resetWinn1FallbackDispatchAuthorization() {
  _winn1FallbackSelectionGeneration = '';
  _winn1FallbackOrdinaryFailureAuthorized = false;
  _winn1PrimaryHubDispatchIssued = false;
  _burnedWinn1FallbackDispatchIdentity = '';
  _winn1FallbackDispatchGrant = null;
}

void _expireWinn1FallbackDispatchGrantIfNeeded() {
  final grant = _winn1FallbackDispatchGrant;
  if (grant == null) return;
  final age =
      _winn1FallbackDispatchClock.elapsedMilliseconds - grant.issuedMonotonicMs;
  if (age < 0 || age > kWinn1FallbackDispatchGrantTtlMs) {
    _burnedWinn1FallbackDispatchIdentity = grant.identity;
    _winn1FallbackDispatchGrant = null;
    _winn1FallbackOrdinaryFailureAuthorized = false;
  }
}

String _winn1FallbackTarget(Map<String, dynamic> config) {
  final target = winn3SelectedNodeIdentity(config);
  if (target.isEmpty || target == 'auto') return '';
  return target;
}

/// True only when this exact config may begin the reviewed v1 compatibility
/// pair. The pair is fixed to the bundled AWG engine first and the bundled
/// Xray engine second; this gate performs no package, version, or network
/// lookup at runtime.
bool winn1FallbackDispatchMayLead(Map<String, dynamic> config) {
  _expireWinn1FallbackDispatchGrantIfNeeded();
  final grant = _winn1FallbackDispatchGrant;
  if (!_winn1FallbackOrdinaryFailureAuthorized ||
      grant == null ||
      grant.selectionGeneration != _winn1FallbackSelectionGeneration ||
      grant.nextLeg != _Winn1FallbackDispatchLeg.awg) {
    return false;
  }
  if (_isTrue(config['stealth_active'])) return false;
  final target = _winn1FallbackTarget(config);
  if (target.isEmpty || target == grant.failedV3Node) return false;
  if (grant.exactV1Target.isNotEmpty) {
    return target == grant.exactV1Target;
  }
  _winn1FallbackDispatchGrant = grant.copyWith(
    nextLeg: grant.nextLeg,
    exactV1Target: target,
  );
  return true;
}

/// True only when this exact config is the currently authorized AWG or Xray
/// leg. Unlike [winn1FallbackDispatchMayLead], this permits the Xray second
/// leg after AWG was consumed, but it cannot reorder or retry either leg.
bool winn1FallbackDispatchMayContinue(Map<String, dynamic> config) {
  _expireWinn1FallbackDispatchGrantIfNeeded();
  final grant = _winn1FallbackDispatchGrant;
  if (!_winn1FallbackOrdinaryFailureAuthorized ||
      grant == null ||
      grant.selectionGeneration != _winn1FallbackSelectionGeneration) {
    return false;
  }
  final target = _winn1FallbackTarget(config);
  if (target.isEmpty ||
      target == grant.failedV3Node ||
      grant.exactV1Target.isEmpty ||
      target != grant.exactV1Target) {
    return false;
  }
  final requestedLeg = _isTrue(config['stealth_active'])
      ? _Winn1FallbackDispatchLeg.xray
      : _Winn1FallbackDispatchLeg.awg;
  return requestedLeg == grant.nextLeg;
}

/// Authorizes only the exact leg currently at the head of the fixed pair.
/// The first AWG observation binds the target; after AWG consumption only the
/// matching Xray config can continue.
bool winn1FallbackDispatchMayAuthorizeConfig(Map<String, dynamic> config) {
  _expireWinn1FallbackDispatchGrantIfNeeded();
  final grant = _winn1FallbackDispatchGrant;
  if (grant == null) return false;
  return grant.nextLeg == _Winn1FallbackDispatchLeg.awg
      ? winn1FallbackDispatchMayLead(config)
      : winn1FallbackDispatchMayContinue(config);
}

bool _consumeWinn1FallbackDispatchAuthorization(
  Map<String, dynamic> config,
) {
  _expireWinn1FallbackDispatchGrantIfNeeded();
  final grant = _winn1FallbackDispatchGrant;
  if (!_winn1FallbackOrdinaryFailureAuthorized ||
      grant == null ||
      grant.selectionGeneration != _winn1FallbackSelectionGeneration) {
    return false;
  }
  final target = _winn1FallbackTarget(config);
  if (target.isEmpty || target == grant.failedV3Node) return false;
  if (grant.exactV1Target.isNotEmpty && target != grant.exactV1Target) {
    return false;
  }
  final requestedLeg = _isTrue(config['stealth_active'])
      ? _Winn1FallbackDispatchLeg.xray
      : _Winn1FallbackDispatchLeg.awg;
  if (requestedLeg != grant.nextLeg) return false;
  if (requestedLeg == _Winn1FallbackDispatchLeg.awg) {
    _winn1FallbackDispatchGrant = grant.copyWith(
      nextLeg: _Winn1FallbackDispatchLeg.xray,
      exactV1Target: target,
    );
    return true;
  }
  _burnedWinn1FallbackDispatchIdentity = grant.identity;
  _winn1FallbackDispatchGrant = null;
  _winn1FallbackOrdinaryFailureAuthorized = false;
  return true;
}

/// True when the verified descriptor `node` equals every present selected-node
/// identity on [config].
bool winn3DescriptorMatchesSelectedNode({
  required Winn3Descriptor descriptor,
  required Map<String, dynamic> config,
}) {
  final selected = winn3SelectedNodeIdentity(config);
  return selected.isNotEmpty && selected == descriptor.node;
}

/// Flutter `startTunnel` caller identity for every native host.
///
/// Native hosts bind the signed descriptor `node` to this independently
/// selected slug. Omitting the method keys makes that comparison an INI
/// self-claim: a substituted document can make `node` and `selected_node`
/// agree. Winn v3 therefore refuses a missing or conflicting identity
/// instead of deriving one from the served document. The exact caller slug
/// is retained; ASCII folding is a native comparison, not a rewrite here.
class Winn3StartTunnelCallerIdentity {
  const Winn3StartTunnelCallerIdentity({
    required this.exactSlug,
    required this.startArguments,
  });

  static const String startArgumentKey = 'selected_node';

  static const Winn3StartTunnelCallerIdentity missing =
      Winn3StartTunnelCallerIdentity(
    exactSlug: '',
    startArguments: <String, dynamic>{},
  );

  /// The independently selected slug, not an INI-derived or ASCII-folded copy.
  final String exactSlug;

  /// Method-channel keys to merge into `startTunnel` arguments.
  final Map<String, dynamic> startArguments;

  bool get isPresent =>
      exactSlug.isNotEmpty && startArguments[startArgumentKey] == exactSlug;
}

/// Resolve the Flutter caller identity that every native `startTunnel`
/// must send.
///
/// [independentlySelectedSlug] is the node Flutter already selected (picker,
/// watch, or hub-assigned display). It is not read from served INI. `auto`,
/// blank, non-ASCII, malformed, and conflicting served aliases are missing:
/// Winn v3 must refuse that result rather than omit the method keys.
Winn3StartTunnelCallerIdentity resolveWinn3StartTunnelCallerIdentity({
  required String independentlySelectedSlug,
  Map<String, dynamic> servedConfig = const <String, dynamic>{},
}) {
  final independent = winn3NormalizedNodeIdentity(independentlySelectedSlug);
  if (independent == null || independent == 'auto') {
    return Winn3StartTunnelCallerIdentity.missing;
  }

  String? servedBound;
  var sawServed = false;
  for (final key in kWinn3SelectedNodeIdentityKeys) {
    final read = _readWinn3NodeIdentityValue(servedConfig[key]);
    if (!read.present) continue;
    sawServed = true;
    final value = read.value;
    if (value == null) {
      return Winn3StartTunnelCallerIdentity.missing;
    }
    if (servedBound == null) {
      servedBound = value;
    } else if (servedBound != value) {
      return Winn3StartTunnelCallerIdentity.missing;
    }
  }
  if (sawServed && servedBound != independent) {
    return Winn3StartTunnelCallerIdentity.missing;
  }

  return Winn3StartTunnelCallerIdentity(
    exactSlug: independentlySelectedSlug,
    startArguments: <String, dynamic>{
      Winn3StartTunnelCallerIdentity.startArgumentKey:
          independentlySelectedSlug,
    },
  );
}

/// Copy every present selected-node alias from [raw] onto [dest].
///
/// `_normalizeVpnConfig` rebuilds a closed key list and historically kept
/// only a first-wins `node_slug`. That collapse hid a conflicting
/// `location_slug` or `selected_node` and left startTunnel with an INI
/// self-claim. Maps stay maps; values are never `.toString()`-coerced.
Map<String, dynamic> copyWinn3SelectedNodeIdentities({
  required Map<String, dynamic> dest,
  required Map<String, dynamic> raw,
}) {
  for (final key in kWinn3SelectedNodeIdentityKeys) {
    if (!raw.containsKey(key)) continue;
    final value = raw[key];
    if (value == null) continue;
    if (value is Map) {
      try {
        dest[key] = Map<String, dynamic>.from(value);
      } catch (_) {
        dest[key] = value;
      }
    } else {
      dest[key] = value;
    }
  }
  return dest;
}

/// Copy the hub A3 winn/3 field set from [raw] onto [dest].
///
/// `lib/main.dart` `_normalizeVpnConfig` rebuilds a closed key list and
/// historically omitted every `winn3_*` key, so [verifyWinn3Descriptor] saw
/// no envelope and Connect refused [WinnRefusalReason.winn3DescriptorUnverified].
/// Call this on that rebuilt map with the served body as [raw]:
///
/// ```
/// return applyWinn3ServedFields(dest: <String, dynamic>{...}, raw: raw);
/// ```
///
/// The descriptor stays a Map (`payload` + `sig` strings). It is never
/// JSON-encoded or `.toString()`'d. Empty `{}` is copied as empty and still
/// fails closed as `no-descriptor-served`. String fields keep the hub's
/// underscored names plus the no-underscore twins
/// (`hub_main_patched.py` vpn_config / vpn_config_compat overlay).
///
/// Does not copy `protocol_version` or `protocol_params`; those already
/// survive normalization. Does not invent fields the hub did not serve.
Map<String, dynamic> applyWinn3ServedFields({
  required Map<String, dynamic> dest,
  required Map<String, dynamic> raw,
}) {
  final descriptor = raw['winn3_descriptor'] ?? raw['winn3descriptor'];
  if (descriptor is Map) {
    try {
      dest['winn3_descriptor'] = Map<String, dynamic>.from(descriptor);
    } catch (_) {
      // Non-string keys (Dart-built maps) must not throw out of normalize:
      // a throw here would be a denial of service of Connect. The verifier
      // already fail-closes that shape as `no-descriptor-served`.
    }
  }
  // The relay route (w3r/1). Copied as served under its own spellings and never
  // interpreted here: [readWinn3ServedRelay] refuses anything that is not the
  // exact shape, so a relay dropped by normalization could never turn a Double
  // config into a direct dial (the Double label without a relay is refused).
  // Absent stays absent.
  for (final relayKey in const <String>[kWinn3RelayKey, kWinn3RelayKeyCompat]) {
    if (!raw.containsKey(relayKey)) continue;
    final relayValue = raw[relayKey];
    if (relayValue is Map) {
      try {
        dest[relayKey] = Map<String, dynamic>.from(relayValue);
      } catch (_) {
        dest[relayKey] = relayValue;
      }
    } else {
      dest[relayKey] = relayValue;
    }
  }
  // D1 (round 2). The relay binding runs on this map, so every spelling of the
  // Double route keys the hub served must reach it AS SERVED. Normalization
  // collapses them to one coerced value per field (first spelling wins), which
  // used to let a conflicting or mistyped spelling vanish before the binding
  // could refuse it. With a relay present the raw spellings (and the raw
  // canonical values) are copied back, so [winn3RelayBindingForServedConfig]
  // judges the served document and not its normalized shadow. A null is never
  // copied over a canonical key (it carries no claim).
  if (winn3ConfigCarriesRelay(raw)) {
    for (final key in kWinn3RelayRouteKeys) {
      if (!raw.containsKey(key)) continue;
      final value = raw[key];
      if (value == null) continue;
      dest[key] = value;
    }
  }
  void copyString(String canonical, List<String> aliases) {
    final value = _configString(raw, aliases);
    if (value.isNotEmpty) {
      dest[canonical] = value;
    }
  }

  copyString(
      'winn3_inner_v4', const <String>['winn3_inner_v4', 'winn3innerv4']);
  copyString('winn3_static_private',
      const <String>['winn3_static_private', 'winn3staticprivate']);
  // The hub's echo of THIS device's own v3 public key (IA-CP-05). Kept so the
  // local key is attached only once the hub has adopted it
  // (attachLocalWinn3StaticKey in winn3_device_key.dart).
  copyString('winn3_static_public',
      const <String>['winn3_static_public', 'winn3staticpublic']);
  copyString(
      'winn3_path_mtu', const <String>['winn3_path_mtu', 'winn3pathmtu']);
  copyString('winn3_carrier_classes',
      const <String>['winn3_carrier_classes', 'winn3carrierclasses']);
  copyString('winn3_psk', const <String>['winn3_psk', 'winn3psk']);
  return dest;
}

/// Read, VERIFY and parse `vpn_config["winn3_descriptor"]`.
///
/// Async because Ed25519 verification is, which is why this is a separate step
/// rather than a branch inside [resolveWinnProtocolStartForServedConfig]: that
/// function is synchronous, is called from the tunnel-config builder, and is
/// covered by ~39 tests that would all have to become asynchronous to thread a
/// `Future` through it. Splitting the two keeps the config rules testable as
/// config rules and makes the verification an explicit, awaited precondition
/// that a caller cannot forget silently -- a standalone start with no check
/// passed in refuses by name.
///
/// [now] is injectable for tests only; it defaults to the wall clock.
Future<Winn3DescriptorCheck> verifyWinn3Descriptor({
  required Map<String, dynamic> config,
  Winn3DescriptorKeyRing? ring,
  DateTime? now,
}) async {
  final served = applyWinn3ServedFields(
    dest: Map<String, dynamic>.from(config),
    raw: config,
  );
  final raw = served['winn3_descriptor'] ?? served['winn3descriptor'];
  if (raw is! Map || raw.isEmpty) {
    return const Winn3DescriptorCheck.absent('no-descriptor-served');
  }
  final Map<String, dynamic> envelope;
  try {
    envelope = Map<String, dynamic>.from(raw);
  } catch (_) {
    // Non-string keys (possible if a caller built the map in Dart, not from
    // JSON) must not throw out of this function: a throw is a denial of
    // service of the client that verifies descriptors from the network.
    return const Winn3DescriptorCheck.absent('no-descriptor-served');
  }
  // Same type gate as announcement_signature.dart: a Map/List/number must not
  // be `.toString()`'d into a plausible-looking base64 candidate. The
  // announcement parser already requires String; this one used to coerce.
  final payloadField = envelope['payload'];
  final signatureField = envelope['sig'];
  if (payloadField is! String || signatureField is! String) {
    return const Winn3DescriptorCheck.absent('descriptor-envelope-incomplete');
  }
  final payloadB64 = payloadField.trim();
  final signatureB64 = signatureField.trim();
  if (payloadB64.isEmpty || signatureB64.isEmpty) {
    return const Winn3DescriptorCheck.absent('descriptor-envelope-incomplete');
  }
  // Length BEFORE decode: the byte ceiling below only sees the decoded
  // buffer, so a multi-megabyte base64 string would already have allocated.
  if (payloadB64.length > kWinn3MaxDescriptorPayloadB64Chars) {
    return const Winn3DescriptorCheck.absent('descriptor-payload-too-large');
  }
  if (signatureB64.length > kWinn3MaxDescriptorSignatureB64Chars) {
    return const Winn3DescriptorCheck.absent('descriptor-signature-invalid');
  }

  final keyRing = ring ?? Winn3DescriptorKeyRing.fromCompiledDefines();
  if (!keyRing.enforcing) {
    // No compiled key means this build cannot tell a real descriptor from a
    // forged one. "Standalone unavailable" is the only honest outcome; there is
    // no version of this that accepts it unverified.
    return const Winn3DescriptorCheck.absent(
        'descriptor-no-verification-keys-compiled');
  }
  if (ring == null &&
      !keyRing.attestsExpectedIdentity(_kWinn3DescriptorRingSha256)) {
    return const Winn3DescriptorCheck.absent(
        'descriptor-verification-ring-identity-mismatch');
  }

  List<int> payloadBytes;
  List<int> signatureBytes;
  try {
    payloadBytes = base64.decode(payloadB64);
    signatureBytes = base64.decode(signatureB64);
  } catch (_) {
    return const Winn3DescriptorCheck.absent('descriptor-envelope-not-base64');
  }
  if (payloadBytes.length > kWinn3MaxDescriptorBytes) {
    return const Winn3DescriptorCheck.absent('descriptor-payload-too-large');
  }
  if (signatureBytes.length != kWinn3DescriptorSignatureBytes) {
    return const Winn3DescriptorCheck.absent('descriptor-signature-invalid');
  }
  // Depth BEFORE json.decode: a compact `[` * 4096 sits under the byte
  // ceiling and is otherwise a stack overflow on the unauthenticated parse.
  if (winn3DescriptorJSONNestingDepth(payloadBytes) >
      kWinn3MaxDescriptorJSONDepth) {
    return const Winn3DescriptorCheck.absent('descriptor-json-too-deep');
  }

  Map<String, dynamic> payload;
  try {
    final decoded = json.decode(utf8.decode(payloadBytes));
    if (decoded is! Map) {
      return const Winn3DescriptorCheck.absent('descriptor-not-an-object');
    }
    payload = Map<String, dynamic>.from(decoded);
  } catch (_) {
    return const Winn3DescriptorCheck.absent('descriptor-not-utf8-json');
  }

  // `kid` is read from the payload BEFORE verification only to select the slot,
  // and selecting the wrong slot can only make verification fail. It is inside
  // the signed bytes, so a moved signature does not survive this.
  // A Map/List/number must not be `.toString()`'d into a slot name: the
  // envelope already requires String for payload/sig, and kid is the same
  // class of field.
  final kidRaw = payload['kid'];
  if (kidRaw is! String) {
    return const Winn3DescriptorCheck.absent('descriptor-unknown-key-slot');
  }
  final kid = kidRaw.trim().toLowerCase();
  if (!kWinn3DescriptorSlotIds.contains(kid)) {
    return const Winn3DescriptorCheck.absent('descriptor-unknown-key-slot');
  }
  final message = <int>[
    ...utf8.encode(kWinn3DescriptorDomain),
    0x00,
    ...payloadBytes,
  ];
  final accepted = await keyRing.verify(
    message: message,
    signature: signatureBytes,
    kid: kid,
  );
  if (!accepted) {
    return const Winn3DescriptorCheck.absent('descriptor-signature-invalid');
  }

  // Only now is anything in here trusted.
  final presentFields = payload.keys.toSet();
  if (!presentFields.containsAll(kWinn3DescriptorRequiredFields)) {
    return const Winn3DescriptorCheck.absent('descriptor-missing-fields');
  }
  final allowedFields = <String>{
    ...kWinn3DescriptorRequiredFields,
    ...kWinn3DescriptorOptionalFields,
  };
  if (presentFields.any((field) => !allowedFields.contains(field))) {
    return const Winn3DescriptorCheck.absent('descriptor-unknown-fields');
  }
  final version = payload['v'];
  if (version is! int || version != kWinn3DescriptorFormatVersion) {
    return const Winn3DescriptorCheck.absent(
        'descriptor-unsupported-format-version');
  }
  final notAfter = payload['not_after'];
  final issuedAt = payload['iat'];
  if (notAfter is! int || issuedAt is! int || notAfter <= issuedAt) {
    return const Winn3DescriptorCheck.absent('descriptor-lifetime-malformed');
  }
  final wallClock = now ?? DateTime.now().toUtc();
  final nowSeconds = wallClock.millisecondsSinceEpoch ~/ 1000;
  final ttlSeconds = notAfter - issuedAt;
  if (ttlSeconds < kWinn3MinDescriptorTtlSeconds) {
    return const Winn3DescriptorCheck.absent('descriptor-ttl-too-short');
  }
  if (ttlSeconds > kWinn3MaxDescriptorTtlSeconds) {
    return const Winn3DescriptorCheck.absent('descriptor-ttl-too-long');
  }
  if (nowSeconds < issuedAt) {
    return const Winn3DescriptorCheck.absent('descriptor-not-yet-valid');
  }
  if (nowSeconds >= notAfter) {
    // A cached config can outlive its descriptor: the client fast-connects from
    // cache, and the hub computes an admission-key retirement floor from
    // exactly this bound. Using an expired one risks keying with a retired
    // secret, which is the silent failure again.
    return const Winn3DescriptorCheck.absent('descriptor-expired');
  }

  final algorithm = payload['alg'];
  if (algorithm is! String || algorithm.trim().toLowerCase() != 'ed25519') {
    return const Winn3DescriptorCheck.absent(
        'descriptor-unsupported-algorithm');
  }
  final node = winn3NormalizedNodeIdentity(payload['node']);
  if (node == null) {
    return const Winn3DescriptorCheck.absent('descriptor-missing-node');
  }
  final tagSize = payload['tag_size'];
  if (tagSize is! int ||
      tagSize < kWinn3MinDescriptorTagSize ||
      tagSize > kWinn3MaxDescriptorTagSize) {
    return const Winn3DescriptorCheck.absent(
        'descriptor-tag-size-out-of-range');
  }
  if (tagSize != kWinn3SupportedTagSize ||
      payload['padding'] != kWinn3SupportedPadding ||
      payload['bucket_window_s'] != kWinn3SupportedBucketWindowSeconds ||
      payload['max_skew_s'] != kWinn3SupportedMaxSkewSeconds) {
    return const Winn3DescriptorCheck.absent(
        'descriptor-wire-profile-not-implemented');
  }

  final endpoint = (payload['endpoint'] ?? '').toString().trim();
  final innerRouterV4 = (payload['inner_router_v4'] ?? '').toString().trim();
  final gatewayStatic = (payload['static_pub'] ?? '').toString().trim();
  final gatewayId = (payload['gateway_id'] ?? '').toString().trim();
  final admissionKey = (payload['admission_secret'] ?? '').toString().trim();
  final authEd25519 = (payload['auth_ed25519'] ?? '').toString().trim();
  final authMldsa65 = (payload['auth_mldsa65'] ?? '').toString().trim();
  if ((authEd25519.isEmpty) != (authMldsa65.isEmpty)) {
    return const Winn3DescriptorCheck.absent(
        'descriptor-dual-auth-half-provisioned');
  }
  if (authEd25519.isNotEmpty) {
    int edLen;
    int mlLen;
    try {
      edLen = base64.decode(authEd25519).length;
      mlLen = base64.decode(authMldsa65).length;
    } catch (_) {
      return const Winn3DescriptorCheck.absent(
          'descriptor-dual-auth-key-not-base64');
    }
    if (edLen != 32 || mlLen != 1952) {
      return const Winn3DescriptorCheck.absent(
          'descriptor-dual-auth-key-wrong-length');
    }
  }
  if (!isWinnIpLiteralEndpoint(endpoint)) {
    return const Winn3DescriptorCheck.absent(
        'descriptor-endpoint-not-ip-literal');
  }
  if (!isWinnInnerIpv4(innerRouterV4)) {
    return const Winn3DescriptorCheck.absent(
        'descriptor-inner-router-not-ipv4');
  }
  final innerResolverV4 =
      (payload['inner_resolver_v4'] ?? '').toString().trim();
  if (!isWinnInnerIpv4(innerResolverV4)) {
    return const Winn3DescriptorCheck.absent(
        'descriptor-inner-resolver-not-ipv4');
  }
  if (innerResolverV4 != innerRouterV4) {
    return const Winn3DescriptorCheck.absent(
        'descriptor-resolver-does-not-match-gateway-bind');
  }
  if (gatewayStatic.isEmpty || gatewayId.isEmpty || admissionKey.isEmpty) {
    return const Winn3DescriptorCheck.absent('descriptor-missing-fields');
  }
  try {
    final pub = base64.decode(gatewayStatic);
    if (pub.length != 32) {
      return const Winn3DescriptorCheck.absent(
          'descriptor-static-pub-wrong-length');
    }
  } catch (_) {
    return const Winn3DescriptorCheck.absent(
        'descriptor-static-pub-wrong-length');
  }
  List<int> admissionRaw;
  try {
    admissionRaw = base64.decode(admissionKey);
  } catch (_) {
    return const Winn3DescriptorCheck.absent(
        'descriptor-admission-secret-not-base64');
  }
  if (admissionRaw.isEmpty) {
    return const Winn3DescriptorCheck.absent('descriptor-missing-fields');
  }
  // Hub trap, same as gateway_id: Android trims the decoded secret, the
  // gateway does not, and the value is never transmitted. A stolen signing
  // key (or a descriptor that predates the hub check) must not ship it.
  if (_winn3AsciiEdgeWhitespace(admissionRaw)) {
    return const Winn3DescriptorCheck.absent(
        'descriptor-admission-secret-has-edge-whitespace');
  }

  final descriptor = Winn3Descriptor(
    node: node,
    endpoint: endpoint,
    innerRouterV4: innerRouterV4,
    innerResolverV4: innerResolverV4,
    gatewayStaticBase64: gatewayStatic,
    gatewayIdBase64: gatewayId,
    admissionKey: admissionKey,
    authEd25519Base64: authEd25519,
    authMldsa65Base64: authMldsa65,
    kid: kid,
    notAfter: notAfter,
  );
  final operatorText = descriptor.gatewayIdOperatorText;
  if (operatorText == null) {
    // Validated, NOT consumed. The base64 is what ships; this only proves it
    // decodes to text, so a malformed value is a refusal an operator can read
    // instead of a session that starts, reports up and is ignored forever.
    return const Winn3DescriptorCheck.absent('descriptor-gateway-id-not-text');
  }
  // Trap 3 on the hub: one trailing space keys 9 bytes on the gateway and on
  // Apple and 8 on Android, and neither end can discover the disagreement
  // because the value is never transmitted. Refused here so a stolen signing
  // key, or a descriptor that predates the hub check, cannot ship it.
  if (operatorText != operatorText.trim()) {
    return const Winn3DescriptorCheck.absent(
        'descriptor-gateway-id-has-edge-whitespace');
  }
  if (utf8.encode(operatorText).length > 255) {
    return const Winn3DescriptorCheck.absent('descriptor-gateway-id-too-long');
  }
  return Winn3DescriptorCheck.ok(descriptor);
}

/// A bare dotted-quad IPv4 address, the form the inner `[winn]` fields take.
///
/// NOT the endpoint form. `inner_v4` and `inner_router_v4` are addresses INSIDE
/// the tunnel and carry no port. Mirrors `winn3_is_inner_ipv4` in the control
/// plane, including its refusal of the unspecified, loopback and multicast
/// addresses: none of them can be a tunnel assignment or a next hop, and the
/// winn/3 tun layer drops every packet whose source does not match the
/// assignment -- so a bad value here is a session that starts and carries
/// nothing.
bool isWinnInnerIpv4(Object? value) {
  final text = (value ?? '').toString().trim();
  final parts = text.split('.');
  if (parts.length != 4) return false;
  final octets = <int>[];
  for (final part in parts) {
    if (part.isEmpty || part.length > 3) return false;
    // Same all-ASCII-digits rule as [_isIpv4Literal]. Dart's int.tryParse
    // accepts a leading '+' (and 0x hex), which Python ipaddress and the
    // hub's winn3_is_inner_ipv4 reject. A stolen signing key that minted
    // 10.10.0.+1 would verify here and then fail closed at the engine:
    // the silent-failure class.
    if (!part
        .split('')
        .every((c) => c.codeUnitAt(0) >= 0x30 && c.codeUnitAt(0) <= 0x39)) {
      return false;
    }
    final n = int.tryParse(part);
    if (n == null || n < 0 || n > 255) return false;
    // "01" and "1" are different strings for the same address, and an inner
    // address is compared as text in more than one place.
    if (part.length > 1 && part.startsWith('0')) return false;
    octets.add(n);
  }
  if (octets[0] == 0) return false; // unspecified / "this network"
  if (octets[0] == 127) return false; // loopback
  if (octets[0] >= 224) return false; // multicast and reserved
  return true;
}

/// Maximum unescaped `{`/`[` nesting in [raw]. Not a JSON validator;
/// `json.decode` is. Exists so a hostile payload cannot make decode recurse
/// until the stack overflows. Braces and brackets inside strings are ignored,
/// matching `winn3JSONNestingDepth` in cmd/winn-datapath/winn3_profile.go.
int winn3DescriptorJSONNestingDepth(List<int> raw) {
  var depth = 0;
  var maxDepth = 0;
  var inString = false;
  var escaped = false;
  for (final b in raw) {
    if (inString) {
      if (escaped) {
        escaped = false;
        continue;
      }
      if (b == 0x5c) {
        // backslash
        escaped = true;
        continue;
      }
      if (b == 0x22) {
        // quote
        inString = false;
      }
      continue;
    }
    if (b == 0x22) {
      inString = true;
    } else if (b == 0x7b || b == 0x5b) {
      depth++;
      if (depth > maxDepth) maxDepth = depth;
    } else if (b == 0x7d || b == 0x5d) {
      if (depth > 0) depth--;
    }
  }
  return maxDepth;
}

/// Python `bytes.isspace()` on the first or last byte: space, tab, LF, VT,
/// FF, CR. Used for the admission-secret edge-whitespace trap; the secret is
/// opaque bytes and may not be UTF-8, so this must not go through utf8.decode.
bool _winn3AsciiEdgeWhitespace(List<int> raw) {
  if (raw.isEmpty) return false;
  return _winn3AsciiWhitespace(raw.first) || _winn3AsciiWhitespace(raw.last);
}

bool _winn3AsciiWhitespace(int b) =>
    b == 0x09 || b == 0x0a || b == 0x0b || b == 0x0c || b == 0x0d || b == 0x20;

WinnStartDecision resolveWinnProtocolStart({
  required String operatingSystem,
  required Map<String, dynamic> config,
  Winn3DescriptorCheck? winn3Descriptor,
}) {
  final platform = operatingSystem.trim().toLowerCase();
  final standaloneReleasePlatform =
      winn3BuildEnabledPlatforms().contains(platform);
  if (!platformSupportsWinnProtocol(platform)) {
    // The platform list is DERIVED from kWinnHostCapabilities rather than
    // written out here, so this copy cannot go on saying "Android only" after a
    // lane turns a second platform on -- which would be the same class of lie
    // as advertising support that does not exist, just in the other direction.
    final supported = winnSupportedPlatformsSentence();
    return WinnStartDecision.refuse(
      WinnRefusalReason.unsupportedPlatform,
      'This server uses Winn Protocol v3, which this app can only run on '
      '$supported today. Choose a different server, or connect from a device '
      'running $supported.',
    );
  }
  return resolveWinnProtocolStartForServedConfig(
    config: config,
    winn3Descriptor: winn3Descriptor,
    standaloneOnly: standaloneReleasePlatform,
  );
}

/// Everything [resolveWinnProtocolStart] decides AFTER the platform gate: the
/// stealth-chain branch, the `protocol_params` allowlist, and the endpoint,
/// MTU, datagram, session-id, header-type, padding, SPA and carrier
/// validation, plus the `[winn]` section it builds when all of that passes.
///
/// # This is NOT a way around the capability gate, and cannot become one
///
/// It takes no `operatingSystem` because none of this logic has ever depended
/// on one -- that was already documented as a load-bearing property of the
/// real function in `lib/winn_protocol_dev_override.dart`, which relied on it
/// to borrow a supported platform's decision. This function makes that
/// property structural instead of incidental. The ONE production caller is
/// [resolveWinnProtocolStart], which still runs the
/// [platformSupportsWinnProtocol] gate first and refuses before reaching here.
/// Nothing else in `lib/` calls it, and nothing else should: a caller that
/// skipped [resolveWinnProtocolStart] to reach this directly would be starting
/// `winn/3` on a platform [kWinnHostCapabilities] says cannot carry it, which
/// is the exact failure that table exists to prevent.
///
/// # Why it was extracted on 2026-08-08
///
/// The adjudication demoted the last two `.present` entries (see the `android`
/// and `linux` entries above), so the supported set is now EMPTY and every
/// `winn/3` start refuses at the gate. Before this extraction the only way to
/// reach the validation below was through a platform the table called
/// supported, so ~39 tests covering carriers, SPA parameters, MTU bounds,
/// header types and the params allowlist were written as
/// `operatingSystem: 'linux'` -- and with no supported platform left they all
/// short-circuited to `unsupported_platform` and silently stopped testing
/// their own subject. Deleting them would have thrown away the coverage the
/// flip-back gate depends on being correct when a platform is re-promoted;
/// pretending a platform is supported would have put the lie back in the
/// table. Splitting the gate from the logic keeps both honest: the gate is
/// tested as a gate, and the config rules are tested as config rules.
WinnStartDecision resolveWinnProtocolStartForServedConfig({
  required Map<String, dynamic> config,
  Winn3DescriptorCheck? winn3Descriptor,
  bool standaloneOnly = false,
}) {
  // THE PROTOCOL-VERSION GATE, enforced structurally rather than left to the
  // caller's doc contract. The whole of this function describes a winn/3
  // session -- the carrier, the header types, the `[winn]` section it builds.
  // A config that reaches it under any other protocol_version is internally
  // contradictory, and the ONE shipping caller (`resolveWinnProtocolStart`,
  // reached from `main.dart` only for winn/3 after the `winn/1` case has
  // already `break`-ed) never routes one here. The dev override's borrowed
  // decision calls `resolveWinnProtocolStart` with arbitrary served/typed
  // configs, so this refusal is what stops an override that only flips the
  // carrier to `winn3` -- leaving `protocol_version` at `winn/1` -- from
  // building a standalone winn/3 session out of a config that never asked for
  // one. Resolving it would hand that session a `[winn]` section the config
  // did not negotiate.
  final gatedProtocolVersion =
      normalizedWinnProtocolVersion(config['protocol_version']);
  if (gatedProtocolVersion != kWinnProtocolV3) {
    final versionText = gatedProtocolVersion == kWinnProtocolV1
        ? kWinnProtocolV1
        : 'an unsupported value';
    return WinnStartDecision.refuse(
      WinnRefusalReason.protocolVersionMismatch,
      'This config asks for a Winn Protocol v3 session but declares '
      'protocol_version "$versionText", which is not "$kWinnProtocolV3". '
      'The Winn gate resolves only winn/3 sessions and will not pick a '
      'protocol for a config that did not ask for one, so the connection was '
      'stopped.',
    );
  }

  // THE STACKED ARRANGEMENT, and it is an ADDED BRANCH rather than a relaxed
  // refusal. The refusal below is unchanged and still fires for every config
  // that carries `stealth_active` without the explicit opt-in -- which is every
  // config any hub serves today.
  //
  // Winn and Xray are only mutually exclusive as ALTERNATIVES competing for the
  // one AmneziaWG peer-endpoint field. Stacked, each relay owns a distinct
  // loopback port: AmneziaWG's outer datagrams go to the Winn seam, the Winn
  // engine's `direct-awg` carrier writes them to the Xray inbound, and Xray
  // carries them to the edge over VLESS/WS(/TLS). Nothing contends.
  final chainRequested =
      (config[kWinnOuterTransportKey] ?? '').toString().trim().toLowerCase() ==
          kWinnOuterTransportStealthChain;
  final int? chainLocalPort = winnStealthChainXrayLocalPort(config);
  if (chainRequested && chainLocalPort == null) {
    // Asked for the stack and did not supply the leg to stack on. Starting
    // direct-awg here would be the downgrade every refusal in this function
    // exists to prevent, so it is refused with the same code -- the config is
    // still ambiguous about which outer transport it means.
    return WinnStartDecision.refuse(
      WinnRefusalReason.stealthTransportConflict,
      'This server asked for Winn Protocol v3 to run over the stealth '
      'transport but did not supply a usable stealth transport to carry it, so '
      'this connection was stopped rather than started over a transport the '
      'server did not negotiate.',
    );
  }

  if (chainLocalPort == null && _isTrue(config['stealth_active'])) {
    return WinnStartDecision.refuse(
      WinnRefusalReason.stealthTransportConflict,
      'This server asks for Winn Protocol v3 and the stealth transport at the '
      'same time. They are different outer transports and cannot both carry '
      'one tunnel, so this connection was stopped rather than silently '
      'choosing one.',
    );
  }

  final params = config['protocol_params'] is Map
      ? Map<String, dynamic>.from(config['protocol_params'] as Map)
      : const <String, dynamic>{};

  // Refuse anything this build cannot honour BEFORE looking at the values it
  // can. A winn/3 config carrying post-quantum material lands here, which is
  // the whole point: starting a direct-awg session while ignoring an ML-KEM
  // parameter would advertise support this client does not have.
  final unknownParams = params.keys
      .map((k) => k.toString().trim().toLowerCase())
      .where((k) => k.isNotEmpty && !kWinnKnownProtocolParams.contains(k))
      .toList()
    ..sort();
  if (unknownParams.isNotEmpty) {
    return WinnStartDecision.refuse(
      WinnRefusalReason.unhonourableProtocolParams,
      'This server sent Winn Protocol v3 parameters this version of the app '
      'does not implement (${unknownParams.join(', ')}). Connecting anyway '
      'would claim support the app does not have, so the connection was '
      'stopped. Please update the app.',
    );
  }

  final resolvedCarrier = _resolvedCarrier(params);
  if (standaloneOnly && resolvedCarrier != kWinnCarrierWinn3) {
    return WinnStartDecision.refuse(
      WinnRefusalReason.carrierUnsupported,
      'This standalone Winn Protocol v3 release accepts only carrier "winn3". '
      'The server selected a retired relay carrier, so the connection was '
      'stopped rather than downgraded to AmneziaWG or Xray.',
    );
  }

  // THE STANDALONE BRANCH, and it is taken before ANY of the validation below.
  //
  // Everything from here to the end of this function describes a RELAY session:
  // an AmneziaWG engine that owns the tun, whose already-encapsulated outer
  // datagrams Winn carries. A `winn3` session has no AmneziaWG in it at all, so
  // `h1..h4`, `s1..s4`, `max_datagram`, the carrier profile and the SPA knock
  // are not "skipped" for it -- they describe components that are not present.
  // Running them anyway would refuse a valid standalone config for missing
  // parameters no standalone config has ever had.
  if (resolvedCarrier == kWinnCarrierWinn3) {
    return _winn3StandaloneStart(
      config: config,
      params: params,
      check: winn3Descriptor,
      chainRequested: chainRequested || chainLocalPort != null,
    );
  }

  // In the stacked arrangement the Winn engine's "gateway" is the Xray inbound
  // on loopback, and it OVERRIDES any served `gateway_endpoint`: a stacked
  // session that wrote the real gateway here would send AmneziaWG's outer
  // datagrams straight out of the engine's own UDP socket, which is the plain
  // direct-awg session the censor already drops -- and it would do so while the
  // config said stealth. `isWinnIpLiteralEndpoint` accepts a loopback literal
  // (it rejects only the unspecified address and multicast), exactly as
  // `datapath.validateIPLiteralEndpoint` does.
  final endpoint = chainLocalPort != null
      ? '127.0.0.1:$chainLocalPort'
      : _firstNonEmpty(<Object?>[
          params['gateway_endpoint'],
          config['server_endpoint'],
        ]);
  if (!isWinnIpLiteralEndpoint(endpoint)) {
    return WinnStartDecision.refuse(
      WinnRefusalReason.gatewayEndpointNotIpLiteral,
      'This Winn Protocol v3 server did not supply a numeric gateway address. '
      'The Winn engine will not look one up, because that lookup would leave '
      'the device outside the tunnel, so the connection was stopped.',
    );
  }

  final mtu = int.tryParse((config['mtu'] ?? '').toString().trim());
  if (mtu == null || mtu < kWinnMinMtu || mtu > kWinnMaxMtu) {
    return WinnStartDecision.refuse(
      WinnRefusalReason.mtuOutOfRange,
      'This Winn Protocol v3 server supplied an MTU the tunnel engine cannot '
      'use, so the connection was stopped.',
    );
  }

  int? maxDatagram;
  if (params.containsKey('max_datagram')) {
    maxDatagram = int.tryParse(params['max_datagram'].toString().trim());
    if (maxDatagram == null ||
        maxDatagram < kWinnMinDatagram ||
        maxDatagram > kWinnMaxDatagramCeiling) {
      return WinnStartDecision.refuse(
        WinnRefusalReason.maxDatagramOutOfRange,
        'This Winn Protocol v3 server supplied a datagram size outside the '
        'range the tunnel engine accepts, so the connection was stopped.',
      );
    }
  }

  final sessionId = (params['session_id'] ?? '').toString().trim();
  if (sessionId.length > kWinnMaxSessionIdBytes) {
    return WinnStartDecision.refuse(
      WinnRefusalReason.sessionIdTooLong,
      'This Winn Protocol v3 server supplied an over-long session identifier, '
      'so the connection was stopped.',
    );
  }
  // A newline would let a value forge an extra INI key, and '[' would forge a
  // section header. Neither can appear in a legitimate session id.
  if (sessionId.contains('\n') ||
      sessionId.contains('\r') ||
      sessionId.contains('[') ||
      sessionId.contains(']')) {
    return WinnStartDecision.refuse(
      WinnRefusalReason.sessionIdTooLong,
      'This Winn Protocol v3 server supplied a malformed session identifier, '
      'so the connection was stopped.',
    );
  }

  final headerTypes = winnAwgHeaderTypes(config);
  if (headerTypes == null) {
    final obfsForMsg = config['obfuscation'] is Map
        ? Map<String, dynamic>.from(config['obfuscation'] as Map)
        : const <String, dynamic>{};
    final missing = <String>[];
    final malformed = <String>[];
    for (final k in const <String>['H1', 'H2', 'H3', 'H4']) {
      final raw = obfsForMsg[k];
      if (raw == null || raw.toString().trim().isEmpty) {
        missing.add(k);
      } else if (VpnConfigValidator.parseAwgHeaderSpec(raw) == null) {
        malformed.add('$k=${raw.toString().trim()}');
      }
    }
    String detail;
    if (missing.isNotEmpty) {
      detail =
          'missing ${missing.join(', ')} (h1..h4 are REQUIRED for winn/3; without them the transport convergence gate cannot fire and a dead tunnel would be reported as connected)';
    } else if (malformed.isNotEmpty) {
      detail =
          'malformed ${malformed.join(', ')} (each h1..h4 must be a 32-bit unsigned value 5..4294967295 or a range start-end like 16777216-1086324735)';
    } else {
      detail =
          'h1..h4 overlap or otherwise invalid (ranges must be pairwise non-overlapping; for scalars this is distinctness)';
    }
    return WinnStartDecision.refuse(
      WinnRefusalReason.headerTypesInvalid,
      'This Winn Protocol v3 server supplied AmneziaWG header types the tunnel '
      'engine cannot classify ($detail), so the connection was stopped.',
    );
  }
  final padding = winnAwgPaddingSizes(config);
  if (padding == null) {
    return WinnStartDecision.refuse(
      WinnRefusalReason.headerTypesInvalid,
      'This Winn Protocol v3 server supplied AmneziaWG padding sizes the '
      'tunnel engine cannot classify with, so the connection was stopped.',
    );
  }

  // THE CARRIER. This is the value that decides whether the session performs
  // the post-quantum carrier handshake or carries AmneziaWG datagrams straight
  // to the gateway, and it is resolved rather than assumed for the same reason
  // `WinnEngineConfig.carrier` is: a constant here would sit below this gate.
  //
  // An absent `carrier` means direct-awg, so every config served before this
  // field existed behaves exactly as it did.
  if (!kWinnSupportedCarriers.contains(resolvedCarrier)) {
    return WinnStartDecision.refuse(
      WinnRefusalReason.carrierUnsupported,
      resolvedCarrier == kWinnCarrierHttp2
          ? 'This server selected a Winn Protocol v3 transport this app cannot '
              'carry on this device yet. Connecting over a different transport '
              'would not be the session the server negotiated, so the '
              'connection was stopped rather than downgraded.'
          : 'This server selected a Winn Protocol v3 transport this version of '
              'the app does not implement. Connecting anyway would claim '
              'support the app does not have, so the connection was stopped. '
              'Please update the app.',
    );
  }

  // The stack is a `direct-awg` arrangement and only a `direct-awg`
  // arrangement. `direct-awg` is one `WriteTo` of AmneziaWG's own unchanged
  // datagrams, which is exactly what the Xray inbound relays; an authenticated
  // carrier instead dials its OWN transport to the endpoint it is given, and
  // pointing that at a local Xray inbound would neither reach the far end nor
  // be the session the gateway negotiated. Refuse the pairing here rather than
  // let it fail inside the engine after the stealth leg is already up.
  if (chainLocalPort != null && resolvedCarrier != kWinnCarrierDirectAwg) {
    return WinnStartDecision.refuse(
      WinnRefusalReason.stealthTransportConflict,
      'This server asked for Winn Protocol v3 over the stealth transport and '
      'also selected a different Winn transport to carry it. Only one of them '
      'can carry the session, so this connection was stopped rather than '
      'silently choosing one.',
    );
  }

  // A carrier other than direct-awg needs a carrier profile, which is a second
  // document built from these fields. Validate them here so the refusal names
  // the field, rather than letting the native host fail after it has already
  // protected a socket.
  final carrierLines = <String>[];
  if (kWinnCarrierProfileCarriers.contains(resolvedCarrier)) {
    final missing = kWinnRequiredCarrierParams
        .where((k) => (params[k] ?? '').toString().trim().isEmpty)
        .toList()
      ..sort();
    if (missing.isNotEmpty) {
      return WinnStartDecision.refuse(
        WinnRefusalReason.carrierProfileIncomplete,
        'This server selected an authenticated Winn Protocol v3 transport but '
        'did not supply everything needed to verify it '
        '(${missing.join(', ')}). Starting an unauthenticated transport '
        'instead would be a downgrade of the session the server negotiated, so '
        'the connection was stopped.',
      );
    }
    for (final key in kWinnCarrierProfileParams) {
      final value = (params[key] ?? '').toString().trim();
      if (value.isEmpty) continue;
      if (!_isSafeIniValue(value)) {
        return WinnStartDecision.refuse(
          WinnRefusalReason.carrierProfileIncomplete,
          'This server supplied a malformed Winn Protocol v3 transport '
          'parameter ($key), so the connection was stopped.',
        );
      }
      carrierLines.add('$key = $value');
    }
    carrierLines.sort();
  }

  // Validated AFTER the carrier is resolved, because whether SPA can be
  // honoured at all depends on which carrier this session is.
  final spaRefusal = _spaRefusal(params: params, carrier: resolvedCarrier);
  if (spaRefusal != null) return spaRefusal;

  final lines = <String>[
    '[$kWinnConfigSection]',
    'enabled = true',
    'endpoint = $endpoint',
    // Emitted always, including the direct-awg default. The native host
    // defaults an absent value to direct-awg too, so this changes nothing
    // functionally -- it makes the carrier this session runs explicit in the
    // document rather than implied by an absence, which is what lets a reader
    // of a captured config tell a direct-awg session from a truncated one.
    'carrier = $resolvedCarrier',
    if (maxDatagram != null) 'max_datagram = $maxDatagram',
    if (sessionId.isNotEmpty) 'session_id = $sessionId',
    ...carrierLines,
    'h1 = ${headerTypes[0].spec}',
    'h2 = ${headerTypes[1].spec}',
    'h3 = ${headerTypes[2].spec}',
    'h4 = ${headerTypes[3].spec}',
    's1 = ${padding[0]}',
    's2 = ${padding[1]}',
    's3 = ${padding[2]}',
    's4 = ${padding[3]}',
  ];
  return WinnStartDecision.start(lines.join('\n'));
}

/// The `carrier` this config selects. An absent value means `direct-awg`, so
/// every config served before the field existed behaves exactly as it did.
String _resolvedCarrier(Map<String, dynamic> params) {
  final carrier = (params['carrier'] ?? '').toString().trim().toLowerCase();
  return carrier.isEmpty ? kWinnCarrierDirectAwg : carrier;
}

/// First non-empty value under any of [keys], trimmed.
///
/// The compat spellings are checked alongside the underscored ones because the
/// hub serves BOTH (`winn3_inner_v4` and `winn3innerv4`) and a client reading
/// only one of the two schemas would find nothing.
String _configString(Map<String, dynamic> config, List<String> keys) {
  for (final key in keys) {
    final value = (config[key] ?? '').toString().trim();
    if (value.isNotEmpty) return value;
  }
  return '';
}

/// Whether [value] is syntactically base64 of a non-empty byte string.
///
/// Shape only. It deliberately does NOT decode-and-re-encode to check
/// canonicality, and it never interprets what it decodes: `admission_key` is
/// OPAQUE and `gateway_id` belongs to the host's single decode.
bool _isWinnBase64(String value) {
  if (value.isEmpty) return false;
  try {
    return base64.decode(value).isNotEmpty;
  } catch (_) {
    return false;
  }
}

/// The `[winn]` section for a STANDALONE winn/3 session.
///
/// # The two halves, and why neither is usable alone
///
/// The GATEWAY's half arrives on the offline-signed descriptor: `endpoint`,
/// `inner_router_v4`, `gateway_static`, `gateway_id`, `admission_key`. The
/// DEVICE's half arrives per-device on `vpn_config`: `inner_v4` and
/// `static_private`. They come from different places because they have
/// different lifetimes and different trust: the descriptor is one signed object
/// per node, identical for every device and mintable only offline; the device
/// half is provisioned per device by the hub and is a private key, which is why
/// it rides the surface that already carries `client_private_key` rather than
/// `protocol_params` -- whose `WINN3_PARAM_NAME_NEVER_SERVED` guard refuses
/// `static_private` by construction.
///
/// # Every refusal here is a NAMED refusal, and that is the whole point
///
/// A v3 gateway never answers a datagram it could not authenticate. So every
/// one of the encoding mistakes below -- a `gateway_id` that is not base64 over
/// operator text, an `admission_key` this code re-encoded, an `inner_v4` from
/// the wrong address space -- produces a session that starts, reports up and is
/// silently ignored forever, which on a censored network is indistinguishable
/// from the gateway being blocked. Refusing by name here turns each of them
/// into something an operator can read.
WinnStartDecision _winn3StandaloneStart({
  required Map<String, dynamic> config,
  required Map<String, dynamic> params,
  required Winn3DescriptorCheck? check,
  required bool chainRequested,
}) {
  final served = applyWinn3ServedFields(
    dest: Map<String, dynamic>.from(config),
    raw: config,
  );
  if (chainRequested) {
    // The stealth chain works by repointing AmneziaWG's peer endpoint at a
    // local Xray inbound. A standalone session has no AmneziaWG to repoint, and
    // its own dialer aimed at a loopback inbound would neither reach the
    // gateway nor be the session the gateway negotiated.
    return WinnStartDecision.refuse(
      WinnRefusalReason.stealthTransportConflict,
      'This server asked for a standalone Winn Protocol v3 session and also '
      'asked to carry it over the stealth transport. The standalone session '
      'carries its own transport, so only one of them can carry this '
      'connection, and it was stopped rather than silently choosing one.',
    );
  }
  if (check == null || !check.verified || check.descriptor == null) {
    return WinnStartDecision.refuse(
      WinnRefusalReason.winn3DescriptorUnverified,
      'This server selected the standalone Winn Protocol v3 transport but did '
      'not supply a gateway record this app could verify. Connecting without '
      'one would mean trusting connection details this app cannot check, so '
      'the connection was stopped.',
    );
  }
  final descriptor = check.descriptor!;

  // Bind the verified descriptor node to the route-selected node BEFORE any
  // credential field is read. Signature validity is not enough: a valid
  // descriptor for gateway A substituted into gateway B's config would seal
  // initiations only A can open. Conflicting aliases are a mismatch, not a
  // first-wins preference, so a matching decoy key cannot paper over the
  // selected node.
  final selectedNode = winn3SelectedNodeIdentity(served);
  if (!winn3DescriptorBindsSelectedNode(served: served, descriptor: descriptor)) {
    return WinnStartDecision.refuse(
      WinnRefusalReason.winn3DescriptorNodeMismatch,
      'This server supplied a signed Winn Protocol v3 gateway record for a '
      'different node than the one selected for this connection. The record '
      'was refused before any tunnel traffic was sent.',
    );
  }

  // The relay binding of a ciphertext relay Double VPN (w3r/1). It runs AFTER
  // the ruled node binding above: the descriptor is still the selected exit's
  // own. A Double label without a relay, or a relay that does not agree with
  // the rest of the config, is refused before any credential is read; only a
  // valid relay changes the dialled address, never the identity.
  final relayBinding =
      winn3RelayBindingForServedConfig(served: served, descriptor: descriptor);
  if (!relayBinding.accepted) {
    if (relayBinding.refusal == WinnRefusalReason.winn3DoubleLabelWithoutRelay) {
      return WinnStartDecision.refuse(
        WinnRefusalReason.winn3DoubleLabelWithoutRelay,
        'This server labelled the connection as Double VPN but supplied no '
        'relay route for it. Connecting would use one hop under a two hop '
        'label, so the connection was stopped before any tunnel traffic was '
        'sent.',
      );
    }
    return WinnStartDecision.refuse(
      WinnRefusalReason.winn3RelayMalformed,
      'This server supplied a Double VPN relay route this app could not '
      'accept, so the connection was stopped before any tunnel traffic was '
      'sent.',
    );
  }
  // The address this session dials: the Core relay when one is bound, the
  // exit's own signed endpoint otherwise.
  final dialEndpoint = relayBinding.relay?.endpoint ?? descriptor.endpoint;

  // Dual-auth keys in a signed descriptor are consumed only by a host that
  // opted in ([kWinn3DualAuthHostSupported]) and advertised
  // [kWinnClientCapabilityDualAuth]. An unsupported host (iOS, macOS, Linux,
  // Windows, or any build that left the define off) advertised false, so it
  // continues as a legacy standalone session. INI emission below is already
  // gated on the same define and cannot silently drop keys from a dual-auth
  // build: that build either emits both exact values or never takes this
  // branch. Refusing here would strand mixed clients of a dual-provisioned
  // node instead of letting the hub's capability gate do its job.

  final innerV4 =
      _configString(served, const <String>['winn3_inner_v4', 'winn3innerv4']);
  final staticPrivate = _configString(
      served, const <String>['winn3_static_private', 'winn3staticprivate']);
  if (innerV4.isEmpty || staticPrivate.isEmpty) {
    return WinnStartDecision.refuse(
      WinnRefusalReason.winn3DeviceMaterialMissing,
      'This server selected the standalone Winn Protocol v3 transport but did '
      'not supply this device its own tunnel address and key. A standalone '
      'session has no AmneziaWG identity to borrow, so the connection was '
      'stopped rather than started without one.',
    );
  }
  if (!isWinnInnerIpv4(innerV4)) {
    return WinnStartDecision.refuse(
      WinnRefusalReason.winn3FieldMalformed,
      'This server supplied a tunnel address this app cannot use for a '
      'standalone Winn Protocol v3 session, so the connection was stopped.',
    );
  }
  if (!_isWinnBase64(staticPrivate)) {
    return WinnStartDecision.refuse(
      WinnRefusalReason.winn3FieldMalformed,
      'This server supplied a malformed key for a standalone Winn Protocol v3 '
      'session, so the connection was stopped.',
    );
  }
  if (innerV4 == descriptor.innerRouterV4) {
    // The device would be its own next hop. Nothing detects this on the wire.
    return WinnStartDecision.refuse(
      WinnRefusalReason.winn3FieldMalformed,
      'This server gave this device the same tunnel address as the server it '
      'connects through, so the connection was stopped.',
    );
  }
  // THE AMNEZIAWG ADDRESS IS THE TEMPTING MISTAKE AND IT IS ALWAYS WRONG.
  //
  // Standalone shares no address space with the relay because it shares no
  // session with it. The winn/3 tun layer validates the source address of every
  // packet the host offers and drops what does not match ITS assignment, so an
  // interface carrying the AmneziaWG address hands the engine a stream of
  // packets it silently discards as invalid: the gate never carries and the
  // session fails closed at the deadline with `winn3_rx_dropped_invalid` as the
  // only clue.
  //
  // This is the one half of that rule a CLIENT can check. It cannot verify that
  // `inner_v4` lies in the gateway's inner space -- the descriptor names a next
  // hop but not a prefix length, and guessing one would be inventing a fact.
  // The hub checks that half against WINN3_INNER_POOL_CIDR, where the pool is
  // an operator setting rather than a guess.
  final relayClientIp = (served['client_ip'] ?? '').toString().trim();
  if (relayClientIp.isNotEmpty && innerV4 == relayClientIp) {
    return WinnStartDecision.refuse(
      WinnRefusalReason.winn3FieldMalformed,
      'This server gave this device the same tunnel address for two different '
      'connection types. Using it would send traffic the server discards '
      'without reporting anything, so the connection was stopped.',
    );
  }
  // `gateway_static` is a 32-byte X25519 public key and `admission_key` is
  // opaque; both are checked for SHAPE only. Re-encoding either is the defect
  // the conformance suite pins, not a repair.
  if (!_isWinnBase64(descriptor.gatewayStaticBase64) ||
      !_isWinnBase64(descriptor.gatewayIdBase64) ||
      !_isWinnBase64(descriptor.admissionKey)) {
    return WinnStartDecision.refuse(
      WinnRefusalReason.winn3FieldMalformed,
      'This server supplied malformed connection credentials for a standalone '
      'Winn Protocol v3 session, so the connection was stopped.',
    );
  }

  // OPTIONAL FIELDS. Read from `vpn_config` rather than `protocol_params`,
  // which is a closed twenty-key allowlist that carries none of them. Omitted
  // when the hub serves nothing, which is the case today.
  //
  // `carrier_classes` IS THE ONE TO WATCH. The engine reads an empty plan as
  // {"udp"} -- a plan that forbids migration -- but cdatapath SUBSTITUTES that
  // default silently rather than refusing, so an omitted plan gives a udp-only
  // inner-MTU floor (1443 at a 1500 path) with no refusal anywhere. If the
  // gateway's own plan includes tcp or tls, its floor is 1359 and every
  // full-size flow black-holes the moment the session migrates, while both ends
  // report "up". That is the `empty-plan-handling` divergence and defect 2
  // reached by omission. The value is the GATEWAY's plan, so only the operator
  // knows it; this reads it and never invents it.
  final psk = _configString(served, const <String>['winn3_psk', 'winn3psk']);
  final pathMtu =
      _configString(served, const <String>['winn3_path_mtu', 'winn3pathmtu']);
  final carrierClasses = _configString(
      served, const <String>['winn3_carrier_classes', 'winn3carrierclasses']);
  final sessionId = (params['session_id'] ?? '').toString().trim();

  if (carrierClasses.isNotEmpty) {
    final classes = carrierClasses
        .split(',')
        .map((token) => token.trim().toLowerCase())
        .toList(growable: false);
    if (classes.any((token) =>
            token.isEmpty ||
            (token != 'udp' && token != 'tcp' && token != 'tls')) ||
        !classes.contains('udp')) {
      return WinnStartDecision.refuse(
        WinnRefusalReason.winn3FieldMalformed,
        'This server supplied a carrier plan without a usable UDP path. This '
        'client cannot start a TCP- or TLS-only standalone Winn Protocol v3 '
        'session, so the connection was stopped.',
      );
    }
  }

  if (pathMtu.isNotEmpty && int.tryParse(pathMtu) == null) {
    return WinnStartDecision.refuse(
      WinnRefusalReason.winn3FieldMalformed,
      'This server supplied a malformed path size for a standalone Winn '
      'Protocol v3 session, so the connection was stopped.',
    );
  }
  for (final value in <String>[
    innerV4,
    staticPrivate,
    dialEndpoint,
    descriptor.innerRouterV4,
    descriptor.gatewayStaticBase64,
    descriptor.gatewayIdBase64,
    descriptor.admissionKey,
    if (descriptor.innerResolverV4.isNotEmpty) descriptor.innerResolverV4,
    if (psk.isNotEmpty) psk,
    if (carrierClasses.isNotEmpty) carrierClasses,
    if (sessionId.isNotEmpty) sessionId,
  ]) {
    // A newline forges an extra INI key and '[' forges a section header.
    if (!_isSafeIniValue(value)) {
      return WinnStartDecision.refuse(
        WinnRefusalReason.winn3FieldMalformed,
        'This server supplied a malformed standalone Winn Protocol v3 '
        'parameter, so the connection was stopped.',
      );
    }
  }

  // NO `h1`..`h4` AND NO `s1`..`s4`. They are AmneziaWG obfuscation parameters
  // for an AmneziaWG engine this session does not contain. Emitting them would
  // make a standalone document indistinguishable from a relay one to a reader,
  // and `WinsTunnelConfig` selects the AmneziaWG loopback seam on exactly that
  // shape -- which for a standalone session is the silent downgrade the carrier
  // gate exists to prevent.
  final lines = <String>[
    '[$kWinnConfigSection]',
    'enabled = true',
    'carrier = $kWinnCarrierWinn3',
    // The dialled address: the exit's own signed endpoint, or the Core relay
    // address when a valid `winn3_relay` is bound (see
    // winn3RelayBindingForServedConfig). Only this VALUE differs between a
    // single hop and a relay session. Every native host reads its dial target
    // and carrier exclusion from this one line, so no host changes.
    'endpoint = $dialEndpoint',
    'node = ${descriptor.node}',
    'selected_node = $selectedNode',
    'inner_v4 = $innerV4',
    'inner_router_v4 = ${descriptor.innerRouterV4}',
    // Format-3 verification requires this signed address and equality with
    // inner_router_v4. Keep emission conditional for unverified local objects.
    //
    // Position is not cosmetic: it sits beside `inner_router_v4` because it is
    // the same KIND of fact from the same signed document, and
    // `conform.ServedWinnSectionKeyOrder` pins that position so the document a
    // host is handed in the suite is the document this writer produces.
    //
    // Native hosts must consume this signed field according to their format-3
    // contract. This comment makes no claim that a descriptor omits it.
    if (descriptor.innerResolverV4.isNotEmpty)
      'inner_resolver_v4 = ${descriptor.innerResolverV4}',
    'static_private = $staticPrivate',
    'gateway_static = ${descriptor.gatewayStaticBase64}',
    // VERBATIM BASE64, and this line is the reason the whole descriptor path
    // exists. The engine takes the RAW OPERATOR-STRING BYTES; the single decode
    // belongs to the host that reads descriptor-shaped fields. Decoding here
    // would make this the second decode, and a second decode is precisely the
    // `gateway-id-is-raw-operator-bytes` defect: `winsgw01` is eight characters
    // of the base64 alphabet, so the wrong answer looks entirely plausible and
    // the gateway simply never answers.
    'gateway_id = ${descriptor.gatewayIdBase64}',
    // VERBATIM, AND OPAQUE. The key file's 64 ASCII hex characters are what
    // both ends key with. Sending base64 of the 32 DECODED bytes gives a
    // gateway that admits the datagram, BUILDS a session, and then goes
    // completely silent -- worse than a refusal, because a host watching for
    // "did the gateway see me" sees yes.
    'admission_key = ${descriptor.admissionKey}',
    // Dual-signature attestation keys (docs/DUAL_SIGNATURE_SPEC.md). The
    // standalone gate above refuses a dual-auth descriptor unless this build
    // opted in. Therefore this conditional can never silently remove the keys:
    // it either emits both exact descriptor values or no dual-auth session
    // starts at all.
    if (descriptor.hasDualAuth && kWinn3DualAuthHostSupported) ...[
      'auth_ed25519 = ${descriptor.authEd25519Base64}',
      'auth_mldsa65 = ${descriptor.authMldsa65Base64}',
    ],
    if (psk.isNotEmpty) 'psk = $psk',
    if (pathMtu.isNotEmpty) 'path_mtu = $pathMtu',
    if (carrierClasses.isNotEmpty) 'carrier_classes = $carrierClasses',
    if (sessionId.isNotEmpty) 'session_id = $sessionId',
  ];
  return WinnStartDecision.start(lines.join('\n'));
}

/// `knock.HeaderSize` -- a 16-byte nonce plus a 32-byte HMAC-SHA256 tag. The
/// floor on `spa_packet_size`: anything shorter cannot hold a knock.
const int kWinnSpaMinPacketSize = 48;

/// `carrier.AbsoluteMaxDatagram`. The ceiling on `spa_packet_size`, and it is a
/// real constraint rather than a round number: a knock must be ONE unfragmented
/// datagram, because a censor that already drops or flags fragmented UDP would
/// make the knock a worse fingerprint than having no SPA at all.
const int kWinnSpaMaxPacketSize = 1500;

/// `knock.Options.resolve`: a bucket is at least a second, and the skew is at
/// least a bucket.
const int kWinnSpaMinBucketWindowSeconds = 1;

/// Whether the served single-packet-authorization params can be honoured, and
/// why not when they cannot.
///
/// Mirrors `carrierhost.normalizeSPA`, and mirrors it in the same direction:
/// the engine is the authority and refuses last, but it refuses at CREATE time
/// -- after a socket has been opened and protected -- so refusing here first
/// turns a late, opaque failure into an early, named one.
///
/// Returns null when there is nothing to refuse, which includes the ordinary
/// case of a config that names no `spa_*` param at all.
WinnStartDecision? _spaRefusal({
  required Map<String, dynamic> params,
  required String carrier,
}) {
  final mode = (params['spa_mode'] ?? '').toString().trim().toLowerCase();
  final otherSpaKeys = kWinnSpaCarrierProfileKeys
      .where((k) => k != 'spa_mode')
      .where((k) => (params[k] ?? '').toString().trim().isNotEmpty)
      .toList()
    ..sort();

  if (mode.isEmpty || mode == kWinnSpaModeOff) {
    // Refused, not ignored -- the engine's own rule (ErrSPAFieldWithoutMode).
    // A target or a packet size left behind after SPA was turned off is the
    // operator believing something is armed that is not, and silently dropping
    // it is what made this whole feature unreachable in the first place.
    if (otherSpaKeys.isNotEmpty) {
      return WinnStartDecision.refuse(
        WinnRefusalReason.spaParamsUnhonourable,
        'This server sent Winn Protocol v3 single-packet-authorization '
        'settings (${otherSpaKeys.join(', ')}) without turning the mechanism '
        'on. Ignoring them would leave a defence configured that is not '
        'running, so the connection was stopped.',
      );
    }
    return null;
  }

  if (mode != kWinnSpaModeRequired) {
    return WinnStartDecision.refuse(
      WinnRefusalReason.spaParamsUnhonourable,
      'This server asked for a connection-initiation mode this version of the '
      'app does not implement. Connecting anyway would claim support the app '
      'does not have, so the connection was stopped. Please update the app.',
    );
  }

  // A UDP knock cannot ride a connected TCP socket, and direct-awg has no
  // carrier dialer for `knockdial` to decorate at all. `knockdial.New` refuses
  // both at CONSTRUCTION rather than at dial, so neither can ever work; naming
  // that here keeps the reason legible.
  if (carrier != kWinnCarrierHttp3) {
    return WinnStartDecision.refuse(
      WinnRefusalReason.spaParamsUnhonourable,
      'This server asked for single packet authorization on a transport that '
      'cannot carry the knock. Connecting without it would reach a gateway '
      'that is dropping unauthorized packets, so the connection was stopped '
      'rather than left to time out.',
    );
  }

  final target = (params['spa_target'] ?? '').toString().trim();
  // Deliberately no default. The gate may sit in front of the carrier listener
  // or in front of the AmneziaWG gateway, and a wrong guess sends the
  // deployment's shared credential to a host that is not supposed to have it.
  if (!isWinnIpLiteralEndpoint(target)) {
    return WinnStartDecision.refuse(
      WinnRefusalReason.spaParamsUnhonourable,
      'This server asked for single packet authorization but did not say '
      'where to send the knock, or gave a name instead of a numeric address. '
      'Guessing would send a shared credential to the wrong host, so the '
      'connection was stopped.',
    );
  }

  final packetSize = _spaIntParam(params, 'spa_packet_size');
  if (packetSize != null &&
      (packetSize < kWinnSpaMinPacketSize ||
          packetSize > kWinnSpaMaxPacketSize)) {
    return WinnStartDecision.refuse(
      WinnRefusalReason.spaParamsUnhonourable,
      'This server supplied a knock size the tunnel engine cannot send in one '
      'packet, so the connection was stopped.',
    );
  }

  final bucket = _spaIntParam(params, 'spa_bucket_window_seconds');
  final skew = _spaIntParam(params, 'spa_max_skew_seconds');
  // These must match the gate exactly. A mismatch fails CLOSED and is
  // completely silent -- no knock ever verifies and nothing reports an error
  // anywhere -- so a value that is not even self-consistent is worth refusing
  // here, where the reason can still be stated.
  if ((bucket != null && bucket < kWinnSpaMinBucketWindowSeconds) ||
      (skew != null && skew < 0) ||
      (bucket != null && skew != null && skew < bucket)) {
    return WinnStartDecision.refuse(
      WinnRefusalReason.spaParamsUnhonourable,
      'This server supplied knock timing settings the tunnel engine cannot '
      'use, so the connection was stopped. Connecting with them would have '
      'produced a knock that silently never verifies.',
    );
  }

  for (final key in <String>[
    'spa_packet_size',
    'spa_bucket_window_seconds',
    'spa_max_skew_seconds'
  ]) {
    final raw = (params[key] ?? '').toString().trim();
    if (raw.isNotEmpty && int.tryParse(raw) == null) {
      return WinnStartDecision.refuse(
        WinnRefusalReason.spaParamsUnhonourable,
        'This server supplied a malformed knock parameter ($key), so the '
        'connection was stopped.',
      );
    }
  }
  return null;
}

int? _spaIntParam(Map<String, dynamic> params, String key) {
  final raw = (params[key] ?? '').toString().trim();
  if (raw.isEmpty) return null;
  return int.tryParse(raw);
}

/// Whether THIS build compiled in a usable winn/3 descriptor verification
/// ring whose identity matches the reviewed WIRE-FORM digest.
///
/// The keys come from `String.fromEnvironment` (`WINS_WINN3_DESCRIPTOR_PUBKEY_G1..G3`),
/// defaulting to the Track B ceremony public keys
/// ([kWinn3ReviewedDescriptorPubkeyG1]..G3) and
/// [kWinn3ReviewedDescriptorRingSha256]. `--dart-define` still overrides.
/// Absent or unusable overrides mean this build cannot verify a descriptor.
/// This is the fail-closed default the capability gate depends on: a build
/// with no ring must not advertise that it can consume a signed gateway
/// descriptor, because it would then name a verifier that cannot exist and
/// refuse every descriptor it is served.
///
/// `attestsExpectedIdentity` (not mere "any non-empty define") is the right
/// predicate: the ring drops a slot whose value is present but unusable --
/// bad base64 or the wrong key length -- so a typo degrades to "this build
/// has no ring", never to a ring that accepts something it should not. A
/// SHA256 define that is the ceremony MANIFEST digest rather than WIRE-FORM
/// also fail-closes.
bool winnDescriptorVerificationRingCarried() =>
    Winn3DescriptorKeyRing.fromCompiledDefines()
        .attestsExpectedIdentity(_kWinn3DescriptorRingSha256);

Map<String, Object> winnDescriptorVerificationRingAttestation() {
  final ring = Winn3DescriptorKeyRing.fromCompiledDefines();
  return <String, Object>{
    'schema_version': 1,
    'slots': ring.compiledSlotIds,
    'identity_sha256': ring.identitySha256,
    'expected_identity_sha256': _kWinn3DescriptorRingSha256,
    'attested': ring.attestsExpectedIdentity(_kWinn3DescriptorRingSha256),
  };
}

/// The pure form of [winnClientCapabilities]: what a device may honestly
/// advertise, given the three facts that decide it.
///
/// Kept separate from the operating-system wrapper so BOTH directions of the
/// gate can be tested without a platform being `.present` today: an
/// incapable host (an old v1-era client, or iOS while
/// `kWinnHostCapabilities['ios']` is `.absent`) must advertise nothing that
/// could make the hub serve winn/3, and a host that can carry must still be
/// denied the descriptor and SPA flags it cannot honour. Production always
/// feeds [hostCanCarryWinn3] from `kWinnHostCapabilities` (see
/// [winnClientCapabilities]) -- never from a second list.
Map<String, bool> winnClientCapabilityFlags({
  required bool hostCanCarryWinn3,
  required bool spaKeyProvisioned,
  bool? descriptorRingCarried,
  bool? dualAuthHostSupported,
}) {
  final ringCarried =
      descriptorRingCarried ?? winnDescriptorVerificationRingCarried();
  final dualAuth = dualAuthHostSupported ?? kWinn3DualAuthHostSupported;
  return <String, bool>{
    // AWG-carried AND standalone winn/3 both need the native host datapath, so
    // this one flag carries both. Absent-by-default at the hub, so the old
    // client sends neither and is served exactly the winn/1 it is served today.
    'supports_winn3': hostCanCarryWinn3,
    // Standalone v3 additionally needs a verifier ring and a knock of its own;
    // without them the client would refuse every descriptor it is served,
    // which is "advertised capability, silently carried" in its purest form.
    'supports_winn3_descriptor': hostCanCarryWinn3 && ringCarried,
    'supports_winn3_spa': hostCanCarryWinn3 && spaKeyProvisioned,
    // Dual-signature attestation keys ride the signed descriptor. Advertise
    // [kWinnClientCapabilityDualAuth] only when this build actually consumes
    // both of them: native host datapath, verifier ring, AND the release
    // define that emits `auth_ed25519` / `auth_mldsa65` into `[winn]`.
    // Android release sets that define; iOS, macOS, Linux, and Windows leave
    // it off and must therefore advertise false.
    kWinnClientCapabilityDualAuth: hostCanCarryWinn3 && ringCarried && dualAuth,
  };
}

/// The `supports_*` capability flags this device may honestly advertise to the
/// control plane, as the flag names the hub reads them under.
///
/// # Why this exists, and why it is not a version check
///
/// The control plane cannot serve `winn/3` or `spa_*` params blindly. A client
/// that does not understand them refuses the whole connection
/// ([WinnRefusalReason.unhonourableProtocolParams]) -- correct, but it means
/// switching a node to winn/3 or to single packet authorization would strand
/// every client that had not caught up. So capability has to be advertised,
/// not assumed.
///
/// It also cannot be inferred from the app version. Shipping the code that
/// understands `winn/3` and being able to carry it are separate events, and
/// only the device knows where it stands: an OLD client that predates these
/// flags sends neither `supports_winn3` nor
/// `supports_winn3_descriptor` nor `supports_winn3_spa` nor
/// `supports_winn3_dualauth`, the hub defaults all
/// of them to false, and it is served the byte-for-byte winn/1 config it was
/// served before the flags existed. A client on the right version with no key would be served SPA,
/// would name a key file that is not there, and would fail every connection --
/// capability reporting success while carrying nothing.
///
/// So [spaKeyProvisioned] is a fact about this device, not a build flag, and
/// this function is pure so that fact can be tested directly. `supports_winn3`
/// is likewise derived from [platformSupportsWinnProtocol] -- the ONE table,
/// `kWinnHostCapabilities` -- and `supports_winn3_descriptor` additionally
/// from [winnDescriptorVerificationRingCarried]. `supports_winn3_dualauth`
/// additionally requires [kWinn3DualAuthHostSupported], the same define that
/// emits both attestation keys. None of these is ever derived from
/// `Platform.operatingSystem` by an inline comparison; that is how a second,
/// drifting list of "supported" platforms comes into being.
Map<String, bool> winnClientCapabilities({
  required String operatingSystem,
  required bool spaKeyProvisioned,
  bool? descriptorRingCarried,
  bool? dualAuthHostSupported,
}) {
  return winnClientCapabilityFlags(
    hostCanCarryWinn3: platformSupportsWinnProtocol(operatingSystem),
    spaKeyProvisioned: spaKeyProvisioned,
    descriptorRingCarried: descriptorRingCarried,
    dualAuthHostSupported: dualAuthHostSupported,
  );
}

/// Whether the iOS build may report a Winn Protocol v3 datapath it can actually
/// start -- the "host can carry winn/3" fact the capability flags consume for
/// iOS.
///
/// # Why iOS cannot be a static `.present` entry, and why this is the wrap
///
/// iOS is a CONDITIONAL capability. As of 2026-08-10 the winn/3 datapath
/// archive is staged into the iOS app and `WinnTunnelCreateWinn3` is present in
/// a signed dev build (docs/handoff/HW_IOS_DEVICE_WINN3_20260810.md), so
/// "source that compiles and a datapath that resolves" is no longer the
/// blocker -- but NO standalone winn/3 session has ever run on a shipping iOS
/// build. Flipping `kWinnHostCapabilities['ios']` to a hard `.present` on the
/// strength of a staged build would be exactly the "capability reports success
/// while carrying nothing" failure this file exists to prevent.
///
/// So iOS reports winn/3-capable only while its native host is GENUINELY
/// CARRYING a winn/3 datapath -- the runtime `trulyCarrying` fact -- and never
/// from a build flag. This is the one place that fact is turned into an iOS
/// capability predicate; `kWinnHostCapabilities['ios']` itself stays `.absent`
/// because, as a compile-time table, it cannot state a runtime condition. A
/// build (and a test) supplies `trulyCarrying: false`; the native host supplies
/// the fact once its promotion gate has observed a live, carrying session.
///
/// This is deliberately a pure function of the fact, not a global read: exactly
/// the shape of [winnClientCapabilityFlags], so both directions of the gate can
/// be tested without any platform being `.present` and without a second,
/// drifting "supported" list.
bool winn3IosReportsCarryingCapability({required bool trulyCarrying}) =>
    trulyCarrying;

/// The STANDALONE winn/3 start decision for an iOS device, wrapped by the
/// "truly carrying" gate.
///
/// Everything this RESOLVES -- descriptor verification, the per-device half,
/// and the emitted `[winn]` section -- is decided verbatim by
/// [resolveWinnProtocolStartForServedConfig], exactly as on any other platform
/// that reaches a standalone start. What this adds is the iOS capability wrap:
/// a standalone start may resolve on iOS only while the native host is
/// genuinely carrying a winn/3 datapath.
///
/// When it is not carrying, this refuses with
/// [WinnRefusalReason.unsupportedPlatform] and an empty section rather than
/// emitting a start for a build that cannot carry it -- never a fallback to
/// another carrier, and never a [WinnStartDecision.start] the iOS host could
/// not honour. See [winn3IosReportsCarryingCapability] for why iOS cannot be a
/// static `.present` entry in [kWinnHostCapabilities] and what "truly carrying"
/// means.
WinnStartDecision resolveIosWinn3Start({
  required Map<String, dynamic> config,
  required Winn3DescriptorCheck? winn3Descriptor,
  required bool trulyCarrying,
}) {
  if (!winn3IosReportsCarryingCapability(trulyCarrying: trulyCarrying)) {
    return WinnStartDecision.refuse(
      WinnRefusalReason.unsupportedPlatform,
      'This server uses Winn Protocol v3, which the app on this device can '
      'only run while it is genuinely carrying a winn/3 datapath. This build '
      'is not carrying one right now, so the connection was stopped. Choose a '
      'different server, or reconnect on a platform that is carrying winn/3.',
    );
  }
  return resolveWinnProtocolStartForServedConfig(
    config: config,
    winn3Descriptor: winn3Descriptor,
  );
}

/// Whether a served value can be written into an INI section without changing
/// its structure.
///
/// A newline would let one value forge an extra key -- and the keys around it
/// include `endpoint`, so a forged line could redirect the tunnel -- while `[`
/// and `]` would forge a section header and could reopen `[Interface]` or
/// `[Peer]`. `=` is permitted because it appears legitimately inside a MASQUE
/// URI template's query, and only the FIRST `=` on a line separates key from
/// value in the host's parser.
///
/// This applies to every carrier parameter rather than to a chosen few: the
/// values come from `protocol_params`, which the control plane hands through
/// verbatim, so none of them is more trustworthy than any other.
bool _isSafeIniValue(String value) {
  if (value.isEmpty || value.length > 512) return false;
  for (final unit in value.codeUnits) {
    // Control characters, including CR and LF.
    if (unit < 0x20 || unit == 0x7F) return false;
    // '[' and ']' forge a section header.
    if (unit == 0x5B || unit == 0x5D) return false;
  }
  return true;
}

/// The `[winn]` INI section that [config] requires, or `''` when it requires
/// none. THROWS rather than return `''` for a `winn/3` config that cannot
/// start the Winn path.
///
/// This is the second anti-downgrade gate, and it is deliberately not a
/// duplicate of the dispatch seam in `_startTunnelCandidate`. The seam decides
/// gracefully -- it tells the user why and fails the connection. This one sits
/// inside the only function that turns a served config into the string the
/// native tunnel is actually started from, so it is what keeps the property
/// alive if the seam is ever removed, reordered, or bypassed by a new call
/// site that forgets it.
///
/// Returning `''` for an unstartable `winn/3` config would be the bug: an
/// AmneziaWG config with no `[winn]` section is exactly what
/// `VpnTunnelService` starts as plain AmneziaWG, which is the silent downgrade
/// of a Winn Protocol v3 negotiation.
String winnSectionForTunnelConfig({
  required String operatingSystem,
  required Map<String, dynamic> config,
  Winn3DescriptorCheck? winn3Descriptor,
}) {
  final protocolVersion = strictWinnProtocolVersionForTunnelConfig(config);
  if (protocolVersion == kWinnProtocolV1) {
    if (!_consumeWinn1FallbackDispatchAuthorization(config)) {
      throw StateError('Refusing Winn Protocol v1 without a current, exact '
          'ordinary-v3-failure authorization. The reviewed compatibility '
          'order is AWG first and Xray second.');
    }
    return '';
  }
  if (protocolVersion == null) {
    throw StateError('Refusing to build a tunnel configuration for unknown '
        'or ambiguous protocol_version state.');
  }
  final decision = resolveWinnProtocolStart(
    operatingSystem: operatingSystem,
    config: config,
    // Passed through, never derived here: verification is asynchronous and
    // this function is not. A standalone config reaching this point with no
    // check refuses by name (winn3_descriptor_unverified) rather than starting
    // a session on an unverified gateway record -- which is exactly the
    // "forgot to await it" failure this shape is chosen to make impossible.
    winn3Descriptor: winn3Descriptor,
  );
  if (!decision.supported) {
    throw StateError(
        'Refusing to build an AmneziaWG tunnel configuration for a '
        '$kWinnProtocolV3 config that cannot start the Winn path '
        '(${decision.reason.code}). Starting the classical AmneziaWG path '
        'here would silently downgrade a Winn Protocol v3 negotiation.');
  }
  return decision.iniSection;
}

/// The `h1`..`h4` classification table for [config], or null when it is not a
/// usable one.
///
/// WINN_MANDATORY_HEADERS 2026-08-08: h1..h4 are REQUIRED for winn/3. A winn/3
/// section with no h1..h4 disables the transport convergence gate forever:
/// the engine classifies against vanilla WireGuard 1/2/3/4 while the interface
/// emits h1..h4, so transport_observed_both_ways can NEVER become true and the
/// gate cannot fire. A promotion gate that cannot fire is worse than no gate
/// because it looks like protection. The hub always serves all four
/// (DEFAULT_OBFUSCATION / parse_obfuscation requires every key), so refusing
/// missing cannot fleet-lockout; these parameters are not negotiated, so a value
/// the far end cannot start is a lockout anyway. See
/// docs/handoff/WINN3_HEADER_MANDATORY_DECISION_20260808.md.
///
/// The values are read from `obfuscation` and MUST be present. Each entry is an
/// [AwgHeaderSpec] -- either a scalar (`11`) or an inclusive range
/// (`16777216-1086324735`) that the AmneziaWG engine draws from once per packet
/// via `device/magic-header.go:Generate()` in `RoutineEncryption`. The
/// validator for the classic path, [VpnConfigValidator.parseAwgHeaderSpec], is
/// the single source of truth for the parse, the bounds (`5..4294967295`), the
/// interior-whitespace refusal and the width guard; this function delegates to
/// it rather than re-deriving those rules. Being more permissive than the
/// engine (e.g. accepting `1000 - 4000`) would let through a profile the far
/// end cannot start.
///
/// Overlapping ranges are refused here for the same reason
/// `device/uapi.go:mergeWithDevice` refuses them: the receiver classifies by
/// testing the header word against each interval in turn, and two intervals
/// that intersect make that test ambiguous. For scalars this degrades to
/// equality, i.e. the pairwise-distinctness rule that was here before ranges.
List<AwgHeaderSpec>? winnAwgHeaderTypes(Map<String, dynamic> config) {
  // 0xFFFFFFFF parity: ceiling must equal VpnConfigValidator.awgHeaderMax
  final obfs = config['obfuscation'] is Map
      ? Map<String, dynamic>.from(config['obfuscation'] as Map)
      : const <String, dynamic>{};
  final specs = <AwgHeaderSpec>[];
  for (final key in const <String>['H1', 'H2', 'H3', 'H4']) {
    final raw = obfs[key];
    if (raw == null || raw.toString().trim().isEmpty) {
      return null;
    }
    final spec = VpnConfigValidator.parseAwgHeaderSpec(raw);
    if (spec == null) return null;
    specs.add(spec);
  }
  for (var a = 0; a < specs.length; a++) {
    for (var b = a + 1; b < specs.length; b++) {
      if (specs[a].overlaps(specs[b])) return null;
    }
  }
  return specs;
}

/// The `s1`..`s4` prefix padding sizes for [config], or null when one is not a
/// usable value.
///
/// AmneziaWG PREPENDS `s1` random bytes to a handshake initiation, `s2` to a
/// handshake response, `s3` to a cookie reply and `s4` to a transport datagram,
/// so the header word the Winn engine matches on sits at that offset rather
/// than at offset 0.
///
/// These must be emitted or the engine classifies against the wrong offsets.
/// `datapath/classify.go` states the consequence exactly: omitting s1/s2/s3
/// silently kills the handshake counters, and omitting a nonzero s4 silently
/// kills the TRANSPORT counters -- the ones `transport_observed_both_ways` is
/// built from, which `WINN_PROTOCOL_PLATFORM_PLAN.md` names as the only field a
/// route-promotion gate may use. A gate reading a dead counter can pass on a
/// tunnel carrying nothing.
///
/// The defaults are exactly the ones `_buildRawAmneziaConfig` writes into
/// `[Interface] S1..S4`, so the offsets the Winn engine classifies with can
/// never disagree with the padding the AmneziaWG engine is actually applying.
/// `obfuscation` stays the single source of truth for both.
List<int>? winnAwgPaddingSizes(Map<String, dynamic> config) {
  final obfs = config['obfuscation'] is Map
      ? Map<String, dynamic>.from(config['obfuscation'] as Map)
      : const <String, dynamic>{};
  const defaults = <String, int>{'S1': 16, 'S2': 80, 'S3': 16, 'S4': 0};
  final values = <int>[];
  for (final key in const <String>['S1', 'S2', 'S3', 'S4']) {
    final raw = obfs[key];
    final int? value;
    if (raw == null || raw.toString().trim().isEmpty) {
      value = defaults[key];
    } else {
      value = int.tryParse(raw.toString().trim());
    }
    // uint16 in the engine, and WinnEngineConfig enforces the same bound.
    if (value == null || value < 0 || value > 0xFFFF) return null;
    values.add(value);
  }
  return values;
}

String _firstNonEmpty(List<Object?> candidates) {
  for (final candidate in candidates) {
    final text = (candidate ?? '').toString().trim();
    if (text.isNotEmpty) return text;
  }
  return '';
}

bool _isTrue(Object? value) {
  if (value is bool) return value;
  final text = (value ?? '').toString().trim().toLowerCase();
  return text == 'true' || text == '1' || text == 'yes' || text == 'y';
}
