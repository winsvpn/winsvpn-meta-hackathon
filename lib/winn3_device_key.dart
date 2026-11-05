/// This device's own Winn Protocol v3 static identity (IA-CP-05).
///
/// Fable 5.1 ruling, 2026-09-29: a device generates its own winn/3 X25519
/// static keypair. The hub stores and publishes only the PUBLIC half
/// (`winn3_static_public`) plus the inner address it allocates. The private
/// half is generated here, stored only in this app's secure state store under
/// [kWinn3KeyPairFileName], and handed to the tunnel only through the local
/// config layer ([attachLocalWinn3StaticKey]). It is never put on the wire.
///
/// The pattern is the AmneziaWG client identity already shipped in
/// `lib/main.dart` (`_generateWireGuardPrivateKeyBytes`,
/// `_commitClientKeyPairCandidateUnlocked`, `client_public_key` on `/verify`,
/// and the `client_key_mismatch` refusal in `hub_verify_candidate.dart`). It
/// is a SECOND keypair under a second name on purpose: the hub's schema
/// forbids reusing the AWG key as the v3 identity.
///
/// A hub-served private key is the transition case only (a hub not yet
/// upgraded, Fable 5.1 ruling and contract v1): it is used for that session,
/// never written to the device key store, never persisted with the config,
/// dropped when the session ends, and refused outright when the hub also
/// echoes this device's own public key. The local key wins as soon as the hub
/// echoes it.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:cryptography/cryptography.dart';

import 'winn3_cover_fallback.dart';

/// Secure-state record holding every account scope's v3 keypair. Must be in
/// `_sensitiveStateFileNames` (lib/main.dart) and in every native store's
/// allowlist (Apple `WinsSecureStateStore.allowedNames`, Android
/// `SecureFileStore.allowedNames`, Linux `IsAllowedLinuxSecureTextName`,
/// Windows `IsAllowedSecureTextName`).
const String kWinn3KeyPairFileName = 'winn3_keypair.json';

/// Format tag of the [kWinn3KeyPairFileName] document. A document with any
/// other tag is not trusted.
const String kWinn3KeyPairFormat = 'winn3-x25519-static-v1';

/// Request field carrying this device's v3 public key on `/verify` and
/// `/free/verify`, and the hub's echo of it inside `vpn_config`.
const String kWinn3StaticPublicField = 'winn3_static_public';

/// Every spelling the hub may use for the echo (the compat overlay serves the
/// no-underscore twin beside every underscored key).
const List<String> kWinn3StaticPublicAliases = <String>[
  'winn3_static_public',
  'winn3staticpublic',
];

/// The config field the tunnel reads its v3 static private key from. Kept as
/// the same field the hub used to serve so the INI emission and every native
/// host (Android `WinnV3Keys.kt`, Apple `WinsWinn3SessionStart.swift`,
/// Windows `winn3_supervisor.h`, Linux `linux_winn3_host.h`) need no change.
const String kWinn3StaticPrivateField = 'winn3_static_private';

const List<String> kWinn3StaticPrivateAliases = <String>[
  'winn3_static_private',
  'winn3staticprivate',
];

/// Capability flag telling the hub this request carries the device's own v3
/// public key, so it can tell the two populations apart without inferring it
/// from field presence.
const String kWinnClientCapabilityWinn3ClientKey = 'supports_winn3_client_key';

/// Keys under which a v3 pair rides the in-memory `clientKeys` map next to the
/// AWG `private_key` / `public_key`. In-memory only: never sent, never
/// written except through [Winn3DeviceKeyStore].
const String kWinn3ClientKeysPrivateEntry = 'winn3_private_key';
const String kWinn3ClientKeysPublicEntry = 'winn3_public_key';

/// Named refusals added to `hubVerifyCandidateRejection`.
const String kWinn3KeyMismatchRejection = 'winn3_key_mismatch';
const String kWinn3ServedPrivateKeyRejection = 'winn3_served_private_key';

/// Stable code the hub sends (HTTP 409, header `X-Wins-Error-Code`) when the
/// v3 public key a request carried is already on file for another device
/// (lane_keys_hub/api_contract.md v1, rule 4). The gateway refuses a whole
/// registry snapshot holding a duplicate `static_public`, so the hub refuses
/// the request instead; the app answers with a fresh keypair.
const String kWinn3StaticPublicInUseCode = 'winn3_static_public_in_use';

/// Whether one `/verify` response is the hub's "this winn/3 key belongs to
/// another device" refusal. Keyed on the stable header only, never on prose.
bool isWinn3StaticPublicInUse(int statusCode, Map<String, String> headers) {
  if (statusCode != 409) return false;
  for (final entry in headers.entries) {
    if (entry.key.trim().toLowerCase() == 'x-wins-error-code') {
      return entry.value.trim().toLowerCase() == kWinn3StaticPublicInUseCode;
    }
  }
  return false;
}

/// The v3 public key one `/verify` request body carried, or '' when it
/// carried none or is not a JSON object.
String winn3StaticPublicInRequestBody(String? body) {
  if (body == null || body.isEmpty) return '';
  try {
    final decoded = jsonDecode(body);
    if (decoded is! Map) return '';
    return (decoded[kWinn3StaticPublicField] ?? '').toString().trim();
  } catch (_) {
    return '';
  }
}

/// The hub's [kWinn3StaticPublicInUseCode] refusals, keyed by the exact v3
/// public key each refused request carried (Sol, OI-KEYSAPP-7). A refusal can
/// therefore only ever rotate the identity it named: a late 409 for account
/// A's key cannot touch account B's, and a 409 for a key that has already
/// been replaced matches nothing and is inert.
class Winn3KeyCollisionLedger {
  final Set<String> _refused = <String>{};

  /// Records [statusCode] / [headers] if they are the collision refusal for
  /// the request whose body was [requestBody]. True when something was
  /// recorded. A refusal whose request carried no readable key is ignored.
  bool note(
    int statusCode,
    Map<String, String> headers,
    String? requestBody,
  ) {
    if (!isWinn3StaticPublicInUse(statusCode, headers)) return false;
    final publicKey = winn3StaticPublicInRequestBody(requestBody);
    if (!isWinn3Base64Key(publicKey)) return false;
    return _refused.add(publicKey);
  }

  bool refuses(String publicKey) => _refused.contains(publicKey);

  void resolved(String publicKey) => _refused.remove(publicKey);
}

/// This scope's v3 pair for one request, rotating it only when the hub
/// refused THIS pair's public key as another device's. The rotation is a
/// compare-and-replace ([Winn3DeviceKeyStore.replaceIfStill]), so two
/// concurrent requests on the same refusal rotate once.
Future<Winn3DeviceKeyPair> winn3KeyPairResolvingCollision(
  Winn3DeviceKeyStore store,
  String scopeToken,
  Winn3KeyCollisionLedger collisions,
) async {
  final current = await store.loadOrCreate(scopeToken);
  if (!collisions.refuses(current.publicKey)) return current;
  final replacement = await store.replaceIfStill(scopeToken, current.publicKey);
  collisions.resolved(current.publicKey);
  return replacement;
}

bool isWinn3Base64Key(String value) {
  try {
    return base64.decode(value).length == 32;
  } catch (_) {
    return false;
  }
}

/// A clamped X25519 scalar, exactly like `_generateWireGuardPrivateKeyBytes`.
/// Clamping is done here, not left to the library, so the stored bytes are the
/// scalar every consumer (Dart `cryptography`, Go `crypto/ecdh`) uses.
List<int> generateWinn3StaticPrivateBytes([Random? random]) {
  final source = random ?? Random.secure();
  final privateBytes = List<int>.generate(32, (_) => source.nextInt(256));
  privateBytes[0] &= 248;
  privateBytes[31] &= 127;
  privateBytes[31] |= 64;
  return privateBytes;
}

Future<String> deriveWinn3StaticPublic(List<int> privateBytes) async {
  if (privateBytes.length != 32) {
    throw const FormatException('winn/3 static private key must be 32 bytes');
  }
  final keyPair = await X25519().newKeyPairFromSeed(privateBytes);
  return base64.encode((await keyPair.extractPublicKey()).bytes);
}

class Winn3DeviceKeyPair {
  const Winn3DeviceKeyPair({required this.privateKey, required this.publicKey});

  /// Base64 of the 32-byte X25519 private scalar. Never leaves the device.
  final String privateKey;

  /// Base64 of the matching 32-byte public key. The only half ever sent.
  final String publicKey;

  static Future<Winn3DeviceKeyPair> generate({Random? random}) async {
    final privateBytes = generateWinn3StaticPrivateBytes(random);
    return Winn3DeviceKeyPair(
      privateKey: base64.encode(privateBytes),
      publicKey: await deriveWinn3StaticPublic(privateBytes),
    );
  }

  /// Both halves are 32-byte base64 and the public half is derived from the
  /// private half.
  Future<bool> isValid() async {
    if (!isWinn3Base64Key(privateKey) || !isWinn3Base64Key(publicKey)) {
      return false;
    }
    try {
      return await deriveWinn3StaticPublic(base64.decode(privateKey)) ==
          publicKey;
    } catch (_) {
      return false;
    }
  }

  /// The entries this pair adds to an in-memory `clientKeys` map.
  Map<String, String> toClientKeyEntries() => <String, String>{
        kWinn3ClientKeysPrivateEntry: privateKey,
        kWinn3ClientKeysPublicEntry: publicKey,
      };

  /// The v3 pair carried in an in-memory `clientKeys` map, or null when that
  /// map carries none.
  static Winn3DeviceKeyPair? fromClientKeys(Map<String, String> clientKeys) {
    final privateKey = (clientKeys[kWinn3ClientKeysPrivateEntry] ?? '').trim();
    final publicKey = (clientKeys[kWinn3ClientKeysPublicEntry] ?? '').trim();
    if (privateKey.isEmpty || publicKey.isEmpty) return null;
    return Winn3DeviceKeyPair(privateKey: privateKey, publicKey: publicKey);
  }

  Map<String, String> _toStored() => <String, String>{
        'private_key': privateKey,
        'public_key': publicKey,
      };
}

/// [awgKeys] plus the v3 entries of [winn3] when there is one. The AWG
/// entries are never altered.
Map<String, String> clientKeysWithWinn3(
  Map<String, String> awgKeys,
  Winn3DeviceKeyPair? winn3,
) {
  final merged = Map<String, String>.from(awgKeys)
    ..remove(kWinn3ClientKeysPrivateEntry)
    ..remove(kWinn3ClientKeysPublicEntry);
  if (winn3 != null) merged.addAll(winn3.toClientKeyEntries());
  return merged;
}

/// The fields a `/verify` or `/free/verify` body carries for the v3 identity.
///
/// Only the PUBLIC half is ever returned. [kWinnClientCapabilityWinn3ClientKey]
/// says "this build owns its winn/3 identity" and is true for every host that
/// can carry winn/3, INCLUDING a request whose key could not be loaded this
/// time: the hub then mints nothing (api_contract.md v1, "a client-key build
/// that lost its key must not be handed one") and serves no standalone v3 to
/// this request, instead of creating a hub-held private key this build would
/// refuse anyway. A host that cannot carry winn/3 ([hostCarriesWinn3] false)
/// sends no key and claims nothing.
Map<String, dynamic> winn3ClientKeyRequestFields({
  required Map<String, String> clientKeys,
  required bool hostCarriesWinn3,
}) {
  if (!hostCarriesWinn3) {
    return <String, dynamic>{kWinnClientCapabilityWinn3ClientKey: false};
  }
  final publicKey = (clientKeys[kWinn3ClientKeysPublicEntry] ?? '').trim();
  return <String, dynamic>{
    if (isWinn3Base64Key(publicKey)) kWinn3StaticPublicField: publicKey,
    kWinnClientCapabilityWinn3ClientKey: true,
  };
}

String _firstString(Map<String, dynamic> map, List<String> aliases) {
  for (final key in aliases) {
    final value = map[key];
    if (value == null) continue;
    final text = value.toString().trim();
    if (text.isNotEmpty) return text;
  }
  return '';
}

/// The v3 public key a served config echoes, or '' when it echoes none.
String servedWinn3StaticPublic(Map<String, dynamic> config) =>
    _firstString(config, kWinn3StaticPublicAliases);

/// The v3 private key a served config carries, or '' when it carries none.
String servedWinn3StaticPrivate(Map<String, dynamic> config) =>
    _firstString(config, kWinn3StaticPrivateAliases);

/// Marker the app puts beside a hub-served v3 private key it is using for ONE
/// session (transition rule, Arbiter ruling on OI-KEYSAPP-1, 2026-09-29).
/// Set and removed only by [attachLocalWinn3StaticKey]; normalization never
/// copies a hub-sent field of this name, so the hub cannot set it.
const String kWinn3StaticPrivateOriginField = 'winn3_static_private_origin';
const String kWinn3StaticPrivateOriginHubSession = 'hub-session';

/// The v3 binding checks for one authenticated `/verify` reply, run inside
/// `hubVerifyCandidateRejection` beside the AWG `client_key_mismatch` check.
///
/// Only a request that carried this device's own v3 public key
/// ([localWinn3StaticPublic] non-empty) is checked. For such a request:
///
///  * a non-empty echo that is not this device's key is
///    [kWinn3KeyMismatchRejection]: the reply was built for another identity;
///  * a served non-empty private key BESIDE an echo of this device's own key
///    is [kWinn3ServedPrivateKeyRejection]: the hub claims to have adopted the
///    local key and hands over a different private anyway. An upgraded hub
///    never does that (api_contract.md v1: `""` for every client-key device).
///
/// A served private key with NO echo is the transition case (a hub not yet
/// upgraded). The Fable 5.1 ruling and contract v1 accept it for that session
/// only; see [attachLocalWinn3StaticKey] and
/// [withoutForeignWinn3StaticPrivate].
String? winn3ServedKeyRejection({
  required Map<String, dynamic> servedConfig,
  required String localWinn3StaticPublic,
}) {
  final local = localWinn3StaticPublic.trim();
  if (local.isEmpty) return null;
  final echo = servedWinn3StaticPublic(servedConfig);
  if (echo.isNotEmpty && echo != local) return kWinn3KeyMismatchRejection;
  if (echo == local && servedWinn3StaticPrivate(servedConfig).isNotEmpty) {
    return kWinn3ServedPrivateKeyRejection;
  }
  return null;
}

/// Puts the v3 static private key the tunnel will use into a normalized
/// config, the way `_attachLocalClientKeys` puts the AWG private key there.
///
///  * The hub echoes [local]'s public key: the LOCAL private key is attached.
///    The local key always wins once the hub has adopted it, and any served
///    private is discarded.
///  * A foreign echo while a local key exists: nothing is attached (the reply
///    is refused as [kWinn3KeyMismatchRejection]).
///  * Otherwise, a hub-served private key (a hub not yet upgraded) is kept for
///    THIS SESSION ONLY and marked with [kWinn3StaticPrivateOriginField]. It
///    is never committed to the device key store,
///    [withoutForeignWinn3StaticPrivate] strips it (by value) before any
///    config is persisted and when the session ends, and
///    [winn3ConfigKeyUsable] refuses to reuse it for a later session.
///  * No served private and no adopting echo: nothing is attached, and a
///    standalone start refuses by name (`winn3_device_material_missing`).
///
/// Idempotent: applying it to a config it already produced changes nothing,
/// which keeps `winn3ServedPlanChanged` comparisons stable.
Map<String, dynamic> attachLocalWinn3StaticKey(
  Map<String, dynamic> config,
  Winn3DeviceKeyPair? local,
) {
  final served = servedWinn3StaticPrivate(config);
  final withKey = Map<String, dynamic>.from(config);
  for (final alias in kWinn3StaticPrivateAliases) {
    withKey.remove(alias);
  }
  withKey.remove(kWinn3StaticPrivateOriginField);
  final echo = servedWinn3StaticPublic(withKey);
  if (local != null && echo.isNotEmpty) {
    if (echo == local.publicKey) {
      withKey[kWinn3StaticPrivateField] = local.privateKey;
    }
    return withKey;
  }
  if (served.isNotEmpty) {
    withKey[kWinn3StaticPrivateField] = served;
    withKey[kWinn3StaticPrivateOriginField] =
        kWinn3StaticPrivateOriginHubSession;
  }
  return withKey;
}

/// Whether [config] carries a hub-served, session-only v3 private key.
bool carriesHubSessionWinn3Key(Map<String, dynamic> config) =>
    config[kWinn3StaticPrivateOriginField] ==
    kWinn3StaticPrivateOriginHubSession;

/// [config] without any v3 private key that is not one of this device's own
/// ([localPrivateKeys]). Decided BY VALUE, never by the session marker, so a
/// rebuild that drops the marker (`_configForTransport` re-normalizes through
/// a closed key list) cannot let a hub-served key through (Seat C, A-1). This
/// is what every config write persists, and what is left in memory when a
/// session ends. Returns [config] itself when nothing had to be removed.
Map<String, dynamic> withoutForeignWinn3StaticPrivate(
  Map<String, dynamic> config,
  Set<String> localPrivateKeys,
) {
  final carried = servedWinn3StaticPrivate(config);
  final hasMarker = config.containsKey(kWinn3StaticPrivateOriginField);
  final aliasesPresent =
      kWinn3StaticPrivateAliases.where(config.containsKey).length;
  final keep = carried.isNotEmpty && localPrivateKeys.contains(carried);
  if (keep && !hasMarker) return config;
  if (!keep && aliasesPresent == 0 && !hasMarker) return config;
  final stripped = Map<String, dynamic>.from(config)
    ..remove(kWinn3StaticPrivateOriginField);
  if (!keep) {
    for (final alias in kWinn3StaticPrivateAliases) {
      stripped.remove(alias);
    }
  }
  return stripped;
}

/// Whether the connect path may start a session on [config]'s v3 private key,
/// decided by value:
///
///  * exactly this device's local key: yes;
///  * any other key is a hub-served session key: only when [freshFromHub]
///    (fetched for THIS session, so no extra /verify), and never when the hub
///    echoes the local public (that conflict is refused);
///  * no key: yes, except a standalone winn/3 config that did NOT come fresh
///    from the hub. Its session key was dropped at the end of an earlier
///    session (or never persisted), so the connect path refreshes instead of
///    starting a session the start path would refuse.
bool winn3ConfigKeyUsable(
  Map<String, dynamic> config,
  Winn3DeviceKeyPair? local, {
  required bool freshFromHub,
}) {
  final carried = servedWinn3StaticPrivate(config);
  if (carried.isEmpty) {
    return freshFromHub || !isStandaloneWinn3ServedConfig(config);
  }
  if (local != null && carried == local.privateKey) return true;
  if (!freshFromHub) return false;
  return local == null || servedWinn3StaticPublic(config) != local.publicKey;
}

/// Account-scoped storage of v3 keypairs in one secure-state document:
/// `{"format": kWinn3KeyPairFormat, "accounts": {scopeToken: {private_key,
/// public_key}}}`.
///
/// [read], [write] and [delete] are the secure-state accessors for
/// [kWinn3KeyPairFileName]; nothing here touches a file or a channel directly.
/// Every read-modify-write runs on one internal queue, so two scopes never
/// race on the shared document.
///
/// Error policy:
///  * a read that THROWS propagates. The caller then sends no v3 key this
///    time. A transient store failure must never rotate an identity.
///  * a document that reads but is not a valid one, or an entry that fails
///    validation, is unusable forever; [loadOrCreate] replaces it with a
///    fresh pair (rotation costs one registry republish at the hub).
class Winn3DeviceKeyStore {
  Winn3DeviceKeyStore({
    required Future<String?> Function() read,
    required Future<void> Function(String value) write,
    Future<void> Function()? delete,
    Random? random,
  })  : _read = read,
        _write = write,
        _delete = delete,
        _random = random;

  final Future<String?> Function() _read;
  final Future<void> Function(String value) _write;
  final Future<void> Function()? _delete;
  final Random? _random;
  Future<void> _tail = Future<void>.value();

  Future<T> _serialized<T>(Future<T> Function() operation) {
    final completer = Completer<T>();
    final previous = _tail;
    _tail = completer.future.then<void>((_) {}, onError: (_) {});
    previous.whenComplete(() async {
      try {
        completer.complete(await operation());
      } catch (error, stack) {
        completer.completeError(error, stack);
      }
    });
    return completer.future;
  }

  /// The accounts map, or null when the stored document is absent or not a
  /// valid document. Throws when the store itself fails.
  Future<Map<String, dynamic>?> _readAccounts() async {
    final encoded = await _read();
    if (encoded == null || encoded.trim().isEmpty) return null;
    try {
      final decoded = jsonDecode(encoded);
      if (decoded is Map &&
          decoded['format'] == kWinn3KeyPairFormat &&
          decoded['accounts'] is Map) {
        return Map<String, dynamic>.from(decoded['accounts'] as Map);
      }
    } catch (_) {
      // Unreadable document: treated as no document, never trusted.
    }
    return null;
  }

  Future<void> _writeAccounts(Map<String, dynamic> accounts) async {
    final encoded = jsonEncode(<String, dynamic>{
      'format': kWinn3KeyPairFormat,
      'accounts': accounts,
    });
    await _write(encoded);
    if (await _read() != encoded) {
      throw StateError('winn/3 device identity failed read-back verification');
    }
  }

  static Future<Winn3DeviceKeyPair?> _validEntry(Object? entry) async {
    if (entry is! Map) return null;
    final pair = Winn3DeviceKeyPair(
      privateKey: (entry['private_key'] ?? '').toString(),
      publicKey: (entry['public_key'] ?? '').toString(),
    );
    return await pair.isValid() ? pair : null;
  }

  static void _requireScope(String scopeToken) {
    if (scopeToken.trim().isEmpty) {
      throw StateError('Account scope is required for a winn/3 identity');
    }
  }

  /// This scope's stored pair, or null when there is none or it is unusable.
  /// Never creates. Throws only when the store read fails.
  Future<Winn3DeviceKeyPair?> loadExisting(String scopeToken) =>
      _serialized(() async {
        _requireScope(scopeToken);
        final accounts = await _readAccounts();
        return _validEntry(accounts?[scopeToken]);
      });

  /// This scope's stored pair, generating and durably committing a new one
  /// when there is none or the stored one is unusable. This is the migration
  /// trigger: a device upgraded from a build that ran on a hub-minted key has
  /// no local pair, so its first `/verify` on this build creates one and the
  /// hub adopts it, which retires the hub-minted identity.
  Future<Winn3DeviceKeyPair> loadOrCreate(String scopeToken) =>
      _serialized(() async {
        _requireScope(scopeToken);
        final accounts = await _readAccounts() ?? <String, dynamic>{};
        final existing = await _validEntry(accounts[scopeToken]);
        if (existing != null) return existing;
        final fresh = await Winn3DeviceKeyPair.generate(random: _random);
        accounts[scopeToken] = fresh._toStored();
        await _writeAccounts(accounts);
        return fresh;
      });

  /// Generates and durably commits a fresh pair for this scope, replacing
  /// whatever was there. The answer to the hub's
  /// [kWinn3StaticPublicInUseCode] refusal.
  Future<Winn3DeviceKeyPair> replaceWithFresh(String scopeToken) async {
    final fresh = await stageCandidate();
    await commit(scopeToken, fresh);
    return fresh;
  }

  /// Replaces this scope's pair with a fresh one only if the stored pair is
  /// still the one whose public key is [publicKey]; otherwise returns the
  /// stored pair unchanged. One queue slot, so the check and the write cannot
  /// interleave with another operation.
  Future<Winn3DeviceKeyPair> replaceIfStill(
    String scopeToken,
    String publicKey,
  ) =>
      _serialized(() async {
        _requireScope(scopeToken);
        final accounts = await _readAccounts() ?? <String, dynamic>{};
        final stored = await _validEntry(accounts[scopeToken]);
        if (stored != null && stored.publicKey != publicKey) return stored;
        final fresh = await Winn3DeviceKeyPair.generate(random: _random);
        accounts[scopeToken] = fresh._toStored();
        await _writeAccounts(accounts);
        return fresh;
      });

  /// A fresh pair that is NOT stored. Used where the AWG identity is rotated
  /// too (setup-key enrollment): its public half is sent, and it replaces the
  /// stored pair only through [commit] after the hub authenticates.
  Future<Winn3DeviceKeyPair> stageCandidate() =>
      Winn3DeviceKeyPair.generate(random: _random);

  /// Durably replaces this scope's pair with [candidate], verified by reading
  /// it back.
  Future<void> commit(String scopeToken, Winn3DeviceKeyPair candidate) =>
      _serialized(() async {
        _requireScope(scopeToken);
        if (!await candidate.isValid()) {
          throw StateError('Candidate winn/3 identity failed validation');
        }
        final accounts = await _readAccounts() ?? <String, dynamic>{};
        accounts[scopeToken] = candidate._toStored();
        await _writeAccounts(accounts);
        final readBack =
            await _validEntry((await _readAccounts())?[scopeToken]);
        if (readBack == null ||
            readBack.privateKey != candidate.privateKey ||
            readBack.publicKey != candidate.publicKey) {
          throw StateError(
              'Candidate winn/3 identity failed durable read-back');
        }
      });

  /// Every stored private key, across all scopes. Throws when the store read
  /// fails. Used to decide, by value, which v3 private keys may be persisted.
  Future<Set<String>> allPrivateKeys() => _serialized(() async {
        final accounts = await _readAccounts() ?? <String, dynamic>{};
        final keys = <String>{};
        for (final entry in accounts.values) {
          final pair = await _validEntry(entry);
          if (pair != null) keys.add(pair.privateKey);
        }
        return keys;
      });

  /// Removes this scope's pair; true when none remains afterwards. Deletes the
  /// whole record once the last scope is gone, so a logged-out install keeps
  /// no v3 identity at all.
  Future<bool> delete(String scopeToken) => _serialized(() async {
        final accounts = await _readAccounts();
        if (accounts == null) {
          final raw = await _read();
          if (raw != null && raw.trim().isNotEmpty) {
            // An unreadable document still names nothing usable; remove it.
            final remover = _delete;
            if (remover != null) {
              await remover();
            } else {
              await _write('');
            }
          }
          final after = await _read();
          return after == null || after.trim().isEmpty;
        }
        accounts.remove(scopeToken);
        if (accounts.isEmpty) {
          final remover = _delete;
          if (remover != null) {
            await remover();
          } else {
            await _writeAccounts(accounts);
          }
        } else {
          await _writeAccounts(accounts);
        }
        final remaining = await _readAccounts();
        return remaining == null || !remaining.containsKey(scopeToken);
      });
}
