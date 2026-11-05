import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/hub_verify_candidate.dart';
import 'package:wins_vpn/winn3_device_key.dart';
import 'package:wins_vpn/winn_protocol_dispatch.dart';

/// IA-CP-05, app side (Fable 5.1 ruling 2026-09-29): the device generates its
/// own winn/3 X25519 static keypair, keeps the private half in the secure
/// store, sends only the public half, refuses a hub-served private key or a
/// foreign echo, and rotates on the migration and enrollment triggers.

/// An in-memory stand-in for one secure-state record, with switches for the
/// failure modes the store must survive.
class _FakeSecureRecord {
  String? value;
  int writes = 0;
  int deletes = 0;
  bool failReads = false;
  bool dropWrites = false;

  Future<String?> read() async {
    if (failReads) throw StateError('secure store unavailable');
    return value;
  }

  Future<void> write(String next) async {
    writes += 1;
    if (!dropWrites) value = next;
  }

  Future<void> delete() async {
    deletes += 1;
    value = null;
  }
}

Winn3DeviceKeyStore _storeOn(_FakeSecureRecord record, {Random? random}) =>
    Winn3DeviceKeyStore(
      read: record.read,
      write: record.write,
      delete: record.delete,
      random: random,
    );

String _key(int fill) => base64.encode(List<int>.filled(32, fill));

void main() {
  group('key generation', () {
    test('a generated private key is a clamped 32-byte X25519 scalar', () {
      for (var seed = 0; seed < 64; seed++) {
        final bytes = generateWinn3StaticPrivateBytes(Random(seed));
        expect(bytes, hasLength(32));
        expect(bytes[0] & 7, 0, reason: 'low three bits cleared');
        expect(bytes[31] & 128, 0, reason: 'top bit cleared');
        expect(bytes[31] & 64, 64, reason: 'second-top bit set');
      }
    });

    test('two generated pairs never share a private key', () async {
      final a = await Winn3DeviceKeyPair.generate();
      final b = await Winn3DeviceKeyPair.generate();
      expect(a.privateKey, isNot(b.privateKey));
      expect(a.publicKey, isNot(b.publicKey));
      expect(await a.isValid(), isTrue);
      expect(await b.isValid(), isTrue);
    });

    // Pinned byte for byte in the engine:
    // winn_protocol_experimental/winn3/core/device_generated_static_key_test.go
    // derives these publics with core.NewStaticKey(...).Public(). If the two
    // derivations disagreed, the hub would publish a key the engine never
    // proves possession of.
    test('the public key is the one the Go engine derives', () async {
      expect(
        await deriveWinn3StaticPublic(
            base64.decode('AAoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1Vw=')),
        'u1D/noKldM+/gg6X9g+5wUPsdBXPUU+M/Zjv9Z4FlhQ=',
      );
      expect(
        await deriveWinn3StaticPublic(
            base64.decode('dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=')),
        'hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=',
        reason: 'RFC 7748 section 6.1 (Alice)',
      );
    });

    test('a pair whose halves do not match is not valid', () async {
      final a = await Winn3DeviceKeyPair.generate();
      final b = await Winn3DeviceKeyPair.generate();
      expect(
          await Winn3DeviceKeyPair(
                  privateKey: a.privateKey, publicKey: b.publicKey)
              .isValid(),
          isFalse);
      expect(
          await const Winn3DeviceKeyPair(privateKey: 'x', publicKey: 'y')
              .isValid(),
          isFalse);
    });
  });

  group('secure storage', () {
    test('loadOrCreate generates once, stores it, and returns it again',
        () async {
      final record = _FakeSecureRecord();
      final store = _storeOn(record);
      final first = await store.loadOrCreate('scope-a');
      expect(await first.isValid(), isTrue);
      final decoded = jsonDecode(record.value!) as Map<String, dynamic>;
      expect(decoded['format'], kWinn3KeyPairFormat);
      expect((decoded['accounts'] as Map)['scope-a'], <String, dynamic>{
        'private_key': first.privateKey,
        'public_key': first.publicKey,
      });
      final writesAfterCreate = record.writes;
      final second = await store.loadOrCreate('scope-a');
      expect(second.privateKey, first.privateKey);
      expect(second.publicKey, first.publicKey);
      expect(record.writes, writesAfterCreate, reason: 'no silent rotation');
    });

    test('each account scope has its own identity', () async {
      final record = _FakeSecureRecord();
      final store = _storeOn(record);
      final results = await Future.wait(<Future<Winn3DeviceKeyPair>>[
        store.loadOrCreate('scope-a'),
        store.loadOrCreate('scope-b'),
      ]);
      expect(results[0].privateKey, isNot(results[1].privateKey));
      // Both survived the concurrent read-modify-write of the shared record.
      expect((await store.loadExisting('scope-a'))!.privateKey,
          results[0].privateKey);
      expect((await store.loadExisting('scope-b'))!.privateKey,
          results[1].privateKey);
    });

    test('loadExisting never creates an identity', () async {
      final record = _FakeSecureRecord();
      final store = _storeOn(record);
      expect(await store.loadExisting('scope-a'), isNull);
      expect(record.writes, 0);
      expect(record.value, isNull);
    });

    test('a store that cannot be read rotates nothing and writes nothing',
        () async {
      final record = _FakeSecureRecord();
      final store = _storeOn(record);
      final original = await store.loadOrCreate('scope-a');
      final writes = record.writes;
      record.failReads = true;
      await expectLater(store.loadOrCreate('scope-a'), throwsStateError);
      await expectLater(store.loadExisting('scope-a'), throwsStateError);
      expect(record.writes, writes);
      record.failReads = false;
      expect((await store.loadExisting('scope-a'))!.privateKey,
          original.privateKey);
    });

    test('a corrupted entry is replaced by a fresh, valid identity', () async {
      final record = _FakeSecureRecord()
        ..value = jsonEncode(<String, dynamic>{
          'format': kWinn3KeyPairFormat,
          'accounts': <String, dynamic>{
            'scope-a': <String, String>{
              'private_key': _key(0x11),
              'public_key': _key(0x22), // not derived from the private key
            },
          },
        });
      final store = _storeOn(record);
      expect(await store.loadExisting('scope-a'), isNull);
      final fresh = await store.loadOrCreate('scope-a');
      expect(await fresh.isValid(), isTrue);
      expect(fresh.privateKey, isNot(_key(0x11)));
    });

    test('a document of an unknown format is never trusted', () async {
      final pair = await Winn3DeviceKeyPair.generate();
      final record = _FakeSecureRecord()
        ..value = jsonEncode(<String, dynamic>{
          'format': 'wireguard-x25519-v3',
          'accounts': <String, dynamic>{
            'scope-a': <String, String>{
              'private_key': pair.privateKey,
              'public_key': pair.publicKey,
            },
          },
        });
      final store = _storeOn(record);
      expect(await store.loadExisting('scope-a'), isNull);
      expect((await store.loadOrCreate('scope-a')).privateKey,
          isNot(pair.privateKey));
    });

    test('a write that does not persist fails read-back', () async {
      final record = _FakeSecureRecord()..dropWrites = true;
      final store = _storeOn(record);
      await expectLater(store.loadOrCreate('scope-a'), throwsStateError);
      final candidate = await store.stageCandidate();
      await expectLater(store.commit('scope-a', candidate), throwsStateError);
    });

    test('an empty account scope is refused', () async {
      final store = _storeOn(_FakeSecureRecord());
      await expectLater(store.loadOrCreate(' '), throwsStateError);
    });
  });

  group('rotation', () {
    test('a staged candidate is not stored until it is committed', () async {
      final record = _FakeSecureRecord();
      final store = _storeOn(record);
      final original = await store.loadOrCreate('scope-a');
      final candidate = await store.stageCandidate();
      expect(await candidate.isValid(), isTrue);
      expect(candidate.privateKey, isNot(original.privateKey));
      expect((await store.loadExisting('scope-a'))!.privateKey,
          original.privateKey);
      await store.commit('scope-a', candidate);
      final now = await store.loadExisting('scope-a');
      expect(now!.privateKey, candidate.privateKey);
      expect(now.publicKey, candidate.publicKey);
    });

    test('commit refuses a candidate whose halves do not match', () async {
      final store = _storeOn(_FakeSecureRecord());
      final a = await store.stageCandidate();
      final b = await store.stageCandidate();
      await expectLater(
          store.commit(
              'scope-a',
              Winn3DeviceKeyPair(
                  privateKey: a.privateKey, publicKey: b.publicKey)),
          throwsStateError);
    });

    test('migration: a device with no local pair gets a new one', () async {
      // An upgraded install that ran on a hub-minted key has nothing in the
      // v3 record; its first /verify on this build must carry a fresh public
      // key so the hub adopts it and retires the hub-minted identity.
      final record = _FakeSecureRecord();
      final store = _storeOn(record);
      final pair = await store.loadOrCreate('scope-a');
      final fields = winn3ClientKeyRequestFields(
        clientKeys: clientKeysWithWinn3(<String, String>{}, pair),
        hostCarriesWinn3: true,
      );
      expect(fields[kWinn3StaticPublicField], pair.publicKey);
    });

    test('delete retires the scope, and the record goes with the last one',
        () async {
      final record = _FakeSecureRecord();
      final store = _storeOn(record);
      await store.loadOrCreate('scope-a');
      final b = await store.loadOrCreate('scope-b');
      expect(await store.delete('scope-a'), isTrue);
      expect(await store.loadExisting('scope-a'), isNull);
      expect((await store.loadExisting('scope-b'))!.privateKey, b.privateKey);
      expect(await store.delete('scope-b'), isTrue);
      expect(record.value, isNull);
      expect(record.deletes, 1);
      // A new account on the same install starts from a new identity.
      final c = await store.loadOrCreate('scope-b');
      expect(c.privateKey, isNot(b.privateKey));
    });

    test('a collision refusal is answered with a fresh, stored pair', () async {
      final record = _FakeSecureRecord();
      final store = _storeOn(record);
      final before = await store.loadOrCreate('scope-a');
      final fresh = await store.replaceWithFresh('scope-a');
      expect(fresh.privateKey, isNot(before.privateKey));
      expect((await store.loadExisting('scope-a'))!.publicKey, fresh.publicKey);
    });

    test('delete of an absent scope succeeds', () async {
      final store = _storeOn(_FakeSecureRecord());
      expect(await store.delete('scope-a'), isTrue);
    });
  });

  group('what goes on the wire', () {
    late Winn3DeviceKeyPair pair;
    late Map<String, String> clientKeys;
    setUp(() async {
      pair = await Winn3DeviceKeyPair.generate();
      clientKeys = clientKeysWithWinn3(<String, String>{
        'private_key': _key(0x31),
        'public_key': _key(0x32),
      }, pair);
    });

    test('only the public half is sent, with the capability flag', () {
      final fields = winn3ClientKeyRequestFields(
          clientKeys: clientKeys, hostCarriesWinn3: true);
      expect(fields, <String, dynamic>{
        'winn3_static_public': pair.publicKey,
        'supports_winn3_client_key': true,
      });
      final encoded = jsonEncode(fields);
      expect(encoded, isNot(contains(pair.privateKey)));
      expect(encoded, isNot(contains('private')));
    });

    test('a host that cannot carry winn/3 sends no key and no claim', () {
      final fields = winn3ClientKeyRequestFields(
          clientKeys: clientKeys, hostCarriesWinn3: false);
      expect(fields, <String, dynamic>{'supports_winn3_client_key': false});
    });

    test('a key that could not be loaded is not replaced by a hub-minted one',
        () {
      // api_contract.md v1: with supports_winn3_client_key true and no public
      // key the hub mints NOTHING. Claiming false here would invite the hub
      // to mint and store a private key this build refuses anyway.
      final fields = winn3ClientKeyRequestFields(
          clientKeys: <String, String>{'public_key': _key(0x32)},
          hostCarriesWinn3: true);
      expect(fields, <String, dynamic>{'supports_winn3_client_key': true});
    });

    test('OI-KEYSAPP-7: a late 409 for account A never rotates account B',
        () async {
      final record = _FakeSecureRecord();
      final store = _storeOn(record);
      final ledger = Winn3KeyCollisionLedger();
      final a = await winn3KeyPairResolvingCollision(store, 'scope-a', ledger);
      // The user switches to account B; A's request is still in flight.
      final b = await winn3KeyPairResolvingCollision(store, 'scope-b', ledger);
      final bodyA = jsonEncode(<String, dynamic>{
        'winn3_static_public': a.publicKey,
        'supports_winn3_client_key': true,
      });
      // A's refusal arrives late.
      expect(
          ledger.note(
              409,
              <String, String>{
                'X-Wins-Error-Code': kWinn3StaticPublicInUseCode
              },
              bodyA),
          isTrue);
      final bAgain =
          await winn3KeyPairResolvingCollision(store, 'scope-b', ledger);
      expect(bAgain.privateKey, b.privateKey, reason: "B's key must stay");
      expect(bAgain.publicKey, b.publicKey);
      // A's own next request rotates A, once.
      final aNext =
          await winn3KeyPairResolvingCollision(store, 'scope-a', ledger);
      expect(aNext.publicKey, isNot(a.publicKey));
      final aAfter =
          await winn3KeyPairResolvingCollision(store, 'scope-a', ledger);
      expect(aAfter.publicKey, aNext.publicKey, reason: 'rotates only once');
      // A duplicate late copy of the same refusal is inert now.
      ledger.note(
          409,
          <String, String>{'x-wins-error-code': kWinn3StaticPublicInUseCode},
          bodyA);
      expect(
          (await winn3KeyPairResolvingCollision(store, 'scope-a', ledger))
              .publicKey,
          aNext.publicKey);
    });

    test('a refusal names its key or it is ignored', () {
      final ledger = Winn3KeyCollisionLedger();
      final headers = <String, String>{
        'x-wins-error-code': kWinn3StaticPublicInUseCode
      };
      expect(ledger.note(409, headers, null), isFalse);
      expect(ledger.note(409, headers, 'not json'), isFalse);
      expect(
          ledger.note(409, headers, jsonEncode(<String, dynamic>{})), isFalse);
      expect(
          ledger.note(400, headers,
              jsonEncode(<String, dynamic>{'winn3_static_public': _key(0x44)})),
          isFalse);
      expect(
          ledger.note(409, headers,
              jsonEncode(<String, dynamic>{'winn3_static_public': _key(0x44)})),
          isTrue);
      expect(ledger.refuses(_key(0x44)), isTrue);
      expect(ledger.refuses(_key(0x45)), isFalse);
    });

    test('concurrent requests on one refusal rotate once', () async {
      final store = _storeOn(_FakeSecureRecord());
      final ledger = Winn3KeyCollisionLedger();
      final a = await store.loadOrCreate('scope-a');
      ledger.note(
          409,
          <String, String>{'x-wins-error-code': kWinn3StaticPublicInUseCode},
          jsonEncode(<String, dynamic>{'winn3_static_public': a.publicKey}));
      final both = await Future.wait(<Future<Winn3DeviceKeyPair>>[
        store.replaceIfStill('scope-a', a.publicKey),
        store.replaceIfStill('scope-a', a.publicKey),
      ]);
      expect(both[0].publicKey, both[1].publicKey);
      expect(both[0].publicKey, isNot(a.publicKey));
      expect(
          (await store.loadExisting('scope-a'))!.publicKey, both[0].publicKey);
    });

    test('the hub collision refusal is recognised by its stable code only', () {
      expect(
          isWinn3StaticPublicInUse(409, <String, String>{
            'X-Wins-Error-Code': 'winn3_static_public_in_use'
          }),
          isTrue);
      expect(
          isWinn3StaticPublicInUse(409, <String, String>{
            'x-wins-error-code': ' WINN3_STATIC_PUBLIC_IN_USE '
          }),
          isTrue);
      expect(
          isWinn3StaticPublicInUse(400, <String, String>{
            'x-wins-error-code': 'winn3_static_public_in_use'
          }),
          isFalse);
      expect(
          isWinn3StaticPublicInUse(
              409, <String, String>{'x-wins-error-code': 'identity_collision'}),
          isFalse);
      expect(isWinn3StaticPublicInUse(409, <String, String>{}), isFalse);
    });

    test('merging the v3 pair leaves the AWG entries untouched', () {
      expect(clientKeys['private_key'], _key(0x31));
      expect(clientKeys['public_key'], _key(0x32));
      expect(Winn3DeviceKeyPair.fromClientKeys(clientKeys)!.privateKey,
          pair.privateKey);
      final stripped = clientKeysWithWinn3(clientKeys, null);
      expect(Winn3DeviceKeyPair.fromClientKeys(stripped), isNull);
      expect(stripped['private_key'], _key(0x31));
    });

    test(
        'every /verify body in main.dart carries the v3 fields, never the '
        'private key', () {
      final source = File('lib/main.dart').readAsStringSync();
      final spreads = RegExp(r'\.\.\.winn3ClientKeyRequestFields\(')
          .allMatches(source)
          .length;
      expect(spreads, 3, reason: 'paid activation, free payload, paid refresh');
      final bodies = <String>[
        _between(
            source, 'final String requestBodyPayload = jsonEncode({', '});'),
        _between(source, 'Map<String, dynamic> _freeAccessPayload(', '};'),
        _between(
            source,
            'final Map<String, dynamic> paidPayload = <String, dynamic>{',
            '};'),
      ];
      for (final body in bodies) {
        expect(body, contains('winn3ClientKeyRequestFields('));
        expect(body, isNot(contains(kWinn3ClientKeysPrivateEntry)));
        expect(body, isNot(contains('winn3_static_private')));
      }
    });
  });

  group('what is accepted from the hub', () {
    late Winn3DeviceKeyPair local;
    setUp(() async {
      local = await Winn3DeviceKeyPair.generate();
    });

    test('a matching echo with no served private key is accepted', () {
      expect(
          winn3ServedKeyRejection(
            servedConfig: <String, dynamic>{
              'winn3_static_public': local.publicKey,
              'winn3_static_private': '',
            },
            localWinn3StaticPublic: local.publicKey,
          ),
          isNull);
    });

    test('a foreign echo is refused in either spelling', () {
      for (final key in kWinn3StaticPublicAliases) {
        expect(
            winn3ServedKeyRejection(
              servedConfig: <String, dynamic>{key: _key(0x44)},
              localWinn3StaticPublic: local.publicKey,
            ),
            kWinn3KeyMismatchRejection,
            reason: key);
      }
    });

    test('a served private key beside an echo of the local key is refused', () {
      for (final key in kWinn3StaticPrivateAliases) {
        for (final echo in kWinn3StaticPublicAliases) {
          expect(
              winn3ServedKeyRejection(
                servedConfig: <String, dynamic>{
                  echo: local.publicKey,
                  key: _key(0x55),
                },
                localWinn3StaticPublic: local.publicKey,
              ),
              kWinn3ServedPrivateKeyRejection,
              reason: '$key with $echo');
        }
      }
    });

    test('transition: a served private key with no echo is accepted', () {
      // Arbiter ruling on OI-KEYSAPP-1: a hub not yet upgraded keeps v3
      // working; the key is for that session only (see the tunnel group).
      for (final key in kWinn3StaticPrivateAliases) {
        expect(
            winn3ServedKeyRejection(
              servedConfig: <String, dynamic>{key: _key(0x55)},
              localWinn3StaticPublic: local.publicKey,
            ),
            isNull,
            reason: key);
      }
    });

    test('a request that carried no v3 key is not judged on v3 fields', () {
      expect(
          winn3ServedKeyRejection(
            servedConfig: <String, dynamic>{
              'winn3_static_public': _key(0x44),
              'winn3_static_private': _key(0x55),
            },
            localWinn3StaticPublic: '',
          ),
          isNull);
    });

    test('Sol N-1: the raw binding helper refuses before attachment', () {
      // Sol's concrete case: an echo of the local v3 public plus a served
      // private. Attachment would overwrite the private with the local one,
      // so only the RAW served map can show the conflict.
      final served = <String, dynamic>{
        'client_public_key': _key(0x21),
        'winn3_static_public': local.publicKey,
        'winn3_static_private': _key(0x55),
      };
      expect(
          hubVerifyKeyBindingRejection(
            servedConfig: served,
            localClientPublicKey: _key(0x21),
            localWinn3StaticPublic: local.publicKey,
          ),
          kWinn3ServedPrivateKeyRejection);
      expect(attachLocalWinn3StaticKey(served, local)['winn3_static_private'],
          local.privateKey,
          reason: 'why the check must run on the raw map');
      expect(
          hubVerifyKeyBindingRejection(
            servedConfig: <String, dynamic>{'clientpublickey': _key(0x66)},
            localClientPublicKey: _key(0x21),
            localWinn3StaticPublic: local.publicKey,
          ),
          'client_key_mismatch');
      expect(
          hubVerifyKeyBindingRejection(
            servedConfig: <String, dynamic>{'winn3_static_public': _key(0x44)},
            localClientPublicKey: _key(0x21),
            localWinn3StaticPublic: local.publicKey,
          ),
          kWinn3KeyMismatchRejection);
      expect(
          hubVerifyKeyBindingRejection(
            servedConfig: <String, dynamic>{
              'client_public_key': _key(0x21),
              'winn3_static_public': local.publicKey,
            },
            localClientPublicKey: _key(0x21),
            localWinn3StaticPublic: local.publicKey,
          ),
          isNull);
    });

    test('hubVerifyCandidateRejection applies the v3 binding', () async {
      final awgPublic = _key(0x21);
      final normalized = <String, dynamic>{
        'client_private_key': _key(0x11),
        'client_public_key': awgPublic,
        'server_public_key': _key(0x31),
        'client_ip': '10.8.1.3',
        'dns': '10.8.1.1',
        'server_endpoint': '203.0.113.7:51820',
        'mtu': 1280,
        'node_slug': 'lab-alpha',
      };
      Future<String?> reject(Map<String, dynamic> served) =>
          hubVerifyCandidateRejection(
            responseData: <String, dynamic>{
              'status': 'authenticated',
              'selected_node': 'lab-alpha',
            },
            servedConfig: <String, dynamic>{...normalized, ...served},
            normalizedConfig: normalized,
            localClientPublicKey: awgPublic,
            localWinn3StaticPublic: local.publicKey,
            requirements: const HubVerifyRequirements(
              exactTarget: 'lab-alpha',
              doubleVpnRequired: false,
            ),
          );
      expect(
          await reject(<String, dynamic>{
            'winn3_static_public': local.publicKey,
          }),
          isNull);
      expect(await reject(<String, dynamic>{}), isNull,
          reason: 'no echo and no private key: an unmodified hub serving v1');
      expect(await reject(<String, dynamic>{'winn3staticpublic': _key(0x44)}),
          kWinn3KeyMismatchRejection);
      expect(
          await reject(<String, dynamic>{
            'winn3_static_public': local.publicKey,
            'winn3_static_private': _key(0x55),
          }),
          kWinn3ServedPrivateKeyRejection);
      expect(
          await reject(<String, dynamic>{'winn3_static_private': _key(0x55)}),
          isNull,
          reason: 'transition: no echo, served key accepted for the session');
      // The AWG binding still comes first.
      expect(
          await reject(<String, dynamic>{
            'client_public_key': _key(0x66),
            'winn3_static_private': _key(0x55),
          }),
          'client_key_mismatch');
    });
  });

  group('what the tunnel is handed', () {
    late Winn3DeviceKeyPair local;
    setUp(() async {
      local = await Winn3DeviceKeyPair.generate();
    });

    test('the local private key is attached once the hub echoes its public',
        () {
      final attached = attachLocalWinn3StaticKey(<String, dynamic>{
        'winn3_inner_v4': '10.10.4.9',
        'winn3_static_public': local.publicKey,
      }, local);
      expect(attached['winn3_static_private'], local.privateKey);
    });

    test('the local key wins once echoed; a served one is discarded', () {
      for (final key in kWinn3StaticPrivateAliases) {
        final attached = attachLocalWinn3StaticKey(<String, dynamic>{
          key: _key(0x55),
          'winn3_static_public': local.publicKey,
          // A marker arriving from anywhere is never trusted.
          kWinn3StaticPrivateOriginField: kWinn3StaticPrivateOriginHubSession,
        }, local);
        expect(attached['winn3_static_private'], local.privateKey);
        expect(attached.containsKey('winn3staticprivate'), isFalse);
        expect(carriesHubSessionWinn3Key(attached), isFalse);
      }
    });

    test(
        'transition: a served key with no echo is used, marked for the session',
        () {
      for (final key in kWinn3StaticPrivateAliases) {
        for (final device in <Winn3DeviceKeyPair?>[local, null]) {
          final attached = attachLocalWinn3StaticKey(
              <String, dynamic>{key: _key(0x55)}, device);
          expect(attached['winn3_static_private'], _key(0x55),
              reason: '$key, local ${device != null}');
          expect(carriesHubSessionWinn3Key(attached), isTrue);
          expect(attached.containsKey('winn3staticprivate'), isFalse);
        }
      }
      // A legacy hub that echoes ITS OWN public beside the private it minted
      // (no local key this time) is the same transition case.
      final legacy = attachLocalWinn3StaticKey(<String, dynamic>{
        'winn3_static_public': _key(0x44),
        'winn3_static_private': _key(0x55),
      }, null);
      expect(legacy['winn3_static_private'], _key(0x55));
      expect(carriesHubSessionWinn3Key(legacy), isTrue);
    });

    test('a foreign echo while a local key exists attaches nothing', () {
      final attached = attachLocalWinn3StaticKey(<String, dynamic>{
        'winn3_static_public': _key(0x44),
        'winn3_static_private': _key(0x55),
      }, local);
      expect(attached.containsKey('winn3_static_private'), isFalse);
      expect(carriesHubSessionWinn3Key(attached), isFalse);
    });

    test('no echo and no served key attaches nothing', () {
      expect(
          attachLocalWinn3StaticKey(<String, dynamic>{}, local)
              .containsKey('winn3_static_private'),
          isFalse);
      expect(
          attachLocalWinn3StaticKey(
                  <String, dynamic>{'winn3_static_public': _key(0x44)}, local)
              .containsKey('winn3_static_private'),
          isFalse);
    });

    test('attaching is idempotent', () {
      for (final input in <Map<String, dynamic>>[
        <String, dynamic>{
          'winn3_static_public': local.publicKey,
          'winn3_static_private': _key(0x55),
        },
        <String, dynamic>{'winn3_static_private': _key(0x55)},
      ]) {
        final once = attachLocalWinn3StaticKey(input, local);
        final twice = attachLocalWinn3StaticKey(once, local);
        expect(twice, once);
      }
    });

    test('a session key is never persisted and is dropped at session end', () {
      final session = attachLocalWinn3StaticKey(<String, dynamic>{
        'winn3_inner_v4': '10.10.4.9',
        'winn3_static_private': _key(0x55),
      }, local);
      final locals = <String>{local.privateKey};
      final persisted = withoutForeignWinn3StaticPrivate(session, locals);
      expect(persisted.containsKey('winn3_static_private'), isFalse);
      expect(persisted.containsKey(kWinn3StaticPrivateOriginField), isFalse);
      expect(persisted['winn3_inner_v4'], '10.10.4.9');
      expect(jsonEncode(persisted), isNot(contains(_key(0x55))));
      // The local key survives persistence untouched, as the same object.
      final adopted = attachLocalWinn3StaticKey(<String, dynamic>{
        'winn3_static_public': local.publicKey,
      }, local);
      expect(
          identical(withoutForeignWinn3StaticPrivate(adopted, locals), adopted),
          isTrue);
      // A config with no v3 key is returned as is.
      final plain = <String, dynamic>{'winn3_inner_v4': '10.10.4.9'};
      expect(identical(withoutForeignWinn3StaticPrivate(plain, locals), plain),
          isTrue);
    });

    test('Seat C A-1: a rebuild that drops the marker cannot leak the key', () {
      final session = attachLocalWinn3StaticKey(<String, dynamic>{
        'winn3_inner_v4': '10.10.4.9',
        'winn3_static_private': _key(0x55),
      }, local);
      // The closed-list re-normalization _configForTransport performs.
      final rebuilt =
          applyWinn3ServedFields(dest: <String, dynamic>{}, raw: session);
      expect(rebuilt['winn3_static_private'], _key(0x55));
      expect(carriesHubSessionWinn3Key(rebuilt), isFalse);
      // Persistence and the stop-time drop decide by value, not by marker.
      final stripped =
          withoutForeignWinn3StaticPrivate(rebuilt, <String>{local.privateKey});
      expect(jsonEncode(stripped), isNot(contains(_key(0x55))));
      // With no local key known at all, every v3 private key is stripped.
      expect(jsonEncode(withoutForeignWinn3StaticPrivate(rebuilt, <String>{})),
          isNot(contains(_key(0x55))));
      // And the fresh session still needs no second /verify.
      expect(winn3ConfigKeyUsable(rebuilt, local, freshFromHub: true), isTrue);
    });

    test('a standalone config without its key refreshes unless fresh', () {
      final standalone = <String, dynamic>{
        'protocol_version': kWinnProtocolV3,
        'protocol_params': <String, dynamic>{'carrier': kWinnCarrierWinn3},
        'winn3_inner_v4': '10.10.4.9',
      };
      expect(
          winn3ConfigKeyUsable(standalone, local, freshFromHub: false), isFalse,
          reason: 'its session key was dropped; ask the hub again');
      expect(
          winn3ConfigKeyUsable(standalone, local, freshFromHub: true), isTrue,
          reason: 'fresh: the start path refuses by name (OI-KEYSAPP-2)');
      expect(
          winn3ConfigKeyUsable(
              <String, dynamic>{'winn3_inner_v4': '10.10.4.9'}, local,
              freshFromHub: false),
          isTrue,
          reason: 'not standalone v3: nothing to refresh for');
    });

    test('a session key never reaches the device key store', () async {
      final record = _FakeSecureRecord();
      final store = _storeOn(record);
      final committed = await store.loadOrCreate('scope-a');
      final before = record.value;
      final session = attachLocalWinn3StaticKey(
          <String, dynamic>{'winn3_static_private': _key(0x55)}, committed);
      expect(session['winn3_static_private'], _key(0x55));
      expect(record.value, before);
      expect(record.value, isNot(contains(_key(0x55))));
      expect((await store.loadExisting('scope-a'))!.privateKey,
          committed.privateKey);
    });

    test('a session key is usable only by the session that fetched it', () {
      final session = attachLocalWinn3StaticKey(
          <String, dynamic>{'winn3_static_private': _key(0x55)}, local);
      expect(winn3ConfigKeyUsable(session, local, freshFromHub: true), isTrue);
      expect(winn3ConfigKeyUsable(session, null, freshFromHub: true), isTrue);
      expect(winn3ConfigKeyUsable(session, local, freshFromHub: false), isFalse,
          reason: 'a cached session key is never reused');
      // Conflict with a local key the hub already echoes.
      final conflicting = <String, dynamic>{
        ...session,
        'winn3_static_public': local.publicKey,
      };
      expect(winn3ConfigKeyUsable(conflicting, local, freshFromHub: true),
          isFalse);
    });

    test('a foreign key is usable only fresh, marked or not', () {
      // Decided by value: a non-local key is a hub-served session key. A
      // cached one (for example what an older build persisted) is never
      // reused; one fetched for this session is.
      for (final fresh in <bool>[true, false]) {
        expect(
            winn3ConfigKeyUsable(<String, dynamic>{}, null,
                freshFromHub: fresh),
            isTrue);
        expect(
            winn3ConfigKeyUsable(<String, dynamic>{}, local,
                freshFromHub: fresh),
            isTrue);
        expect(
            winn3ConfigKeyUsable(<String, dynamic>{
              'winn3_static_private': local.privateKey
            }, local, freshFromHub: fresh),
            isTrue);
        expect(
            winn3ConfigKeyUsable(
                <String, dynamic>{'winn3_static_private': _key(0x55)}, local,
                freshFromHub: fresh),
            fresh);
        expect(
            winn3ConfigKeyUsable(
                <String, dynamic>{'winn3staticprivate': _key(0x55)}, null,
                freshFromHub: fresh),
            fresh);
      }
    });

    test('normalization never copies a hub-sent origin marker', () {
      final dest = applyWinn3ServedFields(
        dest: <String, dynamic>{},
        raw: <String, dynamic>{
          kWinn3StaticPrivateOriginField: kWinn3StaticPrivateOriginHubSession,
        },
      );
      expect(dest.containsKey(kWinn3StaticPrivateOriginField), isFalse);
    });

    test('normalization keeps the echo in both spellings', () {
      for (final key in kWinn3StaticPublicAliases) {
        final dest = applyWinn3ServedFields(
          dest: <String, dynamic>{},
          raw: <String, dynamic>{key: local.publicKey},
        );
        expect(dest['winn3_static_public'], local.publicKey, reason: key);
      }
    });

    test('the attached key reaches the [winn] static_private line', () async {
      // End to end through the real start resolver: served config with the
      // hub echo and no private key -> local key attached -> INI.
      final ring = await _TestRing.create();
      final served = await ring.standaloneServedConfig(echo: local.publicKey);
      final normalized = attachLocalWinn3StaticKey(
        applyWinn3ServedFields(
            dest: Map<String, dynamic>.from(served), raw: served),
        local,
      );
      final check = await verifyWinn3Descriptor(
          config: normalized, ring: ring.ring, now: ring.insideLifetime);
      expect(check.verified, isTrue, reason: check.reason);
      final decision = resolveWinnProtocolStartForServedConfig(
          config: normalized, winn3Descriptor: check);
      expect(decision.supported, isTrue,
          reason: '${decision.reason.code}: ${decision.message}');
      expect(decision.iniSection,
          contains('static_private = ${local.privateKey}'));

      // Transition: an un-upgraded hub serves its own private and no echo.
      // That session runs on the served key.
      final legacy = await ring.standaloneServedConfig(
          echo: '', servedPrivate: _key(0x55));
      final legacyNormalized = attachLocalWinn3StaticKey(
        applyWinn3ServedFields(
            dest: Map<String, dynamic>.from(legacy), raw: legacy),
        local,
      );
      final legacyDecision = resolveWinnProtocolStartForServedConfig(
          config: legacyNormalized, winn3Descriptor: check);
      expect(legacyDecision.supported, isTrue,
          reason: '${legacyDecision.reason.code}: ${legacyDecision.message}');
      expect(legacyDecision.iniSection,
          contains('static_private = ${_key(0x55)}'));

      // No echo and no served private: refuses by name instead of starting
      // on a key the gateway does not hold.
      final unadopted = await ring.standaloneServedConfig(echo: '');
      final unadoptedNormalized = attachLocalWinn3StaticKey(
        applyWinn3ServedFields(
            dest: Map<String, dynamic>.from(unadopted), raw: unadopted),
        local,
      );
      final refusal = resolveWinnProtocolStartForServedConfig(
          config: unadoptedNormalized, winn3Descriptor: check);
      expect(refusal.reason, WinnRefusalReason.winn3DeviceMaterialMissing);
    });
  });

  group('main.dart wiring', () {
    final source = File('lib/main.dart').readAsStringSync();

    test('the v3 record is a sensitive state file on every native store', () {
      final names = _between(
          source,
          'static const Set<String> _sensitiveStateFileNames = <String>{',
          '};');
      expect(names, contains("'winn3_keypair.json'"));
      expect(kWinn3KeyPairFileName, 'winn3_keypair.json');
      // Each native allowlist itself, not merely somewhere in the file.
      final allowlists = <String, List<String>>{
        'apple/WinsTunnelCore/WinsSecureStateStore.swift': <String>[
          'private static let allowedNames: Set<String> = [',
          ']',
        ],
        'android/app/src/main/kotlin/org/winsvpn/app/SecureFileStore.kt':
            <String>['private val allowedNames = setOf(', '\n        )'],
        'linux/runner/linux_secure_store.cc': <String>[
          'bool IsAllowedLinuxSecureTextName(const std::string& name) {',
          '};',
        ],
        'windows/runner/windows_tunnel_backend.cpp': <String>[
          'bool IsAllowedSecureTextName(const std::string& name) {',
          '};',
        ],
      };
      allowlists.forEach((path, bounds) {
        final list =
            _between(File(path).readAsStringSync(), bounds[0], bounds[1]);
        expect(list, contains('"winn3_keypair.json"'), reason: path);
      });
      // Android also needs a neutral on-disk name for the record.
      expect(
          File('android/app/src/main/kotlin/org/winsvpn/app/SecureFileStore.kt')
              .readAsStringSync(),
          contains('"winn3_keypair.json" to "memory.dat"'));
    });

    test('only a host that can carry winn/3 generates or sends a v3 key', () {
      expect(
          source,
          contains('bool get _winn3ClientKeyHost => '
              "_winnCapabilityFlags['supports_winn3'] == true;"));
      final forRequest = _between(
          source,
          'Future<Winn3DeviceKeyPair?> _winn3KeyPairForRequest(',
          'Future<Winn3DeviceKeyPair?> _stageWinn3KeyPairCandidate()');
      expect(forRequest, contains('if (!_winn3ClientKeyHost) return null;'));
    });

    test('the store reads and writes only through the secure state store', () {
      final store = _between(
          source,
          'late final Winn3DeviceKeyStore _winn3KeyStore = Winn3DeviceKeyStore(',
          ');');
      expect(store, contains('_readSensitiveText(kWinn3KeyPairFileName)'));
      expect(store, contains('_writeSensitiveText(kWinn3KeyPairFileName'));
      expect(store, contains('_deleteSensitiveText(kWinn3KeyPairFileName)'));
    });

    test('the attach step and the verify window apply the v3 binding', () {
      final attach = _between(
          source,
          'Map<String, dynamic> _attachLocalClientKeys(',
          'bool _configMatchesLocalClientKeys(');
      expect(attach, contains('attachLocalWinn3StaticKey('));
      final rejection = _between(source, 'Future<String?> _hubVerifyRejection(',
          'String? _hubKeyBindingRejection(');
      expect(
          rejection,
          contains(
              'localWinn3StaticPublic: clientKeys[kWinn3ClientKeysPublicEntry]'));
    });

    test('logout and duress retire the v3 identity', () {
      final cleanup = _between(
          source, "case 'client_keys':", 'return Future<bool>.value(false);');
      expect(cleanup, contains('_deleteWinn3KeyPairForScopeToken(scopeToken)'));
      expect(cleanup, contains('awgDeleted && winn3Deleted'));
      final duress = _between(
          source,
          'Future<void> _wipeIncriminatingStateForDuress(',
          'Future<void> _sweepAppStorageForDuress(');
      expect(duress, contains("'winn3_keypair.json'"));
    });

    test('setup-key enrollment stages and commits a new v3 identity', () {
      expect(source, contains('await _stageWinn3KeyPairCandidate()'));
      expect(
          source,
          contains(
              '_commitWinn3KeyPairCandidate(\n                        rawToken, winn3Candidate)'));
    });

    test('every /verify response is checked for the collision refusal', () {
      expect(
          RegExp(r'_noteWinn3KeyCollision\(response, verifyRequest\.body\);')
              .allMatches(source)
              .length,
          4,
          reason:
              'free window, Double VPN race, paid activation, paid refresh');
      final forRequest = _between(
          source,
          'Future<Winn3DeviceKeyPair?> _winn3KeyPairForRequest(',
          'Future<Winn3DeviceKeyPair?> _stageWinn3KeyPairCandidate()');
      expect(forRequest, contains('winn3KeyPairResolvingCollision('));
      expect(forRequest, contains('_winn3KeyCollisions,'));
      final note = _between(
          source,
          'void _noteWinn3KeyCollision(http.Response response, String? requestBody) {',
          'bool get _winn3ClientKeyHost');
      expect(
          _normalize(note),
          contains('_winn3KeyCollisions.note( response.statusCode, '
              'response.headers, requestBody)'));
      expect(source, isNot(contains('_winn3KeyCollisionObserved')),
          reason: 'no account-blind collision flag');
    });

    int at(String haystack, String needle) {
      final index = haystack.indexOf(needle);
      expect(index, greaterThanOrEqualTo(0), reason: 'missing: $needle');
      return index;
    }

    test('Sol N-1, paid activation: binding checked before any commit', () {
      final activation = _between(
          source,
          'Future<void> _loginWithAccountNumber() async {',
          'Map<String, dynamic> _freeAccessPayload(');
      final check =
          at(activation, '_hubKeyBindingRejection(replyMap, clientKeys)');
      expect(
          check,
          lessThan(
              at(activation, 'await _commitClientKeyPairCandidate(rawToken')));
      expect(check, lessThan(at(activation, '_commitWinn3KeyPairCandidate(')));
      expect(check, lessThan(at(activation, 'await _onAuthSuccess(')));
      expect(
          _normalize(activation),
          contains('if (bindingRejection != null) { '
              "_debugLog('Pathfinder: reply through \$url rejected: ' "
              "'\$bindingRejection'); continue; }"));
    });

    test('Sol N-1, free Double VPN refresh: binding checked before use', () {
      final freeRefresh = _between(
          source,
          'Future<bool> _refreshFreeVpnConfig({',
          'Future<bool> _refreshVpnConfigForCurrentSelection(');
      final freeDouble = at(freeRefresh, '_postDoubleVpnAssignmentWithRetry(');
      final freeCheck = freeRefresh.indexOf(
          '_hubKeyBindingRejection(responseData, clientKeys)', freeDouble);
      expect(freeCheck, greaterThan(freeDouble));
      expect(freeCheck,
          lessThan(freeRefresh.indexOf('_postAuthenticatedBatchedFallback(')),
          reason: 'inside the Double VPN branch');
      expect(freeCheck, lessThan(at(freeRefresh, '_attachLocalClientKeys(')));
      expect(
          freeCheck, lessThan(at(freeRefresh, '_persistVpnConfigBestEffort(')));
      expect(
          _normalize(freeRefresh),
          contains('if (responseData != null && '
              '_hubKeyBindingRejection(responseData, clientKeys) != null) { '
              "_debugLog('Free Double VPN reply rejected: key binding.'); "
              'return false; }'));
    });

    test('Sol N-1, paid Double VPN refresh: binding checked before use', () {
      final paidRefresh = _between(
          source,
          'Future<bool> _refreshVpnConfigForCurrentSelection(',
          '_hubCancellations.release(paidCancellation);');
      final paidDouble = at(paidRefresh, '_postDoubleVpnAssignmentWithRetry(');
      final paidCheck = paidRefresh.indexOf(
          '_hubKeyBindingRejection(responseData, clientKeys)', paidDouble);
      expect(paidCheck, greaterThan(paidDouble));
      expect(paidCheck,
          lessThan(paidRefresh.indexOf('_attachLocalClientKeys(', paidDouble)));
      expect(
          paidCheck,
          lessThan(
              paidRefresh.indexOf('_persistVpnConfigBestEffort(', paidDouble)));
      expect(
          _normalize(paidRefresh),
          contains('if (_hubKeyBindingRejection(responseData, clientKeys) != '
              "null) { _debugLog('Paid Double VPN reply rejected: key binding.'); "
              'return false; }'));
    });

    test('Sol N-1, activation sink: _onAuthSuccess checks before writing', () {
      final auth = _between(source, 'Future<void> _onAuthSuccess(',
          'Future<bool> _refreshFreeVpnConfig({');
      final check = at(auth, '_hubKeyBindingRejection(data, clientKeys)');
      expect(check, lessThan(at(auth, 'await _resolveAnnouncement(data)')));
      expect(check, lessThan(at(auth, '_persistVpnConfigRequired(')));
      expect(
          _normalize(auth),
          contains('if (bindingRejection != null) { throw StateError('
              "'Hub reply key binding rejected: \$bindingRejection'); }"));
    });

    test('Sol N-1: the window paths keep the full check', () {
      expect(RegExp(r'_hubVerifyRejection\(').allMatches(source).length, 4,
          reason: 'definition, paid window, free activation, free refresh');
      final helper = _between(source, 'String? _hubKeyBindingRejection(',
          '/// [_resolveDynamicEndpoints] inside');
      expect(helper,
          contains("_mapValue(responseData, ['vpn_config', 'vpnconfig'])"));
      expect(
          helper,
          contains(
              'localWinn3StaticPublic: clientKeys[kWinn3ClientKeysPublicEntry]'));
    });

    test('Sol OI-KEYSAPP-13: the stop path clears the Apple session secret',
        () {
      final stop = _between(source, 'Future<bool> _cancelAndStopNativeTunnel({',
          'Future<bool> _settleWindowsTunnelStop(');
      expect(stop.indexOf('await _clearAppleWinnSessionSecret();'),
          greaterThan(stop.indexOf('await _stopNativeTunnel(')));
      for (final path in <String>[
        'ios/Runner/AppDelegate.swift',
        'macos/Runner/MainFlutterWindow.swift',
      ]) {
        final swift = File(path).readAsStringSync();
        expect(swift, contains('case "clearWinnSessionSecret":'), reason: path);
        final handler = _between(swift, 'private func clearWinnSessionSecret(',
            'private func loadOrCreateInstallId(');
        expect(
            handler,
            contains(
                'WinsTunnelSecretStore.clearWinnStaticPrivate(accountScope: scope, keeping: keep)'),
            reason: path);
        expect(handler, isNot(contains('WinsClientKeyStore')), reason: path);
        expect(handler, isNot(contains('WinsTunnelSecretStore.delete(')),
            reason: path);
      }
      final store = _between(
          File('apple/WinsTunnelCore/WinsTunnelConfig.swift')
              .readAsStringSync(),
          'static func clearWinnStaticPrivate(',
          'private static func load(account:');
      expect(store, contains('presharedKey: existing.presharedKey'));
      expect(store, contains('xrayUUID: existing.xrayUUID'));
      expect(store, contains('winnAdmissionKey: existing.winnAdmissionKey'));
      expect(store, contains('winnStaticPrivate: ""'));
      expect(
          store, contains('existing.winnStaticPrivate != keepStaticPrivate'));
      expect(store, isNot(contains('WinsClientKeyStore.delete')));
    });

    test('the connect path reuses no session key and no foreign key', () {
      expect(
          _normalize(source),
          contains('!winn3ConfigKeyUsable(directConfig, localWinn3, '
              'freshFromHub: directConfigFromFreshHub)'));
    });

    test('a session key is stripped before every config write', () {
      for (final start in <String>[
        'Future<void> _persistVpnConfigBestEffort(',
        'Future<void> _persistVpnConfigRequired(Map<String, dynamic> config) async {',
      ]) {
        final body = _between(source, start, 'Future<');
        expect(
            body, contains('jsonEncode(await _winn3PersistableConfig(config))'),
            reason: start);
        expect(body, isNot(contains('jsonEncode(config)')), reason: start);
      }
    });

    test('stopping the tunnel ends the session key', () {
      final stop = _between(source, 'Future<bool> _cancelAndStopNativeTunnel({',
          'Future<bool> _settleWindowsTunnelStop(');
      expect(stop, contains('_dropHubSessionWinn3Key();'));
      final drop = _between(source, 'void _dropHubSessionWinn3Key() {',
          'Future<bool> _deleteWinn3KeyPairForScopeToken(');
      expect(
          _normalize(drop),
          contains('_cachedVpnConfig = withoutForeignWinn3StaticPrivate( '
              '_cachedVpnConfig, _winn3KnownLocalPrivateKeys);'));
      final persistable = _between(
          source,
          'Future<Map<String, dynamic>> _winn3PersistableConfig(',
          'void _dropHubSessionWinn3Key() {');
      expect(
          _normalize(persistable),
          contains(
              'withoutForeignWinn3StaticPrivate( config, await _winn3LocalPrivateKeys())'));
      final transport = _between(source,
          'Map<String, dynamic> _configForTransport(', 'final xray = config');
      expect(transport, contains('config[kWinn3StaticPrivateOriginField] ='));
    });

    test('only freshly generated pairs are ever committed as the device key',
        () {
      expect(RegExp(r'_winn3KeyStore\.commit\(').allMatches(source).length, 1);
      final commit = _between(
          source,
          'Future<bool> _commitWinn3KeyPairCandidate(',
          'Future<Winn3DeviceKeyPair?> _loadExistingWinn3KeyPair(');
      expect(commit, contains('_winn3KeyStore.commit('));
      expect(
          RegExp(r'_commitWinn3KeyPairCandidate\(').allMatches(source).length,
          2,
          reason: 'definition plus the setup-key enrollment call');
      expect(source, contains('await _stageWinn3KeyPairCandidate()'));
      expect(
          source,
          isNot(contains(
              'commit(_clientKeyScopeToken(accountScope), Winn3DeviceKeyPair(')));
    });
  });
}

String _normalize(String source) => source.replaceAll(RegExp(r'\s+'), ' ');

String _between(String source, String start, String end) {
  final s = source.indexOf(start);
  expect(s, greaterThanOrEqualTo(0), reason: 'missing: $start');
  final e = source.indexOf(end, s + start.length);
  expect(e, greaterThan(s), reason: 'missing end after: $start');
  return source.substring(s, e);
}

/// A throwaway descriptor ring and a standalone served config signed by it,
/// shaped like `test/winn_protocol_dispatch_test.dart`'s standalone fixture.
class _TestRing {
  _TestRing._(this._signer, this.ring);

  final SimpleKeyPair _signer;
  final Winn3DescriptorKeyRing ring;
  final DateTime insideLifetime =
      DateTime.fromMillisecondsSinceEpoch(1786000100 * 1000, isUtc: true);

  static Future<_TestRing> create() async {
    final signer = await Ed25519().newKeyPair();
    final pub = await signer.extractPublicKey();
    return _TestRing._(
      signer,
      Winn3DescriptorKeyRing.fromEncoded(
          <String, String>{'g1': base64.encode(pub.bytes)}),
    );
  }

  Future<Map<String, dynamic>> standaloneServedConfig(
      {required String echo, String servedPrivate = ''}) async {
    final raw = utf8.encode(json.encode(<String, dynamic>{
      'v': kWinn3DescriptorFormatVersion,
      'alg': 'ed25519',
      'kid': 'g1',
      'node': 'lab-alpha',
      'endpoint': '203.0.113.7:51820',
      'inner_router_v4': '10.10.0.1',
      'inner_resolver_v4': '10.10.0.1',
      'static_pub': base64.encode(List<int>.filled(32, 0x53)),
      'gateway_id': base64.encode(utf8.encode('winsgw01')),
      'admission_secret': base64.encode(utf8.encode('ab' * 32)),
      'admission_gen': 1,
      'tag_size': 32,
      'padding': 'bucket',
      'bucket_window_s': 10,
      'max_skew_s': 60,
      'seq': 1,
      'iat': 1786000000,
      'not_after': 1786086400,
    }));
    final signature = await Ed25519().sign(
      <int>[...utf8.encode(kWinn3DescriptorDomain), 0x00, ...raw],
      keyPair: _signer,
    );
    return <String, dynamic>{
      'protocol_version': kWinnProtocolV3,
      'protocol_params': <String, dynamic>{'carrier': kWinnCarrierWinn3},
      'node_slug': 'lab-alpha',
      'server_endpoint': '203.0.113.7:51820',
      'client_ip': '10.8.1.3',
      'mtu': 1280,
      'dns': '10.8.1.1',
      'stealth_active': false,
      'obfuscation': <String, dynamic>{'H1': 11, 'H2': 22, 'H3': 33, 'H4': 44},
      'winn3_descriptor': <String, dynamic>{
        'payload': base64.encode(raw),
        'sig': base64.encode(signature.bytes),
      },
      'winn3_inner_v4': '10.10.4.9',
      // What an upgraded hub serves a client-key device: an empty private.
      'winn3_static_private': servedPrivate,
      if (echo.isNotEmpty) 'winn3_static_public': echo,
    };
  }
}
