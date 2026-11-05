import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/tunnel_display_identity.dart';

// Round UN, 2026-09-29 owner report: "Unknown node" instead of the connected
// server after the Calculator relock and PIN unlock, and after background and
// reopen. The committed-node record lived only in the Dart isolate, so a
// destroyed engine, a killed app or one flapping native reading lost it for
// good. These are the pure rules for the persisted record that replaces it;
// the production wiring runs verbatim in
// tunnel_display_restore_production_test.dart.
void main() {
  const scope = 'scope-account-a';
  const otherScope = 'scope-account-b';
  const appleGeneration = '6F9619FF-8B86-D011-B42D-00CF4FC964FF';
  const appleSession = 'apple-status:$appleGeneration';

  PersistedTunnelDisplayRecord record({
    String slug = 'uk-gb1',
    String? name = 'United Kingdom',
    String? flag = 'GB',
    String accountScope = scope,
    String nativeSession = appleSession,
  }) =>
      PersistedTunnelDisplayRecord(
        slug: slug,
        name: name,
        flag: flag,
        accountScope: accountScope,
        nativeSession: nativeSession,
      );

  // The app's own start hands the provider its config as transient start
  // options; a Settings or menu toggle restarts it from the shared config.
  Map<String, dynamic> appleReadiness({
    Object? available = true,
    Object? generation = appleGeneration,
    Object? configSource = 'transient_start_options',
  }) =>
      <String, dynamic>{
        'active': true,
        if (available != null) 'provider_status_available': available,
        if (generation != null) 'provider_status_generation': generation,
        if (configSource != null) 'provider_config_source': configSource,
      };

  Map<String, dynamic> androidReadiness({
    Object? lifecycle = 'connected',
    Object? token = 4242,
  }) =>
      <String, dynamic>{
        'active': true,
        if (lifecycle != null) 'winn3_lifecycle': lifecycle,
        if (token != null) 'winn3_start_token': token,
      };

  group('persisted record shape', () {
    test('round-trips exactly', () {
      final restored =
          PersistedTunnelDisplayRecord.fromJson(record().toJson());
      expect(restored, isNotNull);
      expect(restored!.slug, 'uk-gb1');
      expect(restored.name, 'United Kingdom');
      expect(restored.flag, 'GB');
      expect(restored.accountScope, scope);
      expect(restored.nativeSession, appleSession);
      expect(record().toJson()['schema'], PersistedTunnelDisplayRecord.schema);
    });

    test('optional identity metadata may be absent', () {
      final json = record(name: null, flag: null).toJson();
      expect(json.containsKey('name'), isFalse);
      expect(json.containsKey('flag'), isFalse);
      final restored = PersistedTunnelDisplayRecord.fromJson(json)!;
      expect(restored.name, isNull);
      expect(restored.flag, isNull);
    });

    test('blank name and flag read as absent, the slug is trimmed', () {
      final restored = PersistedTunnelDisplayRecord.fromJson(<String, Object>{
        ...record().toJson(),
        'slug': '  uk-gb1 ',
        'name': '  ',
        'flag': '',
      })!;
      expect(restored.slug, 'uk-gb1');
      expect(restored.name, isNull);
      expect(restored.flag, isNull);
    });

    test('any other shape is no record at all', () {
      final base = record().toJson();
      final rejected = <String, Object?>{
        'not a map': 'uk-gb1',
        'null': null,
        'other schema': <String, Object>{...base, 'schema': 2},
        'schema as string': <String, Object>{...base, 'schema': '1'},
        'no schema': Map<String, Object>.from(base)..remove('schema'),
        'no slug': Map<String, Object>.from(base)..remove('slug'),
        'blank slug': <String, Object>{...base, 'slug': '  '},
        'auto slug': <String, Object>{...base, 'slug': 'Auto'},
        'slug not a string': <String, Object>{...base, 'slug': 7},
        'name not a string': <String, Object>{...base, 'name': 7},
        'flag not a string': <String, Object>{...base, 'flag': 7},
        'no account scope': Map<String, Object>.from(base)
          ..remove('account_scope'),
        'blank account scope': <String, Object>{...base, 'account_scope': ' '},
        'account scope not a string': <String, Object>{
          ...base,
          'account_scope': 1,
        },
        'no native session': Map<String, Object>.from(base)
          ..remove('native_session'),
        'blank native session': <String, Object>{
          ...base,
          'native_session': '',
        },
        'native session not a string': <String, Object>{
          ...base,
          'native_session': 4242,
        },
      };
      rejected.forEach((reason, raw) {
        expect(PersistedTunnelDisplayRecord.fromJson(raw), isNull,
            reason: reason);
      });
    });
  });

  group('native session identity', () {
    test('Apple names the current provider status generation', () {
      for (final os in ['ios', 'macos']) {
        expect(nativeTunnelSession(appleReadiness(), operatingSystem: os),
            appleSession,
            reason: os);
      }
    });

    test('Apple names nothing unless the status document is current', () {
      for (final available in <Object?>[false, null, 'true', 1]) {
        expect(
            nativeTunnelSession(appleReadiness(available: available),
                operatingSystem: 'ios'),
            isNull,
            reason: '$available');
      }
    });

    test('Apple names nothing for a provider started without start options',
        () {
      // Round UN, OI-UN-1: the host rewrites the shared config before it
      // saves the profile, so after a failed save a restart without options
      // runs a newer node's config under the older generation.
      for (final os in ['ios', 'macos']) {
        for (final source in <Object?>[
          'shared_config_path',
          'app_group_fallback',
          'host_app',
          '',
          ' transient_start_options',
          'TRANSIENT_START_OPTIONS',
          null,
          true,
        ]) {
          expect(
              nativeTunnelSession(appleReadiness(configSource: source),
                  operatingSystem: os),
              isNull,
              reason: '$os $source');
          expect(
              committedNativeTunnelSession(appleReadiness(configSource: source),
                  operatingSystem: os, dartStartToken: null),
              isNull,
              reason: 'commit $os $source');
        }
      }
      // Android never reads the Apple config source.
      expect(
          nativeTunnelSession(
              <String, dynamic>{
                ...androidReadiness(),
                'provider_config_source': 'shared_config_path',
              },
              operatingSystem: 'android'),
          'android-winn3:4242');
    });

    test('Apple rejects a missing or malformed generation', () {
      for (final generation in <Object?>[
        null,
        '',
        'short',
        'has space in it',
        'x' * 65,
        42,
      ]) {
        expect(
            nativeTunnelSession(appleReadiness(generation: generation),
                operatingSystem: 'macos'),
            isNull,
            reason: '$generation');
      }
      expect(
          nativeTunnelSession(appleReadiness(generation: 'a' * 64),
              operatingSystem: 'ios'),
          'apple-status:${'a' * 64}');
      expect(
          nativeTunnelSession(appleReadiness(generation: 'abcdefgh'),
              operatingSystem: 'ios'),
          'apple-status:abcdefgh');
    });

    test('Android names the v3 start token only while a v3 lifecycle is live',
        () {
      expect(nativeTunnelSession(androidReadiness(), operatingSystem: 'android'),
          'android-winn3:4242');
      expect(
          nativeTunnelSession(androidReadiness(lifecycle: 'recovering'),
              operatingSystem: 'android'),
          'android-winn3:4242');
      // A v1 tunnel after a v3 session: the token is never reset, the
      // lifecycle is cleared by the teardown.
      expect(
          nativeTunnelSession(androidReadiness(lifecycle: null),
              operatingSystem: 'android'),
          isNull);
      expect(
          nativeTunnelSession(androidReadiness(lifecycle: ' '),
              operatingSystem: 'android'),
          isNull);
      expect(
          nativeTunnelSession(androidReadiness(lifecycle: true),
              operatingSystem: 'android'),
          isNull);
    });

    test('Android rejects a missing, non-positive or non-integer token', () {
      for (final token in <Object?>[null, 0, -1, '4242', 4242.0]) {
        expect(
            nativeTunnelSession(androidReadiness(token: token),
                operatingSystem: 'android'),
            isNull,
            reason: '$token');
      }
      expect(
          nativeTunnelSession(androidReadiness(token: 1),
              operatingSystem: 'android'),
          'android-winn3:1');
    });

    test('no readiness, or a platform with no session echo, names nothing',
        () {
      expect(nativeTunnelSession(null, operatingSystem: 'ios'), isNull);
      expect(nativeTunnelSession(null, operatingSystem: 'android'), isNull);
      for (final os in ['windows', 'linux', 'fuchsia']) {
        expect(
            nativeTunnelSession(
                <String, dynamic>{...appleReadiness(), ...androidReadiness()},
                operatingSystem: os),
            isNull,
            reason: os);
      }
      // One platform's fields never name another platform's session.
      expect(nativeTunnelSession(androidReadiness(), operatingSystem: 'ios'),
          isNull);
      expect(nativeTunnelSession(appleReadiness(), operatingSystem: 'android'),
          isNull);
    });

    test('a commit binds Android only to the token its own start minted', () {
      expect(
          committedNativeTunnelSession(androidReadiness(),
              operatingSystem: 'android', dartStartToken: 4242),
          'android-winn3:4242');
      // An earlier v3 session still live in the readiness snapshot.
      expect(
          committedNativeTunnelSession(androidReadiness(),
              operatingSystem: 'android', dartStartToken: 777),
          isNull);
      // A v1 or cover start mints no token of its own.
      expect(
          committedNativeTunnelSession(androidReadiness(),
              operatingSystem: 'android', dartStartToken: null),
          isNull);
      expect(
          committedNativeTunnelSession(androidReadiness(token: 0),
              operatingSystem: 'android', dartStartToken: 0),
          isNull);
      expect(
          committedNativeTunnelSession(androidReadiness(lifecycle: null),
              operatingSystem: 'android', dartStartToken: 4242),
          isNull);
    });

    test('a commit names its own Android start before the platform is asked',
        () {
      // Round UN-2: the string a live reading of that start names, so the
      // ledger can compare the two without any stored record.
      expect(
          startedNativeTunnelSession(
              operatingSystem: 'android', dartStartToken: 4242),
          'android-winn3:4242');
      expect(
          startedNativeTunnelSession(
              operatingSystem: 'android', dartStartToken: 4242),
          nativeTunnelSession(androidReadiness(), operatingSystem: 'android'));
      // A v1 or cover start mints no token of its own.
      for (final token in <int?>[null, 0, -1]) {
        expect(
            startedNativeTunnelSession(
                operatingSystem: 'android', dartStartToken: token),
            isNull,
            reason: '$token');
      }
      // Apple's session exists only in a provider reading.
      for (final os in ['ios', 'macos', 'linux', 'windows']) {
        expect(
            startedNativeTunnelSession(
                operatingSystem: os, dartStartToken: 4242),
            isNull,
            reason: os);
      }
    });

    test('a commit binds Apple to the generation of the proven start', () {
      expect(
          committedNativeTunnelSession(appleReadiness(),
              operatingSystem: 'ios', dartStartToken: null),
          appleSession);
      expect(
          committedNativeTunnelSession(appleReadiness(available: false),
              operatingSystem: 'ios', dartStartToken: 4242),
          isNull);
      expect(
          committedNativeTunnelSession(appleReadiness(),
              operatingSystem: 'linux', dartStartToken: 4242),
          isNull);
    });
  });

  group('persist re-read while the lifecycle is pending', () {
    // Round UN, OI-UN-6: an Android v3 engine publishes its lifecycle about a
    // second after promotion; the commit may read readiness before that.
    test('pending only for this start\'s own token with no lifecycle yet', () {
      for (final lifecycle in <Object?>[null, '', '  ', true, 7]) {
        expect(
            committedNativeTunnelSessionPending(
                androidReadiness(lifecycle: lifecycle),
                operatingSystem: 'android',
                dartStartToken: 4242),
            isTrue,
            reason: '$lifecycle');
      }
    });

    test('not pending once named, for another start, or off Android', () {
      expect(
          committedNativeTunnelSessionPending(androidReadiness(),
              operatingSystem: 'android', dartStartToken: 4242),
          isFalse,
          reason: 'already named');
      expect(
          committedNativeTunnelSessionPending(
              androidReadiness(lifecycle: null, token: 9999),
              operatingSystem: 'android',
              dartStartToken: 4242),
          isFalse,
          reason: 'another start\'s token');
      expect(
          committedNativeTunnelSessionPending(
              androidReadiness(lifecycle: null, token: '4242'),
              operatingSystem: 'android',
              dartStartToken: 4242),
          isFalse,
          reason: 'non-integer token');
      expect(
          committedNativeTunnelSessionPending(
              androidReadiness(lifecycle: null, token: null),
              operatingSystem: 'android',
              dartStartToken: 4242),
          isFalse,
          reason: 'no token echoed');
      for (final token in <int?>[null, 0, -1]) {
        expect(
            committedNativeTunnelSessionPending(
                androidReadiness(lifecycle: null, token: token),
                operatingSystem: 'android',
                dartStartToken: token),
            isFalse,
            reason: 'v1 or cover start: $token');
      }
      expect(
          committedNativeTunnelSessionPending(null,
              operatingSystem: 'android', dartStartToken: 4242),
          isFalse,
          reason: 'no readiness');
      for (final os in ['ios', 'macos', 'windows', 'linux']) {
        expect(
            committedNativeTunnelSessionPending(
                androidReadiness(lifecycle: null),
                operatingSystem: os,
                dartStartToken: 4242),
            isFalse,
            reason: os);
      }
    });
  });

  group('restore decision', () {
    test('the same account and the same live session restore the record', () {
      final persisted = record();
      expect(
          restorableTunnelDisplayRecord(
              persisted: persisted,
              accountScope: scope,
              nativeSession: appleSession),
          same(persisted));
    });

    test('never another account, another session, or no evidence', () {
      final persisted = record();
      expect(
          restorableTunnelDisplayRecord(
              persisted: persisted,
              accountScope: otherScope,
              nativeSession: appleSession),
          isNull,
          reason: 'another account');
      expect(
          restorableTunnelDisplayRecord(
              persisted: persisted,
              accountScope: scope,
              nativeSession: 'apple-status:another-generation'),
          isNull,
          reason: 'another native session');
      expect(
          restorableTunnelDisplayRecord(
              persisted: persisted, accountScope: scope, nativeSession: null),
          isNull,
          reason: 'no native session named');
      expect(
          restorableTunnelDisplayRecord(
              persisted: persisted,
              accountScope: '',
              nativeSession: appleSession),
          isNull,
          reason: 'no current account');
      expect(
          restorableTunnelDisplayRecord(
              persisted: null, accountScope: scope, nativeSession: appleSession),
          isNull,
          reason: 'no record');
    });

    test('stale only when provably unrestorable', () {
      final persisted = record();
      expect(
          persistedTunnelDisplayRecordIsStale(
              persisted: persisted,
              accountScope: otherScope,
              nativeSession: null),
          isTrue,
          reason: 'another account');
      expect(
          persistedTunnelDisplayRecordIsStale(
              persisted: persisted,
              accountScope: scope,
              nativeSession: 'android-winn3:1'),
          isTrue,
          reason: 'another live session');
      expect(
          persistedTunnelDisplayRecordIsStale(
              persisted: persisted,
              accountScope: '',
              nativeSession: 'android-winn3:1'),
          isTrue,
          reason: 'another live session, account unknown');
      expect(
          persistedTunnelDisplayRecordIsStale(
              persisted: persisted, accountScope: scope, nativeSession: null),
          isFalse,
          reason: 'no reading proves nothing');
      expect(
          persistedTunnelDisplayRecordIsStale(
              persisted: persisted, accountScope: '', nativeSession: null),
          isFalse,
          reason: 'no account and no reading prove nothing');
      expect(
          persistedTunnelDisplayRecordIsStale(
              persisted: persisted,
              accountScope: scope,
              nativeSession: appleSession),
          isFalse,
          reason: 'the restorable record');
      expect(
          persistedTunnelDisplayRecordIsStale(
              persisted: null, accountScope: otherScope, nativeSession: null),
          isFalse,
          reason: 'no record');
    });
  });

  group('ledger restore', () {
    Map<String, dynamic> ukRow() => <String, dynamic>{
          'slug': 'uk-gb1',
          'name': 'United Kingdom (live)',
          'status': 'online',
          'latency_ms': 35,
        };

    DashboardNodeDisplay show(TunnelDisplayLedger ledger, int accountEpoch,
            {List<Map<String, dynamic>> locations =
                const <Map<String, dynamic>>[]}) =>
        dashboardNodeForDisplay(
          locations: locations,
          selectedIndex: 0,
          rendersConnected: true,
          ledger: ledger,
          accountEpoch: accountEpoch,
        );

    test('names an adopted session without replacing it', () {
      final ledger = TunnelDisplayLedger();
      ledger.settle(wasConnected: false, isConnected: true);
      final adopted = ledger.generation;
      expect(show(ledger, 1).source, DashboardNodeSource.unknownTunnel);
      final restored = ledger.restore(
          record: record(), accountEpoch: 1, observedGeneration: adopted);
      expect(restored, isNotNull);
      expect(restored!.sessionGeneration, adopted);
      expect(ledger.generation, adopted, reason: 'the session is not replaced');
      final shown = show(ledger, 1);
      expect(shown.source, DashboardNodeSource.committedTunnel);
      expect(shown.node?['slug'], 'uk-gb1');
      expect(shown.node?['name'], 'United Kingdom');
      expect(shown.node?['status'], 'unknown',
          reason: 'health is never persisted');
      expect(shown.node?['flag'], 'GB');
    });

    test('the live listing row supplies health once it is known', () {
      final ledger = TunnelDisplayLedger();
      ledger.restore(
          record: record(), accountEpoch: 1, observedGeneration: 0);
      final shown = show(ledger, 1, locations: [ukRow()]);
      expect(shown.source, DashboardNodeSource.committedTunnel);
      expect(shown.node?['status'], 'online');
      expect(shown.node?['name'], 'United Kingdom (live)');
    });

    test('a record without name or flag is named by its slug', () {
      final ledger = TunnelDisplayLedger();
      ledger.restore(
          record: record(name: null, flag: null),
          accountEpoch: 1,
          observedGeneration: 0);
      final shown = show(ledger, 1);
      expect(shown.node?['name'], 'uk-gb1');
      expect(shown.node?.containsKey('flag'), isFalse);
    });

    test('an obsolete restore loses to a commit, a death or an adoption', () {
      for (final change in <String, void Function(TunnelDisplayLedger)>{
        'commit': (ledger) => ledger.commit(
              servedIdentity: 'de-fra1',
              callerIdentity: 'de-fra1',
              coverFallbackInProgress: false,
              accountEpoch: 1,
            ),
        'death': (ledger) =>
            ledger.settle(wasConnected: true, isConnected: false),
        'end': (ledger) => ledger.endSession(),
      }.entries) {
        final ledger = TunnelDisplayLedger();
        ledger.settle(wasConnected: false, isConnected: true);
        final observed = ledger.generation;
        change.value(ledger);
        expect(
            ledger.restore(
                record: record(), accountEpoch: 1, observedGeneration: observed),
            isNull,
            reason: change.key);
        final shown = show(ledger, 1);
        expect(shown.node?['slug'], isNot('uk-gb1'), reason: change.key);
      }
    });

    test('a commit in this process outranks a restore', () {
      final ledger = TunnelDisplayLedger();
      ledger.commit(
        servedIdentity: 'de-fra1',
        callerIdentity: 'de-fra1',
        coverFallbackInProgress: false,
        accountEpoch: 1,
      );
      expect(
          ledger.restore(
              record: record(),
              accountEpoch: 1,
              observedGeneration: ledger.generation),
          isNull);
      expect(show(ledger, 1).node?['slug'], 'de-fra1');
    });

    test('a re-login replaces the previous epoch record with its own', () {
      final ledger = TunnelDisplayLedger();
      ledger.commit(
        servedIdentity: 'uk-gb1',
        callerIdentity: 'uk-gb1',
        coverFallbackInProgress: false,
        accountEpoch: 1,
      );
      expect(show(ledger, 2).source, DashboardNodeSource.unknownTunnel);
      expect(
          ledger.restore(
              record: record(),
              accountEpoch: 2,
              observedGeneration: ledger.generation),
          isNotNull);
      expect(show(ledger, 2).node?['slug'], 'uk-gb1');
      expect(show(ledger, 1).source, DashboardNodeSource.unknownTunnel,
          reason: 'the restored record belongs to the new epoch only');
    });

    test('a restored record ends with its session', () {
      final ledger = TunnelDisplayLedger();
      ledger.settle(wasConnected: false, isConnected: true);
      ledger.restore(
          record: record(),
          accountEpoch: 1,
          observedGeneration: ledger.generation);
      ledger.settle(wasConnected: true, isConnected: false);
      ledger.settle(wasConnected: false, isConnected: true);
      expect(show(ledger, 1).source, DashboardNodeSource.unknownTunnel);
    });
  });

  group('ledger same-session resume', () {
    // Round UN-2, 2026-10-23 owner report: a live Android winn/3 tunnel read
    // "Unknown node" after a relock, a Wi-Fi handover and the PIN unlock. A
    // flipped connected flag ends the display session; the native session did
    // not end, so the commit that started it names the node again.
    const session = 'android-winn3:4242';

    Map<String, dynamic> canadaRow() => <String, dynamic>{
          'slug': 'ca-tor1',
          'name': 'Canada',
          'flag': 'CA',
          'status': 'online',
        };

    TunnelDisplayLedger committed({String? nativeSession = session}) {
      final ledger = TunnelDisplayLedger();
      ledger.commit(
        servedIdentity: 'ca-tor1',
        callerIdentity: 'ca-tor1',
        coverFallbackInProgress: false,
        accountEpoch: 1,
        locations: [canadaRow()],
        nativeSession: nativeSession,
      );
      return ledger;
    }

    // A reading flap: not connected, then connected again with no identity.
    void flap(TunnelDisplayLedger ledger) {
      ledger.settle(wasConnected: true, isConnected: false);
      ledger.settle(wasConnected: false, isConnected: true);
    }

    DashboardNodeDisplay show(TunnelDisplayLedger ledger, {int epoch = 1}) =>
        dashboardNodeForDisplay(
          locations: [canadaRow()],
          selectedIndex: 0,
          rendersConnected: true,
          ledger: ledger,
          accountEpoch: epoch,
        );

    test('a flipped flag does not forget the commit: the same session names it',
        () {
      final ledger = committed();
      expect(show(ledger).node?['name'], 'Canada');
      flap(ledger);
      expect(show(ledger).source, DashboardNodeSource.unknownTunnel);
      expect(ledger.remembers(accountEpoch: 1), isTrue);
      final adopted = ledger.generation;
      final resumed = ledger.resume(
          nativeSession: session, accountEpoch: 1, observedGeneration: adopted);
      expect(resumed, isNotNull);
      expect(resumed!.sessionGeneration, adopted);
      expect(ledger.generation, adopted, reason: 'the session is not replaced');
      final shown = show(ledger);
      expect(shown.source, DashboardNodeSource.committedTunnel);
      expect(shown.node?['slug'], 'ca-tor1');
      expect(shown.node?['name'], 'Canada');
      expect(shown.node?['flag'], 'CA');
    });

    test('the identity survives every later flap of the same session', () {
      final ledger = committed();
      for (var i = 0; i < 3; i++) {
        flap(ledger);
        expect(
            ledger.resume(
                nativeSession: session,
                accountEpoch: 1,
                observedGeneration: ledger.generation),
            isNotNull,
            reason: 'flap $i');
        expect(show(ledger).node?['flag'], 'CA', reason: 'flap $i');
      }
    });

    test('the identity needs the record only for health, never for the name',
        () {
      final ledger = committed();
      flap(ledger);
      ledger.resume(
          nativeSession: session,
          accountEpoch: 1,
          observedGeneration: ledger.generation);
      final unlisted = dashboardNodeForDisplay(
        locations: const <Map<String, dynamic>>[],
        selectedIndex: 0,
        rendersConnected: true,
        ledger: ledger,
        accountEpoch: 1,
      );
      expect(unlisted.node?['name'], 'Canada');
      expect(unlisted.node?['flag'], 'CA');
      expect(unlisted.node?['status'], 'unknown');
    });

    test('only the exact native session resumes', () {
      final ledger = committed();
      flap(ledger);
      for (final other in <String?>[
        null,
        '',
        'android-winn3:4243',
        'android-winn3:4242 ',
        'apple-status:6F9619FF-8B86-D011-B42D-00CF4FC964FF',
      ]) {
        expect(
            ledger.resume(
                nativeSession: other,
                accountEpoch: 1,
                observedGeneration: ledger.generation),
            isNull,
            reason: '$other');
      }
      expect(show(ledger).source, DashboardNodeSource.unknownTunnel);
      expect(ledger.remembers(accountEpoch: 1), isTrue,
          reason: 'a wrong reading proves nothing: the right one may follow');
    });

    test('a commit that names no native session is not remembered', () {
      for (final unnamed in <String?>[null, '', '  ']) {
        final ledger = committed(nativeSession: unnamed);
        flap(ledger);
        expect(ledger.remembers(accountEpoch: 1), isFalse, reason: '$unnamed');
        expect(
            ledger.resume(
                nativeSession: session,
                accountEpoch: 1,
                observedGeneration: ledger.generation),
            isNull,
            reason: '$unnamed');
      }
    });

    test('an unusable slug remembers nothing', () {
      final ledger = TunnelDisplayLedger();
      expect(
          ledger.commit(
            servedIdentity: 'auto',
            callerIdentity: '',
            coverFallbackInProgress: false,
            accountEpoch: 1,
            nativeSession: session,
          ),
          isNull);
      expect(ledger.remembers(accountEpoch: 1), isFalse);
    });

    test('another account epoch never resumes', () {
      final ledger = committed();
      flap(ledger);
      expect(ledger.remembers(accountEpoch: 2), isFalse);
      expect(
          ledger.resume(
              nativeSession: session,
              accountEpoch: 2,
              observedGeneration: ledger.generation),
          isNull);
      expect(show(ledger, epoch: 2).source, DashboardNodeSource.unknownTunnel);
    });

    test('an obsolete reading cannot resume', () {
      final ledger = committed();
      flap(ledger);
      final observed = ledger.generation;
      ledger.settle(wasConnected: true, isConnected: false);
      expect(
          ledger.resume(
              nativeSession: session,
              accountEpoch: 1,
              observedGeneration: observed),
          isNull);
    });

    test('a session that already has a record is not replaced', () {
      final ledger = committed();
      expect(
          ledger.resume(
              nativeSession: session,
              accountEpoch: 1,
              observedGeneration: ledger.generation),
          isNull,
          reason: 'the live commit is the record');
      flap(ledger);
      ledger.restore(
          record: PersistedTunnelDisplayRecord(
            slug: 'uk-gb1',
            name: 'United Kingdom',
            flag: 'GB',
            accountScope: 'scope-account-a',
            nativeSession: session,
          ),
          accountEpoch: 1,
          observedGeneration: ledger.generation);
      expect(
          ledger.resume(
              nativeSession: session,
              accountEpoch: 1,
              observedGeneration: ledger.generation),
          isNull);
      expect(ledger.recordFor(accountEpoch: 1)?.slug, 'uk-gb1',
          reason: 'a restored record outranks the remembered commit');
    });

    test('an explicit end, a stop and the next commit forget it', () {
      final ends = <String, void Function(TunnelDisplayLedger)>{
        'endSession': (ledger) => ledger.endSession(),
        'forget': (ledger) => ledger.forget(),
        'commit without a session': (ledger) => ledger.commit(
              servedIdentity: 'de-fra1',
              callerIdentity: 'de-fra1',
              coverFallbackInProgress: false,
              accountEpoch: 1,
            ),
      };
      for (final end in ends.entries) {
        final ledger = committed();
        flap(ledger);
        end.value(ledger);
        expect(ledger.remembers(accountEpoch: 1), isFalse, reason: end.key);
        expect(
            ledger.resume(
                nativeSession: session,
                accountEpoch: 1,
                observedGeneration: ledger.generation),
            isNull,
            reason: end.key);
      }
    });

    test('the next commit remembers its own session, not the earlier one', () {
      final ledger = committed();
      ledger.commit(
        servedIdentity: 'de-fra1',
        callerIdentity: 'de-fra1',
        coverFallbackInProgress: false,
        accountEpoch: 1,
        nativeSession: 'android-winn3:9001',
      );
      flap(ledger);
      expect(
          ledger.resume(
              nativeSession: session,
              accountEpoch: 1,
              observedGeneration: ledger.generation),
          isNull,
          reason: 'the earlier start is gone');
      expect(
          ledger
              .resume(
                  nativeSession: 'android-winn3:9001',
                  accountEpoch: 1,
                  observedGeneration: ledger.generation)
              ?.slug,
          'de-fra1');
    });

    test('an obsolete end leaves the remembered commit alone', () {
      final ledger = committed();
      final observed = ledger.generation;
      ledger.settle(wasConnected: true, isConnected: false);
      // A completion that belongs to the session before the flap.
      expect(ledger.endSession(observedGeneration: observed), isFalse);
      expect(ledger.remembers(accountEpoch: 1), isTrue);
    });
  });
}
