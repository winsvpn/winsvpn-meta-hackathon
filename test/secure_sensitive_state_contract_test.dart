import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/diagnostic_redaction.dart';

String _normalizeSourceWhitespace(String source) => source
    .replaceAll(RegExp(r'\s+'), ' ')
    .replaceAll(RegExp(r'\(\s+'), '(')
    .replaceAll(RegExp(r'\s+\)'), ')')
    .trim();

void main() {
  test(
      'sensitive state uses native stores on Android Windows Linux iOS and macOS',
      () {
    final source = File('lib/main.dart').readAsStringSync();

    final storeGetterStart =
        source.indexOf('bool get _usesNativeSecureStateStore');
    final storeGetterEnd = source.indexOf(';', storeGetterStart);
    expect(storeGetterStart, greaterThanOrEqualTo(0));
    final storeGetter = source.substring(storeGetterStart, storeGetterEnd);
    for (final platform in <String>[
      'Platform.isAndroid',
      'Platform.isWindows',
      'Platform.isLinux',
    ]) {
      expect(storeGetter, contains(platform));
    }
    // H-2: Apple platforms must also be routed through the native secure
    // state store instead of falling back to ordinary files.
    expect(
      storeGetter,
      contains('_isApplePlatform'),
    );
    expect(source, contains("'readSecureText'"));
    expect(source, contains("'writeSecureText'"));
    expect(source, contains("'deleteSecureText'"));
    // H-2 cross-cutting contract with the Apple-native side: exact method
    // names used for the Keychain-backed store on iOS/macOS.
    expect(source, contains("'secureStateRead'"));
    expect(source, contains("'secureStateWrite'"));
    expect(source, contains("'secureStateDelete'"));
    for (final name in <String>[
      'client_keypair.json',
      'pending_logout.json',
      'user_pin.txt',
      'vpn_config.txt',
      'vpn_settings.txt',
    ]) {
      expect(source, contains("'$name'"));
    }

    final storeStart =
        source.indexOf('String _clientKeyScopeToken(String accountScope)');
    final keyEnd = source.indexOf(
        'Map<String, dynamic> _attachLocalClientKeys(', storeStart);
    final keyBody = source.substring(storeStart, keyEnd);
    final normalizedKeyBody = _normalizeSourceWhitespace(keyBody);
    expect(keyBody, contains("_readSensitiveText('client_keypair.json')"));
    expect(keyBody, contains("_writeSensitiveText('client_keypair.json'"));
    expect(
        keyBody, contains('Stored VPN identity is corrupted or unavailable'));
    expect(keyBody, isNot(contains('File(')));

    // Every WireGuard key pair must be scoped by account, never a single
    // unscoped identity shared across whichever account is logged in.
    // Without this, switching the logged-in account on one install (a
    // shared device, or free access -> paid) silently reused the previous
    // account's key, which can collide with another account's key on a
    // shared Double VPN core peer.
    expect(
        normalizedKeyBody,
        contains('Future<Map<String, String>> _loadOrCreateClientKeyPair('
            'String accountScope) =>'));
    expect(normalizedKeyBody,
        contains('Future<Map<String, String>?> _loadExistingClientKeyPair('));
    expect(keyBody, contains('_clientKeyScopeToken(accountScope)'));
    expect(keyBody, isNot(contains("decoded['private_key']")));

    final persistStart =
        source.indexOf('Future<void> _persistVpnConfigBestEffort(');
    final persistEnd = source.indexOf(
        'Future<void> _persistEncodedVpnConfigOnApple(', persistStart);
    expect(
      source.substring(persistStart, persistEnd),
      contains("_writeSensitiveText('vpn_config.txt', encoded)"),
    );
  });

  test(
      'H-2: legacy Apple sensitive files are migrated into the secure store '
      'and never left behind on success', () {
    final source = File('lib/main.dart').readAsStringSync();
    final namesStart = source.indexOf('_legacyAppleMigrationNames = <String>{');
    final namesEnd = source.indexOf('};', namesStart);
    expect(namesStart, greaterThanOrEqualTo(0));
    expect(namesEnd, greaterThan(namesStart));
    final namesBody = source.substring(namesStart, namesEnd);
    for (final name in <String>[
      'user_pin.txt',
      'vpn_settings.txt',
      'pending_logout.json',
    ]) {
      expect(namesBody, contains("'$name'"));
    }

    final start =
        source.indexOf('Future<void> _migrateLegacyAppleSensitiveState()');
    final end = source.indexOf(
        'Future<Map<String, dynamic>> _readSensitiveJsonMap(', start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final body = source.substring(start, end);
    // The migration loop must iterate the same allowlisted legacy names
    // rather than hard-coding (and risking drift from) a separate list.
    expect(body, contains('for (final name in _legacyAppleMigrationNames)'));
    // Read-back verification must happen before the legacy plaintext file is
    // ever deleted, and a failure must leave the legacy file in place
    // (fail closed) rather than losing data.
    final readBackIndex = body.indexOf('readBack');
    final deleteIndex = body.indexOf('legacyFile.delete()');
    expect(readBackIndex, greaterThanOrEqualTo(0));
    expect(deleteIndex, greaterThan(readBackIndex));
    expect(body, contains('catch (_)'));
    // The legacy plaintext content itself must never be logged: the
    // migrated variable name should not appear inside any debug message.
    expect(body, isNot(contains('_debugLog(legacyContent)')));
    expect('legacyContent'.allMatches(body).length, lessThanOrEqualTo(3));

    // M-14: the migration itself is purely local - it must never make a
    // network call or read/send any device identifier.
    expect(body, isNot(contains('http.')));
    expect(body, isNot(contains('Uri.parse(')));
    expect(body, isNot(contains('DeviceHardware')));
    expect(body, isNot(contains('device_id')));
    expect(body, isNot(contains('deviceId')));
  });

  test(
      'M-14: legacy Apple sensitive-state migration runs before the '
      'privacy-consent gate, not after it, and is invoked exactly once', () {
    final source = File('lib/main.dart').readAsStringSync();

    // initState must kick off the new pre-consent wrapper, not the privacy
    // gate directly - otherwise migration would still wait behind consent.
    final initStateStart = source.indexOf('void initState() {');
    final initStateEnd = source.indexOf('}', initStateStart);
    expect(initStateStart, greaterThanOrEqualTo(0));
    expect(initStateEnd, greaterThan(initStateStart));
    // addPostFrameCallback's own body extends past the first '}', so the
    // search has to reach the callback registration below it. Bounded by the
    // next method rather than by a fixed character count: the previous fixed
    // 400-character window silently stopped matching once the
    // WINS_RESET_LOCAL_STATE comment block was added inside initState, which
    // failed this test without any change to the behaviour it guards.
    final initStateLimit =
        source.indexOf('\n  /// Companion-watch commands.', initStateStart);
    expect(initStateLimit, greaterThan(initStateStart));
    final initStateBody = source.substring(initStateStart, initStateLimit);
    expect(
      initStateBody,
      contains('unawaited(_initializeLocalSecurityThenPrivacyConsent());'),
    );
    expect(initStateBody,
        isNot(contains('unawaited(_initializePrivacyConsentGate());')));

    // The wrapper must call the migration strictly before the privacy gate,
    // unconditionally on consent (only gated on being an Apple platform),
    // so a declined ("Not now") consent choice still lets migration run.
    final wrapperStart = source
        .indexOf('Future<void> _initializeLocalSecurityThenPrivacyConsent()');
    final wrapperEnd = source.indexOf(
        'Future<void> _initializePrivacyConsentGate()', wrapperStart);
    expect(wrapperStart, greaterThanOrEqualTo(0));
    expect(wrapperEnd, greaterThan(wrapperStart));
    final wrapperBody = source.substring(wrapperStart, wrapperEnd);
    expect(wrapperBody, contains('if (_isApplePlatform) {'));
    final migrateCallIndex =
        wrapperBody.indexOf('await _migrateLegacyAppleSensitiveState();');
    final gateCallIndex =
        wrapperBody.indexOf('await _initializePrivacyConsentGate();');
    expect(migrateCallIndex, greaterThanOrEqualTo(0));
    expect(gateCallIndex, greaterThan(migrateCallIndex));
    // This wrapper's own body must not itself be conditioned on consent.
    expect(wrapperBody, isNot(contains('_privacyConsentGranted')));

    // The pre-fix bug: the only call site lived inside this consent-gated
    // function. It must not be invoked here a second time (double-migration
    // is harmless since the function is idempotent, but the fix's whole
    // point is that consent must no longer gate migration at all).
    final onboardingStart =
        source.indexOf('Future<void> _determineSecurityOnboardingLayer()');
    final onboardingEnd = source.indexOf(
        'Future<void> _onCalculatorButtonPressed(', onboardingStart);
    expect(onboardingStart, greaterThanOrEqualTo(0));
    expect(onboardingEnd, greaterThan(onboardingStart));
    final onboardingBody = source.substring(onboardingStart, onboardingEnd);
    expect(onboardingBody, contains('if (!_privacyConsentGranted) return;'));
    expect(
      onboardingBody,
      isNot(contains('_migrateLegacyAppleSensitiveState()')),
    );
  });

  test('H-1: macOS announcement notifications never shell out to osascript',
      () {
    final source = File('lib/main.dart').readAsStringSync();
    // 'osascript' as a quoted string literal would mean it's being passed as
    // a Process argument; the word may still appear inside an explanatory
    // comment (backtick-quoted) describing why it is deliberately avoided.
    expect(source, isNot(contains("'osascript'")));
    expect(source, isNot(contains('"osascript"')));

    final start =
        source.indexOf('Future<bool> _showSystemAnnouncementNotification(');
    final end =
        source.indexOf('Future<void> _maybeNotifyServerAnnouncement(', start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final body = source.substring(start, end);
    expect(body, contains("'showAnnouncementNotification'"));
    // Fails closed on macOS (and Windows/Android) when the native call
    // fails; only Linux may fall back, and only via an argument vector.
    expect(body, contains('if (!Platform.isLinux) return false;'));
    expect(body, contains("'notify-send'"));
    // Process.start, not Process.run: the run() form buffers stdout/stderr
    // without bound, which is what let _probePingLatencyMs grow to 152 GiB and
    // take the machine down (MACOS_MEMORY_BLOWUP_20260808.md). The argument
    // vector — the property this assertion actually guards — is unchanged.
    expect(body, contains('Process.start('));
    expect(body, isNot(contains('Process.run(')));
  });

  test('M-1: launcher unlock state is never persisted to settings', () {
    final source = File('lib/main.dart').readAsStringSync();
    expect(source, isNot(contains("settingsData['launcher_unlocked']")));
    expect(source, isNot(contains("'launcher_unlocked'] =")));
    expect(source, isNot(contains('launcherUnlocked:')));
    // Any leftover key from an older build must be actively scrubbed.
    expect(source, contains("data.remove('launcher_unlocked')"));
  });

  test(
      'M-1: PIN verification enforces a persisted lockout ledger and '
      'rejects legacy plaintext credentials', () {
    final source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf('Future<bool> _verifyUserPin(');
    final end = source.indexOf(
        'Future<void> _determineSecurityOnboardingLayer()', start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final body = source.substring(start, end);

    expect(body, contains('_readPinAttemptState()'));
    expect(body, contains('.isLockedAt('));
    expect(body, contains('isLegacyPlaintextCredential('));
    expect(body, contains("_deleteSensitiveText('user_pin.txt')"));
    expect(body, contains('throw const PinReenrollmentRequired()'));
    expect(body, contains('_writePinAttemptState('));
    expect(body, contains('.nextFailure('));
  });

  test(
      'M-15: PIN lockout enforcement uses a native monotonic clock reading '
      'with a wall-clock fallback, and rearms instead of clearing on '
      'rollback', () {
    final source = File('lib/main.dart').readAsStringSync();

    // The monotonic reader itself must fail safe: any channel failure
    // (including a MissingPluginException from a platform that has not
    // implemented the native handler yet) or a null result must fall back
    // to wall-clock-only enforcement rather than crash or lock forever.
    final readerStart = source.indexOf('Future<int?> _monotonicNowMs()');
    final readerEnd = source.indexOf(
        'Future<void> _determineSecurityOnboardingLayer()', readerStart);
    expect(readerStart, greaterThanOrEqualTo(0));
    expect(readerEnd, greaterThan(readerStart));
    final readerBody = source.substring(readerStart, readerEnd);
    expect(readerBody, contains("invokeMethod<int>('monotonicMilliseconds')"));
    expect(readerBody, contains('try {'));
    expect(readerBody, contains('catch (e)'));
    expect(readerBody, contains('return null;'));

    final start = source.indexOf('Future<bool> _verifyUserPin(');
    final end = source.indexOf(
        'Future<void> _determineSecurityOnboardingLayer()', start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final body = source.substring(start, end);

    expect(body, contains('await _monotonicNowMs()'));
    // A monotonic rollback (reboot) must re-arm a fresh delay and persist
    // it, never simply fall through as if the lockout had been cleared.
    expect(body, contains('gate.isMonotonicRollback(nowMonotonicMs)'));
    expect(body, contains('gate.rearmAfterMonotonicRollback(nowMonotonicMs)'));
    var cursor = 0;
    void expectInOrder(String needle) {
      final index = body.indexOf(needle, cursor);
      expect(index, greaterThanOrEqualTo(cursor),
          reason: 'expected "$needle" after offset $cursor in _verifyUserPin');
      cursor = index + needle.length;
    }

    expectInOrder('isMonotonicRollback(nowMonotonicMs)');
    expectInOrder('rearmAfterMonotonicRollback(nowMonotonicMs)');
    expectInOrder('_writePinAttemptState(gate)');
    // The lockout decision must consult both clocks: locked if either the
    // wall clock or the monotonic clock says so, so a locally-advanced
    // wall clock alone can never lift a lockout once a monotonic deadline
    // exists.
    expectInOrder('gate.isLockedAt(nowUtc)');
    expectInOrder('gate.isLockedAtMonotonic(nowMonotonicMs)');
    // The monotonic reading must also be threaded into the failure ledger
    // write so a monotonic deadline actually gets recorded.
    expectInOrder(
        'nextFailure(nowUtc: nowUtc, nowMonotonicMs: nowMonotonicMs)');
  });

  test(
      'M-7: PIN attempt ledger read fails closed instead of resetting on a '
      'storage error', () {
    final source = File('lib/main.dart').readAsStringSync();
    final start =
        source.indexOf('Future<PinAttemptState> _readPinAttemptState()');
    final end = source.indexOf('Future<void> _writePinAttemptState(', start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final body = source.substring(start, end);

    // The pre-fix bug: a read failure was caught here and silently
    // downgraded to a fresh, unlocked PinAttemptState, resetting the
    // failure counter to zero on every transient storage error.
    expect(body, isNot(contains('try {')));
    expect(body, isNot(contains('return const PinAttemptState();')));
    // Must not route through the general settings helper, which itself
    // swallows read failures (see the "awaits native failures inside its
    // catch boundary" test above) for the many unrelated, best-effort
    // settings it backs.
    expect(body, isNot(contains('_readVpnRuntimeSettings()')));
    expect(body, contains('await _settingsMutationQueue;'));
    expect(body, contains("_readSensitiveJsonMap('vpn_settings.txt')"));
  });

  test(
      'M-7: PIN attempt ledger write fails closed via a durable read-back '
      'instead of swallowing the write error', () {
    final source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf('Future<void> _writePinAttemptState(');
    final end = source.indexOf('Future<bool> _verifyUserPin(', start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final body = source.substring(start, end);

    // The pre-fix bug: a write failure (or a write that silently never
    // persisted) was caught and discarded here, so a failed attempt could
    // simply never make it into the ledger.
    expect(body, isNot(contains('try {')));
    expect(body, isNot(contains('PIN attempt state write failed safely')));
    expect(body, contains('_mutateVpnRuntimeSettings('));
    // A write that is acknowledged but does not durably stick must still
    // be treated as a failure rather than silently accepted.
    expect(body, contains('_readPinAttemptState()'));
    expect(body, contains('persisted != state'));
    expect(body, contains('throw StateError('));
  });

  test(
      'M-7: PIN verification fails closed -- an unreadable/unwritable '
      'ledger denies the unlock instead of defaulting to one', () {
    final source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf('Future<bool> _verifyUserPin(');
    final end = source.indexOf(
        'Future<void> _determineSecurityOnboardingLayer()', start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final body = source.substring(start, end);

    // The fix wraps the *entire* body -- including the initial ledger read
    // and lockout check -- inside one try, so a read failure there also
    // denies the unlock instead of (as before the fix) sitting outside any
    // try in this method and propagating uncaught, or a write failure
    // inside the try being swallowed one level down instead of denying.
    var cursor = 0;
    void expectInOrder(String needle) {
      final index = body.indexOf(needle, cursor);
      expect(index, greaterThanOrEqualTo(cursor),
          reason: 'expected "$needle" after offset $cursor in _verifyUserPin');
      cursor = index + needle.length;
    }

    expectInOrder('try {');
    expectInOrder('_readPinAttemptState()');
    expectInOrder('isLegacyPlaintextCredential(');
    expectInOrder("_deleteSensitiveText('user_pin.txt')");
    expectInOrder('throw const PinReenrollmentRequired()');
    // The lockout gate now sits after the credential derivation, not before
    // it -- see the dedicated ordering test below. This assertion moved with
    // it; what M-7 pins is that every step lives inside the one try and that
    // the failure is recorded, not where the gate sits.
    expectInOrder('.isLockedAt(');
    expectInOrder('_writePinAttemptState(');
    expectInOrder('.nextFailure(');
    expectInOrder('on PinReenrollmentRequired');
    expectInOrder('rethrow;');
    expectInOrder('catch (e)');
    expectInOrder('return false;');
  });

  test(
      'the credential is derived before the lockout gate, so a locked-out '
      'attempt is not observably faster and an unthrottled second '
      'credential has somewhere to go', () {
    final source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf('Future<bool> _verifyUserPin(');
    final end = source.indexOf(
        'Future<void> _determineSecurityOnboardingLayer()', start);
    expect(start, greaterThanOrEqualTo(0));
    final body = source.substring(start, end);

    final derivation = body.indexOf('verifyStoredCredentialOffThread(');
    final lockoutGate = body.indexOf('final locked =');
    // The lockout no longer returns early; it is one input to the shared
    // outcome classifier (duress-path-defects lane, 2026-08-06), which is what
    // lets the duress and wrong-PIN branches be proven equal rather than
    // asserted equal. The ordering property this test exists for is unchanged.
    final lockoutApplied = body.indexOf('lockedOut: locked');

    expect(derivation, greaterThanOrEqualTo(0));
    expect(lockoutGate, greaterThan(derivation),
        reason: 'returning early on lockout made a locked attempt finish '
            'without paying the derivation cost, which is observable, and '
            'left no unthrottled point for a duress credential');
    expect(lockoutApplied, greaterThan(derivation));

    // A locked-out attempt must still record nothing: it may not let an
    // attacker re-arm or clear the ledger by hammering the keypad. That is now
    // decided by classifyCredentialEntry and asserted behaviourally in
    // duress_camouflage_contract_test.dart ("under lockout NEITHER path writes
    // the ledger"); here we only pin that the writes are downstream of it.
    final ledgerWrite = body.indexOf('outcome.clearsAttemptLedger');
    expect(ledgerWrite, greaterThan(lockoutApplied));
    expect(body, contains('outcome.recordsAttemptFailure'));

    // Derivation must never be short-circuited on an earlier match: equal
    // work per attempt is what keeps one credential indistinguishable from
    // another once a second one exists.
    expect(body, isNot(contains('if (matches) return')));
  });

  test('M-1: backgrounding re-locks the app behind the decoy camouflage', () {
    final source = File('lib/main.dart').readAsStringSync();
    final start =
        source.indexOf('void didChangeAppLifecycleState(AppLifecycleState');
    final end = source.indexOf('void _startStatusHeartbeat()', start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final body = source.substring(start, end);

    expect(body, contains('AppLifecycleState.paused'));
    expect(body, contains('_setLauncherCamouflage(enabled: true)'));
    expect(body, contains('_showDecoyCalculator = true'));
  });

  test(
      'M-2: recovery gateway record can only select gateways already in the '
      'compiled allowlist', () {
    final source = File('lib/main.dart').readAsStringSync();
    final start =
        source.indexOf('Future<Map<String, String>> _resolveDynamicEndpoints(');
    expect(start, greaterThanOrEqualTo(0));
    // The record URL is now resolved through _recoveryRecordUrl() so that
    // WINS_RECOVERY_RECORD_URL can move the rotation channel at build time.
    // Anchor on that call; everything from it to the close of the method is the
    // region the M-2 invariant governs.
    final recoveryStart =
        source.indexOf('final recordUrl = _recoveryRecordUrl();', start);
    expect(recoveryStart, greaterThan(start));
    final recoveryEnd = source.indexOf('\n  }\n', recoveryStart);
    expect(recoveryEnd, greaterThan(recoveryStart));
    final body = source.substring(recoveryStart, recoveryEnd);

    // The allowlist check exists once, in gateway_failover.dart, and this is
    // the only way the record can become a gateway here. Re-implementing it
    // inline is what let three copies drift apart in the first place.
    expect(body, contains('await resolveRecoveryGateway('));
    expect(body, contains('fetchRecord: _fetchGatewayRecordBody'));
    expect(
        body, contains('Rejected recovery gateway outside signed allowlist'));
    expect(body, isNot(contains('.contains(')));
    expect(body, isNot(contains('parseGatewayRecord')));

    // Nothing derived from the response body may be spread into, or used as,
    // the returned gateway: only the value resolveRecoveryGateway returned,
    // which is by construction a compiled allowlist element.
    expect(body, isNot(contains('{...')));
    expect(body, isNot(contains('res.body')));
    expect(body, contains("return <String, String>{'gateway': recovered};"));

    // The response body must never enter this scope at all -- the fetch is
    // handed over as a callback so only gateway_failover.dart ever holds it.
    expect(
        source, contains('Future<String?> _fetchGatewayRecordBody(Uri url)'));

    // The record-parsing bypass wrapper is gone: main.dart has no route to a
    // record-derived host that skips the allowlist.
    expect(
        source, isNot(contains('Map<String, String>? _parseGatewayRecord(')));

    // The privacy-consent gate still precedes the fetch.
    final consentGate = source.indexOf(
        'if (!_privacyConsentGranted) return {"gateway": activeGateway};',
        start);
    expect(consentGate, greaterThan(start));
    expect(consentGate, lessThan(recoveryStart));

    // The failure gate also precedes the fetch. Without it the record is
    // requested on every launch, connect and heartbeat, which is a recurring
    // beacon paired with the gateway connection that follows it -- and it buys
    // nothing on the happy path, because the record can only re-order gateways
    // the client iterates in full anyway.
    final beaconGate = source.indexOf(
        'if (!_recoveryBeaconGate.shouldFetchRecoveryRecord(now)) {', start);
    expect(beaconGate, greaterThan(consentGate));
    expect(beaconGate, lessThan(recoveryStart));
    expect(
        source, contains('_recoveryBeaconGate.recordRecoveryRecordFetched('));

    // A build-time override reaches an http client, so it is screened by the
    // same library that screens gateways, and an unusable one yields NO fetch
    // rather than falling back to the compiled branded URL. Falling back is the
    // one failure this must never have: it would restore the branded path
    // inside precisely the build that was replacing it. Since B-APP-005 the
    // screen also pins the host to the compiled recovery-record allowlist:
    // the override may rotate the path, never the host.
    final urlResolver = source.indexOf('String _recoveryRecordUrl() {');
    expect(urlResolver, greaterThanOrEqualTo(0));
    final resolverEnd = source.indexOf('\n  }\n', urlResolver);
    final resolverBody = source.substring(urlResolver, resolverEnd);
    expect(resolverBody, contains('isAllowedRecoveryRecordUrl(override)'));
    expect(resolverBody, contains("? override : ''"));
    expect(resolverBody, isNot(contains('http')));
  });

  test(
      'M-2: gateway_failover holds exactly one allowlist check and no public '
      'route to an unvalidated record host', () {
    final source = File('lib/gateway_failover.dart').readAsStringSync();

    // Exactly one comparison of a record candidate against the allowlist.
    expect(
      'allowed == candidate'.allMatches(source).length,
      1,
    );
    expect(source, contains('String? recoveryGatewayFromRecord(String body)'));

    // The structural parser is private, so a record host cannot be obtained
    // without going through the allowlist.
    expect(
        source, contains('List<String> _recordGatewayCandidates(String body)'));
    expect(source, isNot(contains('GatewayEndpoints? parseGatewayRecord(')));
    expect(source, isNot(contains('Map<String, String> toMap()')));

    // The rejection callback carries no arguments, so no record byte can ride
    // out on a diagnostic.
    expect(source, contains('void Function()? onRejected'));

    // Exact match only: no host normalisation may creep into the comparison.
    final matchStart = source.indexOf('String? recoveryGatewayFromRecord(');
    final matchEnd = source.indexOf('Future<String?> resolveRecoveryGateway(');
    expect(matchEnd, greaterThan(matchStart));
    final matchBody = source.substring(matchStart, matchEnd);
    for (final loosening in <String>[
      'toLowerCase',
      'startsWith',
      'endsWith',
      'contains(',
      'replaceAll',
      'RegExp',
    ]) {
      expect(matchBody, isNot(contains(loosening)), reason: loosening);
    }
  });

  test('L-12: external URL launches are routed through validatedHttpsUrl', () {
    final source = File('lib/main.dart').readAsStringSync();
    expect(source, contains('validatedHttpsUrl('));

    final launchUrlStart = source.indexOf('Future<void> _launchURL(');
    final launchUrlEnd =
        source.indexOf('Future<void> _launchSocialUrl(', launchUrlStart);
    expect(launchUrlStart, greaterThanOrEqualTo(0));
    expect(launchUrlEnd, greaterThan(launchUrlStart));
    expect(
      source.substring(launchUrlStart, launchUrlEnd),
      contains('validatedHttpsUrl(url)'),
    );

    final socialStart = source.indexOf('Future<void> _launchSocialUrl(');
    final socialEnd = source.indexOf('String _paymentSourceTag()', socialStart);
    expect(socialStart, greaterThanOrEqualTo(0));
    expect(socialEnd, greaterThan(socialStart));
    final socialBody = source.substring(socialStart, socialEnd);
    expect(socialBody, contains('validatedHttpsUrl(webUrl)'));
  });

  test(
      'M-5: device auth token is captured on activation and required for '
      'authenticated device-mutation calls', () {
    final source = File('lib/main.dart').readAsStringSync();
    expect(source, contains("'device_auth_token'"));

    final logoutStart = source.indexOf('Future<bool> _sendLogoutToHub(');
    final logoutEnd =
        source.indexOf('Future<bool> _queuePendingLogout(', logoutStart);
    expect(logoutStart, greaterThanOrEqualTo(0));
    expect(logoutEnd, greaterThan(logoutStart));
    final logoutBody = source.substring(logoutStart, logoutEnd);
    expect(logoutBody, contains("'Authorization'"));
    expect(
        logoutBody, contains("headers['Authorization'] = 'Bearer \$token';"));
    // Missing token must degrade gracefully (no unauthenticated mutation
    // call), not crash and not silently proceed.
    expect(logoutBody, contains('if (token.isEmpty)'));
    expect(logoutBody, contains('return false;'));
    // The raw token value must only ever be interpolated into the
    // Authorization header, never into a debug/log message.
    expect('\$token'.allMatches(logoutBody).length, 1);
  });

  test(
      'L-1: _queuePendingLogout reports durability via a write-then-'
      'read-back comparison instead of swallowing a write failure', () {
    final source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf('Future<bool> _queuePendingLogout(');
    final end = source.indexOf('Future<void> _retryPendingLogout()', start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final body = source.substring(start, end);

    // The pre-fix bug: this returned void and a caught write failure was
    // only logged, never reported to the caller.
    expect(body, contains("await _writeSensitiveText('pending_logout.json'"));
    expect(
      body,
      contains("await _readSensitiveText('pending_logout.json') == encoded"),
    );
    expect(body, contains('catch (e)'));
    expect(body, contains('return false;'));
  });

  test(
      'L-1: deactivation only deletes local credentials after a '
      'server-confirmed logout or a verified pending-logout queue write, '
      'and otherwise aborts with the audit-specified message', () {
    final source = File('lib/main.dart').readAsStringSync();
    final start =
        source.indexOf('Future<void> _deactivateCurrentDevice() async {');
    final end = source.indexOf('// Account deletion', start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final body = source.substring(start, end);

    var cursor = 0;
    void expectInOrder(String needle) {
      final index = body.indexOf(needle, cursor);
      expect(index, greaterThanOrEqualTo(cursor),
          reason: 'expected "$needle" after offset $cursor in the '
              'Deactivate Device handler');
      cursor = index + needle.length;
    }

    expectInOrder('final epoch = _beginAccountTeardown();');
    expectInOrder('await _writeAccountCleanupJournal(journal, epoch);');
    expectInOrder('if (!await _stopAndProveTunnelInactive()');
    expectInOrder('final logoutOk = await _sendLogoutToHub(');
    expectInOrder('if (logoutOk) {');
    expectInOrder('} else if (!await _queuePendingLogout(');
    expectInOrder(
        "'Could not safely queue server cleanup. No credentials were erased.'");
    expectInOrder('return;');
    expectInOrder("..remove('pending_logout');");
    expectInOrder("journal = journal.copyWith(phase: 'purging');");
    expectInOrder('if (!await _runAccountCleanup(journal, epoch))');
    expectInOrder('_resetAccountUiAfterVerifiedCleanup();');
  });

  test(
      'H-1: device_auth_token persists via a strict mutate-then-durable-'
      'read-back path instead of a silently swallowed write', () {
    final source = File('lib/main.dart').readAsStringSync();
    final start =
        source.indexOf('Future<void> _persistDeviceAuthTokenRequired(');
    final end = source.indexOf('Future<bool> _sendLogoutToHub(', start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final body = source.substring(start, end);

    // The pre-fix bug: device_auth_token was written inside
    // _saveVpnRuntimeSettings' single bare try/catch, so a secure-storage
    // write failure there was silently swallowed and the caller proceeded
    // as if the token had been saved.
    expect(body, isNot(contains('try {')));
    expect(body, isNot(contains('catch (e)')));
    expect(body, contains('_mutateVpnRuntimeSettings('));
    // Must not route the read-back through either general-purpose reader:
    // both swallow read failures (see the M-7 tests above and the "secure
    // settings read awaits native failures" test) for the many unrelated,
    // best-effort settings they back.
    expect(body, isNot(contains('_readVpnRuntimeSettings()')));
    expect(body, isNot(contains('_readDeviceAuthToken()')));
    expect(body, contains('await _settingsMutationQueue;'));
    expect(body, contains("_readSensitiveJsonMap('vpn_settings.txt')"));
    // A write that is acknowledged but does not durably stick must still
    // be treated as a failure rather than silently accepted, exactly like
    // _writePinAttemptState's own durable read-back (M-7).
    expect(body, contains('persisted != trimmed'));
    expect(body, contains('throw StateError('));
    // Empty/too-short tokens must be rejected before ever attempting the
    // write.
    expect(body, contains('trimmed.length < 16'));
  });

  test(
      'H-1: device_auth_token is no longer part of the best-effort '
      '_saveVpnRuntimeSettings snapshot, and _onAuthSuccess persists it '
      'strictly before login can succeed', () {
    final source = File('lib/main.dart').readAsStringSync();

    final saveStart = source.indexOf('Future<void> _saveVpnRuntimeSettings({');
    final saveEnd =
        source.indexOf('Future<bool> _readNativeTunnelActive()', saveStart);
    expect(saveStart, greaterThanOrEqualTo(0));
    expect(saveEnd, greaterThan(saveStart));
    final saveBody = source.substring(saveStart, saveEnd);

    // The pre-fix bug lived here: device_auth_token used to be one of the
    // fields this function's single bare try/catch could silently swallow
    // a write failure for.
    expect(saveBody, isNot(contains('deviceAuthToken')));
    expect(saveBody, isNot(contains("data['device_auth_token']")));

    final authStart = source.indexOf('Future<void> _onAuthSuccess(');
    final authEnd =
        source.indexOf('Future<bool> _refreshFreeVpnConfig(', authStart);
    expect(authStart, greaterThanOrEqualTo(0));
    expect(authEnd, greaterThan(authStart));
    final authBody = source.substring(authStart, authEnd);

    // Not caught anywhere inside _onAuthSuccess: a failure must propagate
    // out to the login flow's existing try/catch instead of being
    // swallowed here, exactly like _storeUserPin's own StateError (right
    // above the new call) already does today.
    expect(authBody, isNot(contains('try {')));

    var cursor = 0;
    void expectInOrder(String needle) {
      final index = authBody.indexOf(needle, cursor);
      expect(index, greaterThanOrEqualTo(cursor),
          reason: 'expected "$needle" after offset $cursor in _onAuthSuccess');
      cursor = index + needle.length;
    }

    expectInOrder('if (deviceAuthToken != null) {');
    expectInOrder('await _persistDeviceAuthTokenRequired(deviceAuthToken);');
    expectInOrder('await _storeUserPin(pin);');
    expectInOrder('await _persistVpnConfigRequired(normalizedConfig);');
    expectInOrder('await _saveActivationSettingsRequired(');
    expectInOrder('await _writeActivationCompleteMarker(');
  });

  // H-1 follow-up (this session): the owner asked for genuine behavioral
  // fault injection -- mock the native secure-state write to throw, drive
  // the real login code, and observe login not succeed -- if at all
  // feasible, instead of only the structural proofs above. It was
  // investigated in depth and is not feasible from this test file. Both
  // reasons below are independently sufficient; together they rule it out:
  //
  // 1. Hard wall: _onAuthSuccess and _persistDeviceAuthTokenRequired are
  //    members of _VpnDashboardBodyState, a library-private class (leading
  //    underscore) declared inside lib/main.dart. Dart privacy is
  //    per-library (per-file): a test file that does
  //    `import 'package:wins_vpn/main.dart'` is a different library and
  //    cannot name that class or call either method directly -- it is a
  //    compile-time restriction, not a design inconvenience. There is no
  //    @visibleForTesting export, no public wrapper, and no separate
  //    testable auth module (every other file under lib/ is an unrelated,
  //    narrowly-scoped helper; the account-activation/login logic exists
  //    only inside this one private State class). The only way to make
  //    either method run at all is to trigger it indirectly through the
  //    real login UI inside a testWidgets test.
  //
  // 2. That remaining route is not realistically usable either. Reaching
  //    _onAuthSuccess means driving _loginWithAccountNumber or
  //    _loginWithFreeAccess all the way through: accepting the privacy
  //    policy dialog (every existing testWidgets test in this suite
  //    deliberately DECLINES it instead -- see declineFirstRunPrivacyPolicy
  //    in test/widget_test.dart -- because accepting it flips on
  //    _startPostPrivacyConsentInitialization, which fires a cascade of
  //    *unawaited* concurrent background calls: _loadDeviceHardwareDetails,
  //    _determineSecurityOnboardingLayer, _startStatusHeartbeat,
  //    _loadCachedNodesFromDisk, _fetchAvailableNodes,
  //    _fetchPreVpnCountryCode, _retryPendingLogout -- several of which
  //    make their own native MethodChannel calls (getDeviceHardwareDetails,
  //    checkDialerLaunch, loadOrCreateInstallId, getTunnelState /
  //    getTunnelReadiness) and HTTP calls outside the test's control); the
  //    legal-acceptance dialog (_ensureLegalAcceptanceForActivation);
  //    dynamic gateway resolution over HTTP (_resolveDynamicEndpoints, an
  //    obfuscated recovery-record URL); and finally the login POST itself
  //    returning a synthetic 200 "authenticated" body. None of this --
  //    accepting consent, the legal dialog, or any HTTP mocking at all --
  //    has any precedent anywhere in test/*.dart: grepping the whole suite
  //    for HttpOverrides/MockClient/runWithClient returns zero hits. The
  //    only fault-injection-shaped precedent that does exist is
  //    test/widget_test.dart's TestDefaultBinaryMessengerBinding mock of
  //    the 'wins_vpn/tunnel' channel -- and even there every case in its
  //    switch returns success (`return true;` for every write/delete);
  //    nothing in the suite has ever actually flipped one of those cases
  //    to throw and observed the effect on app state. Building all of the
  //    above from scratch just to reach two lines of a private method
  //    would produce a large, brittle test whose failures would as often
  //    come from unrelated startup-plumbing drift as from a genuine H-1
  //    regression.
  //
  // This is the same tradeoff the M-7 fix's own author already made for a
  // shallower-reach sibling case (the PIN-attempt ledger, reachable via the
  // PIN-entry UI alone with no network/consent/legal gate at all), recorded
  // in FINAL_RECOMMENDATIONS_FIX_HANDOFF_20260722.md: "It's *not* a test of
  // the actual fail-closed-on-storage-error behavior itself (hard to
  // trigger genuine storage faults through UI alone) -- that part is
  // covered by the source-contract tests instead, which is the right tool
  // for an error-injection scenario like this." H-1's target sits behind
  // strictly more gates than that one did (network + consent + legal
  // acceptance, none of which M-7's PIN path needs at all), so the same
  // conclusion follows with more force, not less.
  //
  // So instead, this test strengthens the structural proof into an
  // explicit chain-of-custody argument. The two H-1 tests above already
  // establish (a) _persistDeviceAuthTokenRequired has no try/catch and a
  // durable read-back that throws on any failure or mismatch, and (b)
  // _onAuthSuccess has no try/catch anywhere in its body and calls it in a
  // fixed statement order. What follows closes the remaining gap: it
  // proves, reading forward from the token-persistence call to both of its
  // real call sites, that (a) nothing _onAuthSuccess does to mark login
  // successful or persist the VPN config can execute before that call
  // returns, and (b) the exception it throws on failure lands in a caller
  // catch clause that never sets the success flag either -- i.e. every
  // path from "token write fails" to "login result the app can observe"
  // runs through code that fails the login, with no bypass.
  test(
      'H-1: chain-of-custody -- a thrown token-persistence failure is '
      'structurally guaranteed to skip every success/config-persistence '
      'statement in _onAuthSuccess and land in a caller catch that never '
      'marks login successful', () {
    final source = File('lib/main.dart').readAsStringSync();

    // --- Inside _onAuthSuccess: every success-shaped statement is
    // strictly after the token-persistence call, in code with no
    // try/catch anywhere in the function, so a throw there skips all of
    // it (StateError propagates straight out to the caller). ---
    final authStart = source.indexOf('Future<void> _onAuthSuccess(');
    final authEnd =
        source.indexOf('Future<bool> _refreshFreeVpnConfig(', authStart);
    expect(authStart, greaterThanOrEqualTo(0));
    expect(authEnd, greaterThan(authStart));
    final authBody = source.substring(authStart, authEnd);
    expect(authBody, isNot(contains('try {')));

    var authCursor = 0;
    void expectAuthInOrder(String needle) {
      final index = authBody.indexOf(needle, authCursor);
      expect(index, greaterThanOrEqualTo(authCursor),
          reason:
              'expected "$needle" after offset $authCursor in _onAuthSuccess');
      authCursor = index + needle.length;
    }

    expectAuthInOrder(
        'await _persistDeviceAuthTokenRequired(deviceAuthToken);');
    // Neither VPN-config persistence nor the logged-in flag may appear
    // before the token-persistence call above.
    expectAuthInOrder('await _persistVpnConfigRequired(normalizedConfig);');
    expectAuthInOrder('await _saveActivationSettingsRequired(');
    expectAuthInOrder('await _writeActivationCompleteMarker(');
    // The success state lives in a local closure, applied through setState
    // when mounted and directly otherwise. A closure could be called early,
    // so pin both that it is first mentioned after the token write and that
    // both applications come after its definition.
    final persistCall =
        authBody.indexOf('await _persistDeviceAuthTokenRequired(deviceAuthToken);');
    expect(authBody.indexOf('applyAuthSuccessState'), greaterThan(persistCall),
        reason: 'applyAuthSuccessState is referenced before token persistence');
    expectAuthInOrder('void applyAuthSuccessState() {');
    expectAuthInOrder('_isLoggedIn = true;');
    expectAuthInOrder('setState(applyAuthSuccessState);');
    expectAuthInOrder('applyAuthSuccessState();');

    // --- Caller 1: _loginWithAccountNumber's per-gateway try/catch.
    // Verified fresh against the current source (not assumed from an
    // earlier description): the call sits inside the per-gateway `try`,
    // whose `catch` only logs and lets the `for` loop move on to the next
    // gateway URL -- it never sets the success flag. Once every gateway
    // has been tried without a persisted login, the function falls
    // through to a visible failure message instead of silently returning
    // as if login had succeeded. ---
    final loginStart =
        source.indexOf('Future<void> _loginWithAccountNumber() async {');
    final loginEnd =
        source.indexOf('Map<String, dynamic> _freeAccessPayload(', loginStart);
    expect(loginStart, greaterThanOrEqualTo(0));
    expect(loginEnd, greaterThan(loginStart));
    final loginBody = source.substring(loginStart, loginEnd);

    var loginCursor = 0;
    void expectLoginInOrder(String needle) {
      final index = loginBody.indexOf(needle, loginCursor);
      expect(index, greaterThanOrEqualTo(loginCursor),
          reason: 'expected "$needle" after offset $loginCursor in '
              '_loginWithAccountNumber');
      loginCursor = index + needle.length;
    }

    expectLoginInOrder('for (var url in gateways) {');
    expectLoginInOrder('try {');
    expectLoginInOrder('await _onAuthSuccess(');
    expectLoginInOrder('responseData,');
    expectLoginInOrder('rawToken,');
    expectLoginInOrder('customPin,');
    expectLoginInOrder('clientKeys,');
    expectLoginInOrder('activationEpoch,');
    expectLoginInOrder('return;');
    expectLoginInOrder('} catch (e) {');
    expectLoginInOrder(r'_debugLog("Pathfinder: Gateway $url failed: $e");');
    // No code path anywhere in this function -- including its catch
    // clause -- sets the success flag directly; the only route to
    // _isLoggedIn becoming true is _onAuthSuccess running to completion.
    expect(loginBody, isNot(contains('_isLoggedIn')));
    expect(
        loginBody,
        contains(
            'Could not reach Wins Hub through the protected gateway network'));

    // --- Caller 2: _loginWithFreeAccess's outer try/catch. Verified
    // fresh against the current source: the call sits inside a single
    // outer `try`, whose `catch` shows a direct, specific failure message
    // and never sets the success flag either. ---
    final freeStart =
        source.indexOf('Future<void> _loginWithFreeAccess() async {');
    final freeEnd = source.indexOf('Future<void> _onAuthSuccess(', freeStart);
    expect(freeStart, greaterThanOrEqualTo(0));
    expect(freeEnd, greaterThan(freeStart));
    final freeBody = source.substring(freeStart, freeEnd);
    final normalizedFreeBody = _normalizeSourceWhitespace(freeBody);

    var freeCursor = 0;
    void expectFreeInOrder(String needle) {
      final index = normalizedFreeBody.indexOf(needle, freeCursor);
      expect(index, greaterThanOrEqualTo(freeCursor),
          reason: 'expected "$needle" after offset $freeCursor in '
              '_loginWithFreeAccess');
      freeCursor = index + needle.length;
    }

    expectFreeInOrder('try {');
    expectFreeInOrder('await _onAuthSuccess(');
    expectFreeInOrder('return;');
    expectFreeInOrder('} catch (e) {');
    expectFreeInOrder(r"_debugLog('Free access failed: $e');");
    expectFreeInOrder(
        "_showFeedback('Free server setup could not be completed. Check your connection and try again, or contact support if it keeps failing.');");
    expect(freeBody, isNot(contains('_isLoggedIn')));
  });

  test('Windows never falls back to a shared temporary state directory', () {
    final source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf('Future<Directory> _appDocumentsDirectory()');
    final end =
        source.indexOf('Future<void> _persistVpnConfigBestEffort(', start);
    final body = source.substring(start, end);
    expect(body, contains("Platform.environment['APPDATA']?.trim()"));
    expect(body, contains('Windows application data directory is unavailable'));
    expect(
      body,
      isNot(contains(
          "Platform.environment['APPDATA'] ?? Directory.systemTemp.path")),
    );
  });

  test('secure settings read awaits native failures inside its catch boundary',
      () {
    final source = File('lib/main.dart').readAsStringSync();
    final start = source.indexOf(
      'Future<Map<String, dynamic>> _readVpnRuntimeSettings() async',
    );
    final end = source.indexOf(
      'Future<void> _mutateVpnRuntimeSettings(',
      start,
    );
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));

    final body = source.substring(start, end);
    expect(
      body,
      contains("return await _readSensitiveJsonMap('vpn_settings.txt');"),
    );
    expect(
      body,
      isNot(contains("return _readSensitiveJsonMap('vpn_settings.txt');")),
    );
    expect(body, contains(r"_debugLog('Settings read failed: $e');"));
  });

  test('diagnostic redaction covers IPv6 hex and URL-safe tokens', () {
    const hex =
        '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    const token =
        'abcdefghijklmnopqrstuvwx.yzABCDEFGHIJKLMNOPQRSTUV.0123456789abcdefghijkl';
    const urlSafeKey = 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdEfGhIjKlMn';
    final redacted = redactTunnelFailureText(
      'peer 2001:db8:85a3::8a2e:370:7334 key $hex token $token urlsafe $urlSafeKey',
    );
    expect(redacted, isNot(contains('2001:db8')));
    expect(redacted, isNot(contains(hex)));
    expect(redacted, isNot(contains(token)));
    expect(redacted, isNot(contains(urlSafeKey)));
    expect(redacted, contains('<ip>'));
    expect(redacted, contains('<key>'));
    expect(redacted, contains('<token>'));
  });

  test('diagnostic redaction covers tunnel URIs credentials hosts and paths',
      () {
    const input = 'wss://alice:secret@carrier.example.com:443/ws '
        'vless://01234567-89ab-cdef-0123-456789abcdef@edge.example.net:80 '
        'socks5://bob:proxy-pass@socks.example.net:1080 '
        'alice:another-secret@proxy.example.org:1080 '
        'fallback.example.com:8443 '
        r'/Users/operator/Library/Application Support/WinsVPN/config.json '
        r'C:\Users\operator\AppData\Roaming\WinsVPN\config.json';
    final redacted = redactTunnelFailureText(input);

    for (final sensitive in <String>[
      'alice',
      'secret',
      'carrier.example.com',
      'edge.example.net',
      'socks.example.net',
      'proxy-pass',
      'proxy.example.org',
      'fallback.example.com',
      '/Users/operator',
      r'C:\Users\operator',
    ]) {
      expect(redacted, isNot(contains(sensitive)));
    }
    expect(redacted, contains('<url>'));
    expect(redacted, contains('<credential>'));
    expect(redacted, contains('<host>'));
    expect(redacted, contains('<path>'));
  });

  test('diagnostic redaction does not classify timestamps as IPv6', () {
    final redacted = redactTunnelFailureText(
      'attempt started at 12:34:56 and ended at 23:59:59',
    );
    expect(redacted, contains('12:34:56'));
    expect(redacted, contains('23:59:59'));
    expect(redacted, isNot(contains('<ip>')));
  });

  test(
      'paid refresh reuses an accepted key and setup-key activation stages '
      'rotation until authorization', () {
    final source = File('lib/main.dart').readAsStringSync();
    final normalizedSource = _normalizeSourceWhitespace(source);
    expect(normalizedSource, isNot(contains('rotate: true')));
    expect(normalizedSource, contains('_loadExistingClientKeyPair(token)'));
    expect(normalizedSource, contains('await _readDeviceAuthToken()'));
    expect(normalizedSource,
        contains('headers: verifyRequest.headers, body: verifyRequest.body'));
    expect(
        normalizedSource, contains('_stageClientKeyPairCandidate(rawToken)'));
    expect(normalizedSource,
        contains('_commitClientKeyPairCandidate(rawToken, clientKeys)'));

    // The reconnect preflight also resumes the persisted identity so it still
    // matches the persisted vpn_config.
    final preflightLoad = normalizedSource.indexOf(
        '_loadExistingClientKeyPair(await _effectiveAccountScopeForKeyPair(),');
    expect(preflightLoad, greaterThanOrEqualTo(0));
    final preflightSegment =
        normalizedSource.substring(preflightLoad, preflightLoad + 140);
    expect(preflightSegment, contains('_effectiveAccountScopeForKeyPair'));
    expect(preflightSegment, isNot(contains('rotate')));
  });
}
