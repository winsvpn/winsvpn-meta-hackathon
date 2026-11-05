// CORE-36 (Sol's required verification): the account status refresh is one
// flight per account epoch. The production entry, the production request
// body and the production background helper run verbatim in a child program;
// only storage, the network and the account handlers are stubs. The
// credential read is held BEFORE the body stamps its sync clock, so every
// caller arrives while the 45 s throttle still reads as due.
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

String _between(String source, String start, String end) {
  final first = source.indexOf(start);
  final last = source.indexOf(end, first + start.length);
  if (first < 0 || last <= first) {
    throw StateError('Could not extract production method: $start');
  }
  return source.substring(first, last);
}

const _harness = r'''
import 'dart:async';
import 'dart:convert';

class _Response {
  _Response(this.statusCode, this.body);
  final int statusCode;
  final String body;
}

class _Client {
  final List<Completer<_Response>> posts = <Completer<_Response>>[];
  final List<String> postBodies = <String>[];
  Future<_Response> post(Uri url, {Map<String, String>? headers, Object? body}) {
    final reply = Completer<_Response>();
    posts.add(reply);
    postBodies.add('$body');
    return reply.future;
  }

  Future<_Response> get(Uri url) => Completer<_Response>().future;
}

class _Epoch {
  int current = 1;
}

class Harness {
  final _accountSessionEpoch = _Epoch();
  bool _accountEpochIsCurrent(int epoch) =>
      _accountSessionEpoch.current == epoch;
  bool _privacyConsentGranted = true;
  bool _isLoggedIn = true;
  bool _isFreeAccessSession = false;
  bool mounted = true;
  void setState(void Function() change) => change();
  bool _accountExpiredTerminal = false;
  DateTime _lastAccountStatusSync = DateTime.fromMillisecondsSinceEpoch(0);
  int? _accountStatusRefreshEpoch;
  Future<bool>? _accountStatusRefreshInFlight;
  int? _accountStatusThrottleEpoch;
  String _serverAnnouncement = '';
  String _expirationDate = '';
  String _referralCode = '';
  String _referralLink = '';
  String _referralBackupLink = '';
  String _appScopedDeviceId = 'device-a';
  final _controlPlaneClient = _Client();
  void _debugLog(String message) {}
  Map<String, String> _jsonHeaders() => <String, String>{};
  Future<Map<String, String>> _resolveDynamicEndpoints() async =>
      <String, String>{'gateway': 'https://gateway.invalid'};
  void _noteGatewaySweepSuccess(String url) {}
  void _noteGatewaySweepFailure() {}

  // The account the store holds. Its read can be held open.
  String account = '111122223333';
  Completer<void>? credentialGate;
  int credentialReads = 0;
  Future<String> _currentAccountNumberForRefresh() async {
    credentialReads++;
    final held = account;
    final gate = credentialGate;
    if (gate != null) await gate.future;
    return held;
  }

  Future<String?> _readDeviceAuthToken() async => 'device-token';

  // What a sweep did to the app's account state.
  final List<String> revoked = <String>[];
  final List<int> applied = <int>[];
  final List<String?> saved = <String?>[];
  Future<void> _handleTrustedRevokedAccount(
    int expectedEpoch,
    String accountNumber, {
    String reason = '',
  }) async {
    revoked.add('$expectedEpoch:$accountNumber');
  }

  Future<void> _handleTrustedExpiredAccount(
      int expectedEpoch, String accountNumber) async {}
  Future<void> _applyAccountSyncData(
      Map<String, dynamic> data, int expectedEpoch) async {
    applied.add(expectedEpoch);
  }

  Future<void> _saveVpnRuntimeSettings({
    String? accountNumber,
    String? announcement,
    String? expiration,
    String? referralCode,
    String? referralLink,
    String? referralBackupLink,
    bool? freeAccessSession,
    String? accountTerminalStatus,
  }) async {
    saved.add(accountNumber);
  }
''';

const _harnessEnd = r'''
}

void check(bool condition, String message) {
  if (!condition) throw StateError(message);
}

Future<void> settle() async {
  for (var i = 0; i < 20; i++) {
    await Future<void>.delayed(Duration.zero);
  }
}

Future<void> oneFlightPerEpoch() async {
  final h = Harness();
  h.credentialGate = Completer<void>();
  final epoch = h._accountSessionEpoch.current;
  // Foreground and background callers, forced and unforced, together.
  final callers = <Future<Object?>>[
    h._runBackgroundSecurityHeartbeat(),
    h._refreshAccountStatus(expectedEpoch: epoch),
    h._refreshAccountStatus(force: true, expectedEpoch: epoch),
    h._refreshAccountStatus(force: true),
    h._runBackgroundSecurityHeartbeat(),
  ];
  await settle();
  check(h.credentialReads == 1,
      '${h.credentialReads} sweeps started for one account epoch, not 1');
  h.credentialGate!.complete();
  h.credentialGate = null;
  await settle();
  check(h._controlPlaneClient.posts.length == 1,
      '${h._controlPlaneClient.posts.length} status requests, not 1');
  h._controlPlaneClient.posts.single
      .complete(_Response(200, jsonEncode({'status': 'active'})));
  await Future.wait(callers);
  check(h.applied.length == 1 && h.applied.single == epoch,
      'applied ${h.applied}');
  // Landed: an unforced caller inside 45 s makes none, a forced one makes one.
  check(await h._refreshAccountStatus(expectedEpoch: epoch),
      'the throttled caller reported failure');
  check(h.credentialReads == 1, 'the 45 s throttle let a sweep through');
  final forced = h._refreshAccountStatus(force: true, expectedEpoch: epoch);
  await settle();
  check(h.credentialReads == 2, 'a forced caller after the sweep was dropped');
  h._controlPlaneClient.posts.last
      .complete(_Response(200, jsonEncode({'status': 'active'})));
  check(await forced, 'the forced sweep failed');
  print('PASS one flight per epoch');
}

Future<void> replacedAccountIsUntouched() async {
  final h = Harness();
  final oldEpoch = h._accountSessionEpoch.current;
  final oldSweep = h._runBackgroundSecurityHeartbeat();
  await settle();
  check(h._controlPlaneClient.posts.length == 1, 'the old sweep sent nothing');
  // The account is replaced while the old sweep's request is in flight.
  h._accountSessionEpoch.current++;
  final newEpoch = h._accountSessionEpoch.current;
  h.account = '444455556666';
  h.credentialGate = Completer<void>();
  final newSweep = h._refreshAccountStatus(force: true);
  await settle();
  check(h.credentialReads == 2,
      'the replacement account waited on the old sweep');
  // The old sweep now lands with revocation data for the OLD account.
  h._controlPlaneClient.posts.first.complete(_Response(401, ''));
  await oldSweep;
  await settle();
  check(h.revoked.isEmpty, 'the old sweep revoked ${h.revoked}');
  check(h.applied.isEmpty && h.saved.isEmpty,
      'the old sweep wrote account state');
  // Its completion left the replacement's flight in place: a joiner issues
  // no second sweep.
  final joiner = h._refreshAccountStatus(expectedEpoch: newEpoch);
  await settle();
  check(h.credentialReads == 2, 'the old completion released the new flight');
  h.credentialGate!.complete();
  h.credentialGate = null;
  await settle();
  check(h._controlPlaneClient.posts.length == 2,
      '${h._controlPlaneClient.posts.length} requests');
  check(h._controlPlaneClient.postBodies.last.contains('444455556666'),
      'the replacement sweep carried the old account');
  h._controlPlaneClient.posts.last
      .complete(_Response(200, jsonEncode({'status': 'active'})));
  check(await newSweep && await joiner, 'the replacement sweep failed');
  check(h.revoked.isEmpty, 'revoked ${h.revoked}');
  check(h.applied.length == 1 && h.applied.single == newEpoch,
      'applied ${h.applied}');
  check(h.saved.length == 1 && h.saved.single == '444455556666',
      'saved ${h.saved}');
  check(await h._refreshAccountStatus(expectedEpoch: oldEpoch) == false,
      'a call for the replaced account was admitted');
  check(h.credentialReads == 2, 'a sweep ran for the replaced account');
  print('PASS replaced account untouched');
}

Future<void> main() async {
  await oneFlightPerEpoch();
  await replacedAccountIsUntouched();
}
''';

void main() {
  final source = File('lib/main.dart').readAsStringSync();

  test('account status refresh: one flight per account epoch', () async {
    final helper = _between(
      source,
      '  Future<void> _runBackgroundSecurityHeartbeat() async {',
      '  /// One foreground tick (CORE-36, ruling A2).',
    );
    final refresh = _between(
      source,
      '  Future<bool> _refreshAccountStatus({',
      '  /// Clears every Product surface that would outlive the swap',
    );
    final temporary = await Directory.systemTemp.createTemp('wins-status-');
    try {
      final program = File('${temporary.path}/status.dart');
      final failover = File('lib/gateway_failover.dart').absolute.uri;
      final revocation =
          File('lib/account_status_revocation.dart').absolute.uri;
      await program.writeAsString("import '$failover';\n"
          "import '$revocation';\n"
          '$_harness$helper$refresh$_harnessEnd');
      final result = await Process.run(
        Platform.environment['DART_EXECUTABLE'] ?? 'dart',
        <String>[program.path],
      );
      expect(result.exitCode, 0, reason: '${result.stdout}\n${result.stderr}');
      expect(result.stdout.toString(), contains('PASS one flight per epoch'));
      expect(
          result.stdout.toString(), contains('PASS replaced account untouched'));
    } finally {
      await temporary.delete(recursive: true);
    }
  });
}
