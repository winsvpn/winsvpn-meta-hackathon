// Behavioural coverage for hub-driven revocation. The two production methods
// (_handleTrustedRevokedAccount, _refreshAccountStatus) run VERBATIM from
// lib/main.dart against a scripted control-plane client, so a change to the
// branch that turns a 404/401 or a cancelled/deleted/revoked status into a
// device deactivation is a red test, not a surviving substring.
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

String _between(String source, String start, String end) {
  final first = source.indexOf(start);
  final last = source.indexOf(end, first + start.length);
  if (first < 0 || last <= first) {
    throw StateError('Could not extract production code: $start');
  }
  return source.substring(first, last);
}

void main() {
  late Directory temporary;
  late File executable;

  setUpAll(() async {
    final source = File('lib/main.dart').readAsStringSync();
    final revoked = _between(
        source,
        '  Future<void> _handleTrustedRevokedAccount(',
        '  Future<bool> _refreshAccountStatus({');
    final refresh = _between(
        source,
        '  Future<bool> _refreshAccountStatus({',
        '  /// Clears every Product surface that would outlive the swap to the decoy');
    // C-core-9: the top-level revocation-marker helper the 401/404 branch
    // calls. Extracted verbatim so the harness runs the shipping rule.
    // The pure-Dart helper lives in its own library so the verbatim
    // selection harness region of main.dart stays Flutter-free.
    final marker = File('lib/account_status_revocation.dart')
        .readAsStringSync()
        .replaceFirst("import 'dart:convert';\n", '');
    temporary =
        await Directory.systemTemp.createTemp('account-revocation-behaviour-');
    executable = File('${temporary.path}/revocation.dart');
    await executable.writeAsString('''
import 'dart:async';
import 'dart:convert';

class Response {
  Response(this.statusCode, this.body);
  final int statusCode;
  final String body;
}

class GatewayEndpoints {
  const GatewayEndpoints({required this.gateway});
  final String gateway;
}

List<String> accountStatusGateways(GatewayEndpoints e) =>
    <String>['\${e.gateway}/account/status', 'https://backup.example/account/status'];
List<String> freeStatusGateways(GatewayEndpoints e) =>
    <String>['\${e.gateway}/free/status'];

class ScriptedClient {
  ScriptedClient(this.script);
  final Response Function(String url) script;
  final List<String> urls = <String>[];
  Future<Response> get(Uri url) async {
    urls.add(url.toString());
    return script(url.toString());
  }
  Future<Response> post(Uri url, {Map<String, String>? headers, Object? body}) async {
    urls.add(url.toString());
    return script(url.toString());
  }
}

class Epoch {
  int current = 1;
  bool isCurrent(int epoch) => epoch == current;
}

$marker
class H {
  H(this._controlPlaneClient);
  final ScriptedClient _controlPlaneClient;
  final Epoch _accountSessionEpoch = Epoch();
  bool mounted = true;
  bool _isFreeAccessSession = false;
  bool _accountExpiredTerminal = false;
  DateTime _lastAccountStatusSync = DateTime.fromMillisecondsSinceEpoch(0);
  int? _accountStatusThrottleEpoch;
  int? _accountStatusRefreshEpoch;
  Future<bool>? _accountStatusRefreshInFlight;
  String _appScopedDeviceId = 'device-1';
  String account = '111122223333';
  String? deviceToken = 'bearer-token';
  String _serverAnnouncement = '';
  DateTime? _expirationDate;
  String _referralCode = '';
  String _referralLink = '';
  String _referralBackupLink = '';
  final List<String> feedback = <String>[];
  final List<String> saved = <String>[];
  int deactivations = 0;
  int expiredHandled = 0;
  int sweepSuccess = 0;
  int sweepFailure = 0;
  int applied = 0;

  void setState(void Function() fn) => fn();
  void _debugLog(String message) {}
  void _showFeedback(String message) => feedback.add(message);
  bool _accountEpochIsCurrent(int epoch) => _accountSessionEpoch.isCurrent(epoch);
  Future<void> _deactivateCurrentDevice() async => deactivations++;
  Future<void> _handleTrustedExpiredAccount(int epoch, String token) async =>
      expiredHandled++;
  Future<Map<String, String>> _resolveDynamicEndpoints() async =>
      <String, String>{'gateway': 'https://primary.example'};
  Future<String> _currentAccountNumberForRefresh() async => account;
  Future<String?> _readDeviceAuthToken() async => deviceToken;
  Map<String, String> _jsonHeaders() => <String, String>{'Content-Type': 'application/json'};
  void _noteGatewaySweepSuccess(String url) => sweepSuccess++;
  void _noteGatewaySweepFailure() => sweepFailure++;
  Future<void> _applyAccountSyncData(Map<String, dynamic> data, int epoch) async =>
      applied++;
  Future<void> _saveVpnRuntimeSettings({
    String? accountNumber,
    String? announcement,
    DateTime? expiration,
    String? referralCode,
    String? referralLink,
    String? referralBackupLink,
    String? accountTerminalStatus,
    bool? freeAccessSession,
  }) async {
    saved.add('status=\$accountTerminalStatus');
  }

$revoked
$refresh
}

void check(bool ok, String message) {
  if (!ok) throw StateError(message);
}

Response json(int status, Map<String, dynamic> body) =>
    Response(status, jsonEncode(body));

Future<void> main(List<String> args) async {
  final scenario = args.single;
  switch (scenario) {
    case 'control_ok_keeps_device':
      final h = H(ScriptedClient((_) => json(200, {'status': 'ok'})));
      final ok = await h._refreshAccountStatus(force: true);
      check(ok, 'an ok status must report success');
      check(h.deactivations == 0, 'ok must not deactivate');
      check(h.applied == 1, 'ok must apply the sync data');
    case 'http_404_deactivates':
      final h = H(ScriptedClient((_) => json(404, {'detail': 'Account not found'})));
      final ok = await h._refreshAccountStatus(force: true);
      check(!ok, '404 must not report success');
      check(h.deactivations == 1, '404 must deactivate exactly once: \${h.deactivations}');
      check(h.feedback.length == 1, 'the user must be told once: \${h.feedback}');
      check(h._controlPlaneClient.urls.length == 1, 'a trusted 404 must end the sweep');
    case 'http_401_deactivates':
      final h = H(ScriptedClient((_) => json(401, {'detail': 'Unauthorized'})));
      await h._refreshAccountStatus(force: true);
      check(h.deactivations == 1, '401 must deactivate: \${h.deactivations}');
    case 'bare_404_is_a_failed_front':
      // C-core-9: a route-missing 404, an HTML error page or a bare 401 from
      // one front is that front failing, never a verdict on the account.
      for (final r in <Response>[
        json(404, {'detail': 'Not Found'}),
        Response(404, '<!DOCTYPE html><p>404</p>'),
        Response(401, ''),
      ]) {
        final h = H(ScriptedClient((url) => url.startsWith('https://primary')
            ? r
            : json(200, {'status': 'ok'})));
        final ok = await h._refreshAccountStatus(force: true);
        check(h.deactivations == 0, 'a markerless \${r.statusCode} must not deactivate');
        check(ok && h.applied == 1, 'the next front must be tried and applied');
        check(h._controlPlaneClient.urls.length == 2, 'the sweep must continue');
      }
    case 'status_strings_deactivate':
      for (final status in <String>['cancelled', 'canceled', 'deleted', 'revoked', 'suspended', 'not_found']) {
        final h = H(ScriptedClient((_) => json(200, {'status': status})));
        await h._refreshAccountStatus(force: true);
        check(h.deactivations == 1, '\$status must deactivate: \${h.deactivations}');
        check(h.expiredHandled == 0, '\$status must not be treated as expired');
      }
    case 'expired_is_terminal_not_revocation':
      final h = H(ScriptedClient((_) => json(200, {'status': 'expired'})));
      final ok = await h._refreshAccountStatus(force: true);
      check(ok, 'expired is a trusted sync result');
      check(h.expiredHandled == 1 && h.deactivations == 0, 'expired must not purge credentials');
    case 'stale_epoch_never_deactivates':
      final h = H(ScriptedClient((_) => Response(404, '')));
      final epoch = h._accountSessionEpoch.current;
      h._accountSessionEpoch.current = epoch + 1;
      await h._refreshAccountStatus(force: true, expectedEpoch: epoch);
      check(h.deactivations == 0, 'a stale epoch must not tear down the new session');
      check(h._controlPlaneClient.urls.isEmpty, 'a stale epoch must not even send');
    case 'revoked_handler_is_fenced_by_epoch':
      final h = H(ScriptedClient((_) => Response(500, '')));
      await h._handleTrustedRevokedAccount(h._accountSessionEpoch.current + 1, h.account);
      check(h.deactivations == 0, 'a stale revocation must not deactivate');
      await h._handleTrustedRevokedAccount(h._accountSessionEpoch.current, h.account);
      check(h.deactivations == 1, 'a current revocation must deactivate');
    case 'html_200_is_not_trusted':
      final h = H(ScriptedClient((_) => Response(200, '<!DOCTYPE html><p>portal</p>')));
      final ok = await h._refreshAccountStatus(force: true);
      check(!ok && h.deactivations == 0, 'an HTML 200 must neither succeed nor revoke');
      check(h.sweepFailure == 1, 'an exhausted sweep must be recorded');
    case 'no_device_token_skips':
      final h = H(ScriptedClient((_) => Response(404, '')));
      h.deviceToken = null;
      final ok = await h._refreshAccountStatus(force: true);
      check(!ok && h.deactivations == 0 && h._controlPlaneClient.urls.isEmpty,
          'no token must mean no request and no revocation');
    default:
      throw StateError('unknown scenario \$scenario');
  }
  print('PASS \$scenario');
}
''');
  });

  tearDownAll(() async {
    if (await temporary.exists()) await temporary.delete(recursive: true);
  });

  for (final scenario in const <String>[
    'control_ok_keeps_device',
    'http_404_deactivates',
    'http_401_deactivates',
    'bare_404_is_a_failed_front',
    'status_strings_deactivate',
    'expired_is_terminal_not_revocation',
    'stale_epoch_never_deactivates',
    'revoked_handler_is_fenced_by_epoch',
    'html_200_is_not_trusted',
    'no_device_token_skips',
  ]) {
    test('revocation: $scenario', () async {
      final result = await Process.run(
        Platform.environment['DART_EXECUTABLE'] ?? 'dart',
        <String>[executable.path, scenario],
        workingDirectory: temporary.path,
      );
      expect(result.exitCode, 0, reason: '${result.stdout}\n${result.stderr}');
      expect(result.stdout.toString(), contains('PASS $scenario'));
    });
  }
}
