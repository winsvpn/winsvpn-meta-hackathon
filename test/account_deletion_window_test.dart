// _postAccountDeletion walks the compiled fronts through the staggered hub
// window (perRequestTimeout 6 s, totalDeadline kHubVerifyTotalDeadline), the
// same bound _sendLogoutToHub uses, so a deletion step on a network that
// blackholes every front ends inside the deadline instead of 6 s per front
// (up to 174 s over 29 fronts), and every timed-out request is aborted.
//
// The method under test is the shipping text, extracted from lib/main.dart
// and asserted verbatim before it runs.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

// fake_async comes with flutter_test (transitive); declaring it would change pubspec.lock.
// ignore: depend_on_referenced_packages
import 'package:fake_async/fake_async.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:wins_vpn/account_deletion.dart';
import 'package:wins_vpn/gateway_failover.dart';
import 'package:wins_vpn/hub_request_window.dart';

class _BlackholeClient extends http.BaseClient {
  int sent = 0;
  int aborted = 0;
  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) {
    sent += 1;
    final completer = Completer<http.StreamedResponse>();
    if (request is http.Abortable) {
      final trigger = request.abortTrigger;
      if (trigger != null) {
        trigger.whenComplete(() {
          aborted += 1;
          if (!completer.isCompleted) {
            completer.completeError(http.RequestAbortedException(request.url));
          }
        });
      }
    }
    return completer.future;
  }
}

class _ScriptedClient extends http.BaseClient {
  _ScriptedClient(this._answer);
  final http.StreamedResponse Function(http.BaseRequest request) _answer;
  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async =>
      _answer(request);
}

class _Text {
  String text = '1111-1111-1111';
}

class _Harness {
  _Harness(this._controlPlaneClient);
  final http.Client _controlPlaneClient;
  final HubOriginPreference _hubOriginPreference = HubOriginPreference();
  final _Text _accountController = _Text();
  final String _appScopedDeviceId = 'install-1';
  String? deviceToken = 'token-token-token-token';
  void _debugLog(String message) {}
  Future<String?> _readDeviceAuthToken() async => deviceToken;
  Map<String, String> _jsonHeaders() => <String, String>{
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      };
  Future<Map<String, String>> _resolveDynamicEndpoints() async =>
      <String, String>{'gateway': gatewayBase(defaultGatewayBase)};

  // ---- verbatim from lib/main.dart (asserted by the first test) ----
  Future<AccountDeletionState?> _postAccountDeletion(
    List<String> Function(GatewayEndpoints) gatewaySelector, {
    Map<String, dynamic> extra = const <String, dynamic>{},
  }) async {
    final token = (await _readDeviceAuthToken())?.trim() ?? '';
    if (token.isEmpty) {
      // Matches the /logout contract: without a scoped token this device was
      // never properly activated, and the hub would reject it anyway.
      _debugLog(
          'Account deletion skipped: device auth token unavailable; device needs re-activation.');
      return null;
    }
    final endpoints = await _resolveDynamicEndpoints();
    final gatewayEndpoints = GatewayEndpoints(gateway: endpoints['gateway']!);
    final body = jsonEncode({
      'account_number': _accountController.text.trim(),
      'device_id': _appScopedDeviceId,
      ...extra,
    });
    final headers = _jsonHeaders();
    headers['Authorization'] = 'Bearer $token';
    // The staggered hub window, as _sendLogoutToHub uses: the serial walk was
    // 29 fronts at 6 s each, up to 174 s of spinner per deletion step on a
    // filtering network. The hub joins a repeated request to the pending one
    // (one pending row per account), so a hedged duplicate is harmless. A
    // timed-out request is aborted, not left open.
    final outcome = await runHubRequestWindow<AccountDeletionState>(
      urls: gatewaySelector(gatewayEndpoints),
      preference: _hubOriginPreference,
      policy: const HubRequestWindowPolicy(
        perRequestTimeout: Duration(seconds: 6),
        totalDeadline: kHubVerifyTotalDeadline,
      ),
      attempt: (url, abort) async {
        try {
          final response = await sendHubRequest(
            _controlPlaneClient,
            'POST',
            Uri.parse(url),
            abort: abort,
            headers: headers,
            body: body,
          );
          if (response.statusCode >= 200 && response.statusCode < 300) {
            final decoded = jsonDecode(response.body);
            if (decoded is Map<String, dynamic>) {
              return HubAttemptResult<AccountDeletionState>.accepted(
                  AccountDeletionState.fromStatusPayload(decoded));
            }
          }
        } catch (_) {}
        return const HubAttemptResult<AccountDeletionState>.rejected();
      },
    );
    return outcome.value;
  }
  // ---- end verbatim ----
}

void main() {
  test('the extracted _postAccountDeletion is the shipping text', () {
    final main = File('lib/main.dart').readAsStringSync();
    final start =
        main.indexOf('  Future<AccountDeletionState?> _postAccountDeletion(');
    final end = main.indexOf(
        '  Future<AccountDeletionState?> _fetchAccountDeletionStatus() =>',
        start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final shipping = main.substring(start, end).trimRight();
    final here =
        File('test/account_deletion_window_test.dart').readAsStringSync();
    final hStart =
        here.indexOf('  Future<AccountDeletionState?> _postAccountDeletion(');
    final hEnd = here.indexOf('  // ---- end verbatim ----', hStart);
    expect(here.substring(hStart, hEnd).trimRight(), shipping);
    expect(shipping, contains('runHubRequestWindow<AccountDeletionState>('));
    expect(shipping, contains('sendHubRequest('));
    expect(shipping, isNot(contains('.timeout(const Duration(seconds: 6))')));
  });

  test('a blackholed network ends a deletion step inside the hub deadline',
      () {
    fakeAsync((async) {
      final client = _BlackholeClient();
      final h = _Harness(client);
      var done = false;
      AccountDeletionState? result;
      h._postAccountDeletion(accountDeletionRequestGateways).then((value) {
        result = value;
        done = true;
      });
      async.elapse(kHubVerifyTotalDeadline + const Duration(seconds: 1));
      expect(done, isTrue);
      expect(result, isNull);
      expect(client.sent, greaterThan(0));
      expect(client.aborted, client.sent);
    });
  });

  test('the first 2xx JSON status wins; an error page loses', () {
    fakeAsync((async) {
      var calls = 0;
      final bodies = <String>[];
      final client = _ScriptedClient((request) {
        calls += 1;
        bodies.add((request as http.Request).body);
        if (calls == 1) {
          return http.StreamedResponse(
              Stream.value(utf8.encode('<html>Gateway error</html>')), 200);
        }
        return http.StreamedResponse(
            Stream.value(utf8.encode(jsonEncode(<String, Object?>{
              'stage': 'awaiting_confirmations',
              'active_device_count': 2,
              'confirmed_device_count': 1,
              'request_id': 'req-1',
            }))),
            200);
      });
      final h = _Harness(client);
      AccountDeletionState? result;
      h
          ._postAccountDeletion(accountDeletionConfirmGateways,
              extra: const <String, dynamic>{'request_id': 'req-1'})
          .then((value) => result = value);
      async.elapse(const Duration(seconds: 3));
      expect(result, isNotNull);
      expect(result!.stage, AccountDeletionStage.awaitingConfirmations);
      expect(calls, 2);
      final sent = jsonDecode(bodies.last) as Map<String, dynamic>;
      expect(sent['account_number'], '1111-1111-1111');
      expect(sent['device_id'], 'install-1');
      expect(sent['request_id'], 'req-1');
    });
  });

  test('no device token sends nothing', () {
    fakeAsync((async) {
      final client = _BlackholeClient();
      final h = _Harness(client)..deviceToken = null;
      var done = false;
      h
          ._postAccountDeletion(accountDeletionStatusGateways)
          .then((_) => done = true);
      async.flushMicrotasks();
      expect(done, isTrue);
      expect(client.sent, 0);
    });
  });
}
