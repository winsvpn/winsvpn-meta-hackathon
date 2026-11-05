// _sendLogoutToHub walks the compiled fronts through the staggered hub
// window (perRequestTimeout 4 s, totalDeadline kHubVerifyTotalDeadline),
// so a Deactivate on a network that blackholes every front ends inside the
// deadline instead of 4 s per front, and every timed-out request is aborted.
//
// The method under test is the shipping text, extracted from lib/main.dart
// and asserted verbatim before it runs against a client whose every request
// hangs until it is aborted: what a blackholed front looks like to the
// pinned client after its own connection timeout.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

// fake_async comes with flutter_test (transitive); declaring it would change pubspec.lock.
// ignore: depend_on_referenced_packages
import 'package:fake_async/fake_async.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:wins_vpn/account_status_revocation.dart';
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

class _Harness {
  _Harness(this._controlPlaneClient);
  final http.Client _controlPlaneClient;
  final HubOriginPreference _hubOriginPreference = HubOriginPreference();
  void _debugLog(String message) {}
  Map<String, String> _jsonHeaders() => <String, String>{
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      };
  Future<Map<String, String>> _resolveDynamicEndpoints() async =>
      <String, String>{'gateway': gatewayBase(defaultGatewayBase)};

  // ---- verbatim from lib/main.dart (asserted by the first test) ----
  Future<bool> _sendLogoutToHub({
    required bool freeAccess,
    required String accountNumber,
    required String deviceId,
    required String? deviceAuthToken,
  }) async {
    final token = deviceAuthToken?.trim() ?? '';
    if (token.isEmpty) {
      // No device auth token means this device predates activation/verify
      // issuing one, or it was never captured. Per M-5, treat it as
      // needing re-activation rather than sending an unauthenticated
      // device-mutation request.
      _debugLog(
          'Logout skipped: device auth token unavailable; device needs re-activation.');
      return false;
    }
    final endpoints = await _resolveDynamicEndpoints();
    final gatewayEndpoints = GatewayEndpoints(
      gateway: endpoints['gateway']!,
    );
    final logoutBody = jsonEncode({
      'account_number': accountNumber,
      'device_id': deviceId,
    });
    final headers = _jsonHeaders();
    headers['Authorization'] = 'Bearer $token';
    final gateways = freeAccess
        ? freeLogoutGateways(gatewayEndpoints)
        : logoutGateways(gatewayEndpoints);
    // The staggered hub window, not a serial walk: 29 fronts at 4 s each was
    // up to 116 s of spinner on Deactivate, and of the startup cleanup
    // barrier on the next launch, before the logout could even be queued.
    // Only the hub's own acknowledgment wins; every other reply loses and the
    // next front is tried. A timed-out request is aborted, not left open.
    final outcome = await runHubRequestWindow<bool>(
      urls: gateways,
      preference: _hubOriginPreference,
      policy: const HubRequestWindowPolicy(
        perRequestTimeout: Duration(seconds: 4),
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
            body: logoutBody,
          );
          if (hubLogoutAcknowledged(response.statusCode, response.body)) {
            return const HubAttemptResult<bool>.accepted(true);
          }
        } catch (_) {}
        return const HubAttemptResult<bool>.rejected();
      },
    );
    return outcome.value == true;
  }
  // ---- end verbatim ----
}

void main() {
  test('the extracted _sendLogoutToHub is the shipping text', () {
    final main = File('lib/main.dart').readAsStringSync();
    final start = main.indexOf('  Future<bool> _sendLogoutToHub(');
    final end =
        main.indexOf('  // L-1: returns whether the pending-logout', start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final shipping = main.substring(start, end).trimRight();
    final here =
        File('test/account_logout_window_test.dart').readAsStringSync();
    final hStart = here.indexOf('  Future<bool> _sendLogoutToHub(');
    final hEnd = here.indexOf('  // ---- end verbatim ----', hStart);
    expect(here.substring(hStart, hEnd).trimRight(), shipping);
    // The walk is the window, never a per-front serial timeout.
    expect(shipping, contains('runHubRequestWindow<bool>('));
    expect(shipping, contains('sendHubRequest('));
    expect(shipping, isNot(contains('.timeout(const Duration(seconds: 4))')));
  });

  test('a blackholed network ends the logout inside the hub deadline', () {
    fakeAsync((async) {
      final client = _BlackholeClient();
      final h = _Harness(client);
      bool? result;
      h
          ._sendLogoutToHub(
            freeAccess: false,
            accountNumber: '1111-1111-1111',
            deviceId: 'install-1',
            deviceAuthToken: 'token-token-token-token',
          )
          .then((value) => result = value);
      async.elapse(kHubVerifyTotalDeadline + const Duration(seconds: 1));
      expect(result, isFalse);
      expect(client.sent, greaterThan(0));
      // Every request the window started was aborted when the walk ended.
      expect(client.aborted, client.sent);
    });
  });

  test('only the hub acknowledgment wins; a front error page loses', () {
    fakeAsync((async) {
      var calls = 0;
      final client = _ScriptedClient((request) {
        calls += 1;
        if (calls == 1) {
          return http.StreamedResponse(
              Stream.value(utf8.encode('<html>Gateway error</html>')), 200);
        }
        return http.StreamedResponse(
            Stream.value(utf8.encode('{"ok": true}')), 200);
      });
      final h = _Harness(client);
      bool? result;
      h
          ._sendLogoutToHub(
            freeAccess: false,
            accountNumber: '1111-1111-1111',
            deviceId: 'install-1',
            deviceAuthToken: 'token-token-token-token',
          )
          .then((value) => result = value);
      async.elapse(const Duration(seconds: 3));
      expect(result, isTrue);
      expect(calls, 2);
    });
  });
}

class _ScriptedClient extends http.BaseClient {
  _ScriptedClient(this._answer);
  final http.StreamedResponse Function(http.BaseRequest request) _answer;
  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async =>
      _answer(request);
}
