import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('Dart sends transition ownership to Windows start and cancel calls', () {
    final source = File('lib/main.dart').readAsStringSync();
    final candidateStart = source.indexOf(
      'Future<bool> _startTunnelCandidate(',
    );
    final candidateEnd = source.indexOf(
      'Future<bool> _loadPowerProtectionPromptSeen(',
      candidateStart,
    );
    expect(candidateStart, greaterThanOrEqualTo(0));
    expect(candidateEnd, greaterThan(candidateStart));
    final candidate = source.substring(candidateStart, candidateEnd);
    expect(candidate, contains('required int transitionGeneration'));
    expect(
      candidate,
      contains("startArguments['transitionGeneration'] = transitionGeneration"),
    );

    final settlementStart = source.indexOf(
      'Future<bool> _cancelAndStopNativeTunnel(',
    );
    final settlementEnd = source.indexOf(
      'Future<void> _setLauncherCamouflage(',
      settlementStart,
    );
    final settlement = source.substring(settlementStart, settlementEnd);
    expect(
      settlement,
      contains('final cancellationGeneration = _tunnelTransitionGate.cancel()'),
    );
    expect(
      RegExp(
        'cancellationGeneration: cancellationGeneration',
      ).allMatches(settlement).length,
      3,
    );
  });

  test('Windows bridge rejects missing and stale generations before Xray', () {
    final source = File(
      'windows/runner/windows_tunnel_backend.cpp',
    ).readAsStringSync();

    expect(
      source,
      contains('std::atomic<int64_t> g_canceled_generation_floor'),
    );
    expect(source, contains('WINDOWS_TUNNEL_GENERATION_REQUIRED'));
    expect(source, contains('WINDOWS_TUNNEL_STALE_START'));
    expect(source, contains('transition_generation <= 0'));

    final installStart = source.indexOf('bool InstallTunnel(');
    final installEnd = source.indexOf('bool UninstallTunnel(', installStart);
    final install = source.substring(installStart, installEnd);
    expect(
      install.indexOf('IsWindowsStartGenerationAllowed'),
      lessThan(install.indexOf('StartXrayIfNeeded')),
    );
    expect(
      RegExp('IsWindowsStartGenerationAllowed').allMatches(install).length,
      greaterThanOrEqualTo(3),
    );

    final stopHandlerStart = source.indexOf(
      'if (call.method_name() == "stopTunnel")',
    );
    final stopHandlerEnd = source.indexOf(
      'if (call.method_name() == "startTunnel")',
      stopHandlerStart,
    );
    final stopHandler = source.substring(stopHandlerStart, stopHandlerEnd);
    expect(
      stopHandler.indexOf('AdvanceWindowsCanceledGenerationFloor'),
      lessThan(stopHandler.indexOf('SignalWindowsTunnelStartCancellation')),
    );
    expect(
      stopHandler,
      contains('generation_status == Int64ArgStatus::kValid'),
    );

    expect(source, contains('if (call.method_name() == "getTunnelActivity")'));
    expect(
      source,
      contains('if (call.method_name() == "getTunnelActivitySnapshot")'),
    );
    expect(source, contains('TunnelActivitySnapshotValue()'));
    expect(source, contains('flutter::EncodableValue("known")'));
    final activityHandler = source.substring(
      source.indexOf('if (call.method_name() == "getTunnelActivity")'),
      source.indexOf(
        'if (call.method_name() == "getTunnelActivitySnapshot")',
      ),
    );
    expect(activityHandler, contains('IsTunnelRunning()'));
    expect(activityHandler, contains('IsXrayProcessRunning()'));
    expect(activityHandler, contains('CompleteEncodableMethodAsync'));
    expect(
      source,
      contains('!IsTransitionGenerationAllowed(3, canceled_floor)'),
    );
  });

  test('Windows activity and connected-state methods stay distinct', () {
    final dart = File('lib/main.dart').readAsStringSync();
    expect(dart, contains("'getTunnelActivitySnapshot'"));

    final native = File(
      'windows/runner/windows_tunnel_backend.cpp',
    ).readAsStringSync();
    final stateStart = native.indexOf(
      'if (call.method_name() == "getTunnelState")',
    );
    final activityStart = native.indexOf(
      'if (call.method_name() == "getTunnelActivity")',
      stateStart,
    );
    expect(stateStart, greaterThanOrEqualTo(0));
    expect(activityStart, greaterThan(stateStart));
    final connectedState = native.substring(stateStart, activityStart);
    expect(connectedState, contains('IsTunnelRunning()'));
    expect(connectedState, isNot(contains('IsXrayProcessRunning()')));
  });

  test('Windows tunnel-manager client uses bounded overlapped pipe I/O', () {
    final client = File(
      'windows/runner/windows_tunnel_service_client.cpp',
    ).readAsStringSync();
    expect(client, contains('FILE_FLAG_OVERLAPPED'));
    expect(client, contains('CancelIoEx(pipe, overlapped)'));
    expect(
      client,
      contains('GetOverlappedResult(pipe, overlapped, &canceled_bytes, TRUE)'),
      reason:
          'timed-out I/O must reach terminal cancellation before stack/event release',
    );
    expect(client, contains('CommandTimeoutMs(Command command)'));
    expect(client, contains('case Command::kStop:'));
    expect(client, contains('"Tunnel manager response timed out."'));
    expect(
      client,
      isNot(
        contains(
          'ReadFile(pipe, output + total, bytes - total, &read, nullptr)',
        ),
      ),
    );
  });

  test('Windows tunnel-manager status polls fail fast instead of blocking', () {
    final client = File(
      'windows/runner/windows_tunnel_service_client.cpp',
    ).readAsStringSync();
    expect(client, contains('DWORD PipeWaitTimeoutMs(Command command)'));
    expect(
      client,
      contains('kStatusPipeWaitTimeoutMilliseconds'),
    );

    final callStart = client.indexOf('bool CallTunnelManager(');
    final callEnd = client.indexOf('}  // namespace', callStart);
    expect(callStart, greaterThanOrEqualTo(0));
    expect(callEnd, greaterThan(callStart));
    final call = client.substring(callStart, callEnd);
    expect(call, contains('PipeWaitTimeoutMs(command)'));
    expect(
      call,
      isNot(
        contains('WaitNamedPipeW(winsvpn::tunnel_service::kPipeName, 5000)'),
      ),
      reason:
          'the pipe-availability wait must vary by command, not stay fixed '
          'at the old one-size-fits-all 5s bound',
    );
  });

  test('Windows tunnel-manager stop watchdog recovers a wedged service', () {
    final service = File(
      'windows/runner/windows_tunnel_service_main.cpp',
    ).readAsStringSync();
    final protocol = File(
      'windows/runner/windows_tunnel_service_protocol.h',
    ).readAsStringSync();
    expect(protocol, contains('kStopOverallWatchdogMilliseconds = 20000'));
    expect(service, contains('bool StopPrivilegedWindowsTunnelBounded('));
    expect(
      service,
      contains(
        '[[noreturn]] void TerminateServiceFailClosed(DWORD exit_code)',
      ),
    );
    expect(
      service,
      contains('TerminateProcess(GetCurrentProcess(), exit_code)'),
    );
    expect(
      service,
      contains('TerminateServiceFailClosed(ERROR_TIMEOUT)'),
    );
    expect(
      RegExp('StopPrivilegedWindowsTunnelBounded').allMatches(service).length,
      greaterThanOrEqualTo(4),
      reason: 'the helper plus explicit, carrier-exit, and SCM stop paths',
    );
    expect(service, contains('WaitForClientDrain(pipe)'));
    expect(service, contains('CancelIoEx(pipe, &overlapped)'));
    expect(service, isNot(contains('CancelSynchronousIo')));
  });

  test('Windows native startup budget includes bounded driver readiness', () {
    final source = File('lib/main.dart').readAsStringSync();
    final timing = File('lib/tunnel_stop_settlement.dart').readAsStringSync();
    final protocol = File(
      'windows/runner/windows_tunnel_service_protocol.h',
    ).readAsStringSync();
    expect(source, contains('final nativeStartTimeout = _isApplePlatform'));
    expect(source, contains('? const Duration(seconds: 45)'));
    expect(source, contains('? windowsTunnelNativeStartTimeout'));
    expect(source, contains(': const Duration(seconds: 12);'));
    expect(source, contains('.timeout(nativeStartTimeout)'));
    expect(
      timing,
      contains(
        'const windowsTunnelNativeStartTimeout = Duration(seconds: 170)',
      ),
    );
    expect(protocol, contains('kNormalAwgCriticalPathBudgetMilliseconds ='));
    expect(protocol, contains('kMutationPipeWaitTimeoutMilliseconds = 5000'));
    expect(protocol, contains('kStatusCommandTimeoutMilliseconds = 12000'));
    final service = File(
      'windows/runner/windows_tunnel_service_main.cpp',
    ).readAsStringSync();
    final startHandler = service.substring(
      service.indexOf('if (command == Command::kStart)'),
      service.indexOf('if (command == Command::kStop)'),
    );
    expect(startHandler, contains('kStartOverallWatchdogMilliseconds'));
    expect(
      startHandler.indexOf('std::thread start_watchdog('),
      lessThan(startHandler.indexOf('StartPrivilegedWindowsTunnel(')),
    );
  });

  test('Windows start runs off the Flutter platform thread and is cancelable',
      () {
    final backend = File(
      'windows/runner/windows_tunnel_backend.cpp',
    ).readAsStringSync();
    final client = File(
      'windows/runner/windows_tunnel_service_client.cpp',
    ).readAsStringSync();
    final service = File(
      'windows/runner/windows_tunnel_service_main.cpp',
    ).readAsStringSync();
    final startHandler = backend.substring(
      backend.indexOf('if (call.method_name() == "startTunnel")'),
      backend.indexOf('if (call.method_name() == "showAnnouncementNotification")'),
    );
    expect(startHandler, contains('std::thread(['));
    expect(startHandler, contains('InstallTunnel(config, transition_generation'));
    expect(backend, contains('SignalWindowsTunnelStartCancellation();'));
    expect(client, contains('ArmWindowsTunnelStartCancellation('));
    expect(client, contains('DisarmWindowsTunnelStartCancellation()'));
    expect(service, contains('OpenEventW(SYNCHRONIZE'));
    expect(service, contains('WaitForMultipleObjects('));
    expect(service, contains('client_process'));
  });

  test('Windows start timeout preserves fail-closed cancellation ordering', () {
    final source = File('lib/main.dart').readAsStringSync();
    final candidateStart = source.indexOf(
      'Future<bool> _startTunnelCandidate(',
    );
    final candidateEnd = source.indexOf(
      'Future<bool> _loadPowerProtectionPromptSeen(',
      candidateStart,
    );
    final candidate = source.substring(candidateStart, candidateEnd);
    final invoke = candidate.indexOf(
      ".invokeMethod(\n            'startTunnel'",
    );
    final timeout = candidate.indexOf('.timeout(nativeStartTimeout)', invoke);
    final postStartCancellation = candidate.indexOf(
      'if (shouldCancel?.call() == true)',
      timeout,
    );
    expect(invoke, greaterThanOrEqualTo(0));
    expect(timeout, greaterThan(invoke));
    expect(postStartCancellation, greaterThan(timeout));
    expect(candidate, contains('} catch (e) {'));
    expect(candidate, contains('return false;'));
  });
}
