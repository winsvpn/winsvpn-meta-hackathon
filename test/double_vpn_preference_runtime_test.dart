import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

// DV-04 and the service's copy of the Double VPN choice, at runtime. The
// production methods are extracted verbatim from lib/main.dart and run against
// a stubbed store, native channel and widget state: `_setDoubleVpnRequested`,
// `_refuseConnectWhileDoubleVpnSaving`, `_persistDoubleVpnRequested` and
// `_writeDoubleVpnIntentRecord`. Only the connect itself is a mirror
// (`pressConnect`), and `double_vpn_connect_guard_contract` below pins that
// production has the same guard in the same place. This is state-machine
// coverage, not device proof.
void main() {
  late Directory temporary;
  late Map<String, bool> results;
  late String source;

  setUpAll(() async {
    source = File('lib/main.dart').readAsStringSync();
    final extracted = _between(
      source,
      "  /// The Android service's own copy of the user's CURRENT Double VPN choice,",
      '  // STEALTH-TRANSPORT-ONLY LANE (2026-08-06). Own key, own writer.',
    );
    temporary = await Directory.systemTemp.createTemp('wins-double-vpn-pref-');
    final program = File('${temporary.path}/probe.dart');
    await program.writeAsString('$_harnessBefore$extracted$_harnessAfter');
    final packages = File('.dart_tool/package_config.json').absolute.path;
    final result = await Process.run(
      Platform.environment['DART_EXECUTABLE'] ?? 'dart',
      ['--packages=$packages', program.path],
    ).timeout(const Duration(seconds: 90));
    expect(result.exitCode, 0, reason: '${result.stdout}\n${result.stderr}');
    results = <String, bool>{
      for (final line in '${result.stdout}'.split('\n'))
        if (line.startsWith('PASS ')) line.substring(5).trim(): true,
    };
  });

  tearDownAll(() async {
    if (await temporary.exists()) await temporary.delete(recursive: true);
  });

  for (final scenario in const <String>[
    'toggle_rejected_while_a_connect_is_starting',
    'toggle_rejected_while_loading_transitioning_or_cleaning_up',
    'second_toggle_rejected_while_a_write_is_pending',
    'connect_refused_while_a_write_is_pending_then_allowed',
    'toggle_rejected_between_native_start_and_commit_marker_unchanged',
    'connected_toggle_keeps_the_original_message',
    'on_records_the_service_copy_first_and_failure_changes_nothing',
    'on_settings_failure_undoes_the_service_copy',
    'off_records_the_service_copy_after',
    'a_failed_wanted_record_write_removes_the_record',
    'forced_off_branches_record_not_wanted',
    'other_platforms_never_touch_the_record',
    'older_intent_write_cannot_overwrite_newer_choice',
    'erase_waits_for_an_inflight_intent_write',
  ]) {
    test('production preference code: $scenario', () {
      expect(results[scenario], isTrue, reason: 'scenario did not PASS');
    });
  }

  group('double_vpn_connect_guard_contract', () {
    test('production refuses a connect in both entry points, before any flag', () {
      final toggle = _between(
        source,
        'Future<void> _toggleVpnConnection() async {',
        '  Future<void> _disconnectHeldWinn3Session() async {',
      );
      final refuse = toggle
          .indexOf('if (!_isConnected && _refuseConnectWhileDoubleVpnSaving()) return;');
      expect(refuse, greaterThanOrEqualTo(0));
      final flags =
          toggle.indexOf('final operationEpoch = ++_vpnUiOperationEpoch;', refuse);
      expect(flags, greaterThan(refuse),
          reason: 'a refused connect has nothing to settle afterwards');
      final connect = _between(
        source,
        'Future<void> _connectWithSmartProtocol({',
        "    var previousTunnelReleased = beforeTunnelStart == null;",
      );
      expect(connect, contains('if (_refuseConnectWhileDoubleVpnSaving()) return;'));
    });
  });
}

String _between(String source, String start, String end) {
  final first = source.indexOf(start);
  final last = first < 0 ? -1 : source.indexOf(end, first + start.length);
  if (first < 0 || last <= first) {
    throw StateError('Could not extract production code: $start');
  }
  return source.substring(first, last);
}

const _harnessBefore = r'''
import 'dart:async';
import 'dart:io' hide Platform;

class Platform {
  static String operatingSystem = 'android';
  static bool get isAndroid => operatingSystem == 'android';
}

void check(bool condition, String message) {
  if (!condition) throw StateError(message);
}

class Epoch {
  Epoch(this.read);
  final int Function() read;
  int get current => read();
}

class Harness {
  bool mounted = true;
  bool _isConnected = false;
  bool _isVpnConnectInFlight = false;
  bool _isTunnelTransitioning = false;
  bool _isLoading = false;
  bool _accountCleanupPending = false;
  bool _isFreeAccessSession = false;
  bool _doubleVpnFreeAccessEnabled = true;
  bool _doubleVpnAvailable = true;
  bool _isDoubleVpnRequested = false;
  int _doubleVpnPreferenceRevision = 0;
  int accountEpoch = 0;
  late final _accountSessionEpoch = Epoch(() => accountEpoch);
  bool _accountEpochIsCurrent(int epoch) => accountEpoch == epoch;
  Future<void> _doubleVpnIntentRecordQueue = Future<void>.value();
  bool _doubleVpnIntentWritesSealed = false;

  final List<String> events = <String>[];
  final List<String> feedback = <String>[];
  final Map<String, String> store = <String, String>{};
  bool recordWriteFails = false;
  bool settingsWriteFails = false;
  Completer<void>? settingsGate;
  Completer<void>? recordGate;
  bool persistedWanted = false;

  void setState(void Function() fn) => fn();
  void _showFeedback(String message) => feedback.add(message);
  void _debugLog(String message) {}

  Future<void> _writeSensitiveText(String name, String value) async {
    events.add('write:$name=$value');
    final gate = recordGate;
    if (gate != null) await gate.future;
    if (recordWriteFails) throw StateError('store write failed');
    store[name] = value;
  }

  Future<void> _deleteSensitiveText(String name) async {
    events.add('delete:$name');
    store.remove(name);
  }

  Future<void> _mutateVpnRuntimeSettings(
      void Function(Map<String, dynamic> data) mutation) async {
    events.add('settings:start');
    final gate = settingsGate;
    if (gate != null) await gate.future;
    if (settingsWriteFails) throw StateError('settings write failed');
    final data = <String, dynamic>{};
    mutation(data);
    persistedWanted = data['double_vpn_requested'] == true;
    events.add('settings:${persistedWanted ? 1 : 0}');
  }

  static const String _doubleVpnIntentRecord = 'route_intent.txt';

  // Mirror of the toggle and of the native start up to the commit. The guard
  // line is the production one (see the contract test); everything else is the
  // minimum a connect does to the flags this feature reads.
  int startTunnelCalls = 0;
  Completer<void>? nativeStartGate;
  bool? intentAtStart;
  String? recordAtStart;
  Future<void> pressConnect() async {
    if (!_isConnected && _refuseConnectWhileDoubleVpnSaving()) return;
    _isLoading = true;
    _isVpnConnectInFlight = !_isConnected;
    // _startTunnelCandidate: refresh the service's copy from the live setting,
    // then hand native the start.
    await _writeDoubleVpnIntentRecord(_isDoubleVpnRequested);
    intentAtStart = _isDoubleVpnRequested;
    recordAtStart = store[_doubleVpnIntentRecord];
    startTunnelCalls++;
    final gate = nativeStartGate;
    if (gate != null) await gate.future;
    _isConnected = true;
    _isLoading = false;
    _isVpnConnectInFlight = false;
  }

''';

const _harnessAfter = r'''
}

Future<void> main() async {
  Future<void> scenario(String name, Future<void> Function(Harness h) body) async {
    Platform.operatingSystem = 'android';
    final h = Harness();
    await body(h);
    print('PASS $name');
  }

  await scenario('toggle_rejected_while_a_connect_is_starting', (h) async {
    h._isVpnConnectInFlight = true;
    await h._setDoubleVpnRequested(true);
    check(!h._isDoubleVpnRequested, 'the choice changed under a connect');
    check(h.events.isEmpty, 'something was written: ${h.events}');
    check(h.feedback.single.contains('Wait for the current connection'),
        'message: ${h.feedback}');
    check(!h._doubleVpnPreferenceChanging, 'the guard stayed raised');
  });

  await scenario('toggle_rejected_while_loading_transitioning_or_cleaning_up',
      (h) async {
    for (final set in <void Function()>[
      () => h._isLoading = true,
      () => h._isTunnelTransitioning = true,
      () => h._accountCleanupPending = true,
    ]) {
      h._isLoading = false;
      h._isTunnelTransitioning = false;
      h._accountCleanupPending = false;
      set();
      await h._setDoubleVpnRequested(true);
    }
    check(!h._isDoubleVpnRequested && h.events.isEmpty,
        'a toggle got through: ${h.events}');
    check(h.feedback.length == 3, 'three refusals expected: ${h.feedback}');
  });

  await scenario('second_toggle_rejected_while_a_write_is_pending', (h) async {
    h.settingsGate = Completer<void>();
    final first = h._setDoubleVpnRequested(true);
    await Future<void>.delayed(Duration.zero);
    check(h._doubleVpnPreferenceChanging, 'the guard is not raised');
    await h._setDoubleVpnRequested(false);
    check(h.feedback.single.contains('Wait for the current connection'),
        'the second toggle was not refused: ${h.feedback}');
    check(!h.events.contains('settings:0'), 'the second toggle wrote');
    h.settingsGate!.complete();
    await first;
    check(h._isDoubleVpnRequested, 'the first toggle was lost');
    check(!h._doubleVpnPreferenceChanging, 'the guard stayed raised');
  });

  await scenario('connect_refused_while_a_write_is_pending_then_allowed',
      (h) async {
    // The auditor's sequence. Hold the write; press Connect: nothing starts and
    // the user is told. Release it; Connect now starts.
    h.settingsGate = Completer<void>();
    final saving = h._setDoubleVpnRequested(true);
    await Future<void>.delayed(Duration.zero);
    await h.pressConnect();
    check(h.startTunnelCalls == 0, 'a connect started under a pending write');
    check(!h._isLoading && !h._isVpnConnectInFlight,
        'a refused connect left flags raised');
    check(h.feedback.single.contains('still being saved'),
        'message: ${h.feedback}');
    h.settingsGate!.complete();
    await saving;
    await h.pressConnect();
    check(h.startTunnelCalls == 1, 'the connect did not start after the save');
    check(h.intentAtStart == true && h.recordAtStart == '1',
        'the start did not see the saved choice');
  });

  await scenario(
      'toggle_rejected_between_native_start_and_commit_marker_unchanged',
      (h) async {
    // Double VPN is wanted and saved; the connect starts and the native start
    // is held. A toggle in that window must be refused, so the choice the
    // service copy was written from is the choice in force at the commit.
    await h._setDoubleVpnRequested(true);
    h.feedback.clear();
    h.nativeStartGate = Completer<void>();
    final connecting = h.pressConnect();
    await Future<void>.delayed(Duration.zero);
    check(h.startTunnelCalls == 1, 'the native start was not reached');
    h.events.clear();
    await h._setDoubleVpnRequested(false);
    check(h._isDoubleVpnRequested, 'the choice changed between start and commit');
    check(h.events.isEmpty, 'the toggle wrote: ${h.events}');
    check(h.store['route_intent.txt'] == '1', 'the service copy changed');
    check(h.feedback.single.contains('Wait for the current connection'),
        'message: ${h.feedback}');
    h.nativeStartGate!.complete();
    await connecting;
    check(h._isConnected, 'the connect did not commit');
    check(h._isDoubleVpnRequested == h.intentAtStart,
        'the choice at commit is not the choice at start');
    check(h.store['route_intent.txt'] == h.recordAtStart,
        'the service copy at commit is not the copy at start');
  });

  await scenario('connected_toggle_keeps_the_original_message', (h) async {
    h._isConnected = true;
    await h._setDoubleVpnRequested(true);
    check(h.feedback.single.startsWith('Please disconnect the VPN first.'),
        'message: ${h.feedback}');
    check(h.events.isEmpty, 'something was written');
  });

  await scenario('on_records_the_service_copy_first_and_failure_changes_nothing',
      (h) async {
    await h._setDoubleVpnRequested(true);
    check(h.events.first == 'write:route_intent.txt=1',
        'the service copy was not first: ${h.events}');
    check(h.events.indexOf('settings:1') > 0, 'settings were not written');
    check(h._isDoubleVpnRequested && h.persistedWanted, 'turning it on failed');
    // A failing service copy: the choice must not be saved or shown.
    final failing = Harness()..recordWriteFails = true;
    await failing._setDoubleVpnRequested(true);
    check(!failing._isDoubleVpnRequested, 'shown although not recorded');
    check(!failing.persistedWanted, 'saved although not recorded');
    check(!failing.events.any((e) => e.startsWith('settings:')),
        'settings were touched: ${failing.events}');
    check(failing.feedback.single.contains('could not be saved'),
        'message: ${failing.feedback}');
  });

  await scenario('on_settings_failure_undoes_the_service_copy', (h) async {
    h.settingsWriteFails = true;
    await h._setDoubleVpnRequested(true);
    check(!h._isDoubleVpnRequested, 'shown although the settings failed');
    check(h.store['route_intent.txt'] == '0',
        'the service copy was left wanted: ${h.store}');
    check(h.feedback.single.contains('could not be saved'),
        'message: ${h.feedback}');
  });

  await scenario('off_records_the_service_copy_after', (h) async {
    h._isDoubleVpnRequested = true;
    h.store['route_intent.txt'] = '1';
    await h._setDoubleVpnRequested(false);
    final settings = h.events.indexOf('settings:0');
    final record = h.events.indexOf('write:route_intent.txt=0');
    check(settings >= 0 && record > settings,
        'off must save the setting first: ${h.events}');
    check(!h._isDoubleVpnRequested && h.store['route_intent.txt'] == '0',
        'off was not recorded');
    // A failing record write on the way off only ever leaves "1" behind.
    final failing = Harness()
      ..store['route_intent.txt'] = '1'
      .._isDoubleVpnRequested = true
      ..recordWriteFails = true;
    await failing._setDoubleVpnRequested(false);
    check(!failing._isDoubleVpnRequested, 'off was blocked by the record');
    check(failing.store['route_intent.txt'] == '1',
        'a failed write somehow cleared the wanted copy');
  });

  await scenario('a_failed_wanted_record_write_removes_the_record', (h) async {
    h.store['route_intent.txt'] = '0';
    h.recordWriteFails = true;
    final ok = await h._writeDoubleVpnIntentRecord(true);
    check(!ok, 'a failed write reported success');
    check(!h.store.containsKey('route_intent.txt'),
        'a stale "0" survived a failed wanted write');
    // Not wanted: a failed write does not delete anything.
    h.store['route_intent.txt'] = '1';
    final okOff = await h._writeDoubleVpnIntentRecord(false);
    check(!okOff && h.store['route_intent.txt'] == '1',
        'a failed not-wanted write deleted the record');
  });

  await scenario('forced_off_branches_record_not_wanted', (h) async {
    h._isFreeAccessSession = true;
    h._doubleVpnFreeAccessEnabled = false;
    h.store['route_intent.txt'] = '1';
    await h._setDoubleVpnRequested(true);
    check(h.store['route_intent.txt'] == '0', 'free access left it wanted');
    check(!h._isDoubleVpnRequested, 'free access enabled it');
    final offline = Harness()..store['route_intent.txt'] = '1';
    offline._doubleVpnAvailable = false;
    await offline._setDoubleVpnRequested(true);
    check(offline.store['route_intent.txt'] == '0',
        'a core outage left it wanted');
  });

  await scenario('older_intent_write_cannot_overwrite_newer_choice',
      (h) async {
    h.recordGate = Completer<void>();
    final oldWrite = h._writeDoubleVpnIntentRecord(false);
    await Future<void>.delayed(Duration.zero);
    final newWrite = h._writeDoubleVpnIntentRecord(true);
    await Future<void>.delayed(Duration.zero);
    check(h.events.where((e) => e.startsWith('write:')).length == 1,
        'new write bypassed the older write');
    h.recordGate!.complete();
    check(await oldWrite && await newWrite, 'a queued write failed');
    check(h.store['route_intent.txt'] == '1', 'old write won');
  });

  await scenario('erase_waits_for_an_inflight_intent_write', (h) async {
    h.recordGate = Completer<void>();
    final pending = h._writeDoubleVpnIntentRecord(true);
    await Future<void>.delayed(Duration.zero);
    h._doubleVpnIntentWritesSealed = true;
    final erase = () async {
      await h._doubleVpnIntentRecordQueue;
      await h._deleteSensitiveText('route_intent.txt');
    }();
    h.recordGate!.complete();
    await pending;
    await erase;
    check(!h.store.containsKey('route_intent.txt'), 'write survived erase');
    check(!await h._writeDoubleVpnIntentRecord(true),
        'sealed writer accepted a new write');
  });

  await scenario('other_platforms_never_touch_the_record', (h) async {
    Platform.operatingSystem = 'ios';
    await h._setDoubleVpnRequested(true);
    await h._setDoubleVpnRequested(false);
    check(!h.events.any((e) => e.contains('route_intent')),
        'a non-Android platform touched the record: ${h.events}');
    check(h.store.isEmpty, 'a non-Android store was written');
  });

  exit(0);
}
''';
