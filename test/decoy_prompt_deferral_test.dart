// The six older dialogs a flow can raise after an await, a timer or a callback
// while the decoy calculator covers the app (Round UI follow-up F3), run
// verbatim from lib/main.dart.
//
//   privacy consent        _showPrivacyPolicyDialog        cancel (the unlock asks again from state)
//   terms and legal        _showTermsAndLegalDialog        cancel (a tap opens it, nothing to keep)
//   Android VPN disclosure _showAndroidVpnServiceDisclosureDialog   defer to the unlock
//   legal acceptance       _showLegalAcceptanceDialog      defer to the unlock
//   package visibility     _promptForAndroidPackageVisibilityConsent   cancel
//   secure-state failure   _showSecureStateFailureDialog   cancel (re-derived by the consent retry)
//   PIN upgrade            _promptForPinUpgrade            cancel (the dashboard notice is the re-offer)
//
// A dialog cannot be built without a widget tree, so the harness takes each
// function's text from main.dart and replaces only its `showDialog<T>(...)`
// call (found with a Dart-aware bracket scanner, which skips strings and
// comments) with a scripted `hostShowDialog<T>(label)`. Everything else in
// the function, and the whole of the glue (_gatedLegalPrompt,
// _offerDeferredLegalConsent, _commitPinUpgrade, the PIN-unlock block), runs
// as written in production. The scripted dialog does what the route guard
// does: it completes null when the decoy is up. It also records a dialog that
// a flow tried to draw while the decoy was up ("DRAWN-OVER-DECOY"), which the
// tests forbid: nothing may even be pushed. DeferredPrompt and
// runGatedConsentPrompt are imported from lib/decoy_prompt_gate.dart itself.
//
// Each scenario runs in its own dart process, like decoy_continuation_test.dart.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// Runs [command] in its own process group with a hard timeout that kills the
/// whole group (the dart launcher, its VM and any child), so a hung scenario
/// cannot outlive the test that started it.
Future<ProcessResult> _runGrouped(
  List<String> command, {
  required String workingDirectory,
  required Duration timeout,
}) async {
  final process = await Process.start(
    'perl',
    <String>['-e', 'setpgrp(0,0); exec @ARGV', ...command],
    workingDirectory: workingDirectory,
  );
  final out = process.stdout.transform(utf8.decoder).join();
  final err = process.stderr.transform(utf8.decoder).join();
  var timedOut = false;
  final code = await process.exitCode.timeout(timeout, onTimeout: () async {
    timedOut = true;
    await Process.run('kill', <String>['-TERM', '--', '-${process.pid}']);
    await Future<void>.delayed(const Duration(seconds: 2));
    await Process.run('kill', <String>['-KILL', '--', '-${process.pid}']);
    return -9;
  });
  // Nothing of the group may remain, whatever the exit path.
  await Process.run('kill', <String>['-KILL', '--', '-${process.pid}']);
  final stdout = await out;
  final stderr = await err;
  return ProcessResult(process.pid, code,
      stdout, timedOut ? '$stderr\nTIMEOUT after ${timeout.inSeconds}s' : stderr);
}

String _between(String source, String start, String end) {
  final first = source.indexOf(start);
  if (first < 0) throw StateError('Could not extract production code: $start');
  final last = source.indexOf(end, first + start.length);
  if (last <= first) throw StateError('Could not find the end of: $start');
  return source.substring(first, last);
}

// ---------------------------------------------------------------------------
// A tiny Dart-aware scanner: enough to find the matching bracket of a call
// whose arguments hold string literals (with interpolation), comments and
// nested closures.
// ---------------------------------------------------------------------------

int _endOfBalanced(String s, int open) {
  var depth = 0;
  var i = open;
  while (i < s.length) {
    final c = s[i];
    if (c == '/' && i + 1 < s.length && s[i + 1] == '/') {
      final eol = s.indexOf('\n', i);
      i = eol < 0 ? s.length : eol + 1;
      continue;
    }
    if (c == '/' && i + 1 < s.length && s[i + 1] == '*') {
      i = s.indexOf('*/', i + 2) + 2;
      continue;
    }
    if (c == "'" || c == '"') {
      i = _endOfString(s, i);
      continue;
    }
    if (c == '(' || c == '{' || c == '[') {
      depth++;
    } else if (c == ')' || c == '}' || c == ']') {
      depth--;
      if (depth == 0) return i + 1;
    }
    i++;
  }
  throw StateError('unbalanced source');
}

int _endOfString(String s, int i) {
  final quote = s[i];
  final triple = s.startsWith(quote * 3, i);
  final raw = i > 0 && s[i - 1] == 'r';
  final close = triple ? quote * 3 : quote;
  var j = i + (triple ? 3 : 1);
  while (j < s.length) {
    final c = s[j];
    if (!raw && c == r'\') {
      j += 2;
      continue;
    }
    if (!raw && c == r'$' && j + 1 < s.length && s[j + 1] == '{') {
      j = _endOfBalanced(s, j + 1);
      continue;
    }
    if (s.startsWith(close, j)) return j + close.length;
    j++;
  }
  throw StateError('unterminated string');
}

/// Replaces every `showDialog<T>(...)` call in [code] with
/// `hostShowDialog<T>('label')`.
String _stripShowDialog(String code, String label) {
  final pattern = RegExp(r'showDialog<(\w+)>\(');
  var out = code;
  var replaced = 0;
  while (true) {
    final match = pattern.firstMatch(out);
    if (match == null) break;
    final open = match.end - 1;
    final end = _endOfBalanced(out, open);
    out = '${out.substring(0, match.start)}'
        "hostShowDialog<${match.group(1)}>('$label')"
        '${out.substring(end)}';
    replaced++;
  }
  if (replaced == 0) throw StateError('no showDialog call in $label');
  return out;
}

const String _harness = r'''
import 'dart:async';

import '@@GATE@@';

const int kCamouflagePinLength = 6;
const String _androidVpnServiceDisclosureVersion = 'disclosure-v1';
const String _legalDocumentVersion = 'legal-v2';
const String _bundledLegalDocumentHash = 'h2';
const String _legalFallbackBody = 'body';

String? pinPolicyRejectionReason(String pin) {
  if (pin.length != kCamouflagePinLength) return 'Please choose a 6-digit code.';
  if (pin == '123456') return 'That code is too easy to guess.';
  return null;
}

String nativeTunnelErrorSummary(Object error) => 'native:$error';

class _Epoch {
  int current = 1;
  int bump() => ++current;
  bool isCurrent(int epoch) => epoch == current;
}

class _PinEntry {
  int pinLength = 4;
  void reset() {}
}

class _Controller {
  int cleared = 0;
  void clear() => cleared++;
}

@@LEGAL_STALE@@

class H {
  bool mounted = true;
  bool isAndroid = false;
  bool _showDecoyCalculator = false;
  int _decoyGeneration = 0;
  final _Epoch _accountSessionEpoch = _Epoch();
  final DeferredPrompt _deferredLegalConsent = DeferredPrompt();

  bool _privacyConsentGranted = true;
  bool _privacyConsentPromptOpen = false;
  bool _isLoggedIn = true;
  bool _isFreeAccessSession = false;
  bool _isLoading = false;
  final String _freeAccessAccountNumber = 'FREE-ACCESS-1';
  String savedAccount = '111122223333';
  String _legalAcceptedVersion = '';
  String _legalAcceptedHash = '';
  String _androidVpnServiceDisclosureConsentVersion = '';
  String _androidVpnServiceDisclosureAcceptedAtUtc = '';
  String _androidPackageVisibilityConsentVersion = '';
  final String _androidPackageVisibilityDisclosureVersion = 'pkg-v1';
  Future<bool>? _androidVpnServiceDisclosureConsentRequest;
  Future<bool>? _androidPackageVisibilityConsentRequest;
  Future<bool>? _legalAcceptanceDialogRequest;
  String _legalAcceptanceDialogKey = '';
  bool _pinResetCommitted = false;
  bool _pinResetWriting = false;
  bool _pinResetPromptWaiting = false;
  bool _pinUpgradePromptWaiting = false;
  bool _pinUpgradeDialogOpen = false;
  bool _pinResetDialogOpen = false;
  Future<String?>? _pinUpgradeInFlight;
  Future<String?>? _pinResetInFlight;
  int issued = 0;
  bool _splitTunnelExpanded = false;
  bool _appsLoading = false;
  bool _pinUpgradeAvailable = true;
  bool _pinResetRequired = false;
  bool _recoveryUnlockPending = false;
  String _calcDisplayString = '0';
  final _PinEntry _calculatorPinEntry = _PinEntry();
  final _Controller _pinUpgradeController = _Controller();

  // What the tests read.
  final List<String> events = <String>[];
  final List<String> saved = <String>[];
  final List<String> feedback = <String>[];
  final List<String> hookOrder = <String>[];
  int docLoads = 0;
  int lookups = 0;
  int persistedConsent = 0;
  int postInit = 0;
  int replaced = 0;
  // What the tests script.
  final Map<String, bool?> answers = <String, bool?>{};
  // Per-dialog answers in order, before falling back to answers[label].
  final Map<String, List<bool?>> answerSeq = <String, List<bool?>>{};
  Future<void> Function(String label)? whileOpen;
  Future<void> Function()? persistHook;
  Future<void> Function()? saveHook;
  Future<void> Function()? replaceHook;
  Future<void> Function()? accountLookupHook;
  Future<void> Function()? docLoadHook;
  // Documents the fetch stub hands out, in order, before falling back to docVersion.
  final List<Map<String, String>> docQueue = <Map<String, String>>[];
  // The account every stored acceptance must name (the account const unless a scenario says otherwise).
  String? expectedAccount;
  String docVersion = 'legal-v2';
  String docHash = 'h2';

  void setState(void Function() fn) => fn();
  String _t(String value) => value;
  void _debugLog(String message) {}
  // Production's _showFeedback returns first when the decoy shows.
  void _showFeedback(String message) {
    if (_showDecoyCalculator) return;
    feedback.add(message);
  }

  bool _accountEpochIsCurrent(int epoch) => _accountSessionEpoch.isCurrent(epoch);

  // What production does when it arms the decoy, and when the PIN unlocks.
  void relock() {
    _decoyGeneration++;
    _showDecoyCalculator = true;
  }

  void unlockOnly() => _showDecoyCalculator = false;

  // The route guard: a dialog the decoy covers completes null.
  int openNow = 0;
  int maxOpen = 0;
  Future<T?> hostShowDialog<T>(String label) async {
    events.add(_showDecoyCalculator ? 'DRAWN-OVER-DECOY:$label' : 'dialog:$label');
    openNow++;
    if (openNow > maxOpen) maxOpen = openNow;
    try {
      final script = whileOpen;
      if (script != null) await script(label);
      await Future<void>.delayed(Duration.zero);
      if (_showDecoyCalculator) return null;
      final seq = answerSeq[label];
      if (seq != null && seq.isNotEmpty) return seq.removeAt(0) as T?;
      return answers[label] as T?;
    } finally {
      openNow--;
    }
  }

  // ---- stubs for what the extracted code calls -------------------------
  Future<void> _persistPrivacyConsent() async {
    final hook = persistHook;
    if (hook != null) await hook();
    persistedConsent++;
  }

  void _startPostPrivacyConsentInitialization() => postInit++;

  Future<void> _saveVpnRuntimeSettings({
    String? accountNumber,
    String? legalAcceptedVersion,
    String? legalAcceptedHash,
    String? androidVpnServiceDisclosureConsentVersion,
    String? androidVpnServiceDisclosureAcceptedAtUtc,
    String? androidPackageVisibilityConsentVersion,
  }) async {
    final want = expectedAccount ?? account;
    if (accountNumber != null && accountNumber != want) {
      throw StateError('stored under $accountNumber, expected $want');
    }
    final hook = saveHook;
    saveHook = null;
    if (hook != null) await hook();
    if (legalAcceptedVersion != null) saved.add('legal:$legalAcceptedVersion');
    if (androidVpnServiceDisclosureConsentVersion != null) {
      saved.add('disclosure:$androidVpnServiceDisclosureConsentVersion');
    }
    if (androidPackageVisibilityConsentVersion != null) {
      saved.add('package:$androidPackageVisibilityConsentVersion');
    }
  }

  Future<Map<String, String>> _loadLegalDocumentForAcceptance() async {
    docLoads++;
    final hook = docLoadHook;
    if (hook != null) await hook();
    if (docQueue.isNotEmpty) return docQueue.removeAt(0);
    return <String, String>{
      'version': docVersion,
      'hash': docHash,
      'body': 'b',
      'display_body': 'd',
    };
  }
  Map<String, dynamic> _legalAcceptancePayload(Map<String, String> doc) =>
      <String, dynamic>{'legal_version': doc['version']};
  // documentOnFile() calls this on every pass of the ensure loop. A loop that
  // never reaches an await cannot be bounded by a timer in this isolate, so a
  // spin is stopped here and fails with its own message, never by a timeout.
  int legalBodyReads = 0;
  String _localizedLegalBody(String body) {
    if (++legalBodyReads > 10000) {
      throw StateError('SPIN: the ensure loop ran 10000 passes without an await');
    }
    return body;
  }

  Future<String> _currentAccountNumberForRefresh() async {
    lookups++;
    final hook = accountLookupHook;
    if (hook != null) await hook();
    return savedAccount;
  }

  Future<void> _replaceUserPin(String pin) async {
    final hook = replaceHook;
    if (hook != null) await hook();
    replaced++;
  }

  void _visibleSplitTunnelAppsPlaceholder() {}
  List<Object> _visibleSplitTunnelApps() => <Object>[];
  Future<void> _loadInstalledAppsForSplitTunnel() async {}
  void _bringSplitTunnelPanelIntoView() {}

  // The presenters hold nothing but the dialog itself: one scripted dialog.
  Future<bool?> _presentLegalAcceptanceDialog(Map<String, String> doc) =>
      hostShowDialog<bool>('legal');
  Future<bool?> _presentAndroidVpnServiceDisclosureDialog() =>
      hostShowDialog<bool>('vpn-disclosure');

  // ---- the PIN-unlock block, as production runs it ---------------------
  Future<void> _setLauncherCamouflage({required bool enabled}) async {}
  Future<void> _reconcileNativeTunnelState(
      {bool refreshNetworkLabel = false}) async {}
  void _runPendingSettingsRestart() => hookOrder.add('restart');
  // Round UN: queues a tunnel-name restore; it raises no dialog.
  void _scheduleTunnelDisplayRestore() {}
  Future<void> _issueAndShowRecoveryCode() async => issued++;
  Future<void> _showPendingRecoveryCode() async => hookOrder.add('recovery-code');

  Future<void> pinUnlockAccepted() async {
@@UNLOCK@@
  }

  // ---- production code, verbatim ---------------------------------------
@@PRIVACY@@
@@ENSURE_PRIVACY@@
@@TERMS@@
@@SECURE_STATE@@
@@PACKAGE@@
@@TOGGLE@@
@@LEGAL_WRAPPER@@
@@DISCLOSURE_WRAPPER@@
@@DISCLOSURE_ENSURE@@
@@LEGAL_ENSURE@@
@@GLUE@@
@@PIN_UPGRADE@@
@@PIN_RESET@@
}

void check(bool ok, String message) {
  if (!ok) throw StateError(message);
}

/// A hang fails the scenario with a message, at once, never by a runner timeout.
Future<T> bounded<T>(Future<T> f) => f.timeout(const Duration(seconds: 3),
    onTimeout: () => throw StateError('HUNG: a caller never returned'));

const String account = '111122223333';

Future<void> main(List<String> args) async {
  final scenario = args.single;
  final h = H();
  switch (scenario) {
@@SCENARIOS@@
    default:
      throw StateError('unknown scenario $scenario');
  }
  print('PASS $scenario');
}
''';

const String _scenarios = r'''
    // ---------------- privacy consent ----------------
    case 'privacy_control':
      h._privacyConsentGranted = false;
      h.answers['privacy'] = true;
      final ok = await h._showPrivacyPolicyDialog(requireConsent: true);
      check(ok && h._privacyConsentGranted, 'control: consent not granted');
      check(h.persistedConsent == 1 && h.postInit == 1, 'control: not persisted once');
      check(h.events.join(',') == 'dialog:privacy', 'control: ${h.events}');
    case 'privacy_behind_decoy_from_a_network_flow':
      // A refresh flow that runs behind the calculator asks for consent.
      h._privacyConsentGranted = false;
      h.relock();
      final ok = await h._ensurePrivacyConsentForNetworkUse();
      check(!ok, 'consent answered true behind the decoy');
      check(h.events.isEmpty, 'a dialog was pushed over the decoy: ${h.events}');
      check(h.persistedConsent == 0 && h.postInit == 0 && !h._privacyConsentGranted,
          'something was done behind the decoy');
      check(!h._privacyConsentPromptOpen, 'the prompt-open latch was left set');
      check(!h._deferredLegalConsent.isPending, 'a record was kept for a prompt that needs none');
    case 'privacy_removed_then_the_unlock_asks_once':
      h._privacyConsentGranted = false;
      h.whileOpen = (label) async => h.relock();
      final ok = await h._showPrivacyPolicyDialog(requireConsent: true);
      check(!ok && !h._privacyConsentGranted, 'a removed dialog counted as consent');
      check(h.persistedConsent == 0, 'consent persisted for a dialog nobody answered');
      check(!h._privacyConsentPromptOpen, 'the prompt-open latch was left set');
      h.whileOpen = null;
      h.answers['privacy'] = true;
      await h.pinUnlockAccepted();
      check(h.events.join(',') == 'dialog:privacy,dialog:privacy',
          'the unlock did not ask again: ${h.events}');
      check(h._privacyConsentGranted && h.persistedConsent == 1, 'accept at unlock not stored');
      h.relock();
      await h.pinUnlockAccepted();
      check(h.events.length == 2, 'asked again after it was granted: ${h.events}');
    case 'privacy_relock_unlock_with_nothing_owed':
      h._privacyConsentGranted = true;
      h.relock();
      await h.pinUnlockAccepted();
      h.relock();
      await h.pinUnlockAccepted();
      check(h.events.isEmpty, 'a prompt appeared with nothing owed: ${h.events}');
    case 'privacy_not_now_is_asked_again_next_unlock':
      // Unchanged behaviour: a refusal is a refusal, and consent stays owed.
      h._privacyConsentGranted = false;
      h.answers['privacy'] = false;
      await h.pinUnlockAccepted();
      await h.pinUnlockAccepted();
      check(h.events.join(',') == 'dialog:privacy,dialog:privacy', '${h.events}');
      check(h.persistedConsent == 0 && !h._privacyConsentGranted, 'refusal stored as consent');
    // ---------------- secure-state failure ----------------
    case 'secure_state_control':
      h._privacyConsentGranted = false;
      h.answers['privacy'] = true;
      h.persistHook = () async => throw StateError('keychain');
      final ok = await h._showPrivacyPolicyDialog(requireConsent: true);
      check(!ok && !h._privacyConsentGranted, 'consent claimed after a failed write');
      check(h.events.join(',') == 'dialog:privacy,dialog:secure-state',
          'control: the failure was not reported: ${h.events}');
    case 'secure_state_relock_during_the_write':
      h._privacyConsentGranted = false;
      h.answers['privacy'] = true;
      h.persistHook = () async {
        h.relock();
        throw StateError('keychain');
      };
      final ok = await h._showPrivacyPolicyDialog(requireConsent: true);
      check(!ok, 'consent claimed');
      check(h.events.join(',') == 'dialog:privacy',
          'the failure dialog was drawn over the decoy: ${h.events}');
      check(!h._deferredLegalConsent.isPending, 'a stale error was kept for the unlock');
      // The unlock asks for consent again (the write never committed) and the
      // retry now succeeds: no failure dialog, and consent is stored.
      h.persistHook = null;
      await h.pinUnlockAccepted();
      check(h.events.join(',') == 'dialog:privacy,dialog:privacy', '${h.events}');
      check(h._privacyConsentGranted && h.persistedConsent == 1, 'retry not stored');
    case 'secure_state_write_still_failing_after_the_unlock':
      // Re-evaluated, not replayed: the retry raises its own failure dialog.
      h._privacyConsentGranted = false;
      h.answers['privacy'] = true;
      h.persistHook = () async {
        h.relock();
        throw StateError('keychain');
      };
      await h._showPrivacyPolicyDialog(requireConsent: true);
      h.persistHook = () async => throw StateError('keychain');
      await h.pinUnlockAccepted();
      check(h.events.join(',') ==
              'dialog:privacy,dialog:privacy,dialog:secure-state',
          '${h.events}');
    case 'secure_state_dialog_removed_by_a_relock':
      h._privacyConsentGranted = false;
      h.answers['privacy'] = true;
      h.persistHook = () async => throw StateError('keychain');
      h.whileOpen = (label) async {
        if (label == 'secure-state') h.relock();
      };
      await h._showPrivacyPolicyDialog(requireConsent: true);
      h.whileOpen = null;
      h.persistHook = null;
      final before = h.events.length;
      await h.pinUnlockAccepted();
      check(h.events.sublist(before).join(',') == 'dialog:privacy',
          'the unlock replayed the failure: ${h.events}');
    // ---------------- terms and legal ----------------
    case 'terms_control':
      await h._showTermsAndLegalDialog();
      check(h.events.join(',') == 'dialog:terms', '${h.events}');
    case 'terms_behind_decoy_and_not_kept':
      h.relock();
      await h._showTermsAndLegalDialog();
      check(h.events.isEmpty, 'terms drawn over the decoy: ${h.events}');
      await h.pinUnlockAccepted();
      check(h.events.isEmpty, 'terms appeared at the unlock: ${h.events}');
    case 'terms_removed_by_a_relock_not_replayed':
      h.whileOpen = (label) async => h.relock();
      await h._showTermsAndLegalDialog();
      h.whileOpen = null;
      await h.pinUnlockAccepted();
      check(h.events.join(',') == 'dialog:terms', 'replayed: ${h.events}');
    // ---------------- package visibility ----------------
    case 'package_control':
      h.isAndroid = true;
      h.answers['package'] = true;
      await h._toggleSplitTunnelPanel();
      check(h._splitTunnelExpanded, 'control: the panel did not open');
      check(h.saved.join(',') == 'package:pkg-v1', 'control: consent not stored ${h.saved}');
    case 'package_behind_decoy':
      h.isAndroid = true;
      h.answers['package'] = true;
      h.relock();
      await h._toggleSplitTunnelPanel();
      check(h.events.isEmpty, 'the consent was drawn over the decoy: ${h.events}');
      check(h.saved.isEmpty && h._androidPackageVisibilityConsentVersion.isEmpty,
          'consent assumed behind the decoy');
      check(!h._splitTunnelExpanded, 'the panel opened without consent');
      await h.pinUnlockAccepted();
      check(h.events.isEmpty && !h._splitTunnelExpanded, 'asked at the unlock');
    case 'package_removed_by_a_relock':
      h.isAndroid = true;
      h.answers['package'] = true;
      h.whileOpen = (label) async => h.relock();
      await h._toggleSplitTunnelPanel();
      check(h.saved.isEmpty && !h._splitTunnelExpanded, 'a removed dialog counted as consent');
      check(h._androidPackageVisibilityConsentRequest == null, 'the in-flight request stayed');
      h.whileOpen = null;
      await h.pinUnlockAccepted();
      check(h.events.length == 1, 'replayed at the unlock: ${h.events}');
      // The user taps the row again: it asks again.
      h._showDecoyCalculator = false;
      await h._toggleSplitTunnelPanel();
      check(h.events.length == 2 && h._splitTunnelExpanded, 'the tap did not ask again');
    case 'package_accepted_then_relock_during_the_write':
      h.isAndroid = true;
      h.answers['package'] = true;
      h.saveHook = () async => h.relock();
      await h._toggleSplitTunnelPanel();
      check(h._androidPackageVisibilityConsentVersion == 'pkg-v1' &&
              h.saved.join(',') == 'package:pkg-v1',
          'an answered consent was lost to the relock');
    // ---------------- legal acceptance ----------------
    case 'legal_control':
      h.answers['legal'] = true;
      final payload = await h._ensureLegalAcceptanceForActivation(account);
      check(payload != null, 'control: no payload');
      check(h.saved.join(',') == 'legal:legal-v2', 'control: ${h.saved}');
      check(h.events.join(',') == 'dialog:legal' && !h._deferredLegalConsent.isPending,
          'control: ${h.events}');
    case 'legal_behind_decoy_is_deferred_not_refused':
      h.answers['legal'] = true;
      h.relock();
      final payload = await h._ensureLegalAcceptanceForActivation(account);
      check(payload == null, 'the flow went on without acceptance');
      check(h.events.isEmpty, 'the dialog was drawn over the decoy: ${h.events}');
      check(h.saved.isEmpty && h._legalAcceptedVersion.isEmpty, 'acceptance stored behind the decoy');
      check(h.feedback.isEmpty, 'a message showed over the decoy');
      check(h._deferredLegalConsent.isPending, 'the blocked prompt was not kept');
    case 'legal_unlock_offers_once':
      h.answers['legal'] = true;
      h.relock();
      await h._ensureLegalAcceptanceForActivation(account);
      await h.pinUnlockAccepted();
      check(h.events.join(',') == 'dialog:legal', 'not offered once at the unlock: ${h.events}');
      check(h.saved.join(',') == 'legal:legal-v2', 'accept not stored: ${h.saved}');
      check(!h._deferredLegalConsent.isPending, 'still pending after the answer');
      h.relock();
      await h.pinUnlockAccepted();
      h.relock();
      await h.pinUnlockAccepted();
      check(h.events.length == 1, 'offered again: ${h.events}');
    case 'legal_unlock_offer_runs_after_the_other_unlock_prompts':
      h.answers['legal'] = true;
      h.relock();
      await h._ensureLegalAcceptanceForActivation(account);
      await h.pinUnlockAccepted();
      check(h.hookOrder.join(',') == 'restart,recovery-code',
          'unlock block order: ${h.hookOrder}');
      check(h.events.join(',') == 'dialog:legal', '${h.events}');
    case 'legal_no_longer_owed_at_the_unlock':
      // Re-evaluated from live state: accepted meanwhile, nothing is asked.
      h.answers['legal'] = true;
      h.relock();
      await h._ensureLegalAcceptanceForActivation(account);
      h._legalAcceptedVersion = 'legal-v2';
      h._legalAcceptedHash = 'h2';
      await h.pinUnlockAccepted();
      check(h.events.isEmpty && h.saved.isEmpty, 'asked though acceptance is current: ${h.events}');
      check(!h._deferredLegalConsent.isPending, 'the record outlived its use');
    case 'legal_other_account_session_is_dropped':
      h.answers['legal'] = true;
      h.relock();
      await h._ensureLegalAcceptanceForActivation(account);
      h._accountSessionEpoch.bump();
      await h.pinUnlockAccepted();
      check(h.events.isEmpty && h.saved.isEmpty, 'a prompt crossed account sessions: ${h.events}');
      check(!h._deferredLegalConsent.isPending, 'the stale record was kept');
      h.relock();
      await h.pinUnlockAccepted();
      check(h.events.isEmpty, 'the stale record came back');
    case 'legal_relock_unlock_with_nothing_pending':
      h.relock();
      await h.pinUnlockAccepted();
      h.relock();
      await h.pinUnlockAccepted();
      check(h.events.isEmpty && h.saved.isEmpty, 'a prompt appeared with nothing pending: ${h.events}');
    case 'legal_removed_mid_dialog_is_kept_then_answered':
      h.whileOpen = (label) async => h.relock();
      final payload = await h._ensureLegalAcceptanceForActivation(account);
      check(payload == null && h.saved.isEmpty, 'a removed dialog counted as acceptance');
      check(h._deferredLegalConsent.isPending, 'the removed prompt was not kept');
      h.whileOpen = null;
      h.answers['legal'] = true;
      await h.pinUnlockAccepted();
      check(h.events.join(',') == 'dialog:legal,dialog:legal', '${h.events}');
      check(h.saved.join(',') == 'legal:legal-v2', 'answer not stored: ${h.saved}');
      check(!h._deferredLegalConsent.isPending, 'pending after it was answered');
    case 'legal_offer_removed_by_another_relock_is_kept_again':
      h.answers['legal'] = true;
      h.relock();
      await h._ensureLegalAcceptanceForActivation(account);
      h.whileOpen = (label) async => h.relock();
      await h.pinUnlockAccepted();
      check(h.saved.isEmpty && h._deferredLegalConsent.isPending, 'lost to a second relock');
      h.whileOpen = null;
      await h.pinUnlockAccepted();
      check(h.saved.join(',') == 'legal:legal-v2', 'not answered at the next unlock');
    case 'legal_refusal_is_final':
      h.answers['legal'] = false;
      final payload = await h._ensureLegalAcceptanceForActivation(account);
      check(payload == null && !h._deferredLegalConsent.isPending, 'a refusal was kept');
      h.relock();
      await h.pinUnlockAccepted();
      check(h.events.length == 1, 'a refused prompt came back: ${h.events}');
    case 'legal_refused_at_the_unlock_is_final':
      h.answers['legal'] = false;
      h.relock();
      await h._ensureLegalAcceptanceForActivation(account);
      await h.pinUnlockAccepted();
      check(h.events.length == 1 && h.saved.isEmpty, '${h.events}');
      h.relock();
      await h.pinUnlockAccepted();
      check(h.events.length == 1, 'asked twice');
    case 'legal_back_gesture_while_unlocked_is_a_refusal':
      // null with the app unlocked is the system back gesture, not a removal.
      final payload = await h._ensureLegalAcceptanceForActivation(account);
      check(payload == null && !h._deferredLegalConsent.isPending,
          'a back gesture was kept as a blocked prompt');
    case 'legal_kept_across_a_second_trip_to_the_background':
      // The lifecycle callback re-arms the decoy (one more generation) each
      // time the app goes inactive, even with the calculator already showing.
      h.answers['legal'] = true;
      h.relock();
      await h._ensureLegalAcceptanceForActivation(account);
      h._decoyGeneration++;
      h._decoyGeneration++;
      await h.pinUnlockAccepted();
      check(h.saved.join(',') == 'legal:legal-v2', 'lost to a generation bump: ${h.events}');
    case 'legal_offer_never_runs_over_the_decoy':
      h.answers['legal'] = true;
      h.relock();
      await h._ensureLegalAcceptanceForActivation(account);
      await h._offerDeferredLegalConsent(h._decoyGeneration);
      check(h.events.isEmpty && h._deferredLegalConsent.isPending,
          'offered behind the decoy, or the record was dropped: ${h.events}');
      await h.pinUnlockAccepted();
      check(h.saved.join(',') == 'legal:legal-v2', 'not offered at the unlock');
    case 'legal_offer_stops_when_the_decoy_returns_during_the_lookup':
      h.answers['legal'] = true;
      h.relock();
      await h._ensureLegalAcceptanceForActivation(account);
      h.accountLookupHook = () async => h.relock();
      final loadsBefore = h.docLoads;
      await h.pinUnlockAccepted();
      check(h.docLoads == loadsBefore, 'the legal document was fetched behind the decoy');
      check(h.events.isEmpty && h.saved.isEmpty, 'asked over the decoy: ${h.events}');
      check(h._deferredLegalConsent.isPending, 'an unasked question was dropped');
      h.accountLookupHook = null;
      await h.pinUnlockAccepted();
      check(h.saved.join(',') == 'legal:legal-v2', 'not asked at the next unlock');
    case 'legal_record_survives_an_offer_attempt_over_the_decoy':
      // Nothing may consume or fetch behind the calculator; the record waits.
      h.answers['legal'] = true;
      h.relock();
      await h._ensureLegalAcceptanceForActivation(account);
      final loadsBefore = h.docLoads;
      final lookupsBefore = h.lookups;
      await h._offerDeferredLegalConsent(h._decoyGeneration);
      check(h._deferredLegalConsent.isPending, 'an offer over the decoy consumed the record');
      check(h.docLoads == loadsBefore && h.lookups == lookupsBefore, 'work ran behind the decoy');
    case 'legal_epoch_changing_during_the_lookup_drops_the_offer':
      h.answers['legal'] = true;
      h.relock();
      await h._ensureLegalAcceptanceForActivation(account);
      h.accountLookupHook = () async => h._accountSessionEpoch.bump();
      final loadsBefore = h.docLoads;
      await h.pinUnlockAccepted();
      check(h.events.isEmpty && h.saved.isEmpty, 'asked for another account session: ${h.events}');
      check(h.docLoads == loadsBefore, 'fetched for another account session');
      // The record is not consumed here (a record the new session made meanwhile is not ours to drop); it is
      // not owed to the new session and the next offer drops it.
      check(!h._deferredLegalConsent.isPendingFor(h._accountSessionEpoch.current),
          'the old session\'s record is owed to the new one');
      h.accountLookupHook = null;
      h._isLoggedIn = true;
      h.relock();
      await h.pinUnlockAccepted();
      check(h.events.isEmpty && h.saved.isEmpty, 'the stale record was offered: ${h.events}');
      check(!h._deferredLegalConsent.isPending, 'the stale record was kept');
    case 'legal_a_record_the_new_session_made_during_the_lookup_survives':
      h.answers['legal'] = true;
      h.relock();
      await h._ensureLegalAcceptanceForActivation(account);
      h.accountLookupHook = () async {
        h._accountSessionEpoch.bump();
        h._legalAcceptedVersion = '';
        // the decoy returns and a flow of the new session is blocked within the same read
        h.relock();
        await h._ensureLegalAcceptanceForActivation(account);
      };
      await h.pinUnlockAccepted();
      check(h._deferredLegalConsent.isPendingFor(h._accountSessionEpoch.current),
          'the new session\'s blocked question was dropped');
    case 'legal_not_offered_once_logged_out':
      h.answers['legal'] = true;
      h.relock();
      await h._ensureLegalAcceptanceForActivation(account);
      h._isLoggedIn = false;
      await h.pinUnlockAccepted();
      check(h.events.isEmpty && h.saved.isEmpty, 'offered with no account: ${h.events}');
      check(!h._deferredLegalConsent.isPending, 'kept after the account went');
    case 'legal_not_offered_while_privacy_consent_is_still_owed':
      // The unlock asks for privacy consent first; a refusal there must not
      // be followed by a second dialog.
      h.answers['legal'] = true;
      h.relock();
      await h._ensureLegalAcceptanceForActivation(account);
      h._privacyConsentGranted = false;
      h.answers['privacy'] = false;
      await h.pinUnlockAccepted();
      check(h.events.join(',') == 'dialog:privacy', '${h.events}');
      check(h.saved.isEmpty, 'legal stored without privacy consent');
    case 'legal_not_offered_over_a_connect_in_flight':
      // The connect that is already running asks for itself; the unlock does
      // not put a second dialog beside it.
      h.answers['legal'] = true;
      h.relock();
      await h._ensureLegalAcceptanceForActivation(account);
      h._isLoading = true;
      await h.pinUnlockAccepted();
      check(h.events.isEmpty && h.saved.isEmpty, 'asked beside a connect: ${h.events}');
      check(h._deferredLegalConsent.isPending, 'an owed question was dropped because a connect was loading');
      // The connect is over: the next unlock offers it.
      h._isLoading = false;
      h.relock();
      await h.pinUnlockAccepted();
      check(h.saved.join(',') == 'legal:legal-v2', 'not offered once the load ended: ${h.events}');
    case 'legal_logout_during_the_fetch_shows_and_writes_nothing':
      // Seat C, N1: the fetch takes seconds; the account is gone when it returns.
      h.answers['legal'] = true;
      h.relock();
      await h._ensureLegalAcceptanceForActivation(account);
      h.docLoadHook = () async {
        h._accountSessionEpoch.bump();
        h._isLoggedIn = false;
      };
      await h.pinUnlockAccepted();
      check(h.docLoads >= 2, 'the fetch did not run');
      check(h.events.isEmpty, 'a dialog appeared for a session that ended: ${h.events}');
      check(h.saved.isEmpty, 'an acceptance was written for a session that ended: ${h.saved}');
      check(!h._deferredLegalConsent.isPending, 'kept for another account session');
    case 'legal_relock_and_unlock_during_the_fetch_is_not_asked_by_the_old_offer':
      h.answers['legal'] = true;
      h.relock();
      await h._ensureLegalAcceptanceForActivation(account);
      h.docLoadHook = () async {
        h.relock();
        h.unlockOnly();
      };
      await h.pinUnlockAccepted();
      check(h.events.isEmpty && h.saved.isEmpty,
          'the offer of an earlier unlock asked in a later one: ${h.events}');
      check(h._deferredLegalConsent.isPending, 'the record was lost, not put back');
      h.docLoadHook = null;
      h.relock();
      await h.pinUnlockAccepted();
      check(h.saved.join(',') == 'legal:legal-v2', 'not asked at the next unlock');
    case 'legal_connect_started_during_the_fetch_keeps_the_record':
      h.answers['legal'] = true;
      h.relock();
      await h._ensureLegalAcceptanceForActivation(account);
      h.docLoadHook = () async => h._isLoading = true;
      await h.pinUnlockAccepted();
      check(h.events.isEmpty && h.saved.isEmpty, 'asked beside a connect: ${h.events}');
      check(h._deferredLegalConsent.isPending, 'the owed question was lost');
    case 'legal_answer_given_after_the_session_ended_is_not_written':
      h.answers['legal'] = true;
      h.relock();
      await h._ensureLegalAcceptanceForActivation(account);
      h.whileOpen = (label) async {
        h._accountSessionEpoch.bump();
      };
      await h.pinUnlockAccepted();
      check(h.events.join(',') == 'dialog:legal', '${h.events}');
      check(h.saved.isEmpty && h._legalAcceptedVersion.isEmpty,
          'an acceptance was written under a new session: ${h.saved}');
      check(!h._deferredLegalConsent.isPending, 'kept for another account session');
    case 'disclosure_answer_given_after_the_session_ended_is_not_written':
      h.isAndroid = true;
      h._legalAcceptedVersion = 'legal-v2';
      h._legalAcceptedHash = 'h2';
      h.answers['vpn-disclosure'] = true;
      h.relock();
      await h._ensureLegalAcceptanceForActivation(account);
      h.whileOpen = (label) async {
        h._accountSessionEpoch.bump();
      };
      await h.pinUnlockAccepted();
      check(h.saved.isEmpty && h._androidVpnServiceDisclosureConsentVersion.isEmpty,
          'a disclosure was recorded under a new session: ${h.saved}');
    case 'legal_two_callers_share_one_dialog':
      // Seat C, N3: the offer and a connect the user taps reach the question together.
      h.answers['legal'] = true;
      final first = h._ensureLegalAcceptanceForActivation(account);
      final second = h._ensureLegalAcceptanceForActivation(account);
      final payloads = await Future.wait(<Future<Map<String, dynamic>?>>[first, second]);
      check(payloads.every((p) => p != null), 'a caller was refused');
      check(h.events.join(',') == 'dialog:legal', 'the dialogs stacked: ${h.events}');
      check(h._legalAcceptanceDialogRequest == null, 'the shared request stayed');
    case 'legal_a_refusal_is_shared_too_and_the_next_ask_opens_a_new_dialog':
      h.answers['legal'] = false;
      final first = h._ensureLegalAcceptanceForActivation(account);
      final second = h._ensureLegalAcceptanceForActivation(account);
      final payloads = await Future.wait(<Future<Map<String, dynamic>?>>[first, second]);
      check(payloads.every((p) => p == null), 'a refusal was read as consent');
      check(h.events.length == 1, 'stacked: ${h.events}');
      h.answers['legal'] = true;
      final third = await h._ensureLegalAcceptanceForActivation(account);
      check(third != null && h.events.length == 2, 'a later ask did not open its own dialog');
    case 'legal_interrupted_flow_decline_is_worded_for_the_connect':
      h.answers['legal'] = false;
      h.relock();
      await h._ensureLegalAcceptanceForActivation(account);
      h.feedback.clear();
      await h.pinUnlockAccepted();
      check(h.feedback.length == 1 &&
              !h.feedback.single.contains('before activation') &&
              h.feedback.single.contains('connect'),
          'decline wording: ${h.feedback}');
      h.feedback.clear();
      await h._ensureLegalAcceptanceForActivation(account);
      check(h.feedback.single == 'Legal acceptance is required before activation.',
          'the activation wording changed: ${h.feedback}');
    // ---------------- mandatory PIN reset ----------------
    case 'pin_reset_control':
      h._pinResetRequired = true;
      h.whileOpen = (label) async {
        final error = await h._commitPinReset('482915');
        check(error == null, 'control: save failed: $error');
        h.answers['pin-reset'] = true;
      };
      await h._promptForMandatoryPinReset();
      check(h.replaced == 1 && !h._pinResetRequired && h._calculatorPinEntry.pinLength == 6,
          'control state');
      check(h.issued == 1, 'the spent recovery code was not retired: ${h.issued}');
    case 'pin_reset_behind_decoy':
      h._pinResetRequired = true;
      h.relock();
      await h._promptForMandatoryPinReset();
      check(h.events.isEmpty && h.replaced == 0 && h.issued == 0, 'something ran behind the decoy');
      check(h._pinResetRequired, 'the debt was cleared');
    case 'pin_reset_save_pressed_then_relock_during_the_write':
      h._pinResetRequired = true;
      h.whileOpen = (label) async {
        // The relock removes the dialog while the write is still running: the
        // dialog's answer (null) arrives BEFORE the write finishes.
        h.replaceHook = () async {
          h.relock();
          await Future<void>.delayed(const Duration(milliseconds: 30));
        };
        unawaited(h._commitPinReset('482915'));
      };
      await h._promptForMandatoryPinReset();
      check(h.replaced == 1, 'the prompt returned before the write committed');
      check(h._calculatorPinEntry.pinLength == 6,
          'the keypad expects ${h._calculatorPinEntry.pinLength} digits for a 6-digit credential');
      check(!h._pinResetRequired, 'the debt stayed for a credential already replaced');
      check(h.issued == 1, 'the typed recovery code was not retired after the interruption');
      check(h.feedback.isEmpty, 'a message showed over the decoy');
    case 'pin_reset_removed_before_save_keeps_the_debt_and_retires_nothing':
      h._pinResetRequired = true;
      h.whileOpen = (label) async => h.relock();
      await h._promptForMandatoryPinReset();
      check(h.replaced == 0 && h.issued == 0, 'stored or retired though nobody saved');
      check(h._pinResetRequired && h._calculatorPinEntry.pinLength == 4, 'state moved without a commit');
      h.whileOpen = null;
      h.answers['pin-reset'] = false;
      await h.pinUnlockAccepted();
      check(h.events.join(',') == 'dialog:pin-reset,dialog:pin-reset', 'the unlock did not ask again: ${h.events}');
    case 'pin_reset_weak_code_and_failed_write_change_nothing':
      h._pinResetRequired = true;
      check(await h._commitPinReset('123456') != null, 'a weak code was accepted');
      h.replaceHook = () async => throw StateError('disk');
      check(await h._commitPinReset('482915') != null, 'a failed write reported success');
      check(h.replaced == 0 && h._pinResetRequired && !h._pinResetCommitted &&
              h._calculatorPinEntry.pinLength == 4,
          'state moved without a stored credential');
    case 'pin_reset_flag_does_not_leak_into_the_next_prompt':
      h._pinResetRequired = true;
      h.whileOpen = (label) async {
        await h._commitPinReset('482915');
        h.answers['pin-reset'] = true;
      };
      await h._promptForMandatoryPinReset();
      h.whileOpen = null;
      h._pinResetRequired = true;
      h.answers['pin-reset'] = false;
      await h._promptForMandatoryPinReset();
      check(h.issued == 1, 'a refusal retired a code: ${h.issued}');
    case 'disclosure_not_asked_when_the_session_ends_during_the_legal_save':
      // Legal is answered and stored; the account goes while it is written;
      // the disclosure that follows must not be asked of the next session.
      h.isAndroid = true;
      h.answers['legal'] = true;
      h.answers['vpn-disclosure'] = true;
      h.relock();
      await h._ensureLegalAcceptanceForActivation(account);
      h.saveHook = () async {
        h._accountSessionEpoch.bump();
        h._isLoggedIn = false;
      };
      await h.pinUnlockAccepted();
      check(h.events.join(',') == 'dialog:legal', 'the disclosure followed a session that ended: ${h.events}');
      check(!h._deferredLegalConsent.isPending, 'kept for another account session');
    case 'disclosure_not_asked_beside_a_connect_that_started_during_the_legal_save':
      h.isAndroid = true;
      h.answers['legal'] = true;
      h.answers['vpn-disclosure'] = true;
      h.relock();
      await h._ensureLegalAcceptanceForActivation(account);
      h.saveHook = () async => h._isLoading = true;
      await h.pinUnlockAccepted();
      check(h.events.join(',') == 'dialog:legal', 'the disclosure was asked beside a connect: ${h.events}');
      // Legal got a real answer: the record is dropped (every connect asks for the disclosure itself).
      check(!h._deferredLegalConsent.isPending, 'a decided question was put back');
    // ---------------- Turn 3 ----------------
    case 'legal_answer_in_the_connects_own_dialog_drops_the_put_back_record':
      // Seat C, OI-F3-8R: refused in the connect's dialog, the next unlock must not ask again.
      h.answers['legal'] = false;
      h.relock();
      await h._ensureLegalAcceptanceForActivation(account);
      h.docLoadHook = () async => h._isLoading = true;
      await h.pinUnlockAccepted();
      check(h._deferredLegalConsent.isPending, 'precondition: the offer lapsed and put the record back');
      h.docLoadHook = null;
      h._isLoading = false;
      final payload = await h._ensureLegalAcceptanceForActivation(account);
      check(payload == null, 'the connect accepted for the user');
      check(!h._deferredLegalConsent.isPending, 'a refused question stayed pending');
      h.relock();
      await h.pinUnlockAccepted();
      check(h.events.join(',') == 'dialog:legal', 'the refused question was asked again: ${h.events}');
    case 'legal_accepted_in_the_connects_own_dialog_drops_the_record_too':
      h.answers['legal'] = true;
      h.relock();
      await h._ensureLegalAcceptanceForActivation(account);
      h.docLoadHook = () async => h._isLoading = true;
      await h.pinUnlockAccepted();
      h.docLoadHook = null;
      h._isLoading = false;
      check(await h._ensureLegalAcceptanceForActivation(account) != null, 'connect refused');
      check(!h._deferredLegalConsent.isPending, 'an accepted question stayed pending');
    case 'legal_a_real_answer_in_another_epoch_does_not_drop_the_record':
      h.answers['legal'] = true;
      h.relock();
      await h._ensureLegalAcceptanceForActivation(account);
      final answered = h._deferredLegalConsent.answerCount;
      h.relock();
      h.unlockOnly();
      h.whileOpen = (label) async => h._accountSessionEpoch.bump();
      h._legalAcceptedVersion = '';
      await h._ensureLegalAcceptanceForActivation(account);
      check(h._deferredLegalConsent.answerCount == answered, 'an answer from a session that ended counted');
    case 'legal_shared_dialog_v2_shown_v3_gets_its_own':
      h.answers['legal'] = true;
      h.docQueue.addAll(<Map<String, String>>[
        <String, String>{'version': 'legal-v2', 'hash': 'h2', 'body': 'b', 'display_body': 'd'},
        <String, String>{'version': 'legal-v3', 'hash': 'h3', 'body': 'b', 'display_body': 'd'},
      ]);
      final a = h._ensureLegalAcceptanceForActivation(account);
      final b = h._ensureLegalAcceptanceForActivation(account);
      final both = await Future.wait(<Future<Map<String, dynamic>?>>[a, b]);
      check(h.events.join(',') == 'dialog:legal,dialog:legal', 'one dialog served two documents: ${h.events}');
      check(h.maxOpen == 1, 'two legal dialogs were open at once: ${h.maxOpen}');
      check(both[0]!['legal_version'] == 'legal-v2', 'first payload: ${both[0]}');
      check(both[1]!['legal_version'] == 'legal-v3', 'second payload was not the document shown: ${both[1]}');
      check(h.saved.join(',') == 'legal:legal-v2,legal:legal-v3', 'stored: ${h.saved}');
      check(h._legalAcceptanceDialogRequest == null, 'the shared request stayed');
    case 'legal_bundled_waiter_after_an_acceptance_asks_nothing_and_never_writes_the_older_record':
      // Seat F and Seat C: the live v3/h3 is accepted; the caller holding the bundled v2/'' must not ask again
      // and must not overwrite the record with its fallback copy.
      h.answers['legal'] = true;
      h.docQueue.addAll(<Map<String, String>>[
        <String, String>{'version': 'legal-v3', 'hash': 'h3', 'body': 'b', 'display_body': 'd'},
        <String, String>{'version': 'legal-v2', 'hash': '', 'body': 'b', 'display_body': 'd'},
      ]);
      final a = h._ensureLegalAcceptanceForActivation(account);
      final b = h._ensureLegalAcceptanceForActivation(account);
      final both = await Future.wait(<Future<Map<String, dynamic>?>>[a, b]);
      check(h.events.join(',') == 'dialog:legal', 'the fallback caller asked again: ${h.events}');
      check(h.saved.join(',') == 'legal:legal-v3', 'stored: ${h.saved}');
      check(h._legalAcceptedVersion == 'legal-v3' && h._legalAcceptedHash == 'h3',
          'the record on file regressed to ${h._legalAcceptedVersion}/${h._legalAcceptedHash}');
      check(both[0]!['legal_version'] == 'legal-v3' && both[1]!['legal_version'] == 'legal-v3',
          'the fallback caller sent another document: $both');
      // Every later caller is served the record on file, with no fetch.
      final loads = h.docLoads;
      final third = await h._ensureLegalAcceptanceForActivation(account);
      check(third!['legal_version'] == 'legal-v3' && h.docLoads == loads, 'later caller: $third');
    case 'legal_bundled_waiter_after_a_refusal_asks_its_own':
      h.answers['legal'] = false;
      h.docQueue.addAll(<Map<String, String>>[
        <String, String>{'version': 'legal-v3', 'hash': 'h3', 'body': 'b', 'display_body': 'd'},
        <String, String>{'version': 'legal-v2', 'hash': '', 'body': 'b', 'display_body': 'd'},
      ]);
      final a = h._ensureLegalAcceptanceForActivation(account);
      final b = h._ensureLegalAcceptanceForActivation(account);
      final both = await Future.wait(<Future<Map<String, dynamic>?>>[a, b]);
      check(h.events.length == 2 && both.every((p) => p == null) && h.saved.isEmpty,
          'a refusal was treated as an acceptance: ${h.events} $both ${h.saved}');
    case 'legal_waiter_with_another_live_document_cancelled_does_not_fail_the_connect':
      // v2/h2 accepted; the caller holding the live v3/h3 asks its own and the user cancels. The acceptance on
      // file stands, so the connect is not failed.
      h.answerSeq['legal'] = <bool?>[true, false];
      h.docQueue.addAll(<Map<String, String>>[
        <String, String>{'version': 'legal-v2', 'hash': 'h2', 'body': 'b', 'display_body': 'd'},
        <String, String>{'version': 'legal-v3', 'hash': 'h3', 'body': 'b', 'display_body': 'd'},
      ]);
      final a = h._ensureLegalAcceptanceForActivation(account);
      final b = h._ensureLegalAcceptanceForActivation(account);
      final both = await Future.wait(<Future<Map<String, dynamic>?>>[a, b]);
      check(h.events.length == 2, 'dialogs: ${h.events}');
      check(both[0] != null && both[1] != null, 'a connect was failed with a valid acceptance on file: $both');
      check(h.saved.join(',') == 'legal:legal-v2', 'stored: ${h.saved}');
      check(h.feedback.isEmpty, 'a failure message showed: ${h.feedback}');
      check(both[1]!['legal_version'] == 'legal-v2', 'payload names what is on file: ${both[1]}');
    case 'legal_live_waiter_cancelled_behind_an_accepted_bundled_document_does_not_fail_the_connect':
      h.answerSeq['legal'] = <bool?>[true, false];
      h.docQueue.addAll(<Map<String, String>>[
        <String, String>{'version': 'legal-v2', 'hash': '', 'body': 'b', 'display_body': 'd'},
        <String, String>{'version': 'legal-v3', 'hash': 'h3', 'body': 'b', 'display_body': 'd'},
      ]);
      final a = h._ensureLegalAcceptanceForActivation(account);
      final b = h._ensureLegalAcceptanceForActivation(account);
      final both = await Future.wait(<Future<Map<String, dynamic>?>>[a, b]);
      check(h.events.length == 2, 'dialogs: ${h.events}');
      check(both[0] != null && both[1] != null && h.feedback.isEmpty,
          'a connect was failed with an acceptance on file: $both ${h.feedback}');
    case 'legal_waiter_does_not_ask_beside_a_connect_that_started_while_it_waited':
      h.answers['legal'] = true;
      h.docQueue.addAll(<Map<String, String>>[
        <String, String>{'version': 'legal-v3', 'hash': 'h3', 'body': 'b', 'display_body': 'd'},
        <String, String>{'version': 'legal-v4', 'hash': 'h4', 'body': 'b', 'display_body': 'd'},
      ]);
      h.whileOpen = (label) async => h._isLoading = true;
      final a = h._ensureLegalAcceptanceForActivation(account);
      final b = h._ensureLegalAcceptanceForActivation(account, canAsk: () => !h._isLoading);
      final both = await Future.wait(<Future<Map<String, dynamic>?>>[a, b]);
      check(h.events.join(',') == 'dialog:legal', 'the waiter asked beside a connect: ${h.events}');
      check(both[1] == null && h.saved.join(',') == 'legal:legal-v3', 'stored ${h.saved} $both');
    case 'legal_waiter_does_not_ask_after_its_session_ended_while_it_waited':
      h.answers['legal'] = true;
      h.docQueue.addAll(<Map<String, String>>[
        <String, String>{'version': 'legal-v3', 'hash': 'h3', 'body': 'b', 'display_body': 'd'},
        <String, String>{'version': 'legal-v4', 'hash': 'h4', 'body': 'b', 'display_body': 'd'},
      ]);
      // The session ends while the waiter waits, after it passed its own post-fetch check.
      h.whileOpen = (label) async {
        await Future<void>.delayed(const Duration(milliseconds: 10));
        h._isLoggedIn = false;
      };
      final a = h._ensureLegalAcceptanceForActivation(account);
      final b = h._ensureLegalAcceptanceForActivation(account, stillCurrent: () => h._isLoggedIn);
      final both = await Future.wait(<Future<Map<String, dynamic>?>>[a, b]);
      check(h.events.join(',') == 'dialog:legal', 'the waiter asked after its session ended: ${h.events}');
      check(both[1] == null && h.saved.join(',') == 'legal:legal-v3', 'stored ${h.saved} $both');
    case 'legal_six_callers_over_three_documents_never_stack':
      // Seat C: a waiter must keep waiting while ANOTHER document's dialog opens, not wait once.
      h.answers['legal'] = true;
      final docs = <List<String>>[
        <String>['legal-v2', 'h2'], <String>['legal-v3', 'h3'], <String>['legal-v4', 'h4'],
        <String>['legal-v3', 'h3'], <String>['legal-v2', 'h2'], <String>['legal-v4', 'h4'],
      ];
      for (final d in docs) {
        h.docQueue.add(<String, String>{'version': d[0], 'hash': d[1], 'body': 'b', 'display_body': 'd'});
      }
      final calls = <Future<Map<String, dynamic>?>>[
        for (var i = 0; i < docs.length; i++) h._ensureLegalAcceptanceForActivation(account),
      ];
      final results = await Future.wait(calls);
      check(h.maxOpen == 1, 'dialogs stacked: maxOpen=${h.maxOpen} events=${h.events}');
      check(h.events.length == 3, 'one dialog per document expected: ${h.events}');
      check(results.every((r) => r != null), 'a caller was refused: $results');
      check(h._legalAcceptanceDialogRequest == null, 'the shared request stayed');
    case 'pin_upgrade_second_dialog_during_the_write_waits_and_asks_nothing':
      // Seat C: the second dialog would receive the first write's answer for a different code.
      final gate = Completer<void>();
      h.whileOpen = (label) async {
        h.replaceHook = () async {
          h.relock();
          await gate.future;
        };
        unawaited(h._commitPinUpgrade('482915'));
      };
      final first = h._promptForPinUpgrade();
      await Future<void>.delayed(const Duration(milliseconds: 20));
      h.whileOpen = null;
      h.unlockOnly();
      final second = h._promptForPinUpgrade();
      await Future<void>.delayed(const Duration(milliseconds: 20));
      gate.complete();
      await first;
      await second;
      check(h.events.join(',') == 'dialog:pin-upgrade', 'a second upgrade dialog opened: ${h.events}');
      check(h.replaced == 1 && !h._pinUpgradeAvailable && h._calculatorPinEntry.pinLength == 6, 'state');
    case 'pin_upgrade_second_dialog_after_a_failed_write_asks_again':
      final gate = Completer<void>();
      h.whileOpen = (label) async {
        h.replaceHook = () async {
          h.relock();
          await gate.future;
          throw StateError('disk');
        };
        unawaited(h._commitPinUpgrade('482915'));
      };
      final first = h._promptForPinUpgrade();
      await Future<void>.delayed(const Duration(milliseconds: 20));
      h.whileOpen = null;
      h.replaceHook = null;
      h.unlockOnly();
      final second = h._promptForPinUpgrade();
      await Future<void>.delayed(const Duration(milliseconds: 20));
      gate.complete();
      await first;
      await second;
      check(h.replaced == 0 && h._pinUpgradeAvailable, 'state moved after a failed write');
      check(h.events.join(',') == 'dialog:pin-upgrade,dialog:pin-upgrade', 'the second prompt did not ask: ${h.events}');
    case 'legal_same_version_other_hash_is_not_shared':
      h.answers['legal'] = true;
      h.docQueue.addAll(<Map<String, String>>[
        <String, String>{'version': 'legal-v2', 'hash': 'h2', 'body': 'b', 'display_body': 'd'},
        <String, String>{'version': 'legal-v2', 'hash': 'hX', 'body': 'b', 'display_body': 'd'},
      ]);
      final a = h._ensureLegalAcceptanceForActivation(account);
      final b = h._ensureLegalAcceptanceForActivation(account);
      await Future.wait(<Future<Map<String, dynamic>?>>[a, b]);
      check(h.events.length == 2, 'a different hash joined the open dialog: ${h.events}');
    case 'legal_waiting_caller_is_refused_with_its_own_dialog':
      h.answers['legal'] = false;
      h.docQueue.addAll(<Map<String, String>>[
        <String, String>{'version': 'legal-v2', 'hash': 'h2', 'body': 'b', 'display_body': 'd'},
        <String, String>{'version': 'legal-v3', 'hash': 'h3', 'body': 'b', 'display_body': 'd'},
      ]);
      final a = h._ensureLegalAcceptanceForActivation(account);
      final b = h._ensureLegalAcceptanceForActivation(account);
      final both = await Future.wait(<Future<Map<String, dynamic>?>>[a, b]);
      check(both.every((p) => p == null) && h.saved.isEmpty && h.events.length == 2,
          'a refusal leaked across documents: $both ${h.saved} ${h.events}');
    case 'pin_reset_reentry_during_the_write_asks_nothing_and_mints_once':
      // Seat F: relock during a slow write, unlock with the old code before it commits.
      h._pinResetRequired = true;
      final gate = Completer<void>();
      h.whileOpen = (label) async {
        h.replaceHook = () async {
          h.relock();
          await gate.future;
        };
        unawaited(h._commitPinReset('482915'));
      };
      final first = h._promptForMandatoryPinReset();
      await Future<void>.delayed(const Duration(milliseconds: 20));
      h.whileOpen = null;
      final unlock = h.pinUnlockAccepted();
      await Future<void>.delayed(const Duration(milliseconds: 20));
      gate.complete();
      await first;
      await unlock;
      check(h.events.join(',') == 'dialog:pin-reset', 'a second reset dialog opened: ${h.events}');
      check(h.replaced == 1, 'two credentials were written: ${h.replaced}');
      check(h.issued == 1, 'recovery codes minted: ${h.issued}');
      check(!h._pinResetRequired && h._calculatorPinEntry.pinLength == 6, 'state');
    case 'pin_reset_reentry_after_a_failed_write_asks_again':
      h._pinResetRequired = true;
      final gate = Completer<void>();
      h.whileOpen = (label) async {
        h.replaceHook = () async {
          h.relock();
          await gate.future;
          throw StateError('disk');
        };
        unawaited(h._commitPinReset('482915'));
      };
      final first = h._promptForMandatoryPinReset();
      await Future<void>.delayed(const Duration(milliseconds: 20));
      h.whileOpen = null;
      h.replaceHook = null;
      final unlock = h.pinUnlockAccepted();
      await Future<void>.delayed(const Duration(milliseconds: 20));
      gate.complete();
      await first;
      await unlock;
      check(h.replaced == 0 && h.issued == 0, 'stored or minted after a failed write');
      check(h._pinResetRequired, 'the debt was cleared');
      check(h.events.join(',') == 'dialog:pin-reset,dialog:pin-reset', 'the unlock did not ask again: ${h.events}');
    case 'pin_reset_out_of_order_second_save_cannot_hide_the_commit':
      // Seat C: a slow valid write, then a second Save that would return first.
      h._pinResetRequired = true;
      final gate = Completer<void>();
      h.whileOpen = (label) async {
        h.replaceHook = () async {
          h.relock();
          await gate.future;
        };
        unawaited(h._commitPinReset('482915'));
        unawaited(h._commitPinReset('123456'));
      };
      final prompt = h._promptForMandatoryPinReset();
      await Future<void>.delayed(const Duration(milliseconds: 20));
      gate.complete();
      await prompt;
      check(h.replaced == 1, 'writes: ${h.replaced}');
      check(!h._pinResetRequired && h._calculatorPinEntry.pinLength == 6, 'state');
      check(h.issued == 1, 'the spent recovery code was not retired (issued=${h.issued})');
    case 'pin_reset_double_save_writes_once':
      h._pinResetRequired = true;
      final gate = Completer<void>();
      h.replaceHook = () async => gate.future;
      final one = h._commitPinReset('482915');
      final two = h._commitPinReset('482915');
      gate.complete();
      check(await one == null && await two == null, 'save results');
      check(h.replaced == 1, 'two writes on one credential: ${h.replaced}');
      // The latch is released afterwards.
      h.replaceHook = null;
      check(await h._commitPinReset('482916') == null && h.replaced == 2, 'the latch stayed shut');
    case 'pin_upgrade_double_save_writes_once':
      final gate = Completer<void>();
      h.replaceHook = () async => gate.future;
      final one = h._commitPinUpgrade('482915');
      final two = h._commitPinUpgrade('482915');
      gate.complete();
      check(await one == null && await two == null, 'save results');
      check(h.replaced == 1, 'two writes on one credential: ${h.replaced}');
      h.replaceHook = null;
      check(await h._commitPinUpgrade('482916') == null && h.replaced == 2, 'the latch stayed shut');
    case 'pin_reset_failed_first_save_releases_the_latch':
      h._pinResetRequired = true;
      h.replaceHook = () async => throw StateError('disk');
      check(await h._commitPinReset('482915') != null, 'a failed write reported success');
      h.replaceHook = null;
      check(await h._commitPinReset('482915') == null && h.replaced == 1, 'the latch stayed shut after a failure');
    case 'legal_same_hash_other_version_is_not_shared':
      h.answers['legal'] = true;
      h.docQueue.addAll(<Map<String, String>>[
        <String, String>{'version': 'legal-v2', 'hash': 'h2', 'body': 'b', 'display_body': 'd'},
        <String, String>{'version': 'legal-v3', 'hash': 'h2', 'body': 'b', 'display_body': 'd'},
      ]);
      final a = h._ensureLegalAcceptanceForActivation(account);
      final b = h._ensureLegalAcceptanceForActivation(account);
      final both = await Future.wait(<Future<Map<String, dynamic>?>>[a, b]);
      check(h.events.length == 2 && h.maxOpen == 1, 'another version joined the open dialog: ${h.events} ${h.maxOpen}');
      check(both[1]!['legal_version'] == 'legal-v3', 'payload: ${both[1]}');
    case 'pin_reset_double_save_then_a_removed_prompt_retires_nothing':
      // Fable: with two Saves in flight the first prompt's flag could linger; a later prompt removed before Save
      // must not retire a code. The Save latch means one write, one retirement.
      h._pinResetRequired = true;
      final gate = Completer<void>();
      h.whileOpen = (label) async {
        h.replaceHook = () async {
          h.relock();
          await gate.future;
        };
        unawaited(h._commitPinReset('482915'));
        unawaited(h._commitPinReset('482915'));
      };
      final prompt = h._promptForMandatoryPinReset();
      await Future<void>.delayed(const Duration(milliseconds: 20));
      gate.complete();
      await prompt;
      check(h.issued == 1 && h.replaced == 1, 'first prompt: issued=${h.issued} replaced=${h.replaced}');
      h.whileOpen = (label) async => h.relock();
      h.replaceHook = null;
      h._pinResetRequired = true;
      h._showDecoyCalculator = false;
      await h._promptForMandatoryPinReset();
      check(h.issued == 1, 'a removed prompt retired a code with no write: ${h.issued}');
    case 'legal_connect_started_during_the_account_lookup_reads_nothing_and_keeps_the_record':
      h.answers['legal'] = true;
      h.relock();
      await h._ensureLegalAcceptanceForActivation(account);
      h.accountLookupHook = () async => h._isLoading = true;
      final loadsBefore = h.docLoads;
      await h.pinUnlockAccepted();
      check(h.docLoads == loadsBefore, 'the legal text was fetched beside a connect');
      check(h.events.isEmpty && h.saved.isEmpty, 'asked beside a connect: ${h.events}');
      check(h._deferredLegalConsent.isPending, 'the owed question was lost');
    case 'legal_dialog_guard_direct_callers_over_three_documents_never_stack':
      // The guard inside the dialog function itself (Seat C's six callers, called directly).
      h.answers['legal'] = true;
      Map<String, String> d(String v, String hh) => <String, String>{'version': v, 'hash': hh, 'body': 'b', 'display_body': 'd'};
      final ds = <Map<String, String>>[d('v2', 'h2'), d('v3', 'h3'), d('v4', 'h4'), d('v3', 'h3'), d('v2', 'h2'), d('v4', 'h4')];
      final got = await Future.wait(<Future<bool>>[for (final x in ds) h._showLegalAcceptanceDialog(x)]);
      check(h.maxOpen == 1, 'dialogs stacked: maxOpen=${h.maxOpen}');
      check(h.events.length == 3, 'one dialog per document expected: ${h.events}');
      check(got.every((x) => x), 'answers: $got');
    case 'legal_dialog_guard_same_document_joins_and_another_waits':
      h.answers['legal'] = true;
      Map<String, String> d2(String v, String hh) => <String, String>{'version': v, 'hash': hh, 'body': 'b', 'display_body': 'd'};
      final x1 = h._showLegalAcceptanceDialog(d2('v2', 'h2'));
      final x2 = h._showLegalAcceptanceDialog(d2('v2', 'h2'));
      final x3 = h._showLegalAcceptanceDialog(d2('v2', 'hX'));
      final x4 = h._showLegalAcceptanceDialog(d2('v9', 'h2'));
      await Future.wait(<Future<bool>>[x1, x2, x3, x4]);
      check(h.events.length == 3 && h.maxOpen == 1, 'events=${h.events} maxOpen=${h.maxOpen}');
    // ---------------- Turn 5 ----------------
    case 'pin_upgrade_two_taps_during_a_failed_write_open_one_dialog':
      // Seat C: every extra tap during the wait added another waiter; all woke on the failure and opened a dialog.
      final gate = Completer<void>();
      h.whileOpen = (label) async {
        h.replaceHook = () async {
          h.relock();
          await gate.future;
          throw StateError('disk');
        };
        unawaited(h._commitPinUpgrade('482915'));
      };
      final first = h._promptForPinUpgrade();
      await Future<void>.delayed(const Duration(milliseconds: 20));
      h.whileOpen = null;
      h.replaceHook = null;
      h.unlockOnly();
      final tapA = h._promptForPinUpgrade();
      final tapB = h._promptForPinUpgrade();
      await Future<void>.delayed(const Duration(milliseconds: 20));
      gate.complete();
      await bounded(Future.wait(<Future<void>>[first, tapA, tapB]));
      check(h.events.join(',') == 'dialog:pin-upgrade,dialog:pin-upgrade', 'dialogs: ${h.events}');
      check(h.maxOpen == 1, 'two upgrade dialogs open at once: ${h.maxOpen}');
      check(h.replaced == 0 && h._pinUpgradeAvailable, 'state moved after a failed write');
    case 'pin_reset_two_unlocks_during_a_failed_write_open_one_dialog':
      h._pinResetRequired = true;
      final gate = Completer<void>();
      h.whileOpen = (label) async {
        h.replaceHook = () async {
          h.relock();
          await gate.future;
          throw StateError('disk');
        };
        unawaited(h._commitPinReset('482915'));
      };
      final first = h._promptForMandatoryPinReset();
      await Future<void>.delayed(const Duration(milliseconds: 20));
      h.whileOpen = null;
      h.replaceHook = null;
      h.unlockOnly();
      final tapA = h._promptForMandatoryPinReset();
      final tapB = h._promptForMandatoryPinReset();
      await Future<void>.delayed(const Duration(milliseconds: 20));
      gate.complete();
      await bounded(Future.wait(<Future<void>>[first, tapA, tapB]));
      check(h.events.join(',') == 'dialog:pin-reset,dialog:pin-reset' && h.maxOpen == 1,
          'dialogs: ${h.events} maxOpen=${h.maxOpen}');
    case 'legal_cancel_after_an_acceptance_returns_nothing_when_the_session_ended':
      // Sol N-1 (non-Android): A accepts v2; B waits, presents v3, its session ends, the user cancels.
      h.answerSeq['legal'] = <bool?>[true, false];
      h.docQueue.addAll(<Map<String, String>>[
        <String, String>{'version': 'legal-v2', 'hash': 'h2', 'body': 'b', 'display_body': 'd'},
        <String, String>{'version': 'legal-v3', 'hash': 'h3', 'body': 'b', 'display_body': 'd'},
      ]);
      var bCurrent = true;
      var opens = 0;
      h.whileOpen = (label) async {
        opens++;
        if (opens == 2) bCurrent = false;
      };
      final a = h._ensureLegalAcceptanceForActivation(account);
      final b = h._ensureLegalAcceptanceForActivation(account, stillCurrent: () => bCurrent);
      final both = await bounded(Future.wait(<Future<Map<String, dynamic>?>>[a, b]));
      check(both[0] != null, 'the first caller: ${both[0]}');
      check(both[1] == null, 'a caller whose session ended got a result: ${both[1]}');
      check(h.feedback.isEmpty, 'message: ${h.feedback}');
    case 'legal_late_fetch_joiner_of_a_cancelled_dialog_gets_the_same_result':
      // Sol N-2: B and C hold v3; A's v2 is accepted first; C's fetch is late and joins B's dialog; both cancel.
      h.answerSeq['legal'] = <bool?>[true, false];
      h.docQueue.addAll(<Map<String, String>>[
        <String, String>{'version': 'legal-v2', 'hash': 'h2', 'body': 'b', 'display_body': 'd'},
        <String, String>{'version': 'legal-v3', 'hash': 'h3', 'body': 'b', 'display_body': 'd'},
        <String, String>{'version': 'legal-v3', 'hash': 'h3', 'body': 'b', 'display_body': 'd'},
      ]);
      final gate = Completer<void>();
      h.docLoadHook = () async {
        if (h.docLoads == 3) await gate.future;
      };
      var opens = 0;
      h.whileOpen = (label) async {
        opens++;
        if (opens == 2) {
          gate.complete();
          await Future<void>.delayed(const Duration(milliseconds: 20));
        }
      };
      final a = h._ensureLegalAcceptanceForActivation(account);
      final b = h._ensureLegalAcceptanceForActivation(account);
      final c = h._ensureLegalAcceptanceForActivation(account);
      final res = await bounded(Future.wait(<Future<Map<String, dynamic>?>>[a, b, c]));
      check(h.events.length == 2, 'dialogs: ${h.events}');
      check(res.every((r) => r != null && r['legal_version'] == 'legal-v2'), 'results differ for one acceptance on file: $res');
      check(h.feedback.isEmpty, 'a failure message showed: ${h.feedback}');
    case 'c4_e1_bundled_third_caller_after_a_cancel_then_an_acceptance':
      // Seat C: O (live v3/h3) is cancelled; W1 (v4/h4) and W2 (bundled) waited behind it. W1 is accepted;
      // W2 waits again behind W1 and must then be served v4/h4.
      h.answerSeq['legal'] = <bool?>[false, true, true];
      Map<String, String> d(String v, String hh) =>
          <String, String>{'version': v, 'hash': hh, 'body': 'b', 'display_body': 'd'};
      h.docQueue.addAll(<Map<String, String>>[d('legal-v3', 'h3'), d('legal-v4', 'h4'), d('legal-v2', '')]);
      final calls = <Future<Map<String, dynamic>?>>[
        for (var i = 0; i < 3; i++) h._ensureLegalAcceptanceForActivation(account),
      ];
      final res = await bounded(Future.wait(calls));
      check(h.maxOpen == 1, 'dialogs stacked: ${h.maxOpen}');
      check(h.events.length == 2, 'the bundled caller asked again after its second wait: ${h.events}');
      check(h.saved.join(',') == 'legal:legal-v4', 'stored: ${h.saved}');
      check(h._legalAcceptedVersion == 'legal-v4' && h._legalAcceptedHash == 'h4',
          'the record on file regressed to ${h._legalAcceptedVersion}/${h._legalAcceptedHash}');
      check(res[0] == null && res[1]!['legal_version'] == 'legal-v4' && res[2]!['legal_version'] == 'legal-v4', 'payloads: $res');
    case 'c4_e4_joiner_writes_after_the_owner_lapsed':
      h.answers['legal'] = true;
      Map<String, String> d(String v, String hh) =>
          <String, String>{'version': v, 'hash': hh, 'body': 'b', 'display_body': 'd'};
      h.docQueue.addAll(<Map<String, String>>[d('legal-v3', 'h3'), d('legal-v2', ''), d('legal-v3', 'h3')]);
      var oCurrent = true;
      Future<Map<String, dynamic>?>? j;
      var opens = 0;
      h.whileOpen = (label) async {
        opens++;
        if (opens == 1) {
          await Future<void>.delayed(const Duration(milliseconds: 5));
          j = h._ensureLegalAcceptanceForActivation(account);
          await Future<void>.delayed(const Duration(milliseconds: 5));
          oCurrent = false;
        }
      };
      final o = h._ensureLegalAcceptanceForActivation(account, stillCurrent: () => oCurrent);
      final w = h._ensureLegalAcceptanceForActivation(account);
      await bounded(Future.wait(<Future<Map<String, dynamic>?>>[o, w]));
      await bounded(j!);
      check(h.events.length == 1, 'the fallback caller asked again: ${h.events}');
      check(h._legalAcceptedVersion == 'legal-v3' && h._legalAcceptedHash == 'h3',
          'the record on file regressed to ${h._legalAcceptedVersion}/${h._legalAcceptedHash}');
    case 'legal_third_caller_does_not_present_after_its_session_ended_during_the_second_wait':
      // Sol E1: A, B, C hold three live documents; C's session ends while B's dialog is open.
      h.answers['legal'] = true;
      Map<String, String> d(String v, String hh) =>
          <String, String>{'version': v, 'hash': hh, 'body': 'b', 'display_body': 'd'};
      h.docQueue.addAll(<Map<String, String>>[d('legal-v3', 'h3'), d('legal-v4', 'h4'), d('legal-v5', 'h5')]);
      var cCurrent = true;
      var opens = 0;
      h.whileOpen = (label) async {
        opens++;
        if (opens == 2) cCurrent = false;
      };
      final a = h._ensureLegalAcceptanceForActivation(account);
      final b = h._ensureLegalAcceptanceForActivation(account);
      final c = h._ensureLegalAcceptanceForActivation(account, stillCurrent: () => cCurrent);
      final res = await bounded(Future.wait(<Future<Map<String, dynamic>?>>[a, b, c]));
      check(h.events.length == 2, 'the third caller presented after its session ended: ${h.events}');
      check(res[2] == null, 'the third caller got a result: ${res[2]}');
    case 'legal_third_caller_does_not_present_beside_a_connect_that_started_during_the_second_wait':
      h.answers['legal'] = true;
      Map<String, String> d(String v, String hh) =>
          <String, String>{'version': v, 'hash': hh, 'body': 'b', 'display_body': 'd'};
      h.docQueue.addAll(<Map<String, String>>[d('legal-v3', 'h3'), d('legal-v4', 'h4'), d('legal-v5', 'h5')]);
      var opens = 0;
      h.whileOpen = (label) async {
        opens++;
        if (opens == 2) h._isLoading = true;
      };
      final a = h._ensureLegalAcceptanceForActivation(account);
      final b = h._ensureLegalAcceptanceForActivation(account);
      final c = h._ensureLegalAcceptanceForActivation(account, canAsk: () => !h._isLoading);
      final res = await bounded(Future.wait(<Future<Map<String, dynamic>?>>[a, b, c]));
      check(h.events.length == 2, 'the third caller presented beside a connect: ${h.events}');
      check(res[2] == null, 'the third caller got a result: ${res[2]}');
    case 'legal_old_session_empty_lookup_does_not_clear_the_new_sessions_record':
      // Sol U10: the old session's account lookup returns nothing after an account switch.
      h.answers['legal'] = true;
      h.relock();
      await h._ensureLegalAcceptanceForActivation(account);
      h.accountLookupHook = () async {
        h._accountSessionEpoch.bump();
        h._legalAcceptedVersion = '';
        h.savedAccount = '';
        h.relock();
        await h._ensureLegalAcceptanceForActivation(account);
      };
      await h.pinUnlockAccepted();
      check(h._deferredLegalConsent.isPendingFor(h._accountSessionEpoch.current),
          'the new session\'s blocked question was cleared by the old session\'s empty lookup');
    case 'legal_acceptance_on_file_path_checks_the_session_after_the_privacy_await':
      // Sol N1a: nothing is fetched on this path; the check after the privacy await is the only one.
      h._legalAcceptedVersion = 'legal-v2';
      h._legalAcceptedHash = 'h2';
      final epoch = h._accountSessionEpoch.current;
      scheduleMicrotask(() => h._accountSessionEpoch.bump());
      final res = await bounded(h._ensureLegalAcceptanceForActivation(account,
          stillCurrent: () => h._accountEpochIsCurrent(epoch)));
      check(res == null, 'a payload was returned for a session that ended: $res');
    case 'legal_cancel_with_a_stale_older_acceptance_on_file_still_fails':
      // An acceptance that was on file when the call began does not stand for a NEW document: cancelling it fails.
      h.isAndroid = true; // the disclosure is missing, so the legal text is read and compared
      h._legalAcceptedVersion = 'legal-v1';
      h._legalAcceptedHash = 'h1';
      h.answers['legal'] = false;
      final res = await bounded(h._ensureLegalAcceptanceForActivation(account));
      check(res == null, 'a cancelled new document was served from the stale acceptance: $res');
      check(h.feedback.join(',') == 'Legal acceptance is required before activation.', 'feedback: ${h.feedback}');
    case 'legal_session_ending_during_the_acceptance_save_returns_nothing':
      h.answers['legal'] = true;
      var current = true;
      h.saveHook = () async => current = false;
      final res = await bounded(h._ensureLegalAcceptanceForActivation(account, stillCurrent: () => current));
      check(h.saved.join(',') == 'legal:legal-v2', 'the answer that was given is stored: ${h.saved}');
      check(res == null, 'a caller whose session ended during the save got a result: $res');
    case 'pin_upgrade_second_wait_after_a_first_one_still_opens_its_dialog':
      // The waiting flag must clear: two failed writes in a row, each followed by one waiting prompt.
      for (var round = 1; round <= 2; round++) {
        final gate = Completer<void>();
        h.replaceHook = () async {
          await gate.future;
          throw StateError('disk');
        };
        unawaited(h._commitPinUpgrade('482915'));
        final waiting = h._promptForPinUpgrade();
        await Future<void>.delayed(const Duration(milliseconds: 10));
        gate.complete();
        await bounded(waiting);
        check(h.events.length == round, 'round $round opened ${h.events.length} dialogs in total: ${h.events}');
      }
    // ---------------- Turn 6 ----------------
    case 'c5_late_fetch_bundled_caller_after_an_acceptance_asks_nothing':
      // Seat C / Sol N-5: C's fetch ends with the bundled copy only after A's live v4/h4 was accepted and its dialog
      // closed. C must be served v4/h4 and must not write v2 over it, wait or no wait.
      h.answers['legal'] = true;
      Map<String, String> d(String v, String hh) =>
          <String, String>{'version': v, 'hash': hh, 'body': 'b', 'display_body': 'd'};
      h.docQueue.addAll(<Map<String, String>>[d('legal-v4', 'h4'), d('legal-v2', '')]);
      final gate = Completer<void>();
      h.docLoadHook = () async {
        if (h.docLoads == 2) await gate.future;
      };
      final a = h._ensureLegalAcceptanceForActivation(account);
      final c = h._ensureLegalAcceptanceForActivation(account);
      await bounded(a);
      gate.complete();
      final rc = await bounded(c);
      check(h.events.length == 1, 'the late bundled caller asked again: ${h.events}');
      check(h.saved.join(',') == 'legal:legal-v4', 'stored: ${h.saved}');
      check(h._legalAcceptedVersion == 'legal-v4' && h._legalAcceptedHash == 'h4',
          'the record on file regressed to ${h._legalAcceptedVersion}/${h._legalAcceptedHash}');
      check(rc!['legal_version'] == 'legal-v4', 'the late caller sent another document: $rc');
      final loads = h.docLoads;
      final later = await bounded(h._ensureLegalAcceptanceForActivation(account));
      check(later!['legal_version'] == 'legal-v4' && h.docLoads == loads, 'a later caller: $later');
    case 'c6_substituted_record_with_padded_version_does_not_spin':
      // Seat C, Turn 6 (its N-7): the record set during C's fetch carries a padded version and an empty hash. After
      // the loop-top substitution the record must count as current; re-deriving it with staleNow() compared the
      // untrimmed record with its trimmed copy and spun the loop with no await.
      h.docQueue.add(<String, String>{'version': 'legal-v2', 'hash': '', 'body': 'b', 'display_body': 'd'});
      final gate = Completer<void>();
      h.docLoadHook = () async => gate.future;
      final c = h._ensureLegalAcceptanceForActivation(account);
      await Future<void>.delayed(const Duration(milliseconds: 5));
      h._legalAcceptedVersion = 'legal-v4 ';
      h._legalAcceptedHash = '';
      gate.complete();
      final rc = await bounded(c);
      check(h.events.isEmpty && rc!['legal_version'] == 'legal-v4' && h.saved.isEmpty,
          'events=${h.events} rc=$rc saved=${h.saved}');
    case 'legal_late_fetch_bundled_caller_cancelled_after_an_acceptance_is_not_asked':
      h.answers['legal'] = false;
      Map<String, String> d(String v, String hh) =>
          <String, String>{'version': v, 'hash': hh, 'body': 'b', 'display_body': 'd'};
      h.answerSeq['legal'] = <bool?>[true];
      h.docQueue.addAll(<Map<String, String>>[d('legal-v4', 'h4'), d('legal-v2', '')]);
      final gate = Completer<void>();
      h.docLoadHook = () async {
        if (h.docLoads == 2) await gate.future;
      };
      final a = h._ensureLegalAcceptanceForActivation(account);
      final c = h._ensureLegalAcceptanceForActivation(account);
      await bounded(a);
      gate.complete();
      final rc = await bounded(c);
      check(h.events.length == 1 && rc!['legal_version'] == 'legal-v4' && h.feedback.isEmpty,
          'events=${h.events} rc=$rc feedback=${h.feedback}');
    case 'legal_bundled_dialog_open_while_a_newer_acceptance_arrives_is_never_written':
      // The write-time guard: another writer records v4/h4 while this caller's bundled dialog is open.
      h.answers['legal'] = true;
      h.docQueue.add(<String, String>{'version': 'legal-v2', 'hash': '', 'body': 'b', 'display_body': 'd'});
      h.whileOpen = (label) async {
        h._legalAcceptedVersion = 'legal-v4';
        h._legalAcceptedHash = 'h4';
      };
      final rw = await bounded(h._ensureLegalAcceptanceForActivation(account));
      check(h.saved.isEmpty, 'the bundled copy was written over a newer acceptance: ${h.saved}');
      check(h._legalAcceptedVersion == 'legal-v4' && h._legalAcceptedHash == 'h4', 'record: ${h._legalAcceptedVersion}/${h._legalAcceptedHash}');
      check(rw!['legal_version'] == 'legal-v4', 'payload: $rw');
    case 'pin_upgrade_two_prompt_calls_without_a_write_open_one_dialog':
      // Sol N-6: no write is running; the first dialog stays unanswered; a second call must add nothing.
      final gate = Completer<void>();
      h.whileOpen = (label) async => gate.future;
      final first = h._promptForPinUpgrade();
      await Future<void>.delayed(const Duration(milliseconds: 10));
      final second = h._promptForPinUpgrade();
      final third = h._promptForPinUpgrade();
      await Future<void>.delayed(const Duration(milliseconds: 10));
      check(h.events.length == 1 && h.maxOpen == 1, 'dialogs: ${h.events} maxOpen=${h.maxOpen}');
      gate.complete();
      await bounded(Future.wait(<Future<void>>[first, second, third]));
      h.whileOpen = null;
      await bounded(h._promptForPinUpgrade());
      check(h.events.length == 2, 'the flag stayed set after the dialog ended: ${h.events}');
    case 'pin_reset_two_prompt_calls_without_a_write_open_one_dialog':
      h._pinResetRequired = true;
      final gate = Completer<void>();
      h.whileOpen = (label) async => gate.future;
      final first = h._promptForMandatoryPinReset();
      await Future<void>.delayed(const Duration(milliseconds: 10));
      final second = h._promptForMandatoryPinReset();
      await Future<void>.delayed(const Duration(milliseconds: 10));
      check(h.events.length == 1 && h.maxOpen == 1, 'dialogs: ${h.events} maxOpen=${h.maxOpen}');
      gate.complete();
      await bounded(Future.wait(<Future<void>>[first, second]));
      h.whileOpen = null;
      await bounded(h._promptForMandatoryPinReset());
      check(h.events.length == 2, 'the flag stayed set after the dialog ended: ${h.events}');
    case 'pin_upgrade_lower_dialog_cannot_confirm_with_the_upper_ones_write':
      // Sol N-6 continuation: two taps before any Save. The upper dialog starts a write and is dismissed while it
      // runs; a lower dialog (if one exists) saves another candidate and is handed the upper write's result.
      final upperGate = Completer<void>();
      final writeStarted = Completer<void>();
      final writeGate = Completer<void>();
      var opens = 0;
      h.answerSeq['pin-upgrade'] = <bool?>[null, true];
      h.whileOpen = (label) async {
        opens++;
        if (opens == 1) {
          await upperGate.future;
          h.replaceHook = () async => writeGate.future;
          unawaited(h._commitPinUpgrade('739104'));
          writeStarted.complete();
          return;
        }
        await writeStarted.future;
        await h._commitPinUpgrade('482915');
      };
      final upper = h._promptForPinUpgrade();
      await Future<void>.delayed(const Duration(milliseconds: 10));
      final lower = h._promptForPinUpgrade();
      await Future<void>.delayed(const Duration(milliseconds: 10));
      upperGate.complete();
      await Future<void>.delayed(const Duration(milliseconds: 10));
      writeGate.complete();
      await bounded(Future.wait(<Future<void>>[upper, lower]));
      await Future<void>.delayed(const Duration(milliseconds: 10));
      check(h.events.length == 1 && h.maxOpen == 1, 'a second dialog opened: ${h.events} maxOpen=${h.maxOpen}');
      check(h.feedback.isEmpty, 'a confirmation showed for a code the user did not type there: ${h.feedback}');
      check(h.replaced == 1, 'writes: ${h.replaced}');
    case 'c5_pin_upgrade_waiter_is_cancelled_by_a_relock_during_the_wait':
      // Seat C CLAUDE-N-3: the tap waited for a write; a relock and a new unlock came before the write failed.
      final gate = Completer<void>();
      h.whileOpen = (label) async {
        h.replaceHook = () async {
          h.relock();
          await gate.future;
          throw StateError('disk');
        };
        unawaited(h._commitPinUpgrade('482915'));
      };
      final first = h._promptForPinUpgrade();
      await Future<void>.delayed(const Duration(milliseconds: 20));
      h.whileOpen = null;
      h.replaceHook = null;
      h.unlockOnly();
      final tap = h._promptForPinUpgrade();
      await Future<void>.delayed(const Duration(milliseconds: 5));
      h.relock();
      await Future<void>.delayed(const Duration(milliseconds: 5));
      h.unlockOnly();
      gate.complete();
      await bounded(Future.wait(<Future<void>>[first, tap]));
      check(h.events.join(',') == 'dialog:pin-upgrade', 'a tap from before the relock opened a dialog: ${h.events}');
      await bounded(h._promptForPinUpgrade());
      check(h.events.length == 2 && h._pinUpgradeAvailable, 'a new tap after the unlock did not ask: ${h.events}');
    case 'legal_no_saved_account_asks_nothing':
      // The acceptance is stored against an account; with none on file the
      // offer must not write one under an empty name.
      h.answers['legal'] = true;
      h.relock();
      await h._ensureLegalAcceptanceForActivation(account);
      h.savedAccount = '';
      await h.pinUnlockAccepted();
      check(h.events.isEmpty && h.saved.isEmpty, 'asked with no account: ${h.events}');
    case 'legal_free_access_session_uses_the_free_account':
      h.answers['legal'] = true;
      h._isLoggedIn = false;
      h._isFreeAccessSession = true;
      h.expectedAccount = 'FREE-ACCESS-1';
      h.relock();
      await h._ensureLegalAcceptanceForActivation('FREE-ACCESS-1');
      await h.pinUnlockAccepted();
      check(h.saved.join(',') == 'legal:legal-v2', '${h.events} ${h.saved}');
    // ---------------- Android VPN disclosure ----------------
    case 'disclosure_control':
      h.isAndroid = true;
      h._legalAcceptedVersion = 'legal-v2';
      h._legalAcceptedHash = 'h2';
      h.answers['vpn-disclosure'] = true;
      final payload = await h._ensureLegalAcceptanceForActivation(account);
      check(payload != null, 'control: no payload');
      check(h.events.join(',') == 'dialog:vpn-disclosure', '${h.events}');
      check(h.saved.join(',') == 'disclosure:disclosure-v1', '${h.saved}');
    case 'disclosure_behind_decoy_never_auto_accepts':
      h.isAndroid = true;
      h._legalAcceptedVersion = 'legal-v2';
      h._legalAcceptedHash = 'h2';
      h.answers['vpn-disclosure'] = true;
      h.relock();
      final direct = await h._ensureAndroidVpnServiceDisclosureConsent();
      check(!direct, 'the disclosure was accepted behind the decoy');
      h._androidVpnServiceDisclosureConsentRequest = null;
      final payload = await h._ensureLegalAcceptanceForActivation(account);
      check(payload == null, 'the flow went on without the disclosure');
      check(h.events.isEmpty, 'drawn over the decoy: ${h.events}');
      check(h.saved.isEmpty && h._androidVpnServiceDisclosureConsentVersion.isEmpty,
          'stored behind the decoy');
      check(h._deferredLegalConsent.isPending, 'not kept for the unlock');
    case 'disclosure_unlock_asks_only_what_is_missing':
      h.isAndroid = true;
      h._legalAcceptedVersion = 'legal-v2';
      h._legalAcceptedHash = 'h2';
      h.answers['vpn-disclosure'] = true;
      h.relock();
      await h._ensureLegalAcceptanceForActivation(account);
      await h.pinUnlockAccepted();
      check(h.events.join(',') == 'dialog:vpn-disclosure',
          'the unlock asked for more than the disclosure: ${h.events}');
      check(h.saved.join(',') == 'disclosure:disclosure-v1', '${h.saved}');
      h.relock();
      await h.pinUnlockAccepted();
      check(h.events.length == 1, 'asked twice');
    case 'disclosure_after_legal_when_the_relock_comes_between':
      h.isAndroid = true;
      h.answers['legal'] = true;
      h.answers['vpn-disclosure'] = true;
      h.saveHook = () async => h.relock(); // the relock lands as legal is stored
      final payload = await h._ensureLegalAcceptanceForActivation(account);
      check(payload == null, 'the flow went on');
      check(h.events.join(',') == 'dialog:legal', 'disclosure drawn over the decoy: ${h.events}');
      check(h.saved.join(',') == 'legal:legal-v2', 'answered legal lost: ${h.saved}');
      check(h._deferredLegalConsent.isPending, 'the disclosure was not kept');
      await h.pinUnlockAccepted();
      check(h.events.join(',') == 'dialog:legal,dialog:vpn-disclosure',
          'legal was asked again or the disclosure was not: ${h.events}');
    case 'disclosure_removed_mid_dialog':
      h.isAndroid = true;
      h._legalAcceptedVersion = 'legal-v2';
      h._legalAcceptedHash = 'h2';
      h.whileOpen = (label) async => h.relock();
      final payload = await h._ensureLegalAcceptanceForActivation(account);
      check(payload == null && h.saved.isEmpty, 'a removed dialog counted as acceptance');
      check(h._deferredLegalConsent.isPending, 'not kept');
      h.whileOpen = null;
      h.answers['vpn-disclosure'] = true;
      await h.pinUnlockAccepted();
      check(h.saved.join(',') == 'disclosure:disclosure-v1', '${h.saved}');
    case 'disclosure_is_not_kept_off_android':
      h.isAndroid = false;
      h.relock();
      final ok = await h._showAndroidVpnServiceDisclosureDialog();
      check(ok, 'off Android there is no disclosure to refuse');
      check(!h._deferredLegalConsent.isPending && h.events.isEmpty, 'kept or drawn off Android');
    // ---------------- PIN upgrade ----------------
    case 'pin_upgrade_control':
      h.whileOpen = (label) async {
        final error = await h._commitPinUpgrade('482915');
        check(error == null, 'control: save failed: $error');
        h.answers['pin-upgrade'] = true;
      };
      await h._promptForPinUpgrade();
      check(h.replaced == 1, 'control: not stored');
      check(!h._pinUpgradeAvailable && h._calculatorPinEntry.pinLength == 6, 'control: state');
      check(h.feedback.join(',') == 'Unlock code updated.', '${h.feedback}');
    case 'pin_upgrade_behind_decoy':
      h.relock();
      await h._promptForPinUpgrade();
      check(h.events.isEmpty, 'drawn over the decoy: ${h.events}');
      check(h.replaced == 0 && h._pinUpgradeAvailable && h._calculatorPinEntry.pinLength == 4,
          'something was done behind the decoy');
      await h.pinUnlockAccepted();
      check(h.events.isEmpty, 'the unlock replayed the prompt: ${h.events}');
      check(h._pinUpgradeAvailable, 'the dashboard notice is gone');
    case 'pin_upgrade_removed_by_a_relock_is_not_replayed':
      h.whileOpen = (label) async => h.relock();
      await h._promptForPinUpgrade();
      check(h.replaced == 0 && h._calculatorPinEntry.pinLength == 4, 'stored though nobody saved');
      check(h._pinUpgradeAvailable, 'the notice was consumed by a dialog nobody answered');
      check(h._pinUpgradeController.cleared >= 2, 'the typed digits were kept');
      h.whileOpen = null;
      await h.pinUnlockAccepted();
      check(h.events.length == 1, 'the unlock replayed the prompt: ${h.events}');
    case 'pin_upgrade_save_pressed_then_relock_during_the_write':
      // The user answered: the write commits. The keypad must follow the
      // credential even though the dialog was removed and answered null.
      h.whileOpen = (label) async {
        h.replaceHook = () async => h.relock();
        final error = await h._commitPinUpgrade('482915');
        check(error == null, 'save failed: $error');
      };
      await h._promptForPinUpgrade();
      check(h.replaced == 1, 'the write did not commit');
      check(h._calculatorPinEntry.pinLength == 6,
          'the keypad expects ${h._calculatorPinEntry.pinLength} digits for a 6-digit credential');
      check(!h._pinUpgradeAvailable, 'the notice stayed for a credential already upgraded');
      check(h.feedback.isEmpty, 'a message showed over the decoy');
    case 'pin_upgrade_weak_code_and_failed_write_change_nothing':
      check(await h._commitPinUpgrade('123456') != null, 'a weak code was accepted');
      check(await h._commitPinUpgrade('12') != null, 'a short code was accepted');
      h.replaceHook = () async => throw StateError('disk');
      check(await h._commitPinUpgrade('482915') != null, 'a failed write reported success');
      check(h.replaced == 0 && h._pinUpgradeAvailable && h._calculatorPinEntry.pinLength == 4,
          'state moved without a stored credential');
    case 'pin_upgrade_relock_unlock_with_nothing_pending':
      h.relock();
      await h.pinUnlockAccepted();
      h.relock();
      await h.pinUnlockAccepted();
      check(h.events.isEmpty, 'a prompt appeared: ${h.events}');
''';

void main() {
  late Directory temporary;
  late File executable;
  late String source;

  setUpAll(() async {
    source = File('lib/main.dart').readAsStringSync();
    final gate = File('lib/decoy_prompt_gate.dart').absolute.uri.toString();

    final legalStale = _between(
        source,
        'bool legalAcceptanceIsStale({',
        '/// Returns the location value sent to the control plane');
    final chunks = <String, String>{
      'GATE': gate,
      'LEGAL_STALE': legalStale,
      'UNLOCK': _between(
          source,
          '        final viaRecoveryCode = _recoveryUnlockPending;',
          '      } else {\n'
              '        // For camouflage purposes'),
      'PRIVACY': _stripShowDialog(
          _between(
              source,
              '  Future<bool> _showPrivacyPolicyDialog({required bool requireConsent}) async {',
              '  Future<void> _showTermsAndLegalDialog() async {'),
          'privacy'),
      'ENSURE_PRIVACY': _between(
          source,
          '  Future<bool> _ensurePrivacyConsentForNetworkUse() async {',
          '  void _startPostPrivacyConsentInitialization() {'),
      'TERMS': _stripShowDialog(
          _between(
              source,
              '  Future<void> _showTermsAndLegalDialog() async {',
              '  // Shown when a write to the native secure-state store'),
          'terms'),
      'SECURE_STATE': _stripShowDialog(
          _between(
              source,
              '  Future<void> _showSecureStateFailureDialog({',
              '  Future<bool> _ensurePrivacyConsentForNetworkUse() async {'),
          'secure-state'),
      'PACKAGE': _stripShowDialog(
          _between(
              source,
              '  Future<bool> _promptForAndroidPackageVisibilityConsent() async {',
              '  Future<void> _toggleSplitTunnelPanel() async {'),
          'package'),
      'TOGGLE': _between(
              source,
              '  Future<bool> _ensureAndroidPackageVisibilityConsent() {',
              '  Future<bool> _promptForAndroidPackageVisibilityConsent() async {') +
          _between(
              source,
              '  Future<void> _toggleSplitTunnelPanel() async {',
              '  bool get _supportsPerAppSplitTunneling =>'),
      'LEGAL_WRAPPER': _between(
          source,
          '  /// Shows the legal dialog for [doc], alone. A caller joins an open dialog',
          '  Future<bool?> _presentLegalAcceptanceDialog('),
      'DISCLOSURE_WRAPPER': _between(
          source,
          '  Future<bool> _showAndroidVpnServiceDisclosureDialog() {',
          '  Future<bool?> _presentAndroidVpnServiceDisclosureDialog() async {'),
      'DISCLOSURE_ENSURE': _between(
          source,
          '  Future<bool> _ensureAndroidVpnServiceDisclosureConsent() {',
          '  Future<Map<String, dynamic>?> _ensureLegalAcceptanceForActivation('),
      'LEGAL_ENSURE': _between(
          source,
          '  Future<Map<String, dynamic>?> _ensureLegalAcceptanceForActivation(',
          '  Future<bool> _fetchAvailableNodes('),
      'GLUE': _between(source, '  bool _decoyStillAway(int decoyGeneration) =>',
              '  Future<void> _showDuressEnrollmentDialog(') +
          _between(
              source,
              '  /// Runs one legal-terms or Android VPN-disclosure dialog under the decoy',
              '  Future<void> _promptForPinUpgrade() async {'),
      'PIN_UPGRADE': _stripShowDialog(
          _between(source, '  Future<void> _promptForPinUpgrade() async {',
              '  Widget _buildVpnDashboard('),
          'pin-upgrade'),
      'PIN_RESET': _stripShowDialog(
          _between(
              source,
              '  Future<void> _promptForMandatoryPinReset() async {',
              '  /// Offer to create a recovery code on an install that predates them.'),
          'pin-reset'),
      'SCENARIOS': _scenarios,
    };
    var text = _harness;
    for (final entry in chunks.entries) {
      text = text.replaceAll('@@${entry.key}@@', entry.value);
    }
    // Production reads Platform.isAndroid; the harness scripts it.
    text = text.replaceAll('Platform.isAndroid', 'isAndroid');
    temporary = await Directory.systemTemp.createTemp('l97-decoy-prompts-');
    executable = File('${temporary.path}/prompts.dart');
    await executable.writeAsString(text);
    final keep = Platform.environment['L97_KEEP_HARNESS'];
    if (keep != null && keep.isNotEmpty) await executable.copy(keep);
  });

  tearDownAll(() async {
    if (await temporary.exists()) await temporary.delete(recursive: true);
  });

  final scenarios = RegExp(r"case '([a-z0-9_]+)':")
      .allMatches(_scenarios)
      .map((m) => m.group(1)!)
      .toList();

  test('the harness lists the scenarios it runs', () {
    expect(scenarios.length, greaterThanOrEqualTo(40));
    expect(scenarios.toSet().length, scenarios.length, reason: 'duplicate case');
  });

  for (final scenario in scenarios) {
    test('prompt: $scenario', () async {
      final result = await _runGrouped(
        <String>[Platform.environment['DART_EXECUTABLE'] ?? 'dart', executable.path, scenario],
        workingDirectory: temporary.path,
        timeout: const Duration(seconds: 60),
      );
      expect(result.exitCode, 0, reason: '${result.stdout}\n${result.stderr}');
      expect(result.stdout.toString(), contains('PASS $scenario'));
    });
  }

  group('call sites in lib/main.dart', () {
    String fn(String start, String end) => _between(source, start, end);

    test('every one of the six refuses to draw while the decoy shows', () {
      final guards = <String, String>{
        '  Future<bool> _showPrivacyPolicyDialog({required bool requireConsent}) async {':
            '    if (_showDecoyCalculator) return _privacyConsentGranted;',
        '  Future<void> _showTermsAndLegalDialog() async {':
            '    if (!mounted || _showDecoyCalculator) return;',
        '  Future<void> _showSecureStateFailureDialog({':
            '    if (!mounted || _showDecoyCalculator) return;',
        '  Future<bool> _promptForAndroidPackageVisibilityConsent() async {':
            '    if (!mounted || _showDecoyCalculator) return false;',
        '  Future<void> _promptForPinUpgrade() async {':
            '    if (!mounted || _showDecoyCalculator) return;',
      };
      for (final entry in guards.entries) {
        final start = source.indexOf(entry.key);
        expect(start, greaterThanOrEqualTo(0), reason: entry.key);
        final show = source.indexOf('showDialog<', start);
        final guard = source.indexOf(entry.value, start);
        expect(guard, greaterThan(start), reason: entry.key);
        expect(guard, lessThan(show),
            reason: 'the guard must come before the dialog: ${entry.key}');
      }
      // The legal and disclosure dialogs go through the gate.
      expect(
          fn('  Future<bool> _showLegalAcceptanceDialog(',
              '  Future<bool?> _presentLegalAcceptanceDialog('),
          contains('_gatedLegalPrompt('));
      expect(
          fn('  Future<bool> _showAndroidVpnServiceDisclosureDialog() {',
              '  Future<bool?> _presentAndroidVpnServiceDisclosureDialog() async {'),
          contains('_gatedLegalPrompt(_presentAndroidVpnServiceDisclosureDialog)'));
    });

    test('the presenters hand back the raw answer, never true for a removal', () {
      final legal = fn('  Future<bool?> _presentLegalAcceptanceDialog(',
          '  Future<bool> _showAndroidVpnServiceDisclosureDialog() {');
      final vpn = fn('  Future<bool?> _presentAndroidVpnServiceDisclosureDialog() async {',
          '  Future<bool> _ensureAndroidVpnServiceDisclosureConsent() {');
      for (final body in <String>[legal, vpn]) {
        expect(body, contains('    return result;\n  }'));
        expect(body, isNot(contains('result == true')));
        expect(body, contains('showDialog<bool>('));
      }
    });

    test('the PIN unlock offers the deferred prompt last, in its own generation',
        () {
      final unlock = fn(
          '  Future<void> _onCalculatorButtonPressed(String buttonText) async {',
          '  String _evaluateDecoyMathExpression(');
      final cleared = unlock.indexOf('_showDecoyCalculator = false;');
      final generation =
          unlock.indexOf('final unlockGeneration = _decoyGeneration;');
      final recovery = unlock.indexOf('await _showPendingRecoveryCode();');
      final offer =
          unlock.indexOf('await _offerDeferredLegalConsent(unlockGeneration);');
      expect(cleared, greaterThan(0));
      expect(generation, greaterThan(cleared));
      expect(recovery, greaterThan(generation));
      expect(offer, greaterThan(recovery));
    });

    test('the offer asks through the one function that re-evaluates', () {
      final offer = fn('  Future<void> _offerDeferredLegalConsent(int unlockGeneration) async {',
          '  Future<void> _promptForPinUpgrade() async {');
      expect(offer, contains('await _ensureLegalAcceptanceForActivation('));
      expect(offer, contains('stillCurrent: () {'));
      expect(offer, contains('canAsk: () {'));
      expect(offer, contains('_deferredLegalConsent.take('));
      // No dialog of its own and no stored answer.
      expect(offer, isNot(contains('showDialog')));
      expect(offer, isNot(contains('_showLegalAcceptanceDialog')));
    });

    test('both PIN prompts commit through their own commit method', () {
      final reset = fn('  Future<void> _promptForMandatoryPinReset() async {',
          '  Future<String?> _commitPinReset(');
      expect(reset, contains('_commitPinReset('));
      expect(reset, isNot(contains('_calculatorPinEntry.pinLength')));
      expect(reset, contains('final committed = _pinResetCommitted;'));
    });

    test('every dialog of the eight ends only its own route', () {
      // Behaviour: decoy_prompt_real_dialogs_test (a late answer never ends a
      // newer dialog). This pins the call sites: no bare pop is left in any of
      // the dialogs, so a new button cannot slip past that test unseen.
      final bodies = <String, String>{
        'privacy': fn(
            '  Future<bool> _showPrivacyPolicyDialog({required bool requireConsent}) async {',
            '  Future<void> _showTermsAndLegalDialog() async {'),
        'terms': fn('  Future<void> _showTermsAndLegalDialog() async {',
            '  // Shown when a write to the native secure-state store'),
        'secure-state': fn('  Future<void> _showSecureStateFailureDialog({',
            '  Future<bool> _ensurePrivacyConsentForNetworkUse() async {'),
        'package': fn(
            '  Future<bool> _promptForAndroidPackageVisibilityConsent() async {',
            '  Future<void> _toggleSplitTunnelPanel() async {'),
        'legal': fn('  Future<bool?> _presentLegalAcceptanceDialog(',
            '  Future<bool> _showAndroidVpnServiceDisclosureDialog() {'),
        'disclosure': fn(
            '  Future<bool?> _presentAndroidVpnServiceDisclosureDialog() async {',
            '  /// Ends the dialog that [dialogContext] was built in, with [result], and'),
        'pin-reset': fn('  Future<void> _promptForMandatoryPinReset() async {',
            '  Future<String?> _commitPinReset('),
        'pin-upgrade': fn('  Future<void> _promptForPinUpgrade() async {',
            '  Future<String?> _commitPinUpgrade('),
      };
      const ends = <String, int>{
        'privacy': 2,
        'terms': 1,
        'secure-state': 1,
        'package': 2,
        'legal': 2,
        'disclosure': 2,
        'pin-reset': 1,
        'pin-upgrade': 3,
      };
      for (final entry in bodies.entries) {
        final body = entry.value;
        expect(body, isNot(contains('.pop(')), reason: '${entry.key}: a bare pop');
        expect(body, isNot(contains('Navigator.pop')), reason: entry.key);
        expect(body, isNot(contains('maybePop')), reason: entry.key);
        expect('_endOwnDialog<'.allMatches(body).length, ends[entry.key],
            reason: '${entry.key}: every answer ends its own route');
      }
      // The rule itself lives in lib/end_own_route.dart; main.dart's helper
      // only delegates to it.
      final wrapper = fn('  bool _endOwnDialog<T>(BuildContext dialogContext, [T? result]) =>',
          '  Future<bool> _ensureAndroidVpnServiceDisclosureConsent() {');
      expect(wrapper, contains('endOwnRoute<T>(dialogContext, result);'));
      final helper = _between(
          File('lib/end_own_route.dart').readAsStringSync(),
          'bool endOwnRoute<T>(BuildContext routeContext, [T? result]) {',
          '\n}\n');
      expect(helper, contains('if (!routeContext.mounted) return false;'));
      expect(helper, contains('if (route == null || !route.isActive) return false;'));
      expect(helper, contains('if (route.isCurrent) {'));
      expect(helper, contains('navigator.pop<T>(result);'));
      expect(helper, contains('navigator.removeRoute<T>(route, result);'));
    });

    test('the duress dialog and the account-deletion sheet end only their own '
        'route after their awaits', () {
      // Behaviour: duress_enrollment_dialog_test and account_deletion_test (a
      // late answer never ends, or answers, a newer dialog). This pins the two
      // call sites outside the eight dialogs, each of which answers after an
      // await: no bare pop, one route-bound end, and the type argument is the
      // one the route was shown with (endOwnRoute casts the route to it).
      final duress =
          File('lib/duress_enrollment_dialog.dart').readAsStringSync();
      final onPressed = _between(duress,
          '            Future<void> onPressed(bool withSms) async {',
          '            return AlertDialog(');
      expect(onPressed, contains('await validateAndEnroll('));
      expect(onPressed, isNot(contains('.pop(')), reason: 'duress: a bare pop');
      expect(onPressed, isNot(contains('Navigator.pop')));
      expect(onPressed, isNot(contains('maybePop')));
      expect('endOwnRoute<'.allMatches(onPressed).length, 1);
      expect(onPressed, contains('endOwnRoute<String>(dialogContext, result);'));
      expect(duress, contains('await showDialog<String>('));

      final run = _between(
          source,
          '  Future<void> _run(Future<AccountDeletionState?> Function() action) async {',
          '  @override\n  Widget build(BuildContext context) {\n    return SafeArea(');
      expect(run, contains('await action()'));
      expect(run, isNot(contains('.pop(')), reason: 'sheet: a bare pop');
      expect(run, isNot(contains('Navigator.pop')));
      expect(run, isNot(contains('maybePop')));
      expect('endOwnRoute<'.allMatches(run).length, 1);
      expect(run, contains('endOwnRoute<bool>(context, true);'));
      expect(source, contains('await showModalBottomSheet<bool>('));
    });

    test('the save handler commits through _commitPinUpgrade', () {
      final prompt = fn('  Future<void> _promptForPinUpgrade() async {',
          '  Future<String?> _commitPinUpgrade(');
      expect(prompt, contains('_commitPinUpgrade('));
      expect(prompt, isNot(contains('_calculatorPinEntry.pinLength')));
    });
  });
}
