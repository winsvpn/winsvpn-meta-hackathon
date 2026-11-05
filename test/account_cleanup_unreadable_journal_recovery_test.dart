// CORE-7-T15C-claude, as amended by CORE-7-T17C-claude: a cleanup journal
// that exists but can never be read
// keeps startup and activation closed. The one way out is an explicit,
// confirmed local reset, offered only after the journal has stayed unreadable
// for three barrier passes. It deletes every account's local data first, the
// departed account's included, removes the journal only after every other
// deletion is verified, and keeps the process blocked until a fresh start.
// A durable marker holds the barrier across an interrupted reset. Kotlin and
// Swift are not compiled by the Flutter suite; their source is pinned here.
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/account_session_lifecycle.dart';

String _block(String source, String start, String end) {
  final a = source.indexOf(start);
  expect(a, greaterThanOrEqualTo(0), reason: 'missing $start');
  final b = source.indexOf(end, a + start.length);
  expect(b, greaterThan(a), reason: 'missing $end after $start');
  return source.substring(a, b);
}

void _inOrder(String block, List<String> steps) {
  var at = -1;
  for (final step in steps) {
    final next = block.indexOf(step, at + 1);
    expect(next, greaterThan(at), reason: 'out of order or missing: $step');
    at = next;
  }
}

void main() {
  test('an unreadable journal holds the barrier until it is durably gone',
      () async {
    var journalPresent = true;
    var attempts = 0;
    var pendingCalls = 0;
    var completedCalls = 0;
    final barrier = AccountCleanupStartupBarrier(
      journalExists: () async => journalPresent,
      // The staged cleanup attempt reads the journal, gets null, and returns.
      attemptCleanup: () async => attempts++,
      onPending: () => pendingCalls++,
      onCompleted: () => completedCalls++,
      onRetryCompleted: () {},
      retryDelay: const Duration(hours: 1),
    );
    for (var i = 0; i < 3; i++) {
      expect(await barrier.resume(), AccountCleanupResumeOutcome.pending);
      expect(await barrier.activationAllowed(), isFalse);
    }
    expect(attempts, 3);
    expect(completedCalls, 0);
    // A fresh start after the reset finds the journal gone.
    journalPresent = false;
    expect(await barrier.resume(), AccountCleanupResumeOutcome.completed);
    expect(completedCalls, 1);
    expect(await barrier.activationAllowed(), isTrue);
    expect(pendingCalls, greaterThanOrEqualTo(3));
    barrier.dispose();
  });

  final source = File('lib/main.dart').readAsStringSync();

  test('the reset is offered only after three unreadable passes', () {
    final attempt = _block(source,
        '  Future<void> _attemptPendingAccountCleanup() async {',
        '  Future<void> _noteUnreadableCleanupJournal() async {');
    _inOrder(attempt, <String>[
      'if (_accountResetRequiresRestart) {',
      "throw StateError('Local account reset requires restart');",
      'if (_accountLifecycleBusy) {',
      'final pending = await _readAccountCleanupJournal();',
      'if (pending == null) {',
      'await _noteUnreadableCleanupJournal();',
      '_unreadableCleanupJournalPasses = 0;',
      'final epoch = _beginAccountTeardown();',
    ]);

    final note = _block(source,
        '  Future<void> _noteUnreadableCleanupJournal() async {', '\n  }\n');
    _inOrder(note, <String>[
      'if (!await _accountCleanupJournalExists()) {',
      '_unreadableCleanupJournalPasses = 0;',
      '_unreadableCleanupJournalPasses += 1;',
      '_unreadableCleanupJournalPasses < 3',
      '_cleanupJournalUnreadable = true',
    ]);

    final complete = _block(source,
        '  void _completePendingAccountCleanup() {', '\n  }\n');
    expect(complete, contains('_unreadableCleanupJournalPasses = 0;'));
    expect(complete, contains('_cleanupJournalUnreadable = false;'));
  });

  test('the reset confirms, re-checks and quiesces before it erases', () {
    final request = _block(source,
        '  Future<void> _requestLocalAccountReset() async {',
        '  Future<bool> _eraseLocalAccountDataKeepingDevice(int epoch) async {');
    _inOrder(request, <String>[
      '!_cleanupJournalUnreadable ||',
      '_accountLifecycleBusy ||',
      '_accountResetSucceeded) {',
      'setState(() => _accountLifecycleBusy = true);',
      'await showDialog<bool>(',
      'barrierDismissible: false,',
      'if (confirmed != true || !mounted) return;',
      'if (await _readAccountCleanupJournal() != null ||',
      '!await _accountCleanupJournalExists()) {',
      'final epoch = _beginAccountTeardown();',
      'await _settingsMutationQueue.timeout(const Duration(seconds: 4));',
      "'sealAccountStartsForRecovery'",
      'if (sealed != true || !_accountEpochIsCurrent(epoch)) {',
      'if (!await _stopAndProveTunnelInactive() ||',
      '!_accountEpochIsCurrent(epoch) ||',
      '_clientKeyOperationQueue.pendingOperationCount != 0) {',
      '_accountResetRequiresRestart = true;',
      "'resetAllLocalAccountData'",
      'await _eraseLocalAccountDataKeepingDevice(epoch);',
      'if (!erased) {',
      '_accountResetSucceeded = true;',
      "'closeAfterAccountRecovery'",
      '} catch (_) {',
      'if (!_accountResetSucceeded) {',
      '} finally {',
      '_accountLifecycleBusy = false;',
    ]);
    expect(request, isNot(contains('_accountCleanupStartupBarrier')),
        reason: 'the reset never reopens the barrier in this process');
    expect(request, isNot(contains('_accountResetRequiresRestart = false')),
        reason: 'only a fresh start clears the block');
  });

  test('off Android the journal goes after every deletion, the marker last',
      () {
    final erase = _block(source,
        '  Future<bool> _eraseLocalAccountDataKeepingDevice(int epoch) async {',
        '  Future<void> _deactivateCurrentDevice() async {');
    _inOrder(erase, <String>[
      'final marker = await _accountResetMarkerFile();',
      "await marker.writeAsString('1', flush: true);",
      "'purgeAppGroupContainer'",
      'if (appGroupPurgeLeftResidual(appGroupReport)) return false;',
      "'purgeAccountDataKeepingCleanupJournal'",
      "keychainReport['keychain_purge_blocked_count'] != 0",
      "keychainReport['keychain_purge_remaining_items'] != 0",
      'if (!await _deleteVpnConfigVerified()) return false;',
      'for (final name in _sensitiveStateFileNames) {',
      "if (name == 'calc_session.json' || name == 'install_id.txt') continue;",
      'if (!await _deleteSensitiveArtifactVerified(name)) return false;',
      'if (await latch.exists()) return false;',
      'if (Platform.isWindows || Platform.isLinux) {',
      "'eraseLocalAccountRuntime'",
      'if (runtimeErased != true) return false;',
      'if (!_accountEpochIsCurrent(epoch)) return false;',
      "if (!await _deleteSensitiveArtifactVerified('calc_session.json')) {",
      'await marker.delete();',
      'return !await marker.exists();',
    ]);
    expect("'calc_session.json'".allMatches(erase).length, 2,
        reason: 'the journal is skipped in the loop and deleted once, last');
  });

  test('a started reset seals Dart writes and holds the barrier', () {
    final write = _block(source,
        '  Future<void> _writeSensitiveText(String name, String value) async {',
        '_validateSensitiveStateName(name);');
    expect(write, contains('if (_accountResetRequiresRestart) {'));

    final exists = _block(source,
        '  Future<bool> _accountCleanupJournalExists() async {',
        '  Future<File> _accountResetMarkerFile() async =>');
    _inOrder(exists, <String>[
      'if (_accountResetRequiresRestart) return true;',
      'try {',
      'if (await _accountResetMarkerPresent()) return true;',
      "return await _readSensitiveText('calc_session.json') != null;",
      '} catch (_) {',
      'return true;',
    ]);

    final read = _block(source,
        '  Future<AccountCleanupJournal?> _readAccountCleanupJournal() async {',
        '  Future<bool> _accountCleanupJournalExists() async {');
    _inOrder(read, <String>[
      'try {',
      'if (await _accountResetMarkerPresent()) return null;',
      "await _readSensitiveText('calc_session.json');",
    ]);

    final marker = _block(source,
        '  Future<bool> _accountResetMarkerPresent() async {', '\n  }\n');
    expect(marker, contains('if (Platform.isAndroid) return false;'),
        reason: 'Android keeps its marker in SecureFileStore');
  });

  test('the pending view offers the reset only for an unreadable journal', () {
    final view = _block(source, '  Widget _buildAccountCleanupPendingView() =>',
        '  @override\n  Widget build(BuildContext context) {');
    final gate =
        view.indexOf('if (_cleanupJournalUnreadable && !_accountResetSucceeded)');
    expect(gate, greaterThan(0));
    expect(view.indexOf('_requestLocalAccountReset'), greaterThan(gate));
    expect(view, isNot(contains('Platform.')),
        reason: 'every platform gets the way out');
  });

  test('Android: marker first, keys gone before the journal, marker last', () {
    final store = File(
            'android/app/src/main/kotlin/org/winsvpn/app/SecureFileStore.kt')
        .readAsStringSync();
    final reset = _block(store,
        '    fun resetAllLocalAccountData(): Boolean {', '\n    }\n\n');
    final roots = _block(reset, 'val roots = listOf(', ').map(');
    expect(roots, isNot(contains('shared_prefs')),
        reason: 'the camouflage enrollment flag is never cleared');
    _inOrder(reset, <String>[
      'check(attributes == null || attributes.isDirectory)',
      'read(KILL_SWITCH_RECORD)',
      'accountDataResetStarted = true',
      'FileOutputStream(accountResetMarker).use',
      'stream.fd.sync()',
      'val kept = journalPaths + killSwitchPaths + secureInstallIdPaths +',
      'eraseForAccountReset(root, kept, keepDirectory = true)',
      'verifyAccountResetTree(root, kept)',
      'keyStore.deleteEntry(keyAlias)',
      'check(!keyStore.containsAlias(keyAlias))',
      'accountDataResetStarted = false',
      'write(KILL_SWITCH_RECORD, "true")',
      'accountDataResetStarted = true',
      'check(delete(KILL_SWITCH_RECORD))',
      'accountDataResetStarted = false',
      'write(INSTALL_ID_RECORD, carriedInstallId)',
      'accountDataResetStarted = true',
      'check(delete(INSTALL_ID_RECORD))',
      'for (journal in journalPaths.sortedBy { it.toString() }) {',
      'Files.delete(journal)',
      'verifyAccountResetTree(root, survivors)',
      'Files.delete(marker)',
      'return true',
    ]);
    expect(RegExp(r'\+ (installId|marker|killSwitchRecord)\b').hasMatch(reset),
        isFalse,
        reason: 'a Path is an Iterable<Path>: set + path adds its segments');

    final write = _block(
        store, '    fun write(name: String, plaintext: String) {', '\n    }\n');
    _inOrder(write, <String>[
      'require(isAllowedName(name))',
      'check(!accountDataResetStarted)',
      'cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())',
    ]);
    expect('accountDataResetStarted = false'.allMatches(reset).length, 2,
        reason: 'the seal lifts twice, for the kill-switch and install id '
            'writes only');
    final read = _block(store,
        '    fun read(name: String, legacyFile: File? = null): String? {',
        'val encryptedFile = secureFile(name)');
    expect(read, contains('if (name == "calc_session.json") {'));
    expect(read, contains('check(!accountDataResetStarted)'));
    expect(
        store,
        contains('    private var accountDataResetStarted =\n'
            '        resetAttributes(accountResetMarker.toPath()) != null\n'));

    final activity =
        File('android/app/src/main/kotlin/org/winsvpn/app/MainActivity.kt')
            .readAsStringSync();
    final close = _block(activity, '"closeAfterAccountRecovery" -> {', '}');
    _inOrder(close, <String>[
      'result.success(true)',
      'finishAndRemoveTask()',
      'android.os.Process.killProcess(android.os.Process.myPid())',
    ]);
    expect(
        activity,
        contains('"resetAllLocalAccountData" -> {\n'
            '                    runSecureStorageOperation(result) {\n'
            '                        secureFileStore.resetAllLocalAccountData()\n'));
  });

  test('the Apple purge keeps the journal for Dart to delete last', () {
    final core =
        File('apple/WinsTunnelCore/WinsTunnelConfig.swift').readAsStringSync();
    final targets = _block(core,
        '  static func unreadableCleanupJournalTargets() -> [WinsKeychainPurgeTarget] {',
        '\n  }\n');
    expect(targets, contains('keptAccounts: ["calc_session.json", "install_id.txt"]'));
    expect(targets, contains('service: "org.winsvpn.client-keypair"'));
    expect(targets, contains('service: "org.winsvpn.tunnel-secrets"'));
    expect(targets, isNot(contains('install-identity')));
    for (final host in const <String>[
      'ios/Runner/AppDelegate.swift',
      'macos/Runner/MainFlutterWindow.swift',
    ]) {
      expect(
        File(host).readAsStringSync(),
        contains('    case "purgeAccountDataKeepingCleanupJournal":\n'
            '      result(WinsKeychainDuressPurge.purgeAccountDataKeepingCleanupJournal().statusFields)\n'),
        reason: host,
      );
    }
  });
}
