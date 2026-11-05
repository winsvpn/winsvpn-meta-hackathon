import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// Fails when this checkout can push but carries no ipscrub pre-push gate.
///
/// # What the gate is
///
/// `tools/ipscrub/` (committed by `8880f6a`) refuses a push that would newly
/// upload a real infrastructure address. It is installed by
/// `sh tools/ipscrub/install-hooks.sh`, and **a fresh clone has none until
/// someone runs that command**. Committing the tooling made the gate
/// *available*; it did not make it *automatic*, and git offers no safe way to
/// close that gap. This test is the closing move.
///
/// # Why it FAILS rather than warns
///
/// A printed warning scrolls past in a 900-test run and is, in practice,
/// indistinguishable from doing nothing. This project spent 2026-08-06/07
/// finding roughly eight guards that had never once fired -- a `strings | grep`
/// under `pipefail` that missed a present string 57% of the time, a validator
/// whose cap made strong values impossible, a smoke test that quantized
/// nothing, a coverage harness that inflated its own results. A ninth,
/// implemented as a warning nobody reads, would be worse than nothing: it would
/// look like coverage.
///
/// # Why failing here is never a false alarm
///
/// The obvious objection is that a fresh clone would be red on arrival, and a
/// suite that is red on arrival gets skipped -- which is exactly how a sibling
/// repo's first ratchet nearly poisoned itself. So this does **not** fire
/// whenever the hook is missing. It fires only when the hook is missing **and a
/// push is actually possible**, i.e. `.git` exists *and* a remote is
/// configured. Three states, three different answers:
///
///   * **No `.git`** -- a CI checkout, a `git archive` export, a vendored copy.
///     There is no hooks directory to install into and no push to make. The
///     check is *inapplicable*, so it skips with a reason rather than failing.
///   * **`.git` but no remote** -- nothing to push to, so the gate guards a harm
///     that cannot occur here. Skips with a reason.
///   * **`.git` and a remote** -- a push can happen, so an absent gate is a real
///     exposure. Fails, and names the one command that fixes it.
///
/// That is a narrower trigger than "hook missing", and it is the reason the
/// failure is always actionable: if you see it, you can push, and you are
/// unprotected.
///
/// # The deliberate opt-out
///
/// `WINS_SKIP_IPSCRUB_HOOK_CHECK=1` skips the check. This is not a loophole in
/// the sense a silent warning would be: it is an explicit, greppable statement
/// in someone's environment that they have chosen to work unguarded, rather
/// than a message they never read. If it turns up in a CI config, that is a
/// decision somebody can see and argue with.
void main() {
  test('the ipscrub pre-push gate is installed in this checkout', () {
    if (Platform.environment['WINS_SKIP_IPSCRUB_HOOK_CHECK'] == '1') {
      markTestSkipped(
        'WINS_SKIP_IPSCRUB_HOOK_CHECK=1 -- running deliberately unguarded.',
      );
      return;
    }

    // `git rev-parse --git-path hooks` is the only correct way to find the
    // hooks directory: it honours core.hooksPath, worktrees (where .git is a
    // file, not a directory) and submodules. Hard-coding `.git/hooks` would
    // report a missing gate on any worktree, which is a false alarm of exactly
    // the kind this test is designed not to produce.
    final hooksPath = _git(<String>['rev-parse', '--git-path', 'hooks']);
    if (hooksPath == null) {
      markTestSkipped(
        'not a git checkout (no .git) -- a CI export or vendored copy cannot '
        'push and has no hooks directory, so this check does not apply.',
      );
      return;
    }

    final remotes = _git(<String>['remote']);
    if (remotes == null || remotes.isEmpty) {
      markTestSkipped(
        'no git remote configured -- nothing to push to, so an absent gate '
        'guards a harm that cannot occur in this checkout.',
      );
      return;
    }

    final hook = File(
      hooksPath.startsWith('/')
          ? '$hooksPath/pre-push'
          : '${Directory.current.path}/$hooksPath/pre-push',
    );

    // Match on the marker, not on the file existing. An unrelated pre-push hook
    // -- or a stale copy predating the gate -- would satisfy an existence check while
    // protecting nothing, which is the "guard that does not guard" shape this
    // whole family of defects takes.
    const marker = 'ipscrub pre-push gate';
    final installed = hook.existsSync() && hook.readAsStringSync().contains(marker);

    expect(
      installed,
      isTrue,
      reason: '\n'
          'The ipscrub pre-push disclosure gate is NOT installed in this '
          'checkout, and this checkout has a remote -- so a push can happen '
          'and would not be checked.\n'
          '\n'
          'The gate refuses a push that would newly upload a real '
          'infrastructure address. Without it, a routine `git push` can '
          'publish gateway addresses and the operator\'s own WAN address.\n'
          '\n'
          'Fix (one command, from the repository root):\n'
          '\n'
          '    sh tools/ipscrub/install-hooks.sh\n'
          '\n'
          'It is idempotent, backs up any unrelated pre-push hook rather than '
          'clobbering it, and warns if core.hooksPath is redirecting hooks '
          'elsewhere.\n'
          '\n'
          'Looked for the marker "$marker" in:\n'
          '    ${hook.path}\n'
          '\n'
          'To work deliberately unguarded, set '
          'WINS_SKIP_IPSCRUB_HOOK_CHECK=1.\n',
    );
  });

  // ---------------------------------------------------------------------
  // E-04 (Sol audit, 2026-08-28): presence is not capability, part two.
  //
  // The installed-hook test above matched a MARKER. A disposable-copy probe
  // inserted `exit 0` immediately after the marker and the suite stayed
  // green: a no-op hook satisfied "the gate is installed". This test
  // executes the ACTUAL installed hook against a real temporary remote and
  // asserts BOTH directions:
  //
  //   * a push whose delta carries a globally routable address not on the
  //     allowlist is REFUSED (non-zero exit, no upload);
  //   * a clean push of the same shape SUCCEEDS (a gate that refused
  //     everything would be switched off within a day).
  //
  // The `exit 0` mutation fails this test on the first assertion: the
  // forbidden push goes through. So does deleting the scan invocation, a
  // broken scanner path, or a gutted allowlist.
  test(
      'the INSTALLED ipscrub hook REFUSES a forbidden push and PASSES a clean one',
      () {
    if (Platform.environment['WINS_SKIP_IPSCRUB_HOOK_CHECK'] == '1') {
      markTestSkipped('WINS_SKIP_IPSCRUB_HOOK_CHECK=1 -- unguarded by choice.');
      return;
    }
    final hooksPath = _git(<String>['rev-parse', '--git-path', 'hooks']);
    if (hooksPath == null) {
      markTestSkipped('not a git checkout -- no hooks directory applies.');
      return;
    }
    final hookFile = File(
      hooksPath.startsWith('/')
          ? '$hooksPath/pre-push'
          : '${Directory.current.path}/$hooksPath/pre-push',
    );
    if (!hookFile.existsSync() ||
        !hookFile.readAsStringSync().contains('ipscrub pre-push gate')) {
      // The presence test above already fails loudly for this case.
      markTestSkipped('hook not installed; the presence test covers it.');
      return;
    }
    final scannerDir = Directory('tools/ipscrub');
    if (!File('${scannerDir.path}/ipscrub.py').existsSync()) {
      markTestSkipped('tools/ipscrub not present in this checkout.');
      return;
    }

    final tmp = Directory.systemTemp.createTempSync('ipscrub_hook_live_');
    try {
      // A local "remote": a bare repo the working repo pushes into.
      final remoteDir = Directory('${tmp.path}/remote.git')
        ..createSync(recursive: true);
      _run(<String>['git', 'init', '--bare', '-q', remoteDir.path]);
      final workDir = Directory('${tmp.path}/work')..createSync(recursive: true);
      _runIn(workDir, <String>['git', 'init', '-q']);
      _runIn(workDir, <String>[
        'git', 'config', 'user.name', 'hook-test',
      ]);
      _runIn(workDir, <String>[
        'git', 'config', 'user.email', 'hook-test@example.test',
      ]);
      _runIn(workDir,
          <String>['git', 'remote', 'add', 'origin', remoteDir.path]);

      // The hook resolves the scanner from $ROOT/tools/ipscrub first.
      final destTools = Directory('${workDir.path}/tools/ipscrub')
        ..createSync(recursive: true);
      for (final name in <String>[
        'ipscrub.py',
        'ipscrub-allowlist.txt',
      ]) {
        File('${scannerDir.path}/$name')
            .copySync('${destTools.path}/$name');
      }
      // THE ACTUAL INSTALLED HOOK from this checkout -- byte-for-byte.
      final hooksRel =
          _runIn(workDir, <String>['git', 'rev-parse', '--git-path', 'hooks'])
              ?.stdout as String? ?? 'hooks';
      var hooksAbs = hooksRel.trim();
      if (!hooksAbs.startsWith('/')) hooksAbs = '${workDir.path}/$hooksAbs';
      final workHooks = Directory(hooksAbs)..createSync(recursive: true);
      hookFile.copySync('${workHooks.path}/pre-push');

      // Clean baseline: one commit with no addresses; must push OK.
      File('${workDir.path}/README.md')
          .writeAsStringSync('clean baseline\n');
      _runIn(workDir, <String>['git', 'add', '-A']);
      _runIn(workDir, <String>[
        'git', 'commit', '-q', '-m', 'baseline',
      ]);
      final clean = _runIn(workDir, <String>[
        'git', 'push', '-q', 'origin', 'HEAD:refs/heads/main',
      ]);
      expect(clean?.exitCode ?? -1, 0,
          reason:
              'the gate refused a CLEAN push (output: ${clean?.stderr}) -- a '
              'gate that blocks everything is noise that gets switched off.');

      // Forbidden delta: a globally routable address not on the allowlist
      // (the same synthetic host family the ipscrub selftest uses).
      // Constructed at runtime from parts so the literal never appears in
      // this source (a full literal here ends up in a pushed blob, and the
      // 2026-08-28 push had to allowlist the selftest's own synthetic host
      // to get past the gate -- the wrong fix, reverted).
      final forbiddenHost = ['77', '88', '99', '222'].join('.');
      File('${workDir.path}/notes.txt').writeAsStringSync(
          'gateway endpoint $forbiddenHost:9111\n');
      _runIn(workDir, <String>['git', 'add', '-A']);
      _runIn(workDir, <String>[
        'git', 'commit', '-q', '-m', 'add node address',
      ]);
      final refused = _runIn(workDir, <String>[
        'git', 'push', 'origin', 'HEAD:refs/heads/main',
      ]);
      expect(refused?.exitCode ?? 0, isNot(0),
          reason: '\n'
              'The INSTALLED pre-push hook let a forbidden push through: a '
              'commit whose delta carries a non-allowlisted routable '
              'address uploaded to the remote without refusal.\n'
              '\n'
              'Presence of the hook is not capability. If this fails while '
              'the presence test passes, the installed hook is a no-op or '
              'mangled -- reinstall it:\n'
              '\n'
              '    sh tools/ipscrub/install-hooks.sh\n');
    } finally {
      try {
        tmp.deleteSync(recursive: true);
      } on FileSystemException {
        // Best-effort cleanup on locked temp files.
      }
    }
  });

  // The test above proves a pre-push hook is installed. It says nothing about
  // whether the gate behind it can actually see anything -- and on 2026-08-03
  // it could not: `scan_objects` sniffed every blob, hit `continue` on any
  // binary, and passed three real `.pcap` captures onto GitHub through a
  // doubled evidence path without reading a byte of them. The hook ran. The
  // hook reported OK. The captures shipped.
  //
  // So this repository briefly had the exact defect it has catalogued eight
  // times over: a guard asserted to exist, never asserted to work. The fix
  // landed in `tools/ipscrub/ipscrub.py` on 2026-08-07 (a binary on an
  // evidence path is now a blocking `binary-evidence` finding). This test is
  // what stops it from silently regressing -- restoring the bare `continue`
  // would leave every other test in this suite green.
  //
  // BOTH directions are asserted on purpose. A rule that refused every binary
  // would refuse app icons and `.so` build output, become noise, and be
  // switched off within a day -- which is the same failure wearing a
  // different hat. The scoped rule is the one worth protecting.
  test('the ipscrub gate REFUSES a binary it cannot read on an evidence path',
      () {
    final scanner = File('tools/ipscrub/ipscrub.py');
    final allowlist = File('tools/ipscrub/ipscrub-allowlist.txt');
    if (!scanner.existsSync() || !allowlist.existsSync()) {
      markTestSkipped(
        'tools/ipscrub is not present in this checkout -- nothing to verify. '
        'The test above is the one that fails when the gate is missing.',
      );
      return;
    }

    // Deliberately NOT `ipscrub_evidence_`: the sibling-drop rule matches any
    // directory component shaped `*_evidence_*`, so that prefix would have put
    // the negative control on an evidence path too and the control would have
    // proved nothing. Found by reading the rule rather than by running it.
    final tmp = Directory.systemTemp.createTempSync('ipscrub_gate_');
    try {
      // A pcap header. Byte 0 of the classic magic is 0xd4, and the NUL bytes
      // are what make `looks_binary` true -- which is the whole point: this is
      // a file the scanner cannot read as text.
      final capture = File('${tmp.path}/evidence/probe.pcap')
        ..parent.createSync(recursive: true)
        ..writeAsBytesSync(<int>[0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
      // Same bytes, ordinary path: a build artifact, not capture output.
      final artifact = File('${tmp.path}/assets/icon.png')
        ..parent.createSync(recursive: true)
        ..writeAsBytesSync(<int>[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a,
          0x0a, 0x00, 0x00, 0x00, 0x0d]);

      final refused = _ipscrub(scanner, allowlist, capture.path);
      final skipped = _ipscrub(scanner, allowlist, artifact.path);

      if (refused == null || skipped == null) {
        markTestSkipped('no python3 interpreter available to run the scanner.');
        return;
      }

      const marker = 'Unscannable binary on an evidence path';
      expect(
        refused.exitCode,
        isNot(0),
        reason: '\n'
            'ipscrub did NOT refuse an unreadable binary sitting on an '
            'evidence path.\n'
            '\n'
            'That is the exact hole that put three .pcap captures on GitHub on '
            '2026-08-03: the scanner sniffs a blob, finds it binary, and '
            'skips it -- reporting a clean push it never actually checked.\n'
            '\n'
            'A packet capture cannot be scrubbed (its addresses live in IP '
            'headers with checksums over them, so rewriting one manufactures '
            'a new file rather than redacting it). Refusal is therefore the '
            'only correct handling, and it must stay refusal.\n'
            '\n'
            'Look for the `is_evidence_path` check in scan_objects / '
            'scan_worktree / cmd_scan_paths in tools/ipscrub/ipscrub.py.\n',
      );
      expect(
        '${refused.stdout}${refused.stderr}',
        contains(marker),
        reason: '\nipscrub exited non-zero but did not say WHY. A refusal '
            'nobody can act on gets overridden. Expected the finding label '
            '"$marker".\n',
      );
      expect(
        skipped.exitCode,
        0,
        reason: '\n'
            'ipscrub refused an ordinary binary that is NOT on an evidence '
            'path.\n'
            '\n'
            'Refusing every binary would block app icons, .so build output '
            'and archives on every push. A gate that noisy gets switched off, '
            'and then it guards nothing at all -- the same failure as the one '
            'above, reached from the opposite direction. The refusal must '
            'stay scoped to evidence paths and capture suffixes.\n',
      );
    } finally {
      tmp.deleteSync(recursive: true);
    }
  });
}

/// Runs `ipscrub scan-paths` on one file, or null when python3 is unavailable.
ProcessResult? _ipscrub(File scanner, File allowlist, String target) {
  for (final py in <String>['python3', '/usr/bin/python3']) {
    try {
      return Process.runSync(
        py,
        <String>[
          scanner.path,
          '--allowlist',
          allowlist.path,
          'scan-paths',
          target,
        ],
        workingDirectory: Directory.current.path,
      );
    } on ProcessException {
      continue;
    }
  }
  return null;
}

/// Runs git and returns trimmed stdout, or null when git is unavailable or the
/// command fails (which includes "not a git repository").
String? _git(List<String> args) {
  try {
    final result = Process.runSync('git', args,
        workingDirectory: Directory.current.path);
    if (result.exitCode != 0) return null;
    return (result.stdout as String).trim();
  } on ProcessException {
    return null;
  }
}

/// Runs a command in [cwd] and returns its result (never throws).
ProcessResult? _runIn(Directory cwd, List<String> args) {
  try {
    return Process.runSync(args.first, args.sublist(1),
        workingDirectory: cwd.path);
  } on ProcessException {
    return null;
  }
}

/// Runs a command in the current directory and returns its result.
ProcessResult? _run(List<String> args) => _runIn(Directory.current, args);
