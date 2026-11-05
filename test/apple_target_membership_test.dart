// A file under apple/WinsTunnelCore/ must never be compiled by NO target on
// an Apple platform that needs it.
//
// WHY THIS EXISTS
//
// docs/handoff/APPLE_SEAM_GAPS_CLOSED_20260808.md §4: `WinsWinnCarrierProfile
// .swift` and `WinsWinnCarrierProfileKeys.swift` had **no PBXFileReference at
// all** in `macos/Runner.xcodeproj/project.pbxproj`: not in the
// `WinsTunnelCore` group, not in either target's Sources phase; while iOS
// carried both in both Sources phases. The macOS packet-tunnel extension
// therefore could never have honoured an `http3-connect-udp` carrier. This
// was invisible for two compounding reasons: nothing in the shared Swift
// referenced the missing type strongly enough to fail a build on its own
// (see that handoff's §3-§4), and `tools/verify_apple_winn_seam.sh` GLOBS
// `apple/WinsTunnelCore/` (a directory listing), so a file missing from an
// Xcode TARGET, while still present in the DIRECTORY, is invisible to it by
// construction. §9 of that handoff: "No one has checked whether other
// `apple/WinsTunnelCore/*.swift` files are missing from the macOS target in
// the same way... worth one grep by whoever owns that project file next."
// This file is that check, made permanent rather than a one-time grep.
//
// docs/handoff/APPLE_TARGET_MEMBERSHIP_AUDIT_20260808.md is the audit that
// commissioned this guard: it confirmed the two files above are fixed in the
// working tree (both Sources phases, both platforms) and found no further
// gaps as of 2026-08-08 (see that document for the full per-file table).
//
// WHAT THIS CHECKS, AND WHY THE BAR IS "AT LEAST ONE TARGET PER PLATFORM",
// NOT "IDENTICAL TARGET SETS"
//
// The obvious stronger rule: every file has the exact same target names on
// both platforms; happens to hold for all 5 files in this directory today.
// It is deliberately NOT what this guard enforces, because it is a stronger
// claim than either the evidence or the assignment support:
// `WinsSecureStateStore.swift` is `Runner`-only on BOTH iOS and macOS, by
// design (`apple/WinsTunnelCore/WinsTunnelConfig.swift:3171`: "
// `WinsSecureStateStore.swift` and this file are both compiled into the
// host..." (i.e. the app, not the PacketTunnel extension)). That is a
// legitimate, symmetric, non-`PacketTunnel` shape, and nothing rules out a
// future file with a similarly legitimate reason to be `Runner`-only (or
// `PacketTunnel`-only) on both platforms at once. The shape this guard
// exists to catch is narrower and exactly matches what actually happened: a
// file with ZERO targets on one platform while another platform (or the
// mere existence of the file in the shared directory) shows it is needed.
// Requiring "at least one target on each platform" catches that precisely,
// without presuming a stronger cross-platform symmetry nobody has asked for.
// Per the audit's own instruction ("do not flatten intentional differences
// ... where you are unsure, say so and leave it"), a same-target-set rule is
// left for a future author who can justify it from evidence this file
// does not have.
//
// SCOPE: apple/WinsTunnelCore/ only, exactly as commissioned.
// `apple/EngineWrappers/` is deliberately EXCLUDED (not an oversight). The
// audit confirmed (raw grep, zero matches in both project.pbxproj files,
// cross-checked against `OTHER_LDFLAGS`/`tools/stage_apple_engine_artifacts
// .sh`) that every file in that directory is compiled EXCLUSIVELY by
// external shell tooling and staged as a prebuilt artifact, linked via
// `OTHER_LDFLAGS`: never a Sources-phase member of any Xcode target on
// either platform. Zero Xcode membership there is the correct, symmetric,
// intentional state; a guard that required Sources-phase membership for
// that directory would be permanently and wrongly red. If that architecture
// ever changes, it needs a different guard shaped around the staging
// script's own file list, not this one.
//
// PARSER: pure text/regex over the `.pbxproj`, deliberately not `plutil`.
// Same reason `appleResourceViolations` in
// `test/tracked_reference_integrity_test.dart` never shells out to it: nothing
// in this suite may assume a macOS host to run.
//
// A NULL RESULT FROM A CHECKER NEVER SEEN TO PRODUCE A NON-NULL ONE IS NOT
// EVIDENCE (the lesson `tracked_reference_integrity_test.dart` states
// explicitly for its own script scan, after a `re.M`-shaped bug in a port of
// it once reported a confident, silent zero). Both tests below assert a
// sane minimum shape was actually parsed out of each project file before
// trusting an empty violation list.
//
// Two tests, same shape as `tracked_reference_integrity_test.dart`:
//
//   * `working tree ...` is the MACHINE-LOCAL ratchet: it reads both
//     `project.pbxproj` files and the WinsTunnelCore directory straight off
//     disk. This is the one proven by breaking and restoring (see
//     docs/handoff/APPLE_TARGET_MEMBERSHIP_AUDIT_20260808.md for the
//     before/red/after transcript). Baseline is empty: the working tree is
//     clean as of 2026-08-08.
//   * `HEAD tree ...` is the half that TRAVELS: it reads both project files
//     and the file list via `git show`/`git ls-tree`, so it answers what a
//     FRESH CLONE actually gets, independent of anyone's working tree. It is
//     STRICT except for `_knownHeadViolations`, which as of 2026-08-08 holds
//     exactly the two entries this audit found already fixed on disk but not
//     yet committed (see that map's own comment for why deleting them
//     requires a commit this lane has no authority to make (ABSOLUTE GIT
//     PROHIBITION), and why leaving the baseline empty would make this guard
//     red on arrival for a gap this file did not create).

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// Real, currently-true violations at `HEAD`: every entry here must be
/// something this checker actually reproduces against `git show HEAD:...`,
/// not a hypothetical.
///
/// TO REMOVE AN ENTRY: it becomes stale (this test starts reporting it as
/// resolved) automatically the moment the working-tree fix is committed:
/// `git show HEAD:...` will then contain the reference and the checker will
/// stop reproducing the violation. Delete the line then. Until then it is
/// not a landmine to defuse in code, it is a commit someone with git
/// authority owes; this lane cannot make it (ABSOLUTE GIT PROHIBITION).
const Map<String, String> _knownHeadViolations = <String, String>{};

/// A file this checker could not place under any target on either platform,
/// with enough detail to act on immediately.
class _MembershipGap {
  _MembershipGap(this.platform, this.path, this.detail);

  final String platform; // 'ios' or 'macos'
  final String path; // repo-relative
  final String detail;

  String get key => '$platform:$path';

  @override
  String toString() => '$key\n      ($detail)';
}

void main() {
  late final String repoRoot;
  var gitAvailable = false;

  setUpAll(() {
    final root = _repoRoot() ?? Directory.current.path;
    repoRoot = root;
    gitAvailable = _isGitCheckout(repoRoot);
  });

  test(
    'working tree: every apple/WinsTunnelCore/*.swift file is compiled by '
    'at least one target on both iOS and macOS',
    () {
      if (!File('$repoRoot/pubspec.yaml').existsSync()) {
        markTestSkipped('repo root not identifiable; skipping');
        return;
      }
      final iosText =
          File('$repoRoot/ios/Runner.xcodeproj/project.pbxproj')
              .readAsStringSync();
      final macosText =
          File('$repoRoot/macos/Runner.xcodeproj/project.pbxproj')
              .readAsStringSync();
      final files = _diskWinsTunnelCoreSwiftFiles(repoRoot);

      _assertParserIsAlive(iosText, macosText, files);

      final violations = _findGaps(
        files: files,
        iosProject: _PbxProject.parse(iosText, projectDir: 'ios'),
        macosProject: _PbxProject.parse(macosText, projectDir: 'macos'),
      );

      const baseline = <String, String>{};
      final unexpected =
          violations.where((v) => !baseline.containsKey(v.key)).toList();

      expect(
        unexpected,
        isEmpty,
        reason:
            'A file under apple/WinsTunnelCore/ is compiled by NO target on '
            'a platform that needs it, in the WORKING TREE right now. This '
            'is the exact shape of the defect docs/handoff/'
            'APPLE_SEAM_GAPS_CLOSED_20260808.md §4 found: the code exists, '
            'it reads correctly, `tools/verify_apple_winn_seam.sh` (which '
            'globs the directory, not the Xcode project) would not notice, '
            'and the app simply ships without it on that platform.\n'
            'Fix it: add the file to the WinsTunnelCore group and to the '
            'relevant Sources build phase(s) in the named platform\'s '
            'project.pbxproj.\n\n'
            '${unexpected.map((v) => '  $v').join('\n')}',
      );
    },
  );

  test(
    'HEAD tree: every apple/WinsTunnelCore/*.swift file is compiled by at '
    'least one target on both iOS and macOS',
    () {
      if (!gitAvailable) {
        markTestSkipped('not a git checkout: target-membership unverifiable');
        return;
      }
      final iosText = _showAtHead(repoRoot, 'ios/Runner.xcodeproj/project.pbxproj');
      final macosText =
          _showAtHead(repoRoot, 'macos/Runner.xcodeproj/project.pbxproj');
      if (iosText == null || macosText == null) {
        fail('git show HEAD could not read one of the two project.pbxproj '
            'files - are they tracked?');
      }
      final files = _headWinsTunnelCoreSwiftFiles(repoRoot);

      _assertParserIsAlive(iosText, macosText, files);

      final violations = _findGaps(
        files: files,
        iosProject: _PbxProject.parse(iosText, projectDir: 'ios'),
        macosProject: _PbxProject.parse(macosText, projectDir: 'macos'),
      );

      final unexpected = violations
          .where((v) => !_knownHeadViolations.containsKey(v.key))
          .toList();
      final stale = _knownHeadViolations.keys
          .where((k) => !violations.any((v) => v.key == k))
          .toList();

      expect(
        unexpected,
        isEmpty,
        reason:
            'A file under apple/WinsTunnelCore/ is compiled by NO target on '
            'a platform that needs it, AT HEAD - what a fresh clone actually '
            'gets. A commit that should not have landed, landed.\n\n'
            '${unexpected.map((v) => '  $v').join('\n')}',
      );

      expect(
        stale,
        isEmpty,
        reason:
            'These _knownHeadViolations entries no longer reproduce against '
            'HEAD - the fix has been committed. Delete each line; it is a '
            'ratchet and may only shrink.\n\n'
            '${stale.map((k) => '  $k').join('\n')}',
      );
    },
  );
}

/// Every violation this checker can currently find, for every file the
/// audit says the WinsTunnelCore directory should have compiled on both
/// platforms.
List<_MembershipGap> _findGaps({
  required List<String> files,
  required _PbxProject iosProject,
  required _PbxProject macosProject,
}) {
  final violations = <_MembershipGap>[];
  for (final path in files) {
    for (final entry in <(String, _PbxProject)>[
      ('ios', iosProject),
      ('macos', macosProject),
    ]) {
      final (platform, project) = entry;
      final targets = project.sourcesMembership[path];
      if (targets != null && targets.isNotEmpty) continue;
      final hasRef = project.allFileReferences.contains(path);
      violations.add(_MembershipGap(
        platform,
        path,
        hasRef
            ? 'a PBXFileReference exists for this file, but it is not in '
                'any target\'s Sources build phase'
            : 'no PBXFileReference at all for this file in '
                '$platform/Runner.xcodeproj/project.pbxproj - not in the '
                'WinsTunnelCore group, not in any Sources phase',
      ));
    }
  }
  return violations;
}

/// Refuse to trust an empty violation list from a parser that might just be
/// broken. Every number here was measured against the tree as it stood on
/// 2026-08-08; if the pbxproj format changes enough to break these regexes,
/// this fails loudly instead of quietly protecting nothing.
void _assertParserIsAlive(
  String iosText,
  String macosText,
  List<String> files,
) {
  expect(
    files.length,
    greaterThanOrEqualTo(3),
    reason: 'Expected several *.swift files in apple/WinsTunnelCore/ '
        '(5 as of 2026-08-08) but found ${files.length}. Either the '
        'directory lost files or the listing is broken - fix before '
        'trusting this guard.',
  );
  for (final entry in <(String, _PbxProject)>[
    ('ios', _PbxProject.parse(iosText, projectDir: 'ios')),
    ('macos', _PbxProject.parse(macosText, projectDir: 'macos')),
  ]) {
    final (platform, project) = entry;
    expect(
      project.targetNames.containsAll(<String>['Runner', 'PacketTunnel']),
      isTrue,
      reason: '$platform/Runner.xcodeproj/project.pbxproj: expected to find '
          'PBXNativeTarget entries named Runner and PacketTunnel, found '
          '${project.targetNames}. The PBXNativeTarget parser is broken.',
    );
    expect(
      project.sourcesMembership.length,
      greaterThanOrEqualTo(5),
      reason: '$platform/Runner.xcodeproj/project.pbxproj: resolved only '
          '${project.sourcesMembership.length} Sources-phase file paths in '
          'total. That is implausibly low for this project - the parser is '
          'not seeing what it should. Fix it before trusting a green run.',
    );
  }
}

// --------------------------------------------------------------- disk/git --

final RegExp _backupName = RegExp(r'\.bak[._]');

List<String> _diskWinsTunnelCoreSwiftFiles(String root) {
  final dir = Directory('$root/apple/WinsTunnelCore');
  if (!dir.existsSync()) return const <String>[];
  final out = <String>[];
  for (final entry in dir.listSync()) {
    if (entry is! File) continue;
    final name = entry.uri.pathSegments.last;
    if (!name.endsWith('.swift')) continue;
    if (_backupName.hasMatch(name)) continue;
    if (name.startsWith('.')) continue;
    out.add('apple/WinsTunnelCore/$name');
  }
  out.sort();
  return out;
}

List<String> _headWinsTunnelCoreSwiftFiles(String root) {
  final result = Process.runSync(
    'git',
    <String>['ls-tree', '-r', '--name-only', 'HEAD', '--', 'apple/WinsTunnelCore'],
    workingDirectory: root,
    stdoutEncoding: utf8,
    stderrEncoding: utf8,
  );
  if (result.exitCode != 0) return const <String>[];
  return (result.stdout as String)
      .split('\n')
      .where((String l) =>
          l.endsWith('.swift') && l.isNotEmpty && !_backupName.hasMatch(l))
      .toList()
    ..sort();
}

String? _showAtHead(String root, String repoPath) {
  final result = Process.runSync(
    'git',
    <String>['show', 'HEAD:$repoPath'],
    workingDirectory: root,
    stdoutEncoding: utf8,
    stderrEncoding: utf8,
  );
  if (result.exitCode != 0) return null;
  return result.stdout as String;
}

String? _repoRoot() {
  try {
    final result = Process.runSync(
      'git',
      <String>['rev-parse', '--show-toplevel'],
      stdoutEncoding: utf8,
      stderrEncoding: utf8,
    );
    if (result.exitCode == 0) {
      final root = (result.stdout as String).trim();
      if (root.isNotEmpty) return root;
    }
  } on ProcessException {
    // Fall back to walking up from Directory.current
  }
  return _workingTreeRoot();
}

String? _workingTreeRoot() {
  var dir = Directory.current;
  while (true) {
    if (File('${dir.path}/pubspec.yaml').existsSync()) {
      return dir.path;
    }
    final parent = dir.parent;
    if (parent.path == dir.path) break;
    dir = parent;
  }
  return null;
}

bool _isGitCheckout(String root) {
  try {
    final res = Process.runSync(
      'git',
      <String>['rev-parse', '--is-inside-work-tree'],
      workingDirectory: root,
      stdoutEncoding: utf8,
      stderrEncoding: utf8,
    );
    return res.exitCode == 0 && (res.stdout as String).trim() == 'true';
  } catch (_) {
    return false;
  }
}

// ------------------------------------------------------------- pbxproj -----

/// A parsed Xcode project, reduced to exactly what this guard needs:
/// per-repo-relative-path Sources-phase target membership, and the set of
/// every path with a PBXFileReference at all (whether or not any target
/// compiles it), so a violation message can say which of the two failure
/// shapes actually occurred.
///
/// Regex-based, not a general `.pbxproj`/plist parser: it slices the file by
/// its `/* Begin X section */ ... /* End X section */` markers (which every
/// `.pbxproj` this project writes carries) and then parses each section
/// against the shape Xcode actually emits for it - two-tab-indented objects,
/// `path = value;` fields, `children = (...)`/`files = (...)`/
/// `buildPhases = (...)` lists of 24-hex-character ids. Verified against
/// both `ios/Runner.xcodeproj/project.pbxproj` and
/// `macos/Runner.xcodeproj/project.pbxproj` as they stood on 2026-08-08:
/// every PBXFileReference in both files resolves to a path (42 for iOS, 41
/// for macOS, zero dropped, zero collisions - cross-checked against a
/// `plutil -convert json` parse of the same two files while writing this).
class _PbxProject {
  _PbxProject._(this.sourcesMembership, this.allFileReferences, this.targetNames);

  /// repo-relative path -> names of targets whose Sources phase compiles it.
  final Map<String, Set<String>> sourcesMembership;

  /// Every repo-relative path with any PBXFileReference, regardless of
  /// whether it is wired into a Sources phase.
  final Set<String> allFileReferences;

  final Set<String> targetNames;

  static final RegExp _hex24 = RegExp(r'[0-9A-Fa-f]{24,}');

  static String _section(String text, String isa) {
    final begin = '/* Begin $isa section */';
    final end = '/* End $isa section */';
    final start = text.indexOf(begin);
    if (start < 0) return '';
    final stop = text.indexOf(end, start);
    if (stop < 0) return '';
    return text.substring(start + begin.length, stop);
  }

  /// Every two-tab-indented `ID /* comment */ = { ... };` object in a
  /// section, id -> its full raw chunk (id line included), whether the
  /// object is written on one line (PBXBuildFile, PBXFileReference) or many
  /// (PBXGroup, PBXNativeTarget, PBXSourcesBuildPhase).
  ///
  /// MEASURED, NOT ASSUMED, and the reason it is chunk-based rather than
  /// "match up to the next `\t\t};`": that first version - matching
  /// `\{(.*?)\n?\t\t\};` - silently returned ZERO objects for
  /// PBXFileReference while returning the right count for PBXGroup/
  /// PBXNativeTarget/PBXSourcesBuildPhase, because a single-line object's
  /// closer is `; };` (one space before the brace) and never `\n\t\t};` (a
  /// closing brace alone on its own two-tab line) the way a multi-line
  /// object's is. `apple/WinsTunnelCore/*.swift`'s own PBXFileReference
  /// entries are single-line, so that bug would have made this guard parse
  /// zero file references and pass vacuously on every run - exactly the
  /// "null result from a checker never proven to fire" trap this file's own
  /// header warns about. Caught here by `_assertParserIsAlive`, which is why
  /// that check exists and is not decorative: it failed loudly on this bug
  /// the first time this file was run, before it was fixed. Fixed by finding
  /// every object's START line only, then slicing each object's chunk up to
  /// the START of the next one (or end of section) - correct regardless of
  /// how the object's own closing brace is formatted.
  static Map<String, String> _objects(String section) {
    final starts = <int>[];
    final ids = <String>[];
    for (final m in RegExp(r'^\t\t([0-9A-Fa-f]{24,}) /\*', multiLine: true)
        .allMatches(section)) {
      starts.add(m.start);
      ids.add(m.group(1)!);
    }
    final out = <String, String>{};
    for (var i = 0; i < starts.length; i += 1) {
      final begin = starts[i];
      final end = i + 1 < starts.length ? starts[i + 1] : section.length;
      out[ids[i]] = section.substring(begin, end);
    }
    return out;
  }

  static String _unquote(String value) {
    final v = value.trim();
    if (v.length >= 2 && v.startsWith('"') && v.endsWith('"')) {
      return v.substring(1, v.length - 1);
    }
    return v;
  }

  static String _normalizePath(String path) {
    final out = <String>[];
    for (final part in path.split('/')) {
      if (part.isEmpty || part == '.') continue;
      if (part == '..') {
        if (out.isNotEmpty && out.last != '..') {
          out.removeLast();
          continue;
        }
      }
      out.add(part);
    }
    return out.join('/');
  }

  factory _PbxProject.parse(String text, {required String projectDir}) {
    // PBXFileReference: id -> its own `path` component (usually just a bare
    // filename here; the directory comes from the enclosing PBXGroup chain).
    final fileRefPath = <String, String>{};
    for (final entry in _objects(_section(text, 'PBXFileReference')).entries) {
      final m = RegExp(r'\bpath = ([^;]+);').firstMatch(entry.value);
      if (m == null) continue;
      fileRefPath[entry.key] = _unquote(m.group(1)!);
    }

    // PBXGroup (+ PBXVariantGroup, same shape): id -> (own path component,
    // child ids). Building the reverse map (child -> parent) is what lets a
    // file reference's full path be resolved by walking up.
    final groupPath = <String, String?>{};
    final groupChildren = <String, List<String>>{};
    for (final isa in <String>['PBXGroup', 'PBXVariantGroup']) {
      for (final entry in _objects(_section(text, isa)).entries) {
        final pathMatch = RegExp(r'\bpath = ([^;]+);').firstMatch(entry.value);
        groupPath[entry.key] =
            pathMatch == null ? null : _unquote(pathMatch.group(1)!);
        final childrenMatch =
            RegExp(r'children = \((.*?)\);', dotAll: true).firstMatch(entry.value);
        groupChildren[entry.key] = childrenMatch == null
            ? const <String>[]
            : _hex24
                .allMatches(childrenMatch.group(1)!)
                .map((Match m) => m.group(0)!)
                .toList();
      }
    }
    final parentOf = <String, String>{};
    groupChildren.forEach((String parent, List<String> children) {
      for (final child in children) {
        parentOf[child] = parent;
      }
    });

    String? resolve(String fileRefId) {
      final segments = <String>[];
      String? cur = fileRefId;
      final seen = <String>{};
      var first = true;
      while (cur != null) {
        if (!seen.add(cur)) return null; // cycle guard; should not happen
        final own = first ? fileRefPath[cur] : groupPath[cur];
        first = false;
        if (own != null && own.isNotEmpty) segments.add(own);
        cur = parentOf[cur];
      }
      if (segments.isEmpty) return null;
      final normalized =
          _normalizePath('$projectDir/${segments.reversed.join('/')}');
      // Keys must be REPO-relative so they compare equal with the
      // apple/WinsTunnelCore/*.swift listing. `../apple/...` groups only pop
      // their platform folder (e.g. `Runner`), so the prefix stays `ios/`
      // or `macos/` unless stripped here (measured 2026-08-21: every
      // WinsTunnelCore file resolved as `ios/apple/...` and read as
      // "no PBXFileReference at all").
      if (normalized.startsWith('$projectDir/')) {
        return normalized.substring(projectDir.length + 1);
      }
      return normalized;
    }

    final allFileReferences = <String>{};
    final resolvedOf = <String, String>{};
    for (final id in fileRefPath.keys) {
      final r = resolve(id);
      if (r == null) continue;
      resolvedOf[id] = r;
      allFileReferences.add(r);
    }

    // PBXBuildFile: id -> fileRef id. Always single-line in this project.
    final buildFileRef = <String, String>{};
    for (final m in RegExp(
      r'^\t\t([0-9A-Fa-f]{24,}) /\*.*?\*/ = \{isa = PBXBuildFile; '
      r'fileRef = ([0-9A-Fa-f]{24,})\b',
      multiLine: true,
    ).allMatches(_section(text, 'PBXBuildFile'))) {
      buildFileRef[m.group(1)!] = m.group(2)!;
    }

    // PBXSourcesBuildPhase: id -> build file ids it compiles.
    final sourcesPhaseFiles = <String, List<String>>{};
    for (final entry in _objects(_section(text, 'PBXSourcesBuildPhase')).entries) {
      final filesMatch =
          RegExp(r'files = \((.*?)\);', dotAll: true).firstMatch(entry.value);
      sourcesPhaseFiles[entry.key] = filesMatch == null
          ? const <String>[]
          : _hex24
              .allMatches(filesMatch.group(1)!)
              .map((Match m) => m.group(0)!)
              .toList();
    }

    // PBXNativeTarget: name -> build phase ids (Sources, Resources,
    // Frameworks, shell scripts, ... - filtered against sourcesPhaseFiles
    // below, which only contains ids that were actually under
    // PBXSourcesBuildPhase).
    final targetPhases = <String, List<String>>{};
    for (final entry in _objects(_section(text, 'PBXNativeTarget')).entries) {
      final nameMatch = RegExp(r'\bname = ([^;]+);').firstMatch(entry.value);
      if (nameMatch == null) continue;
      final name = _unquote(nameMatch.group(1)!);
      final phasesMatch =
          RegExp(r'buildPhases = \((.*?)\);', dotAll: true).firstMatch(entry.value);
      targetPhases[name] = phasesMatch == null
          ? const <String>[]
          : _hex24
              .allMatches(phasesMatch.group(1)!)
              .map((Match m) => m.group(0)!)
              .toList();
    }

    final sourcesMembership = <String, Set<String>>{};
    for (final target in targetPhases.entries) {
      for (final phaseId in target.value) {
        final buildFiles = sourcesPhaseFiles[phaseId];
        if (buildFiles == null) continue; // not a Sources phase id
        for (final bf in buildFiles) {
          final fr = buildFileRef[bf];
          if (fr == null) continue;
          final resolved = resolvedOf[fr];
          if (resolved == null) continue;
          sourcesMembership
              .putIfAbsent(resolved, () => <String>{})
              .add(target.key);
        }
      }
    }

    return _PbxProject._(
      sourcesMembership,
      allFileReferences,
      targetPhases.keys.toSet(),
    );
  }
}
