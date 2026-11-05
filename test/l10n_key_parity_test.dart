import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// L10n key-parity guard.
///
/// Parses `lib/l10n/app_en.arb` (the template) and `lib/l10n/app_my.arb` (the
/// Burmese translation) and fails if ANY non-metadata English key lacks a
/// corresponding Burmese key.
///
/// A key is "non-metadata" when its name does not begin with `@`. This excludes
/// both message placeholders/descriptions (`@foo`) and the top-level
/// `@@locale`/`@@last_modified` entries.
///
/// Why this exists at all: a message can only ever render in Burmese if the
/// generated `app_localizations_my.dart` has a getter for it, and that getter
/// is only emitted when the key exists in `app_my.arb`. An English-only string
/// silently falls back to English at runtime — or, worse, a `Locale('my')`
/// device renders a half-translated screen with no error anywhere. This guard
/// makes that a test failure at the moment the template grows a key the
/// translation has not caught up with.
///
/// The guard reads the real ARB files from the package's `lib/l10n` by
/// default. It honours `L10N_ARB_DIR` (an absolute path to a directory holding
/// `app_en.arb` and `app_my.arb`) so the harness's own green/red controls can
/// be run against a scratch copy without touching the shared working tree.
void main() {
  group('app_en.arb / app_my.arb key parity', () {
    test('every non-metadata English key has a corresponding Myanmar key', () {
      final arbDir = Directory(
        Platform.environment['L10N_ARB_DIR'] ??
            '${_packageRoot.path}/lib/l10n',
      );

      final en = _readArb(arbDir, 'app_en.arb');
      final my = _readArb(arbDir, 'app_my.arb');

      final enTemplateKeys = _nonMetadataKeys(en);
      final myKeys = _nonMetadataKeys(my);

      expect(
        enTemplateKeys,
        isNotEmpty,
        reason: 'app_en.arb must carry at least one translatable key; an '
            'empty template means this guard is reading nothing.',
      );

      final missing = enTemplateKeys
          .where((k) => !myKeys.contains(k))
          .toList()
        ..sort();

      expect(
        missing,
        isEmpty,
        reason: '${missing.length} English key(s) in app_en.arb have no '
            'corresponding entry in app_my.arb. Each listed key must be '
            'translated into app_my.arb (owned by the data-authoring lane), '
            'or every Burmese device falls back to English for it.\n'
            '${missing.map((k) => '  - $k').join('\n')}',
      );
    });
  });
}

Set<String> _nonMetadataKeys(Map<String, dynamic> arb) => arb.keys
    .where((k) => !k.startsWith('@'))
    .toSet();

Map<String, dynamic> _readArb(Directory dir, String name) {
  final file = File('${dir.path}/$name');
  if (!file.existsSync()) {
    fail('$name does not exist in "$dir". The parity contract cannot be '
        'checked against a file that cannot be read.');
  }
  return jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;
}

Directory get _packageRoot {
  var dir = Directory.current;
  while (true) {
    if (File('${dir.path}/pubspec.yaml').existsSync() &&
        File('${dir.path}/lib/l10n/app_en.arb').existsSync()) {
      return dir;
    }
    final parent = dir.parent;
    if (parent.path == dir.path) {
      throw StateError(
        'Could not find the wins_vpn package root by walking up from '
        '"${Directory.current.path}". This guard reads l10n ARB files by '
        'path; without a root it would read nothing and report success.',
      );
    }
    dir = parent;
  }
}
