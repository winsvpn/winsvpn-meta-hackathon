import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// Parses the tv `colors.xml` and `styles.xml` and asserts that every color the
/// tv theme references (`@color/<name>`) is actually defined in `colors.xml`.
///
/// Android fails a build at link time if a style references an undefined color,
/// but that error is only surfaced late and only on the TV variant's own
/// resource merge. This guard reads both real files off disk so the parity is
/// checked in the same Dart test run that exercises the rest of the TV theme,
/// without needing an Android build.
///
/// Owned by lane gen_tv_colorsthemeparity (2026-08-11). Only color references
/// are in scope: `@drawable/...`, `?android:...` and `@android:...` references
/// are resources governed by other files and are intentionally ignored here.

final RegExp _definedColorName = RegExp(r'<color\s+[^>]*\bname="([^"]+)"');
final RegExp _colorRef = RegExp(r'@color/([A-Za-z0-9_.]+)');

/// Returns the sorted set of color names referenced by [stylesXml] that are not
/// defined by [colorsXml]. Empty means full parity.
Set<String> undefinedColorRefs(String colorsXml, String stylesXml) {
  final defined = <String>{};
  for (final m in _definedColorName.allMatches(colorsXml)) {
    defined.add(m.group(1)!);
  }

  final undefined = <String>{};
  for (final m in _colorRef.allMatches(stylesXml)) {
    final name = m.group(1)!;
    if (!defined.contains(name)) {
      undefined.add(name);
    }
  }
  return undefined;
}

void main() {
  const colorsPath = 'android/app/src/tv/res/values/colors.xml';
  const stylesPath = 'android/app/src/tv/res/values/styles.xml';

  test('tv styles.xml references only colors that colors.xml defines', () {
    final colorsFile = File(colorsPath);
    final stylesFile = File(stylesPath);
    expect(colorsFile.existsSync(), isTrue,
        reason: 'expected TV colors.xml at $colorsPath');
    expect(stylesFile.existsSync(), isTrue,
        reason: 'expected TV styles.xml at $stylesPath');

    final undefined = undefinedColorRefs(
      colorsFile.readAsStringSync(),
      stylesFile.readAsStringSync(),
    );

    expect(undefined, isEmpty,
        reason: 'styles.xml references colors undefined in colors.xml: '
            '${undefined.join(', ')}');
  });
}
