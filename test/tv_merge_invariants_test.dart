import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// Merged-manifest TV invariants.
///
/// Reads the MERGED tvDebug Android manifest (the artifact AGP actually
/// produces for the `tv` flavor's debug variant, not the loose `src/tv/`
/// overlay) and asserts the three invariants a TV-configured variant must
/// carry TOGETHER, in one gate:
///
///   1. the leanback feature is declared (`android.software.leanback`),
///   2. the touchscreen feature is declared and NOT required
///      (`android.hardware.touchscreen` with `required="false"`), so a TV
///      form factor with no touchscreen can install the app and Play does not
///      miscategorise it as touch-required,
///   3. the MainActivity intent-filter includes the `LEANBACK_LAUNCHER`
///      category, so the TV launcher surfaces the app.
///
/// It reads the file the build produced at
/// `build/app/intermediates/merged_manifests/tvDebug/processTvDebugManifest/AndroidManifest.xml`
/// (AGP names a flavored variant's merged-manifest dir `processTvDebugManifest`;
/// `processDebugManifest` is only produced for an un-flavored debug variant,
/// so the real artifact is discovered under `tvDebug/`). Build it first with
/// `./gradlew :app:processTvDebugManifest` from `android/`. Asserting on the
/// MERGED text is deliberate: a feature declared in `src/tv/` but stripped or
/// dropped by the merger never appears here, so this gate sees the shipped
/// shape, not the source shape.
void main() {
  final projectRoot = Directory.current.path;
  final tvDebugDir = Directory([
    projectRoot,
    'build',
    'app',
    'intermediates',
    'merged_manifests',
    'tvDebug',
  ].join(Platform.pathSeparator));

  test('tvDebug merged manifest carries all three TV invariants', () {
    if (!tvDebugDir.existsSync()) {
      markTestSkipped(
        'tv release artifacts not built in this checkout; run '
        'flutter build apk --flavor tv --release '
        '(or ./gradlew :app:processTvDebugManifest from android/) '
        'and re-run to exercise the merged-manifest invariants; '
        'a clean clone has no build/app/intermediates tree.',
      );
      return;
    }

    final manifests = tvDebugDir
        .listSync(followLinks: false)
        .whereType<Directory>()
        .expand((d) => d.listSync(followLinks: false))
        .whereType<File>()
        .where((f) => f.path.endsWith('${Platform.pathSeparator}AndroidManifest.xml'))
        .toList();
    if (manifests.isEmpty) {
      fail('No AndroidManifest.xml found under ${tvDebugDir.path}');
    }
    if (manifests.length > 1) {
      fail(
        'Expected exactly one tvDebug merged AndroidManifest.xml under '
        '${tvDebugDir.path} but found ${manifests.length}: '
        '${manifests.map((f) => f.path).join(', ')}',
      );
    }

    final xml = manifests.first.readAsStringSync();
    expect(xml, isNotEmpty, reason: 'merged manifest must not be empty');

    final leanbackFeature = _usesFeatureWidget(xml, 'android.software.leanback');
    expect(
      leanbackFeature,
      isNotNull,
      reason: 'leanback feature (android.software.leanback) must be declared',
    );

    final touchscreen = _usesFeatureWidget(xml, 'android.hardware.touchscreen');
    expect(
      touchscreen,
      isNotNull,
      reason: 'touchscreen feature (android.hardware.touchscreen) must be declared',
    );
    expect(
      touchscreen!.contains('android:required="false"'),
      isTrue,
      reason: 'touchscreen must be declared required="false" (TV has no touchscreen)',
    );
    expect(
      touchscreen.contains('android:required="true"'),
      isFalse,
      reason: 'touchscreen must NOT be declared required="true"',
    );

    expect(
      xml.contains('android.intent.category.LEANBACK_LAUNCHER'),
      isTrue,
      reason: 'MainActivity intent-filter must include LEANBACK_LAUNCHER',
    );
  });
}

/// Returns the source text of a single `<uses-feature>` element declaring the
/// given feature `name`, or null if none exists. The element is captured from
/// `<uses-feature` up to its closing `>` so attribute ORDER is irrelevant.
String? _usesFeatureWidget(String xml, String featureName) {
  final re = RegExp(
    '<uses-feature\\b[^>]*?android:name="$featureName"[^>]*?/?>',
    dotAll: true,
  );
  return re.firstMatch(xml)?.group(0);
}
