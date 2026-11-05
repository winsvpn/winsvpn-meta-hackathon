import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// Regression guard for the legal-acceptance dialog's accessibility.
///
/// The general legal dialog and the separate Android VpnService dialog each
/// contain an `InkWell` wrapping a bare `Checkbox` plus its label
/// text. A bare `Checkbox` contributes a semantics node with no name, and the
/// `InkWell` contributes an unnamed button, so TalkBack reads an unlabelled
/// "checkbox, not checked". Wrapping each row in `MergeSemantics` merges the
/// checkbox's toggle state, the button affordance and the adjacent label into
/// one named node.
///
/// This is a source-consistency guard (same shape as
/// `windows_semantics_lifecycle_test.dart`): it asserts a `MergeSemantics`
/// wrapper actually sits around each legal toggle row, keyed to that row's own
/// checkbox so a silent removal of either wrapper fails the test.
void main() {
  test('separate legal and VPN toggles have labelled semantics nodes', () {
    final source = File('lib/main.dart').readAsStringSync();

    final legalStart =
        source.indexOf('Future<bool> _showLegalAcceptanceDialog');
    final vpnStart = source.indexOf(
      'Future<bool> _showAndroidVpnServiceDisclosureDialog',
    );
    final ensureStart = source.indexOf(
      'Future<Map<String, dynamic>?> _ensureLegalAcceptanceForActivation',
    );
    expect(legalStart, greaterThanOrEqualTo(0));
    expect(vpnStart, greaterThan(legalStart));
    expect(ensureStart, greaterThan(vpnStart));
    final legalDialog = source.substring(legalStart, vpnStart);
    final vpnDialog = source.substring(vpnStart, ensureStart);
    expect(legalDialog, isNot(contains('_androidVpnServiceDisclosure')),
        reason:
            'Google Play requires the VpnService disclosure to be separate');
    expect(vpnDialog, contains('_androidVpnServiceDisclosure'));
    expect(vpnDialog, contains('showDialog<bool>('));
    expect(vpnDialog, contains('barrierDismissible: false'));
    expect(vpnDialog, contains('_lightSurfaceTheme(context)'));
    expect(vpnDialog, contains('onPressed: acceptedVpnServiceDisclosure'));
    expect(
        vpnDialog, isNot(contains('_androidPackageVisibilityConsentVersion')));
    expect(vpnDialog, isNot(contains('combinedLegalLabel')));

    final termsCheckbox =
        source.indexOf('value: acceptedLegalTerms', legalStart);
    expect(termsCheckbox, greaterThanOrEqualTo(0),
        reason: 'expected a Checkbox binding "acceptedLegalTerms"');

    // The terms row's wrapper is the nearest MergeSemantics before its checkbox
    // that appears after the previous row (there is none before it), and it
    // must wrap an InkWell plus the row's label.
    _expectMergedRow(source,
        mergeBefore: termsCheckbox, label: 'combinedLegalLabel');

    // The VPN-disclosure row (Android only) comes after the terms row. Its
    // wrapper must sit strictly between the two checkboxes, so it is that row's
    // own MergeSemantics, not the terms row's.
    final vpnCheckbox =
        source.indexOf('value: acceptedVpnServiceDisclosure', vpnStart);
    expect(vpnCheckbox, greaterThan(vpnStart));
    final vpnMerge = source.lastIndexOf('MergeSemantics(', vpnCheckbox);
    expect(vpnMerge, greaterThan(termsCheckbox),
        reason: 'the VpnService-disclosure checkbox must have its own '
            'MergeSemantics wrapper (not merely inherit the terms row\'s)');
    _expectMergedRow(source,
        mergeBefore: vpnCheckbox,
        label: 'I understand and agree to the Android VpnService disclosure.');
  });
}

/// Asserts that the nearest [MergeSemantics] before [mergeBefore] wraps an
/// `InkWell`, and that the row's [label] occurs inside that wrapped region.
void _expectMergedRow(
  String source, {
  required int mergeBefore,
  required String label,
}) {
  final merge = source.lastIndexOf('MergeSemantics(', mergeBefore);
  expect(merge, greaterThanOrEqualTo(0),
      reason: 'a checkbox must be under MergeSemantics to be labelled');

  final inkWell = source.indexOf('InkWell(', merge);
  expect(inkWell, allOf(greaterThan(merge), lessThan(mergeBefore)),
      reason: 'MergeSemantics must wrap the InkWell that owns the checkbox');

  final labelPos = source.indexOf(label, merge);
  expect(labelPos, greaterThan(merge),
      reason: 'the row label must sit inside the merged region');
}
