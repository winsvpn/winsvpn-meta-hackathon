/// Where the saved server choice points after the listing changes, and which
/// row the server list marks.
///
/// `_selectedLocationIndex` is an index into `_locations`, and the hub
/// listing rewrites `_locations` on every refresh. The re-bind used to return
/// row 0 for a manual choice the new listing did not carry (a node closed to
/// customers, a removed node, or a listing that had not loaded yet) while
/// `_automaticNodeSelection` stayed false. The first row by name then looked
/// like the user's own choice, was persisted as one, and was what the next
/// connect requested. On 2026-09-27 an S26 carrying on us-chicago1 showed its
/// check on Canada, the first row once Canada was listed again.
///
/// Here a manual choice that is not listed stays the choice, is marked as
/// unlisted, and is never replaced by another row. It is requested as itself,
/// so the hub refuses it rather than the app dialling a node the user did not
/// pick. The server list offers only listed rows, so a closed node is never
/// offered. The dashboard names the unlisted choice with status
/// `unavailable` when a fresh live listing omits it, `unknown` otherwise.
/// A user connect is refused only after a live refresh, and only when a fresh
/// live listing omits the choice ([freshListingOmits]); when the listing
/// cannot be refreshed the exact choice is attempted and the hub decides.
///
/// Pure Dart: the selection harness executes the production re-bind against
/// this exact file.
library;

import 'tunnel_display_identity.dart';

/// `_selectedLocationIndex` while a manual choice is not in the listing. It is
/// the only negative index the app writes, and only [rebindSelection] returns
/// it.
const int kUnlistedSelectionIndex = -1;

/// How long a live /nodes listing counts as evidence that a node it omits is
/// not accepting connections. Older listings, cached listings and bootstrap
/// listings never count.
const Duration kFreshListingMaxAge = Duration(minutes: 2);

/// How often a deferred settings restart that found another operation
/// running is tried again.
const Duration kSettingsRestartRetryInterval = Duration(milliseconds: 500);

/// The longest a connect to an unlisted choice waits for a live listing
/// before attempting the exact choice. The same bound as the picker's own
/// pre-open refresh.
const Duration kUnlistedChoiceRefreshBound = Duration(seconds: 2);

/// Whether a live listing received at [liveListingAt] is fresh at [now]. A
/// missing stamp, a clock that went backwards, or an age above [maxAge] is
/// not fresh.
bool listingIsFresh({
  required DateTime? liveListingAt,
  required DateTime now,
  Duration maxAge = kFreshListingMaxAge,
}) {
  if (liveListingAt == null) return false;
  final age = now.difference(liveListingAt);
  return !age.isNegative && age <= maxAge;
}

/// Whether a fresh live listing omits [slug]: the only evidence on which the
/// app refuses a user's exact choice. False for a slug that names no node, an
/// empty listing, or a listing that is not fresh.
bool freshListingOmits({
  required List<Map<String, dynamic>> locations,
  required String slug,
  required DateTime? liveListingAt,
  required DateTime now,
  Duration maxAge = kFreshListingMaxAge,
}) {
  final wanted = slug.trim();
  if (wanted.isEmpty || wanted.toLowerCase() == 'auto') return false;
  if (locations.isEmpty) return false;
  if (!listingIsFresh(liveListingAt: liveListingAt, now: now, maxAge: maxAge)) {
    return false;
  }
  return !locations
      .any((location) => (location['slug'] ?? '').toString() == wanted);
}

class SelectionRebind {
  const SelectionRebind({required this.index, this.unlisted});

  /// Index into the listing, or [kUnlistedSelectionIndex].
  final int index;

  /// Identity only (slug, name, flag) of a manual choice the listing does not
  /// carry; null whenever [index] is a listing row.
  final Map<String, dynamic>? unlisted;
}

/// Binds [intendedSlug] to [locations].
///
/// A listed slug binds to its row, in either mode. An automatic choice, or a
/// slug that names no node (empty or `auto`), keeps the old row-0 display
/// default: automatic routing requests `auto` whatever row is displayed. A
/// manual choice that is not listed returns [kUnlistedSelectionIndex] and its
/// identity, taken from [knownRows] when one of them carries that slug.
SelectionRebind rebindSelection({
  required List<Map<String, dynamic>> locations,
  required String intendedSlug,
  required bool automatic,
  Iterable<Map<String, dynamic>> knownRows = const <Map<String, dynamic>>[],
}) {
  final slug = intendedSlug.trim();
  final usable = slug.isNotEmpty && slug.toLowerCase() != 'auto';
  if (usable) {
    final index = locations
        .indexWhere((location) => (location['slug'] ?? '').toString() == slug);
    if (index >= 0) return SelectionRebind(index: index);
  }
  if (automatic || !usable) return const SelectionRebind(index: 0);
  Map<String, dynamic>? known;
  for (final row in knownRows) {
    if ((row['slug'] ?? '').toString().trim() == slug) {
      known = row;
      break;
    }
  }
  final name = (known?['name'] ?? '').toString().trim();
  final flag = known?['flag'];
  return SelectionRebind(
    index: kUnlistedSelectionIndex,
    unlisted: <String, dynamic>{
      'slug': slug,
      'name': name.isEmpty ? slug : name,
      if (flag != null && !(flag is String && flag.trim().isEmpty))
        'flag': flag,
    },
  );
}

/// The slug the server list marks with its check; empty marks no row.
///
/// While a tunnel is secured that is the node carrying it, and no row when
/// that node is not known (a tunnel adopted after a restart). It is never the
/// saved choice while secured: the saved choice can differ from the carrying
/// node (hub assignment, adoption, a choice that re-bound). Otherwise it is
/// the saved manual choice, or no row in automatic mode.
String pickerCheckedSlug({
  required DashboardNodeDisplay dashboard,
  required bool automatic,
  required String selectedSlug,
}) {
  switch (dashboard.source) {
    case DashboardNodeSource.committedTunnel:
      return (dashboard.node?['slug'] ?? '').toString().trim();
    case DashboardNodeSource.unknownTunnel:
      return '';
    case DashboardNodeSource.picker:
      return automatic ? '' : selectedSlug.trim();
  }
}

/// Whether a tap on [tappedSlug] asks for a server other than the one in use.
///
/// While secured, the node in use is the carrying node in either mode: a tap
/// on it only saves it as the manual choice, and a tap on any row reconnects
/// while the carrying node is not known. Not secured, it is the saved manual
/// choice, and any tap in automatic mode changes the choice.
bool pickerTapChangesServer({
  required DashboardNodeDisplay dashboard,
  required bool automatic,
  required String selectedSlug,
  required String tappedSlug,
}) {
  final tapped = tappedSlug.trim();
  switch (dashboard.source) {
    case DashboardNodeSource.committedTunnel:
    case DashboardNodeSource.unknownTunnel:
      final carrying = pickerCheckedSlug(
        dashboard: dashboard,
        automatic: automatic,
        selectedSlug: selectedSlug,
      );
      return carrying.isEmpty || tapped != carrying;
    case DashboardNodeSource.picker:
      if (automatic) return true;
      final saved = selectedSlug.trim();
      return saved.isEmpty || tapped != saved;
  }
}
