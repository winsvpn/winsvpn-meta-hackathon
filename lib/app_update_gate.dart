/// Pure, testable version-gating logic for the force-update feature.
///
/// The hub advertises a `min_supported_app_version`; a client older than that
/// must not be allowed to connect (it may depend on server behaviour that has
/// since changed, or be a known-broken/insecure build). This is the universal
/// half of the out-of-store update strategy: it works on every platform,
/// including iOS and Play-distributed Android where the app cannot deliver its
/// own update but can still refuse to run until the user updates through the
/// appropriate channel.
library;

/// Parses a `major.minor.patch` triple from a version string, ignoring any
/// `+build` metadata or `-prerelease` suffix and tolerating missing or
/// non-numeric components (each treated as 0). Never throws.
List<int> parseAppVersion(String version) {
  final core = version.trim().split('+').first.split('-').first;
  final parts = core.split('.');
  final result = <int>[];
  for (var i = 0; i < 3; i++) {
    if (i < parts.length) {
      result.add(int.tryParse(parts[i].trim()) ?? 0);
    } else {
      result.add(0);
    }
  }
  return result;
}

/// Returns -1, 0, or 1 comparing two `major.minor.patch` versions
/// numerically (so 1.0.9 < 1.0.10, unlike a string compare).
int compareAppVersions(String a, String b) {
  final pa = parseAppVersion(a);
  final pb = parseAppVersion(b);
  for (var i = 0; i < 3; i++) {
    if (pa[i] != pb[i]) return pa[i] < pb[i] ? -1 : 1;
  }
  return 0;
}

/// Strictly parses an exact, bounded `major.minor.patch` triple, returning
/// null for anything that is not exactly three dot-separated numeric
/// components, each within a bounded width. Unlike [parseAppVersion] it never
/// coerces a missing, extra, non-numeric, negative, or overflowing component
/// to 0 -- that lenient behaviour is exactly what let a garbage or
/// int64-overflowing `min_supported_app_version` silently collapse to `0.0.0`
/// and disable the force-update gate (L-3). A single trailing `+build`
/// metadata suffix is ignored; a `-prerelease` suffix is deliberately NOT
/// accepted here (a gate floor must be an exact release triple). Never throws.
List<int>? tryParseExactAppVersion(String raw) {
  final core = raw.trim().split('+').first;
  final match = RegExp(
    r'^(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})$',
  ).firstMatch(core);
  if (match == null) return null;
  return List<int>.generate(
    3,
    (index) => int.parse(match.group(index + 1)!),
  );
}

/// True when [current] is strictly older than [minimumSupported] -- i.e. a
/// force-update is required.
///
/// Fails OPEN by design, but ONLY for a genuinely empty/whitespace/absent or
/// `0.0.0` minimum (the default the hub ships before an admin sets a real
/// floor). A force-update gate that could brick every client on a missing or
/// fat-fingered server value is more dangerous than the outdated clients it
/// guards against.
///
/// L-3: the untrusted [minimumSupported] floor is parsed with the strict,
/// bounded [tryParseExactAppVersion] rather than the lenient [parseAppVersion],
/// so a garbage or int64-overflowing minimum can no longer silently collapse
/// to `0.0.0` and disable the gate -- an exact `major.minor.patch` triple is
/// now the only value ever honoured as a floor. A non-empty but unparseable
/// minimum fails OPEN here (never brick a client on a malformed server value);
/// the app's `/nodes` ingestion is separately responsible for not letting such
/// a value *clear* a previously-accepted floor (it leaves the prior decision
/// untouched instead of trusting the bad value). [current] is a compiled-in
/// constant and stays leniently parsed, so a legitimate `-prerelease`/`+build`
/// identifier above the floor is not spuriously blocked.
bool appUpdateRequired(String current, String minimumSupported) {
  final minimum = minimumSupported.trim();
  if (minimum.isEmpty) return false;
  final parsedMinimum = tryParseExactAppVersion(minimum);
  if (parsedMinimum == null) return false;
  if (parsedMinimum.every((component) => component == 0)) return false;
  return compareAppVersions(current, minimum) < 0;
}
