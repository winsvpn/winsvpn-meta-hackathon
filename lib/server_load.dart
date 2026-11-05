// Per-server load, as reported by the hub's node listing.
//
// No Flutter import: the watch bridge and the node-list normaliser both use
// this, and it is unit-tested on its own.
//
// CONTRACT (hub -> client, fixed with the hub lane):
//   Each server item in the node-list response MAY carry `load_pct`: an
//   integer 0..100 in steps of 5, or JSON null, or no key at all (unknown,
//   stale, or an older hub).
//
// THE RULE THIS FILE EXISTS FOR
//   A listing value this client did not expect must never throw and must never
//   cost the user the server list. That has happened here before: an
//   unexpected value in a closed vocabulary threw in all three consumers and
//   discarded the whole scan reply. So the parser below is total. Every input
//   that is not exactly a contract value, whatever its type, is "unknown"
//   (null), and "unknown" is a normal, rendered state rather than an error.

/// The node-list key the hub emits.
const String kServerLoadPctKey = 'load_pct';

/// Thresholds for the three filled colours. Green below [kServerLoadAmberFrom],
/// amber from there up to (not including) [kServerLoadRedFrom], red from
/// [kServerLoadRedFrom].
const int kServerLoadAmberFrom = 60;
const int kServerLoadRedFrom = 85;

/// Parse a raw `load_pct` value into the contract domain, or null.
///
/// Accepted: an `int` in 0..100 that is a multiple of 5.
/// Everything else is unknown: null, a missing key, a string (even "45"), a
/// double (even 45.5), a bool, a negative, anything over 100, a value that is
/// not a multiple of 5, a list or a map. Off-step values are treated as a hub
/// defect rather than rounded, so a client never displays a figure finer than
/// the hub promised to publish.
///
/// Note for web builds only: dart2js represents every JSON number as a JS
/// number, so `45.0` decodes as an `int` there and is accepted as 45. That is
/// the same integral value, so the displayed figure is still correct.
int? parseServerLoadPct(Object? raw) {
  if (raw is! int) return null;
  if (raw < 0 || raw > 100) return null;
  if (raw % 5 != 0) return null;
  return raw;
}

/// Read `load_pct` from one node-list item of any shape, or null.
///
/// Never throws: a non-map item, or a map whose `[]` misbehaves, is unknown.
int? serverLoadPctOf(Object? node) {
  if (node is! Map) return null;
  try {
    return parseServerLoadPct(node[kServerLoadPctKey]);
  } catch (_) {
    return null;
  }
}

/// How a load value is coloured.
enum ServerLoadLevel {
  /// No usable value. Rendered as an empty neutral track.
  unknown,

  /// 0..59.
  low,

  /// 60..84.
  elevated,

  /// 85..100.
  high,
}

/// Classify a value that has ALREADY been through [parseServerLoadPct].
///
/// Defensive anyway: anything outside 0..100 is [ServerLoadLevel.unknown].
ServerLoadLevel serverLoadLevel(int? pct) {
  if (pct == null || pct < 0 || pct > 100) return ServerLoadLevel.unknown;
  if (pct >= kServerLoadRedFrom) return ServerLoadLevel.high;
  if (pct >= kServerLoadAmberFrom) return ServerLoadLevel.elevated;
  return ServerLoadLevel.low;
}

// ---------------------------------------------------------------------------
// FRESHNESS
// ---------------------------------------------------------------------------
//
// A load figure is live server state. It is displayed for at most
// [kServerLoadMaxAge] after THIS client received the listing that carried it,
// and is unknown after that, wherever it is shown (an open picker, the home
// tile, the watch). The hub also nulls values it considers stale; this bound
// is the client's own, so a picker left open or an app left in the background
// can never keep showing an old figure.
//
// Every node from one listing gets the same receipt stamp. The stamp is stored
// on each node map rather than once on the list because the picker works on a
// COPY of the list taken when it opened: a list-level stamp read from widget
// state would pair the newest receipt time with the copy's older figures and
// make them look fresh. The stamp keys below live only in memory. They are
// stripped from the on-disk node cache, and the watch payload is built from an
// explicit whitelist that never includes them.

/// How long a received load figure may be displayed.
const Duration kServerLoadMaxAge = Duration(seconds: 60);

/// In-memory receipt stamps (see the section comment). Monotonic ms since this
/// process started, and wall-clock ms since the epoch, read at the same moment.
const String kServerLoadReceivedMonoKey = 'load_rx_mono_ms';
const String kServerLoadReceivedWallKey = 'load_rx_wall_ms';

/// The two clocks freshness is measured with.
///
/// Age is the LARGER of the two elapsed times, because each clock fails in a
/// way the other catches:
///  * the monotonic clock (a Stopwatch) may not advance while the device is
///    suspended, so on its own it would let a figure survive a sleep;
///  * the wall clock can be set backwards (by the user or by time sync), so on
///    its own it would let a figure look younger than it is.
/// Taking the maximum means either failure alone can only make a figure look
/// OLDER, never fresher.
abstract class ServerLoadClock {
  const ServerLoadClock();

  int monotonicMs();

  int wallMs();
}

class _SystemServerLoadClock extends ServerLoadClock {
  _SystemServerLoadClock();

  final Stopwatch _stopwatch = Stopwatch()..start();

  @override
  int monotonicMs() => _stopwatch.elapsedMilliseconds;

  @override
  int wallMs() => DateTime.now().millisecondsSinceEpoch;
}

/// The clock every freshness decision reads. Replaced only by tests, which
/// point it at fake time.
ServerLoadClock serverLoadClock = _SystemServerLoadClock();

/// A receipt stamp for a listing received now.
({int mono, int wall}) serverLoadReceiptNow() =>
    (mono: serverLoadClock.monotonicMs(), wall: serverLoadClock.wallMs());

/// Plausible window for any wall-clock time this feature handles, in ms since
/// the epoch: 2020-09-13 (before the feature existed) to 2100-01-01. The same
/// window, in seconds, bounds `load_at` on both watches.
const int kServerLoadMinEpochMs = 1600000000000;
const int kServerLoadMaxEpochMs = 4102444800000;

/// Age in ms of a figure stamped (rxMono, rxWall), or null when the stamp is
/// missing or malformed (which makes the figure unknown). Never throws.
///
/// Stamps are checked by COMPARISON before any subtraction (Round LC turn 2
/// found an overflow of this class on Wear OS): the monotonic stamp must lie in
/// [0, now] and the wall stamp inside the epoch window. The clocks themselves
/// are bounded (Stopwatch ms since start; DateTime ms, at most 8.64e15), so no
/// difference below can wrap a 64-bit int.
int? serverLoadAgeMs(Object? rxMono, Object? rxWall) {
  if (rxMono is! int || rxWall is! int) return null;
  final nowMono = serverLoadClock.monotonicMs();
  // A monotonic stamp from the future cannot come from this process.
  if (rxMono < 0 || rxMono > nowMono) return null;
  if (rxWall < kServerLoadMinEpochMs || rxWall > kServerLoadMaxEpochMs) {
    return null;
  }
  final monoAge = nowMono - rxMono;
  final wallAge = serverLoadClock.wallMs() - rxWall;
  return wallAge > monoAge ? wallAge : monoAge;
}

/// The figure to DISPLAY for [node] right now: its contract value when it was
/// received less than [kServerLoadMaxAge] ago, otherwise null (unknown).
int? freshServerLoadPct(Object? node) {
  if (node is! Map) return null;
  try {
    final pct = parseServerLoadPct(node[kServerLoadPctKey]);
    if (pct == null) return null;
    final age = serverLoadAgeMs(
        node[kServerLoadReceivedMonoKey], node[kServerLoadReceivedWallKey]);
    if (age == null || age >= kServerLoadMaxAge.inMilliseconds) return null;
    return pct;
  } catch (_) {
    return null;
  }
}

/// How long until [node]'s displayed figure expires, or null if it is not
/// being displayed (unknown already). Used to schedule the one rebuild that
/// turns a bar grey.
Duration? serverLoadTimeToExpiry(Object? node) {
  if (freshServerLoadPct(node) == null) return null;
  final map = node as Map;
  final age = serverLoadAgeMs(
      map[kServerLoadReceivedMonoKey], map[kServerLoadReceivedWallKey]);
  if (age == null) return null;
  return Duration(milliseconds: kServerLoadMaxAge.inMilliseconds - age);
}

/// Copy the load figure and its receipt stamps from [from] into [to], if
/// [from] has a valid figure. Used when a node map is rebuilt from a source
/// that carries no load (the auth reply), so the figure keeps its original age.
void copyServerLoad(Map<String, dynamic> from, Map<String, dynamic> to) {
  final pct = serverLoadPctOf(from);
  final mono = from[kServerLoadReceivedMonoKey];
  final wall = from[kServerLoadReceivedWallKey];
  if (pct == null || mono is! int || wall is! int) return;
  to[kServerLoadPctKey] = pct;
  to[kServerLoadReceivedMonoKey] = mono;
  to[kServerLoadReceivedWallKey] = wall;
}

/// Remove the load figure and its stamps (disk cache, stale copies).
void stripServerLoad(Map<String, dynamic> node) {
  node.remove(kServerLoadPctKey);
  node.remove(kServerLoadReceivedMonoKey);
  node.remove(kServerLoadReceivedWallKey);
}
