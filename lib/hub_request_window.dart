import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;

import 'gateway_failover.dart';

/// How a control-plane request walks the compiled gateway list.
///
/// The list is 29 fronts for one hub. The old walks were serial (status,
/// nodes, paid verify) or paired (free verify: a pair advances only after both
/// attempts fail; either authenticated response completes it at once), and
/// free verify repeated the whole list in a second pass. This window replaces
/// them:
///
///  * during silence the next front starts [stagger] after the previous one;
///    after a front fails outright the next may start sooner, but never less
///    than [minSpacing] after the previous start. With every front failing at
///    once, all 29 start within about 3 s. Whether this start pattern is itself
///    a recognisable network signature is UNVERIFIED-LIVE: nothing here was
///    measured on a censored network;
///  * at most [maxInFlight] of this walk's transport operations are open at
///    once, and every converted walk also draws from one shared
///    [HubTransportPermits] pool, so status, discovery and verify walks
///    together, including windows that already returned or were cancelled,
///    never hold more than its capacity. A permit is held until the operation
///    has actually ended, and waiting for one consumes the walk's own
///    deadline;
///  * cancellation has an explicit notification path ([HubCancellation]) that
///    completes the walk and signals every outstanding abort at once, and it
///    is rechecked before any result is accepted;
///  * each attempt is aborted after [perRequestTimeout];
///  * the whole walk ends at [totalDeadline], and every operation still open
///    is aborted.
///
/// Aborting ends this client's side of a request. It does not undo work the
/// server already did for it.
class HubRequestWindowPolicy {
  const HubRequestWindowPolicy({
    this.stagger = const Duration(milliseconds: 500),
    this.minSpacing = const Duration(milliseconds: 100),
    this.maxInFlight = 3,
    this.perRequestTimeout = const Duration(seconds: 4),
    this.totalDeadline = const Duration(seconds: 12),
  });

  final Duration stagger;
  final Duration minSpacing;
  final int maxInFlight;
  final Duration perRequestTimeout;
  final Duration totalDeadline;
}

/// Provisional budget for one refresh's /verify or /free/verify operation:
/// both passes and the endpoint resolution between them.
const Duration kHubVerifyTotalDeadline = Duration(seconds: 12);

/// Provisional budget for the advisory /free/status preflight.
const Duration kFreeStatusPreflightDeadline = Duration(seconds: 6);

/// Provisional budget for one node discovery: endpoint resolution plus the
/// GET /nodes walk.
const Duration kNodeDiscoveryDeadline = Duration(seconds: 10);

/// A per-node 503 from paid /verify. Committed by the caller only while the
/// refresh that observed it is still current.
const String kHubSignalServerAtCapacity = 'server_at_capacity';

enum HubAttemptVerdict { accepted, terminal, rejected }

/// What one attempt told the window.
///
/// [accepted] ends the walk with that value; an attempt must return it only
/// after every check on the value has passed. [terminal] is an authoritative
/// refusal from the hub: no further fronts are started, but an attempt already
/// in flight may still be accepted. [rejected] is this front failing.
///
/// [signals] are facts the caller may commit after the walk. Only signals from
/// attempts that settled before the walk finished, and not after their own
/// timeout, reach [HubRequestWindowOutcome.signals].
class HubAttemptResult<T> {
  const HubAttemptResult.accepted(T this.value)
      : verdict = HubAttemptVerdict.accepted,
        terminalKind = null,
        signals = const <String>{};

  const HubAttemptResult.terminal(String this.terminalKind)
      : verdict = HubAttemptVerdict.terminal,
        value = null,
        signals = const <String>{};

  const HubAttemptResult.rejected({this.signals = const <String>{}})
      : verdict = HubAttemptVerdict.rejected,
        value = null,
        terminalKind = null;

  final HubAttemptVerdict verdict;
  final T? value;
  final String? terminalKind;
  final Set<String> signals;
}

class HubRequestWindowOutcome<T> {
  const HubRequestWindowOutcome({
    required this.value,
    required this.acceptedUrl,
    required this.started,
    required this.terminalKinds,
    required this.signals,
    required this.deadlineReached,
    required this.cancelled,
    required this.exhaustive,
    required this.outstandingAtFinish,
  });

  /// The first accepted value by arrival time, or null.
  final T? value;
  final String? acceptedUrl;

  /// Every front this walk started, in start order.
  final List<String> started;
  final Set<String> terminalKinds;
  final Set<String> signals;
  final bool deadlineReached;
  final bool cancelled;

  /// True only when every candidate was started and every one of them ended
  /// without an accepted value, before the deadline and without cancellation.
  final bool exhaustive;

  /// Transport operations still open when the walk finished. Each was sent its
  /// abort; this counts how many had not yet ended at that instant.
  final int outstandingAtFinish;
}

/// Transport permits shared by every converted hub walk in this process.
///
/// [acquire] succeeds only while fewer than [capacity] operations hold a
/// permit. A holder releases it when its operation has ended, which may be
/// after the window that started it returned. Waiters are woken on every
/// release and retry; a waiter that no longer wants a permit simply does not.
class HubTransportPermits {
  HubTransportPermits(this.capacity);

  final int capacity;
  int _inUse = 0;
  final List<void Function()> _waiters = <void Function()>[];

  int get inUse => _inUse;

  bool tryAcquire() {
    if (_inUse >= capacity) return false;
    _inUse += 1;
    return true;
  }

  void release() {
    if (_inUse > 0) _inUse -= 1;
    final waiters = List<void Function()>.of(_waiters);
    _waiters.clear();
    for (final waiter in waiters) {
      waiter();
    }
  }

  void wait(void Function() waiter) {
    if (!_waiters.contains(waiter)) _waiters.add(waiter);
  }

  void stopWaiting(void Function() waiter) {
    _waiters.remove(waiter);
  }
}

/// The pool every production walk uses.
final HubTransportPermits kHubTransportPermits = HubTransportPermits(3);

/// An explicit cancellation for one operation.
///
/// [cancel] notifies every listener synchronously, so a window completes and
/// signals its aborts at that moment rather than at its next timer. [isStale]
/// is the operation's own currency predicate; [HubCancellationRegistry]
/// re-evaluates it whenever the owner's generations change.
class HubCancellation {
  HubCancellation([bool Function()? isStale]) : _isStale = isStale;

  final bool Function()? _isStale;
  bool _cancelled = false;
  final List<void Function()> _listeners = <void Function()>[];

  bool get isCancelled => _cancelled || (_isStale?.call() ?? false);

  void cancel() {
    if (_cancelled) return;
    _cancelled = true;
    for (final listener in List<void Function()>.of(_listeners)) {
      listener();
    }
  }

  void addListener(void Function() listener) => _listeners.add(listener);

  void removeListener(void Function() listener) => _listeners.remove(listener);
}

/// Live cancellations of one owner. [notifyGenerationChanged] is called where
/// the owner changes an account epoch or transition generation, and cancels
/// every tracked operation that is no longer current.
class HubCancellationRegistry {
  final Set<HubCancellation> _live = <HubCancellation>{};

  HubCancellation track(bool Function() isStale) {
    final cancellation = HubCancellation(isStale);
    _live.add(cancellation);
    return cancellation;
  }

  void release(HubCancellation cancellation) => _live.remove(cancellation);

  void notifyGenerationChanged() {
    for (final cancellation in List<HubCancellation>.of(_live)) {
      if (cancellation.isCancelled) cancellation.cancel();
    }
  }
}

/// `scheme://host:port` of [url], lowercased, or null when it has no host.
String? hubOriginOf(String url) {
  final uri = Uri.tryParse(url.trim());
  if (uri == null || uri.host.isEmpty) return null;
  return '${uri.scheme.toLowerCase()}://${uri.host.toLowerCase()}:${uri.port}';
}

/// The origin of the most recent accepted attempt, shared by every walk that
/// is given the same instance.
///
/// A walk that is given this starts with the candidates on that origin and
/// keeps every other candidate in its original order after them. It only
/// reorders; it never adds or drops a candidate. On a network where the
/// first compiled fronts are blocked, the next walk then skips their
/// stagger delays and reuses the pooled, already verified TLS connection to
/// the front that answered.
class HubOriginPreference {
  String? _origin;
  int _revision = 0;

  String? get origin => _origin;

  int get revision => _revision;

  void recordAccepted(String url) {
    final origin = hubOriginOf(url);
    if (origin != null) {
      _origin = origin;
      _revision += 1;
    }
  }

  /// A timeout may forget only the preference this walk observed.
  void forgetIfCurrent(int expectedRevision) {
    if (_revision != expectedRevision || _origin == null) return;
    _origin = null;
    _revision += 1;
  }

  List<String> order(List<String> urls) {
    final preferred = _origin;
    if (preferred == null) return urls;
    final first = <String>[];
    final rest = <String>[];
    for (final url in urls) {
      (hubOriginOf(url) == preferred ? first : rest).add(url);
    }
    return <String>[...first, ...rest];
  }
}

/// One attempt. [abort] completes when the window no longer wants the answer
/// (timeout, a winner, cancellation or the deadline); the attempt must pass it
/// to its transport so the operation actually ends.
typedef HubAttempt<T> = Future<HubAttemptResult<T>> Function(
  String url,
  Future<void> abort,
);

/// Runs [attempt] over [urls] under [policy] and returns the first accepted
/// result by arrival time.
///
/// [timeoutPreference] lets a walk that records its own accepted origins
/// invalidate a timed-out preference without teaching it on other replies.
Future<HubRequestWindowOutcome<T>> runHubRequestWindow<T>({
  required List<String> urls,
  required HubAttempt<T> attempt,
  HubRequestWindowPolicy policy = const HubRequestWindowPolicy(),
  bool Function()? shouldCancel,
  HubCancellation? cancellation,
  HubTransportPermits? permits,
  HubOriginPreference? preference,
  HubOriginPreference? timeoutPreference,
}) {
  final pool = permits ?? kHubTransportPermits;
  final timeoutTracker = timeoutPreference ?? preference;
  final preferredAtStart = timeoutTracker?.origin;
  final preferenceRevision = timeoutTracker?.revision;
  bool cancelRequested() =>
      (cancellation?.isCancelled ?? false) || shouldCancel?.call() == true;
  final candidates = <String>[];
  final seen = <String>{};
  for (final raw in preference?.order(urls) ?? urls) {
    final url = raw.trim();
    if (url.isEmpty || !seen.add(url)) continue;
    candidates.add(url);
  }
  final started = <String>[];
  final terminalKinds = <String>{};
  final signals = <String>{};
  final completer = Completer<HubRequestWindowOutcome<T>>();
  final maxInFlight = policy.maxInFlight < 1 ? 1 : policy.maxInFlight;
  var next = 0;
  // Transport operations that have not ended. This, not a count of results
  // still wanted, is what the cap bounds.
  var open = 0;
  var stopLaunching = false;
  var finished = false;
  var staggerDue = true;
  var advanceRequested = false;
  var spacingElapsed = true;
  Timer? staggerTimer;
  Timer? spacingTimer;
  Timer? deadlineTimer;
  final aborts = <Completer<void>>{};
  final requestTimers = <Timer>{};

  late final void Function() tryLaunch;
  late final void Function() onCancelled;

  void abortAll() {
    for (final abort in aborts.toList()) {
      if (!abort.isCompleted) abort.complete();
    }
  }

  void finish({
    T? value,
    String? acceptedUrl,
    bool deadlineReached = false,
    bool cancelled = false,
    bool exhaustive = false,
  }) {
    if (finished) return;
    finished = true;
    pool.stopWaiting(tryLaunch);
    cancellation?.removeListener(onCancelled);
    staggerTimer?.cancel();
    spacingTimer?.cancel();
    deadlineTimer?.cancel();
    for (final timer in requestTimers) {
      timer.cancel();
    }
    requestTimers.clear();
    final outstanding = open;
    abortAll();
    completer.complete(HubRequestWindowOutcome<T>(
      value: value,
      acceptedUrl: acceptedUrl,
      started: List<String>.unmodifiable(started),
      terminalKinds: Set<String>.unmodifiable(terminalKinds),
      signals: Set<String>.unmodifiable(signals),
      deadlineReached: deadlineReached,
      cancelled: cancelled,
      exhaustive: exhaustive,
      outstandingAtFinish: outstanding,
    ));
  }

  void launch() {
    final url = candidates[next];
    next += 1;
    open += 1;
    started.add(url);
    staggerDue = false;
    advanceRequested = false;
    spacingElapsed = false;
    staggerTimer?.cancel();
    staggerTimer = Timer(policy.stagger, () {
      staggerDue = true;
      tryLaunch();
    });
    spacingTimer?.cancel();
    spacingTimer = Timer(policy.minSpacing, () {
      spacingElapsed = true;
      tryLaunch();
    });
    final abort = Completer<void>();
    aborts.add(abort);
    var timedOut = false;
    final requestTimer = Timer(policy.perRequestTimeout, () {
      if (finished) return;
      timedOut = true;
      if (preferredAtStart != null && hubOriginOf(url) == preferredAtStart) {
        timeoutTracker!.forgetIfCurrent(preferenceRevision!);
      }
      if (!abort.isCompleted) abort.complete();
      // The result is no longer wanted, so the next front may start, but the
      // slot stays held until the operation below has actually ended.
      advanceRequested = true;
      tryLaunch();
    });
    requestTimers.add(requestTimer);
    void ended(HubAttemptResult<T> result) {
      requestTimer.cancel();
      requestTimers.remove(requestTimer);
      aborts.remove(abort);
      open -= 1;
      // The permit is returned only now, when the operation has ended, even
      // if this window finished long ago.
      pool.release();
      if (finished) return;
      // Cancellation is rechecked before any result is accepted.
      if (cancelRequested()) {
        finish(cancelled: true);
        return;
      }
      if (!timedOut) {
        switch (result.verdict) {
          case HubAttemptVerdict.accepted:
            preference?.recordAccepted(url);
            finish(value: result.value, acceptedUrl: url);
            return;
          case HubAttemptVerdict.terminal:
            final kind = result.terminalKind;
            if (kind != null && kind.isNotEmpty) terminalKinds.add(kind);
            stopLaunching = true;
            break;
          case HubAttemptVerdict.rejected:
            signals.addAll(result.signals);
            advanceRequested = true;
            break;
        }
      }
      tryLaunch();
    }

    Future<HubAttemptResult<T>>.sync(() => attempt(url, abort.future)).then(
      ended,
      onError: (Object _) => ended(HubAttemptResult<T>.rejected()),
    );
  }

  tryLaunch = () {
    if (finished) return;
    if (cancelRequested()) {
      finish(cancelled: true);
      return;
    }
    if (stopLaunching || next >= candidates.length) {
      if (open <= 0) {
        finish(exhaustive: !stopLaunching && next >= candidates.length);
      }
      return;
    }
    if (open >= maxInFlight) return;
    if (!staggerDue && !advanceRequested) return;
    if (!spacingElapsed) return;
    if (!pool.tryAcquire()) {
      // Another window's operations hold every permit. Wait for one; the
      // deadline keeps running meanwhile.
      pool.wait(tryLaunch);
      return;
    }
    launch();
  };
  onCancelled = () => finish(cancelled: true);
  cancellation?.addListener(onCancelled);

  if (candidates.isEmpty || policy.totalDeadline <= Duration.zero) {
    finish(deadlineReached: candidates.isNotEmpty);
    return completer.future;
  }
  if (cancelRequested()) {
    finish(cancelled: true);
    return completer.future;
  }
  deadlineTimer = Timer(policy.totalDeadline, () {
    finish(deadlineReached: true);
  });
  tryLaunch();
  return completer.future;
}

/// One HTTP request whose transport operation ends when [abort] completes.
///
/// The pinned control-plane client honours `abortTrigger` once `openUrl` has
/// returned a request (control_plane_pinning.dart); during connection setup
/// the abort takes effect when setup finishes or hits that client's own
/// connection timeout. The window keeps the slot held until then.
Future<http.Response> sendHubRequest(
  http.Client client,
  String method,
  Uri uri, {
  required Future<void> abort,
  Map<String, String>? headers,
  String? body,
}) async {
  final request = http.AbortableRequest(method, uri, abortTrigger: abort);
  if (headers != null) request.headers.addAll(headers);
  if (body != null) request.body = body;
  return http.Response.fromStream(await client.send(request));
}

/// A budget with one absolute end, shared by every step of one operation.
class HubOperationBudget {
  HubOperationBudget(this.total, {Duration Function()? elapsed})
      : _elapsed = elapsed ?? _startedStopwatch();

  final Duration total;
  final Duration Function() _elapsed;

  /// What is left, never negative.
  Duration get remaining {
    final left = total - _elapsed();
    return left.isNegative ? Duration.zero : left;
  }

  bool get spent => remaining <= Duration.zero;
}

Duration Function() _startedStopwatch() {
  final stopwatch = Stopwatch()..start();
  return () => stopwatch.elapsed;
}

/// Runs [operation] only if [budget] has time left, and stops waiting for it
/// when the budget runs out, answering [onExhausted] instead. A skipped
/// operation is never started; one that runs out keeps running in the
/// background, and its eventual result is ignored.
Future<T> runWithinBudget<T>(
  Future<T> Function() operation, {
  required Duration budget,
  required T Function() onExhausted,
}) {
  if (budget <= Duration.zero) return Future<T>.value(onExhausted());
  return operation().timeout(budget, onTimeout: onExhausted);
}

/// Classifies one /verify or /free/verify response. A 200 JSON object whose
/// `status` is `authenticated` is only a CANDIDATE: the caller must validate
/// it (hub_verify_candidate.dart) before returning it as accepted. An HTML body
/// is a captive portal or a block page, never the control plane.
HubAttemptResult<Map<String, dynamic>> classifyFreeVerifyAttempt(
  int statusCode,
  String body,
) {
  if (statusCode == 200 && !body.contains('<!DOCTYPE')) {
    try {
      final decoded = jsonDecode(body);
      if (decoded is Map) {
        final data = Map<String, dynamic>.from(decoded);
        if (data['status'] == 'authenticated') {
          return HubAttemptResult<Map<String, dynamic>>.accepted(data);
        }
      }
    } catch (_) {}
    return const HubAttemptResult<Map<String, dynamic>>.rejected();
  }
  final terminal = classifyFreeVerifyTerminalFailure(statusCode, body);
  if (terminal != null) {
    return HubAttemptResult<Map<String, dynamic>>.terminal(terminal);
  }
  return const HubAttemptResult<Map<String, dynamic>>.rejected();
}

/// The single terminal kind a failed free-verify walk reports, by the same
/// priority the paired race used, or null when no front refused terminally.
String? freeVerifyTerminalByPriority(Set<String> kinds) {
  const priority = [
    'identity_collision',
    'maintenance',
    'disabled',
    'offline',
    'rate_limited',
    'rejected',
    'unavailable',
  ];
  for (final candidate in priority) {
    if (kinds.contains(candidate)) return candidate;
  }
  return null;
}
