import 'dart:async';
import 'dart:convert';

/// Stable API signal used by newer gateways for the one Double VPN condition
/// that is safe to retry without changing the request.
const String doubleVpnAssignmentPreparingCode =
    'double_vpn_assignment_preparing';

const String _compatiblePreparingDetail =
    'Double VPN Core assignment is still being prepared. Please try again.';

/// Overall Double assignment polling budget. The Core's bounded recovery can
/// legitimately consume 90 seconds, so callers retain an additional 30
/// seconds for control-plane propagation and a complete final HTTP request.
const Duration defaultDoubleVpnAssignmentMaximumElapsed =
    Duration(seconds: 120);

class DoubleVpnAssignmentAttempt<T> {
  const DoubleVpnAssignmentAttempt({
    required this.statusCode,
    required this.body,
    required this.headers,
    required this.value,
  });

  final int statusCode;
  final String body;
  final Map<String, String> headers;
  final T value;
}

class DoubleVpnAssignmentRetryOutcome<T> {
  const DoubleVpnAssignmentRetryOutcome({
    required this.attempt,
    required this.attemptCount,
    required this.cancelled,
    required this.deadlineReached,
  });

  final DoubleVpnAssignmentAttempt<T>? attempt;
  final int attemptCount;
  final bool cancelled;
  final bool deadlineReached;
}

class FirstAcceptedRace<T> {
  const FirstAcceptedRace({required this.winner, required this.completed});

  final T? winner;
  final List<T?> completed;
}

/// Returns on the first accepted reply, or after every attempt settles.
/// Completed replies retain input order for terminal and pending precedence.
Future<FirstAcceptedRace<T>> firstAcceptedOrAll<T>(
  List<Future<T?>> attempts,
  bool Function(T) accepted,
) {
  if (attempts.isEmpty) {
    return Future<FirstAcceptedRace<T>>.value(
      FirstAcceptedRace<T>(winner: null, completed: <T?>[]),
    );
  }
  final result = Completer<FirstAcceptedRace<T>>();
  final completed = List<T?>.filled(attempts.length, null);
  var outstanding = attempts.length;

  for (var index = 0; index < attempts.length; index++) {
    final slot = index;
    void settle(T? value) {
      completed[slot] = value;
      outstanding--;
      if (result.isCompleted) return;
      var isAccepted = false;
      if (value != null) {
        try {
          isAccepted = accepted(value);
        } catch (_) {}
      }
      if (isAccepted) {
        result.complete(FirstAcceptedRace<T>(
          winner: value,
          completed: List<T?>.unmodifiable(completed),
        ));
      } else if (outstanding == 0) {
        result.complete(FirstAcceptedRace<T>(
          winner: null,
          completed: List<T?>.unmodifiable(completed),
        ));
      }
    }

    unawaited(attempts[index].then(settle, onError: (Object _) => settle(null)));
  }
  return result.future;
}

/// Returns true only for the control plane's authenticated assignment-sync
/// pending condition. Other 503 responses are deliberately terminal.
bool isDoubleVpnAssignmentPreparing({
  required int statusCode,
  required String body,
  Map<String, String> headers = const {},
}) {
  if (statusCode != 503) return false;

  final normalizedHeaders = <String, String>{
    for (final entry in headers.entries)
      entry.key.trim().toLowerCase(): entry.value.trim().toLowerCase(),
  };
  final stableCode = normalizedHeaders['x-wins-error-code'];
  if (stableCode != null) {
    return stableCode == doubleVpnAssignmentPreparingCode;
  }

  // Compatibility for already-deployed control planes that predate the
  // stable header. Match parsed JSON and the complete detail value, never a
  // substring or an HTML/edge response.
  try {
    final decoded = jsonDecode(body);
    return decoded is Map &&
        decoded.length == 1 &&
        decoded['detail'] == _compatiblePreparingDetail;
  } catch (_) {
    return false;
  }
}

/// How long to wait before polling the same assignment again.
///
/// The floor equals the fallback: a reply (or an edge in front of the hub)
/// that says `Retry-After: 0` must not turn the poll into a four-requests-a-
/// second loop, and the hub's own preparing reply asks for five seconds.
Duration doubleVpnAssignmentRetryDelay(
  Map<String, String> headers, {
  Duration fallback = const Duration(seconds: 1),
  Duration minimum = const Duration(seconds: 1),
  Duration maximum = const Duration(seconds: 10),
}) {
  String? raw;
  for (final entry in headers.entries) {
    if (entry.key.trim().toLowerCase() == 'retry-after') {
      raw = entry.value.trim();
      break;
    }
  }
  final seconds = int.tryParse(raw ?? '');
  if (seconds == null || seconds < 0) return fallback;
  final requested = Duration(seconds: seconds);
  if (requested < minimum) return minimum;
  return requested > maximum ? maximum : requested;
}

/// A requested two-hop route may only accept a response that explicitly says
/// the normalized configuration is still two-hop.
bool acceptsRequestedDoubleVpnConfig({
  required bool doubleVpnRequested,
  required Map<String, dynamic> config,
}) {
  if (!doubleVpnRequested) return true;
  return config['double_vpn_active'] == true &&
      (config['double_vpn_core_id'] ?? '').toString().trim().isNotEmpty &&
      (config['double_vpn_exit_slug'] ?? '').toString().trim().isNotEmpty;
}

/// True when Double VPN is requested but [config] is not a two-hop route, so a
/// tunnel running on it is one hop under a Double VPN setting. A missing or
/// empty config cannot prove two hops either.
bool doubleVpnRequestedButSingleHop({
  required bool doubleVpnRequested,
  required Map<String, dynamic>? config,
}) {
  if (!doubleVpnRequested) return false;
  if (config == null) return true;
  return !acceptsRequestedDoubleVpnConfig(
    doubleVpnRequested: true,
    config: config,
  );
}

/// The two values of the Android `[WinsApp] DoubleVpnRoute` key. The Kotlin
/// service reads them (VpnTunnelService.DOUBLE_VPN_ROUTE_*) to tell a Double
/// VPN config from a single-hop one when the system restarts a saved config.
const String doubleVpnRouteTwoHop = 'two-hop';
const String doubleVpnRouteSingleHop = 'single-hop';

/// The route a config really has: two-hop only when it passes
/// [acceptsRequestedDoubleVpnConfig] (flag, core id and exit slug), otherwise
/// single hop. Independent of what the user has asked for.
String doubleVpnRouteOf(Map<String, dynamic>? config) =>
    config != null &&
            acceptsRequestedDoubleVpnConfig(
              doubleVpnRequested: true,
              config: config,
            )
        ? doubleVpnRouteTwoHop
        : doubleVpnRouteSingleHop;

/// What the dashboard latches when a tunnel commits. [nativeReported] is the
/// Android service's own `double_vpn_single_hop` answer when it gave a real
/// boolean; it is the same value its notification was posted from, so it wins.
/// Anything else (no service reading, a non-boolean) falls back to the rule
/// applied to the config that committed.
bool doubleVpnCommittedSingleHop({
  required bool doubleVpnRequested,
  required Map<String, dynamic>? config,
  Object? nativeReported,
}) =>
    nativeReported is bool
        ? nativeReported
        : doubleVpnRequestedButSingleHop(
            doubleVpnRequested: doubleVpnRequested,
            config: config,
          );

/// Shown on the dashboard for as long as a requested Double VPN is running on
/// one hop.
const String doubleVpnSingleHopSessionNotice =
    'Single hop: Double VPN unavailable. Your traffic goes through one '
    'server only.';

/// Shown once when a requested Double VPN connects on one hop.
const String doubleVpnSingleHopConnectedMessage =
    'Double VPN is unavailable right now, so you are connected through one '
    'server only. Disconnect and try again later, or turn Double VPN off in '
    'Settings.';

/// Polls only while the exact Double VPN assignment preparation response is
/// returned. [requestIdentity] is passed back unchanged on every attempt so a
/// caller can construct one immutable request body (including explicit Double
/// preference and client identity) and prove it was never rewritten.
Future<DoubleVpnAssignmentRetryOutcome<T>> pollDoubleVpnAssignment<T, I>({
  required bool doubleVpnRequested,
  required I requestIdentity,
  required Future<DoubleVpnAssignmentAttempt<T>> Function(
    I requestIdentity,
    Duration timeout,
  ) request,
  bool Function()? shouldCancel,
  Duration maximumElapsed = defaultDoubleVpnAssignmentMaximumElapsed,
  Duration requestTimeout = const Duration(seconds: 7),
  Duration deadlineSafetyMargin = const Duration(milliseconds: 250),
  Duration cancellationPollInterval = const Duration(milliseconds: 200),
  Future<void> Function(Duration delay)? sleep,
  Stopwatch? stopwatch,
  Duration Function()? elapsed,
}) async {
  final clock = stopwatch ?? Stopwatch();
  final delay = sleep ?? Future<void>.delayed;
  final elapsedNow = elapsed ?? (() => clock.elapsed);
  if (!clock.isRunning) clock.start();
  var attemptCount = 0;
  DoubleVpnAssignmentAttempt<T>? lastAttempt;

  bool cancelled() => shouldCancel?.call() ?? false;

  while (true) {
    if (cancelled()) {
      return DoubleVpnAssignmentRetryOutcome<T>(
        attempt: lastAttempt,
        attemptCount: attemptCount,
        cancelled: true,
        deadlineReached: false,
      );
    }
    final remaining = maximumElapsed - elapsedNow();
    // Never begin an HTTP request that cannot receive its complete timeout
    // budget before the monotonic overall deadline.
    if (remaining < requestTimeout + deadlineSafetyMargin) {
      return DoubleVpnAssignmentRetryOutcome<T>(
        attempt: lastAttempt,
        attemptCount: attemptCount,
        cancelled: false,
        deadlineReached: true,
      );
    }

    attemptCount += 1;
    final timeoutMarker = Object();
    final cancellationMarker = Object();
    Timer? cancellationTimer;
    final cancellationSignal = Completer<Object>();
    if (shouldCancel != null) {
      cancellationTimer = Timer.periodic(cancellationPollInterval, (_) {
        if (!cancellationSignal.isCompleted && cancelled()) {
          cancellationSignal.complete(cancellationMarker);
        }
      });
    }
    try {
      final result = await Future.any<Object>([
        request(requestIdentity, requestTimeout).then<Object>((value) => value),
        Future<void>.delayed(requestTimeout).then<Object>((_) => timeoutMarker),
        if (shouldCancel != null) cancellationSignal.future,
      ]);
      if (identical(result, cancellationMarker)) {
        return DoubleVpnAssignmentRetryOutcome<T>(
          attempt: lastAttempt,
          attemptCount: attemptCount,
          cancelled: true,
          deadlineReached: false,
        );
      }
      if (identical(result, timeoutMarker)) {
        return DoubleVpnAssignmentRetryOutcome<T>(
          attempt: lastAttempt,
          attemptCount: attemptCount,
          cancelled: false,
          deadlineReached: false,
        );
      }
      lastAttempt = result as DoubleVpnAssignmentAttempt<T>;
    } on TimeoutException {
      return DoubleVpnAssignmentRetryOutcome<T>(
        attempt: lastAttempt,
        attemptCount: attemptCount,
        cancelled: false,
        deadlineReached: false,
      );
    } finally {
      cancellationTimer?.cancel();
    }
    if (cancelled()) {
      return DoubleVpnAssignmentRetryOutcome<T>(
        attempt: lastAttempt,
        attemptCount: attemptCount,
        cancelled: true,
        deadlineReached: false,
      );
    }
    if (!doubleVpnRequested ||
        !isDoubleVpnAssignmentPreparing(
          statusCode: lastAttempt.statusCode,
          body: lastAttempt.body,
          headers: lastAttempt.headers,
        )) {
      return DoubleVpnAssignmentRetryOutcome<T>(
        attempt: lastAttempt,
        attemptCount: attemptCount,
        cancelled: false,
        deadlineReached: false,
      );
    }

    var retryDelay = doubleVpnAssignmentRetryDelay(lastAttempt.headers);
    final latestSafeWake =
        maximumElapsed - requestTimeout - deadlineSafetyMargin;
    if (elapsedNow() + retryDelay > latestSafeWake) {
      return DoubleVpnAssignmentRetryOutcome<T>(
        attempt: lastAttempt,
        attemptCount: attemptCount,
        cancelled: false,
        deadlineReached: true,
      );
    }
    while (retryDelay > Duration.zero) {
      if (cancelled()) {
        return DoubleVpnAssignmentRetryOutcome<T>(
          attempt: lastAttempt,
          attemptCount: attemptCount,
          cancelled: true,
          deadlineReached: false,
        );
      }
      final slice = retryDelay < cancellationPollInterval
          ? retryDelay
          : cancellationPollInterval;
      await delay(slice);
      retryDelay -= slice;
    }
  }
}
