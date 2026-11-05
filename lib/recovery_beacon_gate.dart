/// The failure gate for the GitHub-hosted gateway-recovery beacon.
///
/// ## Why this exists
///
/// `_resolveDynamicEndpoints()` fetched the recovery record **unconditionally**
/// on every call -- launch, every connect, and on the heartbeat. The privacy
/// policy and the code comment both describe it as a censorship fallback, but
/// nothing conditioned it on censorship, so it fired on the happy path forever.
///
/// The cost of that is asymmetric:
///
/// * **Benefit when the gateway works: zero.** The record can only *reorder*
///   gateways already compiled into the signed build
///   (`recoveryGatewayFromRecord`), and every gateway call site iterates the
///   full compiled list anyway. When the primary answers, the record changes
///   nothing that would not have happened without it.
/// * **Cost when the gateway works: a recurring, distinctive beacon** --
///   `raw.githubusercontent.com` fetched, then a TLS session to the gateway,
///   then an ICMP burst to N nodes. Each element is innocuous; the *sequence*,
///   repeated on a timer, is a fingerprint no ordinary app produces.
/// * **Benefit when the gateway is censored: real.** It saves a connect timeout
///   per API call by naming the compiled gateway that currently works.
///
/// Gating on "a full sweep of the compiled gateways has actually failed" keeps
/// the entire censorship benefit and removes the beacon from normal operation.
///
/// ## Why it is built on `bootstrap_resilience.dart`
///
/// That library is the project's single answer to "is this device censored or
/// merely unlucky", and it shipped with zero callers -- so the belief that the
/// client backs off from blocked endpoints was false. Rather than grow a second,
/// weaker copy of that judgement here, this gate folds every observation through
/// [classifyBootstrapAttempt] and [recordBootstrapAttempt] and keeps the
/// resulting [EndpointHealth] per network scope. [plannedGatewayOrder] then
/// exposes [planBootstrapAttempts] to callers that are ready to consume an
/// ordered plan, which is step 5 of the integration checklist in
/// `docs/CONTROL_PLANE_BOOTSTRAP_RESILIENCE.md`.
///
/// ## Why the beacon threshold is looser than the block threshold
///
/// Deliberate, and it is the one place this gate departs from the hysteresis in
/// `bootstrap_resilience.dart`. That library's 3-strike threshold and 15min→24h
/// backoff exist to stop a false positive from **burning a scarce fallback
/// endpoint** -- an unlinked domain that costs money, takes time to provision,
/// and is consumed the moment it is used while anyone is watching.
///
/// The recovery record is not scarce and not steerable. It is a static file on a
/// host with enormous blocking collateral, it carries no user data, and by
/// construction it can only re-order hosts that are already in the binary. The
/// expensive error for a *fallback endpoint* is a false positive; the expensive
/// error for *this* beacon is a false negative, because a censored user who
/// never fetches it pays a connect timeout on every single API call. So one
/// failed sweep opens the gate, and a throttle -- not a strike count -- bounds
/// how often it can fire.
///
/// This library performs no network I/O and reads no clock. Every input is
/// passed in, so it is fully testable and cannot itself emit anything.
library;

import 'bootstrap_resilience.dart';
import 'gateway_failover.dart';

/// Shortest interval between two recovery-record fetches.
///
/// Bounds the beacon under a sustained block: without it, a client whose
/// gateways are all censored would re-fetch on every heartbeat and reproduce
/// exactly the recurring signature this gate exists to remove. Five minutes is
/// short enough that a user who opens the app during an outage waits at most one
/// interval for a re-point, and long enough that the fetch does not track the
/// 3-5 second heartbeat.
const Duration kRecoveryBeaconMinimumInterval = Duration(minutes: 5);

/// How long a failed sweep keeps the gate open.
///
/// After this, a client that has stopped failing -- and has therefore stopped
/// producing fresh evidence -- returns to silence rather than beaconing
/// indefinitely on the strength of one bad minute on a train.
const Duration kRecoveryBeaconFailureWindow = Duration(minutes: 30);

/// Placeholder network scope used until the client can identify its current
/// network attachment.
///
/// `EndpointHealth` is deliberately scoped per network, because blocking is a
/// property of the path: a gateway censored on a hotel Wi-Fi is usually fine on
/// the same user's mobile data. The client has no connectivity-change signal
/// wired yet, so every observation currently lands in one scope. That is
/// **less** discriminating than the design intends, never more -- a stale
/// observation can only hold the gate open, and the gate opening costs one
/// throttled fetch of a static file. When a real scope token exists, pass it to
/// the `networkScope` parameters and the scoping becomes live with no other
/// change.
const String kUnknownNetworkScope = 'unknown';

/// Decides whether the recovery beacon may fire, from observed gateway
/// outcomes. Holds no hostnames of its own beyond the compiled set it is given.
class RecoveryBeaconGate {
  RecoveryBeaconGate({List<String>? compiledGateways})
      : _compiled = List<String>.unmodifiable(
          compiledGateways ?? primaryStealthGateways,
        );

  final List<String> _compiled;
  final Map<String, EndpointHealth> _health = <String, EndpointHealth>{};

  /// Endpoints introduced by a **verified** discovery record.
  ///
  /// Held separately from [_compiled] and never merged into it, so the
  /// compiled Tier-0 set stays exactly what was signed into the build. These
  /// are additive tail entries: [planBootstrapAttempts] admits them only once
  /// every compiled endpoint is blocked, and then at most one per launch.
  List<String> _discovered = const <String>[];

  String _networkScope = kUnknownNetworkScope;
  String? _lastKnownGood;
  DateTime? _lastFailureAt;
  DateTime? _lastFetchAt;

  /// The compiled gateway set this gate reasons about.
  List<String> get compiledGateways => _compiled;

  /// Endpoints from verified discovery records, in the order they will be
  /// admitted once the compiled set is exhausted.
  List<String> get discoveredGateways => _discovered;

  /// Adopt the endpoints of a verified discovery record.
  ///
  /// The caller must have verified the record first — this gate performs no
  /// cryptography and takes what it is given. Endpoints already in the
  /// compiled set are dropped by [discoveredEndpointsForSweep] before they get
  /// here, so a record naming a host the client is already sweeping cannot
  /// waste the single per-launch discovery slot on it.
  ///
  /// Deliberately **not** cleared by a network-scope change. [EndpointHealth]
  /// is scoped because reachability is a property of the path, but a signed
  /// record is a durable statement by the owner about where the control plane
  /// lives; it does not stop being true because the user changed Wi-Fi.
  void adoptDiscoveredEndpoints(List<String> endpoints) {
    final adopted = <String>[];
    for (final endpoint in endpoints) {
      final base = gatewayBase(endpoint);
      if (base.isEmpty || adopted.contains(base) || _compiled.contains(base)) {
        continue;
      }
      adopted.add(base);
    }
    _discovered = List<String>.unmodifiable(adopted);
  }

  /// The gateway that most recently answered on the current network scope.
  String? get lastKnownGoodGateway => _lastKnownGood;

  /// Record that [gateway] answered acceptably.
  ///
  /// Success clears that endpoint's health outright -- recovery needs no
  /// separate unblock path -- and closes the gate, because the evidence that
  /// opened it has been contradicted by a working gateway.
  void recordGatewaySuccess({
    required String gateway,
    required DateTime now,
    String networkScope = kUnknownNetworkScope,
  }) {
    _applyScope(networkScope);
    final endpoint = gatewayBase(gateway);
    if (endpoint.isEmpty) return;
    _health[endpoint] = recordBootstrapAttempt(
      _healthFor(endpoint),
      signal: classifyBootstrapAttempt(
        observation: BootstrapObservation.succeeded,
      ),
      networkScope: _networkScope,
      now: now,
    );
    _lastKnownGood = endpoint;
    _lastFailureAt = null;
  }

  /// Record that a full pass over the compiled gateways produced no usable
  /// response.
  ///
  /// Applied to every compiled endpoint because that is what a failed sweep
  /// means: each one was tried and none answered. Callers that cannot
  /// distinguish *why* a sweep failed should leave [observation] at its default
  /// -- `requestTimedOut` is the most conservative reading, and the gate does
  /// not depend on the distinction. Callers that *can* distinguish should pass
  /// the specific observation, because [EndpointHealth] does depend on it and
  /// will be consumed by [plannedGatewayOrder].
  void recordGatewaySweepFailure({
    required DateTime now,
    BootstrapObservation observation = BootstrapObservation.requestTimedOut,
    ControlProbeOutcome control = ControlProbeOutcome.notAttempted,
    String networkScope = kUnknownNetworkScope,
  }) {
    _applyScope(networkScope);
    if (observation == BootstrapObservation.succeeded) return;
    final signal = classifyBootstrapAttempt(
      observation: observation,
      control: control,
    );
    for (final endpoint in _compiled) {
      _health[endpoint] = recordBootstrapAttempt(
        _healthFor(endpoint),
        signal: signal,
        networkScope: _networkScope,
        now: now,
      );
    }
    _lastKnownGood = null;
    _lastFailureAt = now;
  }

  /// Whether the recovery record may be fetched at [now].
  ///
  /// False on the happy path, which is the entire point: with no recorded
  /// failure the client never touches the beacon host at all.
  bool shouldFetchRecoveryRecord(DateTime now) {
    final failedAt = _lastFailureAt;
    if (failedAt == null) return false;
    if (now.isBefore(failedAt)) return false;
    if (now.difference(failedAt) >= kRecoveryBeaconFailureWindow) return false;
    final fetchedAt = _lastFetchAt;
    if (fetchedAt != null &&
        !now.isBefore(fetchedAt) &&
        now.difference(fetchedAt) < kRecoveryBeaconMinimumInterval) {
      return false;
    }
    return true;
  }

  /// Record that a fetch was attempted, so the throttle starts.
  ///
  /// Called on *attempt*, not on success: a fetch that fails still emitted the
  /// DNS query and the TLS handshake, which is the cost this throttle bounds.
  void recordRecoveryRecordFetched(DateTime now) => _lastFetchAt = now;

  /// True once every compiled gateway is blocked on this network scope.
  ///
  /// This is the condition under which the compiled set has been exhausted and
  /// only a *discovery* record -- one that may introduce a host not in the
  /// binary -- can help. The recovery beacon cannot, because it is allowlisted
  /// to the compiled set. Exposed so the caller can tell the two situations
  /// apart rather than retrying the same exhausted list forever.
  bool discoveryRequired(DateTime now) => _plan(now).shouldQueryDiscovery;

  /// The order the compiled gateways should be attempted in at [now]: last
  /// known good first, then the compiled set, with blocked endpoints skipped
  /// until their recheck falls due.
  ///
  /// Never empty while the compiled set is non-empty -- [planBootstrapAttempts]
  /// surfaces the whole set rather than stranding a client behind its own
  /// hysteresis.
  List<String> plannedGatewayOrder(DateTime now) => _plan(now).endpoints;

  BootstrapPlan _plan(DateTime now) => planBootstrapAttempts(
        compiledEndpoints: _compiled,
        networkScope: _networkScope,
        now: now,
        lastKnownGoodEndpoint:
            _compiled.contains(_lastKnownGood) ? _lastKnownGood : null,
        discoveredEndpoints: _discovered,
        health: _health,
      );

  EndpointHealth _healthFor(String endpoint) =>
      _health[endpoint] ?? EndpointHealth(networkScope: _networkScope);

  void _applyScope(String networkScope) {
    final scope = networkScope.trim().isEmpty
        ? kUnknownNetworkScope
        : networkScope.trim();
    if (scope == _networkScope) return;
    // Evidence gathered on a different path says nothing about this one, and a
    // carried-over failure would hold the beacon open on a network that never
    // failed. Discard rather than merge -- the same rule
    // recordBootstrapAttempt applies per endpoint, applied here to the
    // gate-level state it cannot see.
    _networkScope = scope;
    _health.clear();
    _lastKnownGood = null;
    _lastFailureAt = null;
  }
}
