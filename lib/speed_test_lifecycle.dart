class SpeedTestLease {
  const SpeedTestLease._({
    required this.generation,
    required this.routeIdentity,
  });

  final int generation;
  final String routeIdentity;
}

/// Owns the single speed-test lifetime.
///
/// Cancellation ends the current generation synchronously. A late completion
/// from that generation therefore cannot publish results or clear the running
/// state of a replacement test.
class SpeedTestLeaseController {
  int _generation = 0;
  bool _running = false;

  bool get isRunning => _running;

  SpeedTestLease? tryBegin(String routeIdentity) {
    if (_running) return null;
    _running = true;
    _generation += 1;
    return SpeedTestLease._(
      generation: _generation,
      routeIdentity: routeIdentity,
    );
  }

  bool isCurrent(SpeedTestLease lease, String currentRouteIdentity) =>
      _running &&
      lease.generation == _generation &&
      lease.routeIdentity == currentRouteIdentity;

  /// Invalidates all work issued under the current generation.
  ///
  /// Returns whether a run was active so callers can update UI selectively.
  bool cancel() {
    final wasRunning = _running;
    _generation += 1;
    _running = false;
    return wasRunning;
  }

  /// Cancels only [lease]. A stale operation cannot cancel its replacement.
  bool cancelLease(SpeedTestLease lease) {
    if (!_running || lease.generation != _generation) return false;
    _generation += 1;
    _running = false;
    return true;
  }

  /// Completes [lease] only if no cancellation or replacement occurred.
  bool complete(SpeedTestLease lease) {
    if (!_running || lease.generation != _generation) return false;
    _running = false;
    return true;
  }
}
