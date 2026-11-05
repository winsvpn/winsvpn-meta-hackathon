/// Owns monotonically increasing smart-connect transition generations.
///
/// A cancellation owner stops the native tunnel. Obsolete connect generations
/// only return; they must never stop a newer generation's tunnel.
class TunnelTransitionGate {
  int _generation = 1;

  int begin() => ++_generation;

  int cancel() => ++_generation;

  bool isCurrent(int generation) => generation == _generation;

  int get supersededFloor => _generation > 1 ? _generation - 1 : 1;
}
