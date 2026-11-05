/// Unit tests for the freshness-bounded liveness proof that gates the green
/// "connected" claim. The whole point of this class is a fail-closed false for
/// anything that is not a positive AND recent native read, so the negative
/// controls below are the tests with teeth:
///   * stale positive -> false (a tunnel that died behind a skipped probe
///     window must drop its green the moment the proof ages out);
///   * clock moved backwards -> false (a "future" proof must not extend a
///     stale green, and a backwards jump expires every prior proof);
///   * negative answer -> false (the strongest invalidation);
///   * an absent proof (epoch) -> false for any `now`.
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/tunnel_liveness_proof.dart';

void main() {
  final epoch = DateTime.fromMillisecondsSinceEpoch(0);
  const fresh = Duration(seconds: 8);
  final now = DateTime.fromMillisecondsSinceEpoch(1000000000000);

  test('positive and fresh is active', () {
    final proof = TunnelLivenessProof(
      active: true,
      probedAt: now.subtract(const Duration(seconds: 1)),
    );
    expect(proof.activeWithin(now, fresh), isTrue);
  });

  test('positive exactly at the fresh bound is active', () {
    final proof = TunnelLivenessProof(active: true, probedAt: now.subtract(fresh));
    expect(proof.activeWithin(now, fresh), isTrue);
  });

  test('stale positive is NOT active (fail-closed on the death window)', () {
    final proof = TunnelLivenessProof(
      active: true,
      probedAt: now.subtract(const Duration(seconds: 9)),
    );
    expect(proof.activeWithin(now, fresh), isFalse);
  });

  test('a much older positive is NOT active', () {
    final proof = TunnelLivenessProof(
      active: true,
      probedAt: now.subtract(const Duration(minutes: 4)),
    );
    expect(proof.activeWithin(now, fresh), isFalse);
  });

  test('a negative proof is never active, even at the same instant', () {
    final proof = TunnelLivenessProof(active: false, probedAt: now);
    expect(proof.activeWithin(now, fresh), isFalse);
  });

  test('a proof dated in the future is NOT active (clock jumped backwards)',
      () {
    final proof = TunnelLivenessProof(
      active: true,
      probedAt: now.add(const Duration(seconds: 2)),
    );
    expect(proof.activeWithin(now, fresh), isFalse);
  });

  test('the never-probed epoch proof is never active for this process', () {
    final proof = TunnelLivenessProof(active: true, probedAt: epoch);
    expect(proof.activeWithin(now, fresh), isFalse);
  });

  test('a zero-length freshness window accepts only the exact instant', () {
    final proof = TunnelLivenessProof(active: true, probedAt: now);
    expect(proof.activeWithin(now, Duration.zero), isTrue);
    final aMomentAgo =
        TunnelLivenessProof(active: true, probedAt: now.subtract(const Duration(milliseconds: 1)));
    expect(aMomentAgo.activeWithin(now, Duration.zero), isFalse);
  });
}