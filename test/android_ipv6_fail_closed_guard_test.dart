import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// Android's IPv6 sink used to log the words "fail-closed" and behave
/// fail-open: the whole block was a `try`/`catch` whose handler only called
/// `logWarning("IPv6 fail-closed route is unavailable.", e)`, after which
/// control fell straight through to `builder.establish()`. The tunnel came up,
/// the app said Connected, and host IPv6 kept egressing on the physical
/// interface. The log string asserted a guarantee the control flow did not
/// provide, which is worse than silence because it will be believed.
///
/// The unit test that proves the *predicate*
/// (`android/app/src/test/kotlin/org/winsvpn/app/Ipv6FailClosedGateTest.kt`)
/// runs in the Gradle suite. It cannot see whether anyone actually calls the
/// predicate, or whether the call sits before `establish()`. That ordering is
/// the entire fix, so it is asserted here, in the suite that already owns the
/// Android source-ordering guards (`android_vpn_launch_guard_test.dart`).
///
/// This is deliberately a source-text test rather than a behavioural one.
/// `VpnService.Builder` cannot be instantiated off-device, so the ordering of
/// a refusal relative to `establish()` has no runtime seam on any host this
/// repository builds on. A text guard that runs everywhere beats a behavioural
/// guard that runs nowhere.
///
/// 2026-08-11: extended with the route-only failure case. The tear-down half
/// of the old guard (routes applied, address applied, tunnel up) only fails
/// closed on the *combination*; the stronger claim is the negative one — a
/// start with the sink address applied but its `::/0` route refused must never
/// reach `establish()` at all, because an established tunnel advertises IPv6
/// to the host while being unable to carry it.
void main() {
  test('Android refuses to establish a tunnel with an incomplete IPv6 sink',
      () {
    final service = File(
      'android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt',
    ).readAsStringSync();

    // 1. The predicate exists, is named, and requires BOTH halves.
    expect(service, contains('fun mayEstablishTunnel('));
    expect(
      service,
      contains('return ipv6SinkAddressApplied && ipv6SinkRouteApplied'),
    );

    // 2. The two halves are attempted separately, so a partial application
    //    cannot be mistaken for a whole one and the log can name which half
    //    the platform rejected. The sink address is a named constant rather
    //    than a literal, so a future change to the address is a reviewable
    //    diff and an accidental mutation of the route half cannot silently
    //    re-aim the sink.
    expect(service, contains('var ipv6SinkAddressApplied = false'));
    expect(service, contains('var ipv6SinkRouteApplied = false'));
    expect(
      service,
      contains('const val IPV6_FAIL_CLOSED_SINK = "fd00:d951:0001::1"'),
    );
    expect(service, contains('builder.addAddress(IPV6_FAIL_CLOSED_SINK, 128)'));
    expect(service, contains('builder.addRoute("::", 0)'));

    // 3. The exact fail-open string is gone. Named literally so that
    //    reintroducing the old handler is a red test rather than a silent
    //    regression.
    expect(
      service,
      isNot(contains('logWarning("IPv6 fail-closed route is unavailable."')),
    );

    // 4. THE ORDERING THAT IS THE FIX. The gate must be evaluated before
    //    establish() claims the phone's routing, and its refusal branch must
    //    return before it. A gate placed after establish() would be a
    //    post-hoc teardown of an already-leaking tunnel, which is the
    //    opposite polarity and leaves a window with real packets in it.
    final gate = service.indexOf('if (!mayEstablishTunnel(');
    final establish = service.indexOf('vpnInterface = builder.establish()');
    expect(gate, greaterThanOrEqualTo(0),
        reason: 'nothing consults the IPv6 fail-closed gate');
    expect(establish, greaterThanOrEqualTo(0));
    expect(gate, lessThan(establish),
        reason: 'the IPv6 gate must run before the tunnel claims routing');

    // 5. The refusal follows the platform's existing fail-closed shape --
    //    clear the restart config so the OS does not silently re-run the same
    //    doomed start unattended, tear down, and return START_NOT_STICKY --
    //    rather than inventing a new one. This is also how the user learns:
    //    isServiceActive never becomes true, so isTunnelHealthy() stays false,
    //    so the Dart readiness poll never promotes the UI to Connected. The
    //    absence of a connected state is the signal; the log line is not.
    final refusalBody = service.substring(gate, establish);
    expect(refusalBody, contains('clearRestartConfig()'));
    expect(refusalBody, contains('executeTunnelTeardown()'));
    expect(refusalBody, contains('return START_NOT_STICKY'));

    // 6. Same shape as the sibling fail-closed refusals in this file, so the
    //    comparison in point 5 is anchored to something real rather than
    //    asserted. If those change shape, this test should be revisited with
    //    them.
    expect(service, contains('logError("VPN config has no valid IPv4 AllowedIPs routes")'));
  });

  test('Android refuses a fail-closed IPv6 sink below RFC 8200 link floor', () {
    // The sink-floor guard lives in `WinnV3Posture.promotion`, where the posture
    // is built, not in `VpnTunnelService`. It is IPv6-specific even though the
    // sink carries no traffic, because a Linux kernel refuses to ATTACH any IPv6
    // address to a device below RFC 8200's 1280-byte minimum link MTU
    // (`ipv6_add_dev()` returns -EINVAL; Android surfaces it as
    // "IllegalArgumentException: Cannot set address" out of `establish()`). A
    // sink requested on a sub-1280 inner link would therefore fail at promotion
    // time on a datapath that is already carrying, which is exactly the failure
    // mode that must be made impossible at plan-build time.
    final posture = File(
      'android/app/src/main/kotlin/org/winsvpn/app/WinnV3Posture.kt',
    ).readAsStringSync();

    // The floor constant and the sink branch exist. The branch is written for
    // the sink by name, so a future author who only guards inner IPv6 and forgets
    // the sink turns this exact test red rather than silently broad-green.
    expect(posture, contains('const val IPV6_MIN_LINK_MTU = 1280'),
        reason: 'RFC 8200 link floor is missing from WinnV3Sizing');
    expect(posture, contains('if (ipv6SinkAddress != null) {'));
    expect(
        posture,
        contains('refuseUnless(innerMtu >= WinnV3Sizing.IPV6_MIN_LINK_MTU) {'),
        reason: 'the sink is not guarded against the IPv6 link floor');

    // The refusal names the sink, the floor and the kernel symptom, so a
    // developer reading the exception learns why an otherwise-plausible sink was
    // refused. Asserting the message means a guard that passes a sub-floor sink
    // through, or a sink that is ignored entirely (fail-open), both go red.
    expect(
        posture,
        contains(
            '"the IPv6 fail-closed sink \$ipv6SinkAddress was requested at an inner MTU "'),
        reason: 'the sink-floor refusal must name the sink address it rejected');
    expect(posture, contains('below RFC 8200\'s'));
    expect(
        posture,
        contains('addresses += WinnV3Address(requireNotNull(ipv6SinkAddress), 128)'),
        reason: 'the accepted sink must be installed as a /128 host address');
  });

  test('Android refuses to advertise IPv6 when there is no inner route and no '
      'fail-closed sink', () {
    // The fail-closed heart of the whole IPv6 story: a PROMOTED v4 tunnel must
    // leave host IPv6 either inside the tunnel (inner IPv6) or blackholed (the
    // ::/0 fail-closed sink). If the plan offers NEITHER, promotion refuses
    // rather than leaking host IPv6 on the physical interface next to a tunnel
    // the app reports as Connected.
    final posture = File(
      'android/app/src/main/kotlin/org/winsvpn/app/WinnV3Posture.kt',
    ).readAsStringSync();

    // The gate must be a strict "exactly one of the two shapes" check. Asserting
    // the positive (the guard exists) is the obvious half; the negative matters
    // just as much -- an `&&`, or a clause that only checks inner IPv6 and lets
    // promotion proceed with neither, would both leak host IPv6 while the app
    // reports Connected.
    expect(
        posture,
        contains(
            'refuseUnless(innerIpv6Address != null || ipv6SinkAddress != null) {'),
        reason: 'promotion does not require exactly one IPv6 shape (inner route or sink)');

    // The refusal says the words "fail-closed" and names the leak, so a reviewer
    // or a grep for fail-open regressions can find this as a unit.
    expect(
        posture,
        contains(
            '"promotion carries neither inner IPv6 nor an IPv6 fail-closed sink. Host IPv6 " +'),
        reason: 'the neither-route-nor-sink refusal must name the leak it prevents');

    // When the sink IS installed, it must capture host IPv6 with a ::/0 route,
    // otherwise the /128 ULA address is decoration and IPv6 still egresses.
    expect(
        posture,
        contains('allRoutes += WinnV3Route("::", 0)'),
        reason: 'the fail-closed sink must be paired with a ::/0 default route');
  });

  test(
      'with a sink address but no default IPv6 route the start refuses '
      'rather than advertising a protection it cannot provide', () {
    final service = File(
      'android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt',
    ).readAsStringSync();

    // 1. The gate is a strict conjunction. An address with no ::/0 route is
    //    not a documented blackhole, so the route half is mandatory and
    //    neither half may satisfy the gate on its own. Assert the NEGATIVE
    //    too: an `||` would fail open -- a tunnel with no IPv6 route would
    //    establish and the app would report Connected while host IPv6
    //    egressed in the clear. This is the exact survivor shape the
    //    mutation sweeps keep turning up: a positive assertion that a
    //    conjunction exists, with nothing asserting the OR is absent.
    final predicateStart = service.indexOf('fun mayEstablishTunnel(');
    final predicateEnd =
        service.indexOf('fun isTeardownInProgress()', predicateStart);
    expect(predicateStart, greaterThanOrEqualTo(0),
        reason: 'the IPv6 fail-closed predicate does not exist');
    expect(predicateEnd, greaterThan(predicateStart));
    final predicateBody = service.substring(predicateStart, predicateEnd);
    expect(predicateBody, contains('&& ipv6SinkRouteApplied'));
    expect(
      predicateBody,
      isNot(contains('||')),
      reason: 'an OR gate would let a tunnel establish with no IPv6 route, '
          'claiming protection while IPv6 leaked',
    );

    // 2. The route half is only true after the platform actually accepts
    //    ::/0; a rejection just leaves the flag false, which is exactly what
    //    makes the predicate a refusal rather than a wish.
    expect(service, contains('var ipv6SinkRouteApplied = false'));
    expect(service, contains('builder.addRoute("::", 0)'));

    // 3. The refusal branch sits between the gate and establish(), and it
    //    returns without ever calling establish(). The tuple (address
    //    applied, route refused) lands in this branch, so the sink address
    //    and the ::/0 route are never handed to the OS and nowhere on this
    //    path is IPv6 advertised into a tunnel that cannot carry it.
    final gateText =
        'if (!mayEstablishTunnel(ipv6SinkAddressApplied, ipv6SinkRouteApplied)) {';
    final gate = service.indexOf(gateText);
    final establish = service.indexOf('vpnInterface = builder.establish()');
    expect(gate, greaterThanOrEqualTo(0),
        reason: 'nothing consults the gate for the route-refused failure case');
    expect(establish, greaterThan(gate));
    final refusalPath = service.substring(gate, establish);
    expect(refusalPath, contains('return START_NOT_STICKY'));
    expect(refusalPath, contains('clearRestartConfig()'));
    expect(refusalPath, contains('executeTunnelTeardown()'));
    expect(
      refusalPath,
      isNot(contains('establish()')),
      reason: 'a refusal that still reaches establish() would advertise the '
          'IPv6 sink to the host on a tunnel that cannot carry IPv6 -- the '
          'fail-open shape this guard exists to prevent',
    );

    // 4. The refusal names the leak in its own text: host IPv6 would leave
    //    the tunnel. The message being greppable is secondary; what matters
    //    is that the refusal is a dead stop, not a comment another handler
    //    can fall out of the way it did when assert-in-log was the whole
    //    fix.
    expect(refusalPath, contains('so host IPv6 would leave outside the tunnel.'));
  });

  test('the IPv6 fail-closed posture is the same one Apple hard-requires', () {
    // Cross-platform parity anchor. Apple refuses at parse time with 1203 when
    // a document does not request `::/0`; Android now refuses at build time
    // when the platform will not accept the sink. Both refuse rather than
    // connecting unprotected. This test exists so that a lane relaxing either
    // side has to notice the other.
    final appleConfig = File(
      'apple/WinsTunnelCore/WinsTunnelConfig.swift',
    ).readAsStringSync();

    expect(appleConfig, contains('// EVERY accepted document must request `::/0`. Unconditionally.'));
    expect(
      appleConfig,
      contains(
          'throw validationError(code: 1203, message: "Missing or invalid allowed IP routes.")'),
    );
    expect(appleConfig, contains('allowedIPv6DefaultRouteEnabled else {'));
  });
}