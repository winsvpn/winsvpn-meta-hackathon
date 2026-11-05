// The extension bundle is readable by anyone, including a censor. No real
// infrastructure address may reach it.
//
// This file is the desktop-side half of that guarantee. It has two jobs, and
// the second matters as much as the first:
//
//   1. Every message the host can emit is address-free.
//   2. THE GUARD ACTUALLY FIRES. A guard that has never been observed failing
//      is not evidence of anything. Every pattern class below is proven by
//      planting a violation and asserting the guard rejects it.
//
// The planted cases are written against the real serialisation path -- the
// same `encodeOutboundBridgeMessage` the host writes stdout through -- not
// against the regexes directly, so a future refactor that moves the guard off
// the choke point fails here.

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/browser_bridge_protocol.dart';

/// One of each message the host is capable of emitting.
List<Map<String, Object?>> everyOutboundMessage() {
  final status = BridgeStatus(
    status: BridgeTunnelStatus.connected,
    detail: BridgeDetailCode.none,
    winn: BridgeWinnState.unavailableOnThisPlatform,
    selectedSlug: 'japan',
    nodes: <BridgeNode>[
      BridgeNode(slug: 'japan', name: 'Japan', flag: '🇯🇵'),
      // Burmese, because the app ships it and a naive charset guard would
      // reject exactly this.
      BridgeNode(slug: 'singapore', name: 'စင်ကာပူ', flag: '🇸🇬'),
      BridgeNode(slug: 'st-louis', name: 'St. Louis', flag: '🇺🇸'),
    ],
    canRequestConnect: true,
    proxyPort: 51234,
    proxyReady: true,
    rxKib: 4096,
    txKib: 2048,
  );

  return <Map<String, Object?>>[
    bridgeReply(id: 'abc123', type: 'hello', body: <String, Object?>{
      'protocolVersion': kBridgeProtocolVersion,
      'platform': 'macos',
      'status': status.toWire(),
    }),
    bridgeReply(
      id: 'abc124',
      type: 'status',
      body: <String, Object?>{'status': status.toWire()},
    ),
    bridgeReply(id: 'abc125', type: 'subscribed', body: const {}),
    bridgeReply(id: 'abc126', type: 'unsubscribed', body: const {}),
    bridgeReply(id: 'abc127', type: 'revoked', body: const {}),
    bridgeReply(
      id: 'abc128',
      type: 'proxy_credential',
      body: <String, Object?>{
        // A representative token: 43 URL-safe base64 characters. It must not
        // trip the guard, and it must not be readable from anywhere else.
        'token': 'Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWpr',
        'proxyPort': 51234,
        'expiresInSeconds': 28800,
        'status': status.toWire(),
      },
    ),
    bridgeEvent(
      type: 'status',
      body: <String, Object?>{'status': status.toWire()},
    ),
    for (final code in BridgeErrorCode.values) bridgeError(id: 'e1', code: code),
  ];
}

void main() {
  group('every outbound message is address-free', () {
    test('the full message set passes the choke-point guard', () {
      final messages = everyOutboundMessage();
      expect(messages.length, greaterThanOrEqualTo(8));
      for (final message in messages) {
        expect(
          () => encodeOutboundBridgeMessage(message),
          returnsNormally,
          reason: 'message ${message['type']} must serialise',
        );
      }
    });

    test('the serialised bytes contain no address, checked independently', () {
      // A second, dumber check over the finished bytes: if the structural
      // walk and a flat scan ever disagree, that disagreement is a bug.
      for (final message in everyOutboundMessage()) {
        final text = utf8.decode(encodeOutboundBridgeMessage(message).sublist(4));
        expect(RegExp(r'\b(?:\d{1,3}\.){3}\d{1,3}\b').hasMatch(text), isFalse,
            reason: 'IPv4 literal in $text');
        expect(text.contains('winsvpn.org'), isFalse);
        expect(text.contains('endpoint'), isFalse,
            reason: 'no endpoint field may exist in the schema at all');
      }
    });

    test('legitimate content is not falsely rejected', () {
      // The guard is worthless if it is so noisy that someone disables it.
      for (final safe in <String>[
        'Japan',
        'စင်ကာပူ',
        'St. Louis',
        'United States',
        '1.0.14',
        'v1.0.14+29',
        'Côte d’Ivoire',
        '',
      ]) {
        expect(containsAddressLiteral(safe), isFalse, reason: 'rejected: $safe');
      }
    });
  });

  group('THE GUARD FIRES — planted violations', () {
    // Each case is a plausible future field addition, not a contrived string.

    test('IPv4 literal in a new status field', () {
      final message = bridgeReply(
        id: 'x',
        type: 'status',
        body: <String, Object?>{'gatewayHint': '203.0.113.7'},
      );
      expect(
        () => encodeOutboundBridgeMessage(message),
        throwsA(isA<BridgeAddressLeakException>()),
      );
    });

    test('IPv4 literal nested inside a node list', () {
      final message = bridgeReply(
        id: 'x',
        type: 'status',
        body: <String, Object?>{
          'nodes': <Object?>[
            <String, Object?>{'slug': 'spain', 'name': 'Spain', 'host': '198.51.100.9'},
          ],
        },
      );
      expect(
        () => encodeOutboundBridgeMessage(message),
        throwsA(isA<BridgeAddressLeakException>()),
      );
    });

    test('IPv6 literal', () {
      expect(
        () => encodeOutboundBridgeMessage(bridgeReply(
          id: 'x',
          type: 'status',
          body: <String, Object?>{'peer': '2606:4700:4700::1111'},
        )),
        throwsA(isA<BridgeAddressLeakException>()),
      );
    });

    test('infrastructure hostname', () {
      expect(
        () => encodeOutboundBridgeMessage(bridgeReply(
          id: 'x',
          type: 'status',
          body: <String, Object?>{'hub': 'hub-3.winsvpn.org'},
        )),
        throwsA(isA<BridgeAddressLeakException>()),
      );
    });

    test('address hidden in a map KEY, not a value', () {
      expect(
        () => encodeOutboundBridgeMessage(bridgeReply(
          id: 'x',
          type: 'status',
          body: <String, Object?>{'203.0.113.7': 'up'},
        )),
        throwsA(isA<BridgeAddressLeakException>()),
      );
    });

    test('packed IPv4 smuggled as an integer', () {
      // 3232235777 == 192.168.1.1. An integer field wide enough to hold this
      // is an address field wearing a different type.
      expect(
        () => encodeOutboundBridgeMessage(bridgeReply(
          id: 'x',
          type: 'status',
          body: <String, Object?>{'peerId': 3232235777},
        )),
        throwsA(isA<BridgeAddressLeakException>()),
      );
    });

    test('a double is refused outright as outside the closed schema', () {
      expect(
        () => encodeOutboundBridgeMessage(bridgeReply(
          id: 'x',
          type: 'status',
          body: <String, Object?>{'latencyMs': 42.5},
        )),
        throwsA(isA<BridgeAddressLeakException>()),
      );
    });

    test('the exception names where the leak was', () {
      try {
        encodeOutboundBridgeMessage(bridgeReply(
          id: 'x',
          type: 'status',
          body: <String, Object?>{
            'nodes': <Object?>[
              <String, Object?>{'name': '203.0.113.7'},
            ],
          },
        ));
        fail('guard did not fire');
      } on BridgeAddressLeakException catch (error) {
        expect(error.path, contains('nodes'));
        expect(error.toString(), contains('leak'));
      }
    });
  });

  group('the schema makes an address unrepresentable, not merely absent', () {
    test('a slug cannot spell an address', () {
      for (final bad in <String>['203.0.113.7', 'a:b', 'hub.winsvpn.org', 'UPPER']) {
        expect(
          () => BridgeNode(slug: bad, name: 'x', flag: ''),
          throwsA(isA<ArgumentError>()),
          reason: 'slug "$bad" must be rejected',
        );
      }
    });

    test('a node display name that is an address is rejected, not sanitised', () {
      // Rejected rather than scrubbed: a partially-scrubbed address is still
      // recoverable, and a silently mangled node is a bug someone will "fix".
      expect(
        () => BridgeNode(slug: 'kansas', name: '203.0.113.7', flag: ''),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('BridgeStatus has no field in which a host could travel', () {
      final wire = BridgeStatus.appNotRunning(
        winn: BridgeWinnState.unavailableOnThisPlatform,
      ).toWire();

      // The proxy is described by port alone. There is no host key to fill in,
      // which is why the extension supplies 127.0.0.1 itself.
      expect(wire.containsKey('proxyPort'), isTrue);
      expect(wire.containsKey('proxyHost'), isFalse);
      expect(wire.containsKey('host'), isFalse);
      expect(wire.containsKey('endpoint'), isFalse);
      expect(wire.containsKey('address'), isFalse);

      // And no free-form outbound string: detail is a closed code.
      expect(BridgeDetailCode.values.map((c) => c.wire), contains(wire['detail']));
    });

    test('correlation ids are echoed only when they are opaque tokens', () {
      expect(sanitizeCorrelationId('abc-123_XY'), 'abc-123_XY');
      // An extension bug that put a hostname in the id must not loop it back
      // out through this host.
      expect(sanitizeCorrelationId('hub.winsvpn.org'), '');
      expect(sanitizeCorrelationId('203.0.113.7'), '');
      expect(sanitizeCorrelationId(12345), '');
      expect(sanitizeCorrelationId('x' * 65), '');
    });
  });

  group('winn/3 is reported honestly', () {
    test('the vocabulary can express "not available here"', () {
      // macOS and Windows are WinnHostCapability.absent today. The extension
      // must be able to say so, and must have no value meaning "winn/3 is on"
      // that it could pick by accident.
      expect(BridgeWinnState.unavailableOnThisPlatform.wire,
          'unavailable_on_this_platform');
      expect(BridgeWinnState.values.length, 3);
    });

    test('unknown status never counts as carrying traffic', () {
      for (final status in BridgeTunnelStatus.values) {
        expect(
          status.isCarryingTraffic,
          status == BridgeTunnelStatus.connected,
          reason: '$status must not be treated as carrying traffic',
        );
      }
    });

    test('app-not-running is distinct from disconnected', () {
      expect(BridgeTunnelStatus.appNotRunning.wire, isNot(BridgeTunnelStatus.disconnected.wire));
      expect(BridgeTunnelStatus.fromWire('app_not_running'),
          BridgeTunnelStatus.appNotRunning);
      // An unrecognised wire value degrades to unknown, never to connected.
      expect(BridgeTunnelStatus.fromWire('anything-else'), BridgeTunnelStatus.unknown);
    });
  });
}
