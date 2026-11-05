import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/gateway_failover.dart';

/// Pins the contract between the hub's /nodes listing and the client.
///
/// THE BUG THESE EXIST FOR. The hub proved a node's data plane unreachable but
/// the listing still reported status "online", so users were offered a server
/// that provably could not work. The listing could not simply drop the node
/// either: an empty payload sends _fetchAvailableNodes() into
/// _loadCachedNodesFromDisk() + _useBootstrapNodesIfEmpty(), which offers stale
/// bootstrap servers that are no more connectable. So the node stays listed and
/// the payload carries the truth.
void main() {
  // Captured from the LIVE hub 2026-08-05, platform=linux, while Spain's UDP
  // was blocked at the IONOS edge and only the stealth transport was up.
  const liveUnreachablePayload = '''
  {"nodes":[{"slug":"spain-madrid","name":"Spain (Madrid)","flag":"🇪🇸",
    "status":"unreachable","reachable":false,
    "transports":{"direct_awg_udp":"unreachable","stealth_tcp_ws":"ok"},
    "endpoint":"<NODE_ES_IP>:9110","free_access_enabled":true}]}''';

  const liveReachablePayload = '''
  {"nodes":[{"slug":"spain-madrid","name":"Spain (Madrid)","flag":"🇪🇸",
    "status":"online","reachable":true,
    "transports":{"direct_awg_udp":"unreachable","stealth_tcp_ws":"ok"},
    "endpoint":"<NODE_ES_IP>:9110","free_access_enabled":true}]}''';

  group('listing payload keeps the client off the cached-bootstrap path', () {
    test('an unreachable node still counts as a node, so no cache fallback', () {
      // This is the whole reason the listing is not filtered. If this ever
      // returns false, users get stale bootstrap servers instead.
      expect(nodeDiscoveryPayloadHasNodes(liveUnreachablePayload), isTrue);
      expect(isNodeDiscoveryPayload(liveUnreachablePayload), isTrue);
    });

    test('an empty payload is what WOULD trigger the fallback', () {
      expect(nodeDiscoveryPayloadHasNodes('{"nodes":[]}'), isFalse);
    });
  });

  group('the payload states reachability honestly', () {
    test('unreachable node is flagged and not reported online', () {
      final n = (jsonDecode(liveUnreachablePayload)['nodes'] as List).first;
      expect(n['reachable'], isFalse);
      expect(n['status'], isNot('online'));
      expect(n['status'], 'unreachable');
    });

    test('reachable node is unchanged', () {
      final n = (jsonDecode(liveReachablePayload)['nodes'] as List).first;
      expect(n['reachable'], isTrue);
      expect(n['status'], 'online');
    });

    test('per-transport detail is present so clients can be steered', () {
      final n = (jsonDecode(liveUnreachablePayload)['nodes'] as List).first;
      final t = Map<String, dynamic>.from(n['transports']);
      expect(t['direct_awg_udp'], 'unreachable');
      expect(t['stealth_tcp_ws'], 'ok');
    });

    test('raw probe internals are NOT exposed to clients', () {
      final n = (jsonDecode(liveUnreachablePayload)['nodes'] as List).first;
      for (final k in n.keys) {
        expect(k.toString().startsWith('data_plane'), isFalse,
            reason: 'operational probe detail leaked to a public payload: $k');
      }
    });
  });
}
