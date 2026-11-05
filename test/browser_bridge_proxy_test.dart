// Proof for the two properties the extension lane depends on absolutely:
//
//   1. THE PROXY IS LOOPBACK-ONLY. A proxy on 0.0.0.0 would let anything on
//      the LAN use the tunnel. That is the mistake found on the GX10 (ollama
//      bound wide with no auth, open all night); it must not be reproduced one
//      layer in.
//
//   2. THE PROXY FAILS CLOSED. When the tunnel is not up, the proxy refuses.
//      It does not fall back to the naked interface. The strong form of this
//      proof is not "a 503 came back" but "the upstream connector was never
//      invoked" -- traffic cannot leak through a connection that was never
//      opened.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/browser_bridge_proxy.dart';

/// A gate whose answer the test controls.
class FakeGate implements TunnelGate {
  FakeGate(this._open);

  bool _open;
  final StreamController<bool> _changes = StreamController<bool>.broadcast();

  @override
  bool get admitsTraffic => _open;

  @override
  Stream<bool> get changes => _changes.stream;

  void set(bool open) {
    _open = open;
    _changes.add(open);
  }

  Future<void> dispose() => _changes.close();
}

/// Records every upstream connection attempt so a test can assert there were
/// none.
class RecordingConnector {
  RecordingConnector(this._upstreamPort);

  final int _upstreamPort;
  final List<String> attempts = <String>[];

  Future<Socket> call(String host, int port) async {
    attempts.add('$host:$port');
    // Connect to the stand-in upstream rather than the real destination: no
    // test in this file may put a packet on the Internet.
    return Socket.connect(InternetAddress.loopbackIPv4, _upstreamPort);
  }
}

/// Documentation-range public destination. Used as the positive fixture so
/// name resolution never leaves this machine.
final InternetAddress kPublicConnectFixture = InternetAddress('192.0.2.1');

Future<List<InternetAddress>> _publicFixtureResolver(String host) async {
  final String h = unbracketConnectHost(host);
  final InternetAddress? parsed = InternetAddress.tryParse(h);
  if (parsed != null) return <InternetAddress>[parsed];
  return <InternetAddress>[kPublicConnectFixture];
}

BridgeProxyServer _proxy({
  required FakeGate gate,
  required ProxyCredential credential,
  required UpstreamConnector connector,
  ConnectTargetResolver? resolver,
}) {
  return BridgeProxyServer(
    gate: gate,
    credential: credential,
    connector: connector,
    resolver: resolver ?? _publicFixtureResolver,
  );
}

String _basic(String token) =>
    'Basic ${base64.encode(utf8.encode('bridge:$token'))}';

/// Send a raw CONNECT and return the status line.
Future<String> _connectRequest(
  int port, {
  String? authorization,
  String authority = 'example.org:443',
}) async {
  final socket = await Socket.connect(InternetAddress.loopbackIPv4, port);
  final buffer = StringBuffer()
    ..write('CONNECT $authority HTTP/1.1\r\n')
    ..write('Host: $authority\r\n');
  if (authorization != null) {
    buffer.write('Proxy-Authorization: $authorization\r\n');
  }
  buffer.write('\r\n');
  socket.write(buffer.toString());

  final response = await socket
      .cast<List<int>>()
      .transform(utf8.decoder)
      .take(1)
      .join()
      .timeout(const Duration(seconds: 5), onTimeout: () => '');
  socket.destroy();
  return response.split('\r\n').first;
}

/// What a client saw on a CONNECT whose connection the proxy dropped.
class _ClosedOutcome {
  _ClosedOutcome(this.received, this.closed);

  /// Bytes the proxy sent before the socket ended.
  final String received;

  /// True when the proxy ended the connection itself (a normal close or a
  /// reset). False means the wait timed out with the socket still open.
  final bool closed;
}

/// Send a raw CONNECT and report whether the proxy closed the socket and what,
/// if anything, it wrote first. Used where the proxy must drop the client with
/// no reply at all (a request still resolving when the tunnel gate closes).
Future<_ClosedOutcome> _connectRequestUntilClosed(
  int port, {
  String? authorization,
  String authority = 'example.org:443',
}) async {
  final socket = await Socket.connect(InternetAddress.loopbackIPv4, port);
  final buffer = StringBuffer()
    ..write('CONNECT $authority HTTP/1.1\r\n')
    ..write('Host: $authority\r\n');
  if (authorization != null) {
    buffer.write('Proxy-Authorization: $authorization\r\n');
  }
  buffer.write('\r\n');
  socket.write(buffer.toString());

  final received = <int>[];
  final ended = Completer<bool>();
  socket.listen(
    received.addAll,
    onDone: () {
      if (!ended.isCompleted) ended.complete(true);
    },
    onError: (Object _) {
      if (!ended.isCompleted) ended.complete(true);
    },
    cancelOnError: true,
  );
  final closed = await ended.future
      .timeout(const Duration(seconds: 5), onTimeout: () => false);
  socket.destroy();
  return _ClosedOutcome(utf8.decode(received, allowMalformed: true), closed);
}

/// Send a raw plain-HTTP request (a non-CONNECT method) and return the status
/// line. A proxy that implements CONNECT-only has to refuse this head without
/// ever touching the upstream.
Future<String> _plainRequest(
  int port, {
  String? authorization,
  String target = 'http://example.org/path',
}) async {
  final socket = await Socket.connect(InternetAddress.loopbackIPv4, port);
  final buffer = StringBuffer()
    ..write('GET $target HTTP/1.1\r\n')
    ..write('Host: example.org\r\n');
  if (authorization != null) {
    buffer.write('Proxy-Authorization: $authorization\r\n');
  }
  buffer.write('\r\n');
  socket.write(buffer.toString());

  final response = await socket
      .cast<List<int>>()
      .transform(utf8.decoder)
      .take(1)
      .join()
      .timeout(const Duration(seconds: 5), onTimeout: () => '');
  socket.destroy();
  return response.split('\r\n').first;
}

void main() {
  late ServerSocket upstream;
  late RecordingConnector connector;
  late ProxyCredential credential;

  setUp(() async {
    // Stand-in for "the far end". Accepts and discards.
    upstream = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    upstream.listen((Socket s) => s.listen((_) {}, onError: (_) {}));
    connector = RecordingConnector(upstream.port);
    credential = ProxyCredential.generate();
  });

  tearDown(() async {
    await upstream.close();
  });

  test('revocation during resolution prevents an upstream dial', () async {
    final gate = FakeGate(true);
    final entered = Completer<void>();
    final resolved = Completer<List<InternetAddress>>();
    final proxy = _proxy(
      gate: gate,
      credential: credential,
      connector: connector.call,
      resolver: (_) {
        entered.complete();
        return resolved.future;
      },
    );
    await proxy.start();
    try {
      final response = _connectRequestUntilClosed(
        proxy.port,
        authorization: _basic(credential.token),
      );
      await entered.future.timeout(const Duration(seconds: 5));
      gate.set(false);
      resolved.complete(<InternetAddress>[kPublicConnectFixture]);
      // The gate closing drops every live client, including one whose name is
      // still resolving, so the client sees its socket closed with no reply.
      final outcome = await response;
      expect(outcome.closed, isTrue,
          reason: 'the proxy must close the client socket, not leave it open');
      expect(outcome.received, isEmpty,
          reason: 'a dropped request gets no reply');
      expect(connector.attempts, isEmpty);
    } finally {
      await proxy.stop();
      await gate.dispose();
    }
  });

  group('admission across DNS (Sol-core-5)', () {
    test('a gate closed while the name resolves opens no upstream', () async {
      final gate = FakeGate(true);
      final resolving = Completer<void>();
      final release = Completer<void>();
      final proxy = _proxy(
        gate: gate,
        credential: credential,
        connector: connector.call,
        resolver: (String host) async {
          resolving.complete();
          await release.future;
          return <InternetAddress>[kPublicConnectFixture];
        },
      );
      await proxy.start();
      final status = _connectRequest(proxy.port,
          authorization: _basic(credential.token));
      await resolving.future;
      gate.set(false);
      release.complete();
      await status;
      expect(connector.attempts, isEmpty);
      expect(proxy.upstreamOpened, 0);
      await proxy.stop();
      await gate.dispose();
    });

    test('a stop and restart while resolving opens no upstream for the old '
        'request, and the restarted proxy still serves new ones', () async {
      final gate = FakeGate(true);
      var held = true;
      final resolving = Completer<void>();
      final release = Completer<void>();
      final proxy = _proxy(
        gate: gate,
        credential: credential,
        connector: connector.call,
        resolver: (String host) async {
          if (held) {
            held = false;
            resolving.complete();
            await release.future;
          }
          return <InternetAddress>[kPublicConnectFixture];
        },
      );
      await proxy.start();
      final stale = _connectRequest(proxy.port,
          authorization: _basic(credential.token));
      await resolving.future;
      await proxy.stop();
      await proxy.start();
      release.complete();
      await stale;
      expect(connector.attempts, isEmpty);
      expect(
          await _connectRequest(proxy.port,
              authorization: _basic(credential.token)),
          contains('200'));
      expect(connector.attempts, hasLength(1));
      await proxy.stop();
      await gate.dispose();
    });

    test('T4: a stop while the bind is pending leaves nothing listening, '
        'and a later start works', () async {
      final gate = FakeGate(true);
      final proxy = _proxy(
          gate: gate, credential: credential, connector: connector.call);
      final starting = proxy.start();
      final stopping = proxy.stop();
      await Future.wait(<Future<void>>[starting, stopping]);
      expect(proxy.isListening, isFalse);
      expect(proxy.port, 0);
      await proxy.start();
      expect(proxy.isListening, isTrue);
      expect(
          await _connectRequest(proxy.port,
              authorization: _basic(credential.token)),
          contains('200'));
      await proxy.stop();
      await gate.dispose();
    });

    test('T4: concurrent starts share one bind', () async {
      final gate = FakeGate(true);
      final proxy = _proxy(
          gate: gate, credential: credential, connector: connector.call);
      final a = proxy.start();
      final b = proxy.start();
      expect(identical(a, b), isTrue);
      await Future.wait(<Future<void>>[a, b]);
      expect(proxy.isListening, isTrue);
      await proxy.stop();
      await gate.dispose();
    });
  });

  group('loopback binding', () {
    test('binds 127.0.0.1, never the wildcard', () async {
      final gate = FakeGate(false);
      final proxy = _proxy(
        gate: gate,
        credential: credential,
        connector: connector.call,
      );
      await proxy.start();

      expect(proxy.isListening, isTrue);
      expect(proxy.port, greaterThan(0));

      // Reachable on loopback.
      final local = await Socket.connect(
        InternetAddress.loopbackIPv4,
        proxy.port,
      ).timeout(const Duration(seconds: 5));
      local.destroy();

      await proxy.stop();
      await gate.dispose();
    });
    test('is NOT reachable on this machine\'s LAN address', () async {
      final gate = FakeGate(false);
      final proxy = _proxy(
        gate: gate,
        credential: credential,
        connector: connector.call,
      );
      await proxy.start();

      final interfaces = await NetworkInterface.list(
        includeLoopback: false,
        type: InternetAddressType.IPv4,
      );
      final lan = interfaces.expand((i) => i.addresses).toList();

      if (lan.isEmpty) {
        // No non-loopback IPv4 on this machine; the binding assertion above
        // still stands. Not silently passed off as a success.
        markTestSkipped('no non-loopback IPv4 interface to test against');
      } else {
        for (final address in lan) {
          await expectLater(
            Socket.connect(address, proxy.port,
                timeout: const Duration(seconds: 2)),
            throwsA(isA<SocketException>()),
            reason: 'proxy answered on ${address.address} — it is not '
                'loopback-only',
          );
        }
      }

      await proxy.stop();
      await gate.dispose();
    });
  });

  group('fail closed', () {
test('gate closing during DNS refuses before connecting', () async {
  final gate = FakeGate(true);
  final entered = Completer<void>();
  final resolved = Completer<List<InternetAddress>>();
  final proxy = _proxy(
    gate: gate,
    credential: credential,
    connector: connector.call,
    resolver: (_) {
      entered.complete();
      return resolved.future;
    },
  );
  await proxy.start();
  try {
    final response = _connectRequestUntilClosed(
      proxy.port,
      authorization: _basic(credential.token),
    );
    await entered.future.timeout(const Duration(seconds: 2));
    gate.set(false);
    resolved.complete(<InternetAddress>[kPublicConnectFixture]);
    final outcome = await response;
    expect(outcome.closed, isTrue,
        reason: 'the proxy must close the client socket, not leave it open');
    expect(outcome.received, isEmpty,
        reason: 'a dropped request gets no reply');
    expect(connector.attempts, isEmpty);
    expect(proxy.upstreamOpened, 0);
  } finally {
    await proxy.stop();
    await gate.dispose();
  }
});
    test('tunnel down: refuses, and NEVER opens an upstream connection',
        () async {
      final gate = FakeGate(false); // tunnel is down
      final proxy = _proxy(
        gate: gate,
        credential: credential,
        connector: connector.call,
      );
      await proxy.start();

      final status = await _connectRequest(
        proxy.port,
        authorization: _basic(credential.token),
      );

      expect(status, contains('503'));
      expect(status, contains('Tunnel Not Connected'));

      // The part that actually matters. A 503 with a socket opened behind it
      // would still have leaked.
      expect(connector.attempts, isEmpty,
          reason: 'an upstream connection was attempted while the tunnel was '
              'down — this is the leak the whole feature must not have');
      expect(proxy.upstreamOpened, 0);
      expect(proxy.refusals[ProxyRefusal.tunnelDown], 1);

      await proxy.stop();
      await gate.dispose();
    });

    test('tunnel up: the same request is allowed through', () async {
      // The complement. A gate that refuses everything unconditionally would
      // pass the test above while being useless, so the open case is proven
      // too.
      final gate = FakeGate(true);
      final proxy = _proxy(
        gate: gate,
        credential: credential,
        connector: connector.call,
      );
      await proxy.start();

      final status = await _connectRequest(
        proxy.port,
        authorization: _basic(credential.token),
      );

      expect(status, contains('200'));
      expect(connector.attempts, <String>['192.0.2.1:443']);
      expect(proxy.upstreamOpened, 1);

      await proxy.stop();
      await gate.dispose();
    });

    test('a tunnel that drops mid-session tears down live connections',
        () async {
      final gate = FakeGate(true);
      final proxy = _proxy(
        gate: gate,
        credential: credential,
        connector: connector.call,
      );
      await proxy.start();

      final socket =
          await Socket.connect(InternetAddress.loopbackIPv4, proxy.port);
      socket.write(
        'CONNECT example.org:443 HTTP/1.1\r\n'
        'Proxy-Authorization: ${_basic(credential.token)}\r\n\r\n',
      );

      final closed = Completer<void>();
      socket.listen((_) {}, onError: (_) {
        if (!closed.isCompleted) closed.complete();
      }, onDone: () {
        if (!closed.isCompleted) closed.complete();
      });

      await Future<void>.delayed(const Duration(milliseconds: 300));
      expect(proxy.upstreamOpened, 1);

      // The tunnel drops. Established sockets must not keep running outside it.
      gate.set(false);

      await closed.future.timeout(
        const Duration(seconds: 5),
        onTimeout: () => fail('live connection survived the tunnel dropping'),
      );

      socket.destroy();
      await proxy.stop();
      await gate.dispose();
    });
  });

  group('plain-HTTP proxying is refused', () {
    test('a plain-HTTP target yields a refusal and never proxies upstream',
        () async {
      // The proxy is CONNECT-only. Even with the tunnel UP and a valid
      // credential, a plain-HTTP request head must be refused cleanly, and --
      // the strong form -- no upstream connection may be opened. A proxy that
      // answered a refusal while silently forwarding the request would still
      // have leaked it onto the naked interface, and nothing in the reply body
      // would say so.
      final gate = FakeGate(true);
      final proxy = _proxy(
        gate: gate,
        credential: credential,
        connector: connector.call,
      );
      await proxy.start();

      final status = await _plainRequest(
        proxy.port,
        authorization: _basic(credential.token),
      );

      expect(status, contains('501'));
      expect(status, contains('Not Implemented'));

      // The refusal is observable, not silent: a non-CONNECT head must be
      // counted as an unsupported proxy method, so the "never a raw HTTP
      // proxy" carve-out has a failure mode a test can actually see.
      expect(proxy.refusals[ProxyRefusal.unsupportedProxyMethod], 1);

      expect(connector.attempts, isEmpty,
          reason: 'a plain-HTTP request must not be transparently proxied '
              'to the upstream');
      expect(proxy.upstreamOpened, 0);

      await proxy.stop();
      await gate.dispose();
    });

    test('a plain-HTTP target is refused even with no authorization', () async {
      // Auth still comes first in `_handle`, so an unauthenticated plain-HTTP
      // request is a 407, not a 501. Either way it is a refusal from which no
      // upstream socket can follow; the point is that no method other than
      // CONNECT can ever reach `_connect`.
      final gate = FakeGate(true);
      final proxy = _proxy(
        gate: gate,
        credential: credential,
        connector: connector.call,
      );
      await proxy.start();

      final status = await _plainRequest(proxy.port);
      expect(status, contains('407'));
      expect(connector.attempts, isEmpty);
      expect(proxy.upstreamOpened, 0);

      await proxy.stop();
      await gate.dispose();
    });
  });

  group('caller authentication', () {
    test('no credential: 407, and no upstream connection', () async {
      final gate = FakeGate(true);
      final proxy = _proxy(
        gate: gate,
        credential: credential,
        connector: connector.call,
      );
      await proxy.start();

      final status = await _connectRequest(proxy.port);
      expect(status, contains('407'));
      expect(connector.attempts, isEmpty);
      expect(proxy.refusals[ProxyRefusal.unauthenticated], 1);

      await proxy.stop();
      await gate.dispose();
    });

    test('wrong token: 407', () async {
      final gate = FakeGate(true);
      final proxy = _proxy(
        gate: gate,
        credential: credential,
        connector: connector.call,
      );
      await proxy.start();

      final status = await _connectRequest(
        proxy.port,
        authorization: _basic('not-the-token'),
      );
      expect(status, contains('407'));
      expect(connector.attempts, isEmpty);

      await proxy.stop();
      await gate.dispose();
    });

    test('an unauthenticated caller learns nothing about tunnel state',
        () async {
      // Auth is checked before the gate deliberately: a local process that
      // cannot authenticate should not be able to use the proxy as an oracle
      // for whether the VPN is up.
      final down = FakeGate(false);
      final proxyDown = _proxy(
        gate: down,
        credential: credential,
        connector: connector.call,
      );
      await proxyDown.start();
      final whenDown = await _connectRequest(proxyDown.port);

      final up = FakeGate(true);
      final proxyUp = _proxy(
        gate: up,
        credential: credential,
        connector: connector.call,
      );
      await proxyUp.start();
      final whenUp = await _connectRequest(proxyUp.port);

      expect(whenDown, whenUp,
          reason: 'the unauthenticated response must not vary with tunnel '
              'state');

      await proxyDown.stop();
      await proxyUp.stop();
      await down.dispose();
      await up.dispose();
    });

    test('token comparison is length-safe and constant-time in shape', () {
      final c = ProxyCredential.generate();
      expect(c.matches(c.token), isTrue);
      expect(c.matches(''), isFalse);
      expect(c.matches('${c.token}x'), isFalse);
      expect(c.matches(c.token.substring(0, c.token.length - 1)), isFalse);
    });

    test('generated tokens are unique and long', () {
      final tokens = List<String>.generate(
        50,
        (_) => ProxyCredential.generate().token,
      );
      expect(tokens.toSet().length, 50);
      // 32 random bytes, base64url, padding stripped.
      expect(tokens.first.length, greaterThanOrEqualTo(42));
    });

    test('an expired credential is refused', () async {
      final expired = ProxyCredential.generate(ttl: Duration.zero);
      await Future<void>.delayed(const Duration(milliseconds: 5));
      expect(expired.isExpired, isTrue);

      final gate = FakeGate(true);
      final proxy = _proxy(
        gate: gate,
        credential: expired,
        connector: connector.call,
      );
      await proxy.start();

      final status = await _connectRequest(
        proxy.port,
        authorization: _basic(expired.token),
      );
      expect(status, contains('407'));
      expect(connector.attempts, isEmpty);

      await proxy.stop();
      await gate.dispose();
    });
  });

  group('the default gate', () {
    test('ClosedTunnelGate admits nothing', () {
      expect(ClosedTunnelGate().admitsTraffic, isFalse);
    });
  });

  group('connect target policy fixtures without network', () {
    test('the 407 realm contract is the exact adapter realm', () {
      expect(kBridgeProxyAuthScheme, 'basic');
      expect(kBridgeProxyAuthRealm, 'wins-bridge');
    });

    test('parseConnectAuthority keeps IPv6 bracketed hosts intact', () {
      expect(parseConnectAuthority('example.org:443'), ('example.org', 443));
      expect(parseConnectAuthority('[2001:db8::1]:443'), ('2001:db8::1', 443));
      expect(parseConnectAuthority('[::1]:443'), ('::1', 443));
      expect(parseConnectAuthority('[::ffff:127.0.0.1]:443'),
          ('::ffff:127.0.0.1', 443));
      expect(parseConnectAuthority('2001:db8::1:443'), isNull);
    });

    test('forbidden host literals include unix sockets and metadata names', () {
      expect(isForbiddenConnectHost('/tmp/docker.sock'), isTrue);
      expect(isForbiddenConnectHost('unix:/tmp/docker.sock'), isTrue);
      expect(isForbiddenConnectHost(r'\\.\pipe\docker'), isTrue);
      expect(isForbiddenConnectHost('fe80::1%eth0'), isTrue);
      expect(isForbiddenConnectHost('metadata.google.internal'), isTrue);
      expect(isForbiddenConnectHost('example.org'), isFalse);
      expect(isForbiddenConnectHost('192.0.2.1'), isFalse);
    });

    test('loopback, private, link-local, multicast, unspecified, metadata', () {
      const List<String> forbidden = <String>[
        '127.0.0.1',
        '127.255.255.254',
        '::1',
        '0.0.0.0',
        '::',
        '10.0.0.1',
        '172.16.0.1',
        '192.168.1.1',
        '169.254.1.1',
        '169.254.169.254',
        '100.64.0.1',
        '224.0.0.1',
        '240.0.0.1',
        '255.255.255.255',
        'fe80::1',
        'ff02::1',
        'fc00::1',
        'fd00:ec2::254',
        '::ffff:127.0.0.1',
        '::ffff:10.0.0.1',
        '::ffff:169.254.169.254',
        '::ffff:c0a8:1',
        '64:ff9b::7f00:1',
        '2002:7f00:1::1',
      ];
      for (final String raw in forbidden) {
        final InternetAddress? address = InternetAddress.tryParse(raw);
        expect(address, isNotNull, reason: 'unparseable fixture $raw');
        expect(isForbiddenConnectAddress(address!), isTrue,
            reason: '$raw must be a forbidden CONNECT target');
      }
    });

    test('valid public destinations remain admitted', () {
      const List<String> allowed = <String>[
        '192.0.2.1',
        '198.51.100.1',
        '203.0.113.1',
        '2001:db8::1',
        '::ffff:192.0.2.1',
        '::ffff:c000:201',
      ];
      for (final String raw in allowed) {
        final InternetAddress? address = InternetAddress.tryParse(raw);
        expect(address, isNotNull, reason: 'unparseable fixture $raw');
        expect(isForbiddenConnectAddress(address!), isFalse,
            reason: '$raw must remain a legitimate public CONNECT target');
      }
    });

    test('unix-typed addresses are forbidden without resolving', () {
      final InternetAddress unix = InternetAddress(
        '/tmp/docker.sock',
        type: InternetAddressType.unix,
      );
      expect(isForbiddenConnectAddress(unix), isTrue);
    });

    test('DNS rebinding answers are refused as a whole', () async {
      final List<InternetAddress>? mixed = await admitConnectTarget(
        'rebind.example.org',
        resolver: (String host) async {
          expect(host, 'rebind.example.org');
          return <InternetAddress>[
            InternetAddress('192.0.2.1'),
            InternetAddress.loopbackIPv4,
          ];
        },
      );
      expect(mixed, isNull);

      final List<InternetAddress>? rebound = await admitConnectTarget(
        'rebind.example.org',
        resolver: (String host) async =>
            <InternetAddress>[InternetAddress.loopbackIPv4],
      );
      expect(rebound, isNull);
    });

    test('a name that resolves only to a public fixture is admitted', () async {
      final List<InternetAddress>? admitted = await admitConnectTarget(
        'example.org',
        resolver: (String host) async {
          expect(host, 'example.org');
          return <InternetAddress>[InternetAddress('198.51.100.1')];
        },
      );
      expect(admitted, isNotNull);
      expect(admitted, hasLength(1));
      expect(admitted!.first.address, '198.51.100.1');
    });
  });

  group('loopback CONNECT and DNS rebinding reproductions', () {
    Future<void> expectForbidden({
      required String authority,
      ConnectTargetResolver? resolver,
    }) async {
      final FakeGate gate = FakeGate(true);
      final BridgeProxyServer proxy = _proxy(
        gate: gate,
        credential: credential,
        connector: connector.call,
        resolver: resolver,
      );
      await proxy.start();
      final String status = await _connectRequest(
        proxy.port,
        authorization: _basic(credential.token),
        authority: authority,
      );
      expect(status, contains('403'));
      expect(status, contains('Forbidden'));
      expect(connector.attempts, isEmpty,
          reason: 'a forbidden CONNECT target must never reach upstream');
      expect(proxy.upstreamOpened, 0);
      expect(proxy.refusals[ProxyRefusal.forbiddenTarget], 1);
      await proxy.stop();
      await gate.dispose();
    }

    test('CONNECT 127.0.0.1 is refused and never opens upstream', () async {
      await expectForbidden(authority: '127.0.0.1:443');
    });

    test('unauthenticated loopback CONNECT is 407, not a destination oracle',
        () async {
      final FakeGate gate = FakeGate(true);
      final BridgeProxyServer proxy = _proxy(
        gate: gate,
        credential: credential,
        connector: connector.call,
      );
      await proxy.start();
      final String status = await _connectRequest(
        proxy.port,
        authority: '127.0.0.1:443',
      );
      expect(status, contains('407'));
      expect(connector.attempts, isEmpty);
      expect(proxy.refusals[ProxyRefusal.forbiddenTarget], isNull);
      expect(proxy.refusals[ProxyRefusal.unauthenticated], 1);
      await proxy.stop();
      await gate.dispose();
    });

    test('CONNECT ::1 is refused', () async {
      await expectForbidden(authority: '[::1]:443');
    });

    test('CONNECT IPv4-mapped loopback is refused', () async {
      await expectForbidden(authority: '[::ffff:127.0.0.1]:443');
    });

    test('CONNECT metadata-service link-local is refused', () async {
      await expectForbidden(authority: '169.254.169.254:80');
    });

    test('CONNECT unix socket path is refused', () async {
      await expectForbidden(authority: '/tmp/docker.sock:80');
    });

    test('CONNECT private, link-local, multicast, unspecified', () async {
      for (final String authority in <String>[
        '10.1.2.3:443',
        '172.16.9.1:443',
        '192.168.0.4:443',
        '169.254.1.1:443',
        '100.64.0.1:443',
        '224.0.0.1:443',
        '0.0.0.0:443',
        '[fe80::1]:443',
        '[ff02::1]:443',
        '[fc00::1]:443',
        '[::]:443',
      ]) {
        connector.attempts.clear();
        await expectForbidden(authority: authority);
      }
    });

    test('DNS rebinding to loopback is refused without upstream', () async {
      await expectForbidden(
        authority: 'rebind.example.org:443',
        resolver: (String host) async {
          expect(host, 'rebind.example.org');
          return <InternetAddress>[InternetAddress.loopbackIPv4];
        },
      );
    });

    test('mixed public plus loopback DNS answers are refused', () async {
      await expectForbidden(
        authority: 'rebind.example.org:443',
        resolver: (String host) async => <InternetAddress>[
          InternetAddress('192.0.2.1'),
          InternetAddress.loopbackIPv4,
        ],
      );
    });

    test('IPv4-mapped rebinding is refused', () async {
      await expectForbidden(
        authority: 'rebind.example.org:443',
        resolver: (String host) async => <InternetAddress>[
          InternetAddress('::ffff:127.0.0.1'),
        ],
      );
    });

    test('a valid public name is admitted without network', () async {
      final FakeGate gate = FakeGate(true);
      final BridgeProxyServer proxy = _proxy(
        gate: gate,
        credential: credential,
        connector: connector.call,
        resolver: (String host) async {
          expect(host, 'example.org');
          return <InternetAddress>[InternetAddress('198.51.100.1')];
        },
      );
      await proxy.start();
      final String status = await _connectRequest(
        proxy.port,
        authorization: _basic(credential.token),
      );
      expect(status, contains('200'));
      expect(connector.attempts, <String>['198.51.100.1:443']);
      expect(proxy.upstreamOpened, 1);
      expect(proxy.refusals[ProxyRefusal.forbiddenTarget], isNull);
      await proxy.stop();
      await gate.dispose();
    });

    test('a valid public IPv4 literal is admitted', () async {
      final FakeGate gate = FakeGate(true);
      final BridgeProxyServer proxy = _proxy(
        gate: gate,
        credential: credential,
        connector: connector.call,
      );
      await proxy.start();
      final String status = await _connectRequest(
        proxy.port,
        authorization: _basic(credential.token),
        authority: '203.0.113.1:443',
      );
      expect(status, contains('200'));
      expect(connector.attempts, <String>['203.0.113.1:443']);
      await proxy.stop();
      await gate.dispose();
    });

    test('IPv4-mapped public destinations stay admitted', () async {
      final FakeGate gate = FakeGate(true);
      final BridgeProxyServer proxy = _proxy(
        gate: gate,
        credential: credential,
        connector: connector.call,
      );
      await proxy.start();
      final String status = await _connectRequest(
        proxy.port,
        authorization: _basic(credential.token),
        authority: '[::ffff:192.0.2.1]:443',
      );
      expect(status, contains('200'));
      expect(connector.attempts, <String>['192.0.2.1:443']);
      await proxy.stop();
      await gate.dispose();
    });
  });

  test('an upstream that resets mid-relay does not raise an unhandled error',
      () async {
    // FOUND BY RUNNING THE REAL COMPILED HOST UNDER A REAL FIREFOX, and not
    // findable any other way this tree had: every previous run of this proxy
    // was against a stand-in upstream that closed politely.
    //
    // `Socket` is an `IOSink`. An error raised while flushing bytes queued by
    // `add` is delivered to `done`, and to nothing else -- the read
    // subscription's `onError` never sees it. With nothing awaiting `done`
    // the error escaped as an unhandled asynchronous exception, which in a
    // `dart compile exe` binary terminates the process. Observed in the
    // host's own stderr as:
    //
    //   Unhandled exception:
    //   SocketException: Connection reset by peer ... address = <site>
    //
    // The browser relaunched the host and the extension reconnected, so it
    // failed closed -- and a proxy that dies whenever a site hangs up
    // mid-response is still a defect. This test fails on the unhandled error
    // itself: flutter_test routes an uncaught async error in the test zone
    // to the test, so removing the `done.catchError` guards in
    // `browser_bridge_proxy.dart` turns this red.
    final ServerSocket resetter =
        await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    resetter.listen((Socket peer) {
      // Accept and hang up hard, which is what the far end does when it goes
      // away underneath an established tunnel.
      peer.destroy();
    });

    final FakeGate gate = FakeGate(true);
    final BridgeProxyServer proxy = _proxy(
      gate: gate,
      credential: credential,
      connector: (String host, int port) =>
          Socket.connect(InternetAddress.loopbackIPv4, resetter.port),
    );
    await proxy.start();

    final Socket client =
        await Socket.connect(InternetAddress.loopbackIPv4, proxy.port);
    client.listen((_) {}, onError: (_) {}, onDone: () {});
    // The TEST's own socket needs the same guard, for the same reason and on
    // the same write path -- the proxy tears this connection down once the
    // relay collapses. Guarded here so that the only unguarded sink left in
    // the run is the one inside the proxy, which is what is under test.
    unawaited(client.done.catchError((Object _) => client));

    // PIPELINED, in the same write as the head. `_handle` has a branch for
    // exactly this ("a browser normally waits for the 200, but nothing
    // guarantees it"), and it is the branch that writes to the upstream
    // socket BEFORE the read subscription has had a chance to notice the far
    // end is gone. That ordering is what makes this deterministic rather than
    // a race: without it the read side tears the relay down first and the
    // write never happens.
    client.write('CONNECT example.org:443 HTTP/1.1\r\n'
        'Host: example.org:443\r\n'
        'Proxy-Authorization: ${_basic(credential.token)}\r\n\r\n');
    client.add(List<int>.filled(32768, 0x16));
    await Future<void>.delayed(const Duration(milliseconds: 900));

    expect(proxy.upstreamOpened, 1,
        reason: 'the relay must have been established before the reset, or '
            'this test is measuring the refusal path instead');

    client.destroy();
    await proxy.stop();
    await gate.dispose();
    await resetter.close();
  });

  test('gate closure during resolution never invokes connector', () async {
    final gate = FakeGate(true);
    final entered = Completer<void>();
    final resolved = Completer<List<InternetAddress>>();
    final proxy = _proxy(
      gate: gate,
      credential: credential,
      connector: connector.call,
      resolver: (String _) {
        entered.complete();
        return resolved.future;
      },
    );
    await proxy.start();
    try {
      final request = _connectRequestUntilClosed(
        proxy.port,
        authorization: _basic(credential.token),
      );
      await entered.future.timeout(const Duration(seconds: 5));
      gate.set(false);
      resolved.complete(<InternetAddress>[kPublicConnectFixture]);
      // The gate closing drops every live client, including one whose name is
      // still resolving (705bedd; the reviewed form of this assertion is
      // impl-review-20261006/fix_integ HELD-4): closed, with no reply.
      final outcome = await request;
      expect(outcome.closed, isTrue,
          reason: 'the proxy must close the client socket, not leave it open');
      expect(outcome.received, isEmpty,
          reason: 'a dropped request gets no reply');
      expect(connector.attempts, isEmpty);
      expect(proxy.upstreamOpened, 0);
    } finally {
      await proxy.stop();
      await gate.dispose();
    }
  });

  test('a first address that fails is followed by the next, in resolver order',
      () async {
    final gate = FakeGate(true);
    final tried = <String>[];
    final proxy = _proxy(
      gate: gate,
      credential: credential,
      resolver: (_) async => <InternetAddress>[
        InternetAddress('192.0.2.1'),
        InternetAddress('192.0.2.2'),
      ],
      connector: (host, port) async {
        tried.add(host);
        if (host == '192.0.2.1') throw const SocketException('first refused');
        return Socket.connect(InternetAddress.loopbackIPv4, upstream.port);
      },
    );
    await proxy.start();
    try {
      expect(await _connectRequest(proxy.port,
          authorization: _basic(credential.token)), contains('200'));
      expect(tried, <String>['192.0.2.1', '192.0.2.2']);
    } finally {
      await proxy.stop();
      await gate.dispose();
    }
  });

  test('an address that answers after one lost SYN (about 1.2 s) still connects',
      () async {
    final gate = FakeGate(true);
    final proxy = _proxy(
      gate: gate,
      credential: credential,
      connector: (_, __) async {
        await Future<void>.delayed(const Duration(milliseconds: 1200));
        return Socket.connect(InternetAddress.loopbackIPv4, upstream.port);
      },
    );
    await proxy.start();
    try {
      expect(await _connectRequest(proxy.port,
          authorization: _basic(credential.token)), contains('200'));
    } finally {
      await proxy.stop();
      await gate.dispose();
    }
  });

  group('bridgeAttemptBudget', () {
    test('a fresh budget gives one full address timeout', () {
      expect(bridgeAttemptBudget(Duration.zero), kBridgeAddressTimeout);
    });

    test('the last attempt gets exactly what is left of the connect budget', () {
      final Duration elapsed = kBridgeConnectBudget - const Duration(seconds: 2);
      expect(bridgeAttemptBudget(elapsed), const Duration(seconds: 2));
    });

    test('a sliver of budget never starts an attempt', () {
      // Two full-length attempts end a hair before the stopwatch reaches the
      // budget (millisecond timers against a microsecond clock). The old code
      // treated that remainder as a third attempt.
      expect(bridgeAttemptBudget(kBridgeConnectBudget), isNull);
      expect(bridgeAttemptBudget(kBridgeConnectBudget + const Duration(seconds: 1)), isNull);
      for (final int microseconds in <int>[1, 10, 999, 1000, 20000, 49999]) {
        expect(
          bridgeAttemptBudget(
            kBridgeConnectBudget - Duration(microseconds: microseconds),
          ),
          isNull,
          reason: '$microseconds us left',
        );
      }
      expect(
        bridgeAttemptBudget(kBridgeConnectBudget - kBridgeMinimumAttemptBudget),
        kBridgeMinimumAttemptBudget,
      );
    });

    test('two full attempts exhaust the budget', () {
      var elapsed = Duration.zero;
      var attempts = 0;
      for (;;) {
        final Duration? budget = bridgeAttemptBudget(elapsed);
        if (budget == null) break;
        attempts++;
        // A black-holed address takes its whole budget, plus up to a
        // millisecond of timer rounding in the budget's favour.
        elapsed += budget - const Duration(microseconds: 700);
      }
      expect(attempts, 2);
    });
  });

  test('all addresses black-holed: 502 within the connect budget, late sockets destroyed',
      () async {
    final sink = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    var accepted = 0;
    var closed = 0;
    final sinkSubscription = sink.listen((socket) {
      accepted += 1;
      socket.listen((_) {}, onDone: () {
        closed += 1;
        socket.destroy();
      }, onError: (_) {});
    });
    final gate = FakeGate(true);
    var calls = 0;
    final proxy = _proxy(
      gate: gate,
      credential: credential,
      resolver: (_) async => List<InternetAddress>.generate(
          4, (index) => InternetAddress('192.0.2.${index + 1}')),
      connector: (_, __) async {
        calls += 1;
        await Future<void>.delayed(const Duration(seconds: 4));
        return Socket.connect(InternetAddress.loopbackIPv4, sink.port);
      },
    );
    await proxy.start();
    final client = await Socket.connect(InternetAddress.loopbackIPv4, proxy.port);
    try {
      final watch = Stopwatch()..start();
      client.write('CONNECT example.org:443 HTTP/1.1\r\n'
          'Host: example.org\r\n'
          'Proxy-Authorization: ${_basic(credential.token)}\r\n\r\n');
      final head = await client.cast<List<int>>().transform(utf8.decoder)
          .take(1).join().timeout(const Duration(seconds: 10));
      watch.stop();
      expect(head, startsWith('HTTP/1.1 502'));
      expect(watch.elapsedMilliseconds, lessThan(6800));
      expect(calls, 2);
      await Future<void>.delayed(const Duration(seconds: 3));
      expect(accepted, 2);
      expect(closed, 2);
      expect(proxy.upstreamOpened, 0);
    } finally {
      client.destroy();
      await proxy.stop();
      await gate.dispose();
      await sinkSubscription.cancel();
      await sink.close();
    }
  });
}
