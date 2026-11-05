// The loopback HTTP proxy that the browser extension points at.
//
// No Flutter import: compiled into `bin/wins_bridge_host.dart`.
//
// ---------------------------------------------------------------------------
// WHY HTTP CONNECT AND NOT SOCKS5
// ---------------------------------------------------------------------------
//
// The brief allowed either. HTTP wins on one decisive practical point:
// **a browser extension can authenticate to an HTTP proxy and cannot
// authenticate to a SOCKS5 one.**
//
//  * Chrome and Edge: `chrome.proxy` carries no credential field, but a 407
//    challenge can be answered programmatically from
//    `chrome.webRequest.onAuthRequired`. That is the only way an extension can
//    present a secret to its own proxy.
//  * Firefox: `browser.proxy.onRequest` can return `proxyAuthorizationHeader`
//    directly, which is cleaner still.
//  * SOCKS5 username/password (RFC 1929) has no extension-facing API on any of
//    the three. A SOCKS5 proxy on loopback would therefore have to be
//    unauthenticated -- which is the GX10 ollama mistake reproduced one layer
//    in, and is precisely what this design must not do.
//
// ---------------------------------------------------------------------------
// WHY THE PORT IS EPHEMERAL
// ---------------------------------------------------------------------------
//
// The listener binds port 0 and reports the kernel-assigned port to the
// extension over native messaging. Three reasons: nothing to guess ahead of
// time; no collision with the Xray inbound that occupies 127.0.0.1:42110
// whenever stealth transport is active; and the port's lifetime matches the
// token's, so both die with the browser session.
//
// One plaintext loopback listener ships. Browser authentication is handled by
// the browser adapters, and no certificate, trust-store mutation, or second
// TLS port exists in this host. This keeps the frozen native-host source aligned
// with the 2026-08-07 single-listener ruling.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

/// Decides whether traffic may leave right now.
///
/// The whole fail-closed property rests on this being consulted before any
/// upstream socket is created, and on the default answer being "no".
abstract class TunnelGate {
  /// True only when the desktop app's tunnel is proven to be carrying traffic.
  ///
  /// Must be conservative: anything the host cannot establish is a `false`.
  bool get admitsTraffic;

  /// Fires whenever [admitsTraffic] transitions. The proxy uses it to tear
  /// down connections that were opened while the gate was open, because a
  /// tunnel that drops mid-stream would otherwise leave established sockets
  /// quietly running outside it.
  Stream<bool> get changes;
}

/// A gate that never admits anything.
///
/// This is the default the host runs with, and it is the honest state on any
/// build where the desktop app's tunnel state is not observable. Refusing
/// everything is the correct behaviour for a bridge that cannot prove a
/// tunnel: the alternative is passing browser traffic untunnelled while the
/// extension's UI says it is protected.
class ClosedTunnelGate implements TunnelGate {
  @override
  bool get admitsTraffic => false;

  @override
  Stream<bool> get changes => const Stream<bool>.empty();
}

/// A short-lived bearer token for the proxy.
///
/// Held in memory only, on both sides. The extension lane keeps it in a
/// service-worker variable and never in `storage`, on the assumption that a
/// seized device's browser profile is readable; a token that had to survive a
/// browser restart would force it to persist one and undo that. So this token
/// is generated per native-messaging session, dies when the host process exits
/// (i.e. when the browser disconnects the port), and additionally expires on
/// [ttl] so that a long-lived browser session still rotates.
class ProxyCredential {
  ProxyCredential._(this.token, this.expiresAt);

  factory ProxyCredential.generate({
    Duration ttl = const Duration(hours: 8),
    Random? random,
  }) {
    final rng = random ?? Random.secure();
    final bytes = Uint8List(32);
    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = rng.nextInt(256);
    }
    return ProxyCredential._(
      base64Url.encode(bytes).replaceAll('=', ''),
      DateTime.now().toUtc().add(ttl),
    );
  }

  /// The secret. Never logged, never written to disk, never placed in a
  /// message body other than the one `issue_proxy_credential` reply.
  final String token;

  final DateTime expiresAt;

  bool get isExpired => DateTime.now().toUtc().isAfter(expiresAt);

  /// Constant-time comparison. The timing signal on a loopback port is small
  /// but the fix is three lines, so there is no reason to leave it.
  bool matches(String candidate) {
    final a = utf8.encode(token);
    final b = utf8.encode(candidate);
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }
}

/// Why a request was refused. Surfaced in counters so the handoff can show
/// fail-closed actually firing, without logging any destination.
enum ProxyRefusal {
  unauthenticated,
  tunnelDown,
  malformed,

  /// A non-CONNECT (plain-HTTP) request head. The proxy is CONNECT-only by
  /// design and must never forward a raw HTTP request upstream; this is the
  /// count for that refusal so the "never a raw HTTP proxy" carve-out is
  /// observable, not just silently refused.
  unsupportedProxyMethod,

  /// CONNECT named a loopback, link-local, private, multicast, unspecified,
  /// metadata-service, Unix-socket, or other local-network target. Checked
  /// after DNS resolution so a public-looking name that rebinds to a local
  /// address is refused the same way a literal is.
  forbiddenTarget,
}

/// Auth scheme the browser adapters must match exactly on a 407 challenger.
const String kBridgeProxyAuthScheme = 'basic';

/// Realm the desktop proxy advertises and the adapters must match exactly.
const String kBridgeProxyAuthRealm = 'wins-bridge';

/// Opens an upstream connection. Injectable so tests can assert that a refused
/// request never reaches it at all. The host argument is a validated IP
/// literal, never the original CONNECT name, so a later lookup cannot rebind.
typedef UpstreamConnector = Future<Socket> Function(String host, int port);

/// Resolves a CONNECT host. Injectable so tests can reproduce DNS rebinding
/// without putting a packet on the Internet.
typedef ConnectTargetResolver = Future<List<InternetAddress>> Function(
    String host);

/// Budget for one upstream address. It covers one lost SYN (the initial
/// retransmission timeout is 1 s, RFC 6298 section 2.1) plus a round trip of
/// up to about 2 s, so a single dropped packet does not fail a working site.
const Duration kBridgeAddressTimeout = Duration(seconds: 3);

/// Budget for every upstream attempt of one CONNECT together, so a name whose
/// addresses are all black-holed fails in bounded time.
const Duration kBridgeConnectBudget = Duration(seconds: 6);

/// Budget for resolving the CONNECT name. One lost DNS datagram costs the
/// system resolver a 1 s or longer retry, so a tighter bound would turn a
/// single loss into a refused site.
const Duration kBridgeResolveTimeout = Duration(seconds: 5);

/// At most this many resolved addresses are tried, in resolver order.
const int kBridgeMaxAddressAttempts = 4;

/// An attempt is not started with less than this much of the connect budget
/// left. Timers have millisecond granularity and the budget is read from a
/// microsecond stopwatch, so after two full-length attempts a sliver of the
/// budget can remain (a timer may fire a fraction of a millisecond before the
/// stopwatch reaches the budget). Starting a third attempt on that sliver cannot
/// succeed and made the attempt count, and so the bounded failure, depend on
/// scheduler jitter.
const Duration kBridgeMinimumAttemptBudget = Duration(milliseconds: 50);

/// The time limit for the next upstream attempt after [elapsed] of the connect
/// budget has been spent, or null when no further attempt may start.
Duration? bridgeAttemptBudget(Duration elapsed) {
  final Duration remaining = kBridgeConnectBudget - elapsed;
  if (remaining < kBridgeMinimumAttemptBudget) return null;
  return remaining < kBridgeAddressTimeout ? remaining : kBridgeAddressTimeout;
}

Future<Socket> _defaultUpstreamConnector(String host, int port) async {
  final Socket socket =
      await Socket.connect(host, port, timeout: kBridgeAddressTimeout);
  // Relayed TLS records are small and latency-bound; Nagle on the tunnel-side
  // socket can hold a record for a round trip. Benefit not measured here.
  try {
    socket.setOption(SocketOption.tcpNoDelay, true);
  } catch (_) {}
  return socket;
}

/// One bounded attempt through any connector, including an injected one. A
/// socket that completes after its deadline is destroyed, never used.
Future<Socket> _boundedUpstreamConnect(
  UpstreamConnector connector,
  String host,
  int port,
  Duration limit,
) {
  var expired = false;
  final Future<Socket> guarded = connector(host, port).then((Socket socket) {
    if (expired) {
      socket.destroy();
      throw TimeoutException('upstream connection completed after deadline');
    }
    return socket;
  });
  return guarded.timeout(
    limit,
    onTimeout: () {
      expired = true;
      throw TimeoutException('upstream connection deadline');
    },
  );
}

Future<List<InternetAddress>> lookupConnectTarget(String host) async {
  final String unbracketed = unbracketConnectHost(host);
  if (unbracketed.isEmpty) return const <InternetAddress>[];
  final InternetAddress? literal = InternetAddress.tryParse(unbracketed);
  if (literal != null) return <InternetAddress>[literal];
  return InternetAddress.lookup(unbracketed);
}

/// Strip CONNECT IPv6 brackets. `[::1]` becomes `::1`; other hosts are unchanged.
String unbracketConnectHost(String host) {
  if (host.length >= 2 && host.startsWith('[') && host.endsWith(']')) {
    return host.substring(1, host.length - 1);
  }
  return host;
}

/// `host:port` from a CONNECT request-target. IPv6 must be bracketed.
(String, int)? parseConnectAuthority(String authority) {
  if (authority.isEmpty) return null;
  late final String host;
  late final String portText;
  if (authority.startsWith('[')) {
    final int close = authority.indexOf(']:');
    if (close <= 1) return null;
    host = authority.substring(1, close);
    portText = authority.substring(close + 2);
  } else {
    final int colon = authority.lastIndexOf(':');
    if (colon <= 0 || colon == authority.length - 1) return null;
    host = authority.substring(0, colon);
    portText = authority.substring(colon + 1);
    // Unbracketed IPv6 is not a legal CONNECT authority; refusing it keeps
    // `host:port` from being taken from the last group of a v6 literal.
    if (host.contains(':')) return null;
  }
  if (host.isEmpty) return null;
  for (var i = 0; i < host.length; i++) {
    final int code = host.codeUnitAt(i);
    if (code <= 0x20 || code == 0x7F) return null;
  }
  final int? port = int.tryParse(portText);
  if (port == null || port < 1 || port > 65535) return null;
  return (host, port);
}

/// Unix-socket paths, zone IDs, and other names that must never be resolved.
bool isForbiddenConnectHost(String host) {
  final String h = unbracketConnectHost(host);
  if (h.isEmpty) return true;
  final String lower = h.toLowerCase();
  if (lower.contains('/') || lower.contains('\\')) return true;
  if (lower.contains('\u0000')) return true;
  if (lower.contains('%')) return true;
  if (lower.startsWith('unix:')) return true;
  if (lower.startsWith('@')) return true;
  if (lower == 'metadata' ||
      lower == 'metadata.google.internal' ||
      lower.startsWith('metadata.')) {
    return true;
  }
  return false;
}

/// Unwrap IPv4-mapped, IPv4-compatible, NAT64, and 6to4 forms so a local
/// IPv4 cannot hide inside an IPv6 literal.
InternetAddress canonicalConnectAddress(InternetAddress address) {
  if (address.type == InternetAddressType.unix) return address;
  final Uint8List bytes = address.rawAddress;
  if (address.type != InternetAddressType.IPv6 || bytes.length != 16) {
    return address;
  }
  if (_isIpv4Mapped(bytes) || _isIpv4Compatible(bytes) || _isNat64(bytes)) {
    return InternetAddress.fromRawAddress(
      Uint8List.fromList(bytes.sublist(12)),
    );
  }
  if (_is6to4(bytes)) {
    return InternetAddress.fromRawAddress(
      Uint8List.fromList(bytes.sublist(2, 6)),
    );
  }
  return address;
}

bool isForbiddenConnectAddress(InternetAddress address) {
  if (address.type == InternetAddressType.unix) return true;
  final InternetAddress canonical = canonicalConnectAddress(address);
  final Uint8List bytes = canonical.rawAddress;
  if (canonical.type == InternetAddressType.IPv4 && bytes.length == 4) {
    return _isForbiddenIpv4(bytes);
  }
  if (canonical.type == InternetAddressType.IPv6 && bytes.length == 16) {
    return _isForbiddenIpv6(bytes);
  }
  return true;
}

/// null = forbidden (403). Empty = resolution produced nothing (502).
Future<List<InternetAddress>?> admitConnectTarget(
  String host, {
  required ConnectTargetResolver resolver,
}) async {
  if (isForbiddenConnectHost(host)) return null;
  late final List<InternetAddress> resolved;
  try {
    resolved = await resolver(host);
  } catch (_) {
    return const <InternetAddress>[];
  }
  if (resolved.isEmpty) return const <InternetAddress>[];
  final List<InternetAddress> admitted = <InternetAddress>[];
  for (final InternetAddress address in resolved) {
    if (isForbiddenConnectAddress(address)) return null;
    admitted.add(canonicalConnectAddress(address));
  }
  return admitted;
}

bool _isIpv4Mapped(Uint8List bytes) {
  for (var i = 0; i < 10; i++) {
    if (bytes[i] != 0) return false;
  }
  return bytes[10] == 0xFF && bytes[11] == 0xFF;
}

bool _isIpv4Compatible(Uint8List bytes) {
  for (var i = 0; i < 12; i++) {
    if (bytes[i] != 0) return false;
  }
  final bool unspecified =
      bytes[12] == 0 && bytes[13] == 0 && bytes[14] == 0 && bytes[15] == 0;
  final bool loopback =
      bytes[12] == 0 && bytes[13] == 0 && bytes[14] == 0 && bytes[15] == 1;
  return !unspecified && !loopback;
}

bool _isNat64(Uint8List bytes) {
  return bytes[0] == 0x00 &&
      bytes[1] == 0x64 &&
      bytes[2] == 0xFF &&
      bytes[3] == 0x9B &&
      bytes[4] == 0 &&
      bytes[5] == 0 &&
      bytes[6] == 0 &&
      bytes[7] == 0 &&
      bytes[8] == 0 &&
      bytes[9] == 0 &&
      bytes[10] == 0 &&
      bytes[11] == 0;
}

bool _is6to4(Uint8List bytes) => bytes[0] == 0x20 && bytes[1] == 0x02;

bool _isForbiddenIpv4(Uint8List o) {
  final int a = o[0];
  final int b = o[1];
  final int c = o[2];
  if (a == 0) return true;
  if (a == 10) return true;
  if (a == 100 && b >= 64 && b <= 127) return true;
  if (a == 127) return true;
  if (a == 169 && b == 254) return true;
  if (a == 172 && b >= 16 && b <= 31) return true;
  if (a == 192 && b == 0 && c == 0) return true;
  if (a == 192 && b == 88 && c == 99) return true;
  if (a == 192 && b == 168) return true;
  if (a == 198 && (b == 18 || b == 19)) return true;
  if (a >= 224) return true;
  return false;
}

bool _isForbiddenIpv6(Uint8List b) {
  var allZero = true;
  for (final int x in b) {
    if (x != 0) {
      allZero = false;
      break;
    }
  }
  if (allZero) return true;
  var loop = true;
  for (var i = 0; i < 15; i++) {
    if (b[i] != 0) {
      loop = false;
      break;
    }
  }
  if (loop && b[15] == 1) return true;
  if (b[0] == 0xFF) return true;
  if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return true;
  if (b[0] == 0xFE && (b[1] & 0xC0) == 0xC0) return true;
  if ((b[0] & 0xFE) == 0xFC) return true;
  if (b[0] == 0x01 && b[1] == 0x00) {
    var discard = true;
    for (var i = 2; i < 8; i++) {
      if (b[i] != 0) {
        discard = false;
        break;
      }
    }
    if (discard) return true;
  }
  return false;
}

/// A loopback-only HTTP proxy that fails closed.
class BridgeProxyServer {
  BridgeProxyServer({
    required this.gate,
    required this.credential,
    UpstreamConnector? connector,
    ConnectTargetResolver? resolver,
  })  : _connect = connector ?? _defaultUpstreamConnector,
        _resolve = resolver ?? lookupConnectTarget;

  final TunnelGate gate;
  final ProxyCredential credential;
  final UpstreamConnector _connect;
  final ConnectTargetResolver _resolve;

  ServerSocket? _server;
  int _generation = 0;

  bool _admits(int generation) =>
      _server != null &&
      generation == _generation &&
      gate.admitsTraffic;
  Future<void>? _startInFlight;
  StreamSubscription<bool>? _gateWatch;
  final Set<Socket> _live = <Socket>{};
  final Map<ProxyRefusal, int> refusals = <ProxyRefusal, int>{};

  /// Number of times an upstream connection was actually opened. A test asserts
  /// this stays at zero while the gate is closed.
  int upstreamOpened = 0;

  int get port => _server?.port ?? 0;
  bool get isListening => _server != null;

  /// Bind loopback only.
  ///
  /// `InternetAddress.loopbackIPv4` is not a default that could drift: there is
  /// no configuration path to any other address in this class, so the proxy
  /// cannot be widened to `0.0.0.0` by a settings change. Anything on the LAN
  /// using this tunnel is the failure mode being designed out.
  Future<void> start() {
    if (_server != null) return Future<void>.value();
    final pending = _startInFlight;
    if (pending != null) return pending;

    final generation = ++_generation;
    late final Future<void> started;
    started = (() async {
      final server = await ServerSocket.bind(
        InternetAddress.loopbackIPv4,
        0,
      );
      if (generation != _generation) {
        await server.close();
        return;
      }

      _server = server;
      server.listen(
        (client) {
          if (!identical(_server, server)) {
            client.destroy();
            return;
          }
          unawaited(_handle(client, _generation));
        },
        onError: (_) {},
      );
      _gateWatch = gate.changes.listen((open) {
        if (identical(_server, server) && !open) {
          _generation++;
          _dropAllLive();
        }
      });
    })().whenComplete(() {
      if (identical(_startInFlight, started)) {
        _startInFlight = null;
      }
    });
    _startInFlight = started;
    return started;
  }

  Future<void> stop() async {
    _generation++;
    final starting = _startInFlight;
    _startInFlight = null;
    final server = _server;
    _server = null;
    final gateWatch = _gateWatch;
    _gateWatch = null;

    _dropAllLive();
    await gateWatch?.cancel();
    await server?.close();
    if (starting != null) {
      try {
        await starting;
      } catch (_) {}
    }
  }

  void _dropAllLive() {
    for (final socket in _live.toList()) {
      try {
        socket.destroy();
      } catch (_) {}
    }
    _live.clear();
  }

  void _count(ProxyRefusal refusal) {
    refusals[refusal] = (refusals[refusal] ?? 0) + 1;
  }

  Future<void> _handle(Socket client, int generation) async {
    _live.add(client);
    // A Socket is a single-subscription stream: whoever listens first owns it.
    // So the request head is read through a subscription that is then PAUSED
    // and reused for the relay, rather than by awaiting `client.first` and
    // trying to listen again afterwards -- which throws "Stream has already
    // been listened to" the moment a request is actually allowed through.
    final buffer = BytesBuilder(copy: false);
    final headRead = Completer<List<int>>();
    late final StreamSubscription<Uint8List> subscription;

    subscription = client.listen(
      (Uint8List data) {
        if (headRead.isCompleted) return;
        buffer.add(data);
        final bytes = buffer.toBytes();
        if (_headerEnd(bytes) >= 0) {
          headRead.complete(bytes);
        } else if (bytes.length > 64 * 1024) {
          // A request head this large is not a browser.
          headRead
              .completeError(const FormatException('request head too large'));
        }
      },
      onError: (Object error) {
        if (!headRead.isCompleted) headRead.completeError(error);
      },
      onDone: () {
        if (!headRead.isCompleted) {
          headRead.completeError(const FormatException('closed before head'));
        }
      },
      cancelOnError: false,
    );

    late final List<int> first;
    try {
      first = await headRead.future.timeout(const Duration(seconds: 10));
    } catch (_) {
      _live.remove(client);
      await subscription.cancel();
      client.destroy();
      return;
    }
    subscription.pause();

    final headerEnd = _headerEnd(first);
    final head = utf8.decode(first.sublist(0, headerEnd), allowMalformed: true);
    // Anything the client pipelined after the head. For CONNECT a browser
    // normally waits for the 200, but nothing guarantees it, and dropping
    // these bytes would corrupt the first TLS record.
    final pipelined = first.sublist(headerEnd);
    final lines = head.split(RegExp(r'\r?\n'));

    // Every refusal path must also release the subscription, or the paused
    // socket lingers.
    void refuse(int code, String reason, {String extraHeaders = ''}) {
      _live.remove(client);
      unawaited(subscription.cancel());
      _refuse(client, code, reason, extraHeaders: extraHeaders);
    }

    if (lines.isEmpty) {
      _count(ProxyRefusal.malformed);
      refuse(400, 'Bad Request');
      return;
    }

    final requestLine = lines.first.split(' ');
    if (requestLine.length < 3) {
      _count(ProxyRefusal.malformed);
      refuse(400, 'Bad Request');
      return;
    }

    // Authenticate BEFORE consulting the gate, so that an unauthenticated
    // local process learns nothing about whether the tunnel is up.
    if (!_isAuthenticated(lines)) {
      _count(ProxyRefusal.unauthenticated);
      refuse(
        407,
        'Proxy Authentication Required',
        extraHeaders:
            'Proxy-Authenticate: Basic realm="$kBridgeProxyAuthRealm"\r\n',
      );
      return;
    }

    // THE FAIL-CLOSED CHECK.
    //
    // Before any name resolution, before any socket. If the tunnel is not
    // proven up, the request dies here and no packet leaves this machine on
    // its behalf. This ordering is the single most important line in the file:
    // the extension's entire safety story is that a refusal here is a refusal,
    // not a fallback to the naked interface.
    if (!_admits(generation)) {
      _count(ProxyRefusal.tunnelDown);
      refuse(503, 'Tunnel Not Connected');
      return;
    }

    final method = requestLine[0].toUpperCase();
    if (method != 'CONNECT') {
      // Plain-HTTP proxying is deliberately not implemented, and the refusal
      // must be observable rather than silent. The web/desktop control plane
      // is CONFIG-ONLY: it delivers a resolved winn/3 config, never a raw HTTP
      // proxy. A browser's data-plane traffic reaches the tunnel exclusively
      // as an HTTP CONNECT (an absolute-URI forwarder would be a second parser
      // and a second set of header-smuggling bugs for no benefit), so any
      // non-CONNECT method here is refused and no upstream socket may ever be
      // opened on its behalf. Every such refusal is counted below, giving the
      // never-a-raw-HTTP-proxy promise a failure mode a test can assert.
      _count(ProxyRefusal.unsupportedProxyMethod);
      refuse(501, 'Not Implemented');
      return;
    }

    final target = parseConnectAuthority(requestLine[1]);
    if (target == null) {
      _count(ProxyRefusal.malformed);
      refuse(400, 'Bad Request');
      return;
    }

    // Destination check AFTER auth and the gate, AFTER the name is parsed,
    // and AFTER DNS. A public-looking name that resolves to loopback is the
    // same leak as CONNECT 127.0.0.1; a mixed public+local answer is rebinding
    // and is refused as a whole. The connector is given a validated IP, never
    // the original name.
    List<InternetAddress>? admitted;
    try {
      admitted = await admitConnectTarget(
        target.$1,
        resolver: _resolve,
      ).timeout(kBridgeResolveTimeout);
    } catch (_) {
      refuse(502, 'Bad Gateway');
      return;
    }
    if (!_admits(generation)) {
      _count(ProxyRefusal.tunnelDown);
      refuse(503, 'Tunnel Not Connected');
      return;
    }
    if (admitted == null) {
      _count(ProxyRefusal.forbiddenTarget);
      refuse(403, 'Forbidden');
      return;
    }
    if (admitted.isEmpty) {
      refuse(502, 'Bad Gateway');
      return;
    }

    // Each admitted address in resolver order, within one overall budget. The
    // gate is checked again before EVERY attempt: resolution (and a failed
    // attempt) can take seconds while a tunnel is dropping, and a connect
    // issued after the gate closed would put its SYN on the naked interface
    // before the post-connect check below could see it.
    final Stopwatch connectClock = Stopwatch()..start();
    Socket? connected;
    for (final InternetAddress address
        in admitted.take(kBridgeMaxAddressAttempts)) {
      if (!_admits(generation)) {
        _count(ProxyRefusal.tunnelDown);
        refuse(503, 'Tunnel Not Connected');
        return;
      }
      final Duration? attemptBudget = bridgeAttemptBudget(connectClock.elapsed);
      if (attemptBudget == null) break;
      try {
        connected = await _boundedUpstreamConnect(
          _connect,
          address.address,
          target.$2,
          attemptBudget,
        );
        upstreamOpened++;
        break;
      } catch (_) {
        continue;
      }
    }
    if (connected == null) {
      refuse(502, 'Bad Gateway');
      return;
    }
    final Socket upstream = connected;

    // Re-check after the await. The gate can have closed while the upstream
    // connection was being established, and a connection opened into a tunnel
    // that has since dropped is exactly the leak this class exists to prevent.
    if (!_admits(generation)) {
      _count(ProxyRefusal.tunnelDown);
      upstream.destroy();
      refuse(503, 'Tunnel Not Connected');
      return;
    }

    _live.add(upstream);

    client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    try {
      client.setOption(SocketOption.tcpNoDelay, true);
    } catch (_) {}

    void teardown() {
      _live.remove(client);
      _live.remove(upstream);
      unawaited(subscription.cancel());
      try {
        upstream.destroy();
      } catch (_) {}
      try {
        client.destroy();
      } catch (_) {}
    }

    // A WRITE THAT FAILS REPORTS ON `done`, NOT TO THE READ SUBSCRIPTION.
    //
    // Found by running this host under a real Firefox against a destination
    // that accepted the connection and immediately reset it. `Socket` is an
    // `IOSink`: an error raised while flushing bytes queued by `add` is
    // delivered to `done` and nowhere else, so `listen(onError:)` below never
    // sees it. Nothing was awaiting `done`, so the error escaped as an
    // *unhandled asynchronous exception* -- which in a `dart compile exe`
    // binary terminates the process. The browser then relaunched the host and
    // the extension reconnected, so it failed closed and was invisible from
    // inside the product; it is still a proxy that dies when a site hangs up
    // mid-response, and it took a real host under a real browser to see it.
    //
    // The `catchError` here is what consumes that error. It is not belt and
    // braces: without it there is no handler at all on the write path.
    unawaited(upstream.done.catchError((Object _) {
      teardown();
      return upstream;
    }));
    unawaited(client.done.catchError((Object _) {
      teardown();
      return client;
    }));

    // Client -> upstream, reusing the subscription that read the head. Bytes
    // the client pipelined ahead of the 200 go first so the byte stream stays
    // in order.
    if (pipelined.isNotEmpty) {
      upstream.add(pipelined);
    }
    // BACKPRESSURE IN BOTH DIRECTIONS. `Socket.add` never blocks: it queues
    // in the IOSink. Without pausing the reading side until the writing side
    // has flushed, a fast loopback browser uploading through a slower tunnel
    // (or a fast tunnel feeding a busy browser) is buffered whole in this
    // process.
    subscription
      ..onData((Uint8List data) {
        subscription.pause();
        try {
          upstream.add(data);
        } catch (_) {
          teardown();
          return;
        }
        upstream.flush().then((_) {
          if (_live.contains(upstream)) subscription.resume();
        }, onError: (Object _) => teardown());
      })
      ..onError((Object _) => teardown())
      ..onDone(teardown)
      ..resume();

    // Upstream -> client. This socket has not been listened to yet, so a plain
    // listen is safe here.
    late final StreamSubscription<Uint8List> fromUpstream;
    fromUpstream = upstream.listen(
      (Uint8List data) {
        fromUpstream.pause();
        try {
          client.add(data);
        } catch (_) {
          teardown();
          return;
        }
        client.flush().then((_) {
          if (_live.contains(client)) fromUpstream.resume();
        }, onError: (Object _) => teardown());
      },
      onError: (Object _) => teardown(),
      onDone: teardown,
      cancelOnError: true,
    );
  }

  /// Index just past the blank line that ends the request head, or -1.
  static int _headerEnd(List<int> bytes) {
    for (var i = 0; i + 3 < bytes.length; i++) {
      if (bytes[i] == 0x0D &&
          bytes[i + 1] == 0x0A &&
          bytes[i + 2] == 0x0D &&
          bytes[i + 3] == 0x0A) {
        return i + 4;
      }
    }
    // Tolerate bare LF, which hand-written clients and some tests produce.
    for (var i = 0; i + 1 < bytes.length; i++) {
      if (bytes[i] == 0x0A && bytes[i + 1] == 0x0A) return i + 2;
    }
    return -1;
  }

  bool _isAuthenticated(List<String> lines) {
    for (final line in lines) {
      final lower = line.toLowerCase();
      if (!lower.startsWith('proxy-authorization:')) continue;
      final value = line.substring(line.indexOf(':') + 1).trim();
      if (!value.toLowerCase().startsWith('basic ')) return false;
      try {
        final decoded = utf8.decode(base64.decode(value.substring(6).trim()));
        // `user:token`; the username is ignored, the token is the secret.
        final colon = decoded.indexOf(':');
        if (colon < 0) return false;
        final presented = decoded.substring(colon + 1);
        if (credential.isExpired) return false;
        return credential.matches(presented);
      } catch (_) {
        return false;
      }
    }
    return false;
  }

  void _refuse(Socket client, int code, String reason,
      {String extraHeaders = ''}) {
    // Refusals return before the relay attaches its `done` handlers, so a
    // browser that resets while this response is flushing would otherwise
    // raise an unhandled asynchronous error and end the standalone host (see
    // "A WRITE THAT FAILS REPORTS ON `done`" in _handle).
    unawaited(client.done.catchError((Object _) {
      client.destroy();
      return client;
    }));
    try {
      client.write(
        'HTTP/1.1 $code $reason\r\n'
        '${extraHeaders}Content-Length: 0\r\n'
        'Connection: close\r\n\r\n',
      );
    } catch (_) {}
    // `destroy` rather than `close`: a refused request must not leave a
    // half-open socket the caller could keep writing into.
    Future<void>.delayed(const Duration(milliseconds: 20), client.destroy);
  }
}
