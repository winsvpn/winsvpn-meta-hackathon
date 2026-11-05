import 'dart:async';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:wins_vpn/no_redirect_http.dart';

/// A transport whose body never ends: one [chunk]-byte chunk per millisecond
/// for as long as someone listens. [delivered] counts the bytes handed to the
/// reader, so it is exactly what the reader consumed.
class _EndlessBodyClient extends http.BaseClient {
  _EndlessBodyClient({
    this.chunk = 4096,
    this.contentLength,
    this.chunks = -1,
    this.sendHeaders = true,
  });

  final int chunk;
  final int? contentLength;

  /// How many chunks to send before going silent; -1 never stops.
  final int chunks;

  /// False: the headers never arrive.
  final bool sendHeaders;

  int delivered = 0;
  bool bodyCancelled = false;
  bool closed = false;
  http.BaseRequest? request;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) {
    this.request = request;
    if (!sendHeaders) return Completer<http.StreamedResponse>().future;
    final controller = StreamController<List<int>>();
    var sent = 0;
    final timer = Timer.periodic(const Duration(milliseconds: 1), (_) {
      if (controller.isPaused || (chunks >= 0 && sent >= chunks)) return;
      sent += 1;
      controller.add(List<int>.filled(chunk, 0x41));
    });
    controller.onCancel = () {
      bodyCancelled = true;
      timer.cancel();
    };
    return Future.value(http.StreamedResponse(
      controller.stream.map((bytes) {
        delivered += bytes.length;
        return bytes;
      }),
      200,
      contentLength: contentLength,
      request: request,
    ));
  }

  @override
  void close() {
    closed = true;
  }
}

/// A loopback peer that sends response headers and then [onConnected]'s body,
/// and records when the client side of the connection goes away.
class _RawPeer {
  _RawPeer._(this._server);

  final ServerSocket _server;
  final Completer<void> clientClosed = Completer<void>();
  bool _stopped = false;

  int get port => _server.port;

  static Future<_RawPeer> start({required bool endless}) async {
    final peer = _RawPeer._(
        await ServerSocket.bind(InternetAddress.loopbackIPv4, 0));
    peer._server.listen((socket) {
      socket.listen((_) {}, onDone: () {
        if (!peer.clientClosed.isCompleted) peer.clientClosed.complete();
      }, onError: (Object _) {
        if (!peer.clientClosed.isCompleted) peer.clientClosed.complete();
      }, cancelOnError: true);
      socket.add('HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n'
          'Connection: close\r\n\r\nA'
          .codeUnits);
      if (!endless) return;
      Future<void>(() async {
        final chunk = List<int>.filled(4096, 0x41);
        try {
          while (!peer._stopped && !peer.clientClosed.isCompleted) {
            socket.add(chunk);
            await socket.flush();
          }
        } catch (_) {
          if (!peer.clientClosed.isCompleted) peer.clientClosed.complete();
        }
      });
    });
    return peer;
  }

  Future<void> close() async {
    _stopped = true;
    await _server.close();
  }
}

void main() {
  test('noRedirectHttpClient does not follow a redirect', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final redirectTarget = <String>[];
    final unawaitedServer = server.listen((request) async {
      if (request.uri.path == '/redirect') {
        redirectTarget.add(request.uri.queryParameters['to'] ?? '?');
        request.response.statusCode = HttpStatus.found;
        request.response.headers.set(
          HttpHeaders.locationHeader,
          request.uri.queryParameters['to'] ?? '/',
        );
        await request.response.close();
        return;
      }
      // The redirect destination: if this is ever reached the test must fail.
      redirectTarget.add('DESTINATION-REACHED:${request.uri.path}');
      request.response.statusCode = HttpStatus.ok;
      await request.response.close();
    });
    addTearDown(() => unawaitedServer.cancel());

    final port = server.port;
    final destination =
        'http://127.0.0.1:$port/attacker-destination?secret=1';
    final url = Uri.parse('http://127.0.0.1:$port/redirect?to=$destination');

    final client = noRedirectHttpClient();
    addTearDown(client.close);
    final response = await client.get(url);

    expect(response.statusCode, HttpStatus.found,
        reason: 'the client must return the 3xx itself, not follow it');
    expect(
      redirectTarget.where((entry) => entry.startsWith('DESTINATION-REACHED')),
      isEmpty,
      reason: 'a request reached the redirect destination',
    );
  });

  test('fetchWithoutRedirects returns a direct 200 untouched', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final unawaitedServer = server.listen((request) async {
      request.response.headers.contentType = ContentType.text;
      request.response.write('payload');
      await request.response.close();
    });
    addTearDown(() => unawaitedServer.cancel());

    final response = await fetchWithoutRedirects(
      Uri.parse('http://127.0.0.1:${server.port}/direct'),
      headers: {'X-Test': 'yes'},
    );
    expect(response.statusCode, 200);
    expect(response.body, 'payload');
  });

  test('fetchWithoutRedirects refuses every 3xx instead of following it',
      () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    var destinationHits = 0;
    final unawaitedServer = server.listen((request) async {
      if (request.uri.path == '/redirect') {
        request.response.statusCode = HttpStatus.movedPermanently;
        request.response.headers
            .set(HttpHeaders.locationHeader, '/attacker-destination');
        await request.response.close();
        return;
      }
      destinationHits += 1;
      request.response.statusCode = HttpStatus.ok;
      await request.response.close();
    });
    addTearDown(() => unawaitedServer.cancel());

    final url = Uri.parse('http://127.0.0.1:${server.port}/redirect');
    await expectLater(
      fetchWithoutRedirects(url),
      throwsA(isA<NoRedirectRefusedException>()),
    );
    expect(destinationHits, 0,
        reason: 'the redirect destination must never be fetched');
  });

  test('the refusal message names the original host, never the target',
      () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final unawaitedServer = server.listen((request) async {
      request.response.statusCode = HttpStatus.found;
      request.response.headers.set(
        HttpHeaders.locationHeader,
        'http://127.0.0.1:${server.port}/INJECTED-LOG-TEXT',
      );
      await request.response.close();
    });
    addTearDown(() => unawaitedServer.cancel());

    final url = Uri.parse('http://127.0.0.1:${server.port}/redirect');
    try {
      await fetchWithoutRedirects(url);
      fail('fetchWithoutRedirects followed or accepted a redirect');
    } on NoRedirectRefusedException catch (error) {
      expect(error.toString(), contains('127.0.0.1'));
      expect(error.toString(), isNot(contains('INJECTED-LOG-TEXT')),
          reason: 'a hostile Location header must not reach logs');
    }
  });

  test('fetchWithoutRedirects surfaces non-redirect failures normally',
      () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final unawaitedServer = server.listen((request) async {
      request.response.statusCode = HttpStatus.serviceUnavailable;
      await request.response.close();
    });
    addTearDown(() => unawaitedServer.cancel());

    final response = await fetchWithoutRedirects(
      Uri.parse('http://127.0.0.1:${server.port}/down'),
    );
    expect(response.statusCode, 503);
  });

  group('fetchWithoutRedirectsCapped', () {
    test('returns a body of exactly the cap untouched', () async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      final unawaitedServer = server.listen((request) async {
        request.response.add(List<int>.filled(16384, 0x42));
        await request.response.close();
      });
      addTearDown(() => unawaitedServer.cancel());

      final response = await fetchWithoutRedirectsCapped(
        Uri.parse('http://127.0.0.1:${server.port}/notice'),
        maxBytes: 16384,
        deadline: const Duration(seconds: 4),
      );
      expect(response.statusCode, 200);
      expect(response.bodyBytes, hasLength(16384));
    });

    test('an oversize body is refused after at most the cap plus one chunk, '
        'and the transport is closed', () async {
      final inner = _EndlessBodyClient();
      await expectLater(
        fetchWithoutRedirectsCapped(
          Uri.parse('https://raw.githubusercontent.com/o/r/main/n.json'),
          maxBytes: 16384,
          deadline: const Duration(seconds: 4),
          inner: inner,
        ),
        throwsA(isA<ResponseBodyTooLargeException>()),
      );
      expect(inner.delivered, greaterThan(16384),
          reason: 'the reader must have read up to the cap');
      expect(inner.delivered, lessThanOrEqualTo(16384 + 4096),
          reason: 'no more than one chunk past the cap may be read');
      expect(inner.bodyCancelled, isTrue);
      expect(inner.closed, isTrue);
      expect((inner.request! as http.Abortable).abortTrigger, completes);
    });

    test('a declared Content-Length over the cap is refused before any body '
        'byte is read', () async {
      final inner = _EndlessBodyClient(contentLength: 1 << 20);
      await expectLater(
        fetchWithoutRedirectsCapped(
          Uri.parse('https://raw.githubusercontent.com/o/r/main/n.json'),
          maxBytes: 16384,
          deadline: const Duration(seconds: 4),
          inner: inner,
        ),
        throwsA(isA<ResponseBodyTooLargeException>()),
      );
      expect(inner.delivered, 0);
      expect(inner.closed, isTrue);
    });

    test('a slow body hits the deadline and the transport is closed',
        () async {
      final inner = _EndlessBodyClient(chunk: 1, chunks: 1);
      final stopwatch = Stopwatch()..start();
      await expectLater(
        fetchWithoutRedirectsCapped(
          Uri.parse('https://raw.githubusercontent.com/o/r/main/n.json'),
          maxBytes: 16384,
          deadline: const Duration(milliseconds: 300),
          inner: inner,
        ),
        throwsA(isA<TimeoutException>()),
      );
      expect(stopwatch.elapsed, lessThan(const Duration(seconds: 2)));
      expect(inner.delivered, 1, reason: 'the body had started');
      expect(inner.bodyCancelled, isTrue);
      expect(inner.closed, isTrue);
      expect((inner.request! as http.Abortable).abortTrigger, completes);
    });

    test('headers that never arrive hit the deadline and the transport is '
        'closed', () async {
      final inner = _EndlessBodyClient(sendHeaders: false);
      await expectLater(
        fetchWithoutRedirectsCapped(
          Uri.parse('https://raw.githubusercontent.com/o/r/main/n.json'),
          maxBytes: 16384,
          deadline: const Duration(milliseconds: 300),
          inner: inner,
        ),
        throwsA(isA<TimeoutException>()),
      );
      expect(inner.closed, isTrue);
      expect((inner.request! as http.Abortable).abortTrigger, completes);
    });

    test('sends the caller headers, like fetchWithoutRedirects', () async {
      final inner = _EndlessBodyClient(chunks: 1);
      await expectLater(
        fetchWithoutRedirectsCapped(
          Uri.parse('https://speed.cloudflare.com/meta'),
          maxBytes: 16384,
          deadline: const Duration(milliseconds: 300),
          headers: const <String, String>{
            'Accept': 'application/json',
            'Origin': 'https://speed.cloudflare.com',
          },
          inner: inner,
        ),
        throwsA(isA<TimeoutException>()),
      );
      expect(inner.request!.headers['Accept'], 'application/json');
      expect(inner.request!.headers['Origin'], 'https://speed.cloudflare.com');
      expect(inner.request!.followRedirects, isFalse);
      expect(inner.closed, isTrue);
    });

    test('a redirect is refused like fetchWithoutRedirects', () async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      var destinationHits = 0;
      final unawaitedServer = server.listen((request) async {
        if (request.uri.path == '/redirect') {
          request.response.statusCode = HttpStatus.found;
          request.response.headers.set(HttpHeaders.locationHeader, '/elsewhere');
          await request.response.close();
          return;
        }
        destinationHits += 1;
        await request.response.close();
      });
      addTearDown(() => unawaitedServer.cancel());

      await expectLater(
        fetchWithoutRedirectsCapped(
          Uri.parse('http://127.0.0.1:${server.port}/redirect'),
          maxBytes: 16384,
          deadline: const Duration(seconds: 4),
        ),
        throwsA(isA<NoRedirectRefusedException>()),
      );
      expect(destinationHits, 0);
    });

    test('over a real socket, an endless body closes the connection',
        () async {
      final peer = await _RawPeer.start(endless: true);
      addTearDown(peer.close);
      await expectLater(
        fetchWithoutRedirectsCapped(
          Uri.parse('http://127.0.0.1:${peer.port}/n.json'),
          maxBytes: 16384,
          deadline: const Duration(seconds: 4),
        ),
        throwsA(isA<ResponseBodyTooLargeException>()),
      );
      await peer.clientClosed.future.timeout(const Duration(seconds: 2));
    });

    test('over a real socket, a stalled body closes the connection at the '
        'deadline', () async {
      final peer = await _RawPeer.start(endless: false);
      addTearDown(peer.close);
      await expectLater(
        fetchWithoutRedirectsCapped(
          Uri.parse('http://127.0.0.1:${peer.port}/n.json'),
          maxBytes: 16384,
          deadline: const Duration(milliseconds: 300),
        ),
        throwsA(isA<TimeoutException>()),
      );
      await peer.clientClosed.future.timeout(const Duration(seconds: 2));
    });
  });
}
