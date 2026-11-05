import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';

/// An [http.Client] that forces EVERY request it sends to refuse redirects.
///
/// F-06 (final audit 2026-08-28): `package:http` and `dart:io` both follow
/// redirects by default (the flag lives on the REQUEST, not the client, so
/// a plain `http.get` or an IOClient over a default HttpClient follows
/// them), which made every host allowlist checked on the INITIAL URL of a
/// pre-tunnel request enforceable only on the first hop -- a 302 from an
/// allowlisted origin could move the request, and with it the user's real
/// IP or the data being fetched, to any host the allowlist never named.
/// The pinned control-plane client already refuses redirects at the
/// transport and re-validates each hop; this client gives plain-HTTP
/// fetches the same "the host I resolved is the host I talk to" guarantee,
/// including inside libraries (flutter_map's tile fetcher) that build
/// their own requests and cannot be asked to set the flag themselves.
class NoRedirectClient extends http.BaseClient {
  NoRedirectClient([http.Client? inner]) : _inner = inner ?? http.Client();

  final http.Client _inner;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) {
    request.followRedirects = false;
    request.maxRedirects = 0;
    return _inner.send(request);
  }

  @override
  void close() {
    _inner.close();
  }
}

/// Convenience constructor for [NoRedirectClient].
http.Client noRedirectHttpClient() => NoRedirectClient();

/// A GET that refuses every redirect: any 3xx status is returned to the
/// caller as a failure (via [NoRedirectRefusedException]) instead of being
/// followed to a host nobody allowlisted.
///
/// Callers that need to treat a 3xx as a normal miss can catch
/// [NoRedirectRefusedException]; the response is never fetched from the
/// redirect target either way.
Future<http.Response> fetchWithoutRedirects(
  Uri url, {
  Map<String, String>? headers,
}) async {
  final client = NoRedirectClient();
  try {
    final request = http.Request('GET', url);
    if (headers != null) {
      request.headers.addAll(headers);
    }
    final streamed = await client.send(request);
    final response = await http.Response.fromStream(streamed);
    if (response.statusCode >= 300 && response.statusCode < 400) {
      throw NoRedirectRefusedException(
        'Refusing to follow a ${response.statusCode} redirect from '
        '${url.host}: the destination host was never allowlisted (F-06).',
      );
    }
    return response;
  } finally {
    client.close();
  }
}

/// [fetchWithoutRedirects] with the body bounded while it streams.
///
/// The body is read chunk by chunk and never buffered past [maxBytes]. A
/// declared Content-Length above the cap, a chunk that would take the total
/// above it, or [deadline] (which covers connecting, the headers and the
/// whole body) aborts the request and force-closes this fetch's own client,
/// which closes its connection. At most [maxBytes] plus one chunk is read. A
/// `.timeout` around [fetchWithoutRedirects] only stops waiting; the download
/// behind it runs on until the peer ends it.
///
/// [headers] are added to the request, as in [fetchWithoutRedirects].
/// [inner] is the transport, for tests. It is closed when the fetch ends.
Future<http.Response> fetchWithoutRedirectsCapped(
  Uri url, {
  required int maxBytes,
  required Duration deadline,
  Map<String, String>? headers,
  http.Client? inner,
}) {
  final client = NoRedirectClient(
    inner ?? IOClient(HttpClient()..connectionTimeout = deadline),
  );
  final abort = Completer<void>();
  final result = Completer<http.Response>();
  StreamSubscription<List<int>>? body;
  Timer? timer;

  void stop() {
    timer?.cancel();
    if (!abort.isCompleted) abort.complete();
    final subscription = body;
    body = null;
    if (subscription != null) unawaited(subscription.cancel());
    client.close();
  }

  void fail(Object error) {
    if (result.isCompleted) return;
    result.completeError(error);
    stop();
  }

  void discard(http.StreamedResponse streamed) {
    unawaited(streamed.stream.listen(null, onError: (Object _) {}).cancel());
  }

  timer = Timer(
    deadline,
    () => fail(TimeoutException('Fetch from ${url.host} timed out', deadline)),
  );
  final request =
      http.AbortableRequest('GET', url, abortTrigger: abort.future);
  if (headers != null) {
    request.headers.addAll(headers);
  }
  client.send(request).then((streamed) {
    if (result.isCompleted) {
      discard(streamed);
      return;
    }
    final status = streamed.statusCode;
    if (status >= 300 && status < 400) {
      discard(streamed);
      fail(NoRedirectRefusedException(
        'Refusing to follow a $status redirect from '
        '${url.host}: the destination host was never allowlisted (F-06).',
      ));
      return;
    }
    final declared = streamed.contentLength;
    if (declared != null && declared > maxBytes) {
      discard(streamed);
      fail(ResponseBodyTooLargeException(maxBytes));
      return;
    }
    final bytes = BytesBuilder(copy: false);
    body = streamed.stream.listen(
      (chunk) {
        if (bytes.length + chunk.length > maxBytes) {
          fail(ResponseBodyTooLargeException(maxBytes));
          return;
        }
        bytes.add(chunk);
      },
      onError: fail,
      onDone: () {
        if (result.isCompleted) return;
        result.complete(http.Response.bytes(
          bytes.takeBytes(),
          status,
          request: streamed.request,
          headers: streamed.headers,
          isRedirect: streamed.isRedirect,
          persistentConnection: streamed.persistentConnection,
          reasonPhrase: streamed.reasonPhrase,
        ));
        stop();
      },
      cancelOnError: true,
    );
  }, onError: fail);
  return result.future;
}

/// Thrown by [fetchWithoutRedirectsCapped] when a body would exceed its cap.
/// Nothing past the cap is kept.
final class ResponseBodyTooLargeException implements Exception {
  ResponseBodyTooLargeException(this.maxBytes);

  final int maxBytes;

  @override
  String toString() =>
      'ResponseBodyTooLargeException: body exceeds $maxBytes bytes';
}

/// Thrown by [fetchWithoutRedirects] when the origin answers with a redirect.
///
/// The message deliberately names only the ORIGINAL host, never the
/// redirect target, so a hostile server cannot use the Location header to
/// put arbitrary text in logs.
final class NoRedirectRefusedException implements Exception {
  NoRedirectRefusedException(this.message);

  final String message;

  @override
  String toString() => 'NoRedirectRefusedException: $message';
}
