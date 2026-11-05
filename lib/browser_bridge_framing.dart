// Wire framing for the Chrome/Edge/Firefox native-messaging protocol.
//
// The framing is deliberately in its own file, with no Flutter import, because
// it is compiled twice: once into the Dart test suite, and once into the
// standalone `bin/wins_bridge_host.dart` executable that the browser actually
// launches. `dart compile exe` cannot see a `package:flutter` import.
//
// The format, as Chromium and Gecko both implement it:
//
//   [ 4 bytes: message length ][ N bytes: UTF-8 JSON ]
//
// Three details are where these implementations usually break, so each one is
// pinned by a test rather than assumed:
//
//  1. The length is **little-endian**. Both browsers document it as "native
//     byte order", which is the same thing on every platform this app ships to
//     (x86-64 and arm64 are both little-endian). [assertNativeOrderIsLittle]
//     turns the day that stops being true into a loud failure instead of a
//     silently corrupt first frame.
//  2. The length counts **bytes of UTF-8**, not characters. A Burmese status
//     string is three bytes per character, and a host that writes character
//     counts will desynchronise the stream on the first non-ASCII message and
//     never recover.
//  3. stdin delivers **arbitrary chunks**, not messages. A frame can be split
//     anywhere -- including in the middle of the 4-byte prefix -- and several
//     frames can arrive in one chunk. [NativeMessageReader] is a resumable
//     parser for exactly that reason.

import 'dart:convert';
import 'dart:typed_data';

/// Ceiling on a single framed message, in bytes.
///
/// Chrome caps a host->browser message at 1 MB and drops the host if it is
/// exceeded; Firefox matches. The same ceiling is applied to the inbound
/// direction, where the browsers are far more generous, so that a hostile or
/// wedged caller cannot make the host buffer without bound before it has
/// authenticated anything.
const int kMaxNativeMessageBytes = 1024 * 1024;

/// The length prefix is 4 bytes on both browsers.
const int kNativeLengthPrefixBytes = 4;

/// Thrown when a peer sends something that is not a well-formed frame.
///
/// Always fatal to the connection: once the length prefix is not trustworthy
/// there is no way to find the start of the next message, so the only correct
/// response is to stop reading rather than to resynchronise by guessing.
class NativeFramingException implements Exception {
  const NativeFramingException(this.reason);

  final String reason;

  @override
  String toString() => 'NativeFramingException: $reason';
}

/// Encode one JSON value as a framed native message.
Uint8List encodeNativeMessage(Object? payload) {
  final body = utf8.encode(jsonEncode(payload));
  if (body.length > kMaxNativeMessageBytes) {
    throw NativeFramingException(
      'outbound message is ${body.length} bytes, over the '
      '$kMaxNativeMessageBytes byte ceiling',
    );
  }
  final frame = Uint8List(kNativeLengthPrefixBytes + body.length);
  // Little-endian by explicit request, not by host default: see the file
  // comment. Writing it explicitly means the bytes do not change meaning if
  // this ever cross-compiles somewhere exotic.
  ByteData.sublistView(frame, 0, kNativeLengthPrefixBytes)
      .setUint32(0, body.length, Endian.little);
  frame.setRange(kNativeLengthPrefixBytes, frame.length, body);
  return frame;
}

/// True when this machine's native byte order matches what the framing writes.
///
/// Both browsers specify "native byte order" and every supported target is
/// little-endian, so these agree today. Exposed so a test can pin it.
bool assertNativeOrderIsLittle() => Endian.host == Endian.little;

/// Incremental reader that turns a stream of arbitrary byte chunks into whole
/// messages.
///
/// Feed it whatever stdin produced; it returns however many complete messages
/// that made available, which is frequently zero and occasionally several.
class NativeMessageReader {
  final List<int> _buffer = <int>[];

  /// Bytes currently held pending a complete frame. Exposed for tests that
  /// assert the reader is not accumulating across message boundaries.
  int get bufferedBytes => _buffer.length;

  /// Add [chunk] and drain every message it completed.
  ///
  /// Throws [NativeFramingException] on a length prefix that cannot be
  /// honoured or a body that is not UTF-8 JSON.
  List<Object?> addChunk(List<int> chunk) {
    _buffer.addAll(chunk);
    final messages = <Object?>[];

    while (true) {
      if (_buffer.length < kNativeLengthPrefixBytes) break;

      final header = Uint8List.fromList(
        _buffer.sublist(0, kNativeLengthPrefixBytes),
      );
      final length = ByteData.sublistView(header).getUint32(0, Endian.little);

      if (length > kMaxNativeMessageBytes) {
        throw NativeFramingException(
          'inbound frame declares $length bytes, over the '
          '$kMaxNativeMessageBytes byte ceiling',
        );
      }

      // A zero-length frame carries no JSON value at all. Chrome will not
      // produce one; treating it as a framing error is safer than emitting a
      // null message that every downstream switch would have to special-case.
      if (length == 0) {
        throw const NativeFramingException('inbound frame declares 0 bytes');
      }

      final total = kNativeLengthPrefixBytes + length;
      if (_buffer.length < total) break; // Partial frame: wait for more.

      final body = _buffer.sublist(kNativeLengthPrefixBytes, total);
      _buffer.removeRange(0, total);

      try {
        messages.add(jsonDecode(utf8.decode(body)));
      } on FormatException catch (error) {
        throw NativeFramingException('inbound frame is not UTF-8 JSON: $error');
      }
    }

    return messages;
  }
}
