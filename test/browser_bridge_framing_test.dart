// Proof of the native-messaging wire framing.
//
// The 4-byte prefix is where these implementations break, so every claim the
// design makes about it is pinned here byte-for-byte rather than assumed.

import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/browser_bridge_framing.dart';

void main() {
  group('length prefix', () {
    test('is little-endian, proven by the actual bytes', () {
      // A body of exactly 1 byte. Little-endian writes the significant byte
      // first; a big-endian implementation writes it last. This single
      // assertion is the difference between the two.
      final frame = encodeNativeMessage(1);
      expect(utf8.decode(frame.sublist(4)), '1');
      expect(
        frame.sublist(0, 4),
        <int>[0x01, 0x00, 0x00, 0x00],
        reason: 'little-endian; big-endian would be [0,0,0,1]',
      );
    });

    test('multi-byte length keeps byte order', () {
      // 260 bytes = 0x0104. Little-endian: 04 01 00 00.
      final body = 'x' * 258; // plus two quote characters in the JSON
      final frame = encodeNativeMessage(body);
      expect(frame.length - 4, 260);
      expect(frame.sublist(0, 4), <int>[0x04, 0x01, 0x00, 0x00]);
    });

    test('native order on this target really is little-endian', () {
      // Both browsers document "native byte order". They agree with the
      // explicit little-endian encoding on every platform this ships to. If
      // that ever stops being true, this fails loudly instead of producing one
      // corrupt frame at startup.
      expect(assertNativeOrderIsLittle(), isTrue);
    });

    test('length counts UTF-8 bytes, not characters', () {
      // Burmese: three bytes per character. A host that wrote character counts
      // would desynchronise permanently on the first localised status string.
      const burmese = 'ချိတ်ဆက်ပြီး';
      final frame = encodeNativeMessage(burmese);
      final declared = ByteData.sublistView(frame, 0, 4).getUint32(0, Endian.little);

      expect(declared, frame.length - 4);
      expect(declared, greaterThan(burmese.length),
          reason: 'byte count must exceed the character count here');

      final decoded = NativeMessageReader().addChunk(frame);
      expect(decoded, <Object?>[burmese]);
    });
  });

  group('reader resumability', () {
    test('reassembles a frame split inside the length prefix', () {
      final frame = encodeNativeMessage(<String, Object?>{'type': 'hello'});
      final reader = NativeMessageReader();

      // Split after 2 of the 4 prefix bytes: the nastiest boundary, and the
      // one a reader that assumes it can read the header in one go gets wrong.
      expect(reader.addChunk(frame.sublist(0, 2)), isEmpty);
      expect(reader.bufferedBytes, 2);
      final out = reader.addChunk(frame.sublist(2));
      expect(out, hasLength(1));
      expect((out.first as Map)['type'], 'hello');
      expect(reader.bufferedBytes, 0);
    });

    test('reassembles a frame split inside the body', () {
      final frame = encodeNativeMessage(<String, Object?>{'type': 'get_status'});
      final reader = NativeMessageReader();
      expect(reader.addChunk(frame.sublist(0, 7)), isEmpty);
      expect(reader.addChunk(frame.sublist(7)), hasLength(1));
    });

    test('delivers several frames arriving in one chunk', () {
      final a = encodeNativeMessage(<String, Object?>{'n': 1});
      final b = encodeNativeMessage(<String, Object?>{'n': 2});
      final c = encodeNativeMessage(<String, Object?>{'n': 3});
      final joined = <int>[...a, ...b, ...c];

      final out = NativeMessageReader().addChunk(joined);
      expect(out.map((Object? m) => (m as Map)['n']), <int>[1, 2, 3]);
    });

    test('delivers frames one byte at a time', () {
      final frame = encodeNativeMessage(<String, Object?>{'type': 'subscribe'});
      final reader = NativeMessageReader();
      final collected = <Object?>[];
      for (final byte in frame) {
        collected.addAll(reader.addChunk(<int>[byte]));
      }
      expect(collected, hasLength(1));
      expect((collected.first as Map)['type'], 'subscribe');
    });
  });

  group('hostile frames', () {
    test('rejects a length over the ceiling without buffering it', () {
      final header = Uint8List(4);
      ByteData.sublistView(header).setUint32(0, kMaxNativeMessageBytes + 1, Endian.little);
      expect(
        () => NativeMessageReader().addChunk(header),
        throwsA(isA<NativeFramingException>()),
      );
    });

    test('rejects a zero-length frame', () {
      expect(
        () => NativeMessageReader().addChunk(<int>[0, 0, 0, 0]),
        throwsA(isA<NativeFramingException>()),
      );
    });

    test('rejects a body that is not JSON', () {
      final body = utf8.encode('not json');
      final header = Uint8List(4);
      ByteData.sublistView(header).setUint32(0, body.length, Endian.little);
      expect(
        () => NativeMessageReader().addChunk(<int>[...header, ...body]),
        throwsA(isA<NativeFramingException>()),
      );
    });

    test('refuses to encode over the ceiling', () {
      expect(
        () => encodeNativeMessage('y' * (kMaxNativeMessageBytes + 10)),
        throwsA(isA<NativeFramingException>()),
      );
    });
  });
}
