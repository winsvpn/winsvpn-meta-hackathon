import 'dart:collection';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/server_load.dart';
import 'package:wins_vpn/watch_bridge.dart';

/// Parsing contract for the hub's per-server `load_pct`.
///
/// THE BUG CLASS THIS GUARDS. An unexpected value in a closed vocabulary once
/// threw in all three consumers and discarded the whole scan reply. Here every
/// malformed shape must come back as unknown (null), never throw, and never
/// cost a node its place in the list.
void main() {
  // One listing that carries every shape the contract allows plus every
  // malformed shape named in the lane brief. Decoded with the real jsonDecode,
  // so the Dart runtime types are exactly the ones the app sees.
  const listing = '''
  {"nodes":[
    {"slug":"zero","load_pct":0},
    {"slug":"low","load_pct":55},
    {"slug":"amber-edge","load_pct":60},
    {"slug":"red-edge","load_pct":85},
    {"slug":"full","load_pct":100},
    {"slug":"missing"},
    {"slug":"null","load_pct":null},
    {"slug":"string","load_pct":"45"},
    {"slug":"float","load_pct":45.5},
    {"slug":"integral-float","load_pct":45.0},
    {"slug":"negative","load_pct":-5},
    {"slug":"over","load_pct":105},
    {"slug":"off-step","load_pct":47},
    {"slug":"bool","load_pct":true},
    {"slug":"object","load_pct":{"v":45}},
    {"slug":"array","load_pct":[45]},
    {"slug":"huge","load_pct":99999999999999999999}
  ]}''';

  const valid = <String, int>{
    'zero': 0,
    'low': 55,
    'amber-edge': 60,
    'red-edge': 85,
    'full': 100,
  };

  late List<Map<String, dynamic>> nodes;
  setUp(() {
    nodes = (jsonDecode(listing)['nodes'] as List)
        .map((n) => Map<String, dynamic>.from(n as Map))
        .toList();
  });

  group('parseServerLoadPct', () {
    test('accepts exactly the contract domain', () {
      for (var v = 0; v <= 100; v += 5) {
        expect(parseServerLoadPct(v), v, reason: '$v is a contract value');
      }
    });

    test('rejects every off-contract value as unknown, without throwing', () {
      for (final raw in <Object?>[
        null,
        '45',
        '',
        45.5,
        -5,
        -1,
        101,
        105,
        47,
        1,
        99,
        true,
        false,
        <String, int>{'v': 45},
        <int>[45],
        double.nan,
        double.infinity,
        1 << 40,
      ]) {
        expect(() => parseServerLoadPct(raw), returnsNormally,
            reason: '${raw.runtimeType} must not throw');
        expect(parseServerLoadPct(raw), isNull, reason: '$raw must be unknown');
      }
    });

    test('a JSON float is unknown on the VM even when integral', () {
      // On the VM jsonDecode('45.0') is a double. (On web it is a JS number
      // that reads as int; see the note on parseServerLoadPct.)
      final decoded = jsonDecode('45.0');
      if (decoded is int) {
        expect(parseServerLoadPct(decoded), 45);
      } else {
        expect(parseServerLoadPct(decoded), isNull);
      }
    });
  });

  group('serverLoadPctOf over a real decoded listing', () {
    test('every node is read, valid ones keep their value, the rest are null',
        () {
      expect(nodes, hasLength(17), reason: 'no node may be lost');
      for (final node in nodes) {
        final slug = node['slug'] as String;
        expect(() => serverLoadPctOf(node), returnsNormally, reason: slug);
        expect(serverLoadPctOf(node), valid[slug], reason: slug);
      }
    });

    test('non-map items are unknown, not errors', () {
      for (final item in <Object?>[null, 'node', 42, <Object?>[]]) {
        expect(serverLoadPctOf(item), isNull);
      }
    });

    test('a map whose [] throws is unknown, not an error', () {
      expect(serverLoadPctOf(_ThrowingMap()), isNull);
    });
  });

  group('serverLoadLevel thresholds', () {
    test('green under 60, amber 60 to under 85, red 85 and over', () {
      expect(serverLoadLevel(null), ServerLoadLevel.unknown);
      expect(serverLoadLevel(0), ServerLoadLevel.low);
      expect(serverLoadLevel(55), ServerLoadLevel.low);
      expect(serverLoadLevel(59), ServerLoadLevel.low);
      expect(serverLoadLevel(60), ServerLoadLevel.elevated);
      expect(serverLoadLevel(80), ServerLoadLevel.elevated);
      expect(serverLoadLevel(84), ServerLoadLevel.elevated);
      expect(serverLoadLevel(85), ServerLoadLevel.high);
      expect(serverLoadLevel(100), ServerLoadLevel.high);
    });

    test('published bands 25/60/90/100 are green, amber, red, red', () {
      // 60 is exactly the amber threshold; a `>` would make it green.
      expect(serverLoadLevel(25), ServerLoadLevel.low);
      expect(serverLoadLevel(60), ServerLoadLevel.elevated);
      expect(serverLoadLevel(90), ServerLoadLevel.high);
      expect(serverLoadLevel(100), ServerLoadLevel.high);
      for (final v in <int>[25, 60, 90, 100]) {
        expect(parseServerLoadPct(v), v, reason: 'bands are contract values');
      }
    });

    test('out-of-range input is unknown even if a caller skips parsing', () {
      expect(serverLoadLevel(-5), ServerLoadLevel.unknown);
      expect(serverLoadLevel(105), ServerLoadLevel.unknown);
    });
  });

  group('freshness (fake clock)', () {
    late _FakeClock clock;
    late ServerLoadClock saved;
    setUp(() {
      saved = serverLoadClock;
      clock = _FakeClock();
      serverLoadClock = clock;
    });
    tearDown(() => serverLoadClock = saved);

    Map<String, dynamic> stamped(Object? pct) {
      final rx = serverLoadReceiptNow();
      return <String, dynamic>{
        kServerLoadPctKey: pct,
        kServerLoadReceivedMonoKey: rx.mono,
        kServerLoadReceivedWallKey: rx.wall,
      };
    }

    test('shown until 60 s after receipt, unknown from 60 s', () {
      final node = stamped(45);
      expect(freshServerLoadPct(node), 45);
      expect(serverLoadTimeToExpiry(node), const Duration(seconds: 60));
      clock.advance(const Duration(milliseconds: 59999));
      expect(freshServerLoadPct(node), 45);
      expect(serverLoadTimeToExpiry(node), const Duration(milliseconds: 1));
      clock.advance(const Duration(milliseconds: 1));
      expect(freshServerLoadPct(node), isNull);
      expect(serverLoadTimeToExpiry(node), isNull);
    });

    test('a suspend (monotonic stalls, wall advances) still expires', () {
      final node = stamped(45);
      clock.wall += 61000; // device asleep: only the wall clock moved
      expect(freshServerLoadPct(node), isNull);
    });

    test('a wall clock set backwards cannot make a figure look younger', () {
      final node = stamped(45);
      clock.advance(const Duration(seconds: 61));
      clock.wall -= 3600 * 1000; // user or time sync moves the clock back
      expect(freshServerLoadPct(node), isNull);
    });

    test('a wall clock set forwards only expires early', () {
      final node = stamped(45);
      clock.wall += 120000;
      expect(freshServerLoadPct(node), isNull);
    });

    test('a valid figure with a missing or malformed stamp is unknown', () {
      for (final node in <Map<String, dynamic>>[
        <String, dynamic>{kServerLoadPctKey: 45},
        <String, dynamic>{
          kServerLoadPctKey: 45,
          kServerLoadReceivedMonoKey: '0',
          kServerLoadReceivedWallKey: 0,
        },
        <String, dynamic>{
          kServerLoadPctKey: 45,
          kServerLoadReceivedMonoKey: 0.0,
          kServerLoadReceivedWallKey: clock.wall,
        },
        <String, dynamic>{
          kServerLoadPctKey: 45,
          // a monotonic stamp from the future cannot be from this process
          kServerLoadReceivedMonoKey: clock.mono + 1,
          kServerLoadReceivedWallKey: clock.wall,
        },
      ]) {
        expect(() => freshServerLoadPct(node), returnsNormally);
        expect(freshServerLoadPct(node), isNull, reason: '$node');
        expect(serverLoadTimeToExpiry(node), isNull);
      }
    });

    test('a fresh stamp never rescues a malformed figure', () {
      for (final raw in <Object?>[null, '45', 45.5, -5, 105, 47, true]) {
        expect(freshServerLoadPct(stamped(raw)), isNull, reason: '$raw');
      }
      expect(freshServerLoadPct(null), isNull);
      expect(freshServerLoadPct(_ThrowingMap()), isNull);
    });

    test('copyServerLoad keeps the original age; stripServerLoad removes all',
        () {
      final source = stamped(70);
      clock.advance(const Duration(seconds: 50));
      final copy = <String, dynamic>{'slug': 'x'};
      copyServerLoad(source, copy);
      expect(freshServerLoadPct(copy), 70);
      clock.advance(const Duration(seconds: 10));
      expect(freshServerLoadPct(copy), isNull,
          reason: 'the copy must not restart the 60 s window');
      stripServerLoad(copy);
      expect(copy.keys, <String>['slug']);
      final none = <String, dynamic>{};
      copyServerLoad(<String, dynamic>{kServerLoadPctKey: 70}, none);
      expect(none, isEmpty, reason: 'no stamp, nothing copied');
    });

    group('watch payload', () {
      List<Map<String, dynamic>> stampedListing() {
        final rx = serverLoadReceiptNow();
        return nodes
            .map((n) => <String, dynamic>{
                  ...n,
                  kServerLoadReceivedMonoKey: rx.mono,
                  kServerLoadReceivedWallKey: rx.wall,
                })
            .toList();
      }

      test('forwards load_pct and load_at only when valid and fresh', () {
        final listing = stampedListing();
        clock.advance(const Duration(seconds: 10, milliseconds: 500));
        final entries = watchCountryEntries(listing);
        expect(entries, hasLength(17), reason: 'no country may be dropped');
        for (final entry in entries) {
          final slug = entry['slug'] as String;
          if (valid.containsKey(slug)) {
            expect(entry[kServerLoadPctKey], valid[slug], reason: slug);
            // Receipt time in whole epoch seconds, floored.
            expect(entry[kWatchLoadAtKey], _FakeClock.wallStart ~/ 1000);
          } else {
            expect(entry.containsKey(kServerLoadPctKey), isFalse,
                reason: slug);
            expect(entry.containsKey(kWatchLoadAtKey), isFalse, reason: slug);
          }
          expect(
            entry.keys.toSet().difference(<String>{
              'slug',
              'name',
              'flag',
              kServerLoadPctKey,
              kWatchLoadAtKey,
            }),
            isEmpty,
            reason: 'no other key may reach the watch (stamps stay local)',
          );
        }
      });

      test('load_at is the phone age, not the raw receipt wall reading', () {
        final listing = stampedListing();
        clock.advance(const Duration(seconds: 20));
        clock.wall -= 3600 * 1000; // phone clock corrected backwards
        final entry = watchCountryEntries(listing)
            .firstWhere((e) => e['slug'] == 'low');
        // Current phone wall clock minus the 20 s age, not the pre-change
        // receipt reading.
        expect(entry[kWatchLoadAtKey], (clock.wall - 20000) ~/ 1000);
      });

      test('nothing is forwarded once the figure has expired on the phone', () {
        final listing = stampedListing();
        clock.advance(const Duration(seconds: 60));
        for (final entry in watchCountryEntries(listing)) {
          expect(entry.containsKey(kServerLoadPctKey), isFalse);
          expect(entry.containsKey(kWatchLoadAtKey), isFalse);
        }
      });

      test('still never forwards endpoints', () {
        final rx = serverLoadReceiptNow();
        final entries = watchCountryEntries(<Map<String, dynamic>>[
          <String, dynamic>{
            'slug': 'jp-1',
            'name': 'Japan',
            'flag': 'JP',
            'endpoint': '<ENDPOINT>',
            'stealth_endpoint': '<ENDPOINT>',
            'load_pct': 45,
            kServerLoadReceivedMonoKey: rx.mono,
            kServerLoadReceivedWallKey: rx.wall,
          },
        ]);
        expect(entries.single.keys.toSet(), <String>{
          'slug',
          'name',
          'flag',
          kServerLoadPctKey,
          kWatchLoadAtKey,
        });
      });
    });
  });

  group('Round LC turn 2: extreme integers and overflow (fake clock)', () {
    late _FakeClock clock;
    late ServerLoadClock saved;
    setUp(() {
      saved = serverLoadClock;
      clock = _FakeClock();
      serverLoadClock = clock;
    });
    tearDown(() => serverLoadClock = saved);

    // Sol's Wear value, the 64-bit extremes, 2^53 + 1 (the first integer a
    // JS double cannot hold) and 2^64 (too big for a Dart int: jsonDecode
    // returns a double for it on the VM).
    const extremes = <String>[
      '2305843011004173952',
      '9223372036854775807',
      '-9223372036854775808',
      '9007199254740993',
      '18446744073709551616',
      '-1',
    ];

    test('load_pct: every extreme decoded by jsonDecode is unknown', () {
      for (final text in extremes) {
        final decoded = jsonDecode('{"load_pct":$text}') as Map;
        expect(() => serverLoadPctOf(decoded), returnsNormally, reason: text);
        expect(serverLoadPctOf(decoded), isNull, reason: text);
      }
    });

    test('receipt stamps: extremes are unknown, never wrapped into freshness',
        () {
      final now = serverLoadReceiptNow();
      for (final text in extremes) {
        final v = jsonDecode(text);
        for (final node in <Map<String, dynamic>>[
          {kServerLoadPctKey: 45, kServerLoadReceivedMonoKey: v,
            kServerLoadReceivedWallKey: now.wall},
          {kServerLoadPctKey: 45, kServerLoadReceivedMonoKey: now.mono,
            kServerLoadReceivedWallKey: v},
        ]) {
          expect(() => freshServerLoadPct(node), returnsNormally,
              reason: '$node');
          expect(freshServerLoadPct(node), isNull, reason: '$node');
          expect(serverLoadTimeToExpiry(node), isNull, reason: '$node');
        }
      }
    });

    test('premise: without the window, a Long.MIN wall stamp wraps', () {
      // nowWall - (-2^63) overflows a 64-bit int to a NEGATIVE age, so max()
      // would fall back to the (fresh) monotonic age. The window prevents it.
      const minInt = -9223372036854775808;
      expect(clock.wall - minInt, isNegative);
    });

    test('stamp window edges', () {
      final now = serverLoadReceiptNow();
      Map<String, dynamic> at(int wall) => {
            kServerLoadPctKey: 45,
            kServerLoadReceivedMonoKey: now.mono,
            kServerLoadReceivedWallKey: wall,
          };
      expect(freshServerLoadPct(at(kServerLoadMinEpochMs - 1)), isNull);
      expect(freshServerLoadPct(at(kServerLoadMaxEpochMs + 1)), isNull);
      // In-window stamps are judged by age as usual.
      expect(freshServerLoadPct(at(now.wall)), 45);
    });

    test('watch payload never emits a load_at outside the window', () {
      for (final absurdWall in <int>[
        0, // phone clock reset to 1970 after the listing arrived
        kServerLoadMinEpochMs - 1000,
        kServerLoadMaxEpochMs + 1000, // phone clock jumped past 2100
      ]) {
        // Received with a sane clock; then the phone clock goes absurd. The
        // monotonic age keeps the figure fresh, so only the emit-side window
        // stops a load_at the watches would reject (or misread).
        clock.wall = _FakeClock.wallStart;
        final rx = serverLoadReceiptNow();
        clock.wall = absurdWall;
        final entries = watchCountryEntries(<Map<String, dynamic>>[
          <String, dynamic>{
            'slug': 'jp-1',
            'name': 'Japan',
            'flag': 'JP',
            kServerLoadPctKey: 45,
            kServerLoadReceivedMonoKey: rx.mono,
            kServerLoadReceivedWallKey: rx.wall,
          },
        ]);
        expect(entries, hasLength(1), reason: 'the country is never dropped');
        expect(entries.single.containsKey(kWatchLoadAtKey), isFalse,
            reason: 'wall=$absurdWall');
        expect(entries.single.containsKey(kServerLoadPctKey), isFalse,
            reason: 'wall=$absurdWall');
      }
    });
  });

  group('main.dart wiring (source contract)', () {
    final mainSource = File('lib/main.dart').readAsStringSync();

    test('the node projection keeps load only with a receipt stamp', () {
      final normalize = _slice(mainSource,
          start: 'Map<String, dynamic> _normalizeNodeItem(', end: '\n  }\n');
      expect(normalize, contains('serverLoadPctOf(item)'));
      expect(normalize, contains('if (load != null && loadReceipt != null)'));
      expect(normalize, contains('kServerLoadReceivedMonoKey: loadReceipt.mono'));
    });

    test('only the live /nodes reply stamps a receipt, once per listing', () {
      final parse = _slice(mainSource,
          start: 'Future<void> _parseNodesResponse(', end: '\n  }\n');
      expect(parse, contains('final loadReceipt = serverLoadReceiptNow();'));
      expect(parse, contains('loadReceipt: loadReceipt'));
      expect(parse, contains('_nodeListingRevision.value++'));
      expect('loadReceipt: '.allMatches(mainSource).length, 1,
          reason: 'no other caller may stamp load as freshly received');
    });

    test('stale load never comes back from the on-disk cache', () {
      final save = _slice(mainSource,
          start: 'Future<void> _saveCachedNodes()', end: '\n  }\n');
      final load = _slice(mainSource,
          start: 'Future<void> _loadCachedNodesFromDisk()', end: '\n  }\n');
      expect(save, contains('stripServerLoad(sanitized)'));
      expect(load, contains('stripServerLoad(normalized)'));
    });

    test('the load bar sits on the row under the name, not on the name row',
        () {
      // Owner 2026-09-29: the bar was on the name row and cut long names
      // ("United States (Chicag..."). It now follows the status text.
      final title = _slice(mainSource,
          start: 'Widget _buildServerTitleLine(', end: '\n  }\n');
      expect(title, isNot(contains('ServerLoadBar')),
          reason: 'the name row must not hold the bar');
      expect(title, isNot(contains('LiveServerLoadBar')));
      expect(title, contains('Expanded('),
          reason: 'the name keeps the full width');
      final bar = _slice(mainSource,
          start: 'Widget? _buildServerLoadBar(', end: '\n  }\n');
      expect(bar, contains('ServerLoadBar(node: node)'));
      expect(bar, contains('LiveServerLoadBar('));
      expect(bar, contains('listing: _nodeListingRevision'));
      final row = _slice(mainSource,
          start: 'Widget? _buildServerStatusRow(', end: '\n  }\n');
      expect(row, contains('_buildServerLoadBar('));
      expect(row, contains('Flexible(child: text)'));
      // Home row, picker rows and the free selector all use it.
      expect('_buildServerStatusRow('.allMatches(mainSource).length, 4,
          reason: 'definition plus home, picker and free selector');
      final picker = _slice(mainSource,
          start: 'void _showLocationPickerSheet(', end: '\n  }\n');
      expect(picker, contains('followLiveListing: true'));
    });

    test('the revision notifier is disposed with the state', () {
      final dispose = _slice(mainSource,
          start: '  @override\n  void dispose() {\n    _cancelSpeedTest',
          end: '\n  }\n');
      expect(dispose, contains('_nodeListingRevision.dispose()'));
    });
  });
}

class _FakeClock extends ServerLoadClock {
  static const int wallStart = 1790480000123;
  int mono = 5000;
  int wall = wallStart;

  void advance(Duration d) {
    mono += d.inMilliseconds;
    wall += d.inMilliseconds;
  }

  @override
  int monotonicMs() => mono;

  @override
  int wallMs() => wall;
}

class _ThrowingMap extends MapBase<String, Object?> {
  @override
  Object? operator [](Object? key) => throw StateError('hostile map');
  @override
  void operator []=(String key, Object? value) {}
  @override
  void clear() {}
  @override
  Iterable<String> get keys => const <String>[];
  @override
  Object? remove(Object? key) => null;
}

/// The text between the first [start] and the next [end] after it, or `''`.
String _slice(String source, {required String start, required String end}) {
  final from = source.indexOf(start);
  if (from < 0) return '';
  final to = source.indexOf(end, from + start.length);
  if (to < 0) return '';
  return source.substring(from, to + end.length);
}
