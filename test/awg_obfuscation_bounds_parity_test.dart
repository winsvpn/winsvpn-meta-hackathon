// AmneziaWG obfuscation bounds: cross-language parity.
//
// Why this file exists. On 2026-08-06 the AWG header keyspace was widened so
// H1..H4 could fill the whole little-endian uint32 that carries WireGuard's
// message type -- anything below 2^24 leaves the top byte zero and preserves
// the exact shape DPI matches on. That widening landed in Dart alone. Apple
// and Windows kept a 1,000,000 ceiling on the same fields, on the live connect
// path, so the first node to run AWG_STRONG_OBFUSCATION=1 would have been
// refused by every iOS, macOS and Windows client while Dart called the config
// usable. Nothing in test/ compared the native bounds to the Dart ones, which
// is the only reason it survived a full suite.
//
// So this is a contract test, not a unit test: `VpnConfigValidator` is the
// single source of truth, and every other implementation in the tree is read
// out of its own source and checked against it. A future widening that lands
// in one language fails here.
//
// Adding a platform is meant to be cheap: append a row to `_classicValidators`
// (an implementation that must match all three Dart bounds) or to
// `_headerCeilings` (an implementation that must at least agree on the uint32
// ceiling). Do not hardcode 4294967295 in an expectation -- compare against
// `VpnConfigValidator.awgHeaderMax`, or the test stops proving parity and
// starts asserting a number.

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/vpn_config_validation.dart';
import 'package:wins_vpn/winn_protocol_dispatch.dart';

/// A native implementation of the *classic* AWG validator -- the one on the
/// connect path that must agree with `VpnConfigValidator` on all three bounds.
class _ClassicValidator {
  const _ClassicValidator({
    required this.platforms,
    required this.path,
    required this.junkMaxSymbol,
    required this.headerMinSymbol,
    required this.headerMaxSymbol,
    required this.distinctnessMarker,
  });

  /// Which shipping platforms this one file gates. Apple's is shared.
  final String platforms;
  final String path;

  /// The names the file gives its three bounds. Each must be declared as a
  /// named constant assigned a literal, so this test can read the number back
  /// out; inlining the value is how the 2026-08-06 drift went unnoticed.
  final String junkMaxSymbol;
  final String headerMinSymbol;
  final String headerMaxSymbol;

  /// Text proving the file rejects two header types sharing a value.
  final String distinctnessMarker;
}

/// Matches `<symbol> = <literal>` across Swift and C++ declaration spellings,
/// capturing the literal with its digit separators and width suffix intact:
/// `awgHeaderMax = 4_294_967_295`, `kAwgHeaderMax = 4294967295ULL`.
///
/// Deliberately requires a real `=` assignment. An earlier version also
/// accepted `:`, which made it match the ternary
/// `is_header ? kAwgHeaderMin : 0ULL` as though it were a declaration -- it
/// read the right number only because the declaration happened to sit earlier
/// in the file. A test that can silently read the wrong constant is worse than
/// no test, and is the same defect class this file exists to close.
RegExp _boundPattern(String symbol) => RegExp(
      '\\b$symbol\\b\\s*=\\s*(0[xX][0-9a-fA-F]+|[0-9][0-9_]*)[uUlL]*',
    );

/// An implementation that only has to agree on the uint32 header ceiling.
/// These are the winn/3 datapath validators, which got the bound right first
/// and are the in-tree precedent the classic ones were corrected to match.
class _HeaderCeiling {
  const _HeaderCeiling({
    required this.label,
    required this.path,
    required this.anchor,
  });

  final String label;
  final String path;

  /// Locates the h1..h4 handling, so a ceiling belonging to some other field
  /// cannot satisfy the assertion by accident. Anchor on the *definition*, not
  /// a call site -- `_anchorWindow` only spans the parse that follows it.
  final String anchor;
}

/// How far past an anchor to look for the ceiling. Wide enough for every
/// implementation's h1..h4 parse, narrow enough that a neighbouring field's
/// bound cannot satisfy the assertion instead. The padding bounds these files
/// also declare are 0xFFFF, so they cannot be mistaken for the header ceiling.
const int _anchorWindow = 900;

const List<_ClassicValidator> _classicValidators = <_ClassicValidator>[
  _ClassicValidator(
    platforms: 'iOS + macOS',
    path: 'apple/WinsTunnelCore/WinsTunnelConfig.swift',
    junkMaxSymbol: 'awgJunkMax',
    headerMinSymbol: 'awgHeaderMin',
    headerMaxSymbol: 'awgHeaderMax',
    // Was `Set(headers).count == headers.count` while H1..H4 were scalars.
    // Ranges made the rule intersection rather than equality, which is the
    // engine's own `mergeWithDevice` test; for two scalars it still degrades
    // to equality, so the property being proved is unchanged.
    distinctnessMarker: 'headers[a].overlaps(headers[b])',
  ),
  _ClassicValidator(
    platforms: 'Windows',
    path: 'windows/runner/windows_tunnel_backend.cpp',
    junkMaxSymbol: 'kAwgJunkMax',
    headerMinSymbol: 'kAwgHeaderMin',
    headerMaxSymbol: 'kAwgHeaderMax',
    distinctnessMarker: 'colliding AWG header types',
  ),
];

const List<_HeaderCeiling> _headerCeilings = <_HeaderCeiling>[
  _HeaderCeiling(
    label: 'Android winn/3',
    path: 'android/app/src/main/kotlin/org/winsvpn/app/WinnEngineConfig.kt',
    anchor: 'HEADER_TYPE_KEYS.map',
  ),
  _HeaderCeiling(
    label: 'Linux winn/3',
    path: 'linux/runner/linux_winn_host.cc',
    anchor: 'kHeaderKeys',
  ),
  _HeaderCeiling(
    label: 'Windows winn/3',
    path: 'windows/runner/windows_winn_engine.cpp',
    anchor: 'kHeaderKeys',
  ),
  _HeaderCeiling(
    label: 'Apple winn/3',
    path: 'apple/EngineWrappers/WinsWinnPacketEngine.m',
    anchor: 'header_keys[4]',
  ),
  _HeaderCeiling(
    label: 'Dart winn/3 dispatch',
    path: 'lib/winn_protocol_dispatch.dart',
    // The definition, not the call site 350 lines above it.
    anchor: 'List<AwgHeaderSpec>? winnAwgHeaderTypes(',
  ),
];

/// Parses a decimal or hex source literal, tolerating the digit separators and
/// width suffixes each language spells differently: `4_294_967_295`,
/// `4294967295ULL`, `0xFFFFFFFFull`, `0xFFFFFFFFL`.
int _parseSourceLiteral(String raw) {
  final text = raw.trim().replaceAll('_', '');
  final hex = RegExp(r'^0[xX]([0-9a-fA-F]+)[uUlL]*$').firstMatch(text);
  if (hex != null) return int.parse(hex.group(1)!, radix: 16);
  final decimal = RegExp(r'^([0-9]+)[uUlL]*$').firstMatch(text);
  if (decimal == null) {
    throw FormatException('not a numeric source literal: $raw');
  }
  return int.parse(decimal.group(1)!);
}

/// The package root, found by walking up from the current directory to the
/// `pubspec.yaml` that names this package.
///
/// `flutter test` sets the cwd to the package root, so a plain relative path
/// usually works -- but "usually" is not good enough here. This test audits
/// files by path, and a path that silently resolves to nothing would let it
/// report success while checking no bound at all. That is precisely the defect
/// class it exists to close, so the resolution is explicit and it throws rather
/// than degrades.
final Directory _packageRoot = _resolvePackageRoot();

Directory _resolvePackageRoot() {
  final start = Directory.current.absolute;
  var dir = start;
  for (var hops = 0; hops < 16; hops++) {
    final pubspec = File('${dir.path}/pubspec.yaml');
    if (pubspec.existsSync() &&
        RegExp(r'^name:\s*wins_vpn\s*$', multiLine: true)
            .hasMatch(pubspec.readAsStringSync())) {
      return dir;
    }
    final parent = dir.parent;
    if (parent.path == dir.path) break;
    dir = parent;
  }
  throw StateError(
    'Could not find the wins_vpn package root by walking up from '
    '"${start.path}". This test audits native source files by path; without a '
    'root it would read nothing and report success.',
  );
}

String _read(String relativePath) {
  final file = File('${_packageRoot.path}/$relativePath');
  if (!file.existsSync()) {
    fail('$relativePath does not exist under the package root '
        '"${_packageRoot.path}" (cwd "${Directory.current.path}"). The parity '
        'contract cannot be checked against a file that cannot be read. If the '
        'file moved, update the table in this test rather than deleting the '
        'row.');
  }
  return file.readAsStringSync();
}

Map<String, dynamic> _configWithHeaders(List<int> headers) => <String, dynamic>{
      'client_private_key': 'iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=',
      'server_public_key': 'iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=',
      'preshared_key': '',
      'client_ip': '10.8.1.2',
      'dns': '10.8.1.1',
      'server_endpoint': '203.0.113.20:9110',
      'mtu': 1280,
      'obfuscation': <String, dynamic>{
        'Jc': 2,
        'Jmin': 10,
        'Jmax': 30,
        'S1': 16,
        'S2': 80,
        'S3': 16,
        'S4': 0,
        'H1': headers[0],
        'H2': headers[1],
        'H3': headers[2],
        'H4': headers[3],
      },
    };

Map<String, dynamic> _configWithJunk(String field, int value) {
  final config = _configWithHeaders(<int>[11, 22, 33, 44]);
  (config['obfuscation'] as Map<String, dynamic>)[field] = value;
  return config;
}

// ---------------------------------------------------------------------------
// The legacy-default injection, and why it needs a CROSS-FILE check.
//
// Two files independently hardcode the same eight numbers as the fallback for
// an absent obfuscation key:
//
//   lib/main.dart            `_buildRawAmneziaConfig`, which writes the
//                            AmneziaWG `[Interface]`:  H1 = ${obfs['H1'] ?? 11}
//   lib/winn_protocol_dispatch.dart
//                            `winnAwgHeaderTypes` / `winnAwgPaddingSizes`,
//                            which build the table the WINN engine classifies
//                            with:                     'H1': 11
//
// These are not two defaults that merely happen to match. They must be the same
// table, because one engine produces the datagrams the other classifies. The
// dispatch file says so in prose ("so the table the Winn engine classifies with
// can never disagree with the header types the AmneziaWG engine is actually
// using") -- but prose is not a check, and nothing in the suite compares them.
//
// A bounds table cannot catch this. Every number involved is comfortably inside
// every bound; the failure is two in-range tables disagreeing. If someone edits
// one file's defaults and not the other's, the Winn engine matches the header
// word at values the AWG engine never writes. `winnAwgPaddingSizes`' own doc
// states the consequence for the padding half exactly: omitting a nonzero s4
// silently kills the TRANSPORT counters -- the ones `transport_observed_both_ways`
// is built from, which WINN_PROTOCOL_PLATFORM_PLAN.md names as the only field a
// route-promotion gate may use. A gate reading a dead counter passes a tunnel
// carrying nothing. Nothing throws, nothing logs, and the tunnel looks up.
//
// So this is the same defect class as the native-bound drift above, one layer
// over: a value re-derived in two places with no check that the derivations
// agree. It is asserted here by reading both files, never by restating the
// numbers -- restating them would just add a third copy.
// ---------------------------------------------------------------------------

/// The `[Interface]` obfuscation keys `_buildRawAmneziaConfig` defaults with a
/// bare integer literal. `Jc`/`Jmin`/`Jmax` are excluded on purpose: that
/// function defaults them from named constants (`_defaultAwgJc`), and the
/// dispatch helpers do not default them at all, so there is no pair to compare.
const List<String> _headerDefaultKeys = <String>['H1', 'H2', 'H3', 'H4'];
const List<String> _paddingDefaultKeys = <String>['S1', 'S2', 'S3', 'S4'];

/// Reads `KEY = ${obfs['KEY'] ?? <int>}` out of `_buildRawAmneziaConfig`'s
/// interpolated `[Interface]` block in `lib/main.dart`.
int _awgInterfaceDefault(String source, String key) {
  final match = RegExp(
    '\\b$key\\s*=\\s*\\\$\\{obfs\\[\'$key\'\\]\\s*\\?\\?\\s*([0-9]+)\\}',
  ).firstMatch(source);
  if (match == null) {
    fail('lib/main.dart no longer writes "[Interface] $key" as '
        "\"$key = \\\${obfs['$key'] ?? <literal>}\". That line is one half of "
        'the default table the Winn classifier mirrors. If the writer changed '
        'shape, update this extractor -- do not drop the row, or the two '
        'tables go back to being uncompared.');
  }
  return int.parse(match.group(1)!);
}

/// Reads `'KEY': <int>` out of the `defaults` map inside the named dispatch
/// helper, anchored so a neighbouring function's map cannot answer instead.
int _dispatchDefault(String source, String anchor, String key) {
  // Support both old and new signatures for parity during transition.
  var anchorAt = source.indexOf(anchor);
  if (anchorAt < 0) {
    // Fallback to new spec type if old int type not found.
    final fallback = 'List<AwgHeaderSpec>? winnAwgHeaderTypes(';
    anchorAt = source.indexOf(fallback);
  }
  if (anchorAt < 0) {
    fail('lib/winn_protocol_dispatch.dart no longer defines "$anchor". '
        'Update the anchor rather than dropping the check.');
  }
  final end = (anchorAt + _anchorWindow).clamp(0, source.length);
  final match = RegExp("'$key'\\s*:\\s*([0-9]+)")
      .firstMatch(source.substring(anchorAt, end));
  if (match == null) {
    fail('"$anchor" no longer carries a literal default for "$key" within '
        '$_anchorWindow characters. The defaults it injects are the table the '
        'AmneziaWG engine is actually using; they must stay readable from '
        'source so they can be compared with it.');
  }
  return int.parse(match.group(1)!);
}

/// A served `winn/3` config that can start on Linux, with `obfuscation`
/// replaced by [obfs]. Passing null removes the key entirely.
///
/// Deliberately minimal and local: this file's other helper builds configs for
/// `VpnConfigValidator`, which is a different consumer with different required
/// fields.
Map<String, dynamic> _winn3Config(Map<String, dynamic>? obfs) {
  final config = <String, dynamic>{
    'protocol_version': kWinnProtocolV3,
    'protocol_params': <String, dynamic>{},
    'server_endpoint': '203.0.113.7:51820',
    'client_ip': '10.8.1.3',
    'mtu': 1280,
    'dns': '10.8.1.1',
    'stealth_active': false,
  };
  if (obfs != null) config['obfuscation'] = obfs;
  return config;
}

/// Reads `h1`..`h4` / `s1`..`s4` back out of an emitted `[winn]` INI section.
Map<String, String> _winnSection(String iniSection) {
  final out = <String, String>{};
  for (final line in iniSection.split('\n')) {
    final trimmed = line.trim();
    final split = trimmed.indexOf('=');
    if (trimmed.startsWith('[') || split < 0) continue;
    out[trimmed.substring(0, split).trim().toLowerCase()] =
        trimmed.substring(split + 1).trim();
  }
  return out;
}

void main() {
  group('Dart is the source of truth, and it bounds rather than samples', () {
    // These assert the boundary itself. A test that only tries H1 = 11, or
    // only tries one arbitrary large value, proves nothing about where the
    // ceiling actually sits.
    test('accepts exactly awgHeaderMax and rejects one past it', () {
      final max = VpnConfigValidator.awgHeaderMax;
      expect(
        VpnConfigValidator.isUsable(
          _configWithHeaders(<int>[max, max - 1, max - 2, max - 3]),
        ),
        isTrue,
        reason: 'the documented ceiling must itself be accepted',
      );
      expect(
        VpnConfigValidator.isUsable(
          _configWithHeaders(<int>[max + 1, 22, 33, 44]),
        ),
        isFalse,
        reason: 'one past the ceiling must be refused',
      );
      expect(max, equals(0xFFFFFFFF),
          reason: 'the ceiling is the full uint32 a header type occupies');
    });

    test('accepts exactly awgHeaderMin and rejects one below it', () {
      final min = VpnConfigValidator.awgHeaderMin;
      expect(
        VpnConfigValidator.isUsable(
          _configWithHeaders(<int>[min, min + 1, min + 2, min + 3]),
        ),
        isTrue,
      );
      expect(
        VpnConfigValidator.isUsable(
          _configWithHeaders(<int>[min - 1, 22, 33, 44]),
        ),
        isFalse,
        reason: '1..4 are WireGuard message types and must stay excluded',
      );
      expect(min, equals(5));
    });

    test('rejects colliding header values at any magnitude', () {
      expect(
        VpnConfigValidator.isUsable(_configWithHeaders(<int>[11, 11, 33, 44])),
        isFalse,
      );
      expect(
        VpnConfigValidator.isUsable(_configWithHeaders(
            <int>[3221225473, 3221225473, 4026531843, 1073741828])),
        isFalse,
      );
    });

    test('keeps accepting the legacy 11/22/33/44 set', () {
      // Load-bearing. These parameters are not negotiated, so rejecting the
      // legacy set locks out every peer still configured with it.
      final legacy = _configWithHeaders(<int>[11, 22, 33, 44]);
      expect(VpnConfigValidator.isUsable(legacy), isTrue);
    });

    test('the widened header ceiling does not leak into the junk fields', () {
      final junkMax = VpnConfigValidator.awgJunkMax;
      expect(VpnConfigValidator.isUsable(_configWithJunk('S2', junkMax)),
          isTrue);
      expect(VpnConfigValidator.isUsable(_configWithJunk('S2', junkMax + 1)),
          isFalse);
      expect(
        VpnConfigValidator.isUsable(
            _configWithJunk('S2', VpnConfigValidator.awgHeaderMax)),
        isFalse,
        reason: 'junk fields are packet and byte counts, not header types',
      );
      expect(junkMax, lessThan(VpnConfigValidator.awgHeaderFullWidthMin),
          reason: 'the junk ceiling is deliberately below 2^24');
    });
  });

  group('native connect-path validators match the Dart bounds', () {
    for (final validator in _classicValidators) {
      test('${validator.platforms} (${validator.path})', () {
        final source = _read(validator.path);

        int extract(String symbol) {
          final matches = _boundPattern(symbol).allMatches(source).toList();
          if (matches.isEmpty) {
            fail('${validator.path} no longer declares "$symbol" as a named '
                'constant assigned a literal. It must, so parity is checkable '
                '-- inlining the number is how the 2026-08-06 drift went '
                'unnoticed.');
          }
          // Identical re-declarations are harmless; conflicting ones mean this
          // test would be picking one number out of several and calling it the
          // bound. Refuse to guess.
          final values =
              matches.map((m) => _parseSourceLiteral(m.group(1)!)).toSet();
          if (values.length != 1) {
            fail('${validator.path} assigns "$symbol" more than one distinct '
                'value $values. Parity cannot be checked against an ambiguous '
                'constant.');
          }
          return values.single;
        }

        expect(
          extract(validator.headerMaxSymbol),
          equals(VpnConfigValidator.awgHeaderMax),
          reason: '${validator.platforms} would refuse a config Dart accepts, '
              'on the live connect path, the moment a node runs '
              'AWG_STRONG_OBFUSCATION=1',
        );
        expect(
          extract(validator.headerMinSymbol),
          equals(VpnConfigValidator.awgHeaderMin),
          reason: '${validator.platforms} must exclude WireGuard reserved 1..4',
        );
        expect(
          extract(validator.junkMaxSymbol),
          equals(VpnConfigValidator.awgJunkMax),
          reason: 'the header widening must not leak into packet/byte counts',
        );
        expect(
          source,
          contains(validator.distinctnessMarker),
          reason: '${validator.platforms} must reject two header types sharing '
              'a value; Dart does, and a collision leaves the peer unable to '
              'tell a handshake from a transport packet',
        );
      });
    }

    test('the header ceiling and the junk ceiling are separate constants', () {
      // The original defect was a single ceiling applied to every obfuscation
      // field at once. Asserting the two bounds are distinct constants, and
      // that the header one clears 2^24, catches a re-collapse in any language
      // without depending on how a given file spells its expressions -- an
      // earlier version of this check keyed on the Swift-only text `value.h1`
      // and so silently checked nothing at all on Windows.
      for (final validator in _classicValidators) {
        final source = _read(validator.path);
        final header = _boundPattern(validator.headerMaxSymbol).firstMatch(source);
        final junk = _boundPattern(validator.junkMaxSymbol).firstMatch(source);
        expect(header, isNotNull, reason: '${validator.path} header ceiling');
        expect(junk, isNotNull, reason: '${validator.path} junk ceiling');

        final headerValue = _parseSourceLiteral(header!.group(1)!);
        final junkValue = _parseSourceLiteral(junk!.group(1)!);
        expect(
          headerValue,
          isNot(equals(junkValue)),
          reason: '${validator.path} bounds header types and packet/byte '
              'counts by the same number again, which is the 2026-08-06 '
              'regression exactly',
        );
        expect(
          headerValue,
          greaterThan(VpnConfigValidator.awgHeaderFullWidthMin),
          reason: '${validator.path} must permit values that fill all four '
              'header bytes',
        );
      }
    });
  });

  group('every winn/3 header validator agrees on the uint32 ceiling', () {
    for (final ceiling in _headerCeilings) {
      test(ceiling.label, () {
        final source = _read(ceiling.path);
        final anchorAt = source.indexOf(ceiling.anchor);
        expect(anchorAt, greaterThanOrEqualTo(0),
            reason: 'anchor "${ceiling.anchor}" not found in ${ceiling.path}; '
                'update the table rather than dropping the row');

        final end = (anchorAt + _anchorWindow).clamp(0, source.length);
        final region = source.substring(anchorAt, end);
        final literals = RegExp(r'0[xX][0-9a-fA-F]+[uUlL]*')
            .allMatches(region)
            .map((m) => _parseSourceLiteral(m.group(0)!))
            .toSet();

        expect(
          literals,
          contains(VpnConfigValidator.awgHeaderMax),
          reason: '${ceiling.label} bounds h1..h4 by something other than '
              'VpnConfigValidator.awgHeaderMax. Found: $literals',
        );
      });
    }
  });

  group('the injected legacy defaults are ONE table, not two copies of one',
      () {
    // The bounds groups above prove every implementation agrees on the RANGE.
    // These prove the two implementations that inject a default when a value is
    // absent agree on the VALUE — AND, after 2026-08-08, that winn/3 no longer
    // injects one at all. h1..h4 are now MANDATORY for winn/3 (the transport
    // convergence gate cannot fire without them); an absent table must be refused,
    // not silently filled with 11/22/33/44. The AmneziaWG [Interface] writer in
    // lib/main.dart still defaults for winn/1 compatibility, but winnAwgHeaderTypes
    // must NOT — a silently filled legacy quad is a disabled gate behind a
    // working-looking tunnel. See docs/handoff/WINN3_HEADER_MANDATORY_DECISION_20260808.md.

    test('winn/3 now REQUIRES h1..h4 — missing is refused, not defaulted',
        () {
      // Dispatch must refuse when headers are absent; the old behaviour silently
      // filled 11/22/33/44, which disabled the convergence gate.
      expect(winnAwgHeaderTypes(<String, dynamic>{'obfuscation': <String, dynamic>{}}), isNull);
      expect(winnAwgHeaderTypes(<String, dynamic>{}), isNull);
      final decision = resolveWinnProtocolStartForServedConfig(
        config: _winn3Config(null),
      );
      expect(decision.supported, isFalse);
      expect(decision.reason, WinnRefusalReason.headerTypesInvalid);
      expect(decision.message.toLowerCase(), contains('h1'));
      // And the source must no longer contain a default injection for headers.
      final dispatchSource = _read('lib/winn_protocol_dispatch.dart');
      expect(dispatchSource, contains('h1..h4 are REQUIRED for winn/3'));
      // The old header-defaults literal was `const defaults = <String, int>{'H1': 11, 'H2': 22,`
      // inside winnAwgHeaderTypes. That must be gone; padding defaults remain.
      final headerDefaultsAnchor = dispatchSource.indexOf('List<AwgHeaderSpec>? winnAwgHeaderTypes(');
      final headerWindow = dispatchSource.substring(
        headerDefaultsAnchor,
        (headerDefaultsAnchor + 900).clamp(0, dispatchSource.length),
      );
      expect(headerWindow, isNot(contains("'H1': 11")),
          reason: 'winnAwgHeaderTypes must not contain a defaults map for h1..h4 anymore; padding defaults are still expected');
    });

    test('the Winn padding defaults equal the AmneziaWG [Interface] defaults',
        () {
      final mainSource = _read('lib/main.dart');
      final dispatchSource = _read('lib/winn_protocol_dispatch.dart');

      for (final key in _paddingDefaultKeys) {
        expect(
          _dispatchDefault(
              dispatchSource, 'List<int>? winnAwgPaddingSizes(', key),
          equals(_awgInterfaceDefault(mainSource, key)),
          reason: 'winnAwgPaddingSizes injects a different default for $key '
              'than _buildRawAmneziaConfig writes into [Interface]. s1..s4 are '
              'the OFFSETS the classifier reads the header word at, so a '
              'mismatch here silently kills the transport counters a '
              'route-promotion gate is allowed to read.',
        );
      }
    });

    test('the AmneziaWG [Interface] defaults are still exactly the legacy quad',
        () {
      // Pinned deliberately. The _buildRawAmneziaConfig writer still defaults
      // H1..H4 to 11/22/33/44 for winn/1 and for any path that does not go
      // through winn/3 dispatch (e.g. classic AWG). What changed is that
      // winnAwgHeaderTypes no longer mirrors that default — it refuses instead.
      // If the interface defaults ever change, that is a decision about the
      // shipping AmneziaWG profile, not about the winn/3 gate.
      final mainSource = _read('lib/main.dart');
      for (final key in _headerDefaultKeys) {
        expect(
          _awgInterfaceDefault(mainSource, key),
          equals(<String, int>{'H1': 11, 'H2': 22, 'H3': 33, 'H4': 44}[key]),
          reason: 'the AmneziaWG [Interface] defaults are the legacy quad; winn/3 dispatch now refuses rather than mirrors them',
        );
      }
    });
  });

  group('an unusable header table fails CLOSED and says so', () {
    // The claim this group exists to settle is "an out-of-range or malformed
    // header silently disables the winn path". It does not, and the tests below
    // are what keep that true: `winnAwgHeaderTypes` returns null, but null is a
    // sentinel that is converted immediately into a NAMED refusal carrying a
    // user-facing sentence and an empty section. `WinnStartDecision` has no
    // representation for "fall back to AmneziaWG" at all.
    //
    // The risk worth guarding is therefore not that the refusal is silent
    // today; it is that a later refactor makes it silent by treating the null
    // as "no opinion" and continuing. These assertions fail if that happens.
    //
    // test/winn_protocol_dispatch_test.dart already covers that out-of-range
    // and colliding tables are refused. What it does not assert -- and what
    // makes the refusal SURFACED rather than merely returned -- is the payload:
    // a reason code fit to persist, a non-empty message, and no section.

    final unusable = <String, Map<String, dynamic>>{
      'out of range (one past the uint32 ceiling)': <String, dynamic>{
        'H1': 11,
        'H2': 22,
        'H3': 33,
        'H4': 0x100000000,
      },
      'negative': <String, dynamic>{'H1': -1, 'H2': 22, 'H3': 33, 'H4': 44},
      'not a number at all': <String, dynamic>{
        'H1': 'not-a-number',
        'H2': 22,
        'H3': 33,
        'H4': 44,
      },
      'colliding': <String, dynamic>{'H1': 11, 'H2': 11, 'H3': 33, 'H4': 44},
    };

    unusable.forEach((label, obfs) {
      test('$label is refused with a reason a human and a log can both read',
          () {
        expect(winnAwgHeaderTypes(<String, dynamic>{'obfuscation': obfs}),
            isNull,
            reason: 'precondition: this table must be the unusable case');

        final decision = resolveWinnProtocolStartForServedConfig(
          config: _winn3Config(obfs),
        );

        expect(decision.supported, isFalse);
        expect(
          decision.reason,
          WinnRefusalReason.headerTypesInvalid,
          reason: 'the refusal must be NAMED. main.dart persists '
              '"winn3_refused_${WinnRefusalReason.headerTypesInvalid.code}" as '
              'a diagnostic, so an unnamed refusal is an outage with no '
              'record of why.',
        );
        expect(
          decision.message.trim(),
          isNotEmpty,
          reason: 'main.dart shows this string to the user. An empty message '
              'is a connection that stops with no explanation -- which is what '
              '"silently disabling the winn path" would actually look like.',
        );
        expect(
          decision.iniSection,
          isEmpty,
          reason: 'a refusal must carry no section. A non-empty section on an '
              'unsupported decision is the shape a caller could start anyway.',
        );
      });
    });

    test('the anti-downgrade property: a refusal is never a classic-AWG '
        'fallback', () {
      // The strongest argument for leaving the null as it is. Turning this
      // refusal into a fallback would hand the gateway a winn/1 session it
      // never negotiated -- a silent downgrade, which is strictly worse than
      // the failed connection it replaces.
      final decision = resolveWinnProtocolStartForServedConfig(
        config: _winn3Config(<String, dynamic>{
          'H1': 11,
          'H2': 11,
          'H3': 33,
          'H4': 44,
        }),
      );
      expect(decision.supported, isFalse);
      expect(decision.iniSection, isEmpty);
      expect(
        () => winnSectionForTunnelConfig(
          operatingSystem: 'linux',
          config: _winn3Config(<String, dynamic>{
            'H1': 11,
            'H2': 11,
            'H3': 33,
            'H4': 44,
          }),
        ),
        throwsA(isA<StateError>()),
        reason: 'the config builder is the second gate: it must THROW for a '
            'winn/3 config it cannot build a section for, so the property '
            'survives the dispatch seam being reordered or bypassed',
      );
    });

    test('an ABSENT table is now REFUSED — it would disable the convergence gate',
        () {
      // WINN_MANDATORY_HEADERS 2026-08-08: h1..h4 are REQUIRED for winn/3.
      // An absent table previously returned a usable table built out of literals
      // (11/22/33/44) and reported success, with nothing recording that the
      // values were invented. That silently disabled the convergence gate:
      // transport_observed_both_ways can never fire on a blind classifier, so a
      // dead tunnel was reported as connected. Now it is refused loud.
      final decision = resolveWinnProtocolStartForServedConfig(
        config: _winn3Config(null),
      );
      expect(decision.supported, isFalse);
      expect(decision.reason, WinnRefusalReason.headerTypesInvalid);
      expect(decision.message.toLowerCase(), contains('h1'));
      expect(decision.message.toLowerCase(), contains('required'));
      expect(decision.iniSection, isEmpty);
      expect(winnAwgHeaderTypes(<String, dynamic>{'obfuscation': <String, dynamic>{}}), isNull);
    });

    test('a PARTIAL table is now REFUSED — per-key defaulting is gone', () {
      // After 2026-08-08 per-key defaulting is removed for winn/3 headers.
      // A served object missing one header previously yielded a mixed table that
      // matched NEITHER the node's profile nor the legacy set — and still
      // reported success, disabling the gate for exactly the configs that are
      // hardest to reproduce. Now it is refused and names the missing field.
      final decision = resolveWinnProtocolStartForServedConfig(
        config: _winn3Config(<String, dynamic>{'H1': 3221225473}),
      );
      expect(decision.supported, isFalse);
      expect(decision.reason, WinnRefusalReason.headerTypesInvalid);
      expect(decision.message.toLowerCase(), contains('h2'));
      expect(winnAwgHeaderTypes(<String, dynamic>{'obfuscation': <String, dynamic>{'H1': 3221225473}}), isNull);
    });
  });

  // -------------------------------------------------------------------------
  // H1..H4 AS RANGES.
  //
  // `device/magic-header.go` in the pinned engine
  // (amneziawg-go@v0.0.0-20260309041639-0569d899c9bf) parses `h4=<start>-<end>`
  // on all four header fields, and `device/send.go:529` calls `Generate()`
  // inside `RoutineEncryption` -- once PER PACKET. A range therefore makes the
  // header word vary per datagram, which a constant cannot do at any width.
  //
  // Measured on the two-ended lab rig, 100 transport datagrams per direction,
  // modal size class only: legacy constants and full-width per-node constants
  // BOTH leave payload offsets 0..3 at exactly one value per direction; the
  // four disjoint range quarters take 50-86 values. Offsets 4..7 are constant
  // in every configuration -- WireGuard's receiver index, in the clear by
  // protocol design, which no AmneziaWG parameter touches.
  //
  // These parameters are NOT negotiated, so this group's first duty is the
  // backward-compatibility one: every spelling the fleet already runs must keep
  // validating, on every platform, unchanged.
  // -------------------------------------------------------------------------
  group('H1..H4 accept a range as well as a scalar', () {
    // The four disjoint quarters the generator emits under AWG_HEADER_RANGES.
    const rangeQuad = <String>[
      '16777216-1086324735',
      '1086324736-2155872255',
      '2155872256-3225419775',
      '3225419776-4294967295',
    ];

    Map<String, dynamic> configWithSpecs(List<dynamic> specs) {
      final config = _configWithHeaders(<int>[11, 22, 33, 44]);
      final obfuscation = config['obfuscation'] as Map<String, dynamic>;
      for (var i = 0; i < 4; i++) {
        obfuscation['H${i + 1}'] = specs[i];
      }
      return config;
    }

    test('the legacy quad and full-width constants still validate', () {
      // The whole point of the change. A regression here is a fleet lockout,
      // not a failed test.
      expect(VpnConfigValidator.isUsable(_configWithHeaders(<int>[11, 22, 33, 44])),
          isTrue,
          reason: 'the set the fleet runs today must never stop validating');
      expect(
        VpnConfigValidator.isUsable(_configWithHeaders(
            <int>[1856103457, 2934857201, 3471928465, 4013856219])),
        isTrue,
      );
      // Both spellings of the same scalar, since the hub serves a JSON number
      // and an INI document carries text.
      expect(VpnConfigValidator.isUsable(
              configWithSpecs(<dynamic>['11', '22', '33', '44'])),
          isTrue);
    });

    test('a range validates, and parses back to its endpoints', () {
      expect(VpnConfigValidator.isUsable(configWithSpecs(rangeQuad)), isTrue);
      final spec = VpnConfigValidator.parseAwgHeaderSpec(rangeQuad.last)!;
      expect(spec.start, 3225419776);
      expect(spec.end, VpnConfigValidator.awgHeaderMax);
      expect(spec.isRange, isTrue);
      expect(spec.spec, rangeQuad.last,
          reason: 'the round-trip spelling must match the engine GenSpec()');
    });

    test('a scalar is the degenerate range, exactly as the engine stores it',
        () {
      final spec = VpnConfigValidator.parseAwgHeaderSpec(44)!;
      expect(spec.start, 44);
      expect(spec.end, 44);
      expect(spec.isRange, isFalse);
      expect(spec.spec, '44',
          reason: 'a scalar must not acquire a "-" on the way to the engine');
    });

    test('a mixed profile is usable -- ranges are per field, not per profile',
        () {
      expect(
        VpnConfigValidator.isUsable(
            configWithSpecs(<dynamic>[11, 22, 33, '3225419776-4294967295'])),
        isTrue,
      );
    });

    test('OVERLAP is refused, because the engine refuses it', () {
      // `mergeWithDevice` in device/uapi.go: "headers must not overlap". A
      // validator that accepted this would hand the host a config that cannot
      // start -- and an unstartable config is the failure shape this whole
      // file exists to prevent.
      expect(
        VpnConfigValidator.validationErrors(configWithSpecs(<dynamic>[
          '1000-5000',
          '4000-9000',
          '2155872256-3225419775',
          '3225419776-4294967295',
        ])),
        contains('obfuscation.H1/H2/H3/H4'),
      );
      // Touching at a single value is still an overlap.
      expect(
        VpnConfigValidator.validationErrors(configWithSpecs(<dynamic>[
          '100-200',
          '200-300',
          '2155872256-3225419775',
          '3225419776-4294967295',
        ])),
        contains('obfuscation.H1/H2/H3/H4'),
      );
      // And a scalar sitting inside a range is the same defect.
      expect(
        VpnConfigValidator.validationErrors(configWithSpecs(<dynamic>[
          '1000-5000',
          3000,
          '2155872256-3225419775',
          '3225419776-4294967295',
        ])),
        contains('obfuscation.H1/H2/H3/H4'),
      );
    });

    test('malformed range spellings are refused per field', () {
      const malformed = <String, String>{
        '4000-1000': 'end before start',
        '1-2-3': 'three parts',
        '16777216-': 'empty end',
        '-16777216': 'empty start',
        '-': 'separator only',
        '16777216-4294967296': 'end one past the uint32 ceiling',
        '1-1086324735': 'start below awgHeaderMin',
        '1000 - 4000': 'internal whitespace',
        '0x10-0x20': 'hex',
      };
      malformed.forEach((spelling, why) {
        expect(VpnConfigValidator.parseAwgHeaderSpec(spelling), isNull,
            reason: '$spelling ($why) must not parse');
        expect(
          VpnConfigValidator.validationErrors(
              configWithSpecs(<dynamic>[spelling, 22, 33, 44])),
          contains('obfuscation.H1'),
          reason: '$spelling ($why) must be refused, and named',
        );
      });
    });

    test('the engine cannot be handed a range width that panics it', () {
      // `Generate()` computes `high := int64(h.end - h.start + 1)` in UINT32
      // arithmetic, so a span of exactly 2^32 wraps to 0 and crypto/rand.Int
      // panics ("argument to Int is <= 0"). Confirmed by executing the pinned
      // device/magic-header.go verbatim.
      //
      // awgHeaderMin makes that span unreachable, so this asserts the
      // INVARIANT rather than a rejection -- if someone lowers the floor to 0,
      // this fails and says why, instead of arming a remote panic.
      expect(
        VpnConfigValidator.awgHeaderMax -
                VpnConfigValidator.awgHeaderMin +
                1 <=
            VpnConfigValidator.awgHeaderMaxRangeWidth,
        isTrue,
        reason: 'the widest range this validator can accept must stay inside '
            'the engine uint32 width computation',
      );
    });

    // Every native connect-path validator has to accept the same two
    // spellings. Dart is the only gate Android and Linux classic-AWG have, but
    // Apple and Windows parse the document themselves, so a platform that
    // learns ranges late refuses a node the hub already serves -- which is a
    // per-platform lockout that no throughput test would show.
    const rangeCapableValidators = <String, List<String>>{
      'apple/WinsTunnelCore/WinsTunnelConfig.swift': <String>[
        'parsedHeaderSpec',
        'WinsAwgHeaderSpec',
        'func overlaps(',
      ],
      'windows/runner/windows_tunnel_backend.cpp': <String>[
        'AwgHeaderSpec',
        'kAwgHeaderSpecMaxDigits',
        'header_specs',
      ],
    };

    rangeCapableValidators.forEach((path, markers) {
      test('$path parses a range, not just an integer', () {
        final source = _read(path);
        for (final marker in markers) {
          expect(source, contains(marker),
              reason: '$path must carry the range parse ($marker); a native '
                  'validator that still assumes a scalar refuses every node '
                  'the generator gives a range, and these parameters are not '
                  'negotiated');
        }
      });
    });

    test('the generator can emit a range, behind its own flag', () {
      final generator = _read('server/wins_data_plane_setup_ONETOUCH.sh');
      expect(generator, contains('AWG_HEADER_RANGES'));
      // %s, not %d: a range is a string. This is the line that would silently
      // truncate a range back to an integer if someone "tidied" it.
      for (final field in <String>['H1', 'H2', 'H3', 'H4']) {
        expect(generator, contains('"AWG_$field=%s"'),
            reason: 'AWG_$field must be written with %s so a range survives');
      }
      // The registration payload cannot use --argjson for a range: jq would
      // fail to parse "16777216-1086324735" as JSON. A scalar must still
      // travel as a JSON NUMBER, which is what the `hdr` filter preserves.
      expect(generator, contains(r'--arg h1 "${AWG_H1_DEFAULT}"'));
      expect(generator, contains('def hdr: if test("-") then . else tonumber end;'));
      expect(generator, isNot(contains(r'--argjson h1 "${AWG_H1_DEFAULT}"')),
          reason: '--argjson cannot carry a range');
      // The flag must stay off. Turning it on is a deliberate act with a
      // documented winn/3 consequence, not a default.
      expect(generator, contains(r'AWG_HEADER_RANGES="${AWG_HEADER_RANGES:-0}"'));
      expect(
          generator, contains(r'AWG_STRONG_OBFUSCATION="${AWG_STRONG_OBFUSCATION:-0}"'));
    });

    test('the hub can serve a range without rewriting it', () {
      // `parse_obfuscation` is atomic and fail-closed: it either reproduces
      // every parameter a node reported or refuses the node loudly. Before
      // this change a range was "non-numeric" and took the whole profile down
      // with it, so the hub is a hard gate on the feature.
      final hub = _read('server/wins_control_plane_setup_ONETOUCH.sh');
      expect(hub, contains('AWG_OBFUSCATION_RANGE_KEYS'));
      expect(hub, contains(r're.fullmatch(r"([0-9]+)-([0-9]+)", text)'));
      // Ranges are meaningful ONLY on H1..H4. The engine parses Jc/Jmin/Jmax
      // and S1..S4 as plain integers, so a range there is malformed and must
      // stay refused.
      expect(hub, contains('frozenset({"H1", "H2", "H3", "H4"})'));
      expect(hub, contains('raise ValueError("range-too-wide")'),
          reason: 'the hub must refuse the 2^32 span that panics the engine');
    });

    test('winn/3 ACCEPTS a range and classifies by interval membership', () {
      // The winn/3 datapath now classifies by interval membership, not exact
      // value. A non-overlapping range quad (the four disjoint quarters the
      // generator emits under AWG_HEADER_RANGES) is therefore accepted on the
      // winn path as well as the classic path. Failing closed was correct
      // when the classifier could only express a point; now that all five
      // classifiers plus the Go datapath have learned ranges, the silent
      // blackout behind a completed handshake is gone.
      final config = _winn3Config(<String, dynamic>{
        'H1': '16777216-1086324735',
        'H2': '1086324736-2155872255',
        'H3': '2155872256-3225419775',
        'H4': '3225419776-4294967295',
      });
      final specs = winnAwgHeaderTypes(config);
      expect(specs, isNotNull,
          reason: 'winn/3 must now accept a valid non-overlapping range quad');
      expect(specs!.length, 4);
      expect(specs[0].isRange, isTrue);
      expect(specs[0].spec, '16777216-1086324735');
      expect(specs[3].spec, '3225419776-4294967295');
      // Overlap must still be refused -- the engine refuses it, and a
      // classifier that accepted overlapping intervals would be ambiguous.
      final overlapping = _winn3Config(<String, dynamic>{
        'H1': '1000-5000',
        'H2': '4000-9000',
        'H3': '2155872256-3225419775',
        'H4': '3225419776-4294967295',
      });
      expect(winnAwgHeaderTypes(overlapping), isNull,
          reason: 'overlapping ranges must remain refused');
      final decision = resolveWinnProtocolStartForServedConfig(
        config: config,
      );
      expect(decision.supported, isTrue,
          reason: 'winn/3 must accept a range rather than misclassify it');
      expect(decision.reason.code, 'none');
      expect(decision.iniSection, isNotEmpty);
      final section = _winnSection(decision.iniSection);
      expect(section['h1'], '16777216-1086324735');
      expect(section['h2'], '1086324736-2155872255');
      expect(section['h3'], '2155872256-3225419775');
      expect(section['h4'], '3225419776-4294967295');
      // Must not become a downgrade to classic AWG.
      //
      // 2026-08-08: this used to assert winnSectionForTunnelConfig on 'linux'
      // returnsNormally. docs/handoff/ADJUDICATION_20260808.md demoted every
      // entry in kWinnHostCapabilities, so that call now throws at the
      // capability gate on every platform. The property here is about the
      // RANGE config building a section, not about any platform's capability,
      // so it is asserted against the config half of the same gate -- the
      // function winnSectionForTunnelConfig returns verbatim once its
      // platform check passes.
      expect(
        () => resolveWinnProtocolStartForServedConfig(config: config),
        returnsNormally,
        reason: 'a valid range config must build a section',
      );
      expect(
        resolveWinnProtocolStartForServedConfig(config: config).iniSection,
        isNotEmpty,
        reason: 'and the section must be real, not an empty string -- an '
            'AmneziaWG config with no [winn] section is the downgrade this '
            'test exists to prevent',
      );
    });

    test('every winn/3 host and the Go datapath parse a range, not just an integer', () {
      // Coherence rule: the fail-closed refusal must not be weakened until ALL
      // five winn sites plus the Go classifier can express a range. This test
      // pins that all six have learned range membership, so a partial landing
      // that accepts a range on one side but classifies by exact value on the
      // other cannot ship. The markers are the range parse and the interval
      // checks, not the ceiling.
      const winnRangeMarkers = <String, List<String>>{
        'lib/winn_protocol_dispatch.dart': <String>[
          'AwgHeaderSpec',
          'parseAwgHeaderSpec',
          'overlaps(',
        ],
        'android/app/src/main/kotlin/org/winsvpn/app/WinnEngineConfig.kt': <String>[
          'AwgHeaderSpec',
          'fun parse(',
          'fun overlaps(',
        ],
        'apple/EngineWrappers/WinsWinnPacketEngine.m': <String>[
          'wins_winn_parse_header_spec',
          'header_starts',
          'header_ends',
        ],
        'linux/runner/linux_winn_host.cc': <String>[
          'LinuxAwgHeaderSpec',
          'ParseHeaderSpec',
          'overlaps(',
        ],
        'linux/runner/linux_winn_host.h': <String>[
          'LinuxAwgHeaderSpec',
          'overlaps(',
        ],
        'windows/runner/windows_winn_engine.cpp': <String>[
          'WindowsAwgHeaderSpec',
          'ParseHeaderSpec',
          'overlaps(',
        ],
        'windows/runner/windows_winn_engine.h': <String>[
          'WindowsAwgHeaderSpec',
          'overlaps(',
        ],
        'winn_protocol_experimental/datapath/classify.go': <String>[
          'type AwgHeaderSpec struct',
          'func (s AwgHeaderSpec) Contains',
          'func (s AwgHeaderSpec) Overlaps',
        ],
        'winn_protocol_experimental/datapath/config.go': <String>[
          'AwgHeaderSpec',
          'overlaps(',
        ],
      };
      winnRangeMarkers.forEach((path, markers) {
        final source = _read(path);
        for (final marker in markers) {
          expect(source, contains(marker),
              reason: '$path must carry range handling ($marker); a host that '
                  'still parses a scalar by int.tryParse refuses every node the '
                  'generator gives a range, and these parameters are not negotiated');
        }
      });
      // The JSON contract must carry ranges as quoted strings, not as numbers,
      // so that a range survives the host-to-engine hop.
      final dartWinn = _read('lib/winn_protocol_dispatch.dart');
      expect(dartWinn, contains('headerTypes[0].spec'),
          reason: 'Dart must emit the spec string, not a truncated int');
      final kotlinJson = _read('android/app/src/main/kotlin/org/winsvpn/app/WinnEngineConfig.kt');
      expect(kotlinJson, contains('isRange()'),
          reason: 'Kotlin must branch on isRange to emit quoted ranges');
      final appleJson = _read('apple/EngineWrappers/WinsWinnPacketEngine.m');
      expect(appleJson, contains('%llu-%llu'),
          reason: 'Apple must emit a quoted range string for a range');
      final linuxJson = _read('linux/runner/linux_winn_host.cc');
      expect(linuxJson, contains('isRange()'),
          reason: 'Linux must emit quoted ranges');
      final windowsJson = _read('windows/runner/windows_winn_engine.cpp');
      expect(windowsJson, contains('isRange()'),
          reason: 'Windows must emit quoted ranges');
      final goClass = _read('winn_protocol_experimental/datapath/classify.go');
      expect(goClass, contains('Contains('),
          reason: 'Go classifier must test interval membership, not equality');
    });
   });
}
