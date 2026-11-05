import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/semantics.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/main.dart';

// 2026-10-24: after the hub listed 7 servers, a relaunched phone opened the
// server picker on the 4 rows of the previous on-disk node cache and kept
// showing them, each "Server load unknown", although the live listing landed
// moments later and parsed correctly. The sheet renders a copy of the list it
// is opened on, so a sheet opened on cache rows never gained the live ones.
//
// The real app is cold-started with a 4-row cache. The hub is a local fake
// that serves the live response (test/fixtures/nodes_live_7_20261024.json,
// the 7 node rows verbatim from GET /nodes) one second after the request, and
// refuses every other request: nothing leaves this process.
void main() {
  const tunnelChannel = MethodChannel('wins_vpn/tunnel');
  const account = '1111-2222-3333';
  final source = File('lib/main.dart').readAsStringSync();
  final policyVersion = RegExp(r"_privacyPolicyVersion = '([^']+)'")
      .firstMatch(source)!
      .group(1)!;
  final liveBytes =
      File('test/fixtures/nodes_live_7_20261024.json').readAsBytesSync();
  final live = jsonDecode(utf8.decode(liveBytes)) as Map<String, dynamic>;
  const oldSlugs = <String>{
    'canada-ca1',
    'germany-de1',
    'uk-gb1',
    'us-oregon1',
  };

  late Directory documents;
  late Map<String, String> keychain;
  late List<String> hubRequests;
  var hubDelay = const Duration(seconds: 1);

  setUp(() async {
    documents = await Directory.systemTemp.createTemp('picker-live-listing-');
    keychain = <String, String>{};
    hubRequests = <String>[];
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(tunnelChannel, (call) async {
      final arguments = call.arguments is Map
          ? Map<String, dynamic>.from(call.arguments as Map)
          : const <String, dynamic>{};
      final name = (arguments['name'] ?? '').toString();
      switch (call.method) {
        case 'getAppDocumentsDirectory':
          return documents.path;
        case 'secureStateRead':
        case 'readSecureText':
          return keychain[name];
        case 'secureStateWrite':
        case 'writeSecureText':
          keychain[name] = (arguments['value'] ?? '').toString();
          return true;
        case 'secureStateDelete':
        case 'deleteSecureText':
          keychain.remove(name);
          return true;
        case 'getTunnelReadiness':
          return <String, dynamic>{'active': false, 'status': 'disconnected'};
        case 'getTunnelState':
          return false;
      }
      return null;
    });
    hubDelay = const Duration(seconds: 1);
    HttpOverrides.global =
        _FakeHubOverrides(liveBytes, () => hubDelay, hubRequests);
    // The previous launch listed four servers; its cache carries no load.
    final cached = <Map<String, dynamic>>[
      for (final row in (live['nodes'] as List).cast<Map<String, dynamic>>())
        if (oldSlugs.contains(row['slug']))
          Map<String, dynamic>.from(row)
            ..['free_access_enabled'] = false
            ..['freeaccessenabled'] = false
            ..remove('load_pct'),
    ];
    keychain['node_cache.json'] = jsonEncode(<String, dynamic>{
      'saved_at': DateTime.now().toUtc().toIso8601String(),
      'selected_index': 0,
      'selected_slug': 'canada-ca1',
      'nodes': cached,
    });
    // A free session reaches the dashboard without a PIN on the Apple host.
    keychain['vpn_settings.txt'] = jsonEncode(<String, Object>{
      'privacy_policy_accepted_version': policyVersion,
      'account_number': account,
      'free_access_session': true,
      'selected_slug': 'canada-ca1',
      'automatic_node_selection': false,
    });
  });

  tearDown(() async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(tunnelChannel, null);
    HttpOverrides.global = null;
    if (await documents.exists()) await documents.delete(recursive: true);
  });

  const knownAdvisory =
      'ListTile background color or ink splashes may be invisible.';
  FlutterExceptionHandler? testHandler;
  void dropKnownAdvisory() {
    testHandler = FlutterError.onError;
    FlutterError.onError = (details) {
      if (details.exceptionAsString().contains(knownAdvisory)) return;
      testHandler?.call(details);
    };
  }

  Future<void> settle(WidgetTester tester, int rounds) async {
    for (var i = 0; i < rounds; i++) {
      await tester.runAsync(
          () => Future<void>.delayed(const Duration(milliseconds: 25)));
      await tester.pump(const Duration(milliseconds: 200));
    }
  }

  Set<String> sheetRows(WidgetTester tester) => <String>{
        for (final name in const <String>[
          'Brazil',
          'Canada',
          'Germany',
          'Malaysia',
          'Singapore',
          'United Kingdom',
          'United States (Oregon)',
        ])
          if (find
              .descendant(
                  of: find.byType(BottomSheet), matching: find.text(name))
              .evaluate()
              .isNotEmpty)
            name,
      };

  testWidgets(
      'a picker opened on cached rows shows the live listing that lands next',
      (tester) async {
    dropKnownAdvisory();
    final semantics = tester.ensureSemantics();
    await tester.pumpWidget(const MyApp());
    // Cold start: the dashboard is up on the cached rows, the live /nodes
    // answer is one second away.
    for (var i = 0;
        i < 100 && find.byIcon(Icons.keyboard_arrow_down).evaluate().isEmpty;
        i++) {
      await settle(tester, 1);
    }
    await tester.tap(find.byIcon(Icons.keyboard_arrow_down).first);
    await settle(tester, 30);
    expect(hubRequests.where((r) => r.endsWith('/nodes')), isNotEmpty,
        reason: 'the fake hub was asked for the listing');

    // New servers sort between the old ones, so they are on screen at once.
    final rows = sheetRows(tester);
    expect(rows, containsAll(<String>['Brazil', 'Malaysia']),
        reason: 'the sheet must show the live rows, not the cache: $rows');

    // Every row of the sheet reads the live figure, none "unknown".
    final labels = <String>[];
    void walk(SemanticsNode node) {
      if (node.label.contains('Server load')) labels.add(node.label);
      node.visitChildren((child) {
        walk(child);
        return true;
      });
    }

    walk(tester.binding.renderViews.first.owner!.semanticsOwner!.rootSemanticsNode!);
    expect(labels, isNotEmpty);
    expect(labels.where((l) => l.contains('Server load unknown')), isEmpty,
        reason: '$labels');
    expect(labels.where((l) => l.contains('Server load 25%')).length,
        greaterThanOrEqualTo(4));

    semantics.dispose();
    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pump(const Duration(minutes: 5));
    FlutterError.onError = testHandler;
  }, skip: !(Platform.isMacOS || Platform.isIOS));

  testWidgets('once live rows exist the picker opens at once, with no wait',
      (tester) async {
    dropKnownAdvisory();
    hubDelay = const Duration(milliseconds: 200);
    await tester.pumpWidget(const MyApp());
    for (var i = 0;
        i < 100 && find.byIcon(Icons.keyboard_arrow_down).evaluate().isEmpty;
        i++) {
      await settle(tester, 1);
    }
    await settle(tester, 20); // the live listing has landed
    // A hub that now answers only after 30 s must not delay the sheet.
    hubDelay = const Duration(seconds: 30);
    await tester.tap(find.byIcon(Icons.keyboard_arrow_down).first);
    await tester.pump(const Duration(milliseconds: 300));
    expect(find.byType(BottomSheet), findsOneWidget);
    expect(sheetRows(tester), containsAll(<String>['Brazil', 'Malaysia']));
    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pump(const Duration(minutes: 5));
    FlutterError.onError = testHandler;
  }, skip: !(Platform.isMacOS || Platform.isIOS));

  testWidgets('offline discovery opens the cached picker after the bound',
      (tester) async {
    dropKnownAdvisory();
    hubDelay = const Duration(seconds: 30);
    await tester.pumpWidget(const MyApp());
    for (var i = 0;
        i < 100 && find.byIcon(Icons.keyboard_arrow_down).evaluate().isEmpty;
        i++) {
      await settle(tester, 1);
    }
    await tester.tap(find.byIcon(Icons.keyboard_arrow_down).first);
    await tester.runAsync(
        () => Future<void>.delayed(const Duration(milliseconds: 2300)));
    await settle(tester, 10);
    expect(find.byType(BottomSheet), findsOneWidget);
    expect(sheetRows(tester), contains('Canada'));
    expect(sheetRows(tester), isNot(contains('Brazil')));
    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pump(const Duration(minutes: 5));
    FlutterError.onError = testHandler;
  }, skip: !(Platform.isMacOS || Platform.isIOS));
}

class _FakeHubOverrides extends HttpOverrides {
  _FakeHubOverrides(this.nodesBody, this.delay, this.seen);
  final List<int> nodesBody;
  final Duration Function() delay;
  final List<String> seen;

  @override
  HttpClient createHttpClient(SecurityContext? context) =>
      _FakeHttpClient(nodesBody, delay, seen);
}

class _FakeHttpClient implements HttpClient {
  _FakeHttpClient(this.nodesBody, this.delay, this.seen);
  final List<int> nodesBody;
  final Duration Function() delay;
  final List<String> seen;

  @override
  Future<HttpClientRequest> openUrl(String method, Uri url) async {
    seen.add('$method ${url.host}${url.path}');
    if (method == 'GET' && url.path == '/nodes') {
      return _FakeRequest(nodesBody, delay());
    }
    throw SocketException('refused by the test: $method $url');
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => null;
}

class _FakeHeaders implements HttpHeaders {
  final Map<String, List<String>> _values = <String, List<String>>{};

  @override
  void set(String name, Object value, {bool preserveHeaderCase = false}) {
    _values[name.toLowerCase()] = <String>[value.toString()];
  }

  @override
  void forEach(void Function(String name, List<String> values) action) =>
      _values.forEach(action);

  @override
  List<String>? operator [](String name) => _values[name.toLowerCase()];

  @override
  dynamic noSuchMethod(Invocation invocation) => null;
}

class _FakeRequest implements HttpClientRequest {
  _FakeRequest(this.body, this.delay);
  final List<int> body;
  final Duration delay;

  @override
  final HttpHeaders headers = _FakeHeaders();

  @override
  Future<void> addStream(Stream<List<int>> stream) => stream.drain<void>();

  @override
  void abort([Object? exception, StackTrace? stackTrace]) {}

  @override
  Future<HttpClientResponse> close() async {
    await Future<void>.delayed(delay);
    return _FakeResponse(body);
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => null;
}

class _FakeResponse extends Stream<List<int>> implements HttpClientResponse {
  _FakeResponse(this.body);
  final List<int> body;

  @override
  int get statusCode => 200;

  @override
  int get contentLength => -1;

  @override
  bool get isRedirect => false;

  @override
  bool get persistentConnection => true;

  @override
  String get reasonPhrase => 'OK';

  @override
  HttpHeaders get headers =>
      _FakeHeaders()..set('content-type', 'application/json');

  @override
  StreamSubscription<List<int>> listen(void Function(List<int> event)? onData,
          {Function? onError, void Function()? onDone, bool? cancelOnError}) =>
      Stream<List<int>>.fromIterable(<List<int>>[body]).listen(onData,
          onError: onError, onDone: onDone, cancelOnError: cancelOnError);

  @override
  dynamic noSuchMethod(Invocation invocation) => null;
}
