import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// DESKTOP-4 (Sol-desktop-5 with Fix B), Linux half.
///
/// A start that arrives after a processed stop must be refused before the
/// native start does any work. The Linux runner needs GTK to build, so this
/// suite lifts the PRODUCTION text of the two pieces that decide it out of
/// `linux/runner/linux_tunnel_backend.cc`, compiles them into a tiny C++ probe
/// with the platform calls stubbed, and runs the probe:
///
///  * the `stopTunnel` floor update (raises only for a positive, larger value),
///  * the entry guard of `StartTunnel` (generations 4, 5 and 0 are refused after
///    a stop at 5, generation 6 stays eligible, and a refused start performs no
///    work and leaves no stale Winn v3 outcome flag behind).
///
/// Source-order assertions then pin that the guard is the FIRST statement of
/// `StartTunnel`, so "no work" in the probe means no teardown, elevation, file
/// write or process launch in production. The Dart half pins that every
/// desktop stop carries a positive floor.
///
/// The source paths are injectable via `--dart-define=LINUX_BACKEND_PATH=...`
/// and `--dart-define=MAIN_DART_PATH=...` so a mutant copy must turn this red.
const String _backendPath = String.fromEnvironment(
  'LINUX_BACKEND_PATH',
  defaultValue: 'linux/runner/linux_tunnel_backend.cc',
);
const String _mainPath = String.fromEnvironment(
  'MAIN_DART_PATH',
  defaultValue: 'lib/main.dart',
);

String _balancedBlock(String source, int open) {
  expect(source[open], '{');
  var depth = 0;
  for (var i = open; i < source.length; i++) {
    final c = source[i];
    if (c == '/' && i + 1 < source.length && source[i + 1] == '/') {
      final eol = source.indexOf('\n', i);
      i = eol < 0 ? source.length : eol;
      continue;
    }
    if (c == '{') depth++;
    if (c == '}') {
      depth--;
      if (depth == 0) return source.substring(open, i + 1);
    }
  }
  fail('unbalanced braces');
}

String? _compiler() {
  for (final name in <String>['clang++', 'g++', 'c++']) {
    for (final dir in (Platform.environment['PATH'] ?? '').split(':')) {
      if (dir.isNotEmpty && File('$dir/$name').existsSync()) {
        return '$dir/$name';
      }
    }
  }
  return null;
}

void main() {
  late String backend;
  late String startBody;
  late String guard;
  late String stopFloor;

  setUpAll(() {
    backend = File(_backendPath).readAsStringSync();

    const signature =
        'bool StartTunnel(const std::string& raw_config, int64_t transition_generation,';
    final signatureAt = backend.indexOf(signature);
    expect(signatureAt, greaterThanOrEqualTo(0));
    expect(backend.indexOf(signature, signatureAt + 1), -1);
    final open = backend.indexOf('{', signatureAt);
    startBody = _balancedBlock(backend, open);

    final guardAt = startBody.indexOf('if (transition_generation <= 0 ||');
    expect(guardAt, greaterThan(0));
    expect(
      startBody.substring(1, guardAt).trim(),
      isEmpty,
      reason: 'the generation guard must be the first statement of StartTunnel',
    );
    final guardOpen = startBody.indexOf('{', guardAt);
    guard = startBody.substring(
      guardAt,
      guardOpen + _balancedBlock(startBody, guardOpen).length,
    );

    final stopAt = backend.indexOf('if (method == "stopTunnel") {');
    expect(stopAt, greaterThanOrEqualTo(0));
    final floorAt = backend.indexOf(
        'if (TryInt64ArgFromCall(method_call, "cancellationGeneration",',
        stopAt);
    expect(floorAt, greaterThan(stopAt));
    final floorOpen = backend.indexOf('{', floorAt);
    stopFloor = backend.substring(
      floorAt,
      floorOpen + _balancedBlock(backend, floorOpen).length,
    );
  });

  test('StartTunnel refuses non-positive and superseded generations first', () {
    expect(guard, contains('transition_generation <= 0'));
    expect(
      guard,
      contains('transition_generation <= g_canceled_winn3_generation_floor'),
    );
    expect(guard, contains('return false;'));
    // Everything that tears down, elevates, writes or launches comes later.
    final after = startBody.substring(startBody.indexOf(guard) + guard.length);
    expect(after, contains('g_linux_split_tunnel_ready = false;'));
    expect(after, contains('g_last_start_was_winn3 = false;'));
    expect(guard, isNot(contains('RunPrivileged')));
    expect(guard, isNot(contains('WriteFile')));
    expect(guard, isNot(contains('StopTunnel(')));
  });

  test('the start handler hands the Dart transitionGeneration to StartTunnel',
      () {
    expect(
      backend,
      contains(
        '(void)TryInt64ArgFromCall(method_call, "transitionGeneration",',
      ),
    );
    expect(
      backend,
      contains('StartTunnel(config, transition_generation, &error)'),
    );
  });

  test('Dart sends a positive floor on every desktop stop', () {
    final main = File(_mainPath).readAsStringSync();
    final start = main.indexOf('Future<bool> _stopNativeTunnel({');
    final end = main.indexOf('invokeMethod(\'stopTunnel\'', start);
    expect(start, greaterThanOrEqualTo(0));
    expect(end, greaterThan(start));
    final stop = main.substring(start, end);
    expect(stop, contains('if (Platform.isWindows || Platform.isLinux) {'));
    expect(
      stop,
      contains(
          'cancellationGeneration ?? _tunnelTransitionGate.supersededFloor'),
    );
    expect(stop, contains('if (floor <= 0) {'));
    expect(stop, contains("arguments['cancellationGeneration'] = floor;"));
    expect(
      main,
      contains(
          "startArguments['transitionGeneration'] = transitionGeneration;"),
    );
    final transition = main.indexOf(
      "startArguments['transitionGeneration'] = transitionGeneration;",
    );
    expect(
      main.substring(transition - 60, transition),
      contains('if (Platform.isWindows || Platform.isLinux) {'),
    );
  });

  group('native probe', () {
    late Directory work;
    late Map<String, String> lines;
    final compiler = _compiler();

    setUpAll(() {
      if (compiler == null) return;
      work = Directory.systemTemp.createTempSync('linux_fence_');
      final source = '''
#include <cstdint>
#include <cstdio>
#include <map>
#include <string>

int64_t g_canceled_winn3_generation_floor = 0;
bool g_last_start_was_winn3 = false;
int g_side_effects = 0;
std::map<std::string, int64_t> g_args;
struct FlMethodCall {};

bool TryInt64ArgFromCall(FlMethodCall*, const char* key, int64_t* output) {
  auto it = g_args.find(key);
  if (it == g_args.end()) {
    *output = 0;
    return false;
  }
  *output = it->second;
  return true;
}

bool StartTunnelEntry(int64_t transition_generation, std::string* error) {
  $guard
  // Everything the real StartTunnel does after its guard.
  ++g_side_effects;
  return true;
}

void StopHandler(FlMethodCall* method_call) {
  int64_t cancellation_generation = 0;
  $stopFloor
}

static void Stop(bool present, int64_t generation) {
  g_args.clear();
  if (present) g_args["cancellationGeneration"] = generation;
  FlMethodCall call;
  StopHandler(&call);
  std::printf("stop present=%d gen=%lld floor=%lld\\n", present ? 1 : 0,
              static_cast<long long>(generation),
              static_cast<long long>(g_canceled_winn3_generation_floor));
}

static void Start(int64_t generation) {
  g_side_effects = 0;
  g_last_start_was_winn3 = true;  // a previous Winn v3 start left it set
  std::string error;
  const bool ok = StartTunnelEntry(generation, &error);
  std::printf("start gen=%lld ok=%d effects=%d stale_flag=%d error=%s\\n",
              static_cast<long long>(generation), ok ? 1 : 0, g_side_effects,
              g_last_start_was_winn3 ? 1 : 0, error.c_str());
}

int main() {
  Start(1);                 // before any stop
  Start(0);
  Start(-3);
  Stop(true, 5);
  Start(4);
  Start(5);
  Start(0);
  Start(-1);
  Start(6);
  Stop(false, 0);           // a stop with no generation never moves the floor
  Stop(true, 0);
  Stop(true, -9);
  Stop(true, 3);            // lower than the floor: ignored
  Start(5);
  Start(6);
  Stop(true, 6);
  Start(6);
  Start(7);
  return 0;
}
''';
      File('${work.path}/probe.cc').writeAsStringSync(source);
      final build = Process.runSync(compiler, <String>[
        '-std=c++17',
        '-Wall',
        '-Werror',
        '-o',
        '${work.path}/probe',
        '${work.path}/probe.cc',
      ]);
      expect(build.exitCode, 0, reason: '${build.stdout}\n${build.stderr}');
      final run = Process.runSync('${work.path}/probe', <String>[]);
      expect(run.exitCode, 0);
      lines = <String, String>{};
      var n = 0;
      for (final line in (run.stdout as String).trim().split('\n')) {
        lines['${n++}'] = line;
      }
    });

    tearDownAll(() {
      if (compiler == null) return;
      try {
        work.deleteSync(recursive: true);
      } catch (_) {}
    });

    final skip = compiler == null ? 'no C++ compiler on PATH' : null;

    test('before any stop only positive generations start', () {
      expect(lines['0'], startsWith('start gen=1 ok=1 effects=1'));
      expect(lines['1'], startsWith('start gen=0 ok=0 effects=0'));
      expect(lines['2'], startsWith('start gen=-3 ok=0 effects=0'));
    }, skip: skip);

    test('after stop 5, starts 4, 5 and 0 do no work and generation 6 runs',
        () {
      expect(lines['3'], 'stop present=1 gen=5 floor=5');
      for (final i in <String>['4', '5', '6', '7']) {
        expect(lines[i], contains('ok=0 effects=0'), reason: lines[i]);
        expect(
          lines[i],
          contains(
              'error=Tunnel start was canceled before the transport launched.'),
        );
      }
      expect(lines['4'], startsWith('start gen=4 '));
      expect(lines['5'], startsWith('start gen=5 '));
      expect(lines['6'], startsWith('start gen=0 '));
      expect(lines['8'], startsWith('start gen=6 ok=1 effects=1'));
    }, skip: skip);

    test('a rejected start leaves no stale Winn v3 outcome flag', () {
      for (final i in <String>['1', '2', '4', '5', '6', '7']) {
        expect(lines[i], contains('stale_flag=0'), reason: lines[i]);
      }
    }, skip: skip);

    test('a stop never lowers the floor and ignores non-positive values', () {
      expect(lines['9'], 'stop present=0 gen=0 floor=5');
      expect(lines['10'], 'stop present=1 gen=0 floor=5');
      expect(lines['11'], 'stop present=1 gen=-9 floor=5');
      expect(lines['12'], 'stop present=1 gen=3 floor=5');
      expect(lines['13'], startsWith('start gen=5 ok=0 effects=0'));
      expect(lines['14'], startsWith('start gen=6 ok=1 effects=1'));
      expect(lines['15'], 'stop present=1 gen=6 floor=6');
      expect(lines['16'], startsWith('start gen=6 ok=0 effects=0'));
      expect(lines['17'], startsWith('start gen=7 ok=1 effects=1'));
    }, skip: skip);
  });
}
