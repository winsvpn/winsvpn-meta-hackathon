import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn3_cover_fallback.dart';
import 'package:wins_vpn/winn_protocol_dispatch.dart';

const _generation = '0123456789abcdef0123456789abcdef';
const _nextGeneration = 'fedcba9876543210fedcba9876543210';

Map<String, dynamic> _config({
  String target = 'germany',
  bool stealth = false,
}) =>
    <String, dynamic>{
      'protocol_version': kWinnProtocolV1,
      'node_slug': target,
      'stealth_active': stealth,
    };

void _synchronize({
  String generation = _generation,
  bool ordinaryFailure = false,
}) {
  winn3SelectionGenerationPayload(
    selectionGeneration: generation,
    ordinaryConnectivityAuthorized: ordinaryFailure,
  );
}

bool _arm({String generation = _generation, String target = 'germany'}) =>
    armWinn1PrimaryHubDispatchAuthorization(
      config: _config(target: target),
      selectionGeneration: generation,
    );

String _consume(Map<String, dynamic> config) => winnSectionForTunnelConfig(
      operatingSystem: 'android',
      config: config,
    );

void main() {
  setUp(resetWinn1FallbackDispatchAuthorization);
  tearDown(resetWinn1FallbackDispatchAuthorization);

  test('fresh config cannot cross an unsynchronized selection generation', () {
    // Reproduce the former switch: prefetch synchronized the old generation,
    // then smart-connect minted another generation and skipped its payload.
    _synchronize();
    expect(_arm(generation: _nextGeneration), isFalse);
    expect(
      cachedConfigMayAuthorizeAwgOrXray(
        config: _config(),
        hasFreshHubConfig: true,
        listingNode: null,
      ),
      isFalse,
    );
    _synchronize(generation: _nextGeneration);
    expect(_arm(generation: _nextGeneration), isTrue);
    expect(
      cachedConfigMayAuthorizeAwgOrXray(
        config: _config(),
        hasFreshHubConfig: true,
        listingNode: null,
      ),
      isTrue,
    );
  });

  test('same-generation refresh preserves primary AWG then Xray exactly once',
      () {
    _synchronize();
    expect(_arm(), isTrue);
    _synchronize();
    expect(_consume(_config()), isEmpty);

    // The stealth verify payload has no ordinary-v3-failure field: the hub
    // selected v1 as primary, so there was no preceding v3 failure.
    _synchronize();
    final stealthConfig = _config(stealth: true);
    expect(
      cachedConfigMayAuthorizeAwgOrXray(
        config: stealthConfig,
        hasFreshHubConfig: true,
        listingNode: null,
      ),
      isTrue,
    );
    expect(() => _consume(_config()), throwsStateError);
    expect(_consume(stealthConfig), isEmpty);
    expect(() => _consume(stealthConfig), throwsStateError);
  });

  test('reobserving fresh primary config cannot rewind the consumed AWG leg',
      () {
    _synchronize();
    expect(_arm(), isTrue);
    expect(_consume(_config()), isEmpty);
    expect(_arm(), isTrue);
    expect(() => _consume(_config()), throwsStateError);
    expect(_consume(_config(stealth: true)), isEmpty);
    expect(_arm(), isFalse);
    _synchronize();
    expect(_arm(), isFalse);
    expect(() => _consume(_config()), throwsStateError);
  });

  test('a different target cannot replace an active or consumed primary grant',
      () {
    _synchronize();
    expect(_arm(), isTrue);
    expect(_arm(target: 'france'), isFalse);
    expect(() => _consume(_config(target: 'france')), throwsStateError);
    expect(_consume(_config()), isEmpty);
    _synchronize();
    expect(
      () => _consume(_config(target: 'france', stealth: true)),
      throwsStateError,
    );
    expect(_consume(_config(stealth: true)), isEmpty);
    expect(_arm(target: 'france'), isFalse);
  });

  test('primary grant cannot start Xray before AWG', () {
    _synchronize();
    expect(_arm(), isTrue);
    expect(() => _consume(_config(stealth: true)), throwsStateError);
    expect(_consume(_config()), isEmpty);
    expect(_consume(_config(stealth: true)), isEmpty);
  });

  test('new selection revokes old grant and requires newly armed authority',
      () {
    _synchronize();
    expect(_arm(), isTrue);
    expect(_consume(_config()), isEmpty);
    _synchronize(generation: _nextGeneration);
    expect(() => _consume(_config(stealth: true)), throwsStateError);
    expect(_arm(), isFalse);
    expect(_arm(generation: _nextGeneration), isTrue);
    expect(_consume(_config()), isEmpty);
  });

  test('explicit clear is not undone by refresh or reobserving primary config',
      () {
    _synchronize();
    expect(_arm(), isTrue);
    clearWinn1FallbackDispatchAuthorization(selectionGeneration: _generation);
    _synchronize();
    expect(_arm(), isFalse);
    expect(() => _consume(_config()), throwsStateError);
    expect(() => _consume(_config(stealth: true)), throwsStateError);
  });

  test('stale-generation clear cannot destroy the current primary grant', () {
    _synchronize(generation: _nextGeneration);
    expect(_arm(generation: _nextGeneration), isTrue);
    clearWinn1FallbackDispatchAuthorization(selectionGeneration: _generation);
    expect(_consume(_config()), isEmpty);
  });

  test('withholding ordinary-v3 failure still revokes a fallback grant', () {
    _synchronize(ordinaryFailure: true);
    expect(
      armWinn1FallbackDispatchAuthorization(
        startToken: 7,
        startGeneration: 3,
        selectionGeneration: _generation,
        failedV3Node: 'france',
      ),
      isTrue,
    );
    expect(_consume(_config()), isEmpty);
    _synchronize();
    expect(() => _consume(_config(stealth: true)), throwsStateError);
    expect(
      armWinn1FallbackDispatchAuthorization(
        startToken: 7,
        startGeneration: 3,
        selectionGeneration: _generation,
        failedV3Node: 'france',
      ),
      isFalse,
    );
  });

  test('primary arm cannot replace an existing ordinary-v3 fallback grant', () {
    _synchronize(ordinaryFailure: true);
    expect(
      armWinn1FallbackDispatchAuthorization(
        startToken: 7,
        startGeneration: 3,
        selectionGeneration: _generation,
        failedV3Node: 'france',
      ),
      isTrue,
    );
    expect(_arm(), isFalse);
    expect(_consume(_config()), isEmpty);
  });

  test('malformed generation clears every dispatch grant', () {
    _synchronize();
    expect(_arm(), isTrue);
    _synchronize(generation: 'invalid');
    expect(_arm(), isFalse);
    expect(() => _consume(_config()), throwsStateError);
  });
}
