// Native-messaging host for the Win's VPN browser extension.
//
// Built with:
//   dart compile exe bin/wins_bridge_host.dart -o build/bridge/wins_bridge_host
//
// The browser launches this process, writes length-prefixed JSON to its stdin
// and reads the same framing from its stdout. It is not a service, it is not
// listening for anyone else, and it exits when the browser closes the port.
//
// STDOUT IS THE WIRE. Nothing may `print()` here. A single stray byte on
// stdout desynchronises the length prefix and the browser drops the host with
// no diagnostic. All logging goes to stderr, which the browser captures into
// its own log and which never carries a token.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:wins_bridge_host/browser_bridge_app_ipc.dart';
import 'package:wins_bridge_host/browser_bridge_framing.dart';
import 'package:wins_bridge_host/browser_bridge_protocol.dart';
import 'package:wins_bridge_host/browser_bridge_proxy.dart';
import 'package:wins_bridge_host/winn_protocol_dispatch.dart';

/// Where the host learns the desktop app's tunnel state.
///
/// The shipping source is [AppIpcStateSource]: a loopback-only, bearer-token
/// channel the desktop app publishes while it is running. Every validation or
/// IPC failure is [BridgeStatus.appNotRunning]. That is the correct failure
/// direction. `--state-file` is still refused here on purpose: that switch
/// exists only on `wins_bridge_host_harness.dart`. Honoring it in the shipping
/// binary would let any local writer declare the tunnel up and open the
/// CONNECT proxy.
abstract class BridgeStateSource {
  Future<BridgeStatus> read();

  /// Ask the desktop app to connect. Sources that cannot forward a command
  /// return a status read so the extension renders truth, never an assumption.
  /// A source that forwards and is refused throws [BridgeRefusal].
  Future<BridgeStatus> requestConnect() => read();

  Future<BridgeStatus> requestDisconnect() => read();

  /// The pairing this host presents to the app on every request: the launch
  /// origin and the credential the extension stored. Either may be null.
  void presentPairing({String? origin, String? credential});

  /// Start a pairing for the presented origin. Null: this source cannot pair.
  Future<BridgePairingReply?> pairBegin();

  /// Read the pairing [pairBegin] started. Null: nothing is pending.
  Future<BridgePairingReply?> pairPoll();

  /// Ask the app to forget the presented pairing, then stop presenting it.
  Future<BridgeStatus> pairForget();
}

/// A control or pairing request the app answered with a refusal, mapped to
/// the extension's closed error vocabulary.
class BridgeRefusal implements Exception {
  const BridgeRefusal(this.code);

  final BridgeErrorCode code;

  @override
  String toString() => 'BridgeRefusal: ${code.wire}';
}

BridgeErrorCode _bridgeErrorForIpc(BrowserBridgeAppIpcError error) {
  switch (error) {
    case BrowserBridgeAppIpcError.notPaired:
    case BrowserBridgeAppIpcError.identityMismatch:
      return BridgeErrorCode.notPermitted;
    case BrowserBridgeAppIpcError.busy:
    case BrowserBridgeAppIpcError.rateLimited:
      return BridgeErrorCode.rateLimited;
    default:
      return BridgeErrorCode.appNotRunning;
  }
}

/// Reports the app as unobservable. Used by the harness when no file is given;
/// production uses [AppIpcStateSource], which degrades to the same snapshot.
class UnobservedStateSource implements BridgeStateSource {
  UnobservedStateSource(this.winn);

  final BridgeWinnState winn;

  @override
  Future<BridgeStatus> read() async => BridgeStatus.appNotRunning(winn: winn);

  @override
  Future<BridgeStatus> requestConnect() => read();

  @override
  Future<BridgeStatus> requestDisconnect() => read();

  @override
  void presentPairing({String? origin, String? credential}) {}

  @override
  Future<BridgePairingReply?> pairBegin() async => null;

  @override
  Future<BridgePairingReply?> pairPoll() async => null;

  @override
  Future<BridgeStatus> pairForget() => read();
}

/// Production source: authenticated IPv4-loopback IPC with the running app.
///
/// Fail-closed on a missing/stale/unsafe discovery file, a non-loopback
/// endpoint, a token mismatch, an oversized frame, a duplicate request id,
/// or any transport error. Stderr names only the closed error code.
class AppIpcStateSource implements BridgeStateSource {
  AppIpcStateSource({
    required this.winn,
    File? discoveryFile,
    BrowserBridgeAppIpcTrust? trust,
  }) : _client = _openClient(discoveryFile, trust);

  final BridgeWinnState winn;

  /// Null when no discovery location can be resolved (for example a macOS
  /// host without the App Group entitlement). Every request then answers
  /// app_not_running instead of the host dying before it reads a frame.
  final BrowserBridgeAppIpcClient? _client;

  static BrowserBridgeAppIpcClient? _openClient(
    File? discoveryFile,
    BrowserBridgeAppIpcTrust? trust,
  ) {
    try {
      return BrowserBridgeAppIpcClient(
        discoveryFile: discoveryFile,
        trust: trust,
      );
    } on BrowserBridgeAppIpcException {
      return null;
    }
  }

  String? _origin;
  String? _credential;
  String? _pairingId;

  @override
  void presentPairing({String? origin, String? credential}) {
    if (_origin != origin) _pairingId = null;
    _origin = origin;
    _credential = credential;
  }

  Future<BridgeStatus> _failClosed(BrowserBridgeAppIpcCommand command) {
    final BrowserBridgeAppIpcClient? client = _client;
    if (client == null) {
      return Future<BridgeStatus>.value(BridgeStatus.appNotRunning(winn: winn));
    }
    // A credential is only meaningful with the origin it was minted for.
    final origin = _origin;
    return client.invokeFailClosed(
      command: command,
      winn: winn,
      origin: origin,
      credential: origin == null ? null : _credential,
    );
  }

  /// Control: forwarded with the presented pairing. A refusal by the app is
  /// reported as such; any transport or identity failure stays fail-closed.
  Future<BridgeStatus> _control(BrowserBridgeAppIpcCommand command) async {
    final BrowserBridgeAppIpcClient? client = _client;
    final origin = _origin;
    final credential = _credential;
    if (client == null) return BridgeStatus.appNotRunning(winn: winn);
    if (origin == null || credential == null) {
      throw const BridgeRefusal(BridgeErrorCode.notPermitted);
    }
    try {
      final status = await client.invoke(
        command,
        origin: origin,
        credential: credential,
      );
      return browserBridgeAppIpcAdmitStatus(
        status,
        authenticatedAppIdentity: true,
        winn: winn,
      );
    } on BrowserBridgeAppIpcException catch (error) {
      final code = _bridgeErrorForIpc(error.code);
      if (code == BridgeErrorCode.appNotRunning) {
        return BridgeStatus.appNotRunning(winn: winn);
      }
      throw BridgeRefusal(code);
    } catch (_) {
      return BridgeStatus.appNotRunning(winn: winn);
    }
  }

  @override
  Future<BridgeStatus> read() =>
      _failClosed(BrowserBridgeAppIpcCommand.getStatus);

  @override
  Future<BridgeStatus> requestConnect() =>
      _control(BrowserBridgeAppIpcCommand.requestConnect);

  @override
  Future<BridgeStatus> requestDisconnect() =>
      _control(BrowserBridgeAppIpcCommand.requestDisconnect);

  BridgePairingReply _reply(BrowserBridgePairingAnswer answer) {
    return BridgePairingReply(
      state: answer.state,
      code: answer.code,
      expiresInSeconds: answer.expiresInSeconds,
      credential: answer.credential,
    );
  }

  BridgePairingReply? _refusedPairing(BrowserBridgeAppIpcError error) {
    switch (error) {
      case BrowserBridgeAppIpcError.busy:
      case BrowserBridgeAppIpcError.rateLimited:
        return BridgePairingReply(state: BridgePairingFlowState.busy);
      case BrowserBridgeAppIpcError.pairingUnavailable:
        return BridgePairingReply(state: BridgePairingFlowState.unavailable);
      case BrowserBridgeAppIpcError.identityMismatch:
        throw const BridgeRefusal(BridgeErrorCode.notPermitted);
      default:
        return null;
    }
  }

  @override
  Future<BridgePairingReply?> pairBegin() async {
    final BrowserBridgeAppIpcClient? client = _client;
    final origin = _origin;
    if (origin == null) throw const BridgeRefusal(BridgeErrorCode.notPermitted);
    if (client == null) return null;
    try {
      final answer = await client.pairBegin(origin: origin);
      _pairingId =
          answer.state == BridgePairingFlowState.pending ? answer.pairingId : null;
      return _reply(answer);
    } on BrowserBridgeAppIpcException catch (error) {
      return _refusedPairing(error.code);
    } catch (_) {
      return null;
    }
  }

  @override
  Future<BridgePairingReply?> pairPoll() async {
    final BrowserBridgeAppIpcClient? client = _client;
    final origin = _origin;
    final pairingId = _pairingId;
    if (client == null || origin == null || pairingId == null) return null;
    try {
      final answer =
          await client.pairPoll(origin: origin, pairingId: pairingId);
      if (answer.state != BridgePairingFlowState.pending) _pairingId = null;
      if (answer.state == BridgePairingFlowState.approved) {
        _credential = answer.credential;
      }
      return _reply(answer);
    } on BrowserBridgeAppIpcException catch (error) {
      _pairingId = null;
      return _refusedPairing(error.code) ??
          BridgePairingReply(state: BridgePairingFlowState.expired);
    } catch (_) {
      // Transport failure: keep the handle; the next poll may reach the app.
      return null;
    }
  }

  @override
  Future<BridgeStatus> pairForget() async {
    final BrowserBridgeAppIpcClient? client = _client;
    final origin = _origin;
    final credential = _credential;
    _credential = null;
    _pairingId = null;
    if (client != null && origin != null && credential != null) {
      try {
        await client.pairRevoke(origin: origin, credential: credential);
      } catch (_) {
        // The extension drops its copy regardless. A pairing the app still
        // holds stays visible, and revocable, in the app's settings.
      }
    }
    return read();
  }
}

/// Gate driven by the state source. Closed unless a snapshot says `connected`.
class StateSourceTunnelGate implements TunnelGate {
  StateSourceTunnelGate();

  final StreamController<bool> _changes = StreamController<bool>.broadcast();
  bool _open = false;

  @override
  bool get admitsTraffic => _open;

  @override
  Stream<bool> get changes => _changes.stream;

  void apply(BridgeStatus status) {
    final open = status.status.isCarryingTraffic;
    if (open == _open) return;
    _open = open;
    _changes.add(open);
  }
}

/// The winn/3 statement, read from the real capability gate.
///
/// `kWinnHostCapabilities` has macOS, Windows and iOS as
/// `WinnHostCapability.absent`, so this returns
/// [BridgeWinnState.unavailableOnThisPlatform] there. The extension renders
/// whatever this says and never infers winn/3 from the fact that a tunnel is
/// up: on macOS and Windows today, the tunnel this bridge fronts is plain
/// AmneziaWG.
BridgeWinnState resolveWinnState({
  required String operatingSystem,
  required bool connected,
}) {
  if (!platformSupportsWinnProtocol(operatingSystem)) {
    return BridgeWinnState.unavailableOnThisPlatform;
  }
  // The gate being present is not the same as the live session using winn/3.
  // Distinguishing those needs the config that started the tunnel, which
  // arrives with the state source; until then the honest answer on a supported
  // platform is "available, not proven in use".
  return BridgeWinnState.availableNotInUse;
}

// TLS material removed 2026-08-07 per ruling: webRequest plaintext, no cert.

class BridgeHost {
  BridgeHost({
    required this.stateSource,
    required this.operatingSystem,
    void Function(Map<String, Object?> message)? emitForTest,
    this.allowedOrigins = const <String>{},
  }) : _emitForTest = emitForTest;

  final BridgeStateSource stateSource;
  final String operatingSystem;
  final void Function(Map<String, Object?> message)? _emitForTest;

  /// Public extension allowlist used for routing and configuration checks.
  /// argv is caller-controlled and does not authenticate a browser process.
  /// A same-user process can launch this host with an allowed origin.
  final Set<String> allowedOrigins;

  /// Claimed launch origin. Never use this as authority for VPN control.
  String? _callerOrigin;

  bool get _originAuthorized =>
      allowedOrigins.isNotEmpty && allowedOrigins.contains(_callerOrigin);

  final StateSourceTunnelGate gate = StateSourceTunnelGate();
  final NativeMessageReader _reader = NativeMessageReader();
  ProxyCredential? _credential;
  Future<void> _credentialIssues = Future<void>.value();
  bool _shuttingDown = false;
  BridgeProxyServer? _proxy;
  bool _subscribed = false;
  Timer? _poll;

  Future<void> handleNativeMessageForTest(Object? raw) => _dispatch(raw);

  /// Set the claimed launch origin. Null means no recognized origin was supplied.
  ///
  /// The origin is forwarded to the app only as the name a pairing is bound
  /// to. The app grants control to a paired credential, never to the origin.
  void setCallerOrigin(String? origin) {
    _callerOrigin = origin;
    stateSource.presentPairing(origin: _originAuthorized ? origin : null);
  }

  Timer? _pairingPoll;
  DateTime? _pairingDeadline;
  bool _pairingPollInFlight = false;

  Future<void> run() async {
    // Binary stdin. Any text decoding here would corrupt multi-byte frames.
    await for (final chunk in stdin) {
      List<Object?> messages;
      try {
        messages = _reader.addChunk(chunk);
      } on NativeFramingException catch (error) {
        stderr.writeln('framing error, closing: ${error.reason}');
        break;
      }
      for (final message in messages) {
        await _dispatch(message);
      }
    }
    await _shutdown();
  }

  Future<void> _shutdown() async {
    _shuttingDown = true;
    _subscribed = false;
    _poll?.cancel();
    _poll = null;
    _cancelPairingPoll();
    await _credentialIssues;
    await _proxy?.stop();
    _proxy = null;
    // The credential dies with the process. Nothing persisted it, so there is
    // nothing to revoke and nothing left on disk for a seized device to yield.
    _credential = null;
  }

  void _send(Map<String, Object?> message) {
    final emit = _emitForTest;
    if (emit != null) {
      emit(message);
      return;
    }
    try {
      stdout.add(encodeOutboundBridgeMessage(message));
    } on BridgeAddressLeakException catch (error) {
      // Refuse to emit rather than emit an address. Losing a status update is
      // survivable; leaking a hub address is not.
      stderr.writeln('outbound message suppressed: $error');
    }
  }

  Future<void> _dispatch(Object? raw) async {
    if (raw is! Map) {
      // `BridgeErrorCode.malformed` exists for exactly this and was never
      // emitted: a frame that decodes to something other than an object was
      // dropped in silence. Silence is indistinguishable from a host that has
      // hung, and the closed error vocabulary is the contract's own answer to
      // "what does a peer say when it cannot read what it was sent".
      // (Contract diff 2026-08-07, case G.)
      _send(bridgeError(id: '', code: BridgeErrorCode.malformed));
      return;
    }
    final id = sanitizeCorrelationId(raw['id']);

    final version = raw['v'];
    if (version is! int || version != kBridgeProtocolVersion) {
      _send(bridgeError(id: id, code: BridgeErrorCode.unsupportedVersion));
      return;
    }

    final type = BridgeRequestType.fromWire('${raw['type']}');
    if (type == null) {
      _send(bridgeError(id: id, code: BridgeErrorCode.unknownRequest));
      return;
    }

    switch (type) {
      // THE SNAPSHOT IS SPREAD AT THE TOP LEVEL OF THE REPLY, NOT NESTED.
      //
      // Fixed 2026-08-07. It used to be sent as `{"status": {...}}`, and the
      // extension reads every field of the snapshot from the top level of the
      // message -- `BridgeStatus`'s own doc comment says the snapshot IS the
      // reply body, and `dev_bridge.py`, the stand-in the verification harness
      // runs, has always sent it that way. Nested, the extension parsed
      // `status` (a Map) as the tunnel-status enum, got `unknown`, and fell
      // straight to APP_DOWN. Fail-closed, so nothing leaked -- and the real
      // host and the real extension could not interoperate at all, on any
      // browser. It was invisible because every run to date used the stand-in.
      case BridgeRequestType.hello:
        final status = await _snapshot();
        _send(bridgeReply(id: id, type: 'hello', body: <String, Object?>{
          'protocolVersion': kBridgeProtocolVersion,
          'platform': operatingSystem,
          ...status.toWire(),
        }));

      case BridgeRequestType.getStatus:
        final status = await _snapshot();
        _send(bridgeReply(id: id, type: 'status', body: status.toWire()));

      // THE REPLY VOCABULARY IS CLOSED, AND `status` IS THE ACKNOWLEDGEMENT.
      //
      // These three used to reply `subscribed`, `unsubscribed` and `revoked`.
      // The extension's `parseInbound` knows four reply types -- `hello`,
      // `status`, `proxy_credential`, `error` -- and discards anything else
      // whole, recording `bridge sent something unusable`. So every native
      // messaging session began by putting an error string into the extension's
      // own diagnostics, and a revoke ended it the same way. Nothing broke,
      // because the extension does not await typed replies; it was still three
      // words the two halves did not share.
      //
      // `status` is the right answer rather than teaching the extension three
      // more words: `BridgeStatus`'s own doc comment says the snapshot is the
      // `get_status` reply and the body of every pushed `status` event, the
      // state after a subscribe or a revoke is exactly what the caller needs,
      // and a smaller vocabulary is a smaller thing to keep in agreement.
      // (Contract diff 2026-08-07, case B.)
      case BridgeRequestType.subscribe:
        _subscribed = true;
        _poll ??= Timer.periodic(
          const Duration(seconds: 2),
          (_) => unawaited(_pushIfChanged()),
        );
        _send(bridgeReply(
            id: id, type: 'status', body: (await _snapshot()).toWire()));

      case BridgeRequestType.unsubscribe:
        _subscribed = false;
        _poll?.cancel();
        _poll = null;
        _send(bridgeReply(
            id: id, type: 'status', body: (await _snapshot()).toWire()));

      // CONTROL NEEDS THE APP'S PAIRING, NOT THIS HOST'S ARGV.
      //
      // The app refuses connect and disconnect unless the request carries the
      // credential the user approved in the app for this origin (R20 A1).
      // A refusal is reported as `not_permitted` or `rate_limited`, so the
      // popup can offer pairing instead of claiming the app is gone.
      case BridgeRequestType.requestConnect:
      case BridgeRequestType.requestDisconnect:
        {
          final BridgeStatus status;
          try {
            status = await _overlay(type == BridgeRequestType.requestConnect
                ? await stateSource.requestConnect()
                : await stateSource.requestDisconnect());
          } on BridgeRefusal catch (refusal) {
            _send(bridgeError(id: id, code: refusal.code));
            return;
          }
          if (status.status == BridgeTunnelStatus.appNotRunning) {
            _send(bridgeError(id: id, code: BridgeErrorCode.appNotRunning));
          } else {
            _send(bridgeReply(id: id, type: 'status', body: status.toWire()));
          }
        }

      case BridgeRequestType.pairBegin:
        await _beginPairing(id);

      case BridgeRequestType.setPairing:
        {
          final credential = raw['credential'];
          if (credential is! String ||
              (credential.isNotEmpty &&
                  !kBridgePairingCredentialPattern.hasMatch(credential))) {
            _send(bridgeError(id: id, code: BridgeErrorCode.malformed));
            return;
          }
          if (!_originAuthorized) {
            _send(bridgeError(id: id, code: BridgeErrorCode.notPermitted));
            return;
          }
          stateSource.presentPairing(
            origin: _callerOrigin,
            credential: credential.isEmpty ? null : credential,
          );
          final status = await _snapshot();
          _lastPushed = status.toWire().toString();
          _send(bridgeReply(id: id, type: 'status', body: status.toWire()));
        }

      case BridgeRequestType.pairForget:
        {
          _cancelPairingPoll();
          final status = await _overlay(await stateSource.pairForget());
          _lastPushed = status.toWire().toString();
          _send(bridgeReply(id: id, type: 'status', body: status.toWire()));
        }

      case BridgeRequestType.issueProxyCredential:
        await _issueCredential(id);

      case BridgeRequestType.revokeProxyCredential:
        await _revokeCredential();
        _send(bridgeReply(
            id: id, type: 'status', body: (await _snapshot()).toWire()));
    }
  }

  /// Ask the app for an in-app pairing confirmation, then watch it.
  ///
  /// The reply carries the six-digit code the app shows. Later states arrive
  /// as unsolicited `pairing` events; the approved one carries the credential
  /// once, and the host starts presenting it at the same moment.
  Future<void> _beginPairing(String id) async {
    if (!_originAuthorized) {
      _send(bridgeError(id: id, code: BridgeErrorCode.notPermitted));
      return;
    }
    _cancelPairingPoll();
    final BridgePairingReply? reply;
    try {
      reply = await stateSource.pairBegin();
    } on BridgeRefusal catch (refusal) {
      _send(bridgeError(id: id, code: refusal.code));
      return;
    }
    if (reply == null) {
      _send(bridgeError(id: id, code: BridgeErrorCode.appNotRunning));
      return;
    }
    _send(bridgeReply(id: id, type: 'pairing', body: reply.toWire()));
    if (reply.state != BridgePairingFlowState.pending || _shuttingDown) return;
    _pairingDeadline = DateTime.now().toUtc().add(
          Duration(seconds: reply.expiresInSeconds + 15),
        );
    _pairingPoll = Timer.periodic(
      const Duration(seconds: 1),
      (_) => unawaited(_pollPairing()),
    );
  }

  void _cancelPairingPoll() {
    _pairingPoll?.cancel();
    _pairingPoll = null;
    _pairingDeadline = null;
  }

  Future<void> _pollPairing() async {
    if (_pairingPollInFlight || _pairingPoll == null || _shuttingDown) return;
    _pairingPollInFlight = true;
    try {
      final reply = await stateSource.pairPoll();
      if (_pairingPoll == null || _shuttingDown) return;
      if (reply == null || reply.state == BridgePairingFlowState.pending) {
        final deadline = _pairingDeadline;
        if (deadline != null && !DateTime.now().toUtc().isBefore(deadline)) {
          _cancelPairingPoll();
          _send(bridgeEvent(
            type: 'pairing',
            body: BridgePairingReply(state: BridgePairingFlowState.expired)
                .toWire(),
          ));
        }
        return;
      }
      _cancelPairingPoll();
      // The one message that carries the pairing credential. Not logged, and
      // the extension stores it only after checking its shape.
      _send(bridgeEvent(type: 'pairing', body: reply.toWire()));
      if (reply.state == BridgePairingFlowState.approved) {
        _lastPushed = null;
        await _pushIfChanged();
        if (!_subscribed) {
          _send(bridgeEvent(type: 'status', body: (await _snapshot()).toWire()));
        }
      }
    } finally {
      _pairingPollInFlight = false;
    }
  }

  Future<void> _withCredentialLifecycle(Future<void> Function() operation) {
    final result = _credentialIssues.then((_) async {
      if (!_shuttingDown) await operation();
    });
    _credentialIssues = result.then<void>((_) {}, onError: (Object _, StackTrace __) {});
    return result;
  }

  Future<void> _issueCredential(String id) =>
      _withCredentialLifecycle(() => _issueCredentialNow(id));

  Future<void> _revokeCredential() => _withCredentialLifecycle(() async {
    await _proxy?.stop();
    _proxy = null;
    _credential = null;
  });

  Future<void> _issueCredentialNow(String id) async {
    // Configuration gate only. Same-user launchers can claim an allowed
    // origin. This token grants a local, tunnel-gated CONNECT proxy, not
    // authenticated browser identity or authority to control the VPN.
    // An empty allowlist is the pre-provisioning state (store IDs are not
    // yet recorded); --selftest still works and the host still answers
    // status queries, but credentials are refused until identity is
    // provisioned.
    if (!_originAuthorized) {
      _send(bridgeError(
        id: id,
        code: BridgeErrorCode.appNotRunning,
      ));
      stderr.writeln(
        'native-host refused: caller origin '
        '${_callerOrigin ?? "(none; direct execution)"} is not in the '
        'allowed-origins set; proxy credential refused.',
      );
      return;
    }

    // NO SOCKET UNTIL THE DESKTOP SIDE SAYS IT WOULD ADMIT TRAFFIC.
    //
    // This used to issue a credential and bind two loopback listeners for
    // anybody who asked, whatever the tunnel state. Nothing could get through
    // them -- the gate is shut and the proxy answers 503 -- but they were a
    // listening socket the user had not asked for, opened as a side effect of a
    // browser starting. `controller.js` already declines to ask before
    // `proxyReady`, and that politeness was the only thing enforcing it; a
    // browser extension is not where this rule belongs.
    // (Contract diff 2026-08-07, case C.)
    final BridgeStatus before = await _snapshot();
    if (_shuttingDown) return;
    if (!browserBridgeAppIpcMayIssueProxyCredential(before)) {
      _send(bridgeError(id: id, code: BridgeErrorCode.appNotRunning));
      return;
    }
    if (_credential?.isExpired == true) {
      await _proxy?.stop();
      _proxy = null;
      _credential = null;
    }
    _credential ??= ProxyCredential.generate();
    if (_proxy == null) {
      final proxy = BridgeProxyServer(gate: gate, credential: _credential!);
      await proxy.start();
      // Single plaintext listener. No TLS per ruling.
      _proxy = proxy;
    }
    final status = await _snapshot();
    // The one message that carries the token. It is not logged here, not
    // written to disk, and the extension is required to keep it in memory
    // only.
    _send(bridgeReply(id: id, type: 'proxy_credential', body: <String, Object?>{
      'token': _credential!.token,
      'proxyPort': _proxy!.port,
      'expiresInSeconds':
          _credential!.expiresAt.difference(DateTime.now().toUtc()).inSeconds,
      ...status.toWire(),
    }));
  }

  /// The tunnel state from the state source, overlaid with the proxy port.
  Future<BridgeStatus> _snapshot() async {
    return _overlay(await stateSource.read());
  }

  BridgeStatus _overlay(BridgeStatus status) {
    gate.apply(status);
    final BridgeProxyServer? proxy = _proxy;
    if (proxy == null) return status;
    return status.copyWithProxy(
      proxyPort: proxy.port,
    );
  }

  String? _lastPushed;

  Future<void> _pushIfChanged() async {
    if (!_subscribed) return;
    if (_credential?.isExpired == true) {
      await _issueCredential('');
    }
    final status = await _snapshot();
    final wire = status.toWire();
    final signature = wire.toString();
    if (signature == _lastPushed) return;
    _lastPushed = signature;
    _send(bridgeEvent(type: 'status', body: wire));
  }
}

Future<void> main(List<String> args) async {
  final os = Platform.operatingSystem;
  final winn = resolveWinnState(operatingSystem: os, connected: false);

  // Browsers pass the caller origin (and on Windows a parent-window handle) as
  // extra argv. Those must be ignored. `--state-file` must not: it is the
  // harness-only override that would fail this host open.
  if (args.any((String argument) =>
      argument == '--state-file' || argument.startsWith('--state-file='))) {
    stderr.writeln(
      'native-host refused: production host has no state-file override. '
      'Tunnel state is unobserved and fail-closed (app_not_running).',
    );
    exit(65);
  }

  // `--selftest` proves the framing and the address guard without a browser.
  if (args.contains('--selftest')) {
    stderr.writeln('host=$kBridgeHostName v=$kBridgeProtocolVersion os=$os '
        'winn=${winn.wire} stateSource=app-ipc failClosed=true '
        'nativeOrderLittle=${assertNativeOrderIsLittle()}');
    return;
  }

  // Chromium supplies an origin URL; Firefox supplies a manifest path and
  // its stable add-on ID. Only one configured identity may identify a launch.
  final Set<String> origins = readAllowedOriginsFromManifestDirectory();
  final String? callerOrigin = resolveCallerOrigin(args, origins);

  final host = BridgeHost(
    stateSource: AppIpcStateSource(winn: winn),
    operatingSystem: os,
    allowedOrigins: origins,
  );
  host.setCallerOrigin(callerOrigin);
  await host.run();
}

/// Resolve the documented browser launch forms without relaxing the allowlist.
String? resolveCallerOrigin(List<String> args, Set<String> origins) {
  final candidates = args.where((argument) =>
      argument.startsWith('chrome-extension://') ||
      argument.startsWith('moz-extension://') ||
      origins.contains(argument)).toList(growable: false);
  if (candidates.length != 1 || !origins.contains(candidates.single)) {
    return null;
  }
  final caller = candidates.single;
  if (caller.startsWith('chrome-extension://')) return caller;
  if (args.length < 2 || args[1] != caller ||
      !File(args[0]).isAbsolute || !args[0].endsWith('.json')) {
    return null;
  }
  return caller;
}

/// Read bounded public browser identities beside the installed executable.
/// The JSON companion retains separate browser slots across installations.
/// Missing or malformed configuration denies credentials.
Set<String> readAllowedOriginsFromManifestDirectory({Directory? directory}) {
  final installed = directory ?? File(Platform.script.toFilePath()).parent;
  final companion = File('${installed.path}/allowed_origins.txt');
  RandomAccessFile? reader;
  try {
    if (FileSystemEntity.typeSync(companion.path, followLinks: false) !=
        FileSystemEntityType.file) return const <String>{};
    reader = companion.openSync();
    final bytes = reader.readSync(4097);
    if (bytes.length > 4096) return const <String>{};
    final document = jsonDecode(utf8.decode(bytes));
    if (document is! Map || document.length > 3) return const <String>{};
    final origins = <String>{};
    for (final entry in document.entries) {
      if (!const ['chrome', 'edge', 'firefox'].contains(entry.key)) {
        return const <String>{};
      }
      final values = entry.value;
      if (values is! List || values.length != 1 || values.single is! String) {
        return const <String>{};
      }
      final value = values.single as String;
      final valid = entry.key == 'firefox'
          ? value == 'companion@winsvpn.org'
          : RegExp(r'^chrome-extension://[a-p]{32}/$').hasMatch(value);
      if (!valid) return const <String>{};
      origins.add(value);
    }
    return origins;
  } on FileSystemException {
    return const <String>{};
  } on FormatException {
    return const <String>{};
  } finally {
    reader?.closeSync();
  }
}
