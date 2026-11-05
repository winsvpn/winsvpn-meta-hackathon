/// Winn Protocol v3 -- WEB control-plane session surface (Flutter widget).
///
/// # What this is for
///
/// The user-facing half of the web/desktop control plane: paste a winn/3
/// served config, hit Resolve, and get a resolved session WITHOUT a native
/// tunnel. There is no kernel `tun`, no NetworkExtension and no VpnService on
/// the web surface; this widget's whole job is to run the resolved config
/// through the SAME authoritative gate the native platforms use
/// (`lib/winn_protocol_web_control_plane.dart`) and render the outcome.
///
/// # Config-only, never a raw HTTP proxy
///
/// This is deliberately not a proxy of any kind. It resolves a config and
/// renders the session. There is no port, no `CONNECT`, no upstream socket, no
/// packet path, and no affordance that could be mistaken for a raw HTTP proxy.
/// The plain-HTTP-proxying carve-out that a browser bridge would otherwise
/// have to defend is not present here at all: [WinnWebControlPlaneApp] surfaces
/// a config and nothing else. The parallel bridge (`browser_bridge_proxy.dart`)
/// refuses non-CONNECT heads separately; this widget never gets a chance to be
/// such a head.
library;

import 'dart:convert';

import 'package:flutter/material.dart';

import 'winn_protocol_web_control_plane.dart';

/// How [WinnWebControlPlaneApp] resolves a pasted config. Injectable so tests
/// can drive refusals without depending on the exact fixture shape.
typedef WinnWebControlPlaneResolver = WinnWebControlPlaneEmission Function(
    Map<String, dynamic> config);

/// Default resolver: the authoritative, config-only emission.
WinnWebControlPlaneEmission _defaultResolver(
        Map<String, dynamic> config) =>
    emitWinnProtocolWebControlPlane(config: config);

/// A small web control-plane surface that turns a pasted winn/3 served config
/// into a resolved session, without starting any native tunnel.
class WinnWebControlPlaneApp extends StatefulWidget {
  const WinnWebControlPlaneApp({
    super.key,
    this.initialText,
    this.resolve = _defaultResolver,
  });

  /// Initial pasted config JSON. When null the paste field starts empty.
  final String? initialText;

  /// The config-only resolver; defaults to [emitWinnProtocolWebControlPlane].
  final WinnWebControlPlaneResolver resolve;

  @override
  State<WinnWebControlPlaneApp> createState() => _WinnWebControlPlaneAppState();
}

enum _ConfigParseState { none, ok, empty, notJson, notObject }

class _WinnWebControlPlaneAppState extends State<WinnWebControlPlaneApp> {
  late final TextEditingController _controller;
  _ConfigParseState _parse = _ConfigParseState.none;
  WinnWebControlPlaneEmission? _emission;

  @override
  void initState() {
    super.initState();
    _controller = TextEditingController(text: widget.initialText ?? '');
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _resolve() {
    final text = _controller.text.trim();
    setState(() {
      _parse = _ConfigParseState.none;
      _emission = null;
      if (text.isEmpty) {
        _parse = _ConfigParseState.empty;
        return;
      }
      Object? decoded;
      try {
        decoded = jsonDecode(text);
      } catch (_) {
        _parse = _ConfigParseState.notJson;
        return;
      }
      if (decoded is! Map) {
        _parse = _ConfigParseState.notObject;
        return;
      }
      _parse = _ConfigParseState.ok;
      _emission = widget.resolve(Map<String, dynamic>.from(decoded));
    });
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: const Text('winn/3 web control plane')),
        body: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              const Text(
                'Paste a winn/3 config to resolve a session. Resolves a '
                'config only: starts no native tunnel, proxies nothing.',
                style: TextStyle(fontWeight: FontWeight.w600),
              ),
              const SizedBox(height: 12),
              Expanded(
                child: TextField(
                  controller: _controller,
                  maxLines: 18,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                  decoration: const InputDecoration(
                    border: OutlineInputBorder(),
                    hintText: '{"protocol_version":"winn/3", ...}',
                  ),
                ),
              ),
              const SizedBox(height: 12),
              ElevatedButton(
                onPressed: _resolve,
                child: const Text('Resolve session'),
              ),
              const SizedBox(height: 12),
              _ResultView(parse: _parse, emission: _emission),
            ],
          ),
        ),
      ),
    );
  }
}

class _ResultView extends StatelessWidget {
  const _ResultView({required this.parse, required this.emission});

  final _ConfigParseState parse;
  final WinnWebControlPlaneEmission? emission;

  @override
  Widget build(BuildContext context) {
    if (parse != _ConfigParseState.none && emission == null) {
      final String reason;
      switch (parse) {
        case _ConfigParseState.empty:
          reason = 'config_error_empty';
        case _ConfigParseState.notJson:
          reason = 'config_error_not_json';
        case _ConfigParseState.notObject:
          reason = 'config_error_not_object';
        default:
          reason = 'config_error_unknown';
      }
      return Text('error_code_$reason');
    }
    final e = emission;
    if (e == null) {
      return const Text('no_session_resolved');
    }
    if (!e.accepted) {
      return Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          const Text('refused', style: TextStyle(color: Colors.red)),
          const SizedBox(height: 4),
          Text(e.errors.join(', ')),
        ],
      );
    }
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: <Widget>[
        Text('carrier: ${e.carrier ?? ''}'),
        Text('session: ${e.sessionId ?? '(none)'}'),
        const SizedBox(height: 6),
        const Text('resolved [winn] section:', style: TextStyle(fontWeight: FontWeight.w600)),
        const SizedBox(height: 4),
        SelectableText(
          e.iniDocument ?? '',
          style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
        ),
      ],
    );
  }
}
