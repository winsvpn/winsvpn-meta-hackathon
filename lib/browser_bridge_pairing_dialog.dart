// In-app confirmation and settings UI for browser-extension pairing (R20 A1).
//
// The pairing state machine lives in browser_bridge_app_ipc.dart and has no
// Flutter dependency. This file is only the two screens the user sees: the
// confirmation that grants a browser control of the VPN, and the list that
// takes it away again.

import 'dart:async';

import 'package:flutter/material.dart';

import 'browser_bridge_app_ipc.dart';

typedef BrowserBridgePairingTranslate = String Function(String english);

String _identity(String english) => english;

/// "123456" as "123 456", so the two halves are easy to compare.
String formatBrowserBridgePairingCode(String code) {
  if (code.length != 6) return code;
  return '${code.substring(0, 3)} ${code.substring(3)}';
}

/// Ask the user whether a browser extension may control the VPN.
///
/// Completes true only when the user presses Allow before [request]
/// expires. Dismissing, Deny, and the expiry all complete false. The browser
/// name is the extension's own claim, which is why the text asks the user to
/// compare the code with the one in the extension popup.
Future<bool> confirmBrowserBridgePairing(
  BuildContext context,
  BrowserBridgePairingRequest request, {
  BrowserBridgePairingTranslate t = _identity,
  DateTime Function()? now,
}) async {
  final navigator = Navigator.of(context, rootNavigator: true);
  final remaining =
      request.expiresAt.difference((now ?? DateTime.now)().toUtc());
  if (remaining <= Duration.zero) return false;
  final route = DialogRoute<bool>(
    context: context,
    barrierDismissible: false,
    builder: (dialogContext) => AlertDialog(
      key: const Key('browser_pairing_dialog'),
      title: Text(t('Allow a browser to control the VPN?')),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          Text(
            t('A browser extension that says it is ${request.label} asks to '
                'connect and disconnect Win\'s VPN on this computer. '
                'Disconnecting also turns off the kill switch.'),
          ),
          const SizedBox(height: 12),
          Text(
            t('Allow only if the Win\'s VPN extension popup shows this code:'),
          ),
          const SizedBox(height: 8),
          Center(
            child: SelectableText(
              formatBrowserBridgePairingCode(request.code),
              key: const Key('browser_pairing_code'),
              style: const TextStyle(
                fontSize: 32,
                fontWeight: FontWeight.w700,
                letterSpacing: 4,
              ),
            ),
          ),
          const SizedBox(height: 12),
          Text(
            t('If you did not just ask for this, press Deny. '
                'You can remove paired browsers later in the app.'),
            style: const TextStyle(fontSize: 12),
          ),
        ],
      ),
      actions: <Widget>[
        TextButton(
          key: const Key('browser_pairing_deny'),
          autofocus: true,
          onPressed: () => Navigator.of(dialogContext).pop(false),
          child: Text(t('Deny')),
        ),
        TextButton(
          key: const Key('browser_pairing_allow'),
          onPressed: () => Navigator.of(dialogContext).pop(true),
          child: Text(t('Allow')),
        ),
      ],
    ),
  );
  final timer = Timer(remaining, () {
    if (route.isActive) navigator.removeRoute(route, false);
  });
  try {
    return await navigator.push(route) == true;
  } finally {
    timer.cancel();
  }
}

/// List paired browsers with a Revoke button for each.
Future<void> showBrowserBridgePairingsDialog(
  BuildContext context,
  BrowserBridgePairingRegistry registry, {
  BrowserBridgePairingTranslate t = _identity,
}) {
  return showDialog<void>(
    context: context,
    builder: (dialogContext) {
      return StreamBuilder<void>(
        stream: registry.changes,
        builder: (context, _) {
          final records = registry.records;
          return AlertDialog(
            key: const Key('browser_pairings_dialog'),
            title: Text(t('Paired browsers')),
            content: SizedBox(
              width: 420,
              child: records.isEmpty
                  ? Text(t('No browser extension can control the VPN.'))
                  : Column(
                      mainAxisSize: MainAxisSize.min,
                      children: <Widget>[
                        Text(
                          t('These browser extensions can connect and '
                              'disconnect the VPN. Revoke one to return it '
                              'to status only.'),
                          style: const TextStyle(fontSize: 12),
                        ),
                        const SizedBox(height: 8),
                        for (final record in records)
                          ListTile(
                            key: Key('browser_pairing_${record.label}'),
                            dense: true,
                            contentPadding: EdgeInsets.zero,
                            title: Text(record.label),
                            subtitle: Text(
                              t('Paired ${_day(record.createdAt)}'),
                            ),
                            trailing: TextButton(
                              key:
                                  Key('browser_pairing_revoke_${record.label}'),
                              onPressed: () => unawaited(
                                _revoke(context, registry, record.origin, t),
                              ),
                              child: Text(t('Revoke')),
                            ),
                          ),
                      ],
                    ),
            ),
            actions: <Widget>[
              TextButton(
                onPressed: () => Navigator.of(dialogContext).pop(),
                child: Text(t('Close')),
              ),
            ],
          );
        },
      );
    },
  );
}

String _day(DateTime at) {
  final local = at.toLocal();
  String two(int value) => value.toString().padLeft(2, '0');
  return '${local.year}-${two(local.month)}-${two(local.day)}';
}

Future<void> _revoke(
  BuildContext context,
  BrowserBridgePairingRegistry registry,
  String origin,
  BrowserBridgePairingTranslate t,
) async {
  final messenger = ScaffoldMessenger.maybeOf(context);
  try {
    await registry.revoke(origin);
  } catch (_) {
    messenger?.showSnackBar(SnackBar(
      content: Text(t('Revoked for now, but the change could not be saved. '
          'Revoke it again after restarting the app.')),
    ));
  }
}
