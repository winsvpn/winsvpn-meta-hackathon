/// The paste-in box: the primary intake channel for a discovery record.
///
/// ## Why a text field is the right answer here
///
/// Every automated intake channel a single unchangeable release could ship —
/// a DoH TXT lookup, a well-known URL, a rendezvous host — is a fixed target
/// whose resolver set and query name are sitting in the shipped binary for
/// anyone to read. Blocked once, blocked permanently, because there is no
/// second release to move it.
///
/// A paste box has no rendezvous to block and emits **no network traffic at
/// all** until the user already holds a working address. The record is signed,
/// so its transport is untrusted and therefore fungible: Signal, Telegram,
/// a photo of a QR code, a slip of paper, or read aloud and retyped all carry
/// it equally safely. Rotation becomes a distribution problem rather than a
/// network one a censor can sit on.
///
/// The complement, not shipped here, is pre-positioning records through the
/// working tunnel for users who are already connected. That covers the warm
/// population; this covers the cold-start user who installed after the block
/// and has never connected — which is exactly the person a censored rollout
/// leaves behind.
///
/// ## What the user sees
///
/// Deliberately dull, and deliberately unbranded. On a phone that may be
/// inspected at a checkpoint, a screen captioned "censorship bypass" is
/// evidence. This is presented as a support/connection code — the wording is
/// ordinary, the failure messages name no adversary, and nothing on screen
/// announces what the feature defends against.
library;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'discovery_intake.dart';

/// Plain-language result text for each outcome.
///
/// Pure and top-level so the wording is testable without building a widget.
/// Every failure is *specific* — "that code was already used" and "that code
/// is not for this app" send a user to different places, and a single generic
/// "invalid code" would make a real distribution problem undebuggable over a
/// messaging app.
///
/// None of these strings name a censor, a country, or a blocked host: they are
/// read by the user and potentially by whoever else is holding the phone.
String discoveryIntakeMessage(DiscoveryIntakeOutcome outcome) {
  switch (outcome.status) {
    case DiscoveryIntakeStatus.accepted:
      final count = outcome.record?.endpoints.length ?? 0;
      return count == 1
          ? 'Code accepted. 1 new server address saved.'
          : 'Code accepted. $count new server addresses saved.';
    case DiscoveryIntakeStatus.alreadyHeld:
      return 'This device already has that code. Nothing to do.';
    case DiscoveryIntakeStatus.notProvisioned:
      return 'This version of the app cannot accept connection codes.';
    case DiscoveryIntakeStatus.empty:
      return 'Paste the code first.';
    case DiscoveryIntakeStatus.malformed:
      return 'That does not look like a complete code. Copy the whole line, '
          'including the long ending, and try again.';
    case DiscoveryIntakeStatus.replayed:
      return 'That code has already been used on this device. Ask for the '
          'newest one.';
    case DiscoveryIntakeStatus.expired:
      return 'That code has expired. Ask for a newer one.';
    case DiscoveryIntakeStatus.unsafeEndpoints:
      return 'That code does not contain usable server addresses.';
    case DiscoveryIntakeStatus.badSignature:
      return 'That code could not be verified. It may have been altered in '
          'transit, or it may not be from this app.';
  }
}

/// A modal sheet that verifies a pasted discovery record.
class DiscoveryPasteInSheet extends StatefulWidget {
  const DiscoveryPasteInSheet({
    super.key,
    required this.intake,
    required this.currentState,
    required this.onAccepted,
    this.now,
    this.onIntake,
    this.translate,
  });

  final DiscoveryIntake intake;

  /// The device's discovery state at the moment the sheet opened.
  final DiscoveryIntakeState currentState;

  /// Called once, with the advanced state, when a record verifies. The caller
  /// persists it and hands the endpoints to the gateway sweep — this widget
  /// deliberately owns neither storage nor the sweep.
  final Future<void> Function(DiscoveryIntakeOutcome outcome) onAccepted;

  /// Injectable clock, so the sheet is testable without waiting for time.
  final DateTime Function()? now;
  final Future<DiscoveryIntakeOutcome> Function(String raw)? onIntake;

  /// Injectable translator; identity when absent.
  final String Function(String)? translate;

  @override
  State<DiscoveryPasteInSheet> createState() => _DiscoveryPasteInSheetState();
}

class _DiscoveryPasteInSheetState extends State<DiscoveryPasteInSheet> {
  final TextEditingController _controller = TextEditingController();
  late DiscoveryIntakeState _state = widget.currentState;
  DiscoveryIntakeOutcome? _outcome;
  bool _busy = false;
  bool _showDetails = false;

  String _t(String english) =>
      widget.translate?.call(english) ?? english;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  Future<void> _pasteFromClipboard() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    final text = data?.text;
    if (text == null || text.trim().isEmpty) return;
    _controller.text = text.trim();
    if (mounted) setState(() {});
  }

  Future<void> _apply() async {
    if (_busy) return;
    setState(() => _busy = true);
    try {
      final delegate = widget.onIntake;
      final outcome = delegate == null
          ? await widget.intake.acceptPastedRecord(
              _controller.text,
              now: (widget.now ?? DateTime.now)(),
              current: _state,
            )
          : await delegate(_controller.text);
      if (outcome.accepted && delegate == null) {
        await widget.onAccepted(outcome);
      }
      if (!mounted) return;
      setState(() {
        _outcome = outcome;
        _state = outcome.state;
        if (outcome.accepted) _controller.clear();
      });
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final outcome = _outcome;
    final provisioned = widget.intake.enforcing;

    return SafeArea(
      child: Padding(
        padding: EdgeInsets.only(
          left: 20,
          right: 20,
          top: 20,
          bottom: MediaQuery.of(context).viewInsets.bottom + 20,
        ),
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                _t('Enter connection code'),
                style: theme.textTheme.titleLarge,
              ),
              const SizedBox(height: 8),
              Text(
                _t('If the app cannot reach the service, you can enter a '
                    'connection code provided by support. Paste the whole '
                    'line exactly as you received it.'),
                style: theme.textTheme.bodyMedium,
              ),
              const SizedBox(height: 16),
              TextField(
                controller: _controller,
                enabled: provisioned && !_busy,
                minLines: 3,
                maxLines: 6,
                autocorrect: false,
                enableSuggestions: false,
                textInputAction: TextInputAction.newline,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 13),
                decoration: InputDecoration(
                  border: const OutlineInputBorder(),
                  hintText: _t('Paste code here'),
                  isDense: true,
                ),
              ),
              const SizedBox(height: 12),
              Row(
                children: [
                  OutlinedButton.icon(
                    onPressed:
                        provisioned && !_busy ? _pasteFromClipboard : null,
                    icon: const Icon(Icons.content_paste, size: 18),
                    label: Text(_t('Paste')),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: FilledButton(
                      onPressed: provisioned && !_busy ? _apply : null,
                      child: Text(_busy ? _t('Checking...') : _t('Apply')),
                    ),
                  ),
                ],
              ),
              if (outcome != null) ...[
                const SizedBox(height: 16),
                Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Icon(
                      outcome.accepted
                          ? Icons.check_circle_outline
                          : Icons.error_outline,
                      size: 20,
                      color: outcome.accepted
                          ? theme.colorScheme.primary
                          : theme.colorScheme.error,
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        _t(discoveryIntakeMessage(outcome)),
                        style: theme.textTheme.bodyMedium,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 4),
                // Diagnosable, not silent -- but folded away, and log-safe:
                // slot names and enum names only, never the code, a hostname,
                // or key material.
                TextButton(
                  onPressed: () =>
                      setState(() => _showDetails = !_showDetails),
                  child: Text(
                    _showDetails ? _t('Hide details') : _t('Details'),
                  ),
                ),
                if (_showDetails)
                  SelectableText(
                    outcome.diagnostics.describe(),
                    style: theme.textTheme.bodySmall
                        ?.copyWith(fontFamily: 'monospace'),
                  ),
              ],
              if (_state.hasEndpoints) ...[
                const SizedBox(height: 16),
                Text(
                  _state.acceptedSequence == null
                      ? _t('Saved addresses: ${_state.endpoints.length}')
                      : _t('Saved addresses: ${_state.endpoints.length} '
                          '(code #${_state.acceptedSequence})'),
                  style: theme.textTheme.bodySmall,
                ),
              ],
              if (!provisioned) ...[
                const SizedBox(height: 16),
                Text(
                  _t('Connection codes are not available in this build.'),
                  style: theme.textTheme.bodySmall
                      ?.copyWith(color: theme.colorScheme.error),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }
}

/// Present the paste-in sheet.
Future<void> showDiscoveryPasteInSheet(
  BuildContext context, {
  required DiscoveryIntake intake,
  required DiscoveryIntakeState currentState,
  required Future<void> Function(DiscoveryIntakeOutcome outcome) onAccepted,
  DateTime Function()? now,
  Future<DiscoveryIntakeOutcome> Function(String raw)? onIntake,
  String Function(String)? translate,
}) {
  return showModalBottomSheet<void>(
    context: context,
    isScrollControlled: true,
    builder: (context) => DiscoveryPasteInSheet(
      intake: intake,
      currentState: currentState,
      onAccepted: onAccepted,
      now: now,
      onIntake: onIntake,
      translate: translate,
    ),
  );
}
