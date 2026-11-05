import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;

// Round R2: in-app prepaid card redemption (new account or extension), with an
// optional referral and promo code. Shown only on direct-distribution builds
// (see _canRedeemPrepaidInApp in main.dart): Apple 3.1.1 forbids an own
// license-key unlock in App Store builds and Google Play's Payments policy
// governs Play builds.
//
// Localization: every visible string, and every hub message shown verbatim,
// goes through [PrepaidRedemptionDialog.translate] with its English text as the
// key. main.dart passes its `_t` lookup, which holds the Burmese.
//
// The request is frozen at the first submit and replayed byte for byte on a
// retry, because the hub keys idempotent recovery on the code and a lost
// response may follow a committed redemption. Credentials live only in this
// dialog's memory.

/// One frozen redemption request.
class PrepaidRedemptionRequest {
  PrepaidRedemptionRequest(Map<String, String> fields, Map<String, String> auth)
      : body = jsonEncode(fields),
        headers = Map.unmodifiable(
            <String, String>{'Content-Type': 'application/json', ...auth});

  final String body;
  final Map<String, String> headers;
}

typedef PrepaidRedemptionPost = Future<http.Response> Function(
    String path, PrepaidRedemptionRequest request);

/// Canonical form the hub HMACs: upper case, A-Z0-9 only, I/L -> 1, O -> 0,
/// U -> V (same folding as web/index.html and the hub).
String normalizePrepaidCode(String raw) => raw
    .toUpperCase()
    .replaceAll(RegExp('[^A-Z0-9]'), '')
    .replaceAll(RegExp('[IL]'), '1')
    .replaceAll('O', '0')
    .replaceAll('U', 'V');

final RegExp _codePattern = RegExp(r'^[0-9ABCDEFGHJKMNPQRSTVWXYZ]{27}$');
final RegExp _promoPattern = RegExp(r'^[A-Z0-9][A-Z0-9_-]{3,31}$');

/// Formats 12 digits as 1234-5678-9012, or returns '' when it is not an
/// account number.
String formatAccountNumberForRedemption(String raw) {
  final digits = raw.replaceAll(RegExp(r'\D'), '');
  if (digits.length != 12) return '';
  return '${digits.substring(0, 4)}-${digits.substring(4, 8)}-${digits.substring(8)}';
}

String _untranslated(String english) => english;

class PrepaidRedemptionDialog extends StatefulWidget {
  const PrepaidRedemptionDialog({
    super.key,
    required this.post,
    this.account = '',
    this.deviceId = '',
    this.deviceToken = '',
    this.onNewCredentials,
    this.onAccountExtended,
    this.translate = _untranslated,
  });

  final PrepaidRedemptionPost post;

  /// The app's string lookup (main.dart `_t`): English in, the UI language
  /// out, English when there is no entry.
  final String Function(String english) translate;

  /// The signed-in account, or '' when signed out.
  final String account;
  final String deviceId;
  final String deviceToken;

  /// Called with a NEW account's number and setup key after the user confirms
  /// they saved them, so a signed-out app can prefill its sign-in fields.
  final void Function(String accountNumber, String setupKey)? onNewCredentials;

  /// Called with the new expiry after an extension succeeds, so the signed-in
  /// app can refresh its account status (R2-AUDIT-09).
  final void Function(String expirationDate)? onAccountExtended;

  @override
  State<PrepaidRedemptionDialog> createState() =>
      _PrepaidRedemptionDialogState();
}

class _PrepaidRedemptionDialogState extends State<PrepaidRedemptionDialog> {
  final _code = TextEditingController();
  final _otherAccount = TextEditingController();
  final _referral = TextEditingController();
  final _promo = TextEditingController();
  final _email = TextEditingController();
  late bool _extendMine = widget.account.isNotEmpty;
  PrepaidRedemptionRequest? _request;
  String _ackCode = '';
  Map<String, dynamic>? _result;
  bool _busy = false;
  bool _saved = false;
  bool _acked = false;
  String _message = '';
  DateTime? _retryAfter;

  @override
  void dispose() {
    for (final c in [_code, _otherAccount, _referral, _promo, _email]) {
      c.clear();
      c.dispose();
    }
    _request = null;
    super.dispose();
  }

  bool get _signedIn => widget.account.isNotEmpty;

  // {name} placeholders are filled after the lookup, so a translation may
  // put them anywhere in the sentence.
  String _tr(String english, [Map<String, String> values = const {}]) {
    var text = widget.translate(english);
    values.forEach((name, value) => text = text.replaceAll('{$name}', value));
    return text;
  }

  String? _buildRequest() {
    final code = normalizePrepaidCode(_code.text);
    if (!_codePattern.hasMatch(code)) {
      return _tr('That code looks incomplete. It should be 27 characters (shown as XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXX).');
    }
    final fields = <String, String>{'code': code};
    final auth = <String, String>{};
    if (_signedIn && _extendMine) {
      fields['account_number'] = widget.account;
      if (widget.deviceToken.isNotEmpty && widget.deviceId.isNotEmpty) {
        // The device's own bearer proves ownership, so even a lapsed
        // account can be renewed from the app that is signed in to it.
        fields['device_id'] = widget.deviceId;
        auth['Authorization'] = 'Bearer ${widget.deviceToken}';
      }
    } else if (!_signedIn && _otherAccount.text.trim().isNotEmpty) {
      final target = formatAccountNumberForRedemption(_otherAccount.text);
      if (target.isEmpty) {
        return _tr('Enter the account number as 12 digits (1234-5678-9012), or leave it empty to create a new account.');
      }
      fields['account_number'] = target;
    }
    final referral = _referral.text.trim().replaceAll(RegExp(r'[^\w-]'), '');
    if (referral.isNotEmpty) fields['referral_code'] = referral;
    final promo = _promo.text.trim().toUpperCase();
    if (promo.isNotEmpty) {
      if (!_promoPattern.hasMatch(promo)) {
        return _tr('That promo code is not valid. Check it or leave the field empty.');
      }
      fields['promo_code'] = promo;
    }
    final email = _email.text.trim();
    if (email.isNotEmpty && !fields.containsKey('account_number')) {
      fields['email'] = email;
    }
    _ackCode = code;
    _request = PrepaidRedemptionRequest(fields, auth);
    return null;
  }

  Future<void> _submit() async {
    if (_busy || _result != null) return;
    final wait = _retryAfter;
    if (wait != null && DateTime.now().isBefore(wait)) {
      setState(() => _message = _tr('Too many attempts. Please wait a few minutes and try again.'));
      return;
    }
    if (_request == null) {
      final problem = _buildRequest();
      if (problem != null) {
        setState(() => _message = problem);
        return;
      }
    }
    setState(() {
      _busy = true;
      _message = _tr('Redeeming...');
    });
    try {
      final response = await widget.post('/api/redeem', _request!);
      if (!mounted) return;
      if (response.statusCode == 429) {
        final seconds = int.tryParse(response.headers['retry-after'] ?? '') ?? 300;
        _retryAfter = DateTime.now().add(Duration(seconds: seconds.clamp(1, 3600).toInt()));
        setState(() => _message = _tr('Too many attempts. Please wait a few minutes and try again.'));
        return;
      }
      final data = jsonDecode(response.body);
      if (response.statusCode != 200 || data is! Map<String, dynamic> || data['ok'] is! bool) {
        throw const FormatException('unconfirmed');
      }
      if (data['ok'] != true) {
        final status = (data['status'] ?? '').toString();
        final serverMessage = (data['message'] ?? '').toString();
        setState(() {
          // The code was not used (a refusal) or is not redeemable: either
          // way the user may edit the request and try again. A hub message is
          // looked up by its exact English text, as the website does.
          _request = null;
          _message = status.isNotEmpty && status != 'not_redeemable' && serverMessage.isNotEmpty
              ? _tr(serverMessage)
              : _tr('That code is not valid, or has already been redeemed.');
        });
        return;
      }
      final expiry = data['expiration_date'];
      final extended = data['mode'] == 'extend';
      final key = (data['setup_key'] ?? '').toString();
      if (expiry is! String || expiry.trim().isEmpty || data['account_number'] is! String ||
          (!extended && key.isEmpty)) {
        throw const FormatException('incomplete');
      }
      setState(() {
        _result = data;
        _acked = extended; // An extension carries no secret to acknowledge.
        _message = extended
            ? _tr('Account extended. Your existing credentials and devices are unchanged.')
            : _tr('Redeemed. Save your account number and setup key now: the setup key is shown only once.');
      });
      if (extended) widget.onAccountExtended?.call(expiry.trim());
    } catch (_) {
      if (mounted) {
        setState(() => _message =
            _tr('Redemption could not be confirmed. Retry with the same details: it may already have been accepted.'));
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _acknowledge() async {
    final result = _result;
    if (_busy || result == null || !_saved || _acked) return;
    setState(() => _busy = true);
    try {
      final ack = PrepaidRedemptionRequest({'code': _ackCode}, const {});
      final response = await widget.post('/api/redeem/ack', ack);
      if (!mounted) return;
      if (response.statusCode != 200) throw const FormatException('ack');
      setState(() {
        _acked = true;
        _message = _tr('Confirmed. Keep your saved credentials safe; the setup key will not be shown again.');
      });
      widget.onNewCredentials?.call(
          (result['account_number'] ?? '').toString(), (result['setup_key'] ?? '').toString());
    } catch (_) {
      if (mounted) {
        setState(() => _message = _tr('Could not confirm yet. Your credentials above are still valid; try again in a moment.'));
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Widget _field(TextEditingController controller, String label, int max,
          {TextInputType? keyboard, ValueChanged<String>? onChanged}) =>
      TextField(
        controller: controller,
        enabled: _request == null && !_busy,
        maxLength: max,
        autocorrect: false,
        enableSuggestions: false,
        keyboardType: keyboard,
        onChanged: onChanged,
        decoration: InputDecoration(labelText: label),
      );

  List<Widget> _resultWidgets(Map<String, dynamic> result) {
    final account = (result['account_number'] ?? '').toString();
    final key = (result['setup_key'] ?? '').toString();
    final expiry = (result['expiration_date'] ?? '').toString();
    final referralDays = (result['referral_bonus_days'] as num?)?.toInt() ?? 0;
    final promoDays = (result['promo_bonus_days'] as num?)?.toInt() ?? 0;
    final accountLine = _tr('Account number: {account}', {'account': account});
    final keyLine = _tr('Setup key: {setup_key}', {'setup_key': key});
    return [
      SelectableText(accountLine),
      if (key.isNotEmpty) SelectableText(keyLine),
      SelectableText(_tr('Expires: {date}',
          {'date': expiry.length >= 10 ? expiry.substring(0, 10) : expiry})),
      if (referralDays > 0)
        Text(_tr('Referral bonus days added: {days}', {'days': '$referralDays'})),
      if (promoDays > 0)
        Text(_tr('Promo bonus days added: {days}', {'days': '$promoDays'})),
      if (key.isNotEmpty) ...[
        TextButton(
          onPressed: () async {
            try {
              await Clipboard.setData(ClipboardData(text: '$accountLine\n$keyLine'));
            } catch (_) {
              if (mounted) {
                setState(() => _message = _tr('Copy failed: select and copy manually'));
              }
            }
          },
          child: Text(_tr('Copy')),
        ),
        if (!_acked)
          CheckboxListTile(
            value: _saved,
            title: Text(_tr('I have saved my account number and setup key securely')),
            onChanged: _busy ? null : (v) => setState(() => _saved = v ?? false),
          ),
      ],
    ];
  }

  @override
  Widget build(BuildContext context) {
    final result = _result;
    final newAccount = !(_signedIn && _extendMine) && _otherAccount.text.trim().isEmpty;
    return PopScope(
      canPop: !_busy,
      child: AlertDialog(
        title: Text(_tr('Redeem a prepaid card')),
        content: SizedBox(
          width: 440,
          child: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                if (result == null) ...[
                  _field(_code, _tr('Prepaid code'), 40),
                  if (_signedIn)
                    SwitchListTile(
                      title: Text(_tr('Add the time to my account ({account})',
                          {'account': widget.account})),
                      subtitle: Text(_tr('Turn off to create a new account instead')),
                      value: _extendMine,
                      onChanged: _request != null || _busy
                          ? null
                          : (v) => setState(() => _extendMine = v),
                    ),
                  if (!_signedIn)
                    _field(_otherAccount, _tr('Existing account number (optional)'), 14,
                        keyboard: TextInputType.number,
                        // R2-AUDIT-07: the email field only applies to a new
                        // account, so rebuild when this field changes.
                        onChanged: (_) => setState(() {})),
                  _field(_referral, _tr('Referral code (optional)'), 64),
                  _field(_promo, _tr('Promo code (optional)'), 32),
                  if (newAccount) _field(_email, _tr('Email (optional, for setup key delivery)'), 254,
                      keyboard: TextInputType.emailAddress),
                ],
                if (result != null) ..._resultWidgets(result),
                Semantics(liveRegion: true, child: Text(_message)),
              ],
            ),
          ),
        ),
        actions: [
          TextButton(
            onPressed: _busy ? null : () => Navigator.pop(context),
            child: Text(_tr('Close')),
          ),
          if (result == null)
            FilledButton(
              onPressed: _busy ? null : _submit,
              child: Text(_request == null ? _tr('Redeem Code') : _tr('Retry unchanged request')),
            ),
          if (result != null && !_acked)
            FilledButton(
              onPressed: _busy || !_saved ? null : _acknowledge,
              child: Text(_tr('Confirm I have saved these')),
            ),
        ],
      ),
    );
  }
}
