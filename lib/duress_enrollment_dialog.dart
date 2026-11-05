/// The duress (emergency code) enrollment dialog.
///
/// Moved verbatim from main.dart's _showDuressEnrollmentDialog in L91 so a
/// widget test can run the real body, with the platform work behind
/// [DuressEnrollmentHooks]. Rule (Round UI Turn 8): a flow whose dialog a
/// relock removed never commits. [DuressEnrollmentHooks.stillAway] is checked
/// after every await, before any dialog-state change and before the
/// credential and contact are written; a relock removes the dialog itself
/// (decoy_cover.dart).
library;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'camouflage_policy.dart';
import 'duress_dispatch.dart';
import 'end_own_route.dart';
import 'local_security.dart';

// The dashboard's surface colours (main.dart _surfacePanel, _surfaceText,
// _flagRed); duress_enrollment_dialog_test pins them equal.
const Color _duressError = Color(0xFFDE2910);
const Color _duressText = Color(0xFF111827);
const Color _duressPanel = Color(0xD8FDFDFD);

class DuressEnrollmentHooks {
  const DuressEnrollmentHooks({
    required this.translate,
    required this.verifyRealPin,
    required this.requestSmsPermission,
    required this.enroll,
    required this.isPhoneShapedContact,
    required this.debugLog,
    required this.stillAway,
  });

  final String Function(String) translate;

  /// Verifies the real unlock code against the stored credential, with no
  /// side effects.
  final Future<bool> Function(String realPin) verifyRealPin;
  final Future<bool> Function() requestSmsPermission;
  /// Writes the enrollment; false (nothing written) when [stillAway] reports
  /// a relock inside it (main.dart _enrollDuress).
  final Future<bool> Function({
    required String realPin,
    required String duressPin,
    String? trustedPhone,
    String? trustedEmail,
    bool Function()? stillAway,
  }) enroll;
  final bool Function(String contact) isPhoneShapedContact;
  final void Function(String message) debugLog;

  /// True while the app is still unlocked in the decoy generation the dialog
  /// opened in.
  final bool Function() stillAway;
}

/// Shows the dialog. Returns 'sms', 'wipe', or null when nothing was
/// enrolled (dismissed, a validation failure, or removed by a relock).
Future<String?> showDuressEnrollmentDialog(
  BuildContext context, {
  String? knownRealPin,
  required bool canOfferSms,
  required DuressEnrollmentHooks hooks,
}) async {
  final currentCodeController = TextEditingController();
  final phoneController = TextEditingController();
  final emailController = TextEditingController();
  final codeController = TextEditingController();
  final confirmController = TextEditingController();
  String? inlineError;
  var busy = false;
  // The controllers belong to the dialog's widgets, which are still built
  // during the dialog's exit transition after showDialog has returned.
  // Disposing them when the future completes (as the body did in main.dart)
  // tripped "A TextEditingController was used after being disposed" on
  // every close; found by running the real body in
  // duress_enrollment_dialog_test. They are disposed when the dialog's
  // subtree is, or here if it was never built (a route removed before its
  // first frame).
  var controllersOwned = false;
  void disposeControllers() {
    currentCodeController.dispose();
    phoneController.dispose();
    emailController.dispose();
    codeController.dispose();
    confirmController.dispose();
  }
  try {
    // Returns null on a validation failure (inlineError already shown), or
    // the outcome to pop: 'sms' when a real SMS alert is armed, 'wipe' when
    // the code is a local-wipe-only action (iOS, or an Android user who
    // declined SMS). [withSms] is the button the user pressed.
    Future<String?> validateAndEnroll({
      required bool withSms,
      required void Function(void Function()) setDialogState,
    }) async {
      final realPin = (knownRealPin ?? currentCodeController.text).trim();
      final duressCode = codeController.text.trim();
      final confirm = confirmController.text.trim();
      final phone = phoneController.text.trim();
      final email = emailController.text.trim();
      // Re-authenticate when the real code was not passed in. Verified
      // against the stored credential with no side effects (never through
      // _verifyUserPin, which would itself arm duress and touch the ledger).
      if (knownRealPin == null) {
        final ok = await hooks.verifyRealPin(realPin);
        // The dialog was removed by a relock during the read: no dialog
        // state, and nothing below may commit.
        if (!hooks.stillAway()) return null;
        if (!ok) {
          setDialogState(
              () => inlineError = hooks.translate("That unlock code is not correct."));
          return null;
        }
      }
      final rejection = duressPinPolicyRejectionReason(realPin, duressCode);
      if (rejection != null) {
        setDialogState(() => inlineError = rejection);
        return null;
      }
      if (duressCode != confirm) {
        setDialogState(
            () => inlineError = hooks.translate("The two emergency codes do not match."));
        return null;
      }
      if (withSms &&
          (sanitizeTrustedContact(phone) == null ||
              !hooks.isPhoneShapedContact(phone))) {
        setDialogState(() =>
            inlineError = hooks.translate("Enter a valid phone number for your contact."));
        return null;
      }
      setDialogState(() => busy = true);
      // For the SMS path, get the grant BEFORE storing a phone, so a contact
      // is never stored that the app has no permission to actually reach. A
      // decline here is first-class: it becomes a wipe-only enrollment.
      var grantedSms = false;
      if (withSms) {
        grantedSms = await hooks.requestSmsPermission();
        // A relock during the permission prompt: never commit the code or
        // the contact behind the calculator.
        if (!hooks.stillAway()) return null;
      }
      final storePhone = withSms && grantedSms;
      try {
        final enrolled = await hooks.enroll(
          realPin: realPin,
          duressPin: duressCode,
          trustedPhone: storePhone ? phone : null,
          trustedEmail: storePhone && email.isNotEmpty ? email : null,
          stillAway: hooks.stillAway,
        );
        // A relock came inside the write: nothing was stored.
        if (!enrolled) return null;
      } catch (e) {
        hooks.debugLog('Duress enrollment failed: $e');
        if (!hooks.stillAway()) return null;
        setDialogState(() {
          busy = false;
          inlineError = hooks.translate(
              "The emergency code could not be stored on this device. Nothing was changed.");
        });
        return null;
      }
      return storePhone ? 'sms' : 'wipe';
    }

    final outcome = await showDialog<String>(
      context: context,
      barrierDismissible: true,
      builder: (dialogContext) {
        return _DisposeWhenGone(
          onFirstBuild: () => controllersOwned = true,
          onDispose: disposeControllers,
          child: StatefulBuilder(
          builder: (dialogContext, setDialogState) {
            InputDecoration decoration(String hint) => InputDecoration(
                  counterText: '',
                  hintText: hint,
                  isDense: true,
                );
            Widget codeField(TextEditingController c) => TextField(
                  controller: c,
                  obscureText: true,
                  textAlign: TextAlign.center,
                  autofillHints: null,
                  enableSuggestions: false,
                  autocorrect: false,
                  keyboardType: TextInputType.number,
                  maxLength: kCamouflagePinLength,
                  inputFormatters: [FilteringTextInputFormatter.digitsOnly],
                  decoration: decoration("$kCamouflagePinLength digits"),
                );
            Future<void> onPressed(bool withSms) async {
              final result = await validateAndEnroll(
                  withSms: withSms, setDialogState: setDialogState);
              if (result != null &&
                  dialogContext.mounted &&
                  hooks.stillAway()) {
                // This dialog's own route only (endOwnRoute): a newer dialog
                // over it, or this one already dismissed, is never answered
                // with the outcome.
                endOwnRoute<String>(dialogContext, result);
              }
            }

            return AlertDialog(
              backgroundColor: _duressPanel,
              title: Text(hooks.translate("Set up an emergency alert"),
                  style: const TextStyle(fontSize: 16)),
              content: SingleChildScrollView(
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      canOfferSms
                          ? hooks.translate(
                              "Choose a second code. If you ever enter it on "
                              "the lock screen instead of your normal code, "
                              "this app can quietly text your trusted contact "
                              "your approximate location, then clear itself, "
                              "showing only an ordinary error. Use it only if "
                              "you are forced to unlock this device.")
                          : hooks.translate(
                              "Choose a second code. If you ever enter it on "
                              "the lock screen instead of your normal code, "
                              "this app clears its data and shows an ordinary "
                              "error. On this device it CANNOT send any "
                              "message (that is not possible here), so no "
                              "contact will be notified."),
                      style:
                          const TextStyle(fontSize: 12, color: _duressText),
                    ),
                    const SizedBox(height: 14),
                    if (knownRealPin == null) ...[
                      Text(hooks.translate("Current unlock code"),
                          style: const TextStyle(
                              fontSize: 12, color: _duressText)),
                      codeField(currentCodeController),
                      const SizedBox(height: 10),
                    ],
                    if (canOfferSms) ...[
                      Text(hooks.translate("Trusted contact phone number"),
                          style: const TextStyle(
                              fontSize: 12, color: _duressText)),
                      TextField(
                        controller: phoneController,
                        keyboardType: TextInputType.phone,
                        autofillHints: null,
                        enableSuggestions: false,
                        autocorrect: false,
                        inputFormatters: [
                          FilteringTextInputFormatter.allow(
                              RegExp(r'[0-9+ ().-]')),
                        ],
                        decoration:
                            decoration(hooks.translate("Required for the text alert")),
                      ),
                      const SizedBox(height: 10),
                      Text(hooks.translate("Contact email (optional)"),
                          style: const TextStyle(
                              fontSize: 12, color: _duressText)),
                      TextField(
                        controller: emailController,
                        keyboardType: TextInputType.emailAddress,
                        autofillHints: null,
                        enableSuggestions: false,
                        autocorrect: false,
                        decoration: decoration(hooks.translate("Optional")),
                      ),
                      const SizedBox(height: 10),
                    ],
                    Text(hooks.translate("Emergency code"),
                        style: const TextStyle(
                            fontSize: 12, color: _duressText)),
                    codeField(codeController),
                    const SizedBox(height: 10),
                    Text(hooks.translate("Confirm emergency code"),
                        style: const TextStyle(
                            fontSize: 12, color: _duressText)),
                    codeField(confirmController),
                    if (canOfferSms) ...[
                      const SizedBox(height: 12),
                      Text(
                        hooks.translate("Sending a text needs SMS permission, which you "
                            "will be asked for. If you choose not to allow it, "
                            "the code still clears this device and shows the "
                            "error. It just will not send a message."),
                        style: const TextStyle(
                            fontSize: 11, color: _duressText),
                      ),
                    ],
                    if (inlineError != null) ...[
                      const SizedBox(height: 10),
                      Text(inlineError!,
                          style:
                              const TextStyle(fontSize: 12, color: _duressError)),
                    ],
                  ],
                ),
              ),
              actions: canOfferSms
                  ? [
                      TextButton(
                        onPressed: busy
                            ? null
                            : () => Navigator.of(dialogContext).pop(),
                        child: Text(hooks.translate("Not now")),
                      ),
                      TextButton(
                        onPressed: busy ? null : () => onPressed(false),
                        child: Text(hooks.translate("Wipe only")),
                      ),
                      TextButton(
                        onPressed: busy ? null : () => onPressed(true),
                        child: Text(hooks.translate("Allow text alert")),
                      ),
                    ]
                  : [
                      TextButton(
                        onPressed: busy
                            ? null
                            : () => Navigator.of(dialogContext).pop(),
                        child: Text(hooks.translate("Not now")),
                      ),
                      TextButton(
                        onPressed: busy ? null : () => onPressed(false),
                        child: Text(hooks.translate("Save")),
                      ),
                    ],
            );
          },
        ),
        );
      },
    );
    return outcome;
  } finally {
    if (!controllersOwned) disposeControllers();
  }
}

/// Runs [onDispose] when this subtree leaves the tree (after the dialog's
/// exit transition, or at once when a relock removes the route).
class _DisposeWhenGone extends StatefulWidget {
  const _DisposeWhenGone({
    required this.onFirstBuild,
    required this.onDispose,
    required this.child,
  });

  final VoidCallback onFirstBuild;
  final VoidCallback onDispose;
  final Widget child;

  @override
  State<_DisposeWhenGone> createState() => _DisposeWhenGoneState();
}

class _DisposeWhenGoneState extends State<_DisposeWhenGone> {
  @override
  void initState() {
    super.initState();
    widget.onFirstBuild();
  }

  @override
  void dispose() {
    widget.onDispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => widget.child;
}
