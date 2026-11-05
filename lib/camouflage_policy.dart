enum DeviceFormFactor { phone, tv }

bool supportsInAppCalculatorCamouflage(
  String operatingSystem,
  DeviceFormFactor formFactor,
) {
  if (formFactor == DeviceFormFactor.tv) return false;
  final platform = operatingSystem.trim().toLowerCase();
  return platform == 'android' || platform == 'ios';
}

/// Whether the very first Flutter frame must use the neutral calculator
/// surface while local activation state is being read.
///
/// A fresh install is switched to the normal activation UI as soon as that
/// local read proves there is no enrolled account. An activated install stays
/// on the calculator. Starting neutral avoids one branded frame before the
/// asynchronous state restore has had a chance to decide which case applies.
bool calculatorCoversFirstFrame(
  String operatingSystem,
  DeviceFormFactor formFactor,
) =>
    supportsInAppCalculatorCamouflage(operatingSystem, formFactor);

// =====================================================================
// DURESS PLATFORM POLICY - and the desktop answer is DEFERRED, not refused.
//
// Why this function exists at all. Until it did, "does duress work on
// macOS/Windows/Linux?" had no answer anywhere - not a comment, not a test,
// not a constant. It resolved through a chain nobody wrote down: the duress
// credential can only be typed at the decoy keypad, the decoy keypad renders
// only when in-app camouflage is supported, and in-app camouflage is
// Android/iOS. So desktop duress is absent as an EMERGENT CONSEQUENCE OF A
// CAMOUFLAGE PREDICATE, not as a decision anyone made. A reader of the
// feature list assumes it works. That is the same defect class this file was
// created to remove (see the block below): a safety property expressed only
// as inline conditions, which nothing can call and no test can fail.
//
// DEFERRED, and specifically NOT refused, for four reasons.
//
//  1. The mechanism we have answers a threat the desktop mostly does not
//     face. Duress here is a credential typed under observation: the device
//     is taken WHILE YOU ARE PRESENT and you are compelled to unlock it. A
//     phone is seized that way - at a checkpoint, in a search, in your hand.
//     A laptop is more often seized at a premises search, frequently while
//     its owner is elsewhere, and a duress code you are never at the keyboard
//     to type protects nobody.
//  2. Against the desktop's actual threat, an app-level wipe is not merely
//     weak, it is LATE. The competent response to a seized laptop is to image
//     the disk before the machine is ever booted normally. A wipe that runs
//     after the image exists deletes nothing an examiner does not already
//     hold - and it deletes it DETECTABLY, producing a difference between the
//     image and the live disk that is affirmative evidence of a hidden
//     capability and of deliberate destruction. On this threat model that
//     converts "owns a VPN" into "was operating a covert tool", which is a
//     worse outcome than the one the wipe was meant to prevent. Shipping the
//     phone mechanism unchanged onto desktop would be a net harm, not a gap
//     being closed.
//  3. The protection that DOES fit desktop is full-disk encryption at rest,
//     which every desktop OS already provides and this app does not own. That
//     is a different mechanism, not a smaller version of this one, and the
//     honest advice is to point at it rather than to imitate it badly.
//  4. But refusal would over-claim, which is why this is deferred. Duress has
//     two halves and only the wipe is answered above. The other half - the
//     outbound alert to a trusted contact - is not defeated by imaging at
//     all, and its value to a desktop user is genuinely open. What blocks it
//     is not a decision; it is that there is no desktop surface on which a
//     duress credential can be entered, because the only entry point is
//     wired behind camouflage. So the refusal is narrow (do not port the
//     wipe) and the deferral is real (the entry point and the alert are
//     unanswered).
//
// WHAT WOULD FLIP THIS. A desktop credential-entry surface that does not
// depend on camouflage, plus a decision on whether an alert without a wipe is
// worth shipping alone. If either lands, this function changes on one line
// and the test below turns red until someone updates it deliberately.
//
// This function is INDEPENDENT of supportsInAppCalculatorCamouflage on
// purpose, even though the two agree today. Delegating would re-encode the
// exact accident being named here, and would mean that a lane adding desktop
// camouflage silently ships desktop duress as a side effect - the same
// failure, one layer up. The test pins both the values and the coincidence.
// =====================================================================

/// Whether a duress credential can be enrolled, entered and armed on this
/// platform.
///
/// Owner decision 2026-08-15: Win For All does not ship duress. The historical
/// platform analysis above is retained as provenance, but is superseded by
/// this product-wide false result.
///
/// `true` does not mean the same thing on both platforms it returns `true`
/// for, and the difference is a settled owner decision rather than a gap:
///
///   * Android - full duress. The credential arms the wipe AND a covert
///     device-native SMS alert from the handset's own radio.
///   * iOS - LOCAL WIPE ONLY. No alert can leave the device, because iOS
///     cannot send an SMS without showing the compose UI and taking a manual
///     tap, and there is deliberately no relay or hub fallback. See
///     `_supportsDeviceNativeSms` in main.dart, which still carries that
///     decision in a comment rather than in a function and is owed this same
///     treatment.
///
/// So this predicate answers "can a duress code be typed and armed here",
/// which is the question the desktop absence turns on. It is not a claim that
/// the two platforms do the same thing afterwards.
bool supportsDuress(
  String operatingSystem,
  DeviceFormFactor formFactor,
) {
  return false;
}

/// Win For All does not ship an offline recovery credential. The ordinary
/// camouflage PIN is the only credential accepted by the calculator surface.
const bool kRecoveryUnlockEnabled = false;

// =====================================================================
// Camouflage latch, decoy arming, credential-entry outcome, and the duress
// wipe's keep-list.
//
// These four things used to be expressed only as inline conditions inside
// main.dart's private State class, which is why the 2026-08-06 device test
// found defects that a green 30-test suite had never noticed: nothing a test
// could call decided any of them. They are pure functions here so the
// behaviour itself - not the source text that spells it - is what the suite
// asserts, and so a regression fails the suite instead of a person.
// =====================================================================

/// Name of the durable record that latches "this install runs behind the decoy
/// calculator".
///
/// Two hard requirements, and they pull in opposite directions:
///
///   1. It MUST survive the duress wipe. The decoy used to be armed from
///      "a PIN credential exists", and the duress wipe deletes exactly that
///      credential - so the one feature built to make a seized phone look
///      innocent was what stripped the disguise off it, re-exposing the
///      branded consent dialog and the real activation screen on the next
///      cold start. The wipe therefore keeps this file on purpose
///      ([duressWipeKeepsEntry]).
///
///   2. It MUST NOT be a tell in its own right. A lone surviving file called
///      `decoy_mode` or `camouflage_state` is worse than no file at all: it
///      proves to anyone holding the phone that the calculator is a front.
///      So the survivor is shaped, named and filled as what a calculator app
///      legitimately keeps - its own display preferences - and it is its
///      PRESENCE, not any field inside it, that latches the disguise. Nothing
///      in it names this app, a VPN, a decoy, or a duress code.
const String kCamouflageLatchFileName = 'calc_prefs.json';

/// The contents written to [kCamouflageLatchFileName]. Ordinary calculator
/// display settings and nothing else: an inspector who opens the file finds a
/// calculator's preferences, which is exactly what an innocent phone has.
const Map<String, Object> kCamouflageLatchContents = <String, Object>{
  'display_mode': 'basic',
  'group_digits': true,
  'decimals': 6,
  'memory': '0',
};

/// Tokens that must never appear in the latch file's name. Asserted by the
/// suite: the survivor's job is to be unremarkable, and a name that describes
/// the disguise defeats the whole mechanism.
const List<String> kCamouflageLatchForbiddenTokens = <String>[
  'decoy',
  'duress',
  'camouflage',
  'panic',
  'vpn',
  'wins',
  'secret',
  'hidden',
  'disguise',
];

/// Whether the decoy calculator should be presented on this launch.
///
/// [camouflageLatched] is the post-wipe survivor described on
/// [kCamouflageLatchFileName]. It is ORed with the activation facts rather
/// than ANDed with them precisely so that a wipe which destroys every
/// credential still leaves the disguise standing: after duress the app is a
/// calculator with nothing behind it, which is both the safest thing to hand
/// back and the most convincing.
bool decoyCalculatorShouldArm({
  required bool supportsInAppCamouflage,
  required bool appIsActivated,
  required bool freeAccessSession,
  required bool camouflageLatched,
  required bool openedByDialer,
  required bool unlockedThisSession,
}) {
  if (!supportsInAppCamouflage) return false;
  // Both of these are a deliberate, in-session request for the real app.
  if (openedByDialer || unlockedThisSession) return false;
  return appIsActivated || freeAccessSession || camouflageLatched;
}

/// Everything a person holding the phone - or an examiner instrumenting it -
/// can observe about one credential-shaped entry at the decoy keypad.
///
/// [CredentialEntryOutcome.armsDuress] is deliberately NOT part of this: the
/// entire security property is that arming leaves no observable trace, so the
/// suite asserts that the duress entry and a mistyped entry produce equal
/// signatures while differing only in that hidden field.
class ObservableEntrySignature {
  const ObservableEntrySignature({
    required this.unlocks,
    required this.recoveryUnlock,
    required this.showsFailureDialog,
    required this.clearsAttemptLedger,
    required this.recordsAttemptFailure,
  });

  final bool unlocks;
  final bool recoveryUnlock;

  /// Whether the generic "Something went wrong" dialog is raised.
  final bool showsFailureDialog;

  /// Whether the attempt ledger is written. Both of these are observable to
  /// an examiner in two ways: the persisted-state delta, and the ~60 ms of
  /// wall clock the write costs. A branch that skips the write is a timing
  /// side-channel that identifies which code was entered.
  final bool clearsAttemptLedger;
  final bool recordsAttemptFailure;

  bool get writesAttemptLedger => clearsAttemptLedger || recordsAttemptFailure;

  @override
  bool operator ==(Object other) =>
      other is ObservableEntrySignature &&
      other.unlocks == unlocks &&
      other.recoveryUnlock == recoveryUnlock &&
      other.showsFailureDialog == showsFailureDialog &&
      other.clearsAttemptLedger == clearsAttemptLedger &&
      other.recordsAttemptFailure == recordsAttemptFailure;

  @override
  int get hashCode => Object.hash(unlocks, recoveryUnlock, showsFailureDialog,
      clearsAttemptLedger, recordsAttemptFailure);

  @override
  String toString() => 'ObservableEntrySignature(unlocks:$unlocks, '
      'recoveryUnlock:$recoveryUnlock, dialog:$showsFailureDialog, '
      'clearLedger:$clearsAttemptLedger, failLedger:$recordsAttemptFailure)';
}

/// What one credential-shaped entry at the decoy keypad does.
class CredentialEntryOutcome {
  const CredentialEntryOutcome({
    required this.unlocks,
    required this.recoveryUnlock,
    required this.armsDuress,
    required this.clearsAttemptLedger,
    required this.recordsAttemptFailure,
  });

  final bool unlocks;
  final bool recoveryUnlock;

  /// The only part of the outcome that is meant to be invisible.
  final bool armsDuress;

  final bool clearsAttemptLedger;
  final bool recordsAttemptFailure;

  /// The generic failure dialog is raised for EVERY entry that did not unlock
  /// the app, whatever the reason. That is what makes the duress entry's
  /// Whether the decoy raises the failure dialog.
  /// For camouflage purposes, an innocent calculator must never show an error dialog
  /// when wrong numbers are entered; it simply acts like a regular calculator.
  bool get showsFailureDialog => false;

  /// Whether this entry touches the attempt ledger at all. Both the persisted
  /// delta and the ~60 ms the write costs are observable to an examiner, so a
  /// branch that skips it is a fingerprint for the code that was entered.
  bool get writesAttemptLedger => clearsAttemptLedger || recordsAttemptFailure;

  ObservableEntrySignature get observable => ObservableEntrySignature(
        unlocks: unlocks,
        recoveryUnlock: recoveryUnlock,
        showsFailureDialog: showsFailureDialog,
        clearsAttemptLedger: clearsAttemptLedger,
        recordsAttemptFailure: recordsAttemptFailure,
      );
}

/// Decides what one entry at the decoy keypad does, from the facts the
/// verifier has already established.
///
/// The duress branch is deliberately shaped so its [ObservableEntrySignature]
/// is byte-for-byte a mistyped code's:
///
///   * it never unlocks, exactly like a wrong code;
///   * it raises the same dialog a wrong code now raises;
///   * it pays for the SAME attempt-ledger write, so the two paths are drawn
///     from one timing distribution instead of two separated by the ~60 ms
///     the ledger write costs.
///
/// It still sits ABOVE the lockout gate in the sense that matters: arming is
/// reported whether or not the entry is throttled, because five failures is
/// exactly what happens when someone is handed a "calculator" and told to
/// prove it works, and a panic code that stops working then is worse than
/// none. Under lockout NEITHER path writes the ledger, so they stay identical
/// there too.
CredentialEntryOutcome classifyCredentialEntry({
  required bool credentialEnrolled,
  required bool pinMatches,
  required bool recoveryMatches,
  required bool duressMatches,
  required bool lockedOut,
}) {
  // Nothing is enrolled - the state a duress wipe leaves behind. Nothing to
  // verify, nothing to record; the entry simply fails, and the same dialog
  // says so, which reads as the app being broken rather than as a disguise.
  if (!credentialEnrolled) {
    return const CredentialEntryOutcome(
      unlocks: false,
      recoveryUnlock: false,
      armsDuress: false,
      clearsAttemptLedger: false,
      recordsAttemptFailure: false,
    );
  }
  if (lockedOut) {
    return CredentialEntryOutcome(
      unlocks: false,
      recoveryUnlock: false,
      armsDuress: duressMatches,
      clearsAttemptLedger: false,
      recordsAttemptFailure: false,
    );
  }
  if (duressMatches) {
    return const CredentialEntryOutcome(
      unlocks: false,
      recoveryUnlock: false,
      armsDuress: true,
      clearsAttemptLedger: false,
      recordsAttemptFailure: true,
    );
  }
  if (recoveryMatches) {
    return const CredentialEntryOutcome(
      unlocks: true,
      recoveryUnlock: true,
      armsDuress: false,
      clearsAttemptLedger: true,
      recordsAttemptFailure: false,
    );
  }
  return CredentialEntryOutcome(
    unlocks: pinMatches,
    recoveryUnlock: false,
    armsDuress: false,
    clearsAttemptLedger: pinMatches,
    recordsAttemptFailure: !pinMatches,
  );
}

/// Whether one entry inside the app's own storage is allowed to survive the
/// duress wipe. [path] is relative to the storage root being swept, with '/'
/// separators.
///
/// Exactly two things may survive, and both are survivors on purpose:
///
///   * [kCamouflageLatchFileName], so the disguise outlives the wipe;
///   * the encrypted secure-state directory, and ONLY while an undelivered
///     alert is still queued in it - a thorough wipe there would destroy the
///     only copy of the alert.
///
/// Everything else goes, including `node_cache.json`, which is plaintext JSON
/// listing node endpoints and the covert stealth domain and which used to
/// survive the offline wipe untouched, handing an inspector the very
/// infrastructure the wipe exists to hide.
bool duressWipeKeepsEntry(
  String path, {
  required bool preserveEmergencyQueue,
}) {
  final normalized = path.replaceAll('\\', '/').trim();
  if (normalized.isEmpty || normalized == '.' || normalized == '/') return true;
  final segments =
      normalized.split('/').where((segment) => segment.isNotEmpty).toList();
  if (segments.isEmpty) return true;
  if (segments.length == 1 && segments.first == kCamouflageLatchFileName) {
    return true;
  }
  if (preserveEmergencyQueue && segments.first == kSecureStateDirectoryName) {
    return true;
  }
  return false;
}

/// Directory the native secure-state store keeps its AES-GCM records in. The
/// offline duress branch must keep this one subtree so the queued alert can
/// still be retried.
const String kSecureStateDirectoryName = 'secure_state';

bool supportsLauncherIconCamouflage(
  String operatingSystem,
  DeviceFormFactor formFactor,
) {
  if (formFactor == DeviceFormFactor.tv) return false;
  final platform = operatingSystem.trim().toLowerCase();
  return platform == 'android' || platform == 'ios';
}

/// Length of a camouflage PIN enrolled by this build. Raised from 4 to 6 so
/// the guessing space is 10^6 rather than 10^4. Throttling
/// (`PinAttemptState`) remains the primary defence; this only deepens it.
const int kCamouflagePinLength = 6;

/// Length of a camouflage PIN enrolled by builds before the 6-digit change.
/// Credentials of this length are still accepted at the decoy keypad -
/// refusing them would lock out every existing install, which is the exact
/// defect this lane exists to remove. See `PinCredentialCodec.storedPinLength`.
const int kLegacyCamouflagePinLength = 4;

/// Length of the offline recovery code. See the reasoning in the handoff:
/// the binding constraint is not keypad guessing (throttling makes that
/// hopeless at any of these lengths) but an OFFLINE attack by someone who
/// extracts the stored credential and runs PBKDF2 on their own hardware,
/// where no throttle applies. 16 digits is ~53 bits; 12 would fall to a
/// well-resourced offline attacker in days.
const int kRecoveryCodeLength = 16;

/// Upper bound on buffered keystrokes. Purely a memory guard: a decoy
/// calculator that a user actually does arithmetic on can accumulate digits
/// indefinitely otherwise.
const int _maxBufferedEntryLength = 64;

/// Digit accumulator behind the decoy calculator keypad.
///
/// Two independent buffers, deliberately:
///
///   * [_pinWindow] fires a PIN candidate the moment exactly [pinLength]
///     digits have been typed and then clears, which is what makes a
///     mistyped PIN retryable without pressing any key first. This is the
///     original 4-digit behaviour, parameterised by length.
///   * [_entryBuffer] accumulates every digit since the last clear and is
///     only ever handed over by [submit], which the decoy wires to the
///     calculator's own `=` key. That is how a credential longer than a PIN
///     is entered without adding any visible affordance - `=` is already on
///     a real calculator, so nothing about the observable behaviour changes.
///
/// [submit] returns a candidate only when the buffer is exactly
/// [recoveryLength] digits long. That bound matters: without it every `=`
/// pressed during genuine arithmetic would spend a throttle failure against
/// [PinAttemptState] and could lock a user out of their own PIN for using
/// the decoy as the calculator it pretends to be.
///
/// A second distinct credential (e.g. a duress PIN) slots in here by adding
/// one more expected length and returning a candidate for it - no change to
/// how entry terminates.
class CalculatorPinEntry {
  CalculatorPinEntry({
    int pinLength = kCamouflagePinLength,
    int recoveryLength = 0,
  })  : _pinLength = _sanitizedPinLength(pinLength),
        _recoveryLength = recoveryLength < 0 ? 0 : recoveryLength;

  String _pinWindow = '';
  String _entryBuffer = '';
  int _pinLength;
  int _recoveryLength;

  static int _sanitizedPinLength(int value) {
    return value == kLegacyCamouflagePinLength
        ? kLegacyCamouflagePinLength
        : kCamouflagePinLength;
  }

  /// Number of digits that forms a PIN candidate. Set from the length
  /// recorded in the stored credential so exactly one candidate is produced
  /// per attempt; evaluating both lengths on every keystroke would spend two
  /// throttle failures for one wrong entry.
  int get pinLength => _pinLength;

  set pinLength(int value) {
    final sanitized = _sanitizedPinLength(value);
    if (sanitized == _pinLength) return;
    _pinLength = sanitized;
    _pinWindow = '';
    _pinCandidateOffered = false;
  }

  /// Length of the stored recovery credential, or 0 when none is enrolled.
  /// Zero disables [submit] entirely, so a build with no recovery credential
  /// performs no verification work on `=` at all.
  int get recoveryLength => _recoveryLength;

  set recoveryLength(int value) {
    _recoveryLength = value < 0 ? 0 : value;
  }

  /// True once this entry session has already produced its PIN candidate.
  ///
  /// Exactly one PIN candidate is offered per session, and it is always the
  /// first [pinLength] digits typed since the last clear. Without this, a
  /// longer credential would be chopped into PIN-length windows on its way
  /// in - a 16-digit recovery code would fire a PIN candidate at digit 6 and
  /// again at digit 12, spending two extra throttle failures on every
  /// recovery attempt. The cost is that retrying a PIN needs AC or backspace
  /// first, which is what those keys are for and is ordinary calculator
  /// behaviour; the display shows the typed digits either way.
  bool _pinCandidateOffered = false;

  String addDigit(String digit) {
    if (!RegExp(r'^\d$').hasMatch(digit)) return '';
    if (_entryBuffer.length < _maxBufferedEntryLength) {
      _entryBuffer += digit;
    }
    if (_pinCandidateOffered) return '';
    _pinWindow += digit;
    if (_pinWindow.length < _pinLength) return '';
    final candidate = _pinWindow;
    _pinWindow = '';
    _pinCandidateOffered = true;
    return candidate;
  }

  /// Removes the most recently entered digit from both the PIN candidate window
  /// and the full entry buffer, resetting the candidate-offered latch so
  /// corrected typing can produce a PIN candidate.
  void backspace() {
    if (_pinWindow.isNotEmpty) {
      _pinWindow = _pinWindow.substring(0, _pinWindow.length - 1);
    }
    if (_entryBuffer.isNotEmpty) {
      _entryBuffer = _entryBuffer.substring(0, _entryBuffer.length - 1);
    }
    _pinCandidateOffered = false;
  }

  /// Hands over the accumulated entry when it is exactly [recoveryLength]
  /// digits long, or if an explicit [fallbackValue] matches [pinLength],
  /// then clears. Wired to the calculator's `=` key.
  String submit({String? fallbackValue}) {
    final buffered = _entryBuffer;
    final fallback = (fallbackValue ?? '').replaceAll(RegExp(r'[^\d]'), '');
    reset();
    if (_recoveryLength > 0 && buffered.length == _recoveryLength) {
      return buffered;
    }
    if (_recoveryLength > 0 && fallback.length == _recoveryLength) {
      return fallback;
    }
    if (fallback.length == _pinLength) {
      return fallback;
    }
    return '';
  }

  void reset() {
    _pinWindow = '';
    _entryBuffer = '';
    _pinCandidateOffered = false;
  }
}

/// Compares two PIN strings in constant time to prevent side-channel timing attacks.
/// Evaluates length and all character code units without early exit.
bool constantTimePinEquals(String a, String b) {
  final ca = a.codeUnits;
  final cb = b.codeUnits;
  var difference = ca.length ^ cb.length;
  final max = ca.length > cb.length ? ca.length : cb.length;
  for (var i = 0; i < max; i++) {
    final av = i < ca.length ? ca[i] : 0;
    final bv = i < cb.length ? cb[i] : 0;
    difference |= av ^ bv;
  }
  return difference == 0;
}

// =====================================================================
// CAMOUFLAGE SURFACE ENFORCEMENT - the OS badge is not ours to remove, so
// the app's own surface must never do the identifying.
//
// The in-app disguise above (decoy calculator, launcher icon, latch file)
// hides the app only where the app controls the surface. It cannot hide the
// status-bar VPN badge: on Android and iOS the OS draws that icon the moment
// any VpnService / NetworkExtension tunnel is up, and it keeps drawing it
// whether or not the app behind it is wearing its disguise. So while the
// tunnel runs the OS openly announces "some VPN is on" - that half is out of
// our control. What IS in our control, and what this block enforces, is the
// OTHER half: that nothing in the app's own observable surface tells an
// examiner WHICH app it is. A hostile observer who can already see the badge
// must still be unable to narrow it to this product.
//
// The surfaces that would leak the identity are the same class as
// [kCamouflageLatchForbiddenTokens] - file names, diagnostic strings, log
// lines, persisted tokens that mention this product's own vocabulary (winn,
// wins, vpn, camouflage, decoy, duress, stealth, tunnel). The start path is
// where the tunnel first becomes externally visible, so that is where the
// enforcement belongs: a tunnel may run under the badge while the surface
// it emits carries no VPN-app identity.
//
// This is pure and unit-testable on purpose, for the same reason the rest of
// this file is: a disguise property expressed only inline in main.dart is a
// property nothing can call and no test can fail. Splitting the "does a
// surface leak identity" check out lets a test assert BOTH signs of the
// property - a hostile packet must show no identity, and a surface that
// still names the app must be flagged / stripped.
// =====================================================================

/// Whether the operating system draws a status-bar VPN badge while the app's
/// tunnel is up. This is the half of the camouflage surface the app does not
/// control, and it is exactly when the app's own surface must compensate.
///
/// Android and iOS always draw the badge while a VpnService / NE tunnel runs,
/// on both phones and tablets. TV never gets the decoy, and the desktop OSes
/// present no badge (macOS has no status-bar VPN icon to speak of) - so this
/// lines up with, but is deliberately NOT derived from,
/// [supportsInAppCalculatorCamouflage], for the same reason that functions is
/// independent of `supportsDuress`: the badge is an OS property, not an app
/// capability, and folding them together would re-encode the accident this
/// block exists to name.
bool osDrawsVpnBadge(
  String operatingSystem,
  DeviceFormFactor formFactor,
) {
  if (formFactor == DeviceFormFactor.tv) return false;
  final platform = operatingSystem.trim().toLowerCase();
  return platform == 'android' || platform == 'ios';
}

/// Exact tokens that would identify this app as a VPN if they appeared in a
/// hostile-observable surface. Deliberately the product's own vocabulary and
/// the camouflage mechanism's own vocabulary, plus the generic VPN words
/// every operator would grep for. Kept bare (lowercase) and matched
/// case-insensitively so a surface cannot dodge the check by capitalising.
const List<String> kCamouflageSurfaceForbiddenTokens = <String>[
  'winn',
  'wins',
  'vpn',
  'camouflage',
  'decoy',
  'duress',
  'stealth',
  'tunnel',
  'proxy',
];

/// Whether any of [kCamouflageSurfaceForbiddenTokens] appears in [surface].
///
/// [surface] is whatever a hostile examiner could observe and grep: a packet
/// metadata line, a persisted file name, a diagnostic string, a log line. The
/// check is case-insensitive so `WINS`/`Vpn` are caught as readily as their
/// lowercase forms.
bool camouflageSurfaceCarriesVpnIdentity(String surface) {
  final lower = surface.toLowerCase();
  return kCamouflageSurfaceForbiddenTokens.any(lower.contains);
}

/// Everything in [surface] after every forbidden identity token has been
/// removed, so a surface that would have named the app no longer can.
///
/// This is the enforcement the start path applies: whatever the tunnel emits
/// while the OS badge is up is run through this so an examiner who sees the
/// badge still cannot read the app off its surface. Removing rather than
/// masking keeps the output byte-grepable proof that no token survived.
String camouflageSurfaceWithoutVpnIdentity(String surface) {
  var result = surface;
  for (final token in kCamouflageSurfaceForbiddenTokens) {
    result = result.replaceAll(RegExp(token, caseSensitive: false), '');
  }
  return result;
}

/// Whether the app must keep its own observable surface free of any VPN-app
/// identity while a tunnel runs: i.e. the OS draws a badge on this platform
/// (so the identity question is live) and the disguise is in-band camouflage
/// rather than a form-factor where the decoy cannot exist anyway.
///
/// The two clauses are ANDed for a reason. If the OS draws no badge, the
/// examiner cannot tell from the badge that any VPN is on, so there is no
/// heightened identity surface to defend. If the form factor is TV, the decoy
/// cannot arm at all, so the covert-surface contract does not apply. Only
/// where both hold - a phone/tablet that shows the badge AND runs the decoy -
/// does the start path enforce anonymity. This is consulted by the tunnel
/// start path so the decision is a policy, not a greppable habit.
bool camouflageSurfaceMustStayAnonymous(
  String operatingSystem,
  DeviceFormFactor formFactor,
) {
  return osDrawsVpnBadge(operatingSystem, formFactor) &&
      supportsInAppCalculatorCamouflage(operatingSystem, formFactor);
}

/// The decoy keypad's fallback PIN candidate: the digits of the operand
/// currently being typed (after the last operator), and only when there are
/// exactly [pinLength] of them. `12+3456` is arithmetic, not a six-digit code.
String decoyPinCandidateFromDisplay(String display, int pinLength) {
  final operand = display.split(RegExp(r'[+\-×÷*/]')).last;
  final digits = operand.replaceAll(RegExp(r'[^\d]'), '');
  return digits.length == pinLength ? digits : '';
}
