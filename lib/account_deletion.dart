/// Account-deletion consent policy (Apple Guideline 5.1.1(v) / Play Data
/// Safety in-app deletion).
///
/// The security requirement is that a single stolen or compromised device must
/// never be able to destroy an account on its own. Taken literally as "every
/// active device must confirm", that rule locks out any user whose device is
/// lost, broken, or wiped -- which Apple rejects as unreasonably burdensome.
///
/// The rule implemented here is a QUORUM instead:
///
///   required_confirmations = min(kAccountDeletionQuorum, activeDeviceCount)
///
/// With the product's three-device limit that means:
///   * 3 active devices -> 2 confirmations (NOT 3; losing one device is fine)
///   * 2 active devices -> 2 confirmations (naturally stricter, same rule)
///   * 1 active device  -> 1 confirmation PLUS a waiting period, because a
///     quorum of two distinct devices is arithmetically impossible and the
///     user must still have a reachable path to deletion
///   * 0 active devices -> not reachable; activate a device first
///
/// The quorum is derived from the account's real active-device count at
/// request time, never from an assumed device limit, so raising or lowering
/// the three-device product constraint does not silently change who can
/// delete an account.
library;

/// Number of DISTINCT active devices that must confirm before deletion runs.
///
/// Two, not three: two independent devices agreeing is already proof that the
/// request is not a lone thief, and requiring the full device limit would make
/// deletion impossible for anyone who lost a device.
const int kAccountDeletionQuorum = 2;

/// Waiting period applied when an account has exactly one active device.
///
/// Seven days is chosen deliberately:
///   * It preserves the anti-theft property. A thief holding the only device
///     cannot delete the account instantly; the real owner has a week to
///     activate a replacement (account number + setup key) and cancel.
///   * It is not burdensome under Apple's rule. The user takes no further
///     action after requesting -- deletion completes on its own -- and seven
///     days is far shorter than the 30-day grace period used by the major
///     platforms.
///   * It is short enough that a genuine privacy request is honoured promptly.
const Duration kAccountDeletionSingleDeviceDelay = Duration(days: 7);

/// Where a pending deletion currently stands, from this device's point of view.
enum AccountDeletionStage {
  /// No deletion has been requested.
  none,

  /// Requested; still waiting for enough distinct devices to confirm.
  awaitingConfirmations,

  /// Quorum satisfied via the single-device path; running out the waiting
  /// period. Any device that signs in can still cancel.
  awaitingDelay,

  /// Deletion has executed. The account and its data are gone.
  completed,

  /// A pending request was cancelled before it completed.
  cancelled,

  /// Deletion cannot be started right now (no active devices on the account).
  unavailable,
}

/// Returns how many distinct devices must confirm for [activeDeviceCount]
/// active devices.
///
/// Deliberately `min(quorum, count)` rather than a hard-coded 2 or 3: an
/// account with fewer devices than the quorum still has to reach unanimity of
/// what it actually has, and an account with more never has to reach unanimity
/// at all.
int requiredDeletionConfirmations(int activeDeviceCount) {
  if (activeDeviceCount <= 0) return 0;
  return activeDeviceCount < kAccountDeletionQuorum
      ? activeDeviceCount
      : kAccountDeletionQuorum;
}

/// Whether an account with [activeDeviceCount] devices must serve out the
/// waiting period instead of deleting as soon as the quorum is met.
///
/// True only for exactly one active device, where two distinct confirmations
/// are impossible.
bool deletionUsesWaitingPeriod(int activeDeviceCount) =>
    activeDeviceCount == 1;

/// Immutable view of a deletion request as this device understands it.
class AccountDeletionState {
  const AccountDeletionState({
    required this.stage,
    required this.activeDeviceCount,
    required this.confirmedDeviceCount,
    this.thisDeviceConfirmed = false,
    this.scheduledFor,
    this.requestId = '',
  });

  /// No request outstanding, for an account with [activeDeviceCount] devices.
  factory AccountDeletionState.idle(int activeDeviceCount) {
    return AccountDeletionState(
      stage: activeDeviceCount <= 0
          ? AccountDeletionStage.unavailable
          : AccountDeletionStage.none,
      activeDeviceCount: activeDeviceCount,
      confirmedDeviceCount: 0,
    );
  }

  final AccountDeletionStage stage;
  final int activeDeviceCount;
  final int confirmedDeviceCount;

  /// Whether the device currently running the app has already confirmed.
  final bool thisDeviceConfirmed;

  /// When the single-device waiting period elapses. Null on every other path.
  final DateTime? scheduledFor;

  /// Server-issued identifier for THIS request. A confirmation is only counted
  /// when it carries the current id, so a confirmation captured during an
  /// earlier (cancelled) request cannot be replayed against a new one.
  final String requestId;

  /// Confirmations still outstanding before deletion can proceed.
  int get remainingConfirmations {
    final remaining =
        requiredDeletionConfirmations(activeDeviceCount) - confirmedDeviceCount;
    return remaining < 0 ? 0 : remaining;
  }

  bool get isPending =>
      stage == AccountDeletionStage.awaitingConfirmations ||
      stage == AccountDeletionStage.awaitingDelay;

  /// Deletion may be started from this device.
  bool get canRequest =>
      activeDeviceCount > 0 &&
      (stage == AccountDeletionStage.none ||
          stage == AccountDeletionStage.cancelled);

  /// This device can add a confirmation that actually moves the request
  /// forward. A device that already confirmed cannot confirm twice -- that is
  /// what stops one compromised device from both starting and finishing a
  /// deletion.
  bool get canConfirmOnThisDevice =>
      stage == AccountDeletionStage.awaitingConfirmations &&
      !thisDeviceConfirmed &&
      remainingConfirmations > 0;

  /// Any active device may cancel while a request is pending, including the
  /// device that started it and a replacement device the real owner activates
  /// after a theft.
  bool get canCancel => isPending;

  /// Whether the waiting period applies to this account.
  bool get usesWaitingPeriod => deletionUsesWaitingPeriod(activeDeviceCount);

  AccountDeletionState copyWith({
    AccountDeletionStage? stage,
    int? activeDeviceCount,
    int? confirmedDeviceCount,
    bool? thisDeviceConfirmed,
    DateTime? scheduledFor,
    String? requestId,
  }) {
    return AccountDeletionState(
      stage: stage ?? this.stage,
      activeDeviceCount: activeDeviceCount ?? this.activeDeviceCount,
      confirmedDeviceCount: confirmedDeviceCount ?? this.confirmedDeviceCount,
      thisDeviceConfirmed: thisDeviceConfirmed ?? this.thisDeviceConfirmed,
      scheduledFor: scheduledFor ?? this.scheduledFor,
      requestId: requestId ?? this.requestId,
    );
  }

  /// Parses the hub's `/account/deletion/status` payload.
  ///
  /// Unknown or missing fields degrade to a safe "nothing pending" state
  /// rather than throwing, because this runs on a censorship-resistant
  /// transport where a gateway may return a truncated or substituted body.
  static AccountDeletionState fromStatusPayload(Map<String, dynamic> payload) {
    final active = _asInt(payload['active_device_count']);
    final confirmed = _asInt(payload['confirmed_device_count']);
    final rawStage = (payload['stage'] ?? '').toString().trim().toLowerCase();
    final scheduledRaw = (payload['execute_after'] ?? '').toString().trim();

    AccountDeletionStage stage;
    switch (rawStage) {
      case 'awaiting_confirmations':
        stage = AccountDeletionStage.awaitingConfirmations;
        break;
      case 'awaiting_delay':
        stage = AccountDeletionStage.awaitingDelay;
        break;
      case 'completed':
        stage = AccountDeletionStage.completed;
        break;
      case 'cancelled':
        stage = AccountDeletionStage.cancelled;
        break;
      case 'unavailable':
        stage = AccountDeletionStage.unavailable;
        break;
      default:
        stage = active <= 0
            ? AccountDeletionStage.unavailable
            : AccountDeletionStage.none;
    }

    return AccountDeletionState(
      stage: stage,
      activeDeviceCount: active,
      confirmedDeviceCount: confirmed,
      thisDeviceConfirmed: payload['this_device_confirmed'] == true,
      scheduledFor:
          scheduledRaw.isEmpty ? null : DateTime.tryParse(scheduledRaw),
      requestId: (payload['request_id'] ?? '').toString(),
    );
  }
}

int _asInt(Object? value) {
  if (value is int) return value;
  if (value is num) return value.toInt();
  return int.tryParse((value ?? '').toString().trim()) ?? 0;
}

String _days(Duration duration) {
  final days = duration.inDays;
  return days == 1 ? '1 day' : '$days days';
}

/// The consent rule, stated in plain language for the user.
///
/// Apple requires the policy itself to be visible in the app, not only the
/// button, so this string is rendered on the deletion screen verbatim.
String accountDeletionPolicyCopy(int activeDeviceCount) {
  final required = requiredDeletionConfirmations(activeDeviceCount);
  if (activeDeviceCount <= 0) {
    return 'This account has no active devices, so there is no device that can '
        'authorise deletion. Activate a device with your account number and '
        'setup key, then return here to delete the account.';
  }
  if (activeDeviceCount == 1) {
    return 'This account has 1 active device. Deleting normally needs '
        '$kAccountDeletionQuorum different devices to confirm, so that a lost '
        'or stolen device cannot destroy your account on its own. With only '
        'one device there is no second device to confirm, so deletion instead '
        'starts a ${_days(kAccountDeletionSingleDeviceDelay)} waiting period. '
        'Your account and data are erased automatically when it ends. Signing '
        'in on any device during that time lets you cancel.';
  }
  return 'This account has $activeDeviceCount active devices. Deletion must be '
      'confirmed from $required different devices, so a single lost or stolen '
      'device cannot destroy your account. You do not need every device: if '
      'one is lost or broken, the remaining $required can still complete the '
      'deletion. Any active device can cancel while the request is pending.';
}

/// The irreversibility / forfeiture warning shown before the final confirm.
String accountDeletionIrreversibleWarningCopy() {
  return 'Deleting your account is permanent and cannot be undone. Your '
      'account number, its setup key, every device record and its stored VPN '
      'keys, and your legal-acceptance records are erased. Any remaining paid '
      'time, lifetime access, or referral bonus is forfeited and is not '
      'refunded. Referral links you shared stop working. Payment and prepaid '
      'redemption records that we must keep for tax, accounting, and '
      'fraud-prevention reasons are retained -- see the Privacy Policy for the '
      'full list.';
}

/// Status line describing where the request currently stands.
String accountDeletionStatusCopy(AccountDeletionState state) {
  switch (state.stage) {
    case AccountDeletionStage.none:
      return 'No deletion is pending for this account.';
    case AccountDeletionStage.unavailable:
      return 'This account has no active devices, so deletion cannot be '
          'started from here. Activate a device first.';
    case AccountDeletionStage.awaitingConfirmations:
      final remaining = state.remainingConfirmations;
      final devices = remaining == 1 ? 'device' : 'devices';
      final here = state.thisDeviceConfirmed
          ? 'This device has confirmed. '
          : 'This device has not confirmed yet. ';
      return '${here}Deletion is pending: '
          '${state.confirmedDeviceCount} of '
          '${requiredDeletionConfirmations(state.activeDeviceCount)} '
          'confirmations received. Open Win\'s VPN on $remaining more $devices '
          'and confirm there. Any active device can cancel until then.';
    case AccountDeletionStage.awaitingDelay:
      final when = state.scheduledFor;
      final suffix = when == null
          ? ''
          : ' Scheduled for ${when.toUtc().toIso8601String().split('T').first} '
              '(UTC).';
      return 'Deletion is confirmed and waiting out the '
          '${_days(kAccountDeletionSingleDeviceDelay)} single-device waiting '
          'period.$suffix Signing in on any device and cancelling stops it.';
    case AccountDeletionStage.completed:
      return 'This account has been deleted.';
    case AccountDeletionStage.cancelled:
      return 'The pending deletion was cancelled. No data was erased.';
  }
}

/// Label for the primary button on the deletion screen.
String accountDeletionPrimaryActionLabel(AccountDeletionState state) {
  switch (state.stage) {
    case AccountDeletionStage.none:
    case AccountDeletionStage.cancelled:
      return 'Delete Account';
    case AccountDeletionStage.awaitingConfirmations:
      return state.canConfirmOnThisDevice
          ? 'Confirm Deletion On This Device'
          : 'Waiting For Another Device';
    case AccountDeletionStage.awaitingDelay:
      return 'Deletion Scheduled';
    case AccountDeletionStage.completed:
      return 'Account Deleted';
    case AccountDeletionStage.unavailable:
      return 'Deletion Unavailable';
  }
}
