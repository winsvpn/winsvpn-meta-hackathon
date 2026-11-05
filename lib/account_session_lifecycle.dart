import 'dart:async';

class AccountSessionEpoch {
  int _value = 0;

  int get current => _value;

  int bump() => ++_value;

  bool isCurrent(int captured) => captured == _value;
}

class ClientKeyOperationQueue {
  final Map<String, Future<void>> _queues = <String, Future<void>>{};

  int get pendingOperationCount => _queues.length;

  Future<T> run<T>(
    String operationKey,
    Future<T> Function() operation,
  ) {
    final inheritedOwners = _activeOwners();
    if (inheritedOwners.any(
      (owner) => owner.active && owner.operationKey == operationKey,
    )) {
      return Future<T>.error(StateError(
        'Client key operation attempted to queue behind itself',
      ));
    }

    final previous = _queues[operationKey] ?? Future<void>.value();
    final result = Completer<T>();
    late final Future<void> tail;
    tail = previous.catchError((Object _) {}).then((_) async {
      final currentOwner = _ClientKeyOperationOwner(operationKey);
      try {
        result.complete(await runZoned<Future<T>>(
          operation,
          zoneValues: <Object?, Object?>{
            this: Set<_ClientKeyOperationOwner>.unmodifiable(
              <_ClientKeyOperationOwner>[...inheritedOwners, currentOwner],
            ),
          },
        ));
      } catch (error, stackTrace) {
        result.completeError(error, stackTrace);
      } finally {
        currentOwner.active = false;
      }
    });
    _queues[operationKey] = tail;
    unawaited(tail.whenComplete(() {
      if (identical(_queues[operationKey], tail)) {
        _queues.remove(operationKey);
      }
    }));
    return result.future;
  }

  Set<_ClientKeyOperationOwner> _activeOwners() {
    final owners = Zone.current[this];
    return owners is Set<_ClientKeyOperationOwner>
        ? owners
        : const <_ClientKeyOperationOwner>{};
  }
}

// Identity equality is required: a scope can retain an inactive owner and add
// a new active owner for the same key. Do not override == or hashCode.
class _ClientKeyOperationOwner {
  _ClientKeyOperationOwner(this.operationKey);

  final String operationKey;
  bool active = true;
}

enum AccountCleanupResumeOutcome { none, completed, pending }

class AccountCleanupStartupBarrier {
  AccountCleanupStartupBarrier({
    required this.journalExists,
    required this.attemptCleanup,
    required this.onPending,
    required this.onCompleted,
    required this.onRetryCompleted,
    this.retryDelay = const Duration(seconds: 5),
  });

  final Future<bool> Function() journalExists;
  final Future<void> Function() attemptCleanup;
  final void Function() onPending;
  final void Function() onCompleted;
  final void Function() onRetryCompleted;
  final Duration retryDelay;

  Timer? _retryTimer;
  Future<AccountCleanupResumeOutcome>? _resumeInFlight;
  bool _pendingObserved = false;
  bool _disposed = false;

  Future<AccountCleanupResumeOutcome> resume() {
    final running = _resumeInFlight;
    if (running != null) return running;

    late final Future<AccountCleanupResumeOutcome> resumeFuture;
    resumeFuture = _resumeOnce().whenComplete(() {
      if (identical(_resumeInFlight, resumeFuture)) {
        _resumeInFlight = null;
      }
    });
    _resumeInFlight = resumeFuture;
    return resumeFuture;
  }

  Future<bool> activationAllowed() async {
    try {
      if (!await journalExists()) return true;
    } catch (_) {
      // An unreadable journal store is ambiguous. Keep activation fail-closed.
    }
    _pendingObserved = true;
    onPending();
    _scheduleRetry();
    return false;
  }

  Future<AccountCleanupResumeOutcome> _resumeOnce() async {
    try {
      if (!await journalExists()) {
        if (_pendingObserved) {
          _pendingObserved = false;
          onCompleted();
          return AccountCleanupResumeOutcome.completed;
        }
        return AccountCleanupResumeOutcome.none;
      }
      await attemptCleanup();
      if (!await journalExists()) {
        _pendingObserved = false;
        onCompleted();
        return AccountCleanupResumeOutcome.completed;
      }
    } catch (_) {
      // Stop-proof, artifact, parse, and storage failures all retain the same
      // fail-closed pending state. A later retry must observe durable absence.
    }
    _pendingObserved = true;
    onPending();
    _scheduleRetry();
    return AccountCleanupResumeOutcome.pending;
  }

  void _scheduleRetry() {
    if (_disposed || _retryTimer?.isActive == true) return;
    _retryTimer = Timer(retryDelay, () {
      _retryTimer = null;
      unawaited(resume().then((outcome) {
        if (outcome == AccountCleanupResumeOutcome.completed) {
          onRetryCompleted();
        }
      }));
    });
  }

  void dispose() {
    _disposed = true;
    _retryTimer?.cancel();
    _retryTimer = null;
  }
}

enum AccountCleanupIntent { deactivate, accountDelete, activationRollback }

class AccountCleanupJournal {
  const AccountCleanupJournal({
    required this.intent,
    required this.scopeToken,
    required this.phase,
    required this.pendingArtifacts,
  });

  final AccountCleanupIntent intent;
  final String scopeToken;
  final String phase;
  final Set<String> pendingArtifacts;

  Map<String, dynamic> toJson() => <String, dynamic>{
        'v': 1,
        'intent': intent.name,
        'scope': scopeToken,
        'phase': phase,
        'pending': pendingArtifacts.toList()..sort(),
      };

  factory AccountCleanupJournal.fromJson(Map<String, dynamic> json) {
    final intentName = (json['intent'] ?? '').toString();
    AccountCleanupIntent? intent;
    for (final candidate in AccountCleanupIntent.values) {
      if (candidate.name == intentName) {
        intent = candidate;
        break;
      }
    }
    final scope = (json['scope'] ?? '').toString().trim();
    final phase = (json['phase'] ?? '').toString().trim();
    final pending = json['pending'];
    if (json['v'] != 1 ||
        intent == null ||
        scope.isEmpty ||
        phase.isEmpty ||
        pending is! List) {
      throw const FormatException('Invalid account cleanup journal');
    }
    return AccountCleanupJournal(
      intent: intent,
      scopeToken: scope,
      phase: phase,
      pendingArtifacts: pending
          .map((value) => value.toString())
          .where((value) => value.isNotEmpty)
          .toSet(),
    );
  }

  AccountCleanupJournal copyWith({
    String? phase,
    Set<String>? pendingArtifacts,
  }) =>
      AccountCleanupJournal(
        intent: intent,
        scopeToken: scopeToken,
        phase: phase ?? this.phase,
        pendingArtifacts: pendingArtifacts ?? this.pendingArtifacts,
      );
}
