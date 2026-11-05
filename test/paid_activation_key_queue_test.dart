import 'dart:async';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/account_session_lifecycle.dart';

class _ScopeQueue {
  final Map<String, Future<void>> _queues = <String, Future<void>>{};

  int get pendingOperationCount => _queues.length;

  Future<T> serialize<T>(
    String operationKey,
    Future<T> Function() operation,
  ) {
    final previous = _queues[operationKey] ?? Future<void>.value();
    final result = Completer<T>();
    late final Future<void> tail;
    tail = previous.catchError((Object _) {}).then((_) async {
      try {
        result.complete(await operation());
      } catch (error, stackTrace) {
        result.completeError(error, stackTrace);
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
}

String _methodBody(String source, String signature, String nextSignature) {
  final start = source.indexOf(signature);
  final end = source.indexOf(nextSignature, start);
  expect(start, greaterThanOrEqualTo(0), reason: signature);
  expect(end, greaterThan(start), reason: nextSignature);
  return source.substring(start, end);
}

void main() {
  test(
      'paid login auth success completes without queueing its key read behind itself',
      () async {
    final source = File('lib/main.dart').readAsStringSync();
    final paidLogin = _methodBody(
      source,
      'Future<void> _loginWithAccountNumber() async {',
      'Future<void> _loginWithFreeAccess() async {',
    );
    final authSuccess = _methodBody(
      source,
      'Future<void> _onAuthSuccess(',
      'Future<bool> _refreshFreeVpnConfig(',
    );

    final authRunsWhileQueueHeld = paidLogin.contains(
      'await _serializeClientKeyOperation(rawToken, () async {',
    );
    expect(authSuccess, contains('_loadExistingClientKeyPair('));
    final queue = _ScopeQueue();
    final events = <String>[];

    Future<void> loadExistingKeys() async {
      events.add('key-load');
      await Future<void>.delayed(Duration.zero);
    }

    Future<void> authSuccessPath() async {
      events.add('auth-success');
      await queue.serialize('paid-account', loadExistingKeys);
      events.add('activation-complete');
    }

    Future<void> paidLoginPath() async {
      events.add('login');
      await Future<void>.delayed(Duration.zero);
      await authSuccessPath();
    }

    final activation = authRunsWhileQueueHeld
        ? queue.serialize('paid-account', paidLoginPath)
        : paidLoginPath();
    await activation.timeout(const Duration(milliseconds: 250));
    await Future<void>.delayed(Duration.zero);

    expect(
      events,
      <String>['login', 'auth-success', 'key-load', 'activation-complete'],
    );
    expect(queue.pendingOperationCount, 0);
  });

  test('same-key re-entry fails fast and drains instead of poisoning the queue',
      () async {
    final queue = ClientKeyOperationQueue();

    await expectLater(
      queue.run<void>('scope:device', () async {
        await queue.run<void>('scope:device', () async {});
      }).timeout(const Duration(milliseconds: 250)),
      throwsA(
        isA<StateError>().having(
          (error) => error.message,
          'message',
          contains('queue behind itself'),
        ),
      ),
    );
    await Future<void>.delayed(Duration.zero);

    expect(queue.pendingOperationCount, 0);
    await queue
        .run<void>('scope:device', () async {})
        .timeout(const Duration(milliseconds: 250));
  });

  test('cross-key ABA re-entry fails fast instead of deadlocking', () async {
    final queue = ClientKeyOperationQueue();

    await expectLater(
      queue.run<void>('scope:k1', () async {
        await queue.run<void>('scope:k2', () async {
          await queue.run<void>('scope:k1', () async {});
        });
      }).timeout(const Duration(milliseconds: 250)),
      throwsA(
        isA<StateError>().having(
          (error) => error.message,
          'message',
          contains('queue behind itself'),
        ),
      ),
    );
    await Future<void>.delayed(Duration.zero);

    expect(queue.pendingOperationCount, 0);
    await queue
        .run<void>('scope:k1', () async {})
        .timeout(const Duration(milliseconds: 250));
    await queue
        .run<void>('scope:k2', () async {})
        .timeout(const Duration(milliseconds: 250));
  });

  test('nested distinct keys complete and expired owners do not accumulate',
      () async {
    final queue = ClientKeyOperationQueue();
    final events = <String>[];

    await queue.run<void>('scope:k1', () async {
      events.add('k1');
      await queue.run<void>('scope:k2', () async {
        events.add('k2');
        await queue.run<void>('scope:k3', () async {
          events.add('k3');
        });
      });
      await queue.run<void>('scope:k2', () async {
        events.add('k2-again');
      });
    }).timeout(const Duration(milliseconds: 250));
    await Future<void>.delayed(Duration.zero);

    expect(events, <String>['k1', 'k2', 'k3', 'k2-again']);
    expect(queue.pendingOperationCount, 0);
  });

  test('independent keys run concurrently', () async {
    final queue = ClientKeyOperationQueue();
    final firstStarted = Completer<void>();
    final releaseFirst = Completer<void>();
    final events = <String>[];

    final first = queue.run<void>('scope:k1', () async {
      events.add('k1-start');
      firstStarted.complete();
      await releaseFirst.future;
      events.add('k1-end');
    });
    await firstStarted.future;

    await queue.run<void>('scope:k2', () async {
      events.add('k2');
    }).timeout(const Duration(milliseconds: 250));
    expect(events, <String>['k1-start', 'k2']);

    releaseFirst.complete();
    await first.timeout(const Duration(milliseconds: 250));
    await Future<void>.delayed(Duration.zero);

    expect(events, <String>['k1-start', 'k2', 'k1-end']);
    expect(queue.pendingOperationCount, 0);
  });

  test('same-key operations stay FIFO and drain after an error', () async {
    final queue = ClientKeyOperationQueue();
    final firstStarted = Completer<void>();
    final releaseFirst = Completer<void>();
    final events = <String>[];

    final first = queue.run<void>('scope:device', () async {
      events.add('first-start');
      firstStarted.complete();
      await releaseFirst.future;
      events.add('first-end');
    });
    await firstStarted.future;
    final second = queue.run<void>('scope:device', () async {
      events.add('second');
      throw StateError('expected test error');
    });
    final secondFailed = expectLater(second, throwsA(isA<StateError>()));
    final third = queue.run<void>('scope:device', () async {
      events.add('third');
    });

    await Future<void>.delayed(Duration.zero);
    expect(events, <String>['first-start']);
    releaseFirst.complete();

    await first.timeout(const Duration(milliseconds: 250));
    await secondFailed;
    await third.timeout(const Duration(milliseconds: 250));
    await Future<void>.delayed(Duration.zero);

    expect(
      events,
      <String>['first-start', 'first-end', 'second', 'third'],
    );
    expect(queue.pendingOperationCount, 0);
  });

  test('sibling scopes do not inherit each other active keys', () async {
    final queue = ClientKeyOperationQueue();
    final secondKeyStarted = Completer<void>();
    final releaseSecondKey = Completer<void>();

    await queue.run<void>('scope:k1', () async {
      final secondKey = queue.run<void>('scope:k2', () async {
        secondKeyStarted.complete();
        await releaseSecondKey.future;
      });
      await secondKeyStarted.future;

      final thirdKey = queue.run<void>('scope:k3', () async {
        final nestedSecondKey = queue.run<void>('scope:k2', () async {});
        releaseSecondKey.complete();
        await nestedSecondKey;
      });

      await Future.wait(<Future<void>>[secondKey, thirdKey]);
    }).timeout(const Duration(milliseconds: 250));
    await Future<void>.delayed(Duration.zero);

    expect(queue.pendingOperationCount, 0);
  });

  test('detached callbacks may re-enter expired scope keys', () async {
    final queue = ClientKeyOperationQueue();
    final releaseDetached = Completer<void>();
    late Future<void> detached;

    await queue.run<void>('scope:device', () async {
      detached = releaseDetached.future.then(
        (_) => queue.run<void>('scope:device', () async {}),
      );
    });
    releaseDetached.complete();

    await detached.timeout(const Duration(milliseconds: 250));
    await Future<void>.delayed(Duration.zero);
    expect(queue.pendingOperationCount, 0);
  });
}
