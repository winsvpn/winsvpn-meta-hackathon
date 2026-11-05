// fake_async comes with flutter_test (transitive); declaring it would change pubspec.lock.
// ignore: depend_on_referenced_packages
import 'package:fake_async/fake_async.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/hub_request_window.dart';

void main() {
  test('legal fetch over 29 silent fronts is bounded by its window', () {
    fakeAsync((async) {
      final urls =
          List<String>.generate(29, (i) => 'https://f$i.example/legal/current');
      var finished = false;
      runHubRequestWindow<Map<String, String>>(
        urls: urls,
        policy: const HubRequestWindowPolicy(
          perRequestTimeout: Duration(seconds: 4),
          totalDeadline: Duration(seconds: 10),
        ),
        attempt: (url, abort) =>
            Future<HubAttemptResult<Map<String, String>>>.delayed(
                const Duration(seconds: 4),
                () => const HubAttemptResult<Map<String, String>>.rejected()),
      ).then((_) => finished = true);
      async.elapse(const Duration(seconds: 15));
      expect(finished, isTrue);
    });
  });
}
