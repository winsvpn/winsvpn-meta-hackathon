import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/account_status_revocation.dart';

void main() {
  test('the hub logout replies retire a pending logout', () {
    expect(hubLogoutAcknowledged(200, '{"ok":true}'), isTrue);
    expect(hubLogoutAcknowledged(401, '{"detail":"Unauthorized"}'), isTrue);
  });

  test('front and CDN error pages never retire a pending logout', () {
    for (final status in [200, 204, 401, 404]) {
      expect(hubLogoutAcknowledged(status, '<html>Gateway error</html>'),
          isFalse,
          reason: 'HTML reply with status $status');
    }
    expect(hubLogoutAcknowledged(200, ''), isFalse);
    expect(hubLogoutAcknowledged(200, '{"ok":false}'), isFalse);
    expect(hubLogoutAcknowledged(200, '{"ok":"true"}'), isFalse);
    expect(hubLogoutAcknowledged(200, '[]'), isFalse);
    expect(hubLogoutAcknowledged(401, '{"detail":"Access denied"}'), isFalse);
    expect(hubLogoutAcknowledged(404, '{"detail":"Not Found"}'), isFalse);
    expect(hubLogoutAcknowledged(429, '{"detail":"Unauthorized"}'), isFalse);
    expect(hubLogoutAcknowledged(503, '{"ok":true}'), isFalse);
  });
}
