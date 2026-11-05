import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/gateway_failover.dart';

void main() {
  group('signed update notice URL', () {
    test('sits beside the recovery record on the compiled host', () {
      expect(
        signedUpdateNoticeUrlFor(
          'https://raw.githubusercontent.com/o/r/main/gateway.txt',
        ).toString(),
        'https://raw.githubusercontent.com/o/r/main/update-notice.json',
      );
    });

    test('is refused for any record URL outside the compiled host', () {
      for (final bad in <String>[
        '',
        'http://raw.githubusercontent.com/o/r/main/gateway.txt',
        'https://raw.githubusercontent.com.evil.example/o/gateway.txt',
        'https://evil.example/o/r/main/gateway.txt',
        'https://user@raw.githubusercontent.com/o/r/main/gateway.txt',
      ]) {
        expect(signedUpdateNoticeUrlFor(bad), isNull, reason: bad);
      }
    });
  });

  group('signed update notice fetch', () {
    String ingest() {
      final source = File('lib/main.dart').readAsStringSync();
      const signature =
          'Future<void> _ingestSignedUpdateNotice(String recordUrl) async {';
      final start = source.indexOf(signature);
      expect(start, greaterThanOrEqualTo(0), reason: 'missing $signature');
      final end = source.indexOf('\n  }\n', start);
      expect(end, greaterThan(start));
      return source.substring(start, end);
    }

    test('the cap and the deadline are enforced while the body streams', () {
      final body = ingest();
      expect(
        body,
        contains('await fetchWithoutRedirectsCapped(\n'
            '        noticeUrl,\n'
            '        maxBytes: kMaxSignedUpdateNoticeBytes,\n'
            '        deadline: const Duration(seconds: 4),\n'
            '      );'),
      );
      expect(body, isNot(contains('fetchWithoutRedirects(noticeUrl)')));
      expect(body, isNot(contains('.timeout(')));
    });

    test('the account epoch is captured before the first await and is the '
        'one applied', () {
      final body = ingest();
      final capture =
          body.indexOf('final accountEpoch = _accountSessionEpoch.current;');
      expect(capture, greaterThan(0));
      expect(capture, lessThan(body.indexOf('await ')));
      expect(body, contains('await _applyAccountSyncData(data, accountEpoch);'));
      expect(body, isNot(contains('_accountSessionEpoch.current);')));
    });
  });
}
