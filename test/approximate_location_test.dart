import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/approximate_location.dart';

void main() {
  test('parses normalized country and numeric coordinates', () {
    final location = parseApproximateNetworkLocation({
      'country_code': ' us ',
      'latitude': 41.8781,
      'longitude': -87.6298,
    });

    expect(location?.countryCode, 'US');
    expect(location?.latitude, 41.8781);
    expect(location?.longitude, -87.6298);
  });

  test('accepts finite coordinate strings from fallback providers', () {
    final location = parseApproximateNetworkLocation({
      'country_code2': 'MM',
      'latitude': '16.8409',
      'longitude': '96.1735',
    });

    expect(location?.countryCode, 'MM');
    expect(location?.latitude, 16.8409);
    expect(location?.longitude, 96.1735);
  });

  test('keeps country fallback but drops an invalid coordinate pair', () {
    for (final coordinates in [
      {'latitude': 'NaN', 'longitude': '10'},
      {'latitude': 'Infinity', 'longitude': '10'},
      {'latitude': '20', 'longitude': '-Infinity'},
      {'latitude': '91', 'longitude': '10'},
      {'latitude': '20', 'longitude': '181'},
      {'latitude': '20'},
    ]) {
      final location = parseApproximateNetworkLocation({
        'country': 'DE',
        ...coordinates,
      });

      expect(location?.countryCode, 'DE');
      expect(location?.latitude, isNull);
      expect(location?.longitude, isNull);
    }
  });

  test('rejects malformed or non-ISO country responses', () {
    expect(parseApproximateNetworkLocation(null), isNull);
    expect(parseApproximateNetworkLocation([]), isNull);
    expect(parseApproximateNetworkLocation({'country_code': 'USA'}), isNull);
    expect(parseApproximateNetworkLocation({'country_code': '1!'}), isNull);
    expect(parseApproximateNetworkLocation({'country_code': ''}), isNull);
  });
}
