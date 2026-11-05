class ApproximateNetworkLocation {
  const ApproximateNetworkLocation({
    required this.countryCode,
    this.latitude,
    this.longitude,
  });

  final String countryCode;
  final double? latitude;
  final double? longitude;
}

ApproximateNetworkLocation? parseApproximateNetworkLocation(Object? value) {
  if (value is! Map) return null;

  final countryCode = (value['country_code'] ??
          value['country_code2'] ??
          value['country'] ??
          '')
      .toString()
      .trim()
      .toUpperCase();
  if (!RegExp(r'^[A-Z]{2}$').hasMatch(countryCode)) return null;

  final latitude = _finiteCoordinate(value['latitude']);
  final longitude = _finiteCoordinate(value['longitude']);
  final hasValidPair = latitude != null &&
      longitude != null &&
      latitude >= -90 &&
      latitude <= 90 &&
      longitude >= -180 &&
      longitude <= 180;

  return ApproximateNetworkLocation(
    countryCode: countryCode,
    latitude: hasValidPair ? latitude : null,
    longitude: hasValidPair ? longitude : null,
  );
}

double? _finiteCoordinate(Object? value) {
  final parsed = value is num
      ? value.toDouble()
      : double.tryParse(value?.toString().trim() ?? '');
  return parsed != null && parsed.isFinite ? parsed : null;
}
