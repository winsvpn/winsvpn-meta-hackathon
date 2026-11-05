// lib/signed_discovery_admission.dart
Map<String, DateTime> _signedDiscoveryAdmission =
    const <String, DateTime>{};

void setSignedDiscoveryAdmission(Map<String, DateTime> leases) {
  final accepted = <String, DateTime>{};
  for (final entry in leases.entries) {
    final uri = Uri.tryParse(entry.key);
    if (uri == null ||
        uri.scheme != 'https' ||
        uri.host.isEmpty ||
        uri.userInfo.isNotEmpty ||
        uri.port != 443 ||
        (uri.path.isNotEmpty && uri.path != '/') ||
        uri.hasQuery ||
        uri.hasFragment) {
      continue;
    }
    accepted['https://${uri.host.toLowerCase()}'] = entry.value.toUtc();
  }
  _signedDiscoveryAdmission =
      Map<String, DateTime>.unmodifiable(accepted);
}

bool signedDiscoveryHostAuthorized(String host, {DateTime? now}) {
  final until = _signedDiscoveryAdmission[
      'https://${host.trim().toLowerCase()}'];
  return until != null &&
      !until.isBefore((now ?? DateTime.now()).toUtc());
}

bool signedDiscoveryRequestAuthorized(Uri uri, {DateTime? now}) =>
    uri.scheme == 'https' &&
    uri.port == 443 &&
    uri.userInfo.isEmpty &&
    signedDiscoveryHostAuthorized(uri.host, now: now);

List<String> get signedDiscoveryGatewayTail {
  final now = DateTime.now().toUtc();
  return List<String>.unmodifiable(
    _signedDiscoveryAdmission.entries
        .where((entry) => !entry.value.isBefore(now))
        .map((entry) => entry.key),
  );
}
