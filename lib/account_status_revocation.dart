// lib/account_status_revocation.dart
import 'dart:convert';

String? hubAccountStatusRevocationReason(int statusCode, String body) {
  if (statusCode != 401 && statusCode != 404) return null;

  Object? decoded;
  try {
    decoded = jsonDecode(body);
  } catch (_) {
    return null;
  }
  if (decoded is! Map) return null;
  final detail = decoded['detail'];
  if (detail is! String) return null;

  if (statusCode == 401 && detail == 'Unauthorized') {
    return 'detail:Unauthorized';
  }
  if (statusCode == 404 && detail == 'Account not found') {
    return 'detail:Account not found';
  }
  return null;
}

/// Whether a /logout or /free/logout reply proves the hub no longer holds
/// this device. An HTTP status alone does not: a front or CDN error page can
/// carry 200, 401 or 404 without the hub handler ever running. The hub
/// answers {"ok": true} after deleting the device, and its exact 401
/// {"detail": "Unauthorized"} means the queued token no longer authorizes
/// that device (already removed or replaced). Anything else keeps the
/// pending logout queued for the next front or the next launch.
bool hubLogoutAcknowledged(int statusCode, String body) {
  Object? decoded;
  try {
    decoded = jsonDecode(body);
  } catch (_) {
    return false;
  }
  if (decoded is! Map) return false;
  if (statusCode == 200) return decoded['ok'] == true;
  return statusCode == 401 && decoded['detail'] == 'Unauthorized';
}
