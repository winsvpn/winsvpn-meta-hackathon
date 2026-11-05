import 'dart:async';

import 'package:flutter/services.dart';

const int _appleDiagnosticStringMaxLength = 256;
const int _appleDiagnosticListStringMaxLength = 96;
const int _appleDiagnosticListMaxCount = 16;

const List<String> _appleRawDiagnosticFragments = [
  '/users/',
  '/var/',
  '/private/',
  '/tmp/',
  '/etc/',
  '.ssh/',
  'group containers',
  'latest_tunnel.conf',
  'latest_status.json',
  'privatekey',
  'private key',
  'presharedkey',
  'preshared key',
  'endpoint =',
  'publickey =',
  'allowedips =',
  'address =',
  'http://',
  'https://',
  'file://',
];

final RegExp _appleIpv4LiteralPattern =
    RegExp(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)');
final RegExp _appleIpv6CandidatePattern = RegExp(
  r'(^|[^A-Za-z0-9])((?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f]{0,4})(?=$|[^A-Za-z0-9])',
);
final RegExp _appleHostnameLikePattern = RegExp(
  r'(^|[^A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?=$|[^A-Za-z0-9_-])',
);
final RegExp _appleUuidLikePattern = RegExp(
  r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
  caseSensitive: false,
);

bool _appleContainsIpv6Literal(String text) {
  for (final match in _appleIpv6CandidatePattern.allMatches(text)) {
    final candidate = match.group(2) ?? '';
    final colonCount = ':'.allMatches(candidate).length;
    if (candidate.contains('::') || colonCount >= 3) {
      return true;
    }
  }
  return false;
}

bool _appleContainsUnsafeDiagnosticToken(String text) {
  final lower = text.toLowerCase();
  return _appleRawDiagnosticFragments.any(lower.contains) ||
      _appleIpv4LiteralPattern.hasMatch(text) ||
      _appleContainsIpv6Literal(text) ||
      _appleHostnameLikePattern.hasMatch(text) ||
      _appleUuidLikePattern.hasMatch(text);
}

String appleSafeDiagnosticString(
  Object? value, {
  int maxLength = _appleDiagnosticStringMaxLength,
}) {
  final text = value?.toString().trim() ?? '';
  if (text.isEmpty || text.length > maxLength) return '';
  if (RegExp(r'[\x00-\x1F\x7F]').hasMatch(text)) return '';
  if (_appleContainsUnsafeDiagnosticToken(text)) return '';
  return text;
}

bool appleReadinessBool(Map<dynamic, dynamic>? readiness, String key) {
  final value = readiness?[key];
  if (value is bool) return value;
  return value?.toString().toLowerCase() == 'true';
}

String appleLiveTunnelContractFailureSummary({
  required bool doubleVpnRequested,
  required bool doubleVpnVerified,
  required bool ready,
  required bool connected,
  required bool transportModeVerified,
  required bool probeOk,
  required bool externalLeakAuditOk,
  Object? readinessFailure,
  Object? probeFailure,
}) {
  if (doubleVpnRequested && !doubleVpnVerified) {
    return 'Double VPN was requested, but the Core-to-exit route was not verified.';
  }
  if (!ready) {
    final safe = appleSafeDiagnosticString(readinessFailure, maxLength: 160);
    return safe.isNotEmpty
        ? safe
        : 'Apple VPN provider readiness was not verified.';
  }
  if (!connected) {
    return 'Apple VPN did not remain connected for the live probe.';
  }
  if (!transportModeVerified) {
    return 'Apple VPN transport did not match the requested route.';
  }
  if (!probeOk) {
    final safe = appleSafeDiagnosticString(probeFailure, maxLength: 160);
    return safe.isNotEmpty ? safe : 'Apple VPN internet probe failed.';
  }
  if (!externalLeakAuditOk) {
    return 'Apple VPN external leak-audit canaries did not all pass.';
  }
  return 'Apple live tunnel contract did not pass.';
}

String appleReadinessString(Map<dynamic, dynamic>? readiness, String key) {
  return appleSafeDiagnosticString(readiness?[key]);
}

const String appleAutomaticTransportMode = 'automatic';
const String appleDirectTransportMode = 'amneziawg';
const String appleXrayTransportMode = 'xray_vless_ws_amneziawg';

List<String> appleAllowedLiveTransportModes({required bool forceXray}) {
  return forceXray
      ? const <String>[appleXrayTransportMode]
      : const <String>[appleDirectTransportMode, appleXrayTransportMode];
}

String appleExpectedLiveTransportMode({required bool forceXray}) {
  return forceXray ? appleXrayTransportMode : appleAutomaticTransportMode;
}

bool appleLiveTransportModeVerified({
  required bool forceXray,
  required String observedTransportMode,
  required bool transportModeSupported,
  required bool transportModeConsistent,
  required bool executableSha256MatchesExpected,
}) {
  return appleAllowedLiveTransportModes(forceXray: forceXray)
          .contains(observedTransportMode) &&
      transportModeSupported &&
      transportModeConsistent &&
      executableSha256MatchesExpected;
}

int appleReadinessInt(Map<dynamic, dynamic>? readiness, String key) {
  return int.tryParse(appleReadinessString(readiness, key)) ?? 0;
}

Map<String, dynamic> appleLiveTunnelSmokeReadinessSnapshot(
    Map<dynamic, dynamic>? readiness) {
  if (readiness == null) {
    return const {
      'readiness_available': false,
      'readiness_summary': 'provider_readiness_unavailable',
    };
  }
  final summary = appleTunnelDebugFailureSummary(readiness, null);
  final safeSummary = appleSafeDiagnosticString(summary);
  final userFailure = appleTunnelUserFailureStatus(readiness, null);
  return {
    'readiness_available': true,
    'active': appleReadinessBool(readiness, 'active'),
    'network_extension_connected':
        appleReadinessBool(readiness, 'network_extension_connected'),
    'provider_ready': appleReadinessBool(readiness, 'provider_ready'),
    'provider_status_available':
        appleReadinessBool(readiness, 'provider_status_available'),
    'vpn_manager_invalid_after_config_save':
        appleReadinessBool(readiness, 'vpn_manager_invalid_after_config_save'),
    'vpn_configuration_permission_pending':
        appleReadinessBool(readiness, 'vpn_configuration_permission_pending'),
    'provider_status_current':
        appleReadinessBool(readiness, 'provider_status_current'),
    'provider_engine_ready':
        appleReadinessBool(readiness, 'provider_engine_ready'),
    'provider_network_settings_ready':
        appleReadinessBool(readiness, 'provider_network_settings_ready') ||
            appleReadinessBool(readiness, 'provider_network_settings_applied'),
    'provider_healthy': appleReadinessBool(readiness, 'provider_healthy'),
    'provider_message_probe_healthy':
        appleReadinessBool(readiness, 'provider_message_probe_healthy'),
    'provider_message_probe_accepted':
        appleReadinessBool(readiness, 'provider_message_probe_accepted'),
    'provider_message_probe_engine_running':
        appleReadinessBool(readiness, 'provider_message_probe_engine_running'),
    'provider_message_probe_transport_mode': appleReadinessString(
        readiness, 'provider_message_probe_transport_mode'),
    'provider_message_probe_xray_enabled':
        appleReadinessBool(readiness, 'provider_message_probe_xray_enabled'),
    'provider_message_probe_transport_mode_supported': appleReadinessBool(
        readiness, 'provider_message_probe_transport_mode_supported'),
    'provider_message_probe_transport_mode_consistent': appleReadinessBool(
        readiness, 'provider_message_probe_transport_mode_consistent'),
    'provider_message_probe_executable_sha256': appleReadinessString(
        readiness, 'provider_message_probe_executable_sha256'),
    'provider_message_probe_executable_sha256_matches_expected':
        appleReadinessBool(readiness,
            'provider_message_probe_executable_sha256_matches_expected'),
    'provider_stage': appleReadinessString(readiness, 'provider_stage'),
    'provider_previous_stage_before_stop':
        appleReadinessString(readiness, 'provider_previous_stage_before_stop'),
    'provider_previous_healthy_before_stop':
        appleReadinessBool(readiness, 'provider_previous_healthy_before_stop'),
    'provider_previous_engine_ready_before_stop': appleReadinessBool(
        readiness, 'provider_previous_engine_ready_before_stop'),
    'provider_previous_network_settings_ready_before_stop': appleReadinessBool(
        readiness, 'provider_previous_network_settings_ready_before_stop'),
    'provider_previous_network_settings_applied_before_stop':
        appleReadinessBool(readiness,
            'provider_previous_network_settings_applied_before_stop'),
    'provider_previous_transport_mode_before_stop': appleReadinessString(
        readiness, 'provider_previous_transport_mode_before_stop'),
    'provider_previous_network_settings_remote_address_kind_before_stop':
        appleReadinessString(readiness,
            'provider_previous_network_settings_remote_address_kind_before_stop'),
    'provider_previous_network_settings_remote_address_source_before_stop':
        appleReadinessString(readiness,
            'provider_previous_network_settings_remote_address_source_before_stop'),
    'provider_previous_engine_runtime_engine_ready_reported_before_stop':
        appleReadinessBool(readiness,
            'provider_previous_engine_runtime_engine_ready_reported_before_stop'),
    'provider_previous_engine_runtime_engine_running_reported_before_stop':
        appleReadinessBool(readiness,
            'provider_previous_engine_runtime_engine_running_reported_before_stop'),
    'provider_previous_app_message_command_before_stop': appleReadinessString(
        readiness, 'provider_previous_app_message_command_before_stop'),
    'provider_previous_app_message_command_is_health_before_stop':
        appleReadinessBool(readiness,
            'provider_previous_app_message_command_is_health_before_stop'),
    'provider_previous_app_message_accepted_before_stop': appleReadinessBool(
        readiness, 'provider_previous_app_message_accepted_before_stop'),
    'provider_previous_app_message_raw_payload_redacted_before_stop':
        appleReadinessBool(readiness,
            'provider_previous_app_message_raw_payload_redacted_before_stop'),
    'provider_previous_app_message_engine_running_before_stop':
        appleReadinessBool(readiness,
            'provider_previous_app_message_engine_running_before_stop'),
    'internet_probe_blocked_by_provider_readiness': appleReadinessBool(
        readiness, 'internet_probe_blocked_by_provider_readiness'),
    'internet_probe_blocked_by_leak_protection_config': appleReadinessBool(
        readiness, 'internet_probe_blocked_by_leak_protection_config'),
    'internet_probe_url_kind':
        appleReadinessString(readiness, 'internet_probe_url_kind'),
    'leak_protection_config_checked':
        appleReadinessBool(readiness, 'leak_protection_config_checked'),
    'leak_protection_config_passed':
        appleReadinessBool(readiness, 'leak_protection_config_passed'),
    'leak_protection_config_kind':
        appleReadinessString(readiness, 'leak_protection_config_kind'),
    'leak_protection_provider_status_current': appleReadinessBool(
        readiness, 'leak_protection_provider_status_current'),
    'leak_protection_default_route_enabled':
        appleReadinessBool(readiness, 'leak_protection_default_route_enabled'),
    'leak_protection_ipv6_enabled':
        appleReadinessBool(readiness, 'leak_protection_ipv6_enabled'),
    'leak_protection_engine_ipv6_enabled':
        appleReadinessBool(readiness, 'leak_protection_engine_ipv6_enabled'),
    'leak_protection_dns_full_tunnel_match_enabled': appleReadinessBool(
        readiness, 'leak_protection_dns_full_tunnel_match_enabled'),
    'leak_protection_engine_dns_full_tunnel_match_enabled': appleReadinessBool(
        readiness, 'leak_protection_engine_dns_full_tunnel_match_enabled'),
    'leak_protection_dns_server_count':
        appleReadinessInt(readiness, 'leak_protection_dns_server_count'),
    'leak_protection_engine_dns_server_count':
        appleReadinessInt(readiness, 'leak_protection_engine_dns_server_count'),
    'native_tunnel_status': appleReadinessString(readiness, 'status'),
    'readiness_summary': safeSummary.isEmpty ? userFailure : safeSummary,
  };
}

String _appleLiveTunnelSmokeProbeFallbackSummary(Map<dynamic, dynamic> probe) {
  if (appleReadinessBool(probe, 'ok')) {
    return 'internet_probe_ok';
  }
  if (appleReadinessBool(probe, 'external_leak_audit_requested')) {
    if (appleReadinessBool(
        probe, 'external_leak_audit_blocked_by_configuration')) {
      return 'external_leak_audit_blocked_by_configuration';
    }
    if (appleReadinessInt(probe, 'external_leak_audit_invalid_endpoint_count') >
        0) {
      return 'external_leak_audit_invalid_endpoint';
    }
    if (appleReadinessBool(probe, 'external_leak_audit_attempted') &&
        !appleReadinessBool(probe, 'external_leak_audit_passed')) {
      return 'external_leak_audit_failed';
    }
  }
  if (appleReadinessBool(
      probe, 'internet_probe_blocked_by_provider_readiness')) {
    return 'internet_probe_blocked_by_provider_readiness';
  }
  if (appleReadinessBool(
      probe, 'internet_probe_blocked_by_leak_protection_config')) {
    return 'internet_probe_blocked_by_leak_protection_config';
  }
  return 'internet_probe_failed';
}

Map<String, dynamic> appleLiveTunnelSmokeProbeSnapshot(
    Map<dynamic, dynamic>? probe) {
  if (probe == null) {
    return const {
      'internet_probe_available': false,
      'internet_probe_ok': false,
    };
  }
  final summary = appleTunnelDebugFailureSummary(probe, null);
  final safeSummary = appleSafeDiagnosticString(summary);
  final fallbackSummary = _appleLiveTunnelSmokeProbeFallbackSummary(probe);
  final useFallbackSummary = fallbackSummary.startsWith('external_leak_audit_');
  return {
    'internet_probe_available': true,
    'internet_probe_ok': appleReadinessBool(probe, 'ok'),
    'internet_probe_attempted':
        appleReadinessBool(probe, 'internet_probe_attempted'),
    'internet_probe_blocked_by_provider_readiness': appleReadinessBool(
        probe, 'internet_probe_blocked_by_provider_readiness'),
    'internet_probe_blocked_by_leak_protection_config': appleReadinessBool(
        probe, 'internet_probe_blocked_by_leak_protection_config'),
    'internet_probe_status_code': appleReadinessInt(probe, 'status_code'),
    'internet_probe_url_kind':
        appleSafeDiagnosticString(probe['internet_probe_url_kind']),
    'leak_protection_config_checked':
        appleReadinessBool(probe, 'leak_protection_config_checked'),
    'leak_protection_config_passed':
        appleReadinessBool(probe, 'leak_protection_config_passed'),
    'leak_protection_config_kind':
        appleReadinessString(probe, 'leak_protection_config_kind'),
    'leak_protection_provider_status_current':
        appleReadinessBool(probe, 'leak_protection_provider_status_current'),
    'leak_protection_default_route_enabled':
        appleReadinessBool(probe, 'leak_protection_default_route_enabled'),
    'leak_protection_ipv6_enabled':
        appleReadinessBool(probe, 'leak_protection_ipv6_enabled'),
    'leak_protection_engine_ipv6_enabled':
        appleReadinessBool(probe, 'leak_protection_engine_ipv6_enabled'),
    'leak_protection_dns_full_tunnel_match_enabled': appleReadinessBool(
        probe, 'leak_protection_dns_full_tunnel_match_enabled'),
    'leak_protection_engine_dns_full_tunnel_match_enabled': appleReadinessBool(
        probe, 'leak_protection_engine_dns_full_tunnel_match_enabled'),
    'leak_protection_dns_server_count':
        appleReadinessInt(probe, 'leak_protection_dns_server_count'),
    'leak_protection_engine_dns_server_count':
        appleReadinessInt(probe, 'leak_protection_engine_dns_server_count'),
    'internet_probe_native_error_domain':
        appleSafeDiagnosticString(probe['native_error_domain']),
    'internet_probe_native_error_code':
        appleSafeDiagnosticString(probe['native_error_code']),
    'internet_probe_error':
        appleSafeDiagnosticString(probe['error'], maxLength: 160),
    'external_leak_audit_requested':
        appleReadinessBool(probe, 'external_leak_audit_requested'),
    'external_leak_audit_attempted':
        appleReadinessBool(probe, 'external_leak_audit_attempted'),
    'external_leak_audit_passed':
        appleReadinessBool(probe, 'external_leak_audit_passed'),
    'external_leak_audit_endpoint_count':
        appleReadinessInt(probe, 'external_leak_audit_endpoint_count'),
    'external_leak_audit_minimum_endpoint_count':
        appleReadinessInt(probe, 'external_leak_audit_minimum_endpoint_count'),
    'external_leak_audit_invalid_endpoint_count':
        appleReadinessInt(probe, 'external_leak_audit_invalid_endpoint_count'),
    'external_leak_audit_success_count':
        appleReadinessInt(probe, 'external_leak_audit_success_count'),
    'external_leak_audit_failure_count':
        appleReadinessInt(probe, 'external_leak_audit_failure_count'),
    'external_leak_audit_transport_error_count':
        appleReadinessInt(probe, 'external_leak_audit_transport_error_count'),
    'external_leak_audit_server_error_count':
        appleReadinessInt(probe, 'external_leak_audit_server_error_count'),
    'external_leak_audit_https_canary_count':
        appleReadinessInt(probe, 'external_leak_audit_https_canary_count'),
    'external_leak_audit_dns_canary_count':
        appleReadinessInt(probe, 'external_leak_audit_dns_canary_count'),
    'external_leak_audit_non_google_cloudflare_only': appleReadinessBool(
        probe, 'external_leak_audit_non_google_cloudflare_only'),
    'external_leak_audit_blocked_by_configuration': appleReadinessBool(
        probe, 'external_leak_audit_blocked_by_configuration'),
    'external_leak_audit_url_kind':
        appleSafeDiagnosticString(probe['external_leak_audit_url_kind']),
    'internet_probe_summary': useFallbackSummary || safeSummary.isEmpty
        ? fallbackSummary
        : safeSummary,
  };
}

String appleReadinessStatusGeneration(
    Map<dynamic, dynamic>? readiness, String key) {
  final value = appleReadinessString(readiness, key);
  if (value.isEmpty || value.length > 64) return '';
  if (RegExp(r'[\x00-\x1F\x7F]').hasMatch(value)) return '';
  if (_appleContainsUnsafeDiagnosticToken(value)) return '';
  return value;
}

List<String> appleReadinessStringList(
    Map<dynamic, dynamic>? readiness, String key) {
  final value = readiness?[key];
  if (value is Iterable) {
    return value
        .map((entry) => appleSafeDiagnosticString(
              entry,
              maxLength: _appleDiagnosticListStringMaxLength,
            ))
        .where((entry) => entry.isNotEmpty)
        .take(_appleDiagnosticListMaxCount)
        .toList();
  }
  final single = appleSafeDiagnosticString(
    value,
    maxLength: _appleDiagnosticListStringMaxLength,
  );
  return single.isEmpty ? const [] : [single];
}

bool appleTunnelProviderStatusCurrent(Map<dynamic, dynamic>? readiness) {
  return appleReadinessBool(readiness, 'provider_status_available') &&
      appleTunnelProviderSchemaSupported(readiness) &&
      !appleReadinessBool(readiness, 'provider_status_stale') &&
      !appleReadinessBool(readiness, 'provider_status_bundle_mismatch') &&
      !appleReadinessBool(
          readiness, 'provider_status_extension_type_mismatch') &&
      !appleReadinessBool(readiness, 'provider_status_timestamp_invalid') &&
      !appleReadinessBool(readiness, 'provider_status_stage_invalid') &&
      !appleTunnelProviderSchemaUnsupported(readiness);
}

bool appleTunnelProviderAppMessageTrusted(Map<dynamic, dynamic>? readiness) {
  if (appleReadinessString(readiness, 'provider_stage') != 'app_message') {
    return true;
  }
  final statusMessageTrusted = appleReadinessBool(
          readiness, 'provider_app_message_accepted') &&
      appleReadinessBool(readiness, 'provider_app_message_command_is_health') &&
      appleReadinessBool(
          readiness, 'provider_app_message_raw_payload_redacted');
  final probeMessageTrusted = appleReadinessBool(
          readiness, 'provider_message_probe_healthy') &&
      appleReadinessBool(readiness, 'provider_message_probe_engine_running');
  return statusMessageTrusted || probeMessageTrusted;
}

bool appleTunnelProviderLifecycleTrusted(Map<dynamic, dynamic>? readiness) {
  return appleReadinessString(readiness, 'provider_stage') != 'sleeping' &&
      !appleReadinessBool(readiness, 'provider_lifecycle_suspended');
}

bool appleTunnelProviderSchemaSupported(Map<dynamic, dynamic>? readiness) {
  return appleReadinessBool(readiness, 'provider_status_schema_supported') &&
      !appleReadinessBool(readiness, 'provider_status_schema_unsupported');
}

bool appleTunnelProviderSchemaUnsupported(Map<dynamic, dynamic>? readiness) {
  final supported =
      appleReadinessString(readiness, 'provider_status_schema_supported');
  return appleReadinessBool(readiness, 'provider_status_schema_unsupported') ||
      (supported.isNotEmpty &&
          !appleReadinessBool(
            readiness,
            'provider_status_schema_supported',
          ));
}

bool appleTunnelNeedsVpnConfigurationPermission(
    Map<dynamic, dynamic>? readiness,
    [Object? error]) {
  final platform = appleReadinessString(readiness, 'platform');
  final explicitPermissionPending =
      appleReadinessBool(readiness, 'vpn_configuration_permission_pending');
  final isIosReadiness =
      platform == 'ios' || (platform.isEmpty && explicitPermissionPending);
  final stageInvalid =
      appleReadinessBool(readiness, 'provider_status_stage_invalid');
  final stage =
      stageInvalid ? '' : appleReadinessString(readiness, 'provider_stage');
  final nativeTunnelStatus = appleReadinessString(readiness, 'status');
  final iosPermissionPending = isIosReadiness &&
      (appleReadinessBool(readiness, 'vpn_manager_invalid_after_config_save') ||
          explicitPermissionPending ||
          (stage == 'config_saved' && nativeTunnelStatus == 'invalid'));
  if (iosPermissionPending) return true;

  if (platform != 'macos') return false;
  if (error is TimeoutException &&
      stage == 'config_saved' &&
      nativeTunnelStatus == 'invalid') {
    return true;
  }
  if (error is! PlatformException) return false;
  final nativeDetails = error.details is Map ? error.details as Map : null;
  final nativeDomain = appleSafeDiagnosticString(
    nativeDetails?['native_error_domain'],
    maxLength: 128,
  ).toLowerCase();
  final nativeCode = appleSafeDiagnosticString(
    nativeDetails?['native_error_code'],
    maxLength: 32,
  );
  final safeMessage = appleSafeDiagnosticString(error.message).toLowerCase();
  return error.code == 'APPLE_TUNNEL_SAVE_FAILED' &&
      ((nativeDomain == 'nevpnerrordomain' && nativeCode == '5') ||
          safeMessage.contains('permission denied'));
}

bool appleTunnelReady(Map<dynamic, dynamic>? readiness) {
  final active = appleReadinessBool(readiness, 'active') ||
      appleReadinessString(readiness, 'status') == 'connected';
  final providerMessageProbeAttempted =
      appleReadinessBool(readiness, 'provider_message_probe_attempted');
  final providerMessageProbeHealthy =
      appleReadinessBool(readiness, 'provider_message_probe_healthy');
  final providerMessageProbeEngineRunning =
      appleReadinessBool(readiness, 'provider_message_probe_engine_running');
  final providerEngineReady =
      appleReadinessBool(readiness, 'provider_engine_ready') ||
          (providerMessageProbeHealthy && providerMessageProbeEngineRunning);
  final providerNetworkReady =
      appleReadinessBool(readiness, 'provider_network_settings_applied') ||
          appleReadinessBool(readiness, 'provider_network_settings_ready') ||
          (active && providerMessageProbeHealthy);
  final providerHealthy = appleReadinessBool(readiness, 'provider_healthy') ||
      (providerMessageProbeHealthy &&
          providerEngineReady &&
          providerNetworkReady);
  return active &&
      appleTunnelProviderStatusCurrent(readiness) &&
      providerEngineReady &&
      providerNetworkReady &&
      providerHealthy &&
      appleTunnelProviderAppMessageTrusted(readiness) &&
      appleTunnelProviderLifecycleTrusted(readiness) &&
      (!providerMessageProbeAttempted || providerMessageProbeHealthy);
}

String nativeTunnelErrorSummary(Object? error) {
  if (error == null) return '';
  if (error is PlatformException) {
    final code = appleSafeDiagnosticString(error.code, maxLength: 96).isEmpty
        ? 'NATIVE_ERROR'
        : appleSafeDiagnosticString(error.code, maxLength: 96);
    final message = appleSafeDiagnosticString(error.message);
    final summary = message.isEmpty ? code : '$code: $message';
    final nativeDetails = platformExceptionNativeDetails(error.details);
    return nativeDetails.isEmpty ? summary : '$summary; $nativeDetails';
  }
  final fallback = appleSafeDiagnosticString(error);
  return fallback.isEmpty ? 'native_error_redacted' : fallback;
}

String platformExceptionNativeDetails(Object? details) {
  if (details is! Map) return '';
  final nativeDomain = appleSafeDiagnosticString(
    details['native_error_domain'],
    maxLength: 128,
  );
  final nativeCode = appleSafeDiagnosticString(
    details['native_error_code'],
    maxLength: 32,
  );
  final parts = <String>[
    if (nativeDomain.isNotEmpty) 'native_domain=$nativeDomain',
    if (nativeCode.isNotEmpty) 'native_code=$nativeCode',
  ];
  return parts.join('; ');
}

String appleTunnelUserFailureStatus(
    Map<dynamic, dynamic>? readiness, Object? error) {
  final stageInvalid =
      appleReadinessBool(readiness, 'provider_status_stage_invalid');
  final stage =
      stageInvalid ? '' : appleReadinessString(readiness, 'provider_stage');
  final probe = appleReadinessString(readiness, 'provider_engine_bundle_probe');
  final errorCode = appleReadinessString(readiness, 'provider_error_code');
  final providerConfigSourceAvailable =
      appleReadinessString(readiness, 'provider_config_source_available');
  final providerConfigFileReadable =
      appleReadinessString(readiness, 'provider_config_file_readable');
  final providerConfigUtf8Valid =
      appleReadinessString(readiness, 'provider_config_utf8_valid');
  final providerConfigFileSymbolicLink =
      appleReadinessString(readiness, 'provider_config_file_symbolic_link');
  final providerConfigAppGroupContainerAvailable = appleReadinessString(
      readiness, 'provider_config_app_group_container_available');
  final providerConfigAppGroupIdAllowed =
      appleReadinessString(readiness, 'provider_config_app_group_id_allowed');
  final providerConfigSharedPathAllowed =
      appleReadinessString(readiness, 'provider_config_shared_path_allowed');
  final providerSharedKeychainPrivateKeyAvailable = appleReadinessString(
      readiness, 'provider_shared_keychain_private_key_available');
  final providerExpectedClientPublicKeyValid = appleReadinessString(
      readiness, 'provider_expected_client_public_key_valid');
  final providerStatusContainerAvailable =
      appleReadinessString(readiness, 'provider_status_container_available');
  final providerStatusFileReadable =
      appleReadinessString(readiness, 'provider_status_file_readable');
  final providerStatusJsonValid =
      appleReadinessString(readiness, 'provider_status_json_valid');
  final providerAppMessageAccepted =
      appleReadinessString(readiness, 'provider_app_message_accepted');
  final providerAppMessageCommandIsHealth =
      appleReadinessString(readiness, 'provider_app_message_command_is_health');
  final errorText = [
    appleReadinessString(readiness, 'provider_error'),
    nativeTunnelErrorSummary(error),
  ].join(' ').toLowerCase();

  if (stageInvalid) {
    return 'Apple VPN provider returned an unknown readiness stage.';
  }
  if (stage == 'engine_start_failed' ||
      errorCode == '1004' ||
      errorText.contains('running packet flow')) {
    return 'Apple VPN engine did not become ready.';
  }
  if (stage == 'engine_missing' ||
      probe == 'missing_native_engine_library' ||
      probe == 'native_engine_adapter_missing' ||
      errorText.contains('native packet engine is not bundled') ||
      errorText.contains('awg/xray engine is not bundled')) {
    return 'Apple VPN engine is not ready in this build yet.';
  }
  if (stage == 'network_settings_failed') {
    return 'Apple rejected the VPN route settings for this build.';
  }
  if (appleReadinessBool(readiness, 'provider_config_file_too_large') ||
      appleReadinessBool(readiness, 'provider_config_too_large')) {
    return 'Apple VPN provider config file is too large.';
  }
  if (providerConfigAppGroupIdAllowed.isNotEmpty &&
      !appleReadinessBool(readiness, 'provider_config_app_group_id_allowed')) {
    return 'Apple VPN provider rejected the App Group identifier.';
  }
  if (providerConfigAppGroupContainerAvailable.isNotEmpty &&
      !appleReadinessBool(
          readiness, 'provider_config_app_group_container_available')) {
    return 'Apple VPN provider cannot access the App Group config.';
  }
  if (providerConfigSharedPathAllowed.isNotEmpty &&
      !appleReadinessBool(readiness, 'provider_config_shared_path_allowed')) {
    return 'Apple VPN provider rejected the App Group config handoff path.';
  }
  if (providerConfigFileSymbolicLink.isNotEmpty &&
      appleReadinessBool(readiness, 'provider_config_file_symbolic_link')) {
    return 'Apple VPN provider config handoff file is not a regular file.';
  }
  if (providerConfigFileReadable.isNotEmpty &&
      !appleReadinessBool(readiness, 'provider_config_file_readable') &&
      appleReadinessBool(readiness, 'provider_config_file_present')) {
    return 'Apple VPN provider config file could not be read.';
  }
  if (providerConfigUtf8Valid.isNotEmpty &&
      !appleReadinessBool(readiness, 'provider_config_utf8_valid')) {
    return 'Apple VPN provider config file is unreadable.';
  }
  if (appleReadinessBool(readiness, 'provider_config_empty')) {
    return 'Apple VPN provider config file is empty.';
  }
  if (providerSharedKeychainPrivateKeyAvailable.isNotEmpty &&
      !appleReadinessBool(
          readiness, 'provider_shared_keychain_private_key_available')) {
    return 'Apple VPN provider could not access the shared Keychain key.';
  }
  if ((providerConfigSourceAvailable.isNotEmpty &&
          !appleReadinessBool(readiness, 'provider_config_source_available')) ||
      errorCode == '1001') {
    return 'Apple VPN provider did not receive tunnel config. Refresh activation and try again.';
  }
  if (providerExpectedClientPublicKeyValid.isNotEmpty &&
      !appleReadinessBool(
          readiness, 'provider_expected_client_public_key_valid')) {
    return 'Apple VPN client key is invalid. Refresh activation and try again.';
  }
  if (stage == 'start_rejected' ||
      errorCode == '1101' ||
      errorCode == '1105' ||
      errorText.contains('apple_tunnel_config_invalid')) {
    return 'Apple VPN config validation failed. Refresh activation and try again.';
  }
  if (appleTunnelNeedsVpnConfigurationPermission(readiness, error)) {
    if (appleReadinessString(readiness, 'platform') == 'macos') {
      return "Approve the macOS VPN configuration permission for Win's VPN, then try again.";
    }
    return "Approve the iOS VPN configuration permission for Win's VPN on this iPhone, then try again.";
  }
  if (appleReadinessBool(readiness, 'provider_status_stale')) {
    return 'Apple VPN provider did not return current readiness yet.';
  }
  if (appleTunnelProviderSchemaUnsupported(readiness)) {
    return 'Apple VPN provider returned an unsupported readiness format.';
  }
  if (appleReadinessBool(readiness, 'provider_status_bundle_mismatch')) {
    return 'Apple VPN provider readiness came from the wrong extension.';
  }
  if (appleReadinessBool(
      readiness, 'provider_status_extension_type_mismatch')) {
    return 'Apple VPN provider readiness came from the wrong Network Extension type.';
  }
  if (appleReadinessBool(readiness, 'provider_status_timestamp_invalid')) {
    return 'Apple VPN provider returned an invalid readiness timestamp.';
  }
  if (stage == 'sleeping' ||
      appleReadinessBool(readiness, 'provider_lifecycle_suspended')) {
    return 'Apple VPN provider is suspended.';
  }
  if (appleReadinessBool(
      readiness, 'provider_status_write_payload_too_large')) {
    return 'Apple VPN provider readiness was reduced safely.';
  }
  if (appleReadinessBool(readiness, 'provider_status_file_too_large')) {
    return 'Apple VPN provider readiness file is too large.';
  }
  if (appleReadinessBool(readiness, 'provider_status_file_symbolic_link')) {
    return 'Apple VPN provider readiness file is not a regular file.';
  }
  if (stage == 'app_message' &&
      ((providerAppMessageAccepted.isNotEmpty &&
              !appleReadinessBool(
                  readiness, 'provider_app_message_accepted')) ||
          (providerAppMessageCommandIsHealth.isNotEmpty &&
              !appleReadinessBool(
                  readiness, 'provider_app_message_command_is_health')))) {
    return 'Apple VPN provider did not accept health check.';
  }
  if (providerStatusContainerAvailable.isNotEmpty &&
      !appleReadinessBool(readiness, 'provider_status_container_available')) {
    return 'Apple VPN App Group is unavailable.';
  }
  if (providerStatusFileReadable.isNotEmpty &&
      !appleReadinessBool(readiness, 'provider_status_file_readable') &&
      appleReadinessBool(readiness, 'provider_status_file_present')) {
    return 'Apple VPN provider readiness file could not be read.';
  }
  if (providerStatusJsonValid.isNotEmpty &&
      !appleReadinessBool(readiness, 'provider_status_json_valid') &&
      appleReadinessBool(readiness, 'provider_status_file_present')) {
    return 'Apple VPN provider returned unreadable readiness.';
  }
  if (appleReadinessBool(readiness, 'provider_message_probe_attempted') &&
      !appleReadinessBool(readiness, 'provider_message_probe_healthy')) {
    return 'Apple VPN provider did not respond to health check.';
  }
  if (readiness == null ||
      appleReadinessBool(readiness, 'provider_status_available') == false) {
    return 'Apple VPN provider did not return readiness yet.';
  }
  return 'Apple VPN could not start on this build.';
}

String appleTunnelDebugFailureSummary(
    Map<dynamic, dynamic>? readiness, Object? error) {
  final nativeError = nativeTunnelErrorSummary(error);
  final components = appleReadinessStringList(
      readiness, 'provider_engine_required_components');
  final missingBundleComponents = appleReadinessStringList(
      readiness, 'provider_engine_bundle_missing_components');
  final availableBundleComponents = appleReadinessStringList(
      readiness, 'provider_engine_bundle_available_components');
  final bundleAllRequiredPresent = appleReadinessString(
      readiness, 'provider_engine_bundle_all_required_components_present');
  final adapterAvailable =
      appleReadinessString(readiness, 'provider_engine_adapter_available');
  final runtimePacketFlowAttached = appleReadinessString(
      readiness, 'provider_engine_runtime_packet_flow_attached');
  final runtimeContractFailed = appleReadinessString(
      readiness, 'provider_engine_runtime_contract_failed');
  final runtimeReadyReported = appleReadinessString(
      readiness, 'provider_engine_runtime_engine_ready_reported');
  final runtimeRunningReported = appleReadinessString(
      readiness, 'provider_engine_runtime_engine_running_reported');
  final runtimeAwgStarted =
      appleReadinessString(readiness, 'provider_engine_runtime_awg_started');
  final runtimeXrayStarted =
      appleReadinessString(readiness, 'provider_engine_runtime_xray_started');
  final runtimeSecretsRedacted = appleReadinessString(
      readiness, 'provider_engine_runtime_secret_material_redacted');
  final runtimeStatusSanitized = appleReadinessString(
      readiness, 'provider_engine_runtime_status_sanitized');
  final launchDescriptorReady = appleReadinessString(
      readiness, 'provider_engine_launch_descriptor_ready');
  final launchSecretsRedacted = appleReadinessString(
      readiness, 'provider_engine_launch_descriptor_secret_material_redacted');
  final awgUapiConfigReady =
      appleReadinessString(readiness, 'provider_engine_awg_uapi_config_ready');
  final awgUapiSecretsRedacted = appleReadinessString(
      readiness, 'provider_engine_awg_uapi_secret_material_redacted');
  final interfacePrivateKeyRedacted = appleReadinessString(
      readiness, 'provider_engine_interface_private_key_redacted');
  final peerPublicKeyRedacted = appleReadinessString(
      readiness, 'provider_engine_peer_public_key_redacted');
  final awgObfuscationFieldCount = appleReadinessString(
      readiness, 'provider_engine_awg_obfuscation_field_count');
  final launchContractVersion = appleReadinessString(
      readiness, 'provider_engine_launch_contract_version');
  final packetFlowRequired =
      appleReadinessString(readiness, 'provider_engine_packet_flow_required');
  final packetFlowAvailable =
      appleReadinessString(readiness, 'provider_engine_packet_flow_available');
  final engineXrayRequired = appleReadinessString(
      readiness, 'provider_engine_xray_transport_required');
  final engineRouteCount = appleReadinessString(
      readiness, 'provider_engine_allowed_ipv4_route_count');
  final engineDnsCount =
      appleReadinessString(readiness, 'provider_engine_dns_server_count');
  final ipv6LeakProtection =
      appleReadinessString(readiness, 'provider_ipv6_leak_protection_enabled');
  final engineIpv6LeakProtection = appleReadinessString(
      readiness, 'provider_engine_ipv6_leak_protection_enabled');
  final transportEndpointKind =
      appleReadinessString(readiness, 'provider_transport_endpoint_kind');
  final networkRemoteKind = appleReadinessString(
      readiness, 'provider_network_settings_remote_address_kind');
  final networkRemoteSource = appleReadinessString(
      readiness, 'provider_network_settings_remote_address_source');
  final transportExclusionPresent = appleReadinessString(
      readiness, 'provider_transport_ipv4_exclusion_route_present');
  final dnsFullTunnelMatch =
      appleReadinessString(readiness, 'provider_dns_full_tunnel_match_enabled');
  final keyVerificationRequired = appleReadinessString(
      readiness, 'provider_client_key_pair_verification_required');
  final expectedClientPublicKeySource = appleReadinessString(
      readiness, 'provider_expected_client_public_key_source');
  final expectedClientPublicKeyValid = appleReadinessString(
      readiness, 'provider_expected_client_public_key_valid');
  final keyVerified =
      appleReadinessString(readiness, 'provider_client_key_pair_verified');
  final providerConfigSource =
      appleReadinessString(readiness, 'provider_config_source');
  final providerConfigSourceAvailable =
      appleReadinessString(readiness, 'provider_config_source_available');
  final providerConfigFilePresent =
      appleReadinessString(readiness, 'provider_config_file_present');
  final providerConfigFileReadable =
      appleReadinessString(readiness, 'provider_config_file_readable');
  final providerConfigFileTooLarge =
      appleReadinessString(readiness, 'provider_config_file_too_large');
  final providerConfigTooLarge =
      appleReadinessString(readiness, 'provider_config_too_large');
  final providerConfigUtf8Valid =
      appleReadinessString(readiness, 'provider_config_utf8_valid');
  final providerConfigFileSymbolicLink =
      appleReadinessString(readiness, 'provider_config_file_symbolic_link');
  final providerConfigEmpty =
      appleReadinessString(readiness, 'provider_config_empty');
  final providerConfigSize =
      appleReadinessString(readiness, 'provider_config_size_bytes');
  final providerConfigMaxSize =
      appleReadinessString(readiness, 'provider_config_max_size_bytes');
  final providerConfigSharedPathPresent =
      appleReadinessString(readiness, 'provider_config_shared_path_present');
  final providerConfigSharedPathAllowed =
      appleReadinessString(readiness, 'provider_config_shared_path_allowed');
  final providerConfigSharedPathMatchesExpected = appleReadinessString(
      readiness, 'provider_config_shared_path_matches_expected');
  final providerConfigSharedPathInsideAppGroup = appleReadinessString(
      readiness, 'provider_config_shared_path_inside_app_group');
  final providerConfigAppGroupIdPresent =
      appleReadinessString(readiness, 'provider_config_app_group_id_present');
  final providerConfigAppGroupIdAllowed =
      appleReadinessString(readiness, 'provider_config_app_group_id_allowed');
  final providerConfigAppGroupContainerAvailable = appleReadinessString(
      readiness, 'provider_config_app_group_container_available');
  final providerSharedKeychainPrivateKeyAvailable = appleReadinessString(
      readiness, 'provider_shared_keychain_private_key_available');
  final lifecycleEvent =
      appleReadinessString(readiness, 'provider_lifecycle_event');
  final lifecycleSuspended =
      appleReadinessString(readiness, 'provider_lifecycle_suspended');
  final appMessageCommand =
      appleReadinessString(readiness, 'provider_app_message_command');
  final appMessageCommandIsHealth =
      appleReadinessString(readiness, 'provider_app_message_command_is_health');
  final appMessageAccepted =
      appleReadinessString(readiness, 'provider_app_message_accepted');
  final appMessageRedacted = appleReadinessString(
      readiness, 'provider_app_message_raw_payload_redacted');
  final engineWasRunningBeforeStop = appleReadinessString(
      readiness, 'provider_engine_was_running_before_stop');
  final previousStageBeforeStop =
      appleReadinessString(readiness, 'provider_previous_stage_before_stop');
  final previousHealthyBeforeStop =
      appleReadinessString(readiness, 'provider_previous_healthy_before_stop');
  final previousEngineReadyBeforeStop = appleReadinessString(
      readiness, 'provider_previous_engine_ready_before_stop');
  final previousNetworkReadyBeforeStop = appleReadinessString(
      readiness, 'provider_previous_network_settings_ready_before_stop');
  final previousNetworkAppliedBeforeStop = appleReadinessString(
      readiness, 'provider_previous_network_settings_applied_before_stop');
  final previousNetworkRemoteSourceBeforeStop = appleReadinessString(readiness,
      'provider_previous_network_settings_remote_address_source_before_stop');
  final previousRuntimeReadyBeforeStop = appleReadinessString(readiness,
      'provider_previous_engine_runtime_engine_ready_reported_before_stop');
  final previousRuntimeRunningBeforeStop = appleReadinessString(readiness,
      'provider_previous_engine_runtime_engine_running_reported_before_stop');
  final previousAppMessageCommandBeforeStop = appleReadinessString(
      readiness, 'provider_previous_app_message_command_before_stop');
  final previousAppMessageCommandIsHealthBeforeStop = appleReadinessString(
      readiness, 'provider_previous_app_message_command_is_health_before_stop');
  final previousAppMessageAcceptedBeforeStop = appleReadinessString(
      readiness, 'provider_previous_app_message_accepted_before_stop');
  final previousAppMessageRedactedBeforeStop = appleReadinessString(readiness,
      'provider_previous_app_message_raw_payload_redacted_before_stop');
  final previousAppMessageEngineRunningBeforeStop = appleReadinessString(
      readiness, 'provider_previous_app_message_engine_running_before_stop');
  final providerProbeAttempted =
      appleReadinessString(readiness, 'provider_message_probe_attempted');
  final providerProbeHealthy =
      appleReadinessString(readiness, 'provider_message_probe_healthy');
  final providerProbeAccepted =
      appleReadinessString(readiness, 'provider_message_probe_accepted');
  final providerProbeEngineRunning =
      appleReadinessString(readiness, 'provider_message_probe_engine_running');
  final providerProbeCommand =
      appleReadinessString(readiness, 'provider_message_probe_command');
  final providerProbeCommandIsHealth = appleReadinessString(
      readiness, 'provider_message_probe_command_is_health');
  final providerProbeTimeout =
      appleReadinessString(readiness, 'provider_message_probe_timeout');
  final providerProbeResponseSchemaVersion = appleReadinessString(
      readiness, 'provider_message_probe_response_schema_version');
  final providerProbeResponseSchemaSupported = appleReadinessString(
      readiness, 'provider_message_probe_response_schema_supported');
  final providerProbeResponseRedacted = appleReadinessString(
      readiness, 'provider_message_probe_response_redacted');
  final providerProbeResponseJsonValid = appleReadinessString(
      readiness, 'provider_message_probe_response_json_valid');
  final providerProbeResponseTooLarge = appleReadinessString(
      readiness, 'provider_message_probe_response_too_large');
  final providerProbeResponseBytes =
      appleReadinessString(readiness, 'provider_message_probe_response_bytes');
  final providerProbeResponseMaxBytes = appleReadinessString(
      readiness, 'provider_message_probe_response_max_bytes');
  final providerStatusCurrent =
      appleReadinessString(readiness, 'provider_status_current');
  final providerReady = appleReadinessString(readiness, 'provider_ready');
  final providerStatusWriteLimited =
      appleReadinessString(readiness, 'provider_status_write_limited');
  final providerStatusWritePayloadTooLarge = appleReadinessString(
      readiness, 'provider_status_write_payload_too_large');
  final providerStatusWriteOriginalStage =
      appleReadinessString(readiness, 'provider_status_write_original_stage');
  final providerStatusContainerAvailable =
      appleReadinessString(readiness, 'provider_status_container_available');
  final providerStatusFilePresent =
      appleReadinessString(readiness, 'provider_status_file_present');
  final providerStatusFileReadable =
      appleReadinessString(readiness, 'provider_status_file_readable');
  final providerStatusFileSymbolicLink =
      appleReadinessString(readiness, 'provider_status_file_symbolic_link');
  final providerStatusJsonValid =
      appleReadinessString(readiness, 'provider_status_json_valid');
  final providerStatusFileTooLarge =
      appleReadinessString(readiness, 'provider_status_file_too_large');
  final providerStatusFileSize =
      appleReadinessString(readiness, 'provider_status_file_size_bytes');
  final providerStatusMaxFileSize =
      appleReadinessString(readiness, 'provider_status_max_file_size_bytes');
  final internetProbeAttempted =
      appleReadinessString(readiness, 'internet_probe_attempted');
  final internetProbeBlocked = appleReadinessString(
      readiness, 'internet_probe_blocked_by_provider_readiness');
  final internetProbeBlockedByLeakProtection = appleReadinessString(
      readiness, 'internet_probe_blocked_by_leak_protection_config');
  final internetProbeUrlKind =
      appleReadinessString(readiness, 'internet_probe_url_kind');
  final internetProbeStatusCode =
      appleReadinessString(readiness, 'status_code');
  final leakProtectionConfigChecked =
      appleReadinessString(readiness, 'leak_protection_config_checked');
  final leakProtectionConfigKind =
      appleReadinessString(readiness, 'leak_protection_config_kind');
  final leakProtectionProviderCurrent = appleReadinessString(
      readiness, 'leak_protection_provider_status_current');
  final leakProtectionDefaultRoute =
      appleReadinessString(readiness, 'leak_protection_default_route_enabled');
  final leakProtectionIpv6 =
      appleReadinessString(readiness, 'leak_protection_ipv6_enabled');
  final leakProtectionEngineIpv6 =
      appleReadinessString(readiness, 'leak_protection_engine_ipv6_enabled');
  final leakProtectionDnsFullTunnel = appleReadinessString(
      readiness, 'leak_protection_dns_full_tunnel_match_enabled');
  final leakProtectionEngineDnsFullTunnel = appleReadinessString(
      readiness, 'leak_protection_engine_dns_full_tunnel_match_enabled');
  final leakProtectionDnsCount =
      appleReadinessString(readiness, 'leak_protection_dns_server_count');
  final leakProtectionEngineDnsCount = appleReadinessString(
      readiness, 'leak_protection_engine_dns_server_count');
  final leakProtectionConfigPassed =
      appleReadinessString(readiness, 'leak_protection_config_passed');
  final nativeTunnelStatus = appleReadinessString(readiness, 'status');
  final managerInvalidAfterConfigSave =
      appleReadinessString(readiness, 'vpn_manager_invalid_after_config_save');
  final permissionPending =
      appleReadinessString(readiness, 'vpn_configuration_permission_pending');
  final stale = appleReadinessBool(readiness, 'provider_status_stale');
  final providerStatusGenerationInvalid =
      appleReadinessBool(readiness, 'provider_status_generation_invalid');
  final providerExpectedStatusGenerationInvalid = appleReadinessBool(
      readiness, 'provider_expected_status_generation_invalid');
  final bundleMismatch =
      appleReadinessBool(readiness, 'provider_status_bundle_mismatch');
  final extensionTypeMismatch =
      appleReadinessBool(readiness, 'provider_status_extension_type_mismatch');
  final timestampInvalid =
      appleReadinessBool(readiness, 'provider_status_timestamp_invalid');
  final stageInvalid =
      appleReadinessBool(readiness, 'provider_status_stage_invalid');
  final schemaUnsupported = appleTunnelProviderSchemaUnsupported(readiness);
  final parts = <String>[
    if (nativeError.isNotEmpty) 'native_error=$nativeError',
    if (stale) 'provider_status_stale=true',
    if (providerStatusGenerationInvalid)
      'provider_status_generation_invalid=true',
    if (providerExpectedStatusGenerationInvalid)
      'provider_expected_status_generation_invalid=true',
    if (bundleMismatch) 'provider_bundle_mismatch=true',
    if (extensionTypeMismatch) 'provider_extension_type_mismatch=true',
    if (timestampInvalid) 'provider_timestamp_invalid=true',
    if (stageInvalid) 'provider_stage_invalid=true',
    if (schemaUnsupported) 'provider_status_schema_unsupported=true',
    if (!stageInvalid &&
        appleReadinessString(readiness, 'provider_stage').isNotEmpty)
      'stage=${appleReadinessString(readiness, 'provider_stage')}',
    if (nativeTunnelStatus.isNotEmpty) 'native_status=$nativeTunnelStatus',
    if (managerInvalidAfterConfigSave.isNotEmpty)
      'manager_invalid_after_config_save=$managerInvalidAfterConfigSave',
    if (permissionPending.isNotEmpty)
      'vpn_permission_pending=$permissionPending',
    if (appleReadinessStatusGeneration(readiness, 'provider_status_generation')
        .isNotEmpty)
      'status_generation=${appleReadinessStatusGeneration(readiness, 'provider_status_generation')}',
    if (appleReadinessStatusGeneration(
            readiness, 'provider_expected_status_generation')
        .isNotEmpty)
      'expected_status_generation=${appleReadinessStatusGeneration(readiness, 'provider_expected_status_generation')}',
    if (appleReadinessString(readiness, 'provider_error_code').isNotEmpty)
      'code=${appleReadinessString(readiness, 'provider_error_code')}',
    if (appleReadinessString(readiness, 'provider_error').isNotEmpty)
      'provider_error=${appleReadinessString(readiness, 'provider_error')}',
    if (appleReadinessString(readiness, 'provider_engine_bundle_probe')
        .isNotEmpty)
      'engine_probe=${appleReadinessString(readiness, 'provider_engine_bundle_probe')}',
    if (appleReadinessString(readiness, 'provider_engine_transport_mode')
        .isNotEmpty)
      'transport=${appleReadinessString(readiness, 'provider_engine_transport_mode')}',
    if (components.isNotEmpty) 'required_components=${components.join('+')}',
    if (missingBundleComponents.isNotEmpty)
      'missing_bundle_components=${missingBundleComponents.join('+')}',
    if (availableBundleComponents.isNotEmpty)
      'available_bundle_components=${availableBundleComponents.join('+')}',
    if (bundleAllRequiredPresent.isNotEmpty)
      'bundle_components_ready=$bundleAllRequiredPresent',
    if (adapterAvailable.isNotEmpty)
      'engine_adapter_available=$adapterAvailable',
    if (runtimeContractFailed.isNotEmpty)
      'engine_runtime_contract_failed=$runtimeContractFailed',
    if (runtimePacketFlowAttached.isNotEmpty)
      'engine_runtime_packet_flow_attached=$runtimePacketFlowAttached',
    if (runtimeReadyReported.isNotEmpty)
      'engine_runtime_ready_reported=$runtimeReadyReported',
    if (runtimeRunningReported.isNotEmpty)
      'engine_runtime_running_reported=$runtimeRunningReported',
    if (runtimeAwgStarted.isNotEmpty)
      'engine_runtime_awg_started=$runtimeAwgStarted',
    if (runtimeXrayStarted.isNotEmpty)
      'engine_runtime_xray_started=$runtimeXrayStarted',
    if (runtimeSecretsRedacted.isNotEmpty)
      'engine_runtime_secrets_redacted=$runtimeSecretsRedacted',
    if (runtimeStatusSanitized.isNotEmpty)
      'engine_runtime_status_sanitized=$runtimeStatusSanitized',
    if (launchDescriptorReady.isNotEmpty)
      'engine_launch_descriptor_ready=$launchDescriptorReady',
    if (launchSecretsRedacted.isNotEmpty)
      'engine_launch_secrets_redacted=$launchSecretsRedacted',
    if (awgUapiConfigReady.isNotEmpty)
      'engine_awg_uapi_ready=$awgUapiConfigReady',
    if (awgUapiSecretsRedacted.isNotEmpty)
      'engine_awg_uapi_secrets_redacted=$awgUapiSecretsRedacted',
    if (interfacePrivateKeyRedacted.isNotEmpty)
      'engine_interface_key_redacted=$interfacePrivateKeyRedacted',
    if (peerPublicKeyRedacted.isNotEmpty)
      'engine_peer_key_redacted=$peerPublicKeyRedacted',
    if (launchContractVersion.isNotEmpty)
      'engine_contract=$launchContractVersion',
    if (packetFlowRequired.isNotEmpty)
      'engine_packet_flow_required=$packetFlowRequired',
    if (packetFlowAvailable.isNotEmpty)
      'engine_packet_flow_available=$packetFlowAvailable',
    if (engineXrayRequired.isNotEmpty)
      'engine_xray_required=$engineXrayRequired',
    if (awgObfuscationFieldCount.isNotEmpty)
      'engine_awg_fields=$awgObfuscationFieldCount',
    if (engineRouteCount.isNotEmpty) 'engine_routes=$engineRouteCount',
    if (engineDnsCount.isNotEmpty) 'engine_dns=$engineDnsCount',
    if (ipv6LeakProtection.isNotEmpty)
      'ipv6_leak_protection=$ipv6LeakProtection',
    if (engineIpv6LeakProtection.isNotEmpty)
      'engine_ipv6_leak_protection=$engineIpv6LeakProtection',
    if (transportEndpointKind.isNotEmpty)
      'transport_endpoint_kind=$transportEndpointKind',
    if (networkRemoteKind.isNotEmpty) 'network_remote_kind=$networkRemoteKind',
    if (networkRemoteSource.isNotEmpty)
      'network_remote_source=$networkRemoteSource',
    if (transportExclusionPresent.isNotEmpty)
      'transport_exclusion_present=$transportExclusionPresent',
    if (dnsFullTunnelMatch.isNotEmpty)
      'dns_full_tunnel_match=$dnsFullTunnelMatch',
    if (keyVerificationRequired.isNotEmpty)
      'client_key_verification_required=$keyVerificationRequired',
    if (expectedClientPublicKeySource.isNotEmpty)
      'expected_client_key_source=$expectedClientPublicKeySource',
    if (expectedClientPublicKeyValid.isNotEmpty)
      'expected_client_key_valid=$expectedClientPublicKeyValid',
    if (keyVerified.isNotEmpty) 'client_key_verified=$keyVerified',
    if (providerConfigSource.isNotEmpty)
      'provider_config_source=$providerConfigSource',
    if (providerConfigSourceAvailable.isNotEmpty)
      'provider_config_source_available=$providerConfigSourceAvailable',
    if (providerConfigFilePresent.isNotEmpty)
      'provider_config_file_present=$providerConfigFilePresent',
    if (providerConfigFileReadable.isNotEmpty)
      'provider_config_file_readable=$providerConfigFileReadable',
    if (providerConfigFileTooLarge.isNotEmpty)
      'provider_config_file_too_large=$providerConfigFileTooLarge',
    if (providerConfigTooLarge.isNotEmpty)
      'provider_config_too_large=$providerConfigTooLarge',
    if (providerConfigUtf8Valid.isNotEmpty)
      'provider_config_utf8_valid=$providerConfigUtf8Valid',
    if (providerConfigFileSymbolicLink.isNotEmpty)
      'provider_config_file_symbolic_link=$providerConfigFileSymbolicLink',
    if (providerConfigEmpty.isNotEmpty)
      'provider_config_empty=$providerConfigEmpty',
    if (providerConfigSize.isNotEmpty)
      'provider_config_size_bytes=$providerConfigSize',
    if (providerConfigMaxSize.isNotEmpty)
      'provider_config_max_size_bytes=$providerConfigMaxSize',
    if (providerConfigSharedPathPresent.isNotEmpty)
      'provider_config_shared_path_present=$providerConfigSharedPathPresent',
    if (providerConfigSharedPathAllowed.isNotEmpty)
      'provider_config_shared_path_allowed=$providerConfigSharedPathAllowed',
    if (providerConfigSharedPathMatchesExpected.isNotEmpty)
      'provider_config_shared_path_matches_expected=$providerConfigSharedPathMatchesExpected',
    if (providerConfigSharedPathInsideAppGroup.isNotEmpty)
      'provider_config_shared_path_inside_app_group=$providerConfigSharedPathInsideAppGroup',
    if (providerConfigAppGroupIdPresent.isNotEmpty)
      'provider_config_app_group_id_present=$providerConfigAppGroupIdPresent',
    if (providerConfigAppGroupIdAllowed.isNotEmpty)
      'provider_config_app_group_id_allowed=$providerConfigAppGroupIdAllowed',
    if (providerConfigAppGroupContainerAvailable.isNotEmpty)
      'provider_config_app_group_container_available=$providerConfigAppGroupContainerAvailable',
    if (providerSharedKeychainPrivateKeyAvailable.isNotEmpty)
      'provider_shared_keychain_private_key_available=$providerSharedKeychainPrivateKeyAvailable',
    if (lifecycleEvent.isNotEmpty) 'lifecycle=$lifecycleEvent',
    if (lifecycleSuspended.isNotEmpty)
      'lifecycle_suspended=$lifecycleSuspended',
    if (appMessageCommand.isNotEmpty) 'app_message=$appMessageCommand',
    if (appMessageCommandIsHealth.isNotEmpty)
      'app_message_is_health=$appMessageCommandIsHealth',
    if (appMessageAccepted.isNotEmpty)
      'app_message_accepted=$appMessageAccepted',
    if (appMessageRedacted.isNotEmpty)
      'app_message_redacted=$appMessageRedacted',
    if (engineWasRunningBeforeStop.isNotEmpty)
      'engine_was_running_before_stop=$engineWasRunningBeforeStop',
    if (previousStageBeforeStop.isNotEmpty)
      'previous_stage_before_stop=$previousStageBeforeStop',
    if (previousHealthyBeforeStop.isNotEmpty)
      'previous_healthy_before_stop=$previousHealthyBeforeStop',
    if (previousEngineReadyBeforeStop.isNotEmpty)
      'previous_engine_ready_before_stop=$previousEngineReadyBeforeStop',
    if (previousNetworkReadyBeforeStop.isNotEmpty)
      'previous_network_ready_before_stop=$previousNetworkReadyBeforeStop',
    if (previousNetworkAppliedBeforeStop.isNotEmpty)
      'previous_network_applied_before_stop=$previousNetworkAppliedBeforeStop',
    if (previousNetworkRemoteSourceBeforeStop.isNotEmpty)
      'previous_network_remote_source_before_stop=$previousNetworkRemoteSourceBeforeStop',
    if (previousRuntimeReadyBeforeStop.isNotEmpty)
      'previous_runtime_ready_before_stop=$previousRuntimeReadyBeforeStop',
    if (previousRuntimeRunningBeforeStop.isNotEmpty)
      'previous_runtime_running_before_stop=$previousRuntimeRunningBeforeStop',
    if (previousAppMessageCommandBeforeStop.isNotEmpty)
      'previous_app_message_before_stop=$previousAppMessageCommandBeforeStop',
    if (previousAppMessageCommandIsHealthBeforeStop.isNotEmpty)
      'previous_app_message_is_health_before_stop=$previousAppMessageCommandIsHealthBeforeStop',
    if (previousAppMessageAcceptedBeforeStop.isNotEmpty)
      'previous_app_message_accepted_before_stop=$previousAppMessageAcceptedBeforeStop',
    if (previousAppMessageRedactedBeforeStop.isNotEmpty)
      'previous_app_message_redacted_before_stop=$previousAppMessageRedactedBeforeStop',
    if (previousAppMessageEngineRunningBeforeStop.isNotEmpty)
      'previous_app_message_engine_running_before_stop=$previousAppMessageEngineRunningBeforeStop',
    if (providerProbeAttempted.isNotEmpty)
      'provider_message_probe_attempted=$providerProbeAttempted',
    if (providerProbeHealthy.isNotEmpty)
      'provider_message_probe_healthy=$providerProbeHealthy',
    if (providerProbeAccepted.isNotEmpty)
      'provider_message_probe_accepted=$providerProbeAccepted',
    if (providerProbeEngineRunning.isNotEmpty)
      'provider_message_probe_engine_running=$providerProbeEngineRunning',
    if (providerProbeCommand.isNotEmpty)
      'provider_message_probe_command=$providerProbeCommand',
    if (providerProbeCommandIsHealth.isNotEmpty)
      'provider_message_probe_command_is_health=$providerProbeCommandIsHealth',
    if (providerProbeTimeout.isNotEmpty)
      'provider_message_probe_timeout=$providerProbeTimeout',
    if (providerProbeResponseSchemaVersion.isNotEmpty)
      'provider_message_probe_schema=$providerProbeResponseSchemaVersion',
    if (providerProbeResponseSchemaSupported.isNotEmpty)
      'provider_message_probe_schema_supported=$providerProbeResponseSchemaSupported',
    if (providerProbeResponseRedacted.isNotEmpty)
      'provider_message_probe_redacted=$providerProbeResponseRedacted',
    if (providerProbeResponseJsonValid.isNotEmpty)
      'provider_message_probe_json_valid=$providerProbeResponseJsonValid',
    if (providerProbeResponseTooLarge.isNotEmpty)
      'provider_message_probe_too_large=$providerProbeResponseTooLarge',
    if (providerProbeResponseBytes.isNotEmpty)
      'provider_message_probe_bytes=$providerProbeResponseBytes',
    if (providerProbeResponseMaxBytes.isNotEmpty)
      'provider_message_probe_max_bytes=$providerProbeResponseMaxBytes',
    if (providerStatusCurrent.isNotEmpty)
      'provider_status_current=$providerStatusCurrent',
    if (providerReady.isNotEmpty) 'provider_ready=$providerReady',
    if (providerStatusWriteLimited.isNotEmpty)
      'provider_status_write_limited=$providerStatusWriteLimited',
    if (providerStatusWritePayloadTooLarge.isNotEmpty)
      'provider_status_write_payload_too_large=$providerStatusWritePayloadTooLarge',
    if (providerStatusWriteOriginalStage.isNotEmpty)
      'provider_status_write_original_stage=$providerStatusWriteOriginalStage',
    if (providerStatusContainerAvailable.isNotEmpty)
      'provider_status_container_available=$providerStatusContainerAvailable',
    if (providerStatusFilePresent.isNotEmpty)
      'provider_status_file_present=$providerStatusFilePresent',
    if (providerStatusFileReadable.isNotEmpty)
      'provider_status_file_readable=$providerStatusFileReadable',
    if (providerStatusFileSymbolicLink.isNotEmpty)
      'provider_status_file_symbolic_link=$providerStatusFileSymbolicLink',
    if (providerStatusJsonValid.isNotEmpty)
      'provider_status_json_valid=$providerStatusJsonValid',
    if (providerStatusFileTooLarge.isNotEmpty)
      'provider_status_file_too_large=$providerStatusFileTooLarge',
    if (providerStatusFileSize.isNotEmpty)
      'provider_status_file_size_bytes=$providerStatusFileSize',
    if (providerStatusMaxFileSize.isNotEmpty)
      'provider_status_max_file_size_bytes=$providerStatusMaxFileSize',
    if (leakProtectionConfigChecked.isNotEmpty)
      'leak_protection_config_checked=$leakProtectionConfigChecked',
    if (leakProtectionConfigKind.isNotEmpty)
      'leak_protection_config_kind=$leakProtectionConfigKind',
    if (leakProtectionProviderCurrent.isNotEmpty)
      'leak_protection_provider_current=$leakProtectionProviderCurrent',
    if (leakProtectionDefaultRoute.isNotEmpty)
      'leak_protection_default_route=$leakProtectionDefaultRoute',
    if (leakProtectionIpv6.isNotEmpty)
      'leak_protection_ipv6=$leakProtectionIpv6',
    if (leakProtectionEngineIpv6.isNotEmpty)
      'leak_protection_engine_ipv6=$leakProtectionEngineIpv6',
    if (leakProtectionDnsFullTunnel.isNotEmpty)
      'leak_protection_dns_full_tunnel_match=$leakProtectionDnsFullTunnel',
    if (leakProtectionEngineDnsFullTunnel.isNotEmpty)
      'leak_protection_engine_dns_full_tunnel_match=$leakProtectionEngineDnsFullTunnel',
    if (leakProtectionDnsCount.isNotEmpty)
      'leak_protection_dns_count=$leakProtectionDnsCount',
    if (leakProtectionEngineDnsCount.isNotEmpty)
      'leak_protection_engine_dns_count=$leakProtectionEngineDnsCount',
    if (leakProtectionConfigPassed.isNotEmpty)
      'leak_protection_config_passed=$leakProtectionConfigPassed',
    if (internetProbeAttempted.isNotEmpty)
      'internet_probe_attempted=$internetProbeAttempted',
    if (internetProbeBlocked.isNotEmpty)
      'internet_probe_blocked_by_provider_readiness=$internetProbeBlocked',
    if (internetProbeBlockedByLeakProtection.isNotEmpty)
      'internet_probe_blocked_by_leak_protection_config=$internetProbeBlockedByLeakProtection',
    if (internetProbeUrlKind.isNotEmpty)
      'internet_probe_url_kind=$internetProbeUrlKind',
    if (internetProbeStatusCode.isNotEmpty)
      'internet_probe_status_code=$internetProbeStatusCode',
  ];
  return parts.isEmpty
      ? 'no Apple provider status available'
      : parts.join('; ');
}
