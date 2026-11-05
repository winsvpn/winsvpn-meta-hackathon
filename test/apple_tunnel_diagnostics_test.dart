import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/apple_tunnel_diagnostics.dart';

void main() {
  test('engine missing status stays user-safe and debug-rich', () {
    final readiness = {
      'provider_stage': 'engine_missing',
      'provider_engine_bundle_probe': 'missing_native_engine_library',
      'provider_engine_transport_mode': 'xray_vless_ws_amneziawg',
      'provider_engine_required_components': [
        'amneziawg_packet_engine',
        'xray_vless_ws_transport',
      ],
      'provider_engine_bundle_missing_components': [
        'amneziawg_packet_engine',
        'xray_vless_ws_transport',
      ],
      'provider_engine_bundle_available_components': <String>[],
      'provider_engine_bundle_all_required_components_present': false,
      'provider_engine_launch_descriptor_ready': true,
      'provider_engine_launch_descriptor_secret_material_redacted': true,
      'provider_engine_awg_uapi_config_ready': true,
      'provider_engine_awg_uapi_secret_material_redacted': true,
      'provider_engine_interface_private_key_redacted': true,
      'provider_engine_peer_public_key_redacted': true,
      'provider_engine_awg_obfuscation_field_count': 11,
      'provider_engine_launch_contract_version': 1,
      'provider_engine_packet_flow_required': true,
      'provider_engine_packet_flow_available': true,
      'provider_engine_xray_transport_required': true,
      'provider_engine_allowed_ipv4_route_count': 1,
      'provider_engine_dns_server_count': 1,
      'provider_engine_ipv6_leak_protection_enabled': true,
      'provider_ipv6_leak_protection_enabled': true,
      'provider_error_code': 1003,
      'provider_error': 'native packet engine is not bundled',
      'provider_peer_endpoint': '203.0.113.10:9110',
      'provider_transport_endpoint_host': '203.0.113.10',
      'provider_network_settings_remote_address': '203.0.113.10',
      'provider_transport_ipv4_exclusion_route': '203.0.113.10/32',
      'provider_engine_xray_uuid': '00000000-0000-0000-0000-000000000000',
      'provider_transport_endpoint_kind': 'ipv4',
      'provider_network_settings_remote_address_kind': 'ipv4',
      'provider_transport_ipv4_exclusion_route_present': true,
      'provider_dns_full_tunnel_match_enabled': true,
    };

    expect(
      appleTunnelUserFailureStatus(readiness, null),
      'Apple VPN engine is not ready in this build yet.',
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('stage=engine_missing'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains(
          'required_components=amneziawg_packet_engine+xray_vless_ws_transport'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains(
          'missing_bundle_components=amneziawg_packet_engine+xray_vless_ws_transport'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('bundle_components_ready=false'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('engine_launch_descriptor_ready=true'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('engine_launch_secrets_redacted=true'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('engine_awg_uapi_ready=true'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('engine_awg_uapi_secrets_redacted=true'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('engine_interface_key_redacted=true'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('engine_peer_key_redacted=true'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('engine_contract=1'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('engine_packet_flow_required=true'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('engine_packet_flow_available=true'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('engine_xray_required=true'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('engine_awg_fields=11'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('engine_routes=1'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('engine_dns=1'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('ipv6_leak_protection=true'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('engine_ipv6_leak_protection=true'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('transport_exclusion_present=true'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('network_remote_kind=ipv4'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('transport_endpoint_kind=ipv4'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('dns_full_tunnel_match=true'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      isNot(contains('203.0.113.10')),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      isNot(contains('00000000-0000-0000-0000-000000000000')),
    );
  });

  test('adapter missing probe stays mapped to the safe engine message', () {
    final readiness = {
      'provider_status_available': true,
      'provider_stage': 'engine_missing',
      'provider_engine_bundle_probe': 'native_engine_adapter_missing',
      'provider_engine_bundle_available_components': [
        'amneziawg_packet_engine',
        'xray_vless_ws_transport',
      ],
      'provider_engine_bundle_missing_components': <String>[],
      'provider_engine_bundle_all_required_components_present': true,
      'provider_engine_adapter_available': false,
      'provider_engine_packet_flow_available': true,
    };

    expect(
      appleTunnelUserFailureStatus(readiness, null),
      'Apple VPN engine is not ready in this build yet.',
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains(
          'available_bundle_components=amneziawg_packet_engine+xray_vless_ws_transport'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('bundle_components_ready=true'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('engine_adapter_available=false'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('engine_packet_flow_available=true'),
    );
  });

  test('adapter start contract failures are distinct from missing engine', () {
    final readiness = {
      'provider_status_available': true,
      'provider_stage': 'engine_start_failed',
      'provider_engine_bundle_probe': 'native_engine_adapter_missing',
      'provider_engine_bundle_available_components': [
        'amneziawg_packet_engine',
        'xray_vless_ws_transport',
      ],
      'provider_engine_bundle_missing_components': <String>[],
      'provider_engine_bundle_all_required_components_present': true,
      'provider_engine_adapter_available': true,
      'provider_engine_packet_flow_available': true,
      'provider_engine_runtime_contract_failed': true,
      'provider_engine_runtime_packet_flow_attached': false,
      'provider_engine_runtime_engine_ready_reported': true,
      'provider_engine_runtime_engine_running_reported': true,
      'provider_engine_runtime_awg_started': false,
      'provider_engine_runtime_xray_started': true,
      'provider_engine_runtime_secret_material_redacted': true,
      'provider_engine_runtime_status_sanitized': true,
      'provider_error_code': 1004,
      'provider_error':
          "Win's VPN native packet engine did not report a running packet flow.",
    };

    expect(
      appleTunnelUserFailureStatus(readiness, null),
      'Apple VPN engine did not become ready.',
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('stage=engine_start_failed'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('engine_adapter_available=true'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('engine_packet_flow_available=true'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('engine_runtime_contract_failed=true'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('engine_runtime_packet_flow_attached=false'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('engine_runtime_ready_reported=true'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('engine_runtime_running_reported=true'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('engine_runtime_awg_started=false'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('engine_runtime_xray_started=true'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('engine_runtime_secrets_redacted=true'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('engine_runtime_status_sanitized=true'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('code=1004'),
    );
  });

  test('network settings failures map to Apple route status', () {
    final readiness = {
      'provider_status_available': true,
      'provider_stage': 'network_settings_failed',
      'provider_error': 'NEPacketTunnelNetworkSettings rejected routes',
    };

    expect(
      appleTunnelUserFailureStatus(readiness, null),
      'Apple rejected the VPN route settings for this build.',
    );
  });

  test('provider lifecycle and app-message diagnostics stay sanitized', () {
    final readiness = {
      'provider_status_available': true,
      'provider_stage': 'app_message',
      'provider_lifecycle_event': 'wake',
      'provider_lifecycle_suspended': false,
      'provider_app_message_command': 'health',
      'provider_app_message_command_is_health': true,
      'provider_app_message_accepted': true,
      'provider_app_message_raw_payload_redacted': true,
      'provider_engine_was_running_before_stop': true,
      'provider_previous_app_message_command_before_stop': 'health',
      'provider_previous_app_message_command_is_health_before_stop': true,
      'provider_previous_app_message_accepted_before_stop': true,
      'provider_previous_app_message_raw_payload_redacted_before_stop': true,
      'provider_previous_app_message_engine_running_before_stop': true,
      'provider_app_message_raw_payload': 'secret raw payload',
    };

    final summary = appleTunnelDebugFailureSummary(readiness, null);
    expect(summary, contains('stage=app_message'));
    expect(summary, contains('lifecycle=wake'));
    expect(summary, contains('lifecycle_suspended=false'));
    expect(summary, contains('app_message=health'));
    expect(summary, contains('app_message_is_health=true'));
    expect(summary, contains('app_message_accepted=true'));
    expect(summary, contains('app_message_redacted=true'));
    expect(summary, contains('engine_was_running_before_stop=true'));
    expect(summary, contains('previous_app_message_before_stop=health'));
    expect(
        summary, contains('previous_app_message_is_health_before_stop=true'));
    expect(summary, contains('previous_app_message_accepted_before_stop=true'));
    expect(summary, contains('previous_app_message_redacted_before_stop=true'));
    expect(
      summary,
      contains('previous_app_message_engine_running_before_stop=true'),
    );
    expect(summary, isNot(contains('secret raw payload')));
  });

  test('provider health message probe gates Apple readiness when attempted',
      () {
    final readiness = {
      'active': true,
      'status': 'connected',
      'provider_status_available': true,
      'provider_status_schema_supported': true,
      'provider_status_stale': false,
      'provider_engine_ready': true,
      'provider_network_settings_ready': true,
      'provider_healthy': true,
      'provider_message_probe_attempted': true,
      'provider_message_probe_healthy': false,
      'provider_message_probe_timeout': true,
      'provider_message_probe_response_redacted': true,
      'provider_message_probe_response_json_valid': false,
      'provider_message_probe_response_too_large': false,
      'provider_message_probe_response_bytes': 0,
      'provider_message_probe_response_max_bytes': 4096,
      'provider_message_probe_raw_payload': 'secret raw response',
    };

    expect(appleTunnelReady(readiness), isFalse);
    expect(
      appleTunnelUserFailureStatus(readiness, null),
      'Apple VPN provider did not respond to health check.',
    );

    final summary = appleTunnelDebugFailureSummary(readiness, null);
    expect(summary, contains('provider_message_probe_attempted=true'));
    expect(summary, contains('provider_message_probe_healthy=false'));
    expect(summary, contains('provider_message_probe_timeout=true'));
    expect(summary, contains('provider_message_probe_redacted=true'));
    expect(summary, contains('provider_message_probe_json_valid=false'));
    expect(summary, contains('provider_message_probe_too_large=false'));
    expect(summary, contains('provider_message_probe_bytes=0'));
    expect(summary, contains('provider_message_probe_max_bytes=4096'));
    expect(summary, isNot(contains('secret raw response')));

    expect(
      appleTunnelReady({
        ...readiness,
        'provider_message_probe_healthy': true,
        'provider_message_probe_timeout': false,
      }),
      isTrue,
    );
  });

  test('provider health probe contract failures stay not ready', () {
    final readiness = {
      'active': true,
      'status': 'connected',
      'provider_status_available': true,
      'provider_status_schema_supported': true,
      'provider_status_stale': false,
      'provider_engine_ready': true,
      'provider_network_settings_ready': true,
      'provider_healthy': true,
      'provider_message_probe_attempted': true,
      'provider_message_probe_accepted': false,
      'provider_message_probe_engine_running': true,
      'provider_message_probe_healthy': false,
      'provider_message_probe_response_schema_version': 1,
      'provider_message_probe_response_schema_supported': true,
      'provider_message_probe_response_redacted': true,
      'provider_message_probe_response_json_valid': true,
      'provider_message_probe_response_too_large': false,
      'provider_message_probe_command': 'readiness',
      'provider_message_probe_command_is_health': false,
      'provider_message_probe_raw_payload': 'secret raw response',
    };

    expect(appleTunnelReady(readiness), isFalse);
    expect(
      appleTunnelUserFailureStatus(readiness, null),
      'Apple VPN provider did not respond to health check.',
    );
    final summary = appleTunnelDebugFailureSummary(readiness, null);
    expect(summary, contains('provider_message_probe_attempted=true'));
    expect(summary, contains('provider_message_probe_healthy=false'));
    expect(summary, contains('provider_message_probe_accepted=false'));
    expect(summary, contains('provider_message_probe_engine_running=true'));
    expect(summary, contains('provider_message_probe_command=readiness'));
    expect(summary, contains('provider_message_probe_command_is_health=false'));
    expect(summary, contains('provider_message_probe_schema=1'));
    expect(summary, contains('provider_message_probe_schema_supported=true'));
    expect(summary, contains('provider_message_probe_redacted=true'));
    expect(summary, contains('provider_message_probe_json_valid=true'));
    expect(summary, isNot(contains('secret raw response')));
  });

  test('provider health probe oversized response stays sanitized', () {
    final readiness = {
      'active': true,
      'status': 'connected',
      'provider_status_available': true,
      'provider_status_schema_supported': true,
      'provider_status_stale': false,
      'provider_engine_ready': true,
      'provider_network_settings_ready': true,
      'provider_healthy': true,
      'provider_message_probe_attempted': true,
      'provider_message_probe_healthy': false,
      'provider_message_probe_timeout': false,
      'provider_message_probe_response_redacted': true,
      'provider_message_probe_response_json_valid': false,
      'provider_message_probe_response_too_large': true,
      'provider_message_probe_response_bytes': 5000,
      'provider_message_probe_response_max_bytes': 4096,
      'provider_message_probe_raw_payload':
          'PrivateKey = secret\nEndpoint = 203.0.113.10:9110',
    };

    expect(appleTunnelReady(readiness), isFalse);
    final summary = appleTunnelDebugFailureSummary(readiness, null);
    expect(summary, contains('provider_message_probe_attempted=true'));
    expect(summary, contains('provider_message_probe_healthy=false'));
    expect(summary, contains('provider_message_probe_redacted=true'));
    expect(summary, contains('provider_message_probe_json_valid=false'));
    expect(summary, contains('provider_message_probe_too_large=true'));
    expect(summary, contains('provider_message_probe_bytes=5000'));
    expect(summary, contains('provider_message_probe_max_bytes=4096'));
    expect(summary, isNot(contains('PrivateKey')));
    expect(summary, isNot(contains('Endpoint =')));
    expect(summary, isNot(contains('203.0.113.10')));
  });

  test('config validation failures map to refresh activation status', () {
    expect(
      appleTunnelUserFailureStatus(
        {
          'provider_status_available': true,
          'provider_stage': 'start_rejected',
          'provider_error_code': 1105,
        },
        null,
      ),
      'Apple VPN config validation failed. Refresh activation and try again.',
    );
    expect(
      appleTunnelUserFailureStatus(
        null,
        PlatformException(
          code: 'APPLE_TUNNEL_CONFIG_INVALID',
          message: 'Interface private key does not match Keychain key.',
        ),
      ),
      'Apple VPN config validation failed. Refresh activation and try again.',
    );
  });

  test('iOS permission pending state is explicit after config save', () {
    final readiness = {
      'platform': 'ios',
      'provider_status_available': true,
      'provider_status_schema_supported': true,
      'provider_status_current': true,
      'provider_stage': 'config_saved',
      'status': 'invalid',
      'vpn_manager_invalid_after_config_save': true,
      'vpn_configuration_permission_pending': true,
    };

    expect(
      appleTunnelNeedsVpnConfigurationPermission(readiness),
      isTrue,
    );
    expect(
      appleTunnelUserFailureStatus(readiness, null),
      "Approve the iOS VPN configuration permission for Win's VPN on this iPhone, then try again.",
    );
    final summary = appleTunnelDebugFailureSummary(readiness, null);
    expect(summary, contains('stage=config_saved'));
    expect(summary, contains('native_status=invalid'));
    expect(summary, contains('manager_invalid_after_config_save=true'));
    expect(summary, contains('vpn_permission_pending=true'));
  });

  test('explicit iOS VPN permission flag works without platform metadata', () {
    final readiness = {
      'provider_status_available': true,
      'provider_status_schema_supported': true,
      'provider_stage': 'config_saved',
      'status': 'invalid',
      'vpn_configuration_permission_pending': true,
    };

    expect(
      appleTunnelNeedsVpnConfigurationPermission(readiness),
      isTrue,
    );
    expect(
      appleTunnelUserFailureStatus(readiness, null),
      "Approve the iOS VPN configuration permission for Win's VPN on this iPhone, then try again.",
    );
  });

  test('macOS invalid saved manager is not classified as iOS permission', () {
    final readiness = {
      'platform': 'macos',
      'provider_status_available': true,
      'provider_status_schema_supported': true,
      'provider_status_current': true,
      'provider_stage': 'config_saved',
      'status': 'invalid',
    };

    expect(
      appleTunnelNeedsVpnConfigurationPermission(readiness),
      isFalse,
    );
  });

  test('macOS save permission denial requests one-time VPN approval', () {
    final readiness = {
      'platform': 'macos',
      'provider_status_available': true,
      'provider_status_schema_supported': true,
      'provider_status_current': true,
      'provider_stage': 'config_saved',
      'status': 'invalid',
    };
    final error = PlatformException(
      code: 'APPLE_TUNNEL_SAVE_FAILED',
      message: 'Could not save VPN configuration: permission denied',
      details: const {
        'native_error_domain': 'NEVPNErrorDomain',
        'native_error_code': '5',
      },
    );

    expect(
      appleTunnelNeedsVpnConfigurationPermission(readiness, error),
      isTrue,
    );
    expect(
      appleTunnelUserFailureStatus(readiness, error),
      "Approve the macOS VPN configuration permission for Win's VPN, then try again.",
    );
  });

  test('unrelated macOS save failure is not treated as user permission', () {
    final readiness = {
      'platform': 'macos',
      'provider_stage': 'config_saved',
      'status': 'invalid',
    };
    final error = PlatformException(
      code: 'APPLE_TUNNEL_SAVE_FAILED',
      message: 'Could not save VPN configuration.',
      details: const {
        'native_error_domain': 'NEVPNErrorDomain',
        'native_error_code': '3',
      },
    );

    expect(
      appleTunnelNeedsVpnConfigurationPermission(readiness, error),
      isFalse,
    );
  });

  test('macOS first-use save timeout requests one-time VPN approval', () {
    final readiness = {
      'platform': 'macos',
      'provider_status_available': true,
      'provider_status_schema_supported': true,
      'provider_status_current': true,
      'provider_stage': 'config_saved',
      'status': 'invalid',
    };

    expect(
      appleTunnelNeedsVpnConfigurationPermission(
        readiness,
        TimeoutException('Future not completed'),
      ),
      isTrue,
    );
    expect(
      appleTunnelUserFailureStatus(
        readiness,
        TimeoutException('Future not completed'),
      ),
      "Approve the macOS VPN configuration permission for Win's VPN, then try again.",
    );
  });

  test(
      'generic invalid manager without platform is not classified as iOS permission',
      () {
    final readiness = {
      'provider_status_available': true,
      'provider_status_schema_supported': true,
      'provider_stage': 'config_saved',
      'status': 'invalid',
      'vpn_manager_invalid_after_config_save': true,
    };

    expect(
      appleTunnelNeedsVpnConfigurationPermission(readiness),
      isFalse,
    );
    expect(
      appleTunnelUserFailureStatus(readiness, null),
      'Apple VPN could not start on this build.',
    );
  });

  test('client key verification failures stay visible in diagnostics', () {
    final readiness = {
      'provider_status_available': true,
      'provider_stage': 'start_rejected',
      'provider_error_code': 1105,
      'provider_client_key_pair_verification_required': true,
      'provider_expected_client_public_key_source': 'saved_tunnel_preference',
      'provider_expected_client_public_key_valid': false,
      'provider_client_key_pair_verified': false,
    };

    expect(
      appleTunnelUserFailureStatus(readiness, null),
      'Apple VPN client key is invalid. Refresh activation and try again.',
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('client_key_verification_required=true'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('expected_client_key_source=saved_tunnel_preference'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('expected_client_key_valid=false'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('client_key_verified=false'),
    );
  });

  test('missing provider status is distinct from generic startup failure', () {
    expect(
      appleTunnelUserFailureStatus(null, null),
      'Apple VPN provider did not return readiness yet.',
    );
    expect(
      appleTunnelUserFailureStatus(
        {'provider_status_available': true, 'provider_stage': 'connecting'},
        null,
      ),
      'Apple VPN could not start on this build.',
    );
  });

  test('provider status file diagnostics explain unreadable App Group state',
      () {
    final oversized = {
      'provider_status_available': false,
      'provider_status_file_present': true,
      'provider_status_file_too_large': true,
      'provider_status_file_size_bytes': 70000,
      'provider_status_max_file_size_bytes': 65536,
      'raw_path':
          '/Users/winsvpn/Library/Group Containers/group.org.winsvpn.app/Tunnel/latest_status.json',
    };

    expect(
      appleTunnelUserFailureStatus(oversized, null),
      'Apple VPN provider readiness file is too large.',
    );
    final oversizedSummary = appleTunnelDebugFailureSummary(oversized, null);
    expect(
      oversizedSummary,
      contains('provider_status_file_too_large=true'),
    );
    expect(
      oversizedSummary,
      contains('provider_status_file_size_bytes=70000'),
    );
    expect(
      oversizedSummary,
      contains('provider_status_max_file_size_bytes=65536'),
    );
    expect(oversizedSummary, isNot(contains('/Users/')));

    final appGroupUnavailable = {
      'provider_status_available': false,
      'provider_status_container_available': false,
    };
    expect(
      appleTunnelUserFailureStatus(appGroupUnavailable, null),
      'Apple VPN App Group is unavailable.',
    );

    final symlinkStatus = {
      'provider_status_available': false,
      'provider_status_container_available': true,
      'provider_status_file_present': true,
      'provider_status_file_symbolic_link': true,
      'provider_status_file_readable': false,
      'raw_path':
          '/Users/winsvpn/Library/Group Containers/group.org.winsvpn.app/Tunnel/latest_status.json',
    };
    expect(
      appleTunnelUserFailureStatus(symlinkStatus, null),
      'Apple VPN provider readiness file is not a regular file.',
    );
    final symlinkStatusSummary =
        appleTunnelDebugFailureSummary(symlinkStatus, null);
    expect(
      symlinkStatusSummary,
      contains('provider_status_file_symbolic_link=true'),
    );
    expect(symlinkStatusSummary, isNot(contains('/Users/')));
    expect(symlinkStatusSummary, isNot(contains('latest_status.json')));

    final unreadable = {
      'provider_status_available': false,
      'provider_status_container_available': true,
      'provider_status_file_present': true,
      'provider_status_file_readable': false,
    };
    expect(
      appleTunnelUserFailureStatus(unreadable, null),
      'Apple VPN provider readiness file could not be read.',
    );

    final invalidJson = {
      'provider_status_available': false,
      'provider_status_container_available': true,
      'provider_status_file_present': true,
      'provider_status_file_readable': true,
      'provider_status_json_valid': false,
    };
    expect(
      appleTunnelUserFailureStatus(invalidJson, null),
      'Apple VPN provider returned unreadable readiness.',
    );
    expect(
      appleTunnelDebugFailureSummary(invalidJson, null),
      contains('provider_status_json_valid=false'),
    );
  });

  test('provider status write limiting stays safe and visible', () {
    final readiness = {
      'provider_status_available': true,
      'provider_status_write_limited': true,
      'provider_status_write_payload_too_large': true,
      'provider_status_write_original_stage': 'app_message',
      'provider_status_generation': 'limited-generation',
      'provider_stage': 'app_message',
      'raw_payload': 'secret raw payload',
    };

    expect(
      appleTunnelUserFailureStatus(readiness, null),
      'Apple VPN provider readiness was reduced safely.',
    );
    final summary = appleTunnelDebugFailureSummary(readiness, null);
    expect(summary, contains('provider_status_write_limited=true'));
    expect(
      summary,
      contains('provider_status_write_payload_too_large=true'),
    );
    expect(
      summary,
      contains('provider_status_write_original_stage=app_message'),
    );
    expect(summary, contains('status_generation=limited-generation'));
    expect(summary, isNot(contains('secret raw payload')));
  });

  test('provider config handoff diagnostics stay user-safe', () {
    final oversized = {
      'provider_status_available': false,
      'provider_stage': 'start_rejected',
      'provider_error_code': 1005,
      'provider_config_source': 'shared_config_path',
      'provider_config_file_present': true,
      'provider_config_file_too_large': true,
      'provider_config_size_bytes': 300000,
      'provider_config_max_size_bytes': 262144,
      'raw_path':
          '/Users/winsvpn/Library/Group Containers/group.org.winsvpn.app/Tunnel/latest_tunnel.conf',
    };

    expect(
      appleTunnelUserFailureStatus(oversized, null),
      'Apple VPN provider config file is too large.',
    );
    final oversizedSummary = appleTunnelDebugFailureSummary(oversized, null);
    expect(
      oversizedSummary,
      contains('provider_config_source=shared_config_path'),
    );
    expect(
      oversizedSummary,
      contains('provider_config_file_too_large=true'),
    );
    expect(
      oversizedSummary,
      contains('provider_config_size_bytes=300000'),
    );
    expect(
      oversizedSummary,
      contains('provider_config_max_size_bytes=262144'),
    );
    expect(oversizedSummary, isNot(contains('/Users/')));
    expect(oversizedSummary, isNot(contains('latest_tunnel.conf')));

    final appGroupUnavailable = {
      'provider_status_available': false,
      'provider_stage': 'start_rejected',
      'provider_config_source': 'app_group_fallback',
      'provider_config_app_group_id_present': true,
      'provider_config_app_group_id_allowed': true,
      'provider_config_app_group_container_available': false,
    };
    expect(
      appleTunnelUserFailureStatus(appGroupUnavailable, null),
      'Apple VPN provider cannot access the App Group config.',
    );
    final appGroupUnavailableSummary =
        appleTunnelDebugFailureSummary(appGroupUnavailable, null);
    expect(
      appGroupUnavailableSummary,
      contains('provider_config_app_group_id_present=true'),
    );
    expect(
      appGroupUnavailableSummary,
      contains('provider_config_app_group_id_allowed=true'),
    );
    expect(
      appGroupUnavailableSummary,
      contains('provider_config_app_group_container_available=false'),
    );

    final appGroupRejected = {
      'provider_status_available': false,
      'provider_stage': 'start_rejected',
      'provider_config_source': 'app_group_fallback',
      'provider_config_app_group_id_present': true,
      'provider_config_app_group_id_allowed': false,
      'provider_config_app_group_container_available': false,
      'raw_app_group_id': 'group.com.example.secret',
    };
    expect(
      appleTunnelUserFailureStatus(appGroupRejected, null),
      'Apple VPN provider rejected the App Group identifier.',
    );
    final appGroupRejectedSummary =
        appleTunnelDebugFailureSummary(appGroupRejected, null);
    expect(
      appGroupRejectedSummary,
      contains('provider_config_app_group_id_allowed=false'),
    );
    expect(appGroupRejectedSummary, isNot(contains('group.com.example')));

    final transientAppGroupRejected = {
      'provider_status_available': false,
      'provider_stage': 'start_rejected',
      'provider_config_source': 'transient_start_options',
      'provider_config_app_group_id_present': true,
      'provider_config_app_group_id_allowed': false,
      'provider_config_app_group_container_available': false,
      'provider_config_size_bytes': 4096,
      'raw_app_group_id': 'group.com.example.transient',
    };
    expect(
      appleTunnelUserFailureStatus(transientAppGroupRejected, null),
      'Apple VPN provider rejected the App Group identifier.',
    );
    final transientAppGroupRejectedSummary =
        appleTunnelDebugFailureSummary(transientAppGroupRejected, null);
    expect(
      transientAppGroupRejectedSummary,
      contains('provider_config_source=transient_start_options'),
    );
    expect(
      transientAppGroupRejectedSummary,
      contains('provider_config_app_group_id_allowed=false'),
    );
    expect(
      transientAppGroupRejectedSummary,
      isNot(contains('group.com.example')),
    );

    final handoffPathRejected = {
      'provider_status_available': false,
      'provider_stage': 'start_rejected',
      'provider_config_source': 'shared_config_path',
      'provider_config_shared_path_present': true,
      'provider_config_shared_path_allowed': false,
      'provider_config_shared_path_matches_expected': false,
      'provider_config_shared_path_inside_app_group': false,
      'raw_path': '/Users/winsvpn/.ssh/id_rsa',
    };
    expect(
      appleTunnelUserFailureStatus(handoffPathRejected, null),
      'Apple VPN provider rejected the App Group config handoff path.',
    );
    final handoffPathSummary =
        appleTunnelDebugFailureSummary(handoffPathRejected, null);
    expect(
      handoffPathSummary,
      contains('provider_config_shared_path_present=true'),
    );
    expect(
      handoffPathSummary,
      contains('provider_config_shared_path_allowed=false'),
    );
    expect(
      handoffPathSummary,
      contains('provider_config_shared_path_matches_expected=false'),
    );
    expect(
      handoffPathSummary,
      contains('provider_config_shared_path_inside_app_group=false'),
    );
    expect(handoffPathSummary, isNot(contains('/Users/')));
    expect(handoffPathSummary, isNot(contains('id_rsa')));

    final symlinkConfig = {
      'provider_status_available': false,
      'provider_stage': 'start_rejected',
      'provider_config_source': 'shared_config_path',
      'provider_config_file_present': true,
      'provider_config_file_symbolic_link': true,
      'provider_config_file_readable': false,
      'raw_path':
          '/Users/winsvpn/Library/Group Containers/group.org.winsvpn.app/Tunnel/latest_tunnel.conf',
    };
    expect(
      appleTunnelUserFailureStatus(symlinkConfig, null),
      'Apple VPN provider config handoff file is not a regular file.',
    );
    final symlinkConfigSummary =
        appleTunnelDebugFailureSummary(symlinkConfig, null);
    expect(
      symlinkConfigSummary,
      contains('provider_config_file_symbolic_link=true'),
    );
    expect(symlinkConfigSummary, isNot(contains('/Users/')));
    expect(symlinkConfigSummary, isNot(contains('latest_tunnel.conf')));

    final unreadable = {
      'provider_status_available': false,
      'provider_stage': 'start_rejected',
      'provider_config_file_present': true,
      'provider_config_file_readable': false,
    };
    expect(
      appleTunnelUserFailureStatus(unreadable, null),
      'Apple VPN provider config file could not be read.',
    );

    final invalidUtf8 = {
      'provider_status_available': false,
      'provider_stage': 'start_rejected',
      'provider_config_file_present': true,
      'provider_config_file_readable': true,
      'provider_config_utf8_valid': false,
    };
    expect(
      appleTunnelUserFailureStatus(invalidUtf8, null),
      'Apple VPN provider config file is unreadable.',
    );

    final sharedKeychainUnavailable = {
      'provider_status_available': false,
      'provider_stage': 'start_rejected',
      'provider_config_source': 'app_group_fallback',
      'provider_private_key_source': 'shared_keychain',
      'provider_shared_config_private_key_redacted': true,
      'provider_shared_keychain_private_key_available': false,
    };
    expect(
      appleTunnelUserFailureStatus(sharedKeychainUnavailable, null),
      'Apple VPN provider could not access the shared Keychain key.',
    );
    expect(
      appleTunnelDebugFailureSummary(sharedKeychainUnavailable, null),
      contains('provider_shared_keychain_private_key_available=false'),
    );

    final missingConfig = {
      'provider_status_available': false,
      'provider_stage': 'start_rejected',
      'provider_error_code': 1001,
      'provider_config_source_available': false,
    };
    expect(
      appleTunnelUserFailureStatus(missingConfig, null),
      'Apple VPN provider did not receive tunnel config. Refresh activation and try again.',
    );
  });

  test('stale provider status waits for current readiness', () {
    final readiness = {
      'provider_status_available': false,
      'provider_status_stale': true,
      'provider_status_generation': 'old-generation',
      'provider_expected_status_generation': 'current-generation',
    };

    expect(
      appleTunnelUserFailureStatus(readiness, null),
      'Apple VPN provider did not return current readiness yet.',
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('provider_status_stale=true'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('expected_status_generation=current-generation'),
    );
  });

  test('stale provider status generation diagnostics stay sanitized', () {
    final readiness = {
      'provider_status_available': false,
      'provider_status_stale': true,
      'provider_status_generation_invalid': true,
      'provider_expected_status_generation_invalid': true,
      'provider_status_generation':
          '/Users/winsvpn/Library/Group Containers/group.org.winsvpn.shared/Tunnel/latest_status.json',
      'provider_expected_status_generation': 'Endpoint = 203.0.113.10:9110',
    };

    expect(
      appleTunnelUserFailureStatus(readiness, null),
      'Apple VPN provider did not return current readiness yet.',
    );
    final summary = appleTunnelDebugFailureSummary(readiness, null);
    expect(summary, contains('provider_status_stale=true'));
    expect(summary, contains('provider_status_generation_invalid=true'));
    expect(
      summary,
      contains('provider_expected_status_generation_invalid=true'),
    );
    expect(summary, isNot(contains('latest_status.json')));
    expect(summary, isNot(contains('/Users/')));
    expect(summary, isNot(contains('Endpoint =')));
    expect(summary, isNot(contains('203.0.113.10')));
  });

  test('unsupported provider status schema is not current readiness', () {
    final readiness = {
      'active': true,
      'status': 'connected',
      'provider_status_available': false,
      'provider_status_schema_supported': false,
      'provider_status_schema_version': 99,
      'provider_engine_ready': true,
      'provider_network_settings_ready': true,
      'provider_healthy': true,
    };

    expect(appleTunnelProviderSchemaUnsupported(readiness), isTrue);
    expect(appleTunnelReady(readiness), isFalse);
    expect(
      appleTunnelUserFailureStatus(readiness, null),
      'Apple VPN provider returned an unsupported readiness format.',
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('provider_status_schema_unsupported=true'),
    );

    final missingSchemaProof = {
      ...readiness,
      'provider_status_available': true,
    }..remove('provider_status_schema_supported');
    expect(appleTunnelProviderSchemaSupported(missingSchemaProof), isFalse);
    expect(appleTunnelProviderSchemaUnsupported(missingSchemaProof), isFalse);
    expect(appleTunnelProviderStatusCurrent(missingSchemaProof), isFalse);
    expect(appleTunnelReady(missingSchemaProof), isFalse);
    expect(
      appleTunnelUserFailureStatus(missingSchemaProof, null),
      'Apple VPN could not start on this build.',
    );
  });

  test('provider bundle mismatches are not current readiness', () {
    final readiness = {
      'active': true,
      'status': 'connected',
      'provider_status_available': false,
      'provider_status_bundle_mismatch': true,
      'provider_expected_bundle_id': 'org.winsvpn.app.PacketTunnel',
      'provider_reported_bundle_id': 'com.example.wrong.PacketTunnel',
      'provider_engine_ready': true,
      'provider_network_settings_ready': true,
      'provider_healthy': true,
    };

    expect(appleTunnelProviderStatusCurrent(readiness), isFalse);
    expect(appleTunnelReady(readiness), isFalse);
    expect(
      appleTunnelUserFailureStatus(readiness, null),
      'Apple VPN provider readiness came from the wrong extension.',
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('provider_bundle_mismatch=true'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      isNot(contains('com.example.wrong.PacketTunnel')),
    );
  });

  test('provider extension type mismatches are not current readiness', () {
    final readiness = {
      'active': true,
      'status': 'connected',
      'provider_status_available': false,
      'provider_status_extension_type_mismatch': true,
      'provider_expected_network_extension_type': 'packet_tunnel',
      'provider_network_extension_type': 'app_proxy',
      'provider_engine_ready': true,
      'provider_network_settings_ready': true,
      'provider_healthy': true,
    };

    expect(appleTunnelProviderStatusCurrent(readiness), isFalse);
    expect(appleTunnelReady(readiness), isFalse);
    expect(
      appleTunnelUserFailureStatus(readiness, null),
      'Apple VPN provider readiness came from the wrong Network Extension type.',
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('provider_extension_type_mismatch=true'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      isNot(contains('app_proxy')),
    );
  });

  test('invalid provider status timestamps are not current readiness', () {
    final readiness = {
      'active': true,
      'status': 'connected',
      'provider_status_available': false,
      'provider_status_timestamp_invalid': true,
      'provider_status_updated_at_present': true,
      'provider_updated_at': 'not-a-timestamp',
      'provider_engine_ready': true,
      'provider_network_settings_ready': true,
      'provider_healthy': true,
    };

    expect(appleTunnelProviderStatusCurrent(readiness), isFalse);
    expect(appleTunnelReady(readiness), isFalse);
    expect(
      appleTunnelUserFailureStatus(readiness, null),
      'Apple VPN provider returned an invalid readiness timestamp.',
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('provider_timestamp_invalid=true'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      isNot(contains('not-a-timestamp')),
    );
  });

  test('unknown provider status stages are not current readiness', () {
    final readiness = {
      'active': true,
      'status': 'connected',
      'provider_status_available': false,
      'provider_status_stage_invalid': true,
      'provider_status_stage_present': true,
      'provider_stage': 'secret-stage',
      'provider_engine_ready': true,
      'provider_network_settings_ready': true,
      'provider_healthy': true,
    };

    expect(appleTunnelProviderStatusCurrent(readiness), isFalse);
    expect(appleTunnelReady(readiness), isFalse);
    expect(
      appleTunnelUserFailureStatus(readiness, null),
      'Apple VPN provider returned an unknown readiness stage.',
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      contains('provider_stage_invalid=true'),
    );
    expect(
      appleTunnelDebugFailureSummary(readiness, null),
      isNot(contains('secret-stage')),
    );
  });

  test('apple tunnel ready requires current provider health', () {
    final currentProviderReady = {
      'active': true,
      'status': 'connected',
      'provider_status_available': true,
      'provider_status_schema_supported': true,
      'provider_status_stale': false,
      'provider_engine_ready': true,
      'provider_network_settings_ready': true,
      'provider_healthy': true,
    };

    expect(appleTunnelReady(currentProviderReady), isTrue);

    final hostOnlyConnected = {
      'active': true,
      'status': 'connected',
      'engine_ready': true,
      'tunnel_healthy': true,
      'provider_status_available': false,
    };
    expect(appleTunnelReady(hostOnlyConnected), isFalse);

    final staleProviderReady = {
      ...currentProviderReady,
      'provider_status_stale': true,
    };
    expect(appleTunnelReady(staleProviderReady), isFalse);

    final providerMissingEngine = {
      ...currentProviderReady,
      'provider_engine_ready': false,
    };
    expect(appleTunnelReady(providerMissingEngine), isFalse);

    final currentProviderReadyFromProbe = {
      ...currentProviderReady,
      'provider_stage': 'app_message',
      'provider_engine_ready': false,
      'provider_network_settings_ready': false,
      'provider_healthy': false,
      'provider_message_probe_attempted': true,
      'provider_message_probe_healthy': true,
      'provider_message_probe_engine_running': true,
    };
    expect(appleTunnelProviderAppMessageTrusted(currentProviderReadyFromProbe),
        isTrue);
    expect(appleTunnelReady(currentProviderReadyFromProbe), isTrue);

    final currentProviderProbeWithoutEngine = {
      ...currentProviderReadyFromProbe,
      'provider_message_probe_engine_running': false,
    };
    expect(appleTunnelReady(currentProviderProbeWithoutEngine), isFalse);

    final acceptedAppMessage = {
      ...currentProviderReady,
      'provider_stage': 'app_message',
      'provider_app_message_accepted': true,
      'provider_app_message_command_is_health': true,
      'provider_app_message_raw_payload_redacted': true,
    };
    expect(appleTunnelProviderAppMessageTrusted(acceptedAppMessage), isTrue);
    expect(appleTunnelReady(acceptedAppMessage), isTrue);

    final rejectedAppMessage = {
      ...acceptedAppMessage,
      'provider_app_message_accepted': false,
    };
    expect(appleTunnelProviderAppMessageTrusted(rejectedAppMessage), isFalse);
    expect(appleTunnelReady(rejectedAppMessage), isFalse);
    expect(
      appleTunnelUserFailureStatus(rejectedAppMessage, null),
      'Apple VPN provider did not accept health check.',
    );

    final wrongCommandAppMessage = {
      ...acceptedAppMessage,
      'provider_app_message_command_is_health': false,
    };
    expect(
        appleTunnelProviderAppMessageTrusted(wrongCommandAppMessage), isFalse);
    expect(appleTunnelReady(wrongCommandAppMessage), isFalse);

    final unredactedAppMessage = {
      ...acceptedAppMessage,
      'provider_app_message_raw_payload_redacted': false,
    };
    expect(appleTunnelProviderAppMessageTrusted(unredactedAppMessage), isFalse);
    expect(appleTunnelReady(unredactedAppMessage), isFalse);

    final sleepingLifecycle = {
      ...currentProviderReady,
      'provider_stage': 'sleeping',
      'provider_lifecycle_event': 'sleep',
      'provider_lifecycle_suspended': true,
    };
    expect(appleTunnelProviderLifecycleTrusted(sleepingLifecycle), isFalse);
    expect(appleTunnelReady(sleepingLifecycle), isFalse);
    expect(
      appleTunnelUserFailureStatus(sleepingLifecycle, null),
      'Apple VPN provider is suspended.',
    );

    final wokeLifecycle = {
      ...currentProviderReady,
      'provider_stage': 'woke',
      'provider_lifecycle_event': 'wake',
      'provider_lifecycle_suspended': false,
    };
    expect(appleTunnelProviderLifecycleTrusted(wokeLifecycle), isTrue);
    expect(appleTunnelReady(wokeLifecycle), isTrue);
  });

  test('readiness coercion handles native bridge value types', () {
    final readiness = {
      'active': 'true',
      'provider_network_settings_applied': true,
      'provider_engine_required_components': [
        ' amneziawg_packet_engine ',
        '',
        'xray_vless_ws_transport',
      ],
    };

    expect(appleReadinessBool(readiness, 'active'), isTrue);
    expect(
      appleReadinessStringList(
        readiness,
        'provider_engine_required_components',
      ),
      ['amneziawg_packet_engine', 'xray_vless_ws_transport'],
    );
    expect(nativeTunnelErrorSummary(null), '');
  });

  test('diagnostic scalar and list values fail closed when unsafe', () {
    final readiness = {
      'provider_stage': 'engine_missing',
      'provider_error': 'PrivateKey = secret\nEndpoint = 203.0.113.10:9110',
      'provider_config_source':
          '/Users/winsvpn/Library/Group Containers/group.org.winsvpn.shared/Tunnel/latest_tunnel.conf',
      'provider_engine_bundle_probe': 'api.winsvpn.org',
      'provider_engine_transport_mode':
          'xray_vless_ws_amneziawg fd48:6989:709::1',
      'provider_engine_required_components': [
        'amneziawg_packet_engine',
        '/Users/winsvpn/.ssh/id_rsa',
        'Endpoint = 203.0.113.10:9110',
        '2001:db8:1:2::9',
        'stream.winsvpn.org',
        '00000000-0000-0000-0000-000000000000',
        'xray_vless_ws_transport',
        List.filled(120, 'a').join(),
      ],
      'provider_engine_bundle_available_components':
          'https://www.winsvpn.org/internal',
      'provider_engine_bundle_missing_components': [
        for (var i = 0; i < 20; i += 1) 'component_$i',
      ],
    };

    expect(appleReadinessString(readiness, 'provider_error'), '');
    expect(appleReadinessString(readiness, 'provider_config_source'), '');
    expect(appleReadinessString(readiness, 'provider_engine_bundle_probe'), '');
    expect(
      appleReadinessString(readiness, 'provider_engine_transport_mode'),
      '',
    );
    expect(
      appleReadinessString(
        {'provider_error': 'transport endpoint fd48:6989:709::1'},
        'provider_error',
      ),
      '',
    );
    expect(
      appleReadinessString(
        {'provider_error': 'timestamp 00:00:00 remains a non-address token'},
        'provider_error',
      ),
      'timestamp 00:00:00 remains a non-address token',
    );
    expect(
      appleReadinessStringList(
        readiness,
        'provider_engine_required_components',
      ),
      ['amneziawg_packet_engine', 'xray_vless_ws_transport'],
    );
    expect(
      appleReadinessStringList(
        readiness,
        'provider_engine_bundle_available_components',
      ),
      isEmpty,
    );
    expect(
      appleReadinessStringList(
        readiness,
        'provider_engine_bundle_missing_components',
      ).length,
      16,
    );

    final summary = appleTunnelDebugFailureSummary(readiness, null);
    expect(
      summary,
      contains(
          'required_components=amneziawg_packet_engine+xray_vless_ws_transport'),
    );
    expect(summary, contains('missing_bundle_components=component_0'));
    expect(summary, isNot(contains('PrivateKey')));
    expect(summary, isNot(contains('Endpoint =')));
    expect(summary, isNot(contains('203.0.113.10')));
    expect(summary, isNot(contains('fd48:6989:709::1')));
    expect(summary, isNot(contains('2001:db8:1:2::9')));
    expect(summary, isNot(contains('/Users/')));
    expect(summary, isNot(contains('https://www.winsvpn.org')));
    expect(summary, isNot(contains('api.winsvpn.org')));
    expect(summary, isNot(contains('stream.winsvpn.org')));
    expect(summary, isNot(contains('00000000-0000-0000-0000-000000000000')));
    expect(summary, isNot(contains('component_16')));
  });

  test('internet probe diagnostics stay provider-gated and sanitized', () {
    final readiness = {
      'active': true,
      'status': 'connected',
      'provider_status_available': true,
      'provider_status_current': true,
      'provider_ready': false,
      'provider_engine_ready': true,
      'provider_network_settings_applied': true,
      'provider_healthy': false,
      'provider_message_probe_attempted': true,
      'provider_message_probe_healthy': false,
      'internet_probe_attempted': false,
      'internet_probe_blocked_by_provider_readiness': true,
      'internet_probe_blocked_by_leak_protection_config': false,
      'internet_probe_url_kind': 'public_https',
      'status_code': 0,
      'leak_protection_config_checked': true,
      'leak_protection_config_kind': 'full_tunnel_route_dns_ipv6',
      'leak_protection_provider_status_current': true,
      'leak_protection_default_route_enabled': true,
      'leak_protection_ipv6_enabled': true,
      'leak_protection_engine_ipv6_enabled': true,
      'leak_protection_dns_full_tunnel_match_enabled': true,
      'leak_protection_engine_dns_full_tunnel_match_enabled': true,
      'leak_protection_dns_server_count': 1,
      'leak_protection_engine_dns_server_count': 1,
      'leak_protection_config_passed': true,
      'raw_probe_url': 'https://www.winsvpn.org/',
    };

    final summary = appleTunnelDebugFailureSummary(readiness, null);
    expect(summary, contains('provider_status_current=true'));
    expect(summary, contains('provider_ready=false'));
    expect(summary, contains('internet_probe_attempted=false'));
    expect(
      summary,
      contains('internet_probe_blocked_by_provider_readiness=true'),
    );
    expect(
      summary,
      contains('internet_probe_blocked_by_leak_protection_config=false'),
    );
    expect(summary, contains('leak_protection_config_checked=true'));
    expect(
      summary,
      contains('leak_protection_config_kind=full_tunnel_route_dns_ipv6'),
    );
    expect(summary, contains('leak_protection_provider_current=true'));
    expect(summary, contains('leak_protection_default_route=true'));
    expect(summary, contains('leak_protection_ipv6=true'));
    expect(summary, contains('leak_protection_engine_ipv6=true'));
    expect(summary, contains('leak_protection_dns_full_tunnel_match=true'));
    expect(
      summary,
      contains('leak_protection_engine_dns_full_tunnel_match=true'),
    );
    expect(summary, contains('leak_protection_dns_count=1'));
    expect(summary, contains('leak_protection_engine_dns_count=1'));
    expect(summary, contains('leak_protection_config_passed=true'));
    expect(summary, contains('internet_probe_url_kind=public_https'));
    expect(summary, contains('internet_probe_status_code=0'));
    expect(summary, isNot(contains('https://www.winsvpn.org')));
  });

  test('internet probe exposes leak-protection config block safely', () {
    final readiness = {
      'active': true,
      'status': 'connected',
      'provider_status_available': true,
      'provider_status_current': true,
      'provider_ready': true,
      'internet_probe_attempted': false,
      'internet_probe_blocked_by_provider_readiness': false,
      'internet_probe_blocked_by_leak_protection_config': true,
      'leak_protection_config_checked': true,
      'leak_protection_config_kind': 'full_tunnel_route_dns_ipv6',
      'leak_protection_provider_status_current': true,
      'leak_protection_default_route_enabled': true,
      'leak_protection_ipv6_enabled': false,
      'leak_protection_engine_ipv6_enabled': false,
      'leak_protection_dns_full_tunnel_match_enabled': true,
      'leak_protection_engine_dns_full_tunnel_match_enabled': true,
      'leak_protection_dns_server_count': 1,
      'leak_protection_engine_dns_server_count': 1,
      'leak_protection_config_passed': false,
      'provider_dns_match_domains': [''],
      'provider_raw_dns_server': '10.8.0.1',
    };

    final summary = appleTunnelDebugFailureSummary(readiness, null);
    expect(
      summary,
      contains('internet_probe_blocked_by_leak_protection_config=true'),
    );
    expect(summary, contains('leak_protection_config_passed=false'));
    expect(summary, contains('leak_protection_ipv6=false'));
    expect(summary, contains('leak_protection_engine_ipv6=false'));
    expect(summary, contains('leak_protection_dns_count=1'));
    expect(summary, isNot(contains('10.8.0.1')));
    expect(summary, isNot(contains('provider_raw_dns_server')));
  });

  test('live tunnel smoke readiness snapshot preserves safe failure evidence',
      () {
    expect(
      appleLiveTunnelSmokeReadinessSnapshot(null),
      {
        'readiness_available': false,
        'readiness_summary': 'provider_readiness_unavailable',
      },
    );

    final readiness = {
      'active': true,
      'status': 'connected',
      'network_extension_connected': true,
      'provider_status_available': true,
      'provider_status_current': true,
      'provider_ready': false,
      'provider_stage': 'app_message',
      'provider_engine_ready': true,
      'provider_network_settings_applied': true,
      'provider_healthy': false,
      'provider_message_probe_attempted': true,
      'provider_message_probe_healthy': false,
      'provider_message_probe_accepted': false,
      'provider_message_probe_engine_running': false,
      'provider_message_probe_transport_mode': 'xray_vless_ws_amneziawg',
      'provider_message_probe_xray_enabled': true,
      'provider_message_probe_transport_mode_supported': true,
      'provider_message_probe_transport_mode_consistent': true,
      'provider_message_probe_executable_sha256':
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      'provider_message_probe_executable_sha256_matches_expected': true,
      'provider_previous_stage_before_stop': 'connected',
      'provider_previous_healthy_before_stop': true,
      'provider_previous_engine_ready_before_stop': true,
      'provider_previous_network_settings_ready_before_stop': true,
      'provider_previous_network_settings_applied_before_stop': true,
      'provider_previous_transport_mode_before_stop': 'xray_vless_ws_amneziawg',
      'provider_previous_network_settings_remote_address_kind_before_stop':
          'ipv4',
      'provider_previous_network_settings_remote_address_source_before_stop':
          'loopback_tunnel',
      'provider_previous_engine_runtime_engine_ready_reported_before_stop':
          true,
      'provider_previous_engine_runtime_engine_running_reported_before_stop':
          true,
      'provider_previous_app_message_command_before_stop': 'health',
      'provider_previous_app_message_command_is_health_before_stop': true,
      'provider_previous_app_message_accepted_before_stop': true,
      'provider_previous_app_message_raw_payload_redacted_before_stop': true,
      'provider_previous_app_message_engine_running_before_stop': true,
      'internet_probe_attempted': false,
      'internet_probe_blocked_by_provider_readiness': true,
      'internet_probe_blocked_by_leak_protection_config': false,
      'internet_probe_url_kind': 'public_https',
      'leak_protection_config_checked': true,
      'leak_protection_config_passed': true,
      'leak_protection_config_kind': 'full_tunnel_route_dns_ipv6',
      'leak_protection_provider_status_current': true,
      'leak_protection_default_route_enabled': true,
      'leak_protection_ipv6_enabled': true,
      'leak_protection_engine_ipv6_enabled': true,
      'leak_protection_dns_full_tunnel_match_enabled': true,
      'leak_protection_engine_dns_full_tunnel_match_enabled': true,
      'leak_protection_dns_server_count': '2',
      'leak_protection_engine_dns_server_count': 2,
      'raw_probe_url': 'https://www.winsvpn.org/',
      'provider_raw_dns_server': '10.8.0.1',
    };

    final snapshot = appleLiveTunnelSmokeReadinessSnapshot(readiness);
    expect(snapshot['readiness_available'], isTrue);
    expect(snapshot['active'], isTrue);
    expect(snapshot['network_extension_connected'], isTrue);
    expect(snapshot['provider_ready'], isFalse);
    expect(snapshot['provider_status_current'], isTrue);
    expect(snapshot['provider_engine_ready'], isTrue);
    expect(snapshot['provider_network_settings_ready'], isTrue);
    expect(snapshot['provider_healthy'], isFalse);
    expect(snapshot['provider_message_probe_healthy'], isFalse);
    expect(snapshot['provider_message_probe_accepted'], isFalse);
    expect(snapshot['provider_message_probe_engine_running'], isFalse);
    expect(snapshot['provider_message_probe_transport_mode'],
        'xray_vless_ws_amneziawg');
    expect(snapshot['provider_message_probe_xray_enabled'], isTrue);
    expect(snapshot['provider_message_probe_transport_mode_supported'], isTrue);
    expect(
        snapshot['provider_message_probe_transport_mode_consistent'], isTrue);
    expect(snapshot['provider_message_probe_executable_sha256'],
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    expect(
        snapshot['provider_message_probe_executable_sha256_matches_expected'],
        isTrue);
    expect(snapshot['provider_previous_stage_before_stop'], 'connected');
    expect(snapshot['provider_previous_healthy_before_stop'], isTrue);
    expect(snapshot['provider_previous_engine_ready_before_stop'], isTrue);
    expect(
      snapshot[
          'provider_previous_network_settings_remote_address_source_before_stop'],
      'loopback_tunnel',
    );
    expect(snapshot['provider_previous_app_message_command_before_stop'],
        'health');
    expect(
      snapshot['internet_probe_blocked_by_provider_readiness'],
      isTrue,
    );
    expect(
      snapshot['internet_probe_blocked_by_leak_protection_config'],
      isFalse,
    );
    expect(snapshot['internet_probe_url_kind'], 'public_https');
    expect(snapshot['leak_protection_config_checked'], isTrue);
    expect(snapshot['leak_protection_config_passed'], isTrue);
    expect(
        snapshot['leak_protection_config_kind'], 'full_tunnel_route_dns_ipv6');
    expect(snapshot['leak_protection_provider_status_current'], isTrue);
    expect(snapshot['leak_protection_default_route_enabled'], isTrue);
    expect(snapshot['leak_protection_ipv6_enabled'], isTrue);
    expect(snapshot['leak_protection_engine_ipv6_enabled'], isTrue);
    expect(snapshot['leak_protection_dns_full_tunnel_match_enabled'], isTrue);
    expect(
      snapshot['leak_protection_engine_dns_full_tunnel_match_enabled'],
      isTrue,
    );
    expect(snapshot['leak_protection_dns_server_count'], 2);
    expect(snapshot['leak_protection_engine_dns_server_count'], 2);
    expect(snapshot['native_tunnel_status'], 'connected');
    expect(
      snapshot['readiness_summary'],
      'Apple VPN provider did not respond to health check.',
    );
    expect(snapshot.toString(), isNot(contains('https://www.winsvpn.org')));
    expect(snapshot.toString(), isNot(contains('10.8.0.1')));
  });

  test('live tunnel smoke probe snapshot stays sanitized and typed', () {
    expect(
      appleLiveTunnelSmokeProbeSnapshot(null),
      {
        'internet_probe_available': false,
        'internet_probe_ok': false,
      },
    );

    final snapshot = appleLiveTunnelSmokeProbeSnapshot({
      'ok': 'true',
      'internet_probe_attempted': 'true',
      'internet_probe_blocked_by_provider_readiness': false,
      'internet_probe_blocked_by_leak_protection_config': false,
      'status_code': '204',
      'internet_probe_url_kind': 'public_https',
      'leak_protection_config_checked': true,
      'leak_protection_config_passed': true,
      'leak_protection_config_kind': 'full_tunnel_route_dns_ipv6',
      'leak_protection_provider_status_current': true,
      'leak_protection_default_route_enabled': true,
      'leak_protection_ipv6_enabled': true,
      'leak_protection_engine_ipv6_enabled': true,
      'leak_protection_dns_full_tunnel_match_enabled': true,
      'leak_protection_engine_dns_full_tunnel_match_enabled': true,
      'leak_protection_dns_server_count': '1',
      'leak_protection_engine_dns_server_count': 1,
      'native_error_domain': 'NSURLErrorDomain',
      'native_error_code': -1001,
      'error': 'probe completed without raw details',
      'raw_probe_url': 'https://www.winsvpn.org/',
      'provider_raw_dns_server': '10.8.0.1',
    });

    expect(snapshot['internet_probe_available'], isTrue);
    expect(snapshot['internet_probe_ok'], isTrue);
    expect(snapshot['internet_probe_attempted'], isTrue);
    expect(snapshot['internet_probe_status_code'], 204);
    expect(snapshot['internet_probe_url_kind'], 'public_https');
    expect(snapshot['leak_protection_config_checked'], isTrue);
    expect(snapshot['leak_protection_config_passed'], isTrue);
    expect(snapshot['leak_protection_dns_server_count'], 1);
    expect(snapshot['leak_protection_engine_dns_server_count'], 1);
    expect(snapshot['internet_probe_native_error_domain'], 'NSURLErrorDomain');
    expect(snapshot['internet_probe_native_error_code'], '-1001');
    expect(
      snapshot['internet_probe_error'],
      'probe completed without raw details',
    );
    expect(snapshot['internet_probe_summary'], contains('internet_probe_ok'));
    expect(snapshot.toString(), isNot(contains('https://www.winsvpn.org')));
    expect(snapshot.toString(), isNot(contains('10.8.0.1')));
  });

  test('native bridge error summaries keep structured codes but not raw paths',
      () {
    final summary = nativeTunnelErrorSummary(
      PlatformException(
        code: 'APPLE_TUNNEL_LOAD_FAILED',
        message:
            'Apple system error occurred. See native error domain and code.',
        details: {
          'platform': 'ios',
          'provider_bundle_id': 'org.winsvpn.app.PacketTunnel',
          'native_error_domain': 'NEVPNErrorDomain',
          'native_error_code': 5,
          'raw_path':
              '/Users/winsvpn/Library/Group Containers/group.org.winsvpn.app/Tunnel/latest_status.json',
        },
      ),
    );

    expect(summary, contains('APPLE_TUNNEL_LOAD_FAILED'));
    expect(summary, contains('native_domain=NEVPNErrorDomain'));
    expect(summary, contains('native_code=5'));
    expect(summary, isNot(contains('/Users/')));
    expect(summary, isNot(contains('Group Containers')));
    expect(summary, isNot(contains('latest_status.json')));
  });

  test('native bridge error summaries redact unsafe messages', () {
    final summary = nativeTunnelErrorSummary(
      PlatformException(
        code: 'APPLE_TUNNEL_LOAD_FAILED',
        message:
            '/Users/winsvpn/Library/Group Containers/group.org.winsvpn.app/Tunnel/latest_status.json Endpoint = 203.0.113.10:9110',
        details: {
          'native_error_domain': 'NEVPNErrorDomain',
          'native_error_code': 5,
        },
      ),
    );

    expect(summary, contains('APPLE_TUNNEL_LOAD_FAILED'));
    expect(summary, contains('native_domain=NEVPNErrorDomain'));
    expect(summary, contains('native_code=5'));
    expect(summary, isNot(contains('/Users/')));
    expect(summary, isNot(contains('Group Containers')));
    expect(summary, isNot(contains('latest_status.json')));
    expect(summary, isNot(contains('Endpoint =')));
    expect(summary, isNot(contains('203.0.113.10')));
  });

  test('external leak audit probe fields stay sanitized', () {
    final snapshot = appleLiveTunnelSmokeProbeSnapshot({
      'ok': true,
      'internet_probe_attempted': true,
      'internet_probe_url_kind': 'public_https',
      'external_leak_audit_requested': true,
      'external_leak_audit_attempted': true,
      'external_leak_audit_passed': true,
      'external_leak_audit_endpoint_count': 2,
      'external_leak_audit_minimum_endpoint_count': 2,
      'external_leak_audit_invalid_endpoint_count': 0,
      'external_leak_audit_success_count': 2,
      'external_leak_audit_failure_count': 0,
      'external_leak_audit_transport_error_count': 0,
      'external_leak_audit_server_error_count': 0,
      'external_leak_audit_https_canary_count': 2,
      'external_leak_audit_dns_canary_count': 2,
      'external_leak_audit_non_google_cloudflare_only': true,
      'external_leak_audit_blocked_by_configuration': false,
      'external_leak_audit_url_kind': 'public_https_hostname_canary',
      'external_leak_audit_raw_url': 'https://example.invalid/leak',
      'external_leak_audit_raw_ip': '203.0.113.10',
    });

    expect(snapshot['external_leak_audit_requested'], isTrue);
    expect(snapshot['external_leak_audit_attempted'], isTrue);
    expect(snapshot['external_leak_audit_passed'], isTrue);
    expect(snapshot['external_leak_audit_endpoint_count'], 2);
    expect(snapshot['external_leak_audit_minimum_endpoint_count'], 2);
    expect(snapshot['external_leak_audit_success_count'], 2);
    expect(snapshot['external_leak_audit_failure_count'], 0);
    expect(snapshot['external_leak_audit_non_google_cloudflare_only'], isTrue);
    expect(snapshot['external_leak_audit_url_kind'],
        'public_https_hostname_canary');
    expect(snapshot.toString(), isNot(contains('https://')));
    expect(snapshot.toString(), isNot(contains('203.0.113.10')));

    final blockedSnapshot = appleLiveTunnelSmokeProbeSnapshot({
      'ok': false,
      'internet_probe_attempted': true,
      'internet_probe_url_kind': 'public_https',
      'external_leak_audit_requested': true,
      'external_leak_audit_attempted': false,
      'external_leak_audit_passed': false,
      'external_leak_audit_endpoint_count': 1,
      'external_leak_audit_minimum_endpoint_count': 2,
      'external_leak_audit_invalid_endpoint_count': 1,
      'external_leak_audit_blocked_by_configuration': true,
    });
    expect(
      blockedSnapshot['internet_probe_summary'],
      'external_leak_audit_blocked_by_configuration',
    );
  });

  test('live tunnel contract reports the exact failed invariant', () {
    expect(
      appleLiveTunnelContractFailureSummary(
        doubleVpnRequested: true,
        doubleVpnVerified: false,
        ready: true,
        connected: true,
        transportModeVerified: false,
        probeOk: true,
        externalLeakAuditOk: true,
      ),
      contains('Core-to-exit route was not verified'),
    );
    expect(
      appleLiveTunnelContractFailureSummary(
        doubleVpnRequested: false,
        doubleVpnVerified: true,
        ready: true,
        connected: true,
        transportModeVerified: false,
        probeOk: true,
        externalLeakAuditOk: true,
      ),
      'Apple VPN transport did not match the requested route.',
    );
    expect(
      appleLiveTunnelContractFailureSummary(
        doubleVpnRequested: false,
        doubleVpnVerified: true,
        ready: false,
        connected: false,
        transportModeVerified: false,
        probeOk: false,
        externalLeakAuditOk: false,
        readinessFailure: 'safe provider readiness detail',
      ),
      'safe provider readiness detail',
    );
  });

  test('automatic Apple live lane accepts direct AWG or verified Xray fallback',
      () {
    expect(
      appleExpectedLiveTransportMode(forceXray: false),
      appleAutomaticTransportMode,
    );
    expect(
      appleAllowedLiveTransportModes(forceXray: false),
      [appleDirectTransportMode, appleXrayTransportMode],
    );
    for (final observed in [appleDirectTransportMode, appleXrayTransportMode]) {
      expect(
        appleLiveTransportModeVerified(
          forceXray: false,
          observedTransportMode: observed,
          transportModeSupported: true,
          transportModeConsistent: true,
          executableSha256MatchesExpected: true,
        ),
        isTrue,
      );
    }
  });

  test('forced Apple Xray lane rejects a direct AWG observation', () {
    expect(
      appleExpectedLiveTransportMode(forceXray: true),
      appleXrayTransportMode,
    );
    expect(
      appleAllowedLiveTransportModes(forceXray: true),
      [appleXrayTransportMode],
    );
    expect(
      appleLiveTransportModeVerified(
        forceXray: true,
        observedTransportMode: appleDirectTransportMode,
        transportModeSupported: true,
        transportModeConsistent: true,
        executableSha256MatchesExpected: true,
      ),
      isFalse,
    );
    expect(
      appleLiveTransportModeVerified(
        forceXray: true,
        observedTransportMode: appleXrayTransportMode,
        transportModeSupported: true,
        transportModeConsistent: false,
        executableSha256MatchesExpected: true,
      ),
      isFalse,
    );
  });
}
