package main

import (
	"fmt"
	"strings"
	"time"

	"winsvpn.local/winnprotocol/internal/protocol"
)

// Sourced enrollment-chain contract for lane E3.
//
// Hub paths and payload field names are copied from the control-plane
// installer heredoc (server/wins_control_plane_setup_ONETOUCH.sh) and from
// the data-plane wins-node-register payload
// (server/wins_data_plane_setup_ONETOUCH.sh). Controller paths and media
// types are the Go protocol constants this module already ships. Nothing
// here is invented: if an installer string disappears, TestE3ContractPins
// fails. Frozen Kansas/Spain identifiers are never used as lab slugs.
const (
	hubRegisterPath         = "/api/v1/nodes/register"
	hubBootstrapPath        = "/api/v1/nodes/bootstrap"
	hubAdminWinn3Path       = "/admin/nodes/winn3"
	hubAdminDescriptorPath  = "/admin/nodes/winn3/descriptor"
	hubVerifyPath           = "/verify"
	hubRegisterContentType  = "application/json"
	hubAdminTokenHeader     = "X-Admin-Token"
	hubActivationHeader     = "X-Wins-Activation"
	controllerListenDefault = "127.0.0.1:9443"
	controllerKeyTTLFlag    = "24h"
)

// hubRegisterJSONFields is the exact object wins-node-register POSTs.
// protocol_version / protocol_params_json are deliberately absent: the hub
// refuses to let a node self-assert winn/3 on this path.
var hubRegisterJSONFields = []string{
	"slug", "name", "flag", "endpoint", "tunnel_gateway_ipv4",
	"stealth_endpoint", "public_key", "preshared_key", "secret_token",
	"status", "obfuscation_json", "ssh_host", "wg_port", "xray_uuid",
	"xray_path", "xray_security", "xray_sni", "stealth_public_port",
	"xray_inbound_port", "regional_aliases", "stealth_transports",
	"awg_rx_bytes", "awg_tx_bytes", "wan_rx_bytes", "wan_tx_bytes",
	"peer_count", "max_peers", "direct_awg_enabled",
}

// hubAdminWinn3FormFields is POST /admin/nodes/winn3 (operator, after register).
var hubAdminWinn3FormFields = []string{
	"slug", "enabled", "protocol_params_json", "path_mtu", "carrier_classes",
}

// hubAdminDescriptorFormFields is POST /admin/nodes/winn3/descriptor.
var hubAdminDescriptorFormFields = []string{
	"slug", "enabled", "descriptor_payload_b64", "descriptor_sig_b64",
}

// hubVerifyJSONFields is the LoginRequest subset that gates a served
// winn3_descriptor. supports_winn3 and supports_winn3_descriptor default
// false; both must be true or the hub serves winn/1 and {}.
var hubVerifyJSONFields = []string{
	"account_number", "device_id", "client_public_key",
	"supports_winn3", "supports_winn3_descriptor", "stealth_mode",
}

// winn3DescriptorPayloadFields is the closed key set of a signed gateway
// descriptor. The hub serves envelope {payload, sig}; payload.node must
// equal the node slug.
var winn3DescriptorPayloadFields = []string{
	"admission_gen", "admission_secret", "alg", "bucket_window_s", "endpoint",
	"gateway_id", "iat", "inner_resolver_v4", "inner_router_v4", "kid",
	"max_skew_s", "node", "not_after", "padding", "seq", "static_pub",
	"tag_size", "v",
}

func controllerRekeyMediaType() string {
	return protocol.MediaType + ";version=2"
}

func hubContractDocumentation(skipReason string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "E3 hub hops skipped: %s\n\n", skipReason)
	b.WriteString("Hop 1. D4 data-plane register\n")
	fmt.Fprintf(&b, "  POST {HUB}%s\n", hubRegisterPath)
	fmt.Fprintf(&b, "  Content-Type: %s\n", hubRegisterContentType)
	b.WriteString("  Auth: JSON secret_token = node token from POST ")
	b.WriteString(hubBootstrapPath)
	b.WriteString(" (bootstrap_token grant). Fleet admin token is not accepted.\n")
	b.WriteString("  Body fields: ")
	b.WriteString(strings.Join(hubRegisterJSONFields, ", "))
	b.WriteString("\n  Success: {\"ok\": true}\n")
	b.WriteString("  protocol_version is NOT a register field. Operator sets winn/3 via\n")
	fmt.Fprintf(&b, "  POST {HUB}%s (form %s) with X-Admin-Token.\n",
		hubAdminWinn3Path, strings.Join(hubAdminWinn3FormFields, ", "))
	b.WriteString("  Standalone carrier body: protocol_params_json={\"carrier\":\"winn3\"} plus a servable plan.\n\n")
	b.WriteString("Hop 2. Controller mint (this package runs it in-process)\n")
	fmt.Fprintf(&b, "  POST https://%s%s\n", controllerListenDefault, protocol.RekeyPath)
	fmt.Fprintf(&b, "  Content-Type / Accept: %s\n", controllerRekeyMediaType())
	fmt.Fprintf(&b, "  suite default %s (Go crypto/tls X25519MLKEM768 = IANA 4588)\n", protocol.DefaultSuite)
	fmt.Fprintf(&b, "  -key-ttl default %s (%s)\n", controllerKeyTTLFlag, (24 * time.Hour).String())
	b.WriteString("  Body: protocol.RekeyRequest (version winn/2, suite, controller_id, device_id,\n")
	b.WriteString("  peer_public_key, request_id, nonce, current_generation, capabilities,\n")
	b.WriteString("  auth_algorithm, auth_key_id, auth_signature). Mutual TLS + ML-DSA-65.\n")
	b.WriteString("  Success: 201 Created (or 200 idempotent retry) protocol.RekeyResponse with\n")
	b.WriteString("  generation, key_id, preshared_key (32-byte base64), issued_at, expires_at.\n\n")
	b.WriteString("Hop 3. Hub serves a descriptor naming the node\n")
	fmt.Fprintf(&b, "  Operator: POST {HUB}%s form %s, X-Admin-Token.\n",
		hubAdminDescriptorPath, strings.Join(hubAdminDescriptorFormFields, ", "))
	b.WriteString("  Stored envelope keys: payload, sig. Decoded payload keys: ")
	b.WriteString(strings.Join(winn3DescriptorPayloadFields, ", "))
	b.WriteString("\n  Client: POST {HUB}")
	b.WriteString(hubVerifyPath)
	b.WriteString(" JSON {")
	b.WriteString(strings.Join(hubVerifyJSONFields, ", "))
	b.WriteString("} plus header ")
	b.WriteString(hubActivationHeader)
	b.WriteString(".\n  Served at vpn_config.winn3_descriptor. Empty {} unless protocol_version is\n")
	b.WriteString("  winn/3 and supports_winn3_descriptor is true. payload.node must equal the slug.\n")
	b.WriteString("  Opt-in for a loopback hub: WINN3_E3_HUB_BASE (loopback only),\n")
	b.WriteString("  WINN3_E3_NODE_TOKEN, WINN3_E3_NODE_SLUG (not kansas/spain-madrid).\n")
	return b.String()
}
