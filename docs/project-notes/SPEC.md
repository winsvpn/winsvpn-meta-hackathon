# XPRIZE Demo Spec v2 (Winn Protocol v3 transport)

Date: 2026-08-17. Owner deadline: 4:00 PM EDT. This file scopes the
standalone-Winn-v3 XPRIZE demo lane only. It does not supersede the product
release transport policy: Winn Protocol v3 is primary, and a connectivity
failure may move to a distinct Winn Protocol v1 cover node using current
AmneziaWG first and current Xray second. A v3 security refusal remains
fail-closed and must never authorize fallback.
All lanes read this first. Supervisor fills TO_BE_SET fields.

## Chain

Phone (org.winsvpn.app.debug, WINS_GATEWAY_BASE -> staging hub, WINS_WINN3_ENABLED_PLATFORMS=android, descriptor ring G1 pinned)
 -> staging hub (GCE xprize-hub <STAGING_HUB_IP>, Caddy TLS on sslip.io name, FastAPI twin) serves /nodes + free-verify with vpn_config protocol_version "winn/3"
 -> Gemini Router (Cloud Run, google-genai, gemini-3-flash-preview, structured output, deterministic fallback, 2s deadline)
 -> 2x winn3 gateways (GCE xprize-route-a 203.0.113.10 subnet 10.10.0.0/24, xprize-route-b 203.0.113.20 subnet 10.11.0.0/24, UDP/TCP 9111)

## Gemini model

MODEL = gemini-3-flash-preview (owner rule: latest Flash only; 2.5 forbidden as outdated; 3.5/3.6/3.7 do not exist on this key). Env var GEMINI_MODEL everywhere; supervisor sets it at deploy.

## Nodes

| slug | name | flag | vm | egress IP | subnet | gateway_id |
|---|---|---|---|---|---|---|
| demo-route-a | AI Route A - US Central | 🇺🇸 | xprize-route-a | 203.0.113.10 | 10.10.0.0/24 (gw .1) | demo-gw-a |
| demo-route-b | AI Route B - US East | 🇺🇸 | xprize-route-b | 203.0.113.20 | 10.11.0.0/24 (gw .1) | demo-gw-b |

Both: status online, free_access_enabled true, reachable flag live.

## winn/3 serving contract (hub twin MUST extract exact field names from source, then serve)

The authoritative reader is /Users/owner/Documents/wins/source/wins_vpn/lib/winn_protocol_dispatch.dart (READ-ONLY):
- served-config seam ~:2457-2580: gateway half rides the signed descriptor (endpoint, inner_router_v4, gateway_static, gateway_id, admission_key); device half rides vpn_config (winn3_inner_v4, winn3_static_private).
- descriptor envelope: {"payload": <b64>, "sig": <b64>} with format_version 3 inside, domain winsvpn-winn3-descriptor/v1, Ed25519 over DOMAIN||0x00||payload-bytes.
- keyring: kWinn3DescriptorFormatVersion, WINS_WINN3_DESCRIPTOR_PUBKEY_G1..G3 + WINS_WINN3_DESCRIPTOR_RING_SHA256 (canonical "g1=<hex>\n" per populated slot, sha256 hex).
- hub reference serving: server/wins_control_plane_setup_ONETOUCH.sh ~:18065-18164 (how the real hub writes winn3 fields onto vpn_config).
- gateway reference: server/wins_winn3_gateway_install.sh + runbook docs/WINN3_STANDALONE_V3_OPERATOR_RUNBOOK_20260812.md §5 (Path A): gateway env WINN3_GATEWAY_ID, PATH_MTU=1450, INNER_V4=<.1>, LISTEN=0.0.0.0:9111, FORWARD=1, FORWARD_IF=winn3gw0, FORWARD_CIDR=<subnet>; keys via tools/winn3_gateway_provision_keys.sh.
- engine staging: android/tools/prepare_android_winn_assets.sh --stage (release builder runs it as a freshness gate at tools/build_android_release_macos.sh:306).
- proven prior art: docs/handoff/WINN3_ANDROID_PHYSICAL_CARRY_RUN_20260811_bld_and_install.md (same handset, debug APK + packaged engine + gateway serve mode = handshake, carrying, promotion).

vpn_config keys the hub twin serves (EXTRACT + VERIFY exact names/nesting from source before implementing; keep BOTH raw snake_case as the hub does):
- protocol_version: "winn/3"  protocol_params: {…per source…}
- winn3_inner_v4 (sticky per device, from node subnet, start .2), winn3_static_private (device static private)
- descriptor: {payload_b64, sig_b64} OR the exact envelope field names from source
- node_slug, dns "1.1.1.1,1.0.0.1", mtu per source (likely 1450 path mtu)
- NO xray, NO stealth_active, NO obfuscation (v3 path ignores them)

Descriptor signing: supervisor runs tools/winn3_sign_descriptor.py (offline ceremony, private key NEVER in any lane workdir or repo). Lanes receive finished envelopes + the G1 PUBLIC key + ring sha only.

## Staging login

Free path: account 9999-9999-9999, any 4-digit PIN. App: fetch /nodes -> POST free-verify (exact path from lib/gateway_failover.dart freeVerifyGateways) -> status "authenticated" + vpn_config + selected_node.

## Router API (unchanged from v1 spec)

POST /route {request_id, current_route_id, candidates:[{route_id, reachable, handshake_ms, packet_loss_pct, jitter_ms, dns_ok, recent_failures}], signals:{udp_ok, tcp443_ok, tls_ok, control_plane_ok, dns_ok}}
-> Gemini structured, enum-constrained to allowed ids: {selected_route_id, decision keep|switch, confidence, reason_codes[]} + source gemini|fallback. 2.0s deadline -> deterministic fallback. NEVER blocks connectivity.
POST /hoppy/escalate, GET /decisions, GET / (dark dashboard), GET /health. Allowed ids: demo-route-a, demo-route-b.

## Dart defines for the debug APK

--dart-define=WINS_GATEWAY_BASE=<STAGING_BASE_URL>
--dart-define=WINS_GATEWAY_BASES=<STAGING_BASE_URL>
--dart-define=WINS_HUB_HOST=<STAGING_HOSTNAME>
--dart-define=WINS_WINN3_ENABLED_PLATFORMS=android
--dart-define=WINS_WINN3_DESCRIPTOR_PUBKEY_G1=<G1_PUBKEY_B64_RAW32>   (supervisor supplies)
--dart-define=WINS_WINN3_DESCRIPTOR_RING_SHA256=<RING_SHA256>          (supervisor supplies)

STAGING_HOSTNAME = <STAGING_HUB_SSLTIP_HOST> (hub IP <STAGING_HUB_IP>, dashes, Caddy LE cert).

## Hard rules (unchanged)

- Work ONLY inside your assigned directory. /Users/owner/Documents/wins is READ-ONLY reference. NO git. NO secrets in code/logs. Never contact production VPN infrastructure. Tests pass before finish. LANE_REPORT.md at end. PROGRESS.json + CONTINUE.md maintained (dashboard reads them).
