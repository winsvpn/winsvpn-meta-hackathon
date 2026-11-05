# FIELD_MAP.md - winn/3 vpn_config served by the staging-hub twin

Pivot v3 (owner ruling: standalone Winn Protocol v3, NO AWG, NO Xray).
Every row below was extracted from the READ-ONLY client/hub source, not
invented. Column `status` is machine-checked by
`tests/test_hub.py::test_field_map_coverage` (required/forbidden rows are
asserted against a live `/free/verify` response).

Sources (abbreviations):

- **DISPATCH** = `/Users/owner/Documents/wins/source/wins_vpn/lib/winn_protocol_dispatch.dart`
- **MAIN** = `/Users/owner/Documents/wins/source/wins_vpn/lib/main.dart`
- **HUB** = `/Users/owner/Documents/wins/source/wins_vpn/server/wins_control_plane_setup_ONETOUCH.sh`
- **TWIN** = `app.py` in this directory

## 1. vpn_config fields the twin serves

| field (vpn_config.*) | status | client expectation -> source line | hub reference line | twin serves |
|---|---|---|---|---|
| protocol_version | required | must be exactly `"winn/3"`: protocol gate DISPATCH:2106-2120 (`normalizedWinnProtocolVersion` :1191-1194 refuses every other value); read into the tunnel dispatch at MAIN:11284-11333 (`_startTunnelCandidate` case `kWinnProtocolV3`) | HUB:18112 (`resolve_served_winn_protocol` :9806-9973 returns `WINN_PROTOCOL_V3` only when every gate passes) | TWIN app.py:37,639 `"winn/3"` always (the twin speaks nothing else) |
| protocol_params.carrier | required | `"winn3"`: carrier resolved from `protocol_params` DISPATCH:2425-2428 (`_resolvedCarrier`); on a standalone-only platform (android via `WINS_WINN3_ENABLED_PLATFORMS`) any other carrier is refused DISPATCH:2183-2191; `carrier` is inside the params allowlist DISPATCH:311-317; params is a pass-through Map after normalize MAIN:4719-4721 | HUB:18113; params validated by `validate_winn3_protocol_params` (carrier winn3 install-time set HUB:9786-9799) | TWIN app.py:40,640 `{"carrier": "winn3"}` only |
| winn3_inner_v4 | required | device tunnel address read from vpn_config (compat `winn3innerv4`) DISPATCH:2511-2515; empty -> refusal `winn3DeviceMaterialMissing` :2515-2523; must be inner-IPv4 shaped `isWinnInnerIpv4` :2524-2530,1947-1975; must differ from descriptor `inner_router_v4` :2538-2545 and from `client_ip` when one is served :2561-2569 | HUB:18074; allocated lazily+idempotently per device `allocate_winn3_inner_ip` :11628-11671 (descriptor inner addresses reserved, hosts from .2 up) via `resolve_served_winn3_device_config` :11839-11915 | TWIN app.py:444-477 `allocate_winn3_inner_v4`: sticky per (device_id, node slug) from the selected node's subnet, first free host from `.2`, descriptor `inner_router_v4`/`inner_resolver_v4` reserved, persisted in STATE_FILE |
| winn3_static_private | required | device static key read from vpn_config (compat `winn3staticprivate`) DISPATCH:2513-2515; empty -> `winn3DeviceMaterialMissing`; must be base64 of non-empty bytes DISPATCH:2531-2537 (`_isWinnBase64` :2448-2455); rides vpn_config, NEVER protocol_params (allowlist refuses key-shaped names by construction, HUB:10257) | HUB:18075; X25519 raw-32-bytes base64 minted per device `generate_winn3_static_material` :11686-11740, kept for the device's life `ensure_winn3_device_material` :11743-11836 | TWIN app.py:479-551 `ensure_winn3_device_material`: openssl X25519, unwrapped to raw 32 bytes base64 (identical DER prefixes/lengths as HUB:11680-11683), generated once, persisted, never logged/echoed in admin |
| winn3_descriptor | required | object read from vpn_config (compat `winn3descriptor`) `verifyWinn3Descriptor` DISPATCH:1716-1741: envelope keys must be `payload` (String) and `sig` (String), non-empty after trim; the client verifies Ed25519 over `DOMAIN("winsvpn-winn3-descriptor/v1")||0x00||payload` :1811-1823 before reading payload fields :1826-1935; a missing/unverifiable descriptor on carrier winn3 -> refusal `winn3DescriptorUnverified` :2500-2508 | HUB:18122 serves the stored envelope VERBATIM (`parse_winn3_descriptor_envelope` :10647-10665; `resolve_served_winn3_descriptor` :10702-10745) | TWIN app.py:315-423 `descriptor_for_node`: supervisor envelope files `DESCRIPTORS_DIR/<slug>.json` first, else the nodes.json placeholder, else `{}` + loud log; served byte-verbatim, twin never re-encodes and never verifies the signature (ceremony keys are not in this lane; the phone verifies) |
| winn3_descriptor.payload / .sig | required | both base64 Strings, payload <=8192 chars / <=4096 decoded bytes, sig 64 bytes DISPATCH:1744-1778 | same envelope, verbatim | TWIN app.py:334-357 shape-checks (base64 validate, 4096-byte ceiling, UTF-8 JSON object, `v==3`, `node==slug`, `not_after` sane/not expired) then serves as-is app.py:643 |
| node_slug | required | consumed post-normalize MAIN:4710-4711; also drives the app's node picker via `selected_node` (prior study, stands) | HUB:18098 | TWIN app.py:646 the selected node's slug |
| dns | required | read at MAIN:4713 (absent -> app default `10.8.1.1`); passed to the tunnel via `_nativeTunnelDnsServers` MAIN:4811-4822 (comma list split per server) | HUB:18100 (`config_dns`) | TWIN app.py:42,647 `"1.1.1.1,1.0.0.1"` per SPEC v2 (`VPN_DNS` env override) |
| mtu | required | carried at MAIN:4712 (default 1280); the v3 datapath ignores it and sizes from `winn3_path_mtu` (DISPATCH:2597-2627), so it is inert-but-present exactly as the real hub serves it | HUB:18199 hardcoded 1280 | TWIN app.py:44,648 `1280` (`VPN_MTU` env override) |
| winn3_path_mtu | optional | string form, int-parseable, read from vpn_config not params DISPATCH:2597-2598,2621-2627; empty string means engine default; hub refuses plans in the 1280..1420 never-promote dead zone (HUB:4610-4611) | HUB:18044-18052 plan fields; fleet default `WINN3_DEFAULT_PATH_MTU = 1450` HUB:9254 | TWIN app.py:45,644 `"1450"` (`WINN3_PATH_MTU` env override) |
| winn3_carrier_classes | optional | comma list, must contain `udp` DISPATCH:2599-2619 | HUB:18045-18052; default `udp` HUB:9768 | TWIN app.py:46,645 `"udp"` (`WINN3_CARRIER_CLASSES` env override) |
| server_public_key | compat | AWG relay field, but the real hub serves it on the winn/3 path too (HUB:18087) and VpnConfigValidator.isUsable REQUIRES it, so the twin serves the gateway static public as a syntactically-valid stand-in; v3 dispatch ignores it | HUB:18087 | TWIN: gateway static pub (node awg_compat_public_key) |
| server_endpoint | compat | validator requires an endpoint; v3 dispatch takes the real endpoint from the signed descriptor (DISPATCH:2661); must differ from nothing, just be host:port | HUB:18089 | TWIN: <egress_ip>:9111 |
| client_ip | compat | validator requires an IPv4; DISPATCH:2561-2569 REFUSES client_ip == winn3_inner_v4, so the twin MUST serve a different address (uses gateway .1) | HUB:18054 | TWIN: subnet .1 (gateway inner addr, never the device's inner_v4) |
| obfuscation | compat | `h1..h4`/`s1..s4` are AmneziaWG params this session does not contain; emitting them makes a standalone doc indistinguishable from a relay one DISPATCH:2651-2656; SPEC v2: NO obfuscation | HUB:18101 | TWIN: not served |
| stealth_active | forbidden | winn/3 + stealth is a named refusal `stealthTransportConflict` DISPATCH:2150-2158,2487-2499; SPEC v2: NO stealth_active | HUB:18092 (false on this path) | TWIN: not served at all |
| xray | forbidden | SPEC v2: NO xray (v3 path ignores it); any xray presence would mark a relay doc | HUB:18092 | TWIN: not served at all |
| preshared_key | forbidden | AWG-era optional field; a standalone winn/3 session has no WG/AWG peer to share a PSK with (SPEC v2 drops all AWG fields) | HUB:18087 (relay-only path) | TWIN: not served |

## 2. Descriptor payload (inside the envelope, signed by the supervisor)

The twin does not mint these; it shape-checks only the identity-binding subset
(TWIN app.py:359-380). The full contract, for the supervisor's
`tools/winn3_sign_descriptor.py` ceremony and for reading FIELD_MAP against
landed files:

| payload field | client rule (DISPATCH) | hub rule (HUB `WINN3_DESCRIPTOR_REQUIRED_FIELDS` :10220-10225) |
|---|---|---|
| v | int == 3 (:1826-1830) | == `WINN3_DESCRIPTOR_FORMAT_VERSION` 3 (:10474) |
| kid | `g1`\|`g2`\|`g3` (:1803-1810) | slot must match a compiled pubkey (:10479-10481) |
| node | read :1907; hub binds descriptor to the node row | must equal the node slug (:10483-10493) |
| endpoint | IP-literal host:port (:1845-1853, `isWinnIpLiteralEndpoint` :1199-1231) | literal required (:10495-10497) |
| inner_router_v4 | inner IPv4 (:1854-1857); must differ from device `winn3_inner_v4` (:2538-2545) | plain dotted-quad, in hub pool (:10499-10509) |
| inner_resolver_v4 | optional client-side, validated when present (:1858-1874); emitted to `[winn]` only when carried (:2664-2679) | required at v3, equals `inner_router_v4` (HUB:10505-10509, resolver-mismatch refusal on serve :11897-11902) |
| static_pub | base64, decodes to exactly 32 bytes (:1878-1887) | exact_len 32 (:10511-10512) |
| gateway_id | base64 of operator TEXT, verbatim, decoded exactly once elsewhere (:1606-1626, :1917-1934) | b64 + text + no edge whitespace + <=255 bytes (:10513+) |
| admission_secret | base64, OPAQUE, never re-encoded, no ASCII edge whitespace (:1888-1904, :2690-2695) | secret field, redacted everywhere (HUB:10238) |
| iat / not_after | ints, not_after > iat (:1831-1835); expired -> refused (:1836-1843) | ints, sane lifetime |
| admission_gen, alg, bucket_window_s, max_skew_s, padding, seq, tag_size | admission-geometry fields the client treats via the gateway handshake | required by HUB:10220-10225 |

## 3. Response envelope around vpn_config (unchanged from the prior study)

`status: "authenticated"`, `vpn_config`, `selected_node{slug,name,flag,status}`,
`expiration_date`, `device_auth_token`, `announcement` - main.dart
`_onAuthSuccess` MAIN:10107-10203, `_applySelectedNodeFromAuth` MAIN:4609-4632;
`/nodes` envelope and free-verify path per LANE_REPORT.md section 1 (stands).
The twin additionally serves `demo_provisioning{selection_source,
descriptor_source, descriptor_reason, material_reason}` (non-secret debug
aids; the real hub keeps the equivalent in logs only, HUB:17909-17949).
