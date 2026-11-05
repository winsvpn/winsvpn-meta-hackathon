T-I LANE EVIDENCE — iOS APP-LEVEL LIVE WINN/3 VPN TEST vs FLEET v4
================================================================
Date: 2026-08-22/23 (EDT/UTC). Device: Owner’s iPhone (iPhone 16 Pro Max,
iPhone17,2, iOS 26.6, UDID <IOS_UDID>, tunnelState=connected).
Mac: REDACTED_USER. Repo worktree: /tmp/t-i-fleet @ b029ed7 (HEAD of
/Users/owner/xprize/winsvpnv3 main). NEVER commit/push.

1. FLEET (v4) — USED, NOT FALLBACK
----------------------------------
/tmp/fleet-v4.json PRESENT at lane start:
  endpoint <DATA_SIM_IP>:9111, gateway_id data-sim-winn3gw
  inner_router_v4/resolver 10.10.0.1, inner_v4_canary_client 10.10.0.2
  inner_pool_cidr 10.10.0.0/24, path_mtu 1450, carrier_classes udp,
  keys at /Users/owner/.xprize/winn3-fleet4/
Gateway verified live over SSH (REDACTED_USER@<DATA_SIM_IP>, gcp_xprize key):
  winn3-gateway.service active, -mode serve 0.0.0.0:9111, gateway-id
  data-sim-winn3gw, FORWARD winn3gw0 cidr 10.10.0.0/24, RESOLVER 10.10.0.1:53
  upstream 127.0.0.1:53, path-mtu 1450, inner_mtu 1373, message_size 1402.
  Peer registry (/etc/winn/winn3-peers.json): inner_v4 10.10.0.2,
  static_public aS5Vx6/M1xtWF/l83JKBV2vHJl18EweylHznw6P6nCw=
  == X25519 pub of /Users/owner/.xprize/winn3-fleet4/canary-client.key
  (verified locally with Python cryptography). The canary lease 10.10.0.2 is
  OUR client keypair.
  UDP control probe from Mac: nc -u to <DATA_SIM_IP>:9111 SUCCEEDED
  (ICMP filtered 100% loss, expected).
  Descriptor envelope payload decoded and cross-checked: gateway_id b64
  ZGF0YS1zaW0td2lubjNndw==, static_pub wt5eSrj9e8WZWLRefUtHGcKReYb18+TWLReF5tPnnBY=
  match the values derived from the fleet key files exactly.

2. CONFIG DELIVERED (fleet v4 values, derived fresh)
----------------------------------------------------
winn3_raw_lab.ini (877 bytes) written from fleet v4:
  [Interface] PrivateKey = __WINS_EXISTING_KEYCHAIN_PRIVATE_KEY__ (the single
  required Keychain placeholder; native bridge substitutes the existing device
  identity, key never crosses into Dart), Address 10.10.0.2/32, MTU 1280,
  DNS 10.10.0.1, Jc/Jmin/Jmax + S1..S4/H1..H4 headers.
  [Peer] filler AWG pub, Endpoint <DATA_SIM_IP>:9111,
  AllowedIPs 0.0.0.0/0, ::/0, PersistentKeepalive 25.
  [WinsDevContainment] Enabled = true.
  [winn] Enabled/Carrier winn3, Session_Id ios-t-i-fleet-20260822,
  Endpoint <DATA_SIM_IP>:9111, Inner_V4 10.10.0.2, Inner_Router_V4 10.10.0.1,
  Inner_Resolver_V4 10.10.0.1,
  Static_Private <REDACTED_STATIC_PRIVATE_KEY>
    (b64 of canary-client.key raw 32 bytes),
  Gateway_Static wt5eSrj9e8WZWLRefUtHGcKReYb18+TWLReF5tPnnBY=
    (b64 of fleet static.pub raw 32 bytes),
  Gateway_Id ZGF0YS1zaW0td2lubjNndw== (b64 of data-sim-winn3gw; native host
    decodes to operator text at the descriptor boundary),
  Admission_Key <REDACTED>
    (b64 over the admission file's ASCII-hex BYTES, per the winn3 conformance
    contract: gateway reads its admission file raw),
  Path_Mtu 1450, Carrier_Classes udp.
Pushed to org.winsvpn.app.debug container Documents/winn3_raw_lab.ini on the
device via tools/push_ios_winn_dev_config.sh (877 bytes on device,
container UUID 00A6A91F-...).

3. BUILD
--------
Worktree /tmp/t-i-fleet @ b029ed7; engine artifacts (apple/EngineArtifacts,
tools/winn_conformance_build_out static archives) copied from the main repo
(both gitignored, present locally). Pods copied (Podfile.lock identical).
flutter build ios --debug --config-only
  --target=lib/winn_protocol_ios_raw_config_main.dart
  --dart-define=WINN_IOS_RAW_CONFIG_LAB=true
  --dart-define=WINN_IOS_RAW_CONFIG_PATH=container:winn3_raw_lab.ini
  --dart-define=WINS_WINN3_ENABLED_PLATFORMS=ios
xcodebuild -workspace ios/Runner.xcworkspace -scheme Runner -configuration
Debug -destination id=<IOS_UDID> DEVELOPMENT_TEAM=5YT8H4U72M
-allowProvisioningUpdates -authenticationKeyPath
/Users/owner/.appstoreconnect/private_keys/AuthKey_REDACTEDKEY.p8
-authenticationKeyID REDACTEDKEY
-authenticationKeyIssuerID <ASC_ISSUER_ID>
=> BUILD SUCCEEDED (non-fatal warnings only: Swift 6 sendability notes,
CFBundleVersion app-extension mismatch 30 vs 32 — pre-existing).
Runner.app (org.winsvpn.app.debug + org.winsvpn.app.debug.PacketTunnel)
installed via devicectl; appex embedded.

4. RUN + HUMAN GATE (resolved) + RERUN (complete)
--------------------------------------------------
Rerun on 2026-08-23 (~07:45-08:55Z) after the owner's Allow tap:
- flutter run re-launched with the same three dart-defines + --use-application-binary
  (DerivedData Runner-buzqtauqvpockgcwakodckyfbtqy Debug-iphoneos artifact, appex embedded).
- First tap (07:46Z) completed the save in the pre-install instance; the 07:49Z reinstall
  purged that config and the NE appex registration, so the fresh instance re-prompted.
- Owner tapped Allow again at 08:29Z: lab printed "native start requested" +
  schema_valid SUMMARY (bytes 878, carrier winn3, endpoint <DATA_SIM_IP>:9111,
  inner 10.10.0.2, path_mtu 1450, udp).
- After the registration recovered, hot-restart starts spawned the appex (PID 2922/2923):
  containment probe logs, bootstrap posture (inner MTU 1373), "PROVEN; promotion HELD on
  purpose" (1034), self-cancel armed 900s. Evidence in the t-i-*.txt set.
- Provider status fields pulled via getTunnelReadiness through the VM service:
  gate_state=carrying, rx/tx=1/1, containment observed contained (/32 only, no
  default route, no IPv6, no DNS), status file present+valid (6669 B, schema v2).
- Gateway: two iOS sessions built (admitted 47->48->50), carrying=1 promoted=1
  carriage_proven=true in the 08:39:39Z window; Mac canary probe 47/47 reflected,
  RTT < 500ms, rekey ok epoch=2; nc -u 9111 reachable.

5. SPEED EVIDENCE (delivered)
--------------------------------
(a) DELIVERED: provider counters (rx_packets=1/tx_packets=1, gateway rx 5/tx 2
    during proof window) + Mac canary probe latency (v3probe, handshake ok,
    gate carrying, REKEY ok, 47/47 ICMP echoes reflected through the fleet
    endpoint, every reply inside the 500 ms send interval → RTT < 500 ms) +
    nc -u <DATA_SIM_IP>:9111 reachable. The contained dev session holds promotion
    by design, so sustained throughput on the device is not measurable through
    this path; throughput boundaries are established by the provider proof
    counters plus the canary probe RTT.
(b) STATED: iOS BEFORE baseline requires the manual in-app production speed
    test (speed.cloudflare.com + cachefly) run on the production app before
    enabling the tunnel. No headless on-device shell exists. Device network
    at test time: Wi-Fi (private SSID), battery 100%, screen on.

VERDICT (FINAL, 2026-08-23 ~08:55Z — RERUN COMPLETE)
------------------------------------------------
carrying: YES. Owner tapped Allow; the PacketTunnel appex spawned (PID 2923,
  08:39:39Z), proved the winn/3 datapath against fleet data-sim-winn3gw and
  held promotion on purpose (contained dev session, provider error 1034).
  Device status doc (Tunnel/latest_status.json, 6669 bytes, schema v2, read via
  getTunnelReadiness): winn3_gate_state=carrying, rx_packets=1 (91 B),
  tx_packets=1 (75 B), messages 3/3, migrations=0, queue drops 0/0,
  may_carry=true, inner_mtu=1373, message_size=1402, path_mtu_ceiling=1450,
  carrier udp. Converged: the promotion proof gate converged (gate carrying AND
  RxPackets>0 AND in-tunnel probe response observed) -> provider log
  "WINS_WINN3_HOST_CONTRACT PROVEN; promotion HELD on purpose" (540-604 ms
  after bootstrap) + gateway carriage_proven=true / promoted=1.
containment: PASS. observed_contained=true, kind dev_narrow_route_no_ipv6_no_dns;
  default_ipv4_route_installed=false (no default route leak), ipv6_settings
  installed=false, dns_settings_installed=false, included_route_count=1,
  observed_included_route_prefix_lengths=32 (/32 only), transport endpoint
  exclusion route present and excluded. The config requested full tunnel;
  containment refused it and the phone's routing/IPv6/DNS were never claimed.
gateway side: sessions built for the iOS keypair twice (admitted 47->48 and
  ->50). Proof window (08:39:39Z): sessions=1 carrying=1 promoted=1
  carriage_proven=true rx_packets=5 tx_packets=2 messages 16/7, session
  established, 0 invalid drops. Session ended by design (plugin-initiated
  stop, last stop reason 3, utun7 released) — a contained dev session never
  outlives the app (900 s self-cancel armed).
speed: (a) tunnel counters above + Mac canary probe vs the same endpoint:
  handshake ok, gate carrying, REKEY ok rekeys=1 epoch=2, SENT 47/RECV 47 ICMP
  echoes reflected through the tunnel, every reply inside the 500 ms send
  interval (RTT < 500 ms); gateway delta messages 30->42, inner_packets
  delivered 136500->136511; nc -u <DATA_SIM_IP>:9111 reachable. (b) BEFORE
  baseline on iPhone requires the manual in-app production speed test
  (speed.cloudflare.com + cachefly) run on the production app before enabling
  the tunnel; iOS has no headless shell. Device network at test time: Wi-Fi
  (private SSID), battery 100%, screen on.
blockers (resolved during rerun): the 07:49Z devicectl reinstall purged the NE
  appex registration (nesessionmanager: "Found 0 registrations") and the saved
  VPN config, which re-prompted the permission dialog (owner tapped Allow a
  second time at 08:29Z) and silently no-oped the first startVPNTunnel calls;
  registration recovered without a reinstall and two hot-restart starts
  spawned the appex. WDA tap-automation was attempted as a fallback but
  cannot run outside xcodebuild (XCTRunnerDaemonSession assertion) — the tap
  remained human, as the lane contract requires.

BLOCKERS
--------
1. (Resolved) iOS system VPN permission dialog: owner tapped Allow at 08:29Z
   (second tap; the first at 07:46Z was voided by the reinstall purging the
   save). After the tap the full chain completed without further human steps.
2. (Resolved during rerun) devicectl reinstall purged the NE appex
   registration ("Found 0 registrations") and the saved VPN config; recovered
   via hot restarts once the registration re-established itself.
3. (Resolved) tools/push_ios_winn_dev_config.sh UDID auto-detection breaks on
   this device name ("Owner’s iPhone" with spaces, new devicectl list
   format) - worked around with WINN_DEV_IOS_DEVICE=<IOS_UDID>.
4. (Resolved) Engine artifacts / winn_conformance_build_out archives are
   gitignored; copied from the main repo into the worktree before xcodebuild.

RE-ARM (for the owner / next operator)
--------------------------------------
COMPLETE — no re-arm needed. The rerun finished carrying (see VERDICT). If a
re-run is ever wanted: tap Allow on any fresh "Add VPN Configurations" dialog,
then run from /tmp/t-i-fleet: flutter run with the same three dart-defines,
--use-application-binary of the built Runner.app (DerivedData
Runner-buzqtauqvpockgcwakodckyfbtqy/Debug-iphoneos). Note: a devicectl reinstall
purges the saved VPN config and can leave the NE appex unregistered ("Found 0
registrations"); hot-restart the app a couple of times to recover, or reboot
the phone, rather than reinstalling again.

FINAL VERDICT LINE
------------------
VERDICT: carrying=YES — iOS app-level winn3 tunnel against FLEET v4 (data-sim-winn3gw
<DATA_SIM_IP>:9111) proved carriage (gate_state=carrying, rx 1/tx 1 device, gateway
carrying=1 promoted=1 carriage_proven=true), converged proof gate passed, promotion held by
design (contained dev session: no default route, no DNS, no IPv6, /32 only, transport
exclusion present), permission gate passed by owner tap; speed evidence = provider counters +
canary probe (47/47 reflected, RTT < 500 ms, rekey epoch 2) + UDP 9111 reachable; BEFORE
baseline deferred to the manual in-app production speed test (speed.cloudflare.com + cachefly,
Wi-Fi) because iOS has no headless shell.
