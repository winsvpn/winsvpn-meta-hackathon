# Lane D export notes (tools/, docs/, web/, extension/, legal/)

Source: git worktree `/Volumes/WinsBuild/winsvpn/podium/lanes/rel17`, branch `release-1.0.17`, commit `faff0b5` (clean tree). File list taken from `git ls-files tools docs web extension legal` (1,832 tracked files).
Output: `/Volumes/WinsBuild/winsvpn/hackathon/fullsrc/laneD/` with original relative paths. The source worktree was not modified.

## 1. Included directories and file counts

| Directory | Tracked in source | Copied to laneD | Excluded |
|---|---|---|---|
| tools/ | 988 | 988 | 0 |
| docs/ | 602 | 598 | 4 |
| web/ | 130 | 130 | 0 |
| extension/ | 99 | 98 | 1 |
| legal/ | 13 | 13 | 0 |
| total | 1832 | 1827 | 5 |

Binary files copied byte-for-byte: 57 (web images, icons, demo videos under 5 MB). Text files were copied as UTF-8 with only the scrub replacements below; line endings, executable bits and all other bytes are unchanged. 1598 unscrubbed files are byte-identical to the source; 229 files carry scrubs.

## 2. Excluded paths, grouped by rule

### Rule 2 (owner identity)

- `extension/store_listings/store_identity.json`: rule 2: store identity record carrying an owner identity receipt (issuance id, issuer, timestamp). Store ids themselves remain available in tools/native_messaging/manifests

### Rule 3 (evidence captures with device ids or user data) plus rule 2

- `docs/evidence/vpn-perf/fleet-v4/android-logcat-raw.txt`: rule 3 and rule 2: raw Android logcat capture (1.9 MB) with the owner's personal e-mail accounts, device identifiers, installed-app inventory and third-party endpoint addresses; not cleanly scrubbable
- `docs/evidence/vpn-perf/fleet-v4/android-logcat-raw2.txt`: rule 3 and rule 2: raw Android logcat capture (1.2 MB) with device identifiers, account names and third-party endpoint addresses; not cleanly scrubbable
- `docs/evidence/vpn-perf/fleet-v4/wfp_filters.xml`: rule 3 and rule 2: 2.9 MB Windows Filtering Platform dump listing the owner's Windows user-profile paths and installed-application inventory; not cleanly scrubbable

### Rule 4 (size) plus rules 3 and 2

- `docs/evidence/vpn-perf/fleet-v4/android-logcat-raw3.txt`: rule 4 (45.9 MB non-source file) and rules 3 and 2: raw Android logcat capture with the owner's personal e-mail accounts, device identifiers, Wi-Fi/Bluetooth MAC addresses, installed-app inventory and third-party endpoint addresses

Rule 1 (secrets and key material): no file in the slice had to be excluded. There are no *.pem, *.key, *.p12, *.pfx, *.mobileprovision, *.keystore, AuthKey_*.p8, env files with values, credential/seed/password files or SSH private keys among the tracked files. Every `BEGIN ... PRIVATE KEY` string is a scanner pattern or a unit-test fixture whose body is placeholder text (checked: zero base64 body lines follow any PRIVATE KEY header in the slice). `tools/winn_garble_pin.json` pins the garble tool version and digests only; the garble seed is read at build time from an owner-only file named by `WINS_GARBLE_SEED_FILE` and no seed value exists in the tree. `tools/winn_release_authority.json` holds only the Ed25519 public key and a home-relative path. `tools/release_secret_inventory.py` and `tools/release_artifact_exact_secrets.py` are scanner/policy modules, not inventories of values. `extension/store_listings/owner_signoff.json` contains status flags and blocker text only (no personal data) and was kept.

## 3. Scrubbed files with per-rule replacement counts

Rule legend:

- `users_path`: /Users/<owner>/... local path -> /Users/owner/...
- `username`: bare operator account name <owner> -> REDACTED_USER
- `ip_kansas_hub`: Kansas control hub IPv4 -> <KANSAS_HUB_IP>
- `ip_node_canada`: Canada ca1 data-plane IPv4 -> <NODE_CANADA_IP>
- `ip_node_germany`: Germany de1 data-plane IPv4 -> <NODE_GERMANY_IP>
- `ip_node_spain`: Spain data-plane IPv4 -> <NODE_SPAIN_IP>
- `ip_demo_route_a`: demo-route-a gateway egress IPv4 -> <DEMO_ROUTE_A_IP>
- `ip_demo_route_a_artifact`: tokenizer artifact of demo-route-a IPv4 -> <DEMO_ROUTE_A_IP>
- `ip_demo_route_b`: demo-route-b gateway egress IPv4 -> <DEMO_ROUTE_B_IP>
- `ip_operator_wan`: operator home WAN IPv4 -> <OPERATOR_WAN_IP>
- `host_stealth_zone`: stealth zone domain app-cloud-sync.net -> app-cloud-sync.net
- `host_stealth_zone_bare`: bare stealth zone label app-cloud-sync -> stealth-zone
- `host_ech_cover`: ECH cover hostname -> <ECH_COVER_NAME>
- `host_mac_local`: build Mac mDNS hostname -> build-mac.local
- `host_windows_local`: Windows LAN mDNS hostname -> windows-host.local
- `host_windows_account`: Windows LAN account HOST\admin -> windows-host\admin
- `host_linux_box`: Linux LAN box hostname (aicore-EliteMini[-Series]) -> linux-host
- `host_windows_box`: Windows LAN machine name -> WINDOWS-HOST
- `ssh_user_windows`: Windows LAN SSH user name -> windows-user
- `ssh_alias_canada_mgmt`: SSH alias canada-mgmt -> <CANADA_MGMT_SSH_ALIAS>
- `ssh_alias_lan`: ssh aicore|winpc|yoga alias usage -> ssh <name-SSH-ALIAS>
- `owner_name`: owner's full name -> <OWNER_NAME>
- `owner_device_name`: owner's iPhone device name -> Owner's iPhone
- `owner_name_short`: owner's name -> <OWNER_NAME>
- `owner_email_path`: owner's personal e-mail inside a cloud-storage path -> REDACTED_EMAIL
- `home_old_ssid_domain`: retired home network name (personal domain) -> <OLD_HOME_SSID>
- `home_router_name`: home router name containing the street address -> <HOME_ROUTER_NAME>
- `android_serial`: owner's Android device serial -> REDACTED_SERIAL
- `ios_udid`: owner's iPhone UDID -> <IOS_UDID>
- `devicectl_id`: owner's iPhone devicectl identifier -> <DEVICECTL_ID>
- `mac_hw_colon`: Windows laptop Wi-Fi/Bluetooth MAC (colon form) -> <MAC>
- `mac_hw_space`: Windows laptop Wi-Fi/Bluetooth MAC (route-table form) -> xx xx xx xx xx xx
- `asc_key_id`: App Store Connect API key id -> REDACTEDKEY
- `asc_issuer_id`: App Store Connect issuer id -> <ASC_ISSUER_ID>
- `google_oauth_client_id`: Google OAuth client id of the backup project -> <GOOGLE_OAUTH_CLIENT_ID>
- `gcp_project_number`: GCP project number inside a GCS bucket name -> <GCP_PROJECT_NUMBER>
- `allowlist_entry_commented`: ipscrub allowlist entries whose address became a placeholder were turned into comment lines

Totals across the slice:

- `users_path`: 700
- `host_stealth_zone`: 48
- `android_serial`: 44
- `ip_node_canada`: 30
- `ip_node_spain`: 13
- `ip_node_germany`: 10
- `ssh_alias_canada_mgmt`: 10
- `ssh_alias_lan`: 8
- `asc_key_id`: 8
- `mac_hw_space`: 8
- `ip_kansas_hub`: 7
- `ios_udid`: 5
- `mac_hw_colon`: 5
- `allowlist_entry_commented`: 5
- `username`: 4
- `host_linux_box`: 4
- `owner_device_name`: 4
- `host_windows_box`: 3
- `home_router_name`: 3
- `host_stealth_zone_bare`: 3
- `host_mac_local`: 2
- `ssh_user_windows`: 2
- `gcp_project_number`: 2
- `ip_demo_route_a`: 2
- `ip_operator_wan`: 2
- `host_windows_local`: 1
- `host_windows_account`: 1
- `google_oauth_client_id`: 1
- `home_old_ssid_domain`: 1
- `devicectl_id`: 1
- `host_ech_cover`: 1
- `owner_name`: 1
- `asc_issuer_id`: 1
- `ip_demo_route_a_artifact`: 1
- `ip_demo_route_b`: 1
- `owner_email_path`: 1

Per file (path: rule=count):

- `docs/APPLE_PLATFORM_IMPLEMENTATION_PLAN.md`: host_stealth_zone=1
- `docs/CONTROL_PLANE_BOOTSTRAP_RESILIENCE.md`: host_stealth_zone=2
- `docs/CROSS_DEVICE_CODEX_WORKFLOW.md`: host_mac_local=1, host_windows_account=1, host_windows_local=1
- `docs/LAUNCH_COMPLETION_AUDIT.md`: android_serial=3, host_stealth_zone=5
- `docs/RCLONE_CUSTOM_OAUTH_CLIENT_MIGRATION_PLAN.md`: google_oauth_client_id=1
- `docs/RELEASEPYTHON_SOURCE_FREEZE_OWNER_HANDOFF_20260831.md`: users_path=1
- `docs/WINN3_THROUGHPUT_EVOLUTION_200MBPS_TO_1500MBPS.md`: android_serial=1
- `docs/audit/DEEP_AUDIT_PROMPT.md`: users_path=9
- `docs/blueprints/AI_HANDOFF_20260823.md`: asc_key_id=3, devicectl_id=1, home_old_ssid_domain=1, home_router_name=3, host_linux_box=1, host_windows_box=2, ios_udid=1, ip_node_germany=1, ip_node_spain=1, mac_hw_colon=5, ssh_alias_lan=1, ssh_user_windows=1, username=1, users_path=5
- `docs/blueprints/FINAL_AUDIT_PROMPT_20260828.md`: users_path=1
- `docs/blueprints/FINAL_AUDIT_PROMPT_20260828_INDEPENDENT.md`: ssh_alias_lan=1, users_path=2
- `docs/blueprints/FINAL_AUDIT_PROMPT_20260828_R3.md`: ssh_alias_lan=1, users_path=1
- `docs/blueprints/WINS_VPN_COMPLETE_HANDOFF_BLUEPRINT.md`: asc_key_id=1, gcp_project_number=2, host_ech_cover=1, host_linux_box=1, host_stealth_zone=6, host_windows_box=1, ip_node_germany=1, ip_node_spain=4, owner_name=1, ssh_alias_lan=5, ssh_user_windows=1
- `docs/evidence/codex_daybreak_blue_audit.md`: users_path=2
- `docs/evidence/codex_daybreak_blue_audit_round10.md`: users_path=3
- `docs/evidence/codex_daybreak_blue_audit_round11.md`: users_path=2
- `docs/evidence/codex_daybreak_blue_audit_round12.md`: users_path=3
- `docs/evidence/codex_daybreak_blue_audit_round13.md`: users_path=5
- `docs/evidence/codex_daybreak_blue_audit_round14.md`: users_path=5
- `docs/evidence/codex_daybreak_blue_audit_round15.md`: users_path=5
- `docs/evidence/codex_daybreak_blue_audit_round16.md`: users_path=3
- `docs/evidence/codex_daybreak_blue_audit_round17.md`: users_path=9
- `docs/evidence/codex_daybreak_blue_audit_round18.md`: users_path=3
- `docs/evidence/codex_daybreak_blue_audit_round19.md`: users_path=2
- `docs/evidence/codex_daybreak_blue_audit_round3.md`: users_path=2
- `docs/evidence/codex_daybreak_blue_audit_round4.md`: users_path=2
- `docs/evidence/codex_daybreak_blue_audit_round5.md`: users_path=2
- `docs/evidence/codex_daybreak_blue_audit_round6.md`: users_path=2
- `docs/evidence/codex_daybreak_blue_audit_round7.md`: users_path=3
- `docs/evidence/codex_daybreak_blue_audit_round8.md`: users_path=2
- `docs/evidence/codex_daybreak_blue_audit_round9.md`: users_path=2
- `docs/evidence/codex_opus_5_audit.md`: users_path=2
- `docs/evidence/codex_sol_audit.md`: users_path=2
- `docs/evidence/debate_round32_stage1_antigravity.md`: android_serial=2, ip_node_canada=1
- `docs/evidence/debate_round32_stage1_fable51.md`: ip_kansas_hub=1, ip_node_canada=2, ip_node_germany=1, ip_node_spain=1
- `docs/evidence/debate_round32_stage1_opus5.md`: ip_kansas_hub=2, ip_node_canada=2, ip_node_germany=3, ip_node_spain=3
- `docs/evidence/debate_round32_stage2_fable51.md`: ip_node_canada=1
- `docs/evidence/debate_round32_stage2_opus5.md`: ip_node_canada=2
- `docs/evidence/debate_round32_stage3_opus5.md`: ip_node_canada=1
- `docs/evidence/debate_round32_treaty.md`: android_serial=1, ip_kansas_hub=2, ip_node_canada=2, ip_node_germany=2, ip_node_spain=2
- `docs/evidence/debate_round33_stage1_antigravity.md`: android_serial=1
- `docs/evidence/debate_round33_treaty.md`: android_serial=1
- `docs/evidence/debate_round34_stage1_antigravity.md`: android_serial=1
- `docs/evidence/debate_round34_treaty.md`: android_serial=1
- `docs/evidence/debate_round35_stage1_antigravity.md`: android_serial=1
- `docs/evidence/debate_round35_treaty.md`: android_serial=2
- `docs/evidence/debate_round36_stage2_agy.md`: ssh_alias_canada_mgmt=2, users_path=1
- `docs/evidence/debate_round36_treaty.md`: ssh_alias_canada_mgmt=1
- `docs/evidence/debate_round37_stage1_agy.md`: users_path=2
- `docs/evidence/debate_round38_oi_docket.md`: ssh_alias_canada_mgmt=2
- `docs/evidence/debate_round38_stage3_opus5.md`: ssh_alias_canada_mgmt=1
- `docs/evidence/debate_round38_treaty.md`: ssh_alias_canada_mgmt=1
- `docs/evidence/debate_round42_stage1_opus5.md`: ip_node_canada=2
- `docs/evidence/debate_round44_stage1_agy.md`: ip_node_canada=1
- `docs/evidence/debate_round45_stage1_agy.md`: ip_node_canada=2
- `docs/evidence/debate_round45_stage1_opus5.md`: ip_node_canada=2
- `docs/evidence/debate_round46_treaty.md`: ip_node_canada=1
- `docs/evidence/debate_speed_stage1_opus5.md`: android_serial=5
- `docs/evidence/debate_speed_stage2_sol_pro.md`: android_serial=3
- `docs/evidence/debate_speed_stage3_opus5.md`: users_path=1
- `docs/evidence/debate_upload_asymmetry_4ai_treaty.md`: android_serial=1
- `docs/evidence/round10_remediation.md`: users_path=1
- `docs/evidence/round10_remediation/additional-results.json`: users_path=16
- `docs/evidence/round10_remediation/gateway-report.md`: users_path=1
- `docs/evidence/round10_remediation/host-report.md`: users_path=1
- `docs/evidence/round10_remediation/mandatory-results.json`: users_path=18
- `docs/evidence/round11_remediation.md`: users_path=1
- `docs/evidence/round11_remediation/flutter-final-results.json`: users_path=2
- `docs/evidence/round11_remediation/flutter-results.json`: users_path=2
- `docs/evidence/round11_remediation/go-results.json`: users_path=2
- `docs/evidence/round11_remediation/mandatory-results.json`: users_path=19
- `docs/evidence/round11_remediation/platform-results.json`: users_path=5
- `docs/evidence/round11_remediation/server-results.json`: users_path=11
- `docs/evidence/round11_remediation/supplemental-results.json`: users_path=6
- `docs/evidence/round12_remediation.md`: users_path=1
- `docs/evidence/round12_remediation/baseline.json`: host_stealth_zone=1
- `docs/evidence/round12_remediation/check-results.json`: users_path=27
- `docs/evidence/round12_remediation/lane-go-prompt.txt`: users_path=1
- `docs/evidence/round12_remediation/lane-native-prompt.txt`: users_path=1
- `docs/evidence/round12_remediation/mandatory-results.json`: users_path=20
- `docs/evidence/round4_remediation.md`: users_path=1
- `docs/evidence/round5_remediation.md`: users_path=1
- `docs/evidence/round6_remediation.md`: users_path=1
- `docs/evidence/round7_remediation.md`: users_path=1
- `docs/evidence/round7_remediation/results.json`: users_path=1
- `docs/evidence/round8_remediation.md`: users_path=1
- `docs/evidence/round8_remediation/android-jvm-summary.json`: users_path=8
- `docs/evidence/round8_remediation/linux-results.json`: users_path=2
- `docs/evidence/round8_remediation/repairs.diff`: users_path=1
- `docs/evidence/round8_remediation/results.json`: users_path=8
- `docs/evidence/round9_remediation.md`: users_path=1
- `docs/evidence/round9_remediation/apple-contract-results.json`: users_path=1
- `docs/evidence/round9_remediation/apple-ownership-results.json`: users_path=1
- `docs/evidence/round9_remediation/apple-watchdog-results.json`: users_path=1
- `docs/evidence/round9_remediation/apple-wiring-results.json`: users_path=1
- `docs/evidence/round9_remediation/control-plane-round9-results.json`: users_path=1
- `docs/evidence/round9_remediation/crypto-payments-results.json`: users_path=1
- `docs/evidence/round9_remediation/emergency-dispatch-results.json`: users_path=1
- `docs/evidence/round9_remediation/flutter-results.json`: users_path=2
- `docs/evidence/round9_remediation/go-results.json`: users_path=1
- `docs/evidence/round9_remediation/ios-parse-results.json`: users_path=1
- `docs/evidence/round9_remediation/lane-checks.json`: users_path=20
- `docs/evidence/round9_remediation/linux-runargv-results.json`: users_path=2
- `docs/evidence/round9_remediation/mandatory-results.json`: users_path=15
- `docs/evidence/round9_remediation/rulings-results.json`: users_path=1
- `docs/evidence/round9_remediation/server-negative-results.json`: users_path=1
- `docs/evidence/round9_remediation/server-results.json`: users_path=8
- `docs/evidence/round9_remediation/shell-syntax-results.json`: users_path=1
- `docs/evidence/round9_remediation/website-results.json`: users_path=1
- `docs/evidence/tripartite_surgical_optimization_treaty.md`: android_serial=1
- `docs/evidence/vpn-perf/fleet-v4/linux-before.txt`: host_linux_box=1
- `docs/evidence/vpn-perf/fleet-v4/linux-verdict.txt`: host_linux_box=1, users_path=2
- `docs/evidence/vpn-perf/fleet-v4/macos-lane-report.txt`: users_path=1
- `docs/evidence/vpn-perf/fleet-v4/macos-session.txt`: users_path=4
- `docs/evidence/vpn-perf/fleet-v4/macos-session2.txt`: users_path=1
- `docs/evidence/vpn-perf/fleet-v4/macos-session3.txt`: users_path=1
- `docs/evidence/vpn-perf/fleet-v4/macos-session4.txt`: users_path=1
- `docs/evidence/vpn-perf/fleet-v4/macos-session5.txt`: users_path=1
- `docs/evidence/vpn-perf/fleet-v4/macos-session6.txt`: users_path=1
- `docs/evidence/vpn-perf/fleet-v4/t-i-canary-probe.txt`: users_path=1
- `docs/evidence/vpn-perf/fleet-v4/t-i-gateway-ios-session.txt`: username=1
- `docs/evidence/vpn-perf/fleet-v4/t-i-report.md`: asc_issuer_id=1, asc_key_id=2, ios_udid=3, owner_device_name=2, username=2, users_path=4
- `docs/evidence/vpn-perf/fleet-v4/t-i-rerun-console.txt`: ios_udid=1
- `docs/evidence/vpn-perf/fleet-v4/windows-route-after.txt`: mac_hw_space=4
- `docs/evidence/vpn-perf/fleet-v4/windows-route-final2.txt`: mac_hw_space=4
- `docs/evidence/winn3_speed_astra_study.md`: users_path=93
- `docs/evidence/winn3_stages345_astra_study.md`: users_path=101
- `docs/evidence/winn3_stages345_sol_study.md`: users_path=1
- `docs/rulings/OWNER_RATIFICATION_RELEASEPYTHON_V2_AND_DEPLOYMENT_GOVERNANCE_20260903.md`: users_path=4
- `docs/runbooks/WEBSITE_DOWNLOAD_R2_PUBLICATION.md`: users_path=10
- `extension/tools/test_packaging.py`: users_path=2
- `tools/README_SYNC.md`: users_path=1
- `tools/android-toolchain-custody.json`: users_path=3
- `tools/android_ondevice_route_guard.sh`: users_path=2
- `tools/apple_runtime_smoke.sh`: owner_device_name=2
- `tools/apple_watch_companion_smoke.py`: users_path=1
- `tools/build_openssl_release_archive.sh`: users_path=2
- `tools/build_windows_tunnel_service_xcompile.sh`: users_path=2
- `tools/check_control_plane_anchor_coverage.py`: host_stealth_zone=2
- `tools/check_flip_authorization.sh`: users_path=1
- `tools/council_docket_round3.py`: users_path=1
- `tools/council_round2_micro_aggregation.py`: users_path=1
- `tools/council_surgical_optimizations.py`: android_serial=2, users_path=1
- `tools/execute_run17_speedtest.py`: android_serial=1, users_path=1
- `tools/execute_run18_speedtest.py`: android_serial=1, users_path=1
- `tools/execute_run19_speedtest.py`: android_serial=2, users_path=1
- `tools/generate_blueprint_pdf.py`: host_stealth_zone=1, host_stealth_zone_bare=2
- `tools/ipscrub/ipscrub-allowlist.txt`: allowlist_entry_commented=5, ip_demo_route_a=2, ip_demo_route_a_artifact=1, ip_demo_route_b=1, ip_node_germany=1, ip_node_spain=1
- `tools/macos_release_python_runtime_production.py`: asc_key_id=2
- `tools/onetouch_tiers/cover_material.py`: users_path=1
- `tools/package_release_artifacts.sh`: users_path=1
- `tools/remote_mac.ps1`: host_mac_local=1
- `tools/run_4ai_upload_debate.py`: android_serial=2, users_path=2
- `tools/run_astra_remediation.py`: users_path=2
- `tools/run_astra_remediation_round10.py`: users_path=2
- `tools/run_astra_remediation_round11.py`: users_path=2
- `tools/run_astra_remediation_round12.py`: users_path=2
- `tools/run_astra_remediation_round5.py`: users_path=2
- `tools/run_astra_remediation_round6.py`: users_path=2
- `tools/run_astra_remediation_round7.py`: users_path=2
- `tools/run_astra_remediation_round8.py`: users_path=2
- `tools/run_astra_remediation_round9.py`: users_path=2
- `tools/run_codex_tripartite_audit.py`: users_path=5
- `tools/run_deepseek_all_targets_audit.py`: ip_kansas_hub=1
- `tools/run_openrouter_batch_debate.py`: users_path=1
- `tools/run_opus5_fixer.py`: android_serial=2, ip_node_canada=1, ssh_alias_canada_mgmt=1, users_path=2
- `tools/run_presidential_debate_speed.py`: android_serial=1, owner_email_path=1, users_path=3
- `tools/run_round32_speed_debate.py`: android_serial=1, ip_kansas_hub=1, ip_node_canada=1, ip_node_germany=1, ip_node_spain=1, users_path=2
- `tools/run_round33_upload_debate.py`: android_serial=2, users_path=1
- `tools/run_round34_upload_debate.py`: android_serial=2, users_path=1
- `tools/run_round35_upload_debate.py`: android_serial=4, users_path=1
- `tools/run_round36_disputes.py`: users_path=1
- `tools/run_round36_oi35_final.py`: users_path=1
- `tools/run_round36_surface_audit.py`: ssh_alias_canada_mgmt=1, users_path=2
- `tools/run_round37_microvote.py`: users_path=1
- `tools/run_round37_verify.py`: users_path=1
- `tools/run_round38_speedtest.py`: users_path=1
- `tools/run_round38_stage3.py`: ssh_alias_canada_mgmt=1, users_path=1
- `tools/run_round39_stage3.py`: users_path=1
- `tools/run_round39_verify.py`: users_path=1
- `tools/run_round40_addendum.py`: users_path=1
- `tools/run_round40_addendum_stage2.py`: users_path=1
- `tools/run_round40_addendum_stage3.py`: users_path=1
- `tools/run_round40_addendum_stage4.py`: users_path=1
- `tools/run_round40_addendum_stage5.py`: users_path=1
- `tools/run_round40_addendum_stage6.py`: users_path=1
- `tools/run_round41_death.py`: ip_node_canada=1, ip_operator_wan=1, users_path=1
- `tools/run_round41_stage2.py`: ip_operator_wan=1, users_path=1
- `tools/run_round41_turn3.py`: users_path=1
- `tools/run_round42_wirespeed_debate.py`: ip_node_canada=1, users_path=1
- `tools/run_round43_debate.py`: ip_node_canada=1, users_path=1
- `tools/run_round44_debate.py`: ip_node_canada=3, users_path=1
- `tools/run_round45_debate.py`: ip_node_canada=2, users_path=1
- `tools/run_round45_turn2.py`: users_path=1
- `tools/run_round46_debate.py`: ip_node_canada=1, users_path=1
- `tools/run_round46_turn2.py`: users_path=1
- `tools/run_round46_turn3.py`: users_path=1
- `tools/run_stage2_cross_rebuttal.py`: users_path=2
- `tools/run_stage3_synthesis.py`: users_path=2
- `tools/run_tripartite_cycle.py`: users_path=1
- `tools/run_winn3_speed_optimization_study.py`: users_path=3
- `tools/run_winn3_stages345_study.py`: users_path=3
- `tools/sign_android_aab_keyb_20260810_signroute.sh`: users_path=3
- `tools/sync_lanes.py`: users_path=1
- `tools/test_build_openssl_release_archive.py`: users_path=8
- `tools/test_data_plane_sync_contract.py`: host_stealth_zone=9, host_stealth_zone_bare=1
- `tools/test_deployment_runtime_configs.sh`: host_stealth_zone=7
- `tools/test_macos_release_python_owner_provision.py`: users_path=1
- `tools/test_release_android_toolchain_archive_custody.py`: users_path=2
- `tools/test_release_artifact_exact_secrets.py`: host_stealth_zone=3
- `tools/test_release_browser_archive_custody.py`: users_path=1
- `tools/test_release_gate_determinism.py`: users_path=3
- `tools/test_release_go_archive_custody.py`: users_path=1
- `tools/test_release_openssl_archive_custody.py`: users_path=2
- `tools/test_verify_android_aab_signers.py`: users_path=2
- `tools/test_wear_os_release_supply_chain.py`: users_path=1
- `tools/test_website_download_custody.py`: users_path=1
- `tools/test_website_download_publication.py`: users_path=1
- `tools/test_windows_arm64_inner_payload_gate.py`: users_path=2
- `tools/toolchain-pins.json`: users_path=11
- `tools/validate_deployment_scripts.py`: host_stealth_zone=2
- `tools/validate_release_artifact_privacy.py`: host_stealth_zone=2
- `tools/website_download_custody.py`: users_path=1
- `tools/winn3_descriptor_ring_defines.py`: users_path=1
- `tools/winn_conformance_results/baseline_final_pass.json`: users_path=10
- `tools/winn_conformance_results/baseline_final_pass2.json`: users_path=10
- `tools/winn_conformance_results/baseline_first_pass.json`: users_path=10
- `tools/winn_garble_pin.json`: users_path=1
- `tools/wins_deployment_preseed.ps1`: host_stealth_zone=7

### Scrub decisions worth knowing

- Project node addresses were replaced even though `tools/ipscrub/ipscrub-allowlist.txt` records an owner policy (2026-08-28/30) that production data-plane exit IPs are publishable. The lane brief asked for real infrastructure IPv4 addresses to be scrubbed, so the Spain, Germany, Canada, Kansas hub and demo-route addresses are placeholders; the owner can restore the data-plane ones from the source if that policy should apply to the public copy. The five allowlist entries that became placeholders were turned into comment lines so the ipscrub tool still parses the file.
- `app-cloud-sync.net` is the fleet's stealth Cloudflare zone (a cover name, not a marketing domain). It was replaced consistently with `app-cloud-sync.net` (bare label `stealth-zone`), including inside `tools/test_data_plane_sync_contract.py` and `tools/check_control_plane_anchor_coverage.py`, so those tests stay self-consistent within this lane. The same string exists in lib/, apple/, server/ and test/ (other lanes) and in `.env.example`; whichever placeholder the other lanes choose, cross-lane tests that compare the literal will only line up if the same replacement is used.
- Two tools carry the stealth zone as a literal that drives behaviour: `tools/validate_release_artifact_privacy.py` (line 148, the `plaintext_sync_hostname` forbidden-marker fixture, plus a test payload at line 2815) and `tools/validate_deployment_scripts.py` (lines 2988 and 2995, an expected Cloudflare zone query asserted against the server installers). In the public copy those now reference `app-cloud-sync.net`, so the privacy scanner there would not flag the real zone name and the deployment-script assertion only lines up if the server lane uses the same placeholder. Nothing else about their logic changed.
- `aicore`, `yoga` and `winpc` remain as plain nicknames in prose (443, 32 and 27 occurrences); only their SSH-alias usages (`ssh aicore` etc.), the resolvable hostnames (`aicore-EliteMini-Series`, `BOOK-OFOIHG3LA4`, `AICORE.local`, `Wins-MacBook-Pro.local`) and the `canada-mgmt` alias were replaced. The literal `EliteMini` that survives in `docs/blueprints/AI_HANDOFF_20260823.md` is the hardware product name, not a hostname.
- RFC 1918 LAN addresses (192.168.4.x, 192.168.50.x, 10.x) were kept as the brief allows; they describe the owner's LAN topology in the handoff documents but are not routable.
- Wrangler's OAuth client id `54d11594-84e4-41aa-b438-e81b8fa78ee7` (in both handoff blueprints) is Cloudflare's public, open-source wrangler client id and was kept.
- Scrubbing `/Users/<owner>/...` inside `tools/toolchain-pins.json` and `tools/android-toolchain-custody.json` changes those data files, so the SHA-256 of `tools/toolchain-pins.json` recorded in `tools/android-toolchain-custody.json`, `tools/provision_macos_release_android_toolchains.sh`, `tools/release_browser_archive_custody.trust.json`, `tools/release_freeze_client.py` (and `apple/EngineArtifacts/apple_winn_v3_engine_provenance.json` in another lane) no longer matches the public copy. Likewise `tools/winn_garble_pin.json` (install path scrubbed). No code logic was changed; only literal strings.
- `tools/apple_runtime_smoke.sh` self-test fixture reproducing an Xcode error now says `Owner’s iPhone`; the matcher it exercises keys on `Unlock .+ to Continue`, so the self-test still passes.
- `tools/macos_release_python_runtime_production.py` hard-coded the owner's App Store Connect key id in a key path and a `--key-id` argument; both literals are now `REDACTEDKEY` (the .p8 file itself is not in the repository).
- Kept on purpose (public by construction or already public): the business phone and Florida registration number in legal/ and web/, the donation wallet addresses in `web/index.html`, the SSH public key embedded as the overridable default in `tools/recover_home_core_ssh.sh` and `tools/recover_ionos_hub_ssh.sh`, AWG/WireGuard public keys in evidence files whose endpoints were already placeholders in the source, GCP service-account e-mail addresses used by tests and the blueprint, Cloudflare edge addresses that public DNS returns for winsvpn.org, public resolvers, the Apple Team ID, store ids and extension ids, and the `/root/winsvpn-secrets.env` file name (a path reference used by scripts and tests; no values).

## 4. Verification

### 4.1 gitleaks (exact command)

```
gitleaks detect --no-git --source /Volumes/WinsBuild/winsvpn/hackathon/fullsrc/laneD --redact
```

Output:

```
○
    │╲
    │ ○
    ○ ░
    ░    gitleaks

10:00PM INF scanned ~58405260 bytes (58.41 MB) in 6.01s
10:00PM WRN leaks found: 190
```

Findings: 190 (generic-api-key: 120, jfrog-identity-token: 53, private-key: 17). None is a credential; Appendix A gives the reason for every row. By reason: 114 are SHA-256 file digests inside two file-inventory manifests whose keys contain the words Key or Secret, 26 are 64-hex SHA-256 pins of build inputs or upstream archives, 17 are PEM header strings in unit-test fixtures or key-generation code with no key body, and the remaining 33 are synthetic test keys, WebSocket handshake nonces, certificate and binary digests, the WireGuard documentation example key, prose, code expressions, one scanner self-test sample and one public AWG key.

### 4.2 Required greps over the output

```
grep -rn '/Users/<owner>' . | wc -l      -> 0
grep -rn '<owner>' . | wc -l             -> 0
grep -rn -E 'BEGIN .*PRIVATE KEY' . | wc -l -> 68 lines in 38 files (all under tools/ and extension/; scanner patterns, assertions, test fixtures; no key bodies)
grep -rn 'winsvpn-secrets' . | wc -l    -> 50 lines in 21 files (file-name references to /root/winsvpn-secrets.env; no values)
grep -rn 'AuthKey_' . | wc -l          -> 17 lines in 10 files (test fixtures, scanner patterns, f-string template, scrubbed REDACTEDKEY path)
grep -rn -i 'garble' . | wc -l         -> 163 lines in 7 files (obfuscation build/sign/provenance tooling and its tests; no seed value)
grep -rn -E 'ssh-(rsa|ed25519) AAAA' . | wc -l -> 23 lines (public keys: recovery-admin default in two scripts, test fixtures)
```

Handling: `/Users/<owner>` and `<owner>` are gone. `BEGIN ... PRIVATE KEY` hits are scanner regexes, assertions and test fixtures (full list in `tools/` and `extension/` only; see Appendix B). `winsvpn-secrets` hits are references to the server-side file name `/root/winsvpn-secrets.env` in scripts, tests and runbooks; no values. `AuthKey_` hits are test fixtures (`AuthKey_ABCDEFGHIJ.p8`, `AuthKey_TESTKEY123.p8`, `AuthKey_SECRET_PRIVATE.p8`), scanner patterns, an f-string template, and the scrubbed `AuthKey_REDACTEDKEY.p8` path. `garble` hits are the obfuscation build script, the release signer, the artifact provenance checker, the tool pin file and their tests; no seed value is present.

### 4.3 IPv4 literals outside the allowed ranges

Allowed by the brief: 127.0.0.0/8, ::1, 0.0.0.0, RFC 1918, RFC 5737, RFC 3849, 1.1.1.1, 8.8.8.8, 9.9.9.9. Everything else that remains is listed below with its class; no project node, hub or operator address remains.

```
distinct IPv4 literals outside the allowed set: 113
address           hits files  class  (example file)
128.0.0.0           31    15  netmask / route-math block base, host bits zero  (docs/evidence/deepseek_round1_audit.md)
17.0.20.1           36    11  version string: JDK 17.0.20.1 version string  (tools/android-toolchain-custody.json)
255.255.255.255     34    10  netmask / route-math block base, host bits zero  (docs/blueprints/AI_HANDOFF_20260823.md)
1.0.17.34           30     9  version string: app version 1.0.17+34 dotted  (docs/rulings/RELEASE_IDENTITY_MAP_20260824.json)
1.3.0.0             10     8  version string: dependency version string  (docs/DESKTOP_STORE_RELEASE_READINESS.md)
255.255.255.0       15     8  netmask / route-math block base, host bits zero  (docs/evidence/deepseek_all_targets_audit.md)
8.8.4.4             22     8  public resolver: Google Public DNS secondary  (extension/tools/leakscan.py)
1.2.3.4             10     7  documentation / test sentinel value (ipscrub allowlist or unit test)  (docs/evidence/codex_daybreak_blue_audit_round16.md)
104.21.36.50         6     6  Cloudflare anycast edge address returned by public DNS for a public hostname  (docs/evidence/codex_daybreak_blue_audit.md)
149.112.112.112      8     6  public resolver: Quad9 secondary  (docs/CONTROL_PLANE_BOOTSTRAP_RESILIENCE.md)
1.0.0.1             16     5  public resolver: Cloudflare resolver secondary  (extension/tools/leakscan.py)
1.0.15.30            6     5  version string: historical Windows four-part version  (docs/CROSS_STORE_RELEASE_CHECKLIST.md)
1.0.16.33            6     5  version string: historical Windows four-part version  (tools/ipscrub/ipscrub-allowlist.txt)
172.67.185.162       5     5  Cloudflare anycast edge address returned by public DNS for a public hostname  (docs/evidence/codex_daybreak_blue_audit.md)
1.0.0.0             11     4  netmask / route-math block base, host bits zero  (extension/tools/test_browser_runtime_custody.py)
172.66.0.218         4     4  Cloudflare anycast edge address returned by public DNS for a public hostname  (docs/evidence/debate_round35_stage1_antigravity.md)
2.5.4.3              5     4  X.509 OID (2.5.x.y), not an address  (tools/release_dependency_freeze.py)
208.67.222.222       4     4  public resolver: OpenDNS  (docs/LAUNCH_COMPLETION_AUDIT.md)
224.0.0.1            4     4  multicast / reserved range  (tools/awg_carry_client/request_test.go)
255.0.0.0            4     4  netmask / route-math block base, host bits zero  (docs/blueprints/AI_HANDOFF_20260823.md)
93.184.216.34        5     4  example.com IANA example host / range  (extension/tools/core_tests.py)
131.0.0.0            3     3  netmask / route-math block base, host bits zero  (docs/evidence/debate_round34_stage1_antigravity.md)
162.159.140.220      4     3  Cloudflare anycast edge address returned by public DNS for a public hostname  (docs/evidence/debate_round35_stage1_antigravity.md)
2.5.4.11             3     3  X.509 OID (2.5.x.y), not an address  (tools/release_dependency_freeze.py)
224.0.0.0           10     3  multicast / reserved range  (docs/evidence/vpn-perf/fleet-v4/android-after.txt)
86.54.11.13          3     3  public resolver: DNS4EU  (tools/ipscrub/ipscrub-allowlist.txt)
94.140.14.14         3     3  public resolver: AdGuard DNS  (tools/ipscrub/ipscrub-allowlist.txt)
94.140.15.15         3     3  public resolver: AdGuard DNS secondary  (tools/ipscrub/ipscrub-allowlist.txt)
1.0.14.29            2     2  version string: historical app version dotted  (tools/ipscrub/ipscrub-allowlist.txt)
100.64.0.1           2     2  CGNAT shared space (RFC 6598), test value  (tools/ipscrub/ipscrub.py)
103.21.244.0         2     2  Cloudflare published ingress range base (cloudflare.com/ips)  (tools/ipscrub/ipscrub-allowlist.txt)
103.22.200.0         2     2  Cloudflare published ingress range base (cloudflare.com/ips)  (tools/ipscrub/ipscrub-allowlist.txt)
103.31.4.0           2     2  Cloudflare published ingress range base (cloudflare.com/ips)  (tools/ipscrub/ipscrub-allowlist.txt)
104.16.0.0           2     2  Cloudflare published ingress range base (cloudflare.com/ips)  (tools/ipscrub/ipscrub-allowlist.txt)
104.24.0.0           2     2  Cloudflare published ingress range base (cloudflare.com/ips)  (tools/ipscrub/ipscrub-allowlist.txt)
108.162.192.0        2     2  Cloudflare published ingress range base (cloudflare.com/ips)  (tools/ipscrub/ipscrub-allowlist.txt)
129.6.15.28          2     2  NIST time server (route probe)  (tools/ipscrub/ipscrub-allowlist.txt)
131.0.72.0           2     2  Cloudflare published ingress range base (cloudflare.com/ips)  (tools/ipscrub/ipscrub-allowlist.txt)
141.101.64.0         2     2  Cloudflare published ingress range base (cloudflare.com/ips)  (tools/ipscrub/ipscrub-allowlist.txt)
162.158.0.0          2     2  Cloudflare published ingress range base (cloudflare.com/ips)  (tools/ipscrub/ipscrub-allowlist.txt)
169.254.1.1          2     2  link-local (RFC 3927)  (tools/test_core_double_vpn_path_hardening.py)
172.64.0.0           2     2  Cloudflare published ingress range base (cloudflare.com/ips)  (tools/ipscrub/ipscrub-allowlist.txt)
173.245.48.0         2     2  Cloudflare published ingress range base (cloudflare.com/ips)  (tools/ipscrub/ipscrub-allowlist.txt)
188.114.96.0         2     2  Cloudflare published ingress range base (cloudflare.com/ips)  (tools/ipscrub/ipscrub-allowlist.txt)
190.93.240.0         2     2  Cloudflare published ingress range base (cloudflare.com/ips)  (tools/ipscrub/ipscrub-allowlist.txt)
192.0.0.0            2     2  netmask / route-math block base, host bits zero  (docs/blueprints/FINAL_AUDIT_PROMPT_20260828_INDEPENDENT.md)
192.128.0.0          4     2  netmask / route-math block base, host bits zero  (tools/ipscrub/ipscrub-allowlist.txt)
192.33.4.12          2     2  c.root-servers.net root hint (upstream Xray constant)  (tools/ipscrub/ipscrub-allowlist.txt)
197.234.240.0        2     2  Cloudflare published ingress range base (cloudflare.com/ips)  (tools/ipscrub/ipscrub-allowlist.txt)
198.41.128.0         2     2  Cloudflare published ingress range base (cloudflare.com/ips)  (tools/ipscrub/ipscrub-allowlist.txt)
2.5.29.15            3     2  X.509 OID (2.5.x.y), not an address  (tools/release_dependency_freeze.py)
2.5.29.19            4     2  X.509 OID (2.5.x.y), not an address  (tools/release_dependency_freeze.py)
2.5.4.10             3     2  X.509 OID (2.5.x.y), not an address  (tools/release_inno_toolchain_custody.ps1)
2.5.4.6              3     2  X.509 OID (2.5.x.y), not an address  (tools/ipscrub/ipscrub.py)
208.67.220.220       2     2  public resolver: OpenDNS secondary  (extension/tools/leakscan.py)
240.0.0.0            7     2  multicast / reserved range  (docs/evidence/vpn-perf/fleet-v4/windows-route-after.txt)
255.255.0.0          6     2  netmask / route-math block base, host bits zero  (docs/evidence/deepseek_all_targets_audit.md)
4.1.1.4              2     2  version string: dependency version string  (tools/amneziawg_android_official_jni/gradle-verification-metadata.xml)
0.9.1.2              1     1  documentation / test sentinel value (ipscrub allowlist or unit test)  (tools/ipscrub/ipscrub.py)
1.0.17.35            1     1  version string: app version (test)  (tools/test_release_identity_consistency.py)
1.1.3.1              1     1  version string: dependency version string  (tools/ipscrub/ipscrub-allowlist.txt)
100.64.0.0           1     1  netmask / route-math block base, host bits zero  (tools/ipscrub/ipscrub.py)
100.64.1.1           1     1  CGNAT shared space (RFC 6598), test value  (tools/test_xray_v26_9_config_contract.py)
100.64.1.2           1     1  CGNAT shared space (RFC 6598), test value  (tools/test_core_double_vpn_path_hardening.py)
104.21.85.254        1     1  Cloudflare anycast edge address returned by public DNS for a public hostname  (docs/LAUNCH_COMPLETION_AUDIT.md)
11.0.0.0             1     1  netmask / route-math block base, host bits zero  (tools/ipscrub/ipscrub-allowlist.txt)
13.1.1.3             5     1  version string: libcublas version in ipscrub self-test  (tools/ipscrub/ipscrub.py)
150.0.0.0            3     1  netmask / route-math block base, host bits zero  (tools/ipscrub/ipscrub.py)
151.0.0.0            3     1  netmask / route-math block base, host bits zero  (extension/tools/test_edge_proxy_product.py)
169.254.0.0          1     1  link-local (RFC 3927)  (extension/tools/leakscan.py)
169.254.10.1         2     1  link-local (RFC 3927)  (docs/evidence/deepseek_round1_audit.md)
169.254.10.2         1     1  link-local (RFC 3927)  (docs/evidence/deepseek_round1_audit.md)
169.254.44.38        1     1  link-local (RFC 3927)  (tools/ipscrub/ipscrub.py)
172.15.0.1           1     1  documentation / test sentinel value (ipscrub allowlist or unit test)  (tools/ipscrub/ipscrub-allowlist.txt)
172.32.0.1           1     1  documentation / test sentinel value (ipscrub allowlist or unit test)  (tools/test_xray_v26_9_config_contract.py)
198.18.0.0           1     1  benchmark range base (RFC 2544)  (docs/blueprints/FINAL_AUDIT_PROMPT_20260828_INDEPENDENT.md)
2.0.0.1              1     1  documentation / test sentinel value (ipscrub allowlist or unit test)  (tools/ipscrub/ipscrub.py)
2.5.29.37            3     1  X.509 OID (2.5.x.y), not an address  (tools/ipscrub/ipscrub.py)
2.5.4.4              1     1  X.509 OID (2.5.x.y), not an address  (tools/release_inno_toolchain_custody.ps1)
2.5.4.7              1     1  X.509 OID (2.5.x.y), not an address  (tools/release_inno_toolchain_custody.ps1)
2.5.4.8              1     1  X.509 OID (2.5.x.y), not an address  (tools/release_inno_toolchain_custody.ps1)
203.0.114.25         3     1  synthetic test value adjacent to RFC 5737 range (tools/test_deployment_runtime_configs.sh)  (tools/test_deployment_runtime_configs.sh)
203.0.114.77         2     1  synthetic test value adjacent to RFC 5737 range (tools/test_deployment_runtime_configs.sh)  (tools/test_deployment_runtime_configs.sh)
209.50.48.1          1     1  documentation / test sentinel value (ipscrub allowlist or unit test)  (tools/ipscrub/ipscrub-allowlist.txt)
209.50.51.255        1     1  documentation / test sentinel value (ipscrub allowlist or unit test)  (tools/ipscrub/ipscrub-allowlist.txt)
209.94.56.1          1     1  documentation / test sentinel value (ipscrub allowlist or unit test)  (tools/ipscrub/ipscrub-allowlist.txt)
209.94.59.255        1     1  documentation / test sentinel value (ipscrub allowlist or unit test)  (tools/ipscrub/ipscrub-allowlist.txt)
21.0.9.1            11     1  version string: JDK 21.0.9.1 version string (test)  (tools/test_android_release_producer.py)
21.0.9.2             1     1  version string: JDK version string (test)  (tools/test_android_release_producer.py)
224.0.0.251          1     1  multicast / reserved range  (tools/ipscrub/ipscrub.py)
240.0.0.1            1     1  multicast / reserved range  (tools/test_data_plane_management_rollback_guard.py)
255.240.0.0          1     1  netmask / route-math block base, host bits zero  (docs/evidence/deepseek_all_targets_audit.md)
3.3.3.3              1     1  documentation / test sentinel value (ipscrub allowlist or unit test)  (tools/ipscrub/ipscrub-allowlist.txt)
32.0.0.0             1     1  netmask / route-math block base, host bits zero  (tools/ipscrub/ipscrub-allowlist.txt)
4.8.1.1              1     1  documentation / test sentinel value (ipscrub allowlist or unit test)  (tools/ipscrub/ipscrub.py)
5.6.7.8              1     1  documentation / test sentinel value (ipscrub allowlist or unit test)  (tools/test_release_browser_archive_custody.py)
6.18.33.2            1     1  version string: dependency version string  (tools/ipscrub/ipscrub-allowlist.txt)
6.3.3.1              1     1  version string: dependency version string  (tools/ipscrub/ipscrub-allowlist.txt)
6.6.6.6              1     1  documentation / test sentinel value (ipscrub allowlist or unit test)  (tools/ipscrub/ipscrub-allowlist.txt)
64.0.0.0             1     1  netmask / route-math block base, host bits zero  (tools/ipscrub/ipscrub.py)
7.255.255.255        1     1  documentation / test sentinel value (ipscrub allowlist or unit test)  (tools/ipscrub/ipscrub-allowlist.txt)
77.1.0.0             1     1  netmask / route-math block base, host bits zero  (tools/ipscrub/ipscrub-allowlist.txt)
8.0.0.0              1     1  netmask / route-math block base, host bits zero  (tools/ipscrub/ipscrub-allowlist.txt)
8.233.232.167        1     1  version string: dependency version string (ipscrub allowlist triage)  (tools/ipscrub/ipscrub-allowlist.txt)
8.8.4.0              1     1  documentation / test sentinel value (ipscrub allowlist or unit test)  (tools/onetouch_tiers/pred_cases.py)
8.8.8.0              1     1  documentation / test sentinel value (ipscrub allowlist or unit test)  (tools/onetouch_tiers/pred_cases.py)
9.24.0.43            1     1  version string: dependency version string  (tools/ipscrub/ipscrub-allowlist.txt)
9.255.255.255        1     1  documentation / test sentinel value (ipscrub allowlist or unit test)  (tools/ipscrub/ipscrub-allowlist.txt)
9.9.9.255            1     1  documentation / test sentinel value (ipscrub allowlist or unit test)  (tools/test_core_double_vpn_path_hardening.py)
93.184.216.0         1     1  example.com IANA example host / range  (tools/test_extension_receipt_execution_custody.py)
96.30.204.0          1     1  documentation / test sentinel value (ipscrub allowlist or unit test)  (tools/ipscrub/ipscrub-allowlist.txt)
96.30.204.1          1     1  documentation / test sentinel value (ipscrub allowlist or unit test)  (tools/ipscrub/ipscrub-allowlist.txt)
96.30.205.255        1     1  documentation / test sentinel value (ipscrub allowlist or unit test)  (tools/ipscrub/ipscrub-allowlist.txt)
entries needing review: 0
```

### 4.4 Token-like strings (>= 32 chars of [A-Za-z0-9_-]) in non-test files

```
16162 occurrences in  630 files : identifier / contract name (words joined by _ or -)
  6289 occurrences in  218 files : hex digest / commit id
  1342 occurrences in  121 files : camel/Pascal-case identifier
   695 occurrences in   72 files : separator run of - or _
   198 occurrences in  176 files : UUID / GUID (provider, session, WFP or dummy ids)
   154 occurrences in   37 files : OTHER
    17 occurrences in    2 files : hex digest prefixed by a dash (table cell)
    16 occurrences in    1 files : go.sum / lockfile hash
     8 occurrences in    1 files : published donation wallet address (XMR/BTC/DASH) on the public website
     3 occurrences in    2 files : Windows SID
     2 occurrences in    2 files : alphabet / charset literal
     2 occurrences in    2 files : SSH public key body (public)
     2 occurrences in    1 files : model-API batch id
     1 occurrences in    1 files : SCREAMING_CASE identifier

OTHER distinct tokens (masked prefix, length, entropy, hits, files): 53
  abcdef...(63) e=5.98 n=2 files=2 ['tools/android_play_redemption_gate.py', 'tools/verify_apple_method_channel_contract.py']
  ABCDEF...(63) e=5.98 n=1 files=1 ['tools/ipscrub/ipscrub.py']
  SyD123...(35) e=5.13 n=1 files=1 ['tools/audit_git_history_for_secrets.py']
  TestSt...(48) e=4.73 n=1 files=1 ['docs/evidence/winn3_stages345_astra_study.md']
  V0lOU1...(48) e=4.63 n=1 files=1 ['docs/evidence/debate_round36_stage1_agy.md']
  everyP...(47) e=4.56 n=2 files=2 ['docs/evidence/round8_remediation/android-jvm-summary.json', 'docs/evidence/round8_remediation/results.json']
  winn1F...(39) e=4.50 n=1 files=1 ['tools/native_messaging/host/lib/winn_protocol_dispatch.dart']
  kWinn3...(34) e=4.48 n=2 files=1 ['tools/native_messaging/host/lib/winn_protocol_dispatch.dart']
  TestBa...(51) e=4.48 n=1 files=1 ['docs/evidence/winn3_stages345_astra_study.md']
  device...(52) e=4.47 n=1 files=1 ['tools/native_messaging/host/lib/winn_protocol_dispatch.dart']
  winn3-...(45) e=4.46 n=4 files=4 ['docs/evidence/debate_speed_stage1_antigravity.md', 'docs/evidence/debate_speed_stage2_opus5.md']
  TestBa...(33) e=4.45 n=1 files=1 ['docs/evidence/winn3_stages345_astra_study.md']
  kBrows...(41) e=4.45 n=5 files=1 ['tools/native_messaging/host/lib/browser_bridge_app_ipc.dart']
  TestBa...(41) e=4.43 n=1 files=1 ['docs/evidence/winn3_stages345_astra_study.md']
  Expect...(38) e=4.43 n=3 files=1 ['tools/android_public_release_live_smoke.ps1']
  browse...(37) e=4.43 n=8 files=1 ['tools/native_messaging/host/lib/browser_bridge_app_ipc.dart']
  TestWi...(59) e=4.41 n=1 files=1 ['tools/verify_apple_winn3_host_contract_harness.swift']
  winn3_...(59) e=4.41 n=1 files=1 ['tools/native_messaging/host/lib/winn_protocol_dispatch.dart']
  browse...(44) e=4.40 n=2 files=1 ['tools/native_messaging/host/lib/browser_bridge_app_ipc.dart']
  winn3_...(61) e=4.38 n=1 files=1 ['tools/native_messaging/host/lib/winn_protocol_dispatch.dart']
  _expir...(41) e=4.35 n=7 files=1 ['tools/native_messaging/host/lib/winn_protocol_dispatch.dart']
  _consu...(42) e=4.29 n=2 files=1 ['tools/native_messaging/host/lib/winn_protocol_dispatch.dart']
  WINS_D...(43) e=4.29 n=4 files=1 ['tools/verify_apple_readiness.sh']
  -Expec...(33) e=4.28 n=1 files=1 ['tools/windows_prefreeze_bind_exact_case.ps1']
  _burne...(36) e=4.27 n=8 files=1 ['tools/native_messaging/host/lib/winn_protocol_dispatch.dart']
  WINS_I...(47) e=4.26 n=7 files=5 ['docs/evidence/vpn-perf/fleet-v4/macos-session3.txt', 'docs/evidence/vpn-perf/fleet-v4/macos-session4.txt']
  _winn1...(39) e=4.22 n=10 files=1 ['tools/native_messaging/host/lib/winn_protocol_dispatch.dart']
  -Ackno...(35) e=4.18 n=2 files=2 ['tools/android_final_evidence_collector.py', 'tools/android_fresh_release_regression.ps1']
  -SelfT...(32) e=4.18 n=1 files=1 ['docs/blueprints/AI_HANDOFF_20260823.md']
  _apple...(41) e=4.18 n=1 files=1 ['tools/verify_apple_readiness.sh']
  _windo...(34) e=4.06 n=2 files=1 ['tools/native_messaging/host/lib/browser_bridge_app_ipc.dart']
  -disab...(34) e=4.06 n=2 files=1 ['extension/safari/README.md']
  _resol...(35) e=4.05 n=1 files=1 ['tools/verify_apple_method_channel_contract.py']
  -Expec...(33) e=4.04 n=1 files=1 ['tools/windows_prefreeze_bind_exact_case.ps1']
  _winn3...(36) e=4.04 n=6 files=3 ['docs/evidence/deepseek_round1_audit.md', 'docs/evidence/deepseek_round2_consensus.md']
  _freeA...(32) e=4.03 n=2 files=1 ['docs/CONTROL_PLANE_BOOTSTRAP_RESILIENCE.md']
  -Diagn...(36) e=4.02 n=1 files=1 ['tools/windows_split_tunnel_browser_live_cycle.ps1']
  -Diagn...(37) e=4.01 n=1 files=1 ['tools/windows_split_tunnel_browser_live_cycle.ps1']
  _asser...(33) e=4.00 n=3 files=1 ['tools/native_messaging/host/lib/browser_bridge_app_ipc.dart']
  _emitA...(36) e=3.99 n=1 files=1 ['tools/verify_apple_readiness.sh']
  _asser...(35) e=3.95 n=3 files=1 ['tools/native_messaging/host/lib/browser_bridge_app_ipc.dart']
  _refre...(36) e=3.95 n=1 files=1 ['docs/APPLE_APP_PRIVACY_LABEL_AUDIT.md']
  _erase...(35) e=3.94 n=2 files=1 ['tools/verify_apple_method_channel_contract.py']
  _kWinn...(33) e=3.94 n=2 files=1 ['tools/native_messaging/host/lib/winn_protocol_dispatch.dart']
  _parse...(35) e=3.91 n=2 files=1 ['tools/native_messaging/host/lib/browser_bridge_app_ipc.dart']
  _linux...(32) e=3.89 n=2 files=1 ['tools/native_messaging/host/lib/browser_bridge_app_ipc.dart']
  _kBrow...(33) e=3.87 n=2 files=1 ['tools/native_messaging/host/lib/browser_bridge_app_ipc.dart']
  _winn1...(33) e=3.84 n=10 files=1 ['tools/native_messaging/host/lib/winn_protocol_dispatch.dart']
  _kBrow...(36) e=3.81 n=2 files=1 ['tools/native_messaging/host/lib/browser_bridge_app_ipc.dart']
  elemen...(35) e=3.76 n=1 files=1 ['extension/tools/marionette.py']
  _chall...(35) e=3.68 n=2 files=2 ['extension/src/adapters/chromium.js', 'extension/src/adapters/firefox.js']
  n-----...(71) e=0.11 n=21 files=1 ['docs/evidence/round9_remediation/lane-checks.json']
  n-----...(81) e=0.10 n=1 files=1 ['tools/verify_release_legal_compliance.py']
```

The `OTHER` bucket was reviewed by hand: UUIDs (WFP/NetworkExtension/Apple provider identifiers, the WebSocket GUID constant, dummy 0000.../1111... ids), `-<sha256>` digest cells, SSH public keys (public), the website's published BTC/XMR/DASH donation addresses, OpenRouter batch ids, Dart/Swift identifiers, charset literals, and one self-test sample inside the repository's own secret scanner. No API key, bearer token, Cloudflare account or zone id, or private key remains.

### 4.5 Integrity of the copy

```
source tracked files in slice: 1832
copied: 1827 excluded: 5 missing: []
excluded files present in output: []
files in output not from the tracked list: []
unscrubbed files byte-identical to source: 1598
scrubbed files: 229 source lines touched by scrubs: 773
unexpected content differences: []
mode (executable bit) mismatches: []
line-ending count changes in scrubbed files: []
```

## 5. License finding

- Repository root: no `LICENSE`, `LICENSE.md` or `COPYING` file exists at the root of the worktree (checked with `git ls-files`). Nothing was invented or added.
- Inside this lane's directories: `legal/release/WINS_VPN_SOFTWARE_LICENSE.txt` (version 2026-08-25.v3) is the project's bundled proprietary end-user license: Copyright (C) 2025-2026 Win Empire LLC, all rights reserved; limited, personal, non-exclusive, non-transferable, revocable license to install and run the proprietary portions; no copying, sublicensing, distribution or derivative works of the proprietary portions; it states that it does not apply to third-party components or to Winn Protocol code distributed under an open-source license. `legal/release/SOURCE_OFFER.txt` states that the Winn Protocol v3 engine is offered under AGPL-3.0-or-later with a separate commercial license, and carries the GPL-2.0 written offer for amneziawg-tools and the MPL-2.0 source notices for Xray-core / amnezia-xray-core. `legal/release/licenses/` holds the Apache-2.0 and MIT texts for the bundled AmneziaWG components, and `legal/release/THIRD_PARTY_RUNTIME_NOTICES.txt` plus `docs/THIRD_PARTY_NOTICES_AND_COMPONENT_INVENTORY.md` inventory the components. All of these were copied as part of legal/ and docs/.
- Elsewhere in the repository (outside this lane, reported only, not copied): `winn_protocol_experimental/LICENSE` is the GNU Affero General Public License v3 text, `winn_protocol_experimental/NOTICE`, `winn_protocol_experimental/internal/masque/LICENSE`, and `installer/windows/licenses/*` (Wintun, Xray-core MPL-2.0, amneziawg MIT, amneziawg-tools GPL-2.0).
- The repository as a whole therefore has no single top-level license; the application code is proprietary (Win Empire LLC) and the Winn Protocol v3 engine is AGPL-3.0-or-later with a commercial option. The owner should decide what license file, if any, the public hackathon repository carries.

## 6. Not done / out of scope

- Nothing was pushed, published or committed. laneA, laneB and laneC were not touched.
- No file outside the worktree was read (in particular not ~/.winsvpn-secrets or any env/key file).
- Cross-lane consistency of the `app-cloud-sync.net` and `/Users/owner` placeholders is for the coordinator to align.

## Appendix A. gitleaks findings with reasons

| File | Line | Rule | Why it is a false positive |
|---|---|---|---|
| `docs/WINN3_THROUGHPUT_EVOLUTION_200MBPS_TO_1500MBPS.md` | 11 | generic-api-key | prose about the cipher suite (ML-KEM-768, Ed25519, ML-DSA-65); no value |
| `docs/evidence/round12_remediation/baseline.json` | 56 | jfrog-identity-token | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 57 | jfrog-identity-token | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 58 | jfrog-identity-token | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 63 | jfrog-identity-token | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 64 | jfrog-identity-token | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 65 | jfrog-identity-token | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 74 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 84 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 92 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 153 | jfrog-identity-token | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 155 | jfrog-identity-token | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 157 | jfrog-identity-token | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 161 | jfrog-identity-token | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 163 | jfrog-identity-token | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 165 | jfrog-identity-token | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 168 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 211 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 339 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 347 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 352 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 400 | jfrog-identity-token | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 423 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 457 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 483 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 501 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 585 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 881 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 883 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 907 | jfrog-identity-token | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 908 | jfrog-identity-token | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 913 | jfrog-identity-token | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1037 | jfrog-identity-token | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1060 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1101 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1155 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1304 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1350 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1398 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1415 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1419 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1490 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1493 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1494 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1516 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1542 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1574 | jfrog-identity-token | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1621 | jfrog-identity-token | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1622 | jfrog-identity-token | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1623 | jfrog-identity-token | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1717 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1737 | jfrog-identity-token | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1744 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1760 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1765 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1783 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1784 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1789 | jfrog-identity-token | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1815 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1832 | jfrog-identity-token | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1833 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1875 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1907 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1952 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1970 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1971 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1984 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 1999 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 2001 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 2010 | jfrog-identity-token | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 2023 | jfrog-identity-token | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 2124 | jfrog-identity-token | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 2200 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 2250 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 2495 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 2546 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 2547 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 2877 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 2878 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 2920 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 2921 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 2959 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 2960 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 2992 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 2993 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 3081 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 3082 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 3088 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 3089 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 3102 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 3103 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 3156 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 3157 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 3158 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 3180 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 3181 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 3246 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 3247 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 3252 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 3355 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 3356 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 3389 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 3401 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 3421 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 3422 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 3546 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 3553 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 3567 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 3657 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 3658 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 3687 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 3688 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 3736 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round12_remediation/baseline.json` | 3740 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/round4_remediation/source-manifest.json` | 9 | generic-api-key | file-inventory manifest: SHA-256 digest of a repository file keyed by a filename that contains Key/Secret; a digest, not a credential |
| `docs/evidence/vpn-perf/fleet-v4/windows-awg-show-after.txt` | 2 | generic-api-key | AWG 'public key:' line from a lab client; public by construction, endpoint already placeholdered |
| `tools/amneziawg_android_official_jni/uapi_adapt_test.go` | 9 | generic-api-key | upstream amneziawg-go unit-test fixture: the WireGuard documentation example key, not a project secret |
| `tools/amneziawg_android_official_jni/uapi_adapt_test.go` | 57 | generic-api-key | upstream amneziawg-go unit-test fixture: the WireGuard documentation example key, not a project secret |
| `tools/amneziawg_android_official_jni/uapi_adapt_test.go` | 69 | generic-api-key | upstream amneziawg-go unit-test fixture: the WireGuard documentation example key, not a project secret |
| `tools/android_public_release_live_smoke.ps1` | 57 | generic-api-key | SHA-256 digests of tools/release_secret_*.py source files in a pin table; gitleaks keyed on the word 'secret' in the file name |
| `tools/android_public_release_live_smoke.ps1` | 58 | generic-api-key | SHA-256 digests of tools/release_secret_*.py source files in a pin table; gitleaks keyed on the word 'secret' in the file name |
| `tools/audit_git_history_for_secrets.py` | 429 | generic-api-key | self-test fixture inside the repository's own secret scanner (assigned_secret sample string) |
| `tools/build_amneziawg_android_engine.sh` | 71 | generic-api-key | SHA-256 pins of upstream API files (UPSTREAM_API_SHA256 / OVERLAY_API_SHA256); digests |
| `tools/build_amneziawg_android_engine.sh` | 89 | generic-api-key | SHA-256 pins of upstream API files (UPSTREAM_API_SHA256 / OVERLAY_API_SHA256); digests |
| `tools/build_apple_engine_wrappers.sh` | 57 | jfrog-identity-token | 64-hex SHA-256 pin of a build input or upstream archive (variable name ends in SHA256); a digest, not a token |
| `tools/build_apple_wg_go_bridge.sh` | 61 | jfrog-identity-token | 64-hex SHA-256 pin of a build input or upstream archive (variable name ends in SHA256); a digest, not a token |
| `tools/build_apple_wg_go_bridge.sh` | 82 | jfrog-identity-token | 64-hex SHA-256 pin of a build input or upstream archive (variable name ends in SHA256); a digest, not a token |
| `tools/build_apple_wg_go_bridge.sh` | 83 | jfrog-identity-token | 64-hex SHA-256 pin of a build input or upstream archive (variable name ends in SHA256); a digest, not a token |
| `tools/build_apple_wg_go_bridge.sh` | 84 | jfrog-identity-token | 64-hex SHA-256 pin of a build input or upstream archive (variable name ends in SHA256); a digest, not a token |
| `tools/build_linux_release.sh` | 47 | jfrog-identity-token | 64-hex SHA-256 pin of a build input or upstream archive (variable name ends in SHA256); a digest, not a token |
| `tools/build_linux_release.sh` | 95 | jfrog-identity-token | 64-hex SHA-256 pin of a build input or upstream archive (variable name ends in SHA256); a digest, not a token |
| `tools/build_linux_release.sh` | 96 | jfrog-identity-token | 64-hex SHA-256 pin of a build input or upstream archive (variable name ends in SHA256); a digest, not a token |
| `tools/build_xray_engine.sh` | 88 | jfrog-identity-token | 64-hex SHA-256 pin of a build input or upstream archive (variable name ends in SHA256); a digest, not a token |
| `tools/build_xray_engine.sh` | 89 | jfrog-identity-token | 64-hex SHA-256 pin of a build input or upstream archive (variable name ends in SHA256); a digest, not a token |
| `tools/gcloud_custody_test.py` | 39 | private-key | PEM header string inside a unit-test fixture; the body is synthetic placeholder text, no key material (verified: no base64 body lines follow any PRIVATE KEY header in the slice) |
| `tools/gcloud_custody_test.py` | 64 | private-key | PEM header string inside a unit-test fixture; the body is synthetic placeholder text, no key material (verified: no base64 body lines follow any PRIVATE KEY header in the slice) |
| `tools/gcloud_custody_test.py` | 125 | private-key | PEM header string inside a unit-test fixture; the body is synthetic placeholder text, no key material (verified: no base64 body lines follow any PRIVATE KEY header in the slice) |
| `tools/gcp_proof_client/gcloud_custody_test.go` | 56 | private-key | PEM header string inside a unit-test fixture; the body is synthetic placeholder text, no key material (verified: no base64 body lines follow any PRIVATE KEY header in the slice) |
| `tools/gcp_proof_deploy_test.py` | 1190 | private-key | PEM header string inside a unit-test fixture; the body is synthetic placeholder text, no key material (verified: no base64 body lines follow any PRIVATE KEY header in the slice) |
| `tools/gcp_proof_evidence_test.py` | 21 | private-key | PEM header string inside a unit-test fixture; the body is synthetic placeholder text, no key material (verified: no base64 body lines follow any PRIVATE KEY header in the slice) |
| `tools/gcp_proof_live_probe_test.py` | 120 | private-key | PEM header string inside a unit-test fixture; the body is synthetic placeholder text, no key material (verified: no base64 body lines follow any PRIVATE KEY header in the slice) |
| `tools/inno-toolchain-pins.example.json` | 119 | generic-api-key | authenticode_leaf_sha256: SHA-256 of a public code-signing certificate; a digest |
| `tools/inno-toolchain-pins.json` | 119 | generic-api-key | authenticode_leaf_sha256: SHA-256 of a public code-signing certificate; a digest |
| `tools/mint_and_register_winn3_descriptors.py` | 272 | private-key | code that writes the PEM header for a key it generates at runtime; no key material in the file |
| `tools/public_release_gate.ps1` | 987 | jfrog-identity-token | 64-hex SHA-256 pin of a build input or upstream archive (variable name ends in SHA256); a digest, not a token |
| `tools/release_dependency_freeze.py` | 777 | generic-api-key | SHA-256 digests of tools/release_secret_*.py source files in a pin table; gitleaks keyed on the word 'secret' in the file name |
| `tools/release_dependency_freeze.py` | 778 | generic-api-key | SHA-256 digests of tools/release_secret_*.py source files in a pin table; gitleaks keyed on the word 'secret' in the file name |
| `tools/release_inno_toolchain_custody.ps1` | 40 | generic-api-key | authenticode_leaf_sha256: SHA-256 of a public code-signing certificate; a digest |
| `tools/release_inno_toolchain_custody.py` | 89 | generic-api-key | authenticode_leaf_sha256: SHA-256 of a public code-signing certificate; a digest |
| `tools/run_round36_surface_audit.py` | 205 | generic-api-key | prose about the cipher suite (ML-KEM-768, Ed25519, ML-DSA-65); no value |
| `tools/stage_apple_engine_artifacts.sh` | 34 | jfrog-identity-token | 64-hex SHA-256 pin of a build input or upstream archive (variable name ends in SHA256); a digest, not a token |
| `tools/test_apple_awg_31_producers.py` | 39 | jfrog-identity-token | 64-hex SHA-256 pin of a build input or upstream archive (variable name ends in SHA256); a digest, not a token |
| `tools/test_apple_awg_31_producers.py` | 41 | jfrog-identity-token | 64-hex SHA-256 pin of a build input or upstream archive (variable name ends in SHA256); a digest, not a token |
| `tools/test_apple_awg_31_producers.py` | 43 | jfrog-identity-token | 64-hex SHA-256 pin of a build input or upstream archive (variable name ends in SHA256); a digest, not a token |
| `tools/test_apple_awg_31_producers.py` | 44 | jfrog-identity-token | 64-hex SHA-256 pin of a build input or upstream archive (variable name ends in SHA256); a digest, not a token |
| `tools/test_apple_xray_runtime_hardening.py` | 32 | jfrog-identity-token | 64-hex SHA-256 pin of a build input or upstream archive (variable name ends in SHA256); a digest, not a token |
| `tools/test_core_installer_fix_wave_b.py` | 1612 | jfrog-identity-token | 64-hex SHA-256 pin of a build input or upstream archive (variable name ends in SHA256); a digest, not a token |
| `tools/test_deployment_runtime_configs.sh` | 683 | generic-api-key | Sec-WebSocket-Key handshake nonce in a probe/test fixture; a protocol nonce, not a credential |
| `tools/test_deployment_runtime_configs.sh` | 706 | generic-api-key | Sec-WebSocket-Key handshake nonce in a probe/test fixture; a protocol nonce, not a credential |
| `tools/test_deployment_runtime_configs.sh` | 1040 | generic-api-key | Sec-WebSocket-Key handshake nonce in a probe/test fixture; a protocol nonce, not a credential |
| `tools/test_extension_artifact_secret_privacy.py` | 293 | private-key | PEM header string inside a unit-test fixture; the body is synthetic placeholder text, no key material (verified: no base64 body lines follow any PRIVATE KEY header in the slice) |
| `tools/test_gcloud_custody.py` | 35 | private-key | PEM header string inside a unit-test fixture; the body is synthetic placeholder text, no key material (verified: no base64 body lines follow any PRIVATE KEY header in the slice) |
| `tools/test_gcloud_custody.py` | 60 | private-key | PEM header string inside a unit-test fixture; the body is synthetic placeholder text, no key material (verified: no base64 body lines follow any PRIVATE KEY header in the slice) |
| `tools/test_gcloud_custody.py` | 121 | private-key | PEM header string inside a unit-test fixture; the body is synthetic placeholder text, no key material (verified: no base64 body lines follow any PRIVATE KEY header in the slice) |
| `tools/test_linux_arch_release.py` | 76 | jfrog-identity-token | 64-hex SHA-256 pin of a build input or upstream archive (variable name ends in SHA256); a digest, not a token |
| `tools/test_linux_arch_release.py` | 77 | jfrog-identity-token | 64-hex SHA-256 pin of a build input or upstream archive (variable name ends in SHA256); a digest, not a token |
| `tools/test_linux_arm64_fallback.py` | 55 | jfrog-identity-token | 64-hex SHA-256 pin of a build input or upstream archive (variable name ends in SHA256); a digest, not a token |
| `tools/test_linux_arm64_fallback_elf.py` | 459 | generic-api-key | test fixture (HeaderProtectionKey= line in a synthetic config blob) |
| `tools/test_linux_cross_store_artifact_gate.py` | 455 | private-key | PEM header string inside a unit-test fixture; the body is synthetic placeholder text, no key material (verified: no base64 body lines follow any PRIVATE KEY header in the slice) |
| `tools/test_linux_store_engine_staging.py` | 1457 | private-key | PEM header string inside a unit-test fixture; the body is synthetic placeholder text, no key material (verified: no base64 body lines follow any PRIVATE KEY header in the slice) |
| `tools/test_native_standalone_gate.py` | 27 | generic-api-key | deterministic test key: base64 of the byte sequence 0x00..0x1f, synthetic by construction |
| `tools/test_private_release_symbol_hardening.py` | 647 | private-key | PEM header string inside a unit-test fixture; the body is synthetic placeholder text, no key material (verified: no base64 body lines follow any PRIVATE KEY header in the slice) |
| `tools/test_release_artifact_exact_secrets.py` | 42 | private-key | PEM header string inside a unit-test fixture; the body is synthetic placeholder text, no key material (verified: no base64 body lines follow any PRIVATE KEY header in the slice) |
| `tools/test_release_secret_scan_policy.py` | 107 | private-key | PEM header string inside a unit-test fixture; the body is synthetic placeholder text, no key material (verified: no base64 body lines follow any PRIVATE KEY header in the slice) |
| `tools/test_windows_zip_route_security.py` | 92 | jfrog-identity-token | 64-hex SHA-256 pin of a build input or upstream archive (variable name ends in SHA256); a digest, not a token |
| `tools/test_windows_zip_route_security.py` | 111 | jfrog-identity-token | 64-hex SHA-256 pin of a build input or upstream archive (variable name ends in SHA256); a digest, not a token |
| `tools/test_winn3_release_enablement.py` | 93 | generic-api-key | test constant: base64 of an ASCII marker string (dual-auth blob fixture) |
| `tools/verify_android_aab_signers.py` | 176 | generic-api-key | SHA-256 digest of the pinned keytool binary; a digest |
| `tools/verify_apple_tunnel_config.swift` | 9 | generic-api-key | deterministic test key: base64 of the byte sequence 0x00..0x1f, synthetic by construction |
| `tools/verify_apple_winn3_host_contract_harness.swift` | 79 | generic-api-key | deterministic test key: base64 of the byte sequence 0x00..0x1f, synthetic by construction |
| `tools/verify_apple_winn_seam_harness.swift` | 118 | generic-api-key | deterministic test key: base64 of the byte sequence 0x00..0x1f, synthetic by construction |
| `tools/verify_deployment_supply_chain.py` | 1198 | jfrog-identity-token | 64-hex SHA-256 pin of a build input or upstream archive (variable name ends in SHA256); a digest, not a token |
| `tools/verify_native_standalone_tests.sh` | 71 | generic-api-key | deterministic test key: base64 of the byte sequence 0x00..0x1f, synthetic by construction |
| `tools/website_download_publication.py` | 340 | generic-api-key | identifier/path expression referring to a trusted cosign public key file; no value |
| `tools/windows_spain_http_fingerprint_observation.py` | 42 | generic-api-key | Sec-WebSocket-Key handshake nonce in a probe/test fixture; a protocol nonce, not a credential |
| `tools/windows_spain_http_fingerprint_observation.py` | 42 | generic-api-key | Sec-WebSocket-Key handshake nonce in a probe/test fixture; a protocol nonce, not a credential |
| `tools/winn3_sign_announcement.py` | 135 | generic-api-key | code expression (ED25519_SPKI_PREFIX + public_raw); no value |
| `tools/winn3_sign_descriptor.py` | 374 | generic-api-key | code expression (ED25519_SPKI_PREFIX + public_raw); no value |
| `tools/xray_external_core_probe.sh` | 299 | jfrog-identity-token | 64-hex SHA-256 pin of a build input or upstream archive (variable name ends in SHA256); a digest, not a token |
| `tools/xray_external_core_probe.sh` | 300 | jfrog-identity-token | 64-hex SHA-256 pin of a build input or upstream archive (variable name ends in SHA256); a digest, not a token |

## Appendix B. `BEGIN ... PRIVATE KEY` hits (file:line)

```
tools/gcloud_custody.py:158
tools/fin_release_gate.sh:910
tools/fin_release_gate.sh:1338
tools/gcp_proof_fleet_test.py:1925
tools/gcp_proof_fleet.py:468
tools/test_fde_early_boot_network.py:355
tools/test_winn3_perf_bench.py:3268
tools/gcp_proof_evidence_test.py:21
tools/test_release_artifact_exact_secrets.py:42
tools/winn_release.py:1254
tools/release_secret_scan_policy.py:27
tools/release_secret_scan_policy.py:44
tools/gcp_proof_deploy.py:422
tools/validate_apple_owner_signoff.py:91
tools/test_windows_inno_compiler_custody.py:17
tools/test_windows_inno_compiler_custody.py:18
tools/test_linux_cross_store_artifact_gate.py:455
tools/gcloud_custody_test.py:39
tools/gcloud_custody_test.py:64
tools/gcloud_custody_test.py:125
tools/gcloud_custody_test.py:162
tools/gcloud_custody_test.py:168
tools/gcloud_custody_test.py:1626
tools/gcloud_custody_test.py:1833
tools/gcloud_custody_test.py:1840
tools/gcloud_custody_test.py:1924
tools/gcloud_custody_test.py:1938
tools/gcloud_custody_test.py:1950
tools/validate_release_artifact_privacy.py:3006
tools/gcp_proof_deploy_test.py:1190
tools/gcp_proof_remote_install.py:708
tools/provision_macos_release_go_runtime.sh:429
tools/run_round36_surface_audit.py:145
tools/gcp_proof_live_probe_test.py:120
tools/test_backup_recipients_provisioning.sh:116
tools/test_windows_installer_prerequisite_custody.py:25
tools/test_windows_installer_prerequisite_custody.py:26
tools/test_extension_artifact_secret_privacy.py:293
tools/test_release_secret_scan_policy.py:107
tools/test_linux_store_engine_staging.py:1457
tools/test_gcloud_custody.py:35
tools/test_gcloud_custody.py:60
tools/test_gcloud_custody.py:121
tools/test_gcloud_custody.py:158
tools/test_gcloud_custody.py:164
tools/test_gcloud_custody.py:908
tools/test_gcloud_custody.py:1075
tools/test_gcloud_custody.py:1082
tools/test_gcloud_custody.py:1166
tools/test_gcloud_custody.py:1180
tools/test_gcloud_custody.py:1192
tools/validate_apple_submission_package.py:630
tools/validate_apple_submission_package.py:842
tools/validate_apple_submission_package.py:4217
tools/audit_git_history_for_secrets.py:26
tools/test_winn_release.py:46
tools/test_winn_release.py:147
tools/website_security_audit.py:296
tools/test_private_release_symbol_hardening.py:647
tools/test_private_release_symbol_hardening.py:1882
tools/onetouch_tiers/cover_material.py:542
tools/mint_and_register_winn3_descriptors.py:272
tools/gcp_proof_client/gcloud_custody.go:47
tools/gcp_proof_client/gcloud_custody_test.go:56
tools/gcp_proof_client/gcloud_custody_test.go:280
tools/gcp_proof_client/gcloud_custody_test.go:293
extension/build.py:973
extension/tools/test_target_receipts.py:223
```

## Appendix C. `winsvpn-secrets` hits (file:line)

```
tools/refresh_live_role_secrets.ps1:104
tools/refresh_live_role_secrets.ps1:107
tools/refresh_live_role_secrets.ps1:111
tools/test_ops_secrets_file_mechanism.py:223
tools/test_ops_secrets_file_mechanism.py:258
tools/test_ops_secrets_file_mechanism.py:286
tools/test_ops_secrets_file_mechanism.py:471
tools/test_ops_secrets_file_mechanism.py:517
tools/test_ops_secrets_file_mechanism.py:575
tools/test_ops_secrets_file_mechanism.py:614
tools/test_ops_secrets_file_mechanism.py:617
tools/test_ops_secrets_file_mechanism.py:619
tools/test_paypal_empty_credentials_fail_closed.py:338
tools/gcp_proof_remote_action.py:151
tools/test_data_plane_low_findings.py:662
tools/test_deployment_reboot_resume.py:144
tools/restore_live_core_security_rollback.ps1:65
tools/restore_live_core_security_rollback.ps1:79
tools/test_data_plane_ia_dp_high.py:211
tools/test_data_plane_ia_dp_high.py:458
tools/test_data_plane_ia_dp_high.py:471
tools/test_server_xray_pin_fail_closed.py:475
tools/test_server_xray_pin_fail_closed.py:493
tools/test_core_reboot_pause_failure_hold.sh:36
tools/capture_live_infrastructure_rollback.ps1:49
tools/capture_live_infrastructure_rollback.ps1:61
tools/wins_deployment_preseed.ps1:752
tools/wins_deployment_preseed.ps1:799
tools/wins_deployment_preseed.ps1:817
tools/wins_deployment_preseed.ps1:939
tools/recover_live_admin_from_rollback.ps1:36
tools/gcp_proof_attempt_broker.py:142
tools/onetouch_tiers/tier_b_catalogue.py:35
tools/onetouch_tiers/linux/s7_tb09.sh:23
docs/HUB_BACKUP_RECOVERY_CONTRACT.md:18
docs/blueprints/AI_HANDOFF_20260823.md:73
docs/blueprints/AI_HANDOFF_20260823.md:78
docs/blueprints/WINS_VPN_COMPLETE_HANDOFF_BLUEPRINT.md:157
docs/blueprints/WINS_VPN_COMPLETE_HANDOFF_BLUEPRINT.md:164
docs/blueprints/WINS_VPN_COMPLETE_HANDOFF_BLUEPRINT.md:171
docs/blueprints/WINS_VPN_COMPLETE_HANDOFF_BLUEPRINT.md:172
docs/blueprints/WINS_VPN_COMPLETE_HANDOFF_BLUEPRINT.md:183
docs/runbooks/HUB_COMPROMISE_G3_RECOVERY.md:107
docs/runbooks/HUB_COMPROMISE_G3_RECOVERY.md:118
docs/runbooks/HUB_COMPROMISE_G3_RECOVERY.md:283
docs/runbooks/HUB_COMPROMISE_G3_RECOVERY.md:344
docs/runbooks/HUB_COMPROMISE_G3_RECOVERY.md:345
docs/runbooks/HUB_COMPROMISE_G3_RECOVERY.md:592
docs/runbooks/HUB_COMPROMISE_G3_RECOVERY.md:606
docs/audit/DEEP_AUDIT_PROMPT.md:46
```

## Appendix D. `AuthKey_` hits (file:line)

```
tools/test_apple_app_store_connect_auth_probe.py:158
tools/validate_apple_owner_signoff.py:92
tools/apple_runtime_smoke.sh:896
tools/apple_runtime_smoke.sh:901
tools/macos_release_python_runtime_production.py:1180
tools/apple_upload_exact_release_candidates.py:1528
tools/apple_upload_exact_release_candidates.py:1579
tools/validate_apple_submission_package.py:631
tools/validate_apple_submission_package.py:843
tools/validate_apple_submission_package.py:4218
tools/test_apple_watch_release_integration.py:297
tools/test_apple_watch_release_integration.py:437
docs/blueprints/AI_HANDOFF_20260823.md:50
docs/blueprints/AI_HANDOFF_20260823.md:104
docs/blueprints/AI_HANDOFF_20260823.md:268
docs/blueprints/WINS_VPN_COMPLETE_HANDOFF_BLUEPRINT.md:122
docs/evidence/vpn-perf/fleet-v4/t-i-report.md:70
```

## Appendix E. files mentioning `garble`

```
tools/android_play_redemption_gate.py
tools/build_winn_protocol_engine.sh
tools/test_release_obfuscation_contract.py
tools/test_winn_garble_website_engines.py
tools/windows_winn3_artifact_provenance.py
tools/winn_garble_pin.json
tools/winn_release.py
```

