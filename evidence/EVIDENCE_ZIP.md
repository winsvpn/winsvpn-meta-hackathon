# EVIDENCE_ZIP.md - manifest for the judges' evidence attachment

Do not zip yet. This is the exact file list for `winsvpn-evidence-20260817.zip`.
Build it by running the `zip` command block at the bottom once every file below is
marked PRESENT. Every file is public-safe: no secrets, no API keys, no admission
key values, no g1.pem, no descriptor envelope contents, no device static private
keys. Where a receipt exists in two trees, only one copy ships.

Status legend: PRESENT = on disk now and included. PENDING = must be captured in
the owner's video session before 12:15 PM EDT (EVIDENCE_CHECKLIST slug). LARGE =
present but big; include at owner discretion.

## 00_submission (always ships)

| zip path | source | status |
|---|---|---|
| 00_submission/SUBMISSION_DRAFT.md | evidence/SUBMISSION_DRAFT.md | PRESENT |
| 00_submission/VIDEO_SCRIPT.md | evidence/VIDEO_SCRIPT.md | PRESENT |
| 00_submission/REVENUE_TEMPLATE.md | evidence/REVENUE_TEMPLATE.md | PRESENT |
| 00_submission/EVIDENCE_CHECKLIST.md | evidence/EVIDENCE_CHECKLIST.md | PRESENT |
| 00_submission/REPO_PLAN.md | evidence/REPO_PLAN.md | PRESENT |
| 00_submission/FACTS.md | evidence/FACTS.md | PRESENT |
| 00_submission/DEMO_RUNBOOK.md | evidence/DEMO_RUNBOOK.md | PRESENT |
| 00_submission/EVIDENCE_PACK.md | evidence/EVIDENCE_PACK.md | PRESENT |
| 00_submission/EVIDENCE_ZIP.md | evidence/EVIDENCE_ZIP.md | PRESENT |
| 00_submission/README_INDEX.md | evidence/README_INDEX.md (created from EVIDENCE_PACK.md + live/CAPTURE.md; present on disk since 2026-08-17 12:0x EDT) | PRESENT |

## 01_live_receipts (always ships)

| zip path | source | status |
|---|---|---|
| 01_live_receipts/CAPTURE.md | evidence/live/CAPTURE.md | PRESENT |
| 01_live_receipts/decisions-20260817T145454Z.json | evidence/live/decisions-20260817T145454Z.json | PRESENT (pre-demo baseline, empty ring) |
| 01_live_receipts/stats-20260817T145455Z.json | evidence/live/stats-20260817T145455Z.json | PRESENT |
| 01_live_receipts/router-health-20260817T145514Z.json | evidence/live/router-health-20260817T145514Z.json | PRESENT |
| 01_live_receipts/hub-nodes-20260817T145456Z.json | evidence/live/hub-nodes-20260817T145456Z.json | PRESENT |
| 01_live_receipts/hub-free-status-20260817T145456Z.json | evidence/live/hub-free-status-20260817T145456Z.json | PRESENT |
| 01_live_receipts/decisions-20260817T154010Z.json | evidence/live/decisions-20260817T154010Z.json | PRESENT (round 2, ring still pre-demo empty) |
| 01_live_receipts/stats-20260817T154010Z.json | evidence/live/stats-20260817T154010Z.json | PRESENT |
| 01_live_receipts/router-health-20260817T154010Z.json | evidence/live/router-health-20260817T154010Z.json | PRESENT |
| 01_live_receipts/hub-nodes-20260817T154010Z.json | evidence/live/hub-nodes-20260817T154010Z.json | PRESENT |
| 01_live_receipts/hub-free-status-20260817T154010Z.json | evidence/live/hub-free-status-20260817T154010Z.json | PRESENT |
| 01_live_receipts/hub-verify-cached-20260817T154019Z.json | evidence/live/hub-verify-cached-20260817T154019Z.json | PRESENT (cached Gemini decision timing receipt, redacted) |
| 01_live_receipts/verify-demo-gw-a.status.log | evidence/live/verify-demo-gw-a.status.log | PRESENT |
| 01_live_receipts/verify-demo-gw-b.status.log | evidence/live/verify-demo-gw-b.status.log | PRESENT |
| 01_live_receipts/soak-demo-gw-a.receipt.txt | evidence/live/soak-demo-gw-a.receipt.txt | PRESENT |
| 01_live_receipts/soak-demo-gw-b.receipt.txt | evidence/live/soak-demo-gw-b.receipt.txt | PRESENT |
| 01_live_receipts/decisions-20260817T155725Z.json | evidence/live/decisions-20260817T155725Z.json | PRESENT (round 3, POST-demo: ring populated with the first real Gemini decision + demo-video keep/switch) |
| 01_live_receipts/stats-20260817T155725Z.json | evidence/live/stats-20260817T155725Z.json | PRESENT (round 3, total=10, gemini 2 / fallback 8) |
| 01_live_receipts/router-health-20260817T155725Z.json | evidence/live/router-health-20260817T155725Z.json | PRESENT (round 3, ok=true, gemini-3-flash-preview) |
| 01_live_receipts/hub-nodes-20260817T155725Z.json | evidence/live/hub-nodes-20260817T155725Z.json | PRESENT (round 3, both nodes reachable, latency 2ms/32ms) |
| 01_live_receipts/hub-free-status-20260817T155725Z.json | evidence/live/hub-free-status-20260817T155725Z.json | PRESENT (round 3, free_access=true) |

## 02_gateway_soak (always ships)

| zip path | source | status |
|---|---|---|
| 02_gateway_soak/soak-demo-gw-a.receipt.txt | evidence/gateway_soak/soak-demo-gw-a.receipt.txt | PRESENT |
| 02_gateway_soak/soak-demo-gw-a.status.log | evidence/gateway_soak/soak-demo-gw-a.status.log | PRESENT |
| 02_gateway_soak/soak-demo-gw-b.receipt.txt | evidence/gateway_soak/soak-demo-gw-b.receipt.txt | PRESENT |
| 02_gateway_soak/soak-demo-gw-b.status.log | evidence/gateway_soak/soak-demo-gw-b.status.log | PRESENT |
| 02_gateway_soak/soak.py | evidence/gateway_soak/soak.py | PRESENT |

## 03_router (always ships)

| zip path | source | status |
|---|---|---|
| 03_router/prod_sanity.txt | router/receipts/prod_sanity.txt | PRESENT |
| 03_router/prod_sanity.sh | router/receipts/prod_sanity.sh | PRESENT |
| 03_router/README.md | router/README.md | PRESENT |
| 03_router/test_router.py | router/tests/test_router.py | PRESENT |
| 03_router/router-decisions.json | evidence/router-decisions.json | PRESENT (canonical 21-row POST-demo export, 15:57-15:58Z: first real Gemini decision af13acd1ebea11fa keep [STABLE_LINK, LATENCY_OPTIMIZED] + demo-video-* keep/switch; re-export at end of the take optional) |
| 03_router/router-decisions.csv | evidence/router-decisions.csv | PRESENT (rebuilt from the canonical export, same 21 rows) |
| 03_router/router-decisions.jsonl | evidence/router-decisions.jsonl | PENDING (copy off Cloud Run) |

## 04_staging_hub (always ships)

| zip path | source | status |
|---|---|---|
| 04_staging_hub/README.md | staging-hub/README.md | PRESENT |
| 04_staging_hub/FIELD_MAP.md | staging-hub/FIELD_MAP.md | PRESENT |
| 04_staging_hub/SUPERVISOR_NOTES.md | staging-hub/SUPERVISOR_NOTES.md | PRESENT |
| 04_staging_hub/hub-admin-state.txt | evidence/hub-admin-state.txt | PENDING (GET /admin/state, no key material) |
| 04_staging_hub/hub-nodes.png | evidence/hub-nodes.png | PENDING |

Signed descriptor envelopes (staging-hub/descriptors/*.json) are EXCLUDED: the
signed payload embeds `admission_secret`. Their existence and hashes are proven by
the ceremony record in 05_gateway_lane instead.

## 05_gateway_lane (always ships)

| zip path | source | status |
|---|---|---|
| 05_gateway_lane/SUPERVISOR_2026-08-17_PUBSUMMARY_gateway-public-material.md | pb_gateway/receipts/SUPERVISOR_2026-08-17_PUBSUMMARY_gateway-public-material.md | PRESENT |
| 05_gateway_lane/SUPERVISOR_2026-08-17_descriptor-ceremony-record.md | pb_gateway/receipts/SUPERVISOR_2026-08-17_descriptor-ceremony-record.md | PRESENT |
| 05_gateway_lane/SUPERVISOR_2026-08-17_verify-demo-gw-a.log | pb_gateway/receipts/SUPERVISOR_2026-08-17_verify-demo-gw-a.log | PRESENT |
| 05_gateway_lane/SUPERVISOR_2026-08-17_verify-demo-gw-b.log | pb_gateway/receipts/SUPERVISOR_2026-08-17_verify-demo-gw-b.log | PRESENT |
| 05_gateway_lane/GATEWAY-A_2026-08-17_hardening-inspection.txt | pb_gateway/receipts/GATEWAY-A_2026-08-17_hardening-inspection.txt | PRESENT |
| 05_gateway_lane/GATEWAY-B_2026-08-17_hardening-inspection.txt | pb_gateway/receipts/GATEWAY-B_2026-08-17_hardening-inspection.txt | PRESENT |
| 05_gateway_lane/LANE_2026-08-17_rotation-e2e-test.log | pb_gateway/receipts/LANE_2026-08-17_rotation-e2e-test.log | PRESENT |

## 06_nodes (always ships)

| zip path | source | status |
|---|---|---|
| 06_nodes/winn3-gateway-linux-amd64 + .sha256 | awg-nodes/out/winn3-gateway-linux-amd64, awg-nodes/out/winn3-gateway-linux-amd64.sha256 | PRESENT |
| 06_nodes/winn-datapath-linux-amd64 + .sha256 | awg-nodes/out/winn-datapath-linux-amd64, awg-nodes/out/winn-datapath-linux-amd64.sha256 | PRESENT |
| 06_nodes/winn3-demo-material-linux-amd64 + .sha256 | awg-nodes/out/winn3-demo-material-linux-amd64, awg-nodes/out/winn3-demo-material-linux-amd64.sha256 | PRESENT |
| 06_nodes/PUBSUMMARY.md | awg-nodes/keys/PUBSUMMARY.md | PRESENT |
| 06_nodes/deploy_and_verify.sh | awg-nodes/deploy_and_verify.sh | PRESENT |
| 06_nodes/provision_gw.sh | awg-nodes/provision_gw.sh | PRESENT |

No key files (client.key, winn3-gateway-static.key, winn3-gateway-admission.key,
cover/, client.pub only where it is the public half and already in PUBSUMMARY).

## 07_phone (always ships)

| zip path | source | status |
|---|---|---|
| 07_phone/apk-sha256.txt | evidence/apk-sha256.txt | PRESENT (shasum -a 256 apk/app-phone-debug.apk = 3e9c461f0b93085d1027b7b21e1a0930824a1fb6ecaf396864f5fcf1ff6cb3e0; APK rebuilt 12:00 EDT, same v1.0.15 + defines) |
| 07_phone/winn3-descriptor-ring.txt | evidence/winn3-descriptor-ring.txt | PRESENT (G1 pubkey + ring sha256 from the compiled APK; SUP confirms) |
| 07_phone/app-phone-debug.apk | apk/app-phone-debug.apk | PRESENT LARGE (158 MB; the installable judges need; keep) |
| 07_phone/ios_device_install.txt | pb_ios/receipts/ios_device_install.txt | PRESENT |
| 07_phone/owner_consent_runbook.md | pb_ios/receipts/owner_consent_runbook.md | PRESENT |
| 07_phone/devicectl_devices.txt | pb_ios/receipts/devicectl_devices.txt | PRESENT |
| 07_phone/ios_build.txt | pb_ios/receipts/ios_build.txt | PRESENT |
| 07_phone/macos_build_dev_dbg.txt | pb_ios/receipts/macos_build_dev_dbg.txt | PRESENT |
| 07_phone/profiles_matrix.md | pb_ios/receipts/profiles_matrix.md | PRESENT |
| 07_phone/engine_staging/artifact_provenance.txt | pb_ios/receipts/engine_staging/artifact_provenance.txt | PRESENT |
| 07_phone/tests.txt | pb_ios/receipts/tests.txt | PRESENT |
| 07_phone/phone-tunnel-up.txt | evidence/phone-tunnel-up.txt | PENDING (logcat winn3 handshake/carrying tail) |

## 08_android (always ships)

| zip path | source | status |
|---|---|---|
| 08_android/stage_before_sha256.txt | android/stage_before_sha256.txt | PRESENT |
| 08_android/stage_after_sha256.txt | android/stage_after_sha256.txt | PRESENT |
| 08_android/release_compile_proof.md | android/receipts/release_compile_proof.md | PRESENT |
| 08_android/upload_key_proof.md | android/receipts/upload_key_proof.md | PRESENT |

## 09_platform_lanes (always ships)

| zip path | source | status |
|---|---|---|
| 09_platform_lanes/linux/provenance_hashes_20260817.txt | pb_linux/evidence/provenance_hashes_20260817.txt | PRESENT |
| 09_platform_lanes/linux/verify_provenance.py | pb_linux/evidence/verify_provenance.py | PRESENT |
| 09_platform_lanes/watch/lipo_repro_verdict.md | pb_watch/receipts/lipo_repro_verdict.md | PRESENT |
| 09_platform_lanes/watch/lipo_repro.txt | pb_watch/receipts/lipo_repro.txt | PRESENT LARGE |
| 09_platform_lanes/watch/watch_sim_running.png | pb_watch/receipts/watch_sim_running.png | PRESENT |
| 09_platform_lanes/watch/wear_unit.log | pb_watch/receipts/wear_unit.log | PRESENT |
| 09_platform_lanes/windows/01_candidate_tree_copy.txt | pb_windows/receipts/01_candidate_tree_copy.txt | PRESENT |
| 09_platform_lanes/windows/02_verify_native_standalone_tests.txt | pb_windows/receipts/02_verify_native_standalone_tests.txt | PRESENT |
| 09_platform_lanes/windows/03_win32_six_units_msvc_compile.txt | pb_windows/receipts/03_win32_six_units_msvc_compile.txt | PRESENT |
| 09_platform_lanes/windows/04_pwsh_selftests.txt | pb_windows/receipts/04_pwsh_selftests.txt | PRESENT |
| 09_platform_lanes/windows/05_python_freezes_winpc.txt | pb_windows/receipts/05_python_freezes_winpc.txt | PRESENT |
| 09_platform_lanes/windows/06_stage_vc_redist_payload_stage.txt | pb_windows/receipts/06_stage_vc_redist_payload_stage.txt | PRESENT |
| 09_platform_lanes/windows/07_build_installer_attempt_blocked.txt | pb_windows/receipts/07_build_installer_attempt_blocked.txt | PRESENT |
| 09_platform_lanes/windows/08_python_suites_pass3.txt | pb_windows/receipts/08_python_suites_pass3.txt | PRESENT |
| 09_platform_lanes/hub/suites_run.txt | pb_hub/receipts/suites_run.txt | PRESENT |

## 10_release_lane (always ships)

| zip path | source | status |
|---|---|---|
| 10_release_lane/repo_scan_report.html | pb_release/repo_scan_report.html | PRESENT (gitleaks: zero findings) |
| 10_release_lane/repo_scan.json | pb_release/repo_scan.json | PRESENT (`[]`) |
| 10_release_lane/secret-scan-output.txt | evidence/secret-scan-output.txt | PRESENT (gitleaks 8.30.1 over pb_release/repo, 12:17 EDT 2026-08-17: 0 findings, json=[]) |
| 10_release_lane/inventories/run1.txt | pb_release/inventories/run1.txt | PRESENT |

## 11_checklist_captures (PENDING until the video session - EVIDENCE_CHECKLIST slugs)

| zip path | source | status |
|---|---|---|
| 11_checklist_captures/preflight.txt | evidence/preflight.txt | PRESENT (lane E, 12:13 EDT 2026-08-17: router /health + hub /nodes + per-node reachable=true) |
| 11_checklist_captures/phone-01-serverlist.png | evidence/phone-01-serverlist.png | PENDING |
| 11_checklist_captures/phone-02-connected-a.png | evidence/phone-02-connected-a.png | PENDING |
| 11_checklist_captures/phone-03-ip-a.png | evidence/phone-03-ip-a.png | PENDING |
| 11_checklist_captures/phone-04-impairment.png | evidence/phone-04-impairment.png | PENDING |
| 11_checklist_captures/phone-05-reconnected-b.png | evidence/phone-05-reconnected-b.png | PENDING |
| 11_checklist_captures/phone-06-ip-b.png | evidence/phone-06-ip-b.png | PENDING |
| 11_checklist_captures/phone-07-calculator.png | evidence/phone-07-calculator.png | PENDING |
| 11_checklist_captures/phone-08-hoppy.png | evidence/phone-08-hoppy.png | PENDING |
| 11_checklist_captures/router-dashboard-switch.mp4 | evidence/router-dashboard-switch.mp4 | PENDING (one unbroken 15s take) |
| 11_checklist_captures/gateway-verify-a.txt | evidence/gateway-verify-a.txt | PRESENT (hub-VM verifier status log vs demo-route-a, same provenance as live/ round 1; handshake + carrying, NAT egress layers in the soak receipt) |
| 11_checklist_captures/gateway-verify-b.txt | evidence/gateway-verify-b.txt | PRESENT (hub-VM verifier status log vs demo-route-b, same provenance as live/ round 1) |
| 11_checklist_captures/cloud-run-logs-route-demo-003.png | evidence/cloud-run-logs-route-demo-003.png | PENDING |
| 11_checklist_captures/cloud-run-logs-1.png | evidence/cloud-run-logs-1.png | PENDING |
| 11_checklist_captures/cloud-run-logs-2.png | evidence/cloud-run-logs-2.png | PENDING |
| 11_checklist_captures/cloud-run-service.png | evidence/cloud-run-service.png | PENDING |
| 11_checklist_captures/cloud-logging-query.png | evidence/cloud-logging-query.png | PENDING |
| 11_checklist_captures/gce-vm-list.png | evidence/gce-vm-list.png | PENDING |
| 11_checklist_captures/artifact-registry.png | evidence/artifact-registry.png | PENDING |
| 11_checklist_captures/secret-manager.png | evidence/secret-manager.png | PENDING (names only) |
| 11_checklist_captures/hoppy-escalation.log | evidence/hoppy-escalation.log | PENDING |

## 12_business (always ships)

| zip path | source | status |
|---|---|---|
| 12_business/nonprofit-certificate.pdf | evidence/nonprofit-certificate.pdf | PENDING (read-only copy of WIN'S VPN INC Certificate.pdf) |

## Exclusions (never in the zip)

- staging-hub/descriptors/*.json (signed payload embeds admission_secret)
- awg-nodes/keys/* private files, cover/, winn3-gateway-admission.key,
  winn3-gateway-static.key, client.key
- Any state.json carrying device static keys (hub /srv/hub/state.json, client
  capture state.json in source trees). The two dashboard/state.json status files
  have no device keys and are not needed in the zip.
- g1.pem, X-Demo-Key value, GCP API keys, service-account JSON, .env.
- The judged source repo itself (delivered separately on GitHub per REPO_PLAN.md).
- router/tests and staging-hub/tests full trees are already represented by their
  receipts; include only the receipts in the zip.

## Zip command (run ONLY after every PENDING row is PRESENT)

```bash
cd $HOME/xprize
zip -r winsvpn-evidence-20260817.zip \
  evidence/SUBMISSION_DRAFT.md evidence/VIDEO_SCRIPT.md evidence/REVENUE_TEMPLATE.md \
  evidence/EVIDENCE_CHECKLIST.md evidence/REPO_PLAN.md evidence/FACTS.md \
  evidence/DEMO_RUNBOOK.md evidence/EVIDENCE_PACK.md evidence/EVIDENCE_ZIP.md \
  evidence/README_INDEX.md \
  evidence/live/ evidence/gateway_soak/ \
  router/receipts/prod_sanity.txt router/receipts/prod_sanity.sh router/README.md \
  router/tests/test_router.py \
  staging-hub/README.md staging-hub/FIELD_MAP.md staging-hub/SUPERVISOR_NOTES.md \
  pb_gateway/receipts/ awg-nodes/out/ awg-nodes/keys/PUBSUMMARY.md \
  awg-nodes/deploy_and_verify.sh awg-nodes/provision_gw.sh \
  apk/app-phone-debug.apk pb_ios/receipts/ios_device_install.txt \
  pb_ios/receipts/owner_consent_runbook.md pb_ios/receipts/devicectl_devices.txt \
  pb_ios/receipts/ios_build.txt pb_ios/receipts/macos_build_dev_dbg.txt \
  pb_ios/receipts/profiles_matrix.md pb_ios/receipts/engine_staging/artifact_provenance.txt \
  pb_ios/receipts/tests.txt android/stage_before_sha256.txt android/stage_after_sha256.txt \
  android/receipts/release_compile_proof.md android/receipts/upload_key_proof.md \
  pb_linux/evidence/ pb_watch/receipts/lipo_repro_verdict.md \
  pb_watch/receipts/lipo_repro.txt pb_watch/receipts/watch_sim_running.png \
  pb_watch/receipts/wear_unit.log pb_windows/receipts/ pb_hub/receipts/suites_run.txt \
  pb_release/repo_scan_report.html pb_release/repo_scan.json \
  pb_release/inventories/run1.txt \
  evidence/preflight.txt evidence/router-decisions.json evidence/router-decisions.csv \
  evidence/router-decisions.jsonl evidence/hub-admin-state.txt evidence/hub-nodes.png \
  evidence/gateway-verify-a.txt evidence/gateway-verify-b.txt evidence/phone-tunnel-up.txt \
  evidence/phone-0*.png evidence/phone-1*.png evidence/router-dashboard-switch.mp4 \
  evidence/cloud-run-*.png evidence/gce-vm-list.png evidence/artifact-registry.png \
  evidence/secret-manager.png evidence/hoppy-escalation.log evidence/apk-sha256.txt \
  evidence/winn3-descriptor-ring.txt evidence/secret-scan-output.txt \
  evidence/nonprofit-certificate.pdf
```

Run `gitleaks detect --source . --no-git --redact -r evidence/secret-scan-output.txt`
against the staged zip contents before shipping.