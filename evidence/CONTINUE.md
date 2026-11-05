# CONTINUE.md - Lane E (submission materials)

HARVEST-3 / POST-DEMO EXPORT pass complete 2026-08-17 ~12:15 EDT. The demo has
ALREADY RAN on the live stack (router /decisions ring holds the first real
Gemini decision + demo-video keep/switch records). The evidence index, runbook,
zip manifest, and post-demo exports are on disk. What remains is the physical
phone tunnel-up, the owner's video-session captures, the owner's finance
figures, and the final zip.

## What this pass changed (resume-relevant)

- Round-3 live harvest saved (evidence/live/*-20260817T155725Z.json) and
  router-decisions.json/.csv/-curl.txt captured POST-demo (canonical 21-row
  export with both keep [STABLE_LINK, LATENCY_OPTIMIZED] and the demo switch;
  first real Gemini decision id af13acd1ebea11fa). The live ring later flooded
  with the video lane's gem-poll loop + take4 pair; that state was preserved at
  live/decisions-20260817T161425Z.json/.csv and is NOT the demo export.
- CRITICAL: the debug APK was REBUILT at 12:00 EDT by the Android lane (same
  v1.0.15, versionCode 32, same winn/3 defines + G1 ring; installed on the
  phone 12:01, matches apk/ copy). New sha256
  3e9c461f0b93085d1027b7b21e1a0930824a1fb6ecaf396864f5fcf1ff6cb3e0. Every doc
  that named the old 106ec293... value was updated. apk-sha256.txt rewritten.
- New PRESENT rows: preflight.txt, gateway-verify-a/b.txt, apk-sha256.txt,
  winn3-descriptor-ring.txt, README_INDEX.md (was referenced but missing),
  secret-scan-output.txt (gitleaks 8.30.1 over pb_release/repo, 0 findings).
  All 84 PRESENT-row manifest sources verified on disk.
- Phone app reached the main screen (server list + Connect VPN button, Status:
  Disconnected) but logcat through 12:18 EDT still shows engineReady=false
  vpnPresent=false; phone_bootstrap_ping.txt (10.10.0.1, 25x, all 100% loss)
  confirms the tunnel is not carrying inner traffic: phone-tunnel-up.txt stays
  genuinely PENDING.

## OWNER-REQUIRED (cannot be done by this lane)

1. Physical phone tunnel-up (gate for the whole impairment take). Logcat must
   show winn/3 handshake/carrying and bootstrap ping to 10.10.0.1 must succeed
   (currently 100% loss). The phone lane is on it; once up, save
   evidence/phone-tunnel-up.txt (checklist step 8).
2. Video session captures (in flight at 12:15 EDT): phone-01..08.png,
   router-dashboard-switch.mp4 (one unbroken 15s take: keep card ->
   /admin/health flip -> card flips to demo-route-b -> phone reconnects ->
   IP DEMO_ROUTE_B_IP), hoppy-escalation.log. Save every slug-named file into
   $HOME/xprize/evidence/.
3. Post-demo exports: hub-admin-state.txt (GET /admin/state with the demo key),
   router-decisions.jsonl (copy off Cloud Run), hub-nodes.png,
   cloud-run-logs-route-demo-003.png + cloud-run-logs-1/2.png +
   cloud-run-service.png + cloud-logging-query.png, gce-vm-list.png,
   artifact-registry.png, secret-manager.png (names only).
   secret-scan-output.txt is DONE (lane E, 12:17 EDT, 0 findings).
4. apk-sha256.txt is DONE (3e9c461f...); copy the APK itself into evidence/ if
   you want the zip to carry it next to the hash (optional, it already ships
   from apk/).
5. Fill every OWNER-FILL box in REVENUE_TEMPLATE.md before 4:00 PM EDT (one-stop
   list at the top; $0 plainly where zero).
6. Create the private GitHub repo per REPO_PLAN.md; run the exact gitleaks
   command (`gitleaks detect --source . --no-git --redact -r evidence/secret-scan-output.txt`);
   push only after zero findings; save the verbatim output to
   evidence/secret-scan-output.txt (checklist step 11).
7. Confirm the Devpost category name (recommended Education & Human Potential)
   and launch date precision ("end of June 2026") at submission time.
8. Zip per EVIDENCE_ZIP.md ONLY after every PENDING row is PRESENT; re-run
   gitleaks against the staged contents before shipping.

## Next actions this lane can take when unblocked

- After the take: re-export GET /decisions to a final frozen
  router-decisions.json if you prefer a state not flooded by the gem-poll
  loop (optional; the shipped export already proves both scenarios).
- Once phone-tunnel-up.txt exists, confirm the checklist cross-checks (request_id
  match across the .json export, the Cloud Run console screenshot, and the
  dashboard take).
- Build the zip from the manifest command block and update this file.

## Lane guardrails (still binding)

No git commands from this lane. No writes outside $HOME/xprize/evidence/.
No production systems contacted (only the public router URL and the staging hub
<STAGING_HUB_IP>). No invented numbers; finance stays OWNER-FILL. No secrets or
private keys referenced beyond their names; never capture the X-Demo-Key value,
the GCP API key, or any state.json carrying device static keys.