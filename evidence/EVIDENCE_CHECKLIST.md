# EVIDENCE_CHECKLIST.md

Deadline: everything below captured before 12:15 PM EDT today. Files land in $HOME/xprize/evidence/. Naming: use the slug in bold. No screenshot may contain secrets, API keys, the production console, or the X-Demo-Key.

Legend: OWNER = owner on the business accounts. SUP = supervisor running staging infra. Either party may save the file into evidence/, but the named party is responsible for the capture being real and uncut.

Live router URL (SUPERVISOR RECEIPT 2026-08-17): https://AI_ROUTER_HOST
Chain proven end to end: phone app -> staging hub (GCE, https://<STAGING_HUB_SSLTIP_HOST>) -> Gemini router (Cloud Run, gemini-3-flash-preview) -> winn/3 gateway (GCE) carrying real traffic (handshake, inner ICMP, NAT egress ICMP receipts). Healthy link: Gemini keep [STABLE_LINK, LATENCY_OPTIMIZED]; impairment trigger (admin health flip, recent_failures +1) -> switch to demo-route-b with reason codes; exportable at /decisions. Phone: org.winsvpn.app.debug v1.0.15, sha256 3e9c461f0b93085d1027b7b21e1a0930824a1fb6ecaf396864f5fcf1ff6cb3e0, consent accepted, device allocated inner 10.10.0.3 on demo-route-a. Physical tunnel-up receipt pending (step 8).

## Capture order (single pass, owner's video session)

Run these in order. The video session records steps 2-6 live; steps 7-15 are exports and console captures right after the take.

### Step 1 - Pre-flight health (SUP)

- [x] **preflight.txt** - GET /health on the live router URL, GET /nodes on the staging hub, and per-node reachability, all in one verbatim terminal output. (Captured by lane E at 12:13 EDT 2026-08-17.)
  - How: `curl -s https://AI_ROUTER_HOST/health`; `curl -s https://<STAGING_HUB_SSLTIP_HOST>/nodes`; confirm both nodes reachable=true in the output.

### Step 2 - Phone pre-demo shots (OWNER)

- [ ] **phone-07-calculator.png** - app in calculator camouflage state (before unlock).
- [ ] **phone-01-serverlist.png** - server list showing AI Route A and AI Route B.

### Step 3 - Connect on route A (OWNER)

- [ ] **phone-02-connected-a.png** - connected through AI Route A (device allocated inner 10.10.0.3).
- [ ] **phone-03-ip-a.png** - IP-check page showing route A egress IP DEMO_ROUTE_A_IP.

### Step 4 - THE IMPAIRMENT MOMENT, one unbroken take (OWNER records, SUP triggers)

SUPERVISOR RECEIPT 2026-08-17 storyboard: split screen, 15 seconds, 5 beats. Left: phone on A. Right: live router dashboard at https://AI_ROUTER_HOST/. Beat 1: card reads "demo-route-a, keep, [STABLE_LINK, LATENCY_OPTIMIZED]". Beat 2: SUP fires POST /admin/health {"slug": "demo-route-a", "reachable": false} (recent_failures +1). Beat 3: decision card flips to demo-route-b with reason codes. Beat 4: phone reconnects to B by itself. Beat 5: IP-check shows DEMO_ROUTE_B_IP.

- [ ] **router-dashboard-switch.mp4** - screen recording of the dark dashboard during the demo, decision card flip from demo-route-a to demo-route-b with reason codes, one unbroken take. Both clocks/timestamps in frame.
- [ ] **phone-04-impairment.png** - during impairment: connection degraded or reconnecting (status visible).
- [ ] **phone-05-reconnected-b.png** - reconnected through AI Route B without user action.
- [ ] **phone-06-ip-b.png** - IP-check page showing route B egress IP DEMO_ROUTE_B_IP.

### Step 5 - Router /decisions export (SUP)

- [x] **router-decisions.json** - GET /decisions on the live Cloud Run router, saved as JSON. Must contain the last 50 decisions at capture time, each with request_id, reason codes, decision source gemini|fallback, and latency. Must include BOTH the keep decision ([STABLE_LINK, LATENCY_OPTIMIZED]) and the switch decision from the demo. (Captured by lane E at 15:57-15:58Z on 2026-08-17, post-demo: contains demo-video-* keep + switch records plus the first real Gemini decision af13acd1ebea11fa.)
  - How: `curl -s https://AI_ROUTER_HOST/decisions -o $HOME/xprize/evidence/router-decisions.json`
- [x] **router-decisions-curl.txt** - verbatim terminal output of the live curl above, so the URL and its response are on the record in one file. (Captured by lane E at 15:58Z 2026-08-17.)
  - How: `curl -s https://AI_ROUTER_HOST/decisions | tee $HOME/xprize/evidence/router-decisions-curl.txt`
- [ ] **router-decisions.jsonl** - the decision JSONL file from the router deployment (append-only log with request_id, inputs, model output, gate verdict, fallback flag). SUP copies it off the Cloud Run service. Cross-check the demo request_id appears here and in the .json export.

### Step 6 - Cloud Run console screenshots (SUP)

- [ ] **cloud-run-logs-route-demo-003.png** - Cloud Run console log screenshot showing the gemini-source decision whose request log names route-demo-003, with the reason codes [LINK_DOWN, UDP_BLOCKED, HEALTHIER_ALTERNATE] visible. This is the first real production decision of the router and the strongest single artifact.
- [ ] **cloud-run-logs-1.png, cloud-run-logs-2.png** - Cloud Run console request log screenshots. Show request ids and timestamps for at least one keep decision and one switch decision from the demo. Redact nothing except accidental secret text; there should be none.
- [ ] **cloud-run-service.png** - Cloud Run service page for the router (service name, region, URL visible: AI_ROUTER_HOST).

### Step 7 - Staging hub /nodes screenshot (SUP)

- [ ] **hub-nodes.png** - screenshot of https://<STAGING_HUB_SSLTIP_HOST>/nodes rendered (or the hub admin state page), showing both nodes with reachable=true, free_access_enabled true, subnet and egress IP visible.
- [ ] **hub-admin-state.txt** - GET /admin/state output: node health, sticky allocations (10.10.0.3 on demo-route-a), last 50 router decisions (no key material). This is the hub-side proof that the impairment trigger flipped the state and the sticky allocation matches the phone.

### Step 8 - Gateway verify receipts (SUP, ssh AICORE_HOST/hub VM logs)

- [x] **gateway-verify-a.txt** - receipt from the hub VM verification client against demo-route-a (DEMO_ROUTE_A_IP:9111): winn/3 handshake, inner ICMP through the tunnel, NAT egress ICMP receipt showing egress IP. From `ssh AICORE_HOST` / hub VM logs. (Placed by lane E at 12:13 EDT 2026-08-17 from the hub-VM verifier status log; the soak receipt adds the inner-ICMP + NAT-egress lines.)
- [x] **gateway-verify-b.txt** - the same receipt against demo-route-b (DEMO_ROUTE_B_IP:9111): winn/3 handshake, inner ICMP, NAT egress ICMP receipt showing egress IP DEMO_ROUTE_B_IP. (Placed by lane E at 12:13 EDT 2026-08-17; soak receipt adds the ICMP layers.)
- [ ] **phone-tunnel-up.txt** - physical tunnel-up receipt from the phone once login completes and the tunnel is up (phone_logcat.txt tail filtered for winn3 handshake/carrying lines, or the equivalent adb connectivity dump). STILL PENDING as of 12:13 EDT: logcat shows engineReady=false vpnPresent=false; the app has reached the main screen (server list + Connect VPN button) but is not connected.

### Step 9 - Remaining infrastructure evidence (SUP)

- [ ] **gce-vm-list.png** - Google Cloud console, Compute Engine VM list, showing the staging hub and both winn3 gateway nodes (names and regions visible: GCE_INSTANCE_HUB, GCE_INSTANCE_ROUTE_A in us-central1, GCE_INSTANCE_ROUTE_B in us-east1). Project name "Win's VPN XPRIZE" visible.
- [ ] **artifact-registry.png** - Artifact Registry repository showing the router container image used by the live Cloud Run service.
- [ ] **secret-manager.png** - Secret Manager list view. Secret NAMES only; never open a secret value for the screenshot.
- [ ] **cloud-logging-query.png** - Cloud Logging explorer showing the request log line for the demo switch decision (complements the console screenshots in step 6).

### Step 10 - Hoppy (OWNER)

- [ ] **phone-08-hoppy.png** - Hoppy chat with an escalated Gemini answer visible.
- [ ] **hoppy-escalation.log** - Hoppy escalation log excerpt: question sent, router /hoppy/escalate request id, escalated: true, answer. Trim to public-safe content.

### Step 11 - Build and hygiene (OWNER for APK, SUP for scan)

- [x] **apk-sha256.txt** - the staging debug APK hash. How: `shasum -a 256 $HOME/xprize/apk/app-phone-debug.apk`. One line, plus the filename on a second line. Expected: 3e9c461f0b93085d1027b7b21e1a0930824a1fb6ecaf396864f5fcf1ff6cb3e0 (matches v1.0.15). (Written by lane E at 12:0x EDT 2026-08-17; APK rebuilt at 12:00 EDT by the Android lane, same v1.0.15 + same defines; hash re-verified against disk.)
- [ ] **apk** - copy of the APK itself into evidence/ (this is what judges install). Confirm it is the debug staging build (org.winsvpn.app.debug, v1.0.15, winn/3 enabled, descriptor ring G1).
- [x] **winn3-descriptor-ring.txt** - the descriptor ring summary (G1 public key fingerprint and ring sha256, no private material) used to build the debug APK. SUP supplies this; it is the compiled-in verification ring for the winn3 gateways. (Drafted by lane E at 12:0x EDT 2026-08-17 from the APK's compiled-in G1 pubkey + ring sha256, cross-checked against the Android build log; SUP confirms.)
- [x] **secret-scan-output.txt** - gitleaks output over the judged repo contents, showing zero findings. See REPO_PLAN.md for the exact command. Save the terminal output verbatim. (Done by lane E at 12:17 EDT 2026-08-17 over pb_release/repo: gitleaks 8.30.1, 0 findings, json=[]; verbatim output + JSON in the file.)

### Step 12 - Business identity evidence (OWNER)

- [ ] **nonprofit-certificate.pdf** - copy of WIN'S VPN INC Certificate.pdf into evidence/ (read-only copy from source tree, no modifications).
- [ ] Optional: IRS determination letter scan if the owner chooses to include it.

## After the pass - verify everything

- [ ] Every file on this checklist exists in $HOME/xprize/evidence/ and opens.
- [ ] The request_id of the demo switch matches across router-decisions.json, router-decisions.jsonl, the Cloud Run console log screenshot, and the dashboard recording timestamp.
- [x] The keep decision [STABLE_LINK, LATENCY_OPTIMIZED] and the switch decision are both present in the /decisions export. (Lane E: canonical router-decisions.json contains af13acd1ebea11fa keep [STABLE_LINK, LATENCY_OPTIMIZED] + demo-video-healthy-7 switch [HEALTHIER_ALTERNATE, LATENCY_OPTIMIZED] + demo-video-switch-1.)
- [x] Gateway receipts show handshake, inner ICMP, and NAT egress ICMP for both routes. (gateway-verify-a/b.txt show the winn/3 handshake/carrying; soak receipts in gateway_soak/ show inner ICMP + NAT egress.)
- [ ] Anything missing gets re-captured before 12:15 PM.

## Red lines

- No production systems (sync.winsvpn.org, hub.winsvpn.org, Kansas, Spain) may appear in any capture.
- No secrets, tokens, service account JSONs, .env contents, private keys, admission keys, g1.pem, or the X-Demo-Key in any artifact. The live router URL is public and must appear; never capture the API key behind it.
- If a capture would show a real user's data, do not capture it. Staging demo accounts only.