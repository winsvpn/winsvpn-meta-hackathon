# README_INDEX.md - Win's VPN XPRIZE evidence attachment

Read this first. This attachment is the evidence behind the Devpost submission
"Win's VPN: Gemini routing that keeps people online when censors fight back"
(submission date 2026-08-17). Everything here is public-safe: no secrets, no
API keys, no admission key values, no g1.pem, no device static private keys.

## Start here

1. **SUBMISSION_DRAFT.md** - the Devpost text (what the judges read).
2. **VIDEO_SCRIPT.md** - the 2:50 shot list + the 15-second impairment-moment
   storyboard.
3. **DEMO_RUNBOOK.md** - the operator script for the live demo (exact commands,
   URLs, taps, expected outcomes).
4. **FACTS.md** - claim-by-claim sources, including the SUPERVISOR RECEIPT
   2026-08-17 block for live infrastructure facts.
5. **EVIDENCE_PACK.md** - the master index table (every artifact, what it
   proves, capture date, cross-check requirements).
6. **live/CAPTURE.md** - provenance for the perishable live receipts in
   `01_live_receipts/` (harvest timestamp, source URL, status).

## Zip layout

- `00_submission/` - the six submission documents + this index.
- `01_live_receipts/` - live API captures from the public router URL
  (https://AI_ROUTER_HOST) and the
  staging hub (https://<STAGING_HUB_SSLTIP_HOST>), plus gateway verify/soak
  receipts pulled from the hub VM. Round-1 (14:54Z) and round-2 (15:40Z)
  are pre-demo baselines; the round-3 harvest (15:57Z) and the
  `router-decisions.json`/`.csv` exports in `03_router/` are post-demo and
  contain BOTH the keep decision ([STABLE_LINK, LATENCY_OPTIMIZED]) and the
  demo switch to demo-route-b.
- `02_gateway_soak/` - the 60s soak receipts and the soak harness.
- `03_router/` - the live Cloud Run router: production sanity receipt,
  README, test suite, and the post-demo decision exports.
- `04_staging_hub/` - the staging control plane (GCE) source notes + admin
  state + nodes screenshot.
- `05_gateway_lane/` - gateway hardening, descriptor ceremony record, and
  rotation e2e test.
- `06_nodes/` - the winn3 gateway binaries with pinned sha256 and the G1
  public ring summary.
- `07_phone/` - the installable debug APK (+ sha256), iOS device install and
  consent receipts.
- `08_android/` - Android engine staging hashes and compile/upload-key proof.
- `09_platform_lanes/` - Linux, watch, windows, and hub receipts.
- `10_release_lane/` - gitleaks scan (zero findings) and repo inventory.
- `11_checklist_captures/` - the EVIDENCE_CHECKLIST.md captures from the
  owner's video session (phone shots, dashboard switch take, Cloud Run /
  GCE / Secret Manager / Artifact Registry screenshots, Hoppy log).
- `12_business/` - the WIN'S VPN INC Certificate.pdf.

## The one-liner the whole pack proves

Phone app (org.winsvpn.app.debug v1.0.15) -> staging hub (GCE) -> Gemini
router (Cloud Run, gemini-3-flash-preview) -> winn/3 gateway (GCE) carrying
real traffic, with a live impairment demo: keep [STABLE_LINK,
LATENCY_OPTIMIZED] on a healthy link, admin health flip, switch to
demo-route-b with reason codes, phone reconnects unaided, new egress IP.

## Cross-check (also in EVIDENCE_PACK.md)

- The switch request_id matches across `router-decisions.json`,
  `router-decisions.jsonl`, the Cloud Run console log, and the dashboard
  recording timestamp.
- Both keep and switch decisions are present in the /decisions export.
- Gateway receipts show handshake, inner ICMP, and NAT egress ICMP for both
  routes.
- Sticky allocation 10.10.0.3 on demo-route-a in hub-admin-state.txt matches
  the phone's connected shot.
- apk-sha256.txt equals `shasum -a 256 apk/app-phone-debug.apk`.