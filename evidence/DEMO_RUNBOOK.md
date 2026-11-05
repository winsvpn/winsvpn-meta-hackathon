# DEMO_RUNBOOK.md - operator script for the demo / video session

Run order: open app -> login -> connect (consent tap) -> IP check -> show dashboard
URL -> impairment trigger (curl admin health flip) -> watch switch -> IP re-check ->
Hoppy escalate. This is the same chain the judges see in the video and can re-run
from the live URLs. The demo phone is the Android device running the staging debug
APK (org.winsvpn.app.debug v1.0.15, sha256
3e9c461f0b93085d1027b7b21e1a0930824a1fb6ecaf396864f5fcf1ff6cb3e0, winn/3 enabled,
descriptor ring G1). Note: the APK was rebuilt by the Android lane on 2026-08-17
12:00 EDT (same v1.0.15, same winn/3 defines, same G1 ring); this hash supersedes
the 106ec293... value attested earlier that day. The installed APK on the phone
was verified to match this hash at 12:01 EDT.

Never show the X-Demo-Key value on screen. In every curl below it is written as
`${DEMO_KEY}`; the value is the supervisor's secret and stays out of the capture.

New fact (SUPERVISOR, 2026-08-17): the hub's /free/verify now serves cached
Gemini decisions in ~21ms hub-side. The cache is keyed on the node-health tuple
(slug, reachable, recent_failures); same health = same decision. POST
/admin/probe (below) warms it, and a health change re-keys it so the next verify
is a fresh Gemini call. Warm verifies never touch the router, so the router
/decisions ring only fills when /admin/probe or a post-flip cache-miss refresh
lands a /route call on a live Cloud Run instance. The warm-up in step 5 is
therefore mandatory, not optional, before the take.

## Step 0 - Pre-flight (10 seconds, optional)

Confirm both routes are healthy and the router is live before the take.

```bash
curl -s https://AI_ROUTER_HOST/health
curl -s https://<STAGING_HUB_SSLTIP_HOST>/nodes
```

Expected: `{"ok":true,"model":"gemini-3-flash-preview","gemini_configured":true}`
and both `demo-route-a` and `demo-route-b` with `"reachable": true`,
`"free_access_enabled": true`.

## Step 1 - Open the app (OWNER)

1. On the home screen, tap the calculator icon (camouflage state).
2. Enter the unlock sequence, then the camouflage PIN (default demo PIN works).
3. The VPN UI appears.

Expected: the app looks like a calculator until the sequence unlocks it.

## Step 2 - Login (OWNER)

1. On the free login screen, type account `9999-9999-9999`.
2. Type any 4-digit PIN (device-local; staging demo convention).
3. Tap Sign in.

Expected: status becomes authenticated. Server list appears: AI Route A - US
Central and AI Route B - US East. Both are free-access enabled.

## Step 3 - Connect on route A, with the consent tap (OWNER)

1. Tap AI Route A - US Central.
2. Android VPN consent dialog appears: "Win's VPN wants to set up a VPN
   connection." Tap **Allow** (this is the critical consent tap; without it there
   is no tunnel).
3. If a second system dialog appears (notification / network), tap **Allow** / **OK**.

Expected: the app shows connected on AI Route A. The device is allocated inner
`10.10.0.3` on demo-route-a. For evidence: `phone-02-connected-a.png`. If the
hub verify-cache is already warm (same health key as the last /admin/probe), this
login's /free/verify serves the cached Gemini decision in ~21ms hub-side instead
of blocking on a fresh Gemini call; either way the phone lands on demo-route-a.

## Step 4 - IP check (OWNER)

1. Open the phone browser.
2. Visit an IP-check page: `https://api.ipify.org?format=json` (or any public
   IP-check page).
3. Screenshot it: `phone-03-ip-a.png`.

Expected: the page shows egress IP **DEMO_ROUTE_A_IP** (demo-route-a,
us-central1). If it does not, the tunnel is not up on A; do not continue.

## Step 5 - Warm the cache and show the live router dashboard (SUP)

1. On the laptop, open `https://AI_ROUTER_HOST/`
   in a browser (show the URL bar).
2. Warm the hub verify-cache and plant the keep record on the router ring (this
   also makes the phone's login verify instant):

```bash
curl -s -X POST https://<STAGING_HUB_SSLTIP_HOST>/admin/probe \
  -H "X-Demo-Key: ${DEMO_KEY}"
```

   Expected: `{"probes":{"demo-route-a":<latency_ms or null>,"demo-route-b":<latency_ms or null>}}`.
   This runs a real TCP probe pass and fires one router /route call in the
   background, so the healthy decision ("keep demo-route-a, [STABLE_LINK,
   LATENCY_OPTIMIZED]") lands on the dashboard card.

3. The dark dashboard shows: model gemini-3-flash-preview, routing stats card,
   and the Last decision card reading "demo-route-a, keep, [STABLE_LINK,
   LATENCY_OPTIMIZED]".

Expected: the healthy-link decision card shows keep with reason codes
STABLE_LINK and LATENCY_OPTIMIZED. The dashboard refreshes every 2 seconds.
If the card is still empty after the probe warm-up, POST one healthy /route
directly (Step 5b).

### Step 5b - Seed a healthy decision if the card is empty (SUP)

```bash
curl -s https://AI_ROUTER_HOST/route \
  -H "Content-Type: application/json" \
  -d '{"request_id":"demo-healthy-1","current_route_id":"demo-route-a",
       "candidates":[{"route_id":"demo-route-a","reachable":true,"handshake_ms":220,
                      "packet_loss_pct":0,"jitter_ms":12,"recent_failures":0},
                     {"route_id":"demo-route-b","reachable":true,"handshake_ms":180,
                      "packet_loss_pct":0,"jitter_ms":9,"recent_failures":0}],
       "signals":{"udp_ok":true,"tcp443_ok":true,"tls_ok":true,
                  "control_plane_ok":true,"dns_ok":true}}'
```

Expected: a JSON decision with `decision: "keep"`, `selected_route_id:
"demo-route-a"`, and reason codes including STABLE_LINK and LATENCY_OPTIMIZED.
The dashboard card now shows it.

## Step 6 - THE impairment trigger (SUP fires, OWNER keeps recording)

One unbroken split-screen take starts here (storyboard in VIDEO_SCRIPT.md). On the
laptop terminal, fire the admin health flip against the staging hub:

```bash
curl -s -X POST https://<STAGING_HUB_SSLTIP_HOST>/admin/health \
  -H "Content-Type: application/json" \
  -H "X-Demo-Key: ${DEMO_KEY}" \
  -d '{"slug": "demo-route-a", "reachable": false}'
```

Expected response (no key material in it):
`{"slug":"demo-route-a","reachable":false,"recent_failures":1}`

This flips route-a to unreachable and increments recent_failures by 1. Because
the verify-cache is keyed on node health, the key now changes: the next phone
verify is a cache miss, so it is served instantly by the deterministic pick of
the remaining healthy route while a background thread asks Gemini for the switch
decision.

## Step 7 - Watch the switch (SUP + OWNER, both screens)

1. Left screen (phone): within seconds the app reconnects to AI Route B by
   itself. No user action. The hub serves the cache-miss verify immediately
   (deterministic pick of the healthy route), so the reconnect is near-instant;
   the Gemini decision follows in the background.
2. Right screen (dashboard): the decision card flips to "selected_route_id
   demo-route-b, decision switch, confidence, reason_codes" when the background
   refresh lands the /route call on the router (a few seconds after the trigger;
   Gemini takes ~4s cold). Reason codes are highlighted (LINK_DOWN,
   HEALTHIER_ALTERNATE, etc.). Every subsequent verify on the new health state
   serves the cached switch decision in ~21ms hub-side.

Expected: the reconnect lands within about 2-5 seconds of the trigger and the
card flip within about 5-10 seconds, comfortably inside the 15-second take.
Phone shot: `phone-05-reconnected-b.png`. If the phone is mid-session, tap once
to bring the app to front; do not touch the connect button.

## Step 8 - IP re-check (OWNER)

1. On the phone browser, refresh the IP-check page.
2. Screenshot it: `phone-06-ip-b.png`.

Expected: the page now shows egress IP **DEMO_ROUTE_B_IP** (demo-route-b, us-east1).
The user never touched the connect button between step 6 and this screenshot.

## Step 9 - Export the decision log (SUP)

After the take, export the live record so the judges can cross-check:

```bash
curl -s https://AI_ROUTER_HOST/decisions \
  -o $HOME/xprize/evidence/router-decisions.json
curl -s https://AI_ROUTER_HOST/decisions \
  | tee $HOME/xprize/evidence/router-decisions-curl.txt
curl -s https://AI_ROUTER_HOST/decisions.csv \
  -o $HOME/xprize/evidence/router-decisions.csv
```

Expected: router-decisions.json contains the last 50 decisions with request_id,
reason codes, source (gemini|fallback) and latency, including BOTH the keep
([STABLE_LINK, LATENCY_OPTIMIZED]) and the switch decisions from this take. The
request_id of the switch must also appear in the hub's /admin/state and the Cloud
Run console log.

## Step 10 - Hoppy escalate (OWNER)

Option A - live site chat: open the support chat widget on the public site, ask a
hard question ("What happens to my tunnel if the exit route is blocked?"), watch
the answer stream back with an "escalated to Gemini" indicator.

Option B - direct API (recommended for the runbook record):

```bash
curl -s https://AI_ROUTER_HOST/hoppy/escalate \
  -H "Content-Type: application/json" \
  -d '{"question":"What happens to my tunnel if the exit route is blocked?","context":"demo-route-b"}'
```

Expected: a JSON answer with `"escalated": true` (or the guarded fallback naming
the docs page if Gemini is slow). Save the trimmed request/response to
`evidence/hoppy-escalation.log`; keep the question public-safe.

## Success criteria for the whole runbook

- Step 3: connected on AI Route A, inner 10.10.0.3.
- Step 4: egress DEMO_ROUTE_A_IP.
- Step 5: /admin/probe warms the verify-cache and plants the keep record;
  dashboard shows keep [STABLE_LINK, LATENCY_OPTIMIZED].
- Step 6: admin flip returns recent_failures 1.
- Step 7: phone reconnects to B unaided (cache-miss verify served instantly,
  deterministic pick of the healthy route); dashboard card flips to demo-route-b
  when the background Gemini decision lands; subsequent verifies on the new
  health state serve the cached switch decision in ~21ms hub-side.
- Step 8: egress DEMO_ROUTE_B_IP.
- Step 9: both decisions in /decisions with matching request_id.
- Step 10: Hoppy escalates and answers.

## Red lines during the demo

- Never show the X-Demo-Key value, the GCP API key, Secret Manager values, or any
  private key. The router URL is public and must appear.
- No production VPN systems (sync.winsvpn.org, hub.winsvpn.org, Kansas, Spain).
- One unbroken take for the impairment moment (steps 6-8). Both clocks in frame.