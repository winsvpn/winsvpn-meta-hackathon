# VIDEO_SCRIPT.md

Target length: 2:50 max. Short voiceover lines, recordable by a non-native speaker. Every VO sentence is under 12 words where possible.

| Time | On-screen action | Voiceover |
|---|---|---|
| 0:00-0:08 | Black screen, then title card: "Win's VPN" + "Built with Gemini". Slow fade of a world map with a few dark spots. | In some countries, a VPN can save your life. |
| 0:08-0:15 | Founder on camera (or static photo + text if not filming). Lines: "A US 501(c)(3) nonprofit. Made in the USA. Launched June 2026." | We are a US nonprofit. Made in the USA. Our price is ninety-nine cents. |
| 0:15-0:25 | Phone screen recording. App opens. It looks like a calculator. Type numbers, then the unlock sequence. The VPN UI appears. | This is a phone in Myanmar. The app looks like a calculator. Only the user knows the trick. |
| 0:25-0:35 | Phone: free login screen. Type account 9999-9999-9999, then any PIN. Status: authenticated. Server list appears: AI Route A, AI Route B. | Login is free. No name, no email. The list shows two AI routes. |
| 0:35-0:45 | Phone: tap AI Route A, connect. Status changes to connected. Show route name. | Now we connect through Route A. |
| 0:45-0:55 | Phone: open browser, load an IP-check page. It shows the Route A egress IP DEMO_ROUTE_A_IP. Text overlay: "Route A IP". | The exit IP proves it. Traffic leaves from Route A. |
| 0:55-1:05 | SPLIT SCREEN. Left: phone, connected on A. Right: router dashboard, dark theme, decision card shows "demo-route-a, keep, [STABLE_LINK, LATENCY_OPTIMIZED]". | Here is the important part. On the right, the Gemini router. It watches every route, every second. |
| 1:05-1:15 | Right side: admin flips the health trigger. Route A probe data goes red: reachable=false, recent_failures +1, packet loss up, handshake failing. Keep both screens visible. | Now we impair Route A. Like a censor would. Watch what happens. |
| 1:15-1:30 | Right: decision card flips. New card: selected_route_id demo-route-b, decision "switch", confidence, reason_codes listed (LINK_DOWN, HEALTHIER_ALTERNATE). Highlight reason codes. | Gemini sees the failure. It reads the probes. It chooses Route B. It gives reasons. |
| 1:30-1:40 | Left: phone reconnects by itself. Browser refresh: IP-check now shows Route B egress IP DEMO_ROUTE_B_IP. Text overlay: "Route B IP". Freeze both screens for one beat. | The phone moves to Route B. New exit IP. The user never touched it. |
| 1:40-1:50 | Laptop: Cloud Run console, request log view. Scroll real entries, timestamps visible. Highlight the gemini-source decision for route-demo-003. | Every decision is logged on Cloud Run. Real requests, real timestamps. |
| 1:50-2:00 | Laptop: open https://AI_ROUTER_HOST/decisions. Highlight one full object: request_id, candidates, selected_route_id, reason_codes, source. | This is the raw decision. Same request id as the switch you just saw. |
| 2:00-2:15 | Laptop: website support chat. Ask Hoppy a hard question. Answer streams back, then a subtle "escalated to Gemini" indicator. | This is Hoppy, our support agent. Hard questions go to Gemini. |
| 2:15-2:25 | Back to site: pricing section. $0.99/month card, PayPal checkout. Nonprofit badge text. | The business is simple. Ninety-nine cents a month. PayPal. A real nonprofit. |
| 2:25-2:40 | B-roll: staging GCE console, VM list (staging hub + 2 winn3 gateway nodes). Then phone under Winn Protocol v3 on physical devices for 5 seconds. Roadmap card: "Winn v3 transport, live now." | Our tunnel is our own protocol, Winn v3. Post-quantum. Signed gateways. Live now. |
| 2:40-2:50 | Title card return: "Win's VPN". Final line centered. | AI is not just answering questions. It is keeping people connected. |

## The impairment moment (exact 15-second storyboard)

SUPERVISOR RECEIPT 2026-08-17: these beats are the proven demo moment at API level, and the on-screen storyboard below is exactly how to shoot it. Budget exactly 15 seconds, five beats of about 3 seconds each, one unbroken split-screen take. Live router dashboard: https://AI_ROUTER_HOST/.

| Beat | Time | Screen | What must happen on screen |
|---|---|---|---|
| 1 | 0:00-0:03 | Split screen established | Left: phone connected on AI Route A, inner 10.10.0.3, IP-check shows DEMO_ROUTE_A_IP. Right: router dashboard, decision card reads "demo-route-a, keep, [STABLE_LINK, LATENCY_OPTIMIZED]". |
| 2 | 0:03-0:06 | Trigger fires on the right | Admin flips the health trigger: POST /admin/health {"slug": "demo-route-a", "reachable": false}. Route A probe data turns red, recent_failures +1, reachable false. |
| 3 | 0:06-0:09 | Decision card flips on the right | Card becomes "selected_route_id demo-route-b, decision switch, confidence, reason_codes". Reason codes highlighted. |
| 4 | 0:09-0:12 | Phone reacts on the left | Phone reconnects to AI Route B by itself, no user action. Status changes from reconnecting to connected. |
| 5 | 0:12-0:15 | Egress proof on the left | Browser refresh on the phone: IP-check now shows route B egress IP DEMO_ROUTE_B_IP. Text overlay "Route B IP". Freeze one beat, then cut. |

Recording rules for the 15 seconds: both screens must stay in frame the whole time with visible clocks or console timestamps, so the phone reconnect and the dashboard flip can be matched in time. Keep the take silent; no music under it. After the take, cut to the Cloud Run console log for the same request_id and to GET /decisions to prove the card you watched is the record that was written. The keep decision ([STABLE_LINK, LATENCY_OPTIMIZED]) is in the same /decisions export, so judges can see both the healthy baseline and the switch.

## Recording notes

- The 0:55-1:40 block is one continuous screen capture. Do not cut it. Judges must see impairment, decision, and reconnect in a single take. Do a dry run, then record until clean. The exact 15-second storyboard above is the core of this block; the surrounding seconds are the setup and the proof.
- Phone facts for on-screen lower-thirds and the voiceover, all SUPERVISOR RECEIPT 2026-08-17: debug build org.winsvpn.app.debug v1.0.15, sha256 3e9c461f0b93085d1027b7b21e1a0930824a1fb6ecaf396864f5fcf1ff6cb3e0, privacy and legal consent accepted, device allocated inner 10.10.0.3 on demo-route-a. Do not put the sha256 in the video itself; it lives in the evidence pack.
- The healthy baseline on the dashboard card is "keep, [STABLE_LINK, LATENCY_OPTIMIZED]". The impairment trigger is the admin health flip (reachable=false, recent_failures +1). The switch card lists the switch reason codes. Do not show the API key or the X-Demo-Key in the capture.
- Both screens need visible clocks or the console timestamps in frame, so the phone reconnect and the dashboard flip can be matched in time.
- The router dashboard and /decisions pages are live at https://AI_ROUTER_HOST/. Show the URL bar in the browser capture so judges can open it themselves.
- In the 1:40-1:50 Cloud Run segment, scroll the request logs slowly and pause on the gemini-source decision whose request_id matches the switch. The console shows reason codes and the decision source.
- VO lines are written for slow, clear delivery by a non-native speaker. Total spoken words: about 230. At a calm pace that fits 2:50.
- If founder does not appear on camera, replace 0:08-0:15 with a text card over the website mission section. Same VO.
- No music under the 0:55-1:40 block. Keep it quiet so the reconnect moment lands.
- Before or after the demo, show a short disclosure text card, one beat: "VPN client and nonprofit predate the hackathon. The Gemini router, Cloud Run deployment, and v3 demo gateway network were built for this submission." Copy from the disclosure section in SUBMISSION_DRAFT.md.