# VIDEO_STATUS.md - XPRIZE demo video build status

Generated: 2026-08-17 ~12:25 EDT by the VIDEO lane.
Target: final_demo.mp4 (< 2:50, 1080p, H.264). Current build: **2:46 (166.2s), 1920x1080, H.264 High, 30fps, 4.4MB**.

## What is REAL footage (captured from live systems)

| Segment | Time | Content | Source |
|---|---|---|---|
| Nonprofit / website mission | 0:08-0:15 | winsvpn.org mission section, 501(c)(3) text | Screen capture (Safari, winsvpn.org) |
| Phone calculator disguise | 0:15-0:25 | Android app camouflage calculator + notification gate | adb screenrecord (real device, app not yet logged in) |
| Split-screen core block | 0:55-1:40 | RIGHT side: live AI router dashboard, impairment trigger + keep->switch flip | Screen capture of live dashboard (polls live router every 2s) |
| Dashboard impairment sequence | - | POST /admin/health {demo-route-a, reachable:false} -> decision card flips keep->switch demo-route-b | Real live triggers on staging hub + live router (request_ids take5-healthy / take5-switch) |
| Cloud Run-style request log | 1:40-1:50 | Real request log entries (timestamps, request_id, route, decision, source, reason codes) | Rendered from live GET /decisions export |
| Raw decision page | 1:50-2:00 | Live /decisions JSON (request_id, candidates, selected_route_id, reason_codes, source) | Screen capture of live /decisions |
| Hoppy support | 2:00-2:15 | Hoppy chat Q&A "What happens to my tunnel if the exit route is blocked?" | Chat UI + real /hoppy/escalate API response |
| Pricing | 2:15-2:25 | winsvpn.org pricing: $0.99/month, PayPal, nonprofit badge | Screen capture (winsvpn.org #get) |
| Disclosure card | 2:40-2:50 | winsvpn.org + disclosure text (from SUBMISSION_DRAFT.md) | Generated card |

## What is PLACEHOLDER (pending the phone tunnel lane)

| Segment | Time | Content | Replacement needed when phone succeeds |
|---|---|---|---|
| Phone login + server list | 0:25-0:35 | Static card "Free login 9999-9999-9999, two AI routes" | Real app login screen + server list (AI Route A/B) |
| Phone connect Route A | 0:35-0:45 | Static card "Route A connected" | Real app connect + consent tap + connected status |
| IP check Route A | 0:45-0:55 | Static card "203.0.113.10" | Real phone browser IP check (api.ipify.org) |
| Split-screen LEFT side | 0:55-1:40 | Generated phone panel (A -> reconnecting -> B) | Real phone screen showing reconnect to Route B during the impairment |
| IP check Route B | (inside split) | Generated panel "203.0.113.20" | Real phone browser refresh showing 203.0.113.20 |
| Winn v3 B-roll | 2:25-2:40 | Generated card "Winn Protocol v3 ... live now" | Staging GCE console + physical device footage (if captured) |

## Live system notes (verified during this build)

- Router health: `{"ok":true,"model":"gemini-3-flash-preview","gemini_configured":true}`.
- Hub /nodes: both demo-route-a (203.0.113.10:9111) and demo-route-b (203.0.113.20:9111) online, free-access enabled.
- Impairment trigger works: POST /admin/health {slug:demo-route-a, reachable:false} -> recent_failures increments, /route then selects demo-route-b (switch).
- **KNOWN ISSUE - Gemini throttling**: at capture time Gemini calls were mostly falling back (stats showed gemini 2 / fallback 109 in the hour window). Dashboard decision cards therefore show reason code `DETERMINISTIC_FALLBACK` rather than the scripted `[STABLE_LINK, LATENCY_OPTIMIZED]` / `[LINK_DOWN, HEALTHIER_ALTERNATE]`. The keep->switch story is real and captured; the exact Gemini reason codes were captured once (request demo-video-healthy-7: switch gemini [HEALTHIER_ALTERNATE, LATENCY_OPTIMIZED]) but not consistently.
- **KNOWN ISSUE - live dashboard serves HTML as JSON**: GET / on the live router returns `Content-Type: application/json` with the HTML as a JSON string, so a browser shows the raw source instead of the rendered dashboard. The video's dashboard visuals were captured from a faithful local render of the SAME dashboard HTML polling the SAME live endpoints (proxy at 127.0.0.1:8080). This should be reported to the router lane / supervisor: the deployed main.py at / returns a JSON-wrapped string (local source returns the HTML string directly). Judges opening the URL directly today will see the source text, not the dashboard.

## Security

- No secrets on camera: X-Demo-Key never printed (read from a 0600 file), no API keys, no state.json, no private keys. Dashboard shows routes/decisions only.
- Local proxy serves only the public live endpoints.

## Rebuild checklist when the phone tunnel succeeds

1. Watch `/Users/owner/xprize/logs/phone_*.log` and the phone screen (adb screencap OCR) for "connected" + IP check pages.
2. Re-record phone segments S1-S4 with `adb shell screenrecord` (180s cap; 4 segments as planned).
3. Re-record the split-screen core take: phone screenrecord (left) in parallel with the live dashboard capture (right), one unbroken take through the impairment trigger (fire_take.sh).
4. Replace placeholder cards, re-run `build_segments.sh` + `assemble.sh`.
5. Re-verify with OCR frame extraction.

Build assets and scripts are in /Users/owner/xprize/video/ (clips/, build/, cards/, vo/, ocr.py, make_dashboard.py, dash_proxy.py, fire_take.sh, build_segments.sh, assemble.sh).