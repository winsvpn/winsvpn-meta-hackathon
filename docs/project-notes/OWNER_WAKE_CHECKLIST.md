# OWNER WAKE CHECKLIST (15:30–16:00 EDT) — 4 steps, ~10 minutes total

Everything below is pre-staged. You only upload, invite, fill numbers, and click submit.

## STEP 1 — Upload the video (YouTube, you are logged in on Edge)
1. Open https://studio.youtube.com in Edge (already logged in).
2. Click CREATE → Upload videos.
3. Select this file: `/Users/owner/xprize/video/final_demo.mp4` (2:46, 1080p).
4. Title: `Win's VPN: Gemini AI Routing Keeps People Connected`
5. Description (paste exactly):
   `Win's VPN is a 501(c)(3) nonprofit privacy and anti-censorship VPN. This demo shows our live Gemini 3 Flash adaptive routing brain on Google Cloud selecting between Winn Protocol v3 gateways, failing open to deterministic routing, and logging every decision. Learn more: https://winsvpn.org. Repository access is supplied to XPRIZE judges.`
6. Audience: "No, it's not made for kids". Visibility: **Unlisted** (not Public).
7. Save. Copy the video URL.

## STEP 2 — Share the repo with judges (GitHub, you are `winsvpn`)
1. Open https://github.com/winsvpn/winsvpnv3/settings/access
2. Add collaborators: `testing@devpost.com` and `judging@hacker.fund`.
3. (Do NOT make the repo public unless you want to.)

## STEP 3 — Devpost finance numbers (fill, do not submit yet)
Open https://devpost.com/submit-to/29541-build-with-gemini-xprize/manage/submissions
Finance fields (your own real numbers; lower bounds you told me):
- Total revenue: your actual cash donations (a few hundred USD) + any premium ($0.99/mo) sales.
- Monthly: June / July / August 2026.
- Total expenses: more than $24,000.
- Marketing spend: more than $2,000.
- Users: more than 10,000 (premium was free during the July 4 promo).
- Paste the YouTube video URL from Step 1 into the video field.

## STEP 4 — Submit
1. Confirm category = Education & Human Potential.
2. Confirm repo = https://github.com/winsvpn/winsvpnv3 and website = https://winsvpn.org.
3. Click Submit. (Deadline is 1:00 PM Pacific = 4:00 PM Eastern.)

## What is already DONE (no action needed)
- Gemini Router LIVE on Google Cloud Run: https://AI_ROUTER_HOST (gemini-3-flash-preview, structured output, deterministic fallback, /decisions + /stats logs).
- Winn Protocol v3 gateways (2) on Google Cloud Compute Engine, verified carrying real traffic: handshake, inner ICMP, NAT egress (carriage_proven=true).
- Physical Android device PROVEN on Winn Protocol v3: logcat "Winn v3 promoted after 12 polls; rxPackets=13", tun interface VALIDATED, key icon shown, gateway session carrying/promoted.
- Judged repo pushed to https://github.com/winsvpn/winsvpnv3 (clean secret scan, identical freeze inventories).
- Submission text + evidence pack + revenue template in /Users/owner/xprize/evidence/.
- ProtonDrive backup synced (2.1 GB).

## Known honest caveats to state if asked
- The demo app's censorship-recovery mechanism can fall back to production AmneziaWG nodes if the staging hub is unreachable. The Winn Protocol v3 staging path is independently proven on the device.
- Exact monthly revenue split still needs your PayPal figures (I only had lower bounds).
