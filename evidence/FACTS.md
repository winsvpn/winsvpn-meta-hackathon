# FACTS.md - Claim Sources

Every public-facing claim usable in the submission, with its source in the read-only reference tree ($HOME/Documents/wins/source/wins_vpn/) or in the SUPERVISOR RECEIPT below. If a claim is not in this list, it does not go in the submission without a new source check.

## SUPERVISOR RECEIPT - live infrastructure (attested 2026-08-17)

Attestation label: SUPERVISOR RECEIPT. Date: 2026-08-17. These facts were verified live today by the supervisor and are safe to publish in the submission.

| Claim | SUPERVISOR RECEIPT detail |
|---|---|
| Gemini Router is live in production on Google Cloud Run | URL: https://AI_ROUTER_HOST |
| Router model | gemini-3-flash-preview |
| Structured output | Constrained to a closed route-id set (demo-route-a, demo-route-b) |
| Fallback | Deterministic fallback scorer; routing never blocks connectivity |
| Decision logging | Every decision logged with request id, reason codes, decision source gemini\|fallback, and latency |
| First real routing decision | Returned in about 4 seconds with reason codes [LINK_DOWN, UDP_BLOCKED, HEALTHIER_ALTERNATE] |
| Full chain proven end to end | Phone app -> staging hub (GCE, https://<STAGING_HUB_SSLTIP_HOST>) -> Gemini router (Cloud Run, gemini-3-flash-preview) -> winn/3 gateway (GCE) carrying real traffic: handshake, inner ICMP, and NAT egress ICMP receipts all recorded |
| Healthy-link scenario | Gemini returns keep with reason codes [STABLE_LINK, LATENCY_OPTIMIZED] |
| Impairment scenario | Admin trigger flips route-a unreachable (recent_failures +1); next login Gemini switches to demo-route-b with reason codes; decision exportable at GET /decisions |
| Reason-code vocabulary | Closed, documented in the router prompt: LINK_DOWN, INTERFERENCE_SUSPECTED, UDP_BLOCKED, DNS_TAMPERING, HEALTHIER_ALTERNATE, STABLE_LINK, LATENCY_OPTIMIZED; gate uses DETERMINISTIC_FALLBACK |
| Phone build | Debug APK org.winsvpn.app.debug v1.0.15, sha256 3e9c461f0b93085d1027b7b21e1a0930824a1fb6ecaf396864f5fcf1ff6cb3e0, installed, privacy and legal consent accepted via adb. Note: the APK was rebuilt by the Android lane on 2026-08-17 12:00 EDT (same v1.0.15, same winn/3 defines, same G1 ring); this hash supersedes the 106ec293... value attested earlier the same day. |
| Phone login state | Free login in progress; device allocated on demo-route-a inner 10.10.0.3; physical tunnel-up receipt pending |
| Impairment trigger control | Staging hub POST /admin/health {"slug": "demo-route-a", "reachable": false}, header X-Demo-Key (name only, never the value); flips reachability and increments recent_failures |
| Google Cloud products in the deployment | Cloud Run (router), Compute Engine (3 VMs: staging hub GCE_INSTANCE_HUB + 2 winn3 gateway nodes GCE_INSTANCE_ROUTE_A, GCE_INSTANCE_ROUTE_B), Secret Manager (Gemini API key), Artifact Registry (router image), Cloud Logging (request and decision logs) |
| GCP project name | "Win's VPN XPRIZE" |
| Transport | Standalone Winn Protocol v3: post-quantum hybrid X25519 + ML-KEM-768, Ed25519-signed gateway descriptors with a compiled-in verification ring, fail-closed |
| Demo app build | Debug build carrying the freshly rebuilt winn engine (libwinnengine.so for 3 ABIs) pinned to descriptor ring G1 |
| Decision pipeline | Phone app -> staging control plane (GCE) probes routes -> Cloud Run router -> Gemini structured decision -> deterministic policy gate -> tunnel connects through selected gateway -> result logged |
| Gateway nodes | GCE_INSTANCE_ROUTE_A (demo-route-a, us-central1, egress DEMO_ROUTE_A_IP, subnet 10.10.0.0/24, UDP/TCP 9111), GCE_INSTANCE_ROUTE_B (demo-route-b, us-east1, egress DEMO_ROUTE_B_IP, subnet 10.11.0.0/24, UDP/TCP 9111). Both online, free_access_enabled true, reachable flag live. |
| Staging hub | GCE GCE_INSTANCE_HUB <STAGING_HUB_IP>, Caddy TLS on <STAGING_HUB_SSLTIP_HOST> (sslip.io name derived from the hub IP), FastAPI twin, serves protocol_version "winn/3" |
| Business facts | 501(c)(3) nonprofit (IRS determination July 21, 2026, effective June 11, 2026), $0.99/month, made in the USA, no-logs (only device-count metadata), calculator camouflage, Hoppy support. Business launched end of June 2026. |

## Pre-existing work disclosure (attested in this submission)

| Claim | SUPERVISOR RECEIPT detail |
|---|---|
| VPN client and nonprofit predate the hackathon window minimally and are disclosed | Client app (Flutter, calculator camouflage, account/free-tier login, Winn Protocol tunnel client), Hoppy support framework, and the nonprofit business existed before the window |
| Built during the hackathon window for this submission | The Gemini adaptive routing layer (Cloud Run router, structured-output decision service, deterministic gate, decision log and dashboard, /hoppy/escalate Gemini path), the Cloud Run deployment, and the v3 demo gateway network (winn3 gateway nodes, signed descriptor ring G1, staging hub twin serving winn/3 config, rebuilt debug APK with libwinnengine.so for 3 ABIs) |

## Identity and nonprofit status

| Claim | Source |
|---|---|
| US 501(c)(3) non-profit, censorship-resistant, no-logs VPN | web/index.html:8 (meta description) |
| "A U.S. 501(c)(3) non-profit public charity - Donations are tax-deductible" | web/index.html:2158 |
| Win's VPN Inc. operates the service; Win Empire LLC designs and builds the software | web/index.html:2674 |
| Florida nonprofit corporation, document number N26000008302, phone (424) 946-7876 | web/index.html:2674 and web/index.html:2746 |
| IRS determination letter dated July 21, 2026; exemption effective June 11, 2026; public charity under 509(a)(2) | web/index.html:2674 |
| December 31 accounting period; Form 990-series filer | web/index.html:2674 |
| Certificate held: WIN'S VPN INC Certificate.pdf | source tree file, listed in project root |

## Mission and users

| Claim | Source |
|---|---|
| Mission: access to essential cybersecurity and information restricted by cost, censorship or surveillance | web/index.html:2191-2194 |
| Founder's parent was assassinated by the Myanmar junta in 2025; mission to help people keep their freedom | web/index.html:2580 |
| Android safety mode for high-risk censorship regions such as Myanmar/Burma | web/index.html:75 (product description) and web/index.html:2712 |
| Founder is disabled; small nonprofit, security work held to standard | web/index.html:2581 |
| First non-profit VPN built on its own protocol | web/index.html:2232 (this claim is now directly demonstrated by the winn/3 demo deployment in the SUPERVISOR RECEIPT above) |

## Pricing and payment

| Claim | Source |
|---|---|
| $0.99 one month, "Monthly access with 99% reliability target" | web/index.html:2462-2465 |
| $11.88 one year | web/index.html:2470-2472 |
| 10-year lifetime passes (with and without tech support) | web/index.html:2476-2494 |
| "99 cents for 99% reliability" tagline | web/index.html:13 |
| Payments processed by PayPal; card data on PayPal-hosted PCI DSS pages; no card data stored on Win's servers | web/index.html:2460 and web/index.html:2676 |
| Product offer JSON price 0.99 USD (1 month), 11.88 USD (1 year) | web/index.html:83-92 |
| July 4, 2026 notice: premium servers free until August 31, 2026 | web/index.html:2096 |

## Free tier

| Claim | Source |
|---|---|
| Free users set a 4-digit PIN and use Try Free Server (Limited Speed) when free servers are available | web/_worker.js:635 (Hoppy public facts) |
| Free access uses built-in free route; users do not need to type 9999-9999-9999; free access limited to hub-marked free servers; PIN stays on device | web/index.html:3171 (translated copy of English FAQ) and web/index.html:3907 (English FAQ source) |
| Paid users choose a 6-digit app PIN; PIN is device-local, never sent to server | web/index.html:2510 and web/index.html:2946 |

Note: the demo login in SPEC.md is account 9999-9999-9999 + any 4-digit PIN, which is a staging convention. On the public product, free users do not type that number. Do not conflate the two in submission copy.

## Camouflage

| Claim | Source |
|---|---|
| Calculator camouflage shown in the Android app demo | web/index.html:3473 (demo copy) |
| Android camouflage mode is an optional user-safety feature for high-risk censorship environments; does not hide malicious activity; VPN notification user-controlled | web/index.html:2712 and web/index.html:2745 |

## No-logs design

| Claim | Source |
|---|---|
| No browsing history, no DNS query history, no traffic contents, no destination records; transient session state cleared on disconnect; 90-day deletion/anonymization of unneeded operational data | web/index.html:2240 and web/index.html:2677 |
| VPN does not log browsing history, DNS query history, traffic contents, raw VPN traffic, or user destination activity (policy text) | web/index.html:2677 |
| Privacy-preserving device-limit metadata for the three-device limit, deleted or overwritten on deactivation | web/index.html:2240 and web/index.html:2679 |
| Win's VPN does not sell personal or sensitive user data | web/index.html:2678 |

## AI and Hoppy

| Claim | Source |
|---|---|
| Hoppy is the public support agent; answers about setup, free access, payments, privacy, troubleshooting; will not reveal private infrastructure details or secrets | web/index.html:2756 and web/_worker.js:630 |
| Hoppy uses the Gemini API (generativelanguage.googleapis.com, model from GEMINI_MODEL, default gemini-2.5-flash, temperature 0.35) with fallback to a public fallback answer on any failure | web/_worker.js:624-666 |
| Customized local AI used for privacy; real-world censorship conditions tracked; no personal data collected, so no training on it | web/index.html:2228 |

Note: the hackathon router uses gemini-3-flash-preview (SUPERVISOR RECEIPT above), while the pre-existing public site widget still names an older default. The submission text always says gemini-3-flash-preview for the router and does not repeat the site default.

## Protocols and infrastructure (public statements plus SUPERVISOR RECEIPT)

| Claim | Source |
|---|---|
| Adaptable, modified, hardened versions of proven censorship-bypassing protocols designed to bypass censorship without affecting speed | web/index.html:2304 |
| Winn Protocol passes Win's VPN's own verification suites; external comparable results being completed and published as archived | web/index.html:2345 |
| Winn Protocol trademark; trademark and patent filings in process | web/index.html:2746 |
| Gateway recovery file fetched from GitHub raw so the app can find gateways when DNS/CDN paths are censored | web/index.html:2704 |
| Post-quantum resistance and traffic stealth claims in the public comparison table | web/index.html:2340 |
| Winn Protocol v3 transport in the demo: X25519 + ML-KEM-768 hybrid, Ed25519-signed descriptors, compiled-in verification ring G1, fail-closed | SUPERVISOR RECEIPT, 2026-08-17 |
| Router source and live deployment: Cloud Run at https://AI_ROUTER_HOST | SUPERVISOR RECEIPT, 2026-08-17 |

## Claims that need OWNER-FILL numbers (no public source, never invented)

- Launch date precision ("end of June 2026"): owner confirmation. Supported indirectly by the July 4, 2026 notice (web/index.html:2096) implying live operations by then, and the exemption effective date June 11, 2026 (web/index.html:2674).
- Revenue, users, expenses, donors, marketing spend: REVENUE_TEMPLATE.md only.
- Physical-device carriage evidence: owner holds it; describe, do not fabricate.
- Exact Devpost category name at submission time: confirm against the page; recommended category is Education & Human Potential.