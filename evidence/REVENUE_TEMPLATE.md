# REVENUE_TEMPLATE.md - Devpost Required Finance Fields

Rules: fill every OWNER-FILL cell with real numbers from PayPal reports and the hub admin panel before 4:00 PM EDT. If a value is genuinely zero, write $0. Never estimate. Never round up. These fields are attested on Devpost.

## Remaining OWNER-FILL boxes (one-stop list)

Every box below still needs the owner. Fill them in the tables in this file; do not paste numbers anywhere else.

1. Total revenue to date and the exact launch date for the period row.
2. Monthly gross revenue: June, July, August 2026 (state $0 plainly if a month had no sales; the July 4 promo may make July near-zero).
3. Expense totals by category (hosting/GCP, Gemini API, app store, PayPal fees, tools, hardware, other) and the total.
4. Marketing spend total and channels.
5. Related-party revenue (Win Empire LLC / founder / board / family) and its nature.
6. User counts: paid accounts, free tier, active last 30 days, platform breakdown, donor count, testimonials pointer.

## Total Revenue

| Field | Value |
|---|---|
| Total revenue to date (all sources, since launch) | OWNER-FILL $ |
| Period covered | June 2026 launch date OWNER-FILL through Aug 17, 2026 |

Source of truth: PayPal transaction reports (sales, not donations) for the Win's VPN Inc. account. Exclude personal transfers.

## Revenue by Month

| Month | Gross revenue | Notes |
|---|---|---|
| June 2026 | OWNER-FILL $ | Launch month. Possible $0 if launch was after first sale. |
| July 2026 | OWNER-FILL $ | Note: July 4 promo gave premium servers free until Aug 31, 2026 (website notice). Revenue may be $0 or near it. Say so plainly if true. |
| August 2026 (through submission date) | OWNER-FILL $ | |

## Total Expenses

| Category | Amount to date | Notes |
|---|---|---|
| Hosting and infrastructure (servers, domains, CDN) | OWNER-FILL $ | Include GCP spend for the project "Win's VPN XPRIZE": Cloud Run (live router at https://AI_ROUTER_HOST), Compute Engine (staging hub + 2 winn3 gateway nodes), Artifact Registry, Cloud Logging. |
| AI API costs (Gemini API) | OWNER-FILL $ | Router decisions (gemini-3-flash-preview) + Hoppy. GCP billing export shows Gemini API line items. |
| App store and developer accounts | OWNER-FILL $ | |
| Payment processing fees (PayPal) | OWNER-FILL $ | |
| Software, tools, certificates, security | OWNER-FILL $ | |
| Hardware (v3 R&D devices, if attributed to the business) | OWNER-FILL $ | |
| Other (specify each in notes) | OWNER-FILL $ | |
| **Total expenses** | **OWNER-FILL $** | |

Note: the VPN client and nonprofit predate the hackathon window minimally and are disclosed. The Gemini adaptive routing layer, the Cloud Run deployment, and the v3 demo gateway network were built during the window for this submission. Any costs for those items belong here; any client costs from before the window are not hackathon spend. Do not invent either number.

## Marketing Spend

| Field | Value |
|---|---|
| Paid marketing to date | OWNER-FILL $ (state $0 if none was ever spent) |
| Channels used, if any | OWNER-FILL (e.g., "none; organic and Ad Grants application only") |

## Related-Party Revenue

| Field | Value |
|---|---|
| Revenue from related parties (Win Empire LLC, founder, board, family) | OWNER-FILL $ (state $0 if none) |
| Nature of any related-party amounts | OWNER-FILL (e.g., "none" or "design services donated, not revenue") |

Note for judges: Win Empire LLC designs and builds the software used by the service, per the website company identity disclosure. Disclose any money that moved between the LLC and the nonprofit, or state that none did.

## User Evidence

| Field | Value |
|---|---|
| Total users to date (paid accounts) | OWNER-FILL count |
| Free tier users (if separately countable, else "not separately tracked") | OWNER-FILL count |
| Active users in last 30 days | OWNER-FILL count |
| Breakdown by platform (Android/iOS/Windows/macOS/Linux) | OWNER-FILL |
| Donor count (separate from customers) | OWNER-FILL |
| Testimonials / user feedback pointer | OWNER-FILL (support inbox excerpts with permission, Play Store review text, or "no public testimonials yet" if none) |

Do not screenshot anything containing user identifiers beyond what the site already publishes.

## Corporate / Nonprofit Identity

| Field | Value |
|---|---|
| Legal entity | Win's VPN Inc. |
| Entity type | Florida nonprofit corporation, 501(c)(3) public charity under 509(a)(2) |
| Florida filing document number | N26000008302 |
| IRS exemption effective date | June 11, 2026 |
| IRS determination letter date | July 21, 2026 |
| Business phone | (424) 946-7876 |
| Principal operations | Florida, USA |
| Fiscal year end | December 31 (Form 990-series filer) |
| Website | winsvpn.org |
| Evidence to attach | WIN'S VPN INC Certificate.pdf (already exists in the source tree), IRS determination letter if available to owner |

## Sign-off checklist before pasting into Devpost

- [ ] Every OWNER-FILL replaced or intentionally set to $0 / "none"
- [ ] Revenue total equals the sum of the three monthly rows (or explain a mismatch, e.g., mid-month launch)
- [ ] Expense total equals the sum of category rows
- [ ] No number appears anywhere that cannot be shown from PayPal, GCP billing, or the hub admin panel on request
- [ ] Nonprofit ID section matches the certificate PDF exactly
