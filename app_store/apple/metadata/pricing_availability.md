# Apple Pricing And Availability Decision

Last reviewed: 2026-08-31

Status: OWNER APPROVED; COUNSEL REVIEW PENDING. This does not state or imply that counsel reviewed this decision.

## Recommended First Submission

- App price: Free.
- In-App Purchases: None in the first Apple binary unless Apple subscription
  products are created, tested, and submitted for review at the same time.
- Premium access behavior: The Apple build's Premium Access Info button opens
  the developer's home page, https://www.winsvpn.org, in the user's browser.
  The app embeds no payment SDK, offers no in-app purchase, and does not open a
  checkout or payment page. Users can use an existing Win's VPN account number
  or Try Free Server.
- Release option: Manual release after approval.
- Phased release: Off for the first release, unless owner review chooses a
  staged rollout after TestFlight feedback.

## Availability

For the first submission, choose Specific Countries or Regions and select the
United States only. Do not select all storefronts. Myanmar is a central intended
beneficiary context for the product, but keep its storefront unavailable until
local VPN-law, license, sanctions, and export review is complete. This
1.0.17+34 binary is the universal iOS/macOS purchase; it is not an Apple TV
listing. This file does not authorize a portal change.

## App Review Open Item

The mandatory clickwrap describes the external PayPal recurring terms and
shows a plaintext billing URL, but it provides no tappable purchase control.
Hold submission until counsel reviews that disclosure against Guideline 3.1.1
and confirms that using Apple's standard EULA does not conflict with the
additional clickwrap terms.

## Future Paid Plan

If Apple subscriptions are added later, prepare the subscription group,
products, review screenshots, review notes, App Store Server Notifications,
receipt/server-validation flow, privacy answers, and TestFlight sandbox tests
before changing the Apple build's premium-access path.
