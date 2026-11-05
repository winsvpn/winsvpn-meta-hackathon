# App Store Connect Submission Answer Sheet

Status: OWNER APPROVED 2026-08-31; COUNSEL REVIEW PENDING. This marking does not state or imply that counsel reviewed these answers.

Scope: Win's VPN 1.0.17+34 for iOS, its embedded non-VPN watchOS companion, and macOS. This file prepares answers only. It does not authorize credentials, upload, submission, release, or a portal change.

## App Review Guideline 5.4

Place in App Review Information, Notes:

> Win's VPN uses Network Extension and NEVPNManager to provide its core VPN service. Before activation or purchase, the app presents a clear declaration of the data it processes and how that data is used. It does not collect browsing history, DNS query history, traffic contents, raw VPN traffic, or destination activity. Win's VPN does not sell, trade, or otherwise monetize any user data collected through the VPN connection, and does not disclose such data to third parties. PayPal, SMTP2GO, Cloudflare, GitHub, Apple Maps, ipify, and speed-test operators process only the separately disclosed non-VPN functions described in the privacy policy. Win's VPN Inc. is the organization that operates the service.

Privacy Policy URL: `https://www.winsvpn.org/privacy/`

If App Review requests a VPN-service license for a selected territory, do not claim one exists. Keep that territory unavailable until a current license or a documented determination that no license is required is approved by counsel.

## App Privacy

In App Privacy, answer as follows:

- Does this app collect data? **Yes**.
- Data Used to Track You: **No**.
- User ID: **Collected**, **Linked to the User**, **Not Used for Tracking**, purpose **App Functionality**.
- Device ID: **Collected**, **Linked to the User**, **Not Used for Tracking**, purpose **App Functionality**.
- Coarse Location: **Collected**, **Linked to the User**, **Not Used for Tracking**, purpose **App Functionality**.
- Product Interaction: **Collected**, **Linked to the User**, **Not Used for Tracking**, purpose **App Functionality**.
- Purchase History: **Not Collected**.
- Diagnostics: **Not Collected by the app**.
- All other Apple data types: **Not Collected**, unless a final-binary re-audit proves otherwise.

The live record last verified July 11, 2026 is stale. At the later authorized submission, remove Purchase History and add Product Interaction. Do not claim this repository change updated App Store Connect.

## Export Compliance

Use these conservative answers for the intended 1.0.17+34 configuration. Re-audit the exact signed IPA and PKG before entering them because no current 1.0.17+34 Apple candidate set exists:

- Does the app use, access, contain, implement, or incorporate encryption? **Yes**.
- Is all encryption limited to encryption provided by the Apple operating system? **No**.
- Does the app implement standard encryption algorithms outside Apple's operating system? **Yes**.
- Does the app implement proprietary or non-standard encryption algorithms? **Yes, conservatively**. The binary ships protocol obfuscation and transport framing outside the published cryptographic primitives, including AmneziaWG randomized junk and padding parameters, enabled Xray transports, Winn v3 handshake framing, and single-packet authorization. This answer avoids claiming an exemption before counsel classifies the complete enabled protocol set.
- `ITSAppUsesNonExemptEncryption`: **YES**.
- `ITSEncryptionExportComplianceCode`: **Leave absent** until Apple issues a code for accepted documentation.
- Has Apple-approved export documentation already been obtained for this binary? **No**.

Submission remains held until export counsel confirms the U.S. classification, any License Exception ENC submission or reporting duty, and Apple's required documentation. No CCATS, self-classification report, French declaration, or Apple approval is represented as filed or obtained.

Submission is separately held until counsel reviews the mandatory clickwrap against Guideline 3.1.1: the clickwrap presents external PayPal recurring subscription terms and a plaintext `https://www.winsvpn.org/billing/` URL with no tappable purchase control, and counsel must confirm that Apple's standard EULA does not conflict with those additional terms.

## Availability, Sanctions, and Myanmar Context

In Pricing and Availability choose **Specific Countries or Regions** and select **United States only** for the first submission. Do not select all storefronts.

Myanmar is a core intended beneficiary context for the product's censorship-resistance and safety design. Put this sentence in App Review Notes:

> Win's VPN is designed in part for journalists, activists, and ordinary people affected by internet censorship in Myanmar. On iOS, the disclosed calculator safety screen and alternate home-screen icon are applied automatically once the device is activated and cannot be switched off in the app; the real interface appears after the user's six-digit PIN is entered. The macOS app has neither. The operating system's VPN status remains visible when a tunnel is active.

These paragraphs are additions to, not replacements for, the platform review notes. The iOS notes must continue to disclose the calculator safety screen and the installed on-device name `Win's VPN`; omitting either disclosure is not authorized. The macOS notes must continue to explain that those iOS-only details do not apply to the Mac app.

Do not enable the Myanmar storefront until counsel completes local VPN-law, license, sanctions, and export review. Do not make the app available to sanctioned persons, entities, end users, end uses, or destinations prohibited by applicable U.S. law. The repository does not claim an OFAC license or a Myanmar VPN license.

## Trademark, Content Rights, and Entity

Use these values in the App Information record:

- App name: **Win's VPN**.
- Company name / seller / developer organization: **Win's VPN Inc.**
- Service operator: **Win's VPN Inc.**
- Software and infrastructure builder: **Win Empire LLC**.
- Content Rights: **This app does not contain, show, or access third-party media content that requires separate content-rights clearance.**
- Trademark presentation in App Store Connect: use **Win's VPN** and **Winn Protocol** without `(R)`. Do not state that either mark is federally registered. Use of `(TM)` in public copy is a source-accuracy question, not proof of registration; omit it from the submission answers.

The repository does not contain an executed intercompany trademark or software-rights instrument establishing the complete rights chain between Win Empire LLC and Win's VPN Inc. Do not claim that instrument exists. Keep supporting entity and rights-chain evidence counsel-pending and provide it only if verified and requested.

## Record Locations

- Guideline 5.4 and Myanmar context: App Review Information, Notes for iOS and macOS.
- Privacy answers: App Privacy for Apple ID `6789417002`.
- Export answers: App Information, Export Compliance, and the binary's `Info.plist` declaration.
- Availability: Pricing and Availability, Countries or Regions.
- Entity and content rights: App Information and the Apple Developer organization record.
- Trademark presentation: app name, subtitle, description, keywords, promotional text, and review notes.

No App Store Connect action was taken by this lane.
