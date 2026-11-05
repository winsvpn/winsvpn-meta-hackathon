# Win's VPN Change Management And Customer Acceptance Procedure

Version: 2026-06-30.v1
Owner: Win's VPN Inc. operations and Win Empire LLC engineering

## Purpose

This procedure documents how Win's VPN changes are approved and how customer acceptance is captured without scaring customers or making activation complicated.

## Change Management

Every production change must have:

1. Change ID or release version.
2. Business reason.
3. Risk rating.
4. Affected systems.
5. Test evidence.
6. Rollback plan.
7. Release artifact hashes where applicable.
8. Company signoff.
9. Insurance-impact note if the change affects customer commitments, security controls, privacy/no-log boundaries, data retention, app behavior, payment handling, or service availability.

Emergency changes may be deployed first to restore service, but the evidence and signoff must be completed afterward.

## Company Signoff

Company signoff should include:

- Release version.
- Date and time.
- Approver name/title.
- Summary of tests reviewed.
- Known risks accepted.
- Artifact hashes.

The signoff can be stored as a text/PDF record in the release evidence folder. It does not need to be shown to ordinary retail customers.

## Insurance Evidence

Technology Errors and Omissions underwriting commonly asks whether the company has written customer acceptance procedures, warranty disclaimers, limitation of liability language, hold harmless or indemnity language, and final signoff on deliverables. Win's VPN addresses those points through:

- This written change-management procedure.
- Company release signoff records.
- Customer clickwrap acceptance before activation.
- Public legal terms and app-bundled fallback legal text.
- Tamper-evident server acceptance records.
- Release hashes, test results, and rollback notes.

Do not state that a Technology Errors and Omissions policy is active unless coverage is bound. Insurance readiness evidence supports the application process but is not a substitute for an issued policy.

## Customer Acceptance

Retail customers accept the service through a simple clickwrap flow in the app before activation. The customer sees concise checkboxes for:

- Terms of Service.
- Hold Harmless Agreement.
- Limitation of Liability.
- Electronic service records.

The hub stores a tamper-evident acceptance record with document version/hash, account or free-access identity, device bucket, source IP bucket, platform, app version, locale, timestamp, and HMAC signature.

## Public Wording Style

Customer-facing wording should be firm but calm:

"By activating or using Win's VPN, you agree to use the service lawfully, not attack or abuse our services or infrastructure, and accept the Terms, Hold Harmless Agreement, Limitation of Liability, and Electronic Records consent. We work hard to provide advanced privacy and security technology, but availability, speed, routing, compatibility, and access may vary by region, device, network, and censorship conditions."

Avoid threatening language such as "we will come after you." Use professional wording:

"We may suspend access, preserve evidence, cooperate with lawful process when required, and seek recovery of damages, costs, and fees caused by misuse, abuse, attacks, or unlawful conduct."

## Governing Law

Default public terms should use Florida law and Florida venue to the maximum extent permitted by law, while preserving non-waivable consumer rights required by a customer's country or state.

Suggested wording:

"These terms are governed by the laws of the State of Florida, United States, without regard to conflict-of-law principles, except where non-waivable consumer protection laws require otherwise."

Counsel should review international consumer-law, arbitration, class-action waiver, and venue language before broad public launch.
