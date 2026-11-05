# Win's VPN Technology Errors And Omissions Insurance Readiness Program

Version: 2026-06-30.v1
Owner: Win's VPN Inc. operations and Win Empire LLC engineering
Applies to: cyber insurance, Technology Errors and Omissions insurance, professional liability underwriting, customer-contract evidence, release evidence, and incident records

## Purpose

This program documents how Win's VPN Inc. and Win Empire LLC prepare for Technology Errors and Omissions insurance underwriting. It is an operational control document, not a statement that a policy is active. Do not represent that an active Technology Errors and Omissions policy exists unless a binder, declarations page, policy number, carrier, effective dates, limits, retroactive date, and endorsements have been issued and saved in the insurance evidence folder.

## Policy Status Rule

If an insurance application asks whether an active Technology Errors and Omissions policy exists:

1. Answer "Yes" only if the policy is already bound and the declarations page or binder is available.
2. Answer "No" or contact the broker/carrier if the organization is only applying, shopping, or waiting for a quote.
3. Do not use customer terms, website wording, or internal readiness documents as a substitute for a bound insurance policy.
4. Preserve all broker communications and application responses in the insurance evidence folder.

## Named Insureds To Request

The preferred policy structure should be reviewed by a licensed broker, but the insurance request should generally identify:

- Win's VPN Inc. as service operator.
- Win Empire LLC as software, website, deployment automation, infrastructure, and engineering provider.
- Any additional insured, waiver of subrogation, or contractual coverage wording only if required by a written contract and approved by broker/counsel.

## Coverage Areas To Discuss With Broker

The broker should be asked whether the policy covers, excludes, sublimits, or requires endorsements for:

- Technology professional services and software products.
- VPN service availability, deployment, configuration, update, and maintenance errors.
- Security failure, privacy liability, network interruption, and incident response costs.
- Media liability and advertising injury.
- Intellectual property risk, including copyright and trademark allegations, to the extent available.
- Open-source software usage, redistribution, and alleged license violations.
- Payment processing, PayPal webhook handling, subscription provisioning, and customer email notifications.
- International customers and users in high-censorship jurisdictions.
- Free, donated, trial, and administrator-granted access.
- Contractors, outsourced infrastructure providers, Cloudflare, Netlify, IONOS, InterServer, PayPal, SMTP2GO, GitHub, app stores, and other vendors.
- Prior acts, retroactive date, claims-made reporting requirements, extended reporting period, and defense-cost treatment.

## Required Underwriting Evidence

Maintain the following evidence before public launch and before every renewal:

- Current architecture blueprint without secrets.
- Current deployment scripts with shellcheck results.
- Current app build hashes and installer hashes.
- Written quality control program.
- Change management and company signoff procedure.
- Customer clickwrap acceptance procedure.
- Current public legal terms, privacy/no-log policy, acceptable use policy, hold harmless agreement, limitation of liability, electronic records notice, and insurance notice.
- IP and open-source license compliance program.
- Third-party component inventory and notices.
- Security controls summary, including IDS/IPS, Fail2Ban, firewall controls, backups, alerting, patching, and incident escalation.
- Incident response, backup, and retention evidence.
- Broker questions, application answers, binders, declarations pages, exclusions, endorsements, and renewal notes.

## Customer Contract Controls

Customer acceptance is captured through clickwrap before paid or free activation. The customer-facing flow must remain simple, but it must preserve evidence that the user accepted:

- Terms of Service.
- Hold Harmless Agreement.
- Limitation of Liability.
- Electronic Records consent.
- Acceptable Use obligations.

The hub stores tamper-evident acceptance metadata, including document version, document hash, account or free-access identity, device bucket, source IP bucket, platform, app version, locale, timestamp, and HMAC signature. This supports E-SIGN style evidence without storing browsing history, DNS query history, destination traffic, or raw VPN traffic metadata.

## Insurance Notice Boundary

Insurance wording in public terms must not promise coverage to customers. Any public or app wording should say that insurance, if bound, is governed only by the issued policy, is for the named insureds only, and does not create:

- A service warranty.
- A direct claim right.
- Third-party beneficiary status.
- Guaranteed recovery.
- A higher liability cap.
- Any change to customer hold harmless, acceptable use, or limitation of liability obligations.

## Change And Renewal Cadence

Review this program:

- Before first public launch.
- Before each insurance application or renewal.
- After any P1 security, privacy, payment, or outage incident.
- After material architecture changes such as new operating systems, new data-plane countries, Double VPN, Smart Boost bonding gateways, app-store publication, or new payment processors.

## Signoff

Company signoff should include:

- Date.
- Release or application version.
- Reviewer name/title.
- Broker or carrier name, if applicable.
- Coverage status: planned, quoted, bound, declined, or renewed.
- Known exclusions or unresolved questions.
- Evidence folder path or hash manifest.

