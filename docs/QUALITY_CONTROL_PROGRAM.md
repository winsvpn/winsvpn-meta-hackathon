# Win's VPN Written Quality Control Program

Version: 2026-06-30.v1
Owner: Win Empire LLC engineering
Applies to: Android, Windows, future iOS/macOS/Linux apps, control hub, data planes, website, installers, deployment scripts

## Objective

Win's VPN releases must be reviewed, tested, documented, and accepted before production use. The goal is to reduce outages, security regressions, privacy mistakes, and customer-impacting defects while keeping the customer experience simple.

## Quality Gates

Every production release should have a release evidence folder containing:

1. Scope summary and release version.
2. Files changed and reason for change.
3. Open-source/license review result.
4. Security/privacy review result.
5. Test output.
6. Build artifact hashes.
7. Deployment instructions or migration notes.
8. Company release acceptance signoff.
9. Insurance-impact review when a release changes security, privacy, payment, activation, routing, or customer-facing legal terms.

## Minimum Test Requirements

### App

- `flutter analyze`
- `flutter test`
- Android release build
- Windows release build
- Fresh install test after uninstalling old app
- Free server activation test
- Paid-account activation test when test credentials are available
- Winn Protocol® direct AWG and Xray fallback test when servers are available
- No-leak check after connection
- Wi-Fi/mobile-data transition test when a debug phone is available

### Control Hub

- `shellcheck` for deployment scripts
- Embedded FastAPI syntax compile
- SQLite schema migration sanity check
- `/healthz`, `/nodes`, `/legal/current`, `/verify`, `/free/verify`, and PayPal webhook smoke tests after deploy
- Backup and restore dry-run where practical

### Data Plane

- `shellcheck` for deployment scripts
- Service status checks for AmneziaWG, Xray, Nginx, AdGuard Home, hardening, node registration, and IDS where enabled
- NAT/firewall validation
- Node registration and heartbeat validation
- VPN egress IP validation

### Website

- Local preview check
- Download links check
- Legal links check
- Language selector smoke test
- AI support widget smoke test
- Metadata and favicon check

## Defect Severity

- P1: Security, privacy, payment, account lockout, no internet, app cannot install, or deployment crash.
- P2: Core feature broken, misleading legal/privacy wording, serious UI issue, or server registration problem.
- P3: Cosmetic, copy, or minor administrative issue.

P1 blocks release. P2 requires owner approval to release. P3 can ship with a follow-up task if customer risk is low.

## Release Acceptance

Company signoff means Win Empire LLC engineering and Win's VPN Inc. operations accept the release for production. Customer acceptance is captured separately through the app clickwrap legal acceptance before activation.

## Technology Errors And Omissions Readiness

The quality program is part of the Technology Errors and Omissions insurance evidence package. Before public launch and before each insurance renewal, Win's VPN should confirm that release evidence, customer acceptance records, legal version/hash records, third-party component inventories, incident records, and change signoffs are available for broker or underwriter review.

Do not claim an active Technology Errors and Omissions policy exists unless a binder or declarations page has been issued. If coverage is bound, keep the carrier name, policy number, effective dates, limits, retroactive date, exclusions, and endorsements in the insurance evidence folder.

## Records

Keep release evidence, hashes, test output, and signoff records for at least seven years or the period required by insurance/counsel, whichever is longer.
