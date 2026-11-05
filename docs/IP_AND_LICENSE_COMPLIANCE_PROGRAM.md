# Win's VPN IP And Open-Source License Compliance Program

Version: 2026-06-30.v1
Owner: Win Empire LLC engineering, with Win's VPN Inc. operator review
Review cadence: before every public release and at least quarterly

## Purpose

This program reduces the risk that Win's VPN software, scripts, website assets, app builds, or deployment configurations infringe third-party software copyrights, patents, trademarks, or license obligations.

This is an engineering control document, not legal advice. Counsel should review patent, trademark, copyright, and open-source-license strategy before public launch.

## Required Controls

1. Keep a current third-party inventory for app, server, website, installer, and deployment-script dependencies.
2. Identify each third-party component's license, source URL, version, and whether Win's VPN modifies, links, redistributes, or only calls it as an external program.
3. Preserve upstream copyright notices and license texts for redistributed software.
4. Keep Win's VPN proprietary code and configuration clearly separated from third-party source code.
5. Do not remove license headers from upstream files.
6. Do not represent upstream projects as owned by Win's VPN.
7. Track trademark status for every public mark. Win's VPN and Winn Protocol use the registered symbol in customer-facing materials per owner direction while filings are in process; release notes should preserve the filing status and counsel review record.
8. Do not use "patent pending" unless a provisional or non-provisional patent application has actually been filed.
9. Before release, run dependency/license review and save the output in the release evidence folder.
10. If a license conflict is found, block the release until counsel or engineering approves a remediation.

## Current High-Visibility Components

| Component | Current Use | Compliance Handling |
| --- | --- | --- |
| AmneziaWG / AmneziaWG-Go | Data-plane tunnel runtime and client-side tunnel compatibility | Track exact image/binary/source origin, preserve license notices, record whether any source modification is made. |
| Xray-core | TCP/WebSocket stealth fallback runtime | Track exact binary/source origin, preserve license notices, document config-only vs source modification. |
| WireGuard tooling | Key and tunnel support | Preserve notices where redistributed and avoid implying endorsement. |
| Flutter/Dart packages | App UI/networking/crypto dependencies | Track via `pubspec.lock` and generated dependency report. |
| Windows installer dependencies | Xray, AmneziaWG MSI, VC runtime | Track vendor source, hash, license, and redistribution permission. |

## Release Evidence

Each public release should save:

- Dependency inventory from `pubspec.lock`.
- Native binary inventory with SHA-256 hashes.
- Third-party notice file used in the installer/app package.
- Summary of modified third-party code, if any.
- Confirmation that Win's VPN-only proprietary logic/configuration is owned by Win Empire LLC or licensed to Win's VPN Inc.
- Patent/trademark status at release time.
- Insurance-impact note for any component or claim that could affect Technology Errors and Omissions, intellectual property, media liability, or cyber insurance underwriting.

## Patent And Trademark Guardrails

- "Win's VPN®" and "Winn Protocol®" may be used in customer-facing materials per owner direction while filings are in process.
- Keep evidence of filing status, specimen usage, and counsel or owner approval with each public release.
- "Patent pending" may be used only after filing a provisional or non-provisional patent application.
- Public claims should describe product behavior without disclosing confidential implementation details.

## Remediation

If a possible infringement or license issue is found:

1. Freeze the affected release.
2. Record the issue, component, evidence, and affected builds.
3. Remove, replace, isolate, or relicense the component.
4. Obtain written approval from engineering leadership and counsel before release.
5. Preserve the remediation record for insurance and audit review.

## Technology Errors And Omissions Interface

Before answering insurance questions about software copyright, open-source components, patent status, trademark status, or third-party code, review this program and the current third-party inventory. If the answer depends on legal interpretation, counsel or broker review is required before submission.

Technology Errors and Omissions applications should not describe AmneziaWG, Xray-core, WireGuard, Flutter, or other upstream projects as owned by Win's VPN. The accurate position is that Win's VPN uses third-party open-source components with preserved notices and separate proprietary configuration, orchestration, app logic, deployment automation, and operational controls.
