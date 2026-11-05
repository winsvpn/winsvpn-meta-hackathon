# Win's VPN Microsoft Store Win32-installer certification notes

These notes are a local Partner Center disclosure draft for the signed
offline EXE route of release `1.0.17+34` (`1.0.17` / `1.0.17.34`). They are
not completed certification evidence and do not claim upload readiness.
Public-trust signing identity, Partner Center enrollment, reviewer
credentials, reviewer routes, the immutable download URL, and the exact
installer hash remain owner-blocked until the owner supplies them.

The Store does not re-sign MSI/EXE submissions. The installer and every
Portable Executable it contains must be Authenticode-signed through a Microsoft
Trusted Root Program chain. An immutable, versioned HTTPS direct URL and the
silent Inno Setup install parameters are required for the Win32-installer
path, but those values are not recorded here. Attach the current
exact-artifact test report only when it exists. Do not remove the service,
elevation, or payment disclosures.

The release does not include the previously evaluated Mullvad split-tunnel
kernel driver.

The release builder verifies upstream hashes before copying dependencies into a
private staging directory, product-signs the otherwise unsigned Xray executable,
signs every app EXE/DLL, and asks Inno to sign both Setup and its generated
uninstaller. Microsoft, Privacy Technologies, and WireGuard payloads
retain their upstream signatures. Every signer must chain to Windows AuthRoot or
one of the explicitly pinned Microsoft 2010/2011 system roots; self-signed and
locally trusted private-CA identities are rejected. These notes do not attach a
signed installer or prove that signing has occurred.

Keep website and Partner Center as separate x64 artifacts:
`WinsVPN-Setup.exe` and `WinsVPN-PartnerCenter.exe`. Native ARM64 uses the
distinct names `WinsVPN-Setup-arm64.exe` and
`WinsVPN-PartnerCenter-arm64.exe`. Never submit the x64 EXE as ARM64 or mix
payload architectures in one installer. The ARM64 producer must run on a
Windows ARM64 host and rejects any loose executable or DLL that is not
PE32+ ARM64. Flutter stable does not support x64-host to ARM64 cross-building.
The Inno bootstrap is a vendor compatibility executable; the native ARM64
claim is bound to the Flutter runner and complete VPN payload, not the setup
stub's own machine type. These names are not evidence that either candidate
exists or is upload-ready.

## Product selection policy

Standalone Winn Protocol v3 is primary. Winn Protocol v1 is fallback and
tries current reviewed AmneziaWG first, then current reviewed Xray only if
AWG fails. Certification review must not treat AmneziaWG as the primary
product path or Xray as the first fallback.

## Restricted capabilities

- `runFullTrust` is required because the Flutter desktop application runs the
  standalone Winn Protocol v3 datapath and, on Winn Protocol v1 fallback,
  invokes the current reviewed AmneziaWG and Xray engines and communicates
  with the co-installed protected tunnel-manager service.
- `allowElevation` is required because Windows permits installation/removal of
  the AmneziaWG tunnel service and protected tunnel manager only from an
  elevated process. The Inno installer requests UAC once to install the
  dependencies and dedicated service. The Flutter application itself carries
  `requestedExecutionLevel=asInvoker` and does not bypass UAC.

## Driver and NT service disclosure

- Windows per-application exclusions are disabled in this release. The
  previously reviewed Mullvad 1.3.0.0 SYS/CAT/INF package is excluded from all
  installers because upstream issue #10738 reports a nonpaged-pool leak. It may
  return only after a fixed, signed upstream package passes an independent
  long-duration kernel-pool stress gate. Destination-based split tunneling
  remains available without that driver. The automatic-start `WinsVpnTunnelManager` service
  performs only the reviewed privileged tunnel operations. It starts
  immediately so the signed-in GUI cannot race a delayed service during the
  boot/sign-in window and misreport a repair failure. Its
  local-only pipe verifies the active-session, co-installed UI process and
  rejects unreviewed config sections, duplicate keys, script directives, NUL
  bytes, and oversized input.
- Standalone Winn Protocol v3 is the primary tunnel. Exact Winn Protocol v3
  reviewer nodes are owner-blocked and are not listed in these notes.
- Winn Protocol v1 fallback uses the current reviewed, Authenticode-signed
  AmneziaWG Windows engine first. That engine creates the per-tunnel
  `AmneziaWGTunnel$winsvpn` service only when connecting and removes it on
  disconnect. This is necessary to provide the advertised AmneziaWG protocol
  rather than substituting ordinary WireGuard.
- If that AmneziaWG attempt fails, Winn Protocol v1 then uses the current
  reviewed Xray executable. Xray is started as a child process only for that
  selected fallback route, is bound to loopback for the AWG handoff, and
  remains unprivileged. It is placed in a kill-on-close Job object. The tunnel
  manager verifies the co-installed Xray PID and removes AWG routing if that
  carrier exits unexpectedly. Loopback HTTP on port 80 is not a public
  listener. Local HTTPS control uses port 443 only as a loopback bind for
  that handoff. UDP 9110 is the default AmneziaWG remote port when a served
  route does not name another port. Exact reviewer endpoints remain
  owner-blocked and are not listed here.
- Exact component versions, upstream licenses, SHA-256 values, Authenticode
  status, and source references are recorded only in a submitted artifact
  manifest and `docs/THIRD_PARTY_NOTICES_AND_COMPONENT_INVENTORY.md` when
  those documents are attached by the owner. These notes do not copy those
  hashes.

## Network and privacy behavior

- Product selection follows the policy above. Exact reviewer-safe routes are
  owner-blocked and are not listed here.
- The client never embeds or falls back to the private Control Hub origin.
  Gateway discovery uses authenticated public edge configuration and the VPN
  connects only to disposable data-plane endpoints returned for the account.
- Before VPN connection, location artwork is offline/native and makes no map
  tile requests. The product does not sell browsing history and follows the
  public no-log/privacy disclosures linked from the Store listing.

## Commerce

- Win's VPN is a non-game PC product. Premium access is purchased through the
  secure PayPal checkout on `https://winsvpn.org`; the app does not collect card
  data. The listing and purchase screen identify PayPal as the transaction
  provider. This secure third-party subscription path is disclosed in Partner
  Center.

## Certification test account and procedure

- Test account: OWNER-BLOCKED: ABSENT. A time-limited Partner Center reviewer
  account has not been supplied by the owner. This field is not completed
  evidence.
- Test regions/routes: OWNER-BLOCKED: ABSENT. Reviewer-safe standalone Winn
  Protocol v3 primary nodes and Winn Protocol v1 fallback nodes have not been
  supplied by the owner. This field is not completed evidence.
- Attach evidence, when the owner later supplies it, for clean Store install,
  UAC, standalone Winn Protocol v3 primary, Winn Protocol v1 current reviewed
  AmneziaWG, then current reviewed Xray only if AWG fails, destination split
  routing, DNS/IPv4/IPv6 leak prevention, disconnect, update, uninstall, and
  no residual `WinsVPN*`/`AmneziaWGTunnel$winsvpn` services or drivers. Missing
  evidence is not a pass.
- Installer type: signed, standalone/offline Inno Setup EXE.
- Silent install parameters: `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART
  /RESTARTEXITCODE=3010 /SP-`. Exit code `3010` is a successful installation
  that must be rebooted before certification continues.
- Versioned HTTPS direct URL: OWNER-BLOCKED: ABSENT. An immutable, versioned HTTPS
  direct URL has not been supplied by the owner. This field is not completed
  evidence. Never replace installer bytes after a later Partner Center
  submission.
- Exact installer SHA-256: OWNER-BLOCKED: ABSENT. No installer hash is recorded
  here. This field is not completed evidence.
- Upload readiness: not claimed. These notes do not authorize Partner Center
  upload.
