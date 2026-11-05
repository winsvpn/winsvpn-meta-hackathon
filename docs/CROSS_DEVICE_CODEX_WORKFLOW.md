# Cross-device Codex workflow

## Hosts and project locations

- Windows: `windows-host.local` (`windows-host\admin`), canonical project at `C:\Users\admin\Downloads\wins_vpn`
- Mac: `build-mac.local` (`winsvpn`), project at `/Users/winsvpn/Downloads/wins_vpn`
- Windows SSH alias for the Mac: `macbook`
- Mac SSH alias for Windows: `windows-lan`

Both directions use dedicated Ed25519 keys. Windows inbound SSH is restricted by its firewall to the local subnet.

## Windows commands for the Mac

Run these from the Windows project root:

```powershell
# Verify the connection, Xcode, Swift, Git branch, and remote Codex CLI.
.\tools\remote_mac.ps1 -Action Check

# List installed Apple simulators.
.\tools\remote_mac.ps1 -Action Simulators

# Run an arbitrary command in the Mac project.
.\tools\remote_mac.ps1 -Action Run -Command "git status --short --branch"

# Build the iOS simulator target without code signing.
.\tools\remote_mac.ps1 -Action BuildIOS

# Build the macOS target without code signing.
.\tools\remote_mac.ps1 -Action BuildMacOS

# Run the repository's Apple readiness verification.
.\tools\remote_mac.ps1 -Action VerifyApple
```

## Offload a Codex task to the Mac

Start a persistent Mac Codex session:

```powershell
.\tools\remote_mac.ps1 -Action Codex -Prompt "Inspect the iOS project and run the requested Mac-only checks."
```

The command output includes a session UUID. Continue that task directly from Windows:

```powershell
.\tools\remote_mac.ps1 -Action CodexResume -SessionId "SESSION-UUID" -Prompt "Continue with the next requested step."
```

Omit `-SessionId` to resume the Mac's most recent persisted Codex CLI session.

## Source synchronization

The private GitHub repository is the long-term source of truth. Keep normal changes on branches and push/fetch between hosts. For an uncommitted file that must be tested immediately, copy only that file while preserving its repository-relative path:

```powershell
scp .\relative\path\file.swift macbook:/Users/winsvpn/Downloads/wins_vpn/relative/path/file.swift
```

The Windows checkout intentionally excludes generated or bulk directories such as `.artifacts`, `.dart_tool`, `build`, `web/downloads`, and `Update/mac_codex_sync/packages`. Those artifacts remain on the Mac and in the repository history as applicable.

The live canonical working tree is `C:\Users\admin\Downloads\wins_vpn`. Reconciliation directories such as `_merge_metadata`, `_merge_variants`, `MacCodexSync-*`, `Update`, and `.artifacts` are evidence, source snapshots, or generated staging; they must never override or be deployed as canonical runtime source. A newer modification time is not sufficient to select a file. Select by the current product contract, security gates, tests, and platform ownership, then synchronize the chosen canonical file to the other host.

Production billing is PayPal-only. The retired Lemon Squeezy webhook must not exist in the active tree, publish staging, environment template, website, Cloudflare worker, deployment preseed, or control-plane scripts. After billing-related synchronization, run both release gates:

```powershell
python tools/test_paypal_entitlement_contract.py
python tools/website_security_audit.py
```

Codex's native connected-host registry did not automatically pair the two desktop installations. The SSH plus remote Codex CLI workflow provides direct task control independently of that registry.
