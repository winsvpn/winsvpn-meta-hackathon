# Android release route-guard workflow

This workflow exists only to produce truthful physical Android release evidence. It does not open provider firewalls, change VPN configuration, deploy application code, or authorize publication.

The observer is deliberately isolated from normal production administration:

- one dedicated Ed25519 key, stored only under a private `.artifacts` directory;
- one locked `winsroute` account on each observed first-hop host;
- an authorized-key `restrict` option and a root-owned forced-command dispatcher;
- passwordless sudo limited to the four validated guard actions: `snapshot`, `apply`, `observe`, and `restore`;
- key-only SSH with strict pinned-host verification;
- a redacted hub-derived inventory that expires after one hour;
- watchdog restoration in the existing route guard.

No private key, server credential, raw client public IP, Core ID, or exit slug is written to Git or printed by the workflow.

## Safety gates

Do not start the Android collector unless all of these are true:

1. The current frozen release index and Android carry-forward receipt verify.
2. IONOS inbound UDP/9110 reaches the Spain host NIC.
3. Existing node and Core management aliases authenticate with keys and pinned host keys.
4. The management accounts can run `sudo -n python3 -` through the already-approved management channel.
5. `node-release` and `core-release` pass a zero-active-operation snapshot.
6. The inventory was generated from the hub less than one hour ago.

The workflow must stop before Android uninstall when any gate fails.

## One-time release identity

Run from the repository root on the controller that will execute the physical test:

```powershell
python tools/android_route_guard_release_bootstrap.py init-key `
  --identity .artifacts/private-release-route-control/id_ed25519
```

The command refuses to overwrite a key and restricts the private directory ACL. Back up this release-test identity through the same protected operator-secret process as other deployment keys; never commit it.

## Provision each observed host

Provision only through an existing authorized management alias. The tool forces key-only authentication for the management connection, streams public source plus the release public key to `sudo -n python3 -`, validates all guard dependencies, locks the account password, validates sudoers with `visudo`, and returns a redacted digest attestation.

```powershell
python tools/android_route_guard_release_bootstrap.py provision-target `
  --management-alias <existing-node-management-alias> `
  --role node `
  --public-key .artifacts/private-release-route-control/id_ed25519.pub

python tools/android_route_guard_release_bootstrap.py provision-target `
  --management-alias <existing-core-management-alias> `
  --role core `
  --public-key .artifacts/private-release-route-control/id_ed25519.pub
```

This step is intentionally unavailable over password SSH. If either managed channel cannot perform non-interactive sudo, repair that approved channel separately; do not add a password, broaden sudo, or expose public SSH for this test.

## Render isolated release aliases

The release aliases inherit the existing management host, port, Cloudflare proxy command, and pinned known-hosts path. They override the user, identity, and authentication policy. The generated file is private and does not alter the normal SSH config.

```powershell
python tools/android_route_guard_release_bootstrap.py render-alias-config `
  --node-management-alias <existing-node-management-alias> `
  --core-management-alias <existing-core-management-alias> `
  --identity .artifacts/private-release-route-control/id_ed25519 `
  --output .artifacts/private-release-route-control/release_ssh_config
```

The strict route controller consumes it through an inherited environment variable:

```powershell
$env:WINSVPN_ANDROID_SSH_CONFIG = `
  (Resolve-Path .artifacts/private-release-route-control/release_ssh_config).Path
```

## Generate a fresh redacted inventory

The hub query opens SQLite in read-only mode, requires exactly one eligible free exit/Core pair, and emits only ports, fixed alias names, and SHA-256 identity digests.

```powershell
python tools/android_route_guard_release_bootstrap.py fetch-inventory `
  --hub-alias <existing-hub-management-alias> `
  --output .artifacts/private-release-route-control/android-route-inventory.json
```

The inventory becomes invalid after one hour. Generate it immediately before preflight and physical collection.

## Preflight and collect

```powershell
python tools/android_route_guard_release_bootstrap.py preflight `
  --inventory .artifacts/private-release-route-control/android-route-inventory.json `
  --ssh-config .artifacts/private-release-route-control/release_ssh_config
```

Only after preflight passes and UDP/9110 reaches the data-plane NIC may the approved collector run. Keep the same `WINSVPN_ANDROID_SSH_CONFIG` environment variable and supply the fresh inventory, frozen carry-forward index, original Android receipt, physical serial, Tesseract path, and truthful expected map cities.

The collector itself performs the mandatory uninstall, exact APK install, launch, logcat review, route matrix, split tunneling, network transitions, map OCR, disconnect, cleanup, and rollback evidence. Never hand-translate partial or supplemental observations into the schema-v3 release record.

## Verification

```powershell
python tools/android_route_guard_release_bootstrap.py self-test
python tools/android_remote_route_control.py self-test
python -m unittest tools.test_android_route_guard_release_bootstrap tools.test_android_final_evidence_collector
```

If a live preflight fails, leave the phone disconnected, verify no `tun0` or Xray process remains, and retain only a redacted blocker record.
