# Partial Encrypted Vault Fallback

Last updated: 2026-07-02

## Purpose

This is the fallback when a VPS provider does not make LUKS root encryption practical through the control panel, rescue ISO, or reinstall workflow.

The one-touch scripts can create a LUKS2 encrypted file container and place Win's VPN application secrets/configuration inside it. The passphrase is not stored on the VPS.

## What It Protects

When the VPS is powered off and the vault passphrase is not available, the partial vault protects the selected Win's VPN application data from simple disk-image browsing:

- Control hub:
  - `/root/vpn_auth`
  - `/root/vpn_auth.env`
  - `/var/lib/wins-security-alerts`
  - `/root/.config/rclone`
  - `/etc/winsvpn`
- Data plane:
  - `/root/node.env`
  - `/etc/amnezia`
  - `/usr/local/etc/xray`
  - `/opt/AdGuardHome`
  - `/root/.config/rclone`
  - `/etc/winsvpn`

## What It Does Not Protect

This does not protect the unencrypted operating system root. A provider, data-center operator, or attacker with offline disk-image access can still modify:

- `/etc/shadow` and root/user password hashes.
- SSH server files.
- systemd service files.
- boot files.
- kernel/initramfs/bootloader content.
- any code that can capture the vault passphrase on the next unlock.

So this fallback is useful for at-rest confidentiality of Win's VPN secrets, but it cannot provide the same tamper resistance as full root disk encryption.

## Deployment

Run the normal one-touch script with:

```bash
WINS_PARTIAL_VAULT_ENABLED=1 \
WINS_PARTIAL_VAULT_PASSPHRASE='use-a-long-unique-passphrase' \
./deploy.sh --deploy
```

Recommended sizes:

- Control hub default: `16G`
- Data plane default: `8G`

Override with:

```bash
WINS_PARTIAL_VAULT_SIZE=32G
```

The passphrase can be typed interactively instead of passed through the environment if you run the script manually in a terminal:

```bash
WINS_PARTIAL_VAULT_ENABLED=1 ./deploy.sh --deploy
```

## After Reboot

Because the passphrase is not stored on the VPS, services that need vault files may fail until the vault is unlocked.

Unlock manually:

```bash
sudo wins-vault-unlock
```

Then enter the vault passphrase. The unlock helper mounts the vault and starts the relevant Win's VPN services/timers.

## Recommended Policy

Use this fallback only when provider-side full root encryption is not available or is too slow to arrange.

For final high-assurance nodes, prefer:

```bash
REQUIRE_LUKS_ROOT=1 ./deploy.sh --deploy
```

The strongest practical setup is still full root LUKS encryption plus remote unlock, because it prevents simple offline root password resets and broad filesystem tampering.

