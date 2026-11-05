# VPS Disk Encryption Runbook

Last updated: 2026-10-11 (LUKS-FIX round: one early-boot network file, dropbear-only DHCP)

## Recommendation

Use LUKS2 during the VPS OS reinstall, then run the Win's VPN one-touch script with `REQUIRE_LUKS_ROOT=1`.

Do not try to encrypt the mounted root disk from the normal deployment script. That is risky on a remote VPS and can leave the server unbootable. The one-touch scripts now verify encryption early and configure remote unlock when the OS is already installed on LUKS.

## What This Protects

- Protects root filesystem and swap data at rest if the virtual disk/NVMe image is copied while powered off.
- Prevents simple offline password-reset or filesystem edits against the encrypted root volume.
- Keeps Win's VPN application secrets, SQLite databases, logs, and root-owned env files inside encrypted storage when the OS was installed correctly.

## What This Does Not Fully Protect

- A live malicious hypervisor or provider with memory access while the VPS is running.
- Evil-maid bootloader/initramfs replacement if `/boot` is not independently verified.
- Traffic/content that is never supposed to be logged by the VPN in the first place.

The practical VPS design leaves `/boot` and `/boot/efi` unencrypted so initramfs can boot and accept an SSH unlock. Root and swap should be inside LUKS.

## Recommended Partition Layout

- EFI system partition: 512 MB, FAT32, mounted at `/boot/efi`, unencrypted.
- Boot partition: 1-2 GB, ext4, mounted at `/boot`, unencrypted.
- LUKS2 encrypted partition: rest of disk.
- Inside LUKS: root filesystem `/` and swap, either directly through LVM or as a swap file stored on the encrypted root filesystem.

## Fresh VPS Procedure

1. Reset/reinstall the VPS from the provider panel using Ubuntu 24.04 and manual/custom install if available.
2. Enable LUKS2 encryption for the root volume. Put swap inside the encrypted volume or disable swap.
3. First boot requires provider console/VNC unlock.
4. Install your SSH public key in `/root/.ssh/authorized_keys`.
5. Run the appropriate one-touch script with encryption enforcement:

```bash
REQUIRE_LUKS_ROOT=1 \
LUKS_REMOTE_UNLOCK=1 \
LUKS_UNLOCK_SSH_PORT=2222 \
LUKS_UNLOCK_SSH_AUTHORIZED_KEYS='ssh-ed25519 AAAA... your-admin-key' \
./deploy.sh --deploy
```

For a provider that does not provide DHCP in initramfs, also set Ubuntu initramfs networking explicitly:

```bash
LUKS_INITRAMFS_DEVICE=eth0
LUKS_INITRAMFS_IP='client-ip::gateway-ip:netmask:hostname:eth0:none'
```

## Reboot Unlock Procedure

After a reboot, the server waits in initramfs until unlocked:

```bash
ssh -p 2222 root@SERVER_IP cryptroot-unlock
```

Then enter the LUKS passphrase. After unlock, the normal OS boots and the usual Win's VPN services start.

Provider firewalls must allow TCP `2222` from your trusted admin IP or from the already-unlocked control hub if you unlock data planes through the hub.

## Script Behavior

Both one-touch scripts now run this check immediately after apt package installation and before secrets/services are written:

- `REQUIRE_LUKS_ROOT=0` default: warn if root is not LUKS and continue.
- `REQUIRE_LUKS_ROOT=1`: abort if root is not backed by LUKS/dm-crypt.
- `REQUIRE_LUKS_ROOT=1`: abort if active swap exists outside LUKS. Swap files are accepted when their backing filesystem is LUKS-backed.
- If root is LUKS and `LUKS_REMOTE_UNLOCK=1`, install and configure:
  - `cryptsetup-initramfs`
  - `dropbear-initramfs`
  - `busybox`
  - `/etc/dropbear/initramfs/authorized_keys`
  - `/etc/dropbear/initramfs/dropbear.conf`
  - `/etc/initramfs-tools/conf.d/winn-fde-network` (the one early-boot network file, also written by `deploy/fde_boot_chain.sh`; a legacy `wins-remote-unlock` is backed up under `/var/backups/winsvpn-luks-unlock` and removed, handoff section 42)
  - `update-initramfs -u -k all` (verified afterwards by `verify_luks_unlock_initramfs`)

## Operational Notes

- Do not store the LUKS passphrase on the same VPS.
- Keep a separate emergency copy of the unlock public/private key pair.
- Test one reboot/unlock before treating the server as production-ready.
- If a provider cannot offer custom install, LUKS root encryption may require rescue ISO access. If neither custom install nor rescue ISO is available, choose a provider that supports encrypted OS installs for sensitive nodes.
