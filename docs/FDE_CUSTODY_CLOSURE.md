# FDE custody closure contract

This contract separates guest evidence from provider and owner authority. A
guest-only inspection can establish the state of the running disk, cached
cloud-init data, and installed initramfs files. It cannot establish what the
provider control plane retains, which credential occupies a LUKS keyslot, or
which recovery image an owner approved.

## Required evidence

| Boundary | PASS evidence | Insufficient evidence |
|---|---|---|
| LUKS header | LUKS2, exactly one active keyslot, zero tokens, no active reencryption metadata | One active slot without a credential challenge |
| Credential transition | Conversion credential returns cryptsetup challenge exit 2 after removal; production credential returns exit 0 using the same device and invocation shape | Slot count, file absence, or a self-written boolean alone |
| Initramfs | Every regular `/boot/initrd.img-*` is nonempty, listable, and contains none of the conversion hook or credential names; every image with matching `/lib/modules/<release>` additionally carries the required cryptroot, cryptsetup, dropbear, and unlock-network paths, and at least one such bootable image exists | Checking only the running kernel image or treating an empty listing as clean |
| Guest files | Production and conversion passphrase files are absent; staged `fde.sh`, `fde_boot_chain.sh`, `ionos_fde_reinstall.sh` (retired, checked only for hosts staged by an older route), and `/usr/local/sbin/winn-fde-arm` are absent | A completion marker created before cleanup |
| Early-boot network | Exactly one DHCP owner in every bootable initramfs: `conf/conf.d/winn-fde-network` is the only file defining `IP=`, `IP6=`, `DEVICE=` or `DEVICE6=`, with `IP='dhcp'`, `DEVICE=''`, `DEVICE6=''`, `IP6='off'`, no script under `/etc/initramfs-tools/scripts/init-premount` calls `configure_networking`, exactly one `winn-fde` init-premount hook, no `zz-winn-fde-network`, no `conf/conf.d/wins-remote-unlock` and no `conf/conf.d/winn-fde-layout` (the PARTUUID pin of the conversion boots); the receipt carries `early_boot_network_mode` and `early_boot_dhcp_owner=dropbear-init-premount` | A boot that reached the unlock prompt once; a `DEVICE=<iface>` file that sorts after the boot chain's file |
| GRUB menu | `/etc/default/grub.d/99-winn-fde-menu.cfg` present with `GRUB_TIMEOUT=5`, `GRUB_TIMEOUT_STYLE=menu`, `GRUB_RECORDFAIL_TIMEOUT=5`, and the generated `grub.cfg` carries `set timeout=5` with no `set timeout=0`, `set timeout=-1` or `timeout_style=hidden` | A value in `/etc/default/grub` alone (the cloud image's `50-cloudimg-settings.cfg` overrides it) or a hand edit of `grub.cfg` |
| Guest cloud-init | Cached and datasource-query user-data are hashed and searched without printing content; FDE marker count is zero | Guest cleanup as a claim about provider storage |
| Provider control plane | Authenticated read-only evidence binds the provider account, server, and volume; records the current user-data disposition; enumerates relevant snapshots and private images; names the approved recovery point; and records the console-verified host fingerprint | SSH, DMI, NoCloud cache, local snapshot commands, or an unverified portal claim |

The pasted provider user-data (built by `deploy/make_ionos_user_data.sh`) holds
no credential: it stages the converter and the arm helper and arms nothing. Its
digest is recorded on the guest in `/var/lib/winn-fde-userdata.sha256`.

Provider exports may contain secrets. Record sanitized identifiers, timestamps,
counts, dispositions, and SHA-256 digests. Do not copy user-data contents,
passphrases, private keys, or authentication tokens into a report or commit.

If the provider does not support deleting launch user-data, the provider report
must say so and bind the retained payload by digest. The owner must separately
confirm that the payload never contained the production or conversion
credential. A guest hash match is useful corroboration, but it is not provider
authority.

## Boot-chain receipt

`fde_boot_chain.sh` publishes `/var/lib/winn-fde-custody.receipt` on the
encrypted root only after all of these operations succeed:

1. Every retained initramfs passes the residue and listability checks, and
   every bootable image with installed modules passes the required-assets
   check.
2. The conversion keyslot is removed.
3. The conversion credential challenge returns exit 2 and the production
   credential positive control returns exit 0.
4. Final LUKS metadata has one active keyslot and zero tokens.
5. Passphrase files and explicitly named one-shot entrypoints are absent.
6. The receipt is written to a temporary file, synced, atomically renamed, and
   followed by the completion marker.

The receipt records the source digest, boot ID, LUKS UUID, active keyslot IDs,
challenge return codes, `early_boot_network_mode`, `early_boot_dhcp_owner`,
`initramfs_count`, `bootable_initramfs_count`, and a digest for every scanned
initramfs. Its clock is labelled as unsynchronized
because it is written from initramfs. The receipt is post-hoc guest evidence.
It is not an unlock aid and must never be mirrored to unencrypted `/boot`.

On an adverse finalization path, the hook writes a stage-only incomplete
receipt when the encrypted root remains writable. The
`winn-fde-custody.pending` file may also remain after initramfs verification;
it is non-authoritative and never contains `state=closed`. No success marker
is published. Absence of a receipt is not proof that conversion never began.

## Legacy hosts

This source change does not retroactively close hosts converted by an older
boot-chain. A legacy completion marker may predate slot retirement. Close such
a host only with a fresh read-only guest inspection plus either a preserved,
owner-controlled conversion credential that fails the challenge or other
auditable evidence from the exact historical execution. Exactly one remaining
slot does not identify its credential.

Deleting a file proves pathname absence, not physical block erasure on a
virtual or copy-on-write disk. Provider snapshots and images taken before
credential retirement remain a separate control-plane question.

## Verdict language

- `PASS`: evidence directly proves the named boundary.
- `FAIL`: evidence shows residue, an unexpected credential result, or an
  unsafe metadata state.
- `UNVERIFIED`: required provider, owner, or out-of-band evidence was not
  available. Never convert this to PASS from guest evidence.

The hub and Spain deployment lanes require separate FDE custody reports. Each
report must include all three boundaries: guest state, credential transition,
and provider control plane.
