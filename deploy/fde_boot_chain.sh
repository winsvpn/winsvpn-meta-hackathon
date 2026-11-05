#!/usr/bin/env bash
# fde_boot_chain.sh v5: single-boot-cycle LUKS FDE for freshly reset cloud
# hosts. EVERYTHING happens offline in the initramfs pre-mount hook; the
# stage-2 systemd service of v2/v3 is GONE.
#
# WHY v5 (2026-10-11, LUKS-FIX round, Turn 2 convergence of the four seats;
# handoff section 42, Kansas 2026-09-04):
#   - ONE early-boot DHCP owner: dropbear's packaged init-premount script is
#     the only caller of configure_networking in the premount phase (Ubuntu's
#     own init calls it once more after the root is mounted, outside the
#     unlock window). conf.d/winn-fde-network holds
#     IP='dhcp', DEVICE='' (empty: ipconfig takes every interface, the
#     measured Kansas repair), DEVICE6='' and IP6='off'. The 00-winn-fde-network
#     hook is an inert kmsg marker; it never contains configure_networking or
#     ipconfig. Only DHCP hosts with exactly one physical NIC are qualified;
#     static, VLAN, bond and bridge networking refuse to arm.
#   - every stale winn-fde or wins-remote-unlock file in the initramfs script
#     and conf.d directories is removed before the canonical set is written;
#     the final listing must hold exactly one winn-fde init-premount hook.
#   - a visible 5 second GRUB menu, also after recordfail, lives in
#     /etc/default/grub.d/99-winn-fde-menu.cfg: on cloud images
#     50-cloudimg-settings.cfg sets GRUB_TIMEOUT=0 and GRUB_RECORDFAIL_TIMEOUT=0
#     AFTER /etc/default/grub is sourced, so /etc/default/grub alone cannot
#     carry it. Verified in grub.cfg after update-grub at arm time and again
#     inside the chroot.
#   - the kernel root argument is pinned to the GPT PARTUUID while the
#     conversion initramfs is armed (98-winn-fde-root.cfg): the ext4 UUID stops
#     identifying the raw partition once a LUKS header exists, and Noble's
#     local_device_setup resolves root= BEFORE local-premount hooks run, so an
#     interrupted encryption could never resume on root=UUID. Finalization
#     removes the override before the encrypted-root GRUB entries are built.
#   - the shrink continues straight into the offline encryption in the same
#     boot: one owner reboot arms the whole conversion.
#   - pre-flight refuses a host that is not UEFI x86_64 Ubuntu 24.04 on one
#     GPT disk with an ext4 root partition, a separate ext4 /boot and a vfat
#     ESP (PARTTYPE checked), fstab disagreeing with the mounts, a pending
#     reboot or a newer installed kernel, disk-backed swap, a prior armed or
#     incomplete conversion, vendor-directory FDE copies, more than one NIC,
#     no DHCP evidence, or a serial device as the LAST console= token while
#     the owner unlocks at the provider VNC console (then console=tty1 is
#     appended, because the passphrase prompt reads /dev/console).
#     WINN_FDE_PREFLIGHT_ONLY=1 runs only these read-only checks.
#   - the final dropbear.conf is byte-identical to the control-plane
#     installer's (forced cryptroot-unlock, IFDOWN=none); the conversion
#     initramfs keeps a shell so a failed conversion can be inspected on 2222.
#   - every installed kernel's initramfs is rebuilt and verified at arm time;
#     dm_crypt, xts and aesni modules and the NIC driver are added explicitly;
#     dropbear host-key fingerprints are printed; a silent set -e exit is
#     reported with its line and command.
#
# WHY v4 (2026-08-29, after live verification on the GCP test VM):
#   - cryptsetup reencrypt --encrypt on a DIRECTLY-MOUNTED root partition
#     FAILS ("Failed to open in exclusive mode (already mapped or mounted)")
#     -- measured. Online encryption of a plain root is not possible; both
#     the shrink AND the encryption must run pre-mount with the root not
#     mounted. v4 does exactly that, then prepares the boot stack from a
#     chroot of the ENCRYPTED root, then reboots into the LUKS boot.
#   - Proven working from v3: pre-mount hook execution (with /scripts guard
#     and raw ROOT-spec normalization), offline fsck+resize2fs shrink,
#     forced mkinitramfs builds, lsinitramfs verification (file-based,
#     SIGPIPE-proof), cloud-init growpart+resize_rootfs disabling.
#
# THE HOOK STATE MACHINE (runs pre-mount each boot, safe-continue on error):
#   1. root partition not LUKS, headroom < 256MiB  -> offline shrink, then
#      continue into state 2 in the same boot
#   2. root partition not LUKS, headroom >= 256MiB -> OFFLINE ENCRYPT, chroot
#      boot-stack setup (crypttab/fstab/dropbear/initramfs/grub), reboot
#   3. root partition IS LUKS -> finish or resume conversion while the
#      conversion credential exists. After successful finalization, the
#      LUKS-aware initrd and crypttab handle boot; the conversion hook has
#      removed itself.
#
# Usage (as root on the live host): bash fde_boot_chain.sh && reboot
#   Pre-flight only, nothing written:  WINN_FDE_PREFLIGHT_ONLY=1 bash fde_boot_chain.sh
#   Owner unlocks at a serial console:  WINN_FDE_UNLOCK_CONSOLE=serial
set -Eeuo pipefail

say() { echo "[fde-chain] $*" | tee -a /var/log/fde-chain.log; }
die() { echo "[fde-chain][FATAL] $*" | tee -a /var/log/fde-chain.log >&2; exit 1; }
# A failure that set -e would swallow silently is reported with its status,
# line and command instead of a bare exit (measured: a silent rc=2 in the
# QEMU rehearsal of this round).
on_unexpected_error() {
  echo "[fde-chain][FATAL] unexpected failure (rc=$1) at line $2: $3" | tee -a /var/log/fde-chain.log >&2
  exit "$1"
}
trap 'on_unexpected_error "$?" "${LINENO}" "${BASH_COMMAND}"' ERR

validate_passphrase_file() {
  local file="$1" bytes links mode owner parent_mode first last newlines
  [[ ! -L "${file}" ]] || die "passphrase file must not be a symlink: ${file}"
  [[ -f "${file}" ]] || die "deliver the passphrase as the regular file ${file}"
  owner="$(stat -c '%u' "${file}")"
  mode="$(stat -c '%a' "${file}")"
  links="$(stat -c '%h' "${file}")"
  [[ "${owner}" == "0" && "${mode}" == "600" && "${links}" == "1" ]] \
    || die "${file} must be root-owned mode 0600 with exactly one hard link"
  [[ "$(stat -c '%u' /root)" == "0" ]] || die "/root is not root-owned"
  parent_mode="$(stat -c '%a' /root)"
  (( (0${parent_mode} & 0022) == 0 )) || die "/root is group- or other-writable"
  bytes="$(wc -c < "${file}")"
  (( bytes >= 32 && bytes <= 4096 )) || die "passphrase file must contain 32 to 4096 bytes"
  newlines="$(LC_ALL=C tr -cd '\n' < "${file}" | wc -c)"
  (( newlines == 0 )) || die "passphrase file must contain no newline; deliver it with printf, not echo"
  first="$(od -An -tu1 -N1 "${file}" | tr -d ' ')"
  last="$(tail -c 1 "${file}" | od -An -tu1 | tr -d ' ')"
  case "${first}:${last}" in
    9:*|10:*|11:*|12:*|13:*|32:*|*:9|*:10|*:11|*:12|*:13|*:32)
      die "passphrase file must not start or end with whitespace" ;;
  esac
}

# The early-boot network file. ONE file, ONE DHCP owner (handoff section 42).
# The control-plane installer carries the same function and keeps a converted
# host's copy of this file; a test asserts the two outputs are identical.
write_early_boot_network_conf() {
  # $1 = dhcp | kernel ip= spec, $2 = device name ('' = every interface)
  printf '%s\n' \
    "IP='$1'" \
    "DEVICE='$2'" \
    "DEVICE6=''" \
    "IP6='off'" \
    'BUSYBOX=y'
}

# The GRUB menu file. 99- sorts after the cloud image's 50-cloudimg-settings.cfg.
write_grub_menu_cfg() {
  # $1 = optional full GRUB_CMDLINE_LINUX_DEFAULT value (console order fix)
  printf '%s\n' \
    '# Written by deploy/fde_boot_chain.sh (handoff section 42): a visible 5 second' \
    '# GRUB menu on every boot, also after a failed boot (recordfail), so the owner' \
    '# can reach the menu from the provider console. It sorts after' \
    '# 50-cloudimg-settings.cfg, which sets GRUB_TIMEOUT=0 after /etc/default/grub.' \
    '# server/wins_control_plane_setup_ONETOUCH.sh writes the same text when absent.' \
    'GRUB_TIMEOUT=5' \
    'GRUB_TIMEOUT_STYLE=menu' \
    'GRUB_RECORDFAIL_TIMEOUT=5'
  if [[ -n "${1:-}" ]]; then
    printf '%s\n' \
      '# The LUKS passphrase prompt reads /dev/console, which the kernel binds to the' \
      '# LAST console= token: a VGA console is kept last so the provider VNC console' \
      '# can unlock. The serial console still receives kernel messages.'
    printf 'GRUB_CMDLINE_LINUX_DEFAULT="%s"\n' "$1"
  fi
}

# Keep /etc/default/grub (named in handoff section 42) consistent with the
# drop-in, which decides: grub-mkconfig sources it after /etc/default/grub.
ensure_main_grub_menu() {
  # $1 = /etc/default/grub
  local file="$1" key value pair
  for pair in GRUB_TIMEOUT_STYLE=menu GRUB_TIMEOUT=5; do
    key="${pair%%=*}"
    value="${pair#*=}"
    if grep -Eq "^[[:space:]]*(export[[:space:]]+)?${key}[[:space:]]*=" "${file}"; then
      sed -i -E "s/^[[:space:]]*(export[[:space:]]+)?${key}[[:space:]]*=.*/${key}=${value}/" "${file}"
    else
      printf '%s=%s\n' "${key}" "${value}" >> "${file}"
    fi
  done
  sed -i -E '/^[[:space:]]*(export[[:space:]]+)?GRUB_HIDDEN_TIMEOUT(_QUIET)?[[:space:]]*=/s/^/# disabled by winn-fde: /' "${file}"
}

# The LAST console= token of every kernel line that has one must be the unlock
# console (recovery entries have none and are skipped; one line must qualify).
# The stock image already carries console=tty1 first, so presence proves nothing.
verify_console_last() {
  # $1 = generated grub.cfg, $2 = expected last token
  awk -v expected="$2" '
    /^[[:space:]]*linux[^[:space:]]*[[:space:]]/ {
      last = ""
      for (i = 1; i <= NF; i++) if ($i ~ /^console=/) last = $i
      if (last != "") { seen = 1; if (last != expected) bad = 1 }
    }
    END { exit (!seen || bad) }
  ' "$1"
}

verify_grub_menu_cfg() {
  # $1 = generated grub.cfg; the recordfail branch and the menu branch both set 5
  grep -Eq '^[[:space:]]*set timeout=5$' "$1" || return 1
  ! grep -Eq '^[[:space:]]*set timeout=(0|-1)$' "$1" || return 1
  ! grep -Eq '^[[:space:]]*set timeout_style=hidden$' "$1" || return 1
  return 0
}

[[ "${EUID}" -eq 0 ]] || die "run as root."
[[ -d /var/log ]] || install -d -m 755 /var/log
touch /var/log/fde-chain.log && chmod 600 /var/log/fde-chain.log

# ---- pre-flight on the LIVE system, READ-ONLY ------------------------------
# Every refusal here happens before a single byte is written. The checks name
# the exact host shape the pre-mount hook depends on (handoff section 42 and
# the LUKS-FIX round): UEFI x86_64 Ubuntu 24.04 on one GPT disk, ext4 root
# partition, separate ext4 /boot and vfat ESP, no pending reboot, no disk
# swap, no prior arm, one DHCP NIC, and a kernel console order that lets the
# owner's console show the prompt.
say "pre-flight: platform, boot mode, disk layout, kernel, console, network"
PREFLIGHT_ONLY="${WINN_FDE_PREFLIGHT_ONLY:-0}"
[[ "$(uname -m)" == "x86_64" ]] || die "host is $(uname -m); this chain is verified for x86_64 hosts only."
OS_ID="$(. /etc/os-release 2>/dev/null && printf '%s' "${ID:-}")"
OS_VERSION_ID="$(. /etc/os-release 2>/dev/null && printf '%s' "${VERSION_ID:-}")"
[[ "${OS_ID}" == "ubuntu" && "${OS_VERSION_ID}" == "24.04" ]] \
  || die "host is ${OS_ID:-unknown} ${OS_VERSION_ID:-unknown}; this chain is verified for Ubuntu 24.04 only."
[[ -d /sys/firmware/efi ]] || die "host is not currently booted in UEFI mode (BIOS boot is not qualified)."
[[ -d /boot/efi/EFI ]] || die "mounted ESP or its EFI directory is unavailable."
[[ -s /boot/efi/EFI/ubuntu/grub.cfg ]] \
  || die "/boot/efi/EFI/ubuntu/grub.cfg is missing; the UEFI loader does not chain to /boot/grub/grub.cfg on this host."
if { dpkg-query -W -f='${db:Status-Status}\n' grub-pc 2>/dev/null || true; } | grep -qx installed; then
  say "WARNING: grub-pc is installed on a UEFI host; never run grub-install from it (it replaces the EFI loader)."
fi
{ dpkg-query -W -f='${db:Status-Status}\n' grub-efi-amd64-signed grub-efi-amd64 grub-efi-amd64-bin 2>/dev/null || true; } \
  | grep -qx installed || die "no grub-efi-amd64 package is installed; the UEFI boot stack cannot be regenerated."
[[ -x /usr/sbin/update-grub ]] || die "update-grub is missing."
[[ ! -f /run/reboot-required ]] \
  || die "a reboot is already required on this host (new kernel or libc); reboot first, then arm."
RUNNING_KVER="$(uname -r)"
NEWEST_KVER="$(linux-version list 2>/dev/null | linux-version sort 2>/dev/null | tail -1 || true)"
[[ -z "${NEWEST_KVER}" || "${NEWEST_KVER}" == "${RUNNING_KVER}" ]] \
  || die "running kernel ${RUNNING_KVER} is not the newest installed kernel (${NEWEST_KVER}); GRUB would boot the newest one without the conversion initramfs. Reboot first."
[[ -s "/boot/vmlinuz-${RUNNING_KVER}" && -s "/boot/initrd.img-${RUNNING_KVER}" ]] \
  || die "running kernel ${RUNNING_KVER} has no vmlinuz/initrd pair in /boot."

ROOT_DEV="$(findmnt -no SOURCE /)"
[[ -n "${ROOT_DEV}" ]] || die "cannot resolve root device"
say "root device: ${ROOT_DEV}"
if [[ "$(lsblk -no TYPE "${ROOT_DEV}" 2>/dev/null | head -1)" == "crypt" ]]; then
  if [[ -s /var/lib/winn-fde-done ]]; then
    say "root is already LUKS-backed and the custody completion marker exists; nothing to convert."
    exit 0
  fi
  die "root is already on a crypt mapper without a completion marker; do not re-arm blind. Recover it from the console or the rescue system (mythos_t2.md item 2, recovery)."
fi
if [[ "${ROOT_DEV}" =~ ^/dev/(vd|sd)[a-z]+[0-9]+$ || "${ROOT_DEV}" =~ ^/dev/nvme[0-9]+n[0-9]+p[0-9]+$ ]]; then
  :
else
  die "root device ${ROOT_DEV} is not a plain /dev/vdaN, /dev/sdaN or /dev/nvme0n1pN partition (LVM, RAID, dm or an already encrypted root are not supported)."
fi
[[ "$(findmnt -no FSTYPE /)" == "ext4" ]] || die "root filesystem is not ext4."
[[ "$(lsblk -no TYPE "${ROOT_DEV}" 2>/dev/null)" == "part" ]] || die "${ROOT_DEV} is not a partition."
ROOT_DISK="$(lsblk -no PKNAME "${ROOT_DEV}" 2>/dev/null | head -1)"
[[ -n "${ROOT_DISK}" && -b "/dev/${ROOT_DISK}" ]] || die "cannot resolve the parent disk of ${ROOT_DEV}."
[[ "$(lsblk -dnro TYPE "/dev/${ROOT_DISK}" 2>/dev/null)" == "disk" && "$(lsblk -dnro PTTYPE "/dev/${ROOT_DISK}" 2>/dev/null)" == "gpt" ]] \
  || die "/dev/${ROOT_DISK} is not a GPT disk; the PARTUUID-pinned conversion boot needs GPT."
BOOT_PART="$(findmnt -no SOURCE /boot 2>/dev/null || true)"
ESP_PART="$(findmnt -no SOURCE /boot/efi 2>/dev/null || true)"
[[ -n "${BOOT_PART}" && "${BOOT_PART}" != "${ROOT_DEV}" ]] || die "/boot is not a separately mounted partition."
[[ "$(findmnt -no FSTYPE /boot)" == "ext4" ]] || die "/boot is not ext4."
[[ -n "${ESP_PART}" && "${ESP_PART}" != "${ROOT_DEV}" && "${ESP_PART}" != "${BOOT_PART}" ]] \
  || die "/boot/efi is not a separately mounted ESP."
[[ "$(findmnt -no FSTYPE /boot/efi)" == "vfat" ]] || die "/boot/efi is not vfat."
[[ "$(lsblk -dnro PARTTYPE "${ESP_PART}" 2>/dev/null)" == "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" ]] \
  || die "${ESP_PART} does not carry the EFI System Partition type GUID."
[[ "$(lsblk -no PKNAME "${BOOT_PART}" 2>/dev/null | head -1)" == "${ROOT_DISK}" \
   && "$(lsblk -no PKNAME "${ESP_PART}" 2>/dev/null | head -1)" == "${ROOT_DISK}" ]] \
  || die "/boot (${BOOT_PART}) and the ESP (${ESP_PART}) must be partitions of the root disk /dev/${ROOT_DISK}."
if command -v cryptsetup >/dev/null 2>&1 && cryptsetup isLuks "${ROOT_DEV}" >/dev/null 2>&1; then
  die "${ROOT_DEV} already carries a LUKS header; nothing to convert."
fi
for mountpoint in / /boot /boot/efi; do
  FSTAB_ROWS="$(awk -v target="${mountpoint}" '$0 !~ /^[[:space:]]*#/ && $2 == target { n++ } END { print n+0 }' /etc/fstab)"
  [[ "${FSTAB_ROWS}" == "1" ]] || die "fstab must contain exactly one active ${mountpoint} entry (found ${FSTAB_ROWS})."
  FSTAB_SPEC="$(findmnt --fstab -nro SOURCE --evaluate --target "${mountpoint}" 2>/dev/null || true)"
  MOUNTED_SPEC="$(findmnt -nro SOURCE --mountpoint "${mountpoint}" 2>/dev/null || true)"
  [[ -n "${FSTAB_SPEC}" && -n "${MOUNTED_SPEC}" && "$(readlink -f "${FSTAB_SPEC}")" == "$(readlink -f "${MOUNTED_SPEC}")" ]] \
    || die "fstab and the mounted device disagree for ${mountpoint} (fstab ${FSTAB_SPEC:-none}, mounted ${MOUNTED_SPEC:-none})."
done
OTHER_MOUNTS="$(findmnt -rn -o SOURCE,TARGET 2>/dev/null \
  | awk -v d="/dev/${ROOT_DISK}" 'index($1, d) == 1 { print $2 }' | grep -vxE '/|/boot|/boot/efi' || true)"
[[ -z "${OTHER_MOUNTS}" ]] || die "unexpected mounts from /dev/${ROOT_DISK}: $(printf '%s' "${OTHER_MOUNTS}" | tr '\n' ' ')"
DISK_SWAP="$(swapon --noheadings --show=NAME 2>/dev/null | grep -vE '^/dev/(zram|ram)' || true)"
[[ -z "${DISK_SWAP}" ]] || die "disk-backed swap is active (${DISK_SWAP//$'\n'/ }); the passphrase must never reach a plaintext swap device. swapoff it first."
[[ ! -e /root/.winn-fde-conversion-key && ! -e /etc/initramfs-tools/scripts/local-premount/zz-winn-fde-v4 ]] \
  || die "a conversion is already armed or incomplete (conversion key or hook present); recover it instead of arming again."
for vendor_copy in /usr/share/initramfs-tools/scripts/*/*winn*fde* /usr/share/initramfs-tools/hooks/*winn*fde* \
                   /usr/share/initramfs-tools/conf.d/*winn*fde*; do
  [[ ! -e "${vendor_copy}" ]] || die "unexpected vendor-directory FDE copy: ${vendor_copy}; remove it before arming."
done
say "layout: root ${ROOT_DEV} ext4, /boot ${BOOT_PART} ext4, ESP ${ESP_PART} vfat, GPT disk /dev/${ROOT_DISK}"
lsblk -o NAME,TYPE,SIZE,FSTYPE,PARTTYPE,MOUNTPOINT "/dev/${ROOT_DISK}" >>/var/log/fde-chain.log 2>&1 || true

# The passphrase prompt (cryptsetup askpass) reads /dev/console, which the
# kernel binds to the LAST console= token. With "console=tty1 console=ttyS0"
# (the Ubuntu cloud image default) the prompt and its input live on the
# serial port, which the provider VNC console does not show. The owner's
# console is the VNC one (D1 (b)), so a VGA console must be last.
WINN_FDE_UNLOCK_CONSOLE="${WINN_FDE_UNLOCK_CONSOLE:-vga}"
case "${WINN_FDE_UNLOCK_CONSOLE}" in
  vga|serial) ;;
  *) die "WINN_FDE_UNLOCK_CONSOLE must be vga (provider VNC console) or serial." ;;
esac
LAST_CONSOLE="$(tr ' ' '\n' < /proc/cmdline | sed -n 's/^console=//p' | tail -1 | cut -d, -f1)"
GRUB_CMDLINE_OVERRIDE=""
if [[ "${WINN_FDE_UNLOCK_CONSOLE}" == "vga" ]]; then
  if [[ -n "${LAST_CONSOLE}" && ! "${LAST_CONSOLE}" =~ ^tty[0-9]*$ ]]; then
    EFFECTIVE_CMDLINE_DEFAULT="$(
      set +u
      for f in /etc/default/grub /etc/default/grub.d/*.cfg; do
        [[ -e "${f}" && "${f}" != /etc/default/grub.d/99-winn-fde-menu.cfg ]] || continue
        # shellcheck disable=SC1090
        . "${f}"
      done
      printf '%s' "${GRUB_CMDLINE_LINUX_DEFAULT:-}"
    )"
    EFFECTIVE_CMDLINE_DEFAULT="$(printf '%s' "${EFFECTIVE_CMDLINE_DEFAULT}" | sed -E 's/(^|[[:space:]])ip=[^[:space:]]+//g; s/^[[:space:]]+//; s/[[:space:]]+$//')"
    GRUB_CMDLINE_OVERRIDE="${EFFECTIVE_CMDLINE_DEFAULT:+${EFFECTIVE_CMDLINE_DEFAULT} }console=tty1"
    say "kernel console order ends with ${LAST_CONSOLE}: the passphrase prompt would read the serial port, not the VNC console; GRUB_CMDLINE_LINUX_DEFAULT becomes \"${GRUB_CMDLINE_OVERRIDE}\" via /etc/default/grub.d/99-winn-fde-menu.cfg"
  fi
else
  [[ "${LAST_CONSOLE}" =~ ^(ttyS|ttyAMA|hvc)[0-9]+$ ]] \
    || die "WINN_FDE_UNLOCK_CONSOLE=serial but the last console= token is '${LAST_CONSOLE:-none}'; the prompt would not appear on the serial console."
fi

# Network facts. Only IPv4 DHCP on exactly one physical NIC is qualified:
# dropbear's packaged init-premount script then owns early boot alone with an
# EMPTY device. Static, VLAN, bond and bridge networking refuse to arm; they
# need their own boot-tested design.
# Without a default route "ip route get" exits 2 and, under pipefail, v4 died
# silently (measured in the QEMU rehearsal of this round): name the condition.
ROUTE4="$(ip -4 route get 1.1.1.1 2>/dev/null | head -1 || true)"
[[ -n "${ROUTE4}" ]] || die "no IPv4 route towards the internet; the early-boot network cannot be derived from this host."
NET_IFACE="$(awk '{ for (i=1; i<=NF; i++) if ($i == "dev") { print $(i+1); exit } }' <<<"${ROUTE4}")"
NET_ADDR="$(awk '{ for (i=1; i<=NF; i++) if ($i == "src") { print $(i+1); exit } }' <<<"${ROUTE4}")"
NET_GATEWAY="$(awk '{ for (i=1; i<=NF; i++) if ($i == "via") { print $(i+1); exit } }' <<<"${ROUTE4}")"
[[ "${NET_IFACE}" =~ ^[[:alnum:]_.:-]+$ ]] || die "unsupported boot interface name: ${NET_IFACE:-missing}."
NET_CIDR="$(ip -o -4 addr show dev "${NET_IFACE}" scope global 2>/dev/null | awk -v addr="${NET_ADDR}" '$4 ~ ("^" addr "/") { print $4; exit }')"
NET_PREFIX="${NET_CIDR#*/}"
NET_MTU="$(cat "/sys/class/net/${NET_IFACE}/mtu" 2>/dev/null || true)"
[[ "${NET_ADDR}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "no usable source IPv4 address for initramfs."
[[ "${NET_GATEWAY}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "no via-gateway on the primary IPv4 route."
[[ "${NET_PREFIX}" =~ ^[0-9]+$ && "${NET_PREFIX}" -ge 0 && "${NET_PREFIX}" -le 32 ]] \
  || die "no usable IPv4 prefix for ${NET_ADDR}."
[[ "${NET_MTU}" =~ ^[0-9]+$ && "${NET_MTU}" -ge 576 && "${NET_MTU}" -le 65535 ]] \
  || die "no usable MTU for ${NET_IFACE}."
[[ -e "/sys/class/net/${NET_IFACE}/device" ]] || die "${NET_IFACE} is not a physical (provider) interface."
PHYSICAL_NICS=""
for sysif in /sys/class/net/*; do
  ifname="${sysif##*/}"
  [[ -e "${sysif}/device" ]] || continue
  PHYSICAL_NICS="${PHYSICAL_NICS}${PHYSICAL_NICS:+ }${ifname}"
done
if [[ "${PHYSICAL_NICS}" != "${NET_IFACE}" ]]; then
  die "more than one physical interface is present (${PHYSICAL_NICS:-none}); with an empty early-boot DEVICE ipconfig would race them: early DHCP needs exactly one physical NIC carrying the default route."
fi
NET_DRIVER="$(basename "$(readlink -f "/sys/class/net/${NET_IFACE}/device/driver" 2>/dev/null || true)")"
[[ "${NET_DRIVER}" =~ ^[[:alnum:]_-]+$ ]] || die "cannot resolve the driver of ${NET_IFACE}."
NET_DRIVER_BUILTIN=0
grep -q "/${NET_DRIVER//-/_}\.ko$" "/lib/modules/${RUNNING_KVER}/modules.builtin" 2>/dev/null && NET_DRIVER_BUILTIN=1
grep -q "/${NET_DRIVER}\.ko$" "/lib/modules/${RUNNING_KVER}/modules.builtin" 2>/dev/null && NET_DRIVER_BUILTIN=1
[[ "${NET_DRIVER_BUILTIN}" -eq 1 ]] || modinfo "${NET_DRIVER}" >/dev/null 2>&1 \
  || die "NIC driver ${NET_DRIVER} is not available as a module for kernel ${RUNNING_KVER}."
NET_IFINDEX="$(cat "/sys/class/net/${NET_IFACE}/ifindex" 2>/dev/null || true)"
if ip -4 route show default dev "${NET_IFACE}" 2>/dev/null | grep -Eq '(^|[[:space:]])proto[[:space:]]+dhcp([[:space:]]|$)' \
    || [[ "${NET_IFINDEX}" =~ ^[0-9]+$ && -s "/run/systemd/netif/leases/${NET_IFINDEX}" ]] \
    || { command -v netplan >/dev/null 2>&1 \
         && [[ "$(netplan get "network.ethernets.${NET_IFACE}.dhcp4" 2>/dev/null | tr -d '[:space:]')" == true ]]; }; then
  EARLY_NET_MODE=dhcp
else
  die "no IPv4 DHCP evidence on ${NET_IFACE} (no dhcp default route, no networkd lease, netplan dhcp4 not true); static, VLAN, bond and bridge networking is not qualified for this chain."
fi
say "initramfs network mode ${EARLY_NET_MODE}: ${NET_ADDR}/${NET_PREFIX} via ${NET_GATEWAY} on ${NET_IFACE} (driver ${NET_DRIVER}), MTU ${NET_MTU}, early-boot DEVICE=''"

# Foreign early-boot network definitions make a second DHCP owner. Refuse
# before writing anything; the stale-file sweep below removes only our own
# names and the legacy installer file.
INITRAMFS_ETC=/etc/initramfs-tools
if grep -Eq '^[[:space:]]*(IP|IP6|DEVICE|DEVICE6|BOOTIF|VLAN)=.+' "${INITRAMFS_ETC}/initramfs.conf" 2>/dev/null; then
  die "${INITRAMFS_ETC}/initramfs.conf defines a non-empty IP, IP6, DEVICE, DEVICE6, BOOTIF or VLAN value; early-boot networking must live only in conf.d/winn-fde-network."
fi
FOREIGN_CONF="$(grep -lsE '^[[:space:]]*(IP|IP6|DEVICE|DEVICE6|BOOTIF|VLAN)=' "${INITRAMFS_ETC}"/conf.d/* 2>/dev/null \
  | grep -vxE "${INITRAMFS_ETC}/conf.d/(winn-fde-network|wins-remote-unlock)" || true)"
[[ -z "${FOREIGN_CONF}" ]] || die "early-boot network defined outside conf.d/winn-fde-network: $(printf '%s' "${FOREIGN_CONF}" | tr '\n' ' ')"
FOREIGN_NET="$(grep -ls 'configure_networking' "${INITRAMFS_ETC}"/scripts/init-premount/* 2>/dev/null \
  | grep -vx "${INITRAMFS_ETC}/scripts/init-premount/00-winn-fde-network" || true)"
[[ -z "${FOREIGN_NET}" ]] || die "a local init-premount script calls configure_networking (second early-boot DHCP owner): $(printf '%s' "${FOREIGN_NET}" | tr '\n' ' ')"
ROOT_PARTUUID="$(lsblk -dnro PARTUUID "${ROOT_DEV}" 2>/dev/null || true)"
[[ "${ROOT_PARTUUID}" =~ ^[0-9a-fA-F-]{36}$ ]] || die "root PARTUUID unavailable for ${ROOT_DEV}."
say "pre-flight passed (root PARTUUID ${ROOT_PARTUUID})"
if [[ "${PREFLIGHT_ONLY}" == "1" ]]; then
  say "PREFLIGHT PASS: nothing was written. Deliver /root/.winn-fde-pass and run without WINN_FDE_PREFLIGHT_ONLY to arm."
  exit 0
fi

PASS_FILE_ON_ROOT=/root/.winn-fde-pass
validate_passphrase_file "${PASS_FILE_ON_ROOT}"
if ! FDE_SOURCE_SHA256="$(sha256sum -- "$0" | awk '{print $1}')"; then
  die "cannot hash the running FDE source"
fi
[[ "${FDE_SOURCE_SHA256}" =~ ^[0-9a-f]{64}$ ]] || die "cannot hash the running FDE source"
[[ -d /var/lib ]] || install -d -m 755 /var/lib
printf '%s\n' "${FDE_SOURCE_SHA256}" > /var/lib/winn-fde-source.sha256
chmod 600 /var/lib/winn-fde-source.sha256

# ---- arm: packages (network available) -------------------------------------
# Packages needed later inside the chroot are installed NOW (the initramfs
# has no usable apt); they change nothing about the boot until the crypttab
# is written by the hook after encryption. The image's GRUB package family is
# never changed and grub-install is never run.
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >>/var/log/fde-chain.log 2>&1 \
  || die "package index refresh failed; see /var/log/fde-chain.log."
apt-get install -y -qq cryptsetup cryptsetup-initramfs dropbear-initramfs busybox e2fsprogs >>/var/log/fde-chain.log 2>&1 \
  || die "package pre-install failed; see /var/log/fde-chain.log."
say "conversion packages present"

# Dropbear's initramfs key is sourced from root. Cloud images commonly put
# the injected key only in the sudo user's account, so bootstrap root's copy
# before building any initramfs. Never continue without a usable unlock key.
if [[ ! -s /root/.ssh/authorized_keys ]]; then
  SUDO_HOME=""
  if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    SUDO_HOME="$(getent passwd "${SUDO_USER}" | awk -F: '{print $6}')"
  fi
  [[ -n "${SUDO_HOME}" && -s "${SUDO_HOME}/.ssh/authorized_keys" ]] \
    || die "root has no authorized_keys and the sudo user's key could not be found."
  install -d -m 700 /root/.ssh
  install -m 600 "${SUDO_HOME}/.ssh/authorized_keys" /root/.ssh/authorized_keys
  say "root authorized_keys bootstrapped from the sudo user"
fi
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys
grep -qE '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521))[[:space:]]' /root/.ssh/authorized_keys \
  || die "authorized_keys has no plain dropbear-compatible ed25519, RSA, or ECDSA key."

# Make the conversion initramfs itself remotely recoverable. If any
# post-encryption setup step fails, the hook still exits without panic and
# dropbear remains reachable with the owner key on the documented port, WITH a
# shell during the conversion boot; the final initramfs (built in the chroot)
# carries the installer-identical forced cryptroot-unlock configuration.
# IFDOWN=none: our init-bottom handoff script owns the interface teardown.
install -d -m 700 /etc/dropbear/initramfs /etc/dropbear-initramfs
install -m 600 /root/.ssh/authorized_keys /etc/dropbear/initramfs/authorized_keys
printf 'DROPBEAR_OPTIONS="-I 180 -j -k -p 2222 -s"\nIFDOWN=none\n' > /etc/dropbear/initramfs/dropbear.conf
cp /etc/dropbear/initramfs/dropbear.conf /etc/dropbear-initramfs/config
for hostkey in /etc/dropbear/initramfs/dropbear_ed25519_host_key /etc/dropbear/initramfs/dropbear_ecdsa_host_key /etc/dropbear/initramfs/dropbear_rsa_host_key; do
  [[ -s "${hostkey}" ]] || continue
  FP="$(dropbearkey -y -f "${hostkey}" 2>/dev/null | sed -n 's/^Fingerprint: //p' | head -1)"
  [[ -n "${FP}" ]] && say "dropbear :2222 host key ${hostkey##*/dropbear_} ${FP}"
done
say "conversion initramfs dropbear recovery configured on port 2222 (shell during conversion, cryptroot-unlock after)"
mkdir -p /etc/cryptsetup-initramfs
printf 'UMASK=0077\n' > /etc/cryptsetup-initramfs/conf-hook

# The NIC driver rides in every initramfs explicitly (MODULES=dep images
# would otherwise leave early boot without a network device).
if [[ "${NET_DRIVER_BUILTIN}" -eq 0 ]]; then
  touch "${INITRAMFS_ETC}/modules"
  grep -Fxq "${NET_DRIVER}" "${INITRAMFS_ETC}/modules" || printf '%s\n' "${NET_DRIVER}" >> "${INITRAMFS_ETC}/modules"
fi

# Stale copies of our own early-boot files and the legacy installer file are
# removed BEFORE the canonical set is written (section 42: duplicate hook
# copies raced dropbear). Foreign files were refused above. The legacy file
# is copied away first, OUTSIDE conf.d: mkinitramfs sources every well-formed
# file there, so a backup left in conf.d would be a second network owner.
LEGACY_UNLOCK_CONF="${INITRAMFS_ETC}/conf.d/wins-remote-unlock"
if [[ -e "${LEGACY_UNLOCK_CONF}" || -L "${LEGACY_UNLOCK_CONF}" ]]; then
  install -d -m 700 /var/backups/winn-fde
  cp -a -- "${LEGACY_UNLOCK_CONF}" "/var/backups/winn-fde/wins-remote-unlock.$(date -u +%Y%m%dT%H%M%SZ)"
  say "legacy installer file ${LEGACY_UNLOCK_CONF} backed up under /var/backups/winn-fde"
fi
for stale in "${INITRAMFS_ETC}"/scripts/init-premount/*winn-fde* \
             "${INITRAMFS_ETC}"/scripts/init-premount/*wins-remote-unlock* \
             "${INITRAMFS_ETC}"/scripts/init-bottom/*winn-fde* \
             "${INITRAMFS_ETC}"/scripts/local-premount/*winn-fde* \
             "${INITRAMFS_ETC}"/scripts/local-top/*winn-fde* \
             "${INITRAMFS_ETC}"/hooks/*winn-fde* \
             "${INITRAMFS_ETC}"/conf.d/*winn-fde* \
             "${INITRAMFS_ETC}"/conf.d/wins-remote-unlock; do
  [[ -e "${stale}" || -L "${stale}" ]] || continue
  rm -f -- "${stale}"
  say "removed stale early-boot file ${stale}"
done

# Keep the early-boot address inside the initramfs rather than on the kernel
# command line. This avoids systemd-network-generator consuming ip= again in
# the real root and competing with the provider's netplan configuration.
install -d -m 755 "${INITRAMFS_ETC}/conf.d"
write_early_boot_network_conf dhcp "" > "${INITRAMFS_ETC}/conf.d/winn-fde-network"

# The arm-time layout travels in the conversion initramfs: the hook pins the
# raw root partition by GPT PARTUUID (stable across the LUKS header creation)
# and refuses a firmware mode change. Removed again at finalization.
printf "ROOT_PARTUUID='%s'\nBOOT_MODE='uefi'\n" "${ROOT_PARTUUID}" > "${INITRAMFS_ETC}/conf.d/winn-fde-layout"

# The init-premount hook: an inert kmsg marker. It NEVER calls
# configure_networking or ipconfig: dropbear's packaged init-premount script is
# the only early-boot DHCP owner (section 42). Its presence in the listing
# proves the converter's initramfs inputs were the ones built.
install -d -m 755 "${INITRAMFS_ETC}/scripts/init-premount"
cat > "${INITRAMFS_ETC}/scripts/init-premount/00-winn-fde-network" <<EOS
#!/bin/sh
PREREQ=""
prereqs() { echo "\$PREREQ"; }
case "\$1" in prereqs) prereqs; exit 0;; esac
# Deliberately no network setup here: dropbear's packaged init-premount script
# owns IPv4 DHCP alone with an empty DEVICE (handoff section 42).
echo "winn-fde-network: early-boot DHCP is owned by the dropbear init-premount script alone (DEVICE empty, armed on ${NET_IFACE}); this hook configures nothing" > /dev/kmsg 2>/dev/null || true
exit 0
EOS
chmod 755 "${INITRAMFS_ETC}/scripts/init-premount/00-winn-fde-network"

# Dropbear's packaged init-bottom script runs before local scripts; with
# IFDOWN=none it leaves the links alone. Report what early boot configured,
# then hand clean, UP physical links to netplan (names may differ between the
# initramfs and the running system, so every physical NIC is handled).
install -d -m 755 "${INITRAMFS_ETC}/scripts/init-bottom"
cat > "${INITRAMFS_ETC}/scripts/init-bottom/zz-winn-fde-network-handoff" <<'EOS'
#!/bin/sh
PREREQ=""
prereqs() { echo "$PREREQ"; }
case "$1" in prereqs) prereqs; exit 0;; esac
for netconf in /run/net-*.conf; do
    [ -e "${netconf}" ] || continue
    echo "winn-fde-network: early boot configured ${netconf##*/net-}" > /dev/kmsg 2>/dev/null || true
done
# This directory is volatile initramfs output. Remove every generated YAML so
# none can outrank the provider's durable /etc/netplan configuration.
rm -f /run/netplan/*.yaml
for nic in /sys/class/net/*; do
    [ -e "${nic}/device" ] || continue
    IFACE="${nic##*/}"
    ip addr flush dev "${IFACE}" scope global 2>/dev/null || true
    ip route flush dev "${IFACE}" 2>/dev/null || true
    ip link set dev "${IFACE}" up 2>/dev/null || true
done
echo "winn-fde-network: clean handoff to userspace" > /dev/kmsg 2>/dev/null || true
EOS
chmod 755 "${INITRAMFS_ETC}/scripts/init-bottom/zz-winn-fde-network-handoff"

install -d -m 755 "${INITRAMFS_ETC}/hooks"
cat > "${INITRAMFS_ETC}/hooks/winn-fde-network-tools" <<'EOS'
#!/bin/sh
PREREQ=""
prereqs() { echo "$PREREQ"; }
case "$1" in prereqs) prereqs; exit 0;; esac
. /usr/share/initramfs-tools/hook-functions
for bin in /usr/sbin/ip /sbin/ip /usr/bin/ip /bin/ip; do
    [ -x "$bin" ] || continue
    copy_exec "$bin" /sbin
    exit 0
done
exit 1
EOS
chmod 755 "${INITRAMFS_ETC}/hooks/winn-fde-network-tools"

# A visible 5 second GRUB menu on every boot, also after recordfail, in a
# grub.d file that sorts after the cloud image's 50-cloudimg-settings.cfg.
# The temporary 98- file pins the kernel root argument to the GPT PARTUUID
# while the conversion initramfs is armed (see the header); the chroot
# removes it before the encrypted-root GRUB entries are generated.
install -d -m 755 /etc/default/grub.d
write_grub_menu_cfg "${GRUB_CMDLINE_OVERRIDE}" > /etc/default/grub.d/99-winn-fde-menu.cfg
chmod 644 /etc/default/grub.d/99-winn-fde-menu.cfg
printf '%s\n' \
  '# Temporary, written by deploy/fde_boot_chain.sh for the conversion boots only:' \
  '# the raw root partition keeps its GPT PARTUUID once a LUKS header hides the' \
  '# ext4 UUID, so an interrupted encryption can resume. Removed at finalization.' \
  'GRUB_DISABLE_LINUX_UUID=true' \
  'GRUB_DISABLE_LINUX_PARTUUID=false' > /etc/default/grub.d/98-winn-fde-root.cfg
chmod 644 /etc/default/grub.d/98-winn-fde-root.cfg
[[ -e /etc/default/grub.pre-winn-fde ]] || cp -a /etc/default/grub /etc/default/grub.pre-winn-fde
ensure_main_grub_menu /etc/default/grub
say "GRUB files written: 99-winn-fde-menu.cfg (5 second menu), 98-winn-fde-root.cfg (conversion root=PARTUUID) and /etc/default/grub kept consistent"

# GCP's Ubuntu image enables an initrdless fast path here. The conversion
# hook cannot run unless GRUB loads the initramfs, so disable every active
# assignment while preserving the vendor file for review. Other providers
# do not ship this file.
FORCE_PARTUUID_CFG=/etc/default/grub.d/40-force-partuuid.cfg
if [[ -f "${FORCE_PARTUUID_CFG}" ]]; then
  cp -a "${FORCE_PARTUUID_CFG}" "${FORCE_PARTUUID_CFG}.pre-winn-fde"
  sed -i -E '/^[[:space:]]*(export[[:space:]]+)?GRUB_FORCE_PARTUUID[[:space:]]*=/s/^/# disabled by winn-fde: /' "${FORCE_PARTUUID_CFG}"
  if grep -qE '^[[:space:]]*(export[[:space:]]+)?GRUB_FORCE_PARTUUID[[:space:]]*=' "${FORCE_PARTUUID_CFG}"; then
    die "could not disable GRUB_FORCE_PARTUUID in ${FORCE_PARTUUID_CFG}."
  fi
  say "GRUB_FORCE_PARTUUID initrdless boot disabled"
fi

# The separately delivered passphrase remains a root-only file on the
# soon-encrypted root. It is never copied into the conversion initramfs.
say "separately delivered passphrase validated (root-only, shredded after conversion)"

# Use a one-time random key for the destructive conversion and its resume path.
# The production passphrase is enrolled only after the encrypted root is open,
# then this keyslot is destroyed. Any conversion-initrd residue on unencrypted
# /boot therefore contains a credential that no longer unlocks the volume.
CONVERSION_KEY_ON_ROOT=/root/.winn-fde-conversion-key
( umask 077; head -c 48 /dev/urandom | base64 | tr -d '\n' > "${CONVERSION_KEY_ON_ROOT}" )
chmod 600 "${CONVERSION_KEY_ON_ROOT}"
[[ "$(wc -c < "${CONVERSION_KEY_ON_ROOT}")" -ge 64 ]] || die "could not generate conversion key."

# ---- initramfs hook: copy the conversion tools into the initrd -------------
HOOKS_DIR="${INITRAMFS_ETC}/hooks"
mkdir -p "${HOOKS_DIR}"
cat > "${HOOKS_DIR}/winn-fde-tools" <<'EOS'
#!/bin/sh
# initramfs hook: copy the offline-conversion toolset into the initrd:
# shrink tools + cryptsetup (+ its libs) + util-linux mount helpers + the
# dm-crypt and cipher modules the conversion needs before any crypttab exists.
PREREQ=""
prereqs() { echo "$PREREQ"; }
case "$1" in prereqs) prereqs; exit 0;; esac
. /usr/share/initramfs-tools/hook-functions
for bin in /sbin/e2fsck /sbin/resize2fs /sbin/tune2fs \
           /usr/sbin/e2fsck /usr/sbin/resize2fs /usr/sbin/tune2fs \
           /sbin/cryptsetup /usr/sbin/cryptsetup \
           /sbin/findmnt /usr/bin/findmnt \
           /usr/sbin/chroot /usr/bin/chroot; do
    [ -x "$bin" ] || continue
    copy_exec "$bin" /sbin
done
manual_add_modules dm_crypt xts aes aesni_intel crypto_simd cryptd sha256_ssse3 2>/dev/null || true
if [ -s /root/.winn-fde-conversion-key ]; then
    mkdir -p "${DESTDIR}/conf"
    cp /root/.winn-fde-conversion-key "${DESTDIR}/conf/winn-fde-conversion-key"
    chmod 600 "${DESTDIR}/conf/winn-fde-conversion-key"
else
    exit 1
fi
EOS
chmod 755 "${HOOKS_DIR}/winn-fde-tools"
say "initramfs tools hook installed (shrink + cryptsetup + dm-crypt modules)"

# ---- the pre-mount conversion hook -----------------------------------------
PREMOUNT_DIR="${INITRAMFS_ETC}/scripts/local-premount"
mkdir -p "${PREMOUNT_DIR}"
cat > "${PREMOUNT_DIR}/zz-winn-fde-v4" <<'EOS'
#!/bin/sh
# Pre-mount OFFLINE LUKS conversion of the root filesystem.
# State machine + failure policy: see fde_boot_chain.sh header. Every
# failure logs and CONTINUES (exit 0). Before encryption the host stays
# bootable on the plain partition. After encryption, the arm-time dropbear
# recovery shell remains key-accessible on port 2222. Nothing destructive
# runs unless every precondition held.
PREREQ=""
prereqs() { echo "$PREREQ"; }
case "$1" in prereqs) prereqs; exit 0;; esac

# Boot-environment guard (mkinitramfs also runs this file at build time).
[ -d /scripts ] || exit 0

log() { echo "winn-fde-v4: $*" > /dev/kmsg 2>/dev/null || echo "winn-fde-v4: $*"; }
skip() { log "SKIP: $*"; exit 0; }

# The raw root partition is pinned by its GPT PARTUUID (arm-time layout). The
# ext4 UUID stops identifying it once a LUKS header exists, so neither the
# kernel root= argument nor this hook may rely on it during the conversion.
ROOT_PARTUUID=""
BOOT_MODE=""
[ -r /conf/conf.d/winn-fde-layout ] || skip "arm-time layout file missing from the initramfs"
. /conf/conf.d/winn-fde-layout
[ -n "${ROOT_PARTUUID}" ] || skip "arm-time root PARTUUID missing"
case "${BOOT_MODE}" in
    uefi) [ -d /sys/firmware/efi ] || skip "firmware changed from UEFI since arming";;
    *) skip "unqualified boot mode '${BOOT_MODE}'";;
esac
ROOTDEV="/dev/disk/by-partuuid/${ROOT_PARTUUID}"
i=0
while [ "$i" -lt 30 ]; do
    RESOLVED="$(readlink -f "${ROOTDEV}" 2>/dev/null || echo "${ROOTDEV}")"
    [ -b "${RESOLVED}" ] && break
    sleep 1
    i=$((i + 1))
done
[ -b "${RESOLVED}" ] || skip "device ${ROOTDEV} never appeared"
ROOTDEV="${RESOLVED}"
case "${ROOTDEV}" in
    /dev/vd*[0-9]|/dev/sd*[0-9]|/dev/nvme*n*p[0-9]) ;;
    *) skip "unexpected root device ${ROOTDEV} at the conversion boot";;
esac
log "target: ${ROOTDEV}"

command -v tune2fs >/dev/null 2>&1 || skip "tune2fs not in initramfs"

# Cleanup is idempotent and always unwinds in reverse mount order.
MAPPER=root_crypt
PASS_TMP=/tmp/winn-fde-pass
ROOT_MOUNTED=0
BOOT_MOUNTED=0
ESP_MOUNTED=0
DEV_MOUNTED=0
PROC_MOUNTED=0
SYS_MOUNTED=0
MAPPER_OPEN=0
cleanup() {
    [ "${SYS_MOUNTED}" -eq 0 ] || { umount /winnmnt/sys 2>/dev/null; SYS_MOUNTED=0; }
    [ "${PROC_MOUNTED}" -eq 0 ] || { umount /winnmnt/proc 2>/dev/null; PROC_MOUNTED=0; }
    [ "${DEV_MOUNTED}" -eq 0 ] || { umount /winnmnt/dev 2>/dev/null; DEV_MOUNTED=0; }
    [ "${ESP_MOUNTED}" -eq 0 ] || { umount /winnmnt/boot/efi 2>/dev/null; ESP_MOUNTED=0; }
    [ "${BOOT_MOUNTED}" -eq 0 ] || { umount /winnmnt/boot 2>/dev/null; BOOT_MOUNTED=0; }
    [ "${ROOT_MOUNTED}" -eq 0 ] || { umount /winnmnt 2>/dev/null; ROOT_MOUNTED=0; }
    [ "${MAPPER_OPEN}" -eq 0 ] || { cryptsetup luksClose "${MAPPER}" 2>/dev/null; MAPPER_OPEN=0; }
    rm -f "${PASS_TMP}"
}
skip() { log "SKIP: $*"; cleanup; exit 0; }
emit_log() {
    [ -f "$1" ] || return 0
    while IFS= read -r line; do log "$2: ${line}"; done < "$1"
}
resolve_spec() {
    case "$1" in
        UUID=*)     readlink -f "/dev/disk/by-uuid/${1#UUID=}" 2>/dev/null;;
        PARTUUID=*) readlink -f "/dev/disk/by-partuuid/${1#PARTUUID=}" 2>/dev/null;;
        LABEL=*)    readlink -f "/dev/disk/by-label/${1#LABEL=}" 2>/dev/null;;
        *)          readlink -f "$1" 2>/dev/null || echo "$1";;
    esac
}

# ---- state 3 / interrupted state 2 -----------------------------------------
# The conversion initrd carries only the random one-time conversion key so an
# abrupt reset can resume from LUKS2 metadata. It never carries the production
# passphrase. The final initrd is built after removing the conversion hook.
RESUMED=0
if cryptsetup isLuks "${ROOTDEV}" >/dev/null 2>&1; then
    [ -s /conf/winn-fde-conversion-key ] || skip "${ROOTDEV} already LUKS; no conversion credential present"
    cp /conf/winn-fde-conversion-key "${PASS_TMP}" 2>/dev/null || skip "cannot stage resume credential"
    chmod 600 "${PASS_TMP}"
    log "LUKS header found; checking for interrupted reencryption"
    if cryptsetup reencrypt --batch-mode --resume-only --progress-frequency 30 \
            --key-file "${PASS_TMP}" "${ROOTDEV}" >/tmp/winn-fde-resume.log 2>&1; then
        RESUMED=1
        log "interrupted encryption resumed and completed"
    else
        emit_log /tmp/winn-fde-resume.log "resume"
        cryptsetup luksDump "${ROOTDEV}" >/tmp/winn-fde-luks-dump.log 2>&1 \
            || skip "cannot inspect LUKS metadata after resume failure"
        if grep -qi 'reencrypt' /tmp/winn-fde-luks-dump.log; then
            skip "reencryption metadata remains after resume failure"
        fi
        cryptsetup open --test-passphrase --key-file "${PASS_TMP}" "${ROOTDEV}" >/dev/null 2>&1 \
            || skip "${ROOTDEV} is LUKS but the conversion key cannot open it"
        RESUMED=1
        log "encryption was already complete; continuing finalization"
    fi
fi

# Mount the plain root to read the staged passphrase and validate every
# post-encryption dependency before making the destructive transition.
command -v mount >/dev/null 2>&1 || skip "mount not available"
command -v chroot >/dev/null 2>&1 || skip "chroot not available"
mkdir -p /winnmnt
umount /winnmnt 2>/dev/null || true
if [ "${RESUMED}" -eq 0 ]; then
mount -t ext4 "${ROOTDEV}" /winnmnt 2>/dev/null || skip "cannot mount ${ROOTDEV}"
ROOT_MOUNTED=1
PASS_SRC=/conf/winn-fde-conversion-key
[ -s "${PASS_SRC}" ] || skip "no staged passphrase"
log "plain root mounted; conversion requested"

# ---- geometry + headroom ----------------------------------------------------
TUNE="$(tune2fs -l "${ROOTDEV}" 2>/dev/null)" || skip "tune2fs read failed"
FS_BLOCKS="$(echo "$TUNE" | sed -n 's/^Block count:[[:space:]]*//p')"
FS_BLOCK_SIZE="$(echo "$TUNE" | sed -n 's/^Block size:[[:space:]]*//p')"
BDEV="$(basename "${ROOTDEV}")"
DEV_BYTES=$(( $(cat "/sys/class/block/${BDEV}/size" 2>/dev/null || echo 0) * 512 ))
[ -n "${FS_BLOCKS}" ] && [ -n "${FS_BLOCK_SIZE}" ] && [ "${DEV_BYTES}" -gt 0 ] \
    || skip "no geometry"
HEADROOM=$(( DEV_BYTES - FS_BLOCKS * FS_BLOCK_SIZE ))
log "headroom: ${HEADROOM} bytes"

# ---- state 1: shrink first (offline fsck + resize2fs), then continue -------
if [ "${HEADROOM}" -lt 268435456 ]; then
    command -v e2fsck    >/dev/null 2>&1 || skip "e2fsck missing"
    command -v resize2fs >/dev/null 2>&1 || skip "resize2fs missing"
    SHRINK_BLOCKS=$(( (536870912 + FS_BLOCK_SIZE - 1) / FS_BLOCK_SIZE ))
    log "shrinking by ${SHRINK_BLOCKS} blocks"
    umount /winnmnt 2>/dev/null || skip "cannot unmount plain root for shrink"
    ROOT_MOUNTED=0
    e2fsck -fy "${ROOTDEV}" >/tmp/winn-fde-fsck.log 2>&1
    FSCK_RC=$?
    [ "${FSCK_RC}" -ge 4 ] && { emit_log /tmp/winn-fde-fsck.log "e2fsck"; skip "e2fsck rc=${FSCK_RC}"; }
    if [ "${FSCK_RC}" -eq 2 ]; then
        e2fsck -fy "${ROOTDEV}" >/tmp/winn-fde-fsck-rerun.log 2>&1 \
            || { emit_log /tmp/winn-fde-fsck-rerun.log "e2fsck"; skip "e2fsck re-run failed"; }
    fi
    resize2fs "${ROOTDEV}" $(( FS_BLOCKS - SHRINK_BLOCKS )) >/tmp/winn-fde-resize.log 2>&1 \
        || { emit_log /tmp/winn-fde-resize.log "resize2fs"; skip "resize2fs failed"; }
    FS_BLOCKS2="$(tune2fs -l "${ROOTDEV}" 2>/dev/null | sed -n 's/^Block count:[[:space:]]*//p')"
    HEADROOM2=$(( DEV_BYTES - FS_BLOCKS2 * FS_BLOCK_SIZE ))
    log "after shrink: headroom ${HEADROOM2} bytes"
    [ "${HEADROOM2}" -ge 268435456 ] || skip "shrink insufficient (${HEADROOM2})"
    log "shrink OK; continuing the offline conversion in this boot"
    mount -t ext4 "${ROOTDEV}" /winnmnt 2>/dev/null || skip "cannot remount the shrunken root"
    ROOT_MOUNTED=1
fi

# ---- state 2 preflight: prove the chroot can build a bootable stack --------
command -v cryptsetup >/dev/null 2>&1 || skip "cryptsetup not in initramfs"
BOOT_SPEC="$(awk '$2 == "/boot" && $1 !~ /^#/ { print $1; exit }' /winnmnt/etc/fstab)"
ESP_SPEC="$(awk '$2 == "/boot/efi" && $1 !~ /^#/ { print $1; exit }' /winnmnt/etc/fstab)"
ROOT_ROWS="$(awk '$0 !~ /^[[:space:]]*#/ && $2 == "/" { n++ } END { print n+0 }' /winnmnt/etc/fstab)"
[ "${ROOT_ROWS}" -eq 1 ] || skip "fstab must contain exactly one active root entry (found ${ROOT_ROWS})"
[ -n "${BOOT_SPEC}" ] || skip "separate /boot entry missing from fstab"
[ -n "${ESP_SPEC}" ] || skip "ESP entry missing from fstab"
BOOT_DEV="$(resolve_spec "${BOOT_SPEC}")"
ESP_DEV="$(resolve_spec "${ESP_SPEC}")"
[ -b "${BOOT_DEV}" ] && [ "${BOOT_DEV}" != "${ROOTDEV}" ] || skip "invalid /boot device ${BOOT_SPEC}"
[ -b "${ESP_DEV}" ] && [ "${ESP_DEV}" != "${ROOTDEV}" ] && [ "${ESP_DEV}" != "${BOOT_DEV}" ] || skip "invalid ESP device ${ESP_SPEC}"
[ -s /winnmnt/root/.ssh/authorized_keys ] || skip "root authorized_keys missing before encryption"
for needed in /winnmnt/bin/sh /winnmnt/usr/sbin/update-initramfs \
              /winnmnt/usr/sbin/mkinitramfs /winnmnt/usr/sbin/update-grub \
              /winnmnt/usr/bin/lsinitramfs; do
    [ -x "${needed}" ] || skip "required chroot command missing: ${needed#/winnmnt}"
done

# Prove both unencrypted boot filesystems can be mounted before encryption.
mkdir -p /winnmnt/boot /winnmnt/boot/efi
mount "${BOOT_DEV}" /winnmnt/boot 2>/dev/null || skip "cannot preflight-mount /boot (${BOOT_SPEC})"
BOOT_MOUNTED=1
mount "${ESP_DEV}" /winnmnt/boot/efi 2>/dev/null || skip "cannot preflight-mount ESP (${ESP_SPEC})"
ESP_MOUNTED=1
[ -d /winnmnt/boot/efi/EFI ] || skip "ESP has no EFI directory"
CURRENT_INITRD="/winnmnt/boot/initrd.img-$(uname -r)"
[ -s "${CURRENT_INITRD}" ] || skip "running kernel initrd missing from /boot"
INITRD_BYTES="$(wc -c < "${CURRENT_INITRD}")"
BOOT_FREE_BYTES=$(( $(df -Pk /winnmnt/boot | awk 'NR == 2 { print $4 }') * 1024 ))
BOOT_NEEDED_BYTES=$(( INITRD_BYTES * 2 + 134217728 ))
[ "${BOOT_FREE_BYTES}" -ge "${BOOT_NEEDED_BYTES}" ] \
    || skip "/boot free space ${BOOT_FREE_BYTES} below safe rebuild floor ${BOOT_NEEDED_BYTES}"
umount /winnmnt/boot/efi 2>/dev/null || skip "cannot unmount preflight ESP"
ESP_MOUNTED=0
umount /winnmnt/boot 2>/dev/null || skip "cannot unmount preflight /boot"
BOOT_MOUNTED=0

# Copy the passphrase into initramfs memory, then ALWAYS unmount the plain
# root before reencrypt. The old v4 kept PASS pointing inside /winnmnt after
# unmount and could also leave /winnmnt mounted when the first cp succeeded.
cp "${PASS_SRC}" "${PASS_TMP}" 2>/dev/null || skip "cannot stage passphrase in initramfs memory"
chmod 600 "${PASS_TMP}"
umount /winnmnt 2>/dev/null || skip "cannot unmount plain root before encryption"
ROOT_MOUNTED=0
log "pre-encryption gates passed; root unmounted"

# cryptsetup requires batch mode when the hook has no tty. Its output is
# retained in initramfs memory and copied to the serial log on any failure.
if cryptsetup reencrypt --batch-mode --encrypt --reduce-device-size 64M --type luks2 --progress-frequency 30 \
        --key-file "${PASS_TMP}" "${ROOTDEV}" >/tmp/winn-fde-reencrypt.log 2>&1; then
    log "encryption complete"
else
    emit_log /tmp/winn-fde-reencrypt.log "reencrypt"
    skip "reencrypt failed; manual recovery may be required if a LUKS header was created"
fi
fi

cryptsetup luksOpen "${ROOTDEV}" "${MAPPER}" --key-file "${PASS_TMP}" >/tmp/winn-fde-open.log 2>&1 \
    || { emit_log /tmp/winn-fde-open.log "luksOpen"; skip "luksOpen failed after encryption"; }
MAPPER_OPEN=1
mount -t ext4 "/dev/mapper/${MAPPER}" /winnmnt 2>/dev/null || skip "cannot mount encrypted root"
ROOT_MOUNTED=1
log "encrypted root mounted"

PRODUCTION_KEY=/winnmnt/root/.winn-fde-pass
[ -s "${PRODUCTION_KEY}" ] || skip "production passphrase missing after encryption"
TEMP_SLOT=""
slot=0
while [ "${slot}" -lt 32 ]; do
    if cryptsetup open --test-passphrase --key-slot "${slot}" --key-file "${PASS_TMP}" \
            "${ROOTDEV}" >/dev/null 2>&1; then
        TEMP_SLOT="${slot}"
        break
    fi
    slot=$((slot + 1))
done
[ -n "${TEMP_SLOT}" ] || skip "conversion keyslot not found"
if ! cryptsetup open --test-passphrase --key-file "${PRODUCTION_KEY}" "${ROOTDEV}" >/dev/null 2>&1; then
    cryptsetup luksAddKey --batch-mode --key-file "${PASS_TMP}" \
        --new-keyfile "${PRODUCTION_KEY}" "${ROOTDEV}" >/tmp/winn-fde-add-key.log 2>&1 \
        || { emit_log /tmp/winn-fde-add-key.log "luksAddKey"; skip "production passphrase enrollment failed"; }
fi
cryptsetup open --test-passphrase --key-file "${PRODUCTION_KEY}" "${ROOTDEV}" >/dev/null 2>&1 \
    || skip "production passphrase verification failed"
log "production passphrase enrolled and verified"

if [ "${RESUMED}" -eq 1 ]; then
    BOOT_SPEC="$(awk '$2 == "/boot" && $1 !~ /^#/ { print $1; exit }' /winnmnt/etc/fstab)"
    ESP_SPEC="$(awk '$2 == "/boot/efi" && $1 !~ /^#/ { print $1; exit }' /winnmnt/etc/fstab)"
    [ -n "${BOOT_SPEC}" ] || skip "separate /boot entry missing after resume"
    [ -n "${ESP_SPEC}" ] || skip "ESP entry missing after resume"
    BOOT_DEV="$(resolve_spec "${BOOT_SPEC}")"
    ESP_DEV="$(resolve_spec "${ESP_SPEC}")"
    [ -b "${BOOT_DEV}" ] && [ "${BOOT_DEV}" != "${ROOTDEV}" ] || skip "invalid /boot device after resume"
    [ -b "${ESP_DEV}" ] && [ "${ESP_DEV}" != "${ROOTDEV}" ] && [ "${ESP_DEV}" != "${BOOT_DEV}" ] || skip "invalid ESP device after resume"
    [ -s /winnmnt/root/.ssh/authorized_keys ] || skip "root authorized_keys missing after resume"
    for needed in /winnmnt/bin/sh /winnmnt/usr/sbin/update-initramfs \
                  /winnmnt/usr/sbin/mkinitramfs /winnmnt/usr/sbin/update-grub \
                  /winnmnt/usr/bin/lsinitramfs; do
        [ -x "${needed}" ] || skip "required command missing after resume: ${needed#/winnmnt}"
    done
fi

LUKS_UUID="$(cryptsetup luksUUID "${ROOTDEV}" 2>/dev/null)"
[ -n "${LUKS_UUID}" ] || skip "LUKS UUID unavailable after encryption"

# Required auxiliary and virtual mounts. Any failure stops before rebuilding
# GRUB or rebooting, and cleanup unwinds everything in reverse order.
mount "${BOOT_DEV}" /winnmnt/boot 2>/dev/null || skip "cannot mount /boot after encryption"
BOOT_MOUNTED=1
mount "${ESP_DEV}" /winnmnt/boot/efi 2>/dev/null || skip "cannot mount ESP after encryption"
ESP_MOUNTED=1
[ -d /winnmnt/boot/efi/EFI ] || skip "ESP has no EFI directory after encryption"
CURRENT_INITRD="/winnmnt/boot/initrd.img-$(uname -r)"
[ -s "${CURRENT_INITRD}" ] || skip "running kernel initrd missing after encryption"
INITRD_BYTES="$(wc -c < "${CURRENT_INITRD}")"
BOOT_FREE_BYTES=$(( $(df -Pk /winnmnt/boot | awk 'NR == 2 { print $4 }') * 1024 ))
BOOT_NEEDED_BYTES=$(( INITRD_BYTES * 2 + 134217728 ))
[ "${BOOT_FREE_BYTES}" -ge "${BOOT_NEEDED_BYTES}" ] \
    || skip "/boot free space ${BOOT_FREE_BYTES} below post-encryption rebuild floor ${BOOT_NEEDED_BYTES}"
for vfs in dev proc sys; do
    mkdir -p "/winnmnt/${vfs}"
    mount -o bind "/${vfs}" "/winnmnt/${vfs}" 2>/dev/null || skip "cannot bind-mount ${vfs}"
    case "${vfs}" in
        dev) DEV_MOUNTED=1;;
        proc) PROC_MOUNTED=1;;
        sys) SYS_MOUNTED=1;;
    esac
done

# ---- boot-stack setup INSIDE the chroot (no network needed) ----------------
chroot /winnmnt /bin/sh -s "${LUKS_UUID}" >/tmp/winn-fde-chroot.log 2>&1 <<'CHROOTEOS'
set -eu
LUKS_UUID="$1"
log() { echo "winn-fde-v4[chroot]: $*" >/dev/kmsg 2>/dev/null || echo "winn-fde-v4[chroot]: $*"; }

# crypttab: mapper <- the real LUKS UUID before any initramfs is generated.
cp -a /etc/crypttab /etc/crypttab.pre-fde 2>/dev/null || true
awk -v mapper="root_crypt" '$1 == mapper { next } { print }' /etc/crypttab 2>/dev/null > /etc/crypttab.new || true
{
    cat /etc/crypttab.new 2>/dev/null || true
    printf 'root_crypt UUID=%s none luks,discard\n' "${LUKS_UUID}"
} > /etc/crypttab
rm -f /etc/crypttab.new
awk -v uuid="UUID=${LUKS_UUID}" '$1 == "root_crypt" && $2 == uuid && $3 == "none" && $4 == "luks,discard" { ok=1 } END { exit !ok }' /etc/crypttab
log "crypttab written with live LUKS UUID"

# fstab: swap ONLY the device on the root line; keep its mount options.
cp -a /etc/fstab /etc/fstab.pre-fde.$(date +%Y%m%d%H%M%S)
awk -v mapper="/dev/mapper/root_crypt" '$0 !~ /^[[:space:]]*#/ && $2 == "/" { $1 = mapper; roots++ } { print } END { exit roots != 1 }' /etc/fstab > /etc/fstab.new
mv /etc/fstab.new /etc/fstab
awk '$2 == "/" && $1 == "/dev/mapper/root_crypt" { ok=1 } END { exit !ok }' /etc/fstab
log "fstab root switched to /dev/mapper/root_crypt"

# Dropbear remote unlock on port 2222: the FINAL configuration, byte-identical
# to the one server/wins_control_plane_setup_ONETOUCH.sh writes (forced
# cryptroot-unlock, 180 s idle timeout, no forwarding, keys only, IFDOWN=none
# because our handoff script owns the teardown). Both Noble and legacy config
# paths are written; absence of the SSH key is fatal.
install -d -m 700 /etc/dropbear/initramfs /etc/dropbear-initramfs
install -m 600 /root/.ssh/authorized_keys /etc/dropbear/initramfs/authorized_keys
printf 'DROPBEAR_OPTIONS="-I 180 -j -k -p 2222 -s -c cryptroot-unlock"\nIFDOWN=none\n' > /etc/dropbear/initramfs/dropbear.conf
grep -q '^DROPBEAR_OPTIONS="-I 180 -j -k -p 2222 -s -c cryptroot-unlock"$' /etc/dropbear/initramfs/dropbear.conf
grep -qx 'IFDOWN=none' /etc/dropbear/initramfs/dropbear.conf
cp /etc/dropbear/initramfs/dropbear.conf /etc/dropbear-initramfs/config
mkdir -p /etc/cryptsetup-initramfs
printf 'UMASK=0077\n' > /etc/cryptsetup-initramfs/conf-hook
log "dropbear unlock configuration installed"

# The arm-time initramfs-only network configuration survives in root. One
# file, one DHCP owner: nothing else may define IP= or DEVICE=.
grep -qx "IP='dhcp'" /etc/initramfs-tools/conf.d/winn-fde-network
grep -qx "DEVICE=''" /etc/initramfs-tools/conf.d/winn-fde-network
FOREIGN_CONF="$(grep -lsE '^[[:space:]]*(IP|IP6|DEVICE|DEVICE6|BOOTIF|VLAN)=' /etc/initramfs-tools/conf.d/* 2>/dev/null \
    | grep -vx /etc/initramfs-tools/conf.d/winn-fde-network || true)"
[ -z "${FOREIGN_CONF}" ] || { log "foreign early-boot network file: ${FOREIGN_CONF}"; exit 1; }
FOREIGN_NET="$(grep -ls 'configure_networking' /etc/initramfs-tools/scripts/init-premount/* 2>/dev/null || true)"
[ -z "${FOREIGN_NET}" ] || { log "local init-premount script calls configure_networking: ${FOREIGN_NET}"; exit 1; }
FORCE_PARTUUID_CFG=/etc/default/grub.d/40-force-partuuid.cfg
if [ -f "${FORCE_PARTUUID_CFG}" ]; then
    sed -i -E '/^[[:space:]]*(export[[:space:]]+)?GRUB_FORCE_PARTUUID[[:space:]]*=/s/^/# disabled by winn-fde: /' "${FORCE_PARTUUID_CFG}"
fi
if grep -qE '^[[:space:]]*(export[[:space:]]+)?GRUB_FORCE_PARTUUID[[:space:]]*=' "${FORCE_PARTUUID_CFG}" 2>/dev/null; then
    exit 1
fi
grep -qx 'GRUB_TIMEOUT=5' /etc/default/grub.d/99-winn-fde-menu.cfg
grep -qx 'GRUB_RECORDFAIL_TIMEOUT=5' /etc/default/grub.d/99-winn-fde-menu.cfg

# Remove the conversion sources BEFORE generating the shipped initramfs: the
# hook, its tools, the PARTUUID layout and the temporary root= override (the
# encrypted-root entries use the ext4 UUID behind the mapper again).
rm -f /etc/initramfs-tools/scripts/local-premount/zz-winn-fde-v4
rm -f /etc/initramfs-tools/hooks/winn-fde-tools
rm -f /etc/initramfs-tools/conf.d/winn-fde-layout
rm -f /etc/default/grub.d/98-winn-fde-root.cfg

# Run the normal all-kernel refresh, then force the running kernel's image so
# initramfs-tools state caching cannot leave the conversion initrd in place.
update-initramfs -u -k all
KVER="$(uname -r)"
INITRD="/boot/initrd.img-${KVER}"
FINAL_TMP="${INITRD}.winn-new"
rm -f "${FINAL_TMP}"
mkinitramfs -o "${FINAL_TMP}" "${KVER}"
mv "${FINAL_TMP}" "${INITRD}"
sed -i -E '/^[[:space:]]*GRUB_CMDLINE_LINUX(_DEFAULT)?=/ s/(["=[:space:]])ip=[^"[:space:]]+/\1/g' /etc/default/grub
update-grub
if grep -Eq '^[[:space:]]*linux[^[:space:]]*[[:space:]].*(^|[[:space:]])ip=[^[:space:]]+' /boot/grub/grub.cfg; then
    exit 1
fi
if grep -Eq '^[[:space:]]*linux[^[:space:]]*[[:space:]].*(^|[[:space:]])root=PARTUUID=' /boot/grub/grub.cfg; then
    log "grub.cfg still pins root=PARTUUID after finalization"
    exit 1
fi
if grep -q '^GRUB_CMDLINE_LINUX_DEFAULT=' /etc/default/grub.d/99-winn-fde-menu.cfg; then
    awk '
        /^[[:space:]]*linux[^[:space:]]*[[:space:]]/ {
            last = ""
            for (i = 1; i <= NF; i++) if ($i ~ /^console=/) last = $i
            if (last != "") { seen = 1; if (last != "console=tty1") bad = 1 }
        }
        END { exit (!seen || bad) }
    ' /boot/grub/grub.cfg || { log "final grub.cfg lost the VGA-last console order; the prompt would sit on the serial port"; exit 1; }
fi
grep -Eq '^[[:space:]]*set timeout=5$' /boot/grub/grub.cfg || { log "grub.cfg has no 5 second menu"; exit 1; }
if grep -Eq '^[[:space:]]*set timeout=(0|-1)$|^[[:space:]]*set timeout_style=hidden$' /boot/grub/grub.cfg; then
    log "grub.cfg still hides the menu or waits forever after recordfail"
    exit 1
fi

# Inspect every retained initramfs byte set, including backup-suffixed
# initrd.img-* files. A zero-image or empty-listing result is a hard failure,
# never a vacuous residue PASS.
INITRD_PATHS="/tmp/winn-fde-final-initrd-paths.$$"
LISTING="/tmp/winn-fde-final-initrd-listing.$$"
CUSTODY_BUILD="/var/lib/.winn-fde-custody.pending.$$"
cleanup_custody_build() {
    rm -f "${INITRD_PATHS}" "${LISTING}" "${CUSTODY_BUILD}"
}
trap cleanup_custody_build EXIT
find /boot -maxdepth 1 -type f -name 'initrd.img-*' -print | LC_ALL=C sort > "${INITRD_PATHS}"
[ -s "${INITRD_PATHS}" ] || { log "no /boot initrd.img-* files found"; exit 1; }
SOURCE_SHA256="$(cat /var/lib/winn-fde-source.sha256 2>/dev/null || true)"
printf '%s' "${SOURCE_SHA256}" | grep -Eq '^[0-9a-f]{64}$' \
    || { log "source digest receipt is absent or malformed"; exit 1; }
umask 077
{
    printf 'format=winn-fde-custody-v1\n'
    printf 'phase=initramfs-verified\n'
    printf 'clock_source=initramfs-unsynchronized\n'
    printf 'captured_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    BOOT_ID="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)"
    printf '%s' "${BOOT_ID}" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' \
        || { log "boot ID is absent or malformed"; exit 1; }
    printf 'boot_id=%s\n' "${BOOT_ID}"
    printf 'source_sha256=%s\n' "${SOURCE_SHA256}"
    printf 'early_boot_network_mode=dhcp\n'
    printf 'early_boot_dhcp_owner=dropbear-init-premount\n'
} > "${CUSTODY_BUILD}"
chmod 600 "${CUSTODY_BUILD}"
INITRD_COUNT=0
BOOTABLE_INITRD_COUNT=0
while IFS= read -r CANDIDATE; do
    [ -s "${CANDIDATE}" ] || { log "empty initramfs candidate: ${CANDIDATE}"; exit 1; }
    rm -f "${LISTING}"
    lsinitramfs "${CANDIDATE}" > "${LISTING}" \
        || { log "cannot list initramfs ${CANDIDATE}"; exit 1; }
    LISTING_LINES="$(wc -l < "${LISTING}")"
    [ "${LISTING_LINES}" -ge 20 ] \
        || { log "implausibly short initramfs listing for ${CANDIDATE}"; exit 1; }
    if grep -Eq 'zz-winn-fde-v4|winn-fde-tools|conf/winn-fde-conversion-key|winn-fde-pass|winn-luks-initpass|conf/conf.d/winn-fde-layout' "${LISTING}"; then
        log "conversion hook, layout or credential unexpectedly remains in ${CANDIDATE}"
        exit 1
    fi
    if grep -Eq 'scripts/init-premount/zz-winn-fde-network$|conf/conf.d/wins-remote-unlock$' "${LISTING}"; then
        log "duplicate early-boot network file remains in ${CANDIDATE}"
        exit 1
    fi
    KERNEL_RELEASE="${CANDIDATE#/boot/initrd.img-}"
    if [ -d "/lib/modules/${KERNEL_RELEASE}" ]; then
        for REQUIRED in \
            scripts/local-top/cryptroot \
            scripts/init-premount/dropbear \
            scripts/init-premount/00-winn-fde-network \
            scripts/init-bottom/zz-winn-fde-network-handoff \
            conf/conf.d/winn-fde-network; do
            grep -Fxq "${REQUIRED}" "${LISTING}" \
                || { log "required unlock asset missing from ${CANDIDATE}: ${REQUIRED}"; exit 1; }
        done
        PREMOUNT_HOOKS="$(grep -Ec '^scripts/init-premount/.*winn-fde' "${LISTING}" || true)"
        [ "${PREMOUNT_HOOKS}" = "1" ] \
            || { log "expected exactly one winn-fde init-premount hook in ${CANDIDATE}, found ${PREMOUNT_HOOKS}"; exit 1; }
        grep -Eq '^(usr/)?sbin/cryptsetup$' "${LISTING}" \
            || { log "cryptsetup missing from bootable initramfs ${CANDIDATE}"; exit 1; }
        grep -Eq '^(usr/)?sbin/dropbear$' "${LISTING}" \
            || { log "dropbear missing from bootable initramfs ${CANDIDATE}"; exit 1; }
        grep -Eq '^(usr/)?s?bin/ip$' "${LISTING}" \
            || { log "ip missing from bootable initramfs ${CANDIDATE}"; exit 1; }
        BOOTABLE_INITRD_COUNT=$((BOOTABLE_INITRD_COUNT + 1))
    fi
    INITRD_COUNT=$((INITRD_COUNT + 1))
    INITRD_SHA256="$(sha256sum "${CANDIDATE}" 2>/dev/null | awk '{print $1}')"
    printf '%s' "${INITRD_SHA256}" | grep -Eq '^[0-9a-f]{64}$' \
        || { log "cannot hash initramfs ${CANDIDATE}"; exit 1; }
    printf 'initramfs_%s_path=%s\n' "${INITRD_COUNT}" "${CANDIDATE}" >> "${CUSTODY_BUILD}"
    printf 'initramfs_%s_sha256=%s\n' "${INITRD_COUNT}" "${INITRD_SHA256}" >> "${CUSTODY_BUILD}"
    rm -f "${LISTING}"
done < "${INITRD_PATHS}"
[ "${INITRD_COUNT}" -gt 0 ] || { log "zero initramfs files verified"; exit 1; }
[ "${BOOTABLE_INITRD_COUNT}" -gt 0 ] || { log "zero bootable initramfs files verified"; exit 1; }
printf 'initramfs_count=%s\n' "${INITRD_COUNT}" >> "${CUSTODY_BUILD}"
printf 'bootable_initramfs_count=%s\n' "${BOOTABLE_INITRD_COUNT}" >> "${CUSTODY_BUILD}"
mv "${CUSTODY_BUILD}" /var/lib/winn-fde-custody.pending
rm -f "${INITRD_PATHS}" "${LISTING}"
trap - EXIT
log "all retained initramfs files verified: unlock assets present, conversion residue absent, one early-boot hook"
CHROOTEOS
CHROOT_RC=$?
if [ "${CHROOT_RC}" -ne 0 ]; then
    emit_log /tmp/winn-fde-chroot.log "chroot"
    skip "chroot boot-stack setup failed rc=${CHROOT_RC}; not rebooting"
fi

write_custody_failure() {
    STAGE="$1"
    FAILURE_TMP="/winnmnt/var/lib/.winn-fde-custody-failure.$$"
    umask 077
    {
        printf 'format=winn-fde-custody-v1\n'
        printf 'state=incomplete\n'
        printf 'stage=%s\n' "${STAGE}"
        printf 'clock_source=initramfs-unsynchronized\n'
        FAILURE_BOOT_ID="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || printf unavailable)"
        printf 'boot_id=%s\n' "${FAILURE_BOOT_ID}"
    } > "${FAILURE_TMP}" 2>/dev/null || return 0
    chmod 600 "${FAILURE_TMP}" 2>/dev/null || true
    sync
    mv "${FAILURE_TMP}" /winnmnt/var/lib/winn-fde-custody-failure 2>/dev/null || true
    sync
}
custody_fail() {
    STAGE="$1"
    shift
    write_custody_failure "${STAGE}"
    skip "$*"
}
remove_secret_file() {
    SECRET_FILE="$1"
    shred -u "${SECRET_FILE}" 2>/dev/null || rm -f "${SECRET_FILE}" 2>/dev/null || true
    [ ! -e "${SECRET_FILE}" ] && [ ! -L "${SECRET_FILE}" ]
}
remove_operational_file() {
    OPERATIONAL_FILE="$1"
    rm -f "${OPERATIONAL_FILE}" 2>/dev/null || true
    [ ! -e "${OPERATIONAL_FILE}" ] && [ ! -L "${OPERATIONAL_FILE}" ]
}

if ! cryptsetup luksKillSlot --batch-mode --key-file "${PRODUCTION_KEY}" \
        "${ROOTDEV}" "${TEMP_SLOT}" >/tmp/winn-fde-kill-slot.log 2>&1; then
    emit_log /tmp/winn-fde-kill-slot.log "luksKillSlot"
    remove_secret_file /winnmnt/root/.winn-fde-conversion-key \
        || custody_fail "conversion-key-unlink-after-slot-removal-failure" "conversion key file removal failed"
    custody_fail "conversion-slot-removal" "conversion keyslot removal failed"
fi
cryptsetup open --test-passphrase --key-file "${PASS_TMP}" "${ROOTDEV}" >/dev/null 2>&1
CONVERSION_CHALLENGE_RC=$?
[ "${CONVERSION_CHALLENGE_RC}" -eq 2 ] \
    || custody_fail "conversion-credential-negative-challenge" "conversion credential rejection was indeterminate rc=${CONVERSION_CHALLENGE_RC}"
remove_secret_file /winnmnt/root/.winn-fde-conversion-key \
    || custody_fail "conversion-key-unlink-after-negative-challenge" "conversion key file remains after rejection"
cryptsetup open --test-passphrase --key-file "${PRODUCTION_KEY}" "${ROOTDEV}" >/dev/null 2>&1
PRODUCTION_CHALLENGE_RC=$?
[ "${PRODUCTION_CHALLENGE_RC}" -eq 0 ] \
    || custody_fail "production-credential-positive-challenge" "production credential stopped unlocking rc=${PRODUCTION_CHALLENGE_RC}"

FINAL_LUKS_DUMP=/tmp/winn-fde-final-luks-dump.log
cryptsetup luksDump "${ROOTDEV}" > "${FINAL_LUKS_DUMP}" 2>&1 \
    || custody_fail "final-luks-metadata" "cannot inspect final LUKS metadata"
FINAL_SLOT_COUNT="$(awk 'BEGIN{s=0;n=0} /^Keyslots:/ {s=1;next} /^Tokens:|^Digests:/ {s=0} s && /^[[:space:]]+[0-9]+:/ {n++} END{print n}' "${FINAL_LUKS_DUMP}")"
FINAL_SLOT_IDS="$(awk 'BEGIN{s=0} /^Keyslots:/ {s=1;next} /^Tokens:|^Digests:/ {s=0} s && /^[[:space:]]+[0-9]+:/ {gsub(/^[[:space:]]+|:.*/, ""); printf "%s%s", sep, $0; sep=","}' "${FINAL_LUKS_DUMP}")"
FINAL_TOKEN_COUNT="$(awk 'BEGIN{s=0;n=0} /^Tokens:/ {s=1;next} /^Digests:/ {s=0} s && /^[[:space:]]+[0-9]+:/ {n++} END{print n}' "${FINAL_LUKS_DUMP}")"
[ "${FINAL_SLOT_COUNT}" -eq 1 ] \
    || custody_fail "final-keyslot-count" "expected exactly one active keyslot, found ${FINAL_SLOT_COUNT}"
[ "${FINAL_TOKEN_COUNT}" -eq 0 ] \
    || custody_fail "final-token-count" "expected zero LUKS tokens, found ${FINAL_TOKEN_COUNT}"
if grep -qi 'reencrypt' "${FINAL_LUKS_DUMP}"; then
    custody_fail "final-reencryption-metadata" "active reencryption metadata remains"
fi
FINAL_LUKS_UUID="$(cryptsetup luksUUID "${ROOTDEV}" 2>/dev/null)"
[ -n "${FINAL_LUKS_UUID}" ] \
    || custody_fail "final-luks-uuid" "final LUKS UUID unavailable"
log "one-time conversion keyslot removed and final credential controls verified"

# Durable secret files and staged one-shot entrypoints must be absent before
# the success receipt and completion marker become authoritative.
[ "${ROOT_MOUNTED}" -eq 1 ] && findmnt -n /winnmnt >/dev/null 2>&1 \
    || custody_fail "encrypted-root-mount" "encrypted root is not mounted at /winnmnt"
[ -s "${PRODUCTION_KEY}" ] \
    || custody_fail "production-passphrase-pre-unlink" "production passphrase file is absent before custody cleanup"
remove_secret_file /winnmnt/root/.winn-fde-pass \
    || custody_fail "production-passphrase-unlink" "production passphrase file remains"
remove_secret_file /winnmnt/root/.winn-fde-conversion-key \
    || custody_fail "conversion-key-unlink" "conversion key file remains"
remove_secret_file /winnmnt/root/fde.sh \
    || custody_fail "legacy-fde-script-unlink" "legacy FDE script remains"
remove_operational_file /winnmnt/root/fde_boot_chain.sh \
    || custody_fail "boot-chain-unlink" "staged FDE boot-chain script remains"
remove_operational_file /winnmnt/root/ionos_fde_reinstall.sh \
    || custody_fail "reinstall-script-unlink" "staged FDE reinstall script remains"
remove_operational_file /winnmnt/usr/local/sbin/winn-fde-arm \
    || custody_fail "arm-helper-unlink" "staged arm helper remains"
remove_operational_file /winnmnt/var/lib/winn-fde-source.sha256 \
    || custody_fail "source-digest-staging-unlink" "source digest staging file remains"

CUSTODY_PENDING=/winnmnt/var/lib/winn-fde-custody.pending
CUSTODY_FINAL=/winnmnt/var/lib/winn-fde-custody.receipt
CUSTODY_FINAL_TMP=/winnmnt/var/lib/.winn-fde-custody.receipt.tmp
[ -s "${CUSTODY_PENDING}" ] \
    || custody_fail "pending-receipt" "pending initramfs receipt is absent"
umask 077
{
    cat "${CUSTODY_PENDING}"
    printf 'state=closed\n'
    printf 'luks_uuid=%s\n' "${FINAL_LUKS_UUID}"
    printf 'active_keyslot_ids=%s\n' "${FINAL_SLOT_IDS}"
    printf 'active_keyslot_count=%s\n' "${FINAL_SLOT_COUNT}"
    printf 'token_count=%s\n' "${FINAL_TOKEN_COUNT}"
    printf 'reencryption_metadata=absent\n'
    printf 'conversion_challenge_rc=%s\n' "${CONVERSION_CHALLENGE_RC}"
    printf 'production_challenge_rc=%s\n' "${PRODUCTION_CHALLENGE_RC}"
    printf 'passphrase_files_absent=true\n'
    printf 'staged_entrypoints_absent=true\n'
} > "${CUSTODY_FINAL_TMP}" \
    || custody_fail "final-receipt-write" "cannot write final custody receipt"
chmod 600 "${CUSTODY_FINAL_TMP}" \
    || custody_fail "final-receipt-mode" "cannot set final custody receipt mode"
sync
mv "${CUSTODY_FINAL_TMP}" "${CUSTODY_FINAL}" \
    || custody_fail "final-receipt-publish" "cannot publish final custody receipt"
remove_operational_file "${CUSTODY_PENDING}" \
    || custody_fail "pending-receipt-unlink" "pending custody receipt remains"
DONE_TMP=/winnmnt/var/lib/.winn-fde-done.tmp
printf 'receipt=/var/lib/winn-fde-custody.receipt\n' > "${DONE_TMP}" \
    || custody_fail "completion-marker-write" "cannot write completion marker"
chmod 600 "${DONE_TMP}" \
    || custody_fail "completion-marker-mode" "cannot set completion marker mode"
sync
mv "${DONE_TMP}" /winnmnt/var/lib/winn-fde-done \
    || custody_fail "completion-marker-publish" "cannot publish completion marker"
rm -f /winnmnt/var/lib/winn-fde-custody-failure
sync
cleanup
log "conversion complete; rebooting into the LUKS boot"
# The current boot's cmdline still points at the plain root, which no longer
# mounts; reboot immediately so the LUKS-aware boot stack takes over.
reboot -f
EOS
chmod 755 "${PREMOUNT_DIR}/zz-winn-fde-v4"
say "pre-mount conversion hook installed (shrink -> encrypt -> chroot setup -> reboot, one boot)"

# ---- disable cloud-init growth (would undo the shrink every boot) ----------
mkdir -p /etc/cloud/cloud.cfg.d
cat > /etc/cloud/cloud.cfg.d/99-winn-fde-no-grow.cfg <<'CGEOF'
# Installed by fde_boot_chain.sh: the root filesystem is deliberately
# smaller than its partition (LUKS reencryption tail). Never auto-grow.
growpart:
  mode: 'off'
resize_rootfs: false
CGEOF
say "cloud-init growpart and resize_rootfs disabled"

# ---- build + verify (every installed kernel, forced, SIGPIPE-proof) ---------
KVER="$(uname -r)"
module_is_builtin() {
  grep -q "/$1\.ko$" "/lib/modules/${KVER}/modules.builtin" 2>/dev/null
}
verify_initrd() {
  # $1 = initramfs image to verify
  local image="$1"
  [ -s "${image}" ] || return 1
  [ "$(stat -c '%a' "${image}")" = "600" ] || { say "${image} is not mode 0600."; return 1; }
  command -v lsinitramfs >/dev/null 2>&1 || { say "lsinitramfs unavailable; cannot verify ${image}."; return 1; }
  local listing="/tmp/winn-initrd-listing.$$"
  lsinitramfs "${image}" >"${listing}" 2>/dev/null
  local missed=""
  for needle in "zz-winn-fde-v4" "00-winn-fde-network" "zz-winn-fde-network-handoff" \
                "conf/conf.d/winn-fde-network" "conf/conf.d/winn-fde-layout" "conf/winn-fde-conversion-key" \
                "scripts/init-premount/dropbear" \
                "e2fsck" "resize2fs" "tune2fs" "cryptsetup"; do
    grep -q "${needle}" "${listing}" || missed="${missed} ${needle}"
  done
  grep -Eq '(^|/)(usr/)?sbin/ip$' "${listing}" || missed="${missed} sbin/ip"
  grep -Eq '(^|/)(usr/)?sbin/dropbear$' "${listing}" || missed="${missed} sbin/dropbear"
  for module in dm-crypt xts; do
    module_is_builtin "${module}" && continue
    grep -Eq "/${module}\.ko(\.[a-z0-9]+)?$" "${listing}" || missed="${missed} ${module}.ko"
  done
  if [[ "${NET_DRIVER_BUILTIN}" -eq 0 ]]; then
    grep -Eq "/${NET_DRIVER//-/[-_]}\.ko(\.[a-z0-9]+)?$" "${listing}" || missed="${missed} ${NET_DRIVER}.ko"
  fi
  local premount_hooks
  premount_hooks="$(grep -Ec '^scripts/init-premount/.*winn-fde' "${listing}" || true)"
  [ "${premount_hooks}" = "1" ] || missed="${missed} one-winn-fde-init-premount-hook(found:${premount_hooks})"
  if grep -Eq 'scripts/init-premount/zz-winn-fde-network$|conf/conf.d/wins-remote-unlock$' "${listing}"; then
    missed="${missed} duplicate-early-boot-network-file-present"
  fi
  rm -f "${listing}"
  [ -z "${missed}" ] || { say "${image} missing:${missed}"; return 1; }
  return 0
}
# Every installed kernel first (section 42: all images rebuilt), then the
# running kernel is forced past initramfs-tools state caching; every image
# that has modules installed is verified, built into a temporary file and
# only then moved into place.
update-initramfs -u -k all >>/var/log/fde-chain.log 2>&1 \
  || die "update-initramfs -u -k all failed; see /var/log/fde-chain.log."
chmod 600 /boot/initrd.img-* 2>/dev/null || true
VERIFIED_IMAGES=0
for MODULE_DIR in /lib/modules/*; do
  [[ -d "${MODULE_DIR}" ]] || continue
  BUILD_KVER="${MODULE_DIR##*/}"
  [[ -s "/boot/vmlinuz-${BUILD_KVER}" ]] || continue
  INITRD="/boot/initrd.img-${BUILD_KVER}"
  BUILD_INITRD="${INITRD}.winn-new"
  rm -f "${BUILD_INITRD}"
  mkinitramfs -o "${BUILD_INITRD}" "${BUILD_KVER}" >>/var/log/fde-chain.log 2>&1 \
    || die "mkinitramfs failed for ${BUILD_KVER}; do not reboot."
  chmod 600 "${BUILD_INITRD}"
  verify_initrd "${BUILD_INITRD}" || die "initramfs verification failed for ${BUILD_KVER}; do not reboot."
  mv "${BUILD_INITRD}" "${INITRD}"
  VERIFIED_IMAGES=$((VERIFIED_IMAGES + 1))
  say "conversion initramfs built and verified for kernel ${BUILD_KVER}"
done
[[ "${VERIFIED_IMAGES}" -ge 1 ]] || die "no kernel initramfs was built."
verify_initrd "/boot/initrd.img-${KVER}" || die "the running kernel's initramfs failed verification after the build loop."
say "hook + tools verified in ${VERIFIED_IMAGES} initramfs image(s) (running kernel ${KVER})."

# Regenerate grub.cfg after disabling the vendor initrdless setting and
# writing the menu and root files. Building an initramfs alone does not
# change an already generated GRUB menu.
sed -i -E '/^[[:space:]]*GRUB_CMDLINE_LINUX(_DEFAULT)?=/ s/(["=[:space:]])ip=[^"[:space:]]+/\1/g' /etc/default/grub
update-grub >>/var/log/fde-chain.log 2>&1 || die "update-grub failed after arming the conversion initramfs."
grep -qE '^[[:space:]]*initrd[[:space:]]+' /boot/grub/grub.cfg \
  || die "grub.cfg has no initrd command; conversion hook would never run."
if grep -Eq '^[[:space:]]*linux[^[:space:]]*[[:space:]].*(^|[[:space:]])ip=[^[:space:]]+' /boot/grub/grub.cfg; then
  die "grub.cfg still carries a kernel ip= token that would override initramfs network mode."
fi
grep -Eq "^[[:space:]]*linux[^[:space:]]*[[:space:]].*(^|[[:space:]])root=PARTUUID=${ROOT_PARTUUID}([[:space:]]|$)" /boot/grub/grub.cfg \
  || die "grub.cfg does not pin root=PARTUUID=${ROOT_PARTUUID} for the conversion boot; do not reboot."
verify_grub_menu_cfg /boot/grub/grub.cfg \
  || die "grub.cfg does not show a 5 second menu (set timeout=5 missing, or timeout 0/-1 or hidden style present)."
if [[ -n "${GRUB_CMDLINE_OVERRIDE}" ]]; then
  verify_console_last /boot/grub/grub.cfg console=tty1 \
    || die "the last console= token of a grub.cfg linux line is not console=tty1 after the console order fix."
fi
say "grub.cfg verified: conversion initramfs loaded, root=PARTUUID pinned, 5 second menu, no kernel ip= token"

say "chain armed. REBOOT NOW: the next boot shrinks and encrypts offline, prepares the LUKS boot stack and reboots itself; the boot after it shows the 5 second menu and asks for the passphrase (console, or ssh -p 2222 with cryptroot-unlock)."
