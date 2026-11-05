#!/usr/bin/env bash
# TOMBSTONE: the standalone IONOS FDE conversion script, retired by the
# LUKS-FIX rounds (decision D1 (b), 2026-10-13). It converts nothing.
#
# No run of it reached its conversion step: it took ROOT_DEV from the root it
# was running on, then refused to run cryptsetup reencrypt on a mounted root
# (its only success was the no-op on an already-encrypted root). It also wrote
# a kernel ip= token into GRUB_CMDLINE_LINUX_DEFAULT, a second early-boot DHCP
# owner next to the dropbear init-premount script (handoff section 42), and set
# its own dropbear options. The supported path is
# deploy/make_ionos_user_data.sh, which embeds deploy/fde_boot_chain.sh. The
# converter owns the early-boot network: one physical NIC, one DHCP owner, no
# override.
#
# Every invocation prints the pointer below to stderr and exits 2. No argument
# and no environment variable is read. There is no root check, no package
# manager, no disk, boot loader, key or file access, and nothing is sourced:
# the body is printf and exit, both shell builtins. The converter's closure
# still removes a copy of this file that an older user-data stage left in /root,
# and tools/test_fde_passphrase_custody.py holds this file to that shape.
printf '%s\n' \
  'ionos_fde_reinstall.sh is retired. This run did nothing and changed nothing.' \
  'The IONOS hub is converted by the user-data route:' \
  '  deploy/make_ionos_user_data.sh builds the text to paste into the IONOS user data field,' \
  '  and it embeds deploy/fde_boot_chain.sh, the one supported converter.' \
  'The passphrase is delivered separately over SSH as /root/.winn-fde-pass (docs/FDE_CUSTODY_CLOSURE.md).' >&2
exit 2
