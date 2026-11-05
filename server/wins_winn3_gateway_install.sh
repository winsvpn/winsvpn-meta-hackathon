#!/usr/bin/env bash
# TOMBSTONE: the standalone Winn v3 gateway installer, retired by design v17 2.8
# (slice S6). It installs nothing.
#
# The gateway now lives in server/wins_data_plane_setup_ONETOUCH.sh, which
# installs it on every data plane as part of the one install (design v17 2.1,
# owner decision Q2). This file stays for one release so a stale runbook, a
# copied command or a remote script that still calls it gets a clear refusal
# instead of a missing file. After that release it is deleted.
#
# Every invocation prints the pointer below to stderr and exits 2. No argument
# and no environment variable is read. There is no root check, no package
# manager, no firewall, service, key or file access, and nothing is sourced:
# the body is printf and exit, both shell builtins. The frozen copy of the old
# body that tools/winn3_gateway_block.py proves the move against is
# server/testdata/winn3_gateway_install_retired/. It is not an installer.
# tools/winn3_gateway_block.py (tombstone_problems) and
# tools/validate_deployment_scripts.py hold this file to that shape.
printf '%s\n' \
  'wins_winn3_gateway_install.sh is retired. It did nothing and changed nothing.' \
  'The Winn v3 gateway is now installed by the data-plane installer, on every data plane:' \
  '  server/wins_data_plane_setup_ONETOUCH.sh' \
  'There is no separate gateway step. A node built by the old standalone installer is adopted' \
  'by a normal run of the data-plane installer (design v17 2.6).' \
  'This file is a tombstone for one release and is then deleted.' >&2
exit 2
