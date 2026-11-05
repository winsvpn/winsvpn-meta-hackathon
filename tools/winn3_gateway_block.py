#!/usr/bin/env python3
"""The winn3 gateway block of the data-plane installer (design v17 2.2, slice S3).

The standalone gateway installer server/wins_winn3_gateway_install.sh (G) is
moved into server/wins_data_plane_setup_ONETOUCH.sh (DP) as one marked block.
This file is the single statement of that move: which top-level items of G
are moved, which are not and why, and how moved text is renamed. Each entry
below is one line of the equivalence checker's enumerated allow-list.

  check    the equivalence checker. The block in DP must equal G transformed
           by exactly the allow-list below, then edited exactly as allow-list 4
           (the post-move edits) lists. Any other difference fails, and so
           does an allow-list entry that no longer matches G. It also
           checks that the block runs nothing when DP is loaded, carries only
           WINN3_GATEWAY_* variables, defines no function DP defines, and
           that every intentional change of design 2.2 is in place, and that
           G is the tombstone (tombstone_problems).
  extract  write the block as a file tests can source, with the few DP
           definitions it reads. Tests extract and source the block; they
           never source DP.
  render   print what the block body must be (how the block was written).

usage: tools/winn3_gateway_block.py check   [--root DIR] [--source FILE] [--tombstone FILE]
       tools/winn3_gateway_block.py extract [--root DIR] --out FILE
       tools/winn3_gateway_block.py render  [--root DIR] [--source FILE]

Slice S6 made server/wins_winn3_gateway_install.sh a tombstone (design v17
2.8), so G is no longer the file the check reads. It compares against the
frozen copy of G that S6 pinned (SOURCE, byte-identical to the S3 source whose
SHA-256 is SOURCE_SHA256) and fails if that copy changes. --source names
another copy of G. The frozen copy and this equivalence check are removed
together when the tombstone is deleted, one release after S6.
"""
import argparse
import difflib
import functools
import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# G itself is a tombstone since slice S6 (TOMBSTONE below). SOURCE is the frozen
# copy of the pre-tombstone installer: the text the move is proven against.
TOMBSTONE = "server/wins_winn3_gateway_install.sh"
SOURCE = "server/testdata/winn3_gateway_install_retired/wins_winn3_gateway_install.sh.snapshot"
# Frozen S3 source snapshot. A source change needs review before this pin changes.
# Re-pinned 2026-10-11 for PQ OI-5 (gateway client isolation): the snapshot
# carries the same firewall edits as the block, so the move stays provable.
SOURCE_SHA256 = "293f275940b3a50341d74e027d115bee5c6a82ead74cb5aa44fe75d0e09ffde2"
TARGET = "server/wins_data_plane_setup_ONETOUCH.sh"
BEGIN = "# --- begin winn3 gateway block ---"
END = "# --- end winn3 gateway block ---"

# The block's own header: the comment paragraph right after BEGIN. It is glue,
# not moved text, so the check compares what follows it.
HEADER = """\
# The Winn Protocol v3 gateway, moved from server/wins_winn3_gateway_install.sh
# (design v17 2.2, slice S3). Only function definitions and WINN3_GATEWAY_*
# defaults: loading this file runs none of it, and main() does not call it yet
# (the install phases are slice S4). Every line equals the standalone
# installer's text except as tools/winn3_gateway_block.py lists: the items it
# does not move, with the reason for each, the renamed variables and the
# block's own logging helpers. `python3 tools/winn3_gateway_block.py check`
# fails on any other difference. Tests extract and source this block, never
# this whole file."""

# ---------------------------------------------------------------------------
# Allow-list 1: top-level items of G that are not moved, each with its reason.
# A function, a variable assignment, or a statement named by its first line.
# ---------------------------------------------------------------------------
DELETED = "deleted (design 2.2)"
DUPLICATE = "duplicate helper: the data-plane copy is kept (design 1.3, 2.2)"
MERGED = "merged into data-plane code (design 2.2): the data plane is the single owner"
ENTRY = "the standalone command line: DP's main() and argument handling are kept (design 1.3)"

NOT_MOVED = {
    # Design 2.2 "Deleted": mark_winn3_role, refuse_on_hub, the gateway's apt,
    # maintenance and EXIT trap, --apply-listen-firewall, the reflector banner.
    "refuse_on_hub": DELETED + "; DP's own role and hub checks stay in force",
    "mark_winn3_role": DELETED + "; the data-winn3 role is migrated by adoption (2.6, slice S5)",
    "install_gateway_maintenance_packages": DELETED + ": the gateway's apt run and its EXIT trap; nftables and age join DP's apt_install",
    "preflight_maintenance": DELETED + ": the gateway's maintenance",
    "data_plane_weekly_present": DELETED + ": the gateway's maintenance",
    "write_fail2ban_sshd_jail": DELETED + ": the gateway's maintenance (fail2ban merged: DP's jail is the only writer)",
    "write_gateway_backup_env": DELETED + ": the gateway's maintenance (its backup is merged into DP's backup, 2.1 E)",
    "write_gateway_recovery_contract": DELETED + ": the gateway's maintenance",
    "write_gateway_backup_script": DELETED + ": the gateway's maintenance",
    "write_gateway_backup_timer": DELETED + ": the gateway's maintenance",
    "run_initial_gateway_backup": DELETED + ": the gateway's maintenance",
    "write_gateway_weekly_maintenance": DELETED + ": the gateway's maintenance (weekly maintenance merged into DP's, 2.1 E)",
    "install_gateway_maintenance": DELETED + ": the gateway's maintenance",
    "WINN3_GATEWAY_FAIL2BAN_IGNOREIPS": DELETED + ": read only by the gateway's maintenance",
    "WINN3_GATEWAY_BACKUP_ENV": DELETED + ": read only by the gateway's maintenance",
    "WINN3_GATEWAY_INSTALL_CONTRACT": DELETED + ": read only by the gateway's maintenance",
    "BACKUP_AGE_RECIPIENTS_FILE": DELETED + ": read only by the gateway's maintenance (and unprefixed, so it would shadow DP's)",
    "REQUIRE_BACKUP_ENCRYPTION": DELETED + ": read only by the gateway's maintenance (and unprefixed)",
    "REQUIRE_REMOTE_BACKUP": DELETED + ": read only by the gateway's maintenance; REQUIRE_REMOTE_BACKUP=0 would silently disable DP's remote backup (1.3)",
    "RCLONE_REMOTE": DELETED + ": read only by the gateway's maintenance (and unprefixed, so it would shadow DP's)",
    "apply_listen_firewall": DELETED + ": --apply-listen-firewall; DP's edge rebuild owns the WINVPN-INPUT listen rules",
    "WINN3_GATEWAY_MANAGE_FIREWALL": DELETED + ": read only by main() and apply_listen_firewall (--apply-listen-firewall)",
    "announce_non_forwarding_gateway": DELETED + ": the reflector banner (forwarding is fixed on, 2.3)",
    "warn_both": DELETED + ": the reflector banner's printer, its only caller",
    # Duplicate helpers: same name at DP top level, and the data-plane copy is
    # kept. log, warn and err are not here: G's print to stderr with a
    # [winn3-gw] prefix and DP's print to stdout, and moved code reads helper
    # output through $( ), `read < <( )` and >/dev/null, so the block keeps
    # G's under block-private names (FUNCTION_RENAMES below).
    "require_root": DUPLICATE + " (DP require_root); only G's main() called it",
    "require_supported_production_os": DUPLICATE + " (DP require_supported_production_os); only G's main() called it",
    "package_manager_busy": DUPLICATE + " (DP package_manager_busy); only the gateway's apt called it",
    "wait_for_package_manager": DUPLICATE + " (DP wait_for_package_manager)",
    "wait_for_fail2ban": DUPLICATE + " (DP wait_for_fail2ban)",
    "restore_unattended_upgrades": DUPLICATE + " (DP restore_unattended_upgrades)",
    "resolve_node_backup_host_id": DUPLICATE + " (DP resolve_node_backup_host_id)",
    "wins_owned_paths_from_source": DUPLICATE + " (the owned-paths block is byte-identical in every installer)",
    "write_owned_paths_manifest": DUPLICATE + " (the owned-paths block; DP's manifest now lists the gateway's paths too)",
    "report_unknown_owned_paths": DUPLICATE + " (the owned-paths block)",
    "WINS_OWNED_PATHS_DIRS": DUPLICATE + " (the owned-paths block)",
    "WINN3_GATEWAY_CODE_STAMP": DUPLICATE + ": DP assigns the same default at top level (DP_PROVIDED)",
    "main": DUPLICATE + "; " + ENTRY,
    # Merged sysctls: DP's setup_sysctl and edge script set ip_forward=1,
    # rmem/wmem_max 134217728 and nf_conntrack_max 1048576, each at or above
    # the value G wrote (P-1), so G's writers and its UDP-buffer preflight go.
    "preflight_udp_socket_buffers": MERGED + " for rmem/wmem; only G's main() called it",
    "ensure_udp_socket_buffers": MERGED + " (rmem/wmem_max, 60-winn3-gateway-udp-buffers.conf)",
    "ensure_ip_forward": MERGED + " (net.ipv4.ip_forward, 60-winn3-gateway-forward.conf)",
    "_upsert_forward_sysctl_conf": MERGED + " (the 60-winn3-gateway-forward.conf writer)",
    "data_plane_sysctl_owner": MERGED + " (only ensure_conntrack_max read it)",
    "data_plane_sysctl_value": MERGED + " (only ensure_conntrack_max read it)",
    "_drop_forward_sysctl_key": MERGED + " (the 60-winn3-gateway-forward.conf writer)",
    "ensure_conntrack_max": MERGED + " (nf_conntrack_max)",
    # The standalone command line.
    "usage": ENTRY,
    "warn_retired_winn_protocol_v3_enable_flag": ENTRY + "; only G's main() called it, and DP's main() refuses the flag first",
    "set -euo pipefail": ENTRY + "; DP sets set -Eeuo pipefail",
    'if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then': ENTRY,
}

# Items not moved whose leading comment describes items that are moved, so
# the comment stays.
KEEP_LEADING_COMMENT = {"WINN3_GATEWAY_CODE_STAMP"}

# ---------------------------------------------------------------------------
# Allow-list 2: renames.
# ---------------------------------------------------------------------------
# File-top variables carry the WINN3_GATEWAY_ prefix (design 2.2; 1.3 "File-top
# variables"). Every occurrence outside a quoted here-document is renamed:
# code, messages and comments. Inside an unquoted here-document only $NAME
# and ${NAME...} are, so generated files keep their text.
VARIABLE_RENAMES = {
    "WINN_CREDENTIALS_DIR": "WINN3_GATEWAY_CREDENTIALS_DIR",
    "WINN3_STATIC_KEY_PATH": "WINN3_GATEWAY_STATIC_KEY_PATH",
    "WINN3_ADMISSION_KEY_PATH": "WINN3_GATEWAY_ADMISSION_KEY_PATH",
    "WINN3_ENV_FILE": "WINN3_GATEWAY_ENV_FILE",
    "WINN3_UNIT_PATH": "WINN3_GATEWAY_UNIT_PATH",
    "WINN3_SERVICE_USER": "WINN3_GATEWAY_SERVICE_USER",
    "WINN3_PEER_REGISTRY_PATH": "WINN3_GATEWAY_PEER_REGISTRY_PATH",
    "WINN3_REPLAY_JOURNAL_DIR": "WINN3_GATEWAY_REPLAY_JOURNAL_DIR",
    "WINN3_REPLAY_JOURNAL_PATH": "WINN3_GATEWAY_REPLAY_JOURNAL_PATH",
    "MODE": "WINN3_GATEWAY_MODE",
}
# WINN3_REPLAY_JOURNAL is also the env-file key the gateway binary reads, so
# only its shell-variable uses are renamed: ${...} and $NAME expansions, its
# assignments, and the one line that names it for ${!name}. Its key text in
# the env file, the helper's key list and the sed that reads the key stay.
# (WINN3_GATEWAY_REPLAY_JOURNAL is taken: it is the install-time flag.)
EXPANSION_RENAMES = {
    "WINN3_REPLAY_JOURNAL": "WINN3_GATEWAY_REPLAY_JOURNAL_VALUE",
}
EXPANSION_RENAME_LINES = {
    "      WINN3_GATEWAY_DUAL_AUTH_ML_SEED WINN3_REPLAY_JOURNAL; do":
        "      WINN3_GATEWAY_DUAL_AUTH_ML_SEED WINN3_GATEWAY_REPLAY_JOURNAL_VALUE; do",
}
# The one moved top-level variable kept unprefixed: the shared fd 7 lock path,
# named identically by every writer of the live ruleset (DP's edge script,
# both guards, the queue watchdog, the runtime firewall and the gateway
# helper). DP assigns it at top level nowhere, and prefixing it here would
# let the installer side lock a different file from the rest.
KEPT_UNPREFIXED = {"WINS_FIREWALL_LOCK"}

# G's logging helpers, kept with G's behaviour (stderr, [winn3-gw] prefix)
# under block-private names, because DP's log, warn and err print to stdout
# and DP has no top-level die. Renamed at their definitions and at every
# command position outside here-documents.
FUNCTION_RENAMES = {
    "log": "winn3gw_log",
    "warn": "winn3gw_warn",
    "err": "winn3gw_err",
    "die": "winn3gw_die",
}

# Assignments the block reads from DP's top level. They are not moved (DP's
# copy is kept), and `extract` copies DP's exact line into the sourceable file.
DP_PROVIDED = {
    "WINN3_GATEWAY_ENV_FILE": 'WINN3_GATEWAY_ENV_FILE="${WINN3_GATEWAY_ENV_FILE:-/etc/winn/winn3-gateway.env}"',
    "WINN3_GATEWAY_CODE_STAMP": 'WINN3_GATEWAY_CODE_STAMP="${WINN3_GATEWAY_CODE_STAMP:-/etc/winsvpn/.winn3_gateway_installer.sha256}"',
    "WINS_FREE_MBIT": 'WINS_FREE_MBIT="${WINS_FREE_MBIT:-100}"',
}
DP_PROVIDED_FUNCTIONS = {
    "validate_free_bandwidth_rate": '''validate_free_bandwidth_rate() {
  local name value
  for name in WINS_FREE_MBIT WINN3_GATEWAY_FREE_MBIT; do
    value="${!name:-${WINS_FREE_MBIT}}"
    [[ "${value}" =~ ^(0|[1-9][0-9]{0,5})$ ]] && ((value <= 100000)) || {
      echo "${name} must be in 0..100000" >&2
      return 1
    }
  done
}''',
}

# FREE-CAP intentionally changes only these exact fragments of the frozen
# gateway source. Every original occurrence is counted before replacement.
FREECAP_REPLACEMENTS = [
    ("  validate_speedtest_ingest_port || bad=1\n",
     "  validate_speedtest_ingest_port || bad=1\n  validate_free_bandwidth_rate || bad=1\n", 1),
    ("  validate_forward_async || return 1\n",
     "  validate_forward_async || return 1\n  validate_free_bandwidth_rate || return 1\n", 2),
    ("WINN3_GATEWAY_MAX_SESSIONS=${WINN3_GATEWAY_MAX_SESSIONS}\n",
     "WINN3_GATEWAY_MAX_SESSIONS=${WINN3_GATEWAY_MAX_SESSIONS}\n\n"
     "# D5 free-tier cap (owner ruling 2026-10-11): the per-direction tunnel goodput\n"
     "# limit the binary applies to sessions the hub registry marks tier=free. 0\n"
     "# disables the cap; paid sessions are never limited. Read LIVE at start like\n"
     "# the DF and TCP values above (the unit bakes no -free-mbps), so an edit here\n"
     "# takes effect on the next restart. Decimal integers only, 0 to 100000; the\n"
     "# binary refuses anything else.\n"
     "WINN3_GATEWAY_FREE_MBIT=${WINN3_GATEWAY_FREE_MBIT}\n", 1),
    ("WINN3_GATEWAY_TCP_INGRESS=\"${WINN3_GATEWAY_TCP_INGRESS:-0}\"\n",
     "WINN3_GATEWAY_TCP_INGRESS=\"${WINN3_GATEWAY_TCP_INGRESS:-0}\"\n\n"
     "# D5 free-tier cap (owner ruling 2026-10-11): the per-direction tunnel goodput\n"
     "# limit the binary applies to sessions the hub registry marks tier=free. 0\n"
     "# disables the cap. Echoes the shared WINS_FREE_MBIT; the binary reads it LIVE\n"
     "# from the env file (EnvironmentFile=), so an edit there takes effect on the\n"
     "# next restart and no unit flag is baked for it. Decimal integers only, from\n"
     "# 0 to 100000; the binary refuses anything else before the socket exists.\n"
     "WINN3_GATEWAY_FREE_MBIT=\"${WINN3_GATEWAY_FREE_MBIT:-${WINS_FREE_MBIT:-100}}\"\n", 1),
    ("      WINN3_GATEWAY_TCP_INGRESS WINN3_GATEWAY_DUAL_AUTH_ED_KEY \\\n",
     "      WINN3_GATEWAY_TCP_INGRESS WINN3_GATEWAY_FREE_MBIT \\\n"
     "      WINN3_GATEWAY_DUAL_AUTH_ED_KEY \\\n", 1),
    ("      WINN3_GATEWAY_LISTENER_DF|WINN3_GATEWAY_TCP_INGRESS|\\\n",
     "      WINN3_GATEWAY_LISTENER_DF|WINN3_GATEWAY_TCP_INGRESS|\\\n"
     "      WINN3_GATEWAY_FREE_MBIT|\\\n", 1),
]
# G's assignment of a renamed variable that DP already assigns identically:
# not moved, DP's is kept.
NOT_MOVED_AFTER_RENAME = {
    "WINN3_GATEWAY_ENV_FILE": DUPLICATE + ": WINN3_ENV_FILE renamed is DP's WINN3_GATEWAY_ENV_FILE, same default (DP_PROVIDED)",
}

# ---------------------------------------------------------------------------
# Allow-list 3: the intentional changes of design 2.2, each with where it is
# and what proves it is in place. Items 1 to 5 and 7 landed in G in slice S2,
# so the move carries them and the block and G agree; items 1 (the runtime
# firewall unit) and 6 are DP changes made in S3; item 8 belongs to S4.
# Slice S2 also landed six behaviours 2.2 does not list (S2 report, section
# 3); they are listed here so the move carries them knowingly.
# ---------------------------------------------------------------------------
INTENTIONAL_CHANGES = [
    {
        "id": "2.2 item 1, helper",
        "why": "the boot helper takes wins_fw_lock over its whole flush and refill (S2)",
        "scope": "function:gateway_firewall_helper_text",
        "require": ["wins_fw_lock || {", "WINS_FIREWALL_LOCK_HELD"],
    },
    {
        "id": "2.2 item 1, apply_forwarding_firewall",
        "why": "takes wins_fw_lock around its whole flush and refill (S2)",
        "scope": "function:apply_forwarding_firewall",
        "require": ["wins_fw_lock || {", "apply_forwarding_firewall_locked", "wins_fw_unlock"],
    },
    {
        "id": "2.2 item 1, teardown_forwarding_firewall",
        "why": "takes wins_fw_lock around its whole flush and removal (S2)",
        "scope": "function:teardown_forwarding_firewall",
        "require": ["wins_fw_lock || {", "teardown_forwarding_firewall_locked", "wins_fw_unlock"],
    },
    {
        "id": "2.2 item 1, runtime firewall unit (S2-Q1)",
        "why": "wins-vpn-firewall holds wins_fw_lock from before its first change to its exit (S3)",
        "scope": "dp:write_runtime_vpn_firewall_unit",
        "require": ["wins_fw_lock() {", "if ! wins_fw_lock; then",
                    'WINS_FIREWALL_LOCK="${WINS_FIREWALL_LOCK:-/run/lock/wins-firewall.lock}"'],
    },
    {
        "id": "2.2 item 1, write_firewall",
        "why": "the edge rebuild already holds wins_fw_lock over its transaction (DP apply_firewall)",
        "scope": "dp:file",
        "require": ['wins_fw_lock || { err "The shared firewall lock is unavailable; active rules were not changed."; return 1; }'],
    },
    {
        "id": "2.2 item 2",
        "why": "the WINN3GW-INPUT jump goes immediately behind the SSH-recovery jump (S2)",
        "scope": "function:place_winn3gw_input_jump",
        "require": ["WINVPN-SSH-RECOVERY"],
        "forbid": ["-I INPUT 1 -i"],
    },
    {
        "id": "2.2 item 3",
        "why": "the helper writer is split into render (no start) and activate (S2)",
        "scope": "function:winn3gw_render_helper",
        "require": ["systemctl enable winn3-gateway-firewall.service"],
        "forbid": ["systemctl restart", "systemctl start"],
    },
    {
        "id": "2.2 item 3, activate",
        "why": "only winn3gw_activate runs the helper (S2)",
        "scope": "function:winn3gw_activate",
        "require": ["systemctl restart winn3-gateway-firewall.service"],
    },
    {
        "id": "2.2 item 4",
        "why": "/etc/winn is 0750 root:winn3-gateway (S2)",
        "scope": "function:write_env_file",
        "require": ['install -d -m 750 -o root -g "${WINN3_GATEWAY_SERVICE_USER}" /etc/winn'],
        "forbid": ["install -d -m 755"],
    },
    {
        "id": "2.2 item 5",
        "why": "the helper unit runs after netfilter-persistent and the local-serving latch (S2)",
        "scope": "function:winn3gw_render_helper",
        "require": ["After=network-online.target wins-vpn-firewall.service netfilter-persistent.service wins-node-local-serving.service systemd-tmpfiles-setup.service"],
    },
    {
        "id": "2.2 item 6 (S2-Q2)",
        "why": "the latch unit is ordered before both gateway units (S3)",
        "scope": "dp:file",
        "require": ["Before=docker.service nginx.service xray.service wins-node-register.service wins-vpn-firewall.service winn3-gateway.service winn3-gateway-firewall.service"],
    },
    {
        "id": "2.2 item 7",
        "why": "the staged binary's architecture is read from its ELF header with od, never file(1) (S2)",
        "scope": "function:staged_gateway_elf_arch",
        "require": ["od -An -tx1"],
        "forbid": ["file -b"],
    },
    {
        "id": "2.2 item 8",
        "why": "keygen .pub outputs are persisted: slice S4 (the credential transaction, 2.4)",
        "scope": "pending:S4",
        "require": [],
    },
    {
        "id": "S2 extra: xtables lock",
        "why": "prepare_wins_xtables_lock runs before the helper is rendered; the unit may write /run/lock and /run/xtables.lock",
        "scope": "function:winn3gw_render_helper",
        "require": ["prepare_wins_xtables_lock", "ReadWritePaths=/run/lock /run/xtables.lock"],
    },
    {
        "id": "S2 extra: ELF encoding",
        "why": "byte 5 must be 01, little endian",
        "scope": "function:staged_gateway_elf_arch",
        "require": ["-j5 -N1"],
    },
    {
        "id": "S2 extra: immediately behind",
        "why": "a WINN3GW-INPUT jump anywhere else behind the recovery jump is replaced",
        "scope": "function:place_winn3gw_input_jump",
        "require": ["inserted"],
    },
    {
        "id": "S2 extra: backup refuses without BACKUP_HOST_ID; --install hint",
        "why": "both live in parts of G that are not moved (the gateway backup script, G's main)",
        "scope": "pending:not-moved",
        "require": [],
    },
    {
        "id": "S2-Q7: no hostname fallback",
        "why": "no backup prefix or identity in the moved code falls back to hostname -s, and DP's node backup refuses without BACKUP_HOST_ID (S3)",
        "scope": "dp:write_backup_script",
        "require": ['HOST_ID="${BACKUP_HOST_ID:?BACKUP_HOST_ID missing; re-run the installer}"'],
        "forbid": ['HOST="$(hostname -s)"', "${BACKUP_HOST_ID:-${HOST}}"],
    },
]
# ---------------------------------------------------------------------------
# Allow-list 4: edits made to the moved text after the move, each with its
# reason. The frozen S3 source stays byte-identical (SOURCE_SHA256), and the
# block is G moved under allow-lists 1 to 3 and then edited exactly as listed
# here, in order. An entry whose old text no longer occurs exactly once in
# the moved text is stale and fails the check, so no edit can hide behind
# another, and any edit not listed still fails the equivalence diff. The
# first nine are TUNNEL-SPEED-2 OI-4 (t11/memory_merged.diff, certified at
# Turns 11 and 12), landed on the release tree at Turn 14; the tenth is the
# Turn 14 comment fix for WINN3_GATEWAY_FORWARD_ASYNC.
# ---------------------------------------------------------------------------
POST_MOVE_EDITS = [
    {
        "id": 'TS2 OI-4: WINN3_GATEWAY_DEDICATED and the payment-server rule',
        "why": 'the data-plane default is an uncapped gateway (owner 2026-10-10); a host with monero-wallet-rpc.service renders 0 (memory_merged, Turn 11)',
        "old": [
            'WINN3_GATEWAY_MEMORY_OVERCOMMIT="${WINN3_GATEWAY_MEMORY_OVERCOMMIT-}"',
            '# Route lookup and interface sysfs for check_gateway_egress_mtu. Production runs',
        ],
        "new": [
            'WINN3_GATEWAY_MEMORY_OVERCOMMIT="${WINN3_GATEWAY_MEMORY_OVERCOMMIT-}"',
            '# TUNNEL-SPEED-2 Turn 9 (owner 2026-10-10: "Remove the cap. Canada is a',
            '# dedicated server for VPN"). 1, the default for every data plane (the owner\'s',
            '# rule is that data planes are identical), writes MemoryMax=infinity and',
            '# MemoryHigh=infinity to the unit and keeps GOMEMLIMIT as a SOFT collector',
            '# target no lower than half of host RAM; the session formula below still',
            '# derives WINN3_GATEWAY_MAX_SESSIONS and the GOMEMLIMIT floor. 0 restores the',
            '# capped formula for a host that shares its RAM with other services.',
            '#',
            '# The one such data plane is rendered by the installer itself, so the fleet',
            '# keeps one config (owner rule 2026-09-24: identical "except Spain would also',
            '# have Crypto payment server"): when WINN3_GATEWAY_DEDICATED is unset and the',
            "# payment server's unit exists (server/spain_crypto_payments_setup.sh writes",
            '# /etc/systemd/system/monero-wallet-rpc.service), the default is 0 and the log',
            '# reads "dedicated 0 (payment server present)", so the capped formula keeps a',
            '# gateway at full occupancy away from the wallet RPC. An explicit value still',
            '# wins. WINN3_GATEWAY_PAYMENT_UNIT exists so the unit tests can supply a',
            '# fixture path.',
            'WINN3_GATEWAY_PAYMENT_UNIT="${WINN3_GATEWAY_PAYMENT_UNIT:-/etc/systemd/system/monero-wallet-rpc.service}"',
            'WINN3_GATEWAY_DEDICATED_REASON=""',
            'if [[ -z "${WINN3_GATEWAY_DEDICATED+x}" && -e "${WINN3_GATEWAY_PAYMENT_UNIT}" ]]; then',
            '  WINN3_GATEWAY_DEDICATED=0',
            '  WINN3_GATEWAY_DEDICATED_REASON=" (payment server present)"',
            'fi',
            'WINN3_GATEWAY_DEDICATED="${WINN3_GATEWAY_DEDICATED-1}"',
            '# Route lookup and interface sysfs for check_gateway_egress_mtu. Production runs',
        ],
    },
    {
        "id": 'TS2 OI-4: memory banner, 208 MiB base plus 64 MiB per session',
        "why": 'the 8192-slot uplink inbox the async write needs re-sized the per-session term (memory_merged, Turn 11)',
        "old": [
            '#',
            '# MemoryMax = 96 MiB base + 40 MiB * WINN3_GATEWAY_MAX_SESSIONS',
            '# MemoryHigh = 75% of MemoryMax',
        ],
        "new": [
            '#',
            '# MemoryMax = 208 MiB base + 64 MiB * WINN3_GATEWAY_MAX_SESSIONS',
            '# MemoryHigh = 75% of MemoryMax',
        ],
    },
    {
        "id": 'TS2 OI-4: per-session bill paragraph and the format_cgroup_kib example',
        "why": 'the bill is 36.98 MiB adversarial per session over the 8192-slot inbox; cgroup_memory_budget_test.go pins it (memory_merged, Turn 11)',
        "old": [
            '#',
            '# Per-session bill, from source and measured (Round K, lane L12, 2026-09-23;',
            '# cmd/winn3-gateway/cgroup_memory_budget_test.go measures and pins it):',
            '#   send queue  gatewaySendQueue 8192 * 2 KiB pooled slab, allocated lazily,',
            '#               plus append headroom                        17,170,432 B',
            '#   windows     2 * gatewayTokenWindow 32768 * 53 B, the modeled',
            '#               transition allowance (not a bound on garbage) 3,473,408 B',
            '#   inbox       512 * (2 KiB slab + 32 B)                    1,064,960 B',
            '#   fixed       pipe, loop, device, goroutines (measured)      ~0.6 MiB',
            '# about 21.3 MiB adversarial per session. GOMEMLIMIT (60% of MemoryMax) is the',
            '# binding term, so the per-session coefficient is that bill / 0.6 plus about',
            '# 12%: 40 MiB. The 96 MiB base carries the shared live memory at 60%: the',
            '# demux queues at full occupancy (2 * 4096 * 4 KiB = 32 MiB, plus 256 KiB of',
            '# recvmmsg staging) and a measured 11 MiB process base with headroom.',
            '# At the default 64 sessions: MemoryMax 2656 MiB, MemoryHigh 1992 MiB,',
            '# GOMEMLIMIT 1594 MiB against about 1412 MiB of adversarial live memory.',
            '# Before Round K this term was 1.5 MiB, billed against a 256-entry send queue',
            '# while production queued 65536 (128 MiB per session, 8 GiB at 64 sessions).',
            '# Re-verify if the gateway token window, send queue, inbox Depth or path MTU move.',
            '#',
            '# These values are baked at install into the unit (MemoryMax/MemoryHigh,',
            '# Environment=GOMEMLIMIT, and -max-sessions) and copied into the env file.',
            '# Editing WINN3_GATEWAY_MAX_SESSIONS in the env file and restarting does',
            '# NOT retune them -- same bar as -forward. Re-run --install / --start.',
            '',
            "# format_cgroup_kib prints a systemd MemoryMax/MemoryHigh value. systemd's M",
            '# is MiB (1024^2). Use M when the quantity is a whole number of MiB so the',
            '# default (N=64 → 160M) stays readable; otherwise K so odd session counts',
            '# are exact rather than truncated.',
        ],
        "new": [
            '#',
            '# Per-session bill, from source and measured (tunnel-speed round 2, 2026-10-10;',
            '# cmd/winn3-gateway/cgroup_memory_budget_test.go measures and pins it):',
            '#   send queue  gatewaySendQueue 8192 * 2 KiB pooled slab, allocated lazily,',
            '#               plus append headroom                        17,563,648 B',
            '#   windows     2 * gatewayTokenWindow 32768 * 52 B, the modeled',
            '#               transition allowance (not a bound on garbage) 3,473,408 B',
            '#   inbox       8192 * (2 KiB slab + 32 B)                 17,039,360 B',
            '#   fixed       pipe, loop, device, goroutines (measured)      ~0.66 MiB',
            '#   asyncSub    one slab per blocked submit                      2,048 B',
            "#   36.98 MiB adversarial per session; -send-queue-fq adds the flow queues'",
            '#   own storage (session.SendFQBytes, measured 401,408 B) for 37.35 MiB.',
            '#   GOMEMLIMIT (60% of MemoryMax) is the binding term, so the per-session',
            '#   coefficient is the bill / 0.6: 64 MiB. The 208 MiB base carries the',
            '#   shared live memory at 60%: the demux staging, a measured process base,',
            '#   and four retiring sessions billed to the base (aggregate check at n=1:',
            '#   154 MiB live against a 163.2 MiB GOMEMLIMIT).',
            '# At the default 64 sessions: MemoryMax 4304 MiB, MemoryHigh 3228 MiB,',
            '# GOMEMLIMIT 2582.4 MiB (2707842662 bytes) against 2483 to 2508 MiB of',
            '# adversarial live memory.',
            '# Before round K this term was 1.5 MiB, billed against a 256-entry send queue',
            '# while production queued 65536 (128 MiB per session, 8 GiB at 64 sessions);',
            '# round K set it to 40 MiB over a 512-entry inbox, and round 2 (2026-10-10)',
            '# set 64 MiB over the 8192-slot inbox the async write needs.',
            '# Re-verify if the gateway token window, send queue, inbox Depth or path MTU move.',
            '#',
            '# These values are baked at install into the unit (MemoryMax/MemoryHigh,',
            '# Environment=GOMEMLIMIT, and -max-sessions) and copied into the env file.',
            '# Editing WINN3_GATEWAY_MAX_SESSIONS in the env file and restarting does',
            '# NOT retune them -- same bar as -forward. Re-run --install / --start.',
            '',
            "# format_cgroup_kib prints a systemd MemoryMax/MemoryHigh value. systemd's M",
            '# is MiB (1024^2). Use M when the quantity is a whole number of MiB so the',
            '# default (N=64 → 4304M) stays readable; otherwise K so odd session counts',
            '# are exact rather than truncated.',
        ],
    },
    {
        "id": 'TS2 OI-4: derive_gateway_memory term and the host-fit comment',
        "why": 'max_kib = 208 * 1024 + 65536 * n; host fit uses the same two constants (memory_merged, Turn 11)',
        "old": [
            '  fi',
            '  max_kib=$((96 * 1024 + 40960 * n))',
            '  high_kib=$((max_kib * 75 / 100))',
            '  # 80% of MemoryHigh, not of MemoryMax. Keep the existing sizing policy.',
            '  gomem_bytes=$((high_kib * 1024 * 80 / 100))',
            '  WINN3_GATEWAY_EFFECTIVE_MEMORY_MAX="$(format_cgroup_kib "${max_kib}")"',
            '  WINN3_GATEWAY_EFFECTIVE_MEMORY_HIGH="$(format_cgroup_kib "${high_kib}")"',
            '  WINN3_GATEWAY_EFFECTIVE_GOMEMLIMIT="$(format_gomemlimit_bytes "${gomem_bytes}")"',
            '  return 0',
            '}',
            '',
            '# ---------------------------------------------------------------------------',
            '# Host fit (OI-K4, Round K), kept SEPARATE from derive_gateway_memory, which',
            '# stays a pure session-to-memory function.',
            '# ---------------------------------------------------------------------------',
            '# Measured 2026-09-23: every fleet node ran -max-sessions 64, which at 40 MiB',
            "# per session asks for a 2656 MiB MemoryMax, above chicago's 1967 MiB of RAM.",
            '# The cgroup allowance may use at most half of MemTotal:',
            '#   cap_kib = floor(MemTotal_kib / 2)',
            '#   fit     = floor((cap_kib - 98304) / 40960), 0 when the numerator is not positive',
            '# Unset WINN3_GATEWAY_MAX_SESSIONS selects min(64, fit) and refuses automatic',
            '# selection below 4. An explicit count keeps the positive-decimal validation',
            '# and range, and refuses when 98304 + 40960 * n > cap_kib (naming fit) unless',
            '# WINN3_GATEWAY_MEMORY_OVERCOMMIT=1; explicit fitting counts of 1 to 3 stay',
        ],
        "new": [
            '  fi',
            '  # Base 208 MiB and 65536 KiB (64 MiB) per session since 2026-10-10',
            '  # (tunnel-speed round 2): the uplink inbox deepened to gatewayTokenWindow/4',
            '  # = 8192. The pooled slabs allocate to the high water (the channel holds',
            '  # only pointers), so the TYPICAL session costs nothing more; the ADVERSARIAL',
            '  # bill (cgroup_memory_budget_test.go, the L12 standard) is 36.98 MiB per',
            '  # full inbox plus four retiring sessions billed to the base, which needs a',
            '  # 61.7 MiB term at the 60% GOMEMLIMIT ratio and a 208 MiB base for the',
            '  # aggregate check at n=1 (153.9 MiB live against a 163.2 MiB GOMEMLIMIT).',
            '  # Host fit uses the same two constants.',
            '  max_kib=$((208 * 1024 + 65536 * n))',
            '  high_kib=$((max_kib * 75 / 100))',
            '  # 80% of MemoryHigh, not of MemoryMax. Keep the existing sizing policy.',
            '  gomem_bytes=$((high_kib * 1024 * 80 / 100))',
            '  WINN3_GATEWAY_EFFECTIVE_MEMORY_MAX="$(format_cgroup_kib "${max_kib}")"',
            '  WINN3_GATEWAY_EFFECTIVE_MEMORY_HIGH="$(format_cgroup_kib "${high_kib}")"',
            '  WINN3_GATEWAY_EFFECTIVE_GOMEMLIMIT="$(format_gomemlimit_bytes "${gomem_bytes}")"',
            '  return 0',
            '}',
            '',
            '# ---------------------------------------------------------------------------',
            '# Host fit (OI-K4, Round K), kept SEPARATE from derive_gateway_memory, which',
            '# stays a pure session-to-memory function.',
            '# ---------------------------------------------------------------------------',
            '# Measured 2026-09-23: every fleet node ran -max-sessions 64, which at the',
            "# then-40 MiB per session asked for a 2656 MiB MemoryMax, above chicago's",
            '# 1967 MiB of RAM; at the round-2 term (64 MiB over a 208 MiB base) the same',
            '# count asks for 4304 MiB, so the half-of-RAM cap still governs small hosts.',
            '# The cgroup allowance may use at most half of MemTotal:',
            '#   cap_kib = floor(MemTotal_kib / 2)',
            '#   fit     = floor((cap_kib - 212992) / 65536), 0 when the numerator is not positive',
            '# Unset WINN3_GATEWAY_MAX_SESSIONS selects min(64, fit) and refuses automatic',
            '# selection below 4. An explicit count keeps the positive-decimal validation',
            '# and range, and refuses when 212992 + 65536 * n > cap_kib (naming fit) unless',
            '# WINN3_GATEWAY_MEMORY_OVERCOMMIT=1; explicit fitting counts of 1 to 3 stay',
        ],
    },
    {
        "id": 'TS2 OI-4: gateway_sessions_that_fit constants',
        "why": 'fit = floor((cap_kib - 212992) / 65536) (memory_merged, Turn 11)',
        "old": [
            '',
            '# gateway_sessions_that_fit prints floor((cap_kib - 98304) / 40960), or 0.',
            'gateway_sessions_that_fit() {',
            '  local cap_kib="$1" numerator',
            '  numerator=$((cap_kib - 98304))',
            '  if (( numerator <= 0 )); then',
            "    printf '0'",
            '  else',
            '    printf \'%s\' "$((numerator / 40960))"',
            '  fi',
        ],
        "new": [
            '',
            '# gateway_sessions_that_fit prints floor((cap_kib - 212992) / 65536), or 0.',
            'gateway_sessions_that_fit() {',
            '  local cap_kib="$1" numerator',
            '  numerator=$((cap_kib - 212992))',
            '  if (( numerator <= 0 )); then',
            "    printf '0'",
            '  else',
            '    printf \'%s\' "$((numerator / 65536))"',
            '  fi',
        ],
    },
    {
        "id": 'TS2 OI-4: the automatic-selection refusal names the new term',
        "why": '64 MiB each above a 208 MiB base (memory_merged, Turn 11)',
        "old": [
            '    if (( fit < 4 )); then',
            '      winn3gw_err "Half of host RAM (${cap_kib} KiB of MemTotal ${mem_kib} kB) fits only ${fit} session(s) at 40 MiB each above a 96 MiB base; automatic selection needs at least 4. Refusing to install."',
            '      return 1',
        ],
        "new": [
            '    if (( fit < 4 )); then',
            '      winn3gw_err "Half of host RAM (${cap_kib} KiB of MemTotal ${mem_kib} kB) fits only ${fit} session(s) at 64 MiB each above a 208 MiB base; automatic selection needs at least 4. Refusing to install."',
            '      return 1',
        ],
    },
    {
        "id": 'TS2 OI-4: the explicit-count host fit uses the new term',
        "why": 'need_kib = 212992 + 65536 * n (memory_merged, Turn 11)',
        "old": [
            '  WINN3_GATEWAY_HOST_SOURCE="explicit"',
            '  need_kib=$((98304 + 40960 * n))',
            '  if (( need_kib > cap_kib )); then',
        ],
        "new": [
            '  WINN3_GATEWAY_HOST_SOURCE="explicit"',
            '  need_kib=$((212992 + 65536 * n))',
            '  if (( need_kib > cap_kib )); then',
        ],
    },
    {
        "id": 'TS2 OI-4: resolve_gateway_memory dedicated branch',
        "why": 'WINN3_GATEWAY_DEDICATED=1 writes MemoryMax and MemoryHigh infinity and lends GOMEMLIMIT the larger of the formula and half of host RAM; other values are refused (memory_merged, Turn 11)',
        "old": [
            'resolve_gateway_memory() {',
            '  local max_bytes cap_bytes key',
            '  resolve_gateway_host_fit || return 1',
            '  derive_gateway_memory || return 1',
            '  max_bytes="$(gateway_effective_max_bytes)" || return 1',
            '  cap_bytes=$((WINN3_GATEWAY_HOST_CAP_KIB * 1024))',
            '  if (( max_bytes > cap_bytes )); then',
            '    if [[ "${WINN3_GATEWAY_MEMORY_OVERCOMMIT}" != "1" ]]; then',
            '      winn3gw_err "Effective MemoryMax ${WINN3_GATEWAY_EFFECTIVE_MEMORY_MAX} (${max_bytes} B) is above half of host RAM (${cap_bytes} B). Set WINN3_GATEWAY_MEMORY_OVERCOMMIT=1 to install anyway."',
            '      return 1',
            '    fi',
            '    WINN3_GATEWAY_HOST_OVERCOMMIT_USED=1',
            '    winn3gw_warn "Effective MemoryMax ${WINN3_GATEWAY_EFFECTIVE_MEMORY_MAX} (${max_bytes} B) is above half of host RAM (${cap_bytes} B). Installing anyway: WINN3_GATEWAY_MEMORY_OVERCOMMIT=1."',
            '  fi',
            '  key="${WINN3_GATEWAY_MAX_SESSIONS}|${WINN3_GATEWAY_EFFECTIVE_MEMORY_MAX}|${WINN3_GATEWAY_EFFECTIVE_MEMORY_HIGH}|${WINN3_GATEWAY_EFFECTIVE_GOMEMLIMIT}|${WINN3_GATEWAY_HOST_OVERCOMMIT_USED}"',
            '  if [[ "${WINN3_GATEWAY_MEMORY_LOGGED}" != "${key}" ]]; then',
            '    WINN3_GATEWAY_MEMORY_LOGGED="${key}"',
            '    winn3gw_log "host fit: sessions ${WINN3_GATEWAY_MAX_SESSIONS} (${WINN3_GATEWAY_HOST_SOURCE}); MemTotal ${WINN3_GATEWAY_HOST_MEMTOTAL_KIB} kB from ${WINN3_GATEWAY_MEMINFO}; cap ${WINN3_GATEWAY_HOST_CAP_KIB} KiB fits ${WINN3_GATEWAY_HOST_FIT}; MemoryMax=${WINN3_GATEWAY_EFFECTIVE_MEMORY_MAX} MemoryHigh=${WINN3_GATEWAY_EFFECTIVE_MEMORY_HIGH} GOMEMLIMIT=${WINN3_GATEWAY_EFFECTIVE_GOMEMLIMIT}; overcommit ${WINN3_GATEWAY_HOST_OVERCOMMIT_USED}" >&2',
            '  fi',
        ],
        "new": [
            'resolve_gateway_memory() {',
            '  local max_bytes cap_bytes key gomem_bytes',
            '  case "${WINN3_GATEWAY_DEDICATED}" in',
            '    0|1) ;;',
            '    *) winn3gw_err "WINN3_GATEWAY_DEDICATED must be 1, 0 or unset."; return 1 ;;',
            '  esac',
            '  resolve_gateway_host_fit || return 1',
            '  derive_gateway_memory || return 1',
            '  cap_bytes=$((WINN3_GATEWAY_HOST_CAP_KIB * 1024))',
            '  if [[ "${WINN3_GATEWAY_DEDICATED}" == "1" && -z "${WINN3_GATEWAY_MEMORY_MAX:-}" ]]; then',
            '    # Dedicated VPN node (TUNNEL-SPEED-2 Turn 9): no cgroup cap. The formula',
            '    # above still sized the session count and a GOMEMLIMIT that the budget',
            '    # test (cgroup_memory_budget_test.go) proves covers the adversarial live',
            '    # set; a dedicated host lends the collector the larger of that figure and',
            '    # half of its RAM, so a leak spins the collector long before the kernel',
            '    # OOM killer sees it, and no self-imposed cap can throttle reclaim under',
            '    # a full session table (the stall that reads as censorship). An explicit',
            '    # override triplet still wins, exactly as before.',
            '    gomem_bytes="$(parse_gateway_memory_bytes "${WINN3_GATEWAY_EFFECTIVE_GOMEMLIMIT}" go)" || return 1',
            '    if (( cap_bytes > gomem_bytes )); then',
            '      gomem_bytes="${cap_bytes}"',
            '    fi',
            '    WINN3_GATEWAY_EFFECTIVE_MEMORY_MAX="infinity"',
            '    WINN3_GATEWAY_EFFECTIVE_MEMORY_HIGH="infinity"',
            '    WINN3_GATEWAY_EFFECTIVE_GOMEMLIMIT="$(format_gomemlimit_bytes "${gomem_bytes}")"',
            '    max_bytes=0',
            '  else',
            '    max_bytes="$(gateway_effective_max_bytes)" || return 1',
            '  fi',
            '  if (( max_bytes > cap_bytes )); then',
            '    if [[ "${WINN3_GATEWAY_MEMORY_OVERCOMMIT}" != "1" ]]; then',
            '      winn3gw_err "Effective MemoryMax ${WINN3_GATEWAY_EFFECTIVE_MEMORY_MAX} (${max_bytes} B) is above half of host RAM (${cap_bytes} B). Set WINN3_GATEWAY_MEMORY_OVERCOMMIT=1 to install anyway."',
            '      return 1',
            '    fi',
            '    WINN3_GATEWAY_HOST_OVERCOMMIT_USED=1',
            '    winn3gw_warn "Effective MemoryMax ${WINN3_GATEWAY_EFFECTIVE_MEMORY_MAX} (${max_bytes} B) is above half of host RAM (${cap_bytes} B). Installing anyway: WINN3_GATEWAY_MEMORY_OVERCOMMIT=1."',
            '  fi',
            '  key="${WINN3_GATEWAY_MAX_SESSIONS}|${WINN3_GATEWAY_EFFECTIVE_MEMORY_MAX}|${WINN3_GATEWAY_EFFECTIVE_MEMORY_HIGH}|${WINN3_GATEWAY_EFFECTIVE_GOMEMLIMIT}|${WINN3_GATEWAY_HOST_OVERCOMMIT_USED}"',
            '  if [[ "${WINN3_GATEWAY_MEMORY_LOGGED}" != "${key}" ]]; then',
            '    WINN3_GATEWAY_MEMORY_LOGGED="${key}"',
            '    winn3gw_log "host fit: sessions ${WINN3_GATEWAY_MAX_SESSIONS} (${WINN3_GATEWAY_HOST_SOURCE}); MemTotal ${WINN3_GATEWAY_HOST_MEMTOTAL_KIB} kB from ${WINN3_GATEWAY_MEMINFO}; cap ${WINN3_GATEWAY_HOST_CAP_KIB} KiB fits ${WINN3_GATEWAY_HOST_FIT}; dedicated ${WINN3_GATEWAY_DEDICATED}${WINN3_GATEWAY_DEDICATED_REASON}; MemoryMax=${WINN3_GATEWAY_EFFECTIVE_MEMORY_MAX} MemoryHigh=${WINN3_GATEWAY_EFFECTIVE_MEMORY_HIGH} GOMEMLIMIT=${WINN3_GATEWAY_EFFECTIVE_GOMEMLIMIT}; overcommit ${WINN3_GATEWAY_HOST_OVERCOMMIT_USED}" >&2',
            '  fi',
        ],
    },
    {
        "id": "TS2 OI-4: the unit's MemoryMax comment",
        "why": 'the rendered unit states the dedicated rule beside the capped formula (memory_merged, Turn 11)',
        "old": [
            'TasksMax=256',
            '# Session-derived at install from WINN3_GATEWAY_MAX_SESSIONS=${WINN3_GATEWAY_MAX_SESSIONS}:',
            '# MemoryMax = 96M + 40 MiB * max-sessions, MemoryHigh = 75% of that.',
            '# Not a percentage of host RAM. GOMEMLIMIT (80% of MemoryHigh, below the',
            '# cgroup throttle) is also in Environment= above and in the env file; Go',
            '# does not read cgroup limits.',
            'MemoryMax=${WINN3_GATEWAY_EFFECTIVE_MEMORY_MAX}',
        ],
        "new": [
            'TasksMax=256',
            '# Derived at install from WINN3_GATEWAY_MAX_SESSIONS=${WINN3_GATEWAY_MAX_SESSIONS}',
            '# with WINN3_GATEWAY_DEDICATED=${WINN3_GATEWAY_DEDICATED}: on a dedicated VPN',
            '# node both limits are infinity and GOMEMLIMIT (Environment= above and the',
            '# env file) is a soft collector target no lower than half of host RAM;',
            '# otherwise MemoryMax = 208M + 64 MiB * max-sessions, MemoryHigh = 75% of',
            '# that, GOMEMLIMIT = 80% of MemoryHigh. Go does not read cgroup limits.',
            'MemoryMax=${WINN3_GATEWAY_EFFECTIVE_MEMORY_MAX}',
        ],
    },
    {
        "id": 'TS2 Turn 14: WINN3_GATEWAY_FORWARD_ASYNC comment follows the binary default',
        "why": 'since 2026-10-10 the binary writes asynchronously by default and 0 bakes nothing; the comment said 0 kept the synchronous write',
        "old": [
            '',
            '# Multicore TUN writes (rev3.4, Round X): OFF BY DEFAULT. Ruling:',
            '# .agent/debates/_decisions/fable_ruling_multicore_r34_landing_20260929.md.',
            '# 0 (default) keeps the synchronous TUN write the gateway has always done. 1',
            "# bakes -forward-async-write into the unit's ExecStart, right after",
            '# -peer-registry, so each validated client packet goes to one writer goroutine',
            "# per TUN queue and one session's uplink can use more than one core. It needs",
            '# WINN3_GATEWAY_FORWARD=1: the binary refuses the flag without -forward, and so',
            '# does this script. At start the binary reads its usable CPUs (affinity, cgroup',
            '# cpu.max, cpuset.cpus.effective) and logs one "-forward-async-write" gate',
            '# line; below 2 usable CPUs it keeps the synchronous path. Baked at INSTALL',
            '# time like WINN3_GATEWAY_FORWARD: editing the env file and restarting changes',
            '# nothing. Only 0 and 1 are accepted.',
            'WINN3_GATEWAY_FORWARD_ASYNC="${WINN3_GATEWAY_FORWARD_ASYNC:-0}"',
        ],
        "new": [
            '',
            '# Multicore TUN writes (rev3.4, Round X). Ruling:',
            '# .agent/debates/_decisions/fable_ruling_multicore_r34_landing_20260929.md;',
            '# owner ruling 2026-10-10 (tunnel-speed round 2): multicore is always on.',
            "# 0 (default) bakes nothing into the unit's ExecStart, and since 2026-10-10",
            "# the binary's own default is the asynchronous write (cmd/winn3-gateway",
            '# forward_async_default.go): each validated client packet goes to one writer',
            "# goroutine per TUN queue and one session's uplink can use more than one",
            "# core; WINN3_GATEWAY_ASYNC_WRITE=0 in the unit's environment is the rollback",
            '# to the synchronous write. 1 bakes -forward-async-write explicitly, right',
            '# after -peer-registry (the ONETOUCH profile refuses it: the binary default',
            '# already carries it). It needs WINN3_GATEWAY_FORWARD=1: the binary refuses',
            '# the flag without -forward, and so does this script. At start the binary',
            '# reads its usable CPUs (affinity, cgroup cpu.max, cpuset.cpus.effective) and',
            '# logs one "-forward-async-write" gate line; below 2 usable CPUs it keeps the',
            '# synchronous path. Baked at INSTALL time like WINN3_GATEWAY_FORWARD: editing',
            '# the env file and restarting changes nothing. Only 0 and 1 are accepted.',
            'WINN3_GATEWAY_FORWARD_ASYNC="${WINN3_GATEWAY_FORWARD_ASYNC:-0}"',
        ],
    },
    {
        "id": 'AUDIT-FIX L04 F-4: the replay journal is opened non-blocking',
        "why": 'a FIFO planted at the journal path blocked the installer in open() before its regular-file check (audit 2026-10-13, lane L04, Astra F-4)',
        "old": [
            '        fd = os.open(journal_name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)',
        ],
        "new": [
            '        fd = os.open(journal_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)',
        ],
    },
    {
        "id": 'A1-ARGON-F3: the boot helper refuses a relative env file path',
        "why": 'source searches PATH for a name with no slash before the working directory, so the trust checks passed ./NAME and the PATH copy ran (A1 Argon audit 2026-10-14, verifier twin site)',
        "old": [
            '  env_file="${WINN3_GATEWAY_ENV_FILE:-/etc/winn/winn3-gateway.env}"',
            '  [[ -f "${env_file}" && ! -L "${env_file}" \\',
        ],
        "new": [
            '  env_file="${WINN3_GATEWAY_ENV_FILE:-/etc/winn/winn3-gateway.env}"',
            '  # A1-ARGON-F3: `source` searches PATH for a name with no slash before it',
            '  # tries the working directory, while the checks below look at the working',
            '  # directory.',
            '  [[ "${env_file}" == /* ]] || {',
            '    echo "winn3 gateway firewall refuses to source ${env_file}: it must be an absolute path" >&2',
            '    exit 1',
            '  }',
            '  [[ -f "${env_file}" && ! -L "${env_file}" \\',
        ],
    },
]

# Code the block itself must never contain (patterns over its non-comment
# lines).
BLOCK_FORBID = [
    (r"hostname -s", "S2-Q7: no hostname fallback in the moved code"),
    (r"(^|[;&|{]|then|do)\s*trap\s", "design 2.2: no EXIT trap moves (G's was the apt run's)"),
]

# The two top-level statements that may run when the block is loaded. Each
# only records whether the operator supplied a variable, and must run before
# that variable's default applies: WINN3_GATEWAY_MAX_SESSIONS (OI-K4), and
# WINN3_GATEWAY_DEDICATED, whose default is 0 when the payment server's unit
# exists on the host (TUNNEL-SPEED-2 OI-4). Neither reads anything but the
# environment and one path's existence.
ALLOWED_STATEMENTS = {'''if [[ -n "${WINN3_GATEWAY_MAX_SESSIONS+set}" ]]; then
  WINN3_GATEWAY_MAX_SESSIONS_SUPPLIED=1
else
  WINN3_GATEWAY_MAX_SESSIONS_SUPPLIED=0
fi''', '''if [[ -z "${WINN3_GATEWAY_DEDICATED+x}" && -e "${WINN3_GATEWAY_PAYMENT_UNIT}" ]]; then
  WINN3_GATEWAY_DEDICATED=0
  WINN3_GATEWAY_DEDICATED_REASON=" (payment server present)"
fi'''}


# ---------------------------------------------------------------------------
# Bash structure: top-level items, here-documents, quoting.
# ---------------------------------------------------------------------------
HEREDOC = re.compile(r"<<(-?)[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")
FUNCTION = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\(\)\s*\{")
ASSIGNMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\+?=")




def heredocs_opened(line):
    """Here-documents a code line opens, as (strip_tabs, quoted, delimiter)."""
    if line.lstrip().startswith("#"):
        return []
    found = []
    for match in HEREDOC.finditer(line):
        before = line[:match.start()]
        # 1 << 24 inside (( )) is a shift, not a here-document.
        if "((" in before and "))" not in before[before.rfind("(("):]:
            continue
        found.append((match.group(1) == "-", match.group(2) != "", match.group(3)))
    return found


def heredoc_spans(lines):
    """Map each here-document line to ("body" or "end", quoted)."""
    spans = {}
    i = 0
    while i < len(lines):
        opened = heredocs_opened(lines[i])
        i += 1
        for strip, quoted, delim in opened:
            while i < len(lines):
                text = lines[i].lstrip("\t") if strip else lines[i]
                if text == delim:
                    spans[i] = ("end", quoted)
                    i += 1
                    break
                spans[i] = ("body", quoted)
                i += 1
    return spans


def segment(lines):
    """Split bash text into top-level items.

    Each item is a dict: kind (func, assign, stmt, comment, blank), name (the
    function or variable, or a statement's first line), and inclusive line
    indexes start and end. A function ends at the first "}" in column 0
    outside a here-document, which is how G and DP write every function.
    """
    docs = heredoc_spans(lines)
    items = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        match = FUNCTION.match(line)
        if match:
            start = i
            one_line = (line.rstrip().endswith("}") and line.count("{") == line.count("}")
                        and not heredocs_opened(line))
            if not one_line:
                i += 1
                while i < n and not (lines[i] == "}" and i not in docs):
                    i += 1
            items.append({"kind": "func", "name": match.group(1), "start": start, "end": i})
            i += 1
            continue
        stripped = line.strip()
        if not stripped:
            items.append({"kind": "blank", "name": "", "start": i, "end": i})
            i += 1
            continue
        if stripped.startswith("#"):
            items.append({"kind": "comment", "name": "", "start": i, "end": i})
            i += 1
            continue
        start = i
        if re.match(r"^if\b", line):
            depth = 0
            while i < n:
                word = lines[i].strip()
                if i not in docs and re.match(r"^if\b", word):
                    depth += 1
                if i not in docs and word == "fi":
                    depth -= 1
                i += 1
                if depth == 0:
                    break
            items.append({"kind": "stmt", "name": line, "start": start, "end": i - 1})
            continue
        text = line
        while (text.rstrip().endswith("\\") or text.count("(") > text.count(")")) and i + 1 < n:
            i += 1
            text += "\n" + lines[i]
        i += 1
        while i < n and i in docs:
            i += 1
        assign = ASSIGNMENT.match(line)
        kind = "assign" if assign else "stmt"
        items.append({"kind": kind, "name": assign.group(1) if assign else line,
                      "start": start, "end": i - 1})
    return items


def lex_contexts(line, stack):
    """Classify each character of a code line, carrying quote state across lines.

    Returns one letter per character: N for code, S inside '...' or $'...',
    D inside "...", P inside ${...}, C for a comment. `stack` holds the open
    contexts and is updated in place; a $( ) inside double quotes opens code
    again, so "$(cmd "x")" reads correctly.
    """
    out = []
    i = 0
    n = len(line)
    while i < n:
        top = stack[-1] if stack else "N"
        ch = line[i]
        two = line[i:i + 2]
        if top == "S":
            out.append("S")
            if ch == "'":
                stack.pop()
            i += 1
            continue
        if top == "A":
            if ch == "\\" and i + 1 < n:
                out.extend("SS")
                i += 2
                continue
            out.append("S")
            if ch == "'":
                stack.pop()
            i += 1
            continue
        code = "N" if top in ("N", "X") else top
        if ch == "\\" and i + 1 < n:
            out.extend(code * 2)
            i += 2
            continue
        if top == "D":
            if ch == '"':
                out.append("D")
                stack.pop()
                i += 1
            elif two == "$(":
                out.extend("DD")
                stack.append("X")
                i += 2
            elif two == "${":
                out.extend("PP")
                stack.append("P")
                i += 2
            else:
                out.append("D")
                i += 1
            continue
        if top == "P":
            if two == "${":
                out.extend("PP")
                stack.append("P")
                i += 2
                continue
            out.append("P")
            if ch == "}":
                stack.pop()
            elif ch == '"':
                stack.append("D")
            elif ch == "'":
                stack.append("S")
            i += 1
            continue
        # Code: the top level (N) or inside $( ) and $(( )) (X).
        if ch == "#" and (i == 0 or line[i - 1] in " \t;|&("):
            out.extend("C" * (n - i))
            break
        if two == "$'":
            out.extend("SS")
            stack.append("A")
            i += 2
            continue
        if ch == "'":
            out.append("S")
            stack.append("S")
            i += 1
            continue
        if ch == '"':
            out.append("D")
            stack.append("D")
            i += 1
            continue
        if two == "${":
            out.extend("PP")
            stack.append("P")
            i += 2
            continue
        if two == "$(":
            out.extend("NN")
            stack.append("X")
            i += 2
            continue
        if top == "X":
            if ch == "(":
                stack.append("X")
            elif ch == ")":
                stack.pop()
        out.append("N")
        i += 1
    return "".join(out)


COMMAND_POSITION = re.compile(
    r"(?:^|[;&|{(!)]|\bthen|\belse|\bdo|\belif)[ \t]*("
    + "|".join(re.escape(name) for name in FUNCTION_RENAMES)
    + r")(?=[ \t;]|$)")
DEFINITION = re.compile(r"^(" + "|".join(re.escape(name) for name in FUNCTION_RENAMES) + r")\(\)")


def rename_functions(line, contexts):
    """Rename FUNCTION_RENAMES where they are defined or run as commands."""
    masked = "".join(ch if ctx == "N" else "\0" for ch, ctx in zip(line, contexts))
    edits = {(m.start(1), m.end(1)) for m in COMMAND_POSITION.finditer(masked)}
    definition = DEFINITION.match(line)
    if definition:
        edits.add((0, definition.end(1)))
    for start, end in sorted(edits, reverse=True):
        line = line[:start] + FUNCTION_RENAMES[line[start:end]] + line[end:]
    return line


def rename_words(text, table):
    for old, new in table.items():
        text = re.sub(r"(?<![A-Za-z0-9_])" + re.escape(old) + r"(?![A-Za-z0-9_])", new, text)
    return text


def rename_expansions(text, table):
    for old, new in table.items():
        text = re.sub(r"\$\{([#!]?)" + re.escape(old) + r"(?![A-Za-z0-9_])", r"${\g<1>" + new, text)
        text = re.sub(r"\$" + re.escape(old) + r"(?![A-Za-z0-9_])", "$" + new, text)
    return text


EXPANSION_ASSIGNMENT = re.compile(
    r"^(\s*)(" + "|".join(re.escape(name) for name in EXPANSION_RENAMES) + r")=")


def transform(lines):
    """Apply allow-list 2 (the renames) to moved lines. Line count is kept."""
    docs = heredoc_spans(lines)
    every = dict(VARIABLE_RENAMES)
    every.update(EXPANSION_RENAMES)
    stack = []
    out = []
    for index, line in enumerate(lines):
        if index in docs:
            state, quoted = docs[index]
            if state == "body" and not quoted:
                line = rename_expansions(line, every)
            out.append(line)
            continue
        line = EXPANSION_RENAME_LINES.get(line, line)
        line = rename_functions(line, lex_contexts(line, stack))
        line = rename_words(line, VARIABLE_RENAMES)
        line = rename_expansions(line, EXPANSION_RENAMES)
        assignment = EXPANSION_ASSIGNMENT.match(line)
        if assignment:
            line = (assignment.group(1) + EXPANSION_RENAMES[assignment.group(2)]
                    + line[assignment.end(2):])
        out.append(line)
    return out


# ---------------------------------------------------------------------------
# The move: G -> the block body.
# ---------------------------------------------------------------------------
def item_key(item):
    if item["kind"] == "stmt":
        return item["name"].rstrip()
    return item["name"]


def moved(item):
    """Whether a code item of G is moved, and if not, the reason."""
    key = item_key(item)
    if key in NOT_MOVED:
        return False, NOT_MOVED[key]
    if item["kind"] == "assign":
        renamed = VARIABLE_RENAMES.get(key, key)
        if renamed in NOT_MOVED_AFTER_RENAME:
            return False, NOT_MOVED_AFTER_RENAME[renamed]
    return True, ""


def apply_post_move_edits(body):
    """Allow-list 4: the listed edits applied in order to the moved text.

    Returns the edited body and the entries that are stale (their old text
    does not occur exactly once), which check() reports as failures.
    """
    text = "\n".join(body)
    stale = []
    for edit in POST_MOVE_EDITS:
        old = "\n".join(edit["old"])
        if text.count(old) != 1:
            stale.append(f"allow-list is stale: post-move edit {edit['id']!r} does not match the moved text "
                         f"exactly once ({edit['why']})")
            continue
        text = text.replace(old, "\n".join(edit["new"]))
    return text.split("\n"), stale


def render_body(source_text):
    """The block body: G's moved items, renamed, with their comments, then
    the post-move edits of allow-list 4."""
    body, _ = apply_post_move_edits(render_moved(source_text))
    return body


def render_moved(source_text):
    """G's moved items, renamed, with their comments: allow-lists 1 to 3."""
    lines = source_text.split("\n")
    items = segment(lines)
    keep = [False] * len(lines)
    code = [k for k, item in enumerate(items) if item["kind"] in ("func", "assign", "stmt")]
    for k, item in enumerate(items):
        if item["kind"] not in ("func", "assign", "stmt"):
            continue
        is_moved, _ = moved(item)
        for j in range(item["start"], item["end"] + 1):
            keep[j] = is_moved
        # The comment lines directly above an item belong to it.
        j = k - 1
        attached = is_moved or item_key(item) in KEEP_LEADING_COMMENT
        while j >= 0 and items[j]["kind"] == "comment":
            keep[items[j]["start"]] = attached
            j -= 1
    # A comment paragraph followed by a blank line stays when the next code
    # item after it is moved (section banners and notes).
    for k, item in enumerate(items):
        if item["kind"] != "comment" or (k + 1 < len(items) and items[k + 1]["kind"] == "comment"):
            continue
        if k + 1 < len(items) and items[k + 1]["kind"] != "blank":
            continue
        following = [c for c in code if c > k]
        stays = bool(following) and moved(items[following[0]])[0]
        j = k
        while j >= 0 and items[j]["kind"] == "comment":
            keep[items[j]["start"]] = stays
            j -= 1
    for item in items:
        if item["kind"] == "blank":
            keep[item["start"]] = True
    kept = [line for line, flag in zip(lines, keep) if flag]
    body = []
    for line in transform(kept):
        if not line.strip() and (not body or not body[-1].strip()):
            continue
        body.append(line)
    while body and not body[-1].strip():
        body.pop()
    text = "\n".join(body)
    for old, new, count in FREECAP_REPLACEMENTS:
        if text.count(old) != count:
            raise BlockError("FREE-CAP source fragment count changed")
        text = text.replace(old, new)
    return text.split("\n")


def render_block(source_text):
    return [BEGIN] + HEADER.split("\n") + [""] + render_body(source_text) + [END]


# ---------------------------------------------------------------------------
# The block in DP.
# ---------------------------------------------------------------------------
class BlockError(Exception):
    pass


def find_block(dp_lines):
    begins = [i for i, line in enumerate(dp_lines) if line == BEGIN]
    ends = [i for i, line in enumerate(dp_lines) if line == END]
    if len(begins) != 1 or len(ends) != 1 or begins[0] > ends[0]:
        raise BlockError(f"{TARGET} must hold exactly one '{BEGIN}' followed by one '{END}' "
                         f"(found {len(begins)} and {len(ends)})")
    return begins[0], ends[0]


def block_body(dp_lines):
    begin, end = find_block(dp_lines)
    header = HEADER.split("\n")
    lines = dp_lines[begin + 1:end]
    if lines[:len(header)] != header or (len(lines) > len(header) and lines[len(header)] != ""):
        raise BlockError("the block must start with its fixed header comment and a blank line")
    return lines[len(header) + 1:]


def outside_block(dp_lines):
    begin, end = find_block(dp_lines)
    return dp_lines[:begin] + [""] * (end - begin + 1) + dp_lines[end + 1:]


def top_level(lines, kind):
    return {item["name"] for item in segment(lines) if item["kind"] == kind}


def function_text(lines, name):
    for item in segment(lines):
        if item["kind"] == "func" and item["name"] == name:
            return "\n".join(lines[item["start"]:item["end"] + 1])
    return None


def dp_provided_defaults(outside):
    """Read actual installer assignments, excluding generated heredoc bodies."""
    items = segment(outside)
    defaults = []
    for name, expected in DP_PROVIDED.items():
        definitions = ["\n".join(outside[item["start"]:item["end"] + 1])
                       for item in items
                       if item["kind"] == "assign" and item["name"] == name]
        if definitions != [expected]:
            raise BlockError(f"DP must assign {name} exactly once at top level: {expected}")
        defaults.append(definitions[0])
    return defaults


def dp_provided_functions(outside):
    definitions = []
    for name, expected in DP_PROVIDED_FUNCTIONS.items():
        actual = function_text(outside, name)
        if actual != expected:
            raise BlockError(f"DP must define {name} with the exact FREE-CAP validation")
        definitions.append(actual)
    return definitions


def pure_default(text):
    """Accept only the block's inert quoted defaults and numeric arrays."""
    if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*=\([0-9.]+(?: [0-9.]+)*\)', text):
        return True
    match = re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*="([^"\n]*)"', text)
    if match is None:
        return False
    value = match.group(1)
    expansion = re.compile(
        r'\$\{[A-Za-z_][A-Za-z0-9_]*(?:(?::-|-)[A-Za-z0-9_./:@,+ -]*)?\}')
    while True:
        reduced = expansion.sub("x", value)
        if reduced == value:
            return re.fullmatch(r"[A-Za-z0-9_./:@,+ -]*", value) is not None
        value = reduced


def closes_early(lines):
    """Whether a multi-line definition's braces close before its last "}".

    segment() ends a function at the next bare "}" in column 0, so a closer
    elsewhere (indented, or after other code on its line) would leave what
    follows it to run when the block is loaded. This reads the lines as bash
    does: quotes carry across lines, "{" and "}" in code nest, and only a
    "<<" in code opens a here-document (a quoted '<<word' opens none).
    """
    stack = []
    depth = 0
    pending = []
    last = len(lines) - 1
    for i, line in enumerate(lines):
        if pending:
            strip, delim = pending[0]
            if (line.lstrip("\t") if strip else line) == delim:
                pending.pop(0)
            continue
        contexts = lex_contexts(line, stack)
        for j, (ch, ctx) in enumerate(zip(line, contexts)):
            if ctx != "N" or ch not in "{}":
                continue
            depth += 1 if ch == "{" else -1
            if depth <= 0 and (i, j) != (last, len(line) - 1):
                return True
        for match in HEREDOC.finditer(line):
            k = match.start()
            before = line[:k]
            if contexts[k:k + 2] != "NN" or before.endswith("<"):
                continue
            if "((" in before and "))" not in before[before.rfind("(("):]:
                continue
            pending.append((match.group(1) == "-", match.group(3)))
    return depth != 0 or bool(pending) or bool(stack)


@functools.lru_cache(maxsize=None)
def bash_parses(text):
    """Whether bash -n accepts text. bash -n reads it and runs nothing."""
    bash = shutil.which("bash")
    if bash is None:
        raise BlockError("bash is required to read block functions")
    return subprocess.run([bash, "-n"], input=text + "\n", capture_output=True, text=True,
                          timeout=30).returncode == 0


def bash_closes_at_last_line(lines):
    """Whether bash itself ends a multi-line definition at its last "}".

    bash -n reads the definition as written, then with the function's own
    "{" and "}" swapped for "if :; then" and "fi". A "}" that bash would take
    as the function's closer before the last line has no "{" left to close in
    the second form, so bash refuses it there, whatever hides it from
    closes_early(). A "fi" that would end the second form early is refused
    by the first.
    """
    header = FUNCTION.fullmatch(lines[0])
    if header is None or lines[-1] != "}":
        return False
    swapped = [lines[0][:header.end() - 1] + "if :; then"] + lines[1:-1] + ["fi"]
    return bash_parses("\n".join(lines)) and bash_parses("\n".join(swapped))


def bash_closes_before_end(lines):
    """Refuse invalid definitions or a syntax-complete prefix before the end."""
    return bash_text_closes_before_end("\n".join(lines))


@functools.lru_cache(maxsize=None)
def bash_text_closes_before_end(text):
    env = dict(os.environ, BASH_ENV="")

    def complete(prefix):
        # Parse only. Disable the non-interactive startup file as well.
        result = subprocess.run(
            ["bash", "-n"], input=(prefix + "\n").encode("utf-8"),
            capture_output=True, timeout=10, env=env)
        return result.returncode == 0 and not result.stderr

    try:
        if not complete(text):
            return True
        # A reserved closing brace starts a word after whitespace or an
        # operator. Bash decides whether each candidate closes the definition.
        return any(complete(text[:i + 1])
                   for i, ch in enumerate(text[:-1])
                   if ch == "}" and (i == 0 or text[i - 1] in " \t\n;&|()<>"))
    except (OSError, subprocess.TimeoutExpired):
        return True


def pure_function_definition(text):
    """Require a definition with no executable or redirecting suffix."""
    lines = text.split("\n")
    if len(lines) > 1:
        # segment() ends a function at the next bare "}" in column 0, so a
        # closer with a suffix ("}; cmd") would hide inside the next item.
        docs = heredoc_spans(lines)
        hidden = [line for i, line in enumerate(lines[1:-1], 1)
                  if i not in docs and (line.startswith("}") or FUNCTION.match(line))]
        return (FUNCTION.fullmatch(lines[0]) is not None and lines[-1] == "}" and not hidden
                and bash_closes_at_last_line(lines)
                and not bash_closes_before_end(lines))
    contexts = lex_contexts(text, [])
    code = "".join(ch if ctx == "N" else " " for ch, ctx in zip(text, contexts))
    match = FUNCTION.match(code)
    if match is None:
        return False
    braces = [i for i, ch in enumerate(code) if ch in "{}"]
    return braces == [match.end() - 1, len(text) - 1]


# ---------------------------------------------------------------------------
# The tombstone (design v17 2.8, slice S6). server/wins_winn3_gateway_install.sh
# is a pointer and `exit 2`, nothing else. tombstone_problems holds it to that
# exact shape: a rename, a restored body or a changed exit status fails here
# and in tools/validate_deployment_scripts.py, which calls this function.
# ---------------------------------------------------------------------------
TOMBSTONE_MARKER = "# TOMBSTONE: the standalone Winn v3 gateway installer, retired by design v17 2.8"
TOMBSTONE_POINTER = "server/wins_data_plane_setup_ONETOUCH.sh"
TOMBSTONE_MAX_LINES = 40
TOMBSTONE_FIRST_CODE_LINE = "printf '%s\\n' \\"
# One quoted message line: single-quoted, so nothing expands, and continued
# with a backslash except for the last, which redirects to stderr.
TOMBSTONE_MESSAGE_LINE = re.compile(r"^  '[^'$`\\]*'( \\| >&2)$")


def tombstone_problems(text):
    """Why `text` is not the tombstone, as a list; empty means it is."""
    problems = []
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if not lines or lines[0] != "#!/usr/bin/env bash":
        problems.append("the tombstone must start with #!/usr/bin/env bash")
    if not any(line.startswith(TOMBSTONE_MARKER) for line in lines):
        problems.append(f"the tombstone lost its marker line {TOMBSTONE_MARKER!r}")
    if len(lines) > TOMBSTONE_MAX_LINES:
        problems.append(f"the tombstone is {len(lines)} lines; it is a pointer and exit 2, at most {TOMBSTONE_MAX_LINES}")
    if "\u2014" in text or "\u2013" in text:
        problems.append("the tombstone carries an em or en dash")
    code = [line for line in lines if line.strip() and not line.lstrip().startswith("#")]
    if not code or code[-1] != "exit 2":
        problems.append("the tombstone must end with exit 2, its only exit")
    if sum(1 for line in code if re.match(r"\s*(exit|return)\b", line)) != 1:
        problems.append("the tombstone must have exactly one exit and no return")
    if not code or code[0] != TOMBSTONE_FIRST_CODE_LINE:
        problems.append(f"the tombstone's first code line must be {TOMBSTONE_FIRST_CODE_LINE!r}")
    message = code[1:-1]
    if not message:
        problems.append("the tombstone prints no message")
    for line in message:
        if not TOMBSTONE_MESSAGE_LINE.match(line):
            problems.append(f"the tombstone has a code line that is not a quoted message line: {line.strip()!r}")
    if message and not message[-1].endswith(" >&2"):
        problems.append("the tombstone must print to stderr (last message line ends with >&2)")
    if any(line.endswith(" >&2") for line in message[:-1]):
        problems.append("the tombstone's message is split by an early >&2")
    if not any(TOMBSTONE_POINTER in line for line in message):
        problems.append(f"the tombstone does not point at {TOMBSTONE_POINTER}")
    return problems


def check(source_text, dp_text):
    """Return a list of failures; empty means the block is equivalent."""
    if hashlib.sha256(source_text.encode("utf-8")).hexdigest() != SOURCE_SHA256:
        return ["source safety at file top requires re-review: standalone source differs from the reviewed snapshot"]
    failures = []
    g_lines = source_text.split("\n")
    dp_lines = dp_text.split("\n")
    try:
        body = block_body(dp_lines)
    except BlockError as exc:
        return [str(exc)]
    outside = outside_block(dp_lines)

    # Allow-list entries must still describe G.
    g_items = segment(g_lines)
    g_keys = {item_key(item) for item in g_items if item["kind"] in ("func", "assign", "stmt")}
    for key in NOT_MOVED:
        if key not in g_keys:
            failures.append(f"allow-list is stale: NOT_MOVED names '{key}', which is not a top-level item of {SOURCE}")
    for old in list(VARIABLE_RENAMES) + list(EXPANSION_RENAMES):
        if old not in g_keys:
            failures.append(f"allow-list is stale: rename of '{old}', which {SOURCE} does not assign at top level")
    for line in EXPANSION_RENAME_LINES:
        if g_lines.count(line) != 1:
            failures.append(f"allow-list is stale: expected exactly one line {line!r} in {SOURCE}")
    for name in FUNCTION_RENAMES:
        if name not in g_keys:
            failures.append(f"allow-list is stale: function rename of '{name}', which {SOURCE} does not define")

    # Equivalence: the block body is G moved under the allow-list, exactly,
    # then edited exactly as allow-list 4 lists.
    expected, stale = apply_post_move_edits(render_moved(source_text))
    failures.extend(stale)
    if body != expected:
        diff = list(difflib.unified_diff(expected, body, "expected (G under the allow-list)",
                                         "actual (block in DP)", lineterm="", n=2))
        shown = "\n".join(diff[:120]) + ("\n..." if len(diff) > 120 else "")
        failures.append("the block differs from the moved text outside the allow-list:\n" + shown)

    # No side effects when DP is loaded: definitions and defaults only.
    seen = {"assign": set(), "func": set()}
    for item in segment(body):
        item_text = "\n".join(body[item["start"]:item["end"] + 1])
        if item["kind"] == "stmt" and item_text not in ALLOWED_STATEMENTS:
            failures.append(f"the block runs a top-level statement when DP is loaded: {item['name'].strip()!r}")
        if item["kind"] == "assign" and not pure_default(item_text):
            failures.append(f"block default '{item['name']}' is not an inert assignment at file top")
        if item["kind"] == "func" and not pure_function_definition(item_text):
            failures.append(f"block function '{item['name']}' is not a standalone definition at file top")
        if item["kind"] in seen:
            if item["name"] in seen[item["kind"]]:
                failures.append(f"duplicate block {item['kind']} '{item['name']}'")
            seen[item["kind"]].add(item["name"])
        if item["kind"] == "assign" and not (item["name"].startswith("WINN3_GATEWAY_")
                                             or item["name"] in KEPT_UNPREFIXED):
            failures.append(f"block variable '{item['name']}' does not carry the WINN3_GATEWAY_ prefix")
    # No duplicates: nothing the block defines or assigns is defined or
    # assigned at DP's top level outside it.
    block_functions = top_level(body, "func")
    for name in sorted(block_functions & top_level(outside, "func")):
        failures.append(f"function '{name}' is defined both in the block and elsewhere at DP top level")
    for name in sorted(top_level(body, "assign") & top_level(outside, "assign")):
        failures.append(f"variable '{name}' is assigned both in the block and elsewhere at DP top level")
    for name in sorted(block_functions & set(FUNCTION_RENAMES)):
        failures.append(f"the block defines '{name}', which would replace DP's own helper")
    try:
        dp_provided_defaults(outside)
        dp_provided_functions(outside)
    except BlockError as exc:
        failures.append(str(exc))
    code_lines = [line for line in body if not line.lstrip().startswith("#")]
    for pattern, why in BLOCK_FORBID:
        hits = [line.strip() for line in code_lines if re.search(pattern, line)]
        if hits:
            failures.append(f"the block contains {hits[0]!r} ({why})")

    # The intentional changes of design 2.2 are in place.
    outside_text = "\n".join(outside)
    for change in INTENTIONAL_CHANGES:
        scope = change["scope"]
        if scope.startswith("pending:"):
            continue
        if scope.startswith("function:"):
            text = function_text(body, scope.split(":", 1)[1])
        elif scope == "dp:file":
            text = outside_text
        else:
            text = function_text(outside, scope.split(":", 1)[1])
        if text is None:
            failures.append(f"{change['id']}: {scope} not found")
            continue
        for needle in change.get("require", []):
            if needle not in text:
                failures.append(f"{change['id']}: {scope} lacks {needle!r} ({change['why']})")
        for needle in change.get("forbid", []):
            if needle in text:
                failures.append(f"{change['id']}: {scope} contains {needle!r} ({change['why']})")
    return failures


def sourceable(dp_text):
    """The block as a file tests can source: DP_PROVIDED, then the body."""
    dp_lines = dp_text.split("\n")
    body = block_body(dp_lines)
    outside = outside_block(dp_lines)
    head = [
        "#!/usr/bin/env bash",
        f"# Extracted by tools/winn3_gateway_block.py from {TARGET} for tests.",
        "# The definitions the block reads from DP's top level come first.",
    ]
    head.extend(dp_provided_defaults(outside))
    head.extend(dp_provided_functions(outside))
    return "\n".join(head + [""] + body) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("mode", choices=("check", "extract", "render"))
    parser.add_argument("--root", default=str(Path(__file__).resolve().parent.parent))
    parser.add_argument("--source", help=f"G, the frozen copy (default: <root>/{SOURCE})")
    parser.add_argument("--dp", help=f"DP (default: <root>/{TARGET})")
    parser.add_argument("--tombstone", help=f"the tombstone (default: <root>/{TOMBSTONE})")
    parser.add_argument("--out", help="extract: the file to write")
    args = parser.parse_args(argv)
    root = Path(args.root)
    source = Path(args.source) if args.source else root / SOURCE
    dp = Path(args.dp) if args.dp else root / TARGET
    if args.mode == "render":
        sys.stdout.write("\n".join(render_block(source.read_text(encoding="utf-8"))) + "\n")
        return 0
    if args.mode == "extract":
        if not args.out:
            parser.error("extract needs --out")
        try:
            text = sourceable(dp.read_text(encoding="utf-8"))
        except BlockError as exc:
            print(f"winn3 gateway block: {exc}", file=sys.stderr)
            return 1
        Path(args.out).write_text(text, encoding="utf-8")
        return 0
    failures = check(source.read_text(encoding="utf-8"), dp.read_text(encoding="utf-8"))
    tombstone = Path(args.tombstone) if args.tombstone else root / TOMBSTONE
    if not tombstone.is_file():
        failures.append(f"the tombstone {TOMBSTONE} is missing")
    else:
        failures.extend(f"tombstone: {problem}" for problem in tombstone_problems(tombstone.read_text(encoding="utf-8")))
    for failure in failures:
        print(f"FAIL: {failure}")
    if failures:
        print(f"winn3 gateway block: {len(failures)} failure(s); {dp} is not {source} moved under the allow-list.")
        return 1
    print(f"winn3 gateway block: equivalent ({dp.name} block == {source.name} under the allow-list; "
          f"{len(NOT_MOVED) + len(NOT_MOVED_AFTER_RENAME)} items not moved, "
          f"{len(VARIABLE_RENAMES) + len(EXPANSION_RENAMES)} variables and {len(FUNCTION_RENAMES)} helpers renamed, "
          f"{len(INTENTIONAL_CHANGES)} intentional changes listed, {len(POST_MOVE_EDITS)} post-move edits applied).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
