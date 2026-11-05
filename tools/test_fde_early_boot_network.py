#!/usr/bin/env python3
"""LUKS-FIX round (2026-10-11, Turn 3 candidate): early-boot network ownership,
GRUB menu and console order, PARTUUID-pinned conversion boots, no duplicate
hooks, a secret-free pasted script, and converter/installer agreement.

Every test here FAILED on deploy/fde_boot_chain.sh v4 (sha256 75ca43bf...) and
on the installer that wrote /etc/initramfs-tools/conf.d/wins-remote-unlock with
DEVICE=<iface> (handoff section 42, Kansas 2026-09-04).

Run: python3 -B -m pytest -q -p no:cacheprovider tools/test_fde_early_boot_network.py
"""

from __future__ import annotations

import base64
import hashlib
import lzma
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CHAIN = ROOT / "deploy" / "fde_boot_chain.sh"
GENERATOR = ROOT / "deploy" / "make_ionos_user_data.sh"
INSTALLER = ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh"
CUSTODY = ROOT / "docs" / "FDE_CUSTODY_CLOSURE.md"

sys.path.insert(0, str(ROOT / "server"))
import fleet_reset_testlib as lib  # noqa: E402

CHAIN_TEXT = CHAIN.read_text(encoding="utf-8")
INSTALLER_TEXT = INSTALLER.read_text(encoding="utf-8")

CANONICAL_DROPBEAR = 'DROPBEAR_OPTIONS="-I 180 -j -k -p 2222 -s -c cryptroot-unlock"\nIFDOWN=none'
CANONICAL_NETWORK = ["IP='dhcp'", "DEVICE=''", "DEVICE6=''", "IP6='off'", "BUSYBOX=y"]
NETWORK_CONF = "/etc/initramfs-tools/conf.d/winn-fde-network"
GRUB_MENU_CFG = "/etc/default/grub.d/99-winn-fde-menu.cfg"
GRUB_ROOT_CFG = "/etc/default/grub.d/98-winn-fde-root.cfg"


def heredoc(text: str, header: str, terminator: str, unquoted: bool = False) -> str:
    start = text.index(header)
    start = text.index("\n", start) + 1
    end = text.index(f"\n{terminator}\n", start)
    body = text[start:end] + "\n"
    if unquoted:
        body = body.replace("\\$", "$").replace("\\\\\n", "\\\n")
    return body


def premount_network_hook() -> str:
    return heredoc(CHAIN_TEXT, 'scripts/init-premount/00-winn-fde-network" <<EOS', "EOS", unquoted=True)


def handoff_hook() -> str:
    return heredoc(CHAIN_TEXT, 'scripts/init-bottom/zz-winn-fde-network-handoff" <<\'EOS\'', "EOS")


def conversion_hook() -> str:
    return heredoc(CHAIN_TEXT, 'cat > "${PREMOUNT_DIR}/zz-winn-fde-v4" <<\'EOS\'', "EOS")


def chroot_block() -> str:
    return heredoc(CHAIN_TEXT, "<<'CHROOTEOS'", "CHROOTEOS")


def arm_region() -> str:
    return CHAIN_TEXT[:CHAIN_TEXT.index('cat > "${PREMOUNT_DIR}/zz-winn-fde-v4" <<\'EOS\'')]


def bash(script: str, **env: str) -> subprocess.CompletedProcess:
    full_env = dict(os.environ)
    full_env.update(env)
    return subprocess.run([lib.BASH, "-c", script], capture_output=True, text=True, env=full_env, timeout=120)


# ---- 1. one early-boot DHCP owner --------------------------------------------

def test_premount_hook_is_an_inert_marker() -> None:
    hook = premount_network_hook()
    for forbidden in ("configure_networking", "ipconfig", "ip link", "ip addr", "ip route", "/scripts/functions"):
        assert forbidden not in hook, forbidden
    assert "this hook configures nothing" in hook
    assert hook.rstrip().endswith("exit 0")
    assert "configure_networking" not in handoff_hook()


def test_only_dhcp_is_qualified_and_device_stays_empty() -> None:
    assert "static, VLAN, bond and bridge networking is not qualified" in CHAIN_TEXT
    assert "INITRAMFS_IP=none" not in CHAIN_TEXT
    assert ":none\"" not in CHAIN_TEXT
    assert f'write_early_boot_network_conf dhcp "" > "${{INITRAMFS_ETC}}/conf.d/winn-fde-network"' in CHAIN_TEXT
    assert 'printf "IP=\'%s\'\\nDEVICE=\'%s\'\\n"' not in CHAIN_TEXT
    fn = lib.function_text(CHAIN_TEXT, "write_early_boot_network_conf")
    out = bash(fn + "write_early_boot_network_conf dhcp ''")
    assert out.returncode == 0, out.stderr
    assert out.stdout.splitlines() == CANONICAL_NETWORK


def test_arm_time_and_chroot_refuse_a_second_dhcp_owner() -> None:
    assert "grep -ls 'configure_networking' \"${INITRAMFS_ETC}\"/scripts/init-premount/*" in CHAIN_TEXT
    assert "second early-boot DHCP owner" in CHAIN_TEXT
    assert "early-boot network defined outside conf.d/winn-fde-network" in CHAIN_TEXT
    assert "(IP|IP6|DEVICE|DEVICE6|BOOTIF|VLAN)=.+" in CHAIN_TEXT
    chroot = chroot_block()
    assert "grep -qx \"IP='dhcp'\" /etc/initramfs-tools/conf.d/winn-fde-network" in chroot
    assert "grep -qx \"DEVICE=''\" /etc/initramfs-tools/conf.d/winn-fde-network" in chroot
    assert "local init-premount script calls configure_networking" in chroot
    assert "early_boot_dhcp_owner=dropbear-init-premount" in chroot
    assert "scripts/init-premount/dropbear" in chroot


def test_pre_flight_names_a_missing_default_route_instead_of_a_silent_exit() -> None:
    # v4 line 116 died with a bare rc=2 under pipefail when "ip route get" had
    # no route (measured in the QEMU rehearsal); v5 names it and traps the rest.
    assert 'ROUTE4="$(ip -4 route get 1.1.1.1 2>/dev/null | head -1 || true)"' in CHAIN_TEXT
    assert 'no IPv4 route towards the internet' in CHAIN_TEXT
    assert "trap 'on_unexpected_error \"$?\" \"${LINENO}\" \"${BASH_COMMAND}\"' ERR" in CHAIN_TEXT
    assert 'WINN_FDE_PREFLIGHT_ONLY' in CHAIN_TEXT and 'PREFLIGHT PASS' in CHAIN_TEXT


def test_pre_flight_refusals_cover_the_qualified_host_shape() -> None:
    arm = arm_region()
    for marker in (
        'is not a GPT disk',
        'does not carry the EFI System Partition type GUID',
        'fstab and the mounted device disagree',
        'disk-backed swap is active',
        'a conversion is already armed or incomplete',
        'unexpected vendor-directory FDE copy',
        'more than one physical interface is present',
        'no IPv4 DHCP evidence',
        'is not available as a module for kernel',
        'root PARTUUID unavailable',
        'already LUKS-backed and the custody completion marker exists',
        'without a completion marker; do not re-arm blind',
        'a reboot is already required',
        'is not the newest installed kernel',
        'BIOS boot is not qualified',
    ):
        assert marker in arm, marker
    assert 'printf \'%s\\n\' "${NET_DRIVER}" >> "${INITRAMFS_ETC}/modules"' in arm


def test_multi_nic_hosts_are_refused_without_an_override() -> None:
    assert "WINN_FDE_ALLOW_MULTI_NIC" not in CHAIN_TEXT
    assert "early DHCP needs exactly one physical NIC carrying the default route" in arm_region()


# ---- 2. the GRUB menu is durable ---------------------------------------------

def test_grub_menu_lives_in_grub_d_after_the_cloudimg_file_and_is_verified() -> None:
    assert f'write_grub_menu_cfg "${{GRUB_CMDLINE_OVERRIDE}}" > {GRUB_MENU_CFG}' in CHAIN_TEXT
    fn = lib.function_text(CHAIN_TEXT, "write_grub_menu_cfg")
    out = bash(fn + "write_grub_menu_cfg")
    assert out.returncode == 0, out.stderr
    lines = [line for line in out.stdout.splitlines() if not line.startswith("#")]
    assert lines == ["GRUB_TIMEOUT=5", "GRUB_TIMEOUT_STYLE=menu", "GRUB_RECORDFAIL_TIMEOUT=5"]
    out = bash(fn + "write_grub_menu_cfg 'console=ttyS0 console=tty1'")
    assert 'GRUB_CMDLINE_LINUX_DEFAULT="console=ttyS0 console=tty1"' in out.stdout
    assert "verify_grub_menu_cfg /boot/grub/grub.cfg" in CHAIN_TEXT
    chroot = chroot_block()
    assert f"grep -qx 'GRUB_TIMEOUT=5' {GRUB_MENU_CFG}" in chroot
    assert f"grep -qx 'GRUB_RECORDFAIL_TIMEOUT=5' {GRUB_MENU_CFG}" in chroot
    assert "grep -Eq '^[[:space:]]*set timeout=5$' /boot/grub/grub.cfg" in chroot
    assert "/etc/default/grub.d/60-winn-fde-menu.cfg" not in CHAIN_TEXT


@pytest.mark.parametrize(
    ("cfg", "ok"),
    (
        ("if [ x ]; then\n  set timeout_style=menu\n  set timeout=5\nfi\nset timeout=5\n", True),
        ("set timeout_style=hidden\nset timeout=5\n", False),
        ("set timeout=-1\nset timeout=5\n", False),
        ("set timeout=0\nset timeout=5\n", False),
        ("set timeout=30\n", False),
    ),
)
def test_verify_grub_menu_cfg_accepts_only_a_five_second_menu(tmp_path: Path, cfg: str, ok: bool) -> None:
    grub_cfg = tmp_path / "grub.cfg"
    grub_cfg.write_text(cfg)
    fn = lib.function_text(CHAIN_TEXT, "verify_grub_menu_cfg")
    out = bash(fn + f"verify_grub_menu_cfg {grub_cfg}")
    assert (out.returncode == 0) is ok, out.stderr


# ---- 3. the conversion boots are pinned to the GPT PARTUUID ------------------

def test_conversion_boots_pin_root_by_partuuid_and_finalization_unpins() -> None:
    arm = arm_region()
    assert 'ROOT_PARTUUID="$(lsblk -dnro PARTUUID "${ROOT_DEV}" 2>/dev/null || true)"' in arm
    assert 'printf "ROOT_PARTUUID=\'%s\'\\nBOOT_MODE=\'uefi\'\\n" "${ROOT_PARTUUID}" > "${INITRAMFS_ETC}/conf.d/winn-fde-layout"' in arm
    assert "'GRUB_DISABLE_LINUX_UUID=true' \\\n  'GRUB_DISABLE_LINUX_PARTUUID=false' > " + GRUB_ROOT_CFG in arm
    assert 'root=PARTUUID=${ROOT_PARTUUID}([[:space:]]|$)" /boot/grub/grub.cfg' in CHAIN_TEXT
    hook = conversion_hook()
    assert '. /conf/conf.d/winn-fde-layout' in hook
    assert 'ROOTDEV="/dev/disk/by-partuuid/${ROOT_PARTUUID}"' in hook
    assert 'uefi) [ -d /sys/firmware/efi ] || skip "firmware changed from UEFI since arming";;' in hook
    chroot = chroot_block()
    assert "rm -f /etc/initramfs-tools/conf.d/winn-fde-layout" in chroot
    assert f"rm -f {GRUB_ROOT_CFG}" in chroot
    assert "grub.cfg still pins root=PARTUUID after finalization" in chroot
    assert "conf/conf.d/winn-fde-layout" in chroot.split("Inspect every retained initramfs", 1)[1]


def test_shrink_continues_into_the_encryption_in_the_same_boot() -> None:
    hook = conversion_hook()
    assert 'log "shrink OK; continuing the offline conversion in this boot"' in hook
    assert 'mount -t ext4 "${ROOTDEV}" /winnmnt 2>/dev/null || skip "cannot remount the shrunken root"' in hook
    assert 'shrink OK; next boot converts' not in hook
    cfg = heredoc(CHAIN_TEXT, "cat > /etc/cloud/cloud.cfg.d/99-winn-fde-no-grow.cfg <<'CGEOF'", "CGEOF")
    assert "resize_root:" not in cfg and "resize_fs:" not in cfg
    assert "mode: 'off'" in cfg and "resize_rootfs: false" in cfg


# ---- 3b. Turn 3 amendments: tested conf-hook, legacy backup, /etc/default/grub, console order ----

def test_conversion_initramfs_keeps_the_conf_hook_the_end_to_end_runs_booted() -> None:
    assert "CRYPTSETUP=y" not in CHAIN_TEXT
    assert CHAIN_TEXT.count("printf 'UMASK=0077\\n' > /etc/cryptsetup-initramfs/conf-hook") == 2


def test_legacy_installer_file_is_backed_up_outside_conf_d_before_the_sweep() -> None:
    arm = arm_region()
    backup = arm.index('cp -a -- "${LEGACY_UNLOCK_CONF}" "/var/backups/winn-fde/wins-remote-unlock.')
    sweep = arm.index('for stale in "${INITRAMFS_ETC}"/scripts/init-premount/*winn-fde*')
    assert backup < sweep
    assert "install -d -m 700 /var/backups/winn-fde" in arm
    # mkinitramfs sources every conf.d file whose name is alphanumeric/dot/dash/underscore (not *.dpkg-*), so
    # a backup named wins-remote-unlock.<anything> left in conf.d would be a second early-boot network owner
    assert "/etc/initramfs-tools/conf.d/wins-remote-unlock.pre" not in CHAIN_TEXT


def test_main_grub_file_is_kept_consistent_with_the_drop_in() -> None:
    assert "ensure_main_grub_menu /etc/default/grub" in arm_region()
    assert "cp -a /etc/default/grub /etc/default/grub.pre-winn-fde" in arm_region()
    fn = lib.function_text(CHAIN_TEXT, "ensure_main_grub_menu")
    sb = lib.Sandbox()
    try:
        stock = (
            "GRUB_DEFAULT=0\nGRUB_TIMEOUT_STYLE=hidden\nGRUB_TIMEOUT=0\nGRUB_HIDDEN_TIMEOUT=2\n"
            "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet splash\"\n"
        )
        target = sb.path("grub")
        target.write_text(stock)
        out = sb.run(fn + f"ensure_main_grub_menu {target}")
        assert out.returncode == 0, out.stderr
        text = target.read_text()
        assert text.splitlines() == [
            "GRUB_DEFAULT=0", "GRUB_TIMEOUT_STYLE=menu", "GRUB_TIMEOUT=5",
            "# disabled by winn-fde: GRUB_HIDDEN_TIMEOUT=2", 'GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"',
        ]
        out = sb.run(fn + f"ensure_main_grub_menu {target}")
        assert out.returncode == 0 and target.read_text() == text  # idempotent
        bare = sb.path("grub_bare")
        bare.write_text("GRUB_DEFAULT=0\n")
        out = sb.run(fn + f"ensure_main_grub_menu {bare}")
        assert out.returncode == 0, out.stderr
        assert bare.read_text() == "GRUB_DEFAULT=0\nGRUB_TIMEOUT_STYLE=menu\nGRUB_TIMEOUT=5\n"
    finally:
        sb.cleanup()


STOCK_LINES = (
    "\tlinux\t/vmlinuz-6.8.0-142-generic root=PARTUUID=aaaaaaaa-0000-0000-0000-000000000001 ro  console=tty1 console=ttyS0\n"
    "\tlinux\t/vmlinuz-6.8.0-142-generic root=PARTUUID=aaaaaaaa-0000-0000-0000-000000000001 ro recovery nomodeset dis_ucode_ldr \n"
)


@pytest.mark.parametrize(
    ("cfg", "ok"),
    (
        # the fix: console=tty1 appended last; the recovery entry carries no console= token and is skipped
        (STOCK_LINES.replace("console=ttyS0\n", "console=ttyS0 console=tty1\n"), True),
        # the unmodified stock line: console=tty1 is already present (first), but the serial token is last
        (STOCK_LINES, False),
        # the override was lost: nothing qualifies
        ("\tlinux\t/vmlinuz-1 root=PARTUUID=x ro quiet\n", False),
        # one kernel line fixed, another still ends with the serial port
        (STOCK_LINES.replace("console=ttyS0\n", "console=ttyS0 console=tty1\n") + "\tlinux\t/vmlinuz-0 root=PARTUUID=x ro console=tty1 console=ttyS0\n", False),
    ),
)
def test_console_order_is_verified_by_the_last_token_not_by_presence(tmp_path: Path, cfg: str, ok: bool) -> None:
    grub_cfg = tmp_path / "grub.cfg"
    grub_cfg.write_text(cfg)
    fn = lib.function_text(CHAIN_TEXT, "verify_console_last")
    out = bash(fn + f"verify_console_last {grub_cfg} console=tty1")
    assert (out.returncode == 0) is ok, out.stderr
    # the retired presence-only test passed on the unmodified stock line
    presence_only = subprocess.run(
        [lib.BASH, "-c", f"grep -Eq '^[[:space:]]*linux[^[:space:]]*[[:space:]].*(^|[[:space:]])console=tty1([[:space:]]|$)' {grub_cfg}"],
        capture_output=True,
    ).returncode == 0
    if cfg == STOCK_LINES:
        assert presence_only


def test_arm_time_and_chroot_both_verify_the_console_order() -> None:
    assert "verify_console_last /boot/grub/grub.cfg console=tty1" in CHAIN_TEXT
    chroot = chroot_block()
    assert "if grep -q '^GRUB_CMDLINE_LINUX_DEFAULT=' /etc/default/grub.d/99-winn-fde-menu.cfg; then" in chroot
    assert 'if (last != "") { seen = 1; if (last != "console=tty1") bad = 1 }' in chroot
    assert "final grub.cfg lost the VGA-last console order" in chroot


# ---- 4. no duplicate hooks ---------------------------------------------------

def test_stale_hook_copies_are_swept_and_the_final_listing_holds_one_hook() -> None:
    for stale in (
        '"${INITRAMFS_ETC}"/scripts/init-premount/*winn-fde*',
        '"${INITRAMFS_ETC}"/scripts/init-premount/*wins-remote-unlock*',
        '"${INITRAMFS_ETC}"/scripts/init-bottom/*winn-fde*',
        '"${INITRAMFS_ETC}"/scripts/local-premount/*winn-fde*',
        '"${INITRAMFS_ETC}"/hooks/*winn-fde*',
        '"${INITRAMFS_ETC}"/conf.d/wins-remote-unlock',
    ):
        assert stale in CHAIN_TEXT
    chroot = chroot_block()
    assert "grep -Ec '^scripts/init-premount/.*winn-fde'" in chroot
    assert 'expected exactly one winn-fde init-premount hook' in chroot
    assert "scripts/init-premount/zz-winn-fde-network$|conf/conf.d/wins-remote-unlock$" in chroot
    # arm-time verification applies the same count to every built image
    assert "one-winn-fde-init-premount-hook" in CHAIN_TEXT
    assert "duplicate-early-boot-network-file-present" in CHAIN_TEXT
    assert "update-initramfs -u -k all >>/var/log/fde-chain.log" in CHAIN_TEXT
    assert 'verify_initrd "${BUILD_INITRD}" || die' in CHAIN_TEXT


# ---- 5. the pasted script holds no secret ------------------------------------

@pytest.fixture(scope="module")
def user_data() -> str:
    completed = subprocess.run([lib.BASH, str(GENERATOR)], capture_output=True, text=True, check=False)
    assert completed.returncode == 0, completed.stderr
    return completed.stdout


def test_pasted_script_embeds_the_exact_converter_and_no_secret(user_data: str) -> None:
    assert user_data.startswith("#!/bin/bash\n")
    start = user_data.index("<<'BLOB'")
    start = user_data.index("\n", start) + 1
    end = user_data.index("\nBLOB\n", start)
    decoded = lzma.decompress(base64.b64decode(user_data[start:end]))
    assert decoded == CHAIN.read_bytes()
    sha = hashlib.sha256(decoded).hexdigest()
    assert user_data.count(sha) == 3  # header, stage check, helper
    assert "WINN_FDE_PREFLIGHT_ONLY=1" in user_data
    for forbidden in ("LUKS_PASSPHRASE", "PASSPHRASE=", "BEGIN OPENSSH PRIVATE KEY", "BEGIN PRIVATE KEY",
                      "AGE-SECRET-KEY", "ssh-ed25519 AAAA", "ssh-rsa AAAA", "TOKEN=", "SECRET="):
        assert forbidden not in user_data, forbidden
    body = user_data.replace(user_data[start:end], "")
    assert "luksAddKey" not in body
    assert "bash \"${CONVERTER}\"" not in body.split("<<'HELPER'")[0]
    assert "exec bash \"${CONVERTER}\"" in body.split("<<'HELPER'")[1]
    assert len(user_data.encode()) < 32768


def test_pasted_script_is_deterministic_and_parses(user_data: str) -> None:
    again = subprocess.run([lib.BASH, str(GENERATOR)], capture_output=True, text=True, check=False)
    assert again.stdout == user_data
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as handle:
        handle.write(user_data)
        path = handle.name
    try:
        assert subprocess.run([lib.BASH, "-n", path], capture_output=True).returncode == 0
        helper_start = user_data.index("<<'HELPER'")
        helper_start = user_data.index("\n", helper_start) + 1
        helper = user_data[helper_start:user_data.index("\nHELPER\n", helper_start)] + "\n"
        assert subprocess.run([lib.BASH, "-n"], input=helper, capture_output=True, text=True).returncode == 0
        assert "[[ ! -t 0 ]]" in helper
        assert "head -c 4098" in helper
    finally:
        os.unlink(path)


def _stage_sandbox(tmp_path: Path, user_data: str) -> tuple[Path, Path, dict]:
    sandbox = tmp_path / "sb"
    for sub in ("bin", "root", "var/lib", "var/log", "usr/local/sbin"):
        (sandbox / sub).mkdir(parents=True)
    shims = {
        "id": "#!/bin/sh\necho 0\n",
        "findmnt": "#!/bin/sh\necho /dev/vda1\n",
        "lsblk": "#!/bin/sh\necho part\n",
    }
    if shutil.which("sha256sum") is None:
        shims["sha256sum"] = '#!/bin/sh\nexec shasum -a 256 "$@"\n'
    for name, body in shims.items():
        shim = sandbox / "bin" / name
        shim.write_text(body)
        shim.chmod(0o755)
    text = user_data
    for prefix in ("/root/", "/usr/local/sbin", "/var/lib", "/var/log/"):
        text = text.replace(prefix, f"{sandbox}{prefix}")
    script = sandbox / "userdata.sh"
    script.write_text(text)
    env = {"PATH": f"{sandbox / 'bin'}:{os.environ['PATH']}"}
    return sandbox, script, env


def test_pasted_script_stages_without_arming(tmp_path: Path, user_data: str) -> None:
    sandbox, script, env = _stage_sandbox(tmp_path, user_data)
    first = subprocess.run([lib.BASH, str(script)], capture_output=True, text=True, env=env, timeout=120)
    assert first.returncode == 0, (sandbox / "var/log/winn-fde-userdata.log").read_text()
    staged = sandbox / "root/fde_boot_chain.sh"
    assert staged.read_bytes() == CHAIN.read_bytes()
    assert stat.S_IMODE(staged.stat().st_mode) == 0o700
    helper = sandbox / "usr/local/sbin/winn-fde-arm"
    assert helper.exists() and stat.S_IMODE(helper.stat().st_mode) == 0o700
    state = (sandbox / "var/lib/winn-fde-staged").read_text()
    assert f"converter_sha256={hashlib.sha256(CHAIN.read_bytes()).hexdigest()}" in state
    assert not (sandbox / "root/.winn-fde-pass").exists()
    assert not (sandbox / "root/.winn-fde-conversion-key").exists()
    second = subprocess.run([lib.BASH, str(script)], capture_output=True, text=True, env=env, timeout=120)
    assert second.returncode == 0
    assert "already staged with the expected digest" in (sandbox / "var/log/winn-fde-userdata.log").read_text()


def test_pasted_script_refuses_to_overwrite_a_different_converter(tmp_path: Path, user_data: str) -> None:
    sandbox, script, env = _stage_sandbox(tmp_path, user_data)
    staged = sandbox / "root/fde_boot_chain.sh"
    staged.write_text("#!/bin/bash\necho not the pinned converter\n")
    staged.chmod(0o700)
    run = subprocess.run([lib.BASH, str(script)], capture_output=True, text=True, env=env, timeout=120)
    assert run.returncode == 1
    assert staged.read_text() == "#!/bin/bash\necho not the pinned converter\n"
    assert "refusing to overwrite" in (sandbox / "var/lib/winn-fde-stage-failed").read_text()
    assert not (sandbox / "usr/local/sbin/winn-fde-arm").exists()


def _helper_text(user_data: str) -> str:
    start = user_data.index("<<'HELPER'")
    start = user_data.index("\n", start) + 1
    return user_data[start:user_data.index("\nHELPER\n", start)] + "\n"


def _run_helper(tmp_path: Path, user_data: str, stdin: bytes, preflight_rc: int, *args: str):
    sbx = lib.Sandbox()
    try:
        root = sbx.path("root")
        root.mkdir()
        calls = sbx.path("helper_calls.log")
        stub = (
            "#!/bin/bash\n"
            f'pass=absent; test -e "{root}/.winn-fde-pass" && pass=present\n'
            f'echo "preflight=${{WINN_FDE_PREFLIGHT_ONLY:-0}} pass=${{pass}}" >> "{calls}"\n'
            f'if [ "${{WINN_FDE_PREFLIGHT_ONLY:-0}}" = 1 ]; then exit {preflight_rc}; fi\n'
            "exit 0\n"
        )
        converter = root / "fde_boot_chain.sh"
        converter.write_text(stub)
        digest = hashlib.sha256(stub.encode()).hexdigest()
        text = _helper_text(user_data)
        text = re.sub(r"EXPECTED='[0-9a-f]{64}'", f"EXPECTED='{digest}'", text)
        text = text.replace('[[ "${EUID}" -eq 0 ]] || die "run as root"\n', "")
        text = text.replace("/root/", f"{root}/")
        helper = sbx.path("winn-fde-arm")
        helper.write_text(text)
        done = subprocess.run([lib.BASH, str(helper), *args], input=stdin, capture_output=True, env=sbx.env(), timeout=60)
        pass_file = root / ".winn-fde-pass"
        return (
            done.returncode,
            done.stderr.decode(),
            pass_file.read_bytes() if pass_file.exists() else None,
            calls.read_text().splitlines() if calls.exists() else [],
        )
    finally:
        sbx.cleanup()


def test_helper_runs_the_preflight_before_it_writes_the_passphrase(tmp_path: Path, user_data: str) -> None:
    secret = b"correct-horse-battery-staple-ok-0123456789"
    rc, err, written, calls = _run_helper(tmp_path, user_data, secret + b"\n", 0)
    assert rc == 0, err
    assert written == secret  # one trailing newline forgiven, nothing else changed
    assert calls == ["preflight=1 pass=absent", "preflight=0 pass=present"]
    rc, err, written, calls = _run_helper(tmp_path, user_data, secret + b"\n", 1)
    assert rc == 1 and "no passphrase was written" in err
    assert written is None and calls == ["preflight=1 pass=absent"]
    rc, err, written, calls = _run_helper(tmp_path, user_data, b"too-short", 0)
    assert rc == 1 and written is None and "32 to 4096 bytes" in err
    rc, err, written, calls = _run_helper(tmp_path, user_data, b"", 3, "--check")
    assert rc == 3 and written is None and calls == ["preflight=1 pass=absent"]


# ---- 6. the installer and the converter agree --------------------------------

def test_installer_and_converter_share_the_early_boot_functions_byte_for_byte() -> None:
    assert lib.function_text(CHAIN_TEXT, "write_early_boot_network_conf") == lib.function_text(
        INSTALLER_TEXT, "write_early_boot_network_conf")
    # the installer never manages the GRUB menu: only the converter does (three of four seats)
    assert "write_grub_menu_cfg" not in INSTALLER_TEXT
    assert "verify_grub_menu_cfg" not in INSTALLER_TEXT


def test_installer_and_converter_write_the_same_dropbear_configuration() -> None:
    chroot = chroot_block()
    assert "printf 'DROPBEAR_OPTIONS=\"-I 180 -j -k -p 2222 -s -c cryptroot-unlock\"\\nIFDOWN=none\\n' > /etc/dropbear/initramfs/dropbear.conf" in chroot
    assert "grep -q '^DROPBEAR_OPTIONS=\"-I 180 -j -k -p 2222 -s -c cryptroot-unlock\"$' /etc/dropbear/initramfs/dropbear.conf" in chroot
    assert "grep -qx 'IFDOWN=none' /etc/dropbear/initramfs/dropbear.conf" in chroot
    installer_conf = lib.heredoc(INSTALLER_TEXT, 'cat > "${stage}/dropbear.conf" <<EOF', "EOF").strip()
    assert installer_conf.replace("${unlock_port}", "2222") == CANONICAL_DROPBEAR
    # the conversion-phase configuration keeps a shell and the same teardown policy
    assert "printf 'DROPBEAR_OPTIONS=\"-I 180 -j -k -p 2222 -s\"\\nIFDOWN=none\\n' > /etc/dropbear/initramfs/dropbear.conf" in arm_region()


def test_installer_uses_the_boot_chain_network_file_and_removes_the_legacy_one() -> None:
    fn = lib.function_text(INSTALLER_TEXT, "configure_luks_root_policy")
    assert 'local unlock_conf="${WINS_INITRAMFS_UNLOCK_CONF:-${initramfs_etc}/conf.d/winn-fde-network}"' in fn
    assert 'local legacy_unlock_conf="${unlock_conf%/*}/wins-remote-unlock"' in fn
    assert 'write_early_boot_network_conf dhcp "" > "${stage}/${unlock_conf##*/}"' in fn
    assert 'echo "IP=:::::${initramfs_device}:dhcp"' not in fn
    assert "verify_luks_unlock_initramfs || exit 1" in fn
    assert "second early-boot DHCP owner" in fn
    assert "pins an early-boot DEVICE" in fn
    assert "overrides are refused on this host" in fn


class InstallerSandbox:
    """configure_luks_root_policy on a sandbox root with faked host effects."""

    def __init__(self, tmp_path: Path) -> None:
        self.sb = lib.Sandbox()
        self.root = tmp_path / "r"
        for sub in ("etc/initramfs-tools/conf.d", "etc/initramfs-tools/scripts/init-premount",
                    "etc/dropbear/initramfs", "etc/default/grub.d", "boot/grub", "lib/modules/6.8.0-1-generic",
                    "root/.ssh", "var/backups"):
            (self.root / sub).mkdir(parents=True)
        (self.root / "root/.ssh/authorized_keys").write_text("ssh-ed25519 AAAAC3Nzatest operator\n")
        (self.root / "etc/initramfs-tools/initramfs.conf").write_text("MODULES=most\nBUSYBOX=auto\nDEVICE=\nNFSROOT=auto\n")
        (self.root / "boot/grub/grub.cfg").write_text("set timeout_style=menu\nset timeout=5\n")
        (self.root / "boot/initrd.img-6.8.0-1-generic").write_bytes(b"initrd")
        self.listing = self.root / "listing.txt"
        self.listing.write_text("\n".join([
            "scripts/local-top/cryptroot", "conf/conf.d/winn-fde-network", "usr/sbin/dropbear",
            "usr/sbin/cryptsetup", "scripts/init-premount/00-winn-fde-network",
            "scripts/init-premount/dropbear", "usr/sbin/ip",
            "scripts/init-bottom/zz-winn-fde-network-handoff",
        ]) + "\n")
        shims = {
            "lsinitramfs": f'#!/bin/sh\ncat "{self.listing}"\n',
            "update-initramfs": '#!/bin/sh\nprintf "update-initramfs %s\\n" "$*" >> "$FLEET_CALLS"\n',
            "update-grub": '#!/bin/sh\nprintf "update-grub\\n" >> "$FLEET_CALLS"\n',
            "ip": '#!/bin/sh\necho "default via 10.0.0.1 dev ens6 proto dhcp"\n',
            "lsblk": '#!/bin/sh\necho crypt\n',
            "findmnt": '#!/bin/sh\necho /dev/mapper/root_crypt\n',
            "readlink": '#!/bin/sh\necho /dev/dm-0\n',
            "swapon": '#!/bin/sh\nexit 0\n',
            "cmp": '#!/bin/sh\nexec /usr/bin/cmp "$@"\n',
        }
        for name, body in shims.items():
            shim = self.sb.bin / name
            shim.write_text(body)
            shim.chmod(0o755)

    def run(self, **env: str) -> subprocess.CompletedProcess:
        fns = "".join(lib.function_text(INSTALLER_TEXT, n) for n in (
            "write_early_boot_network_conf",
            "verify_luks_unlock_initramfs", "root_backed_by_luks", "unencrypted_swap_devices",
            "collect_luks_unlock_authorized_keys", "configure_luks_root_policy"))
        script = (lib.LOG_STUBS + "set -Eeuo pipefail\n"
                  "APT_GET=(apt-get)\napt_retry() { :; }\n"
                  "REQUIRE_LUKS_ROOT_DEFAULT=0\nLUKS_REMOTE_UNLOCK_DEFAULT=1\nLUKS_UNLOCK_SSH_PORT_DEFAULT=2222\n"
                  "LUKS_INITRAMFS_IP_DEFAULT=dhcp\nLUKS_INITRAMFS_DEVICE_DEFAULT=auto\n"
                  "CONTROL_DISK_ENCRYPTION_EFFECTIVE=luks\n"
                  + fns + "configure_luks_root_policy\n")
        extra = {
            "WINS_DROPBEAR_INITRAMFS_DIR": str(self.root / "etc/dropbear/initramfs"),
            "WINS_INITRAMFS_TOOLS_DIR": str(self.root / "etc/initramfs-tools"),
            "WINS_LUKS_UNLOCK_BACKUP_DIR": str(self.root / "var/backups/winsvpn-luks-unlock"),
            "WINS_ROOT_SSH_DIR": str(self.root / "root/.ssh"),
            "WINS_BOOT_DIR": str(self.root / "boot"),
            "WINS_MODULES_DIR": str(self.root / "lib/modules"),
        }
        extra.update(env)
        return self.sb.run(script, **extra)

    def cleanup(self) -> None:
        self.sb.cleanup()


@pytest.fixture
def installer_sandbox(tmp_path: Path):
    sandbox = InstallerSandbox(tmp_path)
    yield sandbox
    sandbox.cleanup()


def test_installer_writes_dhcp_with_an_empty_device_and_leaves_grub_to_the_converter(installer_sandbox: InstallerSandbox) -> None:
    sb = installer_sandbox
    completed = sb.run()
    assert completed.returncode == 0, completed.stderr + completed.stdout
    conf = (sb.root / "etc/initramfs-tools/conf.d/winn-fde-network").read_text()
    assert conf.splitlines() == CANONICAL_NETWORK
    assert not (sb.root / "etc/initramfs-tools/conf.d/wins-remote-unlock").exists()
    assert (sb.root / "etc/dropbear/initramfs/dropbear.conf").read_text() == CANONICAL_DROPBEAR + "\n"
    assert not (sb.root / "etc/default/grub.d/99-winn-fde-menu.cfg").exists()
    calls = sb.sb.logged()
    assert "update-grub" not in calls
    assert "update-initramfs -u -k all" in calls
    assert "LUKS unlock verified in 1 bootable initramfs" in completed.stdout


def test_installer_keeps_a_converted_hosts_file_and_removes_the_legacy_one(installer_sandbox: InstallerSandbox) -> None:
    sb = installer_sandbox
    chain_file = "\n".join(CANONICAL_NETWORK) + "\n"
    (sb.root / "etc/initramfs-tools/conf.d/winn-fde-network").write_text(chain_file)
    (sb.root / "etc/initramfs-tools/conf.d/wins-remote-unlock").write_text("BUSYBOX=y\nDEVICE=ens6\nIP=:::::ens6:dhcp\n")
    (sb.root / "etc/initramfs-tools/scripts/init-premount/zz-winn-fde-network").write_text("#!/bin/sh\nexit 0\n")
    (sb.root / "etc/dropbear/initramfs/dropbear.conf").write_text(CANONICAL_DROPBEAR + "\n")
    (sb.root / "etc/dropbear/initramfs/authorized_keys").write_text("ssh-ed25519 AAAAC3Nzatest operator\n")
    completed = sb.run()
    assert completed.returncode == 0, completed.stderr + completed.stdout
    assert (sb.root / "etc/initramfs-tools/conf.d/winn-fde-network").read_text() == chain_file
    assert not (sb.root / "etc/initramfs-tools/conf.d/wins-remote-unlock").exists()
    assert not (sb.root / "etc/initramfs-tools/scripts/init-premount/zz-winn-fde-network").exists()
    assert "written by the boot chain" in completed.stdout
    assert "Removed" in completed.stdout
    backups = list((sb.root / "var/backups/winsvpn-luks-unlock").rglob("wins-remote-unlock"))
    assert len(backups) == 1
    assert "update-initramfs -u -k all" in sb.sb.logged()
    # a second run finds everything in place and does not rebuild
    completed = sb.run()
    assert completed.returncode == 0, completed.stderr + completed.stdout
    assert sb.sb.logged().count("update-initramfs -u -k all") == 1
    assert "initramfs not rebuilt" in completed.stdout


def test_installer_keeps_an_existing_empty_device_file_with_other_text(installer_sandbox: InstallerSandbox) -> None:
    sb = installer_sandbox
    legacy_quoting = "# repaired by hand on 2026-09-04\nIP=dhcp\nDEVICE=\n"
    (sb.root / "etc/initramfs-tools/conf.d/winn-fde-network").write_text(legacy_quoting)
    completed = sb.run()
    assert completed.returncode == 0, completed.stderr + completed.stdout
    assert (sb.root / "etc/initramfs-tools/conf.d/winn-fde-network").read_text() == legacy_quoting
    assert "not the boot chain's exact text" in completed.stdout


def test_installer_refuses_a_pinned_device_in_the_boot_chain_file(installer_sandbox: InstallerSandbox) -> None:
    sb = installer_sandbox
    (sb.root / "etc/initramfs-tools/conf.d/winn-fde-network").write_text("IP='dhcp'\nDEVICE='ens6'\n")
    completed = sb.run()
    assert completed.returncode == 1
    assert "pins an early-boot DEVICE" in completed.stderr
    assert "update-initramfs -u -k all" not in sb.sb.logged()
    assert (sb.root / "etc/initramfs-tools/conf.d/winn-fde-network").read_text() == "IP='dhcp'\nDEVICE='ens6'\n"


def test_installer_refuses_explicit_overrides_on_a_converted_host(installer_sandbox: InstallerSandbox) -> None:
    sb = installer_sandbox
    (sb.root / "etc/initramfs-tools/conf.d/winn-fde-network").write_text("\n".join(CANONICAL_NETWORK) + "\n")
    completed = sb.run(LUKS_INITRAMFS_IP="10.0.0.5::10.0.0.1:255.255.255.0::ens6:none")
    assert completed.returncode == 1
    assert "overrides are refused on this host" in completed.stderr
    assert "update-initramfs -u -k all" not in sb.sb.logged()


def test_installer_refuses_a_second_dhcp_owner_before_rebuilding(installer_sandbox: InstallerSandbox) -> None:
    sb = installer_sandbox
    foreign = sb.root / "etc/initramfs-tools/scripts/init-premount/00-winn-fde-network"
    foreign.write_text("#!/bin/sh\n. /scripts/functions\nconfigure_networking\n")
    completed = sb.run()
    assert completed.returncode == 1
    assert "second early-boot DHCP owner" in completed.stderr
    assert "update-initramfs -u -k all" not in sb.sb.logged()


def test_installer_refuses_an_explicit_device_with_dhcp(installer_sandbox: InstallerSandbox) -> None:
    completed = installer_sandbox.run(LUKS_INITRAMFS_IP="dhcp", LUKS_INITRAMFS_DEVICE="ens6")
    assert completed.returncode == 1
    assert "EMPTY early-boot DEVICE" in completed.stderr


@pytest.mark.parametrize("definition", ("IP6=dhcp", "DEVICE6=ens6", "BOOTIF=01-00-11-22-33-44-55", "VLAN=7:ens6"))
@pytest.mark.parametrize("location", ("initramfs.conf", "conf.d/foreign-network"))
def test_installer_refuses_the_same_foreign_network_variables_as_the_converter(installer_sandbox: InstallerSandbox,
                                                                             definition: str, location: str) -> None:
    sb = installer_sandbox
    foreign = sb.root / "etc/initramfs-tools" / location
    with foreign.open("a") as stream:
        stream.write(definition + "\n")
    completed = sb.run()
    assert completed.returncode == 1
    assert "update-initramfs -u -k all" not in sb.sb.logged()


def test_installer_stops_when_the_rebuilt_initramfs_lacks_the_unlock_path(installer_sandbox: InstallerSandbox) -> None:
    sb = installer_sandbox
    sb.listing.write_text("scripts/local-top/cryptroot\nusr/sbin/dropbear\n")
    completed = sb.run()
    assert completed.returncode == 1
    assert "lacks scripts/init-premount/dropbear" in completed.stderr
    assert "update-initramfs -u -k all" in sb.sb.logged()


@pytest.mark.parametrize("asset", (
    "scripts/init-premount/dropbear", "usr/sbin/ip",
    "scripts/init-bottom/zz-winn-fde-network-handoff",
))
@pytest.mark.parametrize("unchanged", (False, True))
def test_installer_refuses_missing_network_boot_assets(installer_sandbox: InstallerSandbox,
                                                      asset: str, unchanged: bool) -> None:
    sb = installer_sandbox
    if unchanged:
        assert sb.run().returncode == 0
    sb.listing.write_text("\n".join(line for line in sb.listing.read_text().splitlines() if line != asset) + "\n")
    completed = sb.run()
    assert completed.returncode == 1
    assert "LUKS unlock verified" not in completed.stdout
    if unchanged:
        assert sb.sb.logged().count("update-initramfs -u -k all") == 1


@pytest.mark.parametrize("residue", (
    "conf/winn-fde-conversion-key", "scripts/local-premount/zz-winn-fde-v4",
    "hooks/winn-fde-tools", "conf/conf.d/winn-fde-layout",
))
@pytest.mark.parametrize("retained_only", (False, True))
def test_installer_refuses_conversion_residue_in_every_retained_image(installer_sandbox: InstallerSandbox,
                                                                     residue: str, retained_only: bool) -> None:
    sb = installer_sandbox
    assert sb.run().returncode == 0
    if retained_only:
        (sb.root / "boot/initrd.img-retired-kernel.bak").write_bytes(b"retained image")
        shim = sb.sb.bin / "lsinitramfs"
        shim.write_text(f'#!/bin/sh\ncase "$1" in *.bak) printf "%s\\n" "{residue}";; *) cat "{sb.listing}";; esac\n')
    else:
        sb.listing.write_text(sb.listing.read_text() + residue + "\n")
    completed = sb.run()
    assert completed.returncode == 1
    assert "retains conversion code or credentials" in completed.stderr
    assert "LUKS unlock verified" not in completed.stdout
    assert sb.sb.logged().count("update-initramfs -u -k all") == 1


def test_installer_stops_on_a_duplicate_network_file_in_the_initramfs(installer_sandbox: InstallerSandbox) -> None:
    sb = installer_sandbox
    sb.listing.write_text(sb.listing.read_text() + "conf/conf.d/wins-remote-unlock\n")
    completed = sb.run()
    assert completed.returncode == 1
    assert "duplicate early-boot network file" in completed.stderr


# ---- 7. custody contract -----------------------------------------------------

def test_custody_contract_names_the_early_boot_boundary() -> None:
    text = CUSTODY.read_text(encoding="utf-8")
    assert "early_boot_dhcp_owner" in text
    assert "one dhcp owner" in text.lower()
    assert "99-winn-fde-menu.cfg" in text
    assert "winn-fde-layout" in text


def test_every_embedded_initramfs_script_is_valid_posix_shell() -> None:
    if shutil.which("dash") is None:
        pytest.skip("dash is required")
    for body in (premount_network_hook(), handoff_hook(), chroot_block(), conversion_hook(),
                 heredoc(CHAIN_TEXT, '"${HOOKS_DIR}/winn-fde-tools" <<\'EOS\'', "EOS"),
                 heredoc(CHAIN_TEXT, 'hooks/winn-fde-network-tools" <<\'EOS\'', "EOS")):
        completed = subprocess.run(["dash", "-n"], input=body, capture_output=True, text=True)
        assert completed.returncode == 0, completed.stderr
