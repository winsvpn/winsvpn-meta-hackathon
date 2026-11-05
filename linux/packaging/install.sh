#!/usr/bin/env bash
set -Eeuo pipefail

IFS=$'\n\t'
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 022
TARGET=/opt/wins-vpn
NATIVE_HOST_BUNDLE_REL=tools/native_messaging/host/wins_bridge_host
NATIVE_HOST_INSTALLER_REL=tools/native_messaging/install_native_host.sh
NATIVE_HOST_LAYOUT_REL=tools/native_messaging/native_host_layout.py
NATIVE_HOST_RENDERER_REL=tools/native_messaging/render_host_manifest.py
NATIVE_HOST_STORE_IDS_REL=tools/native_messaging/manifests/store_ids.json
NATIVE_HOST_CHROME_MANIFEST_REL=tools/native_messaging/manifests/org.winsvpn.bridge.chrome.json
NATIVE_HOST_EDGE_MANIFEST_REL=tools/native_messaging/manifests/org.winsvpn.bridge.edge.json
NATIVE_HOST_FIREFOX_MANIFEST_REL=tools/native_messaging/manifests/org.winsvpn.bridge.firefox.json
NATIVE_HOST_JSONC_REL=extension/tools/jsonc.py
NATIVE_HOST_FIREFOX_FRAGMENT_REL=extension/manifest/firefox.jsonc
NATIVE_HOST_SYSTEM_DIR=/usr/lib/wins-vpn
NATIVE_HOST_SYSTEM_PATH=/usr/lib/wins-vpn/wins_bridge_host
NATIVE_HOST_CHROME_MANIFEST_DIR=/etc/opt/chrome/native-messaging-hosts
NATIVE_HOST_EDGE_MANIFEST_DIR=/etc/opt/edge/native-messaging-hosts
NATIVE_HOST_FIREFOX_MANIFEST_DIR=/usr/lib/mozilla/native-messaging-hosts
NATIVE_HOST_CHROME_USER_REL=.config/google-chrome/NativeMessagingHosts
NATIVE_HOST_EDGE_USER_REL=.config/microsoft-edge/NativeMessagingHosts
NATIVE_HOST_FIREFOX_USER_REL=.mozilla/native-messaging-hosts
NATIVE_HOST_USER_HOST_REL=.local/lib/wins-vpn/wins_bridge_host
NATIVE_HOST_NAME=org.winsvpn.bridge
# The producer converts upstream awg-quick into the reviewed userspace-only
# script before packaging. Verify that exact packaged output, not the upstream
# source input. The transformed script is byte-identical across targets.
AWG_QUICK_SHA256=89dca7788242e542cec249af5d062764fbcb3a6a3ef66999c400d5bbe2f446db

# The other three pins ARE architecture-specific, and until 2026-08-08 this
# script did not admit that: it pinned the x86-64 values unconditionally and
# refused every other host outright with `uname -m == x86_64`. arm64 is the
# only architecture any Linux session in this project has ever run on, so the
# refusal covered the only real deployment.
#
# Empty means "no pinned hash exists for this architecture". Every use below
# treats empty as a REFUSAL, never as a skip: an unpinned third-party binary is
# not installed under any circumstances.
#
# EXPECTED_ELF_MACHINE is the ELF e_machine this host can execute. It is
# checked against the release's own `wins_vpn` binary AFTER the manifest has
# authenticated it, which is a stronger statement than the archive's filename
# and needs no new trust: an x86-64 payload on an arm64 host is refused by what
# the bytes are, not by what the download was called.
case "$(uname -m)" in
  x86_64|amd64)
    EXPECTED_ELF_MACHINE=62   # EM_X86_64
    AWG_SHA256=23d29323258166183eeeb288c1f9f08b879f3707e54591b1bfb2402413f6d8d8
    AWG_GO_SHA256=5e8e2e656d77f9f66102660234fa08d8c2ddb99bf32961db8c02ad19c32e872f
    XRAY_SHA256=09e63d5420f26db2bc6144f6d047601909541acf21792878d3859e4fc4980a12
    ;;
  aarch64|arm64)
    EXPECTED_ELF_MACHINE=183  # EM_AARCH64
    # From-source linux-arm64 rebuilds of the same pinned amneziawg-tools
    # v3.1.20260812 / amneziawg-go v3.1.20260828 / Xray-core already trusted
    # on x86_64. See tools/build_linux_arm64_awg.sh and tools/build_xray_engine.sh.
    AWG_SHA256=bbf94b3753fb7660897d102918de797a55d675bd66c12bda63a9887400e1876d
    AWG_GO_SHA256=9083c92dbd16422cd590df8fcf2ebae2c604b43539bdd58dddaede74efd0642a
    XRAY_SHA256=868fcabbf9a08d1e453bc6dc82dd8ca27cfcf8cdb2b3a8ff31b824361966964b
    ;;
  *)
    printf '[WINS-LINUX-INSTALL] ERROR: %s\n' \
      "Win's VPN has no build for this computer's processor type ($(uname -m)). Supported: x86-64 and arm64." >&2
    exit 1
    ;;
esac
# M-2: archive authenticity is proven once, up front, by
# linux/packaging/install-winsvpn-linux.sh (cosign-verify-blob against the
# required local/offline public key that built the release -- see that script), which is
# the only supported way to reach this file: it verifies the whole .tar.gz
# *before* ever extracting it, then extracts directly into a fresh root-owned
# 0700 stage and runs this script from there with WINSVPN_VERIFIED_STAGE=1.
# Because authenticity was already proven on the untouched archive bytes,
# this script only needs an *unsigned* exhaustive manifest below to catch
# corruption/substitution of individual files during/after extraction -- it
# does not re-authenticate the release, so no keyring or signature is
# required here. Running this script any other way (direct extraction, no
# bootstrap) is refused below.

log() {
  printf '[WINS-LINUX-INSTALL] %s\n' "$*"
}

die() {
  printf '[WINS-LINUX-INSTALL] ERROR: %s\n' "$*" >&2
  exit 1
}

# Read the authenticated ELF identity directly from the fixed header. Both
# supported release architectures are little-endian ELF64, and Linux executes
# only ET_EXEC (2) or PIE/shared-object ET_DYN (3) images here.
elf_identity_of() {
  local path="$1" magic elf_class elf_data type_low type_high machine_low machine_high
  [[ -f "$path" && ! -L "$path" ]] || return 1
  magic="$(od -An -tx1 -j0 -N4 -- "$path" | tr -d ' \n')"
  [[ "$magic" == "7f454c46" ]] || return 1
  elf_class="$(od -An -tu1 -j4 -N1 -- "$path" | tr -d ' \n')"
  elf_data="$(od -An -tu1 -j5 -N1 -- "$path" | tr -d ' \n')"
  [[ "$elf_class" == 2 && "$elf_data" == 1 ]] || return 1
  IFS=' ' read -r type_low type_high < <(od -An -tu1 -j16 -N2 -- "$path" | tr -s ' ' | sed 's/^ //')
  IFS=' ' read -r machine_low machine_high < <(od -An -tu1 -j18 -N2 -- "$path" | tr -s ' ' | sed 's/^ //')
  printf '%d %d\n' \
    "$(( type_low + 256 * type_high ))" \
    "$(( machine_low + 256 * machine_high ))"
}

assert_elf_matches_this_machine() {
  local path="$1" label="$2" elf_type machine
  IFS=' ' read -r elf_type machine < <(elf_identity_of "$path") || \
    die "The extracted release's $label is not a supported little-endian ELF64 executable."
  [[ "$elf_type" == 2 || "$elf_type" == 3 ]] || \
    die "The extracted release's $label has unsupported ELF type $elf_type."
  [[ "$machine" == "$EXPECTED_ELF_MACHINE" ]] || \
    die "The extracted release's $label targets ELF machine $machine, but this computer expects $EXPECTED_ELF_MACHINE ($(uname -m))."
}

# ---------------------------------------------------------------------------
# Bundled-tool self-test.
#
# Verifies that every bundled runtime the Linux data path depends on resolves
# from a given prefix directory, using the SAME resolution rule the Linux
# runtime applies at startup: each tool is located as "<bundle-dir>/<name>"
# beside the application binary (see FindWinnDatapathExecutable(),
# FindXrayExecutable() and the privileged awg/awg-quick/amneziawg-go runtime
# discovery in linux/runner/linux_tunnel_backend.cc). "Resolves" here means the
# file exists in the prefix, is a regular non-symlink file, and is executable
# -- the exact shape that lets the runtime exec it from the installed
# location. The bytes themselves are already authenticated on a real install
# (cosign before extraction, then the exhaustive manifest + the fixed per-arch
# pins), so this asserts PRESENCE and RESOLVABILITY, never a hash or an exact
# count.
#
# The required set mirrors install.sh's own shipping model:
#   - wins_vpn, winsvpn-bypass-bpf and winn-datapath (the Winn Protocol v3
#     engine) are UNCONDITIONALLY required -- a Linux install must always carry
#     v3.
#   - The AmneziaWG triple (awg, awg-quick, amneziawg-go) is ALL THREE, on both
#     x86_64 and arm64. A partial bundle is a tunnel that starts and then cannot
#     finish.
#   - xray is required on both architectures for trusted-hub Winn v1 fallback.
#
# It runs before every other guard so it is both the post-install verification
# and a clean-prefix rehearsal that does not touch the host:
#   install.sh --self-test <prefix>
#   (after a real install, <prefix> is $TARGET, i.e. /opt/wins-vpn)
run_bundle_self_test() {
  local prefix="${1:-}"
  [[ -n "$prefix" ]] && [[ -d "$prefix" ]] || {
    printf '[WINS-LINUX-INSTALL] ERROR: --self-test requires an existing prefix directory\n' >&2
    return 65
  }
  local tool candidate fail=0

  local -a unconditional=(
    wins_vpn
    winsvpn-bypass-bpf
    winn-datapath
    tools/native_messaging/host/wins_bridge_host
  )
  for tool in "${unconditional[@]}"; do
    candidate="$prefix/$tool"
    if [[ -f "$candidate" && ! -L "$candidate" && -x "$candidate" ]]; then
      printf '[WINS-LINUX-INSTALL] self-test: %-22s resolve OK\n' "$tool"
    else
      printf '[WINS-LINUX-INSTALL] ERROR: required bundled tool does not resolve from %s: %s\n' "$prefix" "$tool" >&2
      fail=1
    fi
  done

  local -a required_elf=(
    wins_vpn
    winsvpn-bypass-bpf
    winn-datapath
    xray
    awg
    amneziawg-go
    tools/native_messaging/host/wins_bridge_host
  )
  for tool in "${required_elf[@]}"; do
    candidate="$prefix/$tool"
    if [[ -f "$candidate" && ! -L "$candidate" && -x "$candidate" ]]; then
      if ! identity="$(elf_identity_of "$candidate")"; then
        printf '[WINS-LINUX-INSTALL] ERROR: required bundled ELF is malformed or unsupported: %s\n' "$tool" >&2
        fail=1
        continue
      fi
      IFS=' ' read -r elf_type machine <<<"$identity"
      if [[ "$elf_type" != 2 && "$elf_type" != 3 ]]; then
        printf '[WINS-LINUX-INSTALL] ERROR: required bundled ELF has unsupported type %s: %s\n' "$elf_type" "$tool" >&2
        fail=1
      elif [[ "$machine" != "$EXPECTED_ELF_MACHINE" ]]; then
        printf '[WINS-LINUX-INSTALL] ERROR: required bundled ELF targets machine %s, expected %s: %s\n' "$machine" "$EXPECTED_ELF_MACHINE" "$tool" >&2
        fail=1
      else
        printf '[WINS-LINUX-INSTALL] self-test: %-22s ELF architecture OK\n' "$tool"
      fi
    fi
  done

  local walk_fail=0
  while IFS= read -r -d '' candidate; do
    local walk_magic walk_identity walk_type walk_machine
    walk_magic="$(od -An -tx1 -j0 -N4 -- "$candidate" | tr -d ' \n')"
    [[ "$walk_magic" == "7f454c46" ]] || continue
    if ! walk_identity="$(elf_identity_of "$candidate")"; then
      printf '[WINS-LINUX-INSTALL] ERROR: bundled ELF is malformed or unsupported: %s\n' "$candidate" >&2
      walk_fail=1
      continue
    fi
    IFS=' ' read -r walk_type walk_machine <<<"$walk_identity"
    if [[ "$walk_type" != 2 && "$walk_type" != 3 ]]; then
      printf '[WINS-LINUX-INSTALL] ERROR: bundled ELF has unsupported type %s: %s\n' "$walk_type" "$candidate" >&2
      walk_fail=1
    elif [[ "$walk_machine" != "$EXPECTED_ELF_MACHINE" ]]; then
      printf '[WINS-LINUX-INSTALL] ERROR: bundled ELF targets machine %s, expected %s: %s\n' "$walk_machine" "$EXPECTED_ELF_MACHINE" "$candidate" >&2
      walk_fail=1
    fi
  done < <(find "$prefix" -type f -print0)
  [[ "$walk_fail" == 0 ]] || fail=1

  # AmneziaWG triple, all required.
  local awg_present=0
  for tool in awg awg-quick amneziawg-go; do
    [[ -e "$prefix/$tool" ]] && awg_present=$((awg_present + 1))
  done
  case "$awg_present" in
    3)
      for tool in awg awg-quick amneziawg-go; do
        candidate="$prefix/$tool"
        if [[ -f "$candidate" && ! -L "$candidate" && -x "$candidate" ]]; then
          printf '[WINS-LINUX-INSTALL] self-test: %-22s resolve OK\n' "$tool"
        else
          printf '[WINS-LINUX-INSTALL] ERROR: bundled tool does not resolve from %s: %s\n' "$prefix" "$tool" >&2
          fail=1
        fi
      done
      ;;
    *)
      printf '[WINS-LINUX-INSTALL] ERROR: Linux x86_64 and arm64 both require the AmneziaWG triple (%s of awg/awg-quick/amneziawg-go) in %s\n' "$awg_present" "$prefix" >&2
      fail=1
      ;;
  esac

  if [[ -f "$prefix/xray" && ! -L "$prefix/xray" && -x "$prefix/xray" ]]; then
    printf '[WINS-LINUX-INSTALL] self-test: %-22s resolve OK\n' 'xray'
  else
    printf '[WINS-LINUX-INSTALL] ERROR: required bundled tool does not resolve from %s: xray\n' "$prefix" >&2
    fail=1
  fi

  if [[ "$fail" == 1 ]]; then
    printf '[WINS-LINUX-INSTALL] SELF-TEST: FAIL\n' >&2
    return 65
  fi
  printf '[WINS-LINUX-INSTALL] SELF-TEST: PASS - all bundled tools resolve\n'
  return 0
}

restore_native_host_executable_modes() {
  local prefix="$1"
  [[ -f "$prefix/$NATIVE_HOST_BUNDLE_REL" && ! -L "$prefix/$NATIVE_HOST_BUNDLE_REL" ]] || {
    printf '[WINS-LINUX-INSTALL] ERROR: native-messaging host is missing: %s\n' \
      "$prefix/$NATIVE_HOST_BUNDLE_REL" >&2
    return 1
  }
  [[ -f "$prefix/$NATIVE_HOST_INSTALLER_REL" && ! -L "$prefix/$NATIVE_HOST_INSTALLER_REL" ]] || {
    printf '[WINS-LINUX-INSTALL] ERROR: native-host installer is missing: %s\n' \
      "$prefix/$NATIVE_HOST_INSTALLER_REL" >&2
    return 1
  }
  chmod 0755 \
    "$prefix/$NATIVE_HOST_BUNDLE_REL" \
    "$prefix/$NATIVE_HOST_INSTALLER_REL"
  [[ -x "$prefix/$NATIVE_HOST_BUNDLE_REL" && -x "$prefix/$NATIVE_HOST_INSTALLER_REL" ]] || {
    printf '[WINS-LINUX-INSTALL] ERROR: native-host delivery files are not executable in %s\n' \
      "$prefix" >&2
    return 1
  }
}

linux_native_host_overlay() {
  python3 - "$@" <<'PY'
import os
import stat
import sys

ERROR = "[WINS-LINUX-INSTALL] ERROR: "


class MissingPath(Exception):
    pass


def fail(message):
    sys.stderr.write(ERROR + message + "\n")
    raise SystemExit(1)


def identity(info):
    return (info.st_dev, info.st_ino)


def symlink_is_replaceable(info):
    if info.st_uid == os.getuid():
        return True
    mode = stat.S_IMODE(info.st_mode)
    if mode & 0o002:
        return True
    if mode & 0o020:
        try:
            groups = os.getgroups()
        except OSError:
            return True
        if info.st_gid in groups or info.st_gid == os.getgid():
            return True
    return False


def is_special(info):
    mode = info.st_mode
    return bool(
        stat.S_ISFIFO(mode)
        or stat.S_ISCHR(mode)
        or stat.S_ISBLK(mode)
        or stat.S_ISSOCK(mode)
    )


def require_nofollow():
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        fail("overlay binding requires O_NOFOLLOW and O_DIRECTORY")


def cloexec():
    return getattr(os, "O_CLOEXEC", 0)


def dir_flags():
    require_nofollow()
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | cloexec()


def file_read_flags():
    require_nofollow()
    return os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | cloexec()


def file_excl_flags():
    require_nofollow()
    return (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | getattr(os, "O_NONBLOCK", 0)
        | cloexec()
    )


def absolute(path, *, label):
    if path is None or path == "":
        fail(label + " is required")
    if "\x00" in path:
        fail(label + " contains a NUL")
    if path.startswith("/"):
        return path
    cwd = os.getcwd()
    if not cwd.startswith("/"):
        fail("working directory is not absolute")
    return cwd.rstrip("/") + "/" + path


def split_abs(path, *, label):
    path = absolute(path, label=label)
    while path != "/" and path.endswith("/"):
        path = path[:-1]
    if path == "/":
        return "/", []
    parts = path.split("/")[1:]
    if any(part == "" or part == "." or part == ".." for part in parts):
        fail("native-host path has an empty, dot, or dot-dot component: " + path)
    return path, parts


def open_root():
    return os.open("/", os.O_RDONLY | os.O_DIRECTORY | cloexec())


def walk_dirs(start_fd, components, *, create, label, symlink_error):
    current = start_fd
    built = ""
    transferring = False
    try:
        for index, name in enumerate(components):
            built += "/" + name
            last = index == len(components) - 1
            try:
                info = os.lstat(name, dir_fd=current)
            except FileNotFoundError:
                if not create:
                    raise MissingPath(label + " is not a directory: " + built)
                try:
                    os.mkdir(name, 0o755, dir_fd=current)
                except FileExistsError:
                    pass
                info = os.lstat(name, dir_fd=current)
            if stat.S_ISLNK(info.st_mode):
                if last or symlink_is_replaceable(info):
                    fail(symlink_error + built)
                nxt = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | cloexec(),
                    dir_fd=current,
                )
            else:
                if is_special(info):
                    fail("refusing special native-host path " + built)
                if not stat.S_ISDIR(info.st_mode):
                    fail("refusing non-directory intermediate native-host path " + built)
                nxt = os.open(name, dir_flags(), dir_fd=current)
            try:
                opened = os.fstat(nxt)
                if not stat.S_ISDIR(opened.st_mode) or is_special(opened):
                    fail(label + " changed while it was bound")
                if not stat.S_ISLNK(info.st_mode) and (
                    identity(opened) != identity(info)
                    or not stat.S_ISDIR(opened.st_mode)
                ):
                    fail(label + " changed while it was bound")
            except BaseException:
                os.close(nxt)
                raise
            previous = current
            current = nxt
            if previous != start_fd:
                os.close(previous)
        transferring = True
        return current, built
    finally:
        if not transferring and current != start_fd:
            os.close(current)


def bind_overlay(prefix):
    path, parts = split_abs(prefix, label="overlay prefix")
    if not parts:
        fail("refusing overlay prefix /")
    root = open_root()
    overlay_fd = None
    transferring = False
    try:
        try:
            overlay_fd, _built = walk_dirs(
                root,
                parts,
                create=False,
                label="overlay prefix",
                symlink_error="refusing intermediate symlink overlay prefix ",
            )
        except MissingPath:
            fail("overlay prefix is not a directory: " + path)
        opened = os.fstat(overlay_fd)
        if not stat.S_ISDIR(opened.st_mode):
            fail("overlay prefix is not a directory: " + path)
        if overlay_fd != root:
            os.close(root)
            root = -1
        transferring = True
        return overlay_fd, path, opened
    finally:
        if not transferring:
            if overlay_fd is not None and overlay_fd != root:
                os.close(overlay_fd)
            if root >= 0:
                os.close(root)


def rel_under(canonical, dest):
    dest_path, dest_parts = split_abs(dest, label="native-host path")
    prefix_path, prefix_parts = split_abs(canonical, label="overlay prefix")
    if dest_path == prefix_path:
        return []
    if not dest_path.startswith(prefix_path + "/"):
        fail(
            "native-host path %s is outside overlay prefix %s"
            % (dest_path, prefix_path)
        )
    rel_parts = dest_parts[len(prefix_parts) :]
    if dest_parts[: len(prefix_parts)] != prefix_parts:
        fail(
            "native-host path %s is outside overlay prefix %s"
            % (dest_path, prefix_path)
        )
    return rel_parts


def inspect_leaf(parent_fd, leaf, leaf_kind, built):
    try:
        info = os.lstat(leaf, dir_fd=parent_fd)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(info.st_mode):
        fail("refusing symlink native-host path " + built)
    if is_special(info):
        fail("refusing special native-host path " + built)
    if leaf_kind == "file":
        if not stat.S_ISREG(info.st_mode):
            fail("refusing non-regular native-host path " + built)
    elif leaf_kind == "dir":
        if not stat.S_ISDIR(info.st_mode):
            fail("refusing non-directory native-host path " + built)
    else:
        fail("native-host leaf kind is invalid")
    return info


def bind_parent_under(start_fd, rel_parts, *, create, leaf_kind, dest_label):
    if not rel_parts:
        info = os.fstat(start_fd)
        if leaf_kind == "dir":
            if not stat.S_ISDIR(info.st_mode):
                fail("refusing non-directory native-host path " + dest_label)
            return start_fd, None, "", False
        fail("refusing overlay prefix / as a native-host file dest")
    parent_parts = rel_parts[:-1]
    leaf = rel_parts[-1]
    parent_fd, parent_built = walk_dirs(
        start_fd,
        parent_parts,
        create=create,
        label="native-host path",
        symlink_error="refusing intermediate symlink native-host path ",
    )
    owned = parent_fd != start_fd
    built = parent_built + "/" + leaf if parent_built else "/" + leaf
    transferring = False
    try:
        inspect_leaf(parent_fd, leaf, leaf_kind, built)
        transferring = True
        return parent_fd, leaf, built, owned
    finally:
        if not transferring and owned:
            os.close(parent_fd)


def copy_fd(src_fd, dst_fd):
    while True:
        chunk = os.read(src_fd, 1024 * 1024)
        if not chunk:
            return
        view = memoryview(chunk)
        while view:
            written = os.write(dst_fd, view)
            view = view[written:]


def exclusive_temp(parent_fd, name, mode):
    flags = file_excl_flags()
    for _ in range(16):
        tmp = ".%s.%s.tmp" % (name, os.urandom(8).hex())
        try:
            fd = os.open(tmp, flags, mode, dir_fd=parent_fd)
        except FileExistsError:
            continue
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or is_special(opened):
            os.close(fd)
            try:
                os.unlink(tmp, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            fail("refusing special native-host temp " + tmp)
        return fd, tmp
    fail("cannot create exclusive native-host temp beside " + name)


def replace_from_fd(parent_fd, leaf, src_fd, mode, dest_info, *, refuse_hardlink):
    if dest_info is not None:
        if refuse_hardlink and dest_info.st_nlink != 1:
            fail("refusing hardlinked native-host rollback destination")
        if dest_info.st_nlink < 1:
            fail("refusing hardlinked native-host rollback destination")
    tmp_fd, tmp_name = exclusive_temp(parent_fd, leaf, mode)
    try:
        copy_fd(src_fd, tmp_fd)
        os.fchmod(tmp_fd, mode)
        os.fsync(tmp_fd)
        os.close(tmp_fd)
        tmp_fd = -1
        try:
            current = os.lstat(leaf, dir_fd=parent_fd)
        except FileNotFoundError:
            current = None
        if current is not None:
            if stat.S_ISLNK(current.st_mode):
                fail("refusing symlink native-host path " + leaf)
            if is_special(current) or not stat.S_ISREG(current.st_mode):
                fail("refusing special native-host path " + leaf)
        if dest_info is None:
            if current is not None:
                fail("native-host dest appeared while it was bound")
        else:
            if current is None or identity(current) != identity(dest_info):
                fail("native-host dest changed while it was bound")
            if refuse_hardlink and current.st_nlink != 1:
                fail("refusing hardlinked native-host rollback destination")
        os.rename(tmp_name, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        tmp_name = None
    finally:
        if tmp_fd >= 0:
            os.close(tmp_fd)
        if tmp_name is not None:
            try:
                os.unlink(tmp_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass


def open_regular(path, *, label, refuse_hardlink, missing_ok=False):
    dest_path, dest_parts = split_abs(path, label=label)
    if not dest_parts:
        fail(label + " must not be /")
    root = open_root()
    parent_fd = None
    owned = False
    try:
        try:
            parent_fd, leaf, built, owned = bind_parent_under(
                root,
                dest_parts,
                create=False,
                leaf_kind="file",
                dest_label=dest_path,
            )
        except MissingPath:
            if missing_ok:
                return None, None
            fail(label + " is unreadable: " + path)
        if owned:
            os.close(root)
            root = -1
        info = inspect_leaf(parent_fd, leaf, "file", built)
        if info is None:
            if missing_ok:
                return None, None
            fail(label + " is unreadable: " + path)
        if refuse_hardlink and info.st_nlink != 1:
            fail("refusing hardlinked native-host backup")
        fd = os.open(leaf, file_read_flags(), dir_fd=parent_fd)
        try:
            opened = os.fstat(fd)
            if (
                identity(opened) != identity(info)
                or not stat.S_ISREG(opened.st_mode)
                or is_special(opened)
            ):
                fail(label + " is not a regular file: " + path)
            if refuse_hardlink and opened.st_nlink != 1:
                fail("refusing hardlinked native-host backup")
            handed = fd
            fd = -1
            return handed, opened
        finally:
            if fd >= 0:
                os.close(fd)
    finally:
        if owned and parent_fd is not None:
            os.close(parent_fd)
        if root >= 0:
            os.close(root)


def with_dest_parent(overlay, dest, *, create, leaf_kind):
    session = Session(overlay)
    try:
        parent_fd, leaf, built, owned = session.dest_parent(
            dest, create=create, leaf_kind=leaf_kind
        )
        return session, parent_fd, leaf, built, owned
    except BaseException:
        session.close()
        raise


def close_dest(session, parent_fd, owned):
    if owned and parent_fd is not None and parent_fd >= 0:
        if session.overlay_fd is None or parent_fd != session.overlay_fd:
            os.close(parent_fd)
    session.close()


class Session:
    def __init__(self, overlay):
        self.overlay = overlay or ""
        if self.overlay:
            self.overlay_fd, self.canonical, self.overlay_info = bind_overlay(self.overlay)
        else:
            self.overlay_fd = None
            self.canonical = None
            self.overlay_info = None

    def close(self):
        if self.overlay_fd is not None:
            os.close(self.overlay_fd)
            self.overlay_fd = None

    def check(self):
        if self.overlay_fd is None:
            return
        held = os.fstat(self.overlay_fd)
        if identity(held) != identity(self.overlay_info) or not stat.S_ISDIR(held.st_mode):
            fail("overlay prefix changed while it was bound")

    def dest_parent(self, dest, *, create, leaf_kind):
        self.check()
        if self.overlay_fd is not None:
            rel = rel_under(self.canonical, dest)
            return bind_parent_under(
                self.overlay_fd,
                rel,
                create=create,
                leaf_kind=leaf_kind,
                dest_label=self.canonical,
            )
        dest_path, dest_parts = split_abs(dest, label="native-host path")
        if not dest_parts:
            fail("refusing overlay prefix /")
        root = open_root()
        transferring = False
        try:
            parent_fd, leaf, built, owned = bind_parent_under(
                root,
                dest_parts,
                create=create,
                leaf_kind=leaf_kind,
                dest_label=dest_path,
            )
            if owned:
                os.close(root)
                root = -1
            transferring = True
            return parent_fd, leaf, built, True
        finally:
            if not transferring and root >= 0:
                os.close(root)

    def close_parent(self, parent_fd, owned):
        if owned and parent_fd is not None and parent_fd >= 0:
            if self.overlay_fd is None or parent_fd != self.overlay_fd:
                os.close(parent_fd)


def under_overlay(session, path):
    if session.overlay_fd is None or session.canonical is None:
        return False
    dest_path, _parts = split_abs(path, label="native-host path")
    return dest_path == session.canonical or dest_path.startswith(
        session.canonical + "/"
    )


def session_open_regular(session, path, *, label, refuse_hardlink, missing_ok=False):
    if session.overlay_fd is not None and not under_overlay(session, path):
        return open_regular(
            path, label=label, refuse_hardlink=refuse_hardlink, missing_ok=missing_ok
        )
    try:
        parent_fd, leaf, built, owned = session.dest_parent(
            path, create=False, leaf_kind="file"
        )
    except MissingPath:
        if missing_ok:
            return None, None
        fail(label + " is unreadable: " + path)
    try:
        if not leaf:
            fail(label + " must not be /")
        info = inspect_leaf(parent_fd, leaf, "file", built)
        if info is None:
            if missing_ok:
                return None, None
            fail(label + " is unreadable: " + path)
        if refuse_hardlink and info.st_nlink != 1:
            fail("refusing hardlinked native-host backup")
        fd = os.open(leaf, file_read_flags(), dir_fd=parent_fd)
        try:
            opened = os.fstat(fd)
            if (
                identity(opened) != identity(info)
                or not stat.S_ISREG(opened.st_mode)
                or is_special(opened)
            ):
                fail(label + " is not a regular file: " + path)
            if refuse_hardlink and opened.st_nlink != 1:
                fail("refusing hardlinked native-host backup")
            handed = fd
            fd = -1
            return handed, opened
        finally:
            if fd >= 0:
                os.close(fd)
    finally:
        session.close_parent(parent_fd, owned)


def session_assert_dest(session, dest, leaf_kind, missing_parent_ok=False):
    try:
        parent_fd, leaf, built, owned = session.dest_parent(
            dest, create=False, leaf_kind=leaf_kind
        )
    except MissingPath as exc:
        if missing_parent_ok:
            return
        fail(str(exc))
    try:
        if leaf:
            inspect_leaf(parent_fd, leaf, leaf_kind, built)
    finally:
        session.close_parent(parent_fd, owned)


def session_mkdir_p(session, dest):
    parent_fd, leaf, built, owned = session.dest_parent(
        dest, create=True, leaf_kind="dir"
    )
    try:
        if leaf:
            info = inspect_leaf(parent_fd, leaf, "dir", built)
            if info is None:
                os.mkdir(leaf, 0o755, dir_fd=parent_fd)
                inspect_leaf(parent_fd, leaf, "dir", built)
            else:
                nxt = os.open(leaf, dir_flags(), dir_fd=parent_fd)
                try:
                    opened = os.fstat(nxt)
                    if identity(opened) != identity(info):
                        fail("native-host directory changed while it was bound")
                finally:
                    os.close(nxt)
    finally:
        session.close_parent(parent_fd, owned)


def session_unlink(session, dest, missing_ok=True):
    try:
        parent_fd, leaf, built, owned = session.dest_parent(
            dest, create=False, leaf_kind="file"
        )
    except MissingPath:
        if missing_ok:
            return
        raise
    try:
        if not leaf:
            return
        info = inspect_leaf(parent_fd, leaf, "file", built)
        if info is None:
            return
        os.unlink(leaf, dir_fd=parent_fd)
    finally:
        session.close_parent(parent_fd, owned)


def session_install_file(session, source, dest, mode_text):
    mode = int(mode_text, 8)
    src_fd, _src_info = session_open_regular(
        session, source, label="native-host source", refuse_hardlink=False
    )
    try:
        parent_fd, leaf, built, owned = session.dest_parent(
            dest, create=True, leaf_kind="file"
        )
        try:
            if not leaf:
                fail("refusing overlay prefix /")
            staged = leaf + ".new"
            try:
                staged_info = os.lstat(staged, dir_fd=parent_fd)
            except FileNotFoundError:
                staged_info = None
            if staged_info is not None:
                if stat.S_ISLNK(staged_info.st_mode):
                    fail("refusing preplanted staging symlink " + built + ".new")
                if is_special(staged_info) or not stat.S_ISREG(staged_info.st_mode):
                    fail("refusing preplanted staging path " + built + ".new")
            dest_info = inspect_leaf(parent_fd, leaf, "file", built)
            replace_from_fd(
                parent_fd, leaf, src_fd, mode, dest_info, refuse_hardlink=False
            )
        finally:
            session.close_parent(parent_fd, owned)
    finally:
        os.close(src_fd)


def session_restore(session, dest, backup):
    backup_fd = None
    backup_mode = 0o644
    try:
        if backup:
            backup_fd, backup_info = session_open_regular(
                session,
                backup,
                label="native-host backup",
                refuse_hardlink=True,
                missing_ok=True,
            )
            if backup_fd is None:
                fail("native-host backup is missing: " + backup)
            backup_mode = stat.S_IMODE(backup_info.st_mode)
        parent_fd, leaf, built, owned = session.dest_parent(
            dest, create=False, leaf_kind="file"
        )
        try:
            if not leaf:
                fail("refusing overlay prefix /")
            dest_info = inspect_leaf(parent_fd, leaf, "file", built)
            if backup_fd is not None:
                replace_from_fd(
                    parent_fd,
                    leaf,
                    backup_fd,
                    backup_mode,
                    dest_info,
                    refuse_hardlink=True,
                )
            elif dest_info is not None:
                if dest_info.st_nlink != 1:
                    fail("refusing hardlinked native-host rollback destination")
                os.unlink(leaf, dir_fd=parent_fd)
        finally:
            session.close_parent(parent_fd, owned)
    finally:
        if backup_fd is not None:
            os.close(backup_fd)


def session_snapshot(session, source, dest):
    try:
        parent_fd, leaf, built, owned = session.dest_parent(
            source, create=False, leaf_kind="file"
        )
    except MissingPath:
        return ""
    try:
        info = inspect_leaf(parent_fd, leaf, "file", built)
        if info is None:
            return ""
        src_fd = os.open(leaf, file_read_flags(), dir_fd=parent_fd)
        transferring_src = False
        try:
            src_info = os.fstat(src_fd)
            if identity(src_info) != identity(info) or not stat.S_ISREG(src_info.st_mode):
                fail("native-host source is not a regular file: " + source)
            transferring_src = True
        finally:
            if not transferring_src:
                os.close(src_fd)
    finally:
        session.close_parent(parent_fd, owned)
    try:
        parent_fd, leaf, built, owned = session.dest_parent(
            dest, create=True, leaf_kind="file"
        )
        try:
            if not leaf:
                fail("refusing overlay prefix /")
            dest_info = inspect_leaf(parent_fd, leaf, "file", built)
            replace_from_fd(
                parent_fd,
                leaf,
                src_fd,
                stat.S_IMODE(src_info.st_mode),
                dest_info,
                refuse_hardlink=False,
            )
            return dest
        finally:
            session.close_parent(parent_fd, owned)
    finally:
        os.close(src_fd)


def run_session(overlay, fn, *args):
    session = Session(overlay)
    try:
        return fn(session, *args)
    finally:
        session.close()


def cmd_bind_prefix(prefix):
    overlay_fd, canonical, _info = bind_overlay(prefix)
    os.close(overlay_fd)
    sys.stdout.write(canonical + "\n")


def cmd_assert_dest(overlay, dest, leaf_kind):
    run_session(overlay, session_assert_dest, dest, leaf_kind, False)


def cmd_mkdir_p(overlay, dest):
    run_session(overlay, session_mkdir_p, dest)


def cmd_unlink(overlay, dest):
    run_session(overlay, session_unlink, dest, True)


def cmd_install_file(overlay, source, dest, mode_text):
    run_session(overlay, session_install_file, source, dest, mode_text)


def cmd_restore(overlay, dest, backup):
    run_session(overlay, session_restore, dest, backup)


def cmd_snapshot(overlay, source, dest):
    created = run_session(overlay, session_snapshot, source, dest) or ""
    sys.stdout.write(created + "\n")


def parse_transaction(args):
    ops = []
    i = 0
    while i < len(args):
        cmd = args[i]
        if cmd in (
            "preflight-file",
            "preflight-optional",
            "preflight-dir",
            "mkdir-p",
            "unlink",
        ):
            if i + 1 >= len(args):
                fail("transaction " + cmd + " requires PATH")
            ops.append((cmd, args[i + 1]))
            i += 2
            continue
        if cmd in ("restore", "snapshot"):
            if i + 2 >= len(args):
                fail("transaction " + cmd + " requires PATH BACKUP")
            ops.append((cmd, args[i + 1], args[i + 2]))
            i += 3
            continue
        if cmd == "install-file":
            if i + 3 >= len(args):
                fail("transaction install-file requires SRC DEST MODE")
            ops.append((cmd, args[i + 1], args[i + 2], args[i + 3]))
            i += 4
            continue
        fail("unknown overlay helper operation")
    return ops


def cmd_transaction(overlay, args):
    ops = parse_transaction(args)
    session = Session(overlay)
    try:
        preflights = [op for op in ops if op[0].startswith("preflight-")]
        mutations = [op for op in ops if not op[0].startswith("preflight-")]
        for op in preflights:
            session.check()
            if op[0] == "preflight-file":
                session_assert_dest(session, op[1], "file", missing_parent_ok=False)
            elif op[0] == "preflight-optional":
                session_assert_dest(session, op[1], "file", missing_parent_ok=True)
            elif op[0] == "preflight-dir":
                session_assert_dest(session, op[1], "dir", missing_parent_ok=False)
        for op in mutations:
            session.check()
            if op[0] == "mkdir-p":
                session_mkdir_p(session, op[1])
            elif op[0] == "unlink":
                session_unlink(session, op[1], missing_ok=True)
            elif op[0] == "install-file":
                session_install_file(session, op[1], op[2], op[3])
            elif op[0] == "restore":
                session_restore(session, op[1], op[2])
            elif op[0] == "snapshot":
                session_snapshot(session, op[1], op[2])
            else:
                fail("unknown overlay helper operation")
    finally:
        session.close()


def main(argv):
    if not argv:
        fail("overlay helper requires an operation")
    op = argv[0]
    args = argv[1:]
    if op == "bind-prefix":
        if len(args) != 1:
            fail("bind-prefix requires PREFIX")
        cmd_bind_prefix(args[0])
        return
    if op == "assert-dest":
        if len(args) != 3:
            fail("assert-dest requires PREFIX PATH KIND")
        cmd_assert_dest(args[0], args[1], args[2])
        return
    if op == "mkdir-p":
        if len(args) != 2:
            fail("mkdir-p requires PREFIX PATH")
        cmd_mkdir_p(args[0], args[1])
        return
    if op == "unlink":
        if len(args) != 2:
            fail("unlink requires PREFIX PATH")
        cmd_unlink(args[0], args[1])
        return
    if op == "install-file":
        if len(args) != 4:
            fail("install-file requires PREFIX SRC DEST MODE")
        cmd_install_file(args[0], args[1], args[2], args[3])
        return
    if op == "restore":
        if len(args) != 3:
            fail("restore requires PREFIX PATH BACKUP")
        cmd_restore(args[0], args[1], args[2])
        return
    if op == "snapshot":
        if len(args) != 3:
            fail("snapshot requires PREFIX SRC DEST")
        cmd_snapshot(args[0], args[1], args[2])
        return
    if op == "transaction":
        if not args:
            fail("transaction requires PREFIX")
        cmd_transaction(args[0], args[1:])
        return
    fail("unknown overlay helper operation")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except SystemExit:
        raise
    except MissingPath as exc:
        fail(str(exc))
    except OSError as exc:
        fail(str(exc))
PY
}

normalize_overlay_prefix() {
  linux_native_host_overlay bind-prefix "$1"
}

assert_native_host_leaf_safe() {
  local path="$1" leaf_kind="$2"
  if [[ -L "$path" ]]; then
    printf '[WINS-LINUX-INSTALL] ERROR: refusing symlink native-host path %s\n' "$path" >&2
    return 1
  fi
  if [[ -e "$path" ]]; then
    case "$leaf_kind" in
      file)
        if [[ ! -f "$path" ]]; then
          printf '[WINS-LINUX-INSTALL] ERROR: refusing non-regular native-host path %s\n' "$path" >&2
          return 1
        fi
        ;;
      dir)
        if [[ ! -d "$path" ]]; then
          printf '[WINS-LINUX-INSTALL] ERROR: refusing non-directory native-host path %s\n' "$path" >&2
          return 1
        fi
        ;;
      *)
        return 1
        ;;
    esac
  fi
  return 0
}

assert_overlay_path_safe() {
  local prefix="$1" path="$2" leaf_kind="$3"
  linux_native_host_overlay assert-dest "$prefix" "$path" "$leaf_kind"
}

assert_native_host_dest_safe() {
  local overlay_root="$1" path="$2" leaf_kind="$3"
  if [[ -n "$overlay_root" ]]; then
    assert_overlay_path_safe "$overlay_root" "$path" "$leaf_kind"
    return $?
  fi
  assert_native_host_leaf_safe "$path" "$leaf_kind"
}

native_host_manifest_path_field() {
  python3 - "$1" <<'PY'
import json
import sys

def reject_duplicates(pairs):
    document = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate JSON key: {key}")
        document[key] = value
    return document

with open(sys.argv[1], "r", encoding="ascii") as fh:
    document = json.load(fh, object_pairs_hook=reject_duplicates)
if not isinstance(document, dict):
    raise SystemExit(1)
required = {"name", "description", "path", "type"}
if "allowed_origins" in document:
    required = required | {"allowed_origins"}
elif "allowed_extensions" in document:
    required = required | {"allowed_extensions"}
else:
    raise SystemExit(1)
if set(document) != required:
    raise SystemExit(1)
value = document.get("path")
if not isinstance(value, str) or not value:
    raise SystemExit(1)
print(value)
PY
}

assert_native_host_manifest_path() {
  local manifest="$1" expected="$2" actual
  [[ -f "$manifest" && ! -L "$manifest" ]] || {
    printf '[WINS-LINUX-INSTALL] ERROR: native-host manifest is missing: %s\n' "$manifest" >&2
    return 1
  }
  actual="$(native_host_manifest_path_field "$manifest")" || {
    printf '[WINS-LINUX-INSTALL] ERROR: native-host manifest is unreadable: %s\n' "$manifest" >&2
    return 1
  }
  if [[ "$actual" != "$expected" ]]; then
    printf '[WINS-LINUX-INSTALL] ERROR: native-host manifest path %s does not match installed host %s (%s)\n' \
      "$actual" "$expected" "$manifest" >&2
    return 1
  fi
}

native_host_manifest_chromium_origin() {
  python3 - "$1" <<'PY'
import json
import sys

def reject_duplicates(pairs):
    document = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate JSON key: {key}")
        document[key] = value
    return document

with open(sys.argv[1], "r", encoding="ascii") as fh:
    document = json.load(fh, object_pairs_hook=reject_duplicates)
if not isinstance(document, dict):
    raise SystemExit(1)
required = {"name", "description", "path", "type", "allowed_origins"}
if set(document) != required:
    raise SystemExit(1)
origins = document.get("allowed_origins")
if not isinstance(origins, list) or len(origins) != 1 or not isinstance(origins[0], str) or not origins[0]:
    raise SystemExit(1)
print(origins[0])
PY
}

assert_native_host_chromium_origin() {
  local manifest="$1" expected_id="$2" actual
  [[ -f "$manifest" && ! -L "$manifest" ]] || {
    printf '[WINS-LINUX-INSTALL] ERROR: native-host manifest is missing: %s\n' "$manifest" >&2
    return 1
  }
  actual="$(native_host_manifest_chromium_origin "$manifest")" || {
    printf '[WINS-LINUX-INSTALL] ERROR: native-host chromium origin is unreadable: %s\n' "$manifest" >&2
    return 1
  }
  if [[ "$actual" != "chrome-extension://${expected_id}/" ]]; then
    printf '[WINS-LINUX-INSTALL] ERROR: native-host origin %s does not match store id %s (%s)\n' \
      "$actual" "$expected_id" "$manifest" >&2
    return 1
  fi
}

read_native_host_store_ids() {
  python3 - "$1" <<'PY'
import json
import re
import sys

def reject_duplicates(pairs):
    document = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate JSON key: {key}")
        document[key] = value
    return document

def valid_chromium_id(value):
    return (
        isinstance(value, str)
        and re.fullmatch(r"[a-p]{32}", value) is not None
        and "placeholder" not in value.lower()
    )

try:
    with open(sys.argv[1], "r", encoding="ascii") as fh:
        document = json.load(fh, object_pairs_hook=reject_duplicates)
except ValueError as exc:
    if "duplicate JSON key" in str(exc):
        print("packaged native-host store identity has a duplicate JSON key", file=sys.stderr)
        raise SystemExit(1)
    raise
if not isinstance(document, dict):
    raise SystemExit(1)
extra = set(document) - {"chrome", "edge"}
if extra:
    print("packaged native-host store identity has extra JSON keys; refusing to invent ids", file=sys.stderr)
    raise SystemExit(1)

chrome_id = document.get("chrome")
edge_id = document.get("edge")
if not valid_chromium_id(chrome_id):
    raise SystemExit(1)
if edge_id is None or edge_id == "":
    print(
        "owner-blocked: packaged native-host store identity is missing a distinct Edge id; refusing to invent one",
        file=sys.stderr,
    )
    raise SystemExit(78)
if not isinstance(edge_id, str) or "placeholder" in edge_id.lower():
    print(
        "owner-blocked: packaged Edge store identity is a placeholder; refusing to invent one",
        file=sys.stderr,
    )
    raise SystemExit(78)
if re.fullmatch(r"[a-p]{32}", edge_id) is None:
    print(
        "owner-blocked: packaged Edge store identity is not a store-issued [a-p]{32} id; refusing to invent one",
        file=sys.stderr,
    )
    raise SystemExit(78)
if chrome_id == edge_id:
    print(
        "owner-blocked: Chrome and Edge store-listing ids must be distinct; refusing to reuse one identity",
        file=sys.stderr,
    )
    raise SystemExit(78)
print(chrome_id)
print(edge_id)
PY
}

snapshot_native_host_path() {
  local path="$1" dest="$2" overlay_root="${3:-}" result_variable="${4:-}"
  local created
  created="$(linux_native_host_overlay snapshot "$overlay_root" "$path" "$dest")" || return 1
  if [[ -n "$result_variable" ]]; then
    printf -v "$result_variable" '%s' "$created"
  fi
}

restore_native_host_path() {
  local path="$1" backup="$2" overlay_root="${3:-}"
  linux_native_host_overlay restore "$overlay_root" "$path" "$backup"
}

restore_linux_native_messaging() {
  local overlay_root="$1"
  local host_path="$2" host_backup="$3"
  local chrome_manifest="$4" chrome_backup="$5"
  local firefox_manifest="$6" firefox_backup="$7"
  local edge_manifest="$8" edge_backup="$9"
  [[ $# -eq 9 ]] || {
    printf '[WINS-LINUX-INSTALL] ERROR: native-host rollback requires overlay root plus host, Chrome, Firefox, and Edge backups.\n' >&2
    return 1
  }
  linux_native_host_overlay transaction "$overlay_root" \
    restore "$host_path" "$host_backup" \
    restore "$chrome_manifest" "$chrome_backup" \
    restore "$firefox_manifest" "$firefox_backup" \
    restore "$edge_manifest" "$edge_backup"
}

uninstall_linux_native_messaging() {
  local overlay_root="$1"
  local host_path="$2"
  local chrome_manifest="$3"
  local firefox_manifest="$4"
  local edge_manifest="$5"
  local home_dir="${6:-}"
  local -a tx=(transaction "$overlay_root")
  local preflight="preflight-file"
  if [[ -z "$overlay_root" ]]; then
    preflight="preflight-optional"
  fi
  tx+=("$preflight" "$chrome_manifest" "$preflight" "$firefox_manifest" "$preflight" "$edge_manifest")
  if [[ -n "$host_path" ]]; then
    tx+=("$preflight" "$host_path")
  fi
  if [[ -n "$home_dir" ]]; then
    if [[ -n "$overlay_root" ]]; then
      if [[ -e "$home_dir" || -L "$home_dir" ]]; then
        tx+=(preflight-dir "$home_dir")
        tx+=(preflight-file "$home_dir/$NATIVE_HOST_CHROME_USER_REL/${NATIVE_HOST_NAME}.json")
        tx+=(preflight-file "$home_dir/$NATIVE_HOST_EDGE_USER_REL/${NATIVE_HOST_NAME}.json")
        tx+=(preflight-file "$home_dir/$NATIVE_HOST_FIREFOX_USER_REL/${NATIVE_HOST_NAME}.json")
        tx+=(preflight-file "$home_dir/$NATIVE_HOST_USER_HOST_REL")
      fi
    else
      tx+=(preflight-optional "$home_dir/$NATIVE_HOST_CHROME_USER_REL/${NATIVE_HOST_NAME}.json")
      tx+=(preflight-optional "$home_dir/$NATIVE_HOST_EDGE_USER_REL/${NATIVE_HOST_NAME}.json")
      tx+=(preflight-optional "$home_dir/$NATIVE_HOST_FIREFOX_USER_REL/${NATIVE_HOST_NAME}.json")
      tx+=(preflight-optional "$home_dir/$NATIVE_HOST_USER_HOST_REL")
    fi
  fi
  tx+=(unlink "$chrome_manifest" unlink "$firefox_manifest" unlink "$edge_manifest")
  if [[ -n "$host_path" ]]; then
    tx+=(unlink "$host_path")
  fi
  if [[ -n "$home_dir" ]]; then
    if [[ -z "$overlay_root" || -e "$home_dir" || -L "$home_dir" ]]; then
      tx+=(unlink "$home_dir/$NATIVE_HOST_CHROME_USER_REL/${NATIVE_HOST_NAME}.json")
      tx+=(unlink "$home_dir/$NATIVE_HOST_EDGE_USER_REL/${NATIVE_HOST_NAME}.json")
      tx+=(unlink "$home_dir/$NATIVE_HOST_FIREFOX_USER_REL/${NATIVE_HOST_NAME}.json")
      tx+=(unlink "$home_dir/$NATIVE_HOST_USER_HOST_REL")
    fi
  fi
  linux_native_host_overlay "${tx[@]}"
}

uninstall_linux_native_host_user_manifests() {
  local overlay_root="$1"
  local home_dir="$2"
  [[ -n "$home_dir" ]] || return 0
  uninstall_linux_native_messaging "$overlay_root" \
    "$home_dir/$NATIVE_HOST_USER_HOST_REL" \
    "$home_dir/$NATIVE_HOST_CHROME_USER_REL/${NATIVE_HOST_NAME}.json" \
    "$home_dir/$NATIVE_HOST_FIREFOX_USER_REL/${NATIVE_HOST_NAME}.json" \
    "$home_dir/$NATIVE_HOST_EDGE_USER_REL/${NATIVE_HOST_NAME}.json"
}

require_native_host_identity_inputs() {
  local prefix="$1" required
  for required in \
    "$NATIVE_HOST_BUNDLE_REL" \
    "$NATIVE_HOST_INSTALLER_REL" \
    "$NATIVE_HOST_LAYOUT_REL" \
    "$NATIVE_HOST_RENDERER_REL" \
    "$NATIVE_HOST_STORE_IDS_REL" \
    "$NATIVE_HOST_CHROME_MANIFEST_REL" \
    "$NATIVE_HOST_EDGE_MANIFEST_REL" \
    "$NATIVE_HOST_FIREFOX_MANIFEST_REL" \
    "$NATIVE_HOST_JSONC_REL" \
    "$NATIVE_HOST_FIREFOX_FRAGMENT_REL"; do
    if [[ ! -f "$prefix/$required" || -L "$prefix/$required" ]]; then
      printf '[WINS-LINUX-INSTALL] ERROR: native-host identity or registration input is missing: %s\n' \
        "$prefix/$required" >&2
      return 1
    fi
  done
}

BROWSER_BRIDGE_IDENTITY_DIR=/usr/lib/wins-vpn
BROWSER_BRIDGE_IDENTITY_FILE="$BROWSER_BRIDGE_IDENTITY_DIR/browser_bridge.identity"

browser_bridge_identity_directory_valid() {
  python3 - "$1" <<'PY'
import os, stat, sys
path = sys.argv[1]
try:
    if not os.path.isabs(path):
        sys.exit(1)
    while True:
        info = os.lstat(path)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o022 or not info.st_mode & 0o001):
            sys.exit(1)
        if path == "/":
            break
        path = os.path.dirname(path)
except OSError:
    sys.exit(1)
PY
}

# The same acceptance rules the app and host apply (lib/browser_bridge_app_ipc.dart:
# exact keys v and secret, v == 1, 64 lowercase hex; the file and every
# ancestor not a symlink, root-owned, no group or other write), plus a single
# link, so a hard link elsewhere cannot alias the secret.
browser_bridge_identity_valid() {
  python3 - "$1" <<'PY'
import json, os, re, stat, sys
path = sys.argv[1]

def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

try:
    info = os.lstat(path)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != 0 or info.st_mode & 0o022
            or not info.st_mode & 0o004
            or not 0 < info.st_size <= 4096):
        sys.exit(1)
    parent = os.path.dirname(path)
    while True:
        node = os.lstat(parent)
        if (not stat.S_ISDIR(node.st_mode) or node.st_uid != 0
                or node.st_mode & 0o022 or not node.st_mode & 0o001):
            sys.exit(1)
        if parent == "/":
            break
        parent = os.path.dirname(parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                 | getattr(os, "O_CLOEXEC", 0))
    try:
        opened = os.fstat(fd)
        if identity(opened) != identity(info):
            sys.exit(1)
        with os.fdopen(fd, "rb", closefd=False) as handle:
            payload = handle.read(4097)
        if (len(payload) != opened.st_size or not 0 < len(payload) <= 4096
                or identity(os.fstat(fd)) != identity(opened)
                or identity(os.lstat(path)) != identity(opened)):
            sys.exit(1)
    finally:
        os.close(fd)
    data = json.loads(payload.decode("utf-8"))
    if (type(data) is not dict or set(data) != {"v", "secret"}
            or type(data["v"]) is not int or data["v"] != 1
            or type(data["secret"]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", data["secret"]) is None):
        sys.exit(1)
except (OSError, ValueError):
    sys.exit(1)
PY
}

# Keeps a valid receipt byte for byte; refuses (does not replace) an unsafe or
# malformed one; otherwise creates one exclusively and records that this
# transaction created it, so cleanup() removes only what this run made.
install_browser_bridge_identity() {
  local dir="$BROWSER_BRIDGE_IDENTITY_DIR" file="$BROWSER_BRIDGE_IDENTITY_FILE"
  local tmp secret
  browser_bridge_identity_directory_valid "${dir%/*}" || return 1
  if [[ -e "$file" || -L "$file" ]]; then
    if browser_bridge_identity_valid "$file"; then
      log "Keeping the existing browser bridge identity receipt."
      return 0
    fi
    printf '[WINS-LINUX-INSTALL] ERROR: %s is not a root-owned, single-link, valid receipt. It was left untouched; inspect it, remove it, and run the installer again.\n' \
      "$file" >&2
    return 1
  fi
  if [[ ! -e "$dir" && ! -L "$dir" ]]; then
    install -d -o root -g root -m 0755 -- "$dir" || return 1
    browser_bridge_identity_dir_created=1
  fi
  browser_bridge_identity_directory_valid "$dir" || return 1
  secret="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
  [[ "$secret" =~ ^[0-9a-f]{64}$ ]] || return 1
  tmp="$(mktemp -- "$dir/.browser_bridge.identity.XXXXXX")" || return 1
  if ! { printf '{"v":1,"secret":"%s"}' "$secret" >"$tmp" \
      && chown root:root -- "$tmp" && chmod 0644 -- "$tmp"; }; then
    rm -f -- "$tmp"
    return 1
  fi
  # ln refuses an existing name, so the receipt is created exclusively.
  if ! ln -- "$tmp" "$file"; then
    rm -f -- "$tmp"
    return 1
  fi
  rm -f -- "$tmp"
  browser_bridge_identity_created=1
  browser_bridge_identity_valid "$file" || {
    printf '[WINS-LINUX-INSTALL] ERROR: the new browser bridge identity receipt failed validation.\n' >&2
    return 1
  }
}

install_linux_native_messaging() {
  local bundle_root="$1"
  local host_dir="$2"
  local host_path="$3"
  local chrome_dir="$4"
  local firefox_dir="$5"
  local edge_dir="$6"
  local use_system="$7"
  local overlay_root="${8:-}"
  local bundled_host bundled_installer packaged_chrome packaged_edge packaged_firefox
  local store_ids_out store_status=0 chrome_id edge_id staged_host
  local -a installer_args

  bundled_host="$bundle_root/$NATIVE_HOST_BUNDLE_REL"
  bundled_installer="$bundle_root/$NATIVE_HOST_INSTALLER_REL"
  packaged_chrome="$bundle_root/$NATIVE_HOST_CHROME_MANIFEST_REL"
  packaged_edge="$bundle_root/$NATIVE_HOST_EDGE_MANIFEST_REL"
  packaged_firefox="$bundle_root/$NATIVE_HOST_FIREFOX_MANIFEST_REL"
  staged_host="$host_path.new"

  require_native_host_identity_inputs "$bundle_root" || return 1
  restore_native_host_executable_modes "$bundle_root" || return 1
  command -v python3 >/dev/null 2>&1 || {
    printf '[WINS-LINUX-INSTALL] ERROR: python3 is required to register the native-messaging host.\n' >&2
    return 1
  }
  store_ids_out="$(read_native_host_store_ids "$bundle_root/$NATIVE_HOST_STORE_IDS_REL")" || store_status=$?
  if [[ "$store_status" -eq 78 ]]; then
    printf '[WINS-LINUX-INSTALL] ERROR: owner-blocked: packaged Edge store identity is absent or reused. Refusing to invent an Edge id.\n' >&2
    return 78
  fi
  if [[ "$store_status" -ne 0 ]]; then
    printf '[WINS-LINUX-INSTALL] ERROR: packaged native-host store identity is missing a Chrome id or is not an exact Chrome/Edge record.\n' >&2
    return 1
  fi
  chrome_id="$(printf '%s\n' "$store_ids_out" | sed -n '1p')"
  edge_id="$(printf '%s\n' "$store_ids_out" | sed -n '2p')"
  [[ -n "$chrome_id" && -n "$edge_id" && "$chrome_id" != "$edge_id" ]] || {
    printf '[WINS-LINUX-INSTALL] ERROR: owner-blocked: packaged Edge store identity is absent or reused. Refusing to invent an Edge id.\n' >&2
    return 78
  }

  assert_native_host_manifest_path "$packaged_chrome" "$host_path" || return 1
  assert_native_host_manifest_path "$packaged_edge" "$host_path" || return 1
  assert_native_host_manifest_path "$packaged_firefox" "$host_path" || return 1
  assert_native_host_chromium_origin "$packaged_chrome" "$chrome_id" || return 1
  assert_native_host_chromium_origin "$packaged_edge" "$edge_id" || return 1
  if cmp -s "$packaged_chrome" "$packaged_edge"; then
    printf '[WINS-LINUX-INSTALL] ERROR: owner-blocked: Chrome and Edge native-host manifests must be distinct.\n' >&2
    return 78
  fi

  assert_native_host_dest_safe "$overlay_root" "$host_dir" dir || return 1
  assert_native_host_dest_safe "$overlay_root" "$host_path" file || return 1
  assert_native_host_dest_safe "$overlay_root" "$staged_host" file || return 1
  assert_native_host_dest_safe "$overlay_root" "$chrome_dir" dir || return 1
  assert_native_host_dest_safe "$overlay_root" "$firefox_dir" dir || return 1
  assert_native_host_dest_safe "$overlay_root" "$edge_dir" dir || return 1
  assert_native_host_dest_safe "$overlay_root" "$chrome_dir/${NATIVE_HOST_NAME}.json" file || return 1
  assert_native_host_dest_safe "$overlay_root" "$firefox_dir/${NATIVE_HOST_NAME}.json" file || return 1
  assert_native_host_dest_safe "$overlay_root" "$edge_dir/${NATIVE_HOST_NAME}.json" file || return 1

  linux_native_host_overlay transaction "$overlay_root" \
    mkdir-p "$host_dir" \
    mkdir-p "$chrome_dir" \
    mkdir-p "$firefox_dir" \
    mkdir-p "$edge_dir" \
    install-file "$bundled_host" "$host_path" 0755 || return 1
  if [[ ! -f "$host_path" || -L "$host_path" || ! -x "$host_path" ]]; then
    printf '[WINS-LINUX-INSTALL] ERROR: installed native-messaging host is missing or not executable: %s\n' \
      "$host_path" >&2
    return 1
  fi

  installer_args=(
    --host-path "$host_path"
    --dest-dir "$host_dir"
    --require-installed-path "$host_path"
  )
  if [[ "$use_system" == 1 ]]; then
    installer_args+=(--system)
  fi

  # Chrome, Edge, and Firefox through the authenticated installed host. Edge uses
  # the distinct owner-issued store identity already packaged for extension receipts.
  "$bundled_installer" "${installer_args[@]}" --manifest-dir "$chrome_dir" chrome "$chrome_id" || {
    printf '[WINS-LINUX-INSTALL] ERROR: Chrome native-messaging registration failed.\n' >&2
    return 1
  }
  "$bundled_installer" "${installer_args[@]}" --manifest-dir "$edge_dir" edge "$edge_id" || {
    printf '[WINS-LINUX-INSTALL] ERROR: Edge native-messaging registration failed.\n' >&2
    return 1
  }
  "$bundled_installer" "${installer_args[@]}" --manifest-dir "$firefox_dir" firefox || {
    printf '[WINS-LINUX-INSTALL] ERROR: Firefox native-messaging registration failed.\n' >&2
    return 1
  }

  assert_native_host_manifest_path "$chrome_dir/${NATIVE_HOST_NAME}.json" "$host_path" || return 1
  assert_native_host_manifest_path "$edge_dir/${NATIVE_HOST_NAME}.json" "$host_path" || return 1
  assert_native_host_manifest_path "$firefox_dir/${NATIVE_HOST_NAME}.json" "$host_path" || return 1
  assert_native_host_chromium_origin "$chrome_dir/${NATIVE_HOST_NAME}.json" "$chrome_id" || return 1
  assert_native_host_chromium_origin "$edge_dir/${NATIVE_HOST_NAME}.json" "$edge_id" || return 1
  if cmp -s "$chrome_dir/${NATIVE_HOST_NAME}.json" "$edge_dir/${NATIVE_HOST_NAME}.json"; then
    printf '[WINS-LINUX-INSTALL] ERROR: Chrome and Edge native-host manifests must be distinct.\n' >&2
    return 1
  fi
}

write_native_host_delivery_fixture() {
  local origin="$1" bundle="$2" host_path="$3" chrome_id="$4"
  local edge_id="${5:-}"
  local dummy_host="$bundle/$NATIVE_HOST_BUNDLE_REL"
  mkdir -p \
    "$bundle/tools/native_messaging/host" \
    "$bundle/tools/native_messaging/manifests" \
    "$bundle/extension/tools" \
    "$bundle/extension/manifest"
  cp "$origin/tools/native_messaging/install_native_host.sh" \
    "$bundle/$NATIVE_HOST_INSTALLER_REL"
  cp "$origin/tools/native_messaging/native_host_layout.py" \
    "$bundle/$NATIVE_HOST_LAYOUT_REL"
  cp "$origin/tools/native_messaging/render_host_manifest.py" \
    "$bundle/$NATIVE_HOST_RENDERER_REL"
  cp "$origin/extension/tools/jsonc.py" "$bundle/$NATIVE_HOST_JSONC_REL"
  cp "$origin/extension/manifest/firefox.jsonc" \
    "$bundle/$NATIVE_HOST_FIREFOX_FRAGMENT_REL"
  python3 - "$dummy_host" <<'PY'
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.write_text(
    "#!/bin/sh\n"
    "exec python3 -c "
    "'import json,struct,sys;"
    "header=sys.stdin.buffer.read(4);"
    "n=struct.unpack(\"<I\",header)[0] if len(header)==4 else 0;"
    "sys.stdin.buffer.read(n);"
    "body=json.dumps({\"type\":\"hello\",\"protocolVersion\":1,"
    "\"platform\":\"test\",\"status\":\"app_not_running\"}).encode();"
    "sys.stdout.buffer.write(struct.pack(\"<I\",len(body))+body)'\n",
    encoding="ascii",
)
os.chmod(path, 0o755)
PY
  python3 - "$bundle/$NATIVE_HOST_STORE_IDS_REL" "$chrome_id" "$edge_id" "$host_path" \
    "$bundle/$NATIVE_HOST_CHROME_MANIFEST_REL" \
    "$bundle/$NATIVE_HOST_EDGE_MANIFEST_REL" \
    "$bundle/$NATIVE_HOST_FIREFOX_MANIFEST_REL" <<'PY'
import json
import pathlib
import sys

store_ids, chrome_id, edge_id, host_path, chrome_manifest, edge_manifest, firefox_manifest = sys.argv[1:]
record = {"chrome": chrome_id}
if edge_id:
    record["edge"] = edge_id
pathlib.Path(store_ids).write_text(
    json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n",
    encoding="ascii",
)
shared = {
    "name": "org.winsvpn.bridge",
    "description": "Win's VPN browser bridge",
    "path": host_path,
    "type": "stdio",
}
pathlib.Path(chrome_manifest).write_text(
    json.dumps({**shared, "allowed_origins": [f"chrome-extension://{chrome_id}/"]}, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n",
    encoding="ascii",
)
if edge_id:
    edge_origin = f"chrome-extension://{edge_id}/"
else:
    edge_origin = "chrome-extension://missing-edge-id/"
pathlib.Path(edge_manifest).write_text(
    json.dumps({**shared, "allowed_origins": [edge_origin]}, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n",
    encoding="ascii",
)
pathlib.Path(firefox_manifest).write_text(
    json.dumps({**shared, "allowed_extensions": ["companion@winsvpn.org"]}, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n",
    encoding="ascii",
)
PY
}

verify_installed_linux_native_messaging() {
  local prefix="${1:-}"
  local overlay_root="" bundle_root host_path chrome_dir firefox_dir edge_dir
  local store_ids_out store_status=0 chrome_id edge_id
  if [[ -n "$prefix" ]]; then
    overlay_root="$(normalize_overlay_prefix "$prefix")" || return 1
    bundle_root="$overlay_root$TARGET"
    host_path="$overlay_root$NATIVE_HOST_SYSTEM_PATH"
    chrome_dir="$overlay_root$NATIVE_HOST_CHROME_MANIFEST_DIR"
    firefox_dir="$overlay_root$NATIVE_HOST_FIREFOX_MANIFEST_DIR"
    edge_dir="$overlay_root$NATIVE_HOST_EDGE_MANIFEST_DIR"
    assert_native_host_dest_safe "$overlay_root" "$bundle_root/$NATIVE_HOST_STORE_IDS_REL" file || return 1
    assert_native_host_dest_safe "$overlay_root" "$host_path" file || return 1
    assert_native_host_dest_safe "$overlay_root" "$chrome_dir/${NATIVE_HOST_NAME}.json" file || return 1
    assert_native_host_dest_safe "$overlay_root" "$firefox_dir/${NATIVE_HOST_NAME}.json" file || return 1
    assert_native_host_dest_safe "$overlay_root" "$edge_dir/${NATIVE_HOST_NAME}.json" file || return 1
  else
    bundle_root="$TARGET"
    host_path="$NATIVE_HOST_SYSTEM_PATH"
    chrome_dir="$NATIVE_HOST_CHROME_MANIFEST_DIR"
    firefox_dir="$NATIVE_HOST_FIREFOX_MANIFEST_DIR"
    edge_dir="$NATIVE_HOST_EDGE_MANIFEST_DIR"
    assert_native_host_leaf_safe "$host_path" file || return 1
    assert_native_host_leaf_safe "$chrome_dir/${NATIVE_HOST_NAME}.json" file || return 1
    assert_native_host_leaf_safe "$firefox_dir/${NATIVE_HOST_NAME}.json" file || return 1
    assert_native_host_leaf_safe "$edge_dir/${NATIVE_HOST_NAME}.json" file || return 1
  fi
  store_ids_out="$(read_native_host_store_ids "$bundle_root/$NATIVE_HOST_STORE_IDS_REL")" || store_status=$?
  if [[ "$store_status" -eq 78 ]]; then
    printf '[WINS-LINUX-INSTALL] ERROR: owner-blocked: packaged Edge store identity is absent or reused. Refusing to invent an Edge id.\n' >&2
    return 78
  fi
  if [[ "$store_status" -ne 0 ]]; then
    printf '[WINS-LINUX-INSTALL] ERROR: packaged native-host store identity is missing a Chrome id or is not an exact Chrome/Edge record.\n' >&2
    return 1
  fi
  chrome_id="$(printf '%s\n' "$store_ids_out" | sed -n '1p')"
  edge_id="$(printf '%s\n' "$store_ids_out" | sed -n '2p')"
  [[ -n "$chrome_id" && -n "$edge_id" && "$chrome_id" != "$edge_id" ]] || {
    printf '[WINS-LINUX-INSTALL] ERROR: owner-blocked: packaged Edge store identity is absent or reused. Refusing to invent an Edge id.\n' >&2
    return 78
  }
  [[ -f "$host_path" && ! -L "$host_path" && -x "$host_path" ]] || {
    printf '[WINS-LINUX-INSTALL] ERROR: installed native-messaging host is missing or not executable: %s\n' \
      "$host_path" >&2
    return 1
  }
  assert_native_host_manifest_path \
    "$chrome_dir/${NATIVE_HOST_NAME}.json" "$host_path" || return 1
  assert_native_host_manifest_path \
    "$edge_dir/${NATIVE_HOST_NAME}.json" "$host_path" || return 1
  assert_native_host_manifest_path \
    "$firefox_dir/${NATIVE_HOST_NAME}.json" "$host_path" || return 1
  assert_native_host_chromium_origin \
    "$chrome_dir/${NATIVE_HOST_NAME}.json" "$chrome_id" || return 1
  assert_native_host_chromium_origin \
    "$edge_dir/${NATIVE_HOST_NAME}.json" "$edge_id" || return 1
  if cmp -s \
      "$chrome_dir/${NATIVE_HOST_NAME}.json" \
      "$edge_dir/${NATIVE_HOST_NAME}.json"
  then
    printf '[WINS-LINUX-INSTALL] ERROR: Chrome and Edge native-host manifests must be distinct.\n' >&2
    return 1
  fi
  if [[ -n "$overlay_root" ]]; then
    printf '[WINS-LINUX-INSTALL] native-host delivery verified for Chrome, Edge, and Firefox (overlay %s)\n' \
      "$overlay_root"
  else
    printf '[WINS-LINUX-INSTALL] native-host delivery verified for Chrome, Edge, and Firefox\n'
  fi
  return 0
}

run_native_host_uninstall() {
  local prefix="${1:-}"
  local overlay_root="" host_path chrome_manifest firefox_manifest edge_manifest user_home
  if [[ -n "$prefix" ]]; then
    overlay_root="$(normalize_overlay_prefix "$prefix")" || return 1
    host_path="$overlay_root$NATIVE_HOST_SYSTEM_PATH"
    chrome_manifest="$overlay_root$NATIVE_HOST_CHROME_MANIFEST_DIR/${NATIVE_HOST_NAME}.json"
    firefox_manifest="$overlay_root$NATIVE_HOST_FIREFOX_MANIFEST_DIR/${NATIVE_HOST_NAME}.json"
    edge_manifest="$overlay_root$NATIVE_HOST_EDGE_MANIFEST_DIR/${NATIVE_HOST_NAME}.json"
    uninstall_linux_native_messaging \
      "$overlay_root" "$host_path" "$chrome_manifest" "$firefox_manifest" "$edge_manifest" \
      "$overlay_root/home" || return 1
    printf '[WINS-LINUX-INSTALL] self-test: native-host uninstall complete (prefix %s)\n' "$overlay_root"
    return 0
  fi
  if [[ "${EUID}" -ne 0 ]]; then
    command -v sudo >/dev/null 2>&1 || {
      printf '[WINS-LINUX-INSTALL] ERROR: native-host uninstall requires root or sudo.\n' >&2
      return 1
    }
    exec sudo -- "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/$(basename "${BASH_SOURCE[0]}")" --uninstall-native-host
  fi
  user_home="${SUDO_USER:+$(getent passwd "$SUDO_USER" | cut -d: -f6)}"
  uninstall_linux_native_messaging \
    "" \
    "$NATIVE_HOST_SYSTEM_PATH" \
    "$NATIVE_HOST_CHROME_MANIFEST_DIR/${NATIVE_HOST_NAME}.json" \
    "$NATIVE_HOST_FIREFOX_MANIFEST_DIR/${NATIVE_HOST_NAME}.json" \
    "$NATIVE_HOST_EDGE_MANIFEST_DIR/${NATIVE_HOST_NAME}.json" \
    "${user_home:-$HOME}" || return 1
  printf '[WINS-LINUX-INSTALL] native-host uninstall complete\n'
  return 0
}

native_host_registration_untouched() {
  local root="$1"
  local host="$root/usr/lib/wins-vpn/wins_bridge_host"
  local chrome="$root/etc/opt/chrome/native-messaging-hosts/${NATIVE_HOST_NAME}.json"
  local firefox="$root/usr/lib/mozilla/native-messaging-hosts/${NATIVE_HOST_NAME}.json"
  local edge="$root/etc/opt/edge/native-messaging-hosts/${NATIVE_HOST_NAME}.json"
  if [[ -e "$host" || -L "$host" || \
        -e "$chrome" || -L "$chrome" || \
        -e "$firefox" || -L "$firefox" || \
        -e "$edge" || -L "$edge" ]]; then
    return 1
  fi
  return 0
}

run_native_host_delivery_self_test() {
  local prefix="${1:-}" origin self_dir fail=0
  [[ -n "$prefix" ]] || {
    printf '[WINS-LINUX-INSTALL] ERROR: --self-test-native-host-delivery requires a prefix directory\n' >&2
    return 65
  }
  mkdir -p "$prefix"
  prefix="$(normalize_overlay_prefix "$prefix")" || return 65
  self_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
  if [[ -f "$self_dir/$NATIVE_HOST_INSTALLER_REL" ]]; then
    origin="$self_dir"
  elif [[ -f "$self_dir/../../$NATIVE_HOST_INSTALLER_REL" ]]; then
    origin="$(cd "$self_dir/../.." && pwd -P)"
  else
    printf '[WINS-LINUX-INSTALL] ERROR: cannot locate native-host installer sources beside install.sh\n' >&2
    return 65
  fi

  local chrome_id="abcdefghijklmnopabcdefghijklmnop"
  local edge_id="ponmlkjihgfedcbaponmlkjihgfedcba"
  local happy="$prefix/happy"
  local bundle="$happy/bundle"
  local host_dir="$happy/usr/lib/wins-vpn"
  local host_path="$host_dir/wins_bridge_host"
  local chrome_dir="$happy/etc/opt/chrome/native-messaging-hosts"
  local firefox_dir="$happy/usr/lib/mozilla/native-messaging-hosts"
  local edge_dir="$happy/etc/opt/edge/native-messaging-hosts"

  write_native_host_delivery_fixture "$origin" "$bundle" "$host_path" "$chrome_id" "$edge_id"
  find "$bundle" -type f -exec chmod 0644 {} +
  if [[ -x "$bundle/$NATIVE_HOST_BUNDLE_REL" || -x "$bundle/$NATIVE_HOST_INSTALLER_REL" ]]; then
    printf '[WINS-LINUX-INSTALL] ERROR: chmod 0644 left native-host files executable\n' >&2
    fail=1
  fi
  if ! restore_native_host_executable_modes "$bundle"; then
    fail=1
  elif [[ ! -x "$bundle/$NATIVE_HOST_BUNDLE_REL" || ! -x "$bundle/$NATIVE_HOST_INSTALLER_REL" ]]; then
    printf '[WINS-LINUX-INSTALL] ERROR: native-host executable mode was not restored\n' >&2
    fail=1
  else
    printf '[WINS-LINUX-INSTALL] self-test: executable mode restored for host and installer\n'
  fi

  mkdir -p "$host_dir" "$chrome_dir" "$firefox_dir" "$edge_dir"
  # Previous registration that rollback must restore.
  printf 'old-host' > "$host_path"
  chmod 0755 "$host_path"
  printf '{"path":"/old/chrome"}\n' > "$chrome_dir/${NATIVE_HOST_NAME}.json"
  printf '{"path":"/old/firefox"}\n' > "$firefox_dir/${NATIVE_HOST_NAME}.json"
  printf '{"path":"/old/edge"}\n' > "$edge_dir/${NATIVE_HOST_NAME}.json"
  local backup="$happy/backup"
  mkdir -p "$backup"
  snapshot_native_host_path "$host_path" "$backup/host"
  snapshot_native_host_path "$chrome_dir/${NATIVE_HOST_NAME}.json" "$backup/chrome.json"
  snapshot_native_host_path "$firefox_dir/${NATIVE_HOST_NAME}.json" "$backup/firefox.json"
  snapshot_native_host_path "$edge_dir/${NATIVE_HOST_NAME}.json" "$backup/edge.json"

  if ! install_linux_native_messaging "$bundle" "$host_dir" "$host_path" "$chrome_dir" "$firefox_dir" "$edge_dir" 0 "$happy"; then
    printf '[WINS-LINUX-INSTALL] ERROR: native-host delivery failed on the isolated prefix\n' >&2
    fail=1
  else
    if [[ ! -x "$host_path" ]]; then
      printf '[WINS-LINUX-INSTALL] ERROR: installed host is not executable\n' >&2
      fail=1
    fi
    if ! assert_native_host_manifest_path "$chrome_dir/${NATIVE_HOST_NAME}.json" "$host_path"; then
      fail=1
    fi
    if ! assert_native_host_manifest_path "$firefox_dir/${NATIVE_HOST_NAME}.json" "$host_path"; then
      fail=1
    fi
    if ! assert_native_host_manifest_path "$edge_dir/${NATIVE_HOST_NAME}.json" "$host_path"; then
      fail=1
    fi
    if ! assert_native_host_chromium_origin "$chrome_dir/${NATIVE_HOST_NAME}.json" "$chrome_id"; then
      fail=1
    fi
    if ! assert_native_host_chromium_origin "$edge_dir/${NATIVE_HOST_NAME}.json" "$edge_id"; then
      fail=1
    fi
    printf '[WINS-LINUX-INSTALL] self-test: Chrome, Firefox, and Edge registered at %s\n' "$host_path"
  fi

  if ! restore_linux_native_messaging \
      "$happy" \
      "$host_path" "$backup/host" \
      "$chrome_dir/${NATIVE_HOST_NAME}.json" "$backup/chrome.json" \
      "$firefox_dir/${NATIVE_HOST_NAME}.json" "$backup/firefox.json" \
      "$edge_dir/${NATIVE_HOST_NAME}.json" "$backup/edge.json"; then
    printf '[WINS-LINUX-INSTALL] ERROR: native-host rollback of a successful delivery failed\n' >&2
    fail=1
  else
    if [[ "$(cat "$host_path")" != "old-host" ]]; then
      printf '[WINS-LINUX-INSTALL] ERROR: native-host rollback did not restore the previous host\n' >&2
      fail=1
    fi
    if ! grep -q '/old/chrome' "$chrome_dir/${NATIVE_HOST_NAME}.json"; then
      printf '[WINS-LINUX-INSTALL] ERROR: native-host rollback did not restore the Chrome manifest\n' >&2
      fail=1
    fi
    if ! grep -q '/old/firefox' "$firefox_dir/${NATIVE_HOST_NAME}.json"; then
      printf '[WINS-LINUX-INSTALL] ERROR: native-host rollback did not restore the Firefox manifest\n' >&2
      fail=1
    fi
    if ! grep -q '/old/edge' "$edge_dir/${NATIVE_HOST_NAME}.json"; then
      printf '[WINS-LINUX-INSTALL] ERROR: native-host rollback did not restore the Edge manifest\n' >&2
      fail=1
    fi
    printf '[WINS-LINUX-INSTALL] self-test: native-host rollback restored previous registration\n'
    printf '[WINS-LINUX-INSTALL] self-test: native-host rollback restored the Firefox manifest\n'
  fi

  local wrong="$prefix/wrong-path"
  local wrong_bundle="$wrong/bundle"
  local wrong_host_dir="$wrong/usr/lib/wins-vpn"
  local wrong_host_path="$wrong_host_dir/wins_bridge_host"
  local wrong_chrome="$wrong/etc/opt/chrome/native-messaging-hosts"
  local wrong_firefox="$wrong/usr/lib/mozilla/native-messaging-hosts"
  local wrong_edge="$wrong/etc/opt/edge/native-messaging-hosts"
  write_native_host_delivery_fixture "$origin" "$wrong_bundle" "$wrong_host_path" "$chrome_id" "$edge_id"
  restore_native_host_executable_modes "$wrong_bundle"
  python3 - "$wrong_bundle/$NATIVE_HOST_CHROME_MANIFEST_REL" <<'PY'
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
document = json.loads(path.read_text(encoding="ascii"))
document["path"] = "/tmp/wrong/wins_bridge_host"
path.write_text(json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n", encoding="ascii")
PY
  mkdir -p "$wrong_host_dir" "$wrong_chrome" "$wrong_firefox" "$wrong_edge"
  if install_linux_native_messaging "$wrong_bundle" "$wrong_host_dir" "$wrong_host_path" "$wrong_chrome" "$wrong_firefox" "$wrong_edge" 0 "$wrong"; then
    printf '[WINS-LINUX-INSTALL] ERROR: wrong packaged host path was accepted\n' >&2
    fail=1
  elif ! native_host_registration_untouched "$wrong"; then
    printf '[WINS-LINUX-INSTALL] ERROR: wrong-path rejection still wrote the host or live manifests\n' >&2
    fail=1
  else
    printf '[WINS-LINUX-INSTALL] self-test: wrong packaged host path was rejected\n'
  fi

  local require_wrong="$prefix/require-path"
  write_native_host_delivery_fixture "$origin" "$require_wrong/bundle" \
    "$require_wrong/usr/lib/wins-vpn/wins_bridge_host" "$chrome_id" "$edge_id"
  restore_native_host_executable_modes "$require_wrong/bundle"
  mkdir -p "$require_wrong/usr/lib/wins-vpn" \
    "$require_wrong/etc/opt/chrome/native-messaging-hosts" \
    "$require_wrong/usr/lib/mozilla/native-messaging-hosts" \
    "$require_wrong/etc/opt/edge/native-messaging-hosts"
  if "$require_wrong/bundle/$NATIVE_HOST_INSTALLER_REL" \
      --host-path "$require_wrong/bundle/$NATIVE_HOST_BUNDLE_REL" \
      --dest-dir "$require_wrong/tmp-host" \
      --manifest-dir "$require_wrong/etc/opt/chrome/native-messaging-hosts" \
      --require-installed-path "$require_wrong/usr/lib/wins-vpn/wins_bridge_host" \
      chrome "$chrome_id"
  then
    printf '[WINS-LINUX-INSTALL] ERROR: installer accepted a dest-dir that was not the required path\n' >&2
    fail=1
  else
    printf '[WINS-LINUX-INSTALL] self-test: installer rejected a host path that was not the required installed path\n'
  fi

  local missing="$prefix/missing-edge"
  write_native_host_delivery_fixture "$origin" "$missing/bundle" \
    "$missing/usr/lib/wins-vpn/wins_bridge_host" "$chrome_id"
  restore_native_host_executable_modes "$missing/bundle"
  mkdir -p "$missing/usr/lib/wins-vpn" \
    "$missing/etc/opt/chrome/native-messaging-hosts" \
    "$missing/usr/lib/mozilla/native-messaging-hosts" \
    "$missing/etc/opt/edge/native-messaging-hosts"
  if install_linux_native_messaging \
      "$missing/bundle" \
      "$missing/usr/lib/wins-vpn" \
      "$missing/usr/lib/wins-vpn/wins_bridge_host" \
      "$missing/etc/opt/chrome/native-messaging-hosts" \
      "$missing/usr/lib/mozilla/native-messaging-hosts" \
      "$missing/etc/opt/edge/native-messaging-hosts" \
      0 \
      "$missing"
  then
    printf '[WINS-LINUX-INSTALL] ERROR: missing Edge store identity was accepted\n' >&2
    fail=1
  elif ! native_host_registration_untouched "$missing"; then
    printf '[WINS-LINUX-INSTALL] ERROR: owner-blocked missing Edge identity still wrote the host or live manifests\n' >&2
    fail=1
  else
    printf '[WINS-LINUX-INSTALL] self-test: missing Edge store identity was owner-blocked\n'
    printf '[WINS-LINUX-INSTALL] self-test: owner-blocked missing Edge identity left host and manifests untouched\n'
  fi

  local reused="$prefix/reused-edge"
  write_native_host_delivery_fixture "$origin" "$reused/bundle" \
    "$reused/usr/lib/wins-vpn/wins_bridge_host" "$chrome_id" "$chrome_id"
  restore_native_host_executable_modes "$reused/bundle"
  mkdir -p "$reused/usr/lib/wins-vpn" \
    "$reused/etc/opt/chrome/native-messaging-hosts" \
    "$reused/usr/lib/mozilla/native-messaging-hosts" \
    "$reused/etc/opt/edge/native-messaging-hosts"
  if install_linux_native_messaging \
      "$reused/bundle" \
      "$reused/usr/lib/wins-vpn" \
      "$reused/usr/lib/wins-vpn/wins_bridge_host" \
      "$reused/etc/opt/chrome/native-messaging-hosts" \
      "$reused/usr/lib/mozilla/native-messaging-hosts" \
      "$reused/etc/opt/edge/native-messaging-hosts" \
      0 \
      "$reused"
  then
    printf '[WINS-LINUX-INSTALL] ERROR: reused Chrome/Edge store identity was accepted\n' >&2
    fail=1
  elif ! native_host_registration_untouched "$reused"; then
    printf '[WINS-LINUX-INSTALL] ERROR: owner-blocked reused Edge identity still wrote the host or live manifests\n' >&2
    fail=1
  else
    printf '[WINS-LINUX-INSTALL] self-test: reused Chrome/Edge store identity was owner-blocked\n'
    printf '[WINS-LINUX-INSTALL] self-test: owner-blocked reused Edge identity left host and manifests untouched\n'
  fi

  local per_user="$prefix/per-user"
  local per_home="$per_user/home"
  local per_host_dir="$per_user/usr/lib/wins-vpn"
  local per_host_path="$per_host_dir/wins_bridge_host"
  local per_chrome="$per_home/$NATIVE_HOST_CHROME_USER_REL"
  local per_firefox="$per_home/$NATIVE_HOST_FIREFOX_USER_REL"
  local per_edge="$per_home/$NATIVE_HOST_EDGE_USER_REL"
  write_native_host_delivery_fixture "$origin" "$per_user/bundle" "$per_host_path" "$chrome_id" "$edge_id"
  restore_native_host_executable_modes "$per_user/bundle"
  mkdir -p "$per_host_dir" "$per_chrome" "$per_firefox" "$per_edge"
  if ! HOME="$per_home" install_linux_native_messaging \
      "$per_user/bundle" "$per_host_dir" "$per_host_path" \
      "$per_chrome" "$per_firefox" "$per_edge" 0 "$per_user"
  then
    printf '[WINS-LINUX-INSTALL] ERROR: per-user Edge native-host delivery failed\n' >&2
    fail=1
  elif ! assert_native_host_manifest_path "$per_edge/${NATIVE_HOST_NAME}.json" "$per_host_path"; then
    fail=1
  elif ! assert_native_host_chromium_origin "$per_edge/${NATIVE_HOST_NAME}.json" "$edge_id"; then
    fail=1
  elif [[ -e "$per_user$NATIVE_HOST_EDGE_MANIFEST_DIR/${NATIVE_HOST_NAME}.json" ]]; then
    printf '[WINS-LINUX-INSTALL] ERROR: per-user Edge delivery wrote the system Edge dest\n' >&2
    fail=1
  else
    printf '[WINS-LINUX-INSTALL] self-test: per-user Edge registered at %s\n' \
      "$per_home/$NATIVE_HOST_EDGE_USER_REL/${NATIVE_HOST_NAME}.json"
  fi

  local remove="$prefix/uninstall"
  local remove_host_dir="$remove$NATIVE_HOST_SYSTEM_DIR"
  local remove_host_path="$remove$NATIVE_HOST_SYSTEM_PATH"
  local remove_chrome="$remove$NATIVE_HOST_CHROME_MANIFEST_DIR"
  local remove_firefox="$remove$NATIVE_HOST_FIREFOX_MANIFEST_DIR"
  local remove_edge="$remove$NATIVE_HOST_EDGE_MANIFEST_DIR"
  local remove_user_chrome="$remove/home/$NATIVE_HOST_CHROME_USER_REL"
  local remove_user_firefox="$remove/home/$NATIVE_HOST_FIREFOX_USER_REL"
  local remove_user_edge="$remove/home/$NATIVE_HOST_EDGE_USER_REL"
  # Derived from the relative constants, never spelled out: a literal home
  # directory path in a shipped script matches the release privacy scan's
  # local-user-home pattern, which refuses the whole archive.
  local remove_user_host="$remove/home/$NATIVE_HOST_USER_HOST_REL"
  local remove_user_host_dir="${remove_user_host%/*}"
  write_native_host_delivery_fixture "$origin" "$remove/bundle" "$remove_host_path" "$chrome_id" "$edge_id"
  restore_native_host_executable_modes "$remove/bundle"
  mkdir -p "$remove_host_dir" "$remove_chrome" "$remove_firefox" "$remove_edge" \
    "$remove_user_chrome" "$remove_user_firefox" "$remove_user_edge" "$remove_user_host_dir"
  if ! install_linux_native_messaging \
      "$remove/bundle" "$remove_host_dir" "$remove_host_path" \
      "$remove_chrome" "$remove_firefox" "$remove_edge" 0 "$remove"
  then
    printf '[WINS-LINUX-INSTALL] ERROR: uninstall rehearsal delivery failed\n' >&2
    fail=1
  else
    printf '{"path":"/old/user-chrome"}\n' > "$remove_user_chrome/${NATIVE_HOST_NAME}.json"
    printf '{"path":"/old/user-firefox"}\n' > "$remove_user_firefox/${NATIVE_HOST_NAME}.json"
    printf '{"path":"/old/user-edge"}\n' > "$remove_user_edge/${NATIVE_HOST_NAME}.json"
    printf 'user-host\n' > "$remove_user_host"
    printf '{"path":"/keep-me"}\n' > "$remove_edge/other.json"
    if ! run_native_host_uninstall "$remove"; then
      printf '[WINS-LINUX-INSTALL] ERROR: native-host uninstall failed\n' >&2
      fail=1
    elif [[ -e "$remove_host_path" || \
            -e "$remove_chrome/${NATIVE_HOST_NAME}.json" || \
            -e "$remove_firefox/${NATIVE_HOST_NAME}.json" || \
            -e "$remove_edge/${NATIVE_HOST_NAME}.json" || \
            -e "$remove_user_chrome/${NATIVE_HOST_NAME}.json" || \
            -e "$remove_user_firefox/${NATIVE_HOST_NAME}.json" || \
            -e "$remove_user_edge/${NATIVE_HOST_NAME}.json" || \
            -e "$remove_user_host" ]]; then
      printf '[WINS-LINUX-INSTALL] ERROR: native-host uninstall left registration behind\n' >&2
      fail=1
    elif [[ ! -f "$remove_edge/other.json" ]]; then
      printf '[WINS-LINUX-INSTALL] ERROR: native-host uninstall removed an unrelated file\n' >&2
      fail=1
    else
      printf '[WINS-LINUX-INSTALL] self-test: native-host uninstall removed system and per-user Edge registration\n'
      printf '[WINS-LINUX-INSTALL] self-test: native-host uninstall removed system and per-user Chrome, Firefox, and Edge registration\n'
    fi
  fi

  local placeholder="$prefix/placeholder-edge"
  write_native_host_delivery_fixture "$origin" "$placeholder/bundle" \
    "$placeholder/usr/lib/wins-vpn/wins_bridge_host" "$chrome_id" "$edge_id"
  restore_native_host_executable_modes "$placeholder/bundle"
  mkdir -p "$placeholder/usr/lib/wins-vpn" \
    "$placeholder/etc/opt/chrome/native-messaging-hosts" \
    "$placeholder/usr/lib/mozilla/native-messaging-hosts" \
    "$placeholder/etc/opt/edge/native-messaging-hosts"
  python3 - "$placeholder/bundle/$NATIVE_HOST_STORE_IDS_REL" "$chrome_id" <<'PY'
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
chrome_id = sys.argv[2]
path.write_text(
    json.dumps({"chrome": chrome_id, "edge": "PLACEHOLDER_EDGE_EXTENSION_ID"}, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n",
    encoding="ascii",
)
PY
  if install_linux_native_messaging \
      "$placeholder/bundle" \
      "$placeholder/usr/lib/wins-vpn" \
      "$placeholder/usr/lib/wins-vpn/wins_bridge_host" \
      "$placeholder/etc/opt/chrome/native-messaging-hosts" \
      "$placeholder/usr/lib/mozilla/native-messaging-hosts" \
      "$placeholder/etc/opt/edge/native-messaging-hosts" \
      0 \
      "$placeholder"
  then
    printf '[WINS-LINUX-INSTALL] ERROR: placeholder Edge store identity was accepted\n' >&2
    fail=1
  elif ! native_host_registration_untouched "$placeholder"; then
    printf '[WINS-LINUX-INSTALL] ERROR: placeholder Edge identity still wrote the host or live manifests\n' >&2
    fail=1
  else
    printf '[WINS-LINUX-INSTALL] self-test: placeholder Edge store identity was owner-blocked\n'
    printf '[WINS-LINUX-INSTALL] self-test: owner-blocked placeholder Edge identity left host and manifests untouched\n'
  fi

  local extra_keys="$prefix/extra-keys"
  write_native_host_delivery_fixture "$origin" "$extra_keys/bundle" \
    "$extra_keys/usr/lib/wins-vpn/wins_bridge_host" "$chrome_id" "$edge_id"
  restore_native_host_executable_modes "$extra_keys/bundle"
  mkdir -p "$extra_keys/usr/lib/wins-vpn" \
    "$extra_keys/etc/opt/chrome/native-messaging-hosts" \
    "$extra_keys/usr/lib/mozilla/native-messaging-hosts" \
    "$extra_keys/etc/opt/edge/native-messaging-hosts"
  python3 - "$extra_keys/bundle/$NATIVE_HOST_STORE_IDS_REL" "$chrome_id" "$edge_id" <<'PY'
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
path.write_text(
    json.dumps({"chrome": sys.argv[2], "edge": sys.argv[3], "extra": "nope"}, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n",
    encoding="ascii",
)
PY
  if install_linux_native_messaging \
      "$extra_keys/bundle" \
      "$extra_keys/usr/lib/wins-vpn" \
      "$extra_keys/usr/lib/wins-vpn/wins_bridge_host" \
      "$extra_keys/etc/opt/chrome/native-messaging-hosts" \
      "$extra_keys/usr/lib/mozilla/native-messaging-hosts" \
      "$extra_keys/etc/opt/edge/native-messaging-hosts" \
      0 \
      "$extra_keys"
  then
    printf '[WINS-LINUX-INSTALL] ERROR: extra JSON keys in store identity were accepted\n' >&2
    fail=1
  elif ! native_host_registration_untouched "$extra_keys"; then
    printf '[WINS-LINUX-INSTALL] ERROR: extra JSON keys still wrote the host or live manifests\n' >&2
    fail=1
  else
    printf '[WINS-LINUX-INSTALL] self-test: extra JSON keys in store identity were rejected\n'
  fi

  local duplicate_keys="$prefix/duplicate-keys"
  write_native_host_delivery_fixture "$origin" "$duplicate_keys/bundle" \
    "$duplicate_keys/usr/lib/wins-vpn/wins_bridge_host" "$chrome_id" "$edge_id"
  restore_native_host_executable_modes "$duplicate_keys/bundle"
  mkdir -p "$duplicate_keys/usr/lib/wins-vpn" \
    "$duplicate_keys/etc/opt/chrome/native-messaging-hosts" \
    "$duplicate_keys/usr/lib/mozilla/native-messaging-hosts" \
    "$duplicate_keys/etc/opt/edge/native-messaging-hosts"
  python3 - "$duplicate_keys/bundle/$NATIVE_HOST_STORE_IDS_REL" "$chrome_id" "$edge_id" <<'PY'
import pathlib
import sys
pathlib.Path(sys.argv[1]).write_text(
    '{"chrome":"%s","edge":"%s","edge":"%s"}\n' % (sys.argv[2], sys.argv[3], sys.argv[3]),
    encoding="ascii",
)
PY
  if install_linux_native_messaging \
      "$duplicate_keys/bundle" \
      "$duplicate_keys/usr/lib/wins-vpn" \
      "$duplicate_keys/usr/lib/wins-vpn/wins_bridge_host" \
      "$duplicate_keys/etc/opt/chrome/native-messaging-hosts" \
      "$duplicate_keys/usr/lib/mozilla/native-messaging-hosts" \
      "$duplicate_keys/etc/opt/edge/native-messaging-hosts" \
      0 \
      "$duplicate_keys"
  then
    printf '[WINS-LINUX-INSTALL] ERROR: duplicate JSON keys in store identity were accepted\n' >&2
    fail=1
  elif ! native_host_registration_untouched "$duplicate_keys"; then
    printf '[WINS-LINUX-INSTALL] ERROR: duplicate JSON keys still wrote the host or live manifests\n' >&2
    fail=1
  else
    printf '[WINS-LINUX-INSTALL] self-test: duplicate JSON keys in store identity were rejected\n'
  fi

  local mid_edge="$prefix/mid-edge-fail"
  local mid_host_dir="$mid_edge/usr/lib/wins-vpn"
  local mid_host_path="$mid_host_dir/wins_bridge_host"
  local mid_chrome="$mid_edge/etc/opt/chrome/native-messaging-hosts"
  local mid_firefox="$mid_edge/usr/lib/mozilla/native-messaging-hosts"
  local mid_edge_dir="$mid_edge/etc/opt/edge/native-messaging-hosts"
  write_native_host_delivery_fixture "$origin" "$mid_edge/bundle" "$mid_host_path" "$chrome_id" "$edge_id"
  restore_native_host_executable_modes "$mid_edge/bundle"
  mkdir -p "$mid_host_dir" "$mid_chrome" "$mid_firefox" "$mid_edge_dir"
  printf 'old-host' > "$mid_host_path"
  chmod 0755 "$mid_host_path"
  printf '{"path":"/old/chrome"}\n' > "$mid_chrome/${NATIVE_HOST_NAME}.json"
  printf '{"path":"/old/firefox"}\n' > "$mid_firefox/${NATIVE_HOST_NAME}.json"
  printf '{"path":"/old/edge"}\n' > "$mid_edge_dir/${NATIVE_HOST_NAME}.json"
  local mid_backup="$mid_edge/backup"
  mkdir -p "$mid_backup"
  snapshot_native_host_path "$mid_host_path" "$mid_backup/host"
  snapshot_native_host_path "$mid_chrome/${NATIVE_HOST_NAME}.json" "$mid_backup/chrome.json"
  snapshot_native_host_path "$mid_firefox/${NATIVE_HOST_NAME}.json" "$mid_backup/firefox.json"
  snapshot_native_host_path "$mid_edge_dir/${NATIVE_HOST_NAME}.json" "$mid_backup/edge.json"
  chmod a-w "$mid_edge_dir"
  if install_linux_native_messaging \
      "$mid_edge/bundle" "$mid_host_dir" "$mid_host_path" \
      "$mid_chrome" "$mid_firefox" "$mid_edge_dir" 0 "$mid_edge"
  then
    chmod u+w "$mid_edge_dir" 2>/dev/null || true
    printf '[WINS-LINUX-INSTALL] ERROR: Edge registration succeeded against a write-blocked dest\n' >&2
    fail=1
  else
    chmod u+w "$mid_edge_dir"
    if ! restore_linux_native_messaging \
        "$mid_edge" \
        "$mid_host_path" "$mid_backup/host" \
        "$mid_chrome/${NATIVE_HOST_NAME}.json" "$mid_backup/chrome.json" \
        "$mid_firefox/${NATIVE_HOST_NAME}.json" "$mid_backup/firefox.json" \
        "$mid_edge_dir/${NATIVE_HOST_NAME}.json" "$mid_backup/edge.json"
    then
      printf '[WINS-LINUX-INSTALL] ERROR: mid-Edge failure rollback failed\n' >&2
      fail=1
    elif [[ "$(cat "$mid_host_path")" != "old-host" ]]; then
      printf '[WINS-LINUX-INSTALL] ERROR: mid-Edge failure rollback did not restore the previous host\n' >&2
      fail=1
    elif ! grep -q '/old/chrome' "$mid_chrome/${NATIVE_HOST_NAME}.json"; then
      printf '[WINS-LINUX-INSTALL] ERROR: mid-Edge failure rollback did not restore the Chrome manifest\n' >&2
      fail=1
    elif ! grep -q '/old/firefox' "$mid_firefox/${NATIVE_HOST_NAME}.json"; then
      printf '[WINS-LINUX-INSTALL] ERROR: mid-Edge failure rollback did not restore the Firefox manifest\n' >&2
      fail=1
    elif ! grep -q '/old/edge' "$mid_edge_dir/${NATIVE_HOST_NAME}.json"; then
      printf '[WINS-LINUX-INSTALL] ERROR: mid-Edge failure rollback did not restore the Edge manifest\n' >&2
      fail=1
    else
      printf '[WINS-LINUX-INSTALL] self-test: native-host rollback restored a mid-Edge failure\n'
    fi
  fi

  local symlink_dest="$prefix/symlink-dest"
  local symlink_target="$prefix/symlink-target"
  write_native_host_delivery_fixture "$origin" "$symlink_dest/bundle" \
    "$symlink_dest/usr/lib/wins-vpn/wins_bridge_host" "$chrome_id" "$edge_id"
  restore_native_host_executable_modes "$symlink_dest/bundle"
  mkdir -p "$symlink_dest/usr/lib/wins-vpn" \
    "$symlink_dest/etc/opt/chrome/native-messaging-hosts" \
    "$symlink_dest/usr/lib/mozilla/native-messaging-hosts" \
    "$symlink_dest/etc/opt/edge/native-messaging-hosts" \
    "$symlink_target"
  printf 'outside-host\n' > "$symlink_target/wins_bridge_host"
  ln -s "$symlink_target/wins_bridge_host" "$symlink_dest/usr/lib/wins-vpn/wins_bridge_host"
  if install_linux_native_messaging \
      "$symlink_dest/bundle" \
      "$symlink_dest/usr/lib/wins-vpn" \
      "$symlink_dest/usr/lib/wins-vpn/wins_bridge_host" \
      "$symlink_dest/etc/opt/chrome/native-messaging-hosts" \
      "$symlink_dest/usr/lib/mozilla/native-messaging-hosts" \
      "$symlink_dest/etc/opt/edge/native-messaging-hosts" \
      0 \
      "$symlink_dest"
  then
    printf '[WINS-LINUX-INSTALL] ERROR: preexisting native-host symlink dest was accepted\n' >&2
    fail=1
  elif [[ "$(cat "$symlink_target/wins_bridge_host")" != "outside-host" ]]; then
    printf '[WINS-LINUX-INSTALL] ERROR: preexisting native-host symlink dest mutated the target\n' >&2
    fail=1
  else
    printf '[WINS-LINUX-INSTALL] self-test: preexisting native-host symlink dest was refused\n'
  fi

  local dir_dest="$prefix/directory-dest"
  write_native_host_delivery_fixture "$origin" "$dir_dest/bundle" \
    "$dir_dest/usr/lib/wins-vpn/wins_bridge_host" "$chrome_id" "$edge_id"
  restore_native_host_executable_modes "$dir_dest/bundle"
  mkdir -p "$dir_dest/usr/lib/wins-vpn/wins_bridge_host" \
    "$dir_dest/etc/opt/chrome/native-messaging-hosts" \
    "$dir_dest/usr/lib/mozilla/native-messaging-hosts" \
    "$dir_dest/etc/opt/edge/native-messaging-hosts"
  printf 'keep-dir\n' > "$dir_dest/usr/lib/wins-vpn/wins_bridge_host/inside"
  if install_linux_native_messaging \
      "$dir_dest/bundle" \
      "$dir_dest/usr/lib/wins-vpn" \
      "$dir_dest/usr/lib/wins-vpn/wins_bridge_host" \
      "$dir_dest/etc/opt/chrome/native-messaging-hosts" \
      "$dir_dest/usr/lib/mozilla/native-messaging-hosts" \
      "$dir_dest/etc/opt/edge/native-messaging-hosts" \
      0 \
      "$dir_dest"
  then
    printf '[WINS-LINUX-INSTALL] ERROR: preexisting native-host directory dest was accepted\n' >&2
    fail=1
  elif [[ ! -f "$dir_dest/usr/lib/wins-vpn/wins_bridge_host/inside" ]]; then
    printf '[WINS-LINUX-INSTALL] ERROR: preexisting native-host directory dest was mutated\n' >&2
    fail=1
  else
    printf '[WINS-LINUX-INSTALL] self-test: preexisting native-host directory dest was refused\n'
  fi

  local live="$prefix/fake-live"
  mkdir -p "$live/usr/lib/wins-vpn" "$live/etc/opt/edge/native-messaging-hosts" \
    "$live/etc/opt/chrome/native-messaging-hosts" "$live/usr/lib/mozilla/native-messaging-hosts"
  printf 'LIVE-HOST\n' > "$live/usr/lib/wins-vpn/wins_bridge_host"
  printf 'LIVE-EDGE\n' > "$live/etc/opt/edge/native-messaging-hosts/${NATIVE_HOST_NAME}.json"
  printf 'LIVE-CHROME\n' > "$live/etc/opt/chrome/native-messaging-hosts/${NATIVE_HOST_NAME}.json"
  printf 'LIVE-FIREFOX\n' > "$live/usr/lib/mozilla/native-messaging-hosts/${NATIVE_HOST_NAME}.json"
  local linked="$prefix/symlink-overlay"
  mkdir -p "$linked"
  ln -s "$live/usr" "$linked/usr"
  ln -s "$live/etc" "$linked/etc"
  if run_native_host_uninstall "$linked"; then
    printf '[WINS-LINUX-INSTALL] ERROR: overlay inner symlink dests were uninstalled\n' >&2
    fail=1
  elif [[ "$(cat "$live/usr/lib/wins-vpn/wins_bridge_host")" != "LIVE-HOST" || \
          "$(cat "$live/etc/opt/edge/native-messaging-hosts/${NATIVE_HOST_NAME}.json")" != "LIVE-EDGE" || \
          "$(cat "$live/etc/opt/chrome/native-messaging-hosts/${NATIVE_HOST_NAME}.json")" != "LIVE-CHROME" || \
          "$(cat "$live/usr/lib/mozilla/native-messaging-hosts/${NATIVE_HOST_NAME}.json")" != "LIVE-FIREFOX" ]]; then
    printf '[WINS-LINUX-INSTALL] ERROR: overlay inner symlink uninstall mutated files outside the overlay\n' >&2
    fail=1
  else
    printf '[WINS-LINUX-INSTALL] self-test: overlay inner symlink dests were refused\n'
  fi
  if verify_installed_linux_native_messaging "$linked"; then
    printf '[WINS-LINUX-INSTALL] ERROR: overlay verify followed inner symlink dests\n' >&2
    fail=1
  fi

  local slash_dot="$prefix/slash-dot"
  local slash_dot_real="$slash_dot/real"
  mkdir -p "$slash_dot_real/usr/lib/wins-vpn" \
    "$slash_dot_real/etc/opt/edge/native-messaging-hosts" \
    "$slash_dot_real/etc/opt/chrome/native-messaging-hosts" \
    "$slash_dot_real/usr/lib/mozilla/native-messaging-hosts"
  printf 'SLASH-DOT-HOST\n' > "$slash_dot_real/usr/lib/wins-vpn/wins_bridge_host"
  printf 'SLASH-DOT-EDGE\n' > "$slash_dot_real/etc/opt/edge/native-messaging-hosts/${NATIVE_HOST_NAME}.json"
  printf 'SLASH-DOT-CHROME\n' > "$slash_dot_real/etc/opt/chrome/native-messaging-hosts/${NATIVE_HOST_NAME}.json"
  printf 'SLASH-DOT-FIREFOX\n' > "$slash_dot_real/usr/lib/mozilla/native-messaging-hosts/${NATIVE_HOST_NAME}.json"
  ln -s "$slash_dot_real" "$slash_dot/link"
  if run_native_host_uninstall "$slash_dot/link/."; then
    printf '[WINS-LINUX-INSTALL] ERROR: symlink overlay prefix with /. was uninstalled\n' >&2
    fail=1
  elif [[ "$(cat "$slash_dot_real/usr/lib/wins-vpn/wins_bridge_host")" != "SLASH-DOT-HOST" || \
          "$(cat "$slash_dot_real/etc/opt/edge/native-messaging-hosts/${NATIVE_HOST_NAME}.json")" != "SLASH-DOT-EDGE" ]]; then
    printf '[WINS-LINUX-INSTALL] ERROR: symlink overlay prefix with /. mutated files outside the overlay\n' >&2
    fail=1
  else
    printf '[WINS-LINUX-INSTALL] self-test: symlink overlay prefix with /. was refused\n'
  fi

  local inner_dotdot="$prefix/inner-dotdot"
  local inner_outside="$prefix/inner-outside"
  mkdir -p "$inner_dotdot/inside" \
    "$inner_outside/usr/lib/wins-vpn" \
    "$inner_outside/etc/opt/edge/native-messaging-hosts" \
    "$inner_outside/etc/opt/chrome/native-messaging-hosts" \
    "$inner_outside/usr/lib/mozilla/native-messaging-hosts"
  printf 'INNER-OUTSIDE-HOST\n' > "$inner_outside/usr/lib/wins-vpn/wins_bridge_host"
  printf 'INNER-OUTSIDE-EDGE\n' > "$inner_outside/etc/opt/edge/native-messaging-hosts/${NATIVE_HOST_NAME}.json"
  printf 'INNER-OUTSIDE-CHROME\n' > "$inner_outside/etc/opt/chrome/native-messaging-hosts/${NATIVE_HOST_NAME}.json"
  printf 'INNER-OUTSIDE-FIREFOX\n' > "$inner_outside/usr/lib/mozilla/native-messaging-hosts/${NATIVE_HOST_NAME}.json"
  ln -s "$inner_outside" "$inner_dotdot/inside/link"
  if run_native_host_uninstall "$inner_dotdot/inside/link/.."; then
    printf '[WINS-LINUX-INSTALL] ERROR: inner-symlink/.. overlay prefix was uninstalled\n' >&2
    fail=1
  elif [[ "$(cat "$inner_outside/usr/lib/wins-vpn/wins_bridge_host")" != "INNER-OUTSIDE-HOST" || \
          "$(cat "$inner_outside/etc/opt/edge/native-messaging-hosts/${NATIVE_HOST_NAME}.json")" != "INNER-OUTSIDE-EDGE" ]]; then
    printf '[WINS-LINUX-INSTALL] ERROR: inner-symlink/.. overlay prefix mutated files outside the overlay\n' >&2
    fail=1
  else
    printf '[WINS-LINUX-INSTALL] self-test: inner-symlink/.. overlay prefix was refused\n'
  fi

  if normalize_overlay_prefix / >/dev/null 2>&1; then
    printf '[WINS-LINUX-INSTALL] ERROR: overlay prefix / was accepted\n' >&2
    fail=1
  elif run_native_host_uninstall /; then
    printf '[WINS-LINUX-INSTALL] ERROR: overlay prefix / uninstall was accepted\n' >&2
    fail=1
  elif verify_installed_linux_native_messaging /; then
    printf '[WINS-LINUX-INSTALL] ERROR: overlay prefix / verify was accepted\n' >&2
    fail=1
  else
    printf '[WINS-LINUX-INSTALL] self-test: root overlay prefix / was refused\n'
  fi

  local hardlink_root="$prefix/hardlink-rollback"
  mkdir -p "$hardlink_root/usr/lib/wins-vpn"
  local hardlink_victim="$prefix/hardlink-victim"
  local hardlink_dest="$hardlink_root/usr/lib/wins-vpn/wins_bridge_host"
  printf 'HARD-LINK-VICTIM\n' > "$hardlink_victim"
  ln "$hardlink_victim" "$hardlink_dest"
  printf 'HARD-LINK-BACKUP\n' > "$hardlink_root/backup-host"
  if restore_linux_native_messaging \
      "$hardlink_root" \
      "$hardlink_dest" "$hardlink_root/backup-host" \
      "$hardlink_root/chrome.json" "$hardlink_root/missing-chrome" \
      "$hardlink_root/firefox.json" "$hardlink_root/missing-firefox" \
      "$hardlink_root/edge.json" "$hardlink_root/missing-edge"
  then
    printf '[WINS-LINUX-INSTALL] ERROR: hardlinked rollback destination was restored\n' >&2
    fail=1
  elif [[ "$(cat "$hardlink_victim")" != "HARD-LINK-VICTIM" || \
          "$(cat "$hardlink_dest")" != "HARD-LINK-VICTIM" ]]; then
    printf '[WINS-LINUX-INSTALL] ERROR: hardlinked rollback destination mutated the victim inode\n' >&2
    fail=1
  else
    printf '[WINS-LINUX-INSTALL] self-test: hardlinked rollback destination was refused\n'
  fi

  local verify_overlay="$prefix/verify-overlay"
  local verify_host_dir="$verify_overlay$NATIVE_HOST_SYSTEM_DIR"
  local verify_host_path="$verify_overlay$NATIVE_HOST_SYSTEM_PATH"
  local verify_chrome="$verify_overlay$NATIVE_HOST_CHROME_MANIFEST_DIR"
  local verify_firefox="$verify_overlay$NATIVE_HOST_FIREFOX_MANIFEST_DIR"
  local verify_edge="$verify_overlay$NATIVE_HOST_EDGE_MANIFEST_DIR"
  local verify_bundle_root="$verify_overlay$TARGET"
  write_native_host_delivery_fixture "$origin" "$verify_overlay/bundle" "$verify_host_path" "$chrome_id" "$edge_id"
  restore_native_host_executable_modes "$verify_overlay/bundle"
  mkdir -p "$verify_host_dir" "$verify_chrome" "$verify_firefox" "$verify_edge" \
    "$verify_bundle_root/$(dirname "$NATIVE_HOST_STORE_IDS_REL")"
  if ! install_linux_native_messaging \
      "$verify_overlay/bundle" "$verify_host_dir" "$verify_host_path" \
      "$verify_chrome" "$verify_firefox" "$verify_edge" 0 "$verify_overlay"
  then
    printf '[WINS-LINUX-INSTALL] ERROR: overlay verify rehearsal delivery failed\n' >&2
    fail=1
  else
    cp "$verify_overlay/bundle/$NATIVE_HOST_STORE_IDS_REL" \
      "$verify_bundle_root/$NATIVE_HOST_STORE_IDS_REL"
    if ! verify_installed_linux_native_messaging "$verify_overlay"; then
      printf '[WINS-LINUX-INSTALL] ERROR: overlay native-host verify failed\n' >&2
      fail=1
    else
      printf '[WINS-LINUX-INSTALL] self-test: overlay native-host delivery verified\n'
    fi
  fi

  local closed="$prefix/rollback-fail"
  mkdir -p "$closed"
  printf 'not-a-directory\n' > "$closed/parent"
  printf 'previous-host\n' > "$closed/backup-host"
  if restore_linux_native_messaging \
      "$closed" \
      "$closed/parent/host" "$closed/backup-host" \
      "$closed/chrome.json" "$closed/missing-chrome" \
      "$closed/firefox.json" "$closed/missing-firefox" \
      "$closed/edge.json" "$closed/missing-edge"; then
    printf '[WINS-LINUX-INSTALL] ERROR: native-host rollback succeeded against an unusable backup dest\n' >&2
    fail=1
  else
    printf '[WINS-LINUX-INSTALL] self-test: native-host rollback failed closed\n'
  fi

  if [[ "$fail" == 1 ]]; then
    printf '[WINS-LINUX-INSTALL] NATIVE-HOST DELIVERY SELF-TEST: FAIL\n' >&2
    return 65
  fi
  printf '[WINS-LINUX-INSTALL] NATIVE-HOST DELIVERY SELF-TEST: PASS\n'
  return 0
}

if [[ "${1:-}" == "--self-test" ]]; then
  run_bundle_self_test "${2:-}"
  exit $?
fi

if [[ "${1:-}" == "--self-test-native-host-delivery" ]]; then
  run_native_host_delivery_self_test "${2:-}"
  exit $?
fi

if [[ "${1:-}" == "--uninstall-native-host" ]]; then
  run_native_host_uninstall "${2:-}"
  exit $?
fi

if [[ "${1:-}" == "--verify-native-host-delivery" ]]; then
  verify_installed_linux_native_messaging "${2:-}"
  exit $?
fi

run_full_uninstall() {
  local exe target pid tool table rules path name uid home invoker
  local xray_home xray_shell xray_shadow xray_record="" xray_identity_residual=0 purge=0
  local -a purge_users=() residual=()

  remove_owned_path() {
    rm -rf -- "$1" 2>/dev/null || true
    if [[ -e "$1" || -L "$1" ]]; then
      residual+=("$1")
    fi
  }
  user_has_graphical_session() {
    local session session_type session_state
    command -v loginctl >/dev/null 2>&1 || return 1
    while IFS=' ' read -r session _; do
      [[ -n "$session" ]] || continue
      session_type="$(loginctl show-session "$session" -p Type --value 2>/dev/null || true)"
      session_state="$(loginctl show-session "$session" -p State --value 2>/dev/null || true)"
      case "$session_type" in
        x11|wayland|mir)
          if [[ "$session_state" != closing ]]; then
            return 0
          fi
          ;;
      esac
    done < <(loginctl list-sessions --no-legend 2>/dev/null | \
               awk -v u="$1" '$2 == u { print $1 }' || true)
    return 1
  }

  [[ "${EUID}" -eq 0 ]] || die "Run the uninstall as root: sudo $TARGET/install.sh --uninstall-all"
  if [[ "${1:-}" == "--purge-user-data" ]]; then
    purge=1
    shift
    purge_users=("$@")
  elif [[ $# -gt 0 ]]; then
    die "Usage: install.sh --uninstall-all [--purge-user-data [USER...]]"
  fi
  invoker="${SUDO_USER:-}"
  if [[ -z "$invoker" && -n "${PKEXEC_UID:-}" ]]; then
    invoker="$(getent passwd "$PKEXEC_UID" | cut -d: -f1 || true)"
  fi
  if (( purge )) && (( ${#purge_users[@]} == 0 )); then
    [[ -n "$invoker" && "$invoker" != root ]] || \
      die "Name the users whose Win's VPN data should be removed: --purge-user-data USER..."
    purge_users=("$invoker")
  fi

  for exe in /proc/[0-9]*/exe; do
    target="$(readlink -- "$exe" 2>/dev/null)" || continue
    case "$target" in
      "$TARGET"/*|/opt/.wins-vpn.*)
        pid="${exe#/proc/}"; pid="${pid%/exe}"
        die "Win's VPN is still running (process $pid). Press Disconnect, quit Win's VPN, then uninstall."
        ;;
    esac
  done
  for name in winsvpn winsvpn3; do
    if ip link show dev "$name" >/dev/null 2>&1; then
      die "The Win's VPN network interface $name is still present. Press Disconnect first."
    fi
  done
  for tool in iptables ip6tables; do
    command -v "$tool" >/dev/null 2>&1 || continue
    for table in filter nat mangle; do
      rules="$("$tool" -w 5 -t "$table" -S 2>/dev/null || true)"
      if grep -q '^-N WINSVPN_' <<<"$rules"; then
        die "A Win's VPN firewall chain is still present ($tool, table $table). Follow $TARGET/share/doc/wins-vpn/RECOVERY.md, then uninstall."
      fi
    done
  done

  # Ruling A7: the account is removed only when this installer recorded that
  # it created it, never on its shape alone. Read before /var/lib/winsvpn is
  # removed below.
  if [[ -f /var/lib/winsvpn/installer-created-identities && \
        ! -L /var/lib/winsvpn/installer-created-identities ]]; then
    xray_record="$(head -n 1 -- /var/lib/winsvpn/installer-created-identities 2>/dev/null || true)"
  fi
  # System-level registration only. The per-user manifests and host copy
  # belong to the opt-in purge below (ruling A7), so no home is passed here.
  uninstall_linux_native_messaging "" "$NATIVE_HOST_SYSTEM_PATH" \
    "$NATIVE_HOST_CHROME_MANIFEST_DIR/${NATIVE_HOST_NAME}.json" \
    "$NATIVE_HOST_FIREFOX_MANIFEST_DIR/${NATIVE_HOST_NAME}.json" \
    "$NATIVE_HOST_EDGE_MANIFEST_DIR/${NATIVE_HOST_NAME}.json" "" || \
    residual+=("native-messaging host registration")
  if [[ -e /etc/systemd/system/winsvpn-recover.service ]]; then
    systemctl disable winsvpn-recover.service >/dev/null 2>&1 || true
    remove_owned_path /etc/systemd/system/winsvpn-recover.service
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  if [[ -L /usr/local/bin/wins_vpn && "$(readlink -- /usr/local/bin/wins_vpn)" == "$TARGET/wins_vpn" ]]; then
    remove_owned_path /usr/local/bin/wins_vpn
  fi
  for path in \
      /usr/share/applications/org.winsvpn.app.desktop \
      /usr/share/metainfo/org.winsvpn.app.metainfo.xml \
      /usr/share/icons/hicolor/512x512/apps/org.winsvpn.app.png \
      /usr/share/polkit-1/actions/org.winsvpn.app.helper.policy \
      /usr/lib/wins-vpn/browser_bridge.identity \
      /etc/wins-vpn /run/wins-vpn /run/wins-vpn-xray; do
    if [[ -e "$path" || -L "$path" ]]; then
      remove_owned_path "$path"
    fi
  done
  for path in "$NATIVE_HOST_SYSTEM_DIR" "$NATIVE_HOST_EDGE_MANIFEST_DIR" \
              "$NATIVE_HOST_CHROME_MANIFEST_DIR" "$NATIVE_HOST_FIREFOX_MANIFEST_DIR"; do
    rmdir -- "$path" 2>/dev/null || true
  done
  if [[ -d /usr/lib/wins-vpn ]]; then
    rmdir -- /usr/lib/wins-vpn 2>/dev/null || \
      residual+=("/usr/lib/wins-vpn (holds files this installer did not create; left in place)")
  fi
  if getent passwd winsvpn-xray >/dev/null 2>&1; then
    IFS=: read -r _ _ _ _ _ xray_home xray_shell < <(getent passwd winsvpn-xray)
    xray_shadow="$(getent shadow winsvpn-xray | cut -d: -f2 || true)"
    if [[ "$xray_record" != "winsvpn-xray user" &&
          "$xray_record" != "winsvpn-xray user group" ]]; then
      residual+=("account winsvpn-xray (no record that this installer created it; left in place)")
      xray_identity_residual=1
    elif [[ "$xray_home" == /nonexistent && "$xray_shell" == */nologin &&
            ( "$xray_shadow" == '!'* || "$xray_shadow" == '*'* ) ]]; then
      userdel winsvpn-xray >/dev/null 2>&1 || true
      if getent passwd winsvpn-xray >/dev/null 2>&1; then
        residual+=("account winsvpn-xray")
        xray_identity_residual=1
      fi
    else
      residual+=("account winsvpn-xray (not in the shape this installer creates; left in place)")
      xray_identity_residual=1
    fi
  fi
  if [[ "$xray_record" == "winsvpn-xray user group" ]] &&
      ! getent passwd winsvpn-xray >/dev/null 2>&1; then
    groupdel winsvpn-xray >/dev/null 2>&1 || true
    if getent group winsvpn-xray >/dev/null 2>&1; then
      residual+=("group winsvpn-xray")
      xray_identity_residual=1
    fi
  fi
  if (( xray_identity_residual )); then
    if [[ -e /var/lib/winsvpn || -L /var/lib/winsvpn ]]; then
      residual+=("/var/lib/winsvpn (installer identity record retained for retry)")
    fi
  elif [[ -e /var/lib/winsvpn || -L /var/lib/winsvpn ]]; then
    remove_owned_path /var/lib/winsvpn
  fi

  if (( purge )); then
    for name in "${purge_users[@]}"; do
      uid=""; home=""
      if ! IFS=: read -r _ _ uid _ _ home _ < <(getent passwd "$name"); then
        residual+=("user data of $name (no such user)")
        continue
      fi
      if [[ -z "$uid" || "$home" != /* || ! -d "$home" ]]; then
        residual+=("user data of $name (no usable home directory)")
        continue
      fi
      if [[ "$name" != "$invoker" ]] && user_has_graphical_session "$uid"; then
        residual+=("user data of $name (skipped: $name has an active graphical session)")
        continue
      fi
      runuser -u "$name" -- rm -rf -- "$home/.local/share/wins_vpn" >/dev/null 2>&1 || true
      if [[ -e "$home/.local/share/wins_vpn" || -L "$home/.local/share/wins_vpn" ]]; then
        residual+=("$home/.local/share/wins_vpn")
      fi
      for path in "$NATIVE_HOST_CHROME_USER_REL" "$NATIVE_HOST_EDGE_USER_REL" \
                  "$NATIVE_HOST_FIREFOX_USER_REL"; do
        path="$home/$path/${NATIVE_HOST_NAME}.json"
        if [[ -e "$path" || -L "$path" ]]; then
          runuser -u "$name" -- rm -f -- "$path" >/dev/null 2>&1 || true
          if [[ -e "$path" || -L "$path" ]]; then
            residual+=("$path")
          fi
        fi
      done
      path="$home/$NATIVE_HOST_USER_HOST_REL"
      if [[ -e "$path" || -L "$path" ]]; then
        runuser -u "$name" -- rm -f -- "$path" >/dev/null 2>&1 || true
        if [[ -e "$path" || -L "$path" ]]; then
          residual+=("$path")
        fi
      fi
      path="$home/${NATIVE_HOST_USER_HOST_REL%/*}"
      if [[ -d "$path" && ! -L "$path" ]]; then
        runuser -u "$name" -- rmdir -- "$path" >/dev/null 2>&1 || \
          residual+=("$path (holds files this installer did not create; left in place)")
      fi
      if command -v secret-tool >/dev/null 2>&1 && [[ -S "/run/user/$uid/bus" ]] && \
         runuser -u "$name" -- env XDG_RUNTIME_DIR="/run/user/$uid" \
           DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
           secret-tool clear application org.winsvpn.app >/dev/null 2>&1; then
        :
      else
        residual+=("keyring items of $name: log in as $name and run 'secret-tool clear application org.winsvpn.app'")
      fi
    done
  fi

  command -v update-desktop-database >/dev/null 2>&1 && \
    update-desktop-database /usr/share/applications >/dev/null 2>&1 || true
  command -v gtk-update-icon-cache >/dev/null 2>&1 && \
    gtk-update-icon-cache -q /usr/share/icons/hicolor >/dev/null 2>&1 || true
  remove_owned_path "$TARGET"

  log "The release-signing key under /etc/winsvpn was left in place: the bootstrap installer has no embedded copy and reads it only from /etc/winsvpn/release-signing/cosign.pub."
  log "Not removed by this uninstaller: the Win's VPN browser extensions (remove them in each browser), system journal entries, and shell history."
  if (( ${#residual[@]} > 0 )); then
    printf '[WINS-LINUX-INSTALL] Could not remove:\n' >&2
    printf '  %s\n' "${residual[@]}" >&2
    exit 1
  fi
  log "Win's VPN was removed."
  exit 0
}

if [[ "${1:-}" == "--uninstall-all" ]]; then
  run_full_uninstall "${@:2}"
fi

[[ "$(uname -s)" == Linux ]] || die "This installer only supports Linux."
# The host architecture was resolved into EXPECTED_ELF_MACHINE at the top of
# this file, which refuses anything but x86-64 and arm64. Whether the PAYLOAD
# matches this host is a separate question and is answered further down, on
# manifest-verified bytes, by assert_payload_matches_this_machine.

extraction_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
[[ "$extraction_dir" != "$TARGET" ]] || die "Run install.sh from the extracted release archive, not from $TARGET."

if [[ "${EUID}" -ne 0 ]]; then
  command -v sudo >/dev/null 2>&1 || die "Run this installer as root or install sudo."
  exec sudo -- "$extraction_dir/install.sh" "$@"
fi

# M-2: this script must never be the first thing that touches an unverified
# download. It is only reached safely via
# install-winsvpn-linux.sh, which cosign-verifies the *complete, unmodified*
# .tar.gz against the required local/offline release key before extracting a
# single byte, and which sets this flag itself (in a clean, minimal sudo
# environment) only after that verification succeeds. A bare `sudo
# ./install.sh` run by hand from a manually extracted, never-verified archive
# will not have it set -- refuse to proceed rather than silently install an
# unauthenticated payload.
[[ "${WINSVPN_VERIFIED_STAGE:-}" == "1" ]] || \
  die "This script must be run via install-winsvpn-linux.sh (linux/packaging/install-winsvpn-linux.sh in the source release), which verifies the release archive's cosign signature before extracting or installing anything. Do not run install.sh directly from a manually extracted archive."

# H-5: the extraction directory is still user-writable, so a local process
# could keep racing to swap its bytes for as long as this script keeps
# reading from it. Snapshot it into a brand-new root-owned 0700 directory
# immediately, verify the release manifest against ONLY that frozen snapshot,
# and use exclusively the snapshot (never $extraction_dir again) for every
# remaining read, hash check, or copy into $TARGET.
payload_stage="$(mktemp -d /var/tmp/winsvpn-install.XXXXXX)"
trap 'rm -rf -- "$payload_stage"' EXIT
chmod 0700 -- "$payload_stage"
cp -a --no-preserve=ownership -- "$extraction_dir/." "$payload_stage/"
chown -R root:root -- "$payload_stage"
SOURCE="$payload_stage"
unset extraction_dir

verify_release_manifest() {
  local manifest="$SOURCE/release-manifest.sha256"
  local manifest_entries payload_entries
  [[ -f "$manifest" && ! -L "$manifest" && -s "$manifest" ]] || \
    die "The extracted release does not include release-manifest.sha256; refusing to install an unverifiable payload."
  ( cd "$SOURCE" && sha256sum --strict --check "$(basename "$manifest")" ) || \
    die "One or more staged release files failed manifest hash verification."
  manifest_entries="$(awk '{ sub(/^[^ ]+[ ]+/, ""); sub(/^\*/, ""); print }' "$manifest" | LC_ALL=C sort -u)"
  payload_entries="$(cd "$SOURCE" && find . -type f \
    ! -name "$(basename "$manifest")" | \
    sed 's|^\./||' | LC_ALL=C sort -u)"
  [[ "$manifest_entries" == "$payload_entries" ]] || \
    die "The release manifest does not exactly match the staged payload (missing, extra, or renamed files); refusing to install."
}
verify_release_manifest

verify_hash() {
  local path="$1" expected="$2"
  [[ -f "$path" && ! -L "$path" ]] || die "Required runtime is missing or unsafe: $path"
  [[ -n "$expected" ]] || \
    die "Win's VPN has no pinned hash for $(basename -- "$path") on this computer's processor type ($(uname -m)); refusing to install an unpinned runtime."
  [[ "$(sha256sum "$path" | awk '{print $1}')" == "$expected" ]] || \
    die "Runtime integrity verification failed: $path"
}

assert_payload_matches_this_machine() {
  local relative
  for relative in \
    wins_vpn \
    winsvpn-bypass-bpf \
    winn-datapath \
    xray \
    awg \
    amneziawg-go \
    tools/native_messaging/host/wins_bridge_host \
    lib/libapp.so \
    lib/libflutter_linux_gtk.so; do
    assert_elf_matches_this_machine "$SOURCE/$relative" "$relative"
  done
  assert_every_extracted_elf_matches_this_machine "$SOURCE"
}

assert_every_extracted_elf_matches_this_machine() {
  local root="$1" candidate magic elf_type machine
  while IFS= read -r -d '' candidate; do
    magic="$(od -An -tx1 -j0 -N4 -- "$candidate" | tr -d ' \n')"
    [[ "$magic" == "7f454c46" ]] || continue
    IFS=' ' read -r elf_type machine < <(elf_identity_of "$candidate") || \
      die "The extracted release contains an unsupported ELF object: $candidate"
    [[ "$elf_type" == 2 || "$elf_type" == 3 ]] || \
      die "The extracted release contains unsupported ELF type $elf_type: $candidate"
    [[ "$machine" == "$EXPECTED_ELF_MACHINE" ]] || \
      die "The extracted release contains mixed-architecture ELF $candidate (machine $machine, expected $EXPECTED_ELF_MACHINE)."
  done < <(find "$root" -type f -print0)
}

# The Winn Protocol v3 datapath engine is no longer optional: it is the thing
# that carries every outer datagram once a v3 session is up, and the Linux
# runtime locates it as "winn-datapath" beside the running executable
# (FindWinnDatapathExecutable() in linux/runner/linux_tunnel_backend.cc). A
# Linux install that omits v3 cannot start a Winn v3 session. Winn v1 over
# AWG/Xray is not an implicit substitute; it is used only when the trusted
# served configuration selects that cover path. Refuse a release that omits it.
for required in \
  wins_vpn \
  winsvpn-bypass-bpf \
  winn-datapath \
  tools/native_messaging/host/wins_bridge_host \
  lib/libapp.so \
  lib/libflutter_linux_gtk.so \
  winn3-descriptor-ring-attestation.json; do
  [[ -f "$SOURCE/$required" && ! -L "$SOURCE/$required" ]] || \
    die "The extracted release is incomplete (missing): $required"
done
for required in \
  wins_vpn \
  winsvpn-bypass-bpf \
  winn-datapath \
  tools/native_messaging/host/wins_bridge_host; do
  [[ -x "$SOURCE/$required" ]] || \
    die "The extracted release is incomplete (missing or not executable): $required"
done
require_native_host_identity_inputs "$SOURCE" || \
  die "The extracted release is missing native-messaging identity or registration inputs."
restore_native_host_executable_modes "$SOURCE" || \
  die "The extracted release's native-messaging host is not executable."
native_host_identity_status=0
read_native_host_store_ids "$SOURCE/$NATIVE_HOST_STORE_IDS_REL" >/dev/null || \
  native_host_identity_status=$?
if [[ "$native_host_identity_status" -eq 78 ]]; then
  die "owner-blocked: packaged Edge store identity is absent or reused. Refusing to invent an Edge id."
fi
if [[ "$native_host_identity_status" -ne 0 ]]; then
  die "The extracted release is missing a Chrome native-host store identity."
fi
assert_payload_matches_this_machine

# Linux x86_64 and arm64 both require the AmneziaWG triple and Xray. Two rules
# keep it honest, and they mirror linux/runner/linux_tunnel_backend.cc:
#
#   - the AmneziaWG triple is ALL THREE, because a partial bundle is a tunnel
#     that starts and then cannot finish; and
#   - anything present is hash-verified against an architecture-specific pin,
#     and an absent pin is a refusal rather than a skip.
awg_present=0
for tool in awg awg-quick amneziawg-go; do
  [[ ! -e "$SOURCE/$tool" ]] || awg_present=$((awg_present + 1))
done
case "$awg_present" in
  3)
    verify_hash "$SOURCE/awg" "$AWG_SHA256"
    verify_hash "$SOURCE/awg-quick" "$AWG_QUICK_SHA256"
    verify_hash "$SOURCE/amneziawg-go" "$AWG_GO_SHA256"
    ;;
  *)
    die "The extracted release carries an incomplete AmneziaWG runtime ($awg_present of awg, awg-quick, amneziawg-go); refusing to install a partial one. Linux x86_64 and arm64 both require the AmneziaWG triple."
    ;;
esac
[[ -f "$SOURCE/xray" && ! -L "$SOURCE/xray" ]] || \
  die "The extracted release is missing the required Xray runtime."
verify_hash "$SOURCE/xray" "$XRAY_SHA256"

if find "$SOURCE" -type l -print -quit | grep -q .; then
  die "The extracted release contains a symbolic link and was rejected."
fi
if find "$SOURCE" ! -type d ! -type f -print -quit | grep -q .; then
  die "The extracted release contains an unsupported file type and was rejected."
fi

log "Installing minimal host networking and desktop runtime dependencies"
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  export DEBIAN_PRIORITY=critical
  export APT_LISTCHANGES_FRONTEND=none
  export NEEDRESTART_MODE=a
  export UCF_FORCE_CONFFOLD=1
  APT_GET=(
    apt-get
    -o DPkg::Lock::Timeout=300
    -o Acquire::Retries=3
    -o Dpkg::Use-Pty=0
  )
  "${APT_GET[@]}" update
  "${APT_GET[@]}" \
    -o Dpkg::Options::=--force-confdef \
    -o Dpkg::Options::=--force-confold \
    install -y --no-install-recommends \
    bash ca-certificates curl gnome-keyring iproute2 iptables \
    libgtk-3-0 libsecret-1-0 libstdc++6 nftables passwd policykit-1 \
    python3 systemd-resolved util-linux
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y \
    bash ca-certificates curl gnome-keyring gtk3 iproute iptables-nft \
    libsecret libstdc++ nftables openresolv polkit python3 shadow-utils util-linux
elif command -v pacman >/dev/null 2>&1; then
  pacman -S --needed --noconfirm \
    bash ca-certificates curl gcc-libs gnome-keyring gtk3 iproute2 \
    iptables-nft libsecret nftables openresolv polkit python shadow util-linux || \
    die "pacman could not install the dependencies from the current package database. Run 'sudo pacman -Syu', reboot, then run this installer again."
else
  die "Supported package manager not found. Use Ubuntu/Debian, Fedora, or Arch Linux."
fi

# M-2: the OpenPGP signature-verification tooling this list used to require
# is intentionally gone. Release authenticity is proven once, up front, by
# cosign in install-winsvpn-linux.sh; gnome-keyring/libsecret above are
# unrelated runtime dependencies of the app's own Secret Service credential
# storage (see linux/runner/linux_secure_store.cc), not of this installer.
for required in bash curl flock getent groupdel id ip iptables pkexec \
                ip6tables nft python3 resolvconf setpriv sha256sum systemctl \
                systemd-run useradd userdel usermod; do
  command -v "$required" >/dev/null 2>&1 || \
    die "Required host command is unavailable after dependency installation: $required"
done

exec 9>/run/winsvpn-install.lock
flock -n 9 || die "Another Win's VPN installation is already running."

stage="/opt/.wins-vpn.new.$$"
backup="/opt/.wins-vpn.old.$$"
failed="/opt/.wins-vpn.failed.$$"
integration_backup="/opt/.wins-vpn.integration.old.$$"
native_host_backup="/opt/.wins-vpn.native-host.old.$$"
launcher=/usr/local/bin/wins_vpn
desktop=/usr/share/applications/org.winsvpn.app.desktop
metainfo=/usr/share/metainfo/org.winsvpn.app.metainfo.xml
icon=/usr/share/icons/hicolor/512x512/apps/org.winsvpn.app.png
recover_unit=/etc/systemd/system/winsvpn-recover.service
launcher_new="${launcher}.winsvpn-new.$$"
desktop_new="${desktop}.winsvpn-new.$$"
metainfo_new="${metainfo}.winsvpn-new.$$"
icon_new="${icon}.winsvpn-new.$$"
recover_unit_new="${recover_unit}.winsvpn-new.$$"
activated=0
had_previous=0
integration_mutated=0
launcher_had_previous=0
desktop_had_previous=0
metainfo_had_previous=0
icon_had_previous=0
recover_unit_had_previous=0
xray_identity_created=0
xray_group_preexisting=0
native_host_mutated=0
browser_bridge_identity_created=0
browser_bridge_identity_dir_created=0
native_host_host_backup=""
native_host_chrome_backup=""
native_host_firefox_backup=""
native_host_edge_backup=""

restore_integration_path() {
  local path="$1" name="$2" had_previous_path="$3"
  rm -rf -- "$path"
  if [[ "$had_previous_path" == 1 ]]; then
    cp -a -- "$integration_backup/$name" "$path" || return 1
  fi
}

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  set +e
  rollback_failed=0
  rm -f -- "$launcher_new" "$desktop_new" "$metainfo_new" "$icon_new" "$recover_unit_new"
  rm -rf -- "$stage" "$failed" "$payload_stage"
  if [[ "$activated" == 1 ]]; then
    rollback_ready=1
    if [[ -e "$TARGET" ]] && ! mv -- "$TARGET" "$failed"; then
      rollback_ready=0
      rollback_failed=1
    fi
    if [[ "$rollback_ready" == 1 && "$had_previous" == 1 && \
          -d "$backup" ]]; then
      if mv -- "$backup" "$TARGET"; then
        rm -rf -- "$failed"
      else
        mv -- "$failed" "$TARGET" || true
        rollback_failed=1
      fi
    elif [[ "$rollback_ready" == 1 ]]; then
      rm -rf -- "$failed"
    fi
  elif [[ -d "$backup" && ! -e "$TARGET" ]]; then
    mv -- "$backup" "$TARGET" || rollback_failed=1
  fi
  if [[ "$integration_mutated" == 1 ]]; then
    restore_integration_path "$launcher" launcher "$launcher_had_previous" || rollback_failed=1
    restore_integration_path "$desktop" desktop "$desktop_had_previous" || rollback_failed=1
    restore_integration_path "$metainfo" metainfo "$metainfo_had_previous" || rollback_failed=1
    restore_integration_path "$icon" icon "$icon_had_previous" || rollback_failed=1
    restore_integration_path "$recover_unit" recover_unit "$recover_unit_had_previous" || rollback_failed=1
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  if [[ "$native_host_mutated" == 1 ]]; then
    restore_linux_native_messaging \
      "" \
      "$NATIVE_HOST_SYSTEM_PATH" "$native_host_host_backup" \
      "$NATIVE_HOST_CHROME_MANIFEST_DIR/${NATIVE_HOST_NAME}.json" \
      "$native_host_chrome_backup" \
      "$NATIVE_HOST_FIREFOX_MANIFEST_DIR/${NATIVE_HOST_NAME}.json" \
      "$native_host_firefox_backup" \
      "$NATIVE_HOST_EDGE_MANIFEST_DIR/${NATIVE_HOST_NAME}.json" \
      "$native_host_edge_backup" || rollback_failed=1
  fi
  if [[ "$browser_bridge_identity_created" == 1 ]]; then
    rm -f -- "$BROWSER_BRIDGE_IDENTITY_FILE" || rollback_failed=1
  fi
  if [[ "$browser_bridge_identity_dir_created" == 1 ]]; then
    rmdir -- "$BROWSER_BRIDGE_IDENTITY_DIR" || rollback_failed=1
  fi
  rm -rf -- "$integration_backup" "$native_host_backup"
  if [[ "$xray_identity_created" == 1 ]]; then
    userdel winsvpn-xray >/dev/null 2>&1 || true
    if [[ "$xray_group_preexisting" == 0 ]]; then
      groupdel winsvpn-xray >/dev/null 2>&1 || true
    fi
  fi
  if [[ "$rollback_failed" == 1 ]]; then
    printf '[WINS-LINUX-INSTALL] ERROR: installation rollback failed closed\n' >&2
    if [[ "$status" -eq 0 ]]; then
      status=1
    fi
  fi
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

log "Creating the locked Xray transport service identity"
nologin_shell="$(command -v nologin || true)"
[[ -n "$nologin_shell" ]] || die "The nologin account shell is unavailable."

firewall_references_uid() {
  local candidate="$1"
  local command_name line fragment token range_start range_end rules

  for command_name in iptables-save ip6tables-save; do
    command -v "$command_name" >/dev/null 2>&1 || continue
    rules="$("$command_name" 2>/dev/null || true)"
    while IFS= read -r line; do
      if [[ "$line" == *"--uid-owner"* ]]; then
        fragment="${line#*--uid-owner}"
      else
        continue
      fi
      while [[ "$fragment" =~ ([0-9]+)(-([0-9]+))? ]]; do
        token="${BASH_REMATCH[0]}"
        range_start="${BASH_REMATCH[1]}"
        range_end="${BASH_REMATCH[3]:-$range_start}"
        if (( candidate >= range_start && candidate <= range_end )); then
          return 0
        fi
        fragment="${fragment#*"$token"}"
      done
    done <<<"$rules"
  done

  rules="$(nft list ruleset 2>/dev/null || true)"
  while IFS= read -r line; do
    [[ "$line" == *"skuid"* ]] || continue
    fragment="${line#*skuid}"
    while [[ "$fragment" =~ ([0-9]+)(-([0-9]+))? ]]; do
      token="${BASH_REMATCH[0]}"
      range_start="${BASH_REMATCH[1]}"
      range_end="${BASH_REMATCH[3]:-$range_start}"
      if (( candidate >= range_start && candidate <= range_end )); then
        return 0
      fi
      fragment="${fragment#*"$token"}"
    done
  done <<<"$rules"
  return 1
}

select_unreferenced_system_uid() {
  local uid_min=100 uid_max=999 key value candidate
  if [[ -r /etc/login.defs ]]; then
    while read -r key value _; do
      case "$key" in
        SYS_UID_MIN) [[ "$value" =~ ^[0-9]+$ ]] && uid_min="$value" ;;
        SYS_UID_MAX) [[ "$value" =~ ^[0-9]+$ ]] && uid_max="$value" ;;
      esac
    done < /etc/login.defs
  fi
  (( uid_min > 0 && uid_max >= uid_min )) ||
    die "The configured system UID range is invalid."

  for ((candidate = uid_max; candidate >= uid_min; candidate--)); do
    getent passwd "$candidate" >/dev/null 2>&1 && continue
    firewall_references_uid "$candidate" && continue
    printf '%s\n' "$candidate"
    return 0
  done
  return 1
}

if id -u winsvpn-xray >/dev/null 2>&1; then
  # Never commandeer, lock, or rewrite an unrelated preexisting account. Read
  # and validate the complete service-identity contract before any mutation.
  IFS=: read -r xray_name _xray_password xray_uid _xray_gid _xray_gecos \
    xray_home xray_shell < <(getent passwd winsvpn-xray)
  [[ "$xray_name" == winsvpn-xray && "$xray_uid" =~ ^[0-9]+$ && \
     "$xray_uid" -gt 0 && "$xray_uid" -lt 1000 && \
     "$xray_home" == /nonexistent && "$xray_shell" == "$nologin_shell" ]] || \
    die "A preexisting winsvpn-xray account conflicts with the required locked system identity; it was not modified."
  xray_shadow="$(getent shadow winsvpn-xray | cut -d: -f2)"
  [[ "$xray_shadow" == '!'* || "$xray_shadow" == '*'* ]] || \
    die "The preexisting winsvpn-xray identity is not password-locked; it was not modified."
else
  getent group winsvpn-xray >/dev/null 2>&1 && xray_group_preexisting=1
  xray_install_uid="$(select_unreferenced_system_uid)" ||
    die "No unreferenced system UID is available for the Xray transport identity."
  if ! useradd --system --uid "$xray_install_uid" --no-create-home --home-dir /nonexistent \
      --shell "$nologin_shell" winsvpn-xray; then
    die "Could not create the dedicated Xray transport identity."
  fi
  xray_identity_created=1
  usermod --home /nonexistent --shell "$nologin_shell" --lock winsvpn-xray
  IFS=: read -r xray_name _xray_password xray_uid _xray_gid _xray_gecos \
    xray_home xray_shell < <(getent passwd winsvpn-xray)
  [[ "$xray_name" == winsvpn-xray && "$xray_uid" =~ ^[0-9]+$ && \
     "$xray_uid" -gt 0 && "$xray_uid" -lt 1000 ]] || \
    die "The Xray transport identity is not a non-root system account."
  [[ "$xray_home" == /nonexistent && "$xray_shell" == "$nologin_shell" ]] || \
    die "The Xray transport identity does not have the required locked profile."
  xray_shadow="$(getent shadow winsvpn-xray | cut -d: -f2)"
  [[ "$xray_shadow" == '!'* || "$xray_shadow" == '*'* ]] || \
    die "The Xray transport identity password is not locked."
fi

rm -rf -- "$stage" "$backup" "$failed" "$integration_backup" "$native_host_backup"
rm -f -- "$launcher_new" "$desktop_new" "$metainfo_new" "$icon_new" "$recover_unit_new"
mkdir -m 0755 -- "$stage"
cp -a -- "$SOURCE/." "$stage/"
chown -R root:root "$stage"
find "$stage" -type d -exec chmod 0755 -- {} +
find "$stage" -type f -exec chmod 0644 -- {} +
# wins_vpn, winsvpn-bypass-bpf, winn-datapath, xray and the AmneziaWG triple
# are all required -- the checks above refused the release otherwise.
chmod 0755 -- \
  "$stage/wins_vpn" "$stage/winsvpn-bypass-bpf" "$stage/install.sh"
for required_executable in xray awg awg-quick amneziawg-go winn-datapath; do
  [[ -f "$stage/$required_executable" ]] || \
    die "Staged release is missing required executable: $required_executable"
  chmod 0755 -- "$stage/$required_executable"
done
for recovery_file in share/wins-vpn/winsvpn-recover \
                     share/wins-vpn/winsvpn-recover.service \
                     share/doc/wins-vpn/RECOVERY.md; do
  [[ -f "$stage/$recovery_file" && ! -L "$stage/$recovery_file" ]] || \
    die "Staged release is missing the offline recovery file: $recovery_file"
done
chmod 0755 -- "$stage/share/wins-vpn/winsvpn-recover"
restore_native_host_executable_modes "$stage" || \
  die "Staged native-messaging host is missing or not executable."

snapshot_integration_path() {
  local path="$1" name="$2" result_variable="$3"
  if [[ -e "$path" || -L "$path" ]]; then
    if [[ ! -f "$path" && ! -L "$path" ]]; then
      die "Existing integration target is not a regular file or symbolic link: $path"
    fi
    cp -a -- "$path" "$integration_backup/$name"
    printf -v "$result_variable" '%s' 1
  fi
}

log "Staging desktop integration, native-host, and rollback copies"
mkdir -m 0700 -- "$integration_backup"
mkdir -m 0700 -- "$native_host_backup"
snapshot_integration_path "$launcher" launcher launcher_had_previous
snapshot_integration_path "$desktop" desktop desktop_had_previous
snapshot_integration_path "$metainfo" metainfo metainfo_had_previous
snapshot_integration_path "$icon" icon icon_had_previous
snapshot_integration_path "$recover_unit" recover_unit recover_unit_had_previous
snapshot_native_host_path "$NATIVE_HOST_SYSTEM_PATH" "$native_host_backup/host" "" native_host_host_backup || \
  die "Could not snapshot the existing native-messaging host."
snapshot_native_host_path \
  "$NATIVE_HOST_CHROME_MANIFEST_DIR/${NATIVE_HOST_NAME}.json" \
  "$native_host_backup/chrome.json" "" native_host_chrome_backup || \
  die "Could not snapshot the existing Chrome native-messaging manifest."
snapshot_native_host_path \
  "$NATIVE_HOST_FIREFOX_MANIFEST_DIR/${NATIVE_HOST_NAME}.json" \
  "$native_host_backup/firefox.json" "" native_host_firefox_backup || \
  die "Could not snapshot the existing Firefox native-messaging manifest."
snapshot_native_host_path \
  "$NATIVE_HOST_EDGE_MANIFEST_DIR/${NATIVE_HOST_NAME}.json" \
  "$native_host_backup/edge.json" "" native_host_edge_backup || \
  die "Could not snapshot the existing Edge native-messaging manifest."
mkdir -p -- "$(dirname "$launcher")"
ln -s -- "$TARGET/wins_vpn" "$launcher_new"
install -D -m 0644 \
  "$stage/share/applications/org.winsvpn.app.desktop" "$desktop_new"
install -D -m 0644 \
  "$stage/share/metainfo/org.winsvpn.app.metainfo.xml" "$metainfo_new"
install -D -m 0644 \
  "$stage/share/icons/hicolor/512x512/apps/org.winsvpn.app.png" "$icon_new"
install -m 0644 \
  "$stage/share/wins-vpn/winsvpn-recover.service" "$recover_unit_new"

refuse_running_bundle() {
  local exe target pid
  for exe in /proc/[0-9]*/exe; do
    target="$(readlink -- "$exe" 2>/dev/null)" || continue
    case "$target" in
      "$TARGET"/*|/opt/.wins-vpn.old.*)
        pid="${exe#/proc/}"
        pid="${pid%/exe}"
        die "Win's VPN is still running from $TARGET (process $pid). Press Disconnect, quit Win's VPN, then run the installer again."
        ;;
    esac
  done
}
refuse_running_bundle

log "Installing the verified application into $TARGET"
if [[ -e "$TARGET" ]]; then
  mv -- "$TARGET" "$backup"
  had_previous=1
fi
if ! mv -- "$stage" "$TARGET"; then
  [[ ! -e "$backup" ]] || mv -- "$backup" "$TARGET"
  die "Could not activate the new application bundle."
fi
activated=1

integration_mutated=1
mv -Tf -- "$launcher_new" "$launcher"
mv -Tf -- "$desktop_new" "$desktop"
mv -Tf -- "$metainfo_new" "$metainfo"
mv -Tf -- "$icon_new" "$icon"
mv -Tf -- "$recover_unit_new" "$recover_unit"
systemctl daemon-reload >/dev/null 2>&1 || true

command -v update-desktop-database >/dev/null 2>&1 && \
  update-desktop-database /usr/share/applications >/dev/null 2>&1 || true
command -v gtk-update-icon-cache >/dev/null 2>&1 && \
  gtk-update-icon-cache -q /usr/share/icons/hicolor >/dev/null 2>&1 || true

log "Installing the authenticated native-messaging host for Chrome, Edge, and Firefox"
native_host_mutated=1
install_linux_native_messaging \
  "$TARGET" \
  "$NATIVE_HOST_SYSTEM_DIR" \
  "$NATIVE_HOST_SYSTEM_PATH" \
  "$NATIVE_HOST_CHROME_MANIFEST_DIR" \
  "$NATIVE_HOST_FIREFOX_MANIFEST_DIR" \
  "$NATIVE_HOST_EDGE_MANIFEST_DIR" \
  1 || die "Native-messaging host delivery failed."
verify_installed_linux_native_messaging || \
  die "Native-messaging host package verification failed."
log "Provisioning the browser bridge identity receipt"
install_browser_bridge_identity || \
  die "Browser bridge identity receipt provisioning failed."

# Post-install verification: every bundled runtime must resolve from the exact
# installed prefix the app will exec them from. This is a presence/executability
# check (never a hash or exact count -- bytes were already authenticated by
# cosign + the manifest + the fixed per-arch pins above); it exists so a
# release that staged a tool as unexecutable or that lost one in the
# copy-to-$TARGET step is caught here rather than on the user's first launch.
if run_bundle_self_test "$TARGET"; then
  log "Bundled-tool self-test passed on the installed prefix $TARGET."
else
  die "Bundled-tool self-test FAILED after install: $TARGET"
fi

if [[ "$xray_identity_created" == 1 ]]; then
  # The creation record --uninstall-all reads (ruling A7): the account, and the
  # group only if this run created it, are removed only when this installer
  # recorded creating them. A failure here rolls the install back through
  # cleanup, which still owns the new identity.
  xray_created_record="winsvpn-xray user"
  [[ "$xray_group_preexisting" == 0 ]] && xray_created_record+=" group"
  { install -d -m 0755 -o root -g root /var/lib/winsvpn &&
    printf '%s\n' "$xray_created_record" \
      > /var/lib/winsvpn/installer-created-identities.new &&
    chmod 0644 /var/lib/winsvpn/installer-created-identities.new &&
    mv -f -- /var/lib/winsvpn/installer-created-identities.new \
      /var/lib/winsvpn/installer-created-identities; } ||
    die "Could not record the Xray transport identity this installer created."
fi

rm -rf -- "$backup"
rm -rf -- "$integration_backup"
rm -rf -- "$native_host_backup"
activated=0
native_host_mutated=0
integration_mutated=0
browser_bridge_identity_created=0
browser_bridge_identity_dir_created=0
trap - EXIT HUP INT TERM
log "Installation complete. Launch Win's VPN from the app menu or run wins_vpn."
# Printed now, while this machine still has a working network, because the one
# situation the document covers is the one where it cannot be looked up online.
log "If this computer ever loses all internet after using the VPN, read:"
log "  $TARGET/share/doc/wins-vpn/RECOVERY.md"
