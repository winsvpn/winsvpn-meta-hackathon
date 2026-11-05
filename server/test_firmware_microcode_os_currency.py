#!/usr/bin/env python3
"""Stub-based tests for the firmware, microcode and OS-currency block.

The block (WINS-FWOS-BLOCK-BEGIN .. END) is extracted from each installer and
run under bash with stubbed dpkg, apt-get, needrestart, systemd-detect-virt and
friends, against synthetic /proc, /sys, /boot and state directories. Nothing
here touches the real system, the network or a package manager.

Run: python3 server/test_firmware_microcode_os_currency.py
"""

import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
INSTALLERS = {
    "data": HERE / "wins_data_plane_setup_ONETOUCH.sh",
    "control": HERE / "wins_control_plane_setup_ONETOUCH.sh",
    "core": HERE / "wins_core_server_setup_ONETOUCH.sh",
}
BASH = os.environ.get("WINS_TEST_BASH") or shutil.which("bash") or "bash"

INTEL_VM_CPUINFO = (
    "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R)\n"
    "microcode\t: 0x1\nflags\t\t: fpu vme sse2 hypervisor lahf_lm\n"
)
INTEL_METAL_CPUINFO = (
    "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R)\n"
    "microcode\t: 0x2000065\nflags\t\t: fpu vme sse2 lahf_lm\n"
)
AMD_METAL_CPUINFO = (
    "processor\t: 0\nvendor_id\t: AuthenticAMD\nmodel name\t: AMD EPYC\n"
    "microcode\t: 0xa0011d1\nflags\t\t: fpu vme sse2 lahf_lm\n"
)


def extract(path: pathlib.Path, begin: str, end: str) -> str:
    text = path.read_text(encoding="utf-8")
    start = text.find(begin)
    stop = text.find(end, start)
    if start < 0 or stop < 0:
        raise AssertionError(f"{path.name}: marker {begin} .. {end} not found")
    return text[start : stop + len(end)] + "\n"


def install_block(role: str) -> str:
    return extract(INSTALLERS[role], "# WINS-FWOS-BLOCK-BEGIN", "# WINS-FWOS-BLOCK-END")


def weekly_block(path: pathlib.Path) -> str:
    return extract(path, "# WINS-FWOS-WEEKLY-BEGIN", "# WINS-FWOS-WEEKLY-END")


def function_body(source: str, name: str) -> str:
    marker = f"{name}() {{"
    start = source.find(marker)
    if start < 0:
        raise AssertionError(f"missing function {name}")
    cursor = source.find("\n}", start)
    while cursor >= 0:
        candidate = source[start : cursor + 2]
        if candidate.count("{") == candidate.count("}"):
            return candidate
        cursor = source.find("\n}", cursor + 2)
    raise AssertionError(f"unterminated function {name}")


PRELUDE = r'''
set -Eeuo pipefail
T="$PWD"
log()  { printf 'LOG %s\n' "$*" >> "$T/events"; }
warn() { printf 'WARN %s\n' "$*" >> "$T/events"; }
err()  { printf 'ERR %s\n' "$*" >> "$T/events"; }
maint_warn() { printf 'MAINTWARN %s\n' "$*" >> "$T/events"; }
apt_retry() { "$@"; }
APT_GET=(apt-get)
install() { local arg target=""; for arg in "$@"; do target="$arg"; done; mkdir -p -- "$target"; chmod 0700 "$target"; }
chown() { :; }
timeout() { shift; "$@"; }
dpkg() { [[ "$1" == --print-architecture ]] && cat "$T/arch"; }
uname() { case "$1" in -r) cat "$T/running_kernel" ;; -m) echo x86_64 ;; esac; }
pkg_installed() { [[ -e "$T/pkgs/$1" ]]; }
dpkg-query() {
  local fmt="" pkg pats=() a
  for a in "$@"; do
    case "$a" in
      -W) ;;
      -f=*) fmt="${a#-f=}" ;;
      *) pats+=("$a") ;;
    esac
  done
  if [[ "$fmt" == *'${Package}'* ]]; then
    local f name p
    for f in "$T"/pkgs/*; do
      [[ -e "$f" ]] || continue
      name="$(basename "$f")"
      for p in "${pats[@]}"; do
        case "$name" in $p) printf 'ii  %s\n' "$name"; break ;; esac
      done
    done
    return 0
  fi
  pkg="${pats[0]}"
  case "$fmt" in
    *Status-Abbrev*) if pkg_installed "$pkg"; then printf 'ii '; else return 1; fi ;;
    *Version*) pkg_installed "$pkg" && cat "$T/pkgs/$pkg" || return 1 ;;
    *Last-Modified*) [[ -e "$T/mtime/$pkg" ]] && cat "$T/mtime/$pkg" || return 1 ;;
  esac
}
apt-get() {
  printf 'apt-get %s\n' "$*" >> "$T/apt.calls"
  local a prev=""
  case " $* " in
    *" -s "*)
      if [[ -e "$T/phased_done" ]]; then src="$T/residual_after"; else src="$T/residual_before"; fi
      [[ -e "$src" ]] && tr ',' '\n' < "$src" | sed '/^$/d;s/^/Inst /;s/$/ [1] (2)/'
      return 0 ;;
  esac
  case "$*" in
    *Always-Include-Phased-Updates=true*upgrade*) : > "$T/phased_done" ;;
  esac
  for a in "$@"; do
    if [[ "$prev" == --no-install-recommends || ( "$a" != -* && "$prev" == "-y" ) ]]; then :; fi
    prev="$a"
  done
  if [[ " $* " == *" install "* ]]; then
    for a in "$@"; do
      case "$a" in intel-microcode|amd64-microcode|linux-firmware) mkdir -p "$T/pkgs"; echo "9.9-new" > "$T/pkgs/$a" ;; esac
    done
  fi
  return 0
}
apt-mark() { [[ "$1" == showhold ]] && { [[ -e "$T/holds" ]] && cat "$T/holds"; true; }; }
systemd-detect-virt() {
  local v="none"
  [[ -e "$T/virt" ]] && v="$(cat "$T/virt")"
  case "$1" in
    --container) echo none; return 1 ;;
    --vm) echo "$v"; [[ "$v" != none ]] ;;
  esac
}
if [[ -e "$T/has_needrestart" ]]; then needrestart() { cat "$T/needrestart"; }; fi
if [[ -e "$T/has_fwupd" ]]; then fwupdmgr() { cat "$T/fwupd.json"; }; fi
export WINS_FWOS_CPUINFO="$T/cpuinfo"
export WINS_FWOS_SYS_CPU_DIR="$T/sys-cpu"
export WINS_FWOS_DMI_DIR="$T/dmi"
export WINS_FWOS_BOOT_DIR="$T/boot"
export WINS_FWOS_PROC_STAT="$T/stat"
export WINS_FWOS_STATE_DIR="$T/state"
export WINSVPN_DEPLOY_STATE_DIR="$T/state"
export WINSVPN_REBOOT_REQUIRED_FILE="$T/reboot-required"
export WINSVPN_BOOT_ID_FILE="$T/boot-id"
'''

BOOT_A = "11111111-1111-4111-8111-111111111111"
BOOT_B = "22222222-2222-4222-8222-222222222222"


class Case:
    """A synthetic host in a temp directory."""

    def __init__(self, root: pathlib.Path):
        self.root = root
        for d in ("pkgs", "mtime", "sys-cpu", "dmi", "boot", "state"):
            (root / d).mkdir(exist_ok=True)
        self.set("arch", "amd64\n")
        self.set("running_kernel", "6.8.0-100-generic\n")
        self.set("cpuinfo", INTEL_METAL_CPUINFO)
        self.set("boot-id", BOOT_A + "\n")
        self.set("stat", "cpu 1 2 3\nbtime 1000\n")
        self.set("virt", "none\n")

    def set(self, name: str, content: str) -> None:
        (self.root / name).write_text(content)

    def pkg(self, name: str, version: str = "1.0") -> None:
        (self.root / "pkgs" / name).write_text(version + "\n")

    def loader(self, active: bool) -> None:
        d = self.root / "sys-cpu" / "cpu0" / "microcode"
        if active:
            d.mkdir(parents=True, exist_ok=True)
            (d / "version").write_text("0x2000065\n")
        elif d.exists():
            shutil.rmtree(self.root / "sys-cpu" / "cpu0")

    def needrestart(self, ksta: int, ucsta: int | None = None, kexp: str = "6.8.0-142-generic") -> None:
        (self.root / "has_needrestart").write_text("")
        lines = ["NEEDRESTART-VER: 3.6", "NEEDRESTART-KCUR: 6.8.0-100-generic"]
        lines.append(f"NEEDRESTART-KEXP: {kexp}")
        lines.append(f"NEEDRESTART-KSTA: {ksta}")
        if ucsta is not None:
            lines.append(f"NEEDRESTART-UCSTA: {ucsta}")
        self.set("needrestart", "\n".join(lines) + "\n")

    def kvm_guest(self) -> None:
        self.set("cpuinfo", INTEL_VM_CPUINFO)
        self.set("virt", "kvm\n")
        self.loader(False)

    def metal(self, vendor: str = "intel") -> None:
        self.set("cpuinfo", INTEL_METAL_CPUINFO if vendor == "intel" else AMD_METAL_CPUINFO)
        self.set("virt", "none\n")
        self.loader(True)

    def run(self, role: str, script: str, block: str | None = None) -> subprocess.CompletedProcess:
        body = (block if block is not None else install_block(role)) + "\n" + script
        path = self.root / "t.sh"
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(PRELUDE + body)
        return subprocess.run(
            [BASH, "t.sh"], cwd=self.root, check=False, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )

    def state(self) -> dict[str, str]:
        out: dict[str, str] = {}
        path = self.root / "state" / "firmware-os.state"
        for line in path.read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                out[k] = v
        return out

    def apt_calls(self) -> str:
        p = self.root / "apt.calls"
        return p.read_text() if p.exists() else ""

    def events(self) -> str:
        p = self.root / "events"
        return p.read_text() if p.exists() else ""


class FirmwareMicrocodeTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="wins-fwos-")
        self.addCleanup(self._tmp.cleanup)
        self.case = Case(pathlib.Path(self._tmp.name))

    def each_role(self):
        for role in INSTALLERS:
            self._tmp.cleanup()
            self._tmp = tempfile.TemporaryDirectory(prefix="wins-fwos-")
            self.case = Case(pathlib.Path(self._tmp.name))
            yield role

    def apply(self, role: str) -> subprocess.CompletedProcess:
        result = self.case.run(role, f"ensure_firmware_microcode {role}\n")
        self.assertEqual(0, result.returncode, result.stdout)
        return result

    # ---- virtual machines: record, do not install for show -----------------
    def test_kvm_guest_records_not_applicable_and_installs_nothing(self) -> None:
        for role in self.each_role():
            with self.subTest(role=role):
                self.case.kvm_guest()
                self.case.set("dmi/sys_vendor", "QEMU\n")
                self.case.set("dmi/product_name", "Standard PC (Q35 + ICH9)\n")
                self.apply(role)
                st = self.case.state()
                self.assertEqual("not-applicable", st["microcode_decision"])
                self.assertEqual("-", st["microcode_package"])
                self.assertIn("loader=inactive", st["microcode_evidence"])
                self.assertIn("hypervisor_flag=1", st["microcode_evidence"])
                self.assertEqual("vm:kvm", st["virt"])
                self.assertEqual("1", st["hypervisor_flag"])
                self.assertEqual("QEMU", st["dmi_vendor"])
                self.assertTrue(st["linux_firmware_decision"].startswith("not-applicable:vm"))
                calls = self.case.apt_calls()
                self.assertNotIn("microcode", calls)
                self.assertNotIn("linux-firmware", calls)
                self.assertFalse((self.case.root / "reboot-required").exists())

    def test_vm_with_linux_firmware_already_present_is_kept_not_reinstalled(self) -> None:
        for role in self.each_role():
            with self.subTest(role=role):
                self.case.kvm_guest()
                self.case.pkg("linux-firmware", "20240318.git3b128b60-0ubuntu2.26")
                self.apply(role)
                st = self.case.state()
                self.assertEqual("present-kept-current", st["linux_firmware_decision"])
                self.assertNotIn("install", self.case.apt_calls())

    def test_vm_with_firmware_mode_all_installs_firmware_but_never_microcode(self) -> None:
        self.case.kvm_guest()
        result = self.case.run(
            "data", "export WINS_LINUX_FIRMWARE_MODE=all\nensure_firmware_microcode data\n"
        )
        self.assertEqual(0, result.returncode, result.stdout)
        calls = self.case.apt_calls()
        self.assertIn("install -y --no-install-recommends linux-firmware", calls)
        self.assertNotIn("microcode", calls)

    def test_bad_firmware_mode_is_refused(self) -> None:
        result = self.case.run("data", "export WINS_LINUX_FIRMWARE_MODE=sometimes\nensure_firmware_microcode data\n")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("WINS_LINUX_FIRMWARE_MODE", self.case.events())

    # ---- bare metal ---------------------------------------------------------
    def test_bare_metal_intel_installs_firmware_and_intel_microcode_only(self) -> None:
        for role in self.each_role():
            with self.subTest(role=role):
                self.case.metal("intel")
                self.apply(role)
                calls = self.case.apt_calls()
                self.assertIn("install -y --no-install-recommends linux-firmware", calls)
                self.assertIn("install -y --no-install-recommends intel-microcode", calls)
                self.assertNotIn("amd64-microcode", calls)
                st = self.case.state()
                self.assertEqual("install", st["microcode_decision"])
                self.assertEqual("intel-microcode", st["microcode_package"])
                self.assertEqual("9.9-new", st["microcode_version_after"])
                self.assertEqual("bare-metal", st["virt"])

    def test_bare_metal_amd_installs_amd64_microcode_only(self) -> None:
        self.case.metal("amd")
        self.apply("data")
        calls = self.case.apt_calls()
        self.assertIn("amd64-microcode", calls)
        self.assertNotIn("intel-microcode", calls)

    def test_non_amd64_is_not_applicable_even_with_an_active_loader(self) -> None:
        self.case.metal("intel")
        self.case.set("arch", "arm64\n")
        self.apply("data")
        st = self.case.state()
        self.assertEqual("not-applicable", st["microcode_decision"])
        self.assertIn("arch=arm64", st["microcode_evidence"])

    def test_bare_metal_with_inactive_loader_is_recorded_not_installed(self) -> None:
        self.case.metal("intel")
        self.case.loader(False)
        self.apply("data")
        st = self.case.state()
        self.assertEqual("not-applicable", st["microcode_decision"])
        self.assertIn("loader=inactive", st["microcode_evidence"])
        self.assertIn("hypervisor_flag=0", st["microcode_evidence"])
        self.assertNotIn("microcode", self.case.apt_calls())

    def test_package_install_failure_fails_the_step(self) -> None:
        self.case.metal("intel")
        result = self.case.run(
            "data",
            'apt-get() { if [[ " $* " == *" intel-microcode "* ]]; then return 1; fi; return 0; }\n'
            "ensure_firmware_microcode data\n",
        )
        self.assertNotEqual(0, result.returncode)
        self.assertFalse((self.case.root / "state" / "firmware-os.state").exists())

    # ---- fwupd --------------------------------------------------------------
    def test_fwupd_is_recorded_read_only_and_never_applied(self) -> None:
        self.case.metal("intel")
        (self.case.root / "has_fwupd").write_text("")
        self.case.set("fwupd.json", '{"Devices":[{"DeviceId":"a"},{"DeviceId":"b"}]}\n')
        self.apply("data")
        st = self.case.state()
        self.assertEqual("present-readonly", st["fwupd"])
        self.assertEqual("2", st["fwupd_devices"])
        self.assertNotIn("fwupd", self.case.apt_calls())

    def test_fwupd_on_a_vm_is_skipped(self) -> None:
        self.case.kvm_guest()
        (self.case.root / "has_fwupd").write_text("")
        self.apply("data")
        self.assertEqual("present-skipped-vm", self.case.state()["fwupd"])

    def test_fwupd_absent_is_not_installed(self) -> None:
        self.case.metal("intel")
        self.apply("data")
        self.assertEqual("absent", self.case.state()["fwupd"])
        self.assertNotIn("fwupd", self.case.apt_calls())

    # ---- reboot evidence and the pause boundary ------------------------------
    def test_pending_microcode_raises_the_standard_flag_and_pause_returns_75(self) -> None:
        for role in self.each_role():
            with self.subTest(role=role):
                self.case.metal("intel")
                self.case.needrestart(ksta=1, ucsta=2)
                self.apply(role)
                flag = self.case.root / "reboot-required"
                self.assertTrue(flag.exists())
                self.assertIn("microcode", (self.case.root / "reboot-required.pkgs").read_text())
                st = self.case.state()
                self.assertEqual("1", st["reboot_required"])
                self.assertEqual("microcode", st["reboot_reasons"])
                self.assertEqual(BOOT_A, st["raised_boot_id"])
                # The existing boundary turns the flag into a marker and status 75.
                source = INSTALLERS[role].read_text(encoding="utf-8")
                pause = function_body(source, "pause_for_required_reboot")
                result = self.case.run(
                    role,
                    pause
                    + f"\nset +e; pause_for_required_reboot {role}; rc=$?; set -e\n"
                    + 'echo "rc=${rc}" > rc.txt\n',
                )
                self.assertEqual(0, result.returncode, result.stdout)
                self.assertEqual("rc=75", (self.case.root / "rc.txt").read_text().strip())
                marker = self.case.root / "state" / f"{role}.reboot-required"
                self.assertIn(f"boot_id={BOOT_A}", marker.read_text())

    def test_full_cycle_pause_reboot_rerun_resumes_without_a_second_pause(self) -> None:
        role = "data"
        self.case.metal("intel")
        self.case.needrestart(ksta=3, ucsta=1)
        self.apply(role)
        self.assertEqual("kernel", self.case.state()["reboot_reasons"])
        source = INSTALLERS[role].read_text(encoding="utf-8")
        pause = function_body(source, "pause_for_required_reboot")
        first = self.case.run(role, pause + f"\nset +e; pause_for_required_reboot {role}; echo $? > rc1\n")
        self.assertEqual(0, first.returncode, first.stdout)
        self.assertEqual("75", (self.case.root / "rc1").read_text().strip())
        # Reboot: new boot id, tmpfs flag gone, kernel now current.
        (self.case.root / "reboot-required").unlink()
        (self.case.root / "reboot-required.pkgs").unlink()
        self.case.set("boot-id", BOOT_B + "\n")
        self.case.set("running_kernel", "6.8.0-142-generic\n")
        self.case.needrestart(ksta=1, ucsta=1)
        self.apply(role)
        st = self.case.state()
        self.assertEqual("0", st["reboot_required"])
        self.assertEqual("", st["raised_boot_id"])
        self.assertFalse((self.case.root / "reboot-required").exists())
        second = self.case.run(role, pause + f"\nset +e; pause_for_required_reboot {role}; echo $? > rc2\n")
        self.assertEqual(0, second.returncode, second.stdout)
        self.assertEqual("0", (self.case.root / "rc2").read_text().strip())
        self.assertFalse((self.case.root / "state" / f"{role}.reboot-required").exists())

    def test_condition_that_survives_a_reboot_is_reported_not_raised_again(self) -> None:
        self.case.metal("intel")
        self.case.needrestart(ksta=3, ucsta=1)
        self.apply("data")
        self.assertTrue((self.case.root / "reboot-required").exists())
        # Reboot happened (new boot id, flag gone) but the kernel did not change.
        (self.case.root / "reboot-required").unlink()
        self.case.set("boot-id", BOOT_B + "\n")
        self.apply("data")
        st = self.case.state()
        self.assertFalse((self.case.root / "reboot-required").exists())
        self.assertEqual("kernel", st["unresolved_after_reboot"])
        self.assertIn("not requesting another", self.case.events())

    def test_a_newer_kernel_after_the_reboot_is_a_new_request_not_a_survivor(self) -> None:
        self.case.metal("intel")
        self.case.needrestart(ksta=3, ucsta=1, kexp="6.8.0-142-generic")
        self.apply("data")
        first = self.case.state()
        self.assertEqual(BOOT_A, first["raised_boot_id"])
        (self.case.root / "reboot-required").unlink()
        self.case.set("boot-id", BOOT_B + "\n")
        self.case.needrestart(ksta=3, ucsta=1, kexp="6.8.0-150-generic")
        self.apply("data")
        st = self.case.state()
        self.assertTrue((self.case.root / "reboot-required").exists())
        self.assertEqual("none", st["unresolved_after_reboot"])
        self.assertEqual(BOOT_B, st["raised_boot_id"])
        self.assertIn("kernel", st["raised_identity"])
        self.assertIn("6.8.0-150-generic", st["raised_identity"])

    def test_a_failed_state_write_stops_the_step_instead_of_losing_the_reboot_guard(self) -> None:
        for role in self.each_role():
            with self.subTest(role=role):
                self.case.metal("intel")
                self.case.needrestart(ksta=3, ucsta=1)
                result = self.case.run(
                    role,
                    "wins_fwos_write_state() { cat > /dev/null; return 1; }\n"
                    f"ensure_firmware_microcode {role}\n",
                )
                self.assertNotEqual(0, result.returncode, result.stdout)
                self.assertIn("ERR Could not write the firmware and OS state record", self.case.events())

    def test_failed_reboot_flag_write_stops_before_recording_a_request(self) -> None:
        for role in self.each_role():
            with self.subTest(role=role):
                self.case.metal("intel")
                self.case.needrestart(ksta=3, ucsta=1)
                self.case.set("flag-parent", "regular file\n")
                result = self.case.run(
                    role,
                    'export WINSVPN_REBOOT_REQUIRED_FILE='
                    '"$T/flag-parent/reboot-required"\n'
                    f"ensure_firmware_microcode {role}\n",
                )
                self.assertNotEqual(0, result.returncode, result.stdout)
                self.assertIn("ERR Could not write", self.case.events())
                self.assertFalse(
                    (self.case.root / "state" / "firmware-os.state").exists()
                )

    def test_a_later_new_update_can_raise_the_flag_again(self) -> None:
        self.case.metal("intel")
        self.case.needrestart(ksta=3, ucsta=1)
        self.apply("data")
        (self.case.root / "reboot-required").unlink()
        self.case.set("boot-id", BOOT_B + "\n")
        self.case.needrestart(ksta=1, ucsta=1)
        self.apply("data")
        self.assertEqual("", self.case.state()["raised_boot_id"])
        self.case.needrestart(ksta=3, ucsta=1)
        self.apply("data")
        self.assertTrue((self.case.root / "reboot-required").exists())

    def test_kernel_fallback_without_needrestart_compares_boot_images(self) -> None:
        self.case.metal("intel")
        (self.case.root / "boot" / "vmlinuz-6.8.0-100-generic").write_text("")
        (self.case.root / "boot" / "vmlinuz-6.8.0-142-generic").write_text("")
        (self.case.root / "boot" / "vmlinuz-6.8.0-999-kvm").write_text("")
        self.apply("data")
        st = self.case.state()
        self.assertEqual("version_upgrade", st["kernel_state"])
        self.assertEqual("6.8.0-142-generic", st["expected_kernel"])
        self.assertTrue((self.case.root / "reboot-required").exists())

    def test_kernel_fallback_current_when_running_the_newest(self) -> None:
        self.case.metal("intel")
        self.case.set("running_kernel", "6.8.0-142-generic\n")
        (self.case.root / "boot" / "vmlinuz-6.8.0-142-generic").write_text("")
        self.apply("data")
        self.assertEqual("current", self.case.state()["kernel_state"])
        self.assertEqual("0", self.case.state()["reboot_required"])

    def test_microcode_fallback_uses_dpkg_change_time_against_boot_time(self) -> None:
        self.case.metal("intel")
        self.case.set("running_kernel", "6.8.0-142-generic\n")
        (self.case.root / "boot" / "vmlinuz-6.8.0-142-generic").write_text("")
        self.case.pkg("intel-microcode", "3.1")
        (self.case.root / "mtime" / "intel-microcode").write_text("2000\n")  # after btime 1000
        self.apply("data")
        st = self.case.state()
        self.assertEqual("obsolete", st["microcode_state"])
        self.assertEqual("dpkg-mtime", st["microcode_method"])
        self.assertEqual("microcode", st["reboot_reasons"])
        (self.case.root / "reboot-required").unlink()
        self.case.set("boot-id", BOOT_B + "\n")
        self.case.set("stat", "btime 3000\n")
        self.apply("data")
        self.assertEqual("current", self.case.state()["microcode_state"])
        self.assertFalse((self.case.root / "reboot-required").exists())

    def test_vm_never_reports_microcode_pending(self) -> None:
        self.case.kvm_guest()
        self.case.needrestart(ksta=1)  # needrestart prints no UCSTA inside a VM
        self.apply("data")
        st = self.case.state()
        self.assertEqual("unknown", st["microcode_state"])
        self.assertEqual("0", st["reboot_required"])

    def test_existing_apt_flag_is_honoured_and_not_rewritten(self) -> None:
        self.case.metal("intel")
        self.case.set("reboot-required", "*** System restart required ***\n")
        self.case.set("running_kernel", "6.8.0-142-generic\n")
        (self.case.root / "boot" / "vmlinuz-6.8.0-142-generic").write_text("")
        self.apply("data")
        st = self.case.state()
        self.assertEqual("1", st["reboot_required"])
        self.assertEqual("reboot-required-file", st["reboot_reasons"])
        self.assertFalse((self.case.root / "reboot-required.pkgs").exists())

    # ---- OS currency --------------------------------------------------------
    def test_phased_pass_runs_once_and_records_what_remains(self) -> None:
        self.case.metal("intel")
        self.case.set("residual_before", "libfoo,libbar")
        self.case.set("residual_after", "")
        self.apply("data")
        calls = self.case.apt_calls()
        self.assertEqual(1, calls.count("Always-Include-Phased-Updates=true upgrade -y --with-new-pkgs"))
        st = self.case.state()
        self.assertEqual("1", st["phased_pass"])
        self.assertEqual("none", st["upgradable_after"])

    def test_phased_pass_uses_full_upgrade_only_when_removals_are_allowed(self) -> None:
        self.case.metal("intel")
        self.case.set("residual_before", "libfoo")
        result = self.case.run("data", "export APT_ALLOW_REMOVALS=1\nensure_firmware_microcode data\n")
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("Always-Include-Phased-Updates=true full-upgrade -y", self.case.apt_calls())

    def test_phased_pass_can_be_disabled(self) -> None:
        self.case.metal("intel")
        self.case.set("residual_before", "libfoo")
        result = self.case.run("data", "export WINS_APT_INCLUDE_PHASED=0\nensure_firmware_microcode data\n")
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertNotIn("upgrade -y --with-new-pkgs", self.case.apt_calls())
        self.assertEqual("0", self.case.state()["phased_pass"])

    def test_residual_after_the_pass_is_warned_and_recorded(self) -> None:
        self.case.metal("intel")
        self.case.set("residual_before", "libfoo")
        self.case.set("residual_after", "libfoo")
        self.apply("data")
        self.assertIn("libfoo", self.case.state()["upgradable_after"])
        self.assertIn("WARN Packages still upgradable", self.case.events())

    def test_cloudflared_hold_is_expected_other_holds_warn(self) -> None:
        self.case.metal("intel")
        self.case.set("holds", "cloudflared\n")
        self.apply("data")
        self.assertNotIn("on hold", self.case.events())
        self.assertEqual("cloudflared", self.case.state()["held_packages"])
        self.assertEqual("none", self.case.state()["unexpected_holds"])
        self.case.set("holds", "cloudflared\nlinux-image-generic\n")
        self.apply("data")
        self.assertIn("linux-image-generic", self.case.state()["unexpected_holds"])
        self.assertIn("on hold", self.case.events())

    def test_missing_kernel_metapackage_is_reported(self) -> None:
        self.case.metal("intel")
        self.apply("data")
        self.assertEqual("none", self.case.state()["kernel_track"])
        self.assertIn("No kernel metapackage", self.case.events())
        self.case.pkg("linux-image-generic")
        self.case.pkg("linux-image-6.8.0-100-generic")
        self.apply("data")
        self.assertEqual("linux-image-generic", self.case.state()["kernel_track"])

    # ---- idempotence and structure -------------------------------------------
    def test_rerun_is_idempotent(self) -> None:
        for role in self.each_role():
            with self.subTest(role=role):
                self.case.metal("amd")
                self.case.needrestart(ksta=1, ucsta=1)
                self.apply(role)
                volatile = {"recorded_at_utc", "microcode_version_before"}
                first = {k: v for k, v in self.case.state().items() if k not in volatile}
                self.apply(role)
                second = {k: v for k, v in self.case.state().items() if k not in volatile}
                self.assertEqual(first, second)
                self.assertFalse((self.case.root / "reboot-required").exists())

    def test_state_record_has_the_fields_operators_read(self) -> None:
        self.case.metal("intel")
        self.apply("data")
        st = self.case.state()
        for key in (
            "schema", "role", "recorded_at_utc", "boot_id", "virt", "microcode_decision",
            "microcode_evidence", "linux_firmware_decision", "fwupd", "running_kernel",
            "kernel_state", "reboot_required", "reboot_reasons", "held_packages",
            "upgradable_after", "kernel_track", "unresolved_after_reboot",
        ):
            self.assertIn(key, st)
        self.assertEqual("data", st["role"])
        self.assertEqual("1", st["schema"])

    def test_block_is_byte_identical_in_the_three_installers(self) -> None:
        blocks = {role: install_block(role) for role in INSTALLERS}
        self.assertEqual(1, len(set(blocks.values())), "install block differs between installers")
        self.assertIn("ensure_firmware_microcode", blocks["data"])

    def test_weekly_block_is_identical_in_the_three_installers_and_copies_the_installer_functions(self) -> None:
        # The standalone gateway installer is a tombstone (design v17 2.8) and
        # has no weekly maintenance of its own: the gateway runs on a data plane,
        # whose weekly maintenance carries this block (2.1 E, 2.2 "merged").
        weeklies = {p.name: weekly_block(p) for p in INSTALLERS.values()}
        self.assertEqual(1, len(set(weeklies.values())), "weekly block differs between scripts")
        install = install_block("data")
        for name in (
            "wins_fwos_clean", "wins_fwos_timeout", "wins_fwos_reboot_evidence",
            "wins_fwos_residual_upgrades", "wins_fwos_held_packages",
        ):
            self.assertIn(function_body(install, name), weeklies["wins_data_plane_setup_ONETOUCH.sh"], name)

    def test_the_gateway_hosts_weekly_os_currency_runs_in_the_data_planes_weekly_maintenance(self) -> None:
        # Design v17 2.1 E and 2.2: the data plane owns weekly maintenance for
        # the gateway's host. The weekly block, its call and the restart of a
        # failed gateway sit in the one generated wins-weekly-maintenance script.
        source = INSTALLERS["data"].read_text(encoding="utf-8")
        start = source.index("\nwrite_weekly_maintenance() {\n") + 1
        opener = "cat > /usr/local/bin/wins-weekly-maintenance <<'EOF'\n"
        self.assertEqual(1, source.count(opener))
        begin = source.index(opener)
        # The heredoc is the first thing write_weekly_maintenance writes: no
        # other function starts between the definition and the opener.
        self.assertEqual(["write_weekly_maintenance() {"],
                         re.findall(r"^[A-Za-z_][A-Za-z0-9_]*\(\) \{$", source[start:begin], re.M))
        script = source[begin + len(opener):source.index("\nEOF\n", begin)]
        self.assertEqual(1, script.count("# WINS-FWOS-WEEKLY-BEGIN"))
        self.assertEqual(1, script.count("# WINS-FWOS-WEEKLY-END"))
        self.assertIn(weekly_block(INSTALLERS["data"]).rstrip("\n"), script)
        self.assertEqual(1, script.count('record_os_currency || maint_warn "OS currency check failed"'))
        self.assertIn("if systemctl is-failed --quiet winn3-gateway.service; then\n"
                      "  run_step \"restart failed Winn v3 gateway\"", script)
        self.assertEqual(1, source.count("# WINS-FWOS-WEEKLY-BEGIN"))

    def test_the_block_never_reboots_and_never_returns_75(self) -> None:
        code = "\n".join(
            line for line in install_block("data").splitlines() if not line.lstrip().startswith("#")
        )
        for forbidden in (r"systemctl\s+reboot", r"\bshutdown\b", r"\breboot\s*(;|$)", r"\bexit\s+75\b", r"return\s+75\b", r"\bkexec\b"):
            self.assertIsNone(re.search(forbidden, code, re.M), forbidden)

    def test_call_sites_sit_inside_apt_install_before_the_reboot_pause(self) -> None:
        for role, path in INSTALLERS.items():
            with self.subTest(role=role):
                source = path.read_text(encoding="utf-8")
                apt_install = function_body(source, "apt_install")
                self.assertEqual(1, apt_install.count(f"ensure_firmware_microcode {role} || return 1"))
                self.assertLess(
                    apt_install.index("upgrade -y --with-new-pkgs"),
                    apt_install.index("ensure_firmware_microcode"),
                )
                main = source[source.rfind("\nmain() {") :]
                self.assertLess(main.index("\n  apt_install\n"), main.index(f"\n  pause_for_required_reboot {role}\n"))
                self.assertNotIn("ensure_firmware_microcode", main)

    def test_weekly_status_files_gain_the_new_fields_in_all_scripts(self) -> None:
        for path in INSTALLERS.values():
            with self.subTest(script=path.name):
                text = path.read_text(encoding="utf-8")
                for field in ("reboot_required", "reboot_reasons", "running_kernel", "expected_kernel", "held_packages", "upgradable_after"):
                    self.assertIn(f"printf '{field}=%s\\n'", text)
                self.assertIn('record_os_currency || maint_warn "OS currency check failed"', text)

    def test_weekly_record_reports_pending_reboot_and_never_reboots(self) -> None:
        self.case.metal("intel")
        self.case.needrestart(ksta=3, ucsta=1)
        self.case.set("holds", "cloudflared\n")
        self.case.set("residual_before", "")
        (self.case.root / "state" / "firmware-os.state").write_text("microcode_package=intel-microcode\n")
        weekly = weekly_block(INSTALLERS["data"])
        result = self.case.run(
            "data",
            "record_os_currency\n"
            'printf "%s|%s|%s|%s|%s\\n" "$OS_REBOOT_REQUIRED" "$OS_REBOOT_REASONS" "$OS_UPGRADABLE" "$OS_HELD" "$OS_EXPECTED_KERNEL" > out.txt\n',
            block=weekly,
        )
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertEqual("1|kernel|none|cloudflared|6.8.0-142-generic", (self.case.root / "out.txt").read_text().strip())
        self.assertIn("weekly maintenance never reboots", self.case.events())
        self.assertFalse((self.case.root / "reboot-required").exists())

    def test_weekly_record_warns_when_packages_remain_upgradable(self) -> None:
        self.case.metal("intel")
        self.case.needrestart(ksta=1, ucsta=1)
        self.case.set("residual_before", "libfoo")
        result = self.case.run("data", "record_os_currency\n", block=weekly_block(INSTALLERS["data"]))
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("MAINTWARN packages still upgradable", self.case.events())

    # ---- a failed "apt-get -s" is unknown, never "none" -----------------------
    SIMULATION_FAILS = (
        'apt-get() { printf "apt-get %s\\n" "$*" >> "$T/apt.calls"; '
        'case " $* " in *" -s "*) echo "E: Could not get lock" >&2; return 100 ;; esac; return 0; }\n'
    )

    def test_failed_simulation_is_recorded_unknown_not_none(self) -> None:
        for role in self.each_role():
            with self.subTest(role=role):
                self.case.metal("intel")
                result = self.case.run(role, self.SIMULATION_FAILS + f"ensure_firmware_microcode {role}\n")
                self.assertEqual(0, result.returncode, result.stdout)
                self.assertEqual("unknown", self.case.state()["upgradable_after"])
                self.assertEqual("0", self.case.state()["phased_pass"])
                self.assertIn("WARN apt-get -s failed", self.case.events())

    def test_failed_holds_query_is_recorded_unknown_not_none(self) -> None:
        self.case.metal("intel")
        result = self.case.run(
            "data", 'apt-mark() { return 1; }\nensure_firmware_microcode data\n'
        )
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertEqual("unknown", self.case.state()["held_packages"])

    def test_weekly_failed_simulation_is_unknown_and_warns(self) -> None:
        self.case.metal("intel")
        self.case.needrestart(ksta=1, ucsta=1)
        result = self.case.run(
            "data",
            self.SIMULATION_FAILS
            + "record_os_currency\n"
            + 'printf "%s" "$OS_UPGRADABLE" > out.txt\n',
            block=weekly_block(INSTALLERS["data"]),
        )
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertEqual("unknown", (self.case.root / "out.txt").read_text())
        self.assertIn("MAINTWARN apt-get -s failed", self.case.events())

    def test_weekly_residual_respects_phasing_like_the_weekly_upgrade(self) -> None:
        self.case.metal("intel")
        self.case.needrestart(ksta=1, ucsta=1)
        result = self.case.run("data", "record_os_currency\n", block=weekly_block(INSTALLERS["data"]))
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertNotIn("Always-Include-Phased-Updates", self.case.apt_calls())

    def test_extraction_is_not_vacuous(self) -> None:
        with self.assertRaises(AssertionError):
            extract(INSTALLERS["data"], "# NO-SUCH-BLOCK-BEGIN", "# NO-SUCH-BLOCK-END")


if __name__ == "__main__":
    unittest.main()
