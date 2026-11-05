import pathlib, re, shlex, shutil, subprocess, sys, tempfile, unittest
ROOT = pathlib.Path(__file__).resolve().parents[3]
INSTALLER = ROOT / "linux/packaging/install.sh"

def _function(name: str) -> str:
    src = INSTALLER.read_text(encoding="utf-8")
    start = src.index(f"{name}() {{\n")
    return src[start:src.index("\n}\n", start) + 3]

class UpgradeGuardTests(unittest.TestCase):
    def test_guard_runs_before_target_is_moved(self) -> None:
        src = INSTALLER.read_text(encoding="utf-8")
        self.assertLess(src.index("\nrefuse_running_bundle\n"),
                        src.index('mv -- "$TARGET" "$backup"'))

    def test_lock_not_in_world_writable_dir(self) -> None:
        self.assertNotIn("/run/lock/", INSTALLER.read_text(encoding="utf-8"))

    def test_umask_set_before_any_helper(self) -> None:
        src = INSTALLER.read_text(encoding="utf-8")
        self.assertLess(src.index("\numask 022\n"),
                        src.index("linux_native_host_overlay() {"))

    def test_pkexec_required(self) -> None:
        src = INSTALLER.read_text(encoding="utf-8")
        start = src.index("for required in bash curl")
        self.assertIn("pkexec", src[start:src.index("; do", start)])

    def test_arch_install_does_not_upgrade_the_system(self) -> None:
        src = INSTALLER.read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"(?m)^\s*pacman -Syu", src))

    @unittest.skipUnless(sys.platform.startswith("linux"), "needs /proc")
    def test_guard_refuses_process_running_from_target(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            target = pathlib.Path(raw) / "wins-vpn"
            target.mkdir()
            shutil.copy2("/bin/sleep", target / "wins_vpn")
            proc = subprocess.Popen([str(target / "wins_vpn"), "30"])
            try:
                script = ("die() { printf '%s\\n' \"$*\" >&2; exit 1; }\n"
                          f"TARGET={shlex.quote(str(target))}\n"
                          + _function("refuse_running_bundle") + "refuse_running_bundle\n")
                r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=10)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn("still running", r.stderr)
            finally:
                proc.kill(); proc.wait()
