import pathlib, re, unittest
ROOT = pathlib.Path(__file__).resolve().parents[3]
INSTALLER = ROOT / "linux/packaging/install.sh"
UNIT = ROOT / "linux/packaging/winsvpn-recover.service"
RECOVER = ROOT / "linux/packaging/winsvpn-recover"


class RecoveryPackagingTest(unittest.TestCase):
    def test_recover_script_executable_and_unit_installed(self) -> None:
        src = INSTALLER.read_text(encoding="utf-8")
        blanket = src.index('find "$stage" -type f -exec chmod 0644')
        self.assertGreater(
            src.index('chmod 0755 -- "$stage/share/wins-vpn/winsvpn-recover"'),
            blanket)
        self.assertIn(
            "recover_unit=/etc/systemd/system/winsvpn-recover.service", src)
        self.assertIn('mv -Tf -- "$recover_unit_new" "$recover_unit"', src)

    def test_recover_unit_orders_after_persistence_and_waits_for_lock(self) -> None:
        unit = UNIT.read_text(encoding="utf-8")
        after: set[str] = set()
        for line in unit.splitlines():
            if line.startswith("After="):
                after.update(line.split("=", 1)[1].split())
        for name in ("netfilter-persistent.service", "iptables.service",
                     "nftables.service"):
            self.assertIn(name, after)
        self.assertIn("RequiresMountsFor=/opt/wins-vpn", unit.splitlines())
        calls = [line for line in RECOVER.read_text(encoding="utf-8").splitlines()
                 if re.search(r'"\$tool" -', line)]
        self.assertTrue(calls)
        for line in calls:
            self.assertIn("-w 5", line)


if __name__ == "__main__":
    unittest.main()
