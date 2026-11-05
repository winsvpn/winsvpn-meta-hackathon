import unittest
from unittest import mock
from xml.etree import ElementTree as ET

try:
    from tools import android_release_ui_driver as driver_module
except ModuleNotFoundError:
    import android_release_ui_driver as driver_module


def node(label: str) -> ET.Element:
    return ET.Element(
        "node",
        {
            "content-desc": label,
            "bounds": "[0,0][100,100]",
        },
    )


class AndroidReleaseUiDriverTests(unittest.TestCase):
    def test_launch_clears_camouflage_display_before_entering_pin(self) -> None:
        driver = object.__new__(driver_module.AndroidDriver)
        driver.package = "org.winsvpn.app"
        driver.pin = "1357"
        driver.adb_run = mock.Mock(return_value="")
        controls = {
            "Calculator 1": node("Calculator 1"),
            "Calculator AC": node("Calculator AC"),
            "Calculator 3": node("Calculator 3"),
            "Calculator 5": node("Calculator 5"),
            "Calculator 7": node("Calculator 7"),
            "Connect VPN": node("Connect VPN"),
        }
        driver.find = mock.Mock(side_effect=lambda label, **_: controls.get(label))
        tapped: list[str] = []
        driver.tap = mock.Mock(
            side_effect=lambda control: tapped.append(
                driver_module.AndroidDriver.label(control)
            )
        )

        with mock.patch.object(driver_module.time, "sleep"):
            driver.launch()

        self.assertEqual(
            tapped,
            [
                "Calculator AC",
                "Calculator 1",
                "Calculator 3",
                "Calculator 5",
                "Calculator 7",
            ],
        )
        driver.adb_run.assert_called_once_with(
            [
                "shell",
                "monkey",
                "-p",
                "org.winsvpn.app",
                "-c",
                "android.intent.category.LAUNCHER",
                "1",
            ]
        )

    def test_post_tunnel_battery_sheet_is_denied_before_runtime_proof(self) -> None:
        driver = object.__new__(driver_module.AndroidDriver)
        deny = ET.Element(
            "node",
            {
                "text": "Don’t allow",
                "resource-id": "android:id/button2",
                "bounds": "[0,0][100,100]",
            },
        )
        driver.adb_run = mock.Mock(
            side_effect=[
                "mCurrentFocus com.android.settings/.fuelgauge.RequestIgnoreBatteryOptimizations",
                "mCurrentFocus org.winsvpn.app/.MainActivity",
            ]
        )
        driver.nodes = mock.Mock(return_value=[deny])
        driver.tap = mock.Mock()

        with mock.patch.object(driver_module.time, "sleep"):
            driver.handle_post_tunnel_battery_exemption()

        driver.tap.assert_called_once_with(deny)
        self.assertEqual(driver.adb_run.call_count, 2)

    def test_connect_handles_optional_battery_sheet_before_connected_proof(self) -> None:
        driver = object.__new__(driver_module.AndroidDriver)
        order: list[str] = []
        connect_button = node("Connect VPN")
        driver.launch = mock.Mock(side_effect=lambda: order.append("launch"))
        driver.find_scroll = mock.Mock(
            side_effect=lambda *_args, **_kwargs: (
                order.append("find-connect") or connect_button
            )
        )
        driver.tap = mock.Mock(side_effect=lambda _node: order.append("tap-connect"))
        driver.handle_vpn_permission = mock.Mock(
            side_effect=lambda: order.append("vpn-permission")
        )
        driver.handle_post_tunnel_battery_exemption = mock.Mock(
            side_effect=lambda: order.append("battery-after-tunnel")
        )
        driver.wait_connected = mock.Mock(
            side_effect=lambda: order.append("runtime-proof")
        )

        driver.connect()

        self.assertEqual(
            order,
            [
                "launch",
                "find-connect",
                "tap-connect",
                "vpn-permission",
                "battery-after-tunnel",
                "runtime-proof",
            ],
        )


if __name__ == "__main__":
    unittest.main()
