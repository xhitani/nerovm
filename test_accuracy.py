import unittest
from unittest.mock import patch

import masscan_scan
import nikto_scan
import sensors
import dashboard


class NetworkAccuracyTests(unittest.TestCase):
    def test_lan_membership_rejects_similar_prefixes(self):
        self.assertTrue(sensors._is_lan("192.168.1.25"))
        self.assertFalse(sensors._is_lan(sensors.ROUTER_IP))
        self.assertFalse(sensors._is_lan("192.168.10.25"))
        self.assertFalse(sensors._is_lan("not-an-ip"))

    def test_register_device_normalizes_and_rejects_invalid_values(self):
        sensors.devices.clear()
        with patch.object(sensors.memory, "upsert_device"):
            self.assertTrue(
                sensors._register_device(
                    "192.168.1.25", "AA:BB:CC:DD:EE:FF", "Linux", "TEST"
                )
            )
        self.assertEqual(sensors.devices["192.168.1.25"]["mac"], "aa:bb:cc:dd:ee:ff")
        self.assertFalse(sensors._register_device("not-an-ip", "aa:bb", "Linux"))
        self.assertFalse(
            sensors._register_device(
                "192.168.1.26", "ff:ff:ff:ff:ff:ff", "Linux"
            )
        )
        self.assertFalse(
            sensors._register_device("192.168.1.26", "not-a-mac", "Linux")
        )

    def test_masscan_process_ignores_invalid_ports(self):
        raw = [
            {
                "ip": "192.168.1.25",
                "ports": [
                    {"proto": "tcp", "port": 443},
                    {"proto": "udp", "port": 53},
                    {"proto": "tcp", "port": "bad"},
                    {"proto": "tcp", "port": 70000},
                ],
            }
            ,
            {
                "ip": "192.168.10.25",
                "ports": [{"proto": "tcp", "port": 22}],
            },
        ]
        masscan_scan.scan_results.clear()
        found = masscan_scan._process(raw)
        self.assertEqual(found["192.168.1.25"], {443})

    def test_nikto_parser_classifies_findings(self):
        findings = nikto_scan._parse(
            "+ /admin: default password found\n"
            "+ /debug: debug endpoint exposed\n",
            80,
        )
        self.assertEqual([f["severity"] for f in findings], ["critical", "medium"])

    def test_dashboard_rejects_unknown_devices(self):
        client = dashboard.app.test_client()
        response = client.post("/api/block/192.168.1.250")
        self.assertEqual(response.status_code, 400)
        response = client.get("/api/device/192.168.10.25")
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
