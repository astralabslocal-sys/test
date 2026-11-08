"""Parser-Tests mit echten Beispielausgaben.  python -m unittest discover -s tests"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import collectors as c  # noqa: E402

PING_OK = """PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.

--- 1.1.1.1 ping statistics ---
10 packets transmitted, 9 received, 10% packet loss, time 1823ms
rtt min/avg/max/mdev = 11.204/13.587/19.902/2.441 ms
"""
PING_DEAD = """PING 10.9.9.9 (10.9.9.9) 56(84) bytes of data.

--- 10.9.9.9 ping statistics ---
10 packets transmitted, 0 received, 100% packet loss, time 1840ms
"""
PING_BUSYBOX = """--- 8.8.8.8 ping statistics ---
4 packets transmitted, 4 packets received, 0% packet loss
round-trip min/avg/max = 15.1/16.2/18.0 ms
"""
IW_LINK = """Connected to 3c:a6:2f:aa:bb:cc (on wlan0)
\tSSID: Zuhause-5G
\tfreq: 5180.0
\tRX: 123456 bytes (789 packets)
\tTX: 23456 bytes (123 packets)
\tsignal: -57 dBm
\trx bitrate: 433.3 MBit/s VHT-MCS 9 80MHz short GI VHT-NSS 1
\ttx bitrate: 390.0 MBit/s VHT-MCS 8 80MHz short GI VHT-NSS 1
\tbss flags: short-slot-time
\tdtim period: 1
\tbeacon int: 100
"""
NMCLI = (
    "3C\\:A6\\:2F\\:AA\\:BB\\:CC:Zuhause-5G:36:5180 MHz:86:WPA2 WPA3\n"
    "AA\\:BB\\:CC\\:00\\:11\\:22:Nachbar\\:EG:6:2437 MHz:40:WPA2\n"
    "AA\\:BB\\:CC\\:00\\:11\\:33::11:2462 MHz:15:\n"
    "kaputte zeile\n"
)
IW_SCAN = """BSS 3c:a6:2f:aa:bb:cc(on wlan0) -- associated
\tlast seen: 120 ms ago
\tfreq: 2437
\tsignal: -48.00 dBm
\tSSID: Zuhause
\tRSN:\t * Version: 1
BSS aa:bb:cc:00:11:22(on wlan0)
\tfreq: 5240.0
\tsignal: -77.00 dBm
\tSSID:
\tWPA:\t * Version: 1
"""


class TestPing(unittest.TestCase):
    def test_ok(self):
        r = c.parse_ping(PING_OK)
        self.assertEqual((r["sent"], r["recv"], r["loss"]), (10, 9, 10.0))
        self.assertEqual((r["rtt_min"], r["rtt_avg"], r["rtt_max"], r["jitter"]), (11.204, 13.587, 19.902, 2.441))

    def test_dead(self):
        r = c.parse_ping(PING_DEAD)
        self.assertEqual(r["loss"], 100.0)
        self.assertIsNone(r["rtt_avg"])

    def test_busybox(self):
        r = c.parse_ping(PING_BUSYBOX)
        self.assertEqual(r["recv"], 4)
        self.assertEqual(r["rtt_avg"], 16.2)
        self.assertIsNone(r["jitter"])

    def test_garbage(self):
        self.assertIsNone(c.parse_ping("ping: unknown host"))


class TestLink(unittest.TestCase):
    def test_connected(self):
        r = c.parse_iw_link(IW_LINK)
        self.assertTrue(r["connected"])
        self.assertEqual(r["ssid"], "Zuhause-5G")
        self.assertEqual(r["bssid"], "3c:a6:2f:aa:bb:cc")
        self.assertEqual((r["freq"], r["channel"], r["band"]), (5180, 36, "5"))
        self.assertEqual(r["signal"], -57)
        self.assertEqual((r["rx_rate"], r["tx_rate"]), (433.3, 390.0))

    def test_not_connected(self):
        self.assertEqual(c.parse_iw_link("Not connected.\n"), {"connected": False})


class TestScan(unittest.TestCase):
    def test_nmcli(self):
        nets = c.parse_nmcli_scan(NMCLI)
        self.assertEqual(len(nets), 3)
        self.assertEqual(nets[0]["bssid"], "3c:a6:2f:aa:bb:cc")
        self.assertEqual(nets[1]["ssid"], "Nachbar:EG")
        self.assertEqual((nets[1]["channel"], nets[1]["band"], nets[1]["signal_pct"]), (6, "2.4", 40))
        self.assertIsNone(nets[2]["ssid"])
        self.assertIsNone(nets[2]["security"])

    def test_iw(self):
        nets = c.parse_iw_scan(IW_SCAN)
        self.assertEqual(len(nets), 2)
        self.assertEqual((nets[0]["ssid"], nets[0]["channel"], nets[0]["signal"]), ("Zuhause", 6, -48))
        self.assertEqual(nets[0]["security"], "WPA2/WPA3")
        self.assertEqual((nets[1]["channel"], nets[1]["band"]), (48, "5"))
        self.assertIsNone(nets[1]["ssid"])

    def test_recommend(self):
        nets = [
            {"band": "2.4", "channel": 6, "signal_pct": 90},
            {"band": "2.4", "channel": 1, "signal_pct": 60},
            {"band": "2.4", "channel": 3, "signal_pct": 50},
            {"band": "5", "channel": 36, "signal_pct": 80},
            {"band": "5", "channel": 44, "signal_pct": 50},
        ]
        rec = c.recommend_channels(nets)
        self.assertEqual(rec["2.4"]["best"], 11)
        self.assertEqual(rec["5"]["best_non_dfs"], 149)


class TestHelpers(unittest.TestCase):
    def test_channels(self):
        self.assertEqual(c.freq_to_channel(2412), (1, "2.4"))
        self.assertEqual(c.freq_to_channel(2484), (14, "2.4"))
        self.assertEqual(c.freq_to_channel(5745), (149, "5"))
        self.assertEqual(c.freq_to_channel(5955), (1, "6"))
        self.assertEqual(c.freq_to_channel(None), (None, None))

    def test_route(self):
        out = "default via 192.168.178.1 dev wlan0 proto dhcp src 192.168.178.40 metric 600\n"
        self.assertEqual(c.parse_default_route(out), ("192.168.178.1", "wlan0"))
        self.assertEqual(c.parse_default_route(""), (None, None))

    def test_split_terse(self):
        self.assertEqual(c._split_terse(r"a\:b:c\\d:"), ["a:b", "c\\d", ""])


if __name__ == "__main__":
    unittest.main()
