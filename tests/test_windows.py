"""Windows-Parser mit echten deutschen und englischen netsh/ping-Ausgaben."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import windows as w  # noqa: E402

IFACE_DE = """
Es ist 1 Schnittstelle auf dem System vorhanden:

    Name                   : WLAN
    Beschreibung            : MediaTek Wi-Fi 6E MT7922 (RZ616) 160MHz Wireless LAN Card
    GUID                   : 8dcaf837-be39-4b90-b46d-261d253c17c6
    Physische Adresse       : 84:9e:56:78:16:01
    Benutzeroberflächentyp         : Primär
    Status                  : Verbunden
    SSID                   : Router
    AP BSSID               : 50:e6:36:08:50:f1
    Band                   : 5 GHz
    Kanal                  : 36
    Funktyp                : 802.11ax
    Authentifizierung      : WPA2-Personal
    Verschlüsselung        : CCMP
    Empfangsrate (MBit/s)  : 1201
    Übertragungsrate (MBit/s) : 960.5
    Signal                 : 92%
    Rssi                   : -48
    Profil                 : Router
"""
IFACE_EN = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    State                  : connected
    SSID                   : HomeNet
    BSSID                  : aa:bb:cc:dd:ee:ff
    Radio type             : 802.11n
    Channel                : 6
    Receive rate (Mbps)    : 144.4
    Transmit rate (Mbps)   : 130
    Signal                 : 70%
"""
IFACE_OFF = """
    Name                   : WLAN
    Status                  : getrennt
    Funkstatus           : Hardware Aktiviert
                             Software Aktiviert
"""
NETWORKS_DE = """
Schnittstellenname : WLAN
Momentan sind 3 Netzwerke sichtbar.

SSID 1 : FRITZ!Repeater 1200
    Netzwerktyp             : Infrastruktur
    Authentifizierung       : WPA2-Personal
    Verschlüsselung         : CCMP
    BSSID 1                 : dc:15:c8:3e:63:35
         Signal             : 3%
         Funktyp         : 802.11ac
         Band               : 5 GHz
         Kanal            : 52
         BSS-Last:
             Verbundene Stationen:         5
             Kanalnutzung:        2 (0 %)
         Basisraten (MBit/s)   : 6 12 24
    BSSID 2                 : dc:15:c8:3e:63:36
         Signal             : 40%
         Band               : 2,4 GHz
         Kanal            : 11

SSID 2 :
    Netzwerktyp             : Infrastruktur
    Authentifizierung       : Offen
    BSSID 1                 : 50:e6:36:08:50:f1
         Signal             : 24%
         Kanal            : 36
"""
PING_DE = """
Ping wird ausgeführt für 1.1.1.1 mit 32 Bytes Daten:
Antwort von 1.1.1.1: Bytes=32 Zeit=20ms TTL=55
Antwort von 1.1.1.1: Bytes=32 Zeit=15ms TTL=55
Zeitüberschreitung der Anforderung.
Antwort von 1.1.1.1: Bytes=32 Zeit=18ms TTL=55

Ping-Statistik für 1.1.1.1:
    Pakete: Gesendet = 4, Empfangen = 3, Verloren = 1
"""
PING_EN_LAN = """
Reply from 192.168.1.1: bytes=32 time<1ms TTL=64
Reply from 192.168.1.1: bytes=32 time=2ms TTL=64
"""


class TestInterfaces(unittest.TestCase):
    def test_german_connected(self):
        link = w.link_from_interface(w.parse_interfaces(IFACE_DE)[0])
        self.assertTrue(link["connected"])
        self.assertEqual((link["ssid"], link["bssid"]), ("Router", "50:e6:36:08:50:f1"))
        self.assertEqual((link["band"], link["channel"], link["freq"]), ("5", 36, 5180))
        self.assertEqual((link["signal"], link["signal_pct"]), (-48, 92))  # Rssi hat Vorrang
        self.assertEqual((link["rx_rate"], link["tx_rate"]), (1201.0, 960.5))

    def test_english_without_rssi(self):
        link = w.link_from_interface(w.parse_interfaces(IFACE_EN)[0])
        self.assertEqual((link["ssid"], link["channel"], link["band"], link["freq"]), ("HomeNet", 6, "2.4", 2437))
        self.assertEqual((link["signal_pct"], link["signal"]), (70, -65))
        self.assertEqual((link["rx_rate"], link["tx_rate"]), (144.4, 130.0))

    def test_disconnected(self):
        ifaces = w.parse_interfaces(IFACE_OFF)
        self.assertEqual(ifaces[0]["name"], "WLAN")
        self.assertEqual(w.link_from_interface(ifaces[0]), {"connected": False})


class TestNetworks(unittest.TestCase):
    def test_german(self):
        nets = w.parse_networks(NETWORKS_DE)
        self.assertEqual(len(nets), 3)
        a, b, c = nets
        self.assertEqual((a["ssid"], a["bssid"], a["channel"], a["band"], a["signal_pct"]),
                         ("FRITZ!Repeater 1200", "dc:15:c8:3e:63:35", 52, "5", 3))
        self.assertEqual(a["security"], "WPA2-Personal")
        self.assertEqual((b["channel"], b["band"], b["freq"]), (11, "2.4", 2462))
        self.assertIsNone(c["ssid"])          # verborgenes Netz
        self.assertEqual(c["band"], "5")      # ohne Band-Zeile aus dem Kanal abgeleitet
        self.assertEqual(c["security"], "Offen")


class TestPing(unittest.TestCase):
    def test_german_with_timeout(self):
        r = w.parse_ping(PING_DE, 4)
        self.assertEqual((r["sent"], r["recv"], r["loss"]), (4, 3, 25.0))
        self.assertEqual((r["rtt_min"], r["rtt_max"]), (15.0, 20.0))
        self.assertAlmostEqual(r["rtt_avg"], 17.67, places=2)
        self.assertIsNotNone(r["jitter"])

    def test_sub_millisecond(self):
        r = w.parse_ping(PING_EN_LAN, 2)
        self.assertEqual(r["rtt_min"], 0.5)
        self.assertEqual(r["recv"], 2)

    def test_nothing(self):
        r = w.parse_ping("Ping-Anforderung konnte Host nicht finden.", 10)
        self.assertEqual((r["recv"], r["loss"]), (0, 100.0))


if __name__ == "__main__":
    unittest.main()
