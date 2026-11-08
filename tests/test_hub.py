"""Hub-Ende-zu-Ende: echter HTTP-Server, Anmeldung, Token, Werbeblocker, Sperren, Rauswerfen."""
import base64
import http.client
import json
import os
import struct
import sys
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import agent  # noqa: E402
import auth as auth_mod  # noqa: E402
import dnsblock  # noqa: E402
import wifimon  # noqa: E402
from storage import DB  # noqa: E402
from test_dns import FakeUpstream, query  # noqa: E402

TOKEN = "test-token-1234567890"
PASSWORD = "1234"


class HubTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cfg = {**wifimon.HUB_DEFAULTS, **agent.DEFAULTS}
        db = DB(os.path.join(cls.tmp.name, "t.db"))
        cls.db = db
        cls.hub = wifimon.Hub(cfg, db)
        cls.auth = auth_mod.Auth(db, PASSWORD)
        cls.adblock = dnsblock.AdBlocker(db, cls.tmp.name, upstream=FakeUpstream())
        cls.adblock.domains = frozenset({"ads.example.com"})
        handler = wifimon.make_handler(cls.hub, TOKEN, cls.auth, cls.adblock, True)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.port = cls.server.server_port
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.sid, _ = cls.auth.login(PASSWORD, "127.0.0.1", "Mozilla/5.0 (Windows NT 10.0) Chrome/130")

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.db.conn.close()
        cls.tmp.cleanup()

    def req(self, path, data=None, headers=None, login=True, method=None, raw=None):
        h = dict(headers or {})
        if login:
            h["Cookie"] = f"{wifimon.COOKIE}={self.sid}"
            h.setdefault("X-WiFiMon", "1")
        body = raw if raw is not None else (json.dumps(data).encode() if data is not None else None)
        if body is not None and raw is None:
            h.setdefault("Content-Type", "application/json")
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request(method or ("POST" if body is not None else "GET"), path, body=body, headers=h)
        r = c.getresponse()
        payload = r.read()
        c.close()
        try:
            out = json.loads(payload) if r.getheader("Content-Type", "").startswith("application/json") else payload
        except ValueError:
            out = payload
        return r.status, out, r

    def batch(self, **kw):
        return {"device": "PC-Test", "ts": int(time.time()), "platform": "windows", "iface": "WLAN",
                "gateway": "192.168.178.1", "route_dev": "WLAN", "busy": False, "ping_interval_s": 60, **kw}

    def ingest(self, batch, token=TOKEN):
        return self.req("/api/ingest", batch, {"Authorization": f"Bearer {token}"}, login=False)

    # --- Anmeldung -----------------------------------------------------------------
    def test_01_health_without_auth(self):
        self.assertEqual(self.req("/healthz", login=False)[0], 200)

    def test_02_pages_and_api_need_login(self):
        st, _, r = self.req("/", login=False)
        self.assertEqual((st, r.getheader("Location")), (303, "/login"))
        self.assertEqual(self.req("/geraete", login=False)[0], 303)
        self.assertEqual(self.req("/api/devices", login=False)[0], 401)
        self.assertEqual(self.req("/login", login=False)[0], 200)
        self.assertEqual(self.req("/app.js", login=False)[0], 200)
        st, _, r = self.req("/adblock")
        self.assertEqual(st, 200)
        self.assertIn("frame-ancestors 'none'", r.getheader("Content-Security-Policy"))

    def test_03_login_flow(self):
        hdr = {"X-WiFiMon": "1"}
        with mock.patch("auth.time.sleep"):
            self.assertEqual(self.req("/api/login", {"password": "falsch"}, hdr, login=False)[0], 401)
        self.assertEqual(self.req("/api/login", {"password": PASSWORD}, login=False)[0], 403)  # ohne Header
        st, _, r = self.req("/api/login", {"password": PASSWORD}, hdr, login=False)
        self.assertEqual(st, 200)
        cookie = r.getheader("Set-Cookie")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        sid = cookie.split(";")[0].split("=", 1)[1]
        st, me, _ = self.req("/api/me", headers={"Cookie": f"{wifimon.COOKIE}={sid}"}, login=False)
        self.assertEqual((st, me["ip"], me["family"]), (200, "127.0.0.1", "IPv4"))

    def test_04_ingest_rejects_wrong_token(self):
        self.assertEqual(self.ingest(self.batch(), token="falsch")[0], 401)

    def test_05_ingest_and_read(self):
        link = {"connected": True, "ssid": "Router", "bssid": "50:e6:36:08:50:f1", "channel": 36,
                "band": "5", "freq": 5180, "signal": -48, "signal_pct": 92, "rx_rate": 1201, "tx_rate": 960}
        pings = [{"target": "1.1.1.1", "label": "Cloudflare", "sent": 10, "recv": 10, "loss": 0,
                  "rtt_min": 12, "rtt_avg": 14.2, "rtt_max": 19, "jitter": 1.8, "evil": "x"}]
        code, resp, _ = self.ingest(self.batch(link=link, pings=pings))
        self.assertEqual((code, resp["commands"]), (200, []))
        net = {"hostname": "DESKTOP-1", "addrs": [
                   {"iface": "WLAN", "family": "IPv4", "ip": "192.168.178.40", "prefix": 24, "scope": "privat"},
                   {"iface": "WLAN", "family": "IPv6", "ip": "2001:db8::40", "prefix": 64, "scope": "öffentlich"},
                   {"iface": "x", "ip": "kein-ip"}],
               "neighbors": [{"ip": "192.168.178.1", "mac": "50:e6:36:08:50:f1", "state": "Reachable"},
                             {"ip": "fe80::1", "mac": "50:e6:36:08:50:f1", "state": "Stale"},
                             {"ip": "1.2.3.4", "mac": "<b>"}]}
        self.ingest(self.batch(scan=[{"bssid": "aa:bb:cc:dd:ee:ff", "ssid": "Nachbar", "channel": 6,
                                      "band": "2.4", "freq": 2437, "signal": -70, "signal_pct": 60}], net=net))
        self.ingest(self.batch(speed={"down": 250.5, "up": 40.1, "idle_ping": 13, "loaded_ping": 30,
                                      "mb_used": 180, "error": None}))

        code, dv, _ = self.req("/api/devices")
        self.assertEqual([d["device"] for d in dv["devices"]], ["PC-Test"])
        self.assertTrue(dv["devices"][0]["online"])
        self.assertEqual([a["ip"] for a in dv["devices"][0]["addrs"]], ["192.168.178.40", "2001:db8::40"])
        self.assertEqual(dv["devices"][0]["public_ip"], "127.0.0.1")
        code, st, _ = self.req("/api/status?device=PC-Test")
        self.assertEqual((st["link"]["signal"], st["pings"][0]["rtt_avg"], st["speed"]["down"]), (-48, 14.2, 250.5))
        code, sc, _ = self.req("/api/scan?device=PC-Test")
        self.assertEqual(sc["recommendation"]["2.4"]["best"], 1)
        code, acc, _ = self.req("/api/access")
        self.assertEqual({(n["ip"], n["family"]) for n in acc["neighbors"]},
                         {("192.168.178.1", "IPv4"), ("fe80::1", "IPv6")})
        self.assertIn(("agent", "PC-Test"), {(s["kind"], s["ref"]) for s in acc["seen"]})
        self.assertEqual(acc["agents"][0]["hostname"], "DESKTOP-1")

    def test_06_bad_input(self):
        self.assertEqual(self.ingest({"device": "<script>"})[0], 400)
        self.assertEqual(self.ingest(["kein", "objekt"])[0], 400)
        self.assertEqual(self.req("/api/status?device=")[0], 400)
        self.assertEqual(self.ingest(self.batch(link={"connected": True, "signal": "-40; DROP TABLE"}))[0], 200)

    def test_07_speedtest_command_roundtrip(self):
        self.ingest(self.batch())
        self.assertEqual(self.req("/api/speedtest?device=PC-Test", method="POST",
                                  headers={"X-WiFiMon": "0"})[0], 403)
        self.assertEqual(self.req("/api/speedtest?device=PC-Test", method="POST")[0], 202)
        self.assertTrue(self.req("/api/status?device=PC-Test")[1]["speed_running"])
        self.assertEqual(self.ingest(self.batch())[1]["commands"], ["speedtest"])
        self.assertEqual(self.ingest(self.batch())[1]["commands"], [])
        self.assertEqual(self.req("/api/speedtest?device=Gibts-Nicht", method="POST")[0], 400)

    # --- Werbeblocker ------------------------------------------------------------------
    def test_08_doh(self):
        st, r, _ = self.req("/api/adblock/client", {"action": "add", "name": "Handy"})
        self.assertEqual(st, 200)
        c = r["client"]
        self.assertTrue(c["doh_url"].endswith("/dns-query/" + c["token"]))

        def doh_get(name, tok=c["token"]):
            b64 = base64.urlsafe_b64encode(query(name)).rstrip(b"=").decode()
            return self.req(f"/dns-query/{tok}?dns={b64}", login=False)

        st, body, r = doh_get("ads.example.com")
        self.assertEqual((st, r.getheader("Content-Type"), body[-4:]), (200, "application/dns-message", b"\0\0\0\0"))
        st, body, r = self.req(f"/dns-query/{c['token']}", login=False, raw=query("example.org"),
                               headers={"Content-Type": "application/dns-message"})
        self.assertEqual((st, body[-4:]), (200, bytes([93, 184, 216, 34])))
        self.assertIn("max-age", r.getheader("Cache-Control"))
        self.assertEqual(doh_get("x.de", tok="unbekannter-schluessel")[0], 403)

        st, prof, r = self.req(f"/ios/{c['token']}.mobileconfig", login=False)
        self.assertEqual((st, r.getheader("Content-Type")), (200, "application/x-apple-aspen-config"))
        self.assertIn(b"com.apple.dnsSettings.managed", prof)

        self.assertEqual(self.req("/api/adblock/client", {"action": "disable", "id": c["id"]})[0], 200)
        self.assertEqual(doh_get("x.de")[0], 403)
        self.assertEqual(self.req("/api/adblock/rule", {"kind": "block", "domain": "tiktok.com"})[0], 200)
        self.assertEqual(self.req("/api/adblock/rule", {"kind": "block", "domain": "kein domain"})[0], 400)
        st, s, _ = self.req("/api/adblock")
        self.assertEqual((st, s["rules"]["block"], s["clients"][0]["disabled"]), (200, ["tiktok.com"], 1))

    # --- Sperren und Rauswerfen -------------------------------------------------------
    def test_09_ban(self):
        st, r, _ = self.req("/api/ban", {"ip": "127.0.0.1"})
        self.assertEqual(st, 400)  # sich selbst aussperren geht nicht
        self.assertIn("selbst", r["error"])
        self.assertEqual(self.req("/api/ban", {"ip": "0.0.0.0/0"})[0], 400)
        self.assertEqual(self.req("/api/ban", {"ip": "2001:db8::/64", "note": "test"})[1]["banned"], "2001:db8::/64")
        self.assertTrue(self.auth.is_banned("2001:db8::abcd"))
        self.assertFalse(self.auth.is_banned("2001:db9::1"))
        self.assertEqual(self.req("/api/unban", {"ip": "2001:db8::/64"})[0], 200)
        self.assertFalse(self.auth.is_banned("2001:db8::abcd"))

    def test_10_kick_session(self):
        other, _ = self.auth.login(PASSWORD, "10.0.0.9", "Safari iPhone")
        pid = next(s["pid"] for s in self.auth.sessions() if s["ip"] == "10.0.0.9")
        self.assertEqual(self.req("/api/session/kick", {"pid": pid})[0], 200)
        self.assertEqual(self.req("/api/me", headers={"Cookie": f"{wifimon.COOKIE}={other}"}, login=False)[0], 401)

    def test_11_device_ban(self):
        self.ingest(self.batch(device="Fremd"))
        self.assertEqual(self.req("/api/device/remove", {"device": "Fremd", "ban": True})[0], 200)
        self.assertEqual(self.ingest(self.batch(device="Fremd"))[0], 403)
        self.assertNotIn("Fremd", [d["device"] for d in self.req("/api/devices")[1]["devices"]])
        self.assertEqual(self.req("/api/device/unban", {"device": "Fremd"})[0], 200)
        self.assertEqual(self.ingest(self.batch(device="Fremd"))[0], 200)


class AuthTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = DB(os.path.join(self.tmp.name, "a.db"))

    def tearDown(self):
        self.db.conn.close()
        self.tmp.cleanup()

    @mock.patch("auth.time.sleep")
    def test_lockout_and_autoban(self, _sleep):
        a = auth_mod.Auth(self.db, "1234")
        for _ in range(auth_mod.FAIL_LIMIT):
            self.assertEqual(a.login("0000", "203.0.113.5")[1], "Falsches Passwort.")
        tok, err = a.login("1234", "203.0.113.5")
        self.assertIsNone(tok)
        self.assertIn("warten", err)
        self.assertIsNotNone(a.login("1234", "198.51.100.7")[0])  # andere IP nicht betroffen
        # IPv6: das ganze /64 zählt als ein Anschluss
        for i in range(auth_mod.FAIL_LIMIT):
            a.login("0000", f"2001:db8:1:2::{i + 1}")
        self.assertIn("warten", a.login("1234", "2001:db8:1:2::99")[1])
        # automatische Sperre nach vielen Fehlversuchen
        a.fails.clear()
        for _ in range(auth_mod.AUTO_BAN):
            a.fails.clear()
            a.global_fails.clear()
            a.login("0000", "192.0.2.66")
        self.assertTrue(a.is_banned("192.0.2.66"))

    def test_ipv4_mapped(self):
        self.assertEqual(auth_mod.normalize_ip("::ffff:192.0.2.1"), "192.0.2.1")
        self.assertIsNone(auth_mod.normalize_ip("kein"))


class AgentSinkTest(unittest.TestCase):
    def test_buffer_when_hub_down(self):
        sink = agent.HttpSink("http://127.0.0.1:9", TOKEN)  # Port 9: niemand hört zu
        self.assertEqual(sink({"device": "x"}), [])
        self.assertEqual(sink({"device": "x"}), [])
        self.assertEqual(len(sink.queue), 2)


if __name__ == "__main__":
    unittest.main()
