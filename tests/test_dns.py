"""Werbeblocker: Sperrlisten lesen, DNS-Nachrichten bauen und auswerten."""
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import dnsblock as d  # noqa: E402
from storage import DB  # noqa: E402


def query(name, qtype=1, tid=0x1234):
    qn = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) + qn + struct.pack(">HH", qtype, 1)


HOSTS = """# StevenBlack-Beispiel
127.0.0.1 localhost
0.0.0.0 0.0.0.0
0.0.0.0 ads.example.com
0.0.0.0 tracker.example.net  # Kommentar
0.0.0.0 a.example.org b.example.org
::1 ip6-localhost
"""
PLAIN = """! Adblock-Kommentar
||doubleclick.net^
||pixel.example.de^$third-party
*.wild.example.com
nur-domain.example
kaputt..domain
http://keine.url/pfad
"""


class TestLists(unittest.TestCase):
    def test_hosts(self):
        self.assertEqual(d.parse_list(HOSTS),
                         {"ads.example.com", "tracker.example.net", "a.example.org", "b.example.org"})

    def test_plain_and_adblock(self):
        self.assertEqual(d.parse_list(PLAIN),
                         {"doubleclick.net", "pixel.example.de", "wild.example.com", "nur-domain.example"})

    def test_normalize(self):
        self.assertEqual(d.normalize_domain("Ads.Example.COM."), "ads.example.com")
        self.assertEqual(d.normalize_domain("bücher.de"), "xn--bcher-kva.de")
        self.assertIsNone(d.normalize_domain("localhost"))
        self.assertIsNone(d.normalize_domain("ohne-punkt"))
        self.assertIsNone(d.normalize_domain("<script>.de"))


class TestMessages(unittest.TestCase):
    def test_parse_query(self):
        self.assertEqual(d.parse_query(query("WWW.Example.com", 28))[:3], ("www.example.com", 28, 1))

    def test_bad_queries(self):
        for bad in (b"", b"\0" * 11, query("a.de")[:-2], b"\x12\x34\x81\x00" + query("a.de")[4:]):
            with self.assertRaises(d.DNSError):
                d.parse_query(bad)

    def test_blocked_a_and_aaaa(self):
        for qtype, rdata in ((1, b"\0" * 4), (28, b"\0" * 16)):
            msg = query("ads.example.com", qtype)
            r = d.blocked_reply(msg, d.parse_query(msg)[3], qtype)
            tid, flags, qd, an = struct.unpack_from(">HHHH", r)
            self.assertEqual((tid, flags & 0x8000, flags & 0x0F, qd, an), (0x1234, 0x8000, 0, 1, 1))
            self.assertTrue(r.endswith(rdata))
            self.assertEqual(d.answer_ttl(r), d.BLOCK_TTL)

    def test_blocked_other_type_is_empty(self):
        msg = query("ads.example.com", 65)
        r = d.blocked_reply(msg, d.parse_query(msg)[3], 65)
        self.assertEqual(struct.unpack_from(">H", r, 6)[0], 0)

    def test_servfail(self):
        msg = query("x.de")
        self.assertEqual(d.servfail(msg, d.parse_query(msg)[3])[3] & 0x0F, 2)


class FakeUpstream:
    calls = 0

    def resolve(self, msg):
        FakeUpstream.calls += 1
        qend = d.parse_query(msg)[3]
        return d.make_reply(msg, qend, answer=bytes([93, 184, 216, 34]), qtype=1, ttl=120)


class TestBlocker(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = DB(os.path.join(self.tmp.name, "t.db"))
        self.b = d.AdBlocker(self.db, self.tmp.name, upstream=FakeUpstream())
        self.b.domains = frozenset({"ads.example.com", "doubleclick.net"})

    def tearDown(self):
        self.db.conn.close()
        self.tmp.cleanup()

    def test_suffix_and_rules(self):
        self.assertEqual(self.b.check("ads.example.com"), (True, "Sperrliste"))
        self.assertEqual(self.b.check("x.y.doubleclick.net"), (True, "Sperrliste"))
        self.assertEqual(self.b.check("example.com"), (False, None))
        self.b.set_rule("allow", "doubleclick.net")
        self.assertEqual(self.b.check("x.doubleclick.net"), (False, "erlaubt"))
        self.b.set_rule("block", "tiktok.com")
        self.assertEqual(self.b.check("www.tiktok.com"), (True, "eigene Liste"))
        self.b.set_rule("block", "doubleclick.net")  # wechselt von erlaubt zu blockiert
        self.assertEqual(self.b.custom["allow"], set())
        with self.assertRaises(ValueError):
            self.b.set_rule("block", "kein domain")

    def test_handle_clients_cache_and_log(self):
        c = self.b.add_client("Handy")
        self.assertEqual(self.b.handle("falsch-falsch", query("a.de"), "1.2.3.4")[0], 403)
        st, resp, _ = self.b.handle(c["token"], query("ads.example.com"), "1.2.3.4")
        self.assertEqual((st, resp[-4:]), (200, b"\0\0\0\0"))
        before = FakeUpstream.calls
        for tid in (1, 2):
            st, resp, ttl = self.b.handle(c["token"], query("example.org", tid=tid), "2001:db8::1")
            self.assertEqual((st, resp[:2], resp[-4:]), (200, struct.pack(">H", tid), bytes([93, 184, 216, 34])))
        self.assertEqual(FakeUpstream.calls, before + 1)  # zweite Anfrage aus dem Cache
        self.assertEqual(self.b.handle(c["token"], b"kaputt", "1.2.3.4")[0], 400)

        self.b.pause(5)
        self.assertEqual(self.b.handle(c["token"], query("ads.example.com"), "1.2.3.4")[1][-4:], bytes([93, 184, 216, 34]))
        self.b.pause(0)

        items = []
        while not self.b._log.empty():
            items.append(self.b._log.get_nowait())
        self.b.flush(items)
        row = self.db.one("SELECT * FROM dns_clients WHERE id = ?", (c["id"],))
        self.assertEqual((row["queries"], row["blocked"], row["last_ip"]), (4, 1, "1.2.3.4"))
        self.assertEqual({r["ip"] for r in self.db.query("SELECT ip FROM seen WHERE kind='dns'")},
                         {"1.2.3.4", "2001:db8::1"})
        st = self.b.stats(24)
        self.assertEqual((st["totals"]["total"], st["totals"]["blocked"]), (4, 1))
        self.assertEqual(st["top_blocked"][0]["qname"], "ads.example.com")
        self.assertEqual(len(self.b.recent(blocked="1")), 1)
        self.assertEqual(len(self.b.recent(search="example.o")), 2)

        self.b.set_disabled(c["id"], True)
        self.assertEqual(self.b.handle(c["token"], query("a.de"), "1.2.3.4")[0], 403)


if __name__ == "__main__":
    unittest.main()
