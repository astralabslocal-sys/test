"""Werbeblocker für WiFiMon: ein eigener DNS-over-HTTPS-Server (RFC 8484) mit Sperrlisten.

Handy, PC und Laptop tragen  https://<deine-domain>/dns-query/<geräte-schlüssel>  als
"sicheres DNS" ein. Werbe- und Tracker-Domains bekommen 0.0.0.0 bzw. :: zurück, alles
andere wird an Cloudflare/Quad9 weitergereicht. Nur Python-Standardbibliothek.
"""
import ipaddress
import logging
import os
import queue
import re
import secrets
import socket
import struct
import threading
import time
import urllib.request

log = logging.getLogger("wifimon.dns")

DEFAULT_LISTS = ("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",)
UPSTREAM_UDP = (("1.1.1.1", 53), ("9.9.9.9", 53))
UPSTREAM_DOH = "https://cloudflare-dns.com/dns-query"
BLOCK_TTL = 300
MAX_LIST_BYTES = 40_000_000
LIST_REFRESH_S = 24 * 3600
NAME_RE = re.compile(r"^[\w .\-]{1,40}$")

QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
          33: "SRV", 64: "SVCB", 65: "HTTPS", 255: "ANY"}
_LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
_DOMAIN = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(?:\.{_LABEL})+$")
_IGNORE = {"localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost",
           "ip6-loopback", "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters",
           "ip6-allhosts", "0.0.0.0"}


# --- Sperrlisten ----------------------------------------------------------------

def normalize_domain(s):
    """'||ads.example.com^' / '*.ads.example.com' / 'Ads.Example.com.' -> 'ads.example.com' oder None."""
    s = (s or "").strip().lower()
    if s.startswith("||"):
        s = s[2:].split("^", 1)[0]
    if s.startswith("*."):
        s = s[2:]
    s = s.rstrip(".")
    if s and not s.isascii():
        try:
            s = s.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    return s if _DOMAIN.match(s) and s not in _IGNORE else None


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def parse_list(text):
    """Versteht hosts-Dateien ('0.0.0.0 ads.example.com'), reine Domainlisten und '||domain^'."""
    out = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("!"):
            continue
        parts = line.split()
        names = parts[1:] if len(parts) > 1 and _is_ip(parts[0]) else parts[:1]
        for n in names:
            d = normalize_domain(n)
            if d:
                out.add(d)
    return out


# --- DNS-Nachrichten -------------------------------------------------------------

class DNSError(ValueError):
    pass


def parse_query(msg):
    """-> (name, qtype, qclass, ende_der_frage)"""
    if len(msg) < 17:
        raise DNSError("zu kurz")
    _tid, flags, qd = struct.unpack_from(">HHH", msg)
    if flags & 0x8000 or qd != 1:
        raise DNSError("keine einfache Anfrage")
    pos, labels = 12, []
    while True:
        if pos >= len(msg):
            raise DNSError("Name abgeschnitten")
        n = msg[pos]
        pos += 1
        if n == 0:
            break
        if n > 63:
            raise DNSError("ungültiges Label")
        labels.append(msg[pos:pos + n])
        pos += n
    if pos + 4 > len(msg):
        raise DNSError("Frage abgeschnitten")
    qtype, qclass = struct.unpack_from(">HH", msg, pos)
    name = ".".join(lb.decode("ascii", "replace") for lb in labels).lower()
    if len(name) > 253:
        raise DNSError("Name zu lang")
    return name, qtype, qclass, pos + 4


def make_reply(msg, qend, rcode=0, answer=None, qtype=None, ttl=BLOCK_TTL):
    tid, flags = struct.unpack_from(">HH", msg)
    out_flags = 0x8000 | (flags & 0x7900) | 0x0080 | rcode  # QR + Opcode + RD + RA
    out = struct.pack(">HHHHHH", tid, out_flags, 1, 1 if answer is not None else 0, 0, 0) + msg[12:qend]
    if answer is not None:
        out += struct.pack(">HHHIH", 0xC00C, qtype, 1, ttl, len(answer)) + answer
    return out


def blocked_reply(msg, qend, qtype):
    if qtype == 1:
        return make_reply(msg, qend, answer=b"\0" * 4, qtype=1)
    if qtype == 28:
        return make_reply(msg, qend, answer=b"\0" * 16, qtype=28)
    return make_reply(msg, qend)  # leere Antwort (NODATA)


def servfail(msg, qend):
    return make_reply(msg, qend, rcode=2)


def _skip_name(msg, pos):
    while True:
        n = msg[pos]
        if n == 0:
            return pos + 1
        if n & 0xC0 == 0xC0:
            return pos + 2
        pos += n + 1


def answer_ttl(resp, default=60):
    """Kleinste TTL aus Antwort- und Autoritätsteil (für den Cache)."""
    try:
        qd, an, ns = struct.unpack_from(">HHH", resp, 4)
        pos = 12
        for _ in range(qd):
            pos = _skip_name(resp, pos) + 4
        ttls = []
        for _ in range(an + ns):
            pos = _skip_name(resp, pos)
            _t, _c, ttl, rdlen = struct.unpack_from(">HHIH", resp, pos)
            pos += 10 + rdlen
            ttls.append(ttl)
        return min(ttls) if ttls else default
    except (IndexError, struct.error):
        return default


# --- Weiterleitung und Cache -------------------------------------------------------

class Upstream:
    """Fragt Cloudflare/Quad9 per UDP, bei Problemen oder großen Antworten per DoH."""

    def __init__(self, udp=UPSTREAM_UDP, doh=UPSTREAM_DOH, timeout=2.0):
        self.udp, self.doh, self.timeout = udp, doh, timeout

    def _udp(self, msg, server):
        tid = os.urandom(2)  # eigene Kennung gegen gefälschte Antworten
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(self.timeout)
            s.sendto(tid + msg[2:], server)
            deadline = time.monotonic() + self.timeout
            while True:
                data, addr = s.recvfrom(65535)
                if addr[0] == server[0] and data[:2] == tid:
                    return msg[:2] + data[2:]
                if time.monotonic() > deadline:
                    raise socket.timeout("keine passende Antwort")

    def _doh(self, msg):
        req = urllib.request.Request(self.doh, data=msg, method="POST", headers={
            "Content-Type": "application/dns-message", "Accept": "application/dns-message",
            "User-Agent": "wifimon-dns"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.read(65535)

    def resolve(self, msg):
        for server in self.udp:
            try:
                data = self._udp(msg, server)
            except OSError:
                continue
            if not data[2] & 0x02:  # TC-Bit: Antwort war zu groß für UDP
                return data
            break
        return self._doh(msg)


class Cache:
    def __init__(self, size=20000):
        self.size, self.d, self.lock = size, {}, threading.Lock()

    def get(self, key):
        with self.lock:
            v = self.d.get(key)
        if v and v[0] > time.time():
            return v[1], int(v[0] - time.time())
        return None

    def put(self, key, resp, ttl):
        ttl = max(10, min(int(ttl), 3600))
        with self.lock:
            if len(self.d) >= self.size:
                now = time.time()
                for k in [k for k, v in self.d.items() if v[0] <= now]:
                    del self.d[k]
                while len(self.d) >= self.size:
                    del self.d[next(iter(self.d))]
            self.d[key] = (time.time() + ttl, resp)

    def clear(self):
        with self.lock:
            self.d.clear()


# --- Werbeblocker ----------------------------------------------------------------

class AdBlocker:
    def __init__(self, db, data_dir, lists=None, upstream=None):
        self.db = db
        self.lists = list(lists or DEFAULT_LISTS)
        self.cache_file = os.path.join(data_dir, "blocklist.txt")
        self.domains = frozenset()
        self.list_info = {"updated": None, "count": 0, "error": None, "sources": self.lists}
        self.custom = {"block": set(), "allow": set()}
        self.upstream = upstream or Upstream()
        self.cache = Cache()
        self._log = queue.SimpleQueue()
        self._clients, self._clients_ts = {}, 0
        self._clients_lock = threading.Lock()
        row = db.one("SELECT value FROM settings WHERE key = 'adblock_paused_until'")
        self._paused_until = int(row["value"]) if row and str(row["value"]).isdigit() else 0
        self.load_rules()
        self._load_cached()

    # --- Listen -------------------------------------------------------------------
    def _load_cached(self):
        if not os.path.isfile(self.cache_file):
            return
        try:
            with open(self.cache_file, encoding="utf-8") as f:
                self.domains = frozenset(line.strip() for line in f if line.strip())
            self.list_info.update(updated=int(os.path.getmtime(self.cache_file)), count=len(self.domains))
        except OSError as e:
            log.warning("Gespeicherte Sperrliste unlesbar: %s", e)

    def refresh_lists(self):
        found, errors = set(), []
        for url in self.lists:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "wifimon-adblock"})
                with urllib.request.urlopen(req, timeout=60) as r:
                    data = r.read(MAX_LIST_BYTES + 1)
                if len(data) > MAX_LIST_BYTES:
                    raise ValueError("Liste ist zu groß")
                found |= parse_list(data.decode("utf-8", "replace"))
            except Exception as e:  # noqa: BLE001 - eine kaputte Liste darf die anderen nicht stoppen
                errors.append(f"{url}: {e}")
        if found:
            self.domains = frozenset(found)
            try:
                tmp = self.cache_file + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    f.write("\n".join(sorted(found)))
                os.replace(tmp, self.cache_file)
            except OSError as e:
                errors.append(f"Speichern: {e}")
            self.list_info.update(updated=int(time.time()), count=len(found))
            log.info("Sperrliste geladen: %d Domains", len(found))
        self.list_info["error"] = "; ".join(errors) or (None if found else "keine Domains gefunden")
        if errors:
            log.warning("Sperrliste: %s", self.list_info["error"])
        return self.list_info

    def start(self):
        def lists_loop():
            if not self.list_info["updated"] or time.time() - self.list_info["updated"] > LIST_REFRESH_S:
                self.refresh_lists()
            while True:
                time.sleep(LIST_REFRESH_S)
                self.refresh_lists()

        threading.Thread(target=lists_loop, daemon=True, name="blocklist").start()
        threading.Thread(target=self._writer, daemon=True, name="dns-log").start()

    # --- eigene Regeln ---------------------------------------------------------------
    def load_rules(self):
        rows = self.db.query("SELECT kind, domain FROM rules")
        self.custom = {"block": {r["domain"] for r in rows if r["kind"] == "block"},
                       "allow": {r["domain"] for r in rows if r["kind"] == "allow"}}

    def set_rule(self, kind, domain, add=True):
        if kind not in ("block", "allow"):
            raise ValueError("kind muss block oder allow sein")
        d = normalize_domain(domain)
        if not d:
            raise ValueError("ungültige Domain")
        if add:
            other = "allow" if kind == "block" else "block"
            self.db.execute("DELETE FROM rules WHERE kind = ? AND domain = ?", (other, d))
            self.db.execute("INSERT OR REPLACE INTO rules (kind, domain, ts) VALUES (?, ?, ?)",
                            (kind, d, int(time.time())))
        else:
            self.db.execute("DELETE FROM rules WHERE kind = ? AND domain = ?", (kind, d))
        self.load_rules()
        self.cache.clear()
        return d

    def check(self, name):
        """-> (blockiert, grund). Eine Regel gilt auch für alle Subdomains."""
        parts = name.split(".")
        suffixes = [".".join(parts[i:]) for i in range(len(parts) - 1)] or [name]
        if any(s in self.custom["allow"] for s in suffixes):
            return False, "erlaubt"
        if any(s in self.custom["block"] for s in suffixes):
            return True, "eigene Liste"
        if any(s in self.domains for s in suffixes):
            return True, "Sperrliste"
        return False, None

    # --- Pause --------------------------------------------------------------------------
    def paused_until(self):
        return self._paused_until if self._paused_until > time.time() else 0

    def pause(self, minutes):
        minutes = max(0, min(int(minutes), 24 * 60))
        self._paused_until = int(time.time()) + minutes * 60 if minutes else 0
        self.db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('adblock_paused_until', ?)",
                        (str(self._paused_until),))
        return self.paused_until()

    # --- Geräte -------------------------------------------------------------------------
    def clients(self):
        return self.db.query("SELECT * FROM dns_clients ORDER BY name COLLATE NOCASE")

    def _client(self, token):
        with self._clients_lock:
            if time.time() - self._clients_ts > 30:
                self._clients = {c["token"]: c for c in self.clients()}
                self._clients_ts = time.time()
            return self._clients.get(token)

    def _changed(self):
        with self._clients_lock:
            self._clients_ts = 0

    def add_client(self, name):
        name = (name or "").strip()
        if not NAME_RE.match(name):
            raise ValueError("Name: 1-40 Zeichen, nur Buchstaben, Ziffern, Leerzeichen, . _ -")
        token = secrets.token_urlsafe(18)
        cid = self.db.execute("INSERT INTO dns_clients (name, token, created) VALUES (?, ?, ?)",
                              (name, token, int(time.time())))
        self._changed()
        return self.db.one("SELECT * FROM dns_clients WHERE id = ?", (cid,))

    def set_disabled(self, cid, disabled):
        n = self.db.execute("UPDATE dns_clients SET disabled = ? WHERE id = ?", (int(bool(disabled)), int(cid)))
        if not n:
            raise ValueError("unbekanntes Gerät")
        self._changed()

    def delete_client(self, cid):
        n = self.db.execute("DELETE FROM dns_clients WHERE id = ?", (int(cid),))
        if not n:
            raise ValueError("unbekanntes Gerät")
        self.db.execute("DELETE FROM seen WHERE kind = 'dns' AND ref = ?", (str(int(cid)),))
        self._changed()

    def client_by_token(self, token):
        c = self._client(token)
        return dict(c) if c else None

    # --- Anfrage beantworten -------------------------------------------------------------
    def handle(self, token, msg, ip):
        """-> (http_status, antwort_bytes, ttl)"""
        client = self._client(token)
        if not client or client["disabled"]:
            return 403, None, 0
        t0 = time.monotonic()
        try:
            name, qtype, qclass, qend = parse_query(msg)
        except DNSError:
            return 400, None, 0
        blocked, reason = (False, "pausiert") if self.paused_until() else self.check(name)
        if blocked:
            resp, ttl = blocked_reply(msg, qend, qtype), BLOCK_TTL
        else:
            key = (name, qtype, qclass)
            hit = self.cache.get(key)
            if hit:
                resp, ttl = msg[:2] + hit[0][2:], hit[1]
            else:
                try:
                    resp = self.upstream.resolve(msg)
                    ttl = answer_ttl(resp)
                    if resp[3] & 0x0F in (0, 3):  # NOERROR / NXDOMAIN merken
                        self.cache.put(key, resp, ttl)
                except Exception as e:  # noqa: BLE001
                    log.warning("Upstream-DNS fehlgeschlagen für %s: %s", name, e)
                    resp, ttl = servfail(msg, qend), 0
        self._log.put((int(time.time()), client["id"], ip, name[:253], QTYPES.get(qtype, str(qtype)),
                       int(blocked), reason, round((time.monotonic() - t0) * 1000, 1)))
        return 200, resp, ttl

    def _writer(self):
        """Schreibt das Protokoll gesammelt alle 2 Sekunden (schont die Datenbank)."""
        cols = ("ts", "client", "ip", "qname", "qtype", "blocked", "reason", "ms")
        while True:
            time.sleep(2)
            items = []
            while True:
                try:
                    items.append(self._log.get_nowait())
                except queue.Empty:
                    break
            if items:
                try:
                    self.flush(items, cols)
                except Exception:  # noqa: BLE001
                    log.exception("DNS-Protokoll konnte nicht gespeichert werden")

    def flush(self, items, cols=("ts", "client", "ip", "qname", "qtype", "blocked", "reason", "ms")):
        self.db.insert_many("dns_log", [dict(zip(cols, it)) for it in items])
        per_client, per_ip = {}, {}
        for ts, cid, ip, _n, _t, blocked, _r, _ms in items:
            c = per_client.setdefault(cid, [0, 0, 0, None])
            c[0] += 1
            c[1] += blocked
            c[2], c[3] = ts, ip
            k = (str(cid), ip)
            per_ip[k] = (per_ip.get(k, (0, 0))[0] + 1, ts)
        self.db.executemany(
            "UPDATE dns_clients SET queries = queries + ?, blocked = blocked + ?, last_seen = ?, last_ip = ? WHERE id = ?",
            [(q, b, ts, ip, cid) for cid, (q, b, ts, ip) in per_client.items()])
        self.db.touch_seen([("dns", ref, ip, ts, n) for (ref, ip), (n, ts) in per_ip.items()])

    # --- Auswertung ------------------------------------------------------------------------
    def stats(self, hours=24):
        hours = max(1, min(int(hours), 24 * 7))
        now = int(time.time())
        since = now - hours * 3600
        b = 3600 if hours <= 48 else 6 * 3600
        q = self.db.query
        return {
            "now": now, "hours": hours, "since": since, "bucket": b,
            "totals": self.db.one("SELECT COUNT(*) AS total, COALESCE(SUM(blocked), 0) AS blocked "
                                  "FROM dns_log WHERE ts >= ?", (since,)),
            "timeline": q("SELECT (ts/?)*? AS t, COUNT(*) AS total, SUM(blocked) AS blocked FROM dns_log "
                          "WHERE ts >= ? GROUP BY t ORDER BY t", (b, b, since)),
            "top_blocked": q("SELECT qname, COUNT(*) AS n FROM dns_log WHERE ts >= ? AND blocked = 1 "
                             "GROUP BY qname ORDER BY n DESC LIMIT 15", (since,)),
            "top_allowed": q("SELECT qname, COUNT(*) AS n FROM dns_log WHERE ts >= ? AND blocked = 0 "
                             "GROUP BY qname ORDER BY n DESC LIMIT 15", (since,)),
            "per_client": q("SELECT client, COUNT(*) AS total, SUM(blocked) AS blocked FROM dns_log "
                            "WHERE ts >= ? GROUP BY client", (since,)),
            "list": {**self.list_info, "count": len(self.domains)},
            "rules": {k: sorted(v) for k, v in self.custom.items()},
            "paused_until": self.paused_until(),
        }

    def recent(self, limit=200, client=None, blocked=None, search=None):
        sql = ("SELECT l.*, c.name AS client_name FROM dns_log l LEFT JOIN dns_clients c ON c.id = l.client "
               "WHERE 1=1")
        args = []
        if client:
            sql += " AND l.client = ?"
            args.append(int(client))
        if blocked in ("0", "1"):
            sql += " AND l.blocked = ?"
            args.append(int(blocked))
        if search:
            sql += " AND l.qname LIKE ? ESCAPE '\\'"
            args.append("%" + re.sub(r"([%_\\])", r"\\\1", search.lower()[:100]) + "%")
        sql += " ORDER BY l.ts DESC, l.rowid DESC LIMIT ?"
        args.append(max(1, min(int(limit), 1000)))
        return self.db.query(sql, args)
