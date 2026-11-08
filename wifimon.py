#!/usr/bin/env python3
"""WiFiMon-Hub: WLAN-Monitor, Werbeblocker (DNS-over-HTTPS) und Geräteverwaltung in einem.

Betriebsarten:
    python wifimon.py            Hub (z. B. auf Railway). Geräte schicken Daten per agent.py.
    python wifimon.py --local    Hub + Messung auf diesem Gerät selbst (Linux oder Windows).
    python wifimon.py --demo     Hub mit zwei simulierten Geräten - zum Ausprobieren.

Umgebungsvariablen:
    WIFIMON_PASSWORD   Passwort fürs Dashboard (Pflicht im Hub-Betrieb)
    WIFIMON_TOKEN      Geheimer Schlüssel, mit dem Mess-Agents Daten schicken dürfen
    WIFIMON_BLOCKLISTS optionale Sperrlisten-URLs, durch Komma getrennt
    WIFIMON_DEMO=1     zusätzlich Demo-Geräte anzeigen
    WIFIMON_DB         Pfad der SQLite-Datei (Standard: Railway-Volume, sonst ./data)
    PORT               Port (setzt Railway automatisch)
"""
import argparse
import base64
import hmac
import ipaddress
import json
import logging
import os
import re
import socket
import threading
import time
import uuid
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from xml.sax.saxutils import escape as xml_escape

import agent
import auth as auth_mod
import collectors
import dnsblock
from storage import COLUMNS, DB

VERSION = "0.3.0"
HERE = os.path.dirname(os.path.abspath(__file__))
log = logging.getLogger("wifimon")

HUB_DEFAULTS = {
    "listen": "0.0.0.0",
    "port": 8080,
    "db_path": "",
    "retention_days": 30,
    "dns_log_days": 7,
    "device_name": "",
}
MAX_BODY = 2_000_000
COOKIE = "wm_sid"
_MAC = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-]{10,64}$")


# --- Konfiguration --------------------------------------------------------------

def load_config(path):
    defaults = {**HUB_DEFAULTS, **agent.DEFAULTS}
    cfg = json.loads(json.dumps(defaults))
    if path and os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            user = json.load(f)
        for key in set(user) - set(defaults):
            if not key.startswith("_"):
                log.warning("Unbekannte Einstellung ignoriert: %s", key)
        cfg.update({k: v for k, v in user.items() if k in defaults})
    elif path:
        log.info("Keine Konfiguration unter %s - nutze Standardwerte.", path)
    if os.environ.get("PORT"):
        cfg["port"] = int(os.environ["PORT"])
    cfg["db_path"] = os.environ.get("WIFIMON_DB") or cfg["db_path"] or _default_db_path()
    return cfg


def _default_db_path():
    for var in ("RAILWAY_VOLUME_MOUNT_PATH", "STATE_DIRECTORY"):
        if os.environ.get(var):
            return os.path.join(os.environ[var].split(":")[0], "wifimon.db")
    return os.path.join(HERE, "data", "wifimon.db")


def on_railway():
    return bool(os.environ.get("RAILWAY_ENVIRONMENT_NAME") or os.environ.get("RAILWAY_PROJECT_ID"))


def persistent_storage():
    """Auf Railway sind Daten nur mit Volume dauerhaft."""
    return not on_railway() or bool(os.environ.get("RAILWAY_VOLUME_MOUNT_PATH") or os.environ.get("WIFIMON_DB"))


# --- Eingangsprüfung ------------------------------------------------------------

_NUMERIC = {"ts", "sent", "recv", "loss", "rtt_min", "rtt_avg", "rtt_max", "jitter", "connected", "freq",
            "channel", "signal", "signal_pct", "rx_rate", "tx_rate", "down", "up", "idle_ping",
            "loaded_ping", "mb_used", "busy", "ping_interval_s", "first_seen", "last_seen"}


def _clean(row, table):
    """Nur bekannte Spalten, Zahlen als Zahl, Texte gekürzt. Alles andere wird None."""
    out = {}
    for col in COLUMNS[table]:
        v = row.get(col) if isinstance(row, dict) else None
        if col in _NUMERIC:
            if isinstance(v, bool):
                v = int(v)
            out[col] = v if isinstance(v, (int, float)) and abs(v) < 1e9 else None
        else:
            out[col] = str(v)[:100] if v is not None else None
    return out


def _valid_ip(v):
    try:
        return str(ipaddress.ip_address(str(v)))
    except ValueError:
        return None


def _clean_addrs(items):
    out = []
    for a in items[:50] if isinstance(items, list) else []:
        if not isinstance(a, dict) or not _valid_ip(a.get("ip")):
            continue
        ip = _valid_ip(a["ip"])
        out.append({"iface": str(a.get("iface") or "")[:40], "ip": ip, "family": auth_mod.ip_family(ip),
                    "prefix": a["prefix"] if isinstance(a.get("prefix"), int) else None,
                    "scope": str(a.get("scope") or "")[:12]})
    return out


def _clean_neighbors(items):
    out = []
    for n in items[:512] if isinstance(items, list) else []:
        if not isinstance(n, dict):
            continue
        ip, mac = _valid_ip(n.get("ip")), str(n.get("mac") or "").lower()
        if not ip or not _MAC.match(mac):
            continue
        out.append({"ip": ip, "mac": mac, "family": auth_mod.ip_family(ip),
                    "state": str(n.get("state") or "")[:20], "iface": str(n.get("iface") or "")[:40]})
    return out


class Hub:
    def __init__(self, cfg, db):
        self.cfg, self.db = cfg, db
        self.local = {}          # Gerätename -> Collector im selben Prozess (--local / Demo)
        self.pending = set()     # Geräte, die beim nächsten Melden einen Speedtest starten sollen
        self._lock = threading.Lock()

    def ingest(self, batch, ip=None):
        if not isinstance(batch, dict):
            raise ValueError("batch muss ein Objekt sein")
        device = batch.get("device")
        if not isinstance(device, str) or not agent.DEVICE_RE.match(device):
            raise ValueError("ungültiger Gerätename")
        if self.db.one("SELECT 1 FROM banned_devices WHERE device = ?", (device,)):
            raise PermissionError("Gerät ist gesperrt")
        now = int(time.time())
        ts = batch.get("ts")
        oldest = now - self.cfg["retention_days"] * 86400
        if not isinstance(ts, int) or not oldest <= ts <= now + 300:
            ts = now

        def rows(items, table, limit):
            if not isinstance(items, list):
                return []
            return [{**_clean(r, table), "device": device, "ts": ts} for r in items[:limit]]

        link = batch.get("link")
        if isinstance(link, dict):
            row = _clean({**link, "connected": int(bool(link.get("connected")))}, "link")
            self.db.insert("link", {**row, "device": device, "ts": ts})
        self.db.insert_many("ping", rows(batch.get("pings"), "ping", 20))
        self.db.insert_many("scan", rows(batch.get("scan"), "scan", 300))
        speed = batch.get("speed")
        if isinstance(speed, dict):
            self.db.insert("speed", {**_clean(speed, "speed"), "device": device, "ts": ts})

        info = _clean(batch, "devices")
        info.update(device=device, first_seen=now, last_seen=now, busy=int(bool(batch.get("busy"))),
                    public_ip=ip, hostname=None, local_ips=None)
        net = batch.get("net")
        if isinstance(net, dict):
            info["hostname"] = str(net.get("hostname"))[:63] if net.get("hostname") else None
            info["local_ips"] = json.dumps(_clean_addrs(net.get("addrs")))
            self.db.replace_neighbors(device, ts, _clean_neighbors(net.get("neighbors")))
        self.db.upsert_device(info)
        if ip:
            self.db.touch_seen([("agent", device, ip, now, 1)])

        with self._lock:
            if device in self.pending:
                self.pending.discard(device)
                return ["speedtest"]
        return []

    def request_speedtest(self, device):
        if device in self.local:
            return self.local[device].start_speedtest()
        if not self.db.one("SELECT 1 FROM devices WHERE device = ?", (device,)):
            raise ValueError("unbekanntes Gerät")
        with self._lock:
            self.pending.add(device)
        return True

    def remove_device(self, device, ban=False):
        if device in self.local:
            raise ValueError("Ein lokales Gerät kann nicht entfernt werden.")
        for t in ("ping", "link", "speed", "scan", "neighbors", "devices"):
            self.db.execute(f"DELETE FROM {t} WHERE device = ?", (device,))
        self.db.execute("DELETE FROM seen WHERE kind = 'agent' AND ref = ?", (device,))
        if ban:
            self.db.execute("INSERT OR REPLACE INTO banned_devices (device, ts) VALUES (?, ?)",
                            (device, int(time.time())))
        with self._lock:
            self.pending.discard(device)

    def unban_device(self, device):
        if not self.db.execute("DELETE FROM banned_devices WHERE device = ?", (device,)):
            raise ValueError("Dieses Gerät ist nicht gesperrt.")

    # --- Abfragen ---------------------------------------------------------------

    def devices(self):
        now = int(time.time())
        rows = self.db.query("SELECT * FROM devices ORDER BY last_seen DESC")
        for r in rows:
            r["online"] = now - (r["last_seen"] or 0) < 3 * (r["ping_interval_s"] or 60) + 30
            r["demo"] = r["device"] in self.local and self.local[r["device"]].src.demo
            try:
                r["addrs"] = json.loads(r.pop("local_ips") or "[]")
            except ValueError:
                r["addrs"] = []
        return rows

    def status(self, device):
        q = self.db
        d = q.one("SELECT * FROM devices WHERE device = ?", (device,)) or {}
        d.pop("local_ips", None)
        return {
            "version": VERSION, "now": int(time.time()), "device": device, "info": d,
            "persistent": persistent_storage(),
            "link": q.one("SELECT * FROM link WHERE device = ? ORDER BY ts DESC LIMIT 1", (device,)),
            "pings": q.query("""SELECT * FROM ping WHERE device = ? AND ts =
                                (SELECT MAX(ts) FROM ping WHERE device = ?) ORDER BY rowid""", (device, device)),
            "speed": q.one("SELECT * FROM speed WHERE device = ? ORDER BY ts DESC LIMIT 1", (device,)),
            "speed_running": bool(d.get("busy")) or device in self.pending
                             or (device in self.local and self.local[device].speed_running()),
        }

    def history(self, device, hours):
        hours = max(1, min(hours, 24 * self.cfg["retention_days"]))
        since = int(time.time()) - hours * 3600
        b = max(60, hours * 3600 // 300)  # höchstens ~300 Punkte pro Linie
        q = self.db.query
        a = (b, b, device, since)
        return {
            "hours": hours, "since": since, "bucket": b,
            "ping": q("""SELECT (ts/?)*? AS t, label, ROUND(AVG(rtt_avg),1) AS avg,
                                ROUND(AVG(jitter),1) AS jitter, ROUND(AVG(loss),1) AS loss
                         FROM ping WHERE device = ? AND ts >= ? GROUP BY t, label ORDER BY t""", a),
            "link": q("""SELECT (ts/?)*? AS t, ROUND(AVG(signal),1) AS signal, ROUND(AVG(rx_rate)) AS rx
                         FROM link WHERE device = ? AND ts >= ? AND connected = 1 GROUP BY t ORDER BY t""", a),
            "speed": q("SELECT * FROM speed WHERE device = ? AND ts >= ? ORDER BY ts", (device, since)),
            "ping_summary": q("""SELECT label, ROUND(AVG(loss),2) AS loss, ROUND(AVG(rtt_avg),1) AS avg,
                                        ROUND(MAX(rtt_max),1) AS worst
                                 FROM ping WHERE device = ? AND ts >= ? GROUP BY label ORDER BY MIN(rowid)""",
                              (device, since)),
            "link_summary": self.db.one("""
                SELECT COUNT(*) AS samples, COALESCE(SUM(connected = 0), 0) AS offline_samples,
                       (SELECT COUNT(*) FROM (
                            SELECT connected, LAG(connected) OVER (ORDER BY ts) AS prev
                            FROM link WHERE device = ? AND ts >= ?) WHERE connected = 0 AND prev = 1) AS drops
                FROM link WHERE device = ? AND ts >= ?""", (device, since, device, since)),
        }

    def scan_result(self, device):
        nets = self.db.query("""SELECT * FROM scan WHERE device = ? AND ts =
                                (SELECT MAX(ts) FROM scan WHERE device = ?) ORDER BY signal DESC""",
                             (device, device))
        own = self.db.one("""SELECT bssid, channel, band FROM link WHERE device = ? AND connected = 1
                             ORDER BY ts DESC LIMIT 1""", (device,))
        return {"ts": nets[0]["ts"] if nets else None, "networks": nets, "own": own,
                "recommendation": collectors.recommend_channels(nets)}

    def neighbors(self):
        return self.db.query("SELECT * FROM neighbors ORDER BY family, ip")


def ios_profile(name, url):
    """Konfigurationsprofil, mit dem iPhone/iPad den Werbeblocker systemweit nutzen."""
    u1 = uuid.uuid5(uuid.NAMESPACE_URL, url + "#dns")
    u2 = uuid.uuid5(uuid.NAMESPACE_URL, url + "#profile")
    n = xml_escape(name)
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>DNSSettings</key>
      <dict>
        <key>DNSProtocol</key><string>HTTPS</string>
        <key>ServerURL</key><string>{xml_escape(url)}</string>
      </dict>
      <key>PayloadDisplayName</key><string>WiFiMon Werbeblocker</string>
      <key>PayloadIdentifier</key><string>de.wifimon.dns.{u1}</string>
      <key>PayloadType</key><string>com.apple.dnsSettings.managed</string>
      <key>PayloadUUID</key><string>{u1}</string>
      <key>PayloadVersion</key><integer>1</integer>
    </dict>
  </array>
  <key>PayloadDescription</key><string>Blockiert Werbung und Tracker über deinen eigenen WiFiMon-Server.</string>
  <key>PayloadDisplayName</key><string>WiFiMon Werbeblocker ({n})</string>
  <key>PayloadIdentifier</key><string>de.wifimon.profile.{u2}</string>
  <key>PayloadRemovalDisallowed</key><false/>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadUUID</key><string>{u2}</string>
  <key>PayloadVersion</key><integer>1</integer>
</dict>
</plist>
""".encode("utf-8")


# --- HTTP -----------------------------------------------------------------------

def make_handler(hub, token, auth, adblock, require_password, trust_proxy=False):
    web = os.path.join(HERE, "web")
    pages = {"/": "index.html", "/index.html": "index.html", "/adblock": "adblock.html", "/geraete": "geraete.html"}
    assets = {"/app.css": ("app.css", "text/css; charset=utf-8"),
              "/app.js": ("app.js", "text/javascript; charset=utf-8")}
    csp = ("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
           "style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; "
           "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")

    class Handler(BaseHTTPRequestHandler):
        server_version = f"wifimon/{VERSION}"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            log.debug("%s - %s", self.ip, fmt % args)

        # --- Hilfen ------------------------------------------------------------
        @property
        def ip(self):
            if not hasattr(self, "_ip"):
                raw = ""
                if trust_proxy:  # Railway überschreibt X-Real-IP mit der echten Besucher-IP
                    raw = self.headers.get("X-Real-IP") or (self.headers.get("X-Forwarded-For") or "").split(",")[0]
                self._ip = auth_mod.normalize_ip(raw) or auth_mod.normalize_ip(self.client_address[0]) \
                    or self.client_address[0]
            return self._ip

        def _https(self):
            return trust_proxy and self.headers.get("X-Forwarded-Proto", "").lower() == "https"

        def _base_url(self):
            host = self.headers.get("Host", "")
            if not re.match(r"^[A-Za-z0-9.\-:\[\]]{1,255}$", host):
                host = "localhost"
            return ("https" if self._https() else "http") + "://" + host

        def _send(self, code, body, ctype="application/json; charset=utf-8", headers=None, cache="no-store"):
            if not isinstance(body, bytes):
                body = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", cache)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            if ctype.startswith("text/html"):
                self.send_header("Content-Security-Policy", csp)
                self.send_header("X-Frame-Options", "DENY")
            if self._https():
                self.send_header("Strict-Transport-Security", "max-age=31536000")
            if code >= 400:
                self.send_header("Connection", "close")
                self.close_connection = True
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _file(self, name, ctype, cache="no-cache"):
            with open(os.path.join(web, name), "rb") as f:
                return self._send(200, f.read(), ctype, cache=cache)

        def _redirect(self, where, headers=None):
            return self._send(303, b"", "text/plain", headers={"Location": where, **(headers or {})})

        def _cookie_token(self):
            try:
                c = SimpleCookie(self.headers.get("Cookie", ""))
            except CookieError:
                return None
            return c[COOKIE].value if COOKIE in c else None

        def _session(self):
            if not hasattr(self, "_sess"):
                if not auth.enabled:
                    self._sess = None if require_password else {"pid": "", "ip": self.ip}
                else:
                    self._sess = auth.session(self._cookie_token(), self.ip)
            return self._sess

        def _allowed(self, page=False):
            """True, wenn eingeloggt. Sonst wurde schon geantwortet."""
            if not auth.enabled and require_password:
                self._send(503, "WIFIMON_PASSWORD ist nicht gesetzt. Bitte in Railway unter Variables "
                                "eintragen und neu deployen.".encode("utf-8"), "text/plain; charset=utf-8")
                return False
            if self._session():
                return True
            if page:
                self._redirect("/login")
            else:
                self._send(401, {"error": "Bitte anmelden"})
            return False

        def _body(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length < 0 or length > MAX_BODY:
                raise OverflowError
            return self.rfile.read(length) if length else b""

        def _json(self):
            data = json.loads(self._body() or b"{}")
            if not isinstance(data, dict):
                raise ValueError("JSON-Objekt erwartet")
            return data

        def _device(self, qs):
            dev = qs.get("device", [""])[0]
            if not agent.DEVICE_RE.match(dev):
                raise ValueError("device fehlt")
            return dev

        def _client_view(self, c):
            base = self._base_url()
            return {**c, "doh_url": f"{base}/dns-query/{c['token']}",
                    "ios_url": f"{base}/ios/{c['token']}.mobileconfig"}

        # --- GET -----------------------------------------------------------------
        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            u = urlparse(self.path)
            qs = parse_qs(u.query)
            try:
                if u.path == "/healthz":
                    return self._send(200, {"ok": True, "version": VERSION})
                if auth.is_banned(self.ip):
                    return self._send(403, {"error": "Diese IP-Adresse ist gesperrt."})
                if u.path.startswith("/dns-query/"):
                    dns = qs.get("dns", [""])[0]
                    msg = base64.urlsafe_b64decode(dns + "=" * (-len(dns) % 4)) if dns else b""
                    return self._doh(u.path, msg)
                if u.path.startswith("/ios/") and u.path.endswith(".mobileconfig"):
                    return self._ios(u.path[5:-13])
                if u.path in assets:
                    return self._file(*assets[u.path])
                if u.path == "/login":
                    if auth.enabled and self._session():
                        return self._redirect("/")
                    return self._file("login.html", "text/html; charset=utf-8")
                if u.path in pages:
                    if self._allowed(page=True):
                        self._file(pages[u.path], "text/html; charset=utf-8")
                    return
                if not u.path.startswith("/api/"):
                    return self._send(404, {"error": "not found"})
                if not self._allowed():
                    return
                return self._api_get(u.path, qs)
            except ValueError as e:
                self._send(400, {"error": str(e) or "bad request"})
            except Exception:
                log.exception("API-Fehler")
                self._send(500, {"error": "internal error"})

        def _api_get(self, path, qs):
            if path == "/api/me":
                s = self._session() or {}
                return self._send(200, {"ip": self.ip, "family": auth_mod.ip_family(self.ip), "pid": s.get("pid"),
                                        "auth": auth.enabled, "version": VERSION})
            if path == "/api/devices":
                return self._send(200, {"devices": hub.devices(), "persistent": persistent_storage(),
                                        "ingest_enabled": bool(token), "now": int(time.time())})
            if path == "/api/status":
                return self._send(200, hub.status(self._device(qs)))
            if path == "/api/history":
                return self._send(200, hub.history(self._device(qs), int(qs.get("hours", ["24"])[0])))
            if path == "/api/scan":
                return self._send(200, hub.scan_result(self._device(qs)))
            if path == "/api/adblock":
                st = adblock.stats(int(qs.get("hours", ["24"])[0]))
                st["clients"] = [self._client_view(c) for c in adblock.clients()]
                return self._send(200, st)
            if path == "/api/adblock/log":
                g = lambda k, d=None: qs.get(k, [d])[0]  # noqa: E731
                return self._send(200, {"items": adblock.recent(g("limit", "200"), g("client"),
                                                                  g("blocked"), g("q"))})
            if path == "/api/access":
                s = self._session() or {}
                return self._send(200, {
                    "now": int(time.time()),
                    "me": {"ip": self.ip, "family": auth_mod.ip_family(self.ip), "pid": s.get("pid")},
                    "sessions": auth.sessions(), "agents": hub.devices(),
                    "banned_devices": hub.db.query("SELECT * FROM banned_devices ORDER BY ts DESC"),
                    "dns_clients": [self._client_view(c) for c in adblock.clients()],
                    "seen": hub.db.query("SELECT * FROM seen ORDER BY last_seen DESC LIMIT 400"),
                    "neighbors": hub.neighbors(), "bans": auth.bans(), "events": auth.events(150),
                })
            return self._send(404, {"error": "not found"})

        # --- DNS ----------------------------------------------------------------------
        def _doh(self, path, msg):
            tok = path[len("/dns-query/"):].strip("/")
            if not _TOKEN_RE.match(tok):
                return self._send(404, b"", "text/plain")
            if not msg or len(msg) > 4096:
                return self._send(400, b"", "text/plain")
            status, resp, ttl = adblock.handle(tok, msg, self.ip)
            if status != 200:
                return self._send(status, b"", "text/plain")
            return self._send(200, resp, "application/dns-message", cache=f"max-age={max(0, ttl)}")

        def _ios(self, tok):
            c = adblock.client_by_token(tok) if _TOKEN_RE.match(tok) else None
            if not c or c["disabled"]:
                return self._send(404, {"error": "unbekannt"})
            body = ios_profile(c["name"], f"{self._base_url()}/dns-query/{tok}")
            return self._send(200, body, "application/x-apple-aspen-config",
                              headers={"Content-Disposition": 'attachment; filename="wifimon-werbeblocker.mobileconfig"'})

        # --- POST --------------------------------------------------------------------
        def do_POST(self):
            u = urlparse(self.path)
            try:
                if auth.is_banned(self.ip):
                    return self._send(403, {"error": "Diese IP-Adresse ist gesperrt."})
                if u.path.startswith("/dns-query/"):
                    return self._doh(u.path, self._body())
                if u.path == "/api/ingest":
                    return self._ingest()
                # Schutz vor fremden Webseiten, die im Browser heimlich POSTen
                if self.headers.get("X-WiFiMon") != "1":
                    return self._send(403, {"error": "fehlender Header"})
                if u.path == "/api/login":
                    return self._login()
                if not self._allowed():
                    return
                return self._api_post(u.path, parse_qs(u.query))
            except OverflowError:
                self._send(413, {"error": "zu groß"})
            except PermissionError as e:
                self._send(403, {"error": str(e)})
            except ValueError as e:
                self._send(400, {"error": str(e) or "bad request"})
            except Exception:
                log.exception("API-Fehler")
                self._send(500, {"error": "internal error"})

        def _login(self):
            if not auth.enabled:
                return self._send(200, {"ok": True})
            data = self._json()
            tok, err = auth.login(str(data.get("password", ""))[:200], self.ip,
                                  self.headers.get("User-Agent", ""))
            if err:
                return self._send(429 if "warten" in err or "gesperrt" in err else 401, {"error": err})
            cookie = (f"{COOKIE}={tok}; Path=/; HttpOnly; SameSite=Strict; Max-Age={auth_mod.SESSION_DAYS * 86400}"
                      + ("; Secure" if self._https() else ""))
            return self._send(200, {"ok": True}, headers={"Set-Cookie": cookie})

        def _api_post(self, path, qs):
            me = self._session() or {}
            data = self._json()  # immer zuerst lesen, sonst stört der Rest die nächste Anfrage
            if path == "/api/logout":
                auth.logout(self._cookie_token(), self.ip)
                return self._send(200, {"ok": True},
                                  headers={"Set-Cookie": f"{COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"})
            if path == "/api/speedtest":
                ok = hub.request_speedtest(self._device(qs))
                return self._send(202 if ok else 409, {"started": ok})
            if path == "/api/adblock/client":
                action = data.get("action")
                if action == "add":
                    c = adblock.add_client(str(data.get("name", "")))
                    auth.event("dns_add", self.ip, f"DNS-Gerät '{c['name']}' angelegt")
                    return self._send(200, {"client": self._client_view(c)})
                cid = int(data.get("id", 0))
                if action in ("disable", "enable"):
                    adblock.set_disabled(cid, action == "disable")
                    auth.event("dns_" + action, self.ip, f"DNS-Gerät {cid} {'gesperrt' if action == 'disable' else 'entsperrt'}")
                elif action == "delete":
                    adblock.delete_client(cid)
                    auth.event("dns_delete", self.ip, f"DNS-Gerät {cid} gelöscht")
                else:
                    raise ValueError("unbekannte Aktion")
                return self._send(200, {"ok": True})
            if path == "/api/adblock/rule":
                d = adblock.set_rule(str(data.get("kind")), str(data.get("domain", "")), bool(data.get("add", True)))
                return self._send(200, {"ok": True, "domain": d})
            if path == "/api/adblock/pause":
                return self._send(200, {"paused_until": adblock.pause(data.get("minutes", 0))})
            if path == "/api/adblock/refresh":
                return self._send(200, {"list": adblock.refresh_lists()})
            if path == "/api/session/kick":
                if data.get("others"):
                    return self._send(200, {"kicked": auth.kick_others(me.get("pid"), self.ip)})
                auth.kick(str(data.get("pid", "")), self.ip)
                return self._send(200, {"ok": True, "self": data.get("pid") == me.get("pid")})
            if path == "/api/ban":
                return self._send(200, {"banned": auth.ban(str(data.get("ip", "")), str(data.get("note", "")), self.ip)})
            if path == "/api/unban":
                auth.unban(str(data.get("ip", "")), self.ip)
                return self._send(200, {"ok": True})
            if path == "/api/device/remove":
                dev = str(data.get("device", ""))
                if not agent.DEVICE_RE.match(dev):
                    raise ValueError("ungültiger Gerätename")
                hub.remove_device(dev, bool(data.get("ban")))
                auth.event("device_ban" if data.get("ban") else "device_remove", self.ip,
                           f"Mess-Gerät '{dev}' {'rausgeworfen und gesperrt' if data.get('ban') else 'entfernt'}")
                return self._send(200, {"ok": True})
            if path == "/api/device/unban":
                dev = str(data.get("device", ""))
                hub.unban_device(dev)
                auth.event("device_unban", self.ip, f"Mess-Gerät '{dev}' wieder zugelassen")
                return self._send(200, {"ok": True})
            return self._send(404, {"error": "not found"})

        def _ingest(self):
            if not token:
                return self._send(503, {"error": "WIFIMON_TOKEN ist auf dem Hub nicht gesetzt"})
            got = self.headers.get("Authorization", "")
            if not hmac.compare_digest(got.encode(), f"Bearer {token}".encode()):
                return self._send(401, {"error": "falscher Token"})
            body = self._body()
            if not body:
                return self._send(413, {"error": "leer"})
            return self._send(200, {"ok": True, "commands": hub.ingest(json.loads(body), self.ip)})

    return Handler


# --- Start ----------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description="WiFiMon-Hub")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--local", action="store_true", help="zusätzlich auf diesem Gerät messen")
    mode.add_argument("--demo", action="store_true", help="nur simulierte Geräte (Vorschau)")
    ap.add_argument("--config", help="Pfad zur config.json")
    ap.add_argument("--port", type=int, help="Port überschreiben")
    ap.add_argument("--listen", help="Adresse überschreiben, z. B. 127.0.0.1")
    ap.add_argument("--no-blocklist", action="store_true", help="Sperrliste nicht herunterladen (Tests)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = load_config(args.config)
    if args.port:
        cfg["port"] = args.port
    if args.listen:
        cfg["listen"] = args.listen

    demo = args.demo or os.environ.get("WIFIMON_DEMO") == "1"
    if args.demo:
        import tempfile
        cfg["db_path"] = os.path.join(tempfile.gettempdir(), f"wifimon-demo-{os.getpid()}.db")
    elif not persistent_storage():
        log.warning("Kein Railway-Volume eingebunden: Alle Daten gehen beim nächsten Deploy verloren!")

    token = os.environ.get("WIFIMON_TOKEN", "")
    password = os.environ.get("WIFIMON_PASSWORD", "")
    if token and len(token) < 16:
        raise SystemExit("WIFIMON_TOKEN ist zu kurz (mindestens 16 Zeichen).")
    # Ohne Passwort nur erlaubt: lokaler Betrieb im Heimnetz oder reine Demo
    require_password = not (args.local or args.demo)
    trust_proxy = on_railway() or os.environ.get("WIFIMON_TRUST_PROXY") == "1"

    db = DB(cfg["db_path"])
    hub = Hub(cfg, db)
    auth = auth_mod.Auth(db, password)
    lists = [x.strip() for x in os.environ.get("WIFIMON_BLOCKLISTS", "").split(",") if x.strip()]
    adblock = dnsblock.AdBlocker(db, os.path.dirname(os.path.abspath(cfg["db_path"])), lists or None)
    if not args.no_blocklist:
        adblock.start()
    else:
        threading.Thread(target=adblock._writer, daemon=True, name="dns-log").start()

    def run_collector(source, name):
        col = agent.Collector(cfg, source, name, hub.ingest)
        hub.local[name] = col
        threading.Thread(target=col.loop, daemon=True, name=f"collector-{name}").start()

    if demo:
        import demo as demo_mod
        for name, src in demo_mod.make_devices():
            src.seed(db, name, hours=72)
            run_collector(src, name)
    if args.local:
        run_collector(agent.make_source(cfg), cfg["device_name"] or socket.gethostname()[:40])

    def cleanup_loop():
        while True:
            time.sleep(6 * 3600)
            db.cleanup(cfg["retention_days"], cfg["dns_log_days"])
            auth.cleanup()

    threading.Thread(target=cleanup_loop, daemon=True, name="cleanup").start()

    server = ThreadingHTTPServer((cfg["listen"], cfg["port"]),
                                 make_handler(hub, token, auth, adblock, require_password, trust_proxy))
    server.daemon_threads = True
    log.info("WiFiMon-Hub %s auf Port %d | Agents: %s | Passwort: %s | Daten: %s",
             VERSION, cfg["port"], "an" if token else "AUS (WIFIMON_TOKEN fehlt)",
             "gesetzt" if password else ("FEHLT" if require_password else "keins"), cfg["db_path"])
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Beendet.")


if __name__ == "__main__":
    main()
