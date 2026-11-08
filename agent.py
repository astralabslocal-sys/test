#!/usr/bin/env python3
"""WiFiMon-Agent: misst auf einem Gerät im WLAN und schickt die Werte an den Hub.

    python agent.py --hub https://deine-domain.de --token GEHEIM --name PC-Wohnzimmer

Statt Parametern gehen auch Umgebungsvariablen: WIFIMON_HUB, WIFIMON_TOKEN, WIFIMON_NAME.
Läuft unter Windows 10/11 und Linux. Nur Python-Standardbibliothek.
"""
import argparse
import collections
import json
import logging
import os
import platform
import re
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

VERSION = "0.3.0"
log = logging.getLogger("wifimon.agent")

DEFAULTS = {
    "interface": "auto",
    "ping_targets": [
        {"host": "1.1.1.1", "label": "Cloudflare"},
        {"host": "8.8.8.8", "label": "Google"},
    ],
    "ping_count": 10,
    "ping_interval_s": 60,
    "scan_interval_s": 900,
    "speedtest_interval_s": 3600,
    "speedtest_duration_s": 8,
    "speedtest_streams": 4,
    "speedtest_cap_mb": 200,
    "network_scan": True,
}

DEVICE_RE = re.compile(r"^[\w .\-]{1,40}$")


def make_source(cfg):
    if sys.platform == "win32":
        import windows
        return windows.WindowsSource(cfg["interface"])
    if sys.platform.startswith("linux"):
        import collectors
        return collectors.LinuxSource(cfg["interface"])
    raise SystemExit(f"Plattform {sys.platform} wird noch nicht unterstützt (nur Windows und Linux).")


def network_snapshot():
    try:
        import netinfo
        return netinfo.snapshot()
    except Exception:  # noqa: BLE001 - die Übersicht ist ein Zusatz, Messen geht vor
        log.exception("Netzwerk-Übersicht fehlgeschlagen")
        return None


class Collector:
    """Misst nach Zeitplan und übergibt jede Messung als 'batch' an sink(batch) -> Befehle."""

    def __init__(self, cfg, source, device, sink):
        self.cfg, self.src, self.device, self.sink = cfg, source, device, sink
        self.route = (None, None)
        self.last_link = {}
        self._speed_lock = threading.Lock()
        self._send_lock = threading.Lock()

    def _bind(self):
        dev = self.route[1]
        return bool(self.src.iface and dev and dev != self.src.iface)

    def _batch(self, **parts):
        return {
            "device": self.device, "ts": int(time.time()), "agent_version": VERSION,
            "platform": self.src.platform, "iface": self.src.iface,
            "gateway": self.route[0], "route_dev": self.route[1],
            "busy": self.speed_running(), "ping_interval_s": self.cfg["ping_interval_s"],
            **parts,
        }

    def send(self, batch):
        with self._send_lock:
            commands = self.sink(batch) or []
        if "speedtest" in commands:
            self.start_speedtest()

    def speed_running(self):
        return self._speed_lock.locked()

    def tick(self):
        self.route = self.src.route()
        link = self.src.link()
        self.last_link = link
        pings = []
        bind = self._bind()
        # Pings während des Speedtests wären verfälscht. Und läuft das Internet über
        # ein Kabel, während das WLAN getrennt ist, gibt es nichts WLAN-Bezogenes zu messen.
        if not self.speed_running() and not (bind and not link.get("connected")):
            targets = [(self.route[0], "Router")] if self.route[0] else []
            targets += [(t["host"], t.get("label") or t["host"]) for t in self.cfg["ping_targets"]]
            if targets:
                with ThreadPoolExecutor(len(targets)) as ex:
                    results = list(ex.map(lambda t: self.src.ping(t[0], self.cfg["ping_count"], bind), targets))
                pings = [{"target": h, "label": lbl, **r} for (h, lbl), r in zip(targets, results)]
        self.send(self._batch(link=link, pings=pings))

    def tick_scan(self):
        nets = self.src.scan()
        log.info("Kanal-Scan: %d Netze", len(nets))
        parts = {"scan": nets}
        if self.cfg.get("network_scan", True) and not self.src.demo:
            net = network_snapshot()
            if net:
                log.info("Netzwerk: %d eigene Adressen, %d Geräte im Heimnetz",
                         len(net["addrs"]), len(net["neighbors"]))
                parts["net"] = net
        self.send(self._batch(**parts))

    def start_speedtest(self):
        if self._bind() and not self.last_link.get("connected"):
            log.info("Speedtest übersprungen: WLAN getrennt, Internet läuft über %s.", self.route[1])
            return False
        if not self._speed_lock.acquire(blocking=False):
            return False

        def work():
            try:
                targets = self.cfg["ping_targets"]
                target = targets[0]["host"] if targets else "1.1.1.1"
                log.info("Speedtest gestartet")
                res = self.src.speedtest(self.cfg, target, self._bind())
                log.info("Speedtest: %s / %s Mbit/s (%s MB) %s", res["down"], res["up"], res["mb_used"],
                         res["error"] or "")
            except Exception as e:  # noqa: BLE001
                log.exception("Speedtest fehlgeschlagen")
                res = {"ts": int(time.time()), "error": str(e)}
            finally:
                self._speed_lock.release()
            self.send(self._batch(speed=res))

        threading.Thread(target=work, daemon=True, name="speedtest").start()
        return True

    def loop(self):
        now = time.time()
        c = self.cfg
        jobs = [
            [c["ping_interval_s"], now, self.tick],
            [c["scan_interval_s"], now + 5, self.tick_scan],
            [c["speedtest_interval_s"], now + 120, self.start_speedtest],
        ]
        jobs = [j for j in jobs if j[0] and j[0] > 0]  # Intervall 0 = aus
        while True:
            for job in jobs:
                if time.time() >= job[1]:
                    job[1] = time.time() + job[0]
                    try:
                        job[2]()
                    except Exception:
                        log.exception("Messung fehlgeschlagen")
            time.sleep(1)


class HttpSink:
    """Schickt Batches per HTTPS an den Hub. Ist der Hub nicht erreichbar, werden
    bis zu 1000 Batches gepuffert und später in der richtigen Reihenfolge nachgeliefert."""

    def __init__(self, hub, token):
        self.url = hub.rstrip("/") + "/api/ingest"
        self.token = token
        self.queue = collections.deque(maxlen=1000)
        self.rejected = False

    def _post(self, batch):
        body = json.dumps(batch).encode("utf-8")
        req = urllib.request.Request(self.url, data=body, method="POST", headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.token}",
            "User-Agent": f"wifimon-agent/{VERSION}",
        })
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read() or b"{}")

    def __call__(self, batch):
        self.queue.append(batch)
        commands = []
        while self.queue:
            try:
                resp = self._post(self.queue[0])
            except urllib.error.HTTPError as e:
                if e.code == 401:
                    log.error("Hub lehnt den Token ab (HTTP 401). Stimmt WIFIMON_TOKEN?")
                elif e.code == 403:
                    log.error("Dieses Gerät wurde im Dashboard gesperrt (oder seine IP). Daten werden verworfen.")
                    self.queue.clear()
                    self.rejected = True
                elif 400 <= e.code < 500:
                    log.error("Hub lehnt Daten ab (HTTP %s) - Batch verworfen.", e.code)
                    self.queue.popleft()
                    continue
                else:
                    log.warning("Hub-Fehler HTTP %s - %d Batches gepuffert.", e.code, len(self.queue))
                break
            except (urllib.error.URLError, OSError, ValueError) as e:
                log.warning("Hub nicht erreichbar (%s) - %d Batches gepuffert.", e, len(self.queue))
                break
            self.queue.popleft()
            commands += resp.get("commands", [])
        return commands


def main(argv=None):
    ap = argparse.ArgumentParser(description="WiFiMon-Agent")
    ap.add_argument("--hub", default=os.environ.get("WIFIMON_HUB"), help="Adresse des Hubs, z. B. https://deine-domain.de")
    ap.add_argument("--token", default=os.environ.get("WIFIMON_TOKEN"), help="Geräte-Token (WIFIMON_TOKEN auf dem Hub)")
    ap.add_argument("--name", default=os.environ.get("WIFIMON_NAME") or socket.gethostname(), help="Gerätename im Dashboard")
    ap.add_argument("--config", help="optionale JSON-Datei mit Messeinstellungen")
    ap.add_argument("--once", action="store_true", help="eine Messung, dann beenden (zum Testen)")
    ap.add_argument("--log", help="Logdatei (sinnvoll beim Autostart ohne Konsole)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    handlers = [logging.FileHandler(args.log, encoding="utf-8")] if args.log else None
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, handlers=handlers,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    if not args.hub or not args.token:
        ap.error("--hub und --token sind nötig (oder WIFIMON_HUB / WIFIMON_TOKEN).")
    if not args.hub.startswith("https://") and not re.match(r"^http://(localhost|127\.0\.0\.1)(:\d+)?", args.hub):
        ap.error("Der Hub muss mit https:// erreichbar sein, sonst wäre der Token im Klartext unterwegs.")
    if not DEVICE_RE.match(args.name):
        ap.error("--name: 1-40 Zeichen, nur Buchstaben, Ziffern, Leerzeichen, . _ -")

    cfg = json.loads(json.dumps(DEFAULTS))
    if args.config:
        with open(args.config, encoding="utf-8") as f:
            cfg.update({k: v for k, v in json.load(f).items() if k in DEFAULTS})

    source = make_source(cfg)
    sink = HttpSink(args.hub, args.token)
    col = Collector(cfg, source, args.name, sink)
    log.info("Agent %s - Gerät '%s' (%s, %s) -> %s", VERSION, args.name, platform.system(),
             source.iface or "kein WLAN", args.hub)
    if args.once:
        col.tick()
        col.tick_scan()
        ok = not sink.queue and not sink.rejected
        print("OK - Daten beim Hub angekommen." if ok else "FEHLER - siehe Log oben.")
        sys.exit(0 if ok else 1)
    try:
        col.loop()
    except KeyboardInterrupt:
        log.info("Beendet.")


if __name__ == "__main__":
    main()
