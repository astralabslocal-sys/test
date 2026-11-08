"""Messfunktionen für WiFiMon (Linux) und gemeinsamer Speedtest.

Die Parser sind reine Funktionen und werden in tests/ mit Beispielausgaben geprüft.
Externe Programme werden mit LC_ALL=C gestartet, damit die Ausgabe immer englisch ist.
"""
import http.client
import logging
import os
import re
import shutil
import ssl
import subprocess
import sys
import threading
import time
import urllib.request

log = logging.getLogger("wifimon.collect")

WINDOWS = sys.platform == "win32"
ENV = {**os.environ, "LC_ALL": "C"}
USER_AGENT = "wifimon/0.3"
DOWN_URL = "https://speed.cloudflare.com/__down?bytes=25000000"
UP_URL = "https://speed.cloudflare.com/__up"
UP_BODY_SIZE = 4_000_000
_UP_BLOCK = os.urandom(65536)
# Windows: Ausgabe in der Konsolen-Codepage, kein aufpoppendes Fenster
_RUN_OPTS = ({"encoding": "oem", "errors": "replace", "creationflags": 0x08000000}
             if WINDOWS else {"text": True, "errors": "replace"})


def run(cmd, timeout=30):
    """Startet ein Programm und gibt (returncode, stdout) zurück. Nie eine Exception."""
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, env=ENV, **_RUN_OPTS)
        return p.returncode, p.stdout or ""
    except (OSError, subprocess.TimeoutExpired) as e:
        log.debug("Befehl fehlgeschlagen %s: %s", cmd, e)
        return -1, ""


# --- Umrechnungen -------------------------------------------------------------

def freq_to_channel(freq):
    """MHz -> (Kanal, Band) mit Band '2.4', '5' oder '6'."""
    if not freq:
        return None, None
    f = int(round(freq))
    if f == 2484:
        return 14, "2.4"
    if 2412 <= f <= 2472:
        return (f - 2407) // 5, "2.4"
    if 5150 <= f < 5925:
        return (f - 5000) // 5, "5"
    if 5925 <= f <= 7125:
        return (f - 5950) // 5, "6"
    return None, None


def pct_to_dbm(pct):
    return int(round(pct / 2 - 100))


def dbm_to_pct(dbm):
    return max(0, min(100, int(round(2 * (dbm + 100)))))


# --- Ping ---------------------------------------------------------------------

_PING_COUNT = re.compile(r"(\d+) packets transmitted, (\d+) (?:packets )?received")
_PING_RTT = re.compile(r"min/avg/max(?:/mdev)? = ([\d.]+)/([\d.]+)/([\d.]+)(?:/([\d.]+))?")


def parse_ping(out):
    m = _PING_COUNT.search(out or "")
    if not m:
        return None
    sent, recv = int(m[1]), int(m[2])
    r = {
        "sent": sent,
        "recv": recv,
        "loss": round(100 * (sent - recv) / sent, 1) if sent else 100.0,
        "rtt_min": None, "rtt_avg": None, "rtt_max": None, "jitter": None,
    }
    m = _PING_RTT.search(out)
    if m:
        r["rtt_min"], r["rtt_avg"], r["rtt_max"] = float(m[1]), float(m[2]), float(m[3])
        if m[4]:
            r["jitter"] = float(m[4])
    return r


def _ping_cmd(host, count, interval, iface=None):
    cmd = ["ping", "-n", "-q", "-c", str(count), "-i", str(interval), "-W", "2"]
    if iface:
        cmd += ["-I", iface]
    return cmd + [host]


def ping(host, count=10, iface=None, interval=0.2):
    rc, out = run(_ping_cmd(host, count, interval, iface), timeout=count * interval + 15)
    r = parse_ping(out)
    if r is None:  # Host nicht auflösbar, Netz weg, ...
        r = {"sent": count, "recv": 0, "loss": 100.0,
             "rtt_min": None, "rtt_avg": None, "rtt_max": None, "jitter": None}
    return r


# --- Interface / Route --------------------------------------------------------

def detect_interface(preferred="auto"):
    def is_wireless(n):
        return os.path.isdir(f"/sys/class/net/{n}/wireless")

    if preferred and preferred != "auto":
        return preferred
    try:
        names = sorted(os.listdir("/sys/class/net"))
    except OSError:
        return None
    for n in names:
        if is_wireless(n):
            return n
    return None


def parse_default_route(out):
    for line in (out or "").splitlines():
        m = re.match(r"default(?: via (\S+))?(?:.* dev (\S+))?", line.strip())
        if m:
            return m[1], m[2]
    return None, None


def default_route():
    _, out = run(["ip", "-4", "route", "show", "default"])
    return parse_default_route(out)


# --- WLAN-Verbindung ----------------------------------------------------------

def _grab(pattern, text, conv=str):
    m = re.search(pattern, text, re.M | re.I)
    if not m:
        return None
    try:
        return conv(m[1].strip())
    except ValueError:
        return None


def parse_iw_link(out):
    if not out or "Not connected" in out:
        return {"connected": False}
    r = {
        "connected": True,
        "bssid": _grab(r"Connected to ([0-9a-f:]{17})", out, str.lower),
        "ssid": _grab(r"^\s*SSID: (.*)$", out),
        "freq": _grab(r"^\s*freq: ([\d.]+)", out, lambda s: int(float(s))),
        "signal": _grab(r"^\s*signal: (-?\d+)", out, int),
        "rx_rate": _grab(r"^\s*rx bitrate: ([\d.]+)", out, float),
        "tx_rate": _grab(r"^\s*tx bitrate: ([\d.]+)", out, float),
    }
    r["channel"], r["band"] = freq_to_channel(r["freq"])
    r["signal_pct"] = dbm_to_pct(r["signal"]) if r["signal"] is not None else None
    return r


def channel_to_freq(ch, band=None):
    if not ch:
        return None
    if band == "6":
        return 5950 + 5 * ch
    if ch == 14:
        return 2484
    if ch <= 13 and band != "5":
        return 2407 + 5 * ch
    return 5000 + 5 * ch


# --- Kanal-Scan ---------------------------------------------------------------

def _split_terse(line):
    """nmcli -t trennt mit ':' und maskiert ':' in Werten als '\\:'."""
    parts, cur, esc = [], [], False
    for ch in line:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == ":":
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts


def parse_nmcli_scan(out):
    nets = []
    for line in (out or "").splitlines():
        p = _split_terse(line)
        if len(p) < 6:
            continue
        bssid, ssid, _chan, freq, signal, sec = p[:6]
        try:
            f = int(re.match(r"\d+", freq)[0])
            pct = int(signal)
        except (TypeError, ValueError):
            continue
        ch, band = freq_to_channel(f)
        nets.append({
            "bssid": bssid.lower(), "ssid": ssid or None, "freq": f,
            "channel": ch, "band": band, "signal": pct_to_dbm(pct),
            "signal_pct": pct, "security": sec or None,
        })
    return nets


def parse_iw_scan(out):
    nets, cur = [], None
    for line in (out or "").splitlines():
        m = re.match(r"^BSS ([0-9a-f:]{17})", line, re.I)
        if m:
            cur = {"bssid": m[1].lower(), "ssid": None, "freq": None, "signal": None, "security": None}
            nets.append(cur)
            continue
        if cur is None:
            continue
        s = line.strip()
        try:
            if s.startswith("freq:"):
                cur["freq"] = int(float(s.split()[1]))
            elif s.startswith("signal:"):
                cur["signal"] = int(float(s.split()[1]))
            elif s.startswith("SSID:"):
                cur["ssid"] = s[5:].strip() or None
            elif s.startswith("RSN:"):
                cur["security"] = "WPA2/WPA3"
            elif s.startswith("WPA:") and not cur["security"]:
                cur["security"] = "WPA"
        except (IndexError, ValueError):
            pass
    result = []
    for n in nets:
        if n["freq"] is None:
            continue
        n["channel"], n["band"] = freq_to_channel(n["freq"])
        n["signal_pct"] = dbm_to_pct(n["signal"]) if n["signal"] is not None else None
        result.append(n)
    return result


def scan(iface):
    if shutil.which("nmcli"):
        rc, out = run(["nmcli", "-t", "-f", "BSSID,SSID,CHAN,FREQ,SIGNAL,SECURITY",
                       "dev", "wifi", "list", "ifname", iface, "--rescan", "auto"], timeout=45)
        if rc == 0:
            return parse_nmcli_scan(out)
    # Fallback: aktiver Scan braucht CAP_NET_ADMIN, "scan dump" liefert den Cache
    for cmd in (["iw", "dev", iface, "scan"], ["iw", "dev", iface, "scan", "dump"]):
        rc, out = run(cmd, timeout=45)
        if rc == 0 and out:
            return parse_iw_scan(out)
    return []


# 5-GHz-Kanäle in 80-MHz-Blöcken. DFS-Blöcke kann nicht jeder Router nutzen.
_BLOCKS_5 = {36: False, 52: True, 100: True, 116: True, 132: True, 149: False}


def _block_5(ch):
    for start in sorted(_BLOCKS_5, reverse=True):
        if ch >= start:
            return start if ch < start + 16 else None
    return None


def recommend_channels(nets):
    """Bewertet Kanäle nach Störungen: Summe der Signalstärken überlappender Netze."""
    res = {}
    n24 = [n for n in nets if n.get("band") == "2.4" and n.get("channel")]
    if n24:
        scores = {}
        for c in (1, 6, 11):
            s = 0.0
            for n in n24:
                d = abs(n["channel"] - c)
                if d < 5:
                    s += (n.get("signal_pct") or 0) / 100 * (1 - d / 5)
            scores[c] = round(s, 2)
        res["2.4"] = {"best": min(scores, key=scores.get), "scores": scores}
    n5 = [n for n in nets if n.get("band") == "5" and n.get("channel")]
    if n5:
        scores = {b: 0.0 for b in _BLOCKS_5}
        for n in n5:
            b = _block_5(n["channel"])
            if b is not None:
                scores[b] = round(scores[b] + (n.get("signal_pct") or 0) / 100, 2)
        best_safe = min((b for b in scores if not _BLOCKS_5[b]), key=scores.get)
        res["5"] = {
            "best": min(scores, key=scores.get),
            "best_non_dfs": best_safe,
            "scores": scores,
            "dfs": [b for b, dfs in _BLOCKS_5.items() if dfs],
        }
    return res


# --- Speedtest ----------------------------------------------------------------

class _BoundHTTPSHandler(urllib.request.HTTPSHandler):
    """HTTPS über eine feste Quell-IP. Unter Windows (strong host model) erzwingt
    das das WLAN-Interface, auch wenn zusätzlich ein LAN-Kabel steckt."""

    def __init__(self, source_ip):
        super().__init__(context=ssl.create_default_context())
        self._src = source_ip

    def https_open(self, req):
        src = self._src

        class Conn(http.client.HTTPSConnection):
            def __init__(self, *a, **kw):
                kw["source_address"] = (src, 0)
                super().__init__(*a, **kw)

        return self.do_open(Conn, req, context=self._context)


def _opener(source_ip=None):
    return urllib.request.build_opener(_BoundHTTPSHandler(source_ip)) if source_ip else urllib.request.build_opener()


def _download_worker(add, stop, opener):
    req = urllib.request.Request(DOWN_URL, headers={"User-Agent": USER_AGENT})
    with opener.open(req, timeout=15) as r:
        while not stop.is_set():
            chunk = r.read(65536)
            if not chunk:
                break
            add(len(chunk))


def _upload_worker(add, stop, opener):
    def body():
        sent = 0
        while sent < UP_BODY_SIZE:
            n = min(len(_UP_BLOCK), UP_BODY_SIZE - sent)
            yield _UP_BLOCK[:n]
            add(n)
            sent += n

    req = urllib.request.Request(UP_URL, data=body(), method="POST", headers={
        "User-Agent": USER_AGENT,
        "Content-Type": "application/octet-stream",
        "Content-Length": str(UP_BODY_SIZE),
    })
    with opener.open(req, timeout=30) as r:
        r.read()


def _measure(worker, streams, duration, cap_bytes, warmup=1.5, opener=None):
    """Mehrere parallele Streams. Gemessen wird erst nach der Aufwärmphase,
    damit TLS-Handshake und TCP-Slow-Start das Ergebnis nicht verfälschen."""
    total = [0]
    lock = threading.Lock()
    stop = threading.Event()
    errors = []

    def add(n):
        with lock:
            total[0] += n

    opener = opener or _opener()

    def loop():
        try:
            while not stop.is_set():
                worker(add, stop, opener)
        except Exception as e:  # noqa: BLE001 - Fehler werden gesammelt gemeldet
            errors.append(e)

    def done():
        with lock:
            b = total[0]
        return b >= cap_bytes or not any(t.is_alive() for t in threads)

    threads = [threading.Thread(target=loop, daemon=True) for _ in range(streams)]
    start = time.monotonic()
    for t in threads:
        t.start()
    b0, t0 = None, None
    while time.monotonic() - start < warmup:
        time.sleep(0.05)
        if done():  # Limit schon beim Aufwärmen erreicht -> ganze Zeit werten
            b0, t0 = 0, start
            break
    if t0 is None:
        with lock:
            b0 = total[0]
        t0 = time.monotonic()
        while time.monotonic() - t0 < duration and not done():
            time.sleep(0.05)
    with lock:
        b1 = total[0]
    t1 = time.monotonic()
    stop.set()
    for t in threads:
        t.join(timeout=5)
    if b1 - b0 <= 0:
        raise RuntimeError(str(errors[0]) if errors else "keine Daten empfangen")
    return round((b1 - b0) * 8 / (t1 - t0) / 1e6, 1), b1


def speedtest(cfg, ping_fn, ping_target, source_ip=None):
    """ping_fn(host, count) -> Ping-Ergebnis der jeweiligen Plattform."""
    res = {"ts": int(time.time()), "down": None, "up": None, "idle_ping": None,
           "loaded_ping": None, "mb_used": 0.0, "error": None}
    errors = []
    duration = cfg["speedtest_duration_s"]
    streams = cfg["speedtest_streams"]
    cap = cfg["speedtest_cap_mb"] * 1_000_000
    opener = _opener(source_ip)

    res["idle_ping"] = ping_fn(ping_target, 5)["rtt_avg"]

    # Ping während des Downloads -> Bufferbloat (Latenz unter Last)
    loaded = {}

    def ping_under_load():
        time.sleep(2)  # erst messen, wenn der Download auf vollem Tempo läuft
        loaded.update(ping_fn(ping_target, 6))

    pinger = threading.Thread(target=ping_under_load, daemon=True)
    pinger.start()
    try:
        res["down"], used = _measure(_download_worker, streams, duration, cap, opener=opener)
        res["mb_used"] += used / 1e6
    except Exception as e:  # noqa: BLE001
        errors.append(f"Download: {e}")
    pinger.join(timeout=20)
    res["loaded_ping"] = loaded.get("rtt_avg")

    try:
        res["up"], used = _measure(_upload_worker, streams, duration, cap, opener=opener)
        res["mb_used"] += used / 1e6
    except Exception as e:  # noqa: BLE001
        errors.append(f"Upload: {e}")

    res["mb_used"] = round(res["mb_used"], 1)
    res["error"] = "; ".join(errors) or None
    return res


# --- Quelle für den Monitor ---------------------------------------------------

class LinuxSource:
    demo = False
    platform = "linux"

    def __init__(self, iface="auto"):
        self.iface = detect_interface(iface)
        if not self.iface:
            log.warning("Kein WLAN-Interface gefunden - es werden nur Pings gemessen.")

    def route(self):
        return default_route()

    def link(self):
        if not self.iface:
            return {"connected": False}
        rc, out = run(["iw", "dev", self.iface, "link"])
        return parse_iw_link(out) if rc == 0 else {"connected": False}

    def ping(self, host, count, bind):
        return ping(host, count, self.iface if bind else None)

    def scan(self):
        return scan(self.iface) if self.iface else []

    def speedtest(self, cfg, target, bind):
        # Linux: Quell-IP erzwingt kein Interface (weak host) -> Dashboard warnt stattdessen
        return speedtest(cfg, lambda h, c: self.ping(h, c, bind), target)
