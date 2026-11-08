"""Messquelle für Windows 10/11 (netsh + ping). Versteht deutsche und englische Ausgaben.

Die Parser werten möglichst die Struktur aus (MAC-Adressen, '%', 'TTL=') statt der
übersetzten Beschriftungen, damit sie auch bei anderen Systemsprachen meist funktionieren.
"""
import json
import logging
import re
import statistics
import time

import collectors as c

log = logging.getLogger("wifimon.windows")

_MAC = r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})"
_LOCATION_HINT = re.compile(r"location|standort", re.I)


def _kv(line):
    """'    Schlüssel   : Wert' -> (schlüssel, wert)"""
    m = re.match(r"^\s*([^:]+?)\s*:\s?(.*?)\s*$", line)
    return (m[1].strip().lower(), m[2].strip()) if m else (None, None)


def _band(text):
    m = re.search(r"(2[.,]4|5|6)\s*GHz", text or "", re.I)
    return m[1].replace(",", ".") if m else None


def _num(s):
    m = re.search(r"-?\d+(?:[.,]\d+)?", s or "")
    return float(m[0].replace(",", ".")) if m else None


# --- Verbindung ---------------------------------------------------------------

def parse_interfaces(out):
    """`netsh wlan show interfaces` -> Liste von Schnittstellen (dict)."""
    ifaces, cur = [], None
    for line in (out or "").splitlines():
        k, v = _kv(line)
        if k is None:
            continue
        if k == "name":
            cur = {"name": v, "connected": False}
            ifaces.append(cur)
            continue
        if cur is None:
            continue
        if k in ("status", "state"):
            cur["connected"] = v.lower() in ("verbunden", "connected")
        elif k == "ssid":
            cur["ssid"] = v or None
        elif "bssid" in k:
            m = re.search(_MAC, v, re.I)
            cur["bssid"] = m[1].lower() if m else None
        elif k == "band":
            cur["band"] = _band(v)
        elif k in ("kanal", "channel", "canal", "canale"):
            ch = _num(v)
            cur["channel"] = int(ch) if ch is not None else None
        elif k == "rssi":
            cur["rssi"] = _num(v)
        elif k == "signal" and "%" in v:
            cur["signal_pct"] = int(_num(v))
        elif "mbit" in k or "mbps" in k:
            rate = _num(v)
            if re.search(r"empfang|receive|recep|ricez", k):
                cur["rx_rate"] = rate
            elif re.search(r"übertrag|ubertrag|transmit|emis|trasm", k):
                cur["tx_rate"] = rate
    return ifaces


def link_from_interface(i):
    if not i or not i.get("connected"):
        return {"connected": False}
    ch = i.get("channel")
    band = i.get("band") or (("2.4" if ch <= 14 else "5") if ch else None)
    pct = i.get("signal_pct")
    sig = int(i["rssi"]) if i.get("rssi") is not None else (c.pct_to_dbm(pct) if pct is not None else None)
    return {
        "connected": True, "ssid": i.get("ssid"), "bssid": i.get("bssid"),
        "channel": ch, "band": band, "freq": c.channel_to_freq(ch, band),
        "signal": sig, "signal_pct": pct if pct is not None else (c.dbm_to_pct(sig) if sig is not None else None),
        "rx_rate": i.get("rx_rate"), "tx_rate": i.get("tx_rate"),
    }


# --- Scan ---------------------------------------------------------------------

def parse_networks(out):
    """`netsh wlan show networks mode=bssid` -> Liste der Access Points."""
    nets, ssid, security, cur = [], None, None, None
    for line in (out or "").splitlines():
        m = re.match(r"^SSID \d+\s*:\s?(.*?)\s*$", line)
        if m:
            ssid, security, cur = (m[1] or None), None, None
            continue
        k, v = _kv(line)
        if k is None:
            continue
        if k.startswith(("authentifizierung", "authentication", "authentification", "autenticazione")):
            security = v or None
        m = re.match(r"^bssid \d+$", k)
        if m:
            mac = re.search(_MAC, v, re.I)
            cur = {"bssid": mac[1].lower() if mac else None, "ssid": ssid, "security": security,
                   "signal_pct": None, "channel": None, "band": None}
            nets.append(cur)
            continue
        if cur is None:
            continue
        if k == "signal" and "%" in v:
            cur["signal_pct"] = int(_num(v))
        elif k == "band":
            cur["band"] = _band(v)
        elif k in ("kanal", "channel", "canal", "canale"):
            ch = _num(v)
            cur["channel"] = int(ch) if ch is not None else None
    result = []
    for n in nets:
        if not n["channel"]:
            continue
        n["band"] = n["band"] or ("2.4" if n["channel"] <= 14 else "5")
        n["freq"] = c.channel_to_freq(n["channel"], n["band"])
        n["signal"] = c.pct_to_dbm(n["signal_pct"]) if n["signal_pct"] is not None else None
        result.append(n)
    return result


# --- Ping ---------------------------------------------------------------------

def parse_ping(out, count):
    """Windows-ping: jede Antwortzeile enthält 'TTL='. Zeit steht als 'Zeit=12ms',
    'time=12ms' oder '<1ms' -> sprachunabhängig über '=/<' + 'ms'."""
    rtts = []
    for line in (out or "").splitlines():
        if "TTL=" not in line.upper():
            continue
        m = re.search(r"([=<])\s*(\d+)\s*ms", line, re.I)
        if m:
            v = float(m[2])
            rtts.append(v * 0.5 if m[1] == "<" else v)
    sent = count
    recv = len(rtts)
    r = {"sent": sent, "recv": recv, "loss": round(100 * (sent - recv) / sent, 1) if sent else 100.0,
         "rtt_min": None, "rtt_avg": None, "rtt_max": None, "jitter": None}
    if rtts:
        r.update(rtt_min=min(rtts), rtt_avg=round(statistics.fmean(rtts), 2), rtt_max=max(rtts),
                 jitter=round(statistics.pstdev(rtts), 2))
    return r


# --- Quelle -------------------------------------------------------------------

_ROUTE_PS = (
    "$r = Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue | "
    "Sort-Object { $_.RouteMetric + (Get-NetIPInterface -InterfaceIndex $_.ifIndex -AddressFamily IPv4).InterfaceMetric } | "
    "Select-Object -First 1; "
    "$w = Get-NetIPAddress -InterfaceAlias '{iface}' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1; "
    "@{{gateway=$r.NextHop; dev=$r.InterfaceAlias; wifi_ip=$w.IPAddress}} | ConvertTo-Json -Compress"
)


class WindowsSource:
    demo = False
    platform = "windows"

    def __init__(self, iface="auto"):
        self.hint = None
        ifaces = self._interfaces()
        if iface and iface != "auto":
            self.iface = iface
        else:
            self.iface = ifaces[0]["name"] if ifaces else None
        if not self.iface:
            log.warning("Kein WLAN-Adapter gefunden. %s", self.hint or "")
        self._route = (None, None, None)
        self._route_ts = 0

    def _interfaces(self):
        _, out = c.run(["netsh", "wlan", "show", "interfaces"])
        if _LOCATION_HINT.search(out) and "name" not in out.lower():
            self.hint = ("Windows blockiert den WLAN-Zugriff: Einstellungen -> Datenschutz -> Standort -> "
                         "'Apps den Zugriff auf Ihren Standort erlauben' einschalten.")
            log.warning(self.hint)
        return parse_interfaces(out)

    def _route_info(self):
        if time.time() - self._route_ts > 300:  # PowerShell ist langsam -> 5 Min cachen
            ps = _ROUTE_PS.replace("{iface}", (self.iface or "").replace("'", "''")).replace("{{", "{").replace("}}", "}")
            _, out = c.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], timeout=30)
            try:
                d = json.loads(out.strip() or "{}")
                ip = d.get("wifi_ip")
                if ip and ip.startswith("169.254."):  # Notfall-Adresse = WLAN ohne Verbindung
                    ip = None
                self._route = (d.get("gateway"), d.get("dev"), ip)
            except ValueError:
                self._route = (None, None, None)
            self._route_ts = time.time()
        return self._route

    def route(self):
        gw, dev, _ = self._route_info()
        return gw, dev

    def link(self):
        for i in self._interfaces():
            if i["name"] == self.iface:
                return link_from_interface(i)
        return {"connected": False}

    def _source_ip(self, bind):
        return self._route_info()[2] if bind else None

    def ping(self, host, count, bind):
        cmd = ["ping", "-n", str(count), "-w", "2000"]
        src = self._source_ip(bind)
        if src:
            cmd += ["-S", src]
        _, out = c.run(cmd + [host], timeout=count * 3 + 10)
        return parse_ping(out, count)

    def scan(self):
        _, out = c.run(["netsh", "wlan", "show", "networks", "mode=bssid"], timeout=30)
        return parse_networks(out)

    def speedtest(self, cfg, target, bind):
        return c.speedtest(cfg, lambda h, n: self.ping(h, n, bind), target, self._source_ip(bind))
