"""Simulierte Geräte für `wifimon.py --demo` bzw. WIFIMON_DEMO=1. Abends ist das Netz voller."""
import math
import random
import time

import collectors

_NEIGHBOURS = [
    ("Zuhause-5G", 5180, -54, "WPA2 WPA3"),
    ("Zuhause", 2437, -48, "WPA2 WPA3"),
    ("Nachbar_EG", 2412, -63, "WPA2"),
    ("Nachbar_EG-5G", 5240, -78, "WPA2"),
    ("HomeNet-4821", 2437, -71, "WPA2"),
    ("DIRECT-Drucker", 2462, -66, "WPA2"),
    ("Gast-WLAN", 2437, -80, "WPA2"),
    ("Oben-Mesh", 5500, -82, "WPA3"),
    ("TP-Wohnung3", 2462, -85, "WPA2"),
    (None, 5745, -88, "WPA2"),
]
_BASE_PING = {"Router": 2.5, "Cloudflare": 13.0, "Google": 16.0}


def _load(ts):
    """Abends zwischen 17 und 24 Uhr ist das Netz voller."""
    lt = time.localtime(ts)
    h = lt.tm_hour + lt.tm_min / 60
    return 1.0 + 0.9 * max(0.0, math.sin((h - 17) / 7 * math.pi)) if 17 <= h <= 24 else 1.0


class DemoSource:
    demo = True
    platform = "demo"
    iface = "wlan0"

    def __init__(self, base_signal=-55, ssid="Zuhause-5G", freq=5180, bssid="3c:a6:2f:11:22:33"):
        self.base_signal, self.ssid, self.freq, self.bssid = base_signal, ssid, freq, bssid

    def route(self):
        return "192.168.178.1", "wlan0"

    def link(self, ts=None):
        ts = ts or time.time()
        if random.random() < 0.003:
            return {"connected": False}
        sig = int(self.base_signal + 5 * math.sin(ts / 5400) + random.gauss(0, 1.5) - 4 * (_load(ts) - 1))
        ch, band = collectors.freq_to_channel(self.freq)
        top = 866.7 if band == "5" else 144.4
        rate = round(max(6.0, top + (sig - self.base_signal) * top / 30 + random.gauss(0, top / 30)), 1)
        return {"connected": True, "ssid": self.ssid, "bssid": self.bssid, "freq": self.freq,
                "channel": ch, "band": band, "signal": sig, "signal_pct": collectors.dbm_to_pct(sig),
                "rx_rate": rate, "tx_rate": round(rate * 0.9, 1)}

    def ping(self, host, count, bind, label=None, ts=None):
        ts = ts or time.time()
        load = _load(ts) * (1.3 if self.base_signal < -65 else 1.0)
        base = _BASE_PING.get(label) or (2.5 if host.startswith("192.168.") else
                                         13.0 if host == "1.1.1.1" else 16.0)
        lost = sum(random.random() < 0.003 * load ** 3 for _ in range(count))
        rtts = [base * load + abs(random.gauss(0, 1.2 * load)) +
                (random.random() < 0.05 * load) * random.uniform(10, 60)
                for _ in range(count - lost)]
        if not rtts:
            return {"sent": count, "recv": 0, "loss": 100.0, "rtt_min": None,
                    "rtt_avg": None, "rtt_max": None, "jitter": None}
        avg = sum(rtts) / len(rtts)
        mdev = math.sqrt(sum((r - avg) ** 2 for r in rtts) / len(rtts))
        return {"sent": count, "recv": len(rtts), "loss": round(100 * lost / count, 1),
                "rtt_min": round(min(rtts), 2), "rtt_avg": round(avg, 2),
                "rtt_max": round(max(rtts), 2), "jitter": round(mdev, 2)}

    def scan(self):
        nets = []
        offset = self.base_signal + 55
        for i, (ssid, freq, sig, sec) in enumerate(_NEIGHBOURS):
            s = int(sig + offset + random.gauss(0, 2))
            ch, band = collectors.freq_to_channel(freq)
            bssid = self.bssid if (ssid, freq) == (self.ssid, self.freq) else f"02:00:00:00:{i:02x}:01"
            nets.append({"bssid": bssid, "ssid": ssid, "freq": freq, "channel": ch, "band": band,
                         "signal": s, "signal_pct": collectors.dbm_to_pct(s), "security": sec})
        return nets

    def speedtest(self, cfg, target, bind, ts=None, sleep=True):
        ts = ts or time.time()
        if sleep:
            time.sleep(4)
        load = _load(ts)
        factor = 1.0 if self.freq > 5000 else 0.35
        idle = round(13 * load + random.uniform(0, 2), 1)
        return {"ts": int(ts), "down": round(random.uniform(240, 310) * factor / load, 1),
                "up": round(random.uniform(35, 45) * factor / load ** 0.5, 1), "idle_ping": idle,
                "loaded_ping": round(idle + random.uniform(8, 45) * load, 1),
                "mb_used": round(random.uniform(150, 200), 1), "error": None}

    def seed(self, db, device, hours=72):
        """Füllt Verlauf, damit das Dashboard sofort etwas zeigt (nur wenn noch leer)."""
        if db.one("SELECT 1 FROM link WHERE device = ? LIMIT 1", (device,)):
            return
        now = int(time.time())
        links, pings, speeds = [], [], []
        targets = [("192.168.178.1", "Router"), ("1.1.1.1", "Cloudflare"), ("8.8.8.8", "Google")]
        for ts in range(now - hours * 3600, now, 60):
            link = self.link(ts)
            link.update(device=device, ts=ts, connected=int(link["connected"]))
            links.append(link)
            for host, label in targets:
                pings.append({"device": device, "ts": ts, "target": host, "label": label,
                              **self.ping(host, 10, False, label=label, ts=ts)})
            if ts % 3600 < 60:
                speeds.append({**self.speedtest(None, None, False, ts=ts, sleep=False), "device": device})
        db.insert_many("link", links)
        db.insert_many("ping", pings)
        db.insert_many("speed", speeds)


def make_devices():
    return [
        ("Demo-PC", DemoSource()),
        ("Demo-Laptop-Kueche", DemoSource(base_signal=-69, ssid="Zuhause", freq=2437, bssid="3c:a6:2f:11:22:34")),
    ]
