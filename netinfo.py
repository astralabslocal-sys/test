"""Netzwerk-Übersicht für den Agent: eigene IPv4/IPv6-Adressen und die Geräte im Heimnetz.

Die Heimnetz-Geräte stammen aus der Nachbartabelle des Betriebssystems (ARP bzw. NDP).
Damit auch stille Geräte darin auftauchen, schickt der Agent vorher je ein winziges
UDP-Paket an jede Adresse im eigenen /24-Netz. Das löst nur eine ARP-Anfrage aus.
"""
import ipaddress
import json
import logging
import re
import socket
import sys
import time

import collectors as c

log = logging.getLogger("wifimon.netinfo")
WINDOWS = sys.platform == "win32"
_MAC = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")

_ADDR_PS = (
    "Get-NetIPAddress -ErrorAction SilentlyContinue | "
    "Where-Object { $_.AddressState -eq 'Preferred' } | "
    "Select-Object InterfaceAlias, AddressFamily, IPAddress, PrefixLength | ConvertTo-Json -Compress"
)
_NEIGH_PS = (
    "Get-NetNeighbor -ErrorAction SilentlyContinue | "
    "Where-Object { $_.State -in 'Reachable','Stale','Delay','Probe' } | "
    "Select-Object InterfaceAlias, AddressFamily, IPAddress, LinkLayerAddress, "
    "@{n='State';e={[string]$_.State}} | ConvertTo-Json -Compress"
)


def _ps_json(script):
    _, out = c.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], timeout=40)
    try:
        data = json.loads(out.strip() or "[]")
    except ValueError:
        return []
    return data if isinstance(data, list) else [data]


def _family(v):
    # Windows liefert 2/23 oder 'IPv4'/'IPv6', Linux 'inet'/'inet6'
    return "IPv6" if str(v) in ("23", "IPv6", "inet6") else "IPv4"


def _useful(ip):
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return None
    if a.is_loopback or a.is_multicast or a.is_unspecified or str(a) == "255.255.255.255":
        return None
    if a.version == 4 and str(a).startswith("169.254."):
        return None
    return a


def _mac(v):
    m = (v or "").lower().replace("-", ":")
    return m if _MAC.match(m) and m not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") \
        and not m.startswith(("01:00:5e", "33:33")) else None


def addresses():
    """Eigene Adressen -> [{iface, family, ip, prefix, scope}]"""
    out = []
    if WINDOWS:
        rows = [(r.get("InterfaceAlias"), r.get("AddressFamily"), r.get("IPAddress"), r.get("PrefixLength"))
                for r in _ps_json(_ADDR_PS)]
    else:
        _, raw = c.run(["ip", "-j", "addr"])
        try:
            data = json.loads(raw or "[]")
        except ValueError:
            data = []
        rows = [(i.get("ifname"), a.get("family"), a.get("local"), a.get("prefixlen"))
                for i in data for a in i.get("addr_info", [])]
    for iface, fam, ip, prefix in rows:
        a = _useful(str(ip or ""))
        if not a:
            continue
        scope = ("lokal" if a.is_link_local else "privat" if a.is_private else "öffentlich")
        out.append({"iface": str(iface or "")[:40], "family": _family(fam), "ip": str(a),
                    "prefix": prefix if isinstance(prefix, int) else None, "scope": scope})
    return out[:50]


def _wake_subnet(addrs):
    """Schickt je ein UDP-Paket an alle Adressen der eigenen /24-Netze (Port 9 = discard)."""
    nets = set()
    for a in addrs:
        if a["family"] == "IPv4" and a["scope"] == "privat" and a["prefix"] and a["prefix"] >= 22:
            nets.add(ipaddress.ip_network(f"{a['ip']}/24", strict=False))
    for net in list(nets)[:3]:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            for host in net.hosts():
                try:
                    s.sendto(b"", (str(host), 9))
                except OSError:
                    pass
    if nets:
        time.sleep(3)


def neighbors(addrs=None, wake=True):
    """Geräte im Heimnetz -> [{ip, mac, family, state, iface}]"""
    if wake:
        try:
            _wake_subnet(addrs if addrs is not None else addresses())
        except OSError as e:
            log.debug("Heimnetz-Weckruf fehlgeschlagen: %s", e)
    out, seen = [], set()
    if WINDOWS:
        rows = [(r.get("IPAddress"), r.get("LinkLayerAddress"), r.get("AddressFamily"),
                 r.get("State"), r.get("InterfaceAlias")) for r in _ps_json(_NEIGH_PS)]
    else:
        _, raw = c.run(["ip", "-j", "neigh"])
        try:
            data = json.loads(raw or "[]")
        except ValueError:
            data = []
        rows = [(n.get("dst"), n.get("lladdr"), "inet6" if ":" in str(n.get("dst")) else "inet",
                 ",".join(n.get("state") or []), n.get("dev")) for n in data]
    for ip, mac, fam, state, iface in rows:
        a = _useful(str(ip or ""))
        m = _mac(mac)
        if not a or not m or (str(a), m) in seen:
            continue
        seen.add((str(a), m))
        out.append({"ip": str(a), "mac": m, "family": _family(fam), "state": str(state or "")[:20],
                    "iface": str(iface or "")[:40]})
    return out[:512]


def snapshot():
    addrs = addresses()
    return {"hostname": socket.gethostname()[:63], "addrs": addrs, "neighbors": neighbors(addrs)}
