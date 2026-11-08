"""Anmeldung fürs Dashboard: Passwort -> Sitzungs-Cookie, Schutz gegen Durchprobieren,
Sperrliste für IP-Adressen (IPv4 und IPv6). Jede Sitzung lässt sich einzeln rauswerfen."""
import hashlib
import hmac
import ipaddress
import secrets
import threading
import time

SESSION_DAYS = 30
FAIL_WINDOW = 900    # 15 Minuten
FAIL_LIMIT = 5       # Fehlversuche pro IP (IPv6: pro /64-Netz) in 15 Min
GLOBAL_LIMIT = 30    # Fehlversuche insgesamt in 15 Min -> Anmeldung für alle kurz zu
AUTO_BAN = 15        # Fehlversuche einer IP in 24 Std -> IP wird dauerhaft gesperrt


def normalize_ip(raw):
    try:
        a = ipaddress.ip_address((raw or "").strip().strip("[]"))
    except ValueError:
        return None
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return str(a)


def ip_family(ip):
    return "IPv6" if ip and ":" in ip else "IPv4"


def _ip_key(ip):
    """IPv6-Anschlüsse haben viele Adressen -> Fehlversuche pro /64 zählen."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    return str(ipaddress.ip_network(f"{a}/64", strict=False)) if a.version == 6 else str(a)


def _hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


class Auth:
    def __init__(self, db, password):
        self.db, self.password = db, password or ""
        self.lock = threading.Lock()
        self.fails, self.global_fails = {}, []
        self._touched = {}
        self._bans = []
        self.load_bans()

    @property
    def enabled(self):
        return bool(self.password)

    def event(self, kind, ip, detail=""):
        self.db.execute("INSERT INTO events (ts, kind, ip, detail) VALUES (?, ?, ?, ?)",
                        (int(time.time()), kind, ip, str(detail)[:200]))

    # --- Sperrliste ---------------------------------------------------------------
    def load_bans(self):
        nets = []
        for r in self.db.query("SELECT ip FROM bans"):
            try:
                nets.append(ipaddress.ip_network(r["ip"], strict=False))
            except ValueError:
                pass
        self._bans = nets

    def is_banned(self, ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a.version == n.version and a in n for n in self._bans)

    def ban(self, target, note="", by_ip=None, auto=False):
        try:
            net = ipaddress.ip_network((target or "").strip(), strict=False)
        except ValueError:
            raise ValueError("Bitte eine IPv4- oder IPv6-Adresse (oder einen Bereich wie 1.2.3.0/24) angeben.") from None
        if (net.version == 4 and net.prefixlen < 16) or (net.version == 6 and net.prefixlen < 48):
            raise ValueError("Der Bereich ist zu groß.")
        if by_ip:
            me = ipaddress.ip_address(by_ip)
            if me.version == net.version and me in net:
                raise ValueError("Das ist deine eigene IP - du würdest dich selbst aussperren.")
        key = str(net.network_address) if net.num_addresses == 1 else str(net)
        self.db.execute("INSERT OR REPLACE INTO bans (ip, ts, note, auto) VALUES (?, ?, ?, ?)",
                        (key, int(time.time()), (note or "")[:100], int(auto)))
        self.load_bans()
        kicked = 0
        for s in self.db.query("SELECT id, ip FROM sessions"):
            if s["ip"] and self.is_banned(s["ip"]):
                kicked += self.db.execute("DELETE FROM sessions WHERE id = ?", (s["id"],))
        self.event("ban", by_ip, f"{key} gesperrt" + (f" ({note})" if note else "") +
                   (f", {kicked} Sitzung(en) beendet" if kicked else ""))
        return key

    def unban(self, target, by_ip=None):
        n = self.db.execute("DELETE FROM bans WHERE ip = ?", ((target or "").strip(),))
        if not n:
            raise ValueError("Diese Sperre gibt es nicht.")
        self.load_bans()
        self.event("unban", by_ip, f"{target} entsperrt")

    def bans(self):
        return self.db.query("SELECT * FROM bans ORDER BY ts DESC")

    # --- Anmeldung -----------------------------------------------------------------
    def login(self, password, ip, ua=""):
        """-> (sitzungs_token, None) oder (None, fehlermeldung)"""
        now = time.time()
        key = _ip_key(ip)
        with self.lock:
            mine = [t for t in self.fails.get(key, []) if now - t < FAIL_WINDOW]
            self.fails[key] = mine
            self.global_fails = [t for t in self.global_fails if now - t < FAIL_WINDOW]
            if len(mine) >= FAIL_LIMIT:
                wait = int((FAIL_WINDOW - (now - mine[0])) // 60) + 1
                return None, f"Zu viele Fehlversuche. Bitte {wait} Min warten."
            if len(self.global_fails) >= GLOBAL_LIMIT:
                return None, "Zu viele Fehlversuche insgesamt - die Anmeldung ist für 15 Min gesperrt."
        if not self.password or not hmac.compare_digest(str(password).encode(), self.password.encode()):
            with self.lock:
                mine.append(now)
                self.global_fails.append(now)
            self.event("login_fail", ip, ua[:120])
            n = self.db.one("SELECT COUNT(*) AS n FROM events WHERE kind = 'login_fail' AND ip = ? AND ts >= ?",
                            (ip, int(now) - 86400))["n"]
            if n >= AUTO_BAN:
                try:
                    self.ban(ip, "automatisch: zu viele Fehlversuche", auto=True)
                except ValueError:
                    pass
            time.sleep(1)  # bremst automatisches Durchprobieren
            return None, "Falsches Passwort."
        with self.lock:
            self.fails.pop(key, None)
        token = secrets.token_urlsafe(32)
        h = _hash(token)
        self.db.execute("INSERT INTO sessions (id, created, last_seen, ip, ua) VALUES (?, ?, ?, ?, ?)",
                        (h, int(now), int(now), ip, (ua or "")[:200]))
        self.db.touch_seen([("browser", h[:16], ip, int(now), 1)])
        self.event("login", ip, (ua or "")[:120])
        return token, None

    def session(self, token, ip):
        if not token:
            return None
        h = _hash(token)
        row = self.db.one("SELECT * FROM sessions WHERE id = ?", (h,))
        if not row:
            return None
        now = int(time.time())
        if now - (row["last_seen"] or 0) > SESSION_DAYS * 86400:
            self.db.execute("DELETE FROM sessions WHERE id = ?", (h,))
            return None
        if now - self._touched.get(h, 0) > 60 or row["ip"] != ip:
            self.db.execute("UPDATE sessions SET last_seen = ?, ip = ? WHERE id = ?", (now, ip, h))
            self.db.touch_seen([("browser", h[:16], ip, now, 1)])
            self._touched[h] = now
            if row["ip"] != ip:
                self.event("ip_change", ip, f"Sitzung {h[:6]}: {row['ip']} -> {ip}")
        row.update(pid=h[:16], ip=ip)
        del row["id"]
        return row

    def logout(self, token, ip=None):
        if token:
            self.db.execute("DELETE FROM sessions WHERE id = ?", (_hash(token),))
            self.event("logout", ip)

    def kick(self, pid, by_ip=None):
        n = self.db.execute("DELETE FROM sessions WHERE substr(id, 1, 16) = ?", (str(pid)[:16],))
        if not n:
            raise ValueError("Diese Sitzung gibt es nicht (mehr).")
        self.event("kick", by_ip, f"Sitzung {str(pid)[:6]} rausgeworfen")

    def kick_others(self, keep_pid, by_ip=None):
        n = self.db.execute("DELETE FROM sessions WHERE substr(id, 1, 16) != ?", (str(keep_pid)[:16],))
        self.event("kick", by_ip, f"{n} andere Sitzung(en) rausgeworfen")
        return n

    def sessions(self):
        rows = self.db.query("SELECT * FROM sessions ORDER BY last_seen DESC")
        for r in rows:
            r["pid"] = r.pop("id")[:16]
            r["family"] = ip_family(r["ip"])
        return rows

    def events(self, limit=150):
        return self.db.query("SELECT * FROM events ORDER BY ts DESC, rowid DESC LIMIT ?", (int(limit),))

    def cleanup(self):
        self.db.execute("DELETE FROM sessions WHERE last_seen < ?", (int(time.time()) - SESSION_DAYS * 86400,))
