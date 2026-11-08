"""SQLite-Speicher für WiFiMon. Eine Verbindung, durch ein Lock abgesichert."""
import os
import sqlite3
import threading
import time

MEASURE_TABLES = ("ping", "link", "speed", "scan")

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    device TEXT PRIMARY KEY, first_seen INTEGER, last_seen INTEGER, platform TEXT,
    iface TEXT, gateway TEXT, route_dev TEXT, busy INTEGER, agent_version TEXT,
    ping_interval_s INTEGER, hostname TEXT, public_ip TEXT, local_ips TEXT
);

CREATE TABLE IF NOT EXISTS ping (
    device TEXT NOT NULL, ts INTEGER NOT NULL, target TEXT, label TEXT, sent INTEGER, recv INTEGER,
    loss REAL, rtt_min REAL, rtt_avg REAL, rtt_max REAL, jitter REAL
);
CREATE INDEX IF NOT EXISTS ix_ping ON ping(device, ts);

CREATE TABLE IF NOT EXISTS link (
    device TEXT NOT NULL, ts INTEGER NOT NULL, connected INTEGER, ssid TEXT, bssid TEXT, freq INTEGER,
    channel INTEGER, band TEXT, signal INTEGER, signal_pct INTEGER, rx_rate REAL, tx_rate REAL
);
CREATE INDEX IF NOT EXISTS ix_link ON link(device, ts);

CREATE TABLE IF NOT EXISTS speed (
    device TEXT NOT NULL, ts INTEGER NOT NULL, down REAL, up REAL, idle_ping REAL, loaded_ping REAL,
    mb_used REAL, error TEXT
);
CREATE INDEX IF NOT EXISTS ix_speed ON speed(device, ts);

CREATE TABLE IF NOT EXISTS scan (
    device TEXT NOT NULL, ts INTEGER NOT NULL, bssid TEXT, ssid TEXT, freq INTEGER, channel INTEGER,
    band TEXT, signal INTEGER, signal_pct INTEGER, security TEXT
);
CREATE INDEX IF NOT EXISTS ix_scan ON scan(device, ts);

-- Geräte im Heimnetz, die ein Agent sieht (ARP/Nachbartabelle)
CREATE TABLE IF NOT EXISTS neighbors (
    device TEXT NOT NULL, ts INTEGER NOT NULL, ip TEXT, mac TEXT, family TEXT, state TEXT, iface TEXT
);
CREATE INDEX IF NOT EXISTS ix_neighbors ON neighbors(device);
CREATE TABLE IF NOT EXISTS banned_devices (device TEXT PRIMARY KEY, ts INTEGER);

-- Werbeblocker
CREATE TABLE IF NOT EXISTS dns_clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, token TEXT NOT NULL UNIQUE,
    created INTEGER, last_seen INTEGER, last_ip TEXT, queries INTEGER DEFAULT 0,
    blocked INTEGER DEFAULT 0, disabled INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS dns_log (
    ts INTEGER NOT NULL, client INTEGER, ip TEXT, qname TEXT, qtype TEXT, blocked INTEGER,
    reason TEXT, ms REAL
);
CREATE INDEX IF NOT EXISTS ix_dns_log ON dns_log(ts);
CREATE TABLE IF NOT EXISTS rules (kind TEXT NOT NULL, domain TEXT NOT NULL, ts INTEGER, PRIMARY KEY (kind, domain));
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);

-- Zugriff und Sicherheit
CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, created INTEGER, last_seen INTEGER, ip TEXT, ua TEXT);
CREATE TABLE IF NOT EXISTS seen (
    kind TEXT NOT NULL, ref TEXT NOT NULL, ip TEXT NOT NULL, first_seen INTEGER, last_seen INTEGER,
    hits INTEGER DEFAULT 0, PRIMARY KEY (kind, ref, ip)
);
CREATE TABLE IF NOT EXISTS events (ts INTEGER NOT NULL, kind TEXT, ip TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS ix_events ON events(ts);
CREATE TABLE IF NOT EXISTS bans (ip TEXT PRIMARY KEY, ts INTEGER, note TEXT, auto INTEGER DEFAULT 0);
"""

COLUMNS = {
    "devices": ("device", "first_seen", "last_seen", "platform", "iface", "gateway", "route_dev",
                "busy", "agent_version", "ping_interval_s", "hostname", "public_ip", "local_ips"),
    "ping": ("device", "ts", "target", "label", "sent", "recv", "loss", "rtt_min", "rtt_avg", "rtt_max", "jitter"),
    "link": ("device", "ts", "connected", "ssid", "bssid", "freq", "channel", "band", "signal", "signal_pct",
             "rx_rate", "tx_rate"),
    "speed": ("device", "ts", "down", "up", "idle_ping", "loaded_ping", "mb_used", "error"),
    "scan": ("device", "ts", "bssid", "ssid", "freq", "channel", "band", "signal", "signal_pct", "security"),
    "neighbors": ("device", "ts", "ip", "mac", "family", "state", "iface"),
    "dns_log": ("ts", "client", "ip", "qname", "qtype", "blocked", "reason", "ms"),
}
# Diese Werte schickt ein Agent nur ab und zu mit -> alten Wert behalten, wenn leer
_KEEP_IF_NULL = ("hostname", "public_ip", "local_ips")


class DB:
    def __init__(self, path):
        folder = os.path.dirname(path)
        if folder:
            os.makedirs(folder, exist_ok=True)
        self.path = path
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self.conn.executescript(SCHEMA)
            # ältere Datenbanken nachrüsten
            have = {r[1] for r in self.conn.execute("PRAGMA table_info(devices)")}
            for col in ("hostname", "public_ip", "local_ips"):
                if col not in have:
                    self.conn.execute(f"ALTER TABLE devices ADD COLUMN {col} TEXT")

    def insert_many(self, table, rows):
        if not rows:
            return
        cols = COLUMNS[table]  # feste Spaltenliste, Tabellenname nie aus Eingaben
        sql = f"INSERT INTO {table} ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})"
        values = [[r.get(c) for c in cols] for r in rows]
        with self.lock:
            self.conn.execute("BEGIN")
            try:
                self.conn.executemany(sql, values)
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise

    def insert(self, table, row):
        self.insert_many(table, [row])

    def upsert_device(self, info):
        cols = COLUMNS["devices"]
        updates = ",".join(
            f"{c}=COALESCE(excluded.{c}, devices.{c})" if c in _KEEP_IF_NULL else f"{c}=excluded.{c}"
            for c in cols if c not in ("device", "first_seen"))
        sql = (f"INSERT INTO devices ({','.join(cols)}) VALUES ({','.join('?' * len(cols))}) "
               f"ON CONFLICT(device) DO UPDATE SET {updates}")
        with self.lock:
            self.conn.execute(sql, [info.get(c) for c in cols])

    def replace_neighbors(self, device, ts, rows):
        with self.lock:
            self.conn.execute("BEGIN")
            try:
                self.conn.execute("DELETE FROM neighbors WHERE device = ?", (device,))
                cols = COLUMNS["neighbors"]
                self.conn.executemany(
                    f"INSERT INTO neighbors ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                    [[device, ts] + [r.get(c) for c in cols[2:]] for r in rows])
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise

    def touch_seen(self, items):
        """items: [(kind, ref, ip, ts, hits)] - merkt sich, welche IP wann zu wem gehörte."""
        if not items:
            return
        with self.lock:
            self.conn.executemany(
                """INSERT INTO seen (kind, ref, ip, first_seen, last_seen, hits) VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(kind, ref, ip) DO UPDATE SET last_seen = excluded.last_seen,
                   hits = seen.hits + excluded.hits""",
                [(k, r, ip, ts, ts, n) for k, r, ip, ts, n in items])

    def execute(self, sql, args=()):
        with self.lock:
            cur = self.conn.execute(sql, args)
            return cur.lastrowid if sql.lstrip().upper().startswith("INSERT") else cur.rowcount

    def executemany(self, sql, rows):
        with self.lock:
            self.conn.execute("BEGIN")
            try:
                self.conn.executemany(sql, rows)
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise

    def query(self, sql, args=()):
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, args)]

    def one(self, sql, args=()):
        rows = self.query(sql, args)
        return rows[0] if rows else None

    def cleanup(self, days, dns_days=7):
        now = int(time.time())
        with self.lock:
            for t in MEASURE_TABLES:
                self.conn.execute(f"DELETE FROM {t} WHERE ts < ?", (now - days * 86400,))
            self.conn.execute("DELETE FROM dns_log WHERE ts < ?", (now - dns_days * 86400,))
            self.conn.execute("DELETE FROM events WHERE ts < ?", (now - 90 * 86400,))
            self.conn.execute("DELETE FROM seen WHERE last_seen < ?", (now - 90 * 86400,))
