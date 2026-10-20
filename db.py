"""
Persistence: the SQLite threat ledger shared by the engine (writer) and the dashboard (reader).

Tables
------
alerts       one row per alarm fired (cardinality or entropy)
entropy_log  time series of normalized entropy per source IP (feeds the live chart)
blocks       one row per IP ever blocked; active=1 while the firewall rule is believed live
meta         small key/value store (currently just the engine heartbeat)

The schema is unchanged from the original build, so an existing watchdog.db keeps working.
"""

import sqlite3
import time
from contextlib import contextmanager

import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL, source_ip TEXT, detection_type TEXT,
    unique_ports INTEGER, entropy_value REAL,
    signature TEXT, blocked INTEGER
);
CREATE TABLE IF NOT EXISTS entropy_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL, source_ip TEXT, entropy_value REAL, unique_ports INTEGER
);
CREATE TABLE IF NOT EXISTS blocks (
    ip TEXT PRIMARY KEY, blocked_at REAL, expires_at REAL, active INTEGER
);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY, value REAL
);
CREATE INDEX IF NOT EXISTS idx_entropy_ts ON entropy_log(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
"""


class Database:
    def __init__(self, path=None):
        self.path = str(path or config.DB_PATH)

    @contextmanager
    def _conn(self):
        # Two processes (engine + dashboard) share this file, so wait for locks instead of
        # failing immediately with "database is locked".
        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _rows(self, sql, params=()):
        with self._conn() as conn:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]

    def init(self):
        with self._conn() as conn:
            # WAL lets the dashboard read while the engine writes without blocking either.
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(SCHEMA)

    # ------------------------------------------------------------------ writes
    def log_entropy(self, ip, entropy_value, unique_ports, ts=None):
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO entropy_log (ts, source_ip, entropy_value, unique_ports) VALUES (?,?,?,?)",
                (ts or time.time(), ip, entropy_value, unique_ports))

    def log_alert(self, ip, detection_type, unique_ports, entropy_value, signature, blocked, ts=None):
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO alerts (ts, source_ip, detection_type, unique_ports,
                                       entropy_value, signature, blocked) VALUES (?,?,?,?,?,?,?)""",
                (ts or time.time(), ip, detection_type, unique_ports, entropy_value,
                 signature, int(bool(blocked))))

    def log_block(self, ip, expires_at, ts=None):
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO blocks (ip, blocked_at, expires_at, active) VALUES (?,?,?,1)
                   ON CONFLICT(ip) DO UPDATE SET blocked_at=excluded.blocked_at,
                   expires_at=excluded.expires_at, active=1""",
                (ip, ts or time.time(), expires_at))

    def log_unblock(self, ip):
        with self._conn() as conn:
            conn.execute("UPDATE blocks SET active=0 WHERE ip=?", (ip,))

    def beat(self, ts=None):
        """Engine heartbeat so the dashboard can tell 'engine offline' from 'no alerts yet'."""
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO meta (key, value) VALUES ('engine_heartbeat', ?)
                   ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                (ts or time.time(),))

    # ------------------------------------------------------------------- reads
    def active_blocks(self):
        return self._rows("SELECT * FROM blocks WHERE active=1 ORDER BY blocked_at DESC")

    def recent_alerts(self, limit=50):
        return self._rows("SELECT * FROM alerts ORDER BY ts DESC LIMIT ?", (limit,))

    def entropy_since(self, since):
        return self._rows("SELECT * FROM entropy_log WHERE ts >= ? ORDER BY ts ASC", (since,))

    def stats(self):
        a = self._rows(
            """SELECT COUNT(*) AS total,
                      SUM(detection_type='PORT_SCAN_CARDINALITY') AS card,
                      SUM(detection_type='PORT_SCAN_ENTROPY') AS ent
               FROM alerts""")[0]
        blocks = self._rows("SELECT COUNT(*) AS c FROM blocks WHERE active=1")[0]["c"]
        return {
            "total_alerts": a["total"] or 0,
            "active_blocks": blocks,
            "cardinality_hits": a["card"] or 0,
            "entropy_hits": a["ent"] or 0,
        }

    def engine_last_seen(self):
        rows = self._rows("SELECT value FROM meta WHERE key='engine_heartbeat'")
        return rows[0]["value"] if rows else None
