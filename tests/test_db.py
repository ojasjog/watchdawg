"""Persistence layer."""

import pytest

from db import Database


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "t.db")
    database.init()
    return database


def test_init_is_idempotent(db):
    db.init()
    db.init()
    assert db.stats()["total_alerts"] == 0


def test_stats_count_by_detection_type(db):
    db.log_alert("1.1.1.1", "PORT_SCAN_CARDINALITY", 20, 0.9, "s", True)
    db.log_alert("1.1.1.1", "PORT_SCAN_ENTROPY", 6, 1.0, "s", False)
    db.log_alert("2.2.2.2", "PORT_SCAN_ENTROPY", 7, 0.95, "s", True)
    assert db.stats() == {"total_alerts": 3, "active_blocks": 0,
                          "cardinality_hits": 1, "entropy_hits": 2}


def test_block_upsert_and_unblock(db):
    db.log_block("9.9.9.9", expires_at=2000, ts=1000)
    assert [b["ip"] for b in db.active_blocks()] == ["9.9.9.9"]
    db.log_block("9.9.9.9", expires_at=3000, ts=2500)           # re-block same IP: one row, refreshed
    (row,) = db.active_blocks()
    assert (row["blocked_at"], row["expires_at"]) == (2500, 3000)
    db.log_unblock("9.9.9.9")
    assert db.active_blocks() == []


def test_entropy_since_filters_and_orders(db):
    for ts in (100, 300, 200):
        db.log_entropy("1.1.1.1", 0.5, 3, ts=ts)
    assert [r["ts"] for r in db.entropy_since(150)] == [200, 300]


def test_heartbeat(db):
    assert db.engine_last_seen() is None
    db.beat(ts=1234.0)
    db.beat(ts=1240.0)
    assert db.engine_last_seen() == 1240.0


def test_opens_a_database_created_by_the_original_build(tmp_path):
    """The schema is unchanged, so an existing watchdog.db must keep working."""
    import sqlite3
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, source_ip TEXT,
            detection_type TEXT, unique_ports INTEGER, entropy_value REAL, signature TEXT, blocked INTEGER);
        CREATE TABLE entropy_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, source_ip TEXT,
            entropy_value REAL, unique_ports INTEGER);
        CREATE TABLE blocks (ip TEXT PRIMARY KEY, blocked_at REAL, expires_at REAL, active INTEGER);
        INSERT INTO alerts (ts, source_ip, detection_type, unique_ports, entropy_value, signature, blocked)
            VALUES (1, '5.5.5.5', 'PORT_SCAN_ENTROPY', 6, 0.97, 'abc', 0);
    """)
    conn.commit()
    conn.close()

    db = Database(path)
    db.init()
    assert db.stats()["entropy_hits"] == 1
    db.beat()
    assert db.engine_last_seen() is not None
