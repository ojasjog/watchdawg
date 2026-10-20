"""Active Defense bookkeeping. Runs in dry-run, so no netsh and no admin rights needed."""

import pytest

import firewall
from db import Database
from firewall import BlockManager


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "t.db")
    database.init()
    return database


@pytest.fixture
def blocks(db):
    return BlockManager(db, lifetime=300, dry_run=True)


def test_block_records_expiry_and_is_idempotent(blocks, db):
    assert blocks.block("6.6.6.6", now=1000) is True
    assert blocks.block("6.6.6.6", now=1001) is True            # already blocked: no second rule
    (row,) = db.active_blocks()
    assert row["expires_at"] == 1300


def test_rule_expires(blocks, db):
    blocks.block("6.6.6.6", now=1000)
    blocks.sync(now=1299)
    assert blocks.is_blocked("6.6.6.6")
    blocks.sync(now=1300)
    assert not blocks.is_blocked("6.6.6.6")
    assert db.active_blocks() == []


def test_regression_dashboard_unblock_allows_reblock(blocks, db):
    """
    Bug in the original: 'Unblock now' only flipped the DB flag, the engine's in-memory
    blocked_ips kept the IP, and block_ip() returned early, so the IP could never be
    blocked again until its original expiry.
    """
    blocks.block("6.6.6.6", now=1000)
    db.log_unblock("6.6.6.6")                                   # what the dashboard does
    blocks.sync(now=1010)
    assert not blocks.is_blocked("6.6.6.6")

    assert blocks.block("6.6.6.6", now=1020) is True
    (row,) = db.active_blocks()
    assert row["blocked_at"] == 1020                            # a genuinely new block


def test_regression_restore_cleans_up_after_a_restart(db):
    """Original left stale 'active' rows (and live firewall rules) after the engine restarted."""
    db.log_block("1.1.1.1", expires_at=500, ts=100)             # expired while we were off
    db.log_block("2.2.2.2", expires_at=5000, ts=100)            # still has time left

    blocks = BlockManager(db, lifetime=300, dry_run=True)
    blocks.restore(now=1000)

    assert not blocks.is_blocked("1.1.1.1")
    assert blocks.is_blocked("2.2.2.2")
    assert [b["ip"] for b in db.active_blocks()] == ["2.2.2.2"]


def test_failed_firewall_call_is_not_recorded_as_a_block(db, monkeypatch):
    monkeypatch.setattr(firewall, "add_rule", lambda ip, dry_run=False: False)
    blocks = BlockManager(db, dry_run=True)
    assert blocks.block("6.6.6.6", now=1000) is False
    assert db.active_blocks() == []


def test_rules_reject_things_that_are_not_ip_addresses():
    for bad in ("not-an-ip", "1.2.3.4; rm -rf /", "", "1.2.3"):
        with pytest.raises(ValueError):
            firewall.add_rule(bad, dry_run=True)
        with pytest.raises(ValueError):
            firewall.delete_rule(bad, dry_run=True)
