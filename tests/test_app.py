"""Dashboard API."""

import time

import pytest

import app as app_module


@pytest.fixture
def client(tmp_path, monkeypatch):
    from db import Database
    db = Database(tmp_path / "t.db")
    db.init()
    monkeypatch.setattr(app_module, "db", db)
    app_module.app.config["TESTING"] = True
    return app_module.app.test_client(), db


def test_dashboard_page_renders(client):
    c, _ = client
    r = c.get("/")
    assert r.status_code == 200 and b"Threat Ledger" in r.data


def test_api_reflects_database(client):
    c, db = client
    db.log_alert("1.1.1.1", "PORT_SCAN_ENTROPY", 6, 0.97, "abc", True)
    db.log_block("1.1.1.1", expires_at=time.time() + 100)
    db.log_entropy("1.1.1.1", 0.97, 6)
    assert c.get("/api/stats").get_json()["entropy_hits"] == 1
    assert c.get("/api/alerts").get_json()[0]["source_ip"] == "1.1.1.1"
    assert c.get("/api/blocks").get_json()[0]["ip"] == "1.1.1.1"
    assert len(c.get("/api/entropy").get_json()) == 1


def test_stats_expose_engine_heartbeat(client):
    c, db = client
    assert c.get("/api/stats").get_json()["engine_last_seen"] is None
    db.beat()
    assert c.get("/api/stats").get_json()["engine_last_seen"] is not None


def test_unblock_marks_block_inactive(client):
    c, db = client
    db.log_block("1.1.1.1", expires_at=time.time() + 100)
    r = c.post("/api/unblock", json={"ip": "1.1.1.1"})
    assert r.status_code == 200 and r.get_json() == {"ok": True}
    assert db.active_blocks() == []


@pytest.mark.parametrize("payload", [{}, {"ip": ""}, {"ip": "nope"}, {"ip": "1.1.1.1 & calc"}, {"ip": None}])
def test_unblock_rejects_bad_input(client, payload):
    c, _ = client
    assert c.post("/api/unblock", json=payload).status_code == 400


def test_unblock_requires_json_so_cross_site_forms_cannot_trigger_it(client):
    c, db = client
    db.log_block("1.1.1.1", expires_at=time.time() + 100)
    r = c.post("/api/unblock", data={"ip": "1.1.1.1"})          # form-encoded, as a hostile page would send
    assert r.status_code == 400
    assert len(db.active_blocks()) == 1
