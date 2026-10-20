"""The engine: Judge + Messenger + Active Defense + Persistence wired together."""

import pytest

import config
import watchdog_core
from db import Database
from watchdog_core import CARDINALITY, ENTROPY, Watchdog

ATTACKER = "203.0.113.7"      # TEST-NET-3, never routable
ME = "192.0.2.10"             # TEST-NET-1


class FakeBlocks:
    def __init__(self):
        self.calls = []

    def block(self, ip, now=None):
        self.calls.append(ip)
        return True


@pytest.fixture
def env(tmp_path):
    db = Database(tmp_path / "t.db")
    db.init()
    blocks = FakeBlocks()
    sent = []

    def notify(ip, detection_type):
        sent.append((ip, detection_type))
        return "sig-" + detection_type

    wd = Watchdog(db, blocks, notify, local_ips={ME})
    return wd, db, blocks, sent


def feed(wd, ip, ports, start=1000.0, step=0.1):
    fired = []
    for i, port in enumerate(ports):
        result = wd.handle_syn(ip, port, now=start + i * step)
        if result:
            fired.append(result)
    return fired


def test_loud_scan_alerts_once_blocks_and_logs(env):
    wd, db, blocks, sent = env
    fired = feed(wd, ATTACKER, range(1, 60))
    assert len(fired) == 1                                      # cooldown stops the repeat storm
    assert blocks.calls == [ATTACKER]
    (alert,) = db.recent_alerts()
    assert alert["source_ip"] == ATTACKER and alert["blocked"] == 1
    assert alert["signature"].startswith("sig-")
    assert sent == [(ATTACKER, fired[0])]


def test_KNOWN_BEHAVIOUR_fast_scan_is_reported_as_entropy_not_cardinality(env):
    """
    Pinned on purpose; see 'Known limitations' in the README. With the shipped thresholds
    (ENTROPY_MIN_SAMPLES=5, ENTROPY_THRESHOLD=0.85) five SYNs to five different ports already
    score H=1.0, so the entropy detector fires on SYN #5, long before the cardinality count
    can reach 16. The alert cooldown then suppresses cardinality for the rest of a short scan.
    If you retune the detectors so a loud scan reports as CARDINALITY, this test should change.
    """
    wd, db, *_ = env
    fired = feed(wd, ATTACKER, range(20, 101), step=0.025)       # nmap -sS -T4 -p 20-100
    assert fired == [ENTROPY]
    assert db.stats()["cardinality_hits"] == 0


def test_cardinality_fires_when_entropy_stays_low(env):
    """Where the Lab 6 tripwire still matters: many ports, but a heavily skewed distribution."""
    wd, db, *_ = env
    fired = feed(wd, ATTACKER, [80] * 100 + list(range(1000, 1015)), step=0.05)
    assert fired == [CARDINALITY]


def test_long_scan_gets_entropy_first_then_cardinality_after_the_cooldown(env):
    wd, *_ = env
    fired = feed(wd, ATTACKER, range(1, 1001), step=0.06)        # 60 s of probing
    assert fired == [ENTROPY, CARDINALITY]


def test_slow_scan_trips_entropy_not_cardinality(env):
    wd, db, blocks, _ = env
    ports = [20, 25, 80, 110, 143, 443, 3389, 8080]
    fired = feed(wd, ATTACKER, ports, step=2.0)
    assert fired == [ENTROPY]
    assert db.stats()["cardinality_hits"] == 0 and db.stats()["entropy_hits"] == 1


def test_self_scan_is_detected_and_logged_but_never_blocked(env):
    wd, db, blocks, sent = env
    fired = feed(wd, ME, [20, 25, 80, 110, 143, 443], step=2.0)
    assert fired == [ENTROPY]
    assert blocks.calls == []
    (alert,) = db.recent_alerts()
    assert alert["blocked"] == 0                                # dashboard shows LOGGED ONLY
    assert sent == [(ME, ENTROPY)]                              # the ICMP alert still goes out


def test_cooldown_expires(env):
    wd, db, *_ = env
    first = feed(wd, ATTACKER, range(1, 30), start=1000.0)
    assert len(first) == 1
    again_too_soon = feed(wd, ATTACKER, range(100, 130), start=1005.0)
    assert again_too_soon == []
    later = feed(wd, ATTACKER, range(200, 230), start=1000.0 + config.ALERT_COOLDOWN_SECONDS + 5)
    assert len(later) == 1
    assert db.stats()["total_alerts"] == 2


def test_normal_traffic_never_alerts(env):
    wd, db, blocks, sent = env
    assert feed(wd, "198.51.100.4", [443] * 200, step=0.05) == []
    assert sent == [] and blocks.calls == [] and db.stats()["total_alerts"] == 0


def test_entropy_samples_are_throttled_not_one_row_per_packet(env):
    """Original wrote a DB row (while holding the global lock) for every single SYN."""
    wd, db, *_ = env
    feed(wd, "198.51.100.4", [443] * 200, step=0.05)            # 10 s of traffic, 200 packets
    rows = db.entropy_since(0)
    assert 0 < len(rows) <= 11


def test_alarm_always_records_the_sample_that_crossed_the_threshold(env):
    wd, db, *_ = env
    feed(wd, ATTACKER, [20, 25, 80, 110, 143], step=0.01)       # fires inside the 1 s throttle gap
    assert max(r["entropy_value"] for r in db.entropy_since(0)) >= config.ENTROPY_THRESHOLD


def test_idle_ips_are_forgotten(env):
    wd, *_ = env
    for i in range(500):                                        # e.g. a decoy scan with spoofed sources
        wd.handle_syn(f"198.51.100.{i % 250}", 80, now=1000.0)
    assert len(wd._touches) > 0
    wd.housekeeping(now=1000.0 + 600)
    assert len(wd._touches) == 0 and not wd._last_entropy_log and not wd._last_alert


def test_sniff_callback_survives_an_internal_error(env, capsys):
    scapy = watchdog_core.scapy
    wd, *_ = env
    wd.handle_syn = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
    handler = watchdog_core.make_packet_handler(wd)
    pkt = scapy.IP(src=ATTACKER, dst=ME) / scapy.TCP(dport=80, flags="S")
    handler(pkt)                                                # must not raise
    assert "boom" in capsys.readouterr().err


@pytest.mark.parametrize("exc", [
    watchdog_core.Scapy_Exception("Cannot set filter: libpcap is not available"),   # no Npcap/libpcap
    PermissionError("Operation not permitted"),                                      # not Administrator
])
def test_main_explains_sniff_startup_failures_instead_of_a_traceback(tmp_path, monkeypatch, capsys, exc):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setattr(watchdog_core, "get_local_ips", lambda: set())
    monkeypatch.setattr(watchdog_core, "background_loop", lambda *a: None)

    def broken_sniff(**kwargs):
        raise exc
    monkeypatch.setattr(watchdog_core.scapy, "sniff", broken_sniff)

    assert watchdog_core.main(["--dry-run"]) == 1
    out = capsys.readouterr().out
    assert "Could not start sniffing" in out and "Administrator" in out


def test_main_ctrl_c_exits_cleanly(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setattr(watchdog_core, "get_local_ips", lambda: set())
    monkeypatch.setattr(watchdog_core, "background_loop", lambda *a: None)
    monkeypatch.setattr(watchdog_core.scapy, "sniff",
                        lambda **kw: (_ for _ in ()).throw(KeyboardInterrupt()))
    assert watchdog_core.main(["--dry-run"]) == 0
    assert "Watchdog stopped" in capsys.readouterr().out


def test_handler_only_accepts_bare_syn(env):
    scapy = watchdog_core.scapy
    wd, db, *_ = env
    seen = []
    wd.handle_syn = lambda ip, port, now=None: seen.append((ip, port))
    handler = watchdog_core.make_packet_handler(wd)
    for flags in ("S", "SA", "A", "R", "FA", "PA"):
        handler(scapy.IP(src=ATTACKER, dst=ME) / scapy.TCP(dport=80, flags=flags))
    handler(scapy.IP(src=ATTACKER, dst=ME) / scapy.UDP(dport=80))
    assert seen == [(ATTACKER, 80)]
