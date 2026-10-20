"""The Messenger: signing and the receiving-side verification."""

import messenger

KEY = b"unit-test-key"


def test_round_trip_verifies():
    message, sig = messenger.build_message("10.0.0.5", "PORT_SCAN_ENTROPY", ts=1000, key=KEY)
    assert sig in message
    result = messenger.verify_message(message, now=1010, key=KEY)
    assert result.ok and result.reason == "ok"
    assert (result.ip, result.detection_type, result.ts) == ("10.0.0.5", "PORT_SCAN_ENTROPY", 1000)


def test_signature_is_full_sha256_hmac():
    assert len(messenger.build_signature("1.2.3.4", "X", 1, key=KEY)) == 64


def test_tampered_fields_are_rejected():
    message, _ = messenger.build_message("10.0.0.5", "PORT_SCAN_ENTROPY", ts=1000, key=KEY)
    for forged in (message.replace("10.0.0.5", "10.0.0.6"),
                   message.replace("ENTROPY", "CARDINALITY"),
                   message.replace("TS:1000", "TS:1001")):
        result = messenger.verify_message(forged, now=1000, key=KEY)
        assert not result.ok and result.reason == "bad signature"


def test_wrong_key_is_rejected():
    message, _ = messenger.build_message("10.0.0.5", "PORT_SCAN_ENTROPY", ts=1000, key=KEY)
    assert not messenger.verify_message(message, now=1000, key=b"another-key").ok


def test_stale_and_future_alerts_are_rejected():
    message, _ = messenger.build_message("10.0.0.5", "PORT_SCAN_ENTROPY", ts=1000, key=KEY)
    assert messenger.verify_message(message, now=1060, max_age=60, key=KEY).ok
    assert messenger.verify_message(message, now=1061, max_age=60, key=KEY).reason.startswith("stale")
    assert messenger.verify_message(message, now=900, max_age=60, key=KEY).reason.startswith("stale")


def test_malformed_input_is_rejected_not_crashed():
    for junk in ("", "hello", "ALERT:1.2.3.4|TYPE:X|TS:abc|SIG:00", "ALERT:1.2.3.4|TYPE:X|TS:1"):
        assert messenger.verify_message(junk, key=KEY).reason == "malformed alert"


def test_whitespace_and_uppercase_hex_from_wireshark_are_tolerated():
    message, _ = messenger.build_message("10.0.0.5", "PORT_SCAN_ENTROPY", ts=1000, key=KEY)
    head, sig = message.rsplit("SIG:", 1)
    assert messenger.verify_message(f"  {head}SIG:{sig.upper()}\n", now=1000, key=KEY).ok


def test_send_failure_never_raises_and_still_returns_signature(monkeypatch, capsys):
    import scapy.all as scapy
    monkeypatch.setattr(scapy, "send", lambda *a, **k: (_ for _ in ()).throw(PermissionError("no raw sockets")))
    sig = messenger.send_icmp_alert("10.0.0.5", "PORT_SCAN_ENTROPY")
    assert len(sig) == 64
    assert "could not send" in capsys.readouterr().out
