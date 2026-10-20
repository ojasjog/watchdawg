"""
THE MESSENGER: HMAC-SHA256 authenticated ICMP Type-3 alert (Lab 7, hardened), plus the
receiving-side check that the hardening is meant to enable.

Wire format (the ICMP payload you see in Wireshark):

    ALERT:<ip>|TYPE:<detection_type>|TS:<unix_seconds>|SIG:<64 hex chars>

SIG = HMAC-SHA256(key, "<ip>|<detection_type>|<ts>"). Using the full digest (not a truncated
64-bit hash) and signing the timestamp lets a receiver reject forged alerts AND alerts that
are too old. Note this narrows the replay window to `max_age`; it does not eliminate replays
inside that window (that would need a nonce cache on the receiver).

Verify an alert copied out of Wireshark:

    python messenger.py verify "ALERT:10.0.0.5|TYPE:PORT_SCAN_ENTROPY|TS:1760000000|SIG:..."
"""

import argparse
import hashlib
import hmac
import re
import sys
import time
from dataclasses import dataclass
from typing import Optional

import config

_MESSAGE_RE = re.compile(
    r"^ALERT:(?P<ip>[^|]+)\|TYPE:(?P<type>[^|]+)\|TS:(?P<ts>\d+)\|SIG:(?P<sig>[0-9a-fA-F]{64})$")


def build_signature(ip, detection_type, ts, key=None):
    key = config.PRE_SHARED_KEY if key is None else key
    msg = f"{ip}|{detection_type}|{ts}".encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def build_message(ip, detection_type, ts=None, key=None):
    """Returns (wire_message, signature)."""
    ts = int(time.time()) if ts is None else int(ts)
    signature = build_signature(ip, detection_type, ts, key)
    return f"ALERT:{ip}|TYPE:{detection_type}|TS:{ts}|SIG:{signature}", signature


def send_icmp_alert(ip, detection_type, target=None):
    """
    Broadcast the signed alert. Always returns the signature, even if the packet could not
    be sent (e.g. not elevated): the alert is still recorded in the ledger either way, and a
    failure here must never take down the sniffer.
    """
    message, signature = build_message(ip, detection_type)
    target = target or config.ICMP_ALERT_TARGET
    try:
        import scapy.all as scapy   # imported lazily so verify/tests don't need Scapy
        packet = scapy.IP(dst=target) / scapy.ICMP(type=3, code=0) / scapy.Raw(load=message.encode())
        scapy.send(packet, verbose=False)
        print(f"--> [Messenger] {detection_type} | {ip} | SIG:{signature[:16]}...")
    except Exception as exc:   # noqa: BLE001 - deliberately broad, see docstring
        print(f"[!] Messenger could not send the ICMP alert ({exc}); it is still logged.")
    return signature


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    reason: str
    ip: Optional[str] = None
    detection_type: Optional[str] = None
    ts: Optional[int] = None


def verify_message(message, now=None, max_age=None, key=None):
    """Receiving-side check: well-formed, authentic (constant-time compare), and fresh."""
    max_age = config.ALERT_MAX_AGE_SECONDS if max_age is None else max_age
    now = time.time() if now is None else now

    match = _MESSAGE_RE.match(message.strip())
    if not match:
        return VerifyResult(False, "malformed alert")
    ip, detection_type = match["ip"], match["type"]
    ts, signature = int(match["ts"]), match["sig"].lower()

    expected = build_signature(ip, detection_type, ts, key)
    if not hmac.compare_digest(signature, expected):
        return VerifyResult(False, "bad signature", ip, detection_type, ts)

    age = now - ts
    if abs(age) > max_age:
        return VerifyResult(False, f"stale (age {age:.0f}s, limit {max_age}s)", ip, detection_type, ts)
    return VerifyResult(True, "ok", ip, detection_type, ts)


def _main(argv=None):
    parser = argparse.ArgumentParser(description="Watchdog alert tools")
    sub = parser.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="check an ALERT:... payload copied from Wireshark")
    v.add_argument("message")
    v.add_argument("--max-age", type=int, default=None,
                   help=f"freshness window in seconds (default {config.ALERT_MAX_AGE_SECONDS})")
    args = parser.parse_args(argv)

    result = verify_message(args.message, max_age=args.max_age)
    if result.ok:
        print(f"VALID: {result.detection_type} from {result.ip} at ts={result.ts}")
    else:
        print(f"INVALID: {result.reason}")
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(_main())
