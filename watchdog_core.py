"""
Intelligent Network Watchdog: Final IDPS Core Engine
Unifies Lab 6 (Watcher), Lab 7 (Messenger + Active Defense), Lab 8 (Judge upgrade)
and the final Data Persistence addition into one running system.

Components (one module each)
----------------------------
The Watcher    : watchdog_core.py  Layer-4 TCP packet interception (Scapy, promiscuous sniff)
The Judge      : detectors.py      TWO complementary detectors feeding one decision:
                                     (a) port-cardinality tripwire (Lab 6)
                                     (b) Shannon-entropy stealth model (Lab 8)
The Messenger  : messenger.py      HMAC-SHA256 authenticated ICMP Type-3 alert broadcast
Active Defense : firewall.py       self-expiring Windows Firewall block via netsh
Persistence    : db.py             SQLite threat ledger, read by app.py / the dashboard
Configuration  : config.py         every threshold in one place

Run this in an elevated ("Run as Administrator") terminal: raw packet sniffing and
netsh firewall commands both require it on Windows.

    python watchdog_core.py             # normal
    python watchdog_core.py --dry-run   # detect/log/alert, but never touch the firewall
    python watchdog_core.py --iface "Wi-Fi"
"""

import argparse
import socket
import threading
import time
import traceback
from collections import defaultdict, deque

import scapy.all as scapy
from scapy.error import Scapy_Exception

import config
import detectors
import messenger
from db import Database
from firewall import BlockManager

CARDINALITY = "PORT_SCAN_CARDINALITY"
ENTROPY = "PORT_SCAN_ENTROPY"

# "tcp[13] == 2" is a BPF filter: byte 13 of the TCP header is the flags byte, and 2
# (binary 00000010) is SYN-only, no ACK/FIN/RST/etc. This pushes the SYN-vs-everything-else
# filtering down into libpcap instead of Python, so ordinary traffic never even reaches us.
BPF_FILTER = "tcp and tcp[13] == 2"


# ---------------------------------------------------------------------------
# SELF-IP WHITELIST
# ---------------------------------------------------------------------------
# A machine self-testing with nmap (or running its own retries/loopback traffic) looks
# identical to a real remote attacker to the Judge, and Active Defense would happily
# firewall-block your own IP. We still DETECT and LOG self-scans (useful evidence for the
# report: it proves the detectors work); we just don't let Active Defense act on them.
#
# Windows machines commonly have several IPs at once (Wi-Fi, Ethernet, a VPN/virtual
# adapter...), so this gathers all of them rather than assuming one, plus loopback.
def get_local_ips():
    ips = {"127.0.0.1"}

    # Method 1: everything the hostname resolves to
    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            ips.add(ip)
    except Exception:
        pass

    # Method 2: the IP the OS would actually use to reach the internet
    # (sends nothing, just asks the OS to pick a route)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass

    # Method 3: ask Scapy/Npcap for every interface's address, so a secondary adapter it
    # picks up for sniffing is covered even if the methods above missed it
    try:
        for iface in scapy.get_if_list():
            try:
                addr = scapy.get_if_addr(iface)
                if addr and addr != "0.0.0.0":
                    ips.add(addr)
            except Exception:
                pass
    except Exception:
        pass

    return ips


# ---------------------------------------------------------------------------
# THE ENGINE: per-IP state + the decision. No Scapy objects in here, so tests can drive
# it with plain (ip, port, time) tuples.
# ---------------------------------------------------------------------------
class Watchdog:
    def __init__(self, db, blocks, notify, local_ips=(), clock=time.time):
        self.db = db
        self.blocks = blocks
        self.notify = notify          # (ip, detection_type) -> signature
        self.local_ips = set(local_ips)
        self.clock = clock

        self._touches = defaultdict(deque)   # ip -> deque of (timestamp, dest_port)
        self._last_alert = {}                # ip -> when we last actually fired
        self._last_entropy_log = {}          # ip -> when we last wrote an entropy sample
        self._lock = threading.Lock()
        self._horizon = max(config.CARDINALITY_WINDOW_SECONDS, config.ENTROPY_WINDOW_SECONDS)

    def handle_syn(self, source_ip, dest_port, now=None):
        """Record one SYN. Returns the detection type fired, or None."""
        now = self.clock() if now is None else now

        # Decide under the lock; do all I/O (DB, ICMP, netsh) after releasing it, so a slow
        # disk or netsh call never stalls packet intake.
        with self._lock:
            touches = self._touches[source_ip]
            touches.append((now, dest_port))
            while touches and touches[0][0] < now - self._horizon:
                touches.popleft()

            verdict = detectors.evaluate(touches, now)

            # Suppress repeat alarms for an IP that's still mid-scan and retransmitting;
            # without this, a burst of SYN retries refills the window and re-triggers the
            # same alarm dozens of times a second.
            cooling_down = (now - self._last_alert.get(source_ip, 0)) < config.ALERT_COOLDOWN_SECONDS

            fired = None
            if not cooling_down:
                if verdict.card_alarm:
                    fired = (CARDINALITY, verdict.card_unique)
                elif verdict.entropy_alarm:
                    fired = (ENTROPY, verdict.ent_unique)

            log_sample = verdict.entropy_computed and (
                fired is not None
                or now - self._last_entropy_log.get(source_ip, 0) >= config.ENTROPY_LOG_INTERVAL_SECONDS)
            if log_sample:
                self._last_entropy_log[source_ip] = now

            if fired:
                touches.clear()
                self._last_alert[source_ip] = now

        if log_sample:
            self.db.log_entropy(source_ip, verdict.entropy, verdict.ent_unique, ts=now)
        if fired:
            self._fire(source_ip, fired[0], fired[1], verdict.entropy, now)
            return fired[0]
        return None

    def _fire(self, ip, detection_type, unique_ports, entropy_value, now):
        is_self = ip in self.local_ips
        tag = " [SELF-SCAN, not blocking]" if is_self else ""
        if detection_type == CARDINALITY:
            print(f"\n[ALARM] CARDINALITY | {ip} touched {unique_ports} unique ports.{tag}")
        else:
            print(f"\n[ALARM] ENTROPY | {ip} normalized H={entropy_value:.3f} "
                  f"over {unique_ports} ports (stealth scan pattern).{tag}")

        signature = self.notify(ip, detection_type)
        blocked = False if is_self else self.blocks.block(ip, now)
        self.db.log_alert(ip, detection_type, unique_ports, entropy_value, signature, blocked, ts=now)

    def housekeeping(self, now=None):
        """Forget IPs that have gone quiet so state can't grow without bound
        (a scan with spoofed/decoy sources would otherwise leak one deque per fake IP)."""
        now = self.clock() if now is None else now
        with self._lock:
            for ip in list(self._touches):
                touches = self._touches[ip]
                while touches and touches[0][0] < now - self._horizon:
                    touches.popleft()
                if not touches:
                    del self._touches[ip]
            stale_after = max(config.ALERT_COOLDOWN_SECONDS, config.ENTROPY_LOG_INTERVAL_SECONDS)
            for table in (self._last_alert, self._last_entropy_log):
                for ip in [i for i, t in table.items() if now - t > stale_after]:
                    del table[ip]


# ---------------------------------------------------------------------------
# THE WATCHER: packet interception, Lab 6
# ---------------------------------------------------------------------------
def make_packet_handler(watchdog):
    def process_packet(packet):
        if not (packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP)):
            return
        tcp = packet[scapy.TCP]
        # Defensive second check even though the BPF filter already restricts us to bare SYN
        # packets: only a connection ATTEMPT (SYN, no ACK) is scan-shaped. A SYN-ACK or plain
        # ACK is normal reply traffic from a server you legitimately talked to, on a random
        # ephemeral port; letting those through flooded the Judge with false "scans".
        if int(tcp.flags) != 0x02:
            return
        try:
            watchdog.handle_syn(packet[scapy.IP].src, int(tcp.dport))
        except Exception:
            # One bad packet or a transient DB error must not kill the sniffer.
            traceback.print_exc()
    return process_packet


def background_loop(watchdog, blocks, db):
    """Expire rules, pick up dashboard unblocks, prune idle state, publish a heartbeat."""
    while True:
        try:
            watchdog.housekeeping()
            blocks.sync()
            db.beat()
        except Exception:
            traceback.print_exc()
        time.sleep(config.HOUSEKEEPING_INTERVAL_SECONDS)


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Intelligent Network Watchdog: detection engine")
    parser.add_argument("--dry-run", action="store_true",
                        help="detect, log and alert, but never touch the firewall")
    parser.add_argument("--iface", default=None,
                        help="interface to sniff (default: Scapy's default route interface)")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    db = Database(config.DB_PATH)
    db.init()
    blocks = BlockManager(db, dry_run=args.dry_run)
    local_ips = get_local_ips()
    watchdog = Watchdog(db, blocks, messenger.send_icmp_alert, local_ips)
    blocks.restore()
    threading.Thread(target=background_loop, args=(watchdog, blocks, db), daemon=True).start()

    print("Watchdog IDPS (Labs 6+7+8) is awake.")
    print(f"  Cardinality tripwire : >{config.CARDINALITY_THRESHOLD} ports / "
          f"{config.CARDINALITY_WINDOW_SECONDS}s window")
    print(f"  Entropy stealth model: normalized H >= {config.ENTROPY_THRESHOLD} / "
          f"{config.ENTROPY_WINDOW_SECONDS}s window")
    print(f"  Self-IP whitelist    : {sorted(local_ips)}")
    print("    (these IPs will still trigger alerts/logging if they scan, but Active")
    print("     Defense will NOT firewall-block them; self-tests won't self-lock you out)")
    if blocks.dry_run:
        print("  Active Defense       : DRY-RUN (no firewall changes will be made)")
    else:
        print(f"  Active Defense       : Windows Firewall via netsh, rules expire after "
              f"{config.FIREWALL_RULE_LIFETIME_SECONDS}s")
    if config.PSK_IS_DEFAULT:
        print("  Alert signing key    : DEFAULT lab key (set WATCHDOG_PSK to use your own)")
    print(f"  Database             : {config.DB_PATH}")
    print("Tracking bare-SYN TCP traffic (scan-shaped connection attempts only).")
    print("Start app.py in a second terminal to view the dashboard.\n")

    try:
        scapy.sniff(iface=args.iface, filter=BPF_FILTER,
                    prn=make_packet_handler(watchdog), store=False)
    except KeyboardInterrupt:
        print("\nWatchdog stopped. Active blocks stay in place until they expire; "
              "restarting the engine picks them back up.")
    except (OSError, Scapy_Exception) as exc:
        # Not elevated, Npcap/libpcap missing, or a bad --iface all land here.
        print(f"\n[!] Could not start sniffing: {exc}")
        print("    Run this terminal as Administrator, make sure Npcap is installed, and check --iface.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
