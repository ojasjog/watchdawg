"""
Intelligent Network Watchdog — Final IDPS Core Engine
Unifies Lab 6 (Watcher), Lab 7 (Messenger + Active Defense), Lab 8 (Judge upgrade)
and the final Data Persistence addition into one running system.

Components
----------
The Watcher    : Layer-4 TCP packet interception (Scapy, promiscuous sniff)
The Judge      : TWO complementary detectors feeding one decision:
                   (a) Port-cardinality tripwire (Lab 6)  -> fast, catches loud scans
                   (b) Shannon-entropy stealth model (Lab 8) -> catches slow/low-rate scans
                       that stay under the cardinality threshold
The Messenger  : HMAC-SHA256 authenticated ICMP Type-3 alert broadcast (Lab 7, hardened:
                 full digest instead of a truncated hash, timestamp baked in so replays
                 can be rejected by a freshness check on the receiving side)
Active Defense : Automated Windows Firewall block via netsh, now SELF-EXPIRING
                 (closes the Lab 7 gap where a false positive caused a permanent block)
Persistence    : SQLite threat ledger (alerts, entropy time-series, active blocks) —
                 read by app.py / the dashboard.

Run this in an elevated ("Run as Administrator") terminal — raw packet sniffing and
netsh firewall commands both require it on Windows.
"""

import scapy.all as scapy
from collections import defaultdict, deque
import math
import time
import threading
import subprocess
import sqlite3
import hmac
import hashlib
import socket

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
DB_PATH = "watchdog.db"
PRE_SHARED_KEY = b"CN-Lab-Group-2026-SecretKey"   # replace with a real secret if you extend this
ICMP_ALERT_TARGET = "8.8.8.8"          # kept from Lab 6/7 so alerts pass Windows filters cleanly

CARDINALITY_WINDOW_SECONDS = 20        # Lab 6 tripwire window
CARDINALITY_THRESHOLD = 15             # unique ports in window -> loud scan

ENTROPY_WINDOW_SECONDS = 45            # Lab 8 window — longer, so slow scans have time to show up
ENTROPY_MIN_SAMPLES = 5                # need at least this many touches before entropy is meaningful
ENTROPY_THRESHOLD = 0.85               # normalized entropy (0..1); >= this looks like random probing

FIREWALL_RULE_LIFETIME_SECONDS = 300   # auto-expire blocks after 5 min

ALERT_COOLDOWN_SECONDS = 30            # suppress repeat alarms for the same IP while
                                        # it's mid-scan and retransmitting packets

# ---------------------------------------------------------------------------
# STATE
# ---------------------------------------------------------------------------
# ip -> deque of (timestamp, dest_port) touches, oldest at the left
port_touches = defaultdict(deque)
lock = threading.Lock()
blocked_ips = {}   # ip -> expiry epoch seconds
last_alert_time = {}   # ip -> epoch seconds of the most recent alert we actually fired

# ---------------------------------------------------------------------------
# SELF-IP WHITELIST
# ---------------------------------------------------------------------------
# A machine self-testing with nmap (or running its own retries/loopback traffic)
# will otherwise look identical to a real remote attacker to the Judge, and Active
# Defense will happily firewall-block your own IP. We still want the Judge to
# DETECT and LOG self-scans (that's useful evidence for the report — it proves
# the detectors work), we just don't want Active Defense to act on it.
#
# Windows machines commonly have several IPs at once (Wi-Fi adapter, Ethernet,
# a VPN/virtual adapter, etc.), so this gathers all of them rather than assuming
# just one, and also includes loopback.
def get_local_ips():
    ips = {"127.0.0.1"}

    # Method 1: everything the hostname resolves to
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            ips.add(ip)
    except Exception:
        pass

    # Method 2: the IP the OS would actually use to reach the internet
    # (doesn't send anything, just asks the OS to pick a route)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass

    # Method 3: ask Scapy/Npcap directly for every interface's address, so a
    # secondary adapter it picks up for sniffing is also covered even if the
    # methods above missed it
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

LOCAL_IPS = get_local_ips()

# ---------------------------------------------------------------------------
# DATABASE
# ---------------------------------------------------------------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL, source_ip TEXT, detection_type TEXT,
        unique_ports INTEGER, entropy_value REAL,
        signature TEXT, blocked INTEGER
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS entropy_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL, source_ip TEXT, entropy_value REAL, unique_ports INTEGER
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS blocks (
        ip TEXT PRIMARY KEY, blocked_at REAL, expires_at REAL, active INTEGER
    )""")
    conn.commit()
    conn.close()

def log_entropy(ip, entropy_value, unique_ports):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO entropy_log (ts, source_ip, entropy_value, unique_ports) VALUES (?,?,?,?)",
                 (time.time(), ip, entropy_value, unique_ports))
    conn.commit()
    conn.close()

def log_alert(ip, detection_type, unique_ports, entropy_value, signature, blocked):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""INSERT INTO alerts (ts, source_ip, detection_type, unique_ports,
                    entropy_value, signature, blocked) VALUES (?,?,?,?,?,?,?)""",
                 (time.time(), ip, detection_type, unique_ports, entropy_value, signature, int(blocked)))
    conn.commit()
    conn.close()

def log_block(ip, expires_at):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""INSERT INTO blocks (ip, blocked_at, expires_at, active) VALUES (?,?,?,1)
                    ON CONFLICT(ip) DO UPDATE SET blocked_at=excluded.blocked_at,
                    expires_at=excluded.expires_at, active=1""",
                 (ip, time.time(), expires_at))
    conn.commit()
    conn.close()

def log_unblock(ip):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE blocks SET active=0 WHERE ip=?", (ip,))
    conn.commit()
    conn.close()

# ---------------------------------------------------------------------------
# THE JUDGE — (a) cardinality tripwire, inherited from Lab 6
# ---------------------------------------------------------------------------
def check_cardinality(ip, now):
    recent = [p for (t, p) in port_touches[ip] if now - t <= CARDINALITY_WINDOW_SECONDS]
    unique_ports = len(set(recent))
    return unique_ports, unique_ports > CARDINALITY_THRESHOLD

# ---------------------------------------------------------------------------
# THE JUDGE — (b) Shannon entropy stealth-scan model, Lab 8
# ---------------------------------------------------------------------------
def shannon_entropy(port_list):
    """
    H = -sum( p_i * log2(p_i) )  over the frequency distribution of ports touched.

    Normal traffic hits a small, repeated set of ports (e.g. 443 fifty times) -> LOW entropy.
    A scan — even a slow one — spreads hits close to uniformly across ports it has never
    touched before -> HIGH entropy, and this shows up with far fewer packets than it takes
    to trip a raw unique-port COUNT threshold.

    Result is normalized by the maximum possible entropy for the observed number of unique
    ports (log2(n_unique), the entropy of a perfectly uniform distribution over n_unique
    outcomes), so the score is always 0..1 and comparable across windows of different size.
    """
    if not port_list:
        return 0.0, 0
    counts = defaultdict(int)
    for p in port_list:
        counts[p] += 1
    total = len(port_list)
    n_unique = len(counts)
    entropy = 0.0
    for c in counts.values():
        p_i = c / total
        entropy -= p_i * math.log2(p_i)
    max_entropy = math.log2(n_unique) if n_unique > 1 else 1.0
    normalized = entropy / max_entropy if max_entropy > 0 else 0.0
    return normalized, n_unique

def check_entropy(ip, now):
    recent_ports = [p for (t, p) in port_touches[ip] if now - t <= ENTROPY_WINDOW_SECONDS]
    if len(recent_ports) < ENTROPY_MIN_SAMPLES:
        return 0.0, len(set(recent_ports)), False
    normalized, n_unique = shannon_entropy(recent_ports)
    log_entropy(ip, normalized, n_unique)
    is_stealth_scan = normalized >= ENTROPY_THRESHOLD and n_unique >= ENTROPY_MIN_SAMPLES
    return normalized, n_unique, is_stealth_scan

# ---------------------------------------------------------------------------
# THE MESSENGER — HMAC-SHA256 authenticated ICMP alert, Lab 7 hardened
# ---------------------------------------------------------------------------
def build_signature(ip, detection_type, ts):
    """
    Full HMAC-SHA256 over ip|type|timestamp. This closes both gaps flagged in the
    Lab 7 report: (1) a full digest instead of a truncated 64-bit hash, and
    (2) the timestamp is part of the signed message, so a receiver can reject a
    captured-and-replayed alert by checking that ts is recent.
    """
    msg = f"{ip}|{detection_type}|{ts}".encode()
    return hmac.new(PRE_SHARED_KEY, msg, hashlib.sha256).hexdigest()

def send_icmp_alert(ip, detection_type, unique_ports, entropy_value):
    ts = int(time.time())
    signature = build_signature(ip, detection_type, ts)
    alert_message = f"ALERT:{ip}|TYPE:{detection_type}|TS:{ts}|SIG:{signature}"
    packet = scapy.IP(dst=ICMP_ALERT_TARGET) / scapy.ICMP(type=3, code=0) / scapy.Raw(load=alert_message.encode())
    scapy.send(packet, verbose=False)
    print(f"--> [Messenger] {detection_type} | {ip} | SIG:{signature[:16]}...")
    return signature

# ---------------------------------------------------------------------------
# ACTIVE DEFENSE — self-expiring Windows Firewall block, Lab 7 hardened
# ---------------------------------------------------------------------------
def block_ip(ip):
    if ip in blocked_ips:
        return  # already blocked, don't spam netsh
    rule_name = f"Watchdog_Block_{ip}"
    try:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"],
            check=True, capture_output=True
        )
        expires_at = time.time() + FIREWALL_RULE_LIFETIME_SECONDS
        blocked_ips[ip] = expires_at
        log_block(ip, expires_at)
        print(f"[+] {ip} isolated for {FIREWALL_RULE_LIFETIME_SECONDS}s (auto-expiring rule).")
    except subprocess.CalledProcessError as e:
        # netsh writes its real error to stdout, not stderr — surface it instead of
        # just the generic "non-zero exit status" message.
        detail = (e.stdout or e.stderr or b"").decode(errors="ignore").strip()
        print(f"[!] Firewall rule failed for {ip}: {detail or e}")
        print("    (most common cause: this terminal is not running as Administrator)")

def unblock_ip(ip):
    rule_name = f"Watchdog_Block_{ip}"
    try:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
            check=True, capture_output=True
        )
    except subprocess.CalledProcessError:
        pass
    blocked_ips.pop(ip, None)
    log_unblock(ip)
    print(f"[-] {ip} unblocked (rule expired).")

def expiry_watcher():
    """Background thread: removes firewall rules once their lifetime is up."""
    while True:
        now = time.time()
        for ip, expires_at in list(blocked_ips.items()):
            if now >= expires_at:
                unblock_ip(ip)
        time.sleep(5)

# ---------------------------------------------------------------------------
# THE WATCHER — packet interception, Lab 6
# ---------------------------------------------------------------------------
def process_packet(packet):
    if not (packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP)):
        return
    # Defensive second check even though the BPF capture filter below already
    # restricts us to bare SYN packets: only a connection ATTEMPT (SYN, no ACK)
    # is scan-shaped. A SYN-ACK or plain ACK is just normal reply traffic from
    # a server you legitimately talked to, on a random ephemeral port — letting
    # those through is what was flooding the Judge with false "scans" from
    # ordinary browsing.
    if packet[scapy.TCP].flags != "S":
        return
    source_ip = packet[scapy.IP].src
    destination_port = packet[scapy.TCP].dport
    now = time.time()

    with lock:
        dq = port_touches[source_ip]
        dq.append((now, destination_port))
        cutoff = now - max(CARDINALITY_WINDOW_SECONDS, ENTROPY_WINDOW_SECONDS)
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        card_unique, card_alarm = check_cardinality(source_ip, now)
        entropy_val, ent_unique, entropy_alarm = check_entropy(source_ip, now)

        # Suppress repeat alarms for an IP that's still mid-scan and retransmitting —
        # without this, a burst of SYN retries refills the window and re-triggers the
        # same alarm dozens of times a second.
        cooling_down = (now - last_alert_time.get(source_ip, 0)) < ALERT_COOLDOWN_SECONDS
        if cooling_down:
            card_alarm = False
            entropy_alarm = False

    if card_alarm:
        is_self = source_ip in LOCAL_IPS
        tag = " [SELF-SCAN, not blocking]" if is_self else ""
        print(f"\n[ALARM] CARDINALITY | {source_ip} touched {card_unique} unique ports.{tag}")
        sig = send_icmp_alert(source_ip, "PORT_SCAN_CARDINALITY", card_unique, entropy_val)
        if not is_self:
            block_ip(source_ip)
        log_alert(source_ip, "PORT_SCAN_CARDINALITY", card_unique, entropy_val, sig, not is_self)
        with lock:
            port_touches[source_ip].clear()
            last_alert_time[source_ip] = now

    elif entropy_alarm:
        is_self = source_ip in LOCAL_IPS
        tag = " [SELF-SCAN, not blocking]" if is_self else ""
        print(f"\n[ALARM] ENTROPY | {source_ip} normalized H={entropy_val:.3f} "
              f"over {ent_unique} ports (stealth scan pattern).{tag}")
        sig = send_icmp_alert(source_ip, "PORT_SCAN_ENTROPY", ent_unique, entropy_val)
        if not is_self:
            block_ip(source_ip)
        log_alert(source_ip, "PORT_SCAN_ENTROPY", ent_unique, entropy_val, sig, not is_self)
        with lock:
            port_touches[source_ip].clear()
            last_alert_time[source_ip] = now

# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    threading.Thread(target=expiry_watcher, daemon=True).start()
    print("Watchdog IDPS (Labs 6+7+8) is awake.")
    print(f"  Cardinality tripwire : >{CARDINALITY_THRESHOLD} ports / {CARDINALITY_WINDOW_SECONDS}s window")
    print(f"  Entropy stealth model: normalized H >= {ENTROPY_THRESHOLD} / {ENTROPY_WINDOW_SECONDS}s window")
    print(f"  Self-IP whitelist    : {sorted(LOCAL_IPS)}")
    print("    (these IPs will still trigger alerts/logging if they scan, but Active")
    print("     Defense will NOT firewall-block them — self-tests won't self-lock you out)")
    print("Tracking bare-SYN TCP traffic (scan-shaped connection attempts only).")
    print("Start app.py in a second terminal to view the dashboard.\n")
    # "tcp[13] == 2" is a BPF filter: byte 13 of the TCP header is the flags byte,
    # and 2 (binary 00000010) is SYN-only, no ACK/FIN/RST/etc — this pushes the
    # SYN-vs-everything-else filtering down into libpcap instead of Python, so
    # ordinary traffic never even reaches process_packet.
    scapy.sniff(filter="tcp and tcp[13] == 2", prn=process_packet, store=False)