# Intelligent Network Watchdog

**A lightweight, explainable intrusion detection and prevention system for Windows hosts.**
It watches for port scans, raises a cryptographically signed alert, automatically firewalls the offender, and shows everything on a live dashboard, all from a small Python codebase you can read in an afternoon.

---

## Why Network Watchdog

Most intrusion detection tools are either heavyweight platforms that take days to deploy and tune, or simple threshold scripts that a patient attacker walks straight past. Network Watchdog sits in the gap between them:

- **It catches the scans that simple tools miss.** A classic "more than N ports in M seconds" rule is easy to evade with a slow scan. Watchdog pairs that fast tripwire with a Shannon-entropy model that recognises the *shape* of probing traffic, so a deliberately throttled scan of only a few ports is still flagged.
- **It responds, not just reports.** Detection triggers a self-expiring Windows Firewall block automatically. No analyst needs to be watching.
- **Every decision is explainable.** There is no black-box model. Each alarm maps to a specific, documented rule and a handful of thresholds in one config file.
- **Alerts are tamper-evident.** Alerts are signed with HMAC-SHA256 and carry a timestamp, so a receiver can verify both authenticity and freshness.
- **It runs on a plain Windows machine.** No agents, no cloud service, no database server. Scapy, SQLite and Flask are the whole stack.
- **The detection logic is testable in isolation.** The detectors are pure functions with no I/O, and the test suite runs without Administrator rights, a packet driver or a network connection.

## Key Features

| Capability | Detail |
| --- | --- |
| Dual-detector engine | Cardinality tripwire for loud scans, plus a normalised Shannon-entropy detector for slow and stealthy scans |
| Active defense | Offending IPs are blocked through Windows Firewall (`netsh`) and unblocked automatically after 5 minutes |
| Signed alerts | HMAC-SHA256 over the alert and its timestamp, sent as an ICMP payload, with a constant-time verifier and a 60 s freshness window |
| Live dashboard | Flask UI with stat cards, a live entropy chart, an alert ledger, and blocked IPs with countdowns, including manual unblock |
| Persistent ledger | SQLite database shared by the engine and dashboard, so history survives restarts |
| Safe by default | Self-IP whitelist stops the system from blocking its own host; `--dry-run` mode detects and alerts without touching the firewall |
| Single config file | Every threshold, window and lifetime lives in `config.py`; secrets and endpoints can be overridden through environment variables |

## How It Works

Each component is a single module with one job:

| Component | File | Responsibility |
| --- | --- | --- |
| The Watcher | `watchdog_core.py` | Scapy sniffer that feeds each bare TCP SYN to the detection engine. Entry point for the engine |
| The Judge | `detectors.py` | Cardinality tripwire and Shannon-entropy stealth model. Pure functions, no I/O |
| The Messenger | `messenger.py` | HMAC-SHA256 signed ICMP alerts, plus a `verify` command for the receiving side |
| Active Defense | `firewall.py` | Self-expiring `netsh` blocks; keeps engine, database and dashboard in agreement |
| Persistence | `db.py` | SQLite ledger shared by the engine and dashboard |
| Configuration | `config.py` | All thresholds and windows in one place |
| Dashboard | `app.py`, `templates/dashboard.html` | Flask API and live UI. Entry point for the dashboard |

```
sniffer ──SYN──▶ Watchdog engine ──▶ detectors ──alarm──▶ messenger (ICMP)
                       │                                  firewall   (netsh, 5 min)
                       └──────────── everything ─────────▶ SQLite ◀── dashboard
```

### The two detectors

**Cardinality tripwire.** Counts the unique destination ports a single source IP touches within a 20-second window. More than 15 unique ports is a loud scan. It is cheap, fast and effective against default scanner settings.

**Entropy model.** Measures how evenly a source's probes are spread across ports over a 45-second window. Real client traffic concentrates on a few ports; a scanner sweeping a target looks close to uniform. Entropy is normalised by `log2(n_unique)` so the score always falls between 0 and 1 and a single threshold (0.85) holds steady as the window fills. This is what exposes a scan that stays below the cardinality threshold by going slowly.

Using both gives a clear trade-off. Cardinality is the fast path for noisy scans; entropy covers evasive ones, at the cost of needing a minimum sample size (5 SYNs) to be statistically meaningful.

## Real-World Use Cases

Network Watchdog is a good fit wherever you need transparent, low-overhead scan detection on a Windows host without standing up a full security platform:

- **Home labs and small offices.** Get an early warning and an automatic response when something on the network starts mapping your machine.
- **Exposed development and staging servers.** A Windows box reachable from a wider network can detect reconnaissance before it becomes an incident.
- **Workstation hardening.** Run it on an administrator or developer machine to catch lateral reconnaissance from a compromised device on the same LAN.
- **Security education and training.** Because every detection rule is readable and every threshold is configurable, it is an effective teaching tool for how IDS/IPS systems, scan evasion and statistical detection actually work.
- **Red-team and purple-team exercises.** Use it as a known, tunable detector to measure whether a scan profile evades threshold rules but is still caught by distribution-based analysis.
- **Prototyping detection logic.** The pure-function detectors are easy to extend, benchmark and test before being ported to a production pipeline.

## Advantages at a Glance

- Detects both loud and slow, evasive port scans
- Automated, self-cleaning response with no permanent false-positive lockouts
- Signed, timestamped alerts with receiver-side verification
- Fully transparent logic with centralised, tunable configuration
- Minimal dependencies and a small, readable codebase
- Dry-run mode for safe evaluation before enabling blocking
- Test suite that needs no privileges, drivers or network access

---

## Getting Started

### Requirements

- Windows 10 or 11
- Python 3.11 or 3.12 (Scapy support on 3.13 can vary by version)
- [Npcap](https://npcap.com/#download), installed with **WinPcap API-compatible mode** enabled
- [Nmap](https://nmap.org/download.html) for generating test traffic
- Optional: [Wireshark](https://www.wireshark.org/download.html) to inspect the ICMP alert payload

### Installation

```
git clone https://github.com/ojasjog/watchdawg.git
cd watchdawg
python -m pip install -r requirements.txt
```

### Running

Use two terminals.

**Terminal 1: detection engine** (run as Administrator; raw sockets and firewall rules require it):

```
python watchdog_core.py
```

**Terminal 2: dashboard:**

```
python app.py
```

Open <http://127.0.0.1:5000>. The status light shows **engine live** only while the engine is publishing its heartbeat; amber means the dashboard is up but the engine is not running.

Engine flags:

```
python watchdog_core.py --dry-run          # detect, log and alert, but never touch the firewall
python watchdog_core.py --iface "Wi-Fi"    # sniff a specific adapter (default: Scapy's default route)
```

`--dry-run` does not require Administrator rights for the firewall portion. On non-Windows systems blocking is always a dry run.

## Configuration

All thresholds live in `config.py`.

| Setting | Default | Meaning |
| --- | --- | --- |
| `CARDINALITY_WINDOW_SECONDS` | 20 | Window for the tripwire |
| `CARDINALITY_THRESHOLD` | 15 | Unique ports in the window that count as a loud scan |
| `ENTROPY_WINDOW_SECONDS` | 45 | Longer window so slow scans have time to appear |
| `ENTROPY_MIN_SAMPLES` | 5 | Minimum probes before entropy is meaningful |
| `ENTROPY_THRESHOLD` | 0.85 | Normalised entropy at or above which probing looks random |
| `ALERT_COOLDOWN_SECONDS` | 30 | Suppresses repeat alarms for an IP that is mid-scan |
| `FIREWALL_RULE_LIFETIME_SECONDS` | 300 | Block duration before automatic expiry |
| `ALERT_MAX_AGE_SECONDS` | 60 | Freshness window when verifying an alert |

Three values can be overridden with environment variables so nothing secret or machine-specific is edited into source:

| Variable | Default | Purpose |
| --- | --- | --- |
| `WATCHDOG_PSK` | built-in development key | HMAC key for alert signatures. The engine banner warns while the default is in use |
| `WATCHDOG_ICMP_TARGET` | `8.8.8.8` | Destination for ICMP alerts |
| `WATCHDOG_DB` | `watchdog.db` next to the code | SQLite file. Anchored to the code folder so engine and dashboard always share one database |

```
$env:WATCHDOG_PSK = "something-long-and-random"   # set in BOTH terminals if you want verify to pass
```

**Set `WATCHDOG_PSK` before any real use.** The built-in default key is public.

## Verifying Alerts

Each alert is an ICMP payload of the form `ALERT:<ip>|TYPE:...|TS:...|SIG:...`. You can read it in Wireshark with the filter `icmp`. To verify one on the receiving side:

```
python messenger.py verify "ALERT:<ip>|TYPE:...|TS:...|SIG:..."
```

The result is `VALID`, `INVALID: bad signature`, or `INVALID: stale ...`. Editing a single character, or waiting more than 60 seconds, demonstrates each rejection path.

---

## Testing and Validation

### Automated test suite

The suite needs no Administrator rights, no Npcap and no network access, and it never touches your real `watchdog.db`.

```
python -m pip install -r requirements-dev.txt
python -m pytest
```

It exercises the detection logic directly, including the behaviour where the entropy alarm fires first on a fast scan and the cooldown then suppresses the cardinality alarm.

### Live traffic testing

Live tests use Nmap to generate scans. **Only scan devices you own or have explicit permission to scan.**

| Scenario | Command | Expected result |
| --- | --- | --- |
| Loud scan | `nmap -sS -T4 -p 20-100 <target-ip>` | Entropy alarm fires first (on the 5th SYN); alert is signed and sent by ICMP; ledger and dashboard update |
| Sustained loud scan | `nmap -sS -T4 -p 1-1000 --scan-delay 100ms <target-ip>` | Scan outlasts the cooldown, so the cardinality alarm also fires |
| Slow / stealth scan | `nmap -sS --scan-delay 2s -p 20,25,80,110,143,443,3389,8080 <target-ip>` | Only 8 distinct ports, so the cardinality threshold of 15 is never crossed, but the near-uniform distribution trips the entropy detector |
| Alert authenticity | `python messenger.py verify "<captured alert>"` | `VALID` for an untouched alert; `INVALID` after tampering or after 60 s |

#### Option 1: Scan another host from the same machine (detection only)

Scan a device on your network that you own, such as your router (shown as the Default Gateway in `ipconfig`):

```
nmap -sS -T4 -p 20-100 <router-ip>
nmap -sS --scan-delay 2s -p 20,25,80,110,143,443,3389,8080 <router-ip>
```

The sniffer sees your own outbound SYNs, so both detectors can fire, the ICMP alert is sent, and the ledger and chart populate. Because the source is your own IP, the dashboard row is marked **LOGGED ONLY** and nothing is blocked. This validates detection, the entropy chart, the signed alert and `messenger.py verify` on a single machine.

> Do not scan `127.0.0.1` or your own LAN address. That traffic travels over loopback, which Npcap normally cannot capture without its separate loopback adapter.

#### Option 2: Test active blocking with WSL2, no second device needed

A real **BLOCKED** result requires a source IP that is not whitelisted. WSL2 provides one: it runs behind a virtual adapter with its own address, so a scan from inside WSL looks like a scan from a separate machine.

**Terminals**

| Terminal | Where | Runs |
| --- | --- | --- |
| 1 | PowerShell, **as Administrator** | The detection engine, bound to the WSL virtual adapter |
| 2 | PowerShell (normal) | `python app.py` |
| 3 | WSL (Ubuntu) | The attacking `nmap` commands |

The engine must run on Windows because it uses Windows Firewall (`netsh`) and sniffs the Windows network adapters. WSL is only the attacker.

**Steps**

1. **Confirm WSL2.** In PowerShell, run `wsl -l -v` and check that `VERSION` is `2`. The WSL virtual adapter only exists while a WSL terminal is open.

2. **Find the Windows host address as WSL sees it.** In WSL:

   ```bash
   ip route | grep default
   ```

   The address after `via` (for example `172.30.160.1`) is the scan target.

3. **Install Nmap in WSL:**

   ```bash
   sudo apt update && sudo apt install -y nmap
   ```

4. **Identify the adapter name for the engine.** On Windows, in the project folder:

   ```
   python -c "from scapy.all import conf; print(conf.ifaces)"
   ```

   Pick the **Hyper-V Virtual Ethernet Adapter** entry whose address matches the host address from step 2.

5. **Start the engine on that adapter** (Administrator PowerShell). Use the exact name Scapy printed:

   ```
   python watchdog_core.py --iface "Hyper-V Virtual Ethernet Adapter"
   ```

   The engine listens on one adapter at a time, so this run will not see Wi-Fi traffic. Restart without `--iface` to return to normal operation. In the startup banner, confirm the whitelist contains the host-side address but **not** WSL's own address.

6. **Start the dashboard** in a second PowerShell:

   ```
   python app.py
   ```

7. **Scan from WSL**, using the host address from step 2:

   ```bash
   sudo nmap -sS -T4 -p 20-100 172.30.160.1
   sudo nmap -sS --scan-delay 2s -p 20,25,80,110,143,443,3389,8080 172.30.160.1
   ```

**Expected result:** a **BLOCKED** row in the dashboard with a five-minute countdown. While the block is active, WSL cannot reach Windows, which is the intended behavior. Use **Unblock** on the dashboard, or wait for expiry. If a firewall rule cannot be deleted from the non-elevated dashboard, the elevated engine completes the removal within about 5 seconds.

**Troubleshooting**

- *Row shows LOGGED ONLY instead of BLOCKED:* WSL is probably in mirrored networking mode (`networkingMode=mirrored` in `.wslconfig`), where it shares the Windows IP and is treated as a self-scan. Switch back to NAT mode.
- *"Could not start sniffing" error:* the `--iface` value does not match Scapy's name exactly. Re-run the `conf.ifaces` listing and copy the name verbatim.
- *No WSL adapter in `ipconfig`:* start a WSL terminal first. The adapter only exists while WSL2 is running.

**Alternative second sources:** a VirtualBox VM scanning the host-only address (`--iface` set to the VirtualBox Host-Only adapter), or a phone running Termux on the same network scanning your laptop's IP.

---

## Limitations

Network Watchdog is intentionally compact, and its boundaries are worth understanding before you rely on it.

- **Entropy usually fires first on fast scans.** With `ENTROPY_MIN_SAMPLES = 5` and `ENTROPY_THRESHOLD = 0.85`, any five SYNs to five different ports from one IP score a perfect 1.0, so the entropy alarm triggers on the fifth SYN and the cooldown then mutes cardinality for the rest of a short scan. Cardinality still fires for longer scans or skewed port distributions. Raising the minimum sample size would break slow-scan detection, so this is a genuine trade-off. Two possible refinements are a separate cooldown per detector and gating entropy alarms on probe rate.
- **IP-based blocking cannot stop a spoofed source**, and could be abused to cause a victim's address to be blocked.
- **Replay inside the freshness window is still accepted.** Closing this fully requires the receiver to remember recently seen signatures.
- **The default signing key is public.** It exists in this repository's history. Always set `WATCHDOG_PSK` for anything beyond local evaluation.
- **ICMP alerts go to `8.8.8.8` by default** so they pass typical Windows filters. That is a third party's address; point `WATCHDOG_ICMP_TARGET` at a host you control for real use.
- **Active blocking is Windows-only** (`netsh`). On other platforms the engine detects and logs, but blocks are simulated.
- **The dashboard has no authentication.** It binds to `127.0.0.1` only, and Flask's debugger is off unless you set `FLASK_DEBUG=1`. The live chart loads Chart.js from a CDN and needs internet access.
- **The engine sees every SYN on the interface, including your own outbound connections.** The self-IP whitelist prevents it from blocking you, but self-scans are still detected and logged (shown as `LOGGED ONLY`).
- **It is a single-host, SYN-focused detector.** It is not a replacement for a network-wide IDS, and it does not inspect payloads or detect scan types that avoid SYN packets.

## Project Structure

```
.
├── app.py              # Flask dashboard and API
├── config.py           # Thresholds, windows and environment overrides
├── db.py               # SQLite ledger
├── detectors.py        # Cardinality and entropy detectors
├── firewall.py         # Self-expiring netsh blocks
├── messenger.py        # Signed ICMP alerts and verifier
├── watchdog_core.py    # Sniffer and detection engine
├── templates/          # Dashboard UI
├── tests/              # Automated test suite
├── requirements.txt
└── requirements-dev.txt
```

## Security and Responsible Use

Use this software only on systems and networks you own or are authorized to monitor, and only scan targets you are authorized to test. Automatic blocking changes firewall state; evaluate in `--dry-run` mode first.