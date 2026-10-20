# Intelligent Network Watchdog — Final Build (Labs 6 + 7 + 8)

A small intrusion detection & prevention system: it watches TCP SYNs, decides whether a source
IP is port-scanning, signs and broadcasts an alert, firewalls the offender for a few minutes,
and records everything for a live dashboard.

## How it fits together

One module per component, matching the names used in the lab report:

| Component | File | Job |
|---|---|---|
| The Watcher | `watchdog_core.py` | Scapy sniffer; feeds each bare SYN to the engine. Entry point for the detection engine |
| The Judge | `detectors.py` | Cardinality tripwire (Lab 6) + Shannon-entropy stealth model (Lab 8). Pure functions, no I/O |
| The Messenger | `messenger.py` | HMAC-SHA256 signed ICMP alert, plus `verify` for the receiving side |
| Active Defense | `firewall.py` | Self-expiring `netsh` blocks; keeps engine, DB and dashboard in agreement |
| Persistence | `db.py` | SQLite ledger shared by the engine and the dashboard |
| Configuration | `config.py` | Every threshold and window in one place |
| Dashboard | `app.py`, `templates/dashboard.html` | Flask API + live UI. Entry point for the dashboard |

```
sniffer ──SYN──▶ Watchdog engine ──▶ detectors ──alarm──▶ messenger (ICMP)
                       │                                  firewall   (netsh, 5 min)
                       └──────────── everything ─────────▶ SQLite ◀── dashboard
```

## Setup

Setup from zero on Windows. Do these in order.

## 1. Install Npcap (packet capture driver)
Wireshark needs this even if you never open Wireshark's GUI — Scapy also uses it for raw
sniffing on Windows.
1. Go to https://npcap.com/#download and download the Npcap installer.
2. Run it. Leave **"Support raw 802.11 traffic"** unchecked (not needed). Keep
   **"Install Npcap in WinPcap API-compatible Mode"** checked — Scapy expects this.

## 2. Install Wireshark
1. Go to https://www.wireshark.org/download.html, download the Windows x64 installer.
2. During install, when it asks about Npcap, you can skip re-installing it since you
   just installed it in step 1.
3. You'll use Wireshark to *watch* traffic and take verification screenshots — the
   actual detection logic runs in `watchdog_core.py`, not in Wireshark itself.

## 3. Install Python
1. https://www.python.org/downloads/ — get Python 3.11 or 3.12 (Scapy support on 3.13
   can be spotty depending on version).
2. During install, tick **"Add python.exe to PATH"**.

## 4. Install Nmap
https://nmap.org/download.html — used to *simulate* the attacks the Watchdog should catch.

## 5. Set up the project
```powershell
cd path\to\watchdog_final
python -m pip install -r requirements.txt
```

## 6. Run it (two terminals, both "Run as Administrator")

**Terminal 1 — the detection engine** (needs admin for raw sockets + firewall rules):
```powershell
python watchdog_core.py
```

**Terminal 2 — the dashboard:**
```powershell
python app.py
```
Then open **http://127.0.0.1:5000** in a browser. The status light shows **engine live** only
while the engine is actually running (it publishes a heartbeat); amber means the dashboard is
up but `watchdog_core.py` is not.

Useful flags on the engine:
```powershell
python watchdog_core.py --dry-run          # detect, log and alert, but never touch the firewall
python watchdog_core.py --iface "Wi-Fi"    # sniff a specific adapter (default: Scapy's default route)
```
`--dry-run` also needs no Administrator rights for the firewall part, which makes it handy for
rehearsing the demo. On non-Windows systems blocking is always a dry run.

## 7. Generate test traffic

**A loud scan:**
```powershell
nmap -sS -T4 -p 20-100 <target-ip>
```
> **Heads-up before you screenshot:** on a short, fast scan like this one the *entropy* alarm
> usually fires first (on the 5th SYN, since five distinct ports already score H = 1.0), and the
> 30 s alert cooldown then suppresses the cardinality alarm for the rest of the scan. The
> cardinality tripwire shows up when a scan keeps going past the cooldown (for example
> `-p 1-1000` at a slower `--scan-delay`) or when the port distribution is lopsided. See
> *Known limitations* below; `tests/test_watchdog.py` pins this behaviour.

**A slow / stealth scan — should trip the Lab 8 entropy detector instead, likely
*without* ever crossing the cardinality threshold:**
```powershell
nmap -sS --scan-delay 2s -p 20,25,80,110,143,443,3389,8080 <target-ip>
```
This spreads 8 distinct ports out with a 2-second delay between each — the
cardinality count (8) never crosses the >15 tripwire, but the port distribution is
close to uniform, so normalized entropy should climb toward/above the 0.85 threshold
once `ENTROPY_MIN_SAMPLES` (5) is reached.

Watch Terminal 1 for `[ALARM] CARDINALITY` vs `[ALARM] ENTROPY` lines, watch the
dashboard update live, and capture both in Wireshark (filter `icmp`) the same way you
did in Labs 6–7 — you should see the `ALERT:<ip>|TYPE:...|TS:...|SIG:...` string in the
ICMP payload's hex/ASCII pane.

## 8. What to screenshot for the final report
- Npcap/Wireshark install screens (once, like Lab 6)
- `watchdog_core.py` startup banner
- A CARDINALITY alarm firing (terminal + Wireshark ICMP payload)
- An ENTROPY alarm firing (terminal + Wireshark ICMP payload) — this is the new Lab 8
  evidence and the one worth narrating carefully, since it's the scan that *evades*
  Lab 6's method
- The dashboard: stat cards, the live entropy line chart during both scans, the
  alert ledger table, and a blocked IP with its countdown
- `watchdog.db` growing (optional: `sqlite3 watchdog.db "select * from alerts;"`)
- Receiving-side verification: copy the `ALERT:...` string out of Wireshark's ICMP payload and run
  ```powershell
  python messenger.py verify "ALERT:<ip>|TYPE:...|TS:...|SIG:..."
  ```
  It prints `VALID`, or `INVALID: bad signature` / `INVALID: stale ...` (try editing one character,
  or waiting past 60 s, to show both rejections).

## Notes on the design choices (for your report's discussion section)
- **Why two detectors instead of replacing Lab 6:** cardinality is a cheap, fast
  tripwire for loud scans; entropy is a statistical-shape metric that catches scans
  cardinality misses (few ports, but a distribution that's still anomalous), at the
  cost of needing a slightly longer window and a minimum sample size to be reliable.
- **Why normalize entropy by log2(n_unique):** raw Shannon entropy grows with the
  number of distinct ports, so a fixed raw threshold would need constant retuning as
  the window fills. Dividing by the max-entropy-for-that-sample-size gives a stable
  0–1 score you can threshold once.
- **Firewall rule expiry:** Lab 7 explicitly flagged that a false positive caused a
  permanent block with no authentication of the offending IP. This build fixes the
  first half (auto-expiry after 5 minutes via a background thread) and is explicit
  in the report that IP-based blocking still can't stop a spoofed source — that's a
  known, inherent limitation of this class of defense, not something patched here.
- **Messenger hardening:** upgraded from a truncated 64-bit hash to full HMAC-SHA256
  with the timestamp inside the signed message, closing the replay gap Lab 7 flagged
  as future work. `messenger.py verify` is the receiving side of that design: it checks the
  signature with a constant-time comparison and rejects alerts older than 60 s.
  (It narrows the replay window rather than eliminating it; see *Known limitations*.)

## Configuration

All thresholds live in `config.py`. Three values can be overridden with environment variables
so nothing machine-specific or secret has to be edited into the source:

| Variable | Default | Purpose |
|---|---|---|
| `WATCHDOG_PSK` | the lab key | HMAC key for alert signatures. The engine banner warns while the default is in use |
| `WATCHDOG_ICMP_TARGET` | `8.8.8.8` | Where the ICMP alerts are sent |
| `WATCHDOG_DB` | `watchdog.db` next to the code | SQLite file. Anchored to the code's folder, so the engine and the dashboard always share one database wherever you launch them from |

```powershell
$env:WATCHDOG_PSK = "something-long-and-random"   # set in BOTH terminals if you want verify to pass
```

## Tests

No Administrator rights, Npcap or network needed. The suite never touches your real `watchdog.db`.
```powershell
python -m pip install -r requirements-dev.txt
python -m pytest
```

## Known limitations

These are inherent to the design or deliberate lab simplifications, written down so they can be
discussed honestly in the report.

- **Entropy usually wins the race on fast scans.** With `ENTROPY_MIN_SAMPLES = 5` and
  `ENTROPY_THRESHOLD = 0.85`, any five SYNs to five different ports from one IP score H = 1.0, so
  the entropy alarm fires on SYN #5, long before the cardinality count can reach 16. The cooldown
  then mutes cardinality for the remainder of a short scan. Cardinality still fires for scans that
  outlast the cooldown or hit a skewed port distribution. This is a genuine trade-off, not just a
  tuning slip: the slow-scan demo needs entropy to fire with as few as 5-8 ports, so
  `ENTROPY_MIN_SAMPLES` can't simply be raised past cardinality's 16. Possible designs, left
  unimplemented because they change the lab's tuned behaviour: keep a separate cooldown per detector
  (a loud scan would then log an entropy alarm *and* a cardinality alarm), or let entropy alarm only
  when the probe rate is low.
- **IP-based blocking cannot stop a spoofed source** (and could be abused to block a victim IP).
- **Replay inside the freshness window is still accepted.** Closing that fully needs the receiver to
  remember recently seen signatures.
- **The default signing key is public.** It is in this repository's history, so treat it as
  compromised for anything beyond the lab and set `WATCHDOG_PSK`.
- **Alerts go to `8.8.8.8` by default** (kept so they pass Windows filters in the lab). That is a
  third party's address; point `WATCHDOG_ICMP_TARGET` at a host you control for real use.
- **Blocking is Windows-only** (`netsh`). Elsewhere the engine detects and logs but only simulates blocks.
- **The dashboard has no authentication.** It binds to `127.0.0.1` only, and Flask's debugger is off
  unless you set `FLASK_DEBUG=1`. The chart needs internet access for the Chart.js CDN.
- **The Judge sees every SYN on the interface, including your own outbound connections.** The
  self-IP whitelist stops Active Defense from blocking you, but self-scans are still detected and
  logged (shown as `LOGGED ONLY` on the dashboard) by design.
