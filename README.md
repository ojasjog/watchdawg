# Intelligent Network Watchdog — Final Build (Labs 6 + 7 + 8)

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
Then open **http://127.0.0.1:5000** in a browser.

## 7. Generate test traffic

**A loud scan — should trip the Lab 6 cardinality tripwire:**
```powershell
nmap -sS -T4 -p 20-100 <target-ip>
```

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
  as future work.
