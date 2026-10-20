"""
Central configuration for the Intelligent Network Watchdog.

Every tunable lives here. A few can be overridden with environment variables so that
nothing secret or machine-specific has to be edited into source control:

    WATCHDOG_DB           path to the SQLite file     (default: watchdog.db next to this file)
    WATCHDOG_PSK          HMAC pre-shared key         (default: the lab key; the banner warns)
    WATCHDOG_ICMP_TARGET  destination of ICMP alerts  (default: 8.8.8.8)
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Anchored to this file (not the current directory) so the engine and the dashboard
# always agree on which database they are using, wherever they are launched from.
DB_PATH = os.environ.get("WATCHDOG_DB") or str(BASE_DIR / "watchdog.db")

# ---------------------------------------------------------------------------
# Messenger
# ---------------------------------------------------------------------------
_LAB_DEFAULT_PSK = "CN-Lab-Group-2026-SecretKey"
PRE_SHARED_KEY = (os.environ.get("WATCHDOG_PSK") or _LAB_DEFAULT_PSK).encode()
PSK_IS_DEFAULT = not os.environ.get("WATCHDOG_PSK")

ICMP_ALERT_TARGET = os.environ.get("WATCHDOG_ICMP_TARGET") or "8.8.8.8"   # kept from Lab 6/7
ALERT_MAX_AGE_SECONDS = 60             # freshness window used when verifying an alert

# ---------------------------------------------------------------------------
# Judge
# ---------------------------------------------------------------------------
CARDINALITY_WINDOW_SECONDS = 20        # Lab 6 tripwire window
CARDINALITY_THRESHOLD = 15             # unique ports in window -> loud scan

ENTROPY_WINDOW_SECONDS = 45            # Lab 8 window; longer so slow scans have time to show up
ENTROPY_MIN_SAMPLES = 5                # need at least this many touches before entropy is meaningful
ENTROPY_THRESHOLD = 0.85               # normalized entropy (0..1); >= this looks like random probing

ALERT_COOLDOWN_SECONDS = 30            # suppress repeat alarms for an IP that is mid-scan

# ---------------------------------------------------------------------------
# Active defense / persistence housekeeping
# ---------------------------------------------------------------------------
FIREWALL_RULE_LIFETIME_SECONDS = 300   # auto-expire blocks after 5 min
HOUSEKEEPING_INTERVAL_SECONDS = 5      # expiry checks, dashboard-unblock sync, heartbeat
ENTROPY_LOG_INTERVAL_SECONDS = 1.0     # at most one entropy sample per IP per second goes to the DB
