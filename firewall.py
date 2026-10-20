"""
ACTIVE DEFENSE: self-expiring Windows Firewall blocks via netsh (Lab 7, hardened).

`add_rule` / `delete_rule` are thin wrappers around netsh. On any non-Windows OS (or with
dry_run=True) they only print what they WOULD do, so the whole system can be exercised
without Administrator rights or touching a real firewall.

`BlockManager` owns the engine's view of which IPs are blocked and keeps it consistent with
the database, which is also written by the dashboard's "Unblock now" button:

  * block()    add a rule, remember its expiry, record it
  * sync()     every housekeeping tick: expire old rules AND notice blocks the dashboard
               released (so the IP can be blocked again later, and a rule the dashboard
               couldn't delete, e.g. not elevated, still gets removed)
  * restore()  at startup: re-adopt blocks from a previous run, and clean up ones that
               expired while the engine was off, instead of leaving them live forever
"""

import ipaddress
import os
import subprocess
import threading
import time

import config


def is_windows():
    return os.name == "nt"


def rule_name(ip):
    return f"Watchdog_Block_{ip}"


def _netsh(*args):
    return subprocess.run(["netsh", "advfirewall", "firewall", *args],
                          check=True, capture_output=True)


def add_rule(ip, dry_run=False):
    """Returns True if the rule is in place (or would be, in dry-run)."""
    ip = str(ipaddress.ip_address(ip))   # raises ValueError on anything that isn't an IP
    if dry_run or not is_windows():
        print(f"[dry-run] would firewall-block {ip}")
        return True
    try:
        _netsh("add", "rule", f"name={rule_name(ip)}", "dir=in", "action=block", f"remoteip={ip}")
        return True
    except subprocess.CalledProcessError as e:
        # netsh writes its real error to stdout, not stderr, so surface it instead of just
        # the generic "non-zero exit status" message.
        detail = (e.stdout or e.stderr or b"").decode(errors="ignore").strip()
        print(f"[!] Firewall rule failed for {ip}: {detail or e}")
        print("    (most common cause: this terminal is not running as Administrator)")
        return False
    except OSError as e:
        print(f"[!] Could not run netsh for {ip}: {e}")
        return False


def delete_rule(ip, dry_run=False):
    """Best effort. Returns False if netsh refused (often: the rule is already gone)."""
    ip = str(ipaddress.ip_address(ip))
    if dry_run or not is_windows():
        return True
    try:
        _netsh("delete", "rule", f"name={rule_name(ip)}")
        return True
    except (subprocess.CalledProcessError, OSError):
        return False


class BlockManager:
    def __init__(self, db, lifetime=None, dry_run=False):
        self.db = db
        self.lifetime = config.FIREWALL_RULE_LIFETIME_SECONDS if lifetime is None else lifetime
        self.dry_run = dry_run or not is_windows()
        self._blocked = {}   # ip -> expiry epoch seconds
        self._lock = threading.Lock()

    def is_blocked(self, ip):
        with self._lock:
            return ip in self._blocked

    def block(self, ip, now=None):
        """Returns True if `ip` is blocked after this call, False if the firewall call failed."""
        now = time.time() if now is None else now
        with self._lock:
            if ip in self._blocked:
                return True   # already blocked, don't spam netsh
            if not add_rule(ip, self.dry_run):
                return False
            expires_at = now + self.lifetime
            self._blocked[ip] = expires_at
        self.db.log_block(ip, expires_at, ts=now)
        print(f"[+] {ip} isolated for {self.lifetime}s (auto-expiring rule).")
        return True

    def release(self, ip, reason="rule expired"):
        delete_rule(ip, self.dry_run)
        with self._lock:
            self._blocked.pop(ip, None)
        self.db.log_unblock(ip)
        print(f"[-] {ip} unblocked ({reason}).")

    def sync(self, now=None):
        now = time.time() if now is None else now
        with self._lock:
            snapshot = dict(self._blocked)
        active_in_db = {row["ip"] for row in self.db.active_blocks()}
        for ip, expires_at in snapshot.items():
            if now >= expires_at:
                self.release(ip, "rule expired")
            elif ip not in active_in_db:
                self.release(ip, "released from dashboard")

    def restore(self, now=None):
        now = time.time() if now is None else now
        for row in self.db.active_blocks():
            ip, expires_at = row["ip"], row["expires_at"]
            if expires_at <= now:
                self.release(ip, "expired while the engine was offline")
            else:
                with self._lock:
                    self._blocked[ip] = expires_at
                print(f"[=] Restored existing block on {ip} ({int(expires_at - now)}s left).")
