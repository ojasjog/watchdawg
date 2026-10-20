"""
Flask dashboard backend for the Intelligent Network Watchdog.
Run this in a SECOND terminal while watchdog_core.py is sniffing in the first.
    python app.py
Then open http://127.0.0.1:5000 in a browser.
"""

from flask import Flask, jsonify, render_template, request
import sqlite3
import time
import subprocess

DB_PATH = "watchdog.db"
app = Flask(__name__)


def query(sql, params=()):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/alerts")
def api_alerts():
    return jsonify(query("SELECT * FROM alerts ORDER BY ts DESC LIMIT 50"))


@app.route("/api/entropy")
def api_entropy():
    since = time.time() - 300  # last 5 minutes
    return jsonify(query("SELECT * FROM entropy_log WHERE ts >= ? ORDER BY ts ASC", (since,)))


@app.route("/api/blocks")
def api_blocks():
    return jsonify(query("SELECT * FROM blocks WHERE active=1 ORDER BY blocked_at DESC"))


@app.route("/api/stats")
def api_stats():
    total_alerts = query("SELECT COUNT(*) as c FROM alerts")[0]["c"]
    active_blocks = query("SELECT COUNT(*) as c FROM blocks WHERE active=1")[0]["c"]
    cardinality_hits = query(
        "SELECT COUNT(*) as c FROM alerts WHERE detection_type='PORT_SCAN_CARDINALITY'")[0]["c"]
    entropy_hits = query(
        "SELECT COUNT(*) as c FROM alerts WHERE detection_type='PORT_SCAN_ENTROPY'")[0]["c"]
    return jsonify({
        "total_alerts": total_alerts,
        "active_blocks": active_blocks,
        "cardinality_hits": cardinality_hits,
        "entropy_hits": entropy_hits,
    })


@app.route("/api/unblock", methods=["POST"])
def api_unblock():
    ip = request.json.get("ip")
    rule_name = f"Watchdog_Block_{ip}"
    try:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
            check=True, capture_output=True
        )
    except subprocess.CalledProcessError:
        pass
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE blocks SET active=0 WHERE ip=?", (ip,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
