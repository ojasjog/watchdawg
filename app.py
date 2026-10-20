"""
Flask dashboard backend for the Intelligent Network Watchdog.
Run this in a SECOND terminal while watchdog_core.py is sniffing in the first.
    python app.py
Then open http://127.0.0.1:5000 in a browser.
"""

import ipaddress
import os
import time

from flask import Flask, jsonify, render_template, request

import config
import firewall
from db import Database

app = Flask(__name__)
db = Database(config.DB_PATH)
db.init()   # idempotent; lets the dashboard start cleanly even before the engine ever has


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/alerts")
def api_alerts():
    return jsonify(db.recent_alerts(50))


@app.route("/api/entropy")
def api_entropy():
    return jsonify(db.entropy_since(time.time() - 300))   # last 5 minutes


@app.route("/api/blocks")
def api_blocks():
    return jsonify(db.active_blocks())


@app.route("/api/stats")
def api_stats():
    return jsonify({**db.stats(), "engine_last_seen": db.engine_last_seen(), "now": time.time()})


@app.route("/api/unblock", methods=["POST"])
def api_unblock():
    # silent=True + the JSON content-type requirement also means a cross-site <form> post
    # can't trigger this; it falls through to the 400 below.
    payload = request.get_json(silent=True) or {}
    try:
        ip = str(ipaddress.ip_address(str(payload.get("ip", "")).strip()))
    except ValueError:
        return jsonify({"ok": False, "error": "a valid IP address is required"}), 400

    # Best effort from here (needs Administrator on Windows). If it can't delete the rule,
    # the engine, which runs elevated, notices the DB flag within a few seconds and does it.
    firewall.delete_rule(ip)
    db.log_unblock(ip)
    return jsonify({"ok": True})


if __name__ == "__main__":
    # Localhost only. Werkzeug's debugger allows code execution, so it is opt-in:
    #   FLASK_DEBUG=1 python app.py
    app.run(host="127.0.0.1", port=5000, debug=os.environ.get("FLASK_DEBUG") == "1")
