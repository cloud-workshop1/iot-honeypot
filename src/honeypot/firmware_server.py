"""
firmware_server.py
Deploy to: /opt/honeypot/firmware_server.py

Minimal Flask server simulating a Hikvision firmware update endpoint.
Runs on 172.20.0.12:8080 (internal only — NOT exposed to internet).

Purpose: ZTA violation target. If an attacker reaches this service
from the MQTT namespace, Tetragon fires tcp_connect kprobe → ZeroTrace evidence.
"""

from flask import Flask, request, jsonify
from datetime import datetime
import json

app = Flask(__name__)

DEVICE = {
    "model":             "DS-2CD2183G2",
    "current_firmware":  "V5.7.16 build 230228",
    "latest_firmware":   "V5.7.16 build 230228",
    "update_available":  False,
}


@app.route("/firmware/update", methods=["GET", "POST"])
def firmware_update():
    """Respond to firmware check requests — logs every access."""
    ts     = datetime.utcnow().isoformat() + "Z"
    src_ip = request.remote_addr

    print(f"[{ts}] FIRMWARE ACCESS from {src_ip} {request.method} {request.path}", flush=True)

    return jsonify({
        "device":           DEVICE["model"],
        "current_version":  DEVICE["current_firmware"],
        "latest_version":   DEVICE["latest_firmware"],
        "update_available": DEVICE["update_available"],
        "timestamp":        ts,
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "ts": datetime.utcnow().isoformat() + "Z"})


if __name__ == "__main__":
    # Bind to container IP only — accessible only within iot-internal network
    app.run(host="0.0.0.0", port=8080, debug=False)
