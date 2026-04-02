"""
iot_behavior_sim.py
Deploy to: /opt/honeypot/iot_behavior_sim.py

Simulates a Hikvision DS-2CD2183G2 IP camera's natural behavior:
- MQTT telemetry at Gaussian intervals (mean=30s, sigma=2.1s)
- HTTP health check every ~5 minutes (phone-home behavior)

Gaussian timing is critical: uniform intervals score > 0.80 in RITA
(automated scanner pattern). Gaussian timing produces natural-looking
jitter that validates the behavioral baseline for the LegalTrace paper.
"""

import paho.mqtt.client as mqtt
import time, random, json, requests
from datetime import datetime

# Hikvision DS-2CD2183G2 device profile
DEVICE = {
    "model":    "DS-2CD2183G2",
    "mac":      "44:19:B6:A2:FC:11",
    "firmware": "V5.7.16 build 230228",
    "serial":   "DS-2CD2183G2-J20230228AAWRD",
}

MQTT_BROKER = "172.20.0.10"   # mqtt-broker container IP
MQTT_PORT   = 1883
TOPIC       = f"devices/cameras/{DEVICE['mac']}/status"


def http_health_check() -> None:
    """Mimics device phone-home behavior. Failure is expected — CSP endpoint is fake."""
    try:
        requests.post(
            "https://your-cloud-endpoint.example.com/device/heartbeat",
            json={"device": DEVICE, "ts": datetime.utcnow().isoformat()},
            timeout=5
        )
    except Exception:
        pass  # Expected — endpoint doesn't exist


def main():
    client = mqtt.Client(client_id=DEVICE["mac"], protocol=mqtt.MQTTv5)
    client.connect(MQTT_BROKER, MQTT_PORT, 60)
    client.loop_start()

    iteration = 0
    while True:
        payload = {
            "deviceId":               DEVICE["mac"],
            "ts":                     datetime.utcnow().isoformat() + "Z",
            "temp_celsius":           round(random.gauss(47.2, 1.8), 1),
            "uptime_seconds":         iteration * 30,
            "cpu_load_pct":           round(random.gauss(12.4, 3.1), 1),
            "memory_used_mb":         round(random.gauss(184, 11.2), 1),
            "motion_detected":        random.random() < 0.031,
            "stream_active_channels": random.choices([1, 2], weights=[0.7, 0.3])[0],
            "firmware_check_pending": (iteration % 48 == 0),  # Every ~24hrs
        }

        client.publish(TOPIC, json.dumps(payload), qos=1, retain=True)

        # HTTP health check every 10 cycles (~5 minutes)
        if iteration % 10 == 0:
            http_health_check()

        iteration += 1

        # Gaussian sleep: mean=30s, sigma=2.1s — matches real Hikvision firmware heartbeat
        interval = max(5.0, random.gauss(30, 2.1))
        time.sleep(interval)


if __name__ == "__main__":
    main()
