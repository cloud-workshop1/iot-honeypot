#!/bin/bash
# rita_analyze.sh
# Deploy to: /opt/scripts/rita_analyze.sh
# Runs every 6 hours via cron.

set -euo pipefail

DATE="$(date -u +%Y%m%d)"
DB="iot-honeypot-${DATE}"

echo "[$(date -u +%Y%m%dT%H%M%SZ)] RITA analysis starting: DB=${DB}"

rita import \
    --logs /forensics/zeek \
    --database "$DB" \
    --rolling 2>/dev/null

rita analyze --database "$DB"

# Export beacons for Grafana / LegalTrace figures
rita show-beacons \
    -o json \
    --database "$DB" \
    > "/forensics/rita/beacons-${DATE}-$(date -u +%H%M).json"

# Export long connections
rita show-long-connections \
    -o json \
    --database "$DB" \
    >> "/forensics/rita/long-conns-${DATE}-$(date -u +%H%M).json"

echo "[$(date -u +%Y%m%dT%H%M%SZ)] RITA analysis complete"
