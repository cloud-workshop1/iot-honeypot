#!/bin/bash
# sync_isf.sh
# Deploy to: /opt/scripts/sync_isf.sh
# Runs every hour via cron — pulls latest Volatility ISF from GitHub Release.

set -euo pipefail

REPO="your-github-username/iot-honeypot-firmware"   # TODO: replace with real username
ISF_DIR="/opt/volatility3/isf"
COMMIT="$(git -C /opt/linux-5.15.162 rev-parse --short HEAD 2>/dev/null || echo 'latest')"
ISF_URL="https://github.com/${REPO}/releases/latest/download/iot-arm-linux-${COMMIT}.json"
ISF_PATH="${ISF_DIR}/iot-arm-linux-latest.json"

mkdir -p "$ISF_DIR"

echo "[$(date -u +%Y%m%dT%H%M%SZ)] Syncing ISF from: $ISF_URL"

wget -q "$ISF_URL" -O "$ISF_PATH" || {
    echo "[$(date -u)] WARN: ISF download failed — keeping existing file" >&2
    exit 0
}

# Validate immediately after download
python3 << 'EOF'
import json, sys
try:
    with open("/opt/volatility3/isf/iot-arm-linux-latest.json") as f:
        isf = json.load(f)
    assert "task_struct" in isf["user_types"], "task_struct missing!"
    assert "mm_struct"   in isf["user_types"], "mm_struct missing!"
    print(f"[ISF OK] {len(isf['user_types'])} user types found")
except Exception as e:
    print(f"[ISF FAIL] {e}", file=sys.stderr)
    sys.exit(1)
EOF

echo "[$(date -u +%Y%m%dT%H%M%SZ)] ISF updated: sha256=$(sha256sum "$ISF_PATH" | awk '{print $1}')"
