#!/bin/bash
# zeek_rotate_stamp.sh
# Deploy to: /opt/scripts/zeek_rotate_stamp.sh
#
# Called by Zeek's log rotation mechanism on each completed log file.
# Compress → SHA256 → OTS stamp → MinIO WORM → manifest entry.
#
# Fix from Plan.pdf: manifest writes use JSON objects {} not arrays []

set -euo pipefail

LOG_FILE="$1"
MANIFEST="/forensics/manifest/evidence_manifest.jsonl"

ts="$(date -u +%Y%m%dT%H%M%SZ)"

# SHA256 of the raw log file BEFORE compression
sha256="$(sha256sum "$LOG_FILE" | awk '{print $1}')"

# Compress
zstd -9 --rm "$LOG_FILE" -o "${LOG_FILE}.zst"

# Blockchain timestamp (async)
ots stamp "${LOG_FILE}.zst" &

# MinIO WORM write (async)
mc cp "${LOG_FILE}.zst" minio/forensic-evidence/zeek/ &

# Manifest entry — JSON OBJECT
# log_type extracted from filename (e.g. conn.log → conn)
log_type="$(basename "$LOG_FILE" | cut -d. -f1)"

printf '{"file":"%s","sha256":"%s","ots_proof":"%s","timestamp_utc":"%s","layer":"zeek_log","log_type":"%s","plane":"ediscovery_gap6"}\n' \
    "$(basename "${LOG_FILE}.zst")" \
    "$sha256" \
    "$(basename "${LOG_FILE}.zst").ots" \
    "$ts" \
    "$log_type" \
    >> "$MANIFEST"

echo "[${ts}] Zeek log rotated: $(basename "${LOG_FILE}.zst") type=${log_type}"
