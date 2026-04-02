#!/bin/bash
# pcap_capture.sh
# Deploy to: /opt/scripts/pcap_capture.sh
#
# tcpdump ring buffer with 5-minute rotation.
# Each completed PCAP is: compressed (zstd) → SHA256 hashed →
#   OTS blockchain stamped → written to MinIO WORM → manifest entry appended.
#
# Fix from Plan.pdf: manifest writes use JSON objects {} not arrays []
# Fix from Plan.pdf: proper bash quoting throughout

set -euo pipefail

PCAP_DIR="/forensics/pcap"
MANIFEST="/forensics/manifest/evidence_manifest.jsonl"

# ---------------------------------------------------------------------------
# Post-rotation hook — called by tcpdump -z for each completed file
# ---------------------------------------------------------------------------
capture_and_process() {
    local base_file="$1"
    local compressed="${base_file}.zst"
    local ts
    ts="$(date -u +%Y%m%dT%H%M%SZ)"

    # Compress immediately (~75% size reduction)
    zstd -9 --rm "$base_file" -o "$compressed" 2>/dev/null || {
        echo "[${ts}] ERROR: zstd compression failed for ${base_file}" >&2
        return 1
    }

    # SHA256 hash of the compressed file
    local sha256
    sha256="$(sha256sum "$compressed" | awk '{print $1}')"

    # Submit to OpenTimestamps blockchain (async — does not block capture)
    ots stamp "$compressed" &

    # Write to MinIO WORM bucket (async — does not block capture)
    mc cp "$compressed" minio/forensic-evidence/pcap/ &

    # Append manifest entry — JSON OBJECT (not array)
    # Uses {} braces so python3 json.loads() parses each line correctly
    printf '{"file":"%s","sha256":"%s","ots_proof":"%s","timestamp_utc":"%s","layer":"raw_pcap","plane":"ediscovery_gap6"}\n' \
        "$(basename "$compressed")" \
        "$sha256" \
        "$(basename "$compressed").ots" \
        "$ts" \
        >> "$MANIFEST"

    echo "[${ts}] PCAP captured: $(basename "$compressed") sha256=${sha256:0:16}..."
}

export -f capture_and_process

# ---------------------------------------------------------------------------
# Run tcpdump with 5-minute rotation
# -G 300     : rotate every 300 seconds
# -z         : call capture_and_process on each completed file
# -Z root    : run the hook as root
# Filter     : exclude Oracle metadata service (169.254.0.0/16)
# ---------------------------------------------------------------------------
echo "[$(date -u +%Y%m%dT%H%M%SZ)] Starting PCAP ring buffer on eth0"

sudo tcpdump \
    -i eth0 \
    -n \
    -G 300 \
    -w "${PCAP_DIR}/capture_%Y%m%dT%H%M%S.pcap" \
    -z "bash -c 'capture_and_process \"\$1\"' --" \
    -Z root \
    "not net 169.254.0.0/16"
