"""
run_honeypot_panda.py
Deploy to: /opt/panda/run_honeypot_panda.py

PANDA ARM guest memory acquisition for SemBridge (Gap 3).
Triggered by session_correlator.py via Flask webhook on 127.0.0.1:9000.

Fixes from Plan.pdf:
  - physical_memory_read() correct API (not physical_memory.read)
  - run_serial_cmd() correct API (not run.serial_cmd)
  - Removed vexpress-a9 record/replay checkpoint (broken by PANDA design, Issue #643)
  - Fixed PANDA extra_args to valid list of strings
  - Corrected manifest JSON writing
"""

from pandare import Panda
import os, subprocess, hashlib, datetime, json, threading
import requests

QCOW_PATH  = "/forensics/iot-honeypot.qcow2"
ISF_PATH   = "/opt/volatility3/isf/iot-arm-linux-latest.json"
DUMP_DIR   = "/forensics/memdump"
MANIFEST   = "/forensics/manifest/evidence_manifest.jsonl"

# ---------------------------------------------------------------------------
# PANDA instance — ARM guest (vexpress-a9) on ARM64 host
# ---------------------------------------------------------------------------
panda = Panda(
    arch="arm",
    mem="512M",
    expect_prompt=rb"\$",
    qcow=QCOW_PATH,
    extra_args=[
        "-M", "vexpress-a9",          # valid vexpress machine type
        "-cpu", "cortex-a9",
        "-dtb", "/opt/linux-5.15.162/arch/arm/boot/dts/vexpress-v2p-ca9.dtb",
        "-netdev", "tap,id=net0,ifname=tap0,script=no,downscript=no",
        "-device", "virtio-net-device,netdev=net0",
        "-serial", "mon:stdio",
    ]
)


# ---------------------------------------------------------------------------
# Memory acquisition
# ---------------------------------------------------------------------------
def acquire_memory(session_id: str, trigger_event: dict) -> str:
    """Acquire full guest RAM via PANDA physical_memory_read — guest unaware."""
    ts        = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    dump_path = f"{DUMP_DIR}/memdump_{session_id}_{ts}.raw"

    # Correct API: panda.physical_memory_read(addr, length)
    raw = panda.physical_memory_read(0x0, 512 * 1024 * 1024)
    with open(dump_path, "wb") as f:
        f.write(raw)

    # Hash BEFORE compression (forensic chain of custody requirement)
    with open(dump_path, "rb") as f:
        sha256_pre = hashlib.sha256(f.read()).hexdigest()

    # Compress to save /forensics space (~75% reduction)
    subprocess.run(["zstd", "-9", "--rm", dump_path, "-o", dump_path + ".zst"], check=True)
    compressed_path = dump_path + ".zst"

    # Append to evidence manifest (JSONL, one object per line)
    entry = {
        "session_id":       session_id,
        "dump_path":        compressed_path,
        "sha256_pre_compress": sha256_pre,
        "trigger_event":    trigger_event,
        "timestamp_utc":    ts,
        "plane":            "memory_forensics_gap3",
    }
    with open(MANIFEST, "a") as m:
        m.write(json.dumps(entry) + "\n")

    # Run Volatility 3 asynchronously against the fresh dump
    vol_out = f"/forensics/zeek/vol_{session_id}.json"
    subprocess.Popen([
        "python3", "-m", "volatility3",
        "-f", compressed_path,          # zstd decompresses on-the-fly
        "-s", ISF_PATH,
        "linux.pslist",
        "linux.proc_maps",
        "linux.pstree",
        "--output-file", vol_out,
        "--output", "json"
    ])

    return compressed_path


# ---------------------------------------------------------------------------
# Optional: monitor execution callback (basic block level)
# NOTE: cb_before_block_exec has ~10% overhead — keep lightweight
# ---------------------------------------------------------------------------
@panda.cb_before_block_exec(enabled=False)
def monitor_execution(cpu, tb):
    """
    Fires before every basic block executes in guest.
    Disabled by default — enable selectively for specific analysis.
    Uses correct callback signature: (cpu, tb) not (cpustate, transblock).
    """
    pc = panda.current_pc(cpu)
    # Placeholder — full implementation uses PANDA OSI plugin for process context
    pass


# ---------------------------------------------------------------------------
# Flask webhook server — receives triggers from session_correlator.py
# ---------------------------------------------------------------------------
def start_trigger_server():
    from flask import Flask, request as flask_request

    app = Flask(__name__)

    @app.route("/trigger-dump", methods=["POST"])
    def trigger():
        event      = flask_request.json
        session_id = event.get("session_id", "unknown")

        # NOTE: vexpress-a9 record/replay checkpoint is NOT used here.
        # PANDA Issue #643: savevm/loadvm is broken for vexpress-a9.
        # Forensic collection via physical_memory_read is unaffected.

        try:
            dump_path = acquire_memory(session_id, event)
            return {"status": "acquired", "dump": dump_path, "session_id": session_id}, 200
        except Exception as e:
            print(f"[{datetime.datetime.utcnow().isoformat()}Z] ERROR session={session_id}: {e}", flush=True)
            return {"status": "error", "error": str(e), "session_id": session_id}, 500

    # Bind to localhost ONLY — never expose externally
    app.run(host="127.0.0.1", port=9000, threaded=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
t = threading.Thread(target=start_trigger_server, daemon=True)
t.start()

print("[PANDA] Webhook server started on 127.0.0.1:9000", flush=True)
print("[PANDA] Starting ARM guest...", flush=True)
panda.run()
