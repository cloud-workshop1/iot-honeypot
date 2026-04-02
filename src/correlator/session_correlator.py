"""
session_correlator.py
Deploy to: /opt/correlator/session_correlator.py

Reads Tetragon JSON event stream from stdin (piped from `tetra getevents`).
Maps attacker IP → session_id, writes Plane 1 artifacts to evidence manifest,
triggers PANDA memory dumps (Gap 3), and tags Zeek sessions (Gap 6).

Fixes from Plan.pdf:
  - uuid.uuid4() correct call (not uuid.uuid4.uuid4())
  - manifest writes use JSON objects {} (not arrays [])
  - session_id assigned before use in correlation_tag block
"""

import sys, json, uuid, datetime, requests

MANIFEST_PATH   = "/forensics/manifest/evidence_manifest.jsonl"
SESSIONS_PATH   = "/forensics/manifest/active_sessions.jsonl"
TRIGGER_PORT    = 9000

# Tetragon function names that create a forensic session
TRIGGER_FUNCTIONS = {
    "sys_memfd_create": "fileless_staging",
    "sys_ptrace":       "process_injection",
    "tcp_connect":      "lateral_movement",
    "sys_execve":       "binary_execution",
}

# In-memory map: src_ip → session_id (reuses session for same attacker IP)
active_sessions: dict = {}


def utc_now() -> str:
    return datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


def process_tetragon_event(event: dict) -> None:
    func = event.get("function_name", "")
    if func not in TRIGGER_FUNCTIONS:
        return

    event_type = TRIGGER_FUNCTIONS[func]
    ts         = utc_now()

    # Extract attacker source IP from Tetragon event structure
    src_ip = (
        event.get("process", {})
             .get("pod", {})
             .get("host_ip", "unknown")
    )

    # Reuse session_id if this attacker IP already has an active session
    if src_ip not in active_sessions:
        session_id = str(uuid.uuid4())          # Correct: uuid.uuid4() not uuid.uuid4.uuid4()
        active_sessions[src_ip] = session_id
    else:
        session_id = active_sessions[src_ip]

    # --- Plane 1: Write ZTA forensic artifact to evidence manifest ---
    plane1 = {
        "session_id":  session_id,
        "timestamp":   ts,
        "plane":       "network_forensics_gap2",
        "event_type":  event_type,
        "function":    func,
        "src_ip":      src_ip,
        "process":     event.get("process", {}).get("binary", ""),
        "parent":      event.get("parent",  {}).get("binary", ""),
        "raw_event":   event,
    }
    with open(MANIFEST_PATH, "a") as m:
        m.write(json.dumps(plane1) + "\n")

    # --- Gap 3 bridge: Trigger PANDA memory dump for high-value events ---
    if event_type in ("fileless_staging", "process_injection"):
        try:
            requests.post(
                f"http://127.0.0.1:{TRIGGER_PORT}/trigger-dump",
                json={"event": event, "session_id": session_id},
                timeout=2
            )
        except requests.exceptions.RequestException as e:
            print(f"[{ts}] WARN: PANDA trigger failed for session={session_id}: {e}", flush=True)

    # --- Gap 6 bridge: Tag Zeek session for LegalTrace correlation ---
    correlation_tag = {
        "session_id": session_id,
        "src_ip":     src_ip,
        "start_ts":   ts,
        "trigger":    event_type,
    }
    with open(SESSIONS_PATH, "a") as af:
        af.write(json.dumps(correlation_tag) + "\n")

    print(f"[{ts}] SESSION {session_id} | {event_type} | {src_ip} | {func}", flush=True)


# ---------------------------------------------------------------------------
# Main: read Tetragon JSON stream from stdin
# Invoked as: docker exec tetragon /usr/bin/tetra getevents --output json \
#               --include-fields "process,parent,function_name,args,time" \
#             | python3 /opt/correlator/session_correlator.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print(f"[{utc_now()}] Session correlator started", flush=True)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
            process_tetragon_event(event)
        except json.JSONDecodeError:
            continue
        except Exception as e:
            print(f"[{utc_now()}] ERROR processing event: {e}", flush=True)
            continue
