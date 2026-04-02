"""
figures_sembridge.py
Deploy to: /opt/scripts/figures_sembridge.py

Generates all figures for the SemBridge paper (Gap 3 / PANDA memory forensics).
Run after 7-day sprint: python3 /opt/scripts/figures_sembridge.py

Outputs PDF + PNG to /forensics/figures/sembridge/
Install deps: pip3 install matplotlib seaborn pandas numpy
"""

import json, os, glob
from datetime import datetime
from collections import Counter

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np

sns.set_theme(style="whitegrid", palette="muted", font_scale=1.1)

OUT      = "/forensics/figures/sembridge"
MANIFEST = "/forensics/manifest/evidence_manifest.jsonl"
DUMP_DIR = "/forensics/memdump"

os.makedirs(OUT, exist_ok=True)


def save_fig(fig, name: str) -> None:
    for ext in ("pdf", "png"):
        fig.savefig(f"{OUT}/{name}.{ext}", dpi=300, bbox_inches="tight")
    print(f"  Saved: {name}.pdf + {name}.png")
    plt.close(fig)


def load_gap3_entries() -> list:
    entries = []
    try:
        with open(MANIFEST) as f:
            for line in f:
                try:
                    e = json.loads(line.strip())
                    if e.get("plane") == "memory_forensics_gap3":
                        entries.append(e)
                except json.JSONDecodeError:
                    pass
    except FileNotFoundError:
        pass
    return entries


# ---------------------------------------------------------------------------
print("Generating SemBridge figures...")
dumps = load_gap3_entries()

if not dumps:
    print("No Gap 3 (memory_forensics_gap3) entries found — run after sprint.")
    exit(0)

print(f"  Found {len(dumps)} memory dump manifest entries")

# ---------------------------------------------------------------------------
# Figure 1: Memory Acquisition Latency Distribution
# Latency = time between Tetragon trigger event and dump completion
# ---------------------------------------------------------------------------
latencies = []
for d in dumps:
    try:
        trigger_ts = d.get("trigger_event", {}).get("time", "")
        dump_ts    = d.get("timestamp_utc", "")
        if trigger_ts and dump_ts:
            t1 = datetime.fromisoformat(trigger_ts.replace("Z", "+00:00"))
            t2 = datetime.fromisoformat(dump_ts.replace("Z", "+00:00"))
            ms = (t2 - t1).total_seconds() * 1000
            if 0 < ms < 10000:   # sanity filter: 0–10 seconds
                latencies.append(ms)
    except (ValueError, TypeError):
        pass

if latencies:
    arr  = np.array(latencies)
    mean = np.mean(arr)
    std  = np.std(arr)
    p95  = np.percentile(arr, 95)

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.hist(arr, bins=30, color="#9b59b6", alpha=0.8, edgecolor="white", linewidth=0.5)
    ax.axvline(mean, color="#e74c3c", linestyle="--", linewidth=2,
               label=f"Mean: {mean:.0f}ms")
    ax.axvline(p95, color="#f39c12", linestyle="--", linewidth=2,
               label=f"95th pct: {p95:.0f}ms")
    ax.axvline(200, color="#2ecc71", linestyle="-.", linewidth=1.5, alpha=0.7,
               label="200ms target window")
    ax.set_xlabel("Acquisition Latency (ms)", fontsize=12)
    ax.set_ylabel("Number of Dumps", fontsize=12)
    ax.set_title(
        f"SemBridge: Memory Acquisition Latency Distribution\n"
        f"(Tetragon Trigger → Dump Complete, n={len(latencies)}, σ={std:.0f}ms)",
        fontsize=13, fontweight="bold"
    )
    ax.legend(fontsize=11)
    plt.tight_layout()
    save_fig(fig, "fig1_acquisition_latency")
    print(f"  Latency: mean={mean:.1f}ms std={std:.1f}ms p95={p95:.1f}ms n={len(latencies)}")
else:
    print("  SKIP fig1: insufficient latency data")

# ---------------------------------------------------------------------------
# Figure 2: Trigger Event Type Breakdown (horizontal bar)
# ---------------------------------------------------------------------------
trigger_types = [
    d.get("trigger_event", {}).get("function_name",
    d.get("trigger_event", {}).get("func_name", "unknown"))
    for d in dumps
]
tc = Counter(trigger_types)

fig, ax = plt.subplots(figsize=(9, 5))
colors = ["#9b59b6", "#3498db", "#e74c3c", "#2ecc71"]
bars   = ax.barh(list(tc.keys()), list(tc.values()),
                 color=colors[:len(tc)], alpha=0.85, edgecolor="white")
ax.bar_label(bars, padding=4, fontsize=11)
ax.set_xlabel("Memory Dumps Triggered", fontsize=12)
ax.set_title("SemBridge: Memory Dump Triggers by Syscall Type", fontsize=13, fontweight="bold")
ax.invert_yaxis()
plt.tight_layout()
save_fig(fig, "fig2_trigger_types")

# ---------------------------------------------------------------------------
# Figure 3: Dump File Size Distribution (compressed)
# ---------------------------------------------------------------------------
sizes_mb = []
for d in dumps:
    path = d.get("dump_path", "")
    if path and os.path.exists(path):
        sizes_mb.append(os.path.getsize(path) / (1024 * 1024))

if sizes_mb:
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.hist(sizes_mb, bins=20, color="#3498db", alpha=0.8, edgecolor="white")
    ax.axvline(np.mean(sizes_mb), color="#e74c3c", linestyle="--", linewidth=2,
               label=f"Mean: {np.mean(sizes_mb):.0f}MB")
    ax.set_xlabel("Compressed Dump Size (MB)", fontsize=12)
    ax.set_ylabel("Count", fontsize=12)
    ax.set_title("SemBridge: Memory Dump Compressed Size Distribution\n(zstd -9, 512MB guest RAM)", fontsize=13, fontweight="bold")
    ax.legend()
    plt.tight_layout()
    save_fig(fig, "fig3_dump_sizes")

# ---------------------------------------------------------------------------
# Figure 4: Dumps Per Day Timeline
# ---------------------------------------------------------------------------
day_counts: dict = {}
for d in dumps:
    ts = d.get("timestamp_utc", "")
    if ts:
        try:
            day = datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%Y-%m-%d")
            day_counts[day] = day_counts.get(day, 0) + 1
        except ValueError:
            pass

if day_counts:
    dates  = sorted(day_counts.keys())
    counts = [day_counts[d] for d in dates]
    labels = [datetime.strptime(d, "%Y-%m-%d").strftime("%b %d") for d in dates]

    fig, ax = plt.subplots(figsize=(10, 5))
    bars = ax.bar(labels, counts, color="#9b59b6", alpha=0.85, edgecolor="white", width=0.6)
    ax.bar_label(bars, padding=3, fontsize=11)
    ax.set_xlabel("Date (UTC)", fontsize=12)
    ax.set_ylabel("Memory Dumps Acquired", fontsize=12)
    ax.set_title("SemBridge: Daily Memory Dump Acquisition Count", fontsize=13, fontweight="bold")
    plt.xticks(rotation=20, ha="right")
    plt.tight_layout()
    save_fig(fig, "fig4_daily_dumps")

print(f"\nSemBridge figures complete → {OUT}/")
