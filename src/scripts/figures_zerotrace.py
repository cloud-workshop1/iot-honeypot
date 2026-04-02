"""
figures_zerotrace.py
Deploy to: /opt/scripts/figures_zerotrace.py

Generates all figures for the ZeroTrace paper (Gap 2 / Tetragon eBPF).
Run after 7-day sprint: python3 /opt/scripts/figures_zerotrace.py

Outputs PDF + PNG for each figure to /forensics/figures/zerotrace/
Install deps: pip3 install matplotlib seaborn pandas
"""

import json, os, glob
from collections import Counter, defaultdict
from datetime import datetime

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import seaborn as sns
import pandas as pd
import numpy as np

sns.set_theme(style="darkgrid", palette="deep", font_scale=1.1)

OUT = "/forensics/figures/zerotrace"
os.makedirs(OUT, exist_ok=True)

TETRAGON_DIR = "/forensics/tetragon"
MANIFEST     = "/forensics/manifest/evidence_manifest.jsonl"


def save_fig(fig, name: str) -> None:
    for ext in ("pdf", "png"):
        path = f"{OUT}/{name}.{ext}"
        fig.savefig(path, dpi=300, bbox_inches="tight")
    print(f"  Saved: {name}.pdf + {name}.png")
    plt.close(fig)


def load_tetragon_events() -> list:
    events = []
    for f in sorted(glob.glob(f"{TETRAGON_DIR}/*.json")):
        with open(f) as fh:
            for line in fh:
                try:
                    events.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    pass
    return events


def load_manifest_gap2() -> list:
    entries = []
    try:
        with open(MANIFEST) as f:
            for line in f:
                try:
                    e = json.loads(line.strip())
                    if e.get("plane") == "network_forensics_gap2":
                        entries.append(e)
                except json.JSONDecodeError:
                    pass
    except FileNotFoundError:
        pass
    return entries


# ---------------------------------------------------------------------------
print("Generating ZeroTrace figures...")
events  = load_tetragon_events()
entries = load_manifest_gap2()

if not events and not entries:
    print("No data found — run after 7-day sprint completes.")
    exit(0)

# ---------------------------------------------------------------------------
# Figure 1: ZTA Violation Event Timeline (hourly rate over 7 days)
# ---------------------------------------------------------------------------
timestamps = []
for e in events:
    t = e.get("time") or e.get("timestamp", "")
    if t:
        try:
            timestamps.append(datetime.fromisoformat(t.replace("Z", "+00:00")))
        except ValueError:
            pass

if timestamps:
    df_ts = pd.DataFrame({"ts": timestamps})
    df_ts["hour"] = df_ts["ts"].dt.floor("H")
    hourly = df_ts.groupby("hour").size().reset_index(name="count")

    fig, ax = plt.subplots(figsize=(14, 5))
    ax.fill_between(hourly["hour"], hourly["count"], alpha=0.5, color="#e74c3c")
    ax.plot(hourly["hour"], hourly["count"], color="#c0392b", linewidth=1.5)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%b %d"))
    ax.xaxis.set_major_locator(mdates.DayLocator())
    ax.set_xlabel("Date (UTC)", fontsize=12)
    ax.set_ylabel("ZTA Violation Events / Hour", fontsize=12)
    ax.set_title("ZeroTrace: ZTA Violation Event Rate — 7-Day Deployment", fontsize=14, fontweight="bold")
    plt.xticks(rotation=20, ha="right")
    plt.tight_layout()
    save_fig(fig, "fig1_violation_timeline")
else:
    print("  SKIP fig1: no timestamp data in Tetragon events")

# ---------------------------------------------------------------------------
# Figure 2: Event Type Distribution (pie chart)
# ---------------------------------------------------------------------------
func_names = [e.get("function_name", e.get("func_name", "unknown")) for e in events]
counts = Counter(func_names)
if counts:
    labels = list(counts.keys())
    sizes  = list(counts.values())
    colors = ["#e74c3c", "#3498db", "#2ecc71", "#f39c12", "#9b59b6"]

    fig, ax = plt.subplots(figsize=(8, 8))
    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, colors=colors[:len(labels)],
        autopct="%1.1f%%", startangle=90, pctdistance=0.82,
        wedgeprops={"linewidth": 1.5, "edgecolor": "white"}
    )
    for at in autotexts:
        at.set_fontsize(11)
    ax.set_title("ZeroTrace: ZTA Events by Syscall Type", fontsize=14, fontweight="bold")
    plt.tight_layout()
    save_fig(fig, "fig2_event_types")

# ---------------------------------------------------------------------------
# Figure 3: Unique Source IPs Per Day
# ---------------------------------------------------------------------------
src_by_day = defaultdict(set)
for e in entries:
    ts  = e.get("timestamp", "")
    src = e.get("src_ip", "")
    if ts and src and src != "unknown":
        try:
            d = datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%Y-%m-%d")
            src_by_day[d].add(src)
        except ValueError:
            pass

if src_by_day:
    dates      = sorted(src_by_day.keys())
    ip_counts  = [len(src_by_day[d]) for d in dates]
    date_labels = [datetime.strptime(d, "%Y-%m-%d").strftime("%b %d") for d in dates]

    fig, ax = plt.subplots(figsize=(10, 5))
    bars = ax.bar(date_labels, ip_counts, color="#3498db", alpha=0.85, edgecolor="white", width=0.6)
    ax.bar_label(bars, padding=3, fontsize=10)
    ax.set_xlabel("Date (UTC)", fontsize=12)
    ax.set_ylabel("Unique Attacker Source IPs", fontsize=12)
    ax.set_title("ZeroTrace: Daily Unique Attacker IP Count", fontsize=14, fontweight="bold")
    plt.xticks(rotation=20, ha="right")
    plt.tight_layout()
    save_fig(fig, "fig3_daily_unique_ips")

# ---------------------------------------------------------------------------
# Figure 4: Event Rate Heatmap (hour of day × day of week)
# ---------------------------------------------------------------------------
if timestamps:
    df_heat = pd.DataFrame({"ts": timestamps})
    df_heat["hour"] = df_heat["ts"].dt.hour
    df_heat["day"]  = df_heat["ts"].dt.day_name()
    day_order = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"]
    pivot = df_heat.groupby(["day","hour"]).size().unstack(fill_value=0)
    pivot = pivot.reindex([d for d in day_order if d in pivot.index])

    fig, ax = plt.subplots(figsize=(14, 5))
    sns.heatmap(pivot, ax=ax, cmap="YlOrRd", linewidths=0.3,
                cbar_kws={"label": "Event Count"})
    ax.set_xlabel("Hour of Day (UTC)", fontsize=12)
    ax.set_ylabel("Day of Week", fontsize=12)
    ax.set_title("ZeroTrace: ZTA Violation Activity Heatmap (Hour × Day)", fontsize=14, fontweight="bold")
    plt.tight_layout()
    save_fig(fig, "fig4_activity_heatmap")

print(f"\nZeroTrace figures complete → {OUT}/")
