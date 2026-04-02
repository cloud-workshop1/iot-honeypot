"""
figures_legaltrace.py
Deploy to: /opt/scripts/figures_legaltrace.py

Generates all figures for the LegalTrace paper (Gap 6 / RITA + chain of custody).
Run after 7-day sprint: python3 /opt/scripts/figures_legaltrace.py

Outputs PDF + PNG to /forensics/figures/legaltrace/
Install deps: pip3 install matplotlib seaborn pandas numpy
"""

import json, os, glob
from datetime import datetime
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns
import pandas as pd
import numpy as np

sns.set_theme(style="whitegrid", palette="muted", font_scale=1.1)

OUT      = "/forensics/figures/legaltrace"
MANIFEST = "/forensics/manifest/evidence_manifest.jsonl"
RITA_DIR = "/forensics/rita"

os.makedirs(OUT, exist_ok=True)


def save_fig(fig, name: str) -> None:
    for ext in ("pdf", "png"):
        fig.savefig(f"{OUT}/{name}.{ext}", dpi=300, bbox_inches="tight")
    print(f"  Saved: {name}.pdf + {name}.png")
    plt.close(fig)


def load_rita_beacons() -> list:
    all_beacons = []
    for f in sorted(glob.glob(f"{RITA_DIR}/beacons-*.json")):
        try:
            with open(f) as fh:
                data = json.load(fh)
                if isinstance(data, list):
                    all_beacons.extend(data)
                elif isinstance(data, dict):
                    all_beacons.append(data)
        except (json.JSONDecodeError, OSError):
            pass
    return all_beacons


def load_manifest() -> list:
    entries = []
    try:
        with open(MANIFEST) as f:
            for line in f:
                try:
                    entries.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    pass
    except FileNotFoundError:
        pass
    return entries


# ---------------------------------------------------------------------------
print("Generating LegalTrace figures...")
beacons  = load_rita_beacons()
manifest = load_manifest()

if not beacons and not manifest:
    print("No RITA or manifest data — run after sprint completes.")
    exit(0)

# ---------------------------------------------------------------------------
# Figure 1: RITA Beacon Score Histogram with Classification Zones
# ---------------------------------------------------------------------------
if beacons:
    scores = []
    for b in beacons:
        s = b.get("Score") or b.get("beacon_score") or b.get("score")
        if s is not None:
            try:
                scores.append(float(s))
            except (TypeError, ValueError):
                pass

    if scores:
        arr = np.array(scores)
        automated = np.sum(arr >= 0.80)
        human     = np.sum(arr < 0.25)
        ambiguous = len(arr) - automated - human

        fig, ax = plt.subplots(figsize=(12, 6))

        # Classification zone shading
        ax.axvspan(0.0,  0.25, alpha=0.12, color="#e74c3c", zorder=0)
        ax.axvspan(0.25, 0.80, alpha=0.08, color="#f39c12", zorder=0)
        ax.axvspan(0.80, 1.0,  alpha=0.12, color="#2ecc71", zorder=0)

        ax.hist(arr, bins=50, color="#3498db", alpha=0.85, edgecolor="white", linewidth=0.4, zorder=2)

        # Threshold lines
        ax.axvline(0.25, color="#e74c3c", linestyle="--", linewidth=1.5, alpha=0.8, zorder=3)
        ax.axvline(0.80, color="#2ecc71", linestyle="--", linewidth=1.5, alpha=0.8, zorder=3)

        # Legend patches
        patches = [
            mpatches.Patch(color="#e74c3c", alpha=0.5, label=f"Human Actor (<0.25): {human}"),
            mpatches.Patch(color="#f39c12", alpha=0.5, label=f"Ambiguous (0.25–0.80): {ambiguous}"),
            mpatches.Patch(color="#2ecc71", alpha=0.5, label=f"Automated Scanner (>0.80): {automated}"),
        ]
        ax.legend(handles=patches, loc="upper center", fontsize=10)

        ax.set_xlabel("RITA Beacon Score (0 = human, 1 = automated)", fontsize=12)
        ax.set_ylabel("Number of Source IPs", fontsize=12)
        ax.set_title(
            f"LegalTrace: RITA Beacon Score Distribution — {len(scores):,} Source IPs\n"
            f"Threshold: <0.25 Human Actor | >0.80 Automated Scanner",
            fontsize=13, fontweight="bold"
        )
        plt.tight_layout()
        save_fig(fig, "fig1_beacon_score_histogram")
        print(f"  Beacon scores: n={len(scores)}, human={human}, automated={automated}, ambiguous={ambiguous}")

# ---------------------------------------------------------------------------
# Figure 2: Classification Breakdown Donut Chart
# ---------------------------------------------------------------------------
    if scores:
        class_counts = {
            "Automated Scanner": int(automated),
            "Ambiguous":         int(ambiguous),
            "Human Actor":       int(human),
        }
        class_counts = {k: v for k, v in class_counts.items() if v > 0}
        colors_map   = {"Automated Scanner": "#2ecc71", "Ambiguous": "#f39c12", "Human Actor": "#e74c3c"}

        fig, ax = plt.subplots(figsize=(8, 8))
        wedge_props = {"linewidth": 2, "edgecolor": "white"}
        wedges, texts, autotexts = ax.pie(
            list(class_counts.values()),
            labels=list(class_counts.keys()),
            colors=[colors_map[k] for k in class_counts],
            autopct="%1.1f%%",
            startangle=90,
            pctdistance=0.80,
            wedgeprops=wedge_props,
        )
        # Draw inner circle for donut effect
        centre = plt.Circle((0, 0), 0.55, fc="white")
        ax.add_artist(centre)
        ax.text(0, 0, f"n={len(scores):,}", ha="center", va="center",
                fontsize=14, fontweight="bold", color="#333")
        for at in autotexts:
            at.set_fontsize(12)
        ax.set_title("LegalTrace: Traffic Classification\n(RITA Beacon Score Thresholds)", fontsize=13, fontweight="bold")
        plt.tight_layout()
        save_fig(fig, "fig2_classification_donut")

# ---------------------------------------------------------------------------
# Figure 3: Evidence Chain of Custody — Daily Artifact Collection by Plane
# ---------------------------------------------------------------------------
if manifest:
    planes      = ["network_forensics_gap2", "memory_forensics_gap3", "ediscovery_gap6"]
    plane_labels = {
        "network_forensics_gap2": "ZeroTrace (Gap 2)",
        "memory_forensics_gap3":  "SemBridge (Gap 3)",
        "ediscovery_gap6":        "LegalTrace (Gap 6)",
    }
    plane_colors = {
        "network_forensics_gap2": "#e74c3c",
        "memory_forensics_gap3":  "#9b59b6",
        "ediscovery_gap6":        "#3498db",
    }

    daily: dict = defaultdict(lambda: defaultdict(int))
    for e in manifest:
        ts    = e.get("timestamp_utc", e.get("timestamp", ""))
        plane = e.get("plane", "")
        if ts and plane:
            try:
                day = datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%Y-%m-%d")
                daily[day][plane] += 1
            except ValueError:
                pass

    if daily:
        dates       = sorted(daily.keys())
        date_labels = [datetime.strptime(d, "%Y-%m-%d").strftime("%b %d") for d in dates]
        n           = len(dates)
        bottom      = np.zeros(n)

        fig, ax = plt.subplots(figsize=(14, 6))
        for plane in planes:
            vals = np.array([daily[d].get(plane, 0) for d in dates])
            ax.bar(date_labels, vals, bottom=bottom,
                   label=plane_labels[plane],
                   color=plane_colors[plane], alpha=0.88, edgecolor="white")
            bottom += vals

        ax.set_xlabel("Date (UTC)", fontsize=12)
        ax.set_ylabel("Evidence Artifacts Collected", fontsize=12)
        ax.set_title(
            "LegalTrace: Evidence Chain of Custody\nDaily Artifact Collection by Forensic Plane",
            fontsize=13, fontweight="bold"
        )
        ax.legend(loc="upper left", fontsize=11)
        plt.xticks(rotation=20, ha="right")
        plt.tight_layout()
        save_fig(fig, "fig3_evidence_timeline")

# ---------------------------------------------------------------------------
# Figure 4: Cross-Plane Session Linkage (sessions appearing in all 3 planes)
# ---------------------------------------------------------------------------
if manifest:
    plane_sessions: dict = defaultdict(set)
    for e in manifest:
        sid   = e.get("session_id", "")
        plane = e.get("plane", "")
        if sid and plane:
            plane_sessions[plane].add(sid)

    p1 = plane_sessions.get("network_forensics_gap2", set())
    p2 = plane_sessions.get("memory_forensics_gap3",  set())
    p3 = plane_sessions.get("ediscovery_gap6",        set())

    linked    = p1 & p2 & p3
    p1_only   = p1 - p2 - p3
    p2_only   = p2 - p1 - p3
    p3_only   = p3 - p1 - p2
    p1_p2     = (p1 & p2) - p3
    p1_p3     = (p1 & p3) - p2
    p2_p3     = (p2 & p3) - p1

    categories = ["Gap2 only", "Gap3 only", "Gap6 only",
                  "Gap2+Gap3", "Gap2+Gap6", "Gap3+Gap6", "All 3 Planes"]
    values     = [len(p1_only), len(p2_only), len(p3_only),
                  len(p1_p2),  len(p1_p3),  len(p2_p3),  len(linked)]
    bar_colors = ["#e74c3c","#9b59b6","#3498db","#e67e22","#8e44ad","#2980b9","#27ae60"]

    fig, ax = plt.subplots(figsize=(12, 5))
    bars = ax.bar(categories, values, color=bar_colors, alpha=0.85, edgecolor="white", width=0.6)
    ax.bar_label(bars, padding=3, fontsize=11)
    ax.set_ylabel("Number of Sessions", fontsize=12)
    ax.set_title(
        f"LegalTrace: Cross-Plane Session Coverage\n"
        f"Sessions linked across all 3 planes: {len(linked)}",
        fontsize=13, fontweight="bold"
    )
    plt.xticks(rotation=15, ha="right")
    plt.tight_layout()
    save_fig(fig, "fig4_cross_plane_sessions")
    print(f"  Cross-plane: all 3 planes = {len(linked)}, total sessions = {len(p1|p2|p3)}")

print(f"\nLegalTrace figures complete → {OUT}/")
