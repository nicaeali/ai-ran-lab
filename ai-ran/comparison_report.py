"""Student-facing CSV, Markdown, and plots; retain failed/missing outcomes."""

import csv
import math
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


LABELS = {"rf": "Random Forest", "byte-periodic": "Weak byte rule (10 s reports)"}
COLORS = {"rf": "#0072B2", "byte-periodic": "#D55E00"}


def summary_row(trial):
    values = trial["metrics"]["impact"]
    attack = trial["attack_start"]
    releases = [event["time"] - attack for event in trial["release_commands"]
                if attack is not None and event["ue_id"] == 1 and event["time"] >= attack]
    return {"scenario": trial["scenario"], "pair": trial["pair"], "detector": trial["config"]["detector"],
            "ue2_mbps": values["ue2_mbps"], "ue2_rtt_mean_ms": values["ue2_rtt_mean_ms"],
            "ue2_rtt_median_ms": values["ue2_rtt_median_ms"], "ue2_loss_percent": trial["ping_total"]["loss_percent"],
            "upf1_cpu_percent": values["upf1_cpu_percent"], "upf2_cpu_percent": values["upf2_cpu_percent"],
            "upf1_memory_mib": values["upf1_memory_mib"], "upf2_memory_mib": values["upf2_memory_mib"],
            "host_cpu_percent": values["host_cpu_percent"], "host_used_mib": values["host_used_mib"],
            "detectors_cpu_percent": values["detectors_cpu_percent"], "detectors_rss_mib": values["detectors_rss_mib"],
            "gnb_cpu_percent": values["gnb_cpu_percent"], "xapp_cpu_percent": values["xapp_cpu_percent"],
            "ue1_release_delay_s": min(releases) if releases else None,
            "benign_release_commands": len(trial["benign_release_commands"]),
            "valid_runtime": trial["valid_runtime"], "valid_measurements": trial["valid_measurements"],
            "utilization_valid": trial["utilization_valid"]}


def fmt(value):
    return "NA" if value is None else f"{value:.2f}" if isinstance(value, float) else str(value)


def mark_events(ax, trial):
    if trial["attack_start"] is not None:
        ax.axvline(trial["attack_start"], color="#AA2222", linestyle=":", linewidth=1)
    for event in trial["release_commands"]:
        ax.axvline(event["time"], color="#AA2222" if event in trial["benign_release_commands"] else "#555555",
                   linestyle="--", linewidth=0.8)
    ax.set_xlim(0, 62)
    ax.grid(alpha=0.25)


def interval_trace(ax, rows, key, label, color):
    x, y, previous = [], [], None
    for row in rows:
        if row.get(key) is None:
            x.append(float("nan")); y.append(float("nan"))
            previous = None
            continue
        if previous is not None and row["start"] - previous > 0.1:
            x.append(float("nan")); y.append(float("nan"))
        x.extend((row["start"], row["end"]))
        y.extend((row[key], row[key]))
        previous = row["end"]
    ax.plot(x, y, label=label, color=color, linewidth=1.1)


def plots(trials, directory):
    plt.rcParams.update({"font.size": 8, "axes.spines.top": False, "axes.spines.right": False})
    for kind, title, ylabel in (("throughput", "Receiver goodput", "Mbit/s"),
                                ("cpu-utilization", "UPF container CPU utilization (paper Figure 7 metric)", "% of one logical CPU"),
                                ("memory-utilization", "Detector resident memory", "MiB, sum of two RSS values")):
        fig, axes = plt.subplots(4, 2, figsize=(12, 10), sharex=True, squeeze=False)
        for trial in trials:
            ax = axes[trial["pair"], 0 if trial["config"]["detector"] == "rf" else 1]
            if kind == "throughput":
                for ue, color in ((1, "#D55E00"), (2, "#0072B2")):
                    interval_trace(ax, trial["throughput"][f"ue{ue}"], "mbps", f"UE{ue}", color)
            elif kind == "cpu-utilization":
                interval_trace(ax, trial["resources"], "upf1_cpu_percent", "UPF1 container", "#D55E00")
                interval_trace(ax, trial["resources"], "upf2_cpu_percent", "UPF2 container", "#0072B2")
            else:
                interval_trace(ax, trial["resources"], "detectors_rss_mib", "Detectors RSS", "#0072B2")
            mark_events(ax, trial)
            valid = trial["valid_runtime"] and trial["valid_measurements"] and trial["utilization_valid"]
            case = "Clean control" if trial["scenario"] == "clean" else f"Attack pair {trial['pair']}"
            ax.set_title(case + " — " + LABELS[trial["config"]["detector"]] + ("" if valid else " [inspect flags]"))
            ax.set_ylabel(ylabel)
            ax.set_ylim(bottom=0)
            ax.legend(loc="upper right", fontsize=6)
        # Use identical y limits within each matched pair of panels.
        for row in axes:
            upper = 1.08 * max((float(value) for ax in row for line in ax.lines
                                for value in line.get_ydata() if math.isfinite(value)), default=1)
            for ax in row:
                ax.set_ylim(0, upper)
        for ax in axes[-1]:
            ax.set_xlabel("Seconds from measurement start")
        fig.suptitle(title + ": AI versus intentionally weaker heuristic", fontsize=13)
        fig.text(0.5, 0.005, "Dotted: attack onset. Dashed: release request (red = benign). Missing observations are not zero-filled.", ha="center")
        fig.tight_layout(rect=(0, 0.02, 1, 0.97))
        for extension in ("png", "svg"):
            fig.savefig(directory / f"{kind}.{extension}", dpi=150)
        plt.close(fig)
    fig, axes = plt.subplots(4, 1, figsize=(11, 9), sharex=True)
    for trial in trials:
        ax = axes[trial["pair"]]
        x, y, previous = [], [], None
        for point in sorted(trial["ping"], key=lambda p: p["seq"]):
            if previous is not None and point["seq"] != previous + 1:
                x.append(float("nan")); y.append(float("nan"))
            x.append(point["send_time"]); y.append(point["rtt_ms"])
            previous = point["seq"]
        detector = trial["config"]["detector"]
        ax.plot(x, y, ".-", color=COLORS[detector], linewidth=0.8, markersize=2,
                label=f"{LABELS[detector]}: {trial['ping_total']['loss_percent']:.2f}% trial loss")
        if trial["attack_start"] is not None:
            ax.axvline(trial["attack_start"], color="#AA2222", linestyle=":", linewidth=0.8)
        ax.set(title="Clean control" if trial["pair"] == 0 else f"Attack pair {trial['pair']}", ylabel="UE2 RTT (ms)", xlim=(0, 50), ylim=(0, None))
        ax.grid(alpha=0.25)
        ax.legend(fontsize=7)
    for pair, ax in enumerate(axes):
        upper = 1.08 * max((point["rtt_ms"] for trial in trials if trial["pair"] == pair
                           for point in trial["ping"]), default=1)
        ax.set_ylim(0, upper)
    axes[-1].set_xlabel("Probe send time from measurement start (s)")
    fig.suptitle("Legitimate-UE latency and loss", fontsize=14)
    fig.tight_layout(rect=(0, 0, 1, 0.97))
    for extension in ("png", "svg"):
        fig.savefig(directory / f"latency.{extension}", dpi=150)
    plt.close(fig)


def write_report(campaign, folder):
    rows = [summary_row(trial) for trial in campaign["trials"]]
    text = ["# AI versus weaker heuristic: measured comparison", "", campaign["design"], "", campaign["scope"], "",
            f"Complete: **{campaign['complete']}**. Recorded trials: **{len(rows)}/8**.",
            f"Evidence directory: `{folder}`.", "",
            "The heuristic classifies low-byte packets using cutoff 28 and reports at most every 10 seconds. RF reports every window.",
            "Both use the original extractor, 30-packet windows, 10-packet steps, controller, and workloads. This deliberately includes a reporting-cadence disadvantage.", "",
            "Impact means use [15,48) s for both clean and attack trials; this includes the attack response period. Baseline [5,15), post-event [20,48), and late [25,48) metrics remain in each summary.json.",
            "Ping loss covers the whole trial. RTT is measured on received replies. Release delay is command launch to captured release request, not inference time or completed RRC release.", "",
            "## Throughput, latency, and UPF CPU utilization", "",
            "| Scenario/pair | Method | UE2 Mbit/s | UE2 RTT ms | Ping loss % | UPF1 CPU % | UPF2 CPU % |",
            "|---|---|---:|---:|---:|---:|---:|"]
    for row in rows:
        text.append("| " + " | ".join([f"{row['scenario']}/{row['pair']}", LABELS[row["detector"]],
            *[fmt(row[key]) for key in ("ue2_mbps", "ue2_rtt_mean_ms", "ue2_loss_percent", "upf1_cpu_percent", "upf2_cpu_percent")]]) + " |")
    text += ["", "## Compute overhead and outcomes", "",
             "| Scenario/pair | Method | Host CPU % | Detector CPU % | Detector RSS MiB | Release delay s | Benign releases | Runtime / network / utilization valid |",
             "|---|---|---:|---:|---:|---:|---:|---|"]
    for row in rows:
        text.append("| " + " | ".join([f"{row['scenario']}/{row['pair']}", LABELS[row["detector"]],
            *[fmt(row[key]) for key in ("host_cpu_percent", "detectors_cpu_percent", "detectors_rss_mib", "ue1_release_delay_s", "benign_release_commands")],
            f"{row['valid_runtime']} / {row['valid_measurements']} / {row['utilization_valid']}"]) + " |")
    text += ["", "Utilization follows the paper's Figure 7 metric: CPU use of the UPF Docker containers. Cgroup CPU-time deltas are normalized to one logical CPU (100% = one fully busy CPU); values can exceed 100%. This includes each UPF's detector. CPU use is not an energy measurement. Our comparator is a weaker heuristic, whereas the paper compares defense on/off.",
             "Host CPU is normalized to the whole machine; detector CPU to one logical CPU (sum may exceed 100%). Detector RSS sums two processes and can double-count shared pages; host memory and individual process metrics are in summary.csv/summary.json.",
             "All outcomes remain in the report, including benign releases, runtime faults, incomplete coverage, and no observed release. NA means missing, not zero. Three attack pairs are descriptive, not a guarantee of AI superiority."]
    if campaign.get("error"):
        text += ["", "Run error: " + campaign["error"]]
    if rows:
        with (folder / "summary.csv").open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader(); writer.writerows(rows)
        plots(campaign["trials"], folder)
        for name in ("throughput", "latency", "cpu-utilization", "memory-utilization"):
            text += ["", f"![{name}]({name}.png)"]
    (folder / "comparison.md").write_text("\n".join(text) + "\n")
