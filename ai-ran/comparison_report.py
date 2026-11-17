"""Student-facing CSV, Markdown, and plots; retain failed/missing outcomes."""

import csv
import math
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


LABELS = {"rf": "Random Forest", "byte": "Heuristic (byte-only)", "byte-periodic": "Heuristic (10 s reports)", "tcp-flags": "Heuristic (TCP-aware)"}
COLORS = {"rf": "#0072B2", "byte": "#D55E00", "byte-periodic": "#D55E00", "tcp-flags": "#D55E00"}


def summary_row(trial):
    values = trial["metrics"]["impact"]
    attack = trial["attack_start"]
    releases = [event["time"] - attack for event in trial["release_commands"]
                if attack is not None and event["ue_id"] == 1 and event["time"] >= attack]
    row = {"scenario": trial["scenario"], "pair": trial["pair"], "detector": trial["config"]["detector"],
            "ue2_mbps": values["ue2_mbps"], "ue2_rtt_mean_ms": values["ue2_rtt_mean_ms"],
            "ue2_rtt_median_ms": values["ue2_rtt_median_ms"], "ue2_loss_percent": trial["ping_total"]["loss_percent"],
            "upf1_cpu_percent": values["upf1_cpu_percent"], "upf2_cpu_percent": values["upf2_cpu_percent"],
            "upf1_memory_mib": values["upf1_memory_mib"], "upf2_memory_mib": values["upf2_memory_mib"],
            "ue1_release_delay_s": min(releases) if releases else None,
            "benign_release_commands": len(trial["benign_release_commands"]),
            "valid_runtime": trial["valid_runtime"], "valid_measurements": trial["valid_measurements"],
            "utilization_valid": trial["utilization_valid"]}
    for key in ("host_cpu_percent", "host_used_mib", "detectors_cpu_percent", "detectors_rss_mib", "gnb_cpu_percent", "xapp_cpu_percent"):
        if key in values:
            row[key] = values[key]
    return row


def fmt(value):
    return "NA" if value is None else f"{value:.2f}" if isinstance(value, float) else str(value)


def mark_events(ax, trial):
    shift = trial["attack_start"] if trial["config"].get("manual_timing") else 0
    if trial["attack_start"] is not None:
        ax.axvline(trial["attack_start"] - shift, color="#AA2222", linestyle=":", linewidth=1)
    for event in trial["release_commands"]:
        ax.axvline(event["time"] - shift, color="#AA2222" if event in trial["benign_release_commands"] else "#555555",
                   linestyle="--", linewidth=0.8)
    ax.set_xlim((-12, 35) if trial["config"].get("manual_timing") else (0, 62))
    ax.grid(alpha=0.25)


def interval_trace(ax, rows, key, label, color, shift=0):
    x, y, previous = [], [], None
    for row in rows:
        # Docker stats records the two containers on separate rows. A row for
        # the other container is not a missing observation of this series.
        if key not in row:
            continue
        if row.get(key) is None:
            x.append(float("nan")); y.append(float("nan"))
            previous = None
            continue
        if previous is not None and row["start"] - previous > 0.1:
            x.append(float("nan")); y.append(float("nan"))
        x.extend((row["start"] - shift, row["end"] - shift))
        y.extend((row[key], row[key]))
        previous = row["end"]
    ax.plot(x, y, label=label, color=color, linewidth=1.1)


def plots(trials, directory):
    plt.rcParams.update({"font.size": 8, "axes.spines.top": False, "axes.spines.right": False})
    pairs = sorted({trial["pair"] for trial in trials})
    positions = {pair: index for index, pair in enumerate(pairs)}
    manual = all(trial["config"].get("manual_timing") for trial in trials)
    manual_limits = (-12, max(35, max(trial["config"]["duration"] - trial["attack_start"] for trial in trials))) if manual else None
    xlabel = "Seconds relative to the student's attack-start marker" if manual else "Seconds from measurement start"
    for kind, title, ylabel in (("throughput", "Receiver goodput", "Mbit/s"),
                                ("cpu-utilization", "UPF container CPU utilization (paper Figure 7 metric)", "% of one logical CPU"),
                                ("memory-utilization", "UPF memory" if manual else "Detector resident memory", "MiB")):
        fig, axes = plt.subplots(len(pairs), 2, figsize=(12, max(3.8, 2.5 * len(pairs))), sharex=True, squeeze=False)
        for trial in trials:
            ax = axes[positions[trial["pair"]], 0 if trial["config"]["detector"] == "rf" else 1]
            shift = trial["attack_start"] if manual else 0
            if kind == "throughput":
                for ue, color in ((1, "#D55E00"), (2, "#0072B2")):
                    interval_trace(ax, trial["throughput"][f"ue{ue}"], "mbps", f"UE{ue}", color, shift)
            elif kind == "cpu-utilization":
                interval_trace(ax, trial["resources"], "upf1_cpu_percent", "UPF1 container", "#D55E00", shift)
                interval_trace(ax, trial["resources"], "upf2_cpu_percent", "UPF2 container", "#0072B2", shift)
            elif manual:
                interval_trace(ax, trial["resources"], "upf1_memory_mib", "UPF1 container", "#D55E00", shift)
                interval_trace(ax, trial["resources"], "upf2_memory_mib", "UPF2 container", "#0072B2", shift)
            else:
                interval_trace(ax, trial["resources"], "detectors_rss_mib", "Detectors RSS", "#0072B2")
            mark_events(ax, trial)
            if manual:
                ax.set_xlim(manual_limits)
            valid = trial["valid_runtime"] and trial["valid_measurements"] and trial["utilization_valid"]
            case = "Single run" if manual else "Clean control" if trial["scenario"] == "clean" else f"Attack pair {trial['pair']}"
            ax.set_title(case + " — " + LABELS[trial["config"]["detector"]] + ("" if valid else " [inspect flags]"))
            ax.set_ylabel(ylabel)
            ax.set_ylim(bottom=0)
            ax.legend(loc="upper right", fontsize=6)
        # Use identical y limits within each matched pair of panels.
        for row in axes:
            upper = 1.08 * max(1, max((float(value) for ax in row for line in ax.lines
                                      for value in line.get_ydata() if math.isfinite(value)), default=1))
            for ax in row:
                ax.set_ylim(0, upper)
        for ax in axes[-1]:
            ax.set_xlabel(xlabel)
        fig.suptitle(title + ": AI versus heuristic", fontsize=13)
        fig.text(0.5, 0.005, "Dotted: attack onset. Dashed: release request (red = benign). Missing observations are not zero-filled.", ha="center")
        fig.tight_layout(rect=(0, 0.02, 1, 0.97))
        for extension in ("png", "svg"):
            fig.savefig(directory / f"{kind}.{extension}", dpi=150)
        plt.close(fig)
    fig, grid = plt.subplots(len(pairs), 1, figsize=(11, max(3.8, 2.25 * len(pairs))), sharex=True, squeeze=False)
    axes = grid[:, 0]
    for trial in trials:
        ax = axes[positions[trial["pair"]]]
        shift = trial["attack_start"] if manual else 0
        x, y, previous = [], [], None
        for point in sorted(trial["ping"], key=lambda p: p["seq"]):
            if previous is not None and point["seq"] != previous + 1:
                x.append(float("nan")); y.append(float("nan"))
            x.append(point["send_time"] - shift); y.append(point["rtt_ms"])
            previous = point["seq"]
        detector = trial["config"]["detector"]
        ax.plot(x, y, ".-", color=COLORS[detector], linewidth=0.8, markersize=2,
                label=f"{LABELS[detector]}: {trial['ping_total']['loss_percent']:.2f}% trial loss")
        if trial["attack_start"] is not None:
            ax.axvline(trial["attack_start"] - shift, color="#AA2222", linestyle=":", linewidth=0.8)
        ax.set(title="Single paired observation" if manual else "Clean control" if trial["pair"] == 0 else f"Attack pair {trial['pair']}",
               ylabel="UE2 RTT (ms)", xlim=manual_limits if manual else (0, 50), ylim=(0, None))
        ax.grid(alpha=0.25)
        ax.legend(fontsize=7)
    for pair, ax in zip(pairs, axes):
        upper = 1.08 * max((point["rtt_ms"] for trial in trials if trial["pair"] == pair
                           for point in trial["ping"]), default=1)
        ax.set_ylim(0, upper)
    axes[-1].set_xlabel(xlabel + " (probe send time)")
    fig.suptitle("Legitimate-UE latency and loss", fontsize=14)
    fig.tight_layout(rect=(0, 0, 1, 0.97))
    for extension in ("png", "svg"):
        fig.savefig(directory / f"latency.{extension}", dpi=150)
    plt.close(fig)


def write_report(campaign, folder):
    rows = [summary_row(trial) for trial in campaign["trials"]]
    manual = campaign.get("expected_trials") == 2
    expected = campaign.get("expected_trials", len(campaign.get("trial_order", rows)))
    every_window = all(trial["config"].get("report_interval_seconds", 0) == 0 for trial in campaign["trials"])
    tcp_aware = any(trial["config"]["detector"] == "tcp-flags" for trial in campaign["trials"])
    text = ["# AI versus heuristic: measured comparison", "", campaign["design"], "", campaign["scope"], "",
            f"Complete: **{campaign['complete']}**. Recorded trials: **{len(rows)}/{expected}**.",
            f"Evidence directory: `{folder}`.", "",
            ("The heuristic flags short TCP SYN-without-ACK or reset packets (byte sum <= 28). Ordinary ACK/FIN/data packets are not flagged solely for being small. Both methods report every computed window."
             if tcp_aware else "The heuristic classifies low-byte packets using cutoff 28. Both RF and the heuristic report every computed window, with no wall-clock reporting delay."
             if every_window else "The heuristic classifies low-byte packets using cutoff 28. This historical comparison includes a ten-second reporting interval; RF reports every window."),
            ("Both use the original extractor, 30-packet windows, 10-packet steps, report trigger, controller, and workloads. Achieved reports per second can still differ with packet arrival and processing rates."
             if every_window else "Both use the original extractor, 30-packet windows, 10-packet steps, controller, and workloads. Reporting cadence differs between these recorded configurations."), "",
            ("Baseline means use the ten seconds before each student's attack-start marker; impact means use the following 25 seconds. Plots align the two attack markers at zero. These are two manually operated runs, not repeated trials."
             if manual else "Impact means use [15,48) s for both clean and attack trials; this includes the attack response period. Baseline [5,15), post-event [20,48), and late [25,48) metrics remain in each summary.json."),
            "Ping loss covers the whole trial. RTT is measured on received replies. Release delay is command launch to captured release request, not inference time or completed RRC release.", "",
            "## Throughput, latency, and UPF CPU utilization", "",
            "| Scenario/pair | Method | UE2 Mbit/s | UE2 RTT ms | Ping loss % | UPF1 CPU % | UPF2 CPU % |",
            "|---|---|---:|---:|---:|---:|---:|"]
    for row in rows:
        text.append("| " + " | ".join([f"{row['scenario']}/{row['pair']}", LABELS[row["detector"]],
            *[fmt(row[key]) for key in ("ue2_mbps", "ue2_rtt_mean_ms", "ue2_loss_percent", "upf1_cpu_percent", "upf2_cpu_percent")]]) + " |")
    text += ["", "## Memory and observed outcomes", "",
             "| Scenario/pair | Method | UPF1 MiB | UPF2 MiB | Release delay s | Benign releases | Runtime / network / utilization valid |",
             "|---|---|---:|---:|---:|---:|---|"]
    for row in rows:
        text.append("| " + " | ".join([f"{row['scenario']}/{row['pair']}", LABELS[row["detector"]],
            *[fmt(row[key]) for key in ("upf1_memory_mib", "upf2_memory_mib", "ue1_release_delay_s", "benign_release_commands")],
            f"{row['valid_runtime']} / {row['valid_measurements']} / {row['utilization_valid']}"]) + " |")
    text += ["", "Utilization follows the paper's Figure 7 metric: CPU use of the UPF Docker containers, including their detectors. One fully busy logical CPU is 100%; values can exceed 100%. CPU use is not an energy measurement. Our comparator is a heuristic, whereas the paper compares defense on/off.",
             ("CPU values are timestamped Docker stats samples, interval-weighted; gaps longer than five seconds remain missing. Memory is Docker CLI-reported container usage with its cache adjustment."
              if manual else "Container CPU uses cgroup counters. Host/process CPU and memory diagnostics remain in each summary.json."),
             "All outcomes remain in the report, including benign releases, runtime faults, incomplete coverage, and no observed release. NA means missing, not zero.",
             ("One run per method illustrates behavior; it cannot establish repeatability, confidence intervals, or general superiority."
              if manual else "These observations are descriptive, not a guarantee of AI superiority.")]
    text += ["", "## Captured release requests", "",
             "| Method | UE ID | Seconds from traffic marker | Seconds from attack marker | Benign UE/phase |",
             "|---|---:|---:|---:|---|"]
    for trial in campaign["trials"]:
        for event in trial["release_commands"]:
            delay = event["time"] - trial["attack_start"] if trial["attack_start"] is not None else None
            text.append(f"| {LABELS[trial['config']['detector']]} | {event['ue_id']} | {event['time']:.2f} | {fmt(delay)} | {event in trial['benign_release_commands']} |")
    if not any(trial["release_commands"] for trial in campaign["trials"]):
        text += ["", "No release request was captured."]
    if manual:
        text += ["", "Plots include the recorded post-traffic period so late release requests remain visible. Their timing does not change the 25-second impact window. A captured request is distinct from a confirmed RRC release in the UE log."]
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
