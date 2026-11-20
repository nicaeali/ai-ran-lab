#!/usr/bin/env python3
"""Instructor tool: compare recorded runs of the lab (no defense, Random Forest, heuristic).

Students do not run this. It needs more than the lab asks students to save. Run the
lab's measurement commands as usual, with these differences:

  - pipe the receivers and docker stats through record.py, which adds a timestamp:
      iperf3 -s ... 2>&1 | python3 record.py ue1-receiver.jsonl   (and ue2-receiver.jsonl)
      docker stats --format '{{.Name}} {{.CPUPerc}}' oai-upf-slice1 oai-upf-slice2 | python3 record.py cpu.jsonl
  - save `date +%s.%N` to traffic-start.txt when the traffic starts, attack-start.txt
    when the attack starts, and end.txt when it ends
  - save the senders' output with `iperf3 -J` as ue1-sender.json and ue2-sender.json,
    run ping with -D, and save tcpdump's messages with 2> capture.log and
    2> detector-capture.log

Usage: analyze.py COMPARISON_DIRECTORY   (folders no-defense, rf, heuristic inside it)
Needs the packages in requirements.txt.
"""

import fcntl
import json
import math
from pathlib import Path
import re
import statistics
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scapy.all import IP, TCP, PcapReader


LABELS = {"no-defense": "No defense", "rf": "Random Forest", "heuristic": "Heuristic"}
DETECTORS = ("rf", "heuristic")
COLORS = ("#D55E00", "#0072B2")


def records(path):
    with path.open() as source:
        # Refuse to analyze a stream that record.py is still writing.
        fcntl.flock(source, fcntl.LOCK_SH | fcntl.LOCK_NB)
        return [json.loads(line) for line in source if line.strip()]


def receiver(rows, origin):
    intervals = []
    anchor = None
    for row in rows:
        if "sender" in row["line"] or "receiver" in row["line"]:
            continue
        match = re.search(r"^\[\s*\d+\]\s+([\d.]+)-([\d.]+)\s+sec\s+[\d.]+\s+\w*Bytes\s+([\d.]+)\s+Mbits/sec", row["line"])
        if not match:
            continue
        start, end, rate = map(float, match.groups())
        if end <= start:
            continue
        if anchor is None:
            anchor = row["epoch"] - origin - end
        intervals.append({"start": anchor + start, "end": anchor + end, "mbps": rate})
    return intervals


def cpu_intervals(rows, origin):
    previous, intervals = {}, []
    names = {"oai-upf-slice1": "upf1", "oai-upf-slice2": "upf2"}
    for row in rows:
        container, percent = row["line"].split()
        name = names[container]
        value = float(percent.rstrip("%"))
        if not math.isfinite(value) or value < 0:
            raise ValueError("Invalid Docker CPU sample")
        now = row["epoch"] - origin
        if name in previous and 0 < now - previous[name] <= 5:
            intervals.append({"start": previous[name], "end": now, name + "_cpu_percent": value})
        previous[name] = now
    return intervals


def mean_over(rows, key, left, right):
    samples = [(row[key], max(0, min(right, row["end"]) - max(left, row["start"])))
               for row in rows if key in row]
    covered = sum(seconds for _, seconds in samples)
    mean = sum(value * seconds for value, seconds in samples) / covered if covered else None
    return mean, covered


def summarize(folder):
    origin = float((folder / "traffic-start.txt").read_text())
    attack = float((folder / "attack-start.txt").read_text()) - origin
    duration = float((folder / "end.txt").read_text()) - origin
    if attack < 15 or duration < attack + 25:
        raise ValueError(f"{folder.name}: expected 15 seconds of baseline and the full 25-second impact period")
    throughput = {f"ue{n}": receiver(records(folder / f"ue{n}-receiver.jsonl"), origin) for n in (1, 2)}
    resources = cpu_intervals(records(folder / "cpu.jsonl"), origin)
    ping_text = (folder / "ue2-ping.log").read_text()
    ping = [{"seq": int(seq), "send_time": float(epoch) - origin - float(rtt) / 1000, "rtt_ms": float(rtt)}
            for epoch, seq, rtt in re.findall(r"\[([\d.]+)\].*icmp_seq=(\d+).*time=([\d.]+) ms", ping_text)]
    match = re.search(r"(\d+) packets transmitted, (\d+) received", ping_text)
    if not match:
        raise ValueError(f"{folder.name}: ping has no final summary")
    sent, received = map(int, match.groups())
    releases = {}
    with PcapReader(str(folder / "control.pcap")) as packets:
        for packet in packets:
            if IP in packet and TCP in packet and packet[TCP].dport == 9090:
                payload = bytes(packet[TCP].payload)
                match = re.search(rb"rrc release_rrc (\d+)", payload)
                if match:
                    key = (packet[IP].src, packet[TCP].sport, packet[TCP].seq, payload)
                    releases.setdefault(key, {"ue_id": int(match[1]), "time": float(packet.time) - origin})
    issues, metrics = [], {}
    if not sent:
        issues.append("Ping: no probes sent")
    series = [(f"ue{n}_mbps", throughput[f"ue{n}"], "mbps") for n in (1, 2)]
    series += [(f"upf{n}_cpu_percent", resources, f"upf{n}_cpu_percent") for n in (1, 2)]
    for phase, window in {"baseline": (attack - 10, attack), "impact": (attack, attack + 25)}.items():
        values = {"window_seconds": window}
        for label, rows, key in series:
            values[label], covered = mean_over(rows, key, *window)
            values[label + "_covered_seconds"] = covered
            if covered < 0.75 * (window[1] - window[0]):
                issues.append(f"{phase}: incomplete {label} coverage")
        rtts = [row["rtt_ms"] for row in ping if window[0] <= row["send_time"] < window[1]]
        values["ue2_rtt_mean_ms"] = statistics.mean(rtts) if rtts else None
        metrics[phase] = values
    for n in (1, 2):
        if (metrics["baseline"][f"ue{n}_mbps"] or 0) < 1:
            issues.append(f"UE{n}: no active baseline stream")
        sender = (folder / f"ue{n}-sender.json").read_text()
        if "Address already in use" in sender or "unable to connect" in sender:
            issues.append(f"UE{n}: sender connection failed")
        if folder.name in DETECTORS:
            detector = (folder / f"ads{n}.log").read_text()
            if ("TCP_FLAG_HEURISTIC:" in detector) != (folder.name == "heuristic"):
                raise ValueError(f"{folder.name}: detector {n} does not match the run's label")
    for name in ("capture.log", "detector-capture.log"):
        if not re.search(r"^0 packets dropped by kernel$", (folder / name).read_text(), re.M):
            issues.append(name + ": capture incomplete or packets dropped")
    for name in ("gnb", "ue1", "ue2") + (("xapp", "ads1", "ads2") if folder.name in DETECTORS else ()):
        text = (folder / (name + ".log")).read_text(errors="replace")
        if re.search(r"Assertion .*failed|Segmentation fault|Error sending message to server|free\(\): invalid pointer|double free|corrupted size", text):
            issues.append(name + ": runtime fault; inspect log")
    summary = {"method": folder.name, "attack_start": attack, "duration": duration,
               "throughput": throughput, "resources": resources, "ping": ping, "metrics": metrics,
               "loss_percent": 100 * (sent - received) / sent if sent else None,
               "release_commands": list(releases.values()),
               "benign_release_commands": [r for r in releases.values() if r["ue_id"] == 2 or r["time"] < attack],
               "ue1_rrc_release": "Received RRC Release" in (folder / "ue1.log").read_text(),
               "ue2_rrc_release": "Received RRC Release" in (folder / "ue2.log").read_text(),
               "issues": issues}
    (folder / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def interval_trace(ax, rows, key, label, color, shift):
    x, y, previous = [], [], None
    for row in rows:
        if key not in row:
            continue
        if previous is not None and row["start"] - previous > 0.1:
            x.append(float("nan")); y.append(float("nan"))
        x.extend((row["start"] - shift, row["end"] - shift))
        y.extend((row[key], row[key]))
        previous = row["end"]
    ax.plot(x, y, label=label, color=color)


def plots(trials, folder):
    limits = (-12, max(t["duration"] - t["attack_start"] for t in trials))
    for kind, ylabel in (("throughput", "Receiver goodput (Mbit/s)"),
                         ("cpu", "UPF CPU (% of one logical CPU)"), ("latency", "UE2 RTT (ms)")):
        fig, axes = plt.subplots(1, len(trials), figsize=(6 * len(trials), 4), sharex=True, sharey=True, squeeze=False)
        axes = axes[0]
        for ax, trial in zip(axes, trials):
            shift = trial["attack_start"]
            if kind == "latency":
                x, y, previous = [], [], None
                for point in trial["ping"]:
                    if previous is not None and point["seq"] != previous + 1:
                        x.append(float("nan")); y.append(float("nan"))
                    x.append(point["send_time"] - shift); y.append(point["rtt_ms"])
                    previous = point["seq"]
                ax.plot(x, y, ".-", color=COLORS[1], label="UE2 replies")
            else:
                for n, color in zip((1, 2), COLORS):
                    rows, key, label = (trial["throughput"][f"ue{n}"], "mbps", f"UE{n}") if kind == "throughput" else (trial["resources"], f"upf{n}_cpu_percent", f"UPF{n}")
                    interval_trace(ax, rows, key, label, color, shift)
            ax.axvline(0, color="red", linestyle=":")
            for release in trial["release_commands"]:
                ax.axvline(release["time"] - shift, color="red" if release in trial["benign_release_commands"] else "gray", linestyle="--")
            ax.set(title=LABELS[trial["method"]] + (" [inspect issues]" if trial["issues"] else ""),
                   xlabel="Seconds from attack marker", ylabel=ylabel, xlim=limits)
            ax.grid(alpha=0.25)
            ax.legend()
        axes[0].set_ylim(bottom=0)
        fig.suptitle("Dotted: attack; dashed: release request (red = benign UE/phase)")
        fig.tight_layout()
        fig.savefig(folder / (kind + ".png"), dpi=150)
        plt.close(fig)


def report(trials, folder):
    fmt = lambda value: "NA" if value is None else f"{value:.2f}"
    text = ["# One run of each condition", "",
            "Baseline: 10 seconds before each attack marker. Impact: the following 25 seconds.",
            "Ping loss covers the whole run; RTT uses received replies. Missing data is not zero.", "",
            "| Method / phase | UE2 Mbit/s | UE2 RTT ms | UPF1 CPU % | UPF2 CPU % |",
            "|---|---:|---:|---:|---:|"]
    for trial in trials:
        for phase, values in trial["metrics"].items():
            text.append("| " + " | ".join([LABELS[trial["method"]] + " / " + phase,
                *[fmt(values[key]) for key in ("ue2_mbps", "ue2_rtt_mean_ms", "upf1_cpu_percent", "upf2_cpu_percent")]]) + " |")
    for trial in trials:
        text += ["", "## " + LABELS[trial["method"]], "", f"Ping loss: {fmt(trial['loss_percent'])}%.",
                 f"UE logs show RRC Release: UE1={trial['ue1_rrc_release']}, UE2={trial['ue2_rrc_release']}."]
        for release in trial["release_commands"]:
            text.append(f"- UE{release['ue_id']} release request: {release['time'] - trial['attack_start']:.3f} s from attack marker" +
                        (" **(benign UE/phase)**" if release in trial["benign_release_commands"] else ""))
        if not trial["release_commands"]:
            text.append("No release request captured.")
        text += ["- " + issue for issue in trial["issues"]] or ["Coverage and recorded runtime checks passed."]
    text += ["", "A release request is not completed RRC release or inference latency. One run per condition does not establish general superiority.",
             "CPU includes forwarding and detection; 100% is one busy logical CPU. Inspect summary.json for coverage and raw logs for outcomes."]
    for name in ("throughput", "latency", "cpu"):
        text += ["", f"![{name}]({name}.png)"]
    (folder / "comparison.md").write_text("\n".join(text) + "\n")


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: analyze.py COMPARISON_DIRECTORY")
    folder = Path(sys.argv[1])
    methods = [m for m in ("no-defense", "rf", "heuristic") if m in DETECTORS or (folder / m / "end.txt").exists()]
    trials = [summarize(folder / method) for method in methods]
    plots(trials, folder)
    report(trials, folder)
    print("Results:", folder / "comparison.md")


if __name__ == "__main__":
    main()
