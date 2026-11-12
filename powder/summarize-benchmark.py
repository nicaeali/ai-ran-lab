#!/usr/bin/env python3
"""Extract receiver goodput, ping RTT/loss, and control evidence from one benchmark."""

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import statistics
from zoneinfo import ZoneInfo

from scapy.all import IP, TCP, PcapReader


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    args = parser.parse_args()
    root = args.results
    config = json.loads((root / "config.json").read_text())
    events = [json.loads(line) for line in (root / "events.jsonl").read_text().splitlines()]
    origin = next(e["epoch"] for e in events if e["event"] == "measurement_start")
    attack = next((e["epoch"] - origin for e in events if e["event"] == "attack_start"), None)
    duration = config["duration"]
    throughput = {}
    errors = {}
    for ue in (1, 2):
        streamed = root / f"ue{ue}-receiver.jsonl"
        if streamed.exists():
            rows = []
            issues = []
            anchor = None
            for line in streamed.read_text().splitlines():
                record = json.loads(line)
                text = record["line"]
                if "error" in text.lower() or "WARNING" in text:
                    issues.append(text)
                if "sender" in text or "receiver" in text:
                    continue
                match = re.search(r"^\[\s*\d+\]\s+([\d.]+)-([\d.]+)\s+sec\s+[\d.]+\s+\w*Bytes\s+([\d.]+)\s+Mbits/sec", text)
                if not match:
                    continue
                start, end, mbps = map(float, match.groups())
                seconds = end - start
                if seconds <= 0:
                    continue
                observed_end = record["epoch"] - origin
                if anchor is None:
                    anchor = observed_end - end
                rows.append({"start": anchor + start, "end": anchor + end,
                             "seconds": seconds, "mbps": mbps,
                             "stdout_observed_time": observed_end,
                             "iperf_interval_start": start, "iperf_interval_end": end})
            throughput[f"ue{ue}"] = rows
            errors[f"ue{ue}"] = issues
            continue
        raw = json.loads((root / f"ue{ue}-receiver.json").read_text())
        errors[f"ue{ue}"] = raw.get("error")
        offset = raw["start"]["timestamp"]["timesecs"] - origin
        rows = []
        for interval in raw.get("intervals", []):
            row = interval["sum"]
            if row.get("sender") is not False:
                raise ValueError("Expected receiver-side interval, not sender throughput")
            if row["seconds"] <= 0:
                continue
            calculated = row["bytes"] * 8 / row["seconds"]
            if abs(calculated - row["bits_per_second"]) > max(1, calculated * 1e-5):
                raise ValueError("Byte/time and reported throughput disagree")
            rows.append({"start": offset + row["start"], "end": offset + row["end"],
                         "seconds": row["seconds"], "bytes": row["bytes"],
                         "mbps": row["bits_per_second"] / 1e6})
        throughput[f"ue{ue}"] = rows
    ping_text = (root / "ue2-ping.log").read_text()
    ping = []
    for match in re.finditer(r"\[([\d.]+)\].*icmp_seq=(\d+).*time=([\d.]+) ms", ping_text):
        epoch, seq, rtt = float(match[1]), int(match[2]), float(match[3])
        ping.append({"seq": seq, "receive_time": epoch - origin,
                     "send_time": epoch - origin - rtt / 1000, "rtt_ms": rtt})
    ping_summary = re.search(r"(\d+) packets transmitted, (\d+) received.*?([\d.]+)% packet loss", ping_text)
    if not ping_summary:
        raise ValueError("Missing ping summary; do not infer loss from 'no answer yet' lines")
    transmitted, received = int(ping_summary[1]), int(ping_summary[2])
    commands = {}
    with PcapReader(str(root / "control.pcap")) as packets:
        for packet in packets:
            if IP in packet and TCP in packet and packet[TCP].dport == 9090:
                payload = bytes(packet[TCP].payload)
                match = re.search(rb"rrc release_rrc (\d+)", payload)
                if match:
                    key = (packet[IP].src, packet[TCP].sport, packet[TCP].seq, payload)
                    commands.setdefault(key, {"ue_id": int(match[1]), "time": float(packet.time) - origin})
    phases = {"baseline": (5, config["attack_start"]),
              "post_event": (config["attack_start"] + 5, duration - 2)}
    metrics = {}
    for name, (left, right) in phases.items():
        phase = {"window_seconds": [left, right]}
        for ue, rows in throughput.items():
            selected = [(r, max(0, min(right, r["end"]) - max(left, r["start"]))) for r in rows]
            seconds = sum(overlap for _, overlap in selected)
            phase[ue + "_mbps"] = sum(r["mbps"] * overlap for r, overlap in selected) / seconds if seconds else None
            phase[ue + "_covered_seconds"] = seconds
        rtts = [r["rtt_ms"] for r in ping if left <= r["send_time"] < right]
        phase["ue2_rtt_mean_ms"] = statistics.mean(rtts) if rtts else None
        phase["ue2_rtt_median_ms"] = statistics.median(rtts) if rtts else None
        phase["ue2_rtt_samples"] = len(rtts)
        metrics[name] = phase
    xapp = (root / "xapp.log").read_text()
    gnb = (root / "gnb.log").read_text(errors="replace")
    ue1 = (root / "ue1.log").read_text(errors="replace")
    capture_log = (root / "capture.log").read_text()
    report = {
        "analyzer_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "config": config, "origin_epoch": origin, "attack_start": attack,
        "throughput": throughput, "ping": ping, "metrics": metrics,
        "ping_total": {"transmitted": transmitted, "received": received,
                       "loss_percent": 100 * (transmitted - received) / transmitted},
        "receiver_errors": errors, "release_commands": list(commands.values()),
        "xapp_release_attempts": xapp.count("Triggering RRC release."),
        "ue1_rrc_release_received": "Received RRC Release" in ue1,
        "ue1_context_removed": "removed UE CU UE ID 1" in gnb,
        "monitor_only": "BENCHMARK MONITOR-ONLY" in xapp,
        "capture_zero_kernel_drops": bool(re.search(r"^0 packets dropped by kernel$", capture_log, re.MULTILINE)),
        "anomaly_counts_seen": {},
        "runtime_faults": [],
        "measurement_errors": [],
        "timing_note": ("Receiver clock anchored to first force-flushed interval arrival; subsequent boundaries use iperf elapsed times. Adaptive printed rate precision (about 3 significant digits), not fixed 0.01 Mbps. Phase means integrate interval averages with boundary overlap; long bins cannot resolve within-bin release timing. Ping send time = receive time minus RTT."
                        if config.get("receiver_format") else
                        "iperf3 start times are integer Unix seconds: throughput alignment uncertainty <1 s; ping send times reconstructed from receive timestamp minus RTT"),
    }
    for ue in (1, 2):
        pairs = re.findall(r"Window results: (\d+) Normal, (\d+) Anomaly", (root / f"ads{ue}.log").read_text())
        report["anomaly_counts_seen"][f"ue{ue}"] = sorted(set(int(a) for _, a in pairs))
    for actor in ("xapp", "gnb", "ric", "ads1", "ads2"):
        text = (root / f"{actor}.log").read_text(errors="replace")
        fault_pattern = r"Assertion .*failed|Segmentation fault|Error sending message to server"
        if config.get("benchmark_schema", 1) >= 2:
            report["window_count_semantics"] = "Computed overlapping windows; periodic variant forwards a subset. Not independent packet accuracy."
            fault_pattern += r"|free\(\): invalid pointer|double free|corrupted size"
        faults = re.findall(r"^.*(?:" + fault_pattern + r").*$",
                            text, flags=re.MULTILINE)
        if faults:
            report["runtime_faults"].append({"actor": actor, "count": len(faults), "first": faults[0]})
    report["valid_runtime"] = not report["runtime_faults"]
    for ue in (1, 2):
        baseline = metrics["baseline"]
        if baseline[f"ue{ue}_covered_seconds"] < 5 or (baseline[f"ue{ue}_mbps"] or 0) < 1:
            report["measurement_errors"].append(f"UE{ue} lacks a valid active baseline stream")
        if metrics["post_event"][f"ue{ue}_covered_seconds"] < 0.75 * (duration - 2 - config["attack_start"] - 5):
            report["measurement_errors"].append(f"UE{ue} receiver interval coverage is incomplete after the event")
        sender = (root / f"ue{ue}-sender.json").read_text()
        if "Address already in use" in sender or "unable to connect" in sender:
            report["measurement_errors"].append(f"UE{ue} sender connection failed")
    report["valid_measurements"] = not report["measurement_errors"]
    if "detector" in config:
        # Add detector-comparison evidence without changing legacy report schemas.
        ue2 = (root / "ue2.log").read_text(errors="replace")
        report["ue2_rrc_release_received"] = "Received RRC Release" in ue2
        report["ue2_context_removed"] = "removed UE CU UE ID 2" in gnb
        report["benign_release_commands"] = [event for event in commands.values()
                                             if event["ue_id"] == 2 or attack is None or event["time"] < attack]
        detector_capture = (root / "detector-capture.log").read_text()
        report["detector_capture_zero_kernel_drops"] = bool(re.search(
            r"^0 packets dropped by kernel$", detector_capture, re.MULTILINE))
        report["detector_windows"] = {}
        for ue in (1, 2):
            text = (root / f"ads{ue}.log").read_text()
            is_byte = "BYTE_HEURISTIC:" in text
            if is_byte != (config["detector"] != "rf"):
                raise ValueError(f"UE{ue} detector identity does not match configuration")
            windows = []
            for match in re.finditer(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d+) - Window results: (\d+) Normal, (\d+) Anomaly", text, re.MULTILINE):
                stamp = datetime.strptime(match[1], "%Y-%m-%d %H:%M:%S,%f").replace(tzinfo=ZoneInfo("Europe/Paris")).timestamp()
                windows.append({"time": stamp - origin, "normal": int(match[2]), "anomaly": int(match[3])})
            report["detector_windows"][f"ue{ue}"] = {}
            for phase, (left, right) in phases.items():
                selected = [w for w in windows if left <= w["time"] < right]
                total = sum(w["normal"] + w["anomaly"] for w in selected)
                report["detector_windows"][f"ue{ue}"][phase] = {
                    "reported_windows": len(selected),
                    "reported_anomaly_fraction": sum(w["anomaly"] for w in selected) / total if total else None,
                    "all_anomaly_windows": sum(w["anomaly"] == 30 for w in selected),
                }
        report["outcome_note"] = ("Receiver coverage failures are retained. A benign release is a detector/control outcome, not grounds to discard a trial; missing goodput/RTT is not zero.")
        if config.get("benchmark_schema", 1) >= 2:
            expected_interval = config.get("report_interval_seconds", 0)
            for ue in (1, 2):
                text = (root / f"ads{ue}.log").read_text()
                if config["detector"] != "rf" and f"REPORT_INTERVAL_SECONDS: {float(expected_interval)};" not in text:
                    raise ValueError("Heuristic reporting interval differs from configuration")
            if config.get("readme_attack"):
                text = (root / "attack.log").read_text()
                size = re.search(r"40 headers \+ (\d+) data bytes", text)
                report["hping_reported_payload_bytes"] = int(size[1]) if size else None
    if (config["defense"] == "off") != report["monitor_only"]:
        raise ValueError("Controller mode does not match requested condition")
    if config["defense"] == "off" and (commands or report["xapp_release_attempts"]):
        raise ValueError("Monitor-only condition unexpectedly attempted release")
    # The classroom runner redirects this process's stdout to analysis.log;
    # that file is still being written while this manifest is computed.
    source_paths = [p for p in root.iterdir() if p.is_file() and p.name not in ("summary.json", "analysis.log")]
    report["source_sha256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(source_paths)}
    (root / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k not in
                      ("throughput", "ping", "source_sha256")}, indent=2))


if __name__ == "__main__":
    main()
