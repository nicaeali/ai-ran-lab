#!/usr/bin/env python3
"""Bookkeeping for student-operated trials; never starts traffic or network actors."""

from datetime import datetime, timezone
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys
import time

import lab


REPO = Path(__file__).resolve().parents[1]
BASE = Path("/var/tmp/ai-ran/captures/comparison")
CURRENT = BASE / "current"
STATE = Path("/var/tmp/ai-ran/state/observation.json")
ATTACK_SECONDS = 25


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def context():
    if not STATE.exists():
        raise RuntimeError("Run prepare-rf-trial first")
    state = json.loads(STATE.read_text())
    return state, Path(state["directory"]) / state["active"]


def events(folder):
    path = folder / "events.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def event(folder, name):
    row = {"event": name, "epoch": time.time(), "monotonic": time.monotonic()}
    with (folder / "events.jsonl").open("a") as handle:
        handle.write(json.dumps(row) + "\n")
    print(f"Recorded {name}: {row['epoch']:.6f}; timestamp only, no traffic started", flush=True)
    return row


def check_recorders(folder):
    for name in ("ue1", "ue2", "cpu"):
        path = folder / (name + ".lock")
        if not path.exists():
            continue
        with path.open("r") as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError("Stop the recording in its terminal before continuing: " + name)


def prepare(method):
    detector = "rf" if method == "rf" else "tcp-flags"
    lab.need("gnb", "ric", "ue1", "ue2", "xapp", "ads1", "ads2")
    if lab.state().get("detector") != detector:
        raise RuntimeError("Start the detector specified for this run first")
    if lab.state().get("attack_run") or lab.contains("ue1", "Received RRC Release") or lab.contains("ue2", "Received RRC Release"):
        raise RuntimeError("Use a fresh staged startup before preparing the next measurement")
    if subprocess.run(["pgrep", "-x", "tcpdump"], stdout=subprocess.DEVNULL).returncode == 0:
        raise RuntimeError("Stop the previous packet captures first")
    if STATE.exists():
        previous, previous_folder = context()
        check_recorders(previous_folder)
        if method == "heuristic" and not previous.get("finished", False):
            raise RuntimeError("Finish the current trial before preparing another")
    BASE.mkdir(parents=True, exist_ok=True)
    if method == "rf":
        pair = BASE / datetime.now(timezone.utc).strftime("pair-%Y%m%dT%H%M%S.%fZ")
        pair.mkdir()
        state = {"directory": str(pair), "active": method, "finished": False}
    else:
        state, _ = context()
        pair = Path(state["directory"])
        if not (pair / "rf/summary.json").exists() or (pair / "heuristic").exists():
            raise RuntimeError("Complete one RF run first; the heuristic run must belong to that same pair")
        state.update(active=method, finished=False)
    folder = pair / method
    folder.mkdir()
    folder.chmod(0o1777)
    if CURRENT.is_symlink():
        CURRENT.unlink()
    elif CURRENT.exists():
        raise RuntimeError("Expected a managed current-trial symlink; inspect " + str(CURRENT))
    CURRENT.symlink_to(folder.relative_to(BASE), target_is_directory=True)
    STATE.parent.mkdir(parents=True, exist_ok=True)
    save(STATE, state)
    config = {"output": str(folder), "detector": detector, "defense": "on", "pair": 1,
              "scenario": "attack", "manual_timing": True, "duration": None, "attack_start": None,
              "attack_duration": ATTACK_SECONDS, "attack_pps": 10000, "rate_mbps": 100,
              "transport": "tcp", "client_data_ports": [20, 80], "iperf_buffer_bytes": 1200,
              "traffic_duration": 75, "report_interval_seconds": 0,
              "byte_threshold": None if method == "rf" else 28, "benchmark_schema": 2,
              "heuristic_rule": None if method == "rf" else "tcp-flags",
              "receiver_format": "student-operated force-flushed iperf3 text with observation timestamps",
              "readme_attack": None, "cpu_source": "docker stats JSON stream",
              "workload_source": "Commands prescribed in the handout; record any manual deviations in the lab report",
              "xapp_binary_sha256": hashlib.sha256((lab.FLEXRIC / "examples/xApp/c/ctrl/xapp_rc_slice_ctrl").read_bytes()).hexdigest(),
              "gnb_binary_sha256": hashlib.sha256((lab.RAN / "nr-softmodem").read_bytes()).hexdigest()}
    save(folder / "config.json", config)
    for number, address in ((1, "12.2.1.2"), (2, "12.1.1.130")):
        lab.run(["ip", "-n", f"ue{number}", "route", "replace", "unreachable", "192.168.70.145/32", "metric", "32760"])
        route = lab.run(["ip", "-n", f"ue{number}", "route", "get", "192.168.70.145"], capture=True).stdout
        if "dev oaitun_ue1" not in route or address not in route:
            raise RuntimeError("Unexpected UE data path: " + route)
        (folder / f"ue{number}-route.txt").write_text(route)
        fingerprints = lab.run(["docker", "exec", f"oai-upf-slice{number}", "sha256sum",
                                f"/app/anomaly-detection-server-slice{number}.py", "/app/random_forest_model.pkl",
                                "/app/preprocessor.pkl"], capture=True).stdout
        (folder / f"detector-artifacts-slice{number}.sha256").write_text(fingerprints)
    print("Prepared", folder)
    print("Run the receiver, Docker stats, capture, and traffic commands yourself, as shown in the handout.")


def mark(name):
    state, folder = context()
    if state["finished"]:
        raise RuntimeError("This run is already finished")
    recorded = events(folder)
    if any(row["event"] == name for row in recorded):
        raise RuntimeError("This timestamp is already recorded")
    if name == "attack_start":
        start = next((row for row in recorded if row["event"] == "measurement_start"), None)
        if start is None or time.monotonic() - start["monotonic"] < 15:
            raise RuntimeError("Start traffic and observe at least 15 seconds of baseline first")
        lab.record(attack_run=True)
    event(folder, name)


def record(kind):
    state, folder = context()
    if state["finished"]:
        raise RuntimeError("Prepare a fresh trial before recording")
    filename = "cpu.jsonl" if kind == "cpu" else kind + "-receiver.jsonl"
    with (folder / (kind + ".lock")).open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with (folder / filename).open("x") as handle:
            try:
                for line in sys.stdin:
                    if not line.strip():
                        continue
                    sample = docker_sample(line) if kind == "cpu" else None
                    if kind == "cpu" and sample is None:
                        continue
                    row = {"epoch": time.time(), "line": line.rstrip("\n")}
                    handle.write(json.dumps(row) + "\n")
                    handle.flush()
                    start = next((e["epoch"] for e in events(folder) if e["event"] == "measurement_start"), None)
                    stamp = f"t={row['epoch'] - start:5.1f}s" if start is not None else "ready"
                    if kind == "cpu":
                        print(f"[{stamp}] {sample['Name']}: CPU {sample['CPUPerc']}, memory {sample['MemUsage']}", flush=True)
                    else:
                        print(f"[{kind.upper()} {stamp}] {line.rstrip()}", flush=True)
            except KeyboardInterrupt:
                pass


def docker_sample(line):
    # Docker CLI versions can emit cursor/clear-screen CSI sequences even when
    # stdout is piped. Keep the raw line in the recording, but parse its JSON.
    cleaned = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", line).strip()
    return json.loads(cleaned) if cleaned else None


def memory_mib(text):
    match = re.fullmatch(r"\s*([\d.]+)\s*(B|KiB|MiB|GiB|TiB|kB|MB|GB)\s*", text.split("/")[0])
    if not match:
        raise ValueError("Unrecognized Docker memory value: " + text)
    scales = {"B": 1, "KiB": 1024, "MiB": 1024 ** 2, "GiB": 1024 ** 3, "TiB": 1024 ** 4,
              "kB": 1000, "MB": 1000 ** 2, "GB": 1000 ** 3}
    return float(match[1]) * scales[match[2]] / 1024 ** 2


def cpu_intervals(rows, origin):
    previous, intervals = {}, []
    for row in rows:
        sample = docker_sample(row["line"])
        if sample is None:
            continue
        name = {"oai-upf-slice1": "upf1", "oai-upf-slice2": "upf2"}.get(sample["Name"])
        if name is None:
            raise ValueError("Unexpected Docker stats container: " + sample["Name"])
        value = float(sample["CPUPerc"].rstrip("%"))
        if not math.isfinite(value) or value < 0:
            raise ValueError("Invalid CPU utilization")
        if name in previous:
            elapsed = row["epoch"] - previous[name]
            # Preserve sampling gaps rather than stretching an observation across them.
            if 0 < elapsed <= 5:
                intervals.append({"start": previous[name] - origin, "end": row["epoch"] - origin,
                                  name + "_cpu_percent": value, name + "_memory_mib": memory_mib(sample["MemUsage"])})
        previous[name] = row["epoch"]
    return intervals


def weighted_mean(rows, key, left, right):
    values = [(row[key], max(0, min(right, row["end"]) - max(left, row["start"])))
              for row in rows if row.get(key) is not None]
    covered = sum(seconds for _, seconds in values)
    return (sum(value * seconds for value, seconds in values) / covered if covered else None), covered


def finish():
    state, folder = context()
    check_recorders(folder)
    recorded = events(folder)
    start = next((row for row in recorded if row["event"] == "measurement_start"), None)
    attack = next((row for row in recorded if row["event"] == "attack_start"), None)
    if not start or not attack:
        raise RuntimeError("Record the traffic and attack start markers before finishing")
    for name in ("capture.log", "detector-capture.log"):
        if "packets dropped by kernel" not in (folder / name).read_text():
            raise RuntimeError("Wait for the capture to finish before analysis: " + name)
    if "packets transmitted" not in (folder / "ue2-ping.log").read_text():
        raise RuntimeError("Wait for ping to finish before analysis")
    if state["finished"]:
        raise RuntimeError("This run is already finished")
    end = next((row for row in recorded if row["event"] == "measurement_end"), None) or event(folder, "measurement_end")
    config = json.loads((folder / "config.json").read_text())
    onset = attack["epoch"] - start["epoch"]
    config.update(duration=end["epoch"] - start["epoch"], attack_start=onset,
                  phase_windows={"baseline": [onset - 10, onset], "impact": [onset, onset + ATTACK_SECONDS],
                                 "post_event": [onset + 5, onset + ATTACK_SECONDS],
                                 "late": [onset + 15, onset + ATTACK_SECONDS]})
    save(folder / "config.json", config)
    for actor in ("gnb", "ric", "ue1", "ue2", "xapp", "ads1", "ads2"):
        shutil.copy2(lab.LOGS / (actor + ".log"), folder / (actor + ".log"))
    result = subprocess.run([sys.executable, str(REPO / "powder/summarize-benchmark.py"), str(folder)],
                            text=True, capture_output=True)
    (folder / "analysis.log").write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError("Analysis failed; evidence retained. Inspect " + str(folder / "analysis.log"))
    summary = json.loads((folder / "summary.json").read_text())
    summary.update(scenario="attack", pair=1)
    raw = [json.loads(line) for line in (folder / "cpu.jsonl").read_text().splitlines()]
    summary["resources"] = cpu_intervals(raw, summary["origin_epoch"])
    for values in summary["metrics"].values():
        for key in ("upf1_cpu_percent", "upf2_cpu_percent", "upf1_memory_mib", "upf2_memory_mib"):
            values[key], values[key + "_covered_seconds"] = weighted_mean(summary["resources"], key, *values["window_seconds"])
    summary["utilization_valid"] = all(summary["metrics"][phase][f"upf{number}_cpu_percent_covered_seconds"] >= 0.75 * (right - left)
                                       for phase, (left, right) in config["phase_windows"].items() for number in (1, 2))
    summary["utilization_scope"] = "Timestamped Docker stats observations, interval-weighted; one busy logical CPU = 100%. Docker memory is the CLI-reported usage, with its cache adjustment. Gaps longer than five seconds remain missing."
    save(folder / "summary.json", summary)
    state["finished"] = True
    save(STATE, state)
    print(json.dumps({"method": config["detector"], "baseline": summary["metrics"]["baseline"],
                      "during_attack": summary["metrics"]["impact"], "valid_runtime": summary["valid_runtime"],
                      "valid_measurements": summary["valid_measurements"], "utilization_valid": summary["utilization_valid"]}, indent=2))
    print("Saved", folder, "— network remains running for inspection")


def report():
    state, _ = context()
    if state["active"] != "heuristic" or not state["finished"]:
        raise RuntimeError("Finish both runs before generating the comparison")
    pair = Path(state["directory"])
    trials = [json.loads((pair / method / "summary.json").read_text()) for method in ("rf", "heuristic")]
    if trials[0]["config"]["detector"] != "rf" or trials[1]["config"]["detector"] not in ("byte", "byte-periodic", "tcp-flags"):
        raise RuntimeError("Expected one RF run and one heuristic run")
    for key in ("gnb_binary_sha256", "xapp_binary_sha256", "traffic_duration", "attack_duration", "attack_pps", "rate_mbps", "client_data_ports"):
        if trials[0]["config"][key] != trials[1]["config"][key]:
            raise RuntimeError("The prescribed conditions differ between runs: " + key)
    for number in (1, 2):
        name = f"detector-artifacts-slice{number}.sha256"
        if (pair / "rf" / name).read_bytes() != (pair / "heuristic" / name).read_bytes():
            raise RuntimeError("The original detector/model artifacts differ between runs")
    same_reporting = all(row["config"].get("report_interval_seconds", 0) == 0 for row in trials)
    campaign = {"directory": str(pair), "trials": trials, "complete": True, "expected_trials": 2,
                "design": "One student-operated RF run and one heuristic run; compare each pre-attack baseline with its attack period",
                "scope": ("Single-pair classroom demonstration. Both methods report every computed window; classification/processing can differ. No repeatability or statistical-superiority claim."
                          if same_reporting else "Historical single-pair demonstration with different classifier/reporting settings; no repeatability or statistical-superiority claim.")}
    save(pair / "campaign.json", campaign)
    from comparison_report import write_report
    write_report(campaign, pair)
    shutil.copy2(pair / "comparison.md", lab.STATE.parent / "comparison.md")
    print("TABLE AND PLOTS:", pair)
    print("Read: less /var/tmp/ai-ran/state/comparison.md")


def main():
    actions = {"prepare-rf": lambda: prepare("rf"), "prepare-heuristic": lambda: prepare("heuristic"),
               "traffic-start": lambda: mark("measurement_start"), "attack-start": lambda: mark("attack_start"),
               "record-ue1": lambda: record("ue1"), "record-ue2": lambda: record("ue2"),
               "record-cpu": lambda: record("cpu"), "finish": finish, "report": report}
    if len(sys.argv) != 2 or sys.argv[1] not in actions:
        raise SystemExit("Use the measurement entry points listed in the student handout")
    if not sys.argv[1].startswith("record-") and os.geteuid() != 0:
        raise SystemExit("Run this bookkeeping command with sudo")
    try:
        actions[sys.argv[1]]()
    except (OSError, RuntimeError, ValueError) as error:
        raise SystemExit(str(error))


if __name__ == "__main__":
    main()
