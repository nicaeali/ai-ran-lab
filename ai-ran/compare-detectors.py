#!/usr/bin/env python3
"""Fixed eight-trial RF versus weaker periodic-byte comparison; no student flags."""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time

import lab
from comparison_metrics import augment, container_cgroup, sample_resources
from comparison_report import write_report


REPO = Path(__file__).resolve().parents[1]
ORDER = [("clean", 0, "rf"), ("clean", 0, "byte-periodic"),
         ("attack", 1, "rf"), ("attack", 1, "byte-periodic"),
         ("attack", 2, "byte-periodic"), ("attack", 2, "rf"),
         ("attack", 3, "rf"), ("attack", 3, "byte-periodic")]
IPS = ("12.2.1.2", "12.1.1.130")
DN = "192.168.70.145"


def trial(folder, scenario, pair, detector):
    folder.mkdir()
    folder.chmod(0o1777)
    processes, handles, readers = [], [], []
    stop_sampler = threading.Event()
    sampler = None
    config = {"output": str(folder), "scenario": scenario, "pair": pair, "detector": detector,
              "defense": "on", "duration": 50, "attack_start": 15, "attack_pps": 10000 if scenario == "attack" else 0,
              "rate_mbps": 100, "transport": "tcp", "direction": "downlink", "server_port": 80,
              "client_data_ports": [20, 80], "iperf_buffer_bytes": 1200, "reset_dn_namespace": True,
              "benchmark_schema": 2, "byte_threshold": 28 if detector != "rf" else None,
              "report_interval_seconds": 10 if detector != "rf" else 0,
              "receiver_format": "timestamped force-flushed iperf3 text", "readme_attack": None,
              "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"), "logical_cpus": os.cpu_count(),
              "xapp_binary_sha256": hashlib.sha256((lab.FLEXRIC / "examples/xApp/c/ctrl/xapp_rc_slice_ctrl").read_bytes()).hexdigest(),
              "gnb_binary_sha256": hashlib.sha256((lab.RAN / "nr-softmodem").read_bytes()).hexdigest(),
              "source_sha256": {name: hashlib.sha256((REPO / name).read_bytes()).hexdigest() for name in
                                ("ai-ran/compare-detectors.py", "ai-ran/comparison_metrics.py", "ai-ran/lab.py",
                                 "powder/byte-heuristic-detector.py", "powder/summarize-benchmark.py",
                                 "conf/gnb.conf")}}
    (folder / "config.json").write_text(json.dumps(config, indent=2) + "\n")

    def event(kind, **values):
        row = {"event": kind, "epoch": time.time(), "monotonic": time.monotonic(), **values}
        with (folder / "events.jsonl").open("a") as handle:
            handle.write(json.dumps(row) + "\n")
        return row

    def run(command, name, timeout=180):
        command = list(map(str, command))
        event("command", command=shlex.join(command), log=name)
        with (folder / name).open("w") as handle:
            result = subprocess.run(command, stdout=handle, stderr=subprocess.STDOUT, timeout=timeout)
        if result.returncode:
            raise RuntimeError(f"Command failed: {name}; evidence retained in {folder}")

    def spawn(command, name, timestamp=False):
        command = list(map(str, command))
        event("spawn", command=shlex.join(command), log=name)
        handle = (folder / name).open("w")
        handles.append(handle)
        process = subprocess.Popen(command, stdout=subprocess.PIPE if timestamp else handle,
                                   stderr=subprocess.STDOUT, text=True, start_new_session=True)
        processes.append((name, process))
        if timestamp:
            def copy_lines():
                for line in process.stdout:
                    handle.write(json.dumps({"epoch": time.time(), "line": line.rstrip("\n")}) + "\n")
                    handle.flush()
            reader = threading.Thread(target=copy_lines)
            reader.start()
            readers.append(reader)
        return process

    try:
        run(lab.COMPOSE + ["up", "-d", "--no-deps", "--force-recreate", "oai_ext_dn"], "dn-reset.log")
        for action in ("core", "ric", "gnb", "ue1", "ue2", "xapp", "detectors" if detector == "rf" else "heuristic"):
            run([sys.executable, REPO / "ai-ran/lab.py", action], "startup-" + action + ".log")
        for ue, ip in enumerate(IPS, 1):
            run(["docker", "exec", f"oai-upf-slice{ue}", "sha256sum", f"/app/anomaly-detection-server-slice{ue}.py",
                 "/app/random_forest_model.pkl", "/app/preprocessor.pkl"], f"detector-artifacts-slice{ue}.sha256")
            run(["ip", "-n", f"ue{ue}", "route", "replace", "unreachable", DN + "/32", "metric", "32760"], f"ue{ue}-fallback.log")
            route = subprocess.check_output(["ip", "-n", f"ue{ue}", "route", "get", DN], text=True)
            if "dev oaitun_ue1" not in route or ip not in route:
                raise RuntimeError("Traffic would not use the UE radio path")
            event("route_verified", ue=ue, route=route.strip())
        run(["iperf3", "--version"], "iperf-version.txt")
        dn_pid = subprocess.check_output(["docker", "inspect", "-f", "{{.State.Pid}}", "oai-ext-dn"], text=True).strip()
        for ue, ip in enumerate(IPS, 1):
            route = subprocess.check_output(["nsenter", "-t", dn_pid, "-n", "ip", "route", "get", ip], text=True)
            if f"via 192.168.70.{141 + ue}" not in route or f"src {DN}" not in route:
                raise RuntimeError("Downlink traffic would not use the selected UPF")
            event("dn_route_verified", ue=ue, route=route.strip())
        pids = {actor: int(subprocess.check_output(lab.TMUX + ["display-message", "-p", "-t", actor, "#{pane_pid}"], text=True))
                for actor in ("gnb", "ric", "xapp", "ue1", "ue2")}
        for number in (1, 2):
            listing = subprocess.check_output(["docker", "top", f"oai-upf-slice{number}", "-eo", "pid,args"], text=True)
            candidates = [int(line.split()[0]) for line in listing.splitlines()[1:]
                          if re.search(r"python3.*(?:anomaly-detection-server|byte-heuristic-detector)", line)]
            if len(candidates) != 1:
                raise RuntimeError("Could not identify the detector process for utilization measurement")
            pids[f"ads{number}"] = candidates[0]
        containers = {f"upf{number}": container_cgroup(subprocess.check_output(
            ["docker", "inspect", "-f", "{{.State.Pid}}", f"oai-upf-slice{number}"], text=True).strip()) for number in (1, 2)}
        event("resource_processes", pids=pids, containers=containers)
        sampler = threading.Thread(target=sample_resources, args=(pids, containers, folder / "resources.jsonl", stop_sampler))
        sampler.start()
        for ue, ip in enumerate(IPS, 1):
            spawn(["ip", "netns", "exec", f"ue{ue}", "timeout", "-s", "INT", "-k", "3", "62",
                   "iperf3", "-s", "-1", "-B", ip, "-p", "80", "-i", "1", "--forceflush", "-f", "m"],
                  f"ue{ue}-receiver.jsonl", timestamp=True)
        for interface, name, expression in (("lo", "control", "tcp port 9090 or sctp port 36421 or sctp port 36422"),
                                            ("demo-oai", "detector-reports", "tcp port 8080 and host 192.168.70.1")):
            spawn(["timeout", "-s", "INT", "-k", "3", "62", "tcpdump", "-i", interface, "-n", "-U", "-w", folder / (name + ".pcap"), expression],
                  "capture.log" if name == "control" else "detector-capture.log")
        time.sleep(1)
        if any(process.poll() is not None for _, process in processes):
            raise RuntimeError("Measurement server or capture failed before traffic startup")
        origin = event("measurement_start")
        spawn(["ip", "netns", "exec", "ue2", "ping", "-n", "-D", "-O", "-i", "0.2", "-W", "1", "-w", "50", DN], "ue2-ping.log")
        for ue, ip in enumerate(IPS, 1):
            spawn(["nsenter", "-t", dn_pid, "-n", "timeout", "-s", "INT", "-k", "3", "53", "iperf3", "-c", ip,
                   "-p", "80", "--cport", "20" if ue == 1 else "80", "-b", "100M", "-l", "1200", "-t", "50", "-i", "1", "-J"], f"ue{ue}-sender.json")
        if scenario == "attack":
            time.sleep(max(0, origin["monotonic"] + 15 - time.monotonic()))
            event("attack_start", requested_pps=10000, interval_microseconds=100)
            spawn(["ip", "netns", "exec", "ue1", "timeout", "-s", "INT", "-k", "3", "35", "hping3", "-q", "-S",
                   "-s", "333", "-k", "-p", "333", "-d", "0", "-i", "u100", "-c", "350000", "-I", "oaitun_ue1", DN], "attack.log")
        time.sleep(max(0, origin["monotonic"] + 50 - time.monotonic()))
        event("measurement_end")
        for _, process in processes:
            try:
                process.wait(timeout=max(1, origin["monotonic"] + 68 - time.monotonic()))
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGINT)
        event("process_exit_codes", returncodes={name: process.poll() for name, process in processes})
    finally:
        for _, process in processes:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGINT)
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
        stop_sampler.set()
        if sampler:
            sampler.join()
        for reader in readers:
            reader.join()
        for handle in handles:
            handle.close()
        for actor in ("xapp", "gnb", "ric", "ue1", "ue2", "ads1", "ads2"):
            if (lab.LOGS / (actor + ".log")).exists():
                shutil.copy2(lab.LOGS / (actor + ".log"), folder / (actor + ".log"))
    run([sys.executable, REPO / "powder/summarize-benchmark.py", folder], "analysis.log")
    summary = augment(json.loads((folder / "summary.json").read_text()), folder)
    summary.update(scenario=scenario, pair=pair)
    (folder / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main():
    if len(sys.argv) != 1 or os.geteuid() != 0:
        raise SystemExit("Run: sudo /opt/ai-ran/bin/run-comparison")
    if not (lab.LAB / "READY").exists():
        raise SystemExit("Complete profile preparation first")
    if shutil.which("iperf3") is None:
        raise SystemExit("Install the comparison update before running this command")
    if subprocess.run(["pgrep", "-x", "tcpdump"], stdout=subprocess.DEVNULL).returncode == 0:
        raise SystemExit("Stop the manual packet captures before starting the comparison")
    folder = Path("/var/tmp/ai-ran/captures") / datetime.now(timezone.utc).strftime("comparison-%Y%m%dT%H%M%S.%fZ")
    folder.mkdir()
    folder.chmod(0o1777)
    report = {"directory": str(folder), "trial_order": ORDER, "trials": [], "complete": False,
              "design": "RF versus intentionally weaker byte threshold 28 with 10-second reporting; one clean control each and three alternating attack pairs",
              "scope": "End-to-end detector/reporting-policy comparison; reporting cadence also differs. All outcomes retained."}
    def save():
        (folder / "campaign.json").write_text(json.dumps(report, indent=2) + "\n")
        write_report(report, folder)
        shutil.copy2(folder / "comparison.md", lab.STATE.parent / "comparison.md")
    save()
    try:
        lab.stop()
        lab.export_results()
        for index, (scenario, pair, detector) in enumerate(ORDER):
            print(f"TRIAL {index + 1}/8: {scenario}, pair {pair}, {detector}", flush=True)
            try:
                result = trial(folder / f"{index + 1:02d}-{scenario}-{pair}-{detector}", scenario, pair, detector)
                report["trials"].append(result)
            finally:
                lab.stop()
            save()
            if index + 1 < len(ORDER):
                time.sleep(20)
        report["complete"] = True
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        save()
        print("COMPARISON:", folder, flush=True)
        print("SUMMARY: /var/tmp/ai-ran/state/comparison.md", flush=True)
    if not all(t["utilization_valid"] for t in report["trials"]):
        raise SystemExit("Comparison recorded, but utilization coverage needs inspection; see all retained trials")


if __name__ == "__main__":
    main()
