"""Paper-style UPF container CPU and supplementary compute/memory measurements."""

import json
import os
from pathlib import Path
import re
import statistics
import time


def container_cgroup(pid):
    memberships = {}
    for line in Path(f"/proc/{pid}/cgroup").read_text().splitlines():
        _, controllers, directory = line.split(":", 2)
        for controller in controllers.split(","):
            memberships[controller] = directory.lstrip("/")
    if "" in memberships:
        root = Path("/sys/fs/cgroup") / memberships[""]
        return {"version": 2, "cpu": str(root / "cpu.stat"), "memory": str(root / "memory.current")}
    cpu = Path("/sys/fs/cgroup/cpuacct") / memberships["cpuacct"] / "cpuacct.usage"
    memory = Path("/sys/fs/cgroup/memory") / memberships["memory"] / "memory.usage_in_bytes"
    return {"version": 1, "cpu": str(cpu), "memory": str(memory)}


def sample_resources(pids, containers, destination, stop):
    """Read counters without running docker stats or loading the detector CPUs."""
    with destination.open("w") as handle:
        while not stop.is_set():
            row = {"epoch": time.time(), "monotonic": time.monotonic(), "processes": {}, "containers": {}}
            try:
                cpu = list(map(int, Path("/proc/stat").read_text().splitlines()[0].split()[1:9]))
                memory = {line.split(":")[0]: int(line.split()[1]) for line in Path("/proc/meminfo").read_text().splitlines()}
                row.update(cpu_total=sum(cpu), cpu_idle=cpu[3] + cpu[4],
                           host_used_mib=(memory["MemTotal"] - memory["MemAvailable"]) / 1024,
                           host_total_mib=memory["MemTotal"] / 1024)
                for name, paths in containers.items():
                    text = Path(paths["cpu"]).read_text()
                    usage = (int(dict(line.split() for line in text.splitlines())["usage_usec"]) * 1000
                             if paths["version"] == 2 else int(text))
                    row["containers"][name] = {"usage_ns": usage, "memory_mib": int(Path(paths["memory"]).read_text()) / 2 ** 20}
                for name, pid in pids.items():
                    try:
                        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
                        row["processes"][name] = {"pid": pid, "ticks": int(fields[11]) + int(fields[12]),
                                                  "start_ticks": int(fields[19]),
                                                  "rss_mib": int(fields[21]) * os.sysconf("SC_PAGE_SIZE") / 2 ** 20}
                    except (FileNotFoundError, ProcessLookupError):
                        row["processes"][name] = None
            except Exception as error:
                row["error"] = str(error)
            handle.write(json.dumps(row) + "\n")
            handle.flush()
            stop.wait(1)


def resource_intervals(samples, origin, ticks_per_second):
    output = []
    for previous, current in zip(samples, samples[1:]):
        if "error" in previous or "error" in current:
            continue
        elapsed = current["monotonic"] - previous["monotonic"]
        total = current["cpu_total"] - previous["cpu_total"]
        idle = current["cpu_idle"] - previous["cpu_idle"]
        if elapsed <= 0 or total <= 0:
            continue
        row = {"start": previous["epoch"] - origin, "end": current["epoch"] - origin,
               "host_cpu_percent": 100 * (total - idle) / total,
               "host_used_mib": current["host_used_mib"]}
        for name, value in current["containers"].items():
            earlier = previous["containers"].get(name)
            delta = value["usage_ns"] - earlier["usage_ns"] if earlier else -1
            row[name + "_cpu_percent"] = 100 * delta / 1e9 / elapsed if delta >= 0 else None
            row[name + "_memory_mib"] = value["memory_mib"]
        for name, value in current["processes"].items():
            earlier = previous["processes"].get(name)
            valid = value and earlier and value["start_ticks"] == earlier["start_ticks"] and value["ticks"] >= earlier["ticks"]
            row[name + "_cpu_percent"] = 100 * (value["ticks"] - earlier["ticks"]) / ticks_per_second / elapsed if valid else None
            row[name + "_rss_mib"] = value["rss_mib"] if value else None
        for suffix in ("cpu_percent", "rss_mib"):
            values = [row.get(f"ads{number}_{suffix}") for number in (1, 2)]
            row["detectors_" + suffix] = sum(values) if all(v is not None for v in values) else None
        output.append(row)
    return output


def average(rows, key, left, right):
    selected = [(row[key], max(0, min(right, row["end"]) - max(left, row["start"])))
                for row in rows if row.get(key) is not None]
    covered = sum(overlap for _, overlap in selected)
    return (sum(value * overlap for value, overlap in selected) / covered if covered else None), covered


def augment(summary, folder):
    origin = summary["origin_epoch"]
    samples = [json.loads(line) for line in (folder / "resources.jsonl").read_text().splitlines()]
    summary["resources"] = resource_intervals(samples, origin, summary["config"]["clock_ticks_per_second"])
    summary["resource_sample_errors"] = [row["error"] for row in samples if "error" in row]
    for phase, (left, right) in {"impact": (15, 48), "late": (25, 48)}.items():
        values = {"window_seconds": [left, right]}
        for ue, rows in summary["throughput"].items():
            values[ue + "_mbps"], values[ue + "_covered_seconds"] = average(rows, "mbps", left, right)
        rtts = [row["rtt_ms"] for row in summary["ping"] if left <= row["send_time"] < right]
        values["ue2_rtt_mean_ms"] = statistics.mean(rtts) if rtts else None
        values["ue2_rtt_median_ms"] = statistics.median(rtts) if rtts else None
        values["ue2_rtt_samples"] = len(rtts)
        summary["metrics"][phase] = values
    for values in summary["metrics"].values():
        left, right = values["window_seconds"]
        for category, keys in {
            "resources": ("host_cpu_percent", "host_used_mib", "gnb_cpu_percent", "xapp_cpu_percent", "detectors_cpu_percent", "detectors_rss_mib",
                          "upf1_cpu_percent", "upf2_cpu_percent", "upf1_memory_mib", "upf2_memory_mib"),
        }.items():
            for key in keys:
                values[key], values[key + "_covered_seconds"] = average(summary[category], key, left, right)
    summary["utilization_valid"] = (not summary["resource_sample_errors"] and
        all(summary["metrics"]["impact"][key + "_covered_seconds"] >= 0.75 * 33
            for key in ("host_cpu_percent", "upf1_cpu_percent", "upf2_cpu_percent")))
    summary["utilization_scope"] = {
        "paper_metric": "UPF Docker-container CPU utilization, as in paper Figure 7. Cgroup CPU time delta / elapsed wall time * 100; one logical CPU fully busy is 100%, matching Docker's Linux CPU-percent convention. Includes all processes in each UPF container, including its detector. The paper does not specify its CPU normalization, so absolute percentages are not claimed to replicate the paper.",
        "cpu": "Host percent of all logical CPUs (excluding idle/iowait); process percent of one CPU, summed across both detector processes. Includes packet capture, extraction, inference/rule, logging, and reporting.",
        "memory": "Host MemTotal-MemAvailable; container cgroup memory including cache; detector RSS sum (shared pages may be counted twice). Missing/dead process observations remain missing.",
        "sampling": "Approximately 1 s counter samples; phase summaries use interval-overlap weighting. CPU use is not a direct energy measurement."}
    return summary
