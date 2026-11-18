#!/usr/bin/env python3
"""Replace classification in the pinned detector while preserving extraction/windows.

Run inside the appropriate UPF with /app as the working directory. The TCP-aware
rule reports every computed window. Original scripts and model files are read-only.
"""

import gc
import importlib.util
from pathlib import Path
import sys


THRESHOLD = 28


def load_detector(number):
    path = Path(f"/app/anomaly-detection-server-slice{number}.py")
    spec = importlib.util.spec_from_file_location(f"packaged_detector_{number}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if (module.window_size, module.step_size, module.sst, module.sd) != (30, 10, 1, 1 if number == 1 else 5):
        raise RuntimeError("Unexpected packaged detector configuration")
    return module


def classify(row):
    small = row["src_bytes"] + row["dst_bytes"] <= THRESHOLD
    flags = row["flag"]
    connection_attempt_or_reset = ("S" in flags and "A" not in flags) or "R" in flags
    return row["protocol_type"] == "tcp" and small and connection_attempt_or_reset


def install_rule(module):
    def make_predictions():
        anomaly_count = sum(classify(row) for row in module.sliding_window)
        normal_count = len(module.sliding_window) - anomaly_count
        module.logging.info(f"Window results: {normal_count} Normal, {anomaly_count} Anomaly")
        message = f"sst:{module.sst},sd:{module.sd},normal:{normal_count},anomaly:{anomaly_count}"
        print(message, flush=True)
        module.send_message_to_server(message)
        for _ in range(module.step_size):
            module.sliding_window.popleft()
    module.make_predictions = make_predictions
    # Import uses the original initialization, but the heuristic needs neither
    # prediction object. Release these in-memory references; never edit pickles.
    module.model = None
    module.preprocessor = None
    gc.collect()
    module.logging.info("TCP_FLAG_HEURISTIC: tcp, src_bytes + dst_bytes <= 28, SYN without ACK or RST; window=30, step=10; original capture/extraction/report transport")
    module.logging.info("REPORT_INTERVAL_SECONDS: 0.0; every computed window")


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("1", "2"):
        raise SystemExit("Usage: python3 heuristic.py 1|2")
    module = load_detector(int(sys.argv[1]))
    install_rule(module)
    module.main()


if __name__ == "__main__":
    main()
