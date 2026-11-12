#!/usr/bin/env python3
"""Swap only the classifier in the pinned packaged detector; preserve capture/reporting.

Run inside the appropriate UPF with /app as the working directory. The original
files and ML artifacts are read-only. Threshold 28 was fixed by training-only
offline calibration before this live experiment.
"""

import argparse
import gc
import hashlib
import importlib.util
from pathlib import Path
import time


THRESHOLD = 28
ORIGINAL_HASHES = {
    1: "de62b5a63f62eca4581ec851ae95f06eb0eff5bf4243ac344aaf88f2d8fae1fe",
    2: "2cd6cdb15f8cdc7b8c4127a5a8dc568bbc42808ccdae2fc48ea4a168c0a6caba",
}
ARTIFACT_HASHES = {
    "random_forest_model.pkl": "e51d159d41c628ded011392decc004a945d735d3392dea4a62549b8fe10e96bd",
    "preprocessor.pkl": "7b36e33b30c342ff17085bff0ba1076ed3c3d2c52995fa85548e291da517fbb3",
}


def load_detector(number):
    path = Path(f"/app/anomaly-detection-server-slice{number}.py")
    expected = {path: ORIGINAL_HASHES[number],
                **{Path("/app") / name: value for name, value in ARTIFACT_HASHES.items()}}
    for source, value in expected.items():
        if hashlib.sha256(source.read_bytes()).hexdigest() != value:
            raise RuntimeError(f"Pinned detector/artifact changed: {source}")
    spec = importlib.util.spec_from_file_location(f"packaged_detector_{number}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if (module.window_size, module.step_size, module.sst, module.sd) != (30, 10, 1, 1 if number == 1 else 5):
        raise RuntimeError("Unexpected packaged detector configuration")
    return module


def install_rule(module, report_interval=0.0):
    last_report = None
    def make_predictions():
        nonlocal last_report
        predictions = [int(row["src_bytes"] + row["dst_bytes"] <= THRESHOLD)
                       for row in module.sliding_window]
        anomaly_count = sum(predictions)
        normal_count = len(predictions) - anomaly_count
        module.logging.info(f"Window results: {normal_count} Normal, {anomaly_count} Anomaly")
        message = f"sst:{module.sst},sd:{module.sd},normal:{normal_count},anomaly:{anomaly_count}"
        now = time.monotonic()
        if last_report is None or now - last_report >= report_interval:
            print(message, flush=True)
            module.send_message_to_server(message)
            last_report = now
            if report_interval:
                module.logging.info(f"PERIODIC_REPORT attempt: {message}")
        for _ in range(module.step_size):
            module.sliding_window.popleft()
    module.make_predictions = make_predictions
    # Import uses the original initialization, but the heuristic needs neither
    # prediction object. Release these in-memory references; never edit pickles.
    module.model = None
    module.preprocessor = None
    gc.collect()
    module.logging.info("BYTE_HEURISTIC: src_bytes + dst_bytes <= 28; window=30, step=10; original capture/extraction/report transport")
    module.logging.info(f"REPORT_INTERVAL_SECONDS: {report_interval}; 0 means every window; periodic mode is a reporting-latency ablation")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slice", type=int, choices=(1, 2), required=True)
    parser.add_argument("--report-interval", type=float, default=0.0)
    args = parser.parse_args()
    if args.report_interval not in (0.0, 10.0):
        parser.error("only the declared 0- or 10-second reporting variants are supported")
    module = load_detector(args.slice)
    install_rule(module, args.report_interval)
    module.main()


if __name__ == "__main__":
    main()
