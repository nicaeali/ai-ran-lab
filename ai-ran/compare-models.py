#!/usr/bin/env python3
"""Evaluate the unchanged RF and fixed byte rule on the same held-out records."""

import hashlib
import json
from pathlib import Path
import runpy
import sys

import joblib
import pandas as pd
from sklearn.metrics import confusion_matrix


ROOT = Path(__file__).resolve().parents[1]
RULE = runpy.run_path(str(ROOT / "powder/byte-heuristic-detector.py"))


def metrics(actual, predicted):
    matrix = confusion_matrix(actual, predicted, labels=[0, 1]).tolist()
    (tn, fp), (fn, tp) = matrix
    return {"confusion_matrix": matrix, "rows": tn + fp + fn + tp,
            "accuracy": (tn + tp) / len(actual), "balanced_accuracy": (tn / (tn + fp) + tp / (tp + fn)) / 2,
            "attack_precision": tp / (tp + fp) if tp + fp else 0,
            "attack_recall": tp / (tp + fn), "attack_f1": 2 * tp / (2 * tp + fp + fn),
            "normal_false_positive_rate": fp / (fp + tn)}


def evaluate():
    paths = {name: ROOT / "notebooks" / name for name in ("Test.txt", "random_forest_model.pkl", "preprocessor.pkl")}
    hashes = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in paths.items()}
    for name, expected in RULE["ARTIFACT_HASHES"].items():
        if hashes[name] != expected:
            raise RuntimeError("Saved artifact differs from the fixed comparison: " + name)
    data = pd.read_csv(paths["Test.txt"], header=None)
    if data.shape[1] != 43:
        raise RuntimeError("Expected the bundled 43-column test dataset")
    features = data.iloc[:, [1, 2, 3, 4, 5]].copy()
    features.columns = ["protocol_type", "service", "flag", "src_bytes", "dst_bytes"]
    model = joblib.load(paths["random_forest_model.pkl"])
    preprocessor = joblib.load(paths["preprocessor.pkl"])
    if preprocessor.named_transformers_["cat"].categories_[2].tolist() != [""]:
        raise RuntimeError("Unexpected saved flag preprocessing")
    features["flag"] = ""
    actual = (data[41] != "normal").astype(int)
    forest = model.predict(preprocessor.transform(features[list(preprocessor.feature_names_in_)]))
    heuristic = (features["src_bytes"] + features["dst_bytes"] <= RULE["THRESHOLD"]).astype(int)
    return {"rf": metrics(actual, forest), "byte_rule": metrics(actual, heuristic), "sha256": hashes,
            "heuristic": {"rule": "attack iff src_bytes + dst_bytes <= 28", "threshold_bytes": RULE["THRESHOLD"],
                          "selection": "Fixed beforehand by maximizing training-only balanced accuracy; lowest-cutoff tie break",
                          "live_reporting_interval_seconds": 10},
            "scope": "Held-out record classification. Reporting cadence affects the live comparison, not these offline predictions."}


if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit("Run compare-models without arguments")
    print(json.dumps(evaluate(), indent=2))
