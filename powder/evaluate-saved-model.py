#!/usr/bin/env python3
"""Reproduce offline binary classification with the bundled RF artifacts."""

import hashlib
import json
from pathlib import Path

import joblib
import pandas as pd
import sklearn
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, roc_auc_score


def main():
    root = Path(__file__).resolve().parents[1]
    # Column schema of the bundled NSL-KDD test records.
    columns = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty_level']
    data = pd.read_csv(root / "notebooks/Test.txt", names=columns, header=None)
    preprocessor = joblib.load(root / "notebooks/preprocessor.pkl")
    model = joblib.load(root / "notebooks/random_forest_model.pkl")
    flag_categories = preprocessor.named_transformers_["cat"].categories_[2].tolist()
    if flag_categories != [""]:
        raise RuntimeError("The bundled preprocessing artifact changed; review its flag mapping before comparison")
    # The training notebook iterated over characters, producing an empty flag
    # for every row. Reproduce that artifact here; do not silently retrain it.
    data["flag"] = ""
    features = data[list(preprocessor.feature_names_in_)]
    transformed = preprocessor.transform(features)
    actual = (data["label"] != "normal").astype(int)
    predicted = model.predict(transformed)
    probabilities = model.predict_proba(transformed)[:, 1]
    report = {
        "sklearn_version": sklearn.__version__,
        "rows": len(data),
        "features": list(preprocessor.feature_names_in_),
        "training_flag_categories": flag_categories,
        "accuracy": accuracy_score(actual, predicted),
        "roc_auc_from_probabilities": roc_auc_score(actual, probabilities),
        "confusion_matrix_true_rows_predicted_columns": confusion_matrix(actual, predicted).tolist(),
        "classification_report": classification_report(actual, predicted, output_dict=True),
        "sha256": {name: hashlib.sha256((root / "notebooks" / name).read_bytes()).hexdigest()
                   for name in ("Test.txt", "preprocessor.pkl", "random_forest_model.pkl")},
        "scope": "Offline dataset records; this is not live packet-classification accuracy.",
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
