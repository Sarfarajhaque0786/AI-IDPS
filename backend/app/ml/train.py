"""
Trains a Random Forest classifier on the sample traffic dataset.
Saves the trained model, label encoder, and evaluation metrics.

Run from backend/ with venv active:
    python -m app.ml.train
"""
import os
import csv
import json
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report,
)

from app.network.feature_extractor import extract_features, FEATURE_NAMES

DATASET_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "datasets", "sample", "traffic_sample.csv"
)
MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")
RANDOM_SEED = 42


def load_dataset(path):
    records, labels = [], []
    with open(path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            record = {
                "packet_count": int(row["packet_count"]),
                "byte_count": int(row["byte_count"]),
                "protocol": row["protocol"],
                "source_port": int(row["source_port"]),
                "destination_port": int(row["destination_port"]),
            }
            records.append(record)
            labels.append(row["label"])
    return records, labels


def main():
    os.makedirs(MODELS_DIR, exist_ok=True)

    print(f"Loading dataset from {DATASET_PATH} ...")
    records, labels = load_dataset(DATASET_PATH)
    print(f"Loaded {len(records)} rows.")

    X = np.array([extract_features(r) for r in records])

    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(labels)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_SEED, stratify=y
    )

    print("Training RandomForestClassifier...")
    model = RandomForestClassifier(n_estimators=100, random_state=RANDOM_SEED)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average="weighted", zero_division=0)
    recall = recall_score(y_test, y_pred, average="weighted", zero_division=0)
    f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)
    cm = confusion_matrix(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=label_encoder.classes_, zero_division=0)

    print("\n=== Evaluation Results ===")
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1 Score:  {f1:.4f}")
    print("\nConfusion Matrix:")
    print(cm)
    print("\nClassification Report:")
    print(report)

    joblib.dump(model, os.path.join(MODELS_DIR, "random_forest_model.joblib"))
    joblib.dump(label_encoder, os.path.join(MODELS_DIR, "label_encoder.joblib"))

    metrics = {
        "algorithm": "RandomForestClassifier",
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "feature_names": FEATURE_NAMES,
        "classes": label_encoder.classes_.tolist(),
        "train_rows": len(X_train),
        "test_rows": len(X_test),
    }
    with open(os.path.join(MODELS_DIR, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"\nModel saved to {MODELS_DIR}")


if __name__ == "__main__":
    main()