"""Train a lightweight RandomForest model for URL phishing detection."""
from __future__ import annotations

import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split

from feature_extractor import FEATURE_NAMES, extract_features

BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "data" / "dataset.csv"
MODEL_PATH = BASE_DIR / "model.pkl"
FEATURES_PATH = BASE_DIR / "features.pkl"
METRICS_PATH = BASE_DIR / "metrics.json"


def build_frame(dataset_path: Path = DATASET_PATH) -> tuple[pd.DataFrame, pd.Series]:
    data = pd.read_csv(dataset_path)
    if "url" not in data.columns or "label" not in data.columns:
        raise ValueError("dataset.csv must contain url and label columns")
    if data.empty:
        raise ValueError("dataset.csv is empty")
    rows = [extract_features(str(url)) for url in data["url"]]
    x = pd.DataFrame(rows)[FEATURE_NAMES]
    y = data["label"].astype(int)
    if not set(y.unique()).issubset({0, 1}):
        raise ValueError("label must contain only 0 and 1")
    return x, y


def train() -> RandomForestClassifier:
    x, y = build_frame()
    stratify = y if y.nunique() == 2 and y.value_counts().min() >= 2 else None
    x_train, x_test, y_train, y_test = train_test_split(
        x, y, test_size=0.25, random_state=42, stratify=stratify
    )
    model = RandomForestClassifier(
        n_estimators=220,
        max_depth=10,
        min_samples_leaf=1,
        random_state=42,
        class_weight="balanced",
    )
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)
    matrix = confusion_matrix(y_test, predictions)
    report_text = classification_report(y_test, predictions, zero_division=0)

    cv_scores = []
    if y.nunique() == 2 and y.value_counts().min() >= 5:
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        cv_scores = list(cross_val_score(model, x, y, cv=cv, scoring="accuracy"))

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, predictions, average="binary", zero_division=0
    )
    metrics = {
        "dataset_size": int(len(y)),
        "safe_count": int((y == 0).sum()),
        "phishing_count": int((y == 1).sum()),
        "test_size": int(len(y_test)),
        "accuracy": round(float(accuracy_score(y_test, predictions)), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
        "confusion_matrix": matrix.tolist(),
        "cv_accuracy_mean": round(float(sum(cv_scores) / len(cv_scores)), 4) if cv_scores else None,
        "cv_accuracy_scores": [round(float(score), 4) for score in cv_scores],
        "note": "Educational synthetic/demo dataset; metrics are not a production guarantee.",
    }

    print("Confusion matrix:")
    print(matrix)
    print("Classification report:")
    print(report_text)
    if cv_scores:
        print("5-fold CV accuracy:", ", ".join(f"{score:.3f}" for score in cv_scores))
        print(f"5-fold CV mean accuracy: {metrics['cv_accuracy_mean']:.3f}")

    joblib.dump(model, MODEL_PATH)
    joblib.dump(FEATURE_NAMES, FEATURES_PATH)
    METRICS_PATH.write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Saved model to {MODEL_PATH}")
    print(f"Saved metrics to {METRICS_PATH}")
    return model


if __name__ == "__main__":
    train()
