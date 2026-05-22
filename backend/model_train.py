"""Train a hybrid URL phishing model with engineered and textural features."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import StratifiedKFold, train_test_split

from config import DATASET_PATH, FEATURES_PATH, MODEL_PATH
from feature_extractor import FEATURE_NAMES, extract_features
from textured_model import TexturedUrlClassifier

BASE_DIR = Path(__file__).resolve().parent
METRICS_PATH = BASE_DIR / "metrics.json"


def _read_dataset(dataset_path: Path, max_rows: int | None = None) -> pd.DataFrame:
    data = pd.read_csv(dataset_path)
    if "url" not in data.columns or "label" not in data.columns:
        raise ValueError("dataset.csv must contain url and label columns")
    if data.empty:
        raise ValueError("dataset.csv is empty")
    data = data[["url", "label"]].copy()
    data["label"] = data["label"].astype(int)
    if not set(data["label"].unique()).issubset({0, 1}):
        raise ValueError("label must contain only 0 and 1")
    if data["label"].nunique() < 2:
        raise ValueError("dataset must contain both safe and phishing classes")
    if max_rows is not None and len(data) > max_rows:
        per_class = max(1, max_rows // max(data["label"].nunique(), 1))
        sampled = [
            frame.sample(n=min(len(frame), per_class), random_state=42)
            for _, frame in data.groupby("label")
        ]
        data = pd.concat(sampled, ignore_index=True).sample(frac=1.0, random_state=42).reset_index(drop=True)
    return data


def _features_from_data(data: pd.DataFrame) -> pd.DataFrame:
    rows = [extract_features(str(url)) for url in data["url"]]
    return pd.DataFrame(rows)[FEATURE_NAMES]


def build_frame(dataset_path: Path = DATASET_PATH, max_rows: int | None = None) -> tuple[pd.DataFrame, pd.Series]:
    """Build numeric feature matrix; kept stable for tests and diagnostics."""
    data = _read_dataset(dataset_path, max_rows=max_rows)
    x = _features_from_data(data)
    y = data["label"].astype(int)
    return x, y


def build_training_data(
    dataset_path: Path = DATASET_PATH,
    max_rows: int | None = None,
) -> tuple[pd.DataFrame, pd.Series, pd.Series]:
    """Build feature matrix, labels and raw URL strings for textural n-grams."""
    data = _read_dataset(dataset_path, max_rows=max_rows)
    x = _features_from_data(data)
    y = data["label"].astype(int)
    urls = data["url"].astype(str)
    return x, y, urls


def _cross_validate_textured_model(x: pd.DataFrame, y: pd.Series, urls: pd.Series) -> list[float]:
    if y.nunique() != 2 or y.value_counts().min() < 5:
        return []
    cv_frame = x.copy()
    cv_frame["__label"] = y.values
    cv_frame["__url"] = urls.values
    if len(cv_frame) > 2000:
        cv_frame = cv_frame.groupby("__label", group_keys=False).sample(n=1000, random_state=42)
    cv_y = cv_frame["__label"].astype(int).reset_index(drop=True)
    cv_urls = cv_frame["__url"].astype(str).reset_index(drop=True)
    cv_x = cv_frame.drop(columns=["__label", "__url"]).reset_index(drop=True)
    cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
    scores: list[float] = []
    for train_idx, test_idx in cv.split(cv_x, cv_y):
        fold_model = TexturedUrlClassifier(
            FEATURE_NAMES,
            numeric_estimators=20,
            numeric_depth=10,
            text_max_features=8000,
        )
        fold_model.fit(cv_x.iloc[train_idx], cv_urls.iloc[train_idx], cv_y.iloc[train_idx])
        fold_predictions = fold_model.predict_with_urls(cv_x.iloc[test_idx], cv_urls.iloc[test_idx])
        scores.append(float(accuracy_score(cv_y.iloc[test_idx], fold_predictions)))
    return scores


def train(dataset_path: Path = DATASET_PATH, max_rows: int | None = None) -> TexturedUrlClassifier:
    x, y, urls = build_training_data(dataset_path, max_rows=max_rows)
    stratify = y if y.nunique() == 2 and y.value_counts().min() >= 2 else None
    x_train, x_test, y_train, y_test, url_train, url_test = train_test_split(
        x, y, urls, test_size=0.25, random_state=42, stratify=stratify
    )
    model = TexturedUrlClassifier(FEATURE_NAMES)
    model.fit(x_train, url_train, y_train)
    predictions = model.predict_with_urls(x_test, url_test)
    probabilities = model.predict_proba_with_urls(x_test, url_test)[:, 1]
    matrix = confusion_matrix(y_test, predictions)
    report_text = classification_report(y_test, predictions, zero_division=0)
    cv_scores = _cross_validate_textured_model(x, y, urls)

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, predictions, average="binary", zero_division=0
    )
    metrics = {
        "dataset_size": int(sum(1 for _ in open(dataset_path, encoding="utf-8")) - 1),
        "training_size": int(len(y)),
        "safe_count": int((y == 0).sum()),
        "phishing_count": int((y == 1).sum()),
        "test_size": int(len(y_test)),
        "feature_count": int(len(FEATURE_NAMES)),
        "texture_feature_count": int(sum(1 for name in FEATURE_NAMES if name.startswith("texture_"))),
        "textural_ngram_model": True,
        "textural_ngram_range": list(model.text_texture_ngram_range),
        "textural_max_features": int(model.textural_pipeline.named_steps["tfidf"].max_features),
        "model": "TexturedUrlClassifier(RandomForest + char_wb TF-IDF LogisticRegression)",
        "accuracy": round(float(accuracy_score(y_test, predictions)), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
        "mean_phishing_probability": round(float(probabilities.mean()), 4),
        "confusion_matrix": matrix.tolist(),
        "cv_accuracy_mean": round(float(sum(cv_scores) / len(cv_scores)), 4) if cv_scores else None,
        "cv_accuracy_scores": [round(float(score), 4) for score in cv_scores],
        "note": "Synthetic dataset. Metrics confirm reproducible training on the bundled data.",
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Train phishing URL classifier")
    parser.add_argument("--dataset", type=Path, default=DATASET_PATH)
    parser.add_argument(
        "--max-rows",
        type=int,
        default=20000,
        help="Stratified training sample size. Set to dataset size for full rebuild; default keeps training faster.",
    )
    args = parser.parse_args()
    train(dataset_path=args.dataset, max_rows=args.max_rows)


if __name__ == "__main__":
    main()
