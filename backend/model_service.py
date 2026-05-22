"""Model loading and prediction service for phishing URL detection."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import pandas as pd

from feature_extractor import FEATURE_NAMES, extract_features, heuristic_score


class ModelService:
    """Thin service layer over the trained classifier with deterministic fallback."""

    def __init__(self, model_path: str | Path, features_path: str | Path):
        self.model_path = Path(model_path)
        self.features_path = Path(features_path)
        self.model: Any | None = None
        self.feature_names: list[str] = list(FEATURE_NAMES)
        self.load_error: str | None = None
        self.load()

    def load(self) -> None:
        if not (self.model_path.exists() and self.features_path.exists()):
            self.model = None
            self.load_error = "model files are missing"
            return
        try:
            model = joblib.load(self.model_path)
            loaded_features = list(joblib.load(self.features_path))
            unknown = set(loaded_features) - set(FEATURE_NAMES)
            if unknown:
                raise ValueError(f"Model expects unknown features: {sorted(unknown)}")
            self.model = model
            self.feature_names = loaded_features
            self.load_error = None
        except Exception as exc:  # corrupted model must not break request processing
            self.model = None
            self.feature_names = list(FEATURE_NAMES)
            self.load_error = str(exc)

    def predict(self, url: str, include_features: bool = False) -> dict[str, Any]:
        features = extract_features(url)

        if self.model is not None:
            frame = pd.DataFrame([features])[self.feature_names]
            if hasattr(self.model, "predict_url_proba") and hasattr(self.model, "predict_url"):
                probability = float(self.model.predict_url_proba(url, features))
                prediction = int(self.model.predict_url(url, features))
                source = "ml_textured"
            else:
                prediction = int(self.model.predict(frame)[0])
                probability = self._phishing_probability(frame)
                source = "ml"
            confidence = probability if prediction == 1 else 1.0 - probability
        else:
            prediction, probability, confidence = self._heuristic_prediction(features)
            source = "heuristic"

        verdict = "phishing" if prediction == 1 else "safe"
        if verdict == "phishing" and confidence >= 0.75:
            risk_level = "high"
        elif verdict == "phishing" or probability >= 0.35:
            risk_level = "medium"
        else:
            risk_level = "low"

        result = {
            "verdict": verdict,
            "source": source,
            "confidence": round(float(confidence), 3),
            "phishing_probability": round(float(probability), 3),
            "risk_level": risk_level,
        }
        if self.load_error and source == "heuristic":
            result["model_load_error"] = self.load_error
        if include_features:
            result["features"] = features
        return result

    def _phishing_probability(self, frame: pd.DataFrame) -> float:
        if self.model is None or not hasattr(self.model, "predict_proba"):
            return 0.5
        proba = self.model.predict_proba(frame)[0]
        classes = list(self.model.classes_)
        if 1 in classes:
            return float(proba[classes.index(1)])
        return float(max(proba))

    @staticmethod
    def _heuristic_prediction(features: dict[str, int | float]) -> tuple[int, float, float]:
        """Fallback used before training; returns prediction, probability, confidence."""
        score = heuristic_score(features)
        prediction = int(score >= 0.55)
        confidence = max(score, 1.0 - score)
        return prediction, score, confidence
