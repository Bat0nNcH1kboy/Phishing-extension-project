"""Model loading and prediction service for phishing URL detection."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import pandas as pd

from feature_extractor import FEATURE_NAMES, extract_features, explain


class ModelService:
    """Thin service layer over the trained classifier with a deterministic fallback."""

    def __init__(self, model_path: str | Path, features_path: str | Path):
        self.model_path = Path(model_path)
        self.features_path = Path(features_path)
        self.model: Any | None = None
        self.feature_names: list[str] = list(FEATURE_NAMES)
        self.load()

    def load(self) -> None:
        if self.model_path.exists() and self.features_path.exists():
            self.model = joblib.load(self.model_path)
            loaded_features = list(joblib.load(self.features_path))
            missing = set(loaded_features) - set(FEATURE_NAMES)
            if missing:
                raise ValueError(f"Model expects unknown features: {sorted(missing)}")
            self.feature_names = loaded_features
        else:
            self.model = None

    def predict(self, url: str, include_features: bool = False) -> dict[str, Any]:
        features = extract_features(url)
        reasons = explain(features)

        if self.model is not None:
            frame = pd.DataFrame([features])[self.feature_names]
            prediction = int(self.model.predict(frame)[0])
            probability = self._phishing_probability(frame)
            confidence = probability if prediction == 1 else 1.0 - probability
            source = "ml"
        else:
            prediction, probability, confidence = self._heuristic_prediction(features)
            source = "heuristic"

        verdict = "phishing" if prediction == 1 else "safe"
        if verdict == "phishing" and confidence >= 0.75:
            risk_level = "high"
        elif verdict == "phishing" or reasons:
            risk_level = "medium"
        else:
            risk_level = "low"

        result = {
            "verdict": verdict,
            "source": source,
            "confidence": round(float(confidence), 3),
            "phishing_probability": round(float(probability), 3),
            "risk_level": risk_level,
            "reasons": reasons,
        }
        if include_features:
            result["features"] = features
        return result

    def _phishing_probability(self, frame: pd.DataFrame) -> float:
        if not hasattr(self.model, "predict_proba"):
            return 0.5
        proba = self.model.predict_proba(frame)[0]
        classes = list(self.model.classes_)
        if 1 in classes:
            return float(proba[classes.index(1)])
        return float(max(proba))

    @staticmethod
    def _heuristic_prediction(features: dict[str, int | float]) -> tuple[int, float, float]:
        """Fallback used before training; returns prediction, probability, confidence."""
        score = 0.0
        score += min(float(features["length_url"]) / 180.0, 0.25)
        score += 0.18 if features["qty_at_url"] else 0.0
        score += 0.20 if features["domain_in_ip"] else 0.0
        score += 0.12 if features["url_shortened"] else 0.0
        score += 0.10 if features["punycode_domain"] else 0.0
        score += min(float(features["suspicious_words_count"]) * 0.08, 0.24)
        score += min(float(features["qty_subdomains"]) * 0.05, 0.15)
        score = min(score, 0.99)
        prediction = int(score >= 0.5)
        confidence = max(score, 1.0 - score)
        return prediction, score, confidence
