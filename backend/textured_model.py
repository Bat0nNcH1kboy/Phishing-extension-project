"""Hybrid classifier with engineered features and URL textural n-grams."""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline


class TexturedUrlClassifier:
    """Combines numeric URL features with character-level URL texture analysis.

    The RandomForest part uses deterministic engineered features. The textural
    part uses TF-IDF over character n-grams, which captures URL string texture:
    repeated login/auth fragments, brand-typo substrings, random tokens and
    separator rhythm. The final probability is a weighted average.
    """

    def __init__(
        self,
        feature_names: list[str],
        numeric_weight: float = 0.58,
        textural_weight: float = 0.42,
        threshold: float = 0.5,
        numeric_estimators: int = 35,
        numeric_depth: int = 12,
        text_max_features: int = 18000,
        random_state: int = 42,
    ) -> None:
        self.feature_names = list(feature_names)
        self.numeric_weight = float(numeric_weight)
        self.textural_weight = float(textural_weight)
        self.threshold = float(threshold)
        self.uses_url_textures = True
        self.text_texture_ngram_range = (3, 5)
        self.numeric_model = RandomForestClassifier(
            n_estimators=numeric_estimators,
            max_depth=numeric_depth,
            min_samples_leaf=2,
            min_samples_split=4,
            random_state=random_state,
            class_weight="balanced_subsample",
            n_jobs=1,
        )
        self.textural_pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(
                analyzer="char_wb",
                ngram_range=self.text_texture_ngram_range,
                lowercase=True,
                min_df=2,
                max_features=text_max_features,
                sublinear_tf=True,
            )),
            ("clf", LogisticRegression(
                max_iter=900,
                class_weight="balanced",
                solver="liblinear",
                random_state=random_state,
            )),
        ])

    @staticmethod
    def _text(urls: Iterable[str]) -> list[str]:
        return [str(url).lower() for url in urls]

    @staticmethod
    def _positive_probability(model: Any, x: Any) -> np.ndarray:
        proba = model.predict_proba(x)
        classes = list(model.classes_)
        if 1 in classes:
            return proba[:, classes.index(1)]
        return proba.max(axis=1)

    def fit(self, x: pd.DataFrame, urls: Iterable[str], y: Iterable[int]) -> "TexturedUrlClassifier":
        frame = pd.DataFrame(x)[self.feature_names]
        labels = pd.Series(y).astype(int)
        text = self._text(urls)
        self.numeric_model.fit(frame, labels)
        self.textural_pipeline.fit(text, labels)
        return self

    def predict_proba_with_urls(self, x: pd.DataFrame, urls: Iterable[str]) -> np.ndarray:
        frame = pd.DataFrame(x)[self.feature_names]
        text = self._text(urls)
        numeric_positive = self._positive_probability(self.numeric_model, frame)
        textural_positive = self._positive_probability(self.textural_pipeline, text)
        positive = (
            numeric_positive * self.numeric_weight
            + textural_positive * self.textural_weight
        ) / max(self.numeric_weight + self.textural_weight, 0.0001)
        positive = np.clip(positive, 0.0, 1.0)
        return np.column_stack([1.0 - positive, positive])

    def predict_with_urls(self, x: pd.DataFrame, urls: Iterable[str]) -> np.ndarray:
        positive = self.predict_proba_with_urls(x, urls)[:, 1]
        return (positive >= self.threshold).astype(int)

    def predict_url_proba(self, url: str, features: dict[str, int | float]) -> float:
        frame = pd.DataFrame([features])[self.feature_names]
        return float(self.predict_proba_with_urls(frame, [url])[0, 1])

    def predict_url(self, url: str, features: dict[str, int | float]) -> int:
        return int(self.predict_url_proba(url, features) >= self.threshold)

    # Compatibility fallback for tools that only pass engineered features.
    def predict_proba(self, x: pd.DataFrame) -> np.ndarray:
        frame = pd.DataFrame(x)[self.feature_names]
        return self.numeric_model.predict_proba(frame)

    def predict(self, x: pd.DataFrame) -> np.ndarray:
        proba = self.predict_proba(x)
        classes = list(self.numeric_model.classes_)
        if 1 in classes:
            return (proba[:, classes.index(1)] >= self.threshold).astype(int)
        return self.numeric_model.predict(frame)
