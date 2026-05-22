"""Hybrid risk scoring layer that combines ML, transparent heuristics and DNS."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from dns_checker import DnsResult
from feature_extractor import explain, extract_features, heuristic_score
from url_texture import summarize_texture_features
from model_service import ModelService


@dataclass(frozen=True)
class RiskPolicy:
    low_threshold: float = 0.35
    phishing_threshold: float = 0.60
    high_threshold: float = 0.78
    ml_weight: float = 0.62
    heuristic_weight: float = 0.38


class RiskEngine:
    """Builds a final verdict from model probability, heuristic score and DNS."""

    def __init__(self, model_service: ModelService, policy: RiskPolicy | None = None):
        self.model_service = model_service
        self.policy = policy or RiskPolicy()

    def analyze(
        self,
        normalized_url: str,
        dns_result: DnsResult | None = None,
        include_features: bool = False,
    ) -> dict[str, Any]:
        features = extract_features(normalized_url)
        dns_resolvable = dns_result.resolvable if dns_result is not None else None
        model_result = self.model_service.predict(normalized_url, include_features=False)
        transparent_score = heuristic_score(features, dns_resolvable=dns_resolvable)
        model_probability = float(model_result.get("phishing_probability", 0.5))
        combined = (
            model_probability * self.policy.ml_weight
            + transparent_score * self.policy.heuristic_weight
        )

        # Strong transparent signals must not be hidden by an overconfident model.
        if features.get("qty_at_url") or features.get("brand_impersonation"):
            combined = max(combined, 0.72)
        if features.get("domain_in_ip") and features.get("suspicious_words_count", 0) >= 2:
            combined = max(combined, 0.76)
        if dns_resolvable is False and not features.get("trusted_registered_domain"):
            combined = max(combined, 0.55)
        combined = round(max(0.0, min(combined, 0.99)), 4)

        verdict = "phishing" if combined >= self.policy.phishing_threshold else "safe"
        if combined >= self.policy.high_threshold:
            risk_level = "high"
        elif combined >= self.policy.low_threshold:
            risk_level = "medium"
        else:
            risk_level = "low"
        confidence = combined if verdict == "phishing" else 1.0 - combined
        reasons = explain(features, dns_resolvable=dns_resolvable)

        result: dict[str, Any] = {
            "verdict": verdict,
            "source": "hybrid",
            "confidence": round(float(confidence), 3),
            "phishing_probability": round(float(combined), 3),
            "risk_level": risk_level,
            "reasons": reasons,
            "checks": {
                "ml_probability": round(model_probability, 3),
                "heuristic_score": round(transparent_score, 3),
                "dns_checked": bool(dns_result and dns_result.checked),
                "dns_resolvable": dns_resolvable,
                "model_source": model_result.get("source", "unknown"),
                "url_texture_model": model_result.get("source") == "ml_textured",
            },
            "texture_analysis": summarize_texture_features(features),
        }
        if dns_result is not None:
            result["dns"] = dns_result.to_dict(include_addresses=False)
        if include_features:
            result["features"] = features
        return result
