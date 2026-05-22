from __future__ import annotations

import logging

from flask import Flask, jsonify, request
from flask_cors import CORS

from config import (
    API_DEBUG,
    API_HOST,
    API_PORT,
    CORS_ALLOWED_ORIGINS,
    DEMO_ENDPOINTS_ENABLED,
    DNS_CHECK_ENABLED,
    DNS_TIMEOUT_SECONDS,
    FEATURES_PATH,
    INCLUDE_DEBUG_FEATURES,
    MODEL_PATH,
    VERDICTS_PATH,
    VERDICTS_SAMPLE_LIMIT,
)
from dns_checker import resolve_domain
from feature_extractor import extract_domain, extract_features, normalize_url
from url_texture import summarize_texture_features
from model_service import ModelService
from risk_engine import RiskEngine
from verdict_repository import VerdictRepository

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("phishing-checker")


def _validation_error(message: str, raw_url: str, status: int = 400):
    return jsonify({
        "verdict": "unknown",
        "source": "validation",
        "confidence": 0.0,
        "phishing_probability": 0.0,
        "risk_level": "unknown",
        "reasons": [message],
        "normalized_url": raw_url,
        "domain": "",
        "checks": {
            "ml_probability": None,
            "heuristic_score": None,
            "dns_checked": False,
            "dns_resolvable": None,
            "model_source": None,
        },
    }), status


def _bool_arg(name: str, default: bool) -> bool:
    raw = request.args.get(name)
    if raw is None:
        return default
    return raw.lower() in {"1", "true", "yes", "on"}


def create_app(enable_dns_check: bool | None = None) -> Flask:
    app = Flask(__name__)
    CORS(
        app,
        resources={r"/api/*": {"origins": CORS_ALLOWED_ORIGINS}},
        supports_credentials=False,
        max_age=600,
    )

    repository = VerdictRepository(VERDICTS_PATH)
    model_service = ModelService(MODEL_PATH, FEATURES_PATH)
    risk_engine = RiskEngine(model_service)
    dns_enabled = DNS_CHECK_ENABLED if enable_dns_check is None else bool(enable_dns_check)

    @app.get("/")
    @app.get("/health")
    def health():
        return jsonify({
            "status": "ok",
            "service": "phishing-url-checker",
            "model_loaded": model_service.model is not None,
            "model_load_error": model_service.load_error,
            "debug": API_DEBUG,
            "dns_check_enabled": dns_enabled,
            "verdict_base_size": repository.count(),
            "verdict_base_stats": repository.stats(),
        })

    @app.post("/api/check")
    def check_url():
        payload = request.get_json(silent=True) or {}
        if "url" not in payload:
            return _validation_error("URL field is required", "")
        raw_url = str(payload.get("url", ""))
        include_features = bool(payload.get("include_features", False)) and INCLUDE_DEBUG_FEATURES
        force_dns = bool(payload.get("dns_check", False))
        try:
            normalized_url = normalize_url(raw_url)
            domain = extract_domain(normalized_url)
            features_for_summary = extract_features(normalized_url)
            record = repository.find(normalized_url, domain)
            dns_result = None
            should_check_dns = dns_enabled or force_dns
            if should_check_dns:
                dns_result = resolve_domain(domain, DNS_TIMEOUT_SECONDS)

            if record:
                verdict = record.get("verdict", "unknown")
                logger.info("checked domain=%s verdict=%s source=database", domain, verdict)
                response = {
                    "verdict": verdict,
                    "source": "database",
                    "confidence": 1.0,
                    "phishing_probability": 1.0 if verdict == "phishing" else 0.0,
                    "risk_level": "high" if verdict == "phishing" else "low",
                    "reasons": [record.get("comment", "совпадение с внутренней базой")],
                    "normalized_url": normalized_url,
                    "domain": domain,
                    "checks": {
                        "ml_probability": None,
                        "heuristic_score": None,
                        "dns_checked": bool(dns_result and dns_result.checked),
                        "dns_resolvable": dns_result.resolvable if dns_result else None,
                        "model_source": None,
                        "url_texture_model": False,
                    },
                    "texture_analysis": summarize_texture_features(features_for_summary),
                }
                if dns_result is not None:
                    response["dns"] = dns_result.to_dict(include_addresses=False)
                return jsonify(response)

            result = risk_engine.analyze(
                normalized_url,
                dns_result=dns_result,
                include_features=include_features,
            )
            result.update({"normalized_url": normalized_url, "domain": domain})
            logger.info("checked domain=%s verdict=%s source=%s", domain, result["verdict"], result["source"])
            return jsonify(result)
        except ValueError as exc:
            return _validation_error(str(exc), raw_url)
        except Exception:  # defensive boundary for the browser extension
            logger.exception("unexpected check error")
            return jsonify({
                "verdict": "unknown",
                "source": "error",
                "confidence": 0.0,
                "phishing_probability": 0.0,
                "risk_level": "unknown",
                "reasons": ["internal server error"],
                "normalized_url": raw_url,
                "domain": "",
            }), 500

    @app.post("/predict")
    def legacy_predict():
        return check_url()

    @app.get("/api/verdicts")
    def list_verdicts():
        if not DEMO_ENDPOINTS_ENABLED:
            return jsonify({
                "error": "demo endpoint is disabled",
                "hint": "set PHISHING_DEMO_ENDPOINTS=1 for local demonstration",
            }), 404
        limit = int(request.args.get("limit", VERDICTS_SAMPLE_LIMIT))
        offset = int(request.args.get("offset", 0))
        full = _bool_arg("full", False)
        if full:
            return jsonify({"stats": repository.stats(), "items": repository.all()})
        return jsonify({
            "stats": repository.stats(),
            "limit": max(0, min(limit, 250)),
            "offset": max(0, offset),
            "items": repository.sample(limit=limit, offset=offset),
        })

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host=API_HOST, port=API_PORT, debug=API_DEBUG)
