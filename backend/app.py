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
    FEATURES_PATH,
    INCLUDE_DEBUG_FEATURES,
    MODEL_PATH,
    VERDICTS_PATH,
)
from feature_extractor import extract_domain, normalize_url
from model_service import ModelService
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
    }), status


def create_app() -> Flask:
    app = Flask(__name__)
    CORS(
        app,
        resources={r"/api/*": {"origins": CORS_ALLOWED_ORIGINS}},
        supports_credentials=False,
        max_age=600,
    )

    repository = VerdictRepository(VERDICTS_PATH)
    model_service = ModelService(MODEL_PATH, FEATURES_PATH)

    @app.get("/")
    @app.get("/health")
    def health():
        return jsonify({
            "status": "ok",
            "service": "phishing-url-checker",
            "model_loaded": model_service.model is not None,
            "debug": API_DEBUG,
        })

    @app.post("/api/check")
    def check_url():
        payload = request.get_json(silent=True) or {}
        if "url" not in payload:
            return _validation_error("URL field is required", "")
        raw_url = str(payload.get("url", ""))
        try:
            normalized_url = normalize_url(raw_url)
            domain = extract_domain(normalized_url)
            record = repository.find(normalized_url, domain)
            if record:
                verdict = record.get("verdict", "unknown")
                logger.info("checked domain=%s verdict=%s source=database", domain, verdict)
                return jsonify({
                    "verdict": verdict,
                    "source": "database",
                    "confidence": 1.0,
                    "phishing_probability": 1.0 if verdict == "phishing" else 0.0,
                    "risk_level": "high" if verdict == "phishing" else "low",
                    "reasons": [record.get("comment", "совпадение с внутренней базой")],
                    "normalized_url": normalized_url,
                    "domain": domain,
                })

            result = model_service.predict(normalized_url, include_features=INCLUDE_DEBUG_FEATURES)
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
        return jsonify(repository.all())

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host=API_HOST, port=API_PORT, debug=API_DEBUG)
