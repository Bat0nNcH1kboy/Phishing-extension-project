from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODEL_PATH = Path(os.getenv("PHISHING_MODEL_PATH", BASE_DIR / "model.pkl"))
FEATURES_PATH = Path(os.getenv("PHISHING_FEATURES_PATH", BASE_DIR / "features.pkl"))
VERDICTS_PATH = Path(os.getenv("PHISHING_VERDICTS_PATH", DATA_DIR / "verdicts.json"))
API_HOST = os.getenv("API_HOST", "127.0.0.1")
API_PORT = int(os.getenv("API_PORT", "5001"))
API_DEBUG = os.getenv("API_DEBUG", "0").lower() in {"1", "true", "yes", "on"}
INCLUDE_DEBUG_FEATURES = os.getenv("PHISHING_INCLUDE_FEATURES", "0").lower() in {"1", "true", "yes", "on"}
DEMO_ENDPOINTS_ENABLED = os.getenv("PHISHING_DEMO_ENDPOINTS", "1").lower() in {"1", "true", "yes", "on"}

# Flask-CORS accepts literal origins and regular expressions. The default policy
# is intentionally limited to local development pages and Chrome extension pages.
# For a deployed backend, set CORS_ALLOWED_ORIGINS to exact trusted origins.
CORS_ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ALLOWED_ORIGINS",
        r"^chrome-extension://[a-z]{32}$,^http://localhost(:\d+)?$,^http://127\.0\.0\.1(:\d+)?$",
    ).split(",")
    if origin.strip()
]
