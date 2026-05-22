from pathlib import Path

from model_service import ModelService


def test_service_fallback_returns_verdict(tmp_path: Path):
    service = ModelService(tmp_path / "missing_model.pkl", tmp_path / "missing_features.pkl")
    result = service.predict("https://example.com")
    assert result["verdict"] in {"safe", "phishing"}
    assert 0 <= result["confidence"] <= 1
    assert result["source"] == "heuristic"


def test_service_fallback_marks_obvious_risk(tmp_path: Path):
    service = ModelService(tmp_path / "missing_model.pkl", tmp_path / "missing_features.pkl")
    result = service.predict("http://192.168.0.1/secure/login/verify/account")
    assert result["verdict"] == "phishing"
    assert result["risk_level"] in {"medium", "high"}


def test_service_can_include_features(tmp_path: Path):
    service = ModelService(tmp_path / "missing_model.pkl", tmp_path / "missing_features.pkl")
    result = service.predict("https://paypal-login.example.bad", include_features=True)
    assert "features" in result
    assert result["features"]["brand_impersonation"] == 1
