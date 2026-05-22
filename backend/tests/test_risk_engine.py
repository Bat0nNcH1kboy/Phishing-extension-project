from dns_checker import DnsResult
from risk_engine import RiskEngine


class FakeModelService:
    model = None

    def __init__(self, probability):
        self.probability = probability

    def predict(self, url, include_features=False):
        return {
            "verdict": "phishing" if self.probability >= 0.5 else "safe",
            "source": "fake",
            "confidence": max(self.probability, 1 - self.probability),
            "phishing_probability": self.probability,
            "risk_level": "medium",
        }


def test_risk_engine_keeps_low_risk_safe():
    engine = RiskEngine(FakeModelService(0.05))
    result = engine.analyze("https://example.com/docs")
    assert result["verdict"] == "safe"
    assert result["risk_level"] == "low"


def test_risk_engine_raises_risk_for_brand_impersonation():
    engine = RiskEngine(FakeModelService(0.10))
    result = engine.analyze("https://paypal-login-secure.example.bad/account")
    assert result["verdict"] == "phishing"
    assert result["phishing_probability"] >= 0.6


def test_risk_engine_uses_dns_negative_signal():
    engine = RiskEngine(FakeModelService(0.10))
    dns = DnsResult("unknown-login.example", True, False, tuple(), 5, "not found")
    result = engine.analyze("https://unknown-login.example/account", dns_result=dns)
    assert result["checks"]["dns_resolvable"] is False
    assert result["risk_level"] in {"medium", "high"}


def test_risk_engine_can_include_features():
    engine = RiskEngine(FakeModelService(0.10))
    result = engine.analyze("https://example.com", include_features=True)
    assert "features" in result
