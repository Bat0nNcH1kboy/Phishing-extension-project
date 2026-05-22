from __future__ import annotations

from app import create_app
from dns_checker import DnsResult


def test_unknown_url_uses_hybrid_logic_and_returns_texture_contract():
    app = create_app(enable_dns_check=False)
    client = app.test_client()
    response = client.post("/api/check", json={
        "url": "https://paypa1-security-login-check-zzzzzz999.invalidx/account?token=ABCDEF1234567890XYZ"
    })
    assert response.status_code == 200
    data = response.get_json()
    assert data["source"] == "hybrid"
    assert data["checks"]["model_source"] in {"ml_textured", "heuristic"}
    assert "texture_analysis" in data
    assert "summary" in data["texture_analysis"]
    assert isinstance(data["reasons"], list)
    assert data["domain"].endswith(".invalidx")


def test_database_hit_still_returns_dns_and_texture_fields(monkeypatch):
    def fake_resolve(domain: str, timeout_seconds: float):
        return DnsResult(domain=domain, checked=True, resolvable=True, addresses=("93.184.216.34",), elapsed_ms=1)

    monkeypatch.setattr("app.resolve_domain", fake_resolve)
    app = create_app(enable_dns_check=True)
    client = app.test_client()
    response = client.post("/api/check", json={"url": "https://example.com"})
    assert response.status_code == 200
    data = response.get_json()
    assert data["source"] == "database"
    assert data["checks"]["dns_checked"] is True
    assert data["dns"]["resolvable"] is True
    assert "texture_analysis" in data


def test_validation_errors_have_stable_json_contract():
    app = create_app(enable_dns_check=False)
    client = app.test_client()
    response = client.post("/api/check", json={"url": "javascript:alert(1)"})
    assert response.status_code == 400
    data = response.get_json()
    assert data["source"] == "validation"
    assert data["checks"]["dns_checked"] is False
    assert data["risk_level"] == "unknown"
