from app import create_app


def _client():
    return create_app(enable_dns_check=False).test_client()


def test_health_endpoint():
    response = _client().get("/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "ok"
    assert data["verdict_base_size"] >= 100000


def test_check_requires_url_field():
    response = _client().post("/api/check", json={})
    assert response.status_code == 400
    assert response.get_json()["source"] == "validation"


def test_check_database_safe_domain():
    response = _client().post("/api/check", json={"url": "https://example.com/path"})
    assert response.status_code == 200
    data = response.get_json()
    assert data["source"] == "database"
    assert data["verdict"] == "safe"


def test_check_database_phishing_domain():
    response = _client().post("/api/check", json={"url": "https://secure-login-example.bad/account"})
    assert response.status_code == 200
    data = response.get_json()
    assert data["source"] == "database"
    assert data["verdict"] == "phishing"
    assert data["risk_level"] == "high"


def test_unknown_domain_uses_hybrid_without_debug_features():
    response = _client().post("/api/check", json={"url": "https://unknown-login-verify.example.net/account"})
    assert response.status_code == 200
    data = response.get_json()
    assert data["source"] == "hybrid"
    assert data["verdict"] in {"safe", "phishing"}
    assert "domain" in data
    assert "features" not in data
    assert "checks" in data


def test_api_force_dns_adds_dns_section(monkeypatch):
    class FakeDns:
        checked = True
        resolvable = False
        def to_dict(self, include_addresses=False):
            return {"domain": "unknown.example", "checked": True, "resolvable": False, "addresses": [], "elapsed_ms": 1, "error": "fake"}

    monkeypatch.setattr("app.resolve_domain", lambda domain, timeout: FakeDns())
    response = _client().post("/api/check", json={"url": "https://unknown-example-training.net/login", "dns_check": True})
    data = response.get_json()
    assert response.status_code == 200
    assert data["dns"]["checked"] is True
    assert data["checks"]["dns_resolvable"] is False


def test_invalid_url_scheme():
    response = _client().post("/api/check", json={"url": "ftp://example.com"})
    assert response.status_code == 400
    assert response.get_json()["source"] == "validation"


def test_invalid_empty_hostname():
    response = _client().post("/api/check", json={"url": "https://."})
    assert response.status_code == 400
    data = response.get_json()
    assert data["source"] == "validation"
    assert data["domain"] == ""


def test_legacy_predict_endpoint():
    response = _client().post("/predict", json={"url": "https://example.com"})
    assert response.status_code == 200
    assert response.get_json()["verdict"] == "safe"


def test_verdicts_endpoint_is_paginated():
    response = _client().get("/api/verdicts?limit=5")
    assert response.status_code == 200
    data = response.get_json()
    assert data["stats"]["total"] >= 100000
    assert len(data["items"]) == 5
