from app import create_app


def test_health_endpoint():
    client = create_app().test_client()
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


def test_check_requires_url_field():
    client = create_app().test_client()
    response = client.post("/api/check", json={})
    assert response.status_code == 400
    assert response.get_json()["source"] == "validation"


def test_check_database_safe_domain():
    client = create_app().test_client()
    response = client.post("/api/check", json={"url": "https://example.com/path"})
    assert response.status_code == 200
    data = response.get_json()
    assert data["source"] == "database"
    assert data["verdict"] == "safe"


def test_check_database_phishing_domain():
    client = create_app().test_client()
    response = client.post("/api/check", json={"url": "https://secure-login-example.bad/account"})
    assert response.status_code == 200
    data = response.get_json()
    assert data["source"] == "database"
    assert data["verdict"] == "phishing"
    assert data["risk_level"] == "high"


def test_unknown_domain_uses_ml_or_heuristic_without_debug_features():
    client = create_app().test_client()
    response = client.post("/api/check", json={"url": "https://unknown-login-verify.example.net/account"})
    assert response.status_code == 200
    data = response.get_json()
    assert data["source"] in {"ml", "heuristic"}
    assert data["verdict"] in {"safe", "phishing"}
    assert "domain" in data
    assert "features" not in data


def test_invalid_url_scheme():
    client = create_app().test_client()
    response = client.post("/api/check", json={"url": "ftp://example.com"})
    assert response.status_code == 400
    assert response.get_json()["source"] == "validation"


def test_invalid_empty_hostname():
    client = create_app().test_client()
    response = client.post("/api/check", json={"url": "https://."})
    assert response.status_code == 400
    data = response.get_json()
    assert data["source"] == "validation"
    assert data["domain"] == ""
