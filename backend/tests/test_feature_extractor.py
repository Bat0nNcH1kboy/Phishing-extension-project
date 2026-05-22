import pytest

from feature_extractor import (
    FEATURE_NAMES,
    extract_domain,
    extract_features,
    heuristic_score,
    normalize_url,
    registered_domain,
)


def test_normalize_adds_https():
    assert normalize_url("example.com") == "https://example.com"


def test_normalize_lowercases_idna_hostname():
    assert normalize_url("https://Пример.РФ/login").startswith("https://xn--")


def test_extract_domain_without_port():
    assert extract_domain("http://Example.COM:5001/path") == "example.com"


def test_registered_domain_two_part_suffix():
    assert registered_domain("secure.login.example.co.uk") == "example.co.uk"


def test_preserves_at_symbol_as_risk_signal():
    features = extract_features("https://example.com@evil-login.bad/secure/update")
    assert extract_domain("https://example.com@evil-login.bad/secure/update") == "evil-login.bad"
    assert features["qty_at_url"] == 1
    assert features["has_userinfo"] == 1
    assert features["suspicious_words_count"] >= 2


def test_ip_feature():
    features = extract_features("http://192.168.0.1/login")
    assert features["domain_in_ip"] == 1


def test_punycode_feature_from_unicode_domain():
    features = extract_features("https://пример.рф/login")
    assert features["punycode_domain"] == 1


def test_shortener_feature():
    features = extract_features("https://bit.ly/paypal-verify-1")
    assert features["url_shortened"] == 1


def test_sensitive_params_and_redirect_features():
    features = extract_features("https://safe.example/login?token=abc&redirect=https://evil.bad")
    assert features["sensitive_params_count"] >= 1
    assert features["redirect_tokens_count"] >= 1
    assert features["query_contains_url"] == 1


def test_brand_impersonation_feature():
    features = extract_features("https://paypal-login-secure.example.bad/account")
    assert features["brand_impersonation"] == 1
    assert features["brand_keywords_count"] >= 1


def test_trusted_brand_is_not_impersonation():
    features = extract_features("https://paypal.com/security")
    assert features["trusted_registered_domain"] == 1
    assert features["brand_impersonation"] == 0


def test_non_standard_port_feature():
    features = extract_features("https://example.com:8443/login")
    assert features["has_port"] == 1
    assert features["non_standard_port"] == 1


def test_entropy_and_ratio_features_exist():
    features = extract_features("https://x9q2zz-auth-client.example.xyz/login")
    assert features["domain_entropy"] > 0
    assert 0 <= features["domain_digit_ratio"] <= 1
    assert set(FEATURE_NAMES).issubset(features.keys())


def test_heuristic_score_is_higher_for_obvious_phishing():
    safe_score = heuristic_score(extract_features("https://example.com/docs"))
    phish_score = heuristic_score(extract_features("http://192.168.1.8/secure/login/verify/account"))
    assert phish_score > safe_score


@pytest.mark.parametrize("bad_url", [
    "file:///etc/passwd",
    "javascript:alert(1)",
    "https://exa mple.com",
    "https://.",
    "https://example.com:badport/path",
    "https://example.com:70000/path",
    "https://" + "a" * 2050 + ".com",
    "http:///path-only",
])
def test_rejects_invalid_urls(bad_url):
    with pytest.raises(ValueError):
        normalize_url(bad_url)
