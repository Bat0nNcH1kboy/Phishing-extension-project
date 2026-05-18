import pytest

from feature_extractor import extract_domain, extract_features, normalize_url


def test_normalize_adds_https():
    assert normalize_url("example.com") == "https://example.com"


def test_extract_domain_without_port():
    assert extract_domain("http://Example.COM:5001/path") == "example.com"


def test_preserves_at_symbol_as_risk_signal():
    features = extract_features("https://example.com@evil-login.bad/secure/update")
    assert extract_domain("https://example.com@evil-login.bad/secure/update") == "evil-login.bad"
    assert features["qty_at_url"] == 1
    assert features["suspicious_words_count"] >= 2


def test_ip_feature():
    features = extract_features("http://192.168.0.1/login")
    assert features["domain_in_ip"] == 1


def test_punycode_feature_from_unicode_domain():
    features = extract_features("https://пример.рф/login")
    assert features["punycode_domain"] == 1


@pytest.mark.parametrize("bad_url", [
    "file:///etc/passwd",
    "javascript:alert(1)",
    "https://exa mple.com",
    "https://.",
    "https://example.com:badport/path",
    "https://" + "a" * 2050 + ".com",
])
def test_rejects_invalid_urls(bad_url):
    with pytest.raises(ValueError):
        normalize_url(bad_url)
