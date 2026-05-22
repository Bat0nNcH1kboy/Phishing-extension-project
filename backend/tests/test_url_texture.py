from url_texture import extract_url_textures, summarize_texture_features
from feature_extractor import extract_features


def test_url_texture_features_detect_login_rhythm():
    features = extract_url_textures(
        "https://paypa1-login-secure.example.bad/account/verify?token=ABCDEF1234567890XYZ"
    )
    assert features["texture_token_count"] >= 5
    assert features["texture_login_marker_count"] >= 3
    assert features["texture_brand_typo_count"] >= 1
    assert features["texture_charclass_transitions"] > 0


def test_feature_extractor_merges_texture_features():
    features = extract_features("https://g00gle-secure-login.example.bad/auth")
    assert features["texture_brand_typo_count"] >= 1
    assert features["texture_login_marker_count"] >= 2


def test_texture_summary_is_compact():
    features = extract_features("https://example.com/docs")
    summary = summarize_texture_features(features)
    assert summary["enabled"] is True
    assert set(summary) == {
        "enabled",
        "summary",
        "token_count",
        "charclass_transitions",
        "digit_letter_transitions",
        "login_markers",
        "brand_typo_markers",
        "base64_like_score",
    }
    assert isinstance(summary["summary"], str) and summary["summary"]
