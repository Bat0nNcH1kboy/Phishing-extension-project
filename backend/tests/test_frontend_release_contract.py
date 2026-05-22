from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXT = ROOT / "extension"


def test_popup_has_manual_url_input():
    html = (EXT / "popup.html").read_text(encoding="utf-8").lower()
    js = (EXT / "popup.js").read_text(encoding="utf-8").lower()
    assert "manualurl" in html
    assert "checkmanualbtn" in html
    assert "checkmanualurl" in js
    assert "проверить введённый url" in html or "проверить введенный url" in html


def test_popup_renders_dns_texture_and_model_details():
    js = (EXT / "popup.js").read_text(encoding="utf-8").lower()
    for token in ["dns", "texture_analysis", "ml_probability", "heuristic_score", "phishing_probability"]:
        assert token in js


def test_manifest_keeps_permissions_minimal():
    manifest = (EXT / "manifest.json").read_text(encoding="utf-8")
    assert '"activeTab"' in manifest
    assert '"tabs"' not in manifest
    assert '"<all_urls>"' not in manifest
