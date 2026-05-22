from pathlib import Path

import pandas as pd

from model_train import build_frame


def test_build_frame_from_dataset(tmp_path: Path):
    dataset = tmp_path / "dataset.csv"
    pd.DataFrame({
        "url": [
            "https://example.com",
            "https://github.com/docs",
            "http://192.168.0.1/login/verify",
            "https://paypal-login.example.bad/account",
        ],
        "label": [0, 0, 1, 1],
    }).to_csv(dataset, index=False)
    x, y = build_frame(dataset)
    assert len(x) == 4
    assert list(y) == [0, 0, 1, 1]
    assert "length_url" in x.columns
    assert "brand_impersonation" in x.columns
    assert "texture_login_marker_count" in x.columns


def test_build_frame_rejects_bad_columns(tmp_path: Path):
    dataset = tmp_path / "bad.csv"
    pd.DataFrame({"address": ["https://example.com"], "label": [0]}).to_csv(dataset, index=False)
    try:
        build_frame(dataset)
    except ValueError as exc:
        assert "url and label" in str(exc)
    else:
        raise AssertionError("ValueError expected")
