from pathlib import Path

import pandas as pd

from model_train import build_frame


def test_build_frame_from_dataset(tmp_path: Path):
    dataset = tmp_path / "dataset.csv"
    pd.DataFrame({
        "url": ["https://example.com", "http://192.168.0.1/login/verify"],
        "label": [0, 1],
    }).to_csv(dataset, index=False)
    x, y = build_frame(dataset)
    assert len(x) == 2
    assert list(y) == [0, 1]
    assert "length_url" in x.columns
