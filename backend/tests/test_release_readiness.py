from __future__ import annotations

import csv
import json
import re
from pathlib import Path

from feature_extractor import FEATURE_NAMES

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"


def test_dataset_has_100k_balanced_records():
    dataset = BACKEND / "data" / "dataset.csv"
    assert dataset.exists()
    counts = {0: 0, 1: 0}
    total = 0
    with dataset.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        assert {"url", "label"}.issubset(reader.fieldnames or [])
        for row in reader:
            total += 1
            counts[int(row["label"])] += 1
    assert total == 100_000
    assert counts == {0: 50_000, 1: 50_000}


def test_verdict_base_has_100k_records_and_two_classes():
    verdicts = json.loads((BACKEND / "data" / "verdicts.json").read_text(encoding="utf-8"))
    assert len(verdicts) == 100_000
    class_counts = {"safe": 0, "phishing": 0}
    for item in verdicts.values():
        class_counts[item["verdict"]] += 1
    assert class_counts == {"safe": 50_000, "phishing": 50_000}


def test_feature_set_contains_texture_layer():
    texture_names = [name for name in FEATURE_NAMES if name.startswith("texture_")]
    assert len(FEATURE_NAMES) >= 67
    assert len(texture_names) >= 21
    assert "brand_impersonation" in FEATURE_NAMES
    assert "sensitive_params_count" in FEATURE_NAMES
    assert "non_standard_port" in FEATURE_NAMES


def test_release_contains_ci_scripts_and_operator_documentation():
    required_files = [
        ROOT / ".github" / "workflows" / "ci.yml",
        ROOT / "scripts" / "check_project.py",
        ROOT / "scripts" / "release_audit.py",
        ROOT / "start_backend_windows.bat",
        ROOT / "check_project_windows.bat",
        ROOT / "docs" / "URL_TEXTURES.md",
        ROOT / "docs" / "DEMO_CHECKLIST.md",
        ROOT / "README.md",
    ]
    for path in required_files:
        assert path.exists(), f"missing {path.relative_to(ROOT)}"


def test_readme_describes_release_capabilities():
    readme = (ROOT / "README.md").read_text(encoding="utf-8").lower()
    for phrase in [
        "100 000",
        "dns-проверка",
        "ci workflow",
        "texturedurlclassifier",
        "url-текстур",
        "ручной ввод url",
        "scripts/check_project.py",
        "загрузить распакованное расширение",
    ]:
        assert phrase in readme


def test_ci_runs_python_tests_and_javascript_syntax_check():
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8").lower()
    assert "setup-python" in ci
    assert "setup-node" in ci
    assert "pytest" in ci
    assert "compileall" in (ROOT / "scripts" / "check_project.py").read_text(encoding="utf-8").lower()
    assert re.search(r"node.*--check", (ROOT / "scripts" / "check_project.py").read_text(encoding="utf-8").lower(), re.S)
