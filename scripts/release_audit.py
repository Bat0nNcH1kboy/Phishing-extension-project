from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"


def fail(message: str) -> None:
    raise AssertionError(message)


def count_dataset() -> tuple[int, dict[int, int]]:
    path = BACKEND / "data" / "dataset.csv"
    counts = {0: 0, 1: 0}
    total = 0
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if not {"url", "label"}.issubset(reader.fieldnames or []):
            fail("dataset.csv must contain url,label columns")
        for row in reader:
            total += 1
            counts[int(row["label"])] += 1
    return total, counts


def main() -> int:
    checks: list[tuple[str, bool, str]] = []

    dataset_total, dataset_counts = count_dataset()
    checks.append(("dataset_100k", dataset_total == 100_000, f"{dataset_total} rows, {dataset_counts}"))

    verdicts = json.loads((BACKEND / "data" / "verdicts.json").read_text(encoding="utf-8"))
    verdict_counts = {"safe": 0, "phishing": 0}
    for item in verdicts.values():
        verdict_counts[item.get("verdict", "")] = verdict_counts.get(item.get("verdict", ""), 0) + 1
    checks.append(("verdict_base_100k", len(verdicts) == 100_000, f"{len(verdicts)} records, {verdict_counts}"))

    from feature_extractor import FEATURE_NAMES
    texture_count = len([name for name in FEATURE_NAMES if name.startswith("texture_")])
    checks.append(("texture_features", len(FEATURE_NAMES) >= 67 and texture_count >= 21, f"{len(FEATURE_NAMES)} features, {texture_count} texture"))

    config = (BACKEND / "config.py").read_text(encoding="utf-8")
    checks.append(("dns_default_enabled", 'PHISHING_DNS_CHECK_ENABLED", "1"' in config, "DNS is enabled by default"))

    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    check_project = (ROOT / "scripts" / "check_project.py").read_text(encoding="utf-8")
    checks.append(("ci_checks", all(word in ci + check_project for word in ["pytest", "compileall", "node", "--check"]), "pytest + compileall + node --check"))

    readme = (ROOT / "README.md").read_text(encoding="utf-8").lower()
    checks.append(("readme_capabilities", all(word in readme for word in ["100 000", "dns-проверка", "url-текстур", "ручной ввод url"]), "README covers key capabilities"))

    popup_html = (ROOT / "extension" / "popup.html").read_text(encoding="utf-8").lower()
    popup_js = (ROOT / "extension" / "popup.js").read_text(encoding="utf-8").lower()
    checks.append(("manual_url_input", "manualurl" in popup_html and "checkmanualurl" in popup_js, "manual URL input exists"))
    checks.append(("dns_texture_ui", all(token in popup_js for token in ["dns", "texture_analysis", "ml_probability", "heuristic_score"]), "popup renders DNS/texture details"))

    test_files = list((BACKEND / "tests").glob("test_*.py"))
    test_count = sum(len(re.findall(r"^def test_", path.read_text(encoding="utf-8"), flags=re.M)) for path in test_files)
    checks.append(("expanded_tests", len(test_files) >= 10 and test_count >= 55, f"{len(test_files)} files, {test_count} explicit test functions"))

    failed = False
    print("Release audit checklist:")
    for name, ok, detail in checks:
        status = "OK" if ok else "FAIL"
        print(f"- {status}: {name} — {detail}")
        failed = failed or not ok
    if failed:
        return 1
    print("Release audit passed.")
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(BACKEND))
    raise SystemExit(main())
