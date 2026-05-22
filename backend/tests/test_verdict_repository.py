import json
from pathlib import Path

from verdict_repository import VerdictRepository


def test_repository_loads_and_finds_domain(tmp_path: Path):
    path = tmp_path / "verdicts.json"
    path.write_text(json.dumps({"evil.test": {"verdict": "phishing", "comment": "bad"}}), encoding="utf-8")
    repo = VerdictRepository(path)
    assert repo.find("https://evil.test/login", "evil.test")["verdict"] == "phishing"


def test_repository_finds_registered_domain(tmp_path: Path):
    path = tmp_path / "verdicts.json"
    path.write_text(json.dumps({"example.co.uk": {"verdict": "safe", "comment": "ok"}}), encoding="utf-8")
    repo = VerdictRepository(path)
    assert repo.find("https://secure.example.co.uk/login", "secure.example.co.uk")["verdict"] == "safe"


def test_repository_stats_and_sample(tmp_path: Path):
    path = tmp_path / "verdicts.json"
    path.write_text(json.dumps({
        "a.test": {"verdict": "safe"},
        "b.test": {"verdict": "phishing"},
        "c.test": {"verdict": "safe"},
    }), encoding="utf-8")
    repo = VerdictRepository(path)
    assert repo.stats() == {"total": 3, "safe": 2, "phishing": 1}
    assert len(repo.sample(limit=2)) == 2


def test_repository_falls_back_on_invalid_json(tmp_path: Path):
    path = tmp_path / "bad.json"
    path.write_text("not-json", encoding="utf-8")
    repo = VerdictRepository(path)
    assert repo.count() >= 4
