"""Repository for trusted and malicious URL/domain verdicts stored in JSON."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

DEFAULT_VERDICTS = {
    "example.com": {"verdict": "safe", "comment": "демонстрационный безопасный домен"},
    "google.com": {"verdict": "safe", "comment": "пример доверенного домена"},
    "test-phishing.local": {"verdict": "phishing", "comment": "демонстрационный фишинговый домен"},
    "secure-login-example.bad": {"verdict": "phishing", "comment": "учебный пример опасного домена"},
}
ALLOWED_VERDICTS = {"safe", "phishing"}


class VerdictRepository:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text(json.dumps(DEFAULT_VERDICTS, ensure_ascii=False, indent=2), encoding="utf-8")
        self._data = self._load()

    def _load(self) -> dict[str, dict[str, Any]]:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("verdicts.json root must be an object")
            result: dict[str, dict[str, Any]] = {}
            for key, value in raw.items():
                if not isinstance(value, dict):
                    continue
                verdict = str(value.get("verdict", "")).lower()
                if verdict not in ALLOWED_VERDICTS:
                    continue
                result[str(key).lower()] = {
                    "verdict": verdict,
                    "comment": str(value.get("comment", "совпадение с внутренней базой")),
                }
            return result or dict(DEFAULT_VERDICTS)
        except (json.JSONDecodeError, OSError, ValueError):
            return dict(DEFAULT_VERDICTS)

    def find(self, normalized_url: str, domain: str) -> dict[str, Any] | None:
        return self._data.get(normalized_url.lower()) or self._data.get(domain.lower())

    def all(self) -> dict[str, dict[str, Any]]:
        return dict(self._data)
