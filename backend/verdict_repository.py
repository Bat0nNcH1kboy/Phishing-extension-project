"""Repository for trusted and malicious URL/domain verdicts stored in JSON."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from feature_extractor import registered_domain

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
        self._domain_index = {key: value for key, value in self._data.items() if "://" not in key and "/" not in key}

    def _load(self) -> dict[str, dict[str, Any]]:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                raw = {str(item.get("key", item.get("domain", ""))): item for item in raw if isinstance(item, dict)}
            if not isinstance(raw, dict):
                raise ValueError("verdicts.json root must be an object or list")
            result: dict[str, dict[str, Any]] = {}
            for key, value in raw.items():
                if not isinstance(value, dict):
                    continue
                verdict = str(value.get("verdict", "")).lower()
                if verdict not in ALLOWED_VERDICTS:
                    continue
                clean_key = str(key).strip().lower()
                if not clean_key:
                    continue
                result[clean_key] = {
                    "verdict": verdict,
                    "comment": str(value.get("comment", "совпадение с внутренней базой")),
                    "source": str(value.get("source", "local-training-base")),
                }
            return result or dict(DEFAULT_VERDICTS)
        except (json.JSONDecodeError, OSError, ValueError):
            return dict(DEFAULT_VERDICTS)

    def find(self, normalized_url: str, domain: str) -> dict[str, Any] | None:
        normalized_key = (normalized_url or "").lower()
        domain_key = (domain or "").lower()
        if normalized_key in self._data:
            return self._data[normalized_key]
        if domain_key in self._data:
            return self._data[domain_key]
        reg = registered_domain(domain_key) if domain_key else ""
        return self._domain_index.get(reg) if reg and reg != domain_key else None

    def all(self) -> dict[str, dict[str, Any]]:
        return dict(self._data)

    def count(self) -> int:
        return len(self._data)

    def stats(self) -> dict[str, int]:
        safe = sum(1 for item in self._data.values() if item.get("verdict") == "safe")
        phishing = sum(1 for item in self._data.values() if item.get("verdict") == "phishing")
        return {"total": len(self._data), "safe": safe, "phishing": phishing}

    def sample(self, limit: int = 25, offset: int = 0) -> dict[str, dict[str, Any]]:
        limit = max(0, min(int(limit), 250))
        offset = max(0, int(offset))
        items = list(self._data.items())[offset:offset + limit]
        return dict(items)
