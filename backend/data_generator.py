"""Deterministic generator for a large synthetic URL base.

The generated URLs are diverse: safe-looking domains, public docs,
phishing-like login/payment flows, IP-hosted URLs, shorteners, punycode and brand
impersonation patterns. The generator is reproducible so project artifacts can
be rebuilt from source without relying on external feeds.
"""
from __future__ import annotations

import argparse
import csv
import json
import random
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATASET_PATH = DATA_DIR / "dataset.csv"
VERDICTS_PATH = DATA_DIR / "verdicts.json"

SAFE_DOMAINS = [
    "example.com", "google.com", "wikipedia.org", "github.com", "gitlab.com",
    "python.org", "docs.python.org", "pypi.org", "numpy.org", "pandas.pydata.org",
    "scikit-learn.org", "flask.palletsprojects.com", "owasp.org", "cloudflare.com",
    "bbc.com", "openstreetmap.org", "mozilla.org", "developer.mozilla.org", "hse.ru",
    "habr.com", "stackoverflow.com", "kaggle.com", "microsoft.com", "npmjs.com",
    "nalog.gov.ru", "gosuslugi.ru", "sberbank.ru", "yandex.ru", "vk.com",
]
SAFE_PATHS = [
    "/", "/docs", "/docs/reference", "/api/reference", "/help", "/support",
    "/security", "/privacy", "/download", "/learn/security", "/profile",
    "/account/settings", "/search", "/news", "/mail/u/0/", "/blog/article",
]
PHISHING_HOSTS = [
    "secure-login-example.bad", "test-phishing.local", "login-verify-account.example.bad",
    "wallet-payment-confirm.example.invalid", "bonus-gift-prize.example.net",
    "secure-update-login-user.example.com.evil.bad", "account-restore-client.example.top",
    "payment-billing-support.example.xyz", "verify-session-token.example.click",
]
BRANDS = [
    "google", "g00gle", "microsoft", "office", "paypal", "paypa1", "amazon",
    "facebook", "icloud", "apple", "sberbank", "sber", "gosuslugi", "hse",
    "vk", "yandex", "steam", "discord", "tinkoff",
]
PHISHING_PATHS = [
    "/login", "/secure/update", "/account/verify", "/confirm", "/signin/payment",
    "/bank/secure/urgent", "/password/reset", "/wallet/verify", "/billing/confirm",
    "/restore", "/unlock/limited", "/client/cabinet/auth", "/session/token",
]
SHORTENERS = ["bit.ly", "tinyurl.com", "rb.gy", "cutt.ly", "t.co", "clck.ru", "vk.cc"]
PUNYCODE = ["xn--gogle-85.example", "xn--paypa1-l2a.example", "xn--sberbnk-8za.example"]
SAFE_QUERIES = ["", "?ref={n}", "?page={p}&lang=ru", "?q=security", "?utm_source=docs"]
PHISHING_QUERIES = [
    "", "?email=user{n}@example.com", "?token=verify-{n}", "?session=locked-{n}",
    "?redirect=https://{brand}.com/login", "?continue=https://{brand}.com/account",
]


def _safe_url(index: int) -> str:
    domain = SAFE_DOMAINS[index % len(SAFE_DOMAINS)]
    if index % 7 == 0:
        domain = "www." + domain
    scheme = "https" if index % 5 != 0 else "http"
    path = SAFE_PATHS[(index * 3) % len(SAFE_PATHS)]
    query_template = SAFE_QUERIES[(index * 5 + 2) % len(SAFE_QUERIES)]
    query = query_template.format(n=index, p=(index % 30) + 1)
    return f"{scheme}://{domain}{path}{query}"


def _phishing_url(index: int) -> str:
    brand = BRANDS[index % len(BRANDS)]
    path = PHISHING_PATHS[(index * 5) % len(PHISHING_PATHS)]
    query = PHISHING_QUERIES[(index * 7) % len(PHISHING_QUERIES)].format(n=index, brand=brand)
    mode = index % 8
    if mode == 0:
        host = f"{brand}-login-verify-account-{index % 97}.{PHISHING_HOSTS[index % len(PHISHING_HOSTS)]}"
        return f"https://{host}{path}{query}"
    if mode == 1:
        ip = f"{10 + index % 210}.{20 + index % 200}.{30 + index % 180}.{40 + index % 160}"
        return f"http://{ip}{path}{query}"
    if mode == 2:
        host = SHORTENERS[index % len(SHORTENERS)]
        return f"https://{host}/{brand}-verify-account-{index}"
    if mode == 3:
        host = PUNYCODE[index % len(PUNYCODE)]
        return f"http://{host}{path}{query}"
    if mode == 4:
        legitimate = f"{brand}.com"
        host = PHISHING_HOSTS[index % len(PHISHING_HOSTS)]
        return f"https://{legitimate}@{host}{path}{query}"
    if mode == 5:
        host = f"secure.{brand}.account.login.verify.{PHISHING_HOSTS[index % len(PHISHING_HOSTS)]}"
        return f"https://{host}{path}{query}"
    if mode == 6:
        host = f"{brand}-security-support-{index % 1000}.example.top"
        return f"https://{host}:8443{path}{query}"
    host = f"{brand}--{index}--auth--client.example.xyz"
    return f"http://{host}{path}{query}"


def generate_dataset(size: int = 100_000, seed: int = 42) -> list[tuple[str, int]]:
    if size < 2:
        raise ValueError("size must be at least 2")
    random.seed(seed)
    half = size // 2
    rows = [(_safe_url(i), 0) for i in range(half)]
    rows.extend((_phishing_url(i), 1) for i in range(size - half))
    random.shuffle(rows)
    return rows


def write_dataset(path: Path = DATASET_PATH, size: int = 100_000) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = generate_dataset(size=size)
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["url", "label"])
        writer.writerows(rows)


def write_verdicts(path: Path = VERDICTS_PATH, size: int = 100_000) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    verdicts: dict[str, dict[str, str]] = {
        "example.com": {"verdict": "safe", "comment": "демонстрационный безопасный домен", "source": "seed"},
        "google.com": {"verdict": "safe", "comment": "пример доверенного домена", "source": "seed"},
        "secure-login-example.bad": {"verdict": "phishing", "comment": "учебный пример опасного домена", "source": "seed"},
        "test-phishing.local": {"verdict": "phishing", "comment": "демонстрационный фишинговый домен", "source": "seed"},
    }
    # Domain-level verdict base: 50k safe + 50k phishing with stable synthetic keys.
    safe_target = size // 2
    phishing_target = size - safe_target
    for i in range(safe_target):
        base = SAFE_DOMAINS[i % len(SAFE_DOMAINS)].replace("/", "")
        key = f"safe-{i:05d}.{base}" if i >= len(SAFE_DOMAINS) else SAFE_DOMAINS[i]
        verdicts[key.lower()] = {
            "verdict": "safe",
            "comment": "учебная запись безопасного домена из расширенной базы",
            "source": "generated-100k-training-base",
        }
    for i in range(phishing_target):
        brand = BRANDS[i % len(BRANDS)]
        host = f"{brand}-login-verify-{i:05d}.phishing-training.example.bad"
        verdicts[host.lower()] = {
            "verdict": "phishing",
            "comment": "учебная запись фишингового домена из расширенной базы",
            "source": "generated-100k-training-base",
        }
    # Trim/pad to exact size without removing seed examples when possible.
    items = list(verdicts.items())[:size]
    path.write_text(json.dumps(dict(items), ensure_ascii=False, indent=2), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic URL dataset and verdict base")
    parser.add_argument("--size", type=int, default=100_000)
    parser.add_argument("--dataset", type=Path, default=DATASET_PATH)
    parser.add_argument("--verdicts", type=Path, default=VERDICTS_PATH)
    args = parser.parse_args()
    write_dataset(args.dataset, args.size)
    write_verdicts(args.verdicts, args.size)
    print(f"generated dataset: {args.dataset} ({args.size} rows)")
    print(f"generated verdicts: {args.verdicts} ({args.size} records)")


if __name__ == "__main__":
    main()
