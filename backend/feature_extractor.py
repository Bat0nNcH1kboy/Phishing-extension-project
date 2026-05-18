"""URL normalization and lexical feature extraction for phishing detection.

The module intentionally uses deterministic lexical features only. It does not
read page content, cookies, forms or browsing history, which keeps the MVP
privacy-preserving and easy to demonstrate in a diploma project.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import unquote, urlparse, urlunparse

SUPPORTED_SCHEMES = {"http", "https"}
MAX_URL_LENGTH = 2048
SHORTENERS = {
    "bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "s.id", "shorturl.at", "rb.gy", "lnkd.in"
}
SUSPICIOUS_WORDS = {
    "login", "verify", "account", "update", "secure", "bank", "wallet", "password",
    "signin", "confirm", "payment", "billing", "free", "bonus", "gift", "prize",
    "support", "unlock", "limited", "urgent", "restore"
}
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_SCHEME_LIKE_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
_EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
_HOSTNAME_RE = re.compile(r"^[a-z0-9.-]+$")


def _to_ascii_hostname(hostname: str) -> str:
    """Normalize internationalized hostnames to IDNA ASCII where possible."""
    hostname = hostname.strip().strip(".").lower()
    try:
        return hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("URL hostname contains invalid IDNA characters") from exc


def _validate_hostname(hostname: str) -> None:
    if not hostname:
        raise ValueError("URL hostname is missing")
    if len(hostname) > 253:
        raise ValueError("URL hostname is too long")
    try:
        ipaddress.ip_address(hostname)
        return
    except ValueError:
        pass
    if not _HOSTNAME_RE.fullmatch(hostname):
        raise ValueError("URL hostname contains invalid characters")
    labels = hostname.split(".")
    if any(not label for label in labels):
        raise ValueError("URL hostname contains an empty label")
    if any(len(label) > 63 for label in labels):
        raise ValueError("URL hostname label is too long")
    if any(label.startswith("-") or label.endswith("-") for label in labels):
        raise ValueError("URL hostname label cannot start or end with hyphen")


def normalize_url(url: str) -> str:
    """Return a normalized http/https URL or raise ValueError for unsafe input."""
    value = (url or "").strip()
    if not value:
        raise ValueError("URL is empty")
    if len(value) > MAX_URL_LENGTH:
        raise ValueError("URL is too long")
    if _CONTROL_CHARS.search(value) or any(ch.isspace() for ch in value):
        raise ValueError("URL contains spaces or control characters")
    if _SCHEME_LIKE_RE.match(value) and not _SCHEME_RE.match(value):
        raise ValueError("Unsupported URL scheme")
    if not _SCHEME_RE.match(value):
        value = "https://" + value

    parsed = urlparse(value)
    scheme = parsed.scheme.lower()
    if scheme not in SUPPORTED_SCHEMES:
        raise ValueError("Unsupported URL scheme")
    if not parsed.netloc:
        raise ValueError("URL domain is missing")
    if not parsed.hostname:
        raise ValueError("URL hostname is missing")

    hostname = _to_ascii_hostname(parsed.hostname)
    _validate_hostname(hostname)

    # Preserve userinfo to keep the '@' risk signal visible in lexical features,
    # but normalize the actual host part and validate the port.
    userinfo = ""
    if "@" in parsed.netloc:
        userinfo = parsed.netloc.rsplit("@", 1)[0] + "@"
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid URL port") from exc
    netloc = f"{userinfo}{hostname}"
    if port is not None:
        netloc += f":{port}"

    return urlunparse((scheme, netloc, parsed.path or "", parsed.params or "", parsed.query or "", parsed.fragment or ""))


def extract_domain(url: str) -> str:
    parsed = urlparse(normalize_url(url))
    hostname = parsed.hostname or ""
    return _to_ascii_hostname(hostname)


def _is_ip_address(hostname: str) -> int:
    try:
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0


def _registered_domain(hostname: str) -> str:
    parts = [p for p in hostname.split(".") if p]
    if len(parts) <= 2:
        return hostname
    # MVP approximation: for production use the Public Suffix List (for example, tldextract).
    return ".".join(parts[-2:])


def _count_digits(value: str) -> int:
    return sum(ch.isdigit() for ch in value)


def extract_features(url: str) -> dict[str, int | float]:
    """Extract deterministic URL lexical features used by the classifier."""
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    hostname = extract_domain(normalized)
    decoded = unquote(normalized).lower()
    path = parsed.path or ""
    query = parsed.query or ""
    registered = _registered_domain(hostname)
    hostname_parts = [p for p in hostname.split(".") if p]

    return {
        "length_url": len(normalized),
        "domain_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "qty_dot_url": normalized.count("."),
        "qty_dot_domain": hostname.count("."),
        "qty_hyphen_url": normalized.count("-"),
        "qty_hyphen_domain": hostname.count("-"),
        "qty_slash_url": normalized.count("/"),
        "qty_questionmark_url": normalized.count("?"),
        "qty_equal_url": normalized.count("="),
        "qty_at_url": normalized.count("@"),
        "qty_and_url": normalized.count("&"),
        "qty_percent_url": normalized.count("%"),
        "qty_underline_url": normalized.count("_"),
        "qty_digits_url": _count_digits(normalized),
        "qty_digits_domain": _count_digits(hostname),
        "qty_subdomains": max(0, len(hostname_parts) - 2),
        "domain_in_ip": _is_ip_address(hostname),
        "has_https": int(parsed.scheme == "https"),
        "url_shortened": int(registered in SHORTENERS),
        "punycode_domain": int("xn--" in hostname),
        "email_in_url": int(bool(_EMAIL_RE.search(decoded))),
        "suspicious_words_count": sum(1 for word in SUSPICIOUS_WORDS if word in decoded),
    }


def explain(features: dict[str, int | float]) -> list[str]:
    """Produce human-readable risk factors from extracted features."""
    reasons: list[str] = []
    if features.get("length_url", 0) > 90:
        reasons.append("URL имеет повышенную длину")
    if features.get("qty_at_url", 0) > 0:
        reasons.append("в адресе присутствует символ @")
    if features.get("domain_in_ip", 0):
        reasons.append("вместо домена используется IP-адрес")
    if features.get("url_shortened", 0):
        reasons.append("используется сокращатель ссылок")
    if features.get("qty_hyphen_domain", 0) > 1:
        reasons.append("в домене много дефисов")
    if features.get("email_in_url", 0):
        reasons.append("URL содержит фрагмент, похожий на email")
    if features.get("punycode_domain", 0):
        reasons.append("домен содержит punycode-представление")
    if features.get("suspicious_words_count", 0) >= 2:
        reasons.append("найдены слова, типичные для фишинговых сценариев")
    return reasons


FEATURE_NAMES = list(extract_features("https://example.com/path?x=1").keys())
