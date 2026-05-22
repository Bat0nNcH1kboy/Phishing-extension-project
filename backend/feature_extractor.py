"""URL normalization and feature extraction for phishing detection.

The module extracts deterministic lexical/structural URL features and textual
URL texture features. It does not read page content, cookies, forms or browser
history, so the browser extension can work with minimum permissions
and without collecting private page data.
"""
from __future__ import annotations

import ipaddress
import math
import re
from urllib.parse import parse_qsl, unquote, urlparse, urlunparse

from url_texture import extract_url_textures

SUPPORTED_SCHEMES = {"http", "https"}
MAX_URL_LENGTH = 2048
SHORTENERS = {
    "bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "s.id", "shorturl.at", "rb.gy", "lnkd.in",
    "clck.ru", "vk.cc", "bitly.com", "tiny.cc", "adf.ly", "soo.gd",
}
SUSPICIOUS_WORDS = {
    "login", "verify", "verification", "account", "update", "secure", "security",
    "bank", "wallet", "password", "passwd", "signin", "sign-in", "confirm",
    "payment", "billing", "free", "bonus", "gift", "prize", "support", "unlock",
    "limited", "urgent", "restore", "recovery", "invoice", "webscr", "auth",
    "oauth", "session", "token", "kyc", "client", "cabinet", "suspend", "blocked",
}
BRAND_KEYWORDS = {
    "google", "g00gle", "gogle", "gmail", "microsoft", "office", "outlook",
    "apple", "icloud", "paypal", "paypa1", "amazon", "faceboook", "facebook",
    "instagram", "whatsapp", "telegram", "sberbank", "sber", "gosuslugi", "hse",
    "vk", "yandex", "tinkoff", "alfabank", "raiffeisen", "steam", "discord",
}
TRUSTED_REGISTERED_DOMAINS = {
    "google.com", "gmail.com", "microsoft.com", "office.com", "outlook.com",
    "apple.com", "icloud.com", "paypal.com", "amazon.com", "facebook.com",
    "instagram.com", "whatsapp.com", "telegram.org", "sberbank.ru", "sber.ru",
    "gosuslugi.ru", "hse.ru", "vk.com", "yandex.ru", "tinkoff.ru", "alfabank.ru",
    "github.com", "gitlab.com", "python.org", "wikipedia.org", "cloudflare.com",
}
SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "work", "support", "tk", "ml", "ga", "cf",
    "gq", "pw", "country", "stream", "download", "loan", "men", "review", "rest",
    "bad", "invalid", "local",
}
SENSITIVE_PARAM_NAMES = {
    "token", "session", "sid", "auth", "password", "passwd", "pwd", "email", "user",
    "login", "redirect", "redirect_uri", "url", "continue", "next", "return", "callback",
}
REDIRECT_TOKENS = {"redirect", "redirect_uri", "continue", "next", "return", "url", "callback"}
COMMON_SAFE_EXTENSIONS = {"html", "htm", "php", "asp", "aspx", "jsp"}
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_SCHEME_LIKE_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
_EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
_HOSTNAME_RE = re.compile(r"^[a-z0-9.-]+$")
_REPEATED_CHARS_RE = re.compile(r"(.)\1{2,}")


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

    userinfo = ""
    if "@" in parsed.netloc:
        userinfo = parsed.netloc.rsplit("@", 1)[0] + "@"
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid URL port") from exc
    if port is not None and not (1 <= int(port) <= 65535):
        raise ValueError("Invalid URL port")
    netloc = f"{userinfo}{hostname}"
    if port is not None:
        netloc += f":{port}"

    return urlunparse((scheme, netloc, parsed.path or "", parsed.params or "", parsed.query or "", parsed.fragment or ""))


def extract_domain(url: str) -> str:
    parsed = urlparse(normalize_url(url))
    hostname = parsed.hostname or ""
    return _to_ascii_hostname(hostname)


def is_ip_address(hostname: str) -> int:
    try:
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0


def registered_domain(hostname: str) -> str:
    parts = [p for p in hostname.split(".") if p]
    if len(parts) <= 2:
        return hostname
    two_part_public_suffixes = {
        "co.uk", "com.au", "co.jp", "com.br", "com.tr", "co.in", "com.cn",
        "net.cn", "org.cn", "ac.uk", "edu.au", "gov.ru",
    }
    suffix = ".".join(parts[-2:])
    if suffix in two_part_public_suffixes and len(parts) >= 3:
        return ".".join(parts[-3:])
    return suffix


def _count_digits(value: str) -> int:
    return sum(ch.isdigit() for ch in value)


def _count_letters(value: str) -> int:
    return sum(ch.isalpha() for ch in value)


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    total = len(value)
    counts = {ch: value.count(ch) for ch in set(value)}
    return round(-sum((count / total) * math.log2(count / total) for count in counts.values()), 4)


def _tld(hostname: str) -> str:
    if is_ip_address(hostname):
        return ""
    parts = hostname.rsplit(".", 1)
    return parts[1] if len(parts) == 2 else ""


def _last_path_extension(path: str) -> str:
    name = (path.rsplit("/", 1)[-1] or "").lower()
    if "." not in name:
        return ""
    ext = name.rsplit(".", 1)[-1]
    return ext if ext.isalnum() and len(ext) <= 8 else ""


def extract_features(url: str) -> dict[str, int | float]:
    """Extract deterministic URL lexical features used by the classifier."""
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    hostname = extract_domain(normalized)
    decoded = unquote(normalized).lower()
    decoded_path = unquote(parsed.path or "").lower()
    decoded_query = unquote(parsed.query or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    query_pairs = parse_qsl(query, keep_blank_values=True)
    reg_domain = registered_domain(hostname)
    hostname_parts = [p for p in hostname.split(".") if p]
    domain_without_tld = hostname_parts[-2] if len(hostname_parts) >= 2 else hostname
    full_hostname_text = hostname.replace(".", "-")
    tld = _tld(hostname)
    userinfo_present = int("@" in parsed.netloc)
    port = parsed.port
    params_lower = {name.lower() for name, _ in query_pairs}
    query_values = [value.lower() for _, value in query_pairs]
    brand_hits = sum(1 for brand in BRAND_KEYWORDS if brand in full_hostname_text or brand in decoded_path)
    trusted_exact = int(reg_domain in TRUSTED_REGISTERED_DOMAINS)
    brand_impersonation = int(brand_hits > 0 and not trusted_exact)
    repeated = int(bool(_REPEATED_CHARS_RE.search(hostname)))
    extension = _last_path_extension(path)
    encoded_chars = normalized.count("%")
    texture_features = extract_url_textures(normalized)

    features = {
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
        "qty_percent_url": encoded_chars,
        "qty_underline_url": normalized.count("_"),
        "qty_digits_url": _count_digits(normalized),
        "qty_digits_domain": _count_digits(hostname),
        "qty_letters_url": _count_letters(normalized),
        "qty_params": len(query_pairs),
        "qty_fragments": int(bool(parsed.fragment)),
        "qty_subdomains": max(0, len(hostname_parts) - 2),
        "path_depth": len([p for p in path.split("/") if p]),
        "domain_in_ip": is_ip_address(hostname),
        "has_https": int(parsed.scheme == "https"),
        "has_port": int(port is not None),
        "non_standard_port": int(port is not None and port not in {80, 443}),
        "has_userinfo": userinfo_present,
        "url_shortened": int(reg_domain in SHORTENERS),
        "punycode_domain": int("xn--" in hostname),
        "email_in_url": int(bool(_EMAIL_RE.search(decoded))),
        "suspicious_words_count": sum(1 for word in SUSPICIOUS_WORDS if word in decoded),
        "sensitive_params_count": sum(1 for name in params_lower if name in SENSITIVE_PARAM_NAMES),
        "redirect_tokens_count": sum(
            1 for name, value in query_pairs
            if name.lower() in REDIRECT_TOKENS or any(token in value.lower() for token in REDIRECT_TOKENS)
        ),
        "brand_keywords_count": brand_hits,
        "brand_impersonation": brand_impersonation,
        "trusted_registered_domain": trusted_exact,
        "suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "domain_entropy": _entropy(domain_without_tld),
        "url_entropy": _entropy(decoded),
        "path_entropy": _entropy(decoded_path),
        "domain_digit_ratio": round(_count_digits(domain_without_tld) / max(len(domain_without_tld), 1), 4),
        "domain_hyphen_ratio": round(domain_without_tld.count("-") / max(len(domain_without_tld), 1), 4),
        "repeated_chars_domain": repeated,
        "has_encoded_chars": int(encoded_chars > 0),
        "has_common_web_extension": int(extension in COMMON_SAFE_EXTENSIONS),
        "query_contains_url": int(any("http" in value or "://" in value for value in query_values)),
    }
    features.update(texture_features)
    return features


def heuristic_score(features: dict[str, int | float], dns_resolvable: bool | None = None) -> float:
    """Transparent risk score used as an explanation layer above ML."""
    score = 0.0
    score += min(float(features["length_url"]) / 220.0, 0.18)
    score += 0.20 if features["qty_at_url"] else 0.0
    score += 0.18 if features["domain_in_ip"] else 0.0
    score += 0.12 if features["url_shortened"] else 0.0
    score += 0.12 if features["punycode_domain"] else 0.0
    score += min(float(features["suspicious_words_count"]) * 0.055, 0.22)
    score += min(float(features["sensitive_params_count"]) * 0.04, 0.12)
    score += min(float(features["redirect_tokens_count"]) * 0.05, 0.15)
    score += min(float(features["qty_subdomains"]) * 0.04, 0.16)
    score += 0.16 if features["brand_impersonation"] else 0.0
    score += 0.08 if features["suspicious_tld"] else 0.0
    score += 0.06 if features["non_standard_port"] else 0.0
    score += 0.05 if features["has_encoded_chars"] else 0.0
    score += 0.06 if float(features["domain_entropy"]) >= 3.7 else 0.0
    score += 0.05 if float(features.get("texture_base64_like_score", 0.0)) >= 0.34 else 0.0
    score += min(float(features.get("texture_login_marker_count", 0)) * 0.035, 0.16)
    score += 0.08 if features.get("texture_brand_typo_count", 0) else 0.0
    score += 0.04 if features.get("texture_digit_letter_transitions", 0) >= 8 else 0.0
    score += 0.04 if features.get("texture_max_token_length", 0) >= 24 else 0.0
    score += 0.03 if features.get("texture_consonant_run_domain", 0) >= 6 else 0.0
    if dns_resolvable is False and not features["domain_in_ip"]:
        score += 0.10
    if features["trusted_registered_domain"]:
        score -= 0.16
    if features["has_https"] and not features["qty_at_url"] and not features["brand_impersonation"]:
        score -= 0.04
    return round(max(0.0, min(score, 0.99)), 4)


def explain(features: dict[str, int | float], dns_resolvable: bool | None = None) -> list[str]:
    """Produce human-readable risk factors from extracted features."""
    reasons: list[str] = []
    if features.get("length_url", 0) > 90:
        reasons.append("URL имеет повышенную длину")
    if features.get("qty_at_url", 0) > 0 or features.get("has_userinfo", 0) > 0:
        reasons.append("в адресе присутствует userinfo/символ @, который может маскировать реальный домен")
    if features.get("domain_in_ip", 0):
        reasons.append("вместо доменного имени используется IP-адрес")
    if features.get("url_shortened", 0):
        reasons.append("используется сокращатель ссылок")
    if features.get("qty_hyphen_domain", 0) > 1:
        reasons.append("в домене много дефисов")
    if features.get("qty_subdomains", 0) >= 3:
        reasons.append("в адресе слишком много уровней поддоменов")
    if features.get("email_in_url", 0):
        reasons.append("URL содержит фрагмент, похожий на email")
    if features.get("punycode_domain", 0):
        reasons.append("домен содержит punycode/IDN-представление")
    if features.get("suspicious_words_count", 0) >= 2:
        reasons.append("найдены слова, типичные для фишинговых сценариев авторизации или платежей")
    if features.get("sensitive_params_count", 0) > 0:
        reasons.append("query-параметры содержат чувствительные имена вроде token/session/email/redirect")
    if features.get("redirect_tokens_count", 0) > 0 or features.get("query_contains_url", 0) > 0:
        reasons.append("адрес содержит признаки перенаправления на другой URL")
    if features.get("brand_impersonation", 0):
        reasons.append("домен или путь имитирует известный бренд вне доверенного домена")
    if features.get("suspicious_tld", 0):
        reasons.append("используется TLD, часто встречающийся в одноразовых или учебно-опасных доменах")
    if features.get("non_standard_port", 0):
        reasons.append("используется нестандартный порт")
    if features.get("has_encoded_chars", 0):
        reasons.append("URL содержит процентное кодирование, которое может скрывать часть адреса")
    if features.get("texture_login_marker_count", 0) >= 3:
        reasons.append("текстурный анализ URL выявил плотное скопление login/auth/verify/payment-маркеров")
    if features.get("texture_brand_typo_count", 0) > 0:
        reasons.append("текстурный анализ выявил typo-squatting/похожее написание бренда")
    if features.get("texture_digit_letter_transitions", 0) >= 8:
        reasons.append("в URL много чередований букв и цифр, характерных для маскировки домена или токенов")
    if float(features.get("texture_base64_like_score", 0.0)) >= 0.34:
        reasons.append("найдены длинные случайно выглядящие токены в структуре URL")
    if dns_resolvable is False and not features.get("domain_in_ip", 0):
        reasons.append("DNS-проверка не подтвердила существование домена")
    if not reasons and features.get("trusted_registered_domain", 0):
        reasons.append("зарегистрированный домен входит в локальный список доверенных учебных доменов")
    return reasons


FEATURE_NAMES = list(extract_features("https://example.com/path?x=1").keys())
