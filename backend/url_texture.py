"""Textural URL analysis for phishing detection.

In this project the word "texture" is interpreted as the textual/symbolic
texture of a URL: character n-grams, token rhythm, digit-letter alternation,
separator density, long random-looking tokens and brand-typo patterns. These
signals are useful for URL phishing detection and are safer for the MVP than
page screenshot/DOM analysis because the extension still does not read page
content, cookies or forms.
"""
from __future__ import annotations

import math
import re
from urllib.parse import unquote, urlparse

TOKEN_RE = re.compile(r"[a-z0-9]+")
ALNUM_RE = re.compile(r"[a-z0-9]", re.IGNORECASE)
VOWELS = set("aeiouy")
LOGIN_TEXTURE_MARKERS = {
    "login", "signin", "verify", "secure", "account", "auth", "oauth",
    "token", "session", "wallet", "payment", "billing", "password", "restore",
    "unlock", "confirm", "support", "bonus", "gift", "prize", "urgent",
}
BRAND_TYPO_TEXTURES = {
    "g00gle", "go0gle", "gogle", "paypa1", "paypai", "faceboook", "fac ebook",
    "micros0ft", "rnicrosoft", "out1ook", "icl0ud", "sberbnk", "gosus1ugi",
    "yand3x", "tink0ff", "stearn", "disc0rd",
}
SEPARATORS = set(".-_/?:=&%+@#")
SYMBOLS = set(".-_/?:=&%+@#;~,!")


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    total = len(value)
    counts = {ch: value.count(ch) for ch in set(value)}
    return round(-sum((count / total) * math.log2(count / total) for count in counts.values()), 4)


def _max_run(value: str, predicate) -> int:
    best = 0
    current = 0
    for ch in value:
        if predicate(ch):
            current += 1
            best = max(best, current)
        else:
            current = 0
    return best


def _max_repeated_char_run(value: str) -> int:
    best = 0
    current = 0
    previous = None
    for ch in value:
        if ch == previous:
            current += 1
        else:
            current = 1
            previous = ch
        best = max(best, current)
    return best


def _char_class(ch: str) -> str:
    if ch.isalpha():
        return "a"
    if ch.isdigit():
        return "d"
    if ch in SEPARATORS:
        return "s"
    return "o"


def _count_charclass_transitions(value: str) -> int:
    if len(value) < 2:
        return 0
    classes = [_char_class(ch) for ch in value]
    return sum(1 for left, right in zip(classes, classes[1:]) if left != right)


def _count_digit_letter_transitions(value: str) -> int:
    if len(value) < 2:
        return 0
    total = 0
    for left, right in zip(value, value[1:]):
        if (left.isdigit() and right.isalpha()) or (left.isalpha() and right.isdigit()):
            total += 1
    return total


def _max_consonant_run(value: str) -> int:
    return _max_run(value, lambda ch: ch.isalpha() and ch.lower() not in VOWELS)


def _vowel_ratio(value: str) -> float:
    letters = [ch.lower() for ch in value if ch.isalpha()]
    if not letters:
        return 0.0
    return round(sum(1 for ch in letters if ch in VOWELS) / len(letters), 4)


def _base64_like_score(tokens: list[str]) -> float:
    """Score long random-looking URL tokens, often used for sessions/tracking."""
    risky = 0
    for token in tokens:
        if len(token) >= 16 and _entropy(token) >= 3.4 and any(ch.isdigit() for ch in token):
            risky += 1
    return round(min(risky / 3.0, 1.0), 4)


def _alpha_numeric_token_count(tokens: list[str]) -> int:
    return sum(1 for token in tokens if any(ch.isalpha() for ch in token) and any(ch.isdigit() for ch in token))


def extract_url_textures(normalized_url: str) -> dict[str, int | float]:
    """Return numeric URL texture features suitable for ML and explanations."""
    parsed = urlparse(normalized_url)
    decoded = unquote(normalized_url).lower()
    host = (parsed.hostname or "").lower()
    path = unquote(parsed.path or "").lower()
    query = unquote(parsed.query or "").lower()
    without_scheme = re.sub(r"^https?://", "", decoded)
    tokens = TOKEN_RE.findall(without_scheme)
    path_tokens = TOKEN_RE.findall(path)
    query_tokens = TOKEN_RE.findall(query)
    alnum_total = sum(1 for ch in decoded if ch.isalnum())
    symbol_total = sum(1 for ch in decoded if ch in SYMBOLS)
    separator_total = sum(1 for ch in decoded if ch in SEPARATORS)
    login_marker_count = sum(1 for marker in LOGIN_TEXTURE_MARKERS if marker in decoded)
    brand_typo_count = sum(1 for typo in BRAND_TYPO_TEXTURES if typo.replace(" ", "") in decoded.replace(" ", ""))
    homoglyph_digit_count = sum(1 for ch in host if ch in "013457")
    avg_token_length = sum(len(token) for token in tokens) / max(len(tokens), 1)

    return {
        "texture_token_count": len(tokens),
        "texture_path_token_count": len(path_tokens),
        "texture_query_token_count": len(query_tokens),
        "texture_avg_token_length": round(avg_token_length, 4),
        "texture_max_token_length": max((len(token) for token in tokens), default=0),
        "texture_numeric_token_count": sum(1 for token in tokens if token.isdigit()),
        "texture_alpha_numeric_token_count": _alpha_numeric_token_count(tokens),
        "texture_digit_letter_transitions": _count_digit_letter_transitions(without_scheme),
        "texture_charclass_transitions": _count_charclass_transitions(without_scheme),
        "texture_separator_ratio": round(separator_total / max(len(decoded), 1), 4),
        "texture_symbol_ratio": round(symbol_total / max(len(decoded), 1), 4),
        "texture_max_digit_run": _max_run(without_scheme, str.isdigit),
        "texture_max_alpha_run": _max_run(without_scheme, str.isalpha),
        "texture_max_repeated_char_run": _max_repeated_char_run(without_scheme),
        "texture_consonant_run_domain": _max_consonant_run(host),
        "texture_vowel_ratio_domain": _vowel_ratio(host),
        "texture_login_marker_count": login_marker_count,
        "texture_brand_typo_count": brand_typo_count,
        "texture_homoglyph_digit_count": homoglyph_digit_count,
        "texture_base64_like_score": _base64_like_score(tokens),
        "texture_url_entropy": _entropy(without_scheme),
    }


def summarize_texture_features(features: dict[str, int | float]) -> dict[str, int | float | bool | str]:
    """Compact texture summary safe to return to the extension UI."""
    token_count = int(features.get("texture_token_count", 0))
    transitions = int(features.get("texture_charclass_transitions", 0))
    login_markers = int(features.get("texture_login_marker_count", 0))
    brand_typo_markers = int(features.get("texture_brand_typo_count", 0))
    random_score = float(features.get("texture_base64_like_score", 0.0))
    risk_markers = login_markers + brand_typo_markers + int(random_score >= 0.34)
    if risk_markers >= 3 or transitions >= 28:
        summary = "выраженная подозрительная URL-текстура"
    elif risk_markers >= 1 or transitions >= 16:
        summary = "есть отдельные подозрительные текстурные признаки"
    else:
        summary = "текстура URL без выраженных подозрительных паттернов"
    return {
        "enabled": True,
        "summary": summary,
        "token_count": token_count,
        "charclass_transitions": transitions,
        "digit_letter_transitions": int(features.get("texture_digit_letter_transitions", 0)),
        "login_markers": login_markers,
        "brand_typo_markers": brand_typo_markers,
        "base64_like_score": random_score,
    }
