"""Canonical URL feature extraction engine.

This module defines every feature used for training and inference.
The FEATURE_NAMES list is the single source of truth for feature ordering.
"""

import math
import re
from collections import Counter
from urllib.parse import urlparse

from app.utils.url_utils import is_ipv4

# ─── Centralized suspicious keywords ────────────────────────────────────────
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "secure",
    "account", "update", "confirm", "password", "bank", "payment",
    "wallet", "bonus", "free", "urgent", "alert", "support", "security",
    "authenticate", "credential", "suspend", "restrict", "expire",
    "billing", "invoice", "recover", "unlock",
]

# ─── Canonical feature order — used everywhere ──────────────────────────────
FEATURE_NAMES = [
    # Basic structure (16)
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "fragment_length",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_slashes",
    "num_question_marks",
    "num_equals",
    "num_ampersands",
    "num_percent_chars",
    "num_digits",
    "num_letters",
    "special_character_count",
    # Hostname (5)
    "num_subdomains",
    "has_ip",
    "hostname_digit_count",
    "hostname_hyphen_count",
    "hostname_dot_count",
    # Protocol / security (4)
    "has_https",
    "has_http",
    "has_port",
    "non_standard_port",
    # Lexical / phishing signals (1)
    "suspicious_keyword_count",
    # Entropy / complexity (5)
    "entropy",
    "hostname_entropy",
    "digit_ratio",
    "special_char_ratio",
    "character_diversity",
    # Domain / path signals (4)
    "path_has_login_keyword",
    "query_has_sensitive_keyword",
    "hostname_has_suspicious_keyword",
    "long_token_count",
]

assert len(FEATURE_NAMES) == 35, f"Expected 35 features, got {len(FEATURE_NAMES)}"


# ─── Shannon entropy ────────────────────────────────────────────────────────
def _shannon_entropy(text: str) -> float:
    """Compute Shannon entropy of a string. Returns 0.0 for empty input."""
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length) for count in freq.values()
    )


# ─── Keyword helpers ────────────────────────────────────────────────────────
def _count_keywords(text: str, keywords: list[str] | None = None) -> int:
    """Count how many suspicious keywords appear in lowered text."""
    words = keywords or SUSPICIOUS_KEYWORDS
    lower = text.lower()
    return sum(1 for kw in words if kw in lower)


def _has_keyword(text: str, keywords: list[str] | None = None) -> bool:
    return _count_keywords(text, keywords) > 0


# ─── Standard ports ─────────────────────────────────────────────────────────
_STANDARD_PORTS = {80, 443, None}


# ─── Main extractor ─────────────────────────────────────────────────────────
def extract_features(url: str) -> dict:
    """Extract the canonical feature dictionary from a URL string.

    Returns a dict keyed by FEATURE_NAMES with numeric / bool values.
    """
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    full = url

    # Subdomain count (e.g. "a.b.example.com" → 2 subdomains)
    if is_ipv4(hostname):
        num_subdomains = 0
    else:
        parts = hostname.split(".")
        num_subdomains = max(0, len(parts) - 2)

    port = parsed.port
    has_port = port is not None
    non_standard_port = port not in _STANDARD_PORTS

    # Character class counts on full URL
    num_digits = sum(c.isdigit() for c in full)
    num_letters = sum(c.isalpha() for c in full)
    special_chars = sum(
        1 for c in full if not c.isalnum() and c not in (":", "/", ".", "?", "&", "=", "#")
    )

    digit_ratio = num_digits / max(len(full), 1)
    special_char_ratio = special_chars / max(len(full), 1)
    character_diversity = len(set(full)) / max(len(full), 1)

    # Long tokens (tokens > 20 chars) split on common separators
    tokens = re.split(r"[/\.\-_?&=]", full)
    long_token_count = sum(1 for t in tokens if len(t) > 20)

    features = {
        # Basic structure
        "url_length": len(full),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "fragment_length": len(fragment),
        "num_dots": full.count("."),
        "num_hyphens": full.count("-"),
        "num_underscores": full.count("_"),
        "num_slashes": full.count("/"),
        "num_question_marks": full.count("?"),
        "num_equals": full.count("="),
        "num_ampersands": full.count("&"),
        "num_percent_chars": full.count("%"),
        "num_digits": num_digits,
        "num_letters": num_letters,
        "special_character_count": special_chars,
        # Hostname
        "num_subdomains": num_subdomains,
        "has_ip": is_ipv4(hostname),
        "hostname_digit_count": sum(c.isdigit() for c in hostname),
        "hostname_hyphen_count": hostname.count("-"),
        "hostname_dot_count": hostname.count("."),
        # Protocol / security
        "has_https": parsed.scheme == "https",
        "has_http": parsed.scheme == "http",
        "has_port": has_port,
        "non_standard_port": non_standard_port,
        # Lexical signals
        "suspicious_keyword_count": _count_keywords(full),
        # Entropy / complexity
        "entropy": round(_shannon_entropy(full), 4),
        "hostname_entropy": round(_shannon_entropy(hostname), 4),
        "digit_ratio": round(digit_ratio, 4),
        "special_char_ratio": round(special_char_ratio, 4),
        "character_diversity": round(character_diversity, 4),
        # Domain / path signals
        "path_has_login_keyword": _has_keyword(path, ["login", "signin", "sign-in", "verify", "authenticate", "password", "confirm"]),
        "query_has_sensitive_keyword": _has_keyword(query, ["password", "token", "session", "key", "secret", "credential"]),
        "hostname_has_suspicious_keyword": _has_keyword(hostname),
        "long_token_count": long_token_count,
    }

    return features


def features_to_vector(features: dict) -> list:
    """Convert a feature dict to an ordered list matching FEATURE_NAMES."""
    vec = []
    for name in FEATURE_NAMES:
        val = features[name]
        # Convert booleans to int for ML
        if isinstance(val, bool):
            val = int(val)
        vec.append(val)
    return vec


def features_for_display(features: dict) -> dict:
    """Return a subset of features suitable for the frontend."""
    display_keys = [
        "url_length", "hostname_length", "path_length",
        "num_dots", "num_hyphens", "num_subdomains",
        "suspicious_keyword_count", "digit_ratio",
        "special_character_count", "entropy",
        "has_https", "has_ip", "has_port",
    ]
    return {k: features[k] for k in display_keys if k in features}
