"""Canonical URL feature extraction engine.

This module defines every feature used for training and inference.
The FEATURE_NAMES list is the single source of truth for feature ordering.
"""

import math
import re
from collections import Counter
from urllib.parse import urlparse, unquote

import tldextract

from app.utils.url_utils import is_ipv4

# ─── Centralized suspicious keywords ────────────────────────────────────────
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "secure",
    "account", "update", "confirm", "password", "bank", "payment",
    "wallet", "bonus", "free", "urgent", "alert", "support", "security",
    "authenticate", "credential", "suspend", "restrict", "expire",
    "billing", "invoice", "recover", "unlock",
]

# Small, transparent list of high-value brand tokens used ONLY as a
# generic "brand-like token in subdomain" signal.  This is NOT a whitelist
# — having a brand token does NOT make a URL safe.  The feature detects
# when a well-known brand name appears in a subdomain/hostname prefix but
# the registrable domain is different (a common phishing pattern).
BRAND_TOKENS = frozenset([
    "google", "facebook", "apple", "microsoft", "amazon", "paypal",
    "netflix", "instagram", "whatsapp", "twitter", "linkedin", "github",
    "yahoo", "dropbox", "spotify", "adobe", "chase", "wellsfargo",
    "bankofamerica", "citibank", "americanexpress", "usps", "fedex",
    "dhl", "ebay", "walmart", "target", "costco",
])

# Suspicious TLD suffixes — commonly abused free-hosting / cheap TLDs
_SUSPICIOUS_TLDS = frozenset([
    "tk", "ml", "ga", "cf", "gq",       # Freenom free TLDs
    "xyz", "top", "club", "online",      # cheap generic TLDs
    "buzz", "work", "surf", "icu",       # spam-heavy
    "ru", "cn",                          # region-specific high abuse
])


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
    # ── NEW: Domain-aware features (11) ──
    "registrable_domain_length",
    "subdomain_length",
    "subdomain_depth",
    "tld_length",
    "max_hostname_token_length",
    "avg_hostname_token_length",
    "hostname_digit_ratio",
    "suspicious_tld",
    "brand_in_subdomain",
    "brand_domain_mismatch",
    "subdomain_keyword_count",
    # ── NEW: Obfuscation features (6) ──
    "has_at_symbol",
    "percent_encoded_count",
    "percent_encoding_ratio",
    "hex_token_count",
    "repeated_separator_count",
    "url_decoded_length_diff",
]

assert len(FEATURE_NAMES) == 52, f"Expected 52 features, got {len(FEATURE_NAMES)}"


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


# ─── Domain helpers (tldextract-based) ───────────────────────────────────────
def _extract_domain_parts(hostname: str) -> dict:
    """Use tldextract for proper registrable domain extraction.

    Returns dict with: domain, suffix, subdomain, registrable_domain.
    """
    ext = tldextract.extract(hostname)
    reg_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    return {
        "domain": ext.domain,
        "suffix": ext.suffix,
        "subdomain": ext.subdomain,
        "registrable_domain": reg_domain,
    }


def _brand_in_subdomain(subdomain: str) -> bool:
    """Check if a brand token appears anywhere in the subdomain."""
    if not subdomain:
        return False
    lower = subdomain.lower()
    return any(brand in lower for brand in BRAND_TOKENS)


def _brand_domain_mismatch(subdomain: str, domain: str) -> bool:
    """Detect if a brand token in the subdomain does not match the domain.

    Example: paypal.attacker.com → brand "paypal" in subdomain, domain="attacker" → mismatch
    Example: login.paypal.com → brand "paypal" NOT in subdomain (it IS the domain) → no mismatch
    """
    if not subdomain:
        return False
    lower_sub = subdomain.lower()
    lower_domain = domain.lower()

    for brand in BRAND_TOKENS:
        if brand in lower_sub and brand != lower_domain:
            return True
    return False


# ─── Obfuscation helpers ────────────────────────────────────────────────────
_PERCENT_ENCODED_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_HEX_TOKEN_RE = re.compile(r"(?:0x)?[0-9a-fA-F]{8,}")
_REPEATED_SEP_RE = re.compile(r"[/\\]{3,}|[-]{4,}|[.]{3,}")


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

    # ── Registrable domain extraction (tldextract) ──────────────────────
    dparts = _extract_domain_parts(hostname)
    subdomain = dparts["subdomain"]
    reg_domain = dparts["registrable_domain"]
    domain_name = dparts["domain"]
    tld_suffix = dparts["suffix"]

    # ── Subdomain count ─────────────────────────────────────────────────
    if is_ipv4(hostname):
        num_subdomains = 0
        subdomain_depth = 0
    else:
        parts = hostname.split(".")
        num_subdomains = max(0, len(parts) - 2)
        # subdomain_depth: based on tldextract's subdomain
        subdomain_depth = len(subdomain.split(".")) if subdomain else 0

    port = parsed.port
    has_port = port is not None
    non_standard_port = port not in _STANDARD_PORTS

    # ── Character class counts on full URL ──────────────────────────────
    num_digits = sum(c.isdigit() for c in full)
    num_letters = sum(c.isalpha() for c in full)
    special_chars = sum(
        1 for c in full if not c.isalnum() and c not in (":", "/", ".", "?", "&", "=", "#")
    )

    digit_ratio = num_digits / max(len(full), 1)
    special_char_ratio = special_chars / max(len(full), 1)
    character_diversity = len(set(full)) / max(len(full), 1)

    # ── Long tokens (tokens > 20 chars) split on common separators ──────
    tokens = re.split(r"[/\.\-_?&=]", full)
    long_token_count = sum(1 for t in tokens if len(t) > 20)

    # ── NEW: Domain-aware features ──────────────────────────────────────
    registrable_domain_length = len(reg_domain)
    subdomain_length = len(subdomain)
    tld_length = len(tld_suffix)

    # Hostname token analysis
    hostname_tokens = [t for t in hostname.split(".") if t]
    max_hostname_token_length = max((len(t) for t in hostname_tokens), default=0)
    avg_hostname_token_length = (
        sum(len(t) for t in hostname_tokens) / len(hostname_tokens)
        if hostname_tokens else 0.0
    )

    # Hostname digit ratio (separate from URL digit ratio)
    hostname_digit_ratio = (
        sum(c.isdigit() for c in hostname) / max(len(hostname), 1)
    )

    # Suspicious TLD
    suspicious_tld = tld_suffix.lower() in _SUSPICIOUS_TLDS

    # Brand features
    brand_in_sub = _brand_in_subdomain(subdomain)
    brand_mismatch = _brand_domain_mismatch(subdomain, domain_name)

    # Keyword count in subdomain only (NOT full URL)
    subdomain_keyword_count = _count_keywords(subdomain) if subdomain else 0

    # ── NEW: Obfuscation features ───────────────────────────────────────
    has_at_symbol = "@" in full
    percent_encoded_matches = _PERCENT_ENCODED_RE.findall(full)
    percent_encoded_count = len(percent_encoded_matches)
    percent_encoding_ratio = percent_encoded_count * 3 / max(len(full), 1)
    hex_token_count = len(_HEX_TOKEN_RE.findall(full))
    repeated_separator_count = len(_REPEATED_SEP_RE.findall(full))
    try:
        decoded = unquote(full)
        url_decoded_length_diff = len(full) - len(decoded)
    except Exception:
        url_decoded_length_diff = 0

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
        # ── NEW: Domain-aware features ──
        "registrable_domain_length": registrable_domain_length,
        "subdomain_length": subdomain_length,
        "subdomain_depth": subdomain_depth,
        "tld_length": tld_length,
        "max_hostname_token_length": max_hostname_token_length,
        "avg_hostname_token_length": round(avg_hostname_token_length, 4),
        "hostname_digit_ratio": round(hostname_digit_ratio, 4),
        "suspicious_tld": suspicious_tld,
        "brand_in_subdomain": brand_in_sub,
        "brand_domain_mismatch": brand_mismatch,
        "subdomain_keyword_count": subdomain_keyword_count,
        # ── NEW: Obfuscation features ──
        "has_at_symbol": has_at_symbol,
        "percent_encoded_count": percent_encoded_count,
        "percent_encoding_ratio": round(percent_encoding_ratio, 4),
        "hex_token_count": hex_token_count,
        "repeated_separator_count": repeated_separator_count,
        "url_decoded_length_diff": url_decoded_length_diff,
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
