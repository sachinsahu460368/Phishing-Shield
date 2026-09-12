"""Tests for URL feature extraction."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import math
from app.services.url_features import (
    FEATURE_NAMES,
    extract_features,
    features_to_vector,
    _shannon_entropy,
)


# ── Helper ──────────────────────────────────────────────────────────────────
def _assert_features(features: dict):
    """Shared sanity checks for any feature dict."""
    # All canonical features present
    for name in FEATURE_NAMES:
        assert name in features, f"Missing feature: {name}"

    # Numeric values are finite
    for name, val in features.items():
        if isinstance(val, (int, float)):
            assert math.isfinite(val), f"{name} is not finite: {val}"

    # Booleans are valid
    for key in ("has_https", "has_http", "has_ip", "has_port", "non_standard_port",
                "path_has_login_keyword", "query_has_sensitive_keyword",
                "hostname_has_suspicious_keyword",
                # New boolean features (Phase 4-8)
                "suspicious_tld", "brand_in_subdomain", "brand_domain_mismatch",
                "has_at_symbol"):
        assert isinstance(features[key], bool), f"{key} should be bool, got {type(features[key])}"


# ── Tests — basic structure ─────────────────────────────────────────────────
def test_simple_url():
    feats = extract_features("https://example.com")
    _assert_features(feats)
    assert feats["has_https"] is True
    assert feats["has_ip"] is False
    assert feats["num_subdomains"] == 0


def test_login_url():
    feats = extract_features("https://example.com/login")
    _assert_features(feats)
    assert feats["path_has_login_keyword"] is True
    assert feats["suspicious_keyword_count"] >= 1


def test_suspicious_url():
    feats = extract_features("https://secure-login-example.com/verify")
    _assert_features(feats)
    assert feats["suspicious_keyword_count"] >= 2
    assert feats["num_hyphens"] >= 2


def test_ip_url():
    feats = extract_features("http://192.168.1.1/login")
    _assert_features(feats)
    assert feats["has_ip"] is True
    assert feats["has_https"] is False
    assert feats["has_http"] is True
    assert feats["num_subdomains"] == 0


def test_subdomain_url():
    feats = extract_features("https://sub.example.com/account/verify")
    _assert_features(feats)
    assert feats["num_subdomains"] == 1


def test_deep_subdomain_url():
    feats = extract_features("https://login.account.security.example.com/verify")
    _assert_features(feats)
    assert feats["num_subdomains"] == 3


def test_port_url():
    feats = extract_features("https://example.com:8080/login")
    _assert_features(feats)
    assert feats["has_port"] is True
    assert feats["non_standard_port"] is True


def test_standard_port():
    feats = extract_features("https://example.com:443/path")
    _assert_features(feats)
    assert feats["has_port"] is True
    assert feats["non_standard_port"] is False


def test_entropy_empty():
    assert _shannon_entropy("") == 0.0


def test_entropy_finite():
    val = _shannon_entropy("https://example.com")
    assert isinstance(val, float)
    assert math.isfinite(val)
    assert val > 0


def test_feature_vector_order():
    feats = extract_features("https://example.com")
    vec = features_to_vector(feats)
    assert len(vec) == len(FEATURE_NAMES)
    # Same URL → same vector every time
    assert vec == features_to_vector(extract_features("https://example.com"))


def test_feature_count():
    assert len(FEATURE_NAMES) == 52, f"Expected 52 features, got {len(FEATURE_NAMES)}"


def test_query_has_sensitive_keyword():
    feats = extract_features("https://example.com/page?token=abc&password=xyz")
    _assert_features(feats)
    assert feats["query_has_sensitive_keyword"] is True


# ── Tests — domain-aware features ──────────────────────────────────────────
def test_registrable_domain_length():
    feats = extract_features("https://github.com")
    _assert_features(feats)
    # github.com → registrable_domain_length = len("github.com") = 10
    assert feats["registrable_domain_length"] == 10


def test_subdomain_depth_simple():
    feats = extract_features("https://example.com")
    # No subdomain → depth 0
    assert feats["subdomain_depth"] == 0


def test_subdomain_depth_deep():
    feats = extract_features("https://a.b.c.example.com")
    # subdomain = "a.b.c" → depth 3
    assert feats["subdomain_depth"] == 3


def test_tld_length():
    feats = extract_features("https://example.com")
    assert feats["tld_length"] == 3  # "com"


def test_hostname_token_lengths():
    feats = extract_features("https://sub.example.com")
    # Tokens: ["sub", "example", "com"]
    assert feats["max_hostname_token_length"] == 7  # "example"
    assert feats["avg_hostname_token_length"] > 0


def test_hostname_digit_ratio():
    feats = extract_features("https://abc123.com")
    # hostname = "abc123.com" → 3 digits / 10 chars = 0.3
    assert feats["hostname_digit_ratio"] == 0.3


def test_suspicious_tld():
    feats_tk = extract_features("http://example.tk")
    assert feats_tk["suspicious_tld"] is True

    feats_com = extract_features("https://example.com")
    assert feats_com["suspicious_tld"] is False


# ── Tests — brand features ─────────────────────────────────────────────────
def test_brand_in_subdomain_positive():
    feats = extract_features("https://paypal.attacker.com/login")
    _assert_features(feats)
    assert feats["brand_in_subdomain"] is True
    assert feats["brand_domain_mismatch"] is True


def test_brand_in_subdomain_negative():
    # paypal IS the domain, not a subdomain
    feats = extract_features("https://login.paypal.com")
    assert feats["brand_in_subdomain"] is False
    assert feats["brand_domain_mismatch"] is False


def test_brand_mismatch_github_attacker():
    feats = extract_features("https://github.com.attacker.com/login")
    # sub = "github.com", domain = "attacker" → brand "github" in subdomain but != domain
    assert feats["brand_in_subdomain"] is True
    assert feats["brand_domain_mismatch"] is True


def test_brand_no_mismatch_legitimate():
    feats = extract_features("https://www.google.com")
    # subdomain = "www" → no brand token in subdomain
    assert feats["brand_in_subdomain"] is False
    assert feats["brand_domain_mismatch"] is False


def test_subdomain_keyword_count():
    feats = extract_features("https://login-verify.example.com/path")
    # subdomain = "login-verify" → "login" and "verify" are suspicious keywords
    assert feats["subdomain_keyword_count"] >= 2


# ── Tests — obfuscation features ───────────────────────────────────────────
def test_at_symbol():
    feats = extract_features("https://user@evil.com")
    _assert_features(feats)
    assert feats["has_at_symbol"] is True

    feats_no_at = extract_features("https://example.com")
    assert feats_no_at["has_at_symbol"] is False


def test_percent_encoding():
    feats = extract_features("https://example.com/%2F%2F%2E%2E")
    _assert_features(feats)
    assert feats["percent_encoded_count"] >= 4
    assert feats["percent_encoding_ratio"] > 0
    assert feats["url_decoded_length_diff"] > 0


def test_hex_token():
    feats = extract_features("https://example.com/0x4a3b2c1d0e4f5a6b")
    assert feats["hex_token_count"] >= 1


def test_repeated_separators():
    feats = extract_features("https://example.com////path---to....file")
    assert feats["repeated_separator_count"] >= 2


# ── Tests — feature vector consistency ─────────────────────────────────────
def test_vector_booleans_are_int():
    """Booleans in the vector must be converted to 0/1 ints for ML."""
    feats = extract_features("https://example.com")
    vec = features_to_vector(feats)
    for i, name in enumerate(FEATURE_NAMES):
        if isinstance(feats[name], bool):
            assert vec[i] in (0, 1), f"{name}: bool not converted, got {vec[i]}"
            assert isinstance(vec[i], int), f"{name}: expected int, got {type(vec[i])}"


def test_all_features_non_negative():
    """Most features should be non-negative for typical URLs."""
    for url in ("https://example.com", "http://192.168.1.1/login",
                "https://sub.example.com/path?q=1"):
        feats = extract_features(url)
        for name in FEATURE_NAMES:
            val = feats[name]
            if isinstance(val, bool):
                continue
            assert val >= 0, f"{name} is negative ({val}) for {url}"


def test_github_not_suspicious():
    """github.com should not trigger brand/obfuscation signals."""
    feats = extract_features("https://github.com")
    _assert_features(feats)
    assert feats["brand_in_subdomain"] is False
    assert feats["brand_domain_mismatch"] is False
    assert feats["suspicious_tld"] is False
    assert feats["has_at_symbol"] is False
    assert feats["subdomain_keyword_count"] == 0
    assert feats["percent_encoded_count"] == 0
