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
                "hostname_has_suspicious_keyword"):
        assert isinstance(features[key], bool), f"{key} should be bool, got {type(features[key])}"


# ── Tests ───────────────────────────────────────────────────────────────────
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
    assert len(FEATURE_NAMES) >= 20, f"Expected ≥20 features, got {len(FEATURE_NAMES)}"


def test_query_has_sensitive_keyword():
    feats = extract_features("https://example.com/page?token=abc&password=xyz")
    _assert_features(feats)
    assert feats["query_has_sensitive_keyword"] is True
