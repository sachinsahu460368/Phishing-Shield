"""Tests for the predictor service and explainer."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services.explainer import generate_reasons


def test_reasons_safe_url():
    features = {
        "url_length": 23,
        "hostname_length": 11,
        "num_subdomains": 0,
        "has_ip": False,
        "has_https": True,
        "has_http": False,
        "non_standard_port": False,
        "hostname_length": 11,
        "entropy": 3.2,
        "num_hyphens": 0,
        "suspicious_keyword_count": 0,
        "hostname_has_suspicious_keyword": False,
        "path_has_login_keyword": False,
        "digit_ratio": 0.0,
        "long_token_count": 0,
    }
    reasons = generate_reasons(features, risk_score=12)
    assert isinstance(reasons, list)
    assert len(reasons) >= 1
    # Should be safe-leaning reasons
    assert all(isinstance(r, str) for r in reasons)


def test_reasons_phishing_url():
    features = {
        "url_length": 150,
        "hostname_length": 45,
        "num_subdomains": 4,
        "has_ip": True,
        "has_https": False,
        "has_http": True,
        "non_standard_port": True,
        "entropy": 4.8,
        "num_hyphens": 5,
        "suspicious_keyword_count": 3,
        "hostname_has_suspicious_keyword": True,
        "path_has_login_keyword": True,
        "digit_ratio": 0.35,
        "long_token_count": 2,
    }
    reasons = generate_reasons(features, risk_score=92)
    assert isinstance(reasons, list)
    assert len(reasons) >= 3
    assert len(reasons) <= 5


def test_reasons_max_five():
    features = {
        "url_length": 200,
        "hostname_length": 60,
        "num_subdomains": 5,
        "has_ip": True,
        "has_https": False,
        "has_http": True,
        "non_standard_port": True,
        "entropy": 5.0,
        "num_hyphens": 6,
        "suspicious_keyword_count": 5,
        "hostname_has_suspicious_keyword": True,
        "path_has_login_keyword": True,
        "digit_ratio": 0.4,
        "long_token_count": 3,
    }
    reasons = generate_reasons(features, risk_score=98)
    assert len(reasons) <= 5
