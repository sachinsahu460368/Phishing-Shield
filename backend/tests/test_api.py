"""Tests for URL validation utilities."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.utils.url_utils import normalize_url, validate_url, is_ipv4


def test_normalize_adds_scheme():
    assert normalize_url("example.com") == "https://example.com"


def test_normalize_preserves_https():
    assert normalize_url("https://example.com") == "https://example.com"


def test_normalize_preserves_http():
    assert normalize_url("http://example.com") == "http://example.com"


def test_normalize_strips_whitespace():
    assert normalize_url("  https://example.com  ") == "https://example.com"


def test_validate_valid_https():
    ok, err = validate_url("https://example.com")
    assert ok is True
    assert err == ""


def test_validate_valid_http():
    ok, err = validate_url("http://example.com")
    assert ok is True


def test_validate_no_hostname():
    ok, err = validate_url("https://")
    assert ok is False


def test_validate_empty():
    ok, err = validate_url("")
    assert ok is False


def test_validate_bad_scheme():
    ok, err = validate_url("ftp://example.com")
    assert ok is False


def test_validate_no_dot():
    ok, err = validate_url("https://notadomain")
    assert ok is False


def test_validate_localhost():
    ok, err = validate_url("http://localhost")
    assert ok is True


def test_is_ipv4_true():
    assert is_ipv4("192.168.1.1") is True


def test_is_ipv4_false():
    assert is_ipv4("example.com") is False


def test_is_ipv4_out_of_range():
    assert is_ipv4("999.999.999.999") is False
