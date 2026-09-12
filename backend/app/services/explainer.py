"""Explainability engine — converts feature values into human-readable reasons."""

from app.services.url_features import SUSPICIOUS_KEYWORDS


def generate_reasons(features: dict, risk_score: int) -> list[str]:
    """Return up to 5 human-readable risk reasons from feature values.

    Reasons are ranked by relevance.  For low-risk URLs the list may describe
    why the URL appears safe.
    """
    reasons: list[str] = []

    # ── High-signal indicators (domain-aware, Phase 4-8) ─────────────────
    if features.get("brand_domain_mismatch"):
        reasons.append("Brand name appears in subdomain but not in the actual domain — classic impersonation pattern.")

    if features.get("has_ip"):
        reasons.append("URL uses an IP address instead of a domain name.")

    subdomain_depth = features.get("subdomain_depth", 0)
    if subdomain_depth >= 4:
        reasons.append("Unusually deep subdomain structure — often used to hide the real domain.")
    elif subdomain_depth >= 3:
        reasons.append("Multiple subdomain levels present.")

    if features.get("brand_in_subdomain") and not features.get("brand_domain_mismatch"):
        # brand is in subdomain but domain also matches (e.g. login.paypal.com) — not suspicious
        pass

    if features.get("suspicious_tld"):
        reasons.append("URL uses a TLD commonly associated with free hosting or high spam volume.")

    # ── Obfuscation signals ───────────────────────────────────────────────
    if features.get("has_at_symbol"):
        reasons.append("URL contains '@' symbol — can hide the real destination.")

    pct_encoded = features.get("percent_encoded_count", 0)
    if pct_encoded >= 5:
        reasons.append("Heavy percent-encoding in the URL — common obfuscation technique.")
    elif pct_encoded >= 2:
        reasons.append("URL contains percent-encoded characters — possible obfuscation.")

    hex_tokens = features.get("hex_token_count", 0)
    if hex_tokens >= 2:
        reasons.append("Multiple long hex tokens detected — may indicate encoded payloads.")

    if features.get("repeated_separator_count", 0) >= 2:
        reasons.append("Unusual repeated separators in the URL path.")

    # ── Keyword / lexical signals ─────────────────────────────────────────
    if features.get("hostname_has_suspicious_keyword"):
        reasons.append("Hostname contains a keyword often used in phishing URLs.")

    subdomain_kw = features.get("subdomain_keyword_count", 0)
    if subdomain_kw >= 2:
        reasons.append("Multiple phishing-related keywords in the subdomain.")

    kw_count = features.get("suspicious_keyword_count", 0)
    if kw_count >= 3:
        reasons.append("Multiple account/login-related keywords detected.")
    elif kw_count >= 1 and not features.get("hostname_has_suspicious_keyword"):
        reasons.append("Suspicious keyword detected in the URL.")

    # ── Structural signals ────────────────────────────────────────────────
    subs = features.get("num_subdomains", 0)
    if subs >= 3 and subdomain_depth < 3:
        reasons.append("URL contains an unusually deep subdomain structure.")
    elif subs >= 2 and subdomain_depth < 2:
        reasons.append("Multiple subdomain levels present.")

    url_length = features.get("url_length", 0)
    if url_length > 120:
        reasons.append("Unusually long URL structure.")
    elif url_length > 80:
        reasons.append("Above-average URL length.")

    if features.get("non_standard_port"):
        reasons.append("URL uses a non-standard port number.")

    hostname_length = features.get("hostname_length", 0)
    if hostname_length > 40:
        reasons.append("Hostname is unusually long.")

    entropy = features.get("entropy", 0)
    if entropy > 4.5:
        reasons.append("URL contains high character randomness (entropy).")

    hyphens = features.get("num_hyphens", 0)
    if hyphens >= 3:
        reasons.append("Multiple hyphens in the URL, common in phishing domains.")

    if features.get("path_has_login_keyword"):
        reasons.append("URL path contains a login or verification keyword.")

    digit_ratio = features.get("digit_ratio", 0)
    if digit_ratio > 0.3:
        reasons.append("Unusually high proportion of digits in the URL.")

    long_tokens = features.get("long_token_count", 0)
    if long_tokens >= 2:
        reasons.append("URL contains multiple unusually long tokens.")

    if not features.get("has_https") and features.get("has_http"):
        reasons.append("URL does not use HTTPS encryption.")

    # Safe-leaning reasons when nothing suspicious found
    if not reasons:
        safe_reasons = []
        if features.get("has_https"):
            safe_reasons.append("Uses HTTPS encryption.")
        if kw_count == 0:
            safe_reasons.append("No deceptive login keywords detected.")
        if url_length < 60:
            safe_reasons.append("URL structure is concise and consistent.")
        if subs <= 1:
            safe_reasons.append("Simple domain structure.")
        if not features.get("brand_in_subdomain"):
            safe_reasons.append("No brand impersonation detected in domain structure.")
        if not safe_reasons:
            safe_reasons.append("No major suspicious URL patterns detected.")
        return safe_reasons[:3]

    return reasons[:5]
