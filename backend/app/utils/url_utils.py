"""URL validation and normalization utilities."""

from urllib.parse import urlparse
import re

# IPv4 pattern for hostname detection
_IPV4_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)


def normalize_url(raw: str) -> str:
    """Add https:// scheme if missing. Returns stripped URL."""
    url = raw.strip()
    if not url:
        return url
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    return url


def validate_url(url: str) -> tuple[bool, str]:
    """Validate a URL string.  Returns (is_valid, error_message)."""
    if not url or not url.strip():
        return False, "URL must not be empty."

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL format."

    if parsed.scheme not in ("http", "https"):
        return False, "URL must use http or https scheme."

    hostname = parsed.hostname or ""
    if not hostname:
        return False, "URL has no hostname."

    # Reject hostnames without a dot (except IP addresses or localhost)
    if "." not in hostname and hostname != "localhost":
        return False, "Invalid hostname."

    return True, ""


def is_ipv4(hostname: str) -> bool:
    """Check if hostname is an IPv4 address."""
    if not _IPV4_RE.match(hostname):
        return False
    return all(0 <= int(part) <= 255 for part in hostname.split("."))
