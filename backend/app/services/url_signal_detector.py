from __future__ import annotations

from ipaddress import ip_address

from backend.app.schemas.signals import URLTechnicalSignals


SUSPICIOUS_TLDS = {
    "buzz",
    "click",
    "icu",
    "top",
    "work",
    "xyz",
}


def is_ip_address_hostname(hostname: str) -> bool:
    """Return True when the hostname is a literal IP address."""
    try:
        ip_address(hostname)
    except ValueError:
        return False

    return True


def count_hostname_labels(hostname: str) -> int:
    """Count dot-separated hostname labels."""
    return len(
        [
            label
            for label in hostname.split(".")
            if label
        ]
    )


def has_excessive_subdomains(
    hostname: str,
    *,
    maximum_labels: int = 4,
) -> bool:
    """
    Return True when a hostname contains more than the
    permitted number of labels.
    """
    return count_hostname_labels(hostname) > maximum_labels


def has_long_url(
    normalized_url: str,
    *,
    maximum_length: int = 120,
) -> bool:
    """Return True when the normalized URL is unusually long."""
    return len(normalized_url) > maximum_length


def has_suspicious_tld(hostname: str) -> bool:
    """
    Return True when the hostname ends with a TLD that warrants
    additional review.

    A suspicious TLD is only a contextual indicator and does not
    establish that a domain is malicious or fraudulent.
    """
    normalized_hostname = hostname.lower().rstrip(".")
    labels = normalized_hostname.split(".")

    if len(labels) < 2:
        return False

    return labels[-1] in SUSPICIOUS_TLDS


def detect_url_structural_signals(
    signals: URLTechnicalSignals,
) -> list[str]:
    """Detect deterministic structural URL indicators."""
    detected: list[str] = []

    if is_ip_address_hostname(signals.hostname):
        detected.append("ip_address_hostname")

    if has_excessive_subdomains(signals.hostname):
        detected.append("excessive_subdomains")

    if has_long_url(signals.normalized_url):
        detected.append("long_url")

    if has_suspicious_tld(signals.hostname):
        detected.append("suspicious_tld")

    return detected