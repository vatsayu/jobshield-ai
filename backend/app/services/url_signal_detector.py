from __future__ import annotations

from ipaddress import ip_address
from urllib.parse import urlparse

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


def has_suspicious_encoding(normalized_url: str) -> bool:
    """
    Detect excessive or suspicious percent-encoding in a URL.

    This is a heuristic signal only. Percent-encoding is legitimate in
    many URLs, so this function should not independently imply maliciousness.
    """
    encoded_markers = normalized_url.lower().count("%")

    if encoded_markers >= 4:
        return True

    suspicious_sequences = (
        "%2f",
        "%5c",
        "%2e",
        "%25",
    )

    return any(
        sequence in normalized_url.lower()
        for sequence in suspicious_sequences
    )


def has_userinfo_in_url(normalized_url: str) -> bool:
    """
    Return True when a URL contains userinfo before the hostname.

    Userinfo can make a URL visually misleading and should receive
    additional review. This does not independently prove maliciousness.
    """
    parsed = urlparse(normalized_url)

    return (
        parsed.username is not None
        or parsed.password is not None
    )


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


def has_hyphenated_hostname_abuse(
    hostname: str,
    *,
    maximum_hyphens: int = 3,
) -> bool:
    """
    Return True when the hostname contains an unusually high number
    of hyphens.

    This is a heuristic indicator only and does not establish
    malicious activity.
    """
    return hostname.count("-") > maximum_hyphens


def has_long_hostname_label(
    hostname: str,
    *,
    maximum_length: int = 30,
) -> bool:
    """
    Return True when an individual hostname label is unusually long.

    This is a heuristic indicator only and does not establish
    malicious activity.
    """
    labels = [
        label
        for label in hostname.split(".")
        if label
    ]

    return any(
        len(label) > maximum_length
        for label in labels
    )


def detect_url_structural_signals(
    signals: URLTechnicalSignals,
) -> list[str]:
    detected: list[str] = []

    if is_ip_address_hostname(signals.hostname):
        detected.append("ip_address_hostname")

    if has_excessive_subdomains(signals.hostname):
        detected.append("excessive_subdomains")

    if has_long_url(signals.normalized_url):
        detected.append("long_url")

    if has_suspicious_tld(signals.hostname):
        detected.append("suspicious_tld")

    if has_suspicious_encoding(signals.normalized_url):
        detected.append("suspicious_encoding")

    if has_userinfo_in_url(signals.normalized_url):
        detected.append("userinfo_in_url")

    if has_hyphenated_hostname_abuse(signals.hostname):
        detected.append("hyphenated_hostname_abuse")

    if has_long_hostname_label(signals.hostname):
        detected.append("long_hostname_label")

    return detected