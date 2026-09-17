from backend.app.schemas.signals import URLTechnicalSignals
from backend.app.services.url_signal_detector import (
    count_hostname_labels,
    detect_url_structural_signals,
    has_excessive_subdomains,
    has_long_url,
    is_ip_address_hostname,
)


def build_signals(
    *,
    hostname: str = "example.com",
    normalized_url: str = "https://example.com/jobs",
) -> URLTechnicalSignals:
    return URLTechnicalSignals(
        normalized_url=normalized_url,
        hostname=hostname,
        scheme="https",
        port=None,
        has_https=True,
        redirect_count=0,
        final_url=normalized_url,
        status_code=200,
        content_type="text/html",
        content_length=128,
        response_size_bytes=128,
        fetch_status="success",
        fetch_error=None,
        domain_age_days=None,
        suspicious_keywords=[],
    )


def test_detects_ipv4_hostname() -> None:
    assert is_ip_address_hostname("8.8.8.8") is True


def test_detects_ipv6_hostname() -> None:
    assert is_ip_address_hostname("2001:4860:4860::8888") is True


def test_rejects_domain_as_ip_hostname() -> None:
    assert is_ip_address_hostname("example.com") is False


def test_counts_hostname_labels() -> None:
    assert count_hostname_labels("example.com") == 2
    assert count_hostname_labels("a.b.example.com") == 4


def test_detects_excessive_subdomains() -> None:
    assert has_excessive_subdomains("a.b.c.example.com") is True


def test_allows_normal_subdomain_count() -> None:
    assert has_excessive_subdomains("jobs.example.com") is False


def test_detects_long_url() -> None:
    long_url = "https://example.com/" + ("a" * 130)
    assert has_long_url(long_url) is True


def test_allows_normal_url_length() -> None:
    assert has_long_url("https://example.com/jobs") is False


def test_detect_url_structural_signals() -> None:
    signals = build_signals(
        hostname="a.b.c.example.com",
        normalized_url="https://a.b.c.example.com/" + ("x" * 130),
    )

    detected = detect_url_structural_signals(signals)

    assert detected == [
        "excessive_subdomains",
        "long_url",
    ]


def test_detects_ip_hostname_structural_signal() -> None:
    signals = build_signals(
        hostname="8.8.8.8",
        normalized_url="https://8.8.8.8/jobs",
    )

    detected = detect_url_structural_signals(signals)

    assert detected == ["ip_address_hostname"]

def test_detects_suspicious_tld() -> None:
    from backend.app.services.url_signal_detector import (
        has_suspicious_tld,
    )

    assert has_suspicious_tld("example.xyz") is True
    assert has_suspicious_tld("example.top") is True


def test_allows_common_tld() -> None:
    from backend.app.services.url_signal_detector import (
        has_suspicious_tld,
    )

    assert has_suspicious_tld("example.com") is False
    assert has_suspicious_tld("example.org") is False


def test_suspicious_tld_is_detected_structurally() -> None:
    signals = build_signals(
        hostname="jobs.example.xyz",
        normalized_url="https://jobs.example.xyz/jobs",
    )

    detected = detect_url_structural_signals(signals)

    assert detected == ["suspicious_tld"]

def test_detects_suspicious_url_encoding() -> None:
    from backend.app.services.url_signal_detector import has_suspicious_encoding

    assert has_suspicious_encoding("https://example.com/%2Flogin") is True
    assert has_suspicious_encoding("https://example.com/%252e%252e%252f") is True


def test_detects_excessive_percent_encoding() -> None:
    from backend.app.services.url_signal_detector import has_suspicious_encoding

    url = "https://example.com/path/%41/%42/%43/%44"

    assert has_suspicious_encoding(url) is True


def test_allows_normal_url_encoding() -> None:
    from backend.app.services.url_signal_detector import has_suspicious_encoding

    assert has_suspicious_encoding("https://example.com/jobs?id=123") is False
    assert has_suspicious_encoding("https://example.com/careers") is False


def test_suspicious_encoding_is_detected_structurally() -> None:
    signals = build_signals(
        hostname="example.com",
        normalized_url="https://example.com/%2Flogin",
    )

    detected = detect_url_structural_signals(signals)

    assert detected == ["suspicious_encoding"]