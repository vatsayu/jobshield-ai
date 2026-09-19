from backend.app.schemas.signals import URLTechnicalSignals
from backend.app.services.url_signal_detector import (
    detect_url_structural_signals,
)


def build_signals(
    *,
    normalized_url: str = "https://example.com/jobs",
    hostname: str = "example.com",
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


def test_detects_ip_address_hostname() -> None:
    from backend.app.services.url_signal_detector import (
        is_ip_address_hostname,
    )

    assert is_ip_address_hostname("192.168.1.10") is True
    assert is_ip_address_hostname("example.com") is False


def test_counts_hostname_labels() -> None:
    from backend.app.services.url_signal_detector import (
        count_hostname_labels,
    )

    assert count_hostname_labels("example.com") == 2
    assert count_hostname_labels("jobs.example.com") == 3


def test_detects_excessive_subdomains() -> None:
    from backend.app.services.url_signal_detector import (
        has_excessive_subdomains,
    )

    assert has_excessive_subdomains(
        "a.b.c.d.example.com"
    ) is True

    assert has_excessive_subdomains(
        "jobs.example.com"
    ) is False


def test_allows_configurable_subdomain_limit() -> None:
    from backend.app.services.url_signal_detector import (
        has_excessive_subdomains,
    )

    assert has_excessive_subdomains(
        "a.b.example.com",
        maximum_labels=4,
    ) is False

    assert has_excessive_subdomains(
        "a.b.c.example.com",
        maximum_labels=3,
    ) is True


def test_detects_long_url() -> None:
    from backend.app.services.url_signal_detector import (
        has_long_url,
    )

    url = "https://example.com/" + ("a" * 130)

    assert has_long_url(url) is True


def test_allows_normal_length_url() -> None:
    from backend.app.services.url_signal_detector import (
        has_long_url,
    )

    assert has_long_url(
        "https://example.com/jobs"
    ) is False


def test_allows_configurable_url_length() -> None:
    from backend.app.services.url_signal_detector import (
        has_long_url,
    )

    url = "https://example.com/" + ("a" * 60)

    assert has_long_url(
        url,
        maximum_length=50,
    ) is True


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
    from backend.app.services.url_signal_detector import (
        has_suspicious_encoding,
    )

    assert has_suspicious_encoding(
        "https://example.com/%2Flogin"
    ) is True

    assert has_suspicious_encoding(
        "https://example.com/%252e%252e%252f"
    ) is True


def test_detects_excessive_percent_encoding() -> None:
    from backend.app.services.url_signal_detector import (
        has_suspicious_encoding,
    )

    url = "https://example.com/path/%41/%42/%43/%44"

    assert has_suspicious_encoding(url) is True


def test_allows_normal_url_encoding() -> None:
    from backend.app.services.url_signal_detector import (
        has_suspicious_encoding,
    )

    assert has_suspicious_encoding(
        "https://example.com/jobs?id=123"
    ) is False

    assert has_suspicious_encoding(
        "https://example.com/careers"
    ) is False


def test_suspicious_encoding_is_detected_structurally() -> None:
    signals = build_signals(
        hostname="example.com",
        normalized_url="https://example.com/%2Flogin",
    )

    detected = detect_url_structural_signals(signals)

    assert detected == ["suspicious_encoding"]


def test_detects_userinfo_in_url() -> None:
    from backend.app.services.url_signal_detector import (
        has_userinfo_in_url,
    )

    assert has_userinfo_in_url(
        "https://candidate@example.com/jobs"
    ) is True

    assert has_userinfo_in_url(
        "https://user:password@example.com/jobs"
    ) is True


def test_allows_url_without_userinfo() -> None:
    from backend.app.services.url_signal_detector import (
        has_userinfo_in_url,
    )

    assert has_userinfo_in_url(
        "https://example.com/jobs"
    ) is False


def test_userinfo_is_detected_structurally() -> None:
    signals = build_signals(
        hostname="example.com",
        normalized_url=(
            "https://candidate@example.com/jobs"
        ),
    )

    detected = detect_url_structural_signals(signals)

    assert detected == ["userinfo_in_url"]


def test_detects_hyphenated_hostname_abuse() -> None:
    from backend.app.services.url_signal_detector import (
        has_hyphenated_hostname_abuse,
    )

    assert has_hyphenated_hostname_abuse(
        "secure-job-verify-account-login.example.com"
    ) is True


def test_allows_normal_hyphenated_hostname() -> None:
    from backend.app.services.url_signal_detector import (
        has_hyphenated_hostname_abuse,
    )

    assert has_hyphenated_hostname_abuse(
        "my-job.example.com"
    ) is False


def test_hyphenated_hostname_abuse_is_detected_structurally() -> None:
    signals = build_signals(
        hostname="secure-job-verify-account-login.example.com",
        normalized_url=(
            "https://secure-job-verify-account-login.example.com/jobs"
        ),
    )

    detected = detect_url_structural_signals(signals)

    assert detected == ["hyphenated_hostname_abuse"]