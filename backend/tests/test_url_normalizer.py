import pytest

from backend.app.services.url_normalizer import (
    URLNormalizationError,
    normalize_url,
)


def test_normalize_url_lowercases_scheme_and_hostname() -> None:
    result = normalize_url("HTTPS://Example.COM/jobs")

    assert result == "https://example.com/jobs"


def test_normalize_url_removes_fragment() -> None:
    result = normalize_url(
        "https://example.com/jobs#tracking"
    )

    assert result == "https://example.com/jobs"


def test_normalize_url_removes_default_https_port() -> None:
    result = normalize_url(
        "https://example.com:443/jobs"
    )

    assert result == "https://example.com/jobs"


def test_normalize_url_preserves_non_default_port() -> None:
    result = normalize_url(
        "https://example.com:8443/jobs"
    )

    assert result == "https://example.com:8443/jobs"


def test_normalize_url_preserves_query_string() -> None:
    result = normalize_url(
        "https://example.com/jobs?id=123#fragment"
    )

    assert result == "https://example.com/jobs?id=123"


def test_normalize_url_rejects_unsupported_scheme() -> None:
    with pytest.raises(URLNormalizationError):
        normalize_url("ftp://example.com/file")


def test_normalize_url_rejects_missing_hostname() -> None:
    with pytest.raises(URLNormalizationError):
        normalize_url("https:///missing-host")


def test_normalize_url_adds_root_path_when_missing() -> None:
    result = normalize_url("https://example.com")

    assert result == "https://example.com/"


def test_normalize_url_rejects_embedded_credentials() -> None:
    with pytest.raises(URLNormalizationError):
        normalize_url(
            "https://user:password@example.com/jobs"
        )


def test_normalize_url_rejects_loopback_ip() -> None:
    with pytest.raises(URLNormalizationError):
        normalize_url("http://127.0.0.1:8000")


def test_normalize_url_rejects_private_ip() -> None:
    with pytest.raises(URLNormalizationError):
        normalize_url("http://192.168.1.10")


def test_normalize_url_rejects_link_local_ip() -> None:
    with pytest.raises(URLNormalizationError):
        normalize_url("http://169.254.169.254/latest")


def test_normalize_url_rejects_unspecified_ip() -> None:
    with pytest.raises(URLNormalizationError):
        normalize_url("http://0.0.0.0")


def test_normalize_url_allows_public_ip() -> None:
    result = normalize_url("https://8.8.8.8/dns")

    assert result == "https://8.8.8.8/dns"


def test_normalize_url_rejects_hostname_whitespace() -> None:
    with pytest.raises(URLNormalizationError):
        normalize_url("https://example .com/jobs")