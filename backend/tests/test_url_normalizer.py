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