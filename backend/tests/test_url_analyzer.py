from unittest.mock import Mock

import pytest

from backend.app.services.url_analyzer import URLAnalyzer
from backend.app.services.url_fetcher import URLFetchError
from backend.app.services.url_normalizer import URLNormalizationError


def build_fetch_result(
    *,
    requested_url: str = "https://example.com/jobs",
    final_url: str = "https://example.com/jobs",
    status_code: int = 200,
    content_type: str = "text/html",
    content_length: int = 24,
    redirect_count: int = 0,
    response_size_bytes: int = 24,
    status: str = "success",
    error: str | None = None,
) -> dict:
    return {
        "requested_url": requested_url,
        "final_url": final_url,
        "status_code": status_code,
        "content_type": content_type,
        "content_length": content_length,
        "redirect_count": redirect_count,
        "response_size_bytes": response_size_bytes,
        "status": status,
        "error": error,
    }


def test_url_analyzer_returns_fetch_metadata() -> None:
    fetcher = Mock()

    fetcher.fetch.return_value = build_fetch_result(
        requested_url="https://example.com/jobs/security-analyst",
        final_url="https://example.com/jobs/security-analyst",
        status_code=200,
        content_type="text/html",
        content_length=128,
        redirect_count=0,
        response_size_bytes=128,
    )

    analyzer = URLAnalyzer(fetcher=fetcher)

    result = analyzer.analyze(
        "https://example.com/jobs/security-analyst"
    )

    assert result.hostname == "example.com"
    assert result.scheme == "https"
    assert result.has_https is True
    assert result.fetch_status == "success"
    assert result.status_code == 200
    assert result.content_type == "text/html"
    assert result.content_length == 128
    assert result.response_size_bytes == 128
    assert result.redirect_count == 0
    assert result.final_url == (
        "https://example.com/jobs/security-analyst"
    )

    fetcher.fetch.assert_called_once_with(
        "https://example.com/jobs/security-analyst"
    )


def test_url_analyzer_detects_http() -> None:
    fetcher = Mock()

    fetcher.fetch.return_value = build_fetch_result(
        requested_url="http://example.com/job",
        final_url="http://example.com/job",
    )

    analyzer = URLAnalyzer(fetcher=fetcher)

    result = analyzer.analyze("http://example.com/job")

    assert result.scheme == "http"
    assert result.has_https is False
    assert result.fetch_status == "success"


def test_url_analyzer_uses_normalized_url() -> None:
    fetcher = Mock()

    fetcher.fetch.return_value = build_fetch_result(
        requested_url="https://example.com/jobs",
        final_url="https://example.com/jobs",
    )

    analyzer = URLAnalyzer(fetcher=fetcher)

    result = analyzer.analyze(
        "HTTPS://Example.COM:443/jobs#tracking"
    )

    assert result.normalized_url == "https://example.com/jobs"
    assert result.final_url == "https://example.com/jobs"
    assert result.hostname == "example.com"
    assert result.scheme == "https"
    assert result.port is None

    fetcher.fetch.assert_called_once_with(
        "https://example.com/jobs"
    )


def test_url_analyzer_preserves_non_default_port() -> None:
    fetcher = Mock()

    fetcher.fetch.return_value = build_fetch_result(
        requested_url="https://example.com:8443/jobs",
        final_url="https://example.com:8443/jobs",
    )

    analyzer = URLAnalyzer(fetcher=fetcher)

    result = analyzer.analyze(
        "https://example.com:8443/jobs"
    )

    assert result.normalized_url == (
        "https://example.com:8443/jobs"
    )
    assert result.port == 8443


def test_url_analyzer_returns_failed_fetch_status() -> None:
    fetcher = Mock()

    fetcher.fetch.side_effect = URLFetchError(
        "Unable to resolve the URL hostname."
    )

    analyzer = URLAnalyzer(fetcher=fetcher)

    result = analyzer.analyze(
        "https://unreachable-example.com/jobs"
    )

    assert result.fetch_status == "failed"
    assert result.fetch_error == (
        "Unable to resolve the URL hostname."
    )
    assert result.status_code is None
    assert result.final_url is None
    assert result.response_size_bytes == 0
    assert result.redirect_count == 0


def test_url_analyzer_rejects_unsupported_scheme() -> None:
    fetcher = Mock()

    analyzer = URLAnalyzer(fetcher=fetcher)

    with pytest.raises(URLNormalizationError):
        analyzer.analyze("ftp://example.com/file")

    fetcher.fetch.assert_not_called()


def test_url_analyzer_rejects_missing_hostname() -> None:
    fetcher = Mock()

    analyzer = URLAnalyzer(fetcher=fetcher)

    with pytest.raises(URLNormalizationError):
        analyzer.analyze("https:///missing-host")

    fetcher.fetch.assert_not_called()