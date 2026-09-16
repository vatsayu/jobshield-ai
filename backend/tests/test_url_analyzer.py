import pytest

from backend.app.services.url_analyzer import URLAnalyzer
from backend.app.services.url_normalizer import URLNormalizationError


def test_url_analyzer_extracts_basic_url_signals() -> None:
    analyzer = URLAnalyzer()

    result = analyzer.analyze(
        "https://example.com/jobs/security-analyst"
    )

    assert result.hostname == "example.com"
    assert result.scheme == "https"
    assert result.has_https is True
    assert result.redirect_count == 0
    assert result.final_url == "https://example.com/jobs/security-analyst"


def test_url_analyzer_detects_http() -> None:
    analyzer = URLAnalyzer()

    result = analyzer.analyze("http://example.com/job")

    assert result.scheme == "http"
    assert result.has_https is False


def test_url_analyzer_uses_normalized_url() -> None:
    analyzer = URLAnalyzer()

    result = analyzer.analyze(
        "HTTPS://Example.COM:443/jobs#tracking"
    )

    assert result.normalized_url == "https://example.com/jobs"
    assert result.final_url == "https://example.com/jobs"
    assert result.hostname == "example.com"
    assert result.scheme == "https"
    assert result.port is None


def test_url_analyzer_preserves_non_default_port() -> None:
    analyzer = URLAnalyzer()

    result = analyzer.analyze(
        "https://example.com:8443/jobs"
    )

    assert result.normalized_url == "https://example.com:8443/jobs"
    assert result.port == 8443


def test_url_analyzer_rejects_unsupported_scheme() -> None:
    analyzer = URLAnalyzer()

    with pytest.raises(URLNormalizationError):
        analyzer.analyze("ftp://example.com/file")


def test_url_analyzer_rejects_missing_hostname() -> None:
    analyzer = URLAnalyzer()

    with pytest.raises(URLNormalizationError):
        analyzer.analyze("https:///missing-host")